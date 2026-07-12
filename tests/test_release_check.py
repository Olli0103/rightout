import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-workflows.mjs"
SHA = "0123456789012345678901234567890123456789"


def validate_workflow(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="rightout-workflow-test-") as raw:
        path = Path(raw) / "workflow.yml"
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            ["node", str(VALIDATOR), str(path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


class WorkflowCheckoutHardeningTests(unittest.TestCase):
    def test_checkout_requires_boolean_false_under_with(self) -> None:
        secure = validate_workflow(f"""
steps:
  - uses: actions/checkout@{SHA}
    with:
      fetch-depth: 0
      persist-credentials: false
""")
        self.assertEqual(secure.returncode, 0, secure.stderr)
        self.assertEqual(json.loads(secure.stdout)["checkout_count"], 1)

        for insecure in [
            f"""steps:\n  - uses: actions/checkout@{SHA}\n    env:\n      persist-credentials: false\n""",
            f"""steps:\n  - uses: actions/checkout@{SHA}\n    with:\n      persist-credentials: "false"\n""",
        ]:
            denied = validate_workflow(insecure)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("with.persist-credentials", denied.stderr)

    def test_named_checkout_step_is_detected_regardless_of_key_order(self) -> None:
        insecure = validate_workflow(f"""
steps:
  - name: Checkout
    uses: actions/checkout@{SHA}
""")
        self.assertNotEqual(insecure.returncode, 0)

        secure = validate_workflow(f"""
steps:
  - name: Checkout
    with:
      persist-credentials: false
    uses: actions/checkout@{SHA}
""")
        self.assertEqual(secure.returncode, 0, secure.stderr)

    def test_block_and_flow_checkout_mappings_are_detected(self) -> None:
        fixtures = [
            f"""steps:\n  -\n    uses: actions/checkout@{SHA}\n""",
            f"""steps:\n  - {{uses: actions/checkout@{SHA}}}\n""",
        ]
        for fixture in fixtures:
            denied = validate_workflow(fixture)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("with.persist-credentials", denied.stderr)

    def test_invalid_or_checkout_free_workflow_fails_closed(self) -> None:
        invalid = validate_workflow("steps:\n  - name: broken\n   run: true\n")
        self.assertNotEqual(invalid.returncode, 0)
        checkout_free = validate_workflow("steps:\n  - name: Build\n    run: npm run build\n")
        self.assertNotEqual(checkout_free.returncode, 0)
        self.assertIn("no checkout action found", checkout_free.stderr)


if __name__ == "__main__":
    unittest.main()
