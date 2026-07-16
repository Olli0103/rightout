import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.release_check import validate_market_policy_report


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


class MarketReleaseGateTests(unittest.TestCase):
    def report(self) -> dict:
        market_ids = [
            "eu_eea", "uk", "us_california", "us_other", "canada", "brazil",
            "australia", "japan", "singapore", "india", "other",
        ]
        report = {
            "report_version": 1,
            "markets": [
                {
                    "market_id": market_id,
                    "coverage_class": "core" if market_id in {"eu_eea", "uk", "us_california"} else ("unknown" if market_id == "other" else "extended"),
                    "source_status": "current",
                    "operational_authority": "diagnostic_only_not_authorization",
                    "rightout_support": {"gpc_preference": "unsupported_or_not_evidenced"},
                    "safe_default": "human_gate",
                    "open_requirements": ["needs_evidence"],
                    "next_review_at": "2026-10-01",
                }
                for market_id in market_ids
            ],
            "cross_market_rules": [
                "technical_discovery_support_is_not_legal_or_provider_authorization",
                "publisher_automation_requires_current_written_provider_authorization_in_every_market",
                "provider_specific_route_eligibility_does_not_create_a_universal_privacy_right",
                "unsupported_or_uncertain_rights_execution_stops_at_a_human_gate",
                "no_market_claims_universal_or_permanent_deletion",
                "preference_signal_is_not_deletion_request_or_deletion_proof",
            ],
        }
        uk = next(item for item in report["markets"] if item["market_id"] == "uk")
        uk["evidence_status"] = "evidenced"
        uk["rightout_support"] = {
            "controller_request": "catalog_limited_1_uk_email_route",
            "gpc_preference": "unsupported_or_not_evidenced",
        }
        uk["safe_default"] = "dedicated_uk_contract_or_human_gate"
        uk["open_requirements"] = [
            "only_cognism_uk_email_route_is_currently_evidenced",
            "additional_uk_provider_route_inventory_needs_evidence",
        ]
        california = next(item for item in report["markets"] if item["market_id"] == "us_california")
        california["rightout_support"].update({
            "universal_broker_request": "human_verified_drop_filing_record_only",
            "gpc_preference": "human_verified_signal_record_only",
        })
        california["open_requirements"] = [
            "drop_processing_begins_2026_08_01",
            "gpc_provider_compliance_requires_site_specific_evidence",
        ]
        us_other = next(item for item in report["markets"] if item["market_id"] == "us_other")
        us_other["rightout_support"]["gpc_preference"] = "human_verified_signal_legal_effect_needs_market_evidence"
        return report

    def analysis(self) -> str:
        return "\n".join([
            "### EU and EEA",
            "### United Kingdom",
            "### United States — California",
            "### Other US states",
            "### Canada",
            "### Brazil",
            "### Australia",
            "### Japan",
            "### Singapore",
            "### India",
            "### All other markets",
        ])

    def test_current_complete_market_contract_passes(self) -> None:
        errors = validate_market_policy_report(
            self.report(),
            self.analysis(),
            {"docs/market-analysis-2026-07.md", "docs/roadmap-v0.10.0.md"},
        )
        self.assertEqual(errors, [])

    def test_stale_core_source_blocks_release(self) -> None:
        report = self.report()
        next(item for item in report["markets"] if item["market_id"] == "us_california")["source_status"] = "review_due"
        errors = validate_market_policy_report(
            report,
            self.analysis(),
            {"docs/market-analysis-2026-07.md", "docs/roadmap-v0.10.0.md"},
        )
        self.assertTrue(any("us_california" in error for error in errors))

    def test_uk_contract_substitution_blocks_release(self) -> None:
        report = self.report()
        uk = next(item for item in report["markets"] if item["market_id"] == "uk")
        uk["rightout_support"]["controller_request"] = "catalog_limited_18_email_routes"
        errors = validate_market_policy_report(
            report,
            self.analysis(),
            {"docs/market-analysis-2026-07.md", "docs/roadmap-v0.10.0.md"},
        )
        self.assertTrue(any("UK market policy" in error for error in errors))

    def test_undocumented_or_unpackaged_market_contract_blocks_release(self) -> None:
        errors = validate_market_policy_report(
            self.report(),
            self.analysis().replace("### India", ""),
            {"docs/market-analysis-2026-07.md"},
        )
        self.assertTrue(any("india" in error for error in errors))
        self.assertTrue(any("roadmap-v0.10.0.md" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
