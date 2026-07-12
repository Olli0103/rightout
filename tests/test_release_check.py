import unittest

from scripts.release_check import checkout_steps_are_hardened


class WorkflowCheckoutHardeningTests(unittest.TestCase):
    def test_checkout_requires_false_under_with(self) -> None:
        secure = """
steps:
  - uses: actions/checkout@0123456789012345678901234567890123456789
    with:
      fetch-depth: 0
      persist-credentials: false
"""
        self.assertTrue(checkout_steps_are_hardened(secure))

        misplaced = """
steps:
  - uses: actions/checkout@0123456789012345678901234567890123456789
    env:
      persist-credentials: false
"""
        self.assertFalse(checkout_steps_are_hardened(misplaced))

    def test_named_checkout_step_is_detected_regardless_of_key_order(self) -> None:
        insecure = """
steps:
  - name: Checkout
    uses: actions/checkout@0123456789012345678901234567890123456789
"""
        self.assertFalse(checkout_steps_are_hardened(insecure))

        secure = """
steps:
  - name: Checkout
    with:
      persist-credentials: false
    uses: actions/checkout@0123456789012345678901234567890123456789
"""
        self.assertTrue(checkout_steps_are_hardened(secure))

    def test_non_checkout_steps_do_not_require_checkout_settings(self) -> None:
        workflow = """
steps:
  - name: Build
    run: npm run build
"""
        self.assertTrue(checkout_steps_are_hardened(workflow))


if __name__ == "__main__":
    unittest.main()
