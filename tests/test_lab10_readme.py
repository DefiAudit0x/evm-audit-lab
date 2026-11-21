from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "labs" / "lab-10-unchecked-return-value" / "README.md"


class Lab10ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.remediation = " ".join(
            README.read_text(encoding="utf-8")
            .split("## Remediation", 1)[1]
            .split("### Additional defenses", 1)[0]
            .lower()
            .split()
        )

    def test_no_interactions_before_effects_advice(self):
        self.assertNotRegex(
            self.remediation,
            r"(?:mutate|update|clear|delete|change)\b[^.]*\bafter\b[^.]*"
            r"(?:external call|transfer|interaction)[^.]*\b(?:succeed|success)",
        )
        self.assertNotIn("revert happens *before* any state change", self.remediation)

    def test_claim_is_cleared_before_external_call(self):
        self.assertRegex(
            self.remediation,
            r"clear the claim\b.*?\bbefore the external call\b",
        )
        self.assertIn("`totalclaimable`", self.remediation)
        self.assertIn("increment `claimed[msg.sender]`", self.remediation)

    def test_failed_transfer_reverts_effects_atomically(self):
        self.assertRegex(
            self.remediation,
            r"revert[^.]*\batomically\b[^.]*\b(?:effects|accounting)\b",
        )
        self.assertIn("retryable", self.remediation)
        self.assertIn("revert transferfailed()", self.remediation)


if __name__ == "__main__":
    unittest.main()
