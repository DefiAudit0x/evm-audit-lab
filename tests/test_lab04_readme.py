from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "lab-04-oracle-manipulation"


class Lab04ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = " ".join(
            (LAB / "README.md").read_text(encoding="utf-8").split()
        )

    def test_readme_documents_round_integrity_and_decimal_scaling(self):
        self.assertNotRegex(self.readme, r"(?i)does\s+(?:\*\*)?not(?:\*\*)?\s+validate")
        self.assertNotIn("without a deviation check", self.readme)
        self.assertIn("validates round integrity", self.readme)
        self.assertIn("`answeredInRound >= roundId`", self.readme)
        self.assertIn("normalizes feed decimal scaling to 18 decimals", self.readme)
        self.assertIn("rejects feeds with more than 18 decimals", self.readme)

    def test_readme_documents_optional_sequencer_and_deviation_checks(self):
        self.assertIn("`ConfiguredSafeLending` adds optional checks", self.readme)
        self.assertIn("L2 sequencer status must be up", self.readme)
        self.assertIn("recovery must be more than one hour ago", self.readme)
        self.assertIn("validates deviation from a TWAP reference price", self.readme)
        self.assertIn("within 10% of it", self.readme)
        self.assertIn("zero sequencer or TWAP address disables that optional check", self.readme)

    def test_stale_price_demonstrates_debt_accounting_without_profit(self):
        self.assertIn("only updates debt accounting", self.readme)
        self.assertIn("no loan asset is transferred", self.readme)
        for path in (ROOT / "test" / "StaleOracle.t.sol", LAB / "test" / "StaleOracle.t.sol"):
            with self.subTest(path=str(path.relative_to(ROOT))):
                text = " ".join(path.read_text(encoding="utf-8").split())
                self.assertNotRegex(text, r"\$1,000\s+profit")
                self.assertNotIn("walks away", text)
                self.assertNotIn("away with a $250 profit", text)
                self.assertIn("This only changes debt", text)
                self.assertIn("accounting: no loan asset is paid out", text)
                self.assertIn("no realized profit is demonstrated", text)


if __name__ == "__main__":
    unittest.main()
