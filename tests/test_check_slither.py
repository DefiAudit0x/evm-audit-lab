import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/check_slither.py"
GATE = runpy.run_path(str(SCRIPT))


def detector(check, impact, *paths):
    return {
        "check": check,
        "impact": impact,
        "first_markdown_element": paths[0] + "#1",
        "elements": [
            {"source_mapping": {"filename_relative": path}} for path in paths
        ],
    }


def report(*extras):
    required = [
        detector(check, "High", path) for path, check in GATE["REQUIRED_DETECTIONS"]
    ]
    return {"success": True, "error": None, "results": {"detectors": required + list(extras)}}


class SlitherGateTests(unittest.TestCase):
    def assert_gate(self, body, status, message):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(body)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        self.assertIn(message, result.stdout)
        self.assertEqual(result.stderr, "")

    def test_clean_report_passes(self):
        self.assert_gate(report(), 0, "RESULT: PASS")

    def test_no_slither_suppressions_or_excluded_detectors(self):
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / "slither.config.json").read_text())
        self.assertEqual(config.get("detectors_to_exclude"), "")
        for folder in ("src", "labs", "test"):
            for source in (root / folder).rglob("*.sol"):
                with self.subTest(source=source.relative_to(root)):
                    self.assertNotIn("slither-disable", source.read_text())

    def test_accepted_findings_match_triage_record(self):
        root = Path(__file__).resolve().parents[1]
        record = (root / "docs/slither-triage.md").read_text()
        section = record.split("## Accepted findings (2026-11-21)", 1)[1]
        headings = list(re.finditer(r"^### Entry \d+: `([^`]+)` / `([^`]+)`$", section, re.MULTILINE))
        entries = {}
        for index, heading in enumerate(headings):
            end = headings[index + 1].start() if index + 1 < len(headings) else len(section)
            entries[(heading.group(1), heading.group(2))] = section[heading.end():end]

        self.assertEqual(len(GATE["ACCEPTED"]), 8)
        self.assertEqual(len(entries), 8)
        for finding in GATE["ACCEPTED"]:
            with self.subTest(finding=finding):
                self.assertIn(finding, entries)
                subsection = entries[finding]
                self.assertRegex(subsection, r"(?m)^\*\*Owner:\*\* .+")
                expiry = re.search(r"(?m)^\*\*Expiry:\*\* (.+)$", subsection)
                self.assertIsNotNone(expiry)
                self.assertRegex(expiry.group(1), r"^\d{4}-\d{2}-\d{2}$")

    def test_required_detection_is_still_required(self):
        body = report()
        body["results"]["detectors"].pop()
        self.assert_gate(body, 1, "no longer fires")

    def test_unsuccessful_report_fails_even_with_required_detections(self):
        for fields in (
            {"success": False, "error": "analysis failed"},
            {"success": True, "error": "analysis failed"},
            {"success": False},
            {"success": 1},
        ):
            with self.subTest(fields=fields):
                self.assert_gate(report() | fields, 1, "analysis did not succeed")

    def test_medium_wins_in_both_orders(self):
        low = detector("unchecked-transfer", "Low", "src/SafeAmm.sol")
        medium = detector("unchecked-transfer", "Medium", "src/SafeAmm.sol")
        self.assert_gate(report(low), 0, "RESULT: PASS")
        for order in ((low, medium), (medium, low)):
            with self.subTest(first=order[0]["impact"]):
                self.assert_gate(report(*order), 1, "UNTRIAGED [Medium]")

    def test_safe_matching_uses_filename_not_parent_path(self):
        finding = detector("incorrect-equality", "High", "src/SafeLessons/Ordinary.sol")
        self.assert_gate(report(finding), 0, "RESULT: PASS")

    def test_second_source_element_is_gated(self):
        finding = detector(
            "unchecked-transfer", "High", "src/VulnerableRouter.sol", "./src/SafeRouter.sol"
        )
        self.assert_gate(report(finding), 1, "fired on safe contract src/SafeRouter.sol")

    def test_malformed_reports_fail_cleanly(self):
        valid = json.dumps(report()).encode()
        for body, message in (
            (b"{", "cannot read Slither report"),
            (b"\xff", "cannot read Slither report"),
            ([], "report must be an object"),
            (report() | {"results": None}, "results.detectors must be a list"),
            (report() | {"results": {"detectors": {}}}, "results.detectors must be a list"),
            (report(None), "must be an object"),
            (report(detector("test", "Unknown", "src/SafeAmm.sol")), "invalid impact"),
            (report({"check": "test", "impact": "Medium", "elements": [{}]}), "invalid source_mapping"),
            (valid.replace(b'"error": null', b'"error": "failed", "error": null'), "duplicate JSON key"),
            (valid.replace(b'"error": null', b'"extra": NaN'), "non-finite JSON number"),
            (valid.replace(b'"error": null', b'"extra": Infinity'), "non-finite JSON number"),
            (valid.replace(b'"error": null', b'"extra": 1e999'), "non-finite JSON number"),
        ):
            with self.subTest(message=message):
                self.assert_gate(body, 1, message)

    def test_report_size_limit(self):
        valid = json.dumps(report()).encode()
        at_limit = valid.ljust(16 * 1024 * 1024, b" ")
        self.assert_gate(at_limit, 0, "RESULT: PASS")
        self.assert_gate(at_limit + b" ", 1, "report exceeds 16 MiB")


if __name__ == "__main__":
    unittest.main()
