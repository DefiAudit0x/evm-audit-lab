import contextlib
import io
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


def detector(check, impact, *paths, lines=None):
    if lines is None:
        anchor = paths[0] + "#1"
        elements = [
            {"source_mapping": {"filename_relative": path}} for path in paths
        ]
    else:
        start, end = lines
        anchor = f"{paths[0]}#L{start}-L{end}"
        elements = [
            {
                "source_mapping": {
                    "filename_relative": paths[0],
                    "lines": list(range(start, end + 1)),
                }
            }
        ]
        elements += [
            {"source_mapping": {"filename_relative": path}}
            for path in paths[1:]
        ]
    return {
        "check": check,
        "impact": impact,
        "first_markdown_element": anchor,
        "elements": elements,
    }


def report(*extras, safe_sources=None):
    required = [
        detector(check, "High", path) for path, check in GATE["REQUIRED_DETECTIONS"]
    ]
    if safe_sources is None:
        safe_sources = GATE["SAFE_COUNTERPARTS"]
    source_units = {"src/VulnerableVault.sol": {}}
    source_units.update({path: {} for path in safe_sources})
    return {
        "success": True,
        "error": None,
        "results": {
            "detectors": required + list(extras),
            "compilations": [{"compilation_units": {"test-unit": {"source_units": source_units}}}],
        },
    }


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
        headings = list(re.finditer(r"^### Entry (\d+): `([^`]+)` / `([^`]+)`$", section, re.MULTILINE))
        anchors = list(re.finditer(r'^<a id="accepted-(\d+)"></a>$', section, re.MULTILINE))
        entries = {}
        numbers = {}
        for index, heading in enumerate(headings):
            end = headings[index + 1].start() if index + 1 < len(headings) else len(section)
            body = section[heading.end():end]
            location = re.search(r"(?m)^\*\*Location:\*\* (\d+-\d+)$", body)
            self.assertIsNotNone(
                location, f"Entry {heading.group(1)} has no Location"
            )
            key = (heading.group(2), heading.group(3), location.group(1))
            entries[key] = body
            numbers[key] = heading.group(1)
            preceding = [a for a in anchors if a.start() < heading.start()]
            self.assertTrue(preceding, f"Entry {heading.group(1)} has no anchor")
            self.assertEqual(preceding[-1].group(1), heading.group(1))

        self.assertEqual(len(anchors), len(headings))
        self.assertEqual(len(GATE["ACCEPTED"]), 11)
        self.assertEqual(len(entries), 11)
        for (path, check, lines), entry in GATE["ACCEPTED"].items():
            with self.subTest(finding=(path, check, lines)):
                self.assertIn((path, check, lines), entries)
                subsection = entries[(path, check, lines)]
                self.assertEqual(
                    entry.anchor, "accepted-" + numbers[(path, check, lines)]
                )
                self.assertRegex(subsection, r"(?m)^\*\*Owner:\*\* .+")
                expiry = re.search(r"(?m)^\*\*Expiry:\*\* (.+)$", subsection)
                self.assertIsNotNone(expiry)
                self.assertEqual(expiry.group(1), entry.expires.isoformat())
                self.assertRegex(expiry.group(1), r"^\d{4}-\d{2}-\d{2}$")

    def test_all_accepted_sites_pass(self):
        sites = [
            ("incorrect-equality", "Medium", "src/SafeFotVault.sol", (36, 45)),
            ("reentrancy-balance", "High", "src/SafeFotVault.sol", (47, 58)),
            ("divide-before-multiply", "Medium", "src/SafeLending.sol", (65, 74)),
            ("unused-return", "Medium", "src/SafeLending.sol", (108, 123)),
            ("incorrect-equality", "Medium", "src/SafeSwap.sol", (57, 75)),
            ("controlled-delegatecall", "High", "src/SafeUupsVault.sol", (52, 71)),
            ("incorrect-equality", "Medium", "src/SafeVault4626.sol", (49, 64)),
            ("reentrancy-balance", "High", "src/SafeVault4626.sol", (66, 84)),
            ("reentrancy-balance", "High", "src/SafeFotVault.sol", (36, 45)),
            ("reentrancy-balance", "High", "src/SafeVault4626.sol", (49, 64)),
            ("unused-return", "Medium", "src/SafeLending.sol", (76, 90)),
        ]
        findings = [
            detector(check, impact, path, lines=span)
            for check, impact, path, span in sites
        ]
        self.assert_gate(report(*findings), 0, "RESULT: PASS")

    def test_second_site_under_accepted_pair_fails(self):
        # Fixture D: the accepted deposit site passes, but a second
        # distinct line range under the same (file, check) pair must fail.
        accepted = detector(
            "reentrancy-balance", "High", "src/SafeFotVault.sol", lines=(36, 45)
        )
        self.assert_gate(report(accepted), 0, "RESULT: PASS")
        second_site = detector(
            "reentrancy-balance", "High", "src/SafeFotVault.sol", lines=(100, 110)
        )
        self.assert_gate(
            report(accepted, second_site), 1, "UNTRIAGED [High]"
        )

    def test_expired_exception_fails(self):
        from datetime import date

        accepted = dict(GATE["ACCEPTED"])
        key = ("src/SafeFotVault.sol", "reentrancy-balance", "36-45")
        entry = accepted[key]
        accepted[key] = GATE["AcceptedFinding"](
            reason=entry.reason,
            owner=entry.owner,
            expires=date(2000, 1, 1),
            anchor=entry.anchor,
        )
        body = report(
            detector(
                "reentrancy-balance", "High", "src/SafeFotVault.sol", lines=(36, 45)
            )
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(json.dumps(body).encode())
            findings, _ = GATE["read_report"](str(path))
        decisions = GATE["triage_findings"](findings, accepted=accepted)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0][1], "expired")

    def test_expired_exception_fails_end_to_end(self):
        from datetime import date

        accepted = dict(GATE["ACCEPTED"])
        key = ("src/SafeFotVault.sol", "reentrancy-balance", "36-45")
        entry = accepted[key]
        accepted[key] = GATE["AcceptedFinding"](
            reason=entry.reason,
            owner=entry.owner,
            expires=date(2000, 1, 1),
            anchor=entry.anchor,
        )
        body = report(
            detector(
                "reentrancy-balance", "High", "src/SafeFotVault.sol", lines=(36, 45)
            )
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(json.dumps(body).encode())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = GATE["main"](
                    ["check_slither.py", str(path)], accepted=accepted
                )
        self.assertEqual(status, 1)
        self.assertIn("EXPIRED [High]", output.getvalue())
        self.assertIn("expired on 2000-01-01", output.getvalue())

    def test_required_detection_is_still_required(self):
        body = report()
        body["results"]["detectors"].pop()
        self.assert_gate(body, 1, "no longer fires")

    def test_all_positive_hits_without_safe_scan_evidence_fail(self):
        body = report(safe_sources=[])
        self.assert_gate(body, 1, "no scan evidence for safe counterpart")

    def test_manual_only_proxy_collision_is_reported_as_skipped(self):
        self.assertIn(
            ("Lab 07", "src/SafeProxy.sol", "proxy-storage-collision", "not in Slither 0.11.6 detector catalog"),
            GATE["SKIPPED_CHECKS"],
        )
        self.assert_gate(report(), 0, "SKIP Lab 07 proxy-storage-collision")

    def test_low_unchecked_transfer_on_safe_amm_fails(self):
        finding = detector("unchecked-transfer", "Low", "src/SafeAmm.sol")
        self.assert_gate(report(finding), 1, "unchecked-transfer fired on safe contract src/SafeAmm.sol")

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
        low = detector("unchecked-transfer", "Low", "src/SafeLending.sol")
        medium = detector("unchecked-transfer", "Medium", "src/SafeLending.sol")
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
