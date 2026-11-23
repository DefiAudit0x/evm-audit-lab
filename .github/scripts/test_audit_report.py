import io
import json
from pathlib import Path
import unittest
from unittest.mock import mock_open, patch

import audit_report as a
from check_slither import ACCEPTED

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DEFAULT_ALLOWLIST = [
    {
        "path": path,
        "check": check,
        "lines": lines,
        "reason": entry.reason,
        "owner": entry.owner,
        "expires": entry.expires.isoformat(),
        "anchor": entry.anchor,
    }
    for (path, check, lines), entry in sorted(ACCEPTED.items())
]


def detector(
    path="src/VulnerableVault.sol",
    check="reentrancy-eth",
    impact="High",
    line=5,
):
    return {
        "check": check,
        "impact": impact,
        "confidence": "High",
        "description": (
            "Finding <script>alert(1)</script> | "
            "[x](evil)\nsecond line"
        ),
        "first_markdown_element": (
            f"{path}#L{line}-L{line + 1}"
        ),
        "elements": [
            {
                "source_mapping": {
                    "filename_relative": path,
                    "lines": [line, line + 1],
                }
            }
        ],
    }


def raw(*items):
    return {
        "success": True,
        "error": None,
        "results": {"detectors": list(items)},
    }


def policy(required=(), forbidden=None, allowed=()):
    entries = []
    for entry in allowed:
        if len(entry) == 3:
            path, check, reason = entry
            lines, owner, expires, anchor = (
                "5-6",
                "DefiAudit0x",
                "2099-01-01",
                "test",
            )
        else:
            path, check, reason, lines, owner, expires, anchor = entry
        entries.append(
            {
                "path": path,
                "check": check,
                "lines": lines,
                "reason": reason,
                "owner": owner,
                "expires": expires,
                "anchor": anchor,
            }
        )
    return {
        "schema_version": 1,
        "required_detections": [
            {"path": p, "check": c} for p, c in required
        ],
        "forbidden_on_safe": forbidden or {},
        "allowed_on_safe": entries,
    }


class AuditTests(unittest.TestCase):
    def build(self, data, rules=None, threshold="none"):
        return a.build_report(
            a.parse_findings(data, ROOT),
            rules or policy(),
            threshold,
        )

    def config(self, value):
        with patch.object(a, "read_json", return_value=value):
            return a.load_policy(Path("policy.json"), ROOT)

    def test_defaults_validate(self):
        result = a.load_policy(None, ROOT)
        self.assertEqual(len(result["required_detections"]), 7)
        self.assertEqual(result["allowed_on_safe"], EXPECTED_DEFAULT_ALLOWLIST)

    def test_research_metadata_exports(self):
        key = "src/SafeA.sol:SafeA"
        counterexample = {"Single": {"args": [1]}}
        artifact = {
            "metadata": {
                "compiler": {"version": "0.8.24"},
                "settings": {"compilationTarget": {"src/SafeA.sol": "SafeA"}},
            },
            "storageLayout": {"storage": [], "types": {}},
        }
        tests = {"suite": {"test_results": {"test": {"counterexample": counterexample}}}}
        with (
            patch.object(Path, "glob", return_value=[Path("out/SafeA.sol/SafeA.json")]),
            patch.object(a, "read_json", side_effect=[artifact, tests]),
            patch.object(a.subprocess, "check_output", side_effect=["forge", "slither", "abc", ""]),
        ):
            research = a.collect_research(ROOT, Path("out"), Path("test.json"), "0x13")
        self.assertEqual(research["compiler_settings"][key]["version"], "0.8.24")
        self.assertEqual(research["storage_layouts"][key], artifact["storageLayout"])
        self.assertEqual(research["minimal_counterexamples"], {"suite::test": counterexample})
        self.assertEqual(research["test_seeds"], {"foundry_fuzz_seed": "0x13"})
        self.assertEqual(research["source_revision"], "abc")
        self.assertEqual(research["tool_versions"]["slither"], "slither")
        report = self.build(raw())
        report["research"] = research
        self.assertEqual(json.loads(a.render(report, "json"))["research"], research)
        props = a.to_sarif(report)["runs"][0]["properties"]
        self.assertEqual(props["research"], research)
        self.assertIn('"foundry_fuzz_seed": "0x13"', a.render(report, "markdown"))

    def research(self, revision=None, dirty=None):
        artifact = {
            "metadata": {
                "compiler": {"version": "0.8.24"},
                "settings": {"compilationTarget": {"src/A.sol": "A"}},
            },
            "storageLayout": {"storage": [], "types": {}},
        }
        tests = {"suite": {"test_results": {}}}
        with (
            patch.object(Path, "glob", return_value=[Path("out/A.sol/A.json")]),
            patch.object(a, "read_json", side_effect=[artifact, tests]),
            patch.object(a.subprocess, "check_output", side_effect=["forge", "slither", "checkout-rev", ""]),
        ):
            return a.collect_research(
                ROOT, Path("out"), Path("test.json"), "seed", revision, dirty
            )

    def test_provided_provenance_is_used_verbatim(self):
        research = self.research("artifact-revision", True)
        self.assertEqual(research["source_revision"], "artifact-revision")
        self.assertIs(research["source_dirty"], True)
        self.assertEqual(research["source_revision_origin"], "provided")

    def test_absent_provenance_uses_exporter_checkout(self):
        research = self.research()
        self.assertEqual(research["source_revision"], "checkout-rev")
        self.assertIs(research["source_dirty"], False)
        self.assertEqual(research["source_revision_origin"], "exporter-checkout")

    def test_url_markdown_anchor_uses_structured_source_mapping(self):
        item = detector("src/VulnerableVault.sol")
        item["first_markdown_element"] = "https://github.com/org/repo/blob/main/src/VulnerableVault.sol#L9"
        findings = a.parse_findings(raw(item), ROOT)
        self.assertEqual(findings[0]["locations"][0]["path"], "src/VulnerableVault.sol")
        self.assertEqual(findings[0]["locations"][0]["start_line"], 5)

    def test_partial_config_preserves_defaults(self):
        result = self.config(
            {"schema_version": 1, "required_detections": []}
        )
        self.assertFalse(result["required_detections"])
        self.assertEqual(result["allowed_on_safe"], EXPECTED_DEFAULT_ALLOWLIST)
        self.assertTrue(result["forbidden_on_safe"])

    def test_bad_config(self):
        bad = [
            [],
            {"schema_version": True},
            {"schema_version": 2},
            {"schema_version": 1, "unknown": 1},
            {
                "schema_version": 1,
                "required_detections": "bad",
            },
            {
                "schema_version": 1,
                "required_detections": [
                    {"path": "../bad", "check": "x"}
                ],
            },
            {
                "schema_version": 1,
                "required_detections": [
                    {
                        "path": "src/a",
                        "check": "x",
                        "extra": 1,
                    }
                ],
            },
            {
                "schema_version": 1,
                "forbidden_on_safe": {
                    "src/SafeA.sol": ["x", "x"]
                },
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "1-2",
                        "reason": " ",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/A.sol",
                        "check": "x",
                        "lines": "1-2",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeVault.sol",
                        "check": "reentrancy-eth",
                        "lines": "1-2",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "5",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "5-2",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "1-2",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-13-40",
                        "anchor": "a",
                    }
                ],
            },
            {
                "schema_version": 1,
                "allowed_on_safe": [
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "1-2",
                        "reason": "why",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "a",
                    },
                    {
                        "path": "src/SafeA.sol",
                        "check": "x",
                        "lines": "1-2",
                        "reason": "why again",
                        "owner": "o",
                        "expires": "2099-01-01",
                        "anchor": "b",
                    },
                ],
            },
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(a.AuditError):
                    self.config(value)

    def test_duplicate_and_nonfinite_json(self):
        for content in (
            '{"a":1,"a":2}',
            '{"a":NaN}',
            '{"a":Infinity}',
            "{bad",
        ):
            with self.subTest(content=content):
                with patch.object(
                    Path, "read_text", return_value=content
                ):
                    with self.assertRaises(a.AuditError):
                        a.read_json("input.json")

    def test_invalid_reports_fail_closed(self):
        bad = [
            {},
            {
                "success": False,
                "results": {"detectors": []},
            },
            {
                "success": True,
                "error": "compile failed",
                "results": {"detectors": []},
            },
            {"success": True, "results": {}},
            raw(
                {
                    "check": "x",
                    "impact": "Unknown",
                    "description": "x",
                }
            ),
            raw(
                {
                    "check": "x",
                    "impact": "High",
                    "description": "x",
                }
            ),
            raw({**detector(), "elements": "bad"}),
            raw(
                {
                    **detector(),
                    "first_markdown_element": 7,
                }
            ),
            raw(detector("../outside.sol")),
            raw(detector("/outside.sol")),
            raw(detector("https://evil/a.sol")),
            raw(
                {
                    **detector(),
                    "elements": [
                        {
                            "source_mapping": {
                                "filename_relative": "src/a.sol",
                                "lines": [True],
                            }
                        }
                    ],
                }
            ),
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(a.AuditError):
                    a.parse_findings(value, ROOT)

    def test_empty_success_still_checks_required(self):
        result = self.build(
            raw(),
            policy(required=[("src/V.sol", "x")]),
        )
        self.assertEqual(result["status"], "failed")
        sarif_result = a.to_sarif(result)["runs"][0]["results"][0]
        self.assertEqual(
            sarif_result["ruleId"],
            "audit/missing-detection",
        )

    def test_defaults_all_three_gates(self):
        defaults = a.load_policy(None, ROOT)
        detections = [
            detector(p, c) for p, c in a.REQUIRED_DETECTIONS
        ]
        self.assertEqual(
            self.build(raw(*detections), defaults)["status"],
            "passed",
        )
        detections.append(detector("src/SafeVault.sol"))
        self.assertEqual(
            self.build(raw(*detections), defaults)["status"],
            "failed",
        )

    def test_allowlist_justification_and_suppression(self):
        result = self.build(
            raw(detector("src/SafeA.sol")),
            policy(
                allowed=[
                    (
                        "src/SafeA.sol",
                        "reentrancy-eth",
                        "Reviewed scope",
                    )
                ]
            ),
            "low",
        )
        self.assertEqual(result["status"], "passed")
        sarif_result = a.to_sarif(result)["runs"][0]["results"][0]
        self.assertEqual(
            sarif_result["suppressions"][0]["justification"],
            "Reviewed scope",
        )

    def test_safe_medium_not_hidden_by_low(self):
        result = self.build(
            raw(
                detector("src/SafeA.sol", impact="Low"),
                detector("src/SafeA.sol", impact="Medium"),
            )
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["findings"], 2)

    def test_preserve_distinct_locations_and_deduplicate_exact(self):
        first, second = detector(), detector(line=9)
        result = self.build(raw(first, first, second))
        self.assertEqual(result["summary"]["findings"], 2)
        self.assertEqual(
            len({f["id"] for f in result["findings"]}),
            2,
        )
        self.assertEqual(
            a.render(result, "json"),
            a.render(self.build(raw(second, first)), "json"),
        )

    def router_allowlist_report(self, primary, related):
        item = detector(primary, "unchecked-transfer", "High")
        item["elements"].append(
            {"source_mapping": {"filename_relative": related, "lines": [2]}}
        )
        rules = policy(allowed=[
            ("src/SafeRouter.sol", "unchecked-transfer", "Reviewed router scope")
        ])
        return self.build(raw(item), rules, threshold="high")

    def test_related_allowlist_does_not_accept_primary(self):
        # Per-site matching: the related SafeRouter element sits at lines
        # 2-2, which no exception covers, so the finding is untriaged at
        # that site and the triage gate fails even though the pair is
        # allowlisted at 5-6. The primary finding is still not accepted
        # (no justification).
        result = self.router_allowlist_report(
            "src/VulnerableRouter.sol", "src/SafeRouter.sol"
        )
        finding = result["findings"][0]
        self.assertEqual(finding["locations"][0]["path"], "src/VulnerableRouter.sol")
        self.assertEqual(finding["disposition"], "untriaged")
        self.assertNotIn("justification", finding)
        self.assertEqual(result["summary"]["threshold_failures"], 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["gates"][0]["kind"], "safe-triage")
        self.assertEqual(result["gates"][0]["status"], "failed")
        self.assertIn("allowlist reason", result["gates"][0]["message"])

    def test_expired_allowlist_entry_does_not_allow(self):
        result = self.build(
            raw(detector("src/SafeA.sol")),
            policy(
                allowed=[
                    (
                        "src/SafeA.sol",
                        "reentrancy-eth",
                        "Reviewed scope",
                        "5-6",
                        "DefiAudit0x",
                        "2000-01-01",
                        "test",
                    )
                ]
            ),
        )
        self.assertEqual(result["status"], "failed")
        gate = [g for g in result["gates"] if g["kind"] == "safe-triage"][0]
        self.assertEqual(gate["status"], "failed")
        self.assertIn("expired on 2000-01-01", gate["message"])

    def test_second_site_under_allowed_pair_needs_its_own_entry(self):
        allowed = policy(
            allowed=[("src/SafeA.sol", "reentrancy-eth", "Reviewed scope")]
        )
        self.assertEqual(
            self.build(raw(detector("src/SafeA.sol")), allowed)["status"],
            "passed",
        )
        self.assertEqual(
            self.build(raw(detector("src/SafeA.sol", line=9)), allowed)[
                "status"
            ],
            "failed",
        )

    def test_primary_allowlist_preserves_acceptance(self):
        result = self.router_allowlist_report(
            "src/SafeRouter.sol", "src/VulnerableRouter.sol"
        )
        finding = result["findings"][0]
        self.assertEqual(finding["locations"][0]["path"], "src/SafeRouter.sol")
        self.assertEqual(finding["disposition"], "allowed")
        self.assertEqual(finding["justification"], "Reviewed router scope")
        self.assertEqual(result["summary"]["threshold_failures"], 0)
        self.assertEqual(result["status"], "passed")

    def test_related_safe_source_gates_shared_attribution_policy(self):
        item = detector(
            "src/VulnerableRouter.sol", "unchecked-transfer", "High"
        )
        item["elements"].append(
            {
                "source_mapping": {
                    "filename_relative": "src/SafeRouter.sol",
                    "lines": [2],
                }
            }
        )
        rules = policy(
            forbidden={"src/SafeRouter.sol": ["unchecked-transfer"]}
        )
        result = self.build(raw(item), rules)
        self.assertEqual(result["status"], "failed")
        gates = [
            gate for gate in result["gates"]
            if gate["path"] == "src/SafeRouter.sol"
            and gate["kind"] == "safe-regression"
        ]
        self.assertEqual(len(gates), 1)
        self.assertEqual(gates[0]["status"], "failed")
        self.assertEqual(gates[0]["message"], "Detector fired on safe contract.")
        sarif_result = a.to_sarif(result)["runs"][0]["results"][0]
        self.assertEqual(
            len(sarif_result["relatedLocations"]),
            1,
        )

    def test_fallback_and_path_normalization(self):
        item = detector()
        del item["first_markdown_element"]
        item["elements"][0]["source_mapping"][
            "filename_relative"
        ] = str(ROOT / "src/VulnerableVault.sol")
        parsed = a.parse_findings(raw(item), ROOT)
        self.assertEqual(
            parsed[0]["locations"][0]["path"],
            "src/VulnerableVault.sol",
        )
        self.assertEqual(
            a.source_path(r".\src\SafeA.sol", ROOT),
            "src/SafeA.sol",
        )

    def test_uri_escaping_and_no_fabricated_region(self):
        loc = a.sarif_location({"path": "src/a #b.sol"})
        physical = loc["physicalLocation"]
        self.assertEqual(
            physical["artifactLocation"]["uri"],
            "src/a%20%23b.sol",
        )
        self.assertNotIn("region", physical)

    def test_markdown_escaping(self):
        rendered = a.render(
            self.build(raw(detector())), "markdown"
        )
        self.assertNotIn("<script>", rendered)
        self.assertIn(r"\|", rendered)
        self.assertIn(r"\[x\]", rendered)

    def test_severity_threshold(self):
        self.assertEqual(
            self.build(
                raw(detector(impact="Low")),
                threshold="high",
            )["status"],
            "passed",
        )
        self.assertEqual(
            self.build(
                raw(detector(impact="Low")),
                threshold="low",
            )["status"],
            "failed",
        )

    def test_machine_stdout(self):
        with (
            patch.object(a, "read_json", return_value=raw()),
            patch.object(
                a, "load_policy", return_value=policy()
            ),
        ):
            for fmt in ("json", "sarif", "markdown", "text"):
                with (
                    self.subTest(format=fmt),
                    patch(
                        "sys.stdout",
                        new_callable=io.StringIO,
                    ) as output,
                ):
                    self.assertEqual(
                        a.main(["input.json", "--format", fmt]),
                        0,
                    )
                    if fmt in ("json", "sarif"):
                        json.loads(output.getvalue())

    def test_error_reports_and_exit(self):
        for fmt in ("json", "sarif"):
            with (
                self.subTest(format=fmt),
                patch.object(
                    a,
                    "read_json",
                    side_effect=a.AuditError("invalid scan"),
                ),
                patch(
                    "sys.stdout",
                    new_callable=io.StringIO,
                ) as output,
            ):
                self.assertEqual(
                    a.main(["bad.json", "--format", fmt]),
                    2,
                )
                result = json.loads(output.getvalue())
                if fmt == "json":
                    self.assertEqual(result["status"], "error")
                else:
                    self.assertFalse(
                        result["runs"][0]["invocations"][0][
                            "executionSuccessful"
                        ]
                    )

    def test_all_formats_even_when_policy_fails(self):
        with (
            patch.object(a, "read_json", return_value=raw()),
            patch.object(a, "write_output") as writer,
        ):
            self.assertEqual(
                a.main(
                    [
                        "input.json",
                        "--format",
                        "all",
                        "--output-dir",
                        "reports",
                    ]
                ),
                1,
            )
            self.assertEqual(writer.call_count, 3)
            for call in writer.call_args_list:
                if str(call.args[0]).endswith(
                    (".json", ".sarif")
                ):
                    json.loads(call.args[1])

    def test_validate_only(self):
        with (
            patch.object(
                a,
                "read_json",
                side_effect=AssertionError(
                    "must not read scan"
                ),
            ),
            patch(
                "sys.stdout",
                new_callable=io.StringIO,
            ) as output,
        ):
            self.assertEqual(a.main(["--validate-config"]), 0)
            self.assertEqual(
                json.loads(output.getvalue())["schema_version"],
                1,
            )

    def test_output_does_not_overwrite_input(self):
        with (
            patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaises(SystemExit) as raised,
        ):
            a.main(["input.json", "-o", "./input.json"])
        self.assertEqual(raised.exception.code, 2)

    def test_output_failure_is_operational_error(self):
        with (
            patch.object(a, "read_json", return_value=raw()),
            patch.object(
                a,
                "write_output",
                side_effect=OSError("denied"),
            ),
            patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as error,
        ):
            self.assertEqual(
                a.main(["input.json", "--format", "json"]),
                2,
            )
            self.assertIn("denied", error.getvalue())

    def test_atomic_file_output(self):
        handle = mock_open()
        with (
            patch.object(Path, "mkdir"),
            patch.object(
                a.tempfile,
                "mkstemp",
                return_value=(42, "temporary"),
            ),
            patch.object(a.os, "fdopen", handle),
            patch.object(a.os, "fsync") as fsync,
            patch.object(a.os, "replace") as replace,
            patch.object(
                a.os.path, "exists", return_value=False
            ),
        ):
            a.write_output("reports/result.json", "complete")
            handle().write.assert_called_once_with("complete")
            fsync.assert_called_once()
            replace.assert_called_once_with(
                "temporary", Path("reports/result.json")
            )

    def test_failed_write_keeps_previous_output(self):
        handle = mock_open()
        handle().write.side_effect = OSError("disk full")
        with (
            patch.object(Path, "mkdir"),
            patch.object(
                a.tempfile,
                "mkstemp",
                return_value=(42, "temporary"),
            ),
            patch.object(a.os, "fdopen", handle),
            patch.object(a.os, "replace") as replace,
            patch.object(
                a.os.path, "exists", return_value=True
            ),
            patch.object(a.os, "unlink") as unlink,
        ):
            with self.assertRaises(OSError):
                a.write_output(
                    "reports/result.json", "complete"
                )
            replace.assert_not_called()
            unlink.assert_called_once_with("temporary")

    def test_sarif_rule_indexes_resolve(self):
        result = self.build(
            raw(
                detector(),
                detector(check="tx-origin", impact="Low"),
            ),
            policy(
                required=[("src/other.sol", "missing")]
            ),
        )
        run = a.to_sarif(result)["runs"][0]
        for finding in run["results"]:
            self.assertEqual(
                run["tool"]["driver"]["rules"][
                    finding["ruleIndex"]
                ]["id"],
                finding["ruleId"],
            )
        self.assertTrue(
            run["invocations"][0]["executionSuccessful"]
        )
        self.assertEqual(
            run["properties"]["auditStatus"], "failed"
        )


if __name__ == "__main__":
    unittest.main()
