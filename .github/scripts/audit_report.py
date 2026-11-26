#!/usr/bin/env python3
"""Validated Slither audit reports. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
from datetime import date
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote

from check_slither import (
    ACCEPTED,
    FORBIDDEN_ON_SAFE,
    REQUIRED_DETECTIONS,
    TEACHING_NOTE,
    attributed_paths,
)

VERSION = "1.0.0"
SEVERITIES = ("optimization", "informational", "low", "medium", "high")
RANK = {value: index for index, value in enumerate(SEVERITIES)}
LEVEL = dict(zip(SEVERITIES, ("note", "note", "note", "warning", "error")))
RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


class AuditError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def nonempty(value, label):
    require(
        isinstance(value, str) and bool(value.strip()),
        f"{label}: expected nonempty string",
    )
    return value


def rule_id(value):
    require(
        isinstance(value, str) and RULE.fullmatch(value) is not None,
        "check: expected a detector identifier",
    )
    return value


LINE_RANGE = re.compile(r"[1-9][0-9]*-[1-9][0-9]*")


def line_range(value):
    require(
        isinstance(value, str) and LINE_RANGE.fullmatch(value) is not None,
        "lines: expected a start-end line range",
    )
    start, end = (int(part) for part in value.split("-"))
    require(end >= start, "lines: end must not precede start")
    return value


def expiry_date(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None,
        "expires: expected a YYYY-MM-DD date",
    )
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise AuditError(f"expires: invalid date {value!r}") from exc
    return value


def source_path(value, root):
    value = nonempty(value, "source path").replace("\\", "/")
    require(
        not any(ord(char) < 32 for char in value),
        "source path contains control characters",
    )
    require(
        not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value),
        "source path must be a local path",
    )
    if value.startswith("/"):
        try:
            value = Path(value).resolve().relative_to(root).as_posix()
        except ValueError as exc:
            raise AuditError("source path is outside --root") from exc
    value = posixpath.normpath(value)
    require(
        value not in (".", "..") and not value.startswith("../"),
        "source path escapes --root or names a directory",
    )
    return value


def object_fields(value, allowed, required, label):
    require(isinstance(value, dict), f"{label}: expected object")
    require(
        not (value.keys() - allowed),
        f"{label}: unknown fields {sorted(value.keys() - allowed)}",
    )
    require(
        not (required - value.keys()),
        f"{label}: missing fields {sorted(required - value.keys())}",
    )


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise AuditError(f"non-finite JSON number: {value}")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        reject_constant(value)
    return number


def read_json(path, stdin=False):
    try:
        content = (
            sys.stdin.read()
            if stdin and str(path) == "-"
            else Path(path).read_text(encoding="utf-8-sig")
        )
        return json.loads(
            content,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise AuditError(f"cannot read JSON from {path}: {exc}") from exc


def load_policy(path, root):
    policy = {
        "schema_version": 1,
        "required_detections": [
            {"path": p, "check": c} for p, c in REQUIRED_DETECTIONS
        ],
        "forbidden_on_safe": {
            p: list(checks) for p, checks in FORBIDDEN_ON_SAFE.items()
        },
        "allowed_on_safe": [
            {
                "path": p,
                "check": c,
                "lines": lines,
                "reason": entry.reason,
                "owner": entry.owner,
                "expires": entry.expires.isoformat(),
                "anchor": entry.anchor,
            }
            for (p, c, lines), entry in ACCEPTED.items()
        ],
    }
    if path is not None:
        supplied = read_json(path)
        object_fields(
            supplied,
            set(policy),
            {"schema_version"},
            "configuration",
        )
        policy.update(supplied)
    require(
        type(policy["schema_version"]) is int
        and policy["schema_version"] == 1,
        "configuration.schema_version must be 1",
    )

    def entries(value, kind, label):
        require(isinstance(value, list), f"{label}: expected array")
        seen, result = set(), []
        fields = (
            {"path", "check"}
            if kind == "required"
            else {"path", "check", "lines", "reason", "owner", "expires", "anchor"}
        )
        for item in value:
            object_fields(item, fields, fields, label)
            entry = {
                "path": source_path(item["path"], root),
                "check": rule_id(item["check"]),
            }
            if kind == "allowed":
                entry["lines"] = line_range(item["lines"])
                pair = (entry["path"], entry["check"], entry["lines"])
            else:
                pair = (entry["path"], entry["check"])
            require(pair not in seen, f"{label}: duplicate {pair}")
            seen.add(pair)
            if kind == "allowed":
                require(
                    PurePosixPath(entry["path"]).name.startswith("Safe"),
                    "allowed_on_safe paths must name Safe* files",
                )
                entry["reason"] = nonempty(
                    item["reason"], "allowlist reason"
                ).strip()
                entry["owner"] = nonempty(
                    item["owner"], "allowlist owner"
                ).strip()
                entry["expires"] = expiry_date(item["expires"])
                entry["anchor"] = nonempty(
                    item["anchor"], "allowlist anchor"
                ).strip()
            result.append(entry)
        return sorted(
            result,
            key=lambda item: (
                item["path"],
                item["check"],
                item.get("lines", ""),
            ),
        )

    policy["required_detections"] = entries(
        policy["required_detections"],
        "required",
        "required_detections",
    )
    policy["allowed_on_safe"] = entries(
        policy["allowed_on_safe"],
        "allowed",
        "allowed_on_safe",
    )

    require(
        isinstance(policy["forbidden_on_safe"], dict),
        "forbidden_on_safe: expected object",
    )
    forbidden = {}
    for path, checks in policy["forbidden_on_safe"].items():
        path = source_path(path, root)
        require(
            path not in forbidden,
            f"forbidden_on_safe: duplicate normalized path {path}",
        )
        require(
            isinstance(checks, list),
            f"forbidden_on_safe.{path}: expected array",
        )
        checks = [rule_id(check) for check in checks]
        require(
            len(checks) == len(set(checks)),
            f"forbidden_on_safe.{path}: duplicate detector",
        )
        forbidden[path] = sorted(checks)
    policy["forbidden_on_safe"] = dict(sorted(forbidden.items()))

    denied = {
        (p, c)
        for p, checks in forbidden.items()
        for c in checks
    }
    for item in (
        policy["required_detections"] + policy["allowed_on_safe"]
    ):
        require(
            (item["path"], item["check"]) not in denied,
            "conflicting required/allowed and forbidden rule: "
            f"{item['path']} {item['check']}",
        )
    return policy


def location(path, root, lines=None):
    result = {"path": source_path(path, root)}
    if lines is not None:
        require(
            isinstance(lines, list)
            and all(type(n) is int and n > 0 for n in lines),
            "source_mapping.lines: expected positive integer array",
        )
        if lines:
            result.update(
                start_line=min(lines),
                end_line=max(lines),
            )
    return result


def site_lines(item, path):
    """Line range ("start-end") of item's first location in path, or None."""
    for location in item["locations"]:
        if location["path"] == path and "start_line" in location:
            return f"{location['start_line']}-{location['end_line']}"
    return None


def parse_findings(raw, root):
    require(isinstance(raw, dict), "Slither report must be an object")
    require(
        raw.get("success") is True,
        "Slither did not complete successfully",
    )
    require(
        raw.get("error") in (None, ""),
        f"Slither error: {raw.get('error')}",
    )
    results = raw.get("results")
    require(
        isinstance(results, dict)
        and isinstance(results.get("detectors", []), list),
        "results.detectors must be an array",
    )

    findings = {}
    for index, detector in enumerate(results.get("detectors", [])):
        require(
            isinstance(detector, dict),
            f"detector {index}: expected object",
        )
        check = rule_id(detector.get("check"))
        severity = nonempty(
            detector.get("impact"), "impact"
        ).lower()
        require(severity in RANK, f"unknown impact: {severity}")

        confidence = nonempty(
            detector.get("confidence", "unknown"),
            "confidence",
        ).lower()
        require(
            confidence in ("high", "medium", "low", "unknown"),
            "unknown confidence",
        )
        message = nonempty(
            detector.get("description"), "description"
        ).strip()
        elements = detector.get("elements", [])
        require(
            isinstance(elements, list),
            "elements must be an array",
        )

        locations = []
        for element in elements:
            require(
                isinstance(element, dict),
                "element must be an object",
            )
            mapping = element.get("source_mapping")
            if mapping is None:
                continue
            require(
                isinstance(mapping, dict),
                "source_mapping must be an object",
            )
            filename = next(
                (
                    mapping.get(key)
                    for key in (
                        "filename_relative",
                        "filename_short",
                        "filename_absolute",
                    )
                    if mapping.get(key)
                ),
                None,
            )
            require(
                filename is not None,
                "source_mapping is missing a filename",
            )
            locations.append(
                location(filename, root, mapping.get("lines"))
            )

        # Policy attribution uses the structured source mappings ONLY.
        # `first_markdown_element` is a display hint: it is kept verbatim
        # for display and never contributes a location, so an anchor-only
        # path cannot satisfy a required detection or a triage entry
        # (m-22). This report and check_slither.py both attribute findings
        # through the shared `attributed_paths` helper over structured
        # paths only.
        anchor = detector.get("first_markdown_element")
        if anchor is not None:
            require(
                isinstance(anchor, str),
                "first_markdown_element must be a string",
            )

        require(
            bool(locations),
            f"detector {index}: no source location",
        )
        unique = []
        for item in locations:
            if item not in unique:
                unique.append(item)
        primary = unique[0]
        related = sorted(
            unique[1:],
            key=lambda item: (
                item["path"],
                item.get("start_line", 0),
                item.get("end_line", 0),
            ),
        )
        canonical = {
            "check": check,
            "severity": severity,
            "confidence": confidence,
            "message": message,
            "locations": [primary] + related,
        }
        key = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                ensure_ascii=True,
            ).encode()
        ).hexdigest()
        # The Markdown anchor is display-only metadata: it is recorded
        # verbatim but excluded from the canonical finding (and therefore
        # from the finding id), so it can never affect policy.
        finding = {"id": key, **canonical}
        if anchor:
            finding["markdown_anchor"] = anchor
        findings[key] = finding

    return sorted(
        findings.values(),
        key=lambda item: (
            -RANK[item["severity"]],
            item["locations"][0]["path"],
            item["locations"][0].get("start_line", 0),
            item["check"],
            item["id"],
        ),
    )


def collect_research(
    root,
    build_dir,
    test_results,
    seed,
    source_revision=None,
    source_dirty=None,
):
    """Collect provenance and Foundry output for an audit report.

    The build directory and test results are caller-supplied paths: the
    exporter records their contents but does not verify they were
    produced from the recorded revision in the same run (m-23). A
    caller-supplied revision is therefore labelled unverified; only a
    revision read by the exporter from its own checkout is labelled
    exporter-checkout, and even then the input artifacts remain
    caller-supplied (see `inputs_provenance`).
    """
    def command(*args):
        try:
            return subprocess.check_output(args, cwd=root, text=True).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise AuditError(f"cannot collect {' '.join(args)}: {exc}") from exc

    layouts = {}
    compilers = {}
    for path in sorted(build_dir.glob("*/*.json")):
        artifact = read_json(path)
        if "storageLayout" not in artifact:
            continue
        metadata = artifact["metadata"]
        settings = dict(metadata["settings"])
        targets = settings.pop("compilationTarget")
        for source, contract in targets.items():
            if source.startswith("src/"):
                key = f"{source}:{contract}"
                layouts[key] = artifact["storageLayout"]
                compilers[key] = {"version": metadata["compiler"]["version"], **settings}
    require(layouts, "no src/ storage layouts; build with --extra-output storageLayout")

    tests = read_json(test_results)
    require(isinstance(tests, dict) and tests, "expected Foundry test suites")
    counterexamples = {
        f"{suite}::{name}": result["counterexample"]
        for suite, data in tests.items()
        for name, result in data["test_results"].items()
        if result.get("counterexample") is not None
    }
    return {
        "tool_versions": {
            "audit_report": VERSION,
            "python": sys.version.split()[0],
            "forge": command("forge", "--version").splitlines()[0],
            "slither": command("slither", "--version"),
        },
        "compiler_settings": compilers,
        "source_revision": source_revision if source_revision is not None else command("git", "rev-parse", "HEAD"),
        "source_dirty": source_dirty if source_dirty is not None else bool(command("git", "status", "--porcelain")),
        "source_revision_origin": "provided-unverified" if source_revision is not None else "exporter-checkout",
        "inputs_provenance": "caller-supplied, unverified",
        "test_seeds": {"foundry_fuzz_seed": seed},
        "minimal_counterexamples": counterexamples,
        "storage_layouts": layouts,
    }


def base_report():
    return {
        "schema_version": "1.0",
        "tool": {
            "name": "evm-audit-lab",
            "version": VERSION,
        },
        "status": "error",
        "summary": {
            "findings": 0,
            "by_severity": {
                s: 0 for s in reversed(SEVERITIES)
            },
            "failed_gates": 0,
            "threshold_failures": 0,
        },
        "findings": [],
        "gates": [],
        "errors": [],
        "notes": [TEACHING_NOTE.strip()],
    }


def build_report(findings, policy, threshold="none", today=None):
    if today is None:
        today = date.today()
    report = base_report()
    report["configuration"] = policy
    report["findings"] = findings

    observed = {
        (path, item["check"])
        for item in findings
        for path in attributed_paths(
            location["path"] for location in item["locations"]
        )
    }
    required = {
        (item["path"], item["check"])
        for item in policy["required_detections"]
    }
    forbidden = {
        (p, c)
        for p, checks in policy["forbidden_on_safe"].items()
        for c in checks
    }
    allowed = {
        (item["path"], item["check"], item["lines"]): item
        for item in policy["allowed_on_safe"]
    }

    def gate(kind, path, check, passed, message):
        report["gates"].append(
            {
                "kind": kind,
                "path": path,
                "check": check,
                "status": "passed" if passed else "failed",
                "message": message,
            }
        )

    for path, check in sorted(required):
        present = (path, check) in observed
        gate(
            "required-detection",
            path,
            check,
            present,
            (
                "Expected detector fired."
                if present
                else "Expected detector did not fire."
            ),
        )

    for path, checks in policy["forbidden_on_safe"].items():
        if not checks:
            report["gates"].append(
                {
                    "kind": "safe-regression",
                    "path": path,
                    "check": None,
                    "status": "skipped",
                    "message": "No class detector configured.",
                }
            )
        for check in checks:
            present = (path, check) in observed
            gate(
                "safe-regression",
                path,
                check,
                not present,
                (
                    "Detector fired on safe contract."
                    if present
                    else "Detector remained silent."
                ),
            )

    triage = {}
    for item in findings:
        dispositions = []
        for path in attributed_paths(
            location["path"] for location in item["locations"]
        ):
            pair = (path, item["check"])
            safe = PurePosixPath(path).name.startswith("Safe")
            disposition = "observation"
            site = site_lines(item, path)
            entry = allowed.get((path, item["check"], site)) if site else None
            expired = (
                entry is not None
                and date.fromisoformat(entry["expires"]) < today
            )
            if pair in forbidden:
                disposition = "regression"
            elif safe and entry is not None and not expired:
                disposition = "allowed"
                if path == item["locations"][0]["path"]:
                    item["justification"] = entry["reason"]
            elif safe and item["severity"] in ("high", "medium"):
                disposition = "untriaged"
            elif pair in required:
                disposition = "expected"
            dispositions.append(disposition)
            if safe and item["severity"] in ("high", "medium"):
                key = (path, item["check"], site)
                if key not in triage:
                    triage[key] = (disposition == "allowed", entry)

        item["disposition"] = next(
            (
                status
                for status in ("regression", "untriaged")
                if status in dispositions
            ),
            dispositions[0],
        )
        report["summary"]["by_severity"][item["severity"]] += 1

        if (
            threshold != "none"
            and item["disposition"] != "allowed"
            and RANK[item["severity"]] >= RANK[threshold]
        ):
            report["summary"]["threshold_failures"] += 1

    for (path, check, site), (accepted, entry) in sorted(
        triage.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or "")
    ):
        if accepted:
            message = entry["reason"]
        elif entry is not None:
            message = (
                f"exception {entry['anchor']} for {check} on {path} "
                f"({site}) expired on {entry['expires']}"
            )
        else:
            message = "High/Medium finding needs a written allowlist reason."
        gate(
            "safe-triage",
            path,
            check,
            accepted,
            message,
        )

    report["summary"]["findings"] = len(findings)
    report["summary"]["failed_gates"] = sum(
        g["status"] == "failed" for g in report["gates"]
    )
    report["status"] = (
        "failed"
        if (
            report["summary"]["failed_gates"]
            or report["summary"]["threshold_failures"]
        )
        else "passed"
    )
    return report


def sarif_location(item):
    physical = {
        "artifactLocation": {
            "uri": quote(item["path"], safe="/")
        }
    }
    if "start_line" in item:
        physical["region"] = {
            "startLine": item["start_line"],
            "endLine": item["end_line"],
        }
    return {"physicalLocation": physical}


def to_sarif(report):
    results = []

    for item in report["findings"]:
        result = {
            "ruleId": "slither/" + item["check"],
            "level": LEVEL[item["severity"]],
            "message": {"text": item["message"]},
            "locations": [
                sarif_location(item["locations"][0])
            ],
            "partialFingerprints": {
                "auditFinding/v1": item["id"]
            },
            "properties": {
                "severity": item["severity"],
                "confidence": item["confidence"],
                "auditDisposition": item["disposition"],
            },
        }

        if len(item["locations"]) > 1:
            result["relatedLocations"] = [
                {"id": index, **sarif_location(loc)}
                for index, loc in enumerate(
                    item["locations"][1:], 1
                )
            ]

        if item["disposition"] == "allowed":
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": item["justification"],
                }
            ]

        results.append(result)

    for gate in report["gates"]:
        if (
            gate["kind"] == "required-detection"
            and gate["status"] == "failed"
        ):
            results.append(
                {
                    "ruleId": "audit/missing-detection",
                    "level": "error",
                    "message": {
                        "text": (
                            f"{gate['check']}: "
                            f"{gate['message']}"
                        )
                    },
                    "locations": [
                        sarif_location({"path": gate["path"]})
                    ],
                    "partialFingerprints": {
                        "auditGate/v1": hashlib.sha256(
                            (
                                f"{gate['path']}:"
                                f"{gate['check']}"
                            ).encode()
                        ).hexdigest()
                    },
                }
            )

    ids = sorted({result["ruleId"] for result in results})
    indexes = {
        rule: index for index, rule in enumerate(ids)
    }
    for result in results:
        result["ruleIndex"] = indexes[result["ruleId"]]

    rules = []
    for rule in ids:
        levels = [
            result["level"]
            for result in results
            if result["ruleId"] == rule
        ]
        level = max(
            levels,
            key={"note": 0, "warning": 1, "error": 2}.__getitem__,
        )
        description = (
            "Expected lab detector missing"
            if rule.startswith("audit/")
            else (
                "Slither detector: "
                + rule.removeprefix("slither/")
            )
        )
        rules.append(
            {
                "id": rule,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": level},
            }
        )

    invocation = {
        "executionSuccessful": report["status"] != "error"
    }
    if report["errors"]:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {"text": message},
            }
            for message in report["errors"]
        ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report["tool"]["name"],
                        "version": VERSION,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "auditStatus": report["status"],
                    "summary": report["summary"],
                    "gates": report["gates"],
                    "notes": report["notes"],
                    **({"research": report["research"]} if "research" in report else {}),
                },
            }
        ],
    }


def md(value):
    value = html.escape(str(value), quote=False)
    return re.sub(
        r"([\\`*{}\[\]()#+.!_|>~-])",
        r"\\\1",
        value,
    ).replace("\n", "<br>")


def render(report, format):
    if format in ("json", "sarif"):
        return (
            json.dumps(
                to_sarif(report)
                if format == "sarif"
                else report,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        )

    if format == "text":
        lines = [
            f"EVM audit: {report['status'].upper()}",
            json.dumps(report["summary"], sort_keys=True),
        ]
        lines += [
            f"ERROR: {message}"
            for message in report["errors"]
        ]
        lines += [
            f"{g['status'].upper()} {g['kind']} "
            f"{g['path']} {g['check'] or '-'}: "
            f"{g['message']}"
            for g in report["gates"]
        ]
        lines += [
            f"{f['severity'].upper()} "
            f"[{f['disposition']}] {f['check']} "
            f"{f['locations'][0]['path']}: {f['message']}"
            for f in report["findings"]
        ]
        return "\n".join(lines + report["notes"]) + "\n"

    lines = [
        "# EVM Audit Report",
        "",
        f"Status: **{report['status'].upper()}**",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
    ]
    if "research" in report:
        lines[4:4] = [
            "## Reproducibility",
            "",
            "    " + json.dumps(report["research"], sort_keys=True, indent=2)
            .replace("\n", "\n    "),
            "",
        ]
    lines += [
        f"| {severity} | {count} |"
        for severity, count in (
            report["summary"]["by_severity"].items()
        )
    ]
    lines += [
        "",
        f"Failed gates: {report['summary']['failed_gates']}; "
        "severity threshold failures: "
        f"{report['summary']['threshold_failures']}.",
        "",
    ]
    lines += [
        f"> Error: {md(message)}"
        for message in report["errors"]
    ]
    lines += [
        "",
        "## Policy checks",
        "",
        "| Status | Kind | Source | Detector | Details |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {g['status']} | {g['kind']} | "
        f"{md(g['path'])} | {md(g['check'] or '-')} | "
        f"{md(g['message'])} |"
        for g in report["gates"]
    ]
    lines += ["", "## Findings", ""]

    if not report["findings"]:
        lines += [
            (
                "No findings were recorded."
                if not report["errors"]
                else "Analysis was incomplete."
            ),
            "",
        ]

    for item in report["findings"]:
        lines += [
            f"### {md(item['check'])} ({item['severity']})",
            "",
            f"Disposition: {item['disposition']}; "
            f"confidence: {item['confidence']}.",
            "",
            "> " + md(item["message"]),
            "",
        ]
        for loc in item["locations"]:
            suffix = (
                f":{loc['start_line']}-{loc['end_line']}"
                if "start_line" in loc
                else ""
            )
            lines += [f"- {md(loc['path'] + suffix)}"]
        if item.get("justification"):
            lines += [
                "",
                f"Triage: {md(item['justification'])}",
            ]
        lines += [""]

    lines += ["## Analysis limitations", ""]
    lines += [
        "> " + md(note) for note in report["notes"]
    ]
    return "\n".join(lines) + "\n"


def write_output(path, content):
    if str(path) == "-":
        sys.stdout.write(content)
        return

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".",
        dir=path.parent,
    )
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report",
        nargs="?",
        default="slither-report.json",
        help=(
            "Slither JSON file, or - for stdin "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "JSON policy overrides; omitted groups "
            "inherit defaults"
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Project root for source paths",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "sarif", "all"),
        default="text",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file, or - for stdout",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Required with --format all",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none",) + tuple(reversed(SEVERITIES)),
        default="none",
        help=(
            "Additional minimum severity gate; "
            "excludes allowlisted findings"
        ),
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help=(
            "Print validated effective configuration "
            "as JSON and exit without scanning"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument("--build-dir", type=Path, help="Foundry output with storageLayout")
    parser.add_argument("--test-results", type=Path, help="Foundry test --json output")
    parser.add_argument("--test-seed", help="Seed passed to Foundry via --fuzz-seed")
    parser.add_argument("--source-revision", help="Revision recorded when artifacts were generated")
    parser.add_argument("--source-dirty", choices=("true", "false"), help="Dirty state recorded when artifacts were generated")
    args = parser.parse_args(argv)
    if (args.source_revision is None) != (args.source_dirty is None):
        parser.error("--source-revision and --source-dirty must be supplied together")
    metadata_inputs = (args.build_dir, args.test_results, args.test_seed)
    if any(metadata_inputs) and (not all(metadata_inputs) or args.validate_config):
        parser.error("research exports require --build-dir, --test-results and --test-seed")

    if args.format == "all":
        if (
            args.output_dir is None
            or args.output != "-"
            or args.validate_config
        ):
            parser.error(
                "--format all requires --output-dir, "
                "with no --output or --validate-config"
            )
    elif args.output_dir is not None:
        parser.error("--output-dir requires --format all")

    root = args.root.resolve()
    if not root.is_dir():
        parser.error("--root must be an existing directory")

    outputs = (
        [
            (args.output_dir / name, format)
            for name, format in (
                ("report.json", "json"),
                ("report.md", "markdown"),
                ("report.sarif", "sarif"),
            )
        ]
        if args.format == "all"
        else [(args.output, args.format)]
    )

    protected = (
        {Path(args.report).resolve()}
        if args.report != "-"
        else set()
    )
    if args.config:
        protected.add(args.config.resolve())
    if args.test_results:
        protected.add(args.test_results.resolve())
    for path, _ in outputs:
        if (
            str(path) != "-"
            and (
                Path(path).resolve() in protected
                or (args.build_dir and args.build_dir.resolve() in Path(path).resolve().parents)
            )
        ):
            parser.error(
                "output would overwrite the input "
                "report or configuration"
            )

    report = base_report()
    try:
        policy = load_policy(args.config, root)
        if args.validate_config:
            write_output(
                args.output,
                json.dumps(
                    policy,
                    indent=2,
                    ensure_ascii=True,
                )
                + "\n",
            )
            return 0

        research = (
            collect_research(
                root,
                *metadata_inputs,
                args.source_revision,
                None if args.source_dirty is None else args.source_dirty == "true",
            )
            if all(metadata_inputs)
            else None
        )
        report = build_report(
            parse_findings(
                read_json(args.report, stdin=True),
                root,
            ),
            policy,
            args.fail_on,
        )
        if research is not None:
            report["research"] = research
    except (AuditError, KeyError, TypeError, AttributeError) as exc:
        report["errors"] = [str(exc)]
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        rendered = [
            (path, render(report, format))
            for path, format in outputs
        ]
        for path, content in rendered:
            write_output(path, content)
    except (OSError, UnicodeError) as exc:
        print(
            f"ERROR: cannot write report: {exc}",
            file=sys.stderr,
        )
        return 2

    return {
        "passed": 0,
        "failed": 1,
        "error": 2,
    }[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
