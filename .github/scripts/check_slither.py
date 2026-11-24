#!/usr/bin/env python3
"""CI gate for Slither output on evm-audit-lab.

CI runs Slither with --fail-none and checks the resulting report here.
This script turns the raw JSON report into the checks that actually
matter for a security-teaching repository:

1. POSITIVE (lab integrity) — each tool-visible signal selected for a lab
   is really detected on its `Vulnerable*` contract. Some signals check a
   companion behaviour or exploit consequence, not the lab's core lesson.

2. COVERAGE and NEGATIVE (safe regression) — compilation metadata must show
   that every `Safe*` counterpart was scanned, and selected companion
   behaviour detectors must stay silent on their safe counterpart.

3. TRIAGE (scope separation) — every remaining High/Medium finding on a
   `Safe*` contract fails until individually reviewed. `ACCEPTED` contains
   only findings with a written, evidence-backed decision in the triage
   record. Each exception identifies one finding (file + detector + line
   range) and carries a parsed expiry date the gate enforces; an expired
   exception fails just like an untriaged finding.

Manual-only vulnerability classes are shown as skipped — tool output is a
lead for manual verification, never a proof of safety.

Usage: check_slither.py [path/to/slither-report.json]
"""
from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_REPORT_BYTES = 16 * 1024 * 1024
IMPACT_RANK = {
    "Optimization": 0,
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
}

# --- 1. POSITIVE: lab lesson signals, including companion behaviour. ---
REQUIRED_DETECTIONS: list[tuple[str, str]] = [
    ("src/VulnerableVault.sol", "reentrancy-eth"),        # Lab 01 core lesson — reentrancy
    ("src/VulnerableAccess.sol", "tx-origin"),            # Lab 02 core lesson — tx.origin auth
    ("src/VulnerableAccess.sol", "arbitrary-send-eth"),   # Lab 02 companion — auth bypass consequence
    ("src/VulnerableAmm.sol", "unchecked-transfer"),      # Lab 06 companion: token IO; core slippage lesson is manual
    ("src/VulnerableRouter.sol", "unchecked-transfer"),   # Lab 10 core lesson — discarded bool
    ("src/VulnerableUupsVault.sol", "controlled-delegatecall"),  # Lab 14 companion: upgrade target
    ("src/VulnerableUupsVault.sol", "arbitrary-send-eth"),      # Lab 14 companion: takeover consequence; initializer lesson is manual
]

# Source inventory is emitted by Slither's pinned compilation export. Findings
# alone cannot prove a source was scanned because clean sources emit no finding.
SAFE_COUNTERPARTS: tuple[str, ...] = (
    "src/SafeAccess.sol",
    "src/SafeAmm.sol",
    "src/SafeFotVault.sol",
    "src/SafeLending.sol",
    "src/SafeMint.sol",
    "src/SafePool.sol",
    "src/SafeProxy.sol",
    "src/SafeRouter.sol",
    "src/SafeSignature.sol",
    "src/SafeSplitter.sol",
    "src/SafeSwap.sol",
    "src/SafeUupsVault.sol",
    "src/SafeVault.sol",
    "src/SafeVault4626.sol",
)

# --- 2. NEGATIVE: tool-visible companion behaviours on safe counterparts. ---
FORBIDDEN_ON_SAFE: dict[str, list[str]] = {
    "src/SafeVault.sol": ["reentrancy-eth"],
    "src/SafeAccess.sol": ["tx-origin", "arbitrary-send-eth"],
    "src/SafeAmm.sol": ["unchecked-transfer"],  # Companion: checked token-call results, not slippage
    "src/SafeRouter.sol": ["unchecked-transfer"],
    "src/SafeUupsVault.sol": ["arbitrary-send-eth"],  # Companion: guarded withdrawal destination
}

# These concepts are manual checks, not Slither gates. The proxy-storage
# collision identifier is absent from Slither 0.11.6's detector catalog.
SKIPPED_CHECKS: tuple[tuple[str, str, str, str], ...] = (
    ("Lab 03", "src/SafePool.sol", "flash-loan price manipulation", "economic logic; manual tests/reasoning"),
    ("Lab 04", "src/SafeLending.sol", "stale-oracle manipulation", "economic logic; manual tests/reasoning"),
    ("Lab 05", "src/SafePool.sol", "first-depositor rounding inflation", "numeric intent; manual reasoning"),
    ("Lab 06", "src/SafeAmm.sol", "slippage / sandwich resistance", "economic behaviour; manual tests/reasoning"),
    ("Lab 07", "src/SafeProxy.sol", "proxy-storage-collision", "not in Slither 0.11.6 detector catalog"),
    ("Lab 08", "src/SafeSignature.sol", "signature replay", "off-chain signature semantics; manual tests/reasoning"),
    ("Lab 09", "src/SafeMint.sol", "missing access control on mint", "authorization intent; manual reasoning"),
    ("Lab 11", "src/SafeVault4626.sol", "share-price inflation", "numeric intent; manual reasoning"),
    ("Lab 12", "src/SafeSplitter.sol", "unbounded-loop gas DoS", "liveness and gas economics; manual reasoning"),
    ("Lab 13", "src/SafeFotVault.sol", "fee-on-transfer accounting", "integration semantics; manual reasoning"),
    ("Lab 14", "src/SafeUupsVault.sol", "unguarded initializer", "initialization semantics; manual reasoning"),
)

TEACHING_NOTE = """
Manual-only core lessons (SKIPPED by the detector gate): flash-loan and stale-oracle
manipulation, first-depositor rounding inflation, slippage/sandwich resistance,
proxy storage collision, signature replay, missing mint access control, share-price
inflation, unbounded-loop gas DoS, fee-on-transfer accounting, and the unguarded
UUPS initializer. `proxy-storage-collision` is not in Slither 0.11.6's catalog.
Slither findings are leads for manual review, not proof of safety.
"""

# --- 3. TRIAGE: individually documented Safe* findings may be accepted. ---
# Each exception identifies ONE finding: its key is the stable finding
# identifier (source file + detector + line range), so two sites under one
# (file, check) pair need two entries. `expires` is a parsed date the gate
# enforces (expired -> FAIL); the reason text no longer embeds the
# metadata. The matching triage record lives in docs/slither-triage.md
# under the entry's anchor; tests/test_check_slither.py enforces parity
# between this table and that record (count, sites, owners, expiries).


@dataclass(frozen=True)
class AcceptedFinding:
    reason: str
    owner: str
    expires: date
    anchor: str


ACCEPTED: dict[tuple[str, str, str], AcceptedFinding] = {
    (
        "src/SafeFotVault.sol",
        "incorrect-equality",
        "36-45",
    ): AcceptedFinding(
        reason="The zero check rejects a zero computed receipt after the balance-delta guard; donations increase the credited receipt; see docs/slither-triage.md#accepted-1",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-1",
    ),
    (
        "src/SafeFotVault.sol",
        "reentrancy-balance",
        "47-58",
    ): AcceptedFinding(
        reason="The shared lock blocks callbacks, state updates precede transfer, and balance mismatches revert; see docs/slither-triage.md#accepted-2",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-2",
    ),
    (
        "src/SafeLending.sol",
        "divide-before-multiply",
        "65-74",
    ): AcceptedFinding(
        reason="Downward rounding at both steps makes the borrow limit conservative and cannot enable over-borrowing; see docs/slither-triage.md#accepted-3",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-3",
    ),
    (
        "src/SafeLending.sol",
        "unused-return",
        "108-123",
    ): AcceptedFinding(
        reason="Sequencer status and grace time are checked while primary-feed round completeness is validated; see docs/slither-triage.md#accepted-5",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-5",
    ),
    (
        "src/SafeSwap.sol",
        "incorrect-equality",
        "57-75",
    ): AcceptedFinding(
        reason="Observation maintenance bounds the count to one or two, making equality to two sufficient; see docs/slither-triage.md#accepted-7",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-7",
    ),
    (
        "src/SafeUupsVault.sol",
        "controlled-delegatecall",
        "56-75",
    ): AcceptedFinding(
        reason="UUPS upgrade calls require proxy context, owner authorization, and UUID compatibility; see docs/slither-triage.md#accepted-8",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-8",
    ),
    (
        "src/SafeVault4626.sol",
        "incorrect-equality",
        "49-64",
    ): AcceptedFinding(
        reason="Deposits revert unless measured receipts match requested assets, preserving the exact-transfer assumption; see docs/slither-triage.md#accepted-9",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-9",
    ),
    (
        "src/SafeVault4626.sol",
        "reentrancy-balance",
        "66-84",
    ): AcceptedFinding(
        reason="The shared lock blocks callbacks, shares burn before transfer, and balance mismatches revert; see docs/slither-triage.md#accepted-10",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-10",
    ),
    (
        "src/SafeFotVault.sol",
        "reentrancy-balance",
        "36-45",
    ): AcceptedFinding(
        reason="`deposit` is guarded by the shared `nonReentrant` lock, so no callback can re-enter while the deposit is in flight; the post-call balance checks (`afterBalance < beforeBalance`, `received == 0`) only ever revert (fail-closed) and the credit is the measured `afterBalance - beforeBalance`; see docs/slither-triage.md#accepted-11",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-11",
    ),
    (
        "src/SafeVault4626.sol",
        "reentrancy-balance",
        "49-64",
    ): AcceptedFinding(
        reason="`deposit` is guarded by the shared `nonReentrant` lock; shares mint only from the measured receipt after `transferFrom` settles, and the post-call checks (`assetsAfter < assetsBefore`, `received == assets`, `minted > 0`) only ever revert; see docs/slither-triage.md#accepted-12",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-12",
    ),
    (
        "src/SafeLending.sol",
        "unused-return",
        "76-90",
    ): AcceptedFinding(
        reason="Base `_validatedPrice` ignores only the third return value (`startedAt`) of `oracle.latestRoundData()`; freshness is established via `updatedAt` (nonzero, not future, within the staleness window) and round completeness via `answeredInRound >= roundId`, so `startedAt` adds nothing for the primary feed; see docs/slither-triage.md#accepted-13",
        owner="DefiAudit0x",
        expires=date(2027, 5, 21),
        anchor="accepted-13",
    ),
}


def attributed_paths(paths):
    """Return each distinct source path associated with a finding.

    This is the single shared policy-attribution entry point for both
    this gate and audit_report.py: callers must pass paths from the
    structured source mappings only. A Slither `first_markdown_element`
    anchor is display-only and must never be passed here (m-22).
    """
    return tuple(dict.fromkeys(paths))

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        reject_constant(value)
    return number


def _safe_relative_source(filename: str) -> str | None:
    if not isinstance(filename, str) or not filename.strip() or "\0" in filename:
        return None
    path = (ROOT / filename.replace("\\", "/")).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return None


@dataclass(frozen=True)
class SiteFinding:
    """One detector result at one attributed source site.

    `start_line`/`end_line` are the first element's line range in `path`
    (the function the detector names); both are None when the report
    carries no location for the site, which can never match an exception.
    """

    path: str
    check: str
    impact: str
    start_line: int | None
    end_line: int | None

    @property
    def lines(self) -> str | None:
        if self.start_line is None or self.end_line is None:
            return None
        return f"{self.start_line}-{self.end_line}"


def _site_span(det: dict, path: str) -> tuple[int, int] | None:
    """Line range of the first element attributed to path, else None.

    Only the structured source mapping supplies a span. The Markdown
    anchor is display-only (m-22): its line range must not satisfy a
    triage entry, so a site with no mapped lines has no span and can
    never match an exception.
    """
    for element in det.get("elements", []):
        mapping = element.get("source_mapping") if isinstance(element, dict) else None
        filename = mapping.get("filename_relative") if isinstance(mapping, dict) else None
        if _safe_relative_source(filename) != path:
            continue
        lines = mapping.get("lines")
        if (
            isinstance(lines, list)
            and lines
            and all(type(n) is int and n > 0 for n in lines)
        ):
            return min(lines), max(lines)
    return None


def triage_findings(findings, accepted=None, today=None):
    """Decide each Safe* High/Medium site: allowed, untriaged, or expired.

    Returns a list of (finding, status, entry); status is "allowed" when a
    matching exception exists and has not expired, "expired" when the only
    match is past its expiry, and "untriaged" otherwise. `accepted`
    defaults to ACCEPTED; `today` defaults to the current date.
    """
    if accepted is None:
        accepted = ACCEPTED
    if today is None:
        today = date.today()
    decisions = []
    for finding in sorted(
        findings,
        key=lambda f: (f.path, f.check, f.start_line or 0, f.end_line or 0),
    ):
        if not Path(finding.path).name.startswith("Safe"):
            continue
        if finding.impact not in ("High", "Medium"):
            continue
        entry = None
        if finding.lines is not None:
            entry = accepted.get((finding.path, finding.check, finding.lines))
        if entry is None:
            decisions.append((finding, "untriaged", None))
        elif entry.expires < today:
            decisions.append((finding, "expired", entry))
        else:
            decisions.append((finding, "allowed", entry))
    return decisions


def read_report(report_path: str) -> tuple[list[SiteFinding], set[str]]:
    with open(report_path, "rb") as fh:
        raw = fh.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds 16 MiB")
    report = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    if report.get("success") is not True or report.get("error") not in (None, ""):
        raise ValueError(f"analysis did not succeed: {report.get('error')!r}")
    results = report.get("results")
    if not isinstance(results, dict) or not isinstance(results.get("detectors"), list):
        raise ValueError("results.detectors must be a list")

    compilations = results.get("compilations")
    if not isinstance(compilations, list) or not compilations:
        raise ValueError("results.compilations must contain Slither compilation metadata")
    scanned_sources: set[str] = set()
    for compilation_index, compilation in enumerate(compilations):
        units = compilation.get("compilation_units") if isinstance(compilation, dict) else None
        if not isinstance(units, dict) or not units:
            raise ValueError(f"compilation {compilation_index} has no compilation_units")
        for unit_index, unit in enumerate(units.values()):
            source_units = unit.get("source_units") if isinstance(unit, dict) else None
            if not isinstance(source_units, dict) or not source_units:
                raise ValueError(
                    f"compilation {compilation_index} unit {unit_index} has no source_units"
                )
            for source in source_units:
                relative = _safe_relative_source(source)
                if relative is not None:
                    scanned_sources.add(relative)

    sites: dict[tuple[str, str, int | None, int | None], str] = {}
    for index, det in enumerate(results["detectors"]):
        if not isinstance(det, dict):
            raise ValueError(f"detector {index} must be an object")
        check, impact = det.get("check"), det.get("impact")
        if not isinstance(check, str) or not check.strip():
            raise ValueError(f"detector {index} has no check identifier")
        if not isinstance(impact, str) or impact not in IMPACT_RANK:
            raise ValueError(f"detector {index} has invalid impact")
        elements = det.get("elements")
        if not isinstance(elements, list):
            raise ValueError(f"detector {index} elements must be a list")
        if not elements and IMPACT_RANK[impact] >= IMPACT_RANK["Medium"]:
            raise ValueError(f"cannot attribute {impact} finding {check}")
        paths = []
        for element in elements:
            mapping = element.get("source_mapping") if isinstance(element, dict) else None
            filename = mapping.get("filename_relative") if isinstance(mapping, dict) else None
            if not isinstance(filename, str) or not filename.strip() or "\0" in filename:
                raise ValueError(f"detector {index} has invalid source_mapping.filename_relative")
            relative = _safe_relative_source(filename)
            if relative is None:
                continue  # Source is outside the repository.
            paths.append(relative)
        for relative in attributed_paths(paths):
            span = _site_span(det, relative)
            start, end = span if span is not None else (None, None)
            key = (relative, check, start, end)
            if key not in sites or IMPACT_RANK[impact] > IMPACT_RANK[sites[key]]:
                sites[key] = impact
    findings = [
        SiteFinding(path, check, impact, start, end)
        for (path, check, start, end), impact in sites.items()
    ]
    return findings, scanned_sources


def main(argv=None, accepted=None) -> int:
    if argv is None:
        argv = sys.argv
    report_path = argv[1] if len(argv) > 1 else "slither-report.json"
    try:
        findings, scanned_sources = read_report(report_path)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: cannot read Slither report '{report_path}': {exc}")
        print("Slither must run with --json-types detectors,compilations before this checker.")
        return 1

    failures: list[str] = []

    pair_impact: dict[tuple[str, str], str] = {}
    for finding in findings:
        key = (finding.path, finding.check)
        if key not in pair_impact or IMPACT_RANK[finding.impact] > IMPACT_RANK[pair_impact[key]]:
            pair_impact[key] = finding.impact

    print("=== 0. Safe counterpart coverage: every counterpart must be scanned ===")
    for path in SAFE_COUNTERPARTS:
        scanned = path in scanned_sources
        print(f"  {'SCANNED (OK)' if scanned else 'MISSING (FAIL)'} {path}")
        if not scanned:
            failures.append(f"report has no scan evidence for safe counterpart {path}")

    print("=== 1. Lab detector signals must be present ===")
    for path, check in REQUIRED_DETECTIONS:
        impact = pair_impact.get((path, check))
        status = f"OK   [{impact}] {check}" if impact else "MISSING"
        print(f"  {status} on {path}")
        if not impact:
            failures.append(f"{check} no longer fires on {path}")

    print("\n=== 2. Safe regression: selected companion behaviour checks ===")
    for path, checks in FORBIDDEN_ON_SAFE.items():
        for check in checks:
            fired = (path, check) in pair_impact
            print(f"  {'FIRED  (FAIL)' if fired else 'silent (OK)  '} {check} on {path}")
            if fired:
                failures.append(f"{check} fired on safe contract {path}")

    print("\n=== Manual-only core lessons: skipped ===")
    for lab, path, check, reason in SKIPPED_CHECKS:
        print(f"  SKIP {lab} {check} on {path} ({reason})")

    print("\n=== 3. Triage: High/Medium on Safe* must be allowlisted ===")
    for finding, status, entry in triage_findings(findings, accepted=accepted):
        label = finding.lines or "location unknown"
        if status == "allowed":
            print(f"  ALLOWED [{finding.impact}] {finding.check} on {finding.path} ({label})")
            print(f"           -> {entry.reason} [{entry.anchor}, owner {entry.owner}, expires {entry.expires.isoformat()}]")
        elif status == "expired":
            print(f"  EXPIRED [{finding.impact}] {finding.check} on {finding.path} ({label})")
            print(f"           -> exception {entry.anchor} expired on {entry.expires.isoformat()}")
            failures.append(
                f"exception for {finding.check} on {finding.path} ({label}) expired on {entry.expires.isoformat()} "
                "(renew the triage decision or fix the finding)"
            )
        else:
            print(f"  UNTRIAGED [{finding.impact}] {finding.check} on {finding.path} ({label})")
            failures.append(
                f"untriaged {finding.impact} finding {finding.check} on {finding.path} ({label}) "
                "(fix it or document and evidence a specific exception before accepting it)"
            )

    print()
    if failures:
        print(f"RESULT: FAIL — {len(failures)} problem(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: PASS — lab detections present, safe contracts clean/triaged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
