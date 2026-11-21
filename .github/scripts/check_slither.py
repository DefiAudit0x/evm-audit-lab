#!/usr/bin/env python3
"""CI gate for Slither output on evm-audit-lab.

CI runs Slither with --fail-none and checks the resulting report here.
This script turns the raw JSON report into the checks that actually
matter for a security-teaching repository:

1. POSITIVE (lab integrity) — each gateable lab's core vulnerability class
   is really detected on its `Vulnerable*` contract. If Slither stops
   flagging what the lab claims to teach, the lab or the detector drifted
   and CI must fail.

2. NEGATIVE (safe regression) — the `Safe*` counterpart of every gateable
   lab is free of its own class' detector, so a refactor can never
   silently reintroduce the lab's bug.

3. TRIAGE (scope separation) — every remaining High/Medium finding on a
   `Safe*` contract fails until individually reviewed. `ACCEPTED` contains
   only findings with a written, evidence-backed decision in the triage record.

Vulnerability classes that static analysis cannot see (oracle
manipulation, signature replay, missing access control, stale oracles)
produce a teaching note instead of a gate — tool output is a lead for
manual verification, never a proof of safety.

Usage: check_slither.py [path/to/slither-report.json]
"""
from __future__ import annotations

import json
import math
import sys
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

# --- 1. POSITIVE: the detector for each lab's core class must fire here. ---
REQUIRED_DETECTIONS: list[tuple[str, str]] = [
    ("src/VulnerableVault.sol", "reentrancy-eth"),        # Lab 01 — reentrancy
    ("src/VulnerableAccess.sol", "tx-origin"),            # Lab 02 — tx.origin auth
    ("src/VulnerableAccess.sol", "arbitrary-send-eth"),   # Lab 02 — consequence of tx.origin
    ("src/VulnerableAmm.sol", "unchecked-transfer"),      # Lab 06 — unguarded token IO
    ("src/VulnerableRouter.sol", "unchecked-transfer"),   # Lab 10 — discarded bool
    ("src/VulnerableUupsVault.sol", "controlled-delegatecall"),  # Lab 14 — owner-gated upgrade target
    ("src/VulnerableUupsVault.sol", "arbitrary-send-eth"),      # Lab 14 — unguarded initializer makes owner attacker-chosen
]

# --- 2. NEGATIVE: the class' detector must NOT fire on the Safe counterpart. ---
FORBIDDEN_ON_SAFE: dict[str, list[str]] = {
    "src/SafeVault.sol": ["reentrancy-eth"],
    "src/SafeAccess.sol": ["tx-origin", "arbitrary-send-eth"],
    "src/SafeAmm.sol": [],           # Lab 06's class (slippage) has no detector — see teaching note
    "src/SafeProxy.sol": ["proxy-storage-collision"],
    "src/SafeRouter.sol": ["unchecked-transfer"],
    "src/SafeVault4626.sol": [],     # Lab 11's class (share inflation) has no detector — see teaching note
    "src/SafeSplitter.sol": [],      # Lab 12's class (unbounded loop) has no detector — see teaching note
    "src/SafeFotVault.sol": [],      # Lab 13's class (fee-on-transfer accounting) has no detector — see teaching note
    "src/SafeUupsVault.sol": [],     # Lab 14's class (initializer guard) has no detector — see teaching note
}

# --- 3. TRIAGE: individually documented Safe* findings may be accepted. ---
ACCEPTED = {
    (
        "src/SafeFotVault.sol",
        "incorrect-equality",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: The zero check rejects a zero computed receipt after the balance-delta guard; donations increase the credited receipt; see docs/slither-triage.md#accepted-1",
    (
        "src/SafeFotVault.sol",
        "reentrancy-balance",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: The shared lock blocks callbacks, state updates precede transfer, and balance mismatches revert; see docs/slither-triage.md#accepted-2",
    (
        "src/SafeLending.sol",
        "divide-before-multiply",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Downward rounding at both steps makes the borrow limit conservative and cannot enable over-borrowing; see docs/slither-triage.md#accepted-3",
    (
        "src/SafeLending.sol",
        "locked-ether",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Collateral ETH has no recovery path in this educational debt-accounting model, which is not a custody product; see docs/slither-triage.md#accepted-4",
    (
        "src/SafeLending.sol",
        "unused-return",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Sequencer status and grace time are checked while primary-feed round completeness is validated; see docs/slither-triage.md#accepted-5",
    (
        "src/SafeProxy.sol",
        "locked-ether",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Proxy-held ETH has no recovery path in this storage-collision lab's minimal implementations; see docs/slither-triage.md#accepted-6",
    (
        "src/SafeSwap.sol",
        "incorrect-equality",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Observation maintenance bounds the count to one or two, making equality to two sufficient; see docs/slither-triage.md#accepted-7",
    (
        "src/SafeUupsVault.sol",
        "controlled-delegatecall",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: UUPS upgrade calls require proxy context, owner authorization, and UUID compatibility; see docs/slither-triage.md#accepted-8",
    (
        "src/SafeVault4626.sol",
        "incorrect-equality",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: Deposits revert unless measured receipts match requested assets, preserving the exact-transfer assumption; see docs/slither-triage.md#accepted-9",
    (
        "src/SafeVault4626.sol",
        "reentrancy-balance",
    ): "Accepted 2026-11-21, owner DefiAudit0x, expires 2027-05-21: The shared lock blocks callbacks, shares burn before transfer, and balance mismatches revert; see docs/slither-triage.md#accepted-10",
}


def attributed_paths(paths):
    """Return each distinct source path associated with a finding."""
    return tuple(dict.fromkeys(paths))

# Vulnerability classes with no Slither detector — printed, never gated.
TEACHING_NOTE = """
--- Classes static analysis does NOT see (lead, not proof) ---
  Lab 03/04 — flash-loan & stale-oracle price manipulation (economic logic)
  Lab 05     — first-depositor rounding inflation (numeric intent)
  Lab 07     — proxy storage collision layout (structural intent)
  Lab 08     — signature replay (off-chain signature semantics)
  Lab 09     — missing access control on mint (authorization intent)
  Lab 11     — ERC-4626 share-price inflation (numeric intent)
  Lab 12     — unbounded-loop gas DoS (liveness / gas economics)
  Lab 13     — fee-on-transfer accounting break (integration semantics)
  Lab 14     — unguarded UUPS initializer (initialization semantics)
These labs pair the tool with manual reasoning for exactly this reason.
"""


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


def read_findings(report_path: str) -> dict[tuple[str, str], str]:
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

    findings: dict[tuple[str, str], str] = {}
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
            path = (ROOT / filename.replace("\\", "/")).resolve()
            try:
                relative = path.relative_to(ROOT).as_posix()
            except ValueError:
                continue  # Source is outside the repository.
            paths.append(relative)
        for relative in attributed_paths(paths):
            key = (relative, check)
            if key not in findings or IMPACT_RANK[impact] > IMPACT_RANK[findings[key]]:
                findings[key] = impact
    return findings


def main() -> int:
    report_path = sys.argv[1] if len(sys.argv) > 1 else "slither-report.json"
    try:
        findings = read_findings(report_path)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: cannot read Slither report '{report_path}': {exc}")
        print("Slither must run with --json before this checker.")
        return 1

    failures: list[str] = []

    print("=== 1. Lab integrity: core classes must be detected ===")
    for path, check in REQUIRED_DETECTIONS:
        impact = findings.get((path, check))
        status = f"OK   [{impact}] {check}" if impact else "MISSING"
        print(f"  {status} on {path}")
        if not impact:
            failures.append(f"{check} no longer fires on {path}")

    print("\n=== 2. Safe regression: class detectors must stay silent ===")
    for path, checks in FORBIDDEN_ON_SAFE.items():
        if not checks:
            print(f"  SKIP {path} (class has no detector)")
            continue
        for check in checks:
            fired = (path, check) in findings
            print(f"  {'FIRED  (FAIL)' if fired else 'silent (OK)  '} {check} on {path}")
            if fired:
                failures.append(f"{check} fired on safe contract {path}")

    print("\n=== 3. Triage: High/Medium on Safe* must be allowlisted ===")
    for (fpath, check), impact in sorted(findings.items()):
        if "/Safe" not in fpath or impact not in ("High", "Medium"):
            continue
        reason = ACCEPTED.get((fpath, check))
        if reason:
            print(f"  ALLOWED [{impact}] {check} on {fpath}")
            print(f"           -> {reason}")
        else:
            print(f"  UNTRIAGED [{impact}] {check} on {fpath}")
            failures.append(
                f"untriaged {impact} finding {check} on {fpath} "
                "(fix it or document and evidence a specific exception before accepting it)"
            )

    print(TEACHING_NOTE)

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
