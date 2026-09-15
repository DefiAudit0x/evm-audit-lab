#!/usr/bin/env python3
"""CI gate for Slither output on evm-audit-lab.

Slither exits non-zero whenever any finding exists — which is always the
case here, because half of the repository is intentionally vulnerable.
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
   `Safe*` contract needs an explicit allowlist entry with a reason. A
   Safe contract is remediated for *its* lab's vulnerability class, not
   for every class at once; out-of-scope findings are accepted in writing
   instead of hidden.

Vulnerability classes that static analysis cannot see (oracle
manipulation, signature replay, missing access control, stale oracles)
produce a teaching note instead of a gate — tool output is a lead for
manual verification, never a proof of safety.

Usage: check_slither.py [path/to/slither-report.json]
"""
from __future__ import annotations

import json
import sys

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

# --- 3. TRIAGE: accepted out-of-scope High/Medium findings on Safe contracts. ---
ALLOWED_ON_SAFE: dict[tuple[str, str], str] = {
    ("src/SafeAmm.sol", "unchecked-transfer"):
        "Lab 06's subject is slippage protection; raw token transfers are "
        "Lab 10's subject and are gated there on SafeRouter.",
    ("src/SafeAmm.sol", "reentrancy-no-eth"):
        "Assumes standard hook-free ERC-20 tokens; no state is mutated "
        "after the external calls.",
    ("src/SafeLending.sol", "divide-before-multiply"):
        "Intended collateral math: the unit price is derived once, then "
        "applied with floor rounding in the user-safe direction.",
    ("src/SafeLending.sol", "locked-ether"):
        "The lending pool custodies user ETH by design.",
    ("src/SafeLending.sol", "unused-return"):
        "The oracle's round data is destructured deliberately; the unused "
        "slots are answeredRound fields the pool does not consume.",
    ("src/SafeProxy.sol", "locked-ether"):
        "A proxy custodies the implementation's ETH by design.",
    ("src/SafeRouter.sol", "reentrancy-no-eth"):
        "Standard hook-free ERC-20 assumed; the entitlement state is "
        "updated immediately after the checked transfer returns.",
    ("src/SafeVault4626.sol", "reentrancy-no-eth"):
        "Standard hook-free ERC-20 assumed; shares are computed from "
        "pre-call state and written after the checked transfer returns.",
    ("src/SafeFotVault.sol", "reentrancy-balance"):
        "The balance-delta deposit pattern intentionally re-reads the token "
        "balance after the checked transfer; that observation IS the "
        "remediation, and no privileged accounting sits between the reads.",
    ("src/SafeSplitter.sol", "reentrancy-eth"):
        "A payout loop necessarily continues after transfers; each owed "
        "amount is zeroed before its transfer, so a reentrant distribute() "
        "call cannot double-pay anyone.",
    ("src/SafeUupsVault.sol", "controlled-delegatecall"):
        "Upgrade target is owner-gated by design — this is the UUPS "
        "pattern itself. Lab 14's subject is initializer protection, not "
        "eliminating the delegatecall.",
}

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


def normalize(element: str) -> str:
    """'src/SafeAmm.sol#48-69' -> 'src/SafeAmm.sol'."""
    return (element or "").split("#")[0]


def main() -> int:
    report_path = sys.argv[1] if len(sys.argv) > 1 else "slither-report.json"
    try:
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read Slither report '{report_path}': {exc}")
        print("Slither must run with --json before this checker.")
        return 1

    # (path, check) -> highest impact reported
    findings: dict[tuple[str, str], str] = {}
    for det in report.get("results", {}).get("detectors", []):
        path = normalize(det.get("first_markdown_element", ""))
        check, impact = det.get("check", "?"), det.get("impact", "?")
        key = (path, check)
        if key not in findings or impact == "High":
            findings[key] = impact

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
        reason = ALLOWED_ON_SAFE.get((fpath, check))
        if reason:
            print(f"  ALLOWED [{impact}] {check} on {fpath}")
            print(f"           -> {reason}")
        else:
            print(f"  UNTRIAGED [{impact}] {check} on {fpath}")
            failures.append(
                f"untriaged {impact} finding {check} on {fpath} "
                f"(add an ALLOWED_ON_SAFE entry with a reason, or fix the contract)"
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
