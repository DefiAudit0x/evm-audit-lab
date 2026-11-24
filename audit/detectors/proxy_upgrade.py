"""Checks for initializer and UUPS upgrade validation omissions."""

from __future__ import annotations

from pathlib import Path
import re

from .access_control import _initializer_state_flags
from .finding import Finding
from .solidity import (
    condition_enforces,
    contract_blocks,
    function_blocks,
    relative_path,
    solidity_files,
    top_level_guard_conditions,
)
from .storage_collision import _storage_fields


INITIALIZATION_MODIFIER = re.compile(r"\b(?:initializer|onlyInitializing)\b(?!\s*[,\)])")
INITIALIZED_FLAG = r"_?initialized"
PRIVILEGED_ASSIGNMENT = re.compile(r"\b(?:owner|admin)\s*=(?!=)")
REPEAT_GUARD = re.compile(
    rf"\b(?:require|assert)\s*\(\s*!\s*({INITIALIZED_FLAG})\s*(?:,|\))[^;]*;"
    rf"|\bif\s*\(\s*({INITIALIZED_FLAG})\s*\)\s*(?:\{{\s*)?(?:revert|return)\b[^;]*;"
)

# The expected UUPS implementation slot: the EIP-1967 standard value and
# the lab value this repo's own contracts use (SafeUupsVault defines
# IMPLEMENTATION_SLOT with the lab hex). A guard comparing the probe
# output to anything else — e.g. bytes32(0) — checks the wrong value.
_EXPECTED_SLOT_HEXES = (
    "0x360894a13ba1a3210667c828492db98dca3e9e2076cc4c2f0e3b8b1e9e2c0c",
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
)
# RHS of a slot comparison: the IMPLEMENTATION_SLOT identifier (optionally
# qualified), or one of the expected slot hexes (case-insensitive),
# optionally wrapped in bytes32(...) / bytes32(uint256(...)) casts.
_SLOT_RHS = (
    r"(?:bytes32\s*\(\s*(?:uint256\s*\(\s*)?)?"
    r"(?:(?:[A-Za-z_]\w*\.)*IMPLEMENTATION_SLOT"
    + "".join(rf"|(?i:{value})" for value in _EXPECTED_SLOT_HEXES)
    + r")"
    r"(?:\s*\))?(?:\s*\))?"
)


def _has_repeat_guard(header: str, body: str, state_flags: set[str]) -> bool:
    if INITIALIZATION_MODIFIER.search(header):
        return True
    for guard in REPEAT_GUARD.finditer(body):
        is_return_guard = guard.group(2) is not None and bool(
            re.search(r"\breturn\b", guard.group(0))
        )
        if is_return_guard and PRIVILEGED_ASSIGNMENT.search(body, 0, guard.start()):
            continue
        flag = guard.group(1) or guard.group(2)
        if flag in state_flags and re.search(rf"\b{flag}\s*=\s*true\s*;", body[guard.end():]):
            return True
    return False


def _assigned_between(body: str, start: int, end: int, name: str) -> bool:
    """True if `name = ...` occurs in body[start:end]: plain, as an element
    of a tuple-assignment LHS (e.g. `(compatible, uuid) = (...)`), or as
    an indexed write (`uuid[0] = ...`, including compound operators).
    A `==` comparison is not an assignment, and a tuple in a call or a
    return has no `=` after its `)`, so neither is flagged."""
    window = body[start:end]
    if re.search(rf"\b{re.escape(name)}\s*=(?!=)", window):
        return True
    if re.search(
        rf"\([^()]*\b{re.escape(name)}\b[^()]*\)\s*=(?!=)", window
    ) is not None:
        return True
    return re.search(
        rf"\b{re.escape(name)}\s*(?:\[[^\]]*\])+\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=)",
        window,
    ) is not None


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    contracts = list(contract_blocks(source_path, source))
    by_name = {contract.name: contract for contract in contracts}
    for contract in contracts:
        code = contract.code_body
        functions = list(function_blocks(contract))
        initializers = [function for function in functions if function.name == "initialize"]
        state_names = {name for name, _, _ in _storage_fields(contract, by_name)}
        for initializer in initializers:
            if PRIVILEGED_ASSIGNMENT.search(initializer.code_body) and not _has_repeat_guard(
                initializer.code_header, initializer.code_body,
                _initializer_state_flags(initializer, state_names),
            ):
                findings.append(
                    _finding(root, source_path, contract, initializer.start,
                             "Initializer can overwrite privileged state repeatedly",
                             "The initializer assigns owner/admin state without a one-shot initialization guard.", "high")
                )
        for function in functions:
            if function.name != "upgradeToAndCall" and "proxiableUUID" not in code:
                continue
            if not re.match(r"upgradeTo", function.name):
                continue
            body = function.code_body
            parameters, _, modifiers = function.code_header.partition(")")
            candidate = re.search(r"\baddress\s+(?:payable\s+)?([A-Za-z_]\w*)\s*(?:,|$)", parameters)
            candidate_name = re.escape(candidate.group(1)) if candidate else r"(?!)"
            guard_pairs = top_level_guard_conditions(body)
            guards = [condition for condition, _ in guard_pairs]
            uuid_pattern = re.compile(
                rf"\b\w+\s*\(\s*{candidate_name}\s*\)\s*\.\s*proxiableUUID\s*\(\s*\)\s*==\s*{_SLOT_RHS}"
            )
            compatible = any(
                condition_enforces(guard, uuid_pattern) for guard in guards
            )
            # Low-level UUID probes enforce their success flag and returned data separately.
            for probe in re.finditer(
                rf"\(\s*bool\s+(\w+)\s*,\s*bytes\s+memory\s+(\w+)\s*\)\s*=\s*"
                rf"{candidate_name}\s*\.\s*staticcall\s*\([^;]*\bproxiableUUID\b[^;]*;",
                body,
            ):
                success_name, uuid_name = probe.groups()
                success, uuid = map(re.escape, probe.groups())
                success_pattern = re.compile(
                    rf"^(?:{success}\s*==\s*true|{success}\s*!=\s*false|{success})$"
                )
                decode_pattern = re.compile(
                    rf"\babi\s*\.\s*decode\s*\(\s*{uuid}\s*,\s*\(\s*bytes32\s*\)\s*\)\s*==\s*{_SLOT_RHS}"
                )
                # Compatible either as one combined guard (`success &&` +
                # decode comparison) or as two separate top-level guards for
                # the same probe outputs — one requiring the success flag,
                # another requiring the decoded value to match the slot.
                # A probe output reassigned between the probe and a guard
                # invalidates that guard: it would validate the replacement
                # value, not the probe result. An assignment AFTER the
                # guards does not invalidate them.
                # A guard counts only if it runs AFTER the probe: a guard
                # before the probe checked the state variables of the same
                # names, not the probe outputs.
                success_ok = any(
                    offset >= probe.end()
                    and condition_enforces(condition, success_pattern)
                    and not _assigned_between(body, probe.end(), offset, success_name)
                    for condition, offset in guard_pairs
                )
                decode_ok = any(
                    offset >= probe.end()
                    and condition_enforces(condition, decode_pattern)
                    and not _assigned_between(body, probe.end(), offset, uuid_name)
                    for condition, offset in guard_pairs
                )
                compatible |= success_ok and decode_ok
            missing = []
            if not compatible:
                missing.append("UUPS proxiableUUID compatibility")
            if not re.search(r"\bonlyProxy\b", modifiers) and not any(
                condition_enforces(
                    guard,
                    re.compile(r"address\s*\(\s*this\s*\)\s*!=\s*SELF\b"),
                )
                for guard in guards
            ):
                missing.append("proxy-only execution context")
            if not any(condition_enforces(
                guard,
                re.compile(rf"\b{candidate_name}\s*\.\s*code\s*\.\s*length\s*>\s*0\b"),
            ) for guard in guards):
                missing.append("implementation code check")
            if missing:
                findings.append(
                    _finding(root, source_path, contract, function.start,
                             "Upgrade path omits compatibility or context checks",
                             "Missing checks: " + ", ".join(missing) + ".", "high")
                )
    return findings


def _finding(root, source_path, contract, offset, title, message, severity):
    return Finding(
        detector="proxy_upgrade",
        severity=severity,
        confidence="high",
        title=title,
        message=message,
        file=relative_path(root, source_path),
        line=contract.line(offset),
        contract=contract.name,
    )


def detect(root: Path) -> list[Finding]:
    return [
        finding
        for path, source in solidity_files(root)
        for finding in detect_source(root, path, source)
    ]
