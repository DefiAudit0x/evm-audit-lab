"""Checks for initializer and UUPS upgrade validation omissions."""

from __future__ import annotations

from pathlib import Path
import re

from .access_control import _initializer_state_flags
from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files
from .storage_collision import _storage_fields


INITIALIZATION_MODIFIER = re.compile(r"\b(?:initializer|onlyInitializing)\b(?!\s*[,\)])")
INITIALIZED_FLAG = r"_?initialized"
PRIVILEGED_ASSIGNMENT = re.compile(r"\b(?:owner|admin)\s*=(?!=)")
REPEAT_GUARD = re.compile(
    rf"\b(?:require|assert)\s*\(\s*!\s*({INITIALIZED_FLAG})\s*(?:,|\))[^;]*;"
    rf"|\bif\s*\(\s*({INITIALIZED_FLAG})\s*\)\s*(?:\{{\s*)?(?:revert|return)\b[^;]*;"
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
            guards = re.findall(r"\b(?:require|assert)\s*\(([^;]+)\)\s*;", body)
            compatible = any(re.search(
                rf"\b\w+\s*\(\s*{candidate_name}\s*\)\s*\.\s*proxiableUUID\s*\(\s*\)\s*==",
                guard,
            ) for guard in guards)
            # Low-level UUID probes enforce their success flag and returned data separately.
            for probe in re.finditer(
                rf"\(\s*bool\s+(\w+)\s*,\s*bytes\s+memory\s+(\w+)\s*\)\s*=\s*"
                rf"{candidate_name}\s*\.\s*staticcall\s*\([^;]*\bproxiableUUID\b[^;]*;",
                body,
            ):
                success, uuid = map(re.escape, probe.groups())
                compatible |= any(re.search(rf"\b{success}\s*&&", guard) and re.search(
                    rf"\babi\s*\.\s*decode\s*\(\s*{uuid}\s*,\s*\(\s*bytes32\s*\)\s*\)\s*==",
                    guard,
                ) for guard in guards)
            missing = []
            if not compatible:
                missing.append("UUPS proxiableUUID compatibility")
            if not re.search(r"\bonlyProxy\b", modifiers) and not any(
                re.search(r"address\s*\(\s*this\s*\)\s*!=\s*SELF\b", guard) for guard in guards
            ):
                missing.append("proxy-only execution context")
            if not any(re.search(
                rf"\b{candidate_name}\s*\.\s*code\s*\.\s*length\s*>\s*0\b", guard
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
