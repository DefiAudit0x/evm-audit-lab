"""Checks for initializer and UUPS upgrade validation omissions."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files


INITIALIZATION_MODIFIER = re.compile(r"\b(?:initializer|onlyInitializing)\b(?!\s*[,\)])")
INITIALIZED_FLAG = r"_?initialized"
PRIVILEGED_ASSIGNMENT = re.compile(r"\b(?:owner|admin)\s*=(?!=)")
REPEAT_GUARD = re.compile(
    rf"\b(?:require|assert)\s*\(\s*!\s*({INITIALIZED_FLAG})\s*(?:,|\))[^;]*;"
    rf"|\bif\s*\(\s*({INITIALIZED_FLAG})\s*\)\s*(?:\{{\s*)?(?:revert|return)\b[^;]*;"
)


def _has_repeat_guard(header: str, body: str) -> bool:
    if INITIALIZATION_MODIFIER.search(header):
        return True
    for guard in REPEAT_GUARD.finditer(body):
        is_return_guard = guard.group(2) is not None and bool(
            re.search(r"\breturn\b", guard.group(0))
        )
        if is_return_guard and PRIVILEGED_ASSIGNMENT.search(body, 0, guard.start()):
            continue
        flag = guard.group(1) or guard.group(2)
        if re.search(rf"\b{flag}\s*=\s*true\s*;", body[guard.end():]):
            return True
    return False


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        functions = list(function_blocks(contract))
        initializers = [function for function in functions if function.name == "initialize"]
        for initializer in initializers:
            if PRIVILEGED_ASSIGNMENT.search(initializer.code_body) and not _has_repeat_guard(
                initializer.code_header, initializer.code_body
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
            missing = []
            if "proxiableUUID" not in body:
                missing.append("UUPS proxiableUUID compatibility")
            if not re.search(r"onlyProxy|address\(this\)\s*!=\s*SELF", function.code_header + body):
                missing.append("proxy-only execution context")
            if "newImpl.code.length" not in body:
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
