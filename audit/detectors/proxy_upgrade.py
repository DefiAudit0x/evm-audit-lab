"""Checks for initializer and UUPS upgrade validation omissions."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        functions = list(function_blocks(contract))
        initializers = [function for function in functions if function.name == "initialize"]
        for initializer in initializers:
            if re.search(r"\b(?:owner|admin)\s*=", initializer.code_body) and not re.search(
                r"initializer|onlyInitializing|initialized|_initialized|\binitialized\s*=", initializer.code_header + initializer.code_body
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
