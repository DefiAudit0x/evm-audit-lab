"""Heuristics for missing authorization on value-moving/admin entry points."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files


PRIVILEGED_FUNCTIONS = re.compile(
    r"^(?:mint|setMinter|setClaimable|upgradeTo(?:AndCall)?|pause|unpause|setOwner|setAdmin|initialize)$"
)
AUTH_MODIFIER = re.compile(r"\bonly(?:Owner|Admin|Role|Minter)\b")
CALLER_CHECK = re.compile(
    r"\b(?:require|assert)\s*\([^;]*(?:msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender|"
    r"hasRole\s*\([^;]*msg\.sender|isMinter\s*\[\s*msg\.sender\s*\])"
    r"|\bif\s*\([^)]*(?:msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender|"
    r"hasRole\s*\([^)]*msg\.sender|isMinter\s*\[\s*msg\.sender\s*\])[^)]*\)\s*(?:revert|return|\{\s*revert)",
    re.DOTALL,
)
ONE_SHOT_INITIALIZER = re.compile(
    r"\brequire\s*\(\s*!\s*(\w+)\b[^;]*\)\s*;"
    r".*?\b\1\s*=\s*true\s*;",
    re.DOTALL,
)


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        for function in function_blocks(contract):
            body = function.code_header + function.code_body
            if not PRIVILEGED_FUNCTIONS.fullmatch(function.name):
                if "tx.origin" in function.code_body and re.search(r"\b(?:owner|admin)\b", function.code_body):
                    findings.append(
                        _finding(root, source_path, contract, function.start, function.name,
                                 "Authorization depends on tx.origin", "tx.origin can authorize a contract call initiated by the owner; use an explicit role check on msg.sender.", "high")
                    )
                continue
            sensitive = bool(re.search(r"\b(?:totalSupply|totalMinted|isMinter|claimable|implementation|owner|admin)\b\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=)", function.code_body))
            initializer = function.name == "initialize" and re.search(r"\b(?:owner|admin)\s*=", function.code_body)
            authorized = AUTH_MODIFIER.search(function.code_header) or CALLER_CHECK.search(function.code_body)
            guarded_initializer = function.name == "initialize" and ONE_SHOT_INITIALIZER.search(function.code_body)
            if (sensitive or initializer) and not authorized and not guarded_initializer:
                findings.append(
                    _finding(root, source_path, contract, function.start, function.name,
                             f"Privileged entry point `{function.name}` lacks caller authorization",
                             "The function changes privileged or redeemable state without a recognizable owner, role, or immediate-caller check.", "high")
                )
    return findings


def _finding(root, source_path, contract, offset, name, title, message, severity):
    return Finding(
        detector="access_control",
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
