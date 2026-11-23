"""Heuristics for share rounding, donation sensitivity, and arithmetic order."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files


DIVIDE_THEN_MULTIPLY = re.compile(
    r"\([^()]+\s*/\s*[^()]+\)\s*\*\s*[A-Za-z0-9_(]"
)


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        funcs = list(function_blocks(contract))
        share_math = bool(re.search(r"\b(?:totalShares|shares)\b", code))
        deposit_code = "\n".join(f.code_body for f in funcs if f.name in {"deposit", "convertToShares"})
        if share_math and deposit_code and "/" in deposit_code:
            # A `&&` continuation still enforces the guard (both sides must
            # hold); a `||` continuation does not, so it stays a finding.
            zero_guard = bool(re.search(
                r"\b(?:require|assert)\s*\(\s*(?:minted|shares)\s*>\s*0\s*[,)&]"
                r"|\bif\s*\(\s*(?:minted|shares)\s*==\s*0\s*\)\s*\{?\s*revert\b",
                deposit_code,
            ))
            seeded = bool(re.search(r"DEAD_SHARES|_VIRTUAL_SHARES", code))
            if re.search(r"\b(?:minted|shares)\s*=", deposit_code) and not zero_guard:
                findings.append(
                    Finding(
                        detector="precision",
                        severity="high",
                        confidence="high",
                        title="Share deposit may accept a zero-rounded mint",
                        message="Share conversion uses floor division but no positive-share check or explicit nonzero seed was found.",
                        file=relative_path(root, source_path),
                        line=contract.line(contract.start),
                        contract=contract.name,
                    )
                )
            if "balanceOf(address(this))" in deposit_code and not seeded:
                findings.append(
                    Finding(
                        detector="precision",
                        severity="high",
                        confidence="medium",
                        title="Share price uses externally mutable live balance",
                        message="Direct donations can change the conversion denominator without minting shares; use accounted assets or an explicit virtual-liquidity policy.",
                        file=relative_path(root, source_path),
                        line=contract.line(contract.start),
                        contract=contract.name,
                    )
                )
            if re.search(r"\b(?:minted|shares)\s*=\s*\([^;]+\+\s*[^;]+-\s*1\)\s*/", deposit_code):
                findings.append(
                    Finding(
                        detector="precision",
                        severity="medium",
                        confidence="medium",
                        title="Deposit conversion rounds shares upward",
                        message="Ceiling division on a deposit can issue more shares than the exact proportional amount.",
                        file=relative_path(root, source_path),
                        line=contract.line(contract.start),
                        contract=contract.name,
                    )
                )
        for function in funcs:
            if DIVIDE_THEN_MULTIPLY.search(function.code_body):
                findings.append(
                    Finding(
                        detector="precision",
                        severity="medium",
                        confidence="medium",
                        title="Arithmetic divides before multiplying",
                        message="Intermediate truncation may discard precision; compare a full-precision multiply-divide implementation and intended rounding direction.",
                        file=relative_path(root, source_path),
                        line=contract.line(function.start),
                        contract=contract.name,
                    )
                )
                break
    return findings


def detect(root: Path) -> list[Finding]:
    return [
        finding
        for path, source in solidity_files(root)
        for finding in detect_source(root, path, source)
    ]
