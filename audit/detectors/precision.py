"""Heuristics for share rounding, donation sensitivity, and arithmetic order."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import (
    condition_enforces,
    contract_blocks,
    function_blocks,
    matching_brace,
    relative_path,
    solidity_files,
    top_level_guard_conditions,
)


DIVIDE_THEN_MULTIPLY = re.compile(
    r"\([^()]+\s*/\s*[^()]+\)\s*\*\s*[A-Za-z0-9_(]"
)
POSITIVE_SHARE = re.compile(r"\b(?:minted|shares)\s*>\s*0")


def _top_level_if_else_branches(code: str):
    """Yield (then_body, else_body_or_None) for top-level `if` statements.

    Only braced branches are analyzed; an `else if` chain yields
    else_body None (not analyzed — conservative).
    """
    braces = parentheses = 0
    statement_start = True
    for token in re.finditer(r"\w+|[^\s]", code):
        if braces == parentheses == 0 and statement_start and token.group() == "if":
            open_paren = code.find("(", token.start())
            if open_paren == -1:
                continue
            depth = 0
            close_paren = None
            for index in range(open_paren, len(code)):
                if code[index] == "(":
                    depth += 1
                elif code[index] == ")":
                    depth -= 1
                    if depth == 0:
                        close_paren = index
                        break
            if close_paren is None:
                continue
            cursor = close_paren + 1
            while cursor < len(code) and code[cursor] in " \t\n":
                cursor += 1
            if cursor >= len(code) or code[cursor] != "{":
                continue
            then_end = matching_brace(code, cursor)
            if then_end is None:
                continue
            then_body = code[cursor + 1 : then_end]
            cursor = then_end + 1
            while cursor < len(code) and code[cursor] in " \t\n":
                cursor += 1
            else_body = None
            if re.match(r"else\b", code[cursor:]):
                after_else = cursor + 4
                while after_else < len(code) and code[after_else] in " \t\n":
                    after_else += 1
                if after_else < len(code) and code[after_else] == "{":
                    else_end = matching_brace(code, after_else)
                    if else_end is not None:
                        else_body = code[after_else + 1 : else_end]
            yield then_body, else_body
        char = token.group()
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        statement_start = braces == parentheses == 0 and char in (";", "}")


def _branch_covers_mint(branch: str, top_conditions: list[str]) -> bool:
    """True if a branch guarantees a positive mint on its own path: either
    it holds an enforcing require, or it assigns `minted`/`shares` from a
    value with a top-level positive require (e.g. `minted = msg.value`
    with `require(msg.value > 0)`)."""
    if any(
        condition_enforces(condition, POSITIVE_SHARE)
        for condition, _ in top_level_guard_conditions(branch)
    ):
        return True
    for assign in re.finditer(r"\b(?:minted|shares)\s*=\s*([\w.]+)\s*;", branch):
        value = assign.group(1)
        pattern = re.compile(rf"{re.escape(value)}\s*(?:>\s*0|>=\s*1)")
        if any(condition_enforces(condition, pattern) for condition in top_conditions):
            return True
    return False


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        funcs = list(function_blocks(contract))
        share_math = bool(re.search(r"\b(?:totalShares|shares)\b", code))
        deposit_code = "\n".join(f.code_body for f in funcs if f.name in {"deposit", "convertToShares"})
        if share_math and deposit_code and "/" in deposit_code:
            # A guard enforces a positive mint only if it runs on the
            # deposit path: only top-level require/assert statements count.
            # A guard inside `if (...) { ... }` is skipped when the branch
            # is not taken, so it enforces nothing. A parenthesized guard
            # `(minted > 0)` at the top level still counts.
            top_conditions = [
                condition
                for condition, _ in top_level_guard_conditions(deposit_code)
            ]
            zero_guard = any(
                condition_enforces(condition, POSITIVE_SHARE)
                for condition in top_conditions
            )
            if not zero_guard:
                # An `if/else` is exhaustive: it guards the mint only if
                # BOTH branches guarantee a positive mint on their own path
                # (an enforcing require, or an assignment from a value with
                # a top-level positive require). A bare `if` never counts.
                zero_guard = any(
                    else_body is not None
                    and _branch_covers_mint(then_body, top_conditions)
                    and _branch_covers_mint(else_body, top_conditions)
                    for then_body, else_body in _top_level_if_else_branches(deposit_code)
                )
            zero_guard = zero_guard or bool(re.search(
                r"\bif\s*\(\s*(?:minted|shares)\s*==\s*0\s*\)\s*\{?\s*revert\b",
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
