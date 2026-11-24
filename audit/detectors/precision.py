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
    """Yield (then_body, else_body_or_None, then_start, else_start_or_None,
    stmt_end) for top-level `if` statements, with each arm body's absolute
    start offset in `code` and `stmt_end` the offset just past the whole
    if/else statement (past the else arm when one exists, else past the
    then arm).

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
            then_start = cursor + 1
            cursor = then_end + 1
            while cursor < len(code) and code[cursor] in " \t\n":
                cursor += 1
            else_body = None
            else_start = None
            stmt_end = then_end + 1
            if re.match(r"else\b", code[cursor:]):
                after_else = cursor + 4
                while after_else < len(code) and code[after_else] in " \t\n":
                    after_else += 1
                if after_else < len(code) and code[after_else] == "{":
                    else_end = matching_brace(code, after_else)
                    if else_end is not None:
                        else_body = code[after_else + 1 : else_end]
                        else_start = after_else + 1
                        stmt_end = else_end + 1
            yield then_body, else_body, then_start, else_start, stmt_end
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


def _top_level_statements(code: str):
    """Yield (statement, start_offset) for top-level statements of `code`:
    text between `;`/`}` delimiters at brace/paren depth 0. A statement
    nested in `if`/`for` braces is yielded whole (e.g. an entire
    `if (...) { ... }`), never split — only a statement that IS a plain
    `minted = X;` / `shares = X;` can prove a branch mints."""
    braces = parentheses = 0
    start = 0
    for index, char in enumerate(code):
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
            if braces == parentheses == 0:
                yield code[start : index + 1], start
                start = index + 1
        elif char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        elif char == ";" and braces == parentheses == 0:
            yield code[start : index + 1], start
            start = index + 1
    tail = code[start:]
    if tail.strip():
        yield tail, start


def _written_between(code: str, start: int, end: int, name: str, *, include_indexed: bool = True) -> bool:
    """True if `name` is written in code[start:end]: a plain or compound
    assignment, `++`/`--` (prefix or postfix), `delete`, a tuple-assignment
    LHS element, or an indexed write `name[...] = ...`. A `==` comparison
    is not a write, and a name in a call or a return is not either.

    With include_indexed=False, writes to a mapping slot `name[...]`
    are ignored: they change a balance entry, not the scalar mint value
    itself (e.g. the `shares[msg.sender] += minted` credit after a
    deposit's if/else must not invalidate the two-arm mint proof)."""
    window = code[start:end]
    escaped = re.escape(name)
    if re.search(rf"\b{escaped}\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=|\+\+|--)", window):
        return True
    if re.search(rf"(?:\bdelete\s+|\+\+|--)\s*{escaped}\b", window):
        return True
    if re.search(rf"\([^()]*\b{escaped}\b[^()]*\)\s*=(?!=)", window):
        return True
    if not include_indexed:
        return False
    return re.search(
        rf"\b{escaped}\s*(?:\[[^\]]*\])+\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=)",
        window,
    ) is not None


# A top-level statement that writes `minted`/`shares` outright: plain or
# compound assignment, `++`/`--` (prefix or postfix), `delete`, or a
# tuple-assignment LHS element. Indexed writes `name[...] = ...` are not
# included: they change a balance entry, not the scalar mint value.
_TOP_LEVEL_WRITE = re.compile(
    r"\s*(?:(?:minted|shares)\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=|\+\+|--)"
    r"|delete\s+(?:minted|shares)\b|(?:\+\+|--)\s*(?:minted|shares)\b"
    r"|\([^()]*\b(?:minted|shares)\b[^()]*\)\s*=(?!=))"
)


def _branch_covers_mint(
    branch: str,
    guard_pairs: list[tuple[str, int]],
    branch_start: int,
    deposit_code: str,
) -> bool:
    """True if a branch guarantees a positive mint on its own path, at the
    end of the branch: either it holds an enforcing require, or it assigns
    `minted`/`shares` from a value with a top-level positive require (e.g.
    `minted = msg.value` with `require(msg.value > 0)`).

    The proof is a state machine over the arm's top-level statements, in
    order: an enforcing require or a credited guarded copy sets the arm
    covered; any other top-level write to `minted`/`shares` clears it (a
    later require re-proves the arm, and a re-copy from the same guarded
    value is itself a proof point). The assignment must be a plain
    top-level statement of the arm: an assignment nested in an inner `if`
    runs only when that branch is taken, so it neither proves the arm nor
    clears it (recorded limitation, same path-insensitivity family as
    H1/H2). A guarded copy counts only if the guard stating `X > 0`
    precedes the copy and `X` is not rewritten between the guard and the
    copy."""
    covered = False
    for statement, stmt_start in _top_level_statements(branch):
        if any(
            condition_enforces(condition, POSITIVE_SHARE)
            for condition, _ in top_level_guard_conditions(statement)
        ):
            covered = True
            continue
        match = re.fullmatch(r"\s*(?:minted|shares)\s*=\s*([\w.]+)\s*;", statement)
        if match is not None:
            value = match.group(1)
            assign_offset = branch_start + stmt_start + (len(statement) - len(statement.lstrip()))
            pattern = re.compile(rf"{re.escape(value)}\s*(?:>\s*0|>=\s*1)")
            credited = False
            for condition, guard_offset in guard_pairs:
                if guard_offset >= assign_offset:
                    continue
                if not condition_enforces(condition, pattern):
                    continue
                if _written_between(deposit_code, guard_offset, assign_offset, value):
                    continue
                credited = True
                break
            covered = credited
            continue
        if _TOP_LEVEL_WRITE.match(statement):
            covered = False
    return covered


def _last_consumer_end(body: str, stmt_end: int) -> int:
    """End offset of the last top-level statement after `stmt_end` that
    reads `minted` or `shares`, or `len(body)` when there is none.

    A statement reads the mint value when it mentions `minted`/`shares`
    without being solely a write to that name (`totalShares += minted;`
    and `shares[msg.sender] += minted;` read it; `minted = 0;` does not).
    The post-join write check stops at this consumer: a write after the
    share update cannot change the credited amount. The bound is the LAST
    consumer because a deposit can credit the mint twice (SafePool credits
    `totalShares` and then `shares[msg.sender]`); a write between the two
    credits must still invalidate the proof.
    """
    consumer_end = len(body)
    for statement, stmt_start in _top_level_statements(body):
        stmt_end_offset = stmt_start + len(statement)
        if stmt_end_offset <= stmt_end:
            continue
        if not re.search(r"\b(?:minted|shares)\b", statement):
            continue
        if _TOP_LEVEL_WRITE.match(statement):
            continue
        consumer_end = stmt_end_offset
    return consumer_end


def _body_has_zero_mint_guard(body: str) -> bool:
    """True if one function body enforces a positive mint on its own path:
    a top-level positive-share guard, an exhaustive if/else whose arms both
    guarantee a positive mint, or an `if (minted == 0) revert` check.

    Guards are checked per body: a guard in `convertToShares` says nothing
    about a `deposit` that never calls it. The two-arm proof holds only at
    the share update: a write to `minted`/`shares` after the if/else join
    invalidates it, but only up to the last statement that consumes the
    mint value — a write after the share update cannot change the credited
    amount (the top-level-guard path stays position-insensitive — the
    recorded H1/H2 limitation). An indexed write such as
    `shares[msg.sender] += minted` does not invalidate it: it credits a
    balance with the mint, it does not replace the mint value.
    """
    top_guard_pairs = top_level_guard_conditions(body)
    if any(
        condition_enforces(condition, POSITIVE_SHARE)
        for condition, _ in top_guard_pairs
    ):
        return True
    # An `if/else` is exhaustive: it guards the mint only if BOTH branches
    # guarantee a positive mint on their own path (an enforcing require, or
    # an assignment from a value with a top-level positive require). A bare
    # `if` never counts.
    for then_body, else_body, then_start, else_start, stmt_end in _top_level_if_else_branches(body):
        if else_body is None:
            continue
        if not (
            _branch_covers_mint(then_body, top_guard_pairs, then_start, body)
            and _branch_covers_mint(else_body, top_guard_pairs, else_start, body)
        ):
            continue
        consumer_end = _last_consumer_end(body, stmt_end)
        if _written_between(body, stmt_end, consumer_end, "minted", include_indexed=False):
            continue
        if _written_between(body, stmt_end, consumer_end, "shares", include_indexed=False):
            continue
        return True
    return bool(re.search(
        r"\bif\s*\(\s*(?:minted|shares)\s*==\s*0\s*\)\s*\{?\s*revert\b",
        body,
    ))


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
            # The check runs per `deposit` body: a guard in `convertToShares`
            # says nothing about a `deposit` that never calls it, and a
            # read-only converter need not reject zero shares (ERC-4626
            # requires it to round down). The finding stands if ANY
            # `deposit` assigning `minted`/`shares` lacks its own guard
            # (at most one finding per contract).
            zero_guard = all(
                _body_has_zero_mint_guard(f.code_body)
                for f in funcs
                if f.name == "deposit"
                and re.search(r"\b(?:minted|shares)\s*=", f.code_body)
            )
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
