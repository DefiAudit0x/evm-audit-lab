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
    """Yield (arms, final_else, final_else_start, stmt_end) for top-level
    braced if/else chains. Each arm is a (body, absolute_start) pair; a
    missing final else remains uncovered and is not exhaustive.
    """
    def parse_chain(start):
        open_paren = code.find("(", start)
        if open_paren == -1:
            return None
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
            return None
        cursor = close_paren + 1
        while cursor < len(code) and code[cursor] in " \t\n":
            cursor += 1
        if cursor >= len(code) or code[cursor] != "{":
            return None
        then_end = matching_brace(code, cursor)
        if then_end is None:
            return None
        arms = [(code[cursor + 1:then_end], cursor + 1)]
        stmt_end = then_end + 1
        cursor = stmt_end
        while cursor < len(code) and code[cursor] in " \t\n":
            cursor += 1
        if not re.match(r"else\b", code[cursor:]):
            return arms, None, None, stmt_end
        cursor += 4
        while cursor < len(code) and code[cursor] in " \t\n":
            cursor += 1
        if re.match(r"if\b", code[cursor:]):
            nested = parse_chain(cursor)
            if nested is None:
                return arms, None, None, stmt_end
            nested_arms, final_else, final_else_start, nested_end = nested
            return arms + nested_arms, final_else, final_else_start, nested_end
        if cursor < len(code) and code[cursor] == "{":
            else_end = matching_brace(code, cursor)
            if else_end is not None:
                return arms, code[cursor + 1:else_end], cursor + 1, else_end + 1
        return arms, None, None, stmt_end

    braces = parentheses = 0
    statement_start = True
    for token in re.finditer(r"\w+|[^\s]", code):
        if braces == parentheses == 0 and statement_start and token.group() == "if":
            parsed = parse_chain(token.start())
            if parsed is not None:
                yield parsed
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
    # Match a complete tuple LHS by balancing backwards from its closing
    # parenthesis, including arbitrarily nested tuples.
    for assignment in re.finditer(r"\)\s*=(?!=)", window):
        depth = 0
        for index in range(assignment.start(), -1, -1):
            if window[index] == ")":
                depth += 1
            elif window[index] == "(":
                depth -= 1
                if depth == 0:
                    lhs = window[index:assignment.start() + 1]
                    # Only scalar tuple targets invalidate a scalar proof.
                    # A name inside an index or index-call is merely read.
                    brackets = 0
                    target_text = []
                    for char in lhs:
                        if char == "[":
                            if brackets == 0:
                                target_text.append("[]")
                            brackets += 1
                        elif char == "]":
                            brackets -= 1
                        elif not brackets:
                            target_text.append(char)
                    targets = "".join(target_text)
                    pattern = rf"\b{escaped}\b" if include_indexed else rf"\b{escaped}\s*(?=[,)])"
                    if re.search(pattern, targets):
                        return True
                    break
    if not include_indexed:
        return False
    return re.search(
        rf"\b{escaped}\s*(?:\[[^\]]*\])+\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=)",
        window,
    ) is not None


# A top-level statement that writes `minted`/`shares` outright: plain or
# compound assignment, `++`/`--` (prefix or postfix), `delete`, or a
# tuple-assignment LHS element (checked separately below). Indexed writes
# `name[...] = ...` are not included: they change a balance entry, not the scalar mint value.
_TOP_LEVEL_WRITE = re.compile(
    r"\s*(?:(?:minted|shares)\s*(?:=(?!=)|[+\-*/%&|^]=|<<=|>>=|\+\+|--)"
    r"|delete\s+(?:minted|shares)\b|(?:\+\+|--)\s*(?:minted|shares)\b"
    r")"
)


def _positive_guard_in_statement(statement: str, name: str) -> bool:
    """Recognize a positive-share guard, including an exact boolean ternary."""
    if any(
        condition_enforces(condition, re.compile(rf"\b{re.escape(name)}\s*>\s*0"))
        for condition, _ in top_level_guard_conditions(statement)
    ):
        return True
    if re.fullmatch(
        rf"\s*require\s*\(\s*{re.escape(name)}\s*>\s*0\s*\?\s*true\s*:\s*false\s*\)\s*;",
        statement,
    ):
        return True
    return bool(re.match(
        rf"\s*if\s*\(\s*{re.escape(name)}\s*==\s*0\s*\)\s*"
        r"(?:\{\s*)?revert\b",
        statement,
    ))


def _mint_credit_names(statement: str) -> set[str]:
    """Mint scalars read by a top-level credit assignment (not returns)."""
    if re.match(r"\s*(?:if|else|for|while)\b", statement):
        return set()
    assignment = re.search(r"(?<![=!<>])=(?!=)", statement)
    if assignment is None:
        return set()
    lhs = statement[:assignment.start()]
    if re.fullmatch(r"\s*(?:(?:uint\d*)\s+)?(?:minted|shares)\s*", lhs):
        return set()
    return set(re.findall(r"\b(?:minted|shares)\b(?!\s*\[)", statement[assignment.end():]))


def _branch_covers_mint(
    branch: str,
    guard_pairs: list[tuple[str, int]],
    branch_start: int,
    deposit_code: str,
    required_names: set[str],
    prefix_credit: set[str] | None = None,
    overwritten_prefix_credit: set[str] | None = None,
) -> bool:
    """True when an arm guarantees a positive mint at its end."""
    covered: set[str] = set()
    # A reverting guard can validate an earlier credit only until its scalar changes.
    uncovered_credit = set(prefix_credit or ())
    overwritten_credit = set(overwritten_prefix_credit or ())
    for statement, stmt_start in _top_level_statements(branch):
        uncovered_credit.update(_mint_credit_names(statement) - covered)
        written = {name for name in ("minted", "shares")
                   if _written_between(statement, 0, len(statement), name, include_indexed=False)}
        overwritten_credit.update(uncovered_credit & written)
        proven = {name for name in ("minted", "shares")
                  if _positive_guard_in_statement(statement, name)}
        if proven:
            uncovered_credit.difference_update(proven - overwritten_credit)
            covered.update(proven)
            continue
        match = re.fullmatch(r"\s*(minted|shares)\s*=\s*([\w.]+|\d+)\s*;", statement)
        if match is not None:
            name, value = match.groups()
            covered.discard(name)
            if value.isdecimal() and int(value) > 0:
                covered.add(name)
                continue
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
            if credited:
                covered.add(name)
            continue
        # Writes in a nested conditional are still possible on the arm's
        # path and therefore invalidate an earlier proof.
        covered.difference_update(written)
    return required_names <= covered and not uncovered_credit

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
        if _TOP_LEVEL_WRITE.match(statement) or (
            statement.lstrip().startswith("(")
            and any(_written_between(statement, 0, len(statement), name, include_indexed=False)
                    for name in ("minted", "shares"))
        ):
            continue
        consumer_end = stmt_end_offset
    return consumer_end


def _body_has_zero_mint_guard(body: str) -> bool:
    """True when every path to the mint consumer rejects a zero mint."""
    top_guard_pairs = top_level_guard_conditions(body)
    # A top-level guard is valid only until the last mint consumer; later
    # scalar writes must not be allowed to erase the proof.
    consumer_end = _last_consumer_end(body, 0)
    required_names = set().union(*(_mint_credit_names(stmt)
                                  for stmt, _ in _top_level_statements(body)))
    if not required_names:
        required_names = set(re.findall(r"\b(minted|shares)\s*=(?!=)", body))
    guarded: set[str] = set()
    # A reverting guard can validate an earlier credit only until its scalar changes.
    uncovered_credit: set[str] = set()
    overwritten_credit: set[str] = set()
    prefix_credit_states = {}
    for statement, stmt_start in _top_level_statements(body):
        prefix_credit_states[stmt_start + len(statement)] = (
            uncovered_credit.copy(), overwritten_credit.copy(),
        )
        if stmt_start >= consumer_end:
            continue
        uncovered_credit.update(_mint_credit_names(statement) - guarded)
        written = {name for name in ("minted", "shares")
                   if _written_between(statement, 0, len(statement), name, include_indexed=False)}
        overwritten_credit.update(uncovered_credit & written)
        proven = {name for name in ("minted", "shares")
                  if _positive_guard_in_statement(statement, name)}
        if proven:
            uncovered_credit.difference_update(proven - overwritten_credit)
            guarded.update(proven)
            continue
        constant = re.fullmatch(r"\s*(minted|shares)\s*=\s*(\d+)\s*;", statement)
        if constant is not None:
            name, value = constant.groups()
            guarded.discard(name)
            if int(value) > 0:
                guarded.add(name)
            continue
        guarded.difference_update(written)
    if required_names <= guarded and not uncovered_credit:
        return True
    # An if/else is exhaustive only when both arms prove a positive mint.
    for arms, else_body, else_start, stmt_end in _top_level_if_else_branches(body):
        if else_body is None:
            continue
        post_join_required = set().union(*(
            _mint_credit_names(statement)
            for statement, stmt_start in _top_level_statements(body)
            if stmt_start >= stmt_end and stmt_start < consumer_end
        ))
        for statement, stmt_start in _top_level_statements(body):
            if stmt_start < stmt_end or stmt_start >= consumer_end:
                continue
            if not _TOP_LEVEL_WRITE.match(statement):
                post_join_required.update(
                    name for name in ("minted", "shares")
                    if re.search(rf"\b{re.escape(name)}\b(?!\s*\[)", statement)
                )
        # The first arm ends the top-level `if` statement. Preserve the
        # credit state from before that statement, not from after the join.
        first_body, first_start = arms[0]
        prefix_credit, overwritten_prefix_credit = prefix_credit_states.get(
            first_start + len(first_body) + 1, (set(), set()),
        )
        paths = []
        for arm_body, arm_start in [*arms, (else_body, else_start)]:
            arm_required = set().union(*(
                _mint_credit_names(statement)
                for statement, _ in _top_level_statements(arm_body)
            ))
            if not arm_required:
                arm_required = set(re.findall(r"\b(minted|shares)\s*=(?!=)", arm_body))
            paths.append(_branch_covers_mint(
                arm_body, top_guard_pairs, arm_start, body,
                arm_required | post_join_required | prefix_credit,
                prefix_credit, overwritten_prefix_credit,
            ))
        if not all(paths):
            continue
        consumer_end = _last_consumer_end(body, stmt_end)
        if _written_between(body, stmt_end, consumer_end, "minted", include_indexed=False):
            continue
        if _written_between(body, stmt_end, consumer_end, "shares", include_indexed=False):
            continue
        return True
    # `if (minted == 0) revert` is path-sensitive only when it is the
    # top-level statement that reaches the mint; nested conditional guards
    # do not cover the alternate path.
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
