"""Small Solidity source helpers; intentionally avoids compiler dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterator


@dataclass(frozen=True, slots=True)
class Contract:
    name: str
    bases: tuple[str, ...]
    source_path: Path
    source: str
    code: str
    start: int
    body_start: int
    body_end: int

    @property
    def body(self) -> str:
        return self.source[self.body_start : self.body_end]

    @property
    def code_body(self) -> str:
        return self.code[self.body_start : self.body_end]

    def line(self, offset: int) -> int:
        return self.source.count("\n", 0, offset) + 1


@dataclass(frozen=True, slots=True)
class Function:
    name: str
    header: str
    body: str
    code_header: str
    code_body: str
    start: int
    body_start: int


def clean_solidity(source: str) -> str:
    """Blank comments and string contents while preserving offsets/newlines."""
    chars = list(source)
    i = 0
    state = "code"
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if char == "/" and next_char == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if char in ('"', "'"):
                quote = char
                chars[i] = " "
                i += 1
                state = "string:" + quote
                continue
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block":
            if char == "*" and next_char == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if char != "\n":
                chars[i] = " "
        else:
            quote = state[-1]
            if char == "\\":
                chars[i] = " "
                if i + 1 < len(source):
                    if source[i + 1] != "\n":
                        chars[i + 1] = " "
                    i += 2
                    continue
            elif char == quote:
                chars[i] = " "
                state = "code"
            elif char != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def matching_brace(code: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def contract_blocks(source_path: Path, source: str) -> Iterator[Contract]:
    code = clean_solidity(source)
    pattern = re.compile(
        r"\b(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+([^\{]+?))?\s*\{"
    )
    for match in pattern.finditer(code):
        end = matching_brace(code, match.end() - 1)
        if end is None:
            continue
        bases_text = match.group(2) or ""
        bases = tuple(
            re.findall(r"\b([A-Za-z_]\w*)\b", re.sub(r"\([^)]*\)", " ", bases_text))
        )
        yield Contract(
            name=match.group(1),
            bases=bases,
            source_path=source_path,
            source=source,
            code=code,
            start=match.start(),
            body_start=match.end(),
            body_end=end,
        )


def _member_blocks(
    contract: Contract, pattern: re.Pattern[str], name_group: int | None
) -> Iterator[Function]:
    body = contract.code_body
    for match in pattern.finditer(body):
        open_paren = body.find("(", match.start())
        depth = 0
        close_paren = None
        for index in range(open_paren, len(body)):
            if body[index] == "(":
                depth += 1
            elif body[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue
        cursor = close_paren + 1
        delimiter = None
        paren_depth = 0
        while cursor < len(body):
            char = body[cursor]
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
            elif paren_depth == 0 and char in "{;":
                delimiter = cursor
                break
            cursor += 1
        if delimiter is None or body[delimiter] != "{":
            continue
        end = matching_brace(body, delimiter)
        if end is None:
            continue
        absolute_start = contract.body_start + match.start()
        absolute_body_start = contract.body_start + delimiter + 1
        name = match.group(name_group) if name_group is not None else "constructor"
        yield Function(
            name=name,
            header=contract.source[absolute_start:absolute_body_start],
            body=contract.source[absolute_body_start : contract.body_start + end],
            code_header=body[match.start() : delimiter + 1],
            code_body=body[delimiter + 1 : end],
            start=absolute_start,
            body_start=absolute_body_start,
        )


def function_blocks(contract: Contract) -> Iterator[Function]:
    return _member_blocks(
        contract, re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("), 1
    )


def modifier_blocks(contract: Contract) -> Iterator[Function]:
    return _member_blocks(
        contract, re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*\("), 1
    )


def constructor_blocks(contract: Contract) -> Iterator[Function]:
    return _member_blocks(contract, re.compile(r"\bconstructor\s*\("), None)


def solidity_files(root: Path) -> list[tuple[Path, str]]:
    source_dir = root / "src"
    if not source_dir.is_dir():
        return []
    return [
        (path, path.read_text(encoding="utf-8"))
        for path in sorted(source_dir.rglob("*.sol"))
        if path.is_file()
    ]


def split_top_level(condition: str, operator: str) -> list[str]:
    """Split on top-level occurrences of a two-char operator, parenthesis-aware.

    A `||` or `&&` nested inside parens does not split; the operator must
    appear at depth 0. `condition` is expected to be cleaned code (comments
    and string contents blanked), so no quote tracking is needed.
    """
    parts = []
    depth = 0
    start = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and condition.startswith(operator, index):
            parts.append(condition[start:index])
            index += len(operator)
            start = index
            continue
        index += 1
    parts.append(condition[start:])
    return parts


def strip_outer_parens(text: str) -> str:
    """Strip balanced outer parens repeatedly, e.g. `((x))` -> `x`."""
    text = text.strip()
    while len(text) >= 2 and text[0] == "(":
        depth = 0
        closed_at = None
        for index, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    closed_at = index
                    break
        if closed_at == len(text) - 1:
            text = text[1:-1].strip()
        else:
            break
    return text


def call_condition(code: str, open_paren: int) -> str | None:
    """Condition of a call whose `(` is at `open_paren`.

    Returns the text inside the parens up to the first top-level comma
    (the error-string argument of `require(cond, "...")` is not part of
    the condition), or None if the parens never balance.
    """
    depth = 0
    close = None
    for index in range(open_paren, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                close = index
                break
    if close is None:
        return None
    inner = code[open_paren + 1 : close]
    depth = 0
    for index, char in enumerate(inner):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            return inner[:index]
    return inner


def require_conditions(code: str) -> list[str]:
    """Conditions of every `require(...)`/`assert(...)` call in cleaned code."""
    conditions = []
    for match in re.finditer(r"\b(?:require|assert)\s*\(", code):
        condition = call_condition(code, match.end() - 1)
        if condition is not None:
            conditions.append(condition)
    return conditions


def condition_enforces(condition: str, wanted: re.Pattern[str]) -> bool:
    """True if a require/assert condition enforces `wanted` unconditionally.

    A top-level `||` lets the call continue when another disjunct holds, so
    the condition must have exactly one top-level `||` part. Within it, some
    top-level `&&` conjunct (after stripping balanced outer parens) must
    match `wanted` — and the conjunct must itself be a single comparison,
    not a disjunction wrapped in parens: `(x > 0 || y > 0)` passes when
    `y > 0` holds with `x == 0`, so it enforces nothing. A conjunct
    starting with `!` never counts: `!(x > 0)` does not enforce `x > 0`.
    """
    parts = split_top_level(condition, "||")
    if len(parts) != 1:
        return False
    for conjunct in split_top_level(parts[0], "&&"):
        stripped = strip_outer_parens(conjunct)
        if stripped.startswith("!"):
            continue
        if len(split_top_level(stripped, "||")) != 1:
            continue
        if wanted.search(stripped):
            return True
    return False


def relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
