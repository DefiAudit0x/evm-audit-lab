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


def function_blocks(contract: Contract) -> Iterator[Function]:
    body = contract.code_body
    pattern = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
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
        yield Function(
            name=match.group(1),
            header=contract.source[absolute_start:absolute_body_start],
            body=contract.source[absolute_body_start : contract.body_start + end],
            code_header=body[match.start() : delimiter + 1],
            code_body=body[delimiter + 1 : end],
            start=absolute_start,
            body_start=absolute_body_start,
        )


def solidity_files(root: Path) -> list[tuple[Path, str]]:
    source_dir = root / "src"
    if not source_dir.is_dir():
        return []
    return [
        (path, path.read_text(encoding="utf-8"))
        for path in sorted(source_dir.rglob("*.sol"))
        if path.is_file()
    ]


def relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
