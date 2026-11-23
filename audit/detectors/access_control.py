"""Heuristics for missing authorization on value-moving/admin entry points."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .reentrancy import _is_shadowed, _local_declarations
from .solidity import Function, contract_blocks, function_blocks, relative_path, solidity_files
from .storage_collision import _storage_fields


PRIVILEGED_FUNCTIONS = re.compile(
    r"^(?:mint|setMinter|setClaimable|upgradeTo(?:AndCall)?|pause|unpause|setOwner|setAdmin|initialize)$"
)
AUTH_MODIFIER = re.compile(r"\bonly(?:Owner|Admin|Role|Minter)\b")
AUTHORITY = r"(?:_?(?:owner|admin|minter)(?:\s*\(\s*\))?|_getSlot\s*\(\s*ADMIN_SLOT\s*\))"
CALLER = r"msg\.sender"
ROLE_CHECK = rf"(?:hasRole\s*\(\s*\w+\s*,\s*{CALLER}\s*\)|isMinter\s*\[\s*{CALLER}\s*\])"
CALLER_CHECK = re.compile(
    rf"\b(?:require|assert)\s*\(\s*(?:{CALLER}\s*==\s*{AUTHORITY}|"
    rf"{AUTHORITY}\s*==\s*{CALLER}|{ROLE_CHECK})\s*(?:,|\))"
    rf"|\bif\s*\(\s*(?:{CALLER}\s*!=\s*{AUTHORITY}|"
    rf"{AUTHORITY}\s*!=\s*{CALLER}|!\s*{ROLE_CHECK})\s*\)"
    r"\s*(?:\{\s*)?(?:revert|(?P<early_return>return))\b",
)
ONE_SHOT_INITIALIZER = re.compile(
    r"\brequire\s*\(\s*!\s*(\w+)\b[^;]*\)\s*;"
    r".*?\b\1\s*=\s*true\s*;",
    re.DOTALL,
)
IF_FLAG_GUARD = re.compile(
    r"\bif\s*\(\s*(\w+)\s*\)\s*(?:\{\s*)?(?:revert|return)\b"
)


TUPLE_BOOL_DECLARATION = re.compile(
    r"\(\s*[^()]*\bbool\s+([A-Za-z_]\w*)\b[^()]*\)\s*="
)


def _tuple_bool_declarations(body: str) -> dict[str, list[tuple[int, int]]]:
    # A `bool` declared as a tuple element, e.g.
    # `(bool initialized, uint256 x) = (false, 1);`, is scoped to the
    # enclosing block from the declaration onward, so it shadows a state
    # flag at a later guard just like a plain local. `_local_declarations`
    # does not see it (its regex requires the type at a statement start),
    # so collect it here with the same enclosing-block scope logic.
    # A `for` header cannot match: the pattern requires `) =` after the
    # tuple, and a for header's `)` is followed by the body, never `=`.
    scope_ends: dict[int, int] = {}
    scopes: list[int] = []
    for brace in re.finditer(r"[{}]", body):
        if brace.group() == "{":
            scopes.append(brace.start())
        elif scopes:
            scope_ends[scopes.pop()] = brace.start()
    braces = list(re.finditer(r"[{}]", body))
    declarations: dict[str, list[tuple[int, int]]] = {}
    scopes = []
    brace_index = 0
    for match in TUPLE_BOOL_DECLARATION.finditer(body):
        start = match.start(1)
        while brace_index < len(braces) and braces[brace_index].start() < start:
            brace = braces[brace_index]
            if brace.group() == "{":
                scopes.append(brace.start())
            elif scopes:
                scopes.pop()
            brace_index += 1
        end = scope_ends.get(scopes[-1], len(body)) if scopes else len(body)
        declarations.setdefault(match.group(1), []).append((start, end))
    return declarations


def _initializer_state_flags(function: Function, state_names: set[str]) -> set[str]:
    # A bare flag name can resolve to a parameter or local instead of storage.
    # Parameters shadow the whole function (correct as-is). A local shadows
    # the flag only if its declaration range covers a use position — the
    # guard position and the `flag = true` assignment of the one-shot guard.
    # A `bool` declared in a block AFTER the guard does not shadow it.
    local_declarations = _local_declarations(function.code_body)
    for name, ranges in _tuple_bool_declarations(function.code_body).items():
        local_declarations.setdefault(name, []).extend(ranges)
    body = function.code_body
    flags = set()
    for name in state_names:
        if re.search(rf"\bbool\s+{re.escape(name)}\s*[,)]", function.code_header):
            continue
        uses: list[int] = []
        for guard in ONE_SHOT_INITIALIZER.finditer(body):
            if guard.group(1) != name:
                continue
            uses.append(guard.start(1))
            assignment = re.search(rf"\b{re.escape(name)}\s*=\s*true\b", guard.group(0))
            if assignment:
                uses.append(guard.start() + assignment.start())
        for guard in IF_FLAG_GUARD.finditer(body):
            if guard.group(1) != name:
                continue
            uses.append(guard.start(1))
            assignment = re.search(
                rf"\b{re.escape(name)}\s*=\s*true\s*;", body[guard.end():]
            )
            if assignment:
                uses.append(guard.end() + assignment.start())
        if uses and any(
            _is_shadowed(name, position, local_declarations) for position in uses
        ):
            continue
        flags.add(name)
    return flags


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    contracts = list(contract_blocks(source_path, source))
    by_name = {contract.name: contract for contract in contracts}
    for contract in contracts:
        state_names = {name for name, _, _ in _storage_fields(contract, by_name)}
        for function in function_blocks(contract):
            if not PRIVILEGED_FUNCTIONS.fullmatch(function.name):
                if "tx.origin" in function.code_body and re.search(r"\b(?:owner|admin)\b", function.code_body):
                    findings.append(
                        _finding(root, source_path, contract, function.start, function.name,
                                 "Authorization depends on tx.origin", "tx.origin can authorize a contract call initiated by the owner; use an explicit role check on msg.sender.", "high")
                    )
                continue
            if not re.search(r"\b(?:public|external)\b", function.code_header):
                continue
            sensitive = re.search(r"\b(?:totalSupply|totalMinted|isMinter|claimable|implementation|owner|admin|_?paused)\b\s*(?:\[[^\]]+\])?\s*(?:=(?!=)|\+=|-=)", function.code_body)
            initializer = function.name == "initialize" and re.search(r"\b(?:owner|admin)\s*=", function.code_body)
            write = sensitive or initializer
            authorized = AUTH_MODIFIER.search(function.code_header) or (
                write and _has_top_level_guard(function.code_body, write.start())
            )
            guarded_initializer = False
            if function.name == "initialize":
                state_flags = _initializer_state_flags(function, state_names)
                guarded_initializer = any(
                    guard.group(1) in state_flags
                    for guard in ONE_SHOT_INITIALIZER.finditer(function.code_body)
                )
            if (sensitive or initializer) and not authorized and not guarded_initializer:
                findings.append(
                    _finding(root, source_path, contract, function.start, function.name,
                             f"Privileged entry point `{function.name}` lacks caller authorization",
                             "The function changes privileged or redeemable state without a recognizable owner, role, or immediate-caller check.", "high")
                )
    return findings


def _has_top_level_guard(body: str, before: int) -> bool:
    """Look for a caller check that starts a top-level statement."""
    braces = parentheses = 0
    statement_start = True
    for token in re.finditer(r"\w+|[^\s]", body):
        if braces == parentheses == 0 and statement_start:
            guard = CALLER_CHECK.match(body, token.start())
            # Reverts roll back writes, but returns only protect later writes.
            if guard and (not guard.group("early_return") or guard.start() < before):
                return True

        char = token.group()
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        # An unbraced branch or ternary is still part of the current statement.
        statement_start = braces == parentheses == 0 and char in (";", "}")
    return False


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
