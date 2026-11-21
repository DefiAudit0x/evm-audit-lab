"""Review leads for external-call ordering and callback-capable execution."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files

from .storage_collision import _storage_fields


INTERACTION = re.compile(
    r"\.\s*(?:call|delegatecall|staticcall|transfer|send|safeTransfer|"
    r"safeTransferFrom|transferFrom|operatorSend|send)\s*(?:\{|\()"
)
STATE_WRITE = re.compile(
    r"\b[A-Za-z_]\w*\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|-=|\*=|/=|=(?!=))"
)
HOOK_ENTRY = re.compile(
    r"\b(?:tokensReceived|tokensToSend|onERC777Received|onERC1155Received|"
    r"onERC1155BatchReceived|onERC721Received)\s*\("
)


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for contract in contract_blocks(source_path, source):
        functions = list(function_blocks(contract))
        state_names = {name for name, _, _ in _storage_fields(contract, {})}
        for function in functions:
            body = function.code_body
            header = function.code_header
            if "nonReentrant" in header or "nonReentrant" in body:
                continue
            interactions = list(INTERACTION.finditer(body))
            if interactions and any(
                _storage_write_after(body, match.end(), state_names) for match in interactions
            ):
                variable = _shared_state_name(body, functions, state_names)
                flavor = "cross-function reentrancy" if variable else "reentrancy"
                if HOOK_ENTRY.search(body) or re.search(r"\b(?:operatorSend|safeTransferFrom)\s*\(", body):
                    flavor = "callback-capable token reentrancy"
                findings.append(
                    Finding(
                        detector="reentrancy",
                        severity="high",
                        confidence="high",
                        title=f"External interaction precedes state effects ({flavor})",
                        message=(
                            "An external call occurs before a later state write. A receiver, "
                            "token hook, or re-entered function may observe stale accounting."
                        ),
                        file=relative_path(root, source_path),
                        line=contract.line(function.start),
                        contract=contract.name,
                    )
                )
        # A delegatecall in a proxy fallback is expected when the proxy keeps
        # its control slots out of ordinary storage. Flag non-standard layouts.
        if "delegatecall" in contract.code_body and not _uses_dedicated_proxy_slot(contract.code_body):
            findings.append(
                Finding(
                    detector="reentrancy",
                    severity="medium",
                    confidence="medium",
                    title="Delegatecall path lacks a recognized isolated proxy slot",
                    message=(
                        "Delegatecall executes foreign code in this contract's storage context. "
                        "Review re-entry, storage ownership, and implementation validation."
                    ),
                    file=relative_path(root, source_path),
                    line=contract.line(contract.start),
                    contract=contract.name,
                )
            )
    return findings


def _storage_write_after(body: str, offset: int, state_names: set[str]) -> bool:
    if not state_names:
        return False
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(name) for name in sorted(state_names, key=len, reverse=True))
        + r")\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|-=|\*=|/=|=(?!=))"
    )
    return bool(pattern.search(body, offset))


def _shared_state_name(body: str, functions, state_names: set[str]) -> str | None:
    names = set(
        re.findall(
            r"\b(" + "|".join(re.escape(name) for name in sorted(state_names, key=len, reverse=True))
            + r")\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|-=|=)",
            body,
        )
    ) if state_names else set()
    for name in names:
        if sum(bool(re.search(rf"\b{re.escape(name)}\b", item.code_body)) for item in functions) > 1:
            return name
    return None


def _uses_dedicated_proxy_slot(body: str) -> bool:
    return bool(
        re.search(r"(?:IMPLEMENTATION|ADMIN)_SLOT\s*=\s*0x[0-9a-fA-F]{64}", body)
        or "proxiableUUID" in body and "onlyProxy" in body
    )


def detect(root: Path) -> list[Finding]:
    return [
        finding
        for path, source in solidity_files(root)
        for finding in detect_source(root, path, source)
    ]
