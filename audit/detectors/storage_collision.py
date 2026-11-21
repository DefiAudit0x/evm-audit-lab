"""Conservative proxy/implementation storage layout checks."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import Contract, contract_blocks, function_blocks, relative_path, solidity_files


EIP1967_IMPLEMENTATION = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    contracts = list(contract_blocks(source_path, source))
    by_name = {contract.name: contract for contract in contracts}
    findings: list[Finding] = []
    for proxy in contracts:
        if "delegatecall" not in proxy.code_body:
            continue
        if _dedicated_slot_status(proxy) == "valid":
            continue
        if _dedicated_slot_status(proxy) == "invalid":
            findings.append(
                _finding(
                    root,
                    source_path,
                    proxy,
                    "Proxy control slot does not match the EIP-1967 slot",
                    "A recognized implementation/admin slot constant is present but differs from the standard value.",
                    "high",
                )
            )
            continue

        proxy_fields = _storage_fields(proxy, by_name)
        if not proxy_fields:
            continue
        for implementation in contracts:
            if implementation.name == proxy.name or "delegatecall" in implementation.code_body:
                continue
            implementation_fields = _storage_fields(implementation, by_name)
            if not implementation_fields:
                continue
            for slot, (proxy_name, proxy_type, proxy_line) in enumerate(proxy_fields):
                if slot >= len(implementation_fields):
                    continue
                impl_name, impl_type, _ = implementation_fields[slot]
                # The same slot is unsafe regardless of type; matching names
                # are especially suspicious because intent can be mistaken.
                findings.append(
                    Finding(
                        detector="storage_collision",
                        severity="high",
                        confidence="high",
                        title=f"Proxy slot {slot} overlaps implementation storage",
                        message=(
                            f"Proxy field `{proxy_name}` ({proxy_type}) and implementation field "
                            f"`{impl_name}` ({impl_type}) both occupy sequential slot {slot}. "
                            "Delegatecall writes can corrupt proxy control state."
                        ),
                        file=relative_path(root, source_path),
                        line=proxy_line,
                        contract=proxy.name,
                    )
                )
                break
    findings.extend(_check_v1_v2_append_only(root, source_path, contracts, by_name))
    return findings


def _dedicated_slot_status(contract: Contract) -> str:
    body = contract.code_body
    constants = re.findall(
        r"\b((?:IMPLEMENTATION|ADMIN)_SLOT)\s*=\s*0x([0-9a-fA-F]{64})", body
    )
    if not constants:
        return "missing"
    expected = {EIP1967_IMPLEMENTATION, EIP1967_ADMIN}
    if any(value.lower() not in expected for _, value in constants):
        return "invalid"

    implementation_slots = {
        name for name, value in constants
        if name == "IMPLEMENTATION_SLOT" and value.lower() == EIP1967_IMPLEMENTATION
    }
    if implementation_slots and _implementation_slot_is_accessed(contract, implementation_slots):
        return "valid"
    # A correct but unused control-slot constant cannot prove that the proxy
    # stores its implementation there. Continue with the ordinary layout check.
    return "missing"


def _implementation_slot_is_accessed(contract: Contract, constants: set[str]) -> bool:
    """Check that the implementation slot is read into the delegate target."""
    body = contract.code_body
    aliases = {
        name
        for constant in constants
        for name in re.findall(
            r"\b(?:bytes32|uint256)\s+([A-Za-z_]\w*)\s*=\s*"
            + re.escape(constant)
            + r"\s*;",
            body,
        )
    }

    readers: set[str] = set()
    for function in function_blocks(contract):
        parameters = re.search(r"\(([^)]*)\)", function.code_header, re.DOTALL)
        if parameters is None:
            continue
        first_parameter = parameters.group(1).split(",", 1)[0]
        names = re.findall(r"\b[A-Za-z_]\w*\b", first_parameter)
        if names and re.search(r"\bsload\s*\(\s*" + re.escape(names[-1]) + r"\b", function.code_body):
            readers.add(function.name)

    slot_names = constants | aliases
    read_forms = [
        r"sload\s*\(\s*" + re.escape(name) + r"\s*\)"
        for name in slot_names
    ]
    read_forms.extend(
        re.escape(reader) + r"\s*\(\s*" + re.escape(name) + r"\s*\)"
        for reader in readers
        for name in slot_names
    )

    for read_form in read_forms:
        assigned = re.compile(r"\b([A-Za-z_]\w*)\s*(?:=|:=)\s*" + read_form)
        for match in assigned.finditer(body):
            target = re.escape(match.group(1))
            if re.search(r"\bdelegatecall\s*\([^,]+,\s*" + target + r"\s*,", body) or re.search(
                r"\b" + target + r"\s*\.\s*delegatecall\s*\(", body
            ):
                return True
        if re.search(r"\bdelegatecall\s*\([^,]+,\s*" + read_form + r"\s*,", body):
            return True
    return False


def _storage_fields(contract: Contract, by_name: dict[str, Contract], seen=None):
    seen = set() if seen is None else seen
    if contract.name in seen:
        return []
    seen.add(contract.name)
    fields = []
    # Solidity lays out inherited state before derived state. This lightweight
    # approximation handles simple single inheritance; complex linearization
    # remains a manual-review case rather than a claimed compiler layout.
    for base_name in contract.bases:
        base = by_name.get(base_name)
        if base is not None:
            fields.extend(_storage_fields(base, by_name, seen))
    variable = re.compile(
        r"^\s*(address(?:\s+payable)?|bool|u?int\d*|bytes\d*|mapping\s*\([^;]+?\)|\w+)\s+"
        r"(?:(?:public|private|internal|constant|immutable|transient)\s+)*"
        r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
        re.MULTILINE,
    )
    body = _contract_scope_code(contract.code_body)
    for match in variable.finditer(body):
        declaration = body[match.start() : body.find(";", match.start()) + 1]
        if re.search(r"\b(?:constant|immutable)\b", declaration):
            continue
        fields.append((match.group(2), re.sub(r"\s+", " ", match.group(1)).strip(), contract.line(contract.body_start + match.start())))
    return fields


def _contract_scope_code(body: str) -> str:
    """Blank nested blocks so declarations inside functions are not state."""
    chars = list(body)
    depth = 0
    for index, char in enumerate(body):
        if char == "{":
            depth += 1
            chars[index] = " "
        elif char == "}":
            chars[index] = " "
            depth = max(0, depth - 1)
        elif depth:
            if char != "\n":
                chars[index] = " "
    return "".join(chars)


def _check_v1_v2_append_only(root, source_path, contracts, by_name):
    findings = []
    for old in contracts:
        match = re.fullmatch(r"(.+?)V(\d+)", old.name)
        if not match:
            continue
        new = by_name.get(f"{match.group(1)}V{int(match.group(2)) + 1}")
        if new is None:
            continue
        # Source locations are useful for findings but do not affect layout.
        old_fields = [(name, kind) for name, kind, _ in _storage_fields(old, by_name)]
        new_fields = [(name, kind) for name, kind, _ in _storage_fields(new, by_name)]
        if new_fields[: len(old_fields)] != old_fields:
            findings.append(
                _finding(
                    root,
                    source_path,
                    new,
                    "Upgrade changes an existing storage prefix",
                    f"{old.name} and {new.name} do not preserve the prior variable prefix; compare compiler storage layouts.",
                    "high",
                )
            )
    return findings


def _finding(root, source_path, contract, title, message, severity):
    return Finding(
        detector="storage_collision",
        severity=severity,
        confidence="medium",
        title=title,
        message=message,
        file=relative_path(root, source_path),
        line=contract.line(contract.start),
        contract=contract.name,
    )


def detect(root: Path) -> list[Finding]:
    return [
        finding
        for path, source in solidity_files(root)
        for finding in detect_source(root, path, source)
    ]
