"""Conservative proxy/implementation storage layout checks."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import Contract, contract_blocks, function_blocks, matching_brace, relative_path, solidity_files


EIP1967_IMPLEMENTATION = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    contracts = list(contract_blocks(source_path, source))
    by_name = {contract.name: contract for contract in contracts}
    findings: list[Finding] = []
    for proxy in contracts:
        if "delegatecall" not in proxy.code_body:
            continue
        slot_status = _dedicated_slot_status(proxy)
        if slot_status == "invalid":
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
                            + (" The isolated implementation pointer does not protect these fields."
                               if slot_status == "valid" else "")
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
    expected = {"IMPLEMENTATION_SLOT": EIP1967_IMPLEMENTATION, "ADMIN_SLOT": EIP1967_ADMIN}
    if any(value.lower() != expected[name] for name, value in constants):
        return "invalid"
    if len({value.lower() for _, value in constants}) != len(constants):
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

    # Scan individual members so a local in one function cannot establish
    # the target of a delegatecall in another.
    cursor = 0
    while (opening := body.find("{", cursor)) != -1:
        closing = matching_brace(body, opening)
        if closing is None:
            break
        member = body[opening + 1:closing]
        if _delegate_uses_slot_read(member, read_forms):
            return True
        cursor = closing + 1
    return False


def _delegate_uses_slot_read(member: str, read_forms: list[str]) -> bool:
    read_expression = "(?:" + "|".join(read_forms) + ")"
    if re.search(r"\bdelegatecall\s*\([^,]+,\s*" + read_expression + r"\s*,", member):
        return True

    delegate = re.compile(
        r"\bdelegatecall\s*\([^,]+,\s*([A-Za-z_]\w*)\s*,"
        r"|\b([A-Za-z_]\w*)\s*\.\s*delegatecall\s*\("
    )
    for call in delegate.finditer(member):
        target = re.escape(call.group(1) or call.group(2))
        writes = list(re.finditer(
            rf"\b{target}\s*(?::=|=(?!=)|[+*/%&|^\-]=|\+\+|--)"
            rf"|(?:\+\+|--)\s*\b{target}\b",
            member[:call.start()],
        ))
        if not writes:
            continue
        write = writes[-1]
        if not re.match(read_expression + r"(?=\s*(?:;|\}|$|[A-Za-z_]))", member[write.end():].lstrip()):
            continue
        # A write in a closed sibling scope cannot establish the current target.
        depth = 0
        for brace in re.findall(r"[{}]", member[write.end():call.start()]):
            depth += 1 if brace == "{" else -1
            if depth < 0:
                break
        else:
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
        r"(?:^\s*|(?<=[;}])[ \t]*)(?P<type>(?:address(?:\s+payable)?|bool|u?int\d*|bytes\d*|"
        r"mapping\s*\([^;]+?\)|\w+)(?:\s*\[[^\[\];]*\])*)\s+"
        r"(?:(?:public|private|internal|constant|immutable|transient)\s+)*"
        r"(?P<name>[A-Za-z_]\w*)\s*(?:=[^;]*)?;",
        re.MULTILINE,
    )
    body = _contract_scope_code(contract.code_body)
    for match in variable.finditer(body):
        declaration = match.group()
        if re.search(r"\b(?:constant|immutable)\b", declaration):
            continue
        kind = re.sub(r"\s+", " ", match.group("type"))
        kind = re.sub(r"\s*\[([^\]]*)\]", lambda dimension: "[" + dimension[1].strip() + "]", kind)
        fields.append((match.group("name"), kind, contract.line(contract.body_start + match.start())))
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
            depth = max(0, depth - 1)
            chars[index] = char if depth == 0 else " "
        elif depth:
            if char != "\n":
                chars[index] = " "
    return "".join(chars)


def _resolved_storage_layout(contract, by_name):
    """Flatten struct members into name-independent types, slots and offsets."""
    structs = {}

    def collect(owner):
        for base_name in owner.bases:
            if base_name in by_name:
                collect(by_name[base_name])
        for match in re.finditer(r"\bstruct\s+(\w+)\s*\{([^{}]*)\}", owner.code_body):
            members = []
            for declaration in match[2].split(";"):
                parts = declaration.strip().rsplit(None, 1)
                if len(parts) == 2:
                    members.append(re.sub(r"\s+", " ", parts[0]))
            structs[match[1]] = members

    collect(contract)

    def resolve(kind, seen=()):
        kind = kind.strip()
        if kind in structs and kind not in seen:
            return tuple(resolve(member, (*seen, kind)) for member in structs[kind])
        array = re.fullmatch(r"(.+)\[\s*(\d*)\s*\]", kind)
        if array:
            return ("array", resolve(array[1], seen), array[2])
        if kind in ("uint", "int"):
            return kind + "256"
        return kind

    def flatten(types, start=0, prefix=()):
        # Each leaf entry carries its aggregate boundary path: a tuple of
        # indices from the top-level field down to the leaf (array elements
        # get their element index). Two layouts that flatten to the same
        # (kind, slot, offset) sequence still differ when a field moved
        # because an array resized — the path records where it came from.
        layout = []
        slot, offset = start, 0
        for index, kind in enumerate(types):
            path = prefix + (index,)
            if isinstance(kind, tuple):
                slot += bool(offset)
                offset = 0
                if kind and kind[0] == "array":
                    _, element, length = kind
                    if length:
                        count = int(length)
                        if count <= 1024:
                            members, end = flatten([element] * count, slot, path)
                        else:
                            # Do not materialize huge fixed arrays: one
                            # descriptor entry, advancing the cursor by the
                            # slot span of a single element times the length.
                            # That span is a conservative over-estimate:
                            # elements of small types may pack across element
                            # boundaries (e.g. uint128[4] occupies 2 slots).
                            # Comparisons are relative between two layouts,
                            # so the over-estimate cannot mask a change.
                            _, span = flatten([element], 0, path)
                            members, end = [(kind, slot, 0, path)], slot + span * count
                    else:
                        members, end = [(kind, slot, 0, path)], slot + 1
                else:
                    members, end = flatten(kind, slot, path)
                layout.extend(members)
                slot = end
                continue
            integer = re.fullmatch(r"u?int(\d+)", kind)
            fixed_bytes = re.fullmatch(r"bytes(\d+)", kind)
            size = (int(integer[1]) // 8 if integer else
                    int(fixed_bytes[1]) if fixed_bytes else
                    20 if kind in ("address", "address payable") else
                    1 if kind == "bool" else 32)
            if offset + size > 32 or kind in ("bytes", "string") or kind.startswith("mapping"):
                slot += bool(offset)
                offset = 0
            layout.append((kind, slot, offset, path))
            offset += size
            if offset == 32:
                slot += 1
                offset = 0
        return layout, slot + bool(offset)

    fields = _storage_fields(contract, by_name)
    return flatten([resolve(kind) for _, kind, _ in fields])[0]


def _check_v1_v2_append_only(root, source_path, contracts, by_name):
    findings = []
    for old in contracts:
        match = re.fullmatch(r"(.+?)V(\d+)", old.name)
        if not match:
            continue
        new = by_name.get(f"{match.group(1)}V{int(match.group(2)) + 1}")
        if new is None:
            continue
        # Names and source locations do not affect storage layout.
        old_fields = _resolved_storage_layout(old, by_name)
        new_fields = _resolved_storage_layout(new, by_name)
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
