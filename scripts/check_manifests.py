#!/usr/bin/env python3
"""Validate that every lab has a complete manifest with real file references."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_manifest(path: Path, repository: Path) -> list[str]:
    label = path.relative_to(repository).as_posix()
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        return [f"{label}: cannot read manifest: {error}"]

    if not isinstance(data, dict):
        return [f"{label}: manifest must be a JSON object"]

    if data.get("schema_version") != 1:
        errors.append(f"{label}: schema_version must be 1")
    for field in ("name", "threat_model", "invariant"):
        if not _nonempty_string(data.get(field)):
            errors.append(f"{label}: {field} must be a non-empty string")

    assumptions = data.get("assumptions")
    if not isinstance(assumptions, list) or not assumptions or not all(
        _nonempty_string(item) for item in assumptions
    ):
        errors.append(f"{label}: assumptions must be a non-empty list of strings")

    contracts = data.get("contracts")
    if not isinstance(contracts, dict) or not contracts:
        errors.append(f"{label}: contracts must be a non-empty object")
    elif any(
        not isinstance(contract, dict)
        or not _nonempty_string(contract.get("role"))
        or not _nonempty_string(contract.get("path"))
        for contract in contracts.values()
    ):
        errors.append(f"{label}: each contract must have non-empty role and path strings")

    tests = data.get("tests")
    if not isinstance(tests, list) or not tests or any(
        not isinstance(test, dict)
        or not _nonempty_string(test.get("name"))
        or not _nonempty_string(test.get("path"))
        for test in tests
    ):
        errors.append(f"{label}: tests must be a non-empty list with name and path strings")

    expectations = data.get("detector_expectations")
    if not isinstance(expectations, list) or not expectations or any(
        not isinstance(expectation, dict)
        or not _nonempty_string(expectation.get("detector"))
        or not _nonempty_string(expectation.get("expectation"))
        for expectation in expectations
    ):
        errors.append(
            f"{label}: detector_expectations must be a non-empty list with detector and expectation strings"
        )

    # All manifest file references use a `path` field and are repository-relative.
    # Walk the whole document so newly added path fields cannot bypass the gate.
    def check_paths(value: Any, location: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_location = f"{location}.{key}" if location else key
                if key == "path":
                    if not _nonempty_string(child):
                        errors.append(f"{label}: {child_location} must be a non-empty path string")
                        continue
                    relative = Path(child)
                    resolved = (repository / relative).resolve()
                    try:
                        resolved.relative_to(repository.resolve())
                    except ValueError:
                        errors.append(f"{label}: {child_location} escapes the repository: {child!r}")
                        continue
                    if not resolved.is_file():
                        errors.append(f"{label}: {child_location} does not resolve to a file: {child!r}")
                else:
                    check_paths(child, child_location)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check_paths(child, f"{location}[{index}]")

    check_paths(data)
    return errors


def check_manifests(repository: Path) -> int:
    repository = repository.resolve()
    labs = repository / "labs"
    if not labs.is_dir():
        print(f"labs directory does not exist: {labs}")
        return 1

    lab_directories = sorted(path for path in labs.glob("lab-*") if path.is_dir())
    if not lab_directories:
        print(f"no lab directories found under {labs}")
        return 1

    errors: list[str] = []
    for lab in lab_directories:
        manifest = lab / "manifest.json"
        if not manifest.is_file():
            errors.append(f"{manifest.relative_to(repository)}: missing manifest")
        else:
            errors.extend(_validate_manifest(manifest, repository))

    if errors:
        print("Lab manifest check failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1

    print(f"Lab manifest check passed ({len(lab_directories)} labs).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to check (defaults to this checkout)",
    )
    args = parser.parse_args()
    return check_manifests(args.root)


if __name__ == "__main__":
    sys.exit(main())
