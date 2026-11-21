"""JSON entry point for the six detector review modules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import access_control, oracle, precision, proxy_upgrade, reentrancy, storage_collision


DETECTORS = (
    reentrancy,
    storage_collision,
    oracle,
    precision,
    access_control,
    proxy_upgrade,
)


def run(root: Path) -> dict[str, object]:
    findings = [finding for detector in DETECTORS for finding in detector.detect(root)]
    findings.sort(key=lambda item: (item.file, item.line, item.detector, item.contract, item.title))
    return {
        "schema_version": 1,
        "tool": "evm-audit-lab-detectors",
        "findings": [finding.to_dict() for finding in findings],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run dependency-free audit review detectors.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    args = parser.parse_args(argv)
    print(json.dumps(run(args.root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
