#!/usr/bin/env python3
"""Generate lab executable mirrors from the canonical src/ and test/ trees."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"


def expected_files(lab: Path) -> list[tuple[Path, Path]]:
    pairs: list[tuple[Path, Path]] = []
    manifest = json.loads((lab / "manifest.json").read_text(encoding="utf-8"))
    references = [*manifest["contracts"].values(), *manifest["tests"]]
    mirror_paths = set()
    for reference in references:
        path = ROOT / reference["path"]
        # Root-only references (Lab 01) do not declare lab mirrors.
        if path.is_relative_to(lab):
            mirror_paths.add(path.relative_to(lab))
    for relative in sorted(mirror_paths):
        pairs.append((ROOT / relative, lab / relative))
    if any(path.parts[0] == "test" for path in mirror_paths):
        fixtures = ROOT / "test" / "fixtures"
        for source in sorted(fixtures.rglob("*")):
            relative = source.relative_to(fixtures)
            # Fixtures for cross-lab suites stay in the root Foundry project.
            if source.is_file() and relative.parts[0] != "root-only":
                pairs.append((source, lab / "test" / "fixtures" / relative))
    # Shared dependencies are generated into every lab that has executable code.
    if any(path.parts[0] == "src" for path in mirror_paths):
        for source in sorted((ROOT / "src" / "shared").glob("*.sol")):
            pairs.append((source, lab / "src" / "shared" / source.name))
    return pairs


def sync(check: bool) -> int:
    failures: list[str] = []
    for lab in sorted(p for p in LABS.glob("lab-*") if p.is_dir()):
        expected = {mirror for _, mirror in expected_files(lab)}
        if check:
            for tree in (lab / "src", lab / "test"):
                if tree.exists():
                    for mirror in tree.rglob("*"):
                        if mirror.is_file() and mirror not in expected:
                            failures.append(str(mirror.relative_to(ROOT)))
        for source, mirror in expected_files(lab):
            if not source.is_file():
                failures.append(f"{lab.name}: canonical file missing: {source.relative_to(ROOT)}")
                continue
            if check:
                if not mirror.is_file() or mirror.read_bytes() != source.read_bytes():
                    failures.append(str(mirror.relative_to(ROOT)))
            else:
                mirror.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, mirror)
    if failures:
        print("Lab mirrors are out of sync:")
        print("\n".join(f"- {item}" for item in failures))
        return 1
    print("Lab mirrors are in sync.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail instead of updating mirrors")
    args = parser.parse_args()
    sys.exit(sync(args.check))
