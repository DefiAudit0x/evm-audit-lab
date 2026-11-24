# Contributing

Each new lab should explain its threat model, violated invariant, vulnerable implementation, remediation, and regression test.

Run the following before opening a pull request:

```bash
forge fmt
forge test -vv
forge fmt --check
```

Keep vulnerable examples clearly labeled and never include real credentials, private client material, or instructions intended to attack production systems.

## Validation checklist

Run every check in this table before opening a pull request. The commands are
copied verbatim from `.github/workflows/test.yml` and
`.github/workflows/slither.yml`; run them in the same order the workflows do.

Several commands expand variables the workflows set for their own jobs.
Initialize them first, in the same shell, before running the table:

```bash
report_dir="$(mktemp -d)"
AUDIT_TEST_SEED="0x13"
source_revision="$(git rev-parse HEAD)"
source_dirty="$(test -n "$(git status --porcelain)" && echo true || echo false)"
```

| Check | Command | What it covers |
| --- | --- | --- |
| Foundry tests (root) | `forge test -vv` | All root Foundry suites |
| Foundry tests (per lab) | `for lab_test in labs/*/test; do FOUNDRY_TEST="$lab_test" forge test --contracts "${lab_test%/test}/src" -vv; done` | Each lab mirror's Foundry tests against its own `src` (the workflow's loop, shown on one line) |
| Formatting (root) | `forge fmt --check` | Formatting of the root tree |
| Formatting (labs) | `forge fmt --check labs` | Formatting of the lab mirrors |
| Lab mirrors | `python3 scripts/sync_lab_mirrors.py --check` | Root and lab copies of every lab file are in sync |
| Lab manifests | `python3 scripts/check_manifests.py` | Lab manifests are consistent with the labs |
| Python infrastructure | `python3 -B -m unittest discover -s tests -v` | Detector and infrastructure tests in `tests/` |
| Audit reporting tests | `python3 -B -m unittest discover -s .github/scripts -p test_audit_report.py` | Tests for `.github/scripts/audit_report.py` (Slither workflow) |
| Slither scan | `slither . --fail-none --json "$report_dir/slither.json" --json-types detectors,compilations` | Slither 0.11.6 detector scan, exported as JSON |
| Foundry results for reports | `forge test --force --extra-output storageLayout --fuzz-seed "$AUDIT_TEST_SEED" --json > "$report_dir/foundry.json"` | Foundry test results (with storage layout) for the research reports |
| Research reports | `python3 -B .github/scripts/audit_report.py "$report_dir/slither.json" --build-dir out --test-results "$report_dir/foundry.json" --test-seed "$AUDIT_TEST_SEED" --source-revision "$source_revision" --source-dirty "$source_dirty" --format all --output-dir "$report_dir"` | Research reports built from the Slither and Foundry results |
| Slither gate | `python3 -B .github/scripts/check_slither.py "$report_dir/slither.json"` | Gate: lab detections present, `Safe*` contracts clean or triaged |

The setup block above mirrors the Slither workflow: `$report_dir` is a fresh
temporary directory (`mktemp -d`), `$AUDIT_TEST_SEED` is `0x13`,
`$source_revision` is the current commit, and `$source_dirty` records whether
the checkout has uncommitted changes. Each Slither scan must write to a
FRESH output path: the setup block's `report_dir` is a fresh temporary
directory (`mktemp -d`) per run, so never point the scan at an existing
file — Slither 0.11.6 does not overwrite an existing output file, and a
scan (or a second run reusing the same `report_dir`) pointed at an
existing path silently leaves the stale report in place for the gate and
the research reports. The committed artifact
`docs/slither-rescan-2026-11-24.json` is an input only for checks that
intentionally inspect a saved scan (for example, running the Slither gate
on a saved report).

## New detector template

- **Module:** Add `audit/detectors/<name>.py` with `detect(root)` and register it in `audit/detectors/runner.py`.
- **Findings:** Return `Finding` records with `detector`, `severity`, `confidence`, `title`, `message`, `file` (repository-relative), `line` (one-based), and `contract`. Serialization adds `schema_version`.
- **Tests:** In `tests/test_detectors.py`, use the repository runner (`python3 -m audit.detectors`) to verify that the detector flags the intended `Vulnerable*` contract and stays silent on its `Safe*` counterpart.
- **Docs note:** Update the relevant lab documentation with what the detector checks, its limitations, and what still needs manual review.

## Slither exceptions

Keep `ACCEPTED = {}` in `.github/scripts/check_slither.py` until a specific exception is reviewed and approved. In [the Slither triage record](docs/slither-triage.md), identify the exact file and check, give a written reason backed by evidence, name an owner, and set an expiry date (YYYY-MM-DD). Add only the approved file/check pair to the accept list. The owner must remove the entry by expiry or obtain a new review with updated evidence and a new expiry date.

## Dependency pins

Pin GitHub Actions to full commit SHAs and keep the exact Foundry release consistent across both workflows. Pin the Solidity compiler in `foundry.toml`, Python in `.python-version`, and Slither with an exact `==` version in both `requirements.txt` and the Slither workflow. Keep the provenance of the vendored Forge Standard Library in `lib/forge-std/PINNED_COMMIT`.

For an update, review the upstream release notes and verify the release or commit, then update all copies of the affected pin together. For a vendor update, record the verified upstream commit and the resulting vendor tree identity. Explain the reason for the update in the change description and rerun the Foundry suite, formatting, mirror and manifest checks, detector tests, and Slither checks before merging.
