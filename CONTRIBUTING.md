# Contributing

Each new lab should explain its threat model, violated invariant, vulnerable implementation, remediation, and regression test.

Run the following before opening a pull request:

```bash
forge fmt
forge test -vv
forge fmt --check
```

Keep vulnerable examples clearly labeled and never include real credentials, private client material, or instructions intended to attack production systems.

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
