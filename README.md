<div align="center">

# EVM Audit Lab

**Reproducible Solidity security laboratories — vulnerable vs. remediated, side by side.**

[![CI](https://github.com/DefiAudit0x/evm-audit-lab/actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)
[![Slither](https://github.com/DefiAudit0x/evm-audit-lab/actions/workflows/slither.yml/badge.svg)](../../actions/workflows/slither.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-181717?style=flat-square)](LICENSE)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FF8C42?style=flat-square)](https://getfoundry.sh)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.24-363636?style=flat-square&logo=solidity&logoColor=white)](https://soliditylang.org)

</div>

---

> ⚠️ **For educational use only.** The `Vulnerable*.sol` contracts are intentionally unsafe and **must never be deployed**. Run them only in a local Foundry test environment.

## What this repository is

Each lab is a **minimal, self-contained** demonstration of one vulnerability class. Every lab contains:

- `src/Vulnerable*.sol` — A minimal contract containing the bug.
- `src/Safe*.sol` — The remediated version, with the fix and a comment explaining why it works.
- `test/*.t.sol` — A Foundry test that **exploits** the vulnerable contract and **verifies** the safe contract resists the same attack.

Tests are reproducible:

```bash
forge test -vv
forge fmt --check
python3 -B -m unittest discover -s tests
python3 -B -m unittest discover -s .github/scripts
python3 -B -m audit.detectors --root .
```

The Foundry tests, the formatting check, and the Python suite (`tests/`) run automatically in GitHub Actions through `.github/workflows/test.yml`. The audit-report tests run in `.github/workflows/slither.yml`; the full scripts suite and the detector run are local-only.

## Review and verification

This repository has been through two independent blind reviews (November 2026) followed by eight fix rounds (Fixes 1–172), all merged into `main` (PRs #1–#6). The second review found 46 findings (15 Major, 31 Minor) plus 20 improvements; every one was fixed or recorded with evidence. The only item left open by design is a non-discriminating anchor-guard test, kept as a regression guard.

Current status on `main` (verified 2026-11-26):

- Foundry: 140/140 tests (19 suites)
- Python suites: 192 tests, plus 39 script tests
- Custom detectors (`audit/detectors`): 19 findings, 0 on `Safe*` contracts
- Slither gate: PASS on a 117-result scan — 11 written triage entries, all false positives (see `docs/slither-triage.md`), expiring 2027-05-21
- Weekly invariant profile: runs every Monday 03:23 UTC and on demand (`workflow_dispatch`), with the scheduled profile (fuzz 2048 runs; invariant 256 runs, 96 calls per run); first run 2026-11-26

## What this demonstrates

This repository is designed to make vulnerability reasoning **reproducible**: each lab isolates one failure mode, shows the attack against a vulnerable implementation, then verifies a narrow remediation with a regression test. It is a training and research corpus, not a collection of production contracts.

## Lab index

| # | Lab | Vulnerability class | Status |
| --- | --- | --- | --- |
| 01 | [Reentrancy](./test/Reentrancy.t.sol) | Reentrancy (checks-effects-interactions) | ✅ |
| 02 | [tx.origin Authorization](./test/TxOrigin.t.sol) | Access control via `tx.origin` | ✅ |
| 03 | [Flash Loan Price Manipulation](./test/FlashLoan.t.sol) | Reserve manipulation and TWAP | ✅ |
| 04 | [Stale Oracle](./test/StaleOracle.t.sol) | Missing staleness / heartbeat check | ✅ |
| 05 | [Integer Precision Loss](./test/Precision.t.sol) | Rounding & precision attacks (EIP-4626 inflation) | ✅ |
| 06 | [Sandwich / MEV Front-running](./test/Sandwich.t.sol) | Mempool exploitation | ✅ |
| 07 | [Upgradeable Proxy Storage Collision](./test/ProxyCollision.t.sol) | EIP-1967 vs hand-rolled proxy slots | ✅ |
| 08 | [Signature Replay](./test/SignatureReplay.t.sol) | Missing nonce/deadline/domain binding on signed payouts | ✅ |
| 09 | [Privileged Mint](./test/PrivilegedMint.t.sol) | Unprotected supply creation on a backed token | ✅ |
| 10 | [Unchecked Return Value](./test/UncheckedReturn.t.sol) | Discarded `bool` from `transfer` / low-level `call` | ✅ |
| 11 | [ERC-4626 Inflation Attack](./test/InflationAttack.t.sol) | First-depositor share-price inflation via donation | ✅ |
| 12 | [Unbounded Loop DoS](./test/LoopDoS.t.sol) | Gas-limit denial of service on an unbounded payee list | ✅ |
| 13 | [Fee-on-Transfer Accounting](./test/FeeOnTransfer.t.sol) | Claims minted from requested, not received, amounts | ✅ |
| 14 | [Unprotected UUPS Initializer](./test/UupsTakeover.t.sol) | Repeated initialization and ownership reassignment via unguarded `initialize` | ✅ |

## Repository structure

```
.
├── src/
│   ├── VulnerableVault.sol        # Lab 01 — vulnerable
│   ├── SafeVault.sol              # Lab 01 — remediated
│   ├── VulnerableAccess.sol       # Lab 02 — vulnerable
│   ├── SafeAccess.sol             # Lab 02 — remediated
│   ├── VulnerableSwap.sol         # Lab 03 — vulnerable
│   ├── SafeSwap.sol               # Lab 03 — remediated
│   ├── VulnerableLending.sol      # Lab 04 — vulnerable
│   ├── SafeLending.sol            # Lab 04 — remediated
│   ├── VulnerablePool.sol         # Lab 05 — vulnerable
│   ├── SafePool.sol               # Lab 05 — remediated
│   ├── VulnerableAmm.sol          # Lab 06 — vulnerable
│   ├── SafeAmm.sol                # Lab 06 — remediated
│   ├── VulnerableProxy.sol        # Lab 07 — vulnerable
│   ├── SafeProxy.sol              # Lab 07 — remediated
│   ├── VulnerableSignature.sol    # Lab 08 — vulnerable
│   ├── SafeSignature.sol          # Lab 08 — remediated
│   ├── VulnerableMint.sol         # Lab 09 — vulnerable
│   ├── SafeMint.sol               # Lab 09 — remediated
│   ├── VulnerableRouter.sol       # Lab 10 — vulnerable
│   ├── SafeRouter.sol             # Lab 10 — remediated
│   ├── VulnerableVault4626.sol    # Lab 11 — vulnerable
│   ├── SafeVault4626.sol          # Lab 11 — remediated
│   ├── VulnerableSplitter.sol     # Lab 12 — vulnerable
│   ├── SafeSplitter.sol           # Lab 12 — remediated
│   ├── VulnerableFotVault.sol     # Lab 13 — vulnerable
│   ├── SafeFotVault.sol           # Lab 13 — remediated
│   ├── Erc1967Proxy.sol           # Lab 14 helper — minimal ERC-1967 proxy
│   ├── VulnerableUupsVault.sol    # Lab 14 — vulnerable
│   └── SafeUupsVault.sol          # Lab 14 — remediated
├── test/
│   ├── Reentrancy.t.sol           # Lab 01
│   ├── TxOrigin.t.sol             # Lab 02
│   ├── FlashLoan.t.sol            # Lab 03
│   ├── StaleOracle.t.sol          # Lab 04
│   ├── Precision.t.sol            # Lab 05
│   ├── Sandwich.t.sol             # Lab 06
│   ├── ProxyCollision.t.sol       # Lab 07
│   ├── SignatureReplay.t.sol      # Lab 08
│   ├── PrivilegedMint.t.sol       # Lab 09
│   ├── UncheckedReturn.t.sol      # Lab 10
│   ├── InflationAttack.t.sol      # Lab 11
│   ├── LoopDoS.t.sol              # Lab 12
│   ├── FeeOnTransfer.t.sol        # Lab 13
│   └── UupsTakeover.t.sol         # Lab 14
├── labs/                          # per-lab deep-dive write-ups
│   ├── lab-01-reentrancy/         # Lab 01 README (sources live in src/ and test/)
│   ├── lab-02-tx-origin/          # Lab 02 README + self-contained src/test copy
│   ├── lab-03-flash-loan/         # Lab 03 README + self-contained src/test copy
│   ├── lab-04-oracle-manipulation/ # Lab 04 README + self-contained src/test copy
│   ├── lab-05-integer-precision-loss/ # Lab 05 README + self-contained src/test copy
│   ├── lab-06-sandwich-mev/       # Lab 06 README + self-contained src/test copy
│   ├── lab-07-proxy-storage-collision/ # Lab 07 README + self-contained src/test copy
│   ├── lab-08-signature-replay/   # Lab 08 README + self-contained src/test copy
│   ├── lab-09-privileged-mint/    # Lab 09 README + self-contained src/test copy
│   ├── lab-10-unchecked-return-value/ # Lab 10 README + self-contained src/test copy
│   ├── lab-11-erc4626-inflation/  # Lab 11 README + self-contained src/test copy
│   ├── lab-12-loop-dos/           # Lab 12 README + self-contained src/test copy
│   ├── lab-13-fee-on-transfer/    # Lab 13 README + self-contained src/test copy
│   └── lab-14-uups-initializer/   # Lab 14 README + self-contained src/test copy
├── .github/
│   ├── workflows/
│   │   ├── test.yml               # Foundry test + formatting CI
│   │   └── slither.yml            # Slither static analysis CI
│   └── scripts/
│       └── check_slither.py       # expectations gate over the Slither JSON report
├── slither.config.json            # Slither scope (excludes lib/, labs/, test/)
├── foundry.toml                   # project configuration
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

There are no active Solidity sources at the repository root; contract sources belong in `src/` and tests belong in `test/`.

## Method

Each lab contains the following five sections, encoded in the test file's docstring:

1. **Threat model** — Who can call what, and with what assumptions?
2. **Violated invariant** — Which invariant does the bug break?
3. **Minimal reproduction** — A Foundry test that demonstrates the exploit.
4. **Remediation** — The narrow fix, applied to the `Safe*.sol` counterpart.
5. **Regression test** — A test that re-runs the exploit against the safe contract and asserts it now fails.

Tool output (Slither, Foundry fuzz) is treated as a **lead for manual verification** rather than a replacement for protocol reasoning.

### Static analysis in CI

A second workflow (`.github/workflows/slither.yml`) runs pinned Slither 0.11.6 on pushes to `main` and on pull requests targeting `main`, and enforces these checks encoded in `.github/scripts/check_slither.py`:

1. **Lab detector signals** — selected findings must appear on the `Vulnerable*` examples. `reentrancy-eth` (Lab 01), `tx-origin` (Lab 02), and `unchecked-transfer` (Lab 10) check the taught behaviour directly. `arbitrary-send-eth` on Lab 02 checks the consequence of its authorization bypass. Lab 06's `unchecked-transfer` checks token-call handling, while its sandwich/slippage lesson is manual. Lab 14's `controlled-delegatecall` and `arbitrary-send-eth` findings check upgrade and custody-loss consequences; its unguarded-initializer lesson is manual.
2. **Safe scan coverage and companion behaviour** — Slither's compilation metadata must list every `src/Safe*.sol` counterpart as scanned. The gate requires `reentrancy-eth` to stay silent on `SafeVault`; `tx-origin` and `arbitrary-send-eth` on `SafeAccess`; `unchecked-transfer` on `SafeAmm` (token-call handling) and `SafeRouter` (Lab 10's discarded return); and `arbitrary-send-eth` on `SafeUupsVault` (owner-guarded withdrawal). These checks cover the named behaviours; they do not establish that every Safe contract is free of every finding.
3. **Written triage** — any remaining High/Medium finding on a `Safe*` contract needs an explicit allowlist entry with a reason. A safe contract is remediated for its lab's lesson, not every detector category.

The core lessons for flash-loan and stale-oracle manipulation, rounding inflation, proxy storage collision, signature replay, missing access control, share-price inflation, unbounded-loop gas denial of service, fee-on-transfer accounting, and an unguarded UUPS initializer require manual reasoning or tests. The CI output lists them as **SKIPPED**, not as detector checks. In particular, `proxy-storage-collision` is not in the pinned Slither 0.11.6 detector catalog. Slither findings are leads for review, not proof of safety.

## Responsible use

- Use these examples only in local Foundry test environments.
- Do not deploy the `Vulnerable*.sol` contracts on mainnet or any public network.
- Do not use them against systems you do not own or have explicit permission to test.
- If you fork this repository for teaching purposes, keep the disclaimer intact.

## Roadmap

| Milestone | Target | Status |
| --- | --- | --- |
| 4 core labs | Reentrancy, tx.origin, Reserve Manipulation and TWAP, Stale Oracle | ✅ Done |
| 6 additional labs | Precision, MEV, Proxy, Signatures, ACL, Low-level calls | ✅ Done |
| 4 companion labs | 4626 inflation, Loop DoS, Fee-on-transfer, UUPS initializer | ✅ Done |
| Slither integration | CI with detection assertions, safe-regression gate and written triage | ✅ Done |
| Invariant fuzzing | Echidna / `forge invariant` for each lab | 🔄 Scheduled Foundry profile live in CI since 2026-11-26 (weekly + on-demand); per-lab Echidna suites still to come |
| Blog writeups | Each lab paired with a public write-up | 📋 2027 Q1 |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the lab template, naming conventions, and PR requirements.

## Contact

For questions, collaboration, or audit inquiries:

- X: [@DeFiAudit](https://x.com/DeFiAudit)
- Telegram: [@DefiAudit0x](https://t.me/DefiAudit0x)
- Email: [defiaudit@gmail.com](mailto:defiaudit@gmail.com)

## License

[MIT](./LICENSE) — Educational and research material. Vulnerable contracts in this repository are intentionally unsafe and are not production code.
