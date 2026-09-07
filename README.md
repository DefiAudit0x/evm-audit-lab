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
```

The same checks run automatically in GitHub Actions through `.github/workflows/test.yml`.

## Lab index

| # | Lab | Vulnerability class | Status |
| --- | --- | --- | --- |
| 01 | [Reentrancy](./test/Reentrancy.t.sol) | Reentrancy (checks-effects-interactions) | ✅ |
| 02 | [tx.origin Authorization](./test/TxOrigin.t.sol) | Access control via `tx.origin` | ✅ |
| 03 | [Flash Loan Price Manipulation](./test/FlashLoan.t.sol) | Oracle manipulation via single-block borrow | ✅ |
| 04 | [Stale Oracle](./test/StaleOracle.t.sol) | Missing staleness / heartbeat check | ✅ |
| 05 | [Integer Precision Loss](./test/Precision.t.sol) | Rounding & precision attacks (EIP-4626 inflation) | ✅ |
| 06 | [Sandwich / MEV Front-running](./test/Sandwich.t.sol) | Mempool exploitation | ✅ |
| 07 | [Upgradeable Proxy Storage Collision](./test/ProxyCollision.t.sol) | EIP-1967 vs hand-rolled proxy slots | ✅ |
| 08 | [Signature Replay](./test/SignatureReplay.t.sol) | Missing nonce/deadline/domain binding on signed payouts | ✅ |
| 09 | [Privileged Mint](./test/PrivilegedMint.t.sol) | Unprotected supply creation on a backed token | ✅ |
| 10 | [Unchecked Return Value](./test/UncheckedReturn.t.sol) | Discarded `bool` from `transfer` / low-level `call` | ✅ |

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
│   └── SafeRouter.sol             # Lab 10 — remediated
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
│   └── UncheckedReturn.t.sol      # Lab 10
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
│   └── lab-10-unchecked-return-value/ # Lab 10 README + self-contained src/test copy
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

A second workflow (`.github/workflows/slither.yml`) runs Slither on every push and enforces three rules encoded in `.github/scripts/check_slither.py`:

1. **Lab integrity** — the detector for each gateable lab's core class must fire on its `Vulnerable*` contract (reentrancy-eth, tx-origin + arbitrary-send-eth, unchecked-transfer). If the lab stops teaching what the tool actually flags, CI fails.
2. **Safe regression** — the same detector must stay silent on the `Safe*` counterpart, so a refactor cannot reintroduce the lab's bug unnoticed.
3. **Written triage** — any remaining High/Medium finding on a `Safe*` contract needs an explicit allowlist entry with a reason (scope separation: a Safe contract is remediated for *its* lab's class, not every class).

Vulnerability classes static analysis cannot see (flash-loan and stale-oracle manipulation, rounding inflation, storage-collision layout, signature replay, missing access control) are deliberately **not gated** — they are listed in the CI output as the boundary between tooling and manual reasoning.

## Responsible use

- Use these examples only in local Foundry test environments.
- Do not deploy the `Vulnerable*.sol` contracts on mainnet or any public network.
- Do not use them against systems you do not own or have explicit permission to test.
- If you fork this repository for teaching purposes, keep the disclaimer intact.

## Roadmap

| Milestone | Target | Status |
| --- | --- | --- |
| 4 core labs | Reentrancy, tx.origin, Flash Loan, Stale Oracle | ✅ Done |
| 6 additional labs | Precision, MEV, Proxy, Signatures, ACL, Low-level calls | ✅ Done |
| Slither integration | CI with detection assertions, safe-regression gate and written triage | ✅ Done |
| Invariant fuzzing | Echidna / `forge invariant` for each lab | 📋 2026 Q4 |
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
