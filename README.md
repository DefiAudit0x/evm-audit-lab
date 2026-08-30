<div align="center">

# EVM Audit Lab

**Reproducible Solidity security laboratories — vulnerable vs. remediated, side by side.**

[![CI](https://github.com/DefiAudit0x/evm-audit-lab/actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)
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
| 05 | `_coming soon_` — Integer Precision Loss | Rounding & precision attacks | 🚧 |
| 06 | `_planned_` — Sandwich / MEV Front-running | Mempool exploitation | 📋 |
| 07 | `_planned_` — Upgradeable Proxy Storage Collision | UUPS / transparent proxy misuse | 📋 |
| 08 | `_planned_` — Signature Replay | EIP-712 nonce reuse | 📋 |
| 09 | `_planned_` — Privileged Mint via Access Control | Role-based access flaws | 📋 |
| 10 | `_planned_` — Unchecked Return Value (Low-level call) | Silent failures | 📋 |

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
│   └── SafeLending.sol           # Lab 04 — remediated
├── test/
│   ├── Reentrancy.t.sol           # Lab 01
│   ├── TxOrigin.t.sol             # Lab 02
│   ├── FlashLoan.t.sol            # Lab 03
│   └── StaleOracle.t.sol          # Lab 04
├── labs/                          # per-lab deep-dive write-ups
│   ├── lab-01-reentrancy/         # Lab 01 README (sources live in src/ and test/)
│   ├── lab-02-tx-origin/          # Lab 02 README + self-contained src/test copy
│   ├── lab-03-flash-loan/         # Lab 03 README + self-contained src/test copy
│   └── lab-04-oracle-manipulation/ # Lab 04 README + self-contained src/test copy
├── .github/workflows/
│   └── test.yml                   # Foundry test + formatting CI
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

## Responsible use

- Use these examples only in local Foundry test environments.
- Do not deploy the `Vulnerable*.sol` contracts on mainnet or any public network.
- Do not use them against systems you do not own or have explicit permission to test.
- If you fork this repository for teaching purposes, keep the disclaimer intact.

## Roadmap

| Milestone | Target | Status |
| --- | --- | --- |
| 4 core labs | Reentrancy, tx.origin, Flash Loan, Stale Oracle | ✅ Done |
| 6 additional labs | Precision, MEV, Proxy, Signatures, ACL, Low-level calls | 📋 2026 Q4 |
| Slither integration | Add Slither to CI with custom detectors | 🚧 In progress |
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
