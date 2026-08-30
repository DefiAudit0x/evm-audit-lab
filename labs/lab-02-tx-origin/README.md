# Lab 02 — tx.origin Authorization Bypass

> ⚠️ The `VulnerableAccess.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** ETH held by the vault contract.
- **Privileged actor:** the vault's `owner` EOA.
- **Untrusted actor:** any contract the owner is tricked into interacting with (phishing DApp, fake airdrop claim, malicious NFT mint).

## Violated invariant

> "Only the owner's EOA can authorize privileged actions."

`tx.origin` returns the EOA that started the transaction — not the immediate caller. When the owner calls an attacker-controlled contract, that contract inherits the owner's `tx.origin` for the entire transaction, and any subsequent `require(tx.origin == owner)` check passes.

## Minimal reproduction

```bash
forge test --match-contract TxOriginTest --match-test testExploitVulnerableTxOrigin -vvv
```

```
1. Deployer funds VulnerableAccess with 10 ETH (owner = deployer EOA).
2. Owner calls Attacker.proxyWithdrawVulnerable(vault, attackerEOA, 10 ether).
3. Attacker forwards to vault.withdraw(attackerEOA, 10 ether).
4. Inside vault.withdraw: tx.origin == owner → check passes.
5. 10 ETH is sent to attackerEOA. Vault drained.
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **High** | Owner calls any attacker-controlled contract | All privileged actions (withdraw, mint, upgrade) can be triggered by the attacker |

## Remediation

Replace `tx.origin` with `msg.sender`:

```diff
- require(tx.origin == owner, "not owner");
+ require(msg.sender == owner, "not owner");
```

`msg.sender` is always the immediate caller — when the owner calls an attacker contract that then calls the vault, `msg.sender` will be the attacker contract's address, not the owner's.

## Regression test

```bash
forge test --match-contract TxOriginTest --match-test testCannotExploitSafeAccess -vvv
```

The same exploit path against `SafeAccess` must revert with `"not owner"` and the vault must retain its funds.

## Related resources

- [Solidity docs — `tx.origin`](https://docs.soliditylang.org/en/latest/units-and-global-variables.html#block-and-transaction-properties)
- [SWC-115: Authorization through tx.origin](https://swcregistry.io/docs/SWC-115)
- [ConsenSys Best Practices — tx.origin](https://consensys.github.io/smart-contract-best-practices/Recommendations/#avoid-using-txorigin)
