# Lab 13 — Fee-on-Transfer Token Accounting Break

> ⚠️ The `VulnerableFotVault.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** the vault's real backing — the shortfall is borne pro-rata by honest depositors.
- **Privileged actor:** none — the flaw activates the moment a fee-on-transfer token (or a fee-wrapping router) is accepted.
- **Untrusted actor:** any depositor through such a token, including one who deployed the fee token for the purpose.
- **Preconditions:** deposits of a token that delivers less than instructed (fee-on-transfer, some rebasing tokens).

## Violated invariant

> "Credited claims must equal value actually received by the vault."

The vulnerable deposit credits the *requested* amount while the token balance grows by the *received* amount. For a 10% fee token, every deposit mints 10% more claims than backing — and withdrawals pay full claims against short backing.

```solidity
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;   // credits the instruction, not the delivery
}
```

## Attack anatomy (socialized shortfall, 10% fee token)

```
alice.deposit(100) -> credited 100, vault received 90
bob.deposit(100)   -> credited 100, vault received 90   (real backing: 180)

alice.withdraw(100) -> paid in full                    (backing left: 80)
bob.withdraw(100)   -> REVERT — only 80 back 100 of claims

bob's 90 real tokens became 80 frozen ones; alice captured the difference
```

Cycling deposit/withdraw through the fee token repeats the extraction until
honest backing is drained.

## Remediation

`SafeFotVault` credits by balance delta — the observed change in
`token.balanceOf(address(this))` across the transfer — so claims never
exceed received value regardless of token behavior. Checked transfers plus a
`received > 0` guard round out the pattern.

## Minimal reproduction

```bash
forge test --match-contract FeeOnTransferTest --match-test testVulnerableVaultSocializesTheShortfall -vvv
```

## Regression test

```bash
forge test --match-contract FeeOnTransferTest --match-test testSafeVaultCreditsOnlyWhatArrived -vvv
```

Both depositors on `SafeFotVault` are credited exactly what arrived (90
each), both withdraw in full, and the vault ends solvent at zero.

Companion report: [Audit-Reports/012 — Fee-on-Transfer Token Accounting Break](https://github.com/DefiAudit0x/Audit-Reports/blob/main/012-fee-on-transfer-accounting.md).
