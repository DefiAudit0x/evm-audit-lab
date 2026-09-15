# Lab 11 — ERC-4626 First-Depositor Inflation Attack

> ⚠️ The `VulnerableVault4626.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** depositors' assets — from dust up to a full deposit, depending on where the rounding lands.
- **Privileged actor:** none — the attack needs no special rights, only the timing of being first.
- **Untrusted actor:** any first (or early) depositor: at vault launch, or after a full withdrawal returns share supply to zero.
- **Preconditions:** share supply at zero or dust, and a vault that prices shares against its live token balance.

## Violated invariant

> "A depositor's shares must be proportional to their contribution, with a rounding error bounded independently of existing share supply."

The naive `convertToShares` floors in the depositor's disfavor exactly when supply is smallest, and `totalAssets` is sensitive to direct transfers — so a donation moves the price with no shares minted. At 1 wei of supply, the rounding bound degenerates to the donated amount.

```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
    if (totalShares == 0) return assets;
    return (assets * totalShares) / asset.balanceOf(address(this)); // floors against the depositor
}
```

## Attack anatomy (donation + zero-share rounding)

```
attacker.deposit(1 wei)                -> 1 share (totalShares == 0 path)
attacker donates 100_000e18 tokens     -> price inflated, no shares minted
victim.deposit(100_000e18)             -> (100_000e18 * 1) / (200_000e18) = 0 shares
attacker.withdraw(1)                   -> redeems essentially the whole vault
```

The victim's deposit is absorbed by the attacker's single share. The mirror
variant — partial losses at slightly larger supply, and pure griefing where
the attacker spends capital to make the vault unusable — follows the same
mechanics.

## Remediation

`SafeVault4626` folds virtual share/asset constants (the OpenZeppelin
`_decimalsOffset` pattern) into both sides of the share math, so real supply
never operates in the degenerate 1-share regime and a donation moves the
price by a dust fraction only. A `minted > 0` guard additionally rejects
deposits that would round to zero shares outright.

## Minimal reproduction

```bash
forge test --match-contract InflationAttackTest --match-test testVulnerableFirstDepositorAbsorbsVictimDeposit -vvv
```

## Regression test

```bash
forge test --match-contract InflationAttackTest --match-test testSafeVaultAbsorbsTheDonation -vvv
```

The same script against `SafeVault4626` leaves the victim whole (deposit
redeemed within floor-rounding dust) and the attacker's single share worth
a dust fraction of the vault — the donation is absorbed, not weaponized.

Companion report: [Audit-Reports/006 — ERC-4626 First-Depositor Inflation Attack](https://github.com/DefiAudit0x/Audit-Reports/blob/main/006-erc4626-inflation-attack.md).
