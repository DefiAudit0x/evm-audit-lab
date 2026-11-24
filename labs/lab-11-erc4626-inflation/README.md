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
victim.deposit(100_000e18)             -> (100_000e18 * 1) / (100_000e18 + 1) = 0 shares
attacker.withdraw(1)                   -> redeems essentially the whole vault
```

The victim's deposit is absorbed by the attacker's single share. The mirror
variant — partial losses at slightly larger supply, and pure griefing where
the attacker spends capital to make the vault unusable — follows the same
mechanics.

## Remediation

`SafeVault4626` adds equal virtual share and asset values (`1000e18`) to
both sides of the conversion. This is virtual liquidity, not an OpenZeppelin
decimal offset: it softens the large donation sequence tested below but does
not prevent every inflation attack. A `minted > 0` guard rejects deposits
that still round to zero. Deposits are priced from the measured balance
increase and fee-on-transfer deposits are explicitly rejected; the model
assumes exact-transfer, non-rebasing assets. It is an ERC-4626-style share
accounting example, not an implementation of the full IERC4626 interface.

## Minimal reproduction

```bash
forge test --match-contract InflationAttackTest --match-test testVulnerableFirstDepositorAbsorbsVictimDeposit -vvv
```

## Regression test

```bash
forge test --match-contract InflationAttackTest --match-test testSafeVaultAbsorbsTheDonation -vvv
```

`testSafeVaultAbsorbsTheDonation` proves that, for the listed 100,000-token
donation and victim deposit, the victim redeems within 1,000 wei of the
deposit. `testSafeVaultCanStillRejectOneWeiAfterDonation` demonstrates the
limit: after a 1-wei seed and 1-wei donation, another 1-wei deposit rounds to
zero shares and reverts without taking the depositor's tokens.

Companion report: [Audit-Reports/006 — ERC-4626 First-Depositor Inflation Attack](https://github.com/DefiAudit0x/Audit-Reports/blob/main/006-erc4626-inflation-attack.md).
