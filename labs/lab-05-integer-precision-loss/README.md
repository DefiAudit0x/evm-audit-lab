# Lab 05 — Integer Precision Loss

> ⚠️ The `VulnerablePool.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** every deposit that lands after the pool price has been inflated.
- **Privileged actor:** none — the attacker just has to be the *first* depositor.
- **Untrusted actor:** any address that can deposit and donate.

## Violated invariant

> "A depositor's shares never round below the value they deposited."

The pool mints shares with floor division:

```solidity
minted = (msg.value * totalShares) / totalAssets;
```

When `totalShares` is tiny and `totalAssets` is huge, the quotient truncates
to `0` — but the deposit is still accepted. The depositor's ETH is now
pool liquidity they can never redeem.

## Attack anatomy (first-depositor inflation)

```
attacker.deposit(1 wei)      -> totalShares = 1, totalAssets = 1
attacker.donate(10 ETH)      -> totalAssets = 1e19 + 1   (shares unchanged)

victim.deposit(5 ETH)
  minted = 5e18 * 1 / (1e19 + 1)
         = 0 shares            <- floor rounding
  totalAssets = 1.5e19 + 1     <- victim's ETH is in the pool

attacker.withdraw(1 share)
  out = (1e19 + 1 + 5e18) * 1 / 1
      = entire pool            <- victim's 5 ETH is stolen
```

The core primitive is **rounding, not overflow**: `solc ^0.8` prevents
overflows by default, yet the truncation is still exploitable. Any value
that reaches the pool outside `deposit()` (a donation, `selfdestruct`, a
misrouted transfer) is attacker ammunition.

## Minimal reproduction

```bash
forge test --match-contract PrecisionTest --match-test testVulnerablePoolInflationStealsDeposit -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Share-based vault where the first depositor can inflate the reserve externally and deposits mint floor-rounded shares | 100% loss of every deposit minted zero shares |

## Remediation

Several independent defenses; `SafePool.sol` rejects zero-share deposits and
seeds a fixed dead-share amount:

1. **Fixed dead shares on first deposit** — `SafePool` mints 1,000,000
   shares to `address(0)` when the pool is empty. In the tested 1-wei seed,
   10-ETH donation, and 5-ETH victim sequence, this leaves the victim with
   positive shares and limits their redemption shortfall to 0.1%. A large
   first deposit can still own nearly all live shares, and fixed dead shares
   do not guarantee every donation strategy is unprofitable.
2. **Round up on mint, round down on burn** (`Math.ceilDiv`) — deposits can
   never mint zero shares.
3. **Virtual shares / decimal offset** (OpenZeppelin ERC4626) — a virtual
   share supply makes inflation attacks cost more than they can steal.
4. **Revert on zero mint** — turning the theft into a griefing-only DoS
   is better than silently accepting the deposit.

### Additional defenses

- Fuzz the invariant `convertToShares(deposit) > 0` after arbitrary
  donations (`forge invariant`).
- Track and cap `totalAssets` growth that is not attributable to deposits.

## Regression test

```bash
forge test --match-contract PrecisionTest --match-test testSafePoolResistsInflation -vvv
```

`testSafePoolResistsInflation` proves the selected attack sequence leaves
the victim with shares and redemption within 0.1% of the deposit. The
additional `testLargeFirstDepositorCanStillOwnNearlyAllLiveShares` shows
that a 1-ETH first depositor owns over 99% of live shares despite the fixed
dead-share amount.

## Related resources

- [SWC-101: Integer Overflow and Underflow](https://swcregistry.io/docs/SWC-101)
- [EIP-4626: inflation/dilution attacks](https://eips.ethereum.org/EIPS/eip-4626#security-considerations)
- [OpenZeppelin ERC4626 — virtual shares & decimals offset](https://docs.openzeppelin.com/contracts/5.x/erc4626)
- [OpenZeppelin Math.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol)
