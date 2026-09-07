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

Several independent defenses; `SafePool.sol` implements the first:

1. **Dead shares on first deposit** — mint a large, fixed amount of shares
   to `address(0)` when the pool is empty. To zero out a victim's mint the
   attacker must donate ~`DEAD_SHARES × victim deposit`, and the donation is
   unrecoverable: the attack becomes a guaranteed net loss.
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

The same attack against `SafePool` leaves the victim with shares and at
least their deposit back, while the attacker exits with less than they
contributed.

## Related resources

- [SWC-101: Integer Overflow and Underflow](https://swcregistry.io/docs/SWC-101)
- [EIP-4626: inflation/dilution attacks](https://eips.ethereum.org/EIPS/eip-4626#security-considerations)
- [OpenZeppelin ERC4626 — virtual shares & decimals offset](https://docs.openzeppelin.com/contracts/5.x/erc4626)
- [OpenZeppelin Math.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol)
