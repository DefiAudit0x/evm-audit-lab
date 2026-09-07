# Lab 10 — Unchecked Return Value

> ⚠️ The `VulnerableRouter.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** every user entitlement the router pays out — airdrops, vesting releases, settlement legs.
- **Privileged actor:** none — the failure needs no attacker at all; the harm triggers whenever the token reports failure by returning `false`.
- **Untrusted actor:** any token in the transfer path that does not follow the revert-on-failure convention (USDT-style), or an address whose payout is expected to fail (blacklisted, paused, fee-on-transfer edge cases).

## Violated invariant

> "State only records value that actually moved."

ERC-20's `transfer` is specified to return `bool`; nothing forces a token to revert on failure. The vulnerable router discards the return value and completes its own accounting regardless of what the token said:

```solidity
token.transfer(msg.sender, amount);   // bool return discarded

claimed[msg.sender] = amount;         // records a payment that may not have happened
delete claimable[msg.sender];         // destroys the entitlement either way
```

A token that returns `false` (paused, blacklisted recipient, frozen funds) does not revert here. The router's state now claims the user was paid while the tokens never left the contract — and because the entitlement was deleted, the user can never retry.

## Attack anatomy (phantom payout, destroyed entitlement)

```
claimant holds a 100e18 allocation on a USDT-style token (paused)

claimant.claim()
  router: token.transfer(claimant, 100e18)  -> returns false (ignored!)
  router: claimed[claimant] = 100e18        -> accounting says "paid"
  router: delete claimable[claimant]        -> retry impossible

claimant.balanceOf: 0        <- received nothing
router token balance: 100e18 <- tokens stuck forever
claimed[claimant]: 100e18    <- the state is now a lie
```

Note the failure needs **no attacker and no trickery**: a token pause or a
blacklisted claimant is enough. The same unchecked-`bool` pattern applied
to a low-level `call` has the identical effect — "send ETH, ignore
success, record as paid" — and batch loops multiply the damage: one
failing leg silently corrupts the accounting of every subsequent one.

## Minimal reproduction

```bash
forge test --match-contract UncheckedReturnTest --match-test testVulnerableRouterSilentFailureDestroysEntitlement -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **High** | Router records entitlements as paid without checking the `transfer`/`call` return value, and any supported token can signal failure by returning `false` | Users' allocations are permanently destroyed while tokens remain stuck in the contract; accounting and reality diverge silently |

## Remediation

Several independent defenses; `SafeRouter.sol` implements the first two:

1. **Check the return value and revert** — `bool ok = token.transfer(...); if (!ok) revert TransferFailed();`. The revert happens *before* any state change, so a failed claim stays fully retryable.
2. **Checks-effects-interactions** — mutate `claimable`/`claimed` only after the external call is known to have succeeded, never before.
3. **Prefer vetted token libraries** — OpenZeppelin `SafeERC20.forceApprove`/`safeTransfer` normalizes the convention across reverting and non-reverting tokens.
4. **For low-level `call`:** `(bool ok,) = to.call{value: v}(""); if (!ok) revert();` — and consider the *pull* pattern for payouts, letting recipients retry instead of a push loop that one bad leg poisons.

### Additional defenses

- Maintain a denylist of non-standard tokens per pool/router and document it.
- Fuzz the invariant: "after any `claim()`, either `claimed == 0` and
  `claimable` is unchanged, or the claimant's token balance increased by
  the claimed amount" — any divergence is an unchecked return value.

## Regression test

```bash
forge test --match-contract UncheckedReturnTest -vvv
```

On `SafeRouter` the failing token reverts with `TransferFailed` and leaves
`claimable` intact for retry, while the honest token pays out normally.
The vulnerable router passes with an honest token too — exactly why this
class of bug ships unnoticed and only detonates when a non-standard token
arrives.

## Related resources

- [SWC-104: Unchecked Return Value](https://swcregistry.io/docs/SWC-104)
- [EIP-20: `transfer` returns `bool`](https://eips.ethereum.org/EIPS/eip-20#transfer)
- [OpenZeppelin SafeERC20.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol)
- [Solidity docs: low-level `call` never reverts](https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions)
