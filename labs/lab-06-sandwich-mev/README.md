# Lab 06 — Sandwich / MEV Front-running

> ⚠️ The `VulnerableAmm.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** the difference between the price a trader signed at and the price their transaction actually executed at.
- **Privileged actor:** none — any searcher monitoring the public mempool.
- **Untrusted actor:** the attacker, who can place two transactions around any pending one.

## Violated invariant

> "A trader receives the price they expected when they signed."

`VulnerableAmm.swap()` has no `minAmountOut` and no `deadline`. The executed
price is whatever the reserves are when the transaction lands — and anyone
can choose *when* that is by outbidding the victim's gas price.

## Attack anatomy

```
mempool:  victim signs swap(10 A -> B)

block N:
  tx 1  attacker swaps 50 A -> 33.27 B     (front-run: B becomes expensive)
  tx 2  victim swaps 10 A -> 4.16 B        (fair price was ~9.07 B)
  tx 3  attacker sells 33.27 B -> 55.42 A  (back-run)

net: attacker +5.42 A, victim -4.9 B vs the signed price
```

The attacker needs no special access — only priority-fee bidding and a
node that streams the mempool. The victim's slippage *is* the attacker's
profit.

## Minimal reproduction

```bash
forge test --match-contract SandwichTest --match-test testVulnerableAmmIsSandwiched -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **High** | Public mempool + no on-chain slippage bound + volatile pair | Deterministic extraction from every large trade |
| **Medium** | Slippage bound present but set loose by front-ends | Attacker extracts up to the tolerated slippage |

## Remediation

`SafeAmm.sol` enforces both bounds protocol-side:

1. **`minAmountOut`** — the caller states the worst acceptable execution.
   A front-run that pushes the price beyond the bound reverts the victim's
   transaction instead of executing it; the attacker's round trip then
   pays the pool fee twice with no victim to subsidize it.
2. **`deadline`** — a transaction that lands late reverts instead of
   executing at a stale, attacker-chosen price.

### Additional defenses

- **Private orderflow** — send transactions through Flashbots Protect or
  similar so they never enter the public mempool.
- **Batch auctions / frequent batch auctions** — one uniform clearing
  price per batch removes intra-block ordering games.
- **Oracle-based execution bounds** — bound execution to an external
  price reference, not just pool reserves.
- Front-end heuristics (auto min-out from a trusted quote) are a UX aid,
  **not** a security control unless enforced by the protocol.

## Regression tests

```bash
forge test --match-contract SandwichTest --match-test testSafeAmmBlocksSandwich -vvv
forge test --match-contract SandwichTest --match-test testSafeAmmRevertsOnExpiredDeadline -vvv
```

The sandwich cannot execute against `SafeAmm`: the victim's swap reverts
with `SlippageExceeded`, and the unmatched attacker round trip loses the fee.

## Related resources

- [SWC-114: Transaction Order Dependence](https://swcregistry.io/docs/SWC-114)
- [Flash Boys 2.0 (Daian et al., 2019)](https://arxiv.org/abs/1904.05234)
- [Flashbots Protect](https://docs.flashbots.net/flashbots-protect/overview)
- [Uniswap V2 `amountOutMin` / deadline](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02)
