# Lab 03 — Flash Loan Price Manipulation (Reserve-Manipulation Model)

> ⚠️ The `VulnerableSwap.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

> **Model scope:** this lab demonstrates reserve and spot-price manipulation
> only. `VulnerableSwap` changes synthetic reserve values; it does not transfer
> tokens, obtain or repay a flash loan, charge a fee, call a downstream
> consumer, or measure protocol loss or attacker profit. Its executable test
> establishes only the reserve and spot-quote changes described below.

## Threat model

- **Asset at risk:** any protocol that reads on-chain spot prices (lending protocols, perpetuals, synthetic assets, leveraged yield farming).
- **Privileged actor:** none. Any caller can invoke the synthetic reserve update.
- **Modeled actor:** any caller can supply an amount directly to the synthetic `swap` function. This model does not establish flash-loan availability or capital requirements.

## Violated invariant

> "The on-chain spot price reflects the fair market price."

The model shows that a spot quote derived from reserves changes when the
synthetic reserves change. A real protocol that consumes a manipulable spot
price may be exposed, but this lab does not implement or measure that consumer
or an end-to-end exploit.

## Attack diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Synthetic reserve-state transition (not a flash loan)        │
│                                                              │
│  1. Start with synthetic reserves A=10,000, B=10,000.        │
│  2. Call swap(1,000,000 A).                                  │
│     → reserveA=1,010,000; reserveB≈99.0099.                 │
│  3. The modeled spot quote changes from 1.0 to ≈0.00009803.  │
│  4. The test reads reserves and the quote only.               │
│     No token, loan, fee, repayment, or consumer is modeled.   │
└─────────────────────────────────────────────────────────────┘
```

## Minimal reproduction

```bash
forge test --match-contract FlashLoanTest --match-test testReserveManipulationModelChangesSpotPrice -vvv
```

The test starts with synthetic reserves of 10,000 A / 10,000 B, applies a
modeled input of 1,000,000 A, checks the resulting reserve values, and verifies
that the spot quote falls by **more than 90%**. It does not execute a flash
loan or demonstrate downstream loss or attacker profit.

## Impact

The following are potential consequences in a separate protocol that trusts
the manipulated spot price; they are not outcomes measured by this lab.

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Lending protocol reads spot price from a low-liquidity AMM | Undercollateralized borrowing, protocol insolvency |
| **High** | Perpetual / synthetic asset uses spot price | Wrong funding rate, wrong liquidation threshold |
| **Medium** | Yield strategy harvests based on spot price | Sandwich loss on harvest |

## Remediation

For a real protocol, use a **TWAP oracle** (Uniswap V3 `observe`, Chainlink
price feed with a heartbeat, or a custom TWAP) rather than trusting a
manipulable spot quote. See `SafeSwap.sol`.

**Why TWAP helps:** A cumulative TWAP assigns weight according to how long a
price was in effect, so a same-block change has zero elapsed-time weight. A
sustained manipulated price contributes proportionally over time.

**Why Chainlink can help:** A suitably configured feed uses an external price
source rather than this pool's current reserve ratio. Its heartbeat and
validation assumptions still need to fit the consuming protocol.

**Why a spot oracle is exposed:** Spot price = current reserves ratio. A
reserve change immediately changes the quote, with no time dimension to
attenuate a transient change.

## Regression test

```bash
forge test --match-contract FlashLoanTest --match-test testTWAPResistsSingleBlockManipulation -vvv
```

`SafeSwap` accumulates the spot price multiplied by the time it was in effect.
It keeps at most two checkpoints, at least 30 minutes apart, with `uint256`
timestamps. Reads use the newest checkpoint that is at least 30 minutes old.
During warm-up, the oracle reverts with `insufficient observation history`.

The regression checks that a swap at the observation boundary leaves the
same-block TWAP exactly unchanged. Once time elapses, the new price contributes
in proportion to its duration. After a full period at that price, the newest
checkpoint matures and the average reflects the new price for the entire
window.

## Related resources

- [Uniswap V3 TWAP oracle](https://docs.uniswap.org/concepts/protocol/oracle)
- [Chainlink Price Feeds](https://docs.chain.link/data-feeds/price-feeds)
- [SWC-116: Block values as proxy for time](https://swcregistry.io/docs/SWC-116) (related — using block state)
- [Rekt News — Cream Finance flash loan incident](https://rekt.news/cream-rekt/)
