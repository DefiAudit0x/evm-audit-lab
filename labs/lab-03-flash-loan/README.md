# Lab 03 — Flash Loan Price Manipulation

> ⚠️ The `VulnerableSwap.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** any protocol that reads on-chain spot prices (lending protocols, perpetuals, synthetic assets, leveraged yield farming).
- **Privileged actor:** none — this is a permissionless exploit.
- **Untrusted actor:** anyone with access to a flash loan provider (Aave, Balancer, dYdX). The attacker needs **zero upfront capital**.

## Violated invariant

> "The on-chain spot price reflects the fair market price."

Spot reserves on an AMM can be moved arbitrarily within a single transaction. Any protocol that consumes the spot price as a price feed can be exploited before the transaction ends — and the attacker can repay the flash loan in the same transaction.

## Attack diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Single transaction (block N)                                │
│                                                              │
│  1. Attacker borrows 1,000,000 token A from Aave.           │
│  2. Attacker swaps all of it into VulnerableSwap.            │
│     → reserveA jumps 100x, spot price drops 100x.           │
│  3. Attacker calls LendingProtocol.depositCollateral(B)      │
│     which reads the manipulated price and over-credits       │
│     the attacker's collateral value.                         │
│  4. Attacker borrows the maximum against the inflated        │
│     collateral.                                              │
│  5. Attacker repays the flash loan (1,000,000 A + fee).      │
│  6. Transaction commits. LendingProtocol is now              │
│     undercollateralized.                                     │
└─────────────────────────────────────────────────────────────┘
```

## Minimal reproduction

```bash
forge test --match-contract FlashLoanTest --match-test testExploitFlashLoanPriceManipulation -vvv
```

The test shows that a single swap of 1,000,000 A (against initial reserves of 10,000 A / 10,000 B) drops the spot price by **more than 90%**.

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Lending protocol reads spot price from a low-liquidity AMM | Undercollateralized borrowing, protocol insolvency |
| **High** | Perpetual / synthetic asset uses spot price | Wrong funding rate, wrong liquidation threshold |
| **Medium** | Yield strategy harvests based on spot price | Sandwich loss on harvest |

## Remediation

Use a **TWAP oracle** (Uniswap V3 `observe`, Chainlink price feed with a heartbeat, or a custom TWAP). See `SafeSwap.sol`.

**Why TWAP works:** The attacker must hold the manipulated position across multiple blocks. Each block they hold the position, they expose themselves to other traders arbitraging the price back. The cost of manipulation grows roughly with `manipulation_size × time_held × volatility`.

**Why Chainlink works:** Chainlink aggregates prices off-chain from multiple independent sources, with a configurable heartbeat. Single-block on-chain manipulation does not affect the aggregated value.

**Why a spot oracle fails:** Spot price = current reserves ratio. Manipulating reserves within one transaction manipulates the price, with no time for arbitrage to correct it.

## Regression test

```bash
forge test --match-contract FlashLoanTest --match-test testTWAPResistsSingleBlockManipulation -vvv
```

The same swap amount against `SafeSwap` must not move the TWAP by more than 5%.

## Related resources

- [Uniswap V3 TWAP oracle](https://docs.uniswap.org/concepts/protocol/oracle)
- [Chainlink Price Feeds](https://docs.chain.link/data-feeds/price-feeds)
- [SWC-116: Block values as proxy for time](https://swcregistry.io/docs/SWC-116) (related — using block state)
- [Rekt News — Cream Finance flash loan incident](https://rekt.news/cream-rekt/)
