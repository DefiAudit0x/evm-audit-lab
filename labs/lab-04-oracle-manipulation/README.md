# Lab 04 — Stale Oracle Data

> ⚠️ The `VulnerableLending.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** protocol solvency — if the protocol honors stale prices, attackers can borrow against overvalued collateral and the protocol becomes undercollateralized.
- **Privileged actor:** none — the oracle is an external dependency.
- **Untrusted actor:** anyone — once the oracle is stale, any user can exploit the protocol.

## Violated invariant

> "Collateral is valued at the current fair market price."

`latestRoundData()` returns the last reported price, even if the report is hours or days old. If the protocol does not check `updatedAt` against `block.timestamp`, it treats the stale price as live.

## Common causes of staleness

| Cause | Where it happens |
| --- | --- |
| **L2 sequencer outage** | Arbitrum, Optimism, Base — when the sequencer goes down, Chainlink's L2 sequencer uptime feed flips to "down", and price feeds stop updating |
| **Oracle node outage** | Any chain — node operators may go offline, especially for less popular pairs |
| **Chainlink multisig pause** | Any chain — Chainlink can pause feeds in response to incidents |
| **Low-liquidity pair** | Niche tokens where the source exchange itself has stale liquidity |
| **Manual feed** | Custom off-chain feed where the maintainer stops pushing updates |

## Minimal reproduction

```bash
forge test --match-contract StaleOracleTest --match-test testExploitStaleOracle -vvv
```

The test:
1. Deploys an oracle with ETH = $2,000.
2. Warps time forward 2 hours — the oracle is now stale.
3. Attacker deposits 1 ETH (real value: $2,000 if ETH stayed at $2,000; but assume real market price crashed to $500).
4. The protocol credits 1 ETH collateral at the stale $2,000 price → collateral value = $2,000.
5. Attacker borrows $1,500 (75% LTV) — but their collateral is only worth $500 at the real market price.
6. The protocol is now undercollateralized by $1,000.

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Lending protocol without staleness check, on L2 without sequencer uptime check | Protocol insolvency after sequencer outage |
| **High** | Lending protocol without staleness check, on L1 with reliable oracle | Latent risk — exploitable when oracle next goes stale |
| **Medium** | Yield strategy that harvests based on stale price | Wrong harvest, loss of yield |

## Remediation

Combine the following checks (see `SafeLending.sol`):

```solidity
(, int256 price, uint256 startedAt, uint256 updatedAt, uint256 answeredInRound)
    = oracle.latestRoundData();

// 1. Price must be positive.
require(price > 0, "invalid price");

// 2. Round must have been answered.
require(updatedAt != 0, "round not complete");
require(answeredInRound >= startedAt, "stale round");

// 3. Staleness check.
require(block.timestamp - updatedAt < MAX_STALENESS, "stale oracle");

// 4. Sanity lower bound (catches broken feeds returning 0).
require(uint256(price) >= MIN_PRICE, "price too low");
```

**On L2s**, additionally check the [sequencer uptime feed](https://docs.chain.link/data-feeds/l2-sequencer-feeds):

```solidity
(, int256 sequencerUp, uint256 sequencerStartedAt,,) = sequencerUptimeFeed.latestRoundData();
require(sequencerUp == 0, "sequencer down");
require(block.timestamp - sequencerStartedAt > GRACE_PERIOD, "sequencer grace period");
```

## Regression test

```bash
forge test --match-contract StaleOracleTest --match-test testCannotBorrowWithStaleOracleSafe -vvv
```

The same stale-price call against `SafeLending` must revert with `"stale oracle"` and no debt must accrue.

## Related resources

- [Chainlink — Check Latest Data](https://docs.chain.link/data-feeds/price-feeds-api-reference#latestrounddata)
- [Chainlink — L2 Sequencer Uptime Feeds](https://docs.chain.link/data-feeds/l2-sequencer-feeds)
- [SWC-116: Block values as proxy for time](https://swcregistry.io/docs/SWC-116)
- [Rekt News — BonqDAO bridge exploit (stale oracle)](https://rekt.news/bonqdao-rekt/)
- [Rekt News — Mango Markets (oracle manipulation)](https://rekt.news/mango-markets-rekt-2/)
