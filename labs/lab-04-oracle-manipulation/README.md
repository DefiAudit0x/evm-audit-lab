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
5. The protocol accepts $1,500 of debt (75% LTV) — but the collateral is only worth $500 at the assumed real market price.
6. The recorded debt exceeds that assumed collateral value by $1,000. This model only updates debt accounting; no loan asset is transferred and no realized profit is demonstrated.

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Lending protocol without staleness check, on L2 without sequencer uptime check | Protocol insolvency after sequencer outage |
| **High** | Lending protocol without staleness check, on L1 with reliable oracle | Latent risk — exploitable when oracle next goes stale |
| **Medium** | Yield strategy that harvests based on stale price | Wrong harvest, loss of yield |

## Remediation demonstrated by this example

[`SafeLending.sol`](../../src/SafeLending.sol) is an educational debt-accounting
model. It requires a positive price, a nonzero `updatedAt` timestamp that is
not in the future and is less than one hour old, and a price at or above a fixed
minimum. It also requires the ETH deposit to match the credited collateral
and caps cumulative debt. It does not transfer a loan asset.

`SafeLending` validates round integrity by requiring `answeredInRound >= roundId`
and a nonzero `updatedAt`. It normalizes feed decimal scaling to 18 decimals,
rejects feeds with more than 18 decimals, and checks for scaling overflow.

`ConfiguredSafeLending` adds optional checks when nonzero feed addresses are
configured: L2 sequencer status must be up, the recovery timestamp must be
nonzero and not in the future, and recovery must be more than one hour ago.
It also validates deviation from a TWAP reference price: the reference must be
available and nonzero, quote the same pair at 18 decimals, and the primary
price must be within 10% of it. Passing a zero sequencer or TWAP address disables
that optional check.

The test double [`FakeOracle.sol`](../../src/shared/FakeOracle.sol) supplies
18-decimal prices and matching round IDs. The tests in
[`StaleOracle.t.sol`](../../test/StaleOracle.t.sol) use mocked feed responses to
exercise round integrity, 8-decimal normalization, unsupported decimals,
sequencer downtime and recovery grace periods, and TWAP availability and
deviation boundaries. They also cover stale, future, and zero timestamps,
nonpositive/below-minimum prices, and the one-hour staleness boundary. A fresh
price change above the minimum is accepted by the base `SafeLending`; deviation
checking requires the configured TWAP. These are mocked teaching examples;
production integrations must configure feeds and policies appropriate to their
deployment.

## Regression test

```bash
forge test --match-contract StaleOracleTest --match-test testCannotBorrowWithStaleOracleSafe -vvv
```

The stale-price call against `SafeLending` reverts with `"stale oracle"` and
no additional debt accrues; see the cases above for the other checks this
mocked example actually establishes.

## Related resources

- [Chainlink — Check Latest Data](https://docs.chain.link/data-feeds/price-feeds-api-reference#latestrounddata)
- [Chainlink — L2 Sequencer Uptime Feeds](https://docs.chain.link/data-feeds/l2-sequencer-feeds)
- [SWC-116: Block values as proxy for time](https://swcregistry.io/docs/SWC-116)
- [Rekt News — BonqDAO bridge exploit (stale oracle)](https://rekt.news/bonqdao-rekt/)
- [Rekt News — Mango Markets (oracle manipulation)](https://rekt.news/mango-markets-rekt-2/)
