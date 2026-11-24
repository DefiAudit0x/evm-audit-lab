# Slither suppression decisions

The project has no inline `slither-disable` directives or excluded detectors.
The gate's eleven accepted findings are individually documented below; a `Safe*`
filename is not evidence that a finding is harmless. Each exception identifies
one finding, describes its concrete behavior and assumptions, and cites test or
source evidence.

The previous allowlist was reviewed entry by entry. The table below is a
historical record of withdrawn suppressions; those rows are not current
exceptions. Current exceptions appear only under “Accepted findings” and are
time-bounded with owner and evidence.

| Previous entry | Decision and evidence |
| --- | --- |
| `SafeAmm` / `unchecked-transfer` | Removed. The AMM checks optional-return transfer results and exact balance deltas. False-return and taxed-token regressions are in `test/Sandwich.t.sol`. |
| `SafeAmm` / `reentrancy-no-eth` | Removed. Liquidity and swaps share a lock, and swap reserves are updated before token calls. `testSafeAmmUpdatesReservesBeforeTokenCallback` checks the callback-visible state and blocked reentry. |
| `SafeLending` / `divide-before-multiply` | Removed. It is not a suppression for the implementation's multiply-then-divide collateral calculation, and no full-precision arithmetic guarantee is claimed. |
| `SafeLending` / `locked-ether` | Removed. Calling ETH custody “by design” did not prove funds could be recovered; the teaching model has no withdrawal path. |
| `SafeLending` / `unused-return` | Removed. The mock feed's round fields are not validated. `test/StaleOracle.t.sol` and the Lab 04 README now state the exact timestamp and price checks and explicitly exclude round-completion, deviation, decimal-scaling, and sequencer checks.<br><br>2026-11-21 note: Fix 10 implemented primary-feed round validation, and Fix 24 documented it; see [accepted finding 5](#accepted-5). |
| `SafeProxy` / `locked-ether` | Removed. No evidence established that ETH sent to the proxy is recoverable through its implementation. |
| `SafeRouter` / `reentrancy-no-eth` | Removed. Fix 3 added effects-before-interactions, a guard, and callback regressions in `test/UncheckedReturn.t.sol`. |
| `SafeVault4626` / `reentrancy-no-eth` | Removed. Deposit and withdrawal share a guard; `test/InflationAttack.t.sol` checks callback attempts in both directions. |
| `SafeFotVault` / `reentrancy-balance` | Removed. Deposit and withdrawal share a guard while retaining balance-delta accounting; `test/FeeOnTransfer.t.sol` checks nested callback attempts. |
| `SafeSplitter` / `reentrancy-eth` | Removed. Fix 4 uses independent pull claims; `test/LoopDoS.t.sol` covers claiming and distribution without payee calls. |
| `SafeUupsVault` / `controlled-delegatecall` | Removed. Owner gating alone does not prove an upgrade target safe, so the detector remains visible. |

Slither 0.11.6 ran a real scan and produced 115 detector results. The sanitized
pre-fix baseline report is committed at
[`docs/slither-baseline-2026-11-21.json`](slither-baseline-2026-11-21.json),
so maintainers can retrieve and re-run the triage without a machine-specific
home-directory path. Fix 36 (2026-11-21) resolved the two
`locked-ether` findings; the re-scan produced 117 detector results,
committed at
[`docs/slither-rescan-2026-11-24.json`](slither-rescan-2026-11-24.json).

## Resolved findings

### Resolved 2026-11-21 (Fix 36): `src/SafeLending.sol` / `locked-ether`

Owner-only `rescueETH` recovers unaccounted ETH while `totalCollateral` protects all credited collateral. The live-balance cap also bounds nested rescues. Removed this pair from `ACCEPTED`. Evidence in `test/RescueEth.t.sol`: `testLendingOwnerRescuesStrayEthPreservingCollateral`, `testLendingRescueCannotTakeCollateral`, `testLendingRescueRejectsNonOwner`, `testLendingRescueRejectsZeroAddress`, and `testConfiguredLendingInheritsRescue`.

### Resolved 2026-11-21 (Fix 36): `src/SafeProxy.sol` / `locked-ether`

Admin-only `rescueETH` recovers proxy-held ETH without adding trust beyond the existing arbitrary upgrade authority. Proxy functions take precedence over fallback dispatch. Removed this pair from `ACCEPTED`. Evidence in `test/RescueEth.t.sol`: `testProxyAdminRescuesEth`, `testProxyRescueRejectsNonAdmin`, `testProxyRescueRejectsExcessAndZeroAddress`, and `testProxyImplementationWorksAfterRescue`.

## Accepted findings (2026-11-21)

Each acceptance below is owned by DefiAudit0x and expires on 2027-05-21.

<a id="accepted-1"></a>
### Entry 1: `src/SafeFotVault.sol` / `incorrect-equality`

**Location:** 36-45

**Verdict:** ACCEPT (Medium). `deposit` rejects only when the computed balance delta is zero, after checking that the balance did not decrease; a donation increases the received delta and is credited to the depositor. This is a deliberate zero-amount check, not a strict comparison to an expected balance. **Evidence:** deposit tests in `test/FeeOnTransfer.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-2"></a>
### Entry 2: `src/SafeFotVault.sol` / `reentrancy-balance`

**Location:** 47-58

**Verdict:** ACCEPT (High). `withdraw` uses the shared `nonReentrant` lock, updates the user's balance before the token call, and reverts if the post-call balance check does not match. Nested callbacks cannot enter deposit or withdraw. **Evidence:** `testSafeFotVaultBlocksCallbacksAcrossDepositAndWithdraw` in `test/FeeOnTransfer.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-3"></a>
### Entry 3: `src/SafeLending.sol` / `divide-before-multiply`

**Location:** 65-74

**Verdict:** ACCEPT (Medium). Both divisions in the collateral-value and LTV calculation round down, so the resulting borrow limit is conservative and cannot enable over-borrowing; each rounding loss is less than one wei. No full-precision arithmetic guarantee is claimed. **Evidence:** LTV-cap tests in `test/StaleOracle.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-5"></a>
### Entry 5: `src/SafeLending.sol` / `unused-return`

**Location:** 108-123

**Verdict:** ACCEPT (Medium). `ConfiguredSafeLending._validatedPrice` intentionally ignores the sequencer feed's `roundId` and `answeredInRound`: it validates status and `startedAt` (nonzero, not future, and beyond the one-hour grace period). The primary price feed separately validates round completeness with `answeredInRound >= roundId`; the sequencer check does not independently validate freshness. **Evidence:** `testL2OracleChecksSequencerStatusAndRecovery` in `test/StaleOracle.t.sol` and the Lab 04 README.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-7"></a>
### Entry 7: `src/SafeSwap.sol` / `incorrect-equality`

**Location:** 57-75

**Verdict:** ACCEPT (Medium). `observations` is kept at length one or two: `swap()` pushes when the count is one and otherwise overwrites slots zero and one. Therefore `count == 2` in `getTWAP` is equivalent to `count >= 2`. **Evidence:** `swap()` in `src/SafeSwap.sol` and TWAP tests in `test/FlashLoan.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-8"></a>
### Entry 8: `src/SafeUupsVault.sol` / `controlled-delegatecall`

**Location:** 52-71

**Verdict:** ACCEPT (High). The delegatecall is the defined UUPS upgrade-and-call behavior. The operation requires `onlyProxy`, `onlyOwner`, and a target that passes the proxiable UUID compatibility check; the residual risk is the documented trust in the owner. **Evidence:** unauthorized-upgrade tests in `test/UupsTakeover.t.sol` and the guards in `src/SafeUupsVault.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-9"></a>
### Entry 9: `src/SafeVault4626.sol` / `incorrect-equality`

**Location:** 49-64

**Verdict:** ACCEPT (Medium). `deposit` requires the measured receipt to equal the requested assets and reverts otherwise, enforcing the documented exact-transfer, non-rebasing asset assumption. A donation that makes the receipt larger also reverts, so accounting does not proceed on an incorrect assumption. **Evidence:** fee-token rejection tests in `test/InflationAttack.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-10"></a>
### Entry 10: `src/SafeVault4626.sol` / `reentrancy-balance`

**Location:** 66-84

**Verdict:** ACCEPT (High). `withdraw` uses `nonReentrant`, burns the user's shares and reduces `totalShares` before the token call, and reverts on a post-call balance mismatch. Nested deposit and withdrawal callback attempts are blocked. **Evidence:** `testSafeVaultBlocksNestedDepositAndWithdrawalCallbacks` in `test/InflationAttack.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-11"></a>
### Entry 11: `src/SafeFotVault.sol` / `reentrancy-balance`

**Location:** 36-45

**Verdict:** ACCEPT (High). `deposit` is guarded by the shared `nonReentrant` lock, so no callback can re-enter while the deposit is in flight; the post-call balance checks (`afterBalance < beforeBalance`, `received == 0`) only ever revert (fail-closed) and the credit is the measured `afterBalance - beforeBalance`. **Evidence:** `testSafeFotVaultBlocksCallbacksAcrossDepositAndWithdraw` in `test/FeeOnTransfer.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-12"></a>
### Entry 12: `src/SafeVault4626.sol` / `reentrancy-balance`

**Location:** 49-64

**Verdict:** ACCEPT (High). `deposit` is guarded by the shared `nonReentrant` lock; shares mint only from the measured receipt after `transferFrom` settles, and the post-call checks (`assetsAfter < assetsBefore`, `received == assets`, `minted > 0`) only ever revert. **Evidence:** fee-token rejection tests in `test/InflationAttack.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21

<a id="accepted-13"></a>
### Entry 13: `src/SafeLending.sol` / `unused-return`

**Location:** 76-90

**Verdict:** ACCEPT (Medium). Base `_validatedPrice` ignores only the third return value (`startedAt`) of `oracle.latestRoundData()`; freshness is established via `updatedAt` (nonzero, not future, within the staleness window) and round completeness via `answeredInRound >= roundId`, so `startedAt` adds nothing for the primary feed. **Evidence:** oracle validation tests in `test/StaleOracle.t.sol`.

**Owner:** DefiAudit0x  
**Expiry:** 2027-05-21
