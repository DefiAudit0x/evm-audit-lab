// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSwap} from "../src/VulnerableSwap.sol";
import {SafeSwap} from "../src/SafeSwap.sol";

/// @title FlashLoan.t.sol
/// @notice Lab 03 — Reserve-model demonstration + TWAP regression.
///
/// Lab: Flash Loan Price Manipulation
///
/// Model scope:
///   VulnerableSwap is a reserve-manipulation model. It updates synthetic
///   reserve values but transfers no tokens and implements no flash lender,
///   fee, repayment, or downstream consumer. The test measures reserve and
///   spot-price changes only.
///
/// Violated invariant:
///   "The on-chain spot price reflects the fair market price."
///   In a single transaction, spot reserves can be moved arbitrarily.
///
/// Reproduction:
///   1. Deploy VulnerableSwap with synthetic reserves A=10_000, B=10_000.
///   2. Call swap(1_000_000 A); the model records A=1_010_000 and
///      B≈99.0099, changing the spot quote from 1.0 to ≈0.00009803.
///   3. No assets move, no loan is issued or repaid, and no consumer loss
///      or attacker profit is measured.
///
/// Remediation:
///   Use a cumulative-price TWAP oracle (see SafeSwap). A same-block spot
///   manipulation contributes zero time weight; an attacker
///   must sustain the manipulated price across the observation window.
///
/// Regression test:
///   The same spot manipulation against SafeSwap.getTWAP() must return
///   the pre-manipulation price exactly.
contract FlashLoanTest is Test {
    VulnerableSwap vulnerable;
    SafeSwap safe;

    uint256 constant INITIAL_A = 10_000 ether;
    uint256 constant INITIAL_B = 10_000 ether;
    uint256 constant MANIP_AMOUNT = 1_000_000 ether;

    function setUp() public {
        vulnerable = new VulnerableSwap(address(0), INITIAL_A, INITIAL_B);
        safe = new SafeSwap(INITIAL_A, INITIAL_B);
    }

    /// @notice Reserve model: one synthetic swap changes its spot quote.
    function testReserveManipulationModelChangesSpotPrice() public {
        uint256 priceBefore = vulnerable.getPrice();
        assertEq(priceBefore, 1e18, "initial price should be 1.0");

        // The model accepts an amount directly; no token or loan transfer occurs.
        vulnerable.swap(MANIP_AMOUNT);

        uint256 priceAfter = vulnerable.getPrice();
        assertEq(vulnerable.reserveA(), INITIAL_A + MANIP_AMOUNT, "input reserve not updated");
        assertEq(vulnerable.reserveB(), 99.009900990099009901 ether, "unexpected output reserve");
        // The synthetic spot quote falls by more than 90%.
        assertLt(priceAfter, priceBefore / 10, "spot price should be manipulated");
    }

    /// @notice Regression: a same-block spot manipulation has zero
    ///         weight in a cumulative-price TWAP.
    function testTWAPResistsSingleBlockManipulation() public {
        // Cross the uint32 boundary while building the observation history.
        uint256 start = uint256(type(uint32).max) - 1;
        vm.warp(start);
        safe = new SafeSwap(INITIAL_A, INITIAL_B);
        uint256 period = safe.PERIOD();

        vm.warp(start + period - 1);
        vm.expectRevert("insufficient observation history");
        safe.getTWAP();

        vm.warp(start + period);
        uint256 twapBefore = safe.getTWAP();
        assertEq(twapBefore, 1e18, "baseline TWAP should be 1.0");

        // Manipulate immediately after the observation window closes.
        // No time elapses at the manipulated price in this block.
        safe.swap(MANIP_AMOUNT);

        // The manipulation must actually move the reserves (m-02): without
        // the reserve update this regression would pass on an
        // unmanipulated pool.
        assertEq(safe.reserveA(), INITIAL_A + MANIP_AMOUNT, "manipulation did not move reserve A");
        assertEq(safe.reserveB(), 99.009900990099009901 ether, "manipulation did not move reserve B");

        uint256 twapAfter = safe.getTWAP();
        // The manipulated spot contributes zero elapsed-time weight.
        assertEq(twapAfter, twapBefore, "same-block swap changed TWAP");

        uint256 newSpot = safe.reserveB() * 1e18 / safe.reserveA();
        // The manipulated spot must actually collapse against the TWAP.
        assertLt(newSpot, twapBefore / 10, "manipulated spot did not move vs the TWAP");
        vm.warp(start + period + 1);
        assertEq(safe.getTWAP(), (twapBefore * period + newSpot) / (period + 1), "wrong time weights");

        // At the next boundary the newest checkpoint is mature and the
        // entire averaging window reflects the sustained reserve change.
        vm.warp(start + 2 * period);
        assertEq(safe.getTWAP(), newSpot, "newest mature checkpoint was not used");

        safe.swap(1 ether);
        assertEq(safe.lastTimestamp(), start + 2 * period);
        (, uint256 previousTimestamp) = safe.observations(0);
        (, uint256 latestTimestamp) = safe.observations(1);
        assertEq(previousTimestamp, start + period);
        assertEq(latestTimestamp, start + 2 * period);
        vm.expectRevert();
        safe.observations(2);

        assertEq(safe.getTWAP(), newSpot, "rolling the checkpoints changed TWAP");
    }

    /// @notice Regression (m-04): the constant product is nondecreasing,
    ///         not exactly constant — integer rounding can increase it.
    function testConstantProductIsNondecreasingNotExactlyConstant() public {
        VulnerableSwap small = new VulnerableSwap(address(0), 3, 10);
        assertEq(small.reserveA() * small.reserveB(), 30, "product before the swap");
        small.swap(1);
        assertEq(small.reserveA(), 4, "reserve A after swap(1) from (3, 10)");
        assertEq(small.reserveB(), 8, "reserve B after swap(1) from (3, 10)");
        assertEq(small.reserveA() * small.reserveB(), 32, "rounding increased the product 30 -> 32");

        // The same property holds on the large pool: the product never falls.
        uint256 productBefore = vulnerable.reserveA() * vulnerable.reserveB();
        vulnerable.swap(MANIP_AMOUNT);
        assertGe(vulnerable.reserveA() * vulnerable.reserveB(), productBefore, "product must not decrease");
    }

    /// @notice Varied timing + multiple swaps: the TWAP is checked against
    ///         an independent reference computed in this test from the
    ///         test-side reserve bookkeeping (spot price x elapsed time),
    ///         not from the contract's own cumulative state.
    function testTWAPVariedTimingAndMultipleSwaps() public {
        uint256 start = 10_000;
        vm.warp(start);
        safe = new SafeSwap(INITIAL_A, INITIAL_B);
        uint256 period = safe.PERIOD();

        // Test-side reference bookkeeping (independent of SafeSwap's math).
        uint256 refA = INITIAL_A;
        uint256 refB = INITIAL_B;
        uint256 spot;

        // One full period at the initial spot: TWAP must be exactly 1.0.
        vm.warp(start + period);
        assertEq(safe.getTWAP(), 1e18, "baseline TWAP should be 1.0");

        // Swap 1: 1,000 A at start + PERIOD. New spot from the reference.
        safe.swap(1_000 ether);
        (refA, refB, spot) = _applySwap(refA, refB, 1_000 ether);
        assertEq(safe.reserveA(), refA, "reference reserve A after swap 1");
        assertEq(safe.reserveB(), refB, "reference reserve B after swap 1");
        uint256 spot1 = spot;

        // Half a period at the moved spot: TWAP = (1.0 * P + spot1 * P/2) / 1.5P.
        vm.warp(start + period + period / 2);
        assertEq(
            safe.getTWAP(),
            (1e18 * period + spot1 * (period / 2)) / (period + period / 2),
            "TWAP after varied timing must match the reference"
        );

        // Swap 2: 5,000 A at start + 2 * PERIOD (a full period at spot1).
        vm.warp(start + 2 * period);
        safe.swap(5_000 ether);
        (refA, refB, spot) = _applySwap(refA, refB, 5_000 ether);
        assertEq(safe.reserveA(), refA, "reference reserve A after swap 2");
        assertEq(safe.reserveB(), refB, "reference reserve B after swap 2");
        uint256 spot2 = spot;

        // A quarter period at the new spot. The window starts at the oldest
        // checkpoint (start + PERIOD): spot1 for one period, spot2 for P/4.
        vm.warp(start + 2 * period + period / 4);
        assertEq(
            safe.getTWAP(),
            (spot1 * period + spot2 * (period / 4)) / (period + period / 4),
            "TWAP after the second swap must match the reference"
        );

        // Swap 3: 500 A at start + 3 * PERIOD. The checkpoints roll over:
        // the oldest checkpoint is now start + 2 * PERIOD.
        vm.warp(start + 3 * period);
        safe.swap(500 ether);
        (refA, refB, spot) = _applySwap(refA, refB, 500 ether);
        assertEq(safe.reserveA(), refA, "reference reserve A after swap 3");
        assertEq(safe.reserveB(), refB, "reference reserve B after swap 3");
        uint256 spot3 = spot;
        (, uint256 oldestTs) = safe.observations(0);
        (, uint256 newestTs) = safe.observations(1);
        assertEq(oldestTs, start + 2 * period, "checkpoints must roll over");
        assertEq(newestTs, start + 3 * period, "newest checkpoint must be the latest swap");

        // Half a period at the newest spot. The window starts at the rolled
        // checkpoint (start + 2 * PERIOD): spot2 for one period, spot3 for P/2.
        vm.warp(start + 3 * period + period / 2);
        assertEq(
            safe.getTWAP(),
            (spot2 * period + spot3 * (period / 2)) / (period + period / 2),
            "TWAP after rollover must match the reference"
        );
    }

    /// @notice Reference constant-product step for the TWAP test above:
    ///         applies a swap to test-side reserves and returns the new
    ///         reserves and spot price, independently of SafeSwap's state.
    function _applySwap(uint256 reserveA_, uint256 reserveB_, uint256 amountIn)
        internal
        pure
        returns (uint256 newA, uint256 newB, uint256 spot)
    {
        uint256 out = (reserveB_ * amountIn) / (reserveA_ + amountIn);
        newA = reserveA_ + amountIn;
        newB = reserveB_ - out;
        spot = newB * 1e18 / newA;
    }
}
