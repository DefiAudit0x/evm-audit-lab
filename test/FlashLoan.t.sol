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

        uint256 twapAfter = safe.getTWAP();
        // The manipulated spot contributes zero elapsed-time weight.
        assertEq(twapAfter, twapBefore, "same-block swap changed TWAP");

        uint256 newSpot = safe.reserveB() * 1e18 / safe.reserveA();
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
}
