// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSwap} from "../src/VulnerableSwap.sol";
import {SafeSwap} from "../src/SafeSwap.sol";

/// @title FlashLoan.t.sol
/// @notice Lab 03 — Exploit + regression test for flash loan price manipulation.
///
/// Lab: Flash Loan Price Manipulation
///
/// Threat model:
///   Attacker borrows 1,000,000 token A via a flash loan, swaps it into
///   the VulnerableSwap pool to massively skew reserves, then calls a
///   downstream consumer that reads the manipulated spot price. The
///   attacker repays the flash loan within the same transaction.
///
/// Violated invariant:
///   "The on-chain spot price reflects the fair market price."
///   In a single transaction, spot reserves can be moved arbitrarily.
///
/// Reproduction:
///   1. Deploy VulnerableSwap with reserves A=10_000, B=10_000.
///      Spot price = 1.0.
///   2. Attacker swaps 1_000_000 A into the pool.
///   3. New reserves: A=1_010_000, B≈9_901 → price ≈ 0.0098.
///   4. Attacker now exploits any consumer that reads VulnerableSwap
///      .getPrice() (e.g. a lending protocol that uses this as the
///      price for collateral valuation).
///   5. Attacker repays the flash loan. Net profit > 0.
///
/// Remediation:
///   Use a cumulative-price TWAP oracle (see SafeSwap). A same-block spot
///   manipulation contributes essentially zero time weight; an attacker
///   must sustain the manipulated price across the observation window.
///
/// Regression test:
///   The same spot manipulation against SafeSwap.getTWAP() must return
///   a price within epsilon of the pre-manipulation price.
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

    /// @notice Exploit: spot price drops from 1.0 to ~0.0098 after one swap.
    function testExploitFlashLoanPriceManipulation() public {
        uint256 priceBefore = vulnerable.getPrice();
        assertEq(priceBefore, 1e18, "initial price should be 1.0");

        // Attacker swaps a huge amount via flash loan.
        vulnerable.swap(MANIP_AMOUNT);

        uint256 priceAfter = vulnerable.getPrice();
        // Price has dropped by >90%.
        assertLt(priceAfter, priceBefore / 10, "spot price should be manipulated");
    }

    /// @notice Regression: a same-block spot manipulation has negligible
    ///         weight in a cumulative-price TWAP.
    function testTWAPResistsSingleBlockManipulation() public {
        // Build the minimum observation history using the honest price.
        vm.warp(block.timestamp + safe.PERIOD());
        uint256 twapBefore = safe.getTWAP();
        assertEq(twapBefore, 1e18, "baseline TWAP should be 1.0");

        // Manipulate immediately after the observation window closes.
        // No time elapses at the manipulated price in this block.
        safe.swap(MANIP_AMOUNT);

        uint256 twapAfter = safe.getTWAP();
        // The manipulated spot contributes zero elapsed-time weight.
        assertApproxEqRel(twapBefore, twapAfter, 0.05e18, "TWAP moved too much");
    }
}
