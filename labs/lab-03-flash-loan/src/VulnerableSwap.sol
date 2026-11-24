// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPriceOracle
/// @notice Trivial oracle interface for the flash loan lab.
interface IPriceOracle {
    function price() external view returns (uint256);
}

/// @title VulnerableSwap
/// @notice Lab 03 — Reserve-manipulation model: a DEX-like swap over
///         synthetic reserves whose ratio is the spot quote.
/// @dev DO NOT DEPLOY. This is a reserve-only model: `swap` only changes
///      synthetic reserve state and `getPrice` only reads their ratio.
///      No tokens are transferred, no flash loan is obtained or repaid,
///      no fee is charged, and no downstream consumer is modeled. The
///      stored `oracle` is unused by the swap logic. A real protocol
///      that trusts such a manipulable spot quote may be exposed, but
///      this lab does not implement or measure that consumer or an
///      end-to-end exploit.
///
/// Violated invariant:
///   "The on-chain spot price reflects the fair market price."
///   In a single transaction, spot prices can be moved arbitrarily.
contract VulnerableSwap {
    IPriceOracle public oracle;
    uint256 public reserveA; // token A reserves
    uint256 public reserveB; // token B reserves

    constructor(address oracle_, uint256 reserveA_, uint256 reserveB_) {
        oracle = IPriceOracle(oracle_);
        reserveA = reserveA_;
        reserveB = reserveB_;
    }

    /// @notice Updates reserves after a swap. The "price" is now
    ///         reserveB / reserveA.
    function swap(uint256 amountIn) external {
        reserveA += amountIn;
        // Constant product k = reserveA * reserveB is nondecreasing, not
        // exactly constant: integer rounding can increase it. E.g. reserves
        // (3, 10) + swap(1) -> (4, 8), product 30 -> 32.
        uint256 amountOut = (reserveB * amountIn) / reserveA;
        reserveB -= amountOut;
    }

    /// @notice Returns the manipulated spot price.
    function getPrice() external view returns (uint256) {
        return (reserveB * 1e18) / reserveA;
    }
}
