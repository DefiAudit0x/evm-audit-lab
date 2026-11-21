// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPriceOracle
/// @notice Trivial oracle interface for the flash loan lab.
interface IPriceOracle {
    function price() external view returns (uint256);
}

/// @title VulnerableSwap
/// @notice Lab 03 — Vulnerable DEX-like swap that reads spot price from
///         a single on-chain oracle (a Uniswap-V2-style pool balance).
/// @dev DO NOT DEPLOY. The "price" is derived from reserves that an
///      attacker can manipulate within a single transaction using a
///      flash loan.
///
/// Threat model:
///   An attacker with no capital can borrow a huge amount of one asset
///   via a flash loan, swap it into the pool to skew the price, exploit
///   the consumer contract, then repay the loan in the same transaction.
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
        // Constant product k = reserveA * reserveB must be preserved.
        uint256 amountOut = (reserveB * amountIn) / reserveA;
        reserveB -= amountOut;
    }

    /// @notice Returns the manipulated spot price.
    function getPrice() external view returns (uint256) {
        return (reserveB * 1e18) / reserveA;
    }
}
