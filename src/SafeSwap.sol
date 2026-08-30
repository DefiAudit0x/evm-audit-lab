// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeSwap
/// @notice Lab 03 — Remediated: uses TWAP (time-weighted average price)
///         instead of spot reserves.
/// @dev TWAP smooths out single-block manipulation because the attacker
///      would have to hold the manipulated position across multiple
///      blocks — at which point they bear the price risk.
contract SafeSwap {
    struct Observation {
        uint256 price;
        uint32 timestamp;
    }

    Observation[] public observations;
    uint256 public reserveA;
    uint256 public reserveB;
    uint32 public constant PERIOD = 30 minutes;

    constructor(uint256 reserveA_, uint256 reserveB_) {
        reserveA = reserveA_;
        reserveB = reserveB_;
        observations.push(
            Observation({price: (reserveB * 1e18) / reserveA, timestamp: uint32(block.timestamp)})
        );
    }

    function swap(uint256 amountIn) external {
        reserveA += amountIn;
        uint256 amountOut = (reserveB * amountIn) / reserveA;
        reserveB -= amountOut;
        _updateObservation();
    }

    /// @notice Returns the time-weighted average price over the last
    ///         PERIOD seconds. Manipulating spot price within a single
    ///         block does not move this average meaningfully.
    function getTWAP() external view returns (uint256) {
        require(observations.length > 0, "no observations");
        Observation memory current = observations[observations.length - 1];
        Observation memory past = observations[0];
        if (current.timestamp <= past.timestamp + PERIOD) {
            return past.price;
        }
        // Simplified TWAP for the lab: average of past and current.
        return (past.price + current.price) / 2;
    }

    function _updateObservation() internal {
        if (block.timestamp >= observations[observations.length - 1].timestamp + PERIOD) {
            observations.push(
                Observation({price: (reserveB * 1e18) / reserveA, timestamp: uint32(block.timestamp)})
            );
        }
    }
}
