// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeSwap
/// @notice Lab 03 — Remediated: uses a cumulative-price TWAP instead of spot reserves.
/// @dev The cumulative price advances with elapsed time, so a same-block spot
///      manipulation contributes essentially zero weight to the TWAP. A consumer
///      must have at least PERIOD of observation history before reading it.
contract SafeSwap {
    struct Observation {
        uint256 priceCumulative;
        uint32 timestamp;
    }

    Observation[] public observations;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public priceCumulativeLast;
    uint32 public lastTimestamp;
    uint32 public constant PERIOD = 30 minutes;

    constructor(uint256 reserveA_, uint256 reserveB_) {
        require(reserveA_ > 0, "zero reserve A");
        require(reserveB_ > 0, "zero reserve B");
        reserveA = reserveA_;
        reserveB = reserveB_;
        lastTimestamp = uint32(block.timestamp);
        observations.push(Observation({priceCumulative: 0, timestamp: lastTimestamp}));
    }

    function swap(uint256 amountIn) external {
        require(amountIn > 0, "zero input");

        _accumulatePrice();

        reserveA += amountIn;
        uint256 amountOut = (reserveB * amountIn) / reserveA;
        require(amountOut > 0 && amountOut < reserveB, "invalid swap");
        reserveB -= amountOut;

        // Record the post-swap cumulative price once a full observation
        // period has elapsed since the last recorded observation.
        if (block.timestamp >= observations[observations.length - 1].timestamp + PERIOD) {
            observations.push(
                Observation({
                    priceCumulative: priceCumulativeLast,
                    timestamp: uint32(block.timestamp)
                })
            );
        }
    }

    /// @notice Returns a time-weighted average price over an observation
    ///         window of at least PERIOD seconds.
    function getTWAP() external view returns (uint256) {
        require(observations.length > 0, "no observations");

        Observation memory past = observations[observations.length - 1];
        uint256 currentCumulative = priceCumulativeLast;
        uint256 elapsedSinceUpdate = block.timestamp - lastTimestamp;

        if (elapsedSinceUpdate > 0) {
            currentCumulative += _spotPrice() * elapsedSinceUpdate;
        }

        uint256 elapsed = block.timestamp - past.timestamp;
        require(elapsed >= PERIOD, "insufficient observation history");

        return (currentCumulative - past.priceCumulative) / elapsed;
    }

    function _spotPrice() internal view returns (uint256) {
        return (reserveB * 1e18) / reserveA;
    }

    function _accumulatePrice() internal {
        uint256 elapsed = block.timestamp - lastTimestamp;
        if (elapsed > 0) {
            priceCumulativeLast += _spotPrice() * elapsed;
            lastTimestamp = uint32(block.timestamp);
        }
    }
}
