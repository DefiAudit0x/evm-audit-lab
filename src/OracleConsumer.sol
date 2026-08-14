// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;



interface IPriceFeed {

    function latestRoundData()

        external

        view

        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

}



/// @notice Educational example: accepts a stale or invalid oracle answer.

contract VulnerableOracleConsumer {

    IPriceFeed public immutable feed;



    constructor(IPriceFeed feed_) {

        feed = feed_;

    }



    function collateralValue(uint256 amount) external view returns (uint256) {

        (, int256 answer, , , ) = feed.latestRoundData();

        require(answer > 0, "invalid price");

        return amount * uint256(answer);

    }

}



/// @notice Remediation: validates positive price, round completeness, and freshness.

contract SafeOracleConsumer {

    IPriceFeed public immutable feed;

    uint256 public immutable maxAge;



    constructor(IPriceFeed feed_, uint256 maxAge_) {

        feed = feed_;

        maxAge = maxAge_;

    }



    function collateralValue(uint256 amount) external view returns (uint256) {

        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();

        require(answer > 0, "invalid price");

        require(updatedAt != 0 && block.timestamp - updatedAt <= maxAge, "stale price");

        require(answeredInRound >= roundId, "incomplete round");

        return amount * uint256(answer);

    }

}

