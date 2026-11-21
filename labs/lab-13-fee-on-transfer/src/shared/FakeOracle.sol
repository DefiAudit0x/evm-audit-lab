// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FakeOracle {
    uint8 public constant decimals = 18;
    uint256 public latestPrice;
    uint256 public updatedAt;

    constructor(uint256 price_) {
        latestPrice = price_;
        updatedAt = block.timestamp;
    }

    function setStale(uint256 stalePrice, uint256 staleTimestamp) external {
        latestPrice = stalePrice;
        updatedAt = staleTimestamp;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (0, int256(latestPrice), 0, updatedAt, 0);
    }
}
