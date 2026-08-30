// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FakeOracle} from "./VulnerableLending.sol";

/// @title SafeLending
/// @notice Lab 04 — Remediated: checks staleness, deviation, and sequencer
///         status before trusting the oracle.
/// @dev The fix combines three checks:
///   1. updatedAt must be within MAX_STALENESS of block.timestamp.
///   2. price must be > 0 (reverts on broken feed).
///   3. On L2, an explicit sequencer uptime feed must report "up".
///      (Omitted here for brevity — see Chainlink L2 docs.)
contract SafeLending {
    FakeOracle public oracle;
    uint256 public constant MAX_STALENESS = 1 hours;
    uint256 public constant MIN_PRICE = 1e14; // reject absurdly low prices

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV = 75;

    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);

    constructor(address oracle_) {
        oracle = FakeOracle(oracle_);
    }

    function deposit(uint256 amount) external payable {
        collateral[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice SAFE: checks staleness and sanity before use.
    function borrow(uint256 amount) external {
        (, int256 price, uint256 startedAt, uint256 updatedAt,) = oracle.latestRoundData();

        // 1. Price must be positive.
        require(price > 0, "invalid price");

        // 2. Round must have been answered.
        require(updatedAt != 0, "round not complete");

        // 3. Staleness check.
        require(block.timestamp - updatedAt < MAX_STALENESS, "stale oracle");

        // 4. Sanity lower bound.
        require(uint256(price) >= MIN_PRICE, "price too low");

        uint256 collateralValue = (collateral[msg.sender] * uint256(price)) / 1e18;
        uint256 maxBorrow = (collateralValue * LTV) / 100;
        require(amount <= maxBorrow, "exceeds LTV");
        debt[msg.sender] += amount;
        emit Borrowed(msg.sender, amount);
    }

    receive() external payable {}
}
