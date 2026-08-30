// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableLending
/// @notice Lab 04 — Vulnerable lending protocol that trusts a Chainlink-
///         style oracle without checking staleness or deviation.
/// @dev DO NOT DEPLOY. Real Chainlink feeds expose `latestRoundData`
///      which returns (roundId, answer, startedAt, updatedAt, answeredInRound).
///      This simplified oracle mimics a feed that stops updating —
///      VulnerableLending ignores the updatedAt timestamp entirely.
///
/// Threat model:
///   The oracle goes stale (L2 sequencer outage, oracle node outage,
///   Chainlink multisig pause). The lending protocol still uses the
///   last reported price as if it were current. An attacker deposits
///   stale-priced collateral and borrows against the inflated value.
///
/// Violated invariant:
///   "Collateral is valued at the current fair market price."
contract FakeOracle {
    uint256 public latestPrice;
    uint256 public updatedAt;

    constructor(uint256 price_) {
        latestPrice = price_;
        updatedAt = block.timestamp;
    }

    /// @notice Simulates "no new update" — price stays at the old value.
    function setStale(uint256 stalePrice, uint256 staleTimestamp) external {
        latestPrice = stalePrice;
        updatedAt = staleTimestamp;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (0, int256(latestPrice), 0, updatedAt, 0);
    }
}

contract VulnerableLending {
    FakeOracle public oracle;
    uint256 public constant MAX_STALENESS = 1 hours;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV = 75; // 75% loan-to-value

    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);

    constructor(address oracle_) {
        oracle = FakeOracle(oracle_);
    }

    function deposit(uint256 amount) external payable {
        collateral[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice VULNERABLE: trusts the latest price without checking staleness.
    function borrow(uint256 amount) external {
        (, int256 price,,,) = oracle.latestRoundData();
        uint256 collateralValue = (collateral[msg.sender] * uint256(price)) / 1e18;
        uint256 maxBorrow = (collateralValue * LTV) / 100;
        require(amount <= maxBorrow, "exceeds LTV");
        debt[msg.sender] += amount;
        emit Borrowed(msg.sender, amount);
    }

    receive() external payable {}
}
