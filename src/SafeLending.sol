// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface LendingFeed {
    function decimals() external view returns (uint8);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

interface LendingTwap {
    function getTWAP() external view returns (uint256);
}

/// @title SafeLending
/// @notice Lab 04 — Rejects unfunded collateral, cumulative over-borrowing,
///         and zero, future, stale, or below-minimum oracle prices.
/// @dev Educational debt-accounting model: no loan asset is transferred.
///      Debt and normalized prices have 18 decimals. For L2 or TWAP checks,
///      use ConfiguredSafeLending with feeds appropriate to the deployment.
contract SafeLending {
    LendingFeed public immutable oracle;
    uint256 public constant MAX_STALENESS = 1 hours;
    uint256 public constant MIN_PRICE = 1e14; // reject absurdly low prices

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV = 75;

    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);

    constructor(address oracle_) {
        oracle = LendingFeed(oracle_);
    }

    function deposit(uint256 amount) external payable {
        require(amount > 0 && msg.value == amount, "invalid deposit");
        collateral[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice SAFE: checks staleness and sanity before use.
    function borrow(uint256 amount) external {
        uint256 price = _validatedPrice();

        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;
        uint256 maxBorrow = (collateralValue * LTV) / 100;
        uint256 existing = debt[msg.sender];
        require(existing <= maxBorrow && amount <= maxBorrow - existing, "exceeds LTV");
        debt[msg.sender] += amount;
        emit Borrowed(msg.sender, amount);
    }

    function _validatedPrice() internal view virtual returns (uint256 normalized) {
        (uint80 roundId, int256 price,, uint256 updatedAt, uint80 answeredInRound) = oracle.latestRoundData();

        require(price > 0, "invalid price");
        require(updatedAt != 0 && answeredInRound >= roundId, "round not complete");
        require(updatedAt <= block.timestamp, "future oracle");
        require(block.timestamp - updatedAt < MAX_STALENESS, "stale oracle");

        uint8 decimals = oracle.decimals();
        require(decimals <= 18, "unsupported decimals");
        uint256 scale = 10 ** (18 - decimals);
        require(uint256(price) <= type(uint256).max / scale, "price overflow");
        normalized = uint256(price) * scale;
        require(normalized >= MIN_PRICE, "price too low");
    }

    receive() external payable {}
}

/// @notice Optional L2 uptime and deviation checks, configured at deployment.
/// @dev The TWAP must quote the same pair as the primary feed, scaled to 18 decimals.
contract ConfiguredSafeLending is SafeLending {
    LendingFeed public immutable sequencer;
    LendingTwap public immutable twap;
    uint256 public constant SEQUENCER_GRACE = 1 hours;
    uint256 public constant MAX_DEVIATION_PERCENT = 10;

    constructor(address oracle_, address sequencer_, address twap_) SafeLending(oracle_) {
        sequencer = LendingFeed(sequencer_);
        twap = LendingTwap(twap_);
    }

    function _validatedPrice() internal view override returns (uint256 price) {
        if (address(sequencer) != address(0)) {
            (, int256 status, uint256 startedAt,,) = sequencer.latestRoundData();
            require(status == 0, "sequencer down");
            require(startedAt != 0 && startedAt <= block.timestamp, "invalid sequencer timestamp");
            require(block.timestamp - startedAt > SEQUENCER_GRACE, "sequencer grace period");
        }

        price = super._validatedPrice();
        if (address(twap) != address(0)) {
            uint256 average = twap.getTWAP();
            require(average != 0, "invalid TWAP");
            uint256 difference = price > average ? price - average : average - price;
            require(difference <= average / (100 / MAX_DEVIATION_PERCENT), "price deviation");
        }
    }
}
