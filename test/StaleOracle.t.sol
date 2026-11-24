// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableLending} from "../src/VulnerableLending.sol";
import {FakeOracle} from "../src/shared/FakeOracle.sol";
import {SafeLending, ConfiguredSafeLending, LendingFeed, LendingTwap} from "../src/SafeLending.sol";

/// @title StaleOracle.t.sol
/// @notice Lab 04 — Exploit + regression test for stale oracle data.
///
/// Lab: Stale Oracle Data
///
/// Threat model:
///   The stale-price test models a feed that stops updating. Additional
///   regression tests mock round integrity, decimals, L2 sequencer status,
///   and TWAP deviation checks.
///   The lending protocol still reads `latestRoundData` and treats
///   the stale price as current. An attacker borrows against
///   collateral at the stale (now incorrect) price.
///
/// Violated invariant:
///   "Collateral is valued at the current fair market price."
///
/// Reproduction:
///   1. Deploy a fake oracle that returns price = $2,000 for ETH
///      (correct at deployment).
///   2. User deposits 1 ETH. Collateral value = $2,000.
///   3. Oracle goes stale: the price is frozen at $2,000 even though
///      the real market price has crashed to $500.
///   4. Attacker deposits 1 ETH, but the protocol credits them
///      with $2,000 of collateral value at the stale $2,000 price.
///      At the stale price, 1 ETH = $2,000, so the attacker
///      can borrow $1,500 (75% LTV). If the real price is $500, then
///      the attacker's collateral is only worth $500. The recorded
///      debt exceeds that assumed value by $1,000; no loan asset is paid
///      out and no realized profit is demonstrated.
///
/// Remediation:
///   Check `block.timestamp - updatedAt < MAX_STALENESS`. Optionally
///   also check sequencer uptime on L2s.
///
/// Regression test:
///   The same stale-price call against SafeLending must revert with
///   "stale oracle".
contract StaleOracleTest is Test {
    FakeOracle oracle;
    VulnerableLending vulnerable;
    SafeLending safe;

    address attacker = makeAddr("attacker");

    function setUp() public {
        oracle = new FakeOracle(2_000 ether); // ETH = $2,000
        vulnerable = new VulnerableLending(address(oracle));
        safe = new SafeLending(address(oracle));
    }

    /// @notice Exploit: attacker borrows against the stale price.
    function testExploitStaleOracle() public {
        // Time travel 2 hours — oracle hasn't updated.
        vm.warp(block.timestamp + 2 hours);

        // Oracle still reports $2,000 (stale).
        (, int256 price,,,) = oracle.latestRoundData();
        assertEq(uint256(price), 2_000 ether, "oracle should still report stale price");

        // Attacker deposits 1 ETH. At the stale price, that's $2,000.
        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);
        vulnerable.deposit{value: 1 ether}(1 ether);

        // At 75% LTV, the protocol accepts $1,500 of debt.
        // At an assumed real market price of $500, collateral is worth $500.
        // Recorded debt exceeds that value by $1,000. This only changes debt
        // accounting: no loan asset is paid out and no realized profit is demonstrated.
        vulnerable.borrow(1_500 ether);
        vm.stopPrank();

        assertEq(vulnerable.debt(attacker), 1_500 ether, "debt should be 1,500");
    }

    /// @notice Regression: SafeLending rejects the stale oracle.
    function testCannotBorrowWithStaleOracleSafe() public {
        vm.warp(block.timestamp + 2 hours);

        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);
        safe.deposit{value: 1 ether}(1 ether);

        vm.expectRevert("stale oracle");
        safe.borrow(1_500 ether);
        vm.stopPrank();

        assertEq(safe.debt(attacker), 0, "no debt should accrue");
    }

    function testSafeDepositRejectsUnfundedCollateral() public {
        vm.prank(attacker);
        vm.expectRevert("invalid deposit");
        safe.deposit(1 ether);
        assertEq(safe.collateral(attacker), 0);
        assertEq(address(safe).balance, 0);
    }

    function testSafeDepositRejectsZeroAndMismatchedValue() public {
        vm.deal(attacker, 2 ether);
        vm.startPrank(attacker);
        vm.expectRevert("invalid deposit");
        safe.deposit(0);
        vm.expectRevert("invalid deposit");
        safe.deposit{value: 1 ether}(2 ether);
        vm.expectRevert("invalid deposit");
        safe.deposit{value: 2 ether}(1 ether);
        vm.stopPrank();
        assertEq(safe.collateral(attacker), 0);
        assertEq(address(safe).balance, 0);
        assertEq(attacker.balance, 2 ether);
    }

    function _depositSafe() internal {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        safe.deposit{value: 1 ether}(1 ether);
    }

    function testSafeBorrowCapsCumulativeDebt() public {
        _depositSafe();
        vm.startPrank(attacker);
        safe.borrow(1_000 ether);
        vm.expectRevert("exceeds LTV");
        safe.borrow(501 ether);
        assertEq(safe.debt(attacker), 1_000 ether);
        safe.borrow(500 ether);
        vm.expectRevert("exceeds LTV");
        safe.borrow(1);
        vm.stopPrank();
        assertEq(safe.debt(attacker), 1_500 ether);
        assertEq(safe.collateral(attacker), 1 ether);
    }

    function testSafeBorrowRejectsDebtAboveNewLimit() public {
        _depositSafe();
        vm.prank(attacker);
        safe.borrow(1_000 ether);
        oracle.setStale(1_000 ether, block.timestamp);
        vm.prank(attacker);
        vm.expectRevert("exceeds LTV");
        safe.borrow(1);
        assertEq(safe.debt(attacker), 1_000 ether);
    }

    function testSafeOracleRejectsFutureTimestamp() public {
        _depositSafe();
        oracle.setStale(2_000 ether, block.timestamp + 1);
        vm.prank(attacker);
        vm.expectRevert("future oracle");
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 0);
    }

    function testSafeOracleRejectsMissingTimestamp() public {
        _depositSafe();
        oracle.setStale(2_000 ether, 0);
        vm.prank(attacker);
        // The fake feed has no meaningful round IDs; this exercises only the
        // SafeLending check that updatedAt is nonzero.
        vm.expectRevert("round not complete");
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 0);
    }

    function testSafeOracleRejectsInvalidPrices() public {
        _depositSafe();
        uint256[3] memory prices = [uint256(0), type(uint256).max, safe.MIN_PRICE() - 1];
        for (uint256 i; i < prices.length; i++) {
            oracle.setStale(prices[i], block.timestamp);
            vm.prank(attacker);
            vm.expectRevert(i == 2 ? bytes("price too low") : bytes("invalid price"));
            safe.borrow(1 ether);
            assertEq(safe.debt(attacker), 0);
        }
    }

    function testSafeOracleNormalizesEightDecimalFeed() public {
        _depositSafe();
        vm.mockCall(address(oracle), abi.encodeCall(LendingFeed.decimals, ()), abi.encode(uint8(8)));
        oracle.setStale(2_000e8, block.timestamp);

        vm.prank(attacker);
        safe.borrow(1_500 ether);
        assertEq(safe.debt(attacker), 1_500 ether);
    }

    function testSafeOracleRejectsUnsupportedDecimals() public {
        vm.mockCall(address(oracle), abi.encodeCall(LendingFeed.decimals, ()), abi.encode(uint8(19)));
        vm.expectRevert("unsupported decimals");
        safe.borrow(0);
    }

    function testSafeOracleRequiresAnswerFromCurrentOrLaterRound() public {
        _depositSafe();
        bytes memory query = abi.encodeCall(LendingFeed.latestRoundData, ());
        vm.mockCall(address(oracle), query, abi.encode(uint80(42), int256(2_000 ether), 0, block.timestamp, uint80(41)));
        vm.prank(attacker);
        vm.expectRevert("round not complete");
        safe.borrow(1 ether);
        vm.mockCall(address(oracle), query, abi.encode(uint80(42), int256(2_000 ether), 0, block.timestamp, uint80(42)));
        vm.prank(attacker);
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 1 ether);
    }

    function testL2OracleChecksSequencerStatusAndRecovery() public {
        address uptime = address(new FakeOracle(0));
        safe = new ConfiguredSafeLending(address(oracle), uptime, address(0));
        _depositSafe();
        vm.warp(2 hours);
        oracle.setStale(2_000 ether, block.timestamp);

        _expectSequencerRejection(uptime, 1, 1, "sequencer down");
        _expectSequencerRejection(uptime, 0, 0, "invalid sequencer timestamp");
        _expectSequencerRejection(uptime, 0, block.timestamp + 1, "invalid sequencer timestamp");
        _expectSequencerRejection(uptime, 0, block.timestamp - 1 hours, "sequencer grace period");
        _mockSequencer(uptime, 0, block.timestamp - 1 hours - 1);
        vm.prank(attacker);
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 1 ether);
    }

    function _mockSequencer(address uptime, int256 status, uint256 startedAt) internal {
        vm.mockCall(
            uptime,
            abi.encodeCall(LendingFeed.latestRoundData, ()),
            abi.encode(uint80(1), status, startedAt, 0, uint80(1))
        );
    }

    function _expectSequencerRejection(address uptime, int256 status, uint256 startedAt, string memory reason)
        internal
    {
        _mockSequencer(uptime, status, startedAt);
        vm.prank(attacker);
        vm.expectRevert(bytes(reason));
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 0);
    }

    function testOracleRejectsUnavailableOrZeroTwap() public {
        address referenceFeed = address(new FakeOracle(0));
        safe = new ConfiguredSafeLending(address(oracle), address(0), referenceFeed);
        bytes memory query = abi.encodeCall(LendingTwap.getTWAP, ());

        vm.mockCallRevert(referenceFeed, query, abi.encodeWithSignature("Error(string)", "no TWAP history"));
        vm.expectRevert("no TWAP history");
        safe.borrow(0);
        vm.clearMockedCalls();

        vm.mockCall(referenceFeed, query, abi.encode(uint256(0)));
        vm.expectRevert("invalid TWAP");
        safe.borrow(0);
    }

    function testOracleChecksDeviationAgainstTwap() public {
        address referenceFeed = address(new FakeOracle(0));
        safe = new ConfiguredSafeLending(address(oracle), address(0), referenceFeed);
        _depositSafe();
        vm.mockCall(referenceFeed, abi.encodeCall(LendingTwap.getTWAP, ()), abi.encode(2_000 ether));
        vm.mockCall(address(oracle), abi.encodeCall(LendingFeed.decimals, ()), abi.encode(uint8(8)));

        oracle.setStale(2_200e8 + 1, block.timestamp);
        vm.prank(attacker);
        vm.expectRevert("price deviation");
        safe.borrow(1 ether);
        oracle.setStale(1_800e8 - 1, block.timestamp);
        vm.prank(attacker);
        vm.expectRevert("price deviation");
        safe.borrow(1 ether);
        oracle.setStale(2_200e8, block.timestamp);
        vm.prank(attacker);
        safe.borrow(1_650 ether);
        assertEq(safe.debt(attacker), 1_650 ether);
    }

    /// @notice The scaling-overflow boundary: a 0-decimal feed whose price
    ///         would overflow when scaled to 18 decimals is rejected.
    function testSafeOracleRejectsScalingOverflow() public {
        _depositSafe();
        // 0 decimals -> scale 1e18; price = int256 max exceeds
        // type(uint256).max / 1e18, so normalizing it would overflow.
        vm.mockCall(address(oracle), abi.encodeCall(LendingFeed.decimals, ()), abi.encode(uint8(0)));
        oracle.setStale(uint256(type(int256).max), block.timestamp);

        vm.prank(attacker);
        vm.expectRevert("price overflow");
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 0, "no debt should accrue");
    }

    /// @notice The exact minimum price is accepted: MIN_PRICE (1e14) at
    ///         18 decimals is "at or above" the minimum, and borrowing
    ///         against it records positive debt.
    function testSafeOracleAcceptsExactMinimumPrice() public {
        _depositSafe();
        oracle.setStale(safe.MIN_PRICE(), block.timestamp);

        vm.prank(attacker);
        safe.borrow(1e13);
        assertGt(safe.debt(attacker), 0, "exact minimum price must record positive debt");
        assertEq(safe.debt(attacker), 1e13, "borrowed amount must be recorded");
    }

    function testSafeOracleStalenessBoundary() public {
        _depositSafe();
        uint256 updated = block.timestamp;
        vm.warp(updated + safe.MAX_STALENESS() - 1);
        vm.prank(attacker);
        safe.borrow(1 ether);
        vm.warp(updated + safe.MAX_STALENESS());
        vm.prank(attacker);
        vm.expectRevert("stale oracle");
        safe.borrow(1 ether);
        assertEq(safe.debt(attacker), 1 ether);
    }
}
