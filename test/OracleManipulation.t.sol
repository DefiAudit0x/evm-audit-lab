// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableLending, FakeOracle} from "../src/VulnerableLending.sol";
import {SafeLending} from "../src/SafeLending.sol";

/// @title StaleOracle.t.sol
/// @notice Lab 04 — Exploit + regression test for stale oracle data.
///
/// Lab: Stale Oracle Data
///
/// Threat model:
///   The Chainlink (or other) oracle stops updating — L2 sequencer
///   outage, oracle node compromise, or Chainlink multisig pause.
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
///   4. Attacker deposits 0.25 ETH, but the protocol credits them
///      with $500 of collateral value at the stale $2,000 price.
///      Wait — at the stale price, 0.25 ETH = $500, so the attacker
///      can borrow $375 (75% LTV). If the real price is $500, then
///      the attacker's collateral is only worth $125 — they walk
///      away with a $250 profit.
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

        // At 75% LTV, attacker can borrow $1,500 worth.
        // Real market price = $500, so collateral is really worth $500.
        // Attacker borrows $1,500, walks away with $1,000 profit.
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
}
