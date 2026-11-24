// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeLending, ConfiguredSafeLending} from "../src/SafeLending.sol";
import {SafeProxy, SafeImplV1} from "../src/SafeProxy.sol";

contract RescueMockFeed {
    function decimals() external pure returns (uint8) {
        return 18;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, 2_000 ether, block.timestamp, block.timestamp, 1);
    }
}

contract RejectingRescueRecipient {
    receive() external payable {
        revert("reject");
    }
}

contract RescueEthTest is Test {
    SafeLending lending;
    SafeProxy proxy;
    address user = makeAddr("user");
    address payable recipient = payable(makeAddr("recipient"));

    // Nested-rescue callback state: when set, the test contract's receive()
    // re-enters rescueETH on `lending` as the owner (the test contract).
    bool internal _reenterRescue;
    uint256 internal _reenterAmount;

    receive() external payable {
        if (_reenterRescue) {
            _reenterRescue = false;
            lending.rescueETH(payable(address(this)), _reenterAmount);
        }
    }

    function setUp() public {
        lending = new SafeLending(address(new RescueMockFeed()));
        proxy = new SafeProxy(address(new SafeImplV1()));
        vm.deal(address(this), 10 ether);
        vm.deal(user, 1 ether);
    }

    function _send(address payable to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount}("");
        assertTrue(ok);
    }

    function _deposit() internal {
        vm.prank(user);
        lending.deposit{value: 1 ether}(1 ether);
    }

    function testLendingOwnerRescuesStrayEthPreservingCollateral() public {
        _deposit();
        _send(payable(address(lending)), 0.5 ether);
        assertEq(lending.owner(), address(this));
        lending.rescueETH(recipient, 0.5 ether);
        assertEq(recipient.balance, 0.5 ether);
        assertEq(address(lending).balance, 1 ether);
        assertEq(lending.collateral(user), 1 ether);
        assertEq(lending.totalCollateral(), 1 ether);
    }

    function testLendingRescueCannotTakeCollateral() public {
        _deposit();
        _send(payable(address(lending)), 0.5 ether);
        vm.expectRevert("exceeds recoverable");
        lending.rescueETH(recipient, 0.6 ether);
        lending.rescueETH(recipient, 0.5 ether);
        assertEq(address(lending).balance, 1 ether);
        assertEq(lending.collateral(user), 1 ether);
        assertEq(lending.totalCollateral(), 1 ether);
    }

    function testLendingRescueRejectsNonOwner() public {
        _send(payable(address(lending)), 1 ether);
        vm.prank(user);
        vm.expectRevert("not owner");
        lending.rescueETH(recipient, 1 ether);
    }

    function testLendingRescueRejectsZeroAddress() public {
        vm.expectRevert("zero address");
        lending.rescueETH(payable(address(0)), 0);
    }

    function testConfiguredLendingInheritsRescue() public {
        ConfiguredSafeLending configured =
            new ConfiguredSafeLending(address(new RescueMockFeed()), address(0), address(0));
        _send(payable(address(configured)), 1 ether);
        configured.rescueETH(recipient, 1 ether);
        assertEq(recipient.balance, 1 ether);
        assertEq(address(configured).balance, 0);
        assertEq(configured.owner(), address(this));
        assertEq(configured.totalCollateral(), 0);
    }

    function testProxyAdminRescuesEth() public {
        _send(payable(address(proxy)), 1 ether);
        uint256 beforeBalance = recipient.balance;
        proxy.rescueETH(recipient, 1 ether);
        assertEq(recipient.balance, beforeBalance + 1 ether);
        assertEq(address(proxy).balance, 0);
    }

    function testProxyRescueRejectsNonAdmin() public {
        _send(payable(address(proxy)), 1 ether);
        vm.prank(user);
        vm.expectRevert("not admin");
        proxy.rescueETH(recipient, 1 ether);
    }

    function testProxyRescueRejectsExcessAndZeroAddress() public {
        _send(payable(address(proxy)), 1 ether);
        vm.expectRevert("insufficient balance");
        proxy.rescueETH(recipient, 2 ether);
        vm.expectRevert("zero address");
        proxy.rescueETH(payable(address(0)), 1 ether);
        assertEq(address(proxy).balance, 1 ether);
    }

    function testProxyImplementationWorksAfterRescue() public {
        _send(payable(address(proxy)), 1 ether);
        proxy.rescueETH(recipient, 1 ether);
        SafeImplV1(address(proxy)).setValue(42);
        assertEq(SafeImplV1(address(proxy)).value(), 42);
        assertEq(proxy.admin(), address(this));
    }

    /// @notice A failed transfer rolls everything back: the rescue reverts
    ///         with "transfer failed" and balances, collateral, and the
    ///         recoverable surplus are intact — on both the lending vault
    ///         and the proxy — and the surplus stays recoverable afterwards.
    function testRescueRejectsFailedTransferAndPreservesState() public {
        _deposit();
        _send(payable(address(lending)), 0.5 ether);
        _send(payable(address(proxy)), 1 ether);
        RejectingRescueRecipient rejector = new RejectingRescueRecipient();

        vm.expectRevert("transfer failed");
        lending.rescueETH(payable(address(rejector)), 0.5 ether);
        assertEq(address(lending).balance, 1.5 ether, "failed lending rescue must leave balances intact");
        assertEq(lending.collateral(user), 1 ether, "collateral must be untouched");
        assertEq(lending.totalCollateral(), 1 ether, "total collateral must be untouched");

        vm.expectRevert("transfer failed");
        proxy.rescueETH(payable(address(rejector)), 1 ether);
        assertEq(address(proxy).balance, 1 ether, "failed proxy rescue must leave balances intact");

        // The surplus is still recoverable to a good recipient afterwards.
        lending.rescueETH(recipient, 0.5 ether);
        assertEq(recipient.balance, 0.5 ether, "surplus must stay recoverable");
        assertEq(address(lending).balance, 1 ether, "only collateral must remain");
        proxy.rescueETH(recipient, 1 ether);
        assertEq(recipient.balance, 1.5 ether, "proxy funds must stay recoverable");
        assertEq(address(proxy).balance, 0, "proxy must be empty after recovery");
    }

    /// @notice Nested owner callbacks: a rescue paid to the owner re-enters
    ///         rescueETH during the callback. Each rescue recomputes the
    ///         live surplus, so the nested rescue can take the remainder —
    ///         but never more: a nested attempt above the remaining surplus
    ///         reverts and rolls the whole outer rescue back.
    function testLendingNestedOwnerCallbackCannotOverDrain() public {
        _deposit();
        _send(payable(address(lending)), 0.5 ether);
        uint256 ownerBalanceBefore = address(this).balance;

        // Nested rescue of the remainder: 0.25 outer + 0.25 nested = the
        // full 0.5 surplus, collateral untouched.
        _reenterRescue = true;
        _reenterAmount = 0.25 ether;
        lending.rescueETH(payable(address(this)), 0.25 ether);
        assertEq(address(this).balance, ownerBalanceBefore + 0.5 ether, "nested rescue must pay the remainder");
        assertEq(address(lending).balance, 1 ether, "only collateral must remain");
        assertEq(lending.collateral(user), 1 ether, "collateral must be untouched");
        assertEq(lending.totalCollateral(), 1 ether, "total collateral must be untouched");

        // A further rescue now exceeds the (exhausted) surplus.
        vm.expectRevert("exceeds recoverable");
        lending.rescueETH(recipient, 1);

        // Nested over-drain attempt: fresh 0.5 surplus, outer rescue of
        // 0.25 whose callback tries to rescue 0.5 more (only 0.25 left).
        // The nested call reverts, the outer transfer fails, and the whole
        // rescue rolls back — no ETH moves at all.
        _send(payable(address(lending)), 0.5 ether);
        assertEq(address(lending).balance, 1.5 ether, "fresh surplus must be in place");
        ownerBalanceBefore = address(this).balance;
        _reenterRescue = true;
        _reenterAmount = 0.5 ether;
        vm.expectRevert("transfer failed");
        lending.rescueETH(payable(address(this)), 0.25 ether);
        assertEq(address(this).balance, ownerBalanceBefore, "failed nested rescue must pay nothing");
        assertEq(address(lending).balance, 1.5 ether, "failed nested rescue must leave balances intact");
        assertEq(lending.collateral(user), 1 ether, "collateral must be untouched");
        assertEq(lending.totalCollateral(), 1 ether, "total collateral must be untouched");
    }
}
