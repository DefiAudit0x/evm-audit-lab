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

contract RescueEthTest is Test {
    SafeLending lending;
    SafeProxy proxy;
    address user = makeAddr("user");
    address payable recipient = payable(makeAddr("recipient"));

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
}
