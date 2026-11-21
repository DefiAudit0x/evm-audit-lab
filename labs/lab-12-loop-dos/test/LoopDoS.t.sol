// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSplitter} from "../src/VulnerableSplitter.sol";
import {SafeSplitter} from "../src/SafeSplitter.sol";

contract RejectingSplitterPayee {
    function register(SafeSplitter splitter) external payable {
        splitter.register{value: msg.value}();
    }

    function claim(SafeSplitter splitter) external {
        splitter.claim();
    }

    function withdrawTo(SafeSplitter splitter, address payable recipient) external {
        splitter.withdrawTo(recipient);
    }

    receive() external payable {
        revert("reject");
    }
}

contract GasGuzzlingSplitterPayee {
    function register(SafeSplitter splitter) external payable {
        splitter.register{value: msg.value}();
    }

    function claim(SafeSplitter splitter) external {
        splitter.claim();
    }

    function withdrawTo(SafeSplitter splitter, address payable recipient) external {
        splitter.withdrawTo(recipient);
    }

    receive() external payable {
        assembly {
            for {} 1 {} {}
        }
    }
}

/// @title LoopDoS.t.sol
/// @notice Lab 12 — Exploit + regression tests for unbounded-loop DoS.
contract LoopDoSTest is Test {
    uint256 internal constant GAS_BUDGET = 30_000_000;
    uint256 internal constant ATTACK_PAYEES = 3_000;
    uint256 internal constant HONEST_BALANCE = 1 ether;

    address internal honest;

    function setUp() public {
        honest = makeAddr("honest");
    }

    function _seedPayee(VulnerableSplitter splitter, address p, uint256 value) internal {
        vm.deal(p, value);
        vm.prank(p);
        splitter.register{value: value}();
    }

    function _bloat(VulnerableSplitter splitter) internal {
        for (uint256 i = 1; i <= ATTACK_PAYEES; ++i) {
            _seedPayee(splitter, address(uint160(uint256(keccak256(abi.encode("payee", i))))), 1);
        }
        _seedPayee(splitter, honest, HONEST_BALANCE);
    }

    function testVulnerableDistributeBricksPastGasLimit() public {
        VulnerableSplitter splitter = new VulnerableSplitter();
        _bloat(splitter);

        assertEq(splitter.payeeCount(), ATTACK_PAYEES + 1);

        vm.expectRevert();
        splitter.distribute{gas: GAS_BUDGET}();

        assertEq(splitter.owed(honest), HONEST_BALANCE);
    }

    function testSafeSplitterCreditsLargeListThroughBoundedBatches() public {
        SafeSplitter splitter = new SafeSplitter();
        for (uint256 i = 1; i <= ATTACK_PAYEES; ++i) {
            address p = address(uint160(uint256(keccak256(abi.encode("payee", i)))));
            vm.deal(p, 1);
            vm.prank(p);
            splitter.register{value: 1}();
        }

        vm.deal(honest, HONEST_BALANCE);
        vm.prank(honest);
        splitter.register{value: HONEST_BALANCE}();

        bool done;
        while (!done) {
            done = splitter.distribute(256);
        }

        assertEq(splitter.pending(honest), 0);
        assertEq(splitter.owed(honest), HONEST_BALANCE);
        assertEq(splitter.totalPending(), 0);
        assertEq(splitter.totalOwed(), ATTACK_PAYEES + HONEST_BALANCE);
        assertEq(honest.balance, 0);

        vm.prank(honest);
        splitter.claim();

        assertEq(honest.balance, HONEST_BALANCE, "honest payee must be paid");
        assertEq(splitter.owed(honest), 0);
        assertEq(splitter.totalOwed(), ATTACK_PAYEES);
    }

    function testRejectingAndGasGuzzlingPayeesCannotBlockHonestClaim() public {
        SafeSplitter splitter = new SafeSplitter();
        RejectingSplitterPayee rejector = new RejectingSplitterPayee();
        GasGuzzlingSplitterPayee gasGuzzler = new GasGuzzlingSplitterPayee();
        address payable rejectRecovery = payable(makeAddr("reject-recovery"));
        address payable gasRecovery = payable(makeAddr("gas-recovery"));

        rejector.register{value: 1 ether}(splitter);
        gasGuzzler.register{value: 1 ether}(splitter);
        vm.deal(honest, 1 ether);
        vm.prank(honest);
        splitter.register{value: 1 ether}();

        assertTrue(splitter.distribute(256));
        assertEq(splitter.owed(address(rejector)), 1 ether);
        assertEq(splitter.owed(address(gasGuzzler)), 1 ether);
        assertEq(splitter.owed(honest), 1 ether);

        vm.prank(honest);
        splitter.claim();
        assertEq(honest.balance, 1 ether);

        vm.expectRevert("transfer failed");
        rejector.claim(splitter);
        assertEq(splitter.owed(address(rejector)), 1 ether);

        vm.expectRevert("transfer failed");
        gasGuzzler.claim(splitter);
        assertEq(splitter.owed(address(gasGuzzler)), 1 ether);

        rejector.withdrawTo(splitter, rejectRecovery);
        gasGuzzler.withdrawTo(splitter, gasRecovery);
        assertEq(rejectRecovery.balance, 1 ether);
        assertEq(gasRecovery.balance, 1 ether);
        assertEq(splitter.totalOwed(), 0);
    }

    function testRegistrationAndBatchBounds() public {
        SafeSplitter splitter = new SafeSplitter();
        address payee = makeAddr("payee");

        vm.expectRevert("zero amount");
        vm.prank(payee);
        splitter.register();

        vm.deal(payee, 2);
        vm.prank(payee);
        splitter.register{value: 1}();
        assertTrue(splitter.distribute(1));

        vm.prank(payee);
        splitter.claim();

        vm.prank(payee);
        splitter.register{value: 1}();
        assertEq(splitter.payeeCount(), 1, "payee must not be re-registered");

        vm.expectRevert("invalid batch");
        splitter.distribute(0);

        vm.expectRevert("invalid batch");
        splitter.distribute(257);
    }
}
