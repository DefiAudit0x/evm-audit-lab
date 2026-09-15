// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableFotVault} from "../src/VulnerableFotVault.sol";
import {SafeFotVault} from "../src/SafeFotVault.sol";

/// @title FeeOnTransfer.t.sol
/// @notice Lab 13 — Exploit + regression tests for fee-on-transfer
///         accounting breaks.
///
/// Lab: Claims minted from the requested amount, not the received amount
///
/// Threat model:
///   The vault credits `balances[msg.sender] += amount` where `amount` is
///   what the depositor *instructed*, while a 10% fee-on-transfer token
///   delivers only 90%. Every deposit mints 10% more claims than backing.
///   The shortfall is socialized: whoever withdraws first is paid in full,
///   and the last depositors find the vault short.
///
/// Violated invariant:
///   "Credited claims must equal value actually received by the vault."
///
/// Reproduction (10% fee token, two depositors of 100 each):
///   1. Alice deposits 100 -> credited 100, vault received 90.
///   2. Bob deposits 100   -> credited 100, vault received 90 (real: 180).
///   3. Alice withdraws 100 -> paid in full (vault real balance 80).
///   4. Bob withdraws 100   -> reverts: only 80 tokens remain for 100 claims.
///   Bob's 90 real tokens became 80 frozen tokens; Alice captured 10.
///
/// Remediation (see SafeFotVault):
///   Balance-delta accounting credits the observed balance change, so claims
///   never exceed received value regardless of token behavior.
///
/// Regression tests:
///   Both depositors on SafeFotVault are credited 90 each and both withdraw
///   in full; the vault ends at exactly zero and never goes short.
contract FeeOnTransferTest is Test {
    address internal alice;
    address internal bob;

    uint256 internal constant DEPOSIT = 100e18;
    uint256 internal constant FEE_BPS = 1_000; // 10%

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
    }

    function testVulnerableVaultSocializesTheShortfall() public {
        FeeToken token = new FeeToken(FEE_BPS);
        VulnerableFotVault vault = new VulnerableFotVault(address(token));
        deal(address(token), alice, DEPOSIT);
        deal(address(token), bob, DEPOSIT);

        vm.startPrank(alice);
        token.approve(address(vault), DEPOSIT);
        vault.deposit(DEPOSIT);
        vm.stopPrank();

        vm.startPrank(bob);
        token.approve(address(vault), DEPOSIT);
        vault.deposit(DEPOSIT);
        vm.stopPrank();

        // Claims exceed real backing by two fees.
        assertEq(vault.balances(alice), DEPOSIT, "alice over-credited");
        assertEq(vault.balances(bob), DEPOSIT, "bob over-credited");
        assertEq(token.balanceOf(address(vault)), 180e18, "real backing is 180");

        // Alice exits whole (the token's own fee applies on the way out too:
        // she instructs 100, receives 90); Bob is left short.
        vm.prank(alice);
        vault.withdraw(DEPOSIT);
        assertEq(token.balanceOf(alice), 90e18, "alice paid in full, minus the token fee");

        vm.prank(bob);
        vm.expectRevert();
        vault.withdraw(DEPOSIT); // only 80e18 back 100e18 of claims

        assertEq(token.balanceOf(address(vault)), 80e18, "bob's backing leaked to alice");
    }

    function testSafeVaultCreditsOnlyWhatArrived() public {
        FeeToken token = new FeeToken(FEE_BPS);
        SafeFotVault vault = new SafeFotVault(address(token));
        deal(address(token), alice, DEPOSIT);
        deal(address(token), bob, DEPOSIT);

        vm.startPrank(alice);
        token.approve(address(vault), DEPOSIT);
        vault.deposit(DEPOSIT);
        vm.stopPrank();

        vm.startPrank(bob);
        token.approve(address(vault), DEPOSIT);
        vault.deposit(DEPOSIT);
        vm.stopPrank();

        // Credits match received value exactly.
        assertEq(vault.balances(alice), 90e18);
        assertEq(vault.balances(bob), 90e18);
        assertEq(token.balanceOf(address(vault)), 180e18);

        // Both withdraw in full; the vault ends solvent at zero. Each
        // withdrawal pays the token's own 10% fee on the way out (81 = 90 - 9).
        vm.prank(alice);
        vault.withdraw(90e18);
        vm.prank(bob);
        vault.withdraw(90e18);

        assertEq(token.balanceOf(alice), 81e18, "alice: credited 90, fee 9 on exit");
        assertEq(token.balanceOf(bob), 81e18, "bob: credited 90, fee 9 on exit");
        assertEq(token.balanceOf(address(vault)), 0, "vault solvent at zero");
    }
}

contract FeeToken {
    string public constant name = "Fee Token";
    string public constant symbol = "FEE";
    uint8 public constant decimals = 18;

    uint256 public immutable feeBps;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 feeBps_) {
        feeBps = feeBps_;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function _deliver(address from, address to, uint256 amount) internal {
        uint256 fee = (amount * feeBps) / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _deliver(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        _deliver(from, to, amount);
        return true;
    }
}
