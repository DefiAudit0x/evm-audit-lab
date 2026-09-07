// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableMint} from "../src/VulnerableMint.sol";
import {SafeMint} from "../src/SafeMint.sol";

/// @title PrivilegedMint.t.sol
/// @notice Lab 09 — Exploit + regression tests for unprotected minting.
///
/// Lab: Privileged mint with missing access control
///
/// Threat model:
///   The token is fully backed 1:1 by ETH held in the contract. Minting is
///   the only way tokens come into existence, so the mint entry point IS
///   the value gate. If that gate is open, the backing reserve is free to
///   take for anyone.
///
/// Violated invariant:
///   "Only privileged addresses can create supply."
///   The vulnerable contract stores `admin` but never checks it on `mint`,
///   so the declared authorization is decorative.
///
/// Reproduction:
///   1. The contract holds a 5 ETH reserve backing 0 supply.
///   2. The attacker calls `mint(attacker, 5e18)` — no access check.
///   3. The attacker redeems 5 tokens for the entire 5 ETH reserve.
///
/// Remediation (see SafeMint):
///   An explicit minter role granted only by the admin, enforced with a
///   custom error on every mint, plus a hard `maxSupply` cap that bounds
///   the damage even a legitimate-but-compromised minter can cause.
///
/// Regression tests:
///   Unauthorized minting reverts, only the admin can grant the role, the
///   cap is enforced, and the honest mint -> redeem flow still works.
contract PrivilegedMintTest is Test {
    VulnerableMint internal vulnerable;
    SafeMint internal safe;

    uint256 internal constant RESERVE = 5 ether;
    uint256 internal constant CAP = 1_000_000 ether;

    address internal attacker;
    address internal teamMinter;
    address internal admin;

    function setUp() public {
        attacker = makeAddr("attacker");
        teamMinter = makeAddr("teamMinter");
        admin = makeAddr("admin");

        // Deal more than the reserve: the deployer pays RESERVE *plus gas*.
        vm.deal(admin, RESERVE * 2);
        vm.prank(admin);
        vulnerable = new VulnerableMint{value: RESERVE}(RESERVE);

        vm.prank(admin);
        safe = new SafeMint{value: RESERVE}(RESERVE, CAP);
        vm.prank(admin);
        safe.setMinter(teamMinter, true);
    }

    function testVulnerableMintAnyoneMintsAndDrainsReserve() public {
        // Step 2: anyone mints redeemable supply for free.
        vm.prank(attacker);
        vulnerable.mint(attacker, RESERVE);
        assertEq(vulnerable.balanceOf(attacker), RESERVE, "attacker minted with no privileges");

        // Step 3: redeem the entire backing reserve.
        vm.prank(attacker);
        vulnerable.redeem(RESERVE);

        assertEq(address(vulnerable).balance, 0, "reserve drained");
        assertEq(attacker.balance, RESERVE, "attacker stole the whole reserve for free");
    }

    function testSafeMintRequiresMinterRole() public {
        vm.expectRevert(SafeMint.NotMinter.selector);
        vm.prank(attacker);
        safe.mint(attacker, 1 ether);

        assertEq(safe.totalSupply(), 0, "no supply can be created without the role");
        assertEq(address(safe).balance, RESERVE, "reserve untouched");
    }

    function testSafeMintOnlyAdminGrantsRole() public {
        // The attacker cannot self-grant the role.
        vm.expectRevert(SafeMint.NotAdmin.selector);
        vm.prank(attacker);
        safe.setMinter(attacker, true);

        // The admin grants the role; then, and only then, minting works.
        vm.prank(admin);
        safe.setMinter(teamMinter, true);
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 ether);

        assertEq(safe.balanceOf(teamMinter), 1 ether, "authorized mint succeeded");
    }

    function testSafeMintEnforcesCap() public {
        vm.prank(teamMinter);
        safe.mint(teamMinter, CAP);
        assertEq(safe.totalSupply(), CAP, "cap-sized mint accepted");

        vm.expectRevert(SafeMint.CapExceeded.selector);
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 wei);
    }

    function testSafeMintRedeemFlowWorks() public {
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 ether);

        uint256 before = teamMinter.balance;
        vm.prank(teamMinter);
        safe.redeem(1 ether);

        assertEq(teamMinter.balance, before + 1 ether, "redeem pays 1:1");
        assertEq(address(safe).balance, RESERVE - 1 ether, "reserve reduced exactly by the redemption");
    }
}
