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

    /// @notice Regression (m-14): the drain leaves honest holders behind.
    ///         The honest holder mints first; the attacker then mints and
    ///         redeems the full reserve while the honest balance remains
    ///         outstanding — and unbacked.
    function testVulnerableMintLeavesHonestHoldersUnbacked() public {
        address honest = makeAddr("honest");

        // Initial honest issuance: 2 tokens backed by the 5 ETH reserve.
        vm.prank(honest);
        vulnerable.mint(honest, 2 ether);
        assertEq(vulnerable.balanceOf(honest), 2 ether, "honest issuance must exist first");

        // Attacker mints and redeems the entire reserve.
        vm.prank(attacker);
        vulnerable.mint(attacker, RESERVE);
        vm.prank(attacker);
        vulnerable.redeem(RESERVE);

        assertEq(address(vulnerable).balance, 0, "reserve drained");
        assertEq(vulnerable.totalSupply(), 2 ether, "honest balance remains outstanding");
        assertEq(vulnerable.balanceOf(honest), 2 ether, "honest holder still holds claims");

        // The honest balance is now unbacked: redemption fails with no ETH
        // left, and the failed redemption leaves the claim outstanding.
        vm.prank(honest);
        vm.expectRevert("transfer failed");
        vulnerable.redeem(2 ether);
        assertEq(vulnerable.balanceOf(honest), 2 ether, "failed redemption keeps the claim");
        assertEq(vulnerable.totalSupply(), 2 ether, "failed redemption keeps the supply");
    }

    /// @notice Regression (m-13): one wei backs each raw supply unit —
    ///         minting and redeeming 1 moves exactly one wei.
    function testSafeMintOneWeiBacksOneSupplyUnit() public {
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1);
        assertEq(safe.balanceOf(teamMinter), 1, "one raw supply unit minted");
        assertEq(safe.totalSupply(), 1, "one unit of supply outstanding");

        uint256 before = teamMinter.balance;
        vm.prank(teamMinter);
        safe.redeem(1);

        assertEq(teamMinter.balance, before + 1, "redeeming 1 unit pays exactly one wei");
        assertEq(safe.totalSupply(), 0, "supply returns to zero");
        assertEq(address(safe).balance, RESERVE - 1, "reserve reduced by exactly one wei");
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

        // A fresh, initially unauthorized recipient cannot mint until the
        // admin grants the role — this is not the setUp grant repeated.
        address freshRecipient = makeAddr("freshRecipient");
        assertFalse(safe.isMinter(freshRecipient), "fresh recipient starts unauthorized");
        vm.expectRevert(SafeMint.NotMinter.selector);
        vm.prank(freshRecipient);
        safe.mint(freshRecipient, 1 ether);

        vm.prank(admin);
        safe.setMinter(freshRecipient, true);
        vm.prank(freshRecipient);
        safe.mint(freshRecipient, 1 ether);
        assertEq(safe.balanceOf(freshRecipient), 1 ether, "fresh grant enables minting");

        // Revoking the role takes the privilege away again.
        vm.prank(admin);
        safe.setMinter(teamMinter, false);
        assertFalse(safe.isMinter(teamMinter), "revoked minter loses the role");
        vm.expectRevert(SafeMint.NotMinter.selector);
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 ether);
        assertEq(safe.balanceOf(teamMinter), 1 ether, "revoked minter mints nothing more");
    }

    function testSafeMintEnforcesCap() public {
        // Fund the cap-sized issuance so this isolates the lifetime cap.
        vm.deal(address(safe), CAP);
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

    function testSafeMintReentrantRecipientCannotDoubleRedeem() public {
        ReentrantRedeemer redeemer = new ReentrantRedeemer(safe);
        vm.prank(teamMinter);
        safe.mint(address(redeemer), 1 ether);

        redeemer.redeem(1 ether);

        // The nested redeem inside the receive hook failed: state was
        // already deducted before the ETH left, so the second attempt
        // found no balance.
        assertTrue(redeemer.nestedAttempted(), "nested redeem must have been attempted");
        assertFalse(redeemer.nestedSucceeded(), "nested redeem must fail");
        assertEq(address(redeemer).balance, 1 ether, "exactly one payout");
        assertEq(safe.balanceOf(address(redeemer)), 0, "redeemer balance fully deducted");
        assertEq(safe.totalSupply(), 0, "supply reduced by the single redemption");
        assertEq(safe.totalMinted(), 1 ether, "lifetime issuance is not recycled by redeeming");
        assertEq(address(safe).balance, RESERVE - 1 ether, "backing reduced exactly by the redemption");
        assertGe(address(safe).balance, safe.totalSupply(), "backing remains sufficient");
    }

    function testSafeMintRejectingRecipientRollsBackRedemption() public {
        RejectingRedeemer rejecter = new RejectingRedeemer(safe);
        vm.prank(teamMinter);
        safe.mint(address(rejecter), 1 ether);

        uint256 supplyBefore = safe.totalSupply();
        uint256 mintedBefore = safe.totalMinted();

        vm.expectRevert(bytes("transfer failed"));
        rejecter.redeem(1 ether);

        // The failed transfer reverts the whole redemption: balances,
        // supply, and lifetime issuance are exactly as before.
        assertEq(safe.balanceOf(address(rejecter)), 1 ether, "redeemer balance rolled back");
        assertEq(safe.totalSupply(), supplyBefore, "supply rolled back");
        assertEq(safe.totalMinted(), mintedBefore, "lifetime issuance rolled back");
        assertEq(address(safe).balance, RESERVE, "reserve untouched");
        assertEq(address(rejecter).balance, 0, "rejecting recipient received nothing");
    }

    function testSafeMintRejectsUnbackedSupply() public {
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 ether);
        vm.prank(teamMinter);
        vm.expectRevert(SafeMint.InsufficientBacking.selector);
        safe.mint(attacker, RESERVE);
        assertEq(safe.totalSupply(), 1 ether);
        assertEq(safe.totalMinted(), 1 ether);
        assertEq(safe.balanceOf(attacker), 0);
        assertEq(address(safe).balance, RESERVE);
        vm.prank(teamMinter);
        safe.mint(teamMinter, RESERVE - 1 ether);
        vm.prank(teamMinter);
        safe.redeem(RESERVE);
        assertEq(safe.totalSupply(), 0);
        assertEq(safe.totalMinted(), RESERVE);
        assertEq(address(safe).balance, 0);
    }

    function testSafeMintCannotRecycleLifetimeCap() public {
        vm.deal(address(this), 10 ether);
        SafeMint capped = new SafeMint{value: 10 ether}(10 ether, 5 ether);
        capped.setMinter(teamMinter, true);
        vm.prank(teamMinter);
        capped.mint(teamMinter, 5 ether);
        vm.prank(teamMinter);
        capped.redeem(5 ether);
        vm.prank(teamMinter);
        vm.expectRevert(SafeMint.CapExceeded.selector);
        capped.mint(teamMinter, 1);
        assertEq(capped.totalSupply(), 0);
        assertEq(capped.totalMinted(), 5 ether);
        assertEq(capped.balanceOf(teamMinter), 0);
        assertEq(address(capped).balance, 5 ether);
    }

    function testSafeMintRejectsZeroRecipient() public {
        vm.prank(teamMinter);
        vm.expectRevert(SafeMint.InvalidRecipient.selector);
        safe.mint(address(0), 1 ether);
        assertEq(safe.totalSupply(), 0);
        assertEq(safe.totalMinted(), 0);
        assertEq(safe.balanceOf(address(0)), 0);
    }

    function testSafeMintOverflowingAmountUsesCapError() public {
        vm.prank(teamMinter);
        safe.mint(teamMinter, 1 ether);
        vm.prank(teamMinter);
        vm.expectRevert(SafeMint.CapExceeded.selector);
        safe.mint(teamMinter, type(uint256).max);
        assertEq(safe.totalSupply(), 1 ether);
        assertEq(safe.totalMinted(), 1 ether);
        assertEq(safe.balanceOf(teamMinter), 1 ether);
    }
}

/// @dev Recipient that tries to redeem again from inside its receive hook,
///      while the outer redemption is still in flight. It attempts the
///      nested redeem only once: repeated attempts would recurse until the
///      vault is empty and mask the single-reentry effect this test pins down.
contract ReentrantRedeemer {
    SafeMint internal immutable vault;
    bool public nestedAttempted;
    bool public nestedSucceeded;
    bool private nestedDone;

    constructor(SafeMint vault_) {
        vault = vault_;
    }

    function redeem(uint256 amount) external {
        vault.redeem(amount);
    }

    receive() external payable {
        if (nestedDone) return;
        nestedDone = true;
        nestedAttempted = true;
        (nestedSucceeded,) = address(vault).call(abi.encodeCall(SafeMint.redeem, (1 ether)));
    }
}

/// @dev Recipient that refuses every ETH transfer.
contract RejectingRedeemer {
    SafeMint internal immutable vault;

    constructor(SafeMint vault_) {
        vault = vault_;
    }

    function redeem(uint256 amount) external {
        vault.redeem(amount);
    }

    receive() external payable {
        revert("payment refused");
    }
}
