// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableRouter} from "../src/VulnerableRouter.sol";
import {SafeRouter} from "../src/SafeRouter.sol";

/// @title UncheckedReturn.t.sol
/// @notice Lab 10 — Exploit + regression tests for unchecked return values.
///
/// Lab: Unchecked return value of a low-level / token call
///
/// Threat model:
///   A claims router forwards `token.transfer` payouts. Not every token
///   follows the revert-on-failure convention: tokens like USDT return
///   `false` instead of reverting. Any code path that ignores the returned
///   `bool` treats a failed payment as a successful one.
///
/// Violated invariant:
///   "State only records value that actually moved."
///   The vulnerable router marks the claim as paid and deletes the
///   entitlement even when `transfer` returned false — the user's
///   allocation is destroyed and the tokens remain stuck in the router.
///
/// Reproduction:
///   1. A user holds a 100e18 allocation against a token whose `transfer`
///      returns false (paused / blacklisted).
///   2. `claim()` does not revert: the ignored bool hides the failure.
///   3. `claimed[user] == 100e18`, `claimable[user] == 0`, but the user's
///      token balance is still 0 — the entitlement is gone forever.
///
/// Remediation (see SafeRouter):
///   Check the boolean and `revert TransferFailed()` before any state
///   change. A reverted claim is fully retryable once the token recovers.
///
/// Regression tests:
///   The failing token reverts the claim on SafeRouter with state intact;
///   the honest token still pays; and the vulnerable router passes with an
///   honest token — which is exactly why the bug ships unnoticed.
contract UncheckedReturnTest is Test {
    /// @dev USDT-style token: transfer() reports failure by returning
    ///      false, without reverting.
    BadToken internal bad;
    /// @dev OZ-style token: transfer() reverts on failure and returns true.
    GoodToken internal good;

    VulnerableRouter internal vulnerable;
    SafeRouter internal safe;

    uint256 internal constant ALLOCATION = 100 ether;

    address internal claimant;

    function setUp() public {
        bad = new BadToken();
        good = new GoodToken();
        claimant = makeAddr("claimant");

        vulnerable = new VulnerableRouter(address(bad));
        safe = new SafeRouter(address(good));

        bad.mint(address(vulnerable), ALLOCATION);
        good.mint(address(safe), ALLOCATION);
    }

    function testVulnerableRouterSilentFailureDestroysEntitlement() public {
        vulnerable.setClaimable(claimant, ALLOCATION);

        // No revert: the ignored false return hides the failed payment.
        vm.prank(claimant);
        vulnerable.claim();

        // Accounting says "paid"...
        assertEq(vulnerable.claimed(claimant), ALLOCATION, "router recorded the claim");
        assertEq(vulnerable.claimable(claimant), 0, "entitlement erased");

        // ...but reality says otherwise.
        assertEq(bad.balanceOf(claimant), 0, "user never received tokens");
        assertEq(bad.balanceOf(address(vulnerable)), ALLOCATION, "tokens stuck in the router");
    }

    function testSafeRouterRevertsOnFailedTransfer() public {
        // Same scenario against the remediated router: point it at the
        // failing token by deploying one with the same setup.
        SafeRouter failingSafe = new SafeRouter(address(bad));
        bad.mint(address(failingSafe), ALLOCATION);
        failingSafe.setClaimable(claimant, ALLOCATION);

        vm.expectRevert(SafeRouter.TransferFailed.selector);
        vm.prank(claimant);
        failingSafe.claim();

        // State untouched — the claim is fully retryable.
        assertEq(failingSafe.claimable(claimant), ALLOCATION, "entitlement preserved");
        assertEq(failingSafe.claimed(claimant), 0, "no phantom claim recorded");
    }

    function testSafeRouterHappyPathPaysOut() public {
        safe.setClaimable(claimant, ALLOCATION);

        vm.prank(claimant);
        safe.claim();

        assertEq(good.balanceOf(claimant), ALLOCATION, "tokens received");
        assertEq(safe.claimed(claimant), ALLOCATION, "claim recorded");
        assertEq(safe.claimable(claimant), 0, "allocation consumed");
    }

    function testVulnerableRouterWorksWhenTokenIsHonest() public {
        // The bug is latent: with an honest token the vulnerable router
        // behaves identically to the safe one — which is why it ships.
        VulnerableRouter honestRouter = new VulnerableRouter(address(good));
        good.mint(address(honestRouter), ALLOCATION);
        honestRouter.setClaimable(claimant, ALLOCATION);

        vm.prank(claimant);
        honestRouter.claim();

        assertEq(good.balanceOf(claimant), ALLOCATION, "honest token pays out fine");
    }
}

/// @dev Minimal token whose transfer returns false (paused), USDT-style.
contract BadToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false; // contract "paused" forever
    }
}

/// @dev Minimal token whose transfer reverts on failure and returns true,
///      OpenZeppelin-style.
contract GoodToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
