// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeRouter} from "../src/SafeRouter.sol";
import {SafeLending} from "../src/SafeLending.sol";
import {SafeSplitter} from "../src/SafeSplitter.sol";
import {SafeSwap} from "../src/SafeSwap.sol";
import {FakeOracle} from "../src/shared/FakeOracle.sol";
import {PropertyToken, RejectingPayee} from "./fixtures/root-only/PropertyFixtures.sol";

contract DefensiveFuzzTest is Test {
    function testFuzz_twapWeightsElapsedTime(uint96 rawA, uint96 rawB, uint96 rawInput, uint32 rawElapsed) public {
        uint256 reserveA = bound(rawA, 1 ether, 100 ether);
        uint256 reserveB = bound(rawB, 1 ether, 100 ether);
        uint256 input = bound(rawInput, 1 ether, 100 ether);
        SafeSwap swap = new SafeSwap(reserveA, reserveB);
        uint256 period = swap.PERIOD();
        uint256 firstPrice = reserveB * 1e18 / reserveA;
        vm.warp(block.timestamp + period);
        swap.swap(input);
        assertEq(swap.getTWAP(), firstPrice);

        uint256 elapsed = bound(rawElapsed, 1, period - 1);
        uint256 remainingB = reserveB - reserveB * input / (reserveA + input);
        uint256 secondPrice = remainingB * 1e18 / (reserveA + input);
        vm.warp(block.timestamp + elapsed);
        assertEq(swap.getTWAP(), (firstPrice * period + secondPrice * elapsed) / (period + elapsed));
    }

    function testFuzz_lendingRoundsAndAccountsForDebt(uint96 rawCollateral, uint96 rawPrice, uint96 rawFirst) public {
        vm.warp(1 days);
        uint256 amount = bound(rawCollateral, 1, 100 ether);
        uint256 price = bound(rawPrice, 1e14, 100e18);
        SafeLending lending = new SafeLending(address(new FakeOracle(price)));
        address borrower = address(0xB0B);
        vm.deal(borrower, amount);
        vm.startPrank(borrower);
        lending.deposit{value: amount}(amount);

        uint256 collateralValue = amount * price / 1e18;
        uint256 credit = collateralValue * 3 / 4;
        uint256 first = bound(rawFirst, 0, credit);
        lending.borrow(first);
        assertEq(lending.debt(borrower), first);
        lending.borrow(credit - first);
        assertEq(lending.debt(borrower), credit);
        vm.expectRevert(bytes("exceeds LTV"));
        lending.borrow(1);
        assertEq(lending.debt(borrower), credit);
        vm.stopPrank();
    }

    function testFuzz_splitterIsolatesRejectedPayout(
        uint96 rawRejected,
        uint96 rawAccepted,
        uint256 rawBatch,
        bool rejectingFirst
    ) public {
        SafeSplitter splitter = new SafeSplitter();
        RejectingPayee rejector = new RejectingPayee();
        address payable recipient = payable(address(0xB0B));
        uint256 rejected = bound(rawRejected, 1, 100 ether);
        uint256 accepted = bound(rawAccepted, 1, 100 ether);
        vm.deal(address(this), rejected);
        vm.deal(recipient, accepted);
        if (rejectingFirst) rejector.register{value: rejected}(splitter);
        vm.prank(recipient);
        splitter.register{value: accepted}();
        if (!rejectingFirst) rejector.register{value: rejected}(splitter);

        uint256 batch = bound(rawBatch, 1, splitter.MAX_BATCH());
        if (!splitter.distribute(batch)) assertTrue(splitter.distribute(batch));
        assertEq(splitter.totalPending(), 0);
        assertEq(splitter.totalOwed(), rejected + accepted);

        vm.expectRevert(bytes("transfer failed"));
        rejector.claim(splitter);
        assertEq(splitter.owed(address(rejector)), rejected);
        assertEq(splitter.totalOwed(), rejected + accepted);
        assertEq(address(splitter).balance, rejected + accepted);

        vm.prank(recipient);
        splitter.claim();
        assertEq(recipient.balance, accepted);
        assertEq(splitter.totalOwed(), rejected);

        rejector.redirect(splitter, recipient);
        assertEq(recipient.balance, accepted + rejected);
        assertEq(splitter.totalOwed(), 0);
        assertEq(address(splitter).balance, 0);
    }

    // Splitter itself pays ETH. Exercise the token failure fixture on Router.
    function testFuzz_tokenPayoutCanRetryAfterFailure(uint96 rawAmount) public {
        uint256 amount = bound(rawAmount, 1, 100 ether);
        address recipient = address(0xB0B);
        PropertyToken token = new PropertyToken();
        SafeRouter router = new SafeRouter(address(token));
        token.mint(address(router), amount);
        router.setClaimable(recipient, amount);

        token.setRejectTransfer(true);
        vm.prank(recipient);
        vm.expectRevert(SafeRouter.TransferFailed.selector);
        router.claim();
        assertEq(router.claimable(recipient), amount);

        token.setRejectTransfer(false);
        vm.prank(recipient);
        router.claim();
        assertEq(token.balanceOf(recipient), amount);
        assertEq(router.totalClaimable(), 0);
        assertEq(router.claimed(recipient), amount);
    }
}
