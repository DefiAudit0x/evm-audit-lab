// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeSignature} from "../src/SafeSignature.sol";
import {SafeRouter} from "../src/SafeRouter.sol";
import {SafeSplitter} from "../src/SafeSplitter.sol";
import {PropertyToken, RejectingPayee} from "./fixtures/root-only/PropertyFixtures.sol";

contract PayoutHandler is Test {
    uint256 private constant SIGNER_KEY = 0x12345;
    bytes32 private constant WITHDRAWAL =
        keccak256("Withdrawal(address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    SafeSignature public immutable payouts;
    SafeRouter public immutable router;
    PropertyToken public immutable token;
    SafeSplitter public immutable splitter;
    RejectingPayee public immutable rejector;

    address[2] public recipients = [address(0xA11CE), address(0xB0B)];
    mapping(address => uint256) public authorizations;
    mapping(address => uint256) public paid;
    bool public rollbackIntact = true;
    bool public claimsConsumed = true;
    uint256 public tokenPaid;

    constructor() {
        payouts = new SafeSignature(vm.addr(SIGNER_KEY));
        vm.deal(address(payouts), 100 ether);
        token = new PropertyToken();
        router = new SafeRouter(address(token));
        token.mint(address(router), 100 ether);
        splitter = new SafeSplitter();
        rejector = new RejectingPayee();
        vm.deal(address(this), 1000 ether);
    }

    function authorize(uint256 actorIndex, uint256 rawAmount) external {
        address recipient = recipients[actorIndex % recipients.length];
        uint256 reserve = address(payouts).balance;
        if (reserve == 0) return;
        uint256 amount = bound(rawAmount, 1, reserve < 1 ether ? reserve : 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 withdrawal = keccak256(abi.encode(WITHDRAWAL, recipient, amount, authorizations[recipient], deadline));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", payouts.domainSeparator(), withdrawal));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        payouts.withdraw(recipient, amount, deadline, v, r, s);
        authorizations[recipient]++;
        paid[recipient] += amount;
    }

    function rejectTokenPayout(uint96 rawAmount) external {
        address recipient = recipients[0];
        uint256 reserve = token.balanceOf(address(router));
        if (reserve == 0) return;
        uint256 amount = bound(rawAmount, 1, reserve);
        router.setClaimable(recipient, amount);
        token.setRejectTransfer(true);
        uint256 priorClaimed = router.claimed(recipient);
        uint256 priorReserve = token.balanceOf(address(router));
        uint256 priorWallet = token.balanceOf(recipient);
        vm.prank(recipient);
        (bool ok, bytes memory reason) = address(router).call(abi.encodeCall(router.claim, ()));
        rollbackIntact = rollbackIntact && !ok
            && keccak256(reason) == keccak256(abi.encodeWithSelector(SafeRouter.TransferFailed.selector))
            && router.claimable(recipient) == amount && router.totalClaimable() == amount
            && router.claimed(recipient) == priorClaimed && token.balanceOf(address(router)) == priorReserve
            && token.balanceOf(recipient) == priorWallet;
        token.setRejectTransfer(false);
    }

    function claimTokenPayout(uint96 rawAmount) external {
        address recipient = recipients[0];
        uint256 reserve = token.balanceOf(address(router));
        if (reserve == 0) return;
        uint256 amount = bound(rawAmount, 1, reserve);
        router.setClaimable(recipient, amount);
        uint256 priorWallet = token.balanceOf(recipient);
        uint256 priorClaimed = router.claimed(recipient);

        vm.prank(recipient);
        router.claim();
        tokenPaid += amount;
        // Check consumption immediately: a duplicate claim might revert merely
        // because totalClaimable underflows even if claimable was not deleted.
        claimsConsumed = claimsConsumed && router.claimable(recipient) == 0 && router.totalClaimable() == 0
            && router.claimed(recipient) == priorClaimed + amount && token.balanceOf(recipient) == priorWallet + amount;

        vm.prank(recipient);
        (bool ok,) = address(router).call(abi.encodeCall(router.claim, ()));
        claimsConsumed = claimsConsumed && !ok && router.claimable(recipient) == 0 && router.totalClaimable() == 0
            && router.claimed(recipient) == priorClaimed + amount && token.balanceOf(recipient) == priorWallet + amount
            && token.balanceOf(address(router)) == reserve - amount;
    }

    function registerPayees(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 1, 0.5 ether);
        rejector.register{value: amount}(splitter);
        address recipient = recipients[1];
        vm.deal(recipient, recipient.balance + amount);
        vm.prank(recipient);
        splitter.register{value: amount}();
    }

    function distribute(uint256 rawLimit) external {
        splitter.distribute(bound(rawLimit, 1, 2));
    }
}

contract PayoutInvariantTest is Test {
    PayoutHandler private handler;

    function setUp() public {
        handler = new PayoutHandler();
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = handler.authorize.selector;
        selectors[1] = handler.rejectTokenPayout.selector;
        selectors[2] = handler.registerPayees.selector;
        selectors[3] = handler.distribute.selector;
        selectors[4] = handler.claimTokenPayout.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector(address(handler), selectors));
    }

    function invariant_nonceConsumption() public view {
        SafeSignature payouts = handler.payouts();
        uint256 paid;
        for (uint256 i; i < 2; ++i) {
            address recipient = handler.recipients(i);
            assertEq(payouts.nonces(recipient), handler.authorizations(recipient));
            paid += handler.paid(recipient);
        }
        assertEq(address(payouts).balance + paid, 100 ether);
    }

    function invariant_revertOnFailureRollback() public view {
        assertTrue(handler.rollbackIntact());
        assertTrue(handler.claimsConsumed());
        SafeRouter router = handler.router();
        address recipient = handler.recipients(0);
        assertEq(router.claimed(recipient), handler.tokenPaid());
        assertEq(handler.token().balanceOf(recipient), handler.tokenPaid());
        assertEq(handler.token().balanceOf(address(router)) + handler.tokenPaid(), 100 ether);
        assertEq(router.totalClaimable(), router.claimable(recipient));
        assertLe(router.totalClaimable(), handler.token().balanceOf(address(router)));
    }

    // A full traversal from a partial cursor can need two passes over the payee count.
    function invariant_withdrawalLiveness() public {
        SafeSplitter splitter = handler.splitter();
        address recipient = handler.recipients(1);
        uint256 outstanding = splitter.pending(recipient) + splitter.owed(recipient);
        if (outstanding == 0) return;
        uint256 before = recipient.balance;
        uint256 snapshot = vm.snapshotState();
        splitter.distribute(2);
        splitter.distribute(2);
        vm.prank(recipient);
        splitter.claim();
        assertEq(recipient.balance - before, outstanding);
        assertEq(splitter.owed(recipient) + splitter.pending(recipient), 0);
        assertTrue(vm.revertToState(snapshot));
    }
}
