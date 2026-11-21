// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeRouter} from "../src/SafeRouter.sol";
import {SafeLending} from "../src/SafeLending.sol";
import {SafeVault4626} from "../src/SafeVault4626.sol";
import {FakeOracle} from "../src/shared/FakeOracle.sol";
import {PropertyToken} from "./fixtures/root-only/PropertyFixtures.sol";

contract AccountingHandler is Test {
    PropertyToken public immutable token;
    SafeRouter public immutable router;
    SafeLending public immutable lending;
    SafeVault4626 public immutable vault;

    address[3] public actors = [address(0xA11CE), address(0xB0B), address(0xCAFE)];
    mapping(address => uint256) public funded;
    mapping(address => uint256) public borrowed;
    bool public overCapRejected = true;
    mapping(address => uint256) public shareLedger;

    constructor() {
        token = new PropertyToken();
        router = new SafeRouter(address(token));
        token.mint(address(router), 100 ether);
        lending = new SafeLending(address(new FakeOracle(2e18)));
        vault = new SafeVault4626(address(token));
    }

    function allocate(uint256 actorIndex, uint256 rawAmount) external {
        address actor = actors[actorIndex % actors.length];
        uint256 others = router.totalClaimable() - router.claimable(actor);
        uint256 room = token.balanceOf(address(router)) - others;
        router.setClaimable(actor, bound(rawAmount, 0, room));
    }

    function claim(uint256 actorIndex) external {
        address actor = actors[actorIndex % actors.length];
        if (router.claimable(actor) == 0) return;
        vm.prank(actor);
        router.claim();
    }

    function fund(uint256 actorIndex, uint256 rawAmount) external {
        address actor = actors[actorIndex % actors.length];
        uint256 amount = bound(rawAmount, 1, 10 ether);
        vm.deal(actor, amount);
        vm.prank(actor);
        lending.deposit{value: amount}(amount);
        funded[actor] += amount;
    }

    function borrow(uint256 actorIndex, uint256 rawAmount) external {
        address actor = actors[actorIndex % actors.length];
        uint256 room = funded[actor] * 3 / 2 - borrowed[actor];
        // Probe the contract's cap too, including exhausted and unfunded accounts.
        if (rawAmount % 2 == 0) {
            uint256 excessive = room + bound(rawAmount, 1, 10 ether);
            vm.prank(actor);
            (bool ok, bytes memory reason) = address(lending).call(abi.encodeCall(lending.borrow, (excessive)));
            overCapRejected = overCapRejected && !ok
                && keccak256(reason) == keccak256(abi.encodeWithSignature("Error(string)", "exceeds LTV"));
            // A rejected borrow must never enter the successful-borrow ledger.
            return;
        }
        if (room == 0) return;
        uint256 amount = bound(rawAmount, 1, room);
        vm.prank(actor);
        lending.borrow(amount);
        borrowed[actor] += amount;
    }

    function depositShares(uint256 actorIndex, uint256 rawAmount) external {
        address actor = actors[actorIndex % actors.length];
        uint256 amount = bound(rawAmount, 1 ether, 10 ether);
        token.mint(actor, amount);
        vm.prank(actor);
        shareLedger[actor] += vault.deposit(amount);
    }

    function redeemShares(uint256 actorIndex, uint256 rawShares) external {
        address actor = actors[actorIndex % actors.length];
        uint256 held = shareLedger[actor];
        if (held == 0) return;
        uint256 amount = bound(rawShares, 1, held);
        vm.prank(actor);
        vault.withdraw(amount);
        shareLedger[actor] -= amount;
    }

    function donate(uint256 rawAmount) external {
        token.mint(address(vault), bound(rawAmount, 1, 10 ether));
    }
}

contract AccountingInvariantTest is Test {
    AccountingHandler private handler;

    function setUp() public {
        vm.warp(1 days);
        handler = new AccountingHandler();
        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = handler.allocate.selector;
        selectors[1] = handler.claim.selector;
        selectors[2] = handler.fund.selector;
        selectors[3] = handler.borrow.selector;
        selectors[4] = handler.depositShares.selector;
        selectors[5] = handler.redeemShares.selector;
        selectors[6] = handler.donate.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector(address(handler), selectors));
    }

    function invariant_totalCoverage() public view {
        SafeRouter router = handler.router();
        uint256 outstanding;
        for (uint256 i; i < 3; ++i) {
            outstanding += router.claimable(handler.actors(i));
        }
        assertEq(router.totalClaimable(), outstanding);
        assertLe(outstanding, handler.token().balanceOf(address(router)));
    }

    function invariant_cumulativeDebt() public view {
        assertTrue(handler.overCapRejected());
        SafeLending lending = handler.lending();
        uint256 collateral;
        for (uint256 i; i < 3; ++i) {
            address actor = handler.actors(i);
            uint256 funded = handler.funded(actor);
            assertEq(lending.collateral(actor), funded);
            assertEq(lending.debt(actor), handler.borrowed(actor));
            assertLe(lending.debt(actor), funded * 3 / 2);
            collateral += funded;
        }
        assertEq(address(lending).balance, collateral);
    }

    function invariant_shareConservation() public view {
        SafeVault4626 vault = handler.vault();
        uint256 shares;
        for (uint256 i; i < 3; ++i) {
            address actor = handler.actors(i);
            assertEq(vault.shares(actor), handler.shareLedger(actor));
            shares += handler.shareLedger(actor);
        }
        assertEq(vault.totalShares(), shares);
    }
}
