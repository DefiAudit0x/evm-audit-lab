// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableProxy, VulnerableImplV1} from "../src/VulnerableProxy.sol";
import {SafeProxy, SafeImplV1, SafeImplV2} from "../src/SafeProxy.sol";

/// @title ProxyCollision.t.sol
/// @notice Lab 07 — Exploit + regression test for proxy storage collision.
///
/// Lab: Upgradeable proxy storage collision
///
/// Threat model:
///   A hand-rolled proxy keeps `admin` and `implementation` in regular
///   slots 0 and 1. Storage is shared between the proxy and whatever
///   implementation it delegates to: the implementation's `value`
///   variable also lives in slot 0. Any state write executed through the
///   proxy therefore rewrites proxy administration.
///
/// Violated invariant:
///   "Only the deployer-admin can change the implementation."
///   With overlapping layouts, the implementation can rewrite the admin
///   (or the implementation pointer) without any permission check.
///
/// Reproduction:
///   1. Deploy VulnerableImplV1 and a VulnerableProxy around it.
///   2. Admin calls `proxy.setValue(1)` through the proxy.
///      `delegatecall` executes V1's code against proxy storage: slot 0
///      — the admin slot — is set to 1.
///   3. `proxy.admin()` now returns `address(1)`. The original admin fails
///      `require(msg.sender == admin)` on `upgradeTo`, but unrestricted
///      `setValue` lets anyone write a chosen address to slot 0 and take
///      over or reassign admin authority.
///
/// Remediation:
///   Store proxy metadata in EIP-1967 slots (keccak256-derived, far from
///   any realistic layout), keep implementation storage append-only
///   across upgrades, and initialize with a one-time `initializer`-guarded
///   `initialize` — never a constructor. This example does not demonstrate
///   guarded initialization: its implementations expose only unrestricted
///   setters and there is no `initialize` function, so a production proxy
///   must add it (see SafeProxy / SafeImplV1 / SafeImplV2).
///
/// Regression test:
///   The same `setValue` call against SafeProxy leaves `admin()` intact,
///   the upgrade still works, and upgraded state (V1's `value`) is
///   preserved by the append-only V2 layout.
contract ProxyCollisionTest is Test {
    function testVulnerableProxyAdminIsClobbered() public {
        VulnerableImplV1 impl = new VulnerableImplV1();
        VulnerableProxy proxy = new VulnerableProxy(address(impl));

        // Admin calls a seemingly harmless setter through the proxy.
        (bool ok,) = address(proxy).call(abi.encodeWithSignature("setValue(uint256)", 1));
        assertTrue(ok, "setValue must succeed");

        // Slot 0 of the shared storage was overwritten: admin is gone.
        assertEq(proxy.admin(), address(1), "admin must be clobbered to address(1)");
        assertEq(VulnerableImplV1(address(proxy)).value(), 1, "value read from slot 0");

        // The original admin cannot upgrade, but anyone can use unrestricted
        // setValue to take over or reassign admin authority.
        VulnerableImplV1 replacement = new VulnerableImplV1();
        vm.expectRevert(bytes("not admin"));
        proxy.upgradeTo(address(replacement));
        assertEq(proxy.implementation(), address(impl), "rejected upgrade must preserve implementation");
    }

    function testSafeProxyRejectsCodeLessDeployment() public {
        vm.expectRevert(bytes("no code"));
        new SafeProxy(makeAddr("code-less"));
    }

    function testSafeProxyRejectsCodeLessUpgrade() public {
        SafeImplV1 impl = new SafeImplV1();
        SafeProxy proxy = new SafeProxy(address(impl));
        address codeLess = makeAddr("code-less");

        vm.expectRevert(bytes("no code"));
        proxy.upgradeTo(codeLess);
        assertEq(proxy.implementation(), address(impl));
    }

    function testSafeProxyRejectsInitializerCalls() public {
        // Neither SafeProxy nor SafeImplV1 has an initializer: guarded
        // initialization is an additional production requirement absent
        // from this example, and any initialize() call through the proxy
        // reverts instead of taking effect.
        SafeImplV1 impl = new SafeImplV1();
        SafeProxy proxy = new SafeProxy(address(impl));

        (bool ok0,) = address(proxy).call(abi.encodeWithSignature("initialize()"));
        assertFalse(ok0, "initialize() must revert through the proxy");
        (bool ok1,) = address(proxy).call(abi.encodeWithSignature("initialize(uint256)", 1));
        assertFalse(ok1, "initialize(uint256) must revert through the proxy");

        assertEq(proxy.admin(), address(this), "admin unchanged by the failed calls");
        assertEq(proxy.implementation(), address(impl), "implementation unchanged by the failed calls");
    }

    function testSafeProxyKeepsAdminSeparate() public {
        SafeImplV1 implV1 = new SafeImplV1();
        SafeProxy proxy = new SafeProxy(address(implV1));

        (bool ok,) = address(proxy).call(abi.encodeWithSignature("setValue(uint256)", 42));
        assertTrue(ok, "setValue must succeed");

        // Proxy metadata lives in EIP-1967 slots — untouched by the impl.
        assertEq(proxy.admin(), address(this), "admin must remain intact");
        assertEq(SafeImplV1(address(proxy)).value(), 42, "value stored via delegatecall");

        // Upgrade works and state is preserved across implementations.
        proxy.upgradeTo(address(new SafeImplV2()));
        assertEq(SafeImplV2(address(proxy)).value(), 42, "append-only layout preserves slot 0");
        SafeImplV2(address(proxy)).setExtra(7);
        assertEq(SafeImplV2(address(proxy)).extra(), 7, "appended slot is usable");
    }

    /// @notice A non-admin upgrade attempt reverts and the implementation
    ///         (and admin) remain unchanged.
    function testSafeProxyRejectsNonAdminUpgrade() public {
        SafeImplV1 implV1 = new SafeImplV1();
        SafeProxy proxy = new SafeProxy(address(implV1));
        SafeImplV2 replacement = new SafeImplV2();

        address nonAdmin = makeAddr("non-admin");
        vm.prank(nonAdmin);
        vm.expectRevert(bytes("not admin"));
        proxy.upgradeTo(address(replacement));

        assertEq(proxy.implementation(), address(implV1), "rejected upgrade must preserve implementation");
        assertEq(proxy.admin(), address(this), "admin must remain unchanged");
        assertEq(SafeImplV1(address(proxy)).value(), 0, "implementation state must be untouched");
    }
}
