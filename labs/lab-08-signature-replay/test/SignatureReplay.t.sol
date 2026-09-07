// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSignature} from "../src/VulnerableSignature.sol";
import {SafeSignature} from "../src/SafeSignature.sol";

/// @title SignatureReplay.t.sol
/// @notice Lab 08 — Exploit + regression tests for signature authorization.
///
/// Lab: Missing protection against signature replay
///
/// Threat model:
///   The vault pays out ETH against an ECDSA signature from an off-chain
///   authority. Every signature travels through the mempool and lands
///   permanently on-chain, so it must be treated as public knowledge that
///   anyone can resubmit at any time, on any contract.
///
/// Violated invariant:
///   "One signature authorizes exactly one payout."
///   The vulnerable contract signs a raw `keccak256(abi.encodePacked(
///   recipient, amount))` with no nonce, deadline, chain id or verifying
///   contract, and never marks signatures as consumed.
///
/// Reproduction:
///   1. The authority signs a 1 ETH payout to the victim.
///   2. Anyone submits it — the victim is paid (the legitimate use).
///   3. The attacker resubmits the identical (v, r, s) — the vault pays
///      again. Repeat until the vault is empty.
///
/// Remediation (see SafeSignature):
///   EIP-712 domain separator binds the digest to (name, version, chainId,
///   address(this)); a per-recipient nonce is consumed before the transfer;
///   the deadline check bounds the signature's lifetime; and a high-s check
///   blocks malleable forgeries.
///
/// Regression tests:
///   The replay, the cross-contract reuse, the expired deadline and the
///   malleable s-value all revert on SafeSignature, while the honest flow
///   still pays exactly once.
contract SignatureReplayTest is Test {
    VulnerableSignature internal vulnerable;
    SafeSignature internal safe;

    uint256 internal constant AUTHORITY_KEY = 0xA11CE;
    uint256 internal constant PAYOUT = 1 ether;
    uint256 internal constant VAULT_FUNDING = 5 ether;

    address internal authority;
    address internal victim;

    function setUp() public {
        authority = vm.addr(AUTHORITY_KEY);
        victim = makeAddr("victim");

        vulnerable = new VulnerableSignature{value: VAULT_FUNDING}(authority);
        safe = new SafeSignature{value: VAULT_FUNDING}(authority);
    }

    function _signRawPayout(uint256 privateKey, address recipient, uint256 amount)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 message = keccak256(abi.encodePacked(recipient, amount));
        (v, r, s) = vm.sign(privateKey, message);
    }

    function _signTypedPayout(uint256 privateKey, SafeSignature vault, address recipient, uint256 amount)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 domainSeparator = vault.domainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Withdrawal(address recipient,uint256 amount,uint256 nonce,uint256 deadline)"),
                        recipient,
                        amount,
                        vault.nonces(recipient),
                        block.timestamp + 1 hours
                    )
                )
            )
        );
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function testVulnerableSignatureSingleSigDrainsVault() public {
        // Step 1-2: one legitimate payout.
        (uint8 v, bytes32 r, bytes32 s) = _signRawPayout(AUTHORITY_KEY, victim, PAYOUT);
        vulnerable.withdraw(victim, PAYOUT, v, r, s);
        assertEq(victim.balance, PAYOUT, "victim received the legitimate payout");

        // Step 3: the same signature pays again — and again.
        for (uint256 i = 0; i < 4; i++) {
            vulnerable.withdraw(victim, PAYOUT, v, r, s);
        }

        assertEq(address(vulnerable).balance, 0, "vault drained by one signature");
        assertEq(victim.balance, VAULT_FUNDING, "victim received five payouts from one signature");
    }

    function testSafeSignaturePaysExactlyOnce() public {
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);
        assertEq(victim.balance, PAYOUT, "honest flow pays once");

        // Replaying the exact same call reverts: the nonce moved on.
        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);

        assertEq(victim.balance, PAYOUT, "no extra payout from the replay");
    }

    function testSafeSignatureRejectsExpired() public {
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(SafeSignature.SignatureExpired.selector);
        safe.withdraw(victim, PAYOUT, block.timestamp - 1, v, r, s);

        assertEq(victim.balance, 0, "nothing paid after the deadline");
    }

    function testSafeSignatureRejectsCrossContractReplay() public {
        // A second vault with the same authority and message layout.
        SafeSignature secondVault = new SafeSignature{value: VAULT_FUNDING}(authority);

        // Signed for `safe` only — the domain separator pins it to this
        // contract and chain.
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        secondVault.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);

        assertEq(victim.balance, 0, "signature from one vault must not pay on another");
    }

    function testSafeSignatureRejectsMalleableS() public {
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        // Flip (v, s) to the other curve point with the same recovered
        // address. A signature scheme without a high-s check accepts the
        // forgery; SafeSignature rejects it outright.
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes32 flippedS = bytes32(SECP256K1_N - uint256(s));

        vm.expectRevert(SafeSignature.MalleableSignature.selector);
        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, flippedV, r, flippedS);
    }

    uint256 private constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
}
