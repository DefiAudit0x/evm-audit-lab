// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSignature} from "../src/VulnerableSignature.sol";
import {SafeSignature} from "../src/SafeSignature.sol";

contract PayoutReceiver {
    SafeSignature internal immutable vault;
    bool public acceptsPayment;
    uint256 public observedNonce;

    constructor(SafeSignature vault_) {
        vault = vault_;
    }

    function acceptPayment() external {
        acceptsPayment = true;
    }

    receive() external payable {
        require(acceptsPayment, "payment refused");
        observedNonce = vault.nonces(address(this));
    }
}

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

    /// @notice Regression (m-12): replay repeats the fixed-size payout
    ///         while funds suffice — it does not drain the vault
    ///         completely unless the amounts line up. With 5.5 ETH funded
    ///         and a 1 ETH authorization, five payouts succeed, the sixth
    ///         fails, and 0.5 ETH remains.
    function testVulnerableSignatureReplayStopsWhenFundsRunShort() public {
        VulnerableSignature vault = new VulnerableSignature{value: 5.5 ether}(authority);
        (uint8 v, bytes32 r, bytes32 s) = _signRawPayout(AUTHORITY_KEY, victim, PAYOUT);

        for (uint256 i = 0; i < 5; i++) {
            vault.withdraw(victim, PAYOUT, v, r, s);
        }
        assertEq(victim.balance, 5 ether, "five payouts must succeed");
        assertEq(address(vault).balance, 0.5 ether, "0.5 ETH must remain");

        vm.expectRevert("transfer failed");
        vault.withdraw(victim, PAYOUT, v, r, s);
        assertEq(address(vault).balance, 0.5 ether, "failed sixth payout must leave the remainder");
        assertEq(victim.balance, 5 ether, "victim must receive nothing more");
    }

    function testSafeSignaturePaysExactlyOnce() public {
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);
        assertEq(victim.balance, PAYOUT, "honest flow pays once");
        assertEq(safe.nonces(victim), 1);

        // Replaying the exact same call reverts: the nonce moved on.
        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);

        assertEq(victim.balance, PAYOUT, "no extra payout from the replay");
        assertEq(safe.nonces(victim), 1);
    }

    function testSafeSignatureFollowsCurrentChainId() public {
        uint256 newChain = block.chainid + 1;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);
        vm.chainId(newChain);
        assertEq(
            safe.domainSeparator(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("SafeSignature"),
                    keccak256("1"),
                    newChain,
                    address(safe)
                )
            )
        );
        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);
        assertEq(safe.nonces(victim), 0);

        (v, r, s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);
        safe.withdraw(victim, PAYOUT, block.timestamp + 1 hours, v, r, s);
        assertEq(victim.balance, PAYOUT);
    }

    function testSafeSignatureConsumesNonceBeforePayoutAndRollsBackOnFailure() public {
        PayoutReceiver receiver = new PayoutReceiver(safe);
        address recipient = address(receiver);
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, recipient, PAYOUT);
        uint256 deadline = block.timestamp + 1 hours;

        vm.expectRevert(SafeSignature.TransferFailed.selector);
        safe.withdraw(recipient, PAYOUT, deadline, v, r, s);
        assertEq(safe.nonces(recipient), 0);
        assertEq(address(safe).balance, VAULT_FUNDING);

        receiver.acceptPayment();
        safe.withdraw(recipient, PAYOUT, deadline, v, r, s);
        assertEq(receiver.observedNonce(), 1);
        assertEq(recipient.balance, PAYOUT);
        assertEq(safe.nonces(victim), 0);
    }

    function testSafeSignatureRejectsExpired() public {
        // Preserve the original signed deadline: the test submits the
        // deadline the authority actually signed, after it has passed,
        // so the revert demonstrates expiration of that authorization
        // directly rather than of a deadline invented at submit time.
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(SafeSignature.SignatureExpired.selector);
        safe.withdraw(victim, PAYOUT, deadline, v, r, s);

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
        assertEq(safe.nonces(victim), 0);
    }

    function testSafeSignatureRejectsMalformedSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        // Zeroed (v, r, s): ecrecover yields the zero address.
        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        safe.withdraw(victim, PAYOUT, deadline, 0, bytes32(0), bytes32(0));

        // A signature from the wrong key recovers a non-authority signer.
        (uint8 wv, bytes32 wr, bytes32 ws) = _signTypedPayout(0xBADD, safe, victim, PAYOUT);
        vm.expectRevert(SafeSignature.InvalidSignature.selector);
        safe.withdraw(victim, PAYOUT, deadline, wv, wr, ws);

        assertEq(safe.nonces(victim), 0, "malformed signatures must not consume the nonce");

        // The valid signature still pays exactly once afterwards.
        safe.withdraw(victim, PAYOUT, deadline, v, r, s);
        assertEq(victim.balance, PAYOUT);
        assertEq(safe.nonces(victim), 1);
    }

    function testSafeSignatureAcceptsAtExactDeadline() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        // At exactly the deadline the signature is still live: the check
        // reverts only when block.timestamp > deadline.
        vm.warp(deadline);
        safe.withdraw(victim, PAYOUT, deadline, v, r, s);
        assertEq(victim.balance, PAYOUT, "payout at the exact deadline must succeed");
        assertEq(safe.nonces(victim), 1);
    }

    function testSafeSignatureRejectsOneSecondPastDeadline() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, victim, PAYOUT);

        vm.warp(deadline + 1);
        vm.expectRevert(SafeSignature.SignatureExpired.selector);
        safe.withdraw(victim, PAYOUT, deadline, v, r, s);
        assertEq(victim.balance, 0, "nothing paid one second past the deadline");
        assertEq(safe.nonces(victim), 0);
    }

    function testSafeSignatureReentrantReplayFails() public {
        ReentrantReplayReceiver receiver = new ReentrantReplayReceiver(safe);
        address recipient = address(receiver);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signTypedPayout(AUTHORITY_KEY, safe, recipient, PAYOUT);
        receiver.armReplay(recipient, PAYOUT, deadline, v, r, s);

        // The outer payout succeeds once; the nested replay inside the
        // receive hook fails because the nonce was consumed before the
        // transfer, so the replayed digest no longer matches.
        safe.withdraw(recipient, PAYOUT, deadline, v, r, s);

        assertTrue(receiver.replayAttempted(), "nested replay must have been attempted");
        assertFalse(receiver.replaySucceeded(), "nested replay must fail");
        assertEq(recipient.balance, PAYOUT, "exactly one payout");
        assertEq(safe.nonces(recipient), 1);
        assertEq(address(safe).balance, VAULT_FUNDING - PAYOUT);
    }

    uint256 private constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
}

/// @dev Receiver that tries to replay the exact same signature from inside
///      its receive hook, while the outer payout is still in flight.
contract ReentrantReplayReceiver {
    SafeSignature internal immutable vault;
    bytes public pendingCalldata;
    bool public replayAttempted;
    bool public replaySucceeded;

    constructor(SafeSignature vault_) {
        vault = vault_;
    }

    function armReplay(address recipient, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        pendingCalldata = abi.encodeCall(SafeSignature.withdraw, (recipient, amount, deadline, v, r, s));
    }

    receive() external payable {
        if (pendingCalldata.length == 0) return;
        replayAttempted = true;
        (replaySucceeded,) = address(vault).call(pendingCalldata);
    }
}
