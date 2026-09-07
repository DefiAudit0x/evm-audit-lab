// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeSignature
/// @notice Lab 08 — Remediated: EIP-712 typed signatures bound to this
///         contract and chain, with per-recipient nonces, deadlines and a
///         high-s malleability guard.
/// @dev A signature can only ever authorize one payout: the nonce is
///      consumed before the transfer, the domain separator pins the digest
///      to (name, version, chainId, address(this)), and an expired deadline
///      or a malleable high-s value reverts.
contract SafeSignature {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant WITHDRAWAL_TYPEHASH =
        keccak256("Withdrawal(address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    /// @dev Half of the secp256k1 group order. Signatures with
    ///      `s > HALF_N` are malleable forgeries of a valid signature.
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    address public immutable authority;
    bytes32 public immutable domainSeparator;

    /// @dev One slot per recipient: replaying a consumed signature makes
    ///      the recovered digest differ from the signed one.
    mapping(address => uint256) public nonces;

    error InvalidSignature();
    error SignatureExpired();
    error MalleableSignature();
    error TransferFailed();

    event Withdrawn(address indexed recipient, uint256 amount);

    constructor(address _authority) payable {
        authority = _authority;
        domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("SafeSignature"), keccak256("1"), block.chainid, address(this))
        );
    }

    receive() external payable {}

    /// @notice Pays out `amount` ETH to `recipient` against a fresh,
    ///         unexpired EIP-712 signature from the authority.
    function withdraw(address recipient, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (uint256(s) > HALF_N) revert MalleableSignature();

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(abi.encode(WITHDRAWAL_TYPEHASH, recipient, amount, nonces[recipient], deadline))
            )
        );

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != authority) revert InvalidSignature();

        // Consume the nonce BEFORE any external interaction so a reentrant
        // or repeated call computes a different digest.
        nonces[recipient]++;

        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit Withdrawn(recipient, amount);
    }
}
