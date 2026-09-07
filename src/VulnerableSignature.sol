// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableSignature
/// @notice Lab 08 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. Withdrawals are authorized with a raw ECDSA
///      signature over `keccak256(abi.encodePacked(recipient, amount))`.
///      The signed message carries no nonce, no deadline, no chain id and
///      no verifying-contract address, and consumed signatures are never
///      tracked. Anyone who observes one valid payout (in the mempool or
///      on-chain) can resubmit the exact same signature until the vault is
///      empty, and can also reuse the signature verbatim on any other
///      contract that hashes the same layout (cross-contract replay).
contract VulnerableSignature {
    address public immutable authority;

    event Withdrawn(address indexed recipient, uint256 amount);

    /// @param _authority The off-chain signer whose signature authorizes payouts.
    constructor(address _authority) payable {
        authority = _authority;
    }

    receive() external payable {}

    /// @notice Pays out `amount` ETH to `recipient` when the authority signs
    ///         `keccak256(abi.encodePacked(recipient, amount))`.
    function withdraw(address recipient, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        // Vulnerability: replayable authorization. Nothing binds this
        // signature to a nonce, a deadline, a chain or this contract, and
        // there is no record of already-used signatures.
        bytes32 message = keccak256(abi.encodePacked(recipient, amount));
        address signer = ecrecover(message, v, r, s);
        require(signer != address(0) && signer == authority, "invalid signature");

        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawn(recipient, amount);
    }
}
