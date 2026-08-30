// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableAccess
/// @notice Lab 02 — Vulnerable access control using tx.origin.
/// @dev DO NOT DEPLOY. This contract is intentionally unsafe.
///
/// Threat model:
///   Any address that can persuade an owner to call any function on any
///   contract controlled by the attacker (e.g. a fake airdrop claim,
///   a malicious NFT mint, a phishing DApp) can become a transient
///   "owner" for the duration of that call.
///
/// Violated invariant:
///   "Only the owner's EOA can authorize privileged actions."
///   tx.origin breaks this invariant because it returns the EOA that
///   started the transaction, not the immediate caller. Any contract
///   the owner interacts with inherits the owner's tx.origin for that
///   transaction.
contract VulnerableAccess {
    address public owner;

    event Withdrawal(address indexed to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    /// @notice VULNERABLE: uses tx.origin instead of msg.sender.
    function withdraw(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawal(to, amount);
    }

    receive() external payable {}
}
