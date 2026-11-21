// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeAccess
/// @notice Lab 02 — Remediated access control using msg.sender.
/// @dev The fix is one keyword: replace `tx.origin` with `msg.sender`.
///
/// Why it works:
///   msg.sender is always the immediate caller. When the owner EOA
///   calls a malicious contract that tries to chain-call SafeAccess,
///   msg.sender will be the malicious contract's address — not the
///   owner's. The authorization check fails.
contract SafeAccess {
    address public owner;

    event Withdrawal(address indexed to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    /// @notice SAFE: uses msg.sender — the immediate caller.
    function withdraw(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawal(to, amount);
    }

    receive() external payable {}
}
