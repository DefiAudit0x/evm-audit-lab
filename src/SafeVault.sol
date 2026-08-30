// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeVault
/// @notice Lab 01 — Remediated: applies checks-effects-interactions.
/// @dev The balance is decremented BEFORE the external call. A malicious
///      receiver that tries to re-enter withdraw() will fail the balance
///      check on the second call.
contract SafeVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient balance");

        // Checks-effects-interactions: restore the accounting invariant first.
        balances[msg.sender] -= amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
