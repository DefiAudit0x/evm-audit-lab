// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableVault
/// @notice Lab 01 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. The withdraw function sends ETH before updating
///      accounting, allowing a malicious receiver to re-enter.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient balance");

        // Vulnerability: control is transferred before accounting is updated.
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // Intentionally unchecked so Solidity 0.8 underflow protection does
        // not mask the reentrancy lesson: nested calls can spend stale credit.
        unchecked {
            balances[msg.sender] -= amount;
        }
    }

    receive() external payable {}
}
