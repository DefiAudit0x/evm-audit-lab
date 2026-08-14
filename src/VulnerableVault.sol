// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Intentionally vulnerable educational example. Do not deploy.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient balance");

        // Vulnerability: control is transferred before accounting is updated.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}
