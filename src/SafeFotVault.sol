// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeFotVault
/// @notice Lab 13 — Remediated: balance-delta accounting.
/// @dev Deposits are credited by the observed balance change, not the
///      requested amount, so fee-on-transfer and short-delivery tokens can
///      never mint claims above real backing.
interface ISafeFotERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SafeFotVault {
    ISafeFotERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address token_) {
        token = ISafeFotERC20(token_);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        uint256 received = token.balanceOf(address(this)) - before;
        require(received > 0, "nothing received");
        balances[msg.sender] += received;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
