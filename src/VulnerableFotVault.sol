// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableFotVault
/// @notice Lab 13 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. The vault credits the *requested* deposit amount while
///      a fee-on-transfer token delivers less, so every deposit mints claims
///      that exceed the value actually received. The shortfall is silently
///      socialized onto honest depositors, and a cycling attacker extracts it.
interface IFotERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableFotVault {
    IFotERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address token_) {
        token = IFotERC20(token_);
    }

    /// @notice Vulnerability: accounting trusts the instruction, not the
    ///         observed balance delta.
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        balances[msg.sender] += amount; // credited > received for fee tokens
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
