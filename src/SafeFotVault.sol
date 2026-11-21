// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeFotVault
/// @notice Lab 13 — credits deposits from the token balance delta.
/// @dev Incoming transfer fees are supported when the token reports balances
///      honestly. Rebases and transfers that debit the vault by more than the
///      requested withdrawal are unsupported. This is an educational model.
interface ISafeFotERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SafeFotVault {
    error TransferFailed();
    error Reentrancy();
    error NothingReceived();
    error UnsupportedTokenBehavior();

    ISafeFotERC20 public immutable token;
    mapping(address => uint256) public balances;
    uint256 private _lock = 1;

    constructor(address token_) {
        token = ISafeFotERC20(token_);
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    function deposit(uint256 amount) external nonReentrant {
        uint256 beforeBalance = token.balanceOf(address(this));
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        uint256 afterBalance = token.balanceOf(address(this));
        if (afterBalance < beforeBalance) revert UnsupportedTokenBehavior();

        uint256 received = afterBalance - beforeBalance;
        if (received == 0) revert NothingReceived();
        balances[msg.sender] += received;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");
        uint256 beforeBalance = token.balanceOf(address(this));

        balances[msg.sender] -= amount;
        if (!token.transfer(msg.sender, amount)) revert TransferFailed();

        uint256 afterBalance = token.balanceOf(address(this));
        if (afterBalance > beforeBalance || beforeBalance - afterBalance != amount) {
            revert UnsupportedTokenBehavior();
        }
    }
}
