// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeRouter
/// @notice Lab 10 — Remediated: every external call's return value is
///         checked and a failed token transfer reverts before any state
///         changes, so a failed claim leaves the entitlement intact.
/// @dev The only functional difference from VulnerableRouter is the
///      explicit `if (!ok) revert TransferFailed()` — exactly the line
///      that turns a silent accounting lie into a visible failure.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SafeRouter {
    IERC20 public immutable token;
    mapping(address => uint256) public claimable;
    mapping(address => uint256) public claimed;

    error TransferFailed();
    error NothingToClaim();

    event Claimed(address indexed claimant, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Seed a user's allocation (lab helper standing in for a merkle
    ///         or vesting backend).
    function setClaimable(address who, uint256 amount) external {
        claimable[who] = amount;
    }

    /// @notice Pay out the caller's entire allocation. Reverts — without
    ///         touching state — if the token reports failure.
    function claim() external {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingToClaim();

        bool ok = token.transfer(msg.sender, amount);
        if (!ok) revert TransferFailed();

        // State changes happen only after the transfer is known to have
        // succeeded: a reverted claim is fully retryable.
        claimed[msg.sender] = amount;
        delete claimable[msg.sender];

        emit Claimed(msg.sender, amount);
    }
}
