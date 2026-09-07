// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableRouter
/// @notice Lab 10 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. An airdrop-style claims router that calls
///      `token.transfer` and ignores the returned `bool`. Tokens that
///      signal failure by returning false (USDT-style) instead of
///      reverting make the router record a claim that never paid out —
///      the user's entitlement is erased and the tokens stay in the
///      router forever.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerableRouter {
    IERC20 public immutable token;
    mapping(address => uint256) public claimable;
    mapping(address => uint256) public claimed;

    event Claimed(address indexed claimant, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Seed a user's allocation (lab helper standing in for a merkle
    ///         or vesting backend).
    function setClaimable(address who, uint256 amount) external {
        claimable[who] = amount;
    }

    /// @notice Pay out the caller's entire allocation.
    function claim() external {
        uint256 amount = claimable[msg.sender];
        require(amount > 0, "nothing to claim");

        // Vulnerability: the bool return value is discarded. A token that
        // returns false on failure (paused, blacklisted, fee-on-transfer
        // edge cases) does not revert here, so execution continues as if
        // the user was paid.
        token.transfer(msg.sender, amount);

        // The entitlement is erased either way — the user can never retry.
        claimed[msg.sender] = amount;
        delete claimable[msg.sender];

        emit Claimed(msg.sender, amount);
    }
}
