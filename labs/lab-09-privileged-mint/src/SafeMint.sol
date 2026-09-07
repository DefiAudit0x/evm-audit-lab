// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeMint
/// @notice Lab 09 — Remediated: role-based minting with an admin that
///         grants/revokes minters, a hard supply cap, and checks-effects-
///         interactions ordering in `redeem`.
/// @dev Two independent defenses: (1) `mint` reverts unless the caller was
///      explicitly granted the minter role by the admin — the role itself
///      is the capability; (2) `maxSupply` bounds the damage a compromised
///      or malicious minter can do.
contract SafeMint {
    address public admin;
    uint256 public immutable maxSupply;
    uint256 public totalSupply;

    mapping(address => bool) public isMinter;
    mapping(address => uint256) public balanceOf;

    error NotAdmin();
    error NotMinter();
    error CapExceeded();

    event MinterSet(address indexed minter, bool allowed);
    event Minted(address indexed to, uint256 amount);
    event Redeemed(address indexed from, uint256 amount);

    /// @param initialBacking ETH held as the 1:1 redemption reserve.
    /// @param cap Maximum total supply any minter can create, ever.
    constructor(uint256 initialBacking, uint256 cap) payable {
        require(msg.value == initialBacking, "must fund the reserve");
        admin = msg.sender;
        maxSupply = cap;
    }

    /// @notice Grant or revoke the minter role. Admin only.
    function setMinter(address minter, bool allowed) external {
        if (msg.sender != admin) revert NotAdmin();

        isMinter[minter] = allowed;
        emit MinterSet(minter, allowed);
    }

    /// @notice Mint tokens. Requires the explicit minter role and respects
    ///         the hard supply cap.
    function mint(address to, uint256 amount) external {
        if (!isMinter[msg.sender]) revert NotMinter();
        if (totalSupply + amount > maxSupply) revert CapExceeded();

        totalSupply += amount;
        balanceOf[to] += amount;

        emit Minted(to, amount);
    }

    /// @notice Redeem tokens 1:1 for the ETH backing them.
    function redeem(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");

        // Checks-effects-interactions: state first, ETH last.
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Redeemed(msg.sender, amount);
    }
}
