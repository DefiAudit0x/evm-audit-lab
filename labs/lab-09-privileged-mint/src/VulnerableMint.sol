// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableMint
/// @notice Lab 09 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. A token fully backed 1:1 by ETH in this contract,
///      whose `mint` entry point was meant for the team — but the `admin`
///      state variable is tracked and never checked. Anyone can mint
///      themselves tokens and immediately redeem them for the reserve.
contract VulnerableMint {
    address public admin;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Minted(address indexed to, uint256 amount);
    event Redeemed(address indexed from, uint256 amount);

    /// @param initialBacking ETH held as the 1:1 redemption reserve.
    constructor(uint256 initialBacking) payable {
        admin = msg.sender;
        require(msg.value == initialBacking, "must fund the reserve");
    }

    /// @notice Team-only minting — except nothing enforces it.
    function mint(address to, uint256 amount) external {
        // Vulnerability: authorization is declared but not enforced.
        // `admin` is stored, exposed, and never read by any check. The
        // function is the entire value gate: whoever can call it creates
        // redeemable claims on the ETH reserve for free.
        totalSupply += amount;
        balanceOf[to] += amount;

        emit Minted(to, amount);
    }

    /// @notice Redeem tokens 1:1 for the ETH backing them.
    function redeem(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");

        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Redeemed(msg.sender, amount);
    }
}
