// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeMint
/// @notice Lab 09 — Role-gated minting, a lifetime issuance cap, and ETH
///         backing for all outstanding 1:1 redeemable claims.
/// @dev Assumes one wei backs each raw supply unit; 10^18 units redeem for
///      one ETH. The admin controls minters; issuance has a lifetime cap and
///      outstanding supply cannot exceed current ETH backing. This is an
///      educational model, not a production token or a proof that admin/minter
///      keys are secure.
contract SafeMint {
    address public admin;
    uint256 public immutable maxSupply;
    uint256 public totalSupply;
    uint256 public totalMinted;

    mapping(address => bool) public isMinter;
    mapping(address => uint256) public balanceOf;

    error NotAdmin();
    error NotMinter();
    error CapExceeded();
    error InsufficientBacking();
    error InvalidRecipient();

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
    ///         lifetime issuance cap and available reserve.
    function mint(address to, uint256 amount) external {
        if (!isMinter[msg.sender]) revert NotMinter();
        if (to == address(0)) revert InvalidRecipient();
        if (amount > maxSupply - totalMinted) revert CapExceeded();
        if (totalSupply > address(this).balance || amount > address(this).balance - totalSupply) {
            revert InsufficientBacking();
        }

        totalMinted += amount;

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
