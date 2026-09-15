// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableVault4626
/// @notice Lab 11 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. Share pricing floors in the depositor's disfavor and
///      `totalAssets` is read straight from the token balance, so a direct
///      donation can inflate the share price. The first depositor can weaponize
///      the degenerate zero/low-supply regime: donate, wait for the next
///      depositor to round to zero shares, and redeem the whole vault for
///      essentially one share.
interface IERC4626Asset {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableVault4626 {
    IERC4626Asset public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address asset_) {
        asset = IERC4626Asset(asset_);
    }

    /// @dev Naive conversion: floors, and prices against the live token
    ///      balance — which anyone can move with a plain transfer.
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalShares == 0) return assets;
        return (assets * totalShares) / asset.balanceOf(address(this));
    }

    function deposit(uint256 assets) external returns (uint256 minted) {
        minted = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transferFrom failed");
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function withdraw(uint256 sharesToBurn) external returns (uint256 assets) {
        require(shares[msg.sender] >= sharesToBurn, "insufficient shares");
        assets = (sharesToBurn * asset.balanceOf(address(this))) / totalShares;
        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        require(asset.transfer(msg.sender, assets), "transfer failed");
    }
}
