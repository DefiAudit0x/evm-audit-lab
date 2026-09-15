// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeVault4626
/// @notice Lab 11 — Remediated: virtual shares offset the degenerate regime.
/// @dev OpenZeppelin-style virtual share/asset constants are folded into both
///      sides of the share math, so real supply never operates in the
///      1-share territory where a rounding unit is worth the whole vault, and
///      a donation moves the price by at most a dust fraction.
interface IERC4626AssetSafe {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SafeVault4626 {
    /// @dev Offset chosen so that a 1-wei deposit still mints proportional
    ///      shares and donations cannot round a real deposit to zero.
    uint256 internal constant _VIRTUAL_SHARES = 1000e18;
    uint256 internal constant _VIRTUAL_ASSETS = 1000e18;

    IERC4626AssetSafe public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address asset_) {
        asset = IERC4626AssetSafe(asset_);
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalShares + _VIRTUAL_SHARES)) / (asset.balanceOf(address(this)) + _VIRTUAL_ASSETS);
    }

    function deposit(uint256 assets) external returns (uint256 minted) {
        minted = convertToShares(assets);
        require(minted > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets), "transferFrom failed");
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function withdraw(uint256 sharesToBurn) external returns (uint256 assets) {
        require(shares[msg.sender] >= sharesToBurn, "insufficient shares");
        assets = (sharesToBurn * (asset.balanceOf(address(this)) + _VIRTUAL_ASSETS)) / (totalShares + _VIRTUAL_SHARES);
        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        require(asset.transfer(msg.sender, assets), "transfer failed");
    }
}
