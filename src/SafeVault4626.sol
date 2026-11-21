// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeVault4626
/// @notice Lab 11 — virtual-liquidity share accounting with zero-share rejection.
/// @dev Equal virtual asset/share offsets make the empty-vault conversion 1:1;
///      they do not provide a decimal precision offset or prevent every
///      donation attack. Deposits that would mint zero shares revert. This
///      model supports exact-transfer, non-rebasing assets only.
interface IERC4626AssetSafe {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SafeVault4626 {
    error TransferFailed();
    error Reentrancy();
    error UnsupportedTokenBehavior();

    /// @dev These equal offsets provide virtual liquidity, not extra precision.
    uint256 internal constant _VIRTUAL_SHARES = 1000e18;
    uint256 internal constant _VIRTUAL_ASSETS = 1000e18;

    IERC4626AssetSafe public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    uint256 private _lock = 1;

    constructor(address asset_) {
        asset = IERC4626AssetSafe(asset_);
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return _sharesForAssets(assets, asset.balanceOf(address(this)));
    }

    function _sharesForAssets(uint256 assets, uint256 assetsBefore) private view returns (uint256) {
        return (assets * (totalShares + _VIRTUAL_SHARES)) / (assetsBefore + _VIRTUAL_ASSETS);
    }

    function deposit(uint256 assets) external nonReentrant returns (uint256 minted) {
        uint256 assetsBefore = asset.balanceOf(address(this));
        if (!asset.transferFrom(msg.sender, address(this), assets)) revert TransferFailed();
        uint256 assetsAfter = asset.balanceOf(address(this));
        if (assetsAfter < assetsBefore) revert UnsupportedTokenBehavior();

        uint256 received = assetsAfter - assetsBefore;
        require(received == assets, "fee token unsupported");

        // Price the minted shares using the measured receipt and pre-deposit
        // assets. Fee-on-transfer deposits are rejected above.
        minted = _sharesForAssets(received, assetsBefore);
        require(minted > 0, "zero shares");
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function withdraw(uint256 sharesToBurn) external nonReentrant returns (uint256 assets) {
        require(shares[msg.sender] >= sharesToBurn, "insufficient shares");
        uint256 assetsBefore = asset.balanceOf(address(this));
        assets = (sharesToBurn * (assetsBefore + _VIRTUAL_ASSETS)) / (totalShares + _VIRTUAL_SHARES);

        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        uint256 recipientBefore = asset.balanceOf(msg.sender);
        if (!asset.transfer(msg.sender, assets)) revert TransferFailed();

        uint256 assetsAfter = asset.balanceOf(address(this));
        uint256 recipientAfter = asset.balanceOf(msg.sender);
        if (
            assetsAfter > assetsBefore || assetsBefore - assetsAfter != assets || recipientAfter < recipientBefore
                || recipientAfter - recipientBefore != assets
        ) {
            revert UnsupportedTokenBehavior();
        }
    }
}
