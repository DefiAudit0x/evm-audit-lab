// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafePool
/// @notice Lab 05 — rejects zero-share deposits and seeds fixed dead shares.
/// @dev Dead shares increase the donation needed for the tested first-deposit
///      attack, but do not cap the first depositor's ownership when that
///      depositor contributes much more than DEAD_SHARES. This model does not
///      guarantee every donation strategy is unprofitable. The first deposit
///      must exceed 1000 wei so redeeming all its shares returns at least 1 wei.
contract SafePool {
    /// @dev Minted to address(0) on the first deposit. Dilutes any attempt
    ///      to buy an outsized fraction of `totalShares` with a tiny deposit.
    uint256 private constant DEAD_SHARES = 1_000_000;

    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    event Deposited(address indexed depositor, uint256 assets, uint256 minted);
    event Withdrawn(address indexed receiver, uint256 assets, uint256 burned);

    function deposit() external payable {
        require(msg.value > 0, "zero amount");

        uint256 minted;
        if (totalShares == 0) {
            require(msg.value > 1000, "first deposit too small");
            // First deposit: seed a fixed dead-share amount. A sufficiently
            // large deposit can still own approximately all live shares.
            totalShares += DEAD_SHARES;
            shares[address(0)] += DEAD_SHARES;
            minted = msg.value;
        } else {
            minted = (msg.value * totalShares) / totalAssets;
            require(minted > 0, "zero shares");
        }

        totalShares += minted;
        totalAssets += msg.value;
        shares[msg.sender] += minted;

        emit Deposited(msg.sender, msg.value, minted);
    }

    /// @notice Donate ETH without receiving shares and increase `totalAssets`.
    /// @dev Outside `deposit()`, only `donate()` increases `totalAssets`.
    ///      Forced ETH (e.g. via selfdestruct) does not inflate the share price:
    ///      it is never counted in `totalAssets` and is permanently locked,
    ///      with no way for anyone to withdraw it. Plain transfers revert
    ///      because the pool has neither receive nor fallback.
    function donate() external payable {
        require(msg.value > 0, "zero amount");
        totalAssets += msg.value;
    }

    function withdraw(uint256 amount) external returns (uint256 out) {
        uint256 userShares = shares[msg.sender];
        require(userShares >= amount, "insufficient shares");

        out = (amount * totalAssets) / totalShares;
        require(out > 0, "zero assets");

        shares[msg.sender] = userShares - amount;
        totalShares -= amount;
        totalAssets -= out;

        (bool ok,) = msg.sender.call{value: out}("");
        require(ok, "transfer failed");

        emit Withdrawn(msg.sender, out, amount);
        return out;
    }
}
