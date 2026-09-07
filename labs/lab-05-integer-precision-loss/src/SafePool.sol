// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafePool
/// @notice Lab 05 — Remediated: first deposit mints dead shares, so share
///         price inflation can no longer be profitable.
/// @dev The vulnerable pool truncates `minted` to zero once the attacker
///      inflates `totalAssets`. Here the very first deposit mints
///      DEAD_SHARES to `address(0)`. An attacker who wants the next
///      depositor to mint zero shares must donate ~DEAD_SHARES times the
///      victim's deposit, and the donation itself is unrecoverable — the
///      attack becomes a guaranteed net loss.
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
            // First deposit: seed dead shares so no single depositor ever
            // owns ~100% of the share supply.
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
