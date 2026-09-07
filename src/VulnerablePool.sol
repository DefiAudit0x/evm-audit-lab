// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerablePool
/// @notice Lab 05 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. Share minting uses floor division without any
///      inflation protection. An attacker who deposits first can inflate
///      `totalAssets` with a donation so the next depositor mints zero
///      shares, then redeem a single share for the entire pool balance.
contract VulnerablePool {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    event Deposited(address indexed depositor, uint256 assets, uint256 minted);
    event Withdrawn(address indexed receiver, uint256 assets, uint256 burned);

    /// @notice Deposit ETH and mint shares at the current floor-rounded rate.
    function deposit() external payable {
        require(msg.value > 0, "zero amount");

        // Vulnerability: floor rounding. When the pool price has been
        // inflated, `minted` truncates to 0 and the deposit is accepted
        // anyway — the depositor's ETH belongs to the pool forever.
        uint256 minted = totalShares == 0 ? msg.value : (msg.value * totalShares) / totalAssets;

        totalShares += minted;
        totalAssets += msg.value;
        shares[msg.sender] += minted;

        emit Deposited(msg.sender, msg.value, minted);
    }

    /// @notice Donate ETH without receiving shares — models any value
    ///         entering the pool outside `deposit` (donation, selfdestruct,
    ///         a misrouted transfer, ...).
    function donate() external payable {
        require(msg.value > 0, "zero amount");
        totalAssets += msg.value;
    }

    /// @notice Burn `amount` shares and receive the floor-rounded asset value.
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
