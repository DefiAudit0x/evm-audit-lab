// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableSplitter
/// @notice Lab 12 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. `distribute()` walks the entire payee list in one
///      transaction and anyone can append payees, so the gas cost of a payout
///      round is attacker-controlled. Once `payees.length` passes the block
///      gas limit divided by the per-payee cost, `distribute()` reverts
///      out-of-gas for everyone, forever — revenue is frozen with no
///      alternative exit path.
contract VulnerableSplitter {
    address[] public payees;
    mapping(address => uint256) public owed;

    /// @notice Permissionless registration — each registration funds a payout.
    function register() external payable {
        payees.push(msg.sender);
        owed[msg.sender] += msg.value;
    }

    function payeeCount() external view returns (uint256) {
        return payees.length;
    }

    /// @notice Vulnerability: cost scales with global, unbounded state.
    function distribute() external {
        uint256 n = payees.length;
        for (uint256 i = 0; i < n; ++i) {
            address p = payees[i];
            uint256 amount = owed[p];
            if (amount == 0) continue;
            owed[p] = 0;
            (bool ok,) = p.call{value: amount}("");
            require(ok, "transfer failed");
        }
    }

    receive() external payable {}
}
