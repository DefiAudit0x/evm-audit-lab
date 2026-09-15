// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeSplitter
/// @notice Lab 12 — Remediated: chunked distribution with a persisted cursor.
/// @dev Each call processes at most `maxPayees` entries, so per-call gas is
///      user-bounded and independent of list size. Repeated calls walk the
///      list to completion; nobody can price a payout round out of the block.
contract SafeSplitter {
    address[] public payees;
    mapping(address => uint256) public owed;
    uint256 public cursor;

    function register() external payable {
        if (owed[msg.sender] == 0) payees.push(msg.sender);
        owed[msg.sender] += msg.value;
    }

    function payeeCount() external view returns (uint256) {
        return payees.length;
    }

    /// @notice Processes at most `maxPayees` entries per call.
    /// @return done True when the cursor wrapped back to the list start.
    function distribute(uint256 maxPayees) external returns (bool done) {
        uint256 n = payees.length;
        if (n == 0) return true;
        uint256 processed = 0;
        while (processed < maxPayees) {
            address p = payees[cursor];
            uint256 amount = owed[p];
            if (amount != 0) {
                owed[p] = 0;
                (bool ok,) = p.call{value: amount}("");
                require(ok, "transfer failed");
            }
            cursor = (cursor + 1) % n;
            ++processed;
            if (cursor == 0) return true;
        }
        return false;
    }

    receive() external payable {}
}
