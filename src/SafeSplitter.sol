// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeSplitter
/// @notice Lab 12 — Remediates recipient-blocked payouts with pull payments.
/// @dev Batches only account for ETH; each payee claims independently. This
///      assumes payees can receive ETH within 30,000 gas or use withdrawTo.
contract SafeSplitter {
    address[] public payees;
    mapping(address => uint256) public pending;
    mapping(address => uint256) public owed;
    mapping(address => bool) private registered;
    uint256 public cursor;
    uint256 public totalPending;
    uint256 public totalOwed;

    uint256 public constant MAX_BATCH = 256;
    uint256 public constant PAYOUT_GAS = 30_000;

    event Registered(address indexed payee, uint256 amount);
    event Distributed(address indexed payee, uint256 amount);
    event Paid(address indexed payee, address indexed recipient, uint256 amount);

    function register() external payable {
        require(msg.value > 0, "zero amount");

        if (!registered[msg.sender]) {
            registered[msg.sender] = true;
            payees.push(msg.sender);
        }

        pending[msg.sender] += msg.value;
        totalPending += msg.value;
        emit Registered(msg.sender, msg.value);
    }

    function payeeCount() external view returns (uint256) {
        return payees.length;
    }

    /// @notice Credits pending deposits without calling any payee.
    /// @return done True when this traversal has processed every registered payee.
    function distribute(uint256 maxPayees) external returns (bool done) {
        require(maxPayees > 0 && maxPayees <= MAX_BATCH, "invalid batch");

        uint256 n = payees.length;
        if (n == 0) return true;

        uint256 remaining = n - cursor;
        uint256 count = maxPayees < remaining ? maxPayees : remaining;
        for (uint256 i; i < count; ++i) {
            address payee = payees[cursor];
            ++cursor;

            uint256 amount = pending[payee];
            if (amount == 0) continue;

            pending[payee] = 0;
            totalPending -= amount;
            owed[payee] += amount;
            totalOwed += amount;
            emit Distributed(payee, amount);
        }

        done = cursor == n;
        if (done) cursor = 0;
    }

    /// @notice Claims the caller's full distributed balance.
    function claim() external {
        _withdraw(msg.sender, payable(msg.sender));
    }

    /// @notice Redirects the caller's full distributed balance to a recipient.
    function withdrawTo(address payable recipient) external {
        require(recipient != address(0) && recipient != address(this), "invalid recipient");
        _withdraw(msg.sender, recipient);
    }

    function _withdraw(address payee, address payable recipient) private {
        uint256 amount = owed[payee];
        require(amount > 0, "nothing owed");

        owed[payee] = 0;
        totalOwed -= amount;

        (bool ok,) = recipient.call{value: amount, gas: PAYOUT_GAS}("");
        require(ok, "transfer failed");
        emit Paid(payee, recipient, amount);
    }

    receive() external payable {}
}
