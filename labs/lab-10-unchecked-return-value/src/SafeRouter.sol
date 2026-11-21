// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./shared/IERC20.sol";

/// @title SafeRouter
/// @notice Lab 10 — Owner-managed, backed allocations with guarded claims
///         consumed before transfer; failed transfers roll back accounting.
/// @dev Assumes a trusted, exact-transfer, bool-returning token with honest
///      balance reporting. Fee-on-transfer and rebasing tokens are unsupported.
contract SafeRouter {
    IERC20 public immutable token;
    address public immutable owner;
    mapping(address => uint256) public claimable;
    mapping(address => uint256) public claimed;
    uint256 public totalClaimable;
    bool private entered;

    error TransferFailed();
    error NothingToClaim();
    error NotOwner();
    error InsufficientBacking();
    error ReentrantCall();

    event Claimed(address indexed claimant, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
        owner = msg.sender;
    }

    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    /// @notice Replace a user's allocation, bounded by the token reserve.
    function setClaimable(address who, uint256 amount) external nonReentrant {
        if (msg.sender != owner) revert NotOwner();
        uint256 next = totalClaimable - claimable[who] + amount;
        if (next > token.balanceOf(address(this))) revert InsufficientBacking();
        totalClaimable = next;
        claimable[who] = amount;
    }

    /// @notice Pay the caller's allocation, reverting all effects on failure.
    function claim() external nonReentrant {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingToClaim();

        delete claimable[msg.sender];
        totalClaimable -= amount;
        claimed[msg.sender] += amount;

        if (!token.transfer(msg.sender, amount)) revert TransferFailed();
        if (totalClaimable > token.balanceOf(address(this))) revert InsufficientBacking();

        emit Claimed(msg.sender, amount);
    }
}
