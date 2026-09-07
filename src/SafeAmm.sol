// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./VulnerableAmm.sol";

/// @title SafeAmm
/// @notice Lab 06 — Remediated: slippage bound + deadline enforced by the
///         protocol, so a sandwicher cannot both move the price and keep
///         the victim's transaction profitable for themselves.
/// @dev The victim's `minAmountOut` is checked against the price the
///      transaction actually executes at. A front-run that pushes the
///      price beyond the bound makes the victim's swap revert, and a
///      back-run against nobody pays the pool fee twice.
contract SafeAmm {
    error SlippageExceeded(uint256 requestedMin, uint256 actualOut);
    error Expired(uint256 deadline, uint256 blockTimestamp);

    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;

    address public immutable tokenA;
    address public immutable tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    event Swap(address indexed trader, bool zeroForOne, uint256 amountIn, uint256 amountOut);

    constructor(address tokenA_, address tokenB_) {
        tokenA = tokenA_;
        tokenB = tokenB_;
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external {
        IERC20(tokenA).transferFrom(msg.sender, address(this), amountA);
        IERC20(tokenB).transferFrom(msg.sender, address(this), amountB);
        reserveA += amountA;
        reserveB += amountB;
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256 out) {
        uint256 inWithFee = amountIn * FEE_NUMERATOR;
        out = (inWithFee * reserveOut) / (reserveIn * FEE_DENOMINATOR + inWithFee);
    }

    /// @notice Swap with an explicit slippage bound and time validity.
    /// @param minAmountOut Reverts if the executed price yields less.
    /// @param deadline Reverts if the transaction lands after it.
    function swap(uint256 amountIn, bool zeroForOne, uint256 minAmountOut, uint256 deadline)
        external
        returns (uint256 out)
    {
        if (block.timestamp > deadline) revert Expired(deadline, block.timestamp);

        out = getAmountOut(amountIn, zeroForOne ? reserveA : reserveB, zeroForOne ? reserveB : reserveA);
        if (out < minAmountOut) revert SlippageExceeded(minAmountOut, out);

        IERC20(zeroForOne ? tokenA : tokenB).transferFrom(msg.sender, address(this), amountIn);
        IERC20(zeroForOne ? tokenB : tokenA).transfer(msg.sender, out);

        if (zeroForOne) {
            reserveA += amountIn;
            reserveB -= out;
        } else {
            reserveB += amountIn;
            reserveA -= out;
        }

        emit Swap(msg.sender, zeroForOne, amountIn, out);
    }
}
