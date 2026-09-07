// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableAmm
/// @notice Lab 06 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. `swap()` executes at whatever price is live at the
///      moment of execution and accepts no slippage bound or deadline, so
///      any transaction can be sandwiched for profit.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableAmm {
    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;

    address public immutable tokenA;
    address public immutable tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

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

    /// @dev Constant-product output with a 0.3% fee.
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256 out) {
        uint256 inWithFee = amountIn * FEE_NUMERATOR;
        out = (inWithFee * reserveOut) / (reserveIn * FEE_DENOMINATOR + inWithFee);
    }

    /// @notice Vulnerability: no `minAmountOut`, no deadline. The caller
    ///         accepts whatever price is live when the transaction lands,
    ///         including a price an attacker just moved in the same block.
    function swap(uint256 amountIn, bool zeroForOne) external returns (uint256 out) {
        out = getAmountOut(amountIn, zeroForOne ? reserveA : reserveB, zeroForOne ? reserveB : reserveA);

        IERC20(zeroForOne ? tokenA : tokenB).transferFrom(msg.sender, address(this), amountIn);
        IERC20(zeroForOne ? tokenB : tokenA).transfer(msg.sender, out);

        if (zeroForOne) {
            reserveA += amountIn;
            reserveB -= out;
        } else {
            reserveB += amountIn;
            reserveA -= out;
        }
    }
}
