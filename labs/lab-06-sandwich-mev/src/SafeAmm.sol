// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./shared/IERC20.sol";

/// @title SafeAmm
/// @notice Lab 06 — enforces caller-specified minimum output and deadlines.
/// @dev These bounds can reject execution below the caller's minimum; they do
///      not prevent every profitable sandwich. This educational AMM accepts
///      optional-return ERC-20s with exact, non-rebasing balance changes only.
contract SafeAmm {
    error SlippageExceeded(uint256 requestedMin, uint256 actualOut);
    error Expired(uint256 deadline, uint256 blockTimestamp);
    error InvalidTokenPair();
    error InvalidAmount();
    error InsufficientLiquidity();
    error TransferFailed();
    error FeeOnTransferUnsupported();
    error ReserveOverflow();
    error Reentrancy();

    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;
    uint256 private constant _MAX_RESERVE = type(uint112).max;

    address public immutable tokenA;
    address public immutable tokenB;
    uint112 public reserveA;
    uint112 public reserveB;
    uint256 private _lock = 1;

    event Swap(address indexed trader, bool zeroForOne, uint256 amountIn, uint256 amountOut);

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(address tokenA_, address tokenB_) {
        if (tokenA_ == tokenB_ || tokenA_.code.length == 0 || tokenB_.code.length == 0) {
            revert InvalidTokenPair();
        }
        tokenA = tokenA_;
        tokenB = tokenB_;
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount();

        uint256 nextA = uint256(reserveA) + amountA;
        uint256 nextB = uint256(reserveB) + amountB;
        if (nextA > _MAX_RESERVE || nextB > _MAX_RESERVE) revert ReserveOverflow();

        uint256 beforeA = _balanceOf(tokenA, address(this));
        uint256 beforeB = _balanceOf(tokenB, address(this));

        // Effects precede token calls. The lock prevents callback-driven state
        // changes while the transfers are in progress.
        reserveA = uint112(nextA);
        reserveB = uint112(nextB);

        _safeTransferFrom(tokenA, msg.sender, address(this), amountA);
        _requireExactIncrease(tokenA, beforeA, amountA);
        _safeTransferFrom(tokenB, msg.sender, address(this), amountB);
        _requireExactIncrease(tokenB, beforeB, amountB);
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256 out) {
        if (amountIn == 0 || reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();
        if (amountIn > _MAX_RESERVE || reserveIn > _MAX_RESERVE || reserveOut > _MAX_RESERVE) {
            revert ReserveOverflow();
        }

        uint256 inWithFee = amountIn * FEE_NUMERATOR;
        out = (inWithFee * reserveOut) / (reserveIn * FEE_DENOMINATOR + inWithFee);
    }

    /// @notice Swap with an explicit minimum output and deadline.
    /// @param minAmountOut Reverts if execution yields less than this amount.
    /// @param deadline Reverts if the transaction lands after this timestamp.
    function swap(uint256 amountIn, bool zeroForOne, uint256 minAmountOut, uint256 deadline)
        external
        nonReentrant
        returns (uint256 out)
    {
        if (block.timestamp > deadline) revert Expired(deadline, block.timestamp);
        if (amountIn == 0) revert InvalidAmount();

        address input = zeroForOne ? tokenA : tokenB;
        address output = zeroForOne ? tokenB : tokenA;
        {
            uint112 oldReserveIn = zeroForOne ? reserveA : reserveB;
            uint112 oldReserveOut = zeroForOne ? reserveB : reserveA;
            out = getAmountOut(amountIn, oldReserveIn, oldReserveOut);
            if (out == 0) revert InsufficientLiquidity();
            if (out < minAmountOut) revert SlippageExceeded(minAmountOut, out);

            uint256 nextReserveIn = uint256(oldReserveIn) + amountIn;
            if (nextReserveIn > _MAX_RESERVE) revert ReserveOverflow();
            uint112 nextReserveOut = oldReserveOut - uint112(out);

            // Store the price effects before either external token interaction.
            if (zeroForOne) {
                reserveA = uint112(nextReserveIn);
                reserveB = nextReserveOut;
            } else {
                reserveB = uint112(nextReserveIn);
                reserveA = nextReserveOut;
            }
        }

        _executeSwap(input, output, amountIn, out);

        emit Swap(msg.sender, zeroForOne, amountIn, out);
    }

    function _executeSwap(address input, address output, uint256 amountIn, uint256 amountOut) private {
        uint256 inputBefore = _balanceOf(input, address(this));
        uint256 outputBefore = _balanceOf(output, address(this));
        uint256 recipientBefore = _balanceOf(output, msg.sender);

        _safeTransferFrom(input, msg.sender, address(this), amountIn);
        _requireExactIncrease(input, inputBefore, amountIn);

        _safeTransfer(output, msg.sender, amountOut);
        uint256 outputAfter = _balanceOf(output, address(this));
        uint256 recipientAfter = _balanceOf(output, msg.sender);
        if (outputBefore < outputAfter || outputBefore - outputAfter != amountOut) {
            revert FeeOnTransferUnsupported();
        }
        if (recipientAfter < recipientBefore || recipientAfter - recipientBefore != amountOut) {
            revert FeeOnTransferUnsupported();
        }
    }

    function _requireExactIncrease(address token, uint256 beforeBalance, uint256 amount) private view {
        uint256 afterBalance = _balanceOf(token, address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) {
            revert FeeOnTransferUnsupported();
        }
    }

    function _balanceOf(address token, address account) private view returns (uint256 balance) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeCall(IERC20.balanceOf, (account)));
        if (!success || data.length < 32) revert TransferFailed();
        balance = abi.decode(data, (uint256));
    }

    function _safeTransfer(address token, address to, uint256 amount) private {
        _callOptionalReturn(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) private {
        _callOptionalReturn(token, abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
    }

    function _callOptionalReturn(address token, bytes memory callData) private {
        (bool success, bytes memory returnData) = token.call(callData);
        if (!success) revert TransferFailed();
        if (returnData.length != 0 && (returnData.length < 32 || !abi.decode(returnData, (bool)))) {
            revert TransferFailed();
        }
    }
}
