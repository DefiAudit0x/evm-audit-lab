// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice ERC-20 fixture that can attempt one configured callback during a
///         transfer or transferFrom operation.
contract HookToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public callbackTarget;
    bytes public callbackData;
    bool public callbackOnTransfer;
    bool public callbackOnTransferFrom;
    bool public callbackAttempted;
    bool public lastCallbackSucceeded;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function approveFromSelf(address spender, uint256 amount) external {
        allowance[address(this)][spender] = amount;
    }

    function configureCallback(address target, bytes calldata data, bool onTransfer, bool onTransferFrom) external {
        callbackTarget = target;
        callbackData = data;
        callbackOnTransfer = onTransfer;
        callbackOnTransferFrom = onTransferFrom;
        callbackAttempted = false;
        lastCallbackSucceeded = false;
    }

    function depositOnVault(address vault, uint256 amount) external {
        allowance[address(this)][vault] = amount;
        (bool success, bytes memory result) = vault.call(abi.encodeWithSignature("deposit(uint256)", amount));
        if (!success) _bubbleRevert(result);
    }

    function withdrawFromVault(address vault, uint256 amount) external {
        (bool success, bytes memory result) = vault.call(abi.encodeWithSignature("withdraw(uint256)", amount));
        if (!success) _bubbleRevert(result);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        if (callbackOnTransfer) _callback();
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        if (callbackOnTransferFrom) _callback();
        return true;
    }

    function _callback() private {
        address target = callbackTarget;
        bytes memory data = callbackData;
        callbackOnTransfer = false;
        callbackOnTransferFrom = false;
        callbackTarget = address(0);
        callbackData = "";
        callbackAttempted = true;
        (lastCallbackSucceeded,) = target.call(data);
    }

    function _bubbleRevert(bytes memory result) private pure {
        assembly ("memory-safe") {
            revert(add(result, 32), mload(result))
        }
    }
}
