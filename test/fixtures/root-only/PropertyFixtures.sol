// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeSplitter} from "../../../src/SafeSplitter.sol";

contract PropertyToken {
    mapping(address => uint256) public balanceOf;
    bool public rejectTransfer;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setRejectTransfer(bool reject) external {
        rejectTransfer = reject;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (rejectTransfer) return false;
        _move(msg.sender, to, amount);
        return true;
    }

    // Test-only fixture. Actors are driven by Foundry and no allowance model is needed.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract RejectingPayee {
    function register(SafeSplitter splitter) external payable {
        splitter.register{value: msg.value}();
    }

    function claim(SafeSplitter splitter) external {
        splitter.claim();
    }

    function redirect(SafeSplitter splitter, address payable recipient) external {
        splitter.withdrawTo(recipient);
    }

    receive() external payable {
        revert("ETH rejected");
    }
}
