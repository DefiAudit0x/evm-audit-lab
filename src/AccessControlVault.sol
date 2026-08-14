// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;



/// @notice Educational example: the first version trusts tx.origin for admin authorization.

/// Never deploy this contract. It intentionally models a phishing-prone authorization boundary.

contract VulnerableAccessControlVault {

    address public immutable owner;

    mapping(address => uint256) public balances;



    constructor() payable {

        owner = msg.sender;

    }



    function deposit() external payable {

        balances[msg.sender] += msg.value;

    }



    function emergencyWithdraw(address payable recipient) external {

        require(tx.origin == owner, "not owner");

        recipient.transfer(address(this).balance);

    }

}



/// @notice Remediation: authorization uses msg.sender and the recipient is constrained.

contract SafeAccessControlVault {

    address public immutable owner;

    mapping(address => uint256) public balances;



    constructor() payable {

        owner = msg.sender;

    }



    function deposit() external payable {

        balances[msg.sender] += msg.value;

    }



    function emergencyWithdraw(address payable recipient) external {

        require(msg.sender == owner, "not owner");

        require(recipient != address(0), "zero recipient");

        (bool ok, ) = recipient.call{value: address(this).balance}("");

        require(ok, "transfer failed");

    }

}

