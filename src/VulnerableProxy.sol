// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableProxy
/// @notice Lab 07 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. The proxy stores `admin` and `implementation` in
///      regular storage slots 0 and 1 — the same slots the implementation
///      contract uses for its own state. Every state write performed
///      through the proxy clobbers proxy administration.
contract VulnerableProxy {
    // Vulnerability: slots 0 and 1 overlap with the implementation's
    // own storage layout. EIP-1967 moves these to dedicated keccak slots.
    address public admin; // slot 0
    address public implementation; // slot 1

    constructor(address implementation_) {
        admin = msg.sender;
        implementation = implementation_;
    }

    function upgradeTo(address implementation_) external {
        require(msg.sender == admin, "not admin");
        implementation = implementation_;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/// @title VulnerableImplV1
/// @notice Naive implementation whose `value` sits in slot 0.
/// @dev `value` and the proxy's `admin` are the SAME storage slot when
///      called through the proxy. `setValue` rewrites the admin.
contract VulnerableImplV1 {
    uint256 public value; // slot 0 — collides with VulnerableProxy.admin

    function setValue(uint256 newValue) external {
        value = newValue; // via delegatecall this overwrites proxy.admin
    }
}
