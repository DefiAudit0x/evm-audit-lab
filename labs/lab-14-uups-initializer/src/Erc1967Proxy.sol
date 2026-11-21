// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Erc1967Proxy
/// @notice Lab 14 helper — minimal ERC-1967 proxy for the UUPS labs.
/// @dev Implementation address lives at the EIP-1967 slot. `initData` runs
///      atomically inside the creation transaction and must be nonempty.
contract Erc1967Proxy {
    /// @dev keccak256("eip1967.proxy.implementation") - 1.
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl, bytes memory initData) payable {
        require(impl.code.length > 0, "no code");
        require(initData.length > 0, "empty init data");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl)
        }
        (bool ok, bytes memory result) = impl.delegatecall(initData);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    fallback() external payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly {
            impl := sload(slot)
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
