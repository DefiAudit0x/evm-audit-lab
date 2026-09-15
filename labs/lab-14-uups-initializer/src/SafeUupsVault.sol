// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeUupsVault
/// @notice Lab 14 — Remediated: one-shot initializer + implementation lock.
/// @dev `initialize` is guarded by an explicit `initialized` flag, and the
///      constructor sets it on the implementation itself so nobody can ever
///      initialize the raw implementation's storage. Combined with an atomic
///      deploy-plus-initialize proxy constructor call, no takeover window
///      exists — not even a one-block one.
contract SafeUupsVault {
    /// @dev keccak256("eip1967.proxy.implementation") - 1.
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public owner;
    bool public initialized;

    constructor() {
        initialized = true; // lock the implementation's own storage forever
    }

    function initialize(address owner_) external {
        require(!initialized, "already initialized");
        initialized = true;
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function upgradeToAndCall(address newImpl, bytes calldata data) external payable onlyOwner {
        require(newImpl.code.length > 0, "no code");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
        if (data.length > 0) {
            (bool ok,) = newImpl.delegatecall(data);
            require(ok, "call failed");
        }
    }

    function withdraw(address to, uint256 amount) external onlyOwner {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
