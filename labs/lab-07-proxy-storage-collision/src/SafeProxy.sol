// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeProxy
/// @notice Lab 07 — Remediated: EIP-1967 dedicated storage slots.
/// @dev Implementation and admin addresses live at keccak256-derived
///      slots no sane storage layout can reach, so implementation state
///      and proxy administration can never collide.
///      Admin-only rescueETH recovers proxy-held ETH. The admin can already
///      upgrade to an arbitrary implementation, so rescue adds no new trust
///      assumption. The proxy's own functions take precedence over fallback
///      dispatch to the implementation.
///      This example has no initializer: a one-time `initializer`-guarded
///      `initialize` is an additional production requirement, not a fix
///      demonstrated here.
contract SafeProxy {
    event EthRescued(address indexed to, uint256 amount);

    /// @dev keccak256("eip1967.proxy.implementation") - 1.
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    /// @dev keccak256("eip1967.proxy.admin") - 1.
    bytes32 private constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    constructor(address implementation_) {
        require(implementation_.code.length > 0, "no code");
        _setSlot(IMPLEMENTATION_SLOT, implementation_);
        _setSlot(ADMIN_SLOT, msg.sender);
    }

    function admin() external view returns (address a) {
        a = _getSlot(ADMIN_SLOT);
    }

    function implementation() external view returns (address a) {
        a = _getSlot(IMPLEMENTATION_SLOT);
    }

    function upgradeTo(address implementation_) external {
        require(msg.sender == _getSlot(ADMIN_SLOT), "not admin");
        require(implementation_.code.length > 0, "no code");
        _setSlot(IMPLEMENTATION_SLOT, implementation_);
    }

    function rescueETH(address payable to, uint256 amount) external {
        require(msg.sender == _getSlot(ADMIN_SLOT), "not admin");
        require(to != address(0), "zero address");
        require(amount <= address(this).balance, "insufficient balance");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit EthRescued(to, amount);
    }

    function _getSlot(bytes32 slot) private view returns (address a) {
        assembly {
            a := sload(slot)
        }
    }

    function _setSlot(bytes32 slot, address value) private {
        assembly {
            sstore(slot, value)
        }
    }

    fallback() external payable {
        address impl = _getSlot(IMPLEMENTATION_SLOT);
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

/// @title SafeImplV1
/// @notice Initial implementation. `value` occupies slot 0 — harmless,
///         because the proxy no longer keeps anything there.
contract SafeImplV1 {
    uint256 public value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }
}

/// @title SafeImplV2
/// @notice Upgraded implementation. Appends a new variable; existing
///         slots keep their meaning (append-only storage layout).
contract SafeImplV2 {
    uint256 public value; // slot 0 — same meaning as V1
    uint256 public extra; // slot 1 — appended, never reordered

    function setValue(uint256 newValue) external {
        value = newValue;
    }

    function setExtra(uint256 newExtra) external {
        extra = newExtra;
    }
}
