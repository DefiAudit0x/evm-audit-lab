# Lab 14 — Unprotected UUPS Initializer Takeover

> ⚠️ The `VulnerableUupsVault.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** every asset the proxy custodies — the takeover ends in an arbitrary-logic upgrade.
- **Privileged actor:** the intended owner initializes the proxy first, but the vulnerable initializer allows anyone to overwrite that owner later.
- **Untrusted actor:** any caller able to reach the proxy.
- **Preconditions:** the proxy uses `VulnerableUupsVault`, whose initializer has no one-shot guard.

## Violated invariant

> "Privileged protocol state must be established exactly once, atomically with deployment, by the deployer."

The unguarded `initialize` can be called by anyone, any number of times. The bug is broader than a first-caller race: an attacker can overwrite a legitimate owner's address after initialization.

```solidity
function initialize(address owner_) external {   // no one-shot guard
    owner = owner_;                              // any caller can overwrite it
}

function upgradeToAndCall(address newImpl, bytes calldata data)
    external payable onlyOwner                   // owner is whoever initialized
{ /* EIP-1967 slot write + optional delegatecall */ }
```

## Attack anatomy (takeover after legitimate initialization)

```
deployer: new Erc1967Proxy(impl, initialize(deployer))
                                          -> proxy is legitimately initialized

attacker: proxy.initialize(attacker)     -> owner := attacker (overwritten)
attacker: proxy.upgradeToAndCall(
              evilImpl, drain(attacker)) -> arbitrary logic in proxy context
                                          -> proxy balance transferred to attacker
```

The executable regression test funds the proxy, performs these calls, and
asserts that the attacker receives the full balance.

## Remediation

`SafeUupsVault` makes the initializer one-shot behind an `initialized` flag,
locks the implementation's own storage in its constructor, and is deployed
through `Erc1967Proxy` with the initializer calldata supplied atomically in
the creation transaction — no window exists, not even a one-block one.

## Minimal reproduction

```bash
forge test --match-contract UupsTakeoverTest --match-test testVulnerableProxyCanBeTakenOverAndDrained -vvv
```

## Regression test

```bash
forge test --match-contract UupsTakeoverTest --match-test testSafeProxyInitializationIsAtomicAndLocked -vvv
```

Against the safe deployment both initialization attempts revert: the proxy is
already initialized and the implementation is locked. A non-owner's upgrade
to a UUID-compatible implementation reverts with `not owner`, leaving the
proxy's implementation slot and balance unchanged.

The UUID check verifies identity only: a target that returns the expected
UUID passes the check even with an incompatible storage layout, so layout
compatibility needs separate validation before any upgrade.

Companion report: [Audit-Reports/010 — Uninitialized UUPS Proxy Takeover](https://github.com/DefiAudit0x/Audit-Reports/blob/main/010-unprotected-uups-initializer.md).
