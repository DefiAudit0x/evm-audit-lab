# Lab 14 — Unprotected UUPS Initializer Takeover

> ⚠️ The `VulnerableUupsVault.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** every asset the proxy custodies — the takeover ends in an arbitrary-logic upgrade.
- **Privileged actor:** nobody yet — that is the bug: `owner` is unset until `initialize` runs, and nothing restricts who runs it.
- **Untrusted actor:** anyone watching the mempool for the proxy-creation transaction, or scanning chain state for uninitialized proxies.
- **Preconditions:** a deployed-but-uninitialized proxy, or an initialization transaction that can be frontrun.

## Violated invariant

> "Privileged protocol state must be established exactly once, atomically with deployment, by the deployer."

The unguarded `initialize` can be called by anyone, any number of times — and because the implementation's constructor never locks its own storage, the raw implementation can be re-initialized too (the self-destruct variant can brick every proxy pointing at it).

```solidity
function initialize(address owner_) external {   // no one-shot guard
    owner = owner_;                              // first caller wins
}

function upgradeToAndCall(address newImpl, bytes calldata data)
    external payable onlyOwner                   // owner is whoever initialized
{ /* EIP-1967 slot write + optional delegatecall */ }
```

## Attack anatomy (three-transaction takeover)

```
deployer: new Erc1967Proxy(impl, "")     -> proxy exists, owner == address(0)
                                          (the two-step deployment mistake)

attacker: proxy.initialize(attacker)     -> owner := attacker
attacker: proxy.upgradeToAndCall(
              evilImpl, drain(attacker)) -> arbitrary logic in proxy context
                                          -> proxy balance: 0
```

Frontrunning completes the attack even when the deployer intends to
initialize promptly: the attacker's identical transaction with a higher tip
lands first.

## Remediation

`SafeUupsVault` makes the initializer one-shot behind an `initialized` flag,
locks the implementation's own storage in its constructor, and is deployed
through `Erc1967Proxy` with the initializer calldata supplied atomically in
the creation transaction — no window exists, not even a one-block one.

## Minimal reproduction

```bash
forge test --match-contract UupsTakeoverTest --match-test testUninitializedProxyIsTakenOverAndDrained -vvv
forge test --match-contract UupsTakeoverTest --match-test testVulnerableImplementationCanBeReinitialized -vvv
```

## Regression test

```bash
forge test --match-contract UupsTakeoverTest --match-test testSafeProxyInitializationIsAtomicAndLocked -vvv
```

Against the safe deployment both takeover attempts revert (proxy already
initialized; implementation locked), the upgrade attempt fails at the owner
gate, and the proxy's funds are untouched.

Companion report: [Audit-Reports/010 — Uninitialized UUPS Proxy Takeover](https://github.com/DefiAudit0x/Audit-Reports/blob/main/010-unprotected-uups-initializer.md).
