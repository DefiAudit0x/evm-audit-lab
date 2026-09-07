# Lab 07 — Upgradeable Proxy Storage Collision

> ⚠️ The `VulnerableProxy.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** control of the proxy (upgrade authority) and every variable whose slot overlaps proxy metadata.
- **Privileged actor:** the proxy admin — whose slot the implementation can silently overwrite.
- **Untrusted actor:** anyone able to call state-changing functions through the proxy (i.e., everyone).

## Violated invariant

> "Only the deployer-admin can change the implementation."

`VulnerableProxy` keeps `admin` in slot 0 and `implementation` in slot 1 —
regular storage slots. Storage is **shared** between the proxy and the
implementation it `delegatecall`s to: the implementation's first state
variable is *also* slot 0. The two layouts collide.

## Attack anatomy

```
proxy storage          impl storage ( VulnerableImplV1 )
slot 0: admin     <->  slot 0: value        <- SAME SLOT
slot 1: impl      <->  slot 1: (unused)

admin calls proxy.setValue(1)
  -> delegatecall executes V1 code against PROXY storage
  -> slot 0 = 1
  -> proxy.admin() == address(1)     <- admin silently replaced

proxy.upgradeTo(x) require(msg.sender == admin)
  -> reverts for everyone            <- upgradeability bricked
```

No special call is needed: a *seemingly harmless* setter executed through
the proxy corrupts proxy administration. The same primitive can overwrite
the implementation pointer (slot 1) if the implementation declares two
variables — turning any state write into arbitrary logic deployment.

## Minimal reproduction

```bash
forge test --match-contract ProxyCollisionTest --match-test testVulnerableProxyAdminIsClobbered -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Proxy metadata in slots the implementation's layout can reach | Admin replaced, upgrade path bricked, or implementation hijacked |

## Remediation

`SafeProxy.sol` implements the canonical fixes:

1. **EIP-1967 dedicated slots** — store the implementation, admin, and
   beacon at `keccak256(...)-1` slots that no realistic storage layout can
   reach. Proxies that follow EIP-1967 are tool-verifiable (`cast
   storage`, EIP-1967 inspection tools).
2. **Append-only implementation storage** — upgraded implementations
   (`SafeImplV2`) may add variables at the end but must never reorder or
   reuse slots from earlier versions.
3. **Initializers, not constructors** — implementation logic deployed
   behind a proxy cannot rely on `constructor` state; use an
   `initializer`-guarded function called once.

### Additional defenses

- Use audited, battle-tested proxy contracts (OpenZeppelin
  `ERC1967Proxy` / `TransparentUpgradeableProxy` / UUPS `UUPSUpgradeable`)
  instead of hand-rolled ones.
- Run `forge inspect <Impl> storage-layout` in CI and fail if an upgrade
  shifts existing slots (OpenZeppelin's layout-compatibility checker).
- Namespace storage (ERC-7201) for modular upgradeable systems.

## Regression test

```bash
forge test --match-contract ProxyCollisionTest --match-test testSafeProxyKeepsAdminSeparate -vvv
```

`setValue(42)` executed through `SafeProxy` leaves `admin()` intact, the
upgrade succeeds, and `SafeImplV2` preserves `value` while appending
`extra`.

## Related resources

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [SWC-112: Delegatecall to Untrusted Callee](https://swcregistry.io/docs/SWC-112)
- [OpenZeppelin Proxies](https://docs.openzeppelin.com/contracts/5.x/proxies)
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
