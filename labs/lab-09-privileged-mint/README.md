# Lab 09 — Privileged Mint

> ⚠️ The `VulnerableMint.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** the entire ETH reserve backing the token, plus the value of every honest holder's balance (dilution).
- **Privileged actor:** the admin, who in a correct design is the only party allowed to create supply.
- **Untrusted actor:** any address — the mint entry point is callable by everyone.

## Violated invariant

> "Only privileged addresses can create supply."

The vulnerable contract *declares* authorization but never *enforces* it. `admin` is stored and exposed as state, yet no check ever reads it on the mint path:

```solidity
address public admin;               // tracked ...
function mint(address to, uint256 amount) external {
    // ...but never checked! No require, no modifier, no error.
    totalSupply += amount;
    balanceOf[to] += amount;
}
```

Because the token is fully backed 1:1 by ETH and `redeem` pays out that backing, the unguarded `mint` is a direct claim on the contract's entire balance. Authorization that is recorded but not enforced is equivalent to no authorization at all.

## Attack anatomy (free mint, instant drain)

```
contract holds 5 ETH reserve, totalSupply = 0

attacker.mint(attacker, 5 tokens)   -> totalSupply = 5, no access check
attacker.redeem(5 tokens)           -> 5 ETH leaves the reserve to the attacker

contract balance: 0                 -> honest holders now hold unbacked claims
```

The same shape appears everywhere in production: mint gates on wrapped
assets, staking receipts, bridge tokens, and reward shares. Whenever the
mint function is the only bridge between "nothing" and "redeemable value",
a missing access check converts the protocol's whole backing into a public
faucet.

## Minimal reproduction

```bash
forge test --match-contract PrivilegedMintTest --match-test testVulnerableMintAnyoneMintsAndDrainsReserve -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Token or share supply can be minted by an entry point without an enforced authorization check, and the supply is redeemable for protocol assets | 100% of the backing reserve is extractable by any address; every existing holder is diluted to unbacked claims |

## Remediation

Several independent defenses; `SafeMint.sol` implements the first two:

1. **Explicit, enforced role** — `mint` reverts with `NotMinter` unless the
   caller was granted the role by the admin via `setMinter`. The capability
   is the role mapping, not a convention.
2. **Hard supply cap** (`maxSupply`) — even a compromised or malicious
   legitimate minter cannot create more than the cap, bounding worst-case
   damage instead of trusting key hygiene forever.
3. **Checks-effects-interactions in `redeem`** — state is updated before
   the ETH transfer, so a reentrant redemption sees consistent balances.
4. **Custom errors** (`NotAdmin`, `NotMinter`, `CapExceeded`) — cheaper
   than strings and precise enough to assert on in tests.

### Additional defenses

- Use OpenZeppelin `AccessControl` when roles multiply: per-role
  `grantRole`/`revokeRole` with an admin hierarchy beats hand-rolled
  `if (msg.sender != admin)` chains.
- Add a `pause` switch for the mint path so a compromised key can be
  contained without redeploying.
- Fuzz the invariant: "totalSupply can never exceed minted-by-authorized
  events" — any excess supply is a broken access control.

## Regression test

```bash
forge test --match-contract PrivilegedMintTest -vvv
```

On `SafeMint` an unauthorized mint reverts with `NotMinter`, the attacker
cannot self-grant the role (`NotAdmin`), minting past the cap reverts with
`CapExceeded`, and the honest mint → redeem flow pays exactly 1:1 against
the reserve.

## Related resources

- [SWC-106: Unprotected Function](https://swcregistry.io/docs/SWC-106)
- [OpenZeppelin AccessControl.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol)
- [OpenZeppelin ERC20::_mint guidance](https://docs.openzeppelin.com/contracts/5.x/erc20)
- [SWC-115: Authorization through tx.origin](https://swcregistry.io/docs/SWC-115) — see Lab 02 for the tx.origin variant of broken authorization
