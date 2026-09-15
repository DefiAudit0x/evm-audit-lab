# Lab 12 — Unbounded Loop Denial of Service

> ⚠️ The `VulnerableSplitter.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** the splitter's entire revenue balance — frozen, not stolen.
- **Privileged actor:** none — `register()` and `distribute()` are both permissionless.
- **Untrusted actor:** any address able to register payees; a batch of 3,000 registrations costs a few dollars of gas.
- **Preconditions:** gas per payee times list length exceeds the block gas limit (~34k gas × ~1,200 payees at a 30M budget in this lab).

## Violated invariant

> "The gas cost of a user-triggered operation must not scale with state that untrusted parties can grow without bound."

`distribute()` walks the entire payee list in one transaction while anyone can append to it. Once the product crosses the block gas limit, the operation is not slow — it is impossible, for every caller, forever.

```solidity
function register() external payable {
    payees.push(msg.sender);        // permissionless — attacker-controlled length
    owed[msg.sender] += msg.value;
}

function distribute() external {
    uint256 n = payees.length;      // cost scales with global state
    for (uint256 i = 0; i < n; ++i) { /* ~34k gas per funded payee */ }
}
```

## Attack anatomy (pricing a payout out of the block)

```
attacker registers 3,000 payees with 1 wei each   -> list length ~3,001
honest payee holds a 1 ETH payout in the same splitter

anyone calls distribute() with the block gas budget -> reverts out-of-gas
repeat                                            -> still reverts, forever

there is no per-payee claim(), no sweep(), no removal path — funds frozen
```

## Remediation

`SafeSplitter` chunks distribution behind a persisted cursor: each call
processes at most `maxPayees` entries, so per-call gas is user-bounded and
independent of list size, and repeated calls walk the list to completion.
(Alternatives: pull payments per payee, or a hard cap on list size.)

## Minimal reproduction

```bash
forge test --match-contract LoopDoSTest --match-test testVulnerableDistributeBricksPastGasLimit -vvv
```

## Regression test

```bash
forge test --match-contract LoopDoSTest --match-test testSafeSplitterDrainsFullyThroughBoundedCalls -vvv
```

The identical list on `SafeSplitter` drains fully through bounded 250-payee
calls, and every registered payee — including the honest one — is paid
exactly once.

Companion report: [Audit-Reports/011 — Unbounded Loop Denial of Service](https://github.com/DefiAudit0x/Audit-Reports/blob/main/011-unbounded-loop-dos.md).
