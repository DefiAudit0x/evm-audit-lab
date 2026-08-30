# Lab 01 — Reentrancy

> ⚠️ The `VulnerableVault.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** ETH held by the vault contract.
- **Privileged actor:** none — any depositor can also be an attacker.
- **Untrusted actor:** any contract that receives ETH via `withdraw()`.

## Violated invariant

> "A caller can withdraw at most the amount they have deposited."

The vulnerable `withdraw()` sends ETH to `msg.sender` BEFORE decrementing `balances[msg.sender]`. If `msg.sender` is a contract, its `receive()` hook is triggered with the ETH transfer — and that hook can call `withdraw()` again. The second call still sees the original (undebited) balance, so it passes the `require` check and sends another round of ETH.

## Attack diagram

```
victim.deposit(1 ETH)        attacker.deposit(1 ETH)
       │                              │
       └──────── vault.balance = 2 ETH ────────┘

attacker.attack(1 ETH)
       │
       ▼
vault.withdraw(1 ETH)
       │
       ├─ require(balances[attacker] >= 1)  ✅
       ├─ msg.sender.call{value: 1 ETH}()   ──── attacker.receive() triggered
       │                                              │
       │                                              └─ vault.withdraw(1 ETH) again
       │                                                    │
       │                                                    ├─ require(balances[attacker] >= 1) ✅ (not yet debited!)
       │                                                    └─ msg.sender.call{value: 1 ETH}()
       │
       └─ balances[attacker] = 0             (zeroed once, after both sends)
```

Result: attacker drains 2 ETH from a 2 ETH vault with a single 1 ETH deposit.

## Minimal reproduction

```bash
forge test --match-contract ReentrancyTest --match-test testVulnerableVaultCanBeReentered -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Any contract that holds user funds and uses `msg.sender.call{value:}()` before updating accounting | Total drain of contract balance |

## Remediation

Apply **checks-effects-interactions**:

1. **Checks** — validate preconditions (`require(balances[msg.sender] >= amount)`).
2. **Effects** — update state (`balances[msg.sender] -= amount`).
3. **Interactions** — perform the external call last (`msg.sender.call{value:}()`).

See `SafeVault.sol`. The second `withdraw()` call from the attacker's `receive()` now fails the balance check because accounting is already updated.

### Additional defenses

- **ReentrancyGuard** (OpenZeppelin) — `nonReentrant` modifier that reverts on re-entry.
- **Pull over push** — instead of pushing ETH to the receiver, let them pull it via a separate `claim()` function.
- **CEI invariants via fuzz testing** — use `forge invariant` to confirm the accounting invariant holds under arbitrary call sequences.

## Regression test

```bash
forge test --match-contract ReentrancyTest --match-test testSafeVaultRejectsReentry -vvv
```

The same exploit against `SafeVault` must revert (insufficient balance on re-entry).

## Related resources

- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [Solidity docs — Checks-Effects-Interactions](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- [OpenZeppelin ReentrancyGuard](https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard)
- [Rekt News — The DAO hack (2016)](https://rekt.news/the-dao-hack/)
