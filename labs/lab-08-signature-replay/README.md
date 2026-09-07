# Lab 08 — Signature Replay

> ⚠️ The `VulnerableSignature.sol` contract is intentionally unsafe and must not be deployed. Run it only in a local Foundry test environment.

## Threat model

- **Asset at risk:** every wei held by the vault — payouts are authorized purely by an ECDSA signature.
- **Privileged actor:** the off-chain authority, the only key allowed to sign a payout.
- **Untrusted actor:** everyone else — including the recipient, whose signed payout is public the moment it enters the mempool or lands on-chain.

## Violated invariant

> "One signature authorizes exactly one payout."

A signature is *public knowledge*, not a bearer secret: it travels through the mempool where anyone can read it, and it stays visible forever in transaction history. The vulnerable contract authorizes a payout with a raw hash and never records what it has already paid:

```solidity
bytes32 message = keccak256(abi.encodePacked(recipient, amount));
address signer = ecrecover(message, v, r, s);
require(signer == authority, "invalid signature");
// ...no nonce, no deadline, no chain id, no contract address, no replay set
```

The message binds only `(recipient, amount)`. Nothing ties the signature to *this* chain, *this* contract, or *this* use, and nothing invalidates it after the first payment.

## Attack anatomy (single-signature vault drain)

```
authority signs payout(victim, 1 ETH)     -> signature (v, r, s) enters the mempool

attacker.withdraw(victim, 1 ETH, v, r, s) -> victim paid (the legitimate use)
attacker.withdraw(victim, 1 ETH, v, r, s) -> paid AGAIN — same signature
attacker.withdraw(victim, 1 ETH, v, r, s) -> paid AGAIN
...                                        -> vault balance: 0
```

One signature intended to pay 1 ETH paid out the entire 5 ETH reserve. Two
variants make it worse in the wild:

- **Cross-contract replay** — any *other* protocol that hashes the same
  `(recipient, amount)` layout accepts the identical signature.
- **Malleability** — flipping `(v, s)` to the other curve point yields a
  byte-different signature that recovers the *same* authority address,
  defeating naive "seen this exact signature before" dedup.

## Minimal reproduction

```bash
forge test --match-contract SignatureReplayTest --match-test testVulnerableSignatureSingleSigDrainsVault -vvv
```

## Impact

| Severity | Conditions | Outcome |
| --- | --- | --- |
| **Critical** | Value transfers authorized by ECDSA signatures that are not bound to a nonce/chain/contract, with no consumed-signature record | One observed signature drains the entire vault; the same signature may also drain any other contract reusing the message layout |

## Remediation

Several independent defenses; `SafeSignature.sol` implements all of them:

1. **EIP-712 typed structured messages** — the domain separator pins the
   digest to `(name, version, chainId, verifyingContract)`, so a signature
   cannot be replayed on another chain or another contract.
2. **Per-recipient nonces consumed before the transfer** — once nonce 0 is
   used, the signed digest no longer matches any recomputable digest. This
   is the single most important defense.
3. **Deadline on the signature** (`block.timestamp > deadline` reverts) —
   bounds the lifetime of any signature that leaks without being used.
4. **High-s malleability guard** — reject `s > secp256k1n / 2` so the
   flipped-curve forgery cannot even reach `ecrecover`.

### Additional defenses

- Prefer audited primitives: OpenZeppelin `ECDSA` + `MessageHashUtils`, or
  EIP-2612 / EIP-4337 `UserOperation` patterns that carry nonces natively.
- Return `address(0)` from a failed recover (`ecrecover`'s silent failure
  for malformed inputs) and revert explicitly — never treat `address(0)`
  as a valid signer.
- Fuzz the invariant: "no `(v, r, s)` pays twice" with `forge invariant`,
  reusing the same signature across blocks.

## Regression test

```bash
forge test --match-contract SignatureReplayTest -vvv
```

On `SafeSignature` the honest flow pays exactly once; the direct replay
reverts with `InvalidSignature`, the cross-contract reuse reverts because
the second vault's domain separator recomputes a different digest, the
expired deadline reverts with `SignatureExpired`, and the malleable
high-s forgery reverts with `MalleableSignature`.

## Related resources

- [SWC-121: Missing Protection against Signature Replay Attacks](https://swcregistry.io/docs/SWC-121)
- [SWC-117: Signature Malleability](https://swcregistry.io/docs/SWC-117)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [OpenZeppelin ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)
- [OpenZeppelin MessageHashUtils.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MessageHashUtils.sol)
