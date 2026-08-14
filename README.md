# EVM Audit Lab

Small, reproducible Solidity security laboratories by **DefiAudit**.

## Current lab

`Reentrancy.t.sol` demonstrates a withdrawal flow that sends Ether before updating accounting, then compares it with a checks-effects-interactions remediation.

The vulnerable contract is intentionally unsafe and must not be deployed. The example is educational; it is not a client audit and does not describe a production protocol.

## Run

This repository is designed for Foundry:

```bash
forge test -vv
forge fmt --check
```

## Structure

```text
src/VulnerableVault.sol   intentionally vulnerable example
src/SafeVault.sol         minimal remediation
 test/Reentrancy.t.sol     exploit and regression tests
```

## Method

Each lab should contain a threat model, violated invariant, minimal reproduction, remediation, and regression test. Tool output is treated as a lead for manual verification rather than a replacement for protocol reasoning.

## Responsible use

Use these examples only in local test environments. Do not deploy the vulnerable contracts or use them against systems you do not own or have permission to test.

## License

MIT
