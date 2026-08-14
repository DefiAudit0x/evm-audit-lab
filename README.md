# EVM Audit Lab



Small, reproducible Solidity security laboratories by **DefiAudit**.



## Current lab



`test/Reentrancy.t.sol` demonstrates a withdrawal flow that sends Ether before updating accounting, then compares it with a checks-effects-interactions remediation.



The vulnerable contract is intentionally unsafe and must not be deployed. The example is educational; it is not a client audit and does not describe a production protocol.



## Run



This repository is designed for Foundry:



```bash

forge test -vv

forge fmt --check

```



The same checks run automatically in GitHub Actions through `.github/workflows/test.yml`.



## Structure



The repository follows the standard Foundry layout defined in `foundry.toml`:



```text

.

├── src/

│   ├── VulnerableVault.sol   # intentionally vulnerable example

│   └── SafeVault.sol         # checks-effects-interactions remediation

├── test/

│   └── Reentrancy.t.sol      # exploit and regression tests

├── .github/workflows/

│   └── test.yml              # Foundry test and formatting checks

└── foundry.toml              # project configuration

```



There are no active Solidity sources at the repository root; contract sources belong in `src/` and tests belong in `test/`.



## Method



Each lab should contain a threat model, violated invariant, minimal reproduction, remediation, and regression test. Tool output is treated as a lead for manual verification rather than a replacement for protocol reasoning.



## Responsible use



Use these examples only in local test environments. Do not deploy the vulnerable contracts or use them against systems you do not own or have permission to test.



## License



MIT

