# Contributing

Each new lab should explain its threat model, violated invariant, vulnerable implementation, remediation, and regression test.

Run the following before opening a pull request:

```bash
forge fmt
forge test -vv
forge fmt --check
```

Keep vulnerable examples clearly labeled and never include real credentials, private client material, or instructions intended to attack production systems.
