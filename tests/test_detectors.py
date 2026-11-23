import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from audit.detectors.access_control import detect_source
from audit.detectors.oracle import detect_source as detect_oracle_source
from audit.detectors.storage_collision import detect_source as detect_storage_collision_source

from audit.detectors import precision, proxy_upgrade, reentrancy
from audit.detectors.solidity import contract_blocks
from audit.detectors.storage_collision import EIP1967_ADMIN, EIP1967_IMPLEMENTATION, _dedicated_slot_status, _resolved_storage_layout


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, "-B", "-m", "audit.detectors", "--root", str(ROOT)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        cls.findings = {
            (item["detector"], item["file"], item["contract"])
            for item in json.loads(result.stdout)["findings"]
        }

    def test_reentrancy_flags_vulnerable_vault(self):
        self.assertIn(("reentrancy", "src/VulnerableVault.sol", "VulnerableVault"), self.findings)

    def test_reentrancy_ignores_safe_vault(self):
        self.assertNotIn(("reentrancy", "src/SafeVault.sol", "SafeVault"), self.findings)

    def test_reentrancy_body_identifier_does_not_suppress(self):
        source = """
        contract Vault {
            mapping(address => uint256) balances;
            function withdraw() external {
                bool nonReentrantEnabled = false;
                (bool ok,) = msg.sender.call("");
                require(ok);
                balances[msg.sender] = 0;
            }
        }
        """
        findings = reentrancy.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].contract, "Vault")

    def test_reentrancy_delete_state_balance_flags(self):
        source = """
        contract Vault {
            mapping(address => uint256) balances;
            function withdraw() external {
                (bool ok,) = msg.sender.call("");
                require(ok);
                delete balances[msg.sender];
            }
        }
        """
        findings = reentrancy.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].contract, "Vault")

    def test_reentrancy_shadow_assignment_only_ignored(self):
        for parameters, declaration in (
            ("uint256 balance", ""),
            ("address payable recipient, uint256 balance", ""),
            ("", "uint256 balance = 1;"),
        ):
            with self.subTest(parameters=parameters, declaration=declaration):
                source = f"""
                contract Vault {{
                    uint256 balance;
                    function withdraw({parameters}) external {{
                        {declaration}
                        (bool ok,) = msg.sender.call("");
                        require(ok);
                        balance = 0;
                    }}
                }}
                """
                self.assertEqual(
                    reentrancy.detect_source(ROOT, Path("src/Synthetic.sol"), source), []
                )

    def test_reentrancy_header_modifier_suppresses(self):
        source = """
        contract Vault {
            mapping(address => uint256) balances;
            modifier nonReentrant() { _; }
            function withdraw() external nonReentrant {
                (bool ok,) = msg.sender.call("");
                require(ok);
                balances[msg.sender] = 0;
            }
        }
        """
        self.assertEqual(reentrancy.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_reentrancy_storage_parameter_write_still_flags(self):
        # A storage reference is state, not a copy: writes through it stay
        # eligible. A memory parameter of the same name is a copy, so writes
        # through it are still correctly discarded.
        for location, expected in (("storage", 1), ("memory", 0)):
            with self.subTest(location=location):
                source = f"""
                contract Vault {{
                    uint256[] balances;
                    function withdraw(uint256[] {location} balances) external {{
                        (bool ok,) = msg.sender.call("");
                        require(ok);
                        balances[0] = 0;
                    }}
                }}
                """
                self.assertEqual(
                    len(reentrancy.detect_source(ROOT, Path("src/Synthetic.sol"), source)),
                    expected,
                )

    def test_storage_collision_flags_vulnerable_proxy(self):
        self.assertIn(("storage_collision", "src/VulnerableProxy.sol", "VulnerableProxy"), self.findings)

    def test_storage_collision_ignores_safe_proxy(self):
        self.assertNotIn(("storage_collision", "src/SafeProxy.sol", "SafeProxy"), self.findings)

    def test_storage_collision_control_slots_match_identity_and_are_distinct(self):
        for implementation, admin, status in (
            (EIP1967_IMPLEMENTATION, EIP1967_IMPLEMENTATION, "invalid"),
            (EIP1967_ADMIN, EIP1967_IMPLEMENTATION, "invalid"),
            (EIP1967_IMPLEMENTATION, EIP1967_ADMIN, "valid"),
        ):
            with self.subTest(implementation=implementation, admin=admin):
                source = f"""
                contract SyntheticProxy {{
                    bytes32 constant IMPLEMENTATION_SLOT = 0x{implementation};
                    bytes32 constant ADMIN_SLOT = 0x{admin};
                    fallback() external {{
                        assembly {{
                            let impl := sload(IMPLEMENTATION_SLOT)
                            let result := delegatecall(gas(), impl, 0, 0, 0, 0)
                        }}
                    }}
                }}
                """
                path = Path("src/SyntheticProxy.sol")
                contract = next(contract_blocks(path, source))
                self.assertEqual(_dedicated_slot_status(contract), status)
                findings = detect_storage_collision_source(ROOT, path, source)
                self.assertEqual(
                    [finding.title for finding in findings],
                    ["Proxy control slot does not match the EIP-1967 slot"] if status == "invalid" else [],
                )

    def test_storage_collision_ignores_append_only_upgrade(self):
        self.assertNotIn(("storage_collision", "src/SafeProxy.sol", "SafeImplV2"), self.findings)

    def test_storage_collision_nested_struct_reorder_flags(self):
        source = """
        contract NestedV1 {
            struct Inner { uint128 amount; address owner; }
            struct Outer { uint256 count; Inner inner; }
            Outer state;
            uint128 tail;
        }
        contract NestedV2 {
            struct Inner { address owner; uint128 amount; }
            struct Outer { uint256 count; Inner inner; }
            Outer state;
            uint128 tail;
        }
        """
        findings = detect_storage_collision_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual([finding.contract for finding in findings], ["NestedV2"])

    def test_storage_collision_pure_rename_ignored(self):
        source = """
        contract RenamedV1 { uint256 amount; }
        contract RenamedV2 { uint256 balance; }
        """
        self.assertEqual(
            detect_storage_collision_source(ROOT, Path("src/Synthetic.sol"), source), []
        )

    def test_storage_collision_flags_standard_admin_constant_with_slot_zero_implementation(self):
        source = """
        pragma solidity ^0.8.24;
        contract SyntheticProxy {
            bytes32 private constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
            address public implementation;
            fallback() external {
                address impl = implementation;
                assembly { let result := delegatecall(gas(), impl, 0, 0, 0, 0) }
            }
        }
        contract SyntheticImpl {
            uint256 public value;
        }
        """
        findings = detect_storage_collision_source(ROOT, Path("src/SyntheticProxy.sol"), source)
        self.assertTrue(any(finding.contract == "SyntheticProxy" for finding in findings))

    def test_storage_collision_ignores_function_local_declarations(self):
        source = """
        pragma solidity ^0.8.24;
        contract SyntheticProxy {
            fallback() external {
                uint256 scratch;
                address impl = address(0);
                assembly { let result := delegatecall(gas(), impl, 0, 0, 0, 0) }
            }
        }
        contract SyntheticImpl {
            uint256 public value;
        }
        """
        findings = detect_storage_collision_source(ROOT, Path("src/SyntheticProxy.sol"), source)
        self.assertFalse(any(finding.contract == "SyntheticProxy" for finding in findings))

    def test_oracle_flags_vulnerable_lending(self):
        self.assertIn(("oracle", "src/VulnerableLending.sol", "VulnerableLending"), self.findings)

    def test_oracle_ignores_safe_lending(self):
        self.assertNotIn(("oracle", "src/SafeLending.sol", "SafeLending"), self.findings)

    def test_oracle_flags_vulnerable_swap(self):
        self.assertIn(("oracle", "src/VulnerableSwap.sol", "VulnerableSwap"), self.findings)

    def test_oracle_ignores_safe_swap(self):
        self.assertNotIn(("oracle", "src/SafeSwap.sol", "SafeSwap"), self.findings)

    def test_oracle_flags_parenthesised_spot_price_in_synthetic_source(self):
        for expression in (
            "reserveB * 1e18 / reserveA",
            "(reserveB * 1e18) / reserveA",
            "((reserveB * 1e18)) / (reserveA)",
            "(reserveB) * (1e18) / (reserveA)",
            "((reserveB) * (1e18)) / ((reserveA))",
        ):
            with self.subTest(expression=expression):
                source = """
                pragma solidity ^0.8.24;
                contract SyntheticSwap {
                    uint256 public reserveA;
                    uint256 public reserveB;
                    function getPrice() external view returns (uint256) {
                        return %s;
                    }
                }
                """ % expression
                findings = detect_oracle_source(ROOT, Path("src/SyntheticSwap.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].contract, "SyntheticSwap")
                self.assertEqual(findings[0].title, "Oracle exposes a manipulable reserve spot price")

    def test_oracle_flags_feed_read_in_modifier_and_constructor(self):
        for unit in (
            "modifier checked() { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); _; }",
            "constructor() { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); }",
        ):
            with self.subTest(unit=unit[:20]):
                source = f"""
                contract SyntheticLender {{
                    address public feed;
                    {unit}
                    function borrow() external {{}}
                }}
                """
                findings = detect_oracle_source(ROOT, Path("src/SyntheticLender.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].title, "Oracle answer is missing validation checks")

    def test_oracle_flags_feed_read_in_fallback_and_receive(self):
        for unit in (
            "fallback() external { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); }",
            "receive() external payable { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); }",
        ):
            with self.subTest(unit=unit[:9]):
                source = f"""
                contract SyntheticLender {{
                    address public feed;
                    {unit}
                    function borrow() external {{}}
                }}
                """
                findings = detect_oracle_source(ROOT, Path("src/SyntheticLender.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].title, "Oracle answer is missing validation checks")

    def test_oracle_flags_feed_read_in_paren_less_modifier(self):
        # Solidity permits `modifier refresh { ... }` without a parameter
        # list; an unvalidated oracle read inside it must still be scanned.
        source = """
        contract SyntheticLender {
            address public feed;
            modifier refresh { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); _; }
            function borrow() external refresh {}
        }
        """
        findings = detect_oracle_source(ROOT, Path("src/SyntheticLender.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Oracle answer is missing validation checks")

    def test_oracle_flags_feed_read_once_with_bodyless_modifier_before(self):
        # A bodyless `modifier optional virtual;` before a paren-less
        # `modifier refresh { ... }` must not steal `refresh`'s body: the
        # oracle read is reported exactly once, on `refresh` only.
        source = """
        contract SyntheticLender {
            address public feed;
            modifier optional virtual;
            modifier refresh { (, int256 answer, , , ) = AggregatorV3Interface(feed).latestRoundData(); _; }
            function borrow() external refresh {}
        }
        """
        findings = detect_oracle_source(ROOT, Path("src/SyntheticLender.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Oracle answer is missing validation checks")
        refresh_line = source.count("\n", 0, source.index("modifier refresh")) + 1
        self.assertEqual(findings[0].line, refresh_line)

    def test_precision_flags_vulnerable_pool(self):
        self.assertIn(("precision", "src/VulnerablePool.sol", "VulnerablePool"), self.findings)

    def test_precision_ignores_safe_pool(self):
        self.assertNotIn(("precision", "src/SafePool.sol", "SafePool"), self.findings)

    def test_precision_flags_discarded_positive_share_comparison(self):
        for guard in (
            "minted > 0;",
            "bool positive = minted > 0;",
            # `||` does not enforce: the guard passes when the other side
            # holds even with a zero mint, so it stays a finding.
            'require(minted > 0 || totalShares == 0, "zero shares");',
            # A trailing `||` after an enforcing `&&` chain still lets the
            # call continue with a zero mint.
            'require(minted > 0 && totalAssets > 0 || assets > 0, "zero shares");',
            # A `||` wrapped in parens is the same bypass one level deeper:
            # the guard passes when the other side holds with a zero mint.
            'require((minted > 0 || shares > 0), "zero shares");',
            'require((shares > 0 || minted > 0), "zero shares");',
            # A comparison wrapped in `== false` requires the comparison
            # to be FALSE — it passes exactly when the mint is zero.
            'require((minted > 0) == false);',
            'require(minted > 0 == false);',
            # A parenthesised disjunction is still a disjunction.
            'require((minted > 0 || assets > 0));',
            # A parenthesised conjunction wrapped in `== false` requires
            # the conjunction to be FALSE.
            'require((minted > 0 && assets > 0) == false);',
            # The same wrapper on a conjunction with a plain second part.
            'require((minted > 0 && enabled) == false);',
            # A ternary selector inside a parenthesised conjunct can hold
            # while the mint is zero, even with a positive sibling conjunct.
            'require((minted > 0 && enabled ? false : true) && assets > 0);',
            # A top-level ternary can hold while the mint is zero (the
            # ternary yields `true`), so it enforces nothing.
            'require(minted > 0 && enabled ? false : true);',
        ):
            with self.subTest(guard=guard):
                findings = self._positive_share_guard_findings(guard)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_conditional_positive_share_guard(self):
        # A guard inside `if (...) { ... }` only runs when the branch is
        # taken, so it does not enforce a positive mint on every path.
        findings = self._positive_share_guard_findings(
            "if (assets > 1) { require((minted > 0)); }"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_accepts_if_else_guarded_mint(self):
        # An if/else is exhaustive: the else branch's require plus the
        # if branch's assignment from a positively-required value cover
        # every path to the mint (the SafePool shape).
        source = """
        contract SyntheticPool {
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {
                require(assets > 0);
                uint256 minted;
                if (totalShares == 0) {
                    minted = assets;
                } else {
                    minted = assets * totalShares / totalAssets;
                    require(minted > 0);
                }
                totalShares += minted;
            }
        }
        """
        self.assertEqual(precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source), [])

    def test_precision_flags_if_else_with_uncovered_branch(self):
        # The else branch's require does not cover the if branch, which
        # assigns minted from an amount with no positive require.
        source = """
        contract SyntheticPool {
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {
                uint256 minted;
                if (totalShares == 0) {
                    minted = assets;
                } else {
                    minted = assets * totalShares / totalAssets;
                    require(minted > 0);
                }
                totalShares += minted;
            }
        }
        """
        findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_if_else_with_optional_assignment_branch(self):
        # An assignment nested in `if (credit) { ... }` inside an arm runs
        # only when `credit` holds, so it does not prove the arm mints on
        # every path — the other arm's require does not cover it.
        source = """
        contract SyntheticPool {
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {
                require(assets > 0);
                uint256 minted;
                if (totalShares == 0) {
                    if (credit) { minted = assets; }
                } else {
                    minted = assets * totalShares / totalAssets;
                    require(minted > 0);
                }
                totalShares += minted;
            }
        }
        """
        findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_guarded_copy_rewritten_before_copy(self):
        # A top-level guard stating `assets > 0` credits a copy
        # `minted = assets` only while `assets` still holds that value: a
        # rewrite between the guard and the copy does not credit it.
        source = """
        contract SyntheticPool {
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {
                require(assets > 0);
                uint256 minted;
                if (totalShares == 0) {
                    assets = 0;
                    minted = assets;
                } else {
                    minted = assets * totalShares / totalAssets;
                    require(minted > 0);
                }
                totalShares += minted;
            }
        }
        """
        findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_guarded_copy_with_guard_after_copy(self):
        # A guard AFTER the copy cannot prove the copied value was
        # positive at the copy point. The bootstrap arm sets `assets = 1`
        # after the copy, so a zero copy can reach the share update and the
        # test genuinely checks that a late guard does not validate an
        # earlier value.
        source = """
        contract SyntheticPool {
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {
                uint256 minted;
                if (totalShares == 0) {
                    minted = assets;
                    assets = 1;
                } else {
                    minted = assets * totalShares / totalAssets;
                    require(minted > 0);
                }
                require(assets > 0);
                totalShares += minted;
            }
        }
        """
        findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_guarded_copy_with_prefix_write_before_copy(self):
        # A write placed BEFORE the copied name — `delete assets;`,
        # `--assets;` or `++assets;` — zeroes or changes it just like a
        # plain assignment, so the guard no longer credits the copy.
        for write in (
            "delete assets;",
            "--assets;",
            "++assets;",
        ):
            with self.subTest(write=write):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    function deposit(uint256 assets) external {{
                        require(assets > 0);
                        uint256 minted;
                        {write}
                        if (totalShares == 0) {{
                            minted = assets;
                        }} else {{
                            minted = assets * totalShares / totalAssets;
                            require(minted > 0);
                        }}
                        totalShares += minted;
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_if_else_proof_invalidated_by_write_after_join(self):
        # The two-arm proof holds only at the share update: a write to
        # `minted` or `shares` after the if/else join means the mint
        # reaching the update can be zero, even though both arms proved
        # a positive mint on their own path.
        for write in (
            "minted = 0;",
            "shares = 0;",
        ):
            with self.subTest(write=write):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    function deposit(uint256 assets) external {{
                        require(assets > 0);
                        uint256 minted;
                        if (totalShares == 0) {{
                            minted = assets;
                        }} else {{
                            minted = assets * totalShares / totalAssets;
                            require(minted > 0);
                        }}
                        {write}
                        totalShares += minted;
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_accepts_write_after_share_update(self):
        # The post-join write check stops at the last statement consuming
        # the mint: a write after the share update cannot change the
        # credited amount, so it does not invalidate the two-arm proof.
        # A write between the two credits (totalShares, then shares) still
        # invalidates it, because the second credit would be zero.
        for writes, expected in (
            ("totalShares += minted;\n                        minted = 0;", 0),
            ("totalShares += minted;\n                        minted = 0;\n                        shares[msg.sender] += minted;", 1),
        ):
            with self.subTest(writes=writes):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    mapping(address => uint256) shares;
                    function deposit(uint256 assets) external {{
                        require(assets > 0);
                        uint256 minted;
                        if (totalShares == 0) {{
                            minted = assets;
                        }} else {{
                            minted = assets * totalShares / totalAssets;
                            require(minted > 0);
                        }}
                        {writes}
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_branch_proof_overwritten_in_arm(self):
        # A branch proof must survive to the branch end: an overwrite of
        # the proved value later in the same arm breaks the proof, even
        # though the first assignment was credited. A later require
        # re-proves the arm, and a re-copy from the same guarded value is
        # itself a proof point.
        for bootstrap_arm, expected in (
            ("minted = assets;\n                            minted = 0;", 1),
            ("minted = 0;\n                            require(minted > 0);", 0),
            ("minted = assets;\n                            minted = assets;", 0),
        ):
            with self.subTest(bootstrap_arm=bootstrap_arm):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    function deposit(uint256 assets) external {{
                        require(assets > 0);
                        uint256 minted;
                        if (totalShares == 0) {{
                            {bootstrap_arm}
                        }} else {{
                            minted = assets * totalShares / totalAssets;
                            require(minted > 0);
                        }}
                        totalShares += minted;
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_flags_guarded_convert_to_shares_with_unguarded_deposit(self):
        # A positive-share guard in `convertToShares` says nothing about a
        # `deposit` that never calls it: each function body is checked
        # against its own mint path. A deposit with its own guard passes.
        for deposit_guard, expected in (
            ("", 1),
            ("require(minted > 0);", 0),
        ):
            with self.subTest(deposit_guard=deposit_guard or "none"):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    function convertToShares(uint256 assets) public view returns (uint256 shares) {{
                        shares = assets * totalShares / totalAssets;
                        require(shares > 0);
                        return shares;
                    }}
                    function deposit(uint256 assets) external {{
                        uint256 minted = assets * totalShares / totalAssets;
                        {deposit_guard}
                        totalShares += minted;
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_accepts_unguarded_convert_to_shares_with_guarded_deposit(self):
        # Only the state-changing mint path must reject zero shares: an
        # unguarded `convertToShares` that assigns and returns `shares`
        # does not make a guarded `deposit` accept a zero mint (a
        # conversion rounds down and must not revert). An unguarded
        # deposit is still flagged.
        for deposit_guard, expected in (
            ("require(minted > 0);", 0),
            ("", 1),
        ):
            with self.subTest(deposit_guard=deposit_guard or "none"):
                source = f"""
                contract SyntheticPool {{
                    uint256 totalShares;
                    uint256 totalAssets;
                    function convertToShares(uint256 assets) public view returns (uint256 shares) {{
                        shares = assets * totalShares / totalAssets;
                        return shares;
                    }}
                    function deposit(uint256 assets) external {{
                        uint256 minted = assets * totalShares / totalAssets;
                        {deposit_guard}
                        totalShares += minted;
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertEqual(findings[0].title, "Share deposit may accept a zero-rounded mint")

    def test_precision_accepts_enforcing_positive_share_guard(self):
        for guard in (
            'require(minted > 0, "zero shares");',
            "require(minted > 0);",
            "assert(minted > 0);",
            "if (minted == 0) revert ZeroShares();",
            "if (minted == 0) { revert ZeroShares(); }",
            'require(minted > 0 && totalAssets > 0, "zero shares");',
            "assert(minted > 0 && totalShares > 0);",
            'require((minted > 0), "zero shares");',
            "assert((shares > 0));",
            # Doubly parenthesised comparisons still enforce.
            'require(((minted > 0)), "zero shares");',
            # `== true` preserves the guard (the wrapper rule).
            'require((minted > 0) == true);',
            # A parenthesised conjunction enforces each of its parts.
            'require((minted > 0 && assets > 0));',
            # A parenthesised conjunction with an `== false` part still
            # enforces through its positive-mint part.
            'require((minted > 0 && enabled == false));',
            # A ternary nested in parens does not select the mint check.
            'require((a ? b : c) && minted > 0);',
            # A ternary inside an array subscript selects an index, not
            # the guard outcome, so the mint check still enforces.
            'require(allowed[enabled ? 1 : 0] && minted > 0);',
            # A plain conjunction enforces each of its parts.
            'require(minted > 0 && enabled);',
        ):
            with self.subTest(guard=guard):
                self.assertEqual(self._positive_share_guard_findings(guard), [])

    def _positive_share_guard_findings(self, guard):
        source = f"""
        contract SyntheticPool {{
            uint256 totalShares;
            uint256 totalAssets;
            function deposit(uint256 assets) external {{
                uint256 minted = assets * totalShares / totalAssets;
                {guard}
                totalShares += minted;
            }}
        }}
        """
        return precision.detect_source(ROOT, Path("src/SyntheticPool.sol"), source)

    def test_access_control_flags_vulnerable_access(self):
        self.assertIn(("access_control", "src/VulnerableAccess.sol", "VulnerableAccess"), self.findings)

    def test_access_control_ignores_safe_access(self):
        self.assertNotIn(("access_control", "src/SafeAccess.sol", "SafeAccess"), self.findings)

    def test_access_control_flags_event_only_msg_sender_mint(self):
        self.assertIn(("access_control", "src/VulnerableMint.sol", "VulnerableMint"), self.findings)

    def test_access_control_flags_event_only_msg_sender_in_synthetic_source(self):
        source = """
        pragma solidity ^0.8.24;
        contract SyntheticMint {
            uint256 public totalSupply;
            event Minted(address indexed account, uint256 amount);
            function mint(uint256 amount) external {
                totalSupply += amount;
                emit Minted(msg.sender, amount);
            }
        }
        """
        findings = detect_source(ROOT, Path("src/SyntheticMint.sol"), source)
        self.assertTrue(any(finding.contract == "SyntheticMint" for finding in findings))

    def test_access_control_flags_conditional_mint_guard(self):
        for guard in (
            "if (check) { require(msg.sender == owner); }",
            "if (check) require(msg.sender == owner);",
            "if (check) {} else require(msg.sender == owner);",
            "check ? require(msg.sender == owner) : assert(true);",
        ):
            with self.subTest(guard=guard):
                self.assertEqual(len(self._mint_guard_findings(guard)), 1)

    def test_access_control_accepts_unconditional_mint_guard(self):
        self.assertEqual(self._mint_guard_findings("require(msg.sender == owner);"), [])

    def _mint_guard_findings(self, guard):
        source = f"""
        contract SyntheticMint {{
            address owner;
            uint256 totalSupply;
            function mint(uint256 amount, bool check) external {{
                {guard}
                totalSupply += amount;
            }}
        }}
        """
        return detect_source(ROOT, Path("src/SyntheticMint.sol"), source)

    def test_access_control_flags_unprotected_initializer(self):
        self.assertIn(("access_control", "src/VulnerableUupsVault.sol", "VulnerableUupsVault"), self.findings)

    def test_access_control_ignores_one_shot_safe_initializer(self):
        self.assertNotIn(("access_control", "src/SafeUupsVault.sol", "SafeUupsVault"), self.findings)

    def test_proxy_upgrade_flags_vulnerable_uups_vault(self):
        self.assertIn(("proxy_upgrade", "src/VulnerableUupsVault.sol", "VulnerableUupsVault"), self.findings)

    def test_proxy_upgrade_ignores_safe_uups_vault(self):
        self.assertNotIn(("proxy_upgrade", "src/SafeUupsVault.sol", "SafeUupsVault"), self.findings)

    def test_proxy_upgrade_accepts_enforced_checks_for_renamed_candidate(self):
        for enforcement in ("require", "assert"):
            with self.subTest(enforcement=enforcement):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        {enforcement}(candidate.code.length > 0);
                        {enforcement}(IERC1822(candidate).proxiableUUID() == IMPLEMENTATION_SLOT);
                        {enforcement}(address(this) != SELF);
                    }}
                }}
                """
                self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

        source = (ROOT / "src/SafeUupsVault.sol").read_text().replace("newImpl", "candidate")
        self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_proxy_upgrade_flags_discarded_checks_and_fake_only_proxy(self):
        source = """
        contract Vault {
            function upgradeToAndCall(address newImpl, bytes calldata data) external {
                newImpl.code.length;
                IERC1822(newImpl).proxiableUUID();
                address(this) != SELF;
                bool onlyProxy = false;
            }
        }
        """
        findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        for check in ("implementation code check", "UUPS proxiableUUID compatibility", "proxy-only execution context"):
            self.assertIn(check, findings[0].message)

    def test_proxy_upgrade_checks_must_reference_candidate_parameter(self):
        source = """
        contract Vault {
            address newImpl;
            function upgradeToAndCall(address candidate, bytes calldata data) external onlyProxy {
                require(newImpl.code.length > 0);
                require(IERC1822(newImpl).proxiableUUID() == IMPLEMENTATION_SLOT);
            }
        }
        """
        findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertIn("implementation code check", findings[0].message)
        self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)

    def test_proxy_upgrade_flags_bypassable_and_conditional_checks(self):
        # A `|| bypass` in any check lets the call continue with the check
        # unmet, so all three checks are missing.
        for guard in (
            """
            require(candidate.code.length > 0 || bypass);
            require(IERC1822(candidate).proxiableUUID() == IMPLEMENTATION_SLOT || bypass);
            require(address(this) != SELF || bypass);
            """,
            # Checks wrapped in `if (check) { ... }` only run when the
            # branch is taken, so they do not count either.
            """
            if (check) {
                require(candidate.code.length > 0);
                require(IERC1822(candidate).proxiableUUID() == IMPLEMENTATION_SLOT);
                require(address(this) != SELF);
            }
            """,
        ):
            with self.subTest(guard=guard[:40]):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        {guard}
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), 1)
                for check in ("implementation code check", "UUPS proxiableUUID compatibility", "proxy-only execution context"):
                    self.assertIn(check, findings[0].message)

    def test_proxy_upgrade_flags_paren_wrapped_or_in_context_check(self):
        # A `|| bypass` wrapped in parens is the same bypass one level
        # deeper: the context check passes with bypass set, so it is missing
        # while the other two checks are enforced.
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                require(IERC1822(candidate).proxiableUUID() == IMPLEMENTATION_SLOT);
                require((address(this) != SELF || bypass));
            }
        }
        """
        findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertIn("proxy-only execution context", findings[0].message)
        self.assertNotIn("implementation code check", findings[0].message)
        self.assertNotIn("UUPS proxiableUUID compatibility", findings[0].message)

    def test_proxy_upgrade_accepts_separate_guards_for_uuid_probe(self):
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                require(compatible);
                require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                require(address(this) != SELF);
            }
        }
        """
        self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_proxy_upgrade_accepts_not_false_success_guard_for_uuid_probe(self):
        # `compatible != false` enforces the probe's success flag just like
        # `compatible` or `compatible == true` (`!compatible` stays rejected).
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                require(compatible != false);
                require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                require(address(this) != SELF);
            }
        }
        """
        self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_proxy_upgrade_accepts_guard_immediately_after_probe(self):
        # A guard starting immediately after the probe — no space between
        # the probe's `;` and the `require` — still runs after the probe
        # and counts.
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));require(compatible);
                require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                require(address(this) != SELF);
            }
        }
        """
        self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_proxy_upgrade_flags_probe_output_reassigned_before_guards(self):
        # A probe output reassigned between the probe and the guards makes
        # the guards validate the replacement value, not the probe result.
        for reassignment in (
            "uuid = abi.encode(IMPLEMENTATION_SLOT);",
            "compatible = true;",
        ):
            with self.subTest(reassignment=reassignment):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        require(candidate.code.length > 0);
                        (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                        {reassignment}
                        require(compatible);
                        require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                        require(address(this) != SELF);
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
                self.assertNotIn("implementation code check", findings[0].message)
                self.assertNotIn("proxy-only execution context", findings[0].message)

    def test_proxy_upgrade_flags_probe_output_tuple_reassigned_before_guards(self):
        # A tuple reassignment between the probe and the guards defeats
        # validation the same way a plain assignment does: the guards
        # check the replacement values, not the probe result.
        for reassignment in (
            "(compatible, uuid) = (true, abi.encode(IMPLEMENTATION_SLOT));",
            "(uuid, compatible) = (abi.encode(IMPLEMENTATION_SLOT), true);",
        ):
            with self.subTest(reassignment=reassignment):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        require(candidate.code.length > 0);
                        (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                        {reassignment}
                        require(compatible);
                        require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                        require(address(this) != SELF);
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), 1)
                self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
                self.assertNotIn("implementation code check", findings[0].message)
                self.assertNotIn("proxy-only execution context", findings[0].message)

    def test_proxy_upgrade_accepts_probe_output_reassigned_after_guards(self):
        # An assignment AFTER the guards does not invalidate them: they
        # already validated the real probe outputs.
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                require(compatible);
                require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                require(address(this) != SELF);
                uuid = abi.encode(IMPLEMENTATION_SLOT);
            }
        }
        """
        self.assertEqual(proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source), [])

    def test_proxy_upgrade_flags_wrapped_decode_comparison(self):
        # `(decode(...) == SLOT) == false` requires the probe result to
        # DIFFER from the slot, so it does not enforce compatibility.
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                require(compatible);
                require((abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT) == false);
                require(address(this) != SELF);
            }
        }
        """
        findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)

    def test_proxy_upgrade_flags_probe_output_indexed_write_before_guards(self):
        # An indexed write `uuid[0] = ...` between the probe and the guards
        # changes what `abi.decode` reads, just like a plain reassignment;
        # the same write AFTER the guards does not invalidate them.
        for write, expected in (
            ("""
                        uuid[0] = 0x00;
                        require(compatible);
                        require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
            """, 1),
            ("""
                        require(compatible);
                        require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
                        uuid[0] = 0x00;
            """, 0),
        ):
            with self.subTest(write=write.strip()[:12]):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        require(candidate.code.length > 0);
                        (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                        {write}
                        require(address(this) != SELF);
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
                    self.assertNotIn("implementation code check", findings[0].message)
                    self.assertNotIn("proxy-only execution context", findings[0].message)

    def test_proxy_upgrade_flags_wrong_slot_in_decode_guard(self):
        # The decode guard must compare against the expected implementation
        # slot: `bytes32(0)` or an unrelated identifier checks the wrong
        # value, while IMPLEMENTATION_SLOT or either known slot hex counts.
        for rhs, expected in (
            ("bytes32(0)", 1),
            ("IMPLEMENTATION_SLOT", 0),
            ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 0),
            ("0x360894a13ba1a3210667c828492db98dca3e9e2076cc4c2f0e3b8b1e9e2c0c", 0),
            ("OTHER_SLOT", 1),
        ):
            with self.subTest(rhs=rhs):
                source = f"""
                contract Vault {{
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        require(candidate.code.length > 0);
                        (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                        require(compatible);
                        require(abi.decode(uuid, (bytes32)) == {rhs});
                        require(address(this) != SELF);
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
                    self.assertNotIn("implementation code check", findings[0].message)
                    self.assertNotIn("proxy-only execution context", findings[0].message)

    def test_proxy_upgrade_flags_wrong_slot_in_direct_uuid_guard(self):
        # The direct `proxiableUUID() == ...` guard must compare against
        # the expected slot too, not just any value.
        source = """
        contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                require(candidate.code.length > 0);
                require(IERC1822(candidate).proxiableUUID() == bytes32(0));
                require(address(this) != SELF);
            }
        }
        """
        findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
        self.assertEqual(len(findings), 1)
        self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
        self.assertNotIn("implementation code check", findings[0].message)
        self.assertNotIn("proxy-only execution context", findings[0].message)

    def test_proxy_upgrade_flags_guards_before_probe(self):
        # Guards placed BEFORE the probe checked the state variables of
        # the same names, not the probe outputs — they do not count. Each
        # guard is moved independently: either one alone before the probe
        # still leaves the compatibility check missing. The same guards
        # after the probe do.
        success_guard = """
                        require(compatible);
        """
        decode_guard = """
                        require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
        """
        for before, expected in (
            ("both", 1),
            ("success", 1),
            ("decode", 1),
            ("none", 0),
        ):
            with self.subTest(before=before):
                before_guards = ""
                if before in ("both", "success"):
                    before_guards += success_guard
                if before in ("both", "decode"):
                    before_guards += decode_guard
                after_guards = ""
                if before not in ("both", "success"):
                    after_guards += success_guard
                if before not in ("both", "decode"):
                    after_guards += decode_guard
                source = f"""
                contract Vault {{
                    bool compatible;
                    bytes uuid;
                    function upgradeToAndCall(address candidate, bytes calldata data) external {{
                        require(candidate.code.length > 0);
                        {before_guards}
                        (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                        {after_guards}
                        require(address(this) != SELF);
                    }}
                }}
                """
                findings = proxy_upgrade.detect_source(ROOT, Path("src/Synthetic.sol"), source)
                self.assertEqual(len(findings), expected)
                if expected:
                    self.assertIn("UUPS proxiableUUID compatibility", findings[0].message)
                    self.assertNotIn("implementation code check", findings[0].message)
                    self.assertNotIn("proxy-only execution context", findings[0].message)


class DetectorMinorTests(unittest.TestCase):
    path = Path("src/Synthetic.sol")

    def test_d01_internal_and_private_helpers_are_not_entry_points(self):
        for visibility in ("internal", "private"):
            with self.subTest(visibility=visibility):
                source = """
                contract Mint {
                    uint256 totalSupply;
                    function mint(uint256 amount) VISIBILITY { totalSupply += amount; }
                }
                """.replace("VISIBILITY", visibility)
                self.assertEqual(detect_source(ROOT, self.path, source), [])

    def test_d02_pause_writes_require_authorization(self):
        source = """
        contract Pausable {
            bool paused;
            address owner;
            function pause() external { paused = true; }
            function unpause() public { paused = false; }
        }
        """
        self.assertEqual(len(detect_source(ROOT, self.path, source)), 2)
        protected = source.replace("{ paused =", "{ require(msg.sender == owner); paused =")
        self.assertEqual(detect_source(ROOT, self.path, protected), [])

    def test_d03_recipient_check_does_not_authorize_mint(self):
        source = """
        contract Mint {
            uint256 totalSupply;
            address owner;
            function mint(address to, uint256 amount) external {
                require(to != msg.sender);
                totalSupply += amount;
            }
        }
        """
        self.assertEqual(len(detect_source(ROOT, self.path, source)), 1)
        protected = source.replace("to != msg.sender", "owner == msg.sender")
        self.assertEqual(detect_source(ROOT, self.path, protected), [])

    def test_d04_fixed_array_resize_changes_storage_prefix(self):
        source = """
        contract LayoutV1 {
            uint256[2] reserved;
            uint256 value;
        }
        contract LayoutV2 {
            uint256[1] reserved;
            uint256 value;
        }
        """
        findings = detect_storage_collision_source(ROOT, self.path, source)
        self.assertEqual([item.title for item in findings], ["Upgrade changes an existing storage prefix"])
        unchanged = source.replace("[1]", "[ 2 ]")
        self.assertEqual(detect_storage_collision_source(ROOT, self.path, unchanged), [])

    def test_storage_collision_array_resize_shifts_later_field(self):
        # V1 `[2]+value` vs V2 `[1]+value+extra` flatten identically without
        # boundaries, though `value` moves slot 2 -> 1.
        source = """
        contract LayoutV1 {
            uint256[2] reserved;
            uint256 value;
        }
        contract LayoutV2 {
            uint256[1] reserved;
            uint256 value;
            uint256 extra;
        }
        """
        findings = detect_storage_collision_source(ROOT, self.path, source)
        self.assertEqual([item.title for item in findings], ["Upgrade changes an existing storage prefix"])

    def test_storage_collision_huge_fixed_array_uses_descriptor(self):
        source = """
        contract LayoutV1 {
            uint256[100000] reserved;
            uint256 value;
        }
        contract LayoutV2 {
            uint256[100000] reserved;
            uint256 value;
        }
        """
        contracts = list(contract_blocks(self.path, source))
        by_name = {contract.name: contract for contract in contracts}
        layout = _resolved_storage_layout(contracts[0], by_name)
        self.assertEqual(len(layout), 2)
        self.assertEqual(layout[0], (("array", "uint256", "100000"), 0, 0, (0,)))
        self.assertEqual(layout[1], ("uint256", 100000, 0, (1,)))
        self.assertEqual(detect_storage_collision_source(ROOT, self.path, source), [])

    def test_storage_collision_nested_array_budget_uses_descriptor(self):
        # A per-dimension cap alone does not bound nested arrays:
        # [1024][1024][1024] would materialize 2^30 leaves. The cumulative
        # budget forces a single descriptor instead.
        source = """
        contract LayoutV1 {
            uint256[1024][1024][1024] values;
            uint256 tail;
        }
        contract LayoutV2 {
            uint256[1024][1024][1024] values;
            uint256 tail;
        }
        """
        contracts = list(contract_blocks(self.path, source))
        by_name = {contract.name: contract for contract in contracts}
        layout = _resolved_storage_layout(contracts[0], by_name)
        self.assertEqual(len(layout), 2)
        self.assertEqual(
            layout[0][0],
            ("array", ("array", ("array", "uint256", "1024"), "1024"), "1024"),
        )
        self.assertEqual(layout[1], ("uint256", 1024 * 1024 * 1024, 0, (1,)))
        self.assertEqual(detect_storage_collision_source(ROOT, self.path, source), [])

    def test_storage_collision_array_budget_boundary(self):
        # [100][100] is 10000 leaves > 4096: a descriptor. [2][2] is 4
        # leaves and [1024] is 1024 leaves: both still expanded.
        for declaration, expanded in (
            ("uint256[100][100] values;", False),
            ("uint256[2][2] values;", True),
            ("uint256[1024] values;", True),
        ):
            with self.subTest(declaration=declaration):
                source = f"""
                contract LayoutV1 {{
                    {declaration}
                    uint256 tail;
                }}
                """
                contracts = list(contract_blocks(self.path, source))
                by_name = {contract.name: contract for contract in contracts}
                layout = _resolved_storage_layout(contracts[0], by_name)
                if expanded:
                    self.assertTrue(all(isinstance(entry[0], str) for entry in layout))
                else:
                    self.assertEqual(layout[0][0][0], "array")

    def test_d05_standard_slot_does_not_isolate_ordinary_storage(self):
        source = f"""
        contract Proxy {{
            bytes32 constant IMPLEMENTATION_SLOT = 0x{EIP1967_IMPLEMENTATION};
            address admin;
            fallback() external {{
                bytes32 slot = IMPLEMENTATION_SLOT;
                assembly {{
                    let impl := sload(slot)
                    let result := delegatecall(gas(), impl, 0, 0, 0, 0)
                }}
            }}
        }}
        contract Logic {{
            uint256 value;
        }}
        """
        findings = detect_storage_collision_source(ROOT, self.path, source)
        self.assertEqual([item.title for item in findings], ["Proxy slot 0 overlaps implementation storage"])
        isolated = source.replace("address admin;", "")
        self.assertEqual(detect_storage_collision_source(ROOT, self.path, isolated), [])

    def test_d06_reassignment_invalidates_slot_read(self):
        source = f"""
        contract Proxy {{
            bytes32 constant IMPLEMENTATION_SLOT = 0x{EIP1967_IMPLEMENTATION};
            fallback() external {{
                bytes32 slot = IMPLEMENTATION_SLOT;
                assembly {{
                    let impl := sload(slot)
                    REASSIGN
                    let result := delegatecall(gas(), impl, 0, 0, 0, 0)
                }}
            }}
        }}
        """
        for replacement, expected in (("", "valid"), ("impl := sload(0)", "missing")):
            with self.subTest(replacement=replacement):
                contract = next(contract_blocks(self.path, source.replace("REASSIGN", replacement)))
                self.assertEqual(_dedicated_slot_status(contract), expected)

    def test_initializer_flag_must_resolve_to_state(self):
        for parameters, declaration, expected in (
            ("bool initialized, ", "", True),
            ("", "bool initialized = false;", True),
            ("", "", False),
        ):
            source = f"""
            contract Vault {{
                address owner;
                bool initialized;
                function initialize({parameters}address nextOwner) external {{
                    {declaration}
                    require(!initialized);
                    initialized = true;
                    owner = nextOwner;
                }}
            }}
            """
            for detector in (detect_source, proxy_upgrade.detect_source):
                with self.subTest(
                    detector=detector.__module__, parameters=parameters, declaration=declaration
                ):
                    findings = detector(ROOT, self.path, source)
                    self.assertEqual(len(findings), int(expected), findings)

    def test_initializer_flag_shadowed_only_after_guard_still_guards(self):
        # CodeRabbit example: a `bool` declared in a block AFTER the guard
        # does not shadow the state flag at the guard/assignment positions.
        source = """
        contract Vault {
            address owner;
            bool initialized;
            function initialize(address nextOwner) external {
                require(!initialized);
                initialized = true;
                owner = nextOwner;
                { bool initialized = false; }
            }
        }
        """
        for detector in (detect_source, proxy_upgrade.detect_source):
            with self.subTest(detector=detector.__module__):
                self.assertEqual(detector(ROOT, self.path, source), [])

    def test_initializer_flag_tuple_bool_before_guard_shadows(self):
        # A `bool` declared as a tuple element before the guard is scoped
        # to the enclosing block, so it shadows the state flag at the guard
        # and the initializer is unprotected in both detectors.
        source = """
        contract Vault {
            address owner;
            bool initialized;
            function initialize(address nextOwner) external {
                (bool initialized, uint256 x) = (false, 1);
                require(!initialized);
                initialized = true;
                owner = nextOwner;
            }
        }
        """
        for detector in (detect_source, proxy_upgrade.detect_source):
            with self.subTest(detector=detector.__module__):
                findings = detector(ROOT, self.path, source)
                self.assertEqual(len(findings), 1, findings)

    def test_initializer_flag_tuple_two_bools_both_shadow(self):
        # A tuple declaring two `bool` locals must shadow the flag for
        # EITHER name. The detector only recognizes `initialized` /
        # `_initialized` as repeat-guard flags, so a `scratch` subtest
        # cannot verify tuple tracking — test `initialized` in each tuple
        # position instead, plus a control without the local declaration.
        for declaration in (
            "(bool initialized, bool scratch) = (false, false);",
            "(bool scratch, bool initialized) = (false, false);",
        ):
            with self.subTest(declaration=declaration):
                source = f"""
                contract Vault {{
                    address owner;
                    bool initialized;
                    bool scratch;
                    function initialize(address nextOwner) external {{
                        {declaration}
                        require(!initialized);
                        initialized = true;
                        owner = nextOwner;
                    }}
                }}
                """
                for detector in (detect_source, proxy_upgrade.detect_source):
                    with self.subTest(detector=detector.__module__):
                        findings = detector(ROOT, self.path, source)
                        self.assertEqual(len(findings), 1, findings)
        # Control: without the local tuple declaration the state flag
        # guards the initializer, so neither detector reports a finding.
        source = """
        contract Vault {
            address owner;
            bool initialized;
            bool scratch;
            function initialize(address nextOwner) external {
                require(!initialized);
                initialized = true;
                owner = nextOwner;
            }
        }
        """
        for detector in (detect_source, proxy_upgrade.detect_source):
            with self.subTest(detector=detector.__module__):
                self.assertEqual(detector(ROOT, self.path, source), [])

    def test_initializer_flag_for_loop_bool_before_guard_does_not_shadow(self):
        # A `bool` declared as a for-loop initializer is scoped to the loop,
        # so the state flag IS guarded after it — no finding in either
        # detector. This pins the old code's false positive as fixed.
        source = """
        contract Vault {
            address owner;
            bool initialized;
            function initialize(address nextOwner) external {
                for (bool initialized = false; initialized; initialized = false) {}
                require(!initialized);
                initialized = true;
                owner = nextOwner;
            }
        }
        """
        for detector in (detect_source, proxy_upgrade.detect_source):
            with self.subTest(detector=detector.__module__):
                self.assertEqual(detector(ROOT, self.path, source), [])

    def test_d07_setting_flag_does_not_guard_initializer(self):
        source = """
        contract Vault {
            address owner;
            bool initialized;
            function initialize(address nextOwner) external {
                owner = nextOwner;
                initialized = true;
            }
        }
        """
        self.assertEqual(len(proxy_upgrade.detect_source(ROOT, self.path, source)), 1)
        guarded = source.replace("owner = nextOwner;", "if (initialized) revert(); owner = nextOwner;")
        self.assertEqual(proxy_upgrade.detect_source(ROOT, self.path, guarded), [])

    def test_d08_division_whitespace_does_not_change_finding(self):
        for expression in ("(amount / total) * supply", "(amount/total)*supply"):
            with self.subTest(expression=expression):
                source = f"""
                contract Pool {{
                    function quote(uint amount, uint total, uint supply) external pure returns (uint) {{
                        return {expression};
                    }}
                }}
                """
                findings = precision.detect_source(ROOT, self.path, source)
                self.assertEqual([item.title for item in findings], ["Arithmetic divides before multiplying"])

    def test_d09_reads_state_declarations_after_functions_and_constructors(self):
        for preceding_member in ("constructor() {}", "function helper() private {}"):
            with self.subTest(preceding_member=preceding_member):
                source = f"""
                contract Vault {{
                    {preceding_member}
                    function update(address receiver) external {{
                        (bool ok,) = receiver.call("");
                        require(ok);
                        balances[msg.sender] = 0;
                    }}
                    mapping(address => uint256) balances;
                }}
                """
                self.assertEqual(len(reentrancy.detect_source(ROOT, self.path, source)), 1)
        local_only = """
        contract Example {
            function update(address receiver) external {
                (bool ok,) = receiver.call("");
                require(ok);
                uint256 scratch = 0;
            }
        }
        """
        self.assertEqual(reentrancy.detect_source(ROOT, self.path, local_only), [])

    def test_d10_unrelated_twap_members_do_not_hide_spot_getter(self):
        for member in (
            "uint256[] observations;",
            "function getTWAP() external pure returns (uint256) { return 1; }",
        ):
            with self.subTest(member=member):
                source = f"""
                contract Oracle {{
                    uint256 reserveA;
                    uint256 reserveB;
                    {member}
                    function getPrice() external view returns (uint256) {{
                        return reserveB * 1e18 / reserveA;
                    }}
                }}
                """
                findings = detect_oracle_source(ROOT, self.path, source)
                self.assertEqual([item.title for item in findings], ["Oracle exposes a manipulable reserve spot price"])

    def test_d11_cli_rejects_nonexistent_scan_root(self):
        with tempfile.TemporaryDirectory() as directory:
            valid_root = Path(directory)
            missing_root = valid_root / "missing"
            command = [sys.executable, "-B", "-m", "audit.detectors", "--root"]
            result = subprocess.run(command + [str(missing_root)], cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Scan root", result.stderr)
            self.assertIn(str(missing_root), result.stderr)

            empty = subprocess.run(command + [str(valid_root)], cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(empty.returncode, 0, empty.stderr)
            self.assertEqual(json.loads(empty.stdout)["findings"], [])


    def test_n1_return_guard_must_precede_sensitive_write(self):
        for statements, expected in (
            ("totalSupply += amount; if (msg.sender != owner) return;", True),
            ("if (msg.sender != owner) return; totalSupply += amount;", False),
            ("totalSupply += amount; if (msg.sender != owner) revert();", False),
            ("totalSupply += amount; require(msg.sender == owner);", False),
            ("totalSupply += amount; assert(msg.sender == owner);", False),
        ):
            with self.subTest(statements=statements):
                source = f"""
                contract Token {{
                    address owner;
                    uint256 totalSupply;
                    function mint(uint256 amount) external {{ {statements} }}
                }}
                """
                self.assertEqual(bool(detect_source(ROOT, self.path, source)), expected)

    def test_n2_repeat_guard_must_precede_owner_assignment(self):
        for statements, expected in (
            ("owner = nextOwner; if (initialized) return;", True),
            ("if (initialized) return; owner = nextOwner;", False),
        ):
            with self.subTest(statements=statements):
                source = f"""
                contract Vault {{
                    address owner;
                    bool initialized;
                    function initialize(address nextOwner) external {{
                        {statements}
                        initialized = true;
                    }}
                }}
                """
                self.assertEqual(bool(proxy_upgrade.detect_source(ROOT, self.path, source)), expected)

    def test_n3_reentrancy_resolves_inherited_storage(self):
        source = """
        contract Base {
            mapping(address => uint256) internal balances;
        }
        contract Child is Base {
            function withdraw() external {
                payable(msg.sender).transfer(balances[msg.sender]);
                balances[msg.sender] = 0;
            }
        }
        """
        findings = reentrancy.detect_source(ROOT, self.path, source)
        self.assertEqual([item.contract for item in findings], ["Child"])
        unrelated = source.replace("Child is Base", "Child")
        self.assertEqual(reentrancy.detect_source(ROOT, self.path, unrelated), [])

    def test_n4_sequencer_exemption_preserves_spot_price_check(self):
        wrapper = """
        contract Wrapper {
            function _validatedPrice() internal view returns (uint256) {
                sequencer.latestRoundData();
                return super._validatedPrice();
            }
            %s
        }
        """
        getter = """
            function getPrice() external view returns (uint256) {
                return reserve0 * 1e18 / reserve1;
            }
        """
        self.assertEqual(detect_oracle_source(ROOT, self.path, wrapper % ""), [])
        findings = detect_oracle_source(ROOT, self.path, wrapper % getter)
        self.assertEqual(
            [item.title for item in findings],
            ["Oracle exposes a manipulable reserve spot price"],
        )

    def test_o1_sequencer_exemption_only_covers_sequencer_feed(self):
        wrapper = """
        contract Wrapper {
            function _validatedPrice() internal view returns (uint256) {
                sequencer.latestRoundData();
                return super._validatedPrice();
            }
            %s
        }
        """
        sequencer_only = detect_oracle_source(ROOT, self.path, wrapper % "")
        self.assertEqual(sequencer_only, [])

        with_price_feed = """
            function getPrice() external view returns (uint256) {
                (int256 answer,,,,) = feed.latestRoundData();
                return uint256(answer);
            }
        """
        findings = detect_oracle_source(ROOT, self.path, wrapper % with_price_feed)
        self.assertEqual(
            [item.title for item in findings],
            ["Oracle answer is missing validation checks"],
        )

    def test_oracle_validation_must_be_in_feed_reading_function(self):
        source = """
        contract SyntheticOracle {
            function getPrice() external view returns (uint256) {
                (uint80 roundId, int256 answer,, uint256 updatedAt, uint80 answeredInRound) =
                    feed.latestRoundData();
                %s
                return uint256(answer);
            }
            function validate(uint80 roundId, int256 answer, uint256 updatedAt, uint80 answeredInRound)
                internal view
            {
                %s
            }
        }
        """
        checks = """
            require(answer > 0);
            require(updatedAt <= block.timestamp);
            require(block.timestamp - updatedAt < 3600);
            require(answeredInRound >= roundId);
            answer = answer * int256(10 ** (18 - feed.decimals()));
        """
        with self.subTest("unused validating helper"):
            findings = detect_oracle_source(ROOT, self.path, source % ("", checks))
            self.assertEqual(
                [item.title for item in findings],
                ["Oracle answer is missing validation checks"],
            )
        with self.subTest("validated getter"):
            self.assertEqual(detect_oracle_source(ROOT, self.path, source % (checks, "")), [])

    def test_o2_repeat_guard_ordering_only_applies_to_return(self):
        template = """
        contract Vault {
            address owner;
            bool initialized;
            function initialize(address nextOwner) external {
                STATEMENTS
            }
        }
        """
        reverting_guard = template.replace(
            "STATEMENTS",
            "owner = nextOwner; require(!initialized); initialized = true;",
        )
        self.assertEqual(proxy_upgrade.detect_source(ROOT, self.path, reverting_guard), [])

        late_return_guard = template.replace(
            "STATEMENTS",
            "owner = nextOwner; if (initialized) return; initialized = true;",
        )
        findings = proxy_upgrade.detect_source(ROOT, self.path, late_return_guard)
        self.assertEqual(
            [item.title for item in findings],
            ["Initializer can overwrite privileged state repeatedly"],
        )

    def test_o3_inherited_storage_write_ignores_local_shadow_only_after_declaration(self):
        source = """
        contract Base {
            uint256 private scratch;
        }
        contract Child is Base {
            function update(address receiver) external {
                (bool ok,) = receiver.call("");
                require(ok);
                uint256 scratch = 1;
            }
        }
        """
        self.assertEqual(reentrancy.detect_source(ROOT, self.path, source), [])

        storage_write = source.replace("uint256 scratch = 1;", "scratch = 1;")
        findings = reentrancy.detect_source(ROOT, self.path, storage_write)
        self.assertEqual([item.contract for item in findings], ["Child"])

        storage_write_before_shadow = source.replace(
            "uint256 scratch = 1;", "scratch = 1; uint256 scratch = 2;"
        )
        findings = reentrancy.detect_source(ROOT, self.path, storage_write_before_shadow)
        self.assertEqual([item.contract for item in findings], ["Child"])


    def test_p1_inherited_storage_write_after_local_scope_ends(self):
        source = """
        contract Base {
            uint256 internal scratch;
        }
        contract Child is Base {
            function update(address receiver) external {
                (bool ok,) = receiver.call("");
                require(ok);
                { uint256 scratch = 1; }
                scratch = 1;
            }
        }
        """
        findings = reentrancy.detect_source(ROOT, self.path, source)
        self.assertEqual([item.contract for item in findings], ["Child"])
        local_only = source.replace("}\n                scratch = 1;", "scratch = 1; }")
        self.assertEqual(reentrancy.detect_source(ROOT, self.path, local_only), [])

    def test_p2_statement_keywords_do_not_shadow_inherited_storage(self):
        source = """
        contract Base {
            uint256 internal balance;
        }
        contract Child is Base {
            function update(address receiver) external {
                delete balance;
                (bool ok,) = receiver.call("");
                require(ok);
                balance = 1;
            }
        }
        """
        findings = reentrancy.detect_source(ROOT, self.path, source)
        self.assertEqual([item.contract for item in findings], ["Child"])
        for keyword in (
            "delete", "return", "emit", "require", "assert", "revert", "if", "for",
            "while", "assembly", "unchecked", "break", "continue",
        ):
            with self.subTest(keyword=keyword):
                self.assertEqual(reentrancy._local_declarations(f"{keyword} balance;"), {})
        for type_name in ("uint256", "address payable", "CustomContract", "uint256[]"):
            with self.subTest(type_name=type_name):
                self.assertIn("balance", reentrancy._local_declarations(f"{type_name} balance;"))


if __name__ == "__main__":
    unittest.main()
