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
from audit.detectors.storage_collision import EIP1967_IMPLEMENTATION, _dedicated_slot_status


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

    def test_storage_collision_flags_vulnerable_proxy(self):
        self.assertIn(("storage_collision", "src/VulnerableProxy.sol", "VulnerableProxy"), self.findings)

    def test_storage_collision_ignores_safe_proxy(self):
        self.assertNotIn(("storage_collision", "src/SafeProxy.sol", "SafeProxy"), self.findings)

    def test_storage_collision_ignores_append_only_upgrade(self):
        self.assertNotIn(("storage_collision", "src/SafeProxy.sol", "SafeImplV2"), self.findings)

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

    def test_precision_flags_vulnerable_pool(self):
        self.assertIn(("precision", "src/VulnerablePool.sol", "VulnerablePool"), self.findings)

    def test_precision_ignores_safe_pool(self):
        self.assertNotIn(("precision", "src/SafePool.sol", "SafePool"), self.findings)

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

    def test_access_control_flags_unprotected_initializer(self):
        self.assertIn(("access_control", "src/VulnerableUupsVault.sol", "VulnerableUupsVault"), self.findings)

    def test_access_control_ignores_one_shot_safe_initializer(self):
        self.assertNotIn(("access_control", "src/SafeUupsVault.sol", "SafeUupsVault"), self.findings)

    def test_proxy_upgrade_flags_vulnerable_uups_vault(self):
        self.assertIn(("proxy_upgrade", "src/VulnerableUupsVault.sol", "VulnerableUupsVault"), self.findings)

    def test_proxy_upgrade_ignores_safe_uups_vault(self):
        self.assertNotIn(("proxy_upgrade", "src/SafeUupsVault.sol", "SafeUupsVault"), self.findings)


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
