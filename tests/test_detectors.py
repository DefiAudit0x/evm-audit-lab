import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from audit.detectors.access_control import detect_source
from audit.detectors.oracle import detect_source as detect_oracle_source
from audit.detectors.storage_collision import detect_source as detect_storage_collision_source


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, "-m", "audit.detectors", "--root", str(ROOT)],
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


if __name__ == "__main__":
    unittest.main()
