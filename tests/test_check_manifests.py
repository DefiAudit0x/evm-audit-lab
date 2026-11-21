import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_manifests.py"


class ManifestCheckerTests(unittest.TestCase):
    def run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_repository_manifests_pass(self):
        result = self.run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Lab manifest check passed (14 labs).", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_missing_manifest_file_reference_fails(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "labs" / "lab-scratch"
            lab.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "name": "Scratch lab",
                "threat_model": "A test-only threat model.",
                "assumptions": ["The checker is run locally."],
                "invariant": "Referenced files exist.",
                "contracts": {
                    "example": {"role": "vulnerable", "path": "src/missing.sol"}
                },
                "tests": [{"name": "scratch", "path": "test/missing.t.sol"}],
                "detector_expectations": [
                    {"detector": "manual-review", "expectation": "documented"}
                ],
            }
            (lab / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not resolve to a file: 'src/missing.sol'", result.stdout)
        self.assertIn("does not resolve to a file: 'test/missing.t.sol'", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
