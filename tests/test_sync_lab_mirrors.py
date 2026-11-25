import subprocess
import sys
import shutil
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_lab_mirrors.py"
MIRROR = ROOT / "labs" / "lab-03-flash-loan" / "src" / "SafeSwap.sol"
FIXTURE_MIRROR = ROOT / "labs" / "lab-11-erc4626-inflation" / "test" / "fixtures" / "HookToken.sol"


def run_check(root=ROOT):
    return subprocess.run(
        [sys.executable, str(root / "scripts" / SCRIPT.name), "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


class SyncLabMirrorTests(unittest.TestCase):
    def test_sync_check_detects_deleted_mirrors(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            for name in ("scripts", "src", "test", "labs"):
                shutil.copytree(ROOT / name, scratch / name)
            result = run_check(scratch)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            lab = Path("labs/lab-03-flash-loan")
            for relative in (
                lab / "src/SafeSwap.sol",
                lab / "test/FlashLoan.t.sol",
                lab / "src/shared/IERC20.sol",
                Path("labs/lab-11-erc4626-inflation/test/fixtures/HookToken.sol"),
            ):
                with self.subTest(mirror=str(relative)):
                    mirror = scratch / relative
                    original = mirror.read_bytes()
                    mirror.unlink()
                    result = run_check(scratch)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(relative.as_posix(), result.stdout)
                    mirror.write_bytes(original)

    def test_sync_check_detects_obsolete_mirrors(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            for name in ("scripts", "src", "test", "labs"):
                shutil.copytree(ROOT / name, scratch / name)
            obsolete = scratch / "labs/lab-03-flash-loan/src/Obsolete.sol"
            obsolete.write_text("// stale mirror\n")
            result = run_check(scratch)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("labs/lab-03-flash-loan/src/Obsolete.sol", result.stdout)

    def test_update_removes_obsolete_and_preserves_valid_mirrors(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            for name in ("scripts", "src", "test", "labs"):
                shutil.copytree(ROOT / name, scratch / name)
            obsolete = scratch / "labs/lab-03-flash-loan/src/Obsolete.sol"
            obsolete.write_text("// stale mirror\n")
            valid = scratch / MIRROR.relative_to(ROOT)
            original = valid.read_bytes()
            anchor = scratch / "valid-mirror-anchor"
            anchor.hardlink_to(valid)
            self.assertEqual(run_check(scratch).returncode, 1)
            result = subprocess.run(
                [sys.executable, str(scratch / "scripts" / SCRIPT.name)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(obsolete.exists())
            self.assertEqual(valid.read_bytes(), original)
            self.assertTrue(valid.samefile(anchor), "valid mirror was removed and recreated")
            self.assertEqual(run_check(scratch).returncode, 0)

    def assert_sync_check_detects_drift(self, path: Path, label: str):
        result = run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n// deliberate drift\n")
            result = run_check()
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(label, result.stdout)
        finally:
            path.write_bytes(original)

        result = run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sync_check_detects_one_line_drift(self):
        self.assert_sync_check_detects_drift(MIRROR, "labs/lab-03-flash-loan/src/SafeSwap.sol")

    def test_sync_check_detects_fixture_drift(self):
        self.assert_sync_check_detects_drift(
            FIXTURE_MIRROR, "labs/lab-11-erc4626-inflation/test/fixtures/HookToken.sol"
        )


if __name__ == "__main__":
    unittest.main()
