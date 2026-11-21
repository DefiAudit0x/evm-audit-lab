from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "labs" / "lab-07-proxy-storage-collision" / "README.md"
PROXY_TEST = ROOT / "test" / "ProxyCollision.t.sol"


class Lab07ReadmeTests(unittest.TestCase):
    def test_readme_and_proxy_test_describe_admin_takeover(self):
        for path in (README, PROXY_TEST):
            with self.subTest(path=str(path.relative_to(ROOT))):
                text = " ".join(path.read_text(encoding="utf-8").lower().split())
                self.assertNotIn("permanently bricked", text)
                self.assertNotIn("upgradeability bricked", text)
                self.assertIn("take over or reassign admin authority", text)


if __name__ == "__main__":
    unittest.main()
