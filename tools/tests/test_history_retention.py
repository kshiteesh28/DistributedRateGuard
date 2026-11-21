import importlib.util
import tempfile
import unittest
from pathlib import Path

module_path = Path(__file__).resolve().parents[1] / "history" / "retention.py"
spec = importlib.util.spec_from_file_location("retention", module_path)
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


class RetentionTest(unittest.TestCase):
    def test_exact_boundary_and_file_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def managed(second, digit):
                return root / f"rg-history-v1-{second}-{digit * 32}.bin"

            expired, recent = managed(100, "a"), managed(101, "a")
            unrelated, link, directory = root / "report.json", managed(99, "b"), managed(99, "c")
            partial = Path(str(managed(100, "d")) + ".partial")
            fresh_partial = Path(str(managed(101, "d")) + ".partial")
            unrelated_partial = root / "notes.bin.partial"
            for file in (expired, recent, unrelated, partial, fresh_partial, unrelated_partial):
                file.write_bytes(b"synthetic")
            link.symlink_to(unrelated)
            directory.mkdir()
            now = 100 + retention.RETENTION_SECONDS
            self.assertEqual(retention.expire_local_exports(root, now), 2)
            self.assertFalse(expired.exists())
            self.assertEqual(set(root.iterdir()), {recent, fresh_partial, unrelated, unrelated_partial, link, directory})
            self.assertEqual(retention.expire_local_exports(root, now), 0)


if __name__ == "__main__":
    unittest.main()
