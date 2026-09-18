import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from release_seal import inventory


class InventoryTests(unittest.TestCase):
    def test_nested_files_include_hidden_files_and_known_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "nested").mkdir()
            (root / "nested" / "hello.txt").write_bytes(b"hello")
            (root / ".empty").write_bytes(b"")
            self.assertEqual(inventory(root), [
                {
                    "path": ".empty",
                    "size": 0,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
                {
                    "path": "nested/hello.txt",
                    "size": 5,
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                },
            ])

    def test_empty_directory_is_empty_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(inventory(folder), [])

    def test_cli_reads_directory_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="release example ") as folder:
            (Path(folder) / "sample.txt").write_bytes(b"hello")
            result = subprocess.run(
                [sys.executable, "-m", "release_seal", "inventory", folder],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout)[0]["path"], "sample.txt")
            self.assertEqual(json.loads(result.stdout)[0]["size"], 5)


if __name__ == "__main__":
    unittest.main()
