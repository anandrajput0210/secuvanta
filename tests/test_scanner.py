import tempfile
import unittest
from pathlib import Path

from core.scanner import (
    scan_directory,
    is_text_file,
)


class TestScanner(unittest.TestCase):

    def test_is_text_file(self):

        self.assertTrue(
            is_text_file(Path("test.py"))
        )

        self.assertTrue(
            is_text_file(Path(".env"))
        )

        self.assertFalse(
            is_text_file(Path("image.png"))
        )

    def test_scan_directory_finds_secret(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            test_file = Path(temp_dir) / "config.py"

            test_file.write_text(
                'password = "supersecret123"'
            )

            result = scan_directory(
    temp_dir
)

            findings = result["findings"]

            files_scanned = result["files_scanned"]

            self.assertEqual(files_scanned, 1)

            self.assertEqual(len(findings), 1)

            self.assertEqual(
                findings[0].finding_type,
                "Hardcoded Password"
            )

    def test_scanner_ignores_binary_files(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            binary_file = Path(temp_dir) / "image.png"

            binary_file.write_bytes(
                b"\x89PNG\r\n\x1a\n"
            )

            result = scan_directory(
    temp_dir
)

            findings = result["findings"]

            files_scanned = result["files_scanned"]

            self.assertEqual(files_scanned, 0)

            self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()