"""Unit tests for filesystem utilities."""

import os
import tempfile
import unittest
from copyparty.fs_util import get_df, rmdirs, rmdirs_up


class TestFsUtil(unittest.TestCase):
    """Test filesystem utility functions."""

    def test_get_df_current(self) -> None:
        """Test getting disk free space for current directory."""
        total, free, error = get_df(".")
        # Should return valid values (not zero)
        self.assertGreater(total, 0)
        self.assertGreater(free, 0)
        self.assertEqual(error, "")

    def test_get_df_invalid_path(self) -> None:
        """Test getting disk free space for invalid path."""
        total, free, error = get_df("/nonexistent/path/xyz")
        # Should return zeros and error message
        self.assertEqual(total, 0)
        self.assertEqual(free, 0)
        self.assertNotEqual(error, "")

    def test_rmdirs_temp_dir(self) -> None:
        """Test removing temporary directory tree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files and directories
            os.makedirs(os.path.join(tmpdir, "a", "b", "c"))
            with open(os.path.join(tmpdir, "a", "file1.txt"), "w") as f:
                f.write("test")
            with open(os.path.join(tmpdir, "a", "b", "file2.txt"), "w") as f:
                f.write("test")

            # Import RootLogger mock
            from unittest.mock import MagicMock

            log = MagicMock()

            # Remove directory tree
            removed, errors = rmdirs(log, os.path.join(tmpdir, "a"), keep_root=True)

            # Should have removed directories
            self.assertGreater(len(removed), 0)
            # Root should still exist
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "a")))

    def test_rmdirs_up_temp(self) -> None:
        """Test removing empty parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested directories
            nested = os.path.join(tmpdir, "a", "b", "c")
            os.makedirs(nested)

            # Remove up from nested
            removed, errors = rmdirs_up(nested, tmpdir)

            # Should have removed directories
            self.assertGreater(len(removed), 0)
            # Stop path should still exist
            self.assertTrue(os.path.exists(tmpdir))


if __name__ == "__main__":
    unittest.main()
