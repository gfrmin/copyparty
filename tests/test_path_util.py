"""Unit tests for path utilities."""

import unittest
from copyparty.path_util import (
    djoin,
    uncyg,
    undot,
    sanitize_fn,
    sanitize_vpath,
    relchk,
    vsplit,
    vjoin,
)


class TestPathUtil(unittest.TestCase):
    """Test path utility functions."""

    def test_djoin(self) -> None:
        """Test path joining with forward slashes."""
        self.assertEqual(djoin("a", "b", "c"), "a/b/c")
        self.assertEqual(djoin("home", "user"), "home/user")
        self.assertEqual(djoin(""), "")

    def test_undot(self) -> None:
        """Test removing leading dot from paths."""
        self.assertEqual(undot("./file.txt"), "file.txt")
        self.assertEqual(undot("."), "")
        self.assertEqual(undot("file.txt"), "file.txt")
        self.assertEqual(undot("./dir/file.txt"), "dir/file.txt")

    def test_sanitize_fn(self) -> None:
        """Test filename sanitization."""
        self.assertEqual(sanitize_fn("file name.txt"), "file name.txt")
        self.assertEqual(sanitize_fn("file.txt "), "file.txt")
        self.assertEqual(sanitize_fn("file.txt..."), "file.txt")
        # Control characters should be removed
        self.assertEqual(sanitize_fn("file\x00\x01.txt"), "file.txt")

    def test_sanitize_vpath(self) -> None:
        """Test virtual path sanitization."""
        self.assertEqual(sanitize_vpath("/media"), "/media")
        self.assertEqual(sanitize_vpath("/media/"), "/media")
        self.assertEqual(sanitize_vpath("media//folder"), "media/folder")
        self.assertEqual(sanitize_vpath("//media///folder//"), "/media/folder")

    def test_relchk_valid(self) -> None:
        """Test relative path checking with valid paths."""
        self.assertEqual(relchk("file.txt"), "file.txt")
        self.assertEqual(relchk("dir/file.txt"), "dir/file.txt")
        self.assertEqual(relchk("dir/../file.txt"), "file.txt")
        self.assertEqual(relchk("./dir/file.txt"), "dir/file.txt")

    def test_relchk_invalid(self) -> None:
        """Test relative path checking with invalid paths."""
        with self.assertRaises(Exception):
            relchk("../etc/passwd")

    def test_vsplit(self) -> None:
        """Test virtual path splitting."""
        self.assertEqual(vsplit("dir/file.txt"), ("dir", "file.txt"))
        self.assertEqual(vsplit("file.txt"), ("", "file.txt"))
        self.assertEqual(vsplit("a/b/c.txt"), ("a/b", "c.txt"))

    def test_vjoin(self) -> None:
        """Test virtual path joining."""
        self.assertEqual(vjoin("dir", "file.txt"), "dir/file.txt")
        self.assertEqual(vjoin("", "file.txt"), "file.txt")
        self.assertEqual(vjoin("dir", ""), "dir")
        self.assertEqual(vjoin("a/b", "c/d"), "a/b/c/d")


if __name__ == "__main__":
    unittest.main()
