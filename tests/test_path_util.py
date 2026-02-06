"""Unit tests for path utilities."""

import unittest
from copyparty.path_util import (
    djoin,
    uncyg,
    undot,
    u8safe,
    vroots,
    vsplit,
    vjoin,
    ujoin,
)


class TestPathUtil(unittest.TestCase):
    """Test path utility functions."""

    def test_djoin_basic(self) -> None:
        """Test basic path joining."""
        result = djoin("a", "b", "c")
        self.assertEqual(result, "a/b/c")

    def test_djoin_skips_empty(self) -> None:
        """Test djoin skips empty string args."""
        self.assertEqual(djoin("a", "", "c"), "a/c")
        self.assertEqual(djoin("", "b"), "b")

    def test_djoin_single(self) -> None:
        """Test djoin with single arg."""
        self.assertEqual(djoin("foo"), "foo")

    def test_uncyg_cygwin_path(self) -> None:
        """Test converting cygwin path to windows path."""
        self.assertEqual(uncyg("/c/foo/bar"), "c:\\foo/bar")

    def test_uncyg_not_cygwin(self) -> None:
        """Test non-cygwin paths pass through."""
        self.assertEqual(uncyg("/usr/bin"), "/usr/bin")
        self.assertEqual(uncyg("relative"), "relative")
        self.assertEqual(uncyg(""), "")
        self.assertEqual(uncyg("x"), "x")

    def test_uncyg_short_path(self) -> None:
        """Test 2-char path /X is treated as cygwin drive letter."""
        self.assertEqual(uncyg("/a"), "a:\\")

    def test_undot_basic(self) -> None:
        """Test resolving . and .. in paths."""
        self.assertEqual(undot("a/./b/../c"), "a/c")
        self.assertEqual(undot("a/b/c"), "a/b/c")

    def test_undot_only_dots(self) -> None:
        """Test path with only dots."""
        self.assertEqual(undot("."), "")
        self.assertEqual(undot(".."), "")
        self.assertEqual(undot("./"), "")

    def test_undot_leading_dot(self) -> None:
        """Test path with leading dot."""
        self.assertEqual(undot("./file.txt"), "file.txt")
        self.assertEqual(undot("./dir/file.txt"), "dir/file.txt")

    def test_undot_double_dot(self) -> None:
        """Test path with .. segments."""
        self.assertEqual(undot("a/b/../c"), "a/c")
        self.assertEqual(undot("a/b/c/../../d"), "a/d")

    def test_undot_empty_segments(self) -> None:
        """Test path with empty segments (double slashes)."""
        self.assertEqual(undot("a//b"), "a/b")

    def test_u8safe_ascii(self) -> None:
        """Test u8safe with plain ASCII."""
        self.assertEqual(u8safe("hello"), "hello")

    def test_u8safe_unicode(self) -> None:
        """Test u8safe with unicode text."""
        self.assertEqual(u8safe("café"), "café")

    def test_u8safe_empty(self) -> None:
        """Test u8safe with empty string."""
        self.assertEqual(u8safe(""), "")

    def test_vroots_basic(self) -> None:
        """Test vroots with matching suffixes."""
        result = vroots("q/w/e/r", "a/s/d/e/r")
        self.assertEqual(result, ("/q/w/", "/a/s/d/"))

    def test_vroots_no_match(self) -> None:
        """Test vroots with no matching suffix."""
        result = vroots("a/b", "c/d")
        self.assertEqual(result, ("/a/b/", "/c/d/"))

    def test_vroots_full_match(self) -> None:
        """Test vroots where all segments match."""
        result = vroots("x", "x")
        self.assertEqual(result, ("/", "/"))

    def test_vsplit_with_slash(self) -> None:
        """Test vsplit with directory separator (returns list from rsplit)."""
        self.assertEqual(vsplit("dir/file.txt"), ["dir", "file.txt"])
        self.assertEqual(vsplit("a/b/c.txt"), ["a/b", "c.txt"])

    def test_vsplit_no_slash(self) -> None:
        """Test vsplit with no directory separator."""
        self.assertEqual(vsplit("file.txt"), ("", "file.txt"))

    def test_vjoin_both(self) -> None:
        """Test vjoin with both dir and file."""
        self.assertEqual(vjoin("dir", "file.txt"), "dir/file.txt")
        self.assertEqual(vjoin("a/b", "c/d"), "a/b/c/d")

    def test_vjoin_empty_dir(self) -> None:
        """Test vjoin with empty directory."""
        self.assertEqual(vjoin("", "file.txt"), "file.txt")

    def test_vjoin_empty_file(self) -> None:
        """Test vjoin with empty filename."""
        self.assertEqual(vjoin("dir", ""), "dir")

    def test_vjoin_both_empty(self) -> None:
        """Test vjoin with both empty."""
        self.assertEqual(vjoin("", ""), "")

    def test_ujoin_basic(self) -> None:
        """Test URL path joining."""
        self.assertEqual(ujoin("a", "b"), "a/b")

    def test_ujoin_strips_slashes(self) -> None:
        """Test ujoin strips trailing/leading slashes."""
        self.assertEqual(ujoin("a/", "/b"), "a/b")
        self.assertEqual(ujoin("a//", "//b"), "a/b")

    def test_ujoin_empty(self) -> None:
        """Test ujoin with empty args."""
        self.assertEqual(ujoin("", "b"), "b")
        self.assertEqual(ujoin("a", ""), "a")


if __name__ == "__main__":
    unittest.main()
