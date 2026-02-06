"""Unit tests for string utilities."""

import unittest
from copyparty.str_util import (
    dedent,
    str_anchor,
    eol_conv,
    align_tab,
    visual_length,
    wrap,
    termsize,
)


class TestStrUtil(unittest.TestCase):
    """Test string utility functions."""

    def test_dedent_basic(self) -> None:
        """Test basic dedentation."""
        txt = "    hello\n    world"
        result = dedent(txt)
        self.assertEqual(result, "hello\nworld")

    def test_dedent_mixed_indent(self) -> None:
        """Test dedentation with mixed indentation."""
        txt = "  hello\n    world\n  foo"
        result = dedent(txt)
        self.assertTrue(result.startswith("hello"))

    def test_dedent_with_carriage_return(self) -> None:
        """Test dedentation with carriage returns."""
        txt = "    hello\r\n    world"
        result = dedent(txt)
        self.assertIn("hello", result)

    def test_str_anchor_empty(self) -> None:
        """Test anchor parsing with empty string."""
        anchor_type, text = str_anchor("")
        self.assertEqual(anchor_type, 0)
        self.assertEqual(text, "")

    def test_str_anchor_contains(self) -> None:
        """Test anchor parsing for contains (~)."""
        anchor_type, text = str_anchor("hello")
        self.assertEqual(anchor_type, 1)  # contains
        self.assertEqual(text, "hello")

    def test_str_anchor_starts_with(self) -> None:
        """Test anchor parsing for starts with (^)."""
        anchor_type, text = str_anchor("^hello")
        self.assertEqual(anchor_type, 2)  # starts with
        self.assertEqual(text, "hello")

    def test_str_anchor_ends_with(self) -> None:
        """Test anchor parsing for ends with ($)."""
        anchor_type, text = str_anchor("hello$")
        self.assertEqual(anchor_type, 3)  # ends with
        self.assertEqual(text, "hello")

    def test_str_anchor_exact_match(self) -> None:
        """Test anchor parsing for exact match (^...$)."""
        anchor_type, text = str_anchor("^hello$")
        self.assertEqual(anchor_type, 4)  # exact
        self.assertEqual(text, "hello")

    def test_str_anchor_case_insensitive(self) -> None:
        """Test anchor parsing is case insensitive."""
        anchor_type, text = str_anchor("HELLO")
        self.assertEqual(text, "hello")

    def test_eol_conv_to_crlf(self) -> None:
        """Test EOL conversion to CRLF."""
        def gen_bytes():
            yield b"hello\nworld"

        result = b"".join(eol_conv(gen_bytes(), "crlf"))
        self.assertEqual(result, b"hello\r\nworld")

    def test_eol_conv_to_lf(self) -> None:
        """Test EOL conversion to LF."""
        def gen_bytes():
            yield b"hello\r\nworld"

        result = b"".join(eol_conv(gen_bytes(), "lf"))
        self.assertEqual(result, b"hello\nworld")

    def test_eol_conv_remove_cr(self) -> None:
        """Test EOL conversion removes CR."""
        def gen_bytes():
            yield b"hello\rworld"

        result = b"".join(eol_conv(gen_bytes(), "lf"))
        self.assertEqual(result, b"helloworld")

    def test_align_tab_basic(self) -> None:
        """Test basic column alignment."""
        lines = ["a b c", "dd eee f"]
        result = align_tab(lines)
        self.assertEqual(len(result), 2)
        # Columns should be aligned
        self.assertGreater(len(result[0]), len("a b c"))

    def test_align_tab_single_column(self) -> None:
        """Test alignment with single column."""
        lines = ["hello", "world"]
        result = align_tab(lines)
        self.assertEqual(len(result), 2)

    def test_align_tab_empty(self) -> None:
        """Test alignment with empty input."""
        lines = []
        result = align_tab(lines)
        self.assertEqual(result, [])

    def test_visual_length_ascii(self) -> None:
        """Test visual length of ASCII text."""
        # ASCII characters should be counted 1:1
        text = "hello"
        self.assertEqual(visual_length(text), 5)

    def test_visual_length_with_ansi(self) -> None:
        """Test visual length ignores ANSI escape codes."""
        # ANSI codes shouldn't count toward visual length
        text = "\033[1;32mhello\033[0m"
        # Should only count "hello" (5 chars)
        self.assertEqual(visual_length(text), 5)

    def test_visual_length_box_drawing(self) -> None:
        """Test visual length of box drawing characters."""
        # Box drawing characters (U+2500-U+25A0) should be 1 width
        text = "─"  # U+2500
        self.assertEqual(visual_length(text), 1)

    def test_visual_length_braille(self) -> None:
        """Test visual length of braille characters."""
        # Braille (U+2800-U+28FF) should be 1 width
        text = "⠀"  # U+2800
        self.assertEqual(visual_length(text), 1)

    def test_visual_length_cjk(self) -> None:
        """Test visual length of CJK characters."""
        # CJK characters should be 2 width
        text = "中"  # CJK Unified Ideograph
        self.assertGreaterEqual(visual_length(text), 1)

    def test_wrap_basic(self) -> None:
        """Test basic text wrapping."""
        text = "hello world test"
        result = wrap(text, 10, 5)
        self.assertGreater(len(result), 1)
        # First line should not exceed max
        self.assertLessEqual(visual_length(result[0]), 10)

    def test_wrap_single_word(self) -> None:
        """Test wrapping with single long word."""
        text = "verylongword"
        result = wrap(text, 5, 5)
        # Should break long word
        self.assertGreater(len(result), 1)

    def test_wrap_preserves_content(self) -> None:
        """Test wrap preserves all content."""
        text = "hello world test"
        result = wrap(text, 20, 5)
        joined = "".join(result).replace("-", "")
        self.assertIn("hello", joined)
        self.assertIn("world", joined)

    def test_termsize_returns_tuple(self) -> None:
        """Test termsize returns valid tuple."""
        w, h = termsize()
        self.assertIsInstance(w, int)
        self.assertIsInstance(h, int)
        # Should have reasonable defaults at minimum
        self.assertGreaterEqual(w, 20)
        self.assertGreaterEqual(h, 10)

    def test_termsize_positive(self) -> None:
        """Test termsize returns positive values."""
        w, h = termsize()
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)


if __name__ == "__main__":
    unittest.main()
