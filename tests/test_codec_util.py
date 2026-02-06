"""Unit tests for codec utilities."""

import unittest
from copyparty.codec_util import (
    json_hesc,
    html_escape,
    html_bescape,
    unescape_cookie,
)


class TestCodecUtil(unittest.TestCase):
    """Test codec utility functions."""

    def test_json_hesc_angle_brackets(self) -> None:
        """Test json_hesc escapes < and > with unicode."""
        self.assertEqual(json_hesc("<script>"), "\\u003cscript\\u003e")

    def test_json_hesc_ampersand(self) -> None:
        """Test json_hesc escapes & with unicode."""
        self.assertEqual(json_hesc("a&b"), "a\\u0026b")

    def test_json_hesc_no_change(self) -> None:
        """Test json_hesc doesn't change normal text."""
        self.assertEqual(json_hesc("hello world"), "hello world")

    def test_html_escape_basic(self) -> None:
        """Test basic HTML escaping."""
        self.assertEqual(html_escape("<div>"), "&lt;div&gt;")
        self.assertEqual(html_escape("a & b"), "a &amp; b")
        self.assertEqual(html_escape("normal"), "normal")

    def test_html_escape_with_quotes(self) -> None:
        """Test HTML escaping with quotes."""
        result = html_escape('test"value', quot=True)
        self.assertIn("&quot;", result)
        result2 = html_escape("test'value", quot=True)
        self.assertIn("&#x27;", result2)

    def test_html_escape_crlf(self) -> None:
        """Test HTML escaping with CRLF."""
        result = html_escape("a\r\nb", crlf=True)
        self.assertEqual(result, "a&#13;&#10;b")

    def test_html_bescape_basic(self) -> None:
        """Test HTML escaping for bytes."""
        self.assertEqual(html_bescape(b"<tag>"), b"&lt;tag&gt;")

    def test_html_bescape_quotes(self) -> None:
        """Test bytes HTML escaping with quotes."""
        result = html_bescape(b'"hi\'there"', quot=True)
        self.assertIn(b"&quot;", result)

    def test_html_bescape_crlf(self) -> None:
        """Test bytes HTML escaping with CRLF."""
        result = html_bescape(b"a\r\nb", crlf=True)
        self.assertEqual(result, b"a&#13;&#10;b")

    def test_unescape_cookie_basic(self) -> None:
        """Test basic cookie values pass through."""
        self.assertEqual(unescape_cookie("hello"), "hello")

    def test_unescape_cookie_percent(self) -> None:
        """Test cookie unescaping with percent encoding."""
        self.assertEqual(unescape_cookie("qwe%2Crty"), "qwe,rty")

    def test_unescape_cookie_semicolon(self) -> None:
        """Test cookie unescaping with semicolon."""
        self.assertEqual(unescape_cookie("asd%3Bfgh"), "asd;fgh")

    def test_unescape_cookie_plus(self) -> None:
        """Test cookie unescaping with encoded plus."""
        self.assertEqual(unescape_cookie("jkl%2Bxyz"), "jkl+xyz")

    def test_unescape_cookie_percent_literal(self) -> None:
        """Test cookie unescaping with %25 -> %."""
        self.assertEqual(unescape_cookie("abc%25def"), "abc%def")

    def test_unescape_cookie_invalid(self) -> None:
        """Test cookie unescaping with invalid percent sequence."""
        self.assertEqual(unescape_cookie("abc%ZZdef"), "abc%ZZdef")

    def test_unescape_cookie_trailing(self) -> None:
        """Test cookie unescaping with trailing partial percent."""
        self.assertEqual(unescape_cookie("abc%2"), "abc%2")


if __name__ == "__main__":
    unittest.main()
