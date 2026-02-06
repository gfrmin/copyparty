"""Unit tests for codec utilities."""

import unittest
from copyparty.codec_util import (
    html_sh_esc,
    json_hesc,
    html_escape,
    html_bescape,
    unquotep,
    unescape_cookie,
)


class TestCodecUtil(unittest.TestCase):
    """Test codec utility functions."""

    def test_html_sh_esc(self) -> None:
        """Test HTML shell escaping."""
        self.assertEqual(html_sh_esc("<script>"), "&lt;script&gt;")
        self.assertEqual(html_sh_esc("a & b"), "a &amp; b")
        self.assertEqual(html_sh_esc("<div>a & b</div>"), "&lt;div&gt;a &amp; b&lt;/div&gt;")

    def test_json_hesc(self) -> None:
        """Test JSON HTML escaping."""
        self.assertEqual(json_hesc('test"value'), 'test\\"value')
        self.assertEqual(json_hesc("line1\nline2"), "line1\\nline2")
        self.assertEqual(json_hesc("carriage\rreturn"), "carriage\\rreturn")
        self.assertEqual(json_hesc("back\\slash"), "back\\\\slash")

    def test_html_escape_basic(self) -> None:
        """Test basic HTML escaping."""
        self.assertEqual(html_escape("<div>"), "&lt;div&gt;")
        self.assertEqual(html_escape("a & b"), "a &amp; b")
        self.assertEqual(html_escape("normal"), "normal")

    def test_html_escape_with_quotes(self) -> None:
        """Test HTML escaping with quotes."""
        result = html_escape('test"value', quot=True)
        # Quotes should be escaped when quot=True
        self.assertIn("&quot;", result)

    def test_html_bescape(self) -> None:
        """Test HTML escaping for bytes."""
        result = html_bescape(b"<tag>")
        self.assertEqual(result, b"&lt;tag&gt;")

    def test_unescape_cookie(self) -> None:
        """Test cookie unescaping."""
        self.assertEqual(unescape_cookie('"value"'), "value")
        self.assertEqual(unescape_cookie("normal"), "normal")
        self.assertEqual(unescape_cookie("back\\\\slash"), "backslash")


if __name__ == "__main__":
    unittest.main()
