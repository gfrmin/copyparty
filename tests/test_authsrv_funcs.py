"""Unit tests for authsrv standalone functions."""

import unittest

from copyparty.authsrv import (
    n_du_who,
    n_ver_who,
    split_cfg_ln,
)


class TestNDuWho(unittest.TestCase):
    """Test disk usage visibility level mapping."""

    def test_all(self) -> None:
        self.assertEqual(n_du_who("all"), 9)

    def test_auth(self) -> None:
        self.assertEqual(n_du_who("auth"), 7)

    def test_w(self) -> None:
        self.assertEqual(n_du_who("w"), 5)

    def test_rw(self) -> None:
        self.assertEqual(n_du_who("rw"), 4)

    def test_a(self) -> None:
        self.assertEqual(n_du_who("a"), 3)

    def test_unknown_returns_zero(self) -> None:
        self.assertEqual(n_du_who(""), 0)
        self.assertEqual(n_du_who("bogus"), 0)
        self.assertEqual(n_du_who("r"), 0)

    def test_ordering(self) -> None:
        """Higher visibility levels should have higher values."""
        self.assertGreater(n_du_who("all"), n_du_who("auth"))
        self.assertGreater(n_du_who("auth"), n_du_who("w"))
        self.assertGreater(n_du_who("w"), n_du_who("rw"))
        self.assertGreater(n_du_who("rw"), n_du_who("a"))
        self.assertGreater(n_du_who("a"), n_du_who(""))


class TestNVerWho(unittest.TestCase):
    """Test version visibility level mapping."""

    def test_all(self) -> None:
        self.assertEqual(n_ver_who("all"), 9)

    def test_auth(self) -> None:
        self.assertEqual(n_ver_who("auth"), 6)

    def test_a(self) -> None:
        self.assertEqual(n_ver_who("a"), 3)

    def test_unknown_returns_zero(self) -> None:
        self.assertEqual(n_ver_who(""), 0)
        self.assertEqual(n_ver_who("bogus"), 0)

    def test_ordering(self) -> None:
        self.assertGreater(n_ver_who("all"), n_ver_who("auth"))
        self.assertGreater(n_ver_who("auth"), n_ver_who("a"))
        self.assertGreater(n_ver_who("a"), n_ver_who(""))


class TestSplitCfgLn(unittest.TestCase):
    """Test config line parsing: 'a, b, c: 3' => {a:True, b:True, c:'3'}."""

    def test_single_flag(self) -> None:
        self.assertEqual(split_cfg_ln("myflag"), {"myflag": True})

    def test_multiple_flags(self) -> None:
        result = split_cfg_ln("a, b, c")
        self.assertEqual(result, {"a": True, "b": True, "c": True})

    def test_key_value(self) -> None:
        result = split_cfg_ln("key: value")
        self.assertEqual(result, {"key": "value"})

    def test_flags_then_value(self) -> None:
        """'a, b, c: 3' => {a:True, b:True, c:'3'}."""
        result = split_cfg_ln("a, b, c: 3")
        self.assertEqual(result, {"a": True, "b": True, "c": "3"})

    def test_empty_string(self) -> None:
        self.assertEqual(split_cfg_ln(""), {})

    def test_whitespace_only(self) -> None:
        self.assertEqual(split_cfg_ln("   "), {})

    def test_value_with_spaces(self) -> None:
        result = split_cfg_ln("key: hello world")
        self.assertEqual(result, {"key": "hello world"})

    def test_flag_whitespace_handling(self) -> None:
        """Whitespace around flags should be stripped."""
        result = split_cfg_ln("  a ,  b  ")
        self.assertEqual(result, {"a": True, "b": True})

    def test_key_value_whitespace(self) -> None:
        """Whitespace around key:value should be stripped."""
        result = split_cfg_ln("  key  :  val  ")
        self.assertEqual(result, {"key": "val"})

    def test_colon_before_comma(self) -> None:
        """When colon comes before comma, it's a key:value pair."""
        result = split_cfg_ln("k: v, extra")
        # colon is first, so k gets "v, extra" as value
        self.assertEqual(result, {"k": "v, extra"})

    def test_single_comma_separated(self) -> None:
        result = split_cfg_ln("x, y")
        self.assertEqual(result, {"x": True, "y": True})


if __name__ == "__main__":
    unittest.main()
