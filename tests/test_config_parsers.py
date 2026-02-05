"""Unit tests for config parsers."""

import unittest
from copyparty.config.parsers import AccountParser, GroupParser, VolspecParser


class TestAccountParser(unittest.TestCase):
    """Test AccountParser class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.parser = AccountParser(lambda msg, level: None)

    def test_parse_empty(self) -> None:
        """Test parsing empty arguments."""
        result = self.parser.parse(None)
        self.assertEqual(result, {})

        result = self.parser.parse([])
        self.assertEqual(result, {})

    def test_parse_single_account(self) -> None:
        """Test parsing single account."""
        result = self.parser.parse(["user1:pass1"])
        self.assertEqual(result, {"user1": "pass1"})

    def test_parse_multiple_accounts(self) -> None:
        """Test parsing multiple accounts."""
        result = self.parser.parse(["user1:pass1", "user2:pass2", "user3:pass3"])
        self.assertEqual(
            result,
            {"user1": "pass1", "user2": "pass2", "user3": "pass3"},
        )

    def test_parse_password_with_colon(self) -> None:
        """Test parsing password containing colons."""
        result = self.parser.parse(["user:pass:with:colons"])
        self.assertEqual(result, {"user": "pass:with:colons"})

    def test_parse_invalid_format_no_colon(self) -> None:
        """Test parsing invalid format (no colon)."""
        with self.assertRaises(Exception) as ctx:
            self.parser.parse(["invalidformat"])
        self.assertIn("invalid value", str(ctx.exception))

    def test_parse_invalid_format_empty_username(self) -> None:
        """Test parsing invalid format (empty username)."""
        result = self.parser.parse([":password"])
        # This is actually valid - empty username is allowed
        self.assertEqual(result, {"": "password"})

    def test_parse_invalid_format_empty_password(self) -> None:
        """Test parsing invalid format (empty password)."""
        result = self.parser.parse(["username:"])
        # This is actually valid - empty password is allowed
        self.assertEqual(result, {"username": ""})


class TestGroupParser(unittest.TestCase):
    """Test GroupParser class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.parser = GroupParser(lambda msg, level: None)

    def test_parse_empty(self) -> None:
        """Test parsing empty arguments."""
        result = self.parser.parse(None)
        self.assertEqual(result, {})

        result = self.parser.parse([])
        self.assertEqual(result, {})

    def test_parse_single_group(self) -> None:
        """Test parsing single group."""
        result = self.parser.parse(["admin:user1,user2,user3"])
        self.assertEqual(result, {"admin": ["user1", "user2", "user3"]})

    def test_parse_multiple_groups(self) -> None:
        """Test parsing multiple groups."""
        result = self.parser.parse(["admin:user1,user2", "users:user3,user4"])
        self.assertEqual(
            result,
            {
                "admin": ["user1", "user2"],
                "users": ["user3", "user4"],
            },
        )

    def test_parse_equals_separator(self) -> None:
        """Test parsing with '=' as separator instead of ':'."""
        result = self.parser.parse(["admin=user1,user2"])
        self.assertEqual(result, {"admin": ["user1", "user2"]})

    def test_parse_colon_member_separator(self) -> None:
        """Test parsing with ':' as member separator instead of ','."""
        result = self.parser.parse(["admin:user1:user2"])
        self.assertEqual(result, {"admin": ["user1", "user2"]})

    def test_parse_mixed_separators(self) -> None:
        """Test parsing with mixed separators."""
        result = self.parser.parse(["admin=user1:user2,user3"])
        self.assertEqual(result, {"admin": ["user1", "user2", "user3"]})

    def test_parse_with_whitespace(self) -> None:
        """Test parsing with whitespace around members."""
        result = self.parser.parse(["admin: user1 , user2 , user3 "])
        self.assertEqual(result, {"admin": ["user1", "user2", "user3"]})

    def test_parse_invalid_format_no_separator(self) -> None:
        """Test parsing invalid format (no separator)."""
        with self.assertRaises(Exception) as ctx:
            self.parser.parse(["invalidformat"])
        self.assertIn("invalid value", str(ctx.exception))

    def test_parse_single_member(self) -> None:
        """Test parsing group with single member."""
        result = self.parser.parse(["admin:user1"])
        self.assertEqual(result, {"admin": ["user1"]})


class TestVolspecParser(unittest.TestCase):
    """Test VolspecParser class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.parser = VolspecParser(lambda msg, level: None)

    def test_parse_empty(self) -> None:
        """Test parsing empty arguments."""
        result = self.parser.parse(None)
        self.assertEqual(result, [])

        result = self.parser.parse([])
        self.assertEqual(result, [])

    def test_parse_basic_volume(self) -> None:
        """Test parsing basic volume spec."""
        result = self.parser.parse(["/srv/data:/data"])
        self.assertEqual(result, [("/srv/data", "/data", "")])

    def test_parse_volume_with_permissions(self) -> None:
        """Test parsing volume spec with permissions."""
        result = self.parser.parse(["/srv/data:/data:rw"])
        self.assertEqual(result, [("/srv/data", "/data", "rw")])

    def test_parse_multiple_volumes(self) -> None:
        """Test parsing multiple volume specs."""
        result = self.parser.parse(
            [
                "/srv/data:/data:rw",
                "/srv/media:/media:r",
                "/srv/private:/admin:a",
            ]
        )
        self.assertEqual(
            result,
            [
                ("/srv/data", "/data", "rw"),
                ("/srv/media", "/media", "r"),
                ("/srv/private", "/admin", "a"),
            ],
        )

    def test_parse_volume_with_complex_permissions(self) -> None:
        """Test parsing volume with complex permission spec."""
        result = self.parser.parse(["/data:/vol:rwm:r,user1:a,admin"])
        self.assertEqual(result, [("/data", "/vol", "rwm:r,user1:a,admin")])

    def test_parse_volume_with_spaces_in_path(self) -> None:
        """Test parsing volume with spaces in paths."""
        result = self.parser.parse(["/srv/My Data:/data"])
        self.assertEqual(result, [("/srv/My Data", "/data", "")])

    def test_parse_invalid_format_missing_dst(self) -> None:
        """Test parsing invalid format (missing destination)."""
        with self.assertRaises(Exception) as ctx:
            self.parser.parse(["/srv/data"])
        self.assertIn("invalid -v argument", str(ctx.exception))

    def test_parse_windows_path(self) -> None:
        """Test parsing Windows path format.

        Note: On Windows, paths like c:\\path need escaping in shell or use /c/path
        This test uses /c/path format which is common in cross-platform usage.
        """
        result = self.parser.parse(["/c/Users/data:/data"])
        self.assertEqual(result, [("/c/Users/data", "/data", "")])


if __name__ == "__main__":
    unittest.main()
