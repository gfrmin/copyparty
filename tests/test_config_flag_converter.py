"""Unit tests for flag converter module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.flag_converter import FlagConverter


class TestFlagConverter(unittest.TestCase):
    """Test FlagConverter class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.converter = FlagConverter(self.log_func)

    def test_converter_instantiation(self) -> None:
        """Test that converter can be instantiated."""
        self.assertIsNotNone(self.converter)
        self.assertEqual(self.converter.log, self.log_func)

    def test_convert_integer_flags(self) -> None:
        """Test converting flags to integers."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"lifetime": "3600", "nrand": "5"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.converter.convert_integer_flags(vfs, ["lifetime", "nrand"])

        self.assertEqual(vol.flags["lifetime"], 3600)
        self.assertEqual(vol.flags["nrand"], 5)

    def test_convert_float_flags(self) -> None:
        """Test converting flags to floats."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"aconvt": "0.8", "convt": "1.5"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.converter.convert_float_flags(vfs, ["aconvt", "convt"])

        self.assertAlmostEqual(vol.flags["aconvt"], 0.8)
        self.assertAlmostEqual(vol.flags["convt"], 1.5)

    def test_convert_chmod_flags_valid(self) -> None:
        """Test chmod flag conversion with valid octal."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"chmod_d": "755", "chmod_f": "644"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        free_umask = self.converter.convert_chmod_flags(vfs)

        self.assertEqual(vol.flags["chmod_d"], 0o755)
        self.assertEqual(vol.flags["chmod_f"], 0o644)

    def test_convert_chmod_flags_invalid(self) -> None:
        """Test chmod flag conversion with invalid octal."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"chmod_d": "999"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        with self.assertRaises(Exception):
            self.converter.convert_chmod_flags(vfs)

    def test_apply_ownership_flags(self) -> None:
        """Test applying ownership flags."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"uid": 1000, "gid": 1000}
        vol.lim = MagicMock()

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.converter.apply_ownership_flags(vfs)

        # Should set chown flag
        self.assertTrue(vol.flags["chown"])
        self.assertTrue(vol.lim.chown)

    def test_validate_database_strategy_valid(self) -> None:
        """Test database strategy validation with valid value."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"dbd": "wal"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        args = MagicMock()
        args.dbd = "acid"

        # Should not raise
        self.converter.validate_database_strategy(vfs, args)

    def test_validate_database_strategy_invalid(self) -> None:
        """Test database strategy validation with invalid value."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"dbd": "invalid"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        args = MagicMock()
        args.dbd = "invalid"

        with self.assertRaises(Exception):
            self.converter.validate_database_strategy(vfs, args)


if __name__ == "__main__":
    unittest.main()
