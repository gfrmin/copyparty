"""Unit tests for volflag processor modules."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.volflag_processor import VolflagValidator, VolflagConverter, LimitationBuilder


class TestVolflagValidator(unittest.TestCase):
    """Test VolflagValidator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.validator = VolflagValidator(self.log_func)

    def test_validator_instantiation(self) -> None:
        """Test that validator can be instantiated."""
        self.assertIsNotNone(self.validator)
        self.assertEqual(self.validator.log, self.log_func)

    def test_validate_flags_no_unknown(self) -> None:
        """Test validation with no unknown flags."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"nosub": True, "robots": True}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        flagdescs = {"nosub": "...", "robots": "..."}

        self.validator.validate_flags(vfs, flagdescs)
        # Should not log anything for valid flags
        self.log_func.assert_not_called()

    def test_validate_flags_with_unknown(self) -> None:
        """Test validation with unknown flags."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"nosub": True, "badkey": "value"}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        flagdescs = {"nosub": "..."}

        self.validator.validate_flags(vfs, flagdescs)
        self.log_func.assert_called()


class TestVolflagConverter(unittest.TestCase):
    """Test VolflagConverter class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.converter = VolflagConverter(self.log_func)

    def test_converter_instantiation(self) -> None:
        """Test that converter can be instantiated."""
        self.assertIsNotNone(self.converter)
        self.assertEqual(self.converter.log, self.log_func)

    def test_convert_zipmax_empty_value(self) -> None:
        """Test zipmax conversion with empty value."""
        vol = MagicMock()
        vol.flags = {"zipmaxn": "", "zipmaxs": "0"}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        unhumanize = lambda x: int(x.rstrip("kmgtpeKMGTPE"))

        self.converter.convert_zipmax(vfs, unhumanize)

        # Empty/zero values should be set to 0
        self.assertEqual(vol.flags["zipmaxn"], 0)
        self.assertEqual(vol.flags["zipmaxs"], 0)

    def test_convert_zipmax_with_values(self) -> None:
        """Test zipmax conversion with valid values."""
        vol = MagicMock()
        vol.flags = {"zipmaxn": "100", "zipmaxs": "1g"}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        def unhumanize(x):
            multipliers = {"k": 1024, "m": 1024**2, "g": 1024**3}
            x_lower = x.lower()
            for suffix, mult in multipliers.items():
                if x_lower.endswith(suffix):
                    return int(x_lower[:-1]) * mult
            return int(x)

        self.converter.convert_zipmax(vfs, unhumanize)

        # Should set _v variants and zipmax flag
        self.assertTrue(vol.flags["zipmax"])


class TestLimitationBuilder(unittest.TestCase):
    """Test LimitationBuilder class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.builder = LimitationBuilder(self.log_func)

    def test_builder_instantiation(self) -> None:
        """Test that builder can be instantiated."""
        self.assertIsNotNone(self.builder)
        self.assertEqual(self.builder.log, self.log_func)

    def test_build_limitations_no_flags(self) -> None:
        """Test building limitations with no flags set."""
        vol = MagicMock()
        vol.flags = {}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        mock_lim = MagicMock()
        LimClass = MagicMock(return_value=mock_lim)

        unhumanize = lambda x: 1024

        self.builder.build_limitations(vfs, unhumanize, LimClass)

        # With no flags, lim should not be set
        # (vol.lim is not automatically set unless "use" is True)
        LimClass.assert_called_once()

    def test_apply_robots_flag_disabled(self) -> None:
        """Test applying robots flag when disabled globally."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.apply_robots_flag(vfs, no_robots=True)

        # Should set norobots when no_robots=True
        self.assertEqual(vol.flags["norobots"], True)

    def test_apply_robots_flag_enabled_per_volume(self) -> None:
        """Test applying robots flag overridden per volume."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"robots": True}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.apply_robots_flag(vfs, no_robots=True)

        # With robots=True, should not override
        self.assertNotIn("norobots", vol.flags)


if __name__ == "__main__":
    unittest.main()
