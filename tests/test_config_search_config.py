"""Unit tests for search config module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.search_config import SearchIndexConfigBuilder


class TestSearchIndexConfigBuilder(unittest.TestCase):
    """Test SearchIndexConfigBuilder class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.builder = SearchIndexConfigBuilder(self.log_func)

    def test_builder_instantiation(self) -> None:
        """Test that builder can be instantiated."""
        self.assertIsNotNone(self.builder)
        self.assertEqual(self.builder.log, self.log_func)

    def test_configure_search_flags_default(self) -> None:
        """Test search flag configuration with defaults."""
        vol = MagicMock()
        vol.flags = {}
        vol.axs = MagicMock()
        vol.axs.uwrite = True

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        args = MagicMock()
        args.e2ds = False
        args.e2dsa = False
        args.e2d = True
        args.no_hash = None
        args.no_idx = None
        args.og_ua = None
        args.srch_excl = None

        vf_bmap = lambda: {}
        vf_vmap = lambda: {}

        self.builder.configure_search_flags(vfs, args, vf_bmap, vf_vmap)

        # Should enable e2d
        self.assertTrue(vol.flags["e2d"])

    def test_disable_database_features_d2d(self) -> None:
        """Test disabling database features with d2d flag."""
        vol = MagicMock()
        vol.flags = {"d2d": True, "e2d": True, "e2t": True}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.disable_database_features(vfs)

        # d2d should disable e2d features
        self.assertTrue(vol.flags["d2t"])

    def test_validate_indexing_requirements_no_e2d(self) -> None:
        """Test validation with e2d required but not set."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {"lifetime": 100}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.validate_indexing_requirements(vfs)

        # lifetime should be removed since e2d not enabled
        self.log_func.assert_called()


class TestSearchIndexConfigBuilderValidation(unittest.TestCase):
    """Test search validation methods."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.builder = SearchIndexConfigBuilder(self.log_func)

    def test_validate_search_warnings(self) -> None:
        """Test search warning generation."""
        vol = MagicMock()
        vol.flags = {"e2d": True}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        args = MagicMock()
        args.have_idp_hdrs = False

        self.builder.validate_search_warnings(vfs, args)

        # Should log hint about multimedia indexing
        self.log_func.assert_called()


if __name__ == "__main__":
    unittest.main()
