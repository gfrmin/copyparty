"""Unit tests for metadata builder module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.metadata_builder import MetadataTagBuilder


class TestMetadataTagBuilder(unittest.TestCase):
    """Test MetadataTagBuilder class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.builder = MetadataTagBuilder(self.log_func)

    def test_builder_instantiation(self) -> None:
        """Test that builder can be instantiated."""
        self.assertIsNotNone(self.builder)
        self.assertEqual(self.builder.log, self.log_func)

    def test_build_embedded_files_config(self) -> None:
        """Test building embedded files config."""
        vol = MagicMock()
        vol.flags = {
            "preadmes": "README.md,readme.txt",
            "readmes": "HELP.md",
            "prologues": "start.txt",
            "epilogues": "end.txt",
        }

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.build_embedded_files_config(vfs)

        # Should create emb_all set and emb_mds/emb_lgs lists
        self.assertTrue("emb_all" in vol.flags)
        self.assertTrue("emb_mds" in vol.flags)
        self.assertTrue("emb_lgs" in vol.flags)

    def test_build_html_head_config_with_favicon(self) -> None:
        """Test HTML head configuration with favicon."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {
            "html_head": None,
            "html_head_s": None,
            "ufavico": "https://example.com/favicon.png",
        }

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.build_html_head_config(vfs)

        # Should create favicon link
        self.assertTrue("ufavico_h" in vol.flags)
        self.assertIn("icon", vol.flags["ufavico_h"])

    def test_build_html_head_config_with_robots(self) -> None:
        """Test HTML head configuration with robots metadata."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {
            "html_head": None,
            "html_head_s": None,
            "norobots": True,
        }

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.build_html_head_config(vfs)

        # Should add robots metadata
        self.assertTrue("html_head_s" in vol.flags)
        self.assertIn("robots", vol.flags["html_head_s"])

    def test_build_theme_color_config_short_format(self) -> None:
        """Test theme color conversion from short format."""
        vol = MagicMock()
        vol.flags = {"tcolor": "#fc5"}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.build_theme_color_config(vfs)

        # Should expand fc5 to ffcc55
        self.assertEqual(vol.flags["tcolor"], "ffcc55")

    def test_build_external_thumbnail_config(self) -> None:
        """Test building external thumbnail configuration."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {
            "ext_th": ["jpg=https://example.com/thumb?f=", "png=https://other.com/"],
        }

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        self.builder.build_external_thumbnail_config(vfs)

        # Should create ext_th_d dict
        self.assertTrue("ext_th_d" in vol.flags)
        self.assertEqual(vol.flags["ext_th_d"]["jpg"], "https://example.com/thumb?f=")

    def test_build_all_metadata_config(self) -> None:
        """Test building all metadata configuration."""
        vol = MagicMock()
        vol.vpath = "media"
        vol.flags = {
            "preadmes": "README.md",
            "readmes": "",
            "prologues": "",
            "epilogues": "",
            "html_head": None,
            "html_head_s": None,
            "tcolor": "#abc",
            "ext_th": [],
        }

        vfs = MagicMock()
        vfs.all_nodes = {"media": vol}

        # Should not raise
        self.builder.build_all_metadata_config(vfs)

        # Should have all metadata configurations
        self.assertTrue("emb_all" in vol.flags)
        self.assertTrue("tcolor" in vol.flags)
        self.assertTrue("ext_th_d" in vol.flags)


if __name__ == "__main__":
    unittest.main()
