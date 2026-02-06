"""Unit tests for frontend config builder module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.frontend_builder import FrontendConfigBuilder


class TestFrontendConfigBuilder(unittest.TestCase):
    """Test FrontendConfigBuilder class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.builder = FrontendConfigBuilder()

    def test_builder_instantiation(self) -> None:
        """Test that builder can be instantiated."""
        self.assertIsNotNone(self.builder)

    def test_build_volume_listing_config(self) -> None:
        """Test building volume listing config."""
        vn = MagicMock()
        vf = {
            "e2d": True,
            "e2t": True,
            "dlni": True,
            "sort": "n",
            "crop": "",
        }

        config = self.builder.build_volume_listing_config(vn, vf)

        self.assertTrue(config["idx"])
        self.assertTrue(config["itag"])
        self.assertTrue(config["dlni"])
        self.assertFalse(config["dgrid"])  # grid not in vf, so False
        self.assertEqual(config["sort"], "n")

    def test_build_volume_html_config(self) -> None:
        """Test building volume HTML config."""
        vn = MagicMock()
        vf = {
            "e2d": True,
            "shr_who": "owner",
            "mth": [],
        }

        args = MagicMock()
        args.spinner = "entropy"
        args.bname = "copyparty"
        args.idp_login = ""
        args.no_acode = False
        args.shr = "[s]"

        listing_config = {"dlni": True, "dgrid": False, "sb_lg": "y", "sb_md": ""}

        config = self.builder.build_volume_html_config(vn, vf, args, listing_config)

        self.assertEqual(config["SPINNER"], "entropy")
        self.assertEqual(config["s_name"], "copyparty")
        self.assertTrue(config["have_up2k_idx"])
        self.assertTrue(config["have_shr"])
        self.assertTrue(config["dlni"])

    def test_build_all_volume_configs(self) -> None:
        """Test building all volume configs."""
        vn1 = MagicMock()
        vn1.flags = {
            "e2d": True,
            "sort": "n",
            "crop": "",
            "shr_who": "",
            "mth": [],
        }

        vn2 = MagicMock()
        vn2.flags = {}

        vfs = MagicMock()
        vfs.all_nodes = {"media": vn1, "backup": vn2}

        args = MagicMock()
        args.spinner = "entropy"
        args.bname = "copyparty"
        args.idp_login = ""
        args.no_acode = False
        args.shr = "[s]"
        args.turbo = 0

        js_ls, js_htm = self.builder.build_all_volume_configs(vfs, args, enshare=True)

        # Verify configs were built for both volumes
        self.assertIn("media", js_ls)
        self.assertIn("backup", js_ls)
        self.assertIn("media", js_htm)
        self.assertIn("backup", js_htm)

        # Verify configuration structure
        self.assertTrue("sort" in js_ls["media"])
        self.assertTrue("SPINNER" in js_htm["media"])


if __name__ == "__main__":
    unittest.main()
