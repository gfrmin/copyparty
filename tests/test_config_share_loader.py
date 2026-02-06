"""Unit tests for share loader module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.share_loader import ShareLoader


class TestShareLoader(unittest.TestCase):
    """Test ShareLoader class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.loader = ShareLoader(self.log_func)

    def test_loader_instantiation(self) -> None:
        """Test that loader can be instantiated."""
        self.assertIsNotNone(self.loader)
        self.assertEqual(self.loader.log, self.log_func)

    def test_load_shares_disabled(self) -> None:
        """Test load_shares with shares disabled."""
        args = MagicMock()
        args.shr = None

        result = self.loader.load_shares(
            MagicMock(),
            {},
            args,
            MagicMock(),
            MagicMock(),
            MagicMock(),
            lambda x: x,
        )

        # Should return empty tuple
        self.assertEqual(result[0], None)
        self.assertEqual(result[1], "")

    def test_load_shares_creates_share_volume(self) -> None:
        """Test that share volume is created."""
        args = MagicMock()
        args.shr = "[s]"
        args.shr_db = ":memory:"
        args.shr_v = False

        vfs = MagicMock()
        vfs.nodes = {}
        vfs.all_vols = {}
        vfs.all_nodes = {}

        acct = {}

        db = MagicMock()
        cur = MagicMock()
        cur.execute = MagicMock(return_value=[])
        db.cursor = MagicMock(return_value=cur)

        VFS = MagicMock(return_value=MagicMock())
        AXS = MagicMock()
        ub64enc = lambda x: b"s_test"

        shv, shr, shrs, db_path = self.loader.load_shares(
            vfs, acct, args, db, VFS, AXS, ub64enc
        )

        # Verify share volume was created
        self.assertIsNotNone(shv)
        self.assertEqual(shr, "s")
        self.assertEqual(shrs, "s/")

    def test_map_shares_disabled(self) -> None:
        """Test map_shares with no share volume."""
        args = MagicMock()

        # Should not raise
        self.loader.map_shares(
            MagicMock(),
            None,
            args,
            MagicMock(),
            lambda x, y: x + "/" + y,
            lambda x: True,
            lambda x: False,
            lambda x: False,
        )


if __name__ == "__main__":
    unittest.main()
