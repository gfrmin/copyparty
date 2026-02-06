"""Unit tests for path resolver module."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.path_resolver import PathResolver


class TestPathResolver(unittest.TestCase):
    """Test PathResolver class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.resolver = PathResolver(self.log_func)

    def test_resolver_instantiation(self) -> None:
        """Test that resolver can be instantiated."""
        self.assertIsNotNone(self.resolver)
        self.assertEqual(self.resolver.log, self.log_func)

    def test_get_hash_id_caching(self) -> None:
        """Test hash ID caching."""
        realpath = "/srv/media"
        afsenc = lambda x: x.encode("utf-8")

        hid1 = self.resolver.get_hash_id(realpath, afsenc)
        hid2 = self.resolver.get_hash_id(realpath, afsenc)

        # Should return same cached value
        self.assertEqual(hid1, hid2)
        # Should be base32-encoded
        self.assertTrue(all(c in "abcdefghijklmnopqrstuvwxyz234567=" for c in hid1))

    def test_resolve_histpath_with_flag(self) -> None:
        """Test histpath resolution with volume flag."""
        vol = MagicMock()
        vol.realpath = "/srv/media"
        vol.flags = {"hist": "/custom/hist"}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        args = MagicMock()
        args.hist = "/default/hist"

        afsenc = lambda x: x.encode("utf-8")
        absreal = lambda x: x
        makedirs = MagicMock()
        uncyg = lambda x: x
        WINDOWS = False

        self.resolver.resolve_histpath(vfs, args, afsenc, absreal, makedirs, uncyg, WINDOWS)

        # Should use volume-specific flag
        self.assertEqual(vol.histpath, "/custom/hist")

    def test_resolve_dbpath_with_flag(self) -> None:
        """Test dbpath resolution with volume flag."""
        vol = MagicMock()
        vol.realpath = "/srv/media"
        vol.flags = {"dbpath": "/custom/db"}

        vfs = MagicMock()
        vfs.all_vols = {"media": vol}

        args = MagicMock()
        args.dbpath = "/default/db"

        afsenc = lambda x: x.encode("utf-8")
        absreal = lambda x: x
        makedirs = MagicMock()
        uncyg = lambda x: x
        WINDOWS = False

        self.resolver.resolve_dbpath(vfs, args, afsenc, absreal, makedirs, uncyg, WINDOWS)

        # Should use volume-specific flag
        self.assertEqual(vol.dbpath, "/custom/db")

    def test_check_path_conflicts_no_conflicts(self) -> None:
        """Test checking for conflicts when none exist."""
        vol1 = MagicMock()
        vol1.vpath = "media"
        vol1.realpath = "/srv/media"
        vol1.histpath = "/hist1"
        vol1.dbpath = "/db1"

        vol2 = MagicMock()
        vol2.vpath = "backup"
        vol2.realpath = "/srv/backup"
        vol2.histpath = "/hist2"
        vol2.dbpath = "/db2"

        vfs = MagicMock()
        vfs.all_vols = {"media": vol1, "backup": vol2}

        is_share = lambda v: False

        # Should not raise
        self.resolver.check_path_conflicts(vfs, is_share)

        # Should populate tables
        self.assertEqual(vfs.histtab["/srv/media"], "/hist1")
        self.assertEqual(vfs.dbpaths["/srv/media"], "/db1")

    def test_check_path_conflicts_histpath_conflict(self) -> None:
        """Test checking for histpath conflicts."""
        vol1 = MagicMock()
        vol1.vpath = "media1"
        vol1.realpath = "/srv/media1"
        vol1.histpath = "/same/hist"

        vol2 = MagicMock()
        vol2.vpath = "media2"
        vol2.realpath = "/srv/media2"
        vol2.histpath = "/same/hist"

        vfs = MagicMock()
        vfs.all_vols = {"media1": vol1, "media2": vol2}

        is_share = lambda v: False

        # Should raise exception
        with self.assertRaises(Exception):
            self.resolver.check_path_conflicts(vfs, is_share)


if __name__ == "__main__":
    unittest.main()
