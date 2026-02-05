"""Unit tests for config builder modules."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.vfs_builder import VFSBuilder
from copyparty.config.permissions import PermissionResolver


class TestVFSBuilder(unittest.TestCase):
    """Test VFSBuilder class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.builder = VFSBuilder(self.log_func)

    def test_builder_instantiation(self) -> None:
        """Test that builder can be instantiated."""
        self.assertIsNotNone(self.builder)
        self.assertEqual(self.builder.log, self.log_func)

    def test_builder_methods_exist(self) -> None:
        """Test that required methods exist."""
        self.assertTrue(hasattr(self.builder, "build_tree"))
        self.assertTrue(hasattr(self.builder, "build_volume_index"))
        self.assertTrue(callable(self.builder.build_tree))
        self.assertTrue(callable(self.builder.build_volume_index))


class TestPermissionResolver(unittest.TestCase):
    """Test PermissionResolver class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.resolver = PermissionResolver(self.log_func)

    def test_resolver_instantiation(self) -> None:
        """Test that resolver can be instantiated."""
        self.assertIsNotNone(self.resolver)
        self.assertEqual(self.resolver.log, self.log_func)

    def test_resolver_methods_exist(self) -> None:
        """Test that required methods exist."""
        self.assertTrue(hasattr(self.resolver, "resolve_permissions"))
        self.assertTrue(hasattr(self.resolver, "build_user_access_tuples"))
        self.assertTrue(hasattr(self.resolver, "validate_user_references"))
        self.assertTrue(callable(self.resolver.resolve_permissions))
        self.assertTrue(callable(self.resolver.build_user_access_tuples))
        self.assertTrue(callable(self.resolver.validate_user_references))

    def test_validate_user_references_returns_tuple(self) -> None:
        """Test that validate_user_references returns expected structure."""
        acct = {"user1": "pass"}
        idp_accs = set()

        # Create minimal mock
        axs = MagicMock()
        axs.uread = {"user1"}
        axs.uwrite = set()
        axs.umove = set()
        axs.udel = set()
        axs.uget = set()
        axs.upget = set()
        axs.uhtml = set()
        axs.uadmin = set()
        axs.udot = set()

        vol1 = MagicMock()
        vol1.axs = axs

        vfs = MagicMock()
        vfs.all_vols = {"/media": vol1}

        result = self.resolver.validate_user_references(vfs, acct, idp_accs, False)

        # Should return a tuple of 3 dicts
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        self.assertIsInstance(result[0], dict)  # all_users
        self.assertIsInstance(result[1], dict)  # missing_users
        self.assertIsInstance(result[2], dict)  # associated_users


if __name__ == "__main__":
    unittest.main()
