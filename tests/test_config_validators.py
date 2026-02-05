"""Unit tests for config validator modules."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock
from copyparty.config.validators import UserValidator, VolumeValidator


class TestUserValidator(unittest.TestCase):
    """Test UserValidator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.validator = UserValidator(self.log_func)

    def test_validator_instantiation(self) -> None:
        """Test that validator can be instantiated."""
        self.assertIsNotNone(self.validator)
        self.assertEqual(self.validator.log, self.log_func)

    def test_validator_methods_exist(self) -> None:
        """Test that required methods exist."""
        self.assertTrue(hasattr(self.validator, "validate_all_users_exist"))
        self.assertTrue(hasattr(self.validator, "validate_reserved_usernames"))
        self.assertTrue(hasattr(self.validator, "populate_empty_passwords"))
        self.assertTrue(hasattr(self.validator, "validate_unique_passwords"))
        self.assertTrue(hasattr(self.validator, "warn_unreferenced_accounts"))

    def test_validate_all_users_exist_no_missing(self) -> None:
        """Test validation when all users exist."""
        all_users = {"user1": 1, "user2": 1}
        missing_users = {}
        acct = {"user1": "pass1", "user2": "pass2"}

        result = self.validator.validate_all_users_exist(all_users, missing_users, acct, False)
        self.assertTrue(result)

    def test_validate_all_users_exist_with_missing_no_idp(self) -> None:
        """Test validation with missing users and no IdP."""
        all_users = {"user1": 1, "undefined": 1}
        missing_users = {"undefined": 1}
        acct = {"user1": "pass1"}

        result = self.validator.validate_all_users_exist(all_users, missing_users, acct, False)
        self.assertFalse(result)
        self.log_func.assert_called()

    def test_validate_reserved_usernames_no_conflict(self) -> None:
        """Test validation with no reserved usernames."""
        all_users = {"user1": 1, "user2": 1}
        result = self.validator.validate_reserved_usernames(all_users)
        self.assertTrue(result)

    def test_populate_empty_passwords(self) -> None:
        """Test populating empty passwords."""
        acct = {"user1": "password", "user2": "", "user3": "  "}

        self.validator.populate_empty_passwords(acct)

        # Non-empty passwords should be unchanged
        self.assertEqual(acct["user1"], "password")

        # Empty passwords should be replaced
        self.assertNotEqual(acct["user2"], "")
        self.assertTrue(len(acct["user2"]) > 0)

        self.assertNotEqual(acct["user3"], "  ")
        self.assertTrue(len(acct["user3"]) > 0)

    def test_validate_unique_passwords_all_unique(self) -> None:
        """Test validation when all passwords are unique."""
        acct = {"user1": "pass1", "user2": "pass2", "user3": "pass3"}
        result = self.validator.validate_unique_passwords(acct)
        self.assertTrue(result)

    def test_validate_unique_passwords_duplicate(self) -> None:
        """Test validation when passwords are duplicated."""
        acct = {"user1": "samepass", "user2": "samepass"}
        result = self.validator.validate_unique_passwords(acct)
        self.assertFalse(result)
        self.log_func.assert_called()


class TestVolumeValidator(unittest.TestCase):
    """Test VolumeValidator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.validator = VolumeValidator(self.log_func)

    def test_validator_instantiation(self) -> None:
        """Test that validator can be instantiated."""
        self.assertIsNotNone(self.validator)
        self.assertEqual(self.validator.log, self.log_func)

    def test_validator_methods_exist(self) -> None:
        """Test that required methods exist."""
        self.assertTrue(hasattr(self.validator, "validate_volume_paths"))
        self.assertTrue(hasattr(self.validator, "detect_case_sensitivity"))
        self.assertTrue(hasattr(self.validator, "check_volume_path_conflicts"))

    def test_validate_volume_paths_existing_paths(self) -> None:
        """Test validation with existing volume paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a volume with existing path
            vol = MagicMock()
            vol.realpath = tmpdir
            vol.vpath = "media"
            vol.flags = {}

            vfs = MagicMock()
            vfs.all_vols = {"media": vol}

            errors, dropvols = self.validator.validate_volume_paths(vfs, False, False)

            self.assertEqual(errors, 0)
            self.assertEqual(len(dropvols), 0)

    def test_validate_volume_paths_missing_with_assert_root(self) -> None:
        """Test validation with missing path and assert_root flag."""
        vol = MagicMock()
        vol.realpath = "/nonexistent/path"
        vol.vpath = "missing"
        vol.flags = {"assert_root": True}

        vfs = MagicMock()
        vfs.all_vols = {"missing": vol}

        errors, dropvols = self.validator.validate_volume_paths(vfs, False, False)

        self.assertGreater(errors, 0)
        self.assertEqual(len(dropvols), 0)

    def test_detect_case_sensitivity_with_existing_setting(self) -> None:
        """Test case sensitivity detection with preset value."""
        vol = MagicMock()
        vol.realpath = "/some/path"
        # Use MagicMock for flags so we can set methods
        flags_mock = MagicMock()
        flags_mock.__getitem__ = MagicMock(side_effect=lambda k: {"casechk": "y"}.get(k))
        flags_mock.__setitem__ = MagicMock()
        flags_mock.get = MagicMock(return_value=None)  # is_file = False
        vol.flags = flags_mock

        self.validator.detect_case_sensitivity(vol, MagicMock())

        # Verify that the method ran without error and set bcasechk
        flags_mock.__setitem__.assert_called()

    def test_check_volume_path_conflicts_no_conflicts(self) -> None:
        """Test path conflict checking with no conflicts."""
        vol1 = MagicMock()
        vol1.vpath = "media"
        vol1.realpath = "/srv/media"
        vol1.histpath = "/data/hist1"

        vol2 = MagicMock()
        vol2.vpath = "backup"
        vol2.realpath = "/srv/backup"
        vol2.histpath = "/data/hist2"

        vfs = MagicMock()
        vfs.all_vols = {"media": vol1, "backup": vol2}
        vfs.histtab = {}

        result = self.validator.check_volume_path_conflicts(vfs)

        self.assertTrue(result)
        self.assertEqual(vfs.histtab[vol1.realpath], vol1.histpath)
        self.assertEqual(vfs.histtab[vol2.realpath], vol2.histpath)


if __name__ == "__main__":
    unittest.main()
