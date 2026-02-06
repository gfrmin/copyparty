"""Unit tests for configuration orchestrator."""

import unittest
from unittest.mock import MagicMock
from copyparty.config.orchestrator import ReloadOrchestrator


class TestReloadOrchestrator(unittest.TestCase):
    """Test ReloadOrchestrator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.log_func = MagicMock()
        self.orchestrator = ReloadOrchestrator(self.log_func)

    def test_orchestrator_instantiation(self) -> None:
        """Test that orchestrator can be instantiated."""
        self.assertIsNotNone(self.orchestrator)
        self.assertEqual(self.orchestrator.log, self.log_func)

    def test_parse_config(self) -> None:
        """Test configuration parsing."""
        args = MagicMock()
        args.a = ["-u user1:pass1"]
        args.grp = []
        args.v = [".:media"]

        parsers = MagicMock()
        parsers.AccountParser = MagicMock(
            return_value=MagicMock(parse=MagicMock(return_value={"user1": "pass1"}))
        )
        parsers.GroupParser = MagicMock(return_value=MagicMock(parse=MagicMock(return_value={})))
        parsers.VolspecParser = MagicMock(
            return_value=MagicMock(parse=MagicMock(return_value=({}, [])))
        )

        acct, grps, mflags, mount = self.orchestrator._parse_config(args, parsers)

        self.assertEqual(acct, {"user1": "pass1"})
        self.assertEqual(grps, {})

    def test_reload_orchestration(self) -> None:
        """Test that reload method coordinates all modules."""
        args = MagicMock()
        args.a = None
        args.grp = None
        args.v = None
        args.shr = None
        args.idp_hdrs = False
        args.vol_or_crash = False
        args.vol_nospawn = False
        args.no_robots = False

        # Mock all modules
        parsers = MagicMock()
        parsers.AccountParser = MagicMock(
            return_value=MagicMock(parse=MagicMock(return_value={}))
        )
        parsers.GroupParser = MagicMock(return_value=MagicMock(parse=MagicMock(return_value={})))
        parsers.VolspecParser = MagicMock(
            return_value=MagicMock(parse=MagicMock(return_value=({}, [])))
        )

        vfs_builder = MagicMock()
        vfs_builder.build_tree = MagicMock(return_value=MagicMock(all_vols={}))

        permission_resolver = MagicMock()
        permission_resolver.resolve_permissions = MagicMock()

        validators = MagicMock()
        validators.UserValidator = MagicMock(
            return_value=MagicMock(
                validate_all_users_exist=MagicMock(),
                validate_reserved_usernames=MagicMock(),
                warn_unreferenced_accounts=MagicMock(),
            )
        )
        validators.VolumeValidator = MagicMock(
            return_value=MagicMock(validate_volume_paths=MagicMock(return_value=(0, [])))
        )

        volflag_processor = MagicMock()
        volflag_processor.VolflagValidator = MagicMock(
            return_value=MagicMock(validate_flags=MagicMock())
        )
        volflag_processor.VolflagConverter = MagicMock(
            return_value=MagicMock(convert_zipmax=MagicMock())
        )
        volflag_processor.LimitationBuilder = MagicMock(
            return_value=MagicMock(
                build_limitations=MagicMock(),
                apply_robots_flag=MagicMock(),
            )
        )

        path_resolver = MagicMock()
        path_resolver.resolve_histpath = MagicMock()
        path_resolver.resolve_dbpath = MagicMock()
        path_resolver.check_path_conflicts = MagicMock()

        # Execute orchestration
        vfs = self.orchestrator.reload(
            args,
            parsers,
            vfs_builder,
            permission_resolver,
            validators,
            volflag_processor,
            path_resolver,
        )

        # Verify all modules were called
        vfs_builder.build_tree.assert_called_once()
        permission_resolver.resolve_permissions.assert_called_once()
        path_resolver.resolve_histpath.assert_called_once()
        path_resolver.resolve_dbpath.assert_called_once()
        path_resolver.check_path_conflicts.assert_called_once()


if __name__ == "__main__":
    unittest.main()
