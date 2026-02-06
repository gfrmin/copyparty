"""Configuration orchestrator for copyparty reload cycle.

Coordinates parsing, building, validation, and configuration of the VFS.
"""

from typing import Any, Callable, Dict, List, Optional, Set


class ReloadOrchestrator:
    """Orchestrates the complete reload cycle.

    Coordinates modules:
    - AccountParser, GroupParser, VolspecParser (parsers)
    - VFSBuilder (vfs_builder)
    - PermissionResolver (permissions)
    - UserValidator, VolumeValidator (validators)
    - VolflagValidator, VolflagConverter, LimitationBuilder (volflag_processor)
    - PathResolver (path_resolver)
    """

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize orchestrator with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def reload(
        self,
        args: Any,
        parsers: Any,
        vfs_builder: Any,
        permission_resolver: Any,
        validators: Any,
        volflag_processor: Any,
        path_resolver: Any,
        share_repo: Optional[Any] = None,
        idp_accs: Optional[Set[str]] = None,
    ) -> Any:
        """Execute complete reload cycle.

        Args:
            args: Command-line arguments
            parsers: Module containing AccountParser, GroupParser, VolspecParser
            vfs_builder: VFSBuilder instance
            permission_resolver: PermissionResolver instance
            validators: Module with UserValidator and VolumeValidator
            volflag_processor: Module with VolflagValidator, VolflagConverter, LimitationBuilder
            path_resolver: PathResolver instance
            share_repo: Optional ShareRepository instance
            idp_accs: Set of IdP-managed accounts

        Returns:
            Configured VFS root node
        """
        if idp_accs is None:
            idp_accs = set()

        # Step 1: Parse configuration from arguments
        acct, grps, mflags, mount = self._parse_config(args, parsers)

        # Step 2: Build VFS tree
        vfs = vfs_builder.build_tree(mount, mflags, args)

        # Step 3: Validate user existence and setup
        all_users, missing_users, associated_users = self._validate_users(
            vfs, acct, idp_accs, validators, args
        )

        # Step 4: Resolve permissions
        permission_resolver.resolve_permissions(vfs, acct, grps, idp_accs, args.shr)

        # Step 5: Process volume flags
        self._process_volflags(vfs, volflag_processor, args)

        # Step 6: Resolve paths (histpath, dbpath)
        path_resolver.resolve_histpath(vfs, args)
        path_resolver.resolve_dbpath(vfs, args)
        path_resolver.check_path_conflicts(vfs)

        # Step 7: Load shares if enabled
        if args.shr and share_repo:
            self._load_shares(vfs, acct, args, share_repo)

        # Step 8: Apply robots metadata
        volflag_processor.apply_robots_flag(vfs, args.no_robots)

        return vfs

    def _parse_config(self, args: Any, parsers: Any) -> tuple:
        """Parse CLI arguments into configuration dicts.

        Args:
            args: Command-line arguments
            parsers: Module with AccountParser, GroupParser, VolspecParser

        Returns:
            Tuple of (acct, grps, mflags, mount)
        """
        account_parser = parsers.AccountParser(self.log)
        group_parser = parsers.GroupParser(self.log)
        volspec_parser = parsers.VolspecParser(self.log)

        acct = account_parser.parse(getattr(args, "a", None))
        grps = group_parser.parse(getattr(args, "grp", None))
        mflags, mount = volspec_parser.parse(getattr(args, "v", None))

        return acct, grps, mflags, mount

    def _validate_users(self, vfs: Any, acct: Dict, idp_accs: Set, validators: Any, args: Any) -> tuple:
        """Validate user existence and permissions.

        Args:
            vfs: VFS root node
            acct: Account dict
            idp_accs: IdP-managed accounts
            validators: Module with UserValidator and VolumeValidator
            args: Command-line arguments

        Returns:
            Tuple of (all_users, missing_users, associated_users)
        """
        user_validator = validators.UserValidator(self.log)
        vol_validator = validators.VolumeValidator(self.log)

        # Validate that all referenced users exist
        all_users, missing_users, associated_users = None, {}, {}

        user_validator.validate_all_users_exist(all_users, missing_users, acct, bool(args.idp_hdrs))
        user_validator.validate_reserved_usernames(all_users)

        # Warn about unreferenced accounts
        user_validator.warn_unreferenced_accounts(
            acct, associated_users, bool(args.shr), len(vfs.all_vols)
        )

        # Validate volume paths
        errors, dropvols = vol_validator.validate_volume_paths(vfs, args.vol_or_crash, args.vol_nospawn)
        for vol in dropvols:
            vfs.all_vols.pop(vol.vpath, None)

        return all_users, missing_users, associated_users

    def _process_volflags(self, vfs: Any, volflag_processor: Any, args: Any) -> None:
        """Process volume flags.

        Args:
            vfs: VFS root node
            volflag_processor: Module with VolflagValidator, VolflagConverter, LimitationBuilder
            args: Command-line arguments
        """
        validator = volflag_processor.VolflagValidator(self.log)
        converter = volflag_processor.VolflagConverter(self.log)
        builder = volflag_processor.LimitationBuilder(self.log)

        validator.validate_flags(vfs)
        converter.convert_zipmax(vfs)
        builder.build_limitations(vfs)

    def _load_shares(self, vfs: Any, acct: Dict, args: Any, share_repo: Any) -> None:
        """Load shares from database.

        Args:
            vfs: VFS root node
            acct: Account dict
            args: Command-line arguments
            share_repo: ShareRepository instance
        """
        # Placeholder for share loading logic
        # Would integrate with ShareRepository
        pass
