"""Configuration parsers for copyparty.

Extracts and parses:
- Account credentials (-a username:password)
- Group memberships (--grp groupname:username1,username2)
- Volume specifications (-v src:dst:perms)
- Config files (-c config.conf)
"""

import re
from typing import Any, Callable, Dict, List, Optional, Tuple


class AccountParser:
    """Parse and validate account credentials from command-line arguments."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize parser with logging function."""
        self.log = log_func

    def parse(self, args: Optional[List[str]]) -> Dict[str, str]:
        """
        Parse account arguments in format 'username:password'.

        Args:
            args: List of 'username:password' strings, or None/empty list

        Returns:
            Dict mapping username -> password

        Raises:
            Exception: If any account argument has invalid format
        """
        acct: Dict[str, str] = {}

        if not args:
            return acct

        for arg in args:
            try:
                username, password = arg.split(":", 1)
                acct[username] = password
            except (ValueError, TypeError, IndexError) as e:
                msg = f'\n  invalid value "{arg}" for argument -a, must be username:password'
                raise Exception(msg) from e

        return acct


class GroupParser:
    """Parse and validate group definitions from command-line arguments."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize parser with logging function."""
        self.log = log_func

    def parse(self, args: Optional[List[str]]) -> Dict[str, List[str]]:
        """
        Parse group arguments in format 'groupname:username1,username2'.

        Flexible format:
        - Accepts both '=' and ':' as groupname/members separator
        - Accepts both ',' and ':' as username separators

        Args:
            args: List of 'groupname:username1,username2' strings, or None/empty list

        Returns:
            Dict mapping groupname -> list of usernames

        Raises:
            Exception: If any group argument has invalid format
        """
        grps: Dict[str, List[str]] = {}

        if not args:
            return grps

        for arg in args:
            try:
                # Normalize: accept both = and : as separator
                normalized = arg.replace("=", ":")
                groupname, members_str = normalized.split(":", 1)

                # Normalize member separator: accept both , and :
                members_str = members_str.replace(":", ",")
                members = [m.strip() for m in members_str.split(",")]
                members = [m for m in members if m]  # Remove empty

                grps[groupname] = members
            except (ValueError, TypeError, IndexError) as e:
                msg = f'\n  invalid value "{arg}" for argument --grp, must be groupname:username1,username2,...'
                raise Exception(msg) from e

        return grps


class VolspecParser:
    """Parse and validate volume specifications from command-line arguments."""

    # Regex for volume specification: src:dst:perms format
    # Allows escaped colons in paths
    RE_VOLSPEC = re.compile(
        r"^(.+?):(.+?)(?::(.+))?$"
    )

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize parser with logging function."""
        self.log = log_func

    def parse(self, args: Optional[List[str]]) -> List[Tuple[str, str, str]]:
        """
        Parse volume specification arguments in format 'src:dst:permset'.

        Format:
        - src: source path on server (required)
        - dst: destination path in VFS (required)
        - permset: permission set spec (optional, default empty)
          Format: 'rwmdgGhaA.,[username],[username]' or 'c,flag[=args]'

        Args:
            args: List of 'src:dst:permset' strings, or None/empty list

        Returns:
            List of (src, dst, perms) tuples

        Raises:
            Exception: If any volume spec has invalid format
        """
        vols: List[Tuple[str, str, str]] = []

        if not args:
            return vols

        for arg in args:
            try:
                # Simple split by colon (3 parts: src:dst:perms)
                parts = arg.split(":", 2)
                if len(parts) < 2:
                    raise ValueError(f"need at least src:dst, got: {arg}")

                src = parts[0]
                dst = parts[1]
                perms = parts[2] if len(parts) > 2 else ""

                vols.append((src, dst, perms))
            except (ValueError, TypeError, IndexError) as e:
                msg = f'invalid -v argument: [{arg}]'
                raise Exception(msg) from e

        return vols
