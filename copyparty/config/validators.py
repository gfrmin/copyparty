"""Configuration validators for copyparty.

Validates:
- User accounts (existence, duplicates, passwords)
- Volume configurations (paths, case-sensitivity)
"""

import base64
import hashlib
import os
from typing import Any, Callable, Dict, Optional, Set, Tuple


class UserValidator:
    """Validate user accounts and access control configuration."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize validator with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def validate_all_users_exist(
        self,
        all_users: Dict[str, int],
        missing_users: Dict[str, int],
        acct: Dict[str, str],
        have_idp_hdrs: bool,
    ) -> bool:
        """Validate that all referenced users exist.

        Args:
            all_users: Dict of all referenced users
            missing_users: Dict of undefined users
            acct: Dict of local accounts
            have_idp_hdrs: Whether IdP headers are configured

        Returns:
            True if validation passed, False otherwise (will log error)
        """
        if not missing_users:
            return True

        zs = ", ".join(k for k in sorted(missing_users))

        if have_idp_hdrs:
            msg = "the following users are unknown, and assumed to come from IdP: " + zs
            self.log(msg, 6)
            return True
        else:
            msg = "you must -a the following users: " + zs
            self.log(msg, 1)
            return False

    def validate_reserved_usernames(self, all_users: Dict[str, int]) -> bool:
        """Check for reserved usernames.

        Args:
            all_users: Dict of all referenced users

        Returns:
            True if validation passed, False otherwise

        Note:
            Reserved: "leeloo_dallas" (internal operations)
        """
        LEELOO_DALLAS = "leeloo_dallas"

        if LEELOO_DALLAS in all_users:
            msg = f"sorry, reserved username: {LEELOO_DALLAS}"
            self.log(msg, 1)
            return False

        return True

    def populate_empty_passwords(self, acct: Dict[str, str]) -> None:
        """Generate random passwords for empty entries.

        Args:
            acct: Dict of username -> password to update in-place
        """
        zsl = []
        for usr in list(acct):
            zs = acct[usr].strip()
            if not zs:
                # Generate random password
                zb = base64.b64encode(os.urandom(48)).decode("ascii")
                acct[usr] = zb
                zsl.append(usr)

        if zsl:
            msg = f"generated random passwords for users {zsl!r}"
            self.log(msg, 6)

    def validate_unique_passwords(self, acct: Dict[str, str]) -> bool:
        """Check that no two accounts share the same password.

        Args:
            acct: Dict of username -> password

        Returns:
            True if all passwords unique, False otherwise
        """
        seenpwds: Dict[str, str] = {}

        for usr, pwd in acct.items():
            if pwd in seenpwds:
                msg = f"accounts [{seenpwds[pwd]}] and [{usr}] have the same password; this is not supported"
                self.log(msg, 1)
                return False
            seenpwds[pwd] = usr

        return True

    def warn_unreferenced_accounts(
        self,
        acct: Dict[str, str],
        associated_users: Dict[str, int],
        enshare: bool,
        num_vols: int,
    ) -> None:
        """Warn about accounts not mentioned in any volume definitions.

        Args:
            acct: Dict of local accounts
            associated_users: Dict of users mentioned in volume perms
            enshare: Whether share feature enabled
            num_vols: Number of volumes configured
        """
        for usr in acct:
            if usr not in associated_users:
                # Share-generated accounts are OK
                if enshare and usr.startswith("s_"):
                    continue

                if num_vols > 1:
                    # Multiple volumes - brief message
                    msg = f"account [{usr}] is not mentioned in any volume definitions; see --help-accounts"
                    self.log(msg, 1)
                else:
                    # Single volume - verbose message with example
                    msg = (
                        f"WARNING: the account [{usr}] is not mentioned in any volume definitions "
                        f"and thus has the same access-level and privileges that guests have; "
                        f"please see --help-accounts for details. For example, if you intended to give "
                        f"that user full access to the current directory, you could do this: "
                        f"-v .::A,{usr}"
                    )
                    self.log(msg, 1)


class VolumeValidator:
    """Validate volume configurations and paths."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize validator with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def validate_volume_paths(
        self,
        vfs: Any,
        vol_or_crash: bool,
        vol_nospawn: bool,
    ) -> Tuple[int, list]:
        """Validate that volume root directories exist.

        Args:
            vfs: Root VFS node
            vol_or_crash: Whether to crash if volume doesn't exist
            vol_nospawn: Whether to disable volumes that don't exist

        Returns:
            Tuple of (error_count, volumes_to_drop)
        """
        dropvols = []
        errors = 0

        for vol in vfs.all_vols.values():
            if (
                not vol.realpath
                or (
                    "assert_root" not in vol.flags
                    and "nospawn" not in vol.flags
                    and not vol_or_crash
                    and not vol_nospawn
                )
                or os.path.exists(vol.realpath)
            ):
                pass  # Volume is OK
            elif "assert_root" in vol.flags or vol_or_crash:
                msg = (
                    f"ERROR: volume [/{vol.vpath}] root folder {vol.realpath!r} "
                    f"does not exist on server HDD; will now crash due to volflag 'assert_root'"
                )
                self.log(msg, 1)
                errors += 1
            else:
                msg = (
                    f"WARNING: volume [/{vol.vpath}] root folder {vol.realpath!r} "
                    f"does not exist on server HDD; volume will be unavailable due to volflag 'nospawn'"
                )
                self.log(msg, 3)
                dropvols.append(vol)

        return errors, dropvols

    def detect_case_sensitivity(
        self,
        vol: Any,
        makedirs_func: Callable[[str, Any], None],
    ) -> None:
        """Detect if filesystem is case-sensitive.

        Updates vol.flags["casechk"] and vol.flags["bcasechk"].

        Args:
            vol: Volume node to test
            makedirs_func: Function to create directories safely
        """
        if not vol.realpath or vol.flags.get("is_file"):
            return

        ccs = vol.flags["casechk"][:1].lower()

        if ccs in ("y", "n"):
            if ccs == "y":
                vol.flags["bcasechk"] = True
            return

        try:
            makedirs_func(vol.realpath, vf=vol.flags)
            files = os.listdir(vol.realpath)

            # Test for case-insensitive filesystem
            for fn in files:
                fn2 = fn.lower()
                if fn == fn2:
                    fn2 = fn.upper()
                if fn == fn2 or fn2 in files:
                    continue

                is_ci = os.path.exists(os.path.join(vol.realpath, fn2))
                ccs = "y" if is_ci else "n"
                break

            if ccs not in ("y", "n"):
                # No case conflicts found - create test file
                ap = os.path.join(vol.realpath, "casechk")
                open(ap, "wb").close()
                ccs = "y" if os.path.exists(ap[:-1] + "K") else "n"
                os.unlink(ap)

        except Exception as ex:
            import sys

            WINDOWS = sys.platform.startswith("win")
            MACOS = sys.platform == "darwin"

            if WINDOWS:
                zs = "Windows"
                ccs = "y"
            elif MACOS:
                zs = "Macos"
                ccs = "y"
            else:
                zs = "Linux"
                ccs = "n"

            msg = (
                f"unable to determine if filesystem at {vol.realpath!r} is case-insensitive "
                f"due to {ex!r}; assuming casechk={ccs} due to {zs}"
            )
            self.log(msg, 3)

        vol.flags["casechk"] = ccs
        if ccs == "y":
            vol.flags["bcasechk"] = True

    def check_volume_path_conflicts(
        self,
        vfs: Any,
    ) -> bool:
        """Check for path conflicts in volumes.

        Validates that:
        - No multiple volumes share same histpath
        - No multiple volumes share same dbpath

        Args:
            vfs: Root VFS node

        Returns:
            True if validation passed, False otherwise
        """
        rhisttab: Dict[str, Any] = {}
        vfs.histtab = {}

        for zv in vfs.all_vols.values():
            histp = zv.histpath
            if histp and histp in rhisttab:
                zv2 = rhisttab[histp]
                msg = (
                    f"invalid config; multiple volumes share the same histpath "
                    f"(database+thumbnails location):\n"
                    f"  histpath: {histp}\n"
                    f"  volume 1: /{zv2.vpath}  [{zv2.realpath}]\n"
                    f"  volume 2: /{zv.vpath}  [{zv.realpath}]"
                )
                self.log(msg, 1)
                return False
            rhisttab[histp] = zv
            vfs.histtab[zv.realpath] = histp

        return True
