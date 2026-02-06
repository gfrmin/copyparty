"""Flag type conversion and validation for copyparty volumes.

Converts volume flags from strings to appropriate Python types.
"""

import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class FlagConverter:
    """Convert and validate volume flags."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize converter with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def convert_integer_flags(self, vfs: Any, flag_names: List[str]) -> None:
        """Convert specified flags to integers.

        Args:
            vfs: Root VFS node containing all_nodes
            flag_names: List of flag names to convert
        """
        for vol in vfs.all_nodes.values():
            for k in flag_names:
                if k in vol.flags:
                    try:
                        vol.flags[k] = int(vol.flags[k])
                    except (ValueError, TypeError):
                        msg = f'volume "/{vol.vpath}" has invalid {k} value: {vol.flags[k]}'
                        self.log(msg, 1)

    def convert_float_flags(self, vfs: Any, flag_names: List[str]) -> None:
        """Convert specified flags to floats.

        Args:
            vfs: Root VFS node containing all_nodes
            flag_names: List of flag names to convert
        """
        for vol in vfs.all_nodes.values():
            for k in flag_names:
                if k in vol.flags:
                    try:
                        vol.flags[k] = float(vol.flags[k])
                    except (ValueError, TypeError):
                        msg = f'volume "/{vol.vpath}" has invalid {k} value: {vol.flags[k]}'
                        self.log(msg, 1)

    def convert_chmod_flags(self, vfs: Any) -> Tuple[bool, bool]:
        """Convert and validate chmod flags.

        Args:
            vfs: Root VFS node containing all_nodes

        Returns:
            Tuple of (free_umask, any_chmod_set)

        Raises:
            Exception: If chmod values are invalid
        """
        free_umask = False

        for vol in vfs.all_nodes.values():
            for k in ("chmod_d", "chmod_f"):
                is_d = k == "chmod_d"
                zs = vol.flags.get(k, "")

                if not zs and is_d:
                    zs = "755"

                if not zs:
                    vol.flags.pop(k, None)
                    continue

                # Validate octal format
                if not re.match(r"^[0-7]{3}$", zs):
                    msg = (
                        f"config-option '{k}' must be a three-digit octal value "
                        f"such as [755] or [644] but the value was [{zs}]"
                    )
                    self.log(msg, 1)
                    raise Exception(msg)

                zi = int(zs, 8)
                vol.flags[k] = zi

                if (is_d and zi != 0o755) or not is_d:
                    free_umask = True

        return free_umask

    def apply_ownership_flags(self, vfs: Any) -> None:
        """Apply uid/gid and related ownership flags.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        for vol in vfs.all_nodes.values():
            # Remove chown flag if not setting uid/gid
            vol.flags.pop("chown", None)
            if vol.flags.get("uid", -1) != -1 or vol.flags.get("gid", -1) != -1:
                vol.flags["chown"] = True

            # Set file permissions flag
            vol.flags.pop("fperms", None)
            if "chown" in vol.flags or vol.flags.get("chmod_f"):
                vol.flags["fperms"] = True

            # Apply to limiter if present
            if vol.lim:
                vol.lim.chmod_d = vol.flags.get("chmod_d", 0o755)
                vol.lim.chown = "chown" in vol.flags
                vol.lim.uid = vol.flags.get("uid", -1)
                vol.lim.gid = vol.flags.get("gid", -1)

    def validate_database_strategy(self, vfs: Any, args: Any) -> None:
        """Validate database strategy (dbd) setting.

        Args:
            vfs: Root VFS node containing all_nodes
            args: Command-line arguments

        Raises:
            Exception: If dbd value is invalid
        """
        valid_strategies = ["acid", "swal", "wal", "yolo"]

        for vol in vfs.all_nodes.values():
            dbd = vol.flags.get("dbd") or getattr(args, "dbd", "acid")
            vol.flags["dbd"] = dbd

            if dbd not in valid_strategies:
                msg = (
                    f'volume "/{vol.vpath}" has invalid dbd [{dbd}]; '
                    f"must be one of {valid_strategies}"
                )
                self.log(msg, 1)
                raise Exception(msg)

    def apply_default_metadata_configs(self, vfs: Any, args: Any) -> None:
        """Apply default metadata configurations to volumes.

        Args:
            vfs: Root VFS node containing all_nodes
            args: Command-line arguments with metadata defaults
        """
        metadata_keys = ("mte", "mth", "exp_md", "exp_lg")

        for vol in vfs.all_nodes.values():
            for k in metadata_keys:
                if k not in vol.flags:
                    vol.flags[k] = getattr(args, k, {}).copy()
