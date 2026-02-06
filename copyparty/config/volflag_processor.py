"""Volume flag processing for copyparty VFS.

Handles validation, type conversion, and limitation building for volume flags.
"""

import re
from typing import Any, Callable, Dict, Optional


class VolflagValidator:
    """Validate volume flags against schema."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize validator with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def validate_flags(
        self,
        vfs: Any,
        flagdescs: Dict[str, str],
    ) -> None:
        """Validate that all flags are recognized.

        Args:
            vfs: Root VFS node containing all_vols
            flagdescs: Dict of valid flag names -> descriptions
        """
        # Flags to always ignore
        k_ign = set("ext_th landmark mtp on403 on404 xbu xau xiu xbc xac xbr xar xbd xad xm xban".split())

        for vol in vfs.all_vols.values():
            unknown_flags = set()
            for k in vol.flags.keys():
                ks = k.lstrip("-")
                if ks not in flagdescs and ks not in k_ign:
                    unknown_flags.add(k)

            if unknown_flags:
                flags_str = "', '".join(unknown_flags)
                msg = (
                    f"WARNING: the config for volume [/{vol.vpath}] has unrecognized volflags; "
                    f"will ignore: '{flags_str}'"
                )
                self.log(msg, 3)


class VolflagConverter:
    """Convert volume flag values to appropriate types."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize converter with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def convert_zipmax(self, vfs: Any, unhumanize_func: Callable[[str], int]) -> None:
        """Convert zipmax string values to bytes.

        Args:
            vfs: Root VFS node containing all_vols
            unhumanize_func: Function to convert human-readable sizes to bytes
        """
        for vol in vfs.all_vols.values():
            use = False
            for k in ["zipmaxn", "zipmaxs"]:
                try:
                    zs = vol.flags[k]
                except (ValueError, TypeError, UnicodeDecodeError, IndexError, KeyError):
                    continue

                if zs in ("", "0"):
                    vol.flags[k] = 0
                    continue

                zf = unhumanize_func(zs)
                vol.flags[k + "_v"] = zf
                if zf:
                    use = True

            if use:
                vol.flags["zipmax"] = True


class LimitationBuilder:
    """Build limitation objects from volume flags."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize builder with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def build_limitations(self, vfs: Any, unhumanize_func: Callable[[str], int], Lim: type) -> None:
        """Build Lim objects from volume flags.

        Args:
            vfs: Root VFS node containing all_vols
            unhumanize_func: Function to convert human-readable sizes to bytes
            Lim: Limitation class constructor
        """
        for vol in vfs.all_vols.values():
            lim = Lim(self.log)
            use = False

            # nosub: disallow subdirectories
            if vol.flags.get("nosub"):
                use = True
                lim.nosub = True

            # df: free disk space limit
            zs = vol.flags.get("df") or ""
            if zs not in ("", "0"):
                use = True
                try:
                    _ = float(zs)
                    zs = f"{zs}g"
                except (ValueError, TypeError):
                    pass
                lim.dfl = unhumanize_func(zs)

            # sz: filesize min-max range
            zs = vol.flags.get("sz")
            if zs:
                use = True
                lim.smin, lim.smax = [unhumanize_func(x) for x in zs.split("-")]

            # rotn: rotation - number of files per directory, directory depth
            zs = vol.flags.get("rotn")
            if zs:
                use = True
                lim.rotn, lim.rotl = [int(x) for x in zs.split(",")]

            # rotf: rotation - date format
            zs = vol.flags.get("rotf")
            if zs:
                use = True
                lim.set_rotf(zs, vol.flags.get("rotf_tz") or "UTC")

            # maxn: max number of files in window
            zs = vol.flags.get("maxn")
            if zs:
                use = True
                lim.nmax, lim.nwin = [int(x) for x in zs.split(",")]

            # maxb: max bytes in window
            zs = vol.flags.get("maxb")
            if zs:
                use = True
                lim.bmax, lim.bwin = [unhumanize_func(x) for x in zs.split(",")]

            # vmaxb: volume max bytes
            zs = vol.flags.get("vmaxb")
            if zs:
                use = True
                lim.vbmax = unhumanize_func(zs)

            # vmaxn: volume max number of files
            zs = vol.flags.get("vmaxn")
            if zs:
                use = True
                lim.vnmax = unhumanize_func(zs)

            if use:
                vol.lim = lim

    def apply_robots_flag(self, vfs: Any, no_robots: bool) -> None:
        """Apply robots metadata flag based on config and volflag.

        Args:
            vfs: Root VFS node containing all_nodes
            no_robots: Whether to apply norobots by default
        """
        if not no_robots:
            return

        for vol in vfs.all_nodes.values():
            # volflag "robots" overrides global "norobots", allowing indexing for this vol
            if not vol.flags.get("robots"):
                vol.flags["norobots"] = True
