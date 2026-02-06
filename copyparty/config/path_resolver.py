"""Path resolution for volume histpath and dbpath.

Resolves locations for database and thumbnail caches.
"""

import base64
import hashlib
import os
from typing import Any, Callable, Dict, Optional


class PathResolver:
    """Resolve histpath and dbpath for volumes."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize resolver with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func
        self.hid_cache: Dict[str, str] = {}

    def get_hash_id(self, realpath: str, afsenc_func: Callable[[str], bytes]) -> str:
        """Get cache ID from realpath hash.

        Args:
            realpath: Volume realpath
            afsenc_func: Function to encode filesystem path

        Returns:
            Base32-encoded hash ID
        """
        if realpath not in self.hid_cache:
            zb = hashlib.sha512(afsenc_func(realpath)).digest()
            hid = base64.b32encode(zb).decode("ascii").lower()
            self.hid_cache[realpath] = hid

        return self.hid_cache[realpath]

    def resolve_histpath(
        self,
        vfs: Any,
        args: Any,
        afsenc_func: Callable[[str], bytes],
        absreal_func: Callable[[str], str],
        makedirs_func: Callable[[str], None],
        uncyg_func: Callable[[str], str],
        WINDOWS: bool,
    ) -> None:
        """Resolve histpath for all volumes.

        Args:
            vfs: Root VFS node containing all_vols
            args: Command-line arguments with hist option
            afsenc_func: Function to encode filesystem paths
            absreal_func: Function to resolve absolute paths
            makedirs_func: Function to create directories
            uncyg_func: Function to convert cygwin paths
            WINDOWS: Whether running on Windows
        """
        for vol in vfs.all_vols.values():
            if not vol.realpath:
                continue

            vflag = vol.flags.get("hist")
            if vflag == "-":
                # Explicitly disabled
                pass
            elif vflag:
                # Volume-specific histpath
                vflag = os.path.expandvars(os.path.expanduser(vflag))
                vol.histpath = vol.dbpath = uncyg_func(vflag) if WINDOWS else vflag
            elif args.hist:
                # Use shared histpath directory
                hid = self.get_hash_id(vol.realpath, afsenc_func)
                for nch in range(len(hid)):
                    hpath = os.path.join(args.hist, hid[: nch + 1])
                    makedirs_func(hpath)

                    powner = os.path.join(hpath, "owner.txt")
                    try:
                        with open(powner, "rb") as f:
                            owner = f.read().rstrip()
                    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                        owner = None

                    me = afsenc_func(vol.realpath).rstrip()
                    if owner not in [None, me]:
                        continue

                    if owner is None:
                        with open(powner, "wb") as f:
                            f.write(me)

                    vol.histpath = vol.dbpath = hpath
                    break

            vol.histpath = absreal_func(vol.histpath)

    def resolve_dbpath(
        self,
        vfs: Any,
        args: Any,
        afsenc_func: Callable[[str], bytes],
        absreal_func: Callable[[str], str],
        makedirs_func: Callable[[str], None],
        uncyg_func: Callable[[str], str],
        WINDOWS: bool,
    ) -> None:
        """Resolve dbpath for all volumes.

        Args:
            vfs: Root VFS node containing all_vols
            args: Command-line arguments with dbpath option
            afsenc_func: Function to encode filesystem paths
            absreal_func: Function to resolve absolute paths
            makedirs_func: Function to create directories
            uncyg_func: Function to convert cygwin paths
            WINDOWS: Whether running on Windows
        """
        for vol in vfs.all_vols.values():
            if not vol.realpath:
                continue

            hid = self.get_hash_id(vol.realpath, afsenc_func)
            vflag = vol.flags.get("dbpath")
            if vflag == "-":
                # Explicitly disabled
                pass
            elif vflag:
                # Volume-specific dbpath
                vflag = os.path.expandvars(os.path.expanduser(vflag))
                vol.dbpath = uncyg_func(vflag) if WINDOWS else vflag
            elif args.dbpath:
                # Use shared dbpath directory
                for nch in range(len(hid)):
                    hpath = os.path.join(args.dbpath, hid[: nch + 1])
                    makedirs_func(hpath)

                    powner = os.path.join(hpath, "owner.txt")
                    try:
                        with open(powner, "rb") as f:
                            owner = f.read().rstrip()
                    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                        owner = None

                    me = afsenc_func(vol.realpath).rstrip()
                    if owner not in [None, me]:
                        continue

                    if owner is None:
                        with open(powner, "wb") as f:
                            f.write(me)

                    vol.dbpath = hpath
                    break

            vol.dbpath = absreal_func(vol.dbpath)

    def check_path_conflicts(self, vfs: Any, is_share_func: Callable[[Any], bool]) -> None:
        """Check for conflicting histpath and dbpath assignments.

        Args:
            vfs: Root VFS node containing all_vols
            is_share_func: Function to determine if volume is a share

        Raises:
            Exception: If multiple volumes share same histpath or dbpath
        """
        rhisttab: Dict[str, Any] = {}
        vfs.histtab = {}

        for zv in vfs.all_vols.values():
            histp = zv.histpath
            if histp and not is_share_func(zv) and histp in rhisttab:
                zv2 = rhisttab[histp]
                msg = (
                    f"invalid config; multiple volumes share the same histpath "
                    f"(database+thumbnails location):\n"
                    f"  histpath: {histp}\n"
                    f"  volume 1: /{zv2.vpath}  [{zv2.realpath}]\n"
                    f"  volume 2: /{zv.vpath}  [{zv.realpath}]"
                )
                self.log(msg, 1)
                raise Exception(msg)
            rhisttab[histp] = zv
            vfs.histtab[zv.realpath] = histp

        rdbpaths: Dict[str, Any] = {}
        vfs.dbpaths = {}

        for zv in vfs.all_vols.values():
            dbp = zv.dbpath
            if dbp and not is_share_func(zv) and dbp in rdbpaths:
                zv2 = rdbpaths[dbp]
                msg = (
                    f"invalid config; multiple volumes share the same dbpath "
                    f"(database location):\n"
                    f"  dbpath: {dbp}\n"
                    f"  volume 1: /{zv2.vpath}  [{zv2.realpath}]\n"
                    f"  volume 2: /{zv.vpath}  [{zv.realpath}]"
                )
                self.log(msg, 1)
                raise Exception(msg)
            rdbpaths[dbp] = zv
            vfs.dbpaths[zv.realpath] = dbp
