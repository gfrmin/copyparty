"""Share loading and integration for copyparty.

Loads shares from database and integrates them into the VFS.
"""

import hashlib
import os
from typing import Any, Callable, Dict, Optional, Set, Tuple


class ShareLoader:
    """Load and integrate shares from database into VFS."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize loader with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def load_shares(
        self,
        vfs: Any,
        acct: Dict[str, str],
        args: Any,
        db_connection: Any,
        VFS: type,
        AXS: type,
        ub64enc_func: Callable[[bytes], bytes],
        log_verbose: bool = False,
    ) -> Tuple[Optional[Any], str, str, str]:
        """Load shares from database and create share volume.

        Args:
            vfs: Root VFS node
            acct: Account dictionary to populate with share users
            args: Command-line arguments (shr, shr_db, shr_v)
            db_connection: SQLite database connection
            VFS: VFS class
            AXS: Access control set class
            ub64enc_func: Function to encode bytes as base64
            log_verbose: Whether to log verbose share loading

        Returns:
            Tuple of (shv, shr, shrs, db_path) where:
            - shv: Share volume VFS node (or None if shares disabled)
            - shr: Share root vpath (e.g., "s")
            - shrs: Share root vpath with slash (e.g., "s/")
            - db_path: Path to share database
        """
        enshare = args.shr
        if not enshare:
            return None, "", "", ""

        shr = enshare[1:-1]  # Remove brackets
        shrs = shr + "/"  # Add trailing slash
        db_path = args.shr_db

        # Create share volume
        log_func_inner = self.log if hasattr(self.log, "__call__") else None
        shv = VFS(log_func_inner, "", shr, shr, AXS(), {})

        # Load shares from database
        cur = db_connection.cursor()
        import time

        now = time.time()

        for row in cur.execute("select * from sh"):
            s_k, s_pw, s_vp, s_pr, s_nf, s_un, s_t0, s_t1 = row

            # Skip expired shares
            if s_t1 and s_t1 < now:
                continue

            if log_verbose:
                msg = f"loading {s_pr} share {s_k!r} by {s_un!r} => {s_vp!r}"
                self.log(msg, 6)

            # Create share user if password protected
            if s_pw:
                zb = hashlib.sha512(s_pw.encode("utf-8")).digest()
                sun = "s_%s" % (ub64enc_func(zb)[4:16].decode("ascii"),)
                acct[sun] = s_pw
            else:
                sun = "*"

            # Create AXS based on share permissions
            s_axs = AXS(
                [sun] if "r" in s_pr else [],
                [sun] if "w" in s_pr else [],
                [sun] if "m" in s_pr else [],
                [sun] if "d" in s_pr else [],
                [sun] if "g" in s_pr else [],
            )

            # Create share VFS node
            vp = f"{shr}/{s_k}"
            shv.nodes[s_k] = VFS(log_func_inner, "", vp, vp, s_axs, {})

        # Register share volume in main VFS
        vfs.nodes[shr] = vfs.all_vols[shr] = shv

        # Configure share nodes
        for vol in shv.nodes.values():
            vfs.all_vols[vol.vpath] = vfs.all_nodes[vol.vpath] = vol
            # Shares use different listing methods
            vol.get_dbv = vol._get_share_src if hasattr(vol, "_get_share_src") else None
            vol.ls = vol._ls_nope if hasattr(vol, "_ls_nope") else None

        cur.close()
        return shv, shr, shrs, db_path

    def map_shares(
        self,
        vfs: Any,
        shv: Optional[Any],
        args: Any,
        db_connection: Any,
        vjoin_func: Callable[[str, str], str],
        path_exists_func: Callable[[str], bool],
        path_isfile_func: Callable[[str], bool],
        is_share_func: Callable[[Any], bool],
        log_verbose: bool = False,
    ) -> None:
        """Map shares to source volumes and set up shadowing.

        Args:
            vfs: Root VFS node
            shv: Share volume VFS node
            args: Command-line arguments
            db_connection: SQLite database connection
            vjoin_func: Function to join volume paths
            path_exists_func: Function to check if path exists
            path_isfile_func: Function to check if path is file
            is_share_func: Function to determine if volume is share
            log_verbose: Whether to log verbose share mapping
        """
        if not shv:
            return

        shr = shv.vpath
        shrs = shr + "/"
        cur = db_connection.cursor()
        cur2 = db_connection.cursor()

        for row in cur.execute("select * from sh"):
            s_k, s_pw, s_vp, s_pr, s_nf, s_un, s_t0, s_t1 = row
            shn = shv.nodes.get(s_k)
            if not shn:
                continue

            try:
                # Get source volume and path
                s_vfs, s_rem = vfs.get(
                    s_vp, s_un, "r" in s_pr, "w" in s_pr, "m" in s_pr, "d" in s_pr
                )
            except Exception as ex:
                msg = f"removing share [{s_k}] by [{s_un}] to [{s_vp}] due to {ex!r}"
                self.log(msg, 3)
                shv.nodes.pop(s_k, None)
                continue

            # Load file list if configured
            fns = []
            if s_nf:
                q = "select vp from sf where k = ?"
                for (s_fn,) in cur2.execute(q, (s_k,)):
                    fns.append(s_fn)
                shn.shr_files = set(fns)
                shn.ls = shn._ls_shr if hasattr(shn, "_ls_shr") else None
            else:
                shn.ls = shn._ls if hasattr(shn, "_ls") else None

            # Store share metadata
            shn.shr_owner = s_un
            shn.shr_src = (s_vfs, s_rem)
            shn.realpath = s_vfs.canonical(s_rem) if hasattr(s_vfs, "canonical") else s_rem

            # Copy limitations and paths from source
            o_vn, _ = shn._get_share_src("") if hasattr(shn, "_get_share_src") else (None, None)
            if o_vn:
                shn.lim = getattr(o_vn, "lim", None)
                shn.flags = getattr(o_vn, "flags", {}).copy()
                shn.dbpath = getattr(o_vn, "dbpath", "")
                shn.histpath = getattr(o_vn, "histpath", "")

            if log_verbose:
                msg = f"mapped {s_pr} share [{s_k}] by [{s_un}] => [{s_vp}] => [{shn.realpath}]"
                self.log(msg, 6)

        cur2.close()
        cur.close()
