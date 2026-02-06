"""Metadata tag configuration builder for copyparty volumes.

Builds metadata tag configurations from volume flags.
"""

import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class MetadataTagBuilder:
    """Build metadata tag configuration for volumes."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize builder with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def build_embedded_files_config(self, vfs: Any) -> None:
        """Build embedded files configuration (readmes, prologues, epilogues).

        Args:
            vfs: Root VFS node containing all_nodes
        """
        for vol in vfs.all_nodes.values():
            emb_all = vol.flags["emb_all"] = set()

            # Process readme files
            zsl1 = [x for x in vol.flags.get("preadmes", "").split(",") if x]
            zsl2 = [x for x in vol.flags.get("readmes", "").split(",") if x]
            zsl3 = list(set([x.lower() for x in zsl1]))
            zsl4 = list(set([x.lower() for x in zsl2]))
            emb_all.update(zsl3)
            emb_all.update(zsl4)
            vol.flags["emb_mds"] = [[0, zsl1, zsl3], [1, zsl2, zsl4]]

            # Process prologue/epilogue files
            zsl1 = [x for x in vol.flags.get("prologues", "").split(",") if x]
            zsl2 = [x for x in vol.flags.get("epilogues", "").split(",") if x]
            zsl3 = list(set([x.lower() for x in zsl1]))
            zsl4 = list(set([x.lower() for x in zsl2]))
            emb_all.update(zsl3)
            emb_all.update(zsl4)
            vol.flags["emb_lgs"] = [[0, zsl1, zsl3], [1, zsl2, zsl4]]

    def build_html_head_config(self, vfs: Any) -> None:
        """Build HTML head configuration with metadata.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        FAVICON_MIMES = {
            "png": "image/png",
            "gif": "image/gif",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "svg": "image/svg+xml",
        }
        META_NOBOTS = '<meta name="robots" content="noindex, nofollow">\n'

        for vol in vfs.all_nodes.values():
            zs = str(vol.flags.get("html_head") or "")
            if zs and zs[:1] in "%@":
                vol.flags["html_head_d"] = zs
                head_s = str(vol.flags.get("html_head_s") or "")
            else:
                zs2 = str(vol.flags.get("html_head_s") or "")
                if zs2 and zs:
                    head_s = f"{zs2.strip()}\n{zs.strip()}\n"
                else:
                    head_s = zs2 or zs

            if head_s and not head_s.endswith("\n"):
                head_s += "\n"

            # Add robots metadata
            if "norobots" in vol.flags:
                head_s += META_NOBOTS

            # Process favicon
            ico_url = vol.flags.get("ufavico")
            if ico_url:
                ico_h = ""
                ico_ext = ico_url.split("?")[0].split(".")[-1].lower()
                if ico_ext in FAVICON_MIMES:
                    zs = '<link rel="icon" type="%s" href="%s">\n'
                    ico_h = zs % (FAVICON_MIMES[ico_ext], ico_url)
                elif ico_ext == "ico":
                    zs = '<link rel="shortcut icon" href="%s">\n'
                    ico_h = zs % (ico_url,)
                if ico_h:
                    vol.flags["ufavico_h"] = ico_h
                    head_s += ico_h

            if head_s:
                vol.flags["html_head_s"] = head_s
            else:
                vol.flags.pop("html_head_s", None)

            if not vol.flags.get("html_head_d"):
                vol.flags.pop("html_head_d", None)

    def build_theme_color_config(self, vfs: Any) -> None:
        """Build theme color configuration from flags.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        for vol in vfs.all_nodes.values():
            zs = str(vol.flags.get("tcolor", "")).lstrip("#")
            if len(zs) == 3:  # Convert fc5 => ffcc55
                vol.flags["tcolor"] = "".join([x * 2 for x in zs])

    def build_external_thumbnail_config(self, vfs: Any) -> None:
        """Build external thumbnail configuration.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        for vol in vfs.all_nodes.values():
            ext_th = vol.flags["ext_th_d"] = {}
            etv = "(?)"
            try:
                for etv in vol.flags.get("ext_th", []) or []:
                    if "=" in etv:
                        k, v = etv.split("=", 1)
                        ext_th[k] = v
            except (KeyError, IndexError, ValueError):
                msg = f'WARNING: volume [/{vol.vpath}]: invalid value specified for ext-th: {etv}'
                self.log(msg, 3)

    def build_all_metadata_config(self, vfs: Any) -> None:
        """Build all metadata configuration.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        self.build_embedded_files_config(vfs)
        self.build_html_head_config(vfs)
        self.build_theme_color_config(vfs)
        self.build_external_thumbnail_config(vfs)
