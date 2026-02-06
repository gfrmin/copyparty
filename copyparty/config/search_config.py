"""Search indexing configuration for copyparty volumes.

Handles search/index flag processing (e2d, e2t, e2v, d2d, etc.)
"""

import re
from typing import Any, Callable, Dict, Optional, Set


class SearchIndexConfigBuilder:
    """Build search and indexing configuration for volumes."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize builder with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def configure_search_flags(
        self,
        vfs: Any,
        args: Any,
        vf_bmap_func: Callable[[], Dict[str, str]],
        vf_vmap_func: Callable[[], Dict[str, str]],
    ) -> None:
        """Configure search and indexing flags for all volumes.

        Args:
            vfs: Root VFS node containing all_nodes
            args: Command-line arguments with search options
            vf_bmap_func: Function returning boolean flag mapping
            vf_vmap_func: Function returning value flag mapping
        """
        for vol in vfs.all_nodes.values():
            # Handle indexing enable/disable
            if (getattr(args, "e2ds", False) and vol.axs.uwrite) or getattr(args, "e2dsa", False):
                vol.flags["e2ds"] = True

            if getattr(args, "e2d", False) or "e2ds" in vol.flags:
                vol.flags["e2d"] = True

            # Compile regex patterns for filters
            pattern_flags = {
                "no_hash": getattr(args, "no_hash", None),
                "no_idx": getattr(args, "no_idx", None),
                "og_ua": getattr(args, "og_ua", None),
                "srch_excl": getattr(args, "srch_excl", None),
            }

            for vf, ptn in pattern_flags.items():
                if vf in vol.flags:
                    # Volume-specific pattern overrides global
                    ptn = re.compile(vol.flags.pop(vf))
                elif ptn:
                    # Use global pattern
                    ptn = ptn if isinstance(ptn, type(re.compile(""))) else re.compile(str(ptn))
                else:
                    ptn = None

                if ptn:
                    vol.flags[vf] = ptn

            # Apply boolean flag mappings
            for ga, vf in vf_bmap_func().items():
                if getattr(args, ga, False):
                    vol.flags[vf] = True

            # Apply value flag mappings with defaults
            for ga, vf in vf_vmap_func().items():
                if vf not in vol.flags:
                    vol.flags[vf] = getattr(args, ga, None)

    def disable_database_features(self, vfs: Any) -> None:
        """Disable database features based on d2d/d2t flags.

        Args:
            vfs: Root VFS node containing all_nodes
        """
        for vol in vfs.all_nodes.values():
            # d2d drops all database features
            if vol.flags.get("d2d", False):
                vol.flags["d2t"] = True
                vol.flags = {k: v for k, v in vol.flags.items() if not k.startswith("e2d")}

            # d2t drops table features
            if vol.flags.get("d2t", False):
                vol.flags = {k: v for k, v in vol.flags.items() if not k.startswith("e2t")}

            # d2ds drops onboot scans
            if vol.flags.get("d2ds", False):
                vol.flags["d2ts"] = True
                vol.flags = {k: v for k, v in vol.flags.items() if not k.startswith("e2ds")}

            if vol.flags.get("d2ts", False):
                vol.flags = {k: v for k, v in vol.flags.items() if not k.startswith("e2ts")}

            # mt* requires e2t
            if not vol.flags.get("e2t", False):
                vol.flags = {
                    k: v
                    for k, v in vol.flags.items()
                    if not k.startswith("mt") or k == "mte"
                }

    def validate_indexing_requirements(self, vfs: Any) -> None:
        """Validate that required indexing features are enabled.

        Args:
            vfs: Root VFS node containing all_nodes

        Raises:
            Exception: If required features are used without e2d
        """
        for vol in vfs.all_nodes.values():
            if "e2d" in vol.flags:
                continue

            # These features require e2d
            requires_e2d = ["lifetime", "rss", "xau", "xiu"]
            missing = [x for x in requires_e2d if x in vol.flags and vol.flags.get(x)]

            if missing:
                msg = (
                    f'cannot enable [{missing[0]}] for volume "/{vol.vpath}" '
                    f"because this requires one of the following: e2d / e2ds / e2dsa"
                )
                self.log(msg, 1)
                for x in missing:
                    vol.flags.pop(x, None)

    def validate_search_warnings(self, vfs: Any, args: Any) -> None:
        """Log warnings about search configuration.

        Args:
            vfs: Root VFS node containing all_nodes
            args: Command-line arguments
        """
        have_e2d = any("e2d" in vol.flags for vol in vfs.all_nodes.values())

        if not have_e2d and not getattr(args, "have_idp_hdrs", False):
            return

        if have_e2d:
            msg = "hint: enable multimedia indexing (artist/title/...) with argument -e2ts"
            self.log(msg, 6)
        else:
            msg = "hint: enable searching and upload-undo with argument -e2dsa"
            self.log(msg, 6)
