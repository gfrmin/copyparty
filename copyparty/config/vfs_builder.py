"""Virtual filesystem (VFS) tree builder for copyparty.

Constructs the hierarchical VFS tree from volume mount specifications.
Handles:
- Default root volume creation
- Volume mounting with path validation
- Volume hierarchy sorting
- VFS node initialization
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

# Type aliases for readability
VolumeDict = Dict[str, Tuple[str, str]]  # dst:(ap, vp0)
DaxsDict = Dict[str, Any]  # dst:AXS


class VFSBuilder:
    """Build virtual filesystem tree from volume specifications."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize builder with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def build_tree(
        self,
        mount: VolumeDict,
        daxs: DaxsDict,
        mflags: Dict[str, Dict[str, Any]],
        default_root_axs: Any,
        default_root_flags: Any,
        absreal_func: Callable[[str], str],
    ) -> Any:
        """Build VFS tree from mount specifications.

        Args:
            mount: Dict of dst -> (src_path, vp0) mappings
            daxs: Dict of dst -> AXS permission objects
            mflags: Dict of dst -> flags
            default_root_axs: Default root volume AXS permissions
            default_root_flags: Default root volume flags
            absreal_func: Function to resolve absolute paths

        Returns:
            Root VFS node

        Notes:
            - Volumes are sorted by hierarchy (depth, length)
            - Root volume ("") fully replaces default VFS if present
            - Sub-volumes are added as children of root
        """
        from copyparty.authsrv import VFS, AXS

        # Handle case where no volumes are mounted
        if not mount:
            # Use default: current directory at root with given permissions
            vfs = VFS(
                self.log,
                absreal_func("."),
                "",
                "",
                default_root_axs,
                default_root_flags,
            )
            return vfs

        vfs = None

        # Sort volumes by hierarchy: fewer slashes first, then shorter paths
        for dst in sorted(mount.keys(), key=lambda x: (x.count("/"), len(x))):
            src, dst0 = mount[dst]

            if dst == "":
                # Root volume: fully replaces default VFS
                vfs = VFS(self.log, src, dst, dst0, daxs[dst], mflags[dst])
            else:
                # Sub-volume: add to existing VFS tree
                if vfs is None:
                    # Initialize default root if not yet created
                    vfs = VFS(
                        self.log,
                        absreal_func("."),
                        "",
                        "",
                        default_root_axs,
                        default_root_flags,
                    )

                # Add sub-volume as child node
                zv = vfs.add(src, dst, dst0)
                zv.axs = daxs[dst]
                zv.flags = mflags[dst]
                zv.dbv = None

        # Ensure we have a root VFS
        if vfs is None:
            vfs = VFS(
                self.log,
                absreal_func("."),
                "",
                "",
                default_root_axs,
                default_root_flags,
            )

        return vfs

    def build_volume_index(self, vfs: Any) -> None:
        """Index all volumes in VFS tree.

        Populates:
        - vfs.all_vols: All volumes by vpath
        - vfs.all_nodes: All volume nodes by vpath
        - vfs.all_aps: All absolute paths
        - vfs.all_vps: All virtual paths

        Args:
            vfs: Root VFS node to index
        """
        vfs.all_vols = {}
        vfs.all_nodes = {}
        vfs.all_aps = []
        vfs.all_vps = []

        # Recursively index all volumes
        vfs.get_all_vols(vfs.all_vols, vfs.all_nodes, vfs.all_aps, vfs.all_vps)

        # Sort sub-paths within each volume
        for vol in vfs.all_nodes.values():
            vol.all_aps.sort(key=lambda x: len(x[0]), reverse=True)
            vol.all_vps.sort(key=lambda x: len(x[0]), reverse=True)
            vol.root = vfs
