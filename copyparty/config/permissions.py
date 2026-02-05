"""Permission resolution for copyparty VFS.

Resolves access control by:
- Expanding wildcard permissions
- Resolving group memberships
- Building user-to-volumes mappings
- Creating per-user access tuples
"""

from typing import Any, Callable, Dict, List, Set, Tuple


class PermissionResolver:
    """Resolve user permissions and access controls for VFS volumes."""

    def __init__(self, log_func: Callable[[str, int], None]):
        """Initialize resolver with logging function.

        Args:
            log_func: Function for logging messages (msg, level)
        """
        self.log = log_func

    def resolve_permissions(
        self,
        vfs: Any,
        acct: Dict[str, str],
        grps: Dict[str, List[str]],
        idp_accs: Set[str],
        enshare: bool,
        shr: str = "",
    ) -> None:
        """Resolve and populate all permission mappings in VFS.

        Modifies vfs to add:
        - aread, awrite, amove, adel, aget, aupget, ahtml, aadmin, adot
          (Dict[str, List[str]] mapping username -> list of vpaths)
        - uaxs on each node
          (Dict[str, Tuple] mapping username -> (read, write, move, del, get, upget, html, admin, dot))

        Args:
            vfs: Root VFS node to populate permissions on
            acct: Dict of username -> password
            grps: Dict of groupname -> list of usernames
            idp_accs: Set of IdP-managed usernames
            enshare: Whether share feature is enabled
            shr: Share volume path prefix (if enabled)
        """
        # Build list of all known usernames
        all_users: Set[str] = set(acct.keys())
        all_users.update(idp_accs)
        unames = ["*"] + list(sorted(all_users))

        # Expand wildcard and resolve group memberships
        for perm in "read write move del get pget html admin dot".split():
            axs_key = "u" + perm

            # First pass: expand wildcards for all volumes
            for vp, vol in vfs.all_vols.items():
                zx = getattr(vol.axs, axs_key)

                # Expand "*" to all usernames
                if "*" in zx and "-@acct" not in zx:
                    for usr in unames:
                        zx.add(usr)

                # Resolve group memberships
                for zs in list(zx):
                    if zs.startswith("-"):
                        # Remove explicit exclusion
                        zx.discard(zs)
                        zs = zs[1:]
                        zx.discard(zs)

                        # Remove group members
                        if zs.startswith("@"):
                            zs = zs[1:]
                            for member in grps.get(zs) or []:
                                zx.discard(member)

            # Second pass: build user-to-volumes mappings
            umap: Dict[str, List[str]] = {x: [] for x in unames}

            for usr in unames:
                for vp, vol in vfs.all_vols.items():
                    # Skip share volumes
                    if enshare and vp.startswith(shr + "/"):
                        continue

                    zx = getattr(vol.axs, axs_key)
                    if usr in zx:
                        umap[usr].append(vp)

                umap[usr].sort()

            # Store mapping on VFS
            setattr(vfs, "a" + perm, umap)

    def build_user_access_tuples(
        self,
        vfs: Any,
        unames: List[str],
    ) -> None:
        """Build per-user access control tuples for each volume node.

        Populates uaxs on each volume node:
        uaxs[username] = (read, write, move, del, get, upget, html, admin, dot)

        Args:
            vfs: Root VFS node containing all_nodes
            unames: List of all known usernames
        """
        for vol in vfs.all_nodes.values():
            za = vol.axs
            vol.uaxs = {
                un: (
                    un in za.uread,
                    un in za.uwrite,
                    un in za.umove,
                    un in za.udel,
                    un in za.uget,
                    un in za.upget,
                    un in za.uhtml,
                    un in za.uadmin,
                    un in za.udot,
                )
                for un in unames
            }

    def validate_user_references(
        self,
        vfs: Any,
        acct: Dict[str, str],
        idp_accs: Set[str],
        have_idp_hdrs: bool,
    ) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
        """Validate that all referenced users exist.

        Args:
            vfs: Root VFS node containing all_vols
            acct: Dict of known local accounts
            idp_accs: Set of IdP-managed usernames
            have_idp_hdrs: Whether IdP headers are configured

        Returns:
            Tuple of:
            - all_users: All referenced users (with count=1 for each)
            - missing_users: Referenced but undefined users
            - associated_users: Users mentioned in permission specs
        """
        all_users: Dict[str, int] = {}
        missing_users: Dict[str, int] = {}
        associated_users: Dict[str, int] = {}

        # Scan all AXS objects for referenced users
        for axs in vfs.all_vols.values():
            for d in [
                axs.uread,
                axs.uwrite,
                axs.umove,
                axs.udel,
                axs.uget,
                axs.upget,
                axs.uhtml,
                axs.uadmin,
                axs.udot,
            ]:
                for usr in d:
                    all_users[usr] = 1

                    # Check if user exists
                    if usr != "*" and usr not in acct and usr not in idp_accs:
                        missing_users[usr] = 1

                    # Track associated users
                    if "*" not in d:
                        associated_users[usr] = 1

        return all_users, missing_users, associated_users
