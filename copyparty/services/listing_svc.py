# coding: utf-8
"""Directory listing service for API endpoints."""
from __future__ import print_function, unicode_literals

import stat
from datetime import datetime, timezone

from ..bos import bos
from ..util import Pebkac

# UTC timezone for consistent timestamps
UTC = timezone.utc


def build_listing(vn, rem, uname, can_read, can_write, can_dot):
    """Build a directory listing for API responses.

    Args:
        vn: Virtual node (VFS node)
        rem: Remaining path within the VFS node
        uname: Username
        can_read: User can read flag
        can_write: User can write flag
        can_dot: User can access dotfiles

    Returns:
        dict with keys: path, breadcrumbs, items, stats

    Raises:
        Pebkac: For access or file errors
    """
    if not can_read:
        raise Pebkac(403, "Read permission required")

    # Get filesystem info
    abspath = vn.dcanonical(rem)

    try:
        st = bos.stat(abspath)
    except OSError:
        raise Pebkac(404, "Path not found")

    if not stat.S_ISDIR(st.st_mode):
        raise Pebkac(400, "Not a directory")

    # List directory contents
    try:
        fsroot, vfs_ls, vfs_virt = vn.ls(
            rem,
            uname,
            True,  # use scandir if available
            9,  # PERMS_rwh (read=1, write=2, html=4, admin=8)
            lstat=False,
            throw=True,
        )
    except Exception as ex:
        raise Pebkac(400, "Cannot list directory: {}".format(str(ex)))

    # Extract stats and names
    stats_dict = {k: v for k, v in vfs_ls}
    ls_names = [x[0] for x in vfs_ls]
    ls_names.extend(list(vfs_virt.keys()))

    # Filter dotfiles
    if not can_dot:
        ls_names = [x for x in ls_names if not x.startswith(".")]

    # Build breadcrumb trail
    breadcrumbs = []
    current_path = ""
    for segment in rem.strip("/").split("/"):
        if not segment:
            continue
        current_path = (current_path + "/" + segment).lstrip("/")
        breadcrumbs.append({
            "path": current_path,
            "name": segment,
        })

    # Build items list
    items = []
    for fn in sorted(ls_names):
        try:
            # Get stats for this file
            if fn in vfs_virt:
                fspath = vfs_virt[fn].realpath
            else:
                fspath = fsroot + "/" + fn

            linf = stats_dict.get(fn) or bos.lstat(fspath)
            inf = bos.stat(fspath) if stat.S_ISLNK(linf.st_mode) else linf
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            # Skip broken symlinks and inaccessible files
            continue

        is_dir = stat.S_ISDIR(inf.st_mode)
        is_link = stat.S_ISLNK(linf.st_mode)

        # Get file extension
        if is_dir:
            ext = ""
        elif "." in fn:
            ext = fn.rsplit(".", 1)[1]
        else:
            ext = ""

        # Format modification time as ISO 8601
        mtime = max(0, linf.st_mtime)
        dt = datetime.fromtimestamp(mtime, UTC).isoformat()

        item = {
            "name": fn,
            "type": "dir" if is_dir else ("link" if is_link else "file"),
            "size": inf.st_size if not is_dir else None,
            "modified": dt,
            "ext": ext,
        }

        items.append(item)

    # Build response
    current_path_str = rem.rstrip("/") if rem else "/"
    return {
        "path": current_path_str,
        "breadcrumbs": breadcrumbs,
        "items": items,
        "stats": {
            "count": len(items),
            "can_write": can_write,
        },
    }
