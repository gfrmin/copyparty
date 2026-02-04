# coding: utf-8
"""File operations service for API endpoints."""
from __future__ import print_function, unicode_literals

from ..bos import bos
from ..util import Pebkac, vjoin


def mkdir(vn, rem, name):
    """Create a new directory.

    Args:
        vn: Virtual node (VFS node)
        rem: Remaining path within the VFS node
        name: Directory name to create (max 512 chars)

    Returns:
        dict with keys: path, name

    Raises:
        Pebkac: For permission or creation errors
    """
    if not name:
        raise Pebkac(400, "Directory name required")

    # Limit name length
    name = name[:512]

    # Check for nosub flag (mkdir forbidden below this folder)
    if "nosub" in vn.flags:
        raise Pebkac(403, "mkdir is forbidden below this folder")

    # Build new virtual path
    new_vpath = vjoin(rem.rstrip("/"), name)

    # Get filesystem info
    abspath = vn.dcanonical(new_vpath)

    # Check if directory already exists
    try:
        if bos.path.exists(abspath):
            raise Pebkac(405, 'folder "/%s" already exists' % (new_vpath,))
    except OSError as ex:
        if ex.errno == 13:  # EACCES
            raise Pebkac(500, "the server OS denied write-access")
        raise Pebkac(500, "mkdir failed: {}".format(str(ex)))

    # Create directory
    try:
        bos.makedirs(abspath, vf=vn.flags)
    except OSError as ex:
        if ex.errno == 13:  # EACCES
            raise Pebkac(500, "the server OS denied write-access")
        raise Pebkac(500, "mkdir failed: {}".format(str(ex)))

    return {
        "path": new_vpath,
        "name": name,
    }


def delete_files(file_list, asrv, broker):
    """Delete files or directories (async via broker).

    Args:
        file_list: List of virtual paths to delete
        asrv: AuthServer instance
        broker: Message broker for async operations

    Returns:
        dict with operation status

    Raises:
        Pebkac: For permission or configuration errors
    """
    # Check for feature disabled
    if getattr(asrv, "no_del", False):
        raise Pebkac(403, "the delete feature is disabled in server config")

    # Queue deletion via broker (async)
    try:
        result = broker.ask("up2k.handle_rm", file_list)
        return {
            "deleted": len(file_list),
            "status": result,
        }
    except Exception as ex:
        raise Pebkac(500, "Delete failed: {}".format(str(ex)))


def move_files(src_path, dst_vpath, uname, asrv, broker, overwrite=False):
    """Move or rename files (async via broker).

    Args:
        src_path: Source virtual path
        dst_vpath: Destination virtual path
        uname: Username
        asrv: AuthServer instance
        broker: Message broker for async operations
        overwrite: Whether to overwrite existing destination

    Returns:
        dict with operation status

    Raises:
        Pebkac: For permission or configuration errors
    """
    if not dst_vpath:
        raise Pebkac(400, "Destination path required")

    # Check for feature disabled
    if getattr(asrv, "no_mv", False):
        raise Pebkac(403, "the rename/move feature is disabled in server config")

    # Validate permissions on source (need read and move)
    try:
        _, _ = asrv.vfs.get(src_path, uname, True, False, True)
    except Pebkac:
        raise Pebkac(403, "you don't have move-access to the source file")

    # Validate permissions on destination (need write)
    try:
        dvn, drem = asrv.vfs.get(dst_vpath, uname, False, True)
    except Pebkac:
        raise Pebkac(403, "you don't have write-access to the destination folder")

    # Check if destination exists and handle overwrite
    if overwrite:
        dabs = dvn.canonical(drem)
        if bos.path.exists(dabs):
            # Need delete permission to overwrite
            try:
                asrv.vfs.get(dst_vpath, uname, False, True, False, True)
            except Pebkac:
                raise Pebkac(403, "you don't have delete-access to overwrite the destination")

    # Queue move via broker (async)
    try:
        result = broker.ask("up2k.handle_mv", src_path, dst_vpath, overwrite)
        return {
            "source": src_path,
            "destination": dst_vpath,
            "status": result,
        }
    except Exception as ex:
        raise Pebkac(500, "Move failed: {}".format(str(ex)))


def rename_file(src_path, new_name, uname, asrv, broker):
    """Rename a file (special case of move).

    Args:
        src_path: Source virtual path
        new_name: New filename
        uname: Username
        asrv: AuthServer instance
        broker: Message broker for async operations

    Returns:
        dict with operation status

    Raises:
        Pebkac: For permission or configuration errors
    """
    if not new_name:
        raise Pebkac(400, "New name required")

    # Build destination path (same directory, new name)
    if "/" in src_path:
        parent_dir = src_path.rsplit("/", 1)[0]
        dst_vpath = vjoin(parent_dir, new_name)
    else:
        dst_vpath = new_name

    # Use move_files with overwrite=False (same directory, should not conflict)
    return move_files(src_path, dst_vpath, uname, asrv, broker, overwrite=False)
