# coding: utf-8
"""File operations API endpoints."""
from __future__ import print_function, unicode_literals

from .base import get_json_body, resolve_user_path
from ..services.file_ops import mkdir, move_files, delete_files, rename_file
from ..util import Pebkac


def post_mkdir(cli):
    """POST /api/v1/files/mkdir - Create a directory.

    Request body (JSON):
        {
            "path": "/parent/dir",
            "name": "newdir"
        }

    Returns:
        dict with path and name of created directory
    """
    body = get_json_body(cli)
    path = body.get("path", "/")
    name = body.get("name")

    if not name:
        raise Pebkac(400, "Directory name required")

    # Resolve parent directory
    vn, rem, perms = resolve_user_path(cli, path)

    # Unpack permissions
    _, can_write, _, _, _, _, _, _, _ = perms

    if not can_write:
        raise Pebkac(403, "Write permission required")

    # Create directory
    return mkdir(vn, rem, name)


def post_delete(cli):
    """POST /api/v1/files/delete - Delete files or directories.

    Request body (JSON):
        {
            "path": "/file/or/dir",
            "paths": ["/file1", "/file2"],  # alternative to path
        }

    Returns:
        dict with deletion status
    """
    body = get_json_body(cli)
    paths = body.get("paths", [])

    if not paths and "path" in body:
        paths = [body["path"]]

    if not paths:
        raise Pebkac(400, "At least one path required")

    # Need delete permission on parent to delete
    # For simplicity, check first file
    first_path = paths[0]
    if "/" in first_path:
        parent_path = first_path.rsplit("/", 1)[0]
    else:
        parent_path = "/"

    vn, rem, perms = resolve_user_path(cli, parent_path)
    _, _, _, can_delete, _, _, _, _, _ = perms

    if not can_delete:
        raise Pebkac(403, "Delete permission required")

    # Delete files
    return delete_files(paths, cli.asrv, cli.conn.hsrv.broker)


def post_move(cli):
    """POST /api/v1/files/move - Move or copy files.

    Request body (JSON):
        {
            "source": "/old/path",
            "destination": "/new/path",
            "overwrite": false
        }

    Returns:
        dict with move status
    """
    body = get_json_body(cli)
    src = body.get("source")
    dst = body.get("destination")
    overwrite = body.get("overwrite", False)

    if not src or not dst:
        raise Pebkac(400, "Source and destination paths required")

    # Resolve source
    _, _, perms = resolve_user_path(cli, src)
    _, _, can_move, _, _, _, _, _, _ = perms

    if not can_move:
        raise Pebkac(403, "Move permission required on source")

    # Move files
    return move_files(src, dst, cli.uname, cli.asrv, cli.conn.hsrv.broker, overwrite)


def post_rename(cli):
    """POST /api/v1/files/rename - Rename a file.

    Request body (JSON):
        {
            "path": "/old/name",
            "name": "newname"
        }

    Returns:
        dict with rename status
    """
    body = get_json_body(cli)
    path = body.get("path")
    name = body.get("name")

    if not path or not name:
        raise Pebkac(400, "Path and new name required")

    # Resolve source
    _, _, perms = resolve_user_path(cli, path)
    _, _, can_move, _, _, _, _, _, _ = perms

    if not can_move:
        raise Pebkac(403, "Move permission required")

    # Rename file
    return rename_file(path, name, cli.uname, cli.asrv, cli.conn.hsrv.broker)
