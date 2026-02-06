# coding: utf-8
"""Configuration and session API endpoints."""
from __future__ import print_function, unicode_literals

from .base import resolve_user_path


def get_config(cli):
    """GET /api/v1/config - Server configuration and features.

    Returns version, server name, and enabled features.
    """
    from ..__version__ import S_VERSION

    return {
        "version": S_VERSION,
        "name": cli.args.name or cli.args.bname or "",
        "features": {
            "up2k": True,  # up2k uploads always enabled
            "thumbnails": hasattr(cli.E.vfs, "th_cache"),  # if VFS has thumb cache
            "search": bool(cli.E.db),  # if database is enabled
            "mediakeys": bool(getattr(cli.E, "mediakeys", None)),  # mediakeys support
        },
    }


def get_session(cli):
    """GET /api/v1/session - Current user session and permissions.

    Returns authenticated user info, root permissions, and accessible volumes.
    Requires read permission on at least one volume.
    """
    # Get user info
    uname = cli.uname or "*"  # Anonymous users are "*"

    # Resolve permissions for root path
    try:
        _, _, perms = resolve_user_path(cli, "/")
    except (KeyError, IndexError):
        # User has no access to root, return minimal session
        return {
            "user": uname,
            "authenticated": bool(cli.uname),
            "permissions": None,
            "volumes": [],
        }

    # Unpack permissions tuple
    (
        can_read, can_write, can_move, can_delete,
        can_get, can_upget, can_html, can_admin, can_dot,
    ) = perms

    # Get accessible volumes
    accessible_vols = []
    for vpath in sorted(cli.rvol):
        try:
            _, _, perms = resolve_user_path(cli, vpath)
            vol_perms = perms[0] or perms[1]  # read or write
            if vol_perms:
                accessible_vols.append({
                    "path": vpath,
                    "read": perms[0],
                    "write": perms[1],
                })
        except Exception:
            pass

    return {
        "user": uname,
        "authenticated": bool(cli.uname),
        "permissions": {
            "read": can_read,
            "write": can_write,
            "move": can_move,
            "delete": can_delete,
            "get": can_get,
            "upget": can_upget,
            "html": can_html,
            "admin": can_admin,
            "dot": can_dot,
        },
        "volumes": accessible_vols,
    }
