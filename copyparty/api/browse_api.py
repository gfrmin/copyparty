# coding: utf-8
"""Directory browsing API endpoints."""
from __future__ import print_function, unicode_literals

from .base import get_path_param, resolve_user_path
from ..services.listing_svc import build_listing


def get_browse(cli):
    """GET /api/v1/browse - Get directory listing with metadata.

    Query parameters:
        path (optional): Directory path (defaults to current path, or "/" if not specified)

    Returns:
        dict with path, breadcrumbs, items, and stats
    """
    # Get the path from query string or use root
    path = get_path_param(cli.qs, "path") if cli.qs else None
    if not path:
        path = "/"

    # Resolve permissions for the requested path
    vn, rem, perms = resolve_user_path(cli, path)

    # Unpack permissions
    (
        can_read, can_write, _, _,
        _, _, _, _, can_dot,
    ) = perms

    # Build and return listing
    return build_listing(vn, rem, cli.uname, can_read, can_write, can_dot)
