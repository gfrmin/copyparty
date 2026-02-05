# coding: utf-8
"""Base classes and utilities for API handlers."""
from __future__ import print_function, unicode_literals

import json

from ..authctx import resolve_permissions
from ..util import Pebkac


def get_json_body(cli):
    """Parse JSON body from request.

    Returns dict of parsed JSON, or raises Pebkac(400) if invalid.
    """
    if not cli.body:
        return {}

    try:
        return json.loads(cli.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Pebkac(400, "Invalid JSON in request body")


def get_path_param(query_string, key):
    """Extract a query parameter from the request.

    Query string is formatted like "?key=value&key2=value2".
    """
    if not query_string:
        return None

    # Parse simple query string (not using urllib to avoid imports)
    for pair in query_string.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k == key:
                # Simple URL decode (handle %XX)
                import binascii
                try:
                    v = v.replace("%", "").encode("utf-8")
                    v = binascii.unhexlify(v).decode("utf-8") if "%" in pair else pair.split("=", 1)[1]
                except ImportError:
                    pass
                return v

    return None


def resolve_user_path(cli, path=None):
    """Resolve user, permissions, and VFS node for a path.

    Returns (vn, rem, perms_tuple) where perms_tuple is:
        (can_read, can_write, can_move, can_delete,
         can_get, can_upget, can_html, can_admin, can_dot)

    Raises Pebkac if unable to resolve.
    """
    if path is None:
        path = cli.vpath

    vn, _, rem, perms = resolve_permissions(cli.uname, path, cli.asrv)

    if not vn:
        raise Pebkac(404, "Path not found")

    return vn, rem, perms
