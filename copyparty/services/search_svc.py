# coding: utf-8
"""Search service for file indexing via API."""
from __future__ import print_function, unicode_literals

from ..util import Pebkac


def search_files(query, path, asrv):
    """Search for files in the index.

    Args:
        query: Search query string
        path: Virtual path to search within (optional)
        asrv: AuthServer instance

    Returns:
        dict with search results

    Raises:
        Pebkac: For invalid queries or disabled search
    """
    if not query:
        raise Pebkac(400, "Search query required")

    # Check if database is available
    if not asrv.db:
        raise Pebkac(503, "Search is not enabled on this server")

    # Delegate to database search (simplified for now)
    # Real implementation would use asrv.db.query()
    return {
        "query": query,
        "path": path or "/",
        "results": [],
        "count": 0,
    }


def get_tags(vpath, asrv):
    """Get tags for a file or directory.

    Args:
        vpath: Virtual path
        asrv: AuthServer instance

    Returns:
        dict with tag information

    Raises:
        Pebkac: For invalid paths or disabled tagging
    """
    if not vpath:
        raise Pebkac(400, "Path required")

    # Check if database is available for tags
    if not asrv.db:
        raise Pebkac(503, "Tagging is not enabled on this server")

    # Return tag info (simplified for now)
    return {
        "path": vpath,
        "tags": [],
    }
