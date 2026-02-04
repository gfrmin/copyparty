# coding: utf-8
"""Search API endpoints."""
from __future__ import print_function, unicode_literals

from .base import get_json_body, get_path_param
from ..services.search_svc import search_files, get_tags
from ..util import Pebkac


def post_search(cli):
    """POST /api/v1/search - Search for files.

    Request body (JSON):
        {
            "query": "*.pdf",
            "path": "/docs"  # optional
        }

    Returns:
        dict with search results
    """
    body = get_json_body(cli)
    query = body.get("query")
    path = body.get("path", "/")

    if not query:
        raise Pebkac(400, "Search query required")

    return search_files(query, path, cli.asrv)


def get_tags_endpoint(cli):
    """GET /api/v1/tags - Get file tags.

    Query parameters:
        path: File or directory path

    Returns:
        dict with tag information
    """
    path = get_path_param(cli.qs, "path") if cli.qs else None

    if not path:
        raise Pebkac(400, "Path parameter required")

    return get_tags(path, cli.asrv)
