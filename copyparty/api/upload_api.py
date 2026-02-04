# coding: utf-8
"""Upload API endpoints."""
from __future__ import print_function, unicode_literals

from .base import get_json_body
from ..services.upload_svc import initiate_upload, finalize_upload
from ..util import Pebkac


def post_upload_init(cli):
    """POST /api/v1/upload/init - Initiate upload session.

    Request body (JSON):
        {
            "path": "/destination/dir"
        }

    Returns:
        dict with upload session info
    """
    body = get_json_body(cli)
    path = body.get("path", "/")

    return initiate_upload(path, cli.uname, cli.asrv)


def post_upload_finalize(cli):
    """POST /api/v1/upload/finalize - Finalize upload.

    Request body (JSON):
        {
            "path": "/destination/file"
        }

    Returns:
        dict with finalize status
    """
    body = get_json_body(cli)
    path = body.get("path")

    if not path:
        raise Pebkac(400, "File path required")

    return finalize_upload(path, cli.uname, cli.asrv)
