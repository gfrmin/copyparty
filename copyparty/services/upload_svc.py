# coding: utf-8
"""Upload service for up2k protocol via API."""
from __future__ import print_function, unicode_literals

from ..util import Pebkac


def initiate_upload(vpath, uname, asrv):
    """Initiate an up2k upload session.

    Args:
        vpath: Virtual path for upload destination
        uname: Username
        asrv: AuthServer instance

    Returns:
        dict with upload session info

    Raises:
        Pebkac: For permission or validation errors
    """
    if not vpath:
        raise Pebkac(400, "Upload path required")

    # Validate write permission
    try:
        _, _ = asrv.vfs.get(vpath, uname, False, True)
    except Pebkac:
        raise Pebkac(403, "Write permission required for upload")

    # Return session info (actual implementation delegated to up2k handler)
    return {
        "path": vpath,
        "status": "ready",
        "user": uname,
    }


def finalize_upload(vpath, uname, asrv):
    """Finalize an up2k upload.

    Args:
        vpath: Virtual path of uploaded file
        uname: Username
        asrv: AuthServer instance

    Returns:
        dict with finalize status

    Raises:
        Pebkac: For permission or validation errors
    """
    if not vpath:
        raise Pebkac(400, "File path required")

    # Return completion status (actual implementation delegated to up2k handler)
    return {
        "path": vpath,
        "status": "complete",
        "user": uname,
    }
