"""Codec utilities for copyparty.

Handles encoding, decoding, and escaping operations.
"""

import html
import re
from typing import Optional, Union


def html_sh_esc(s: str) -> str:
    """Escape string for HTML shell commands.

    Args:
        s: String to escape

    Returns:
        Escaped string safe for HTML shell context
    """
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def json_hesc(s: str) -> str:
    """Escape string for JSON HTML context.

    Args:
        s: String to escape

    Returns:
        Escaped string safe for JSON in HTML
    """
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def html_escape(s: str, quot: bool = False, crlf: bool = False) -> str:
    """Escape HTML special characters.

    Args:
        s: String to escape
        quot: Whether to escape quotes
        crlf: Whether to escape CRLF

    Returns:
        HTML-escaped string
    """
    s = html.escape(s, quote=quot)
    if crlf:
        s = s.replace("\r", "&#13;").replace("\n", "&#10;")
    return s


def html_bescape(s: bytes, quot: bool = False, crlf: bool = False) -> bytes:
    """Escape HTML special characters in bytes.

    Args:
        s: Bytes to escape
        quot: Whether to escape quotes
        crlf: Whether to escape CRLF

    Returns:
        HTML-escaped bytes
    """
    return html_escape(s.decode("utf-8", "replace"), quot, crlf).encode("utf-8")


def _quotep2(txt: str) -> str:
    """Unescape Python 2 quoted string.

    Args:
        txt: Python 2 quoted string

    Returns:
        Unquoted string
    """
    return txt.encode().decode("unicode-escape")


def _quotep3(txt: str) -> str:
    """Unescape Python 3 quoted string.

    Args:
        txt: Python 3 quoted string

    Returns:
        Unquoted string
    """
    return txt.encode("utf-8").decode("unicode-escape")


def unquotep(txt: str) -> str:
    """Unescape quoted string (Python 2 or 3).

    Args:
        txt: Quoted string

    Returns:
        Unquoted string
    """
    # Try Python 3 style first (most common)
    try:
        return _quotep3(txt)
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass

    # Fall back to Python 2 style
    try:
        return _quotep2(txt)
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass

    # Return as-is if both fail
    return txt


def unescape_cookie(orig: str) -> str:
    """Unescape cookie value.

    Args:
        orig: Original cookie string

    Returns:
        Unescaped cookie value
    """
    # Remove quotes and unescape
    if orig.startswith('"') and orig.endswith('"'):
        orig = orig[1:-1]

    return orig.replace("\\", "")
