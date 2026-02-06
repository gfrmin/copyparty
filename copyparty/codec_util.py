"""Codec utilities for copyparty.

Handles HTML escaping, JSON escaping, and cookie operations.
Functions that depend on util.py globals (html_sh_esc, unquotep)
remain in util.py until their dependencies can be migrated.
"""


def json_hesc(s: str) -> str:
    """Escape HTML-special characters in a string destined for JSON in HTML context."""
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def html_escape(s: str, quot: bool = False, crlf: bool = False) -> str:
    """html.escape but also newlines"""
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if quot:
        s = s.replace('"', "&quot;").replace("'", "&#x27;")
    if crlf:
        s = s.replace("\r", "&#13;").replace("\n", "&#10;")

    return s


def html_bescape(s: bytes, quot: bool = False, crlf: bool = False) -> bytes:
    """html.escape but bytestrings"""
    s = s.replace(b"&", b"&amp;").replace(b"<", b"&lt;").replace(b">", b"&gt;")
    if quot:
        s = s.replace(b'"', b"&quot;").replace(b"'", b"&#x27;")
    if crlf:
        s = s.replace(b"\r", b"&#13;").replace(b"\n", b"&#10;")

    return s


def unescape_cookie(orig: str) -> str:
    """Unescape percent-encoded cookie values.

    Handles %XX sequences in cookie strings.
    """
    # mw=idk; doot=qwe%2Crty%3Basd+fgh%2Bjkl%25zxc%26vbn  # qwe,rty;asd fgh+jkl%zxc&vbn
    ret = []
    esc = ""
    for ch in orig:
        if ch == "%":
            if esc:
                ret.append(esc)
            esc = ch

        elif esc:
            esc += ch
            if len(esc) == 3:
                try:
                    ret.append(chr(int(esc[1:], 16)))
                except (ValueError, TypeError):
                    ret.append(esc)
                esc = ""

        else:
            ret.append(ch)

    if esc:
        ret.append(esc)

    return "".join(ret)
