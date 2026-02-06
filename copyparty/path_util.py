"""Path utilities for copyparty.

Self-contained path manipulation functions.
Functions that depend on util.py globals (sanitize_fn, sanitize_vpath,
relchk, absreal) remain in util.py until their dependencies can be migrated.
"""

import os


def djoin(*paths: str) -> str:
    """joins without adding a trailing slash on blank args"""
    return os.path.join(*[x for x in paths if x])


def uncyg(path: str) -> str:
    """Convert Cygwin-style path to Windows path."""
    if len(path) < 2 or not path.startswith("/"):
        return path

    if len(path) > 2 and path[2] != "/":
        return path

    return "%s:\\%s" % (path[1], path[3:])


def undot(path: str) -> str:
    """Resolve . and .. in path segments."""
    ret: list[str] = []
    for node in path.split("/"):
        if node == "." or not node:
            continue

        if node == "..":
            if ret:
                ret.pop()
            continue

        ret.append(node)

    return "/".join(ret)


def u8safe(txt: str) -> str:
    """Ensure string is safe for UTF-8 encoding."""
    try:
        return txt.encode("utf-8", "xmlcharrefreplace").decode("utf-8", "replace")
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        return txt.encode("utf-8", "replace").decode("utf-8", "replace")


def vroots(vp1: str, vp2: str) -> tuple[str, str]:
    """
    input("q/w/e/r","a/s/d/e/r") output("/q/w/","/a/s/d/")
    """
    while vp1 and vp2:
        zt1 = vp1.rsplit("/", 1) if "/" in vp1 else ("", vp1)
        zt2 = vp2.rsplit("/", 1) if "/" in vp2 else ("", vp2)
        if zt1[1] != zt2[1]:
            break
        vp1 = zt1[0]
        vp2 = zt2[0]
    return (
        "/%s/" % (vp1,) if vp1 else "/",
        "/%s/" % (vp2,) if vp2 else "/",
    )


def vsplit(vpath: str) -> tuple[str, str]:
    """Split vpath into (directory, filename)."""
    if "/" not in vpath:
        return "", vpath

    return vpath.rsplit("/", 1)  # type: ignore


# vpath-join
def vjoin(rd: str, fn: str) -> str:
    """Join directory and filename in virtual path."""
    if rd and fn:
        return rd + "/" + fn
    else:
        return rd or fn


# url-join
def ujoin(rd: str, fn: str) -> str:
    """Join directory and filename as URL path."""
    if rd and fn:
        return rd.rstrip("/") + "/" + fn.lstrip("/")
    else:
        return rd or fn
