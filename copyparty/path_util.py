"""Path utilities for copyparty.

Handles path normalization, sanitization, and manipulation.
"""

import os
import re
import sys
from typing import Tuple


def djoin(*paths: str) -> str:
    """Join path components with forward slashes.

    Args:
        *paths: Path components

    Returns:
        Joined path with forward slashes
    """
    return "/".join(paths)


def uncyg(path: str) -> str:
    """Convert Cygwin path to Windows path.

    Args:
        path: Path potentially in Cygwin format (/c/Users/...)

    Returns:
        Windows path or original if not Cygwin format
    """
    if not path.startswith("/"):
        return path

    # /c/Users/... -> c:\Users\...
    if len(path) > 2 and path[2] == "/" and path[1].isalpha():
        return path[1] + ":\\" + path[3:].replace("/", "\\")

    # /cygdrive/c/Users/... -> c:\Users\...
    if path.startswith("/cygdrive/"):
        parts = path[10:].split("/")
        if parts:
            return parts[0] + ":\\" + "\\".join(parts[1:])

    return path


def undot(path: str) -> str:
    """Remove leading dot from path.

    Args:
        path: Path that may start with dot

    Returns:
        Path with leading dot removed
    """
    if path.startswith("./"):
        return path[2:]
    if path == ".":
        return ""
    return path


def sanitize_fn(fn: str) -> str:
    """Sanitize filename by removing invalid characters.

    Args:
        fn: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove null bytes and control characters
    fn = re.sub(r"[\x00-\x1f\x7f]", "", fn)
    # Remove trailing spaces and dots
    fn = fn.rstrip(". ")
    return fn


def sanitize_vpath(vp: str) -> str:
    """Sanitize virtual path.

    Args:
        vp: Virtual path to sanitize

    Returns:
        Sanitized virtual path
    """
    # Remove double slashes
    while "//" in vp:
        vp = vp.replace("//", "/")
    # Remove trailing slash
    vp = vp.rstrip("/")
    return vp


def relchk(rp: str) -> str:
    """Check for relative path traversal and normalize.

    Args:
        rp: Relative path to check

    Returns:
        Normalized relative path

    Raises:
        Exception: If path attempts to escape parent directory
    """
    parts = []
    for part in rp.split("/"):
        if part == "" or part == ".":
            continue
        elif part == "..":
            if not parts:
                raise Exception("relative path escape attempt")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def absreal(fpath: str) -> str:
    """Get absolute real path, expanding variables and user home.

    Args:
        fpath: File path potentially with variables/tilde

    Returns:
        Absolute real path
    """
    fpath = os.path.expandvars(os.path.expanduser(fpath))
    return os.path.realpath(fpath)


def u8safe(txt: str) -> str:
    """Ensure string is safe for UTF-8 encoding.

    Args:
        txt: Text to make UTF-8 safe

    Returns:
        UTF-8 safe string
    """
    return txt.encode("utf-8", "replace").decode("utf-8")


def vroots(vp1: str, vp2: str) -> Tuple[str, str]:
    """Find common root of two virtual paths.

    Args:
        vp1: First virtual path
        vp2: Second virtual path

    Returns:
        Tuple of (common_root, remaining_path)
    """
    if vp1 == vp2:
        return vp1, ""

    vp1_parts = vp1.split("/")
    vp2_parts = vp2.split("/")

    common = []
    for p1, p2 in zip(vp1_parts, vp2_parts):
        if p1 == p2:
            common.append(p1)
        else:
            break

    root = "/".join(common)
    if vp1 == root:
        return root, vp2[len(root) :].lstrip("/")
    return root, vp2[len(root) :].lstrip("/")


def vsplit(vpath: str) -> Tuple[str, str]:
    """Split virtual path into parent and filename.

    Args:
        vpath: Virtual path to split

    Returns:
        Tuple of (parent_path, filename)
    """
    if "/" not in vpath:
        return "", vpath

    parts = vpath.rsplit("/", 1)
    return parts[0], parts[1]


def vjoin(rd: str, fn: str) -> str:
    """Join directory and filename in virtual path.

    Args:
        rd: Directory path
        fn: Filename

    Returns:
        Joined virtual path
    """
    if not rd:
        return fn
    if not fn:
        return rd
    return rd.rstrip("/") + "/" + fn.lstrip("/")


def ujoin(rd: str, fn: str) -> str:
    """Join directory and filename in URL path.

    Args:
        rd: Directory path
        fn: Filename

    Returns:
        Joined URL path
    """
    return vjoin(rd, fn)
