"""Time utilities for copyparty.

Handles timestamp formatting, duration calculation, and time conversions.
"""

import re
import time
from email.utils import formatdate as email_formatdate
from typing import Optional


def formatdate(ts: Optional[float] = None) -> str:
    """Format timestamp as HTTP date.

    Args:
        ts: Unix timestamp (defaults to current time)

    Returns:
        Formatted date string (RFC 2822)
    """
    if ts is None:
        ts = time.time()
    return email_formatdate(ts, usegmt=True)


def humansize(sz: float, terse: bool = False) -> str:
    """Convert byte size to human-readable format.

    Args:
        sz: Size in bytes
        terse: If True, use short format (B instead of bytes)

    Returns:
        Human-readable size string
    """
    units = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"]
    if terse:
        units = ["B", "K", "M", "G", "T", "P"]

    sz = float(sz)
    unit_idx = 0

    while sz >= 1024 and unit_idx < len(units) - 1:
        sz /= 1024
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(sz)} {units[unit_idx]}"
    return f"{sz:.2f} {units[unit_idx]}"


def unhumanize(sz: str) -> int:
    """Convert human-readable size to bytes.

    Args:
        sz: Size string (e.g., "1.5g", "512m", "1024")

    Returns:
        Size in bytes
    """
    sz = str(sz).strip().lower()

    multipliers = {
        "k": 1024,
        "m": 1024 ** 2,
        "g": 1024 ** 3,
        "t": 1024 ** 4,
        "p": 1024 ** 5,
    }

    # Check for suffix
    if sz and sz[-1] in multipliers:
        suffix = sz[-1]
        value = float(sz[:-1])
        return int(value * multipliers[suffix])

    # Plain number
    try:
        return int(float(sz))
    except ValueError:
        return 0


def get_spd(nbyte: int, t0: float, t: Optional[float] = None) -> str:
    """Calculate transfer speed.

    Args:
        nbyte: Number of bytes transferred
        t0: Start time (unix timestamp)
        t: End time (defaults to current time)

    Returns:
        Speed string (e.g., "1.5 MiB/s")
    """
    if t is None:
        t = time.time()

    elapsed = t - t0
    if elapsed <= 0:
        return "∞"

    spd = nbyte / elapsed
    return humansize(spd) + "/s"


def s2hms(s: float, optional_h: bool = False) -> str:
    """Convert seconds to human-readable duration.

    Args:
        s: Duration in seconds
        optional_h: If True, omit hours if < 1 hour

    Returns:
        Duration string (e.g., "1h 23m 45s")
    """
    s = int(s)
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60

    if optional_h and h == 0:
        return f"{m}m {sec}s"

    return f"{h}h {m}m {sec}s"


def rice_tid() -> str:
    """Generate timestamp-based transaction ID.

    Returns:
        Transaction ID string
    """
    # Use current time in milliseconds as transaction ID
    return f"{int(time.time() * 1000000):016x}"
