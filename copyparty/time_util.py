"""Time utilities for copyparty.

Handles timestamp formatting, duration calculation, and size conversions.
Functions that depend on util.py globals (rice_tid) remain in util.py.
"""

import time
from typing import Optional


HUMANSIZE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")

UNHUMANIZE_UNITS = {
    "b": 1,
    "k": 1024,
    "m": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "t": 1024 * 1024 * 1024 * 1024,
    "p": 1024 * 1024 * 1024 * 1024 * 1024,
    "e": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
}

WKDAYS = "Mon Tue Wed Thu Fri Sat Sun".split()
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
RFC2822 = "%s, %02d %s %04d %02d:%02d:%02d GMT"


def formatdate(ts: Optional[float] = None) -> str:
    # gmtime ~= datetime.fromtimestamp(ts, UTC).timetuple()
    y, mo, d, h, mi, s, wd, _, _ = time.gmtime(ts)
    return RFC2822 % (WKDAYS[wd], d, MONTHS[mo - 1], y, h, mi, s)


def humansize(sz: float, terse: bool = False) -> str:
    for unit in HUMANSIZE_UNITS:
        if sz < 1024:
            break

        sz /= 1024.0

    assert unit  # type: ignore  # !rm
    if terse:
        return "%s%s" % (str(sz)[:4].rstrip("."), unit[:1])
    else:
        return "%s %s" % (str(sz)[:4].rstrip("."), unit)


def unhumanize(sz: str) -> int:
    try:
        return int(sz)
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        pass

    mc = sz[-1:].lower()
    mi = UNHUMANIZE_UNITS.get(mc, 1)
    return int(float(sz[:-1]) * mi)


def get_spd(nbyte: int, t0: float, t: Optional[float] = None) -> str:
    if t is None:
        t = time.time()

    bps = nbyte / ((t - t0) or 0.001)
    s1 = humansize(nbyte).replace(" ", "\033[33m").replace("iB", "")
    s2 = humansize(bps).replace(" ", "\033[35m").replace("iB", "")
    return "%s \033[0m%s/s\033[0m" % (s1, s2)


def s2hms(s: float, optional_h: bool = False) -> str:
    s = int(s)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if not h and optional_h:
        return "%d:%02d" % (m, s)

    return "%d:%02d:%02d" % (h, m, s)
