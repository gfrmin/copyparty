"""String utilities for copyparty.

Handles text manipulation, formatting, and terminal operations.
"""

import os
import re
from typing import Optional

try:
    import fcntl  # type: ignore
    import termios  # type: ignore
except ImportError:
    fcntl = None  # type: ignore
    termios = None  # type: ignore


def dedent(txt: str) -> str:
    """Remove common leading whitespace from text.

    Args:
        txt: Text to dedent

    Returns:
        Dedented text
    """
    pad = 64
    lns = txt.replace("\r", "").split("\n")
    for ln in lns:
        zs = ln.lstrip()
        pad2 = len(ln) - len(zs)
        if zs and pad > pad2:
            pad = pad2
    return "\n".join([ln[pad:] for ln in lns])


def str_anchor(txt: str) -> tuple[int, str]:
    """Parse string anchors for matching.

    Handles ^ (start), $ (end), and ~ (contains) anchors.

    Args:
        txt: Text with potential anchors

    Returns:
        Tuple of (anchor_type, text_without_anchors)
        - 0: no text
        - 1: contains (~)
        - 2: starts with (^)
        - 3: ends with ($)
        - 4: exact match (^ and $)
    """
    if not txt:
        return 0, ""
    txt = txt.lower()
    a = txt.startswith("^")
    b = txt.endswith("$")
    if not b:
        if not a:
            return 1, txt  # ~
        return 2, txt[1:]  # ^

    if not a:
        return 3, txt[:-1]  # $
    return 4, txt[1:-1]  # ^...$


def eol_conv(
    fin,
    conv: str,
):
    """Convert end-of-line markers in a byte stream.

    Args:
        fin: Input generator yielding bytes
        conv: Conversion mode ("lf" or "crlf")

    Yields:
        Bytes with converted line endings
    """
    crlf = conv.lower() == "crlf"
    for buf in fin:
        buf = buf.replace(b"\r", b"")
        if crlf:
            buf = buf.replace(b"\n", b"\r\n")
        yield buf


def align_tab(lines: list[str]) -> list[str]:
    """Align whitespace-separated columns in text lines.

    Args:
        lines: List of text lines

    Returns:
        List of aligned lines
    """
    rows = []
    ncols = 0
    for ln in lines:
        row = [x for x in ln.split(" ") if x]
        ncols = max(ncols, len(row))
        rows.append(row)

    lens = [0] * ncols
    for row in rows:
        for n, col in enumerate(row):
            lens[n] = max(lens[n], len(col))

    return ["".join(x.ljust(y + 2) for x, y in zip(row, lens)) for row in rows]


def visual_length(txt: str) -> int:
    """Calculate visual length of text with ANSI escape sequences.

    Accounts for:
    - ANSI escape codes (don't contribute to visual width)
    - Box drawing characters (single width)
    - Braille characters (single width)
    - CJK characters (double width)

    Args:
        txt: Text to measure

    Returns:
        Visual width in characters
    """
    eoc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    clen = 0
    pend = None
    counting = True
    for ch in txt:
        # escape sequences can never contain ESC;
        # treat pend as regular text if so
        if ch == "\033" and pend:
            clen += len(pend)
            counting = True
            pend = None

        if not counting:
            if ch in eoc:
                counting = True
        else:
            if pend:
                pend += ch
                if pend.startswith("\033["):
                    counting = False
                else:
                    clen += len(pend)
                    counting = True
                pend = None
            else:
                if ch == "\033":
                    pend = "%s" % (ch,)
                else:
                    co = ord(ch)
                    # the safe parts of latin1 and cp437 (no greek stuff)
                    if (
                        co < 0x100  # ascii + lower half of latin1
                        or (co >= 0x2500 and co <= 0x25A0)  # box drawings
                        or (co >= 0x2800 and co <= 0x28FF)  # braille
                    ):
                        clen += 1
                    else:
                        # assume CJK or other double-width
                        clen += 2
    return clen


def wrap(txt: str, maxlen: int, maxlen2: int) -> list[str]:
    """Wrap text to fit within maximum width.

    Respects visual length and ANSI escape sequences.

    Args:
        txt: Text to wrap
        maxlen: Initial line maximum width
        maxlen2: Continuation line maximum width (for indent)

    Returns:
        List of wrapped lines
    """
    words = re.sub(r"([, ])", r"\1\n", txt.rstrip()).split("\n")
    pad = maxlen - maxlen2
    ret = []
    for word in words:
        if len(word) * 2 < maxlen or visual_length(word) < maxlen:
            ret.append(word)
        else:
            while visual_length(word) >= maxlen:
                ret.append(word[: maxlen - 1] + "-")
                word = word[maxlen - 1 :]
            if word:
                ret.append(word)

    words = ret
    ret = []
    ln = ""
    spent = 0
    for word in words:
        wl = visual_length(word)
        if spent + wl > maxlen:
            ret.append(ln)
            maxlen = maxlen2
            spent = 0
            ln = " " * pad
        ln += word
        spent += wl
    if ln:
        ret.append(ln)

    return ret


def termsize() -> tuple[int, int]:
    """Get terminal dimensions.

    Returns terminal width and height, with fallbacks:
    1. os.get_terminal_size()
    2. fcntl ioctl TIOCGWINSZ
    3. Environment variables COLUMNS/LINES
    4. Default 80x25

    Returns:
        Tuple of (width, height)
    """
    try:
        w, h = os.get_terminal_size()
        return w, h
    except Exception:
        pass

    env = os.environ

    def ioctl_GWINSZ(fd: int) -> Optional[tuple[int, int]]:
        if not (fcntl and termios):
            return None
        try:
            from .util import sunpack  # Avoid circular import
            cr = sunpack(b"hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"AAAA"))
            return cr[::-1]
        except Exception:
            return None

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except Exception:
            pass

    try:
        return cr or (int(env["COLUMNS"]), int(env["LINES"]))
    except (ValueError, TypeError, KeyError):
        return 80, 25
