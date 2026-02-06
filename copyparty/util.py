# coding: utf-8
from __future__ import print_function, unicode_literals

import argparse
import base64
import binascii
import codecs
import errno
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import platform
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess as sp  # nosec
import sys
import threading
import time
import traceback
from collections import Counter

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

try:
    from zlib_ng import gzip_ng as gzip
    from zlib_ng import zlib_ng as zlib

    sys.modules["gzip"] = gzip
    # sys.modules["zlib"] = zlib
    # `- somehow makes tarfile 3% slower with default malloc, and barely faster with mimalloc
except ImportError:
    import gzip
    import zlib

from .__init__ import (
    ANYWIN,
    EXE,
    GRAAL,
    MACOS,
    PY2,
    PY36,
    TYPE_CHECKING,
    VT100,
    WINDOWS,
    EnvParams,
    unicode,
)
from .__version__ import S_BUILD_DT, S_VERSION


def noop(*a, **ka):
    pass


try:
    from datetime import datetime, timezone

    UTC = timezone.utc
except ImportError:
    from datetime import datetime, timedelta, tzinfo

    TD_ZERO = timedelta(0)

    class _UTC(tzinfo):
        def utcoffset(self, dt):
            return TD_ZERO

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return TD_ZERO

    UTC = _UTC()


if PY2:
    range = xrange  # type: ignore
    from .stolen import surrogateescape

    surrogateescape.register_surrogateescape()


if sys.version_info >= (3, 7) or (
    PY36 and platform.python_implementation() == "CPython"
):
    ODict = dict
else:
    from collections import OrderedDict as ODict


# Re-exports from extracted utility modules (Phase 3c migration)
from .str_util import (  # noqa: F401,E402
    align_tab,
    dedent,
    eol_conv,
    str_anchor,
    termsize,
    visual_length,
    wrap,
)
from .codec_util import (  # noqa: F401,E402
    html_bescape,
    html_escape,
    json_hesc,
    unescape_cookie,
)
from .path_util import (  # noqa: F401,E402
    djoin,
    u8safe,
    ujoin,
    uncyg,
    undot,
    vjoin,
    vroots,
    vsplit,
)
from .time_util import (  # noqa: F401,E402
    HUMANSIZE_UNITS,
    UNHUMANIZE_UNITS,
    formatdate,
    get_spd,
    humansize,
    s2hms,
    unhumanize,
)
from .mime_util import (  # noqa: F401,E402
    EXTS,
    MAGIC_MAP,
    MIMES,
)


def _ens(want: str) -> tuple[int, ...]:
    ret: list[int] = []
    for v in want.split():
        try:
            ret.append(getattr(errno, v))
        except AttributeError:
            pass

    return tuple(ret)


E_FS_MEH = _ens("EPERM EACCES ENOENT ENOTCAPABLE")
E_FS_CRIT = _ens("EIO EFAULT EUCLEAN ENOTBLK")

UC_CDISP = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._"
BC_CDISP = UC_CDISP.encode("ascii")
UC_CDISP_SET = set(UC_CDISP)
BC_CDISP_SET = set(BC_CDISP)

try:
    import fcntl

    HAVE_FCNTL = True
    HAVE_FICLONE = hasattr(fcntl, "FICLONE")
except ImportError:
    HAVE_FCNTL = False
    HAVE_FICLONE = False

try:
    import ctypes
    import termios
except ImportError:
    pass

try:
    if os.environ.get("PRTY_NO_IFADDR"):
        raise Exception()
    try:
        if os.environ.get("PRTY_SYS_ALL") or os.environ.get("PRTY_SYS_IFADDR"):
            raise ImportError()

        from .stolen.ifaddr import get_adapters
    except ImportError:
        from ifaddr import get_adapters

    HAVE_IFADDR = True
except ImportError:
    HAVE_IFADDR = False

    def get_adapters(include_unconfigured=False):
        return []


try:
    if os.environ.get("PRTY_NO_SQLITE"):
        raise Exception()

    HAVE_SQLITE3 = True
    import sqlite3

    assert hasattr(sqlite3, "connect")  # graalpy
except ImportError:
    HAVE_SQLITE3 = False

try:
    import importlib.util

    HAVE_ZMQ = bool(importlib.util.find_spec("zmq"))
except ImportError:
    HAVE_ZMQ = False

try:
    if os.environ.get("PRTY_NO_PSUTIL"):
        raise Exception()

    HAVE_PSUTIL = True
    import psutil
except ImportError:
    HAVE_PSUTIL = False

try:
    if os.environ.get("PRTY_NO_MAGIC") or (
        ANYWIN and not os.environ.get("PRTY_FORCE_MAGIC")
    ):
        raise Exception()

    import magic
except ImportError:
    pass

if os.environ.get("PRTY_MODSPEC"):
    from inspect import getsourcefile

    print("PRTY_MODSPEC: ifaddr:", getsourcefile(get_adapters))

if True:  # pylint: disable=using-constant-test
    import types
    from collections.abc import Callable, Iterable

    import typing
    from typing import IO, Any, Generator, Optional, Pattern, Protocol, Union

    try:
        from typing import LiteralString
    except ImportError:
        pass

    class RootLogger(Protocol):
        def __call__(self, src: str, msg: str, c: Union[int, str] = 0) -> None:
            return None

    class NamedLogger(Protocol):
        def __call__(self, msg: str, c: Union[int, str] = 0) -> None:
            return None


if TYPE_CHECKING:
    from .authsrv import VFS
    from .broker_util import BrokerCli
    from .up2k import Up2k

FAKE_MP = False

try:
    if os.environ.get("PRTY_NO_MP"):
        raise ImportError()

    import multiprocessing as mp

    # import multiprocessing.dummy as mp
except ImportError:
    # support jython
    mp = None  # type: ignore

if not PY2:
    from io import BytesIO
else:
    from StringIO import StringIO as BytesIO  # type: ignore


try:
    if os.environ.get("PRTY_NO_IPV6"):
        raise Exception()

    socket.inet_pton(socket.AF_INET6, "::1")
    HAVE_IPV6 = True
except ImportError:

    def inet_pton(fam, ip):
        return socket.inet_aton(ip)

    socket.inet_pton = inet_pton
    HAVE_IPV6 = False


try:
    struct.unpack(b">i", b"idgi")
    spack = struct.pack  # type: ignore
    sunpack = struct.unpack  # type: ignore
except (KeyError, IndexError):

    def spack(fmt: bytes, *a: Any) -> bytes:
        return struct.pack(fmt.decode("ascii"), *a)

    def sunpack(fmt: bytes, a: bytes) -> tuple[Any, ...]:
        return struct.unpack(fmt.decode("ascii"), a)


try:
    BITNESS = struct.calcsize(b"P") * 8
except (ValueError, TypeError, UnicodeDecodeError, IndexError):
    BITNESS = struct.calcsize("P") * 8


CAN_SIGMASK = not (ANYWIN or PY2 or GRAAL)


RE_ANSI = re.compile("\033\\[[^mK]*[mK]")
RE_HTML_SH = re.compile(r"[<>&$?`\"';]")
RE_MEMTOTAL = re.compile("^MemTotal:.* kB")
RE_MEMAVAIL = re.compile("^MemAvailable:.* kB")


if PY2:

    def umktrans(s1, s2):
        return {ord(c1): ord(c2) for c1, c2 in zip(s1, s2)}

else:
    umktrans = str.maketrans

FNTL_WIN = umktrans('<>:|?*"\\/', "＜＞：｜？＊＂＼／")
VPTL_WIN = umktrans('<>:|?*"\\', "＜＞：｜？＊＂＼")
APTL_WIN = umktrans('<>:|?*"/', "＜＞：｜？＊＂／")
FNTL_MAC = VPTL_MAC = APTL_MAC = umktrans(":", "：")
FNTL_OS = FNTL_WIN if ANYWIN else FNTL_MAC if MACOS else None
VPTL_OS = VPTL_WIN if ANYWIN else VPTL_MAC if MACOS else None
APTL_OS = APTL_WIN if ANYWIN else APTL_MAC if MACOS else None


BOS_SEP = ("%s" % (os.sep,)).encode("ascii")


if WINDOWS and PY2:
    FS_ENCODING = "utf-8"
else:
    FS_ENCODING = sys.getfilesystemencoding()


SYMTIME = PY36 and os.utime in os.supports_follow_symlinks

META_NOBOTS = '<meta name="robots" content="noindex, nofollow">\n'

# smart enough to understand javascript while also ignoring rel="nofollow"
BAD_BOTS = r"Barkrowler|bingbot|BLEXBot|Googlebot|GoogleOther|GPTBot|PetalBot|SeekportBot|SemrushBot|YandexBot"

FFMPEG_URL = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-git-full.7z"

URL_PRJ = "https://github.com/9001/copyparty"

URL_BUG = URL_PRJ + "/issues/new?labels=bug&template=bug_report.md"

HTTPCODE = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    206: "Partial Content",
    207: "Multi-Status",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    422: "Unprocessable Entity",
    423: "Locked",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    503: "Service Unavailable",
    999: "MissingNo",
}


IMPLICATIONS = [
    ["e2dsa", "e2ds"],
    ["e2ds", "e2d"],
    ["e2tsr", "e2ts"],
    ["e2ts", "e2t"],
    ["e2t", "e2d"],
    ["e2vu", "e2v"],
    ["e2vp", "e2v"],
    ["e2v", "e2d"],
    ["hardlink_only", "hardlink"],
    ["hardlink", "dedup"],
    ["tftpvv", "tftpv"],
    ["nodupem", "nodupe"],
    ["no_dupe_m", "no_dupe"],
    ["sftpvv", "sftpv"],
    ["smbw", "smb"],
    ["smb1", "smb"],
    ["smbvvv", "smbvv"],
    ["smbvv", "smbv"],
    ["smbv", "smb"],
    ["zv", "zmv"],
    ["zv", "zsv"],
    ["z", "zm"],
    ["z", "zs"],
    ["zmvv", "zmv"],
    ["zm4", "zm"],
    ["zm6", "zm"],
    ["zmv", "zm"],
    ["zms", "zm"],
    ["zsv", "zs"],
]
if ANYWIN:
    IMPLICATIONS.extend([["z", "zm4"]])


UNPLICATIONS = [["no_dav", "daw"]]


DAV_ALLPROP_L = [
    "contentclass",
    "creationdate",
    "defaultdocument",
    "displayname",
    "getcontentlanguage",
    "getcontentlength",
    "getcontenttype",
    "getlastmodified",
    "href",
    "iscollection",
    "ishidden",
    "isreadonly",
    "isroot",
    "isstructureddocument",
    "lastaccessed",
    "name",
    "parentname",
    "resourcetype",
    "supportedlock",
]
DAV_ALLPROPS = set(DAV_ALLPROP_L)


FAVICON_MIMES = {
    "gif": "image/gif",
    "png": "image/png",
    "svg": "image/svg+xml",
}


DEF_EXP = "self.ip self.ua self.uname self.host cfg.name cfg.logout vf.scan vf.thsize hdr.cf-ipcountry srv.itime srv.htime"

DEF_MTE = ".files,circle,album,.tn,artist,title,tdate,.bpm,key,.dur,.q,.vq,.aq,vc,ac,fmt,res,.fps,ahash,vhash"

DEF_MTH = "tdate,.vq,.aq,vc,ac,fmt,res,.fps"


REKOBO_KEY = {
    v: ln.split(" ", 1)[0]
    for ln in """
1B 6d B
2B 7d Gb F#
3B 8d Db C#
4B 9d Ab G#
5B 10d Eb D#
6B 11d Bb A#
7B 12d F
8B 1d C
9B 2d G
10B 3d D
11B 4d A
12B 5d E
1A 6m Abm G#m
2A 7m Ebm D#m
3A 8m Bbm A#m
4A 9m Fm
5A 10m Cm
6A 11m Gm
7A 12m Dm
8A 1m Am
9A 2m Em
10A 3m Bm
11A 4m Gbm F#m
12A 5m Dbm C#m
""".strip().split(
        "\n"
    )
    for v in ln.strip().split(" ")[1:]
    if v
}

REKOBO_LKEY = {k.lower(): v for k, v in REKOBO_KEY.items()}


_exestr = "python3 python ffmpeg ffprobe cfssl cfssljson cfssl-certinfo"
CMD_EXEB = set(_exestr.encode("utf-8").split())
CMD_EXES = set(_exestr.split())


# mostly from https://github.com/github/gitignore/blob/main/Global/macOS.gitignore
APPLESAN_TXT = r"/(__MACOS|Icon\r\r)|/\.(_|DS_Store|AppleDouble|LSOverride|DocumentRevisions-|fseventsd|Spotlight-|TemporaryItems|Trashes|VolumeIcon\.icns|com\.apple\.timemachine\.donotpresent|AppleDB|AppleDesktop|apdisk)"
APPLESAN_RE = re.compile(APPLESAN_TXT)


VF_CAREFUL = {"mv_re_t": 5, "rm_re_t": 5, "mv_re_r": 0.1, "rm_re_r": 0.1}

FN_EMB = set([".prologue.html", ".epilogue.html", "readme.md", "preadme.md"])


def read_ram() -> tuple[float, float]:
    # NOTE: apparently no need to consider /sys/fs/cgroup/memory.max
    #  (cgroups2) since the limit is synced to /proc/meminfo
    a = b = 0
    try:
        with open("/proc/meminfo", "rb", 0x10000) as f:
            zsl = f.read(0x10000).decode("ascii", "replace").split("\n")

        p = RE_MEMTOTAL
        zs = next((x for x in zsl if p.match(x)))
        a = int((int(zs.split()[1]) / 0x100000) * 100) / 100

        p = RE_MEMAVAIL
        zs = next((x for x in zsl if p.match(x)))
        b = int((int(zs.split()[1]) / 0x100000) * 100) / 100
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        pass
    return a, b


RAM_TOTAL, RAM_AVAIL = read_ram()


pybin = sys.executable or ""
if EXE:
    pybin = ""
    for zsg in "python3 python".split():
        try:
            if ANYWIN:
                zsg += ".exe"

            zsg = shutil.which(zsg)
            if zsg:
                pybin = zsg
                break
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            pass


def py_desc() -> str:
    interp = platform.python_implementation()
    py_ver = ".".join([str(x) for x in sys.version_info])
    ofs = py_ver.find(".final.")
    if ofs > 0:
        py_ver = py_ver[:ofs]
    if "free-threading" in sys.version:
        py_ver += "t"

    host_os = platform.system()
    compiler = platform.python_compiler().split("http")[0]

    m = re.search(r"([0-9]+\.[0-9\.]+)", platform.version())
    os_ver = m.group(1) if m else ""

    return "{:>9} v{} on {}{} {} [{}]".format(
        interp, py_ver, host_os, BITNESS, os_ver, compiler
    )


def expat_ver() -> str:
    try:
        import pyexpat

        return ".".join([str(x) for x in pyexpat.version_info])
    except ImportError:
        return "?"


def _sqlite_ver() -> str:
    assert sqlite3  # type: ignore  # !rm
    try:
        co = sqlite3.connect(":memory:")
        cur = co.cursor()
        try:
            vs = cur.execute("select * from pragma_compile_options").fetchall()
        except (OSError, ValueError, TypeError, UnicodeDecodeError):
            vs = cur.execute("pragma compile_options").fetchall()

        v = next(x[0].split("=")[1] for x in vs if x[0].startswith("THREADSAFE="))
        cur.close()
        co.close()
    except (OSError, ValueError, TypeError, UnicodeDecodeError):
        v = "W"

    return "{}*{}".format(sqlite3.sqlite_version, v)


try:
    SQLITE_VER = _sqlite_ver()
except (OSError, ValueError, TypeError, UnicodeDecodeError):
    SQLITE_VER = "(None)"

try:
    from jinja2 import __version__ as JINJA_VER
except ImportError:
    JINJA_VER = "(None)"

try:
    if os.environ.get("PRTY_NO_PYFTPD"):
        raise Exception()

    from pyftpdlib.__init__ import __ver__ as PYFTPD_VER
except ImportError:
    PYFTPD_VER = "(None)"

try:
    if os.environ.get("PRTY_NO_PARTFTPY"):
        raise Exception()

    from partftpy.__init__ import __version__ as PARTFTPY_VER
except ImportError:
    PARTFTPY_VER = "(None)"

try:
    if os.environ.get("PRTY_NO_PARAMIKO"):
        raise Exception()

    from paramiko import __version__ as MIKO_VER
except ImportError:
    MIKO_VER = "(None)"


PY_DESC = py_desc()

VERSIONS = "copyparty v{} ({})\n{}\n   sqlite {} | jinja {} | pyftpd {} | tftp {} | miko {}".format(
    S_VERSION,
    S_BUILD_DT,
    PY_DESC,
    SQLITE_VER,
    JINJA_VER,
    PYFTPD_VER,
    PARTFTPY_VER,
    MIKO_VER,
)


try:
    _b64_enc_tl = bytes.maketrans(b"+/", b"-_")
    _b64_dec_tl = bytes.maketrans(b"-_", b"+/")

    def ub64enc(bs: bytes) -> bytes:
        x = binascii.b2a_base64(bs, newline=False)
        return x.translate(_b64_enc_tl)

    def ub64dec(bs: bytes) -> bytes:
        bs = bs.translate(_b64_dec_tl)
        return binascii.a2b_base64(bs)

    def b64enc(bs: bytes) -> bytes:
        return binascii.b2a_base64(bs, newline=False)

    def b64dec(bs: bytes) -> bytes:
        return binascii.a2b_base64(bs)

    zb = b">>>????"
    zb2 = base64.urlsafe_b64encode(zb)
    if zb2 != ub64enc(zb) or zb != ub64dec(zb2):
        raise Exception("bad smoke")

except Exception as ex:
    ub64enc = base64.urlsafe_b64encode  # type: ignore
    ub64dec = base64.urlsafe_b64decode  # type: ignore
    b64enc = base64.b64encode  # type: ignore
    b64dec = base64.b64decode  # type: ignore
    if PY36:
        print("using fallback base64 codec due to %r" % (ex,))


class NotUTF8(Exception):
    pass


def read_utf8(log: Optional["NamedLogger"], ap: Union[str, bytes], strict: bool) -> str:
    with open(ap, "rb") as f:
        buf = f.read()

    if buf.startswith(b"\xef\xbb\xbf"):
        buf = buf[3:]

    try:
        return buf.decode("utf-8", "strict")
    except UnicodeDecodeError as ex:
        eo = ex.start
        eb = buf[eo : eo + 1]

    if not strict:
        t = "WARNING: The file [%s] is not using the UTF-8 character encoding; some characters in the file will be skipped/ignored. The first unreadable character was byte %r at offset %d. Please convert this file to UTF-8 by opening the file in your text-editor and saving it as UTF-8."
        t = t % (ap, eb, eo)
        if log:
            log(t, 3)
        else:
            print(t)
        return buf.decode("utf-8", "replace")

    t = "ERROR: The file [%s] is not using the UTF-8 character encoding, and cannot be loaded. The first unreadable character was byte %r at offset %d. Please convert this file to UTF-8 by opening the file in your text-editor and saving it as UTF-8."
    t = t % (ap, eb, eo)
    if log:
        log(t, 3)
    else:
        print(t)
    raise NotUTF8(t)


class Cooldown(object):
    def __init__(self, maxage: float) -> None:
        self.maxage = maxage
        self.mutex = threading.Lock()
        self.hist: dict[str, float] = {}
        self.oldest = 0.0

    def poke(self, key: str) -> bool:
        with self.mutex:
            now = time.time()

            ret = False
            pv: float = self.hist.get(key, 0)
            if now - pv > self.maxage:
                self.hist[key] = now
                ret = True

            if self.oldest - now > self.maxage * 2:
                self.hist = {
                    k: v for k, v in self.hist.items() if now - v < self.maxage
                }
                self.oldest = sorted(self.hist.values())[0]

            return ret


class HLog(logging.Handler):
    def __init__(self, log_func: "RootLogger") -> None:
        logging.Handler.__init__(self)
        self.log_func = log_func
        self.ptn_ftp = re.compile(r"^([0-9a-f:\.]+:[0-9]{1,5})-\[")
        self.ptn_smb_ign = re.compile(r"^(Callback added|Config file parsed)")

    def __repr__(self) -> str:
        level = logging.getLevelName(self.level)
        return "<%s cpp(%s)>" % (self.__class__.__name__, level)

    def flush(self) -> None:
        pass

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        lv = record.levelno
        if lv < logging.INFO:
            c = 6
        elif lv < logging.WARNING:
            c = 0
        elif lv < logging.ERROR:
            c = 3
        else:
            c = 1

        if record.name == "pyftpdlib":
            m = self.ptn_ftp.match(msg)
            if m:
                ip = m.group(1)
                msg = msg[len(ip) + 1 :]
                if ip.startswith("::ffff:"):
                    record.name = ip[7:]
                else:
                    record.name = ip
        elif record.name.startswith("impacket"):
            if self.ptn_smb_ign.match(msg):
                return
        elif record.name.startswith("partftpy."):
            record.name = record.name[9:]

        self.log_func(record.name[-21:], msg, c)


class CachedSet(object):
    def __init__(self, maxage: float) -> None:
        self.c: dict[Any, float] = {}
        self.maxage = maxage
        self.oldest = 0.0

    def add(self, v: Any) -> None:
        self.c[v] = time.time()

    def cln(self) -> None:
        now = time.time()
        if now - self.oldest < self.maxage:
            return

        c = self.c = {k: v for k, v in self.c.items() if now - v < self.maxage}
        try:
            self.oldest = c[min(c, key=c.get)]  # type: ignore
        except (ValueError, KeyError):
            self.oldest = now


class CachedDict(object):
    def __init__(self, maxage: float) -> None:
        self.c: dict[str, tuple[float, Any]] = {}
        self.maxage = maxage
        self.oldest = 0.0

    def set(self, k: str, v: Any) -> None:
        now = time.time()
        self.c[k] = (now, v)
        if now - self.oldest < self.maxage:
            return

        c = self.c = {k: v for k, v in self.c.items() if now - v[0] < self.maxage}
        try:
            self.oldest = min([x[0] for x in c.values()])
        except (ValueError, KeyError):
            self.oldest = now

    def get(self, k: str) -> Optional[tuple[str, Any]]:
        try:
            ts, ret = self.c[k]
            now = time.time()
            if now - ts > self.maxage:
                del self.c[k]
                return None
            return ret
        except (KeyError, TypeError):
            return None


class FHC(object):
    class CE(object):
        def __init__(self, fh: typing.BinaryIO) -> None:
            self.ts: float = 0
            self.fhs = [fh]
            self.all_fhs = set([fh])

    def __init__(self) -> None:
        self.cache: dict[str, FHC.CE] = {}
        self.aps: dict[str, int] = {}

    def close(self, path: str) -> None:
        try:
            ce = self.cache[path]
        except KeyError:
            return

        for fh in ce.fhs:
            fh.close()

        del self.cache[path]
        del self.aps[path]

    def clean(self) -> None:
        if not self.cache:
            return

        keep = {}
        now = time.time()
        for path, ce in self.cache.items():
            if now < ce.ts + 5:
                keep[path] = ce
            else:
                for fh in ce.fhs:
                    fh.close()

        self.cache = keep

    def pop(self, path: str) -> typing.BinaryIO:
        return self.cache[path].fhs.pop()

    def put(self, path: str, fh: typing.BinaryIO) -> None:
        if path not in self.aps:
            self.aps[path] = 0

        try:
            ce = self.cache[path]
            ce.all_fhs.add(fh)
            ce.fhs.append(fh)
        except (KeyError, IndexError):
            ce = self.CE(fh)
            self.cache[path] = ce

        ce.ts = time.time()


class ProgressPrinter(threading.Thread):
    """
    periodically print progress info without linefeeds
    """

    def __init__(self, log: "NamedLogger", args: argparse.Namespace) -> None:
        threading.Thread.__init__(self, name="pp")
        self.daemon = True
        self.log = log
        self.args = args
        self.msg = ""
        self.end = False
        self.n = -1

    def run(self) -> None:
        sigblock()
        tp = 0
        msg = None
        slp_pr = self.args.scan_pr_r
        slp_ps = min(slp_pr, self.args.scan_st_r)
        no_stdout = self.args.q or slp_pr == slp_ps
        fmt = " {}\033[K\r" if VT100 else " {} $\r"
        while not self.end:
            time.sleep(slp_ps)
            if msg == self.msg or self.end:
                continue

            msg = self.msg
            now = time.time()
            if msg and now - tp >= slp_pr:
                tp = now
                self.log("progress: %r" % (msg,), 6)

            if no_stdout:
                continue

            uprint(fmt.format(msg))
            if PY2:
                sys.stdout.flush()

        if no_stdout:
            return

        if VT100:
            print("\033[K", end="")
        elif msg:
            print("------------------------")

        sys.stdout.flush()  # necessary on win10 even w/ stderr btw


class HMaccas(object):
    def __init__(self, keypath: str, retlen: int) -> None:
        self.retlen = retlen
        self.cache: dict[bytes, str] = {}
        try:
            with open(keypath, "rb") as f:
                self.key = f.read()
                if len(self.key) != 64:
                    raise Exception()
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            self.key = os.urandom(64)
            with open(keypath, "wb") as f:
                f.write(self.key)

    def b(self, msg: bytes) -> str:
        try:
            return self.cache[msg]
        except (KeyError, IndexError):
            if len(self.cache) > 9000:
                self.cache = {}

            zb = hmac.new(self.key, msg, hashlib.sha512).digest()
            zs = ub64enc(zb)[: self.retlen].decode("ascii")
            self.cache[msg] = zs
            return zs

    def s(self, msg: str) -> str:
        return self.b(msg.encode("utf-8", "replace"))


class Magician(object):
    def __init__(self) -> None:
        self.bad_magic = False
        self.mutex = threading.Lock()
        self.magic: Optional["magic.Magic"] = None

    def ext(self, fpath: str) -> str:
        try:
            if self.bad_magic:
                raise Exception()

            if not self.magic:
                try:
                    with self.mutex:
                        if not self.magic:
                            self.magic = magic.Magic(uncompress=False, extension=True)
                except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                    self.bad_magic = True
                    raise

            with self.mutex:
                ret = self.magic.from_file(fpath)
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            ret = "?"

        ret = ret.split("/")[0]
        ret = MAGIC_MAP.get(ret, ret)
        if "?" not in ret:
            return ret

        mime = magic.from_file(fpath, mime=True)
        mime = re.split("[; ]", mime, maxsplit=1)[0]
        try:
            return EXTS[mime]
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            pass

        mg = mimetypes.guess_extension(mime)
        if mg:
            return mg[1:]
        else:
            raise Exception()


class Garda(object):
    """ban clients for repeated offenses"""

    def __init__(self, cfg: str, uniq: bool = True) -> None:
        self.uniq = uniq
        try:
            a, b, c = cfg.strip().split(",")
            self.lim = int(a)
            self.win = int(b) * 60
            self.pen = int(c) * 60
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            self.lim = self.win = self.pen = 0

        self.ct: dict[str, list[int]] = {}
        self.prev: dict[str, str] = {}
        self.last_cln = 0

    def cln(self, ip: str) -> None:
        n = 0
        ok = int(time.time() - self.win)
        for v in self.ct[ip]:
            if v < ok:
                n += 1
            else:
                break
        if n:
            te = self.ct[ip][n:]
            if te:
                self.ct[ip] = te
            else:
                del self.ct[ip]
                try:
                    del self.prev[ip]
                except KeyError:
                    pass

    def allcln(self) -> None:
        for k in list(self.ct):
            self.cln(k)

        self.last_cln = int(time.time())

    def bonk(self, ip: str, prev: str) -> tuple[int, str]:
        if not self.lim:
            return 0, ip

        if ":" in ip:
            # assume /64 clients; drop 4 groups
            ip = IPv6Address(ip).exploded[:-20]

        if prev and self.uniq:
            if self.prev.get(ip) == prev:
                return 0, ip

            self.prev[ip] = prev

        now = int(time.time())
        try:
            self.ct[ip].append(now)
        except (KeyError, IndexError):
            self.ct[ip] = [now]

        if now - self.last_cln > 300:
            self.allcln()
        else:
            self.cln(ip)

        if len(self.ct[ip]) >= self.lim:
            return now + self.pen, ip
        else:
            return 0, ip


if WINDOWS and sys.version_info < (3, 8):
    _popen = sp.Popen

    def _spopen(c, *a, **ka):
        enc = sys.getfilesystemencoding()
        c = [x.decode(enc, "replace") if hasattr(x, "decode") else x for x in c]
        return _popen(c, *a, **ka)

    sp.Popen = _spopen


def uprint(msg: str) -> None:
    try:
        print(msg, end="")
    except UnicodeEncodeError:
        try:
            print(msg.encode("utf-8", "replace").decode(), end="")
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            print(msg.encode("ascii", "replace").decode(), end="")


def nuprint(msg: str) -> None:
    uprint("%s\n" % (msg,))


def rice_tid() -> str:
    tid = threading.current_thread().ident
    c = sunpack(b"B" * 5, spack(b">Q", tid)[-5:])
    return "".join("\033[1;37;48;5;{0}m{0:02x}".format(x) for x in c) + "\033[0m"


def trace(*args: Any, **kwargs: Any) -> None:
    t = time.time()
    stack = "".join(
        "\033[36m%s\033[33m%s" % (x[0].split(os.sep)[-1][:-3], x[1])
        for x in traceback.extract_stack()[3:-1]
    )
    parts = ["%.6f" % (t,), rice_tid(), stack]

    if args:
        parts.append(repr(args))

    if kwargs:
        parts.append(repr(kwargs))

    msg = "\033[0m ".join(parts)
    # _tracebuf.append(msg)
    nuprint(msg)


def alltrace(verbose: bool = True) -> str:
    threads: dict[str, types.FrameType] = {}
    names = dict([(t.ident, t.name) for t in threading.enumerate()])
    for tid, stack in sys._current_frames().items():
        if verbose:
            name = "%s (%x)" % (names.get(tid), tid)
        else:
            name = str(names.get(tid))
        threads[name] = stack

    rret: list[str] = []
    bret: list[str] = []
    np = -3 if verbose else -2
    for name, stack in sorted(threads.items()):
        ret = ["\n\n# %s" % (name,)]
        pad = None
        for fn, lno, name, line in traceback.extract_stack(stack):
            fn = os.sep.join(fn.split(os.sep)[np:])
            ret.append('File: "%s", line %d, in %s' % (fn, lno, name))
            if line:
                ret.append("  " + str(line.strip()))
                if "self.not_empty.wait()" in line:
                    pad = " " * 4

        if pad:
            bret += [ret[0]] + [pad + x for x in ret[1:]]
        else:
            rret.extend(ret)

    return "\n".join(rret + bret) + "\n"


def start_stackmon(arg_str: str, nid: int) -> None:
    suffix = "-{}".format(nid) if nid else ""
    fp, f = arg_str.rsplit(",", 1)
    zi = int(f)
    Daemon(stackmon, "stackmon" + suffix, (fp, zi, suffix))


def stackmon(fp: str, ival: float, suffix: str) -> None:
    ctr = 0
    fp0 = fp
    while True:
        ctr += 1
        fp = fp0
        time.sleep(ival)
        st = "{}, {}\n{}".format(ctr, time.time(), alltrace())
        buf = st.encode("utf-8", "replace")

        if fp.endswith(".gz"):
            # 2459b 2304b 2241b 2202b 2194b 2191b lv3..8
            # 0.06s 0.08s 0.11s 0.13s 0.16s 0.19s
            buf = gzip.compress(buf, compresslevel=6)

        elif fp.endswith(".xz"):
            import lzma

            # 2276b 2216b 2200b 2192b 2168b lv0..4
            # 0.04s 0.10s 0.22s 0.41s 0.70s
            buf = lzma.compress(buf, preset=0)

        if "%" in fp:
            dt = datetime.now(UTC)
            for fs in "YmdHMS":
                fs = "%" + fs
                if fs in fp:
                    fp = fp.replace(fs, dt.strftime(fs))

        if "/" in fp:
            try:
                os.makedirs(fp.rsplit("/", 1)[0])
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                pass

        with open(fp + suffix, "wb") as f:
            f.write(buf)


def start_log_thrs(
    logger: Callable[[str, str, int], None], ival: float, nid: int
) -> None:
    ival = float(ival)
    tname = lname = "log-thrs"
    if nid:
        tname = "logthr-n{}-i{:x}".format(nid, os.getpid())
        lname = tname[3:]

    Daemon(log_thrs, tname, (logger, ival, lname))


def log_thrs(log: Callable[[str, str, int], None], ival: float, name: str) -> None:
    while True:
        time.sleep(ival)
        tv = [x.name for x in threading.enumerate()]
        tv = [
            x.split("-")[0]
            if x.split("-")[0] in ["httpconn", "thumb", "tagger"]
            else "listen"
            if "-listen-" in x
            else x
            for x in tv
            if not x.startswith("pydevd.")
        ]
        tv = ["{}\033[36m{}".format(v, k) for k, v in sorted(Counter(tv).items())]
        log(name, "\033[0m \033[33m".join(tv), 3)


def _sigblock():
    signal.pthread_sigmask(
        signal.SIG_BLOCK, [signal.SIGINT, signal.SIGTERM, signal.SIGUSR1]
    )


sigblock = _sigblock if CAN_SIGMASK else noop


def vol_san(vols: list["VFS"], txt: bytes) -> bytes:
    txt0 = txt
    for vol in vols:
        bap = vol.realpath.encode("utf-8")
        bhp = vol.histpath.encode("utf-8")
        bvp = vol.vpath.encode("utf-8")
        bvph = b"$hist(/" + bvp + b")"

        if bap:
            txt = txt.replace(bap, bvp)
            txt = txt.replace(bap.replace(b"\\", b"\\\\"), bvp)
        if bhp:
            txt = txt.replace(bhp, bvph)
            txt = txt.replace(bhp.replace(b"\\", b"\\\\"), bvph)

        if vol.histpath != vol.dbpath:
            bdp = vol.dbpath.encode("utf-8")
            bdph = b"$db(/" + bvp + b")"
            txt = txt.replace(bdp, bdph)
            txt = txt.replace(bdp.replace(b"\\", b"\\\\"), bdph)

    if txt != txt0:
        txt += b"\r\nNOTE: filepaths sanitized; see serverlog for correct values"

    return txt


def min_ex(max_lines: int = 8, reverse: bool = False) -> str:
    et, ev, tb = sys.exc_info()
    stb = traceback.extract_tb(tb) if tb else traceback.extract_stack()[:-1]
    fmt = "%s:%d <%s>: %s"
    ex = [fmt % (fp.split(os.sep)[-1], ln, fun, txt) for fp, ln, fun, txt in stb]
    if et or ev or tb:
        ex.append("[%s] %s" % (et.__name__ if et else "(anonymous)", ev))
    return "\n".join(ex[-max_lines:][:: -1 if reverse else 1])


def _gen_filekey(alg: int, salt: str, fspath: str, fsize: int, inode: int) -> str:
    if alg == 1:
        zs = "%s %s %s %s" % (salt, fspath, fsize, inode)
    else:
        zs = "%s %s" % (salt, fspath)

    zb = zs.encode("utf-8", "replace")
    return ub64enc(hashlib.sha512(zb).digest()).decode("ascii")


def _gen_filekey_w(alg: int, salt: str, fspath: str, fsize: int, inode: int) -> str:
    return _gen_filekey(alg, salt, fspath.replace("/", "\\"), fsize, inode)


gen_filekey = _gen_filekey_w if ANYWIN else _gen_filekey


def gen_filekey_dbg(
    alg: int,
    salt: str,
    fspath: str,
    fsize: int,
    inode: int,
    log: "NamedLogger",
    log_ptn: Optional[Pattern[str]],
) -> str:
    ret = gen_filekey(alg, salt, fspath, fsize, inode)

    assert log_ptn  # !rm
    if log_ptn.search(fspath):
        try:
            import inspect

            ctx = ",".join(inspect.stack()[n].function for n in range(2, 5))
        except ImportError:
            ctx = ""

        p2 = "a"
        try:
            p2 = absreal(fspath)
            if p2 != fspath:
                raise Exception()
        except Exception:
            t = "maybe wrong abspath for filekey;\norig: %r\nreal: %r"
            log(t % (fspath, p2), 1)

        t = "fk(%s) salt(%s) size(%d) inode(%d) fspath(%r) at(%s)"
        log(t % (ret[:8], salt, fsize, inode, fspath, ctx), 5)

    return ret


def gencookie(
    k: str, v: str, r: str, lax: bool, tls: bool, dur: int = 0, txt: str = ""
) -> str:
    v = v.replace("%", "%25").replace(";", "%3B")
    if dur:
        exp = formatdate(time.time() + dur)
    else:
        exp = "Fri, 15 Aug 1997 01:00:00 GMT"

    t = "%s=%s; Path=/%s; Expires=%s%s%s; SameSite=%s"
    return t % (
        k,
        v,
        r,
        exp,
        "; Secure" if tls else "",
        txt,
        "Lax" if lax else "Strict",
    )


def gen_content_disposition(fn: str) -> str:
    safe = UC_CDISP_SET
    bsafe = BC_CDISP_SET
    fn = fn.replace("/", "_").replace("\\", "_")
    zb = fn.encode("utf-8", "xmlcharrefreplace")
    if not PY2:
        zbl = [
            chr(x).encode("utf-8")
            if x in bsafe
            else "%{:02X}".format(x).encode("ascii")
            for x in zb
        ]
    else:
        zbl = [unicode(x) if x in bsafe else "%{:02X}".format(ord(x)) for x in zb]

    ufn = b"".join(zbl).decode("ascii")
    afn = "".join([x if x in safe else "_" for x in fn]).lstrip(".")
    while ".." in afn:
        afn = afn.replace("..", ".")

    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (afn, ufn)


def sanitize_fn(fn: str) -> str:
    fn = fn.replace("\\", "/").split("/")[-1]
    if APTL_OS:
        fn = sanitize_to(fn, APTL_OS)
    return fn.strip()


def sanitize_to(fn: str, tl: dict[int, int]) -> str:
    fn = fn.translate(tl)
    if ANYWIN:
        bad = ["con", "prn", "aux", "nul"]
        for n in range(1, 10):
            bad += ("com%s lpt%s" % (n, n)).split(" ")

        if fn.lower().split(".")[0] in bad:
            fn = "_" + fn
    return fn


def sanitize_vpath(vp: str) -> str:
    if not APTL_OS:
        return vp
    parts = vp.replace(os.sep, "/").split("/")
    ret = [sanitize_to(x, APTL_OS) for x in parts]
    return "/".join(ret)


def relchk(rp: str) -> str:
    if "\x00" in rp:
        return "[nul]"

    if ANYWIN:
        if "\n" in rp or "\r" in rp:
            return "x\nx"

        p = re.sub(r'[\\:*?"<>|]', "", rp)
        if p != rp:
            return "[{}]".format(p)

    return ""


def absreal(fpath: str) -> str:
    try:
        return fsdec(os.path.abspath(os.path.realpath(afsenc(fpath))))
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        if not WINDOWS:
            raise

        # cpython bug introduced in 3.8, still exists in 3.9.1,
        # some win7sp1 and win10:20H2 boxes cannot realpath a
        # networked drive letter such as b"n:" or b"n:\\"
        return os.path.abspath(os.path.realpath(fpath))


def exclude_dotfiles(filepaths: list[str]) -> list[str]:
    return [x for x in filepaths if not x.split("/")[-1].startswith(".")]


def odfusion(
    base: Union[ODict[str, bool], ODict["LiteralString", bool]], oth: str
) -> ODict[str, bool]:
    # merge an "ordered set" (just a dict really) with another list of keys
    words0 = [x for x in oth.split(",") if x]
    words1 = [x for x in oth[1:].split(",") if x]

    ret = base.copy()
    if oth.startswith("+"):
        for k in words1:
            ret[k] = True  # type: ignore
    elif oth[:1] in ("-", "/"):
        for k in words1:
            ret.pop(k, None)  # type: ignore
    else:
        ret = ODict.fromkeys(words0, True)

    return ret  # type: ignore


def html_sh_esc(s: str) -> str:
    s = re.sub(RE_HTML_SH, "_", s).replace(" ", "%20")
    s = s.replace("\r", "_").replace("\n", "_")
    return s


def _quotep2(txt: str) -> str:
    """url quoter which deals with bytes correctly"""
    if not txt:
        return ""
    btxt = w8enc(txt)
    quot = quote(btxt, safe=b"/")
    return w8dec(quot.replace(b" ", b"+"))  # type: ignore


def _quotep3(txt: str) -> str:
    """url quoter which deals with bytes correctly"""
    if not txt:
        return ""
    btxt = w8enc(txt)
    quot = quote(btxt, safe=b"/").encode("utf-8")
    return w8dec(quot.replace(b" ", b"+"))


if not PY2:
    _uqsb = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~/"
    _uqtl = {
        n: ("%%%02X" % (n,) if n not in _uqsb else chr(n)).encode("utf-8")
        for n in range(256)
    }
    _uqtl[b" "] = b"+"

    def _quotep3b(txt: str) -> str:
        """url quoter which deals with bytes correctly"""
        if not txt:
            return ""
        btxt = w8enc(txt)
        if btxt.rstrip(_uqsb):
            lut = _uqtl
            btxt = b"".join([lut[ch] for ch in btxt])
        return w8dec(btxt)

    quotep = _quotep3b

    _hexd = "0123456789ABCDEFabcdef"
    _hex2b = {(a + b).encode(): bytes.fromhex(a + b) for a in _hexd for b in _hexd}

    def unquote(btxt: bytes) -> bytes:
        h2b = _hex2b
        parts = iter(btxt.split(b"%"))
        ret = [next(parts)]
        for item in parts:
            c = h2b.get(item[:2])
            if c is None:
                ret.append(b"%")
                ret.append(item)
            else:
                ret.append(c)
                ret.append(item[2:])
        return b"".join(ret)

    from urllib.parse import quote_from_bytes as quote
else:
    from urllib import quote  # type: ignore # pylint: disable=no-name-in-module
    from urllib import unquote  # type: ignore # pylint: disable=no-name-in-module

    quotep = _quotep2


def unquotep(txt: str) -> str:
    """url unquoter which deals with bytes correctly"""
    btxt = w8enc(txt)
    unq2 = unquote(btxt)
    return w8dec(unq2)


def log_reloc(
    log: "NamedLogger",
    re: dict[str, str],
    pm: tuple[str, str, str, tuple["VFS", str]],
    ap: str,
    vp: str,
    fn: str,
    vn: "VFS",
    rem: str,
) -> None:
    nap, nvp, nfn, (nvn, nrem) = pm
    t = "reloc %s:\nold ap %r\nnew ap %r\033[36m/%r\033[0m\nold vp %r\nnew vp %r\033[36m/%r\033[0m\nold fn %r\nnew fn %r\nold vfs %r\nnew vfs %r\nold rem %r\nnew rem %r"
    log(t % (re, ap, nap, nfn, vp, nvp, nfn, fn, nfn, vn.vpath, nvn.vpath, rem, nrem))


def pathmod(
    vfs: "VFS", ap: str, vp: str, mod: dict[str, str]
) -> Optional[tuple[str, str, str, tuple["VFS", str]]]:
    # vfs: authsrv.vfs
    # ap: original abspath to a file
    # vp: original urlpath to a file
    # mod: modification (ap/vp/fn)

    nvp = "\n"  # new vpath
    ap = os.path.dirname(ap)
    vp, fn = vsplit(vp)
    if mod.get("fn"):
        fn = mod["fn"]
        nvp = vp

    for ref, k in ((ap, "ap"), (vp, "vp")):
        if k not in mod:
            continue

        ms = mod[k].replace(os.sep, "/")
        if ms.startswith("/"):
            np = ms
        elif k == "vp":
            np = undot(vjoin(ref, ms))
        else:
            np = os.path.abspath(os.path.join(ref, ms))

        if k == "vp":
            nvp = np.lstrip("/")
            continue

        # try to map abspath to vpath
        np = np.replace("/", os.sep)
        for vn_ap, vns in vfs.all_aps:
            if not np.startswith(vn_ap):
                continue
            zs = np[len(vn_ap) :].replace(os.sep, "/")
            nvp = vjoin(vns[0].vpath, zs)
            break

    if nvp == "\n":
        return None

    vn, rem = vfs.get(nvp, "*", False, False)
    if not vn.realpath:
        raise Exception("unmapped vfs")

    ap = vn.canonical(rem)
    return ap, nvp, fn, (vn, rem)


def _w8dec2(txt: bytes) -> str:
    """decodes filesystem-bytes to wtf8"""
    return surrogateescape.decodefilename(txt)  # type: ignore


def _w8enc2(txt: str) -> bytes:
    """encodes wtf8 to filesystem-bytes"""
    return surrogateescape.encodefilename(txt)  # type: ignore


def _w8dec3(txt: bytes) -> str:
    """decodes filesystem-bytes to wtf8"""
    return txt.decode(FS_ENCODING, "surrogateescape")


def _w8enc3(txt: str) -> bytes:
    """encodes wtf8 to filesystem-bytes"""
    return txt.encode(FS_ENCODING, "surrogateescape")


def _msdec(txt: bytes) -> str:
    ret = txt.decode(FS_ENCODING, "surrogateescape")
    return ret[4:] if ret.startswith("\\\\?\\") else ret


def _msaenc(txt: str) -> bytes:
    return txt.replace("/", "\\").encode(FS_ENCODING, "surrogateescape")


def _uncify(txt: str) -> str:
    txt = txt.replace("/", "\\")
    if ":" not in txt and not txt.startswith("\\\\"):
        txt = absreal(txt)

    return txt if txt.startswith("\\\\") else "\\\\?\\" + txt


def _msenc(txt: str) -> bytes:
    txt = txt.replace("/", "\\")
    if ":" not in txt and not txt.startswith("\\\\"):
        txt = absreal(txt)

    ret = txt.encode(FS_ENCODING, "surrogateescape")
    return ret if ret.startswith(b"\\\\") else b"\\\\?\\" + ret


w8dec = _w8dec3 if not PY2 else _w8dec2
w8enc = _w8enc3 if not PY2 else _w8enc2


def w8b64dec(txt: str) -> str:
    """decodes base64(filesystem-bytes) to wtf8"""
    return w8dec(ub64dec(txt.encode("ascii")))


def w8b64enc(txt: str) -> str:
    """encodes wtf8 to base64(filesystem-bytes)"""
    return ub64enc(w8enc(txt)).decode("ascii")


if not PY2 and WINDOWS:
    sfsenc = w8enc
    afsenc = _msaenc
    fsenc = _msenc
    fsdec = _msdec
    uncify = _uncify
elif not PY2 or not WINDOWS:
    fsenc = afsenc = sfsenc = w8enc
    fsdec = w8dec
    uncify = str
else:
    # moonrunes become \x3f with bytestrings,
    # losing mojibake support is worth
    def _not_actually_mbcs_enc(txt: str) -> bytes:
        return txt  # type: ignore

    def _not_actually_mbcs_dec(txt: bytes) -> str:
        return txt  # type: ignore

    fsenc = afsenc = sfsenc = _not_actually_mbcs_enc
    fsdec = _not_actually_mbcs_dec
    uncify = str


def s3enc(mem_cur: "sqlite3.Cursor", rd: str, fn: str) -> tuple[str, str]:
    ret: list[str] = []
    for v in [rd, fn]:
        try:
            mem_cur.execute("select * from a where b = ?", (v,))
            ret.append(v)
        except (KeyError, IndexError):
            ret.append("//" + w8b64enc(v))
            # self.log("mojien [{}] {}".format(v, ret[-1][2:]))

    return ret[0], ret[1]


def s3dec(rd: str, fn: str) -> tuple[str, str]:
    return (
        w8b64dec(rd[2:]) if rd.startswith("//") else rd,
        w8b64dec(fn[2:]) if fn.startswith("//") else fn,
    )


def db_ex_chk(log: "NamedLogger", ex: Exception, db_path: str) -> bool:
    if str(ex) != "database is locked":
        return False

    Daemon(lsof, "dbex", (log, db_path))
    return True


def guess_mime(
    url: str, path: str = "", fallback: str = "application/octet-stream"
) -> str:
    try:
        ext = url.rsplit(".", 1)[1].lower()
    except (IndexError, AttributeError):
        ext = ""

    ret = MIMES.get(ext)

    if not ret:
        x = mimetypes.guess_type(url)
        ret = "application/{}".format(x[1]) if x[1] else x[0]

    if not ret and path:
        try:
            with open(fsenc(path), "rb", 0) as f:
                ret = magic.from_buffer(f.read(4096), mime=True)
                if ret.startswith("text/htm"):
                    # avoid serving up HTML content unless there was actually a .html extension
                    ret = "text/plain"
        except Exception as ex:
            pass

    if not ret:
        ret = fallback

    if ";" not in ret:
        if ret.startswith("text/") or ret.endswith("/javascript"):
            ret += "; charset=utf-8"

    return ret


def gzip_orig_sz(fn: str) -> int:
    with open(fsenc(fn), "rb") as f:
        return gzip_file_orig_sz(f)


def gzip_file_orig_sz(f) -> int:
    start = f.tell()
    f.seek(-4, 2)
    rv = f.read(4)
    f.seek(start, 0)
    return sunpack(b"I", rv)[0]  # type: ignore


class Pebkac(Exception):
    def __init__(
        self, code: int, msg: Optional[str] = None, log: Optional[str] = None
    ) -> None:
        super(Pebkac, self).__init__(msg or HTTPCODE[code])
        self.code = code
        self.log = log

    def __repr__(self) -> str:
        return "Pebkac({}, {})".format(self.code, repr(self.args))


class WrongPostKey(Pebkac):
    def __init__(
        self,
        expected: str,
        got: str,
        fname: Optional[str],
        datagen: Generator[bytes, None, None],
    ) -> None:
        msg = 'expected field "{}", got "{}"'.format(expected, got)
        super(WrongPostKey, self).__init__(422, msg)

        self.expected = expected
        self.got = got
        self.fname = fname
        self.datagen = datagen


_: Any = (
    gzip,
    mp,
    zlib,
    BytesIO,
    quote,
    unquote,
    SQLITE_VER,
    JINJA_VER,
    PYFTPD_VER,
    PARTFTPY_VER,
)
__all__ = [
    "gzip",
    "mp",
    "zlib",
    "BytesIO",
    "quote",
    "unquote",
    "SQLITE_VER",
    "JINJA_VER",
    "PYFTPD_VER",
    "PARTFTPY_VER",
]

# re-exports from extracted modules that depend on util.py symbols
# (must be at end to avoid circular imports)
from .proc_util import (  # noqa: F401,E402
    Daemon,
    NICEB,
    NICES,
    ZMQ,
    ZMQ_DESC,
    _find_nice,
    _parsehook,
    _runhook,
    _zmq_hook,
    chkcmd,
    getalive,
    killtree,
    loadpy,
    mchkcmd,
    retchk,
    runcmd,
    runhook,
    runihook,
)
from .fs_util import (  # noqa: F401,E402
    atomic_move,
    dir_is_empty,
    get_df,
    hidedir,
    lock_file,
    lsof,
    rand_name,
    rmdirs,
    rmdirs_up,
    ren_open,
    set_ap_perms,
    set_fperms,
    statdir,
    trystat_shutil_copy2,
    wunlink,
    _fs_mvrm,
)
from .net_util import (  # noqa: F401,E402
    E_ACCESS,
    E_ADDR_IN_USE,
    E_ADDR_NOT_AVAIL,
    E_SCK,
    E_SCK_WR,
    E_UNREACH,
    IP6ALL,
    IP6_LL,
    IP64_LL,
    NetMap,
    Netdev,
    Unrecv,
    UnrecvEOF,
    _LUnrecv,
    _Unrecv,
    build_netmap,
    find_prefix,
    hashcopy,
    ipnorm,
    justcopy,
    list_ips,
    load_ipr,
    load_ipu,
    read_socket,
    read_socket_chunked,
    read_socket_unbounded,
    sendfile_kern,
    sendfile_py,
    shut_socket,
    siocoutq,
    yieldfile,
)
from .multipart_util import (  # noqa: F401,E402
    MultipartParser,
    get_boundary,
    read_header,
)
from .hash_util import MTHash  # noqa: F401,E402
from .resource_util import (  # noqa: F401,E402
    _find_impresource,
    _has_resource,
    _pkg_resource_exists,
    _rescache_has,
    has_resource,
    load_resource,
    stat_resource,
)
