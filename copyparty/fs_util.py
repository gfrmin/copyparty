# coding: utf-8
"""Filesystem utilities for copyparty.

Handles file operations, directory management, permissions, and locking.
"""
from __future__ import print_function, unicode_literals

import errno
import hashlib
import os
import re
import shutil
import stat
import sys
import time
import traceback
import typing
from typing import TYPE_CHECKING, Any, Generator, Optional, Union

from .__init__ import ANYWIN, PY2, WINDOWS

try:
    import fcntl

    HAVE_FCNTL = True
except ImportError:
    fcntl = None  # type: ignore
    HAVE_FCNTL = False

try:
    import ctypes
except ImportError:
    ctypes = None  # type: ignore

if TYPE_CHECKING:
    from typing import Protocol

    class RootLogger(Protocol):
        def __call__(self, src: str, msg: str, c: Union[int, str] = 0) -> None:
            return None

    class NamedLogger(Protocol):
        def __call__(self, msg: str, c: Union[int, str] = 0) -> None:
            return None


# late imports from util to avoid circular deps at module level;
# these are resolved when the functions are actually called
# (util.py re-exports fs_util at module scope, so we import from util here)
from .util import (
    BOS_SEP,
    Pebkac,
    fsenc,
    fsdec,
    min_ex,
    runcmd,
    ub64enc,
)


def set_fperms(f: Union[typing.BinaryIO, typing.IO[Any]], vf: dict[str, Any]) -> None:
    fno = f.fileno()
    if "chmod_f" in vf:
        os.fchmod(fno, vf["chmod_f"])
    if "chown" in vf:
        os.fchown(fno, vf["uid"], vf["gid"])


def set_ap_perms(ap: str, vf: dict[str, Any]) -> None:
    zb = fsenc(ap)
    if "chmod_f" in vf:
        os.chmod(zb, vf["chmod_f"])
    if "chown" in vf:
        os.chown(zb, vf["uid"], vf["gid"])


def lsof(log: "NamedLogger", abspath: str) -> None:
    try:
        rc, so, se = runcmd([b"lsof", b"-R", fsenc(abspath)], timeout=45)
        zs = (so.strip() + "\n" + se.strip()).strip()
        log("lsof %r = %s\n%s" % (abspath, rc, zs), 3)
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        log("lsof failed; " + min_ex(), 3)


def trystat_shutil_copy2(log: "NamedLogger", src: bytes, dst: bytes) -> bytes:
    try:
        return shutil.copy2(src, dst)
    except (KeyError, IndexError):
        # ignore failed mtime on linux+ntfs; for example:
        # shutil.py:437 <copy2>: copystat(src, dst, follow_symlinks=follow_symlinks)
        # shutil.py:376 <copystat>: lookup("utime")(dst, ns=(st.st_atime_ns, st.st_mtime_ns),
        # [PermissionError] [Errno 1] Operation not permitted, '/windows/_videos'
        _, _, tb = sys.exc_info()
        for _, _, fun, _ in traceback.extract_tb(tb):
            if fun == "copystat":
                if log:
                    t = "warning: failed to retain some file attributes (timestamp and/or permissions) during copy from %r to %r:\n%s"
                    log(t % (src, dst, min_ex()), 3)
                return dst  # close enough
        raise


def _fs_mvrm(
    log: "NamedLogger", src: str, dst: str, atomic: bool, flags: dict[str, Any]
) -> bool:
    bsrc = fsenc(src)
    bdst = fsenc(dst)
    if atomic:
        k = "mv_re_"
        act = "atomic-rename"
        osfun = os.replace
        args = [bsrc, bdst]
    elif dst:
        k = "mv_re_"
        act = "rename"
        osfun = os.rename
        args = [bsrc, bdst]
    else:
        k = "rm_re_"
        act = "delete"
        osfun = os.unlink
        args = [bsrc]

    maxtime = flags.get(k + "t", 0.0)
    chill = flags.get(k + "r", 0.0)
    if chill < 0.001:
        chill = 0.1

    ino = 0
    t0 = now = time.time()
    for attempt in range(90210):
        try:
            if ino and os.stat(bsrc).st_ino != ino:
                t = "src inode changed; aborting %s %r"
                log(t % (act, src), 1)
                return False
            if (dst and not atomic) and os.path.exists(bdst):
                t = "something appeared at dst; aborting rename %r ==> %r"
                log(t % (src, dst), 1)
                return False
            osfun(*args)  # type: ignore
            if attempt:
                now = time.time()
                t = "%sd in %.2f sec, attempt %d: %r"
                log(t % (act, now - t0, attempt + 1, src))
            return True
        except OSError as ex:
            now = time.time()
            if ex.errno == errno.ENOENT:
                return False
            if not attempt and ex.errno == errno.EXDEV:
                t = "using copy+delete (%s)\n  %s\n  %s"
                log(t % (ex.strerror, src, dst))
                osfun = shutil.move
                continue
            if now - t0 > maxtime or attempt == 90209:
                raise
            if not attempt:
                if not PY2:
                    ino = os.stat(bsrc).st_ino
                t = "%s failed (err.%d); retrying for %d sec: %r"
                log(t % (act, ex.errno, maxtime + 0.99, src))

        time.sleep(chill)

    return False  # makes pylance happy


def atomic_move(log: "NamedLogger", src: str, dst: str, flags: dict[str, Any]) -> None:
    bsrc = fsenc(src)
    bdst = fsenc(dst)
    if PY2:
        if os.path.exists(bdst):
            _fs_mvrm(log, dst, "", False, flags)  # unlink

        _fs_mvrm(log, src, dst, False, flags)  # rename
    elif flags.get("mv_re_t"):
        _fs_mvrm(log, src, dst, True, flags)
    else:
        try:
            os.replace(bsrc, bdst)
        except OSError as ex:
            if ex.errno != errno.EXDEV:
                raise
            t = "using copy+delete (%s);\n  %s\n  %s"
            log(t % (ex.strerror, src, dst))
            try:
                os.unlink(bdst)
            except OSError:
                pass
            shutil.move(bsrc, bdst)  # type: ignore


def wunlink(log: "NamedLogger", abspath: str, flags: dict[str, Any]) -> bool:
    if not flags.get("rm_re_t"):
        os.unlink(fsenc(abspath))
        return True

    return _fs_mvrm(log, abspath, "", False, flags)


def get_df(abspath: str, prune: bool) -> tuple[int, int, str]:
    try:
        ap = fsenc(abspath)
        while prune and not os.path.isdir(ap) and BOS_SEP in ap:
            # strip leafs until it hits an existing folder
            ap = ap.rsplit(BOS_SEP, 1)[0]

        if ANYWIN:
            assert ctypes  # type: ignore  # !rm
            abspath = fsdec(ap)
            bfree = ctypes.c_ulonglong(0)
            btotal = ctypes.c_ulonglong(0)
            bavail = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(  # type: ignore
                ctypes.c_wchar_p(abspath),
                ctypes.pointer(bavail),
                ctypes.pointer(btotal),
                ctypes.pointer(bfree),
            )
            return (bavail.value, btotal.value, "")
        else:
            sv = os.statvfs(ap)
            free = sv.f_frsize * sv.f_bavail
            total = sv.f_frsize * sv.f_blocks
            return (free, total, "")
    except Exception as ex:
        return (0, 0, repr(ex))


def ren_open(fname: str, *args: Any, **kwargs: Any) -> tuple[typing.IO[Any], str]:
    fun = kwargs.pop("fun", open)
    fdir = kwargs.pop("fdir", None)
    suffix = kwargs.pop("suffix", None)
    vf = kwargs.pop("vf", None)
    fperms = vf and "fperms" in vf

    if fname == os.devnull:
        return fun(fname, *args, **kwargs), fname

    if suffix:
        ext = fname.split(".")[-1]
        if len(ext) < 7:
            suffix += "." + ext

    orig_name = fname
    bname = fname
    ext = ""
    while True:
        ofs = bname.rfind(".")
        if ofs < 0 or ofs < len(bname) - 7:
            # doesn't look like an extension anymore
            break

        ext = bname[ofs:] + ext
        bname = bname[:ofs]

    asciified = False
    b64 = ""
    while True:
        f = None
        try:
            if fdir:
                fpath = os.path.join(fdir, fname)
            else:
                fpath = fname

            if suffix and os.path.lexists(fsenc(fpath)):
                fpath += suffix
                fname += suffix
                ext += suffix

            f = fun(fsenc(fpath), *args, **kwargs)
            if b64:
                assert fdir  # !rm
                fp2 = "fn-trunc.%s.txt" % (b64,)
                fp2 = os.path.join(fdir, fp2)
                with open(fsenc(fp2), "wb") as f2:
                    f2.write(orig_name.encode("utf-8"))
                    if fperms:
                        set_fperms(f2, vf)

            if fperms:
                set_fperms(f, vf)

            return f, fname

        except OSError as ex_:
            ex = ex_
            if f:
                f.close()

            # EPERM: android13
            if ex.errno in (errno.EINVAL, errno.EPERM) and not asciified:
                asciified = True
                zsl = []
                for zs in (bname, fname):
                    zs = zs.encode("ascii", "replace").decode("ascii")
                    zs = re.sub(r"[^][a-zA-Z0-9(){}.,+=!-]", "_", zs)
                    zsl.append(zs)
                bname, fname = zsl
                continue

            # ENOTSUP: zfs on ubuntu 20.04
            if ex.errno not in (errno.ENAMETOOLONG, errno.ENOSR, errno.ENOTSUP) and (
                not WINDOWS or ex.errno != errno.EINVAL
            ):
                raise

        if not b64:
            zs = ("%s\n%s" % (orig_name, suffix)).encode("utf-8", "replace")
            b64 = ub64enc(hashlib.sha512(zs).digest()[:12]).decode("ascii")

        badlen = len(fname)
        while len(fname) >= badlen:
            if len(bname) < 8:
                raise ex

            if len(bname) > len(ext):
                # drop the last letter of the filename
                bname = bname[:-1]
            else:
                try:
                    # drop the leftmost sub-extension
                    _, ext = ext.split(".", 1)
                except (KeyError, IndexError):
                    # okay do the first letter then
                    ext = "." + ext[2:]

            fname = "%s~%s%s" % (bname, b64, ext)


def rand_name(fdir: str, fn: str, rnd: int) -> str:
    ok = False
    try:
        ext = "." + fn.rsplit(".", 1)[1]
    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
        ext = ""

    for extra in range(16):
        for _ in range(16):
            if ok:
                break

            nc = rnd + extra
            nb = (6 + 6 * nc) // 8
            zb = ub64enc(os.urandom(nb))
            fn = zb[:nc].decode("ascii") + ext
            ok = not os.path.exists(fsenc(os.path.join(fdir, fn)))

    return fn


def statdir(
    logger: Optional["RootLogger"], scandir: bool, lstat: bool, top: str, throw: bool
) -> Generator[tuple[str, os.stat_result], None, None]:
    if lstat and ANYWIN:
        lstat = False

    if lstat and (PY2 or os.stat not in os.supports_follow_symlinks):
        scandir = False

    src = "statdir"
    try:
        btop = fsenc(top)
        if scandir and hasattr(os, "scandir"):
            src = "scandir"
            with os.scandir(btop) as dh:
                for fh in dh:
                    try:
                        yield (fsdec(fh.name), fh.stat(follow_symlinks=not lstat))
                    except Exception as ex:
                        if not logger:
                            continue

                        logger(src, "[s] {} @ {}".format(repr(ex), fsdec(fh.path)), 6)
        else:
            src = "listdir"
            fun: Any = os.lstat if lstat else os.stat
            btop_ = os.path.join(btop, b"")
            for name in os.listdir(btop):
                abspath = btop_ + name
                try:
                    yield (fsdec(name), fun(abspath))
                except Exception as ex:
                    if not logger:
                        continue

                    logger(src, "[s] {} @ {}".format(repr(ex), fsdec(abspath)), 6)

    except Exception as ex:
        if throw:
            zi = getattr(ex, "errno", 0)
            if zi == errno.ENOENT:
                raise Pebkac(404, str(ex))
            raise

        t = "{} @ {}".format(repr(ex), top)
        if logger:
            logger(src, t, 1)
        else:
            print(t)


def dir_is_empty(logger: "RootLogger", scandir: bool, top: str):
    for _ in statdir(logger, scandir, False, top, False):
        return False
    return True


def rmdirs(
    logger: "RootLogger", scandir: bool, lstat: bool, top: str, depth: int
) -> tuple[list[str], list[str]]:
    """rmdir all descendants, then self"""
    if not os.path.isdir(fsenc(top)):
        top = os.path.dirname(top)
        depth -= 1

    stats = statdir(logger, scandir, lstat, top, False)
    dirs = [x[0] for x in stats if stat.S_ISDIR(x[1].st_mode)]
    if dirs:
        top_ = os.path.join(top, "")
        dirs = [top_ + x for x in dirs]
    ok = []
    ng = []
    for d in reversed(dirs):
        a, b = rmdirs(logger, scandir, lstat, d, depth + 1)
        ok += a
        ng += b

    if depth:
        try:
            os.rmdir(fsenc(top))
            ok.append(top)
        except OSError:
            ng.append(top)

    return ok, ng


def rmdirs_up(top: str, stop: str) -> tuple[list[str], list[str]]:
    """rmdir on self, then all parents"""
    if top == stop:
        return [], [top]

    try:
        os.rmdir(fsenc(top))
    except (KeyError, IndexError):
        return [], [top]

    par = os.path.dirname(top)
    if not par or par == stop:
        return [top], []

    ok, ng = rmdirs_up(par, stop)
    return [top] + ok, ng


def hidedir(dp) -> None:
    if ANYWIN:
        try:
            assert ctypes  # type: ignore  # !rm
            k32 = ctypes.WinDLL("kernel32")
            attrs = k32.GetFileAttributesW(dp)
            if attrs >= 0:
                k32.SetFileAttributesW(dp, attrs | 2)
        except Exception:
            pass


_flocks = {}


def _lock_file_noop(ap: str) -> bool:
    return True


def _lock_file_ioctl(ap: str) -> bool:
    assert fcntl  # type: ignore  # !rm
    try:
        fd = _flocks.pop(ap)
        os.close(fd)
    except (KeyError, OSError):
        pass

    fd = os.open(ap, os.O_RDWR | os.O_CREAT, 438)
    # NOTE: the fcntl.lockf identifier is (pid,node);
    #  the lock will be dropped if os.close(os.open(ap))
    #  is performed anywhere else in this thread

    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _flocks[ap] = fd
        return True
    except Exception as ex:
        eno = getattr(ex, "errno", -1)
        try:
            os.close(fd)
        except OSError:
            pass
        if eno in (errno.EAGAIN, errno.EACCES):
            return False
        print("WARNING: unexpected errno %d from fcntl.lockf; %r" % (eno, ex))
        return True


def _lock_file_windows(ap: str) -> bool:
    try:
        import msvcrt

        try:
            fd = _flocks.pop(ap)
            os.close(fd)
        except ImportError:
            pass

        fd = os.open(ap, os.O_RDWR | os.O_CREAT, 438)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return True
    except Exception as ex:
        eno = getattr(ex, "errno", -1)
        if eno == errno.EACCES:
            return False
        print("WARNING: unexpected errno %d from msvcrt.locking; %r" % (eno, ex))
        return True


if os.environ.get("PRTY_NO_DB_LOCK"):
    lock_file = _lock_file_noop
elif ANYWIN:
    lock_file = _lock_file_windows
elif HAVE_FCNTL:
    lock_file = _lock_file_ioctl
else:
    lock_file = _lock_file_noop
