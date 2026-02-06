# coding: utf-8
"""Process/hook management utilities for copyparty.

Handles daemon threads, process trees, shell commands, and hook execution.
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import shutil
import signal
import subprocess as sp  # nosec
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Iterable, Optional, Union

from .__init__ import ANYWIN, EXE, MACOS, PY2, WINDOWS

if TYPE_CHECKING:
    from typing import Protocol

    class RootLogger(Protocol):
        def __call__(self, src: str, msg: str, c: Union[int, str] = 0) -> None:
            return None

    class NamedLogger(Protocol):
        def __call__(self, msg: str, c: Union[int, str] = 0) -> None:
            return None

    from .authsrv import VFS
    from .broker_util import BrokerCli
    from .up2k import Up2k

    try:
        from typing import LiteralString
    except ImportError:
        pass


from .util import (
    CAN_SIGMASK,
    CMD_EXEB,
    CMD_EXES,
    HAVE_PSUTIL,
    absreal,
    fsdec,
    fsenc,
    pybin,
    s3dec,
    sfsenc,
    uncify,
)

from .path_util import djoin, vjoin

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


class Daemon(threading.Thread):
    def __init__(
        self,
        target: Any,
        name: Optional[str] = None,
        a: Optional[Iterable[Any]] = None,
        r: bool = True,
        ka: Optional[dict[Any, Any]] = None,
    ) -> None:
        threading.Thread.__init__(self, name=name)
        self.a = a or ()
        self.ka = ka or {}
        self.fun = target
        self.daemon = True
        if r:
            self.start()

    def run(self):
        if CAN_SIGMASK:
            signal.pthread_sigmask(
                signal.SIG_BLOCK, [signal.SIGINT, signal.SIGTERM, signal.SIGUSR1]
            )

        self.fun(*self.a, **self.ka)


def getalive(pids: list[int], pgid: int) -> list[int]:
    alive = []
    for pid in pids:
        try:
            if pgid:
                # check if still one of ours
                if os.getpgid(pid) == pgid:
                    alive.append(pid)
            else:
                # windows doesn't have pgroups; assume
                assert psutil  # type: ignore  # !rm
                psutil.Process(pid)
                alive.append(pid)
        except Exception:
            pass

    return alive


def killtree(root: int) -> None:
    """still racy but i tried"""
    try:
        # limit the damage where possible (unixes)
        pgid = os.getpgid(os.getpid())
    except OSError:
        pgid = 0

    if HAVE_PSUTIL:
        assert psutil  # type: ignore  # !rm
        pids = [root]
        parent = psutil.Process(root)
        for child in parent.children(recursive=True):
            pids.append(child.pid)
            child.terminate()
        parent.terminate()
        parent = None
    elif pgid:
        # linux-only
        pids = []
        chk = [root]
        while chk:
            pid = chk[0]
            chk = chk[1:]
            pids.append(pid)
            _, t, _ = runcmd(["pgrep", "-P", str(pid)])
            chk += [int(x) for x in t.strip().split("\n") if x]

        pids = getalive(pids, pgid)  # filter to our pgroup
        for pid in pids:
            os.kill(pid, signal.SIGTERM)
    else:
        # windows gets minimal effort sorry
        os.kill(root, signal.SIGTERM)
        return

    for n in range(10):
        time.sleep(0.1)
        pids = getalive(pids, pgid)
        if not pids or n > 3 and pids == [root]:
            break

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            pass


def _find_nice() -> str:
    if WINDOWS:
        return ""  # use creationflags

    try:
        zs = shutil.which("nice")
        if zs:
            return zs
    except (OSError, ValueError):
        pass

    # busted PATHs and/or py2
    for zs in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
        zs += "/nice"
        if os.path.exists(zs):
            return zs

    return ""


NICES = _find_nice()
NICEB = NICES.encode("utf-8")


def runcmd(
    argv: Union[list[bytes], list[str], list["LiteralString"]],
    timeout: Optional[float] = None,
    **ka: Any
) -> tuple[int, str, str]:
    isbytes = isinstance(argv[0], (bytes, bytearray))
    oom = ka.pop("oom", 0)  # 0..1000
    kill = ka.pop("kill", "t")  # [t]ree [m]ain [n]one
    capture = ka.pop("capture", 3)  # 0=none 1=stdout 2=stderr 3=both

    sin: Optional[bytes] = ka.pop("sin", None)
    if sin:
        ka["stdin"] = sp.PIPE

    cout = sp.PIPE if capture in [1, 3] else None
    cerr = sp.PIPE if capture in [2, 3] else None
    bout: bytes
    berr: bytes

    if ANYWIN:
        if isbytes:
            if argv[0] in CMD_EXEB:
                argv[0] += b".exe"  # type: ignore
        else:
            if argv[0] in CMD_EXES:
                argv[0] += ".exe"  # type: ignore

    if ka.pop("nice", None):
        if WINDOWS:
            ka["creationflags"] = 0x4000
        elif NICEB:
            if isbytes:
                argv = [NICEB] + argv  # type: ignore
            else:
                argv = [NICES] + argv  # type: ignore

    p = sp.Popen(argv, stdout=cout, stderr=cerr, **ka)

    if oom and not ANYWIN and not MACOS:
        try:
            with open("/proc/%d/oom_score_adj" % (p.pid,), "wb") as f:
                f.write(("%d\n" % (oom,)).encode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            pass

    if not timeout or PY2:
        bout, berr = p.communicate(sin)  # type: ignore
    else:
        try:
            bout, berr = p.communicate(sin, timeout=timeout)  # type: ignore
        except sp.TimeoutExpired:
            if kill == "n":
                return -18, "", ""  # SIGCONT; leave it be
            elif kill == "m":
                p.kill()
            else:
                killtree(p.pid)

            try:
                bout, berr = p.communicate(timeout=1)  # type: ignore
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                bout = b""
                berr = b""

    stdout = bout.decode("utf-8", "replace") if cout else ""
    stderr = berr.decode("utf-8", "replace") if cerr else ""

    rc: int = p.returncode
    if rc is None:
        rc = -14  # SIGALRM; failed to kill

    return rc, stdout, stderr


def chkcmd(argv: Union[list[bytes], list[str]], **ka: Any) -> tuple[str, str]:
    ok, sout, serr = runcmd(argv, **ka)
    if ok != 0:
        retchk(ok, argv, serr)
        raise Exception(serr)

    return sout, serr


def mchkcmd(argv: Union[list[bytes], list[str]], timeout: float = 10) -> None:
    if PY2:
        with open(os.devnull, "wb") as f:
            rv = sp.call(argv, stdout=f, stderr=f)
    else:
        rv = sp.call(argv, stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=timeout)

    if rv:
        raise sp.CalledProcessError(rv, (argv[0], b"...", argv[-1]))


def retchk(
    rc: int,
    cmd: Union[list[bytes], list[str]],
    serr: str,
    logger: Optional["NamedLogger"] = None,
    color: Union[int, str] = 0,
    verbose: bool = False,
) -> None:
    if rc < 0:
        rc = 128 - rc

    if not rc or rc < 126 and not verbose:
        return

    s = None
    if rc > 128:
        try:
            s = str(signal.Signals(rc - 128))
        except (ValueError, KeyError):
            pass
    elif rc == 126:
        s = "invalid program"
    elif rc == 127:
        s = "program not found"
    elif verbose:
        s = "unknown"
    else:
        s = "invalid retcode"

    if s:
        t = "{} <{}>".format(rc, s)
    else:
        t = str(rc)

    try:
        c = " ".join([fsdec(x) for x in cmd])  # type: ignore
    except (TypeError, UnicodeDecodeError):
        c = str(cmd)

    t = "error {} from [{}]".format(t, c)
    if serr:
        if len(serr) > 8192:
            zs = "%s\n[ ...TRUNCATED... ]\n%s\n[ NOTE: full msg was %d chars ]"
            serr = zs % (serr[:4096], serr[-4096:].rstrip(), len(serr))
        serr = serr.replace("\n", "\nstderr: ")
        t += "\nstderr: " + serr

    if logger:
        logger(t, color)
    else:
        raise Exception(t)


def _parsehook(
    log: Optional["NamedLogger"], cmd: str
) -> tuple[str, bool, bool, bool, bool, bool, float, dict[str, Any], list[str]]:
    areq = ""
    chk = False
    fork = False
    jtxt = False
    imp = False
    sin = False
    wait = 0.0
    tout = 0.0
    kill = "t"
    cap = 0
    ocmd = cmd
    while "," in cmd[:6]:
        arg, cmd = cmd.split(",", 1)
        if arg == "c":
            chk = True
        elif arg == "f":
            fork = True
        elif arg == "j":
            jtxt = True
        elif arg == "I":
            imp = True
        elif arg == "s":
            sin = True
        elif arg.startswith("w"):
            wait = float(arg[1:])
        elif arg.startswith("t"):
            tout = float(arg[1:])
        elif arg.startswith("c"):
            cap = int(arg[1:])  # 0=none 1=stdout 2=stderr 3=both
        elif arg.startswith("k"):
            kill = arg[1:]  # [t]ree [m]ain [n]one
        elif arg.startswith("a"):
            areq = arg[1:]  # required perms
        elif arg.startswith("i"):
            pass
        elif not arg:
            break
        else:
            t = "hook: invalid flag {} in {}"
            (log or print)(t.format(arg, ocmd))

    env = os.environ.copy()
    try:
        if EXE:
            raise Exception()

        pypath = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        zsl = [str(pypath)] + [str(x) for x in sys.path if x]
        pypath = str(os.pathsep.join(zsl))
        env["PYTHONPATH"] = pypath
    except Exception:
        if not EXE:
            raise

    sp_ka = {
        "env": env,
        "nice": True,
        "oom": 300,
        "timeout": tout,
        "kill": kill,
        "capture": cap,
    }

    argv = cmd.split(",") if "," in cmd else [cmd]

    argv[0] = os.path.expandvars(os.path.expanduser(argv[0]))

    return areq, chk, imp, fork, sin, jtxt, wait, sp_ka, argv


def runihook(
    log: Optional["NamedLogger"],
    verbose: bool,
    cmd: str,
    vol: "VFS",
    ups: list[tuple[str, int, int, str, str, str, int, str]],
) -> bool:
    _, chk, _, fork, _, jtxt, wait, sp_ka, acmd = _parsehook(log, cmd)
    bcmd = [sfsenc(x) for x in acmd]
    if acmd[0].endswith(".py"):
        bcmd = [sfsenc(pybin)] + bcmd

    vps = [vjoin(*list(s3dec(x[3], x[4]))) for x in ups]
    aps = [djoin(vol.realpath, x) for x in vps]
    if jtxt:
        # 0w 1mt 2sz 3rd 4fn 5ip 6at
        ja = [
            {
                "ap": uncify(ap),  # utf8 for json
                "vp": vp,
                "wark": x[0][:16],
                "mt": x[1],
                "sz": x[2],
                "ip": x[5],
                "at": x[6],
            }
            for x, vp, ap in zip(ups, vps, aps)
        ]
        sp_ka["sin"] = json.dumps(ja).encode("utf-8", "replace")
    else:
        sp_ka["sin"] = b"\n".join(fsenc(x) for x in aps)

    if acmd[0].startswith("zmq:"):
        try:
            msg = sp_ka["sin"].decode("utf-8", "replace")
            _zmq_hook(log, verbose, "xiu", acmd[0][4:].lower(), msg, wait, sp_ka)
            if verbose and log:
                log("hook(xiu) %r OK" % (cmd,), 6)
        except Exception as ex:
            if log:
                log("zeromq failed: %r" % (ex,))
        return True

    t0 = time.time()
    if fork:
        Daemon(runcmd, cmd, bcmd, ka=sp_ka)
    else:
        rc, v, err = runcmd(bcmd, **sp_ka)  # type: ignore
        if chk and rc:
            retchk(rc, bcmd, err, log, 5)
            return False

    if wait:
        wait -= time.time() - t0
        if wait > 0:
            time.sleep(wait)

    return True


ZMQ = {}
ZMQ_DESC = {
    "pub": "fire-and-forget to all/any connected SUB-clients",
    "push": "fire-and-forget to one of the connected PULL-clients",
    "req": "send messages to a REP-server and blocking-wait for ack",
}


def _zmq_hook(
    log: Optional["NamedLogger"],
    verbose: bool,
    src: str,
    cmd: str,
    msg: str,
    wait: float,
    sp_ka: dict[str, Any],
) -> tuple[int, str]:
    import zmq

    try:
        mtx = ZMQ["mtx"]
    except ImportError:
        ZMQ["mtx"] = threading.Lock()
        time.sleep(0.1)
        mtx = ZMQ["mtx"]

    ret = ""
    nret = 0
    t0 = time.time()
    if verbose and log:
        log("hook(%s) %r entering zmq-main-lock" % (src, cmd), 6)

    with mtx:
        try:
            mode, sck, mtx = ZMQ[cmd]
        except (KeyError, IndexError):
            mode, uri = cmd.split(":", 1)
            try:
                desc = ZMQ_DESC[mode]
                if log:
                    t = "libzmq(%s) pyzmq(%s) init(%s); %s"
                    log(t % (zmq.zmq_version(), zmq.__version__, cmd, desc))
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                raise Exception("the only supported ZMQ modes are REQ PUB PUSH")

            try:
                ctx = ZMQ["ctx"]
            except (KeyError, IndexError):
                ctx = ZMQ["ctx"] = zmq.Context()

            timeout = sp_ka["timeout"]

            if mode == "pub":
                sck = ctx.socket(zmq.PUB)
                sck.setsockopt(zmq.LINGER, 0)
                sck.bind(uri)
                time.sleep(1)  # give clients time to connect; avoids losing first msg
            elif mode == "push":
                sck = ctx.socket(zmq.PUSH)
                if timeout:
                    sck.SNDTIMEO = int(timeout * 1000)
                sck.setsockopt(zmq.LINGER, 0)
                sck.bind(uri)
            elif mode == "req":
                sck = ctx.socket(zmq.REQ)
                if timeout:
                    sck.RCVTIMEO = int(timeout * 1000)
                sck.setsockopt(zmq.LINGER, 0)
                sck.connect(uri)
            else:
                raise Exception()

            mtx = threading.Lock()
            ZMQ[cmd] = (mode, sck, mtx)

    if verbose and log:
        log("hook(%s) %r entering socket-lock" % (src, cmd), 6)

    with mtx:
        if verbose and log:
            log("hook(%s) %r sending |%d|" % (src, cmd, len(msg)), 6)

        sck.send_string(msg)  # PUSH can safely timeout here

        if mode == "req":
            if verbose and log:
                log("hook(%s) %r awaiting ack from req" % (src, cmd), 6)
            try:
                ret = sck.recv().decode("utf-8", "replace")
                if ret.startswith("return "):
                    m = re.search("^return ([0-9]+)", ret[:12])
                    if m:
                        nret = int(m.group(1))
            except (KeyError, IndexError):
                sck.close()
                del ZMQ[cmd]  # bad state; must reset
                raise Exception("ack timeout; zmq socket killed")

    if ret and log:
        log("hook(%s) %r ACK: %r" % (src, cmd, ret), 6)

    if wait:
        wait -= time.time() - t0
        if wait > 0:
            time.sleep(wait)

    return nret, ret


def _runhook(
    log: Optional["NamedLogger"],
    verbose: bool,
    src: str,
    cmd: str,
    ap: str,
    vp: str,
    host: str,
    uname: str,
    perms: str,
    mt: float,
    sz: int,
    ip: str,
    at: float,
    txt: Optional[list[str]],
) -> dict[str, Any]:
    ret = {"rc": 0}
    areq, chk, imp, fork, sin, jtxt, wait, sp_ka, acmd = _parsehook(log, cmd)
    if areq:
        for ch in areq:
            if ch not in perms:
                t = "user %s not allowed to run hook %s; need perms %s, have %s"
                if log:
                    log(t % (uname, cmd, areq, perms))
                return ret  # fallthrough to next hook
    if imp or jtxt:
        ja = {
            "ap": ap,
            "vp": vp,
            "mt": mt,
            "sz": sz,
            "ip": ip,
            "at": at or time.time(),
            "host": host,
            "user": uname,
            "perms": perms,
            "src": src,
        }
        if txt:
            ja["txt"] = txt[0]
            ja["body"] = txt[1]
        if imp:
            ja["log"] = log
            mod = loadpy(acmd[0], False)
            return mod.main(ja)
        arg = json.dumps(ja)
    else:
        arg = txt[0] if txt else ap

    if acmd[0].startswith("zmq:"):
        zi, zs = _zmq_hook(log, verbose, src, acmd[0][4:].lower(), arg, wait, sp_ka)
        if zi:
            raise Exception("zmq says %d" % (zi,))
        try:
            ret = json.loads(zs)
            if "rc" not in ret:
                ret["rc"] = 0
            return ret
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            return {"rc": 0, "stdout": zs}

    if sin:
        sp_ka["sin"] = (arg + "\n").encode("utf-8", "replace")
    else:
        acmd += [arg]

    if acmd[0].endswith(".py"):
        acmd = [pybin] + acmd

    bcmd = [fsenc(x) if x == ap else sfsenc(x) for x in acmd]

    t0 = time.time()
    if fork:
        Daemon(runcmd, cmd, [bcmd], ka=sp_ka)
    else:
        rc, v, err = runcmd(bcmd, **sp_ka)  # type: ignore
        if chk and rc:
            ret["rc"] = rc
            zi = 0 if rc == 100 else rc
            retchk(zi, bcmd, err, log, 5)
        else:
            try:
                ret = json.loads(v)
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                pass

            try:
                if "stdout" not in ret:
                    ret["stdout"] = v
                if "stderr" not in ret:
                    ret["stderr"] = err
                if "rc" not in ret:
                    ret["rc"] = rc
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                ret = {"rc": rc, "stdout": v, "stderr": err}

    if wait:
        wait -= time.time() - t0
        if wait > 0:
            time.sleep(wait)

    return ret


def runhook(
    log: Optional["NamedLogger"],
    broker: Optional["BrokerCli"],
    up2k: Optional["Up2k"],
    src: str,
    cmds: list[str],
    ap: str,
    vp: str,
    host: str,
    uname: str,
    perms: str,
    mt: float,
    sz: int,
    ip: str,
    at: float,
    txt: Optional[list[str]],
) -> dict[str, Any]:
    assert broker or up2k  # !rm
    args = (broker or up2k).args  # type: ignore
    verbose = args.hook_v
    vp = vp.replace("\\", "/")
    ret = {"rc": 0}
    stop = False
    for cmd in cmds:
        try:
            hr = _runhook(
                log, verbose, src, cmd, ap, vp, host, uname, perms, mt, sz, ip, at, txt
            )
            if verbose and log:
                log("hook(%s) %r => \033[32m%s" % (src, cmd, hr), 6)
            for k, v in hr.items():
                if k in ("idx", "del") and v:
                    if broker:
                        broker.say("up2k.hook_fx", k, v, vp)
                    else:
                        assert up2k  # !rm
                        up2k.fx_backlog.append((k, v, vp))
                elif k == "reloc" and v:
                    # idk, just take the last one ig
                    ret["reloc"] = v
                elif k == "rc" and v:
                    stop = True
                    ret[k] = 0 if v == 100 else v
                elif k in ret:
                    if k == "stdout" and v and not ret[k]:
                        ret[k] = v
                else:
                    ret[k] = v
        except Exception as ex:
            (log or print)("hook: %r, %s" % (ex, ex))
            if ",c," in "," + cmd:
                return {"rc": 1}
            break
        if stop:
            break

    return ret


def loadpy(ap: str, hot: bool) -> Any:
    """
    a nice can of worms capable of causing all sorts of bugs
    depending on what other inconveniently named files happen
    to be in the same folder
    """
    ap = os.path.expandvars(os.path.expanduser(ap))
    mdir, mfile = os.path.split(absreal(ap))
    mname = mfile.rsplit(".", 1)[0]
    sys.path.insert(0, mdir)

    if PY2:
        mod = __import__(mname)
        if hot:
            reload(mod)  # type: ignore
    else:
        import importlib

        mod = importlib.import_module(mname)
        if hot:
            importlib.reload(mod)

    sys.path.remove(mdir)
    return mod
