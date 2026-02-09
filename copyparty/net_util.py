# coding: utf-8
"""Network/socket utilities for copyparty.

Handles socket I/O, network mapping, sendfile, and related operations.
"""
from __future__ import print_function, unicode_literals

import errno
import hashlib
import os
import select
import socket
import threading
import time
import typing
from typing import TYPE_CHECKING, Any, Generator, Optional, Union

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from .__init__ import ANYWIN, MACOS, PY2

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

try:
    import termios
except ImportError:
    termios = None  # type: ignore

if TYPE_CHECKING:
    from typing import Protocol

    class RootLogger(Protocol):
        def __call__(self, src: str, msg: str, c: Union[int, str] = 0) -> None:
            return None

    class NamedLogger(Protocol):
        def __call__(self, msg: str, c: Union[int, str] = 0) -> None:
            return None


from .util import (
    HAVE_IPV6,
    Pebkac,
    fsenc,
    get_adapters,
    sunpack,
    ub64enc,
)


def _ens(want: str) -> tuple[int, ...]:
    ret: list[int] = []
    for v in want.split():
        try:
            ret.append(getattr(errno, v))
        except AttributeError:
            pass

    return tuple(ret)


# WSAECONNRESET - foribly closed by remote
# WSAENOTSOCK - no longer a socket
# EUNATCH - can't assign requested address (wifi down)
E_SCK = _ens("ENOTCONN EUNATCH EBADF WSAENOTSOCK WSAECONNRESET")
E_SCK_WR = _ens("EPIPE ESHUTDOWN EBADFD")
E_ADDR_NOT_AVAIL = _ens("EADDRNOTAVAIL WSAEADDRNOTAVAIL")
E_ADDR_IN_USE = _ens("EADDRINUSE WSAEADDRINUSE")
E_ACCESS = _ens("EACCES WSAEACCES")
E_UNREACH = _ens("EHOSTUNREACH WSAEHOSTUNREACH ENETUNREACH WSAENETUNREACH")

IP6ALL = "0:0:0:0:0:0:0:0"
IP6_LL = ("fe8", "fe9", "fea", "feb")
IP64_LL = ("fe8", "fe9", "fea", "feb", "169.254")


class Netdev(object):
    def __init__(self, ip: str, idx: int, name: str, desc: str):
        self.ip = ip
        self.idx = idx
        self.name = name
        self.desc = desc

    def __str__(self):
        return "{}-{}{}".format(self.idx, self.name, self.desc)

    def __repr__(self):
        return "'{}-{}'".format(self.idx, self.name)

    def __lt__(self, rhs):
        return str(self) < str(rhs)

    def __eq__(self, rhs):
        return str(self) == str(rhs)


class UnrecvEOF(OSError):
    pass


class _Unrecv(object):
    """
    undo any number of socket recv ops
    """

    def __init__(self, s: socket.socket, log: Optional["NamedLogger"]) -> None:
        self.s = s
        self.log = log
        self.buf: bytes = b""
        self.nb = 0
        self.te = 0

    def recv(self, nbytes: int, spins: int = 1) -> bytes:
        if self.buf:
            ret = self.buf[:nbytes]
            self.buf = self.buf[nbytes:]
            self.nb += len(ret)
            return ret

        while True:
            try:
                ret = self.s.recv(nbytes)
                break
            except socket.timeout:
                spins -= 1
                if spins <= 0:
                    ret = b""
                    break
                continue
            except (OSError, ValueError, TypeError, UnicodeDecodeError):
                ret = b""
                break

        if not ret:
            raise UnrecvEOF("client stopped sending data")

        self.nb += len(ret)
        return ret

    def recv_ex(self, nbytes: int, raise_on_trunc: bool = True) -> bytes:
        """read an exact number of bytes"""
        ret = b""
        try:
            while nbytes > len(ret):
                ret += self.recv(nbytes - len(ret))
        except OSError:
            t = "client stopped sending data; expected at least %d more bytes"
            if not ret:
                t = t % (nbytes,)
            else:
                t += ", only got %d"
                t = t % (nbytes, len(ret))
                if len(ret) <= 16:
                    t += "; %r" % (ret,)

            if raise_on_trunc:
                raise UnrecvEOF(5, t)
            elif self.log:
                self.log(t, 3)

        return ret

    def unrecv(self, buf: bytes) -> None:
        self.buf = buf + self.buf
        self.nb -= len(buf)


# !rm.yes>
class _LUnrecv(object):
    """
    with expensive debug logging
    """

    def __init__(self, s: socket.socket, log: Optional["NamedLogger"]) -> None:
        self.s = s
        self.log = log
        self.buf = b""
        self.nb = 0

    def recv(self, nbytes: int, spins: int) -> bytes:
        if self.buf:
            ret = self.buf[:nbytes]
            self.buf = self.buf[nbytes:]
            t = "\033[0;7mur:pop:\033[0;1;32m {}\n\033[0;7mur:rem:\033[0;1;35m {}\033[0m"
            print(t.format(ret, self.buf))
            self.nb += len(ret)
            return ret

        ret = self.s.recv(nbytes)
        t = "\033[0;7mur:recv\033[0;1;33m {}\033[0m"
        print(t.format(ret))
        if not ret:
            raise UnrecvEOF("client stopped sending data")

        self.nb += len(ret)
        return ret

    def recv_ex(self, nbytes: int, raise_on_trunc: bool = True) -> bytes:
        """read an exact number of bytes"""
        try:
            ret = self.recv(nbytes, 1)
            err = False
        except (OSError, ValueError, TypeError, UnicodeDecodeError):
            ret = b""
            err = True

        while not err and len(ret) < nbytes:
            try:
                ret += self.recv(nbytes - len(ret), 1)
            except OSError:
                err = True

        if err:
            t = "client only sent {} of {} expected bytes".format(len(ret), nbytes)
            if raise_on_trunc:
                raise UnrecvEOF(t)
            elif self.log:
                self.log(t, 3)

        return ret

    def unrecv(self, buf: bytes) -> None:
        self.buf = buf + self.buf
        self.nb -= len(buf)
        t = "\033[0;7mur:push\033[0;1;31m {}\n\033[0;7mur:rem:\033[0;1;35m {}\033[0m"
        print(t.format(buf, self.buf))


# !rm.no>


Unrecv = _Unrecv


def ipnorm(ip: str) -> str:
    if ":" in ip:
        # assume /64 clients; drop 4 groups
        return IPv6Address(ip).exploded[:-20]

    return ip


def find_prefix(ips: list[str], cidrs: list[str]) -> list[str]:
    ret = []
    for ip in ips:
        hit = next((x for x in cidrs if x.startswith(ip + "/") or ip == x), None)
        if hit:
            ret.append(hit)
    return ret


class NetMap(object):
    def __init__(
        self,
        ips: list[str],
        cidrs: list[str],
        keep_lo=False,
        strict_cidr=False,
        defer_mutex=False,
    ) -> None:
        """
        ips: list of plain ipv4/ipv6 IPs, not cidr
        cidrs: list of cidr-notation IPs (ip/prefix)
        """

        # fails multiprocessing; defer assignment
        self.mutex: Optional[threading.Lock] = None if defer_mutex else threading.Lock()

        if "::" in ips:
            ips = [x for x in ips if x != "::"] + list(
                [x.split("/")[0] for x in cidrs if ":" in x]
            )
            ips.append("0.0.0.0")

        if "0.0.0.0" in ips:
            ips = [x for x in ips if x != "0.0.0.0"] + list(
                [x.split("/")[0] for x in cidrs if ":" not in x]
            )

        if not keep_lo:
            ips = [x for x in ips if x not in ("::1", "127.0.0.1")]

        ips = find_prefix(ips, cidrs)

        self.cache: dict[str, str] = {}
        self.b2sip: dict[bytes, str] = {}
        self.b2net: dict[bytes, Union[IPv4Network, IPv6Network]] = {}
        self.bip: list[bytes] = []
        for ip in ips:
            v6 = ":" in ip
            fam = socket.AF_INET6 if v6 else socket.AF_INET
            bip = socket.inet_pton(fam, ip.split("/")[0])
            self.bip.append(bip)
            self.b2sip[bip] = ip.split("/")[0]
            self.b2net[bip] = (IPv6Network if v6 else IPv4Network)(ip, strict_cidr)

        self.bip.sort(reverse=True)

    def map(self, ip: str) -> str:
        if ip.startswith("::ffff:"):
            ip = ip[7:]

        try:
            return self.cache[ip]
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            # intentionally crash the calling thread if unset:
            assert self.mutex  # type: ignore  # !rm

            with self.mutex:
                return self._map(ip)

    def _map(self, ip: str) -> str:
        v6 = ":" in ip
        ci = IPv6Address(ip) if v6 else IPv4Address(ip)
        bip = next((x for x in self.bip if ci in self.b2net[x]), None)
        ret = self.b2sip[bip] if bip else ""
        if len(self.cache) > 9000:
            self.cache = {}
        self.cache[ip] = ret
        return ret


if not ANYWIN and not MACOS:

    def siocoutq(sck: socket.socket) -> int:
        assert fcntl  # type: ignore  # !rm
        assert termios  # type: ignore  # !rm
        # SIOCOUTQ^sockios.h == TIOCOUTQ^ioctl.h
        try:
            zb = fcntl.ioctl(sck.fileno(), termios.TIOCOUTQ, b"AAAA")
            return sunpack(b"I", zb)[0]  # type: ignore
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            return 1

else:
    # macos: getsockopt(fd, SOL_SOCKET, SO_NWRITE, ...)
    # windows: TcpConnectionEstatsSendBuff

    def siocoutq(sck: socket.socket) -> int:
        return 1


def shut_socket(log: "NamedLogger", sck: socket.socket, timeout: int = 3) -> None:
    t0 = time.time()
    fd = sck.fileno()
    if fd == -1:
        sck.close()
        return

    try:
        sck.settimeout(timeout)
        sck.shutdown(socket.SHUT_WR)
        try:
            while time.time() - t0 < timeout:
                if not siocoutq(sck):
                    # kernel says tx queue empty, we good
                    break

                # on windows in particular, drain rx until client shuts
                if not sck.recv(32 * 1024):
                    break

            sck.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError, TypeError, UnicodeDecodeError):
            pass
    except Exception as ex:
        log("shut({}): {}".format(fd, ex), "90")
    finally:
        td = time.time() - t0
        if td >= 1:
            log("shut({}) in {:.3f} sec".format(fd, td), "90")

        sck.close()


def read_socket(
    sr: Unrecv, bufsz: int, total_size: int
) -> Generator[bytes, None, None]:
    remains = total_size
    while remains > 0:
        if bufsz > remains:
            bufsz = remains

        try:
            buf = sr.recv(bufsz)
        except OSError:
            t = "client d/c during binary post after {} bytes, {} bytes remaining"
            raise Pebkac(400, t.format(total_size - remains, remains))

        remains -= len(buf)
        yield buf


def read_socket_unbounded(sr: Unrecv, bufsz: int) -> Generator[bytes, None, None]:
    try:
        while True:
            yield sr.recv(bufsz)
    except (OSError, ValueError, TypeError, UnicodeDecodeError):
        return


def read_socket_chunked(
    sr: Unrecv, bufsz: int, log: Optional["NamedLogger"] = None
) -> Generator[bytes, None, None]:
    err = "upload aborted: expected chunk length, got [{}] |{}| instead"
    while True:
        buf = b""
        while b"\r" not in buf:
            try:
                buf += sr.recv(2)
                if len(buf) > 16:
                    raise Exception()
            except (OSError, ValueError, TypeError, UnicodeDecodeError):
                err = err.format(buf.decode("utf-8", "replace"), len(buf))
                raise Pebkac(400, err)

        if not buf.endswith(b"\n"):
            sr.recv(1)

        try:
            chunklen = int(buf.rstrip(b"\r\n"), 16)
        except (OSError, ValueError, TypeError, UnicodeDecodeError):
            err = err.format(buf.decode("utf-8", "replace"), len(buf))
            raise Pebkac(400, err)

        if chunklen == 0:
            x = sr.recv_ex(2, False)
            if x == b"\r\n":
                sr.te = 2
                return

            t = "protocol error after final chunk: want b'\\r\\n', got {!r}"
            raise Pebkac(400, t.format(x))

        if log:
            log("receiving %d byte chunk" % (chunklen,))

        for chunk in read_socket(sr, bufsz, chunklen):
            yield chunk

        x = sr.recv_ex(2, False)
        if x != b"\r\n":
            t = "protocol error in chunk separator: want b'\\r\\n', got {!r}"
            raise Pebkac(400, t.format(x))


def list_ips() -> list[str]:
    ret: set[str] = set()
    for nic in get_adapters():
        for ipo in nic.ips:
            if len(ipo.ip) < 7:
                ret.add(ipo.ip[0])  # ipv6 is (ip,0,0)
            else:
                ret.add(ipo.ip)

    return list(ret)


def build_netmap(csv: str, defer_mutex: bool = False):
    csv = csv.lower().strip()

    if csv in ("any", "all", "no", ",", ""):
        return None

    srcs = [x.strip() for x in csv.split(",") if x.strip()]

    expanded_shorthands = False
    for shorthand in ("lan", "local", "private", "prvt"):
        if shorthand in srcs:
            if not expanded_shorthands:
                srcs += [
                    # lan:
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "fd00::/8",
                    # link-local:
                    "169.254.0.0/16",
                    "fe80::/10",
                    # loopback:
                    "127.0.0.0/8",
                    "::1/128",
                ]
                expanded_shorthands = True

            srcs.remove(shorthand)

    if not HAVE_IPV6:
        srcs = [x for x in srcs if ":" not in x]

    cidrs = []
    for zs in srcs:
        if not zs.endswith("."):
            cidrs.append(zs)
            continue

        # translate old syntax "172.19." => "172.19.0.0/16"
        words = len(zs.rstrip(".").split("."))
        if words == 1:
            zs += "0.0.0/8"
        elif words == 2:
            zs += "0.0/16"
        elif words == 3:
            zs += "0/24"
        else:
            raise Exception("invalid config value [%s]" % (zs,))

        cidrs.append(zs)

    ips = [x.split("/")[0] for x in cidrs]
    return NetMap(ips, cidrs, True, False, defer_mutex)


def load_ipu(
    log: "RootLogger", ipus: list[str], defer_mutex: bool = False
) -> tuple[dict[str, str], NetMap]:
    ip_u = {"": "*"}
    cidr_u = {}
    for ipu in ipus:
        try:
            cidr, uname = ipu.split("=")
            cip, csz = cidr.split("/")
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            t = "\n  invalid value %r for argument --ipu; must be CIDR=UNAME (192.168.0.0/16=amelia)"
            raise Exception(t % (ipu,))
        uname2 = cidr_u.get(cidr)
        if uname2 is not None:
            t = "\n  invalid value %r for argument --ipu; cidr %s already mapped to %r"
            raise Exception(t % (ipu, cidr, uname2))
        cidr_u[cidr] = uname
        ip_u[cip] = uname
    try:
        nm = NetMap(["::"], list(cidr_u.keys()), True, True, defer_mutex)
    except Exception as ex:
        t = "failed to translate --ipu into netmap, probably due to invalid config: %r"
        log("root", t % (ex,), 1)
        raise
    return ip_u, nm


def load_ipr(
    log: "RootLogger", iprs: list[str], defer_mutex: bool = False
) -> dict[str, NetMap]:
    ret = {}
    for ipr in iprs:
        try:
            zs, uname = ipr.split("=")
            cidrs = zs.split(",")
        except (KeyError, IndexError):
            t = "\n  invalid value %r for argument --ipr; must be CIDR[,CIDR[,...]]=UNAME (192.168.0.0/16=amelia)"
            raise Exception(t % (ipr,))
        try:
            nm = NetMap(["::"], cidrs, True, True, defer_mutex)
        except Exception as ex:
            t = "failed to translate --ipr into netmap, probably due to invalid config: %r"
            log("root", t % (ex,), 1)
            raise
        ret[uname] = nm
    return ret


def yieldfile(fn: str, bufsz: int) -> Generator[bytes, None, None]:
    readsz = min(bufsz, 128 * 1024)
    with open(fsenc(fn), "rb", bufsz) as f:
        while True:
            buf = f.read(readsz)
            if not buf:
                break

            yield buf


def justcopy(
    fin: Generator[bytes, None, None],
    fout: Union[typing.BinaryIO, typing.IO[Any]],
    hashobj: Optional["hashlib._Hash"],
    max_sz: int,
    slp: float,
) -> tuple[int, str, str]:
    tlen = 0
    for buf in fin:
        tlen += len(buf)
        if max_sz and tlen > max_sz:
            continue

        fout.write(buf)
        if slp:
            time.sleep(slp)

    return tlen, "checksum-disabled", "checksum-disabled"


def hashcopy(
    fin: Generator[bytes, None, None],
    fout: Union[typing.BinaryIO, typing.IO[Any]],
    hashobj: Optional["hashlib._Hash"],
    max_sz: int,
    slp: float,
) -> tuple[int, str, str]:
    if not hashobj:
        hashobj = hashlib.sha512()
    tlen = 0
    for buf in fin:
        tlen += len(buf)
        if max_sz and tlen > max_sz:
            continue

        hashobj.update(buf)
        fout.write(buf)
        if slp:
            time.sleep(slp)

    digest_b64 = ub64enc(hashobj.digest()[:33]).decode("ascii")

    return tlen, hashobj.hexdigest(), digest_b64


def sendfile_py(
    log: "NamedLogger",
    lower: int,
    upper: int,
    f: typing.BinaryIO,
    s: socket.socket,
    bufsz: int,
    slp: float,
    use_poll: bool,
    dls: dict[str, tuple[float, int]],
    dl_id: str,
) -> int:
    sent = 0
    remains = upper - lower
    f.seek(lower)
    while remains > 0:
        if slp:
            time.sleep(slp)

        buf = f.read(min(bufsz, remains))
        if not buf:
            return remains

        try:
            s.sendall(buf)
            remains -= len(buf)
        except OSError:
            return remains

        if dl_id:
            sent += len(buf)
            dls[dl_id] = (time.time(), sent)

    return 0


def sendfile_kern(
    log: "NamedLogger",
    lower: int,
    upper: int,
    f: typing.BinaryIO,
    s: socket.socket,
    bufsz: int,
    slp: float,
    use_poll: bool,
    dls: dict[str, tuple[float, int]],
    dl_id: str,
) -> int:
    out_fd = s.fileno()
    in_fd = f.fileno()
    ofs = lower
    stuck = 0.0
    if use_poll:
        poll = select.poll()
        poll.register(out_fd, select.POLLOUT)

    while ofs < upper:
        stuck = stuck or time.time()
        try:
            req = min(0x2000000, upper - ofs)  # 32 MiB
            if use_poll:
                poll.poll(10000)  # type: ignore
            else:
                select.select([], [out_fd], [], 10)
            n = os.sendfile(out_fd, in_fd, ofs, req)
            stuck = 0
        except OSError as ex:
            # client stopped reading; do another select
            d = time.time() - stuck
            if d < 3600 and ex.errno == errno.EWOULDBLOCK:
                time.sleep(0.02)
                continue

            n = 0
        except Exception as ex:
            n = 0
            d = time.time() - stuck
            log("sendfile failed after {:.3f} sec: {!r}".format(d, ex))

        if n <= 0:
            return upper - ofs

        ofs += n
        if dl_id:
            dls[dl_id] = (time.time(), ofs - lower)

        # print("sendfile: ok, sent {} now, {} total, {} remains".format(n, ofs - lower, upper - ofs))

    return 0
