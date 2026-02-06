# coding: utf-8
from __future__ import print_function, unicode_literals

import argparse  # typechk
import copy
import errno
import hashlib
import itertools
import json
import os
import random
import re
import socket
import stat
import sys
import threading  # typechk
import time
import uuid
from datetime import datetime
from operator import itemgetter

import jinja2  # typechk
from ipaddress import IPv6Network

try:
    if os.environ.get("PRTY_NO_LZMA"):
        raise Exception()

    import lzma
except ImportError:
    pass

from .__init__ import ANYWIN, RES, RESM, TYPE_CHECKING, EnvParams, unicode
from .httpcli_dav import HttpCliDav
from .httpcli_tx import ACODE2_FMT, HttpCliTx
from .httpcli_up import HttpCliUpload
from .httpcli_ls import HttpCliListing
from .httpcli_ctl import HttpCliControl
from .__version__ import S_VERSION
from .api import dispatch_api
from .authsrv import LEELOO_DALLAS, VFS  # typechk
from .bos import bos
from .qrkode import QrCode, qr2svg, qrgen
from .star import StreamTar
from .sutil import StreamArc, gfilter
from .szip import StreamZip
from .up2k import up2k_chunksize
from .util import unquote  # type: ignore
from .util import (
    APPLESAN_RE,
    BITNESS,
    DAV_ALLPROPS,
    E_SCK_WR,
    HAVE_SQLITE3,
    HTTPCODE,
    UTC,
    VPTL_MAC,
    VPTL_OS,
    VPTL_WIN,
    Garda,
    MultipartParser,
    ODict,
    Pebkac,
    UnrecvEOF,
    WrongPostKey,
    absreal,
    afsenc,
    alltrace,
    atomic_move,
    b64dec,
    eol_conv,
    exclude_dotfiles,
    formatdate,
    fsenc,
    gen_content_disposition,
    gen_filekey,
    gen_filekey_dbg,
    gencookie,
    get_df,
    get_spd,
    guess_mime,
    gzip,
    gzip_file_orig_sz,
    gzip_orig_sz,
    has_resource,
    hashcopy,
    hidedir,
    html_bescape,
    html_escape,
    html_sh_esc,
    humansize,
    ipnorm,
    json_hesc,
    justcopy,
    load_resource,
    loadpy,
    log_reloc,
    min_ex,
    pathmod,
    quotep,
    rand_name,
    read_header,
    read_socket,
    read_socket_chunked,
    read_socket_unbounded,
    read_utf8,
    relchk,
    ren_open,
    runhook,
    s2hms,
    s3enc,
    sanitize_fn,
    sanitize_vpath,
    sendfile_kern,
    sendfile_py,
    set_fperms,
    stat_resource,
    str_anchor,
    ub64dec,
    ub64enc,
    ujoin,
    undot,
    unescape_cookie,
    unquotep,
    vjoin,
    vol_san,
    vroots,
    vsplit,
    wunlink,
    yieldfile,
)

if True:  # pylint: disable=using-constant-test
    import typing
    from typing import (
        Any,
        Generator,
        Iterable,
        Match,
        Optional,
        Pattern,
        Sequence,
        Type,
        Union,
    )

if TYPE_CHECKING:
    from .httpconn import HttpConn

if not hasattr(socket, "AF_UNIX"):
    setattr(socket, "AF_UNIX", -9001)

_ = (argparse, threading)

USED4SEC = {"usedforsecurity": False} if sys.version_info > (3, 9) else {}

ALL_COOKIES = "k304 no304 js idxh dots cppwd cppws".split()

BADXFF = " due to dangerous misconfiguration (the http-header specified by --xff-hdr was received from an untrusted reverse-proxy)"
BADXFF2 = ". Some copyparty features are now disabled as a safety measure.\n\n\n"
BADXFP = ', or change the copyparty global-option "xf-proto" to another header-name to read this value from. Alternatively, if your reverseproxy is not able to provide a header similar to "X-Forwarded-Proto", then you must tell copyparty which protocol to assume; either "--xf-proto-fb=http" or "--xf-proto-fb=https"'
BADXFFB = "<b>NOTE: serverlog has a message regarding your reverse-proxy config</b>"

H_CONN_KEEPALIVE = "Connection: Keep-Alive"
H_CONN_CLOSE = "Connection: Close"

ACODE2_FMT = set(["opus", "owa", "caf", "mp3", "flac", "wav"])

RE_CC = re.compile(r"[\x00-\x1f]")  # search always faster
RE_USAFE = re.compile(r'[\x00-\x1f<>"]')  # search always faster
RE_HSAFE = re.compile(r"[\x00-\x1f<>\"'&]")  # search always much faster
RE_HOST = re.compile(r"[^][0-9a-zA-Z.:_-]")  # search faster <=17ch
RE_MHOST = re.compile(r"^[][0-9a-zA-Z.:_-]+$")  # match faster >=18ch
RE_K = re.compile(r"[^0-9a-zA-Z_-]")  # search faster <=17ch
RE_HTTP1 = re.compile(r"(GET|HEAD|POST|PUT) [^ ]+ HTTP/1.1$")
RE_RSS_KW = re.compile(r"(\{[^} ]+\})")

UPARAM_CC_OK = set("doc move tree".split())



def _arg2cfg(txt: str) -> str:
    return re.sub(r' "--([^=]{3,12})=', r' global-option "\1: ', txt)


class HttpCli(HttpCliDav, HttpCliTx, HttpCliUpload, HttpCliListing, HttpCliControl):
    """
    Spawned by HttpConn to process one http transaction
    """

    def __init__(self, conn: "HttpConn") -> None:
        assert conn.sr  # !rm

        empty_stringlist: list[str] = []

        self.t0 = time.time()
        self.conn = conn
        self.u2mutex = conn.u2mutex  # mypy404
        self.s = conn.s
        self.sr = conn.sr
        self.ip = conn.addr[0]
        self.addr: tuple[str, int] = conn.addr
        self.args = conn.args  # mypy404
        self.E: EnvParams = self.args.E
        self.asrv = conn.asrv  # mypy404
        self.ico = conn.ico  # mypy404
        self.thumbcli = conn.thumbcli  # mypy404
        self.u2fh = conn.u2fh  # mypy404
        self.pipes = conn.pipes  # mypy404
        self.log_func = conn.log_func  # mypy404
        self.log_src = conn.log_src  # mypy404
        self.gen_fk = self._gen_fk if self.args.log_fk else gen_filekey
        self.tls = self.is_https = hasattr(self.s, "cipher")
        self.is_vproxied = bool(self.args.R)

        # placeholders; assigned by run()
        self.keepalive = False
        self.in_hdr_recv = True
        self.headers: dict[str, str] = {}
        self.mode = " "  # http verb
        self.req = " "
        self.http_ver = ""
        self.hint = ""
        self.host = " "
        self.ua = " "
        self.is_rclone = False
        self.ouparam: dict[str, str] = {}
        self.uparam: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.avn: Optional[VFS] = None
        self.vn = self.asrv.vfs
        self.rem = " "
        self.vpath = " "
        self.vpaths = " "
        self.dl_id = ""
        self.gctx = " "  # additional context for garda
        self.trailing_slash = True
        self.uname = "*"
        self.pw = ""
        self.rvol = self.wvol = self.avol = empty_stringlist
        self.do_log = True
        self.can_read = False
        self.can_write = False
        self.can_move = False
        self.can_delete = False
        self.can_get = False
        self.can_upget = False
        self.can_html = False
        self.can_admin = False
        self.can_dot = False
        self.out_headerlist: list[tuple[str, str]] = []
        self.out_headers: dict[str, str] = {}
        # post
        self.parser: Optional[MultipartParser] = None
        # end placeholders

        self.html_head = ""

    def log(self, msg: str, c: Union[int, str] = 0) -> None:
        ptn = self.asrv.re_pwd
        if ptn and ptn.search(msg):
            if self.asrv.ah.on:
                msg = ptn.sub("\033[7m pw \033[27m", msg)
            else:
                msg = ptn.sub(self.unpwd, msg)

        self.log_func(self.log_src, msg, c)

    def unpwd(self, m: Match[str]) -> str:
        a, b, c = m.groups()
        uname = self.asrv.iacct.get(b) or self.asrv.sesa.get(b)
        return "%s\033[7m %s \033[27m%s" % (a, uname, c)

    def _assert_safe_rem(self, rem: str) -> None:
        # sanity check to prevent any disasters
        # (this function hopefully serves no purpose; validation has already happened at this point, this only exists as a last-ditch effort just in case)
        if rem.startswith(("/", "../")) or "/../" in rem:
            raise Exception("that was close")

    def _gen_fk(self, alg: int, salt: str, fspath: str, fsize: int, inode: int) -> str:
        return gen_filekey_dbg(
            alg, salt, fspath, fsize, inode, self.log, self.args.log_fk
        )

    def j2s(self, name: str, **ka: Any) -> str:
        tpl = self.conn.hsrv.j2[name]
        ka["r"] = self.args.SR if self.is_vproxied else ""
        ka["ts"] = self.conn.hsrv.cachebuster()
        ka["lang"] = self.cookies.get("cplng") or self.args.lang
        ka["favico"] = self.args.favico
        ka["s_doctitle"] = self.args.doctitle
        ka["tcolor"] = self.vn.flags["tcolor"]

        if self.args.js_other and "js" not in ka:
            zs = self.args.js_other
            zs += "&" if "?" in zs else "?"
            ka["js"] = zs

        if "html_head_d" in self.vn.flags:
            ka["this"] = self
            self._build_html_head(ka)

        ka["html_head"] = self.html_head
        return tpl.render(**ka)  # type: ignore

    def j2j(self, name: str) -> jinja2.Template:
        return self.conn.hsrv.j2[name]

    def run(self) -> bool:
        """returns true if connection can be reused"""
        self.out_headers = {
            "Vary": self.args.http_vary,
            "Cache-Control": "no-store, max-age=0",
        }

        if self.args.early_ban and self.is_banned():
            return False

        if self.conn.ipa_nm and not self.conn.ipa_nm.map(self.conn.addr[0]):
            self.log("client rejected (--ipa)", 3)
            self.terse_reply(b"", 500)
            return False

        try:
            self.s.settimeout(2)
            headerlines = read_header(self.sr, self.args.s_thead, self.args.s_thead)
            self.in_hdr_recv = False
            if not headerlines:
                return False

            try:
                self.mode, self.req, self.http_ver = headerlines[0].split(" ")

                # normalize incoming headers to lowercase;
                # outgoing headers however are Correct-Case
                for header_line in headerlines[1:]:
                    k, zs = header_line.split(":", 1)
                    self.headers[k.lower()] = zs.strip()
                    if zs.endswith(" HTTP/1.1") and RE_HTTP1.search(zs):
                        raise Exception()
            except (KeyError, IndexError):
                headerlines = [repr(x) for x in headerlines]
                msg = "#[ " + " ]\n#[ ".join(headerlines) + " ]"
                raise Pebkac(400, "bad headers", log=msg)

        except Pebkac as ex:
            self.mode = "GET"
            self.req = "[junk]"
            self.http_ver = "HTTP/1.1"
            # self.log("pebkac at httpcli.run #1: " + repr(ex))
            self.keepalive = False
            h = {"WWW-Authenticate": 'Basic realm="a"'} if ex.code == 401 else {}
            try:
                self.loud_reply(unicode(ex), status=ex.code, headers=h, volsan=True)
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                pass

            if ex.log:
                self.log("additional error context:\n" + ex.log, 6)

            return False

        self.sr.nb = 0
        self.conn.hsrv.nreq += 1

        self.ua = self.headers.get("user-agent", "")
        self.is_rclone = self.ua.startswith("rclone/")

        zs = self.headers.get("connection", "").lower()
        self.keepalive = "close" not in zs and (
            self.http_ver != "HTTP/1.0" or zs == "keep-alive"
        )

        if (
            "transfer-encoding" in self.headers
            and self.headers["transfer-encoding"].lower() != "identity"
        ):
            self.sr.te = 1
            if "content-length" in self.headers:
                # rfc9112:6.2: ignore CL if TE
                self.keepalive = False
                self.headers.pop("content-length")
                t = "suspicious request (has both TE and CL); ignoring CL and disabling keepalive"
                self.log(t, 3)

        self.host = self.headers.get("host") or ""
        if not self.host:
            if self.s.family == socket.AF_UNIX:
                self.host = self.args.name
            else:
                zs = "%s:%s" % self.s.getsockname()[:2]
                self.host = zs[7:] if zs.startswith("::ffff:") else zs

        trusted_xff = False
        n = self.args.rproxy
        if n:
            zso = self.headers.get(self.args.xff_hdr)
            if zso:
                if n > 0:
                    n -= 1

                zsl = zso.split(",")
                try:
                    cli_ip = zsl[n].strip()
                except (KeyError, IndexError):
                    cli_ip = self.ip
                    self.bad_xff = True
                    if self.args.rproxy != 9999999:
                        t = "global-option --rproxy %d could not be used (out-of-bounds) for the received header [%s]"
                        self.log(t % (self.args.rproxy, zso) + BADXFF2, c=3)
                    else:
                        zsl = [
                            "  rproxy: %d   if this client's IP-address is [%s]"
                            % (-1 - zd, zs.strip())
                            for zd, zs in enumerate(zsl[::-1])
                        ]
                        t = 'could not determine the client\'s IP-address because the global-option --rproxy has not been configured, so the request-header [%s] specified by global-option --xff-hdr cannot be used safely! The raw header value was [%s]. Please see the "reverse-proxy" section in the readme. The best approach is to configure your reverse-proxy to give copyparty the exact IP-address to assume (perhaps in another header), but you may also try the following:'
                        t = t % (self.args.xff_hdr, zso)
                        t = "%s\n\n%s\n" % (t, "\n".join(zsl))

                        zs = self.headers.get(self.args.xf_proto)
                        t2 = "\nFurthermore, the following request-headers are also relevant, and you should check that the values below are sensible:\n\n  request-header [%s] (configured with global-option --xf-proto) has the value [%s]; this should be the protocol that the webbrowser is using, so either 'http' or 'https'"
                        t += t2 % (self.args.xf_proto, zs or "NOT-PROVIDED")
                        if not zs:
                            t += ". Because the header is not provided by the reverse-proxy, you must either fix the reverseproxy config"
                            t += BADXFP
                        zs = self.headers.get(self.args.xf_host)
                        t2 = "\n\n  request-header [%s] (configured with global-option --xf-host) has the value [%s]; this should be the website domain or external IP-address which the webbrowser is accessing"
                        t += t2 % (self.args.xf_host, zs or "NOT-PROVIDED")
                        if not zs:
                            zs = self.headers.get("host")
                            t2 = ". Because the header is not provided by the reverse-proxy, copyparty is using the standard [Host] header which has the value [%s]"
                            t += t2 % (zs or "NOT-PROVIDED")
                            if zs:
                                t += ". If that is the address that visitors are supposed to use to access your server -- or, in other words, it is not some internal address you wish to keep secret -- then the current choice of using the [Host] header is fine (usually the case)"
                        if self.args.c:
                            t = _arg2cfg(t)
                        self.log(t + "\n\n\n", 3)

                pip = self.conn.addr[0]
                xffs = self.conn.xff_nm
                if xffs and not xffs.map(pip):
                    t = 'got header "%s" from untrusted source "%s" claiming the true client ip is "%s" (raw value: "%s");  if you trust this, you must allowlist this proxy with "--xff-src=%s"%s'
                    if self.headers.get("cf-connecting-ip"):
                        t += '  Note: if you are behind cloudflare, then this default header is not a good choice; please first make sure your local reverse-proxy (if any) does not allow non-cloudflare IPs from providing cf-* headers, and then add this additional global setting: "--xff-hdr=cf-connecting-ip"'
                    else:
                        t += '  Note: depending on your reverse-proxy, and/or WAF, and/or other intermediates, you may want to read the true client IP from another header by also specifying "--xff-hdr=SomeOtherHeader"'
                    t += BADXFF2

                    if "." in pip:
                        zs = ".".join(pip.split(".")[:2]) + ".0.0/16"
                    else:
                        zs = IPv6Network(pip + "/64", False).compressed

                    zs2 = ' or "--xff-src=lan"' if self.conn.xff_lan.map(pip) else ""
                    t = t % (self.args.xff_hdr, pip, cli_ip, zso, zs, zs2)
                    if self.args.c:
                        t = _arg2cfg(t)
                    self.log(t, 3)
                    self.bad_xff = True
                else:
                    self.ip = cli_ip
                    self.log_src = self.conn.set_rproxy(self.ip)
                    self.host = self.headers.get(self.args.xf_host, self.host)
                    try:
                        self.is_https = len(self.headers[self.args.xf_proto]) == 5
                    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                        if self.args.xf_proto_fb:
                            self.is_https = len(self.args.xf_proto_fb) == 5
                        else:
                            self.bad_xff = True
                            self.host = "example.com"
                            t = 'got proxied request without header "%s" (global-option "xf-proto"). This header must contain either "http" or "https". Either fix your reverse-proxy config to include this header%s%s'
                            t = t % (self.args.xf_proto, BADXFP, BADXFF2)
                            if self.args.c:
                                t = _arg2cfg(t)
                            self.log(t, 3)

                    # the semantics of trusted_xff and bad_xff are different;
                    # trusted_xff is whether the connection came from a trusted reverseproxy,
                    # regardless of whether the client ip detection is correctly configured
                    # (the primary safeguard for idp is --idp-h-key)
                    trusted_xff = True

        m = RE_HOST.search(self.host)
        if m and self.host != self.args.name:
            zs = self.host
            t = "malicious user; illegal Host header; req(%r) host(%r) => %r"
            self.log(t % (self.req, zs, zs[m.span()[0] :]), 1)
            self.cbonk(self.conn.hsrv.gmal, zs, "bad_host", "illegal Host header")
            self.terse_reply(b"illegal Host header", 400)
            return False

        if self.is_banned():
            return False

        if self.conn.ipar_nm and not self.conn.ipar_nm.map(self.ip):
            self.log("client rejected (--ipar)", 3)
            self.terse_reply(b"", 500)
            return False

        if self.conn.aclose:
            nka = self.conn.aclose
            ip = ipnorm(self.ip)
            if ip in nka:
                rt = nka[ip] - time.time()
                if rt < 0:
                    self.log("client uncapped", 3)
                    del nka[ip]
                else:
                    self.keepalive = False

        ptn: Optional[Pattern[str]] = self.conn.lf_url  # mypy404
        self.do_log = not ptn or not ptn.search(self.req)

        if self.args.ihead and self.do_log:
            keys = self.args.ihead
            if "*" in keys:
                keys = list(sorted(self.headers.keys()))

            for k in keys:
                zso = self.headers.get(k)
                if zso is not None:
                    self.log("[H] {}: \033[33m[{}]".format(k, zso), 6)

        if "&" in self.req and "?" not in self.req:
            self.hint = "did you mean '?' instead of '&'"

        if self.args.uqe and "/.uqe/" in self.req:
            try:
                vpath, query = self.req.split("?")[0].split("/.uqe/")
                query = query.split("/")[0]  # discard trailing junk
                # (usually a "filename" to trick discord into behaving)
                query = ub64dec(query.encode("utf-8")).decode("utf-8", "replace")
                if query.startswith("/"):
                    self.req = "%s/?%s" % (vpath, query[1:])
                else:
                    self.req = "%s?%s" % (vpath, query)
            except Exception as ex:
                t = "bad uqe in request [%s]: %r" % (self.req, ex)
                self.loud_reply(t, status=400)
                return False

        m = RE_USAFE.search(self.req)
        if m:
            zs = self.req
            t = "malicious user; Cc in req0 %r => %r"
            self.log(t % (zs, zs[m.span()[0] :]), 1)
            self.cbonk(self.conn.hsrv.gmal, zs, "cc_r0", "Cc in req0")
            self.terse_reply(b"", 500)
            return False

        # split req into vpath + uparam
        uparam = {}
        if "?" not in self.req:
            vpath = unquotep(self.req)  # not query, so + means +
            self.trailing_slash = vpath.endswith("/")
            vpath = undot(vpath)
        else:
            vpath, arglist = self.req.split("?", 1)
            vpath = unquotep(vpath)
            self.trailing_slash = vpath.endswith("/")
            vpath = undot(vpath)

            re_k = RE_K
            ptn_cc = RE_CC
            k_safe = UPARAM_CC_OK
            for k in arglist.split("&"):
                sv = ""
                if "=" in k:
                    k, zs = k.split("=", 1)
                    # x-www-form-urlencoded (url query part) uses
                    # either + or %20 for 0x20 so handle both
                    sv = unquotep(zs.strip().replace("+", " "))

                m = re_k.search(k)
                if m:
                    t = "malicious user; bad char in query key; req(%r) qk(%r) => %r"
                    self.log(t % (self.req, k, k[m.span()[0] :]), 1)
                    self.cbonk(self.conn.hsrv.gmal, self.req, "bc_q", "illegal qkey")
                    self.terse_reply(b"", 500)
                    return False

                k = k.lower()
                uparam[k] = sv

                if k in k_safe:
                    continue

                zs = "%s=%s" % (k, sv)
                m = ptn_cc.search(zs)
                if not m:
                    continue

                t = "malicious user; Cc in query; req(%r) qp(%r) => %r"
                self.log(t % (self.req, zs, zs[m.span()[0] :]), 1)
                self.cbonk(self.conn.hsrv.gmal, self.req, "cc_q", "Cc in query")
                self.terse_reply(b"", 500)
                return False

            if "k" in uparam:
                m = re_k.search(uparam["k"])
                if m:
                    zs = uparam["k"]
                    t = "malicious user; illegal filekey; req(%r) k(%r) => %r"
                    self.log(t % (self.req, zs, zs[m.span()[0] :]), 1)
                    self.cbonk(self.conn.hsrv.gmal, zs, "bad_k", "illegal filekey")
                    self.terse_reply(b"illegal filekey", 400)
                    return False

        if self.is_vproxied:
            if vpath.startswith(self.args.R):
                vpath = vpath[len(self.args.R) + 1 :]
            else:
                t = "incorrect --rp-loc or webserver config; expected vpath starting with %r but got %r"
                self.log(t % (self.args.R, vpath), 1)
                self.is_vproxied = False

        self.ouparam = uparam.copy()

        if self.args.rsp_slp:
            time.sleep(self.args.rsp_slp)
            if self.args.rsp_jtr:
                time.sleep(random.random() * self.args.rsp_jtr)

        zso = self.headers.get("cookie")
        if zso:
            if len(zso) > self.args.cookie_cmax:
                self.loud_reply("cookie header too big", status=400)
                return False
            zsll = [x.split("=", 1) for x in zso.split(";") if "=" in x]
            cookies = {k.strip(): unescape_cookie(zs) for k, zs in zsll}
            cookie_pw = cookies.get("cppws" if self.is_https else "cppwd") or ""
            if "b" in cookies and "b" not in uparam:
                uparam["b"] = cookies["b"]
            if len(cookies) > self.args.cookie_nmax:
                self.loud_reply("too many cookies", status=400)
        else:
            cookies = {}
            cookie_pw = ""

        if len(uparam) > 12:
            t = "http-request rejected; num.params: %d %r"
            self.log(t % (len(uparam), self.req), 3)
            self.loud_reply("u wot m8", status=400)
            return False

        if VPTL_OS:
            vpath = vpath.translate(VPTL_OS)

        self.uparam = uparam
        self.cookies = cookies
        self.vpath = vpath
        self.vpaths = vpath + "/" if self.trailing_slash and vpath else vpath

        if "qr" in uparam:
            return self.tx_qr()

        if "\x00" in vpath or (ANYWIN and ("\n" in vpath or "\r" in vpath)):
            self.log("illegal relpath; req(%r) => %r" % (self.req, "/" + self.vpath))
            self.cbonk(self.conn.hsrv.gmal, self.req, "bad_vp", "invalid relpaths")
            return self.tx_404() and False

        from .authctx import resolve_credentials, resolve_ip_user, resolve_permissions

        self.pw, self.uname = resolve_credentials(
            self.headers, uparam, cookie_pw, self.args, self.asrv
        )

        if self.args.have_idp_hdrs and (
            self.uname == "*" or self.args.ao_idp_before_pw
        ):
            idp_usr = ""
            if self.args.idp_hm_usr:
                for hn, hmv in self.args.idp_hm_usr_p.items():
                    zs = self.headers.get(hn)
                    if zs:
                        for zs1, zs2 in hmv.items():
                            if zs == zs1:
                                idp_usr = zs2
                                break
                    if idp_usr:
                        break
            for hn in self.args.idp_h_usr:
                if idp_usr and not self.args.ao_h_before_hm:
                    break
                idp_usr = self.headers.get(hn) or idp_usr
            if idp_usr:
                idp_grp = (
                    self.headers.get(self.args.idp_h_grp) or ""
                    if self.args.idp_h_grp
                    else ""
                )
                if self.args.idp_chsub:
                    idp_usr = idp_usr.translate(self.args.idp_chsub_tr)
                    idp_grp = idp_grp.translate(self.args.idp_chsub_tr)

                if not trusted_xff:
                    pip = self.conn.addr[0]
                    xffs = self.conn.xff_nm
                    trusted_xff = xffs and xffs.map(pip)

                trusted_key = (
                    not self.args.idp_h_key
                ) or self.args.idp_h_key in self.headers

                if trusted_key and trusted_xff:
                    if idp_usr.lower() == LEELOO_DALLAS:
                        self.loud_reply("send her back", status=403)
                        return False
                    self.asrv.idp_checkin(self.conn.hsrv.broker, idp_usr, idp_grp)
                else:
                    if not trusted_key:
                        t = 'the idp-h-key header ("%s") is not present in the request; will NOT trust the other headers saying that the client\'s username is "%s" and group is "%s"'
                        self.log(t % (self.args.idp_h_key, idp_usr, idp_grp), 3)

                    if not trusted_xff:
                        t = 'got IdP headers from untrusted source "%s" claiming the client\'s username is "%s" and group is "%s";  if you trust this, you must allowlist this proxy with "--xff-src=%s"%s'
                        if not self.args.idp_h_key:
                            t += "  Note: you probably also want to specify --idp-h-key <SECRET-HEADER-NAME> for additional security"

                        pip = self.conn.addr[0]
                        zs = (
                            ".".join(pip.split(".")[:2]) + "."
                            if "." in pip
                            else ":".join(pip.split(":")[:4]) + ":"
                        ) + "0.0/16"
                        zs2 = (
                            ' or "--xff-src=lan"' if self.conn.xff_lan.map(pip) else ""
                        )
                        self.log(t % (pip, idp_usr, idp_grp, zs, zs2), 3)

                    idp_usr = "*"
                    idp_grp = ""

                if idp_usr in self.asrv.vfs.aread:
                    self.pw = ""
                    self.uname = idp_usr
                    if self.args.ao_have_pw or self.args.idp_logout:
                        self.html_head += "<script>var is_idp=1</script>\n"
                    else:
                        self.html_head += "<script>var is_idp=2</script>\n"
                    zs = self.asrv.ases.get(idp_usr)
                    if zs:
                        self.set_idp_cookie(zs)
                else:
                    self.log("unknown username: %r" % (idp_usr,), 1)

        self.uname = resolve_ip_user(self.uname, self.ip, self.args, self.conn, self.log)

        self.rvol = self.asrv.vfs.aread[self.uname]
        self.wvol = self.asrv.vfs.awrite[self.uname]
        self.avol = self.asrv.vfs.aadmin[self.uname]

        if self.pw and (
            self.pw != cookie_pw or self.conn.freshen_pwd + 30 < time.time()
        ):
            self.conn.freshen_pwd = time.time()
            self.get_pwd_cookie(self.pw)

        if self.is_rclone:
            # dots: always include dotfiles if permitted
            # lt: probably more important showing the correct timestamps of any dupes it just uploaded rather than the lastmod time of any non-copyparty-managed symlinks
            # b: basic-browser if it tries to parse the html listing
            uparam["dots"] = ""
            uparam["lt"] = ""
            uparam["b"] = ""
            cookies["b"] = ""

        self.vn, self.avn, self.rem, perms = resolve_permissions(
            self.uname, self.vpath, self.asrv
        )
        (
            self.can_read,
            self.can_write,
            self.can_move,
            self.can_delete,
            self.can_get,
            self.can_upget,
            self.can_html,
            self.can_admin,
            self.can_dot,
        ) = perms

        if "bcasechk" in self.vn.flags and not self.vn.casechk(self.rem, True):
            return self.tx_404() and False

        self.s.settimeout(self.args.s_tbody or None)

        if "norobots" in self.vn.flags:
            self.out_headers["X-Robots-Tag"] = "noindex, nofollow"

        if "html_head_s" in self.vn.flags:
            self.html_head += self.vn.flags["html_head_s"]

        if self.vpath.startswith(".cpr/api/"):
            return dispatch_api(self) and self.keepalive

        try:
            cors_k = self._cors()
            if self.mode in ("GET", "HEAD"):
                return self.handle_get() and self.keepalive
            if self.mode == "OPTIONS":
                return self.handle_options() and self.keepalive

            if not cors_k:
                host = self.headers.get("host", "<?>")
                origin = self.headers.get("origin", "<?>")
                proto = "https://" if self.is_https else "http://"
                guess = "modifying" if (origin and host) else "stripping"
                t = "cors-reject %s because request-header Origin=%r does not match request-protocol %r and host %r based on request-header Host=%r (note: if this request is not malicious, check if your reverse-proxy is accidentally %s request headers, in particular 'Origin', for example by running copyparty with --ihead='*' to show all request headers)"
                self.log(t % (self.mode, origin, proto, self.host, host, guess), 3)
                raise Pebkac(403, "rejected by cors-check (see fileserver log)")

            # getattr(self.mode) is not yet faster than this
            if self.mode == "POST":
                return self.handle_post() and self.keepalive
            elif self.mode == "PUT":
                return self.handle_put() and self.keepalive
            elif self.mode == "PROPFIND":
                return self.handle_propfind() and self.keepalive
            elif self.mode == "DELETE":
                return self.handle_delete() and self.keepalive
            elif self.mode == "PROPPATCH":
                return self.handle_proppatch() and self.keepalive
            elif self.mode == "LOCK":
                return self.handle_lock() and self.keepalive
            elif self.mode == "UNLOCK":
                return self.handle_unlock() and self.keepalive
            elif self.mode == "MKCOL":
                return self.handle_mkcol() and self.keepalive
            elif self.mode in ("MOVE", "COPY"):
                return self.handle_cpmv() and self.keepalive
            else:
                raise Pebkac(400, "invalid HTTP verb %r" % (self.mode,))

        except Exception as ex:
            if not isinstance(ex, Pebkac):
                pex = Pebkac(500)
            else:
                pex: Pebkac = ex  # type: ignore

            try:
                if pex.code == 999:
                    self.terse_reply(b"", 500)
                    return False

                post = (
                    self.mode in ("POST", "PUT")
                    or "content-length" in self.headers
                    or self.sr.te
                )
                if pex.code >= (300 if post else 400):
                    self.keepalive = False

                em = str(ex)
                msg = em if pex is ex else min_ex()

                if pex.code != 404 or self.do_log:
                    self.log(
                        "http%d: %s\033[0m, %r" % (pex.code, msg, "/" + self.vpath),
                        6 if em.startswith("client d/c ") else 3,
                    )

                if self.hint and self.hint.startswith("<xml> "):
                    if self.args.log_badxml:
                        t = "invalid XML received from client: %r"
                        self.log(t % (self.hint[6:],), 6)
                    else:
                        t = "received invalid XML from client; enable --log-badxml to see the whole XML in the log"
                        self.log(t, 6)
                    self.hint = ""

                msg = "%s\r\nURL: %s\r\n" % (em, self.vpath)
                if self.hint:
                    msg += "hint: %s\r\n" % (self.hint,)

                if "database is locked" in em:
                    self.conn.hsrv.broker.say("log_stacks")
                    msg += "hint: important info in the server log\r\n"

                zb = b"<pre>" + html_escape(msg).encode("utf-8", "replace")
                h = {"WWW-Authenticate": 'Basic realm="a"'} if pex.code == 401 else {}
                self.reply(zb, status=pex.code, headers=h, volsan=True)
                if pex.log:
                    self.log("additional error context:\n" + pex.log, 6)

                return self.keepalive
            except Pebkac:
                return False

        finally:
            if self.dl_id:
                self.conn.hsrv.dli.pop(self.dl_id, None)
                self.conn.hsrv.dls.pop(self.dl_id, None)

    def dip(self) -> str:
        if self.args.plain_ip:
            return self.ip.replace(":", ".")
        else:
            return self.conn.iphash.s(self.ip)

    def cbonk(self, g: Garda, v: str, reason: str, descr: str) -> bool:
        cond = self.args.dont_ban
        if (
            cond == "any"
            or (cond == "auth" and self.uname != "*")
            or (cond == "aa" and self.avol)
            or (cond == "av" and self.can_admin)
            or (cond == "rw" and self.can_read and self.can_write)
        ):
            return False

        self.conn.hsrv.nsus += 1
        if not g.lim:
            return False

        bonk, ip = g.bonk(self.ip, v + self.gctx)
        if not bonk:
            return False

        xban = self.vn.flags.get("xban")
        if xban:
            hr = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xban",
                xban,
                self.vn.canonical(self.rem),
                self.vpath,
                self.host,
                self.uname,
                "",
                time.time(),
                0,
                self.ip,
                time.time(),
                [reason, reason],
            )
            if hr.get("rv") == 0:
                return False

        self.log("client banned: %s" % (descr,), 1)
        self.conn.hsrv.bans[ip] = bonk
        self.conn.hsrv.nban += 1
        return True

    def is_banned(self) -> bool:
        if not self.conn.bans:
            return False

        bans = self.conn.bans
        ip = ipnorm(self.ip)
        if ip not in bans:
            return False

        rt = bans[ip] - time.time()
        if rt < 0:
            del bans[ip]
            self.log("client unbanned", 3)
            return False

        self.log("banned for {:.0f} sec".format(rt), 6)
        self.terse_reply(self.args.banmsg_b, 403)
        return True

    def permit_caching(self) -> None:
        cache = self.uparam.get("cache")
        if cache is None:
            self.out_headers["Cache-Control"] = self.vn.flags["cachectl"]
            return

        n = 69 if not cache else 604869 if cache == "i" else int(cache)
        self.out_headers["Cache-Control"] = "max-age=" + str(n)

    def k304(self) -> bool:
        k304 = self.cookies.get("k304")
        return k304 == "y" or (self.args.k304 == 2 and k304 != "n")

    def no304(self) -> bool:
        no304 = self.cookies.get("no304")
        return no304 == "y" or (self.args.no304 == 2 and no304 != "n")

    def _build_html_head(self, kv: dict[str, Any]) -> None:
        html = str(self.vn.flags["html_head_d"])
        is_jinja = html[:2] in "%@%"
        if is_jinja:
            html = html.replace("%", "", 1)

        if html.startswith("@"):
            html = read_utf8(self.log, html[1:], True)

        if html.startswith("%"):
            html = html[1:]
            is_jinja = True

        if is_jinja:
            with self.conn.hsrv.mutex:
                if html not in self.conn.hsrv.j2:
                    j2env = jinja2.Environment()
                    tpl = j2env.from_string(html)
                    self.conn.hsrv.j2[html] = tpl
                html = self.conn.hsrv.j2[html].render(**kv)

        self.html_head += html + "\n"

    def send_headers(
        self,
        length: Optional[int],
        status: int = 200,
        mime: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        response = ["%s %s %s" % (self.http_ver, status, HTTPCODE[status])]

        # headers{} overrides anything set previously
        if headers:
            self.out_headers.update(headers)

        if status == 304:
            self.out_headers.pop("Content-Length", None)
            self.out_headers.pop("Content-Type", None)
            self.out_headerlist[:] = []
            if self.k304():
                self.keepalive = False
        else:
            if length is not None:
                response.append("Content-Length: " + unicode(length))

            if mime:
                self.out_headers["Content-Type"] = mime
            elif "Content-Type" not in self.out_headers:
                self.out_headers["Content-Type"] = "text/html; charset=utf-8"

        # close if unknown length, otherwise take client's preference
        response.append(H_CONN_KEEPALIVE if self.keepalive else H_CONN_CLOSE)
        response.append("Date: " + formatdate())

        for k, zs in list(self.out_headers.items()) + self.out_headerlist:
            response.append("%s: %s" % (k, zs))

        ptn_cc = RE_CC
        for zs in response:
            m = ptn_cc.search(zs)
            if m:
                t = "malicious user; Cc in out-hdr; req(%r) hdr(%r) => %r"
                self.log(t % (self.req, zs, zs[m.span()[0] :]), 1)
                self.cbonk(self.conn.hsrv.gmal, zs, "cc_hdr", "Cc in out-hdr")
                raise Pebkac(999)

        if self.args.ohead and self.do_log:
            keys = self.args.ohead
            if "*" in keys:
                lines = response[1:]
            else:
                lines = []
                for zs in response[1:]:
                    if zs.split(":")[0].lower() in keys:
                        lines.append(zs)
            for zs in lines:
                hk, hv = zs.split(": ")
                self.log("[O] {}: \033[33m[{}]".format(hk, hv), 5)

        response.append("\r\n")
        try:
            self.s.sendall("\r\n".join(response).encode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(400, "client d/c while replying headers")

    def reply(
        self,
        body: bytes,
        status: int = 200,
        mime: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        volsan: bool = False,
    ) -> bytes:
        if (
            status > 400
            and status in (403, 404, 422)
            and (
                status != 422
                or (
                    not body.startswith(b"<pre>partial upload exists")
                    and not body.startswith(b"<pre>source file busy")
                )
            )
            and (status != 404 or (self.can_get and not self.can_read))
        ):
            if status == 404:
                g = self.conn.hsrv.g404
            elif status == 403:
                g = self.conn.hsrv.g403
            else:
                g = self.conn.hsrv.g422

            gurl = self.conn.hsrv.gurl
            if (
                gurl.lim
                and (not g.lim or gurl.lim < g.lim)
                and self.args.sus_urls.search(self.vpath)
            ):
                g = self.conn.hsrv.gurl

            if g.lim and (
                g == self.conn.hsrv.g422
                or not self.args.nonsus_urls
                or not self.args.nonsus_urls.search(self.vpath)
            ):
                self.cbonk(g, self.vpath, str(status), "%ss" % (status,))

        if volsan:
            vols = list(self.asrv.vfs.all_vols.values())
            body = vol_san(vols, body)
            try:
                zs = absreal(__file__).rsplit(os.path.sep, 2)[0]
                body = body.replace(zs.encode("utf-8"), b"PP")
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                pass

        self.send_headers(len(body), status, mime, headers)

        try:
            if self.mode != "HEAD":
                self.s.sendall(body)
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(400, "client d/c while replying body")

        return body

    def loud_reply(self, body: str, *args: Any, **kwargs: Any) -> None:
        if not kwargs.get("mime"):
            kwargs["mime"] = "text/plain; charset=utf-8"

        self.log(body.rstrip())
        self.reply(body.encode("utf-8") + b"\r\n", *list(args), **kwargs)

    def terse_reply(self, body: bytes, status: int = 200) -> None:
        self.keepalive = False

        lines = [
            "%s %s %s" % (self.http_ver or "HTTP/1.1", status, HTTPCODE[status]),
            H_CONN_CLOSE,
        ]

        if body:
            lines.append(
                "Content-Type: text/html; charset=utf-8\r\nContent-Length: "
                + unicode(len(body))
            )

        lines.append("\r\n")
        self.s.sendall("\r\n".join(lines).encode("utf-8") + body)

    def urlq(self, add: dict[str, str], rm: list[str]) -> str:
        """
        generates url query based on uparam (b, pw, all others)
        removing anything in rm, adding pairs in add

        also list faster than set until ~20 items
        """

        if self.is_rclone:
            return ""

        kv = {k: zs for k, zs in self.uparam.items() if k not in rm}
        # no reason to consider args.pw_urlp
        if "pw" in kv:
            pw = self.cookies.get("cppws") or self.cookies.get("cppwd")
            if kv["pw"] == pw:
                del kv["pw"]

        kv.update(add)
        if not kv:
            return ""

        r = ["%s=%s" % (quotep(k), quotep(zs)) if zs else k for k, zs in kv.items()]
        return "?" + "&amp;".join(r)

    def ourlq(self) -> str:
        # no reason to consider args.pw_urlp
        skip = ("pw", "h", "k")
        ret = []
        for k, v in self.ouparam.items():
            if k in skip:
                continue

            t = "%s=%s" % (quotep(k), quotep(v))
            ret.append(t.replace(" ", "+").rstrip("="))

        if not ret:
            return ""

        return "?" + "&".join(ret)

    def redirect(
        self,
        vpath: str,
        suf: str = "",
        msg: str = "aight",
        flavor: str = "go to",
        click: bool = True,
        status: int = 200,
        use302: bool = False,
    ) -> bool:
        vp = self.args.SRS + vpath
        html = self.j2s(
            "msg",
            h2='<a href="{}">{} {}</a>'.format(
                quotep(vp) + suf, flavor, html_escape(vp, crlf=True) + suf
            ),
            pre=msg,
            click=click,
        ).encode("utf-8", "replace")

        if use302:
            self.reply(html, status=302, headers={"Location": vp})
        else:
            self.reply(html, status=status)

        return True

    def _cors(self) -> bool:
        ih = self.headers
        origin = ih.get("origin")
        if not origin:
            sfsite = ih.get("sec-fetch-site")
            if sfsite and sfsite.lower().startswith("cross"):
                origin = ":|"  # sandboxed iframe
            else:
                return True

        host = self.host.lower()
        if host.startswith("["):
            if "]:" in host:
                host = host.split("]:")[0] + "]"
        else:
            host = host.split(":")[0]

        oh = self.out_headers
        origin = origin.lower()
        proto = "https" if self.is_https else "http"
        good_origins = self.args.acao + ["%s://%s" % (proto, host)]

        if (
            self.args.pw_hdr in ih
            or re.sub(r"(:[0-9]{1,5})?/?$", "", origin) in good_origins
        ):
            good_origin = True
            bad_hdrs = ("",)
        else:
            good_origin = False
            bad_hdrs = ("", self.args.pw_hdr)

        # '*' blocks auth through cookies / WWW-Authenticate;
        # exact-match for Origin is necessary to unlock those,
        # but the ?pw= param and PW: header are always allowed
        acah = ih.get("access-control-request-headers", "")
        acao = (origin if good_origin else None) or (
            "*" if "*" in good_origins else None
        )
        if self.args.allow_csrf:
            acao = origin or acao or "*"  # explicitly permit impersonation
            acam = ", ".join(self.conn.hsrv.mallow)  # and all methods + headers
            oh["Access-Control-Allow-Credentials"] = "true"
            good_origin = True
        else:
            acam = ", ".join(self.args.acam)
            # wash client-requested headers and roll with that
            if "range" not in acah.lower():
                acah += ",Range"  # firefox
            req_h = acah.split(",")
            req_h = [x.strip() for x in req_h]
            req_h = [x for x in req_h if x.lower() not in bad_hdrs]
            acah = ", ".join(req_h)

        if not acao:
            return False

        oh["Access-Control-Allow-Origin"] = acao
        oh["Access-Control-Allow-Methods"] = acam.upper()
        if acah:
            oh["Access-Control-Allow-Headers"] = acah

        return good_origin

    def handle_get(self) -> bool:
        if self.do_log:
            logmsg = "%-4s %s @%s" % (self.mode, self.req, self.uname)

            if "range" in self.headers:
                try:
                    rval = self.headers["range"].split("=", 1)[1]
                except (KeyError, IndexError):
                    rval = self.headers["range"]

                logmsg += " [\033[36m" + rval + "\033[0m]"

            self.log(logmsg)
            if "%" in self.req:
                self.log(" `-- %r" % (self.vpath,))

        # "embedded" resources
        if self.vpath.startswith(".cpr"):
            if self.vpath.startswith(".cpr/ico/"):
                return self.tx_ico(self.vpath.split("/")[-1], exact=True)

            if self.vpath.startswith(".cpr/ssdp"):
                if self.conn.hsrv.ssdp:
                    return self.conn.hsrv.ssdp.reply(self)
                else:
                    self.reply(b"ssdp is disabled in server config", 404)
                    return False

            if self.vpath == ".cpr/metrics":
                return self.conn.hsrv.metrics.tx(self)

            res_path = "web/" + self.vpath[5:]
            if res_path in RES:
                ap = self.E.mod_ + res_path
                if bos.path.exists(ap) or bos.path.exists(ap + ".gz"):
                    return self.tx_file(ap)
                else:
                    return self.tx_res(res_path)

            if res_path in RESM:
                ap = self.E.mod_ + RESM[res_path]
                if (
                    "txt" not in self.uparam
                    and "mime" not in self.uparam
                    and not self.ouparam.get("dl")
                ):
                    # return mimetype matching request extension
                    self.ouparam["dl"] = res_path.split("/")[-1]
                if bos.path.exists(ap) or bos.path.exists(ap + ".gz"):
                    return self.tx_file(ap)
                else:
                    return self.tx_res(res_path)

            self.tx_404()
            return False

        if "cf_challenge" in self.uparam:
            self.reply(self.j2s("cf").encode("utf-8", "replace"))
            return True

        if not self.can_read and not self.can_write and not self.can_get:
            t = "@%s has no access to %r"

            if self.vn.realpath and "on403" in self.vn.flags:
                t += " (on403)"
                self.log(t % (self.uname, "/" + self.vpath))
                ret = self.on40x(self.vn.flags["on403"], self.vn, self.rem)
                if ret == "true":
                    return True
                elif ret == "false":
                    return False
                elif ret == "home":
                    self.uparam["h"] = ""
                elif ret == "allow":
                    self.log("plugin override; access permitted")
                    self.can_read = self.can_write = self.can_move = True
                    self.can_delete = self.can_get = self.can_upget = True
                    self.can_admin = True
                else:
                    return self.tx_404(True)
            else:
                if (
                    self.asrv.badcfg1
                    and "h" not in self.ouparam
                    and "hc" not in self.ouparam
                ):
                    zs1 = "copyparty refused to start due to a failsafe: invalid server config; check server log"
                    zs2 = 'you may <a href="/?h">access the controlpanel</a> but nothing will work until you shutdown the copyparty container and %s config-file (or provide the configuration as command-line arguments)'
                    if self.asrv.is_lxc and len(self.asrv.cfg_files_loaded) == 1:
                        zs2 = zs2 % ("add a",)
                    else:
                        zs2 = zs2 % ("fix the",)

                    html = self.j2s("msg", h1=zs1, h2=zs2)
                    self.reply(html.encode("utf-8", "replace"), 500)
                    return True

                if "ls" in self.uparam:
                    return self.tx_ls_vols()

                if self.vpath:
                    ptn = self.args.nonsus_urls
                    if not ptn or not ptn.search(self.vpath):
                        self.log(t % (self.uname, "/" + self.vpath))

                    return self.tx_404(True)

                self.uparam["h"] = ""

        if "smsg" in self.uparam:
            return self.handle_smsg()

        if "tree" in self.uparam:
            return self.tx_tree()

        if "scan" in self.uparam:
            return self.scanvol()

        if self.args.getmod:
            if "delete" in self.uparam:
                return self.handle_rm([])

            if "move" in self.uparam:
                return self.handle_mv()

            if "copy" in self.uparam:
                return self.handle_cp()

        if not self.vpath and self.ouparam:
            if "reload" in self.uparam:
                return self.handle_reload()

            if "stack" in self.uparam:
                return self.tx_stack()

            if "setck" in self.uparam:
                return self.setck()

            if "reset" in self.uparam:
                return self.set_cfg_reset()

            if "hc" in self.uparam:
                return self.tx_svcs()

            if "shares" in self.uparam:
                return self.tx_shares()

            if "dls" in self.uparam:
                return self.tx_dls()

            if "ru" in self.uparam:
                return self.tx_rups()

            if "idp" in self.uparam:
                return self.tx_idp()

        if "h" in self.uparam:
            return self.tx_mounts()

        if "ups" in self.uparam:
            # vpath is used for share translation
            return self.tx_ups()

        if "rss" in self.uparam:
            return self.tx_rss()

        return self.tx_browser()

    def tx_rss(self) -> bool:
        if self.do_log:
            self.log("RSS  %s @%s" % (self.req, self.uname))

        if not self.can_read:
            return self.tx_404(True)

        vn = self.vn
        if not vn.flags.get("rss"):
            raise Pebkac(405, "RSS is disabled in server config")

        rem = self.rem
        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; rss is disabled")
            raise Pebkac(500, "server busy, cannot generate rss; please retry in a bit")

        uv = [rem]
        if "recursive" in self.uparam:
            uq = "up.rd like ?||'%'"
        else:
            uq = "up.rd == ?"

        zs = str(self.uparam.get("fext", self.args.rss_fext))
        if zs in ("True", "False"):
            zs = ""
        if zs:
            zsl = []
            for ext in zs.split(","):
                zsl.append("+up.fn like '%.'||?")
                uv.append(ext)
            uq += " and ( %s )" % (" or ".join(zsl),)

        zs1 = self.uparam.get("sort") or self.args.rss_sort
        zs2 = zs1.lower()
        zs = RSS_SORT.get(zs2)
        if not zs:
            raise Pebkac(400, "invalid sort key; must be m/u/n/s")

        uq += " order by up." + zs
        if zs1 == zs2:
            uq += " desc"

        nmax = int(self.uparam.get("nf") or self.args.rss_nf)

        hits = idx.run_query(self.uname, [self.vn], uq, uv, False, False, nmax)[0]

        q_pw = a_pw = ""
        pwk = self.args.pw_urlp
        if pwk in self.ouparam and "nopw" not in self.ouparam:
            zs = self.ouparam[pwk]
            q_pw = "?%s=%s" % (pwk, quotep(zs))
            a_pw = "&%s=%s" % (pwk, quotep(zs))
            for i in hits:
                i["rp"] += a_pw if "?" in i["rp"] else q_pw

        title = self.uparam.get("title") or self.vpath.split("/")[-1]
        etitle = html_escape(title, True, True)

        baseurl = "%s://%s/" % (
            "https" if self.is_https else "http",
            self.host,
        )
        feed = baseurl + self.req[1:]
        if pwk in self.ouparam and self.ouparam.get("nopw") == "a":
            feed = re.sub(r"&%s=[^&]*" % (pwk,), "", feed)
        if self.is_vproxied:
            baseurl += self.args.RS
        efeed = html_escape(feed, True, True)
        edirlink = efeed.split("?")[0] + q_pw

        ret = [
            """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd" xmlns:content="http://purl.org/rss/1.0/modules/content/">
\t<channel>
\t\t<atom:link href="%s" rel="self" type="application/rss+xml" />
\t\t<title>%s</title>
\t\t<description></description>
\t\t<link>%s</link>
\t\t<generator>copyparty-2</generator>
"""
            % (efeed, etitle, edirlink)
        ]

        q = "select fn from cv where rd=? and dn=?"
        crd, cdn = rem.rsplit("/", 1) if "/" in rem else ("", rem)
        try:
            cfn = idx.cur[self.vn.realpath].execute(q, (crd, cdn)).fetchone()[0]
            bos.stat(os.path.join(vn.canonical(rem), cfn))
            cv_url = "%s%s?th=jf%s" % (baseurl, vjoin(self.vpath, cfn), a_pw)
            cv_url = html_escape(cv_url, True, True)
            zs = """\
\t\t<image>
\t\t\t<url>%s</url>
\t\t\t<title>%s</title>
\t\t\t<link>%s</link>
\t\t</image>
"""
            ret.append(zs % (cv_url, etitle, edirlink))
        except Exception:
            pass

        ap = ""
        use_magic = "rmagic" in self.vn.flags

        tpl_t = self.uparam.get("fmt_t") or self.vn.flags["rss_fmt_t"]
        tpl_d = self.uparam.get("fmt_d") or self.vn.flags["rss_fmt_d"]
        kw_t = [[x, x[1:-1]] for x in RE_RSS_KW.findall(tpl_t)]
        kw_d = [[x, x[1:-1]] for x in RE_RSS_KW.findall(tpl_d)]

        for i in hits:
            if use_magic:
                ap = os.path.join(self.vn.realpath, i["rp"])

            tags = i["tags"]
            iurl = html_escape("%s%s" % (baseurl, i["rp"]), True, True)
            fname = tags["fname"] = unquotep(i["rp"].split("?")[0].split("/")[-1])
            title = tpl_t
            desc = tpl_d
            for zs1, zs2 in kw_t:
                title = title.replace(zs1, str(tags.get(zs2, "")))
            for zs1, zs2 in kw_d:
                desc = desc.replace(zs1, str(tags.get(zs2, "")))
            title = html_escape(title.strip(), True, True)
            if desc.strip(" -,"):
                desc = html_escape(desc.strip(), True, True)
            else:
                desc = title

            mime = html_escape(guess_mime(fname, ap))
            lmod = formatdate(max(0, i["ts"]))
            zsa = (iurl, iurl, title, desc, lmod, iurl, mime, i["sz"])
            zs = (
                """\
\t\t<item>
\t\t\t<guid>%s</guid>
\t\t\t<link>%s</link>
\t\t\t<title>%s</title>
\t\t\t<description>%s</description>
\t\t\t<pubDate>%s</pubDate>
\t\t\t<enclosure url="%s" type="%s" length="%d"/>
"""
                % zsa
            )
            dur = i["tags"].get(".dur")
            if dur:
                zs += "\t\t\t<itunes:duration>%d</itunes:duration>\n" % (dur,)
            ret.append(zs + "\t\t</item>\n")

        ret.append("\t</channel>\n</rss>\n")
        bret = "".join(ret).encode("utf-8", "replace")
        self.reply(bret, 200, "text/xml; charset=utf-8")
        self.log("rss: %d hits, %d bytes" % (len(hits), len(bret)))
        return True

    def handle_delete(self) -> bool:
        self.log("DELETE %s @%s" % (self.req, self.uname))
        if "%" in self.req:
            self.log("   `-- %r" % (self.vpath,))
        return self.handle_rm([])

    def handle_put(self) -> bool:
        self.log("PUT  %s @%s" % (self.req, self.uname))
        if "%" in self.req:
            self.log(" `-- %r" % (self.vpath,))

        if not self.can_write:
            t = "user %s does not have write-access under /%s"
            raise Pebkac(403 if self.pw else 401, t % (self.uname, self.vn.vpath))

        if not self.args.no_dav and self._applesan():
            return False

        if self.headers.get("expect", "").lower() == "100-continue":
            try:
                self.s.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            except OSError:
                raise Pebkac(400, "client d/c before 100 continue")

        return self.handle_stash(True)

    def handle_post(self) -> bool:
        self.log("POST %s @%s" % (self.req, self.uname))
        if "%" in self.req:
            self.log(" `-- %r" % (self.vpath,))

        if self.headers.get("expect", "").lower() == "100-continue":
            try:
                self.s.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            except OSError:
                raise Pebkac(400, "client d/c before 100 continue")

        if "raw" in self.uparam:
            return self.handle_stash(False)

        ctype = self.headers.get("content-type", "").lower()

        if "multipart/form-data" in ctype:
            return self.handle_post_multipart()

        if (
            "application/json" in ctype
            or "text/plain" in ctype
            or "application/xml" in ctype
        ):
            return self.handle_post_json()

        if "smsg" in self.uparam:
            return self.handle_smsg()

        if "move" in self.uparam:
            return self.handle_mv()

        if "copy" in self.uparam:
            return self.handle_cp()

        if "delete" in self.uparam:
            return self.handle_rm([])

        if "eshare" in self.uparam:
            return self.handle_eshare()

        if "fs_abrt" in self.uparam:
            return self.handle_fs_abrt()

        if "application/octet-stream" in ctype:
            return self.handle_post_binary()

        if "application/x-www-form-urlencoded" in ctype:
            opt = self.args.urlform
            if "stash" in opt:
                return self.handle_stash(False)

            xm = []
            xm_rsp = {}

            if "save" in opt:
                post_sz, _, _, _, _, path, _ = self.dump_to_file(False)
                self.log("urlform: %d bytes, %r" % (post_sz, path))
            elif "print" in opt:
                reader, _ = self.get_body_reader()
                buf = b""
                for rbuf in reader:
                    buf += rbuf
                    if not rbuf or len(buf) >= 32768:
                        break

                if buf:
                    orig = buf.decode("utf-8", "replace")
                    t = "urlform_raw %d @ %r\n  %r\n"
                    self.log(t % (len(orig), "/" + self.vpath, orig))
                    try:
                        zb = unquote(buf.replace(b"+", b" ").replace(b"&", b"\n"))
                        plain = zb.decode("utf-8", "replace")
                        if buf.startswith(b"msg="):
                            plain = plain[4:]
                            xm = self.vn.flags.get("xm")
                            if xm:
                                xm_rsp = runhook(
                                    self.log,
                                    self.conn.hsrv.broker,
                                    None,
                                    "xm",
                                    xm,
                                    self.vn.canonical(self.rem),
                                    self.vpath,
                                    self.host,
                                    self.uname,
                                    self.asrv.vfs.get_perms(self.vpath, self.uname),
                                    time.time(),
                                    len(buf),
                                    self.ip,
                                    time.time(),
                                    [plain, orig],
                                )

                        t = "urlform_dec %d @ %r\n  %r\n"
                        self.log(t % (len(plain), "/" + self.vpath, plain))

                    except Exception as ex:
                        self.log(repr(ex))

            if "xm" in opt:
                if xm:
                    self.loud_reply(xm_rsp.get("stdout") or "", status=202)
                    return True
                else:
                    return self.handle_get()

            if "get" in opt:
                return self.handle_get()

            raise Pebkac(405, "POST(%r) is disabled in server config" % (ctype,))

        raise Pebkac(405, "don't know how to handle POST(%r)" % (ctype,))

    def handle_smsg(self) -> bool:
        if self.mode not in self.args.smsg_set:
            raise Pebkac(403, "smsg is disabled for this http-method in server config")

        msg = self.uparam["smsg"]
        self.log("smsg %d @ %r\n  %r\n" % (len(msg), "/" + self.vpath, msg))

        xm = self.vn.flags.get("xm")
        if xm:
            xm_rsp = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xm",
                xm,
                self.vn.canonical(self.rem),
                self.vpath,
                self.host,
                self.uname,
                self.asrv.vfs.get_perms(self.vpath, self.uname),
                time.time(),
                len(msg),
                self.ip,
                time.time(),
                [msg, msg],
            )
            self.loud_reply(xm_rsp.get("stdout") or "", status=202)
        else:
            self.loud_reply("k", status=202)
        return True

    def get_xml_enc(self, txt: str) -> str:
        ofs = txt[:512].find(' encoding="')
        enc = ""
        if ofs + 1:
            enc = txt[ofs + 6 :].split('"')[1]
        else:
            enc = self.headers.get("content-type", "").lower()
            ofs = enc.find("charset=")
            if ofs + 1:
                enc = enc[ofs + 4].split("=")[1].split(";")[0].strip("\"'")
            else:
                enc = ""

        return enc or "utf-8"

    def _spd(self, nbytes: int, add: bool = True) -> str:
        if add:
            self.conn.nbyte += nbytes

        spd1 = get_spd(nbytes, self.t0)
        spd2 = get_spd(self.conn.nbyte, self.conn.t0)
        return "%s %s n%s" % (spd1, spd2, self.conn.nreq)

    def handle_post_json(self) -> bool:
        try:
            remains = int(self.headers["content-length"])
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(411)

        if remains > 1024 * 1024:
            raise Pebkac(413, "json 2big")

        enc = "utf-8"
        ctype = self.headers.get("content-type", "").lower()
        if "charset" in ctype:
            enc = ctype.split("charset")[1].strip(" =").split(";")[0].strip()

        try:
            json_buf = self.sr.recv_ex(remains)
        except UnrecvEOF:
            raise Pebkac(422, "client disconnected while posting JSON")

        try:
            body = json.loads(json_buf.decode(enc, "replace"))
            try:
                zds = {k: v for k, v in body.items()}
                zds["hash"] = "%d chunks" % (len(body["hash"]),)
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                zds = body
            t = "POST len=%d type=%s ip=%s user=%s req=%r json=%s"
            self.log(t % (len(json_buf), enc, self.ip, self.uname, self.req, zds))
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(422, "you POSTed %d bytes of invalid json" % (len(json_buf),))

        # self.reply(b"cloudflare", 503)
        # return True

        if "srch" in self.uparam or "srch" in body:
            return self.handle_search(body)

        if "share" in self.uparam:
            return self.handle_share(body)

        if "delete" in self.uparam:
            return self.handle_rm(body)

        name = undot(body["name"])
        if "/" in name:
            raise Pebkac(400, "your client is old; press CTRL-SHIFT-R and try again")

        vfs, rem = self.asrv.vfs.get(self.vpath, self.uname, False, True)
        fsnt = vfs.flags["fsnt"]
        if fsnt != "lin":
            tl = VPTL_WIN if fsnt == "win" else VPTL_MAC
            rem = rem.translate(tl)
            name = name.translate(tl)
        dbv, vrem = vfs.get_dbv(rem)

        name = sanitize_fn(name)
        if (
            not self.can_read
            and self.can_write
            and name.lower() in dbv.flags["emb_all"]
            and "wo_up_readme" not in dbv.flags
        ):
            name = "_wo_" + name

        body["name"] = name
        body["vtop"] = dbv.vpath
        body["ptop"] = dbv.realpath
        body["prel"] = vrem
        body["host"] = self.host
        body["user"] = self.uname
        body["addr"] = self.ip
        body["vcfg"] = dbv.flags

        if not self.can_delete and not body.get("replace") == "skip":
            body.pop("replace", None)

        if rem:
            dst = vfs.canonical(rem)
            try:
                if not bos.path.isdir(dst):
                    bos.makedirs(dst, vf=vfs.flags)
            except OSError as ex:
                self.log("makedirs failed %r" % (dst,))
                if not bos.path.isdir(dst):
                    if ex.errno == errno.EACCES:
                        raise Pebkac(500, "the server OS denied write-access")

                    if ex.errno == errno.EEXIST:
                        raise Pebkac(400, "some file got your folder name")

                    raise Pebkac(500, min_ex())
            except Exception:
                raise Pebkac(500, min_ex())

        # not to protect u2fh, but to prevent handshakes while files are closing
        with self.u2mutex:
            x = self.conn.hsrv.broker.ask("up2k.handle_json", body, self.u2fh.aps)
            ret = x.get()

        if self.args.shr and self.vpath.startswith(self.args.shr1):
            # strip common suffix (uploader's folder structure)
            vp_req, vp_vfs = vroots(self.vpath, vjoin(dbv.vpath, vrem))
            if not ret["purl"].startswith(vp_vfs):
                t = "share-mapping failed; req=%r dbv=%r vrem=%r n1=%r n2=%r purl=%r"
                zt = (self.vpath, dbv.vpath, vrem, vp_req, vp_vfs, ret["purl"])
                raise Pebkac(500, t % zt)
            ret["purl"] = vp_req + ret["purl"][len(vp_vfs) :]

        if self.is_vproxied and not self.args.up_site:
            if "purl" in ret:
                ret["purl"] = self.args.SR + ret["purl"]

        ret = json.dumps(ret)
        self.log(ret)
        self.reply(ret.encode("utf-8"), mime="application/json")
        return True

    def handle_search(self, body: dict[str, Any]) -> bool:
        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; search is disabled")
            raise Pebkac(500, "server busy, cannot search; please retry in a bit")

        vols: list[VFS] = []
        seen: dict[VFS, bool] = {}
        for vtop in self.rvol:
            vfs, _ = self.asrv.vfs.get(vtop, self.uname, True, False)
            vfs = vfs.dbv or vfs
            if vfs in seen:
                continue

            seen[vfs] = True
            vols.append(vfs)

        t0 = time.time()
        if idx.p_end:
            penalty = 0.7
            t_idle = t0 - idx.p_end
            if idx.p_dur > 0.7 and t_idle < penalty:
                t = "rate-limit {:.1f} sec, cost {:.2f}, idle {:.2f}"
                raise Pebkac(429, t.format(penalty, idx.p_dur, t_idle))

        if "srch" in body:
            # search by up2k hashlist
            vbody = copy.deepcopy(body)
            vbody["hash"] = len(vbody["hash"])
            self.log("qj: " + repr(vbody))
            hits = idx.fsearch(self.uname, vols, body)
            msg: Any = repr(hits)
            taglist: list[str] = []
            trunc = False
        else:
            # search by query params
            q = body["q"]
            n = body.get("n", self.args.srch_hits)
            self.log("qj: %r |%d|" % (q, n))
            hits, taglist, trunc = idx.search(self.uname, vols, q, n)
            msg = len(hits)

        idx.p_end = time.time()
        idx.p_dur = idx.p_end - t0
        self.log("q#: %r (%.2fs)" % (msg, idx.p_dur))

        order = []
        for t in self.args.mte:
            if t in taglist:
                order.append(t)
        for t in taglist:
            if t not in order:
                order.append(t)

        if self.is_vproxied:
            for hit in hits:
                hit["rp"] = self.args.RS + hit["rp"]

        rj = {"hits": hits, "tag_order": order, "trunc": trunc}
        r = json.dumps(rj).encode("utf-8")
        self.reply(r, mime="application/json")
        return True

    def handle_chpw(self) -> bool:
        assert self.parser  # !rm
        if self.args.usernames:
            self.parser.require("uname", 64)
        pwd = self.parser.require("pw", 64)
        self.parser.drop()

        ok, msg = self.asrv.chpw(self.conn.hsrv.broker, self.uname, pwd)
        if ok:
            self.cbonk(self.conn.hsrv.gpwc, pwd, "pw", "too many password changes")
            if self.args.usernames:
                pwd = "%s:%s" % (self.uname, pwd)
            ok, msg = self.get_pwd_cookie(pwd)
            if ok:
                msg = "new password OK"

        redir = (self.args.SRS + "?h") if ok else ""
        h2 = '<a href="' + self.args.SRS + '?h">continue</a>'
        html = self.j2s("msg", h1=msg, h2=h2, redir=redir)
        self.reply(html.encode("utf-8"))
        return True

    def handle_login(self) -> bool:
        assert self.parser  # !rm
        if self.args.usernames and not (
            self.args.shr and self.vpath.startswith(self.args.shr1)
        ):
            try:
                un = self.parser.require("uname", 64)
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                un = ""
        else:
            un = ""
        pwd = self.parser.require("cppwd", 64)
        try:
            uhash = self.parser.require("uhash", 256)
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            uhash = ""
        self.parser.drop()

        if not pwd:
            raise Pebkac(422, "password cannot be blank")

        if un:
            pwd = "%s:%s" % (un, pwd)

        dst = self.args.SRS
        if self.vpath:
            dst += quotep(self.vpaths)

        dst += self.ourlq()

        uhash = uhash.lstrip("#")
        if uhash not in ("", "-"):
            dst += "&" if "?" in dst else "?"
            dst += "_=1#" + html_escape(uhash, True, True)

        _, msg = self.get_pwd_cookie(pwd)
        h2 = '<a href="' + dst + '">continue</a>'
        html = self.j2s("msg", h1=msg, h2=h2, redir=dst)
        self.reply(html.encode("utf-8"))
        return True

    def handle_logout(self) -> bool:
        assert self.parser  # !rm
        self.parser.drop()

        self.log("logout " + self.uname)
        if not self.uname.startswith("s_"):
            self.asrv.forget_session(self.conn.hsrv.broker, self.uname)
        self.get_pwd_cookie("x")

        dst = self.args.idp_logout or (self.args.SRS + "?h")
        h2 = '<a href="' + dst + '">continue</a>'
        html = self.j2s("msg", h1="ok bye", h2=h2, redir=dst)
        self.reply(html.encode("utf-8"))
        return True

    def get_pwd_cookie(self, pwd: str) -> tuple[bool, str]:
        uname = self.asrv.sesa.get(pwd)
        if not uname:
            hpwd = self.asrv.ah.hash(pwd)
            uname = self.asrv.iacct.get(hpwd)
            if uname:
                pwd = self.asrv.ases.get(uname) or pwd
        if uname and self.conn.hsrv.ipr:
            znm = self.conn.hsrv.ipr.get(uname)
            if znm and not znm.map(self.ip):
                self.log("username [%s] rejected by --ipr" % (self.uname,), 3)
                uname = ""
        if uname:
            msg = "hi " + uname
            dur = int(60 * 60 * self.args.logout)
        else:
            logpwd = pwd
            if self.args.log_badpwd == 0:
                logpwd = ""
            elif self.args.log_badpwd == 2:
                zb = hashlib.sha512(pwd.encode("utf-8", "replace")).digest()
                logpwd = "%" + ub64enc(zb[:12]).decode("ascii")

            if pwd != "x":
                self.log("invalid password: %r" % (logpwd,), 3)
                self.cbonk(self.conn.hsrv.gpwd, pwd, "pw", "invalid passwords")

            msg = "naw dude"
            pwd = "x"  # nosec
            dur = 0

        if pwd == "x":
            # reset both plaintext and tls
            # (only affects active tls cookies when tls)
            for k in ("cppwd", "cppws") if self.is_https else ("cppwd",):
                ck = gencookie(k, pwd, self.args.R, self.args.cookie_lax, False)
                self.out_headerlist.append(("Set-Cookie", ck))
            self.out_headers.pop("Set-Cookie", None)  # drop keepalive
        else:
            k = "cppws" if self.is_https else "cppwd"
            ck = gencookie(
                k,
                pwd,
                self.args.R,
                self.args.cookie_lax,
                self.is_https,
                dur,
                "; HttpOnly",
            )
            self.out_headers["Set-Cookie"] = ck

        return dur > 0, msg

    def set_idp_cookie(self, ases) -> None:
        k = "cppws" if self.is_https else "cppwd"
        ck = gencookie(
            k,
            ases,
            self.args.R,
            self.args.cookie_lax,
            self.is_https,
            self.args.idp_cookie,
            "; HttpOnly",
        )
        self.out_headers["Set-Cookie"] = ck

    def handle_mkdir(self) -> bool:
        assert self.parser  # !rm
        new_dir = self.parser.require("name", 512)
        self.parser.drop()

        return self._mkdir(vjoin(self.vpath, new_dir))

    def _mkdir(self, vpath: str, dav: bool = False) -> bool:
        nullwrite = self.args.nw
        self.gctx = vpath
        vpath = undot(vpath)
        vfs, rem = self.asrv.vfs.get(vpath, self.uname, False, True)
        if "nosub" in vfs.flags:
            raise Pebkac(403, "mkdir is forbidden below this folder")

        rem = sanitize_vpath(rem)
        fn = vfs.canonical(rem)

        if not nullwrite:
            fdir = os.path.dirname(fn)

            if dav and not bos.path.isdir(fdir):
                raise Pebkac(409, "parent folder does not exist")

            if bos.path.isdir(fn):
                raise Pebkac(405, 'folder "/%s" already exists' % (vpath,))

            try:
                bos.makedirs(fn, vf=vfs.flags)
            except OSError as ex:
                if ex.errno == errno.EACCES:
                    raise Pebkac(500, "the server OS denied write-access")

                raise Pebkac(500, "mkdir failed:\n" + min_ex())
            except Exception:
                raise Pebkac(500, min_ex())

        self.out_headers["X-New-Dir"] = quotep(self.args.RS + vpath)

        if dav:
            self.reply(b"", 201)
        else:
            self.redirect(vpath, status=201)

        return True

    def handle_new_md(self) -> bool:
        assert self.parser  # !rm
        new_file = self.parser.require("name", 512)
        self.parser.drop()

        nullwrite = self.args.nw
        vfs, rem = self.asrv.vfs.get(self.vpath, self.uname, False, True)
        self._assert_safe_rem(rem)

        if not self.can_delete and not new_file.lower().endswith(".md"):
            t = "you can only create .md files because you don't have the delete-permission"
            raise Pebkac(400, t)

        sanitized = sanitize_fn(new_file)
        fdir = vfs.canonical(rem)
        fn = os.path.join(fdir, sanitized)

        for hn in ("xbu", "xau"):
            xxu = vfs.flags.get(hn)
            if xxu:
                hr = runhook(
                    self.log,
                    self.conn.hsrv.broker,
                    None,
                    "%s.http.new-md" % (hn,),
                    xxu,
                    fn,
                    vjoin(self.vpath, sanitized),
                    self.host,
                    self.uname,
                    self.asrv.vfs.get_perms(self.vpath, self.uname),
                    time.time(),
                    0,
                    self.ip,
                    time.time(),
                    None,
                )
                t = hr.get("rejectmsg") or ""
                if t or hr.get("rc") != 0:
                    if not t:
                        t = "new-md blocked by " + hn + " server config: %r"
                        t = t % (vjoin(vfs.vpath, rem),)
                    self.log(t, 1)
                    raise Pebkac(403, t)

        if not nullwrite:
            if bos.path.exists(fn):
                raise Pebkac(500, "that file exists already")

            with open(fsenc(fn), "wb") as f:
                if "fperms" in vfs.flags:
                    set_fperms(f, vfs.flags)

            dbv, vrem = vfs.get_dbv(rem)
            self.conn.hsrv.broker.say(
                "up2k.hash_file",
                dbv.realpath,
                dbv.vpath,
                dbv.flags,
                vrem,
                sanitized,
                self.ip,
                bos.stat(fn).st_mtime,
                self.uname,
                True,
            )

        vpath = "{}/{}".format(self.vpath, sanitized).lstrip("/")
        self.redirect(vpath, "?edit")
        return True

    def _chk_lastmod(self, file_ts: int) -> tuple[str, bool, bool]:
        # ret: lastmod, do_send, can_range
        file_lastmod = formatdate(file_ts)
        c_ifrange = self.headers.get("if-range")
        c_lastmod = self.headers.get("if-modified-since")

        if not c_ifrange and not c_lastmod:
            return file_lastmod, True, True

        if c_ifrange and c_ifrange != file_lastmod:
            t = "sending entire file due to If-Range; cli(%s) file(%s)"
            self.log(t % (c_ifrange, file_lastmod), 6)
            return file_lastmod, True, False

        do_send = c_lastmod != file_lastmod
        if do_send and c_lastmod:
            t = "sending body due to If-Modified-Since cli(%s) file(%s)"
            self.log(t % (c_lastmod, file_lastmod), 6)
        elif not do_send and self.no304():
            do_send = True
            self.log("sending body due to no304")

        return file_lastmod, do_send, True

    def _use_dirkey(self, vn: VFS, ap: str) -> bool:
        if self.can_read or not self.can_get:
            return False

        if vn.flags.get("dky"):
            return True

        req = self.uparam.get("k") or ""
        if not req:
            return False

        dk_len = vn.flags.get("dk")
        if not dk_len:
            return False

        if not ap:
            ap = vn.canonical(self.rem)

        zs = self.gen_fk(2, self.args.dk_salt, ap, 0, 0)[:dk_len]
        if req == zs:
            return True

        t = "wrong dirkey, want %s, got %s\n  vp: %r\n  ap: %r"
        self.log(t % (zs, req, self.req, ap), 6)
        return False

    def _use_filekey(self, vn: VFS, ap: str, st: os.stat_result) -> bool:
        if self.can_read or not self.can_get:
            return False

        req = self.uparam.get("k") or ""
        if not req:
            return False

        fk_len = vn.flags.get("fk")
        if not fk_len:
            return False

        if not ap:
            ap = self.vn.canonical(self.rem)

        alg = 2 if "fka" in vn.flags else 1

        zs = self.gen_fk(
            alg, self.args.fk_salt, ap, st.st_size, 0 if ANYWIN else st.st_ino
        )[:fk_len]

        if req == zs:
            return True

        t = "wrong filekey, want %s, got %s\n  vp: %r\n  ap: %r"
        self.log(t % (zs, req, self.req, ap), 6)
        return False

    def tx_shares(self) -> bool:
        if self.uname == "*":
            self.loud_reply("you're not logged in")
            return True

        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; sharing is disabled")
            raise Pebkac(500, "server busy, cannot list shares; please retry in a bit")

        share_repo = idx.get_share_repo()
        if not share_repo:
            raise Pebkac(400, "huh, sharing must be disabled in the server config...")

        rows = share_repo.list_shares()
        rows = [list(x) for x in rows]

        if self.uname != self.args.shr_adm:
            rows = [x for x in rows if x[5] == self.uname]

        for r in rows:
            if not r[4]:
                r[4] = "---"
            else:
                files = share_repo.get_share_files(r[0])
                zsl = [html_escape(f) for f in files]
                r[4] = "<br />".join(zsl)

        if self.args.shr_site:
            site = self.args.shr_site[:-1]
        elif self.is_vproxied:
            site = self.args.SR
        else:
            site = ""

        html = self.j2s(
            "shares",
            this=self,
            shr=self.args.shr,
            site=site,
            rows=rows,
            now=int(time.time()),
        )
        self.reply(html.encode("utf-8"), status=200)
        return True

    def handle_eshare(self) -> bool:
        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; sharing is disabled")
            raise Pebkac(500, "server busy, cannot create share; please retry in a bit")

        skey = self.uparam.get("skey") or self.vpath.split("/")[-1]

        if self.args.shr_v:
            self.log("handle_eshare: " + skey)

        share_repo = idx.get_share_repo()
        if not share_repo:
            raise Pebkac(400, "huh, sharing must be disabled in the server config...")

        share = share_repo.get_share(skey)
        if not share:
            raise Pebkac(400, "that sharekey didn't match anything")

        # share tuple: (k, pw, vp, pr, st, un, t0, t1)
        un = share[5]
        expiry = share[7]

        if un != self.uname and self.uname != self.args.shr_adm:
            t = "your username (%r) does not match the sharekey's owner (%r) and you're not admin"
            raise Pebkac(400, t % (self.uname, un))

        reload = False
        act = self.uparam["eshare"]
        if act == "rm":
            share_repo.delete_share(skey)
            if skey in self.asrv.vfs.nodes[self.args.shr.strip("/")].nodes:
                reload = True
        else:
            now = time.time()
            if expiry < now:
                expiry = now
                reload = True
            expiry += int(act) * 60
            share_repo.update_expiry(skey, expiry)

        share_repo.commit()
        if reload:
            self.conn.hsrv.broker.ask("reload", False, True).get()
            self.conn.hsrv.broker.ask("up2k.wake_rescanner").get()

        self.redirect("", "?shares")
        return True

    def handle_share(self, req: dict[str, str]) -> bool:
        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; sharing is disabled")
            raise Pebkac(500, "server busy, cannot create share; please retry in a bit")

        if self.args.shr_v:
            self.log("handle_share: " + json.dumps(req, indent=4))

        skey = req["k"]
        vps = req["vp"]
        fns = []
        if len(vps) == 1:
            vp = vps[0]
            if not vp.endswith("/"):
                vp, zs = vp.rsplit("/", 1)
                fns = [zs]
        else:
            for zs in vps:
                if zs.endswith("/"):
                    t = "you cannot select more than one folder, or mix files and folders in one selection"
                    raise Pebkac(400, t)
            vp = vps[0].rsplit("/", 1)[0]
            for zs in vps:
                vp2, fn = zs.rsplit("/", 1)
                fns.append(fn)
                if vp != vp2:
                    t = "mismatching base paths in selection:\n  %r\n  %r"
                    raise Pebkac(400, t % (vp, vp2))

        vp = vp.strip("/")
        if self.is_vproxied and (vp == self.args.R or vp.startswith(self.args.RS)):
            vp = vp[len(self.args.RS) :]

        m = re.search(r"([^0-9a-zA-Z_-])", skey)
        if m:
            raise Pebkac(400, "sharekey has illegal character %r" % (m[1],))

        if vp.startswith(self.args.shr1):
            raise Pebkac(400, "yo dawg...")

        share_repo = idx.get_share_repo()
        if not share_repo:
            raise Pebkac(400, "huh, sharing must be disabled in the server config...")

        existing = share_repo.get_share(skey)
        if existing:
            self.log("sharekey taken by %r" % (existing,))
            raise Pebkac(400, "sharekey %r is already in use" % (skey,))

        # ensure user has requested perms
        s_rd = "read" in req["perms"]
        s_wr = "write" in req["perms"]
        s_get = "get" in req["perms"]
        s_axs = [s_rd, s_wr, False, False, s_get]

        if s_axs == [False] * 5:
            raise Pebkac(400, "select at least one permission")

        try:
            vfs, rem = self.asrv.vfs.get(vp, self.uname, *s_axs)
        except Exception:
            raise Pebkac(400, "you dont have all the perms you tried to grant")

        zs = vfs.flags["shr_who"]
        if zs == "auth" and self.uname != "*":
            pass
        elif zs == "a" and self.uname in vfs.axs.uadmin:
            pass
        else:
            raise Pebkac(400, "you dont have perms to create shares from this volume")

        ap, reals, _ = vfs.ls(rem, self.uname, not self.args.no_scandir, [s_axs])
        rfns = set([x[0] for x in reals])
        for fn in fns:
            if fn not in rfns:
                raise Pebkac(400, "selected file not found on disk: %r" % (fn,))

        pw = req.get("pw") or ""
        pw = self.asrv.ah.hash(pw)
        now = int(time.time())
        sexp = req["exp"]
        exp = int(sexp) if sexp else 0
        exp = now + exp * 60 if exp else 0
        pr = "".join(zc for zc, zb in zip("rwmdg", s_axs) if zb)

        share_repo.create_share(skey, pw, vp, pr, len(fns), self.uname, now, exp)

        for fn in fns:
            share_repo.add_share_file(skey, fn)

        share_repo.commit()
        self.conn.hsrv.broker.ask("reload", False, True).get()
        self.conn.hsrv.broker.ask("up2k.wake_rescanner").get()

        fn = quotep(fns[0]) if len(fns) == 1 else ""

        # NOTE: several clients (frontend, party-up) expect url at response[15:]
        if self.args.shr_site:
            surl = "created share: %s%s%s/%s" % (
                self.args.shr_site,
                self.args.shr[1:],
                skey,
                fn,
            )
        else:
            surl = "created share: %s://%s%s%s%s/%s" % (
                "https" if self.is_https else "http",
                self.host,
                self.args.SR,
                self.args.shr,
                skey,
                fn,
            )
        self.loud_reply(surl, status=201)
        return True

    def handle_rm(self, req: list[str]) -> bool:
        if not req and not self.can_delete:
            if self.mode == "DELETE" and self.uname == "*":
                raise Pebkac(401, "authenticate")  # webdav
            raise Pebkac(403, "'delete' not allowed for user " + self.uname)

        if self.args.no_del:
            raise Pebkac(403, "the delete feature is disabled in server config")

        unpost = "unpost" in self.uparam
        if unpost and hasattr(self, "bad_xff"):
            self.log("unpost was denied" + BADXFF, 1)
            raise Pebkac(403, "the delete feature is disabled in server config")

        if not unpost and self.vn.shr_src:
            raise Pebkac(403, "files in shares can only be deleted with unpost")

        if not req:
            req = [self.vpath]
        elif self.is_vproxied:
            req = [x[len(self.args.SR) :] for x in req]

        nlim = int(self.uparam.get("lim") or 0)
        lim = [nlim, nlim] if nlim else []

        x = self.conn.hsrv.broker.ask(
            "up2k.handle_rm", self.uname, self.ip, req, lim, False, unpost
        )
        self.loud_reply(x.get())
        return True

    def handle_mv(self) -> bool:
        # full path of new loc (incl filename)
        dst = self.uparam.get("move")

        if self.is_vproxied and dst and dst.startswith(self.args.SR):
            dst = dst[len(self.args.RS) :]

        if not dst:
            raise Pebkac(400, "need dst vpath")

        return self._mv(self.vpath, dst.lstrip("/"), False)

    def _mv(self, vsrc: str, vdst: str, overwrite: bool) -> bool:
        if self.args.no_mv:
            raise Pebkac(403, "the rename/move feature is disabled in server config")

        # `handle_cpmv` will catch 403 from these and raise 401
        svn, srem = self.asrv.vfs.get(vsrc, self.uname, True, False, True)
        dvn, drem = self.asrv.vfs.get(vdst, self.uname, False, True)

        if overwrite:
            dabs = dvn.canonical(drem)
            if bos.path.exists(dabs):
                self.log("overwriting %s" % (dabs,))
                self.asrv.vfs.get(vdst, self.uname, False, True, False, True)
                wunlink(self.log, dabs, dvn.flags)

        x = self.conn.hsrv.broker.ask(
            "up2k.handle_mv", self.ouparam.get("akey"), self.uname, self.ip, vsrc, vdst
        )
        self.loud_reply(x.get(), status=201)
        return True

    def handle_cp(self) -> bool:
        # full path of new loc (incl filename)
        dst = self.uparam.get("copy")

        if self.is_vproxied and dst and dst.startswith(self.args.SR):
            dst = dst[len(self.args.RS) :]

        if not dst:
            raise Pebkac(400, "need dst vpath")

        return self._cp(self.vpath, dst.lstrip("/"), False)

    def _cp(self, vsrc: str, vdst: str, overwrite: bool) -> bool:
        if self.args.no_cp:
            raise Pebkac(403, "the copy feature is disabled in server config")

        svn, srem = self.asrv.vfs.get(vsrc, self.uname, True, False)
        dvn, drem = self.asrv.vfs.get(vdst, self.uname, False, True)

        if overwrite:
            dabs = dvn.canonical(drem)
            if bos.path.exists(dabs):
                self.log("overwriting %s" % (dabs,))
                self.asrv.vfs.get(vdst, self.uname, False, True, False, True)
                wunlink(self.log, dabs, dvn.flags)

        x = self.conn.hsrv.broker.ask(
            "up2k.handle_cp", self.ouparam.get("akey"), self.uname, self.ip, vsrc, vdst
        )
        self.loud_reply(x.get(), status=201)
        return True

    def handle_fs_abrt(self):
        if self.args.no_fs_abrt:
            t = "aborting an ongoing copy/move is disabled in server config"
            raise Pebkac(403, t)

        self.conn.hsrv.broker.say("up2k.handle_fs_abrt", self.uparam["fs_abrt"])
        self.loud_reply("aborting", status=200)
        return True
