# coding: utf-8
from __future__ import annotations

import errno
import itertools
import os
import re
import stat
import time
import uuid

from .bos import bos
from .util import (
    APPLESAN_RE,
    DAV_ALLPROPS,
    Pebkac,
    exclude_dotfiles,
    formatdate,
    fsenc,
    get_df,
    guess_mime,
    html_escape,
    quotep,
    unquotep,
    vjoin,
)

if True:  # pylint: disable=using-constant-test
    from typing import Any, Iterable


class HttpCliDav(object):
    def handle_propfind(self) -> bool:
        if self.do_log:
            self.log("PFIND %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log("  `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        vn = self.vn
        rem = self.rem
        tap = vn.canonical(rem)

        if "davauth" in vn.flags and self.uname == "*":
            raise Pebkac(401, "authenticate")

        from .dxml import parse_xml

        # enc = "windows-31j"
        # enc = "shift_jis"
        enc = "utf-8"
        uenc = enc.upper()
        props = DAV_ALLPROPS

        clen = int(self.headers.get("content-length", 0))
        if clen:
            buf = b""
            for rbuf in self.get_body_reader()[0]:
                buf += rbuf
                if not rbuf or len(buf) >= 32768:
                    break

            sbuf = buf.decode(enc, "replace")
            self.hint = "<xml> " + sbuf
            xroot = parse_xml(sbuf)
            xtag = next((x for x in xroot if x.tag.split("}")[-1] == "prop"), None)
            if xtag is not None:
                props = set([y.tag.split("}")[-1] for y in xtag])
            # assume <allprop/> otherwise; nobody ever gonna <propname/>
            self.hint = ""

        zi = int(time.time())
        vst = os.stat_result((16877, -1, -1, 1, 1000, 1000, 8, zi, zi, zi))

        try:
            st = bos.stat(tap)
        except OSError as ex:
            if ex.errno not in (errno.ENOENT, errno.ENOTDIR):
                raise
            if tap:
                raise Pebkac(404)
            st = vst

        topdir = {"vp": "", "st": st}
        fgen: Iterable[dict[str, Any]] = []

        depth = self.headers.get("depth", "infinity").lower()
        if depth == "infinity":
            # allow depth:0 from unmapped root, but require read-axs otherwise
            if not self.can_read and (self.vpath or self.asrv.vfs.realpath):
                t = "depth:infinity requires read-access in %r"
                t = t % ("/" + self.vpath,)
                self.log(t, 3)
                raise Pebkac(401, t)

            if not stat.S_ISDIR(topdir["st"].st_mode):
                t = "depth:infinity can only be used on folders; %r is 0o%o"
                t = t % ("/" + self.vpath, topdir["st"])
                self.log(t, 3)
                raise Pebkac(400, t)

            if not self.args.dav_inf:
                self.log("client wants --dav-inf", 3)
                zb = b'<?xml version="1.0" encoding="utf-8"?>\n<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>'
                self.reply(zb, 403, "application/xml; charset=utf-8")
                return True

            # this will return symlink-target timestamps
            # because lstat=true would not recurse into subfolders
            # and this is a rare case where we actually want that
            fgen = vn.zipgen(
                rem,
                rem,
                set(),
                self.uname,
                True,
                1,
                not self.args.no_scandir,
                wrap=False,
            )

        elif depth == "0" or not stat.S_ISDIR(st.st_mode):
            if depth == "0" and not self.vpath and not vn.realpath:
                # rootless server; give dummy listing
                self.can_read = True
            # propfind on a file; return as topdir
            if not self.can_read and not self.can_get:
                self.log("inaccessible: %r" % ("/" + self.vpath,))
                raise Pebkac(401, "authenticate")

        elif depth == "1":
            _, vfs_ls, vfs_virt = vn.ls(
                rem,
                self.uname,
                not self.args.no_scandir,
                [[True, False]],
                lstat="davrt" not in vn.flags,
                throw=True,
            )
            if not self.can_read:
                vfs_ls = []
            if not self.can_dot:
                names = set(exclude_dotfiles([x[0] for x in vfs_ls]))
                vfs_ls = [x for x in vfs_ls if x[0] in names]

            fgen = [{"vp": vp, "st": st} for vp, st in vfs_ls]
            fgen += [{"vp": v, "st": vst} for v in vfs_virt]

        else:
            t = "invalid depth value '{}' (must be either '0' or '1'{})"
            t2 = " or 'infinity'" if self.args.dav_inf else ""
            raise Pebkac(412, t.format(depth, t2))

        if not self.can_read and not self.can_write and not fgen:
            self.log("inaccessible: %r" % ("/" + self.vpath,))
            raise Pebkac(401, "authenticate")

        zi = (
            vn.flags["du_iwho"]
            if vn.realpath
            and "quota-available-bytes" in props
            and "quotaused" not in props  # macos finder; ingnore it
            else 0
        )
        if zi and (
            zi == 9
            or (zi == 7 and self.uname != "*")
            or (zi == 5 and self.can_write)
            or (zi == 4 and self.can_write and self.can_read)
            or (zi == 3 and self.can_admin)
        ):
            bfree, btot, _ = get_df(vn.realpath, False)
            if btot:
                if "vmaxb" in vn.flags:
                    assert vn.lim  # type: ignore  # !rm
                    btot = vn.lim.vbmax
                    if bfree == vn.lim.c_vb_r:
                        bfree = min(bfree, max(0, vn.lim.vbmax - vn.lim.c_vb_v))
                    else:
                        try:
                            zi, _ = self.conn.hsrv.broker.ask(
                                "up2k.get_volsizes", [vn.realpath]
                            ).get()[0]
                            vn.lim.c_vb_v = zi
                            vn.lim.c_vb_r = bfree
                            bfree = min(bfree, max(0, vn.lim.vbmax - zi))
                        except Exception:
                            pass
                df = {
                    "quota-available-bytes": str(bfree),
                    "quota-used-bytes": str(btot - bfree),
                }
            else:
                df = {}
        else:
            df = {}

        fgen = itertools.chain([topdir], fgen)
        vtop = vjoin(self.args.R, vjoin(vn.vpath, rem))

        chunksz = 0x7FF8  # preferred by nginx or cf (dunno which)

        self.send_headers(
            None, 207, "text/xml; charset=" + enc, {"Transfer-Encoding": "chunked"}
        )

        ap = ""
        use_magic = "rmagic" in vn.flags

        ret = '<?xml version="1.0" encoding="{}"?>\n<D:multistatus xmlns:D="DAV:">'
        ret = ret.format(uenc)
        for x in fgen:
            rp = vjoin(vtop, x["vp"])
            st: os.stat_result = x["st"]
            mtime = max(0, st.st_mtime)
            if stat.S_ISLNK(st.st_mode):
                try:
                    st = bos.stat(os.path.join(tap, x["vp"]))
                except OSError:
                    continue

            isdir = stat.S_ISDIR(st.st_mode)

            ret += "<D:response><D:href>/%s%s</D:href><D:propstat><D:prop>" % (
                quotep(rp),
                "/" if isdir and rp else "",
            )

            pvs: dict[str, str] = {
                "displayname": html_escape(rp.split("/")[-1]),
                "getlastmodified": formatdate(mtime),
                "resourcetype": '<D:collection xmlns:D="DAV:"/>' if isdir else "",
                "supportedlock": '<D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>',
            }
            if not isdir:
                if use_magic:
                    ap = os.path.join(tap, x["vp"])
                pvs["getcontenttype"] = html_escape(guess_mime(rp, ap))
                pvs["getcontentlength"] = str(st.st_size)
            elif df:
                pvs.update(df)

            for k, v in pvs.items():
                if k not in props:
                    continue
                elif v:
                    ret += "<D:%s>%s</D:%s>" % (k, v, k)
                else:
                    ret += "<D:%s/>" % (k,)

            ret += "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"

            missing = ["<D:%s/>" % (x,) for x in props if x not in pvs]
            if missing and clen:
                t = "<D:propstat><D:prop>{}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"
                ret += t.format("".join(missing))

            ret += "</D:response>"
            while len(ret) >= chunksz:
                ret = self.send_chunk(ret, enc, chunksz)

        ret += "</D:multistatus>"
        while ret:
            ret = self.send_chunk(ret, enc, chunksz)

        self.send_chunk("", enc, chunksz)
        # self.reply(ret.encode(enc, "replace"),207, "text/xml; charset=" + enc)
        return True

    def handle_proppatch(self) -> bool:
        if self.do_log:
            self.log("PPATCH %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log("   `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        if not self.can_write:
            self.log("%s tried to proppatch %r" % (self.uname, "/" + self.vpath))
            raise Pebkac(401, "authenticate")

        from xml.etree import ElementTree as ET

        from .dxml import mkenod, mktnod, parse_xml

        buf = b""
        for rbuf in self.get_body_reader()[0]:
            buf += rbuf
            if not rbuf or len(buf) >= 128 * 1024:
                break

        if self._applesan():
            return True

        txt = buf.decode("ascii", "replace").lower()
        enc = self.get_xml_enc(txt)
        uenc = enc.upper()

        txt = buf.decode(enc, "replace")
        self.hint = "<xml> " + txt
        ET.register_namespace("D", "DAV:")
        xroot = mkenod("D:orz")
        xroot.insert(0, parse_xml(txt))
        xprop = xroot.find(r"./{DAV:}propertyupdate/{DAV:}set/{DAV:}prop")
        assert xprop  # !rm
        for ze in xprop:
            ze.clear()
        self.hint = ""

        txt = """<multistatus xmlns="DAV:"><response><propstat><status>HTTP/1.1 403 Forbidden</status></propstat></response></multistatus>"""
        xroot = parse_xml(txt)

        el = xroot.find(r"./{DAV:}response")
        assert el  # !rm
        e2 = mktnod("D:href", quotep(self.args.SRS + self.vpath))
        el.insert(0, e2)

        el = xroot.find(r"./{DAV:}response/{DAV:}propstat")
        assert el  # !rm
        el.insert(0, xprop)

        ret = '<?xml version="1.0" encoding="{}"?>\n'.format(uenc)
        ret += ET.tostring(xroot).decode("utf-8")

        self.reply(ret.encode(enc, "replace"), 207, "text/xml; charset=" + enc)
        return True

    def handle_lock(self) -> bool:
        if self.do_log:
            self.log("LOCK %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log(" `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        # win7+ deadlocks if we say no; just smile and nod
        if not self.can_write and "Microsoft-WebDAV" not in self.ua:
            self.log("%s tried to lock %r" % (self.uname, "/" + self.vpath))
            raise Pebkac(401, "authenticate")

        from xml.etree import ElementTree as ET

        from .dxml import mkenod, mktnod, parse_xml

        abspath = self.vn.dcanonical(self.rem)

        buf = b""
        for rbuf in self.get_body_reader()[0]:
            buf += rbuf
            if not rbuf or len(buf) >= 128 * 1024:
                break

        if self._applesan():
            return True

        txt = buf.decode("ascii", "replace").lower()
        enc = self.get_xml_enc(txt)
        uenc = enc.upper()

        txt = buf.decode(enc, "replace")
        self.hint = "<xml> " + txt
        ET.register_namespace("D", "DAV:")
        lk = parse_xml(txt)
        assert lk.tag == "{DAV:}lockinfo"
        self.hint = ""

        token = str(uuid.uuid4())

        if lk.find(r"./{DAV:}depth") is None:
            depth = self.headers.get("depth", "infinity")
            lk.append(mktnod("D:depth", depth))

        lk.append(mktnod("D:timeout", "Second-3310"))
        lk.append(mkenod("D:locktoken", mktnod("D:href", token)))
        lk.append(
            mkenod("D:lockroot", mktnod("D:href", quotep(self.args.SRS + self.vpath)))
        )

        lk2 = mkenod("D:activelock")
        xroot = mkenod("D:prop", mkenod("D:lockdiscovery", lk2))
        for a in lk:
            lk2.append(a)

        ret = '<?xml version="1.0" encoding="{}"?>\n'.format(uenc)
        ret += ET.tostring(xroot).decode("utf-8")

        rc = 200
        if self.can_write and not bos.path.isfile(abspath):
            with open(fsenc(abspath), "wb") as _:
                rc = 201

        self.out_headers["Lock-Token"] = "<{}>".format(token)
        self.reply(ret.encode(enc, "replace"), rc, "text/xml; charset=" + enc)
        return True

    def handle_unlock(self) -> bool:
        if self.do_log:
            self.log("UNLOCK %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log("   `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        if not self.can_write and "Microsoft-WebDAV" not in self.ua:
            self.log("%s tried to lock %r" % (self.uname, "/" + self.vpath))
            raise Pebkac(401, "authenticate")

        self.send_headers(None, 204)
        return True

    def handle_mkcol(self) -> bool:
        if self._applesan():
            return True

        if self.do_log:
            self.log("MKCOL %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log("  `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        if not self.can_write:
            raise Pebkac(401, "authenticate")

        try:
            return self._mkdir(self.vpath, True)
        except Pebkac as ex:
            if ex.code >= 500:
                raise

            self.reply(b"", ex.code)
            return True

    def handle_cpmv(self) -> bool:
        dst = self.headers["destination"]

        # dolphin (kioworker/6.10) "webdav://127.0.0.1:3923/a/b.txt"
        dst = re.sub("^[a-zA-Z]+://[^/]+", "", dst).lstrip()

        if self.is_vproxied and dst.startswith(self.args.SRS):
            dst = dst[len(self.args.RS) :]

        if self.do_log:
            self.log("%s %s  --//>  %s @%s" % (self.mode, self.req, dst, self.uname))
            if "%" in self.req:
                self.log("  `-- %r" % (self.vpath,))

        if self.args.no_dav:
            raise Pebkac(405, "WebDAV is disabled in server config")

        dst = unquotep(dst)

        # overwrite=True is default; rfc4918 9.8.4
        zs = self.headers.get("overwrite", "").lower()
        overwrite = zs not in ["f", "false"]

        try:
            fun = self._cp if self.mode == "COPY" else self._mv
            return fun(self.vpath, dst.lstrip("/"), overwrite)
        except Pebkac as ex:
            if ex.code == 403:
                ex.code = 401
            raise

    def _applesan(self) -> bool:
        if self.args.dav_mac or "Darwin/" not in self.ua:
            return False

        vp = "/" + self.vpath
        if re.search(APPLESAN_RE, vp):
            zt = '<?xml version="1.0" encoding="utf-8"?>\n<D:error xmlns:D="DAV:"><D:lock-token-submitted><D:href>{}</D:href></D:lock-token-submitted></D:error>'
            zb = zt.format(vp).encode("utf-8", "replace")
            self.reply(zb, 423, "text/xml; charset=utf-8")
            return True

        return False

    def send_chunk(self, txt: str, enc: str, bmax: int) -> str:
        orig_len = len(txt)
        buf = txt[:bmax].encode(enc, "replace")[:bmax]
        try:
            _ = buf.decode(enc)
        except UnicodeDecodeError as ude:
            buf = buf[: ude.start]

        txt = txt[len(buf.decode(enc)) :]
        if txt and len(txt) == orig_len:
            raise Pebkac(500, "chunk slicing failed")

        buf = ("%x\r\n" % (len(buf),)).encode(enc) + buf
        self.s.sendall(buf + b"\r\n")
        return txt

    def handle_options(self) -> bool:
        if self.do_log:
            self.log("OPTIONS %s @%s" % (self.req, self.uname))
            if "%" in self.req:
                self.log("    `-- %r" % (self.vpath,))

        oh = self.out_headers
        oh["Allow"] = ", ".join(self.conn.hsrv.mallow)

        if not self.args.no_dav:
            # PROPPATCH, LOCK, UNLOCK, COPY: noop (spec-must)
            oh["Dav"] = "1, 2"
            oh["Ms-Author-Via"] = "DAV"

        # winxp-webdav doesnt know what 204 is
        self.send_headers(0, 200)
        return True
