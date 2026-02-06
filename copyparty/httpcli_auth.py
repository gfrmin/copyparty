# coding: utf-8
from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import re
import stat
import time

from .bos import bos
from .util import (
    HAVE_SQLITE3,
    Pebkac,
    UnrecvEOF,
    VPTL_MAC,
    VPTL_WIN,
    formatdate,
    fsenc,
    gencookie,
    guess_mime,
    html_escape,
    min_ex,
    quotep,
    runhook,
    sanitize_fn,
    sanitize_vpath,
    set_fperms,
    ub64enc,
    undot,
    unquotep,
    vjoin,
    vroots,
    wunlink,
)

if True:  # pylint: disable=using-constant-test
    from typing import Any, Match

RSS_SORT = {"m": "mt", "u": "at", "n": "fn", "s": "sz"}
RE_RSS_KW = re.compile(r"(\{[^} ]+\})")


class HttpCliAuth(object):
    def unpwd(self, m: Match[str]) -> str:
        a, b, c = m.groups()
        uname = self.asrv.iacct.get(b) or self.asrv.sesa.get(b)
        return "%s\033[7m %s \033[27m%s" % (a, uname, c)

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
