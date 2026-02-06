# coding: utf-8
from __future__ import annotations

import json
import os
import re
import stat
import time

from .bos import bos
from .util import (
    ODict,
    Pebkac,
    UTC,
    absreal,
    exclude_dotfiles,
    fsenc,
    get_df,
    guess_mime,
    html_escape,
    humansize,
    min_ex,
    quotep,
    read_utf8,
    s3enc,
    ub64enc,
    ujoin,
    undot,
    vjoin,
    vsplit,
)

from .__init__ import ANYWIN

if True:  # pylint: disable=using-constant-test
    from typing import Any, Optional

IDX_HTML = set(["index.htm", "index.html"])

A_FILE = os.stat_result(
    (0o644, -1, -1, 1, 1000, 1000, 8, 0x39230101, 0x39230101, 0x39230101)
)

RE_HR = re.compile(r"[<>\"'&]")
RE_MDV = re.compile(r"(.*)\.([0-9]+\.[0-9]{3})(\.[Mm][Dd])$")

PERMS_rwh = [
    [True, False],
    [False, True],
    [False, False, False, False, False, False, True],
]


class HttpCliListing(object):
    def _add_logues(
        self, vn: VFS, abspath: str, lnames: Optional[dict[str, str]]
    ) -> tuple[list[str], list[str]]:
        logues = ["", ""]
        for n, fns1, fns2 in [] if self.args.no_logues else vn.flags["emb_lgs"]:
            for fn in fns1 if lnames is None else fns2:
                if lnames is not None:
                    fn = lnames.get(fn)
                    if not fn:
                        continue
                fn = "%s/%s" % (abspath, fn)
                if not bos.path.isfile(fn):
                    continue
                logues[n] = read_utf8(self.log, fsenc(fn), False)
                if "exp" in vn.flags:
                    logues[n] = self._expand(logues[n], vn.flags.get("exp_lg") or [])
                break

        readmes = ["", ""]
        for n, fns1, fns2 in [] if self.args.no_readme else vn.flags["emb_mds"]:
            if logues[n]:
                continue
            for fn in fns1 if lnames is None else fns2:
                if lnames is not None:
                    fn = lnames.get(fn.lower())
                    if not fn:
                        continue
                fn = "%s/%s" % (abspath, fn)
                if not bos.path.isfile(fn):
                    continue
                readmes[n] = read_utf8(self.log, fsenc(fn), False)
                if "exp" in vn.flags:
                    readmes[n] = self._expand(readmes[n], vn.flags.get("exp_md") or [])
                break

        return logues, readmes

    def _expand(self, txt: str, phs: list[str]) -> str:
        ptn_hsafe = RE_HSAFE
        for ph in phs:
            if ph.startswith("hdr."):
                sv = str(self.headers.get(ph[4:], ""))
            elif ph.startswith("self."):
                sv = str(getattr(self, ph[5:], ""))
            elif ph.startswith("cfg."):
                sv = str(getattr(self.args, ph[4:], ""))
            elif ph.startswith("vf."):
                sv = str(self.vn.flags.get(ph[3:]) or "")
            elif ph == "srv.itime":
                sv = str(int(time.time()))
            elif ph == "srv.htime":
                sv = datetime.now(UTC).strftime("%Y-%m-%d, %H:%M:%S")
            else:
                self.log("unknown placeholder in server config: [%s]" % (ph,), 3)
                continue

            sv = ptn_hsafe.sub("_", sv)
            txt = txt.replace("{{%s}}" % (ph,), sv)

        return txt

    def _can_tail(self, volflags: dict[str, Any]) -> bool:
        zp = self.args.ua_nodoc
        if zp and zp.search(self.ua):
            t = "this URL contains no valuable information for bots/crawlers"
            raise Pebkac(403, t)
        lvl = volflags["tail_who"]
        if "notail" in volflags or not lvl:
            raise Pebkac(400, "tail is disabled in server config")
        elif lvl <= 1 and not self.can_admin:
            raise Pebkac(400, "tail is admin-only on this server")
        elif lvl <= 2 and self.uname in ("", "*"):
            raise Pebkac(400, "you must be authenticated to use ?tail on this server")
        return True

    def _can_zip(self, volflags: dict[str, Any]) -> str:
        lvl = volflags["zip_who"]
        if self.args.no_zip or not lvl:
            return "download-as-zip/tar is disabled in server config"
        elif lvl <= 1 and not self.can_admin:
            return "download-as-zip/tar is admin-only on this server"
        elif lvl <= 2 and self.uname in ("", "*"):
            return "you must be authenticated to download-as-zip/tar on this server"
        elif self.args.ua_nozip and self.args.ua_nozip.search(self.ua):
            t = "this URL contains no valuable information for bots/crawlers"
            raise Pebkac(403, t)
        return ""

    def tx_tree(self) -> bool:
        top = self.uparam["tree"] or ""
        dst = self.vpath
        if top in [".", ".."]:
            top = undot(self.vpath + "/" + top)

        if top == dst:
            dst = ""
        elif top:
            if not dst.startswith(top + "/"):
                raise Pebkac(422, "arg funk")

            dst = dst[len(top) + 1 :]

        ret = self.gen_tree(top, dst, self.uparam.get("k", ""))
        if self.is_vproxied and not self.uparam["tree"]:
            # uparam is '' on initial load, which is
            # the only time we gotta fill in the blanks
            parents = self.args.R.split("/")
            for parent in reversed(parents):
                ret = {"k%s" % (parent,): ret, "a": []}

        zs = json.dumps(ret)
        self.reply(zs.encode("utf-8"), mime="application/json")
        return True

    def gen_tree(self, top: str, target: str, dk: str) -> dict[str, Any]:
        ret: dict[str, Any] = {}
        excl = None
        if target:
            excl, target = (target.split("/", 1) + [""])[:2]
            sub = self.gen_tree("/".join([top, excl]).strip("/"), target, dk)
            ret["k" + quotep(excl)] = sub

        vfs = self.asrv.vfs
        dk_sz = False
        if dk:
            vn, rem = vfs.get(top, self.uname, False, False)
            if vn.flags.get("dks") and self._use_dirkey(vn, vn.canonical(rem)):
                dk_sz = vn.flags.get("dk")

        dots = False
        fsroot = ""
        try:
            vn, rem = vfs.get(top, self.uname, not dk_sz, False)
            fsroot, vfs_ls, vfs_virt = vn.ls(
                rem,
                self.uname,
                not self.args.no_scandir,
                PERMS_rwh,
            )
            dots = self.uname in vn.axs.udot
            dk_sz = vn.flags.get("dk")
        except (KeyError, IndexError):
            dk_sz = None
            vfs_ls = []
            vfs_virt = {}
            for v in self.rvol:
                d1, d2 = v.rsplit("/", 1) if "/" in v else ["", v]
                if d1 == top:
                    vfs_virt[d2] = vfs  # typechk, value never read

        dirs = [x[0] for x in vfs_ls if stat.S_ISDIR(x[1].st_mode)]

        if not dots or "dots" not in self.uparam:
            dirs = exclude_dotfiles(dirs)

        dirs = [quotep(x) for x in dirs if x != excl]

        if dk_sz and fsroot:
            kdirs = []
            fsroot_ = os.path.join(fsroot, "")
            for dn in dirs:
                ap = fsroot_ + dn
                zs = self.gen_fk(2, self.args.dk_salt, ap, 0, 0)[:dk_sz]
                kdirs.append(dn + "?k=" + zs)
            dirs = kdirs

        for x in vfs_virt:
            if x != excl:
                try:
                    dvn, drem = vfs.get(vjoin(top, x), self.uname, False, False)
                    if (
                        self.uname not in dvn.axs.uread
                        and self.uname not in dvn.axs.uwrite
                        and self.uname not in dvn.axs.uhtml
                    ):
                        raise Exception()
                    bos.stat(dvn.canonical(drem, False))
                except Exception:
                    x += "\n"
                dirs.append(x)

        ret["a"] = dirs
        return ret

    def tx_ls_vols(self) -> bool:
        e_d = {}
        eses = ["", ""]
        rvol = self.rvol
        wvol = self.wvol
        allvols = self.asrv.vfs.all_nodes
        if self.args.have_unlistc:
            rvol = [x for x in rvol if "unlistcr" not in allvols[x].flags]
            wvol = [x for x in wvol if "unlistcw" not in allvols[x].flags]
        vols = [(x, allvols[x]) for x in list(set(rvol + wvol))]
        if self.vpath:
            zs = "%s/" % (self.vpath,)
            vols = [(x[len(zs) :], y) for x, y in vols if x.startswith(zs)]
        vols = [(x.split("/", 1)[0], y) for x, y in vols]
        vols = list(({x: y for x, y in vols if x}).items())
        if not vols and self.vpath:
            return self.tx_404(True)
        dirs = [
            {
                "lead": "",
                "href": "%s/" % (x,),
                "ext": "---",
                "sz": 0,
                "ts": 0,
                "tags": e_d,
                "dt": 0,
                "name": 0,
                "perms": vn.get_perms("", self.uname),
            }
            for x, vn in sorted(vols)
        ]
        ls = {
            "dirs": dirs,
            "files": [],
            "acct": self.uname,
            "perms": [],
            "taglist": [],
            "logues": eses,
            "readmes": eses,
            "srvinf": "" if self.args.nih else self.args.name,
        }
        return self.tx_ls(ls)

    def tx_ls(self, ls: dict[str, Any]) -> bool:
        dirs = ls["dirs"]
        files = ls["files"]
        arg = self.uparam["ls"]
        if arg in ["v", "t", "txt"]:
            try:
                biggest = max(ls["files"] + ls["dirs"], key=itemgetter("sz"))["sz"]
            except (ValueError, KeyError):
                biggest = 0

            if arg == "v":
                fmt = "\033[0;7;36m{{}}{{:>{}}}\033[0m {{}}"
                nfmt = "{}"
                biggest = 0
                f2 = "".join(
                    "{}{{}}".format(x)
                    for x in [
                        "\033[7m",
                        "\033[27m",
                        "",
                        "\033[0;1m",
                        "\033[0;36m",
                        "\033[0m",
                    ]
                )
                ctab = {"B": 6, "K": 5, "M": 1, "G": 3}
                for lst in [dirs, files]:
                    for x in lst:
                        a = x["dt"].replace("-", " ").replace(":", " ").split(" ")
                        x["dt"] = f2.format(*list(a))
                        sz = humansize(x["sz"], True)
                        x["sz"] = "\033[0;3{}m {:>5}".format(ctab.get(sz[-1:], 0), sz)
            else:
                fmt = "{{}}  {{:{},}}  {{}}"
                nfmt = "{:,}"

            for x in dirs:
                n = x["name"] + "/"
                if arg == "v":
                    n = "\033[94m" + n

                x["name"] = n

            fmt = fmt.format(len(nfmt.format(biggest)))
            retl = [
                ("# %s: %s" % (x, ls[x])).replace(r"</span> // <span>", " // ")
                for x in ["acct", "perms", "srvinf"]
                if x in ls
            ]
            retl += [
                fmt.format(x["dt"], x["sz"], x["name"])
                for y in [dirs, files]
                for x in y
            ]
            ret = "\n".join(retl)
            mime = "text/plain; charset=utf-8"
        else:
            [x.pop(k) for k in ["name", "dt"] for y in [dirs, files] for x in y]

            # nonce (tlnote: norwegian for flake as in snowflake)
            if self.args.no_fnugg:
                ls["fnugg"] = "nei"
            elif "fnugg" in self.headers:
                ls["fnugg"] = self.headers["fnugg"]

            ret = json.dumps(ls)
            mime = "application/json"

        ret += "\n\033[0m" if arg == "v" else "\n"
        self.reply(ret.encode("utf-8", "replace"), mime=mime)
        return True

    def tx_browser(self) -> bool:
        vpath = ""
        vpnodes = [["", "/"]]
        if self.vpath:
            for node in self.vpath.split("/"):
                if not vpath:
                    vpath = node
                else:
                    vpath += "/" + node

                vpnodes.append([quotep(vpath) + "/", html_escape(node, crlf=True)])

        vn = self.vn
        rem = self.rem
        abspath = vn.dcanonical(rem)
        dbv, vrem = vn.get_dbv(rem)

        try:
            st = bos.stat(abspath)
        except (KeyError, IndexError):
            if "on404" not in vn.flags:
                return self.tx_404(not self.can_read)

            ret = self.on40x(vn.flags["on404"], vn, rem)
            if ret == "true":
                return True
            elif ret == "false":
                return False
            elif ret == "retry":
                try:
                    st = bos.stat(abspath)
                except OSError:
                    return self.tx_404(not self.can_read)
            else:
                return self.tx_404(not self.can_read)

        if rem.startswith(".hist/up2k.") or (
            rem.endswith("/dir.txt") and rem.startswith(".hist/th/")
        ):
            raise Pebkac(403)

        e2d = "e2d" in vn.flags
        e2t = "e2t" in vn.flags

        add_og = "og" in vn.flags
        if add_og:
            if "th" in self.uparam or "raw" in self.uparam or "opds" in self.uparam:
                add_og = False
            elif vn.flags["og_ua"]:
                add_og = vn.flags["og_ua"].search(self.ua)
            og_fn = ""

        if "v" in self.uparam:
            add_og = True
            og_fn = ""

        if "b" in self.uparam:
            self.out_headers["X-Robots-Tag"] = "noindex, nofollow"

        is_dir = stat.S_ISDIR(st.st_mode)
        is_dk = False
        fk_pass = False
        icur = None
        if (e2t or e2d) and (is_dir or add_og):
            idx = self.conn.get_u2idx()
            if idx and hasattr(idx, "p_end"):
                icur = idx.get_cur(dbv)

        if "k" in self.uparam or "dky" in vn.flags:
            if is_dir:
                use_dirkey = self._use_dirkey(vn, abspath)
                use_filekey = False
            else:
                use_filekey = self._use_filekey(vn, abspath, st)
                use_dirkey = False
        else:
            use_dirkey = use_filekey = False

        th_fmt = self.uparam.get("th")
        if self.can_read or (
            self.can_get
            and (use_filekey or use_dirkey or (not is_dir and "fk" not in vn.flags))
        ):
            if th_fmt is not None:
                nothumb = "dthumb" in dbv.flags
                if is_dir:
                    vrem = vrem.rstrip("/")
                    if nothumb:
                        pass
                    elif icur and vrem:
                        q = "select fn from cv where rd=? and dn=?"
                        crd, cdn = vrem.rsplit("/", 1) if "/" in vrem else ("", vrem)
                        # no mojibake support:
                        try:
                            cfn = icur.execute(q, (crd, cdn)).fetchone()
                            if cfn:
                                fn = cfn[0]
                                fp = os.path.join(abspath, fn)
                                st = bos.stat(fp)
                                vrem = "{}/{}".format(vrem, fn).strip("/")
                                is_dir = False
                        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                            pass
                    else:
                        for fn in self.args.th_covers:
                            fp = os.path.join(abspath, fn)
                            try:
                                st = bos.stat(fp)
                                vrem = "{}/{}".format(vrem, fn).strip("/")
                                is_dir = False
                                break
                            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                                pass

                    if is_dir:
                        return self.tx_svg("folder")

                thp = None
                if self.thumbcli and not nothumb:
                    try:
                        thp = self.thumbcli.get(dbv, vrem, int(st.st_mtime), th_fmt)
                    except Pebkac as ex:
                        if ex.code == 500 and th_fmt[:1] in "jw":
                            self.log("failed to convert [%s]:\n%s" % (abspath, ex), 3)
                            return self.tx_svg("--error--\ncheck\nserver\nlog")
                        raise

                if thp:
                    return self.tx_file(thp)

                if th_fmt == "p":
                    raise Pebkac(404)
                elif th_fmt in ACODE2_FMT:
                    raise Pebkac(415)

                return self.tx_ico(rem)

        elif self.can_write and th_fmt is not None:
            return self.tx_svg("upload\nonly")

        if not self.can_read and self.can_get and self.avn:
            if not self.can_html:
                pass
            elif is_dir:
                for fn in ("index.htm", "index.html"):
                    ap2 = os.path.join(abspath, fn)
                    try:
                        st2 = bos.stat(ap2)
                    except OSError:
                        continue

                    # might as well be extra careful
                    if not stat.S_ISREG(st2.st_mode):
                        continue

                    if not self.trailing_slash:
                        return self.redirect(
                            self.vpath + "/", flavor="redirecting to", use302=True
                        )

                    fk_pass = True
                    is_dir = False
                    add_og = False
                    rem = vjoin(rem, fn)
                    vrem = vjoin(vrem, fn)
                    abspath = ap2
                    break
            elif self.vpath.rsplit("/", 1)[-1] in IDX_HTML:
                fk_pass = True

        if not is_dir and (self.can_read or self.can_get):
            if (
                not self.can_read
                and not fk_pass
                and "fk" in vn.flags
                and not use_filekey
                and not self.vpath.startswith(self.args.shr1 or "\n")
            ):
                return self.tx_404(True)

            is_md = abspath.lower().endswith(".md")
            if add_og and not is_md:
                if self.host not in self.headers.get("referer", ""):
                    self.vpath, og_fn = vsplit(self.vpath)
                    vpath = self.vpath
                    vn, rem = self.asrv.vfs.get(self.vpath, self.uname, False, False)
                    abspath = vn.dcanonical(rem)
                    dbv, vrem = vn.get_dbv(rem)
                    is_dir = stat.S_ISDIR(st.st_mode)
                    is_dk = True
                    vpnodes.pop()

            if (
                (is_md or self.can_delete)
                and "nohtml" not in vn.flags
                and (
                    (is_md and "v" in self.uparam)
                    or "edit" in self.uparam
                    or "edit2" in self.uparam
                )
            ):
                return self.tx_md(vn, abspath)

            if "zls" in self.uparam:
                return self.tx_zls(abspath)
            if "zget" in self.uparam:
                return self.tx_zget(abspath)

            if not add_og or not og_fn:
                if st.st_size or "nopipe" in vn.flags:
                    return self.tx_file(abspath, None)
                else:
                    return self.tx_file(abspath, vn.get_dbv("")[0].realpath)

        elif is_dir and not self.can_read:
            if use_dirkey:
                is_dk = True
            elif self.can_get and "doc" in self.uparam:
                zs = vjoin(self.vpath, self.uparam["doc"]) + "?v"
                return self.redirect(zs, flavor="redirecting to", use302=True)
            elif not self.can_write:
                return self.tx_404(True)

        srv_info = []

        try:
            if not self.args.nih:
                srv_info.append(self.args.name_html)
        except (AttributeError, TypeError):
            self.log("#wow #whoa")

        zi = vn.flags["du_iwho"]
        if zi and (
            zi == 9
            or (zi == 7 and self.uname != "*")
            or (zi == 5 and self.can_write)
            or (zi == 4 and self.can_write and self.can_read)
            or (zi == 3 and self.can_admin)
        ):
            free, total, zs = get_df(abspath, False)
            if total:
                if "vmaxb" in vn.flags:
                    assert vn.lim  # type: ignore  # !rm
                    total = vn.lim.vbmax
                    if free == vn.lim.c_vb_r:
                        free = min(free, max(0, vn.lim.vbmax - vn.lim.c_vb_v))
                    else:
                        try:
                            zi, _ = self.conn.hsrv.broker.ask(
                                "up2k.get_volsizes", [vn.realpath]
                            ).get()[0]
                            vn.lim.c_vb_v = zi
                            vn.lim.c_vb_r = free
                            free = min(free, max(0, vn.lim.vbmax - zi))
                        except Exception:
                            pass
                h1 = humansize(free or 0)
                h2 = humansize(total)
                srv_info.append("{} free of {}".format(h1, h2))
            elif zs:
                self.log("diskfree(%r): %s" % (abspath, zs), 3)

        srv_infot = "</span> // <span>".join(srv_info)

        perms = []
        if self.can_read or is_dk:
            perms.append("read")
        if self.can_write:
            perms.append("write")
        if self.can_move:
            perms.append("move")
        if self.can_delete:
            perms.append("delete")
        if self.can_get:
            perms.append("get")
        if self.can_upget:
            perms.append("upget")
        if self.can_admin:
            perms.append("admin")

        url_suf = self.urlq({}, ["k"])
        is_ls = "ls" in self.uparam
        is_opds = "opds" in self.uparam
        is_js = self.args.force_js or self.cookies.get("js") == "y"

        if not is_ls and not add_og and self.ua.startswith(("curl/", "fetch")):
            self.uparam["ls"] = "v"
            is_ls = True

        tpl = "browser"
        if "b" in self.uparam:
            tpl = "browser2"
            is_js = False
        elif is_opds:
            # Display directory listing as OPDS v1.2 catalog feed
            if not (self.args.opds or "opds" in self.vn.flags):
                raise Pebkac(405, "OPDS is disabled in server config")
            if not self.can_read:
                raise Pebkac(401, "OPDS requires read permission")
            is_js = is_ls = False

        vf = vn.flags
        ls_ret = {
            "dirs": [],
            "files": [],
            "taglist": [],
            "srvinf": srv_infot,
            "acct": self.uname,
            "perms": perms,
            "cfg": vn.js_ls,
        }
        cgv = {
            "ls0": None,
            "acct": self.uname,
            "perms": perms,
        }
        # also see `js_htm` in authsrv.py
        j2a = {
            "cgv1": vn.js_htm,
            "cgv": cgv,
            "vpnodes": vpnodes,
            "files": [],
            "ls0": None,
            "taglist": [],
            "have_tags_idx": int(e2t),
            "have_b_u": (self.can_write and self.uparam.get("b") == "u"),
            "sb_lg": vn.js_ls["sb_lg"],
            "url_suf": url_suf,
            "title": html_escape("%s %s" % (self.args.bname, self.vpath), crlf=True),
            "srv_info": srv_infot,
            "dtheme": self.args.theme,
        }

        if self.args.js_browser:
            zs = self.args.js_browser
            zs += "&" if "?" in zs else "?"
            j2a["js"] = zs

        if self.args.css_browser:
            zs = self.args.css_browser
            zs += "&" if "?" in zs else "?"
            j2a["css"] = zs

        if not self.conn.hsrv.prism:
            j2a["no_prism"] = True

        if not self.can_read and not is_dk:
            logues, readmes = self._add_logues(vn, abspath, None)
            ls_ret["logues"] = j2a["logues"] = logues
            ls_ret["readmes"] = cgv["readmes"] = readmes

            if is_ls:
                return self.tx_ls(ls_ret)

            if not stat.S_ISDIR(st.st_mode):
                return self.tx_404(True)

            if "zip" in self.uparam or "tar" in self.uparam:
                raise Pebkac(403)

            zsl = j2a["files"] = []
            if is_js:
                j2a["ls0"] = cgv["ls0"] = {
                    "dirs": zsl,
                    "files": zsl,
                    "taglist": zsl,
                }

            html = self.j2s(tpl, **j2a)
            self.reply(html.encode("utf-8", "replace"))
            return True

        for k in ["zip", "tar"]:
            v = self.uparam.get(k)
            if v is not None and (not add_og or not og_fn):
                if is_dk and "dks" not in vn.flags:
                    t = "server config does not allow download-as-zip/tar; only dk is specified, need dks too"
                    raise Pebkac(403, t)
                return self.tx_zip(k, v, self.vpath, vn, rem, [])

        fsroot, vfs_ls, vfs_virt = vn.ls(
            rem,
            self.uname,
            not self.args.no_scandir,
            PERMS_rwh,
            lstat="lt" in self.uparam,
            throw=True,
        )
        stats = {k: v for k, v in vfs_ls}
        ls_names = [x[0] for x in vfs_ls]
        ls_names.extend(list(vfs_virt.keys()))

        if add_og and og_fn and not self.can_read:
            ls_names = [og_fn]
            is_js = True

        # check for old versions of files,
        # [num-backups, most-recent, hist-path]
        hist: dict[str, tuple[int, float, str]] = {}
        try:
            if vf["md_hist"] != "s":
                raise Exception()
            histdir = os.path.join(fsroot, ".hist")
            ptn = RE_MDV
            for hfn in bos.listdir(histdir):
                m = ptn.match(hfn)
                if not m:
                    continue

                fn = m.group(1) + m.group(3)
                n, ts, _ = hist.get(fn, (0, 0, ""))
                hist[fn] = (n + 1, max(ts, float(m.group(2))), hfn)
        except Exception:
            pass

        lnames = {x.lower(): x for x in ls_names}

        # show dotfiles if permitted and requested
        if not self.can_dot or (
            "dots" not in self.uparam and (is_ls or "dots" not in self.cookies)
        ):
            ls_names = exclude_dotfiles(ls_names)

        add_dk = vf.get("dk")
        add_fk = vf.get("fk")
        fk_alg = 2 if "fka" in vf else 1
        if add_dk:
            if vf.get("dky"):
                add_dk = False
            else:
                zs = self.gen_fk(2, self.args.dk_salt, abspath, 0, 0)[:add_dk]
                ls_ret["dk"] = cgv["dk"] = zs

        no_zip = bool(self._can_zip(vf))

        dirs = []
        files = []
        ptn_hr = RE_HR
        use_abs_url = (
            not is_opds
            and not is_ls
            and not is_js
            and not self.trailing_slash
            and vpath
        )
        for fn in ls_names:
            base = ""
            href = fn
            if use_abs_url:
                base = "/" + vpath + "/"
                href = base + fn

            if fn in vfs_virt:
                fspath = vfs_virt[fn].realpath
            else:
                fspath = fsroot + "/" + fn

            try:
                linf = stats.get(fn) or bos.lstat(fspath)
                inf = bos.stat(fspath) if stat.S_ISLNK(linf.st_mode) else linf
            except OSError:
                self.log("broken symlink: %r" % (fspath,))
                continue

            is_dir = stat.S_ISDIR(inf.st_mode)
            if is_dir:
                href += "/"
                if no_zip:
                    margin = "DIR"
                elif add_dk:
                    zs = absreal(fspath)
                    margin = '<a href="%s?k=%s&zip=crc" rel="nofollow">zip</a>' % (
                        quotep(href),
                        self.gen_fk(2, self.args.dk_salt, zs, 0, 0)[:add_dk],
                    )
                else:
                    margin = '<a href="%s?zip=crc" rel="nofollow">zip</a>' % (
                        quotep(href),
                    )
            elif fn in hist:
                margin = '<a href="%s.hist/%s" rel="nofollow">#%s</a>' % (
                    base,
                    html_escape(hist[fn][2], quot=True, crlf=True),
                    hist[fn][0],
                )
            else:
                margin = "-"

            sz = inf.st_size
            zd = datetime.fromtimestamp(max(0, linf.st_mtime), UTC)
            dt = "%04d-%02d-%02d %02d:%02d:%02d" % (
                zd.year,
                zd.month,
                zd.day,
                zd.hour,
                zd.minute,
                zd.second,
            )

            if is_dir:
                ext = "---"
            elif "." in fn:
                ext = ptn_hr.sub("@", fn.rsplit(".", 1)[1])
                if len(ext) > 16:
                    ext = ext[:16]
            else:
                ext = "%"

            if add_fk and not is_dir:
                href = "%s?k=%s" % (
                    quotep(href),
                    self.gen_fk(
                        fk_alg,
                        self.args.fk_salt,
                        fspath,
                        sz,
                        0 if ANYWIN else inf.st_ino,
                    )[:add_fk],
                )
            elif add_dk and is_dir:
                href = "%s?k=%s" % (
                    quotep(href),
                    self.gen_fk(2, self.args.dk_salt, fspath, 0, 0)[:add_dk],
                )
            else:
                href = quotep(href)

            item = {
                "lead": margin,
                "href": href,
                "name": fn,
                "sz": sz,
                "ext": ext,
                "dt": dt,
                "ts": int(linf.st_mtime),
            }
            if is_dir:
                dirs.append(item)
            else:
                files.append(item)

        if is_dk and not vf.get("dks"):
            dirs = []

        if (
            self.cookies.get("idxh") == "y"
            and "ls" not in self.uparam
            and "v" not in self.uparam
            and not is_opds
        ):
            for item in files:
                if item["name"] in IDX_HTML:
                    # do full resolve in case of shadowed file
                    vp = vjoin(self.vpath.split("?")[0], item["name"])
                    vn, rem = self.asrv.vfs.get(vp, self.uname, True, False)
                    ap = vn.canonical(rem)
                    if not self.trailing_slash and bos.path.isfile(ap):
                        return self.redirect(
                            self.vpath + "/", flavor="redirecting to", use302=True
                        )
                    return self.tx_file(ap)  # is no-cache

        if icur:
            mte = vn.flags.get("mte") or {}
            tagset: set[str] = set()
            rd = vrem
            if self.can_admin:
                up_q = "select substr(w,1,16), ip, at, un from up where rd=? and fn=?"
                up_m = ["w", "up_ip", ".up_at", "up_by"]
            else:
                up_q, up_m = vn.flags["ls_q_m"]

            mt_q = "select mt.k, mt.v from up inner join mt on mt.w = substr(up.w,1,16) where up.rd = ? and up.fn = ? and +mt.k != 'x'"
            for fe in files:
                fn = fe["name"]
                erd_efn = (rd, fn)
                try:
                    r = icur.execute(mt_q, erd_efn)
                except Exception as ex:
                    if "database is locked" in str(ex):
                        break

                    try:
                        erd_efn = s3enc(idx.mem_cur, rd, fn)
                        r = icur.execute(mt_q, erd_efn)
                    except Exception:
                        self.log("tag read error, %r / %r\n%s" % (rd, fn, min_ex()))
                        break

                tags = {k: v for k, v in r}

                if up_q:
                    try:
                        up_v = icur.execute(up_q, erd_efn).fetchone()
                        for zs1, zs2 in zip(up_m, up_v):
                            if zs2:
                                tags[zs1] = zs2
                    except Exception:
                        pass

                _ = [tagset.add(k) for k in tags]
                fe["tags"] = tags

            for fe in dirs:
                fe["tags"] = ODict()

            lmte = list(mte)
            if self.can_admin:
                lmte.extend(("w", "up_by", "up_ip", ".up_at"))

            if "nodirsz" not in vf:
                tagset.add(".files")
                vdir = "%s/" % (rd,) if rd else ""
                q = "select sz, nf from ds where rd=? limit 1"
                for fe in dirs:
                    try:
                        hit = icur.execute(q, (vdir + fe["name"],)).fetchone()
                        (fe["sz"], fe["tags"][".files"]) = hit
                    except Exception:
                        pass  # 404 or mojibake

            taglist = [k for k in lmte if k in tagset]
        else:
            taglist = []

        logues, readmes = self._add_logues(vn, abspath, lnames)
        ls_ret["logues"] = j2a["logues"] = logues
        ls_ret["readmes"] = cgv["readmes"] = readmes

        if (
            not files
            and not dirs
            and not readmes[0]
            and not readmes[1]
            and not logues[0]
            and not logues[1]
        ):
            logues[1] = "this folder is empty"

        if "descript.ion" in lnames and os.path.isfile(
            os.path.join(abspath, lnames["descript.ion"])
        ):
            rem = []
            items = {x["name"].lower(): x for x in files + dirs}
            with open(os.path.join(abspath, lnames["descript.ion"]), "rb") as f:
                for bln in [x.strip() for x in f]:
                    try:
                        if bln.endswith(b"\x04\xc2"):
                            # multiline comment; replace literal r"\n" with " // "
                            bln = bln.replace(br"\\n", b" // ")[:-2]
                        ln = bln.decode("utf-8", "replace")
                        if ln.startswith('"'):
                            fn, desc = ln.split('" ', 1)
                            fn = fn[1:]
                        else:
                            fn, desc = ln.split(" ", 1)
                        try:
                            items[fn.lower()]["tags"]["descript.ion"] = desc
                        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                            t = "<li><code>%s</code> %s</li>"
                            rem.append(t % (html_escape(fn), html_escape(desc)))
                    except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                        pass
            if "descript.ion" not in taglist:
                taglist.insert(0, "descript.ion")
            if rem and not logues[1]:
                t = "<h3>descript.ion</h3><ul>\n"
                logues[1] = t + "\n".join(rem) + "</ul>"

        if is_ls:
            ls_ret["dirs"] = dirs
            ls_ret["files"] = files
            ls_ret["taglist"] = taglist
            return self.tx_ls(ls_ret)

        doc = self.uparam.get("doc") if self.can_read else None
        if doc:
            zp = self.args.ua_nodoc
            if zp and zp.search(self.ua):
                t = "this URL contains no valuable information for bots/crawlers"
                raise Pebkac(403, t)
            j2a["docname"] = doc
            doctxt = None
            dfn = lnames.get(doc.lower())
            if dfn and dfn != doc:
                # found Foo but want FOO
                dfn = next((x for x in files if x["name"] == doc), None)
            if dfn:
                docpath = os.path.join(abspath, doc)
                sz = bos.path.getsize(docpath)
                if sz < 1024 * self.args.txt_max:
                    doctxt = read_utf8(self.log, fsenc(docpath), False)
                    if doc.lower().endswith(".md") and "exp" in vn.flags:
                        doctxt = self._expand(doctxt, vn.flags.get("exp_md") or [])
                else:
                    self.log("doc 2big: %r" % (doc,), 6)
                    doctxt = "( size of textfile exceeds serverside limit )"
            else:
                self.log("doc 404: %r" % (doc,), 6)
                doctxt = "( textfile not found )"

            if doctxt is not None:
                j2a["doc"] = doctxt

        for d in dirs:
            d["name"] += "/"

        dirs.sort(key=itemgetter("name"))

        if is_opds:
            # exclude files which don't match --opds-exts
            allowed_exts = vf.get("opds_exts") or self.args.opds_exts
            if allowed_exts:
                files = [
                    x for x in files if x["name"].rsplit(".", 1)[-1] in allowed_exts
                ]
            for item in dirs:
                href = item["href"]
                href += ("&" if "?" in href else "?") + "opds"
                item["href"] = href
                item["iso8601"] = "%sZ" % (item["dt"].replace(" ", "T"),)

            for item in files:
                href = item["href"]
                href += ("&" if "?" in href else "?") + "dl"
                item["href"] = href
                item["iso8601"] = "%sZ" % (item["dt"].replace(" ", "T"),)

                if "rmagic" in self.vn.flags:
                    ap = "%s/%s" % (fsroot, item["name"])
                    item["mime"] = guess_mime(item["name"], ap)
                else:
                    item["mime"] = guess_mime(item["name"])

                # Make sure we can actually generate JPEG thumbnails
                if (
                    not self.args.th_no_jpg
                    and self.thumbcli
                    and "dthumb" not in dbv.flags
                    and "dithumb" not in dbv.flags
                ):
                    item["jpeg_thumb_href"] = href + "&th=jf"
                    item["jpeg_thumb_href_hires"] = item["jpeg_thumb_href"] + "3"

            j2a["files"] = files
            j2a["dirs"] = dirs
            html = self.j2s("opds", **j2a)
            mime = "application/atom+xml;profile=opds-catalog"
            self.reply(html.encode("utf-8", "replace"), mime=mime)
            return True

        if is_js:
            j2a["ls0"] = cgv["ls0"] = {
                "dirs": dirs,
                "files": files,
                "taglist": taglist,
            }
            j2a["files"] = []
        else:
            j2a["files"] = dirs + files

        j2a["taglist"] = taglist

        if add_og and "raw" not in self.uparam:
            j2a["this"] = self
            cgv["og_fn"] = og_fn
            if og_fn and vn.flags.get("og_tpl"):
                tpl = vn.flags["og_tpl"]
                if "EXT" in tpl:
                    zs = og_fn.split(".")[-1].lower()
                    tpl2 = tpl.replace("EXT", zs)
                    if os.path.exists(tpl2):
                        tpl = tpl2
                with self.conn.hsrv.mutex:
                    if tpl not in self.conn.hsrv.j2:
                        tdir, tname = os.path.split(tpl)
                        j2env = jinja2.Environment()
                        j2env.loader = jinja2.FileSystemLoader(tdir)
                        self.conn.hsrv.j2[tpl] = j2env.get_template(tname)
            thumb = ""
            is_pic = is_vid = is_au = False
            for fn in self.args.th_coversd:
                if fn in lnames:
                    thumb = lnames[fn]
                    break
            if og_fn:
                ext = og_fn.split(".")[-1].lower()
                if self.thumbcli and ext in self.thumbcli.thumbable:
                    is_pic = (
                        ext in self.thumbcli.fmt_pil
                        or ext in self.thumbcli.fmt_vips
                        or ext in self.thumbcli.fmt_ffi
                    )
                    is_vid = ext in self.thumbcli.fmt_ffv
                    is_au = ext in self.thumbcli.fmt_ffa
                    if not thumb or not is_au:
                        thumb = og_fn
                file = next((x for x in files if x["name"] == og_fn), None)
            else:
                file = None

            url_base = "%s://%s/%s" % (
                "https" if self.is_https else "http",
                self.host,
                self.args.RS + quotep(vpath),
            )
            j2a["og_is_pic"] = is_pic
            j2a["og_is_vid"] = is_vid
            j2a["og_is_au"] = is_au
            if thumb:
                fmt = vn.flags.get("og_th", "j")
                th_base = ujoin(url_base, quotep(thumb))
                query = "th=%s&cache" % (fmt,)
                if use_filekey:
                    query += "&k=" + self.uparam["k"]
                query = ub64enc(query.encode("utf-8")).decode("ascii")
                # discord looks at file extension, not content-type...
                query += "/th.jpg" if "j" in fmt else "/th.webp"
                j2a["og_thumb"] = "%s/.uqe/%s" % (th_base, query)

            j2a["og_fn"] = og_fn
            j2a["og_file"] = file
            if og_fn:
                og_fn_q = quotep(og_fn)
                query = "raw"
                if use_filekey:
                    query += "&k=" + self.uparam["k"]
                query = ub64enc(query.encode("utf-8")).decode("ascii")
                query += "/%s" % (og_fn_q,)
                j2a["og_url"] = ujoin(url_base, og_fn_q)
                j2a["og_raw"] = j2a["og_url"] + "/.uqe/" + query
            else:
                j2a["og_url"] = j2a["og_raw"] = url_base

            if not vn.flags.get("og_no_head"):
                ogh = {"twitter:card": "summary"}

                title = str(vn.flags.get("og_title") or "")

                if thumb:
                    ogh["og:image"] = j2a["og_thumb"]

                zso = vn.flags.get("og_desc") or ""
                if zso != "-":
                    ogh["og:description"] = str(zso)

                zs = vn.flags.get("og_site") or self.args.name
                if zs not in ("", "-"):
                    ogh["og:site_name"] = zs

                try:
                    assert file is not None  # type: ignore  # !rm
                    zs1, zs2 = file["tags"]["res"].split("x")
                    file["tags"][".resw"] = zs1
                    file["tags"][".resh"] = zs2
                except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                    pass

                tagmap = {}

                if is_au:
                    title = str(vn.flags.get("og_title_a") or "")
                    ogh["og:type"] = "music.song"
                    ogh["og:audio"] = j2a["og_raw"]
                    tagmap = {
                        "artist": "og:music:musician",
                        "album": "og:music:album",
                        ".dur": "og:music:duration",
                    }
                elif is_vid:
                    title = str(vn.flags.get("og_title_v") or "")
                    ogh["og:type"] = "video.other"
                    ogh["og:video"] = j2a["og_raw"]

                    tagmap = {
                        "title": "og:title",
                        ".dur": "og:video:duration",
                        ".resw": "og:video:width",
                        ".resh": "og:video:height",
                    }
                elif is_pic:
                    title = str(vn.flags.get("og_title_i") or "")
                    ogh["twitter:card"] = "summary_large_image"
                    ogh["twitter:image"] = ogh["og:image"] = j2a["og_raw"]

                    tagmap = {
                        ".resw": "og:image:width",
                        ".resh": "og:image:height",
                    }

                try:
                    assert file is not None  # type: ignore  # !rm
                    for k, v in file["tags"].items():
                        zs = "{{ %s }}" % (k,)
                        title = title.replace(zs, str(v))
                except (AssertionError, KeyError, TypeError):
                    pass
                title = re.sub(r"\{\{ [^}]+ \}\}", "", title)
                while title.startswith(" - "):
                    title = title[3:]
                while title.endswith(" - "):
                    title = title[:3]

                if vn.flags.get("og_s_title") or not title:
                    title = str(vn.flags.get("og_title") or "")

                for tag, hname in tagmap.items():
                    try:
                        assert file is not None  # type: ignore  # !rm
                        v = file["tags"][tag]
                        if not v:
                            continue
                        ogh[hname] = int(v) if tag == ".dur" else v
                    except (AssertionError, KeyError, ValueError, TypeError):
                        pass

                ogh["og:title"] = title

                oghs = [
                    '\t<meta property="%s" content="%s">'
                    % (k, html_escape(str(v), True, True))
                    for k, v in ogh.items()
                ]
                zs = self.html_head + "\n%s\n" % ("\n".join(oghs),)
                self.html_head = zs.replace("\n\n", "\n")

        html = self.j2s(tpl, **j2a)
        self.reply(html.encode("utf-8", "replace"))
        return True

    # --- API endpoint handlers (called by api.dispatch_api) ---

