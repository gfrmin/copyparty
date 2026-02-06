# coding: utf-8
from __future__ import annotations

import json
import os
import re
import stat
import time

from .bos import bos
from .util import (
    HAVE_SQLITE3,
    Pebkac,
    alltrace,
    gencookie,
    html_escape,
    html_sh_esc,
    humansize,
    json_hesc,
    loadpy,
    quotep,
    s2hms,
    str_anchor,
    vjoin,
    vroots,
    vsplit,
)

from .__init__ import ANYWIN
from .__version__ import S_VERSION

if True:  # pylint: disable=using-constant-test
    from typing import Any


class HttpCliControl(object):
    def tx_svcs(self) -> bool:
        aname = re.sub("[^0-9a-zA-Z]+", "", self.args.vname) or "a"
        ep = self.host
        sep = "]:" if "]" in ep else ":"
        if sep in ep:
            host, hport = ep.rsplit(":", 1)
            hport = ":" + hport
        else:
            host = ep
            hport = ""

        if host.endswith(".local") and self.args.zm and not self.args.rclone_mdns:
            rip = self.conn.hsrv.nm.map(self.ip) or host
            if ":" in rip and "[" not in rip:
                rip = "[%s]" % (rip,)
        else:
            rip = host

        defpw = "dave:hunter2" if self.args.usernames else "hunter2"

        vp = (self.uparam["hc"] or "").lstrip("/")
        pw = self.ouparam.get(self.args.pw_urlp) or defpw
        if pw in self.asrv.sesa:
            pw = defpw

        unpw = pw
        try:
            un, pw = unpw.split(":")
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            un = ""
            if self.args.usernames:
                un = "dave"

        html = self.j2s(
            "svcs",
            args=self.args,
            accs=bool(self.asrv.acct),
            s="s" if self.is_https else "",
            rip=html_sh_esc(rip),
            ep=html_sh_esc(ep),
            vp=html_sh_esc(vp),
            rvp=html_sh_esc(vjoin(self.args.R, vp)),
            host=html_sh_esc(host),
            hport=html_sh_esc(hport),
            aname=aname,
            b_un=("<b>%s</b>" % (html_sh_esc(un),)) if un else "k",
            un=html_sh_esc(un),
            pw=html_sh_esc(pw),
            unpw=html_sh_esc(unpw),
        )
        self.reply(html.encode("utf-8"))
        return True

    def tx_mounts(self) -> bool:
        suf = self.urlq({}, ["h"])
        rvol, wvol, avol = [
            [("/" + x).rstrip("/") + "/" for x in y]
            for y in [self.rvol, self.wvol, self.avol]
        ]
        for zs in self.asrv.vfs.all_fvols:
            if not zs:
                continue  # webroot
            zs2 = ("/" + zs).rstrip("/") + "/"
            for zsl in (rvol, wvol, avol):
                if zs2 in zsl:
                    zsl[zsl.index(zs2)] = zs2[:-1]

        ups = []
        now = time.time()
        get_vst = self.avol and not self.args.no_rescan
        get_ups = self.rvol and not self.args.no_up_list and self.uname or ""
        if get_vst or get_ups:
            x = self.conn.hsrv.broker.ask("up2k.get_state", get_vst, get_ups)
            vs = json.loads(x.get())
            vstate = {("/" + k).rstrip("/") + "/": v for k, v in vs["volstate"].items()}
            try:
                for rem, sz, t0, poke, vp in vs["ups"]:
                    fdone = max(0.001, 1 - rem)
                    td = max(0.1, now - t0)
                    rd, fn = vsplit(vp.replace(os.sep, "/"))
                    if rd:
                        rds = rd.replace("/", " / ")
                        erd = "/%s/" % (quotep(rd),)
                    else:
                        erd = rds = "/"
                    spd = humansize(sz * fdone / td, True) + "/s"
                    eta = s2hms((td / fdone) - td, True) if rem < 1 else "--"
                    idle = s2hms(now - poke, True)
                    ups.append((int(100 * fdone), spd, eta, idle, erd, rds, fn))
            except Exception as ex:
                self.log("failed to list upload progress: %r" % (ex,), 1)
        if not get_vst:
            vstate = {}
            vs = {
                "scanning": None,
                "hashq": None,
                "tagq": None,
                "mtpq": None,
                "dbwt": None,
            }

        assert vstate is not None and vstate.items and vs  # type: ignore  # !rm

        dls = dl_list = []
        if self.conn.hsrv.tdls:
            zi = self.args.dl_list
            if zi == 2 or (zi == 1 and self.avol):
                dl_list = self.get_dls()
        for t0, t1, sent, sz, vp, dl_id, uname in dl_list:
            td = max(0.1, now - t0)
            rd, fn = vsplit(vp)
            if rd:
                rds = rd.replace("/", " / ")
                erd = "/%s/" % (quotep(rd),)
            else:
                erd = rds = "/"
            spd = humansize(sent / td, True) + "/s"
            hsent = humansize(sent, True)
            idle = s2hms(now - t1, True)
            usr = "%s @%s" % (dl_id, uname) if dl_id else uname
            if sz and sent and td:
                eta = s2hms((sz - sent) / (sent / td), True)
                perc = int(100 * sent / sz)
            else:
                eta = perc = "--"

            fn = html_escape(fn) if fn else self.conn.hsrv.iiam
            dls.append((perc, hsent, spd, eta, idle, usr, erd, rds, fn))

        if self.args.have_unlistc:
            allvols = self.asrv.vfs.all_nodes
            rvol = [x for x in rvol if "unlistcr" not in allvols[x.strip("/")].flags]
            wvol = [x for x in wvol if "unlistcw" not in allvols[x.strip("/")].flags]

        fmt = self.uparam.get("ls", "")
        if not fmt and self.ua.startswith(("curl/", "fetch")):
            fmt = "v"

        if fmt in ["v", "t", "txt"]:
            if self.uname == "*":
                txt = "howdy stranger (you're not logged in)"
            else:
                txt = "welcome back {}".format(self.uname)

            if vstate:
                txt += "\nstatus:"
                for k in ["scanning", "hashq", "tagq", "mtpq", "dbwt"]:
                    txt += " {}({})".format(k, vs[k])

            if ups:
                txt += "\n\nincoming files:"
                for zt in ups:
                    txt += "\n%s" % (", ".join((str(x) for x in zt)),)
                txt += "\n"

            if dls:
                txt += "\n\nactive downloads:"
                for zt in dls:
                    txt += "\n%s" % (", ".join((str(x) for x in zt)),)
                txt += "\n"

            if rvol:
                txt += "\nyou can browse:"
                for v in rvol:
                    txt += "\n  " + v

            if wvol:
                txt += "\nyou can upload to:"
                for v in wvol:
                    txt += "\n  " + v

            zb = txt.encode("utf-8", "replace") + b"\n"
            self.reply(zb, mime="text/plain; charset=utf-8")
            return True

        re_btn = ""
        nre = self.args.ctl_re
        if "re" in self.uparam:
            self.out_headers["Refresh"] = str(nre)
        elif nre:
            re_btn = "&re=%s" % (nre,)

        zi = self.args.ver_iwho
        show_ver = zi and (
            zi == 9 or (zi == 6 and self.uname != "*") or (zi == 3 and avol)
        )

        html = self.j2s(
            "splash",
            this=self,
            qvpath=quotep(self.vpaths) + self.ourlq(),
            rvol=rvol,
            wvol=wvol,
            avol=avol,
            in_shr=self.args.shr and self.vpath.startswith(self.args.shr1),
            vstate=vstate,
            dls=dls,
            ups=ups,
            scanning=vs["scanning"],
            hashq=vs["hashq"],
            tagq=vs["tagq"],
            mtpq=vs["mtpq"],
            dbwt=vs["dbwt"],
            url_suf=suf,
            re=re_btn,
            k304=self.k304(),
            no304=self.no304(),
            k304vis=self.args.k304 > 0,
            no304vis=self.args.no304 > 0,
            msg=BADXFFB if hasattr(self, "bad_xff") else "",
            ver=S_VERSION if show_ver else "",
            chpw=self.args.chpw and self.uname != "*",
            ahttps="" if self.is_https else "https://" + self.host + self.req,
        )
        self.reply(html.encode("utf-8"))
        return True

    def setck(self) -> bool:
        k, v = self.uparam["setck"].split("=", 1)
        t = 0 if v in ("", "x") else 86400 * 299
        ck = gencookie(k, v, self.args.R, True, False, t)
        self.out_headerlist.append(("Set-Cookie", ck))
        if "cc" in self.ouparam:
            self.redirect("", "?h#cc")
        else:
            self.reply(b"o7\n")
        return True

    def set_cfg_reset(self) -> bool:
        for k in ALL_COOKIES:
            if k not in self.cookies:
                continue
            cookie = gencookie(k, "x", self.args.R, True, False)
            self.out_headerlist.append(("Set-Cookie", cookie))

        self.redirect("", "?h#cc")
        return True

    def tx_404(self, is_403: bool = False) -> bool:
        rc = 404
        if self.args.vague_403:
            t = '<h1 id="n">404 not found &nbsp;┐( ´ -`)┌</h1><p id="o">or maybe you don\'t have access -- try a password or <a href="{}/?h">go home</a></p>'
            pt = "404 not found  ┐( ´ -`)┌   (or maybe you don't have access -- try a password)"
        elif is_403:
            t = '<h1 id="p">403 forbiddena &nbsp;~┻━┻</h1><p id="q">use a password or <a href="{}/?h">go home</a></p>'
            pt = "403 forbiddena ~┻━┻   (you'll have to log in)"
            rc = 403
        else:
            t = '<h1 id="n">404 not found &nbsp;┐( ´ -`)┌</h1><p><a id="r" href="{}/?h">go home</a></p>'
            pt = "404 not found  ┐( ´ -`)┌"

        if self.ua.startswith(("curl/", "fetch")):
            pt = "# acct: %s\n%s\n" % (self.uname, pt)
            self.reply(pt.encode("utf-8"), status=rc)
            return True

        if "th" in self.ouparam and str(self.ouparam["th"])[:1] in "jw":
            return self.tx_svg("e" + pt[:3])

        # most webdav clients will not send credentials until they
        # get 401'd, so send a challenge if we're Absolutely Sure
        # that the client is not a graphical browser
        if rc == 403 and self.uname == "*":
            sport = self.s.getsockname()[1]
            if self.args.dav_port == sport or (
                "sec-fetch-site" not in self.headers
                and self.cookies.get("js") != "y"
                and sport not in self.args.p_nodav
                and (
                    not self.args.ua_nodav.search(self.ua)
                    or (self.args.dav_ua1 and self.args.dav_ua1.search(self.ua))
                )
            ):
                rc = 401
                self.out_headers["WWW-Authenticate"] = 'Basic realm="a"'

        t = t.format(self.args.SR)
        qv = quotep(self.vpaths) + self.ourlq()
        html = self.j2s(
            "splash",
            this=self,
            qvpath=qv,
            msg=t,
            in_shr=self.args.shr and self.vpath.startswith(self.args.shr1),
            ahttps="" if self.is_https else "https://" + self.host + self.req,
        )
        self.reply(html.encode("utf-8"), status=rc)
        return True

    def on40x(self, mods: list[str], vn: VFS, rem: str) -> str:
        for mpath in mods:
            try:
                mod = loadpy(mpath, self.args.hot_handlers)
            except Exception as ex:
                self.log("import failed: {!r}".format(ex))
                continue

            ret = mod.main(self, vn, rem)
            if ret:
                return ret.lower()

        return ""  # unhandled / fallthrough

    def scanvol(self) -> bool:
        if self.args.no_rescan:
            raise Pebkac(403, "the rescan feature is disabled in server config")

        vpaths = self.uparam["scan"].split(",/")
        if vpaths == [""]:
            vpaths = [self.vpath]

        vols = []
        for vpath in vpaths:
            vn, _ = self.asrv.vfs.get(vpath, self.uname, True, True)
            vols.append(vn.vpath)
            if self.uname not in vn.axs.uadmin:
                self.log("rejected scanning [%s] => [%s];" % (vpath, vn.vpath), 3)
                raise Pebkac(403, "'scanvol' not allowed for user " + self.uname)

        self.log("trying to rescan %d volumes: %r" % (len(vols), vols))

        args = [self.asrv.vfs.all_vols, vols, False, True]

        x = self.conn.hsrv.broker.ask("up2k.rescan", *args)
        err = x.get()
        if not err:
            self.redirect("", "?h")
            return True

        raise Pebkac(500, err)

    def handle_reload(self) -> bool:
        act = self.uparam.get("reload")
        if act != "cfg":
            raise Pebkac(400, "only config files ('cfg') can be reloaded rn")

        if not self.avol:
            raise Pebkac(403, "'reload' not allowed for user " + self.uname)

        if self.args.no_reload:
            raise Pebkac(403, "the reload feature is disabled in server config")

        x = self.conn.hsrv.broker.ask("reload", True, True)
        return self.redirect("", "?h", x.get(), "return to", False)

    def tx_stack(self) -> bool:
        zs = self.args.stack_who
        if zs == "all" or (
            (zs == "a" and self.avol)
            or (zs == "rw" and [x for x in self.wvol if x in self.rvol])
        ):
            pass
        else:
            raise Pebkac(403, "'stack' not allowed for user " + self.uname)

        ret = html_escape(alltrace(self.args.stack_v))
        if self.args.stack_v:
            ret = "<pre>%s\n%s" % (time.time(), ret)
        else:
            ret = "<pre>%s" % (ret,)
        self.reply(ret.encode("utf-8"))
        return True

    def get_dls(self) -> list[list[Any]]:
        ret = []
        dls = self.conn.hsrv.tdls
        enshare = self.args.shr
        shrs = enshare[1:]
        for dl_id, (t0, sz, vn, vp, uname) in self.conn.hsrv.tdli.items():
            t1, sent = dls[dl_id]
            if sent > 0x100000:  # 1m; buffers 2~4
                sent -= 0x100000
            if self.uname not in vn.axs.uread:
                vp = ""
            elif self.uname not in vn.axs.udot and (vp.startswith(".") or "/." in vp):
                vp = ""
            elif (
                enshare
                and vp.startswith(shrs)
                and self.uname != vn.shr_owner
                and self.uname not in vn.axs.uadmin
                and self.uname not in self.args.shr_adm
                and not dl_id.startswith(self.ip + ":")
            ):
                vp = ""
            if self.uname not in vn.axs.uadmin:
                dl_id = uname = ""

            ret.append([t0, t1, sent, sz, vp, dl_id, uname])
        return ret

    def tx_dls(self) -> bool:
        ret = [
            {
                "t0": x[0],
                "t1": x[1],
                "sent": x[2],
                "size": x[3],
                "path": x[4],
                "conn": x[5],
                "uname": x[6],
            }
            for x in self.get_dls()
        ]
        zs = json.dumps(ret, separators=(",\n", ": "))
        self.reply(zs.encode("utf-8", "replace"), mime="application/json")
        return True

    def tx_ups(self) -> bool:
        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; unpost is disabled")
            raise Pebkac(500, "server busy, cannot unpost; please retry in a bit")

        sfilt = self.uparam.get("filter") or ""
        nfi, vfi = str_anchor(sfilt)
        lm = "ups %d%r" % (nfi, sfilt)

        if self.args.shr and self.vpath.startswith(self.args.shr1):
            shr_dbv, shr_vrem = self.vn.get_dbv(self.rem)
        else:
            shr_dbv = None

        wret: dict[str, Any] = {}
        ret: list[dict[str, Any]] = []
        t0 = time.time()
        lim = time.time() - self.args.unpost
        fk_vols = {
            vol: (vol.flags["fk"], 2 if "fka" in vol.flags else 1)
            for vp, vol in self.asrv.vfs.all_vols.items()
            if "fk" in vol.flags
            and (self.uname in vol.axs.uread or self.uname in vol.axs.upget)
        }

        if hasattr(self, "bad_xff"):
            allvols = []
            t = "will not return list of recent uploads" + BADXFF
            self.log(t, 1)
            if self.avol:
                raise Pebkac(500, t)

            x = self.conn.hsrv.broker.ask("up2k.get_unfinished_by_user", self.uname, "")
        else:
            x = self.conn.hsrv.broker.ask(
                "up2k.get_unfinished_by_user", self.uname, self.ip
            )
        zdsa: dict[str, Any] = x.get()
        uret: list[dict[str, Any]] = []
        if "timeout" in zdsa:
            wret["nou"] = 1
        else:
            uret = zdsa["f"]
        nu = len(uret)

        if not self.args.unpost:
            allvols = []
        else:
            allvols = list(self.asrv.vfs.all_vols.values())

        allvols = [
            x
            for x in allvols
            if "e2d" in x.flags
            and ("*" in x.axs.uwrite or self.uname in x.axs.uwrite or x == shr_dbv)
        ]

        q = ""
        qp = (0,)
        q_c = -1

        for vol in allvols:
            cur = idx.get_cur(vol)
            if not cur:
                continue

            nfk, fk_alg = fk_vols.get(vol) or (0, 0)

            zi = vol.flags["unp_who"]
            if q_c != zi:
                q_c = zi
                q = "select sz, rd, fn, at from up where "
                if zi == 1:
                    q += "ip=? and un=?"
                    qp = (self.ip, self.uname, lim)
                elif zi == 2:
                    q += "ip=?"
                    qp = (self.ip, lim)
                if zi == 3:
                    q += "un=?"
                    qp = (self.uname, lim)
                q += " and at>? order by at desc"

            n = 2000
            for sz, rd, fn, at in cur.execute(q, qp):
                vp = "/" + "/".join(x for x in [vol.vpath, rd, fn] if x)
                if nfi == 0 or (nfi == 1 and vfi in vp.lower()):
                    pass
                elif nfi == 2:
                    if not vp.lower().startswith(vfi):
                        continue
                elif nfi == 3:
                    if not vp.lower().endswith(vfi):
                        continue
                else:
                    continue

                n -= 1
                if not n:
                    break

                rv = {"vp": vp, "sz": sz, "at": at, "nfk": nfk}
                if nfk:
                    rv["ap"] = vol.canonical(vjoin(rd, fn))
                    rv["fk_alg"] = fk_alg

                ret.append(rv)
                if len(ret) > 3000:
                    ret.sort(key=lambda x: x["at"], reverse=True)  # type: ignore
                    ret = ret[:2000]

        ret.sort(key=lambda x: x["at"], reverse=True)  # type: ignore

        if len(ret) > 2000:
            ret = ret[:2000]
        if len(ret) >= 2000:
            wret["oc"] = 1

        for rv in ret:
            rv["vp"] = quotep(rv["vp"])
            nfk = rv.pop("nfk")
            if not nfk:
                continue

            alg = rv.pop("fk_alg")
            ap = rv.pop("ap")
            try:
                st = bos.stat(ap)
            except OSError:
                continue

            fk = self.gen_fk(
                alg, self.args.fk_salt, ap, st.st_size, 0 if ANYWIN else st.st_ino
            )
            rv["vp"] += "?k=" + fk[:nfk]

        if not allvols:
            wret["noc"] = 1
            ret = []

        nc = len(ret)
        ret = uret + ret

        if shr_dbv:
            # translate vpaths from share-target to share-url
            # to satisfy access checks
            assert shr_vrem is not None and shr_vrem.split  # type: ignore  # !rm
            vp_shr, vp_vfs = vroots(self.vpath, vjoin(shr_dbv.vpath, shr_vrem))
            for v in ret:
                vp = v["vp"]
                if vp.startswith(vp_vfs):
                    v["vp"] = vp_shr + vp[len(vp_vfs) :]

        if self.is_vproxied:
            for v in ret:
                v["vp"] = self.args.SR + v["vp"]

        wret["f"] = ret
        wret["nu"] = nu
        wret["nc"] = nc
        jtxt = json.dumps(wret, separators=(",\n", ": "))
        self.log("%s #%d+%d %.2fsec" % (lm, nu, nc, time.time() - t0))
        self.reply(jtxt.encode("utf-8", "replace"), mime="application/json")
        return True

    def tx_rups(self) -> bool:
        if self.args.no_ups_page:
            raise Pebkac(500, "listing of recent uploads is disabled in server config")

        idx = self.conn.get_u2idx()
        if not idx or not hasattr(idx, "p_end"):
            if not HAVE_SQLITE3:
                raise Pebkac(500, "sqlite3 not found on server; recent-uploads n/a")
            raise Pebkac(500, "server busy, cannot list recent uploads; please retry")

        sfilt = self.uparam.get("filter") or ""
        nfi, vfi = str_anchor(sfilt)
        lm = "ru %d%r" % (nfi, sfilt)
        self.log(lm)

        ret: list[dict[str, Any]] = []
        t0 = time.time()
        allvols = [
            x
            for x in self.asrv.vfs.all_vols.values()
            if "e2d" in x.flags and ("*" in x.axs.uread or self.uname in x.axs.uread)
        ]
        fk_vols = {
            vol: (vol.flags["fk"], 2 if "fka" in vol.flags else 1)
            for vol in allvols
            if "fk" in vol.flags and "*" not in vol.axs.uread
        }

        for vol in allvols:
            cur = idx.get_cur(vol)
            if not cur:
                continue

            nfk, fk_alg = fk_vols.get(vol) or (0, 0)
            adm = "*" in vol.axs.uadmin or self.uname in vol.axs.uadmin
            dots = "*" in vol.axs.udot or self.uname in vol.axs.udot

            lvl = vol.flags["ups_who"]
            if not lvl:
                continue
            elif lvl == 1 and not adm:
                continue

            n = 1000
            q = "select sz, rd, fn, ip, at, un from up where at>0 order by at desc"
            for sz, rd, fn, ip, at, un in cur.execute(q):
                vp = "/" + "/".join(x for x in [vol.vpath, rd, fn] if x)
                if nfi == 0 or (nfi == 1 and vfi in vp.lower()):
                    pass
                elif nfi == 2:
                    if not vp.lower().startswith(vfi):
                        continue
                elif nfi == 3:
                    if not vp.lower().endswith(vfi):
                        continue
                else:
                    continue

                if not dots and "/." in vp:
                    continue

                rv = {
                    "vp": vp,
                    "sz": sz,
                    "ip": ip,
                    "at": at,
                    "un": un,
                    "nfk": nfk,
                    "adm": adm,
                }
                if nfk:
                    rv["ap"] = vol.canonical(vjoin(rd, fn))
                    rv["fk_alg"] = fk_alg

                ret.append(rv)
                if len(ret) > 2000:
                    ret.sort(key=lambda x: x["at"], reverse=True)  # type: ignore
                    ret = ret[:1000]

                n -= 1
                if not n:
                    break

        ret.sort(key=lambda x: x["at"], reverse=True)  # type: ignore

        if len(ret) > 1000:
            ret = ret[:1000]

        for rv in ret:
            rv["vp"] = quotep(rv["vp"])
            nfk = rv.pop("nfk")
            if not nfk:
                continue

            alg = rv.pop("fk_alg")
            ap = rv.pop("ap")
            try:
                st = bos.stat(ap)
            except OSError:
                continue

            fk = self.gen_fk(
                alg, self.args.fk_salt, ap, st.st_size, 0 if ANYWIN else st.st_ino
            )
            rv["vp"] += "?k=" + fk[:nfk]

        if self.args.ups_when:
            for rv in ret:
                adm = rv.pop("adm")
                if not adm:
                    rv["ip"] = "(You)" if rv["ip"] == self.ip else "(?)"
                    if rv["un"] not in ("*", self.uname):
                        rv["un"] = "(?)"
        else:
            for rv in ret:
                adm = rv.pop("adm")
                if not adm:
                    rv["ip"] = "(You)" if rv["ip"] == self.ip else "(?)"
                    rv["at"] = 0
                    if rv["un"] not in ("*", self.uname):
                        rv["un"] = "(?)"

        if self.is_vproxied:
            for v in ret:
                v["vp"] = self.args.SR + v["vp"]

        now = time.time()
        self.log("%s #%d %.2fsec" % (lm, len(ret), now - t0))

        ret2 = {"now": int(now), "filter": sfilt, "ups": ret}
        jtxt = json.dumps(ret2, separators=(",\n", ": "))
        if "j" in self.ouparam:
            self.reply(jtxt.encode("utf-8", "replace"), mime="application/json")
            return True

        html = self.j2s("rups", this=self, v=json_hesc(jtxt))
        self.reply(html.encode("utf-8"), status=200)
        return True

    def tx_idp(self) -> bool:
        if self.uname.lower() not in self.args.idp_adm_set:
            raise Pebkac(403, "'idp' not allowed for user " + self.uname)

        cmd = self.uparam["idp"]
        if cmd.startswith("rm="):
            import sqlite3

            db = sqlite3.connect(self.args.idp_db)
            db.execute("delete from us where un=?", (cmd[3:],))
            db.commit()
            db.close()

            self.conn.hsrv.broker.ask("reload", False, True).get()

            self.redirect("", "?idp")
            return True

        rows = [
            [k, "[%s]" % ("], [".join(v))]
            for k, v in sorted(self.asrv.idp_accs.items())
        ]
        html = self.j2s("idp", this=self, rows=rows, now=int(time.time()))
        self.reply(html.encode("utf-8"), status=200)
        return True

    def api_mounts(self):
        """GET /api/mounts - list accessible volumes."""
        return {"volumes": [{"path": vp} for vp in sorted(self.rvol)]}

    def api_config(self):
        """GET /api/config - client configuration."""
        from .__version__ import S_VERSION

        return {
            "version": S_VERSION,
            "name": self.args.name or self.args.bname or "",
        }

    def api_status(self):
        """GET /api/status - server health."""
        from .__version__ import S_VERSION

        return {
            "version": S_VERSION,
            "uptime": time.time() - self.E.t0,
            "ok": True,
        }
