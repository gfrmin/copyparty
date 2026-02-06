# coding: utf-8
from __future__ import annotations

import errno
import hashlib
import itertools
import json
import os
import stat
import time

from .bos import bos
from .util import (
    MultipartParser,
    Pebkac,
    WrongPostKey,
    afsenc,
    atomic_move,
    eol_conv,
    fsenc,
    gzip,
    hashcopy,
    hidedir,
    html_escape,
    humansize,
    justcopy,
    log_reloc,
    min_ex,
    pathmod,
    quotep,
    rand_name,
    read_socket,
    read_socket_chunked,
    read_socket_unbounded,
    ren_open,
    runhook,
    sanitize_fn,
    set_fperms,
    ub64enc,
    unquotep,
    vjoin,
    vol_san,
    vsplit,
    wunlink,
)

from .__init__ import ANYWIN, unicode

try:
    if os.environ.get("PRTY_NO_LZMA"):
        raise Exception()

    import lzma
except ImportError:
    pass

if True:  # pylint: disable=using-constant-test
    from typing import Any, Generator, Optional


class HttpCliUpload(object):
    def get_body_reader(self) -> tuple[Generator[bytes, None, None], int]:
        bufsz = self.args.s_rd_sz
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            return read_socket_chunked(self.sr, bufsz), -1

        remains = int(self.headers.get("content-length", -1))
        if remains == -1:
            self.keepalive = False
            self.in_hdr_recv = True
            self.s.settimeout(max(self.args.s_tbody // 20, 1))
            return read_socket_unbounded(self.sr, bufsz), remains
        else:
            return read_socket(self.sr, bufsz, remains), remains

    def dump_to_file(self, is_put: bool) -> tuple[int, str, str, str, int, str, str]:
        # post_sz, halg, sha_hex, sha_b64, remains, path, url
        reader, remains = self.get_body_reader()
        vfs, rem = self.asrv.vfs.get(self.vpath, self.uname, False, True)
        rnd, lifetime, xbu, xau = self.upload_flags(vfs)
        lim = vfs.get_dbv(rem)[0].lim
        fdir = vfs.canonical(rem)
        fn = None
        if rem and not self.trailing_slash and not bos.path.isdir(fdir):
            fdir, fn = os.path.split(fdir)
            rem, _ = vsplit(rem)

        if lim:
            fdir, rem = lim.all(
                self.ip, rem, remains, vfs.realpath, fdir, self.conn.hsrv.broker
            )

        bos.makedirs(fdir, vf=vfs.flags)

        open_ka: dict[str, Any] = {"fun": open}
        open_a = ["wb", self.args.iobuf]

        # user-request || config-force
        if ("gz" in vfs.flags or "xz" in vfs.flags) and (
            "pk" in vfs.flags
            or "pk" in self.uparam
            or "gz" in self.uparam
            or "xz" in self.uparam
        ):
            fb = {"gz": 9, "xz": 0}  # default/fallback level
            lv = {}  # selected level
            alg = ""  # selected algo (gz=preferred)

            # user-prefs first
            if "gz" in self.uparam or "pk" in self.uparam:  # def.pk
                alg = "gz"
            if "xz" in self.uparam:
                alg = "xz"
            if alg:
                zso = self.uparam.get(alg)
                lv[alg] = fb[alg] if zso is None else int(zso)

            if alg not in vfs.flags:
                alg = "gz" if "gz" in vfs.flags else "xz"

            # then server overrides
            pk = vfs.flags.get("pk")
            if pk is not None:
                # config-forced on
                alg = alg or "gz"  # def.pk
                try:
                    # config-forced opts
                    alg, nlv = pk.split(",")
                    lv[alg] = int(nlv)
                except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                    pass

            lv[alg] = lv.get(alg) or fb.get(alg) or 0

            self.log("compressing with {} level {}".format(alg, lv.get(alg)))
            if alg == "gz":
                open_ka["fun"] = gzip.GzipFile
                open_a = ["wb", lv[alg], None, 0x5FEE6600]  # 2021-01-01
            elif alg == "xz":
                assert lzma  # type: ignore  # !rm
                open_ka = {"fun": lzma.open, "preset": lv[alg]}
                open_a = ["wb"]
            else:
                self.log("fallthrough? thats a bug", 1)

        suffix = "-{:.6f}-{}".format(time.time(), self.dip())
        nameless = not fn
        if nameless:
            fn = vfs.flags["put_name2"].format(now=time.time(), cip=self.dip())

        params = {"suffix": suffix, "fdir": fdir, "vf": vfs.flags}
        if self.args.nw:
            params = {}
            fn = os.devnull

        params.update(open_ka)
        assert fn  # !rm

        if not self.args.nw:
            if rnd:
                fn = rand_name(fdir, fn, rnd)

            fn = sanitize_fn(fn or "")

        path = os.path.join(fdir, fn)

        if xbu:
            at = time.time() - lifetime
            vp = vjoin(self.vpath, fn) if nameless else self.vpath
            hr = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xbu.http.dump",
                xbu,
                path,
                vp,
                self.host,
                self.uname,
                self.asrv.vfs.get_perms(self.vpath, self.uname),
                at,
                remains,
                self.ip,
                at,
                None,
            )
            t = hr.get("rejectmsg") or ""
            if t or hr.get("rc") != 0:
                if not t:
                    t = "upload blocked by xbu server config: %r" % (vp,)
                self.log(t, 1)
                raise Pebkac(403, t)
            if hr.get("reloc"):
                x = pathmod(self.asrv.vfs, path, vp, hr["reloc"])
                if x:
                    if self.args.hook_v:
                        log_reloc(self.log, hr["reloc"], x, path, vp, fn, vfs, rem)
                    fdir, self.vpath, fn, (vfs, rem) = x
                    if self.args.nw:
                        fn = os.devnull
                    else:
                        bos.makedirs(fdir, vf=vfs.flags)
                        path = os.path.join(fdir, fn)
                        if not nameless:
                            self.vpath = vjoin(self.vpath, fn)
                        params["fdir"] = fdir

        if (
            is_put
            and not (self.args.no_dav or self.args.nw)
            and "append" not in self.uparam
            and bos.path.exists(path)
        ):
            # allow overwrite if...
            #  * volflag 'daw' is set, or client is definitely webdav
            #  * and account has delete-access
            # or...
            #  * file exists, is empty, sufficiently new
            #  * and there is no .PARTIAL

            tnam = fn + ".PARTIAL"
            if self.args.dotpart:
                tnam = "." + tnam

            if (
                self.can_delete
                and (
                    vfs.flags.get("daw")
                    or "replace" in self.headers
                    or "x-oc-mtime" in self.headers
                )
            ) or (
                not bos.path.exists(os.path.join(fdir, tnam))
                and not bos.path.getsize(path)
                and bos.path.getmtime(path) >= time.time() - self.args.blank_wt
            ):
                # small toctou, but better than clobbering a hardlink
                wunlink(self.log, path, vfs.flags)

        hasher = None
        copier = hashcopy
        halg = self.ouparam.get("ck") or self.headers.get("ck") or vfs.flags["put_ck"]
        if halg == "sha512":
            pass
        elif halg == "no":
            copier = justcopy
            halg = ""
        elif halg == "md5":
            hasher = hashlib.md5(**USED4SEC)
        elif halg == "sha1":
            hasher = hashlib.sha1(**USED4SEC)
        elif halg == "sha256":
            hasher = hashlib.sha256(**USED4SEC)
        elif halg in ("blake2", "b2"):
            hasher = hashlib.blake2b(**USED4SEC)
        elif halg in ("blake2s", "b2s"):
            hasher = hashlib.blake2s(**USED4SEC)
        else:
            raise Pebkac(500, "unknown hash alg")

        if "apnd" in self.uparam and not self.args.nw and bos.path.exists(path):
            zs = vfs.flags["apnd_who"]
            if (
                zs == "w"
                or (zs == "aw" and self.can_admin)
                or (zs == "dw" and self.can_delete)
            ):
                pass
            elif zs == "ndd":
                raise Pebkac(400, "append is denied here due to non-reflink dedup")
            else:
                raise Pebkac(400, "you do not have permission to append")
            zs = os.path.join(params["fdir"], fn)
            self.log("upload will append to [%s]" % (zs,))
            f = open(zs, "ab")
        else:
            f, fn = ren_open(fn, *open_a, **params)

        try:
            path = os.path.join(fdir, fn)
            post_sz, sha_hex, sha_b64 = copier(reader, f, hasher, 0, self.args.s_wr_slp)
        finally:
            f.close()

        if lim:
            lim.nup(self.ip)
            lim.bup(self.ip, post_sz)
            try:
                lim.chk_sz(post_sz)
                lim.chk_vsz(self.conn.hsrv.broker, vfs.realpath, post_sz)
            except Exception:
                wunlink(self.log, path, vfs.flags)
                raise

        if self.args.nw:
            return post_sz, halg, sha_hex, sha_b64, remains, path, ""

        at = mt = time.time() - lifetime
        cli_mt = self.headers.get("x-oc-mtime")
        if cli_mt:
            bos.utime_c(self.log, path, float(cli_mt), False)

        if nameless and "magic" in vfs.flags:
            try:
                ext = self.conn.hsrv.magician.ext(path)
            except Exception as ex:
                self.log("filetype detection failed for %r: %s" % (path, ex), 6)
                ext = None

            if ext:
                if rnd:
                    fn2 = rand_name(fdir, "a." + ext, rnd)
                else:
                    fn2 = fn.rsplit(".", 1)[0] + "." + ext

                params["suffix"] = suffix[:-4]
                f, fn2 = ren_open(fn2, *open_a, **params)
                f.close()

                path2 = os.path.join(fdir, fn2)
                atomic_move(self.log, path, path2, vfs.flags)
                fn = fn2
                path = path2

        if xau:
            vp = vjoin(self.vpath, fn) if nameless else self.vpath
            hr = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xau.http.dump",
                xau,
                path,
                vp,
                self.host,
                self.uname,
                self.asrv.vfs.get_perms(self.vpath, self.uname),
                mt,
                post_sz,
                self.ip,
                at,
                None,
            )
            t = hr.get("rejectmsg") or ""
            if t or hr.get("rc") != 0:
                if not t:
                    t = "upload blocked by xau server config: %r" % (vp,)
                self.log(t, 1)
                wunlink(self.log, path, vfs.flags)
                raise Pebkac(403, t)
            if hr.get("reloc"):
                x = pathmod(self.asrv.vfs, path, vp, hr["reloc"])
                if x:
                    if self.args.hook_v:
                        log_reloc(self.log, hr["reloc"], x, path, vp, fn, vfs, rem)
                    fdir, self.vpath, fn, (vfs, rem) = x
                    bos.makedirs(fdir, vf=vfs.flags)
                    path2 = os.path.join(fdir, fn)
                    atomic_move(self.log, path, path2, vfs.flags)
                    path = path2
                    if not nameless:
                        self.vpath = vjoin(self.vpath, fn)
            sz = bos.path.getsize(path)
        else:
            sz = post_sz

        vfs, rem = vfs.get_dbv(rem)
        self.conn.hsrv.broker.say(
            "up2k.hash_file",
            vfs.realpath,
            vfs.vpath,
            vfs.flags,
            rem,
            fn,
            self.ip,
            at,
            self.uname,
            True,
        )

        vsuf = ""
        if (self.can_read or self.can_upget) and "fk" in vfs.flags:
            alg = 2 if "fka" in vfs.flags else 1
            vsuf = "?k=" + self.gen_fk(
                alg,
                self.args.fk_salt,
                path,
                sz,
                0 if ANYWIN else bos.stat(path).st_ino,
            )[: vfs.flags["fk"]]

        if "media" in self.uparam or "medialinks" in vfs.flags:
            vsuf += "&v" if vsuf else "?v"

        vpath = "/".join([x for x in [vfs.vpath, rem, fn] if x])
        vpath = quotep(vpath)

        if self.args.up_site:
            url = "%s%s%s" % (
                self.args.up_site,
                vpath,
                vsuf,
            )
        else:
            url = "%s://%s/%s%s%s" % (
                "https" if self.is_https else "http",
                self.host,
                self.args.RS,
                vpath,
                vsuf,
            )

        return post_sz, halg, sha_hex, sha_b64, remains, path, url

    def handle_stash(self, is_put: bool) -> bool:
        post_sz, halg, sha_hex, sha_b64, remains, path, url = self.dump_to_file(is_put)
        spd = self._spd(post_sz)
        t = "%s wrote %d/%d bytes to %r  # %s"
        self.log(t % (spd, post_sz, remains, path, sha_b64[:28]))  # 21

        mime = "text/plain; charset=utf-8"
        ac = self.uparam.get("want") or self.headers.get("accept") or ""
        if ac:
            ac = ac.split(";", 1)[0].lower()
            if ac == "application/json":
                ac = "json"
        if ac == "url":
            t = url
        elif ac == "json" or "j" in self.uparam:
            jmsg = {"fileurl": url, "filesz": post_sz}
            if halg:
                jmsg[halg] = sha_hex[:56]
                jmsg["sha_b64"] = sha_b64

            mime = "application/json"
            t = json.dumps(jmsg, indent=2, sort_keys=True)
        else:
            t = "{}\n{}\n{}\n{}\n".format(post_sz, sha_b64, sha_hex[:56], url)

        h = {"Location": url} if is_put and url else {}

        if "x-oc-mtime" in self.headers:
            h["X-OC-MTime"] = "accepted"
            t = ""  # some webdav clients expect/prefer this

        self.reply(t.encode("utf-8", "replace"), 201, mime=mime, headers=h)
        return True

    def bakflip(
        self,
        f: typing.BinaryIO,
        ap: str,
        ofs: int,
        sz: int,
        good_sha: str,
        bad_sha: str,
        flags: dict[str, Any],
    ) -> None:
        now = time.time()
        t = "bad-chunk:  %.3f  %s  %s  %d  %s  %s  %r"
        t = t % (now, bad_sha, good_sha, ofs, self.ip, self.uname, ap)
        self.log(t, 5)

        if self.args.bf_log:
            try:
                with open(self.args.bf_log, "ab+") as f2:
                    f2.write((t + "\n").encode("utf-8", "replace"))
            except Exception as ex:
                self.log("append %s failed: %r" % (self.args.bf_log, ex))

        if not self.args.bak_flips or self.args.nw:
            return

        sdir = self.args.bf_dir
        fp = os.path.join(sdir, bad_sha)
        if bos.path.exists(fp):
            return self.log("no bakflip; have it", 6)

        if not bos.path.isdir(sdir):
            bos.makedirs(sdir)

        if len(bos.listdir(sdir)) >= self.args.bf_nc:
            return self.log("no bakflip; too many", 3)

        nrem = sz
        f.seek(ofs)
        with open(fp, "wb") as fo:
            while nrem:
                buf = f.read(min(nrem, self.args.iobuf))
                if not buf:
                    break

                nrem -= len(buf)
                fo.write(buf)

        if nrem:
            self.log("bakflip truncated; {} remains".format(nrem), 1)
            atomic_move(self.log, fp, fp + ".trunc", flags)
        else:
            self.log("bakflip ok", 2)

    def handle_post_multipart(self) -> bool:
        self.parser = MultipartParser(self.log, self.args, self.sr, self.headers)
        self.parser.parse()

        file0: list[tuple[str, Optional[str], Generator[bytes, None, None]]] = []
        try:
            act = self.parser.require("act", 64)
        except WrongPostKey as ex:
            if ex.got == "f" and ex.fname:
                self.log("missing 'act', but looks like an upload so assuming that")
                file0 = [(ex.got, ex.fname, ex.datagen)]
                act = "bput"
            else:
                raise

        if act == "login":
            return self.handle_login()

        if act == "mkdir":
            return self.handle_mkdir()

        if act == "new_md":
            # kinda silly but has the least side effects
            return self.handle_new_md()

        if act in ("bput", "uput"):
            return self.handle_plain_upload(file0, act == "uput")

        if act == "tput":
            return self.handle_text_upload()

        if act == "zip":
            return self.handle_zip_post()

        if act == "chpw":
            return self.handle_chpw()

        if act == "logout":
            return self.handle_logout()

        raise Pebkac(422, "invalid action %r" % (act,))

    def handle_zip_post(self) -> bool:
        assert self.parser  # !rm
        try:
            k = next(x for x in self.uparam if x in ("zip", "tar"))
        except StopIteration:
            raise Pebkac(422, "need zip or tar keyword")

        v = self.uparam[k]

        if self._use_dirkey(self.vn, ""):
            vn = self.vn
            rem = self.rem
        else:
            vn, rem = self.asrv.vfs.get(self.vpath, self.uname, True, False)

        zs = self.parser.require("files", 1024 * 1024)
        if not zs:
            raise Pebkac(422, "need files list")

        items = zs.replace("\r", "").split("\n")
        items = [unquotep(x) for x in items if items]

        self.parser.drop()
        return self.tx_zip(k, v, "", vn, rem, items)

    def handle_post_binary(self) -> bool:
        try:
            postsize = remains = int(self.headers["content-length"])
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(400, "you must supply a content-length for binary POST")

        try:
            chashes = self.headers["x-up2k-hash"].split(",")
            wark = self.headers["x-up2k-wark"]
        except KeyError:
            raise Pebkac(400, "need hash and wark headers for binary POST")

        chashes = [x.strip() for x in chashes]
        if len(chashes) == 3 and len(chashes[1]) == 1:
            # the first hash, then length of consecutive hashes,
            # then a list of stitched hashes as one long string
            clen = int(chashes[1])
            siblings = chashes[2]
            chashes = [chashes[0]]
            for n in range(0, len(siblings), clen):
                chashes.append(siblings[n : n + clen])

        vfs, _ = self.asrv.vfs.get(self.vpath, self.uname, False, True)
        ptop = vfs.get_dbv("")[0].realpath
        # if this is a share, then get_dbv has been overridden to return
        # the dbv (which does not exist as a property). And its realpath
        # could point into the middle of its origin vfs node, meaning it
        # is not necessarily registered with up2k, so get_dbv is crucial

        broker = self.conn.hsrv.broker
        x = broker.ask("up2k.handle_chunks", ptop, wark, chashes)
        response = x.get()
        chashes, chunksize, cstarts, path, lastmod, fsize, sprs = response
        maxsize = chunksize * len(chashes)
        cstart0 = cstarts[0]
        locked = chashes  # remaining chunks to be received in this request
        written = []  # chunks written to disk, but not yet released by up2k
        num_left = -1  # num chunks left according to most recent up2k release
        bail1 = False  # used in sad path to avoid contradicting error-text
        treport = time.time()  # ratelimit up2k reporting to reduce overhead

        try:
            if "x-up2k-subc" in self.headers:
                sc_ofs = int(self.headers["x-up2k-subc"])
                chash = chashes[0]

                u2sc = self.conn.hsrv.u2sc
                try:
                    sc_pofs, hasher = u2sc[chash]
                    if not sc_ofs:
                        t = "client restarted the chunk; forgetting subchunk offset %d"
                        self.log(t % (sc_pofs,))
                        raise Exception()
                except Exception:
                    sc_pofs = 0
                    hasher = hashlib.sha512()

                et = "subchunk protocol error; resetting chunk "
                if sc_pofs != sc_ofs:
                    u2sc.pop(chash, None)
                    t = "%s[%s]: the expected resume-point was %d, not %d"
                    raise Pebkac(400, t % (et, chash, sc_pofs, sc_ofs))
                if len(cstarts) > 1:
                    u2sc.pop(chash, None)
                    t = "%s[%s]: only a single subchunk can be uploaded in one request; you are sending %d chunks"
                    raise Pebkac(400, t % (et, chash, len(cstarts)))
                csize = min(chunksize, fsize - cstart0[0])
                cstart0[0] += sc_ofs  # also sets cstarts[0][0]
                sc_next_ofs = sc_ofs + postsize
                if sc_next_ofs > csize:
                    u2sc.pop(chash, None)
                    t = "%s[%s]: subchunk offset (%d) plus postsize (%d) exceeds chunksize (%d)"
                    raise Pebkac(400, t % (et, chash, sc_ofs, postsize, csize))
                else:
                    final_subchunk = sc_next_ofs == csize
                    t = "subchunk %s %d:%d/%d %s"
                    zs = "END" if final_subchunk else ""
                    self.log(t % (chash[:15], sc_ofs, sc_next_ofs, csize, zs), 6)
                    if final_subchunk:
                        u2sc.pop(chash, None)
                    else:
                        u2sc[chash] = (sc_next_ofs, hasher)
            else:
                hasher = None
                final_subchunk = True

            if self.args.nw:
                path = os.devnull

            if remains > maxsize:
                t = "your client is sending %d bytes which is too much (server expected %d bytes at most)"
                raise Pebkac(400, t % (remains, maxsize))

            t = "writing %r %s+%d #%d+%d %s"
            chunkno = cstart0[0] // chunksize
            zs = " ".join([chashes[0][:15]] + [x[:9] for x in chashes[1:]])
            self.log(t % (path, cstart0, remains, chunkno, len(chashes), zs))

            f = None
            fpool = not self.args.no_fpool and sprs
            if fpool:
                with self.u2mutex:
                    try:
                        f = self.u2fh.pop(path)
                    except (KeyError, IndexError):
                        pass

            f = f or open(fsenc(path), "rb+", self.args.iobuf)

            try:
                for chash, cstart in zip(chashes, cstarts):
                    f.seek(cstart[0])
                    reader = read_socket(
                        self.sr, self.args.s_rd_sz, min(remains, chunksize)
                    )
                    post_sz, _, sha_b64 = hashcopy(
                        reader, f, hasher, 0, self.args.s_wr_slp
                    )

                    if sha_b64 != chash and final_subchunk:
                        try:
                            self.bakflip(
                                f, path, cstart[0], post_sz, chash, sha_b64, vfs.flags
                            )
                        except Exception:
                            self.log("bakflip failed: " + min_ex())

                        t = "your chunk got corrupted somehow (received {} bytes); expected vs received hash:\n{}\n{}"
                        raise Pebkac(400, t.format(post_sz, chash, sha_b64))

                    remains -= post_sz

                    if len(cstart) > 1 and path != os.devnull:
                        t = " & ".join(unicode(x) for x in cstart[1:])
                        self.log("clone %s to %s" % (cstart[0], t))
                        ofs = 0
                        while ofs < chunksize:
                            bufsz = max(4 * 1024 * 1024, self.args.iobuf)
                            bufsz = min(chunksize - ofs, bufsz)
                            f.seek(cstart[0] + ofs)
                            buf = f.read(bufsz)
                            for wofs in cstart[1:]:
                                f.seek(wofs + ofs)
                                f.write(buf)

                            ofs += len(buf)

                        self.log("clone {} done".format(cstart[0]))

                    # be quick to keep the tcp winsize scale;
                    # if we can't confirm rn then that's fine
                    if final_subchunk:
                        written.append(chash)
                    now = time.time()
                    if now - treport < 1:
                        continue
                    treport = now
                    x = broker.ask(
                        "up2k.fast_confirm_chunks", ptop, wark, written, locked
                    )
                    num_left, t = x.get()
                    if num_left < -1:
                        self.loud_reply(t, status=500)
                        locked = written = []
                        return False
                    elif num_left >= 0:
                        t = "got %d more chunks, %d left"
                        self.log(t % (len(written), num_left), 6)
                        locked = locked[len(written) :]
                        written = []

                if not fpool:
                    f.close()
                else:
                    with self.u2mutex:
                        self.u2fh.put(path, f)
            except Exception:
                # maybe busted handle (eg. disk went full)
                f.close()
                raise
        finally:
            if locked:
                # now block until all chunks released+confirmed
                x = broker.ask("up2k.confirm_chunks", ptop, wark, written, locked)
                num_left, t = x.get()
                if num_left < 0:
                    self.loud_reply(t, status=500)
                    bail1 = True
                else:
                    t = "got %d more chunks, %d left"
                    self.log(t % (len(written), num_left), 6)

        if num_left < 0:
            if bail1:
                return False
            raise Pebkac(500, "unconfirmed; see fileserver log")

        if not num_left and fpool:
            with self.u2mutex:
                self.u2fh.close(path)

        if not num_left and not self.args.nw:
            broker.ask("up2k.finish_upload", ptop, wark, self.u2fh.aps).get()

        cinf = self.headers.get("x-up2k-stat", "")

        spd = self._spd(postsize)
        self.log("%70s thank %r" % (spd, cinf))

        if remains:
            t = "incorrect content-length from client"
            self.log("%s; header=%d, remains=%d" % (t, postsize, remains), 3)
            raise Pebkac(400, t)

        self.reply(b"thank")
        return True

    def upload_flags(self, vfs: VFS) -> tuple[int, int, list[str], list[str]]:
        if self.args.nw:
            rnd = 0
        else:
            rnd = int(self.uparam.get("rand") or self.headers.get("rand") or 0)
            if vfs.flags.get("rand"):  # force-enable
                rnd = max(rnd, vfs.flags["nrand"])

        zs = self.uparam.get("life", self.headers.get("life", ""))
        if zs:
            vlife = vfs.flags.get("lifetime") or 0
            lifetime = max(0, int(vlife - int(zs)))
        else:
            lifetime = 0

        return (
            rnd,
            lifetime,
            vfs.flags.get("xbu") or [],
            vfs.flags.get("xau") or [],
        )

    def handle_plain_upload(
        self,
        file0: list[tuple[str, Optional[str], Generator[bytes, None, None]]],
        nohash: bool,
    ) -> bool:
        assert self.parser
        nullwrite = self.args.nw
        vfs, rem = self.asrv.vfs.get(self.vpath, self.uname, False, True)
        self._assert_safe_rem(rem)

        hasher = None
        if nohash:
            halg = ""
            copier = justcopy
        else:
            copier = hashcopy
            halg = (
                self.ouparam.get("ck") or self.headers.get("ck") or vfs.flags["bup_ck"]
            )
            if halg == "sha512":
                pass
            elif halg == "no":
                copier = justcopy
                halg = ""
            elif halg == "md5":
                hasher = hashlib.md5(**USED4SEC)
            elif halg == "sha1":
                hasher = hashlib.sha1(**USED4SEC)
            elif halg == "sha256":
                hasher = hashlib.sha256(**USED4SEC)
            elif halg in ("blake2", "b2"):
                hasher = hashlib.blake2b(**USED4SEC)
            elif halg in ("blake2s", "b2s"):
                hasher = hashlib.blake2s(**USED4SEC)
            else:
                raise Pebkac(500, "unknown hash alg")

        upload_vpath = self.vpath
        lim = vfs.get_dbv(rem)[0].lim
        fdir_base = vfs.canonical(rem)
        if lim:
            fdir_base, rem = lim.all(
                self.ip, rem, -1, vfs.realpath, fdir_base, self.conn.hsrv.broker
            )
            upload_vpath = "{}/{}".format(vfs.vpath, rem).strip("/")
            if not nullwrite:
                bos.makedirs(fdir_base, vf=vfs.flags)

        rnd, lifetime, xbu, xau = self.upload_flags(vfs)
        zs = self.uparam.get("want") or self.headers.get("accept") or ""
        if zs:
            zs = zs.split(";", 1)[0].lower()
            if zs == "application/json":
                zs = "json"
        want_url = zs == "url"
        want_json = zs == "json" or "j" in self.uparam

        files: list[tuple[int, str, str, str, str, str]] = []
        # sz, sha_hex, sha_b64, p_file, fname, abspath
        errmsg = ""
        tabspath = ""
        dip = self.dip()
        t0 = time.time()
        try:
            assert self.parser.gen
            gens = itertools.chain(file0, self.parser.gen)
            for nfile, (p_field, p_file, p_data) in enumerate(gens):
                if not p_file:
                    self.log("discarding incoming file without filename")
                    # fallthrough

                fdir = fdir_base
                fname = sanitize_fn(p_file or "")
                abspath = os.path.join(fdir, fname)
                suffix = "-%.6f-%s" % (time.time(), dip)
                if p_file and not nullwrite:
                    if rnd:
                        fname = rand_name(fdir, fname, rnd)

                    open_args = {"fdir": fdir, "suffix": suffix, "vf": vfs.flags}

                    if "replace" in self.uparam or "replace" in self.headers:
                        if not self.can_delete:
                            self.log("user not allowed to overwrite with ?replace")
                        elif bos.path.exists(abspath):
                            try:
                                wunlink(self.log, abspath, vfs.flags)
                                t = "overwriting file with new upload: %r"
                            except OSError:
                                t = "toctou while deleting for ?replace: %r"
                            self.log(t % (abspath,))
                else:
                    open_args = {}
                    tnam = fname = os.devnull
                    fdir = abspath = ""

                if xbu:
                    at = time.time() - lifetime
                    hr = runhook(
                        self.log,
                        self.conn.hsrv.broker,
                        None,
                        "xbu.http.bup",
                        xbu,
                        abspath,
                        vjoin(upload_vpath, fname),
                        self.host,
                        self.uname,
                        self.asrv.vfs.get_perms(upload_vpath, self.uname),
                        at,
                        0,
                        self.ip,
                        at,
                        None,
                    )
                    t = hr.get("rejectmsg") or ""
                    if t or hr.get("rc") != 0:
                        if not t:
                            t = "upload blocked by xbu server config: %r"
                            t = t % (vjoin(upload_vpath, fname),)
                        self.log(t, 1)
                        raise Pebkac(403, t)
                    if hr.get("reloc"):
                        zs = vjoin(upload_vpath, fname)
                        x = pathmod(self.asrv.vfs, abspath, zs, hr["reloc"])
                        if x:
                            if self.args.hook_v:
                                log_reloc(
                                    self.log,
                                    hr["reloc"],
                                    x,
                                    abspath,
                                    zs,
                                    fname,
                                    vfs,
                                    rem,
                                )
                            fdir, upload_vpath, fname, (vfs, rem) = x
                            abspath = os.path.join(fdir, fname)
                            if nullwrite:
                                fdir = abspath = ""
                            else:
                                open_args["fdir"] = fdir

                if p_file and not nullwrite:
                    bos.makedirs(fdir, vf=vfs.flags)

                    # reserve destination filename
                    f, fname = ren_open(fname, "wb", fdir=fdir, suffix=suffix)
                    f.close()

                    tnam = fname + ".PARTIAL"
                    if self.args.dotpart:
                        tnam = "." + tnam

                    abspath = os.path.join(fdir, fname)
                else:
                    open_args = {}
                    tnam = fname = os.devnull
                    fdir = abspath = ""

                if lim:
                    lim.chk_bup(self.ip)
                    lim.chk_nup(self.ip)

                try:
                    max_sz = 0
                    if lim:
                        v1 = lim.smax
                        v2 = lim.dfv - lim.dfl
                        max_sz = min(v1, v2) if v1 and v2 else v1 or v2

                    f, tnam = ren_open(tnam, "wb", self.args.iobuf, **open_args)
                    try:
                        tabspath = os.path.join(fdir, tnam)
                        self.log("writing to %r" % (tabspath,))
                        sz, sha_hex, sha_b64 = copier(
                            p_data, f, hasher, max_sz, self.args.s_wr_slp
                        )
                    finally:
                        f.close()

                    if lim:
                        lim.nup(self.ip)
                        lim.bup(self.ip, sz)
                        try:
                            lim.chk_df(tabspath, sz, True)
                            lim.chk_sz(sz)
                            lim.chk_vsz(self.conn.hsrv.broker, vfs.realpath, sz)
                            lim.chk_bup(self.ip)
                            lim.chk_nup(self.ip)
                        except Exception:
                            if not nullwrite:
                                wunlink(self.log, tabspath, vfs.flags)
                                wunlink(self.log, abspath, vfs.flags)
                            fname = os.devnull
                            raise

                    if not nullwrite:
                        atomic_move(self.log, tabspath, abspath, vfs.flags)

                    tabspath = ""

                    at = time.time() - lifetime
                    if xau:
                        hr = runhook(
                            self.log,
                            self.conn.hsrv.broker,
                            None,
                            "xau.http.bup",
                            xau,
                            abspath,
                            vjoin(upload_vpath, fname),
                            self.host,
                            self.uname,
                            self.asrv.vfs.get_perms(upload_vpath, self.uname),
                            at,
                            sz,
                            self.ip,
                            at,
                            None,
                        )
                        t = hr.get("rejectmsg") or ""
                        if t or hr.get("rc") != 0:
                            if not t:
                                t = "upload blocked by xau server config: %r"
                                t = t % (vjoin(upload_vpath, fname),)
                            self.log(t, 1)
                            wunlink(self.log, abspath, vfs.flags)
                            raise Pebkac(403, t)
                        if hr.get("reloc"):
                            zs = vjoin(upload_vpath, fname)
                            x = pathmod(self.asrv.vfs, abspath, zs, hr["reloc"])
                            if x:
                                if self.args.hook_v:
                                    log_reloc(
                                        self.log,
                                        hr["reloc"],
                                        x,
                                        abspath,
                                        zs,
                                        fname,
                                        vfs,
                                        rem,
                                    )
                                fdir, upload_vpath, fname, (vfs, rem) = x
                                ap2 = os.path.join(fdir, fname)
                                if nullwrite:
                                    fdir = ap2 = ""
                                else:
                                    bos.makedirs(fdir, vf=vfs.flags)
                                    atomic_move(self.log, abspath, ap2, vfs.flags)
                                abspath = ap2
                        sz = bos.path.getsize(abspath)

                    files.append(
                        (sz, sha_hex, sha_b64, p_file or "(discarded)", fname, abspath)
                    )
                    dbv, vrem = vfs.get_dbv(rem)
                    self.conn.hsrv.broker.say(
                        "up2k.hash_file",
                        dbv.realpath,
                        vfs.vpath,
                        dbv.flags,
                        vrem,
                        fname,
                        self.ip,
                        at,
                        self.uname,
                        True,
                    )
                    self.conn.nbyte += sz

                except Pebkac:
                    self.parser.drop()
                    raise

        except Pebkac as ex:
            errmsg = vol_san(
                list(self.asrv.vfs.all_vols.values()), unicode(ex).encode("utf-8")
            ).decode("utf-8")
            try:
                got = bos.path.getsize(tabspath)
                t = "connection lost after receiving %s of the file"
                self.log(t % (humansize(got),), 3)
            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                pass

        td = max(0.1, time.time() - t0)
        sz_total = sum(x[0] for x in files)
        spd = (sz_total / td) / (1024 * 1024)

        status = "OK"
        if errmsg:
            self.log(errmsg, 3)
            status = "ERROR"

        msg = "{} // {} bytes // {:.3f} MiB/s\n".format(status, sz_total, spd)
        jmsg: dict[str, Any] = {
            "status": status,
            "sz": sz_total,
            "mbps": round(spd, 3),
            "files": [],
        }

        if errmsg:
            msg += errmsg + "\n"
            jmsg["error"] = errmsg
            errmsg = "ERROR: " + errmsg

        if halg:
            file_fmt = '{0}: {1} // {2} // {3} bytes // <a href="{4}">{5}</a> {6}\n'
        else:
            file_fmt = '{3} bytes // <a href="{4}">{5}</a> {6}\n'

        for sz, sha_hex, sha_b64, ofn, lfn, ap in files:
            vsuf = ""
            if (self.can_read or self.can_upget) and "fk" in vfs.flags:
                st = A_FILE if nullwrite else bos.stat(ap)
                alg = 2 if "fka" in vfs.flags else 1
                vsuf = "?k=" + self.gen_fk(
                    alg,
                    self.args.fk_salt,
                    ap,
                    st.st_size,
                    0 if ANYWIN or not ap else st.st_ino,
                )[: vfs.flags["fk"]]

            if "media" in self.uparam or "medialinks" in vfs.flags:
                vsuf += "&v" if vsuf else "?v"

            vpath = vjoin(upload_vpath, lfn)
            if self.args.up_site:
                ah_url = j_url = self.args.up_site + quotep(vpath) + vsuf
                rel_url = "/" + j_url.split("//", 1)[-1].split("/", 1)[-1]
            else:
                ah_url = rel_url = "/%s%s%s" % (self.args.RS, quotep(vpath), vsuf)
                j_url = "%s://%s%s" % (
                    "https" if self.is_https else "http",
                    self.host,
                    rel_url,
                )

            msg += file_fmt.format(
                halg,
                sha_hex[:56],
                sha_b64,
                sz,
                ah_url,
                html_escape(ofn, crlf=True),
                vsuf,
            )
            # truncated SHA-512 prevents length extension attacks;
            # using SHA-512/224, optionally SHA-512/256 = :64
            jpart = {
                "url": j_url,
                "sz": sz,
                "fn": lfn,
                "fn_orig": ofn,
                "path": rel_url,
            }
            if halg:
                jpart[halg] = sha_hex[:56]
                jpart["sha_b64"] = sha_b64
            jmsg["files"].append(jpart)

        vspd = self._spd(sz_total, False)
        self.log("%s %r" % (vspd, msg))

        suf = ""
        if not nullwrite and self.args.write_uplog:
            try:
                log_fn = "up.{:.6f}.txt".format(t0)
                with open(log_fn, "wb") as f:
                    ft = "{}:{}".format(self.ip, self.addr[1])
                    ft = "{}\n{}\n{}\n".format(ft, msg.rstrip(), errmsg)
                    f.write(ft.encode("utf-8"))
                    if "fperms" in vfs.flags:
                        set_fperms(f, vfs.flags)
            except Exception as ex:
                suf = "\nfailed to write the upload report: {}".format(ex)

        sc = 400 if errmsg else 201
        if want_url:
            msg = "\n".join([x["url"] for x in jmsg["files"]])
            if errmsg:
                msg += "\n" + errmsg

            self.reply(msg.encode("utf-8", "replace"), status=sc)
        elif want_json:
            if len(jmsg["files"]) == 1:
                jmsg["fileurl"] = jmsg["files"][0]["url"]
            jtxt = json.dumps(jmsg, indent=2, sort_keys=True).encode("utf-8", "replace")
            self.reply(jtxt, mime="application/json", status=sc)
        else:
            self.redirect(
                self.vpath,
                msg=msg + suf,
                flavor="return to",
                click=False,
                status=sc,
            )

        if errmsg:
            return False

        self.parser.drop()
        return True

    def handle_text_upload(self) -> bool:
        assert self.parser  # !rm
        try:
            cli_lastmod3 = int(self.parser.require("lastmod", 16))
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            raise Pebkac(400, "could not read lastmod from request")

        nullwrite = self.args.nw
        vfs, rem = self.asrv.vfs.get(self.vpath, self.uname, True, True)
        self._assert_safe_rem(rem)

        clen = int(self.headers.get("content-length", -1))
        if clen == -1:
            raise Pebkac(411)

        rp, fn = vsplit(rem)
        fp = vfs.canonical(rp)
        lim = vfs.get_dbv(rem)[0].lim
        if lim:
            fp, rp = lim.all(self.ip, rp, clen, vfs.realpath, fp, self.conn.hsrv.broker)
            bos.makedirs(fp, vf=vfs.flags)

        fp = os.path.join(fp, fn)
        rem = "{}/{}".format(rp, fn).strip("/")
        dbv, vrem = vfs.get_dbv(rem)

        if not rem.lower().endswith(".md") and not self.can_delete:
            raise Pebkac(400, "only markdown pls")

        if nullwrite:
            response = json.dumps({"ok": True, "lastmod": 0})
            self.log(response)
            # TODO reply should parser.drop()
            self.parser.drop()
            self.reply(response.encode("utf-8"))
            return True

        srv_lastmod = -1.0
        srv_lastmod3 = -1
        try:
            st = bos.stat(fp)
            srv_lastmod = st.st_mtime
            srv_lastmod3 = int(srv_lastmod * 1000)
        except OSError as ex:
            if ex.errno != errno.ENOENT:
                raise

        # if file exists, check that timestamp matches the client's
        if srv_lastmod >= 0:
            same_lastmod = cli_lastmod3 in [-1, srv_lastmod3]
            if not same_lastmod:
                # some filesystems/transports limit precision to 1sec, hopefully floored
                same_lastmod = (
                    srv_lastmod == int(cli_lastmod3 / 1000)
                    and cli_lastmod3 > srv_lastmod3
                    and cli_lastmod3 - srv_lastmod3 < 1000
                )

            if not same_lastmod:
                response = json.dumps(
                    {
                        "ok": False,
                        "lastmod": srv_lastmod3,
                        "now": int(time.time() * 1000),
                    }
                )
                self.log(
                    "{} - {} = {}".format(
                        srv_lastmod3, cli_lastmod3, srv_lastmod3 - cli_lastmod3
                    )
                )
                self.log(response)
                self.parser.drop()
                self.reply(response.encode("utf-8"))
                return True

            mdir, mfile = os.path.split(fp)
            fname, fext = mfile.rsplit(".", 1) if "." in mfile else (mfile, "md")
            mfile2 = "{}.{:.3f}.{}".format(fname, srv_lastmod, fext)

            dp = ""
            hist_cfg = dbv.flags["md_hist"]
            if hist_cfg == "v":
                vrd = vsplit(vrem)[0]
                zb = hashlib.sha512(afsenc(vrd)).digest()
                zs = ub64enc(zb).decode("ascii")[:24].lower()
                dp = "%s/md/%s/%s/%s" % (dbv.histpath, zs[:2], zs[2:4], zs)
                self.log("moving old version to %s/%s" % (dp, mfile2))
                if bos.makedirs(dp, vf=vfs.flags):
                    with open(os.path.join(dp, "dir.txt"), "wb") as f:
                        f.write(afsenc(vrd))
                        if "fperms" in vfs.flags:
                            set_fperms(f, vfs.flags)
            elif hist_cfg == "s":
                dp = os.path.join(mdir, ".hist")
                try:
                    bos.mkdir(dp, vfs.flags["chmod_d"])
                    if "chown" in vfs.flags:
                        bos.chown(dp, vfs.flags["uid"], vfs.flags["gid"])
                    hidedir(dp)
                except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                    pass
            if dp:
                atomic_move(self.log, fp, os.path.join(dp, mfile2), vfs.flags)

        assert self.parser.gen  # !rm
        p_field, _, p_data = next(self.parser.gen)
        if p_field != "body":
            raise Pebkac(400, "expected body, got %r" % (p_field,))

        if "txt_eol" in vfs.flags:
            p_data = eol_conv(p_data, vfs.flags["txt_eol"])

        xbu = vfs.flags.get("xbu")
        if xbu:
            hr = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xbu.http.txt",
                xbu,
                fp,
                self.vpath,
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
                    t = "save blocked by xbu server config"
                self.log(t, 1)
                raise Pebkac(403, t)

        if bos.path.exists(fp):
            wunlink(self.log, fp, vfs.flags)

        with open(fsenc(fp), "wb", self.args.iobuf) as f:
            if "fperms" in vfs.flags:
                set_fperms(f, vfs.flags)
            sz, sha512, _ = hashcopy(p_data, f, None, 0, self.args.s_wr_slp)

        if lim:
            lim.nup(self.ip)
            lim.bup(self.ip, sz)
            try:
                lim.chk_sz(sz)
                lim.chk_vsz(self.conn.hsrv.broker, vfs.realpath, sz)
            except Exception:
                wunlink(self.log, fp, vfs.flags)
                raise

        new_lastmod = bos.stat(fp).st_mtime
        new_lastmod3 = int(new_lastmod * 1000)
        sha512 = sha512[:56]

        xau = vfs.flags.get("xau")
        if xau:
            hr = runhook(
                self.log,
                self.conn.hsrv.broker,
                None,
                "xau.http.txt",
                xau,
                fp,
                self.vpath,
                self.host,
                self.uname,
                self.asrv.vfs.get_perms(self.vpath, self.uname),
                new_lastmod,
                sz,
                self.ip,
                new_lastmod,
                None,
            )
            t = hr.get("rejectmsg") or ""
            if t or hr.get("rc") != 0:
                if not t:
                    t = "save blocked by xau server config"
                self.log(t, 1)
                wunlink(self.log, fp, vfs.flags)
                raise Pebkac(403, t)

        self.conn.hsrv.broker.say(
            "up2k.hash_file",
            dbv.realpath,
            dbv.vpath,
            dbv.flags,
            vsplit(vrem)[0],
            fn,
            self.ip,
            new_lastmod,
            self.uname,
            True,
        )

        response = json.dumps(
            {"ok": True, "lastmod": new_lastmod3, "size": sz, "sha512": sha512}
        )
        self.log(response)
        self.parser.drop()
        self.reply(response.encode("utf-8"))
        return True

