# coding: utf-8
from __future__ import annotations

import errno
import json
import os
import re
import stat
import time
import typing

from .bos import bos
from .qrkode import qr2svg, qrgen
from .star import StreamTar
from .sutil import StreamArc, gfilter
from .szip import StreamZip
from .up2k import up2k_chunksize
from .util import (
    BITNESS,
    E_SCK_WR,
    Pebkac,
    formatdate,
    fsenc,
    gen_content_disposition,
    guess_mime,
    gzip,
    gzip_file_orig_sz,
    gzip_orig_sz,
    has_resource,
    html_bescape,
    html_escape,
    load_resource,
    sendfile_kern,
    sendfile_py,
    stat_resource,
    yieldfile,
)

from .__init__ import unicode

if True:  # pylint: disable=using-constant-test
    from typing import Any, Optional, Sequence, Type


def _build_zip_xcode() -> Sequence[str]:
    ret = "opus mp3 flac wav p".split()
    for codec in ("j", "w", "x"):
        for suf in ("", "f", "f3", "3"):
            ret.append("%s%s" % (codec, suf))
    return ret


ZIP_XCODE_L = _build_zip_xcode()
ZIP_XCODE_S = set(ZIP_XCODE_L)
ACODE2_FMT = set(["opus", "owa", "caf", "mp3", "flac", "wav"])


class HttpCliTx(object):
    def tx_zls(self, abspath) -> bool:
        if self.do_log:
            self.log("zls %s @%s" % (self.req, self.uname))
        if self.args.no_zls:
            raise Pebkac(405, "zip browsing is disabled in server config")

        import zipfile

        try:
            with zipfile.ZipFile(abspath, "r") as zf:
                filelist = [{"fn": f.filename} for f in zf.infolist()]
                ret = json.dumps(filelist).encode("utf-8", "replace")
                self.reply(ret, mime="application/json")
                return True
        except (zipfile.BadZipfile, RuntimeError):
            raise Pebkac(404, "requested file is not a valid zip file")

    def tx_zget(self, abspath) -> bool:
        maxsz = 1024 * 1024 * 64

        inner_path = self.uparam.get("zget")
        if not inner_path:
            raise Pebkac(405, "inner path is required")
        if self.do_log:
            self.log(
                "zget %s \033[35m%s\033[0m @%s" % (self.req, inner_path, self.uname)
            )
        if self.args.no_zls:
            raise Pebkac(405, "zip browsing is disabled in server config")

        import zipfile

        try:
            with zipfile.ZipFile(abspath, "r") as zf:
                zi = zf.getinfo(inner_path)
                if zi.file_size >= maxsz:
                    raise Pebkac(404, "zip bomb defused")
                with zf.open(zi, "r") as fi:
                    self.send_headers(length=zi.file_size, mime=guess_mime(inner_path))

                    sendfile_py(
                        self.log,
                        0,
                        zi.file_size,
                        fi,
                        self.s,
                        self.args.s_wr_sz,
                        self.args.s_wr_slp,
                        not self.args.no_poll,
                        {},
                        "",
                    )
        except KeyError:
            raise Pebkac(404, "no such file in archive")
        except (zipfile.BadZipfile, RuntimeError):
            raise Pebkac(404, "requested file is not a valid zip file")
        return True

    def tx_res(self, req_path: str) -> bool:
        status = 200
        logmsg = "{:4} {} ".format("", self.req)
        logtail = ""

        editions = {}
        file_ts = 0

        if has_resource(self.E, req_path):
            st = stat_resource(self.E, req_path)
            if st:
                file_ts = max(file_ts, st.st_mtime)
            editions["plain"] = req_path

        if has_resource(self.E, req_path + ".gz"):
            st = stat_resource(self.E, req_path + ".gz")
            if st:
                file_ts = max(file_ts, st.st_mtime)
            if not st or st.st_mtime > file_ts:
                editions[".gz"] = req_path + ".gz"

        if not editions:
            return self.tx_404()

        #
        # force download

        if "dl" in self.ouparam:
            cdis = self.ouparam["dl"] or req_path
            zs = gen_content_disposition(os.path.basename(cdis))
            self.out_headers["Content-Disposition"] = zs
        else:
            cdis = req_path

        #
        # if-modified

        if file_ts > 0:
            file_lastmod, do_send, _ = self._chk_lastmod(int(file_ts))
            self.out_headers["Last-Modified"] = file_lastmod
            if not do_send:
                status = 304

            if self.can_write:
                self.out_headers["X-Lastmod3"] = str(int(file_ts * 1000))
        else:
            do_send = True

        #
        # Accept-Encoding and UA decides which edition to send

        decompress = False
        supported_editions = [
            x.strip()
            for x in self.headers.get("accept-encoding", "").lower().split(",")
        ]
        if ".gz" in editions:
            is_compressed = True
            selected_edition = ".gz"

            if "gzip" not in supported_editions:
                decompress = True
            else:
                if re.match(r"MSIE [4-6]\.", self.ua) and " SV1" not in self.ua:
                    decompress = True

            if not decompress:
                self.out_headers["Content-Encoding"] = "gzip"
        else:
            is_compressed = False
            selected_edition = "plain"

        res_path = editions[selected_edition]
        logmsg += "{} ".format(selected_edition.lstrip("."))

        res = load_resource(self.E, res_path)

        if decompress:
            file_sz = gzip_file_orig_sz(res)
            res = gzip.open(res)
        else:
            res.seek(0, os.SEEK_END)
            file_sz = res.tell()
            res.seek(0, os.SEEK_SET)

        #
        # send reply

        if is_compressed:
            self.out_headers["Cache-Control"] = "max-age=604869"
        else:
            self.permit_caching()

        if "txt" in self.uparam:
            mime = "text/plain; charset={}".format(self.uparam["txt"] or "utf-8")
        elif "mime" in self.uparam:
            mime = str(self.uparam.get("mime"))
        else:
            mime = guess_mime(cdis)

        logmsg += unicode(status) + logtail

        if self.mode == "HEAD" or not do_send:
            res.close()
            if self.do_log:
                self.log(logmsg)

            self.send_headers(length=file_sz, status=status, mime=mime)
            return True

        ret = True
        self.send_headers(length=file_sz, status=status, mime=mime)
        remains = sendfile_py(
            self.log,
            0,
            file_sz,
            res,
            self.s,
            self.args.s_wr_sz,
            self.args.s_wr_slp,
            not self.args.no_poll,
            {},
            "",
        )
        res.close()

        if remains > 0:
            logmsg += " \033[31m" + unicode(file_sz - remains) + "\033[0m"
            ret = False

        spd = self._spd(file_sz - remains)
        if self.do_log:
            self.log("{},  {}".format(logmsg, spd))

        return ret

    def tx_file(self, req_path: str, ptop: Optional[str] = None) -> bool:
        status = 200
        logmsg = "{:4} {} ".format("", self.req)
        logtail = ""

        is_tail = "tail" in self.uparam and self._can_tail(self.vn.flags)

        if ptop is not None:
            ap_data = "<%s>" % (req_path,)
            try:
                dp, fn = os.path.split(req_path)
                tnam = fn + ".PARTIAL"
                if self.args.dotpart:
                    tnam = "." + tnam
                ap_data = os.path.join(dp, tnam)
                st_data = bos.stat(ap_data)
                if not st_data.st_size:
                    raise Exception("partial is empty")
                x = self.conn.hsrv.broker.ask("up2k.find_job_by_ap", ptop, req_path)
                job = json.loads(x.get())
                if not job:
                    raise Exception("not found in registry")
                self.pipes.set(req_path, job)
            except Exception as ex:
                if getattr(ex, "errno", 0) != errno.ENOENT:
                    self.log("will not pipe %r; %s" % (ap_data, ex), 6)
                ptop = None

        #
        # if request is for foo.js, check if we have foo.js.gz

        file_ts = 0.0
        editions: dict[str, tuple[str, int]] = {}
        for ext in ("", ".gz"):
            if ptop is not None:
                assert job and ap_data  # type: ignore  # !rm
                sz = job["size"]
                file_ts = max(0, job["lmod"])
                editions["plain"] = (ap_data, sz)
                break

            try:
                fs_path = req_path + ext
                st = bos.stat(fs_path)
                if stat.S_ISDIR(st.st_mode):
                    continue

                sz = st.st_size
                if stat.S_ISBLK(st.st_mode):
                    fd = bos.open(fs_path, os.O_RDONLY)
                    try:
                        sz = os.lseek(fd, 0, os.SEEK_END)
                    finally:
                        os.close(fd)

                file_ts = max(file_ts, st.st_mtime)
                editions[ext or "plain"] = (fs_path, sz)
            except OSError:
                pass
            if not self.vpath.startswith(".cpr/"):
                break

        if not editions:
            return self.tx_404()

        #
        # force download

        if "dl" in self.ouparam:
            cdis = self.ouparam["dl"] or req_path
            zs = gen_content_disposition(os.path.basename(cdis))
            self.out_headers["Content-Disposition"] = zs
        else:
            cdis = req_path

        #
        # if-modified

        file_lastmod, do_send, can_range = self._chk_lastmod(int(file_ts))
        self.out_headers["Last-Modified"] = file_lastmod
        if not do_send:
            status = 304

        if self.can_write:
            self.out_headers["X-Lastmod3"] = str(int(file_ts * 1000))

        #
        # Accept-Encoding and UA decides which edition to send

        decompress = False
        supported_editions = [
            x.strip()
            for x in self.headers.get("accept-encoding", "").lower().split(",")
        ]
        if ".gz" in editions:
            is_compressed = True
            selected_edition = ".gz"
            fs_path, file_sz = editions[".gz"]
            if "gzip" not in supported_editions:
                decompress = True
            else:
                if re.match(r"MSIE [4-6]\.", self.ua) and " SV1" not in self.ua:
                    decompress = True

            if not decompress:
                self.out_headers["Content-Encoding"] = "gzip"
        else:
            is_compressed = False
            selected_edition = "plain"

        fs_path, file_sz = editions[selected_edition]
        logmsg += "{} ".format(selected_edition.lstrip("."))

        #
        # partial

        lower = 0
        upper = file_sz
        hrange = self.headers.get("range")

        # let's not support 206 with compression
        # and multirange / multipart is also not-impl (mostly because calculating contentlength is a pain)
        if (
            do_send
            and not is_compressed
            and hrange
            and can_range
            and file_sz
            and "," not in hrange
            and not is_tail
        ):
            try:
                if not hrange.lower().startswith("bytes"):
                    raise Exception()

                a, b = hrange.split("=", 1)[1].split("-")

                if a.strip():
                    lower = int(a.strip())
                else:
                    lower = 0

                if b.strip():
                    upper = int(b.strip()) + 1
                else:
                    upper = file_sz

                if upper > file_sz:
                    upper = file_sz

                if lower < 0 or lower >= upper:
                    raise Exception()

            except (ValueError, TypeError, UnicodeDecodeError, IndexError):
                err = "invalid range ({}), size={}".format(hrange, file_sz)
                self.loud_reply(
                    err,
                    status=416,
                    headers={"Content-Range": "bytes */{}".format(file_sz)},
                )
                return True

            status = 206
            self.out_headers["Content-Range"] = "bytes {}-{}/{}".format(
                lower, upper - 1, file_sz
            )

            logtail += " [\033[36m{}-{}\033[0m]".format(lower, upper)

        use_sendfile = False
        if decompress:
            open_func: Any = gzip.open
            open_args: list[Any] = [fsenc(fs_path), "rb"]
            # Content-Length := original file size
            upper = gzip_orig_sz(fs_path)
        else:
            open_func = open
            open_args = [fsenc(fs_path), "rb", self.args.iobuf]
            use_sendfile = (
                # fmt: off
                not self.tls
                and not self.args.no_sendfile
                and (BITNESS > 32 or file_sz < 0x7fffFFFF)
                # fmt: on
            )

        #
        # send reply

        if is_compressed:
            self.out_headers["Cache-Control"] = "max-age=604869"
        else:
            self.permit_caching()

        if "txt" in self.uparam:
            mime = "text/plain; charset={}".format(self.uparam["txt"] or "utf-8")
        elif "mime" in self.uparam:
            mime = str(self.uparam.get("mime"))
        elif "rmagic" in self.vn.flags:
            mime = guess_mime(req_path, fs_path)
        else:
            mime = guess_mime(cdis)

        if "nohtml" in self.vn.flags and "html" in mime:
            mime = "text/plain; charset=utf-8"

        self.out_headers["Accept-Ranges"] = "bytes"
        logmsg += unicode(status) + logtail

        if self.mode == "HEAD" or not do_send:
            if self.do_log:
                self.log(logmsg)

            self.send_headers(length=upper - lower, status=status, mime=mime)
            return True

        dls = self.conn.hsrv.dls
        if is_tail:
            upper = 1 << 30
            if len(dls) > self.args.tail_cmax:
                raise Pebkac(400, "too many active downloads to start a new tail")

        if upper - lower > 0x400000:  # 4m
            now = time.time()
            self.dl_id = "%s:%s" % (self.ip, self.addr[1])
            dls[self.dl_id] = (now, 0)
            self.conn.hsrv.dli[self.dl_id] = (
                now,
                0 if is_tail else upper - lower,
                self.vn,
                self.vpath,
                self.uname,
            )

        if ptop is not None:
            assert job and ap_data  # type: ignore  # !rm
            return self.tx_pipe(
                ptop, req_path, ap_data, job, lower, upper, status, mime, logmsg
            )
        elif is_tail:
            self.tx_tail(open_args, status, mime)
            return False

        ret = True
        with open_func(*open_args) as f:
            self.send_headers(length=upper - lower, status=status, mime=mime)

            sendfun = sendfile_kern if use_sendfile else sendfile_py
            remains = sendfun(
                self.log,
                lower,
                upper,
                f,
                self.s,
                self.args.s_wr_sz,
                self.args.s_wr_slp,
                not self.args.no_poll,
                dls,
                self.dl_id,
            )

        if remains > 0:
            logmsg += " \033[31m" + unicode(upper - remains) + "\033[0m"
            ret = False

        spd = self._spd((upper - lower) - remains)
        if self.do_log:
            self.log("{},  {}".format(logmsg, spd))

        return ret

    def tx_tail(
        self,
        open_args: list[Any],
        status: int,
        mime: str,
    ) -> None:
        vf = self.vn.flags
        self.send_headers(length=None, status=status, mime=mime)
        abspath: bytes = open_args[0]
        sec_rate = vf["tail_rate"]
        sec_max = vf["tail_tmax"]
        sec_fd = vf["tail_fd"]
        sec_ka = self.args.tail_ka
        wr_slp = self.args.s_wr_slp
        wr_sz = self.args.s_wr_sz
        dls = self.conn.hsrv.dls
        dl_id = self.dl_id

        # non-numeric = full file from start
        # positive = absolute offset from start
        # negative = start that many bytes from eof
        try:
            ofs = int(self.uparam["tail"])
        except (ValueError, KeyError):
            ofs = 0

        t0 = time.time()
        ofs0 = ofs
        f = None
        try:
            st = os.stat(abspath)
            f = open(*open_args)
            f.seek(0, os.SEEK_END)
            eof = f.tell()
            f.seek(0)
            if ofs < 0:
                ofs = max(0, ofs + eof)

            self.log("tailing from byte %d: %r" % (ofs, abspath), 6)

            # send initial data asap
            remains = sendfile_py(
                self.log,  # d/c
                ofs,
                eof,
                f,
                self.s,
                wr_sz,
                wr_slp,
                False,  # d/c
                dls,
                dl_id,
            )
            sent = (eof - ofs) - remains
            ofs = eof - remains
            f.seek(ofs)

            try:
                st2 = os.stat(open_args[0])
                if st.st_ino == st2.st_ino:
                    st = st2  # for filesize
            except OSError:
                pass

            gone = 0
            t_fd = t_ka = time.time()
            while True:
                assert f  # !rm
                buf = f.read(4096)
                now = time.time()

                if sec_max and now - t0 >= sec_max:
                    self.log("max duration exceeded; kicking client", 6)
                    zb = b"\n\n*** max duration exceeded; disconnecting ***\n"
                    self.s.sendall(zb)
                    break

                if buf:
                    t_fd = t_ka = now
                    self.s.sendall(buf)
                    sent += len(buf)
                    dls[dl_id] = (time.time(), sent)
                    continue

                time.sleep(sec_rate)
                if t_ka < now - sec_ka:
                    t_ka = now
                    self.s.send(b"\x00")
                if t_fd < now - sec_fd:
                    try:
                        st2 = os.stat(open_args[0])
                        if (
                            st2.st_ino != st.st_ino
                            or st2.st_size < sent
                            or st2.st_size < st.st_size
                        ):
                            assert f  # !rm
                            # open new file before closing previous to avoid toctous (open may fail; cannot null f before)
                            f2 = open(*open_args)
                            f.close()
                            f = f2
                            f.seek(0, os.SEEK_END)
                            eof = f.tell()
                            if eof < sent:
                                ofs = sent = 0  # shrunk; send from start
                                zb = b"\n\n*** file size decreased -- rewinding to the start of the file ***\n\n"
                                self.s.sendall(zb)
                                if ofs0 < 0 and eof > -ofs0:
                                    ofs = eof + ofs0
                            else:
                                ofs = sent  # just new fd? resume from same ofs
                            f.seek(ofs)
                            self.log("reopened at byte %d: %r" % (ofs, abspath), 6)
                            gone = 0
                        st = st2
                    except (OSError, IOError):
                        gone += 1
                        if gone > 3:
                            self.log("file deleted; disconnecting")
                            break
        except IOError as ex:
            if ex.errno not in E_SCK_WR:
                raise
        finally:
            if f:
                f.close()

    def tx_pipe(
        self,
        ptop: str,
        req_path: str,
        ap_data: str,
        job: dict[str, Any],
        lower: int,
        upper: int,
        status: int,
        mime: str,
        logmsg: str,
    ) -> bool:
        M = 1048576
        self.send_headers(length=upper - lower, status=status, mime=mime)
        wr_slp = self.args.s_wr_slp
        wr_sz = self.args.s_wr_sz
        file_size = job["size"]
        chunk_size = up2k_chunksize(file_size)
        num_need = -1
        data_end = 0
        remains = upper - lower
        broken = False
        spins = 0
        tier = 0
        tiers = ["uncapped", "reduced speed", "one byte per sec"]

        while lower < upper and not broken:
            with self.u2mutex:
                job = self.pipes.get(req_path)
                if not job:
                    x = self.conn.hsrv.broker.ask("up2k.find_job_by_ap", ptop, req_path)
                    job = json.loads(x.get())
                    if job:
                        self.pipes.set(req_path, job)

            if not job:
                t = "pipe: OK, upload has finished; yeeting remainder"
                self.log(t, 2)
                data_end = file_size
                break

            if num_need != len(job["need"]) and data_end - lower < 8 * M:
                num_need = len(job["need"])
                data_end = 0
                for cid in job["hash"]:
                    if cid in job["need"]:
                        break
                    data_end += chunk_size
                t = "pipe: can stream %.2f MiB; requested range is %.2f to %.2f"
                self.log(t % (data_end / M, lower / M, upper / M), 6)
                with self.u2mutex:
                    if data_end > self.u2fh.aps.get(ap_data, data_end):
                        fhs: Optional[set[typing.BinaryIO]] = None
                        try:
                            fhs = self.u2fh.cache[ap_data].all_fhs
                            for fh in fhs:
                                fh.flush()
                            self.u2fh.aps[ap_data] = data_end
                            self.log("pipe: flushed %d up2k-FDs" % (len(fhs),))
                        except Exception as ex:
                            if fhs is None:
                                err = "file is not being written to right now"
                            else:
                                err = repr(ex)
                            self.log("pipe: u2fh flush failed: " + err)

            if lower >= data_end:
                if data_end:
                    t = "pipe: uploader is too slow; aborting download at %.2f MiB"
                    self.log(t % (data_end / M,))
                    raise Pebkac(416, "uploader is too slow")

                raise Pebkac(416, "no data available yet; please retry in a bit")

            slack = data_end - lower
            if slack >= 8 * M:
                ntier = 0
                winsz = M
                bufsz = wr_sz
                slp = wr_slp
            else:
                winsz = max(40, int(M * (slack / (12 * M))))
                base_rate = M if not wr_slp else wr_sz / wr_slp
                if winsz > base_rate:
                    ntier = 0
                    bufsz = wr_sz
                    slp = wr_slp
                elif winsz > 300:
                    ntier = 1
                    bufsz = winsz // 5
                    slp = 0.2
                else:
                    ntier = 2
                    bufsz = winsz = slp = 1

            if tier != ntier:
                tier = ntier
                self.log("moved to tier %d (%s)" % (tier, tiers[tier]))

            try:
                with open(ap_data, "rb", self.args.iobuf) as f:
                    f.seek(lower)
                    page = f.read(min(winsz, data_end - lower, upper - lower))
                if not page:
                    raise Exception("got 0 bytes (EOF?)")
            except Exception as ex:
                self.log("pipe: read failed at %.2f MiB: %s" % (lower / M, ex), 3)
                with self.u2mutex:
                    self.pipes.c.pop(req_path, None)
                spins += 1
                if spins > 3:
                    raise Pebkac(500, "file became unreadable")
                time.sleep(2)
                continue

            spins = 0
            pofs = 0
            while pofs < len(page):
                if slp:
                    time.sleep(slp)

                try:
                    buf = page[pofs : pofs + bufsz]
                    self.s.sendall(buf)
                    zi = len(buf)
                    remains -= zi
                    lower += zi
                    pofs += zi
                except OSError:
                    broken = True
                    break

        if lower < upper and not broken:
            with open(req_path, "rb") as f:
                remains = sendfile_py(
                    self.log,
                    lower,
                    upper,
                    f,
                    self.s,
                    wr_sz,
                    wr_slp,
                    not self.args.no_poll,
                    self.conn.hsrv.dls,
                    self.dl_id,
                )

        spd = self._spd((upper - lower) - remains)
        if self.do_log:
            self.log("{},  {}".format(logmsg, spd))

        return not broken

    def tx_zip(
        self,
        fmt: str,
        uarg: str,
        vpath: str,
        vn: "VFS",
        rem: str,
        items: list[str],
    ) -> bool:
        t = self._can_zip(vn.flags)
        if t:
            raise Pebkac(400, t)

        logmsg = "{:4} {} ".format("", self.req)
        self.keepalive = False

        cancmp = not self.args.no_tarcmp

        if fmt == "tar":
            packer: Type[StreamArc] = StreamTar
            if cancmp and "gz" in uarg:
                mime = "application/gzip"
                ext = "tar.gz"
            elif cancmp and "bz2" in uarg:
                mime = "application/x-bzip"
                ext = "tar.bz2"
            elif cancmp and "xz" in uarg:
                mime = "application/x-xz"
                ext = "tar.xz"
            else:
                mime = "application/x-tar"
                ext = "tar"
        else:
            mime = "application/zip"
            packer = StreamZip
            ext = "zip"

        dots = 0 if "nodot" in self.uparam else 1
        scandir = not self.args.no_scandir

        fn = self.vpath.split("/")[-1] or self.host.split(":")[0]
        if items:
            fn = "sel-" + fn

        if vn.flags.get("zipmax") and not (
            vn.flags.get("zipmaxu") and self.uname != "*"
        ):
            maxs = vn.flags.get("zipmaxs_v") or 0
            maxn = vn.flags.get("zipmaxn_v") or 0
            nf = 0
            nb = 0
            fgen = vn.zipgen(vpath, rem, set(items), self.uname, False, dots, scandir)
            t = "total size exceeds a limit specified in server config"
            t = vn.flags.get("zipmaxt") or t
            if maxs and maxn:
                for zd in fgen:
                    nf += 1
                    nb += zd["st"].st_size
                    if maxs < nb or maxn < nf:
                        raise Pebkac(400, t)
            elif maxs:
                for zd in fgen:
                    nb += zd["st"].st_size
                    if maxs < nb:
                        raise Pebkac(400, t)
            elif maxn:
                for zd in fgen:
                    nf += 1
                    if maxn < nf:
                        raise Pebkac(400, t)

        cdis = gen_content_disposition("%s.%s" % (fn, ext))
        self.log(repr(cdis))
        self.send_headers(None, mime=mime, headers={"Content-Disposition": cdis})

        fgen = vn.zipgen(vpath, rem, set(items), self.uname, False, dots, scandir)
        # for f in fgen: print(repr({k: f[k] for k in ["vp", "ap"]}))
        cfmt = ""
        if self.thumbcli and not self.args.no_bacode:
            if uarg in ZIP_XCODE_S:
                cfmt = uarg
            else:
                for zs in ZIP_XCODE_L:
                    if zs in self.ouparam:
                        cfmt = zs

            if cfmt:
                self.log("transcoding to [{}]".format(cfmt))
                fgen = gfilter(fgen, self.thumbcli, self.uname, vpath, cfmt)

        now = time.time()
        self.dl_id = "%s:%s" % (self.ip, self.addr[1])
        self.conn.hsrv.dli[self.dl_id] = (
            now,
            0,
            self.vn,
            "%s :%s" % (self.vpath, ext),
            self.uname,
        )
        dls = self.conn.hsrv.dls
        dls[self.dl_id] = (time.time(), 0)

        bgen = packer(
            self.log,
            self.asrv,
            fgen,
            utf8="utf" in uarg or not uarg,
            pre_crc="crc" in uarg,
            cmp=uarg if cancmp or uarg == "pax" else "",
        )
        n = 0
        bsent = 0
        for buf in bgen.gen():
            if not buf:
                break

            try:
                self.s.sendall(buf)
                bsent += len(buf)
            except OSError:
                logmsg += " \033[31m" + unicode(bsent) + "\033[0m"
                bgen.stop()
                break

            n += 1
            if n >= 4:
                n = 0
                dls[self.dl_id] = (time.time(), bsent)

        spd = self._spd(bsent)
        self.log("{},  {}".format(logmsg, spd))
        return True

    def tx_ico(self, ext: str, exact: bool = False) -> bool:
        self.permit_caching()
        if ext.endswith("/"):
            ext = "folder"
            exact = True

        bad = re.compile(r"[](){}/ []|^[0-9_-]*$")
        n = ext.split(".")[::-1]
        if not exact:
            n = n[:-1]

        ext = ""
        for v in n:
            if len(v) > 7 or bad.search(v):
                break

            ext = "{}.{}".format(v, ext)

        ext = ext.rstrip(".") or "unk"
        if len(ext) > 11:
            ext = "~" + ext[-9:]

        return self.tx_svg(ext, exact)

    def tx_svg(self, txt: str, small: bool = False) -> bool:
        # chrome cannot handle more than ~2000 unique SVGs
        # so url-param "raster" returns a png/webp instead
        # (useragent-sniffing kinshi due to caching proxies)
        mime, ico = self.ico.get(txt, not small, "raster" in self.uparam)

        lm = formatdate(self.E.t0)
        self.reply(ico, mime=mime, headers={"Last-Modified": lm})
        return True

    def tx_qr(self):
        url = "%s://%s%s%s" % (
            "https" if self.is_https else "http",
            self.host,
            self.args.SRS,
            self.vpaths,
        )
        uhash = ""
        uparams = []
        if self.ouparam:
            for k, v in self.ouparam.items():
                if k == "qr":
                    continue
                if k == "uhash":
                    uhash = v
                    continue
                uparams.append(k if v == "" else "%s=%s" % (k, v))
        if uparams:
            url += "?" + "&".join(uparams)
        if uhash:
            url += "#" + uhash

        self.log("qrcode(%r)" % (url,))
        ret = qr2svg(qrgen(url.encode("utf-8")), 2)
        self.reply(ret.encode("utf-8"), mime="image/svg+xml")
        return True

    def tx_md(self, vn: "VFS", fs_path: str) -> bool:
        logmsg = "     %s @%s " % (self.req, self.uname)

        if not self.can_write:
            if "edit" in self.uparam or "edit2" in self.uparam:
                return self.tx_404(True)

        tpl = "mde" if "edit2" in self.uparam else "md"
        template = self.j2j(tpl)

        st = bos.stat(fs_path)
        ts_md = st.st_mtime

        max_sz = 1024 * self.args.txt_max
        sz_md = 0
        lead = b""
        fullfile = b""
        for buf in yieldfile(fs_path, self.args.iobuf):
            if sz_md < max_sz:
                fullfile += buf
            else:
                fullfile = b""

            if not sz_md and buf.startswith((b"\n", b"\r\n")):
                lead = b"\n" if buf.startswith(b"\n") else b"\r\n"
                sz_md += len(lead)

            sz_md += len(buf)
            for c, v in [(b"&", 4), (b"<", 3), (b">", 3)]:
                sz_md += (len(buf) - len(buf.replace(c, b""))) * v

        if (
            fullfile
            and "exp" in vn.flags
            and "edit" not in self.uparam
            and "edit2" not in self.uparam
            and vn.flags.get("exp_md")
        ):
            fulltxt = fullfile.decode("utf-8", "replace")
            fulltxt = self._expand(fulltxt, vn.flags.get("exp_md") or [])
            fullfile = fulltxt.encode("utf-8", "replace")

        if fullfile:
            fullfile = html_bescape(fullfile)
            sz_md = len(lead) + len(fullfile)

        file_ts = int(max(ts_md, self.E.t0))
        file_lastmod, do_send, _ = self._chk_lastmod(file_ts)
        self.out_headers["Last-Modified"] = file_lastmod
        self.out_headers["Cache-Control"] = "no-cache"
        status = 200 if do_send else 304

        arg_base = "?"
        if "k" in self.uparam:
            arg_base = "?k={}&".format(self.uparam["k"])

        boundary = "\roll\tide"
        targs = {
            "r": self.args.SR if self.is_vproxied else "",
            "ts": self.conn.hsrv.cachebuster(),
            "edit": "edit" in self.uparam,
            "title": html_escape(self.vpath, crlf=True),
            "lastmod": int(ts_md * 1000),
            "lang": self.cookies.get("cplng") or self.args.lang,
            "favico": self.args.favico,
            "have_emp": int(self.args.emp),
            "md_no_br": int(vn.flags.get("md_no_br") or 0),
            "md_chk_rate": self.args.mcr,
            "md": boundary,
            "arg_base": arg_base,
        }

        if self.args.js_other and "js" not in targs:
            zs = self.args.js_other
            zs += "&" if "?" in zs else "?"
            targs["js"] = zs

        if "html_head_d" in self.vn.flags:
            targs["this"] = self
            self._build_html_head(targs)

        targs["html_head"] = self.html_head
        zs = template.render(**targs).encode("utf-8", "replace")
        html = zs.split(boundary.encode("utf-8"))
        if len(html) != 2:
            raise Exception("boundary appears in " + tpl)

        self.send_headers(sz_md + len(html[0]) + len(html[1]), status)

        logmsg += unicode(status)
        if self.mode == "HEAD" or not do_send:
            if self.do_log:
                self.log(logmsg)

            return True

        try:
            self.s.sendall(html[0] + lead)
            if fullfile:
                self.s.sendall(fullfile)
            else:
                for buf in yieldfile(fs_path, self.args.iobuf):
                    self.s.sendall(html_bescape(buf))

            self.s.sendall(html[1])

        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            self.log(logmsg + " \033[31md/c\033[0m")
            return False

        if self.do_log:
            self.log(logmsg + " " + unicode(len(html)))

        return True
