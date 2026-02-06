"""Multipart form-data parsing for HTTP uploads."""

from __future__ import print_function, unicode_literals

import argparse
import re
import time
from typing import TYPE_CHECKING, Generator, Iterable, Optional

from .util import Pebkac, Unrecv, WrongPostKey

if TYPE_CHECKING:
    from .util import NamedLogger


RE_CTYPE = re.compile(r"^content-type: *([^; ]+)", re.IGNORECASE)
RE_CDISP = re.compile(r"^content-disposition: *([^; ]+)", re.IGNORECASE)
RE_CDISP_FIELD = re.compile(
    r'^content-disposition:(?: *|.*; *)name="([^"]+)"', re.IGNORECASE
)
RE_CDISP_FILE = re.compile(
    r'^content-disposition:(?: *|.*; *)filename="(.*)"', re.IGNORECASE
)


class MultipartParser(object):
    def __init__(
        self,
        log_func: "NamedLogger",
        args: argparse.Namespace,
        sr: Unrecv,
        http_headers: dict[str, str],
    ):
        self.sr = sr
        self.log = log_func
        self.args = args
        self.headers = http_headers
        try:
            self.clen = int(http_headers["content-length"])
            sr.nb = 0
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            self.clen = 0

        self.re_ctype = RE_CTYPE
        self.re_cdisp = RE_CDISP
        self.re_cdisp_field = RE_CDISP_FIELD
        self.re_cdisp_file = RE_CDISP_FILE

        self.boundary = b""
        self.gen: Optional[
            Generator[
                tuple[str, Optional[str], Generator[bytes, None, None]], None, None
            ]
        ] = None

    def _read_header(self) -> tuple[str, Optional[str]]:
        """
        returns [fieldname, filename] after eating a block of multipart headers
        while doing a decent job at dealing with the absolute mess that is
        rfc1341/rfc1521/rfc2047/rfc2231/rfc2388/rfc6266/the-real-world
        (only the fallback non-js uploader relies on these filenames)
        """
        for ln in read_header(self.sr, 2, 2592000):
            self.log(repr(ln))

            m = self.re_ctype.match(ln)
            if m:
                if m.group(1).lower() == "multipart/mixed":
                    # rfc-7578 overrides rfc-2388 so this is not-impl
                    # (opera >=9 <11.10 is the only thing i've ever seen use it)
                    raise Pebkac(
                        400,
                        "you can't use that browser to upload multiple files at once",
                    )

                continue

            # the only other header we care about is content-disposition
            m = self.re_cdisp.match(ln)
            if not m:
                continue

            if m.group(1).lower() != "form-data":
                raise Pebkac(400, "not form-data: %r" % (ln,))

            try:
                field = self.re_cdisp_field.match(ln).group(1)  # type: ignore
            except (AttributeError, IndexError):
                raise Pebkac(400, "missing field name: %r" % (ln,))

            try:
                fn = self.re_cdisp_file.match(ln).group(1)  # type: ignore
            except (AttributeError, IndexError):
                # this is not a file upload, we're done
                return field, None

            try:
                is_webkit = "applewebkit" in self.headers["user-agent"].lower()
            except (KeyError, AttributeError):
                is_webkit = False

            # chromes ignore the spec and makes this real easy
            if is_webkit:
                # quotes become %22 but they don't escape the %
                # so unescaping the quotes could turn messi
                return field, fn.split('"')[0]

            # also ez if filename doesn't contain "
            if not fn.split('"')[0].endswith("\\"):
                return field, fn.split('"')[0]

            # this breaks on firefox uploads that contain \"
            # since firefox escapes " but forgets to escape \
            # so it'll truncate after the \
            ret = ""
            esc = False
            for ch in fn:
                if esc:
                    esc = False
                    if ch not in ['"', "\\"]:
                        ret += "\\"
                    ret += ch
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    break
                else:
                    ret += ch

            return field, ret

        raise Pebkac(400, "server expected a multipart header but you never sent one")

    def _read_data(self) -> Generator[bytes, None, None]:
        blen = len(self.boundary)
        bufsz = self.args.s_rd_sz
        while True:
            try:
                buf = self.sr.recv(bufsz)
            except (OSError, ValueError, TypeError, UnicodeDecodeError):
                # abort: client disconnected
                raise Pebkac(400, "client d/c during multipart post")

            while True:
                ofs = buf.find(self.boundary)
                if ofs != -1:
                    self.sr.unrecv(buf[ofs + blen :])
                    yield buf[:ofs]
                    return

                d = len(buf) - blen
                if d > 0:
                    # buffer growing large; yield everything except
                    # the part at the end (maybe start of boundary)
                    yield buf[:d]
                    buf = buf[d:]

                # look for boundary near the end of the buffer
                n = 0
                for n in range(1, len(buf) + 1):
                    if not buf[-n:] in self.boundary:
                        n -= 1
                        break

                if n == 0 or not self.boundary.startswith(buf[-n:]):
                    # no boundary contents near the buffer edge
                    break

                if blen == n:
                    # EOF: found boundary
                    yield buf[:-n]
                    return

                try:
                    buf += self.sr.recv(bufsz)
                except (OSError, ValueError, TypeError, UnicodeDecodeError):
                    # abort: client disconnected
                    raise Pebkac(400, "client d/c during multipart post")

            yield buf

    def _run_gen(
        self,
    ) -> Generator[tuple[str, Optional[str], Generator[bytes, None, None]], None, None]:
        """
        yields [fieldname, unsanitized_filename, fieldvalue]
        where fieldvalue yields chunks of data
        """
        run = True
        while run:
            fieldname, filename = self._read_header()
            yield (fieldname, filename, self._read_data())

            tail = self.sr.recv_ex(2, False)

            if tail == b"--":
                # EOF indicated by this immediately after final boundary
                if self.clen == self.sr.nb:
                    tail = b"\r\n"  # dillo doesn't terminate with trailing \r\n
                else:
                    tail = self.sr.recv_ex(2, False)
                run = False

            if tail != b"\r\n":
                t = "protocol error after field value: want b'\\r\\n', got {!r}"
                raise Pebkac(400, t.format(tail))

    def _read_value(self, iterable: Iterable[bytes], max_len: int) -> bytes:
        ret = b""
        for buf in iterable:
            ret += buf
            if len(ret) > max_len:
                raise Pebkac(422, "field length is too long")

        return ret

    def parse(self) -> None:
        boundary = get_boundary(self.headers)
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]  # dillo uses quotes
        self.log("boundary=%r" % (boundary,))

        # spec says there might be junk before the first boundary,
        # can't have the leading \r\n if that's not the case
        self.boundary = b"--" + boundary.encode("utf-8")

        # discard junk before the first boundary
        for junk in self._read_data():
            if not junk:
                continue

            jtxt = junk.decode("utf-8", "replace")
            self.log("discarding preamble |%d| %r" % (len(junk), jtxt))

        # nice, now make it fast
        self.boundary = b"\r\n" + self.boundary
        self.gen = self._run_gen()

    def require(self, field_name: str, max_len: int) -> str:
        """
        returns the value of the next field in the multipart body,
        raises if the field name is not as expected
        """
        assert self.gen  # !rm
        p_field, p_fname, p_data = next(self.gen)
        if p_field != field_name:
            raise WrongPostKey(field_name, p_field, p_fname, p_data)

        return self._read_value(p_data, max_len).decode("utf-8", "surrogateescape")

    def drop(self) -> None:
        """discards the remaining multipart body"""
        assert self.gen  # !rm
        for _, _, data in self.gen:
            for _ in data:
                pass


def get_boundary(headers: dict[str, str]) -> str:
    # boundaries contain a-z A-Z 0-9 ' ( ) + _ , - . / : = ?
    # (whitespace allowed except as the last char)
    ptn = r"^multipart/form-data *; *(.*; *)?boundary=([^;]+)"
    ct = headers["content-type"]
    m = re.match(ptn, ct, re.IGNORECASE)
    if not m:
        raise Pebkac(400, "invalid content-type for a multipart post: %r" % (ct,))

    return m.group(2)


def read_header(sr: Unrecv, t_idle: int, t_tot: int) -> list[str]:
    t0 = time.time()
    ret = b""
    while True:
        if time.time() - t0 >= t_tot:
            return []

        try:
            ret += sr.recv(1024, t_idle // 2)
        except (KeyError, IndexError):
            if not ret:
                return []

            raise Pebkac(
                400,
                "protocol error while reading headers",
                log=ret.decode("utf-8", "replace"),
            )

        ofs = ret.find(b"\r\n\r\n")
        if ofs < 0:
            if len(ret) > 1024 * 32:
                raise Pebkac(400, "header 2big")
            else:
                continue

        if len(ret) > ofs + 4:
            sr.unrecv(ret[ofs + 4 :])

        return ret[:ofs].decode("utf-8", "surrogateescape").lstrip("\r\n").split("\r\n")
