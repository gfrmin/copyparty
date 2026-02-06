"""Multi-threaded file hashing."""

from __future__ import print_function, unicode_literals

import hashlib
import math
import threading
import typing
from queue import Queue
from typing import Optional

from .util import Daemon, ProgressPrinter, RAM_AVAIL, ub64enc


class MTHash(object):
    def __init__(self, cores: int):
        self.pp: Optional[ProgressPrinter] = None
        self.f: Optional[typing.BinaryIO] = None
        self.sz = 0
        self.csz = 0
        self.stop = False
        self.readsz = 1024 * 1024 * (2 if (RAM_AVAIL or 2) < 1 else 12)
        self.omutex = threading.Lock()
        self.imutex = threading.Lock()
        self.work_q: Queue[int] = Queue()
        self.done_q: Queue[tuple[int, str, int, int]] = Queue()
        self.thrs = []
        for n in range(cores):
            t = Daemon(self.worker, "mth-" + str(n))
            self.thrs.append(t)

    def hash(
        self,
        f: typing.BinaryIO,
        fsz: int,
        chunksz: int,
        pp: Optional[ProgressPrinter] = None,
        prefix: str = "",
        suffix: str = "",
    ) -> list[tuple[str, int, int]]:
        with self.omutex:
            self.f = f
            self.sz = fsz
            self.csz = chunksz

            chunks: dict[int, tuple[str, int, int]] = {}
            nchunks = int(math.ceil(fsz / chunksz))
            for nch in range(nchunks):
                self.work_q.put(nch)

            ex: Optional[Exception] = None
            for nch in range(nchunks):
                qe = self.done_q.get()
                try:
                    nch, dig, ofs, csz = qe
                    chunks[nch] = (dig, ofs, csz)
                except (ValueError, TypeError):
                    ex = ex or qe  # type: ignore

                if pp:
                    mb = (fsz - nch * chunksz) // (1024 * 1024)
                    pp.msg = prefix + str(mb) + suffix

            if ex:
                raise ex

            ret = []
            for n in range(nchunks):
                ret.append(chunks[n])

            self.f = None
            self.csz = 0
            self.sz = 0
            return ret

    def worker(self) -> None:
        while True:
            ofs = self.work_q.get()
            try:
                v = self.hash_at(ofs)
            except Exception as ex:
                v = ex  # type: ignore

            self.done_q.put(v)

    def hash_at(self, nch: int) -> tuple[int, str, int, int]:
        f = self.f
        ofs = ofs0 = nch * self.csz
        chunk_sz = chunk_rem = min(self.csz, self.sz - ofs)
        if self.stop:
            return nch, "", ofs0, chunk_sz

        assert f  # !rm
        hashobj = hashlib.sha512()
        while chunk_rem > 0:
            with self.imutex:
                f.seek(ofs)
                buf = f.read(min(chunk_rem, self.readsz))

            if not buf:
                raise Exception("EOF at " + str(ofs))

            hashobj.update(buf)
            chunk_rem -= len(buf)
            ofs += len(buf)

        bdig = hashobj.digest()[:33]
        udig = ub64enc(bdig).decode("ascii")
        return nch, udig, ofs0, chunk_sz
