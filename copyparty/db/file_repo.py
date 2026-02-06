"""File database repository for up2k upload tracking.

Mirrors the up2k DB schema from up2k._create_db:
  table up (w text, mt int, sz int, rd text, fn text, ip text, at int, un text)
    -- wark, mtime, size, directory, filename, upload-ip, upload-time, username
  table mt (w text, k text, v int)
    -- wark-prefix, tag-key, tag-value
  table kv (k text, v int)
    -- key, value
  table dh (d text, h text)
    -- directory, dir-hash
  table iu (c int, w text, rd text, fn text)
    -- cooldown, wark-prefix, directory, filename
  table cv (rd text, dn text, fn text)
    -- directory, subdir, cover-filename
  table ds (rd text, sz int, nf int)
    -- directory, total-size, num-files
  indexes: up_w, up_vp, up_fn, up_ip, up_at, mt_w, mt_k, mt_v, kv_k, dh_d, iu_c, iu_w, cv_i, ds_rd
  kv table with schemaver=6
"""
from __future__ import print_function, unicode_literals

import base64
import sqlite3


class FileRepository(object):
    """Encapsulates SQLite operations for the up2k file database.

    Manages the 'up', 'mt', 'kv', 'dh', 'iu', 'cv', and 'ds' tables.
    """

    DB_VER = 6

    def __init__(self, db_path, timeout=86400, no_expr_idx=False):
        # type: (str, int, bool) -> None
        self.db_path = db_path
        self.timeout = timeout
        self.no_expr_idx = no_expr_idx
        self.cur = None  # type: sqlite3.Cursor | None
        self._conn = None  # type: sqlite3.Connection | None
        self._mem_cur = None  # type: sqlite3.Cursor | None

    def _get_mem_cur(self):
        # type: () -> sqlite3.Cursor
        """Get an in-memory cursor for s3enc testing."""
        if self._mem_cur is None:
            mc = sqlite3.connect(":memory:").cursor()
            mc.execute("create table a (b text)")
            self._mem_cur = mc
        return self._mem_cur

    def open(self):
        # type: () -> FileRepository
        """Open or create the database."""
        self._conn = sqlite3.connect(self.db_path, timeout=self.timeout)
        self._conn.execute("pragma journal_mode=wal")
        self.cur = self._conn.cursor()
        return self

    def wrap_cursor(self, cur):
        # type: (sqlite3.Cursor) -> FileRepository
        """Wrap an existing cursor/connection instead of opening a new one.

        Used when the database is already opened by existing code (e.g., up2k._open_db).
        """
        self.cur = cur
        self._conn = cur.connection
        return self

    def close(self):
        # type: () -> None
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.commit()
            except (OSError, ValueError, TypeError, UnicodeDecodeError):
                pass
            self._conn.close()
            self._conn = None
            self.cur = None

    def commit(self):
        # type: () -> None
        if self._conn:
            self._conn.commit()

    def vacuum(self):
        # type: () -> None
        if self._conn:
            self._conn.execute("vacuum")

    def get_cursor(self):
        # type: () -> sqlite3.Cursor
        assert self.cur is not None
        return self.cur

    def create_schema(self):
        # type: () -> None
        """Create all tables for the file database."""
        assert self.cur is not None
        c = self.cur
        c.execute(
            "create table if not exists up "
            "(w text, mt int, sz int, rd text, fn text, ip text, at int, un text)"
        )
        c.execute("create table if not exists mt (w text, k text, v int)")
        c.execute("create table if not exists kv (k text, v int)")
        c.execute("create table if not exists dh (d text, h text)")
        c.execute("create table if not exists iu (c int, w text, rd text, fn text)")
        c.execute("create table if not exists cv (rd text, dn text, fn text)")
        c.execute("create table if not exists ds (rd text, sz int, nf int)")

        # Create indexes
        if not self.no_expr_idx:
            try:
                c.execute("create index if not exists up_w on up (substr(w,1,16))")
            except Exception:
                self.no_expr_idx = True

        if self.no_expr_idx:
            c.execute("create index if not exists up_w on up (w)")

        c.execute("create index if not exists up_vp on up (rd, fn)")
        c.execute("create index if not exists up_fn on up (fn)")
        c.execute("create index if not exists up_ip on up (ip)")
        c.execute("create index if not exists up_at on up (at)")
        c.execute("create index if not exists mt_w on mt (w)")
        c.execute("create index if not exists mt_k on mt (k)")
        c.execute("create index if not exists mt_v on mt (v)")
        c.execute("create unique index if not exists kv_k on kv (k)")
        c.execute("create index if not exists dh_d on dh (d)")
        c.execute("create index if not exists iu_c on iu (c)")
        c.execute("create index if not exists iu_w on iu (w)")
        c.execute("create index if not exists cv_i on cv (rd, dn)")
        c.execute("create index if not exists ds_rd on ds (rd)")

        self.set_kv("schemaver", self.DB_VER)
        self.commit()

    def _s3enc(self, rd, fn):
        # type: (str, str) -> tuple[str, str]
        """Encode mojibake strings for SQLite compatibility."""
        mem_cur = self._get_mem_cur()
        ret = []  # type: list[str]
        for v in [rd, fn]:
            try:
                mem_cur.execute("select * from a where b = ?", (v,))
                ret.append(v)
            except (UnicodeEncodeError, UnicodeDecodeError):
                ret.append("//" + base64.b64encode(v.encode("utf-8", "surrogateescape")).decode())
        return ret[0], ret[1]

    # --- Upload records (up table) ---

    def find_file(self, rd, fn):
        # type: (str, str) -> tuple | None
        """Find a file by directory and filename."""
        assert self.cur is not None
        sql = "select w, mt, sz, rd, fn, ip, at, un from up where rd = ? and fn = ?"
        try:
            rows = self.cur.execute(sql, (rd, fn)).fetchall()
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            rd2, fn2 = self._s3enc(rd, fn)
            rows = self.cur.execute(sql, (rd2, fn2)).fetchall()
        return rows[0] if rows else None

    def find_files_by_wark(self, wark):
        # type: (str) -> list[tuple]
        """Find files by wark (hash ID)."""
        assert self.cur is not None
        if self.no_expr_idx:
            sql = "select w, mt, sz, rd, fn, ip, at, un from up where w = ?"
            return self.cur.execute(sql, (wark,)).fetchall()
        else:
            wp = wark[:16]
            sql = "select w, mt, sz, rd, fn, ip, at, un from up where substr(w,1,16) = ? and +w = ?"
            return self.cur.execute(sql, (wp, wark)).fetchall()

    def find_files_by_dir(self, rd):
        # type: (str) -> list[str]
        """Find all filenames in a directory."""
        assert self.cur is not None
        sql = "select fn from up where rd = ?"
        return [r[0] for r in self.cur.execute(sql, (rd,)).fetchall()]

    def insert_file(self, wark, mt, sz, rd, fn, ip, at, un):
        # type: (str, int, int, str, str, str, int, str) -> None
        """Insert a file record."""
        assert self.cur is not None
        sql = "insert into up values (?,?,?,?,?,?,?,?)"
        self.cur.execute(sql, (wark, mt, sz, rd, fn, ip, at, un))

    def delete_file(self, rd, fn):
        # type: (str, str) -> int
        """Delete a file record. Returns number of rows deleted."""
        assert self.cur is not None
        sql = "delete from up where rd = ? and fn = ?"
        try:
            self.cur.execute(sql, (rd, fn))
        except Exception:
            rd2, fn2 = self._s3enc(rd, fn)
            self.cur.execute(sql, (rd2, fn2))
        return self.cur.rowcount

    def count_files(self):
        # type: () -> int
        """Count total files."""
        assert self.cur is not None
        return self.cur.execute("select count(*) from up").fetchone()[0]

    # --- Metadata (mt table) ---

    def get_tags(self, wark_prefix):
        # type: (str) -> list[tuple[str, int]]
        """Get tags for a file by wark prefix."""
        assert self.cur is not None
        sql = "select k, v from mt where w = ?"
        return self.cur.execute(sql, (wark_prefix,)).fetchall()

    def insert_tag(self, wark_prefix, key, value):
        # type: (str, str, int) -> None
        """Insert a metadata tag."""
        assert self.cur is not None
        self.cur.execute("insert into mt values (?,?,?)", (wark_prefix, key, value))

    def delete_tags(self, wark_prefix):
        # type: (str) -> None
        """Delete all tags for a file."""
        assert self.cur is not None
        self.cur.execute("delete from mt where w = ?", (wark_prefix,))

    def delete_tags_by_keys(self, wark_prefix, keys):
        # type: (str, list[str]) -> None
        """Delete tags matching specific keys for a wark prefix."""
        assert self.cur is not None
        placeholders = " or ".join("+k = ?" for _ in keys)
        sql = "delete from mt where w = ? and ({})".format(placeholders)
        self.cur.execute(sql, [wark_prefix] + keys)

    def count_tags(self):
        # type: () -> int
        """Count total tags."""
        assert self.cur is not None
        return self.cur.execute("select count(*) from mt").fetchone()[0]

    # --- Key-value (kv table) ---

    def get_kv(self, key):
        # type: (str) -> int | None
        """Get a key-value pair."""
        assert self.cur is not None
        rows = self.cur.execute("select v from kv where k = ?", (key,)).fetchall()
        return rows[0][0] if rows else None

    def set_kv(self, key, value):
        # type: (str, int) -> None
        """Set a key-value pair (upsert)."""
        assert self.cur is not None
        self.cur.execute("delete from kv where k = ?", (key,))
        self.cur.execute("insert into kv values (?,?)", (key, value))

    def get_kv_text(self, key):
        # type: (str) -> str | None
        """Get a key-value pair where value is text (e.g. volcfg)."""
        assert self.cur is not None
        row = self.cur.execute("select v from kv where k = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_kv_text(self, key, value):
        # type: (str, str) -> None
        """Set a key-value pair with text value (upsert)."""
        assert self.cur is not None
        self.cur.execute("delete from kv where k = ?", (key,))
        self.cur.execute("insert into kv values (?,?)", (key, value))

    def delete_kv(self, key):
        # type: (str) -> None
        """Delete a key-value pair."""
        assert self.cur is not None
        self.cur.execute("delete from kv where k = ?", (key,))

    # --- Directory hashes (dh table) ---

    def check_dhash(self, rd, dhash):
        # type: (str, str) -> bool
        """Check if directory hash matches."""
        assert self.cur is not None
        rows = self.cur.execute("select h from dh where d = ?", (rd,)).fetchall()
        return bool(rows) and rows[0][0] == dhash

    def update_dhash(self, rd, dhash):
        # type: (str, str) -> None
        """Update directory hash."""
        assert self.cur is not None
        self.cur.execute("delete from dh where d = ?", (rd,))
        self.cur.execute("insert into dh values (?,?)", (rd, dhash))

    def delete_dhash(self, rd):
        # type: (str) -> None
        """Delete directory hash entry."""
        assert self.cur is not None
        self.cur.execute("delete from dh where d = ?", (rd,))

    def delete_dhash_tree(self, rd):
        # type: (str) -> None
        """Delete directory hash for rd and all subdirectories."""
        assert self.cur is not None
        self.cur.execute("delete from dh where (d = ? or d like ?||'/%')", (rd, rd))

    def delete_all_dhashes(self):
        # type: () -> None
        """Delete all directory hashes."""
        assert self.cur is not None
        self.cur.execute("delete from dh")

    # --- Cover art (cv table) ---

    def get_cover(self, rd, dn):
        # type: (str, str) -> str | None
        """Get cover art filename."""
        assert self.cur is not None
        rows = self.cur.execute("select fn from cv where rd = ? and dn = ?", (rd, dn)).fetchall()
        return rows[0][0] if rows else None

    def set_cover(self, rd, dn, fn):
        # type: (str, str, str) -> None
        """Set cover art for a directory."""
        assert self.cur is not None
        self.cur.execute("delete from cv where rd = ? and dn = ?", (rd, dn))
        self.cur.execute("insert into cv values (?,?,?)", (rd, dn, fn))

    def delete_cover(self, rd, dn, fn):
        # type: (str, str, str) -> None
        """Delete a specific cover art entry."""
        assert self.cur is not None
        self.cur.execute("delete from cv where rd=? and dn=? and +fn=?", (rd, dn, fn))

    # --- Directory sizes (ds table) ---

    def get_dir_size(self, rd):
        # type: (str) -> tuple[int, int] | None
        """Get directory size and file count."""
        assert self.cur is not None
        rows = self.cur.execute("select sz, nf from ds where rd = ?", (rd,)).fetchall()
        return (rows[0][0], rows[0][1]) if rows else None

    def set_dir_size(self, rd, sz, nf):
        # type: (str, int, int) -> None
        """Set directory size and file count."""
        assert self.cur is not None
        self.cur.execute("delete from ds where rd = ?", (rd,))
        self.cur.execute("insert into ds values (?,?,?)", (rd, sz, nf))

    def increment_dir_size(self, rd, sz):
        # type: (str, int) -> int
        """Increment dir file count by 1 and size by sz. Returns rows updated."""
        assert self.cur is not None
        self.cur.execute("update ds set nf=nf+1, sz=sz+? where rd=?", (sz, rd))
        return self.cur.rowcount

    def decrement_dir_size(self, rd, sz):
        # type: (str, int) -> None
        """Decrement dir file count by 1 and size by sz."""
        assert self.cur is not None
        self.cur.execute("update ds set nf=nf-1, sz=sz-? where rd=?", (sz, rd))

    def delete_dir_size_tree(self, rd):
        # type: (str) -> None
        """Delete dir size entries for rd and all subdirectories."""
        assert self.cur is not None
        self.cur.execute("delete from ds where (rd=? or rd like ?||'/%')", (rd, rd))

    # --- Index-update hooks (iu table) ---

    def insert_iu(self, cooldown, wark_prefix, rd, fn):
        # type: (int, str, str, str) -> None
        """Insert index-update record."""
        assert self.cur is not None
        self.cur.execute("insert into iu values (?,?,?,?)", (cooldown, wark_prefix, rd, fn))

    def get_iu_by_cooldown(self, cooldown):
        # type: (int) -> list[tuple]
        """Get index-update records by cooldown threshold."""
        assert self.cur is not None
        return self.cur.execute("select * from iu where c <= ?", (cooldown,)).fetchall()

    def delete_iu_by_wark(self, wark_prefix):
        # type: (str) -> None
        """Delete index-update records by wark prefix."""
        assert self.cur is not None
        self.cur.execute("delete from iu where w = ?", (wark_prefix,))

    def read_version(self):
        # type: () -> int
        """Read the schema version from kv table."""
        ver = self.get_kv("schemaver")
        return ver if ver is not None else 0
