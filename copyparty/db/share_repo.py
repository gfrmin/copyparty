"""Share database repository.

Mirrors the share DB schema from svchub._create_share_db:
  table sh (k text, pw text, vp text, pr text, st int, un text, t0 int, t1 int)
    -- sharekey, password, src-vpath, perms, numFiles, owner, created, expires
  table sf (k text, vp text)
    -- sharekey, file-vpath
  indexes: sf_k, sh_k, sh_t1
  kv table with sver=2
"""
from __future__ import print_function, unicode_literals

import sqlite3

VER_SHARES_DB = 2


class ShareRepository(object):
    """Manages share persistence in SQLite."""

    SCHEMA_1 = [
        r"create table if not exists kv (k text, v int)",
        r"create table if not exists sh (k text, pw text, vp text, pr text, st int, un text, t0 int, t1 int)",
    ]
    SCHEMA_2 = [
        r"create table if not exists sf (k text, vp text)",
        r"create index if not exists sf_k on sf(k)",
        r"create index if not exists sh_k on sh(k)",
        r"create index if not exists sh_t1 on sh(t1)",
    ]

    def __init__(self, db_path):
        # type: (str) -> None
        self.db_path = db_path
        self._conn = None  # type: sqlite3.Connection | None
        self._cur = None  # type: sqlite3.Cursor | None

    def _connect(self):
        # type: () -> sqlite3.Connection
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=10)
        return self._conn

    def get_cursor(self):
        # type: () -> sqlite3.Cursor
        if self._cur is None:
            self._cur = self._connect().cursor()
        return self._cur

    def create_schema(self):
        # type: () -> None
        """Create share DB tables and indexes."""
        conn = self._connect()
        cur = conn.cursor()
        for cmd in self.SCHEMA_1 + self.SCHEMA_2:
            cur.execute(cmd)
        conn.commit()

    def list_shares(self):
        # type: () -> list[tuple]
        """List all shares."""
        cur = self.get_cursor()
        return cur.execute("select * from sh").fetchall()

    def get_share(self, key):
        # type: (str) -> tuple | None
        """Get a share by key. Returns None if not found."""
        cur = self.get_cursor()
        rows = cur.execute("select * from sh where k = ?", (key,)).fetchall()
        return rows[0] if rows else None

    def create_share(self, key, pw, vpath, perms, num_files, username, created, expires):
        # type: (str, str, str, str, int, str, int, int) -> None
        """Insert a new share."""
        cur = self.get_cursor()
        cur.execute(
            "insert into sh values (?,?,?,?,?,?,?,?)",
            (key, pw, vpath, perms, num_files, username, created, expires),
        )

    def delete_share(self, key):
        # type: (str) -> None
        """Delete a share and its files by key."""
        cur = self.get_cursor()
        cur.execute("delete from sh where k = ?", (key,))
        cur.execute("delete from sf where k = ?", (key,))

    def update_expiry(self, key, new_expiry):
        # type: (str, int) -> None
        """Update share expiry time."""
        cur = self.get_cursor()
        cur.execute("update sh set t1 = ? where k = ?", (new_expiry, key))

    def get_share_files(self, key, limit=99):
        # type: (str, int) -> list[str]
        """Get file vpaths in a share."""
        cur = self.get_cursor()
        rows = cur.execute("select vp from sf where k = ? limit ?", (key, limit)).fetchall()
        return [r[0] for r in rows]

    def add_share_file(self, key, vpath):
        # type: (str, str) -> None
        """Add a file to a share."""
        cur = self.get_cursor()
        cur.execute("insert into sf values (?,?)", (key, vpath))

    def delete_share_files(self, key):
        # type: (str) -> None
        """Delete all files in a share."""
        cur = self.get_cursor()
        cur.execute("delete from sf where k = ?", (key,))

    def find_expired(self, now):
        # type: (float) -> list[str]
        """Find shares that have expired (t1 > 0 and t1 < now)."""
        cur = self.get_cursor()
        rows = cur.execute("select k from sh where t1 > 0 and t1 < ?", (now,)).fetchall()
        return [r[0] for r in rows]

    def commit(self):
        # type: () -> None
        if self._conn:
            self._conn.commit()

    def close(self):
        # type: () -> None
        if self._conn:
            self._conn.close()
            self._conn = None
            self._cur = None
