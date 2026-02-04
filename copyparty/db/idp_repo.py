"""IdP database repository.

Mirrors the IdP DB schema from svchub._create_idp_db:
  table us (un text, gs text)
  index: us_un
  kv table with sver=1
"""
from __future__ import print_function, unicode_literals

import sqlite3


class IdpRepository(object):
    """Manages IdP user-group persistence in SQLite."""

    SCHEMA = [
        r"create table if not exists kv (k text, v int)",
        r"create table if not exists us (un text, gs text)",
        r"create index if not exists us_un on us(un)",
    ]

    def __init__(self, db_path):
        # type: (str) -> None
        self.db_path = db_path
        self._conn = None  # type: sqlite3.Connection | None

    def _connect(self):
        # type: () -> sqlite3.Connection
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=10)
        return self._conn

    def create_schema(self, cur):
        # type: (sqlite3.Cursor) -> None
        """Create IdP DB tables and indexes."""
        for cmd in self.SCHEMA:
            cur.execute(cmd)

    def load_all(self):
        # type: () -> list[tuple[str, str]]
        """Load all IdP user-group mappings. Returns [(username, groups), ...]."""
        conn = self._connect()
        cur = conn.cursor()
        rows = cur.execute("select un, gs from us").fetchall()
        cur.close()
        return rows

    def upsert_user(self, username, groups):
        # type: (str, str) -> None
        """Delete existing + insert user-group mapping (upsert)."""
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("delete from us where un = ?", (username,))
        cur.execute("insert into us values (?,?)", (username, groups))
        conn.commit()
        cur.close()

    def delete_user(self, username):
        # type: (str) -> None
        """Delete a user's IdP mapping."""
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("delete from us where un = ?", (username,))
        conn.commit()
        cur.close()

    def close(self):
        # type: () -> None
        if self._conn:
            self._conn.close()
            self._conn = None
