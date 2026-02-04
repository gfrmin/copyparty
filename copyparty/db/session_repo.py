"""Session database repository.

Mirrors the session DB schema from svchub._create_session_db:
  table us (un text, si text, t0 int)
  indexes: us_un, us_si, us_t0
  kv table with sver=1
"""
from __future__ import print_function, unicode_literals

import sqlite3


class SessionRepository(object):
    """Manages session persistence in SQLite."""

    SCHEMA = [
        r"create table if not exists kv (k text, v int)",
        r"create table if not exists us (un text, si text, t0 int)",
        r"create index if not exists us_un on us(un)",
        r"create index if not exists us_si on us(si)",
        r"create index if not exists us_t0 on us(t0)",
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
        """Create session DB tables and indexes."""
        for cmd in self.SCHEMA:
            cur.execute(cmd)

    def load_all(self):
        # type: () -> dict[str, str]
        """Load all sessions. Returns {username: session_id}."""
        conn = self._connect()
        cur = conn.cursor()
        rows = cur.execute("select un, si from us").fetchall()
        cur.close()
        return {un: si for un, si in rows}

    def insert_session(self, username, session_id, timestamp):
        # type: (str, str, int) -> None
        """Insert a new session."""
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("insert into us values (?,?,?)", (username, session_id, timestamp))
        conn.commit()
        cur.close()

    def delete_session(self, username):
        # type: (str) -> None
        """Delete all sessions for a username."""
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
