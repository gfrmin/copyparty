#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import sqlite3
import unittest

from copyparty.db.session_repo import SessionRepository


class TestSessionRepo(unittest.TestCase):
    def setUp(self):
        self.repo = SessionRepository(":memory:")
        # Force connection and create schema for in-memory DB
        self.repo._conn = sqlite3.connect(":memory:")
        cur = self.repo._conn.cursor()
        self.repo.create_schema(cur)
        self.repo._conn.commit()
        cur.close()

    def tearDown(self):
        self.repo.close()

    def test_create_schema(self):
        """Schema creates us table with expected columns."""
        cur = self.repo._conn.cursor()
        cur.execute("pragma table_info(us)")
        cols = {row[1] for row in cur.fetchall()}
        self.assertEqual(cols, {"un", "si", "t0"})
        cur.close()

    def test_load_all_empty(self):
        sessions = self.repo.load_all()
        self.assertEqual(sessions, {})

    def test_insert_and_load(self):
        self.repo.insert_session("alice", "sess123", 1000)
        self.repo.insert_session("bob", "sess456", 2000)

        sessions = self.repo.load_all()
        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions["alice"], "sess123")
        self.assertEqual(sessions["bob"], "sess456")

    def test_delete_session(self):
        self.repo.insert_session("alice", "sess123", 1000)
        self.repo.insert_session("bob", "sess456", 2000)

        self.repo.delete_session("alice")

        sessions = self.repo.load_all()
        self.assertNotIn("alice", sessions)
        self.assertIn("bob", sessions)
        self.assertEqual(sessions["bob"], "sess456")

    def test_delete_nonexistent(self):
        """Deleting a non-existent user should not raise."""
        self.repo.delete_session("ghost")
        sessions = self.repo.load_all()
        self.assertEqual(sessions, {})

    def test_insert_replaces_on_reload(self):
        """Multiple inserts for same user accumulate (caller is expected to delete first)."""
        self.repo.insert_session("alice", "old_sess", 1000)
        self.repo.insert_session("alice", "new_sess", 2000)

        # load_all returns last seen since dict overwrites
        cur = self.repo._conn.cursor()
        rows = cur.execute("select si from us where un = 'alice'").fetchall()
        cur.close()
        # Both rows exist in DB
        self.assertEqual(len(rows), 2)

    def test_close_idempotent(self):
        """Closing twice should not raise."""
        self.repo.close()
        self.repo.close()


if __name__ == "__main__":
    unittest.main()
