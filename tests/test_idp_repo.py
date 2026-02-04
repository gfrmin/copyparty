#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import sqlite3
import unittest

from copyparty.db.idp_repo import IdpRepository


class TestIdpRepo(unittest.TestCase):
    def setUp(self):
        self.repo = IdpRepository(":memory:")
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
        self.assertEqual(cols, {"un", "gs"})
        cur.close()

    def test_load_all_empty(self):
        rows = self.repo.load_all()
        self.assertEqual(rows, [])

    def test_upsert_and_load(self):
        self.repo.upsert_user("alice", "admin,users")
        self.repo.upsert_user("bob", "users")

        rows = self.repo.load_all()
        self.assertEqual(len(rows), 2)

        by_user = {r[0]: r[1] for r in rows}
        self.assertEqual(by_user["alice"], "admin,users")
        self.assertEqual(by_user["bob"], "users")

    def test_upsert_overwrites(self):
        """Upserting the same user replaces the old mapping."""
        self.repo.upsert_user("alice", "users")
        self.repo.upsert_user("alice", "admin,superusers")

        rows = self.repo.load_all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "alice")
        self.assertEqual(rows[0][1], "admin,superusers")

    def test_delete_user(self):
        self.repo.upsert_user("alice", "admin")
        self.repo.upsert_user("bob", "users")

        self.repo.delete_user("alice")

        rows = self.repo.load_all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "bob")

    def test_delete_nonexistent(self):
        """Deleting a non-existent user should not raise."""
        self.repo.delete_user("ghost")
        rows = self.repo.load_all()
        self.assertEqual(rows, [])

    def test_close_idempotent(self):
        """Closing twice should not raise."""
        self.repo.close()
        self.repo.close()


if __name__ == "__main__":
    unittest.main()
