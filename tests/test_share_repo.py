#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import sqlite3
import time
import unittest

from copyparty.db.share_repo import ShareRepository


class TestShareRepo(unittest.TestCase):
    def setUp(self):
        self.repo = ShareRepository(":memory:")
        self.repo._conn = sqlite3.connect(":memory:")
        self.repo.create_schema()

    def tearDown(self):
        self.repo.close()

    def test_create_schema_tables(self):
        """Schema creates sh and sf tables with expected columns."""
        cur = self.repo._conn.cursor()

        cur.execute("pragma table_info(sh)")
        sh_cols = {row[1] for row in cur.fetchall()}
        self.assertEqual(sh_cols, {"k", "pw", "vp", "pr", "st", "un", "t0", "t1"})

        cur.execute("pragma table_info(sf)")
        sf_cols = {row[1] for row in cur.fetchall()}
        self.assertEqual(sf_cols, {"k", "vp"})
        cur.close()

    def test_create_and_get_share(self):
        now = int(time.time())
        self.repo.create_share("key1", "pw", "path/to/dir", "rw", 0, "alice", now, 0)
        self.repo.commit()

        share = self.repo.get_share("key1")
        self.assertIsNotNone(share)
        self.assertEqual(share[0], "key1")
        self.assertEqual(share[1], "pw")
        self.assertEqual(share[2], "path/to/dir")
        self.assertEqual(share[3], "rw")
        self.assertEqual(share[4], 0)
        self.assertEqual(share[5], "alice")
        self.assertEqual(share[6], now)
        self.assertEqual(share[7], 0)

    def test_get_nonexistent_share(self):
        share = self.repo.get_share("nope")
        self.assertIsNone(share)

    def test_delete_share(self):
        now = int(time.time())
        self.repo.create_share("key1", "pw", "path", "r", 0, "alice", now, 0)
        self.repo.add_share_file("key1", "file1.txt")
        self.repo.commit()

        self.repo.delete_share("key1")
        self.repo.commit()

        self.assertIsNone(self.repo.get_share("key1"))
        self.assertEqual(self.repo.get_share_files("key1"), [])

    def test_share_files(self):
        now = int(time.time())
        self.repo.create_share("key1", "", "path", "r", 2, "alice", now, 0)
        self.repo.add_share_file("key1", "file1.txt")
        self.repo.add_share_file("key1", "file2.txt")
        self.repo.commit()

        files = self.repo.get_share_files("key1")
        self.assertEqual(len(files), 2)
        self.assertIn("file1.txt", files)
        self.assertIn("file2.txt", files)

    def test_share_files_limit(self):
        now = int(time.time())
        self.repo.create_share("key1", "", "path", "r", 5, "alice", now, 0)
        for i in range(5):
            self.repo.add_share_file("key1", "file%d.txt" % i)
        self.repo.commit()

        files = self.repo.get_share_files("key1", limit=3)
        self.assertEqual(len(files), 3)

    def test_delete_share_files(self):
        now = int(time.time())
        self.repo.create_share("key1", "", "path", "r", 2, "alice", now, 0)
        self.repo.add_share_file("key1", "file1.txt")
        self.repo.add_share_file("key1", "file2.txt")
        self.repo.commit()

        self.repo.delete_share_files("key1")
        self.repo.commit()

        files = self.repo.get_share_files("key1")
        self.assertEqual(files, [])
        # Share itself should still exist
        self.assertIsNotNone(self.repo.get_share("key1"))

    def test_update_expiry(self):
        now = int(time.time())
        self.repo.create_share("key1", "", "path", "r", 0, "alice", now, now + 3600)
        self.repo.commit()

        new_exp = now + 7200
        self.repo.update_expiry("key1", new_exp)
        self.repo.commit()

        share = self.repo.get_share("key1")
        self.assertEqual(share[7], new_exp)

    def test_find_expired(self):
        now = int(time.time())
        self.repo.create_share("active", "", "p1", "r", 0, "a", now, now + 3600)
        self.repo.create_share("expired", "", "p2", "r", 0, "a", now, now - 100)
        self.repo.create_share("no_exp", "", "p3", "r", 0, "a", now, 0)
        self.repo.commit()

        expired = self.repo.find_expired(now)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0], "expired")

    def test_find_expired_empty(self):
        expired = self.repo.find_expired(time.time())
        self.assertEqual(expired, [])

    def test_list_shares(self):
        now = int(time.time())
        self.repo.create_share("k1", "", "p1", "r", 0, "a", now, 0)
        self.repo.create_share("k2", "", "p2", "rw", 0, "b", now, 0)
        self.repo.commit()

        shares = self.repo.list_shares()
        self.assertEqual(len(shares), 2)
        keys = {s[0] for s in shares}
        self.assertEqual(keys, {"k1", "k2"})

    def test_list_shares_empty(self):
        shares = self.repo.list_shares()
        self.assertEqual(shares, [])

    def test_close_idempotent(self):
        """Closing twice should not raise."""
        self.repo.close()
        self.repo.close()


if __name__ == "__main__":
    unittest.main()
