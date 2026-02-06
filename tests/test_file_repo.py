#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import unittest

from copyparty.db.file_repo import FileRepository


class TestFileRepo(unittest.TestCase):
    def setUp(self):
        self.repo = FileRepository(":memory:")
        self.repo.open()
        self.repo.create_schema()

    def tearDown(self):
        self.repo.close()

    def test_schema_creation(self):
        ver = self.repo.read_version()
        self.assertEqual(ver, FileRepository.DB_VER)

    def test_insert_and_find_file(self):
        self.repo.insert_file("wark123", 1000, 42, "dir/sub", "test.txt", "1.2.3.4", 999, "alice")
        self.repo.commit()
        row = self.repo.find_file("dir/sub", "test.txt")
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "wark123")
        self.assertEqual(row[2], 42)
        self.assertEqual(row[4], "test.txt")

    def test_find_file_not_found(self):
        row = self.repo.find_file("nonexistent", "nope.txt")
        self.assertIsNone(row)

    def test_find_by_wark(self):
        self.repo.insert_file("wark_abcdef1234567890", 1000, 42, "dir", "f.txt", "1.2.3.4", 999, "alice")
        self.repo.commit()
        rows = self.repo.find_files_by_wark("wark_abcdef1234567890")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][4], "f.txt")

    def test_find_by_dir(self):
        self.repo.insert_file("w1", 1000, 10, "mydir", "a.txt", "ip", 999, "u")
        self.repo.insert_file("w2", 1000, 20, "mydir", "b.txt", "ip", 999, "u")
        self.repo.insert_file("w3", 1000, 30, "other", "c.txt", "ip", 999, "u")
        self.repo.commit()
        fns = self.repo.find_files_by_dir("mydir")
        self.assertEqual(sorted(fns), ["a.txt", "b.txt"])

    def test_delete_file(self):
        self.repo.insert_file("w1", 1000, 10, "dir", "f.txt", "ip", 999, "u")
        self.repo.commit()
        deleted = self.repo.delete_file("dir", "f.txt")
        self.assertEqual(deleted, 1)
        self.assertIsNone(self.repo.find_file("dir", "f.txt"))

    def test_count_files(self):
        self.assertEqual(self.repo.count_files(), 0)
        self.repo.insert_file("w1", 1000, 10, "d", "a", "ip", 999, "u")
        self.repo.insert_file("w2", 1000, 20, "d", "b", "ip", 999, "u")
        self.repo.commit()
        self.assertEqual(self.repo.count_files(), 2)

    def test_tags(self):
        self.repo.insert_tag("wp1", "artist", 42)
        self.repo.insert_tag("wp1", "title", 43)
        self.repo.commit()
        tags = self.repo.get_tags("wp1")
        self.assertEqual(len(tags), 2)
        self.repo.delete_tags("wp1")
        self.assertEqual(len(self.repo.get_tags("wp1")), 0)

    def test_count_tags(self):
        self.assertEqual(self.repo.count_tags(), 0)
        self.repo.insert_tag("wp1", "artist", 42)
        self.repo.commit()
        self.assertEqual(self.repo.count_tags(), 1)

    def test_kv(self):
        self.repo.set_kv("mykey", 123)
        self.repo.commit()
        self.assertEqual(self.repo.get_kv("mykey"), 123)
        self.repo.set_kv("mykey", 456)
        self.repo.commit()
        self.assertEqual(self.repo.get_kv("mykey"), 456)
        self.assertIsNone(self.repo.get_kv("nonexistent"))

    def test_dhash(self):
        self.repo.update_dhash("dir1", "hash123")
        self.repo.commit()
        self.assertTrue(self.repo.check_dhash("dir1", "hash123"))
        self.assertFalse(self.repo.check_dhash("dir1", "wrong"))
        self.assertFalse(self.repo.check_dhash("nodir", "hash123"))
        self.repo.delete_dhash("dir1")
        self.assertFalse(self.repo.check_dhash("dir1", "hash123"))

    def test_delete_all_dhashes(self):
        self.repo.update_dhash("dir1", "h1")
        self.repo.update_dhash("dir2", "h2")
        self.repo.commit()
        self.assertTrue(self.repo.check_dhash("dir1", "h1"))
        self.repo.delete_all_dhashes()
        self.assertFalse(self.repo.check_dhash("dir1", "h1"))
        self.assertFalse(self.repo.check_dhash("dir2", "h2"))

    def test_cover(self):
        self.repo.set_cover("dir1", "subdir", "cover.jpg")
        self.repo.commit()
        self.assertEqual(self.repo.get_cover("dir1", "subdir"), "cover.jpg")
        self.assertIsNone(self.repo.get_cover("dir1", "other"))

    def test_cover_overwrite(self):
        self.repo.set_cover("dir1", "subdir", "old.jpg")
        self.repo.set_cover("dir1", "subdir", "new.jpg")
        self.repo.commit()
        self.assertEqual(self.repo.get_cover("dir1", "subdir"), "new.jpg")

    def test_dir_size(self):
        self.repo.set_dir_size("dir1", 1024, 5)
        self.repo.commit()
        result = self.repo.get_dir_size("dir1")
        self.assertEqual(result, (1024, 5))
        self.assertIsNone(self.repo.get_dir_size("nodir"))

    def test_dir_size_overwrite(self):
        self.repo.set_dir_size("dir1", 100, 1)
        self.repo.set_dir_size("dir1", 200, 2)
        self.repo.commit()
        self.assertEqual(self.repo.get_dir_size("dir1"), (200, 2))

    def test_iu(self):
        self.repo.insert_iu(100, "wp1", "dir", "file.txt")
        self.repo.insert_iu(200, "wp2", "dir", "file2.txt")
        self.repo.commit()
        results = self.repo.get_iu_by_cooldown(150)
        self.assertEqual(len(results), 1)
        results = self.repo.get_iu_by_cooldown(300)
        self.assertEqual(len(results), 2)
        self.repo.delete_iu_by_wark("wp1")
        self.assertEqual(len(self.repo.get_iu_by_cooldown(300)), 1)

    def test_vacuum(self):
        self.repo.insert_file("w1", 1000, 10, "d", "a", "ip", 999, "u")
        self.repo.commit()
        self.repo.delete_file("d", "a")
        self.repo.commit()
        # vacuum should not raise
        self.repo.vacuum()

    def test_open_returns_self(self):
        repo2 = FileRepository(":memory:")
        result = repo2.open()
        self.assertIs(result, repo2)
        repo2.close()

    def test_no_expr_idx_fallback(self):
        repo = FileRepository(":memory:", no_expr_idx=True)
        repo.open()
        repo.create_schema()
        repo.insert_file("wark_abcdef1234567890", 1000, 42, "dir", "f.txt", "1.2.3.4", 999, "alice")
        repo.commit()
        rows = repo.find_files_by_wark("wark_abcdef1234567890")
        self.assertEqual(len(rows), 1)
        repo.close()

    def test_wrap_cursor(self):
        """wrap_cursor should adopt an existing cursor and connection."""
        import sqlite3

        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        # Create schema manually (must match up2k.py)
        cur.execute(
            "create table up (w text, mt int, sz int, rd text, fn text, ip text, at int, un text)"
        )
        cur.execute("create table mt (w text, k text, v int)")
        cur.execute("create table kv (k text, v int)")
        cur.execute("create table dh (d text, h text)")
        cur.execute("create table iu (c int, w text, rd text, fn text)")
        cur.execute("create table cv (rd text, dn text, fn text)")
        cur.execute("create table ds (rd text, sz int, nf int)")
        conn.commit()

        repo = FileRepository(":memory:")
        repo.wrap_cursor(cur)
        self.assertIs(repo.cur, cur)
        self.assertIs(repo._conn, conn)

        # Should be able to use repo methods on the wrapped cursor
        repo.insert_file("wk1", 100, 5, "d", "f.txt", "ip", 50, "u")
        repo.commit()
        row = repo.find_file("d", "f.txt")
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "wk1")

        conn.close()


if __name__ == "__main__":
    unittest.main()
