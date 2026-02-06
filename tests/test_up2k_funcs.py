"""Unit tests for up2k standalone functions."""

import binascii
import hashlib
import math
import unittest

from copyparty.up2k import (
    up2k_chunksize,
    up2k_wark_from_hashlist,
    up2k_wark_from_metadata,
)


class TestUp2kChunksize(unittest.TestCase):
    """Test the up2k chunk size calculation."""

    def test_small_file_returns_1mib(self) -> None:
        """Files small enough for 1 MiB chunks should get 1 MiB."""
        cs = up2k_chunksize(1)
        self.assertEqual(cs, 1024 * 1024)

    def test_zero_file(self) -> None:
        """Zero-byte file should get 1 MiB chunk size."""
        cs = up2k_chunksize(0)
        self.assertEqual(cs, 1024 * 1024)

    def test_exactly_256mib(self) -> None:
        """256 MiB file: 256 chunks of 1 MiB, should still be 1 MiB."""
        cs = up2k_chunksize(256 * 1024 * 1024)
        self.assertEqual(cs, 1024 * 1024)

    def test_large_file_scales_up(self) -> None:
        """Files larger than 256 chunks at 1 MiB should get bigger chunks."""
        cs = up2k_chunksize(1024 * 1024 * 1024)  # 1 GiB
        self.assertGreater(cs, 1024 * 1024)

    def test_chunk_count_within_bounds(self) -> None:
        """For any file size, chunk count should be <= 256 or chunk >= 32 MiB with <= 4096."""
        for size in [0, 1, 1024, 1024 * 1024, 100 * 1024 * 1024,
                     1024 * 1024 * 1024, 10 * 1024 * 1024 * 1024]:
            cs = up2k_chunksize(size)
            nchunks = math.ceil(size / cs) if size else 1
            ok = nchunks <= 256 or (cs >= 32 * 1024 * 1024 and nchunks <= 4096)
            self.assertTrue(ok, f"size={size} cs={cs} nchunks={nchunks}")

    def test_chunksize_never_zero(self) -> None:
        """Chunk size must always be positive."""
        for size in [0, 1, 999999999]:
            cs = up2k_chunksize(size)
            self.assertGreater(cs, 0)

    def test_chunksize_is_multiple_of_512k(self) -> None:
        """Chunk sizes should be multiples of 512 KiB (the step size base)."""
        for size in [0, 1024 * 1024, 500 * 1024 * 1024, 2 * 1024 * 1024 * 1024]:
            cs = up2k_chunksize(size)
            self.assertEqual(cs % (512 * 1024), 0, f"size={size} cs={cs}")


class TestUp2kWarkFromHashlist(unittest.TestCase):
    """Test wark generation from chunk hashes."""

    def test_deterministic(self) -> None:
        """Same inputs should produce the same wark."""
        hashes = ["abc123", "def456"]
        w1 = up2k_wark_from_hashlist("salt", 1024, hashes)
        w2 = up2k_wark_from_hashlist("salt", 1024, hashes)
        self.assertEqual(w1, w2)

    def test_different_salt_different_wark(self) -> None:
        """Different salts should produce different warks."""
        hashes = ["abc123"]
        w1 = up2k_wark_from_hashlist("salt1", 1024, hashes)
        w2 = up2k_wark_from_hashlist("salt2", 1024, hashes)
        self.assertNotEqual(w1, w2)

    def test_different_size_different_wark(self) -> None:
        """Different file sizes should produce different warks."""
        hashes = ["abc123"]
        w1 = up2k_wark_from_hashlist("salt", 1024, hashes)
        w2 = up2k_wark_from_hashlist("salt", 2048, hashes)
        self.assertNotEqual(w1, w2)

    def test_different_hashes_different_wark(self) -> None:
        """Different hash lists should produce different warks."""
        w1 = up2k_wark_from_hashlist("salt", 1024, ["aaa"])
        w2 = up2k_wark_from_hashlist("salt", 1024, ["bbb"])
        self.assertNotEqual(w1, w2)

    def test_returns_ascii_string(self) -> None:
        """Wark should be a pure ASCII string."""
        w = up2k_wark_from_hashlist("salt", 100, ["h1", "h2"])
        self.assertIsInstance(w, str)
        w.encode("ascii")  # should not raise

    def test_wark_length(self) -> None:
        """Wark is base64 of 33 bytes = 44 chars."""
        w = up2k_wark_from_hashlist("salt", 100, ["h1"])
        self.assertEqual(len(w), 44)

    def test_manual_computation(self) -> None:
        """Verify the wark is derived from SHA-512 of salt+size+hashes joined by newlines."""
        salt, size, hashes = "test", 42, ["hash1", "hash2"]
        vstr = "\n".join([salt, str(size)] + hashes)
        digest = hashlib.sha512(vstr.encode("utf-8")).digest()[:33]
        w = up2k_wark_from_hashlist(salt, size, hashes)
        # url-safe base64 of 33 bytes = 44 chars
        self.assertEqual(len(w), 44)
        # decode url-safe base64 back and verify digest matches
        raw = w.replace("-", "+").replace("_", "/")
        # add padding if needed
        raw += "=" * (-len(raw) % 4)
        decoded = binascii.a2b_base64(raw.encode("ascii"))
        self.assertEqual(decoded, digest)


class TestUp2kWarkFromMetadata(unittest.TestCase):
    """Test wark generation from file metadata."""

    def test_deterministic(self) -> None:
        """Same inputs produce the same wark."""
        w1 = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "file.txt")
        w2 = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "file.txt")
        self.assertEqual(w1, w2)

    def test_starts_with_hash(self) -> None:
        """Metadata warks start with # to distinguish from hashlist warks."""
        w = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "file.txt")
        self.assertTrue(w.startswith("#"))

    def test_length_is_44(self) -> None:
        """Metadata wark is 44 chars (# + 43 base64)."""
        w = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "file.txt")
        self.assertEqual(len(w), 44)

    def test_different_name_different_wark(self) -> None:
        """Different filenames produce different warks."""
        w1 = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "a.txt")
        w2 = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "b.txt")
        self.assertNotEqual(w1, w2)

    def test_different_dir_different_wark(self) -> None:
        """Different directories produce different warks."""
        w1 = up2k_wark_from_metadata("salt", 100, 12345, "/dir1", "f.txt")
        w2 = up2k_wark_from_metadata("salt", 100, 12345, "/dir2", "f.txt")
        self.assertNotEqual(w1, w2)

    def test_different_lastmod_different_wark(self) -> None:
        """Different last-modified times produce different warks."""
        w1 = up2k_wark_from_metadata("salt", 100, 11111, "/d", "f.txt")
        w2 = up2k_wark_from_metadata("salt", 100, 22222, "/d", "f.txt")
        self.assertNotEqual(w1, w2)

    def test_returns_ascii(self) -> None:
        """Wark must be ASCII."""
        w = up2k_wark_from_metadata("salt", 100, 12345, "/dir", "file.txt")
        self.assertIsInstance(w, str)
        w.encode("ascii")


if __name__ == "__main__":
    unittest.main()
