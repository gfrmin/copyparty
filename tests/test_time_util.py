"""Unit tests for time utilities."""

import time
import unittest
from copyparty.time_util import (
    formatdate,
    humansize,
    unhumanize,
    get_spd,
    s2hms,
)


class TestTimeUtil(unittest.TestCase):
    """Test time utility functions."""

    def test_formatdate(self) -> None:
        """Test date formatting."""
        # Test with specific timestamp
        result = formatdate(0)
        self.assertIn("1970", result)
        self.assertIn("GMT", result)

        # Test with current time
        result = formatdate()
        self.assertIsNotNone(result)
        self.assertGreater(len(result), 10)

    def test_humansize_bytes(self) -> None:
        """Test human-readable size formatting for bytes."""
        self.assertEqual(humansize(0), "0 bytes")
        self.assertEqual(humansize(512), "512 bytes")
        self.assertEqual(humansize(1023), "1023 bytes")

    def test_humansize_kilobytes(self) -> None:
        """Test human-readable size formatting for kilobytes."""
        result = humansize(1024)
        self.assertIn("KiB", result)

    def test_humansize_megabytes(self) -> None:
        """Test human-readable size formatting for megabytes."""
        result = humansize(1024 * 1024)
        self.assertIn("MiB", result)

    def test_humansize_terse(self) -> None:
        """Test terse human-readable size formatting."""
        self.assertEqual(humansize(512, terse=True), "512 B")
        result = humansize(1024, terse=True)
        self.assertIn("K", result)

    def test_unhumanize_bytes(self) -> None:
        """Test converting human-readable sizes to bytes."""
        self.assertEqual(unhumanize("0"), 0)
        self.assertEqual(unhumanize("512"), 512)
        self.assertEqual(unhumanize("1024"), 1024)

    def test_unhumanize_kilobytes(self) -> None:
        """Test converting kilobytes to bytes."""
        self.assertEqual(unhumanize("1k"), 1024)
        self.assertEqual(unhumanize("2K"), 2048)

    def test_unhumanize_megabytes(self) -> None:
        """Test converting megabytes to bytes."""
        self.assertEqual(unhumanize("1m"), 1024 * 1024)
        self.assertEqual(unhumanize("1M"), 1024 * 1024)

    def test_unhumanize_gigabytes(self) -> None:
        """Test converting gigabytes to bytes."""
        self.assertEqual(unhumanize("1g"), 1024 * 1024 * 1024)
        self.assertEqual(unhumanize("1G"), 1024 * 1024 * 1024)

    def test_unhumanize_decimal(self) -> None:
        """Test converting decimal sizes."""
        self.assertEqual(unhumanize("1.5k"), int(1.5 * 1024))
        self.assertEqual(unhumanize("2.5m"), int(2.5 * 1024 * 1024))

    def test_get_spd(self) -> None:
        """Test speed calculation."""
        # 1 second, 1024 bytes = 1 KiB/s
        spd = get_spd(1024, 0, 1)
        self.assertIn("KiB/s", spd)

        # Very fast transfer
        spd = get_spd(1024 * 1024, 0, 0.5)
        self.assertIn("MiB/s", spd)

    def test_s2hms_seconds(self) -> None:
        """Test seconds to HMS conversion for seconds only."""
        self.assertEqual(s2hms(30, optional_h=True), "0m 30s")
        self.assertEqual(s2hms(45, optional_h=True), "0m 45s")

    def test_s2hms_minutes(self) -> None:
        """Test seconds to HMS conversion for minutes."""
        self.assertEqual(s2hms(60, optional_h=True), "1m 0s")
        self.assertEqual(s2hms(125, optional_h=True), "2m 5s")

    def test_s2hms_hours(self) -> None:
        """Test seconds to HMS conversion for hours."""
        result = s2hms(3661, optional_h=True)
        self.assertIn("h", result)
        self.assertIn("m", result)

    def test_s2hms_no_optional_h(self) -> None:
        """Test seconds to HMS without optional hours."""
        self.assertEqual(s2hms(30, optional_h=False), "0h 0m 30s")


if __name__ == "__main__":
    unittest.main()
