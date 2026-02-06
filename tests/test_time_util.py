"""Unit tests for time utilities."""

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

    def test_formatdate_epoch(self) -> None:
        """Test date formatting for epoch."""
        result = formatdate(0)
        self.assertEqual(result, "Thu, 01 Jan 1970 00:00:00 GMT")

    def test_formatdate_fixed(self) -> None:
        """Test date formatting for a known timestamp."""
        result = formatdate(1706745600)
        self.assertIn("2024", result)
        self.assertIn("GMT", result)

    def test_formatdate_default(self) -> None:
        """Test date formatting defaults to current time."""
        result = formatdate()
        self.assertIn("GMT", result)
        self.assertGreater(len(result), 20)

    def test_humansize_bytes(self) -> None:
        """Test human-readable size formatting for bytes."""
        self.assertEqual(humansize(0), "0 B")
        self.assertEqual(humansize(512), "512 B")

    def test_humansize_kilobytes(self) -> None:
        """Test human-readable size formatting for kilobytes."""
        self.assertEqual(humansize(1024), "1.0 KiB")

    def test_humansize_megabytes(self) -> None:
        """Test human-readable size formatting for megabytes."""
        self.assertEqual(humansize(1048576), "1.0 MiB")

    def test_humansize_terse(self) -> None:
        """Test terse human-readable size formatting."""
        self.assertEqual(humansize(512, terse=True), "512B")
        self.assertEqual(humansize(1024, terse=True), "1.0K")

    def test_unhumanize_plain_int(self) -> None:
        """Test converting plain integers."""
        self.assertEqual(unhumanize("0"), 0)
        self.assertEqual(unhumanize("512"), 512)
        self.assertEqual(unhumanize("1024"), 1024)

    def test_unhumanize_kilobytes(self) -> None:
        """Test converting kilobytes to bytes."""
        self.assertEqual(unhumanize("1k"), 1024)

    def test_unhumanize_megabytes(self) -> None:
        """Test converting megabytes to bytes."""
        self.assertEqual(unhumanize("1m"), 1024 * 1024)

    def test_unhumanize_gigabytes(self) -> None:
        """Test converting gigabytes to bytes."""
        self.assertEqual(unhumanize("1g"), 1024 * 1024 * 1024)

    def test_unhumanize_decimal(self) -> None:
        """Test converting decimal sizes."""
        self.assertEqual(unhumanize("1.5k"), int(1.5 * 1024))

    def test_get_spd_contains_speed(self) -> None:
        """Test speed calculation contains size and rate."""
        result = get_spd(1048576, 10.0, 11.0)
        # Contains ANSI color codes and size info
        self.assertIn("/s", result)
        self.assertIn("\033[0m", result)

    def test_s2hms_seconds(self) -> None:
        """Test seconds to H:MM:SS conversion."""
        self.assertEqual(s2hms(30), "0:00:30")
        self.assertEqual(s2hms(0), "0:00:00")

    def test_s2hms_minutes(self) -> None:
        """Test minutes in H:MM:SS format."""
        self.assertEqual(s2hms(90), "0:01:30")

    def test_s2hms_hours(self) -> None:
        """Test hours in H:MM:SS format."""
        self.assertEqual(s2hms(3661), "1:01:01")

    def test_s2hms_optional_h(self) -> None:
        """Test s2hms with optional_h omits hours when 0."""
        self.assertEqual(s2hms(90, optional_h=True), "1:30")

    def test_s2hms_optional_h_with_hours(self) -> None:
        """Test s2hms with optional_h still shows hours when > 0."""
        self.assertEqual(s2hms(3661, optional_h=True), "1:01:01")


if __name__ == "__main__":
    unittest.main()
