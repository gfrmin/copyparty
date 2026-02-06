"""Unit tests for process utilities."""

import os
import unittest
from copyparty.proc_util import getalive, runcmd, chkcmd, retchk


class TestProcUtil(unittest.TestCase):
    """Test process utility functions."""

    def test_getalive_current(self) -> None:
        """Test checking if current process is alive."""
        current_pid = os.getpid()
        alive = getalive([current_pid], os.getpgrp())
        self.assertIn(current_pid, alive)

    def test_getalive_nonexistent(self) -> None:
        """Test checking nonexistent PID."""
        alive = getalive([99999999], os.getpgrp())
        # Unlikely that this PID exists
        self.assertEqual(len([p for p in alive if p == 99999999]), 0)

    def test_runcmd_echo(self) -> None:
        """Test running simple command."""
        stdout, stderr = runcmd(["echo", "test"])
        self.assertIn("test", stdout)

    def test_runcmd_false(self) -> None:
        """Test running command that fails."""
        stdout, stderr = runcmd(["false"])
        # Should return empty strings without raising
        self.assertEqual(stdout, "")

    def test_runcmd_timeout(self) -> None:
        """Test command timeout."""
        stdout, stderr = runcmd(["sleep", "10"], timeout=0.1)
        # Should timeout - check for "timed out" in stderr
        self.assertIn("timed out", stderr.lower())

    def test_chkcmd_true(self) -> None:
        """Test running successful command."""
        stdout, stderr = chkcmd(["true"])
        self.assertEqual(stdout, "")

    def test_retchk_success(self) -> None:
        """Test checking command return code."""
        result = retchk(["true"], expected=0)
        self.assertTrue(result)

    def test_retchk_failure(self) -> None:
        """Test checking failed command return code."""
        result = retchk(["false"], expected=0)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
