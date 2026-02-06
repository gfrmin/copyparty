"""Unit tests for network utilities."""

import unittest
from copyparty.net_util import ipnorm, find_prefix, list_ips


class TestNetUtil(unittest.TestCase):
    """Test network utility functions."""

    def test_ipnorm_ipv4(self) -> None:
        """Test IPv4 address normalization."""
        self.assertEqual(ipnorm("192.168.1.1"), "192.168.1.1")
        self.assertEqual(ipnorm("127.0.0.1"), "127.0.0.1")
        self.assertEqual(ipnorm("255.255.255.255"), "255.255.255.255")

    def test_ipnorm_ipv6(self) -> None:
        """Test IPv6 address normalization."""
        self.assertEqual(ipnorm("::1"), "::1")
        self.assertEqual(ipnorm("2001:db8::1"), "2001:db8::1")

    def test_ipnorm_invalid(self) -> None:
        """Test normalization of invalid IP."""
        result = ipnorm("invalid")
        self.assertEqual(result, "invalid")

    def test_find_prefix_match(self) -> None:
        """Test finding matching CIDR prefixes."""
        ips = ["192.168.1.1"]
        cidrs = ["192.168.0.0/16", "10.0.0.0/8"]
        matches = find_prefix(ips, cidrs)
        self.assertIn("192.168.0.0/16", matches)

    def test_find_prefix_no_match(self) -> None:
        """Test finding prefixes with no matches."""
        ips = ["192.168.1.1"]
        cidrs = ["10.0.0.0/8", "172.16.0.0/12"]
        matches = find_prefix(ips, cidrs)
        self.assertEqual(len(matches), 0)

    def test_find_prefix_multiple(self) -> None:
        """Test finding multiple matching prefixes."""
        ips = ["192.168.1.1"]
        cidrs = ["192.168.0.0/16", "192.0.0.0/8"]
        matches = find_prefix(ips, cidrs)
        self.assertEqual(len(matches), 2)

    def test_list_ips(self) -> None:
        """Test listing system IP addresses."""
        ips = list_ips()
        # Should always have loopback
        self.assertIn("127.0.0.1", ips)
        self.assertIsInstance(ips, list)
        self.assertGreater(len(ips), 0)


if __name__ == "__main__":
    unittest.main()
