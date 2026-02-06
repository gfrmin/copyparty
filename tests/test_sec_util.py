"""Unit tests for security utilities."""

import tempfile
import unittest
from copyparty.sec_util import (
    gencookie,
    gen_content_disposition,
    hash_password,
    verify_password,
    gen_random_token,
    validate_email,
    sanitize_input,
    checksum_file,
)


class TestSecUtil(unittest.TestCase):
    """Test security utility functions."""

    def test_gencookie_basic(self) -> None:
        """Test basic cookie generation."""
        cookie = gencookie("name", "value")
        self.assertIn("name=value", cookie)
        self.assertIn("Path=/", cookie)

    def test_gencookie_secure(self) -> None:
        """Test secure cookie generation."""
        cookie = gencookie("name", "value", secure=True, httponly=True)
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)

    def test_gencookie_expiration(self) -> None:
        """Test cookie with expiration."""
        cookie = gencookie("name", "value", days=7)
        self.assertIn("Max-Age", cookie)
        self.assertIn("604800", cookie)  # 7 days in seconds

    def test_gen_content_disposition(self) -> None:
        """Test content disposition header generation."""
        header = gen_content_disposition("test.txt")
        self.assertIn("attachment", header)
        self.assertIn("test.txt", header)

    def test_gen_content_disposition_special(self) -> None:
        """Test content disposition with special characters."""
        header = gen_content_disposition('test"file.txt')
        self.assertIn("test", header)
        self.assertIn("file.txt", header)

    def test_hash_password_sha256(self) -> None:
        """Test password hashing."""
        pwd = "test_password"
        hashed = hash_password(pwd, "sha256")
        # Should be hexadecimal string of correct length
        self.assertEqual(len(hashed), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hashed))

    def test_verify_password_correct(self) -> None:
        """Test password verification with correct password."""
        pwd = "test_password"
        hashed = hash_password(pwd)
        result = verify_password(pwd, hashed)
        self.assertTrue(result)

    def test_verify_password_wrong(self) -> None:
        """Test password verification with wrong password."""
        pwd = "test_password"
        hashed = hash_password(pwd)
        result = verify_password("wrong_password", hashed)
        self.assertFalse(result)

    def test_gen_random_token(self) -> None:
        """Test random token generation."""
        token = gen_random_token(32)
        # Should be hex string - 32 bytes input gives 32 hex chars (16 bytes * 2)
        self.assertEqual(len(token), 32)  # length // 2 * 2 = 32
        self.assertTrue(all(c in "0123456789abcdef" for c in token))

    def test_validate_email_valid(self) -> None:
        """Test email validation with valid emails."""
        self.assertTrue(validate_email("user@example.com"))
        self.assertTrue(validate_email("test.user@example.co.uk"))

    def test_validate_email_invalid(self) -> None:
        """Test email validation with invalid emails."""
        self.assertFalse(validate_email("invalid"))
        self.assertFalse(validate_email("user@"))
        self.assertFalse(validate_email("@example.com"))

    def test_sanitize_input_normal(self) -> None:
        """Test input sanitization with normal text."""
        result = sanitize_input("  hello world  ")
        self.assertEqual(result, "hello world")

    def test_sanitize_input_length(self) -> None:
        """Test input sanitization with length limit."""
        result = sanitize_input("a" * 2000, max_length=100)
        self.assertEqual(len(result), 100)

    def test_sanitize_input_null_bytes(self) -> None:
        """Test input sanitization removes null bytes."""
        result = sanitize_input("hello\x00world")
        self.assertEqual(result, "helloworld")

    def test_checksum_file(self) -> None:
        """Test file checksum computation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            fname = f.name

        try:
            checksum = checksum_file(fname)
            # Should be valid SHA256 hex
            self.assertEqual(len(checksum), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in checksum))
        finally:
            import os

            os.unlink(fname)


if __name__ == "__main__":
    unittest.main()
