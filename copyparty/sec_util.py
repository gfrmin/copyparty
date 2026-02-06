"""Security utilities for copyparty.

Handles hashing, cryptographic operations, and validation.
"""

import hashlib
import secrets
from typing import Tuple


def gencookie(
    name: str,
    value: str,
    days: int = 365,
    path: str = "/",
    secure: bool = False,
    httponly: bool = True,
) -> str:
    """Generate HTTP Set-Cookie header value.

    Args:
        name: Cookie name
        value: Cookie value
        days: Days until expiration
        path: Cookie path
        secure: Whether to set Secure flag
        httponly: Whether to set HttpOnly flag

    Returns:
        Set-Cookie header value
    """
    cookie = f"{name}={value}"

    if days:
        cookie += f"; Max-Age={days * 86400}"

    if path:
        cookie += f"; Path={path}"

    if secure:
        cookie += "; Secure"

    if httponly:
        cookie += "; HttpOnly"

    cookie += "; SameSite=Lax"

    return cookie


def gen_content_disposition(fn: str) -> str:
    """Generate Content-Disposition header value.

    Args:
        fn: Filename

    Returns:
        Content-Disposition header value
    """
    # Escape filename for HTTP header
    fn_escaped = fn.replace("\\", "\\\\").replace('"', '\\"')
    return f'attachment; filename="{fn_escaped}"'


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """Hash password using specified algorithm.

    Args:
        password: Password to hash
        algorithm: Hash algorithm (sha256, sha512, etc.)

    Returns:
        Hexadecimal hash string
    """
    if algorithm == "sha256":
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode("utf-8")).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode("utf-8")).hexdigest()
    else:
        return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password: str, hashed: str, algorithm: str = "sha256") -> bool:
    """Verify password against hash.

    Args:
        password: Password to verify
        hashed: Hashed password
        algorithm: Hash algorithm used

    Returns:
        True if password matches hash, False otherwise
    """
    return hash_password(password, algorithm) == hashed


def gen_random_token(length: int = 32) -> str:
    """Generate random secure token.

    Args:
        length: Token length in bytes

    Returns:
        Hexadecimal token string
    """
    return secrets.token_hex(length // 2)


def gen_random_password(length: int = 16) -> str:
    """Generate random password.

    Args:
        length: Password length

    Returns:
        Random password string
    """
    import string

    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def checksum_file(filepath: str, algorithm: str = "sha256") -> str:
    """Compute checksum of file.

    Args:
        filepath: Path to file
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal checksum string
    """
    hasher = hashlib.new(algorithm)

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def validate_email(email: str) -> bool:
    """Basic email validation.

    Args:
        email: Email address to validate

    Returns:
        True if email appears valid, False otherwise
    """
    import re

    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input.

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text
    """
    # Remove null bytes
    text = text.replace("\x00", "")
    # Limit length
    text = text[:max_length]
    # Strip whitespace
    text = text.strip()
    return text
