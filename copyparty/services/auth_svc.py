# coding: utf-8
"""Authentication service for API endpoints."""
from __future__ import print_function, unicode_literals

from ..util import Pebkac


def validate_login(pwd, asrv):
    """Validate login credentials and return username.

    Args:
        pwd: Password string (may include username:password)
        asrv: AuthServer instance

    Returns:
        dict with username and auth status

    Raises:
        Pebkac: For invalid credentials
    """
    if not pwd:
        raise Pebkac(422, "Password cannot be blank")

    # Check if password is valid and get corresponding username
    hpwd = asrv.ah.hash(pwd) if asrv.ah.on else pwd
    uname = asrv.iacct.get(hpwd)

    if not uname:
        raise Pebkac(401, "Invalid credentials")

    return {
        "user": uname,
        "authenticated": True,
    }


def change_password(uname, new_pwd, asrv, broker):
    """Change user password.

    Args:
        uname: Username
        new_pwd: New password
        asrv: AuthServer instance
        broker: Message broker

    Returns:
        dict with operation status

    Raises:
        Pebkac: For password policy or permission errors
    """
    if uname == "*":
        raise Pebkac(401, "Anonymous users cannot change password")

    # Use existing asrv.chpw() method
    ok, msg = asrv.chpw(broker, uname, new_pwd)

    if not ok:
        raise Pebkac(400, msg)

    return {
        "status": "password changed",
        "user": uname,
    }


def logout(uname, asrv, broker):
    """Logout user and clear session.

    Args:
        uname: Username
        asrv: AuthServer instance
        broker: Message broker

    Returns:
        dict with logout status
    """
    if uname and not uname.startswith("s_"):
        asrv.forget_session(broker, uname)

    return {
        "status": "logged out",
        "user": uname,
    }
