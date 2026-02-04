# coding: utf-8
"""Authentication API endpoints."""
from __future__ import print_function, unicode_literals

from .base import get_json_body
from ..services.auth_svc import validate_login, change_password, logout
from ..util import Pebkac


def post_login(cli):
    """POST /api/v1/auth/login - Authenticate user.

    Request body (JSON):
        {
            "password": "mypassword",
            "username": "alice"  # optional, if usernames enabled
        }

    Returns:
        dict with user and authenticated flag
    """
    body = get_json_body(cli)
    uname = body.get("username", "")
    pwd = body.get("password", "")

    if not pwd:
        raise Pebkac(422, "Password required")

    # Combine username and password if usernames enabled
    if uname and cli.args.usernames:
        pwd = "{}:{}".format(uname, pwd)

    # Validate credentials
    return validate_login(pwd, cli.asrv)


def post_logout(cli):
    """POST /api/v1/auth/logout - Logout user.

    Returns:
        dict with logout status
    """
    # Logout user
    return logout(cli.uname, cli.asrv, cli.conn.hsrv.broker)


def post_chpw(cli):
    """POST /api/v1/auth/chpw - Change user password.

    Request body (JSON):
        {
            "old_password": "current",
            "new_password": "newpass"
        }

    Returns:
        dict with operation status
    """
    if cli.uname == "*":
        raise Pebkac(401, "Anonymous users cannot change password")

    body = get_json_body(cli)
    old_pwd = body.get("old_password", "")
    new_pwd = body.get("new_password", "")

    if not old_pwd or not new_pwd:
        raise Pebkac(400, "Both old and new passwords required")

    # Verify old password is correct
    if cli.args.usernames:
        check_pwd = "{}:{}".format(cli.uname, old_pwd)
    else:
        check_pwd = old_pwd

    hpwd = cli.asrv.ah.hash(check_pwd) if cli.asrv.ah.on else check_pwd
    stored_pwd = cli.asrv.acct.get(cli.uname)

    if hpwd != stored_pwd:
        raise Pebkac(401, "Current password is incorrect")

    # Change to new password
    return change_password(cli.uname, new_pwd, cli.asrv, cli.conn.hsrv.broker)
