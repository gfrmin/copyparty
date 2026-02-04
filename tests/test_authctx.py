#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import os
import shutil
import tempfile
import unittest

from copyparty.authsrv import AuthSrv
from copyparty.authctx import resolve_credentials, resolve_ip_user, resolve_permissions
from tests import util as tu
from tests.util import Cfg


class TestResolveCredentials(unittest.TestCase):
    def setUp(self):
        self.td = tu.get_ramdisk()
        td = os.path.join(self.td, "vfs")
        os.mkdir(td)
        os.chdir(td)

    def tearDown(self):
        os.chdir(tempfile.gettempdir())
        shutil.rmtree(self.td)

    def log(self, src, msg, c=0):
        print(msg)

    def test_anonymous(self):
        """No credentials yields anonymous user."""
        args = Cfg(v=[".::r"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({}, {}, "", args, asrv)
        self.assertEqual(uname, "*")
        self.assertEqual(pw, "")

    def test_url_param(self):
        """Password from URL parameter resolves to correct user."""
        args = Cfg(v=[".::r"], a=["u:testpw"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({}, {"pw": "testpw"}, "", args, asrv)
        self.assertEqual(pw, "testpw")
        self.assertEqual(uname, "u")

    def test_cookie_fallback(self):
        """Cookie password used when no other source available."""
        args = Cfg(v=[".::r"], a=["u:cookiepw"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({}, {}, "cookiepw", args, asrv)
        self.assertEqual(pw, "cookiepw")
        self.assertEqual(uname, "u")

    def test_header_pw(self):
        """Password from custom header resolves to correct user."""
        args = Cfg(v=[".::r"], a=["u:hdrpw"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({"pw": "hdrpw"}, {}, "", args, asrv)
        self.assertEqual(pw, "hdrpw")
        self.assertEqual(uname, "u")

    def test_url_param_takes_precedence_over_cookie(self):
        """URL param password wins over cookie password."""
        args = Cfg(v=[".::r"], a=["u:urlpw", "v:cookpw"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({}, {"pw": "urlpw"}, "cookpw", args, asrv)
        self.assertEqual(pw, "urlpw")
        self.assertEqual(uname, "u")

    def test_unknown_password(self):
        """Unknown password yields anonymous user."""
        args = Cfg(v=[".::r"], a=["u:realpw"])
        asrv = AuthSrv(args, self.log)
        pw, uname = resolve_credentials({}, {"pw": "wrongpw"}, "", args, asrv)
        self.assertEqual(pw, "wrongpw")
        self.assertEqual(uname, "*")

    def test_basic_auth(self):
        """Basic auth password resolves to correct user."""
        import base64

        args = Cfg(v=[".::r"], a=["u:bapw"])
        asrv = AuthSrv(args, self.log)
        b64 = base64.b64encode(b"u:bapw").decode("ascii")
        headers = {"authorization": "Basic " + b64}
        pw, uname = resolve_credentials(headers, {}, "", args, asrv)
        self.assertEqual(uname, "u")

    def test_no_bauth_flag(self):
        """Basic auth is ignored when no_bauth is set."""
        import base64

        args = Cfg(v=[".::r"], a=["u:bapw"], no_bauth=True)
        asrv = AuthSrv(args, self.log)
        b64 = base64.b64encode(b"u:bapw").decode("ascii")
        headers = {"authorization": "Basic " + b64}
        pw, uname = resolve_credentials(headers, {}, "", args, asrv)
        self.assertEqual(uname, "*")


class TestResolvePermissions(unittest.TestCase):
    def setUp(self):
        self.td = tu.get_ramdisk()
        td = os.path.join(self.td, "vfs")
        os.mkdir(td)
        os.chdir(td)

    def tearDown(self):
        os.chdir(tempfile.gettempdir())
        shutil.rmtree(self.td)

    def log(self, src, msg, c=0):
        print(msg)

    def test_read_only(self):
        """Read-only volume grants read but not write."""
        args = Cfg(v=[".::r"])
        asrv = AuthSrv(args, self.log)
        vn, avn, rem, perms = resolve_permissions("*", "", asrv)
        can_read, can_write = perms[0], perms[1]
        self.assertTrue(can_read)
        self.assertFalse(can_write)

    def test_read_write(self):
        """Read-write volume grants both read and write."""
        args = Cfg(v=[".::rw"])
        asrv = AuthSrv(args, self.log)
        vn, avn, rem, perms = resolve_permissions("*", "", asrv)
        can_read, can_write = perms[0], perms[1]
        self.assertTrue(can_read)
        self.assertTrue(can_write)

    def test_no_access(self):
        """User without access gets all-false permissions."""
        args = Cfg(v=[".::r,u"], a=["u:pw"])
        asrv = AuthSrv(args, self.log)
        vn, avn, rem, perms = resolve_permissions("*", "", asrv)
        can_read, can_write = perms[0], perms[1]
        self.assertFalse(can_read)
        self.assertFalse(can_write)

    def test_vn_and_rem(self):
        """VFS node and remainder are correctly returned."""
        args = Cfg(v=[".::r"])
        asrv = AuthSrv(args, self.log)
        vn, avn, rem, perms = resolve_permissions("*", "", asrv)
        self.assertIsNotNone(vn)
        self.assertIsNotNone(avn)
        self.assertEqual(rem, "")

    def test_admin_permission(self):
        """Admin volume grants admin permission."""
        args = Cfg(v=[".::A"])
        asrv = AuthSrv(args, self.log)
        vn, avn, rem, perms = resolve_permissions("*", "", asrv)
        can_admin = perms[7]
        self.assertTrue(can_admin)


class TestResolveIpUser(unittest.TestCase):
    def log(self, msg, c=0):
        pass

    def test_noop_when_no_flags(self):
        """Returns uname unchanged when have_ipu_or_ipr is False."""
        from argparse import Namespace

        args = Namespace(have_ipu_or_ipr=False)
        uname = resolve_ip_user("testuser", "127.0.0.1", args, None, self.log)
        self.assertEqual(uname, "testuser")

    def test_anonymous_passthrough(self):
        """Anonymous user passes through when no overrides."""
        from argparse import Namespace

        args = Namespace(have_ipu_or_ipr=False)
        uname = resolve_ip_user("*", "127.0.0.1", args, None, self.log)
        self.assertEqual(uname, "*")
