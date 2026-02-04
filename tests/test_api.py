#!/usr/bin/env python3
# coding: utf-8
from __future__ import print_function, unicode_literals

import json
import os
import shutil
import tempfile
import unittest

from copyparty.authsrv import AuthSrv
from copyparty.httpcli import HttpCli
from tests import util as tu
from tests.util import Cfg


def hdr(path, method="GET"):
    h = "{} /{} HTTP/1.1\r\nConnection: close\r\n\r\n"
    return h.format(method, path).encode("utf-8")


class TestApi(unittest.TestCase):
    def setUp(self):
        self.td = tu.get_ramdisk()
        td = os.path.join(self.td, "vfs")
        os.mkdir(td)
        os.chdir(td)
        self.args = Cfg(v=[".::r"])
        self.asrv = AuthSrv(self.args, self.log)
        self.conn = tu.VHttpConn(self.args, self.asrv, self.log, b"")

    def tearDown(self):
        os.chdir(tempfile.gettempdir())
        shutil.rmtree(self.td)

    def api_get(self, path, method="GET"):
        conn = self.conn.setbuf(hdr(path, method))
        HttpCli(conn).run()
        raw = conn.s._reply.decode("utf-8")
        header, body = raw.split("\r\n\r\n", 1)
        return header, body

    def test_api_status(self):
        h, b = self.api_get(".cpr/api/status")
        self.assertIn("200", h)
        data = json.loads(b)
        self.assertTrue(data["ok"])
        self.assertIn("version", data["data"])
        self.assertIn("uptime", data["data"])
        self.assertTrue(data["data"]["ok"])

    def test_api_config(self):
        h, b = self.api_get(".cpr/api/config")
        self.assertIn("200", h)
        data = json.loads(b)
        self.assertTrue(data["ok"])
        self.assertIn("version", data["data"])

    def test_api_mounts(self):
        h, b = self.api_get(".cpr/api/mounts")
        self.assertIn("200", h)
        data = json.loads(b)
        self.assertTrue(data["ok"])
        self.assertIn("volumes", data["data"])

    def test_api_404(self):
        h, b = self.api_get(".cpr/api/nonexistent")
        self.assertIn("404", h)
        data = json.loads(b)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], 404)

    def test_existing_ls_unchanged(self):
        h, b = self.api_get("?ls")
        self.assertIn("200", h)

    def log(self, src, msg, c=0):
        print(msg)
