# coding: utf-8
from __future__ import print_function, unicode_literals

import json

from .util import Pebkac


def api_ok(data):
    return {"ok": True, "data": data}


def api_err(code, msg):
    return {"ok": False, "error": msg, "code": code}


API_ROUTES = {
    ("GET", "mounts"): "api_mounts",
    ("GET", "config"): "api_config",
    ("GET", "status"): "api_status",
}


def dispatch_api(cli):
    """Route an API request. Called when vpath starts with '.cpr/api/'.

    Returns True on success (keepalive), False to close connection.
    """
    api_path = cli.vpath[9:]  # strip ".cpr/api/"
    method = cli.mode

    for (route_method, prefix), handler_name in API_ROUTES.items():
        if method == route_method and api_path == prefix:
            handler = getattr(cli, handler_name, None)
            if handler is None:
                break
            try:
                result = handler()
                body = json.dumps(api_ok(result)).encode("utf-8")
                cli.reply(body, 200, "application/json")
                return True
            except Pebkac as ex:
                body = json.dumps(api_err(ex.code, str(ex))).encode("utf-8")
                cli.reply(body, ex.code, "application/json")
                return ex.code < 500
            except Exception as ex:
                body = json.dumps(api_err(500, str(ex))).encode("utf-8")
                cli.reply(body, 500, "application/json")
                return False

    body = json.dumps(api_err(404, "unknown API endpoint: " + api_path)).encode("utf-8")
    cli.reply(body, 404, "application/json")
    return False
