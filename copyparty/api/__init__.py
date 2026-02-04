# coding: utf-8
"""API v1 endpoints and dispatcher for copyparty.

This package contains the RESTful JSON API endpoints, separated by concern,
plus the dispatcher that routes requests to handlers.
"""
from __future__ import print_function, unicode_literals

import json
import re

from ..util import Pebkac


def api_ok(data):
    return {"ok": True, "data": data}


def api_err(code, msg):
    return {"ok": False, "error": msg, "code": code}


# Legacy v0 routes (backward compatibility)
API_ROUTES_V0 = {
    ("GET", "mounts"): "api_mounts",
    ("GET", "config"): "api_config",
    ("GET", "status"): "api_status",
}

# v1 API routes with version prefix
# Format: (method, pattern, module_name, handler_function_name)
# Patterns support path parameters which become named groups
API_ROUTES_V1 = [
    ("GET", r"^config$", "copyparty.api.config_api", "get_config"),
    ("GET", r"^session$", "copyparty.api.config_api", "get_session"),
    ("GET", r"^browse$", "copyparty.api.browse_api", "get_browse"),
]


def _match_route(method, path, routes):
    """Match a request method and path against route patterns.

    Returns (handler_module, handler_func, params_dict) or None.
    Params dict contains extracted path parameters.
    """
    for route_method, pattern, module_name, handler_name in routes:
        if method != route_method:
            continue

        match = re.match(pattern, path)
        if match:
            params = match.groupdict() if match else {}
            return module_name, handler_name, params

    return None


def dispatch_api(cli):
    """Route an API request. Called when vpath starts with '.cpr/api/'.

    Returns True on success (keepalive), False to close connection.
    """
    api_path = cli.vpath[9:]  # strip ".cpr/api/"
    method = cli.mode

    # Try v1 routes first (api/v1/...)
    if api_path.startswith("v1/"):
        v1_path = api_path[3:]  # strip "v1/"
        route_match = _match_route(method, v1_path, API_ROUTES_V1)

        if route_match:
            module_name, handler_name, params = route_match
            return _call_handler_v1(cli, module_name, handler_name, params)

    # Fall back to legacy v0 routes (backward compatibility)
    for (route_method, prefix), handler_name in API_ROUTES_V0.items():
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


def _call_handler_v1(cli, module_name, handler_name, params):
    """Call a v1 API handler from the api subpackage.

    Returns True on success (keepalive), False to close connection.
    """
    try:
        # Dynamically import the handler module
        parts = module_name.split(".")
        module = __import__(module_name, fromlist=[parts[-1]])
        handler = getattr(module, handler_name, None)

        if handler is None:
            raise Pebkac(500, "Handler not found: {}.{}".format(module_name, handler_name))

        # Call handler with cli context and params
        result = handler(cli, **params)
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
