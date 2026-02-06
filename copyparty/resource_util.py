# coding: utf-8
"""Resource loading utilities for copyparty.

Handles locating and loading package resources via importlib.resources,
pkg_resources, or direct filesystem access.
"""
from __future__ import print_function, unicode_literals

import codecs
import os
import sys
import types
from typing import IO

from .__init__ import PY2, EnvParams

from .util import fsenc

try:
    if sys.version_info < (3, 10) or os.environ.get("PRTY_NO_IMPRESO"):
        # py3.8 doesn't have .files
        # py3.9 has broken .is_file
        raise ImportError()
    import importlib.resources as impresources
except ImportError:
    try:
        import importlib_resources as impresources
    except ImportError:
        impresources = None
try:
    if sys.version_info > (3, 10):
        raise ImportError()
    import pkg_resources
except ImportError:
    pkg_resources = None


def _pkg_resource_exists(pkg: str, name: str) -> bool:
    if not pkg_resources:
        return False
    try:
        return pkg_resources.resource_exists(pkg, name)
    except NotImplementedError:
        return False


def stat_resource(E: EnvParams, name: str):
    path = E.mod_ + name
    if os.path.exists(path):
        return os.stat(fsenc(path))
    return None


def _find_impresource(pkg: types.ModuleType, name: str):
    assert impresources  # !rm
    try:
        files = impresources.files(pkg)
    except ImportError:
        return None

    return files.joinpath(name)


_rescache_has = {}


def _has_resource(name: str):
    try:
        return _rescache_has[name]
    except KeyError:
        pass

    if len(_rescache_has) > 999:
        _rescache_has.clear()

    assert __package__  # !rm
    pkg = sys.modules[__package__]

    if impresources:
        res = _find_impresource(pkg, name)
        if res and res.is_file():
            _rescache_has[name] = True
            return True

    if pkg_resources:
        if _pkg_resource_exists(pkg.__name__, name):
            _rescache_has[name] = True
            return True

    _rescache_has[name] = False
    return False


def has_resource(E: EnvParams, name: str):
    return _has_resource(name) or os.path.exists(E.mod_ + name)


def load_resource(E: EnvParams, name: str, mode="rb") -> IO[bytes]:
    enc = None if "b" in mode else "utf-8"

    if impresources:
        assert __package__  # !rm
        res = _find_impresource(sys.modules[__package__], name)
        if res and res.is_file():
            if enc:
                return res.open(mode, encoding=enc)
            else:
                # throws if encoding= is mentioned at all
                return res.open(mode)

    if pkg_resources:
        assert __package__  # !rm
        pkg = sys.modules[__package__]
        if _pkg_resource_exists(pkg.__name__, name):
            stream = pkg_resources.resource_stream(pkg.__name__, name)
            if enc:
                stream = codecs.getreader(enc)(stream)
            return stream

    ap = E.mod_ + name

    if PY2:
        return codecs.open(ap, "r", encoding=enc)  # type: ignore

    return open(ap, mode, encoding=enc)
