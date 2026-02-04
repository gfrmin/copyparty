"""Database repository package."""
from __future__ import print_function, unicode_literals

DB_VER = 6

try:
    import sqlite3

    HAVE_SQLITE3 = True
except ImportError:
    HAVE_SQLITE3 = False
