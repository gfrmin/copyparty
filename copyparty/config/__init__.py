"""Configuration management for copyparty.

This package provides modular components for parsing and processing
copyparty configuration from command-line arguments and config files.

Modules:
- parsers: Parse CLI arguments (accounts, groups, volumes)
- validators: Validate parsed configuration
- vfs_builder: Build virtual filesystem tree
- permissions: Resolve permission sets
- volflag_processor: Process volume-specific flags
"""

from .parsers import AccountParser, GroupParser, VolspecParser
from .vfs_builder import VFSBuilder
from .permissions import PermissionResolver

__all__ = [
    "AccountParser",
    "GroupParser",
    "VolspecParser",
    "VFSBuilder",
    "PermissionResolver",
]
