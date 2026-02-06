"""Filesystem utilities for copyparty.

Handles file operations, permissions, and directory management.
"""

import os
import shutil
import stat
from typing import Any, Callable, List, Tuple, Union, IO


def set_fperms(f: Union[IO[Any], IO[bytes]], vf: dict[str, Any]) -> None:
    """Set file permissions on an open file.

    Args:
        f: Open file object
        vf: Volume flags dict with uid, gid, chmod_f
    """
    try:
        if hasattr(f, "fileno"):
            fd = f.fileno()
            uid = vf.get("uid", -1)
            gid = vf.get("gid", -1)
            chmod = vf.get("chmod_f", 0)

            if uid != -1 or gid != -1:
                os.fchown(fd, uid, gid)

            if chmod:
                os.fchmod(fd, chmod)
    except (OSError, AttributeError):
        pass


def set_ap_perms(ap: str, vf: dict[str, Any]) -> None:
    """Set file permissions on a file path.

    Args:
        ap: Absolute path
        vf: Volume flags dict with uid, gid, chmod_d, chmod_f
    """
    try:
        uid = vf.get("uid", -1)
        gid = vf.get("gid", -1)

        if uid != -1 or gid != -1:
            os.chown(ap, uid, gid)

        chmod = vf.get("chmod_f", 0)
        if not chmod:
            chmod = vf.get("chmod_d", 0)

        if chmod:
            os.chmod(ap, chmod)
    except (OSError, PermissionError):
        pass


def atomic_move(
    log: "NamedLogger",
    src: str,
    dst: str,
    flags: dict[str, Any],
) -> None:
    """Atomically move file from src to dst.

    Args:
        log: Logger instance
        src: Source path
        dst: Destination path
        flags: Volume flags for permissions
    """
    try:
        # Try atomic rename first
        os.replace(src, dst)
        set_ap_perms(dst, flags)
    except OSError:
        # Fall back to copy + delete
        try:
            shutil.move(src, dst)
            set_ap_perms(dst, flags)
        except Exception as ex:
            log(f"Failed to move {src} to {dst}: {ex}")
            raise


def get_df(abspath: str, prune: bool = False) -> Tuple[int, int, str]:
    """Get disk free space for a path.

    Args:
        abspath: Absolute path
        prune: Whether to prune unavailable space

    Returns:
        Tuple of (total_bytes, free_bytes, error_msg)
    """
    try:
        stat_result = os.statvfs(abspath)
        total = stat_result.f_blocks * stat_result.f_frsize
        free = stat_result.f_bavail * stat_result.f_frsize

        if prune and stat_result.f_bavail < stat_result.f_bfree:
            free = stat_result.f_bavail * stat_result.f_frsize

        return total, free, ""
    except (OSError, AttributeError) as ex:
        return 0, 0, str(ex)


def statdir(
    log: "RootLogger",
    top: str,
    recursive: bool = False,
) -> Tuple[int, int]:
    """Get statistics for directory (size and file count).

    Args:
        log: Logger instance
        top: Top directory path
        recursive: Whether to recurse subdirectories

    Returns:
        Tuple of (total_size, file_count)
    """
    total_size = 0
    file_count = 0

    try:
        for entry in os.scandir(top):
            try:
                if entry.is_file(follow_symlinks=False):
                    total_size += entry.stat(follow_symlinks=False).st_size
                    file_count += 1
                elif recursive and entry.is_dir(follow_symlinks=False):
                    sub_size, sub_count = statdir(log, entry.path, recursive)
                    total_size += sub_size
                    file_count += sub_count
            except (OSError, PermissionError):
                pass
    except (OSError, PermissionError):
        pass

    return total_size, file_count


def rmdirs(
    log: "RootLogger",
    top: str,
    keep_root: bool = False,
) -> Tuple[List[str], List[str]]:
    """Remove directory tree.

    Args:
        log: Logger instance
        top: Top directory path
        keep_root: Whether to keep the root directory

    Returns:
        Tuple of (removed_dirs, errors)
    """
    removed = []
    errors = []

    for root, dirs, files in os.walk(top, topdown=False):
        # Remove files first
        for file in files:
            filepath = os.path.join(root, file)
            try:
                os.unlink(filepath)
            except (OSError, PermissionError) as ex:
                errors.append(f"{filepath}: {ex}")

        # Remove directories
        for dir_name in dirs:
            dirpath = os.path.join(root, dir_name)
            try:
                os.rmdir(dirpath)
                removed.append(dirpath)
            except (OSError, PermissionError) as ex:
                errors.append(f"{dirpath}: {ex}")

    # Remove root directory if not keeping it
    if not keep_root:
        try:
            os.rmdir(top)
            removed.append(top)
        except (OSError, PermissionError) as ex:
            errors.append(f"{top}: {ex}")

    return removed, errors


def rmdirs_up(top: str, stop: str) -> Tuple[List[str], List[str]]:
    """Remove empty directories from top up to stop.

    Args:
        top: Top directory to start removing from
        stop: Stop path (don't remove this or above)

    Returns:
        Tuple of (removed_dirs, errors)
    """
    removed = []
    errors = []

    current = top
    while current and current != stop and len(current) > 1:
        try:
            if os.path.isdir(current) and not os.listdir(current):
                os.rmdir(current)
                removed.append(current)
                current = os.path.dirname(current)
            else:
                break
        except (OSError, PermissionError) as ex:
            errors.append(f"{current}: {ex}")
            break

    return removed, errors
