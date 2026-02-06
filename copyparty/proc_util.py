"""Process and command execution utilities for copyparty.

Handles subprocess execution, process management, and hooks.
"""

import os
import signal
import subprocess
import sys
from typing import Any, List, Optional, Tuple, Union


def getalive(pids: List[int], pgid: int) -> List[int]:
    """Get list of alive processes from given PIDs.

    Args:
        pids: List of process IDs to check
        pgid: Process group ID

    Returns:
        List of alive process IDs
    """
    alive = []
    for pid in pids:
        try:
            # Check if process exists by sending signal 0 (no-op)
            os.kill(pid, 0)
            alive.append(pid)
        except (OSError, ProcessLookupError):
            pass
    return alive


def killtree(root: int) -> None:
    """Kill process tree starting from root PID.

    Args:
        root: Root process ID to kill
    """
    try:
        # Get all child processes
        if sys.platform.startswith("linux"):
            try:
                # Linux: use ps to find children
                result = subprocess.run(
                    ["ps", "--ppid", str(root), "-o", "pid="],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if line.strip():
                        child_pid = int(line.strip())
                        killtree(child_pid)
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass

        # Kill root process
        os.kill(root, signal.SIGTERM)
        try:
            # Wait for graceful shutdown
            os.waitpid(root, 0)
        except OSError:
            # Force kill if still alive
            try:
                os.kill(root, signal.SIGKILL)
            except OSError:
                pass
    except (OSError, ProcessLookupError):
        pass


def runcmd(
    argv: Union[List[bytes], List[str]],
    timeout: Optional[float] = None,
    stdin: Optional[bytes] = None,
    cwd: Optional[str] = None,
) -> Tuple[str, str]:
    """Run command and return stdout/stderr.

    Args:
        argv: Command and arguments
        timeout: Timeout in seconds
        stdin: Input to provide to command
        cwd: Working directory

    Returns:
        Tuple of (stdout, stderr)

    Raises:
        subprocess.TimeoutExpired: If timeout occurs
        subprocess.CalledProcessError: If command fails
    """
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin.decode() if isinstance(stdin, bytes) else stdin,
            cwd=cwd,
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired as ex:
        return "", str(ex)
    except subprocess.CalledProcessError as ex:
        return ex.stdout or "", ex.stderr or ""


def chkcmd(
    argv: Union[List[bytes], List[str]],
    timeout: float = 10,
) -> Tuple[str, str]:
    """Run command and check if it succeeded.

    Args:
        argv: Command and arguments
        timeout: Timeout in seconds

    Returns:
        Tuple of (stdout, stderr)

    Raises:
        subprocess.CalledProcessError: If command fails
    """
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return result.stdout, result.stderr


def retchk(
    argv: Union[List[bytes], List[str]],
    expected: int = 0,
    timeout: float = 10,
) -> bool:
    """Check if command returns expected exit code.

    Args:
        argv: Command and arguments
        expected: Expected exit code (default 0)
        timeout: Timeout in seconds

    Returns:
        True if command returns expected code, False otherwise
    """
    try:
        result = subprocess.run(
            argv,
            timeout=timeout,
            capture_output=True,
        )
        return result.returncode == expected
    except (subprocess.TimeoutExpired, OSError):
        return False
