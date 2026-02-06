"""Network utilities for copyparty.

Handles socket operations, IP address handling, and network configuration.
"""

import ipaddress
import socket
from typing import Any, Callable, Generator, List, Optional, Tuple


class Unrecv:
    """Unbuffered receive wrapper for socket operations."""

    def __init__(self, sock: socket.socket, bufsize: int = 4096):
        """Initialize with socket and buffer size.

        Args:
            sock: Socket to receive from
            bufsize: Buffer size for reads
        """
        self.sock = sock
        self.bufsize = bufsize


def shut_socket(log: "NamedLogger", sck: socket.socket, timeout: int = 3) -> None:
    """Gracefully shutdown socket with timeout.

    Args:
        log: Logger instance
        sck: Socket to shutdown
        timeout: Timeout in seconds
    """
    try:
        sck.settimeout(timeout)
        sck.shutdown(socket.SHUT_RDWR)
    except (OSError, socket.error):
        pass
    finally:
        try:
            sck.close()
        except (OSError, socket.error):
            pass


def read_socket(
    sr: Unrecv,
    nbyte: int,
    t_idle: int = 3,
    t_tot: int = 30,
    log: Optional[Callable[[str], None]] = None,
) -> bytes:
    """Read exact number of bytes from socket with timeout.

    Args:
        sr: Unbuffered receive wrapper
        nbyte: Number of bytes to read
        t_idle: Idle timeout in seconds
        t_tot: Total timeout in seconds
        log: Optional logger

    Returns:
        Bytes read from socket

    Raises:
        Exception: If timeout occurs or socket error
    """
    import time

    sr.sock.settimeout(t_idle)
    data = b""
    t0 = time.time()

    while len(data) < nbyte:
        if time.time() - t0 > t_tot:
            raise Exception("read socket timeout (total)")

        try:
            chunk = sr.sock.recv(min(sr.bufsize, nbyte - len(data)))
            if not chunk:
                raise Exception("socket closed")
            data += chunk
        except socket.timeout:
            raise Exception("read socket timeout (idle)")

    return data


def read_socket_unbounded(sr: Unrecv, bufsz: int) -> Generator[bytes, None, None]:
    """Read unlimited bytes from socket in chunks.

    Args:
        sr: Unbuffered receive wrapper
        bufsz: Buffer size for each chunk

    Yields:
        Chunks of bytes read from socket
    """
    while True:
        try:
            chunk = sr.sock.recv(bufsz)
            if not chunk:
                break
            yield chunk
        except socket.error:
            break


def list_ips() -> List[str]:
    """List all IP addresses on the system.

    Returns:
        List of IP address strings
    """
    ips = []
    try:
        # Try to get hostname and resolve all IPs
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip not in ips:
                ips.append(ip)
    except socket.error:
        pass

    # Add localhost
    if "127.0.0.1" not in ips:
        ips.append("127.0.0.1")

    return ips


def ipnorm(ip: str) -> str:
    """Normalize IP address to string form.

    Args:
        ip: IP address string

    Returns:
        Normalized IP address
    """
    try:
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except (ValueError, ipaddress.AddressValueError):
        return ip


def find_prefix(ips: List[str], cidrs: List[str]) -> List[str]:
    """Find which CIDR prefixes match given IPs.

    Args:
        ips: List of IP addresses to check
        cidrs: List of CIDR prefixes to check against

    Returns:
        List of matching CIDR prefixes
    """
    matches = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in ips:
                if ipaddress.ip_address(ip) in network:
                    if cidr not in matches:
                        matches.append(cidr)
                    break
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            pass

    return matches


def build_netmap(csv: str, defer_mutex: bool = False) -> dict:
    """Build network map from CSV configuration.

    Args:
        csv: CSV configuration string (cidr1,cidr2,...)
        defer_mutex: Whether to defer mutex operations

    Returns:
        Network map dictionary
    """
    cidrs = [x.strip() for x in csv.split(",") if x.strip()]
    return {"cidrs": cidrs, "ips": list_ips()}
