"""Turn bind names ('local', 'lan', 'tailscale', 'all' or an IP) into listening sockets."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

# Tailscale hands out addresses from the CGNAT range.
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")
NAMES = ("local", "tailscale", "lan", "all")
# A program run from a process that has no window (pythonw, a scheduled task) is given one of its own by
# Windows, for a blink, every time it is run. Not these.
NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class BindError(Exception):
    """A bind name is not valid, or the address could not be listened on."""


def tailscale_command() -> str | None:
    """The full path of the Tailscale command-line tool, or None if it is not installed.

    Looked up here instead of just running "tailscale": on Windows that would also run a file
    of that name that happens to lie in the folder the program was started from.
    """
    names = ("tailscale.exe",) if sys.platform == "win32" else ("tailscale", "Tailscale")
    places = [Path(place) for place in os.environ.get("PATH", "").split(os.pathsep) if place]
    if sys.platform == "win32":
        places.insert(0, Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tailscale")
    elif sys.platform == "darwin":
        places.append(Path("/Applications/Tailscale.app/Contents/MacOS"))
    for place in places:
        if not place.is_absolute():
            continue  # "." and the like: exactly what this function exists to leave out
        for name in names:
            if (place / name).is_file():
                return str(place / name)
    return None


def tailscale_ip() -> str | None:
    command = tailscale_command()
    try:
        if command is not None:
            out = subprocess.run(
                [command, "ip", "-4"], capture_output=True, encoding="utf-8", errors="replace", timeout=5, check=True, creationflags=NO_WINDOW
            ).stdout
            return str(ipaddress.ip_address(out.split()[0]))
    except (OSError, subprocess.SubprocessError, ValueError, IndexError, AttributeError):
        pass
    # CLI missing or not on PATH: look for a Tailscale-range address on this machine instead.
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return None
    for info in infos:
        addr = str(info[4][0])
        if ipaddress.ip_address(addr) in TAILSCALE_NET:
            return addr
    return None


def lan_ip() -> str | None:
    """Address of the interface that carries the default route."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))  # UDP connect sends nothing, it only picks a route
            addr = str(probe.getsockname()[0])
        except OSError:
            return None
    # With a Tailscale exit node the default route is the tunnel, which is not the LAN.
    return None if ipaddress.ip_address(addr) in TAILSCALE_NET else addr


_ZONE = re.compile(r"[A-Za-z0-9_.-]{1,32}")


def normalize(names: Iterable[str]) -> list[str]:
    """Validate bind names. 'local' always comes first: this machine can never lock itself out."""
    result = ["local"]
    for name in names:
        key = name.strip().lower()
        if key in ("localhost", "loopback", "127.0.0.1"):
            key = "local"
        if key not in NAMES:
            try:
                address = ipaddress.ip_address(key)
            except ValueError:
                raise BindError(
                    f"unknown bind {name[:80]!r} - use local, lan, tailscale, all or an IP address"
                ) from None
            # An IPv6 address may say which network interface it is on, after a "%" (fe80::1%eth0), and the
            # library takes whatever follows the sign for that. A line break and three thousand letters
            # were "an IP address", saved, and shown back to everybody. Half a character was saved, and
            # refused at the next start, in both copies. A NUL ended the program as it went to listen, at
            # that start and at every one after. An interface is called by a few letters and digits.
            zone = getattr(address, "scope_id", None)
            if zone is not None and not _ZONE.fullmatch(zone):
                raise BindError(f"unknown bind {name[:80]!r} - what follows the % is the name of a network interface: letters, digits, dots, hyphens")
            key = str(address)
        if key not in result:
            result.append(key)
    return result


def resolve(names: Iterable[str]) -> tuple[list[str], list[str]]:
    """Bind names -> (addresses to listen on, names that have no address right now)."""
    addresses: list[str] = []
    missing: list[str] = []
    for name in normalize(names):
        if name == "local":
            addr: str | None = "127.0.0.1"
        elif name == "all":
            addr = "0.0.0.0"
        elif name == "lan":
            addr = lan_ip()
        elif name == "tailscale":
            addr = tailscale_ip()
        else:
            addr = name
        if addr is None:
            missing.append(name)  # e.g. Tailscale not connected yet; the caller retries later
        elif addr not in addresses:
            addresses.append(addr)
    if "0.0.0.0" in addresses:
        # The wildcard already covers every IPv4 address; binding both would conflict.
        addresses = [a for a in addresses if ":" in a or a == "0.0.0.0"]
    return addresses, missing


def open_sockets(addresses: Iterable[str], port: int, wait: float = 0.0) -> list[socket.socket]:
    """Listen on every address. `wait` keeps retrying a busy port for that many seconds."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return _open_sockets(addresses, port)
        except BindError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def _open_sockets(addresses: Iterable[str], port: int) -> list[socket.socket]:
    sockets: list[socket.socket] = []
    for addr in addresses:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if sys.platform == "win32":
                # On Windows SO_REUSEADDR would let a second process steal the port.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((addr, port))
        except (OSError, OverflowError, TypeError, ValueError) as ex:
            # (OverflowError: a port that is no port, which is not the system's to refuse. The other two: an
            # address the system's own reader of addresses will not take, which it says by one of these and
            # not as an error of its own. Unanswered, either ended the program in a traceback, at every start.)
            sock.close()
            for opened in sockets:
                opened.close()
            raise BindError(f"cannot listen on {addr}:{port} - {getattr(ex, 'strerror', None) or ex}") from ex
        sockets.append(sock)
    return sockets
