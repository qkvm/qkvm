"""The ports the tests choose themselves: closed_port() and port_to_listen_on() (tests/test_the_ports_the_tests_choose.py).

One chosen by binding port 0 and letting it go was the system's to hand out again at once, to any process's next bind to
port 0 or outgoing connection, and under fifty test processes at a time it was: two stand-ins of one test given one port, a
wall that found its own port taken. So they are taken from outside the range the system hands out by itself (read from
the system: /proc on Linux, netsh on Windows), never twice in one run, each found free as it is chosen, and each held
across the test processes of this computer's user while it is theirs: a file of its number in a folder they share, made
only where there is none (O_CREAT | O_EXCL) and taken away at the end of the run, or taken over once it is older than
LEASE (a run that was killed: a port let go of for a program is bound by that program within seconds, and one held for
closed_port is bound by its socket all along, which no other process's bind gets past).
"""

from __future__ import annotations

import atexit
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OWN_PORTS = range(21000, 32700)  # (above the walls and farms the lab runs on fixed ports below 21000)
LEASE = 60.0  # seconds a port's file holds it for its process
WAIT = 5 * LEASE  # how long a choice waits where every port of the tests' own is held just now (then: an error): a run that
# chooses many more than there are, as a probe of this did, waits for those let go of as their LEASE ends
_PICK = random.SystemRandom()  # (not the module's own, which a test may seed: processes seeded alike would pick alike)
_chosen: set[int] = set()
_held: list[socket.socket] = []  # (closed_port's: bound, never listening, for as long as the run goes on)
_files: list[Path] = []  # (the port files this process made: taken away at its end)


def system_range() -> range:
    """The ports the system hands out by itself, to a bind to port 0 and to an outgoing connection, as it says."""
    if sys.platform.startswith("linux"):
        try:
            low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
            return range(low, high + 1)
        except (OSError, ValueError):
            return range(32768, 61000)
    if sys.platform == "win32":
        # "Start Port : 49152" and "Number of Ports : 16384", in whatever language Windows speaks: the two numbers.
        try:
            said = subprocess.run(["netsh", "int", "ipv4", "show", "dynamicport", "tcp"], capture_output=True, text=True, timeout=30).stdout
            start, count = (int(number) for number in re.findall(r":\s*(\d+)", said)[:2])
            return range(start, start + count)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return range(49152, 65536)  # (Windows and macOS as they come)


def _ports() -> list[int]:
    system = system_range()
    ports = [port for port in OWN_PORTS if port not in system]
    if len(ports) < 1000:  # (a system that hands out nearly all of them: whatever lies outside its range, high up)
        ports = [port for port in range(OWN_PORTS.stop, 65536) if port not in system] + ports
    return ports


def _shared() -> Path | None:
    """The folder this user's test processes share their ports' files in; None where there is none to be had."""
    if sys.platform == "win32":
        # (Not TEMP: each process of a parallel run is given a temporary folder of its own.)
        folder = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "qkvm-test-ports"
    else:
        folder = Path("/tmp") / f"qkvm-test-ports-{os.getuid()}"
    try:
        folder.mkdir(mode=0o700, exist_ok=True)
        if sys.platform != "win32" and (folder.is_symlink() or folder.stat().st_uid != os.getuid()):
            return None
    except OSError:
        return None
    return folder


_SHARED = _shared()
_PORTS = _ports()


def _held_here(port: int) -> bool:
    """Make `port`'s file, as this process's: False where another process holds it (its file younger than LEASE)."""
    if _SHARED is None:
        return True
    path = _SHARED / str(port)
    for _ in range(3):
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime < LEASE:
                    return False
                path.unlink()  # (a run that ended without taking it away: taken over)
            except FileNotFoundError:
                pass
            except OSError:
                return False
            continue
        except OSError:
            return True  # (the folder will not take it: chosen as before, without the file)
        with os.fdopen(descriptor, "w") as file:
            file.write(str(os.getpid()))
        _files.append(path)
        return True
    return False


def _let_go(port: int) -> None:
    if _SHARED is not None:
        path = _SHARED / str(port)
        if path in _files:
            _files.remove(path)
            try:
                path.unlink()
            except OSError:
                pass


def _own_port() -> socket.socket:
    """A socket bound (without SO_REUSEADDR: nobody else's bind shares it) to a port of the tests' own, not chosen before by
    this process and held by no other; waits up to WAIT where every one is held just now."""
    deadline = time.monotonic() + WAIT
    while True:
        for port in _PICK.sample(_PORTS, len(_PORTS)):
            if port in _chosen or not _held_here(port):
                continue
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:  # (in use, or one the system keeps for itself, as Windows does some)
                sock.close()
                _let_go(port)
                continue
            _chosen.add(port)
            return sock
        if time.monotonic() > deadline:
            raise OSError("no port of the tests' own could be found free")
        time.sleep(0.2)


def closed_port() -> int:
    """A port nothing listens on, and nothing comes to while the run goes on: held bound, never listening, so that a
    connection to it is refused as to one nothing has, and no stand-in or connection of another test is given it."""
    sock = _own_port()
    _held.append(sock)
    return int(sock.getsockname()[1])


def port_to_listen_on() -> int:
    """A port free now, for a program a test starts on it (`--port`, a server bound to it): let go of for that, and held
    from every other test process meanwhile by its file (LEASE), while that program comes to bind it."""
    with _own_port() as sock:
        return int(sock.getsockname()[1])


@atexit.register
def _the_end() -> None:
    for sock in _held:
        sock.close()
    for path in list(_files):
        try:
            path.unlink()
        except OSError:
            pass
