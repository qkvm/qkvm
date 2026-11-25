"""The ports the tests choose themselves (tests/test_wall.py): one nothing listens on stays so, and one a program is to listen
on is nobody else's meanwhile, whatever runs beside the tests.

A port was chosen by binding port 0 and letting it go: the system's own to hand out again at once, to any process's next
bind to port 0 or outgoing connection. Under fifty test processes at a time it was: two stand-ins of one test given one
port (an import of three machines found two), a wall started on its port finding it taken (exit 2), a stand-in's listen
refused (OSError 98, Address already in use).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tests import local_socket, own_ports
from tests.test_wall import closed_port, port_to_listen_on


def handed_out_by_the_system() -> range:
    """The ports the system hands out by itself, to a bind to port 0 and to an outgoing connection, as it says them."""
    return own_ports.system_range()


def test_the_systems_range_is_read_as_it_says_it() -> None:
    # (The review of this round, L3.) On Windows the range was taken to be 49152 on, whatever the computer said: one whose
    # range was moved hands out the tests' own ports by itself.
    said = own_ports.system_range()
    if sys.platform.startswith("linux"):
        low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        assert said == range(low, high + 1)
    elif sys.platform == "win32":
        shown = subprocess.run(["netsh", "int", "ipv4", "show", "dynamicport", "tcp"], capture_output=True, text=True, timeout=30).stdout
        assert str(said.start) in shown and str(len(said)) in shown, (said, shown)
    with socket.socket() as sock:  # (and what the system hands out by itself is in it)
        sock.bind(("127.0.0.1", 0))
        assert sock.getsockname()[1] in said


def test_a_port_nothing_listens_on_stays_so_and_is_never_handed_out_twice() -> None:
    ports = [closed_port() for _ in range(50)]
    assert len(set(ports)) == len(ports)
    system = handed_out_by_the_system()
    assert not [port for port in ports if port in system], ports  # (no bind to port 0, no connection, is given one of them)
    for port in ports[:5]:
        with socket.socket() as asker:
            asker.settimeout(10)
            with pytest.raises(ConnectionRefusedError):
                asker.connect(("127.0.0.1", port))
        # ...and nothing can come to listen there meanwhile: a stand-in binding it as stand-ins do is refused.
        with pytest.raises(OSError):
            local_socket(port).close()


def test_a_port_to_listen_on_is_free_and_never_handed_out_twice() -> None:
    ports = [port_to_listen_on() for _ in range(50)]
    assert len(set(ports)) == len(ports) and not set(ports) & {closed_port() for _ in range(50)}
    system = handed_out_by_the_system()
    assert not [port for port in ports if port in system], ports
    for port in ports[:5]:
        with local_socket(port) as sock:
            sock.listen()
            with socket.create_connection(("127.0.0.1", port), timeout=10):
                pass


# A test process of its own: chooses ports to listen on and binds each a moment later, as a wall started on it does.
CHOOSER = """
import socket, sys, time
from tests.test_wall import port_to_listen_on
lost = 0
for _ in range(int(sys.argv[1])):
    port = port_to_listen_on()
    time.sleep(0.005)
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen()
        time.sleep(0.005)
    except OSError:
        lost += 1
    finally:
        sock.close()
print("LOST", lost, flush=True)
"""


def test_a_port_to_listen_on_is_no_other_test_processs_meanwhile() -> None:
    # (The review of this round, L3.) Each process kept to itself what it had chosen: a port let go of for its program was
    # any other test process's to choose until that program bound it (36 binds of 24,000 refused in the reviewer's probe).
    app = Path(__file__).resolve().parents[1]
    # (The app first, then whatever path the run had: the image's run keeps pytest on a path of its own.)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(app), *filter(None, [os.environ.get("PYTHONPATH")])])}
    workers = [subprocess.Popen([sys.executable, "-P", "-c", CHOOSER, "300"], cwd=app, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
    said = [worker.communicate(timeout=900) for worker in workers]
    lost = [int(out.split()[-1]) if out.strip().startswith("LOST") else None for out, _ in said]
    assert lost == [0] * len(workers), (lost, [err[-400:] for _, err in said if err.strip()][:2])
