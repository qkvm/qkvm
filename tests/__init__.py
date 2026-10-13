"""The tests, and the stand-ins they run against."""

from __future__ import annotations

import os
import socket


def local_socket(port: int = 0) -> socket.socket:
    """A socket bound on this computer to `port` (0: any that is free), for a stand-in to listen on."""
    sock = socket.socket()
    if os.name == "posix":
        # A stand-in that comes back where it was, like a KVM after its reboot: without this, Linux keeps a
        # port from being bound again for a while after its last connection closed. On Windows the option
        # means something else (two programs on one port), and nothing there needs it.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    return sock
