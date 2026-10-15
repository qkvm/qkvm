"""The tests, and the stand-ins they run against."""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Callable


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


class ServerThread:
    """A stand-in's server, run in a thread of its own, and waited for until it is up.

    Until it says it is up, or its thread has ended without saying so: then it failed, and `start` says
    why, with what ended the thread and the errors its server logged from it. (The web server the
    stand-ins use ends its thread with SystemExit when it cannot start, after logging the reason: an
    `except Exception` sees neither.) A loaded machine is given a minute: ten seconds were once not
    enough on one core shared with other work.
    """

    def __init__(self, name: str, serve: Callable[[], object], up: Callable[[], bool]) -> None:
        self._name, self._serve, self._up = name, serve, up
        self._ended_by: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self._serve()
        except BaseException as ex:
            self._ended_by = ex  # said by start(), which is what fails for it
            raise  # and the thread ends as it would have

    def start(self) -> None:
        said: list[str] = []
        thread = self.thread

        class Errors(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                if record.thread == thread.ident:
                    # A line each: a traceback logged as text ends in what was raised; and what a record carries.
                    lines = [line.strip() for line in record.getMessage().splitlines() if line.strip()]
                    said.extend(lines[-1:])
                    if record.exc_info and record.exc_info[1] is not None:
                        said.append(repr(record.exc_info[1]))

        errors = Errors(logging.ERROR)
        logger = logging.getLogger("uvicorn.error")
        logger.addHandler(errors)
        try:
            thread.start()
            deadline = time.monotonic() + 60
            while not self._up():
                if not thread.is_alive():
                    how = f" with {self._ended_by!r}" if self._ended_by is not None else ""
                    why = f": {'; '.join(said)}" if said else " (and its server logged no error)"
                    raise RuntimeError(f"{self._name} did not start: its server thread ended{how}{why}")
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{self._name} did not start within a minute")
                time.sleep(0.02)
        finally:
            logger.removeHandler(errors)
