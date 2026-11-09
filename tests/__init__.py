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


def no_buffer_space(ex: BaseException | None) -> bool:
    """Whether a stand-in's server ended for want of buffer space for a socket (WSAENOBUFS on Windows, ENOBUFS elsewhere)."""
    import errno

    return isinstance(ex, OSError) and (getattr(ex, "winerror", None) == 10055 or ex.errno == errno.ENOBUFS)


class ServerThread:
    """A stand-in's server, run in a thread of its own, and waited for until it is up.

    Until it says it is up, or its thread has ended without saying so: then it failed, and `start` says
    why, with what ended the thread and the errors its server logged from it. (The web server the
    stand-ins use ends its thread with SystemExit when it cannot start, after logging the reason: an
    `except Exception` sees neither.) A loaded machine is given a minute: ten seconds were once not
    enough on one core shared with other work. A thread that ended for want of buffer space for a socket
    (Windows' WSAENOBUFS, 10055: after an hour and a half of tests on GitHub's runner, as its event loop
    made its own pair of sockets) is started again, up to three times, after a pause that grows.
    """

    AGAIN_AFTER = (2.0, 5.0, 10.0)  # seconds before each new start, where a thread ended for want of buffer space

    def __init__(self, name: str, serve: Callable[[], object], up: Callable[[], bool]) -> None:
        self._name, self._serve, self._up = name, serve, up
        self._ended_by: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def join(self, timeout: float | None = None) -> None:
        """Waits for the thread that serves now: where one ended for want of buffer space, the one started again. (Each
        stand-in kept the first thread and waited for it as it stopped, which had ended while the one started again
        still cleaned up: the outside review of 0.3.1, L031-1.)"""
        self.thread.join(timeout)

    def is_alive(self) -> bool:
        """Whether the thread that serves now runs."""
        return self.thread.is_alive()

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
        again = list(self.AGAIN_AFTER)
        try:
            thread.start()
            deadline = time.monotonic() + 60
            while not self._up():
                if not thread.is_alive() and again and no_buffer_space(self._ended_by):
                    time.sleep(again.pop(0))
                    self._ended_by = None
                    said.clear()
                    thread = self.thread = threading.Thread(target=self._run, daemon=True)
                    thread.start()
                    deadline = time.monotonic() + 60
                    continue
                if not thread.is_alive():
                    how = f" with {self._ended_by!r}" if self._ended_by is not None else ""
                    why = f": {'; '.join(said)}" if said else " (and its server logged no error)"
                    raise RuntimeError(f"{self._name} did not start: its server thread ended{how}{why}")
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{self._name} did not start within a minute")
                time.sleep(0.02)
        finally:
            logger.removeHandler(errors)
