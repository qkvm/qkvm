"""On Windows, a connection that the other end reset as it was being closed is no ERROR in the log (the Windows soak of 0.4.0).

Windows' event loop closes a connection with a shutdown() of its socket first, in its connection-lost callback, and that
raises WinError 10054 where a browser or a device had reset the connection already: the loop logged "Exception in callback
_ProactorBasePipeTransport._call_connection_lost()" with a traceback, three times an hour, about nothing the program did or
could do. The wall's process lets exactly that case pass; every other error the loop meets is logged as before.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import struct
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import __main__ as starter

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows' own event loop, which closes a connection with a shutdown() first")


@contextlib.contextmanager
def a_reset_connection() -> Iterator[socket.socket]:
    """A connected socket whose other end reset the connection: what it is asked raises WinError 10054, from Windows itself."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    reset = socket.create_connection(listener.getsockname())
    peer, _ = listener.accept()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # (closed so, a connection is reset)
    peer.close()
    listener.close()
    time.sleep(0.2)
    with reset:
        with pytest.raises(ConnectionResetError) as said:
            reset.recv(1)
        assert said.value.winerror == 10054
        yield reset


class Failing(asyncio.Protocol):
    """A protocol whose own connection_lost() fails: an error of the program's, which the loop logs."""

    def connection_lost(self, exc: Exception | None) -> None:
        raise RuntimeError("the program's own error in connection_lost")


def closed(shutdown: Callable[[int], Any], protocol: type[asyncio.Protocol] = asyncio.Protocol) -> None:
    """A connection of the event loop's own, closed as the program closes one, its socket's shutdown() being `shutdown`: a
    function of Windows' (no frame of Python's), as a socket's own is. `protocol`: the program's side of it."""

    async def run() -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        sock = Sock(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(listener.getsockname())
        sock.shutdown = shutdown  # type: ignore[method-assign]
        peer, _ = listener.accept()
        try:
            transport, _ = await asyncio.get_running_loop().create_connection(protocol, sock=sock)
            transport.close()
            await asyncio.sleep(0.2)  # (its connection-lost callback runs in a turn of the loop of its own)
        finally:
            peer.close()
            sock.close()

    asyncio.run(run())


class Sock(socket.socket):
    """A socket whose shutdown() may be another function."""


def an_error_elsewhere(fails: Callable[[int], Any]) -> None:
    """The same error, raised in a callback of the loop's that is not its closing of a connection."""

    async def run() -> None:
        asyncio.get_running_loop().call_soon(fails, 1)
        await asyncio.sleep(0.1)

    asyncio.run(run())


def errors(caplog: pytest.LogCaptureFixture) -> list[str]:
    found = [f"{record.getMessage()} {record.exc_info[1]!r} {record.exc_info[1].__context__!r}" for record in caplog.records if record.name == "asyncio" and record.levelno >= logging.ERROR and record.exc_info and record.exc_info[1]]
    caplog.clear()
    return found


def test_a_reset_as_a_connection_closes_is_no_error_in_the_wall_and_every_other_error_still_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from asyncio import base_events, proactor_events

    # (What the wall's process sets is set for this test alone: the loop's own handler is put back after it.)
    monkeypatch.setattr(proactor_events.BaseProactorEventLoop, "default_exception_handler", base_events.BaseEventLoop.default_exception_handler, raising=False)
    caplog.set_level(logging.ERROR, logger="asyncio")
    gone = socket.socket()
    gone.close()
    with a_reset_connection() as reset:
        closed(reset.recv)
        said = errors(caplog)
        assert len(said) == 1 and "_call_connection_lost" in said[0] and "ConnectionResetError(10054" in said[0], said  # (as it comes: the soak's line)

        # As the wall's process starts (the starter's child), the program proper stood in for.
        import qkvm.cli

        ran: list[Any] = []
        monkeypatch.setenv(starter.CHILD, "1")
        monkeypatch.setattr(sys, "argv", ["qkvm", "--data-dir", str(tmp_path)])
        monkeypatch.setattr(qkvm.cli, "main", lambda *given, **said: ran.append(given) or 0)
        assert starter.main() == 0 and ran

        closed(reset.recv)
        assert errors(caplog) == []
        # Anything else is said as before: another error of the same callback, the same error from anywhere else.
        closed(gone.recv)  # (WinError 10038: not a socket)
        said = errors(caplog)
        assert len(said) == 1 and "_call_connection_lost" in said[0] and "10038" in said[0], said
        an_error_elsewhere(reset.recv)
        said = errors(caplog)
        assert len(said) == 1 and "ConnectionResetError(10054" in said[0] and "_call_connection_lost" not in said[0], said
        # (The review of this round, L1.) An error of the program's own connection_lost(), which the shutdown's 10054 in the
        # callback's finally then replaced (it is the 10054's __context__): logged, as ever.
        closed(reset.recv, Failing)
        said = errors(caplog)
        assert len(said) == 1 and "ConnectionResetError(10054" in said[0] and "the program's own error" in said[0], said
