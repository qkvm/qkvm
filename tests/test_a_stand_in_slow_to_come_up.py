"""A stand-in that is slow to come up on a loaded computer is waited for, as every stand-in is (tests.ServerThread: a minute).

On GitHub's Windows runners the stand-in Intel AMT machine once did not come up within its own ten seconds, and a test of
every route failed for it ("fake Intel AMT machine did not start", 0.2.2). The stand-ins for VNC waited the same ten
seconds. They wait as the others do now: up to a minute, and where the server's thread ends first, they say why.
"""

from __future__ import annotations

import asyncio
import errno
import os
import re
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest
import uvicorn

from tests import ServerThread
from tests.fake_amt import FakeAmt
from tests.fake_redfish import FakeBmc
from tests.fake_vnc import FakeVnc
from tests.test_live import Wall

LATE = 10.5  # seconds a server takes here to come up: more than the ten the two stand-ins gave it


def test_the_stand_in_amt_machine_and_vnc_server_are_waited_for_past_ten_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    startup = uvicorn.Server.startup

    async def slow_startup(self: uvicorn.Server, sockets: Any = None) -> None:
        await asyncio.sleep(LATE)
        await startup(self, sockets=sockets)

    main = FakeVnc._main

    async def slow_main(self: FakeVnc) -> None:
        if type(self) is FakeVnc:  # (the AMT machine's redirection port is a VNC server too: that one is not made late)
            await asyncio.sleep(LATE)
        await main(self)

    monkeypatch.setattr(uvicorn.Server, "startup", slow_startup)
    monkeypatch.setattr(FakeVnc, "_main", slow_main)
    machine, server = FakeAmt(), FakeVnc()
    failed: list[BaseException] = []

    def start(fake: Any) -> None:
        try:
            fake.start()
        except BaseException as ex:
            failed.append(ex)

    began = time.monotonic()
    starting = [threading.Thread(target=start, args=(fake,)) for fake in (machine, server)]
    try:
        for thread in starting:
            thread.start()
        for thread in starting:
            thread.join(70)
        assert failed == [], failed
        assert time.monotonic() - began >= LATE
        assert machine._server.started and server._started.is_set()
    finally:
        machine.stop()
        server.stop()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")  # (the ends it makes on purpose)
def test_a_stand_in_whose_thread_ended_for_want_of_socket_buffers_is_started_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """GitHub's Windows runner, after an hour and a half of tests, had no buffer space left for a socket (WSAENOBUFS,
    10055) as a stand-in's event loop made its own pair of sockets, and its thread ended: the test failed for it. Such a
    thread is started again after a pause, up to three times; any other end still fails at once."""
    monkeypatch.setattr(ServerThread, "AGAIN_AFTER", (0.05, 0.05, 0.05))
    up = threading.Event()
    tries: list[int] = []

    def serve() -> None:
        tries.append(1)
        if len(tries) < 3:
            # (each platform's own: Windows' WSAENOBUFS, ENOBUFS elsewhere; Windows' on Linux is no buffer-space error)
            if sys.platform == "win32":
                raise OSError(10055, "An operation on a socket could not be performed because the system lacked sufficient buffer space", None, 10055, None)
            raise OSError(errno.ENOBUFS, os.strerror(errno.ENOBUFS))
        up.set()

    ServerThread("a stand-in", serve, up.is_set).start()
    assert len(tries) == 3

    def broken() -> None:
        raise OSError(98, "Address already in use")

    with pytest.raises(RuntimeError, match="did not start: its server thread ended with OSError"):
        ServerThread("another", broken, lambda: False).start()


# The outside review of 0.3.1 (Codex), L031-1: a stand-in started again for want of socket buffers was not waited for as it
# stopped. (Its probe, as it wrote it: the stand-ins built without listeners, a server body whose cleanup is held.)
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
@pytest.mark.parametrize("fixture_kind", ["redfish", "vnc", "wall"])
@pytest.mark.parametrize("retry", [False, True], ids=["original-thread-control", "replacement-thread"])
def test_a_stand_in_that_stops_waits_for_the_thread_that_serves_now(monkeypatch, fixture_kind, retry):
    monkeypatch.setattr(ServerThread, "AGAIN_AFTER", (0.0,))
    up, stop_requested, cleanup_entered, allow_cleanup, closed, stop_done = [threading.Event() for _ in range(6)]
    server = SimpleNamespace(should_exit=False)
    tries = []
    errors = []

    def serve():
        tries.append(1)
        if retry and len(tries) == 1:
            raise OSError(errno.ENOBUFS, "bounded synthetic socket-buffer failure")
        up.set()
        deadline = time.monotonic() + 4
        while not (stop_requested.is_set() or server.should_exit):
            if time.monotonic() >= deadline:
                raise AssertionError("fixture never requested shutdown")
            stop_requested.wait(0.005)
        cleanup_entered.set()
        if not allow_cleanup.wait(4):
            raise AssertionError("cleanup gate was not released")
        closed.set()

    fixture_type = {"redfish": FakeBmc, "vnc": FakeVnc, "wall": Wall}[fixture_kind]
    fixture = fixture_type.__new__(fixture_type)
    fixture._server = server
    fixture._serving = ServerThread("bounded fixture", serve, up.is_set)
    fixture.clients = []
    fixture._stop = stop_requested
    fixture._loop = SimpleNamespace(is_closed=lambda: False, call_soon_threadsafe=lambda callback: callback())

    def stop():
        try:
            if fixture_kind == "wall":
                fixture.__exit__(None, None, None)
            else:
                fixture.stop()
        except BaseException as ex:
            errors.append(ex)
        finally:
            stop_done.set()

    stopping = threading.Thread(target=stop)
    try:
        if fixture_kind == "wall":
            fixture.__enter__()
        else:
            fixture.start()
        assert len(tries) == (2 if retry else 1) and fixture._serving.thread.is_alive()
        stopping.start()
        assert cleanup_entered.wait(2), "new server did not begin shutdown"
        returned_early = stop_done.wait(0.1)
        assert errors == []
        assert not returned_early, "fixture stop joined the dead original thread instead of the retried server"
    finally:
        server.should_exit = True
        stop_requested.set()
        allow_cleanup.set()
        fixture._serving.thread.join(3)
        if stopping.ident is not None:
            stopping.join(3)
    assert closed.is_set()


def test_no_stand_in_keeps_or_waits_for_a_thread_of_its_own() -> None:
    """Every stand-in waits for its server through ServerThread, which knows the thread that serves now; one that kept the
    thread it was given first would wait for one that ended, where its server was started again (L031-1)."""
    from pathlib import Path

    here = Path(__file__).parent
    owners = [path for path in sorted(here.glob("*.py")) if "ServerThread(" in path.read_text(encoding="utf-8") and path.name != "__init__.py"]
    assert len(owners) >= 11
    for path in owners:
        text = path.read_text(encoding="utf-8")
        assert "_serving.thread" not in text or path.name == Path(__file__).name, path.name
        assert not re.search(r"\._thread\.(join|is_alive)\(", text), path.name
