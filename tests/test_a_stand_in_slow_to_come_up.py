"""A stand-in that is slow to come up on a loaded computer is waited for, as every stand-in is (tests.ServerThread: a minute).

On GitHub's Windows runners the stand-in Intel AMT machine once did not come up within its own ten seconds, and a test of
every route failed for it ("fake Intel AMT machine did not start", 0.2.2). The stand-ins for VNC waited the same ten
seconds. They wait as the others do now: up to a minute, and where the server's thread ends first, they say why.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest
import uvicorn

from tests.fake_amt import FakeAmt
from tests.fake_vnc import FakeVnc

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
