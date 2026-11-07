"""A wall the tests run on a real port is waited for as every stand-in is (tests.ServerThread: a minute), 0.3.0.

test_hardening.LiveWall and test_live.Wall gave their web server ten seconds to come up, where the stand-ins have a minute
and say why their thread ended: on a loaded GitHub runner ten seconds were once not enough for a stand-in (0.2.2, "fake
Intel AMT machine did not start"), and these two are started the same way.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import uvicorn

LATE = 10.5  # seconds a server takes here to come up: more than the ten the two walls gave it


def test_a_wall_on_a_real_port_is_waited_for_past_ten_seconds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_hardening import LiveWall
    from tests.test_live import Wall

    startup = uvicorn.Server.startup

    async def slow_startup(self: uvicorn.Server, sockets: Any = None) -> None:
        await asyncio.sleep(LATE)
        await startup(self, sockets=sockets)

    monkeypatch.setattr(uvicorn.Server, "startup", slow_startup)
    walls: list[Any] = [LiveWall(tmp_path / "live"), Wall(tmp_path / "wall")]
    failed: list[BaseException] = []
    entered: list[Any] = []

    def enter(wall: Any) -> None:
        try:
            entered.append(wall.__enter__())
        except BaseException as ex:
            failed.append(ex)

    began = time.monotonic()
    starting = [threading.Thread(target=enter, args=(wall,)) for wall in walls]
    try:
        for thread in starting:
            thread.start()
        for thread in starting:
            thread.join(70)
        assert failed == [], failed
        assert time.monotonic() - began >= LATE and len(entered) == 2
    finally:
        for wall in walls:
            wall.__exit__(None, None, None)
