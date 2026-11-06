"""A server's tile keeps its own lines to the controller (redfish._Lines) no longer than the pool of 0.2.0 kept an idle
connection, has the system watch them, and does not take one dead line after another (the final review of 0.2.1, the drivers
half: review-final-drivers\\probes\\p_stale.py).

Idle lines were kept for ever and reused when dead. Something between the wall and a controller that is well (a NAT's or a
firewall's idle timeout) forgets an idle connection without a word: a press on it waited twenty seconds and failed "Nothing
was sent", and the tile was shown offline. A controller that restarted answers a forgotten connection with a reset: a look's
one retry took the second stale line. Now: a line idle for LINE_IDLE_KEPT is closed, not used; every line has SO_KEEPALIVE;
and where a look's reused line ends with nothing read, the other idle lines are let go of and the look is asked once more on
a line made afresh and compared.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import time
from typing import Any

import httpx
import pytest

from qkvm import redfish
from qkvm.kvm import DeviceSpec
from tests.fake_redfish import BmcState, FakeBmc

A_SYSTEM, A_ROOT = "4c4c4544-0042-3510-8054-b9c04f4a3532", "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
A_MARK = "server:" + hashlib.sha256(A_SYSTEM.lower().encode()).hexdigest()[:32] + hashlib.sha256(A_ROOT.lower().encode()).hexdigest()[:32]


class Middlebox:
    """Forwards each connection to the controller; `forget()` makes every connection open now go silent both ways (kept
    open, nothing passed), as a middlebox that dropped their state does, or (`reset`) answers what comes on it with a reset,
    as a controller that restarted does; connections made after it pass."""

    def __init__(self, port: int, reset: bool) -> None:
        self.port, self.reset = port, reset
        self.flows: list[list[bool]] = []
        self.resets = 0  # (requests that came on a forgotten connection: each answered with a reset)
        self.tasks: set[asyncio.Task[Any]] = set()
        self.transports: list[asyncio.BaseTransport] = []

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.flow, "127.0.0.1", 0)
        return int(self.server.sockets[0].getsockname()[1])

    def forget(self) -> None:
        for alive in self.flows:
            alive[0] = False

    async def close(self) -> None:
        """Its connections ended, the forgotten ones too, and every flow waited for. (The requalification of 0.3.0, Windows
        3.13: flows a forgotten connection held were left pending to the end, held by nothing but one another; the
        collector destroyed them during the loop's poll, and Python's Windows loop raised InvalidStateError out of it.)"""
        self.server.close()
        for transport in self.transports:
            transport.abort()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.server.wait_closed()

    async def flow(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        alive = [True]
        self.flows.append(alive)
        self.transports.append(writer.transport)
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.transports.append(up_writer.transport)

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while data := await src.read(65536):
                    if alive[0]:
                        dst.write(data)
                        await dst.drain()
                    elif self.reset:
                        self.resets += 1
                        writer.transport.abort()
                        up_writer.transport.abort()
                        return
            except (ConnectionError, OSError):
                pass

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        if alive[0]:
            writer.close()
            up_writer.close()


def behind_a_middlebox(reset: bool, test: Any) -> None:
    state = BmcState(uuid=A_SYSTEM, root_uuid=A_ROOT, keeps_idle=3600.0)
    bmc = FakeBmc(state).start()

    async def inside() -> None:
        box = Middlebox(bmc.port, reset)
        port = await box.start()
        device = redfish.RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=f"http://127.0.0.1:{port}", username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        try:
            await test(device, box, state)
        finally:
            await device.close()
            await box.close()

    try:
        asyncio.run(inside())
    finally:
        bmc.stop()


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "LINE_IDLE_KEPT", 1.0, raising=False)
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(3.0))  # (a press on a dead line: three seconds, not twenty)


def test_a_press_after_the_lines_sat_idle_and_were_forgotten_goes_on_a_line_made_afresh(quick: None) -> None:
    async def test(device: redfish.RedfishDevice, box: Middlebox, state: BmcState) -> None:
        assert (await device._read_status())["state"] == "online"
        box.forget()  # (nobody looks for a while; the middlebox drops what sat idle)
        await asyncio.sleep(1.5)
        before, began = len(state.changes), time.monotonic()
        await device.act("locate_on")
        assert len(state.changes) == before + 1 and time.monotonic() - began < 2.0

    behind_a_middlebox(False, test)


def test_a_look_whose_reused_line_ends_with_nothing_read_lets_the_other_idle_lines_go_and_asks_on_a_fresh_one(quick: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "LINE_IDLE_KEPT", 60.0, raising=False)  # (within the time a line is kept: the controller restarted meanwhile)

    async def test(device: redfish.RedfishDevice, box: Middlebox, state: BmcState) -> None:
        assert (await device._read_status())["state"] == "online"
        assert len(device._lines.idle) >= 2, "one line waits beside the other"
        asked: list[tuple[str, bool]] = []
        real_ask = redfish._Line.ask

        async def ask(line: redfish._Line, method: str, path: str, *rest: Any) -> Any:
            try:
                answer = await real_ask(line, method, path, *rest)
            except Exception:
                asked.append((path, False))
                raise
            asked.append((path, True))
            return answer

        monkeypatch.setattr(redfish._Line, "ask", ask)
        box.forget()
        await asyncio.sleep(0.2)
        said = await device._read_status()
        assert said["state"] == "online", said
        failed = [path for path, ok in asked if not ok]
        assert len(failed) == 1 and (failed[0], True) in asked[asked.index((failed[0], False)) :], asked  # (asked again, and answered)
        assert box.resets == 1, f"{box.resets} stale lines were tried one after another"

    behind_a_middlebox(True, test)


def test_a_line_has_the_system_watch_its_connection(quick: None) -> None:
    async def test(device: redfish.RedfishDevice, box: Middlebox, state: BmcState) -> None:
        await device._read_status()
        lines = list(device._lines.idle)
        assert lines, "no line kept"
        for line in lines:
            assert line.connection is not None and line.connection.transport is not None
            sock = line.connection.transport.get_extra_info("socket")
            assert sock is not None and sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), "SO_KEEPALIVE not set"

    behind_a_middlebox(False, test)
