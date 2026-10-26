"""A VNC server with a time limit of its own on connections (FX-B2's L3, paced by the owner's decision for 0.2.0).

TigerVNC's MaxConnectionTime, or a proxy in front of a server, ends every connection after a while. A connection that
drew a frame and lasted a few seconds was the server being there again: its failures went back to none, and each end was
the first failure again. Such a server was connected to again, its password answered, at every end for good (some 14,000
times a day at ten seconds, three lines of the log each). Now the first end of a connection that served is connected to
again at once, as before, and every end after it, before a connection has served SERVED_LONG, waits a rung longer on
CUT_LADDER. Somebody watching it enlarged, and keys sent to it, still have it connected at once. Meanwhile the tile says
that the server is there and ends what it lets in, which is no "offline" for an alert to report as gone. (The fresh review
of b71c231 found the waits ended by the next look at the status, the enlarged view dark for them, the run unseen while
nobody looked, a server that hangs taken for one that ends what it lets in, and the run begun anew by an edit: the tests
after the first two.)
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from qkvm import alerts, amt, kvm, vncdevice
from qkvm.kvm import DeviceSpec, KvmError
from qkvm.vncdevice import VncDevice
from tests.fake_vnc import FakeVnc, VncState


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    # The program's paces, made short: a frame and 0.4 s is the server there again (KEEPALIVE_LASTS, 5 s), a tenth of a
    # second after a failure (ERROR_HOLD), the rungs for ends in a row, and how long a connection must serve to end a run.
    monkeypatch.setattr(vncdevice, "KEEPALIVE_LASTS", 0.4)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0.1)
    monkeypatch.setattr(vncdevice, "ERROR_HOLD", 0.1)
    monkeypatch.setattr(vncdevice, "CUT_LADDER", (1.0, 2.0, 4.0), raising=False)
    monkeypatch.setattr(vncdevice, "SERVED_LONG", 3.0, raising=False)


async def looked_at(device: VncDevice, server: FakeVnc, seconds: float) -> None:
    """A tile that is looked at asks on, as the wall does (its requests come and go on their own), while the server's
    screen changes."""

    async def look() -> None:
        while True:
            server.state.dirty.append((0, 0, 4, 4))
            try:
                await device.snapshot(640)
            except KvmError:
                pass
            await asyncio.sleep(0.05)

    looking = asyncio.create_task(look())
    await asyncio.sleep(seconds)
    looking.cancel()
    await asyncio.gather(looking, return_exceptions=True)


def test_a_server_that_ends_every_connection_soon_is_connected_to_less_and_less_often(quick: None) -> None:
    server = FakeVnc(VncState(width=32, height=32, ends_after=1.0)).start()
    spec = DeviceSpec(id="v7", name="limited", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await looked_at(device, server, 12.0)
            # Ends after a second, again at once, then 1, 2 and 4 s of waiting: four or five connections in twelve
            # seconds, where every end was the first failure again and it was connected to every 1.1 s (nine, on the
            # code before).
            assert server.state.connections <= 6 and server.state.password_tries <= 6, server.state.connections
            # Waited for between connections: it is there, and ends what it lets in; no "offline" for an alert to report as
            # gone, while a connection is open or while one is waited for.
            states: list[str] = []
            for _ in range(100):
                status = await device._read_status()
                states.append(status["state"])
                if status["state"] == "error" and device._connected_or_none() is None:
                    break  # (in a wait: "error" is said while a connection of the run is open too, since f0f6afb's review)
                await asyncio.sleep(0.1)
            assert status["state"] == "error" and "offline" not in states, (status, states)
            assert "ends every connection" in status["error"]["message"], status
            # Keys sent to it (an action) connect at once all the same.
            before = server.state.connections
            with pytest.raises(KvmError):
                device._connected(urgent=True)
            for _ in range(40):
                if server.state.connections > before:
                    break
                await asyncio.sleep(0.05)
            assert server.state.connections == before + 1
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def test_a_server_whose_connections_serve_long_is_connected_to_again_at_once_at_every_end(quick: None) -> None:
    # The other side: a limit of its own longer than SERVED_LONG (an hour, say) is an ordinary end each time, never a run.
    server = FakeVnc(VncState(width=32, height=32, ends_after=3.6)).start()
    spec = DeviceSpec(id="v8", name="hourly", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await looked_at(device, server, 11.5)
            assert server.state.connections >= 3, server.state.connections  # (at 0, about 3.7 and 7.4 s: none waited for)
            assert getattr(device, "_cuts", 0) <= 1
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


async def in_a_wait(device: VncDevice, server: FakeVnc, within: float = 20.0) -> None:
    """Looked at until the server has ended connections in a row and the wait after the last of them is on."""

    async def look() -> None:
        while True:
            server.state.dirty.append((0, 0, 4, 4))
            try:
                await device.snapshot(640)
            except KvmError:
                pass
            await asyncio.sleep(0.05)

    looking = asyncio.create_task(look())
    try:
        deadline = time.monotonic() + within
        while not (device._cut_error is not None and device._down_error is device._cut_error):
            assert time.monotonic() < deadline, "no wait between ends came"
            await asyncio.sleep(0.05)
    finally:
        looking.cancel()
        await asyncio.gather(looking, return_exceptions=True)


def test_a_look_at_the_status_during_a_wait_leaves_the_wait_as_it_is(quick: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # (M1: the greeting asked by the look said the server was there, which ended the wait: with the wall on a screen, the
    # 60 s and 300 s waits were over at the next look, and it was connected to every half minute.)
    monkeypatch.setattr(vncdevice, "CUT_LADDER", (30.0,))
    monkeypatch.setattr(vncdevice, "STILL_THERE_EVERY", 0.0)  # (its greeting is asked at every look)
    server = FakeVnc(VncState(width=32, height=32, ends_after=1.0)).start()
    spec = DeviceSpec(id="v9", name="limited", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await in_a_wait(device, server)
            tries = server.state.password_tries
            for _ in range(20):
                status = await device._read_status()
                assert status["state"] == "error" and "ends every connection" in status["error"]["message"], status
                server.state.dirty.append((0, 0, 4, 4))
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.1)
            assert server.state.password_tries == tries, "a look at the status ended the wait, and it was connected to again"
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def test_somebody_watching_it_enlarged_has_it_connected_at_once_during_a_wait(quick: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # (M2: a plain VNC server has no live view; the enlarged view asked as a tile does, and was dark for every wait.)
    monkeypatch.setattr(vncdevice, "CUT_LADDER", (30.0,))
    server = FakeVnc(VncState(width=32, height=32, ends_after=1.0)).start()
    spec = DeviceSpec(id="v10", name="limited", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await in_a_wait(device, server)
            tries = server.state.password_tries
            with pytest.raises(KvmError):
                await device.snapshot(640)  # (a tile: it waits)
            await asyncio.sleep(0.3)
            assert server.state.password_tries == tries
            with pytest.raises(KvmError):
                await device.snapshot(1920, big=True)  # (enlarged: connected at once)
            deadline = time.monotonic() + 3
            while server.state.password_tries == tries:
                assert time.monotonic() < deadline, "the enlarged view waited out the wait"
                await asyncio.sleep(0.05)
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def test_with_nobody_looking_a_server_that_ends_every_connection_is_in_a_run_too(quick: None) -> None:
    # (L1: frames are drawn only where somebody looks. Counted by frames alone, a connection that the alerts' looks made was
    # never one that served, the server never in a run, and its tile went on flipping between online and offline.)
    server = FakeVnc(VncState(width=32, height=32, ends_after=1.0)).start()
    spec = DeviceSpec(id="v11", name="limited", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        states: list[str] = []
        try:
            started = time.monotonic()
            while time.monotonic() - started < 12.0:  # the alerts look at it, and nobody else
                states.append((await device._read_status())["state"])
                await asyncio.sleep(0.2)
            assert device._cuts >= 2, device._cuts
            assert "error" in states, states
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def served(seconds: float) -> SimpleNamespace:
    """A connection that drew a frame and lasted this long, as `_cut` finds one that ended."""
    return SimpleNamespace(client=SimpleNamespace(frames=3, updates=3), let_in_at=time.monotonic() - seconds)


def test_a_server_that_stops_answering_is_no_server_that_ends_what_it_lets_in() -> None:
    # (L2: the heartbeat's end of a connection that hangs was counted as one more end in a row, and its tile said that the
    # server ends every connection. The consoles behind doors leave it out the same way.)
    device = VncDevice(DeviceSpec(id="v12", name="hangs", base_url="vnc://127.0.0.1:5900", username="", password="secret", kind="vnc"))
    for _ in range(3):
        device._cut(served(10.0), KvmError("timeout", "The VNC server: the server does not answer requests", 504))  # type: ignore[arg-type]
    assert device._cuts == 0 and device._cut_error is None


def test_an_edit_of_its_tile_does_not_begin_the_run_anew() -> None:
    # (L3: the client made anew at an edit began at nothing, and the next end was the first again.)
    spec = DeviceSpec(id="v13", name="limited", base_url="vnc://127.0.0.1:5900", username="", password="secret", kind="vnc")
    before, after = VncDevice(spec), VncDevice(spec)
    for _ in range(3):
        before._cut(served(10.0), KvmError("dropped", "The VNC server: the server closed the connection", 502))  # type: ignore[arg-type]
    after.takes_over(before)
    assert after._cuts == before._cuts == 3


def test_a_pcs_engine_that_ends_its_sessions_is_not_in_a_run() -> None:
    # (L4: the engine ends its session at its own time; in a run, the tile said its redirection port failed and offered no
    # screen for the waits. As before b71c231.)
    screen = amt.AmtScreen(DeviceSpec(id="a1", name="PC", base_url="https://127.0.0.1:16993", username="admin", password="secret", kind="amt"))
    for _ in range(3):
        screen._cut(served(40.0), KvmError("dropped", "The PC's screen: the server closed the connection", 502))  # type: ignore[arg-type]
    assert screen._cuts == 0 and screen._cut_error is None


SCALE = 60.0  # (a minute is a second)


@pytest.fixture
def scaled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The program's times, sixty times shorter (the fresh review's probe of f0f6afb)."""
    monkeypatch.setattr(vncdevice, "KEEPALIVE_LASTS", 5.0 / SCALE)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0 / SCALE)
    monkeypatch.setattr(kvm, "BACKOFF_MAX", 15.0 / SCALE)
    monkeypatch.setattr(vncdevice, "ERROR_HOLD", 1.0 / SCALE)
    monkeypatch.setattr(vncdevice, "CUT_LADDER", (15.0 / SCALE, 60.0 / SCALE, 300.0 / SCALE))
    monkeypatch.setattr(vncdevice, "SERVED_LONG", 240.0 / SCALE)
    monkeypatch.setattr(vncdevice, "SETTLED", 30.0 / SCALE)
    monkeypatch.setattr(vncdevice, "STILL_THERE_EVERY", 30.0 / SCALE)
    monkeypatch.setattr(vncdevice, "STILL_THERE_IN_A_WAIT", 120.0 / SCALE, raising=False)
    monkeypatch.setattr(vncdevice, "HEARTBEAT", 60.0 / SCALE)
    monkeypatch.setattr(VncDevice, "IDLE_PACE", 10.0 / SCALE)


def test_an_hour_of_a_server_that_ends_every_connection_after_a_minute_is_one_alert(scaled: None) -> None:
    # (The fresh review of f0f6afb, its finding 1: with the waits lasting their whole length, the wait said "error" and the
    # connection between said "online", each long enough to count: a problem and a "back" alert every six minutes, some
    # 480 a day, for a server that nobody looked at. The run says "error" all along now: one alert, and one more when a
    # connection serves long. And its greeting is asked less often during a wait (finding 6).)
    server = FakeVnc(VncState(width=32, height=32, ends_after=60.0 / SCALE)).start()
    spec = DeviceSpec(id="v14", name="limited", base_url=server.url, username="", password="secret", kind="vnc")
    told: list[tuple[str, str]] = []

    async def go() -> None:
        device = VncDevice(spec)
        watcher = alerts.Watcher()
        started = time.monotonic()
        try:
            while time.monotonic() - started < 3600.0 / SCALE:  # an hour, as the alerts look at it (every 15 s)
                change = watcher.observe("v14", (await device._read_status())["state"])
                if change is not None:
                    told.append(change)
                await asyncio.sleep(15.0 / SCALE)
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()
    assert len(told) <= 1, told
    assert server.state.connections <= 60, server.state.connections  # (107 an hour, greetings included, before)


def test_an_action_during_a_wait_waits_for_its_connection(quick: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Its finding 5: an action asked for a connection and answered "Connecting" at once; the first click typed nothing.)
    monkeypatch.setattr(vncdevice, "CUT_LADDER", (30.0,))
    server = FakeVnc(VncState(width=32, height=32, ends_after=1.0)).start()
    spec = DeviceSpec(id="v15", name="limited", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await in_a_wait(device, server)
            await device.act("text", text="ok")
            deadline = time.monotonic() + 3
            while len(server.state.keys) < 4:
                assert time.monotonic() < deadline, server.state.keys
                await asyncio.sleep(0.05)
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()
    assert [key for key, down in server.state.keys if down] == [ord("o"), ord("k")]


def test_a_server_that_is_well_and_restarts_twice_says_online_once_it_serves_again(quick: None) -> None:
    # (The final review of 1e21777, its finding 2: two ends within the hour, the connection between them under four
    # minutes (an update's second reboot, x11vnc at a log-in and a log-out), made a run, and the server said "error: ends
    # every connection" for four minutes while it served again, an alert said "problem" and later "back". A run says so
    # while connected only from its third end.)
    server = FakeVnc(VncState(width=32, height=32)).start()
    spec = DeviceSpec(id="v16", name="well", base_url=server.url, username="", password="secret", kind="vnc")
    serving_in_error: list[float] = []

    async def go() -> None:
        device = VncDevice(spec)
        began = time.monotonic()

        async def look() -> None:
            while True:
                server.state.dirty.append((0, 0, 4, 4))
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)

        async def watch() -> None:
            while True:
                status = await device._read_status()
                if status["state"] == "error" and device._connected_or_none() is not None:
                    serving_in_error.append(round(time.monotonic() - began, 1))
                await asyncio.sleep(0.25)

        tasks = [asyncio.create_task(look()), asyncio.create_task(watch())]
        try:
            await asyncio.sleep(1.5)
            server.drop_everybody()  # (the first restart)
            await asyncio.sleep(1.5)
            server.drop_everybody()  # (the second, soon after)
            await asyncio.sleep(6.0)  # (well from now on)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()
    assert serving_in_error == [], f"said error while connected and serving at {serving_in_error}"
