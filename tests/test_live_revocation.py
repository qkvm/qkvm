"""Revocation must precede new input and frame delivery, even while device I/O waits."""
from __future__ import annotations

import asyncio
import contextlib
from types import SimpleNamespace

import pytest

from qkvm import live
from tests.test_live_letting_go import Scene, Screen, held_down, lines_to, played


@pytest.mark.parametrize("reason", ["role", "signed_out", "not_found", "internal"])
@pytest.mark.parametrize("waiting", [False, True])
def test_revoked_holder_cannot_dispatch_input(reason: str, waiting: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    async def scene() -> None:
        s = Scene()
        revoked = False
        errors = []
        s.machine.device._unexpected = lambda *args: errors.append(args)

        def standing(holder: live.Holder, device_id: str) -> tuple[str | None, bool]:
            if not revoked:
                return None, True
            if reason == "internal":
                raise RuntimeError("unavailable authorization")
            return (None if reason == "role" else reason), False

        s.lines.standing = standing
        await s.take(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})
        entered, release = asyncio.Event(), asyncio.Event()

        async def handover(*args: object) -> None:
            entered.set()
            await release.wait()

        if waiting:
            monkeypatch.setattr(live, "handed_over", handover)
            s.lines.handing["d1"] = [s.ways[1]]
            sending = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True}))
            await entered.wait()
            revoked = True
            release.set()
            await sending
        else:
            revoked = True
            await s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True})
        await s.settled()
        assert ("way A", "key", 0x04, True) not in s.said
        assert s.machine.holder is None
        assert held_down(s.said) == (set(), set())
        assert bool(errors) == (reason == "internal")

    played(scene)()


def test_revoked_holder_cannot_reaffirm_control() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        s.lines.standing = lambda *args: (None, False)
        answer = await s.machine.control(s.a, True)
        await s.settled()
        assert answer["on"] is False
        assert s.machine.holder is None
    played(scene)()


def test_queued_frame_is_not_sent_after_access_is_revoked() -> None:
    async def scene() -> None:
        s = Scene()
        sent = []

        async def send_bytes(data: bytes) -> None:
            sent.append(data)
            raise OSError("finished")

        async def send_text(text: str) -> None:
            pass

        async def close() -> None:
            pass

        s.a.ws = SimpleNamespace(send_bytes=send_bytes, send_text=send_text, close=close)
        s.a.pictures.append(SimpleNamespace(message=b"private screen"))
        s.a.ready.set()
        s.lines.standing = lambda *args: ("signed_out", False)
        await asyncio.wait_for(s.a.send_on(), 1)
        assert sent == []
        assert s.a.leaving == "signed_out"
    played(scene)()


def test_stalled_status_cannot_delay_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "STATE_EVERY", 0.01)
    monkeypatch.setattr(live, "STANDING_EVERY", 0.01)

    async def scene() -> None:
        s = Scene()
        s.lines.manager.devices["d1"] = s.machine.device
        entered, revoked = asyncio.Event(), asyncio.Event()
        s.machine.device._unexpected = lambda *args: None

        async def look() -> None:
            entered.set()
            await asyncio.Event().wait()

        s.machine._look = look
        await s.take(s.a)
        watching = asyncio.create_task(s.machine._watch())
        try:
            await asyncio.wait_for(entered.wait(), 1)

            def standing(*args: object) -> tuple[str | None, bool]:
                revoked.set()
                return "signed_out", False

            s.lines.standing = standing
            await asyncio.wait_for(revoked.wait(), 0.3)
            assert s.a.leaving == "signed_out"
            assert s.machine.holder is None
        finally:
            watching.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watching
            await s.settled()
    played(scene)()


def test_revocation_stops_remaining_relative_mouse_steps() -> None:
    async def scene() -> None:
        s = Scene()
        moves = []
        await s.take(s.a)

        async def move(dx: int, dy: int) -> None:
            moves.append((dx, dy))
            s.lines.standing = lambda *args: (None, False)

        s.ways[0]._say_move = move
        await s.machine.input(s.a, {"t": "mr", "dx": 1000, "dy": 0})
        await s.settled()
        assert len(moves) == 1
        assert s.machine.holder is None
    played(scene)()


def test_revocation_stops_a_paced_pointer_before_it_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(live, "time", SimpleNamespace(monotonic=lambda: clock.now))

    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        await s.machine.input(s.a, {"t": "m", "x": 1, "y": 1})
        await s.machine.input(s.a, {"t": "m", "x": 2, "y": 2})
        s.lines.standing = lambda *args: (None, False)
        placing = s.ways[0]._placing
        assert placing is not None
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(placing, 1)
        await s.settled()
        assert not any(word[1] == "pointer" and word[2:4] == (2, 2) for word in s.said)
        assert s.machine.holder is None
    played(scene)()


def test_access_revoked_during_initial_status_never_joins_the_video_source() -> None:
    async def scene() -> None:
        device = Screen()
        revoked = False
        lines = lines_to(device, lambda *args: ("signed_out", False) if revoked else (None, True))
        machine = live.Machine(lines, "d1", device)
        line = live.Line(SimpleNamespace(), live.Holder("u", "u", True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 5.0)
        entered = asyncio.Event()
        look = machine._look

        async def looking() -> None:
            entered.set()
            await look()

        machine._look = looking
        joining = asyncio.create_task(machine.join(line))
        await entered.wait()
        revoked = True
        device.looked.set_result(None)
        await joining
        assert line.leaving == "signed_out"
        assert line.source is None
        assert machine.watching is None
        await machine.leave(line)
    played(scene)()
