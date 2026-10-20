"""A stop that comes in the same moment as what was being waited for.

Up to Python 3.11, `asyncio.wait_for` hands back what it waited for where the stop (a task's cancel) and the
result arrive in the same moment, and the stop is lost: the task goes on as if it had never been told. Against
a device that keeps sending, the reader of its messages could be in that moment at every stop (in the trials
here it was, on Windows, and on Linux with a message every thousandth of a second), and went on reading after
every one: a KVM taken off the wall, changed, or a wall being stopped, and its connection went on. (Python 3.12
rewrote `wait_for` on top of `asyncio.timeout`, which keeps the stop.) The program does not use `wait_for`: it
waits within a time with `asyncio.timeout`, or with `asyncio.wait`, which never takes a result for a stop.
"""

from __future__ import annotations

import ast
import asyncio
import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

import qkvm
from qkvm import jetkvm, kvm
from qkvm.kvm import DeviceSpec, KvmDevice
from tests.test_device_limits import OddDevice, frame


class SaysWhenTold:
    """A device's WebSocket as `Listening` reads it: each message in pieces, each piece arriving when the test says."""

    def __init__(self) -> None:
        self.arriving: asyncio.Queue[tuple[str, bool]] = asyncio.Queue()  # a piece, and whether it is a message's last

    def recv_streaming(self) -> AsyncIterator[str]:
        async def pieces() -> AsyncIterator[str]:
            while True:
                piece, last = await self.arriving.get()
                yield piece
                if last:
                    return

        return pieces()


async def told_to_stop(task: asyncio.Task[Any]) -> bool:
    """Stop `task`, which is in the middle of it: False where it went on as if it had not been told."""
    if task.done():
        return True  # (it was over before the stop: nothing to lose)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        return True
    return False


def test_a_reader_told_to_stop_stops_also_when_a_message_comes_in_that_moment() -> None:
    # Every way the moment can fall is tried: the stop with the only piece of a message, and with the last piece
    # of one that came in two (the first is in hand by then, and the reader waits for the rest).
    async def go(steps: int, two_pieces: bool) -> bool:
        device = SaysWhenTold()
        reading = asyncio.create_task(kvm.Listening(device, 1000).message(5))
        if two_pieces:
            device.arriving.put_nowait(("hel", False))
            for _ in range(20):
                await asyncio.sleep(0)
            assert not reading.done()
        for _ in range(3):
            await asyncio.sleep(0)
        device.arriving.put_nowait(("lo" if two_pieces else "hello", True))
        for _ in range(steps):
            await asyncio.sleep(0)
        return await told_to_stop(reading)

    for two_pieces in (False, True):
        for steps in range(10):
            assert asyncio.run(go(steps, two_pieces)), f"a stop was lost ({'the last of two pieces' if two_pieces else 'a message in one piece'}, {steps} steps)"


def test_a_question_to_a_jetkvm_told_to_stop_stops_also_when_its_answer_comes_in_that_moment() -> None:
    # A text is typed on a JetKVM a key at a time, each key a question that waits for its answer. Told to stop as
    # an answer came, the typing went on with the next key, and with the rest of the text.
    async def go(steps: int) -> bool:
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "j", "http://192.168.1.10", "", "secret", kind="jetkvm"))  # (never reached)
        session = jetkvm._Session()
        session.ready.set()
        asked: list[dict[str, Any]] = []

        class Channel:
            def send(self, text: str) -> None:
                asked.append(json.loads(text))

        session.rpc = Channel()
        asking = asyncio.create_task(device._call(session, "keyboardReport", {"modifier": 0, "keys": [4]}))
        for _ in range(3):
            await asyncio.sleep(0)
        device._on_message(session, json.dumps({"jsonrpc": "2.0", "id": asked[0]["id"], "result": None}))
        for _ in range(steps):
            await asyncio.sleep(0)
        try:
            return await told_to_stop(asking)
        finally:
            await device.close()

    for steps in range(8):
        assert asyncio.run(go(steps)), f"a stop was lost ({steps} steps)"


def keeps_sending(talking: threading.Event, enough: threading.Event, hung_up: threading.Event) -> Callable[[socket.socket], None]:
    """A device's end of the stream that sends an event every thousandth of a second, as long as the test likes.

    It answers nothing, the wall's goodbye neither. `talking` is set once it has begun to send, `hung_up` once the
    wall has ended the connection.

    (No slower. The stop comes from a task woken by its clock, and on Linux an event loop waits for its clock in
    whole thousandths: at two of them between two events, that task woke while the reader had nothing in hand,
    and the stop was kept on Python 3.11 too, ten times in ten. At one, it was lost ten times in ten, as on
    Windows at either pace.)
    """
    event = frame(0x1, json.dumps({"event_type": "streamer_state", "event": {"padding": "x" * 1000}}).encode())

    def talk(conn: socket.socket) -> None:
        try:
            while not enough.is_set():
                conn.sendall(event)
                talking.set()
                time.sleep(0.001)
        except OSError:
            hung_up.set()  # the wall has ended the connection
            raise

    return talk


def test_a_kvm_taken_off_the_wall_while_it_keeps_sending_is_let_go_of(monkeypatch: pytest.MonkeyPatch) -> None:
    # The stream that keeps a KVM's picture coming brings an event after another. Taken off the wall, changed,
    # or the wall stopped, the KVM's reader was told to stop as one was arriving, and went on reading; with
    # Python 3.11, at every stop it was told of. Its connection lived on for as long as the reader then kept it.
    #
    # And once the reader did stop, its goodbye to the device was cut short half a second later (whoever retires
    # a device tells its tasks again), and the library leaves a connection whose goodbye was cut short as it is:
    # open, for as long as a device that does not answer it likes. On every Python.
    #
    # What a flood is, is not asked here: a wall held up for a second on a loaded machine reads what piled up
    # meanwhile in one go, and more than a device has reason to send in a second would end the stream as one.
    monkeypatch.setattr(kvm, "MOST_A_SECOND", 10**6)
    monkeypatch.setattr(kvm, "MOST_FRAMES_A_SECOND", 10**6)

    async def once(port: int, talking: threading.Event, enough: threading.Event, hung_up: threading.Event) -> None:
        device = KvmDevice(DeviceSpec("k", "k", f"http://127.0.0.1:{port}", "admin", "secret"))
        device._token = "token"  # signed in: what is asked here is how the stream ends, not how it begins
        device._glinet = True  # (and known for a GLKVM: the family is not asked of a device that only speaks this line)
        device._wanted_at = time.monotonic()
        device._start_keepalive()
        reading = device._keepalive
        assert reading is not None
        # The stream is open and the device sending, however busy the machine is (stopped before that, the wall
        # leaves a connection it is still making, and the device never begins), and the reader in the middle of it.
        assert await asyncio.to_thread(talking.wait, 10), "the device never began to send"
        await asyncio.sleep(0.2)
        assert not reading.done(), f"the stream ended by itself: {reading.exception() if not reading.cancelled() else 'cancelled'}"
        try:
            await device.close()
            assert reading.done(), "the KVM is off the wall, and its stream is still read"
            assert reading.cancelled(), f"its stream ended, but not by the stop: {reading.exception()}"
            # (Looked at while the wall still runs: a connection left open is closed with the program, by the system.)
            assert await asyncio.to_thread(hung_up.wait, 5), "the KVM is off the wall, and its connection is still open"
        finally:
            if not reading.done():
                enough.set()  # (the device stops and hangs up: a reader that is not told to stop then ends by that)
                await asyncio.wait({reading}, timeout=10)

    for _ in range(3):
        talking, enough, hung_up = threading.Event(), threading.Event(), threading.Event()
        sender = OddDevice(keeps_sending(talking, enough, hung_up))
        try:
            asyncio.run(once(sender.port, talking, enough, hung_up))
        finally:
            enough.set()
            sender.stop()


def test_the_program_waits_within_a_time_only_in_a_way_that_keeps_a_stop() -> None:
    # The rule beside the fix: `asyncio.wait_for` loses a stop up to Python 3.11 (see above), and a Python of
    # that version is one this program runs on. `async with asyncio.timeout(...)` keeps it, on every version.
    found: list[str] = []
    package = Path(qkvm.__file__).resolve().parent
    files = sorted(package.rglob("*.py"))
    assert len(files) > 20
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        # What the module asyncio, and its part asyncio.tasks, are called in this file.
        modules = {"asyncio", "asyncio.tasks"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("asyncio", "asyncio.tasks") and alias.asname:
                        modules.add(alias.asname)
            elif isinstance(node, ast.ImportFrom) and node.module == "asyncio":
                modules |= {alias.asname or alias.name for alias in node.names if alias.name == "tasks"}
        modules |= {f"{name}.tasks" for name in modules}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "wait_for" and ast.unparse(node.value) in modules:
                found.append(f"{path.relative_to(package)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and node.module in ("asyncio", "asyncio.tasks") and any(alias.name == "wait_for" for alias in node.names):
                found.append(f"{path.relative_to(package)}:{node.lineno}")
    assert not found, (
        "asyncio.wait_for, which up to Python 3.11 hands back what came where a stop came in the same moment, and the "
        f"stop is lost (a reader of a device that keeps sending then outlives every stop); wait with `async with asyncio.timeout(...)`: {', '.join(found)}"
    )
