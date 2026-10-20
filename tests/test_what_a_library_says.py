"""What a device's end of a connection can make the wall write, and where that is written.

A line that is not this program's own to say (a library's, the event loop's) goes into the log, by the
thread that writes, each kind once a minute: not to the terminal, and never from the thread that serves
everybody.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import io
import logging
import logging.config
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from qkvm import cli, kvm
from qkvm.kvm import DeviceSpec, KvmDevice
from tests.test_device_limits import GUID, OddDevice, frame
from tests.test_wall import closed_port


def reset(conn: socket.socket) -> None:
    """Hang up the hard way: the other end is told at once that the connection is gone."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0))
    conn.close()


class InOneBreath:
    """A device's WebSocket end that sends something of its own together with its answer to the handshake."""

    def __init__(self, with_it: bytes, then: Callable[[socket.socket], None] = lambda conn: time.sleep(5)) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._with_it, self._then = with_it, then
        self.opened = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                more = conn.recv(4096)
                if not more:
                    return
                data += more
            head = data.split(b"\r\n\r\n")[0].decode("latin1")
            key = next(line.split(":", 1)[1].strip() for line in head.split("\r\n") if line.lower().startswith("sec-websocket-key"))
            accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
            answer = f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            self.opened += 1
            conn.sendall(answer.encode() + self._with_it)
            self._then(conn)
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._sock.close()


class Terminal(io.StringIO):
    """What stands in for the terminal: keeps what is written to it, and counts the writes made by the event loop's thread."""

    def __init__(self) -> None:
        super().__init__()
        self.from_the_loop = 0

    def write(self, text: str) -> int:
        try:
            asyncio.get_running_loop()
            self.from_the_loop += 1
        except RuntimeError:
            pass
        return super().write(text)


@pytest.fixture
def as_the_program_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Terminal, Path]]:
    """The log as the program sets it up, and a stand-in for the terminal."""
    names = ("asyncio", "qkvm", "uvicorn.error", "websockets")
    before = {name: (logging.getLogger(name).handlers[:], logging.getLogger(name).filters[:], logging.getLogger(name).propagate, logging.getLogger(name).level) for name in names}
    terminal = Terminal()
    monkeypatch.setattr(sys, "stderr", terminal)
    cli.setup_logging(tmp_path, "info")
    try:
        yield terminal, tmp_path
    finally:
        cli.stop_logging()
        for name, (handlers, filters, propagate, level) in before.items():
            logger = logging.getLogger(name)
            logger.handlers[:], logger.filters[:], logger.propagate = handlers, filters, propagate
            logger.setLevel(level)


@contextmanager
def nothing_else_listening() -> Iterator[None]:
    """A test run hangs handlers of its own on the root of all loggers, for the length of each test. The
    program has one there, its own (cli.setup_logging), and nothing else: the others are taken off, so that
    what a library logs goes where it goes in the program."""
    root = logging.getLogger()
    kept = root.handlers[:]
    root.handlers[:] = [handler for handler in kept if handler is cli._others]
    try:
        yield
    finally:
        root.handlers[:] = kept


def a_kvm_at(port: int) -> KvmDevice:
    kvmd = KvmDevice(DeviceSpec("d", "Hostile", f"http://127.0.0.1:{port}", "admin", "secret", tls="insecure"))
    kvmd._token = "t"  # signed in already: this is about the connection that keeps the picture coming
    kvmd._glinet = True  # ...and known for a GLKVM, as a look finds one: the family is not asked of a device that only speaks this line
    return kvmd


def test_a_device_that_is_hung_up_on_for_flooding_writes_nothing_on_the_terminal(as_the_program_logs: tuple[Terminal, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    # A device sends its answer to the handshake and a flood (here: sixty pings of no bytes) in one piece.
    # `_ToADevice.data_received` hangs up on it there and then, before the library has come round to noting
    # that the handshake is done. The library noted it a moment later, on a connection that was lost by then,
    # and started its "keepalive" task for it, which nothing stopped any more. When that task tried its first
    # ping it failed, and logged "keepalive ping failed" with a traceback, at ERROR, to "websockets.client".
    # The program gave that logger no place to write to, so Python's handler of last resort wrote it to
    # stderr: not into qkvm.log, which is kept to a size, and from the thread that serves everybody, the one
    # that "must not wait ... for a terminal that holds its output back" (cli.setup_logging).
    # (The library's first ping is due twenty seconds after the handshake; here, one.)
    monkeypatch.setattr(kvm, "ws_connect", functools.partial(kvm.ws_connect, ping_interval=1))
    terminal, folder = as_the_program_logs
    device = InOneBreath(frame(0x9) * 60)
    connections = 12

    async def run() -> int:
        kvmd = a_kvm_at(device.port)
        for _ in range(connections):
            kvmd._wanted_at = time.monotonic()
            await kvmd._hold_stream_open()  # as a tile does that is told "the stream is idle"
        left = sum(1 for task in asyncio.all_tasks() if "keepalive" in repr(task.get_coro()))
        await asyncio.sleep(3.0)  # long enough for a ping of the library's to have come due, and failed
        await kvmd.close()
        return left

    try:
        with nothing_else_listening():
            left = asyncio.run(run())
    finally:
        device.stop()
    cli.stop_logging()
    written = terminal.getvalue()
    log = (folder / "qkvm.log").read_text(encoding="utf-8")
    print(
        f">>> {connections} connections ({device.opened} handshakes answered); {left} tasks of the library left running after them; on the terminal: "
        f"'keepalive ping failed' {written.count('keepalive ping failed')} times, {len(written)} characters in {len(written.splitlines())} lines, "
        f"{terminal.from_the_loop} writes made by the thread of the event loop; in qkvm.log: {log.count('keepalive ping failed')} times"
    )
    assert left == 0, f"{left} of {connections} connections left a task of the library running after they were over"
    assert "keepalive ping failed" not in written, f"{written.count('keepalive ping failed')} tracebacks on the terminal, {len(written)} characters"
    assert terminal.from_the_loop == 0, f"{terminal.from_the_loop} writes to the terminal were made by the thread that serves everybody"


def test_two_thousand_answers_into_a_connection_that_is_gone_cost_the_wall_little(as_the_program_logs: tuple[Terminal, Path]) -> None:
    # Within the first piece of what a device sent, every ping is answered, and each answer into a connection
    # that is gone was a line the event loop put together, for the filter to throw away: eighty thousand of
    # them for forty connections. The loop is told to keep to errors, and does not make the line at all.
    terminal, folder = as_the_program_logs
    made: list[int] = [0]
    held: list[float] = []  # how long each piece of a device's bytes held the thread

    class Counting(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            made[0] += 1
            return True

    logging.getLogger("asyncio").filters.insert(0, Counting())
    real = kvm._ToADevice.data_received

    def timed(self: kvm._ToADevice, data: bytes) -> None:
        began = time.perf_counter()
        try:
            real(self, data)
        finally:
            held.append(time.perf_counter() - began)

    def pings(conn: socket.socket) -> None:
        conn.sendall(frame(0x9) * 2000)
        reset(conn)

    device = OddDevice(pings)
    connections = 40

    async def run() -> float:
        kvmd = a_kvm_at(device.port)
        began = time.perf_counter()
        for _ in range(connections):
            kvmd._wanted_at = time.monotonic()
            await kvmd._hold_stream_open()
        took = time.perf_counter() - began
        await kvmd.close()
        return took

    kvm._ToADevice.data_received = timed  # type: ignore[method-assign]
    try:
        took = asyncio.run(run())
    finally:
        kvm._ToADevice.data_received = real  # type: ignore[method-assign]
        device.stop()
    cli.stop_logging()
    lines = [line for line in (folder / "qkvm.log").read_text(encoding="utf-8").splitlines() if " asyncio: " in line]
    worst = sorted(held, reverse=True)[:connections]  # the piece with the pings in it, of each connection
    print(
        f">>> {connections} connections in {took:.2f} s; records the event loop made: {made[0]} ({made[0] // connections} a connection); lines of it in qkvm.log: {len(lines)}; "
        f"on the terminal: {len(terminal.getvalue())} characters; one piece of a device's bytes held the thread for "
        f"{worst[len(worst) // 2] * 1000:.1f} ms (the middle one of the {len(worst)} longest), {worst[0] * 1000:.1f} ms (the longest), {sum(held) * 1000:.0f} ms in all"
    )
    assert len(lines) <= 1 and "socket.send" not in terminal.getvalue()
    assert made[0] == 0, f"{made[0]} lines were put together by the event loop for answers into connections that were gone"


def test_what_a_device_gives_as_its_reason_for_hanging_up_is_one_line_in_the_log(as_the_program_logs: tuple[Terminal, Path]) -> None:
    # The reason a device gives when it closes its WebSocket is text of its choosing (kvm.py,
    # `_hold_stream_open`, "stream keepalive ended: %s"), and was written into qkvm.log as it came. With a
    # line break in it, what followed read as a line the program wrote.
    _, folder = as_the_program_logs
    forged = "2026-10-11 03:00:00,000 WARNING qkvm: a line the device wrote"
    device = OddDevice(lambda conn: (conn.sendall(frame(0x8, struct.pack(">H", 1000) + b"bye\n" + forged.encode())), time.sleep(0.5)))

    async def run() -> None:
        kvmd = a_kvm_at(device.port)
        kvmd._wanted_at = time.monotonic()
        await kvmd._hold_stream_open()
        await kvmd.close()

    try:
        asyncio.run(run())
    finally:
        device.stop()
    cli.stop_logging()
    lines = (folder / "qkvm.log").read_text(encoding="utf-8").splitlines()
    print(">>> qkvm.log: " + " /// ".join(lines)[:400])
    assert forged not in lines, "a line in qkvm.log that is word for word what the device sent"


def test_what_the_event_loop_says_through_its_exception_handler_is_held_to_once_a_minute_too(as_the_program_logs: tuple[Terminal, Path]) -> None:
    # `cli._OnceAMinute` tells one kind of line from another by the first 120 characters of what is logged.
    # For the line the filter was made for ("socket.send() raised exception.") that was the whole line. What the
    # loop says through its exception handler (a task or a future whose error nobody looked at, a callback
    # that failed) is one text with the name of the task or the address of the object in it, within those
    # 120 characters: every such record is a kind of its own, passes, and brings its traceback along.
    # (No way for a device to cause these is known: this is what the filter does with them if one exists,
    # now or after the next change to a driver.)
    _, folder = as_the_program_logs

    async def fails(number: int) -> None:
        raise RuntimeError(f"what a driver did not foresee, {number}")

    async def run() -> None:
        import gc

        for number in range(50):
            asyncio.ensure_future(fails(number))  # noqa: RUF006 (nobody keeps it, nobody looks at how it ended: that is the case)
        await asyncio.sleep(0.05)
        gc.collect()
        await asyncio.sleep(0.05)

    asyncio.run(run())
    cli.stop_logging()
    log = (folder / "qkvm.log").read_text(encoding="utf-8")
    said = log.count("Task exception was never retrieved")
    print(f">>> 50 tasks that failed with nobody looking: {said} times 'Task exception was never retrieved' in qkvm.log, {len(log)} characters")
    assert said == 1, f"{said} of 50 passed a filter that lets each kind of line through once a minute"


def test_the_stand_in_terminal_counts_what_it_says() -> None:
    terminal = Terminal()
    worker = threading.Thread(target=lambda: terminal.write("x"))
    worker.start()
    worker.join()
    assert terminal.from_the_loop == 0

    async def on_the_loop() -> None:
        terminal.write("y")

    asyncio.run(on_the_loop())
    assert terminal.from_the_loop == 1


@pytest.mark.parametrize("when", ["in answer to something the wall said", "together with its answer to the handshake"])
def test_what_a_device_said_just_before_it_reset_the_connection_is_heard(when: str) -> None:
    # A device that says something and hangs up the hard way in the same breath. On Windows the reset is known
    # of before what came just ahead of it is handed over; for a while "is the connection closing?" was asked
    # before anything was worked through, and what such a device had said was thrown away, its answer to the
    # handshake among it.
    # (What Windows itself throws away is another matter, and not the program's: words that arrived while
    # nobody was reading are gone once a reset comes in behind them, where Linux hands them over. A wall that
    # is late to look, as on a loaded machine, has lost them before it sees anything. This test once let the
    # words come while the wall was between two reads, and heard them 39 times in 40 on an idle machine and 18
    # on a loaded one. Here the wall is reading when they come, and then does not look until the device has
    # hung up, as a loaded machine would not have: the reset is known of before the words are handed over,
    # the moment they used to be thrown away. Forty in forty.)
    said = b'{"the last": "words"}'
    tries = 40
    hung_up = threading.Event()  # set by the device once it has said its words and reset the connection

    def answers_and_resets(conn: socket.socket) -> None:
        conn.recv(4096)  # whatever the wall said
        conn.sendall(frame(0x1, said))
        reset(conn)
        hung_up.set()

    asked = when == "in answer to something the wall said"
    device = OddDevice(answers_and_resets) if asked else InOneBreath(frame(0x1, said), then=reset)

    async def run() -> list[str]:
        heard = []
        for _ in range(tries):
            try:
                async with kvm.ws_connect(f"ws://127.0.0.1:{device.port}/", open_timeout=5, close_timeout=1) as ws:
                    if asked:
                        hung_up.clear()
                        await ws.send("say it")
                        hung_up.wait(5)  # the loop held, on purpose, until the words and the reset have both landed
                    heard.append(str(await asyncio.wait_for(ws.recv(), 5)))
            except Exception as ex:
                heard.append(type(ex).__name__)
        return heard

    try:
        heard = asyncio.run(run())
    finally:
        device.stop()
    assert heard.count(said.decode()) == tries, {what: heard.count(what) for what in set(heard)}


def test_requests_from_nobody_are_a_line_of_each_kind_and_not_a_line_each(tmp_path: Path) -> None:
    # The web server writes a warning for every request that is none; and it wrote two for every one that asked
    # for a WebSocket while this program spoke none (it speaks one now, the live line of live.py, and a request
    # for a WebSocket anywhere else is refused by the router without a line). Anybody who reaches the port can
    # send those, signed in or not: six hundred of them were nine hundred lines in two seconds, in the log
    # (whose history is kept to a size, and was gone in minutes at that rate) and on the terminal (which is
    # kept to none). The program itself, started as it is started.
    port, data = closed_port(), tmp_path / "data"
    env = {**os.environ, "PYTHONPATH": str(Path(cli.__file__).resolve().parent.parent)}
    env.pop("QKVM_CHILD", None)
    program, where = [sys.executable, "-P", "-m", "qkvm"], ["--data-dir", str(data)]
    many, ended = 60, None
    with open(tmp_path / "terminal.txt", "wb") as terminal:
        wall = subprocess.Popen([*program, *where, "--port", str(port), "--bind", "local"], cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=terminal, stdin=subprocess.DEVNULL)
        try:
            for _ in range(120):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2).read()
                    break
                except OSError:
                    assert wall.poll() is None, "the program ended before it answered"
                    time.sleep(0.25)
            for _ in range(many):
                for said in (b"NOT HTTP AT ALL" + b"\r\n" * 2, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket" + b"\r\n" * 2):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                        conn.sendall(said)
                        try:
                            conn.recv(4096)
                        except OSError:
                            pass
            assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5).status == 200
        finally:
            subprocess.run([*program, "stop", *where], cwd=tmp_path, env=env, capture_output=True, timeout=60)
            try:
                ended = wall.wait(30)
            except subprocess.TimeoutExpired:
                wall.kill()
    assert ended == 0, "asked to stop, the program did not"
    log = (data / "qkvm.log").read_text(encoding="utf-8", errors="replace")
    written = (tmp_path / "terminal.txt").read_text(encoding="utf-8", errors="replace")
    counted = {what: (log.count(what), written.count(what)) for what in ("Invalid HTTP request received", "Unsupported upgrade request", "No supported WebSocket library")}
    print(f">>> {2 * many} requests from nobody: (lines in qkvm.log, lines on the terminal) {counted}")
    assert counted["Invalid HTTP request received"][0] == 1 and counted["Invalid HTTP request received"][1] <= 1, counted
    assert counted["Unsupported upgrade request"] == (0, 0) and counted["No supported WebSocket library"] == (0, 0), counted


def test_a_logging_configuration_given_later_puts_no_device_session_in_the_log() -> None:
    # The WebSocket library writes, at its finer levels, every header it sends: a KVM's session in the cookie. Its
    # connections to devices log through a logger that says nothing finer than a warning. A level of that logger's own did
    # not hold: a logging configuration given later that names the library's logger (its lines at DEBUG, to look into
    # something) sets every logger below it back to no level, and so to DEBUG.
    from tests.fake_kvm import FakeKvm, FakeState

    heard: list[str] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            heard.append(record.getMessage())

    library, to_devices = logging.getLogger("websockets"), logging.getLogger("websockets.to_devices")
    kept = [(logger, logger.level, list(logger.handlers), logger.propagate, logger.disabled) for logger in (library, to_devices)]
    hearing = Heard(logging.DEBUG)
    fake = FakeKvm(FakeState()).start()
    try:
        logging.config.dictConfig({"version": 1, "disable_existing_loggers": False, "loggers": {"websockets": {"level": "DEBUG"}}})
        library.addHandler(hearing)

        async def run() -> str:
            device = KvmDevice(DeviceSpec(id="ab12cd34", name="One", base_url=fake.url, username="admin", password="secret"))
            try:
                line = await device.input_line()
                await line.send('{"event_type": "key", "event": {"key": "KeyA", "state": false}}')
                await line.close()
                assert device._token
                return device._token
            finally:
                await device.close()

        session = asyncio.run(run())
    finally:
        library.removeHandler(hearing)
        for logger, level, handlers, propagate, disabled in kept:
            logger.setLevel(level)
            logger.handlers[:] = handlers
            logger.propagate, logger.disabled = propagate, disabled
        fake.stop()
    assert not any(session in said for said in heard), "a device's session is in the log"
    assert not any("KeyA" in said for said in heard), "what was sent to a device is in the log"
