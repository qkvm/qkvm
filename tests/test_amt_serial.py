"""The serial console of a PC with Intel AMT (Serial over LAN), read through the engine's redirection port, against the stand-in.

A real PC was asked (see the README): its serial console opened and answered every ping, and the PC wrote nothing there that
was text. So what a PC writes is the stand-in's here, and the hostile engine is the stand-in told to misbehave.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable, Iterator
from types import SimpleNamespace

import pytest

from qkvm import amtserial, rfb
from qkvm.amt import AmtDevice, Answered
from qkvm.amtserial import Kept, SerialConsole
from qkvm.kvm import REJECTED, DeviceSpec, KvmError
from tests.fake_amt import OTHER_GUID, OTHER_REALM, AmtState, FakeAmt, FakeRedirection, V6Amt


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amtserial, "PING_EVERY", 0.1)
    REJECTED.clear()


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt(AmtState()).start()
    yield machine
    machine.stop()


def asked_of(spec: DeviceSpec) -> Callable[[], Awaitable[Answered]]:
    """The tile's question which PC answers (AmtDevice._before_a_session), as a console is given it: asked by a tile of `spec`
    made for the question and closed after it, in the loop the console runs in."""

    async def checked() -> Answered:
        device = AmtDevice(spec)
        try:
            return await device._before_a_session()
        finally:
            await device.close()

    return checked


def console_of(machine: FakeAmt, password: str = "secret") -> SerialConsole:
    spec = DeviceSpec(id="ab12", name="PC", base_url=machine.url, username="admin", password=password, kind="amt")
    return SerialConsole(spec, checked=asked_of(spec))


async def read_until(console: SerialConsole, wanted: int, within: float = 5.0, quiet_within: float = amtserial.QUIET_WITHIN) -> None:
    """Run the console until `wanted` bytes came, then end it as the engine expects."""
    stop = asyncio.Event()
    running = asyncio.create_task(console.run(stop, quiet_within))
    deadline = time.monotonic() + within
    while console.kept.total < wanted and not running.done():
        assert time.monotonic() < deadline, f"only {console.kept.total} bytes came"
        await asyncio.sleep(0.02)
    stop.set()
    await running


def soon(condition: Callable[[], bool], what: str, within: float = 5.0) -> None:
    """Wait for the stand-in engine to have counted what it was sent last. It runs in a thread of its own and reads the
    console's final bytes a moment after the console has returned (on Linux with Python 3.13, four suites at once, it
    had not yet when looked at at once). Something that never arrives still fails, after `within` seconds."""
    deadline = time.monotonic() + within
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.02)


def test_what_the_pc_writes_is_read_and_the_console_is_ended_as_the_engine_expects(pc: FakeAmt) -> None:
    pc.state.sol_text = [b"\x1b[2J\x1b[1;1H", b"Hello from ", b"the BIOS\r\n"]
    console = console_of(pc)

    async def run() -> None:
        await read_until(console, 30)
        await asyncio.sleep(0.3)  # (pings answered meanwhile)

    asyncio.run(run())
    assert console.kept.last() == b"\x1b[2J\x1b[1;1HHello from the BIOS\r\n"
    soon(lambda: (pc.state.sol_sessions, pc.state.sol_ended, pc.state.sol_open) == (1, 1, 0), "the console's end, then the session's, reached the engine")
    assert pc.state.sol_to_pc == [] and pc.state.screen.keys == []  # (read only: nothing went to the PC)
    assert pc.state.redirection_logins == 1 and REJECTED.times(REJECTED.what("login", console.spec)) == 0


def test_a_console_that_stays_open_is_kept_alive_by_pings(pc: FakeAmt) -> None:
    console = console_of(pc)

    async def run() -> None:
        stop = asyncio.Event()
        # Use the real idle allowance on a real socket: the stand-in runs on another thread, and a busy Windows
        # runner can leave it unscheduled for the old half-second allowance. Wait for actual pings, not a fixed sleep;
        # the reader's renewal of its idle allowance is checked with a controlled clock below.
        running = asyncio.create_task(console.run(stop))
        try:
            async with asyncio.timeout(5):
                while pc.state.sol_pings < 5:
                    if running.done():
                        await running  # report a real connection failure rather than waiting out the test's deadline
                    await asyncio.sleep(0.01)
            assert not running.done()
        finally:
            stop.set()
            await running

    asyncio.run(run())
    assert pc.state.sol_pings >= 5
    soon(lambda: pc.state.sol_ended == 1, "the console's end, then the session's, reached the engine")


def test_each_pong_renews_the_idle_allowance_and_silence_still_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    # Five pongs arrive four tenths of a second apart: the connection lasts longer than its half-second idle
    # allowance, but no individual gap exceeds it. Advance a controlled clock so CPU scheduling cannot make
    # a healthy peer appear silent. The sixth gap really exceeds the allowance and must propagate the timeout.
    elapsed = 0.0
    calls: list[tuple[int, float | None]] = []
    timed_out = rfb.RfbError(rfb.TIMEOUT, "the server did not send the next piece in time")

    class Replies(rfb.Stream):
        pongs = 0

        async def read(self, size: int, within: float | None) -> bytes:
            nonlocal elapsed
            calls.append((size, within))
            if size == 7:
                return bytes(7)
            assert size == 1
            gap = 0.4 if self.pongs < 5 else 0.6
            if within is not None and gap > within:
                elapsed += within
                raise timed_out
            elapsed += gap
            self.pongs += 1
            assert self.pongs <= 5, "silence must end the connection"
            return bytes((amtserial.PONG,))

    replies = Replies()
    kept = Kept()
    monkeypatch.setattr(amtserial, "time", SimpleNamespace(monotonic=lambda: elapsed))
    with pytest.raises(rfb.RfbError) as ended:
        asyncio.run(amtserial.read_console(replies, kept, quiet_within=0.5))
    assert ended.value is timed_out
    assert replies.pongs == 5 and elapsed == 2.5
    assert calls == [(1, 0.5), (7, amtserial.STEP)] * 5 + [(1, 0.5)]
    assert kept.total == 0  # pongs keep the connection alive without inventing serial text


def test_only_the_newest_is_kept_and_each_byte_is_moved_once_at_the_most() -> None:
    kept = Kept(most=1000)
    for number in range(500):
        kept.add(bytes((number % 256,)) * 100)
        assert len(kept._data) <= 2000
    assert kept.total == 50_000
    assert kept.last() == b"".join(bytes((number % 256,)) * 100 for number in range(490, 500))


@pytest.mark.parametrize(
    ("odd", "code", "said"),
    [
        ("huge", "bad_response", "which none is"),
        ("nonsense", "bad_response", "no message of a serial console"),
        ("flood", "bad_response", "more than a serial console writes"),
        ("ends", "dropped", "the engine ended the serial console"),
    ],
)
def test_an_engine_that_sends_what_no_serial_console_sends_is_said_to(pc: FakeAmt, odd: str, code: str, said: str) -> None:
    pc.state.sol_odd = odd
    console = console_of(pc)
    lag: list[float] = []

    async def run() -> None:
        async def ticking() -> None:  # (the loop has its turn while the console is read)
            while True:
                before = time.monotonic()
                await asyncio.sleep(0.01)
                lag.append(time.monotonic() - before - 0.01)

        ticker = asyncio.create_task(ticking())
        try:
            with pytest.raises(KvmError) as ended:
                async with asyncio.timeout(10):
                    await console.run(asyncio.Event())
        finally:
            ticker.cancel()
        assert (ended.value.code, said in ended.value.message) == (code, True), ended.value.message

    asyncio.run(run())
    assert len(console.kept._data) <= 2 * amtserial.MOST_KEPT
    assert max(lag, default=0.0) < 0.5, max(lag)


def test_an_engine_that_answers_no_ping_is_taken_to_be_gone(pc: FakeAmt) -> None:
    pc.state.sol_odd = "silent"

    async def run() -> None:
        with pytest.raises(KvmError) as ended:
            await console_of(pc).run(asyncio.Event(), quiet_within=0.5)
        assert ended.value.code == "timeout"

    asyncio.run(run())


def test_a_console_the_engine_does_not_begin_is_said_so(pc: FakeAmt) -> None:
    pc.state.sol_status = 1

    async def run() -> None:
        with pytest.raises(KvmError) as ended:
            await console_of(pc).run(asyncio.Event())
        assert ended.value.code == "bad_response" and "does not start its serial console" in ended.value.message

    asyncio.run(run())


def test_another_viewers_console_is_said_so(pc: FakeAmt) -> None:
    pc.state.start_status = 2  # (as a real engine answered the KVM's start while another viewer had it)

    async def run() -> None:
        with pytest.raises(KvmError) as ended:
            await console_of(pc).run(asyncio.Event())
        assert "another viewer has its serial console" in ended.value.message

    asyncio.run(run())
    assert pc.state.redirection_logins == 0  # (refused before anything of the password went out)


def test_a_password_the_engine_refuses_is_a_no_and_is_not_offered_again_at_once(pc: FakeAmt) -> None:
    pc.state.redirection_password = "another"
    console = console_of(pc)

    async def run() -> None:
        for _ in range(2):
            with pytest.raises(KvmError) as ended:
                await console.run(asyncio.Event())
            assert ended.value.code == "auth_failed"

    asyncio.run(run())
    assert (pc.state.redirection_logins, pc.state.redirection_rejections) == (1, 1)  # (the second was not sent: a minute first)
    assert REJECTED.times(REJECTED.what("login", console.spec)) == 1


def test_a_console_stopped_twice_is_closed_all_the_same(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The reviewer's F5.) Stopped, and stopped again a moment later (as kvm.stopped does), the console's connection was left
    # open: the close came after a wait that the second stop cut short. An open console keeps the engine from cutting the power.
    from qkvm import rfb

    closed: list[int] = []
    close = rfb.TcpStream.close

    async def counted(self: rfb.TcpStream) -> None:
        closed.append(1)
        await close(self)

    monkeypatch.setattr(rfb.TcpStream, "close", counted)

    async def run() -> None:
        running = asyncio.create_task(console_of(pc).run(asyncio.Event()))
        deadline = time.monotonic() + 5
        while not pc.state.sol_open:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.02)
        running.cancel()
        await asyncio.sleep(0)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(run())
    assert closed == [1]


def test_a_console_begun_with_this_session_is_being_recorded_is_read(pc: FakeAmt) -> None:
    # (The reviewer's F6.) The engine may say "this session is being recorded" before its answer to the start, as it may for the
    # KVM: that byte was taken for the answer, and the console was said to be no serial console.
    pc.state.sol_recorded, pc.state.sol_text = True, [b"text"]
    console = console_of(pc)
    asyncio.run(read_until(console, 4))
    assert console.kept.last() == b"text"


def test_a_serial_console_open_bars_cutting_the_power_as_a_kvm_session_does(pc: FakeAmt) -> None:
    # (What a real engine did: with only its serial console open, it listed neither 8 nor 5 among the states it offers.)
    console = console_of(pc)

    async def run() -> None:
        stop = asyncio.Event()
        running = asyncio.create_task(console.run(stop))
        deadline = time.monotonic() + 5
        while not pc.state.sol_open:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.02)
        from qkvm.amt import AmtDevice

        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt"))
        try:
            _, offered = await device._read_power(urgent=True)
            assert 8 not in offered and 5 not in offered
        finally:
            await device.close()
            stop.set()
            await running

    asyncio.run(run())


# --- which PC answers, on the console's own connection (0.2.1) --------------------------------------------------------


def bound(url: str) -> tuple[AmtDevice, SerialConsole]:
    """A tile of the PC, and its serial console bound to it: before it opens, the console asks the tile which PC answers
    (AmtDevice._before_a_session, as the screen session does), goes to the address that answer came from and compares the
    realm there."""
    device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=url, username="admin", password="secret", kind="amt"))
    return device, SerialConsole(device.spec, checked=device._before_a_session)


def test_another_engine_on_the_redirection_port_is_not_sent_the_password_by_the_serial_console() -> None:
    # (Round 3 of 0.2.1, as the screen session since 76e85b2.) What answers on the redirection port at the very address is not
    # the engine that said which PC it is (its realm, which every engine has of its own, is another): the console is refused
    # before the Digest answer goes, and none is begun. Before: the other engine had the Digest answer and gave its console.
    pc = FakeAmt()
    pc.state.sol_text = [b"hello"]
    other = AmtState(guid=OTHER_GUID, realm=OTHER_REALM, sol_text=[b"other"])
    pc.redirection = FakeRedirection(other, pc.redirection._sock, None)
    pc.start()
    try:
        device, console = bound(pc.url)

        async def run() -> KvmError:
            try:
                with pytest.raises(KvmError) as caught:
                    await console.run(asyncio.Event())
                return caught.value
            finally:
                await device.close()

        error = asyncio.run(run())
        assert (error.code, error.message) == ("another_machine", amtserial.OTHER_ENGINE)
        assert other.redirections == 1 and (other.redirection_logins, other.sol_sessions) == (0, 0), "the other engine was sent the Digest answer"
        assert console.kept.total == 0 and REJECTED.times(REJECTED.what("login", console.spec)) == 0
    finally:
        pc.stop()


def test_the_serial_console_goes_to_the_engine_that_said_which_pc_it_is_where_its_name_has_two_addresses() -> None:
    # (The same.) The tile's name resolves to two addresses ("localhost" here: 127.0.0.1 and ::1; a stale record beside the
    # current one, in a real network). Which PC answers is asked on WS-Management, which reaches the tile's PC at one of them;
    # the console goes to the address that answer came from, not to the name resolved anew (before: it reached the other PC at
    # the other address, which had the Digest answer and gave its console).
    if len({info[4][0] for info in socket.getaddrinfo("localhost", 1, type=socket.SOCK_STREAM)}) < 2:
        pytest.skip("localhost has one address here")
    a = b_sock = None
    for _ in range(20):
        a = V6Amt()
        b_sock = socket.socket()
        try:
            b_sock.bind(("127.0.0.1", a.port + 2))
            break
        except OSError:
            b_sock.close()
            a.redirection._sock.close()
            a._sock.close()
            a = None
    assert a is not None and b_sock is not None
    a.url = f"http://localhost:{a.port}"
    a.state.sol_text = [b"hello"]
    other = AmtState(guid=OTHER_GUID, realm=OTHER_REALM, sol_text=[b"other"])
    b = FakeRedirection(other, b_sock, None)
    a.start()
    b.start()
    try:
        device, console = bound(a.url)

        async def run() -> None:
            try:
                await read_until(console, 5)
            finally:
                await device.close()

        asyncio.run(run())
        assert console.kept.last() == b"hello"
        assert (other.redirections, other.redirection_logins, other.sol_sessions) == (0, 0, 0), "the other PC was reached"
        assert (a.state.redirection_logins, a.state.sol_sessions) == (1, 1)
    finally:
        a.stop()
        b.stop()


def test_a_serial_console_whose_tile_cannot_tell_which_pc_answers_opens_nothing(pc: FakeAmt) -> None:
    # (The same.) What the tile's question says is said by the console, and nothing goes to the redirection port: here the PC
    # answers with the number of another PC than the one this tile was added for.
    from qkvm.amt import own_number

    device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(OTHER_GUID)))
    console = SerialConsole(device.spec, checked=device._before_a_session)

    async def run() -> KvmError:
        try:
            with pytest.raises(KvmError) as caught:
                await console.run(asyncio.Event())
            return caught.value
        finally:
            await device.close()

    assert asyncio.run(run()).code == "another_machine"
    assert pc.state.redirections == 0 and pc.state.sol_sessions == 0


def test_a_serial_console_is_not_made_without_its_tiles_question_which_pc_answers() -> None:
    # (The coordinator, round 3 of 0.2.1.) Bound as the screen session is, or not made at all: nothing builds a serial console
    # that would go to whatever answers at the name and sign in there.
    spec = DeviceSpec(id="ab12", name="PC", base_url="http://127.0.0.1:16992", username="admin", password="secret", kind="amt")
    with pytest.raises(TypeError):
        SerialConsole(spec)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        SerialConsole(spec, Kept())  # type: ignore[arg-type,misc]
