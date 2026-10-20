"""A PC's screen through Intel AMT's own KVM: the redirection port's handshake, RFB in RGB565, the pace a wall needs,
the settings that decide whether a session may be opened at all, and what an engine on that port can make of it.

Against the stand-in (fake_amt.py), whose redirection port answers as a real engine (AMT 16) was seen to answer, byte
for byte where it was seen; the README says what was tried on that real machine, and test_real_amt.py tries it again
where one is named in the environment.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from qkvm import amt, kvm, live, rfb, update, vault, vncdevice
from qkvm.amt import AmtDevice, Challenge, answer_to, redirect, redirection_digest, sign_in_message, texts_of
from qkvm.kvm import REJECTED, DeviceSpec, KvmError
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_vnc import PixelFormat
from tests.test_redfish import status_of
from tests.test_wall import CSRF, snap, wait_until, wall

RGB565 = PixelFormat(16, 16, False, True, 31, 63, 31, 11, 5, 0)


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(amt, "LOOK_EVERY", 0)
    monkeypatch.setattr(amt, "FOLLOW_UP", ())
    monkeypatch.setattr(amt, "HICCUP", 0)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    REJECTED.clear()


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt().start()
    yield machine
    machine.stop()


def a_pc(machine: FakeAmt) -> AmtDevice:
    return AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=machine.url, username="admin", password="secret", kind="amt"))


def as_shown(rgb: bytes) -> bytes:
    """A picture as the reader has it after the engine's RGB565: each sample cut to five or six bits, and stretched back."""
    return rfb._rgb_of_565(RGB565.pixels(rgb))


async def picture_of(device: AmtDevice, within: float = 15.0) -> kvm.Snapshot:
    """The first picture a tile that is only shown on the wall gets (a still), asked for as a tile asks until it comes."""
    deadline = time.monotonic() + within
    while True:
        try:
            return await device.snapshot(4000)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.05)


async def live_picture(device: AmtDevice, within: float = 15.0) -> kvm.Snapshot:
    """The first picture the enlarged or live view gets: the screen is kept live (a held session) and asked for until it comes."""
    deadline = time.monotonic() + within
    while True:
        device._screen.live_seen()
        try:
            return await device.snapshot(4000)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.05)


async def settled_status(device: AmtDevice, state: str, within: float = 10.0) -> dict[str, Any]:
    """The device's status once a look has settled on `state` (the first `status()` may be from before the look)."""
    deadline = time.monotonic() + within
    while True:
        found = await device.status()
        if found.get("state") == state:
            return found
        assert time.monotonic() < deadline, f"the status never said {state}: {found.get('state')}"
        await asyncio.sleep(0.05)


@contextlib.asynccontextmanager
async def kept_live(device: AmtDevice) -> AsyncIterator[None]:
    """A background view that keeps the tile live and polls its picture, as the enlarged view's live line does: a session
    is held open the while."""
    stop = asyncio.Event()

    async def loop() -> None:
        while not stop.is_set():
            device._screen.live_seen()
            try:
                await device.snapshot(640)
            except KvmError:
                pass
            await asyncio.sleep(0.05)

    task = asyncio.create_task(loop())
    try:
        yield
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)


def looked_at_once_it_came(client: TestClient, device: str, came: Any, seconds: float) -> list[tuple[int, str]]:
    """Ask for the tile's picture as a tile does until `came()` (the first try at the redirection port, say: bounded, for a
    slow machine), and for `seconds` more, in which nothing more is to come. (Looked at for a fixed while from the start, the
    first try was not there yet on a loaded machine: the question which PC answers comes before it.)"""
    seen: list[tuple[int, str]] = []
    deadline = time.monotonic() + 30
    while not came():
        assert time.monotonic() < deadline, f"it never came; the tile was answered {seen[-3:]}"
        seen += looked_at(client, device, 0.1)
    return seen + looked_at(client, device, seconds)


def looked_at(client: TestClient, device: str, seconds: float) -> list[tuple[int, str]]:
    """Ask for the tile's picture for this long, as a tile does: what came each time (status, and the code where it was none)."""
    seen: list[tuple[int, str]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        reply = client.get(snap(device))
        seen.append((reply.status_code, "" if reply.status_code == 200 else reply.json()["code"]))
        time.sleep(0.05)
    return seen


# --- the screen, as the engine gives it ---------------------------------------------------------------------------


def test_the_screen_comes_through_the_kvm_in_the_engines_own_format(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            snap_ = await live_picture(device)  # (live, so the session stays open and its screen can be read below)
            device._screen.live_seen()
            assert snap_.content_type == "image/jpeg" and snap_.data[:2] == b"\xff\xd8"
            # Intel's handshake, once, and the password taken there: the same account as on WS-Management.
            assert (pc.state.redirections, pc.state.redirection_logins, pc.state.redirection_rejections, pc.state.kvm_sessions) == (1, 1, 0, 1)
            screen = pc.state.screen
            # RFB as the engine wants it: answered as 3.8 although it greets as 4.0, shared, its own format (it hangs up at
            # any other), Raw and the screen's size changes only.
            assert screen.versions == [b"RFB 003.008\n"] and screen.shared == [1]
            assert [one.bpp for one in screen.formats] == [16] and screen.formats[0] == RGB565
            assert screen.encodings_asked == [[rfb.RAW, rfb.DESKTOP_SIZE]]
            # The first request was answered with the size alone; the whole screen came with the next, as a real engine does it.
            assert screen.requests[0][0] is False and any(incremental for incremental, *_ in screen.requests[1:])
            shown = device._screen.screen()
            assert shown is not None and shown[1:3] == (320, 200)
            assert bytes(shown[3]) == as_shown(screen.picture)  # pixel for pixel, as RGB565 has it
        finally:
            await device.close()

    asyncio.run(run())


def test_rgb565_is_turned_into_pixels_outside_the_event_loop(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Four times the work of the other format's, a pixel at a time: in the reader's own threads, as the other encodings are
    # drawn, so that an engine sending at the most a second allows does not hold the one thread everything is served from.
    where: set[str] = set()
    original = rfb._rgb_of_565

    def recorded(pixels: bytes) -> bytes:
        where.add(threading.current_thread().name)
        return original(pixels)

    monkeypatch.setattr(rfb, "_rgb_of_565", recorded)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
        finally:
            await device.close()

    asyncio.run(run())
    assert where and threading.main_thread().name not in where, where


def test_rgb565_is_read_for_every_value_it_can_have() -> None:
    every = b"".join(value.to_bytes(2, "little") for value in range(65536))
    expected = bytearray()
    for value in range(65536):
        r, g, b = value >> 11, (value >> 5) & 0x3F, value & 0x1F
        expected += bytes(((r * 255 + 15) // 31, (g * 255 + 31) // 63, (b * 255 + 15) // 31))
    assert rfb._rgb_of_565(every) == bytes(expected)
    assert rfb._rgb_of_565(b"") == b""


def test_the_reader_takes_rgb565_only_where_it_can_read_it_and_version_4_only_where_it_is_told() -> None:
    stream = rfb.Stream()
    with pytest.raises(ValueError):
        rfb.Client(stream, pixels=rfb.RGB565)  # (Tight, ZRLE and Hextile carry pixels of their own shapes in it)
    with pytest.raises(ValueError):
        rfb.Client(stream, encodings=(rfb.ZRLE,))  # (no Raw)
    rfb.Client(stream, pixels=rfb.RGB565, encodings=(rfb.RAW, rfb.DESKTOP_SIZE))

    class Greeting(rfb.Stream):
        async def read(self, size: int, within: float | None) -> bytes:
            return b"RFB 004.000\n"

        async def write(self, data: bytes) -> None:
            raise rfb.RfbError(rfb.CLOSED, "taken")

    async def greeted(**options: Any) -> str:
        try:
            await rfb.Client(Greeting(), **options).handshake()
        except rfb.RfbError as ex:
            return ex.code
        return "on"

    assert asyncio.run(greeted()) == rfb.UNSUPPORTED  # a server that says 4.0 is not spoken to as 3.8 by anybody else's family
    assert asyncio.run(greeted(greeted_as_38=(b"RFB 004.000\n",))) == rfb.CLOSED  # (answered: "RFB 003.008" went out)


def test_the_redirection_digest_is_the_standards_own() -> None:
    # The same sums as WS-Management's Digest (proved there against RFC 2617's example), over POST and /RedirectionService.
    challenge = Challenge(realm="Digest:A3F7C2E1A3F7C2E1A3F7C2E1A3F7C2E1", nonce="2a1f0b3c4d5e6f70", opaque=None, algorithm="MD5", qop=True, stale=False)
    header = answer_to(challenge, 2, "admin", "P@ssw0rd!", "POST", amt.REDIRECTION_URI, cnonce="0123456789abcdef0123456789abcdef")
    said = dict(part.strip().split("=", 1) for part in header.removeprefix("Digest ").split(", "))
    assert said["nc"] == amt.NC
    assert redirection_digest("admin", challenge.realm, "P@ssw0rd!", challenge.nonce, "0123456789abcdef0123456789abcdef") == said["response"].strip('"')


def test_a_sign_in_message_is_texts_with_their_lengths() -> None:
    message = sign_in_message(amt.DIGEST, [b"admin", b"", b"/RedirectionService"])
    assert message[:5] == bytes((0x13, 0, 0, 0, 4)) and int.from_bytes(message[5:9], "little") == len(message) - 9
    assert texts_of(message[9:], 3) == [b"admin", b"", b"/RedirectionService"]
    for cut in (b"", bytes((5,)) + b"adm", bytes((1,)) + b"a" + bytes((9,))):
        with pytest.raises(rfb.RfbError) as refused:
            texts_of(cut, 2)
        assert refused.value.code == rfb.PROTOCOL


# --- what the engine on that port may say -------------------------------------------------------------------------


class Scripted(rfb.Stream):
    """A redirection port that says what a test gives it, in order, and keeps what was said to it."""

    def __init__(self, *answers: bytes) -> None:
        self.held = b"".join(answers)
        self.said: list[bytes] = []

    async def read(self, size: int, within: float | None) -> bytes:
        if len(self.held) < size:
            raise rfb.RfbError(rfb.CLOSED, "the server closed the connection")
        taken, self.held = self.held[:size], self.held[size:]
        return taken

    async def write(self, data: bytes) -> None:
        self.said.append(data)

    async def close(self) -> None:
        pass


STARTED = bytes((0x11, 0, 0, 0, 1, 0, 12, 0, 0, 0, 0, 0, 0))
OFFERED = bytes((0x14, 0, 0, 0, 0)) + (1).to_bytes(4, "little") + bytes((4,))


def challenge_of(realm: bytes = b"Digest:A3F7C2E1A3F7C2E1A3F7C2E1A3F7C2E1", nonce: bytes = b"abc123", qop: bytes = b"auth", status: int = 1, kind: int = 4) -> bytes:
    data = b"".join(bytes((len(text),)) + text for text in (realm, nonce, qop))
    return bytes((0x14, status, 0, 0, kind)) + len(data).to_bytes(4, "little") + data


TAKEN = bytes((0x14, 0, 0, 0, 4, 0, 0, 0, 0))
GOING = bytes((0x41, 0, 0, 0, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("answers", "code", "password_went_out"),
    [
        ((b"HTTP/1.1 400 Bad Request\r\n\r\n",), rfb.PROTOCOL, False),  # not an engine
        ((bytes((0x11, 1, 0, 0)),), rfb.REFUSED, False),  # no session just now (the KVM is off, say)
        ((STARTED, bytes((0x14, 0, 0, 0, 0)) + (2).to_bytes(4, "little") + bytes((1, 3))), rfb.UNSUPPORTED, False),  # no Digest
        ((STARTED, bytes((0x14, 0, 0, 0, 0)) + (2**31).to_bytes(4, "little")), rfb.LIMIT, False),  # an answer two gigabytes long
        ((STARTED, bytes((0x15, 0, 0, 0, 0, 0, 0, 0, 0))), rfb.PROTOCOL, False),  # another message where the answer belongs
        ((STARTED, OFFERED, challenge_of(realm=b'Digest:"; nc=1')), rfb.PROTOCOL, False),  # a realm that could end a quoted text
        ((STARTED, OFFERED, challenge_of(nonce=b"")), rfb.PROTOCOL, False),
        ((STARTED, OFFERED, challenge_of(qop=b"auth-int")), rfb.UNSUPPORTED, False),
        ((STARTED, OFFERED, challenge_of(status=0)), rfb.PROTOCOL, False),  # "yes" before anything of the password went out
        ((STARTED, OFFERED, challenge_of()[:12]), rfb.CLOSED, False),  # cut short
        ((STARTED, OFFERED, challenge_of(), challenge_of()), rfb.AUTH, True),  # asked again: a no
        ((STARTED, OFFERED, challenge_of(), bytes((0x14, 7, 0, 0, 4, 0, 0, 0, 0))), rfb.REFUSED, True),  # neither yes nor no
        ((STARTED, OFFERED, challenge_of()), rfb.CLOSED, True),  # hung up on after the password went out
        ((STARTED, OFFERED, challenge_of(), TAKEN, bytes((0x42,)) + bytes(7)), rfb.PROTOCOL, True),  # the KVM does not begin
        ((STARTED, OFFERED, challenge_of(), TAKEN, bytes((0xF0,)) * 9), rfb.PROTOCOL, True),  # "recorded" for ever
    ],
)
def test_what_an_engine_says_on_its_redirection_port_ends_in_a_named_error(answers: tuple[bytes, ...], code: str, password_went_out: bool) -> None:
    stream = Scripted(*answers)
    told: list[int] = []

    async def run() -> str:
        try:
            await redirect(stream, "admin", "secret", lambda: told.append(len(stream.said)), within=1.0)
        except rfb.RfbError as ex:
            return ex.code
        return "taken"

    assert asyncio.run(run()) == code
    # Nothing made with the password goes out before the engine asked for it, and whoever counts is told before it does.
    assert bool(told) is password_went_out
    if told:
        assert told == [3] and len(stream.said) >= 4  # (the start, the question, the name; then the answer, and what follows it)
    else:
        assert len(stream.said) <= 3  # (nothing made with the password: the start, the question, the name at the most)
    assert not any(b"secret" in sent for sent in stream.said)  # and the password itself never goes out


def test_a_user_name_the_sign_in_cannot_carry_is_sent_nothing() -> None:
    stream = Scripted(STARTED, OFFERED, challenge_of(), TAKEN, GOING)

    async def run() -> str:
        try:
            await redirect(stream, "a" * 256, "secret", lambda: None, within=1.0)
        except rfb.RfbError as ex:
            return ex.code
        return "taken"

    assert asyncio.run(run()) == rfb.UNSUPPORTED and stream.said == []


def test_the_redirection_port_is_known_only_beside_the_engines_own_ports() -> None:
    # 16995 beside 16993, 16994 beside 16992. Beside any other port (a gateway's forwarded one; 443 or 80, where an address
    # was saved without a port) it is not known: what listens at that port and two may be anything, and the Digest sign-in,
    # then the keys, would go to it.
    assert amt.redirection_address("https://192.168.1.60:16993") == ("192.168.1.60", 16995, True)
    assert amt.redirection_address("http://192.168.1.60:16992") == ("192.168.1.60", 16994, False)
    for elsewhere in ("http://192.168.1.60", "https://192.168.1.60", "https://gateway.example:20443", "https://192.168.1.60:65534"):
        with pytest.raises(ValueError):
            amt.redirection_address(elsewhere)
        assert "redirection port" in (amt.redirection_unknown(elsewhere) or "")
    assert amt.redirection_unknown("https://192.168.1.60:16993") is None

    async def run() -> str | None:
        screen = amt.AmtScreen(DeviceSpec("x", "x", "https://127.0.0.1:65535", "admin", "secret", kind="amt"))
        screen._session = vncdevice._Session()
        try:
            with pytest.raises(KvmError):
                await screen._open()
            return screen.refused_now()
        finally:
            await screen.close()

    said = asyncio.run(run())
    assert said is not None and "this tile reaches the engine at port 65535" in said


def test_an_engine_behind_a_port_of_its_own_shows_no_screen_and_says_why(tmp_path: Path) -> None:
    # An engine reached at a port beside which its redirection port is not known (a stand-in that does not tell the program
    # where its own is): its state and power buttons are there, its screen is not, the tile says plainly why, and nothing
    # goes to what listens at that port and two.
    pc = FakeAmt(beside=False).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            status = status_of(client, device, state="online")
            assert status["screen"] is False and "screen" not in status["can"] and "power" in status["can"]
            assert f"this tile reaches the engine at port {pc.port}" in status["server"]["no_screen"]
            for _ in range(5):
                shown = client.get(snap(device))
                assert shown.status_code == 404 and "redirection port" in shown.json()["message"]
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_off"}).status_code == 200
            assert pc.state.redirections == 0 and pc.state.actions == [12]
    finally:
        pc.stop()


def test_a_session_that_is_recorded_begins_all_the_same() -> None:
    stream = Scripted(STARTED, OFFERED, challenge_of(), TAKEN, bytes((0xF0,)) + GOING)

    async def run() -> None:
        await redirect(stream, "admin", "secret", lambda: None, within=1.0)

    asyncio.run(run())
    assert stream.said[-1] == amt.KVM_GO and stream.held == b""


# --- what decides whether a session is opened at all -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("control", "consent", "said"),
    [
        (1, False, "Needs the code shown on the PC for every session: in client control mode"),  # consent is mandatory there
        (2, True, "Needs the code shown on the PC for every session, which a wall cannot type"),
    ],
)
def test_no_session_is_opened_where_the_pc_would_ask_for_its_code(tmp_path: Path, pc: FakeAmt, control: int, consent: bool, said: str) -> None:
    pc.state.control, pc.state.consent = control, consent
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status = status_of(client, device, state="online")
        assert status["screen"] is False and status["server"]["no_screen"].startswith(said)
        assert [word for word in status["can"] if word in ("screen", "keys", "text", "live", "control")] == []
        refused = client.get(snap(device))
        assert (refused.status_code, refused.json()["code"]) == (404, "no_picture") and refused.json()["message"].startswith(said)
        assert client.post(f"/api/v1/devices/{device}/live").status_code == 404  # no live line either
        typed = client.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "hello"})
        assert (typed.status_code, typed.json()["code"]) == (404, "no_picture")
        time.sleep(0.3)
        assert pc.state.redirections == 0  # not even to find out: a code would appear on the PC's screen for nothing


def test_how_the_kvm_is_set_up_is_read_at_most_every_300_s(pc: FakeAmt) -> None:
    # The owner's standard (2026-10-18), where consent was read again every 60 s. The engine enforces consent itself, so the
    # only cost of reading it less often is one refused try.
    assert amt.KVM_TTL == kvm.STANDARD_HOLD == 300.0

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            at = device._kvm_at
            assert device._kvm  # read at the look
            await device._read_kvm()  # within KVM_TTL: the cached one, not read again
            assert device._kvm_at == at
        finally:
            await device.close()

    asyncio.run(run())


def test_a_pc_that_is_off_shows_no_screen_and_is_not_asked_for_one(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.power = 8
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status = status_of(client, device, state="no_signal")
        assert status["screen"] is False and status["server"]["no_screen"] is None
        refused = client.get(snap(device))
        assert (refused.status_code, refused.json()["code"], refused.json()["message"]) == (404, "no_picture", "The PC is off")
        assert pc.state.redirections == 0


def test_a_kvm_switched_off_on_the_engine_is_switched_on_only_when_an_admin_asks(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt, "KVM_TTL", 0)  # (read again at every look, so that the change is seen at once)
    pc.state.kvm, pc.state.listener = "disabled", False  # as an engine set up by hand comes
    with wall(tmp_path) as admin:
        device = admin.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status = status_of(admin, device, state="online")
        assert status["screen"] is False and status["server"]["no_screen"].startswith("Its KVM is switched off on its management engine. An admin can switch it on")
        assert (status["server"]["amt"]["kvm"], status["server"]["amt"]["listener"]) == ("disabled", False)
        time.sleep(0.3)
        assert pc.state.changes == [] and pc.state.redirections == 0  # a look changes nothing on the PC
        # An operator may press its buttons, and not change how it is set up.
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "a password for olga"}).status_code == 201
        olga = TestClient(admin.app, headers=CSRF, client=("127.0.0.1", 50091))
        olga.portal = admin.portal  # type: ignore[attr-defined]
        assert olga.post("/api/v1/login", json={"name": "olga", "password": "a password for olga"}).status_code == 200
        assert olga.post(f"/api/v1/devices/{device}/kvm", json={"on": True}).status_code == 403
        assert pc.state.changes == []
        # An admin asks: the KVM's access point on, then the redirection listener on, as Intel's reference has it.
        assert admin.post(f"/api/v1/devices/{device}/kvm", json={"on": True}).status_code == 200
        assert pc.state.changes == [("CIM_KVMRedirectionSAP", "2"), ("AMT_RedirectionService", "ListenerEnabled=true")]
        status = status_of(admin, device, screen=True)
        assert status["server"]["no_screen"] is None and (status["server"]["amt"]["kvm"], status["server"]["amt"]["listener"]) == ("enabled", True)
        wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture after the KVM was switched on", 15)
        # And off again: the access point only (the listener serves the serial console and storage too).
        assert admin.post(f"/api/v1/devices/{device}/kvm", json={"on": False}).status_code == 200
        assert pc.state.changes[2:] == [("CIM_KVMRedirectionSAP", "3")]
        status_of(admin, device, screen=False)
        written = [(e["event"], e.get("on")) for e in admin.get("/api/v1/audit").json()["entries"] if e["event"].startswith("kvm_")]
        assert written[::-1] == [("kvm_switched", True), ("kvm_switched", False)]


def test_a_switch_that_was_half_done_says_what_was_done_and_is_written_down(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.kvm, pc.state.listener, pc.state.put_fails = "disabled", False, True
    with wall(tmp_path) as admin:
        device = admin.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(admin, device, state="online")
        refused = admin.post(f"/api/v1/devices/{device}/kvm", json={"on": True})
        assert refused.status_code == 502 and refused.json()["message"].startswith("Its KVM was switched on on the engine, and its redirection listener was not:")
        assert pc.state.changes == [("CIM_KVMRedirectionSAP", "2")]
        failed = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "kvm_switch_failed"]
        assert len(failed) == 1 and failed[0]["error"].startswith("Its KVM was switched on on the engine")


def test_a_kvm_switched_off_in_the_mebx_is_not_switched_on_from_the_network(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.kvm = "mebx"
    with wall(tmp_path) as admin:
        device = admin.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status = status_of(admin, device, state="online")
        assert status["server"]["no_screen"].startswith("Its KVM is switched off in the PC's MEBx")
        refused = admin.post(f"/api/v1/devices/{device}/kvm", json={"on": True})
        assert (refused.status_code, refused.json()["code"]) == (422, "invalid") and "MEBx" in refused.json()["message"]
        assert pc.state.changes == []
        failed = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "kvm_switch_failed"]
        assert len(failed) == 1 and failed[0]["on"] is True


# --- the pace a wall needs ----------------------------------------------------------------------------------------


def test_a_shown_tile_takes_a_still_now_and_then_and_a_live_view_holds_a_session(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The owner's decision of 2026-10-18, where a shown tile held a session the whole while it was watched.) A tile that is
    # only shown on the wall gets a still every STILL_EVERY, each a short session that closes (Intel's border on the PC's
    # monitor only for that); between them the cached still is handed out. A live view (enlarged, or its live line) holds a
    # session open and draws at a viewer's pace.
    monkeypatch.setattr(amt.AmtScreen, "STILL_EVERY", 1.0)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            first = await picture_of(device)
            # One short session, closed once the still was taken: the border is on the PC only for that.
            assert first.still is True and pc.state.kvm_sessions == 1
            deadline = time.monotonic() + 3
            while pc.state.redirection_open:
                assert time.monotonic() < deadline, "the still session was held open"
                await asyncio.sleep(0.02)
            for _ in range(10):  # a tile shown for half a second: the cached still, no new session
                assert (await device.snapshot(640)).still is True
                await asyncio.sleep(0.05)
            assert pc.state.kvm_sessions == 1 and device._screen._failures == 0
            # STILL_EVERY on: the next look takes a fresh still, another short session, and closes it again.
            await asyncio.sleep(1.0)
            await device.snapshot(640)  # (due: kicks a fresh still in the background, the cached one shown meanwhile)
            deadline = time.monotonic() + 5
            while pc.state.kvm_sessions < 2 or pc.state.redirection_open:
                assert time.monotonic() < deadline, f"{pc.state.kvm_sessions} sessions, {pc.state.redirection_open} open"
                await asyncio.sleep(0.05)
            # A live view holds one session open, asked for what changed at a viewer's pace.
            async with kept_live(device):
                await live_picture(device)
                held, asked = pc.state.kvm_sessions, len(pc.state.screen.requests)
                pc.state.screen.dirty.append((0, 0, 16, 16))
                await asyncio.sleep(0.3)
                assert len(pc.state.screen.requests) > asked  # (asked again, and again, on the one held session)
                assert pc.state.redirection_open == 1 and pc.state.kvm_sessions == held
        finally:
            await device.close()

    asyncio.run(run())
    wait_until(lambda: pc.state.redirection_open == 0, "the session outlived the tile")


def test_the_still_cadence_is_the_owners_standard() -> None:
    # One constant (the owner's standard of 2026-10-18), where a tile held a session the whole while it was watched.
    assert amt.STILL_EVERY == amt.AmtScreen.STILL_EVERY == kvm.STANDARD_HOLD == 300.0


def test_a_shown_tiles_picture_is_a_still_with_its_age(tmp_path: Path, pc: FakeAmt) -> None:
    # The snapshot route says a still's age so the tile can show it; and a tile that is only shown opens no held session
    # (one short session for the still, then closed), where before it held one the whole while it was watched.
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        reply = None

        def came() -> bool:
            nonlocal reply
            reply = client.get(snap(device))
            return reply.status_code == 200

        wait_until(came, "no first still", 15)
        assert reply is not None and reply.headers.get("X-KVM-Still") == "1" and int(reply.headers["X-KVM-Age"]) >= 0
        for _ in range(15):  # shown for the better part of a second: the cached still, no second session
            assert client.get(snap(device)).headers.get("X-KVM-Still") == "1"
            time.sleep(0.05)
        wait_until(lambda: pc.state.redirection_open == 0, "the still session was held open", 5)
        assert pc.state.kvm_sessions == 1


def test_power_on_opens_a_session_first_only_when_the_live_view_is_open(pc: FakeAmt) -> None:
    # W11b's open question 1, the owner's answer of 2026-10-18: a session opened before Power on shows the BIOS from the
    # start, but only where the large or live view is open. Otherwise the press does not wait on one (nobody is watching).
    pc.state.power = 8  # off

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            # Not live: the press opens no session.
            await device.act("power_on")
            assert pc.state.redirections == 0 and pc.state.actions == [2]
            pc.state.power = 8
            device._power_on = False
            await device._refresh_status()
            # The live view is open: a session is opened first, so its BIOS shows from the start.
            device._screen.live_seen()
            await device.act("power_on")
            assert pc.state.redirections >= 1 and pc.state.kvm_sessions >= 1 and pc.state.actions == [2, 2]
        finally:
            await device.close()

    asyncio.run(run())


def test_power_on_opens_no_session_first_where_the_screen_is_not_to_be_shown(pc: FakeAmt) -> None:
    # Even with the live view open: where consent or the KVM's setup would stop a session (a code would appear on the PC's
    # screen for nothing), none is opened before the press.
    pc.state.power, pc.state.consent = 8, True  # off, and user consent on

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            device._screen.live_seen()
            await device.act("power_on")
            assert pc.state.redirections == 0 and pc.state.actions == [2]
        finally:
            await device.close()

    asyncio.run(run())


def test_start_into_bios_setup_arms_it_and_resets_or_powers_on(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            status = await settled_status(device, "online")
            assert "bios_setup" in status["can"]  # the engine says it can start into the BIOS setup
            # On: arm the BIOS setup boot, make it the next one, then reset (RESET is not barred by a session).
            await device.act("bios_setup")
            assert ("AMT_BootSettingData", "BIOSSetup=true") in pc.state.changes
            assert ("CIM_BootService", "Role=1") in pc.state.changes
            assert amt.RESET in pc.state.actions
            assert pc.state.bios_setup_armed is False  # a single-use boot: cleared on the reset
            # Off: arm, then switch on.
            pc.state.power = amt.OFF
            device._power_on = False
            await device._refresh_status()
            pc.state.changes.clear()
            pc.state.actions.clear()
            await device.act("bios_setup")
            assert ("AMT_BootSettingData", "BIOSSetup=true") in pc.state.changes and ("CIM_BootService", "Role=1") in pc.state.changes
            assert pc.state.actions == [amt.ON]
        finally:
            await device.close()

    asyncio.run(run())


def test_the_boot_put_carries_every_property_the_engine_reported(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real AMT 16 engine refused a Put of AMT_BootSettingData that left out EnforceSecureBoot, PlatformErase, SecureErase
    # and UefiBootNumberOfParams (a first version of mine sent a smaller set): the stand-in refuses it now as well, and the
    # driver sends every property the engine reported. With the smaller set, nothing is armed and nothing pressed.
    full = amt.BOOT_PUT_PROPERTIES
    smaller = tuple(key for key in full if key not in ("EnforceSecureBoot", "PlatformErase", "SecureErase", "UefiBootNumberOfParams"))

    async def run(properties: tuple[str, ...]) -> str:
        monkeypatch.setattr(amt, "BOOT_PUT_PROPERTIES", properties)
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            try:
                await device.act("bios_setup")
            except KvmError as ex:
                return ex.message
            return "done"
        finally:
            await device.close()

    said = asyncio.run(run(smaller))
    assert "schema" in said and pc.state.actions == [] and pc.state.bios_setup_armed is False
    assert asyncio.run(run(full)) == "done" and pc.state.actions == [amt.RESET]


def test_start_into_bios_setup_refuses_where_a_destructive_boot_is_already_armed(pc: FakeAmt) -> None:
    # Another tool is in the middle of arming a secure erase: qKVM does not clear it nor carry it out. Nothing is sent.
    pc.state.secure_erase_armed = True

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert refused.value.code == "action_failed" and "SecureErase" in refused.value.message
            assert pc.state.changes == [] and pc.state.actions == [] and pc.state.secure_erase_armed is True
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_whose_power_change_is_refused_clears_the_boot_again(pc: FakeAmt) -> None:
    # The boot is armed, then the power change is refused for certain (not a lost answer): qKVM clears the boot again, so no
    # ordinary boot lands in the setup, and says so.
    pc.state.returns = 5  # (the power command is answered "invalid parameter": a definite refusal)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "cleared again" in refused.value.message
            armed = [v for c, v in pc.state.changes if c == "AMT_BootSettingData"]
            assert armed == ["BIOSSetup=true", "BIOSSetup=false"] and pc.state.bios_setup_armed is False
        finally:
            await device.close()

    asyncio.run(run())


def test_a_refused_power_change_whose_clearing_fails_is_a_maybe(tmp_path: Path, pc: FakeAmt) -> None:
    # (The eighth review's 1.) The power change is refused for certain, and the clearing is refused too: the boot may be armed,
    # so the answer is a "maybe" (504 timeout, which the route's history keeps as "not known"), not the refusal's 502.
    pc.state.returns, pc.state.boot_clear_fails = 5, True
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "could not be cleared" in reply.json()["message"]
        assert pc.state.bios_setup_armed is True


def test_a_bios_setup_whose_role_is_refused_clears_the_boot_again(pc: FakeAmt) -> None:
    # Armed, and then the engine refuses to make it the next boot: no power change goes out, and the boot is cleared again.
    pc.state.role_returns = 2

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "cleared again" in refused.value.message and pc.state.actions == []
            assert pc.state.bios_setup_armed is False
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_whose_power_answer_cannot_be_read_leaves_the_boot_and_says_so(pc: FakeAmt) -> None:
    # The power command was taken (the PC restarted) and its answer could not be read: the boot is not cleared (it may be what
    # the PC is starting into now), and the answer says that it may have gone through, never "nothing was done".
    pc.state.power_answer_empty = True

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as unsure:
                await device.act("bios_setup")
            assert unsure.value.code == "timeout" and "may or may not" in unsure.value.message
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true"]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_whose_power_command_is_answered_with_a_fault_clears_the_boot_again(pc: FakeAmt) -> None:
    # A SOAP fault is the engine's no: the command was not taken. The boot is cleared again, as for any refusal; only an answer
    # that was lost or could not be read leaves it armed.
    pc.state.odd["CIM_PowerManagementService"] = "fault"

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "cleared again" in refused.value.message
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true", "BIOSSetup=false"]
            assert pc.state.bios_setup_armed is False
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_whose_arming_answer_cannot_be_read_clears_it_again(pc: FakeAmt) -> None:
    # (The fourth review's 1.) The Put went out and was taken, and its answer was no SOAP: it may have been armed, so it is
    # cleared again, not left with "nothing was armed".
    pc.state.boot_put_odd_once = "html"

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "cleared again" in refused.value.message and pc.state.actions == []
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true", "BIOSSetup=false"]
            assert pc.state.bios_setup_armed is False
        finally:
            await device.close()

    asyncio.run(run())


def test_clearing_the_setup_boot_does_not_write_over_an_erase_armed_meanwhile(pc: FakeAmt) -> None:
    # (The fourth review's 4.) The role is refused, and meanwhile another tool armed a secure erase: the clearing Put would
    # write every option, that one too, so it is not sent, and the answer says why.
    pc.state.role_returns, pc.state.erase_armed_meanwhile = 2, True

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "SecureErase" in refused.value.message and "not cleared" in refused.value.message
            assert (refused.value.code, refused.value.status) == ("timeout", 504)  # (the eighth review's 1: it may be armed)
            assert pc.state.secure_erase_armed is True and pc.state.actions == []
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true"]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_setup_boot_armed_before_the_press_is_left_as_it_was(pc: FakeAmt) -> None:
    # (The fifth review's L2.) Armed already before the press (an earlier press, not booted since): a press whose power
    # change is refused leaves it as it found it, and says so, not "nothing was done" over a clearing of it.
    pc.state.bios_setup_armed, pc.state.returns = True, 5

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "armed already before this press" in refused.value.message
            assert "made it the next boot" in refused.value.message  # (the sixth review's L3: the role did go through)
            assert pc.state.bios_setup_armed is True
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true"]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_setup_boot_armed_before_whose_role_answer_is_lost_may_be_the_next_boot(pc: FakeAmt) -> None:
    # (The seventh review's 6.) Armed before the press; the role's answer cannot be read: the role may have made it the next
    # boot. Left so, and said as a "maybe", not as "nothing was done".
    pc.state.bios_setup_armed = True
    pc.state.odd["CIM_BootService"] = "html"

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            with pytest.raises(KvmError) as unsure:
                await device.act("bios_setup")
            assert unsure.value.code == "timeout" and "may have made it the next boot" in unsure.value.message
            assert pc.state.bios_setup_armed is True and pc.state.actions == []
        finally:
            await device.close()

    asyncio.run(run())


def test_a_stop_while_the_boot_is_being_cleared_is_logged(pc: FakeAmt) -> None:
    # (The fifth review's L1.) qKVM stopped while the boot is being cleared again (the role was refused): nothing is awaited,
    # and the log says what may be left on the PC.
    pc.state.role_returns = 2

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            clearing = asyncio.Event()

            async def slow_clearing(armed_before: bool) -> str | None:
                clearing.set()
                await asyncio.sleep(10)
                return None

            device._clear_bios_setup = slow_clearing  # type: ignore[method-assign]
            pressing = asyncio.create_task(device.act("bios_setup"))
            await asyncio.wait_for(clearing.wait(), 10)
            pressing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pressing
        finally:
            await device.close()

    heard: list[str] = []
    listener = logging.Handler(logging.WARNING)
    listener.emit = lambda record: heard.append(record.getMessage())  # type: ignore[method-assign]
    logging.getLogger("qkvm").addHandler(listener)  # (heard on qKVM's own logger, whatever an earlier test set up)
    try:
        asyncio.run(run())
    finally:
        logging.getLogger("qkvm").removeHandler(listener)
    assert any("may be armed for the next boot" in line for line in heard), heard


def test_a_pc_between_power_states_is_not_started_into_its_setup(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            pc.state.power = 5  # a power cycle under way: neither "switch on" nor "reset" is sure to be right
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert "changing its state" in refused.value.message
            assert pc.state.changes == [] and pc.state.actions == []
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_whose_switching_on_is_not_seen_says_the_boot_stays_armed(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Taken, and the PC not seen to come on: it may still start into its setup later, so the boot is left armed, and said.
    monkeypatch.setattr(amt, "CONFIRM_WITHIN", 0.5)
    monkeypatch.setattr(amt, "CONFIRM_EVERY", 0.05)
    pc.state.power, pc.state.drops = amt.OFF, [amt.ON]

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "no_signal")
            with pytest.raises(KvmError) as unsure:
                await device.act("bios_setup")
            assert "still off" in unsure.value.message and "stays armed" in unsure.value.message
            assert pc.state.bios_setup_armed is True and pc.state.actions == [amt.ON]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_power_on_sent_from_the_large_view_opens_a_session_first_for_a_pc_that_is_off(tmp_path: Path, pc: FakeAmt) -> None:
    # The page sends `watching` from the PC's large view (its own feed of pictures asks nothing of a PC that is off): the
    # server opens a session before switching it on, so the start shows from the first moment. Without it, none.
    pc.state.power = amt.OFF
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, state="no_signal")
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
        assert pc.state.redirections == 0
        pc.state.power = amt.OFF
        status_of(client, device, state="no_signal")
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on", "watching": True}).status_code == 200
        assert pc.state.redirections >= 1 and pc.state.actions == [amt.ON, amt.ON]


def test_a_bulk_run_is_watching_nothing(tmp_path: Path, pc: FakeAmt) -> None:
    # An entry of a bulk run comes from the selection, not from a large view: one that carries `watching` all the same opens
    # no session before switching on (forty PCs started at once are not forty sessions, with Intel's border on each).
    pc.state.power = amt.OFF
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, state="no_signal")
        sent = {"action": "power_on", "watching": True, "batch": "a-run"}
        assert client.post(f"/api/v1/devices/{device}/actions", json=sent).status_code == 200
        assert pc.state.redirections == 0 and pc.state.actions == [amt.ON]


def test_a_still_taken_while_a_session_is_open_for_keys_leaves_it_open(pc: FakeAmt) -> None:
    # Keys from the tile's menu hold their session a while after the last key; a still due meanwhile uses that session for
    # its picture and does not close it under them.
    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            await device.act("keys", keys="KeyQ")  # (and a still is wanted after keys)
            assert pc.state.kvm_sessions == 1 and device._screen._connected_or_none() is not None
            with contextlib.suppress(KvmError):
                await device.snapshot(640)  # (a still in the background, on the open session)
            if device._screen._taking is not None:
                await asyncio.wait({device._screen._taking}, timeout=10)
            assert device._screen._still is not None  # (taken)
            assert pc.state.kvm_sessions == 1 and device._screen._connected_or_none() is not None  # (and the session left open)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_still_leaves_a_session_that_keys_are_opening_to_them(pc: FakeAmt) -> None:
    # (The fourth review's 8, on the third's L7.) A still due while keys from the menu are still opening their session takes
    # that session's picture and does not close it under them: one session, open after.
    pc.state.challenge_takes = 0.6  # (an engine slow to open a session)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            pressing = asyncio.create_task(device.act("keys", keys="KeyQ"))
            deadline = time.monotonic() + 5
            while device._screen._session is None:  # (the keys' session, being opened)
                assert time.monotonic() < deadline
                await asyncio.sleep(0.01)
            assert not device._screen._session.done.is_set()
            with contextlib.suppress(KvmError):
                await device.snapshot(640)  # a still due (none yet), in the background
            if device._screen._taking is not None:
                await asyncio.wait({device._screen._taking}, timeout=10)
            await pressing
            assert device._screen._still is not None
            assert pc.state.kvm_sessions == 1 and device._screen._connected_or_none() is not None
        finally:
            await device.close()

    asyncio.run(run())


def test_a_still_ends_a_run_of_failures(pc: FakeAmt) -> None:
    # (The fourth review's 8, on the third's L4.) A picture from a session that is still up says the port is well again: the
    # run of failures before it is over, and the next outage is logged as a new one.
    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            device._screen._failures = 2  # (two sessions that failed before, as the port counted them)
            await picture_of(device)
            assert device._screen._failures == 0
        finally:
            await device.close()

    asyncio.run(run())


def test_the_large_view_holds_a_session_for_an_off_pc_so_a_start_can_show_at_once(pc: FakeAmt) -> None:
    # A "big" (enlarged) snapshot of an off PC shows the "Off" panel, but records that the large view is open, so a session
    # is opened before Power on to show the start from the first moment (W11b's finding, the off-PC case the page relies on).
    pc.state.power = amt.OFF

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "no_signal")
            with pytest.raises(KvmError):  # (the picture is not had: the PC is off)
                await device.snapshot(640, big=True)
            assert device._screen._is_live() is True  # (but the large view is noted: a session will be opened before the press)
            await device.act("power_on")
            assert pc.state.redirections >= 1 and pc.state.actions == [amt.ON]  # a session was opened before switching on
        finally:
            await device.close()

    asyncio.run(run())


def test_an_engine_that_cannot_start_into_the_bios_setup_is_not_offered_it(pc: FakeAmt) -> None:
    pc.state.boot_setup_supported = False

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            status = await settled_status(device, "online")
            assert "bios_setup" not in status["can"]
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert refused.value.code == "invalid" and pc.state.changes == [] and pc.state.actions == []
        finally:
            await device.close()

    asyncio.run(run())


def test_start_into_bios_setup_is_sent_to_no_other_pc(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        device.spec.machine = "amt:" + "d" * 32  # a PlatformGUID that is not this engine's: another PC answers here
        try:
            await device.status()
            with pytest.raises(KvmError) as refused:
                await device.act("bios_setup")
            assert refused.value.code == "another_machine"
            assert pc.state.changes == [] and pc.state.actions == []  # nothing armed, nothing pressed
        finally:
            await device.close()

    asyncio.run(run())


def test_a_look_that_sees_the_pc_come_on_asks_for_a_still(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        try:
            device._power_on = False  # the last look found it off
            assert device._screen._refresh_still is False
            device._saw_power(amt.ON)  # a look sees it on now
            assert device._screen._refresh_still is True
        finally:
            await device.close()

    asyncio.run(run())


def test_a_power_change_makes_the_shown_tile_take_a_fresh_still(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt.AmtScreen, "STILL_EVERY", 1000.0)  # (so only a power change, not the clock, brings the next one)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)  # the first still
            deadline = time.monotonic() + 3
            while pc.state.redirection_open:
                assert time.monotonic() < deadline
                await asyncio.sleep(0.02)
            for _ in range(10):  # not due again for a long time: the cached still, no new session
                await device.snapshot(640)
                await asyncio.sleep(0.03)
            assert pc.state.kvm_sessions == 1
            device._screen.want_still()  # a power change was seen
            await device.snapshot(640)
            deadline = time.monotonic() + 5
            while pc.state.kvm_sessions < 2 or pc.state.redirection_open:
                assert time.monotonic() < deadline, f"{pc.state.kvm_sessions} sessions"
                await asyncio.sleep(0.03)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_session_the_engine_ends_at_its_time_is_opened_again_and_the_tile_keeps_its_picture(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real engine with SessionTimeout 3 ended every session at 181 s, asked for a picture every second all the while. (Here
    # each session ends right after its first picture, as the engine's time for it: they ended 0.8 s after the stand-in's own
    # RFB began, which on a loaded machine was inside the wall's handshake, and no picture came at all. And the tile is looked
    # at until three more sessions came, not for four seconds.)
    # (Driven as the enlarged view does, which holds a session: a tile that is only shown takes a still now and then instead.)
    pc.state.session_timeout, pc.state.sessions_end_after_requests = 1, 3  # (one minute, said; a picture, done)
    monkeypatch.setattr(amt, "TIMEOUT_SLACK", 60.0)  # (whenever it ends, it is an end at its time)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            assert device._screen.timeout_minutes == 1
            await live_picture(device)
            seen: list[Any] = []
            deadline = time.monotonic() + 60  # (a bound for a slow machine: the loop ends as soon as three more sessions came)
            while pc.state.kvm_sessions < 4:
                assert time.monotonic() < deadline, f"{pc.state.kvm_sessions} sessions: {seen[-5:]}"
                device._screen.live_seen()
                try:
                    seen.append(("ok", (await device.snapshot(640)).still))
                except KvmError as ex:
                    seen.append(("no", ex.code))
                await asyncio.sleep(0.05)
            # Never "dropped": the last picture stays (BRIDGE) while the next session opens (or, at the most, "connecting").
            assert {code for kind, code in seen if kind == "no"} <= {"no_stream"}, seen
            assert sum(1 for kind, _ in seen if kind == "ok") >= len(seen) * 0.7
        finally:
            await device.close()

    asyncio.run(run())


def test_sessions_that_end_soon_after_their_first_picture_are_asked_less_and_less(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # A redirection port that takes the password, gives a picture and hangs up, every time: a sign-in, and log lines, each
    # round. The pause before the next grows (a picture is no proof that it is well again; a session that lasted is).
    # (Waited for until three have failed, and the pauses read from the stand-in's own times of each connection: three
    # rounds, their handshakes and pauses of one and two seconds were to fit into six seconds, which a loaded machine missed.)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)
    pc.state.session_lasts = 0.3  # (and no SessionTimeout said: these are no ends at the engine's own time)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            deadline = time.monotonic() + 60  # (a bound for a slow machine: the loop ends as soon as three have failed)
            while device._screen._failures < 3:  # (driven as the live view does, which keeps a session; a shown tile takes a still)
                assert time.monotonic() < deadline, f"the sessions failed {device._screen._failures} times"
                device._screen.live_seen()
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
        finally:
            await device.close()

    asyncio.run(run())
    began = pc.state.redirected_at
    # Each session ended 0.3 s after it began at the earliest, and the next was asked for no sooner than the pause after that
    # end: one second after the first failure, two after the second (ERROR_HOLD, doubling). A machine that is slow makes the
    # pauses longer, never shorter.
    assert len(began) == pc.state.redirection_logins == 3, (began, pc.state.redirection_logins)
    assert began[1] - began[0] >= 1.0 and began[2] - began[1] >= 2.0, [round(b - a, 2) for a, b in itertools.pairwise(began)]


def test_a_session_that_ends_before_its_time_is_a_failure_said_as_one(pc: FakeAmt) -> None:
    # Three minutes said, and the session over right after its first picture: something is wrong. (Ended 0.5 s after the
    # stand-in's own RFB began, it ended inside the wall's handshake on a loaded machine, and no picture came.)
    pc.state.session_timeout, pc.state.sessions_end_after_requests = 3, 3

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            deadline = time.monotonic() + 10
            while not device._screen._failures:  # (driven live, which holds a session; a shown tile takes a still)
                assert time.monotonic() < deadline, "an end before its time was not taken for a failure"
                device._screen.live_seen()
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert time.monotonic() - device._screen._ran_out_at > 5
        finally:
            await device.close()

    asyncio.run(run())


# --- an engine that answers wrongly on that port ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("odd", "said"),
    [
        ("not_redirection", "not Intel AMT's redirection service"),
        ("wrong_end", "where the KVM begins"),
        ("not_rfb", "its greeting is not RFB"),
        ("huge_answer", "which no such answer is"),
    ],
)
def test_a_handshake_that_goes_wrong_is_said_on_the_tile_and_not_tried_at_every_look(tmp_path: Path, pc: FakeAmt, odd: str, said: str) -> None:
    pc.state.redirect_odd = odd
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        seen = looked_at_once_it_came(client, device, lambda: pc.state.redirections >= 1, 1.5)
        assert all(status_code != 200 for status_code, _ in seen)
        assert pc.state.redirections == 1  # left alone for a while after it, not asked at every look
        status = status_of(client, device, state="online", screen=False)  # the PC itself is as it was
        assert said in status["server"]["no_screen"], status["server"]["no_screen"]
        # Whatever went wrong there, it was no verdict on the password.
        assert REJECTED.times(REJECTED.what("login", DeviceSpec("x", "x", pc.url, "admin", "secret"))) == 0


def test_a_kvm_that_another_viewer_has_is_said_so_and_asked_again_later(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.start_status = 2  # (what a real engine answered while another viewer had its KVM)
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        looked_at_once_it_came(client, device, lambda: pc.state.redirections >= 1, 1.0)
        assert pc.state.redirections == 1 and pc.state.redirection_logins == 0  # not asked at every look; and no password sent
        status = status_of(client, device, state="online", screen=False)
        assert status["server"]["no_screen"] == "The PC's screen is not shown: another viewer has its KVM: the engine gives one session at a time"


def test_rfb_that_asks_for_vnc_authentication_after_the_handshake_is_sent_nothing_of_the_password(tmp_path: Path, pc: FakeAmt) -> None:
    # Intel's handshake has taken the password; what speaks RFB after it asks for VNC authentication. Its DES answer, keyed
    # on the password's first eight bytes, is far more than the Digest hands out: nothing is sent, and no verdict counted.
    pc.state.screen.password, pc.state.screen.offers = "another", (2,)
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        looked_at_once_it_came(client, device, lambda: pc.state.redirection_logins >= 1, 1.0)
        assert (pc.state.redirection_logins, pc.state.screen.password_tries) == (1, 0)
        assert REJECTED.times(REJECTED.what("login", DeviceSpec("x", "x", pc.url, "admin", "secret"))) == 0
        status = status_of(client, device, state="online", screen=False)
        assert "a way of signing in this program does not speak (type 2)" in status["server"]["no_screen"]


@pytest.mark.parametrize("odd", ["hang_up", "neither"])
def test_a_sign_in_on_that_port_that_comes_to_nothing_is_not_sent_again_at_every_look(tmp_path: Path, pc: FakeAmt, odd: str) -> None:
    pc.state.redirect_odd = odd
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        looked_at_once_it_came(client, device, lambda: pc.state.redirection_logins >= 1, 1.5)
        assert pc.state.redirection_logins == 1  # (held back ten seconds, then twice as long each time: Rejected.unanswered)
        offered = REJECTED.what("login", DeviceSpec("x", "x", pc.url, "admin", "secret"))
        assert REJECTED.times(offered) == 0 and REJECTED.silent(offered) >= 1


def test_a_password_the_redirection_port_refuses_is_a_no_and_is_offered_less_and_less(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.redirection_password = "another"
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        looked_at_once_it_came(client, device, lambda: pc.state.redirection_rejections >= 1, 1.5)
        assert (pc.state.redirection_logins, pc.state.redirection_rejections) == (1, 1)  # a minute before the next, then five
        assert REJECTED.times(REJECTED.what("login", DeviceSpec("x", "x", pc.url, "admin", "secret"))) == 1
        status = status_of(client, device, screen=False)
        assert status["server"]["no_screen"].startswith("Its redirection port does not take the saved password")


def test_a_no_heard_on_the_other_port_while_the_challenge_comes_stops_the_answer(pc: FakeAmt) -> None:
    # The redirection port's sign-in was begun with no no standing; meanwhile WS-Management heard one for the same password.
    # The answer made with the password is not sent: asked again the moment before it would go out.
    pc.state.redirect_odd = "slow_challenge"

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            device._screen._looking()
            device._screen._start(urgent=True)
            await asyncio.sleep(0.4)  # (the handshake has begun: the engine is taking its time over the challenge)
            REJECTED.said_no(REJECTED.what("login", device.spec))
            await asyncio.sleep(1.5)
        finally:
            await device.close()

    asyncio.run(run())
    assert pc.state.redirection_logins == 0 and REJECTED.times(REJECTED.what("login", DeviceSpec("x", "x", pc.url, "admin", "secret"))) == 1


def test_a_handshake_that_stalls_ends_in_time(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt, "REDIRECTION_WITHIN", 1.0)
    pc.state.redirect_odd = "stall"

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            began = time.monotonic()
            with pytest.raises(KvmError):  # (the still is not shown; it is taken in the background)
                await device.snapshot(640)
            while pc.state.redirections == 0:  # (the background still attempts a session)
                assert time.monotonic() - began < 5, "no still was attempted"
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.1)
            assert device._screen._taking is not None
            await asyncio.wait({device._screen._taking}, timeout=5)  # the stalled handshake ends in time, not a hang
            assert device._screen._taking.done() and time.monotonic() - began < 8
        finally:
            await device.close()

    asyncio.run(run())


# --- keys, text and the pointer through the KVM -----------------------------------------------------------------------


def test_a_pc_that_is_starting_is_said_to_be_so_where_its_engine_opens_no_session(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # While a real PC started, its engine answered no new KVM session in time for the first half-minute (every try timed out,
    # and some of its WS-Management answers too), and the tile said "Its redirection port: Device did not respond in time",
    # as of a port that is broken. It says that the PC is starting. (Looked at from the large view, which tries again at the
    # port's own pace: a tile that is only shown asks for a still, and after one that came to nothing waits STILL_RETRY
    # seconds and more before the next.)
    monkeypatch.setattr(amt, "REDIRECTION_WITHIN", 0.3)
    pc.state.power, pc.state.starting_for = 8, 20.0
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, state="no_signal")
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
        said = ""
        deadline = time.monotonic() + 10
        while not said and time.monotonic() < deadline:  # (looked at as the large view does, and the status read meanwhile)
            client.get(snap(device) + "?big=1")
            said = client.get("/api/v1/status").json()[device]["server"]["no_screen"] or ""
            time.sleep(0.05)
        assert said == "The PC is starting, and its engine is too busy for a KVM session meanwhile"
        assert pc.state.kvm_sessions == 0


def test_a_shown_tile_whose_stills_come_to_nothing_asks_less_and_less_often(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The third review's L5 and L6.) A still that came to nothing in any way (here: the engine of a starting PC opens no
    # session in time, a failure the session records itself) is not asked for again at every poll: the next waits
    # STILL_RETRY seconds, counted from the end of the last, and twice as long after each one more.
    monkeypatch.setattr(amt, "REDIRECTION_WITHIN", 0.3)
    monkeypatch.setattr(amt.AmtScreen, "STILL_RETRY", 1.0)
    monkeypatch.setattr(vncdevice, "ERROR_HOLD", 0)  # (so the port's own pause after a failure does not do the pacing here)
    pc.state.came_on_at, pc.state.starting_for = time.monotonic(), 60.0

    async def run() -> None:
        device = a_pc(pc)
        try:
            await settled_status(device, "online")
            began = time.monotonic()
            while time.monotonic() - began < 3.0:  # a tile that is only shown, asked for its picture every 50 ms
                with contextlib.suppress(KvmError):
                    await device.snapshot(640)
                await asyncio.sleep(0.05)
            # A first still (about 0.3 s), the next a second after it ended, the third two seconds after that: two in three
            # seconds, where every poll would be about ten.
            assert 1 <= pc.state.redirections <= 2 and device._screen._still_fails >= 1
        finally:
            await device.close()

    asyncio.run(run())


def test_another_certificate_on_the_redirection_port_is_said_on_the_tile_and_gets_nothing(tmp_path: Path) -> None:
    pc = FakeAmt(AmtState(), tls_dir=tmp_path / "cert-a", redirection_tls_dir=tmp_path / "cert-b").start()
    try:
        with wall(tmp_path / "data") as client:
            device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
            status_of(client, device, screen=True)
            said: dict[str, Any] = {}
            deadline = time.monotonic() + 5
            while not said and time.monotonic() < deadline:  # (looked at as a tile does, and the status read meanwhile)
                client.get(snap(device))
                status = client.get("/api/v1/status").json()[device]
                said = status if status.get("screen") is False else {}
                time.sleep(0.05)
            assert said["state"] == "online"  # (the PC is as it was; its screen is not to be had)
            assert said["server"]["no_screen"] == "Its redirection port: Certificate does not match the one saved for this device"
            assert pc.state.redirection_logins == 0 and pc.state.kvm_sessions == 0
    finally:
        pc.stop()


def test_keys_and_text_go_through_the_kvm(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        act = f"/api/v1/devices/{device}/actions"
        pressed = client.post(act, json={"action": "keys", "keys": "ControlLeft,KeyC"})
        assert pressed.status_code == 200, pressed.text
        assert client.post(act, json={"action": "text", "text": "Hi"}).status_code == 200
        assert client.post(act, json={"action": "ctrl_alt_del"}).status_code == 200
        keys = pc.state.screen.keys
        wait_until(lambda: len(keys) >= 14, f"the PC got {keys}")  # (written when the route answers; read by the PC a moment later)
        assert keys[:4] == [(0xFFE3, True), (0x63, True), (0x63, False), (0xFFE3, False)]
        assert keys[4:8] == [(0x48, True), (0x48, False), (0x69, True), (0x69, False)]
        assert keys[8:] == [(0xFFE3, True), (0xFFE9, True), (0xFFFF, True), (0xFFFF, False), (0xFFE9, False), (0xFFE3, False)]
        assert pc.state.actions == []  # (no power button among them)


def test_a_session_opened_for_keys_is_held_as_for_somebody_who_looks(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keys sent with nobody looking at the tile: a session is opened for them. Let go of at once (nobody "looked"), a real
    # engine dropped the keys with it; held as for one who looks, it is let go of only once nobody acts or looks for a while.
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 1.5)
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        assert pc.state.kvm_sessions == 0  # (nobody has looked)
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyX"}).status_code == 200
        time.sleep(0.5)
        assert (pc.state.kvm_sessions, pc.state.redirection_open) == (1, 1)  # still open after the keys
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyY"}).status_code == 200
        assert pc.state.kvm_sessions == 1  # the same session took the next keys
        # The first went out once the engine takes keys: one sent at once after the handshake was lost on a real one.
        wait_until(lambda: len(pc.state.screen.keys) >= 4, f"the PC got {pc.state.screen.keys}")
        wait_until(lambda: pc.state.redirection_open == 0, "the session was held for nobody", 6)
        assert [keysym for keysym, down in pc.state.screen.keys if down] == [0x78, 0x79]


def test_a_session_opened_for_keys_is_not_let_go_of_before_they_go_however_long_it_takes_to_open(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keys sent with nobody looking at the tile open a session for them, which is wanted while they wait for it and go, and for
    # LET_GO_AFTER after the last of them. It was wanted from the moment they were asked for only: an engine slow to open a
    # session (here 2.5 s, against a LET_GO_AFTER of 2, four times the wait for input) had it let go of before they could
    # go, and the next one too, until the keys gave up with "Waiting for the PC's screen".
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 2.0)
    pc.state.challenge_takes = 2.5

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await device.act("keys", keys="KeyQ")
            assert device._screen._connected_or_none() is not None  # (held after them, for LET_GO_AFTER)
        finally:
            await device.close()

    asyncio.run(run())
    wait_until(lambda: (0x71, False) in pc.state.screen.keys, f"the PC got {pc.state.screen.keys}")
    assert (pc.state.kvm_sessions, pc.state.redirection_logins) == (1, 1)


def test_a_long_text_typed_with_nobody_looking_is_not_cut_off_and_the_session_goes_after_the_last_key(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Text typed into a PC nobody looks at, which takes the keys at its own pace: the session is held while they go, however
    # long that takes, and let go of LET_GO_AFTER after the last one. Let go of LET_GO_AFTER after the text was asked for, it
    # was closed under the typing, and the rest of the text did not arrive.
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 1.0)
    taken = rfb.Client.keys

    async def at_the_engines_pace(self: rfb.Client, events: list[tuple[int, bool]]) -> None:
        await asyncio.sleep(0.2)
        await taken(self, events)

    monkeypatch.setattr(rfb.Client, "keys", at_the_engines_pace)
    text = "abcdefghij" * 20  # 400 key events: thirteen pieces, about 2.6 s

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await device.act("text", text=text)
            typed = time.monotonic()
            while device._screen._connected_or_none() is not None:
                assert time.monotonic() - typed < 5, "the session was held for nobody"
                await asyncio.sleep(0.05)
            assert time.monotonic() - typed >= 0.8  # (let go of after the last key, not before)
        finally:
            await device.close()

    asyncio.run(run())
    wait_until(lambda: len(pc.state.screen.keys) >= 400, f"the PC got {len(pc.state.screen.keys)} key events")
    assert "".join(chr(keysym) for keysym, down in pc.state.screen.keys if down) == text
    assert pc.state.kvm_sessions == 1


def test_keys_after_the_engine_ended_a_session_at_its_time_wait_for_the_next(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # A live viewer with keyboard and mouse: the engine ends the session every few minutes (a real one at 181 s). The next key
    # waits for the next session and arrives; it is not refused, which took keyboard and mouse away from the viewer. (The
    # stand-in ends the first session once its key came. It ended every session 1.5 s after its own RFB began, which on a
    # loaded machine came before the wall's keys did: they went to a session that was over, and none arrived.)
    pc.state.session_timeout, pc.state.first_session_ends_after_keys = 1, 2
    monkeypatch.setattr(amt, "TIMEOUT_SLACK", 60.0)  # (whenever it ends, it is an end at its time: a minute said, and none left)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await device.input_ready()
            await device.press(0x04, True)
            await device.press(0x04, False)
            deadline = time.monotonic() + 5
            while device._screen._connected_or_none() is not None:
                assert time.monotonic() < deadline, "the session never ended at its time"
                await asyncio.sleep(0.02)  # (now between two sessions)
            await device.press(0x05, True)
            await device.press(0x05, False)
            await device.pointer(10, 10, 1)
        finally:
            await device.close()

    asyncio.run(run())
    wait_until(lambda: len(pc.state.screen.keys) >= 4 and pc.state.screen.pointers, f"the PC got {pc.state.screen.keys} {pc.state.screen.pointers}")
    assert [keysym for keysym, down in pc.state.screen.keys if down] == [0x61, 0x62]


def test_what_is_held_down_is_let_go_of_also_when_the_screen_may_no_longer_be_had(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Shift, a letter and the left button down over a live line; then the PC turns out to want its code (consent switched on):
    # no new session, no new key, but what is down is let go of on the session that is still open.
    monkeypatch.setattr(amt, "KVM_TTL", 0)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            hid = live.RfbHid(device)
            await hid.open()
            await hid.key(0xE1, True)
            await hid.key(0x04, True)
            await hid.button(1, True)
            pc.state.consent = True
            await device._refresh_status()
            assert device.console_readable is False
            with pytest.raises(KvmError):
                await hid.key(0x05, True)  # (nothing new goes in)
            await hid.release_all()
        finally:
            await device.close()

    asyncio.run(run())
    screen = pc.state.screen
    wait_until(lambda: (0xFFE1, False) in screen.keys and screen.pointers and screen.pointers[-1][2] == 0, f"the PC got {screen.keys} {screen.pointers}")
    # (The refused key is let go of too: whether it reached the PC before the refusal is not known, and a key-up costs nothing.)
    assert [keysym for keysym, down in screen.keys if down] == [0xFFE1, 0x61] and set(screen.keys[2:]) == {(0x61, False), (0x62, False), (0xFFE1, False)}


def test_the_power_is_cut_also_while_a_session_is_open(pc: FakeAmt) -> None:
    # A real engine (AMT 16) neither offers cutting the power (8) or cycling it (5) while a KVM session is open, nor does it
    # (it answered 2): "Hold power button" while a live view held a session was refused, "does not offer off". The wall's own
    # session is closed for it, and the power is cut.
    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await live_picture(device)  # a live view holds a session open
            device._screen.live_seen()
            assert pc.state.kvm_open == 1
            await device.act("atx_power_long")
            assert (pc.state.actions, pc.state.power, pc.state.kvm_open) == ([8], 8, 0)
            assert device._power_on is False and pc.state.kvm_sessions == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_no_session_is_opened_while_the_power_is_being_cut(pc: FakeAmt) -> None:
    # Between the closing of the wall's own session and the engine's answer to the command, a tile that is looked at would
    # open another, and a real engine refuses the command while one is open: none is opened meanwhile, nor after it until
    # the PC is seen off (a real one opened at once showed a black screen for the seconds the engine took to say "off").
    pc.state.power_answer_takes, pc.state.power_takes = 1.0, 1.5

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
            cutting = asyncio.create_task(device.act("atx_power_long"))
            seen: set[str] = set()
            while not cutting.done():
                try:
                    await device.snapshot(640)
                except KvmError as ex:
                    seen.add(ex.code)
                await asyncio.sleep(0.05)
            await cutting
            assert (pc.state.actions, pc.state.power, pc.state.kvm_sessions) == ([8], 8, 1)
            assert seen <= {"no_stream", "no_picture"}, seen
        finally:
            await device.close()

    asyncio.run(run())


def test_another_viewers_session_is_said_when_the_power_cannot_be_cut(tmp_path: Path, pc: FakeAmt) -> None:
    # Another viewer (Intel's own tools, say) has the KVM: the wall cannot close that session, and says why nothing was done.
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, screen=True)
        pc.state.kvm_open = 1  # (somebody else's)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed")
        assert "KVM" in reply.json()["message"] and pc.state.actions == [] and pc.state.power == 2


def test_a_look_that_ends_after_the_pc_was_seen_off_does_not_say_it_is_on_again(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The reviewer's F1.) A look that read "on" just after the power cut, and went on to read how the KVM is set up, ended after
    # the wait had seen the PC off: it said "on" again, and the next picture opened a session to the PC that was off.
    monkeypatch.setattr(amt, "KVM_TTL", 0)
    pc.state.power_takes = 0.6
    asked = AmtDevice._read_kvm

    async def slowly(self: AmtDevice, urgent: bool = False) -> dict[str, Any]:
        found = await asked(self, urgent)
        await asyncio.sleep(3.0)
        return found

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
            monkeypatch.setattr(AmtDevice, "_read_kvm", slowly)
            await device.act("atx_power_long")
            await asyncio.sleep(3.5)  # (the slow look has ended)
            assert device._power_on is False
            with pytest.raises(KvmError) as refused:
                await device.snapshot(640)
            assert refused.value.code == "no_picture"
            assert pc.state.kvm_sessions == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_the_power_is_cut_a_moment_after_the_walls_own_session_ended(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The reviewer's F2.) A real engine lists 8 again about a second after a session ended. Pressed in that second (the
    # session let go of a moment before, or ended at the engine's time), it was refused at once and another viewer was blamed.
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 0.5)
    pc.state.bars_linger = 1.0

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
            while device._screen._connected_or_none() is not None:  # (let go of: nobody looks)
                await asyncio.sleep(0.02)
            await device.act("atx_power_long")
            assert (pc.state.actions, pc.state.power) == ([8], 8)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_pc_that_goes_off_while_the_power_command_waits_is_not_sent_it(pc: FakeAmt) -> None:
    # (The reviewer's F3.) While the command waits for the engine to offer it again, somebody at the PC switches it off. An
    # engine that offers a cycle (5) and no reset (10) had the reset button send a cycle to the PC that was off, which
    # switched it on.
    pc.state.offered, pc.state.bars_linger = [2, 5, 8], 3.0

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
            asyncio.get_running_loop().call_later(0.5, lambda: setattr(pc.state, "power", 8))  # (the button at the PC)
            with pytest.raises(KvmError) as refused:
                await device.act("atx_reset")
            assert refused.value.code == "action_failed" and "off" in refused.value.message
            assert (pc.state.actions, pc.state.power) == ([], 8)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_power_command_whose_answer_is_lost_is_said_to_be_perhaps_done(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The reviewer's F4.) The engine took the command and the connection broke before its answer came back: that was said as
    # "failed", the history kept it as not done, and "Retry failed" over many machines pressed the button a second time.
    import httpx

    sent = AmtDevice._send

    async def answer_lost(self: AmtDevice, client: httpx.AsyncClient, request: httpx.Request, limit: int) -> httpx.Response:
        reply = await sent(self, client, request, limit)
        if b"RequestPowerStateChange" in request.content:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return reply

    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"}).json()["device"]["id"]
        status_of(client, device, state="online")
        monkeypatch.setattr(AmtDevice, "_send", answer_lost)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout"), reply.json()
        assert "may have been done" in reply.json()["message"] and pc.state.actions == [10]  # (once)
        wait_until(lambda: client.get(f"/api/v1/devices/{device}/history?what=events").json()["rows"], "the press never reached the history")
        (press,) = client.get(f"/api/v1/devices/{device}/history?what=events").json()["rows"]
        assert (press["what"], press["ok"]) == ("atx_reset", None)


def test_a_device_changed_while_the_power_command_waits_is_said_to_have_been_sent_nothing(pc: FakeAmt) -> None:
    # (The reviewer's F8.) Retired while the command waited for the engine to offer it again: nothing had gone out, and that was
    # said as "it may have been done all the same".
    pc.state.bars_linger = 10.0

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await picture_of(device)
            pressing = asyncio.create_task(device.act("atx_power_long"))
            await asyncio.sleep(0.8)
            await device.close()
            with pytest.raises(KvmError) as refused:
                await pressing
            assert refused.value is not kvm.RETIRED and refused.value.code == "action_failed"
            assert "Nothing was sent" in refused.value.message and pc.state.actions == []
        finally:
            await device.close()

    asyncio.run(run())


def test_another_viewer_holding_the_kvm_is_asked_after_every_fifteen_seconds(pc: FakeAmt) -> None:
    # (The reviewer's F9.) The refusal hold doubles to four minutes for a server that sends what is not taken; for another
    # viewer's session, which costs the engine nothing to say, the tile (and a live line, and keys) asks again every 15 s.
    pc.state.start_status = 2

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            for _ in range(3):
                screen = device._screen
                screen._refusal, screen._refusal_until, screen._bad = None, 0.0, 0
                screen._still_at, screen._tried_still_at, screen._still_fails = float("-inf"), float("-inf"), 0
                with pytest.raises(KvmError):
                    await device.snapshot(640)  # a still attempt (in the background), refused: another viewer has the KVM
                if screen._taking is not None:
                    await asyncio.wait({screen._taking}, timeout=5)
                assert round(screen._refusal_until - time.monotonic()) == 15
        finally:
            await device.close()

    asyncio.run(run())


def test_letting_go_after_the_session_ended_opens_no_session_for_it(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # (LET_GO_AFTER above the wait for input, as in the program: with the two equal, the session was let go of at the moment
    # the key could go, before the input was counted as wanting it, and the key waited for sessions until it gave up.)
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 1.0)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            hid = live.RfbHid(device)
            await hid.open()
            await hid.key(0x04, True)
            deadline = time.monotonic() + 5
            while device._screen._connected_or_none() is not None:  # (nobody looks, nobody presses: let go of)
                assert time.monotonic() < deadline, "the session was held for nobody"
                await asyncio.sleep(0.05)
            await hid.release_all()
            await asyncio.sleep(0.3)
            assert (pc.state.kvm_sessions, pc.state.redirection_logins) == (1, 1)  # no sign-in and no session only to let go
        finally:
            await device.close()

    asyncio.run(run())


def test_a_session_that_ends_while_input_waits_for_it_is_followed_by_the_next(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keys wait INPUT_AFTER from the handshake. A session that ends within that wait (at its time, as a real engine's does
    # every few minutes) is no reason to refuse the keys: they wait for the next session and go there. (The stand-in ends the
    # first session as the wall's first request comes, its handshake done. Ended 0.2 s after the stand-in's own RFB began,
    # it ended inside the wall's handshake on a loaded machine, and the keys were refused: no fault of the wall's.)
    pc.state.session_timeout, pc.state.first_session_ends_at_request = 1, True
    monkeypatch.setattr(amt, "TIMEOUT_SLACK", 60.0)  # (whenever it ends, it is an end at its time: a minute said, and none left)

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device.status()
            await device.act("keys", keys="KeyQ")
        finally:
            await device.close()

    asyncio.run(run())
    wait_until(lambda: (0x71, True) in pc.state.screen.keys, f"the PC got {pc.state.screen.keys}")
    assert pc.state.kvm_sessions == 2


def test_the_live_lines_keys_and_pointer_become_rfb_events() -> None:
    class Pc:
        def __init__(self) -> None:
            self.events: list[tuple[str, Any]] = []

        async def input_ready(self) -> None:
            self.events.append(("ready", None))

        async def press(self, usage: int, down: bool) -> None:
            if usage == 0x66:
                raise KvmError("invalid", "no keysym", 422)
            self.events.append(("key", (usage, down)))

        async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False) -> None:
            self.events.append(("let go" if letting_go else "pointer", (x, y, buttons)))

        def screen_size(self) -> tuple[int, int]:
            return (1920, 1080)

    async def run() -> list[tuple[str, Any]]:
        device = Pc()
        hid = live.RfbHid(device)
        await hid.open()
        await hid.key(0x04, True)
        await hid.key(0x66, True)  # the power key has no keysym: not sent, and no reason to take the keyboard away
        await hid._say_place(32767, 0)
        await hid.button(1, True)
        await hid.button(3, True)
        await hid.button(4, True)  # back: RFB has none
        await hid.wheel(0, 1)
        await hid.wheel(-1, 0)
        await hid.move(-5000, 30)
        await hid.release_all()
        return device.events

    assert asyncio.run(run()) == [
        ("ready", None),
        ("key", (0x04, True)),
        ("pointer", (1919, 0, 0)),
        ("pointer", (1919, 0, 1)),
        ("pointer", (1919, 0, 3)),
        ("pointer", (1919, 0, 3 | 8)), ("pointer", (1919, 0, 3)),  # the wheel up: a press and a release of bit 3
        ("pointer", (1919, 0, 3 | 32)), ("pointer", (1919, 0, 3)),  # left
        ("pointer", (0, 30, 3)),  # moved by steps, held to the screen
        ("key", (0x04, False)),  # let go of, the keys first (the one with no keysym says nothing)
        ("let go", (0, 30, 2)), ("let go", (0, 30, 0)),  # (buttons let go of: on the session that is open, past the gate)
    ]  # fmt: skip


def test_the_stand_in_finds_its_two_ports_also_where_the_system_hands_out_the_last_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Seen once in a run of the tests: the system handed the stand-in port 65534 or 65535, the port two above it is no port,
    # and binding it raised OverflowError, which the search for two free ports did not take for a port that is taken.)
    from tests import fake_amt, local_socket

    handed: list[int] = []

    def last_first(port: int = 0) -> Any:
        sock = local_socket(port)
        handed.append(sock.getsockname()[1])
        if len(handed) == 1:
            sock.close()

            class Last:
                def getsockname(self) -> tuple[str, int]:
                    return ("127.0.0.1", 65535)

                def close(self) -> None:
                    pass

            return Last()
        return sock

    monkeypatch.setattr(fake_amt, "local_socket", last_first)
    first, second = fake_amt.FakeAmt._pair(0)
    try:
        assert second.getsockname()[1] == first.getsockname()[1] + 2
    finally:
        first.close()
        second.close()


def test_the_vnc_family_is_spoken_of_as_it_was() -> None:
    # The words a VNC server's tile says did not change with the family hooks that the PC's screen uses.
    device = vncdevice.VncDevice(DeviceSpec("v1", "VNC", "vnc://127.0.0.1:1", "", "x", kind="vnc"))
    assert device.THING == "the VNC server" and device._the() == "The VNC server"
    assert (device.ENCODINGS, device.PIXELS, device.GREETED_AS_38, device.LET_GO_AFTER) == (rfb.ENCODINGS, rfb.RGB888, (), None)
