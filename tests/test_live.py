"""The live line (qkvm/live.py): a pass, then one WebSocket per viewer with the picture down and keys and the mouse up.

Against the program on a real port, with the web server's own options: what the line does to a viewer that
stops reading is only seen on a real socket, and the options that bound a line (the size of a message, the
ping that finds a viewer gone) are the web server's.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import uvicorn
from websockets.exceptions import ConnectionClosed, InvalidStatus
from websockets.sync.client import ClientConnection
from websockets.sync.client import connect as ws_connect

from qkvm import ami, amt, cli, kvm, live, redfish, update, vault
from qkvm.core import Core
from qkvm.kvm import DeviceSpec, KvmDevice
from qkvm.server import create_app
from tests import local_socket
from tests.aspeed_frames import console_screen
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_jetkvm import FakeJetKvm, JetState, no_long_handshake
from tests.fake_kvm import MADE_UP_PPS, MADE_UP_SPS, FakeKvm, FakeState, made_up_film, pictures_of
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_wall import CSRF, PASSWORD, closed_port, wait_until

HEAD = struct.Struct("<BBHIq")
HELLO = {"t": "hello", "v": 2, "video": ["h264", "jpeg"], "max_w": 1920, "max_fps": 30}
# (A line is opened and held by a `Viewer` for as long as a test wants it, not in a `with`: the library would rather it were.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(live, "STANDING_EVERY", 0.2)  # whether a line may still be there is looked at often, so that a test sees it


@dataclass(frozen=True)
class Picture:
    kind: int
    key: bool
    counter: int
    at: int
    data: bytes


def picture_of(message: bytes) -> Picture:
    kind, flags, zero, counter, at = HEAD.unpack_from(message)
    assert zero == 0 and flags in (0, 1) and len(message) > HEAD.size
    return Picture(kind, flags == 1, counter, at, message[HEAD.size :])


class Viewer:
    """One live line, from this side: what it says, and what comes down it."""

    def __init__(self, wall: Wall, device: str, ticket: Any, headers: dict[str, str] | None = None, **hello: Any) -> None:
        self.ws: ClientConnection = ws_connect(f"ws://127.0.0.1:{wall.port}/api/v1/devices/{device}/live", open_timeout=5, additional_headers=headers)
        self.ws.send(json.dumps({**HELLO, "ticket": ticket, **hello}))
        self.words: list[dict[str, Any]] = []  # the text messages that came while a picture was waited for

    def say(self, **word: Any) -> None:
        self.ws.send(json.dumps(word))

    def next(self, timeout: float = 5.0) -> dict[str, Any] | Picture:
        came = self.ws.recv(timeout=timeout)
        if isinstance(came, bytes):
            return picture_of(came)
        said = json.loads(came)
        assert isinstance(said, dict) and isinstance(said.get("t"), str)
        return said

    def word(self, kind: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
        """The next text message (of this kind, where one is named; pictures and other words are kept aside, and looked at first)."""
        for said in self.words:
            if kind is None or said["t"] == kind:
                self.words.remove(said)
                return said
        give_up = time.monotonic() + timeout
        while True:
            came = self.next(max(0.01, give_up - time.monotonic()))
            if isinstance(came, dict) and (kind is None or came["t"] == kind):
                return came
            if isinstance(came, dict):
                self.words.append(came)

    def picture(self, timeout: float = 5.0) -> Picture:
        give_up = time.monotonic() + timeout
        while True:
            came = self.next(max(0.01, give_up - time.monotonic()))
            if isinstance(came, Picture):
                return came
            self.words.append(came)

    def until(self, condition: Any, message: str, timeout: float = 5.0) -> None:
        """Wait until `condition()` holds, reading what comes meanwhile as a browser does (its words kept, for `word`)."""
        give_up = time.monotonic() + timeout
        while not condition():
            assert time.monotonic() < give_up, message
            try:
                came = self.next(0.05)
            except TimeoutError:
                continue
            if isinstance(came, dict):
                self.words.append(came)

    def nothing(self, seconds: float) -> None:
        """Nothing at all comes for this long (words of state apart)."""
        give_up = time.monotonic() + seconds
        while time.monotonic() < give_up:
            try:
                came = self.next(max(0.01, give_up - time.monotonic()))
            except TimeoutError:
                return
            assert isinstance(came, dict) and came["t"] == "state", came

    def closed(self, timeout: float = 5.0) -> None:
        """The server has closed the line."""
        try:
            while True:
                self.next(timeout)
        except ConnectionClosed:
            return

    def close(self) -> None:
        self.ws.close()


class Raw:
    """A WebSocket client on a plain socket, for what a library's client would never do: not read, not answer a ping, send pings by the thousand."""

    def __init__(self, wall: Wall, device: str, headers: str = "") -> None:
        self.sock = socket.create_connection(("127.0.0.1", wall.port), timeout=10)
        head = (
            f"GET /api/v1/devices/{device}/live HTTP/1.1|Host: 127.0.0.1:{wall.port}|Upgrade: websocket|Connection: Upgrade|"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==|Sec-WebSocket-Version: 13|{headers}|"
        )
        self.sock.sendall(head.replace("|", "\r\n").encode())
        answer = b""
        while b"\r\n\r\n" not in answer:
            answer += self.sock.recv(4096)
        assert answer.startswith(b"HTTP/1.1 101"), answer[:80]
        self.rest = answer.split(b"\r\n\r\n", 1)[1]

    def frame(self, opcode: int, payload: bytes = b"", fin: bool = True) -> bytes:
        """One frame, masked as a client's must be; `fin`: the last piece of its message (a message may come in pieces)."""
        head = bytes([(0x80 if fin else 0) | opcode])
        if len(payload) < 126:
            head += bytes([0x80 | len(payload)])
        else:
            head += b"\xfe" + struct.pack(">H", len(payload))
        mask = os.urandom(4)
        return head + mask + bytes(byte ^ mask[at % 4] for at, byte in enumerate(payload))

    def say(self, **word: Any) -> None:
        self.sock.sendall(self.frame(1, json.dumps(word).encode()))

    def next(self, timeout: float = 5.0) -> tuple[int, bytes]:
        """The next frame from the server: (opcode, payload). EOF is (-1, b"")."""
        self.sock.settimeout(timeout)

        def take(count: int) -> bytes:
            while len(self.rest) < count:
                came = self.sock.recv(65536)
                if not came:
                    raise EOFError
                self.rest += came
            taken, self.rest = self.rest[:count], self.rest[count:]
            return taken

        try:
            first, second = take(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", take(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", take(8))[0]
            return first & 0x0F, take(length)
        except (EOFError, ConnectionError):  # (hung up on: a reset, where the server dropped the connection as it stood)
            return -1, b""

    def close(self) -> None:
        self.sock.close()


class Wall:
    """The program on a real localhost port, with the web server's options as the program starts it (`serving`: those changed)."""

    def __init__(self, data: Path, serving: dict[str, Any] | None = None, **options: Any) -> None:
        self._sock = local_socket()
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.core = Core(data, **options)
        self.core.unlock_at_start()
        config = uvicorn.Config(create_app(self.core), **{**cli.SERVER_OPTIONS, "log_level": "error", **(serving or {})})
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)
        self.clients: list[httpx.Client] = []

    def __enter__(self) -> Wall:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            assert time.monotonic() < deadline, "the wall did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *_: object) -> None:
        for client in self.clients:
            client.close()
        self._server.should_exit = True
        self._thread.join(timeout=10)

    def browser(self, name: str | None = None, password: str = PASSWORD) -> httpx.Client:
        """A browser signed in: as the first account (made here if there is none), or as `name`."""
        client = httpx.Client(base_url=self.url, headers=CSRF, timeout=10)
        self.clients.append(client)
        if name is None and not self.core.initialized:
            assert client.post("/api/v1/setup", json={"password": password}).status_code == 200
        else:
            body = {"password": password, **({"name": name} if name else {})}
            assert client.post("/api/v1/login", json=body).status_code == 200
        return client

    def add(self, client: httpx.Client, url: str, **extra: Any) -> str:
        reply = client.post("/api/v1/devices", json={"url": url, "password": "secret", **extra})
        assert reply.status_code == 201, reply.text
        return str(reply.json()["device"]["id"])

    def ticket(self, client: httpx.Client, device: str) -> str:
        reply = client.post(f"/api/v1/devices/{device}/live")
        assert reply.status_code == 200, reply.text
        said = reply.json()
        assert said["v"] == 2 and live.TICKET.fullmatch(said["ticket"])
        return str(said["ticket"])

    def line(self, client: httpx.Client, device: str, **hello: Any) -> Viewer:
        return Viewer(self, device, self.ticket(client, device), **hello)

    def audit(self, client: httpx.Client, word: str) -> list[dict[str, Any]]:
        """The entries of the activity log with this word in them, oldest first."""
        return sorted(client.get("/api/v1/audit", params={"q": word}).json()["entries"], key=lambda entry: float(entry["time"]))


@pytest.fixture
def pikvm() -> Iterator[FakeKvm]:
    """A KVM with stock PiKVM's H.264 line, sending made-up pictures."""
    fake = FakeKvm(FakeState(media=True, fps=15.0)).start()
    yield fake
    fake.stop()


@pytest.fixture
def comet() -> Iterator[FakeKvm]:
    """A KVM without it (a Comet), whose pictures are JPEG."""
    fake = FakeKvm(FakeState(picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    yield fake
    fake.stop()


def a_jpeg(colour: tuple[int, int, int], width: int = 320, height: int = 180) -> bytes:
    """A JPEG of one colour, made the way the program makes them."""
    from qkvm.video import RGBFrame, encode_jpeg

    return encode_jpeg(RGBFrame(width, height, bytes(colour) * width * height), None, 2)


# --- the pass, and the line ----------------------------------------------------------------------------------


def test_the_wall_says_which_form_of_live_line_it_speaks(tmp_path: Path) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        assert admin.get("/api/v1/wall").json()["live"] == 2


def test_a_pass_opens_one_line_once_and_the_pictures_come_numbered(tmp_path: Path, pikvm: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, pikvm.url)
        ticket = wall.ticket(admin, device)
        viewer = Viewer(wall, device, ticket)
        video = viewer.word("video")
        assert video == {"t": "video", "codec": "h264", "w": 1920, "h": 1080}
        assert viewer.word("state")["state"] == "online"
        first = viewer.picture()
        assert first.kind == 1 and first.key, "the line begins with a key frame"
        assert first.data[:6] == b"\x00\x00\x00\x01\x09\xf0", "the access unit as the KVM sent it, delimiter first"
        last = first
        for _ in range(20):
            came = viewer.picture()
            assert came.counter == last.counter + 1, "one higher for each picture"
            assert came.at >= last.at
            last = came
        assert pikvm.state.media_clients == 1 and pikvm.state.ws_streams == ["1"], "one line to the KVM, and its streamer held as a browser would"

        # The same pass again is no pass; nor is one for another machine, nor a made-up one.
        again = Viewer(wall, device, ticket)
        assert again.word("bye")["code"] == "no_pass"
        again.closed()
        other = wall.add(admin, "http://127.0.0.1:9", force=True)
        for wrong in (wall.ticket(admin, other), "x" * 32, 12, None):
            turned = Viewer(wall, device, wrong)
            assert turned.word("bye")["code"] == "no_pass"
            turned.closed()
        viewer.close()
        wait_until(lambda: pikvm.state.media_clients == 0, "the line to the KVM was not closed after the last viewer left")


def test_a_pass_runs_out_and_a_line_that_says_no_hello_is_closed(tmp_path: Path, pikvm: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "PASS_LASTS", 0.3)
    monkeypatch.setattr(live, "HELLO_WITHIN", 0.5)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, pikvm.url)
        ticket = wall.ticket(admin, device)
        time.sleep(0.5)
        late = Viewer(wall, device, ticket)
        assert late.word("bye")["code"] == "no_pass"
        late.closed()
        silent = ws_connect(f"ws://127.0.0.1:{wall.port}/api/v1/devices/{device}/live", open_timeout=5)
        said = json.loads(silent.recv(timeout=5))
        assert said["t"] == "bye" and said["code"] == "no_pass"
        with pytest.raises(ConnectionClosed):
            silent.recv(timeout=5)


def test_a_viewer_that_falls_behind_is_brought_forward_to_a_key_frame(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live.H264Source, "queue", 3)
    fast_kvm = FakeKvm(FakeState(media=True, fps=200.0, unit_bytes=60_000, film=made_up_film(60_000, pictures=40, key_every=20))).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, fast_kvm.url)
            viewer = wall.line(admin, device)
            first = viewer.picture()
            assert first.key
            time.sleep(3)  # not reading: twelve megabytes a second pile up somewhere, and not in the wall
            last, jumped = first, None
            for _ in range(3000):
                came = viewer.picture()
                if came.counter != last.counter + 1:
                    jumped = came
                    break
                last = came
            assert jumped is not None, "the counter never jumped: the viewer was waited for"
            assert jumped.counter > last.counter + 1 and jumped.key, "brought forward to a key frame, and it sees that as a jump in the counter"
            assert fast_kvm.state.key_requests >= 1, "the KVM was asked for a key frame"
            viewer.close()
    finally:
        fast_kvm.stop()


def test_a_key_frame_asked_for_comes_next(tmp_path: Path) -> None:
    slow_keys = FakeKvm(FakeState(media=True, fps=15.0, film=made_up_film(2000, pictures=90, key_every=90))).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, slow_keys.url)
            viewer = wall.line(admin, device)
            assert viewer.picture().key
            while viewer.picture().key:
                pass  # (one was asked for as the line began, and the KVM jumped to one)
            for _ in range(5):
                assert not viewer.picture().key  # (the next key frame would come six seconds on)
            viewer.say(t="key_frame")
            began = time.monotonic()
            while not viewer.picture().key:
                assert time.monotonic() - began < 2, "no key frame came after one was asked for"
            assert slow_keys.state.key_requests == 2  # (once when the line began, once now)
            viewer.close()
    finally:
        slow_keys.stop()


def test_a_real_film_is_cut_into_its_pictures() -> None:
    """The stand-in cuts a film as the desktop's tools make them (every picture behind a delimiter); here, one made the same way."""
    film = b"".join(unit for _, unit in made_up_film(100, pictures=12, key_every=4))
    pictures = pictures_of(film)
    assert len(pictures) == 12 and [key for key, _ in pictures] == [True, False, False, False] * 3
    assert b"".join(unit for _, unit in pictures) == film


def test_a_viewer_that_shows_jpeg_alone_gets_the_pictures_one_by_one(tmp_path: Path, pikvm: FakeKvm) -> None:
    pikvm.state.picture, pikvm.state.picture_type = a_jpeg((20, 120, 60)), "image/jpeg"
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, pikvm.url)
        viewer = wall.line(admin, device, video=["jpeg"])
        assert viewer.word("video") == {"t": "video", "codec": "jpeg", "w": 320, "h": 180}
        came = viewer.picture()
        assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
        assert pikvm.state.media_clients == 0, "its H.264 line was not opened for a viewer that cannot show it"
        viewer.close()


# --- a Comet: pictures asked one after the other ---------------------------------------------------------------


def test_a_kvm_without_an_h264_line_sends_jpeg_and_only_what_changed(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        viewer = wall.line(admin, device, max_fps=10)
        assert viewer.word("video") == {"t": "video", "codec": "jpeg", "w": 320, "h": 180}
        came = viewer.picture()
        assert came.kind == 2 and came.key and came.counter == 1 and came.data == comet.state.picture
        # A still screen: the KVM is asked at the viewer's pace, and gives the same bytes; nothing is sent twice. (Over two
        # seconds, three to fourteen a second: it is asked once the picture before has come, and a busy computer's KVM took
        # a fifth of a second over one; never more often than the viewer wants.)
        asked = len(comet.state.snapshot_queries)
        viewer.nothing(2.0)
        asked = len(comet.state.snapshot_queries) - asked
        assert 6 <= asked <= 28, f"asked {asked} times in two seconds, for a viewer that wants ten pictures a second"
        comet.state.picture = a_jpeg((200, 30, 30))
        came = viewer.picture()
        assert came.counter == 2 and came.data == comet.state.picture
        assert comet.state.media_clients == 0 and all(query.get("preview") is None for query in comet.state.snapshot_queries), "asked as captured, for a viewer this wide"
        viewer.close()


def test_a_kvm_that_sends_a_png_sends_no_picture_down_the_line(tmp_path: Path) -> None:
    """The line carries JPEG and H.264; a KVM without a signal may answer with a PNG, which is no picture for it (the state says no_signal)."""
    fake = FakeKvm(FakeState(signal=False)).start()  # (its picture is the PNG every stand-in makes)
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, fake.url)
            viewer = wall.line(admin, device, max_fps=10)
            assert viewer.word("state")["state"] == "no_signal"
            viewer.nothing(0.7)
            assert viewer.words == [], "a `video` was said of pictures that never come"
            viewer.close()
    finally:
        fake.stop()


# --- keyboard and mouse ---------------------------------------------------------------------------------------


def test_control_is_one_lines_at_a_time_and_what_it_sends_reaches_the_kvm(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        first, second = wall.line(admin, device), wall.line(admin, device)
        for line in (first, second):
            line.say(t="k", u=0x04, d=True)  # before control: nothing goes anywhere
        first.say(t="control", on=True)
        assert first.word("control") == {"t": "control", "on": True}
        second.say(t="control", on=True)
        refused = second.word("control")
        assert refused["on"] is False and refused["code"] == "taken" and refused["message"] and refused["by"] == "admin"
        wait_until(lambda: "0" in comet.state.ws_streams, "the line for keys was not opened, or holds the streamer")
        assert comet.state.hid == []

        first.say(t="k", u=0xE1, d=True)  # ShiftLeft
        first.say(t="k", u=0x04, d=True)  # KeyA
        first.say(t="k", u=0x04, d=False)
        first.say(t="m", x=16384, y=0)
        first.say(t="mb", b=1, d=True)
        first.say(t="mb", b=1, d=False)
        first.say(t="mw", dx=0, dy=-1)
        first.say(t="mr", dx=300, dy=-3)
        first.say(t="k", u=0x9999, d=True)  # a usage kvmd has no name for: nothing is sent
        first.say(t="k", u="KeyA", d=True)  # not a usage at all
        first.say(t="up")
        wait_until(lambda: len(comet.state.hid) >= 11, f"the KVM got {comet.state.hid}")
        assert comet.state.hid == [
            {"event_type": "key", "event": {"key": "ShiftLeft", "state": True}},
            {"event_type": "key", "event": {"key": "KeyA", "state": True}},
            {"event_type": "key", "event": {"key": "KeyA", "state": False}},
            {"event_type": "mouse_move", "event": {"to": {"x": 0, "y": -32768}}},
            {"event_type": "mouse_button", "event": {"button": "left", "state": True}},
            {"event_type": "mouse_button", "event": {"button": "left", "state": False}},
            {"event_type": "mouse_wheel", "event": {"delta": {"x": 0, "y": -1}}},
            {"event_type": "mouse_relative", "event": {"delta": {"x": 127, "y": -3}}},
            {"event_type": "mouse_relative", "event": {"delta": {"x": 127, "y": 0}}},
            {"event_type": "mouse_relative", "event": {"delta": {"x": 46, "y": 0}}},
            {"event_type": "key", "event": {"key": "ShiftLeft", "state": False}},  # `up`: what was still down
        ]
        second.say(t="k", u=0x05, d=True)  # not the holder: ignored
        first.say(t="control", on=False)
        assert first.word("control") == {"t": "control", "on": False}
        time.sleep(0.3)
        assert comet.state.hid[-1]["event"]["key"] == "ShiftLeft"  # nothing more came, from either line
        wait_until(lambda: comet.state.key_lines == 0, "the line for keys was not closed when control was given back")

        second.say(t="control", on=True)
        assert second.word("control") == {"t": "control", "on": True}
        wait_until(lambda: len(wall.audit(admin, "live_control")) == 3, "the activity log does not say who took keyboard and mouse")
        taken = wall.audit(admin, "live_control")
        assert [(entry["user"], entry["on"], entry.get("why")) for entry in taken] == [("admin", True, None), ("admin", False, None), ("admin", True, None)]
        assert all(isinstance(entry["device"], str) for entry in taken) and not any("KeyA" in json.dumps(entry) for entry in taken)
        first.close()
        second.close()


def test_a_viewer_may_look_and_not_act(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": "olga looks only"}).status_code == 201
        olga = wall.browser("olga", "olga looks only")
        line = wall.line(olga, device)
        assert line.picture().kind == 2
        line.say(t="control", on=True)
        refused = line.word("control")
        assert refused["on"] is False and refused["code"] == "not_allowed"
        line.close()


def test_a_line_cut_while_keys_are_down_lets_them_go(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE0, d=True)  # ControlLeft
        line.say(t="k", u=0x06, d=True)  # KeyC
        line.say(t="mb", b=2, d=True)
        wait_until(lambda: len(comet.state.hid) == 3, "the keys did not arrive")
        line.ws.socket.close()  # the viewer's computer went away: no goodbye
        wait_until(lambda: len(comet.state.hid) == 6, f"what was down was not let go of: {comet.state.hid}")
        assert comet.state.hid[3:] == [
            {"event_type": "key", "event": {"key": "KeyC", "state": False}},
            {"event_type": "key", "event": {"key": "ControlLeft", "state": False}},  # (the modifiers last)
            {"event_type": "mouse_button", "event": {"button": "right", "state": False}},
        ]
        wait_until(lambda: comet.state.key_lines == 0, "the line for keys stayed open")
        wait_until(lambda: [e.get("why") for e in wall.audit(admin, "live_control")] == [None, "closed"], "the activity log does not say that the keys left with the line")


def test_the_wall_stopping_lets_go_of_what_a_line_had_down(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x07, d=True)  # KeyD
        line.say(t="mb", b=1, d=True)
        wait_until(lambda: len(comet.state.hid) == 2, "the key and the button did not arrive")
    # The wall was stopped with them down: it let go of them before its connections to the KVM went.
    assert comet.state.hid[2:] == [
        {"event_type": "key", "event": {"key": "KeyD", "state": False}},
        {"event_type": "mouse_button", "event": {"button": "left", "state": False}},
    ]
    line.closed()


def test_an_action_refused_while_somebody_holds_the_keyboard_says_who(tmp_path: Path, comet: FakeKvm) -> None:
    # "Somebody has the keyboard": an admin, or an operator, had no way to find out whom to ask.
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).status_code == 201
        olga = wall.browser("olga", "olga may act here")
        line = wall.line(olga, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert (refused.status_code, refused.json()["code"]) == (409, "busy")
        assert refused.json().get("by") == "olga" and refused.json()["message"].startswith("olga has "), refused.text
        line.close()
        # A token for scripts, by its name; told to an operator as to an admin.
        token = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator"}).json()["token"]
        script = httpx.Client(base_url=wall.url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        wall.clients.append(script)
        line = wall.line(script, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        refused = olga.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "hello"})
        assert refused.status_code == 409 and refused.json().get("by") == "nightly (token)", refused.text
        assert "nightly (token)" in refused.json()["message"]
        line.close()


def test_an_action_and_a_held_keyboard_are_one_thing_at_a_time(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(picture=a_jpeg((10, 10, 10)), picture_type="image/jpeg", atx=True, slow_action=1.0)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, fake.url)
            line = wall.line(admin, device)
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
            assert refused.status_code == 409 and refused.json()["code"] == "busy" and "keyboard" in refused.json()["message"]
            # Also text to type, and also for whoever holds them (the page's "Type text" while its own line has the keyboard):
            # text goes over the line, or after the keyboard is given back.
            typed = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "hello"})
            assert typed.status_code == 409 and typed.json()["code"] == "busy" and not any(a.startswith("type") for a in fake.state.actions)
            line.say(t="control", on=False)
            assert line.word("control") == {"t": "control", "on": False}
            assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"}).status_code == 200

            # And the other way round: while the power button is being pressed, keyboard and mouse are not given out.
            pressing = threading.Thread(target=lambda: admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power"}))
            pressing.start()
            wait_until(lambda: "atx power" in fake.state.actions, "the button was not pressed")
            line.say(t="control", on=True)
            refused_too = line.word("control")
            assert refused_too["on"] is False and refused_too["code"] == "busy"
            pressing.join()
            line.close()
    finally:
        fake.stop()


def test_an_admin_takes_over_from_an_operator_who_is_told_who_and_what_she_had_down_is_let_go_of_first(tmp_path: Path, comet: FakeKvm) -> None:
    # The owner's word (2026-10-18): KVMs run production machines, and an admin must be able to act. Nobody could take a
    # machine's keyboard from whoever held it over a live line; actions were refused for as long as they held it.
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).status_code == 201
        olga = wall.browser("olga", "olga may act here")
        hers = wall.line(olga, device)
        hers.say(t="control", on=True)
        assert hers.word("control")["on"] is True
        hers.say(t="k", u=0xE0, d=True)  # ControlLeft, held down
        hers.say(t="mb", b=1, d=True)  # and the left button
        wait_until(lambda: len(comet.state.hid) == 2, f"her key and button did not arrive: {comet.state.hid}")

        mine = wall.line(admin, device)
        mine.say(t="control", on=True)
        refused = mine.word("control")
        assert refused["on"] is False and refused["code"] == "taken" and refused["by"] == "olga", refused
        # A take-over says whom it takes them from, as a text: without one, it takes nothing.
        for whom in ({}, {"from": None}, {"from": 5}, {"from": ["olga"]}, {"from": "olga "}):
            mine.say(**{"t": "control", "on": True, "take": True, **whom})
            refused = mine.word("control")
            assert refused["on"] is False and refused["code"] == "taken" and refused["by"] == "olga", (whom, refused)
        mine.say(**{"t": "control", "on": True, "take": True, "from": refused["from"]})
        assert mine.word("control") == {"t": "control", "on": True}
        mine.say(t="k", u=0x06, d=True)  # KeyC, at once
        mine.say(t="k", u=0x06, d=False)
        revoked = hers.word("control")
        assert isinstance(revoked["from"], str) and len(revoked["from"]) == 32 and revoked["from"] != refused["from"]
        assert revoked == {"t": "control", "on": False, "code": "taken", "message": "admin took over this machine's keyboard and mouse", "by": "admin", "from": revoked["from"]}
        hers.say(t="k", u=0x04, d=True)  # hers, after: nothing
        hers.say(t="up")
        wait_until(lambda: len(comet.state.hid) >= 6, f"the take-over did not reach the KVM: {comet.state.hid}")
        time.sleep(0.3)
        assert comet.state.hid[2:] == [
            {"event_type": "key", "event": {"key": "ControlLeft", "state": False}},  # hers let go of, first
            {"event_type": "mouse_button", "event": {"button": "left", "state": False}},
            {"event_type": "key", "event": {"key": "KeyC", "state": True}},  # then his, and nothing of hers after
            {"event_type": "key", "event": {"key": "KeyC", "state": False}},
        ], comet.state.hid
        # She keeps looking; asked again, she is told who has them; and she may not take them back.
        hers.say(t="key_frame")
        assert hers.picture().kind == 2
        hers.say(t="control", on=True)
        again = hers.word("control")
        assert again["code"] == "taken" and again["by"] == "admin", again
        hers.say(t="control", on=True, take=True)
        again = hers.word("control")
        assert again["code"] == "taken" and again["by"] == "admin" and "only an admin" in again["message"], again
        wait_until(lambda: len(wall.audit(admin, "live_control")) == 3, "the activity log does not say who took them from whom")
        said = [(entry["user"], entry["on"], entry.get("why"), entry.get("by"), entry.get("from")) for entry in wall.audit(admin, "live_control")]
        # (The two lines of the take-over are written in the same moment: a clock as coarse as Windows' before Python 3.13
        # gives them one time, and the log then lists them either way round.)
        assert said[0] == ("olga", True, None, None, None) and sorted(said[1:], key=str) == sorted(
            [("olga", False, "taken", "admin", None), ("admin", True, None, None, "olga")], key=str
        ), said
        hers.close()
        mine.close()


def test_an_operator_a_token_and_a_wall_screen_never_take_over_and_an_admins_action_does_not_either(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        for name in ("olga", "bob"):
            assert admin.post("/api/v1/users", json={"name": name, "role": "operator", "password": f"{name} may act here"}).status_code == 201
        olga, bob = wall.browser("olga", "olga may act here"), wall.browser("bob", "bob may act here")
        hers = wall.line(olga, device)
        hers.say(t="control", on=True)
        assert hers.word("control")["on"] is True
        hers.say(t="k", u=0xE1, d=True)  # ShiftLeft
        wait_until(lambda: len(comet.state.hid) == 1, "her key did not arrive")

        # Another operator.
        his = wall.line(bob, device)
        his.say(**{"t": "control", "on": True, "take": True, "from": "olga"})  # (with all a take-over needs)
        no = his.word("control")
        assert no["on"] is False and no["code"] == "taken" and no["by"] == "olga" and "only an admin" in no["message"], no
        # A token for scripts, with an operator's role; and one written down as an admin's in the settings (no form makes
        # one): a token is never taken for a person.
        made = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator"}).json()
        script = httpx.Client(base_url=wall.url, headers={"Authorization": f"Bearer {made['token']}"}, timeout=10)
        wall.clients.append(script)
        for role in ("operator", "admin"):
            next(token for token in wall.core.store.tokens if token.id == made["record"]["id"]).role = role
            line = wall.line(script, device)
            line.say(**{"t": "control", "on": True, "take": True, "from": "olga"})
            no = line.word("control")
            assert no["on"] is False and no["code"] == "taken" and no["by"] == "olga", (role, no)
            line.close()
            # Nor does its action say that it could take them over.
            acted = script.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
            assert acted.status_code == 409 and acted.json()["by"] == "olga" and "take them over" not in acted.json()["message"], (role, acted.text)
        # A wall screen opened with its display link only looks.
        key = admin.post("/api/v1/tokens", json={"name": "screen", "kind": "display"}).json()["token"]
        screen = httpx.Client(base_url=wall.url, headers=CSRF, timeout=10)
        wall.clients.append(screen)
        assert screen.post("/api/v1/display", json={"key": key}).status_code == 200
        shown = wall.line(screen, device)
        shown.say(**{"t": "control", "on": True, "take": True, "from": "olga"})
        assert shown.word("control")["code"] == "not_allowed"
        # An admin's action does not take over: refused, with whose they are and where an admin can take them over.
        refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert (refused.status_code, refused.json()["code"], refused.json()["by"]) == (409, "busy", "olga"), refused.text
        message = refused.json()["message"]
        assert message.startswith("olga has ") and message.endswith(" Wait until they are given back. As an admin you can take them over in its live view."), message
        theirs = olga.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert theirs.status_code == 409 and "take them over" not in theirs.json()["message"], theirs.text
        # She held them through all of it, and what she sends still arrives.
        hers.say(t="k", u=0xE1, d=False)
        wait_until(lambda: len(comet.state.hid) == 2, f"her line no longer reaches the machine: {comet.state.hid}")
        assert [entry.get("why") for entry in wall.audit(admin, "live_control")] == [None]
        for line in (hers, his, shown):
            line.close()


def test_an_action_right_after_keyboard_and_mouse_were_given_back_waits_for_the_holders_letting_go(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # The holder gives keyboard and mouse back with Alt down, on a KVM slow to take the letting go; an action follows at
    # once. It went straight out: Ctrl+Alt+Del landed while that Alt was still on its way up.
    real_say_key = live.KvmdHid._say_key

    async def slow_up(self: live.KvmdHid, usage: int, down: bool) -> None:
        if not down:
            await asyncio.sleep(0.8)
        await real_say_key(self, usage, down)

    monkeypatch.setattr(live.KvmdHid, "_say_key", slow_up)
    timeline: list[tuple[str, Any]] = []
    comet.state.hid, comet.state.actions = Told("hid", timeline), Told("action", timeline)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE2, d=True)  # AltLeft, held down
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        line.say(t="control", on=False)
        assert line.word("control") == {"t": "control", "on": False}
        acted = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert acted.status_code == 200, acted.text
        let_go = ("hid", {"key": "AltLeft", "state": False})
        wait_until(lambda: let_go in [(name, item if name == "action" else item["event"]) for name, item in timeline], f"Alt was never let go of: {timeline}")
        kinds = [(name, item if name == "action" else item["event"]) for name, item in timeline]
        up = kinds.index(let_go)
        pressed = next(at for at, (name, _) in enumerate(kinds) if name == "action")
        assert up < pressed, f"the action went before the holder's Alt was let go of: {kinds}"
        line.close()


class Told(list[Any]):
    """A list of what a stand-in KVM was told that also writes each entry into one timeline, in the order they came."""

    def __init__(self, name: str, timeline: list[tuple[str, Any]]) -> None:
        super().__init__()
        self.name, self.timeline = name, timeline

    def append(self, item: Any) -> None:
        super().append(item)
        self.timeline.append((self.name, item))


def slow_letting_go(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """A kvmd KVM that takes this long to take each key let go of, over the live line."""
    real_say_key = live.KvmdHid._say_key

    async def slow_up(self: live.KvmdHid, usage: int, down: bool) -> None:
        if not down:
            await asyncio.sleep(seconds)
        await real_say_key(self, usage, down)

    monkeypatch.setattr(live.KvmdHid, "_say_key", slow_up)


@pytest.mark.parametrize("then", ["an action", "a new line"])
def test_what_a_holder_that_was_the_only_viewer_had_down_is_let_go_of_before_whatever_comes_next(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch, then: str) -> None:
    # The holder's line was the machine's only one and ends without giving keyboard and mouse back (its socket gone): the
    # machine went with it, and with it what was still being let go of. An action, or the next holder on a machine made
    # anew, went straight out: Ctrl+Alt+Del, or a key, landed while the holder's Alt was still on its way up.
    slow_letting_go(monkeypatch, 1.5)
    timeline: list[tuple[str, Any]] = []
    comet.state.hid, comet.state.actions = Told("hid", timeline), Told("action", timeline)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE2, d=True)  # AltLeft, held down
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        line.ws.socket.close()  # the viewer's computer went away
        wait_until(lambda: [entry.get("why") for entry in wall.audit(admin, "live_control")] == [None, "closed"], "the keyboard was not let go of with the line")
        if then == "an action":
            acted = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
            assert acted.status_code == 200, acted.text
        else:
            nxt = wall.line(admin, device)
            nxt.say(t="control", on=True)
            assert nxt.word("control")["on"] is True
            nxt.say(t="k", u=0x04, d=True)
            nxt.say(t="k", u=0x04, d=False)
        let_go = ("hid", {"key": "AltLeft", "state": False})
        wait_until(lambda: let_go in [(name, item if name == "action" else item["event"]) for name, item in timeline], f"Alt was never let go of: {timeline}", timeout=8)
        wait_until(lambda: len(timeline) >= 3, f"what came next never arrived: {timeline}", timeout=8)
        kinds = [(name, item if name == "action" else item["event"]) for name, item in timeline]
        assert kinds.index(let_go) == 1, f"something went to the machine before the last holder's Alt was let go of: {kinds}"


def test_a_tile_edited_while_its_last_holder_who_was_its_only_viewer_is_let_go_of_waits_for_that(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # With no line left to it, the edit closed the machine's connection at once, under the letting go still on its way.
    slow_letting_go(monkeypatch, 1.5)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE2, d=True)
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        line.ws.socket.close()
        wait_until(lambda: [entry.get("why") for entry in wall.audit(admin, "live_control")] == [None, "closed"], "the keyboard was not let go of with the line")
        assert admin.put(f"/api/v1/devices/{device}", json={"url": comet.url, "name": "Renamed"}).status_code == 200
        assert comet.state.hid[1:] == [{"event_type": "key", "event": {"key": "AltLeft", "state": False}}], f"the connection was closed before Alt was let go of: {comet.state.hid}"


def test_an_action_that_waited_for_a_letting_go_while_its_tile_was_removed_sends_nothing_and_says_so(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # It went on to a connection taken away meanwhile and was answered "it may have been done", with that line in the
    # activity log, though nothing was sent. The holder's Alt is let go of only when the test says (within the four seconds
    # a letting go is given): first the action is seen waiting for it, then the tile is seen gone.
    release = threading.Event()
    real_say_key = live.KvmdHid._say_key

    async def held_up(self: live.KvmdHid, usage: int, down: bool) -> None:
        while not down and not release.is_set():
            await asyncio.sleep(0.01)
        await real_say_key(self, usage, down)

    monkeypatch.setattr(live.KvmdHid, "_say_key", held_up)
    waiting = threading.Event()
    real_handed_over = live.Lines.handed_over

    async def noted(self: live.Lines, device_id: str) -> bool:
        waiting.set()
        return await real_handed_over(self, device_id)

    monkeypatch.setattr(live.Lines, "handed_over", noted)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE2, d=True)
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        line.say(t="control", on=False)
        assert line.word("control") == {"t": "control", "on": False}
        answers: list[httpx.Response] = []
        acting = threading.Thread(target=lambda: answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})))
        acting.start()
        assert waiting.wait(5), "the action never came to the wait"
        removed: list[int] = []
        removing = threading.Thread(target=lambda: removed.append(admin.delete(f"/api/v1/devices/{device}").status_code))
        removing.start()
        wait_until(lambda: admin.get("/api/v1/wall").json()["devices"] == [], "the tile was never taken off the wall")
        release.set()  # the Alt is let go of now
        acting.join(10)
        removing.join(10)
        assert removed == [200]
        assert answers, "the action was never answered"
        said = answers[0].json()
        assert answers[0].status_code == 409 and said["code"] == "conflict" and "Nothing was sent" in said["message"], said
        assert comet.state.actions == [], comet.state.actions
        assert comet.state.hid[1:] == [{"event_type": "key", "event": {"key": "AltLeft", "state": False}}], comet.state.hid
        assert wall.audit(admin, "action_failed") == []
        line.closed()


def test_keyboard_and_mouse_are_given_back_after_a_time_without_input_and_the_line_goes_on(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "IDLE_GIVE_BACK", 1.5)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        # Moving the pointer keeps them.
        until = time.monotonic() + 3.0
        x = 100
        while time.monotonic() < until:
            x += 500
            line.say(t="m", x=x, y=100)
            time.sleep(0.4)
        assert not [word for word in line.words if word["t"] == "control"], line.words
        line.say(t="k", u=0xE0, d=True)  # ControlLeft, and whoever held them went away
        wait_until(lambda: any(e["event"].get("key") == "ControlLeft" for e in comet.state.hid if e["event_type"] == "key"), "the key did not arrive")
        given_back = line.word("control", timeout=5)
        assert given_back == {"t": "control", "on": False, "code": "idle", "message": "Given back after 2 seconds without input"}, given_back
        wait_until(lambda: comet.state.hid[-1] == {"event_type": "key", "event": {"key": "ControlLeft", "state": False}}, f"Ctrl stayed down: {comet.state.hid}")
        # The line goes on showing the machine, and takes them again with a clock begun anew.
        line.say(t="key_frame")
        assert line.picture().kind == 2
        line.say(t="control", on=True)
        assert line.word("control") == {"t": "control", "on": True}
        line.say(t="k", u=0x04, d=True)
        line.say(t="k", u=0x04, d=False)
        wait_until(lambda: comet.state.hid[-1]["event"] == {"key": "KeyA", "state": False}, f"the key did not arrive: {comet.state.hid}")
        wait_until(lambda: [entry.get("why") for entry in wall.audit(admin, "live_control")][:2] == [None, "idle"], "the activity log does not say they were given back for no input")
        line.close()


# --- who may still be on the line -----------------------------------------------------------------------------


def test_a_line_ends_when_its_sign_in_does(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        made = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"})
        olga_id = made.json()["user"]["id"]
        olga = wall.browser("olga", "olga may act here")
        line = wall.line(olga, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x04, d=True)
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        assert admin.post(f"/api/v1/users/{olga_id}/logout").status_code == 200  # signed out everywhere
        assert line.word("bye")["code"] == "signed_out"
        line.closed()
        wait_until(lambda: len(comet.state.hid) == 2 and comet.state.hid[1]["event"]["state"] is False, "the key she had down was not let go of")

        # A pass she got before is no good after she signed out.
        olga_again = wall.browser("olga", "olga may act here")
        ticket = wall.ticket(olga_again, device)
        assert olga_again.post("/api/v1/logout", json={}).status_code == 200
        late = Viewer(wall, device, ticket)
        assert late.word("bye")["code"] == "signed_out"
        late.closed()


def test_an_account_given_a_lesser_role_keeps_looking_and_loses_the_keys(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        made = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"})
        olga_id = made.json()["user"]["id"]
        olga = wall.browser("olga", "olga may act here")
        line = wall.line(olga, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        assert admin.put(f"/api/v1/users/{olga_id}", json={"name": "olga", "role": "viewer"}).status_code == 200
        taken = line.word("control")
        assert taken == {"t": "control", "on": False, "code": "not_allowed", "message": "Your account may no longer act on this machine"}
        line.say(t="key_frame")
        assert line.picture().kind == 2  # still looking (the screen stands still: the last picture is sent again when asked)
        line.say(t="control", on=True)
        assert line.word("control")["code"] == "not_allowed"
        # ...and limited to other machines, she is off the line.
        assert admin.put(f"/api/v1/users/{olga_id}", json={"name": "olga", "role": "viewer", "devices": []}).status_code == 200
        assert line.word("bye")["code"] == "not_found"
        line.closed()


def test_a_machine_edited_or_removed_ends_its_lines(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        assert line.picture().kind == 2
        assert admin.put(f"/api/v1/devices/{device}", json={"url": comet.url, "name": "Renamed"}).status_code == 200
        assert line.word("bye")["code"] == "gone"
        line.closed()
        line = wall.line(admin, device)
        assert line.picture().kind == 2
        assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
        assert line.word("bye")["code"] == "gone"
        line.closed()
        assert admin.post(f"/api/v1/devices/{device}/live").status_code == 404


def test_one_account_has_so_many_live_pictures_at_once_and_takes_no_pass_of_anybody_elses(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Any viewer could ask for passes by the hundred: the wall kept 256 and let the oldest go, everybody's, and lines were
    # not counted at all.
    monkeypatch.setattr(live, "MOST_LINES_EACH", 3, raising=False)
    monkeypatch.setattr(live, "MOST_PASSES", 4)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        for name in ("olga", "nina"):
            assert admin.post("/api/v1/users", json={"name": name, "role": "viewer", "password": f"{name} looks only"}).status_code == 201
        first, second = wall.line(admin, device), wall.line(admin, device)
        kept = wall.ticket(admin, device)  # two lines open and a pass: three
        refused = admin.post(f"/api/v1/devices/{device}/live")
        assert refused.status_code == 429, f"the account was given a fourth: {refused.text}"
        assert refused.json()["code"] == "busy" and int(refused.headers["Retry-After"]) > 0, refused.text
        olga = wall.browser("olga", "olga looks only")
        theirs = [wall.ticket(olga, device) for _ in range(3)]  # another account's are its own; and the wall has four passes out now
        nina = wall.browser("nina", "nina looks only")
        full = nina.post(f"/api/v1/devices/{device}/live")
        assert (full.status_code, full.json()["code"]) == (429, "busy"), "a pass was given by taking another's"
        # Nobody's pass was taken to make room: each still opens its line.
        for ticket in (kept, *theirs):
            line = Viewer(wall, device, ticket)
            assert line.picture().kind == 2
            line.close()
        # A line closed, and the account may open another.
        first.close()
        wait_until(lambda: admin.post(f"/api/v1/devices/{device}/live").status_code == 200, "a line that was closed is still counted")
        second.close()


def test_a_key_frame_asked_for_again_and_again_sends_the_last_picture_once_in_a_while(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device, max_fps=5)
        assert line.picture().kind == 2
        for _ in range(200):
            line.say(t="key_frame")
        came, until = 0, time.monotonic() + 1.5
        while time.monotonic() < until:
            try:
                if isinstance(line.next(max(0.01, until - time.monotonic())), Picture):
                    came += 1
            except TimeoutError:
                break
        assert 1 <= came <= 4, f"the still screen's picture was sent {came} times for 200 askings"
        line.close()


def test_a_wall_screen_may_look_and_a_locked_wall_gives_no_pass(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        key = admin.post("/api/v1/tokens", json={"name": "screen", "kind": "display"}).json()["token"]
        screen = httpx.Client(base_url=wall.url, headers=CSRF, timeout=10)
        wall.clients.append(screen)
        assert screen.post("/api/v1/display", json={"key": key}).status_code == 200
        line = wall.line(screen, device)
        assert line.picture().kind == 2
        line.say(t="control", on=True)
        assert line.word("control")["code"] == "not_allowed"
        line.close()
        # A token for a script may, as its role says.
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        script = httpx.Client(base_url=wall.url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        wall.clients.append(script)
        line = wall.line(script, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.close()
    # Started so that nothing opens the saved passwords until somebody signs in: the screen's link gets it a session, and no pass.
    with Wall(tmp_path, locked_start=True) as wall:
        screen = httpx.Client(base_url=wall.url, headers=CSRF, timeout=10)
        wall.clients.append(screen)
        assert screen.post("/api/v1/display", json={"key": key}).status_code == 200
        refused = screen.post(f"/api/v1/devices/{device}/live")
        assert refused.status_code == 503 and refused.json()["code"] == "locked"


# --- the other families --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
def test_a_jetkvm_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hidrpc: bool) -> None:
    no_long_handshake(monkeypatch, hidrpc)  # (the JSON-RPC one: an older JetKVM, which leaves hidrpc unanswered)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, colour=(30, 90, 110), width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=20)
            video = line.word("video", timeout=20)
            assert video == {"t": "video", "codec": "jpeg", "w": 640, "h": 360}
            first = line.picture(timeout=20)
            assert first.kind == 2 and first.key and first.data[:2] == b"\xff\xd8"
            second = line.picture()
            assert second.counter == first.counter + 1 and second.data != first.data  # (the bar moves)
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)  # ControlLeft: bit 0 of the modifiers
            line.say(t="k", u=0x04, d=True)
            line.say(t="k", u=0x04, d=False)
            line.say(t="m", x=100, y=200)
            line.say(t="mb", b=1, d=True)
            line.say(t="mw", dx=0, dy=1)
            line.say(t="up")
            # (Read meanwhile, as a browser reads it; and given a minute: over JSON-RPC one report a round trip, which a busy
            # computer took two seconds over, and these are eight.)
            line.until(lambda: len(jet.state.reports) >= 4 and len(jet.state.mouse) >= 4, f"the JetKVM got {jet.state.reports} and {jet.state.mouse}", timeout=60)
            assert jet.state.reports == [(1, []), (1, [4]), (1, []), (0, [])]
            if hidrpc:
                # (The wheel, which a JetKVM has not got on hidrpc, goes over JSON-RPC, and may be done before or after
                # the mouse reports around it, as from its own page.)
                assert [report for report in jet.state.mouse if report[0] == "abs"] == [("abs", 100, 200, 0), ("abs", 100, 200, 1), ("abs", 100, 200, 0)]
                assert ("wheel", 0, 1) in jet.state.mouse
                assert jet.state.hid_sent[0] == bytes([0x01, 0x01]), jet.state.hid_sent[:3]  # (the handshake first)
            else:
                assert jet.state.mouse == [("abs", 100, 200, 0), ("abs", 100, 200, 1), ("wheel", 0, 1), ("abs", 100, 200, 0)]
                assert jet.state.hid_sent == []
            line.say(t="control", on=False)
            assert line.word("control") == {"t": "control", "on": False}
            line.close()
    finally:
        jet.stop()


def test_a_servers_screen_live_with_its_keys_and_the_pointer(tmp_path: Path) -> None:
    # A server whose controller is AMI's takes keyboard and mouse over the same console the screen comes on, like a KVM.
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=5)])).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            line = wall.line(admin, device, max_fps=5)
            assert line.word("video", timeout=20) == {"t": "video", "codec": "jpeg", "w": 640, "h": 480}
            came = line.picture(timeout=20)
            assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            line.say(t="k", u=0xE1, d=True)  # ShiftLeft: a modifier bit
            line.say(t="k", u=0x04, d=True)  # a
            line.say(t="k", u=0x04, d=False)
            line.say(t="m", x=32767, y=16384)  # the pointer, as an absolute place over the screen
            line.say(t="mb", b=1, d=True)
            line.say(t="mb", b=1, d=False)
            line.say(t="mw", dx=0, dy=1)

            def keys() -> list[Any]:
                return [h for h in bmc.state.hid if h[0] == "key"]

            def mouse() -> list[Any]:
                return [h for h in bmc.state.hid if h[0] == "abs"]

            wait_until(lambda: len(keys()) >= 3 and len(mouse()) >= 4, f"keys/mouse did not all arrive: {bmc.state.hid}")
            assert keys()[0] == ("key", 0x02, []) and ("key", 0x02, [0x04]) in keys()  # Shift alone, then Shift+a; each report the whole keyboard
            assert ("abs", 1, 32767, 16384, 0) in mouse() and ("abs", 0, 32767, 16384, 1) in mouse()  # the pointer at the place, with the left button and with the wheel
            assert bmc.state.bad_hid == []
            # Its USB keyboard is not left with Shift down under somebody's hands: the keyboard is given back first.
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
            assert (refused.status_code, refused.json()["code"]) == (409, "busy") and refused.json().get("by") == "admin"
            line.close()  # with Shift still down: let go of on the server
            wait_until(lambda: keys()[-1] == ("key", 0, []), f"Shift was not let go of: {bmc.state.hid}")
    finally:
        bmc.stop()


SOMEBODY = b"admin".ljust(64, b"\0") + b"192.168.1.60".ljust(70, b"\0")  # a person at the controller's own page, as the console names them


def test_whoever_is_let_in_to_a_servers_console_gets_it_with_nothing_held_and_the_line_types_no_more(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a review: a person who opened the server's own console was let in at once, and the line that held the
    # keyboard went on typing over the wall's session, its Ctrl still down under their hands. What the line had down
    # is let go of before the console is given, nothing more of the line's goes, and its next key takes the keyboard from
    # it. Nor does the tile offer keys while the console is theirs.
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0.3)
    monkeypatch.setattr(redfish, "CONSOLE_IDLE", 2.0)
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=9)])).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            line.say(t="k", u=0xE0, d=True)  # ControlLeft, held
            line.say(t="m", x=1000, y=2000)
            line.say(t="mb", b=1, d=True)  # and the left button, held (a drag)
            wait_until(lambda: ("abs", 1, 1000, 2000, 0) in bmc.state.hid, f"Ctrl and the button never went down: {bmc.state.hid}")
            bmc.state.asks.append((ami.SHARING, SOMEBODY))
            wait_until(lambda: len(bmc.state.answers) == 2, "whoever asked for the console was left waiting")
            heard = [kind for kind, _, _ in bmc.state.heard]
            given = heard.index(ami.SHARING)
            assert max(i for i, kind in enumerate(heard) if kind == ami.HID) < given, "a report went after the console was given"
            keys = [h for h in bmc.state.hid if h[0] == "key"]
            mouse = [h for h in bmc.state.hid if h[0] == "abs"]
            assert keys[-1] == ("key", 0, []), f"Ctrl was not let go of before the console was given: {bmc.state.hid}"
            assert mouse[-1] == ("abs", 0, 1000, 2000, 0), f"the button was not let go of, where it was: {bmc.state.hid}"
            reports = len(bmc.state.hid)
            line.say(t="k", u=0x04, d=True)  # the line types on: nothing goes, and it has the keyboard no more
            refused = line.word("control")
            assert refused["on"] is False and refused["code"] == "in_use", refused
            time.sleep(0.5)
            assert len(bmc.state.hid) == reports, f"the line's key went to the console after it was given: {bmc.state.hid}"
            wait_until(lambda: "keys" not in admin.get("/api/v1/status").json()[device]["can"], "keys are still offered on a console that is somebody else's")
            # Nor does anything go when the wall's session ends (found by the third review: the refused key above was
            # noted as down, and let go of into the console that was theirs).
            line.close()
            wait_until(lambda: bmc.state.watching == 0, "the wall's session never ended", timeout=15)
            heard = [kind for kind, _, _ in bmc.state.heard]
            assert max(i for i, kind in enumerate(heard) if kind == ami.HID) < given, f"a report went into the console after it was given: {bmc.state.hid}"
    finally:
        bmc.stop()


def a_server_line_with_control(wall: Any, bmc: FakeBmc) -> Any:
    admin = wall.browser()
    device = wall.add(admin, bmc.url, kind="redfish")
    line = wall.line(admin, device, max_fps=5)
    assert line.picture(timeout=20).kind == 2
    line.say(t="control", on=True)
    assert line.word("control") == {"t": "control", "on": True}
    return line


def test_the_console_said_to_be_ours_again_changes_nothing_for_the_line_that_holds_it(tmp_path: Path) -> None:
    # Found by the second review: told "the console is yours" while it already was, the wall began a new era of input;
    # the line that held Ctrl could no longer let it go, and nothing else did. Ctrl repeated on the server.
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=13)])).start()
    try:
        with Wall(tmp_path) as wall:
            line = a_server_line_with_control(wall, bmc)
            line.say(t="k", u=0xE0, d=True)  # ControlLeft, held
            wait_until(lambda: ("key", 0x01, []) in bmc.state.hid, f"Ctrl never went down: {bmc.state.hid}")
            answers = sum(1 for kind, _, _ in bmc.state.heard if kind == ami.FULL_SCREEN)
            # (Followed by "who else is there", which the wall answers: once that answer is in, the word before it was read.)
            bmc.state.says.extend([(ami.NEXT_HOLDER, ami.BECAME_MASTER, b""), (ami.OTHERS, 0, bytes(134))])
            wait_until(lambda: sum(1 for kind, _, _ in bmc.state.heard if kind == ami.FULL_SCREEN) > answers, "the wall never read what the console said")
            line.say(t="k", u=0xE0, d=False)
            wait_until(lambda: bmc.state.hid[-1] == ("key", 0, []), f"Ctrl stayed down: {bmc.state.hid}")
            line.say(t="k", u=0x04, d=True)  # and the line still has the keyboard
            wait_until(lambda: ("key", 0, [0x04]) in bmc.state.hid, f"the line lost the keyboard: {bmc.state.hid}")
            line.close()
    finally:
        bmc.stop()


def test_a_servers_console_switched_to_another_session_takes_the_keyboard_from_the_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The console says it was switched to another (SHARING, low byte 6). What the line had down is let go of at once
    # (a key left down repeats; an empty report can at most lift for a moment a key the newcomer holds, which their
    # next report puts down again), and after that nothing more of the wall's goes, the session's end included.
    monkeypatch.setattr(redfish, "CONSOLE_IDLE", 2.0)
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=15)])).start()
    try:
        with Wall(tmp_path) as wall:
            line = a_server_line_with_control(wall, bmc)
            line.say(t="k", u=0xE1, d=True)  # ShiftLeft, held
            wait_until(lambda: ("key", 0x02, []) in bmc.state.hid, f"Shift never went down: {bmc.state.hid}")
            answers = sum(1 for kind, _, _ in bmc.state.heard if kind == ami.FULL_SCREEN)
            # (Followed by "who else is there", which the wall answers: once that answer is in, the word before it was read.)
            bmc.state.says.extend([(ami.SHARING, ami.BECAME_MASTER, b""), (ami.OTHERS, 0, bytes(134))])
            wait_until(lambda: sum(1 for kind, _, _ in bmc.state.heard if kind == ami.FULL_SCREEN) > answers, "the wall never read what the console said")
            assert bmc.state.hid[-1] == ("key", 0, []), f"Shift was not let go of: {bmc.state.hid}"
            reports = len(bmc.state.hid)
            line.say(t="k", u=0x04, d=True)
            refused = line.word("control")
            assert refused["on"] is False and refused["code"] == "in_use", refused
            line.close()
            wait_until(lambda: bmc.state.watching == 0, "the wall's session never ended", timeout=15)
            assert len(bmc.state.hid) == reports, f"a report went to a console that is another's: {bmc.state.hid}"
    finally:
        bmc.stop()


def test_a_console_that_says_its_pass_was_taken_twice_is_left_and_what_was_down_let_go_of(tmp_path: Path) -> None:
    # Found by the third review: a second word on the pass in one session ended input and left a held key down for as
    # long as the tile was watched. The session ends there, and what was down is let go of before its goodbye.
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=17)])).start()
    try:
        with Wall(tmp_path) as wall:
            line = a_server_line_with_control(wall, bmc)
            line.say(t="k", u=0x04, d=True)  # a, held
            wait_until(lambda: ("key", 0, [0x04]) in bmc.state.hid, f"a never went down: {bmc.state.hid}")
            bmc.state.says.append((ami.PASS_SEEN, 0, bytes([1, 0])))
            wait_until(lambda: ami.STOP in [kind for kind, _, _ in bmc.state.heard], "the wall stayed in that session", timeout=10)
            assert bmc.state.hid[-1] == ("key", 0, []), f"a was not let go of: {bmc.state.hid}"
            line.close()
    finally:
        bmc.stop()


def test_giving_a_servers_keyboard_back_does_not_move_its_pointer(tmp_path: Path) -> None:
    # Found by a review: giving the keyboard back sent the pointer to the top left corner, where it had never been put
    # (a desktop opens a menu there). Where no button can be down, no mouse report goes at all.
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=11)])).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            line.say(t="k", u=0x04, d=True)
            line.say(t="k", u=0x04, d=False)
            wait_until(lambda: bmc.state.hid.count(("key", 0, [])) >= 1, f"the key never came: {bmc.state.hid}")
            line.say(t="control", on=False)
            assert line.word("control")["on"] is False
            wait_until(lambda: bmc.state.hid.count(("key", 0, [])) >= 2, f"the keyboard was not let go of: {bmc.state.hid}")
            time.sleep(0.5)
            assert not [h for h in bmc.state.hid if h[0] in ("abs", "rel")], f"the pointer was moved: {bmc.state.hid}"
            line.close()
    finally:
        bmc.stop()


def test_a_server_whose_mouse_is_relative_gets_relative_moves(tmp_path: Path) -> None:
    # Absolute is what AMI's own viewer sends and most boards default to. A board set to a relative mouse says so,
    # and then the pointer goes as a move, not a place.
    bmc = FakeBmc(BmcState(own_console=True, screen=[console_screen(640, 480, seed=7)], mouse_mode=ami.RELATIVE)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            line.say(t="mr", dx=5, dy=-3)
            wait_until(lambda: ("rel", 0, 5, -3, 0) in bmc.state.hid, f"the relative move never arrived: {bmc.state.hid}")
            assert bmc.state.bad_hid == []
            line.close()
    finally:
        bmc.stop()


def test_a_line_outlives_the_clock_of_the_request_that_opened_it(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # A connection has HEADERS_WITHIN to say what it wants. The line's own request said it, and was handed on to the
    # WebSocket: that clock is not the line's, and must not close it. (Every line was closed after twenty seconds.)
    monkeypatch.setattr(cli, "HEADERS_WITHIN", 1.0)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device, max_fps=5)
        assert line.word("video", timeout=10)["codec"] == "jpeg"
        line.picture(timeout=10)
        line.nothing(3.0)  # (a still screen: words of state at the most; and the line still there)
        line.say(t="key_frame")
        assert line.picture(timeout=5).kind == 2  # it answers, three times the clock later
        line.close()


def test_an_amt_pcs_screen_live_with_its_keys_and_pointer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt.AmtScreen, "LIVE_PACE", 0.02)
    pc = FakeAmt(AmtState()).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, pc.url)
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the PC's screen is not said to be there")
            line = wall.line(admin, device, max_fps=5)
            assert line.word("video", timeout=20) == {"t": "video", "codec": "jpeg", "w": 320, "h": 200}
            came = line.picture(timeout=20)
            assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
            pc.state.screen.dirty.append((0, 0, 32, 32))  # something changes on the PC's screen: a picture of it comes
            assert line.picture(timeout=10).counter > came.counter
            # Keys and the pointer, through its KVM, as RFB's own events.
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            line.say(t="k", u=0xE1, d=True)  # ShiftLeft
            line.say(t="k", u=0x04, d=True)
            line.say(t="k", u=0x04, d=False)
            line.say(t="m", x=32767, y=16384)
            line.say(t="mb", b=1, d=True)
            line.say(t="mb", b=1, d=False)
            line.say(t="mw", dx=0, dy=1)
            screen = pc.state.screen
            wait_until(lambda: len(screen.pointers) >= 5 and len(screen.keys) >= 3, f"the PC got {screen.keys} {screen.pointers}")
            assert screen.keys == [(0xFFE1, True), (0x61, True), (0x61, False)]
            assert screen.pointers == [(319, 99, 0), (319, 99, 1), (319, 99, 0), (319, 99, 8), (319, 99, 0)]
            # Its KVM is not switched off under somebody's hands (Shift is still down): first the keyboard is given back.
            refused = admin.post(f"/api/v1/devices/{device}/kvm", json={"on": False})
            assert (refused.status_code, refused.json()["code"]) == (409, "busy") and pc.state.changes == []
            assert refused.json().get("by") == "admin" and refused.json()["message"].startswith("admin has "), refused.text
            line.close()  # with Shift still down: let go of on the PC
            wait_until(lambda: screen.keys[-1] == (0xFFE1, False), f"Shift was not let go of: {screen.keys}")
    finally:
        pc.stop()


@pytest.mark.parametrize("before_control", [0.0, 3.0])
def test_a_pcs_key_waiting_for_its_next_session_when_the_account_is_signed_out_is_not_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, before_control: float) -> None:
    # An operator holds a PC with Intel AMT. Its engine ends the session at its own time, and Ctrl, pressed just then, waits
    # for the next one, held at transmission until the test releases it. Meanwhile she is signed out everywhere: the line ends, and what it had down
    # is let go of, into no session. (It was decided here that Ctrl then lands in the next session and is let go of after
    # it. The review of 850745e, L-W2: it is asked again once the session is there, and goes nowhere.)
    monkeypatch.setattr(amt.AmtScreen, "LIVE_PACE", 0.02)
    monkeypatch.setattr(amt, "TIMEOUT_SLACK", 60.0)
    pending, deliver = threading.Event(), threading.Event()
    say_key = live.RfbHid._say_key

    async def held_key(self: live.RfbHid, usage: int, down: bool) -> None:
        if usage == 0xE0 and down:
            pending.set()
            async with asyncio.timeout(20):
                while not deliver.is_set():
                    await asyncio.sleep(0.01)
        await say_key(self, usage, down)

    monkeypatch.setattr(live.RfbHid, "_say_key", held_key)
    expire = threading.Event()
    pc = FakeAmt(AmtState(session_timeout=1, next_session_ends_when=expire)).start()
    screen = pc.state.screen
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, pc.url)
            olga_id = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).json()["user"]["id"]
            olga = wall.browser("olga", "olga may act here")
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the PC's screen is not said to be there")
            line = wall.line(olga, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            time.sleep(before_control)
            line.say(t="control", on=True)
            assert line.word("control") == {"t": "control", "on": True}
            # End the established session on purpose, after startup/control. A
            # short timer could expire before startup or between polling turns.
            ended_at, sessions = pc.state.session_ended_at, pc.state.kvm_sessions
            pc.state.next_session_starts_when = deliver
            expire.set()
            wait_until(lambda: pc.state.session_ended_at > ended_at, "the engine never ended its session", timeout=10)
            line.say(t="k", u=0xE0, d=True)  # ControlLeft: waits for the next session
            assert pending.wait(5), "the key did not enter transmission before sign-out"
            assert admin.post(f"/api/v1/users/{olga_id}/logout").status_code == 200
            assert line.word("bye", timeout=10)["code"] == "signed_out"
            assert pc.state.kvm_open == 0, "the replacement session opened before sign-out cleanup"
            assert (0xFFE3, True) not in screen.keys, "Ctrl landed before the line ended: this is not the case this test is for"
            deliver.set()
            wait_until(lambda: pc.state.kvm_sessions > sessions, "Ctrl did not wait for a new session", timeout=15)
            time.sleep(1.0)  # (time for Ctrl to arrive, were it sent)
            assert (0xFFE3, True) not in screen.keys, f"Ctrl went to the PC after the sign-out: {screen.keys}"
    finally:
        deliver.set()
        pc.stop()


def test_a_server_without_a_console_the_wall_reads_has_no_live_picture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.1, 0.1, 0.1, 0.1))
    bmc = FakeBmc(BmcState()).start()  # another make: Redfish, and no console qKVM reads
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            line = wall.line(admin, device)
            assert line.word("bye", timeout=20)["code"] == "no_live"
            line.closed()
            refused = admin.post(f"/api/v1/devices/{device}/live")
            assert refused.status_code == 404 and refused.json()["code"] == "no_live"
    finally:
        bmc.stop()


def test_a_jetkvms_keys_are_let_go_of_when_its_tile_is_removed(tmp_path: Path) -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0x04, d=True)
            line.say(t="m", x=10, y=10)
            line.say(t="mb", b=1, d=True)
            wait_until(lambda: jet.state.reports[-1:] == [(0, [4])] and jet.state.mouse[-1:] == [("abs", 10, 10, 1)], f"the key and the button did not arrive: {jet.state.reports} {jet.state.mouse}")
            # The tile is taken off the wall: before its connection to the JetKVM goes, what the line had down is let go of through it.
            # (Over hidrpc, where the JetKVM answers nothing: the wall has it leave before it closes the connection, and the
            # JetKVM does it once it has read it, which under load was a few tenths of a second after the removal was
            # answered. So it is waited for: `reports` and `mouse` hold only what came from the wall, never what the
            # stand-in let go of by itself, and a mouse button it never lets go of by itself; and nothing can come over a
            # connection after it was closed.)
            assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
            wait_until(lambda: jet.state.reports[-1] == (0, []) and jet.state.mouse[-1] == ("abs", 10, 10, 0), f"the key and the button were not let go of: {jet.state.reports} {jet.state.mouse}")
            assert line.word("bye")["code"] == "gone"
            line.closed()
    finally:
        jet.stop()


def test_a_pass_is_for_the_address_it_was_given_to(tmp_path: Path, comet: FakeKvm) -> None:
    # Behind a proxy that is believed about who is calling: the pass goes to one address, the line comes from another.
    with Wall(tmp_path, trusted_proxies=["127.0.0.1"]) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        olga = httpx.Client(base_url=wall.url, headers={**CSRF, "X-Forwarded-For": "192.0.2.5"}, timeout=10)
        wall.clients.append(olga)
        assert olga.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        elsewhere = Viewer(wall, device, wall.ticket(olga, device), headers={"X-Forwarded-For": "192.0.2.6"})
        assert elsewhere.word("bye")["code"] == "no_pass"
        elsewhere.closed()
        same = Viewer(wall, device, wall.ticket(olga, device), headers={"X-Forwarded-For": "192.0.2.5"})
        assert same.picture().kind == 2
        same.close()


def test_a_token_taken_back_ends_its_line(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        made = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()
        script = httpx.Client(base_url=wall.url, headers={"Authorization": f"Bearer {made['token']}"}, timeout=10)
        wall.clients.append(script)
        line = wall.line(script, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x04, d=True)
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        assert admin.delete(f"/api/v1/tokens/{made['record']['id']}").status_code == 200
        assert line.word("bye")["code"] == "signed_out"
        line.closed()
        wait_until(lambda: len(comet.state.hid) == 2 and comet.state.hid[1]["event"]["state"] is False, "the key was not let go of")


def test_a_key_frame_sent_without_its_parameter_sets_gets_them(tmp_path: Path) -> None:
    once = FakeKvm(FakeState(media=True, fps=30.0, film=made_up_film(1500, pictures=30, key_every=5, parameter_sets="first"))).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, once.url)
            viewer = wall.line(admin, device)
            keys = 0
            for _ in range(40):
                came = viewer.picture()
                if came.key:
                    keys += 1
                    assert came.data.startswith(b"\x00\x00\x00\x01\x09\xf0" + MADE_UP_SPS + MADE_UP_PPS + b"\x00\x00\x00\x01\x65"), came.data[:40]
                else:
                    assert MADE_UP_SPS not in came.data
            assert keys >= 6
            viewer.close()
    finally:
        once.stop()


# --- what a hostile or broken client can do, and cannot ------------------------------------------------------


def test_a_viewer_that_stops_reading_loses_the_keyboard_and_the_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "STUCK_AFTER", 2.0)
    fast_kvm = FakeKvm(FakeState(media=True, fps=200.0, unit_bytes=60_000, film=made_up_film(60_000, pictures=40, key_every=20))).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, fast_kvm.url)
            stuck = wall.line(admin, device)
            assert stuck.picture().key
            stuck.say(t="control", on=True)
            assert stuck.word("control")["on"] is True
            stuck.say(t="k", u=0x04, d=True)
            wait_until(lambda: len(fast_kvm.state.hid) == 1, "the key did not arrive")
            began = time.monotonic()
            # It reads nothing from here on. Twelve megabytes a second fill what the system holds, and the wall
            # is left with a line that takes nothing: hung up on, and the key let go of.
            wait_until(lambda: len(fast_kvm.state.hid) == 2 and fast_kvm.state.hid[1]["event"]["state"] is False, "the key stayed down", timeout=20)
            assert time.monotonic() - began < 15
            other = wall.line(admin, device)
            other.say(t="control", on=True)
            assert other.word("control")["on"] is True, "the keyboard stayed with the line that reads nothing"
            other.close()
            stuck.closed(timeout=10)
    finally:
        fast_kvm.stop()


def test_a_client_that_sends_pings_and_reads_nothing_is_hung_up_on(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        raw = Raw(wall, device)  # no pass, no hello: the web server answers pings all the same
        ping = raw.frame(9, b"x" * 100)
        began, sent = time.monotonic(), 0
        try:
            while time.monotonic() - began < 10:
                raw.sock.sendall(ping * 100)
                sent += 100
        except OSError:
            pass  # hung up on
        assert time.monotonic() - began < 10, f"{sent} pings were answered without end"
        # The line is closed. What the wall sent before it hung up comes first where the system hands it over
        # (Linux does; Windows throws it away once the reset lands): nothing but its answers to the pings, and
        # then the end, never another word.
        deadline, opcode = time.monotonic() + 10, 10
        while opcode == 10:  # a pong
            assert time.monotonic() < deadline, "the wall's answers to the pings did not end"
            opcode = raw.next()[0]
        assert opcode in (-1, 8), opcode
        raw.close()
        # The wall is as it was: a line with a pass works.
        line = wall.line(admin, device)
        assert line.picture().kind == 2
        line.close()


def sent_until_hung_up(raw: Raw, chunk: bytes, seconds: float) -> float:
    """Send this again and again, for as long as the wall takes it: the seconds until it hung up (or `seconds`, if it never did)."""
    began = time.monotonic()
    try:
        while time.monotonic() - began < seconds:
            raw.sock.sendall(chunk)
    except OSError:
        pass  # hung up on
    return time.monotonic() - began


@pytest.mark.parametrize("flood", ["pieces of a message that never ends", "pongs nobody asked for", "messages after the line was closed"])
def test_frames_the_program_is_not_handed_are_counted_and_a_flood_of_them_is_hung_up_on(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch, flood: str) -> None:
    # Before any pass is shown: anybody who reaches the port. The web server kept every piece of a message for the message
    # (two million pieces of no bytes in four seconds), and read pongs and whatever came after it closed a line without a
    # count; the program counts only the messages it is handed.
    monkeypatch.setattr(live, "HELLO_WITHIN", 30.0)  # (the line is not turned away for showing no pass while this goes on)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        raw = Raw(wall, device)
        if flood == "pieces of a message that never ends":
            raw.sock.sendall(raw.frame(1, b"{", fin=False))
            chunk = raw.frame(0, b"", fin=False) * 200
        elif flood == "pongs nobody asked for":
            chunk = raw.frame(10, b"") * 200
        else:
            raw.say(**HELLO, ticket="x" * 32)  # no pass: told so, and the line closed
            chunk = raw.frame(1, b"{}") * 200
        took = sent_until_hung_up(raw, chunk, 10)
        assert took < 4, f"{flood}: sent for {took:.1f} s without being hung up on"
        raw.close()
        # The wall is as it was: a line with a pass works.
        line = wall.line(admin, device)
        assert line.picture().kind == 2
        line.close()


def test_a_message_in_more_pieces_than_any_client_sends_one_is_hung_up_on(tmp_path: Path, comet: FakeKvm) -> None:
    def in_pieces(raw: Raw, text: str, pieces: int) -> None:
        data = text.encode()
        cut = [data[at * len(data) // pieces : (at + 1) * len(data) // pieces] for at in range(pieces)]
        for number, piece in enumerate(cut):
            raw.sock.sendall(raw.frame(1 if number == 0 else 0, piece, fin=number == pieces - 1))

    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        sixteen = Raw(wall, device)
        in_pieces(sixteen, json.dumps({**HELLO, "ticket": wall.ticket(admin, device)}), 16)  # (live.MOST_PIECES)
        opcode, said = sixteen.next()
        assert opcode == 1 and json.loads(said)["t"] in ("state", "video"), "a hello in sixteen pieces was not taken"
        sixteen.close()
        seventeen = Raw(wall, device)
        in_pieces(seventeen, json.dumps({**HELLO, "ticket": wall.ticket(admin, device)}), 17)
        assert seventeen.next() == (-1, b""), "a hello in seventeen pieces was let in"
        seventeen.close()


def test_a_line_that_answers_no_ping_is_dropped_and_not_left_to_close(tmp_path: Path) -> None:
    # The web server closes a line whose pings went unanswered, and a close waits for what is still to be sent to be taken:
    # from a computer that vanished, never. The program heard of the end only once the system gave up on the connection,
    # minutes later, and kept the machine's keyboard and the keys down for it meanwhile.
    class Transport:
        def __init__(self) -> None:
            self.done: list[str] = []

        def get_extra_info(self, name: str, default: Any = None) -> Any:
            return ("127.0.0.1", 50000) if name in ("sockname", "peername") else default

        def write(self, data: bytes) -> None:
            pass

        def get_write_buffer_size(self) -> int:
            return 4096  # (something unsent, which nobody takes)

        def is_closing(self) -> bool:
            return bool(self.done)

        def close(self) -> None:
            self.done.append("closed")

        def abort(self) -> None:
            self.done.append("aborted")

    async def run() -> list[str]:
        async def app(scope: Any, receive: Any, send: Any) -> None:
            pass

        config = uvicorn.Config(app, **{**cli.SERVER_OPTIONS, "log_level": "error"})
        config.load()
        line = cli.Line(config=config, server_state=uvicorn.server.ServerState(), app_state={})
        transport = Transport()
        line.connection_made(transport)  # type: ignore[arg-type]
        line.keepalive_timeout()  # (the third ping unanswered)
        return transport.done

    assert asyncio.run(run()) == ["aborted"]


def test_whatever_goes_wrong_in_a_lines_goodbye_as_the_web_server_stops_the_stop_goes_on() -> None:
    # The web server's stop says goodbye on its connections one after the other, and one that raises ends it: the ones
    # after it are not told, and the program's own stop (the lines' letting go, the devices closed) never runs.
    class Transport:
        def __init__(self) -> None:
            self.done: list[str] = []

        def get_extra_info(self, name: str, default: Any = None) -> Any:
            return ("127.0.0.1", 50000) if name in ("sockname", "peername") else default

        def write(self, data: bytes) -> None:
            pass

        def is_closing(self) -> bool:
            return bool(self.done)

        def close(self) -> None:
            self.done.append("closed")

        def abort(self) -> None:
            self.done.append("aborted")

    async def run() -> list[str]:
        async def app(scope: Any, receive: Any, send: Any) -> None:
            pass

        config = uvicorn.Config(app, **{**cli.SERVER_OPTIONS, "log_level": "error"})
        config.load()
        line = cli.Line(config=config, server_state=uvicorn.server.ServerState(), app_state={})
        transport = Transport()
        line.connection_made(transport)  # type: ignore[arg-type]
        line.handshake_complete = True

        def broken(*given: Any) -> None:
            raise RuntimeError("something nobody foresaw")

        line.conn.send_close = broken  # type: ignore[method-assign]
        line.shutdown()
        return transport.done

    assert asyncio.run(run())[:1] == ["aborted"]


def test_what_is_sent_down_a_line_waits_while_its_viewer_is_not_taking_it_whichever_web_server() -> None:
    # The web server before some version after 0.46 (which qKVM still runs on, pyproject.toml) never made a send wait:
    # everything sent to a viewer that read nothing piled up in the wall's memory, a viewer that fell behind was never
    # brought forward to a key frame, and one that read nothing was never told it was not reading (`slow`).
    class Transport:
        def get_extra_info(self, name: str, default: Any = None) -> Any:
            return ("127.0.0.1", 50000) if name in ("sockname", "peername") else default

        def write(self, data: bytes) -> None:
            pass

        def get_write_buffer_size(self) -> int:
            return 0

        def is_closing(self) -> bool:
            return False

        def close(self) -> None:
            pass

        def abort(self) -> None:
            pass

    async def run() -> list[bool]:
        async def app(scope: Any, receive: Any, send: Any) -> None:
            pass

        config = uvicorn.Config(app, **{**cli.SERVER_OPTIONS, "log_level": "error"})
        config.load()
        line = cli.Line(config=config, server_state=uvicorn.server.ServerState(), app_state={})
        line.connection_made(Transport())  # type: ignore[arg-type]
        seen = [line.writable.is_set()]
        line.pause_writing()  # (more waits to be sent than is kept ready)
        seen.append(line.writable.is_set())
        line.resume_writing()
        seen.append(line.writable.is_set())
        line.pause_writing()
        line.connection_lost(None)  # (and a send that waits is let go once the connection is gone)
        seen.append(line.writable.is_set())
        return seen

    assert asyncio.run(run()) == [True, False, True, True]


def test_what_a_line_says_is_never_in_the_log_whatever_the_web_servers_level(tmp_path: Path, comet: FakeKvm) -> None:
    # At its finer levels the WebSocket library writes every frame, the pass in the first one and every key after it, to the
    # logger it is given: the web server's, at whatever level qKVM was started with (`--log-level debug`). (And whatever was
    # set on a logger of the line's own before: the stand-ins' web servers have configured the web server's loggers anew
    # since, as any logging configuration given later does, which sets the loggers below them back to no level.)
    heard: list[str] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            heard.append(f"{record.name}: {record.getMessage()}")

    hearing, web = Heard(logging.DEBUG), logging.getLogger("uvicorn.error")
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        was = web.level
        web.setLevel(logging.DEBUG)
        web.addHandler(hearing)
        logging.getLogger().addHandler(hearing)
        try:
            ticket = wall.ticket(admin, device)
            line = ws_connect(f"ws://127.0.0.1:{wall.port}/api/v1/devices/{device}/live", open_timeout=5)
            line.send(json.dumps({"t": "hello", "ticket": ticket, "v": 2, "video": ["jpeg"]}))
            line.recv(timeout=5)
            line.send(json.dumps({"t": "control", "on": True}))
            line.send(json.dumps({"t": "k", "u": 4, "d": True}))
            wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
            line.close()
            time.sleep(0.3)
        finally:
            web.setLevel(was)
            web.removeHandler(hearing)
            logging.getLogger().removeHandler(hearing)
    said = " | ".join(heard)
    assert ticket[:12] not in said, "the pass is in the log"
    assert '"u": 4' not in said and '"t": "k"' not in said, "a key is in the log"


def test_a_line_that_answers_no_ping_is_closed_and_its_keys_let_go_of(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path, serving={"ws_ping_interval": 0.5, "ws_ping_timeout": 1.5}) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        ticket = wall.ticket(admin, device)
        # (Counted from before the line is opened: no ping goes before that. Counted from the key's arrival, as it was, a
        # busy computer had sent the first ping already, and the line was closed 1.0 s after that clock began.)
        began = time.monotonic()
        raw = Raw(wall, device)
        raw.say(**HELLO, ticket=ticket)
        raw.say(t="control", on=True)
        raw.say(t="k", u=0x04, d=True)
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        # It reads everything and answers no ping (a browser answers them by itself; this one does not).
        closed = False
        while time.monotonic() - began < 20:
            opcode, _ = raw.next(timeout=20)
            if opcode in (8, -1):
                closed = True
                break
            assert opcode in (1, 2, 9), opcode
        assert closed, "the line was not closed after three pings went unanswered"
        # (A ping every half second, each to be answered within a second and a half: not closed before that, and within some
        # seconds more however late the wall is to them.)
        assert 1.5 <= time.monotonic() - began < 15
        wait_until(lambda: len(comet.state.hid) == 2 and comet.state.hid[1]["event"]["state"] is False, "the key stayed down")
        raw.close()


@pytest.mark.filterwarnings("error::pytest.PytestUnhandledThreadExceptionWarning")
@pytest.mark.parametrize("first", ["the viewer", "the wall"])
def test_the_wall_stops_whole_while_a_goodbye_on_a_line_is_still_being_answered(tmp_path: Path, comet: FakeKvm, first: str) -> None:
    # A viewer has stopped reading (pictures wait to be sent to it), and a goodbye is said on its line: by the viewer, or by
    # the wall (a line that floods). The web server closes the connection once what waits is taken. The wall stopping in
    # that moment had the web server say goodbye on it once more, which the library refused (it is closing already), and
    # the refusal stopped the stop: the other connections were not told, and the program's own stop (every line letting
    # go of what it held, every machine's connection closed) never ran.
    fast_kvm = FakeKvm(FakeState(media=True, fps=200.0, unit_bytes=60_000, film=made_up_film(60_000, pictures=40, key_every=20))).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            fast, still = wall.add(admin, fast_kvm.url), wall.add(admin, comet.url)
            holding = wall.line(admin, still)  # somebody else, with a key down on another machine
            holding.say(t="control", on=True)
            assert holding.word("control")["on"] is True
            holding.say(t="k", u=0x07, d=True)
            wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
            # It reads nothing: what is sent to it waits at the wall (a machine whose pictures come by the hundred), or its
            # goodbye from the wall waits to be answered (a still screen: the goodbye goes out, and no answer comes).
            looked_at = fast if first == "the viewer" else still
            raw = Raw(wall, looked_at)
            raw.say(**HELLO, ticket=wall.ticket(admin, looked_at))
            time.sleep(1.0)
            if first == "the viewer":
                raw.sock.sendall(raw.frame(8, struct.pack(">H", 1000)))
            else:
                raw.sock.sendall(raw.frame(1, b"{}") * (live.MOST_A_SECOND + 10))  # (more than a viewer sends: `bye flooding`)
            time.sleep(0.5)
        # The wall has stopped, whole: the other line's key was let go of on its way out.
        assert comet.state.hid[1:] == [{"event_type": "key", "event": {"key": "KeyD", "state": False}}], f"the key stayed down: {comet.state.hid}"
        raw.close()
    finally:
        fast_kvm.stop()


def test_a_source_keeps_its_task_when_one_viewer_leaves_and_another_joins_in_one_turn() -> None:
    async def run() -> None:
        device = KvmDevice(DeviceSpec(id="ab12cd34", name="One", base_url=f"http://127.0.0.1:{closed_port()}", username="admin", password="secret"))
        lines = live.Lines(SimpleNamespace(devices={"ab12cd34": device}), standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]
        machine = live.Machine(lines, "ab12cd34", device)
        holder = live.Holder("u", "u", True, "127.0.0.1")
        first, second = (live.Line(None, holder, machine, frozenset({"jpeg"}), 640, 10) for _ in range(2))  # type: ignore[arg-type]
        source = live.SnapshotSource(machine)
        source.add(first)
        await asyncio.sleep(0.05)
        task = source.task
        assert task is not None and not task.done()
        source.remove(first)
        source.add(second)  # the same turn of the loop
        await asyncio.sleep(0.2)
        assert source.task is task and not task.done() and source.viewers == {second}
        source.remove(second)
        await asyncio.sleep(0.2)
        assert task.done()
        await device.close()

    asyncio.run(run())





def test_what_the_guard_refuses_over_http_the_line_refuses_too(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        where = f"ws://127.0.0.1:{wall.port}/api/v1/devices/{device}/live"
        with pytest.raises(InvalidStatus) as refused:
            ws_connect(where, additional_headers={"Origin": "https://evil.example"}, open_timeout=5)
        assert refused.value.response.status_code == 403
        # A host this wall does not answer to (somebody else's name pointed at it): the handshake written by hand, since
        # the library sends the host of the address.
        with socket.create_connection(("127.0.0.1", wall.port), timeout=5) as raw:
            head = (
                f"GET /api/v1/devices/{device}/live HTTP/1.1|Host: evil.example|Upgrade: websocket|Connection: Upgrade|"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==|Sec-WebSocket-Version: 13||"
            )
            raw.sendall(head.replace("|", "\r\n").encode())
            assert raw.recv(64).startswith(b"HTTP/1.1 403")
        own = ws_connect(where, additional_headers={"Origin": f"http://127.0.0.1:{wall.port}"}, open_timeout=5)
        own.send(json.dumps({**HELLO, "ticket": wall.ticket(admin, device)}))
        assert json.loads(own.recv(timeout=5))["t"] in ("state", "video")
        own.close()


def test_lines_refused_at_the_door_write_nothing_in_the_log(tmp_path: Path, comet: FakeKvm) -> None:
    # Anybody who can reach the port can ask for a line from another site's page. Each is refused; none may be a line
    # in the log (the web server wrote an error for every refusal that was sent as an answer of its own). Listened
    # for on the web server's own logger, which the program sends to its log file (cli.setup_logging): the stand-ins
    # start their web servers with its usual settings, which keep it from reaching the root.
    said: list[str] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            said.append(record.getMessage())

    heard = Heard(logging.WARNING)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        logging.getLogger("uvicorn.error").addHandler(heard)
        try:
            for _ in range(20):
                with pytest.raises(InvalidStatus) as refused:
                    ws_connect(f"ws://127.0.0.1:{wall.port}/api/v1/devices/{device}/live", additional_headers={"Origin": "https://evil.example"}, open_timeout=5)
                assert refused.value.response.status_code == 403
            time.sleep(0.3)
        finally:
            logging.getLogger("uvicorn.error").removeHandler(heard)
    assert said == [], f"{len(said)} lines, the first: {said[:1]}"


def test_what_a_client_sends_that_is_no_word_of_the_line(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        assert line.picture().kind == 2
        line.ws.send(b"\x01\x02\x03")  # bytes: the draft has none from a viewer
        line.ws.send("not json")
        line.ws.send(json.dumps([1, 2, 3]))
        line.ws.send(json.dumps({"t": "something else"}))
        line.ws.send(json.dumps({"t": "control", "on": "yes"}))
        line.ws.send(json.dumps({"t": "shape", "max_w": -5, "max_fps": "many"}))
        line.ws.send(json.dumps({"t": "k", "u": 4, "d": True}))  # not the holder of keyboard and mouse: nothing
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True, "the line went on after what was no word"
        line.close()

        # A message longer than any the line carries ends the line: the web server itself refuses it, unread.
        line = wall.line(admin, device)
        line.ws.send("x" * (live.MOST_WORD + 1))
        line.closed()

        # A flood of messages ends the line, with a word about why.
        line = wall.line(admin, device)
        try:
            for _ in range(3 * live.MOST_A_SECOND):
                line.ws.send(json.dumps({"t": "shape", "max_w": 640}))
        except ConnectionClosed:
            pass  # (closed while the flood was still being sent)
        assert line.word("bye", timeout=10)["code"] == "flooding"
        line.closed()


def test_keyboard_and_mouse_taken_and_given_back_without_end_is_flooding(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        for turn in range(live.MOST_CONTROL_A_MINUTE + 2):
            line.say(t="control", on=turn % 2 == 0)
        assert line.word("bye", timeout=10)["code"] == "flooding"
        line.closed()
        wait_until(lambda: comet.state.key_lines == 0, "the line for keys stayed open")
        # (And the activity log has one line for each taking and giving back that was done, not one for the flood.)
        assert len(wall.audit(admin, "live_control")) <= live.MOST_CONTROL_A_MINUTE + 1


def test_a_key_that_is_no_key_and_a_wheel_turned_a_hundred_times_in_one_word_reach_a_jetkvm_as_nothing_and_sixteen(tmp_path: Path) -> None:
    # A JetKVM is handed the usage itself in its keyboard report: one past the last key (or a made-up 0x1234) went in as it
    # came, and 1 (the keyboard's own "too many keys") makes a Linux host ignore the whole report, a key let go of in it
    # included. One word of the wheel is sixteen turns at the most, as the page says them.
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in (0x01, 0x03, 0xE8, 0x1234, 0xFFFF):
                line.say(t="k", u=usage, d=True)
            line.say(t="k", u=0xE7, d=True)  # MetaRight, the last key there is
            line.say(t="k", u=0x04, d=True)
            wait_until(lambda: jet.state.reports[-1:] == [(0x80, [4])], f"the keys did not arrive: {jet.state.reports}")
            assert jet.state.reports == [(0x80, []), (0x80, [4])], "a usage that is no key went into a keyboard report"
            line.say(t="mw", dx=0, dy=127)
            wait_until(lambda: len(jet.state.mouse) >= 1, f"the wheel did not arrive: {jet.state.mouse}")
            line.say(t="mw", dx=-1000, dy=0)
            wait_until(lambda: len(jet.state.mouse) >= 2, f"the wheel did not arrive: {jet.state.mouse}")
            assert jet.state.mouse == [("wheel", 0, 16), ("wheel", -16, 0)]
            line.close()
    finally:
        jet.stop()


def test_a_wheel_turned_a_hundred_times_in_one_word_is_turned_sixteen_on_a_kvm_and_a_pc(tmp_path: Path, comet: FakeKvm) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="mw", dx=0, dy=127)
        line.say(t="mw", dx=0, dy=-5)
        wait_until(lambda: len(comet.state.hid) >= 2, f"the KVM got {comet.state.hid}")
        assert [event["event"]["delta"] for event in comet.state.hid] == [{"x": 0, "y": 16}, {"x": 0, "y": -5}]
        line.close()

    # Through RFB a turn is a press and a release of a button, two words to the PC for each: one word of the line was 254.
    class Pc:
        kind, label, spec = "amt", "PC", SimpleNamespace(name="PC", id="d1")

        def __init__(self) -> None:
            self.pointers: list[int] = []

        async def input_ready(self) -> None:
            pass

        def screen_size(self) -> tuple[int, int]:
            return (320, 200)

        async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False, still: Any = None) -> None:
            self.pointers.append(buttons)

    async def turned() -> list[int]:
        pc = Pc()
        lines = live.Lines(SimpleNamespace(devices={}), standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]
        machine = live.Machine(lines, "d1", pc)  # type: ignore[arg-type]
        holder = live.Line(None, live.Holder("u", "u", True, "127.0.0.1"), machine, frozenset({"jpeg"}), 640, 10)  # type: ignore[arg-type]
        machine.viewers.add(holder)
        assert (await machine.control(holder, True))["on"] is True
        await machine.input(holder, {"t": "mw", "dx": 0, "dy": 127})
        return pc.pointers

    assert asyncio.run(turned()) == [8, 0] * live.MOST_NOTCHES


def test_a_place_said_between_two_sessions_lands_where_it_was_put() -> None:
    # Between two sessions (the engine ended one at its own time) the size of the PC's screen is not known: a place was worked
    # out against a screen of one pixel, the top left corner, and the click or the end of a drag that followed landed there.
    class Pc:
        kind, label, spec = "amt", "PC", SimpleNamespace(name="PC", id="d1")

        def __init__(self) -> None:
            self.session = True
            self.pointers: list[tuple[int, int, int]] = []

        async def input_ready(self) -> None:
            self.session = True  # (the next session, once it is there)

        def screen_size(self) -> tuple[int, int] | None:
            return (320, 200) if self.session else None

        async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False, still: Any = None) -> None:
            self.pointers.append((x, y, buttons))

    async def placed() -> list[tuple[int, int, int]]:
        pc = Pc()
        lines = live.Lines(SimpleNamespace(devices={}), standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]
        machine = live.Machine(lines, "d1", pc)  # type: ignore[arg-type]
        holder = live.Line(None, live.Holder("u", "u", True, "127.0.0.1"), machine, frozenset({"jpeg"}), 640, 10)  # type: ignore[arg-type]
        machine.viewers.add(holder)
        assert (await machine.control(holder, True))["on"] is True
        pc.session = False  # the engine ends its session
        await machine.input(holder, {"t": "m", "x": live.FARTHEST, "y": live.FARTHEST // 2})
        await machine.input(holder, {"t": "mb", "b": 1, "d": True})
        return pc.pointers

    assert asyncio.run(placed()) == [(319, 99, 0), (319, 99, 1)]


# An SPS made by hand, bit by bit as H.264's syntax table has it (7.3.2.1.1), for a stream of baseline profile.
def an_sps(width_mbs: int, height_units: int, frames_only: bool = True, lists: bool = False, cycle: int = 0) -> bytes:
    """`lists`: of high profile, with all eight scaling lists said number by number (a few hundred bytes of them). `cycle`:
    picture order count of type 1, with a cycle of that many offsets, each as large as they come (63 bits)."""

    def ue(number: int) -> str:
        value = number + 1
        return "0" * (value.bit_length() - 1) + format(value, "b")

    def se(number: int) -> str:
        return ue(2 * number - 1 if number > 0 else -2 * number)

    if lists:
        # chroma_format_idc 1, both bit depths 8, no bypass, scaling lists present; each list's numbers go 8, 108, 8, 108...
        fields = format(100, "08b") + "0" * 8 + format(40, "08b") + ue(0) + ue(1) + ue(0) + ue(0) + "0" + "1"
        fields += "".join("1" + "".join(se(100 if at % 2 == 0 else -100) for at in range(16 if number < 6 else 64)) for number in range(8))
    else:
        fields = format(66, "08b") + "0" * 8 + format(31, "08b") + ue(0)
    if cycle:
        order = ue(1) + "0" + se(0) + se(0) + ue(cycle) + "".join(se(2**30 if at % 2 else -(2**30)) for at in range(cycle))
    else:
        order = ue(2)
    fields += ue(0) + order + ue(1) + "0" + ue(width_mbs - 1) + ue(height_units - 1)
    fields += ("1" if frames_only else "01") + "1" + "0" + "0" + "1"  # (direct_8x8_inference, no cropping, no VUI, the stop bit)
    fields += "0" * (-len(fields) % 8)
    payload = int(fields, 2).to_bytes(len(fields) // 8, "big")
    out, zeros = bytearray(), 0
    for byte in payload:  # (a 3 put in after two zeros where a start code could be read: what a decoder takes out again)
        if zeros >= 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return b"\x00\x00\x00\x01\x67" + bytes(out)


def test_the_size_a_stream_says_its_pictures_are_is_read_as_a_decoder_reads_it() -> None:
    assert live.sps_size(MADE_UP_SPS) == (640, 480)  # (the stand-in's: baseline, in fields)
    assert live.sps_size(an_sps(120, 68)) == (1920, 1088)
    assert live.sps_size(an_sps(45, 15, frames_only=False)) == (720, 480)
    assert live.sps_size(an_sps(4096, 4096)) == (65536, 65536)
    with_lists = an_sps(50, 38, lists=True)  # (800 by 608; read only once all its scaling lists were)
    assert len(with_lists) > 400 and live.sps_size(with_lists) == (800, 608)
    with_a_cycle = an_sps(50, 38, cycle=255)  # (and after a picture order cycle as long as the standard has one)
    assert len(with_a_cycle) > 2000 and live.sps_size(with_a_cycle) == (800, 608)
    assert live.sps_size(b"\x00\x00\x00\x01\x67\x42\xe0") is None  # cut short
    assert live.sps_size(b"\x00\x00\x00\x01\x67\x42\xe0\x1f" + b"\x00\x00\x03" * 20) is None  # nothing but zeros: no number in it
    av = pytest.importorskip("av")
    from fractions import Fraction

    def first_sps(width: int, height: int, pixels: str = "yuv420p", **options: str) -> bytes:
        try:
            made = av.CodecContext.create("libx264", "w")
        except Exception:
            pytest.skip("PyAV has no H.264 encoder here")
        made.width, made.height, made.pix_fmt, made.time_base, made.options = width, height, pixels, Fraction(1, 25), options
        frame = av.VideoFrame(width, height, pixels)
        for plane in frame.planes:
            plane.update(bytes(plane.buffer_size))
        film = b"".join(bytes(packet) for packet in [*made.encode(frame), *made.encode(None)])
        return next(film[begin:end] for begin, end, kind in live.nal_units(film) if kind == live.SPS)

    # A real encoder's, of every kind a KVM's stream may be: baseline, high, 4:4:4 with scaling lists, in fields, and of a
    # size that is no multiple of sixteen (a decoder makes room for the whole blocks).
    assert live.sps_size(first_sps(320, 240, profile="baseline")) == (320, 240)
    assert live.sps_size(first_sps(1920, 1080)) == (1920, 1088)
    assert live.sps_size(first_sps(640, 360, tune="zerolatency")) == (640, 368)
    assert live.sps_size(first_sps(320, 240, "yuv444p", **{"x264-params": "cqm=jvt"})) == (320, 240)
    assert live.sps_size(first_sps(1366, 768, **{"x264-params": "cqm=jvt"})) == (1376, 768)
    assert live.sps_size(first_sps(720, 480, **{"x264-params": "interlaced=1"})) == (720, 480)


def test_a_stream_that_says_its_pictures_are_enormous_is_not_passed_on(tmp_path: Path) -> None:
    # A decoder makes room for the picture its stream says, whatever the size: 65536 by 65536 is sixteen gigabytes for the
    # browser that believes it. Its viewers get the KVM's pictures one by one instead, which the wall measures as it does any.
    huge = an_sps(4096, 4096)
    film = [(key, unit.replace(MADE_UP_SPS, huge)) for key, unit in made_up_film(2000, pictures=30, key_every=5)]
    fake = FakeKvm(FakeState(media=True, fps=15.0, film=film, picture=a_jpeg((90, 20, 20)), picture_type="image/jpeg")).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, fake.url)
            viewer = wall.line(admin, device)
            came = viewer.picture(timeout=10)
            assert came.kind == 2, "a picture of a stream that says it is 65536 by 65536 pixels was passed on"
            assert {"t": "video", "codec": "jpeg", "w": 320, "h": 180} in viewer.words
            fake.state.picture = a_jpeg((20, 90, 20))  # (the screen changes: one more picture, of the same kind)
            assert viewer.picture().kind == 2
            viewer.close()
    finally:
        fake.stop()


def test_the_table_of_keys_and_the_pointer_as_kvmd_counts_it() -> None:
    assert live.CODE_NAMES[0x04] == "KeyA" and live.CODE_NAMES[0x1D] == "KeyZ" and live.CODE_NAMES[0x1E] == "Digit1" and live.CODE_NAMES[0x27] == "Digit0"
    assert live.CODE_NAMES[0x28] == "Enter" and live.CODE_NAMES[0x3A] == "F1" and live.CODE_NAMES[0x45] == "F12" and live.CODE_NAMES[0x68] == "F13" and live.CODE_NAMES[0x73] == "F24"
    assert live.CODE_NAMES[0x59] == "Numpad1" and live.CODE_NAMES[0x61] == "Numpad9" and live.CODE_NAMES[0x62] == "Numpad0"
    assert live.CODE_NAMES[0x64] == "IntlBackslash" and live.CODE_NAMES[0xE0] == "ControlLeft" and live.CODE_NAMES[0xE7] == "MetaRight"
    assert 0x00 not in live.CODE_NAMES and 0x03 not in live.CODE_NAMES and 0xE8 not in live.CODE_NAMES
    assert len(live.CODE_NAMES) == 145
    assert live.BUTTON_NAMES == {1: "left", 2: "right", 3: "middle", 4: "up", 5: "down"}
