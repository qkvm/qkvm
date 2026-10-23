"""The enlarged view over a server's live line, in a browser (desktop/SPEC.md section 6.2, draft 2).

The page's side of the live connection, driven in a real browser against a stand-in of the server's side: a
wall of this program with the draft's two calls added, which sends the pictures a test gives it, records
every word that comes over the line, and does with keyboard and mouse what a test tells it to (give them,
refuse them, cut the line). Each test holds what every page test holds: the script throws nothing, breaks
none of the page's own rules, and asks nobody but its own wall for anything (`looking`).

What is looked at: a key pressed in the page arrives as the right USB HID usage; a click lands at the right
spot of a letterboxed picture, and one beside the picture is no click; what is down is let go when the page
loses the keyboard; a refusal of control is said; a line cut while keys are down ends with nothing down and
the view saying so; after a picture that never came nothing is drawn until the next key frame, which is
asked for once; a JPEG picture is drawn where it belongs; a machine the server has no live picture of, and a
wall that has no live line at all, are looked at by stills as before.

The program has the line itself since (live.py). The stand-in takes the program's two routes out and puts its own
in their place, because what these tests prove needs a server whose words can be read and whose answers can be
chosen (a refusal with a name, one with none, none at all; a picture that never came), which the program's own
line is not made to give. The tests at the end are the other half: the page against the program's own line, end
to end, with stand-in KVMs behind it, where what arrives is what the KVM is sent (kvmd's events).

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does, and PyAV's H.264 encoder for the
film (the wheel has it; where it is missing those tests are skipped).
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import socket
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from playwright.sync_api import Browser, Page, expect
from websockets.sync.client import connect as ws_connect

from qkvm import cli
from qkvm import live as live_module
from qkvm.core import Core
from qkvm.server import create_app
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_hardening import LiveWall
from tests.test_in_a_browser import DEVICE_PASSWORD, PATIENCE, browser, fast, looking, settings, sign_in, tile, told, top, until  # noqa: F401  (the fixtures)
from tests.test_wall import CSRF, PASSWORD

FORM = 2  # the form of the live connection the stand-in speaks
PASS_LASTS = 30.0
LIVE_PATH = "/api/v1/devices/{device_id}/live"  # the path of both of the draft's calls

# The USB HID usages the page is to send for these keys (the Keyboard/Keypad page of the USB HID Usage Tables).
KEY_A, KEY_B, ENTER, ESCAPE, ARROW_LEFT, DELETE = 0x04, 0x05, 0x28, 0x29, 0x50, 0x4C
LEFT_CTRL, LEFT_SHIFT, LEFT_ALT, RIGHT_CTRL = 0xE0, 0xE1, 0xE2, 0xE4
FARTHEST = 32767
HAS_FRAME = re.compile(r"\bhas-frame\b")


# --- pictures ---------------------------------------------------------------------------------------------------


def h264_film(width: int = 320, height: int = 240, count: int = 24, key_every: int = 8) -> list[tuple[bool, bytes]]:
    """A short film in Annex B form, a key frame every `key_every` pictures, each key frame with its parameter sets."""
    av = pytest.importorskip("av", reason="the film needs PyAV")
    try:
        encoder = av.codec.CodecContext.create("libx264", "w")
    except Exception as ex:
        pytest.skip(f"PyAV without an H.264 encoder: {ex}")
    encoder.width, encoder.height, encoder.pix_fmt = width, height, "yuv420p"
    encoder.time_base, encoder.framerate = Fraction(1, 10), Fraction(10, 1)
    encoder.options = {"preset": "ultrafast", "tune": "zerolatency", "profile": "baseline", "x264-params": f"keyint={key_every}:min-keyint={key_every}:scenecut=0:repeat-headers=1:annexb=1"}
    encoder.open()
    pictures: list[tuple[bool, bytes]] = []
    for number in range(count):
        frame = av.VideoFrame(width, height, "yuv420p")
        for plane in frame.planes:
            plane.update(bytes([(40 + number * 9) % 256]) * plane.buffer_size)
        frame.pts = number
        pictures.extend((packet.is_keyframe, bytes(packet)) for packet in encoder.encode(frame))
    pictures.extend((packet.is_keyframe, bytes(packet)) for packet in encoder.encode(None))
    assert pictures and pictures[0][0] and pictures[key_every][0] and not pictures[1][0], [key for key, _ in pictures]
    return pictures


def jpeg_picture(width: int, height: int, colour: tuple[int, int, int]) -> bytes:
    """One JPEG of one colour, as a server's console is sent."""
    av = pytest.importorskip("av", reason="the picture needs PyAV")
    encoder = av.codec.CodecContext.create("mjpeg", "w")
    encoder.width, encoder.height, encoder.pix_fmt = width, height, "yuvj420p"
    encoder.time_base = Fraction(1, 2)
    encoder.open()
    frame = av.VideoFrame(width, height, "rgb24")
    frame.planes[0].update(bytes(colour) * (frame.planes[0].buffer_size // 3))
    frame = frame.reformat(format="yuvj420p")
    frame.pts = 0
    packets = list(encoder.encode(frame)) + list(encoder.encode(None))
    return bytes(packets[0])


# --- the stand-in -----------------------------------------------------------------------------------------------


@dataclass
class Line:
    """One live line a page opened: what it said first, every word since, and the pictures sent down it."""

    device: str
    hello: dict[str, Any]
    words: list[dict[str, Any]] = field(default_factory=list)
    sent: list[int] = field(default_factory=list)  # the counters of the pictures sent
    loop: asyncio.AbstractEventLoop | None = None
    queue: asyncio.Queue[Any] | None = None
    held: bool = False
    over: bool = False

    def said(self, kind: str) -> list[dict[str, Any]]:
        return [word for word in self.words if word.get("t") == kind]

    def keys(self) -> list[tuple[int, bool]]:
        return [(word["u"], word["d"]) for word in self.said("k")]

    def places(self) -> list[tuple[int, int]]:
        return [(word["x"], word["y"]) for word in self.said("m")]

    def send(self, index: int, counter: int, key: bool | None = None) -> None:
        """Sends the stand-in's picture `index` with this counter (and with this key-frame flag, where told)."""
        assert self.loop is not None and self.queue is not None
        self.loop.call_soon_threadsafe(self.queue.put_nowait, ("picture", index, counter, key))

    def cut(self, code: str, message: str) -> None:
        """Says goodbye and closes the line, as a server does when the machine went away."""
        assert self.loop is not None and self.queue is not None
        self.loop.call_soon_threadsafe(self.queue.put_nowait, ("bye", code, message))


class LiveStandIn(LiveWall):
    """A wall of this program with the draft's live line added, on a port of its own, run in a thread.

    `pictures`: what is sent down every line, round and round at `pace` a second; with `pace` 0 nothing is sent
    unless a test says so (`Line.send`). `codec`, `width`, `height`: what the first `video` word says.
    """

    def __init__(self, data: Path, pictures: list[tuple[bool, bytes]], codec: str, width: int, height: int, pace: float) -> None:
        self.pictures, self.codec, self.width, self.height, self.pace = (pictures, codec, width, height, pace)
        self.lines: list[Line] = []
        self.passes: dict[str, tuple[str, float]] = {}
        self.holders: dict[str, Line] = {}
        self.no_live: set[str] = set()  # machines the wall says have no live picture (no "live" in their `can`)
        self.refuses_live: set[str] = set()  # machines whose `can` says live and whose pass is refused all the same
        self.no_control: set[str] = set()  # machines with a live picture and no keyboard or mouse (no "control")
        self.passes_asked: list[str] = []  # which machines a pass was asked for
        self.refuse_control: dict[str, Any] | None = None  # set: every asking for control is answered with this
        self.answer_control: bool = True  # unset: an asking is not answered at all
        self.drop: set[int] = set()  # the counters that are not sent, as on a line that loses some
        self.key_frames_asked = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        app = create_app(Core(data))
        self._wire(app)
        self._server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def __enter__(self) -> LiveStandIn:
        super().__enter__()
        return self

    def line(self) -> Line:
        """The newest line a page opened, once there is one."""
        deadline = time.monotonic() + PATIENCE / 1000
        while not self.lines:
            assert time.monotonic() < deadline, "no live line was opened"
            time.sleep(0.02)
        return self.lines[-1]

    def can_of(self, device_id: str, found: list[str]) -> list[str]:
        """What a tile can do, as the program found it, with `live` and `control` as this test wants them for that machine."""
        can = [word for word in found if word not in ("live", "control")]
        if device_id not in self.no_live:
            can.append("live")
            if device_id not in self.no_control:
                can.append("control")
        return can

    def _wire(self, app: FastAPI) -> None:
        stand_in = self
        # The program has the live line itself (live.py), at the paths the stand-in's own go to. Its two routes are
        # taken out, or the router (which goes by the order routes were added in) would never reach the stand-in's:
        # these tests drive the page against a server whose words they record and whose answers they choose.
        app.router.routes[:] = [route for route in app.router.routes if getattr(route, "path", "") != LIVE_PATH]

        @app.middleware("http")
        async def says_it_has_live(request: Any, call_next: Any) -> Any:
            answer = await call_next(request)
            if request.scope["path"] not in ("/api/v1/wall", "/api/v1/status") or answer.status_code != 200:
                return answer
            said = json.loads(b"".join([part async for part in answer.body_iterator]))
            # What each tile can do (W8's `can`), in the wall and in every status: the page goes by the status's list
            # where it has one, and by the wall's until then, never by the kind.
            if request.scope["path"] == "/api/v1/wall":
                said["live"] = FORM
                for device in said["devices"]:
                    device["can"] = stand_in.can_of(device["id"], device["can"])
            else:
                for device_id, status in said.items():
                    status["can"] = stand_in.can_of(device_id, status["can"])
            kept = {name: value for name, value in answer.headers.items() if name.lower() != "content-length"}
            return JSONResponse(said, status_code=200, headers=kept)

        @app.post("/api/v1/devices/{device_id}/live")
        async def live_pass(device_id: str) -> Any:
            stand_in.passes_asked.append(device_id)
            if device_id in stand_in.no_live or device_id in stand_in.refuses_live:
                return JSONResponse({"code": "no_live", "message": "This machine has no live picture"}, status_code=404)
            ticket = secrets.token_urlsafe(24)
            stand_in.passes[ticket] = (device_id, time.monotonic() + PASS_LASTS)
            return {"v": FORM, "ticket": ticket}

        @app.websocket("/api/v1/devices/{device_id}/live")
        async def live_line(socket: WebSocket, device_id: str) -> None:
            await socket.accept()
            try:
                hello = await asyncio.wait_for(socket.receive_json(), timeout=10)
            except Exception:
                hello = None
            given = stand_in.passes.pop(str(hello.get("ticket", "")), None) if isinstance(hello, dict) else None
            if given is None or given[0] != device_id or given[1] < time.monotonic() or hello.get("t") != "hello" or hello.get("v") != FORM:
                await socket.send_json({"t": "bye", "code": "no_pass", "message": "This live line was not let in"})
                await socket.close()
                return
            queue: asyncio.Queue[Any] = asyncio.Queue()
            line = Line(device_id, hello, loop=asyncio.get_running_loop(), queue=queue)
            stand_in.lines.append(line)
            await socket.send_json({"t": "video", "codec": stand_in.codec, "w": stand_in.width, "h": stand_in.height})
            wants_key = asyncio.Event()

            async def send_picture(index: int, counter: int, key: bool | None) -> None:
                is_key, data = stand_in.pictures[index]
                if key is not None:
                    is_key = key
                head = struct.pack("<BBHIq", 1 if stand_in.codec == "h264" else 2, 1 if is_key else 0, 0, counter & 0xFFFFFFFF, time.monotonic_ns() // 1000)
                await socket.send_bytes(head + data)
                line.sent.append(counter)

            async def paced() -> None:
                at, counter, due = 0, 0, time.monotonic()
                while True:
                    if wants_key.is_set():
                        wants_key.clear()
                        while not stand_in.pictures[at][0]:
                            at = (at + 1) % len(stand_in.pictures)
                    counter += 1
                    if counter not in stand_in.drop:
                        await send_picture(at, counter, None)
                    at = (at + 1) % len(stand_in.pictures)
                    due += 1.0 / stand_in.pace
                    await asyncio.sleep(max(0.0, due - time.monotonic()))

            async def told() -> None:
                while True:
                    what = await queue.get()
                    if what[0] == "picture":
                        await send_picture(what[1], what[2], what[3])
                    elif what[0] == "bye":
                        await socket.send_json({"t": "bye", "code": what[1], "message": what[2]})
                        await socket.close()
                        return

            tasks = [asyncio.create_task(told())]
            if stand_in.pace:
                tasks.append(asyncio.create_task(paced()))
            try:
                while True:
                    word = await socket.receive_json()
                    if not isinstance(word, dict):
                        continue
                    line.words.append(word)
                    kind = word.get("t")
                    if kind == "key_frame":
                        stand_in.key_frames_asked += 1
                        wants_key.set()
                    elif kind == "control":
                        if word.get("on"):
                            if not stand_in.answer_control:
                                continue
                            if stand_in.refuse_control:
                                await socket.send_json({"t": "control", "on": False, **stand_in.refuse_control})
                                continue
                            if stand_in.holders.get(device_id) not in (None, line):
                                await socket.send_json({"t": "control", "on": False, "code": "taken", "message": "Somebody else has this machine's keyboard and mouse"})
                                continue
                            stand_in.holders[device_id] = line
                            line.held = True
                            await socket.send_json({"t": "control", "on": True})
                        else:
                            if stand_in.holders.get(device_id) is line:
                                del stand_in.holders[device_id]
                            line.held = False
                            await socket.send_json({"t": "control", "on": False})
            except Exception:  # (the line is gone, or said what is no word: either way it ends)
                pass
            finally:
                for task in tasks:
                    task.cancel()
                if stand_in.holders.get(device_id) is line:
                    del stand_in.holders[device_id]
                line.held = False
                line.over = True


class WallBeforeTheLine(LiveWall):
    """The program as a server before the live line answered: no `live` in its wall, and neither `live` nor `control` in any `can`."""

    def __init__(self, data: Path) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        app = create_app(Core(data))
        app.router.routes[:] = [route for route in app.router.routes if getattr(route, "path", "") != LIVE_PATH]

        @app.middleware("http")
        async def says_nothing_of_live(request: Any, call_next: Any) -> Any:
            answer = await call_next(request)
            if request.scope["path"] not in ("/api/v1/wall", "/api/v1/status") or answer.status_code != 200:
                return answer
            said = json.loads(b"".join([part async for part in answer.body_iterator]))
            said.pop("live", None) if request.scope["path"] == "/api/v1/wall" else None
            for each in said["devices"] if request.scope["path"] == "/api/v1/wall" else said.values():
                each["can"] = [word for word in each["can"] if word not in ("live", "control")]
            kept = {name: value for name, value in answer.headers.items() if name.lower() != "content-length"}
            return JSONResponse(said, status_code=200, headers=kept)

        self._server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)


@contextmanager
def a_wall_before_the_line(data: Path, fake: FakeKvm) -> Iterator[WallBeforeTheLine]:
    with WallBeforeTheLine(data) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        reply = admin.post("/api/v1/devices", json={"url": fake.url, "password": DEVICE_PASSWORD, "name": "Machine 1"})
        assert reply.status_code == 201, reply.text
        yield live


@contextmanager
def the_program(data: Path, fake: FakeKvm) -> Iterator[LiveWall]:
    """The program itself on a port, with the web server's own options, its first account made and one machine on its wall: no stand-in of the line."""
    with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        made = admin.post("/api/v1/devices", json={"url": fake.url, "password": DEVICE_PASSWORD, "name": "Machine 1"})
        assert made.status_code == 201, made.text
        assert admin.get("/api/v1/wall").json()["live"] == FORM
        live.device = made.json()["device"]["id"]  # type: ignore[attr-defined]
        yield live


def a_live_wall(data: Path, fakes: list[FakeKvm], **how: Any) -> tuple[LiveStandIn, dict[str, str]]:
    """The stand-in, started, with the account made and one tile per stand-in KVM; and the tiles' ids by name."""
    stand_in = LiveStandIn(data, **how).__enter__()
    ids: dict[str, str] = {}
    with httpx.Client(base_url=stand_in.url, headers=CSRF, timeout=30) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        for number, fake in enumerate(fakes):
            name = f"Machine {number + 1}"
            reply = admin.post("/api/v1/devices", json={"url": fake.url, "password": DEVICE_PASSWORD, "name": name})
            assert reply.status_code == 201, reply.text
            ids[name] = str(reply.json()["device"]["id"])
    return stand_in, ids


def enlarged(page: Page, name: str) -> None:
    tile(page, name).click()
    expect(page.locator("#focus")).to_be_visible()
    expect(page.locator("#focus-name")).to_have_text(name)


def live_said(page: Page, what: str) -> Any:
    """One of the numbers the live line's state in the bar carries as data."""
    return page.evaluate(f"document.querySelector('#focus-live').dataset.{what}")


def drawn_counter_is(page: Page, counter: int) -> None:
    page.wait_for_function(f"() => document.querySelector('#focus-live').dataset.counter === '{counter}'")


def take_control(page: Page, stand_in: LiveStandIn) -> Line:
    """Control, by its key; what comes back is the line that holds keyboard and mouse now."""
    expect(page.locator("#focus-control")).to_have_text("Control")
    page.keyboard.press("c")
    expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
    expect(page.locator("#focus-keys")).to_be_visible()
    line = stand_in.line()
    until(page, lambda: line.held, "the stand-in never gave keyboard and mouse")
    return line


def picture_box(page: Page) -> dict[str, float]:
    """Where the picture lies on the page, in CSS pixels: the box, and the picture fitted into it as the page fits it.

    Once the page has drawn it to the box's size. The box changes size when the bar of keys appears above it
    (Control), and the page draws the picture to the new size a moment later. Measured in that moment, the picture
    was where it had been in the taller box, and a click at its middle landed below the middle (one run in two, on
    a fast PC).
    """
    page.wait_for_function("""() => {
      const box = document.querySelector('#focus-screen').getBoundingClientRect();
      const canvas = document.querySelector('#focus-canvas');
      return box.width > 0 && canvas.width > 1 && Math.abs(canvas.height * box.width / canvas.width - box.height) < 1.5;
    }""")
    box: dict[str, float] = page.evaluate("""() => {
      const box = document.querySelector('#focus-screen').getBoundingClientRect();
      const canvas = document.querySelector('#focus-canvas');
      const line = document.querySelector('#focus-live').dataset;
      const w = Number(line.width), h = Number(line.height);
      const ratio = canvas.width / box.width;  // device pixels per CSS pixel
      const scale = Math.min(canvas.width / w, canvas.height / h);
      const dw = Math.max(1, Math.round(w * scale)), dh = Math.max(1, Math.round(h * scale));
      const x = Math.floor((canvas.width - dw) / 2) / ratio, y = Math.floor((canvas.height - dh) / 2) / ratio;
      return { left: box.left, top: box.top, width: box.width, height: box.height, x, y, w: dw / ratio, h: dh / ratio };
    }""")
    return box


# --- the tests ----------------------------------------------------------------------------------------------------


@pytest.fixture
def fakes() -> Any:
    made = [FakeKvm(FakeState()).start(), FakeKvm(FakeState(colour=(135, 74, 32), hostname="mail")).start()]
    yield made
    for fake in made:
        fake.stop()


def test_the_live_picture_is_drawn_and_a_key_arrives_as_its_usage(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            # The line is opened with what this browser can show, and the first picture is drawn from a key frame.
            line = stand_in.line()
            assert line.hello["video"] == ["h264", "jpeg"] and line.hello["max_w"] >= 320 and line.hello["max_fps"] > 0
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264 320×240")  # noqa: RUF001
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 5")
            assert live_said(page, "dropped") == "0"
            expect(page.locator("#focus-screen")).to_have_class(HAS_FRAME)
            expect(page.locator("#focus")).to_have_attribute("data-state", "online")

            # Before control is taken nothing typed goes anywhere (the wall looks; this page is no console yet).
            page.keyboard.type("rm")
            page.wait_for_timeout(300)
            assert line.keys() == []

            line = take_control(page, stand_in)
            page.keyboard.press("KeyA")
            page.keyboard.press("Shift+KeyB")
            page.keyboard.press("ArrowLeft")
            page.keyboard.press("Enter")
            # Esc is the machine's now, and does not close the view; a key held down is down once, however often
            # the keyboard repeats it.
            page.keyboard.press("Escape")
            page.keyboard.down("KeyA")
            page.keyboard.down("KeyA")
            page.keyboard.up("KeyA")
            wanted = [
                (KEY_A, True),
                (KEY_A, False),
                (LEFT_SHIFT, True),
                (KEY_B, True),
                (KEY_B, False),
                (LEFT_SHIFT, False),
                (ARROW_LEFT, True),
                (ARROW_LEFT, False),
                (ENTER, True),
                (ENTER, False),
                (ESCAPE, True),
                (ESCAPE, False),
                (KEY_A, True),
                (KEY_A, False),
            ]
            until(page, lambda: len(line.keys()) >= len(wanted), f"not every key arrived: {line.keys()}")
            assert line.keys() == wanted
            expect(page.locator("#focus")).to_be_visible()

            # The right Ctrl by itself gives keyboard and mouse back, after everything was let go; then Esc is the page's again.
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
            expect(page.locator("#focus-keyboard-toggle")).to_be_disabled()
            until(page, lambda: not line.held, "keyboard and mouse were not given back")
            assert line.keys()[len(wanted) :] == [] and line.said("up") and line.said("control")[-1] == {"t": "control", "on": False}
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            until(page, lambda: line.over, "the line was not closed with the view")
    finally:
        stand_in.__exit__()


def test_a_click_lands_where_it_was_made_on_a_letterboxed_picture(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # A picture of 4:3 in a view wider than that: black at both sides. A click is said in the picture's own
    # measure, 0 to 32767 each way over the picture and not over the box; beside the picture it is no click.
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 720}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 2")
            line = take_control(page, stand_in)
            box = picture_box(page)
            assert box["x"] > 40, box  # letterboxed indeed: the picture does not reach the box's left edge

            def near(place: tuple[int, int], expected: tuple[float, float]) -> bool:
                return abs(place[0] - expected[0]) <= 120 and abs(place[1] - expected[1]) <= 120

            def place_before(button_word: int) -> tuple[int, int]:
                """Where the pointer was said to be right before the button word number `button_word` (from 0)."""
                at = [number for number, word in enumerate(line.words) if word.get("t") == "mb"][button_word]
                assert line.words[at - 1]["t"] == "m", line.words[max(0, at - 3) : at + 1]
                return (line.words[at - 1]["x"], line.words[at - 1]["y"])

            # The middle of the picture.
            page.mouse.click(box["left"] + box["x"] + box["w"] / 2, box["top"] + box["y"] + box["h"] / 2)
            until(page, lambda: len(line.said("mb")) >= 2, f"the click did not arrive: {line.words}")
            assert [(word["b"], word["d"]) for word in line.said("mb")] == [(1, True), (1, False)]
            # (The pointer may have been said elsewhere before the click moved it: a browser says where the pointer is
            # when what lies under it changes. What counts is where it was said to be right before each press.)
            assert near(place_before(0), (FARTHEST / 2, FARTHEST / 2)) and near(place_before(1), (FARTHEST / 2, FARTHEST / 2)), line.places()

            # A tenth of the way in from the picture's top left corner.
            page.mouse.click(box["left"] + box["x"] + box["w"] * 0.1, box["top"] + box["y"] + box["h"] * 0.1)
            until(page, lambda: len(line.said("mb")) >= 4, "the second click did not arrive")
            assert near(place_before(2), (FARTHEST * 0.1, FARTHEST * 0.1)), line.places()[-3:]

            # The right mouse button, and the wheel: down is a click of the wheel towards the hand.
            page.mouse.click(box["left"] + box["x"] + box["w"] / 2, box["top"] + box["y"] + box["h"] / 2, button="right")
            page.mouse.wheel(0, 100)
            page.mouse.wheel(0, -200)
            until(page, lambda: len(line.said("mw")) >= 3, f"the wheel did not arrive: {line.said('mw')}")
            assert [(word["b"], word["d"]) for word in line.said("mb")][-2:] == [(2, True), (2, False)]
            assert [(word["dx"], word["dy"]) for word in line.said("mw")] == [(0, -1), (0, 1), (0, 1)]

            # Two buttons at once: the second pressed while the first is held, and let go in the same order. (A
            # browser says a second button as a move with the buttons changed, not as a press of its own.)
            page.mouse.down(button="left")
            page.mouse.down(button="right")
            page.mouse.up(button="left")
            page.mouse.up(button="right")
            until(page, lambda: len(line.said("mb")) >= 10, f"the two buttons did not arrive: {line.said('mb')}")
            assert [(word["b"], word["d"]) for word in line.said("mb")][-4:] == [(1, True), (2, True), (1, False), (2, False)]
            page.wait_for_function("() => document.querySelector('#focus-live').dataset.down === '0'")

            # Beside the picture, in the black: nothing is said, and nothing is pressed.
            before = len(line.words)
            page.mouse.click(box["left"] + box["x"] / 2, box["top"] + box["height"] / 2)
            page.mouse.wheel(0, 100)
            page.wait_for_timeout(400)
            assert line.words[before:] == [], line.words[before:]
    finally:
        stand_in.__exit__()


def test_what_is_down_is_let_go_when_the_page_loses_the_keyboard(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 720}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 2")
            line = take_control(page, stand_in)
            box = picture_box(page)
            page.keyboard.down("ShiftLeft")
            page.keyboard.down("KeyA")
            page.mouse.move(box["left"] + box["x"] + box["w"] / 2, box["top"] + box["y"] + box["h"] / 2)
            page.mouse.down()
            until(page, lambda: len(line.keys()) == 2 and len(line.said("mb")) == 1, "not everything went down")
            page.wait_for_function("() => document.querySelector('#focus-live').dataset.down === '3'")

            # The window loses the keyboard (another window in front): every key and button is let go, and the
            # whole machine is told to let go as well. Keyboard and mouse stay with this page.
            page.evaluate("window.dispatchEvent(new Event('blur'))")
            until(page, lambda: len(line.keys()) == 4 and len(line.said("mb")) == 2, f"not let go: {line.words}")
            assert line.keys()[2:] == [(LEFT_SHIFT, False), (KEY_A, False)] and line.said("mb")[-1]["d"] is False
            assert line.said("up") == [{"t": "up"}]
            page.mouse.up()
            page.keyboard.up("KeyA")
            page.keyboard.up("ShiftLeft")
            page.wait_for_timeout(300)
            assert len(line.keys()) == 4 and len(line.said("mb")) == 2  # nothing is let go twice
            page.wait_for_function("() => document.querySelector('#focus-live').dataset.down === '0'")
            assert live_said(page, "control") == "on"
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")

            # A key held through a click that opens a dialog (Actions, here) and let go while the dialog has the
            # keyboard goes up on the machine all the same; what is pressed in the dialog goes to the dialog.
            page.keyboard.down("ShiftLeft")
            until(page, lambda: line.keys()[-1] == (LEFT_SHIFT, True), "Shift did not go down")
            page.locator("#focus-actions").click()
            expect(page.locator("dialog[open]")).to_have_count(1)
            page.keyboard.up("ShiftLeft")
            until(page, lambda: line.keys()[-1] == (LEFT_SHIFT, False), f"Shift stayed down behind the dialog: {line.keys()[-3:]}")
            page.keyboard.type("xyz")
            page.keyboard.press("Escape")
            expect(page.locator("dialog[open]")).to_have_count(0)
            page.wait_for_timeout(300)
            assert line.keys()[-1] == (LEFT_SHIFT, False) and live_said(page, "control") == "on"

            # The leave-key held through such a click and let go inside the dialog: forgotten there as well, so that
            # the keys after the dialog go to the machine again (held in memory, every key after it went nowhere).
            page.keyboard.down("ControlRight")
            page.locator("#focus-actions").click()
            expect(page.locator("dialog[open]")).to_have_count(1)
            page.keyboard.up("ControlRight")
            page.keyboard.press("Escape")
            expect(page.locator("dialog[open]")).to_have_count(0)
            page.keyboard.press("KeyA")
            until(page, lambda: line.keys()[-2:] == [(KEY_A, True), (KEY_A, False)], f"the keys after the dialog went nowhere: {line.keys()[-3:]}")
            assert live_said(page, "control") == "on"

            # The page is left while a key is down: everything is let go, keyboard and mouse are given back, and
            # the line is closed, in that order, before the page goes.
            before = len(line.keys())
            page.keyboard.down("KeyB")
            until(page, lambda: len(line.keys()) == before + 1, "the key did not go down")
            page.goto(stand_in.url + "/healthz")
            until(page, lambda: line.over, "the line was not closed when the page was left")
            assert line.keys()[-1] == (KEY_B, True) and line.words[-2:] == [{"t": "up"}, {"t": "control", "on": False}], line.words[-4:]
    finally:
        stand_in.__exit__()


def test_control_that_is_refused_is_said_and_keys_go_nowhere(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    stand_in.refuse_control = {"code": "taken", "message": "Somebody else has this machine's keyboard and mouse", "by": "Alice"}
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.locator("#focus-control").click()
            # (This page is an admin's: who has them is said on the button that offers to take them over.)
            expect(page.locator("#focus-control")).to_have_text("Take over from Alice")
            expect(page.locator("#focus-control")).to_have_attribute(
                "title", "Somebody else has this machine's keyboard and mouse. As an admin you can take them over: you are asked first (C)"
            )
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "false")
            expect(page.locator("#focus-keyboard-toggle")).to_be_disabled()
            line = stand_in.line()
            page.keyboard.type("xyz")  # (letters that are no key of the page's own; Enter would press the button that has the focus)
            page.keyboard.press("Delete")
            page.wait_for_timeout(400)
            assert line.keys() == [] and line.said("control") == [{"t": "control", "on": True}]
            # Taken over: asked first, and then asked of the server with whom it was asked about, as the server named them.
            page.locator("#focus-control").click()
            expect(top(page)).to_contain_text("Alice has the keyboard and mouse of Machine 1. Take them over?")
            top(page).get_by_role("button", name="Take over").click()
            expect(page.locator("#focus-control")).to_have_text("Take over from Alice")  # (the stand-in refuses again)
            until(page, lambda: len(line.said("control")) == 2, "the take-over was not asked for")
            assert line.said("control")[1] == {"t": "control", "on": True, "take": True, "from": "Alice"}, line.said("control")
            # Esc is still the page's: it closes the view.
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()

            # Refused with no name: the button says that they were not given, and the reason is a hover away.
            stand_in.refuse_control = {"code": "no_control", "message": "This KVM has no keyboard"}
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Not given")
            expect(page.locator("#focus-control")).to_have_attribute("title", "This KVM has no keyboard")

            # Not answered yet: said as asked for, for as long as the server's longest way in to a machine can take (a PC with
            # Intel AMT between two sessions, a JetKVM connected anew): not given up on after five seconds. (Given up on at
            # last: the next test.)
            stand_in.refuse_control = None
            stand_in.answer_control = False
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-busy", "true")
            expect(page.locator("#focus-control")).to_have_text("Asking...")
            page.wait_for_timeout(6000)
            expect(page.locator("#focus-control")).to_have_text("Asking...")
            line = stand_in.line()
            assert line.said("control")[-1] == {"t": "control", "on": True}, line.said("control")
    finally:
        stand_in.__exit__()


def test_an_asking_for_control_never_answered_is_said_once_the_longest_way_in_is_over(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # Said "No answer" once the server's longest way in to a machine is over (the page's own clock is moved on to then),
    # and Control rests until the server's owed word, or its time, is over.
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=[(True, jpeg_picture(320, 240, (30, 160, 60)))], codec="jpeg", width=320, height=240, pace=0)
    stand_in.answer_control = False
    try:
        with looking(browser, stand_in) as page:
            page.clock.install()  # (time goes on as it does, until it is moved on below)
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            stand_in.line().send(0, 1)
            drawn_counter_is(page, 1)
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_text("Asking...")
            waits = page.evaluate("CONTROL_ANSWER")
            assert waits > live_module.WAY_IN_WITHIN * 1000, f"the page gives up after {waits} ms, before the server's longest way in"
            page.clock.fast_forward(waits - 2000)
            page.wait_for_timeout(300)
            expect(page.locator("#focus-control")).to_have_text("Asking...")
            page.clock.fast_forward(2500)
            expect(page.locator("#focus-control")).to_have_text("No answer")
            expect(page.locator("#focus-control")).to_be_disabled()
            expect(page.locator("#focus-control")).to_be_enabled(timeout=8000)
            line = stand_in.line()
            assert line.said("control")[-2:] == [{"t": "control", "on": True}, {"t": "control", "on": False}]
    finally:
        stand_in.__exit__()


def test_a_line_cut_while_keys_are_down_ends_with_nothing_down_and_the_view_saying_so(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 2")
            line = take_control(page, stand_in)
            page.keyboard.down("KeyA")
            until(page, lambda: line.keys() == [(KEY_A, True)], "the key did not go down")
            line.cut("gone", "The KVM went away")
            # Nothing is down for this page any more (the server lets go of what it had), keyboard and mouse are
            # not held, the stills are back, and the bar says why.
            expect(page.locator("#focus-keyboard-toggle")).to_be_disabled()
            expect(page.locator("#focus-control")).to_be_hidden()
            expect(page.locator("#focus-live")).to_have_text("No live picture: stills")
            expect(page.locator("#focus-live")).to_have_attribute("title", "The KVM went away")
            expect(page.locator("#focus-again")).to_be_visible()
            assert live_said(page, "down") == "0" and live_said(page, "control") == "off"
            page.keyboard.up("KeyA")
            page.keyboard.type("x")
            page.wait_for_timeout(300)
            assert line.keys() == [(KEY_A, True)]  # nothing more went over a line that is gone
            expect(page.locator("#focus")).to_have_attribute("data-state", "online")  # by snapshots, as before
            expect(page.locator("#focus-screen")).to_have_class(HAS_FRAME)

            # Live again: a new line, with a new pass; the old one is not reopened.
            page.locator("#focus-again").click()
            until(page, lambda: len(stand_in.lines) == 2, "no second line was opened")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264")
            expect(page.locator("#focus-again")).to_be_hidden()
            assert stand_in.lines[1].hello["ticket"] != line.hello["ticket"]

            # Esc is the page's: the view closes, and the new line with it.
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            until(page, lambda: stand_in.lines[1].over, "the second line was not closed with the view")
    finally:
        stand_in.__exit__()


def test_after_a_picture_that_never_came_nothing_is_drawn_until_the_next_key_frame(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film(key_every=8)
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=0)
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            line = stand_in.line()
            expect(page.locator("#focus-live")).to_have_text("Live · waiting for the first picture")
            # A picture that is no key frame before any key frame: nothing is drawn, and a key frame is asked for once.
            line.send(1, 1)
            page.wait_for_timeout(400)
            assert live_said(page, "drawn") == "0"
            until(page, lambda: stand_in.key_frames_asked == 1, "no key frame was asked for")
            # The key frame, and the pictures that build on it, each drawn. (Two sent at once would be one drawn
            # and one dropped: never more than one decoded picture waits, and the newest wins.)
            line.send(0, 2)
            drawn_counter_is(page, 2)
            line.send(1, 3)
            drawn_counter_is(page, 3)
            line.send(2, 4)
            drawn_counter_is(page, 4)
            assert live_said(page, "dropped") == "1" and stand_in.key_frames_asked == 1
            # Picture 5 never comes. 6 and 7 build on it: not drawn, counted as dropped, and a key frame is asked
            # for once, not once per picture.
            line.send(4, 6)
            line.send(5, 7)
            page.wait_for_function("() => document.querySelector('#focus-live').dataset.dropped === '3'")
            assert live_said(page, "counter") == "4"
            until(page, lambda: stand_in.key_frames_asked == 2, "no key frame was asked for after the gap")
            page.wait_for_timeout(300)
            assert stand_in.key_frames_asked == 2
            # The next key frame is drawn, and what follows it again.
            line.send(8, 8)
            drawn_counter_is(page, 8)
            line.send(9, 9)
            drawn_counter_is(page, 9)
            assert live_said(page, "dropped") == "3"
            expect(page.locator("#focus-live")).to_contain_text("3 dropped")
    finally:
        stand_in.__exit__()


def test_a_jpeg_picture_is_drawn_where_it_belongs(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # A server's console comes as JPEGs, each a whole picture. Drawn as large as it goes and centred: the middle
    # of the canvas has the picture's colour, the black at the sides is black.
    red = jpeg_picture(320, 240, (220, 30, 30))
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=[(True, red)], codec="jpeg", width=320, height=240, pace=0)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 720}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            line = stand_in.line()
            assert line.hello["video"] == ["h264", "jpeg"]
            line.send(0, 1)
            drawn_counter_is(page, 1)
            expect(page.locator("#focus-live")).to_contain_text("Live · JPEG 320×240")  # noqa: RUF001
            box = picture_box(page)
            assert box["x"] > 40, box
            middle, side = page.evaluate("""() => {
              const canvas = document.querySelector('#focus-canvas');
              const context = canvas.getContext('2d');
              const at = (x, y) => [...context.getImageData(x, y, 1, 1).data].slice(0, 3);
              return [at(Math.floor(canvas.width / 2), Math.floor(canvas.height / 2)), at(4, Math.floor(canvas.height / 2))];
            }""")
            assert abs(middle[0] - 220) <= 12 and middle[1] <= 45 and middle[2] <= 45, middle
            assert side == [0, 0, 0], side
            # A second picture while nobody waits is drawn too; the counter follows.
            line.send(0, 2)
            drawn_counter_is(page, 2)
    finally:
        stand_in.__exit__()


def test_a_jpeg_picture_that_comes_before_the_view_has_a_size_is_drawn_once_it_has_one(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # A still screen sends one picture and no other (the program's line sends only pictures that changed: a Comet
    # whose screen stands still, a server's console). One that reached the page while the view had no size yet, as
    # it has none in the moment it opens, was not drawn and not kept: the view said "waiting for the first
    # picture" for good. It is kept, and drawn as soon as the view has a size.
    red = jpeg_picture(320, 240, (220, 30, 30))
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=[(True, red)], codec="jpeg", width=320, height=240, pace=0)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 720}) as page:
            sign_in(page, stand_in)
            # The view's picture box without a size, for as long as this test says. (Set through the script: the page's
            # own rules let no style in that is written into it.)
            page.evaluate("document.querySelector('#focus-screen').style.setProperty('display', 'none', 'important')")
            enlarged(page, "Machine 1")
            line = stand_in.line()
            line.send(0, 1)
            # The page has the picture (it knows what it was sent), and cannot draw it yet.
            page.wait_for_function("() => document.querySelector('#focus-live').dataset.codec === 'JPEG'")
            page.wait_for_timeout(300)
            assert live_said(page, "drawn") == "0"
            expect(page.locator("#focus-live")).to_have_text("Live · waiting for the first picture")
            # The box gets its size. Nothing more is sent: the one picture there is, is drawn.
            page.evaluate("document.querySelector('#focus-screen').style.removeProperty('display')")
            drawn_counter_is(page, 1)
            expect(page.locator("#focus-live")).to_contain_text("Live · JPEG 320×240")  # noqa: RUF001
            middle = page.evaluate("""() => {
              const canvas = document.querySelector('#focus-canvas');
              return [...canvas.getContext('2d').getImageData(Math.floor(canvas.width / 2), Math.floor(canvas.height / 2), 1, 1).data].slice(0, 3);
            }""")
            assert abs(middle[0] - 220) <= 12 and middle[1] <= 45 and middle[2] <= 45, middle
            assert line.sent == [1]
    finally:
        stand_in.__exit__()


def test_a_machine_without_a_live_picture_and_a_wall_without_a_line_are_looked_at_by_stills(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    film = h264_film()
    stand_in, ids = a_live_wall(tmp_path / "live", fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    stand_in.no_live.add(ids["Machine 2"])
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 2")
            expect(page.locator("#focus-live")).to_have_text("No live picture: stills")
            expect(page.locator("#focus-control")).to_be_hidden()
            expect(page.locator("#focus-again")).to_be_hidden()
            expect(page.locator("#focus-screen")).to_have_class(HAS_FRAME)
            page.wait_for_timeout(300)
            assert stand_in.lines == [] and stand_in.passes_asked == []  # the wall said "no live": no pass was even asked for
            # The next machine has one: stepping on opens its line, and stepping back closes it.
            page.keyboard.press("ArrowLeft")
            expect(page.locator("#focus-name")).to_have_text("Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264")
            page.keyboard.press("ArrowRight")
            expect(page.locator("#focus-live")).to_have_text("No live picture: stills")
            until(page, lambda: stand_in.lines[0].over, "the line was not closed when another machine was shown")
            page.keyboard.press("Escape")

            # The wall says live and the pass is refused all the same (the server changed its mind): the same words,
            # and no "Live again".
            stand_in.refuses_live.add(ids["Machine 1"])
            page.reload()
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-live")).to_have_text("No live picture: stills")
            expect(page.locator("#focus-live")).to_have_attribute("title", "This machine has no live picture")
            expect(page.locator("#focus-again")).to_be_hidden()
            expect(page.locator("#focus-control")).to_be_hidden()
            assert stand_in.passes_asked[-1] == ids["Machine 1"]
            page.keyboard.press("Escape")

            # A live picture without keyboard and mouse (a server's console, say): Control is not offered.
            stand_in.refuses_live.clear()
            stand_in.no_control.add(ids["Machine 1"])
            page.reload()
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264")
            page.keyboard.press("c")
            page.wait_for_timeout(300)
            expect(page.locator("#focus-control")).to_be_hidden()
            assert stand_in.line().said("control") == []
    finally:
        stand_in.__exit__()


def test_a_view_closed_twice_and_opened_again_at_once_stays_open(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # Found by W8 under load: a tile opens the enlarged view on Space as well as Enter, so text typed on a tile
    # opened it; two Escapes then closed it twice, each hiding a frame later (a movement on screen), and an Enter
    # between the closing and the hiding opened it again at once; the late hiding then hid the view that had just
    # been opened. A hiding that finds another view than the one it was for leaves it alone.
    film = h264_film()
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=film, codec="h264", width=320, height=240, pace=10)
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264")
            # The three keys within one frame, as the page's own handlers see them.
            page.evaluate("""() => {
              const esc = () => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
              esc(); esc();
              const tile = document.querySelector('#wall article');
              tile.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
            }""")
            page.wait_for_timeout(600)
            expect(page.locator("#focus")).to_be_visible()
            expect(page.locator("#focus-name")).to_have_text("Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264")
            assert page.evaluate("[document.querySelector('#wall').inert, document.querySelector('.top').inert]") == [True, True]
            until(page, lambda: len(stand_in.lines) == 2 and stand_in.lines[0].over and not stand_in.lines[1].over, "the first line was not closed, or no second one opened")
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            assert page.evaluate("[document.querySelector('#wall').inert, document.querySelector('.top').inert]") == [False, False]
    finally:
        stand_in.__exit__()

    # A wall whose server speaks no live line (every wall before it had one): the enlarged view asks for none.
    with a_wall_before_the_line(tmp_path / "plain", fakes[0]) as live, looking(browser, live) as page:
        asked: list[str] = []
        page.on("request", lambda request: asked.append(request.url) if "/live" in request.url else None)
        sign_in(page, live)
        enlarged(page, "Machine 1")
        page.wait_for_function("() => document.querySelector('#focus-canvas').width > 1")
        expect(page.locator("#focus-live")).to_be_hidden()
        expect(page.locator("#focus-control")).to_be_hidden()
        page.wait_for_timeout(300)
        assert asked == []


# --- the page against the program's own line, end to end -----------------------------------------------------------


def kvm_keys(fake: FakeKvm) -> list[tuple[str, bool]]:
    """The keys the stand-in KVM was sent, by the names kvmd gives them, down or up."""
    return [(event["event"]["key"], event["event"]["state"]) for event in fake.state.hid if event["event_type"] == "key"]


def test_the_page_shows_a_kvm_live_over_the_programs_line_and_its_keys_and_clicks_arrive(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (220, 30, 30)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · JPEG 320×240")  # noqa: RUF001
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            # Nothing typed before Control goes anywhere.
            page.keyboard.type("rm")
            page.wait_for_timeout(300)
            assert comet.state.hid == []
            expect(page.locator("#focus-control")).to_have_text("Control")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            page.keyboard.press("KeyA")
            page.keyboard.press("Shift+KeyB")
            until(page, lambda: len(kvm_keys(comet)) >= 6, f"the keys did not arrive: {comet.state.hid}")
            assert kvm_keys(comet) == [("KeyA", True), ("KeyA", False), ("ShiftLeft", True), ("KeyB", True), ("KeyB", False), ("ShiftLeft", False)]
            box = picture_box(page)
            page.mouse.click(box["left"] + box["x"] + box["w"] / 2, box["top"] + box["y"] + box["h"] / 2)
            until(page, lambda: [e["event"]["state"] for e in comet.state.hid if e["event_type"] == "mouse_button"] == [True, False], f"the click did not arrive: {comet.state.hid}")
            moves = [e["event"]["to"] for e in comet.state.hid if e["event_type"] == "mouse_move"]
            assert moves and abs(moves[-1]["x"]) <= 300 and abs(moves[-1]["y"]) <= 300, moves  # the middle of the picture: kvmd's 0, 0
            page.keyboard.press("ControlRight")  # gives keyboard and mouse back
            expect(page.locator("#focus-control")).to_have_text("Control")
            until(page, lambda: comet.state.key_lines == 0, "the KVM's line for keys stayed open after the page gave them back")
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
    finally:
        comet.stop()


def test_the_page_shows_a_kvms_h264_over_the_programs_line(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    pikvm = FakeKvm(FakeState(media=True, film=h264_film(), fps=10.0, width=320, height=240)).start()
    try:
        with the_program(tmp_path, pikvm) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-live")).to_contain_text("Live · H.264 320×240")  # noqa: RUF001
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 5")
            assert live_said(page, "dropped") == "0" and pikvm.state.media_clients == 1
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            until(page, lambda: pikvm.state.media_clients == 0, "the KVM's H.264 line stayed open after the view was closed")
    finally:
        pikvm.stop()


def test_the_page_says_who_holds_the_keyboard_the_program_will_not_give(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (30, 160, 60)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            # Somebody has the machine's keyboard and mouse over a line of their own (the same account, elsewhere)
            # before the page looks. (The machine's pictures are under way by then: the program hands the one it has
            # to the page's line the moment it joins, while the view is still opening, and a still screen sends no
            # other. The page draws that one once the view has a size.)
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as other:
                assert other.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
                ticket = other.post(f"/api/v1/devices/{live.device}/live").json()["ticket"]  # type: ignore[attr-defined]
            with ws_connect(f"ws://127.0.0.1:{live.port}/api/v1/devices/{live.device}/live", open_timeout=5) as holder:  # type: ignore[attr-defined]
                holder.send(json.dumps({"t": "hello", "v": FORM, "ticket": ticket, "video": ["jpeg"], "max_w": 640, "max_fps": 5}))
                holder.send(json.dumps({"t": "control", "on": True}))
                while True:
                    came = holder.recv(timeout=10)
                    if isinstance(came, str) and json.loads(came).get("t") == "control":
                        assert json.loads(came)["on"] is True
                        break
                enlarged(page, "Machine 1")
                page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
                page.locator("#focus-control").click()
                # (An admin's page: the button that says who also offers to take them over. An operator's: test_an_admin_takes_over...)
                expect(page.locator("#focus-control")).to_have_text("Take over from admin")
                expect(page.locator("#focus-control")).to_have_attribute(
                    "title", "Somebody else has this machine's keyboard and mouse. As an admin you can take them over: you are asked first (C)"
                )
                page.keyboard.type("xyz")
                page.wait_for_timeout(300)
                assert comet.state.hid == []  # what the page was not given, it sends nothing over
    finally:
        comet.stop()


def test_an_action_the_program_refuses_while_somebody_holds_the_keyboard_names_them_in_the_page(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (160, 120, 30)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)  # (the first account, while it is the only one: its password is all the page asks)
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
                assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
                made = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"})
                assert made.status_code == 201, made.text
            # An operator has the machine's keyboard and mouse over a line of her own.
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as olga:
                assert olga.post("/api/v1/login", json={"name": "olga", "password": "olga may act here"}).status_code == 200
                ticket = olga.post(f"/api/v1/devices/{live.device}/live").json()["ticket"]  # type: ignore[attr-defined]
            with ws_connect(f"ws://127.0.0.1:{live.port}/api/v1/devices/{live.device}/live", open_timeout=5) as holder:  # type: ignore[attr-defined]
                holder.send(json.dumps({"t": "hello", "v": FORM, "ticket": ticket, "video": ["jpeg"], "max_w": 640, "max_fps": 5}))
                holder.send(json.dumps({"t": "control", "on": True}))
                while True:
                    came = holder.recv(timeout=10)
                    if isinstance(came, str) and json.loads(came).get("t") == "control":
                        assert json.loads(came)["on"] is True
                        break
                page.get_by_role("button", name="Actions for Machine 1").click()
                top(page).get_by_role("button", name="Lock screen").click()
                told(page, "Machine 1: olga has Machine 1's keyboard and mouse over a live line at this moment. Wait until they are given back.")
                assert comet.state.hid == []  # (nothing went to the machine by either road)
    finally:
        comet.stop()


def test_a_line_the_program_ends_while_a_key_is_down_leaves_nothing_down_and_the_view_saying_why(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 40, 160)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            page.keyboard.down("KeyA")
            until(page, lambda: kvm_keys(comet) == [("KeyA", True)], f"the key did not go down: {comet.state.hid}")
            # The machine's tile is changed by an admin: the program ends its lines, and lets go of what was down.
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
                assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
                assert admin.put(f"/api/v1/devices/{live.device}", json={"url": comet.url, "name": "Machine 1"}).status_code == 200  # type: ignore[attr-defined]
            until(page, lambda: kvm_keys(comet) == [("KeyA", True), ("KeyA", False)], f"the key stayed down on the machine: {comet.state.hid}")
            expect(page.locator("#focus-live")).to_have_text("No live picture: stills")
            expect(page.locator("#focus-live")).to_have_attribute("title", "This machine was changed or taken off the wall. Open it again.")
            expect(page.locator("#focus-control")).to_be_hidden()
            expect(page.locator("#focus-again")).to_be_visible()
            page.keyboard.up("KeyA")
            page.wait_for_timeout(300)
            assert kvm_keys(comet) == [("KeyA", True), ("KeyA", False)]  # nothing more over a line that is gone
            # Live again: a new pass, a new line, from the program as it is now.
            page.locator("#focus-again").click()
            expect(page.locator("#focus-live")).to_contain_text("Live · JPEG")
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            # The activity log says, in words, that the keyboard and mouse were taken, and why they were taken away.
            pane = settings(page, "activity")
            taken = pane.locator("tr", has=page.locator("td", has_text=re.compile(r"^Keyboard and mouse taken$")))
            expect(taken).to_have_count(1)
            expect(taken).to_contain_text("Machine 1")
            away = pane.locator("tr", has=page.locator("td", has_text=re.compile(r"^Keyboard and mouse taken away$")))
            expect(away).to_have_count(1)
            expect(away).to_contain_text("the machine was changed or taken off the wall")
    finally:
        comet.stop()


def test_an_admin_takes_over_where_somebody_else_holds_the_keyboard_and_the_holders_page_says_who(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # An operator holds the machine's keyboard, with Ctrl down. An admin sees who, takes over after a question that names
    # her, and types; her page says that the admin took over, offers her no take-over of her own, and sends nothing more.
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (60, 30, 160)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live:
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
                assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
                made = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"})
                assert made.status_code == 201, made.text
            with looking(browser, live) as hers, looking(browser, live) as mine:
                sign_in(hers, live, "olga may act here", name="olga")
                enlarged(hers, "Machine 1")
                hers.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
                hers.keyboard.press("c")
                expect(hers.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
                hers.keyboard.down("ControlLeft")
                until(hers, lambda: kvm_keys(comet) == [("ControlLeft", True)], f"her Ctrl did not go down: {comet.state.hid}")

                sign_in(mine, live, PASSWORD, name="admin")
                enlarged(mine, "Machine 1")
                mine.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
                mine.keyboard.press("c")
                expect(mine.locator("#focus-control")).to_have_text("Take over from olga")
                # Asked first, naming her; not taken when the question is answered no.
                mine.locator("#focus-control").click()
                expect(top(mine)).to_contain_text("olga has the keyboard and mouse of Machine 1. Take them over?")
                top(mine).get_by_role("button", name="Cancel").click()
                expect(mine.locator("#focus-control")).to_have_text("Take over from olga")
                mine.wait_for_timeout(300)
                assert kvm_keys(comet) == [("ControlLeft", True)]
                mine.keyboard.press("c")  # (the key C asks the same question)
                top(mine).get_by_role("button", name="Take over").click()
                expect(mine.locator("#focus-control")).to_have_attribute("aria-pressed", "true")

                # Her page: told who took them, and no take-over offered to an operator; her Ctrl let go of on the machine.
                told(hers, "admin took over this machine's keyboard and mouse")
                expect(hers.locator("#focus-control")).to_have_text("Controlled by admin")
                expect(hers.locator("#focus-keyboard-toggle")).to_be_disabled()
                until(hers, lambda: kvm_keys(comet) == [("ControlLeft", True), ("ControlLeft", False)], f"her Ctrl stayed down: {comet.state.hid}")
                hers.keyboard.up("ControlLeft")
                hers.keyboard.press("KeyB")  # (her page holds nothing: nothing goes)
                hers.locator("#focus-control").click()  # asked again: refused, and still no take-over for her
                expect(hers.locator("#focus-control")).to_have_text("Controlled by admin")

                mine.keyboard.press("KeyA")
                until(mine, lambda: len(kvm_keys(comet)) >= 4, f"the admin's key did not arrive: {comet.state.hid}")
                mine.wait_for_timeout(300)
                assert kvm_keys(comet) == [("ControlLeft", True), ("ControlLeft", False), ("KeyA", True), ("KeyA", False)], comet.state.hid

                # The activity log says who took them from whom.
                mine.keyboard.press("ControlRight")  # (given back, so that the page's own keys work again)
                expect(mine.locator("#focus-control")).to_have_text("Control")
                mine.keyboard.press("Escape")
                expect(mine.locator("#focus")).to_be_hidden()
                pane = settings(mine, "activity")
                over = pane.locator("tr", has=mine.locator("td", has_text=re.compile(r"^Keyboard and mouse taken over$")))
                expect(over).to_have_count(1)
                expect(over).to_contain_text("from olga")
                away = pane.locator("tr", has=mine.locator("td", has_text=re.compile(r"^Keyboard and mouse taken away$")))
                expect(away).to_have_count(1)
                expect(away).to_contain_text("taken over by admin")
    finally:
        comet.stop()


def test_keyboard_and_mouse_given_back_for_want_of_input_are_said_in_the_page(tmp_path: Path, browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setattr(live_module, "IDLE_GIVE_BACK", 2.0)
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (30, 120, 120)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            page.keyboard.down("ShiftLeft")  # and nothing more
            told(page, "Given back after 2 seconds without input")
            expect(page.locator("#focus-control")).to_have_text("Control")
            expect(page.locator("#focus-control")).to_have_attribute("title", "Given back after 2 seconds without input. Take them again (C)")
            until(page, lambda: kvm_keys(comet) == [("ShiftLeft", True), ("ShiftLeft", False)], f"Shift stayed down: {comet.state.hid}")
            expect(page.locator("#focus-live")).to_contain_text("Live")  # the picture goes on
            page.keyboard.up("ShiftLeft")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            pane = settings(page, "activity")
            back = pane.locator("tr", has=page.locator("td", has_text=re.compile(r"^Keyboard and mouse given back$")))
            expect(back.filter(has_text="without input")).to_have_count(1)
    finally:
        comet.stop()


def test_a_take_over_slower_than_five_seconds_is_waited_for_and_leaves_the_admin_holding_the_machine(tmp_path: Path, browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    # The way in to a machine's keyboard takes up to ten and a half seconds on a PC with Intel AMT between two sessions,
    # some forty-seven on a JetKVM connected anew. The page gave up on an answer after five and gave keyboard and mouse
    # back; the server, which answers every asking in turn, finished the take-over first: the holder was told "taken",
    # the admin's page said "The machine did not answer", and nobody held the machine.
    real_open = live_module.KvmdHid.open
    slow = {"on": False}

    async def slow_open(self: live_module.KvmdHid) -> None:
        if slow["on"]:
            await asyncio.sleep(7.0)
        await real_open(self)

    monkeypatch.setattr(live_module.KvmdHid, "open", slow_open)
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (90, 40, 140)), picture_type="image/jpeg", width=320, height=240)).start()
    try:
        with the_program(tmp_path, comet) as live:
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
                assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
                made = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"})
                assert made.status_code == 201, made.text
            with looking(browser, live) as hers, looking(browser, live) as mine:
                sign_in(hers, live, "olga may act here", name="olga")
                enlarged(hers, "Machine 1")
                hers.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
                hers.keyboard.press("c")
                expect(hers.locator("#focus-control")).to_have_attribute("aria-pressed", "true")

                slow["on"] = True
                sign_in(mine, live, PASSWORD, name="admin")
                enlarged(mine, "Machine 1")
                mine.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
                mine.keyboard.press("c")
                expect(mine.locator("#focus-control")).to_have_text("Take over from olga")
                mine.keyboard.press("c")
                top(mine).get_by_role("button", name="Take over").click()
                expect(mine.locator("#focus-control")).to_have_text("Asking...")
                mine.wait_for_timeout(5500)  # (past the five seconds the page gave an answer)
                expect(mine.locator("#focus-control")).to_have_text("Asking...")
                expect(mine.locator("#focus-control")).to_have_attribute("aria-pressed", "true", timeout=PATIENCE)
                told(hers, "admin took over this machine's keyboard and mouse")
                expect(hers.locator("#focus-control")).to_have_text("Controlled by admin")
                # Held by the admin: a key of theirs reaches the machine, and nothing gave it back meanwhile.
                mine.keyboard.press("KeyA")
                until(mine, lambda: ("KeyA", False) in kvm_keys(comet), f"the admin's key did not arrive: {comet.state.hid}")
                mine.wait_for_timeout(500)
                expect(mine.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
                with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as olga:
                    assert olga.post("/api/v1/login", json={"name": "olga", "password": "olga may act here"}).status_code == 200
                    refused = olga.post(f"/api/v1/devices/{live.device}/actions", json={"action": "ctrl_alt_del"})  # type: ignore[attr-defined]
                    assert (refused.status_code, refused.json().get("by")) == (409, "admin"), refused.text
                mine.keyboard.press("ControlRight")
                expect(mine.locator("#focus-control")).to_have_text("Control")
    finally:
        comet.stop()
