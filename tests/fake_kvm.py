"""A stand-in for a GLKVM device, or for a stock PiKVM (`stock=True`): just enough of the kvmd API for the wall.

The stock mode answers as kvmd 4.226 did in its own test environment (`make run`, with a video loopback and the
GPIO mockup: see tools/pikvm-testenv.md), where it differs from GL.iNet's firmware: the session only as a cookie,
403 for a session it does not know, none of GL.iNet's own routes (the firmware's version, the host name,
Wake-on-LAN, the KVM's own restart), what it is in /api/info, an empty switch where it has none, its streamer
`null` while nobody watches, a public Redfish root, and a media line that nginx answers 502 while kvmd-media is
not running.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import secrets
import struct
import time
import zlib
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from tests import ServerThread, local_socket


@dataclass
class FakeState:
    password: str = "secret"
    colour: tuple[int, int, int] = (32, 74, 135)
    signal: bool = True
    ws_moved: str = ""  # set: the websocket answers with a redirect to this address
    picture: bytes = b""  # set: sent as the picture, whatever it is
    login_status: int = 200  # another number: signing in fails with it, whatever the password
    width: int = 1920  # what the connected computer outputs
    height: int = 1080
    idle_until_viewer: bool = False  # like kvmd: snapshots fail with 503 until a websocket client connects
    # ...and once the last one has gone, its streamer goes on for this long (kvmd: ten seconds), and then stops
    streamer_grace: float = 0.0
    streamer_until: float = 0.0  # (time.monotonic(): it runs until then with nobody, as after a viewer of its own page left)
    atx: bool = False  # is an ATX power board attached?
    # The computer behind the board, and how the board says so. As a Comet does (seen on a real one with its board,
    # 2026-10-14): in a word of its own, "power": "on", "off" or "sleep", while the light in `leds` stays false;
    # `atx_words=False` answers as stock kvmd does, with the light and no word.
    computer_on: bool = True
    asleep: bool = False
    atx_words: bool = True
    # A Comet's board answers one asker at a time, a fifth of a second each, and tells whoever asks meanwhile that there
    # is no board and the computer is off. The seconds each answer takes here (0: at once, and nobody overlaps).
    atx_answer: float = 0.0
    atx_overlaps: int = 0  # how many answers said "no board" because another was being given
    atx_none_next: int = 0  # this many of the next answers say "no board", as if each came while another was given
    # A Comet answers a click at once and holds the button on: seconds it holds each one (its own page says 0.5 and
    # 6.5; a computer that was off came on at a long press and went off again seconds later). `busy` is said for the
    # first `busy_for` seconds of a press only (about half a second on the real one, whatever the hold).
    holds: dict[str, float] = field(default_factory=lambda: {"power": 0.0, "power_long": 0.0, "reset": 0.0})
    busy_for: float = 0.0
    # How the computer takes the buttons, where it does (`computer_follows`; otherwise nothing a press does is seen): a
    # short press switches on what is off, and asks a running system to shut down, which it does this many seconds
    # later (None: it does not); a long one cuts the power when it is let go (and switches on, for the hold, what was
    # off); reset leaves the power on. The board's word follows the computer `atx_lag` seconds late (three or four on
    # the real one).
    computer_follows: bool = False
    shuts_down_after: float | None = 0.0
    atx_lag: float = 0.0
    word_was: bool = True  # (what the word says until `word_until`)
    word_until: float = 0.0
    held_over: int = 0  # presses that came while the board held another
    # Set: a click the board took (and pressed) is answered with this status and body instead of its yes: what a KVM's web
    # server says while kvmd restarts behind it (502, 503, 504), or kvmd's own 500. (0, ""): the answer breaks off on its way.
    atx_reply: tuple[int, str] | None = None
    # And it says its board's state on its line for events (/api/ws), as its own page reads it (a real Comet on 2026-10-18;
    # stock kvmd 4.226 by its source): an `atx` event with the whole of it, a moment after the line opens
    # and at every change; and "no board, off" there too while the board answers somebody else at /api/atx (two askers at a
    # tenth of a second each beside it: the line said so within a second and until they stopped, then "on" again 0.2 s
    # later). False: a KVM whose events do not carry it. `atx_event_none`: the line says "no board" as long as it is set.
    atx_events: bool = True
    atx_event_none: bool = False
    atx_events_sent: int = 0
    # A Comet reads its board for that line about every second and a quarter, and its `busy` lasts half a second: in two
    # presses on the real one the line never said busy. Stock kvmd's line says it (its poller is told of every change, and
    # its busy lasts the hold). True: this one's line says it all the same.
    line_says_busy: bool = False
    atx_event_busy: bool = False  # the line says busy, whatever the board does (as stock kvmd's says it through a hold)
    atx_resend: float = 0.0  # set: the line says the board's state again every so many seconds, changed or not (a real one does not)
    # How often the line reads the board: a real Comet about every second and a quarter (what it says there may be that
    # old); here every fiftieth of a second unless a test says otherwise.
    line_every: float = 0.02
    # kvmd answers a `ping` on that line with a `pong` (the real Comet within milliseconds); False: it says nothing back,
    # and nothing else either (a line that went quiet).
    pongs: bool = True
    pings: int = 0
    close_on_ping: bool = False  # a KVM that does not know kvmd's `ping` and ends the line at one
    event_junk: str = ""  # set: sent as one message on the next line for events that looks (then emptied)
    # A Fingerbot paired with it (GL.iNet's, over Bluetooth), as a real Comet with one answered on 2026-10-18: its line for
    # events says `{"exist": true}` in a `fingerbot` event a moment after it opens (0.2 to 2.0 s on the real one, twice 4.3; here
    # `fingerbot_event_after`) and again when that changes; a Comet without one says `{"exist": false}` (stock kvmd: no such
    # event, and no such routes). A press (POST /api/fingerbot/click, `press_time` in ms and `angle_enum` 1 or 2, as the
    # Comet's own page sends them) is answered "success" `fingerbot_answer` seconds after it came (about two on the real
    # one, whatever the press's time); one that comes while another is being taken (the first `fingerbot_taking` seconds of
    # it: a press 0.3 s into another failed on the real one, one 1.0 s in was taken) is answered 400 "Failed to click"
    # after `fingerbot_fail_after`; so is every press where `fingerbot_fails`. `fingerbot_silent`: a press is never
    # answered. Its battery (GET /api/fingerbot/battery) is `fingerbot_battery` (the real one said 101).
    fingerbot: bool = False
    fingerbot_events: bool = True  # False: the line says nothing of a Fingerbot at all
    fingerbot_event_after: float = 0.0
    # A real one said it again on every line open to it whenever a new line was told (4.3 s after that line opened, twice):
    # set, it is said again every so many seconds, changed or not.
    fingerbot_resend: float = 0.0
    fingerbot_events_sent: int = 0
    fingerbot_answer: float = 0.0
    fingerbot_taking: float = 0.0
    fingerbot_fail_after: float = 0.0
    fingerbot_fails: bool = False
    fingerbot_silent: bool = False
    fingerbot_battery: object = 101
    fingerbot_battery_answer: float = 0.0  # seconds a question of its battery takes (0.6 to 0.7 on the real one)
    fingerbot_battery_trickle: float = 0.0  # set: its battery's answer comes a byte at a time, this many seconds apart
    # Set: a press it takes is answered with this status and body instead of "success" (after `fingerbot_answer`): what a
    # kvmd in trouble, or a proxy before it, may say. (0, ""): the answer breaks off on its way.
    fingerbot_reply: tuple[int, str] | None = None
    presses: list[tuple[str, str]] = field(default_factory=list)  # (press_time, angle_enum) of every press that came, as sent
    presses_at: list[float] = field(default_factory=list)  # (time.monotonic()) when each press it took came
    battery_asked: int = 0
    battery_at: list[float] = field(default_factory=list)  # (time.monotonic()) when each question of its battery came
    # Without a signal a Comet answers a request for a picture with 503 after five or six seconds, where stock kvmd sends
    # a placeholder at once: seconds to take over that 503 (None: the placeholder).
    no_signal_snapshot: float | None = None
    hostname: str = "glkvm"
    picture_type: str = "image/png"  # what the device claims its snapshot is
    token_reply: str | None = None  # a session token of the device's choosing, instead of a sound one
    stall: float = 0.0  # seconds every request is left unanswered for; set back to 0 to let them go
    slow_snapshot: float = 0.0  # seconds a snapshot takes
    slow_login: float = 0.0  # seconds a login takes
    slow_action: float = 0.0  # seconds a power button takes to be answered
    slow: dict[str, float] = field(default_factory=dict)  # path -> seconds that one takes
    requests: int = 0  # how many requests arrived, answered or not
    asked: deque[str] = field(default_factory=lambda: deque(maxlen=4096))  # the last of them, as "GET /api/info"
    model: object = "RM10"  # what it claims to be
    version_fails: int = 0  # so many times its firmware's version is answered with a 500 first (GLKVM)
    version_moved: str = ""  # set: its firmware's version answers with a redirect to this (GLKVM)
    wol: list[dict[str, str]] = field(default_factory=list)
    # A multi-port KVM (Comet X): one colour per input, None for an input with nothing plugged in.
    ports: list[tuple[int, int, int] | None] = field(default_factory=list)
    active_port: int = 0
    keyboard_online: bool = True  # what it says of the keyboard it is to the computer (a cable that is out: False)
    # Whether its mouse is absolute (stock kvmd's default) or relative (a real Comet was set to "usb_rel": `mouse.absolute`
    # false in its /api/hid). kvmd drops a move of the other kind: counted in `pointer_dropped` (every event is in `hid`
    # as it was sent all the same).
    mouse_absolute: bool = True
    pointer_dropped: int = 0
    # As a real Comet X: after another computer is put on screen it says "no keyboard" until a key has been sent; and as a
    # real Comet, after the computer behind it came on.
    forgets_keyboard: bool = False
    tokens: set[str] = field(default_factory=set)
    logins: int = 0
    viewers: int = 0  # /api/ws connections open right now: those that hold its streamer, and the lines for keys (stream=0)
    streams: int = 0  # ...of which hold its streamer
    key_lines: int = 0  # ...and of which do not
    snapshot_queries: list[dict[str, str]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)  # what the wall asked the device to do
    # The H.264 line of stock PiKVM (/api/media/ws): whether it has one, what pictures it sends round and round
    # (whether each is a key frame, and the access unit; made up when none are given), at what pace, and how large a
    # made-up picture is. A Comet has none: its video is WebRTC only.
    media: bool = False
    film: list[tuple[bool, bytes]] = field(default_factory=list)
    fps: float = 15.0
    unit_bytes: int = 2000
    media_clients: int = 0  # lines open on it right now
    key_requests: int = 0  # how often a line asked for a key frame
    hid: list[dict[str, Any]] = field(default_factory=list)  # the keyboard and mouse events that arrived on /api/ws, as sent
    ws_streams: list[str | None] = field(default_factory=list)  # what each websocket client said with `stream`
    ws_queries: deque[str] = field(default_factory=lambda: deque(maxlen=256))  # what came after the "?" of each websocket asked for
    # Stock kvmd, as it answered in its own test environment (see the top of this file), instead of GLKVM.
    stock: bool = False
    kvmd_version: object = "4.226"  # what a stock one says it is in /api/info
    platform: object = field(default_factory=lambda: {"type": "rpi", "base": "Virtual Raspberry Pi", "model": "test_model", "board": "test_board", "video": "test_video", "serial": "0000000000000000"})
    server_host: object = "pikvm"  # its name in /api/info (meta.server.host: the machine's own, as the page shows it)
    jiggler: bool = False  # whether keep-awake is on (a stock one says so in /api/hid)
    jiggler_enabled: bool = True  # False: keep-awake is switched off in its settings, and switching it on answers yes and does nothing


GLINET_ONLY = (
    "/api/upgrade/version", "/api/upgrade/reboot", "/api/system/get_hostname", "/api/wol/list", "/api/wol/wake",
    "/api/fingerbot/click", "/api/fingerbot/battery",
)  # fmt: skip
REDFISH_ROOT = {
    "@odata.id": "/redfish/v1", "@odata.type": "#ServiceRoot.v1_6_0.ServiceRoot", "Id": "RootService", "Name": "Root Service",
    "RedfishVersion": "1.6.0", "Managers": {"@odata.id": "/redfish/v1/Managers"}, "Systems": {"@odata.id": "/redfish/v1/Systems"},
}  # fmt: skip


def _png(width: int, height: int, rows: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 1)) + chunk(b"IEND", b"")


def fake_frame(width: int, height: int, colour: tuple[int, int, int], tick: int) -> bytes:
    """A flat 'desktop' with a taskbar and a bar that moves every tick, so refreshes are visible."""
    bar_w = max(4, width // 40)
    pos = (tick * bar_w) % (width - bar_w)
    desk = b"\x00" + bytes(colour) * pos + b"\xff\xff\xff" * bar_w + bytes(colour) * (width - pos - bar_w)
    task = b"\x00" + b"\x18\x18\x18" * width
    split = height - max(4, height // 18)
    return _png(width, height, desk * split + task * (height - split))


def make_device_certificate(directory: Path) -> tuple[Path, Path]:
    """A certificate like the Comets ship: self-signed, named localhost, 'valid' from 1970 to 1979.

    Made once per folder: a device that is started again, at another address too, is still that device.
    """
    if (directory / "cert.pem").exists() and (directory / "key.pem").exists():
        return directory / "cert.pem", directory / "key.pem"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GLKVM"), x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(1979, 12, 30, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


def make_fake_kvm(state: FakeState) -> FastAPI:
    app = FastAPI()

    def ok(result: Any = None) -> dict[str, Any]:
        return {"ok": True, "result": result if result is not None else {}}

    def error(name: str, status: int, message: str = "") -> JSONResponse:
        return JSONResponse({"ok": False, "result": {"error": name, "error_msg": message}}, status_code=status)

    def streaming() -> bool:
        """Whether its streamer runs: while somebody holds /api/ws open, and for a while after the last one has gone."""
        return state.streams > 0 or time.monotonic() < state.streamer_until

    async def pause(seconds: float, still_wanted: Any = lambda: True) -> None:
        """Wait, in steps short enough that stopping the fake never has to wait for it."""
        until = time.monotonic() + seconds
        while still_wanted() and time.monotonic() < until:
            await asyncio.sleep(0.02)

    @app.middleware("http")
    async def auth(request: Request, call_next: Any) -> Any:
        state.requests += 1
        state.asked.append(f"{request.method} {request.url.path}")
        await pause(state.stall, lambda: state.stall > 0)
        await pause(state.slow.get(request.url.path, 0), lambda: request.url.path in state.slow)
        if state.stock:
            return await stock_auth(request, call_next)
        if request.url.path != "/api/auth/login" and request.cookies.get("auth_token") not in state.tokens:
            return error("UnauthorizedError", 401)
        return await call_next(request)

    async def stock_auth(request: Request, call_next: Any) -> Any:
        """As kvmd: a route it has not got is not found before anybody is asked who they are; its Redfish root is anybody's;
        the two headers sign one request in, and a session it does not know is forbidden, not unknown."""
        path = request.url.path
        if path == "/api/upgrade/version" and state.version_fails > 0:  # (its web server, at a moment kvmd is not there behind it)
            state.version_fails -= 1
            return PlainTextResponse("502 Bad Gateway", status_code=502)
        if path in GLINET_ONLY:
            return PlainTextResponse("404: Not Found", status_code=404)
        if path == "/redfish/v1/":
            return PlainTextResponse("308: Permanent Redirect", status_code=308, headers={"Location": "/redfish/v1"})
        if path == "/redfish/v1":
            return JSONResponse(REDFISH_ROOT)
        if path == "/api/auth/login":
            return await call_next(request)
        if user := request.headers.get("x-kvmd-user"):
            if user != "admin" or request.headers.get("x-kvmd-passwd") != state.password:
                return error("ForbiddenError", 403, "Forbidden")
            return await call_next(request)
        if token := request.cookies.get("auth_token"):
            return await call_next(request) if token in state.tokens else error("ForbiddenError", 403, "Forbidden")
        return error("UnauthorizedError", 401, "Unauthorized")

    @app.post("/api/auth/login")
    async def login(request: Request) -> Any:
        form = parse_qs((await request.body()).decode())
        state.logins += 1
        await pause(state.slow_login)
        if state.login_status != 200:  # something is wrong with it, and not with the password
            return error("ServerError", state.login_status)
        if form.get("user") != ["admin"] or form.get("passwd") != [state.password]:
            return error("ForbiddenError", 403)
        if state.stock:
            # Stock kvmd hands its session out as a cookie only, and the token is 64 hexadecimal digits.
            token = secrets.token_hex(32) if state.token_reply is None else state.token_reply
            state.tokens.add(token)
            reply = JSONResponse(ok())
            reply.headers["Set-Cookie"] = f"auth_token={token}; HttpOnly; Path=/; SameSite=Strict"
            return reply
        token = secrets.token_hex(16) if state.token_reply is None else state.token_reply
        state.tokens.add(token)
        return ok({"token": token})

    @app.get("/api/auth/check")
    async def auth_check() -> Any:
        return ok()

    @app.get("/api/streamer/snapshot")
    async def snapshot(request: Request) -> Response:
        query = dict(request.query_params)
        state.snapshot_queries.append(query)
        await pause(state.slow_snapshot)
        if state.idle_until_viewer and not streaming():
            return error("UnavailableError", 503)
        if "preview" in query:
            width, height = int(query["preview_max_width"]), int(query["preview_max_height"])
        else:
            width, height = state.width, state.height
        signal, colour = state.signal, state.colour
        if state.ports:
            plugged = state.ports[state.active_port]
            signal, colour = plugged is not None, plugged or colour
        if not signal and state.no_signal_snapshot is not None:
            await pause(state.no_signal_snapshot)
            return error("UnavailableError", 503, "Service Unavailable")
        return Response(
            state.picture or fake_frame(width, height, colour if signal else (60, 60, 60), int(time.time() * 4)),
            media_type=state.picture_type,
            headers={"X-UStreamer-Online": "true" if signal else "false"},
        )

    @app.get("/api/streamer")
    async def streamer() -> Any:
        resolution = {"width": state.width, "height": state.height}
        source = {"online": state.signal, "captured_fps": 60, "resolution": resolution}
        if state.stock:
            # Its streamer runs only while somebody holds /api/ws open with the stream: until then it is nothing at all.
            running = {"encoder": {"type": "CPU", "quality": 80}, "source": {**source, "captured_fps": 30, "desired_fps": 30}}
            return ok({"features": {"h264": True, "quality": True, "resolution": False}, "streamer": running if streaming() else None})
        return ok({"streamer": {"hdmi": {"signal": state.signal}, "source": source}})

    @app.get("/api/info")
    async def info() -> Any:
        health = {"cpu": {"percent": 17}, "mem": {"percent": 39.5}, "temp": {"cpu": 42.5}}
        if state.stock:
            # What it is, and how it is, where kvmd says it: under `hw`, beside its version and the name it goes by.
            return ok({
                "auth": {"enabled": True}, "extras": None, "fan": {"monitored": False, "state": None},
                "hw": {"health": {**health, "throttling": {"raw_flags": 0}}, "platform": state.platform},
                "meta": {"server": {"host": state.server_host}}, "node": {"host": "0c0054417824"},
                "system": {"kvmd": {"version": state.kvmd_version}, "streamer": {"app": "ustreamer", "version": "6.67"}},
            })  # fmt: skip
        return ok({"health": health})

    @app.get("/api/hid")
    async def hid() -> Any:
        if state.stock:
            keyboard = {"online": state.keyboard_online, "leds": {"caps": False, "num": False, "scroll": False}, "outputs": {"active": "", "available": []}}
            output = "usb" if state.mouse_absolute else "usb_rel"
            mouse = {"online": state.keyboard_online, "absolute": state.mouse_absolute, "outputs": {"active": output, "available": ["usb", "usb_rel"]}}
            jiggler = {"active": state.jiggler, "enabled": state.jiggler_enabled, "interval": 60}
            return ok({"busy": False, "connected": None, "enabled": True, "online": True, "jiggler": jiggler, "keyboard": keyboard, "mouse": mouse})
        output = "usb" if state.mouse_absolute else "usb_rel"
        mouse = {"online": state.keyboard_online, "absolute": state.mouse_absolute, "outputs": {"active": output, "available": ["usb", "usb_rel", "usb_hybrid", "usb_touch"]}}
        return ok({"keyboard": {"online": state.keyboard_online}, "mouse": mouse})

    answering_atx = [0]
    busy_until = [0.0]
    held_until = [0.0]
    pressing: set[asyncio.Task[None]] = set()

    def power_to(on: bool) -> None:
        """The computer goes on or off; its picture with it, and the board's word some moments later."""
        if on == state.computer_on:
            return
        state.word_was, state.word_until = state.computer_on, time.monotonic() + state.atx_lag
        state.computer_on = state.signal = on
        if on and state.forgets_keyboard:
            state.keyboard_online = False  # (as a Comet, until a key is sent)

    async def press(button: str, hold: float) -> None:
        was_on = state.computer_on
        if button in ("power", "power_long") and not was_on:
            power_to(True)  # a press switches on what is off, at once
        await pause(hold)
        if button == "power_long" or (button == "power" and was_on and state.shuts_down_after == 0):
            power_to(False)
        elif button == "power" and was_on and state.shuts_down_after is not None:
            await pause(state.shuts_down_after)
            power_to(False)

    def board(overlapping: bool) -> dict[str, Any]:
        """The board's state as it says it, at /api/atx and on the line for events alike; "no board, off" where it is answering somebody else."""
        there = state.atx and not overlapping
        on = there and (state.word_was if time.monotonic() < state.word_until else state.computer_on)
        busy = time.monotonic() < busy_until[0]
        said: dict[str, Any] = {"enabled": there, "busy": busy, "leds": {"power": on and not state.atx_words, "hdd": False}}
        if state.stock:
            said["acts"] = {"power": False, "reset": False}
        if state.atx_words:
            said["power"] = ("sleep" if state.asleep else "on") if on else "off"
        return said

    @app.get("/api/atx")
    async def atx() -> Any:
        overlapping = answering_atx[0] > 0
        answering_atx[0] += 1
        try:
            await pause(state.atx_answer)
        finally:
            answering_atx[0] -= 1
        if state.atx_none_next > 0:
            state.atx_none_next -= 1
            overlapping = True
        if overlapping and state.atx:
            state.atx_overlaps += 1
        return ok(board(overlapping))

    @app.get("/api/upgrade/version")
    async def version() -> Any:
        if state.version_moved:  # sends whoever asks on, to what may be no address at all
            return Response(status_code=302, headers={"Location": state.version_moved})
        if state.version_fails > 0:  # one of its moments
            state.version_fails -= 1
            return error("ServerError", 500)
        return ok({"model": state.model, "version": "V1.10.1 release2"})

    @app.get("/api/system/get_hostname")
    async def hostname() -> Any:
        return ok({"hostname": state.hostname, "success": True})

    @app.post("/api/upgrade/reboot")
    async def reboot() -> Any:
        state.actions.append("reboot")
        return ok()

    @app.post("/api/hid/events/send_shortcut")
    async def shortcut(keys: str) -> Any:
        state.actions.append(f"shortcut {keys}")
        state.keyboard_online = True  # it tried the keyboard, and found it there
        return ok()

    @app.post("/api/hid/print")
    async def hid_print(request: Request) -> Any:
        state.actions.append("type " + repr((await request.body()).decode()))
        return ok()

    @app.post("/api/hid/set_params")
    async def hid_params(jiggler: str = "") -> Any:
        state.actions.append(f"jiggler {jiggler}")
        if state.jiggler_enabled:  # (kvmd: where it is not enabled, it is not switched, and nothing is said of that)
            state.jiggler = jiggler in ("1", "true")
        return ok()

    @app.post("/api/atx/click")
    async def atx_click(button: str) -> Any:
        if not state.atx:
            return error("BadRequestError", 400, "ATX is not available")
        if button not in state.holds:
            return error("ValidationError", 400, "Invalid button")
        state.actions.append(f"atx {button}")
        now = time.monotonic()
        if now < held_until[0]:
            state.held_over += 1  # taken as well, as the real one took it
        hold = state.holds[button]
        busy_until[0], held_until[0] = now + min(hold, state.busy_for), max(held_until[0], now + hold)
        if state.computer_follows:
            task = asyncio.create_task(press(button, hold))
            pressing.add(task)
            task.add_done_callback(pressing.discard)
        await pause(state.slow_action)
        if state.atx_reply is not None:
            status, body = state.atx_reply
            if status == 0:  # (says more than it sends: the web server ends the connection in the middle of the answer)
                return Response(b'{"ok": tr', headers={"content-length": "400"}, media_type="application/json")
            return Response(body.encode(), status_code=status, media_type="application/json" if body.startswith("{") else "text/html")
        return ok()

    fingerbot_taking_until = [0.0]

    @app.post("/api/fingerbot/click")
    async def fingerbot_click(request: Request) -> Any:
        press_time, angle = request.query_params.get("press_time", ""), request.query_params.get("angle_enum", "")
        state.presses.append((press_time, angle))
        # What the Comet's own page lets through: half a second, or from one to sixty seconds in milliseconds; strength 1 or 2.
        if not (press_time == "500" or (press_time.isdigit() and 1000 <= int(press_time) <= 60000)) or angle not in ("1", "2"):
            return error("ValidationError", 400, "Invalid press")
        now = time.monotonic()
        # (A Comet without a Fingerbot: not seen on a real one, and the wall sends none there. Said as a press that failed.)
        if not state.fingerbot or state.fingerbot_fails or now < fingerbot_taking_until[0]:
            await pause(state.fingerbot_fail_after)
            return error("BadRequestError", 400, "Failed to click")
        fingerbot_taking_until[0] = now + state.fingerbot_taking
        state.actions.append(f"fingerbot {press_time} {angle}")
        state.presses_at.append(now)
        if state.fingerbot_silent:
            await pause(3600, lambda: state.fingerbot_silent)
        await pause(state.fingerbot_answer)
        if state.fingerbot_reply is not None:
            status, body = state.fingerbot_reply
            if status == 0:  # (says more than it sends: the web server ends the connection in the middle of the answer)
                return Response(b'{"ok": tr', headers={"content-length": "400"}, media_type="application/json")
            return Response(body.encode(), status_code=status, media_type="application/json" if body.startswith("{") else "text/html")
        return ok({"result": "success"})

    @app.get("/api/fingerbot/battery")
    async def fingerbot_battery() -> Any:
        state.battery_asked += 1
        state.battery_at.append(time.monotonic())
        await pause(state.fingerbot_battery_answer)
        if not state.fingerbot:  # (not seen on a real one either: the wall asks none without one)
            return error("BadRequestError", 400, "Failed to get battery")
        if state.fingerbot_battery_trickle > 0:
            body = json.dumps(ok({"battery": state.fingerbot_battery})).encode()

            async def trickle() -> AsyncIterator[bytes]:
                for byte in body:
                    yield bytes([byte])
                    await pause(state.fingerbot_battery_trickle, lambda: state.fingerbot_battery_trickle > 0)

            return StreamingResponse(trickle(), media_type="application/json")
        return ok({"battery": state.fingerbot_battery})

    @app.get("/api/switch")
    async def switch() -> Any:
        # Shaped like kvmd/apps/kvmd/switch/state.py in GL.iNet's published firmware source.
        if not state.ports and state.stock:
            # Stock kvmd answers for a switch it has not got: with one of no ports, none of them on screen.
            return ok({
                "model": {"firmware": {"version": 9}, "units": [], "ports": []},
                "summary": {"active_port": -1, "active_id": "", "synced": True},
                "video": {"links": []}, "usb": {"links": []}, "beacons": {"uplinks": [], "downlinks": [], "ports": []},
            })  # fmt: skip
        if not state.ports:
            return error("UnavailableError", 503)
        ports = [
            {"unit": 0, "channel": ch, "name": "", "id": f"1.{ch + 1}", "video": {"dummy": False}}
            for ch in range(len(state.ports))
        ]
        return ok({
            "model": {"firmware": {"version": 1}, "units": [], "ports": ports},
            "summary": {"active_port": state.active_port, "active_id": f"1.{state.active_port + 1}", "synced": True},
            "video": {"links": [colour is not None for colour in state.ports]},
            "usb_otg": {"links": [colour is not None for colour in state.ports]},
        })

    @app.post("/api/switch/set_active")
    async def switch_set_active(port: int) -> Any:
        if not 0 <= port < len(state.ports):
            return error("BadRequestError", 400, "No such port")
        state.active_port = port
        state.actions.append(f"port {port}")
        if state.forgets_keyboard:
            state.keyboard_online = False
        return ok()

    @app.get("/api/wol/list")
    async def wol_list() -> Any:
        return ok({"devices": state.wol})

    @app.post("/api/wol/wake")
    async def wol_wake(mac: str) -> Any:
        state.actions.append(f"wol {mac}")
        return ok()

    @app.websocket("/api/ws")
    async def ws(websocket: WebSocket) -> None:
        state.ws_queries.append(websocket.url.query)
        if state.ws_moved:  # "not here, over there": which a device has no business saying
            await websocket.send_denial_response(Response(status_code=302, headers={"Location": state.ws_moved}))
            return
        if websocket.cookies.get("auth_token") not in state.tokens:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        holds = websocket.query_params.get("stream") != "0"  # (kvmd: a line that says stream=0 does not keep the streamer running)
        state.viewers += 1
        state.streams += holds
        state.key_lines += not holds
        state.ws_streams.append(websocket.query_params.get("stream"))

        async def tell_board() -> None:
            """The board's state at once and at every change, as a Comet sends it on this line (looked at as its own poller would);
            and whether a Fingerbot is paired with it, a moment after the line opened and at every change."""
            last: dict[str, Any] | None = None
            said_at = 0.0
            opened = time.monotonic()
            fingerbot_said: bool | None = None
            fingerbot_at = 0.0
            try:
                while True:
                    if state.event_junk:
                        junk, state.event_junk = state.event_junk, ""
                        await websocket.send_text(junk)
                    if state.atx_events and state.pongs:
                        said = board(state.atx_event_none or answering_atx[0] > 0)
                        if not (state.stock or state.line_says_busy):
                            said["busy"] = False
                        if state.atx_event_busy:
                            said["busy"] = True
                        again = state.atx_resend > 0 and time.monotonic() - said_at >= state.atx_resend
                        if said != last or again:
                            await websocket.send_text(json.dumps({"event_type": "atx", "event": said}))
                            state.atx_events_sent += 1
                            last, said_at = said, time.monotonic()
                    # (After the board, as the real one sent them: `atx`, then `serial`, then `fingerbot`.)
                    if not state.stock and state.fingerbot_events and state.pongs and time.monotonic() - opened >= state.fingerbot_event_after:
                        again = state.fingerbot_resend > 0 and time.monotonic() - fingerbot_at >= state.fingerbot_resend
                        if state.fingerbot != fingerbot_said or again:
                            fingerbot_said, fingerbot_at = state.fingerbot, time.monotonic()
                            await websocket.send_text(json.dumps({"event_type": "fingerbot", "event": {"exist": fingerbot_said}}))
                            state.fingerbot_events_sent += 1
                    await asyncio.sleep(state.line_every)
            except Exception:  # (the line is gone)
                return

        telling = asyncio.create_task(tell_board())
        try:
            while True:
                text = await websocket.receive_text()
                try:
                    said = json.loads(text)
                except ValueError:
                    continue
                if isinstance(said, dict) and said.get("event_type") == "ping":
                    state.pings += 1
                    if state.close_on_ping:
                        await websocket.close(code=1003)
                        break
                    if state.pongs:
                        await websocket.send_text(json.dumps({"event_type": "pong", "event": {}}))
                elif isinstance(said, dict) and "event_type" in said:
                    state.hid.append(said)
                    if said["event_type"] == ("mouse_relative" if state.mouse_absolute else "mouse_move"):
                        state.pointer_dropped += 1
        except WebSocketDisconnect:
            pass
        finally:
            telling.cancel()
            state.viewers -= 1
            state.streams -= holds
            state.key_lines -= not holds
            if holds and not state.streams:
                state.streamer_until = time.monotonic() + state.streamer_grace

    @app.websocket("/api/media/ws")
    async def media(websocket: WebSocket) -> None:
        """Stock PiKVM's H.264 line, as kvmd's media server speaks it: a `media` event, a `start` event back, then pictures.

        Each picture is one binary message: a byte of kind (1), a byte of whether it is a key frame, the access unit.
        A binary 1 from the viewer asks for a key frame (the next picture sent is one); a binary 0 is a ping, answered 255.
        """
        if not state.media:
            # As a web server answers for a path it has not got (a Comet); stock kvmd's nginx has it, and answers 502 while
            # kvmd-media, which its test environment does not start, is not there behind it.
            await websocket.send_denial_response(Response(status_code=502 if state.stock else 404))
            return
        if websocket.cookies.get("auth_token") not in state.tokens:
            await websocket.send_denial_response(Response(status_code=401))
            return
        await websocket.accept()
        state.media_clients += 1
        pictures = state.film or made_up_film(state.unit_bytes)
        started, wants_key = asyncio.Event(), asyncio.Event()

        async def send_pictures() -> None:
            await started.wait()
            at, due = 0, time.monotonic()
            while True:
                if wants_key.is_set():
                    wants_key.clear()
                    while not pictures[at][0]:
                        at = (at + 1) % len(pictures)
                key, data = pictures[at]
                at = (at + 1) % len(pictures)
                await websocket.send_bytes(bytes([1, 1 if key else 0]) + data)
                due += 1.0 / state.fps
                await asyncio.sleep(max(0.0, due - time.monotonic()))

        sending = asyncio.create_task(send_pictures())
        try:
            await websocket.send_text(json.dumps({"event_type": "media", "event": {"video": {"h264": {"profile_level_id": "42E01F"}}}}))
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                data = message.get("bytes")
                if data is not None:
                    if data[:1] == b"\x01":
                        state.key_requests += 1
                        wants_key.set()
                    elif data[:1] == b"\x00":
                        await websocket.send_bytes(b"\xff")
                elif isinstance(message.get("text"), str):
                    said = json.loads(message["text"])
                    if said.get("event_type") == "start" and said.get("event", {}).get("format") == "h264":
                        started.set()
        except WebSocketDisconnect:
            pass
        finally:
            sending.cancel()
            state.media_clients -= 1

    return app


MADE_UP_SPS = b"\x00\x00\x00\x01\x67\x42\xe0\x1f\xda\x02\x80\xf6\x80"  # a sequence parameter set, as a made-up stream has it (kind 7)
MADE_UP_PPS = b"\x00\x00\x00\x01\x68\xce\x38\x80"  # ...and its picture parameter set (kind 8)


def made_up_film(unit_bytes: int, pictures: int = 30, key_every: int = 10, parameter_sets: str = "every") -> list[tuple[bool, bytes]]:
    """Pictures in the shape of H.264 access units in Annex B form, which decode to nothing: a delimiter, then one
    slice whose kind says whether it is a key frame (an IDR picture, 5) or not (1), filled with noise to the size.

    `parameter_sets`: "every" key frame carries them, as a KVM's stream should; "first": only the first does, as some
    streams come; "none": no picture does.
    """
    film = []
    for number in range(pictures):
        key = number % key_every == 0
        sets = MADE_UP_SPS + MADE_UP_PPS if key and (parameter_sets == "every" or (parameter_sets == "first" and number == 0)) else b""
        unit = b"\x00\x00\x00\x01\x09\xf0" + sets + b"\x00\x00\x00\x01" + bytes([0x65 if key else 0x41]) + os.urandom(max(0, unit_bytes - 11 - len(sets)))
        film.append((key, unit))
    return film


def pictures_of(film: bytes) -> list[tuple[bool, bytes]]:
    """A real film's pictures, each from its access unit delimiter to the next, and whether each is a key frame (holds an IDR slice).

    For a film as the desktop's tools make them (desktop/tools/make_testdata.ps1): every picture behind a delimiter.
    """
    starts: list[int] = []
    at = film.find(b"\x00\x00\x01\x09")
    while at >= 0:
        starts.append(at - 1 if at > 0 and film[at - 1] == 0 else at)
        at = film.find(b"\x00\x00\x01\x09", at + 4)
    found = []
    for number, begin in enumerate(starts):
        unit = film[begin : starts[number + 1] if number + 1 < len(starts) else len(film)]
        key, at = False, unit.find(b"\x00\x00\x01")
        while at >= 0 and not key:
            key = at + 3 < len(unit) and unit[at + 3] & 0x1F == 5
            at = unit.find(b"\x00\x00\x01", at + 3)
        found.append((key, unit))
    return found


class FakeKvm:
    """Runs make_fake_kvm() on a localhost port in a background thread.

    Give `tls_dir` to serve HTTPS with a freshly made Comet-style certificate.
    """

    def __init__(self, state: FakeState | None = None, port: int = 0, tls_dir: Path | None = None) -> None:
        self.state = state or FakeState()
        self._sock = local_socket(port)
        self.port: int = self._sock.getsockname()[1]
        tls = {}
        if tls_dir is not None:
            cert, key = make_device_certificate(tls_dir)
            tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        config = uvicorn.Config(make_fake_kvm(self.state), log_level="error", access_log=False, **tls)
        self._server = uvicorn.Server(config)
        self._serving = ServerThread("fake KVM", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)
        self._thread = self._serving.thread

    def start(self) -> FakeKvm:
        self._serving.start()
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
