"""A stand-in for a GLKVM device: just enough of the kvmd API for the wall."""

from __future__ import annotations

import asyncio
import datetime
import secrets
import struct
import threading
import time
import zlib
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
from fastapi.responses import JSONResponse, Response

from tests import local_socket


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
    atx: bool = False  # is an ATX power board attached?
    hostname: str = "glkvm"
    picture_type: str = "image/png"  # what the device claims its snapshot is
    token_reply: str | None = None  # a session token of the device's choosing, instead of a sound one
    stall: float = 0.0  # seconds every request is left unanswered for; set back to 0 to let them go
    slow_snapshot: float = 0.0  # seconds a snapshot takes
    slow_login: float = 0.0  # seconds a login takes
    slow_action: float = 0.0  # seconds a power button takes to be answered
    slow: dict[str, float] = field(default_factory=dict)  # path -> seconds that one takes
    requests: int = 0  # how many requests arrived, answered or not
    model: object = "RM10"  # what it claims to be
    wol: list[dict[str, str]] = field(default_factory=list)
    # A multi-port KVM (Comet X): one colour per input, None for an input with nothing plugged in.
    ports: list[tuple[int, int, int] | None] = field(default_factory=list)
    active_port: int = 0
    keyboard_online: bool = True  # what it says of the keyboard it is to the computer (a cable that is out: False)
    # As a real Comet X: after another computer is put on screen it says "no keyboard" until a key has been sent.
    forgets_keyboard: bool = False
    tokens: set[str] = field(default_factory=set)
    logins: int = 0
    viewers: int = 0
    snapshot_queries: list[dict[str, str]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)  # what the wall asked the device to do


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

    async def pause(seconds: float, still_wanted: Any = lambda: True) -> None:
        """Wait, in steps short enough that stopping the fake never has to wait for it."""
        until = time.monotonic() + seconds
        while still_wanted() and time.monotonic() < until:
            await asyncio.sleep(0.02)

    @app.middleware("http")
    async def auth(request: Request, call_next: Any) -> Any:
        state.requests += 1
        await pause(state.stall, lambda: state.stall > 0)
        await pause(state.slow.get(request.url.path, 0), lambda: request.url.path in state.slow)
        if request.url.path != "/api/auth/login" and request.cookies.get("auth_token") not in state.tokens:
            return error("UnauthorizedError", 401)
        return await call_next(request)

    @app.post("/api/auth/login")
    async def login(request: Request) -> Any:
        form = parse_qs((await request.body()).decode())
        state.logins += 1
        await pause(state.slow_login)
        if state.login_status != 200:  # something is wrong with it, and not with the password
            return error("ServerError", state.login_status)
        if form.get("user") != ["admin"] or form.get("passwd") != [state.password]:
            return error("ForbiddenError", 403)
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
        if state.idle_until_viewer and state.viewers == 0:
            return error("UnavailableError", 503)
        if "preview" in query:
            width, height = int(query["preview_max_width"]), int(query["preview_max_height"])
        else:
            width, height = state.width, state.height
        signal, colour = state.signal, state.colour
        if state.ports:
            plugged = state.ports[state.active_port]
            signal, colour = plugged is not None, plugged or colour
        return Response(
            state.picture or fake_frame(width, height, colour if signal else (60, 60, 60), int(time.time() * 4)),
            media_type=state.picture_type,
            headers={"X-UStreamer-Online": "true" if signal else "false"},
        )

    @app.get("/api/streamer")
    async def streamer() -> Any:
        resolution = {"width": state.width, "height": state.height}
        source = {"online": state.signal, "captured_fps": 60, "resolution": resolution}
        return ok({"streamer": {"hdmi": {"signal": state.signal}, "source": source}})

    @app.get("/api/info")
    async def info() -> Any:
        return ok({"health": {"cpu": {"percent": 17}, "mem": {"percent": 39.5}, "temp": {"cpu": 42.5}}})

    @app.get("/api/hid")
    async def hid() -> Any:
        return ok({"keyboard": {"online": state.keyboard_online}, "mouse": {"online": state.keyboard_online}})

    @app.get("/api/atx")
    async def atx() -> Any:
        return ok({"enabled": state.atx, "leds": {"power": state.atx, "hdd": False}})

    @app.get("/api/upgrade/version")
    async def version() -> Any:
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
        return ok()

    @app.post("/api/atx/click")
    async def atx_click(button: str) -> Any:
        if not state.atx:
            return error("BadRequestError", 400, "ATX is not available")
        state.actions.append(f"atx {button}")
        await pause(state.slow_action)
        return ok()

    @app.get("/api/switch")
    async def switch() -> Any:
        # Shaped like kvmd/apps/kvmd/switch/state.py in GL.iNet's published firmware source.
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
        if state.ws_moved:  # "not here, over there": which a device has no business saying
            await websocket.send_denial_response(Response(status_code=302, headers={"Location": state.ws_moved}))
            return
        if websocket.cookies.get("auth_token") not in state.tokens:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        state.viewers += 1
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            state.viewers -= 1

    return app


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
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def start(self) -> FakeKvm:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake KVM did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
