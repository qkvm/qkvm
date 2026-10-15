"""A stand-in for a JetKVM: the same sign-in, signalling and data-channel messages, with a made-up screen.

It follows the device firmware (jetkvm/kvm, release 0.5.9) in the ways the wall depends on:

* one shared session token, replaced by every login;
* the picture exists only as WebRTC video, arranged over a websocket;
* the answer comes without network addresses, which follow one by one;
* one viewer at a time: a second one makes the first get "otherSessionConnected" and be dropped;
* with its HTTPS mode on it serves HTTPS beside plain HTTP, and sends nobody from the one to the other
  (two stand-ins that share one JetState are one such device: see FakeJetKvm's `tls_dir`);
* fresh from its box, before anybody chose how it is signed in to, it lets nobody in.

Uses the aiortc package, like the driver it tests.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

import av
import uvicorn
from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription
from aiortc.mediastreams import MediaStreamTrack
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from tests import ServerThread, local_socket
from tests.fake_kvm import make_device_certificate


@dataclass
class JetState:
    password: str = "secret"  # empty: the device runs in "no password" mode
    setup: bool = True  # False: fresh from its box, nobody has chosen yet how it is signed in to
    device_id: str = "9f1c2e7ab4d05836"  # the number it gives for itself, to whoever is signed in
    colour: tuple[int, int, int] = (150, 60, 40)
    signal: bool = True
    frozen: bool = False  # as when it loses power: no more video, no more answers, and no goodbye
    width: int = 640
    height: int = 360
    extension: str = ""  # "atx-power" when the ATX board is switched on
    wol: list[dict[str, str]] = field(default_factory=list)
    # Put in by a test: what it says over the signalling once its addresses are out, word for word, each
    # after this long (0.05: while they are still being gathered; 1: when the connection has long been made).
    also_says: list[str] = field(default_factory=list)
    also_after: float = 1.0
    also_said: int = 0
    # Put in by a test: it refuses every login, as after five wrong passwords, and says when to come back
    # (the words of its Retry-After line, whatever they are).
    locked_for: str | None = None
    token: str | None = None
    logins: int = 0
    passwords_over: list[str] = field(default_factory=list)  # how each password shown to it travelled: "http" or "https"
    sessions: int = 0  # video connections made so far
    actions: list[str] = field(default_factory=list)
    typed: list[tuple[int, list[int]]] = field(default_factory=list)  # every keyboard report with keys down
    down: list[int] = field(default_factory=list)  # the keys the last keyboard report left pressed


class FakeScreen(MediaStreamTrack):
    """A flat picture with a bar that moves, ten frames a second."""

    kind = "video"

    def __init__(self, state: JetState) -> None:
        super().__init__()
        self.state = state
        self.count = 0
        self.started = time.monotonic()

    async def recv(self) -> av.VideoFrame:
        self.count += 1
        delay = self.started + self.count / 10 - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        while not self.state.signal or self.state.frozen:  # a JetKVM sends nothing while there is no signal
            await asyncio.sleep(0.05)
        width, height = self.state.width, self.state.height
        frame = av.VideoFrame(width, height, "rgb24")
        plane = frame.planes[0]
        bar = (self.count * 8) % (width - 16)
        row = bytes(self.state.colour) * bar + b"\xff\xff\xff" * 16 + bytes(self.state.colour) * (width - bar - 16)
        row += bytes(plane.line_size - len(row))
        plane.update(row * height)
        frame = frame.reformat(format="yuv420p")
        frame.pts = self.count * 9000
        frame.time_base = Fraction(1, 90000)
        return frame


def make_fake_jetkvm(state: JetState) -> FastAPI:
    app = FastAPI()
    current: dict[str, Any] = {"pc": None, "rpc": None}

    def allowed(cookies: dict[str, str]) -> bool:
        if not state.setup:
            return False
        return not state.password or (state.token is not None and cookies.get("authToken") == state.token)

    @app.get("/device/status")
    async def device_status() -> dict[str, Any]:
        return {"isSetup": state.setup, "sku": "jetkvm-v2"}

    @app.post("/auth/login-local")
    async def login(request: Request) -> JSONResponse:
        body = await request.json()
        state.logins += 1
        if body.get("password"):
            state.passwords_over.append(request.url.scheme)
        if state.locked_for is not None:
            return JSONResponse({"error": "Too many failed attempts"}, status_code=429, headers={"Retry-After": state.locked_for})
        if state.setup and not state.password:
            return JSONResponse({"error": "Login is disabled in noPassword mode"}, status_code=400)
        if not state.setup or body.get("password") != state.password:
            return JSONResponse({"error": "Invalid password"}, status_code=401)
        state.token = str(uuid.uuid4())  # one token for everyone: whoever was logged in no longer is
        reply = JSONResponse({"message": "Login successful"})
        reply.set_cookie("authToken", state.token, max_age=604800, httponly=True)
        return reply

    @app.get("/device")
    async def device(request: Request) -> JSONResponse:
        if not allowed(request.cookies):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        mode = "password" if state.password else "noPassword"
        return JSONResponse({"authMode": mode, "deviceId": state.device_id, "loopbackOnly": False})

    def handle_rpc(channel: Any, message: Any) -> None:
        if state.frozen:
            return
        call = json.loads(message)
        method, params = call["method"], call.get("params") or {}
        result: Any = None
        error: dict[str, Any] | None = None
        if method == "getVideoState":
            result = {
                "ready": state.signal, "streaming": 1, "width": state.width, "height": state.height, "fps": 60,
                **({} if state.signal else {"error": "no_signal"}),
            }  # fmt: skip
        elif method == "getUSBState":
            result = "configured"
        elif method == "getLocalVersion":
            result = {"appVersion": "0.5.9", "systemVersion": "0.2.7"}
        elif method == "getActiveExtension":
            result = state.extension
        elif method == "getATXState":
            result = {"power": True, "hdd": False}
        elif method == "getWakeOnLanDevices":
            result = state.wol
        elif method == "keyboardReport":
            state.down = list(params["keys"])
            if params["keys"] or params["modifier"]:
                state.typed.append((params["modifier"], list(params["keys"])))
        elif method == "setJigglerState":
            state.actions.append(f"jiggler {params['enabled']}")
        elif method == "setATXPowerAction":
            state.actions.append(f"atx {params['action']}")
        elif method == "sendWOLMagicPacket":
            state.actions.append(f"wol {params['macAddress']}")
        elif method == "reboot":
            state.actions.append("reboot")
        else:
            error = {"code": -32601, "message": "Method not found"}
        reply = {"jsonrpc": "2.0", "id": call.get("id")}
        channel.send(json.dumps({**reply, "error": error} if error else {**reply, "result": result}))

    @app.websocket("/webrtc/signaling/client")
    async def signalling(websocket: WebSocket) -> None:
        if not allowed(websocket.cookies):
            await websocket.send_denial_response(JSONResponse({"error": "Unauthorized"}, status_code=401))
            return
        await websocket.accept()
        await websocket.send_text(json.dumps({"type": "device-metadata", "data": {"deviceVersion": "0.5.9"}}))
        try:
            while True:
                text = await websocket.receive_text()
                if text == "ping":
                    await websocket.send_text("pong")
                    continue
                message = json.loads(text)
                if message.get("type") != "offer":
                    continue
                offer = json.loads(base64.b64decode(message["data"]["sd"]))

                # One viewer at a time: tell the previous one, then drop it.
                old_pc, old_rpc = current["pc"], current["rpc"]
                if old_pc is not None:
                    if old_rpc is not None and old_rpc.readyState == "open":
                        old_rpc.send(json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None}))
                    asyncio.get_running_loop().call_later(0.3, lambda pc=old_pc: asyncio.ensure_future(pc.close()))

                pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
                current["pc"], current["rpc"] = pc, None
                state.sessions += 1
                pc.addTrack(FakeScreen(state))

                @pc.on("datachannel")
                def on_channel(channel: Any, pc: RTCPeerConnection = pc) -> None:
                    if channel.label != "rpc":
                        return
                    if current["pc"] is pc:
                        current["rpc"] = channel
                    channel.on("message", lambda sent, channel=channel: handle_rpc(channel, sent))
                    for method, params in (
                        ("localVersion", {"appVersion": "0.5.9", "systemVersion": "0.2.7"}),
                        ("videoInputState", {"ready": state.signal, "width": state.width, "height": state.height, "fps": 60}),
                        ("usbState", "configured"),
                    ):  # fmt: skip
                        channel.send(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}))

                await pc.setRemoteDescription(RTCSessionDescription(sdp=offer["sdp"], type="offer"))
                await pc.setLocalDescription(await pc.createAnswer())
                # Like the device: the answer goes out bare, the addresses follow one by one.
                lines = pc.localDescription.sdp.replace("\r\n", "\n").strip("\n").split("\n")
                candidates = list(dict.fromkeys(line[2:] for line in lines if line.startswith("a=candidate:")))
                bare = "\r\n".join(
                    line for line in lines if not line.startswith(("a=candidate:", "a=end-of-candidates"))
                ) + "\r\n"
                answer = base64.b64encode(json.dumps({"type": "answer", "sdp": bare}).encode()).decode()
                await websocket.send_text(json.dumps({"type": "answer", "data": answer}))
                for candidate in candidates:
                    await asyncio.sleep(0.01)
                    data = {"candidate": candidate, "sdpMid": "0", "sdpMLineIndex": 0}
                    await websocket.send_text(json.dumps({"type": "new-ice-candidate", "data": data}))
                for said in state.also_says:
                    await asyncio.sleep(state.also_after)
                    await websocket.send_text(said)
                    state.also_said += 1
        except WebSocketDisconnect:
            pass

    return app


class FakeJetKvm:
    """Runs make_fake_jetkvm() on a localhost port in a background thread.

    Give `tls_dir` to serve HTTPS with a certificate of the device's own making, as a JetKVM does once
    its owner turns its HTTPS mode on. It goes on serving plain HTTP beside it: a second stand-in with
    the same `state` and no `tls_dir` is that.
    """

    def __init__(self, state: JetState | None = None, port: int = 0, tls_dir: Path | None = None) -> None:
        self.state = state or JetState()
        self._sock = local_socket(port)
        self.port: int = self._sock.getsockname()[1]
        tls = {}
        if tls_dir is not None:
            cert, key = make_device_certificate(tls_dir)
            tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        config = uvicorn.Config(make_fake_jetkvm(self.state), log_level="error", access_log=False, **tls)
        self._server = uvicorn.Server(config)
        self._serving = ServerThread("fake JetKVM", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)
        self._thread = self._serving.thread

    def start(self) -> FakeJetKvm:
        self._serving.start()
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
