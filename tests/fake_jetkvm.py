"""A stand-in for a JetKVM: the same sign-in, signalling and data-channel messages, with a made-up screen.

It follows the device firmware (jetkvm/kvm, release 0.5.9, commit 36c008f) in the ways the wall depends on:

* one shared session token, replaced by every login;
* the picture exists only as WebRTC video, arranged over a websocket;
* the answer comes without network addresses, which follow one by one;
* one viewer at a time: a second one makes the first get "otherSessionConnected" and be dropped;
* every call on the `rpc` channel is done in a task of its own (a goroutine, on the device), so calls that arrive
  together are done in no particular order: here, keyboard and mouse reports that arrive together are done in the
  opposite one (see JetState's `together`), and the other calls at once. A real one typed
  the alphabet sent that way as "abdcegfhjikmlnpoqsrtvuwyxz", and kept a key and a mouse button down;
* the binary `hidrpc` channel its own page speaks (`JetState.hidrpc`; an older firmware has none, and leaves the
  channel unanswered): a handshake, answered `01 01`; keyboard messages done in order in one queue, mouse messages in
  order in another, the two queues each in a task of their own (here a key and a mouse message that arrive together
  are done in the opposite order, as the rpc calls are); a key pressed by a keypress message let go of 100 ms later
  unless a keep-alive comes every 50 ms (late ones refused as the device refuses them), a modifier never let go of
  that way; every change of the keyboard said back (`33`) to whoever has the viewer (as a `keysDownState` event on
  `rpc` to a viewer that did no handshake); no wheel on hidrpc. What it received there is kept, byte for byte
  (`hid_sent`);
* a connection that ends, or is taken over by another viewer, has its keyboard let go of, on the device's own
  account, but not its mouse buttons (a real one kept the left button down across both, on 2026-10-18); after a
  hand-over it goes on doing what that connection sends until it is closed (`hand_over_close` later), and lets go of
  none of that when it closes: it is no longer the viewer's (a test can have the hand-over come at a moment of its
  choosing: `take_over_at`, `FakeJetKvm.hand_over`);
* without its ATX extension switched on it says the power and disk lights are both off;
* with its HTTPS mode on it serves HTTPS beside plain HTTP, and sends nobody from the one to the other
  (two stand-ins that share one JetState are one such device: see FakeJetKvm's `tls_dir`);
* fresh from its box, before anybody chose how it is signed in to, it lets nobody in;
* it says which keyboard layout its computer uses (`getKeyboardLayout`, `JetState.layout`).

Uses the aiortc package, like the driver it tests.
"""

from __future__ import annotations

import asyncio
import base64
import json
import struct
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

# The device's own numbers for a key pressed by a keypress message (hid_keyboard.go, hidrpc.go).
RELEASE_AFTER = 0.1  # let go of this long after its press, or after the last keep-alive that counted
KEEP_ALIVE_EVERY = 0.05  # how often a keep-alive is expected
KEEP_ALIVE_LATE = 0.05  # how late one may be and still count (it then extends by that much less)
KEEP_ALIVE_STALE = 0.225  # a keep-alive this long after the last one that counted is not taken at all


@dataclass
class JetState:
    password: str = "secret"  # empty: the device runs in "no password" mode
    setup: bool = True  # False: fresh from its box, nobody has chosen yet how it is signed in to
    device_id: str = "9f1c2e7ab4d05836"  # the number it gives for itself, to whoever is signed in
    colour: tuple[int, int, int] = (150, 60, 40)
    signal: bool = True
    # How long after its signal came back (`FakeJetKvm.say_signal`) the first picture comes. A real one said "ready" a
    # moment before its first picture, and once a computer woke said it and sent none on the connection it had.
    frames_after_signal: float = 0.0
    frames_from: float = 0.0  # (no picture before this moment: set by `say_signal`)
    silent_screens: int = 0  # the next this many connections' video sends nothing at all, signal or not
    video_answer_late: float = 0.0  # getVideoState answered this long after it was asked, with how it was then (a busy one)
    frozen: bool = False  # as when it loses power: no more video, no more answers, and no goodbye
    width: int = 640
    height: int = 360
    extension: str = ""  # "atx-power" when the ATX board is switched on
    atx_power: bool = True  # the computer's power light, as its ATX board reads it (where the board is switched on)
    wol: list[dict[str, str]] = field(default_factory=list)
    layout: str = "en-US"  # the keyboard layout its computer uses, as set on its own page
    hidrpc: bool = True  # it speaks the binary `hidrpc` channel (False: an older firmware, which leaves it unanswered)
    hid_version: int = 1  # what it answers the handshake with
    # Seconds after its hidrpc channel opened in which it does not hear a handshake (a JetKVM still setting the channel up,
    # or one whose answer comes after the wall has given up waiting): those are left unanswered, and counted.
    hid_deaf_for: float = 0.0
    handshakes_unheard: int = 0
    keys_said_on_rpc: bool = False  # says its keyboard as a JSON-RPC `keysDownState` event even after a handshake
    keys_said_backwards: bool = False  # says the keys down in an order of its own (here: the other way round)
    # Keyboard and mouse reports on the `rpc` channel that arrive within this long of each other are done in the
    # opposite order (the device does each call in a goroutine of its own, and they finish as they finish); each is
    # done this long after it came, so this is also how slowly the device answers them. 0: each as it comes. On
    # `hidrpc`, messages that arrive within this long of each other are done as a batch: each queue's in order, the
    # queues in the opposite order to the one they first came in.
    together: float = 0.005
    let_go_at_end: int = 0  # connections that ended with a key down, which the device let go of by itself
    # Put in by a test: another viewer takes the device over around a report that presses keys or mouse buttons, the
    # one with this number (counted from 1, over every connection and both channels): ("before", n, _) as it arrives,
    # before it is done (it is done and answered `together` later, so its answer comes after "otherSessionConnected");
    # ("after", n, s) s seconds after it was done and answered; ("silent", n, _) as "before", and the report is done
    # but never answered; ("silent_only", n, _) never answered, and nobody takes over. (On `hidrpc`, where nothing is
    # answered, "before" and "after" only.)
    take_over_at: tuple[str, int, float] | None = None
    presses_seen: int = 0
    # How long after a hand-over the previous viewer's connection is closed: a second, as a real one does (cloud.go
    # closes it one second later). A shorter time held the wall to answering a press done after the hand-over sooner
    # than the JetKVM does: on a busy computer its letting go came after the connection was gone.
    hand_over_close: float = 1.0
    hand_overs: int = 0
    done_after_hand_over: list[tuple[str, Any]] = field(default_factory=list)  # what a connection handed over still had done
    asked_after_hand_over: list[str] = field(default_factory=list)  # ...and the other calls it still made (by their method)
    hid_after_hand_over: list[bytes] = field(default_factory=list)  # ...and every hidrpc message it still sent
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
    video_offers: list[str] = field(default_factory=list)  # codec negotiation sent by the viewer
    sessions: int = 0  # video connections made so far
    actions: list[str] = field(default_factory=list)
    typed: list[tuple[int, list[int]]] = field(default_factory=list)  # every keyboard state with keys down that a message made
    down: list[int] = field(default_factory=list)  # the keys down now
    modifier: int = 0  # the modifier keys (Ctrl, Shift, Alt, Win) down now
    buttons: int = 0  # the mouse buttons down: on its absolute mouse or its relative one (two devices to the computer)
    reports: list[tuple[int, list[int]]] = field(default_factory=list)  # the keyboard after every keyboard message, the empty ones too
    mouse: list[tuple[Any, ...]] = field(default_factory=list)  # every mouse report: ("abs", x, y, buttons), ("rel", dx, dy, buttons), ("wheel", x, y)
    mouse_at: list[float] = field(default_factory=list)  # ...and when each was done (time.monotonic)
    hid_sent: list[bytes] = field(default_factory=list)  # every message received on `hidrpc`, as it came, over every connection
    handshakes: int = 0  # handshakes answered
    keep_alives: int = 0  # keep-alives that counted
    keep_alives_refused: int = 0  # ...and that did not (late, or after one that was)
    auto_released: list[int] = field(default_factory=list)  # keys it let go of by itself, no keep-alive having come


REPORTS = ("keyboardReport", "absMouseReport", "relMouseReport", "wheelReport", "keypressReport")  # what is kept together
HID_KEYBOARD = (0x02, 0x05)  # the queue each hidrpc message goes to (hidrpc.GetQueueIndex): the keyboard...
HID_MOUSE = (0x03, 0x04, 0x06)  # ...the mouse (0x04, the wheel, is queued there and then refused: "unknown type")


class FakeScreen(MediaStreamTrack):
    """A flat picture with a bar that moves, ten frames a second."""

    kind = "video"

    def __init__(self, state: JetState) -> None:
        super().__init__()
        self.state = state
        self.count = 0
        self.started = time.monotonic()
        self.silent = state.silent_screens > 0
        if self.silent:
            state.silent_screens -= 1

    async def recv(self) -> av.VideoFrame:
        self.count += 1
        delay = self.started + self.count / 10 - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        # A JetKVM sends nothing while there is no signal, nor in the moment between saying it has one and its first picture.
        while not self.state.signal or self.state.frozen or self.silent or time.monotonic() < self.state.frames_from:
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
    # The viewer's connection, its `rpc` and `hidrpc` channels, and whether it did the hidrpc handshake.
    current: dict[str, Any] = {"pc": None, "rpc": None, "hid": None, "shaken": False}

    def allowed(cookies: dict[str, str]) -> bool:
        if not state.setup:
            return False
        return not state.password or (state.token is not None and cookies.get("authToken") == state.token)

    @app.get("/device/status")
    async def device_status() -> dict[str, Any]:
        return {"isSetup": state.setup}  # (all a real one says there)

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

    handed_over: list[Any] = []  # the connections (their `rpc` and `hidrpc` channels) a hand-over took the viewer from
    silent: set[Any] = set()  # calls (by their number) that are done and never answered
    after: dict[Any, float] = {}  # calls (by their number) after whose answer another viewer takes over, so long after
    timers: dict[int, asyncio.TimerHandle] = {}  # keys pressed by a keypress message: when each is let go of
    keep_alive: dict[Any, dict[str, float | None]] = {}  # per hidrpc channel: when its last keep-alive came and counted
    hid_opened: dict[Any, float] = {}  # per hidrpc channel: when it opened

    # --- the keyboard and the mouse, whichever channel they came over -------------------------------------------

    def say_keys() -> None:
        """Every change of the keyboard is said to whoever has the viewer: on hidrpc where it shook hands, else on rpc."""
        keys = ((state.down[::-1] if state.keys_said_backwards else state.down) + [0] * 6)[:6]
        hid, rpc = current["hid"], current["rpc"]
        if current["shaken"] and not state.keys_said_on_rpc and hid is not None and hid.readyState == "open":
            hid.send(bytes([0x33, state.modifier, *keys]))
        elif rpc is not None and rpc.readyState == "open":
            rpc.send(json.dumps({"jsonrpc": "2.0", "method": "keysDownState", "params": {"modifier": state.modifier, "keys": keys}}))
        for channel in keep_alive.values():  # (resetKeepAliveTime: the next keep-alive counts in full)
            channel["arrival"] = channel["reset"] = None

    def set_keys(modifier: int, keys: list[int], own: bool = False) -> None:
        """The keyboard as a message made it (`own`: as the device made it itself, kept out of `reports` and `typed`, so
        that the tests that the wall lets go still test the wall)."""
        changed = (modifier, keys) != (state.modifier, state.down)
        state.modifier, state.down = modifier, keys
        if not own:
            state.reports.append((modifier, list(keys)))
            if keys or modifier:
                state.typed.append((modifier, list(keys)))
        if changed:
            say_keys()

    def keyboard(modifier: int, keys: list[int]) -> None:
        """A whole report: the keyboard as it says."""
        set_keys(modifier, [key for key in keys if key][:6])

    def keypress(key: int, press: bool, own: bool = False) -> None:
        """One key pressed or let go of, the rest as they are (hid_keyboard.go's keypressReport); a key that is no
        modifier, pressed, is let go of RELEASE_AFTER later unless kept alive."""
        modifier, keys = state.modifier, list(state.down)
        if 0xE0 <= key <= 0xE7:
            bit = 1 << (key - 0xE0)
            modifier = modifier | bit if press else modifier & ~bit
        elif press:
            if key not in keys and len(keys) < 6:
                keys.append(key)
        elif key in keys:
            keys.remove(key)
        set_keys(modifier, keys, own)
        if 0xE0 <= key <= 0xE7:
            return
        old = timers.pop(key, None)
        if old is not None:
            old.cancel()
        if press:
            timers[key] = asyncio.get_running_loop().call_later(RELEASE_AFTER, auto_release, key)

    def auto_release(key: int) -> None:
        timers.pop(key, None)
        if key in state.down:
            state.auto_released.append(key)
            keypress(key, False, own=True)

    def keep_alive_came(channel: Any) -> None:
        """A keep-alive (hidrpc.go's handleHidRPCKeypressKeepAlive): every key pressed by a keypress message is let go of
        a little later, unless it came too late, or after one that was."""
        now = time.monotonic()
        mine = keep_alive.setdefault(channel, {"arrival": None, "reset": None})
        reset, arrival = mine["reset"], mine["arrival"]
        if reset is not None and now - reset > KEEP_ALIVE_STALE:
            state.keep_alives_refused += 1
            return
        extension = RELEASE_AFTER
        if arrival is not None:
            lateness = now - arrival - KEEP_ALIVE_EVERY
            if lateness > KEEP_ALIVE_LATE:
                state.keep_alives_refused += 1
                return
            if lateness > 0:
                extension -= lateness
        mine["arrival"] = mine["reset"] = now
        state.keep_alives += 1
        loop = asyncio.get_running_loop()
        for key in list(timers):
            timers[key].cancel()
            timers[key] = loop.call_later(extension, auto_release, key)

    def let_go_of_the_keyboard() -> None:
        """What the device does at a hand-over and as the viewer's connection closes: the keyboard, not the buttons."""
        for timer in timers.values():
            timer.cancel()
        timers.clear()
        if state.down or state.modifier:
            state.let_go_at_end += 1
            set_keys(0, [], own=True)

    # Its absolute and its relative mouse are two devices to the computer, each with buttons of its own: a button is down
    # where either holds it.
    held_by = {"abs": 0, "rel": 0}

    def abs_mouse(x: int, y: int, buttons: int) -> None:
        state.mouse.append(("abs", x, y, buttons))
        state.mouse_at.append(time.monotonic())
        held_by["abs"] = buttons
        state.buttons = held_by["abs"] | held_by["rel"]

    def rel_mouse(dx: int, dy: int, buttons: int) -> None:
        state.mouse.append(("rel", dx, dy, buttons))
        state.mouse_at.append(time.monotonic())
        held_by["rel"] = buttons
        state.buttons = held_by["abs"] | held_by["rel"]

    # --- the rpc channel --------------------------------------------------------------------------------------------

    def handle_rpc(channel: Any, message: Any) -> None:
        if state.frozen:
            return
        call = json.loads(message)
        method, params = call["method"], call.get("params") or {}
        if any(channel is old for old, _ in handed_over):
            if method in REPORTS:
                state.done_after_hand_over.append((method, params))
            else:
                state.asked_after_hand_over.append(method)
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
            # (Asked without its board switched on, a real one answers too: both lights off, whatever the computer does.)
            result = {"power": state.atx_power and state.extension == "atx-power", "hdd": False}
        elif method == "getWakeOnLanDevices":
            result = state.wol
        elif method == "getKeyboardLayout":
            result = state.layout
        elif method == "keyboardReport":
            keyboard(params["modifier"], list(params["keys"]))
        elif method == "keypressReport":
            keypress(params["key"], params["press"])
        elif method == "absMouseReport":
            abs_mouse(params["x"], params["y"], params["buttons"])
        elif method == "relMouseReport":
            rel_mouse(params["dx"], params["dy"], params["buttons"])
        elif method == "wheelReport":
            state.mouse.append(("wheel", params["wheelX"], params["wheelY"]))
            state.mouse_at.append(time.monotonic())
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
        if call.get("id") in silent:
            silent.discard(call.get("id"))
            return
        if channel.readyState == "open":
            answer = json.dumps({**reply, "error": error} if error else {**reply, "result": result})
            if method == "getVideoState" and state.video_answer_late > 0:
                asyncio.get_running_loop().call_later(state.video_answer_late, lambda: channel.readyState == "open" and channel.send(answer))
            else:
                channel.send(answer)
        if call.get("id") in after:
            asyncio.get_running_loop().call_later(after.pop(call.get("id")), hand_over)

    # --- the hidrpc channel ------------------------------------------------------------------------------------------

    def handle_hid(channel: Any, data: bytes) -> None:
        """One message on `hidrpc`, done (as the device's queue for it does it)."""
        if state.frozen or not data:
            return
        handed = any(channel is old for _, old in handed_over)
        if handed:
            state.hid_after_hand_over.append(data)
        kind, body = data[0], data[1:]
        if kind == 0x01:
            if time.monotonic() - hid_opened.get(channel, 0.0) < state.hid_deaf_for:
                state.handshakes_unheard += 1
                return
            state.handshakes += 1
            if current["hid"] is channel:
                current["shaken"] = True
            if channel.readyState == "open":
                channel.send(bytes([0x01, state.hid_version]))
        elif kind == 0x02 and len(body) >= 1:
            if handed:
                state.done_after_hand_over.append(("keyboardReport", {"modifier": body[0], "keys": [key for key in body[1:] if key]}))
            keyboard(body[0], list(body[1:7]))
        elif kind == 0x05 and len(body) >= 2:
            if handed:
                state.done_after_hand_over.append(("keypressReport", {"key": body[0], "press": body[1] == 1}))
            keypress(body[0], body[1] == 1)
        elif kind == 0x09:
            keep_alive_came(channel)
        elif kind == 0x03 and len(body) == 9:
            x, y = struct.unpack(">ii", body[:8])
            if handed:
                state.done_after_hand_over.append(("absMouseReport", {"x": x, "y": y, "buttons": body[8]}))
            abs_mouse(x, y, body[8])
        elif kind == 0x06 and len(body) >= 3:
            dx, dy = struct.unpack(">bb", body[:2])
            if handed:
                state.done_after_hand_over.append(("relMouseReport", {"dx": dx, "dy": dy, "buttons": body[2]}))
            rel_mouse(dx, dy, body[2])
        # (Anything else, the wheel included, it logs as unknown and leaves.)

    def hid_presses(data: bytes) -> bool:
        if data[:1] == b"\x02":
            return any(data[1:])
        if data[:1] == b"\x05":
            return data[2:3] == b"\x01"
        if data[:1] == b"\x03":
            return len(data) >= 10 and data[9] != 0
        if data[:1] == b"\x06":
            return len(data) >= 4 and data[3] != 0
        return False

    hid_batch: list[tuple[Any, bytes]] = []  # hidrpc messages that arrived together and are not done yet

    def take_hid(channel: Any, message: Any) -> None:
        current["loop"] = asyncio.get_running_loop()
        if not isinstance(message, bytes) or not message:
            return  # (a text, or nothing: the device logs it and does nothing)
        state.hid_sent.append(message)
        if state.take_over_at is not None and hid_presses(message):
            state.presses_seen += 1
            when, number, later = state.take_over_at
            if number == state.presses_seen:
                if when == "before":
                    hand_over()
                elif when == "after":
                    asyncio.get_running_loop().call_later(state.together + later, hand_over)
        if state.together <= 0:
            handle_hid(channel, message)
            return
        hid_batch.append((channel, message))
        if len(hid_batch) == 1:
            asyncio.get_running_loop().call_later(state.together, do_hid_batch)

    def do_hid_batch() -> None:
        """What arrived together: each queue's messages in order, the queues in the opposite order to the one they came in
        (one task readied after another runs first, on a device of one core)."""
        batch = list(hid_batch)
        hid_batch.clear()
        queues: dict[int, list[tuple[Any, bytes]]] = {}
        for channel, message in batch:
            queue = 1 if message[0] in HID_KEYBOARD else 2 if message[0] in HID_MOUSE else 3
            queues.setdefault(queue, []).append((channel, message))
        for queue in reversed(list(queues)):
            for channel, message in queues[queue]:
                handle_hid(channel, message)

    # --- hand-overs and ends -----------------------------------------------------------------------------------------

    def hand_over() -> None:
        """Another viewer takes the device over: the one there now is told, its keyboard is let go of (not its mouse
        buttons), and its connection is closed a moment later. (What it sends meanwhile is still done.)"""
        old_pc, old_rpc, old_hid = current["pc"], current["rpc"], current["hid"]
        if old_pc is None:
            return
        state.hand_overs += 1
        handed_over.append((old_rpc, old_hid))
        if old_rpc is not None and old_rpc.readyState == "open":
            old_rpc.send(json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None}))
        asyncio.get_running_loop().call_later(state.hand_over_close, lambda pc=old_pc: asyncio.ensure_future(pc.close()))
        let_go_of_the_keyboard()  # (a real one let go of a key the previous viewer held, as the next one came; said to it)
        current.update(pc=None, rpc=None, hid=None, shaken=False)  # (somebody else's now)

    closing: set[asyncio.Future[Any]] = set()  # (connections being closed, held until they are)

    def drop() -> None:
        """The device ends the viewer's connection without a word of its own (a restart of its program, the network)."""
        if current["pc"] is not None:
            task = asyncio.ensure_future(current["pc"].close())
            closing.add(task)
            task.add_done_callback(closing.discard)

    def close_hid() -> None:
        """The device closes the viewer's hidrpc channel and keeps the rest of the connection."""
        if current["hid"] is not None:
            current["hid"].close()

    def tell_video(ready: bool) -> None:
        """The computer's screen came or went: said to the viewer as it changes, as a real one says it (`videoInputState`)."""
        rpc = current["rpc"]
        if rpc is not None and rpc.readyState == "open" and not state.frozen:
            params = {"ready": ready, "width": state.width, "height": state.height, "fps": 60}
            rpc.send(json.dumps({"jsonrpc": "2.0", "method": "videoInputState", "params": params}))

    app.state.hand_over, app.state.current, app.state.drop, app.state.close_hid = hand_over, current, drop, close_hid
    app.state.tell_video = tell_video

    def presses(message: Any) -> Any:
        """The number of a call that presses keys or mouse buttons; None for any other."""
        try:
            call = json.loads(message)
            params = call.get("params") or {}
            if call.get("method") == "keyboardReport" and (params.get("keys") or params.get("modifier")):
                return call.get("id")
            if call.get("method") in ("absMouseReport", "relMouseReport") and params.get("buttons"):
                return call.get("id")
        except (ValueError, TypeError, AttributeError):
            pass
        return None

    together: list[tuple[Any, Any]] = []  # calls that arrived together and are not done yet

    def take_rpc(channel: Any, message: Any) -> None:
        """A call, done the way the device does it: in a task of its own, so that one that came after may be done first."""
        current["loop"] = asyncio.get_running_loop()
        pressing = presses(message) if state.take_over_at is not None else None
        if pressing is not None and state.take_over_at is not None:
            state.presses_seen += 1
            when, number, later = state.take_over_at
            if number == state.presses_seen:
                if when in ("silent", "silent_only"):
                    silent.add(pressing)
                if when == "after":
                    after[pressing] = later
                elif when != "silent_only":
                    hand_over()
        if state.together <= 0 or not (isinstance(message, str) and any(f'"{name}"' in message for name in REPORTS)):
            handle_rpc(channel, message)
            return
        together.append((channel, message))
        if len(together) == 1:
            asyncio.get_running_loop().call_later(state.together, do_together)

    def do_together() -> None:
        calls = together[::-1]
        together.clear()
        for channel, message in calls:
            handle_rpc(channel, message)

    def ended(pc: RTCPeerConnection) -> None:
        """A connection ended: the device lets go of its keyboard, as a real one does at once (of the viewer it has now
        only), and of no mouse button. What it received before is done first (here: so that a test knows what it is
        left with)."""
        if together:
            do_together()
        if hid_batch:
            do_hid_batch()
        if current["pc"] is pc:
            let_go_of_the_keyboard()

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
                state.video_offers.append(offer["sdp"])

                # One viewer at a time: tell the previous one, then drop it.
                current["loop"] = asyncio.get_running_loop()
                hand_over()

                pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
                current.update(pc=pc, rpc=None, hid=None, shaken=False)
                state.sessions += 1
                pc.addTrack(FakeScreen(state))

                @pc.on("connectionstatechange")
                def on_state(pc: RTCPeerConnection = pc) -> None:
                    if pc.connectionState in ("closed", "failed"):
                        ended(pc)

                @pc.on("datachannel")
                def on_channel(channel: Any, pc: RTCPeerConnection = pc) -> None:
                    if channel.label == "hidrpc":
                        if not state.hidrpc:
                            return  # (an older firmware: the channel opens, and nothing on it is listened to)
                        hid_opened[channel] = time.monotonic()
                        if current["pc"] is pc:
                            current["hid"] = channel
                        channel.on("message", lambda sent, channel=channel: take_hid(channel, sent))
                        return
                    if channel.label != "rpc":
                        return
                    if current["pc"] is pc:
                        current["rpc"] = channel
                    channel.on("message", lambda sent, channel=channel: take_rpc(channel, sent))
                    for method, params in (
                        ("otaState", {"updating": False, "appUpdatePending": False, "systemUpdatePending": False}),
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


def no_long_handshake(monkeypatch: Any, hidrpc: bool) -> None:
    """Where the stand-in plays an older JetKVM (`hidrpc` false), nothing answers the wall's hidrpc handshake: the wall
    gives up asking after 0.3 s, not the two seconds it gives a real one, which every test would wait for. Where it
    speaks hidrpc the wall's own two seconds stand: a busy computer took up to 1.4 s to answer, and a window of 0.3 s put
    the test on JSON-RPC without saying so."""
    if not hidrpc:
        from qkvm import jetkvm

        monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 0.3)


def presses_wait(monkeypatch: Any, seconds: float) -> dict[str, float | None]:
    """The wall waits `seconds` for the JetKVM's answer to a keyboard or mouse report over JSON-RPC, where a test has one
    go unanswered; for anything else as long as it does (RPC_TIMEOUT). A short wait for every question had a busy
    computer's slow answer to the keyboard layout taken for none, and nothing typed. What comes back holds the wait:
    set its "seconds" to None, and the wall waits for reports as long as it does too."""
    from qkvm import jetkvm

    real = jetkvm.JetKvmDevice._call
    held: dict[str, float | None] = {"seconds": seconds}

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if within is None and method in ("keyboardReport", "absMouseReport", "relMouseReport"):
            within = held["seconds"]
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    return held


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
        self._app = make_fake_jetkvm(self.state)
        config = uvicorn.Config(self._app, log_level="error", access_log=False, **tls)
        self._server = uvicorn.Server(config)
        self._serving = ServerThread("fake JetKVM", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)
        self._thread = self._serving.thread

    def start(self) -> FakeJetKvm:
        self._serving.start()
        return self

    def hand_over(self) -> None:
        """Another viewer takes the device over now (from a test's thread), as when its offer arrives."""
        loop = self._app.state.current.get("loop")
        if loop is not None:
            loop.call_soon_threadsafe(self._app.state.hand_over)

    def drop(self) -> None:
        """The device ends the viewer's connection now (from a test's thread), with no word of its own."""
        loop = self._app.state.current.get("loop")
        if loop is not None:
            loop.call_soon_threadsafe(self._app.state.drop)

    def close_hid(self) -> None:
        """The device closes the viewer's hidrpc channel now (from a test's thread), and keeps the connection."""
        loop = self._app.state.current.get("loop")
        if loop is not None:
            loop.call_soon_threadsafe(self._app.state.close_hid)

    def say_signal(self, ready: bool) -> None:
        """The computer's screen goes to sleep, or comes back (from a test's thread), and the viewer is told so at once;
        a screen that comes back sends its first picture `frames_after_signal` later."""
        if ready:
            self.state.frames_from = time.monotonic() + self.state.frames_after_signal
        self.state.signal = ready
        loop = self._app.state.current.get("loop")
        if loop is not None:
            loop.call_soon_threadsafe(self._app.state.tell_video, ready)

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
