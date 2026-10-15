"""Client for a JetKVM.

A JetKVM has no "give me a picture" request. Its screen is a WebRTC video stream and
everything else (status, keys, power) travels on a data channel of the same connection,
so the wall connects the way the JetKVM's own web page does and keeps the latest frame.

Two things follow from how the device works, and shape this file:

* It serves one viewer at a time. When someone opens the JetKVM's own console the wall is
  told so and steps aside; it does not reconnect by itself, because that would throw the
  person out again. The tile offers "Show here" instead.
* Logging in replaces the device's one session token, which signs every other browser
  out. So the wall logs in once and keeps its token for as long as the device accepts it.

Its owner chooses, at the device's own page, whether it has a password and whether it serves HTTPS
(with a certificate of its own making, or one they give it). It serves plain HTTP in any case, and
HTTPS beside it. The wall talks to it over HTTPS wherever it offers that, remembers its certificate
on first contact as it does a Comet's, and follows when the choice is changed later: onto HTTPS,
by itself. Never back onto plain HTTP by itself: there nothing is checked any more, neither who
answers nor who listens, and that it was the owner who switched HTTPS off is only the word of
whatever answers now. The tile says so, and a person decides (see `_ask_the_other_way`).

WebRTC is the `aiortc` package, which is installed with qKVM. It is loaded when the first JetKVM is
connected to and not before: it brings a video decoder, and a wall without a JetKVM has no use for one.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import logging
import struct
import time
import zlib
from collections.abc import Callable
from fractions import Fraction
from typing import Any

import httpx
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed, InvalidStatus, WebSocketException

from .kvm import (
    DOWN_CODES,
    FULL,
    KEEPALIVE_IDLE,
    KEYS,
    LOGIN_BACKOFF,
    LOGIN_RETRY,
    MAC,
    MAX_TEXT,
    MAX_PROBE,
    MAX_REPLY,
    REJECTED,
    TIERS,
    TOKEN,
    Device,
    DeviceSpec,
    KvmError,
    Listening,
    Snapshot,
    _transport_error,
    as_text,
    bounded,
    flag,
    number,
    other_way,
    plain,
    read_json,
    said_cookie,
    share_window,
    sign_in_waits,
    tier_for,
    unverified_context,
    went_out,
    ws_connect,
)

log = logging.getLogger("qkvm")

CONNECT_TIMEOUT = 15.0  # from asking for video to an open connection
RPC_TIMEOUT = 8.0
CANDIDATE_QUIET = 0.3  # the device sends its network addresses one by one; this much silence ends the wait
CANDIDATE_WAIT = 3.0  # ...and this is how long to wait for the first one
MAX_CANDIDATES = 40  # addresses a device may offer; a real one has a handful
KEY_PAUSE = 0.004  # between key reports while typing text
ASK_EVERY = 25  # keys typed before it is asked again whether the account they are typed for may still do that
# A frame older than this is no longer "the screen". A JetKVM sends video all the time, also of a
# screen on which nothing moves, so when frames stop coming while it claims a signal, it is gone.
FRAME_STALE = 5.0
RETRY_PAUSE = 3.0  # after a refusal (wrong password, ...), wait this long before asking again
JET_NO_SAID = "Login rejected - check the password"  # what its tile says where it does not take the saved one
LOGIN_WAIT_MOST = 3600.0  # the longest a JetKVM that refuses logins can have the wall wait before it tries again
PROBE_TIME = 15.0  # the alert watcher's "are you there?" may take this long, all told
WAY_EVERY = 600.0  # a JetKVM talked to over plain HTTP is asked this often whether it offers HTTPS by now
WAY_WHEN_DOWN = 60.0  # ...and one that stopped answering over HTTPS, whether it answers over plain HTTP
# ...once it has not answered for this long. A JetKVM that is starting up serves plain HTTP at once, and HTTPS
# only when it knows what time it is: that is a moment in every restart, and not its owner's choice.
WAY_PATIENCE = 120.0
WAY_ASK = 6.0  # signing in over plain HTTP waits this long, at most, to hear whether HTTPS is on offer by now

# JPEG quantizer per size (2 is the best the encoder does): screen text needs it.
QUANTIZER = {"480": 3, "640": 3, "960": 2, FULL: 2}

# For a copy that runs from the source without having been installed: an installed one has the package.
MISSING_DRIVER = KvmError(
    "missing_driver",
    "JetKVM support needs the aiortc package, which is installed with qKVM but is missing from this Python. Install it with: pip install aiortc",
    501,
)


def not_set_up() -> KvmError:
    return KvmError("not_set_up", "This JetKVM has not been set up yet. Open its own page once and choose how it is signed in to; then it can be added here.")


IN_USE = KvmError("in_use", "Someone is using this JetKVM's own console. It shows its picture to one viewer at a time.", 409)

def _dark_pixel() -> bytes:
    """A 1x1 dark PNG, sent while the JetKVM has no video signal (the tile covers it with "No signal").

    Made here, with the checksums worked out, and not carried as a string somebody typed: the one that
    stood here had a wrong checksum in it, a browser shows no such picture, and the tile of a JetKVM
    whose computer was switched off said "the KVM sent a picture that could not be shown".
    """

    def part(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # one pixel, three bytes of colour
    return bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + part(b"IHDR", header) + part(b"IDAT", zlib.compress(bytes([0, 0x16, 0x18, 0x1D]))) + part(b"IEND", b"")


_BLANK = _dark_pixel()

# Key names as browsers spell them -> USB HID usage codes.
_MODIFIERS = {
    "ControlLeft": 0x01, "ShiftLeft": 0x02, "AltLeft": 0x04, "MetaLeft": 0x08,
    "ControlRight": 0x10, "ShiftRight": 0x20, "AltRight": 0x40, "MetaRight": 0x80,
}  # fmt: skip
_USAGE = {
    **{f"Key{chr(65 + i)}": 0x04 + i for i in range(26)},
    **{f"Digit{i}": 0x1D + i for i in range(1, 10)},
    "Digit0": 0x27, "Enter": 0x28, "Escape": 0x29, "Backspace": 0x2A, "Tab": 0x2B, "Space": 0x2C,
    "Minus": 0x2D, "Equal": 0x2E, "BracketLeft": 0x2F, "BracketRight": 0x30, "Backslash": 0x31,
    "Semicolon": 0x33, "Quote": 0x34, "Backquote": 0x35, "Comma": 0x36, "Period": 0x37, "Slash": 0x38,
    "CapsLock": 0x39,
    **{f"F{i}": 0x39 + i for i in range(1, 13)},
    "PrintScreen": 0x46, "ScrollLock": 0x47, "Pause": 0x48, "Insert": 0x49, "Home": 0x4A, "PageUp": 0x4B,
    "Delete": 0x4C, "End": 0x4D, "PageDown": 0x4E, "ArrowRight": 0x4F, "ArrowLeft": 0x50, "ArrowDown": 0x51,
    "ArrowUp": 0x52, "NumLock": 0x53, "NumpadDivide": 0x54, "NumpadMultiply": 0x55, "NumpadSubtract": 0x56,
    "NumpadAdd": 0x57, "NumpadEnter": 0x58,
    **{f"Numpad{i}": 0x58 + i for i in range(1, 10)},
    "Numpad0": 0x62, "NumpadDecimal": 0x63, "ContextMenu": 0x65,
}  # fmt: skip

# Characters on a US keyboard -> (needs Shift, key name).
_PLAIN = "`-=[]\\;',./"
_PLAIN_KEYS = ("Backquote", "Minus", "Equal", "BracketLeft", "BracketRight", "Backslash", "Semicolon", "Quote", "Comma", "Period", "Slash")  # fmt: skip
_SHIFTED = '~_+{}|:"<>?'
_CHARS: dict[str, tuple[bool, str]] = {
    **{chr(97 + i): (False, f"Key{chr(65 + i)}") for i in range(26)},
    **{chr(65 + i): (True, f"Key{chr(65 + i)}") for i in range(26)},
    **{str(i): (False, f"Digit{i}") for i in range(10)},
    **{char: (True, f"Digit{(i + 1) % 10}") for i, char in enumerate("!@#$%^&*()")},
    **{char: (False, key) for char, key in zip(_PLAIN, _PLAIN_KEYS, strict=True)},
    **{char: (True, key) for char, key in zip(_SHIFTED, _PLAIN_KEYS, strict=True)},
    " ": (False, "Space"), "\n": (False, "Enter"), "\t": (False, "Tab"),
}  # fmt: skip


async def offered_at(address: str) -> dict[str, Any] | None:
    """What a JetKVM says of itself at `address` to anybody who asks; None when none answers there.

    No password goes with the question, and the certificate is not judged for it: the answer only says
    where to look. What is found there is then trusted, or not, the way any device is.
    """
    try:
        async with httpx.AsyncClient(verify=unverified_context(), timeout=httpx.Timeout(3.0, connect=1.5), trust_env=False) as client:
            reply = await bounded(client, client.build_request("GET", f"{address}/device/status"), MAX_PROBE, 5.0)
            said = read_json(reply) if reply.status_code == 200 else None
    except (httpx.HTTPError, ValueError, KvmError):
        return None
    return said if isinstance(said, dict) and "isSetup" in said else None


def webrtc_available() -> bool:
    return importlib.util.find_spec("aiortc") is not None


def key_report(keys: str) -> tuple[int, list[int]]:
    """'ControlLeft,AltLeft,Delete' as a HID keyboard report: (modifier bits, key codes)."""
    modifier, codes = 0, []
    for name in keys.split(","):
        if name in _MODIFIERS:
            modifier |= _MODIFIERS[name]
        elif name in _USAGE:
            codes.append(_USAGE[name])
        else:
            raise KvmError("invalid", f"A JetKVM has no {name} key", 422)
    if len(codes) > 6:
        raise KvmError("invalid", "A keyboard can hold six keys at once, plus Ctrl, Alt, Shift and Win", 422)
    return modifier, codes


def text_reports(text: str) -> list[tuple[int, list[int]]]:
    """What to press, character by character, to type `text` on a US keyboard layout."""
    reports = []
    for char in text.replace("\r\n", "\n"):
        if char not in _CHARS:
            raise KvmError("invalid", f"A JetKVM can type US-keyboard characters only, and {char!r} is not one", 422)
        shift, key = _CHARS[char]
        reports.append((_MODIFIERS["ShiftLeft"] if shift else 0, [_USAGE[key]]))
    return reports


def with_candidates(sdp: str, candidates: list[str]) -> str:
    """The answer with the device's network addresses written into every media section.

    The device sends them separately, after the answer; the WebRTC library used here
    gives up at once unless it knows at least one when it starts connecting.
    """
    lines = [f"a={candidate}" for candidate in candidates if candidate.startswith("candidate:")]
    if not lines:
        return sdp
    out: list[str] = []
    in_media = False
    for line in sdp.replace("\r\n", "\n").strip("\n").split("\n"):
        if line.startswith("m="):
            if in_media:
                out.extend(lines)
            in_media = True
        out.append(line)
    if in_media:
        out.extend(lines)
    return "\r\n".join(out) + "\r\n"


def encode_jpeg(frame: Any, width: int | None, quantizer: int) -> bytes:
    """A decoded video frame as a JPEG, shrunk to `width` when that is smaller."""
    import av

    if width and width < frame.width:
        height = max(2, round(frame.height * width / frame.width / 2) * 2)
        frame = frame.reformat(width=width, height=height, format="yuvj420p", interpolation="LANCZOS")
    else:
        frame = frame.reformat(format="yuvj420p")
    codec: Any = av.CodecContext.create("mjpeg", "w")
    codec.width, codec.height, codec.pix_fmt = frame.width, frame.height, "yuvj420p"
    codec.time_base = Fraction(1, 30)
    codec.options = {"qmin": str(quantizer), "qmax": str(quantizer)}
    frame.pts = 0
    packets = codec.encode(frame) + codec.encode(None)
    return bytes(packets[0])


class _Session:
    """One WebRTC connection to the device and what has arrived over it."""

    def __init__(self) -> None:
        self.pc: Any = None
        self.rpc: Any = None
        self.ready = asyncio.Event()  # the data channel is open: the device can be talked to
        self.done = asyncio.Event()
        self.error: KvmError | None = None
        self.taken = False  # another viewer connected and the device dropped us
        self.frame: Any = None  # latest decoded picture
        self.frame_at = 0.0
        self.video: dict[str, Any] = {}
        self.usb: str | None = None
        self.atx: dict[str, Any] | None = None
        self.version: str | None = None
        self.pending: dict[int, asyncio.Future[Any]] = {}
        self.next_id = 0
        self.encoded: dict[str, tuple[Any, Snapshot]] = {}
        self.watchers: list[asyncio.Task[None]] = []
        self.lost: KvmError | None = None  # the device stopped sending or answering: this connection is to be ended

    @property
    def live(self) -> bool:
        return self.ready.is_set() and not self.done.is_set() and self.lost is None


class JetKvmDevice(Device):
    """A JetKVM, over WebRTC."""

    kind = "jetkvm"

    def __init__(self, spec: DeviceSpec, on_pin: Any = None) -> None:
        super().__init__(spec, on_pin)
        self._token: str | None = None
        self._open_access = False  # the device runs without a password
        self._login_lock = asyncio.Lock()
        self._login_error: KvmError | None = None
        self._login_retry_at = 0.0
        self._session: _Session | None = None
        self._task: asyncio.Task[None] | None = None
        self._displaced = False  # someone took the picture; wait to be asked back
        self._looking_on = 0  # looks under way that are not somebody watching (the alerts' rounds)
        self._told: str | None = None  # what a connection last showed it to be: with a picture, without, not letting us in
        self._retry_at = 0.0
        self._wanted_at = 0.0
        self._encode_locks = {size: asyncio.Lock() for size in (*TIERS, FULL)}
        self._typing = asyncio.Lock()
        self._way_asked_at = float("-inf")  # when it was last asked whether it answers at its other address
        self._way_task: asyncio.Task[None] | None = None
        self._plain_only: str | None = None  # where it answers now, over plain HTTP only: said on its tile, not followed
        self._down_since: float | None = None  # since when it has not answered at its address

    def takes_over(self, retired: Device) -> None:
        # Somebody opened the JetKVM's own console and so took its one viewer: the wall stepped aside, and
        # stays aside until it is asked back, whatever is changed about the tile meanwhile.
        if isinstance(retired, JetKvmDevice):
            self._displaced = retired._displaced

    async def close(self) -> None:
        self._closed = True
        # (Not when it is that very task that retires this client: it has followed the JetKVM to its other address.)
        if self._way_task is not None and self._way_task is not asyncio.current_task():
            self._way_task.cancel()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await super().close()

    # --- plain HTTP: login and identity -------------------------------------

    async def _login(self) -> str | None:
        """The session token to present, or None when the device asks for none."""
        async with self._login_lock:
            if self._token or self._open_access:
                return self._token
            if self._login_error and time.monotonic() < self._login_retry_at:
                raise self._login_error.with_traceback(None)
            if not self.spec.password:
                return None  # a JetKVM set to "no password" lets everyone in
            offered = REJECTED.what("login", self.spec)
            self._not_yet(offered, JET_NO_SAID)
            client = await self._http()
            login = client.build_request("POST", "/auth/login-local", json={"password": self.spec.password}, timeout=sign_in_waits())
            before = REJECTED.sent(offered)
            try:
                resp = await self._send(client, login, MAX_REPLY)
            except httpx.HTTPError as ex:
                raise self._came_to_nothing(offered, _transport_error(ex, self.spec.tls), JET_NO_SAID, before, went_out(ex)) from ex
            except KvmError as ex:
                raise self._came_to_nothing(offered, ex, JET_NO_SAID, before) from None
            self._answered()
            token = said_cookie(resp, "authToken")
            client.cookies.clear()  # we send the token ourselves
            if resp.status_code == 400:
                self._open_access = True  # "no password" mode refuses logins; nothing is needed
                REJECTED.accepted(offered)  # (it is let in: nothing stands against it)
                return None
            if resp.status_code in (401, 429):
                # 429: the device locks an address out after five wrong passwords. So the wall waits longer
                # after each no in a row (see LOGIN_BACKOFFS), and as long as the device names where that is more.
                asked = 0.0
                if resp.status_code == 429:
                    try:
                        asked = float(resp.headers.get("retry-after", "0"))
                    except ValueError:
                        asked = 0.0
                    # (An hour at the most, whatever it says: "inf" there left the tile refused for good.)
                    asked = min(asked, LOGIN_WAIT_MOST) if asked == asked else 0.0
                    message = "The JetKVM is refusing logins after too many wrong passwords - try again later"
                else:
                    message = JET_NO_SAID
                self._login_error = KvmError("auth_failed", message)
                if resp.status_code == 429:
                    # Not a verdict on the password: it says when to come back. Then, and not sooner than a minute.
                    self._login_retry_at = time.monotonic() + REJECTED.later(offered, max(asked, LOGIN_BACKOFF))
                else:
                    # (Noted before anything else is asked of it: retired while that was asked, the no was
                    # heard and noted nowhere.)
                    self._login_retry_at = time.monotonic() + REJECTED.said_no(offered)
                    if await self._fresh_from_its_box():
                        self._login_error = not_set_up()
                log.warning("%s: login rejected", self.label)
                raise self._login_error
            if resp.status_code != 200 or not token or not TOKEN.fullmatch(token):
                # Whatever is at that address did not sign us in, and not because of the password. Every
                # look ends up here too: the password is not sent to it again and again meanwhile.
                raise self._neither_yes_nor_no(offered, KvmError("bad_response", f"Login failed (HTTP {resp.status_code})"), JET_NO_SAID)
            self._login_error = None
            REJECTED.accepted(offered)
            self._token = token
            return token

    def _cookie(self, token: str | None) -> dict[str, str]:
        return {"Cookie": f"authToken={token}"} if token else {}

    async def _fresh_from_its_box(self) -> bool:
        """Whether nobody has chosen yet, at its own page, how this JetKVM is signed in to. It lets nobody in until then."""
        try:
            client = await self._http()
            reply = await self._send(client, client.build_request("GET", "/device/status"), MAX_PROBE)
            said = read_json(reply) if reply.status_code == 200 else None
        except (httpx.HTTPError, ValueError, KvmError):
            return False
        return isinstance(said, dict) and said.get("isSetup") is False

    async def _rejected(self) -> KvmError:
        if await self._fresh_from_its_box():
            return not_set_up()
        if self.spec.password:
            return KvmError("auth_failed", "The JetKVM keeps rejecting the session")
        return KvmError("no_password", "This JetKVM asks for a password and none is saved")

    async def _own_number(self) -> str | None:
        """The number this JetKVM gives for itself, as a mark to know it by at whichever address; None where it gives none.

        Only ever compared with another: it is kept as a digest, since the number itself is nobody's business.
        """
        try:
            client = await self._http()
            reply = await self._send(client, client.build_request("GET", "/device", headers=self._cookie(self._token)), MAX_REPLY)
            said = read_json(reply) if reply.status_code == 200 else None
        except (httpx.HTTPError, ValueError, KvmError):
            return None
        number = said.get("deviceId") if isinstance(said, dict) else None
        if not isinstance(number, str) or not 8 <= len(number) <= 64 or len(set(number)) < 4:
            return None
        return "jetkvm:" + hashlib.sha256(number.encode()).hexdigest()[:32]

    # --- over HTTPS or plain HTTP: wherever it answers -----------------------

    def _look_the_other_way(self, down: bool) -> None:
        """Ask, if it is time to, whether this JetKVM answers at its other address by now.

        One talked to over plain HTTP is asked now and then whether it offers HTTPS (its owner may have
        turned that on); one over HTTPS only once it has stopped answering (they may have turned it off).
        """
        secure = self.spec.base_url.startswith("https://")
        if self.on_move is None or self._closed or (secure and not down) or (self._way_task is not None and not self._way_task.done()):
            return
        now = time.monotonic()
        if down:
            self._down_since = now if self._down_since is None else self._down_since
            if now - self._down_since < WAY_PATIENCE:
                return
        if now - self._way_asked_at < (WAY_WHEN_DOWN if down else WAY_EVERY):
            return
        twin = other_way(self.spec.base_url)
        if twin is None:
            return
        self._way_asked_at = now
        # A task of its own, and not one that ends with this client: following replaces the client, from inside it.
        self._way_task = asyncio.create_task(self._ask_the_other_way(twin))

    async def _ask_the_other_way(self, twin: str) -> None:
        try:
            if await offered_at(twin) is None or self._closed or self.on_move is None:
                return
            if not twin.startswith("https://"):
                # Its HTTPS mode was switched off, or so it looks from here. That is not acted on by itself,
                # with a password or without: over plain HTTP nothing is checked any more, the certificate
                # remembered for it would be let go of, and whoever can keep one port quiet for two minutes
                # and then answer on it would have the tile, with nobody asked. A person changes the address.
                self._plain_only = twin
                return
            await self.on_move(twin)
        except Exception:  # what is saved could not be changed: said, and asked about again later
            log.exception("%s: following it to %s failed", self.label, twin)

    async def _signalling(self) -> ClientConnection:
        """Open the channel over which a video connection is arranged, logging in (again) if needed."""
        if not self.spec.base_url.startswith("https://"):
            # Before anything secret goes to it over plain HTTP (its password, or the session that stands for it):
            # whether it offers HTTPS by now. If it does, the wall moves there, and this client is retired with
            # nothing sent: what follows then finds it closed.
            self._look_the_other_way(down=False)
            asking = self._way_task
            if asking is not None and not asking.done() and asking is not asyncio.current_task():
                await asyncio.wait({asking}, timeout=WAY_ASK)
        url = "ws" + self.spec.base_url[len("http"):] + "/webrtc/signaling/client"
        relogged = False
        while True:
            token = await self._login()
            await self._http()  # makes sure the TLS settings are known
            try:
                ws = await ws_connect(
                    url,
                    additional_headers=self._cookie(token),
                    ssl=self._tls,
                    open_timeout=6,
                    close_timeout=1,  # a device that is gone gets no ten seconds to say goodbye in
                    max_size=2**20,
                )
            except InvalidStatus as ex:
                self._answered()
                if ex.response.status_code != 401:
                    raise KvmError("bad_response", f"The JetKVM refused (HTTP {ex.response.status_code})") from None
                if relogged or not self.spec.password:
                    refused = await self._rejected()
                    if relogged:
                        # It takes the password and refuses the session it gave for it. Every look ends up
                        # here: the password is not sent to it again with each of them. (It was, every three
                        # seconds for as long as its tile was looked at; the other two kinds of device had
                        # this pause already.)
                        async with self._login_lock:
                            self._token = None
                            self._login_error, self._login_retry_at = refused, time.monotonic() + LOGIN_RETRY
                    raise refused from None
                # Someone logged in at the device since, which replaced our token.
                relogged, self._token, self._open_access = True, None, False
                continue
            except TimeoutError as ex:
                raise self._failed(KvmError("timeout", "Device did not respond in time", 504)) from ex
            except (OSError, WebSocketException) as ex:
                raise self._failed(_ws_error(ex, self.spec.tls)) from ex
            # Heard from. That it can be used again is said by whoever uses it: a search that only wanted to
            # know (identify), or the first question it answers over a connection (_read_status). Said here,
            # a JetKVM that lets a connection be arranged and ends each one at once was "reachable again"
            # every three seconds, for good, with two lines in the log each time and no growing pause.
            self._last_ok, self._heard_at = time.time(), time.monotonic()
            return ws

    async def identify(self) -> dict[str, Any]:
        if not webrtc_available():
            raise MISSING_DRIVER.with_traceback(None)
        self._down_error = None  # a person is waiting: try now
        ws = await self._signalling()  # proves the address and the password; takes nobody's picture
        self._answered()
        version = None
        try:
            hello = _parse(await Listening(ws, 2**20).message(3))
            if hello.get("type") == "device-metadata":
                data = hello.get("data")
                version = plain(data.get("deviceVersion"), 40) if isinstance(data, dict) else None
        except (TimeoutError, WebSocketException, KvmError):
            pass
        finally:
            await ws.close()
        return {"model": "JetKVM", "version": version, "hostname": None, "ident": await self._own_number()}

    # --- the WebRTC session --------------------------------------------------

    def _start(self) -> _Session:
        """Begin connecting unless that is already under way."""
        if self._task is None or self._task.done():
            self._session = _Session()
            self._task = asyncio.create_task(self._run(self._session))
        assert self._session is not None
        return self._session

    def _refused(self) -> KvmError | None:
        """Why the last attempt ended, while it is too soon to make another."""
        session = self._session
        if session is not None and session.done.is_set() and session.error and time.monotonic() < self._retry_at:
            return session.error
        return None

    async def _connected(self, urgent: bool = False) -> _Session:
        """The live session, connecting first if need be. Raises KvmError when there is none to be had."""
        if self._displaced:
            raise IN_USE.with_traceback(None)
        if not self._looking_on:
            self._wanted_at = time.monotonic()
        session = self._session
        if session is not None and session.live:
            return session
        if urgent:
            self._down_error = None
        else:
            self._check_backoff()
            refused = self._refused()
            if refused is not None:
                raise refused.with_traceback(None)
        session = self._start()
        waits = [asyncio.ensure_future(session.ready.wait()), asyncio.ensure_future(session.done.wait())]
        try:
            await asyncio.wait(waits, timeout=CONNECT_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for wait in waits:
                wait.cancel()
        if session.live:
            return session
        if self._displaced:
            raise IN_USE.with_traceback(None)
        # (`session.lost`: it closed the channel it is asked over a moment ago, and the connection is on its
        # way out. That is the device having dropped out, and nothing was sent: said as "taking too long",
        # the page showed a key press as one that "may have been done".)
        raise (session.error or session.lost or KvmError("timeout", "The JetKVM is taking too long to connect", 504)).with_traceback(None)

    async def _run(self, session: _Session) -> None:
        try:
            await self._hold(session)
        except KvmError as ex:
            session.error = self._failed(ex)
            if ex.code not in DOWN_CODES:  # those have their own, growing, back-off
                self._retry_at = time.monotonic() + RETRY_PAUSE
        except asyncio.CancelledError:
            raise
        except Exception as ex:  # whatever the WebRTC stack throws must not take the wall down
            self._unexpected("the video connection failed", ex)
            session.error = self._failed(KvmError("dropped", "The video connection to the JetKVM failed"))
        finally:
            session.done.set()
            for future in session.pending.values():
                if not future.done():
                    future.set_exception(KvmError("dropped", "The JetKVM closed the connection"))
            for watcher in session.watchers:
                watcher.cancel()
            # The last picture (decoded, so megabytes of it) is not kept beyond the connection it came over.
            session.frame = None
            session.encoded.clear()
            if session.pc is not None:
                # Given a few seconds, and then left to finish by itself: whoever waits for this is holding
                # up a change to the wall, or the program's way out.
                try:
                    async with asyncio.timeout(5):  # (not wait_for, which loses a stop up to Python 3.11: see Listening.message)
                        await asyncio.shield(session.pc.close())
                except TimeoutError:
                    log.warning("%s: the video connection is taking its time to close", self.label)

    async def _hold(self, session: _Session) -> None:
        """Connect as the JetKVM's own page would, then stay for as long as the wall is watched."""
        try:
            from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription
            from aiortc.sdp import candidate_from_sdp
        except ImportError:
            raise MISSING_DRIVER from None
        # Until the first full frame has arrived, the pieces of video in between cannot be decoded,
        # and the library warns about every one of them. That is how video starts, not something to report.
        logging.getLogger("aiortc.codecs.h264").setLevel(logging.ERROR)

        ws = await self._signalling()
        try:
            # No STUN or TURN servers: the wall and the KVM talk directly, and nobody else needs to know.
            pc = session.pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
            pc.addTransceiver("video", direction="recvonly")
            rpc = session.rpc = pc.createDataChannel("rpc")  # the device only answers on channels the viewer opens
            rpc.on("open", session.ready.set)
            rpc.on("message", lambda message: self._on_message(session, message))
            # What the JetKVM is asked over can be closed by it while its picture goes on coming. A connection
            # with a picture and nobody to ask is none: it is ended like one that went quiet, and made anew.
            rpc.on("close", lambda: self._no_more_asking(session))
            pc.on("track", lambda track: self._on_track(session, track))

            await pc.setLocalDescription(await pc.createOffer())
            offer = {"type": "offer", "sdp": pc.localDescription.sdp}
            await ws.send(json.dumps({"type": "offer", "data": {"sd": _pack(offer)}}))
            heard = Listening(ws, 2**20)
            answer, candidates = await _await_answer(heard)
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=with_candidates(answer, candidates), type="answer")
            )

            deadline = time.monotonic() + CONNECT_TIMEOUT
            signalling = True
            while True:
                if session.taken:
                    return
                # A device that reboots or loses power says no goodbye, and the connection takes half a
                # minute to notice by itself. Until then the last picture would pass for the screen.
                stalled = session.frame is not None and time.monotonic() - session.frame_at > FRAME_STALE
                if stalled and session.video.get("ready") is not False and session.lost is None:
                    session.lost = KvmError("dropped", "The JetKVM stopped sending video")
                if session.lost is not None:
                    raise session.lost
                if pc.connectionState in ("failed", "closed"):
                    if session.ready.is_set():
                        raise KvmError("dropped", "The JetKVM closed the video connection")
                    raise KvmError("dropped", "Could not open a video connection to the JetKVM")
                if not session.ready.is_set() and time.monotonic() > deadline:
                    raise KvmError("timeout", "The JetKVM is taking too long to connect", 504)
                if session.ready.is_set() and time.monotonic() - self._wanted_at > KEEPALIVE_IDLE:
                    return  # nobody is looking at the wall: give the device its viewer slot back
                if not signalling:
                    await asyncio.sleep(1)
                    continue
                try:
                    message = _parse(await heard.message(1))
                except TimeoutError:
                    continue
                except ConnectionClosed:
                    signalling = False  # the video connection lives on without it
                    continue
                data = message.get("data")
                if message.get("type") == "new-ice-candidate" and isinstance(data, dict):
                    text, mid, line = as_text(data.get("candidate")), data.get("sdpMid"), data.get("sdpMLineIndex")
                    if text.startswith("candidate:"):
                        try:
                            candidate = candidate_from_sdp(text.split(":", 1)[1])
                            candidate.sdpMid = mid if isinstance(mid, str) else None
                            candidate.sdpMLineIndex = line if isinstance(line, int) and not isinstance(line, bool) else None
                            await pc.addIceCandidate(candidate)
                        except Exception as ex:  # a late address we can do without, or something that is not one
                            log.debug("%s: ignoring a candidate: %s", self.label, plain(str(ex), 200))
        finally:
            await ws.close()

    def _on_track(self, session: _Session, track: Any) -> None:
        if track.kind == "video":
            session.watchers.append(asyncio.create_task(self._watch(session, track)))

    async def _watch(self, session: _Session, track: Any) -> None:
        """Keep the newest decoded frame. Every frame has to be taken, or they pile up."""
        from aiortc.mediastreams import MediaStreamError

        try:
            while True:
                session.frame = await track.recv()
                session.frame_at = time.monotonic()
        except MediaStreamError:
            pass

    def _on_message(self, session: _Session, message: Any) -> None:
        if not isinstance(message, str):
            return
        try:
            data = json.loads(message)
        except (ValueError, RecursionError):  # (the last: brackets within brackets, thousands deep, on a Python before 3.13)
            return
        if not isinstance(data, dict):
            return
        call_id = data.get("id")
        # Only a number we handed out names a call of ours; anything else from the device is not trusted as a key.
        future = session.pending.pop(call_id, None) if type(call_id) is int else None
        if future is not None:
            if not future.done():
                future.set_result(data)
            return
        method, params = data.get("method"), data.get("params")
        if method == "otherSessionConnected":
            # Someone opened the JetKVM's console. The device is about to drop us; let it,
            # and do not come back until asked.
            if session.taken:
                return  # said already, of this connection: a device can send the message as often as it likes
            log.info("%s: in use from another browser", self.label)
            session.taken = self._displaced = True
            self._status = {"state": "busy", "error": IN_USE.as_dict(), "kind": self.kind}
            self._status_at = time.monotonic()
        elif method == "videoInputState" and isinstance(params, dict):
            session.video = params
        elif method == "usbState" and isinstance(params, str):
            session.usb = params
        elif method == "atxState" and isinstance(params, dict):
            session.atx = params
        elif method == "localVersion" and isinstance(params, dict):
            session.version = plain(params.get("appVersion"), 40)

    def _no_more_asking(self, session: _Session) -> None:
        """The channel the JetKVM is asked over is closed: this connection is to be ended, whatever else still comes over it."""
        if session.ready.is_set() and not session.done.is_set() and session.lost is None:
            session.lost = KvmError("dropped", "The JetKVM closed the channel it is asked over")

    async def _call(self, session: _Session, method: str, params: dict[str, Any] | None = None) -> Any:
        if not session.live:
            raise KvmError("dropped", "The JetKVM closed the connection")
        session.next_id += 1
        call_id = session.next_id
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        session.pending[call_id] = future
        try:
            try:
                session.rpc.send(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": call_id}))
            except Exception:  # (the library's word for a channel that is closed; whichever it is, the question did not go out)
                # Sent before the wait was guarded, this was an error of the library's own kind: the question
                # stayed among the waiting ones for good, three more at every look, the JetKVM was "online"
                # with nobody to ask, and a key pressed on the page was an error inside the program.
                self._no_more_asking(session)
                raise KvmError("dropped", "The JetKVM closed the channel it is asked over") from None
            # (Not wait_for, which up to Python 3.11 loses a stop that comes with the answer: a text being typed
            # went on with the next key, and the rest. See Listening.message.)
            async with asyncio.timeout(RPC_TIMEOUT):
                reply = await future
        except TimeoutError:
            raise KvmError("timeout", "The JetKVM did not answer in time", 504) from None
        finally:
            session.pending.pop(call_id, None)
        error = reply.get("error")
        if error:
            detail = error.get("data") or error.get("message") if isinstance(error, dict) else error
            raise KvmError("action_failed", plain(detail, 200) or "The JetKVM refused")
        return reply.get("result")

    async def probe(self) -> str:
        """Whether the JetKVM is there, without taking its one viewer slot just to find out.

        While the wall is showing it, the full status is known anyway. Otherwise only
        "answers" or "doesn't" can be told: seeing whether it has a picture means connecting.
        """
        session = self._session
        if session is not None and session.live and not self._displaced:
            # A look for the alerts' sake is not somebody watching. Counted as that, it would keep the
            # connection, and with it the JetKVM's one viewer, for as long as alerts are switched on.
            # (Read here and now, not through status(): that hands back what was known and reads anew in a
            # task of its own, after this look is over and no longer there to say what it was for.)
            self._looking_on += 1
            try:
                await self._refresh_status()
                return str((self._status or {}).get("state") or "offline")
            finally:
                self._looking_on -= 1
        try:
            client = await self._http()
            reply = await self._send(client, client.build_request("GET", "/device/status"), MAX_PROBE, PROBE_TIME)
        except (httpx.HTTPError, KvmError):
            reply = None
        if reply is None or reply.status_code != 200:
            self._told = None  # gone: what it showed before says nothing about when it is back
            self._look_the_other_way(down=True)  # ...unless it is only its HTTPS that is gone
            return "error" if self._plain_only is not None else "offline"
        self._plain_only = self._down_since = None  # there: how long it was away before is over and done with
        self._last_ok, self._heard_at = time.time(), time.monotonic()  # heard from, whatever a connection to it would come to
        if self._displaced:
            return "busy"  # there, and somebody else has its picture: nothing to tell anybody
        # There, and that is all it says without a connection. What the last connection showed (no picture,
        # a password it would not take) is taken to be so still: calling it "online" in between would report
        # a picture as back each time somebody stops looking at the wall, and as lost each time they return.
        return self._told or "online"

    async def glance(self) -> dict[str, Any]:
        """What is known of it, asked the way the alerts ask (see probe).

        A collector that comes by every fifteen seconds is not somebody watching either. Asked through
        status(), it would connect to a JetKVM that nobody has on screen, take its one viewer, and keep it.
        """
        state = await self.probe()
        known = self._status if self._status is not None and self._status.get("state") == state else None
        seen = None if self._last_ok is None else max(0, round(time.time() - self._last_ok))
        return {**(known or {"state": state, "error": None, "kind": self.kind}), "last_seen_ago": seen}

    # --- snapshots ----------------------------------------------------------

    async def snapshot(self, width: int, fresh: float | None = None) -> Snapshot:
        arrived = self._wanted_at = time.monotonic()
        if self._displaced:
            raise IN_USE.with_traceback(None)
        session = self._session
        if session is None or not session.live:
            # Connecting takes a second or two; the tile asks again rather than wait here.
            self._check_backoff()
            refused = self._refused()
            if refused is not None:
                raise refused.with_traceback(None)
            self._start()
            raise KvmError("no_stream", "Connecting to the JetKVM", 503)
        frame = session.frame
        no_signal = session.video.get("ready") is False
        if no_signal and (frame is None or time.monotonic() - session.frame_at > FRAME_STALE):
            return Snapshot(_BLANK, "image/png", False, time.monotonic())
        if frame is None:
            raise KvmError("no_stream", "Waiting for the first picture", 503)
        if not no_signal and time.monotonic() - session.frame_at > FRAME_STALE:
            raise KvmError("no_stream", "Waiting for the JetKVM's video", 503)  # what is in hand is not the screen any more
        size = tier_for(width)
        if size != FULL and TIERS[size][0] >= frame.width:
            size = FULL
        async with self._encode_locks[size]:
            cached = session.encoded.get(size)
            # Nothing new since the last viewer asked, or nothing a viewer refreshing this slowly would notice:
            # the video brings a new frame many times a second, and turning each into a JPEG is work.
            if cached and (cached[0] is frame or arrived - cached[1].taken_at < share_window(fresh)):
                return cached[1]
            target = None if size == FULL else TIERS[size][0]
            asked = time.monotonic()
            data = await asyncio.to_thread(encode_jpeg, frame, target, QUANTIZER[size])
            snap = Snapshot(data, "image/jpeg", not no_signal, asked)
            session.encoded[size] = (frame, snap)
            return snap

    # --- actions ------------------------------------------------------------

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        if action == "resume":
            # Take the picture back. Whoever has the JetKVM's console open loses it.
            self._displaced = False
            self._status_at = 0.0
            await self._connected(urgent=True)
            await self._refresh_status()  # the tile should not go on saying "in use"
            return
        reports: list[tuple[int, list[int]]] = []
        if action == "ctrl_alt_del":
            reports = [key_report("ControlLeft,AltLeft,Delete")]
        elif action == "keys":
            if not KEYS.fullmatch(keys):
                raise KvmError("invalid", "Not a valid key combination", 422)
            reports = [key_report(keys)]
        elif action == "text":
            if not text or len(text) > MAX_TEXT:
                raise KvmError("invalid", f"Text must be 1 to {MAX_TEXT} characters", 422)
            reports = text_reports(text)
        elif action == "wol":
            if not MAC.fullmatch(mac):
                raise KvmError("invalid", "Not a valid MAC address", 422)
        elif action not in ("reboot", "jiggler_on", "jiggler_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A JetKVM cannot do that", 422)

        session = await self._connected(urgent=True)
        # Connecting to a JetKVM takes seconds, a quarter of a minute at most: asked now, before anything is
        # pressed, whether whoever wanted it may still have it.
        if still is not None and not still():
            raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
        if reports:
            async with self._typing:  # two people typing at once would interleave
                for typed, (modifier, codes) in enumerate(reports):
                    # A long text takes a minute and more. All that while the connection is in use, whoever
                    # looks or does not: left to count as idle, it was closed in the middle of the text.
                    self._wanted_at = time.monotonic()
                    # And all that while it is this program that presses the keys. Now and then, between two
                    # keys, with none of them down: may whoever asked for this still have it done?
                    if typed and typed % ASK_EVERY == 0 and still is not None and not still():
                        raise KvmError("stopped", f"Typing was stopped after {typed} of {len(reports)} keys: whoever asked for it may no longer do that", 403)
                    let_go = False
                    try:
                        await self._call(session, "keyboardReport", {"modifier": modifier, "keys": codes})
                        await asyncio.sleep(KEY_PAUSE if action == "text" else 0.05)
                        let_go = True
                        await self._call(session, "keyboardReport", {"modifier": 0, "keys": []})  # nothing releases by itself
                    except BaseException:
                        # The key may be down and nothing has said that it was let go (the answer to the
                        # press did not come, or whoever asked went away during the pause): a key held down
                        # repeats on the machine for as long as nobody says otherwise. Said once, unanswered.
                        if not let_go:
                            self._let_go(session)
                        raise
                    await asyncio.sleep(KEY_PAUSE)
        elif action == "wol":
            await self._call(session, "sendWOLMagicPacket", {"macAddress": mac})
        elif action in ("jiggler_on", "jiggler_off"):
            await self._call(session, "setJigglerState", {"enabled": action == "jiggler_on"})
        elif action.startswith("atx_"):
            if await self._call(session, "getActiveExtension") != "atx-power":
                raise KvmError("action_failed", "This JetKVM has no ATX power extension switched on")
            press = {"atx_power": "power-short", "atx_power_long": "power-long", "atx_reset": "reset"}[action]
            await self._call(session, "setATXPowerAction", {"action": press})
        elif action == "reboot":
            try:
                await self._call(session, "reboot", {"force": True})
            except KvmError as ex:
                if ex.code not in ("dropped", "timeout"):  # it may be gone before it can answer
                    raise

    def _let_go(self, session: _Session) -> None:
        """Tell the JetKVM that no key is down, without waiting to hear that it took note."""
        try:
            if session.live:
                session.next_id += 1
                session.rpc.send(json.dumps({"jsonrpc": "2.0", "method": "keyboardReport", "params": {"modifier": 0, "keys": []}, "id": session.next_id}))
        except Exception:  # the connection is gone, and with it what the JetKVM held down
            pass

    async def wol_targets(self) -> list[dict[str, str]]:
        """Machines saved on the JetKVM for Wake-on-LAN."""
        try:
            session = await self._connected(urgent=True)
            saved = await self._call(session, "getWakeOnLanDevices")
        except KvmError:
            return []
        targets = []
        for entry in saved if isinstance(saved, list) else []:
            mac = as_text(entry.get("macAddress")) if isinstance(entry, dict) else ""
            if MAC.fullmatch(mac):
                targets.append({"mac": mac, "name": plain(entry.get("name")) or ""})
        return targets

    # --- status -------------------------------------------------------------

    async def _read_status(self) -> dict[str, Any]:
        try:
            session = await self._connected()
        except KvmError as ex:
            there = False
            if ex.code in ("auth_failed", "no_password", "not_set_up", "no_sign_in", "bad_response"):
                gone = await self._gone_meanwhile("/device/status")
                ex, there = gone or ex, gone is None
            if ex.code == "in_use":
                state = "busy"
            elif ex.code in ("auth_failed", "no_password", "not_set_up"):
                state = "auth"
            elif ex.code in ("cert_mismatch", "cert_invalid", "missing_driver", "no_sign_in") or (there and ex.code == "bad_response"):
                state = "error"
            else:
                state = "offline"
                self._look_the_other_way(down=True)
                if self._plain_only is not None:
                    state, ex = "error", self._only_plain(self._plain_only)
            if there:
                # It answers at its address (it said no, or it does not sign this program in and is there all
                # the same). Since when it was away before that is over: left standing, the next failure of
                # any kind was taken for two minutes of silence, and its tile said that it answers over plain
                # HTTP only.
                self._plain_only = self._down_since = None
            if state == "auth" or ex.code in ("cert_mismatch", "cert_invalid", "missing_driver", "plain_only"):
                # What lasts until somebody does something about it, and so is taken to be so still by a look
                # that makes no connection. A sign-in that came to nothing once is not that: kept, the round
                # that sends alerts went on saying "has a problem" for as long as nobody opened the wall.
                self._told = state
            return {"state": state, "error": ex.as_dict(), "kind": self.kind}
        self._plain_only = self._down_since = None
        self._look_the_other_way(down=False)

        answers: tuple[Any, ...] = await asyncio.gather(
            self._call(session, "getVideoState"),
            self._call(session, "getUSBState"),
            self._call(session, "getActiveExtension"),
            self._version(session),
            return_exceptions=True,
        )
        video, usb, extension, version = answers  # each is what the JetKVM said, or the error asking it ended in
        if isinstance(video, KvmError) and video.code in ("timeout", "dropped"):
            # It does not answer on a connection that is supposed to be open: the connection is dead, and
            # what was last heard over it says nothing about now.
            session.lost = session.lost or KvmError("dropped", "The JetKVM stopped answering")
            return {"state": "offline", "error": session.lost.as_dict(), "kind": self.kind}
        self._answered()
        atx: Any = None
        if extension == "atx-power":
            try:
                atx = await self._call(session, "getATXState")
            except KvmError:
                atx = session.atx
        if isinstance(video, dict):
            session.video = video
        video = session.video
        ready = flag(video.get("ready"))
        if ready is None:  # the device has not said: believe the picture
            ready = session.frame is not None
        attached = None if not isinstance(usb, str) else usb == "configured"
        self._told = "online" if ready else "no_signal"
        return {
            "state": self._told,
            "error": None,
            "kind": self.kind,
            "video": {
                "signal": bool(ready),
                "width": number(video.get("width"), 1, 100_000),
                "height": number(video.get("height"), 1, 100_000),
                "fps": number(video.get("fps"), 0.001, 1000),
            },
            "usb": {"keyboard": attached, "mouse": attached},
            "atx": {
                "enabled": extension == "atx-power",
                "power": flag(atx.get("power")) if isinstance(atx, dict) else None,
                "hdd": flag(atx.get("hdd")) if isinstance(atx, dict) else None,
            },
            "health": {"temp": None, "cpu": None, "mem": None},
            "about": {"model": "JetKVM", "version": version if isinstance(version, str) else None},
            "ports": None,
        }

    def _only_plain(self, twin: str) -> KvmError:
        said = "This JetKVM no longer answers over HTTPS, only over plain HTTP. "
        if self.spec.password:
            said += f"Its password would travel unencrypted there: to allow that, change its address to {twin} and type its password again"
        else:
            said += f"Nothing would be checked or encrypted there: to use it that way, change its address to {twin}"
        return KvmError("plain_only", said)

    async def _version(self, session: _Session) -> str | None:
        if session.version is None:
            local = await self._call(session, "getLocalVersion")
            session.version = plain(local.get("appVersion"), 40) if isinstance(local, dict) else None
        return session.version


def _pack(description: dict[str, str]) -> str:
    return base64.b64encode(json.dumps(description).encode()).decode()


def _parse(raw: Any) -> dict[str, Any]:
    """One signalling message. Anything that isn't a JSON object (such as "pong") comes back empty."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError, RecursionError):  # the last: brackets within brackets, thousands deep
        return {}
    return data if isinstance(data, dict) else {}


async def _await_answer(heard: Listening) -> tuple[str, list[str]]:
    """The device's answer to our offer, and the network addresses it sends right after."""
    answer: str | None = None
    candidates: list[str] = []
    deadline = time.monotonic() + CONNECT_TIMEOUT
    # However much is said and for however long, this ends: the answer has until `deadline`, the addresses
    # after it a little longer, and only so many of them are kept. A device that goes on talking is not
    # listened to for ever, and what it says is not all held in memory.
    last = deadline + CANDIDATE_WAIT
    while True:
        if answer is None:
            timeout = deadline - time.monotonic()
        elif candidates or "a=candidate" in answer:
            timeout = min(CANDIDATE_QUIET, last - time.monotonic())
        else:
            timeout = min(CANDIDATE_WAIT, last - time.monotonic())
        try:
            if timeout <= 0 or len(candidates) >= MAX_CANDIDATES:
                raise TimeoutError
            message = _parse(await heard.message(timeout))
        except TimeoutError:
            if answer is None:
                raise KvmError("timeout", "The JetKVM did not answer the request for video", 504) from None
            return answer, candidates
        except ConnectionClosed:
            if answer is None:
                raise KvmError("dropped", "The JetKVM closed the connection") from None
            return answer, candidates
        kind = message.get("type")
        if kind is None and message.get("error"):
            raise KvmError("bad_response", f"The JetKVM refused the request for video: {plain(message['error'], 200) or 'no reason given'}")
        if kind == "answer":
            try:
                answer = as_text(json.loads(base64.b64decode(message["data"]))["sdp"])
                if not answer:
                    raise ValueError("a description that is no text")
            except (KeyError, ValueError, TypeError, RecursionError):
                raise KvmError("bad_response", "The JetKVM sent an answer that cannot be read") from None
        elif kind == "new-ice-candidate":
            data = message.get("data")
            text = as_text(data.get("candidate")) if isinstance(data, dict) else ""
            if text:
                candidates.append(text[:1000])


def _ws_error(ex: BaseException, tls: str) -> KvmError:
    import ssl

    cause: BaseException | None = ex
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            if tls == "pinned":
                return KvmError("cert_mismatch", "Certificate does not match the one saved for this device")
            return KvmError("cert_invalid", "The device's certificate is not trusted")
        cause = cause.__cause__ or cause.__context__
    if isinstance(ex, OSError):
        return KvmError("unreachable", "Device is unreachable")
    return KvmError("dropped", "The device closed the connection")
