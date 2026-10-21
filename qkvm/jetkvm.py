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
import contextlib
import hashlib
import importlib.util
import json
import logging
import re
import struct
import time
import zlib
from collections import deque
from collections.abc import Callable
from fractions import Fraction
from typing import Any

import httpx
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed, InvalidStatus, WebSocketException

from .kvm import (
    DOWN_CODES,
    FULL,
    KEYS,
    LOGIN_BACKOFF,
    LOGIN_RETRY,
    MAC,
    MAX_TEXT,
    MAX_PROBE,
    MAX_REPLY,
    REJECTED,
    RETIRED,
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
    can_do,
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
    ws_error,
)
from .layouts import LAYOUTS
from .layouts import NAMES as LAYOUT_NAMES

log = logging.getLogger("qkvm")

CONNECT_TIMEOUT = 15.0  # from asking for video to an open connection
RPC_TIMEOUT = 8.0
CANDIDATE_QUIET = 0.3  # the device sends its network addresses one by one; this much silence ends the wait
CANDIDATE_WAIT = 3.0  # ...and this is how long to wait for the first one
MAX_CANDIDATES = 40  # addresses a device may offer; a real one has a handful
KEY_PAUSE = 0.004  # between key reports while typing text
HOLD = 0.05  # how long the keys of a combination (Ctrl+Alt+Del, a saved one) are held down
# Once the JetKVM has said that its own page has the viewer, calls still in its hands are given this long to be
# answered before the wall closes the connection (see `_hold`), while the JetKVM keeps it open.
HAND_OVER_GRACE = 2.0
MOST_GIVEN_UP = 32  # presses with no answer in time that are remembered, should their answer come after all
ASK_EVERY = 25  # keys typed before it is asked again whether the account they are typed for may still do that
# A frame older than this is no longer "the screen". A JetKVM sends video all the time, also of a
# screen on which nothing moves, so when frames stop coming while it claims a signal, it is gone.
FRAME_STALE = 5.0
# A JetKVM says at once that its input is back (its computer woke, or its screen did), and sends the first picture of it a
# moment later: a real one within a second or so, now and then some seconds. That picture is waited for from that moment,
# this long, in place of FRAME_STALE (the picture from before is not the screen, however young, and no sign of a JetKVM
# that stopped, however old); where none comes by then, the JetKVM is taken for one that stopped sending video, as by
# FRAME_STALE (a real one once sent none on the connection it had when its computer was woken, and a new connection had
# the picture at once). Longer than the slowest first picture a real one gave a connection after a long rest (some fifteen).
PICTURE_AFTER_SIGNAL = 20.0
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
# Keys and the mouse for the live line go to a JetKVM one at a time, each once it has answered the one before (see
# `say`). It has this long to answer one before the connection is ended (it then lets go of every key by itself), and
# this many may wait to go. (Longer than a lost packet costs: one message in flight is sent again after a second.)
TAKE_WITHIN = 5.0
MOST_WAITING = 256
MOST_STEP = 127  # the most a relative move or a turn of the wheel says in one report (a signed byte)
# Keys and the mouse go over the binary `hidrpc` channel where the JetKVM answers its handshake (see `_choose_road`):
# it is asked this often, for this long from the channel's opening, before keys go over JSON-RPC instead (an older
# firmware has no hidrpc).
HID_VERSION = 1
HID_SHAKE_EVERY = 0.25
HID_SHAKE_WITHIN = 2.0
# One whose answer comes later (a wall busy for seconds hears it late; a JetKVM still setting the channel up does not hear
# the first questions) is asked again this often, this many times, as its own page asks; once it answers, keys go over
# hidrpc from the first moment nothing of ours is down or on its way over JSON-RPC (see `_late_road`).
HID_ASK_AGAIN_EVERY = 1.0
HID_ASKS_AGAIN = 10
# A key the live line holds is pressed by a keypress message, which the JetKVM lets go of 100 ms later unless a
# keep-alive comes (a gap of more than about 100 ms lets go of it for good): so it is let go of within a tenth of a
# second when the wall vanishes. Modifiers it never lets go of that way. Its own page sends one every 50 ms; one that
# comes early counts in full, so every 30 ms leaves a wall that is busy for a moment 70 ms, not 50, before a key that is
# still held is let go of.
KEEP_ALIVE_EVERY = 0.03
MOST_BUFFERED = 16384  # bytes of hidrpc messages waiting in the wall to go out, beyond which the connection is made anew
MOST_HID_MESSAGE = 64  # what the JetKVM says on hidrpc is a handful of bytes; anything longer is not read
LET_GO_WAIT = 0.5  # before the wall closes a connection with something down: how long it waits for the letting go to leave
LET_GO_SETTLE = 0.05  # ...and then, for the JetKVM to have done it (it does each message within milliseconds)
NOTHING_DOWN = (0, ())  # the keyboard with nothing down: (modifier bits, keys)
# The connection, and with it the JetKVM's one viewer, is given back this long after nobody has asked for its picture
# (the owner's standard for such holds). A JetKVM nobody has watched for a minute sends its first picture some five
# seconds after it is connected to; one that is held shows it at once when somebody looks again.
UNWATCHED = 300.0

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

# The keyboard layout a JetKVM's computer uses, by its name for it (`getKeyboardLayout`): US English, unless it says
# otherwise (one that has no such question typed in it); a name it gives is taken where it looks like one.
US = "en-US"
LAYOUT_NAME = re.compile(r"[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{1,8}){0,3}")

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


def text_reports(text: str, layout: str = US) -> list[tuple[int, list[int]]]:
    """What to press, key by key, to type `text` on a computer set to `layout` (by the name a JetKVM gives it).

    The keys of the layout Windows has under that name (`layouts`, made from Unicode CLDR's), a character a dead key
    makes as that key and the next. KvmError (422) for a character the layout cannot type, or a layout there is no
    table for, before anything is typed. The keys of the live line are places on the keyboard, and not touched by this.
    """
    # (A refusal says which character by its place in the text, never the character: the words go to the activity log,
    # and a saved text is never written there.)
    text = text.replace("\r\n", "\n")
    reports = []
    if layout == US:
        for place, char in enumerate(text, 1):
            if char not in _CHARS:
                raise KvmError("invalid", f"Nothing was typed: character {place} of the text cannot be typed on the US keyboard layout this JetKVM's computer is set to", 422)
            shift, key = _CHARS[char]
            reports.append((_MODIFIERS["ShiftLeft"] if shift else 0, [_USAGE[key]]))
        return reports
    table = LAYOUTS.get(layout)
    if table is None:
        raise KvmError("invalid", f"Nothing was typed: this JetKVM's computer is set to the keyboard layout {layout}, which qKVM has no table for", 422)
    for place, char in enumerate(text, 1):
        steps = table.get(char)
        if steps is None:
            raise KvmError("invalid", f"Nothing was typed: character {place} of the text cannot be typed on the {LAYOUT_NAMES[layout]} keyboard layout this JetKVM's computer is set to", 422)
        reports.extend((step >> 8, [step & 0xFF]) for step in steps)
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


class _Leftover:
    """What the wall's connections to one JetKVM may have left down there (see `JetKvmDevice._settle_owed`)."""

    def __init__(self) -> None:
        self.down = False  # a connection ended with a key or a mouse button of ours down, or maybe down
        self.place: tuple[int, int] | None = None  # where the absolute mouse was last put, over any connection


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
        # When the JetKVM last said its input came back after it had said there was none (`_video_said`): a picture of the
        # screen is waited for from then on (PICTURE_AFTER_SIGNAL), not taken for one that stopped (FRAME_STALE).
        self.signal_at = 0.0
        self.ready_said: bool | None = None  # (the last `ready` it said as a boolean: what a change is told by)
        self.video_events = 0  # `videoInputState` events heard on this connection (an answer asked before one is older)
        self.usb: str | None = None
        self.atx: dict[str, Any] | None = None
        self.version: str | None = None
        self.pending: dict[int, asyncio.Future[Any]] = {}
        self.next_id = 0
        self.encoded: dict[str, tuple[Any, Snapshot]] = {}
        self.watchers: list[asyncio.Task[None]] = []
        self.lost: KvmError | None = None  # the device stopped sending or answering: this connection is to be ended
        # Keys and the mouse for the live line, waiting to go (see JetKvmDevice.say): each with whether a later one of
        # its kind may be folded into it; and what sends them.
        self.outbox: deque[tuple[str, dict[str, Any], bool]] = deque()
        self.sending: asyncio.Task[None] | None = None
        self.refused_said = False  # a report the JetKVM refused was written to the log (once a connection)
        # Calls of ours that press keys or mouse buttons, sent and not yet answered (by their number: what they said);
        # and the calls whose answer came after the JetKVM said that somebody else has its viewer (see `_call`).
        self.pressing: dict[int, tuple[str, dict[str, Any]]] = {}
        self.after_hand_over: set[int] = set()
        self.given_up: dict[int, tuple[str, dict[str, Any]]] = {}  # presses no answer came for in time (the newest few)
        # Set as anything `_answers_due` waits for changes: an answer comes (to a call under way, or to a press given up
        # on), a call's own wait runs out, the channel closes, the connection ends.
        self.heard = asyncio.Event()
        # Why the wall ends this connection itself, to make a new one (keys that may be done late, out of turn: see
        # `JetKvmDevice._make_anew`). Not the JetKVM's fault: it is not counted as down for it.
        self.anew: str | None = None
        # Which way keys and the mouse go over this connection: "hidrpc" or "rpc", once the JetKVM answered the hidrpc
        # handshake or did not (`_choose_road`); `keys_ready` once that is decided and what was owed sent (no key goes
        # before). The hidrpc channel, its being open, and the JetKVM's answer to the handshake.
        self.road: str | None = None
        self.keys_ready = asyncio.Event()
        self.hid: Any = None
        self.hid_open = asyncio.Event()
        self.shaken = asyncio.Event()
        self.hid_other = False  # the JetKVM answered the handshake with another version
        # Calls of keyboard and mouse reports sent over JSON-RPC, until their answer comes, also where nobody waits for it any
        # more (lettings go, a wait that ran out or was cut short): keys do not change road while one may still be done
        # (`JetKvmDevice._quiet`).
        self.unanswered: set[int] = set()
        # What the wall last said of the keyboard and the mice over this connection (either way): the keyboard as
        # (modifier bits, keys); the absolute mouse as (x, y, buttons), the relative one's buttons (two devices to the
        # computer, each with buttons of its own). What the JetKVM ends up with, once it has done everything of ours: it
        # does each kind in the order sent (on hidrpc; on JSON-RPC one is sent once the one before was answered).
        self.kb_sent: tuple[int, tuple[int, ...]] = NOTHING_DOWN
        self.abs_sent: tuple[int, int, int] | None = None
        self.rel_buttons = 0
        self.mouse_calls = 0  # mouse reports over JSON-RPC sent and not yet answered (or given up on)
        self.held: set[int] = set()  # keys pressed by a keypress message on hidrpc and not let go of: kept alive
        self.keeping: asyncio.Task[None] | None = None  # the keep-alive
        # Keyboard states said over hidrpc that an action waits to hear the JetKVM say it has (`0x33`), oldest first.
        self.echoes_due: deque[tuple[tuple[int, tuple[int, ...]], asyncio.Future[None]]] = deque()
        self.layout: str | None = None  # the keyboard layout the JetKVM says its computer uses, once asked (`_layout`)
        self.had_down = False  # something of ours was down, or may have been, when this connection ended

    @property
    def live(self) -> bool:
        return self.ready.is_set() and not self.done.is_set() and self.lost is None and self.anew is None


def _video_said(session: _Session, video: dict[str, Any]) -> None:
    """What the JetKVM says of its input (an event as it changes, or the answer to a question). Where it had said there was
    none and says now that there is, that moment is noted: the picture of the screen is waited for from then (`_hold`)."""
    ready = flag(video.get("ready"))
    if ready is True and session.ready_said is False:
        session.signal_at = time.monotonic()
    if ready is not None:  # (an answer that does not say it, or says it in another kind, changes nothing of it)
        session.ready_said = ready
    session.video = video


class JetKvmDevice(Device):
    """A JetKVM, over WebRTC."""

    kind = "jetkvm"
    # Every JetKVM: its screen, keys and text, keep-awake, Wake-on-LAN, its own restart, and taking its picture
    # back from whoever opened its own page (`resume`). A look adds the ATX power extension, where it is on.
    can = ("screen", "keys", "text", "jiggler", "wol", "reboot", "resume", "live", "control")

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
        # What a connection of the wall's to this JetKVM may have left down when it ended, for the next one to let go of
        # first (see `_settle_owed`): a JetKVM lets go of the keyboard when a connection ends, never of a mouse button.
        self._leftover = _Leftover()
        self._said_no_hid = False  # the log has said that this one takes keys over JSON-RPC only

    def takes_over(self, retired: Device) -> None:
        # Somebody opened the JetKVM's own console and so took its one viewer: the wall stepped aside, and
        # stays aside until it is asked back, whatever is changed about the tile meanwhile.
        if isinstance(retired, JetKvmDevice):
            self._displaced = retired._displaced
            # (And what its connections leave down, the one it is closing as it is retired included, is let go of on
            # this one's first: shared, since that one ends only after this one has taken its place.)
            self._leftover = retired._leftover

    async def close(self) -> None:
        self._closed = True
        session = self._session
        try:
            if session is not None and session.taken and not session.done.is_set():
                # Its own page took the viewer, and presses of ours may still be in the JetKVM's hands: their answers are
                # given HAND_OVER_GRACE to come, so that each is let go of after it and not, out of turn, before it (see
                # `_hold`).
                await self._answers_due(session, presses_only=True)
            elif session is not None and not session.done.is_set():
                # Ended on purpose (the tile edited or removed, the wall locking itself or stopping): what it has down is
                # let go of first, and given a moment to leave (a JetKVM keeps a mouse button down past the end).
                await self._let_go_before_closing(session, wait=True)
        finally:  # (stopped meanwhile, the rest of closing is done all the same)
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
                raise self._failed(ws_error(ex, self.spec.tls)) from ex
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
        if session is not None and session.live and not session.taken:
            return session
        if urgent:
            self._down_error = None
        else:
            self._check_backoff()
            refused = self._refused()
            if refused is not None:
                raise refused.with_traceback(None)
        ending = self._task
        if session is not None and (session.anew is not None or session.taken) and ending is not None and not ending.done():
            # Being ended by the wall (to be made anew, or because its own page took the viewer, as when "Show here"
            # comes a moment after that): once it is closed (HAND_OVER_GRACE and six seconds at the most here; beyond
            # that it is said to be taking too long, and asked again it is made).
            await asyncio.wait({ending}, timeout=HAND_OVER_GRACE + 6)
            # (Looked at again after that wait: the tile may have been edited or removed meanwhile, or the JetKVM's own page
            # may have taken the viewer as the old connection ended.)
            if self._closed:
                raise RETIRED.with_traceback(None)
            if self._displaced:
                raise IN_USE.with_traceback(None)
        session = self._start()
        waits = [asyncio.ensure_future(session.ready.wait()), asyncio.ensure_future(session.done.wait())]
        try:
            await asyncio.wait(waits, timeout=CONNECT_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for wait in waits:
                wait.cancel()
        if session.live and not session.taken:
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
            # What this connection has down is let go of while it is still open, where nobody else has taken its viewer
            # (the ends that come from within it say it in `_hold` and wait for it to leave; this one does not wait).
            if not session.taken:
                self._send_let_go(session)
            # What this connection may have pressed and has no answer for is let go of while it is still open (see
            # `_call`): a press the JetKVM does after this is otherwise down for whoever has its viewer then.
            for pressed in session.pressing.values():
                self._let_go_of(session, *pressed)
            if not session.taken and (session.pressing or session.given_up):
                session.had_down = True
            if session.had_down:
                self._leftover.down = True  # (the next connection says "nothing down" first)
            session.pressing.clear()
            if session.keeping is not None:
                session.keeping.cancel()
            for _, waiting in session.echoes_due:
                if not waiting.done():
                    waiting.set_exception(self._cut_off(session))
            session.echoes_due.clear()
            session.done.set()
            session.heard.set()
            session.keys_ready.set()  # (whoever waits for the road hears of the end, also where it was never chosen)
            for future in session.pending.values():
                if not future.done():
                    future.set_exception(self._cut_off(session))
            for watcher in session.watchers:
                watcher.cancel()
            if session.sending is not None:
                session.sending.cancel()  # (the device lets go of what this connection had down when it ends: seen on a real one)
            session.outbox.clear()
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
            rpc.on("open", lambda: self._opened(session))
            rpc.on("message", lambda message: self._on_message(session, message))
            # What the JetKVM is asked over can be closed by it while its picture goes on coming. A connection
            # with a picture and nobody to ask is none: it is ended like one that went quiet, and made anew.
            rpc.on("close", lambda: self._no_more_asking(session))
            # Keys and the mouse, as its own page sends them (see `_choose_road`): reliable, in order.
            hid = session.hid = pc.createDataChannel("hidrpc")
            hid.on("open", session.hid_open.set)
            hid.on("message", lambda message: self._on_hid(session, message))
            hid.on("close", lambda: self._no_more_hid(session))
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
                    # Its own page has the viewer. What is still in the JetKVM's hands is given its answer first: a
                    # press it does after the hand-over is then let go of in turn, by `_call`, as that answer comes.
                    # (Ended now, the letting go for it would go out of turn, and could be done before the press.)
                    # (Where it closes the connection first, the wait is HAND_OVER_GRACE: nothing more is answered then.)
                    await self._answers_due(session)
                    return
                if session.anew is not None:
                    log.info("%s: the connection is made anew: %s", self.label, session.anew)
                    await self._let_go_before_closing(session, wait=True)
                    return
                # A device that reboots or loses power says no goodbye, and the connection takes half a
                # minute to notice by itself. Until then the last picture would pass for the screen.
                # (Where the JetKVM has said its screen is back since its last picture, that picture is from before the
                # screen went, however old: the first one of the screen is waited for from that moment, PICTURE_AFTER_SIGNAL.)
                if session.signal_at > session.frame_at:
                    stalled = time.monotonic() - session.signal_at > PICTURE_AFTER_SIGNAL
                else:
                    stalled = session.frame is not None and time.monotonic() - session.frame_at > FRAME_STALE
                if stalled and session.ready_said is not False and session.lost is None:
                    session.lost = KvmError("dropped", "The JetKVM stopped sending video")
                if session.lost is not None:
                    raise session.lost
                if pc.connectionState in ("failed", "closed"):
                    if session.ready.is_set():
                        raise KvmError("dropped", "The JetKVM closed the video connection")
                    raise KvmError("dropped", "Could not open a video connection to the JetKVM")
                if not session.ready.is_set() and time.monotonic() > deadline:
                    raise KvmError("timeout", "The JetKVM is taking too long to connect", 504)
                if session.ready.is_set() and time.monotonic() - self._wanted_at > UNWATCHED:
                    await self._let_go_before_closing(session, wait=True)
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

    async def _answers_due(self, session: _Session, presses_only: bool = False) -> None:
        """Wait, HAND_OVER_GRACE at the most, for what the JetKVM still owes this connection after its own page took the
        viewer: the answers to the calls under way (`presses_only`: to those that press), and to the presses whose own
        wait ran out (`given_up`), which are let go of in turn as those answers come (`_on_message`). Never cancels
        what it waits for."""
        deadline = time.monotonic() + HAND_OVER_GRACE
        due = session.pressing if presses_only else session.pending
        # (A call is waited for as long as it is among those under way, whether or not its future is done: one whose own
        # wait ran out in this same turn of the loop has not yet moved a press to `given_up`, and then wakes this.)
        while not session.done.is_set() and session.rpc.readyState == "open" and (left := deadline - time.monotonic()) > 0:
            if not session.given_up and not any(number in session.pending for number in due):
                return
            session.heard.clear()
            try:
                async with asyncio.timeout(left):
                    await session.heard.wait()
            except TimeoutError:
                return

    def _cut_off(self, session: _Session) -> KvmError:
        """What a call is answered with that this connection's end cut off before the JetKVM answered it.

        Every such call went out (one that could not be sent is never among those waiting), and the JetKVM may have done
        it, whichever way the connection ended: its own page took the viewer, the tile was edited or removed, the wall
        locked itself or stopped, the wall made the connection anew or gave it up (no picture, no answer), the JetKVM
        closed it. So it may have been done, and is said so, as a call with no answer in time is: a power press is then
        "unknown" in the history, not "not pressed". A new error each time, or the one a kvmd KVM's tile says it with.
        """
        if session.taken:
            return KvmError("timeout", "The JetKVM's own page took it before it answered: it may have been done", 504)
        if self._closed:
            return RETIRED.with_traceback(None)
        if session.anew is not None:
            return KvmError("timeout", f"The connection to the JetKVM was made anew before it answered ({session.anew}): it may have been done", 504)
        return KvmError("timeout", "The connection to the JetKVM ended before it answered: it may have been done", 504)

    def _ended(self, session: _Session) -> KvmError:
        """Why nothing more goes over this connection, for what was not sent (so not done): the wall closing it, its
        making it anew, the JetKVM closing it, or its end."""
        if self._closed:
            return KvmError("dropped", "The tile was edited or removed, or the wall locked itself or stopped, meanwhile")
        if session.anew is not None:
            return KvmError("dropped", f"The connection to the JetKVM was made anew ({session.anew})")
        if session.lost is not None:
            return session.lost.with_traceback(None)
        return KvmError("dropped", "The connection to the JetKVM ended")

    def _on_track(self, session: _Session, track: Any) -> None:
        if track.kind == "video":
            session.watchers.append(asyncio.create_task(self._watch(session, track)))

    async def _watch(self, session: _Session, track: Any) -> None:
        """Keep the newest decoded frame. Every frame has to be taken, or they pile up."""
        from aiortc.mediastreams import MediaStreamError

        try:
            while True:
                signal_at = session.signal_at
                frame = await track.recv()
                if signal_at != session.signal_at:
                    # This receive began before the screen returned. Its decoded
                    # frame may still belong to the previous signal; wait for the
                    # next receive instead of marking that picture as current.
                    continue
                session.frame = frame
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
        if type(call_id) is int:
            session.unanswered.discard(call_id)
        # Only a number we handed out names a call of ours; anything else from the device is not trusted as a key.
        future = session.pending.pop(call_id, None) if type(call_id) is int else None
        given_up = session.given_up.pop(call_id, None) if future is None and type(call_id) is int else None
        if given_up is not None:
            # A press no answer had come for in time, answered after all: it was done, maybe after the letting go sent
            # when the wait was given up (the JetKVM does each call in a task of its own). Let go of again, now in turn.
            self._let_go_of(session, *given_up)
            session.heard.set()
            return
        if future is not None:
            session.heard.set()
            if session.taken and isinstance(call_id, int):
                # Answered after the JetKVM said that somebody else has its viewer (its channel keeps the order of what
                # it says): what the call asked for was done after the hand-over.
                session.after_hand_over.add(call_id)
            if not future.done():
                future.set_result(data)
            return
        method, params = data.get("method"), data.get("params")
        if method == "otherSessionConnected":
            # Someone opened the JetKVM's console. The device is about to drop us; let it,
            # and do not come back until asked.
            if session.taken:
                return  # said already, of this connection: a device can send the message as often as it likes
            current = self._session
            if current is not None and session is not current and not current.done.is_set():
                # A connection of the wall's that is slow to close, told of the wall's own new one, which is being made or
                # has the viewer now: that one is not somebody else's. Nothing more goes over this one (but its letting go,
                # below). (Where the new one is over already, it may be somebody else's page: said as ever.)
                session.taken = True
                self._let_go_at_hand_over(session)
                return
            log.info("%s: in use from another browser", self.label)
            session.taken = self._displaced = True
            self._status = {"state": "busy", "error": IN_USE.as_dict(), "kind": self.kind}
            self._status_at = time.monotonic()
            self._let_go_at_hand_over(session)
        elif method == "videoInputState" and isinstance(params, dict):
            session.video_events += 1
            _video_said(session, params)
        elif method == "usbState" and isinstance(params, str):
            session.usb = params
        elif method == "atxState" and isinstance(params, dict):
            session.atx = params
        elif method == "localVersion" and isinstance(params, dict):
            session.version = plain(params.get("appVersion"), 40)
        elif method == "keysDownState" and isinstance(params, dict) and session.road == "hidrpc":
            # (Where a JetKVM says its keyboard here rather than on hidrpc: the same word, taken the same way.)
            keys = params.get("keys")
            if isinstance(keys, list) and len(keys) <= 16:
                said = tuple(int(number(key, 0, 255) or 0) for key in keys)
                self._echoed(session, (int(number(params.get("modifier"), 0, 255) or 0), tuple(key for key in said if key)))

    def _no_more_asking(self, session: _Session) -> None:
        """The channel the JetKVM is asked over is closed: this connection is to be ended, whatever else still comes over it."""
        if session.ready.is_set() and not session.done.is_set() and session.lost is None:
            session.lost = KvmError("dropped", "The JetKVM closed the channel it is asked over")
        session.heard.set()  # (nothing more is answered over it: whoever waits for answers stops)

    # --- keys and the mouse over hidrpc, the way the JetKVM's own page sends them -------------------------------------
    #
    # The binary `hidrpc` channel (the JetKVM's source, release 0.5.9: hidrpc.go, internal/hidrpc, webrtc.go): one byte
    # says what a message is. 01 v: the handshake, which the JetKVM answers 01 1. 02 m k...: the whole keyboard (modifier
    # bits, up to six keys). 05 k p: one key pressed (p 1) or let go of (p 0), the rest as they are; the JetKVM lets go
    # of such a key, unless it is a modifier, 100 ms after it was pressed or last kept alive. 09: a keep-alive, while a
    # key is held (its page sends one every 50 ms, qKVM every 30; one that comes more than about 100 ms after the last lets
    # go of it for good). 03 x4 y4 b:
    # the absolute pointer (0 to 32767, big-endian) with the buttons. 06 dx dy b: a relative step (signed bytes) with the
    # buttons. From the JetKVM: 33 m k1..k6, the keyboard as it is after each change, to whoever has the viewer. It does
    # the keyboard's messages in order in one queue and the mouse's in order in another, in tasks of their own, and has
    # no wheel there (the wheel goes over JSON-RPC). Nothing is answered: what it ends up with is the last of each kind.

    def _opened(self, session: _Session) -> None:
        """The channel the JetKVM is asked over is open: the connection is up, and which way keys go is found out."""
        session.ready.set()
        session.watchers.append(asyncio.create_task(self._choose_road(session)))

    async def _choose_road(self, session: _Session) -> None:
        """Whether keys and the mouse go over hidrpc on this connection or over JSON-RPC, and then let them go.

        hidrpc where the JetKVM answers the handshake (01 1) within HID_SHAKE_WITHIN of the channel's opening; it is asked
        every HID_SHAKE_EVERY, since one asked while the JetKVM is still setting the channel up goes unheard (its own page
        asks again too). JSON-RPC where it does not answer (an older firmware has no hidrpc) or answers another version:
        keys never go both ways at once. Then what an earlier connection may have left down is let go of
        (`_settle_owed`), and `keys_ready` is set (also where this is cut short: whoever waits then finds it ended). Where
        no answer came, the JetKVM is asked again for a while, and keys change road if it answers (`_late_road`).
        """
        try:
            hid = session.hid
            if hid is not None:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(HID_SHAKE_WITHIN):
                        await session.hid_open.wait()
            # (Counted from the channel's opening: what is waited for is the JetKVM's answer. Counted from before it, a
            # channel slow to open left the answer less than the time.)
            deadline = time.monotonic() + HID_SHAKE_WITHIN
            while hid is not None and hid.readyState == "open" and not session.shaken.is_set() and not session.taken and (left := deadline - time.monotonic()) > 0:
                try:
                    hid.send(bytes([0x01, HID_VERSION]))
                except Exception:  # (closed meanwhile: then keys go over JSON-RPC, or nowhere)
                    break
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(min(HID_SHAKE_EVERY, left)):
                        await session.shaken.wait()
            session.road = "hidrpc" if session.shaken.is_set() else "rpc"
            if session.road == "rpc" and not self._said_no_hid:
                self._said_no_hid = True
                log.info("%s: this JetKVM did not answer qKVM on its hidrpc channel within %g s: keys and the mouse go to it over JSON-RPC until it does", self.label, HID_SHAKE_WITHIN)
            await self._settle_owed(session)
        finally:
            session.keys_ready.set()
        if session.road == "rpc":
            await self._late_road(session)

    async def _late_road(self, session: _Session) -> None:
        """Keys go over JSON-RPC on this connection because the JetKVM did not answer the hidrpc handshake in time. It may
        yet: a wall busy for seconds hears the answer late (a stand-in on a busy computer took up to 1.4 s of the two), and a
        JetKVM still setting the channel up does not hear the first questions. So it is asked again every
        HID_ASK_AGAIN_EVERY, HID_ASKS_AGAIN times, as its own page asks; and where it answers, keys and the mouse go over
        hidrpc from the first moment nothing of ours is down or on its way over JSON-RPC and no action types (`_quiet`):
        a key pressed over the one and let go of over the other could be done in the other order, the JetKVM doing each
        channel in tasks of its own. Never after a hand-over, nor where it answered another version."""
        hid = session.hid
        for _ in range(HID_ASKS_AGAIN):
            if session.shaken.is_set() or session.hid_other or session.taken or not session.live:
                break
            if hid is not None and hid.readyState == "open":
                try:
                    hid.send(bytes([0x01, HID_VERSION]))
                except Exception:  # (closed meanwhile: keys stay on JSON-RPC)
                    return
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(HID_ASK_AGAIN_EVERY):
                    await session.shaken.wait()
        if not session.shaken.is_set():
            return
        while session.live and not session.taken and not session.hid_other and hid is not None and hid.readyState == "open":
            if self._quiet(session):
                session.road = "hidrpc"
                log.info("%s: this JetKVM answered qKVM on its hidrpc channel late: keys and the mouse go to it over hidrpc from now on", self.label)
                return
            await asyncio.sleep(HID_SHAKE_EVERY)

    def _quiet(self, session: _Session) -> bool:
        """Nothing of ours is down on the JetKVM or on its way to it over JSON-RPC on this connection, and no action types:
        the moment at which keys may change road (`_late_road`). Checked and acted on without a wait in between."""
        place = session.abs_sent
        return (
            not self._typing.locked()
            and session.kb_sent == NOTHING_DOWN
            and (place is None or place[2] == 0)
            and session.rel_buttons == 0
            and not session.outbox
            and (session.sending is None or session.sending.done())
            and session.mouse_calls == 0
            and not session.pressing
            and not session.given_up
            and not session.unanswered
        )

    async def _keys_ready(self, session: _Session) -> None:
        """Wait until keys may go over this connection (`_choose_road`). KvmError where they may not, or no longer may."""
        try:
            # (The channel's opening and the handshake's window, each HID_SHAKE_WITHIN at the most, and what was owed:
            # three questions of TAKE_WITHIN each; and one TAKE_WITHIN to spare.)
            async with asyncio.timeout(2 * HID_SHAKE_WITHIN + 4 * TAKE_WITHIN):
                await session.keys_ready.wait()
        except TimeoutError:
            raise KvmError("timeout", "The JetKVM is taking too long to connect", 504) from None
        if session.taken:
            raise IN_USE.with_traceback(None)
        if not session.live or session.road is None:
            raise self._ended(session)

    def _on_hid(self, session: _Session, message: Any) -> None:
        """What the JetKVM says on hidrpc: its answer to the handshake, and the keyboard after each change. Anything else,
        or anything longer than a few bytes, is not read."""
        if not isinstance(message, (bytes, bytearray)) or not 1 <= len(message) <= MOST_HID_MESSAGE:
            return
        kind = message[0]
        if kind == 0x01 and len(message) >= 2:
            if message[1] == HID_VERSION:
                session.shaken.set()
                return
            session.hid_other = True
            if not session.shaken.is_set() and not self._said_no_hid:
                self._said_no_hid = True
                log.info("%s: this JetKVM speaks hidrpc version %d, not %d: keys and the mouse go to it over JSON-RPC", self.label, message[1], HID_VERSION)
        elif kind == 0x33 and len(message) >= 2 and session.road == "hidrpc":
            self._echoed(session, (message[1], tuple(key for key in message[2:8] if key)))

    def _echoed(self, session: _Session, said: tuple[int, tuple[int, ...]]) -> None:
        """The JetKVM says how its keyboard is now: the first keyboard state of ours waiting for that word that is the
        same, and every one before it (it does them in order), are done. A state none waits for is one it made itself
        (letting go of a key no keep-alive came for, or of everything at a hand-over), or of the live line's."""
        heard = (said[0], tuple(sorted(said[1])))  # (the keys as a set: the order a JetKVM keeps them in is its own)
        for index, (state, _) in enumerate(session.echoes_due):
            if (state[0], tuple(sorted(state[1]))) == heard:
                for _ in range(index + 1):
                    _, waiting = session.echoes_due.popleft()
                    if not waiting.done():
                        waiting.set_result(None)
                return

    def _no_more_hid(self, session: _Session) -> None:
        """The hidrpc channel closed: where keys go over it, this connection is to be ended (as when `rpc` closes)."""
        if session.road == "hidrpc" and session.ready.is_set() and not session.done.is_set() and session.lost is None:
            session.lost = KvmError("dropped", "The JetKVM closed the channel keys go over")
        session.heard.set()

    def _hid_send(self, session: _Session, data: bytes) -> None:
        """One message on hidrpc, handed to the connection (it goes in order, and nobody waits for it). Not once the
        connection is no longer up: its channel reads "open" until it is closed, after the connection's last letting go
        (see `_run`), and what went then would be done after it."""
        if not session.live:
            raise self._ended(session)
        hid = session.hid
        if hid is None or hid.readyState != "open":
            self._no_more_hid(session)
            raise KvmError("dropped", "The JetKVM closed the channel keys go over")
        if hid.bufferedAmount > MOST_BUFFERED:
            # Far behind: a JetKVM (or a link) that takes them slower than they are sent. The connection is ended, and
            # with it what waits; the JetKVM lets go of the keyboard as it ends, and a new one is made for whoever asks.
            self._make_anew(session, "it was not keeping up with keys and the mouse")
            raise KvmError("dropped", "The connection to the JetKVM ended: it was not keeping up with keys and the mouse")
        try:
            hid.send(data)
        except Exception:  # (the library's word for a channel that closed meanwhile)
            self._no_more_hid(session)
            raise KvmError("dropped", "The JetKVM closed the channel keys go over") from None

    def _hid_report(self, session: _Session, method: str, params: dict[str, Any]) -> None:
        """A report of the live line's (the keyboard's whole state, the pointer's place or a step, with the buttons) as the
        hidrpc messages that say it."""
        if method == "keyboardReport":
            keys = tuple(int(number(key, 1, 255) or 0) for key in params.get("keys") or ())
            self._hid_keyboard(session, (int(number(params.get("modifier"), 0, 255) or 0), tuple(key for key in keys if key)[:6]))
            return
        buttons = int(number(params.get("buttons"), 0, 255) or 0)
        # (Said before it goes, as all that was and is down: one that could not go may have gone.)
        if method == "absMouseReport":
            x, y = int(number(params.get("x"), 0, 32767) or 0), int(number(params.get("y"), 0, 32767) or 0)
            before = session.abs_sent[2] if session.abs_sent is not None else 0
            session.abs_sent = (x, y, before | buttons)
            self._leftover.place = (x, y)
            self._hid_send(session, b"\x03" + struct.pack(">iiB", x, y, buttons))
            session.abs_sent = (x, y, buttons)
        elif method == "relMouseReport":
            dx, dy = int(number(params.get("dx"), -MOST_STEP, MOST_STEP) or 0), int(number(params.get("dy"), -MOST_STEP, MOST_STEP) or 0)
            session.rel_buttons |= buttons
            self._hid_send(session, struct.pack(">BbbB", 0x06, dx, dy, buttons))
            session.rel_buttons = buttons
        else:
            raise KvmError("invalid", f"A JetKVM takes no {method} over hidrpc", 422)

    @staticmethod
    def _other_mouse(session: _Session, method: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        """Where a mouse report lets go of a button the JetKVM's other mouse holds (a drag begun by steps and ended by a
        place, or the other way round: the two are two devices to the computer), that mouse's report letting go of it
        too; None where there is none to send."""
        buttons = int(number(params.get("buttons"), 0, 255) or 0)
        rel_buttons, place = session.rel_buttons, session.abs_sent
        for kind, said, _ in session.outbox:  # (over JSON-RPC, what waits to go says it first: the newest of each kind)
            if kind == "relMouseReport":
                rel_buttons = int(number(said.get("buttons"), 0, 255) or 0)
            elif kind == "absMouseReport":
                place = (int(number(said.get("x"), 0, 32767) or 0), int(number(said.get("y"), 0, 32767) or 0), int(number(said.get("buttons"), 0, 255) or 0))
        if method == "absMouseReport" and rel_buttons & ~buttons:
            return "relMouseReport", {"dx": 0, "dy": 0, "buttons": rel_buttons & buttons}
        if method == "relMouseReport" and place is not None and place[2] & ~buttons:
            return "absMouseReport", {"x": place[0], "y": place[1], "buttons": place[2] & buttons}
        return None

    def _hid_keyboard(self, session: _Session, new: tuple[int, tuple[int, ...]]) -> None:
        """The keyboard as the live line has it now, said as the JetKVM's own page says it: a keypress message for each
        key that changed (those let go of first, then the modifiers, then those pressed), kept alive while a key that is
        no modifier is down; a whole report with nothing down where nothing is."""
        old = session.kb_sent
        if new == old:
            return
        modifier, keys = new
        # (Said before they go, as all that was and is down: a message that could not go may have gone.)
        session.kb_sent = (old[0] | modifier, tuple(dict.fromkeys(old[1] + keys)))
        if not modifier and not keys:
            self._hid_send(session, b"\x02\x00")
            session.held.clear()
        else:
            for key in old[1]:
                if key not in keys:
                    self._hid_send(session, bytes([0x05, key, 0]))
                    session.held.discard(key)
            for bit in range(8):
                if (old[0] ^ modifier) & (1 << bit):
                    self._hid_send(session, bytes([0x05, 0xE0 + bit, 1 if modifier & (1 << bit) else 0]))
            for key in keys:
                if key not in old[1]:
                    self._hid_send(session, bytes([0x05, key, 1]))
                    session.held.add(key)
        session.kb_sent = new
        if session.held and (session.keeping is None or session.keeping.done()):
            session.keeping = asyncio.create_task(self._keep_alive(session))

    async def _keep_alive(self, session: _Session) -> None:
        """A keep-alive every KEEP_ALIVE_EVERY while a key pressed by a keypress message is down, as the JetKVM's own page
        sends them (a little more often). Never after the hand-over: it would keep alive the keys of whoever took the
        viewer."""
        due = time.monotonic() + KEEP_ALIVE_EVERY
        while True:
            await asyncio.sleep(max(0.0, due - time.monotonic()))
            hid = session.hid
            if not session.held or session.taken or not session.live or hid is None or hid.readyState != "open":
                return  # (once the connection is ending, the JetKVM lets go of the key itself within a tenth of a second)
            try:
                hid.send(b"\x09")
            except Exception:
                return
            due += KEEP_ALIVE_EVERY
            if due < time.monotonic():  # (late, the loop having been busy: the next one a whole step from now, not at once)
                due = time.monotonic() + KEEP_ALIVE_EVERY

    def _hid_whole(self, session: _Session, state: tuple[int, tuple[int, ...]]) -> asyncio.Future[None]:
        """The whole keyboard said over hidrpc, for an action that types: a future that is done once the JetKVM says it
        has it (its `33`), failed with `in_use` where its own page takes the viewer first, with the cut-off where the
        connection ends first."""
        if not session.live:
            raise self._ended(session)
        waiting: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        waiting.add_done_callback(_retrieved)
        session.echoes_due.append((state, waiting))
        session.kb_sent = (session.kb_sent[0] | state[0], tuple(dict.fromkeys(session.kb_sent[1] + state[1])))
        try:
            self._hid_send(session, bytes([0x02, state[0], *state[1]]))
        except KvmError:
            session.echoes_due.remove((state, waiting))
            raise
        session.kb_sent = state
        session.held.clear()  # (a whole report: nothing pressed by a keypress message is down any more, nor kept alive)
        return waiting

    async def _type_over_hid(self, session: _Session, reports: list[tuple[int, list[int]]], action: str, still: Callable[[], bool] | None) -> None:
        """Type over hidrpc: per key, a whole report pressing it, the JetKVM's word that it has it (one round trip), a
        pause, a whole report letting go of it (not waited for: the JetKVM does it after the press). So one key is on its
        way at most, as on JSON-RPC, and a text stops where the JetKVM's own page takes the viewer: nothing more of it goes
        (the letting go sent at the hand-over, see `_let_go_at_hand_over`, is done after the key on its way)."""
        released: asyncio.Future[None] | None = None
        count = len(reports)
        for typed, (modifier, codes) in enumerate(reports):
            self._wanted_at = time.monotonic()
            if typed and typed % ASK_EVERY == 0 and still is not None and not still():
                raise KvmError("stopped", f"Typing was stopped after {typed} of {count} keys: whoever asked for it may no longer do that", 403)
            if session.taken:
                raise _taken_while(typed, count)
            if self._closed or not session.live:
                # The wall ends the connection, or it has ended: nothing more goes (what was down was let go of as it
                # ended, see `close` and `_run`).
                raise _ended_while(typed, count, self._ended(session))
            try:
                pressed = self._hid_whole(session, (modifier, tuple(codes)))
            except KvmError as ex:
                # Not sent (the channel shut, or the JetKVM far behind): nothing of this key went. The letting go of the
                # key before it may not have gone either, where the channel shut: let go of (over the other, where it did).
                self._send_let_go(session)
                raise _ended_while(typed, count, ex) from None
            try:
                # (Waited for, never cancelled along with whoever waits: its failure, coming later, is taken by itself.)
                done, _ = await asyncio.wait({pressed}, timeout=RPC_TIMEOUT)
                if not done:
                    raise TimeoutError
                pressed.result()  # (the JetKVM's own page took the viewer first, or the connection ended: raised here)
                await asyncio.sleep(KEY_PAUSE if action == "text" else HOLD)
            except KvmError as ex:
                if ex.code == "in_use":
                    # Its own page took the viewer before the JetKVM said it had this press: it may have been done (after
                    # the hand-over, where the letting go sent at the hand-over, behind it, let go of it).
                    if typed + 1 == count:
                        raise KvmError("timeout", "The JetKVM's own page took it before it said the last key was pressed: it may have been done", 504) from None
                    raise KvmError("in_use", f"Typing was stopped at key {typed + 1} of {count}, which may have been pressed: {IN_USE.message}", 409) from None
                raise  # (the connection ended under it: the JetKVM lets go of the keyboard as it ends)
            except TimeoutError:
                # No word that it has the press: unknown. Let go of, in turn behind it, and the connection ended: what
                # comes after it could be done before it or not at all.
                self._send_let_go(session)
                self._make_anew(session, "a key it was sent was not said done in time")
                raise KvmError("timeout", "The JetKVM did not answer in time", 504) from None
            except BaseException:
                # Whoever asked went away (the pause included): the key may be down. Let go of, in turn, unanswered.
                if not session.taken:
                    self._send_let_go(session)
                raise
            if session.taken:
                # Its own page has the viewer now; the JetKVM let go of this key as it handed it over (and the letting go
                # sent then followed). Nothing more goes.
                if typed + 1 == count:
                    break  # (it was the last: what was asked for was done, all of it)
                raise _taken_while(typed + 1, count)
            if self._closed or not session.live:
                # The JetKVM had this key, and the connection is ending: let go of now, behind it (the end's own letting
                # go comes only once the connection is looked at, up to a second later, and a key held that long
                # repeats), and nothing more goes. (Where the wall closes it, it has let go already: nothing is sent.)
                self._send_let_go(session)
                if typed + 1 == count:
                    break  # (it was the last: what was asked for was done, all of it)
                raise _ended_while(typed + 1, count, self._ended(session))
            try:
                released = self._hid_whole(session, NOTHING_DOWN)
            except KvmError as ex:
                self._send_let_go(session)  # (over the other channel, where this one shut: the JetKVM had the key)
                if typed + 1 == count:
                    break
                raise _ended_while(typed + 1, count, ex) from None
            await asyncio.sleep(KEY_PAUSE)
        if released is not None:
            # (The last letting go heard of, so that "done" is done; whatever became of it, the key was typed.)
            await asyncio.wait({released}, timeout=RPC_TIMEOUT)

    def _send_let_go(self, session: _Session, keyboard: bool = True) -> Any:
        """Let go of what the wall has down over this connection, the last it said of the keyboard (`keyboard`) and of
        the mouse buttons, at once and not waited for; the channel it went over, or None where nothing went (nothing was
        down, as said last: so it goes once, however often it is asked for). Over hidrpc it is done after everything of
        ours before it (each kind in order). Over JSON-RPC only the buttons: the JetKVM lets go of the keyboard itself as
        the connection ends and at a hand-over, and a release sent now could be done before a press still in its hands
        (they are done in tasks of their own). Each of the two mice that has a button down is let go of: to the computer
        they are two devices, with buttons of their own. Where the hidrpc channel has shut and the other has not, the
        buttons and the keyboard go over the other."""
        kb_down = keyboard and session.kb_sent != NOTHING_DOWN
        place = session.abs_sent
        abs_down = place is not None and place[2] != 0
        rel_down = session.rel_buttons != 0
        if not kb_down and not abs_down and not rel_down:
            return None
        if not session.taken:
            session.had_down = True
            if session.done.is_set():
                self._leftover.down = True  # (the connection's end has looked already: owed to the next one from here)
        hid = session.hid
        if session.road == "hidrpc" and hid is not None and hid.readyState == "open":
            channel = hid
            try:
                if kb_down:
                    channel.send(b"\x02\x00")
                if abs_down and place is not None:
                    channel.send(b"\x03" + struct.pack(">iiB", place[0], place[1], 0))
                if rel_down:
                    channel.send(b"\x06\x00\x00\x00")
            except Exception:  # (closed meanwhile: what the JetKVM keeps is let go of on the next connection, first)
                return None
            session.held.clear()
            if kb_down:
                session.kb_sent = NOTHING_DOWN
        else:
            # (Also where the hidrpc channel shut under a connection whose other channel is still open: the buttons, which
            # the JetKVM keeps, over that one, and the keyboard, which it lets go of only once the connection ends, a
            # second and more later: what went over hidrpc it has done or never will.)
            channel = session.rpc
            kb_too = kb_down and session.road == "hidrpc"
            if not (abs_down or rel_down or kb_too) or channel is None or channel.readyState != "open":
                return None
            if kb_too:
                session.held.clear()
                self._let_go_of(session, "keyboardReport", {})
            if abs_down and place is not None:
                self._let_go_of(session, "absMouseReport", {"x": place[0], "y": place[1]})
            if rel_down:
                self._let_go_of(session, "relMouseReport", {})
        if abs_down and place is not None:
            session.abs_sent = (place[0], place[1], 0)
        if rel_down:
            session.rel_buttons = 0
        return channel

    async def _let_go_before_closing(self, session: _Session, wait: bool) -> None:
        """Before the wall ends a connection itself: let go of what it has down (`_send_let_go`), and (`wait`) give that
        LET_GO_WAIT to leave and LET_GO_SETTLE to be done. Not after a hand-over: nothing more of ours goes there."""
        if session.taken or session.done.is_set():
            return
        channel = self._send_let_go(session)
        if channel is None and session.had_down and session.road == "hidrpc":
            channel = session.hid  # (let go of already, by an action that stopped: given the same time to leave)
        if not wait or channel is None:
            return
        await _drained(channel, LET_GO_WAIT)
        await asyncio.sleep(LET_GO_SETTLE)

    def _let_go_at_hand_over(self, session: _Session) -> None:
        """The JetKVM said its own page took the viewer. It lets go of the keyboard as it hands the viewer over, never of a
        mouse button (seen on a real one). So: over hidrpc, where the wall cannot tell whether its last messages were done
        before the hand-over or after (nothing is answered, and the word comes over the other channel), one letting go
        of the keyboard where the last it said had something down, and of the buttons where they were down, at once
        and behind everything of ours (done after it). Over JSON-RPC, the buttons, where they were down and no mouse
        report of ours is in its hands (one that is lets go as its answer comes, see `_call`). Nothing else, ever."""
        session.held.clear()  # (no keep-alive goes any more: it would keep alive the keys of whoever took the viewer)
        if session.road == "hidrpc":
            self._send_let_go(session)
            for _, waiting in session.echoes_due:
                if not waiting.done():
                    waiting.set_exception(KvmError("in_use", IN_USE.message, 409))
            session.echoes_due.clear()
        elif session.mouse_calls == 0:
            self._send_let_go(session, keyboard=False)

    async def _settle_owed(self, session: _Session) -> None:
        """Where a connection of the wall's to this JetKVM ended with something of ours down, or maybe down (a key whose
        press was done after its end, a mouse button, which a JetKVM never lets go of by itself): "nothing down" first,
        before any key or action goes over this one. The keyboard, the relative mouse, and the absolute mouse where the
        wall knows where it was last put (it is put there again)."""
        leftover = self._leftover
        if not leftover.down or session.taken:
            return
        leftover.down = False
        place = leftover.place
        try:
            if session.road == "hidrpc":
                self._hid_send(session, b"\x02\x00")
                self._hid_send(session, b"\x06\x00\x00\x00")
                if place is not None:
                    self._hid_send(session, b"\x03" + struct.pack(">iiB", *place, 0))
            else:
                await self._call(session, "keyboardReport", {"modifier": 0, "keys": []}, within=TAKE_WITHIN)
                await self._call(session, "relMouseReport", {"dx": 0, "dy": 0, "buttons": 0}, within=TAKE_WITHIN)
                if place is not None:
                    await self._call(session, "absMouseReport", {"x": place[0], "y": place[1], "buttons": 0}, within=TAKE_WITHIN)
        except KvmError:
            leftover.down = True  # (said again on the next connection)
            return
        except BaseException:
            leftover.down = True  # (stopped meanwhile, the connection ending: said on the next one all the same)
            raise
        log.info("%s: what an earlier connection may have left down was let go of", self.label)

    async def _call(self, session: _Session, method: str, params: dict[str, Any] | None = None, within: float | None = None) -> Any:
        """Ask the JetKVM, and wait for its answer (RPC_TIMEOUT, or `within`).

        Where the call presses keys or mouse buttons, and somebody else may have the JetKVM's viewer by the time it is
        done, this is where it is let go of again. The JetKVM lets go of everything as it hands its viewer over; what it
        does after that stays down for whoever has it then. So:

        * answered before the JetKVM said that somebody else has its viewer: done before the hand-over, and let go of
          by the JetKVM in it. Nothing more is sent;
        * answered after that (its channel keeps the order of what it says): done after the hand-over. Let go of at
          once, by one report that is not waited for;
        * not answered (no answer in time, cut off, or whoever waited went away): unknown. Let go of the same way,
          while the connection is open, before anything ends it (and `_run` does it for a call cut off by its end).

        Nothing else of ours goes to a JetKVM after the hand-over (see `act` and `_say_in_turn`).
        """
        if not session.live:
            raise KvmError("dropped", "The JetKVM closed the connection")
        if session.taken:
            # (Its own page has the viewer: nothing more of ours goes to it. The letting go of what may have been pressed
            # after the hand-over does not come through here.)
            raise IN_USE.with_traceback(None)
        session.next_id += 1
        call_id = session.next_id
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        session.pending[call_id] = future
        answered = False
        mouse = method in ("absMouseReport", "relMouseReport")
        try:
            try:
                session.rpc.send(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": call_id}))
            except Exception:  # (the library's word for a channel that is closed; whichever it is, the question did not go out)
                # Sent before the wait was guarded, this was an error of the library's own kind: the question
                # stayed among the waiting ones for good, three more at every look, the JetKVM was "online"
                # with nobody to ask, and a key pressed on the page was an error inside the program.
                mouse = False
                self._no_more_asking(session)
                raise KvmError("dropped", "The JetKVM closed the channel it is asked over") from None
            self._said(session, method, params)
            if method in ("keyboardReport", "absMouseReport", "relMouseReport", "wheelReport"):
                session.unanswered.add(call_id)  # (until its answer comes, however long after its wait: see `_quiet`)
            if mouse:
                session.mouse_calls += 1
            if params and _presses(method, params):
                session.pressing[call_id] = (method, params)
            # (Not wait_for, which up to Python 3.11 loses a stop that comes with the answer: a text being typed
            # went on with the next key, and the rest. See Listening.message.)
            async with asyncio.timeout(RPC_TIMEOUT if within is None else within):
                reply = await future
            answered = True
        except TimeoutError:
            raise KvmError("timeout", "The JetKVM did not answer in time", 504) from None
        finally:
            # (Popped by `_on_message` already: its answer came, in the same turn of the loop as its own wait ran out.)
            heard_back = session.pending.pop(call_id, None) is None
            pressed = session.pressing.pop(call_id, None)
            late = call_id in session.after_hand_over
            session.after_hand_over.discard(call_id)
            if pressed is not None and (late or not answered):
                self._let_go_of(session, *pressed)
            if pressed is not None and not answered and not heard_back and not session.done.is_set():
                session.given_up[call_id] = pressed
                while len(session.given_up) > MOST_GIVEN_UP:
                    del session.given_up[next(iter(session.given_up))]
            if mouse:
                session.mouse_calls -= 1
                if session.taken and session.mouse_calls == 0:
                    # The last mouse report of ours the JetKVM had in its hands at the hand-over is through: a button it
                    # left down stays down for whoever took the viewer (a JetKVM keeps buttons across a hand-over).
                    self._send_let_go(session, keyboard=False)
            session.heard.set()
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
        return {"can": can_do(*self.can), **(known or {"state": state, "error": None, "kind": self.kind}), "last_seen_ago": seen}

    # --- snapshots ----------------------------------------------------------

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
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
        no_signal = session.ready_said is False
        if no_signal and (frame is None or time.monotonic() - session.frame_at > FRAME_STALE):
            return Snapshot(_BLANK, "image/png", False, time.monotonic())
        if frame is None:
            raise KvmError("no_stream", "Waiting for the first picture", 503)
        if not no_signal and (time.monotonic() - session.frame_at > FRAME_STALE or session.signal_at > session.frame_at):
            # What is in hand is not the screen any more: too old, or from before the JetKVM said its screen was back.
            raise KvmError("no_stream", "Waiting for the JetKVM's video", 503)
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
            # (Which keys type it is known once connected: the JetKVM says which layout its computer uses.)
        elif action == "wol":
            if not MAC.fullmatch(mac):
                raise KvmError("invalid", "Not a valid MAC address", 422)
        elif action not in ("reboot", "jiggler_on", "jiggler_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A JetKVM cannot do that", 422)

        session = await self._connected(urgent=True)
        why = "the JetKVM did not say which keyboard layout its computer uses"
        try:
            if action == "text":
                reports = text_reports(text, await self._layout(session))  # (nothing typed where one character cannot be)
            why = "the connection to the JetKVM was not ready for keys"
            if reports:
                await self._keys_ready(session)  # (which way keys go over this connection, and what was owed sent first)
        except KvmError as ex:
            if ex.code in ("invalid", "in_use"):
                raise
            if session.taken:
                raise _taken_while(0, len(reports) or 1) from None
            # Only asked, so far, or only waited: nothing was pressed, whatever became of the question. (Said in words of
            # its own: the cut-off's "it may have been done" is of the question, not of the keys.)
            log.info("%s: %s was not done: %s (%s)", self.label, action, why, ex.code)
            cause = "" if ex.message.endswith("may have been done") else f" ({ex.message})"
            raise KvmError("action_failed", f"{'Nothing was typed' if action == 'text' else 'It was not done'}: {why}{cause}") from None
        # Connecting to a JetKVM takes seconds, a quarter of a minute at most: asked now, before anything is
        # pressed, whether whoever wanted it may still have it.
        if still is not None and not still():
            raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
        if reports and session.sending is not None and not session.sending.done():
            # What a live line said last (the keys it had down, let go of as it gave the keyboard back) goes first:
            # done by the JetKVM in among these, it would land in the text, or let go of a key held for a combination.
            await asyncio.wait({session.sending}, timeout=TAKE_WITHIN)
            if not session.sending.done():
                raise KvmError("busy", "Keys from the live view are still on their way to this JetKVM. Try again in a moment.", 409)
            if still is not None and not still():  # (asked again after the wait)
                raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
        if reports:
            async with self._typing:  # two people typing at once would interleave
                # (The road read once its turn has come: keys do not change road while an action types, see `_quiet`.)
                if session.road == "hidrpc":
                    await self._type_over_hid(session, reports, action, still)
                    return
                for typed, (modifier, codes) in enumerate(reports):
                    # A long text takes a minute and more. All that while the connection is in use, whoever
                    # looks or does not: left to count as idle, it was closed in the middle of the text.
                    self._wanted_at = time.monotonic()
                    # And all that while it is this program that presses the keys. Now and then, between two
                    # keys, with none of them down: may whoever asked for this still have it done?
                    if typed and typed % ASK_EVERY == 0 and still is not None and not still():
                        raise KvmError("stopped", f"Typing was stopped after {typed} of {len(reports)} keys: whoever asked for it may no longer do that", 403)
                    if session.taken:
                        # Somebody opened its own page: the rest would be typed at their keyboard.
                        raise _taken_while(typed, len(reports))
                    answered = let_go = False
                    try:
                        # (Where the JetKVM does this press after handing its viewer over, `_call` lets go of it.)
                        await self._call(session, "keyboardReport", {"modifier": modifier, "keys": codes})
                        answered = True
                        await asyncio.sleep(KEY_PAUSE if action == "text" else HOLD)
                        if session.taken:
                            # Its own page has the viewer now. This key was let go of: by the JetKVM as it handed the
                            # viewer over, where it was done before that; by `_call`, where it was done after. A release
                            # sent now would land on whoever is at that page: nothing more goes.
                            let_go = True
                            if typed + 1 == len(reports):
                                break  # (it was the last: what was asked for was done, all of it)
                            raise _taken_while(typed + 1, len(reports))
                        let_go = True
                        await self._call(session, "keyboardReport", {"modifier": 0, "keys": []})  # nothing releases by itself
                    except BaseException:
                        # The key may be down and nothing has said that it was let go: a key held down repeats on
                        # the machine for as long as nobody says otherwise.
                        if answered and not let_go:
                            self._let_go(session)  # (whoever asked went away during the pause: said once, unanswered)
                        elif not answered:
                            # The press was not answered: it may still be done, later. Where it went out and no answer
                            # came, `_call` has let go of it, while the connection was open; and as that release could be
                            # done before the press (the JetKVM does each call in a task of its own), the connection is
                            # ended too: the JetKVM lets go of every key of the viewer it has when a connection of that
                            # viewer ends. (Refused by the JetKVM, or never sent, it pressed nothing: ended all the same.)
                            self._make_anew(session, "a key it was sent was not answered in time")
                        raise
                    await asyncio.sleep(KEY_PAUSE)
        elif action == "wol":
            await self._call(session, "sendWOLMagicPacket", {"macAddress": mac})
        elif action in ("jiggler_on", "jiggler_off"):
            await self._call(session, "setJigglerState", {"enabled": action == "jiggler_on"})
        elif action.startswith("atx_"):
            try:
                extension = await self._call(session, "getActiveExtension")
            except KvmError as ex:
                # Only asked, so far: nothing was pressed, whatever became of the question (only a cut-off press may
                # say "may have been done").
                if session.taken or ex.code == "in_use":
                    raise IN_USE.with_traceback(None) from None
                if ex.code == "action_failed":
                    raise  # (its own refusal, in its own words)
                raise KvmError("action_failed", "Nothing was pressed: qKVM was not told whether the JetKVM's power extension is on") from None
            if extension != "atx-power":
                raise KvmError("action_failed", "This JetKVM has no ATX power extension switched on")
            press = {"atx_power": "power-short", "atx_power_long": "power-long", "atx_reset": "reset"}[action]
            if session.taken:  # (its own page took the viewer while the extension was asked about: not pressed)
                raise IN_USE.with_traceback(None)
            await self._call(session, "setATXPowerAction", {"action": press})
        elif action == "reboot":
            try:
                await self._call(session, "reboot", {"force": True})
            except KvmError as ex:
                if ex.code not in ("dropped", "timeout"):  # it may be gone before it can answer
                    raise

    def _let_go_of(self, session: _Session, method: str, params: dict[str, Any]) -> None:
        """Say, without waiting for an answer, that nothing is down any more of what this report pressed: the keyboard
        for a keyboard report, the buttons for a mouse report (where the pointer is). See `_call`."""
        if method == "keyboardReport":
            nothing: dict[str, Any] = {"modifier": 0, "keys": []}
        elif method == "absMouseReport":
            nothing = {"x": params.get("x", 0), "y": params.get("y", 0), "buttons": 0}
        else:
            nothing = {"dx": 0, "dy": 0, "buttons": 0}
        try:
            if session.rpc is not None and session.rpc.readyState == "open":
                session.next_id += 1
                session.rpc.send(json.dumps({"jsonrpc": "2.0", "method": method, "params": nothing, "id": session.next_id}))
                session.unanswered.add(session.next_id)
                self._said(session, method, nothing)
        except Exception:  # the connection is gone, and with it, where it was the JetKVM's viewer, what it held down
            pass

    def _said(self, session: _Session, method: str, params: dict[str, Any] | None) -> None:
        """Note what a report sent over JSON-RPC says of the keyboard or the mouse (see `_Session.kb_sent`)."""
        params = params or {}
        if method == "keyboardReport":
            keys = params.get("keys")
            session.kb_sent = (int(number(params.get("modifier"), 0, 255) or 0), tuple(key for key in keys if type(key) is int and key) if isinstance(keys, list) else ())
        elif method == "absMouseReport":
            x, y = int(number(params.get("x"), 0, 32767) or 0), int(number(params.get("y"), 0, 32767) or 0)
            session.abs_sent = (x, y, int(number(params.get("buttons"), 0, 255) or 0))
            self._leftover.place = (x, y)
        elif method == "relMouseReport":
            session.rel_buttons = int(number(params.get("buttons"), 0, 255) or 0)

    def _let_go(self, session: _Session) -> None:
        """Tell the JetKVM that no key is down, without waiting to hear that it took note."""
        try:
            # (Taken over: the JetKVM let go of everything as it handed the viewer over, and what is sent now would land on
            # whoever took it.)
            if session.live and not session.taken:
                session.next_id += 1
                session.rpc.send(json.dumps({"jsonrpc": "2.0", "method": "keyboardReport", "params": {"modifier": 0, "keys": []}, "id": session.next_id}))
                session.unanswered.add(session.next_id)
                session.kb_sent = NOTHING_DOWN
        except Exception:  # the connection is gone, and with it what the JetKVM held down
            pass

    # --- the live line (see live.py) ------------------------------------------

    async def live_frame(self) -> tuple[Any, float]:
        """The newest decoded frame and when it came (None and 0 while there is none yet), for the live line; connects first.

        KvmError where no picture is to be had: somebody else has the JetKVM's one viewer, it refuses, it is down.
        """
        self._wanted_at = time.monotonic()
        session = await self._connected()
        if self.picture_awaited():
            return None, 0.0  # (a picture from before the JetKVM said its screen was back: not the screen)
        return session.frame, session.frame_at

    def picture_awaited(self) -> bool:
        """Whether the JetKVM has said its screen is back since the last picture of it: what is in hand is from before."""
        session = self._session
        return session is not None and session.signal_at > session.frame_at

    async def input_ready(self) -> object:
        """Keys and the mouse can be sent: the connection is up, or is made now. KvmError where none is to be had.

        What comes back stands for that connection, for `say`: keys pressed over one connection are let go of by the
        JetKVM when it ends, and whoever held them then holds nothing on the next one. Returned once it is known which
        way keys go over it (`_choose_road`).
        """
        self._wanted_at = time.monotonic()
        session = await self._connected(urgent=True)
        await self._keys_ready(session)
        return session

    def say(self, method: str, params: dict[str, Any], fold: bool = False, on: object = None) -> None:
        """A key or the pointer, for the live line: sent after everything said before it, without the caller waiting.

        Over hidrpc (where the JetKVM speaks it, see `_choose_road`) each goes at once, as its own page sends it: the
        JetKVM does the keyboard's messages in order and the mouse's in order (`_hid_report`). The wheel, which it has
        not got there, and everything over JSON-RPC go as follows.

        A JetKVM does every call on its JSON-RPC channel in a task of its own, so two calls that arrive together are
        done in either order. Sent as they came, keys and buttons came out of order on a real one: the alphabet typed as
        "abdcegfhjikmlnpoqsrtvuwyxz", a key let go of before it was pressed (and so held, and repeated by the
        computer), a right button down until the line gave the keyboard back. So each goes once the JetKVM has
        answered the one before (a few milliseconds on a local network), in a task of the connection's
        (`_say_in_turn`). That is one report per round trip: over a slow link they wait.

        `fold`: a move of the pointer or a turn of the wheel and nothing else, which may be folded into one of its kind
        that waits (see `_fold_into`). A report of a whole state (the keyboard; a place with the buttons; the buttons
        alone) that says what the last one of its kind that waits says is not sent again (`_same_as_last`).

        `on`: the connection the keyboard and mouse were taken on (`input_ready`); where that one has ended, so has
        this holding of them, even if a new one is up by now.

        KvmError where there is no live connection, it is not the one they were taken on, somebody else has the
        JetKVM's one viewer, or more wait than a JetKVM that takes them lets pile up (the connection is then ended,
        what waits is lost, and the JetKVM lets go of every key).
        """
        session = self._session
        held = on if isinstance(on, _Session) else session
        if session is None or not session.live or (on is not None and on is not session):
            why = None if held is None else held.anew or (held.lost.message if held.lost is not None else None)
            raise KvmError("dropped", f"The connection to the JetKVM ended{': ' + why if why else ''}")
        if session.taken:
            # Its own page has the viewer, and these would land on the keyboard of whoever is at that page.
            raise IN_USE.with_traceback(None)
        if session.road is None:
            raise KvmError("dropped", "The connection to the JetKVM is not ready for keys yet")
        self._wanted_at = time.monotonic()
        # (A drag begun on one of the JetKVM's two mice and ended on the other: the button is let go of on both.)
        other = self._other_mouse(session, method, params) if method in ("absMouseReport", "relMouseReport") else None
        if session.road == "hidrpc" and method != "wheelReport":
            self._hid_report(session, method, params)
            if other is not None:
                self._hid_report(session, *other)
            return
        self._queue(session, method, params, fold)
        if other is not None:
            self._queue(session, *other, False)
        if session.sending is None or session.sending.done():
            session.sending = asyncio.create_task(self._say_in_turn(session))

    def _queue(self, session: _Session, method: str, params: dict[str, Any], fold: bool) -> None:
        """A report for the live line put among those that wait to go over JSON-RPC (see `say`)."""
        waiting = session.outbox
        if fold and _fold_into(waiting, method, params):
            pass
        elif _same_as_last(waiting, method, params):
            pass  # (a whole state, as it will be already when the last of its kind that waits is done: it adds nothing)
        elif len(waiting) >= MOST_WAITING:
            # Far behind: a JetKVM that answers slower than it is sent to. The connection is ended, and with it what
            # waits (it is lost); the JetKVM lets go of every key when it ends, and a new one is made for whoever asks
            # next. (Letting go of everything asks for nothing else.)
            self._make_anew(session, "it was not keeping up with keys and the mouse")
            raise KvmError("dropped", "The connection to the JetKVM ended: it was not keeping up with keys and the mouse")
        else:
            waiting.append((method, params, fold))

    async def _say_in_turn(self, session: _Session) -> None:
        """Send what waits for the live line, one at a time, each once the one before it was answered."""
        while session.outbox and session.live:
            if session.taken:
                session.outbox.clear()  # (its own page has it now: nothing more goes to whoever is there)
                return
            method, params, _ = session.outbox.popleft()
            try:
                await self._call(session, method, params, within=TAKE_WITHIN)
            except KvmError as ex:
                if ex.code in ("timeout", "dropped"):
                    # Not answered in time, or the channel is gone. Its answer may still come, and what it said be done
                    # late: what waits is not sent after it, out of turn. The connection is ended instead: a JetKVM lets
                    # go of every key when a connection ends (at once, on a real one), and whoever sends next is told.
                    session.outbox.clear()
                    if ex.code == "timeout":
                        self._make_anew(session, "it stopped answering keys and the mouse")
                    return
                # Refused, this one (a JetKVM that will not take a report it was sent): the next goes all the same.
                if not session.refused_said:
                    session.refused_said = True
                    log.info("%s: the JetKVM refused a %s (%s); the reports after it go all the same", self.label, method, ex.message)

    def _make_anew(self, session: _Session, why: str) -> None:
        """End this connection to make a new one, where keys sent over it may be done late and out of turn.

        A JetKVM lets go of every key when a connection ends (at once, on a real one). Not counted as the JetKVM being
        down: it is there. What waits to be sent over it is lost.
        """
        if session.anew is None and not session.done.is_set():
            session.anew = why
            session.outbox.clear()

    async def all_said(self) -> None:
        """Wait until what was said for the live line has gone and been answered, or given up on (TAKE_WITHIN each);
        over hidrpc, where nothing is answered, until it has left (TAKE_WITHIN at the most)."""
        session = self._session
        if session is not None and session.road == "hidrpc":
            await _drained(session.hid, TAKE_WITHIN)
        sending = None if session is None else session.sending
        if sending is not None and not sending.done():
            await asyncio.wait({sending})  # (not cancelled along with whoever waits: it goes on by itself)

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

    async def _read_status(self, again: bool = True) -> dict[str, Any]:
        """How the JetKVM is. `again`: where the wall itself makes the connection anew under the questions, they may be
        asked once more over the new one (see below)."""
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

        events = session.video_events  # (what the JetKVM says of its screen in an event meanwhile is newer than the answer)
        answers: tuple[Any, ...] = await asyncio.gather(
            self._call(session, "getVideoState"),
            self._call(session, "getUSBState"),
            self._call(session, "getActiveExtension"),
            self._version(session),
            return_exceptions=True,
        )
        if session.taken or any(isinstance(answer, KvmError) and answer.code == "in_use" for answer in answers):
            return {"state": "busy", "error": IN_USE.as_dict(), "kind": self.kind}  # (its own page took it meanwhile)
        video, usb, extension, version = answers  # each is what the JetKVM said, or the error asking it ended in
        if video is RETIRED:
            # Cut off as this client was closed (the tile edited or removed, the wall locking itself or stopping): nothing
            # was heard of the JetKVM, and nothing is said of it.
            return {"state": "connecting", "error": RETIRED.as_dict(), "kind": self.kind}
        if session.anew is not None and any(isinstance(answer, KvmError) and answer.code in ("timeout", "dropped") for answer in answers):
            # Cut off by the wall's own making the connection anew (keys it was late with, say): nothing was heard of the
            # JetKVM either way. (Said "offline", the tile, the history and the live line took the wall's own doing for
            # the JetKVM going away: a busy computer met it.) Asked again over the new connection, once; but not by a
            # look for the alerts, which makes no connection (it would take the JetKVM's one viewer), nor on a client being
            # retired: there what was known stands, or "connecting" where nothing was.
            if again and not self._looking_on and not self._closed:
                return await self._read_status(again=False)
            return self._status or {"state": "connecting", "error": RETIRED.as_dict(), "kind": self.kind}
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
            if session.taken:
                return {"state": "busy", "error": IN_USE.as_dict(), "kind": self.kind}
        if isinstance(video, dict) and session.video_events == events:
            _video_said(session, video)
        video = session.video
        ready = flag(video.get("ready"))
        if ready is None:  # the device has not said: believe the picture
            ready = session.frame is not None
        attached = None if not isinstance(usb, str) else usb == "configured"
        self._told = "online" if ready else "no_signal"
        has_atx = extension == "atx-power"
        return {
            "state": self._told,
            "error": None,
            "kind": self.kind,
            # What this one can be asked beside what every JetKVM can: the power and reset buttons of its ATX extension.
            "can": can_do(*self.can, "power" if has_atx else None, "reset" if has_atx else None),
            "video": {
                "signal": bool(ready),
                "width": number(video.get("width"), 1, 100_000),
                "height": number(video.get("height"), 1, 100_000),
                "fps": number(video.get("fps"), 0.001, 1000),
            },
            "usb": {"keyboard": attached, "mouse": attached},
            "atx": {
                "enabled": has_atx,
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

    async def _layout(self, session: _Session) -> str:
        """The keyboard layout the JetKVM says its computer uses (set at its own page), once a connection. US English
        where it has no such question (an older one, which typed US keys only). KvmError where it does not answer: nothing
        is typed without knowing which keys type the text. A name that does not look like one is said as it is not."""
        if session.layout is None:
            try:
                said = await self._call(session, "getKeyboardLayout")
            except KvmError as ex:
                if ex.code != "action_failed" or ex.message != "Method not found":
                    raise
                said = US
            if said == "":
                said = US  # (one never chosen: the JetKVM's own page takes it as US English, useKeyboardLayout.ts)
            if not isinstance(said, str) or not LAYOUT_NAME.fullmatch(said):
                said = "(" + (plain(said, 20) or "none") + ")"
            session.layout = said.replace("_", "-")  # (an older JetKVM's "en_US" is its "en-US")
        return session.layout

    async def _version(self, session: _Session) -> str | None:
        if session.version is None:
            local = await self._call(session, "getLocalVersion")
            session.version = plain(local.get("appVersion"), 40) if isinstance(local, dict) else None
        return session.version


def _presses(method: str, params: dict[str, Any]) -> bool:
    """Whether a report has keys or mouse buttons down: one that leaves something down until another says otherwise."""
    if method == "keyboardReport":
        return bool(params.get("keys")) or bool(params.get("modifier"))
    if method in ("absMouseReport", "relMouseReport"):
        return bool(params.get("buttons"))
    return False


async def _drained(channel: Any, within: float) -> None:
    """Wait until what was handed to a data channel has left the wall (gone on to the network), `within` at the most."""
    if channel is None or channel.readyState != "open" or channel.bufferedAmount <= 0:
        return
    left = asyncio.Event()
    gone = left.set
    channel.on("bufferedamountlow", gone)
    try:
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(within):
                await left.wait()
    finally:
        channel.remove_listener("bufferedamountlow", gone)


def _retrieved(future: asyncio.Future[None]) -> None:
    """(A future nobody may wait for, failed: its failure is taken, so that nothing says it was never looked at.)"""
    if not future.cancelled():
        future.exception()


def _taken_while(done: int, of: int) -> KvmError:
    """An action that types or presses keys, stopped because the JetKVM's own page took the viewer."""
    if done == 0:
        return KvmError("in_use", f"It was not done: {IN_USE.message}", 409)
    return KvmError("in_use", f"Typing was stopped after {done} of {of} keys: {IN_USE.message}", 409)


def _ended_while(done: int, of: int, why: KvmError) -> KvmError:
    """An action that types or presses keys, stopped because the connection ended under it: nothing more of it went."""
    if done == 0:
        return KvmError("action_failed", f"It was not done: {why.message}")
    return KvmError("action_failed", f"Typing was stopped after {done} of {of} keys: {why.message}")


def _fold_into(waiting: deque[tuple[str, dict[str, Any], bool]], method: str, params: dict[str, Any]) -> bool:
    """Fold a move of the pointer or a turn of the wheel into one of its kind that waits to go; whether it was.

    A place replaces a place, moves add up, turns of the wheel add up, as far as one report carries them (a move or a
    turn that would not fit is sent after). Only into one that came after the last key or button that waits: never
    across a press or a release, which would then land where the pointer went next (a drag begun where the hand had
    already gone, a click let go of elsewhere). Across a turn of the wheel a move may be folded, and the other way
    round: the turn then lands where the pointer was before or after those moves, as far off as the pointer went
    while they waited (only where the JetKVM answers slower than the mouse is moved).
    """
    for index in range(len(waiting) - 1, -1, -1):
        kind, said, foldable = waiting[index]
        if not foldable:
            return False
        if kind == method:
            folded = _folded(method, said, params)
            if folded is None:
                return False
            waiting[index] = (method, folded, True)
            return True
        if "wheelReport" not in (kind, method):
            return False  # (a place and a move are not folded across each other)
    return False


def _same_as_last(waiting: deque[tuple[str, dict[str, Any], bool]], method: str, params: dict[str, Any]) -> bool:
    """Whether a report that says a whole state (the keyboard's; the pointer's place with the buttons; the buttons alone)
    says what the last one of its kind that waits says. A relative move or a turn of the wheel says no state."""
    if method not in ("keyboardReport", "absMouseReport", "relMouseReport") or (method == "relMouseReport" and (params.get("dx") or params.get("dy"))):
        return False
    for kind, said, _ in reversed(waiting):
        if kind == method:
            return said == params
    return False


def _folded(method: str, waiting: dict[str, Any], new: dict[str, Any]) -> dict[str, Any] | None:
    """A report for the live line folded into the one of its kind that waits last, or None where it cannot be."""
    if waiting.get("buttons") != new.get("buttons"):
        return None
    if method == "absMouseReport":
        return new  # (where the pointer is now; where it was on the way is not worth waiting for)
    names = {"relMouseReport": ("dx", "dy"), "wheelReport": ("wheelX", "wheelY")}.get(method)
    if names is None:
        return None
    summed = {name: waiting.get(name, 0) + new.get(name, 0) for name in names}
    if any(not -MOST_STEP <= value <= MOST_STEP for value in summed.values()):
        return None
    return {**new, **summed}


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
