"""The live connection: one WebSocket per viewer that carries a machine's picture down and keys and the mouse up.

What it speaks is draft 2 of the live connection in desktop/SPEC.md (section 6.2): a pass for one line
(`POST /api/v1/devices/{id}/live`, a call like every other), then the line itself (`GET` at the same place,
upgraded to a WebSocket) whose first message carries the pass. The two routes are in server.py; all that is
behind them is here.

What a line gets, by the family of the machine:

* A kvmd KVM with the H.264 WebSocket of stock PiKVM (`/api/media/ws`): its access units passed on as they
  come, one connection to the device shared by every viewer that can show H.264 (`H264Source`). One without
  that line (a kvmd KVM whose own page shows video over WebRTC only), or a viewer that shows JPEG alone: the KVM's
  pictures asked one after the other, as the wall's tiles ask them, at the pace the fastest viewer asks for
  and never more than the device gives (`SnapshotSource`).
* A JetKVM: JPEG made of the frames this program decodes anyway. Its video comes over WebRTC, and the library
  that speaks it hands out decoded frames and nothing else through what it documents (`JetSource`).
* A server whose console the wall reads (AMI MegaRAC): JPEG of its screen, each time the screen changes
  (`ConsoleSource`), and keys and the mouse as the USB HID reports that console carries (`RedfishHid`); an OpenBMC
  console shows the screen and takes no keyboard or mouse yet.
* A PC with Intel AMT whose KVM the wall may use: the same, of the screen its KVM gives (`ConsoleSource`), and keys
  and the mouse as RFB's key and pointer events through that KVM (`RfbHid`).

Keyboard and mouse go to a kvmd KVM as the JSON events its own page sends, and to a JetKVM as the reports its
page sends over the channel this program already asks it over. The line names a key by its USB HID usage
(page 7); kvmd wants the name a browser gives the key (`KeyboardEvent.code`), and the table that turns the one
into the other, CODE_NAMES, is typed from the USB HID Usage Tables and the W3C list of code values.

Rules that hold here, beside the draft's: every read from a device is bounded in size and in time; a viewer
that falls behind is brought forward to the next key frame, never waited for; one connection holds a
machine's keyboard and mouse at a time, and an action from the page is refused while one does; an admin, in
person, may take them over from whoever holds them, who is told so; they are given back by themselves after
IDLE_GIVE_BACK without input; whatever a connection had down on the machine is released when it loses them,
for whatever reason, and whoever holds them next sends nothing until that, and everything the one before
still had on its way, is through; the activity log says who took control, from whom, and when and why it
was given back, never which keys; the pass is in no address and in no log line.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import re
import secrets
import struct
import time
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Coroutine, Iterable, Iterator, MutableMapping
from dataclasses import dataclass
from typing import Any, ClassVar

from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from .core import DeviceManager
from .kvm import (
    BACKOFF_MAX,
    ERROR_HOLD,
    FULL,
    MAX_PICTURE_PIXELS,
    MAX_PICTURE_SIDE,
    MOST_UNIT,
    TIERS,
    Device,
    KvmDevice,
    KvmError,
    Listening,
    picture_size,
    plain,
    tier_for,
)

log = logging.getLogger("qkvm")

FORM = 2  # the form of the live connection this server speaks (the draft's number): said in /api/v1/wall as "live"
PASS_LASTS = 30.0  # seconds a pass is good for
MOST_PASSES = 256  # passes outstanding at once, of the whole wall; beyond that none is given (none is taken from another to make room)
# Live lines one account (or one token, one wall screen) may have open at once, the passes it was given and has not used
# counted with them: a person with the wall on a few screens, the desktop program with a few machines live, a script.
MOST_LINES_EACH = 32
TICKET = re.compile(r"[A-Za-z0-9_-]{16,200}")  # what a pass looks like, as the draft has it
HELLO_WITHIN = 10.0  # seconds a line has to show its pass
# Pictures that may wait for one viewer; more, and it is brought forward to the next key frame (which, of JPEG, every
# picture is: a viewer behind by two is handed the newest). A picture is held once for every viewer that has it waiting.
QUEUE_H264, QUEUE_JPEG = 8, 2
MOST_WORDS = 64  # messages of text that may wait for one viewer; more, and it is not reading at all
MOST_WORD = 4096  # bytes one message from a client may be: the longest the draft has is a few dozen
MOST_A_SECOND = 2000  # messages from one client in one second; more is flooding (a mouse reports a thousand times a second at the most)
MOST_STEPS = 8  # words to a device that one relative move of the pointer is cut into, at the most (a signed byte each way: a thousand pixels)
# Takings and givings back of keyboard and mouse in a minute, by one account (a token, a wall screen) on all its lines
# together; each is a line in the activity log, and a taking opens a way in to the machine (a WebSocket to a KVM). Counted
# per line, a script that opened its lines anew took them 1680 times in ten seconds.
MOST_CONTROL_A_MINUTE = 60
# The longest the way in to a machine's keyboard and mouse is waited for when they are asked for (`Hid.open`): a PC with
# Intel AMT between two sessions takes up to ten and a half seconds, a JetKVM whose connection is made anew some
# forty-seven, a kvmd KVM a sign-in and some seconds a try. Not made by then, the asking is answered `timeout` and what is
# made later is closed again. The page waits a little longer than this for an answer (app.js CONTROL_ANSWER): one that
# gave up after five seconds gave keyboard and mouse back once the server had given them, after a take-over too, and
# nobody held the machine.
WAY_IN_WITHIN = 60.0
# Live views opened and ended that one account's lines (a token's, a wall screen's) write into the activity log, at the most:
# so many an hour, and an allowance of as many at once. A script that opened and closed lines in a loop wrote two entries a
# turn, a hundred a second, and pushed out of the log within the hour what everybody had done before. Beyond it they are
# counted, and the next entry of that account says how many were left out (`unsaid`).
LIVE_SAID_AN_HOUR = 120
# Keyboard and mouse are given back by themselves after this long without a key, a button, the wheel or the pointer moved
# by whoever holds them: the line goes on showing the machine, and what was held down is let go of. (A holder who went
# away from a machine that runs production work kept everybody else from it, an admin included, for as long as their
# browser stayed open.) The one place this time is set; what the holder and the log are told is made from it.
IDLE_GIVE_BACK = 15 * 60.0
INPUT = frozenset({"k", "m", "mr", "mb", "mw"})  # the words that are input, and so keep keyboard and mouse held
# Seconds the next holder's first word waits at the most for what the one before still had on its way to be through, and
# for the letting go of what it had down: a word to a PC between two AMT sessions waits up to ten and a half seconds for
# the next, its late letting go is given LET_GO_WITHIN after that. Beyond it, the next holder's words go all the same.
HAND_OVER_WITHIN = 16.0
STATE_EVERY = 1.0  # seconds between looks at how the machine is, for the `state` messages
STANDING_EVERY = 3.0  # seconds between looks at whether whoever holds a line may still have it
POINTER_EVERY = 0.01  # the pointer's place is sent on to the device this often at the most (as kvmd's own page does)
KEY_FRAME_EVERY = 0.5  # a device is asked for a key frame this often at the most
MOST_FPS, LEAST_FPS = 30.0, 1.0  # pictures a second a viewer may ask for, where the pictures are asked for one by one
MOST_WIDTH = 16384  # the widest a viewer may say its picture is
FARTHEST = 32767  # the far edge of the picture, as the line counts the pointer
NO_MEDIA_FOR = 600.0  # seconds a device that has no H.264 line is not asked for one again
# The server asks a line this often whether it is there (a WebSocket ping, which the web server sends and the viewer's
# library answers by itself: a browser cannot send one), and one that has answered none of three such askings is
# gone: its keys are let go of on the machine then.
ASK_EVERY = 5.0
# And a line is hung up on (cli.py, `Line`) when its viewer stops taking what is sent to it: when what waits to be
# sent has not drained for this long, when more waits than a reading viewer would ever let pile up, or when the
# viewer sends more pings in a second than a client has reason to (the web server answers each by itself, straight
# into what waits to be sent). A viewer that kept its connection and read nothing kept a machine's keyboard and mouse,
# the keys it had down with them, for as long as the connection lived; and one that sent pings by the million and
# read nothing had their answers held for it without end.
STUCK_AFTER = ASK_EVERY * 2
MOST_UNSENT_TO_VIEWER = MOST_UNIT + 2**20  # (a picture may be a whole access unit, and is written when the line was free)
MOST_PINGS_A_SECOND = 50
# And every frame the program is not handed as a message (a ping, a pong, a piece of a message in pieces, anything after
# the line was closed) is counted, before any pass was shown as after: more than this in a second, or a message in more
# pieces than MOST_PIECES (no browser and no library sends one in pieces at the sizes the line has), and it is hung up on.
MOST_FRAMES_A_SECOND = MOST_A_SECOND
MOST_PIECES = 16
SAY_WITHIN = 2.0  # seconds a device has to take a word (a key, a request for a key frame) before it counts as not taking them
LET_GO_WITHIN = SAY_WITHIN * 2  # seconds what a line had down on a machine is given to be let go of, once it loses keyboard and mouse
MOST_STEP = 127  # the most the pointer moves in one word to a device (a signed byte)
# The most turns of the wheel one message carries (the page sends them one by one, and says sixteen at the most for one
# turn of a hand). RFB has no turn of more than one: each is a press and a release, two words to the machine.
MOST_NOTCHES = 16
# Keys a line may name by their USB HID usage: page 7 from `a` (4) to the right Meta key (0xE7). Below are no keys but the
# keyboard's own error reports (a Linux host ignores a whole JetKVM report that holds one, and a key let go of with it
# would stay down); above is reserved, and a JetKVM would be handed it as it came.
FIRST_KEY, LAST_KEY = 0x04, 0xE7
# ...but the keyboard's Power key (0x66), which shuts a machine down without the question every power action is asked
# first: the page never sends it, and the line takes it from nobody.
NOT_SENT = frozenset({0x66})
MOST_KEYS = 6  # keys a keyboard report holds, beside the modifiers
SAY_AGAIN = 60.0  # seconds between two lines in the log about a picture source of one machine that keeps failing
# Seconds the wall waits for what the lines still owe a device (the keys they let go of) before that device's connection is
# closed: at the wall's end, and when a tile is edited or removed. Longer than a letting go is given (LET_GO_WITHIN), so
# that one under way is never cut off by the connection it goes through being closed under it.
STOP_WITHIN = LET_GO_WITHIN + 0.5

HEAD = struct.Struct("<BBHIq")  # a picture's header: kind, flags, two bytes of zero, the counter, when it was got (microseconds)
H264, JPEG = 1, 2  # the kinds
KEY = 1  # the flag

# A key by its USB HID usage (page 7, Keyboard/Keypad) and the name a browser gives it (`KeyboardEvent.code`), which is
# what a kvmd KVM is told. Typed from the USB HID Usage Tables (version 1.4, section 10) and the W3C UI Events
# KeyboardEvent code Values (section 3). Usages without a code value in that list are not here, and a key
# that is not here is not sent to a kvmd KVM (a JetKVM is told the usage itself). The modifiers are 0xE0 to 0xE7.
CODE_NAMES: dict[int, str] = {
    **{0x04 + i: f"Key{chr(65 + i)}" for i in range(26)},
    **{0x1D + i: f"Digit{i}" for i in range(1, 10)},
    0x27: "Digit0", 0x28: "Enter", 0x29: "Escape", 0x2A: "Backspace", 0x2B: "Tab", 0x2C: "Space", 0x2D: "Minus", 0x2E: "Equal",
    0x2F: "BracketLeft", 0x30: "BracketRight", 0x31: "Backslash", 0x32: "Backslash", 0x33: "Semicolon", 0x34: "Quote",
    0x35: "Backquote", 0x36: "Comma", 0x37: "Period", 0x38: "Slash", 0x39: "CapsLock",
    **{0x39 + i: f"F{i}" for i in range(1, 13)},
    0x46: "PrintScreen", 0x47: "ScrollLock", 0x48: "Pause", 0x49: "Insert", 0x4A: "Home", 0x4B: "PageUp", 0x4C: "Delete",
    0x4D: "End", 0x4E: "PageDown", 0x4F: "ArrowRight", 0x50: "ArrowLeft", 0x51: "ArrowDown", 0x52: "ArrowUp", 0x53: "NumLock",
    0x54: "NumpadDivide", 0x55: "NumpadMultiply", 0x56: "NumpadSubtract", 0x57: "NumpadAdd", 0x58: "NumpadEnter",
    **{0x58 + i: f"Numpad{i}" for i in range(1, 10)},
    0x62: "Numpad0", 0x63: "NumpadDecimal", 0x64: "IntlBackslash", 0x65: "ContextMenu", 0x66: "Power", 0x67: "NumpadEqual",
    **{0x5B + i: f"F{i}" for i in range(13, 25)},
    0x74: "Open", 0x75: "Help", 0x77: "Select", 0x79: "Again", 0x7A: "Undo", 0x7B: "Cut", 0x7C: "Copy", 0x7D: "Paste", 0x7E: "Find",
    0x7F: "AudioVolumeMute", 0x80: "AudioVolumeUp", 0x81: "AudioVolumeDown", 0x85: "NumpadComma", 0x87: "IntlRo", 0x88: "KanaMode",
    0x89: "IntlYen", 0x8A: "Convert", 0x8B: "NonConvert", 0x90: "Lang1", 0x91: "Lang2", 0x92: "Lang3", 0x93: "Lang4", 0x94: "Lang5",
    0xB6: "NumpadParenLeft", 0xB7: "NumpadParenRight",
    0xE0: "ControlLeft", 0xE1: "ShiftLeft", 0xE2: "AltLeft", 0xE3: "MetaLeft", 0xE4: "ControlRight", 0xE5: "ShiftRight",
    0xE6: "AltRight", 0xE7: "MetaRight",
}  # fmt: skip
MODIFIERS = range(0xE0, 0xE8)  # their usages; a JetKVM wants them as one byte of bits, in this order (ControlLeft is bit 0)
# The mouse buttons as the line counts them (1 to 5, as a USB mouse does: left, right, middle, back, forward) and as
# kvmd's own page names them (it calls the two side buttons "up" and "down").
BUTTON_NAMES = {1: "left", 2: "right", 3: "middle", 4: "up", 5: "down"}


@dataclass(frozen=True)
class Holder:
    """Whoever was given a pass: enough to name them, and to ask again whether they may still be on the line."""

    user_id: str
    name: str  # for the activity log
    may_control: bool  # an operator or an admin, in person or by a token for scripts; a viewer and a wall screen may look
    ip: str
    session: str | None = None  # the cookie the pass was asked with, for a browser: the line ends when that sign-in does
    token: str | None = None  # the id of the token it was asked with, for a script


@dataclass(frozen=True)
class Pass:
    device_id: str
    holder: Holder
    until: float


# Whether a holder may still be on a line to this machine: None, or the code that says why not. Asked now and then
# of whoever gave the pass out (the server), who knows the accounts; and whether the holder may still act.
Standing = Callable[[Holder, str], tuple[str | None, bool]]


class Picture:
    """One picture as it goes down every line: the header and the data, made once for all viewers."""

    __slots__ = ("counter", "key", "message")

    def __init__(self, kind: int, key: bool, counter: int, data: bytes) -> None:
        self.key = key
        self.counter = counter
        self.message = HEAD.pack(kind, KEY if key else 0, 0, counter & 0xFFFFFFFF, time.monotonic_ns() // 1000) + data


MOST_NAME = 60  # letters of a holder's name a refusal carries (`by`)


def refused(code: str, message: str, by: str | None = None) -> dict[str, Any]:
    """What a line is told when it asked for keyboard and mouse and does not get them; `by`: who has them, where somebody has."""
    word: dict[str, Any] = {"t": "control", "on": False, "code": code, "message": message}
    if by is not None:
        word["by"] = by[:MOST_NAME]
    return word


def _duration(seconds: float) -> str:
    """A time as a person says it: "15 minutes", "1 minute", "30 seconds"."""
    if seconds >= 60 and seconds % 60 == 0:
        count, unit = int(seconds // 60), "minute"
    else:
        count, unit = max(1, round(seconds)), "second"
    return f"{count} {unit}{'' if count == 1 else 's'}"


def _number(value: Any, low: int, high: int) -> int | None:
    """A whole number a client sent, within these bounds; None for anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or not low <= value <= high:
        return None
    return int(value)


def _notches(value: Any) -> int:
    """Turns of the wheel as a client said them, MOST_NOTCHES at the most either way; 0 for what is no number."""
    number = _number(value, -(10**6), 10**6)
    return 0 if number is None else max(-MOST_NOTCHES, min(MOST_NOTCHES, number))


def _steps(dx: Any, dy: Any) -> list[tuple[int, int]]:
    """A relative move cut into words a device takes (a signed byte each way), the way a mouse would have said it."""
    x, y = _number(dx, -(10**6), 10**6) or 0, _number(dy, -(10**6), 10**6) or 0
    steps: list[tuple[int, int]] = []
    while (x or y) and len(steps) < MOST_STEPS:
        sx, sy = max(-MOST_STEP, min(MOST_STEP, x)), max(-MOST_STEP, min(MOST_STEP, y))
        steps.append((sx, sy))
        x, y = x - sx, y - sy
    return steps


# --- keyboard and mouse, to each family of device ----------------------------------------------------------


_LOOSE: set[asyncio.Task[None]] = set()  # letting go owed by a Hid that was given nowhere to hand it (`Hid.owe`), held until done
# The buttons the word being sent carries (`Hid._said`), each word in its own task's context: RfbHid's pointer events say
# which buttons they carried once they go, which may be later than the word was asked for.
_CARRIED: contextvars.ContextVar[set[int] | None] = contextvars.ContextVar("carried", default=None)


def _keep(task: asyncio.Task[None]) -> None:
    _LOOSE.add(task)
    task.add_done_callback(_LOOSE.discard)


class Hid:
    """What keys and the mouse go through to one machine, while a line holds them.

    Each of these knows what it has down on the machine (keys, buttons), so that all of it can be let go of when
    the line ends: the draft says nothing to the device by itself about that, and a key that stays down
    repeats on the machine for as long as nobody says otherwise. The pointer's place is sent on at a pace a
    device takes (every ten milliseconds at the most; what came in between is the place it is at now), a button
    or a key sends the place that is waiting first, so that a click lands where the pointer was put.

    A word may take its time on its way: a PC with Intel AMT whose session the engine ended (every few minutes, at
    its own time) has a key wait up to ten seconds for the next one. The line may lose keyboard and mouse meanwhile
    (`end`), and everything it had down is let go of then; the key that was waiting lands after that, in a session
    where nothing will ever let it go. So once a Hid is ended nothing more of the line's goes out, and whatever was
    already on its way and may have put something down is let go of again as soon as it is through (`_said`).

    And whoever holds keyboard and mouse next sends nothing until all of that is through (`until_through`): their first key
    would otherwise land beside a Ctrl of the line before, still down on the machine, or be let go of by that line's
    late letting go of the same key.
    """

    def __init__(self) -> None:
        self.authorized: Callable[[], bool] | None = None  # checked again when delayed input actually dispatches
        self.keys_down: set[int] = set()  # keys that may be down on the machine: put here before they are sent
        self.buttons_down: set[int] = set()
        self._place: tuple[int, int] | None = None  # where the pointer is to be put, not yet sent
        self._placed_at = float("-inf")
        self._placing: asyncio.Task[None] | None = None
        self.ended = False  # the line lost keyboard and mouse: see `end`
        # Where a letting go that comes after the end is handed, so that the wall's end waits for it as for the rest
        # (the machine's: Lines.owed). It must not be awaited by the line, whose task may be being stopped.
        self.owe: Callable[[asyncio.Task[None]], None] = _keep
        # What `until_through` waits for: words of the line's being sent (`sending`), the late lettings go they left, and the
        # letting go of everything once the line lost keyboard and mouse (`letting_go`, set by the machine).
        self._going = 0
        self._quiet = asyncio.Event()
        self._quiet.set()
        self._late: set[asyncio.Task[None]] = set()
        self.letting_go: asyncio.Task[None] | None = None

    @contextlib.contextmanager
    def sending(self) -> Iterator[None]:
        """Around one word of the line's to the machine, for as long as it takes: `until_through` waits for it."""
        self._going += 1
        self._quiet.clear()
        try:
            yield
        finally:
            self._going -= 1
            if not self._going:
                self._quiet.set()

    def is_through(self) -> bool:
        """Whether `until_through` has nothing to wait for."""
        return not self._going and all(task is None or task.done() for task in (self._placing, self.letting_go, *self._late))

    async def until_through(self) -> None:
        """Until nothing the line sent through this is on its way any more, and what is owed for it is done: a late letting
        go, the pointer's place that was waiting, the letting go of everything and the closing. Waits only: a waiter that is
        stopped leaves every one of them to go on (asyncio.wait cancels nothing)."""
        while True:
            if self._going:
                await self._quiet.wait()
                continue
            pending = {task for task in (self._placing, self.letting_go, *self._late) if task is not None and not task.done()}
            if not pending:
                return
            await asyncio.wait(pending)

    def _owe_late(self, task: asyncio.Task[None]) -> None:
        self._late.add(task)
        task.add_done_callback(self._late.discard)
        self.owe(task)

    def end(self) -> None:
        """The line lost keyboard and mouse. Nothing more of its goes to the machine from now on, a pointer's place that
        waits included; and a word already on its way that lands after this is let go of again (`_said`). What it had
        down is let go of by `release_all`, which follows."""
        self.ended = True
        if self._placing is not None:
            self._placing.cancel()
        self._place = None

    async def _said(self, saying: Callable[[], Awaitable[None]], key: int | None = None, buttons: Iterable[int] = ()) -> None:
        """One word to the machine that may put something down: `key` pressed, or the pointer with `buttons` held (RFB sends
        them with every move). It may have landed after what it put down was let go of: by the end of the line (`end`), or
        by the line itself, whose letting go of a button went to the session that was open while this word waited for
        the next (the pointer's place sent by `_placing`, in a task of its own, with the button of a drag in it). What it
        carried and is not held now is let go of again once it is through, in a task of its own."""
        if self.authorized is not None and not self.authorized():
            return
        carried = set(buttons)
        telling = _CARRIED.set(carried)  # (and what a pointer event of this word carries as it goes, it adds: RfbHid._pointer)
        try:
            await saying()
        finally:
            _CARRIED.reset(telling)
            late_key = key if key is not None and (self.ended or key not in self.keys_down) else None
            late_buttons = frozenset(carried if self.ended else carried - self.buttons_down)
            if late_key is not None or late_buttons:
                self._owe_late(asyncio.ensure_future(self._let_go_late(late_key, late_buttons)))

    async def _let_go_late(self, key: int | None, buttons: frozenset[int]) -> None:
        try:
            async with asyncio.timeout(LET_GO_WITHIN):
                # Each is asked again right before it goes: one the line has pressed again since is down because it is
                # meant to be (an earlier one in this task may have waited for its turn to be sent).
                if key is not None and (self.ended or key not in self.keys_down):
                    try:
                        await self._say_key(key, False)
                    except KvmError:
                        pass  # (the buttons all the same)
                for button in sorted(buttons):
                    if not self.ended and button in self.buttons_down:
                        continue
                    try:
                        await self._say_button(button, False)
                    except KvmError:
                        pass
        except (TimeoutError, OSError):
            pass  # the device is gone, and with it what it held down
        except Exception:
            log.debug("letting go again of what landed after the end failed", exc_info=True)

    async def open(self) -> None:
        """Make the way to the machine, where that takes a connection of its own."""

    async def close(self) -> None:
        """Give it up. What was down has been let go of before this, by `release_all`."""

    async def _say_key(self, usage: int, down: bool) -> None:
        raise NotImplementedError

    async def _say_place(self, x: int, y: int) -> None:
        raise NotImplementedError

    async def _say_move(self, dx: int, dy: int) -> None:
        raise NotImplementedError

    async def _say_button(self, button: int, down: bool) -> None:
        raise NotImplementedError

    async def _say_wheel(self, dx: int, dy: int) -> None:
        raise NotImplementedError

    async def key(self, usage: int, down: bool) -> None:
        if self.ended:
            return
        await self._flush()
        if self.ended:
            return  # (lost while the pointer's place went out: the key is not sent)
        if down:
            self.keys_down.add(usage)
            await self._said(lambda: self._say_key(usage, True), key=usage)
        else:
            self.keys_down.discard(usage)
            await self._say_key(usage, False)  # (a letting go puts nothing down, and goes to whatever is open: see RfbHid)

    async def place(self, x: int, y: int) -> None:
        if self.ended:
            return
        now = time.monotonic()
        if now - self._placed_at >= POINTER_EVERY and self._place is None:
            self._placed_at = now
            await self._said(lambda: self._say_place(x, y), buttons=self.buttons_down)
            return
        self._place = (x, y)
        if self._placing is None or self._placing.done():
            self._placing = asyncio.create_task(self._place_later())

    async def _place_later(self) -> None:
        await asyncio.sleep(max(0.0, self._placed_at + POINTER_EVERY - time.monotonic()))
        try:
            await self._flush()
        except KvmError:
            pass  # the next key or button finds the way to the machine gone, and says so

    async def _flush(self) -> None:
        """Send the pointer's place that is waiting, if one is."""
        place, self._place = self._place, None
        if place is not None and not self.ended:
            self._placed_at = time.monotonic()
            await self._said(lambda: self._say_place(*place), buttons=self.buttons_down)

    async def move(self, dx: int, dy: int) -> None:
        if self.ended:
            return
        await self._said(lambda: self._say_move(dx, dy), buttons=self.buttons_down)

    async def button(self, button: int, down: bool) -> None:
        if self.ended:
            return
        await self._flush()
        if self.ended:
            return
        if down:
            self.buttons_down.add(button)
            await self._said(lambda: self._say_button(button, True), buttons=self.buttons_down)
        else:
            self.buttons_down.discard(button)
            await self._say_button(button, False)

    async def wheel(self, dx: int, dy: int) -> None:
        if self.ended:
            return
        await self._flush()
        if self.ended:
            return
        await self._said(lambda: self._say_wheel(dx, dy), buttons=self.buttons_down)

    async def release_all(self) -> None:
        """Let go of everything this line had down on the machine."""
        if self._placing is not None:
            self._placing.cancel()
        self._place = None
        # Each is let go of, whatever became of the one before it: one refused must not leave the rest down on the machine.
        failed: KvmError | None = None
        for usage in sorted(self.keys_down, key=lambda usage: (usage in MODIFIERS, usage)):  # (the modifiers last: a letter released after Ctrl is a letter)
            try:
                await self._say_key(usage, False)
            except KvmError as ex:
                failed = failed or ex
        self.keys_down.clear()
        for button in sorted(self.buttons_down):
            try:
                await self._say_button(button, False)
            except KvmError as ex:
                failed = failed or ex
        self.buttons_down.clear()
        if failed is not None:
            raise failed


class KvmdHid(Hid):
    """Keys and the mouse to a kvmd KVM: its WebSocket for events, with the JSON events its own page sends."""

    def __init__(self, device: KvmDevice) -> None:
        super().__init__()
        self._device = device
        self._ws: Any = None
        self._reading: asyncio.Task[None] | None = None

    async def open(self) -> None:
        self._ws = await self._device.input_line()
        # What the KVM says on this line (its state, every second or so) is read and thrown away: left unread,
        # it would pile up at the KVM's end of the line.
        self._reading = asyncio.create_task(self._read_away())

    async def _read_away(self) -> None:
        heard = Listening(self._ws, 2**20)
        try:
            while True:
                try:
                    await heard.message(5)
                except TimeoutError:
                    pass
        except KvmError:
            # More than a KVM has reason to send (see Listening): hung up on, and the next key finds the line gone.
            self._ws.transport.abort()
        except Exception:  # (the line is gone, in whichever way: the next word on it says so to whoever sends)
            pass

    async def close(self) -> None:
        if self._reading is not None:
            self._reading.cancel()
        if self._ws is not None:
            await self._ws.close()

    async def _say(self, event_type: str, event: dict[str, Any]) -> None:
        if self._ws is None:
            raise KvmError("dropped", "The connection for keys and the mouse is not open")
        try:
            async with asyncio.timeout(SAY_WITHIN):  # (never asyncio.wait_for: on Python 3.11 it can lose a stop)
                await self._ws.send(json.dumps({"event_type": event_type, "event": event}))
        except TimeoutError:
            raise KvmError("dropped", "The KVM stopped taking keys and the mouse") from None
        except Exception as ex:  # (closed by the device, or by this program hanging up on it: the library's words for it vary)
            raise KvmError("dropped", f"The connection for keys and the mouse ended ({type(ex).__name__})") from None

    async def _say_key(self, usage: int, down: bool) -> None:
        name = CODE_NAMES.get(usage)
        if name is not None:  # a key kvmd has no name for is not sent (it would drop it unread)
            await self._say("key", {"key": name, "state": down})

    async def _say_place(self, x: int, y: int) -> None:
        # The line counts 0 to 32767 over the picture; kvmd counts -32768 to 32767.
        await self._say("mouse_move", {"to": {"x": x * 2 - 32768, "y": y * 2 - 32768}})

    async def _say_move(self, dx: int, dy: int) -> None:
        await self._say("mouse_relative", {"delta": {"x": dx, "y": dy}})

    async def _say_button(self, button: int, down: bool) -> None:
        await self._say("mouse_button", {"button": BUTTON_NAMES[button], "state": down})

    async def _say_wheel(self, dx: int, dy: int) -> None:
        await self._say("mouse_wheel", {"delta": {"x": dx, "y": dy}})


class RfbHid(Hid):
    """Keys and the mouse to a machine whose screen is read over RFB (a PC with Intel AMT, through its KVM; a guest of
    Proxmox, through its console): key events
    by keysym, and pointer events in the pixels of its screen, with the buttons held as RFB counts them (the left one
    bit 0, the middle bit 1, the right bit 2; the wheel a press and a release of bit 3 up, 4 down, 5 left, 6 right).
    RFB has no back and forward buttons: those are not sent. A key that has no keysym is not sent either."""

    BITS: ClassVar[dict[int, int]] = {1: 1, 2: 4, 3: 2}  # the line's buttons (left, right, middle) as RFB's bits

    def __init__(self, device: Any) -> None:
        super().__init__()
        self._device = device
        self._buttons = 0
        self._at = (0, 0)  # where the pointer is, in the screen's pixels
        self._to: tuple[int, int] | None = None  # the last place said, in the line's units, until the screen's size is known

    async def open(self) -> None:
        await self._device.input_ready()

    async def _say_key(self, usage: int, down: bool) -> None:
        try:
            await self._device.press(usage, down)
        except KvmError as ex:
            if ex.code != "invalid":  # (a key with no keysym: nothing to send, and no reason to take the keyboard away)
                raise

    async def _size(self) -> tuple[int, int]:
        size = self._device.screen_size()
        if size is None:
            # Between two sessions (the engine ended one at its own time): the next one says how large the screen is. Worked
            # out without it, every place was the top left corner, and a click, or the end of a drag, landed there.
            await self._device.input_ready()
            size = self._device.screen_size()
        return size or (1, 1)

    def _place_now(self, size: tuple[int, int]) -> None:
        """The last place said, in the screen's pixels, where one waits to be worked out."""
        if self._to is not None:
            (x, y), self._to = self._to, None
            width, height = size
            self._at = (x * (width - 1) // FARTHEST, y * (height - 1) // FARTHEST)

    async def _pointer(self, wheel: int = 0, dx: int = 0, dy: int = 0, always: bool = False) -> bool:
        """A pointer event at the newest place said (moved by dx, dy), with the buttons held as they are when it goes (and
        `wheel`, a bit of the wheel). Between two sessions it waits for the next one's screen size; every event that waited
        so goes to the newest place, a click included, and not to where the pointer was before the gap. Where the line lost
        keyboard and mouse meanwhile nothing goes (`always`: the second word of a notch of the wheel begun), and False."""
        size = await self._size()
        if self.ended and not always:
            return False
        self._place_now(size)
        if dx or dy:
            width, height = size
            self._at = (min(max(0, self._at[0] + dx), width - 1), min(max(0, self._at[1] + dy), height - 1))
        held = self._buttons | wheel
        carried = _CARRIED.get()
        if carried is not None:
            carried.update(button for button, bit in self.BITS.items() if held & bit)  # (what this word puts down: Hid._said)
        await self._device.pointer(*self._at, held)
        return True

    async def _say_place(self, x: int, y: int) -> None:
        self._to = (x, y)
        await self._pointer()

    async def _say_move(self, dx: int, dy: int) -> None:
        await self._pointer(dx=dx, dy=dy)

    async def _say_button(self, button: int, down: bool) -> None:
        bit = self.BITS.get(button)
        if bit is None:
            return
        self._buttons = self._buttons | bit if down else self._buttons & ~bit
        if down:
            await self._pointer()
            return
        # Let go of on the session that is open, whatever the tile found since, and never waited for: see AmtDevice.press.
        size = self._device.screen_size()
        if size is not None:
            self._place_now(size)
        await self._device.pointer(*self._at, self._buttons, letting_go=True)

    async def _say_wheel(self, dx: int, dy: int) -> None:
        for steps, forward, backward in ((dy, 8, 16), (dx, 64, 32)):
            bit = forward if steps > 0 else backward
            for _ in range(min(abs(steps), MOST_NOTCHES)):
                if self.ended or not await self._pointer(wheel=bit):
                    return  # (between two notches)
                await self._pointer(always=True)  # (a notch begun is let go of: the second word of the two)


class JetHid(Hid):
    """Keys and the mouse to a JetKVM: the reports its own page sends, as calls on the channel this program asks it over.

    A keyboard report is the whole state of the keyboard (the modifiers as bits, up to six keys down), and a
    mouse report carries the buttons with the place or the move: so each is kept here and sent whole. They are
    handed to the device's own queue (`JetKvmDevice.say`), which sends each once the JetKVM has answered the one
    before: a real one does calls that arrive together in either order. Nobody here waits for that.
    """

    def __init__(self, device: Any) -> None:
        super().__init__()
        self._device = device
        self._modifier = 0
        self._keys: list[int] = []  # the keys down, in the order they went down
        self._buttons = 0
        self._at: tuple[int, int] | None = None  # where the pointer was last put, where it is put by place; None: it is moved by steps
        self._on: object = None  # the connection to the JetKVM keyboard and mouse were taken on

    async def open(self) -> None:
        self._on = await self._device.input_ready()  # (the connection they are held on: see JetKvmDevice.say)

    async def close(self) -> None:
        # (Order needs no waiting: everything goes through the device's one queue. This is so that whoever lets go of
        # the line, the wall's end or a tile's removal, waits until the JetKVM has answered the reports that let go.)
        await self._device.all_said()

    def _say(self, method: str, params: dict[str, Any], fold: bool = False) -> None:
        self._device.say(method, params, fold=fold, on=self._on)

    async def _say_keyboard(self) -> None:
        self._say("keyboardReport", {"modifier": self._modifier, "keys": list(self._keys)})

    async def _say_key(self, usage: int, down: bool) -> None:
        if usage in MODIFIERS:
            bit = 1 << (usage - MODIFIERS.start)
            self._modifier = self._modifier | bit if down else self._modifier & ~bit
        elif down:
            if usage not in self._keys:
                self._keys.append(usage)
                del self._keys[:-MOST_KEYS]  # a seventh key: the oldest is let go of, as a keyboard's own report would
        elif usage in self._keys:
            self._keys.remove(usage)
        await self._say_keyboard()

    async def _say_mouse(self, fold: bool = False) -> None:
        if self._at is None:
            self._say("relMouseReport", {"dx": 0, "dy": 0, "buttons": self._buttons})
        else:
            self._say("absMouseReport", {"x": self._at[0], "y": self._at[1], "buttons": self._buttons}, fold=fold)

    async def _say_place(self, x: int, y: int) -> None:
        self._at = (x, y)
        await self._say_mouse(fold=True)  # (a place, and nothing else: one that waits may be replaced by it)

    async def _say_move(self, dx: int, dy: int) -> None:
        self._at = None
        self._say("relMouseReport", {"dx": dx, "dy": dy, "buttons": self._buttons}, fold=True)

    async def _say_button(self, button: int, down: bool) -> None:
        bit = 1 << (button - 1)
        self._buttons = self._buttons | bit if down else self._buttons & ~bit
        await self._say_mouse()

    async def _say_wheel(self, dx: int, dy: int) -> None:
        self._say("wheelReport", {"wheelY": dy, "wheelX": dx}, fold=True)

    async def release_all(self) -> None:
        if self._placing is not None:
            self._placing.cancel()
        self._place = None
        self.keys_down.clear()
        self.buttons_down.clear()
        self._modifier, self._keys, self._buttons = 0, [], 0
        await self._say_keyboard()
        await self._say_mouse()


class RedfishHid(Hid):
    """Keys and the mouse to a server over its controller's console (AMI MegaRAC): the whole state of the keyboard,
    and a mouse report, as the console's USB wants them (see ami.py). Each report is the whole keyboard, so a key
    stays down until a report without it; the pointer goes as an absolute place where the server's mouse is absolute
    (what AMI's boards are by default), else as a relative move. Back and forward buttons have no bits there.

    Everything goes in the era the console was held in when the line took the keyboard (`RedfishDevice.input_ready`):
    once the console was given to somebody at the controller's own page, or ended, nothing more of this line's goes,
    and its next word takes the keyboard from it (`in_use`, `dropped`). What it had down was let go of then by the
    device: before a person is let in, the moment the controller says the console was switched to another, and
    before the session's goodbye."""

    BITS: ClassVar[dict[int, int]] = {1: 1, 2: 2, 3: 4}  # the line's buttons (left, right, middle) as USB mouse bits
    MIDDLE = (FARTHEST // 2, FARTHEST // 2)  # where a pointer that was never put anywhere is taken to be

    def __init__(self, device: Any) -> None:
        super().__init__()
        self._device = device
        self._era = -1  # the era the keyboard was taken in (see the class)
        self._modifier = 0
        self._keys: list[int] = []  # the keys down, in the order they went down
        self._buttons = 0  # the mouse buttons held, as USB bits
        self._at: tuple[int, int] | None = None  # where the pointer was put, 0 to FARTHEST across the screen and down it; None: never

    async def open(self) -> None:
        self._era = await self._device.input_ready()

    async def _say_key(self, usage: int, down: bool) -> None:
        if usage in MODIFIERS:
            bit = 1 << (usage - MODIFIERS.start)
            self._modifier = self._modifier | bit if down else self._modifier & ~bit
        elif down:
            if usage not in self._keys:
                self._keys.append(usage)
                del self._keys[:-MOST_KEYS]  # a seventh key: the oldest is let go of, as a keyboard's own report would
        elif usage in self._keys:
            self._keys.remove(usage)
        await self._device.send_keyboard(self._modifier, self._keys, self._era)

    async def _mouse(self, wheel: int = 0) -> None:
        if self._device.mouse_absolute:
            await self._device.send_mouse(self._buttons, *(self._at or self.MIDDLE), wheel, era=self._era)
        else:
            await self._device.send_mouse(self._buttons, 0, 0, wheel, era=self._era, relative=True)

    async def _say_place(self, x: int, y: int) -> None:
        self._at = (x, y)  # (the line counts 0 to 32767 over the picture, as an absolute mouse does across the screen)
        await self._mouse()

    async def _say_move(self, dx: int, dy: int) -> None:
        if not self._device.mouse_absolute:
            await self._device.send_mouse(self._buttons, dx, dy, 0, era=self._era, relative=True)
            return
        size = self._device.screen_size()
        if size is None:
            return  # (no screen yet to step over: a move of nothing is no word to the server)
        x, y = self._at or self.MIDDLE  # step the place, by as much of the screen as the move is in pixels
        self._at = (min(max(0, x + dx * FARTHEST // max(1, size[0] - 1)), FARTHEST), min(max(0, y + dy * FARTHEST // max(1, size[1] - 1)), FARTHEST))
        await self._mouse()

    async def _say_button(self, button: int, down: bool) -> None:
        bit = self.BITS.get(button)
        if bit is None:
            return  # (back and forward have no USB mouse bit here)
        self._buttons = self._buttons | bit if down else self._buttons & ~bit
        await self._mouse()

    async def _say_wheel(self, dx: int, dy: int) -> None:
        # One report a notch, up positive; the report has one wheel, so a sideways turn (dx) is not sent.
        for _ in range(min(abs(dy), MOST_NOTCHES)):
            if self.ended:
                return
            await self._mouse(wheel=1 if dy > 0 else -1)

    async def release_all(self) -> None:
        if self._placing is not None:
            self._placing.cancel()
        self._place = None
        had_buttons = bool(self._buttons or self.buttons_down)
        self.keys_down.clear()
        self.buttons_down.clear()
        self._modifier, self._keys, self._buttons = 0, [], 0
        # Each is let go of, whatever became of the other.
        failed: KvmError | None = None
        try:
            await self._device.send_keyboard(0, [], self._era)
        except KvmError as ex:
            failed = ex
        if had_buttons:  # (and no mouse report where none can be down: it would move the pointer, a corner opening a menu)
            await self._mouse()
        if failed is not None:
            raise failed


# --- the pictures, from each family of device --------------------------------------------------------------


class Source:
    """A machine's pictures, as one stream shared by the viewers that take them in this form.

    Each picture is numbered as it comes from the device, once for all viewers: a viewer that was brought
    forward sees the numbers jump. The last key frame is kept, and a viewer that joins a JPEG source is
    handed it at once; one that joins an H.264 source waits for the next key frame, which is asked for.
    """

    codec = ""
    queue = QUEUE_JPEG  # pictures that may wait for one viewer of this source

    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.viewers: set[Line] = set()
        self.task: asyncio.Task[None] | None = None
        self.counter = 0
        self.size: tuple[int, int] | None = None  # the pictures' width and height, where known
        self.last: Picture | None = None  # the last key frame
        self.key_wanted = False
        self._key_asked_at = float("-inf")
        self._said_at = float("-inf")  # when the log last had a line about this source failing

    def word(self) -> dict[str, Any]:
        width, height = self.size or (0, 0)
        return {"t": "video", "codec": self.codec, "w": width, "h": height}

    def known(self) -> bool:
        """Whether what follows can be said yet: of JPEG once a picture has said how large they are, of H.264 once the stream is there."""
        return self.size is not None

    def add(self, line: Line) -> None:
        self.viewers.add(line)
        line.source = self
        line.needs_key = True
        line.pictures.clear()
        if self.known():  # (else said to every viewer when it is: `announce`)
            line.say(self.word())
        if self.last is not None and self.codec == "jpeg":
            line.take(self.last)
        else:
            self.ask_key()
        if self.task is None or self.task.done() or self.task.cancelling():  # (one told to stop is on its way out: not this viewer's)
            self.task = asyncio.create_task(self._run())

    def announce(self) -> None:
        """What follows, said to every viewer: at the start, and whenever it changed. A key frame follows it."""
        self.last = None
        for line in list(self.viewers):  # (a line that is told too much ends, and leaves the viewers as it does)
            line.pictures.clear()
            line.needs_key = True
            line.say(self.word())
        self.ask_key()

    def remove(self, line: Line) -> None:
        self.viewers.discard(line)
        if line.source is self:
            line.source = None
        if not self.viewers:
            # Stopped a moment later, not now: a viewer that joins in this same turn of the loop (one browser's
            # line ending as another's begins) keeps the source, where a task being stopped was no task for it.
            asyncio.get_running_loop().call_soon(self._stop_if_unwanted)

    def _stop_if_unwanted(self) -> None:
        if not self.viewers and self.task is not None:
            self.task.cancel()

    def ask_key(self) -> None:
        self.key_wanted = True

    def key_due(self) -> bool:
        """Whether the device is to be asked for a key frame now (asked, and not asked a moment ago)."""
        now = time.monotonic()
        if self.key_wanted and now - self._key_asked_at >= KEY_FRAME_EVERY:
            self.key_wanted, self._key_asked_at = False, now
            return True
        return False

    def offer(self, kind: int, key: bool, data: bytes) -> None:
        self.counter += 1
        picture = Picture(kind, key, self.counter, data)
        if key:
            self.last = picture
        for line in self.viewers:
            line.take(picture)

    def resize(self, size: tuple[int, int] | None) -> None:
        """The pictures are of this size from now on (the first time, or another size): every viewer is told, and gets a key frame next."""
        if size is None or size == self.size:
            return
        self.size = size
        if self.known():
            self.announce()

    def pace(self) -> float:
        """Pictures a second, where they are asked for one by one: as many as the fastest viewer wants, within reason."""
        return max(LEAST_FPS, min(MOST_FPS, max((line.max_fps for line in self.viewers), default=LEAST_FPS)))

    def tier(self) -> str:
        """Which size of picture to ask for or to make: the smallest that is wide enough for the widest viewer."""
        return tier_for(max((line.max_w for line in self.viewers), default=TIERS["640"][0]))

    async def _run(self) -> None:
        pause = ERROR_HOLD
        while self.viewers:
            try:
                await self.run()
                pause = ERROR_HOLD
            except asyncio.CancelledError:
                raise
            except KvmError as ex:
                if ex.code == "no_media":
                    self.machine.no_media(self)
                    return
                if getattr(self.machine.device, "console_readable", True) is False:  # settled: a server with no console the wall reads
                    self.machine.no_live(ex.message)
                    return
                # Down, or not giving a picture: said once a minute while it goes on, and tried again with a pause that grows.
                now = time.monotonic()
                if now - self._said_at >= SAY_AGAIN:
                    self._said_at = now
                    log.info("%s: no live picture for the moment: %s", self.machine.device.label, ex.message)
            except Exception as ex:  # (a bug here must not end the line, nor the wall)
                self.machine.device._unexpected("the live picture failed", ex)
            await asyncio.sleep(max(pause, 0.05))
            pause = min(BACKOFF_MAX, pause * 2)

    async def run(self) -> None:
        """Take pictures from the device and offer them, until the viewers are gone or the device fails (KvmError)."""
        raise NotImplementedError


def _as_jpeg(data: bytes) -> tuple[int, int] | None:
    """The size of a JPEG a device sent; None where it is no JPEG (a KVM without a signal may send a PNG, which the line does not carry)."""
    return picture_size(data) if data[:2] == b"\xff\xd8" else None


SPS, PPS = 7, 8  # the kinds of NAL unit that are an H.264 stream's parameter sets (sequence, picture)
MOST_NALS = 4096  # units looked through in one picture, at the most: a picture is a handful, and a hostile one is not read for ever
# Bytes of a sequence parameter set read for the picture's size, which comes after its scaling lists (a thousand bytes at
# the most: twelve lists, 480 numbers of up to 17 bits) and its picture order cycle (two thousand at the most: 255 numbers
# of up to 63 bits). Most streams say it within their first dozen bytes.
MOST_SPS = 3200
# Sequence parameter sets of another form a stream may bring in a second, beyond the few already looked at (a stream brings
# one at its start and when its picture changes size); more is no stream, and each would be read.
MOST_FORMS_A_SECOND = 8
HIGH_PROFILES = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135})  # those whose SPS says its chroma format


class _Bits:
    """An H.264 RBSP read as the standard's syntax tables read it (u(n), ue(v), se(v)); ValueError past its end."""

    def __init__(self, data: bytes) -> None:
        self._value, self._left = int.from_bytes(data, "big"), len(data) * 8

    def u(self, count: int) -> int:
        if count > self._left:
            raise ValueError("past the end")
        self._left -= count
        return (self._value >> self._left) & ((1 << count) - 1)

    def ue(self) -> int:
        """Exp-Golomb: as many zeros as the number has bits after its leading one, the one, those bits."""
        zeros = self._left - (self._value & ((1 << self._left) - 1)).bit_length()
        if zeros > 31:
            raise ValueError("no number of 32 bits")  # (also what nothing but zeros to the end is)
        self.u(zeros + 1)
        return (1 << zeros) - 1 + self.u(zeros)

    def se(self) -> int:
        number = self.ue()
        return (number + 1) // 2 if number & 1 else -(number // 2)


def sps_size(nal: bytes) -> tuple[int, int] | None:
    """The width and height of the pictures a sequence parameter set (an H.264 NAL unit of kind 7, start code and all) says
    its stream has, as a decoder makes room for them (before any cropping): None where it cannot be read. Typed from
    ITU-T H.264, 7.3.2.1.1 (the syntax of seq_parameter_set_data) and 7.3.2.1.1.1 (scaling_list)."""
    at = nal.find(b"\x00\x00\x01")
    if at < 0:
        return None
    # After the start code and the unit's header: its payload, with what was put in against start codes taken out.
    bits = _Bits(nal[at + 4 : at + 4 + MOST_SPS].replace(b"\x00\x00\x03", b"\x00\x00"))
    try:
        profile = bits.u(8)
        bits.u(16)  # its constraints, and its level
        bits.ue()  # seq_parameter_set_id
        if profile in HIGH_PROFILES:
            chroma = bits.ue()
            if chroma == 3:
                bits.u(1)  # separate_colour_plane_flag
            bits.ue()  # bit_depth_luma_minus8
            bits.ue()  # bit_depth_chroma_minus8
            bits.u(1)  # qpprime_y_zero_transform_bypass_flag
            if bits.u(1):  # seq_scaling_matrix_present_flag
                for number in range(12 if chroma == 3 else 8):
                    if bits.u(1):  # seq_scaling_list_present_flag
                        last = following = 8
                        for _ in range(16 if number < 6 else 64):
                            if following:
                                following = (last + bits.se()) % 256
                            last = following or last
        bits.ue()  # log2_max_frame_num_minus4
        order = bits.ue()  # pic_order_cnt_type
        if order == 0:
            bits.ue()  # log2_max_pic_order_cnt_lsb_minus4
        elif order == 1:
            bits.u(1)  # delta_pic_order_always_zero_flag
            bits.se()  # offset_for_non_ref_pic
            bits.se()  # offset_for_top_to_bottom_field
            cycle = bits.ue()  # num_ref_frames_in_pic_order_cnt_cycle: 255 at the most
            if cycle > 255:
                return None
            for _ in range(cycle):
                bits.se()
        bits.ue()  # max_num_ref_frames
        bits.u(1)  # gaps_in_frame_num_value_allowed_flag
        width = (bits.ue() + 1) * 16  # pic_width_in_mbs_minus1
        height = (bits.ue() + 1) * 16  # pic_height_in_map_units_minus1
        if not bits.u(1):  # frame_mbs_only_flag: where not, a map unit is a pair of fields, twice the height
            height *= 2
    except ValueError:
        return None
    return width, height


def nal_units(unit: bytes) -> list[tuple[int, int, int]]:
    """Where each NAL unit of an access unit in Annex B form begins and ends, and its kind: (start of its start code, end, kind)."""
    found: list[tuple[int, int, int]] = []
    at = unit.find(b"\x00\x00\x01")
    while at >= 0 and len(found) < MOST_NALS:
        begin = at - 1 if at > 0 and unit[at - 1] == 0 else at  # (a start code is three bytes, or four with a zero before)
        following = unit.find(b"\x00\x00\x01", at + 3)
        end = len(unit) if following < 0 else (following - 1 if following > 0 and unit[following - 1] == 0 else following)
        kind = unit[at + 3] & 0x1F if at + 3 < len(unit) else 0
        found.append((begin, end, kind))
        at = following
    return found


class ParameterSets:
    """The parameter sets an H.264 stream was last seen to carry, and a key frame made whole with them.

    A decoder can begin at a key frame only if that frame carries the stream's parameter sets (the draft promises
    every key frame does, and a browser reads the profile from them). A device that sends them once, at the start,
    and never again has them put back before every key frame that lacks them.

    And a decoder makes room for the picture the sequence parameter set says, whatever size that is: a KVM's word is
    not taken for it. A stream whose pictures would be larger than the wall shows any picture (MAX_PICTURE_PIXELS), or
    whose parameter sets cannot be read, is not passed on (KvmError `no_media`: its viewers get the pictures one by one).
    """

    def __init__(self) -> None:
        self.sps = b""
        self.pps = b""
        self._fit: deque[bytes] = deque(maxlen=4)  # sequence parameter sets read and found fit, the last few
        self._second, self._read = time.monotonic(), 0

    def _look_at(self, sps: bytes) -> None:
        if sps in self._fit:
            return
        now = time.monotonic()
        if now - self._second >= 1.0:
            self._second, self._read = now, 0
        self._read += 1
        if self._read > MOST_FORMS_A_SECOND:
            raise KvmError("no_media", "The KVM's H.264 stream changes the form of its picture far more often than a stream does", 404)
        size = sps_size(sps)
        if size is None:
            raise KvmError("no_media", "The KVM's H.264 stream says something of its picture that cannot be read", 404)
        width, height = size
        if not (0 < width <= MAX_PICTURE_SIDE and 0 < height <= MAX_PICTURE_SIDE and width * height <= MAX_PICTURE_PIXELS):
            # Small to send, enormous to make room for: it would be the browser that pays for it.
            raise KvmError("no_media", f"The KVM's H.264 stream says its picture is {width} by {height} pixels, which is not shown", 404)
        self._fit.append(sps)

    def whole(self, unit: bytes, key: bool) -> bytes:
        """`unit`, with the parameter sets it was seen to carry remembered; a key frame without them gets the last ones in front."""
        has_sps = has_pps = False
        units = nal_units(unit)
        if len(units) >= MOST_NALS:
            raise KvmError("no_media", "A picture of the KVM's H.264 stream is in more parts than any picture is", 404)  # (the rest unread)
        for begin, end, kind in units:
            if kind == SPS:
                self._look_at(unit[begin:end])
                self.sps, has_sps = unit[begin:end], True
            elif kind == PPS:
                self.pps, has_pps = unit[begin:end], True
        if not key or (has_sps and has_pps) or not (self.sps and self.pps):
            return unit
        # Put before the picture's own units, behind its delimiter where it has one (a delimiter goes first by the standard).
        after = units[0][1] if units and units[0][2] == 9 else 0
        return unit[:after] + self.sps + self.pps + unit[after:]


class H264Source(Source):
    """A kvmd KVM's own H.264 stream (stock PiKVM's media WebSocket), passed on as it comes."""

    codec = "h264"
    queue = QUEUE_H264

    def __init__(self, machine: Machine) -> None:
        super().__init__(machine)
        self.started = False  # the KVM's stream is there: until then nothing is said of it (the KVM may turn out to have none)
        # The size of the picture is what the KVM says of its video (the stream carries it as well, for a decoder).
        video = (machine.device._status or {}).get("video")
        if isinstance(video, dict) and type(video.get("width")) is int and type(video.get("height")) is int:
            self.size = (video["width"], video["height"])

    def known(self) -> bool:
        return self.started

    def word(self) -> dict[str, Any]:
        width, height = self.size or (0, 0)  # (0: not known; a decoder reads the size from the stream itself)
        return {"t": "video", "codec": self.codec, "w": width, "h": height}

    async def run(self) -> None:
        device = self.machine.device
        assert isinstance(device, KvmDevice)
        ws = await device.media_line()
        try:
            heard = Listening(ws, MOST_UNIT)
            sets = ParameterSets()
            while self.viewers:
                device.hold_stream()  # the KVM's streamer runs while somebody is connected for the picture: this is somebody
                if self.started and self.key_due():
                    await self._tell(ws, b"\x01")  # "a key frame, please", as its own page asks
                try:
                    message = await heard.message(1.0)
                except TimeoutError:
                    continue
                if isinstance(message, str):
                    if self.started:
                        continue
                    said = _parse(message)
                    if said.get("event_type") != "media":
                        continue
                    formats = said.get("event", {}).get("video") if isinstance(said.get("event"), dict) else None
                    if not isinstance(formats, dict) or "h264" not in formats:
                        raise KvmError("no_media", "The KVM's media line offers no H.264", 404)
                    await self._tell(ws, json.dumps({"event_type": "start", "event": {"type": "video", "format": "h264"}}))
                    self.started = True
                    self.announce()
                    continue
                # A picture: one byte of kind (1), one of whether it is a key frame, then the access unit.
                if len(message) < 3 or message[0] != 1:
                    continue  # (255: its answer to a ping; nothing is asked)
                key = message[1] == 1
                try:
                    unit = sets.whole(bytes(message[2:]), key)
                except KvmError as ex:
                    log.warning("%s: %s; its pictures are asked for one by one instead", device.label, ex.message)
                    raise
                self.offer(H264, key, unit)
        finally:
            # Closed to the end, in a task of its own: this one is being stopped when the last viewer leaves, and
            # a goodbye cut off halfway leaves the KVM with a connection it goes on sending into for a while.
            self.machine.lines.owed(asyncio.ensure_future(ws.close()), self.machine.device_id)

    @staticmethod
    async def _tell(ws: Any, word: str | bytes) -> None:
        try:
            async with asyncio.timeout(SAY_WITHIN):  # (never asyncio.wait_for: on Python 3.11 it can lose a stop)
                await ws.send(word)
        except TimeoutError:
            raise KvmError("dropped", "The KVM stopped taking what is said on its media line") from None
        except Exception as ex:  # (the library's words for a line that is gone)
            raise KvmError("dropped", f"The KVM's media line ended ({type(ex).__name__})") from None


class SnapshotSource(Source):
    """A kvmd KVM's pictures, asked for one after the other: what the wall's tiles get, at a faster pace."""

    codec = "jpeg"

    async def run(self) -> None:
        device = self.machine.device
        assert isinstance(device, KvmDevice)
        last = b""
        while self.viewers:
            due = time.monotonic() + 1.0 / self.pace()
            try:
                snap = await device.live_picture(self.tier())
            except KvmError as ex:
                if ex.code != "no_stream":  # (waking up: the next ask has it)
                    raise
            else:
                # Only what changed: a KVM gives a picture of a still screen as often as it is asked, byte for byte the same.
                if snap.data != last:
                    last = snap.data
                    size = _as_jpeg(snap.data)
                    if size is not None:
                        self.resize(size)
                        self.offer(JPEG, True, snap.data)
            await asyncio.sleep(max(0.0, due - time.monotonic()))


class JetSource(Source):
    """A JetKVM's picture: JPEG made of the frames this program decodes, each when there is a new one, at the viewers' pace."""

    codec = "jpeg"

    @property
    def last(self) -> Picture | None:
        """The last picture offered, for a viewer that comes or asks for a key frame; none where the JetKVM has said its
        screen is back since it (asked of the device as it is asked for, not at the next turn of the loop)."""
        awaited = getattr(self.machine.device, "picture_awaited", None)
        return None if callable(awaited) and awaited() else self._last

    @last.setter
    def last(self, picture: Picture | None) -> None:
        self._last = picture

    async def run(self) -> None:
        from .jetkvm import FRAME_STALE, QUANTIZER, encode_jpeg

        device = self.machine.device
        made_of: Any = None
        while self.viewers:
            due = time.monotonic() + 1.0 / self.pace()
            frame, at = await device.live_frame()  # type: ignore[attr-defined]
            if frame is None or time.monotonic() - at >= FRAME_STALE:
                # What was offered last is not the screen any more (from before the JetKVM said its screen was back, or too
                # old): a viewer that comes now, or asks for a key frame, is given none until the next picture.
                self.last = None
            elif frame is not made_of:
                made_of = frame
                size = self.tier()
                target = None if size == FULL or TIERS[size][0] >= frame.width else TIERS[size][0]
                data = await asyncio.to_thread(encode_jpeg, frame, target, QUANTIZER[size])
                self.resize(_as_jpeg(data))
                self.offer(JPEG, True, data)
            await asyncio.sleep(max(0.0, due - time.monotonic()))


class ConsoleSource(Source):
    """A server's screen, from its controller's console, or a PC's from its Intel AMT KVM: JPEG each time the screen has changed."""

    codec = "jpeg"

    async def run(self) -> None:
        from .redfish import QUANTIZER, screen_jpeg
        from .video import VideoSession

        encoder = VideoSession()
        device = self.machine.device
        made_of = 0
        try:
            while self.viewers:
                due = time.monotonic() + 1.0 / self.pace()
                frames, width, height, shown = await device.live_screen()  # type: ignore[attr-defined]
                if frames != made_of:
                    size = self.tier()
                    target = None if size == FULL or TIERS[size][0] >= width else TIERS[size][0]
                    try:
                        data = await asyncio.to_thread(screen_jpeg, width, height, shown, target, QUANTIZER[size], encoder)
                    except ValueError:
                        data = b""  # the screen changed size while its picture was being made: the next look has it whole
                    if data:
                        made_of = frames
                        self.resize(_as_jpeg(data))
                        self.offer(JPEG, True, data)
                await asyncio.sleep(max(0.0, due - time.monotonic()))
        finally:
            await asyncio.to_thread(encoder.close)


def _parse(text: str) -> dict[str, Any]:
    """One message of JSON, as an object; anything else, deep nesting included, comes back empty."""
    try:
        said = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return {}
    return said if isinstance(said, dict) else {}


# --- one viewer's line -------------------------------------------------------------------------------------


class Line:
    """One viewer's WebSocket: what waits to go down it, and what it holds."""

    def __init__(self, ws: WebSocket, holder: Holder, machine: Machine, wants: frozenset[str], max_w: int, max_fps: float) -> None:
        self.ws = ws
        self.holder = holder
        self.machine = machine
        self.wants = wants  # the codecs it can show
        self.max_w, self.max_fps = max_w, max_fps
        self.words: deque[str] = deque()
        self.pictures: deque[Picture] = deque()
        self.ready = asyncio.Event()
        self.needs_key = True
        self.source: Source | None = None
        self.control = False
        self.may_control = holder.may_control
        self.leaving: str | None = None  # the code the line is closing with, once `end` was called
        self.key_frame_at = float("-inf")  # when the last JPEG was sent again because the line asked for a key frame

    def say(self, word: dict[str, Any]) -> None:
        """Queue a message of text. They go before pictures, and none is ever dropped: a line with more of them waiting
        than a viewer that reads would ever let pile up is not being read, and ends as any line ends (`end`), giving up
        the machine's keyboard and mouse and what it had down there at once."""
        goodbye = word.get("t") == "bye"
        if self.leaving is not None and not goodbye:
            return
        if len(self.words) >= MOST_WORDS and not goodbye:
            self.end("slow", "This line is not being read")
            return
        self.words.append(json.dumps(word))
        self.ready.set()

    def take(self, picture: Picture) -> None:
        """A picture from the source. One that cannot be shown without a key frame waits for one; a viewer with too many waiting is brought forward."""
        if self.leaving is not None:
            return
        if self.needs_key:
            if not picture.key:
                return
            self.needs_key = False
        elif len(self.pictures) >= (self.source.queue if self.source is not None else QUEUE_JPEG):
            self.pictures.clear()
            if not picture.key:
                self.needs_key = True
                if self.source is not None:
                    self.source.ask_key()
                return
        self.pictures.append(picture)
        self.ready.set()

    def end(self, code: str, message: str) -> None:
        """Say goodbye and close, once what is said is sent. The line's own loop ends with the socket.

        What the line held of the machine (keyboard and mouse, a place among the picture's viewers) is given up
        here and now, not when the socket is found closed: a socket whose viewer has stopped reading is found
        closed late, and the machine is not kept for it meanwhile.
        """
        if self.leaving is None:
            self.leaving = code
            self.pictures.clear()
            self.say({"t": "bye", "code": code, "message": message})
            self.machine.ending(self, code)

    async def send_on(self) -> None:
        """Send what waits, in order: words first, then pictures; and close after a goodbye."""
        try:
            while True:
                await self.ready.wait()
                self.ready.clear()
                while self.words or self.pictures:
                    if self.words:
                        await self.ws.send_text(self.words.popleft())
                    else:
                        # A queued screen may outlive the account's access while the socket waits.
                        self.machine._stands(self)
                        if self.leaving is not None:
                            continue
                        await self.ws.send_bytes(self.pictures.popleft().message)
                if self.leaving is not None:
                    await self.ws.close()
                    return
        except (WebSocketDisconnect, RuntimeError, OSError, asyncio.CancelledError):
            pass  # the socket is gone; the receiving loop finds that out as well, and the line ends there


# --- one machine, and the lines to it ----------------------------------------------------------------------


class Machine:
    """What every line to one machine shares: its pictures, who holds its keyboard and mouse, and how it is."""

    def __init__(self, lines: Lines, device_id: str, device: Device) -> None:
        self.lines = lines
        self.device_id = device_id
        self.device = device
        self.viewers: set[Line] = set()
        self.sources: dict[str, Source] = {}
        self.holder: Line | None = None  # the line that has keyboard and mouse
        self.hid: Hid | None = None
        self.input_at = 0.0  # when the holder last sent input (INPUT), or took keyboard and mouse: see IDLE_GIVE_BACK
        self.state: tuple[Any, Any, Any, Any] | None = None  # what the lines were last told of how the machine is
        self.watching: asyncio.Task[None] | None = None

    async def join(self, line: Line) -> None:
        self.viewers.add(line)  # (before anything is waited for: a machine with no viewer is let go of)
        if self.state is None:
            await self._look()  # how the machine is, and how large its picture, before the line is told either
        if line.leaving is not None or line not in self.viewers:
            return  # (told goodbye while the machine was looked at: the tile edited, the wall stopping. Nothing to join.)
        self._stands(line)
        if line.leaving is not None:
            return
        self._source_for(line).add(line)
        line.say(self._state_word())
        if self.watching is None or self.watching.done():
            self.watching = asyncio.create_task(self._watch())

    def ending(self, line: Line, why: str) -> None:
        """A line is on its way out (it was told goodbye): it holds nothing of this machine from now on."""
        if line.source is not None:
            line.source.remove(line)
        if self.holder is line:
            self._let_go(line, why, None)

    async def leave(self, line: Line) -> None:
        """A line's socket is gone."""
        self.viewers.discard(line)
        self.ending(line, "closed")
        if not self.viewers:
            if self.watching is not None:
                self.watching.cancel()
            if self.lines.machines.get(self.device_id) is self:
                self.lines.machines.pop(self.device_id, None)

    def _source_for(self, line: Line) -> Source:
        kind = self.device.kind
        if kind == "kvmd" and "h264" in line.wants and not self._no_media():
            name: str = "h264"
        else:
            name = "jpeg"
        source = self.sources.get(name)
        if source is None:
            if name == "h264":
                source = H264Source(self)
            elif kind == "kvmd":
                source = SnapshotSource(self)
            elif kind == "jetkvm":
                source = JetSource(self)
            else:
                source = ConsoleSource(self)
            self.sources[name] = source
        return source

    def _no_media(self) -> bool:
        """Whether the device was found to have no H.264 line not long ago (remembered beside the machines: a machine is let go of with its last viewer)."""
        found_at = self.lines.no_media_at.get(self.device_id)
        return found_at is not None and time.monotonic() - found_at < NO_MEDIA_FOR

    def no_media(self, source: Source) -> None:
        """The device turned out to have no H.264 line: its viewers get the pictures one by one instead."""
        self.lines.no_media_at[self.device_id] = time.monotonic()
        self.sources.pop("h264", None)
        for line in list(source.viewers):
            source.remove(line)
            self._source_for(line).add(line)

    def no_live(self, why: str) -> None:
        """The device turned out to have no picture at all (a server whose console is not read): every line is told so."""
        for line in list(self.viewers):
            line.end("no_live", why)

    def _state_word(self) -> dict[str, Any]:
        state, code, message, pointer = self.state or ("connecting", None, None, None)
        word: dict[str, Any] = {"t": "state", "state": state}
        if code is not None:
            word["error"] = {"code": code, "message": message}
        if pointer is not None:
            # How its pointer can be moved: a kvmd KVM drops a move of the other kind (a real Comet whose mouse was set to
            # relative never moved its pointer to a place), and a viewer that knows uses the kind it takes.
            word["pointer"] = pointer
        return word

    async def _look(self) -> None:
        """How the machine is, as its lines are told it: said to them when it changes; and its picture's size, to an H.264 source."""
        try:
            status = await self.device.status()
        except Exception as ex:  # (a bug in a driver's status must not end every line)
            self.device._unexpected("reading the status for the live line failed", ex)
            status = {"state": "error", "error": {"code": "internal", "message": "Status could not be read"}}
        error = status.get("error") if isinstance(status.get("error"), dict) else None
        try:
            pointer = self.device.pointer_kind()
        except Exception as ex:  # (as a status that cannot be read: said, and nothing said of the pointer)
            self.device._unexpected("asking how a machine's pointer is moved failed", ex)
            pointer = None
        now = (status.get("state"), error.get("code") if error else None, plain(error.get("message"), 200) if error else None, pointer)
        if now != self.state:
            known = self.state is not None
            self.state = now
            if known:  # (the first look is said by `join`, after the picture's form)
                for line in list(self.viewers):
                    line.say(self._state_word())
            if now[1] == "in_use" and self.holder is not None:
                # Somebody opened the JetKVM's own page, which took its one viewer, and the keyboard and mouse with it
                # (a real one let go of a key this line held as it did). Said now: left to the next key, the holder
                # heard only that the connection had closed, after typing into nothing.
                self._let_go(self.holder, "in_use", now[2] or "Someone is using the KVM's own page")
        video = status.get("video") if isinstance(status.get("video"), dict) else None
        source = self.sources.get("h264")
        if source is not None and video is not None and type(video.get("width")) is int and type(video.get("height")) is int:
            source.resize((video["width"], video["height"]))

    async def _watch_status(self) -> None:
        """Device I/O has its own task: a stalled status request must not postpone revocation."""
        while self.viewers:
            try:
                await self._look()
            except Exception as ex:
                self.device._unexpected("looking at the live status failed", ex)
            await asyncio.sleep(STATE_EVERY)

    async def _watch(self) -> None:
        """Revoke idle or unauthorized control independently of device network requests."""
        checking = asyncio.create_task(self._watch_status())
        checked_at = time.monotonic()
        try:
            while self.viewers:
                if self.lines.manager.devices.get(self.device_id) is not self.device:
                    for line in list(self.viewers):
                        line.end("gone", "This machine was changed or taken off the wall. Open it again.")
                    return
                try:
                    self._idle()
                    if time.monotonic() - checked_at >= STANDING_EVERY:
                        checked_at = time.monotonic()
                        for line in list(self.viewers):
                            self._stands(line)
                except Exception as ex:
                    self.device._unexpected("looking at the live lines failed", ex)
                await asyncio.sleep(STATE_EVERY)
        finally:
            checking.cancel()
            await asyncio.gather(checking, return_exceptions=True)

    def _stands(self, line: Line) -> None:
        """Whether this line may still be here, and still act: ended, or its keyboard taken away, where not."""
        try:
            why, may_control = self.lines.standing(line.holder, self.device_id)
        except Exception as ex:
            self.device._unexpected("asking whether a live line may go on failed", ex)
            line.end("internal", "qKVM could not find out whether this line may go on")
            return
        if why is not None:
            line.end(why, SAID.get(why, "This line may not go on"))
        elif not may_control:
            line.may_control = False
            if self.holder is line:
                self._let_go(line, "not_allowed", "Your account may no longer act on this machine")

    def _idle(self) -> None:
        """Keyboard and mouse given back by themselves, where whoever holds them has sent no input for IDLE_GIVE_BACK."""
        if self.holder is not None and time.monotonic() - self.input_at >= IDLE_GIVE_BACK:
            self._let_go(self.holder, "idle", f"Given back after {_duration(IDLE_GIVE_BACK)} without input")

    # --- keyboard and mouse ---

    def _not_taken(self, line: Line, take: bool, taking_from: str | None) -> dict[str, Any] | None:
        """Where somebody else holds keyboard and mouse: the refusal this line gets, or None where it takes them over.

        Only an admin, in person, takes them over (`Lines.may_take`, asked at this moment: a role lowered a second ago
        counts), and only from whom they were asked about (`taking_from`, the `by` of the refusal they were shown, which a
        take-over has to say): whoever holds them now may be somebody else by the time the question was answered. A check
        of the account that fails is no yes: the line ends (`internal`), as one whose standing cannot be found out does."""
        assert self.holder is not None
        by = self.holder.holder.name[:MOST_NAME]
        if not take:
            return refused("taken", "Somebody else has this machine's keyboard and mouse", by=by)
        try:
            may_take = self.lines.may_take(line.holder, self.device_id)
        except Exception as ex:
            self.device._unexpected("asking whether a live line may take keyboard and mouse over failed", ex)
            line.end("internal", "qKVM could not find out whether this line may go on")
            return refused("taken", "Somebody else has this machine's keyboard and mouse", by=by)
        if not may_take:
            return refused("taken", "Somebody else has this machine's keyboard and mouse, and only an admin may take them over", by=by)
        if taking_from is None:
            return refused("taken", "Somebody else has this machine's keyboard and mouse: a take-over says whom it takes them from", by=by)
        if taking_from != by:
            return refused("taken", "Somebody else has this machine's keyboard and mouse by now", by=by)
        return None

    async def control(self, line: Line, on: bool, take: bool = False, taking_from: str | None = None) -> dict[str, Any]:
        """A line asks for keyboard and mouse, or gives them back: the answer it gets. `take`: from whoever holds them, as
        an admin may (`_not_taken`); they lose them as a line loses them for any reason (`_let_go`), and are told who took
        them. The new holder's first word waits until everything of theirs is through (`handed_over`)."""
        if not on:
            if self.holder is line:
                self._let_go(line, None, None)
            return {"t": "control", "on": False}
        self._stands(line)
        if line.leaving is not None or line not in self.viewers:
            return refused("not_allowed", "This line may no longer act on this machine")
        if self.holder is line:
            return {"t": "control", "on": True}
        if not line.may_control:
            return refused("not_allowed", "Your account may look at this machine, not act on it")
        if self.holder is not None and (refusal := self._not_taken(line, take, taking_from)) is not None:
            return refusal
        if self.lines.busy(self.device_id):
            return refused("busy", f"Something else is being done to {self.device.spec.name} at this moment. Wait for it to finish.")
        hid = self._hid()
        if hid is None:
            return refused("no_input", "This machine's console takes no keyboard or mouse from qKVM yet")
        # Made in a task of its own, waited for WAY_IN_WITHIN at the most (the page waits a little longer for this answer).
        # One not made in time is not cut off (it may be a sign-in on a connection that stays in use), and is closed once
        # it is made.
        opening = asyncio.ensure_future(hid.open())
        try:
            await asyncio.wait({opening}, timeout=WAY_IN_WITHIN)
        except asyncio.CancelledError:
            opening.cancel()  # (the line is being stopped, with the wall: what it opened is closed all the same)
            self._owe(asyncio.create_task(self._close_hid(hid, held=False)))
            raise
        if not opening.done():
            self._owe(asyncio.create_task(self._close_once_made(hid, opening)))
            return refused("timeout", f"{self.device.spec.name} did not hand over its keyboard and mouse within {int(WAY_IN_WITHIN)} seconds")
        try:
            opening.result()
        except KvmError as ex:
            return refused(ex.code, ex.message)
        # (Asked again, after the wait that making the way in is: the account may have lost permission, another line or an
        # action from the page may have come meanwhile, or whoever held them may have given them back. A standing check
        # during the wait may already have lowered may_control while this line held nothing; it must still refuse the
        # grant now. No wait separates this fresh check from the grant. An unused way in is closed in a task of its own.)
        if line in self.viewers and line.leaving is None:
            self._stands(line)
        refusal = refused("taken", "Somebody else has this machine's keyboard and mouse") if line not in self.viewers or line.leaving is not None else None
        if refusal is None and not line.may_control:
            refusal = refused("not_allowed", "Your account may look at this machine, not act on it")
        if refusal is None and self.holder is not None:
            refusal = self._not_taken(line, take, taking_from)
        if refusal is None and self.lines.busy(self.device_id):
            refusal = refused("busy", f"Something else is being done to {self.device.spec.name} at this moment. Wait for it to finish.")
        if refusal is not None:
            self._owe(asyncio.create_task(self._close_hid(hid, held=False)))
            return refusal
        taken_from = self.holder
        if taken_from is not None:
            self._let_go(taken_from, "taken", f"{line.holder.name} took over this machine's keyboard and mouse", by=line.holder.name)
        self.holder, self.hid, line.control = line, hid, True
        hid.authorized = lambda: self._input_allowed(line, hid)
        self.input_at = time.monotonic()
        detail: dict[str, Any] = {"user": line.holder.name, "device": self.device.spec.name, "device_id": self.device_id, "on": True}
        if taken_from is not None:
            detail["from"] = taken_from.holder.name
        self.lines.audit("live_control", line.holder.ip, **detail)
        # (The activity log has it. Not said again in the program's log but at DEBUG: sixty a minute of each account is a
        # line a second in qkvm.log, from one person who takes and gives back in a loop.)
        if taken_from is None:
            log.debug("%s: keyboard and mouse taken by %s", self.device.label, line.holder.name)
        else:
            log.debug("%s: keyboard and mouse taken over by %s from %s", self.device.label, line.holder.name, taken_from.holder.name)
        return {"t": "control", "on": True}

    def _hid(self) -> Hid | None:
        hid: Hid
        if isinstance(self.device, KvmDevice):
            hid = KvmdHid(self.device)
        elif self.device.kind == "jetkvm":
            hid = JetHid(self.device)
        elif self.device.kind in ("amt", "proxmox"):
            hid = RfbHid(self.device)
        elif self.device.kind == "redfish" and getattr(self.device, "takes_keys", False):
            hid = RedfishHid(self.device)  # (a server over AMI's console; OpenBMC's shows the screen but takes no keys yet)
        else:
            return None
        hid.owe = self._owe
        return hid

    def _owe(self, task: asyncio.Task[None]) -> None:
        self.lines.owed(task, self.device_id)

    def _let_go(self, line: Line, why: str | None, message: str | None, by: str | None = None) -> None:
        """Keyboard and mouse leave this line: given back (no reason), or taken away for a reason, which the line is told unless it is going.
        `by`: who took them over (why "taken"), which the line is told and the log says.

        Only from the line that holds them. A line that lost them a moment ago may still have a word on its way that
        fails now, and its failure is no reason to take them from whoever holds them since."""
        if self.holder is not line:
            return
        hid, self.holder, self.hid, line.control = self.hid, None, None, False
        if hid is not None:
            hid.end()  # (at once: a word of the line's still on its way finds the line gone when it is through)
        if why is not None and why != "closed":
            line.say(refused(why, message or "", by=by))  # (said to a line that is leaving: nothing, its goodbye says why)
        detail: dict[str, Any] = {"user": line.holder.name, "device": self.device.spec.name, "device_id": self.device_id, "on": False}
        if why is not None:
            detail["why"] = why
        if by is not None:
            detail["by"] = by
        if why == "idle":
            minutes = IDLE_GIVE_BACK / 60
            detail["minutes"] = int(minutes) if minutes == int(minutes) else round(minutes, 2)
        self.lines.audit("live_control", line.holder.ip, **detail)
        log.debug("%s: keyboard and mouse %s %s", self.device.label, "given back by" if why is None else f"taken from ({why})", line.holder.name)
        if hid is not None:
            # What the line had down is let go of in a task of its own, within a time: not inside the ending of the line
            # (which may be being stopped), and not inside the asking of the next line. That one's words wait for it, and
            # for what this line still had on its way (`handed_over`).
            hid.letting_go = asyncio.create_task(self._close_hid(hid))
            self._owe(hid.letting_go)
            # (Kept beside the machines, not in this one, which goes with its last viewer: a holder that was the only one
            # leaves while its letting go is under way, and whoever comes next, on a machine made anew, waits for it.)
            handing = self.lines.handing
            handing[self.device_id] = [before for before in handing.get(self.device_id, ()) if not before.is_through()] + [hid]

    @classmethod
    async def _close_once_made(cls, hid: Hid, opening: asyncio.Future[None]) -> None:
        """A way in that was being made for an asking nobody waits for any more: closed once it is made, without a letting go
        (it held nothing). One whose making failed has nothing to close."""
        hid.end()  # (nothing goes through it from now on)
        await asyncio.wait({opening})
        if opening.cancelled() or opening.exception() is not None:
            return
        await cls._close_hid(hid, held=False)

    @staticmethod
    async def _close_hid(hid: Hid, held: bool = True) -> None:
        """Let go of what the line had down through this way in, and close it. `held`: it held the keyboard; one that never
        did has nothing down, and is closed without a word: a JetKVM's letting go is the whole state of its keyboard and
        mouse, on the connection that whoever holds them now uses, and would let go of their keys."""
        hid.end()
        try:
            async with asyncio.timeout(LET_GO_WITHIN):
                try:
                    if held:
                        await hid.release_all()
                finally:
                    await hid.close()
        except (KvmError, TimeoutError, OSError):
            pass  # the device is gone, and with it what it held down
        except Exception:
            log.debug("letting go of keys and buttons failed", exc_info=True)

    def _input_allowed(self, line: Line, hid: Hid) -> bool:
        """Recheck delayed input at dispatch. Cleanup releases never depend on continued access."""
        if self.holder is not line or self.hid is not hid:
            return False
        self._stands(line)
        return self.holder is line and self.hid is hid and not hid.ended

    async def input(self, line: Line, word: dict[str, Any]) -> None:
        """A key, the pointer, a button or the wheel from the line that holds them. From any other line: nothing."""
        if self.holder is not line or self.hid is None:
            return
        self._stands(line)
        if self.holder is not line or self.hid is None:
            return
        hid, kind = self.hid, word.get("t")
        if kind in INPUT:
            self.input_at = time.monotonic()
        if self.lines.handing.get(self.device_id):
            await handed_over(self.lines.handing, self.device_id)
            self._stands(line)
            if self.holder is not line or self.hid is not hid:
                return  # (taken from this line while it waited)
        with hid.sending():
            await self._send(line, hid, kind, word)

    async def _send(self, line: Line, hid: Hid, kind: Any, word: dict[str, Any]) -> None:
        """One word of the holder's, through its way in."""
        try:
            if kind == "k":
                usage, down = _number(word.get("u"), FIRST_KEY, LAST_KEY), word.get("d")
                if usage is not None and usage not in NOT_SENT and isinstance(down, bool):
                    await hid.key(usage, down)
            elif kind == "m":
                x, y = _number(word.get("x"), 0, FARTHEST), _number(word.get("y"), 0, FARTHEST)
                if x is not None and y is not None:
                    await hid.place(x, y)
            elif kind == "mr":
                for dx, dy in _steps(word.get("dx"), word.get("dy")):
                    await hid.move(dx, dy)
            elif kind == "mb":
                button, down = _number(word.get("b"), 1, 5), word.get("d")
                if button is not None and isinstance(down, bool):
                    await hid.button(button, down)
            elif kind == "mw":
                dx, dy = _notches(word.get("dx")), _notches(word.get("dy"))
                if dx or dy:
                    await hid.wheel(dx, dy)
            elif kind == "up":
                await hid.release_all()
        except KvmError as ex:
            if self.holder is not line or self.hid is not hid:
                return  # (taken from this line while the word was on its way: whoever holds them now keeps them)
            if ex.code == "in_use":  # (its own page took it: said as such, as the look that notices says it)
                self._let_go(line, "in_use", ex.message)
            else:
                self._let_go(line, "dropped", f"The machine stopped taking keys and the mouse: {ex.message}")


async def handed_over(handing: dict[str, list[Hid]], device_id: str) -> None:
    """What the lines that held this machine's keyboard and mouse before had on their way, and the letting go of what they
    had down, is through: the next holder's first word goes after that, and an action from the page, within
    HAND_OVER_WITHIN. (Gone before it, a key of the new holder's landed beside a Ctrl of the one before that was still down
    on the machine, or was let go of by that one's late letting go of the same key.) `handing`: Lines.handing."""
    waited = list(handing.get(device_id, ()))
    try:
        async with asyncio.timeout(HAND_OVER_WITHIN):
            for before in waited:
                await before.until_through()
                kept = handing.get(device_id)
                if kept is not None and before in kept:
                    kept.remove(before)
    except TimeoutError:
        # Given up on, these and only these: a way in let go of while this waited is waited for by whoever comes next.
        log.debug("what the holder before had on its way was not through in time; the next words go")
        handing[device_id] = [before for before in handing.get(device_id, ()) if before not in waited]
    if not handing.get(device_id):
        handing.pop(device_id, None)


SAID = {
    "signed_out": "You were signed out",
    "not_allowed": "Your account may no longer look at this machine",
    "not_found": "This machine is no longer on your wall",
}


class Lines:
    """The live lines of one wall: the passes given out, and the machines with lines to them."""

    def __init__(
        self,
        manager: DeviceManager,
        standing: Standing,
        busy: Callable[[str], bool],
        audit: Callable[..., None],
        may_take: Callable[[Holder, str], bool] = lambda holder, device_id: False,
    ) -> None:
        self.manager = manager
        self.standing = standing
        self.busy = busy  # whether something else is being done to this machine at this moment (an action from the page)
        self.audit = audit
        # Whether whoever was given this pass may take this machine's keyboard and mouse from whoever holds them, at this
        # moment: an admin in person (the server knows the accounts). Nobody, where it is not said.
        self.may_take = may_take
        self.passes: dict[str, Pass] = {}
        self.machines: dict[str, Machine] = {}
        self.no_media_at: dict[str, float] = {}  # device id -> when it was found to have no H.264 line (a Comet)
        self._owed: dict[str, set[asyncio.Task[None]]] = {}  # device id -> what is still being let go of on it, or closed
        self._open: Counter[str] = Counter()  # account (Holder.user_id) -> lines it has open
        # Device id -> the ways in of the lines that held its keyboard and mouse, until what they had on their way and down is
        # through (`handed_over`). Beside the machines, as `_owed` is: a machine goes with its last viewer.
        self.handing: dict[str, list[Hid]] = {}
        # Account (Holder.user_id) -> (entries of live views it may still write, when that was counted, those left out since).
        self._said_live: dict[str, tuple[float, float, int]] = {}
        # Account (Holder.user_id) -> when it took or gave back keyboard and mouse within the last minute (MOST_CONTROL_A_MINUTE).
        self._control_said: dict[str, deque[float]] = {}

    def control_said(self, holder: Holder) -> bool:
        """One more taking or giving back of keyboard and mouse by this account, on any of its lines: False where that would
        be more than MOST_CONTROL_A_MINUTE within a minute (and then it is not counted: what is refused writes nothing)."""
        now = time.monotonic()
        if len(self._control_said) > 256:  # (accounts and tokens that have not asked within the minute are forgotten)
            for user_id, times in list(self._control_said.items()):
                if not times or now - times[-1] > 60.0:
                    del self._control_said[user_id]
        said = self._control_said.setdefault(holder.user_id, deque())
        while said and now - said[0] > 60.0:
            said.popleft()
        if len(said) >= MOST_CONTROL_A_MINUTE:
            return False
        said.append(now)
        return True

    def said_live(self, event: str, holder: Holder, **detail: Any) -> None:
        """A live view opened or ended, into the activity log: within the account's allowance (LIVE_SAID_AN_HOUR)."""
        now = time.monotonic()
        left, at, unsaid = self._said_live.get(holder.user_id, (float(LIVE_SAID_AN_HOUR), now, 0))
        left = min(float(LIVE_SAID_AN_HOUR), left + (now - at) * LIVE_SAID_AN_HOUR / 3600)
        if left < 1:
            self._said_live[holder.user_id] = (left, now, unsaid + 1)
            return
        self._said_live[holder.user_id] = (left - 1, now, 0)
        self.audit(event, holder.ip, **detail, **({"unsaid": unsaid} if unsaid else {}))

    @staticmethod
    def offers(device: Device) -> bool:
        """Whether a machine of this kind can be had live at all."""
        if device.kind in ("kvmd", "jetkvm"):
            return True
        return bool(getattr(device, "console_readable", False))

    def held_by(self, device_id: str) -> str | None:
        """Who holds this machine's keyboard and mouse over a live line at this moment, by the name a refusal gives (`by`:
        an account's name, a token's or a wall screen's with "(token)"); None where nobody does."""
        machine = self.machines.get(device_id)
        if machine is None or machine.holder is None:
            return None
        return machine.holder.holder.name[:MOST_NAME]

    async def handed_over(self, device_id: str) -> bool:
        """What the lines that held this machine's keyboard and mouse last had on their way, and the letting go of what they
        had down, is through (within HAND_OVER_WITHIN): an action from the page waits for it, as the next holder does, so
        that what it types does not land beside a Ctrl the last holder still had down. Waits only; cancels nothing.
        Whether there was anything to wait for."""
        if not self.handing.get(device_id):
            return False
        await handed_over(self.handing, device_id)
        return True

    def issue(self, device_id: str, holder: Holder) -> str:
        """A pass for one line to this machine, good for half a minute and for one use.

        KvmError `busy` (429) where the account has as many lines open and passes out as it may (MOST_LINES_EACH), or the
        wall as many passes out as it gives: never by taking another's pass away, which anybody who may look at one
        machine could do to everybody's by asking for passes by the hundred."""
        now = time.monotonic()
        for ticket in [ticket for ticket, given in self.passes.items() if given.until < now]:
            del self.passes[ticket]
        theirs = sum(1 for given in self.passes.values() if given.holder.user_id == holder.user_id)
        if theirs + self._open[holder.user_id] >= MOST_LINES_EACH:
            raise KvmError("busy", f"This account has {MOST_LINES_EACH} live pictures open, or about to be: close one first", 429)
        if len(self.passes) >= MOST_PASSES:
            raise KvmError("busy", "Live pictures are being opened on this wall by the hundred just now. Try again in a moment.", 429)
        ticket = secrets.token_urlsafe(24)
        self.passes[ticket] = Pass(device_id, holder, now + PASS_LASTS)
        return ticket

    def redeem(self, ticket: Any, device_id: str) -> Holder | None:
        """Whom this pass was given to, for this machine: None where it is no pass, was used, or has run out. Used up by this."""
        if not isinstance(ticket, str) or not TICKET.fullmatch(ticket):
            return None
        given = self.passes.pop(ticket, None)
        if given is None or given.device_id != device_id or given.until < time.monotonic():
            return None
        return given.holder

    def owed(self, task: asyncio.Task[None], device_id: str) -> None:
        """What a device is still owed (a letting go, a line closed to the end): waited for, within a time, before its connection is closed."""
        tasks = self._owed.setdefault(device_id, set())
        tasks.add(task)

        def done(task: asyncio.Task[None]) -> None:
            tasks.discard(task)
            if not tasks and self._owed.get(device_id) is tasks:
                del self._owed[device_id]

        task.add_done_callback(done)

    async def serve(self, ws: WebSocket, device_id: str, address: str) -> None:
        """One line, from its first message to its end. `address`: whom the line comes from, as the pass's holder was seen."""
        await ws.accept()
        hello = await self._hello(ws)
        holder = self.redeem(hello.get("ticket"), device_id) if hello.get("t") == "hello" and hello.get("v") == FORM else None
        if holder is None or holder.ip != address:
            # (A pass is for the address it was given to: one handed on to another host is no pass there.)
            await self._turn_away(ws, "no_pass", "This live line was not let in: it showed no pass this qKVM gave for it")
            return
        why, may_control = self.standing(holder, device_id)
        device = self.manager.devices.get(device_id)
        if why is not None or device is None:
            await self._turn_away(ws, why or "not_found", SAID.get(why or "not_found", "This line may not go on"))
            return
        if not self.offers(device):
            await self._turn_away(ws, "no_live", "This machine has no live picture")
            return
        wants = frozenset(codec for codec in ("h264", "jpeg") if isinstance(hello.get("video"), list) and codec in hello["video"])
        max_w = _number(hello.get("max_w"), 1, MOST_WIDTH) or TIERS["640"][0]
        max_fps = float(_number(hello.get("max_fps"), 1, 1000) or MOST_FPS)
        machine = self.machines.get(device_id)
        if machine is None or machine.device is not device:
            machine = self.machines[device_id] = Machine(self, device_id, device)
        line = Line(ws, Holder(holder.user_id, holder.name, may_control, holder.ip, holder.session, holder.token), machine, wants or frozenset({"jpeg"}), max_w, max_fps)
        log.debug("%s: a live line for %s", device.label, holder.name)
        # Who looked at a machine's screen, and for how long, is in the activity log: a screen can show what a keyboard
        # never typed (a password manager open, a document), and after an incident that is asked.
        opened = time.monotonic()
        seen = {"user": holder.name, "device": device.spec.name, "device_id": device_id}
        self.said_live("live_opened", holder, **seen)
        self._open[holder.user_id] += 1  # (the pass it came by was counted until now: `issue`)
        sending = asyncio.create_task(line.send_on())
        try:
            await machine.join(line)  # (in here: a line stopped while the machine is looked at leaves it as any other)
            await self._listen(line)
        except asyncio.CancelledError:
            pass  # the web server is stopping and cut the line off: it ends as any other, and that is no error of the program's
        finally:
            # (Written first, before anything is waited for: a line that is cut off in the waiting below is still said to have ended.)
            self.said_live("live_closed", holder, **seen, seconds=round(time.monotonic() - opened), why=line.leaving or "closed")
            self._open[holder.user_id] -= 1
            if self._open[holder.user_id] <= 0:
                del self._open[holder.user_id]
            await machine.leave(line)
            line.leaving = line.leaving or "closed"
            line.ready.set()
            sending.cancel()
            log.debug("%s: the live line for %s ended (%s)", device.label, holder.name, line.leaving)

    @staticmethod
    async def _hello(ws: WebSocket) -> dict[str, Any]:
        try:
            async with asyncio.timeout(HELLO_WITHIN):
                first = await ws.receive()
        except (TimeoutError, WebSocketDisconnect, RuntimeError):
            return {}
        text = first.get("text")
        return _parse(text) if isinstance(text, str) and len(text) <= MOST_WORD else {}

    @staticmethod
    async def _turn_away(ws: WebSocket, code: str, message: str) -> None:
        try:
            await ws.send_text(json.dumps({"t": "bye", "code": code, "message": message}))
            await ws.close()
        except (WebSocketDisconnect, RuntimeError, OSError):
            pass

    async def _listen(self, line: Line) -> None:
        """Take what the viewer says, until the socket is gone."""
        machine, ws = line.machine, line.ws
        second, count = time.monotonic(), 0
        # What came while an asking for keyboard and mouse was being answered (`answer_to`), taken in turn after it; and a
        # reading of the socket begun then and not over yet.
        kept: deque[tuple[Any, MutableMapping[str, Any]]] = deque()  # (its `t`, where it has one; the message)
        reading: asyncio.Future[MutableMapping[str, Any]] | None = None

        def keep(message: MutableMapping[str, Any]) -> None:
            """What came while an asking was answered, kept for after. A new size of the view, or a key frame asked for
            again, is folded into the one kept (a page sends its size at every step of a window being dragged); beyond
            MOST_WORDS of anything else the line is flooding, and ends (the asking then finds it gone)."""
            text = message.get("text")
            kind = _parse(text).get("t") if isinstance(text, str) and len(text) <= MOST_WORD else None
            if kind in ("shape", "key_frame"):
                for at, (before, _) in enumerate(kept):
                    if before == kind:
                        if kind == "shape":
                            kept[at] = (kind, message)  # (the newest size; where it stands among the rest does not matter)
                        return
            if len(kept) >= MOST_WORDS:
                line.end("flooding", "This line sent far more while keyboard and mouse were being asked for than a viewer has reason to")
                return
            kept.append((kind, message))

        async def answer_to(asking: Coroutine[Any, Any, dict[str, Any]]) -> dict[str, Any]:
            """The answer to an asking for keyboard and mouse, which takes as long as the way in to the machine takes (up to
            WAY_IN_WITHIN). Meanwhile the socket is read, never left unread (a socket not read is not found closed), and what
            comes is kept for after, in turn: a viewer that went away meanwhile (the view closed, the page left) ends the line
            at once, so that the asking finds it gone once the way in is made, and a take-over takes nothing from whoever
            holds the machine for nobody."""
            nonlocal reading
            answering = asyncio.ensure_future(asking)
            gone = False
            try:
                while not answering.done():
                    if reading is None and not gone:
                        reading = asyncio.ensure_future(ws.receive())
                    waits: set[asyncio.Future[Any]] = {answering} if reading is None else {answering, reading}
                    await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
                    if reading is not None and reading.done():
                        came, reading = reading, None
                        try:
                            message = came.result()
                        except (WebSocketDisconnect, RuntimeError):
                            message = {"type": "websocket.disconnect"}
                        if message.get("type") == "websocket.disconnect":
                            kept.append((None, message))
                            gone = True
                            line.end("closed", "The viewer went away")
                        elif line.leaving is None:
                            keep(message)
                        # (Once the line is ending, what else comes is read and dropped, as the loop below drops it.)
            except asyncio.CancelledError:
                answering.cancel()  # (the line is being stopped: the asking is, as when it was answered in this task)
                if reading is not None:
                    reading.cancel()
                raise
            return answering.result()

        while line.leaving is None or ws.client_state == WebSocketState.CONNECTED or kept or reading is not None:
            try:
                if kept:
                    message = kept.popleft()[1]
                elif reading is not None:
                    came, reading = reading, None
                    message = await came
                else:
                    message = await ws.receive()
            except (WebSocketDisconnect, RuntimeError):
                return
            if message.get("type") == "websocket.disconnect":
                return
            now = time.monotonic()
            if now - second >= 1.0:
                second, count = now, 0
            count += 1
            if count > MOST_A_SECOND:
                line.end("flooding", "This line sends far more than a viewer has reason to")
                continue
            text = message.get("text")
            if not isinstance(text, str):
                continue  # (the draft has nothing in bytes from a viewer)
            if len(text) > MOST_WORD:
                line.end("bad_message", "A message on this line was longer than any the line carries")
                continue
            word = _parse(text)
            kind = word.get("t")
            if line.leaving is not None:
                continue
            if kind == "key_frame":
                source = line.source
                if source is not None and source.codec == "jpeg":
                    # Every picture of JPEG is a key frame: the last one is sent again (a still screen sends no other), once
                    # in KEY_FRAME_EVERY at the most. Asked two thousand times a second, it was sent two thousand times.
                    if source.last is not None and now - line.key_frame_at >= KEY_FRAME_EVERY:
                        line.key_frame_at = now
                        line.needs_key = True
                        line.pictures.clear()
                        line.take(source.last)
                elif source is not None:
                    line.needs_key = True
                    line.pictures.clear()
                    source.ask_key()  # (asked of the device once in KEY_FRAME_EVERY at the most: Source.key_due)
            elif kind == "shape":
                line.max_w = _number(word.get("max_w"), 1, MOST_WIDTH) or line.max_w
                line.max_fps = float(_number(word.get("max_fps"), 1, 1000) or line.max_fps)
            elif kind == "control":
                on = word.get("on")
                if not isinstance(on, bool):
                    continue
                if not self.control_said(line.holder):
                    line.end("flooding", "This account takes and gives back keyboard and mouse far more often than a person would")
                    continue
                # `take`: from whoever holds them (true, and nothing else, asks it); `from`: whom, as a text, which a take-over
                # has to say (left out, null or of another kind, it takes nothing from anybody: Machine._not_taken).
                said_from = word.get("from")
                taking_from = said_from if isinstance(said_from, str) else None
                line.say(await answer_to(machine.control(line, on, take=word.get("take") is True, taking_from=taking_from)))
            elif kind in ("k", "m", "mr", "mb", "mw", "up"):
                await machine.input(line, word)

    async def retiring(self, device: Device) -> None:
        """This device's connection is about to be closed (the tile edited or removed, the wall locking itself): its lines
        are told, and what they had down on it is let go of through it first, within a time."""
        machine = self.machines.get(device.spec.id)
        if machine is not None and machine.device is device:
            for line in list(machine.viewers):
                line.end("gone", "This machine was changed or taken off the wall. Open it again.")
        # Also where it has no line any more: the last one to hold its keyboard may have left a moment ago, and its letting
        # go still goes through this connection. (Closed at once, it was cut off.)
        await self._settle(device.spec.id)
        # Taken off the wall, nothing comes next to wait for what is left; edited, the next holder on the new connection
        # waits for what is not through yet (the old connection's words fail once it is closed).
        handing = [before for before in self.handing.get(device.spec.id, ()) if not before.is_through()]
        if handing and device.spec.id in self.manager.devices:
            self.handing[device.spec.id] = handing
        else:
            self.handing.pop(device.spec.id, None)

    async def close(self) -> None:
        """The wall is stopping: every line is told (and so lets go of what it has down), and what is owed to the devices is waited for, within a time."""
        for machine in list(self.machines.values()):
            for line in list(machine.viewers):
                line.end("closing", "qKVM is stopping")
        await self._settle(None)

    async def _settle(self, device_id: str | None) -> None:
        """What is owed to this device (None: to every device) is waited for, within STOP_WITHIN: another machine's is not this one's to wait for."""
        owed = self._owed.values() if device_id is None else [self._owed.get(device_id, set())]
        pending = {task for tasks in owed for task in tasks if not task.done()}
        if pending:
            await asyncio.wait(pending, timeout=STOP_WITHIN)
