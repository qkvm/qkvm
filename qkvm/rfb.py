"""The RFB protocol, which VNC speaks: a server's screen kept as pixels, and keys and a pointer sent to it.

Typed from RFC 6143 and IANA's registry of its numbers; the Tight encoding from TightVNC's own description
of it; the keys from X11's list of keysyms and the USB HID usage tables. No other program's code was taken.

The shape of it: a `Stream` is the bytes to and from the server (a TCP connection, TLS over one, or a
WebSocket carrying the same bytes, as OpenBMC's console does; or whatever an already-open connection is
wrapped in). A `Client` speaks the protocol over one: the handshake with either way of signing in that the
RFC has (none, and the DES challenge the RFC calls cryptographically weak), one pixel format of this
program's choosing, the encodings it reads (Raw, CopyRect, Hextile, ZRLE, Tight with JPEG), the server's
other messages, and the key and pointer events. Its output is the screen as three bytes a pixel in `rgb`,
and a count of the frames that have changed it.

Nothing here trusts the server. What it says the screen is, is held to a size; every length it sends is
checked against that screen before any room is taken for it; a rectangle outside the screen, a tile stream
that inflates past what its rectangle can hold, a message of a kind this program does not read, a length
that is no length: the connection ends with a named error (`RfbError`), never with a guess at what was
meant. Every read has a time it must come within, and a message as a whole has one. What a server sends
unasked (some push full frames at their own pace and ignore the incremental flag) is read all the same,
and let go of without being drawn while nobody wants pictures. And what it costs is shared out: the event
loop is let go of every few milliseconds however much has arrived, and the drawing threads, in which every
server's pictures are drawn, take one server's a slice at a time; reading and drawing take one server's share
of the program's time and every server's together no more than theirs; a JPEG is waited for in a thread of
its server's own; and what every server's updates hold at once is held to HELD_ALL.
"""

from __future__ import annotations

import asyncio
import bisect
import itertools
import logging
import re
import socket
import ssl
import struct
import time
import types
import zlib
from collections.abc import Awaitable, Callable, Generator, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .kvm import picture_size
from .video import VideoSession

log = logging.getLogger("qkvm")

# --- the numbers, from the RFC and the registry -------------------------------------------------------------

VERSION = re.compile(rb"RFB (\d{3})\.(\d{3})\n")
SECURITY_INVALID, SECURITY_NONE, SECURITY_VNC = 0, 1, 2
# What the registry calls the ways of signing in that this program does not speak, for a tile to say so.
SECURITY_NAMES = {5: "RA2", 6: "RA2ne", 16: "Tight", 17: "Ultra", 18: "TLS", 19: "VeNCrypt", 20: "SASL", 21: "MD5", 22: "xvp", 30: "Apple remote desktop"}

# Client messages.
SET_PIXEL_FORMAT, SET_ENCODINGS, UPDATE_REQUEST, KEY_EVENT, POINTER_EVENT, CLIENT_CUT_TEXT = 0, 2, 3, 4, 5, 6
# Server messages.
UPDATE, COLOUR_MAP, BELL, SERVER_CUT_TEXT = 0, 1, 2, 3

# Encodings, and the pseudo-encodings that ask for something other than pixels.
RAW, COPY_RECT, HEXTILE, TIGHT, ZRLE = 0, 1, 5, 7, 16
DESKTOP_SIZE = -223
JPEG_QUALITY = -24  # -32 is the lowest quality, -23 the highest: Tight sends JPEG only when one is asked for
ENCODINGS = (TIGHT, ZRLE, HEXTILE, COPY_RECT, RAW, DESKTOP_SIZE, JPEG_QUALITY)  # in order of preference

# The pixel format this program asks for: 32 bits a pixel, 24 of them colour, little-endian, red in the
# lowest byte. On the wire a pixel is then R, G, B and a byte of nothing; ZRLE's three-byte pixel is R, G, B
# (the least significant three bytes); Tight's is R, G, B whatever the format. Always sent, whatever the
# server's own format is: a server left to its own has been known to send its pixels the wrong way round.
PIXEL_FORMAT = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 0, 8, 16)
# ...and the one a server that takes no other is asked for (Intel AMT's KVM resets the connection at any format of
# 32 bits; seen on a real one): 16 bits, little-endian, red in the top five, green in the middle six, blue in the
# low five. Read in Raw (and CopyRect) only: the other encodings carry pixels of their own shapes in this format.
PIXEL_FORMAT_565 = struct.pack(">BBBBHHHBBBxxx", 16, 16, 0, 1, 31, 63, 31, 11, 5, 0)
RGB888, RGB565 = "rgb888", "rgb565"

# --- what the server is held to ---------------------------------------------------------------------------------

LARGEST_SIDE = 8192  # pixels a screen may be wide or tall (8K video is 7680 by 4320)
MOST_PIXELS = 16_000_000  # ...and have in all (a 5K screen has 14.7 million): three bytes each, kept in memory
MOST_NAME = 1024  # bytes of the name a server gives itself that are read
MOST_REASON = 1024  # ...and of the reason it gives for a refusal
MOST_CUT_TEXT = 1024 * 1024  # bytes of clipboard a server may send (it is read and let go of)
TIGHT_WIDEST = 2048  # a Tight rectangle may be no wider, by its own description
MOST_MESSAGES_A_SECOND = 2000  # messages in one second before a server is taken to be flooding
MOST_RECTANGLES_A_SECOND = 50_000  # rectangles in one second: a screen of tiles is one rectangle, or a few thousand (Hextile's tiles count: see below)
MOST_RESIZES_A_SECOND = 10  # changes of the screen's size in one second (a server changes it a few times a minute at most)
# The drawing thread's work is held to the screen too: a few bytes on the wire can say "fill the screen", and the
# thread's time is what every tile's picture is made in.
MOST_SCREENS_AN_UPDATE = 4  # pixels drawn by one update, in screens (rectangles may overlap, within reason)
MOST_SCREENS_A_SECOND = 16  # ...and in one second, weighted by what each kind of rectangle costs to draw...
LEAST_WORK_A_SECOND = 8_000_000  # ...and never less than this many, so that a small screen pushed at speed is not refused
GRADIENT_COST = 8  # a Tight gradient rectangle costs this many times a plain one: sample by sample, in Python
CHEAP = 8  # a fill, or a JPEG (decoded in C), costs this many times less than a plain one
# What no rectangle costs less than, however few of its pixels there are: reading it, and handing it on, cost as much as a
# tile of 16 by 16 pixels. (A rectangle with none was free: a flood of them held the event loop for seconds.)
RECTANGLE_WORK = 256
# A Hextile tile costs a whole tile's work whatever of it is on the screen: a rectangle a pixel wide is tiles from top to
# bottom, each read and drawn by itself. And its tiles count against MOST_RECTANGLES_A_SECOND, so many of them to one
# rectangle: taking a tile apart costs the event loop about an eighth of what taking a rectangle apart does (measured).
TILE_WORK = 256
TILES_A_RECTANGLE = 8
HEXTILE_PIECE = 64 * 1024  # bytes of Hextile tiles taken apart before they are handed on to be drawn (whole rows of them)
ENTRY_BYTES = 128  # what a rectangle handed on to be drawn costs beside its bytes, counted towards BATCH_BYTES
BREATHE = 0.005  # seconds the event loop is held at the most by reading what has arrived already, before others may have it
# Every server's pictures are drawn in the same two threads, and some kilobytes cost one of them seconds (runs of one pixel,
# Tight's gradient, JPEGs of a tile each): a server's drawing is done a slice at a time, held to a share of the threads.
DRAWING_SHARE = 0.5  # seconds of a drawing thread a server's pictures may take in each second, on average...
DRAWING_BURST = 1.0  # ...and at once, after a while of taking less (a first screen, a page that changed)
# ...and every server's together (at once, as one server's): the threads draw in Python, which runs one thread at a time, and
# what they do not take is the event loop's (every page, tile and live line). Three costly servers at their share each left
# it a quarter of the time or less. Reading what the servers send, on the event loop itself, is charged to the same shares
# (to its server's and to every server's), in what it held the loop for: four servers within every limit of their own
# kept it busy 98% of the time while only their drawing was. Reading and drawing wait for these shares by one rule, and
# for every server's in turn (see `Client._turn`): waited for by two (a reader slept once and read on, the drawing waited
# until the share was above nought), servers that only flooded what is read kept every other server's drawing out.
DRAWING_ALL = 0.75
# Seconds a thread draws for one server before the next piece of work in line is let in. Slices of 20 ms, two threads at
# them, kept the event loop waiting 30 to 70 ms now and then (measured): Python hands its one thread on every 5 ms, and
# the loop is one of three asking.
DRAWING_SLICE = 0.005
# A step is a tile or a few rows: milliseconds, and tens of them for a large screen. A JPEG is decoded in its server's own
# video worker, and one of tens of thousands of scans, a few kilobytes, decodes for up to video.WORK_WITHIN: it is waited
# for and drawn in a thread of its server's own (`_pictures`, a run of pictures at a time), never in a drawing thread every server
# shares, and charged to its server in full (every server's share, the program's time, only what the waiting thread did).
# Every server's share is charged a slice of drawing that took long up to STEP_ALLOWANCE past the slice; the rest is its
# server's alone. (Waited for in a drawing thread and charged to every server, such a
# picture stopped every VNC, AMT, Proxmox and OpenBMC screen for as long again, at each one.)
STEP_ALLOWANCE = 0.1
# Seconds of a server's pictures decoded in one hop to its own thread at least, more where its own share has more: a batch
# of a 4K desktop's, as a rule. (Held to what its share had at that moment, near nought once it was in use, a hop was
# three pictures of a millisecond or two, and a turn and a hop each cost a 4K desktop beside three others a quarter of
# its updates.) Its own share is charged all of it: no more is decoded, on the whole, than its share.
PICTURES_AT_ONCE = 0.1
# ...and charged to its server's share what its worker worked over the hop, by the system's count of the worker's processor
# time, where the hop took COUNTED_FROM or more; else what it took by the clock. By the clock, a hop held every wait of the
# thread for Python's lock behind the other servers' reading and drawing: on a wall of four, a 4K desktop's pictures took
# 2.6 ms each where its worker worked 1.3, its share was used up by those waits, and it was drawn three updates a second
# where 0.2.0 drew four. Not under COUNTED_FROM: Windows counts a process's time at each tick of its clock (15.6 ms), and
# a few milliseconds of work that begin after a tick can read nought; over several ticks, pictures one after another
# begin where they may.
COUNTED_FROM = 0.05
# ...and a server whose pictures, or slices, take LONG_STEP or more (beyond starting its video worker) more than
# MOST_LONG_STEPS times within LONG_STEPS_WITHIN is refused: held to its share, it still kept a video worker at work for
# seconds at a time, for as long as it was connected. (Two seconds: a 5K screen's whole-screen ZRLE inflate is a step of
# 156 ms on a desktop PC, and a Raspberry Pi class host is 5 to 10 times slower.)
LONG_STEP = 2.0
MOST_LONG_STEPS = 3
LONG_STEPS_WITHIN = 60.0
STEP_PIXELS = 4096  # pixels of a Tight rectangle drawn in one step (a slice ends between steps): rows of them
_HEXTILE_MORE = 1005  # rows of Hextile tiles going on with the rectangle before them (its colours carry over); no encoding has this number
_DRAWERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="rfb")  # the threads that draw, and nothing else runs on them
_ALL = [DRAWING_BURST, 0.0]  # seconds of the program every server's drawing and reading together may take now, and when that was so


class _Turn:
    """A server's place in line for every server's share (see `_Line`)."""

    __slots__ = ("key", "wake")

    def __init__(self, key: tuple[float, int], wake: asyncio.Future[None]) -> None:
        self.key = key  # (the server's place, see `_Line`; when it came)
        self.wake = wake  # set when it may be first in line


class _Line:
    """The servers that wait for every server's share (`_ALL`) to be above nought, in the order of what each has had of it
    (start-time fair queueing): a server's place is what its turns have taken, each the share it took in advance (a slice,
    a breath) or the work it was where that is more (`Client._placed`), or the place of the last server let in (`given`),
    whichever is more. One whose place is lower than others' is let in before them, and of two of one place the one that
    came first: a server that has just had its turn comes after every one that has had no more than it, none waits for
    good, and one that was away comes in at `given`, never before it, whatever it did not take meanwhile; a server that
    wants a turn now and then (an ordinary screen's drawing) is let in at the next turn, before servers that want every
    turn they can have. The work is the thread's own time, never the clock's: by the clock, a slice that took long while
    the drawing threads waited for Python's lock behind the readers sent its server to the back of the line for as many
    turns again (a probe's ordinary screen waited 0.8 s). By turns alone, a run of JPEGs of some 35 ms of the program was
    a turn as a slice of 5 is. What turns take in the end is every server's share's, in full (see `Client._turn`)."""

    def __init__(self) -> None:
        self.waiting: list[_Turn] = []  # in order of their keys: the first in line waits for the share, the others for it to go on
        self.given = 0.0  # the place of the last server let in
        self.came = itertools.count()


_LINE = _Line()
# Bytes every server's updates together may hold at once, beyond their screens: what was read of a rectangle and is not
# drawn yet, and what it inflates or is decoded to while it is drawn (counted as three times its bytes, which are copied
# on their way, and what they come to). (One update of the largest screen held 3.4 times its 48 MB on its way to it, and
# four such servers at once raised the program by 467 MB; more would have raised it more.) An update that does not fit
# waits, holding nothing.
HELD_ALL = 512 * 1024 * 1024
_T = TypeVar("_T")


def _held_one() -> int:
    """What one server's update holds of HELD_ALL at the most, what it gathered and the rectangle it reads: a quarter. A
    server's update may take a minute to come, holding its room all the while, and two or three slow ones holding half each
    left no room for anybody else's. A rectangle that needs more than a quarter by itself (the largest screens: up to 246 MB
    in ZRLE) is held only alone, and by one server at a time, counted in full (up to half of HELD_ALL, more than any
    rectangle needs): two slow ones of those filled the room."""
    return HELD_ALL // 4


# Seconds an update may wait for room while others that fit are given it before it: from then on room is set aside for it
# as it is let go of, and those that fit are given only what is left beside it. (Passed for good, a rectangle that needs
# more than a quarter, beside four slow servers that each let go of a quarter and asked for it again at once, waited until
# their streams ended: some 100 s.)
ROOM_PASSED_FOR = 10.0


class _Room:
    """An update that waits for room in HELD_ALL: its size, whether it is a rectangle larger than one server may hold with
    others (`_held_one`), whose, what is set once the room is its own (`_Held.hand_on`), and since when it waits."""

    __slots__ = ("client", "given", "large", "since", "size")

    def __init__(self, size: int, large: bool, client: object, given: asyncio.Future[None]) -> None:
        self.size, self.large, self.client, self.given = size, large, client, given
        self.since = time.monotonic()


class _Held:
    """What every server's updates hold together (`held`, bytes, at most HELD_ALL); the server whose rectangle larger than
    `_held_one` is held (`large`), one at a time; and the updates that wait for room, in the order they came. Room that is let
    go of is handed on at once to those that wait, in that order, each that fits now (one that does not fit is passed by
    those after it that do, and keeps its place); an update that asks while others wait is given room at once where it
    fits, as one that waits would be: none waits behind another that does not fit. But one that has waited ROOM_PASSED_FOR
    is passed no more: room is set aside for it (`set_aside`), and those after it, or that ask, are given only what is left
    beside it. And room a server lets go of in its update serves its own next request first (see `Client._room`)."""

    def __init__(self) -> None:
        self.held = 0
        self.large: object | None = None
        self.waiting: list[_Room] = []

    def fits(self, size: int, large: bool, aside: int = 0) -> bool:
        return self.held + size + aside <= HELD_ALL and (not large or self.large is None)

    def set_aside(self, before: _Room | None = None) -> int:
        """Room set aside for those that have waited ROOM_PASSED_FOR or more, ahead of `before` in line (or all of them)."""
        now = time.monotonic()
        aside = 0
        for room in self.waiting:
            if room is before:
                break
            if not room.given.done() and now - room.since >= ROOM_PASSED_FOR:
                aside += room.size
        return aside

    def take(self, size: int, large: bool, client: object) -> None:
        self.held += size
        if large:
            self.large = client

    def let_go(self, size: int, client: object, holds: bool, hand_on: bool = True) -> None:
        """`size` bytes of `client`'s let go of; `holds`: whether it holds any still (else its large rectangle is over);
        `hand_on`: whether it is handed on to those that wait now (not where it serves its own server's request first)."""
        self.held -= size
        if not holds and self.large is client:
            self.large = None
        if hand_on:
            self.hand_on()

    def hand_on(self) -> None:
        for room in list(self.waiting):
            if not room.given.done() and self.fits(room.size, room.large, self.set_aside(before=room)):
                self.waiting.remove(room)
                self.take(room.size, room.large, room.client)
                room.given.set_result(None)


_HELD = _Held()
READ_WAIT = 8.0  # seconds the next piece of a message has to arrive in, once the message has begun
WRITE_WAIT = 8.0  # seconds a server has to take what is sent to it
MESSAGE_WITHIN = 60.0  # seconds a message may take to arrive in full (a 4K screen in Raw is 32 MB)
HANDSHAKE_STEP = 8.0  # seconds each answer of the handshake has to come in
BATCH_BYTES = 1024 * 1024  # bytes of rectangles gathered before they are drawn, in a thread, in one go
MOST_PIECES = 4096  # pieces (frames) one message of a WebSocket that carries the protocol may arrive in
CHUNK = 64 * 1024  # bytes read from the network at a time, where a rectangle is read in pieces
# Bytes a zlib stream may be longer than what it holds: stored blocks cost 5 bytes per 65535, so the largest screen
# (48 MB at three bytes a pixel) needs 3850 of those at most, plus the header and the sync flush.
ZLIB_SLACK = 4096

# Ways a connection ends that the device above turns into what a tile says.
PROTOCOL, REFUSED, AUTH, NO_PASSWORD, UNSUPPORTED, LIMIT, TIMEOUT, CLOSED = (
    "protocol", "refused", "auth", "no_password", "unsupported", "limit", "timeout", "closed",
)  # fmt: skip


class RfbError(Exception):
    """Why the connection to a server ended: one of the codes above, and a sentence for whoever looks."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _closed(ex: BaseException) -> RfbError:
    return RfbError(CLOSED, f"the connection to the server ended ({type(ex).__name__})")


async def _in_time(awaitable: Any, seconds: float | None) -> Any:
    """`awaitable`, given `seconds` to come (None: however long); TimeoutError after that.

    Never asyncio.wait_for: up to Python 3.11 it hands back the result where a stop and the result come in the
    same moment, and the stop is lost. Against a server that pushes frames all the time, a reading task went on
    after every stop, and whatever waited for it to end waited for good.
    """
    async with asyncio.timeout(seconds):
        return await awaitable


# --- the DES of VNC authentication ---------------------------------------------------------------------------


def _mirrored(byte: int) -> int:
    """A byte with its bits the other way round: what VNC does to each byte of the password."""
    return int(f"{byte:08b}"[::-1], 2)


def vnc_key(password: str) -> bytes:
    """The DES key VNC makes of a password: its first eight bytes, padded with zeros, each with its bits mirrored.

    The RFC leaves the mirroring out (its erratum 4951 puts it in); every server does it, from the first
    one on, in a DES whose key schedule read the bits from the other end. A password longer than eight
    characters is cut to eight, by every server: the rest is not checked.
    """
    raw = password.encode("utf-8")[:8].ljust(8, b"\0")
    return bytes(_mirrored(byte) for byte in raw)


def vnc_response(password: str, challenge: bytes) -> bytes:
    """The sixteen bytes that answer a server's challenge."""
    key = vnc_key(password)
    # (The library spells single DES as triple DES with the one key three times.)
    encryptor = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


# --- keys, from X11's keysym list and the USB HID usage tables -----------------------------------------------

# HID keyboard usage -> X11 keysym, as the key is without Shift, on the US layout where the key has a
# character; and the keysym with Shift held, where that is another one. Typed from the HID usage tables
# (chapter 10, the Keyboard/Keypad page) and from X11's keysymdef.h.
_LETTERS = {0x04 + i: (0x61 + i, 0x41 + i) for i in range(26)}  # a..z, A..Z
_DIGITS = {0x1E + i: (ord(digit), ord(shifted)) for i, (digit, shifted) in enumerate(zip("1234567890", "!@#$%^&*()", strict=True))}
_SIGNS = {
    0x2D: (0x2D, 0x5F), 0x2E: (0x3D, 0x2B), 0x2F: (0x5B, 0x7B), 0x30: (0x5D, 0x7D), 0x31: (0x5C, 0x7C),  # - _  = +  [ {  ] }  \ |
    0x32: (0x23, 0x7E), 0x33: (0x3B, 0x3A), 0x34: (0x27, 0x22), 0x35: (0x60, 0x7E), 0x36: (0x2C, 0x3C),  # non-US # ~  ; :  ' "  ` ~  , <
    0x37: (0x2E, 0x3E), 0x38: (0x2F, 0x3F), 0x64: (0x5C, 0x7C),  # . >  / ?  non-US \ |
}  # fmt: skip
_NAMED = {
    0x28: 0xFF0D, 0x29: 0xFF1B, 0x2A: 0xFF08, 0x2B: 0xFF09, 0x2C: 0x0020,  # Return, Escape, BackSpace, Tab, space
    0x39: 0xFFE5, 0x46: 0xFF61, 0x47: 0xFF14, 0x48: 0xFF13,  # Caps_Lock, Print, Scroll_Lock, Pause
    0x49: 0xFF63, 0x4A: 0xFF50, 0x4B: 0xFF55, 0x4C: 0xFFFF, 0x4D: 0xFF57, 0x4E: 0xFF56,  # Insert, Home, Page_Up, Delete, End, Page_Down
    0x4F: 0xFF53, 0x50: 0xFF51, 0x51: 0xFF54, 0x52: 0xFF52,  # Right, Left, Down, Up
    0x53: 0xFF7F, 0x54: 0xFFAF, 0x55: 0xFFAA, 0x56: 0xFFAD, 0x57: 0xFFAB, 0x58: 0xFF8D,  # Num_Lock, KP_Divide, KP_Multiply, KP_Subtract, KP_Add, KP_Enter
    **{0x59 + i: 0xFFB1 + i for i in range(9)}, 0x62: 0xFFB0, 0x63: 0xFFAE,  # KP_1..KP_9, KP_0, KP_Decimal
    0x65: 0xFF67, 0x67: 0xFFBD, 0x74: 0xFF62, 0x75: 0xFF6A, 0x76: 0xFF67, 0x77: 0xFF60,  # Menu, KP_Equal, Execute, Help, Menu, Select
    0x78: 0xFF69, 0x79: 0xFF66, 0x7A: 0xFF65, 0x7E: 0xFF68, 0x85: 0xFFAC, 0x86: 0xFFBD,  # Cancel (Stop), Redo (Again), Undo, Find, KP_Separator, KP_Equal
    0x9A: 0xFF15, 0x9B: 0xFF69, 0x9C: 0xFF0B, 0x9E: 0xFF0D, 0xBA: 0xFF89, 0xCD: 0xFF80,  # Sys_Req, Cancel, Clear, Return, KP_Tab, KP_Space
    **{0x3A + i: 0xFFBE + i for i in range(12)}, **{0x68 + i: 0xFFCA + i for i in range(12)},  # F1..F12, F13..F24
    0xE0: 0xFFE3, 0xE1: 0xFFE1, 0xE2: 0xFFE9, 0xE3: 0xFFEB,  # Control_L, Shift_L, Alt_L, Super_L
    0xE4: 0xFFE4, 0xE5: 0xFFE2, 0xE6: 0xFFEA, 0xE7: 0xFFEC,  # Control_R, Shift_R, Alt_R, Super_R
}  # fmt: skip
KEYSYMS: dict[int, tuple[int, int]] = {**_LETTERS, **_DIGITS, **_SIGNS, **{usage: (keysym, keysym) for usage, keysym in _NAMED.items()}}
SHIFT_USAGES = frozenset({0xE1, 0xE5})
UNICODE_KEYSYM = 0x01000000  # a character that has no keysym of its own: this and its code point


def keysym_for(usage: int, shift: bool = False) -> int | None:
    """The keysym for a HID keyboard usage; None for a key this program has no keysym for."""
    pair = KEYSYMS.get(usage)
    return None if pair is None else pair[1 if shift else 0]


def keysym_of(char: str) -> int | None:
    """The keysym that types `char`: Latin-1 characters are their own code, the rest Unicode keysyms. None: not typed."""
    code = ord(char)
    if char == "\n":
        return 0xFF0D
    if char == "\t":
        return 0xFF09
    if 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF:
        return code
    if code < 0x100 or 0xD800 <= code <= 0xDFFF:
        return None  # a control character, or half of one
    return UNICODE_KEYSYM + code


# --- the bytes to and from the server ---------------------------------------------------------------------------


class Stream:
    """Bytes to and from a server, whatever carries them. What a transport has to give the client."""

    async def read(self, size: int, within: float | None) -> bytes:
        """Exactly `size` bytes, within `within` seconds (None: however long). RfbError when they do not come."""
        raise NotImplementedError

    async def read_some(self, most: int, within: float | None) -> bytes:
        """What has arrived, up to `most` bytes and at least one, waited for within `within` seconds. RfbError when nothing comes."""
        raise NotImplementedError

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class TcpStream(Stream):
    """A TCP connection, with or without TLS over it. See `open_tcp`."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader, self._writer = reader, writer

    async def read(self, size: int, within: float | None) -> bytes:
        if within is not None and within <= 0:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time")
        try:
            return bytes(await _in_time(self._reader.readexactly(size), within))
        except TimeoutError:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time") from None
        except asyncio.IncompleteReadError as ex:
            raise RfbError(CLOSED, "the server closed the connection") from ex
        except OSError as ex:
            raise _closed(ex) from ex

    async def read_some(self, most: int, within: float | None) -> bytes:
        if within is not None and within <= 0:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time")
        try:
            came = bytes(await _in_time(self._reader.read(most), within))
        except TimeoutError:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time") from None
        except OSError as ex:
            raise _closed(ex) from ex
        if not came:
            raise RfbError(CLOSED, "the server closed the connection")
        return came

    async def write(self, data: bytes) -> None:
        try:
            self._writer.write(data)
            await _in_time(self._writer.drain(), WRITE_WAIT)
        except TimeoutError:
            raise RfbError(TIMEOUT, "the server is not taking what is sent to it") from None
        except OSError as ex:
            raise _closed(ex) from ex

    async def close(self) -> None:
        self._writer.transport.abort()  # the protocol has no goodbye


def _keep_alive(sock: Any) -> None:
    """Have the system notice a server that went away without a word, within minutes and not hours."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 4)):
            option = getattr(socket, name, None)
            if option is not None:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
    except (OSError, AttributeError):
        pass  # (it is a courtesy; the connection works without it)


async def open_tcp(host: str, port: int, tls: ssl.SSLContext | None, within: float, name: str | None = None) -> TcpStream:
    """A connection to `host`:`port`, over TLS where a context is given. OSError (an SSL error is one) when none is to be had.
    `name`: the server's name for TLS (what its certificate is checked against), where `host` is one of its addresses."""
    async with asyncio.timeout(within):
        reader, writer = await asyncio.open_connection(host, port, ssl=tls, server_hostname=(name or host) if tls is not None else None)
    sock = writer.get_extra_info("socket")
    if sock is not None:
        _keep_alive(sock)
    return TcpStream(reader, writer)


async def greeting(host: str, port: int, within: float, tls: ssl.SSLContext | None = None) -> str | None:
    """The protocol version a server at `host`:`port` greets with ("3.8"), or None where none does. Nothing is sent to it.

    `tls`: the server speaks TLS from the first byte, and greets inside it: asked over TLS checked with this context (TLS's
    own handshake is all that is sent). A certificate that this check refuses is not "no greeting": that error is raised.
    """
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(within):
            reader, writer = await asyncio.open_connection(host, port, ssl=tls, server_hostname=host if tls is not None else None)
            said = await reader.readexactly(12)
    except ssl.SSLCertVerificationError:
        raise
    except (OSError, asyncio.IncompleteReadError, TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.transport.abort()
    found = VERSION.fullmatch(said)
    return None if found is None else f"{int(found.group(1))}.{int(found.group(2))}"


class WebSocketStream(Stream):
    """The same bytes carried in the binary messages of a WebSocket (as noVNC's servers, and OpenBMC's console, send them).

    Takes a connection that is open already, made by whoever knows how that door opens (the session that
    OpenBMC wants first, say): `ws` is a `websockets` client connection, or anything with `recv`, `send` and
    `close` like it. A message holds any number of bytes; they are taken as one stream.
    """

    MOST_HELD = 4 * 1024 * 1024  # bytes of messages held beyond what was asked for, before the server is taken to be flooding

    def __init__(self, ws: Any) -> None:
        self._ws = ws
        self._held = bytearray()

    async def read(self, size: int, within: float | None) -> bytes:
        deadline = None if within is None else time.monotonic() + within
        while len(self._held) < size:
            await self._next_message(size, deadline)
        taken = bytes(self._held[:size])
        del self._held[:size]
        return taken

    async def read_some(self, most: int, within: float | None) -> bytes:
        if not self._held:
            await self._next_message(1, None if within is None else time.monotonic() + within)
        taken = bytes(self._held[:most])
        del self._held[:most]
        return taken

    async def _next_message(self, size: int, deadline: float | None) -> None:
        """One more message into what is held, towards a read of `size` bytes."""
        wait = None if deadline is None else deadline - time.monotonic()
        if wait is not None and wait <= 0:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time")
        if getattr(self._ws, "recv_streaming", None) is not None:
            await self._next_in_pieces(size, wait, deadline)
            return
        try:
            message = await _in_time(self._ws.recv(), wait)
        except TimeoutError:
            raise RfbError(TIMEOUT, "the server did not send the next piece in time") from None
        except Exception as ex:  # the library's own "closed", and whatever else ends a WebSocket
            raise _closed(ex) from ex
        if not isinstance(message, (bytes, bytearray)):
            raise RfbError(PROTOCOL, "the server sent text where bytes belong")
        if len(self._held) + len(message) > size + self.MOST_HELD:
            raise RfbError(LIMIT, "the server sends far more at once than this program holds")
        self._held += message

    async def _next_in_pieces(self, size: int, wait: float | None, deadline: float | None) -> None:
        """A message taken as the pieces (frames) it arrives in, each counted as it comes. Taken whole, a message begun
        and never ended (empty pieces, under every limit on frames a second) was kept by the library piece by piece, a
        megabyte a second and more for as long as the connection lasted: nothing here saw it until it ended."""
        pieces = self._ws.recv_streaming()
        try:
            try:
                first = await _in_time(anext(pieces), wait)
            except TimeoutError:
                raise RfbError(TIMEOUT, "the server did not send the next piece in time") from None
            except StopAsyncIteration:
                raise RfbError(CLOSED, "the server closed the connection") from None
            except Exception as ex:
                raise _closed(ex) from ex
            if not isinstance(first, (bytes, bytearray)):
                raise RfbError(PROTOCOL, "the server sent text where bytes belong")
            parts, count, room = [first], 1, size + self.MOST_HELD - len(self._held)
            took = len(first)
            # The rest of it within the read's own time, or, for a read that waits as long as it takes (the next message
            # of a server with nothing to say), each piece within READ_WAIT of the one before. (How many pieces, and how
            # much, is held to the most above: a message that trickles on is ended by the pacer's own heartbeat.)
            while True:
                if took > room or count > MOST_PIECES:
                    raise RfbError(LIMIT, "the server sends far more at once, or in far more pieces, than this program holds")
                give_up = deadline if deadline is not None else time.monotonic() + READ_WAIT
                try:
                    piece = await _in_time(anext(pieces), max(0.01, give_up - time.monotonic()))
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    raise RfbError(TIMEOUT, "the server began a message and did not finish it") from None
                except Exception as ex:
                    raise _closed(ex) from ex
                parts.append(piece)
                count, took = count + 1, took + len(piece)
        finally:
            try:
                await pieces.aclose()
            except Exception:  # (the connection is ending, which whoever reads next is told)
                pass
        self._held += b"".join(parts)

    async def write(self, data: bytes) -> None:
        try:
            await _in_time(self._ws.send(data), WRITE_WAIT)
        except TimeoutError:
            raise RfbError(TIMEOUT, "the server is not taking what is sent to it") from None
        except Exception as ex:
            raise _closed(ex) from ex

    async def close(self) -> None:
        try:
            await _in_time(self._ws.close(), 1.0)
        except Exception:  # a server that is gone gets no long goodbye
            pass


# --- reading what arrived -------------------------------------------------------------------------------------


class _Bytes:
    """A rectangle's bytes as they are taken apart: a take past the end is a named error, never an IndexError."""

    __slots__ = ("at", "data")

    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, size: int) -> bytes:
        end = self.at + size
        if end > len(self.data):
            raise RfbError(PROTOCOL, "a rectangle was cut short")
        piece = self.data[self.at : end]
        self.at = end
        return piece

    def byte(self) -> int:
        if self.at >= len(self.data):
            raise RfbError(PROTOCOL, "a rectangle was cut short")
        value = self.data[self.at]
        self.at += 1
        return value

    def left(self) -> int:
        return len(self.data) - self.at


def _rgb_of(pixels: bytes) -> bytes:
    """Pixels of four bytes (R, G, B, nothing), as three."""
    out = bytearray(len(pixels) // 4 * 3)
    out[0::3], out[1::3], out[2::3] = pixels[0::4], pixels[1::4], pixels[2::4]
    return bytes(out)


# RGB565 to three bytes, a byte at a time through tables (no loop over pixels in Python): red is the high byte's top
# five bits, blue the low byte's low five, green three bits of each. Each is stretched to 0..255, rounded.
_RED_565 = bytes(((byte >> 3) * 255 + 15) // 31 for byte in range(256))
_BLUE_565 = bytes(((byte & 0x1F) * 255 + 15) // 31 for byte in range(256))
_GREEN_HIGH = bytes((byte & 7) << 3 for byte in range(256))  # green's top three bits, from the high byte
_GREEN_LOW = bytes(byte >> 5 for byte in range(256))  # ...and its low three, from the low byte
_GREEN_565 = bytes(((byte & 0x3F) * 255 + 31) // 63 for byte in range(256))


def _rgb_of_565(pixels: bytes) -> bytes:
    """Pixels of two bytes (RGB565, little-endian), as three."""
    low, high = pixels[0::2], pixels[1::2]
    count = len(high)
    # The two halves of green sit in bits that do not overlap: joined by one OR over the whole run, as numbers.
    green = (int.from_bytes(high.translate(_GREEN_HIGH), "little") | int.from_bytes(low[:count].translate(_GREEN_LOW), "little")).to_bytes(count, "little")
    out = bytearray(3 * count)
    out[0::3], out[1::3], out[2::3] = high.translate(_RED_565), green.translate(_GREEN_565), low[:count].translate(_BLUE_565)
    return bytes(out)


def _run_length(data: _Bytes) -> int:
    """A ZRLE run length: one more than the bytes add up to, and a byte of 255 means another follows."""
    length = 1
    while True:
        byte = data.byte()
        length += byte
        if byte != 255:
            return length


def _packed(indices: bytes, palette: list[bytes], bits: int, width: int, height: int) -> bytes:
    """Pixels packed `bits` to an index, rows padded to a byte, as three bytes a pixel.

    An index past the palette is a named error where it is a pixel; in the bits that pad a row it is nothing.
    """
    per_byte = 8 // bits
    mask = (1 << bits) - 1
    row_bytes = (width + per_byte - 1) // per_byte
    table: dict[int, list[bytes | None]] = {}
    rows = []
    for y in range(height):
        entries: list[bytes | None] = []
        for byte in indices[y * row_bytes : (y + 1) * row_bytes]:
            expanded = table.get(byte)
            if expanded is None:
                picked = [(byte >> (8 - bits * (i + 1))) & mask for i in range(per_byte)]
                expanded = table[byte] = [palette[index] if index < len(palette) else None for index in picked]
            entries.extend(expanded)
        del entries[width:]
        if None in entries:
            raise RfbError(PROTOCOL, "an index past the palette")
        rows.append(b"".join(entries))  # type: ignore[arg-type]
    return b"".join(rows)


def _all_wait() -> float:
    """Every server's share (`_ALL`), brought up to now: the seconds to wait before any server takes more of it."""
    now = time.monotonic()
    _ALL[0] = min(DRAWING_BURST, _ALL[0] + (now - _ALL[1]) * DRAWING_ALL)
    _ALL[1] = now
    return -_ALL[0] / DRAWING_ALL


def _once(work: Callable[..., Any], *args: Any) -> Iterator[None]:
    """One piece of work as one step of a drawing (see Client._drawn)."""
    work(*args)
    yield


def _advance(steps: Iterator[None], most: float) -> tuple[bool, float, float]:
    """In a drawing thread: `steps` taken until they are all done (True), or until `most` seconds have gone (False); the
    seconds that took by the clock (what the shares are charged); and the work it was, the thread's own time
    (time.thread_time: what LONG_STEP counts). A step is a tile or a few rows: a slice ends at most a step after its time.

    By the clock, a stall that held Python's lock meanwhile (the event loop's, a collection of garbage), or a starved
    container, is in the slice: charged to the shares, which is a slower drawing for a while, never more than a share; but
    counted towards LONG_STEP it refused a server that was well. The thread's own time is not the charge: on Windows it is
    counted at each tick of the system's clock (15.6 ms), and slices of a millisecond or two that begin after a tick read
    nought (84 of 84 of an ordinary server's, measured), where a step of a second cannot."""
    began, working = time.perf_counter(), time.thread_time()
    for _ in steps:
        if time.perf_counter() - began >= most:
            return False, time.perf_counter() - began, time.thread_time() - working
    return True, time.perf_counter() - began, time.thread_time() - working


def _worked(session: VideoSession, worker: object, used: float | None, starting: float, took: float) -> float:
    """What a session's worker worked over a wait that began with `worker` and `used` (VideoSession.cpu_seconds) and
    `starting`, and took `took` by the clock: the worker's processor time meanwhile by the system's count, where it is the same
    worker at both ends and the system says; else the clock, less what starting a worker took. What LONG_STEP counts (a stall
    that holds Python's lock is in the clock, not in the worker's time)."""
    now, used_now = session.cpu_seconds()
    if worker is not None and now is worker and used is not None and used_now is not None and session.starting == starting:
        return used_now - used
    return took - (session.starting - starting)


def _awaited_on(inner: Generator[Any, Any, bytes], waiting: Any) -> Generator[Any, Any, bytes]:
    """What `yield from inner` does, where `inner` has yielded `waiting` already (see `Client._from_network`)."""
    while True:
        try:
            message = yield waiting
        except BaseException as ex:  # (a stop, or the end of the reader: passed on to the read)
            step: Callable[[Any], Any] = inner.throw
            given: Any = ex
        else:
            step, given = inner.send, message
        try:
            waiting = step(given)
        except StopIteration as done:
            result: bytes = done.value
            return result


def _is_jpeg(entry: tuple[int, int, int, int, int, bytes]) -> bool:
    """Whether a rectangle handed on to be drawn is a Tight JPEG."""
    return entry[0] == TIGHT and entry[5][0] >> 4 == 0x9


def _draw_pictures(client: Client, run: list[tuple[int, int, int, int, int, bytes]], most: float) -> tuple[list[tuple[float, float]], float, RfbError | None]:
    """In a server's own thread: a run of its Tight JPEGs, each decoded in its video worker and drawn (where somebody still
    looks), the streams its control byte says reset first, in order, until all are done or what they took by the clock
    reaches `most`. For each done, what it took by the clock in this thread (what its server's share is charged) and what of
    that was starting a worker (VideoSession.starting); this thread's own time (time.thread_time: what of the program the
    hop took, what every server's share is charged); and the error that ended them, if one did (that one counted too)."""
    session = client._video_decoder
    took: list[tuple[float, float]] = []
    spent, working = 0.0, time.thread_time()
    for _, x, y, width, height, data in run:
        starting, began = session.starting, time.perf_counter()
        error = None
        try:
            client._reset_tight(data[0])
            picture = decode_jpeg(data[1:], width, height, session)
            if client.drawing:
                client._blit(x, y, width, height, picture)
        except RfbError as ex:
            error = ex
        seconds = time.perf_counter() - began
        took.append((seconds, session.starting - starting))
        if error is not None:
            return took, time.thread_time() - working, error
        spent += seconds
        if spent >= most:
            break
    return took, time.thread_time() - working, None


def decode_jpeg(data: bytes, width: int, height: int, session: VideoSession | None = None) -> bytes:
    """A JPEG as three bytes a pixel. RfbError where it is not a picture of that size, or none at all."""
    if picture_size(data) != (width, height):
        raise RfbError(PROTOCOL, "a JPEG that is not of its rectangle's size")
    from .video import decode_jpeg as isolated_jpeg

    try:
        return isolated_jpeg(data, width, height, session)
    except Exception as ex:
        raise RfbError(PROTOCOL, f"a JPEG that cannot be read ({type(ex).__name__})") from None


class Client:
    """One connection to a VNC server, from the handshake on. The screen it keeps is `rgb`, `width` by `height`.

    `handshake()` first, then `serve()` runs for as long as the connection lasts; `request()`, `key()` and
    `pointer()` may be called meanwhile. `shown` is width, height and the pixels in one look, for whoever
    makes a picture of the screen in another thread. `frames` counts the updates drawn; `updated` is set at
    each update that arrives, drawn or not. `drawing` False: what arrives is read and let go of (a pushing
    server costs reading, not decoding); `stale` says that frames were let go of since the screen was last
    whole, and the next request had better ask for the whole screen. `clock` is what paces are measured by.
    `encodings`: what the server is told this program reads, in order of preference. `pixels`: RGB888 (what every
    server is asked for), or RGB565 for a server that takes nothing else, with Raw and CopyRect only.
    `greeted_as_38`: greetings beyond version 3 that a family's server sends and means 3.8 by (Intel AMT's KVM says
    "RFB 004.000" and speaks 3.8); any other greeting of another version is refused. `signs_in`: the ways of signing in
    a family's server may ask for (Intel AMT's KVM is signed in to before RFB begins: there, None alone, and a server
    that asks for VNC authentication instead is "a way this program does not speak", and is sent nothing).
    """

    def __init__(
        self,
        stream: Stream,
        password: str | None = None,
        before_password: Callable[[], Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
        encodings: tuple[int, ...] = ENCODINGS,
        greeted_as_38: tuple[bytes, ...] = (),
        pixels: str = RGB888,
        signs_in: tuple[int, ...] = (SECURITY_NONE, SECURITY_VNC),
    ) -> None:
        if not set(encodings) <= set(ENCODINGS) or RAW not in encodings:
            raise ValueError("encodings this reader does not read, or without Raw, which every server may fall back on")
        if pixels not in (RGB888, RGB565) or (pixels == RGB565 and not set(encodings) <= {RAW, COPY_RECT, DESKTOP_SIZE}):
            raise ValueError("a pixel format this reader does not read, or not in these encodings")
        self.stream = stream
        self._video_decoder = VideoSession()
        self.password = password
        self.before_password = before_password  # told the moment before the password's answer goes out
        self.clock = clock
        self.encodings = encodings
        self.greeted_as_38 = greeted_as_38
        self.pixels = pixels
        self._pixel_bytes = 2 if pixels == RGB565 else 4
        self._as_rgb = _rgb_of_565 if pixels == RGB565 else _rgb_of
        self.signs_in = signs_in
        self.version: tuple[int, int] | None = None
        self.security: int | None = None  # how the server had this program sign in
        self.width = self.height = 0
        self.name = ""
        self.rgb = bytearray()
        self.shown: tuple[int, int, bytearray] = (0, 0, self.rgb)
        self.frames = 0
        self.updates = 0  # updates that arrived, drawn or not
        self.updated = asyncio.Event()
        self.drawing = True
        self.stale = False
        self.pending = 0  # update requests sent that no update has answered yet
        self.resized = False  # the server changed the screen's size since the last look
        self._zrle = zlib.decompressobj()
        self._tight = [zlib.decompressobj() for _ in range(4)]
        self._hextile_colours = (b"\0\0\0", b"\0\0\0")  # the background and foreground a Hextile rectangle carries from tile to tile
        self._held = bytearray()  # what was read from the network ahead of need (a Hextile rectangle is read in pieces)
        self._writing = asyncio.Lock()
        self._second = 0.0
        self._messages = self._rectangles = self._resizes = self._work = 0
        self._since = time.perf_counter()  # when this reader last took the event loop back (see `_breathe`)
        self._held_loop = 0.0  # seconds it held the loop before that, since it last let go of it
        self._paid = 0.0  # seconds of the shares taken in advance, at its last turn, for what it holds the loop for next
        self._place = 0.0  # where it comes in line next: what its turns have taken in advance (see `_Line`)
        self._waited = 0.0  # seconds it was away from the server's bytes: drawing, or waiting for its share (see `_away`)
        self._pending = 0  # bytes of HELD_ALL held for the rectangle being read (see `_room`)...
        self._gathered = 0  # ...and for those gathered to be drawn
        self._keeping = False  # it makes room for its own next request (see `_room`)...
        self._freed = 0  # ...and has let go of this much meanwhile
        self._credit = DRAWING_BURST  # seconds of the drawing threads this server's pictures may take now (see `_drawn`)
        self._credit_at = time.monotonic()
        self._long_steps: list[float] = []  # when its pictures or slices took LONG_STEP or more, within LONG_STEPS_WITHIN
        self._decoding: ThreadPoolExecutor | None = None  # the thread that waits for this server's video worker (see `_pictures`)

    # --- the handshake ------------------------------------------------------------------------------------

    async def handshake(self) -> None:
        """Version, security, sign-in, and what the server says of its screen. RfbError says why it did not get that far."""
        said = await self.stream.read(12, HANDSHAKE_STEP)
        found = VERSION.fullmatch(said)
        if found is None:
            raise RfbError(PROTOCOL, "what answers is not a VNC server (its greeting is not RFB)")
        major, minor = int(found.group(1)), int(found.group(2))
        if said in self.greeted_as_38:
            major, minor = 3, 8
        if major != 3:
            raise RfbError(UNSUPPORTED, f"the server speaks RFB {major}.{minor}, which this program does not")
        # The RFC's three versions; anything else of version 3 is taken for 3.3, as it says.
        minor = 8 if minor >= 8 else 7 if minor == 7 else 3
        self.version = (3, minor)
        await self._write(b"RFB 003.%03d\n" % minor)
        if minor == 3:
            (chosen,) = struct.unpack(">I", await self.stream.read(4, HANDSHAKE_STEP))
            if chosen == SECURITY_INVALID:
                raise RfbError(REFUSED, f"the server refused the connection: {await self._reason()}")
            if chosen not in self.signs_in:
                raise RfbError(UNSUPPORTED, f"the server asks for a way of signing in this program does not speak ({self._named(chosen)})")
        else:
            count = (await self.stream.read(1, HANDSHAKE_STEP))[0]
            if count == 0:
                raise RfbError(REFUSED, f"the server refused the connection: {await self._reason()}")
            offered = await self.stream.read(count, HANDSHAKE_STEP)
            if SECURITY_NONE in offered and SECURITY_NONE in self.signs_in:
                chosen = SECURITY_NONE  # nothing to send, and nothing of the server's business which other ways it has
            elif SECURITY_VNC in offered and SECURITY_VNC in self.signs_in:
                chosen = SECURITY_VNC
            else:
                others = ", ".join(self._named(kind) for kind in sorted(set(offered)))
                raise RfbError(UNSUPPORTED, f"the server asks for a way of signing in this program does not speak ({others})")
            await self._write(bytes([chosen]))
        self.security = chosen
        if chosen == SECURITY_VNC:
            challenge = await self.stream.read(16, HANDSHAKE_STEP)
            if self.password is None:
                raise RfbError(NO_PASSWORD, "the server asks for a password, and none is saved for it")
            if self.before_password is not None:
                self.before_password()
            await self._write(vnc_response(self.password, challenge))
        if chosen == SECURITY_VNC or minor == 8:
            (result,) = struct.unpack(">I", await self.stream.read(4, HANDSHAKE_STEP))
            if result == 1:
                why = await self._reason() if minor == 8 else "the server rejected the password"
                raise RfbError(AUTH if chosen == SECURITY_VNC else REFUSED, why)
            if result == 2:
                # (Not in the RFC; TightVNC and RealVNC say it after some wrong passwords, and shut the address out for a while.)
                raise RfbError(REFUSED, "the server says there were too many failed sign-ins, and shuts this address out for a while")
            if result != 0:
                raise RfbError(PROTOCOL, f"the server answered the sign-in with {result}, which means nothing")
        await self._write(b"\x01")  # ClientInit: shared, so that nobody else at the server is thrown out
        width, height, name_length = struct.unpack(">HH16xI", await self.stream.read(24, HANDSHAKE_STEP))
        if name_length > MOST_NAME:
            raise RfbError(LIMIT, f"the server gives itself a name of {name_length} bytes, which is no name")
        self._fit(width, height)
        self.name = (await self.stream.read(name_length, HANDSHAKE_STEP)).decode("utf-8", "replace")
        encodings = struct.pack(">BxH", SET_ENCODINGS, len(self.encodings)) + b"".join(struct.pack(">i", e) for e in self.encodings)
        await self._write(struct.pack(">Bxxx", SET_PIXEL_FORMAT) + (PIXEL_FORMAT_565 if self.pixels == RGB565 else PIXEL_FORMAT) + encodings)

    @staticmethod
    def _named(kind: int) -> str:
        name = SECURITY_NAMES.get(kind)
        return f"type {kind}" if name is None else f"{name}, type {kind}"

    async def _reason(self) -> str:
        """The reason a server gives for a no, as one line of it."""
        (length,) = struct.unpack(">I", await self.stream.read(4, HANDSHAKE_STEP))
        if length > MOST_REASON:
            raise RfbError(LIMIT, f"the server gives a reason of {length} bytes, which is no reason")
        said = (await self.stream.read(length, HANDSHAKE_STEP)).decode("utf-8", "replace")
        return " ".join("".join(ch if ch.isprintable() else " " for ch in said).split())[:200] or "no reason given"

    def _fit(self, width: int, height: int) -> None:
        """A screen of this size from now on, keeping what was at its top left."""
        for _ in self._fitting(width, height):
            pass

    def _fitting(self, width: int, height: int) -> Iterator[None]:
        """`_fit`, rows of STEP_PIXELS a step (a drawing thread took 35 ms over a screen of 16 million pixels in one go);
        the screen shown is the old one until the new one is whole."""
        if not (0 < width <= LARGEST_SIDE and 0 < height <= LARGEST_SIDE) or width * height > MOST_PIXELS:
            raise RfbError(LIMIT, f"a screen of {width} by {height} pixels, which is more than this program shows")
        if (width, height) == (self.width, self.height):
            return
        rgb = bytearray(3 * width * height)
        if self.rgb:
            kept_width, kept_height = min(width, self.width), min(height, self.height)
            rows_at_once = max(1, STEP_PIXELS // kept_width)
            for top in range(0, kept_height, rows_at_once):
                yield
                for y in range(top, min(top + rows_at_once, kept_height)):
                    rgb[3 * y * width : 3 * (y * width + kept_width)] = self.rgb[3 * y * self.width : 3 * (y * self.width + kept_width)]
            self.resized = True
        self.width, self.height, self.rgb = width, height, rgb
        self.shown = (width, height, rgb)

    # --- what this program sends ---------------------------------------------------------------------------

    async def _write(self, data: bytes) -> None:
        async with self._writing:
            await self.stream.write(data)

    async def request(self, incremental: bool = True, area: tuple[int, int, int, int] | None = None) -> None:
        """Ask for an update: what changed, or (`incremental` False) the whole of `area` (the whole screen where none is given)."""
        x, y, width, height = area if area is not None else (0, 0, self.width, self.height)
        self.pending += 1
        await self._write(struct.pack(">BBHHHH", UPDATE_REQUEST, 1 if incremental else 0, x, y, width, height))

    async def key(self, keysym: int, down: bool) -> None:
        await self._write(struct.pack(">BBxxI", KEY_EVENT, 1 if down else 0, keysym & 0xFFFFFFFF))

    async def keys(self, events: list[tuple[int, bool]]) -> None:
        """Several key events in one piece, in this order."""
        await self._write(b"".join(struct.pack(">BBxxI", KEY_EVENT, 1 if down else 0, keysym & 0xFFFFFFFF) for keysym, down in events))

    async def pointer(self, x: int, y: int, buttons: int = 0) -> None:
        """The pointer at (x, y) of the screen, with these buttons held (bit 0 the left one, 1 the middle, 2 the right, 3 and 4 the wheel)."""
        x = min(max(0, x), max(0, self.width - 1))
        y = min(max(0, y), max(0, self.height - 1))
        await self._write(struct.pack(">BBHH", POINTER_EVENT, buttons & 0xFF, x, y))

    async def close(self) -> None:
        try:
            await self.stream.close()
        finally:
            lane, self._decoding = self._decoding, None
            if lane is not None:
                lane.shutdown(wait=False)  # (its thread ends with the picture it waits for, if any)
            await asyncio.to_thread(self._video_decoder.close)

    # --- what the server sends ------------------------------------------------------------------------------

    async def serve(self) -> None:
        """Read the server's messages for as long as the connection lasts. Ends with an RfbError, always."""
        self._since, self._held_loop = time.perf_counter(), 0.0
        while True:
            await self._breathe()
            kind = await self._kind()
            self._count(messages=1)
            deadline = self._now() + MESSAGE_WITHIN
            if kind == UPDATE:
                await self._update(deadline)
            elif kind == COLOUR_MAP:
                _, count = struct.unpack(">xHH", await self._read(5, deadline))
                await self._drop(6 * count, deadline)  # (asked for true colour: a map means nothing here)
            elif kind == BELL:
                pass
            elif kind == SERVER_CUT_TEXT:
                (length,) = struct.unpack(">3xI", await self._read(7, deadline))
                if length > MOST_CUT_TEXT:
                    raise RfbError(LIMIT, f"the server sends a clipboard of {length} bytes, which is more than this program takes")
                await self._drop(length, deadline)
            else:
                raise RfbError(PROTOCOL, f"a message of a kind this program does not read (type {kind})")

    def _count(self, messages: int = 0, rectangles: int = 0, resizes: int = 0, work: int = 0) -> None:
        """What arrived in this second, held to what a server has reason to send. `work`: pixels to draw, weighted by their cost."""
        now = self.clock()
        if now - self._second >= 1.0:
            self._second, self._messages, self._rectangles, self._resizes, self._work = now, 0, 0, 0, 0
        self._messages += messages
        self._rectangles += rectangles
        self._resizes += resizes
        self._work += work
        if self._messages > MOST_MESSAGES_A_SECOND or self._rectangles > MOST_RECTANGLES_A_SECOND:
            raise RfbError(LIMIT, "the server sends far more than a server has reason to")
        if self._resizes > MOST_RESIZES_A_SECOND:
            raise RfbError(LIMIT, "the server changes the screen's size far more often than a server has reason to")
        if self._work > max(MOST_SCREENS_A_SECOND * self.width * self.height, LEAST_WORK_A_SECOND):
            raise RfbError(LIMIT, "the server sends more pixels in a second than its screen could change")

    @types.coroutine
    def _from_network(self, reading: Awaitable[bytes]) -> Generator[Any, Any, bytes]:
        """What `reading` brings from the server, telling the time this reader held the event loop from the time it let it
        go. Where the read lets the loop go (it waits for the server's bytes, and the loop is the rest of the program's, or
        idle), this reader's time up to then is noted (`_held_loop`), and its time starts again where it takes the loop back
        (`_since`), however short the wait; a read that found its bytes there already did not let the loop go, and its time
        is this reader's, in full. (By how long a read took instead, a millisecond or more for a wait: on a fast link most
        waits are shorter, and most of the link's time was charged to the server and to every server's share, as if it read
        all the while.)"""
        inner = reading.__await__()
        try:
            waiting = inner.send(None)
        except StopIteration as done:  # (its bytes were there: it did not let the loop go)
            result: bytes = done.value
            return result
        self._held_loop += time.perf_counter() - self._since  # (it lets the loop go: this reader's time up to here)
        try:
            return (yield from _awaited_on(inner, waiting))
        finally:
            self._since = time.perf_counter()

    async def _kind(self) -> int:
        """The first byte of the next message: out of what was read ahead first (a Hextile rectangle is read ahead a chunk
        at a time, and the messages after it may have come in that chunk), else waited for as long as it takes (a server
        with nothing to say says nothing, for hours)."""
        held = self._held
        if held:
            kind = held[0]
            del held[:1]
            return kind
        return (await self._from_network(self.stream.read(1, None)))[0]

    async def _read(self, size: int, deadline: float) -> bytes:
        """Exactly `size` bytes: out of what was read ahead first, then from the network."""
        held = self._held
        if not held:
            return await self._from_network(self.stream.read(size, min(READ_WAIT, deadline - self._now())))
        if len(held) >= size:
            taken = bytes(held[:size])
            del held[:size]
            return taken
        first, self._held = bytes(held), bytearray()
        return first + await self._from_network(self.stream.read(size - len(first), min(READ_WAIT, deadline - self._now())))

    async def _more(self, size: int, deadline: float) -> None:
        """What is read ahead made `size` bytes at least, a chunk at a time: for the one encoding that says its lengths only
        tile by tile."""
        held = self._held
        while len(held) < size:
            held += await self._from_network(self.stream.read_some(CHUNK, min(READ_WAIT, deadline - self._now())))

    def _now(self) -> float:
        """The clock a server's deadlines are kept by: `clock`, less the time this reader was away from its bytes (drawing
        them, or waiting for its share of the program's time or memory), which is not the server's."""
        return self.clock() - self._waited

    async def _away(self, waiting: Awaitable[_T]) -> _T:
        """`waiting`, while this reader is away from the server's bytes (drawing them, or waiting for its share of the
        program's time or memory): neither the server's time, against its deadlines, nor this reader's, on the event loop."""
        self._held_loop += time.perf_counter() - self._since
        began = self.clock()
        try:
            return await waiting
        finally:
            self._waited += self.clock() - began
            self._since = time.perf_counter()

    async def _breathe(self) -> None:
        """Let the rest of the program have the event loop, where this reader has held it for BREATHE. What has arrived is
        read without waiting for anything, and a message of 65,535 rectangles, or of rows of Hextile tiles, held every other
        tile, page and live line for as long as it took (seconds, of a few kilobytes).

        What it held the loop for is charged to this server's share and every server's (DRAWING_SHARE, DRAWING_ALL), as its
        drawing is, and it waits for its turn by the rule its drawing does (`_turn`), while what the server sends waits in
        the network: however many servers there are, and however fast this machine is, the rest of the program has the rest
        of the loop, and every server's drawing its turn."""
        now = time.perf_counter()
        held = self._held_loop + now - self._since
        if held < BREATHE:
            return
        self._held_loop, self._since = 0.0, now
        unpaid, self._paid = held - self._paid, 0.0  # (what its last turn did not take in advance)
        self._charged(unpaid, unpaid)
        self._placed(unpaid, 0.0)
        if not await self._turn(BREATHE):
            await self._away(asyncio.sleep(0))  # (its turn at once: the rest of the program has the loop for a moment all the same)
        self._paid = BREATHE

    async def _drop(self, size: int, deadline: float) -> None:
        while size > 0:
            await self._breathe()
            piece = min(size, CHUNK)
            await self._read(piece, deadline)
            size -= piece

    async def _update(self, deadline: float) -> None:
        (count,) = struct.unpack(">xH", await self._read(3, deadline))
        self._count(rectangles=count)
        batch: list[tuple[int, int, int, int, int, bytes]] = []  # (encoding, x, y, width, height, data)
        batched = 0

        # (The time the drawing takes, and waits for its turn, is not the server's: `_drawn` is away from its bytes.)
        async def flush() -> None:
            nonlocal batched
            if batch:
                rectangles, batch[:] = list(batch), []
                batched = 0
                await self._draw_batch(rectangles)
            self._let_go(pending=False)

        async def gather(entry: tuple[int, int, int, int, int, bytes]) -> None:
            nonlocal batched
            batch.append(entry)
            self._gathered, self._pending = self._gathered + self._pending, 0
            batched += len(entry[5]) + ENTRY_BYTES
            if batched >= BATCH_BYTES:
                await flush()

        def room(size: int) -> Awaitable[None]:
            return self._room(size, flush)

        try:
            await self._update_rectangles(count, deadline, flush, gather, room)
        finally:
            self._let_go(pending=True)

    async def _update_rectangles(
        self,
        count: int,
        deadline: float,
        flush: Callable[[], Awaitable[None]],
        gather: Callable[[tuple[int, int, int, int, int, bytes]], Awaitable[None]],
        room: Callable[[int], Awaitable[None]],
    ) -> None:
        """The `count` rectangles of an update, read and handed on to be drawn (`gather`, `flush`), with room in HELD_ALL for
        what they hold (`room`)."""
        drawn = False
        pixels = 0  # to draw, in this update

        for _ in range(count):
            await self._breathe()
            x, y, width, height, encoding = struct.unpack(">HHHHi", await self._read(12, deadline))
            if encoding == DESKTOP_SIZE:
                self._count(resizes=1)
                await flush()
                if 0 < width <= LARGEST_SIDE and 0 < height <= LARGEST_SIDE and width * height <= MOST_PIXELS:
                    await room(3 * width * height)  # (the new screen, beside the old one while what is kept is copied)
                await self._drawn(self._fitting(width, height))  # (a screen's worth of copying)
                self._let_go(pending=True)
                continue
            if encoding not in self.encodings or encoding < 0:
                raise RfbError(PROTOCOL, f"a rectangle in an encoding this program did not ask for ({encoding})")
            if x + width > self.width or y + height > self.height:
                raise RfbError(PROTOCOL, f"a rectangle outside the screen ({width} by {height} at {x}, {y} on {self.width} by {self.height})")
            area = width * height
            drawn = drawn or area > 0
            pixels += area
            if pixels > MOST_SCREENS_AN_UPDATE * self.width * self.height:
                raise RfbError(LIMIT, "the server sends more pixels in one update than its screen could change")
            if encoding == RAW:
                self._count(work=max(area, RECTANGLE_WORK))
                await flush()
                await self._raw(x, y, width, height, deadline)
                continue
            if encoding == COPY_RECT:
                self._count(work=max(area, RECTANGLE_WORK))
                source = await self._read(4, deadline)
                source_x, source_y = struct.unpack(">HH", source)
                if source_x + width > self.width or source_y + height > self.height:
                    raise RfbError(PROTOCOL, "a rectangle copied from outside the screen")
                if self.drawing and area:
                    await gather((COPY_RECT, x, y, width, height, source))
                continue
            if encoding == HEXTILE:
                if not area:
                    self._count(work=RECTANGLE_WORK)
                    continue  # (no tiles, and nothing of them follows: there is nothing to read, row by row or otherwise)
                tiles = -(-width // 16) * -(-height // 16)
                self._count(rectangles=-(-tiles // TILES_A_RECTANGLE), work=tiles * TILE_WORK)
                # Read in pieces of whole rows of tiles, handed on as they come: a screen of its tiles is never held whole.
                top = 0
                while top < height:
                    rows, data = await self._hextile_rows(width, height - top, deadline)
                    if self.drawing:
                        await gather((HEXTILE if top == 0 else _HEXTILE_MORE, x, y + top, width, rows, data))
                    top += rows
                continue
            if encoding == ZRLE:
                self._count(work=max(area, RECTANGLE_WORK))
                data = await self._zrle_bytes(width, height, deadline, room)
            else:
                data = await self._tight_bytes(width, height, deadline, room)
                if data[0] >= 0x80:
                    cost = area // CHEAP  # a fill, or a JPEG
                elif data[0] & 0x40 and data[1] == 2:
                    cost = area * GRADIENT_COST
                else:
                    cost = area
                self._count(work=max(cost, RECTANGLE_WORK))
            # Let go of unseen while nobody wants pictures, except what has a zlib stream to keep in step (ZRLE,
            # Tight: a Tight rectangle of any kind may reset the streams), which is taken apart and not drawn. A JPEG is
            # gathered as it came, and decoded with the rest of its batch's (see `_pictures`).
            await gather((encoding, x, y, width, height, data))
        await flush()
        if drawn:
            if self.drawing:
                self.frames += 1
            else:
                self.stale = True
        self.pending = max(0, self.pending - 1)
        self.updates += 1
        self.updated.set()

    async def _raw(self, x: int, y: int, width: int, height: int, deadline: float) -> None:
        """Raw pixels, read and drawn a few rows at a time: a screen of them is never held twice."""
        if width == 0:
            return
        row = self._pixel_bytes * width
        rows_at_once = max(1, CHUNK // row)
        done = 0
        while done < height:
            await self._breathe()
            rows = min(rows_at_once, height - done)
            pixels = await self._read(rows * row, deadline)
            if self.drawing and self.pixels == RGB565:
                # (Four times the work of the other format's: in the drawing threads, as the other encodings are drawn.)
                await self._drawn(_once(self._draw_raw, x, y + done, width, rows, pixels))
            elif self.drawing:
                self._blit(x, y + done, width, rows, self._as_rgb(pixels))
            done += rows

    def _draw_raw(self, x: int, y: int, width: int, rows: int, pixels: bytes) -> None:
        self._blit(x, y, width, rows, self._as_rgb(pixels))

    async def _hextile_rows(self, width: int, height: int, deadline: float) -> tuple[int, bytes]:
        """Whole rows of Hextile tiles from the top of what is left of a rectangle (`height` rows of pixels), until there are
        HEXTILE_PIECE bytes of them or the rectangle ends: how many rows of pixels they cover, and their bytes. Taken apart
        only as far as their lengths demand (they say them tile by tile), where they lie in what is read ahead a chunk at a
        time; a tile is a few comparisons, and nothing is awaited but more bytes."""
        held = self._held
        across = -(-width // 16)
        last_width = width - 16 * (across - 1)
        at = top = 0
        while top < height and at < HEXTILE_PIECE:
            tile_height = min(16, height - top)
            raw_tile = 1 + 64 * tile_height  # (a tile of raw pixels: its byte, and four bytes a pixel)
            for number in range(across):
                if len(held) <= at:
                    await self._more(at + 1, deadline)
                sub = held[at]
                if sub & 1:
                    at += raw_tile if number < across - 1 else 1 + 4 * last_width * tile_height
                    continue
                at += 1 + (4 if sub & 2 else 0) + (4 if sub & 4 else 0)
                if sub & 8:
                    if len(held) <= at:
                        await self._more(at + 1, deadline)
                    at += 1 + held[at] * (6 if sub & 16 else 2)
            top += tile_height
            await self._breathe()
        if len(held) < at:
            await self._more(at, deadline)
        rows = bytes(held[:at])
        del held[:at]
        return top, rows

    async def _zrle_bytes(self, width: int, height: int, deadline: float, room: Callable[[int], Awaitable[None]]) -> bytes:
        (length,) = struct.unpack(">I", await self._read(4, deadline))
        tiles = -(-width // 64) * -(-height // 64)
        if length > 4 * width * height + 64 * tiles + ZLIB_SLACK:
            raise RfbError(LIMIT, f"a tile stream of {length} bytes for a rectangle of {width} by {height}, which is more than it could hold")
        await room(3 * length + 4 * width * height + 385 * tiles + 16)  # (what `_draw_zrle` inflates it to, at the most)
        return await self._whole(length, deadline)

    async def _whole(self, length: int, deadline: float) -> bytes:
        data = bytearray()
        while len(data) < length:
            await self._breathe()
            data += await self._read(min(CHUNK, length - len(data)), deadline)
        return bytes(data)

    async def _compact_length(self, deadline: float) -> int:
        """Tight's length of one to three bytes, seven bits each, the eighth saying another follows."""
        first = (await self._read(1, deadline))[0]
        length = first & 0x7F
        if first & 0x80:
            second = (await self._read(1, deadline))[0]
            length |= (second & 0x7F) << 7
            if second & 0x80:
                length |= (await self._read(1, deadline))[0] << 14
        return length

    async def _tight_bytes(self, width: int, height: int, deadline: float, room: Callable[[int], Awaitable[None]]) -> bytes:
        """The bytes of a Tight rectangle: its control byte, and what the method of that byte says follows."""
        if width > TIGHT_WIDEST:
            raise RfbError(PROTOCOL, f"a Tight rectangle {width} pixels wide, which its own rules do not allow")
        control = await self._read(1, deadline)
        method = control[0] >> 4
        if method == 0x8:  # fill: one pixel for all of it
            return control + await self._read(3, deadline)
        if method == 0x9:  # JPEG
            length = await self._compact_length(deadline)
            if length > 3 * width * height + ZLIB_SLACK:
                raise RfbError(LIMIT, f"a JPEG of {length} bytes for a rectangle of {width} by {height}, which is more than it could hold")
            await room(3 * length + 3 * width * height)  # (and the picture it is decoded to)
            return control + await self._whole(length, deadline)
        if method >= 0x8:
            raise RfbError(PROTOCOL, f"a Tight rectangle of a kind this program does not read (method {method})")
        pieces = [control]
        filter_id = 0
        if control[0] & 0x40:
            given = await self._read(1, deadline)
            pieces.append(given)
            filter_id = given[0]
        if filter_id == 1:  # palette
            said = await self._read(1, deadline)
            pieces.append(said)
            colours = said[0] + 1
            pieces.append(await self._read(3 * colours, deadline))
            plain = ((width + 7) // 8 if colours <= 2 else width) * height
        elif filter_id in (0, 2):  # copy, gradient
            plain = 3 * width * height
        else:
            raise RfbError(PROTOCOL, f"a Tight filter there is none of ({filter_id})")
        if plain < 12:
            pieces.append(await self._read(plain, deadline))
        else:
            length = await self._compact_length(deadline)
            if length > plain + ZLIB_SLACK:
                raise RfbError(LIMIT, f"a Tight stream of {length} bytes for {plain} bytes of pixels, which is more than it could hold")
            await room(3 * length + plain)  # (and what it inflates to)
            pieces.append(await self._whole(length, deadline))
        return b"".join(pieces)

    # --- drawing (in a thread, batch by batch, in the order the rectangles came, a slice at a time) -------------

    async def _drawn(self, steps: Iterator[None]) -> None:
        """`steps` taken in the drawing threads, a slice at a time (DRAWING_SLICE), within this server's share of their time
        and every server's share together.

        Every server's pictures are drawn in the same two threads. After a slice, the next piece of work in line (another
        server's, as like as not) goes first; a server that has used up its share (DRAWING_SHARE of every second,
        DRAWING_BURST at once) waits until it has one again, while what it sends waits in the network (nothing more is read
        of it meanwhile); and so does every server while all of them together have used up theirs (DRAWING_ALL). A step
        that takes far longer than a slice is charged to every server's share up to STEP_ALLOWANCE, and in full to its own.
        Nothing is refused for what it costs to draw, but steps that take LONG_STEP again and again: a server that is well
        and sends costly pictures is shown more slowly, and one that is not cannot keep the others from being drawn, nor
        the event loop from the rest. (Drawn whole, a few kilobytes of Tight's gradient kept a thread for seconds, and three
        such servers kept both, and the loop waiting.)"""
        loop = asyncio.get_running_loop()
        while True:
            # Counted as it is handed on (whoever asks meanwhile sees it), and put right by what it took once it is done.
            await self._turn(DRAWING_SLICE)
            done, took, worked = await self._away(loop.run_in_executor(_DRAWERS, _advance, steps, DRAWING_SLICE))
            self._charged(took - DRAWING_SLICE, min(took, DRAWING_SLICE + STEP_ALLOWANCE) - DRAWING_SLICE)
            self._placed(worked, DRAWING_SLICE)
            if worked >= LONG_STEP:
                self._took_long()
            if done:
                return

    def _own_wait(self) -> float:
        """This server's share, brought up to now: the seconds it has to wait before taking more of it."""
        now = time.monotonic()
        self._credit = min(DRAWING_BURST, self._credit + (now - self._credit_at) * DRAWING_SHARE)
        self._credit_at = now
        return -self._credit / DRAWING_SHARE

    def _charged(self, own: float, every: float) -> None:
        """`own` seconds charged to this server's share, `every` to every server's."""
        self._credit -= own
        _ALL[0] -= every

    def _placed(self, work: float, taken: float) -> None:
        """A turn that took `taken` in advance was `work`, the thread's own time: where that is more, the server's place in
        line moves on by the rest (see `_Line`). (On Windows a thread's own time is counted at each tick of the clock, 15.6
        ms: a slice of a millisecond or two may read nought, and moves its server by what it took in advance, as before.)"""
        if work > taken:
            self._place += work - taken

    async def _turn(self, taking: float) -> bool:
        """This server's share and its turn at every server's, waited for by one rule wherever this server takes the
        program's time (reading on the event loop, drawing in the drawing threads, waiting for its video worker); `taking`
        seconds of both are then taken in advance, and put right by what was taken in the end. Whether it waited.

        Its own share first, alone (no other server waits for it meanwhile); then, where others wait already or every
        server's share is used up, in line (`_Line`): the first waits until every server's share is above nought, each
        after it until it is first. A server comes after every one that has had no more turns than it, and before every
        one that has had more: servers that keep every server's share used up (some that only flood what is read) take
        turns among themselves, and a server whose drawing needs a slice now and then is let in at the next turn, not
        after all of theirs."""
        waited = False
        while (wait := self._own_wait()) > 0:
            waited = True
            await self._away(asyncio.sleep(wait))
        place = max(self._place, _LINE.given)
        if _LINE.waiting or _all_wait() > 0:
            waited = True
            loop = asyncio.get_running_loop()
            turn = _Turn((place, next(_LINE.came)), loop.create_future())
            bisect.insort(_LINE.waiting, turn, key=lambda each: each.key)
            try:
                while True:
                    if _LINE.waiting[0] is not turn:
                        await self._away(turn.wake)  # (until the one before it goes on, or stops waiting)
                        turn.wake = loop.create_future()
                    elif (wait := _all_wait()) > 0:
                        await self._away(asyncio.sleep(wait))
                    else:
                        break
            finally:
                first = _LINE.waiting[0] is turn
                _LINE.waiting.remove(turn)
                if first and _LINE.waiting and not _LINE.waiting[0].wake.done():
                    _LINE.waiting[0].wake.set_result(None)  # (the next in line: it sees what this one takes below before it runs)
        _LINE.given, self._place = place, place + taking
        self._charged(taking, taking)
        return waited

    async def _draw_batch(self, rectangles: list[tuple[int, int, int, int, int, bytes]]) -> None:
        """A batch of rectangles drawn, in the order they came, run by run: a run of Tight JPEGs, where somebody looks, in this
        server's own thread (`_pictures`); any other run in the drawing threads (`_drawn`)."""
        drawing = self.drawing
        at = 0
        while at < len(rectangles):
            pictures = drawing and _is_jpeg(rectangles[at])
            end = at + 1
            while end < len(rectangles) and (drawing and _is_jpeg(rectangles[end])) == pictures:
                end += 1
            if pictures:
                await self._pictures(rectangles[at:end])
            else:
                await self._drawn(self._drawing(rectangles[at:end]))
            at = end

    async def _pictures(self, run: list[tuple[int, int, int, int, int, bytes]]) -> None:
        """A run of Tight JPEGs decoded in this server's video worker and drawn, in a thread of this server's own (however
        long its worker takes, up to video.WORK_WITHIN a picture, no other server's pictures wait for it), each in one step,
        as 0.2.0 decoded and drew each in a drawing thread. Never in a drawing thread every server shares.

        A turn and a hop to that thread for as many of the run's pictures as are done in PICTURES_AT_ONCE, or in what this
        server's own share has where that is more (DRAWING_BURST at the most): for a batch of them all, as a rule. What they
        took is charged to this server's share (what its worker worked, by the system's count, where the hop took
        COUNTED_FROM or more; else the clock); every server's share, the program's time, is charged what the thread itself
        did (its own time, up to STEP_ALLOWANCE a turn), for the worker is a process of its own; a picture of LONG_STEP or
        more is counted against it, as far as what its worker worked says (see `_worked`). (A turn, a
        hop and a slice's place in line a picture: a 4K desktop's 128 pictures a refresh were some 150 turns where 0.2.0 had
        some 28 slices, and beside other servers it was drawn two to four times less often. Every server's share charged the
        clock of a batch's pictures instead, two 4K JPEG desktops beside a 4K Tight and a 4K ZRLE one left these 1.9 and 1.0
        updates a second where 0.2.0 drew 4.9 and 1.6. Drawn in the drawing threads after they were decoded, a batch cost a
        4K desktop beside three others another wait for those threads.) A turn moves its server's place in line as a slice
        does, for a run."""
        if self._decoding is None:
            self._decoding = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rfb-jpeg")
        loop = asyncio.get_running_loop()
        session = self._video_decoder
        while run:
            await self._turn(DRAWING_SLICE)
            worker, used, starting = *session.cpu_seconds(), session.starting
            took, held, error = await self._away(loop.run_in_executor(self._decoding, _draw_pictures, self, run, max(PICTURES_AT_ONCE, self._credit)))
            seconds = sum(clock for clock, _ in took)
            worked = _worked(session, worker, used, starting, seconds)
            self._charged((worked if seconds >= COUNTED_FROM else seconds) - DRAWING_SLICE, min(held, STEP_ALLOWANCE) - DRAWING_SLICE)
            self._placed(held, DRAWING_SLICE)
            # A picture of LONG_STEP or more by the clock (starting a worker aside) counts, as far as what the worker worked
            # over the hop says it could have been one: a stall that holds Python's lock is in the clock, not in that.
            longest = [clock - started for clock, started in took if clock - started >= LONG_STEP]
            for _ in range(min(len(longest), int(worked // LONG_STEP))):
                self._took_long()
            if error is not None:
                raise error
            run = run[len(took) :]

    async def _room(self, size: int, gathered: Callable[[], Awaitable[None]]) -> None:
        """Room for `size` more bytes held by this update (the rectangle about to be read, until it is gathered), out of
        HELD_ALL and this server's quarter of it (`_held_one`; a rectangle larger than that alone, see `_Held`). Where it
        would hold more than its quarter, or where there is no room, what this update gathered is drawn and let go of first
        (`gathered`); where there is no room then, it waits, holding nothing, until room let go of is handed on to it, in
        the order those that wait came, while an update that fits is given room at once whoever waits (none waits behind
        another that does not fit, nor for another that waits). The time it waits is not the server's.

        What it lets go of meanwhile serves this request first, and only then is the rest handed on: four slow servers each
        holding a quarter took what an ordinary server let go of by drawing what it gathered, and it waited for the next
        slow message, again and again within one update (round 2 review: 7.4 s an update where it was 1.9). An update
        that has waited ROOM_PASSED_FOR is passed no more by those that fit (see `_Held`); what a server lets go of within
        its update may still serve that update first, which ends within MESSAGE_WITHIN."""
        size = min(size, HELD_ALL // 2)
        large = size > _held_one()
        self._freed, self._keeping = 0, True
        try:
            if large or self._gathered + self._pending + size > _held_one():
                await gathered()  # (held alone, or within its quarter)
            if not _HELD.fits(size, large, _HELD.set_aside()) and not (size <= self._freed and _HELD.fits(size, large)):
                await gathered()
        finally:
            self._keeping = False
        own = size <= self._freed and _HELD.fits(size, large)  # (what it let go of serves it first)
        if own or _HELD.fits(size, large, _HELD.set_aside()):
            _HELD.take(size, large, self)
            _HELD.hand_on()  # (and what it let go of beyond that goes on to those that wait)
        else:
            _HELD.hand_on()
            room = _Room(size, large, self, asyncio.get_running_loop().create_future())
            _HELD.waiting.append(room)
            try:
                await self._away(room.given)  # (handed on with the room taken: see `_Held.hand_on`)
            except BaseException:
                if room in _HELD.waiting:
                    _HELD.waiting.remove(room)
                elif room.given.done() and not room.given.cancelled():
                    _HELD.let_go(size, self, self._gathered + self._pending > 0)  # (given, and not taken up)
                raise
        self._pending += size

    def _let_go(self, pending: bool) -> None:
        """What this update's gathered rectangles held of HELD_ALL, once they are drawn; and with `pending`, the one being
        read too (the update is over, however it ended). Handed on at once to those that wait for it."""
        let_go = self._gathered + (self._pending if pending else 0)
        self._gathered = 0
        if pending:
            self._pending = 0
        if let_go:
            if self._keeping:  # (it makes room for its own next request: that comes first, see `_room`)
                self._freed += let_go
            _HELD.let_go(let_go, self, self._pending > 0, hand_on=not self._keeping)

    def _took_long(self) -> None:
        """A picture or a slice of this server's took LONG_STEP or more: noted, and the server refused after MOST_LONG_STEPS."""
        now = time.monotonic()
        self._long_steps = [at for at in self._long_steps if now - at < LONG_STEPS_WITHIN]
        self._long_steps.append(now)
        if len(self._long_steps) > MOST_LONG_STEPS:
            raise RfbError(LIMIT, "the server's pictures take far too long to draw, again and again")

    def _blit(self, x: int, y: int, width: int, height: int, rgb: bytes) -> None:
        row, stride = 3 * width, 3 * self.width
        at = 3 * (y * self.width + x)
        screen = self.rgb
        for r in range(height):
            screen[at : at + row] = rgb[r * row : (r + 1) * row]
            at += stride

    def _fill(self, x: int, y: int, width: int, height: int, pixel: bytes) -> None:
        line, stride = pixel * width, 3 * self.width
        at = 3 * (y * self.width + x)
        screen = self.rgb
        for _ in range(height):
            screen[at : at + len(line)] = line
            at += stride

    def _copy(self, x: int, y: int, width: int, height: int, source_x: int, source_y: int) -> Iterator[None]:
        """A CopyRect, rows of STEP_PIXELS a step (a drawing thread took 77 ms over a screen of 16 million pixels in one go).
        The two may overlap: every row is read before it is written over, from the bottom up where the copy moves down,
        from the top down otherwise, and each step's rows are taken whole before any of them is written."""
        row, stride = 3 * width, 3 * self.width
        rows_at_once = max(1, STEP_PIXELS // max(1, width))
        tops = range(0, height, rows_at_once)
        for top in reversed(tops) if y > source_y else tops:
            yield
            count = min(rows_at_once, height - top)
            at = 3 * ((source_y + top) * self.width + source_x)
            rows = [bytes(self.rgb[at + r * stride : at + r * stride + row]) for r in range(count)]
            self._blit(x, y + top, width, count, b"".join(rows))

    def _drawing(self, rectangles: list[tuple[int, int, int, int, int, bytes]]) -> Iterator[None]:
        """A run of rectangles drawn, in the order they came, a step at a time: between tiles, and between rows."""
        for encoding, x, y, width, height, data in rectangles:
            if encoding in (HEXTILE, _HEXTILE_MORE):
                yield from self._draw_hextile(x, y, width, height, _Bytes(data), fresh=encoding == HEXTILE)
            elif encoding == ZRLE:
                yield from self._draw_zrle(x, y, width, height, data)
            elif encoding == COPY_RECT:
                source_x, source_y = struct.unpack(">HH", data)
                yield from self._copy(x, y, width, height, source_x, source_y)
            else:
                yield from self._draw_tight(x, y, width, height, _Bytes(data))

    def _draw_hextile(self, x: int, y: int, width: int, height: int, data: _Bytes, fresh: bool = True) -> Iterator[None]:
        """Rows of Hextile tiles, a tile a step. `fresh`: a rectangle's first rows, whose colours start out black; later
        rows carry theirs over."""
        background, foreground = (b"\0\0\0", b"\0\0\0") if fresh else self._hextile_colours
        for top in range(0, height, 16):
            tile_height = min(16, height - top)
            for left in range(0, width, 16):
                yield
                tile_width = min(16, width - left)
                sub = data.byte()
                if sub & 1:
                    self._blit(x + left, y + top, tile_width, tile_height, _rgb_of(data.take(4 * tile_width * tile_height)))
                    continue
                if sub & 2:
                    background = data.take(4)[:3]
                if sub & 4:
                    foreground = data.take(4)[:3]
                self._fill(x + left, y + top, tile_width, tile_height, background)
                if sub & 8:
                    for _ in range(data.byte()):
                        colour = data.take(4)[:3] if sub & 16 else foreground
                        position, size = data.byte(), data.byte()
                        sx, sy, sw, sh = position >> 4, position & 15, (size >> 4) + 1, (size & 15) + 1
                        if sx + sw > tile_width or sy + sh > tile_height:
                            raise RfbError(PROTOCOL, "a Hextile subrectangle outside its tile")
                        self._fill(x + left + sx, y + top + sy, sw, sh, colour)
        self._hextile_colours = (background, foreground)

    def _inflate(self, stream: Any, data: bytes, most: int, what: str) -> bytes:
        """What `data` inflates to on `stream`, bounded by `most`, with no input past the stream's end."""
        # Once ended, zlib retains every later byte in unused_data, even with max_length set. Check before
        # decompressing: idle and zero-area ZRLE rectangles may never ask the tile parser for another byte.
        # Tight's explicit reset bits replace its inflater before this call; an ended stream needs that reset.
        if stream.eof:
            raise RfbError(PROTOCOL, f"a {what} used after its end")
        try:
            out: bytes = stream.decompress(data, most + 1)
        except zlib.error:
            raise RfbError(PROTOCOL, f"a {what} that does not inflate") from None
        if len(out) > most or stream.unconsumed_tail:
            raise RfbError(LIMIT, f"a {what} that inflates past what its rectangle can hold")
        if stream.unused_data:
            raise RfbError(PROTOCOL, f"a {what} with bytes after its end")
        return out

    def _draw_zrle(self, x: int, y: int, width: int, height: int, data: bytes) -> Iterator[None]:
        """A ZRLE rectangle, a tile a step (the stream inflated first, whether it is drawn or not: it is one stream)."""
        tiles = -(-width // 64) * -(-height // 64)
        plain = _Bytes(self._inflate(self._zrle, data, 4 * width * height + 385 * tiles + 16, "tile stream"))
        if not self.drawing:
            return
        for top in range(0, height, 64):
            tile_height = min(64, height - top)
            for left in range(0, width, 64):
                yield
                tile_width = min(64, width - left)
                pixels = tile_width * tile_height
                sub = plain.byte()
                if sub == 0:
                    self._blit(x + left, y + top, tile_width, tile_height, plain.take(3 * pixels))
                elif sub == 1:
                    self._fill(x + left, y + top, tile_width, tile_height, plain.take(3))
                elif sub <= 16:
                    palette = [plain.take(3) for _ in range(sub)]
                    bits = 1 if sub == 2 else 2 if sub <= 4 else 4
                    per_byte = 8 // bits
                    rows = plain.take((tile_width + per_byte - 1) // per_byte * tile_height)
                    self._blit(x + left, y + top, tile_width, tile_height, _packed(rows, palette, bits, tile_width, tile_height))
                elif sub == 128:
                    runs: list[bytes] = []
                    left_over = pixels
                    while left_over > 0:
                        pixel = plain.take(3)
                        length = _run_length(plain)
                        if length > left_over:
                            raise RfbError(PROTOCOL, "a run past the end of its tile")
                        runs.append(pixel * length)
                        left_over -= length
                    self._blit(x + left, y + top, tile_width, tile_height, b"".join(runs))
                elif sub >= 130:
                    palette = [plain.take(3) for _ in range(sub - 128)]
                    runs = []
                    left_over = pixels
                    while left_over > 0:
                        index = plain.byte()
                        length = _run_length(plain) if index & 0x80 else 1
                        index &= 0x7F
                        if index >= len(palette):
                            raise RfbError(PROTOCOL, "an index past the palette")
                        if length > left_over:
                            raise RfbError(PROTOCOL, "a run past the end of its tile")
                        runs.append(palette[index] * length)
                        left_over -= length
                    self._blit(x + left, y + top, tile_width, tile_height, b"".join(runs))
                else:
                    raise RfbError(PROTOCOL, f"a ZRLE tile of a kind there is none of ({sub})")
        if plain.left():
            raise RfbError(PROTOCOL, "a tile stream longer than its tiles")

    def _reset_tight(self, control: int) -> None:
        """The streams a Tight rectangle's control byte says to start afresh."""
        for i in range(4):
            if control & (1 << i):
                self._tight[i] = zlib.decompressobj()

    def _draw_tight(self, x: int, y: int, width: int, height: int, data: _Bytes) -> Iterator[None]:
        """A Tight rectangle, rows of STEP_PIXELS a step (its stream inflated first, whether it is drawn or not). A JPEG is
        decoded and drawn in its server's own thread (`_pictures`), and comes here only where nobody looked when its batch was
        drawn: it is never decoded here, and where somebody began to look meanwhile the screen is marked stale, and the next
        request asks for all of it. (Decoded here, in a drawing thread every server shares, one took it for up to
        video.WORK_WITHIN.)"""
        control = data.byte()
        self._reset_tight(control)
        method = control >> 4
        if method == 0x8:
            if self.drawing:
                self._fill(x, y, width, height, data.take(3))
            yield
            return
        if method == 0x9:
            if self.drawing:
                self.stale = True
            yield
            return
        filter_id = data.byte() if control & 0x40 else 0
        palette: list[bytes] = []
        if filter_id == 1:
            colours = data.byte() + 1
            palette = [data.take(3) for _ in range(colours)]
            plain = ((width + 7) // 8 if colours <= 2 else width) * height
        else:
            plain = 3 * width * height
        if plain < 12:
            pixels = data.take(plain)
        else:
            pixels = self._inflate(self._tight[(control >> 4) & 3], data.take(data.left()), plain, "Tight stream")
            if len(pixels) < plain:
                raise RfbError(PROTOCOL, "a Tight stream that holds less than its rectangle")
        if data.left():
            raise RfbError(PROTOCOL, "a Tight rectangle longer than its pixels")
        if not self.drawing or width == 0 or height == 0:
            return
        rows_at_once = max(1, STEP_PIXELS // width)
        packed_row = (width + 7) // 8
        undone = _ungradient(pixels, width, height) if filter_id == 2 else None
        at = 0
        while at < height:
            yield
            rows = min(rows_at_once, height - at)
            if filter_id == 1 and len(palette) <= 2:
                rgb = _packed(pixels[at * packed_row : (at + rows) * packed_row], palette, 1, width, rows)
            elif filter_id == 1:
                try:  # (a row at a time: a screen of them in one go is a pointer per pixel, eight bytes each)
                    rgb = b"".join(b"".join(map(palette.__getitem__, pixels[row * width : (row + 1) * width])) for row in range(at, at + rows))
                except IndexError:
                    raise RfbError(PROTOCOL, "an index past the palette") from None
            elif undone is not None:
                rgb = b"".join(next(undone) for _ in range(rows))
            else:
                rgb = pixels[3 * width * at : 3 * width * (at + rows)]
            self._blit(x, y + at, width, rows, rgb)
            at += rows


def _ungradient(delta: bytes, width: int, height: int) -> Iterator[bytes]:
    """Tight's gradient filter undone, row after row: each sample was sent as its difference from a guess made of its neighbours."""
    row = 3 * width
    above = bytes(row)  # (nothing is above the first row, and nothing left of the first column)
    for y in range(height):
        start = y * row
        out = bytearray(row)
        left = [0, 0, 0]
        for i in range(0, row, 3):
            for c in range(3):
                up, up_left = above[i + c], above[i + c - 3] if i else 0
                guess = min(255, max(0, left[c] + up - up_left))
                value = (delta[start + i + c] + guess) & 0xFF
                out[i + c] = value
                left[c] = value
        above = bytes(out)
        yield above
