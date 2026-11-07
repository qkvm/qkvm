"""What the wall needs from a KVM, and the client for GLKVM / PiKVM (kvmd) devices."""

from __future__ import annotations

import asyncio
import contextvars
import errno
import hashlib
import json
import logging
import re
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.client import connect as _ws_connect
from websockets.exceptions import InvalidStatus, WebSocketException
from websockets.frames import CloseCode, Opcode

log = logging.getLogger("qkvm")

# Snapshot sizes the wall may ask for: name -> (max width, max height, JPEG quality).
# kvmd scales the frame on the device. "full" is the frame exactly as captured.
#
# Measured on a Comet Pro showing 2560x1440: shrinking a frame takes the KVM 150-400 ms and
# only pays off for small pictures (a 960 px frame is ~60 KB against ~165 KB for the full one).
# Above that, a shrunk frame is as large as the original and ten times slower to get, so
# anything wider than the last size here is served as the full frame, which costs the KVM
# next to nothing (~50 ms). Quality is kept high: screen text turns to mush below ~85.
TIERS: dict[str, tuple[int, int, int]] = {
    "480": (480, 270, 86),
    "640": (640, 360, 88),
    "960": (960, 540, 90),
}
FULL = "full"

# What the wall can ask a device to do: action -> (path, query).
ACTIONS: dict[str, tuple[str, dict[str, str]]] = {
    "reboot": ("/api/upgrade/reboot", {}),  # restarts the KVM itself
    "ctrl_alt_del": ("/api/hid/events/send_shortcut", {"keys": "ControlLeft,AltLeft,Delete"}),
    "atx_power": ("/api/atx/click", {"button": "power"}),
    "atx_power_long": ("/api/atx/click", {"button": "power_long"}),
    "atx_reset": ("/api/atx/click", {"button": "reset"}),
    "jiggler_on": ("/api/hid/set_params", {"jiggler": "1"}),  # the KVM nudges the mouse to keep the computer awake
    "jiggler_off": ("/api/hid/set_params", {"jiggler": "0"}),
}
# What a tile can do, by word: the whole vocabulary, in the order a list of them is written in. A driver
# says which hold for every device of its kind (`Device.can`), and its look at the device adds what that
# one has (`can` in its status: a power board, several inputs, a light): what a client may ask of the
# machine, said by the server, so that no client guesses it from the kind. Each word opens actions of
# POST /api/v1/devices/{id}/actions, or a request (the README, "The API", says which). The words and the
# labels the page shows for them are in static/words.json; one that is not in there is a mistake.
ABILITIES = (
    "screen", "keys", "text", "jiggler", "power", "reset", "fingerbot", "power_state", "wol", "ports", "reboot", "resume",
    "locator", "console", "live", "control", "bios_setup", "media",
)  # fmt: skip


# --- virtual media (0.3.0): what every family's driver fills in ------------------------------------------------------
# Mounting an image is root on that machine (an installer, a rescue system): a right of its own (the server's MEDIA_ROLE,
# an admin's), a person's and never a token's, every mount, unmount and start from it in the activity log, and a device
# only ever handed what qKVM itself listed or made: never an address somebody typed (a device that fetches an address is
# a way into the network it stands in). A driver says what this machine can do (`Device.media_offer`, a MediaOffer, by
# what the last look at it found: a KVM whose own storage is switched off offers none) and does it (`Device.media_*`);
# the server and the page go by that, never by the kind.

# How a machine can be told to start from what is mounted: for its next start only, or for as long as it is mounted.
MEDIA_BOOTS = ("once", "until_unmounted")
# What an image is mounted as: a CD-ROM drive (always read-only), a USB flash drive (kvmd: read-only unless the person
# chooses it writable), a disk (a JetKVM's: read-only, its own drive has no other way).
MEDIA_DRIVES = ("cd", "flash", "disk")
MOST_UPLOAD = 16_000_000_000  # bytes: the largest image carried through qKVM to a device's own storage (the owner's, 2026-11-03)
# The name of an image on a device's own storage, as qKVM lists it and hands it back: printable ASCII that no device takes
# for a path or an option (no slash, no leading dot or space), 200 characters at most. One of a KVM that keeps images in
# folders is such names joined by slashes (kvmd lists them so); an upload is always one name.
IMAGE_NAME = re.compile(r"[A-Za-z0-9_+()\[\]~-](?:[A-Za-z0-9 _.,+()\[\]~-]{0,198}[A-Za-z0-9_+()\[\]~-])?")
DEVICE_IMAGE = re.compile(rf"{IMAGE_NAME.pattern}(?:/{IMAGE_NAME.pattern}){{0,3}}")
# The drive of a kvmd KVM and of a JetKVM is Linux's USB gadget, whose CD-ROM drive takes an image of 300 sectors of 2048
# bytes at least ("the smallest track is 300 frames", storage_common.c) and refuses a smaller one with a word of the
# kernel's (errno 525, seen on a real JetKVM); of one larger than 256*60*75 sectors it gives the machine only the start,
# MOST_CD bytes, and says so in the kernel's log alone (the page says it at the mount).
LEAST_CD = 300 * 2048
# kvmd lists an image once its watch on the storage has seen the file: some two seconds after its write was answered, on
# kvmd's own test environment (a trial before the release of 0.3.0). Asked again until then, at most this long.
LISTED_WITHIN = 10.0  # seconds, after a write answered whole
LISTED_FOR_A_DISCARD = 3.0  # seconds, before what a cut-off write left is taken to be nothing
MOST_CD = (256 * 60 * 75 - 1) * 2048


def too_small_for_a_cd(name: str, size: int, other: str) -> KvmError | None:
    """Where `size` is less than a CD-ROM drive of Linux's USB gadget takes: the refusal, naming `other`, the drive that does."""
    if size >= LEAST_CD:
        return None
    return KvmError("invalid", f"{name} is {size:,} bytes, and a CD-ROM drive takes an image of {LEAST_CD:,} bytes at least (300 sectors of 2,048 bytes): mount it as {other}.", 422)


PARTIAL = ".incomplete"  # what a JetKVM adds to the name of an image while it is being uploaded (and after an upload cut off)
NAME_RULE = (
    "An image's name is of letters, digits, spaces and . _ + - ( ) [ ] ~ , (200 at the most), and neither begins nor ends with "
    "a space or a dot. Rename the file and upload it again."
)
MOST_DEVICE_IMAGES = 2000  # images of a device's own storage listed to pick from
# An upload is carried on a connection of its own to the device: it may take seconds to connect, as any request, and the
# device as long as UPLOAD_ANSWER to say it has the image once the last byte is out (kvmd writes the rest of it to its
# storage first); a device that takes nothing for UPLOAD_STALL seconds meanwhile has the upload ended. UPLOAD_MOST, the
# longest an upload may take all told: sixteen gigabytes at a megabyte a second, and more.
UPLOAD_STALL = 60.0
UPLOAD_ANSWER = 300.0
UPLOAD_MOST = 24 * 3600.0
UPLOAD_WAITS = httpx.Timeout(connect=4.0, read=UPLOAD_ANSWER, write=UPLOAD_STALL, pool=4.0)
DISCARD_WAIT = 15.0  # seconds what an upload cut off left waits to be removed, while the device is still busy with its end


@dataclass(frozen=True)
class MediaOffer:
    """What a machine's virtual media can do, as its driver says it."""

    drives: tuple[str, ...]  # of MEDIA_DRIVES: what an image can be mounted as
    boot: tuple[str, ...]  # of MEDIA_BOOTS: how it can be told to start from it; () where it cannot (a KVM is no firmware)
    restart: bool  # it can be restarted from here: to start from it now, or (with no `boot`) for its firmware to find it
    upload: bool  # an image can be streamed through qKVM into the device's own storage, and kept nowhere on the way
    where: str  # where the images are: "proxmox" (its storages), "device" (the KVM's own), "qkvm" (a folder qKVM serves)
    writable: tuple[str, ...] = ()  # of `drives`: those an image may be mounted writable in, where the person chooses that
    delete: bool = False  # an image can be deleted from where it is (the device's own storage)
    # A mount or an unmount, where it changes the drive from one kind to the other, drops the machine's keyboard and mouse
    # for a moment (a JetKVM binds its whole USB device anew): the page says so first.
    drops_input: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "drives": list(self.drives), "boot": list(self.boot), "restart": self.restart, "upload": self.upload, "where": self.where,
            "writable": list(self.writable), "delete": self.delete, "drops_input": self.drops_input,
        }  # fmt: skip


class UploadCut(Exception):
    """An image on its way through qKVM stopped before its last byte: the sender stopped or went quiet, or sent more."""


class Carried:
    """An image on its way through qKVM to a device's own storage: `size` bytes, counted and hashed as they pass and kept
    nowhere (a piece at a time in memory, no file). Iterated once, by the driver that hands it on; UploadCut, raised from
    inside the iteration, where the pieces end before `size` bytes or go beyond it (`cut` says why, however the HTTP
    library hands the error on). `sha256` once the last byte has passed."""

    def __init__(self, pieces: Any, size: int) -> None:
        self.size = size
        self.sent = 0
        self.cut: str | None = None
        self.sha256: str | None = None
        self._pieces = pieces  # an async iterator of bytes
        self._hash = hashlib.sha256()
        self._begun = False

    async def __aiter__(self) -> Any:
        if self._begun:
            raise UploadCut("An image is carried once")
        self._begun = True
        try:
            async for piece in self._pieces:
                if self.sent + len(piece) > self.size:
                    raise UploadCut("More came than the upload said it would be")
                self._hash.update(piece)
                self.sent += len(piece)
                yield piece
        except UploadCut as ex:
            self.cut = self.cut or str(ex)
            raise
        if self.sent != self.size:
            self.cut = self.cut or "The upload ended before the image came in full"
            raise UploadCut(self.cut)
        self.sha256 = self._hash.hexdigest()


class MediaNotes:
    """What qKVM did to a device's virtual media, kept while it runs beside the tiles (which are made anew at every edit):
    who mounted which image from here, and the SHA-256 of each image it carried to the device, with the size and the time
    the device gave it (a hash is said of an image only while both are still those: another image of the same name, put
    there on the device itself, is not said to be it). Gone at a restart of qKVM."""

    MOST = 2048

    def __init__(self) -> None:
        self.mounted: dict[str, tuple[str, str, float]] = {}  # device -> (image, by, at)
        self.hashes: dict[str, tuple[str, int, Any]] = {}  # device \0 image -> (sha256, size, the device's time of it)

    @staticmethod
    def _keep(table: dict[str, Any], key: str, value: Any) -> None:
        table.pop(key, None)  # (the newest last)
        table[key] = value
        while len(table) > MediaNotes.MOST:
            del table[next(iter(table))]

    def mounted_by(self, device: str, image: str, by: str) -> None:
        self._keep(self.mounted, device, (image, by, time.time()))

    def who(self, device: str, image: str) -> tuple[str | None, float | None]:
        found = self.mounted.get(device)
        return (found[1], found[2]) if found is not None and found[0] == image else (None, None)

    def carried(self, device: str, image: str, sha256: str, size: int, stamp: Any) -> None:
        self._keep(self.hashes, f"{device}\0{image}", (sha256, size, stamp))

    def hash_of(self, device: str, image: str, size: Any, stamp: Any) -> str | None:
        found = self.hashes.get(f"{device}\0{image}")
        return found[0] if found is not None and found[1] == size and found[2] == stamp else None

    def forget(self, device: str, image: str) -> None:
        self.hashes.pop(f"{device}\0{image}", None)


MEDIA_NOTES = MediaNotes()


# How a machine's pointer is moved over the live line (`Device.pointer_kind`): to a place, by steps, or either.
POINTER_ABSOLUTE, POINTER_RELATIVE, POINTER_BOTH = "absolute", "relative", "both"


def can_do(*words: str | None) -> list[str]:
    """These abilities as a list: each once, in the order of ABILITIES. None stands for one that does not hold."""
    said = {word for word in words if word is not None}
    if unknown := said - set(ABILITIES):
        raise ValueError(f"not an ability: {', '.join(sorted(unknown))}")
    return [word for word in ABILITIES if word in said]


MAC = re.compile(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}")
# Up to eight key names as browsers and kvmd spell them: "ControlLeft,AltLeft,Delete".
KEYS = re.compile(r"[A-Z][A-Za-z0-9]{1,15}(,[A-Z][A-Za-z0-9]{1,15}){0,7}")
# The keyboard's Power key shuts a machine down without the question a power action is asked first: no driver sends it
# (kvmd is told the names as they come and has it; every other has no such name in its table), nor does the live line.
# A saved action naming it is refused where it is saved, by the API or from a file, as a run refuses it.
POWER_KEY_REFUSED = "The keyboard's Power key is not sent. A machine's power is under Power."


def names_the_power_key(keys: str) -> bool:
    return "Power" in keys.split(",")


MAX_TEXT = 2000  # characters one "type text" action may send
MAX_PORTS = 16  # inputs of a multi-port KVM the wall will list

FRAME_MIN_AGE = 0.2  # viewers asking within this window share one frame
MAX_SHARED_AGE = 5.0  # ...and a viewer that refreshes slowly may settle for one this old, at most
FIRST_CONTACT_WAIT = 0.6  # how long a request for a picture waits for a device nothing is known about yet
PICTURE_PATIENCE = 1.5  # how long a request for a picture waits for the device before the tile is told to ask again
ERROR_HOLD = 1.0  # after a failure, leave the device alone for this long; doubles while it stays down
BACKOFF_MAX = 15.0  # ...up to this long between attempts
STATUS_TTL = 4.0
STATUS_FIRST_WAIT = 1.5  # how long the very first status of a device may hold a caller up
ABOUT_TTL = 600.0  # model and firmware version rarely change
ABOUT_RETRY = 60.0  # ...and how soon a kvmd KVM is asked again whose answer said neither whether it is GL.iNet's nor stock (see KvmDevice._glinet)
# A power board the KVM said it has, this long ago or less, is not taken away by a look that says otherwise or says
# nothing. A Comet's board answers one asker at a time and tells whoever asks meanwhile that there is none (two askers
# at once on a real one, 2026-10-14: one answer in five); the tile's power buttons went with each such answer.
BOARD_KEPT = 60.0
# ...and what it said of the computer is kept this long through such answers, which say nothing of it: the tile went from
# "Powered off" to "No signal" and back at each, while the computer stayed as it was.
POWER_KEPT = 10.0
# How long a KVM's power board holds each button after it has answered the click. A Comet answers at once and holds on
# (its own page says half a second, and six and a half for the long press; on a real one a computer that was off came on
# at a long press and went off again seconds later, its `busy` long over) and stock kvmd holds a tenth and five and a
# half seconds. Until the button is let go the machine is being done something to: a second press meanwhile was taken
# by the board as well, and a power button pressed twice undoes itself.
HELD = {"atx_power": 0.5, "atx_power_long": 6.5, "atx_reset": 0.5}
# The click's answer is waited for this long (the next piece of it, as for every request). Only a 4xx is a no: a 5xx (the
# KVM's web server says 502, 503 or 504 while kvmd restarts behind it, kvmd itself 500), none in time, or one that broke off
# says neither, and the board may have pressed. Then the board is left alone, whoever asks, for as long as a click taken
# then can still come to be pressed and held: this long and the button's hold (HELD), from when the answer came or was given
# up on (a KVM may go on with a request whose asker gave up). Said "not pressed", the page offered the press again, and a
# power button pressed twice undoes itself.
BOARD_ANSWER = 8.0
# After the button is let go, a press that must change the computer's power (a short one on a computer that is off, the
# long one on a computer that is on) is waited for until the board shows the change, this long at most, this often. A
# Comet's word followed the computer three or four seconds late, on and off alike.
SEEN_WITHIN = 20.0
SEEN_EVERY = 1.0
# A KVM's power board says how it is on the KVM's line for events (kvmd's /api/ws), at once and at every change, as the KVM's
# own page reads it; asked at /api/atx instead, a Comet's board answers one asker at a time and tells whoever asks meanwhile
# that there is none (the wall's questions, once a look, gave a second wall or a script beside it "no board": one answer in
# five, on a real one). So where the wall holds that line anyway, while somebody watches the KVM's picture (the keepalive,
# `_hold_stream_open`), it hears the board there and does not ask it. No line is opened for the board alone: three times the
# sleeping PC behind a real Comet woke within seconds of one being opened (twice more it did not). The line is asked
# whether it is there every EVENTS_PING seconds (kvmd's own `ping`, answered `pong`), and what it said of the board counts
# while it was heard from within EVENTS_QUIET seconds. Before a press the board is asked all the same (see `_board_now`).
EVENTS_PING = 5.0
EVENTS_QUIET = 12.0
MOST_EVENT = 2**20  # bytes one message on that line may be (what arrives is mostly thrown away, but is held in memory first)
MOST_BOARD_WORD = 4096  # ...and the longest that is read as the board's state (a Comet's is some 90 bytes)
# kvmd's `msd` event on that line: the state of its drive and of its own storage (every image named in it: kilobytes), read
# up to this length. What is mounted is said there as it changes; where no line is held, a look asks /api/msd, every this
# many seconds at the most (a GL.iNet KVM looks at its storage's partitions for every such answer).
MOST_MSD_WORD = 2**18
# What qKVM reads of kvmd's state of its drive (GET /api/msd, the line's `msd` event), and all it keeps of it: a KVM may
# say more, and with every word of the line; what is kept is replaced key by key, each from one word or answer.
MSD_KEPT = ("enabled", "online", "busy", "drive", "drive_partition")
MSD_STORAGE_KEPT = ("images", "parts")
MSD_EVERY = 30.0
# Set once the KVM has answered a power button's click, for the time the button is held and its change waited for: a
# request cut off after that (the wall stopped) was pressed, and is said so, not "may have been done" and offered again.
PRESS_ANSWERED: contextvars.ContextVar[bool] = contextvars.ContextVar("press_answered", default=False)
# Said by a driver that knows when its press goes out (the Fingerbot's): False until the click is on its way, True from then
# on; None where the driver does not say. A request cut off by qKVM stopping while it was False pressed nothing: the KVM was
# only being asked (whether a Fingerbot is paired, say), and the log says so, not "it may have been done".
PRESS_SENT: contextvars.ContextVar[bool | None] = contextvars.ContextVar("press_sent", default=None)
# Whether the request KvmDevice._request was asked to send last can have reached the KVM: False until it is handed to the
# connection, True from then on, and False again where it failed in a way that shows it never got there (went_out: no
# connection to the KVM was had in time). Signing in first, the tile retired before the send: it never went out. A power
# button's click that never went out pressed nothing, and holds nothing (register row 4 of 0.2.1, fx-a N2, w16c).
REQUEST_OUT: contextvars.ContextVar[bool] = contextvars.ContextVar("request_out", default=False)
# GL.iNet's Fingerbot, paired with a Comet over Bluetooth, presses a machine's power button with an arm, for a machine
# that has no ATX board. The Comet says whether one is paired in a `fingerbot` event on its line for events
# (`{"exist": true}`, and nothing more: a real one, 2026-10-18), and has no route that says it. A press is
# POST /api/fingerbot/click with the time to hold, in milliseconds, and the strength (`angle_enum`); the Comet's own page
# offers 0.5, 3 and 8 seconds. These two: a short press, and the eight seconds that force a computer off.
FINGERBOT_PRESSES = {"fingerbot_power": 0.5, "fingerbot_power_long": 8.0}
FINGERBOT_STRENGTHS = {"firm": "2", "light": "1"}  # the Comet's `angle_enum` for "Firmly Press" (its own page's default) and "Lightly Press"
# The real one answered every press 1.9 to 2.5 seconds after it was sent, "success", for half a second, three and eight alike:
# its answer says the Fingerbot took the press, not that the press is over. So the machine is held for the press's own time
# after the answer, and a moment more for the arm to come back up (that moment was not measured: the Fingerbot lay loose on a
# desk). The answer is waited for as long as the Comet's own page waits: eight seconds beside the press's own time.
FINGERBOT_ANSWER = 8.0
FINGERBOT_BACK = 1.0
# A line to the KVM's events is opened before a press only where the KVM has not said either way (nobody has watched its
# picture since qKVM started, say), and its word waited for this long. The real one said it 0.2 to 2.0 s after a line
# opened, and twice some 4.3 s (each time while another line of somebody else's was open to it, on which it then said it
# again). A press goes to the machine anyway, so the line opened for it wakes nothing that the press would not; where the
# KVM said there is none, a press is refused without one (opened for nothing, a line can wake a sleeping computer: see
# EVENTS_PING).
FINGERBOT_ASK_WITHIN = 10.0
# What it said (that none is paired), or that it said nothing when it was asked, stands for this long: a press meanwhile is
# refused without a line opened to ask again. After that it is asked again: one may have been paired since, and a script
# with nobody watching the picture has no other way to find out (the Comet saying it of its own accord was not seen).
FINGERBOT_ASK_AGAIN = 120.0
# Its battery is a question of its own (GET /api/fingerbot/battery, answered `{"battery": 101}` in kvmd's `result`: a round
# trip to the Fingerbot, 0.6 to 0.7 s on the real one), which the Comet's own page asks once when its accessories are opened:
# here once an hour while one is paired (one paired anew within ten minutes of the last question), again after ten minutes
# where it was not answered, never while a press is under way or may be. Below FINGERBOT_LOW percent it is low, as the Comet's own page shows it.
FINGERBOT_BATTERY_EVERY = 3600.0
FINGERBOT_BATTERY_RETRY = 600.0
FINGERBOT_LOW = 25
# ...and its answer is waited for this long, no longer (and the whole of it a few seconds more, for a connection and one that
# trickles in): a person's press waits for a question under way (the Comet talks to its Fingerbot one request at a time),
# and a Fingerbot out of reach is not to hold the press up for half a minute.
FINGERBOT_BATTERY_WAIT = 3.0


class Paced:
    """What paces one KVM's power buttons and the questions to its Fingerbot: until when a press with no clear answer may
    still be pressing (the Fingerbot's, `held_until`; the power board's, `board_until`; time.monotonic()), and the
    Fingerbot's "none" window: whether one is paired as the KVM said last, when it said so, and when a line opened to ask it
    heard nothing (FINGERBOT_ASK_AGAIN); and its battery as last answered, when it was asked, and when it may be asked
    again (FINGERBOT_BATTERY_EVERY)."""

    def __init__(self) -> None:
        self.held_until = 0.0
        self.board_until = 0.0
        self.fingerbot: bool | None = None
        self.fingerbot_heard_at = float("-inf")
        self.fingerbot_silent_at = float("-inf")
        self.battery: int | None = None
        self.battery_next = 0.0
        self.battery_asked_at = float("-inf")

    def idle(self, now: float) -> bool:
        """Whether it paces nothing any more, and holds no word of the KVM's."""
        return (
            self.held_until <= now and self.board_until <= now and self.fingerbot is None and now - self.fingerbot_silent_at >= FINGERBOT_ASK_AGAIN
            and self.battery is None and self.battery_next <= now
        )  # fmt: skip


class _AllPaced:
    """Every KVM's Paced, kept beside the connections for as long as the program runs (as REJECTED is), not in a client:
    a client made anew (an edit, at its address or another; the wall locked and opened again; the tile removed and added
    again at its address) finds what paces its KVM as the client before left it (register row 10 of 0.2.1, fx-a L2,
    w16c: each of them started afresh, and a press with no clear answer could be followed by another at once). Found by
    the KVM's address, and by its certificate where one is pinned (as core.identity knows a KVM at another of its
    addresses): a tile removed and added again keeps its address, one edited to another address of the KVM is shown the
    KVM's certificate there. Not by the tile's id (until 0.3.0): a tile edited to another KVM took the hold along, the KVM
    there was "busy" with a press it never had, and the tile was told what the KVM before said of its Fingerbot. Where
    nothing tells the KVM at a new address from another (plain HTTP), it starts afresh there, as its saved password is
    typed again. Nor by a certificate the tile is not known by: one kept beside another that shows it ("own:", see
    core.identity; KVMs behind one front door, which all show the door's) is found by its own address alone, apart
    from what the others found there. Not across a restart of the program."""

    MOST = 4096  # entries kept before those that pace nothing any more are let go of

    def __init__(self) -> None:
        self._by_mark: dict[str, Paced] = {}
        self._by_address: dict[str, Paced] = {}

    @staticmethod
    def _keys(spec: DeviceSpec) -> tuple[str | None, str]:
        if spec.ident.startswith("own:"):
            return None, f"own\0{spec.base_url}"
        return (saved_mark(spec.cert_pem) if spec.tls == "pinned" else None), spec.base_url

    def find(self, spec: DeviceSpec) -> Paced:
        """What paces this KVM; a Paced of nothing where nothing does (not kept: write through `of`). One found by the
        KVM's certificate is kept under the address it is at now as well, and one found by the address under the
        certificate: a tile edited to another address of the KVM, and then removed and added again there, still finds it.
        (Asked afresh each time: a certificate is pinned at the first contact, after the client is made.)"""
        mark, address = self._keys(spec)
        mine = self._by_mark.get(mark) if mark else None
        there = self._by_address.get(address)
        if mine is not None and there is None:
            self._by_address[address] = mine
        elif there is not None and mine is None and mark:
            self._by_mark[mark] = there
        return mine or there or Paced()

    def of(self, spec: DeviceSpec) -> Paced:
        """What paces this KVM, kept from now on under its certificate and its address."""
        mark, address = self._keys(spec)
        mine = self._by_mark.get(mark) if mark else None
        there = self._by_address.get(address)
        found = mine or there
        if found is None:
            if len(self._by_mark) + len(self._by_address) > self.MOST:
                now = time.monotonic()
                self._by_mark = {key: paced for key, paced in self._by_mark.items() if not paced.idle(now)}
                self._by_address = {key: paced for key, paced in self._by_address.items() if not paced.idle(now)}
            found = Paced()
        elif mine is not None and there is not None and mine is not there:
            # A KVM's certificate shown at an address another tile had (with no certificate, or another one): one KVM
            # there, and what paced either paces it from now on.
            mine.held_until, mine.board_until = max(mine.held_until, there.held_until), max(mine.board_until, there.board_until)
            if there.fingerbot_heard_at > mine.fingerbot_heard_at:
                mine.fingerbot, mine.fingerbot_heard_at = there.fingerbot, there.fingerbot_heard_at
            if there.battery_asked_at > mine.battery_asked_at:
                mine.battery, mine.battery_next, mine.battery_asked_at = there.battery, there.battery_next, there.battery_asked_at
            mine.fingerbot_silent_at = max(mine.fingerbot_silent_at, there.fingerbot_silent_at)
            for keys in (self._by_mark, self._by_address):
                for key in [key for key, paced in keys.items() if paced is there]:
                    keys[key] = mine
            found = mine
        if mark:
            self._by_mark[mark] = found
        self._by_address[address] = found
        return found

    def clear(self) -> None:
        self._by_mark.clear()
        self._by_address.clear()


PACED = _AllPaced()


class FingerbotTurn:
    """One request to a Comet's Fingerbot at a time from this program (a press, a question of its battery), shared by the
    clients of one KVM at one address (see KvmDevice.takes_over); and until when it may still be pressing after a press
    whose answer said neither yes nor no (time.monotonic()), during which nothing more is sent to it. The same for the
    KVM's power board (`board_until`, see BOARD_ANSWER): the machine's power buttons, which are one. The two times are
    kept in PACED, beside the connections, where a client made anew finds them."""

    def __init__(self, spec: DeviceSpec) -> None:
        self.lock = asyncio.Lock()
        self._spec = spec  # (the client's own: the certificate pinned at its first contact is in it from then on)

    @property
    def held_until(self) -> float:
        return PACED.find(self._spec).held_until

    @held_until.setter
    def held_until(self, value: float) -> None:
        PACED.of(self._spec).held_until = value

    @property
    def board_until(self) -> float:
        return PACED.find(self._spec).board_until

    @board_until.setter
    def board_until(self, value: float) -> None:
        PACED.of(self._spec).board_until = value

    def held(self) -> float:
        """Seconds it may still be pressing; 0 where it is not."""
        return max(0.0, self.held_until - time.monotonic())

    def board_held(self) -> float:
        """Seconds the KVM's power board may still be pressing a button; 0 where it is not."""
        return max(0.0, self.board_until - time.monotonic())
LOGIN_BACKOFF = 60.0  # after a rejected password, don't try again for this long
# ...and for longer after each rejection that follows it without a login accepted in between: from the fourth
# on, once an hour. A password that was rejected does not become right by being offered again, and a device
# that locks an account after a few wrong ones (a server's controller does) kept it locked for as long as a
# wrong one was saved here, a try a minute: for the people who run the machine too.
LOGIN_BACKOFFS = (LOGIN_BACKOFF, 300.0, 900.0, 3600.0)
STILL_THERE_EVERY = 30.0  # while a password waits to be offered again, how often the device is asked whether it is there at all
SIGN_IN_PATIENCE = 2.5  # an answer to a sign-in is waited for this many times longer than any other: some devices hold a no back on purpose
UNANSWERED_MOST = 300.0  # the longest a password is held back after sign-ins that nothing answered, where no no was heard before them
KEEPALIVE_IDLE = 30.0  # drop the stream keepalive once nobody has asked for a frame for this long
# The owner's standard for what costs a machine something each time and is done now and then, or held for nobody (decided
# 2026-10-18): a guest's console held after its last viewer; a lying Proxmox's console asked for again; a still of a PC with
# Intel AMT whose tile is only shown; how such a PC's KVM is set up (consent) read again.
STANDARD_HOLD = 300.0
KEEPALIVE_LASTS = 5.0  # ...and one that the KVM ended sooner than this after it was made is begun again only after a pause
MAX_REPLY = 2 * 1024 * 1024  # bytes a device may send in answer to anything but a picture
MAX_PICTURE = 32 * 1024 * 1024  # ...and as one picture (a 4K frame, uncompressed, is 25 MB)
MOST_UNIT = 8 * 1024 * 1024  # ...and as one picture of its H.264 stream, an access unit (a 4K key frame is a megabyte or two)
PACKED_MARGIN = 64 * 1024  # bytes a packed answer may be larger, as it arrives, than the most it may unpack to
MAX_PROBE = 64 * 1024  # ...and to "are you a KVM?", asked of addresses nothing is known about
# The size a picture may claim to be. A hundred kilobytes can say they are sixteen thousand pixels square,
# and the browser that believes them needs a gigabyte to find out. (8K video is 7680 x 4320.)
MAX_PICTURE_SIDE = 16384
MAX_PICTURE_PIXELS = 40_000_000
LOGIN_RETRY = 10.0  # after a sign-in that failed for another reason than the password, don't try again for this long (twice as long each time: see Rejected.unanswered)
WAITS = httpx.Timeout(8.0, connect=4.0)  # seconds a device has to accept a connection, and to send the next piece of an answer
TRANSFER_TIME = 20.0  # seconds an answer may take to arrive in full, once the device has begun to send it
CERT_TIMEOUT = 5.0  # seconds a device has to show its certificate
CONNECT_MARGIN = 0.5  # the time for a whole exchange is at least this much more than getting a connection can take
STOP_TRIES, STOP_WAIT = 4, 0.5  # how often a task is told to stop, and how long each time is waited for it to

# Failures that mean "the device is not there (or is not the device)", as opposed to "it said no".
DOWN_CODES = frozenset({"unreachable", "timeout", "dropped", "cert_mismatch", "cert_invalid"})
_NO_CHECK_TIME = 0x200000  # OpenSSL's X509_V_FLAG_NO_CHECK_TIME; the ssl module has no name for it


NO_SAID = "Login rejected - check the username and password"  # what a tile says whose saved login the device does not take


class AlreadySo(Exception):
    """An action found nothing to do: what it was to bring about is so already. Its text says what ("already on")."""


class NotSeen(AlreadySo):
    """A power button was pressed, and the change it was to bring was not seen within the time it was looked for. Done,
    with a word on what was seen ("pressed, but the computer is still off"): not a failure, whose retry would press the
    button a second time on a computer that may be on its way."""


def wait_after_rejections(times: int) -> float:
    """How long a password is not offered to a device again that it rejected this many times in a row."""
    return LOGIN_BACKOFFS[min(max(times, 1), len(LOGIN_BACKOFFS)) - 1]


ROADS = ("login", "web")  # the sign-in a device is used through, and (a server's controller) that of its own web page
Kept = tuple[int, int, float]  # noes in a row, sign-ins in a row that came to nothing, when it may be offered again
Sent = tuple[Kept | None, Kept]  # of a sign-in that goes out: what was known before, and what was noted as it went


class Rejected:
    """Which passwords devices have said no to, and when each may be offered again.

    Kept here, and not in the connection to a device. A connection is made anew when the saved passwords
    were locked and are opened again, when the listeners are reopened, when a tile is saved under another
    name; each new one began to count at nothing, and the first of those is to be had by any account that
    may sign in, as often as it likes. What is kept is a digest of the address, the user name and the
    password, in memory: never the password, and nothing of it is written anywhere.
    """

    MOST = 2048  # of them; the oldest go first (somebody adding devices with one wrong password after another)

    def __init__(self) -> None:
        # (noes in a row, sign-ins in a row that nothing answered, when it may be offered again)
        self._known: dict[str, tuple[int, int, float]] = {}

    @staticmethod
    def what(road: str, spec: DeviceSpec) -> str:
        """What was offered where, as a mark to know it by again."""
        said = "\0".join((road, spec.base_url, spec.username, spec.password or ""))
        return hashlib.sha256(said.encode("utf-8", "surrogatepass")).hexdigest()

    def times(self, what: str) -> int:
        """How many times in a row it was told no. (What came to nothing in between is not one, and does not end the row.)"""
        return self._known.get(what, (0, 0, 0.0))[0]

    def wait_left(self, what: str) -> float:
        """Seconds until it may be offered again; nothing where it may be now, or was never refused."""
        return max(0.0, self._known.get(what, (0, 0, 0.0))[2] - time.monotonic())

    def _keep(self, what: str, times: int, unanswered: int, wait: float) -> float:
        # (Never sooner than what stands already: nothing here shortens a wait.)
        now = time.monotonic()
        standing = self._known.pop(what, (0, 0, 0.0))[2]
        self._known[what] = (times, unanswered, max(now + wait, standing))  # (the newest last)
        while len(self._known) > self.MOST:
            del self._known[next(iter(self._known))]
        return max(wait, standing - now)

    def said_no(self, what: str) -> float:
        """One more no in a row: how long it is not offered again."""
        times = self.times(what) + 1
        self._known.pop(what, None)  # (a verdict: what `sent` noted of this very sign-in is not a wait to be kept)
        return self._keep(what, times, 0, wait_after_rejections(times))

    @staticmethod
    def _quiet(unanswered: int) -> float:
        return float(min(LOGIN_RETRY * 2 ** min(max(unanswered, 1) - 1, 10), UNANSWERED_MOST))

    def sent(self, what: str) -> Sent:
        """It goes out now. Until its answer is noted, it stands as one that nothing answered. Hands back what `put_back` needs.

        Noted only once the answer had come, a sign-in whose connection was retired meanwhile (the last
        person signed out, and the wall locks itself) left nothing behind, and the next connection sent
        the password again at once: as often as a viewer cared to sign in and out, to a device slow to say no.
        """
        before = self._known.get(what)
        times, unanswered, _ = before or (0, 0, 0.0)
        self._keep(what, times, unanswered + 1, self._quiet(unanswered + 1))
        return before, self._known[what]

    def put_back(self, what: str, mark: Sent) -> None:
        """It did not go out after all (no connection was to be had): what was known before `sent` is what is known.

        Only where nothing was noted since. Two connections to one device can both be signing in: the one
        hears a no, the other finds no connection to be had after that. Putting back what it had found,
        it took the no away with its own mark, and the password went out again at once.
        """
        before, noted = mark
        if self._known.get(what) != noted:
            return
        del self._known[what]
        if before is not None:
            self._known[what] = before

    def unanswered(self, what: str) -> float:
        """What came back says neither yes nor no, or nothing came back: how long it is not sent again, from now.

        Never held to be a no, before one or after: the device may be starting, or hanging, or having
        one of its moments, with the right password saved all the while. Counted as one more no after a
        no, a controller that said 401 once as it started and 503 for some minutes after was shown as
        rejecting the login for a quarter of an hour, and for an hour had it taken longer. Not sent at
        every look either: after ten seconds, then twice as long each time, five minutes at the most.
        How often it was told no stays as it is, for the next no to count on. (The sign-in was counted
        when it went out, see `sent`; where it was not, this is the first.)
        """
        times, unanswered, _ = self._known.get(what, (0, 0, 0.0))
        return self._keep(what, times, max(unanswered, 1), self._quiet(unanswered))

    def silent(self, what: str) -> int:
        """How many sign-ins in a row came to nothing, counting the one that is out."""
        return self._known.get(what, (0, 0, 0.0))[1]

    def later(self, what: str, wait: float) -> float:
        """The device says when to come back (it has locked this address out for a while): then, and not sooner.

        That is no verdict on the password either, and counts as none: taken for one more no each
        time, a JetKVM that asked for a minute was left alone for a quarter of an hour.
        """
        times = self.times(what)
        self._known.pop(what, None)  # (what `sent` noted of this very sign-in is not a wait to be kept)
        return self._keep(what, times, 0, wait)

    def accepted(self, what: str) -> None:
        self._known.pop(what, None)

    def forget(self, spec: DeviceSpec) -> None:
        """A person has typed this password for this device just now: it is tried as if for the first time.

        Also where it is counted for the place the device is at as a whole (the guests of one Proxmox, which share
        the one verdict on a token): a device whose address goes on past its host and port.
        """
        parts = urlsplit(spec.base_url)
        whole = f"{parts.scheme.lower()}://{parts.netloc.lower()}"  # (as a device's address is written: see store.device_url)
        for road in ROADS:
            self._known.pop(self.what(road, spec), None)
            if whole != spec.base_url:
                self._known.pop(self.what(road, DeviceSpec(spec.id, spec.name, whole, spec.username, spec.password, spec.tls, spec.cert_pem, spec.kind)), None)

    def clear(self) -> None:
        self._known.clear()


REJECTED = Rejected()


def not_signing_in(why: str) -> KvmError:
    """What stands against a device that is there and does not sign this program in, for another reason than the password."""
    return KvmError("no_sign_in", f"The device does not sign qKVM in ({why}). It is asked again shortly.", 503)


def went_out(ex: BaseException) -> bool:
    """Whether a request that failed this way can have reached the device: not where no connection to it was had."""
    return not isinstance(ex, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))


def sign_in_waits() -> httpx.Timeout:
    """The waits of the request that signs in: for its answer, longer than for another's.

    A no that came later than the usual wait was not heard as a no: nothing was counted, and the
    password went out again at the next look.
    """
    return httpx.Timeout((WAITS.read or 8.0) * SIGN_IN_PATIENCE, connect=WAITS.connect)


class KvmError(Exception):
    def __init__(self, code: str, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class DeviceSpec:
    id: str
    name: str
    base_url: str
    username: str
    password: str = field(repr=False)  # in no log line, error message or debugger's view that shows a spec
    tls: str = "pinned"  # "pinned" | "system" | "insecure"
    cert_pem: str | None = None
    kind: str = "kvmd"  # which driver talks to it
    # The machine behind the address, by the number it gave for itself when it was added (store.DeviceRecord.machine):
    # a driver that can tell checks it before anything is sent to the machine. "": none remembered.
    machine: str = ""
    # What the tile is known by where it is not its certificate (store.DeviceRecord.ident): "own:...", kept beside another
    # tile that shows the same certificate (a front door's), is not found by that certificate (see _AllPaced).
    ident: str = ""
    fingerbot_strength: str = "firm"  # how hard a Fingerbot paired with the KVM presses: "firm" | "light" (FINGERBOT_STRENGTHS)
    amt_view: str = "stills"  # a PC with Intel AMT: "health", "stills" or "live" (store.DeviceRecord.amt_view); changed in place


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    content_type: str
    signal: bool  # False when the device captured its "no signal" placeholder
    taken_at: float  # when the device was asked for it (time.monotonic())
    # A still kept between sessions, and handed out as it is until the next (a PC with Intel AMT whose tile is only shown):
    # the snapshot route says how old it is (X-KVM-Age), and the tile says so.
    still: bool = False


def tier_for(width: int) -> str:
    """Smallest size that is at least `width` pixels wide, so the browser never has to upscale."""
    for name, (tier_width, _, _) in TIERS.items():
        if width <= tier_width:
            return name
    return FULL


def fingerprint(cert_pem: str) -> str:
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def certificate_mark(cert_pem: str) -> str:
    """A certificate as a mark to know its owner by. The same for a device whichever address it is reached at."""
    return "cert:" + hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem)).hexdigest()


def _as_remembered(cert_pem: Any) -> bytes | None:
    """A certificate out of the settings file, or None for what is none: cut short, mistyped, not a text."""
    try:
        der = ssl.PEM_cert_to_DER_cert(cert_pem)
    except (ValueError, TypeError, AttributeError):  # (what is no base64 is a ValueError)
        return None
    # (And begins as a certificate does. What is base64 and nothing else had a fingerprint in the tile's
    # dialog, beside the sentence that it cannot be read.)
    return der if len(der) > 4 and der[0] == 0x30 else None


def saved_fingerprint(cert_pem: Any) -> str | None:
    """The fingerprint of a remembered certificate, to show; None where there is none to show.

    Asked for every tile, at every look at the wall, by everybody. With `fingerprint`, which takes a
    certificate for granted, one that was cut short in the settings file was an error in the list of
    tiles: nobody got a wall, and no file could be read, for one device that could not be talked to.
    """
    der = _as_remembered(cert_pem) if cert_pem else None
    if der is None:
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def saved_mark(cert_pem: Any) -> str | None:
    """`certificate_mark` of a remembered certificate; None where what is remembered is none."""
    der = _as_remembered(cert_pem) if cert_pem else None
    return None if der is None else "cert:" + hashlib.sha256(der).hexdigest()


def pinned_context(cert_pem: str) -> ssl.SSLContext:
    """Trust exactly one certificate, whatever its dates or hostname say.

    Comet KVMs create their certificate before they know the date (it is "valid"
    1970-1979) and name it "localhost", so only its identity can be checked.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(cadata=cert_pem)
    # Plain ints: going through ssl.VerifyFlags would drop the bit it has no name for.
    flags = int(ctx.verify_flags) | int(ssl.VERIFY_X509_PARTIAL_CHAIN) | _NO_CHECK_TIME
    ctx.verify_flags = flags & ~int(ssl.VERIFY_X509_STRICT)  # type: ignore[assignment]
    return ctx


def other_way(url: str) -> str | None:
    """The same JetKVM's address the other way: over HTTPS for a plain one, plain for one over HTTPS.

    A JetKVM serves plain HTTP on port 80 and, once its owner turns its HTTPS mode on, HTTPS on port 443
    beside it; it sends nobody from the one to the other. None for an address that names a port of its
    own: that is somebody's own arrangement (a forwarded port, a front door), and where the other way
    would be is not known.
    """
    parts = urlsplit(url)
    try:
        usual = parts.port is None or parts.port == {"http": 80, "https": 443}.get(parts.scheme)
    except ValueError:  # a port that is not a number
        return None
    if not usual or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{'http' if parts.scheme == 'https' else 'https'}://{host}"


MOST_ASKED = 4  # addresses of one name that are each asked whether anything listens there


async def listens(url: str) -> bool:
    """Whether anything takes connections at the host and port of `url`, or may: False only where it was plainly refused.

    A JetKVM as it comes has nothing on its HTTPS port, and says so at once. A port that takes a connection,
    or lets one wait (a device slow to wake, a firewall that drops instead of refusing), is not that.
    """
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        async with asyncio.timeout(3.0):  # (never wait_for, which loses a stop up to Python 3.11: see Listening.message)
            found = await asyncio.get_running_loop().getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except (OSError, TimeoutError):
        return True  # where it is cannot be found out just now: not "nothing is there"
    addresses = list(dict.fromkeys(str(entry[4][0]) for entry in found))
    if len(addresses) > MOST_ASKED:
        # Not all of them are asked, so "every one refused" cannot be said: and that is the answer on which
        # a password goes out in the clear to what answers the plain way.
        return True

    async def refuses(address: str) -> bool:
        # Each address by itself: asked for by name, two refusals come back as one error that does not say
        # what it is made of, and on Windows a refusal takes two seconds, so that two were never both heard.
        try:
            async with asyncio.timeout(4.0):
                _, writer = await asyncio.open_connection(address, port)
        except ConnectionRefusedError:
            return True
        except TimeoutError:
            return False
        except OSError as ex:
            # (An address of a kind this computer has no way to, IPv6 where there is none: nothing is there for it either.)
            return ex.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT)
        writer.close()
        return False

    return not all(await asyncio.gather(*(refuses(address) for address in addresses))) if addresses else True


def unverified_context() -> ssl.SSLContext:
    """For looking at a certificate without judging it, and for devices set to "don't check"."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _once(build: Callable[[], ssl.SSLContext]) -> Callable[[], Awaitable[ssl.SSLContext]]:
    """What `build` makes, made the first time it is asked for and kept.

    Made in a worker thread: reading a list of certificate authorities takes a quarter of a
    second, during which nothing else would move if it were done on the event loop.
    """
    made: list[ssl.SSLContext] = []
    making = threading.Lock()  # many KVMs are connected to at once when the program starts: still made only once

    def make() -> ssl.SSLContext:
        with making:
            if not made:
                made.append(build())
            return made[0]

    async def get() -> ssl.SSLContext:
        return made[0] if made else await asyncio.to_thread(make)

    return get


# Two lists of certificate authorities, each read once.
# A KVM set to "require a trusted certificate" is checked against the operating system's list,
# which is where a company puts the authority of its own that signed the KVM's certificate.
system_context = _once(ssl.create_default_context)
# Services on the internet (the alert address, GitHub for updates) are checked the way the HTTP library
# does it by itself: against the list it ships with, or the one SSL_CERT_FILE / SSL_CERT_DIR name.
public_context = _once(httpx.create_ssl_context)


async def fetch_certificate(base_url: str) -> str:
    """The certificate a device presents right now (PEM), without trusting it."""
    parts = urlsplit(base_url)
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(CERT_TIMEOUT):
            _, writer = await asyncio.open_connection(parts.hostname or "", parts.port or 443, ssl=unverified_context())
        tls = writer.get_extra_info("ssl_object")
        der = tls.getpeercert(binary_form=True) if tls is not None else None
        if not der:
            raise ValueError("no certificate was presented")
        return ssl.DER_cert_to_PEM_cert(der)
    except (OSError, ValueError) as ex:  # a wait that ran out is an OSError as well
        raise KvmError("unreachable", "Device is unreachable") from ex
    finally:
        if writer is not None:
            writer.transport.abort()  # nothing was sent that would deserve a goodbye


async def publicly_trusted(base_url: str) -> bool:
    """Does what answers at `base_url` show a certificate this computer trusts for that name as it is?

    A KVM on a shelf does not: it made its certificate itself, and the wall remembers it. One reached
    through somebody's front door does (Cloudflare, a company's proxy, a name under ts.net), and that
    certificate is replaced every few weeks. Remembered, it would raise "the certificate changed" at the
    first renewal, for no reason. Such a device is checked the way a browser checks it instead.
    """
    parts = urlsplit(base_url)
    writer: asyncio.StreamWriter | None = None
    try:
        context = await system_context()
        async with asyncio.timeout(CERT_TIMEOUT):
            _, writer = await asyncio.open_connection(parts.hostname or "", parts.port or 443, ssl=context, server_hostname=parts.hostname or "")
        return True
    except (OSError, ValueError):  # not trusted, not there, or too slow: all of them are "no"
        return False
    finally:
        if writer is not None:
            writer.transport.abort()  # nothing was sent that would deserve a goodbye


def _certificate_refused(ex: BaseException, tls: str) -> KvmError | None:
    """What stands against a connection that failed on the device's certificate; None where that was not it."""
    cause: BaseException | None = ex
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            if tls == "pinned":
                return KvmError("cert_mismatch", "Certificate does not match the one saved for this device")
            return KvmError("cert_invalid", "The device's certificate is not trusted")
        cause = cause.__cause__ or cause.__context__
    return None


def _transport_error(ex: BaseException, tls: str) -> KvmError:
    refused = _certificate_refused(ex, tls)
    if refused is not None:
        return refused
    if isinstance(ex, (httpx.ConnectError, httpx.ConnectTimeout)):
        return KvmError("unreachable", "Device is unreachable")
    if isinstance(ex, httpx.TimeoutException):
        return KvmError("timeout", "Device did not respond in time", 504)
    return KvmError("dropped", "The device closed the connection")


def ws_error(ex: BaseException, tls: str) -> KvmError:
    """The same, for a WebSocket to a device that could not be opened."""
    refused = _certificate_refused(ex, tls)
    if refused is not None:
        return refused
    if isinstance(ex, OSError):
        return KvmError("unreachable", "Device is unreachable")
    return KvmError("dropped", "The device closed the connection")


class _NoCookies(httpx.Cookies):
    """Where the cookies a device sets are not kept.

    The HTTP library keeps every cookie an answer sets, for as long as the client lives, and goes through
    all of them at every request. Nothing here uses that: each driver reads the token it needs out of the
    answer that brought it, and sends it itself. Kept, they are a store a device can fill: three thousand
    new names with every answer were a hundred megabytes within minutes, and seconds of work per request.
    """

    def extract_cookies(self, response: httpx.Response) -> None:
        return None


def _unpacker(reply: httpx.Response) -> Any:
    """What unpacks this answer's body, for a device that packed it although it was asked not to. None: it is not packed.

    One pass of gzip, which is what web servers have always sent, is unpacked. Nothing else was offered; and
    packing twice has one use, which is getting more out of a few bytes than a single pass allows.
    """
    said = [part.strip().lower() for part in reply.headers.get("content-encoding", "").split(",")]
    said = [part for part in said if part not in ("", "identity")]
    if not said:
        return None
    if said in (["gzip"], ["x-gzip"]):
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    # ("dropped", as for a connection that broke off: what is tried again is then tried with a pause that grows.
    # A sign-in answered like this must not be sent again, password and all, at every look.)
    raise KvmError("dropped", "The device packed its answer in a way this program does not unpack")


async def bounded(
    client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None
) -> httpx.Response:
    """Send `request` and read the answer, but never more than `limit` bytes of it, nor for ever.

    What answers may be a broken or hostile device, or not a KVM at all: it must not be able
    to fill this program's memory. The limit is on what the answer is once unpacked, and unpacking
    is not left to the HTTP library, which unpacks whatever has arrived in one go and only then hands
    it over to be counted: a hundred bytes can be megabytes by then. The device is asked not to pack
    its answer. One that does all the same is unpacked here, as far as the limit and no further.

    Nor may it keep a request open for as long as it likes. The waits set on the client apply to
    each step (connecting, the next piece of data), which a device sending a byte at a time never
    runs into. `within` is the time for the whole exchange, in seconds; left out, it is what the
    request's own waits add up to, plus TRANSFER_TIME for the data.

    The HTTP library does not reliably notice being stopped while it waits for a free connection or
    makes one: it may carry on regardless, and it leaves its pool of connections in a state it does
    not recover from. So `within` is never less than getting a connection can take (those steps end
    by their own waits), and a call to this must not be cancelled on a client that stays in use.
    """
    waits = request.extensions.get("timeout") or {}
    if within is None:
        within = (waits.get("connect") or 0.0) + (waits.get("read") or 0.0) + TRANSFER_TIME
    within = max(within, (waits.get("pool") or 0.0) + (waits.get("connect") or 0.0) + CONNECT_MARGIN)
    give_up = time.monotonic() + within
    too_much = KvmError("dropped", "The device sent far more data than this program accepts")
    request.headers["Accept-Encoding"] = "identity"
    if not isinstance(client.cookies, _NoCookies):
        client._cookies = _NoCookies()  # (the library offers no other way to have a client keep none)
    try:
        async with asyncio.timeout(within):
            reply = await client.send(request, stream=True)
            try:
                declared = reply.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > limit:
                    raise too_much
                unpack = _unpacker(reply)
                body = bytearray()
                arrived = 0  # bytes as they came, whatever comes out of them
                async for piece in reply.aiter_raw():  # as it came: at most what one read from the network holds
                    arrived += len(piece)
                    if unpack is None:
                        if len(body) + len(piece) > limit:
                            raise too_much
                        body += piece
                    else:
                        # Packed, an answer is no larger than what it unpacks to, give or take a little. One that
                        # goes on arriving and yields nothing is read no further than that, and not for as long as
                        # the time allows. (Read to its end otherwise, past the end of what was packed too: a
                        # connection left with something unread on it cannot be used for the next request.)
                        if arrived > limit + PACKED_MARGIN:
                            raise too_much
                        while piece and not unpack.eof:
                            # Unpacked as far as what may still come, and one byte more: by that one, too much is known.
                            came = unpack.decompress(piece, limit + 1 - len(body))
                            if not came and len(unpack.unconsumed_tail) == len(piece):
                                raise zlib.error("nothing comes out of it")
                            piece = unpack.unconsumed_tail
                            if len(body) + len(came) > limit:
                                raise too_much
                            body += came
                    if time.monotonic() > give_up:  # should the stop itself have gone unnoticed
                        raise TimeoutError
                if unpack is not None and arrived and not unpack.eof:  # (nothing at all, said to be packed, is nothing at all)
                    raise zlib.error("it breaks off")
            finally:
                await reply.aclose()
    except TimeoutError:
        raise KvmError("timeout", "Device did not respond in time", 504) from None
    except zlib.error:
        raise KvmError("dropped", "The device's answer is not packed the way it says it is") from None
    except httpx.InvalidURL:
        # The library works out where an answer sends it on to, also where it is told not to go there, and
        # says so with an error that is none of its usual ones when that is no address ("Location: http:x").
        raise KvmError("bad_response", "The device sent this program on to an address that is none") from None
    # The body is complete and already decoded, so the headers that describe its transfer no longer apply.
    transfer = ("content-encoding", "content-length", "transfer-encoding")
    headers = [(name, value) for name, value in reply.headers.multi_items() if name.lower() not in transfer]
    return httpx.Response(reply.status_code, headers=headers, content=bytes(body), request=request)


def _dig(obj: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


# What a device reports about itself ends up on the page, in the activity log and in the log file.
# A broken or hostile device decides what that is, so each value is reduced to what it is meant to be.

PICTURES = ("image/jpeg", "image/png")  # the only kinds of data passed on to a browser as a picture


def plain(value: Any, limit: int = 80) -> str | None:
    """A device's text as one short printable line (no line breaks to forge log entries with), or None."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    # Cut before it is gone through: what is wanted is a line, whatever length of text was sent.
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)[: limit * 8]).split())
    return text[:limit] or None


def as_text(value: Any) -> str:
    """What a device sent where a text or a number belongs, as text. Anything else is no text.

    Never `str()` of whatever it sent. A list nested tens of thousands deep is read from its answer without
    a word by a Python from 3.13 on, and cannot be written out: Python says so with an error of its own
    kind (RecursionError), which nobody who asked a device for an address would think to catch.
    """
    return str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""


def read_json(reply: httpx.Response) -> Any:
    """What a device answered, read as JSON. ValueError if it cannot be read as that.

    That includes an answer nested deeper than the reader can follow (sixty thousand opening brackets will
    do), for which Python has an error of its own that none of the callers would think to catch.
    """
    try:
        return reply.json()
    except RecursionError:
        raise ValueError("nested too deep to read") from None


def picture_size(data: bytes) -> tuple[int, int] | None:
    """Width and height a PNG or JPEG says it has, read from its first bytes. None: it is neither, or says nothing."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR" and len(data) >= 24:
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data[:2] != b"\xff\xd8":
        return None
    at = 2
    # A picture says its size within its first few parts. What goes on for megabytes without saying it is
    # not looked through to the end: that is this program's time, on the thread that serves everybody.
    for _ in range(2000):
        if at + 9 > len(data):
            return None
        if data[at] != 0xFF:
            return None
        marker = data[at + 1]
        if marker == 0xFF:  # padding between two parts
            at += 1
            continue
        if marker in (0x01, *range(0xD0, 0xDA)):  # parts that have no length of their own
            at += 2
            continue
        length = int.from_bytes(data[at + 2 : at + 4], "big")
        # The parts that begin the picture proper say how large it is: any "start of frame" (not the three
        # of that range that are tables).
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            return int.from_bytes(data[at + 7 : at + 9], "big"), int.from_bytes(data[at + 5 : at + 7], "big")
        if length < 2:
            return None
        at += 2 + length
    return None


MOST_PIECES = 4096  # pieces one message on a device's WebSocket may arrive in
MESSAGE_WITHIN = 20.0  # seconds a message may take to arrive in full, once its first piece is there
MOST_A_SECOND = 2000  # messages in one second before a device is taken to be flooding
MOST_UNSENT = 2**20  # bytes that may wait to be sent to a device that is not taking them
MOST_PINGS_A_SECOND = 50  # pings and pongs in one second before a device is taken to be flooding (a device sends one every few seconds)
AT_A_TIME = 4096  # bytes of what a device sent that are worked through before it is looked at what they set off
MOST_FRAMES_A_SECOND = 4 * MOST_A_SECOND  # frames of any kind in one second: a message is one, or a few
SAY_AGAIN = 60.0  # seconds between two lines in the log about the same unforeseen error of one device


class Listening:
    """Reads a device's WebSocket message by message, with limits the library's own reading has not got.

    The library limits a message's bytes, and counts them piece by piece as a message arrives in several. A
    piece of no bytes counts for nothing, and every piece is kept until the last one comes: a device that
    sends empty pieces and never the last filled a gigabyte of memory in a quarter of a minute. Here a
    message is put together from its pieces as they come, and is over when it has too many of them, too
    many bytes, or takes too long. Messages that are complete and tiny, but arrive by the hundred thousand,
    keep the one thread there is busy reading them: more than a device has reason to send ends it as well.
    After any of these the connection is good for nothing, and whoever reads closes it.
    """

    def __init__(self, ws: Any, most: int) -> None:
        self._ws, self._most = ws, most
        self._second, self._count = time.monotonic(), 0

    async def message(self, wait: float | None = None) -> str | bytes:
        """The next message. TimeoutError where none begins within `wait` seconds (nothing is lost by that).

        Waited for with `asyncio.timeout`, never `asyncio.wait_for`: up to Python 3.11 that hands back what came
        where a stop came in the same moment, and the stop is lost. Against a device that keeps sending, the
        reader could be in that moment at every stop (in the trials it was, on Windows, and on Linux with a
        message every thousandth of a second), and went on after every one.
        """
        pieces = self._ws.recv_streaming()
        try:
            if wait is not None and wait <= 0:
                raise TimeoutError  # (no time at all: none begins in it, whatever has arrived meanwhile)
            async with asyncio.timeout(wait):
                first = await anext(pieces)
            now = time.monotonic()
            if now - self._second >= 1.0:
                self._second, self._count = now, 0
            self._count += 1
            if self._count > MOST_A_SECOND:
                raise KvmError("dropped", "The device sends far more messages than a device has reason to")
            parts, size, give_up = [first], len(first), now + MESSAGE_WITHIN
            while True:
                try:
                    async with asyncio.timeout(max(0.01, give_up - time.monotonic())):
                        piece = await anext(pieces)
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    raise KvmError("dropped", "The device began a message and did not finish it") from None
                size += len(piece)
                if len(parts) >= MOST_PIECES or size > self._most:
                    raise KvmError("dropped", "The device sent a message in far more pieces than this program accepts")
                parts.append(piece)
        finally:
            await pieces.aclose()
        return "".join(parts) if isinstance(first, str) else b"".join(parts)


class _ToADevice(ClientConnection):
    """A device's WebSocket, hung up on when the device stops taking what it is owed.

    The library answers every ping by itself, as it has to. A device that sent pings as fast as it could and
    read nothing had the answers pile up here, a hundred megabytes in half a minute: a ping is no message,
    and none of the limits on messages (`Listening`) ever sees one. What this program itself sends is a few
    hundred bytes at a time and waits for room; only what is sent unasked can pile up, and it is looked at
    where that is caused.
    """

    _second, _pings, _frames = 0.0, 0, 0  # the second being counted in, and the pings and pongs, and the frames of any kind, that came in it
    _hung_up = False  # by this program, for what the device sent

    def data_received(self, data: bytes) -> None:
        # A ping of no bytes is two bytes on the wire, and one read from the network holds a hundred
        # thousand of them. The library works through all of that at once, on the one thread there is, and
        # queues an answer to each: the wall stood still for a second at every read, and for a minute once
        # the answers piled up. So what arrived is taken a piece at a time, and after each piece it is
        # looked at what that piece set off. A device that floods is hung up on within the first.
        for start in range(0, len(data), AT_A_TIME):
            # (Not what was read before this program hung up and is handed over after: every ping in it
            # would be answered into a connection that is gone. What a device sent before it ended the
            # connection itself is another matter, and is heard: on Windows a reset is known of before
            # what came just ahead of it is handed over, and with "is it closing?" asked here, the last
            # words of a device that hangs up that way were thrown away, its answer to the handshake among them.)
            if self._hung_up:
                return
            super().data_received(data[start : start + AT_A_TIME])
            if self._pings > MOST_PINGS_A_SECOND or self._frames > MOST_FRAMES_A_SECOND or self.transport.get_write_buffer_size() > MOST_UNSENT:
                self._hung_up = True
                self.transport.abort()  # whoever reads is told the connection is gone, as it is
                return

    def start_keepalive(self) -> None:
        # The library starts its own pinging once the handshake is done, and stops it when the connection is
        # lost. A connection that was lost before that (hung up on above, for what the device sent in one
        # breath with its answer to the handshake; or reset by the device, which on Windows is heard of
        # first) had the pinging started after it was over, and nothing stopped it: twenty seconds on it
        # failed, with a traceback, once for every such connection, and a device can have one a second.
        if not self.transport.is_closing():
            super().start_keepalive()

    async def close(self, code: int = CloseCode.NORMAL_CLOSURE, reason: str = "") -> None:
        # The library says goodbye and waits for the device to answer it. Told to stop meanwhile (`stopped`, which
        # retires a KVM's stream and a server's console, tells them again after half a second), it leaves the
        # connection as it is: open, for as long as a device that does not answer likes, with nobody left to read
        # it, and a console seat kept. Cut short in any way, the connection is ended here and now.
        try:
            await super().close(code, reason)
        except BaseException:
            self.transport.abort()
            raise

    def process_event(self, event: Any) -> None:
        # (Every frame comes through here. Pings and pongs are no messages, and nothing else counts them; and
        # frames of no bytes by the hundred thousand are work for the one thread before they are a message.)
        opcode = getattr(event, "opcode", None)
        if opcode is not None:
            now = time.monotonic()
            if now - self._second >= 1.0:
                self._second, self._pings, self._frames = now, 0, 0
            self._frames += 1
            if opcode in (Opcode.PING, Opcode.PONG):
                self._pings += 1
        super().process_event(event)


class WarningsOnly(logging.LoggerAdapter):  # type: ignore[type-arg]
    """A logger that passes on warnings and worse, and nothing finer, whatever level anybody sets on any logger, and when.

    (A level of its own would not hold: a logging configuration given later that names a logger above it, the library's
    or the web server's, sets every logger below that back to no level at all, and so to whatever that one is at.)"""

    def isEnabledFor(self, level: int) -> bool:
        return level >= logging.WARNING and self.logger.isEnabledFor(level)


# What the WebSocket library logs at its finer levels names every header it sends, a device's session or an API token
# among them. Its connections to devices log through the one above, which says nothing finer than a warning, whatever
# level the library's own loggers are set to, now or later (cli.setup_logging keeps those to warnings as well; this does
# not lean on it). Under "websockets", so that what it does say goes where the library's other lines go, once a minute.
_TO_DEVICES = WarningsOnly(logging.getLogger("websockets.to_devices"), {})


class ws_connect(_ws_connect):  # named like the function it takes the place of, and used the way that is
    """A websocket to a device: to that device, straight to it, and as it is sent.

    The library would follow a redirect, to another host as well, taking the device's session cookie along;
    and it would go through whatever proxy this computer is set up to use for the web. A device does not get
    to send qKVM anywhere, and a KVM is on the local network, where the company's web proxy is not.

    It would also offer the device to pack what it sends, and unpack that on the one thread there is before
    any limit of this program's counts: a kilobyte that is a megabyte unpacked, sent a thousand times a
    second, stopped the whole wall for seconds at a time. No device needs it; none is offered it, and one
    that packs unasked is not connected to.
    """

    def __init__(self, uri: str, **options: Any) -> None:
        super().__init__(uri, proxy=None, compression=None, create_connection=_ToADevice, logger=_TO_DEVICES, **options)

    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc  # "not here, over there" is an answer like any other that is not a connection


def number(value: Any, low: float = 0, high: float = 1_000_000) -> int | float | None:
    """A device's number if it is one and within reason, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        return None
    return value


def flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


# GLKVM says how the computer behind its power board is in a word of its own, which its own page shows; the power light
# in `leds` stays false there whatever the computer does (a Comet with its ATX board, 2026-10-14: "power": "on" and
# "leds": {"power": false} on a running PC). Stock kvmd has no word, and its light is the one in `leds`. A computer
# asleep is on: the power is there, and a short press wakes it (as a PC with Intel AMT is said to be).
POWER_WORDS = {"on": True, "sleep": True, "off": False}


def power_said(atx: Any) -> bool | None:
    """Whether the computer behind a KVM's power board is on, by what kvmd's /api/atx answered; None where it does not say.

    Where the answer has GLKVM's word, the word decides, and a word of another kind or one not known says nothing: the
    light beside it is no witness there.
    """
    if isinstance(atx, dict) and "power" in atx:
        word = atx["power"]
        return POWER_WORDS.get(word) if isinstance(word, str) else None
    return flag(_dig(atx, "leds", "power"))


def board_heard(event: Any) -> dict[str, Any] | None:
    """What a power board says of itself on the KVM's line for events (an `atx` event); None where that is no state at all.

    The whole of it each time, as GLKVM (a real Comet) and stock kvmd (by its source: its poller yields the whole state)
    send it, in the shape of /api/atx's answer. Only what the wall reads of it is kept, each by its kind (a value of another
    kind is kept as saying nothing): whether the board is there and busy, GLKVM's word for the computer's power, and the
    two lights.
    """
    if not isinstance(event, dict):
        return None
    said: dict[str, Any] = {name: flag(event.get(name)) for name in ("enabled", "busy")}
    if "power" in event:  # (only where it is: a word of another kind says nothing, and the light beside it is no witness then)
        word = event["power"]
        said["power"] = word if isinstance(word, str) and word in POWER_WORDS else None
    lights = event.get("leds")
    said["leds"] = {name: flag(lights.get(name)) for name in ("power", "hdd")} if isinstance(lights, dict) else {}
    return said


def fingerbot_heard(event: Any) -> bool | None:
    """Whether a Fingerbot is paired with the KVM, by its `fingerbot` event: `{"exist": true}` on a real Comet with one, and
    (by its size, in a record of the line that kept the keys and the size of each event) `{"exist": false}` on a Comet
    without. None where that is no answer: another kind, or nothing."""
    return flag(event.get("exist")) if isinstance(event, dict) else None


def battery_said(result: Any) -> int | None:
    """A Fingerbot's battery in percent, by the Comet's answer at /api/fingerbot/battery (`{"battery": 101}` on a real one);
    None where it is no number. One above a hundred is a full one (the Comet's own page counts anything from 70 up as
    full), and one beyond what a battery can say is no answer."""
    value = number(_dig(result, "battery"), 0, 255)
    return None if value is None else min(100, round(value))


EVENT_PING = '{"event_type": "ping", "event": {}}'  # kvmd answers it with a `pong` (GLKVM's too, on a real Comet)


def event_of(message: str | bytes) -> tuple[str, Any] | None:
    """One message of a kvmd KVM's line for events, as its type and what it says; None for anything else (deep nesting too)."""
    if not isinstance(message, str):
        return None
    try:
        said = json.loads(message)
    except (ValueError, RecursionError):
        return None
    if not isinstance(said, dict) or not isinstance(said.get("event_type"), str):
        return None
    return said["event_type"], said.get("event")


def share_window(fresh: float | None) -> float:
    """How old a picture may be and still do for a viewer who is content with one `fresh` seconds old."""
    return FRAME_MIN_AGE if fresh is None else max(FRAME_MIN_AGE, min(fresh, MAX_SHARED_AGE))


def _ports_from(switch: Any) -> dict[str, Any] | None:
    """kvmd's switch state, reduced to what the wall shows. None unless the device has several inputs.

    A multi-port KVM (GL.iNet Comet X, PiKVM Switch) captures one input at a time:
    `active` is the one on screen, `signal` says whether an input has a computer on it.
    """
    ports = _dig(switch, "model", "ports")
    links = _dig(switch, "video", "links")
    ports = ports if isinstance(ports, list) else []
    signals = links if isinstance(links, list) else []
    count = min(max(len(ports), len(signals)), MAX_PORTS)
    active = _dig(switch, "summary", "active_port")
    # A device without a switch may still answer with an empty shell of this state.
    if count < 2 or type(active) is not int or not 0 <= active < count:
        return None
    return {
        "active": active,
        "list": [
            {
                "name": (plain(_dig(ports[index], "name"), 40) or "") if index < len(ports) else "",
                "signal": signals[index] if index < len(signals) and isinstance(signals[index], bool) else None,
            }
            for index in range(count)
        ],
    }


def _stock_about(info: Any) -> dict[str, Any]:
    """What stock kvmd says it is, in its /api/info: the model of its platform ("v4plus"; "test_model" in kvmd's own test
    environment) and the version of kvmd itself, which is what a PiKVM's software is known by."""
    version = plain(_dig(info, "system", "kvmd", "version"), 32)
    return {"model": plain(_dig(info, "hw", "platform", "model"), 40), "version": f"kvmd {version}" if version else None}


# A session token is sent back to the device in a header on every request: only characters that are safe there.
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,512}")


def said_cookie(resp: httpx.Response, name: str) -> str | None:
    """The cookie of that name which this answer sets; None where it sets none, or more than one.

    The HTTP library refuses to choose between two cookies of one name (for two paths, say) with an error of
    its own. A device that sets its session twice has not said which one it is: that is no session, and
    nothing for a tile to show as an error inside this program.
    """
    try:
        return resp.cookies.get(name)
    except httpx.CookieConflict:
        return None


def _token_from(resp: httpx.Response) -> str | None:
    """GLKVM returns the session token in the JSON body, stock PiKVM sets it as a cookie."""
    try:
        token = read_json(resp)["result"]["token"]
    except (ValueError, KeyError, TypeError):
        token = None
    token = token or said_cookie(resp, "auth_token")
    return token if isinstance(token, str) and TOKEN.fullmatch(token) else None


# Said for a client that was retired (its KVM was edited or removed, or the last person signed out)
# while a request was still under way on it. The tile asks again and reaches the client that replaced it.
RETIRED = KvmError("no_stream", "Reconnecting to the KVM", 503)


def _looked_at(task: asyncio.Future[Any]) -> None:
    """For a task nobody may be waiting for any more: its error counts as seen, and is not reported as forgotten."""
    if not task.cancelled():
        task.exception()


async def stopped(tasks: Iterable[asyncio.Future[Any] | None]) -> None:
    """Stop these tasks and wait until they have stopped, though not for ever.

    They are told more than once if need be: a request that is told to stop at the moment its
    connection is being made does not always notice (see `bounded`).
    """
    pending = {task for task in tasks if task is not None and not task.done()}
    for _ in range(STOP_TRIES):
        if not pending:
            return
        for task in pending:
            task.cancel()
        _, pending = await asyncio.wait(pending, timeout=STOP_WAIT)


class Device:
    """One KVM on the wall, whatever its make.

    A driver subclasses this and talks to the hardware; what is here is shared: backing
    off from a device that is down, and a status that never makes the wall wait.
    """

    kind = ""  # what DeviceRecord.kind says for devices this driver handles
    picture = True  # it shows the computer's screen; False for a server's management controller, which only says how it is
    # What every device of this kind can be asked, of ABILITIES. A look at the device adds what that one has
    # (`can` in the status it reads); a client goes by that list, and by this one until there is a look.
    can: tuple[str, ...] = ()
    # Kept open for longer than the longest pause between two looks (a tile that is watched is asked every
    # second, one that is only watched over for alerts every fifteen): otherwise every look begins with a new
    # connection, and over HTTPS with a new handshake, at the device's cost as much as at ours.
    LIMITS = httpx.Limits(max_connections=8, max_keepalive_connections=4, keepalive_expiry=30.0)
    # How long a device of this kind has to accept a connection and to send the next piece of an answer, where it is
    # not WAITS (read when the connection is made, so that what is set there holds): a driver whose device is a slower
    # computer (a server's management controller) gives it more.
    WAITS: httpx.Timeout | None = None

    def __init__(self, spec: DeviceSpec, on_pin: Callable[[str], Awaitable[None]] | None = None) -> None:
        self.spec = spec
        self.on_pin = on_pin  # told when a certificate is trusted on first contact
        # Told when the device answers at its other address from now on (a JetKVM whose HTTPS mode was switched).
        self.on_move: Callable[[str], Awaitable[None]] | None = None
        # Told what the wall sees of the device at every look (the history keeps it; see history.py). Must not wait.
        self.on_status: Callable[[dict[str, Any]], None] | None = None
        # Told the number the machine behind the device gives for itself, where the driver has just taken one (DeviceSpec.machine):
        # the first one it saw, where none was remembered; or a server's controller's beside its computer's. Called with what
        # was remembered until then and what is from now on; kept with the tile from then on (DeviceManager._known).
        self.on_known: Callable[[str, str], Awaitable[None]] | None = None
        # The images the wall serves to servers' controllers for a mount (served.Served), given to every tile by the wall;
        # None for a client that is not on the wall (one tried out before it is added).
        self.served: Any = None
        self._closed = False  # retired: whatever is still under way on it ends, and nothing new starts
        self._client: httpx.AsyncClient | None = None
        self._tls: ssl.SSLContext | None = None  # how the device's certificate is checked; None without TLS
        self._connect_lock = asyncio.Lock()
        self._flights: set[asyncio.Future[httpx.Response]] = set()  # requests to the device that are under way
        self._failures = 0  # attempts in a row that found the device down
        self._down_until = 0.0
        self._down_error: KvmError | None = None
        self._in_passing = False  # the failure came from something a person asked for, not from looking at the device
        self._odd, self._odd_at = "", 0.0  # the last error nobody foresaw, and when the log last said so
        self._last_ok: float | None = None  # wall-clock time of the device's last answer
        self._heard_at: float | None = None  # the same moment, by the clock that nobody sets back
        self._login_error: KvmError | None = None  # what stands against signing in again just now
        self._login_retry_at = 0.0
        self._status: dict[str, Any] | None = None
        self._status_at = 0.0
        self._status_task: asyncio.Task[None] | None = None
        self._awaited_look: asyncio.Task[None] | None = None  # the status read a picture request last waited for

    async def close(self) -> None:
        self._closed = True
        # Every request that is under way ends here, wherever it is. Closing the connections alone would
        # not reach those still waiting for a free one, and they would go out to the device afterwards.
        await stopped([self._status_task, *self._flights])
        if self._client is not None:
            await self._client.aclose()

    @property
    def label(self) -> str:
        """What to call this device in the log: its name, or its address while it has none yet."""
        return self.spec.name or urlsplit(self.spec.base_url).netloc

    # --- what a driver provides ---------------------------------------------

    async def identify(self) -> dict[str, Any]:
        """Sign in and read what the device says about itself. Raises KvmError if it can't."""
        raise NotImplementedError

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """Latest frame, at least `width` pixels wide when the source has that many.

        `fresh`: how old, in seconds, a frame may be and still do (see share_window).
        """
        raise NotImplementedError

    def tidy(self) -> None:
        """Let go of what is only kept for viewers, once there are none. Called every half minute."""

    def watched(self) -> None:
        """Whoever sends an action has this machine's large view, or its live view, open (the action said so: `watching`).
        Nothing for most machines; a PC with Intel AMT opens a session before switching on then, to show the start."""

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        raise NotImplementedError

    async def wol_targets(self) -> list[dict[str, str]]:
        return []

    def takes_over(self, retired: Device) -> None:
        """Take from the client this one replaces what must outlast an edit of the tile.

        Called where the two talk to the same device at the same address: that somebody else is at the
        device's own console, for one. A tile given another name is no reason to push them out of it.
        """

    async def console(self) -> str:
        """The way into the device's own console for one use, signed in: a path on the device. Few can give one."""
        raise KvmError("no_console", "This device does not hand out a way into its console", 404)

    # --- virtual media (MediaOffer): a driver whose media_offer() is not None provides these -----------------------

    def media_offer(self) -> MediaOffer | None:
        """What this machine's virtual media can do, as the last look at it found it; None: it has none (none found yet)."""
        return None

    async def media_images(self) -> dict[str, Any]:
        """The images that can be mounted, asked now: `images` (each `id`, `name`, `where`, `size`, `partial` (an upload cut
        off: only to delete), `sha256` (where qKVM carried it there, and it is still that image; else None)), `unseen` (a
        sentence for each place whose images could not be listed, or what stands against a mount), `left_out` (entries that
        were not images qKVM hands on), `space` (the device's own storage: `free` and `size` in bytes, or None). A mount names
        an `id`, and is refused where that is not listed at that moment. Afterwards `media_now` says what is mounted."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    def media_now(self) -> dict[str, Any] | None:
        """What is mounted, as it was last found (the status's `media`): None where nothing is, or nothing is known yet; else
        `drive`, `image` (its id, or what the machine says is in it), `name`, `where`, `read_only`, `first` (the machine starts
        from it first at its next start; None where nothing here can tell), `by` and `at` (who mounted it from qKVM, and
        when; None where that is not known), `sha256` (where qKVM carried it there; else None)."""
        return None

    async def media_mount(self, image: str, *, drive: str, writable: bool, by: str, still: Callable[[], bool] | None = None) -> str | None:
        """Mount the image `image` (an id as listed) as `drive` (of the offer's `drives`), read-only unless `writable` (only
        for a drive of the offer's `writable`), for `by` (whose doing it is, said on the tile). A sentence where there is
        more to say than that it was done."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def media_boot(self, how: str, *, restart: bool, still: Callable[[], bool] | None = None) -> str | None:
        """Have the machine start from what is mounted (`how`, of the offer's `boot`): "once", restarted now and its own
        order after; or "until_unmounted", restarted now where `restart` says so. A sentence where there is more to say."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def media_restart(self, *, still: Callable[[], bool] | None = None) -> str | None:
        """Restart the machine, for its firmware to find what is mounted (an offer with `restart` and no `boot`: a KVM is no
        firmware, and the person picks the drive in the machine's boot menu): its reset button where it is on, its power
        button where it is off. A sentence where there is more to say."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def media_unmount(self, image: str, *, still: Callable[[], bool] | None = None) -> str | None:
        """Take out what is mounted, where it is `image` (what the person was shown: KvmError `changed` where another is
        mounted now), and start the machine as before. AlreadySo where nothing is mounted."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def media_upload(self, name: str, carried: Carried, *, by: str, still: Callable[[], bool] | None = None) -> dict[str, Any]:
        """Carry an image into the device's own storage under `name` (an offer with `upload`): `carried`, iterated once,
        handed on a piece at a time. The image as it is listed afterwards (as in `media_images`). Where it ends before its
        last byte, or the device does not have it whole afterwards, what was written is removed from the device where it
        allows that, and KvmError says so (`changed`, where nothing was sent)."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def media_discard(self, name: str) -> str | None:
        """Remove what an upload of `name` that was cut off may have left on the device, where the device allows that (asked
        by the server of a client made anew where the one that carried it was retired meanwhile). A sentence where it could
        not be; None where nothing is left."""
        return None

    async def media_delete(self, image: str, *, still: Callable[[], bool] | None = None) -> str | None:
        """Delete the image `image` (an id as listed) from the device's own storage (an offer with `delete`): refused where
        it is mounted. AlreadySo where it is not there any more."""
        raise KvmError("no_virtual_media", "This machine has no virtual media", 404)

    async def probe(self) -> str:
        """The device's state, for the alert watcher. Must not get in the way of anyone using the device."""
        return str((await self.status())["state"])

    async def glance(self) -> dict[str, Any]:
        """The status, for something that wants to know and is nobody watching: a collector of metrics.

        The same answer as status(), unless being asked for that is taken by the device to mean that
        somebody is looking at it.
        """
        return await self.status()

    async def _read_status(self) -> dict[str, Any]:
        raise NotImplementedError

    async def _gone_meanwhile(self, path: str) -> KvmError | None:
        """Whether a device has gone that is not being signed in to: the error where it has, None where it is there.

        While a rejected password waits to be offered again (up to an hour), nothing is asked that needs a
        sign-in, and so nothing said that the device was gone meanwhile: its tile went on saying that the
        login failed, it counted as up, and no alert went out. This asks what anybody may ask, with no
        password and no token. What it answers does not matter, only that it does.
        """
        if self._heard_at is not None and time.monotonic() - self._heard_at < STILL_THERE_EVERY:
            return None  # it answered not long ago (with the no, for one): it is not asked at every look
        try:
            self._check_backoff()
            client = await self._http()
            await self._send(client, client.build_request("GET", path), MAX_REPLY)
        except httpx.HTTPError as ex:
            return self._failed(_transport_error(ex, self.spec.tls))
        except KvmError as ex:
            if ex.code in DOWN_CODES:
                return self._failed(ex)
            if self._closed:
                return None
            # (An answer this program makes nothing of is an answer: left unnoted, it was asked for again at every look.)
        self._answered()
        return None

    # --- a password the device did not take ---------------------------------

    def _not_yet(self, offered: str, said: str) -> None:
        """Raise what stands against offering the saved password now, noted by another connection to this device.

        Asked each time, and kept nowhere else. Copied into this connection, the wait outlived what it was
        taken from: a connection made while another was signing in was told that the sign-in had come to
        nothing, and went on refusing for ten seconds after the other had been let in.
        """
        if REJECTED.wait_left(offered) <= 0:
            return
        if REJECTED.times(offered):
            raise KvmError("auth_failed", said)
        raise not_signing_in("a sign-in to it is under way, or the last one came to nothing")

    def _came_to_nothing(self, offered: str, error: KvmError, said: str, before: Sent, sent: bool = True) -> KvmError:
        """A sign-in ended without an answer that says yes or no. Hands back what to raise.

        Where it went out (`sent`: the request can have reached the device) it is held back, for a time
        that has nothing to do with a no (see Rejected.unanswered), and what is raised is what stands
        from now on, not the failure: the device answers, and does not sign this program in. Raised as
        "no answer", each try showed the tile as offline for some seconds and as a problem in between,
        which the round that sends alerts reported as gone and back, a pair for every try; and an
        operator's button pressed just then was answered with words that mean "it may have been done",
        where nothing had been sent. Whether the device is there at all is asked apart from this (see
        _gone_meanwhile). While a no stands, that goes on being what the tile says.

        One that could not be connected to was sent nothing: nothing is kept of it (`before` is put
        back), and it is asked again as any device that is down. One whose connection was retired
        meanwhile keeps the mark it went out with: nobody heard how it ended.
        """
        if self._closed:
            return error
        if not sent or error.code not in ("timeout", "dropped", "bad_response"):
            REJECTED.put_back(offered, before)
            return self._failed(error)
        return self._held_back(offered, error, said)

    def _neither_yes_nor_no(self, offered: str, error: KvmError, said: str) -> KvmError:
        """A sign-in was answered with an error of the device's own. Hands back what stands against the next one.

        Not the password's doing, as far as can be told, and never counted as a no. Not sent again
        at every look either: held back like a sign-in that nothing answered, kept beside the
        connections like the rest, and said as what it is: the device is there and does not sign this
        program in. (Said as the error it answered, a KVM's tile was "offline" for those minutes.)
        """
        return self._held_back(offered, error, said)

    def _held_back(self, offered: str, error: KvmError, said: str) -> KvmError:
        self._login_retry_at = time.monotonic() + REJECTED.unanswered(offered)
        self._login_error = KvmError("auth_failed", said) if REJECTED.times(offered) else not_signing_in(error.message)
        if REJECTED.silent(offered) == 1:  # (once for each run of them: they come ten seconds apart at first)
            log.warning("%s: its sign-in came to nothing: %s", self.label, error.message)
        return self._login_error

    # --- shared -------------------------------------------------------------

    def _answered(self) -> None:
        if self._failures:
            log.info("%s: reachable again", self.label)
        self._failures = 0
        self._down_error = None
        self._last_ok, self._heard_at = time.time(), time.monotonic()

    def _failed(self, error: KvmError, in_passing: bool = False) -> KvmError:
        """Note a failed attempt. While a device stays down it is tried less and less often.

        `in_passing`: it was an action that failed, or something else a person asked for.
        """
        if error.code in DOWN_CODES and not self._closed:
            self._in_passing = in_passing
            now = time.monotonic()
            if self._down_error is None or now >= self._down_until:
                # Requests that were under way together fail together: one failed attempt, not several.
                self._failures += 1
                if self._failures == 1:
                    log.warning("%s: %s", self.label, error.message)
                self._down_until = now + min(BACKOFF_MAX, ERROR_HOLD * 2 ** min(self._failures - 1, 10))
            self._down_error = error
        return error

    def _check_backoff(self) -> None:
        if self._down_error is not None and time.monotonic() < self._down_until:
            raise self._down_error.with_traceback(None)

    async def _tls_context(self) -> ssl.SSLContext | None:
        """How to check this device's certificate; None for a device spoken to without TLS."""
        spec = self.spec
        if not spec.base_url.startswith("https"):
            return None
        if spec.tls == "system":
            return await system_context()
        if spec.tls == "insecure":
            return unverified_context()
        if spec.cert_pem is None or spec.cert_pem == "":
            # Trust on first use, like an SSH host key: remember what the device
            # shows now and refuse anything else from then on. (Where nothing is remembered, and only
            # there: something that is no certificate is not nothing, and is replaced by nobody but a person.)
            spec.cert_pem = await fetch_certificate(spec.base_url)
            if self.on_pin and not self._closed:  # a client retired meanwhile has nothing to say about what is saved
                await self.on_pin(spec.cert_pem)
        try:
            return pinned_context(spec.cert_pem)
        except (ssl.SSLError, TypeError, ValueError):
            # What is saved as its certificate is none (cut short or mistyped in the settings file). Nothing
            # is trusted in its place: the device is not talked to, and its tile says what to do. Left as
            # the error it was, every request for its picture was a page in the log.
            raise KvmError("cert_invalid", "The certificate saved for this device cannot be read. Look at its certificate and trust it again.") from None

    async def _http(self) -> httpx.AsyncClient:
        """The connection to this device, made on first use."""
        async with self._connect_lock:
            if self._client is None and not self._closed:
                try:
                    self._tls = await self._tls_context()
                    # An http address never uses the system's list. It is given all the same, so that
                    # nothing could ever leave this program unchecked by accident.
                    verify = self._tls if self._tls is not None else await system_context()
                except KvmError as ex:
                    raise self._failed(ex) from None
                if not self._closed:  # not retired while its certificate was being looked at
                    try:
                        self._client = httpx.AsyncClient(
                            base_url=self.spec.base_url,
                            verify=verify,
                            timeout=self.WAITS or WAITS,
                            limits=self.LIMITS,
                            # Straight to the device, whatever proxy this computer is told to use for the web: the
                            # device is on the local network, and its password is not for a proxy to see.
                            trust_env=False,
                        )
                    except (httpx.InvalidURL, UnicodeError):
                        # An address that was saved and is none the HTTP library takes (it came in a file, or
                        # was written into the settings by hand): a device that cannot be reached, said as that.
                        raise self._failed(KvmError("unreachable", "This device's address is not one that can be connected to")) from None
            if self._closed or self._client is None:
                raise RETIRED.with_traceback(None)
            return self._client

    async def _send(
        self, client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None
    ) -> httpx.Response:
        """`bounded`, on this device's own connection.

        As a task of its own, so that retiring the device can end it wherever it is (see `close`)
        without stopping whoever asked: they are told to ask again.
        """
        if self._closed:
            raise RETIRED.with_traceback(None)
        flight = asyncio.ensure_future(bounded(client, request, limit, within))
        self._flights.add(flight)
        flight.add_done_callback(self._landed)
        try:
            return await flight
        except asyncio.CancelledError:
            asker = asyncio.current_task()
            if self._closed and (asker is None or not asker.cancelling()):
                raise RETIRED.with_traceback(None) from None  # the request was stopped, not the one who made it
            flight.cancel()  # whoever asked was stopped: what they asked for is no longer wanted
            raise
        except Exception:
            if self._closed:
                # Closing the connection is what made this fail, in whichever way: it says nothing about the device.
                raise RETIRED.with_traceback(None) from None
            raise

    def _landed(self, flight: asyncio.Future[httpx.Response]) -> None:
        self._flights.discard(flight)
        if not flight.cancelled():
            flight.exception()  # looked at here, for the case that nobody is waiting for it any more

    def _stale(self) -> bool:
        return self._status is None or time.monotonic() - self._status_at > STATUS_TTL

    def _refresh_soon(self) -> asyncio.Task[None]:
        """Have the status read in the background, unless that is under way already."""
        if self._status_task is None or self._status_task.done():
            self._status_task = asyncio.create_task(self._refresh_status())
        return self._status_task

    async def _expect_up(self) -> None:
        """Keep a request for a picture away from a device that is down, or was never heard from.

        Tiles ask for pictures all the time, a browser makes only a handful of requests at once, and
        a device that is not there takes seconds to fail. Answered at that pace, a few dead KVMs hold
        up the pictures of all the live ones. So finding out whether a device is there is left to the
        status refresh, which runs in the background, and a tile is told at once what is known.
        """
        if self._down_error is None and self._last_ok is None:
            # Never heard from: the status refresh makes the first contact, and gets a moment for it.
            task = self._refresh_soon() if self._stale() else self._status_task
            if task is not None and not task.done():
                await asyncio.wait({task}, timeout=FIRST_CONTACT_WAIT)
                if not task.done():
                    raise KvmError("no_stream", "Connecting to the KVM", 503)
        if self._down_error is not None and time.monotonic() >= self._down_until:
            # The pause after the failure is over: time to look again, which is the status refresh's part.
            looking = self._refresh_soon()
            there = self._status is not None and self._status.get("state") not in ("offline", "connecting")
            if self._in_passing and there and self._failures < 2 and looking is not self._awaited_look:
                # One failed action is not an outage: it took too long, or went out on a connection the
                # KVM had closed. A KVM that was there at last sight says so again within moments, and
                # gets its picture taken after all. That is waited for once. A KVM that failed to give
                # a picture, or to answer a look, is taken to be down, and nothing waits for it: when
                # many go silent together, their tiles must not keep those of the others waiting.
                self._awaited_look = looking
                await asyncio.wait({looking}, timeout=FIRST_CONTACT_WAIT)
        if self._down_error is not None:
            raise self._down_error.with_traceback(None)

    async def status(self) -> dict[str, Any]:
        """Last known status.

        It is refreshed in the background, so one slow or dead device never holds
        up the answer for the whole wall.
        """
        if self._stale():
            self._refresh_soon()
        if self._status is None and self._status_task is not None:
            # Nothing known yet: give the device a moment before answering "connecting".
            await asyncio.wait({self._status_task}, timeout=STATUS_FIRST_WAIT)
        status = self._status or {"state": "connecting", "error": None}
        seen = None if self._last_ok is None else max(0, round(time.time() - self._last_ok))
        # (`can`: what the look found; the driver's own list where the look found nothing, or there was none yet.)
        found = {"can": can_do(*self.can), **status, "last_seen_ago": seen}
        if self.on_status is not None and not self._closed:
            self.on_status(found)
        return found

    def pointer_kind(self) -> str | None:
        """How the machine's pointer can be moved over the live line: "absolute" (to a place: `m`), "relative" (by steps:
        `mr`), "both", or None where that is not known (or the machine takes no mouse). Said to the line's viewers."""
        return POINTER_BOTH if "control" in self.abilities() else None

    def input_taken(self) -> KvmError | None:
        """Why keyboard and mouse were taken from this program at the machine itself (somebody at its own console has them
        now): asked by the live line's look, and said to the line that holds them at once, not at its next key. None where
        they were not (the default; a driver whose status says it tells it there)."""
        return None

    def abilities(self) -> list[str]:
        """What this tile can do, as the last look at the device found it; the driver's own list until there was one."""
        found = (self._status or {}).get("can")
        return list(found) if isinstance(found, list) else can_do(*self.can)

    async def _refresh_status(self) -> None:
        try:
            self._status = await self._read_status()
        except Exception as ex:  # a bug here must not freeze this device's status for good
            self._unexpected("reading the status failed", ex)
            self._status = {"state": "error", "error": {"code": "internal", "message": "Status could not be read"}}
        self._status_at = time.monotonic()

    def _unexpected(self, what: str, error: BaseException) -> None:
        """Log an error nobody foresaw: in full the first time, and in a line a minute while it goes on.

        Whatever causes it is asked for again at the next look, a second later, and a device that can cause
        it once can cause it every time: fifty lines a second in the log are a full disk by the morning.
        """
        kind, now = type(error).__name__, time.monotonic()
        if not self._odd:
            self._odd, self._odd_at = kind, now
            log.error("%s: %s", self.label, what, exc_info=error)
        elif now - self._odd_at >= SAY_AGAIN:
            # Once a minute whatever it is by now: a device that can cause two kinds of error in turn
            # would otherwise have each of them written in full, every time.
            full, self._odd, self._odd_at = kind not in self._odd.split(), f"{self._odd} {kind}"[-200:], now
            log.error("%s: %s, again (%s: %s)", self.label, what, kind, plain(str(error), 200), exc_info=error if full else None)


class KvmDevice(Device):
    """A GLKVM / PiKVM device, over kvmd's HTTP API.

    GL.iNet's firmware is kvmd with routes of its own beside kvmd's: its version and host name, Wake-on-LAN, and a
    restart of the KVM itself. Stock kvmd has none of them (kvmd 4.226 answers 404 for each, before it asks who is
    asking), and says what it is in /api/info instead. Which of the two a device is, is found out from its answer to
    the first of them (`_glinet`).
    """

    kind = "kvmd"
    # Every such KVM: its screen, keys and text, keep-awake. A look adds Wake-on-LAN (what the KVM has saved to wake) and
    # its own restart unless the KVM said it has not got GL.iNet's routes for them, the power board and the inputs where
    # it has them, and takes keep-awake away where the KVM says it is switched off in its own settings.
    can = ("screen", "keys", "text", "jiggler", "live", "control")

    def __init__(self, spec: DeviceSpec, on_pin: Callable[[str], Awaitable[None]] | None = None) -> None:
        super().__init__(spec, on_pin)
        self._token: str | None = None
        self._login_lock = asyncio.Lock()
        self._login_error: KvmError | None = None
        self._login_retry_at = 0.0
        self._frames: dict[str, Snapshot] = {}
        self._frame_errors: dict[str, tuple[float, KvmError]] = {}
        self._unseen: set[str] = set()  # sizes whose frame nobody has been handed yet
        self._fetching: dict[str, asyncio.Task[Snapshot]] = {}  # the request for a frame of each size, under way or over
        self._fetching_since: dict[str, float] = {}
        self._screen = 0  # counts the times the KVM was switched to another computer
        self._source_width: int | None = None
        self._about: dict[str, Any] = {}
        self._about_at = 0.0
        # Whether it has GL.iNet's own routes: True where it answered the first of them, False where it said there is no
        # such thing (stock kvmd), None while that is not known (not asked yet, or answered with an error of the moment).
        self._glinet: bool | None = None
        self._jiggler_off = False  # the KVM said at the last look that keep-awake is switched off in its own settings
        self._single_port_at: float | None = None  # when the device last said it has no port switch
        self._port_seen: int | None = None  # which computer was on screen at the last look (a multi-port KVM)
        self._usb_unsure = False  # another one is since, and the device has not found its keyboard there yet
        # Whether the KVM's mouse is absolute, as it said at the last look (/api/hid, `mouse.absolute`; None: not said). kvmd
        # drops a move of the other kind: relative steps while its mouse is absolute (stock kvmd, W7), and places while it is
        # relative (a real Comet set to "usb_rel", 2026-10-18: the pointer never moved, while steps moved it).
        self._mouse_absolute: bool | None = None
        self._board_at: float | None = None  # when the KVM last said it has a power board
        self._power_seen: tuple[float, bool | None] = (float("-inf"), None)  # when its board last said whether the computer is on, and what
        # What the power board said last on the line for events the keepalive holds (see EVENTS_PING): None where no such
        # line is held, or it has not said yet. `_board_news` is set at every word of the board there, and when the line ends.
        self._events_heard_at = float("-inf")  # when that line was last heard from, of anything
        self._board_said: dict[str, Any] | None = None
        self._board_news = asyncio.Event()
        self._board_words = 0  # how many it said there, all lines together
        # Whether a Fingerbot is paired with the KVM, as it said last (its `fingerbot` event, on the keepalive's line or on
        # one opened before a press), when it said so, and when a line opened to ask it heard nothing: `_fingerbot`,
        # `_fingerbot_heard_at`, `_fingerbot_silent_at`, kept in PACED (below), where a client made anew finds them.
        self._fingerbot_words = 0  # how often that changed (a look under way when it does is not the last word: see _refresh_status)
        # The Comet talks to its Fingerbot one request at a time (a press sent while another was being taken failed): a
        # press and a question of the battery never go out together from here.
        self._fingerbot_turn = FingerbotTurn(spec)
        PACED.find(spec)  # (what paces this KVM, kept under this address too from now on: see _AllPaced.find)
        # Its battery in percent as last answered (see FINGERBOT_BATTERY_EVERY), when it may be asked again, and when it was last
        # asked: `_battery`, `_battery_next`, `_battery_asked_at`, kept in PACED with the rest of what paces the Fingerbot: the
        # listeners opened again make every client anew, and the battery was asked again at once.
        self._battery_task: asyncio.Task[None] | None = None
        self._owed: set[asyncio.Future[None]] = set()  # lines asked for the Fingerbot, being closed in a task of their own
        # Its drive and image storage as kvmd last said them (GET /api/msd, or its `msd` event on the keepalive's line), and when;
        # when the line last said it (see `_msd_look`).
        self._msd: dict[str, Any] | None = None
        self._msd_at = float("-inf")
        self._msd_heard_at = float("-inf")
        self._keepalive: asyncio.Task[None] | None = None
        self._keepalive_fails = 0  # keepalives in a row that did not get, or did not keep, their connection
        self._keepalive_again_at = 0.0  # ...and when one may be begun again
        self._wanted_at = 0.0
        self._ended_said = float("-inf")  # when it was last written down that the connection which keeps the picture coming ended

    async def close(self) -> None:
        self._closed = True
        await stopped([self._keepalive, self._battery_task, *self._fetching.values(), *self._owed])
        await super().close()

    def pointer_kind(self) -> str | None:
        # (By what its mouse is at the last look: kvmd drops a move of the other kind. Not known: nothing is said.)
        return None if self._mouse_absolute is None else POINTER_ABSOLUTE if self._mouse_absolute else POINTER_RELATIVE

    def takes_over(self, retired: Device) -> None:
        # Which family the KVM is, as the client before found it (the same device at the same address), where this one
        # has not asked yet: until it has, its session would go into the address of a stock kvmd's event line.
        if isinstance(retired, KvmDevice) and self._glinet is None:
            self._glinet, self._jiggler_off = retired._glinet, retired._jiggler_off
        # One request to the Fingerbot at a time, across an edit too: a press of the client before may still be holding the
        # button (a tile renamed during a hold had the new client ask the battery while the arm was down).
        if isinstance(retired, KvmDevice):
            self._fingerbot_turn = retired._fingerbot_turn
        # (Whether a Fingerbot is paired, which the KVM says only when a line is opened, and its battery, which it says only when
        # it is asked, are in PACED, found by every client of the KVM: see `_fingerbot`, `_battery`.)

    # Whether a Fingerbot is paired, as the KVM said last, and when: kept beside the connections (PACED), not in this client.
    @property
    def _fingerbot(self) -> bool | None:
        return PACED.find(self.spec).fingerbot

    @_fingerbot.setter
    def _fingerbot(self, value: bool | None) -> None:
        PACED.of(self.spec).fingerbot = value

    @property
    def _fingerbot_heard_at(self) -> float:
        return PACED.find(self.spec).fingerbot_heard_at

    @_fingerbot_heard_at.setter
    def _fingerbot_heard_at(self, value: float) -> None:
        PACED.of(self.spec).fingerbot_heard_at = value

    @property
    def _fingerbot_silent_at(self) -> float:
        return PACED.find(self.spec).fingerbot_silent_at

    @_fingerbot_silent_at.setter
    def _fingerbot_silent_at(self, value: float) -> None:
        PACED.of(self.spec).fingerbot_silent_at = value

    @property
    def _battery(self) -> int | None:
        return PACED.find(self.spec).battery

    @_battery.setter
    def _battery(self, value: int | None) -> None:
        PACED.of(self.spec).battery = value

    @property
    def _battery_next(self) -> float:
        return PACED.find(self.spec).battery_next

    @_battery_next.setter
    def _battery_next(self, value: float) -> None:
        PACED.of(self.spec).battery_next = value

    @property
    def _battery_asked_at(self) -> float:
        return PACED.find(self.spec).battery_asked_at

    @_battery_asked_at.setter
    def _battery_asked_at(self, value: float) -> None:
        PACED.of(self.spec).battery_asked_at = value

    def tidy(self) -> None:
        if (self._frames or self._fetching) and time.monotonic() - self._wanted_at > KEEPALIVE_IDLE:
            # Nobody is watching: the last pictures (a megabyte each, and more) need not be kept.
            self._frames.clear()
            self._unseen.clear()
            self._frame_errors.clear()
            # A request that is over still holds the picture it came back with.
            for size in [size for size, fetch in self._fetching.items() if fetch.done()]:
                del self._fetching[size]
                self._fetching_since.pop(size, None)

    # --- auth ---------------------------------------------------------------

    async def _login(self) -> str:
        async with self._login_lock:
            if self._token:  # someone else logged in while we waited for the lock
                return self._token
            if self._login_error and time.monotonic() < self._login_retry_at:
                raise self._login_error.with_traceback(None)
            if not self.spec.password:
                raise KvmError("no_password", "No password saved for this device")
            offered = REJECTED.what("login", self.spec)
            self._not_yet(offered, NO_SAID)
            client = await self._http()
            login = client.build_request(
                "POST", "/api/auth/login", data={"user": self.spec.username, "passwd": self.spec.password}, timeout=sign_in_waits()
            )
            before = REJECTED.sent(offered)
            try:
                resp = await self._send(client, login, MAX_REPLY)
            except httpx.HTTPError as ex:
                raise self._came_to_nothing(offered, _transport_error(ex, self.spec.tls), NO_SAID, before, went_out(ex)) from ex
            except KvmError as ex:
                raise self._came_to_nothing(offered, ex, NO_SAID, before) from None
            self._answered()
            # We send the token ourselves; don't let the cookie jar send a stale one too.
            client.cookies.clear()
            if resp.status_code in (401, 403):
                # Every tile refresh ends up here, so back off rather than hammer the
                # device with a password it has already rejected: longer each time.
                self._login_error = KvmError("auth_failed", NO_SAID)
                self._login_retry_at = time.monotonic() + REJECTED.said_no(offered)
                log.warning("%s: login rejected", self.label)
                raise self._login_error
            if resp.status_code != 200 or not (token := _token_from(resp)):
                # Whatever is at that address did not sign us in, and not because of the password. Every
                # tile refresh ends up here too: the password is not sent to it again and again meanwhile.
                error = KvmError(
                    "bad_response",
                    f"Login failed (HTTP {resp.status_code})" if resp.status_code != 200 else "Login succeeded but the device returned no session token",
                )
                raise self._neither_yes_nor_no(offered, error, NO_SAID)
            self._login_error = None
            REJECTED.accepted(offered)
            self._token = token
            return token

    async def _request(
        self, method: str, path: str, *, urgent: bool = False, vital: bool = True, still: Callable[[], bool] | None = None,
        within: float | None = None, **kwargs: Any,
    ) -> httpx.Response:
        """Send an authenticated request.

        Logs in (again) when the device asks for it, and repeats a GET once when a
        kept-alive connection turns out to be dead. `urgent` skips the back-off after
        recent failures, for things a person has just asked for. `vital=False` is for a
        detail asked of a device that has just answered: if that one question goes
        unanswered, the device is not taken to be down.

        `still`: asked just before the request goes out, where signing in may have taken a while: whether
        whoever wanted it may still have it. The device may have forgotten this program and be slow to let it
        in again, and a power button is not pressed for an account that was removed half a minute ago.

        `within`: the time for the whole exchange (see `bounded`); left out, what the request's own waits add up to.
        """
        REQUEST_OUT.set(False)
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = False
        while True:
            REQUEST_OUT.set(False)
            token = self._token or await self._login()
            client = await self._http()
            limit = MAX_PICTURE if path == "/api/streamer/snapshot" else MAX_REPLY
            try:
                request = client.build_request(method, path, headers={"Cookie": f"auth_token={token}"}, **kwargs)
                if still is not None and not still():
                    raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
                if self._closed:
                    raise RETIRED.with_traceback(None)  # (as _send says it: not sent)
                REQUEST_OUT.set(True)
                resp = await self._send(client, request, limit, within)
            except KvmError as ex:
                raise failed(ex) from None
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as ex:
                # Usually a connection the device closed while it sat idle, or because it rebooted.
                # Only a GET is safe to send twice.
                if method == "GET" and not retried:
                    retried = True
                    continue
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            except httpx.HTTPError as ex:
                if not went_out(ex):
                    REQUEST_OUT.set(False)
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            self._answered()
            if resp.status_code not in (401, 403):
                return resp
            if relogged:
                # It signs this program in and refuses the session it has just given. Every look ends up
                # here: the password is not sent to it again with each of them.
                async with self._login_lock:
                    if self._token == token:
                        self._token = None
                        self._login_error = KvmError("auth_failed", "Device keeps rejecting the session")
                        self._login_retry_at = time.monotonic() + LOGIN_RETRY
                raise KvmError("auth_failed", "Device keeps rejecting the session")
            # Session expired or kvmd restarted: forget the token and log in once more.
            relogged = True
            if self._token == token:
                self._token = None

    async def _get_result(self, path: str, urgent: bool = False, vital: bool = True) -> Any:
        resp = await self._request("GET", path, urgent=urgent, vital=vital)
        if resp.status_code != 200:
            raise KvmError("bad_response", f"{path} failed (HTTP {resp.status_code})")
        try:
            return read_json(resp)["result"]
        except (ValueError, KeyError, TypeError):
            raise KvmError("bad_response", f"{path} returned unexpected data") from None

    async def _optional(self, path: str, urgent: bool = False, vital: bool = True) -> Any:
        """A GLKVM-only endpoint: None on devices that don't have it."""
        try:
            return await self._get_result(path, urgent, vital)
        except KvmError as ex:
            if ex.code != "bad_response":
                raise
            return None

    # --- identity -----------------------------------------------------------

    async def identify(self) -> dict[str, Any]:
        """Log in and read what the device says about itself. Raises KvmError if it can't."""
        await self._get_result("/api/auth/check", urgent=True)
        version = await self._glinet_version(urgent=True)
        if self._glinet is False:
            # Stock kvmd: what it is, and the name it goes by (the one its own page shows), are in /api/info.
            info = await self._optional("/api/info", urgent=True)
            return {**_stock_about(info), "hostname": plain(_dig(info, "meta", "server", "host"))}
        hostname = await self._optional("/api/system/get_hostname", urgent=True)
        return {
            "model": plain(_dig(version, "model"), 40),
            "version": plain(_dig(version, "version"), 40),
            "hostname": plain(_dig(hostname, "hostname")),
        }

    async def _glinet_version(self, urgent: bool = False, vital: bool = True) -> dict[str, Any] | None:
        """GL.iNet's own account of the firmware (its model and version); None where there is none to have.

        On the way, what the answer says of the KVM is noted (`_glinet`): a 404 is stock kvmd, which has none of
        GL.iNet's routes; an answer of the shape GL.iNet's firmware gives is that firmware. Anything else (an error of
        the moment, an answer of another kind) says neither, and what was known before stays as it was.
        """
        try:
            resp = await self._request("GET", "/api/upgrade/version", urgent=urgent, vital=vital)
        except KvmError as ex:
            if ex.code != "bad_response":  # (one that sends this program on to an address that is none, say: no answer, as before)
                raise
            return None
        if resp.status_code == 404:
            self._glinet = False
            return None
        if resp.status_code != 200:
            return None
        try:
            result = read_json(resp)["result"]
        except (ValueError, KeyError, TypeError):
            return None
        if not isinstance(result, dict):
            return None
        self._glinet = True
        return result

    # --- snapshots ----------------------------------------------------------

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """Latest frame, at least `width` pixels wide when the source has that many.

        Callers wanting the same size share one device request, and so do viewers whose turns to
        refresh fall close together: several browsers on one wall cost the KVM little more than one.

        Nobody waits long for it. A browser makes only a few requests at a time, so a tile that waited
        for as long as a slow KVM takes would hold up the tiles of all the others. After
        PICTURE_PATIENCE the tile is told to ask again; the request to the KVM carries on by itself,
        and what it brings goes to whoever asks next.
        """
        arrived = self._wanted_at = time.monotonic()
        await self._expect_up()
        size = tier_for(width)
        if size != FULL and self._source_width and TIERS[size][0] >= self._source_width:
            size = FULL  # nothing to shrink: take the frame as captured rather than re-encode it
        window = share_window(fresh)
        while True:
            frame = self._frames.get(size)
            # A frame nobody was handed yet is new to whoever asks. Otherwise its age counts from when
            # it was asked for to when this caller asked: one that was fetched while this caller waited
            # is as fresh as can be however long the KVM took over it, and no caller is ever handed,
            # as new, the frame it got the last time.
            if frame and (size in self._unseen or arrived - frame.taken_at < window):
                self._unseen.discard(size)
                return frame
            failed = self._frame_errors.get(size)
            # A stream that is waking up has frames within moments; don't make viewers wait a full hold.
            hold = ERROR_HOLD / 2 if failed and failed[1].code == "no_stream" else ERROR_HOLD
            if failed and time.monotonic() - failed[0] < hold:
                raise failed[1].with_traceback(None)
            fetch = self._fetching.get(size)
            mine = fetch is None or fetch.done()
            if fetch is None or fetch.done():
                fetch = self._fetching[size] = asyncio.create_task(self._fetch(size, arrived))
                fetch.add_done_callback(_looked_at)
                self._fetching_since[size] = arrived
            # The patience is with the KVM, not with this caller: a request that has been with the KVM
            # for long already is not waited for by one caller after the other.
            patience = min(arrived, self._fetching_since[size]) + PICTURE_PATIENCE - time.monotonic()
            if patience > 0:
                await asyncio.wait({fetch}, timeout=patience)
            if not fetch.done():
                raise KvmError("no_stream", "The KVM is slow to answer", 503)
            if fetch.cancelled():  # which only retiring the device does
                raise RETIRED.with_traceback(None)
            if mine:
                frame = fetch.result()  # or the error the request ended in
                self._unseen.discard(size)
                return frame
            # Somebody else's request, now over: look again whether what it brought will do for this caller.

    async def _fetch(self, size: str, asked: float) -> Snapshot:
        """Get a frame from the device and keep it (or why there is none) for those who ask."""
        screen = self._screen
        try:
            frame = await self._fetch_snapshot(size, asked)
        except KvmError as ex:
            if ex.code not in DOWN_CODES:  # those are held back by _check_backoff, for every caller
                self._frame_errors[size] = (time.monotonic(), ex)
            raise
        self._frame_errors.pop(size, None)
        if screen == self._screen:  # else it may show the computer the KVM was switched away from meanwhile
            self._frames[size] = frame
            self._unseen.add(size)
        return frame

    async def _fetch_snapshot(self, size: str, asked: float) -> Snapshot:
        # allow_offline: with no video signal kvmd still returns its placeholder
        # picture (flagged offline) instead of an error.
        params = {"allow_offline": "1"}
        if size != FULL:
            width, height, quality = TIERS[size]
            params |= {
                "preview": "1",
                "preview_max_width": str(width),
                "preview_max_height": str(height),
                "preview_quality": str(quality),
            }
        resp = await self._request("GET", "/api/streamer/snapshot", params=params)
        if resp.status_code == 503:
            # kvmd stops its video pipeline when no client is connected, and
            # snapshots fail until one connects.
            self._start_keepalive()
            raise KvmError("no_stream", "Video stream is idle - waking it up", 503)
        if resp.status_code != 200:
            raise KvmError("bad_response", f"Snapshot failed (HTTP {resp.status_code})")
        kind = resp.headers.get("content-type", "image/jpeg").split(";")[0].strip().lower()
        if kind not in PICTURES:
            # Handing a browser whatever a device calls a picture (a web page, say) would let the device speak as us.
            raise KvmError("bad_response", "The device sent something that is not a picture")
        said = picture_size(resp.content)
        if said is None:
            raise KvmError("bad_response", "The device sent something that is not a picture")
        wide, high = said
        if not (0 < wide <= MAX_PICTURE_SIDE and 0 < high <= MAX_PICTURE_SIDE and wide * high <= MAX_PICTURE_PIXELS):
            # Small to send, enormous to draw: it would be the browser that pays for looking at it.
            raise KvmError("bad_response", f"The device sent a picture of {wide} by {high} pixels, which is not shown")
        # The KVM gave a picture: its streamer is held from now on, as a browser on its own page holds it, and not only
        # once it was found stopped. One that somebody else's viewer had running goes on by itself for a while after that
        # viewer has gone (kvmd: ten seconds), and then stops; held only then, the pictures broke off ("waking it up"),
        # and came back as the KVM's own placeholder ("no live video") while its streamer started again.
        self._start_keepalive()
        return Snapshot(
            data=resp.content,
            content_type=kind,
            signal=resp.headers.get("x-ustreamer-online", "true").lower() != "false",
            taken_at=asked,
        )

    def _keepalive_due(self) -> bool:
        # Not for a client that was retired: nothing would stop it, and it would hold the KVM's streamer with the old
        # session. Nor at once again after one that never got its connection: a KVM that gives pictures and refuses the
        # line for them (or a proxy before it that passes no WebSocket on) was asked for one at every picture, thirty
        # a second for a live line. Asked again after a pause that grows, as a device that is down is.
        due = not self._closed and time.monotonic() >= self._keepalive_again_at
        return due and (self._keepalive is None or self._keepalive.done())

    def _start_keepalive(self) -> None:
        if self._keepalive_due():
            self._keepalive = asyncio.create_task(self._hold_stream_open())
            self._keepalive.add_done_callback(self._keepalive_ended)

    def _keepalive_ended(self, task: asyncio.Task[None]) -> None:
        """An error nobody foresaw that ended the keepalive is said once a minute (as `_unexpected` says it), never left unseen."""
        if not task.cancelled() and (error := task.exception()) is not None:
            self._unexpected("keeping the picture's line failed", error)

    async def _learn_family(self) -> None:
        """Where it is not known yet whether the KVM has GL.iNet's routes (see `_glinet`), ask it; unknown stays unknown."""
        try:
            await self._read_about()
        except KvmError:
            pass

    async def _hold_stream_open(self) -> None:
        """Stay connected to the kvmd websocket, as a browser viewer would, while the wall is watched; and hear its power board
        there (see EVENTS_PING)."""
        url = "ws" + self.spec.base_url[len("http"):] + "/api/ws"
        opened_at: float | None = None
        # Whether the KVM said anything after the first ping. One that ends the line at a ping it does not know lasted as long
        # as the first ping took to come (EVENTS_PING, as long as KEEPALIVE_LASTS), and would be held anew at every picture.
        # (A line this program let go of because nobody watched any more held, whatever came on it.)
        answered = let_go = False
        try:
            if self._glinet is None:
                # Whether the session may go into the address (see `_line`): asked here, in the keepalive's own task, and
                # not on the way to the picture that began it, which waited for the answer before it was handed over.
                await self._learn_family()
            token = self._token or await self._login()  # (after that question, which may have signed in anew)
            async with ws_connect(
                # GLKVM's own web client passes the token both ways; do the same, where it is known to be one (see `_line`).
                f"{url}?stream=1" + (f"&auth_token={token}" if self._glinet is True else ""),
                ssl=self._tls,
                additional_headers={"Cookie": f"auth_token={token}"},
                open_timeout=6,
                close_timeout=1,  # a device that is gone gets no ten seconds to say goodbye in
                max_size=MOST_EVENT,
                max_queue=4,  # messages that may wait to be read; more, and the device is made to wait, not this program's memory
            ) as ws:
                opened_at = asked_at = self._events_heard_at = time.monotonic()
                heard = Listening(ws, MOST_EVENT)
                while time.monotonic() - self._wanted_at < KEEPALIVE_IDLE:
                    if time.monotonic() - asked_at >= EVENTS_PING:
                        asked_at = time.monotonic()
                        async with asyncio.timeout(EVENTS_PING):  # (never asyncio.wait_for: on Python 3.11 it can lose a stop)
                            await ws.send(EVENT_PING)
                    try:
                        message = await heard.message(max(0.0, asked_at + EVENTS_PING - time.monotonic()))
                    except TimeoutError:
                        continue
                    self._events_heard_at = time.monotonic()
                    if asked_at > opened_at:
                        answered = True  # (something came after a ping: a KVM that ended the line at its first one did not)
                    self._heard_on_the_line(message)
                let_go = True
        except (KvmError, OSError, WebSocketException, TimeoutError) as ex:
            # Why it ended is, for a connection the device closed, a text of the device's choosing: said as
            # one line, whatever it holds. And once a minute: a device can end one a second.
            now = time.monotonic()
            if now - self._ended_said >= SAY_AGAIN:
                self._ended_said = now
                log.info("%s: stream keepalive ended: %s", self.label, plain(str(ex), 200) or type(ex).__name__)
        finally:
            self._board_said = None  # (what the board says is asked again from now on)
            self._board_moved()
            if opened_at is not None and time.monotonic() - opened_at >= KEEPALIVE_LASTS and (answered or let_go):
                self._keepalive_fails = 0
            else:  # (it never had its connection, or the KVM ended it at once: not begun again before a pause that grows)
                self._keepalive_fails += 1
                self._keepalive_again_at = time.monotonic() + min(BACKOFF_MAX, ERROR_HOLD * 2 ** min(self._keepalive_fails - 1, 10))

    # --- what the power board says on the keepalive's line (see EVENTS_PING) -----

    def _board_heard(self) -> dict[str, Any] | None:
        """What the power board said last on the keepalive's line, where that line is held and was heard from of late; else None."""
        if self._closed or self._board_said is None or self._keepalive is None or self._keepalive.done():
            return None
        if time.monotonic() - self._events_heard_at > EVENTS_QUIET:
            return None
        return self._board_said

    def _board_moved(self) -> None:
        """Whoever waits for the board's next word is told: it came, or the line it comes on ended."""
        news, self._board_news = self._board_news, asyncio.Event()
        news.set()

    def _heard_on_the_line(self, message: str | bytes) -> None:
        """One message on the keepalive's line: kept where it is the power board's state (an `atx` event), else let be.

        Only a message that can be one is read as JSON (on the one thread there is: a line carries the KVM's other states
        too, a megabyte each at the most). A word that says what was said before is no news: a KVM that repeated its
        state would otherwise have the tile looked at again at every repetition, every question of the look with it.
        """
        if not isinstance(message, str):
            return
        if len(message) <= MOST_MSD_WORD and '"msd"' in message:
            heard = event_of(message)
            if heard is not None and heard[0] == "msd":
                self._msd_said(heard[1])
                return
        if len(message) > MOST_BOARD_WORD or ('"atx"' not in message and '"fingerbot"' not in message):
            return
        said = event_of(message)
        if said is not None and said[0] == "fingerbot":
            self._fingerbot_said(fingerbot_heard(said[1]))
            return
        if said is None or said[0] != "atx" or (board := board_heard(said[1])) is None or board == self._board_said:
            return
        self._board_said = board
        self._board_words += 1
        self._status_at = 0.0  # what the tile says may be out of date now: it is looked at again when next asked
        self._board_moved()

    def _fingerbot_said(self, there: bool | None) -> None:
        """The KVM said whether a Fingerbot is paired with it (None: what it said is no answer, and changes nothing)."""
        if there is None:
            return
        self._fingerbot_heard_at = time.monotonic()
        if there == self._fingerbot:
            return
        self._fingerbot = there
        self._fingerbot_words += 1
        if not there:
            # One paired anew (perhaps another) is asked soon: within FINGERBOT_BATTERY_RETRY of the last question, and not at
            # every word of a KVM that says yes and no in turn (each question is a round trip on the Fingerbot's battery).
            self._battery = None
            self._battery_next = min(self._battery_next, self._battery_asked_at + FINGERBOT_BATTERY_RETRY)
        self._status_at = 0.0  # its buttons come or go on the tile: looked at again when next asked

    # --- the live line (see live.py) ------------------------------------------

    def hold_stream(self) -> None:
        """Somebody is watching the live picture: keep the KVM's streamer running, as a browser on its own page would."""
        self._wanted_at = time.monotonic()
        self._start_keepalive()

    async def live_picture(self, size: str) -> Snapshot:
        """One picture as the KVM gives it now, for the live line: what a tile gets, without the sharing between tiles."""
        now = self._wanted_at = time.monotonic()
        self._check_backoff()
        return await self._fetch_snapshot(size, now)

    async def media_line(self) -> ClientConnection:
        """The KVM's own H.264 line (stock PiKVM's media WebSocket), signed in. KvmError `no_media` where it has none."""
        if self._glinet is None:
            await self._learn_family()  # (the line for events, held beside it by `hold_stream`, is to know where its session may go)
        return await self._line("/api/media/ws", MOST_UNIT, KvmError("no_media", "The KVM has no H.264 line", 404))

    async def input_line(self) -> ClientConnection:
        """The KVM's WebSocket for keys and the mouse, signed in, and not holding its streamer (`stream=0`): that is the picture's business."""
        refused = KvmError("not_allowed", "The KVM does not let this program send keys and the mouse", 403)
        if self._glinet is None:
            await self._learn_family()  # (whether the session may go in the address: see `_line`)
        return await self._line("/api/ws?stream=0", 2**20, refused, token_in_query=self._glinet is True)

    async def _line(self, path: str, most: int, refused: KvmError, token_in_query: bool = False) -> ClientConnection:
        """A WebSocket to the KVM at `path`, signed in; signed in anew, once, where it refuses the session it gave.

        `refused`: what stands where the KVM answers the handshake with anything but a session it does not take.
        `token_in_query`: the session goes in the address as well as in the cookie, as GLKVM's own page sends it
        to the line for events (the keepalive does the same). Not to stock kvmd, which takes the cookie and writes the
        address of every request into its log, where the session stood for anybody who reads it; nor to a KVM not yet
        known to be a GLKVM (its answer said neither), which may be stock kvmd; nor to the media line, which is stock kvmd's.
        """
        self._check_backoff()
        relogged = False
        while True:
            token = self._token or await self._login()
            await self._http()  # (how the certificate is checked is settled there)
            url = "ws" + self.spec.base_url[len("http"):] + path + (f"&auth_token={token}" if token_in_query else "")
            try:
                ws = await ws_connect(
                    url,
                    ssl=self._tls,
                    additional_headers={"Cookie": f"auth_token={token}"},
                    open_timeout=6,
                    close_timeout=1,  # a device that is gone gets no ten seconds to say goodbye in
                    max_size=most,  # (what arrives is read through Listening, which bounds it as it comes; this is the library's own bound)
                    max_queue=4,  # pictures that may wait to be read; more, and the device is made to wait, not this program's memory
                )
            except InvalidStatus as ex:
                self._answered()
                status = ex.response.status_code
                if status in (401, 403):
                    if not relogged:
                        # The session was replaced, or ran out: once more, with a new one.
                        relogged = True
                        if self._token == token:
                            self._token = None
                        continue
                    raise KvmError("auth_failed", "Device keeps rejecting the session") from None
                raise KvmError(refused.code, f"{refused.message} (HTTP {status})", refused.status) from None
            except TimeoutError as ex:
                raise self._failed(KvmError("timeout", "Device did not respond in time", 504)) from ex
            except (OSError, WebSocketException) as ex:
                raise self._failed(ws_error(ex, self.spec.tls)) from ex
            self._answered()
            return ws

    # --- actions ------------------------------------------------------------

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """Run one of ACTIONS, or:

        'wol'   wake `mac` from the device's network
        'keys'  press the key combination `keys` on the connected computer
        'text'  type `text` on the connected computer
        'port'  show input `port` (counted from 0) of a multi-port KVM
        'fingerbot_power', 'fingerbot_power_long'  the power button, pressed or held by a Fingerbot (FINGERBOT_PRESSES)
        """
        if action in FINGERBOT_PRESSES:
            await self._fingerbot_press(action, still)
            return
        extra: dict[str, Any] = {}
        # What the last look found the KVM has not got is not sent. (Where nothing is known yet, it is sent, and the KVM says.)
        if action == "reboot" and self._glinet is False:
            raise KvmError("invalid", "This KVM offers no restart of itself", 422)
        if action == "wol" and self._glinet is False:
            raise KvmError("invalid", "This KVM offers no Wake-on-LAN that qKVM can use", 422)
        if action == "jiggler_on" and self._jiggler_off:
            # (Sent all the same, kvmd answers yes and leaves it off: "done" would be said of nothing done.)
            raise KvmError("invalid", "Keep-awake is switched off in this KVM's own settings", 422)
        if action == "port":
            if not 0 <= port < len(_dig(self._status, "ports", "list") or []):
                raise KvmError("invalid", "This KVM has no such port", 422)
            path, params = "/api/switch/set_active", {"port": str(port)}
            # The KVM answers once it has switched, which takes it several seconds.
            extra = {"timeout": httpx.Timeout(30.0, connect=4.0)}
        elif action == "wol":
            if not MAC.fullmatch(mac):
                raise KvmError("invalid", "Not a valid MAC address", 422)
            path, params = "/api/wol/wake", {"mac": mac}
        elif action == "keys":
            if not KEYS.fullmatch(keys):
                raise KvmError("invalid", "Not a valid key combination", 422)
            if names_the_power_key(keys):
                raise KvmError("invalid", POWER_KEY_REFUSED, 422)  # (kvmd is told the names as they come, and has it)
            path, params = "/api/hid/events/send_shortcut", {"keys": keys}
        elif action == "text":
            if not text or len(text) > MAX_TEXT:
                raise KvmError("invalid", f"Text must be 1 to {MAX_TEXT} characters", 422)
            path, params = "/api/hid/print", {"limit": "0"}
            # The KVM answers once it has finished typing, which takes a while for long text.
            extra = {"content": text.encode("utf-8"), "timeout": httpx.Timeout(90.0, connect=4.0)}
        elif action in ACTIONS:
            path, params = ACTIONS[action]
        else:
            raise KvmError("invalid", "This KVM cannot do that", 422)
        before: bool | None = None  # whether the computer was on before a power button was pressed (None: not known)
        if action in HELD and (left := self._fingerbot_turn.held()) > 0:
            # (Two power buttons of one machine: pressed together, the one undoes the other.)
            raise KvmError("busy", f"Its Fingerbot may still be pressing the power button: its last press got no clear answer. Try again in {int(left) + 1} seconds.", 409)
        if action in HELD:
            PRESS_SENT.set(False)  # (until its click goes out: see REQUEST_OUT)
            self._board_not_now()
            extra = {"timeout": httpx.Timeout(BOARD_ANSWER, connect=WAITS.connect)}
            try:
                before, busy = await self._board_now(ask=True)
            except KvmError:  # (taken away meanwhile: the press itself is refused for that below, as it was before)
                before, busy = None, False
            if busy:
                raise KvmError("busy", "The KVM's power board is pressing a button at this moment (from its own page, or another program). Wait for it to finish.", 409)
            if before is False and flag(_dig(self._status, "video", "signal")) is not False:
                before = None  # a light that says "off" beside a picture is not wired up: it is no witness of what a press does
        try:
            resp = await self._request("POST", path, urgent=True, params=params, still=still, **extra)
        except asyncio.CancelledError:
            if action in HELD and REQUEST_OUT.get():
                PRESS_SENT.set(True)
                self._board_may_be_pressing(action)  # (qKVM stopping, or its listeners reopened: cut off while the click was on its way)
            raise
        except KvmError as ex:
            # A KVM that is already going down may never answer its own reboot request.
            if action == "reboot" and ex.code in ("dropped", "timeout"):
                return
            if action in HELD and (ex is RETIRED or ex.code in ("timeout", "dropped")) and not REQUEST_OUT.get():
                # (Signing in first, or waiting for a connection to the KVM, or the tile saved anew before the click was sent:
                # it never went out, nothing was pressed, and nothing is held.)
                raise KvmError("action_failed", f"Nothing was pressed: the press did not reach the KVM ({ex.message})") from None
            if action in HELD and (ex is RETIRED or ex.code in ("timeout", "dropped")):
                # (No answer in time, one that broke off, or the connection taken away meanwhile: the click may have gone out.)
                self._board_may_be_pressing(action)
                if ex.code == "timeout":
                    raise KvmError("timeout", "The KVM did not say whether its board pressed the button. It may have: look at the machine before pressing again.", 504) from None
                if ex.code == "dropped":
                    raise KvmError("dropped", "The KVM's answer to the press broke off. It may have pressed: look at the machine before pressing again.") from None
            raise
        if resp.status_code != 200 and action in HELD and not 400 <= resp.status_code < 500:
            # Neither its yes nor a no: its web server's 502, 503 or 504 while kvmd restarts, or kvmd's own 500, after the board
            # may have been told. Whether it pressed is not known, and a press is not offered again on the strength of it.
            self._board_may_be_pressing(action)
            raise KvmError("timeout", f"The KVM's answer to the press says neither that it pressed nor that it did not (HTTP {resp.status_code}). It may have: look at the machine before pressing again.", 504)
        if resp.status_code != 200:
            try:
                result = read_json(resp)["result"]
                detail = result.get("error_msg") or result.get("error")
            except (ValueError, KeyError, TypeError, AttributeError):
                detail = None
            raise KvmError("action_failed", plain(detail, 200) or f"The device refused (HTTP {resp.status_code})")
        if action in HELD:
            PRESS_ANSWERED.set(True)
            await self._let_go(action, before, self._board_words)
        if action == "port":
            # What was on screen belongs to the other computer now.
            self._frames.clear()
            self._unseen.clear()
            self._screen += 1
            if self._status and self._status.get("ports"):
                self._status["ports"]["active"] = port
            self._status_at = 0.0

    async def _board_now(self, ask: bool = False, since: int | None = None) -> tuple[bool | None, bool]:
        """What the KVM's power board says at this moment: whether the computer is on (None: it does not say), and whether
        it is pressing a button. From the keepalive's line where that says the board is there (see `_board_heard`); asked
        otherwise, and a second time where the first answer said there is no board: a Comet's board says so to whoever asks
        while it answers somebody else (on its line for events too). One that does not answer is not asked again: it says
        nothing.

        `ask`: asked all the same, before a press. A Comet's board says `busy` for the first half second of a press, and its
        line says the board's state as it read it last, about every second and a quarter: on a real one the line never said
        busy, and a press from the KVM's own page half a second before went unseen there. Busy where either says so; the
        computer's power as the answer says it, the fresher of the two.

        `since`: the count of the board's words on the line (`_board_words`) at the click. What the line said before is from
        before the press (the Comet's reading of its board may be a second and a quarter old), and is no witness of what
        the press did: the board is asked until the line has said something since.
        """
        heard = self._board_heard()
        if heard is not None and flag(heard.get("enabled")) is not True:
            heard = None  # (a "no board" on the line: asked, as above)
        if heard is not None and since is not None and self._board_words == since:
            heard = None
        if heard is not None and not ask:
            return power_said(heard), flag(heard.get("busy")) is True
        heard_busy = heard is not None and flag(heard.get("busy")) is True
        for _ in range(2):
            try:
                atx = await self._get_result("/api/atx", urgent=True, vital=False)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    raise RETIRED.with_traceback(None) from None
                break
            if flag(_dig(atx, "enabled")) is True:
                return power_said(atx), heard_busy or flag(_dig(atx, "busy")) is True
        if heard is not None:
            return power_said(heard), heard_busy
        return None, False

    def _board_not_now(self) -> None:
        """Raise `busy` where the KVM's power board may still be pressing a button after a click of this program's that got
        no clear answer (BOARD_ANSWER): whoever asks, a Fingerbot's press on the same machine too, through a client made
        anew by an edit as well (the turn is shared)."""
        if (left := self._fingerbot_turn.board_held()) > 0:
            raise KvmError("busy", f"Its power board may still be pressing a button: its last press got no clear answer. Look at the machine; try again in {int(left) + 1} seconds.", 409)

    def _board_may_be_pressing(self, action: str) -> None:
        """A click of `action` came to no clear answer: the board may take it as late as now, and hold the button."""
        turn = self._fingerbot_turn
        turn.board_until = max(turn.board_until, time.monotonic() + BOARD_ANSWER + HELD[action])

    async def _let_go(self, action: str, before: bool | None, words: int) -> None:
        """After a power button's click was answered: wait until the board has let go of the button (HELD), and then, for a
        press that must change the computer's power, until the board shows the change, SEEN_WITHIN at the most. Where it
        does not, the press was made all the same, and NotSeen says what was seen instead. `words`: how many words the board
        had said on its line when the click was answered (see `_board_now`)."""
        await asyncio.sleep(HELD[action])
        self._status_at = 0.0  # what the tile says may be out of date now
        changes: dict[tuple[str, bool | None], bool] = {("atx_power", False): True, ("atx_power_long", True): False}
        wanted = changes.get((action, before))
        if wanted is None:
            return  # a running system asked to shut down takes the time it takes; a reset leaves the power as it was
        pressed = "pressed" if wanted else "held"
        deadline = time.monotonic() + SEEN_WITHIN
        said = False  # whether the board has said anything of the computer since
        looking: asyncio.Task[tuple[bool | None, bool]] | None = None
        news = self._board_news
        while True:
            # A look is not cut off (it may be a sign-in, or a connection being made, on a connection that stays in use:
            # see `bounded`). One that is still under way when the time is up goes on by itself, and is not asked again.
            if looking is None or looking.done():
                news = self._board_news  # (taken before the look: a word that comes while it is read is not missed)
                looking = asyncio.ensure_future(self._board_now(since=words))
                looking.add_done_callback(_looked_at)
            await asyncio.wait({looking}, timeout=max(0.0, deadline - time.monotonic()))
            on: bool | None = None
            if looking.done() and not looking.cancelled():
                try:
                    on = looking.result()[0]
                except KvmError:  # (only RETIRED: the tile was edited or removed, or the wall locked itself, meanwhile)
                    raise NotSeen(f"{pressed}; not seen: its connection ended") from None
                looking = None
            if on is wanted:
                self._refresh_soon()
                return
            said = said or on is not None
            if time.monotonic() >= deadline:
                if not said:
                    raise NotSeen(f"{pressed}; its board has not said since")
                raise NotSeen("pressed, but the computer is still off" if wanted else "held, but the computer is still on")
            if looking is None:
                left = min(SEEN_EVERY, max(0.0, deadline - time.monotonic()))
                if self._board_heard() is None:  # (no line held: asked again in a moment)
                    await asyncio.sleep(left)
                    continue
                # The board's next word on its line for events, rather than the next asking: the press is answered as soon
                # as the change is said (and the line's end is told the same way: then it is asked).
                try:
                    async with asyncio.timeout(left):
                        await news.wait()
                except TimeoutError:
                    pass

    # --- a Fingerbot paired with the KVM (see FINGERBOT_PRESSES) -------------------------------------------------

    async def _fingerbot_press(self, action: str, still: Callable[[], bool] | None) -> None:
        """Have the Fingerbot paired with the KVM press the power button, or hold it, as hard as this machine's is set to.

        Done once the Comet has said the Fingerbot took the press and the press's own time has passed after that, and the
        arm's way back: until then the machine is being done something to, and a second press is refused (by the wall's
        one thing at a time). Only a 4xx is a no ("Press Failed" on the Comet's page: its 400, "Failed to click"), and
        nothing was pressed as far as the Comet knows. Anything else that is not its yes (a 5xx, a proxy's page, a yes of
        another shape, an answer that broke off, none within the time the Comet's own page gives it) may have pressed: then
        the Fingerbot is left alone for as long as that press can last (FingerbotTurn.held_until), whoever asks.
        """
        seconds = FINGERBOT_PRESSES[action]
        PRESS_SENT.set(False)
        if self._glinet is False:
            raise KvmError("invalid", "This KVM has no Fingerbot: that is a GL.iNet Comet's", 422)
        self._fingerbot_not_now()
        turn = self._fingerbot_turn
        async with turn.lock:  # (a question of its battery under way is let finish: see FINGERBOT_BATTERY_WAIT)
            self._fingerbot_not_now()  # (as it is now: the turn may have been waited for)
            there: bool | None = self._fingerbot
            if there is not True:
                # Not said either way since qKVM started (nobody has watched its picture), or not of late: asked.
                try:
                    there = await self._ask_fingerbot()
                except KvmError as ex:
                    # (Retired meanwhile too: the KVM was only being asked, and nothing was pressed.)
                    raise KvmError("action_failed", f"Nothing was pressed: the KVM could not be asked whether a Fingerbot is paired with it ({ex.message})") from None
            if there is False:
                raise KvmError("invalid", "No Fingerbot is paired with this KVM", 422)
            if there is None:
                self._fingerbot_silent_at = time.monotonic()
                raise KvmError("action_failed", "Nothing was pressed: the KVM did not say whether a Fingerbot is paired with it")
            if self._closed:
                # The tile was edited or removed, or qKVM let go of the KVM, while it was being asked: not sent. (Said as
                # "may have been done" where it comes later, on the way: see `_request`.)
                raise KvmError("action_failed", "Nothing was pressed: the KVM was changed or let go of while it was being asked")
            strength = FINGERBOT_STRENGTHS.get(self.spec.fingerbot_strength, FINGERBOT_STRENGTHS["firm"])

            def may_be_pressing() -> None:
                # What follows said neither yes nor no: the Comet may take the press as late as now (it may go on with a
                # request whose asker gave up), and it took a second press a second into another. Nothing more goes to the
                # Fingerbot, from whoever, for as long as a press taken now can last: an answer's time, its own and the arm's.
                turn.held_until = max(turn.held_until, time.monotonic() + FINGERBOT_ANSWER + seconds + FINGERBOT_BACK)

            PRESS_SENT.set(True)
            try:
                resp = await self._request(
                    "POST", "/api/fingerbot/click", urgent=True, vital=False, still=still,
                    params={"press_time": str(round(seconds * 1000)), "angle_enum": strength},
                    timeout=httpx.Timeout(FINGERBOT_ANSWER + seconds, connect=WAITS.connect),
                )  # fmt: skip
            except asyncio.CancelledError:
                if REQUEST_OUT.get():
                    may_be_pressing()  # (qKVM stopping, or its listeners reopened: cut off while the press was on its way)
                else:
                    PRESS_SENT.set(False)  # (cut off while the wall signed in to the KVM: it never went out)
                raise
            except KvmError as ex:
                if (ex is RETIRED or ex.code in ("timeout", "dropped")) and not REQUEST_OUT.get():
                    # (Signing in first, waiting for a connection to the KVM, or the tile saved anew before the press was
                    # sent: it never went out, nothing was pressed, and the Fingerbot is not held.)
                    raise KvmError("action_failed", f"Nothing was pressed: the press did not reach the KVM ({ex.message})") from None
                if ex is RETIRED or ex.code in ("timeout", "dropped"):
                    may_be_pressing()
                if ex.code == "timeout":
                    raise KvmError("timeout", "The KVM did not say whether its Fingerbot pressed. It may have: look at the machine before pressing again.", 504) from None
                if ex.code == "dropped":
                    raise KvmError("dropped", "The KVM's answer to the press broke off. It may have pressed: look at the machine before pressing again.") from None
                raise
            try:
                said = read_json(resp)
            except ValueError:
                said = None
            if 400 <= resp.status_code < 500:
                why = plain(_dig(said, "result", "error_msg"), 120) or plain(_dig(said, "result", "error"), 120)
                raise KvmError("action_failed", f"The Fingerbot did not press: the KVM said \"{why}\"" if why else f"The Fingerbot did not press (the KVM answered HTTP {resp.status_code})")
            if resp.status_code != 200 or _dig(said, "ok") is not True or _dig(said, "result", "result") != "success":
                # Neither its yes nor a no (a 5xx: kvmd's own error, or a proxy's, after the Fingerbot may have been told; a yes
                # of another shape): whether it pressed is not known, and a press is not offered again on the strength of it.
                may_be_pressing()
                raise KvmError("timeout", f"The KVM's answer to the press says neither that it pressed nor that it did not (HTTP {resp.status_code}). It may have: look at the machine before pressing again.", 504)
            PRESS_ANSWERED.set(True)
            await asyncio.sleep(seconds + FINGERBOT_BACK)
        self._status_at = 0.0

    def _fingerbot_not_now(self) -> None:
        """Raise what stands against a press of the Fingerbot at this moment, where something does: one that may still be
        pressing, or a word of the KVM's of a moment ago (FINGERBOT_ASK_AGAIN) that none is paired, or nothing said."""
        if (left := self._fingerbot_turn.held()) > 0:
            raise KvmError("busy", f"The Fingerbot may still be pressing: the last press got no clear answer. Try again in {int(left) + 1} seconds.", 409)
        self._board_not_now()  # (two power buttons of one machine: pressed together, the one undoes the other)
        now = time.monotonic()
        if self._fingerbot is False and now - self._fingerbot_heard_at < FINGERBOT_ASK_AGAIN:
            # As it said a moment ago. Not asked again on a line of its own, which may wake its computer, for a press that is
            # not made: where one has been paired since, it says so on the line held while its picture is watched, or when
            # it is asked again a while later.
            raise KvmError("invalid", "No Fingerbot is paired with this KVM", 422)
        if self._fingerbot is not True and now - self._fingerbot_silent_at < FINGERBOT_ASK_AGAIN:
            left = FINGERBOT_ASK_AGAIN - (now - self._fingerbot_silent_at)
            raise KvmError("action_failed", f"Nothing was pressed: the KVM did not say whether a Fingerbot is paired with it when it was asked a moment ago. It is asked again in {int(left) + 1} seconds, or as soon as its picture is watched.")

    async def _ask_fingerbot(self) -> bool | None:
        """Whether a Fingerbot is paired with the KVM, asked on a line of its own to the KVM's events, which is the only way
        it says that: its `fingerbot` event, waited for FINGERBOT_ASK_WITHIN seconds. None where it said nothing in that
        time; KvmError where the line could not be had."""
        if self._glinet is None:
            await self._learn_family()
        if self._glinet is False:
            return False  # (stock kvmd: no Fingerbot, and no line opened to ask it)
        ws = await self._line(
            "/api/ws?stream=0", MOST_EVENT, KvmError("not_allowed", "The KVM does not let this program hear its events", 403), token_in_query=True
        )
        try:
            heard = Listening(ws, MOST_EVENT)
            until = time.monotonic() + FINGERBOT_ASK_WITHIN
            while True:
                message = await heard.message(until - time.monotonic())
                if isinstance(message, str) and len(message) <= MOST_BOARD_WORD and '"fingerbot"' in message:
                    said = event_of(message)
                    if said is not None and said[0] == "fingerbot" and (there := fingerbot_heard(said[1])) is not None:
                        self._fingerbot_said(there)
                        return there
        except (TimeoutError, KvmError, OSError, WebSocketException):
            return None
        finally:
            # Closed to the end in a task of its own: this one may be being stopped (qKVM stopping), and nothing that must
            # finish is waited for there. (See close: such a task is stopped with the client.)
            closing = asyncio.ensure_future(ws.close())
            self._owed.add(closing)
            closing.add_done_callback(self._owed.discard)
            closing.add_done_callback(_looked_at)

    def _battery_soon(self) -> None:
        """Have the Fingerbot's battery asked in the background, where one is paired and it is time (FINGERBOT_BATTERY_EVERY)."""
        turn = self._fingerbot_turn
        if self._closed or self._fingerbot is not True or time.monotonic() < self._battery_next or turn.lock.locked() or turn.held() > 0:
            return
        if self._battery_task is not None and not self._battery_task.done():
            return
        self._battery_asked_at = time.monotonic()
        self._battery_next = self._battery_asked_at + FINGERBOT_BATTERY_RETRY  # (sooner once it has answered: see _read_battery)
        self._battery_task = asyncio.create_task(self._read_battery())
        self._battery_task.add_done_callback(self._battery_ended)

    async def _read_battery(self) -> None:
        async with self._fingerbot_turn.lock:
            if self._fingerbot_turn.held() > 0:
                return  # (a press with no clear answer came first: the Fingerbot may be pressing)
            try:
                # (Waited for FINGERBOT_BATTERY_WAIT, and the whole of it not much longer: a person's press waits for it.)
                waits = httpx.Timeout(FINGERBOT_BATTERY_WAIT, connect=WAITS.connect)
                resp = await self._request("GET", "/api/fingerbot/battery", vital=False, timeout=waits, within=FINGERBOT_BATTERY_WAIT + (WAITS.connect or 0.0))
                result = read_json(resp)["result"] if resp.status_code == 200 else None
            except (KvmError, ValueError, KeyError, TypeError):
                return  # (asked again after FINGERBOT_BATTERY_RETRY; what it said before stays)
        battery = battery_said(result)
        if battery is not None and self._fingerbot is True:
            self._battery = battery
            self._battery_next = time.monotonic() + FINGERBOT_BATTERY_EVERY
            self._fingerbot_words += 1  # (a look under way now would mark the tile fresh without it)
            self._status_at = 0.0

    def _battery_ended(self, task: asyncio.Task[None]) -> None:
        """An error nobody foresaw is said once a minute (as `_unexpected` says it), never left unseen."""
        if not task.cancelled() and (error := task.exception()) is not None:
            self._unexpected("asking the Fingerbot's battery failed", error)

    async def wol_targets(self) -> list[dict[str, str]]:
        """Machines the KVM has saved for Wake-on-LAN (GLKVM only)."""
        if self._glinet is False:
            return []  # (stock kvmd has no such list: asked, it says 404)
        result = await self._optional("/api/wol/list", urgent=True)
        targets = []
        devices = _dig(result, "devices")
        for entry in devices if isinstance(devices, list) else []:
            mac = as_text(_dig(entry, "mac"))
            if MAC.fullmatch(mac):
                name = plain(_dig(entry, "name")) or plain(_dig(entry, "hostname")) or plain(_dig(entry, "ip")) or ""
                targets.append({"mac": mac, "name": name})
        return targets

    # --- virtual media (0.3.0, A2): the KVM's own image storage (kvmd's MSD) ----------------------------------------
    # kvmd's mass storage drive: images in the KVM's own storage, one of them in its drive at a time, as a CD-ROM drive or a
    # USB flash drive (read-only unless the person chooses it writable). Read from kvmd's source (GL.iNet's tree, 4.16, and
    # stock kvmd's): GET /api/msd says it all (`enabled`, `online`, `busy`, `drive`, `storage`); the drive's image is chosen
    # with set_params (only while it is disconnected), and connected with set_connected; an image is written with
    # POST /api/msd/write, its length said in advance (kvmd takes it from Content-Length), `remove_incomplete=1` (what a
    # write cut off leaves is removed by kvmd itself; and by qKVM after it where kvmd did not), and removed with remove.
    # Never write_remote, nor an image by address (kvmd fetches it: a way into the network it stands in), nor read (an
    # image back off the KVM), nor set_enabled (a machine that cannot have a drive and a keyboard on one port is the
    # owner's to switch), nor GL.iNet's partition routes, some of which change things on a GET (partition_format formats).
    # What is mounted is said on the line for events the keepalive holds while the picture is watched (kvmd's `msd` event:
    # the whole state as a line opens, then what changed), and asked of /api/msd otherwise, every MSD_EVERY seconds at a look.

    @property
    def _media_key(self) -> str:
        """What MEDIA_NOTES knows this KVM by: its tile and its address."""
        return f"{self.spec.id}\0{self.spec.base_url}"

    def _media_offer(self, board: bool) -> MediaOffer | None:
        if flag(_dig(self._msd, "enabled")) is not True:
            return None  # (none found yet, or its own drive switched off in its settings: no box, and nothing asked)
        return MediaOffer(drives=("cd", "flash"), boot=(), restart=board, upload=True, where="device", writable=("flash",), delete=True)

    def media_offer(self) -> MediaOffer | None:
        return self._media_offer("reset" in self.abilities())

    @staticmethod
    def _msd_kept(state: dict[str, Any]) -> dict[str, Any]:
        """Of kvmd's state of its drive (or a part of one): what qKVM reads (MSD_KEPT), and nothing else."""
        kept = {key: state[key] for key in MSD_KEPT if key in state}
        if isinstance(storage := state.get("storage"), dict):
            kept["storage"] = {key: storage[key] for key in MSD_STORAGE_KEPT if key in storage}
        return kept

    def _msd_said(self, event: Any) -> None:
        """kvmd's `msd` event on the keepalive's line: the whole state (it has `online`), or what changed of it, merged in;
        of either, what qKVM reads alone. The tile is looked at again where what it says of the drive changed."""
        if not isinstance(event, dict):
            return
        before = self._msd
        if "online" in event or not isinstance(before, dict):
            if "online" not in event:
                return  # (a part of a state nothing is known of yet: the next whole one, or a question, says it)
            merged = self._msd_kept(event)
        else:
            said = self._msd_kept(event)
            merged = {**before, **{key: value for key, value in said.items() if key != "storage"}}
            if "storage" in said:
                storage = merged.get("storage")
                merged["storage"] = {**(storage if isinstance(storage, dict) else {}), **said["storage"]}
        self._msd, self._msd_at = merged, time.monotonic()
        self._msd_heard_at = self._msd_at
        if (_dig(before, "enabled"), _dig(before, "drive")) != (merged.get("enabled"), merged.get("drive")):
            self._status_at = 0.0  # (what the tile says of its drive changed: looked at again when next asked)

    async def _msd_asked(self, urgent: bool = False, vital: bool = True) -> dict[str, Any]:
        """kvmd's state of its drive and storage, asked now (what qKVM reads of it)."""
        state = await self._get_result("/api/msd", urgent=urgent, vital=vital)
        if not isinstance(state, dict):
            raise KvmError("bad_response", "The KVM did not say how its drive is")
        kept = self._msd_kept(state)
        self._msd, self._msd_at = kept, time.monotonic()
        return kept

    async def _msd_look(self) -> Any:
        """For a look: as the line said it of late, or as it was asked within MSD_EVERY seconds; asked otherwise."""
        heard = self._keepalive is not None and not self._keepalive.done() and time.monotonic() - self._msd_heard_at < EVENTS_QUIET
        if self._msd is not None and (heard or time.monotonic() - self._msd_at < MSD_EVERY):
            return self._msd
        try:
            return await self._msd_asked(vital=False)
        except KvmError:
            # (Asked again at the next look after the pause, not at every one: one that has none answers no differently.)
            self._msd_at = time.monotonic()
            return self._msd

    @staticmethod
    def _msd_name(name: Any) -> str | None:
        """An image's name as kvmd says it, as qKVM hands it back (DEVICE_IMAGE); None for what is no such name."""
        return name if isinstance(name, str) and DEVICE_IMAGE.fullmatch(name) else None

    def _msd_listed(self, state: Any) -> tuple[list[dict[str, Any]], int]:
        """The images of the KVM's own storage by what kvmd says, each by its kind; and how many entries were left out."""
        found = _dig(state, "storage", "images")
        images: list[dict[str, Any]] = []
        left_out = 0
        for name, about in found.items() if isinstance(found, dict) else ():
            if self._msd_name(name) is None or not isinstance(about, dict) or len(images) >= MOST_DEVICE_IMAGES:
                left_out += 1
                continue
            size = number(about.get("size"), 0, 2**50)
            partial = flag(about.get("complete")) is False
            sha = None if partial else MEDIA_NOTES.hash_of(self._media_key, name, size, number(about.get("mod_ts"), 0, 1e11))
            images.append({"id": name, "name": name, "where": None, "size": size, "partial": partial, "sha256": sha})
        images.sort(key=lambda one: one["name"].casefold())
        return images, left_out

    def _msd_stands_against(self, state: Any) -> KvmError | None:
        """What stands against a change of the KVM's drive or storage, as kvmd says it now; None where nothing does."""
        if flag(_dig(state, "enabled")) is not True:
            return KvmError("no_virtual_media", "The KVM's own drive is switched off in its own settings", 404)
        if flag(_dig(state, "online")) is not True:
            return KvmError("action_failed", "The KVM says its drive is not there just now (offline): look at it on its own page", 409)
        if flag(_dig(state, "busy")) is True:
            return KvmError("busy", "The KVM's drive is busy with something else (an upload, or its own page): try again in a moment", 409)
        if flag(_dig(state, "drive_partition", "connected")) is True:
            # (GL.iNet's File Sharing: the whole image storage open to the machine, read-write. Nothing is written beside it.)
            return KvmError("action_failed", "The KVM's File Sharing is on: its whole image storage is open to the machine, read-write. Switch it off on the KVM's own page first.", 409)
        return None

    def media_now(self) -> dict[str, Any] | None:
        msd = self._msd
        drive = _dig(msd, "drive")
        if flag(_dig(msd, "enabled")) is not True or not isinstance(drive, dict) or flag(drive.get("connected")) is not True:
            return None
        image = drive.get("image")
        raw = image.get("name") if isinstance(image, dict) else None
        name = self._msd_name(raw) or plain(raw, 200) or "an image"
        cd = flag(drive.get("cdrom")) is True
        by, at = MEDIA_NOTES.who(self._media_key, name)
        sha = MEDIA_NOTES.hash_of(self._media_key, name, number(_dig(image, "size"), 0, 2**50), number(_dig(image, "mod_ts"), 0, 1e11))
        return {
            "drive": "cd" if cd else "flash", "image": name, "name": name, "where": None,
            "read_only": cd or flag(drive.get("rw")) is not True, "first": None, "by": by, "at": at, "sha256": sha,
        }  # fmt: skip

    async def media_images(self) -> dict[str, Any]:
        state = await self._msd_asked(urgent=True)
        if flag(state.get("enabled")) is not True:
            raise KvmError("no_virtual_media", "The KVM's own drive is switched off in its own settings", 404)
        images, left_out = self._msd_listed(state)
        against = self._msd_stands_against(state)
        free, size = number(_dig(state, "storage", "parts", "", "free"), 0, 2**60), number(_dig(state, "storage", "parts", "", "size"), 0, 2**60)
        return {
            "images": images, "unseen": [], "left_out": left_out, "notes": [against.message] if against is not None else [],
            "space": {"free": free, "size": size} if free is not None and size is not None else None,
        }  # fmt: skip

    async def _msd_post(self, path: str, params: dict[str, str], what: str, still: Callable[[], bool] | None) -> None:
        """One of kvmd's changes of its drive or storage, sent once (`what`, for the words of a refusal)."""
        resp = await self._request("POST", path, urgent=True, params=params, still=still)
        if resp.status_code == 200:
            return
        try:
            detail = plain(_dig(read_json(resp), "result", "error_msg"), 200)
        except ValueError:
            detail = None
        if resp.status_code == 409:
            raise KvmError("busy", f"The KVM's drive is busy with something else: {detail or 'try again in a moment'}", 409)
        raise KvmError("action_failed", f"The KVM did not {what}: {detail}" if detail else f"The KVM did not {what} (HTTP {resp.status_code})")

    async def media_mount(self, image: str, *, drive: str, writable: bool, by: str, still: Callable[[], bool] | None = None) -> str | None:
        if drive not in ("cd", "flash") or (writable and drive != "flash"):
            raise KvmError("invalid", "A kvmd KVM takes an image as a CD-ROM drive (read-only) or as a USB flash drive", 422)
        if self._msd_name(image) is None:
            raise KvmError("invalid", "That is not an image of the KVM's that qKVM lists", 422)
        state = await self._msd_asked(urgent=True)
        if (against := self._msd_stands_against(state)) is not None:
            raise against
        found = next((one for one in self._msd_listed(state)[0] if one["id"] == image), None)
        if found is None:
            raise KvmError("changed", f"{image} is not on the KVM's own storage any more: look again.", 409)
        if found["partial"]:
            raise KvmError("changed", f"{image} is not on the KVM whole (an upload of it was cut off): delete it, or upload it again.", 409)
        if drive == "cd" and isinstance(found.get("size"), int) and (small := too_small_for_a_cd(image, found["size"], "a USB flash drive")):
            raise small
        now = self.media_now()
        if now is not None:
            if (now["image"], now["drive"], now["read_only"]) == (image, drive, not writable):
                return "It was mounted so already."
            raise KvmError("changed", f"{now['name']} is mounted on it now: unmount it first.", 409)
        # (CD-ROM: always read-only, `rw` ignored by kvmd; a USB flash drive read-only unless chosen.)
        await self._msd_post("/api/msd/set_params", {"image": image, "cdrom": "1" if drive == "cd" else "0", "rw": "1" if writable else "0"}, "choose the image", still)
        await self._msd_post("/api/msd/set_connected", {"connected": "1"}, "connect its drive", still)
        MEDIA_NOTES.mounted_by(self._media_key, image, by)
        self._status_at = 0.0
        await self._msd_asked(urgent=True)
        now = self.media_now()
        if now is None or (now["image"], now["drive"], now["read_only"]) != (image, drive, not writable):
            # Not as it was asked: another image, another kind of drive, writable where it was to be read-only. Taken out
            # again at once, where it is in, and said.
            if now is not None:
                try:
                    await self._msd_post("/api/msd/set_connected", {"connected": "0"}, "disconnect its drive", None)
                    await self._msd_asked(urgent=True)
                except KvmError as ex:
                    raise KvmError("action_failed", f"The KVM did not mount it as it was asked, and could not be told to take it out again ({ex.message}): look at it on its own page.") from None
            raise KvmError("action_failed", "The KVM did not mount it as it was asked, and it is not mounted: look at it on its own page.")
        return None

    async def media_restart(self, *, still: Callable[[], bool] | None = None) -> str | None:
        if "reset" not in self.abilities():
            raise KvmError("invalid", "This KVM has no power board to restart the machine with", 422)
        on, _ = await self._board_now(ask=True)
        action = "atx_power" if on is False else "atx_reset"
        said = "It was off, and was switched on with its power button" if action == "atx_power" else "It was restarted with its reset button"
        try:
            await self.act(action, still=still)
        except AlreadySo as so:
            said = f"{said} ({so})"
        return f"{said}: pick the KVM's drive in its boot menu where it does not start from it by itself."

    async def media_unmount(self, image: str, *, still: Callable[[], bool] | None = None) -> str | None:
        state = await self._msd_asked(urgent=True)
        if flag(state.get("enabled")) is not True:
            raise KvmError("no_virtual_media", "The KVM's own drive is switched off in its own settings", 404)
        now = self.media_now()
        if now is None:
            raise AlreadySo("nothing was mounted")
        if now["image"] != image:
            raise KvmError("changed", f"{now['name']} is mounted on it now, and not {image}: nothing was taken out. Look at it again.", 409)
        if flag(state.get("busy")) is True:
            raise KvmError("busy", "The KVM's drive is busy with something else (an upload, or its own page): try again in a moment", 409)
        await self._msd_post("/api/msd/set_connected", {"connected": "0"}, "disconnect its drive", still)
        MEDIA_NOTES.mounted.pop(self._media_key, None)
        self._status_at = 0.0
        await self._msd_asked(urgent=True)
        if self.media_now() is not None:
            raise KvmError("action_failed", "The KVM says the image is still in its drive: look at it on its own page.")
        return None

    async def media_delete(self, image: str, *, still: Callable[[], bool] | None = None) -> str | None:
        if self._msd_name(image) is None:
            raise KvmError("invalid", "That is not an image of the KVM's that qKVM lists", 422)
        state = await self._msd_asked(urgent=True)
        if (against := self._msd_stands_against(state)) is not None:
            raise against
        if not any(one["id"] == image for one in self._msd_listed(state)[0]):
            raise AlreadySo("it was not on the KVM any more")
        if (now := self.media_now()) is not None and now["image"] == image:
            raise KvmError("busy", f"{image} is mounted: unmount it first.", 409)
        await self._msd_post("/api/msd/remove", {"image": image}, "delete it", still)
        MEDIA_NOTES.forget(self._media_key, image)
        _, left = await self._msd_listing(image, LISTED_WITHIN, gone=True)  # (listed a moment longer: see LISTED_WITHIN)
        if left is not None:
            raise KvmError("action_failed", "The KVM says the image is still on its storage: look at it on its own page.")
        return None

    async def _msd_listing(self, name: str, within: float, gone: bool = False, whole_at: int | None = None) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """kvmd's state, asked again (half a second apart, for `within` seconds at most) until it lists `name` (until it no
        longer does, `gone`; until it lists it whole at `whole_at` bytes): it lists a file, and stops listing one, as its
        watch on the storage last saw it (LISTED_WITHIN), which may be mid-write. The state, and the image as it is listed
        or None. Only the first question's failure is raised: one of the later ones is asked again."""
        until = time.monotonic() + within
        state: dict[str, Any] | None = None
        listed: dict[str, Any] | None = None
        while True:
            try:
                state = await self._msd_asked(urgent=True)
            except KvmError:
                if state is None:
                    raise
            else:
                listed = next((one for one in self._msd_listed(state)[0] if one["id"] == name), None)
                if gone:
                    done = listed is None
                elif whole_at is not None:
                    done = listed is not None and not listed["partial"] and listed["size"] == whole_at
                else:
                    done = listed is not None
                if done:
                    return state, listed
            if time.monotonic() >= until:
                return state, listed
            await asyncio.sleep(0.5)

    async def media_discard(self, name: str) -> str | None:
        if self._msd_name(name) is None:
            return None
        try:
            state = await self._msd_asked(urgent=True)
            # (A write cut off is over for kvmd once it has read to the cut: it is busy with it until then, a moment.)
            until = time.monotonic() + DISCARD_WAIT
            while flag(state.get("busy")) is True and time.monotonic() < until:
                await asyncio.sleep(0.25)
                state = await self._msd_asked(urgent=True)
            state, left = await self._msd_listing(name, LISTED_FOR_A_DISCARD)
            if left is None:
                return None
            if not left["partial"]:
                # (Whole after all: an image like any other, which stays. Said so: "nothing is left" was said of it.)
                size = f" ({left['size']:,} bytes)" if isinstance(left["size"], int) else ""
                return f"It is on the KVM whole all the same{size}, and stays there: delete it there if it is not wanted."
            await self._msd_post("/api/msd/remove", {"image": name}, "delete what was written of it", None)
            _, left = await self._msd_listing(name, LISTED_WITHIN, gone=True)
        except KvmError as ex:
            return f"What was written of it may be on the KVM still ({ex.message}): delete it there."
        if left is not None:
            return "What was written of it is on the KVM still: delete it there."
        return None

    async def media_upload(self, name: str, carried: Carried, *, by: str, still: Callable[[], bool] | None = None) -> dict[str, Any]:
        if not IMAGE_NAME.fullmatch(name) or name.endswith(PARTIAL):
            raise KvmError("invalid", NAME_RULE, 422)
        state = await self._msd_asked(urgent=True)  # (signed in anew where its session ran out: the upload goes on a fresh one)
        if (against := self._msd_stands_against(state)) is not None:
            raise against
        if any(one["id"] == name for one in self._msd_listed(state)[0]):
            raise KvmError("duplicate", f"{name} is on the KVM's own storage already: delete it first, or upload it under another name.", 409)
        free = number(_dig(state, "storage", "parts", "", "free"), 0, 2**60)
        if free is not None and carried.size > free:
            raise KvmError("no_space", f"The KVM's own storage has {free:,} bytes free, and the image is {carried.size:,}: delete an image there first.", 507)
        if still is not None and not still():
            raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
        try:
            reply = await self._carry(carried, name)
        except BaseException as ex:
            # (Whatever it was: what came of it on the KVM is removed where kvmd did not remove it itself, and said.)
            if isinstance(ex, (KvmError, UploadCut, httpx.HTTPError)) and not self._closed and ex is not RETIRED:
                left = await self.media_discard(name)
                raise self._cut_said(ex, carried, left) from None
            raise
        said: Any = None
        try:
            said = read_json(reply)
        except ValueError:
            pass
        written = number(_dig(said, "result", "image", "written"), 0, 2**60)
        if reply.status_code != 200 or written != carried.size:
            left = await self.media_discard(name)
            detail = plain(_dig(said, "result", "error_msg"), 200)
            if reply.status_code == 507:
                raise KvmError("no_space", f"The KVM's own storage has not got room for it. {left or 'Nothing of it is left on the KVM.'}", 507)
            if reply.status_code in (401, 403):
                self._token = None
                raise KvmError("action_failed", f"The KVM did not take qKVM's session for the upload: try again. {left or 'Nothing of it is left on the KVM.'}")
            why = detail or (f"it says {written:,} of {carried.size:,} bytes were written" if reply.status_code == 200 else f"HTTP {reply.status_code}")
            raise KvmError("action_failed", f"The KVM did not take the image whole ({why}). {left or 'Nothing of it is left on the KVM.'}")
        # Written whole, it says: listed so a moment later (as its watch on the storage saw it last, mid-write, meanwhile).
        state, _ = await self._msd_listing(name, LISTED_WITHIN, whole_at=carried.size)
        about = _dig(state, "storage", "images", name)
        if not isinstance(about, dict) or flag(about.get("complete")) is False or number(about.get("size"), 0, 2**60) != carried.size:
            # (Never taken off: kvmd said it wrote every byte. The delta review of 0.3.0: an image written whole was
            # deleted for a listing that lagged.)
            raise KvmError("action_failed", f"The KVM said it wrote all of the image, and after {LISTED_WITHIN:.0f} seconds still does not list it whole: look at it on the KVM's own page before mounting it.")
        assert carried.sha256 is not None  # (every byte passed: kvmd said so, and the carrying said nothing else)
        MEDIA_NOTES.carried(self._media_key, name, carried.sha256, carried.size, number(about.get("mod_ts"), 0, 1e11))
        return next(one for one in self._msd_listed(state)[0] if one["id"] == name)

    def _cut_said(self, ex: BaseException, carried: Carried, left: str | None) -> KvmError:
        """What an upload that ended before its answer is said as: the sender's doing, or the device's."""
        rest = left or "Nothing of it is left on the KVM."
        if carried.cut is not None:
            return KvmError("disconnected", f"{carried.cut}. {rest}", 400)
        if isinstance(ex, httpx.HTTPError):
            ex = _transport_error(ex, self.spec.tls)
        if isinstance(ex, KvmError):
            return KvmError(ex.code if ex.code in ("timeout", "dropped", "unreachable", "stopped") else "action_failed", f"The upload did not get through to the KVM ({ex.message}). {rest}", ex.status)
        return KvmError("action_failed", f"The upload did not get through to the KVM. {rest}")

    async def _carry(self, carried: Carried, name: str) -> httpx.Response:
        """POST /api/msd/write with the image as its body, its length said, on a connection of its own (closed after it,
        whatever comes: a long upload cut off is no state for the connections every look uses), a piece at a time."""
        await self._http()  # (how the certificate is checked is settled there)
        token = self._token or await self._login()
        verify = self._tls if self._tls is not None else await system_context()
        async with httpx.AsyncClient(base_url=self.spec.base_url, verify=verify, timeout=UPLOAD_WAITS, trust_env=False) as client:
            request = client.build_request(
                "POST", "/api/msd/write", params={"image": name, "remove_incomplete": "1"},
                headers={"Cookie": f"auth_token={token}", "Content-Length": str(carried.size), "Content-Type": "application/octet-stream"},
                content=carried,
            )  # fmt: skip
            return await self._send(client, request, MAX_REPLY, UPLOAD_MOST)

    # --- status -------------------------------------------------------------

    async def _read_about(self) -> dict[str, Any]:
        # (Asked again sooner while its answer said neither family: one error of the moment is not ten minutes of not knowing.)
        if not self._about or time.monotonic() - self._about_at > (ABOUT_TTL if self._glinet is not None else ABOUT_RETRY):
            version = await self._glinet_version(vital=False)  # (stock kvmd's is read from /api/info, at every look: see _read_status)
            self._about = {"model": plain(_dig(version, "model"), 40), "version": plain(_dig(version, "version"), 40)}
            self._about_at = time.monotonic()
        return self._about

    async def _read_ports(self) -> dict[str, Any] | None:
        """The inputs of a multi-port KVM and which one is on screen; None for an ordinary one."""
        if self._single_port_at is not None and time.monotonic() - self._single_port_at < ABOUT_TTL:
            return None  # it said so recently: don't ask every few seconds
        ports = _ports_from(await self._optional("/api/switch", vital=False))
        self._single_port_at = time.monotonic() if ports is None else None
        return ports

    async def _refresh_status(self) -> None:
        # A word of the board on its line that comes while a look is under way may come after the look read the board,
        # and the look's end would mark the tile fresh with what was said before it: until the next look, four seconds
        # on, or fifteen for the alerts. Looked at again when next asked, then.
        words = self._board_words, self._fingerbot_words
        await super()._refresh_status()
        if (self._board_words, self._fingerbot_words) != words:
            self._status_at = 0.0

    async def _board_word(self) -> Any:
        """What the power board says, for a look: as the keepalive's line said it last, where that line is held, was heard
        from of late and says the board is there; asked otherwise. A Comet's line says "no board" while the board answers
        somebody else's questions at /api/atx (a real one, for as long as two others asked), which says nothing of the board:
        then it is asked here as well, and may answer this asker (and where it says "no board" too, see BOARD_KEPT)."""
        heard = self._board_heard()
        if heard is not None and flag(heard.get("enabled")) is True:
            return heard
        return await self._get_result("/api/atx", vital=False)

    async def _read_status(self) -> dict[str, Any]:
        try:
            streamer = await self._get_result("/api/streamer")
        except KvmError as ex:
            if ex.code in ("auth_failed", "no_password", "no_sign_in"):
                ex = await self._gone_meanwhile("/api/auth/check") or ex
            if ex.code in ("auth_failed", "no_password"):
                state = "auth"
            elif ex.code == "no_sign_in":
                state = "error"  # it is there, and something is wrong with it: not "offline", which an alert would report as gone
            elif ex.code in ("cert_mismatch", "cert_invalid"):
                state = "error"
            else:
                state = "offline"
            return {"state": state, "error": ex.as_dict()}

        # The device is there: it has just answered. Whether each of these details arrives changes what
        # the tile can tell, not whether the device counts as down (which would take its picture away).
        info, hid, atx, about, ports, _ = await asyncio.gather(
            self._get_result("/api/info", vital=False),
            self._get_result("/api/hid", vital=False),
            self._board_word(),
            self._read_about(),
            self._read_ports(),
            self._msd_look(),  # (its drive: what is mounted, and whether it has one: `media`)
            return_exceptions=True,
        )
        source = _dig(streamer, "streamer", "source")
        signal = _dig(streamer, "streamer", "hdmi", "signal")  # GLKVM only
        if signal is None:
            signal = _dig(source, "online")  # None while the streamer is stopped
        health = _dig(info, "health") or _dig(info, "hw", "health")  # GLKVM / stock PiKVM
        width = number(_dig(source, "resolution", "width"), 1, 100_000)
        self._source_width = width if isinstance(width, int) else None
        signal = flag(signal)
        # The power board, and what it says of the computer: only from an answer in which it says it is there. One that
        # says it is not, or that did not come, from a KVM whose board was there a moment ago leaves the buttons where
        # they are and keeps what the board said last of the computer, for a while (a Comet's board says "none" and
        # "off" to whoever asks while it answers somebody else).
        board = flag(_dig(atx, "enabled")) is True
        now = time.monotonic()
        started = False  # the board saw the computer come on since the last look
        if board:
            said = power_said(atx)
            started = said is True and self._power_seen[1] is False
            self._board_at, self._power_seen = now, (now, said)
        has_atx = board or (self._board_at is not None and now - self._board_at < BOARD_KEPT)
        power = self._power_seen[1] if has_atx and now - self._power_seen[0] < POWER_KEPT else None
        keyboard, mouse = flag(_dig(hid, "keyboard", "online")), flag(_dig(hid, "mouse", "online"))
        active = ports.get("active") if isinstance(ports, dict) else None
        if active is not None and active != self._port_seen:
            # Another computer is on screen than at the last look. A multi-port KVM goes on saying "no keyboard"
            # after that until a key has been sent (a real Comet X did, for minutes, and found it at the first
            # Shift): that is not knowing, and is told as not knowing, not as a cable that is out.
            self._usb_unsure = self._port_seen is not None
            self._port_seen = active
        if started:
            # So does a Comet after the computer behind it came on: "no keyboard" until the first key (a real one,
            # 2026-10-14, at the computer's sign-in screen; the first Shift found it).
            self._usb_unsure = True
        if keyboard is True:
            self._usb_unsure = False
        elif self._usb_unsure:
            keyboard = mouse = None
        has_ports = isinstance(ports, dict)
        if self._glinet is False:
            about = _stock_about(info)  # (stock kvmd says what it is in /api/info, which is read anyway)
        if isinstance(hid, dict):
            # Stock kvmd says whether keep-awake is enabled in its settings. Where it is not, switching it on is answered
            # with a yes, and nothing is switched. (Only a plain false says so: anything else is no answer.)
            self._jiggler_off = flag(_dig(hid, "jiggler", "enabled")) is False
            self._mouse_absolute = flag(_dig(hid, "mouse", "absolute"))
        glinet = self._glinet is not False  # (as `act` has it: refused only where the KVM said it has no such thing)
        fingerbot = self._fingerbot is True and glinet  # (as the KVM said last on a line to its events: see _heard_on_the_line)
        if fingerbot:
            self._battery_soon()
        return {
            "state": "no_signal" if signal is False else "online",
            "error": None,
            # What this one can be asked, beside what every KVM can: Wake-on-LAN and its own restart unless it said it has not got
            # GL.iNet's routes for them, the power and reset buttons where it has a power board, and another input where it has several.
            "can": can_do(
                *(word for word in self.can if not (word == "jiggler" and self._jiggler_off)),
                "wol" if glinet else None, "reboot" if glinet else None,
                "power" if has_atx else None, "reset" if has_atx else None, "ports" if has_ports else None,
                "fingerbot" if fingerbot else None, "media" if self._media_offer(has_atx) is not None else None,
            ),
            "video": {
                "signal": signal,
                "width": width,
                "height": number(_dig(source, "resolution", "height"), 1, 100_000),
                "fps": number(_dig(source, "captured_fps"), 0, 1000),
            },
            "usb": {"keyboard": keyboard, "mouse": mouse},
            "atx": {
                "enabled": has_atx,
                "power": power,
                "hdd": flag(_dig(atx, "leds", "hdd")) if board else None,
            },
            # A Fingerbot paired with the KVM, which presses the power button (`fingerbot` in `can`): its battery in percent
            # (null until it was asked, or where it was no number), and whether that is low. Null without one. It says
            # nothing of the computer's power.
            "fingerbot": {"battery": self._battery, "low": None if self._battery is None else self._battery < FINGERBOT_LOW} if fingerbot else None,
            "health": {
                "temp": number(_dig(health, "temp", "cpu"), -100, 300),
                "cpu": number(_dig(health, "cpu", "percent"), 0, 100),
                "mem": number(_dig(health, "mem", "percent"), 0, 100),
            },
            "about": {"model": _dig(about, "model"), "version": _dig(about, "version")},
            "ports": ports if has_ports else None,
            "media": self.media_now(),  # what is in its drive (said to everybody who sees the tile)
        }
