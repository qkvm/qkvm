"""Client for a server's management controller (BMC), over Redfish.

Redfish is the interface such controllers share: AMI MegaRAC (ASRock Rack, Gigabyte and
many more), Dell iDRAC, HPE iLO, Supermicro, Lenovo XCC and OpenBMC all speak it. What it
gives the wall is whether the server is on, how it is doing (health, temperatures, fans),
and its power button.

What it does not give is a picture of the screen: the standard has none, and the consoles
the vendors build on top each speak a protocol of their own. Where that protocol is one qKVM
reads (AMI's, see ami.py), the console is held open while the wall is watched and the tile
shows the server's screen. Elsewhere a server's tile shows its state instead, and "Open
console" leads to the controller's own page.

Nothing here assumes where a controller keeps things. It starts at the root and follows
the links the controller gives, and every one of those is checked before it is followed:
a link is only ever a path below /redfish/v1 on the controller itself, never an address
somewhere else that the session token could be carried to.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import re
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any
import hashlib
from urllib.parse import unquote, urlsplit

import httpx
from websockets.exceptions import ConnectionClosed, InvalidStatus, WebSocketException

from . import ami
from .aspeed import Garbled, Screen
from .kvm import (
    ABOUT_RETRY,
    ABOUT_TTL,
    DOWN_CODES,
    FULL,
    KEYS,
    MAX_TEXT,
    TIERS,
    AlreadySo,
    LOGIN_RETRY,
    MAX_REPLY,
    NO_SAID,
    REJECTED,
    RETIRED,
    TOKEN,
    Device,
    DeviceSpec,
    KvmError,
    Listening,
    Snapshot,
    _dig,
    _transport_error,
    as_text,
    bounded,
    can_do,
    not_signing_in,
    number,
    plain,
    read_json,
    share_window,
    sign_in_waits,
    stopped,
    tier_for,
    went_out,
    ws_connect,
    ws_error,
)

if TYPE_CHECKING:
    from .openbmc import OpenBmcScreen  # (made where it is needed: it is a VNC reader's, and that reader uses this file)

log = logging.getLogger("qkvm")

ROOT = "/redfish/v1/"
SESSIONS = "/redfish/v1/SessionService/Sessions"  # where the standard puts signing in
MAX_SENSORS = 40  # temperatures and fans of one server the wall will list
# In the newer shape of the sensors every fan is a read of its own, each bounded like any other. Forty of them
# answered a byte at a time by a controller that means it would hold one look for twenty minutes, the tile saying
# the look before all the while and the server never counting as down. So the sensors get this much of one look:
# once it is up no further fan is asked for, and a fan not asked for is not listed.
SENSORS_WITHIN = 15.0
# Where a controller does not say its firmware's version in its own resource, its firmware inventory is read for it:
# where it lists no more than so many pieces of software (some list dozens), within so many seconds, each read bounded.
MOST_IMAGES = 16
IMAGES_WITHIN = 10.0
LOOK_EVERY = 10.0  # seconds between looks at a server: its controller is a small computer, and a server's state changes slowly
# A controller says "accepted" and does what was asked a little later: five seconds, on the board this was
# measured on. So after something was done to a server it is looked at again at these moments (seconds
# after), instead of the tile saying the old thing until its next turn comes round.
FOLLOW_UP = (2.0, 4.0, 6.0, 8.0, 11.0, 15.0)
# A controller is a small computer with moments of its own. A real one, perfectly well, let a request
# time out now and then, and answered nonsense for twenty-odd seconds at a stretch while its server shut
# down. So a look that fails does not change what the tile says until the last good one is this old;
# meanwhile the server is looked at again after RETRY_LOOK seconds rather than when its turn comes.
HICCUP = 45.0
# A critical fault that has gone away is still the tile's state for this long. One sensor at its limit makes
# a controller call itself Critical and Warning by turns, every few seconds (a real board did, over a fan):
# that is one problem to be told of once, and over when it has stayed away, not a new one every time.
FAULT_HOLD = 300.0
RETRY_LOOK = 4.0
# "Accepted" is not "done": a real controller took a command to cut the power, answered "accepted", and
# left the server running. Where it can be seen whether a command was carried out (on, off), it is
# looked for, this long and this often, before anybody is told that it was.
CONFIRM_WITHIN = 25.0
CONFIRM_EVERY = 2.0
# Signing out is a courtesy, and removing a server waits for it. A real controller took a second over it,
# so it gets a few, counted for the whole exchange: one that answers a byte at a time is not waited out.
SIGN_OUT = httpx.Timeout(4.0, connect=1.5, pool=0.5)
SIGN_OUT_WITHIN = 5.0
# A management controller is a small, often slow computer. An older board (a Gigabyte, AMI's firmware) took nine to
# twelve seconds to show the root of its Redfish service, and four to seven to show its computer, after a quiet
# period as at any other time; with the default eight-second read it timed out, the one who added it was told "did
# not respond in time", and the tile fell offline and came back by turns. So this driver waits longer for each piece
# of an answer (the connect timeout is unchanged, so a controller that is simply not there is still found at once).
BMC_WAITS = httpx.Timeout(20.0, connect=4.0, pool=8.0)
# Start into BIOS setup: that board answered the change of its boot override after 19.8 seconds (all but the 20 above),
# and left reads of the computer unanswered for about a minute after it. That change, the restart after it, and the
# read and change that clear it again wait this long for their answer: one given up on leaves an override that may be
# set, with nothing restarted.
BOOT_WAITS = httpx.Timeout(60.0, connect=4.0, pool=8.0)
# The service root read before a sign-in (see RedfishDevice._same_controller): that board answered it without a sign-in in
# 12 to 20.5 seconds (2026-10-19), against the 20 s of a look's read; given up on, no sign-in goes at all and the tile goes
# offline. So it is given this many times a look's read (40 s, twice the longest seen).
ROOT_WAIT_TIMES = 2.0
# ...and so a server switched on into its setup is waited for that minute after the change, and CONFIRM_WITHIN beyond it,
# before it is said not to have come on: with CONFIRM_WITHIN alone, every read of it fell into the busy minute.
BOOT_BUSY = 60.0

NO_PICTURE = KvmError("no_picture", "A management controller has no picture of the screen", 404)

# --- the server's screen ---------------------------------------------------------------------------------
# A controller with AMI's firmware has the screen in the console its own web page opens. While somebody
# looks at the wall that console is held open, which takes one of the controller's console seats (it has
# two, as a rule); when nobody has asked for the picture for a while, it is closed and the seat given back.
CONSOLE_IDLE = 20.0  # seconds without anybody asking for the picture, after which the console is closed
CONSOLE_QUIET = 40.0  # the controller has said nothing for this long: the connection is taken to be dead
# After the console could not be had (its seats taken, a connection lost), before it is asked for again: longer
# every time, because a controller is a small computer, and a real one was not well for some seconds after
# every console that came and went.
CONSOLE_RETRY = (30.0, 60.0, 120.0, 300.0)
CONSOLE_GIVE_UP = 600.0  # ...and after something that asking again does not change (how it is set up, what it sends)
CONSOLE_HELD = 600.0  # ...and while somebody is using the console: every look puts a question on their screen for a moment
STANDING = ("no_picture", "console_held")  # what is said on the tile until then, in place of asking every few seconds
WHO = 512  # who is asking for the console, as the controller names them: more than this is not a name, and is not said back
CONSOLE_OPENING = 12.0
# A controller ends a console session in which no key was pressed for a while (half an hour, on real boards),
# and a wall that only looks presses none. A session that ran at least this long before it was told so has simply run its
# time, and is opened again at once; one that is ended sooner is a console that cannot be had.
CONSOLE_SETTLED = 60.0
CONSOLE_SAY = 10.0  # what is said to a console is taken within this, or the controller has stopped listening
INPUT_WAIT = 12.0  # seconds keys or the pointer wait for the console to be open and held before they give up
# The question which server answers, before the console's own sign-in: asked this many times, this many seconds apart, where
# the controller answers it with one of its moments (see `_hold_console`).
QUESTION_TRIES = 3
QUESTION_AGAIN = 1.0
# A console whose pass was taken but that was not told "the console is yours" within this long is held by another
# session (one whose holder may come back, say): qKVM shows its screen and types nothing into it.
MASTER_WAIT = 3.0
# A first console session (the controller says so with its answer to the pass) has the virtual keyboard and mouse
# attached to the server as it begins, and a real board dropped a key sent a moment after: the controller's own
# viewer takes no key for its first five seconds then. Nor does qKVM.
HID_SETTLE = 5.0
INPUT_SAY = 2.0  # seconds a key or the pointer has to go out over the console (the console's own answers have CONSOLE_SAY)
LET_GO_WITHIN = 4.0  # seconds a letting go that is owed (a typing cut off with a key down) has to go out
KEY_PAUSE = 0.004  # seconds between the reports of a typed text (as a JetKVM is typed at)
HOLD = 0.05  # seconds the keys of a combination (Ctrl+Alt+Del, a saved one) are held down before they are let go
TYPE_ASK_EVERY = 25  # keys typed before it is asked again whether whoever asked for it may still do that


def handed_over() -> KvmError:
    """What keys and the pointer are told once the console was given to somebody at the controller's own page."""
    return KvmError("in_use", "Somebody at the server's own console has its keyboard and mouse now", 409)
# OpenBMC's console (openbmc.py): the most one of its messages may be (bmcweb hands obmc-ikvm's bytes on 50 KB at a
# time), and how long a picture or a live line waits for it to be open.
OPENBMC_MOST = 1024 * 1024
OPENBMC_WAIT = 10.0
SIGN_IN_OWED = 1.8  # a sign-in under way when the device is retired is waited for this long, to sign out of it again
LET_IN_AT_MOST = 8  # times in one session that somebody asking for the console is let in: a person asks once
# Frames are read by these threads and no others. Reading is done in Python, and a screen that changes all over
# takes seconds: on the threads that check passwords and write the settings, a few busy screens (or a
# controller that means it) would keep people from signing in. Two at a time, the rest wait their turn.
_READERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="screen")
UNREADABLE = 3  # this many frames in a row that cannot be read, and it is not a picture qKVM reads
QUANTIZER = {"480": 3, "640": 3, "960": 2, FULL: 2}  # JPEG strength by size, as for the other pictures made here
# What a controller may hand out to be sent back to it in a header (a session, its token): what a cookie may be
# made of, which is nothing that could end the header line or begin another.
HANDED = re.compile(r"[!#-+\--:<-\[\]-~]{1,512}")
CONSOLE_PASS = re.compile(r"[!-~]{1,128}")  # (this one travels in a message of the console's own, not in a header)
PASS_REFUSED = {
    0: "its console did not accept the pass it had given out",
    2: "this user is not allowed to use its console",
    3: "its console did not accept what qKVM said of itself",
    8: "its console does not know the session any more",
}


def screen_jpeg(width: int, height: int, screen: bytearray, target: int | None, quantizer: int) -> bytes:
    """A screen of three bytes a pixel as a JPEG, shrunk to `target` pixels wide when that is smaller.

    `screen` is the one frames are being read into: it is copied here, in the thread this runs in (megabytes,
    and not on the thread that serves every browser). ValueError: it is not a screen of that size.
    """
    import av

    from .jetkvm import encode_jpeg

    rgb = bytes(screen)
    if len(rgb) != 3 * width * height:
        raise ValueError("not a screen of that size")
    frame = av.VideoFrame(width, height, "rgb24")
    plane = frame.planes[0]
    row = 3 * width
    if plane.line_size == row:
        plane.update(rgb)
    else:  # the library keeps each row a little longer than it is
        padded = bytearray(plane.line_size * height)
        for y in range(height):
            padded[y * plane.line_size : y * plane.line_size + row] = rgb[y * row : (y + 1) * row]
        plane.update(bytes(padded))
    return encode_jpeg(frame, target, quantizer)


class _Console:
    """One console session with a controller, and the server's screen as it has arrived over it."""

    def __init__(self) -> None:
        self.screen = Screen()
        self.frames = 0  # how many have been read: a JPEG made at an earlier count is not the latest picture
        self.since = 0.0  # when the first of them was (time.monotonic())
        self.done = asyncio.Event()
        self.error: KvmError | None = None
        self.encoded: dict[str, tuple[int, Snapshot]] = {}
        self.heard: list[str] = []  # the first things the controller said, for the log when no picture comes of it
# What a board says where nobody filled in its name.
PLACEHOLDER = re.compile(r"\s*(to be filled by o\.?e\.?m\.?|default string|system product name|not specified|n/?a|unknown)?\s*", re.IGNORECASE)
PATH = re.compile(r"/redfish/v1(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*/?")
NUMBER = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}")
# The way into its own console that a controller hands out: a page on itself and a pass, nothing else.
CONSOLE = re.compile(r"(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+\?[A-Za-z0-9._~%&=+-]{1,512}")
# The mark a controller puts on the state of a thing, to be shown again by whoever changes that thing.
ETAG = re.compile(r'(W/)?"[\x21\x23-\x7e]{0,128}"')


def listed(value: Any) -> list[Any]:
    """What a controller sent where a list belongs: the list, or none. (A number there, or a yes, is not gone through.)"""
    return value if isinstance(value, list) else []


def said_yes(value: Any) -> bool:
    """Whether a controller's word for a setting is not a plain no.

    Asked of the two words for "the server's own monitor goes dark while a console is open". A real board
    says 0 or 1. Said some other way (true, 1.0, "on"), or as something that cannot be read at all, it is
    not taken for a no: the console is the thing to leave alone when in doubt. Not said at all is a no.
    """
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "off", "no", "disabled")
    return True


def link(value: Any) -> str | None:
    """A place on the controller that it points to itself, or None for anything else it may claim."""
    if not isinstance(value, str) or len(value) > 300 or not PATH.fullmatch(value):
        return None
    # And no way back up out of /redfish/v1, however it is spelt: the request would be sent to where that leads.
    spelt_out = unquote(value)
    if "\\" in spelt_out or spelt_out.count("/") != value.count("/") or any(part in (".", "..") for part in spelt_out.split("/")):
        return None
    return value


def locator(system: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None, dict[str, Any] | None]:
    """The light that helps to find a server in a rack: (whether it is on, what switches it on, what switches it off).

    All None where the controller has none. Newer controllers have a plain on and off for it. Older ones have
    a light with states, and do not agree on what they mean: on most, "Off" is off, and "Lit" and "Blinking"
    both say that somebody is looking for the machine. Where there is no "Off" to choose, "Lit" is the light
    at rest and only "Blinking" calls for attention.

    Where there is a choice, the light is lit rather than set blinking. On a real board (Gigabyte, AMI's
    controller) a light told to blink was out again within twenty seconds: it is the timed "identify" of
    old, and no use to somebody who first has to walk to the rack.
    """
    active = system.get("LocationIndicatorActive")
    if isinstance(active, bool):
        return active, {"LocationIndicatorActive": True}, {"LocationIndicatorActive": False}
    state, offered = system.get("IndicatorLED"), system.get("IndicatorLED@Redfish.AllowableValues")
    offered = [kind for kind in offered if isinstance(kind, str)] if isinstance(offered, list) else ["Lit", "Blinking", "Off"]
    off = "Off" if "Off" in offered else "Lit"
    on = next((kind for kind in ("Lit", "Blinking") if kind in offered and kind != off), None)
    if state not in ("Lit", "Blinking", "Off") or on is None or off not in offered:
        return None, None, None
    return state != off, {"IndicatorLED": on}, {"IndicatorLED": off}


def boot_targets(system: dict[str, Any]) -> list[str]:
    """Which one-time boot targets the controller says it allows (Boot.BootSourceOverrideTarget@Redfish.AllowableValues);
    [] where it says none. "BiosSetup" among them means "Start into BIOS setup" can be offered for this board."""
    offered = _dig(system, "Boot", "BootSourceOverrideTarget@Redfish.AllowableValues")
    return [target for target in listed(offered) if isinstance(target, str)]


SETUP_OVERRIDE = ("once", "biossetup")  # what Start into BIOS setup sets, as `boot_override` says it
SETUP_CHANGE = {"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "BiosSetup"}}
NOT_CLEARED = "the BIOS setup boot override may be set and could not be cleared, so the next boot may land in the BIOS setup"
SET_BEFORE = "the BIOS setup boot override was set already before this press, and is left set as it was, so the next boot will land in the BIOS setup"
# Where the clearing found the override off and went out before a change of the press's that the controller accepted
# (or whose answer was lost): the clearing cannot undo what comes after it.
CLEARED_LATE = "it showed off and was cleared; should the controller still make the change it accepted, the next boot will land in the BIOS setup"
# What tells that a request never went out (nothing it would change was changed): anything else after it was sent may
# have been done (a timeout, a broken answer, an answer that could not be read, an address it was sent on to that is none).
NOT_SENT = frozenset({"unreachable", "stopped", "cert_mismatch", "cert_invalid", "no_sign_in", "auth_failed", "no_password", "another_machine"})
# A Start into BIOS setup that has not come to its restart within this many seconds goes no further: nothing is
# restarted, and the override is cleared again (whoever pressed may have stopped waiting; the page waits four minutes
# for this press, SETUP_PATIENCE in app.js). Nothing under way is cut off for it: a request is waited out within its own
# time (BOOT_WAITS), and a clearing goes to its end. The real board took 36 s over the change and the restart together.
SETUP_WITHIN = 120.0


def took_too_long() -> str:
    return f"the controller took more than {SETUP_WITHIN:.0f} seconds"


class SetupSteps:
    """How far one Start into BIOS setup came: "looking" (nothing sent that changes anything), "setting" (the override may
    be set), "clearing" (being set back), "restarting" (the power change may have gone), "waiting" (switched on, not yet
    seen on); and until when it may go on to its restart (SETUP_WITHIN)."""

    def __init__(self) -> None:
        self.at = "looking"
        self.until = time.monotonic() + SETUP_WITHIN
        self.changed_at: float | None = None  # when the controller answered the change of the boot override with a yes

    def overdue(self) -> bool:
        return time.monotonic() >= self.until


def boot_override(system: Any) -> tuple[str, str]:
    """The boot override as it stands: (enabled, target), in small letters ("" where not said). Compared without regard to
    case: a controller that writes "ONCE" or "biossetup" means what the standard's "Once" and "BiosSetup" mean."""
    boot = _dig(system, "Boot")
    said = (plain(_dig(boot, "BootSourceOverrideEnabled"), 30), plain(_dig(boot, "BootSourceOverrideTarget"), 30))
    return (said[0] or "").lower(), (said[1] or "").lower()


def own_number(system: dict[str, Any]) -> str | None:
    """The number a server gives for itself, as a mark to know it by; None where it gives none worth the name.

    Only ever compared with another: it is kept as a digest, since the number itself is nobody's business.
    Boards whose maker never set one answer all zeros, or all F: that is no number, and many boards have it.
    """
    digest = _digest(system.get("UUID"))
    return None if digest is None else "server:" + digest


def controller_number(root: Any) -> str | None:
    """The number a controller's Redfish service gives for itself in its service root (its `UUID`, which anybody may read),
    as 32 hex digits of a digest; None where it gives none worth the name. On a real AMI board it is the controller's own
    (the same as its manager's UUID), not the computer's; bmcweb (OpenBMC) gives one it made on its first start."""
    return _digest(root.get("UUID")) if isinstance(root, dict) else None


def _digest(number: Any) -> str | None:
    if not isinstance(number, str) or not NUMBER.fullmatch(number) or len(set(number.replace("-", "").lower())) < 4:
        return None
    return hashlib.sha256(number.lower().encode()).hexdigest()[:32]


# The server a tile was added for, as it is remembered (DeviceSpec.machine): "server:" and the 32 hex digits of the computer's
# number (`own_number`), then, where the controller's service root says one, the 32 of the controller's (`controller_number`).
# A computer that gave no number when the tile was added, behind a controller that did, is remembered as SAID_NONE (no
# digest is 32 zeros): such a server is known by its controller's number alone.
SERVER_MARK = len("server:") + 32
SAID_NONE = "server:" + "0" * 32


def marks_of(machine: str) -> tuple[str, str | None]:
    """(the computer's mark, the controller's or None) as remembered; ("", None) where nothing is. What is not of the
    server's shape (a tile whose kind was changed) is taken whole for the computer's: no number a server gives equals it."""
    if machine.startswith("server:") and len(machine) == SERVER_MARK + 32:
        return machine[:SERVER_MARK], machine[SERVER_MARK:]
    return machine, None


# What a tile says, and a button, a key or its console is answered with, where the server at its address is not the one it
# was added for (see RedfishDevice._judge and `_same_controller`).
ANOTHER_SERVER = (
    "Another server answers at this address: it gives another number for itself (its UUID) than the server this tile was "
    "added for. Nothing is done to it: no power command, no key, no console. If it is this tile's server now, edit the tile and type its password."
)
NO_SERVER_NUMBER = (
    "The server at this address does not say which it is (its UUID), and the server this tile was added for did. Nothing "
    "is done to it: no power command, no key, no console. If it is this tile's server now, edit the tile and type its password."
)
ANOTHER_CONTROLLER = (
    "Another server answers at this address: its controller gives another number for itself (the UUID of its Redfish "
    "service) than the one this tile was added for, so it was not sent the password, and nothing is done to it. If it is "
    "this tile's server now (another board, or its controller set back to its factory settings), edit the tile and type its password."
)
NO_CONTROLLER_NUMBER = (
    "The controller at this address does not say which it is (the UUID of its Redfish service), and the one this tile was "
    "added for did, so it was not sent the password, and nothing is done to it. If it is this tile's server now, edit the tile and type its password."
)
# Times a command asks again which server answers, where the controller signed this program in anew since it last did (see
# RedfishDevice._request): another server at the address does not know the session the question was answered under.
MOST_ASKED = 3
CONTROLLER_SESSIONS = 4  # the last sessions signed in after the controller's number was compared, kept (see RedfishDevice._judge)


class NothingSent(KvmError):
    """A command that never went out: what had to be asked first (which server answers) could not be had."""


def never_sent(ex: KvmError) -> bool:
    """Whether a command's error says that it never went out (nothing it would change was changed)."""
    return ex is not RETIRED and (ex.code in NOT_SENT or isinstance(ex, NothingSent))


def named(*values: Any) -> str | None:
    """The first of `values` that is a real name and not what a board says when nobody filled it in."""
    for value in values:
        text = plain(value, 60)
        if text and not PLACEHOLDER.fullmatch(text):
            return text
    return None


# --- the sensors, in the two shapes Redfish has for them --------------------------------------------------
# The older shape is one resource, Thermal, with every temperature and every fan in it: what AMI's boards,
# iDRAC and iLO give. The newer one (ThermalSubsystem, since Redfish 2020.4) spreads them out: the temperatures
# are readings in ThermalMetrics, each pointing at a sensor of its own, and the fans are a collection, one
# resource each. OpenBMC gives only the newer one (bmcweb left Thermal out in 2026); the others give both.


def temperatures_of(thermal: dict[str, Any]) -> list[dict[str, Any]]:
    """Every temperature in a Thermal resource, by kind: a name, a reading within reason, and whether it is well."""
    return [
        {"name": plain(entry.get("Name"), 40) or "", "celsius": reading, "ok": _dig(entry, "Status", "Health") in (None, "OK")}
        for entry in listed(thermal.get("Temperatures"))[:MAX_SENSORS]
        if isinstance(entry, dict) and (reading := number(entry.get("ReadingCelsius"), -100, 300)) is not None
    ]


def fans_of(thermal: dict[str, Any]) -> list[dict[str, Any]]:
    """Every fan in a Thermal resource that is fitted (one that is not is not a fan), by kind."""
    return [
        {
            "name": plain(entry.get("Name"), 40) or "",
            "reading": number(entry.get("Reading"), 0, 1_000_000),
            "unit": "%" if entry.get("ReadingUnits") == "Percent" else "RPM",
            "ok": _dig(entry, "Status", "Health") in (None, "OK"),
        }
        for entry in listed(thermal.get("Fans"))[:MAX_SENSORS]
        if isinstance(entry, dict) and _dig(entry, "Status", "State") == "Enabled"
    ]


def readings_of(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Every temperature in a ThermalMetrics resource, by kind.

    A reading is named after its device where the controller names one, else after the sensor it points to
    (the last part of its address, which is a place on the controller or nothing). Its health is taken as
    in the older shape where the controller says it with the reading; the standard's excerpt carries none
    (the sensor itself would have to be read for it, and is not), and a reading without one is well.
    """
    found = []
    for entry in listed(metrics.get("TemperatureReadingsCelsius"))[:MAX_SENSORS]:
        if not isinstance(entry, dict) or (reading := number(entry.get("Reading"), -100, 300)) is None:
            continue
        source = link(entry.get("DataSourceUri"))
        name = plain(entry.get("DeviceName"), 40) or (plain(source.rstrip("/").rsplit("/", 1)[-1], 40) if source else None) or ""
        found.append({"name": name, "celsius": reading, "ok": _dig(entry, "Status", "Health") in (None, "OK")})
    return found


def fan_of(fan: Any) -> dict[str, Any] | None:
    """One fan of a Fans collection, by kind; None where it is not a fan that is fitted.

    Its speed is said as revolutions (SpeedRPM), as a share of its most (Reading, in percent), or both:
    revolutions where they are a number, which is what the older shape gives for the same fan; else the
    share where that is one; else no reading, in revolutions where those were said at all, and otherwise
    as the share that the resource (SpeedPercent) is by its name.
    """
    if not isinstance(fan, dict) or _dig(fan, "Status", "State") != "Enabled":
        return None
    speed = fan.get("SpeedPercent")
    if not isinstance(speed, dict):
        return None
    revolutions, share = number(speed.get("SpeedRPM"), 0, 1_000_000), number(speed.get("Reading"), 0, 100)
    in_revolutions = revolutions is not None or (share is None and "SpeedRPM" in speed)
    return {
        "name": plain(fan.get("Name"), 40) or "",
        "reading": revolutions if in_revolutions else share,
        "unit": "RPM" if in_revolutions else "%",
        "ok": _dig(fan, "Status", "Health") in (None, "OK"),
    }


def rfb_console(manager: dict[str, Any]) -> str | None:
    """Where a controller running OpenBMC carries its console, for a reader of that to come; None for any other.

    bmcweb's console is a WebSocket on the controller, `/kvm/0`, carrying RFB (the protocol of VNC) with a
    bmcweb session; it is there when bmcweb was built with its KVM, which its manager then announces as a
    graphical console of the KVM-over-IP kind. bmcweb names no maker at its root: it is known by its manager,
    whose model it hard-codes as "OpenBmc" and whose OEM part is called the same. Nothing is read from the
    console here.
    """
    console = manager.get("GraphicalConsole")
    if is_openbmc(manager) and _dig(console, "ServiceEnabled") is True and "KVMIP" in listed(_dig(console, "ConnectTypesSupported")):
        return "/kvm/0"
    return None


def is_openbmc(manager: dict[str, Any]) -> bool:
    """Whether a controller's own resource says it runs OpenBMC: bmcweb hard-codes its model as "OpenBmc", and calls its OEM part the same."""
    return manager.get("Model") == "OpenBmc" or isinstance(_dig(manager, "Oem", "OpenBmc"), dict)


class RedfishDevice(Device):
    """A server's management controller, over Redfish."""

    kind = "redfish"
    picture = False
    WAITS = BMC_WAITS  # a management controller is slow to answer; see BMC_WAITS
    # Every server: the power and reset buttons, switching on or asking it to shut down by what is wanted, and
    # the controller's own restart. A look adds its screen, a signed-in way into its console, and the light to
    # find it by, where the controller has them. (The controller may still refuse one it is not set up for.)
    can = ("power", "reset", "power_state", "reboot")

    def __init__(self, spec: DeviceSpec, on_pin: Any = None) -> None:
        super().__init__(spec, on_pin)
        self._token: str | None = None
        self._session: str | None = None  # where to sign out again
        self._login_lock = asyncio.Lock()
        self._login_error: KvmError | None = None
        self._login_retry_at = 0.0
        self._places: dict[str, str] = {}  # system, chassis, manager, thermal: where this controller keeps them
        self._places_at = 0.0
        self._controller: dict[str, Any] = {}  # what rarely changes about the controller itself
        # The fans of the newer shape as last read, by place, in the controller's order: (when, the fan, or None
        # where what is there is no fan). At most MAX_SENSORS of them; see `_sensors`.
        self._fans_read: dict[str, tuple[float, dict[str, Any] | None]] = {}
        self._fans_cut_said = False  # whether the log was told that not every fan fits into one look
        self._controller_at = 0.0
        self._power: bool | None = None  # whether the server was on at last sight
        self._following: asyncio.Task[None] | None = None  # the looks that follow something done to the server
        self._good: dict[str, Any] | None = None  # what the last look that worked found, and when
        self._good_at = 0.0
        self._hiccup = False  # the last look failed, and the tile was left saying what the one before found
        self._fault_at: float | None = None  # when it last called itself Critical, and about what
        self._fault_where = ""
        self._console: _Console | None = None  # the console that is open, while the wall is watched
        self._console_task: asyncio.Task[None] | None = None
        self._console_wanted_at = 0.0  # when a picture was last asked for
        self._console_retry_at = 0.0
        self._console_refusal: KvmError | None = None  # why the last attempt came to nothing
        self._leaving: set[asyncio.Future[None]] = set()  # sign-outs of its web page that are under way
        self._no_screen: str | None = None  # why there is no picture to be had at all, for now (said on the tile)
        self._has_console: bool | None = None  # whether this controller has a console qKVM reads; None: not asked yet
        self._ami_root = False  # its service root says the controller is AMI's (see `_openbmc_known`)
        self._console_failures = 0  # attempts in a row that came to nothing
        self._complete_first: bool | None = None  # how its console wants to be greeted (see ami.hello); None: not known yet
        self._encode_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._rfb_screen: OpenBmcScreen | None = None  # OpenBMC's console (see openbmc.py), made where the controller announces it
        # Keys and the mouse, where the console is AMI's (it takes them; OpenBMC's does not). Once the controller tells
        # this program's session "the console is yours", `_live_send` is the one way they go out over it (guarded by
        # `_say_lock`, shared with the loop that reads the console) and `_can_input` is set; both are cleared when the
        # console is given to somebody at the controller's own page and when it ends. `_input_era` goes up at each of
        # those moments: whoever began typing in an earlier one is told so (`_input_lost`) and sends nothing more, so a
        # line that held the keyboard takes it again and begins from a keyboard with nothing down.
        self._live_send: Callable[[bytes, int], Awaitable[None]] | None = None
        self._say_lock = asyncio.Lock()
        self._can_input = asyncio.Event()
        self._input_era = 0
        self._input_lost = KvmError("dropped", "The server's console was closed")
        self._accepted_at: float | None = None  # when this session's pass was taken; None: no session, or not yet
        self._input_from = 0.0  # keys and the pointer go from this moment of the session on (see HID_SETTLE)
        self._handed_over = False  # this session's console was given to somebody at the controller's own page
        self._hid_seq = 0
        self._mouse_mode = ami.ABSOLUTE  # what the console last said the server's mouse is; absolute until it says otherwise
        # What this program has down on the server as far as it has said (let go of before the console is given away).
        self._held_keys = False
        self._held_buttons = 0
        self._key_notes = self._button_notes = 0  # reports noted so far (see `send_keyboard`)
        self._mouse_at: tuple[int, int] | None = None  # the place of the last absolute mouse report
        self._typing = asyncio.Lock()  # one "type text" or "send keys" at a time (two would interleave on the keyboard)
        self._letting_go: set[asyncio.Future[None]] = set()  # releases owed by a typing that was cut off with a key down
        # Which server answers (see `_judge`): another one found there, said on the tile until this one answers again; the
        # session under which the computer was last found to be this tile's (a command goes under that one only: another
        # server does not know it); the session of the last answer; and the controller's number as the controller that made a
        # session said it, with that session (see `_controller_under`).
        self._other: KvmError | None = None
        self._checked_token: str | None = None
        self._answered_token: str | None = None
        self._root_seen: tuple[str | None, str | None] = (None, None)
        # The sessions signed in right after the controller's number was compared (or under which it was taken), the last few:
        # what a server known by its controller alone (SAID_NONE), or whose computer says none just now, is judged by. (A few:
        # a read under the one before may come back after a new one was signed in, and is no less this controller's.)
        self._controller_tokens: deque[str] = deque(maxlen=CONTROLLER_SESSIONS)

    def tidy(self) -> None:
        if self._rfb_screen is not None:
            self._rfb_screen.tidy()

    def takes_over(self, retired: Device) -> None:
        # Somebody at the server's own console was asked for it, and said no or did not answer: they are
        # not asked again before the time that was set, whatever is changed about the tile meanwhile.
        # That, and nothing else there is no picture for: every other reason is one that saving the tile
        # again may be the cure of, and is found out anew.
        if isinstance(retired, RedfishDevice) and retired._console_refusal is not None and retired._console_refusal.code == "console_held":
            self._console_refusal, self._console_retry_at = retired._console_refusal, retired._console_retry_at
            self._no_screen, self._console_failures = retired._no_screen, retired._console_failures

    async def close(self) -> None:
        already, self._closed = self._closed, True  # from here on nothing new is asked, so no new session is made
        if self._letting_go:
            # A key a typing left down is let go of over the console before the console is closed under it.
            await asyncio.wait(set(self._letting_go), timeout=LET_GO_WITHIN + 0.5)
        if self._console_task is not None:
            self._console_task.cancel()  # it signs out of the controller's web page on its way out
            await stopped([self._console_task])
        if self._rfb_screen is not None:
            await self._rfb_screen.close()  # (its seat is given back before the session it was opened with)
        if self._following is not None:
            self._following.cancel()  # it only waits and asks for a look: there is nothing under way in it to end badly
        # Whatever else was under way ends here, a sign-in among it. The session is read after that: read
        # first, one that a sign-in was given while the console was being waited for was never given back.
        await stopped([self._status_task, *self._flights])
        token, session, client = self._token, self._session, self._client
        self._token = self._session = None
        goodbyes: list[Any] = []
        if self._leaving:
            # The sign-out of its web page, begun as the console stopped: waited for, within its own time,
            # before the connections are closed under it.
            goodbyes.append(asyncio.wait(set(self._leaving), timeout=SIGN_OUT_WITHIN))
        if token and session and client is not None and self._down_error is None and not already:
            goodbyes.append(self._give_back(client, session, token))
        if goodbyes:
            await asyncio.gather(*goodbyes)
        await super().close()

    @staticmethod
    async def _give_back(client: httpx.AsyncClient, session: str, token: str) -> None:
        # A controller allows only so many sessions at a time. Leaving this one behind would use one up
        # until it runs out by itself, half an hour later.
        try:
            goodbye = client.build_request("DELETE", session, headers={"X-Auth-Token": token}, timeout=SIGN_OUT)
            await bounded(client, goodbye, MAX_REPLY, SIGN_OUT_WITHIN)
        except (httpx.HTTPError, KvmError):
            pass

    @staticmethod
    async def _leave_its_web_page(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
        try:
            await bounded(client, client.build_request("DELETE", "/api/session", headers=headers, timeout=SIGN_OUT), MAX_REPLY, SIGN_OUT_WITHIN)
        except (httpx.HTTPError, KvmError):
            pass
        client.cookies.clear()

    # --- signing in and asking ----------------------------------------------------

    async def _login(self) -> str:
        async with self._login_lock:
            if self._token:
                return self._token
            if self._login_error and time.monotonic() < self._login_retry_at:
                raise self._login_error.with_traceback(None)
            if not self.spec.password:
                raise KvmError("no_password", "No password saved for this device")
            offered = REJECTED.what("login", self.spec)
            self._not_yet(offered, NO_SAID)
            client = await self._http()
            compared = await self._same_controller(client)  # (where its number is remembered: asked before the password goes)
            login = client.build_request("POST", SESSIONS, json={"UserName": self.spec.username, "Password": self.spec.password}, timeout=sign_in_waits())
            before = REJECTED.sent(offered)
            try:
                reply = await self._send(client, login, MAX_REPLY)
            except httpx.HTTPError as ex:
                raise self._came_to_nothing(offered, _transport_error(ex, self.spec.tls), NO_SAID, before, went_out(ex)) from ex
            except KvmError as ex:
                raise self._came_to_nothing(offered, ex, NO_SAID, before) from None
            self._answered()
            if reply.status_code in (401, 403):
                # A controller locks an account after a few wrong passwords: do not offer it the same one every few
                # seconds, and less often each time it says no (see LOGIN_BACKOFFS).
                self._login_error = KvmError("auth_failed", NO_SAID)
                self._login_retry_at = time.monotonic() + REJECTED.said_no(offered)
                log.warning("%s: login rejected", self.label)
                raise self._login_error
            token: str = reply.headers.get("x-auth-token", "")
            if reply.status_code not in (200, 201) or not TOKEN.fullmatch(token):
                # Not the password's doing (every session it has is given out, or it is not a controller at
                # all). Every look at the tile ends here: the password is not sent again each time meanwhile.
                raise self._neither_yes_nor_no(offered, KvmError("bad_response", f"Login failed (HTTP {reply.status_code})"), NO_SAID)
            self._login_error = None
            REJECTED.accepted(offered)
            self._token = token
            if compared:
                self._controller_tokens.append(token)  # (a session of the controller whose number was just compared: see `_judge`)
            try:
                self._session = link(urlsplit(reply.headers.get("location", "")).path)
            except ValueError:  # what it gave as the place of the session is not an address at all
                self._session = None
            return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        urgent: bool = False,
        vital: bool = True,
        headers: dict[str, str] | None = None,
        still: Callable[[], bool] | None = None,
        command: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send a signed-in request. `urgent`, `vital` and `still` mean what they mean for a KVM (see KvmDevice._request).

        `command`: it changes something on the server (or hands out a way into its console), and goes only under the session
        under which the computer was last found to be this tile's (`_checked_token`). A server that took the address since does
        not know that session, and answers 401: the program signs in anew, and asks which server answers before the command goes
        (`_same_server`). So what takes a command is the server that was asked, however the address changed hands meanwhile,
        whatever certificate and password the two share."""
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = False
        asked = 0
        while True:
            token = self._token or await self._login()
            if command and self.spec.machine and token != self._checked_token:
                asked += 1
                if asked > MOST_ASKED:
                    raise NothingSent("action_failed", "Nothing was sent: the controller at this address signed this program in anew while it was asked which server it is. Try again.")
                await self._which_server_before_a_command(urgent)
                continue
            client = await self._http()
            try:
                signed = {**(headers or {}), "X-Auth-Token": token, "Accept": "application/json"}
                request = client.build_request(method, path, headers=signed, **kwargs)
                if still is not None and not still():
                    raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
                reply = await self._send(client, request, MAX_REPLY)
            except KvmError as ex:
                raise failed(ex) from None
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as ex:
                if method == "GET" and not retried:  # a connection the controller closed while it sat idle
                    retried = True
                    continue
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            except httpx.HTTPError as ex:
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            self._answered()
            if reply.status_code != 401:
                self._answered_token = token  # (read by whoever awaited this, before anything else runs: see `_checked_read`)
                return reply
            if relogged:
                # It signs this program in and refuses the session it has just given. Every look ends up
                # here: the password is not sent to it again with each of them.
                async with self._login_lock:
                    if self._token == token:
                        self._token = None
                        self._login_error = KvmError("auth_failed", "The controller keeps rejecting the session")
                        self._login_retry_at = time.monotonic() + LOGIN_RETRY
                raise KvmError("auth_failed", "The controller keeps rejecting the session")
            relogged = True  # the session ran out, or the controller restarted: sign in once more
            if self._token == token:
                self._token = None

    async def _read(
        self, path: str, urgent: bool = False, vital: bool = True, waits: httpx.Timeout | None = None, command: bool = False
    ) -> tuple[dict[str, Any], str | None]:
        """What is at `path`, and the mark the controller puts on its present state (None: it puts none). `waits`: how long
        its answer is waited for, where not as long as for any other (WAITS). (Never None to httpx: that is no limit.)
        `command`: a read that hands something out (a way into the console), bound as a command is (see `_request`)."""
        if waits is None:
            reply = await self._request("GET", path, urgent=urgent, vital=vital, command=command)
        else:
            reply = await self._request("GET", path, urgent=urgent, vital=vital, command=command, timeout=waits)
        if reply.status_code != 200:
            raise KvmError("bad_response", f"{path} failed (HTTP {reply.status_code})")
        try:
            data = read_json(reply)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise KvmError("bad_response", f"{path} returned unexpected data")
        if "error" in data and "@odata.id" not in data:
            # An error, said with HTTP 200 (some controllers do, at one of their moments), as the standard's
            # record or as a bare text. Every resource has its own address in it and no "error"; this has it
            # the other way round, and is no resource.
            said = plain(_dig(data, "error", "message"), 120) or plain(data.get("error"), 120) or "without a word"
            raise KvmError("bad_response", f"{path} answered an error: {said}")
        marks = (reply.headers.get("etag"), data.get("@odata.etag"))
        return data, next((mark for mark in marks if isinstance(mark, str) and ETAG.fullmatch(mark)), None)

    async def _get(self, path: str, urgent: bool = False, vital: bool = True) -> dict[str, Any]:
        return (await self._read(path, urgent, vital))[0]

    async def _first(self, collection: Any, urgent: bool, vital: bool) -> str | None:
        """The first member of a collection the controller points to."""
        path = link(_dig(collection, "@odata.id"))
        if path is None:
            return None
        members = (await self._get(path, urgent, vital)).get("Members")
        return link(_dig(members[0], "@odata.id")) if isinstance(members, list) and members else None

    async def _find(self, urgent: bool = False) -> dict[str, str]:
        """Where this controller keeps the server, its chassis, itself, and the server's sensors.

        The computer says which chassis is its own and which controller manages it (Links.Chassis and
        Links.ManagedBy): that is taken first, and the first one listed only where the computer says
        nothing. An iDRAC lists every disk enclosure as a chassis too, and whichever comes first in that
        list has no sensors; AMI's boards, with one of each called "Self", say the same thing both ways.
        """
        if self._places and time.monotonic() - self._places_at < ABOUT_TTL:
            return self._places
        root = await self._get(ROOT, urgent)
        self._ami_root = (plain(root.get("Vendor"), 40) or "").upper() == "AMI"
        system = await self._first(root.get("Systems"), urgent, True)
        if system is None:
            raise KvmError("bad_response", "The controller lists no computer")
        places = {"system": system}
        said = (await self._get(system, urgent)).get("Links")
        for name, key, by_the_computer in (("chassis", "Chassis", "Chassis"), ("manager", "Managers", "ManagedBy")):
            # (A link to somewhere else is no link, and the next one is looked at: see `link`. A computer names
            # a chassis or two, not hundreds: the first few are looked at.)
            claimed = [one.get("@odata.id") for one in listed(_dig(said, by_the_computer))[:8] if isinstance(one, dict)]
            found = next((place for one in claimed if (place := link(one))), None)
            if claimed and found is None:
                log.info("%s: what the computer names as its %s is nowhere on the controller; the first listed is taken", self.label, name)
            if found is None:
                try:
                    found = await self._first(root.get(key), urgent, False)
                except KvmError:
                    found = None
            if found:
                places[name] = found
        if update := link(_dig(root, "UpdateService", "@odata.id")):
            places["update"] = update  # (where its firmware inventory is: see `_inventory_version`)
        if "chassis" in places:
            places.update(await self._sensor_places(places["chassis"], urgent))
        self._places, self._places_at = places, time.monotonic()
        return places

    async def _sensor_places(self, chassis: str, urgent: bool) -> dict[str, str]:
        """Where the chassis keeps its sensors: `thermal` (the older shape), or `metrics` and `fans` (the newer)."""
        try:
            found = await self._get(chassis, urgent, False)
        except KvmError:
            return {}
        thermal = link(_dig(found, "Thermal", "@odata.id"))
        if thermal:
            return {"thermal": thermal}
        subsystem = link(_dig(found, "ThermalSubsystem", "@odata.id"))
        if not subsystem:
            return {}
        try:
            parts = await self._get(subsystem, urgent, False)
        except KvmError:
            return {}
        return {name: place for name, key in (("metrics", "ThermalMetrics"), ("fans", "Fans")) if (place := link(_dig(parts, key, "@odata.id")))}

    async def _sensors(self, places: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Every temperature and every fan, in whichever shape this controller has them. The server is there; these are a detail.

        In the newer shape every fan is a read of its own, and the sensors get SENSORS_WITHIN of this look between
        the reads: the time is looked at before the list of fans and before each fan is asked for, never by cutting
        a read short (a read on this connection is not to be cancelled, see `bounded`). So the sensors take at most
        that long plus the read that was under way when it ran out; and one read may be sent up to three times,
        with a sign-in between (see `_request`: once more on a connection the controller had closed, once more
        after signing in again), each of them within its own bounds.

        A fan not read in this look (no time was left for it, or it did not answer) keeps what the last look read
        of it, and the fans read longest ago are asked for first: a controller that is slow does not make a fan
        that is not well drop off the tile, and every fan is read again in turn. One the controller no longer
        lists is gone.
        """
        if "thermal" in places:
            try:
                thermal = await self._get(places["thermal"], vital=False)
            except KvmError:
                return [], []
            return temperatures_of(thermal), fans_of(thermal)
        until = time.monotonic() + SENSORS_WITHIN
        temperatures: list[dict[str, Any]] = []
        if "metrics" in places:
            try:
                temperatures = readings_of(await self._get(places["metrics"], vital=False))
            except KvmError:
                pass
        if "fans" not in places:
            return temperatures, []
        members: list[Any] | None = None
        if time.monotonic() < until:
            try:
                members = listed((await self._get(places["fans"], vital=False)).get("Members"))
            except KvmError:
                members = None
        known = self._fans_read
        if members is None:  # no time left for the list, or no answer: the fans as the last look found them
            return temperatures, [fan for _, fan in known.values() if fan is not None]
        # One resource a fan: as many reads as there are fans, no more than the wall would list, each place once,
        # in the controller's order; read longest ago first (never before that), the others in the next look.
        order = list(dict.fromkeys(place for one in members[:MAX_SENSORS] if (place := link(_dig(one, "@odata.id")))))
        fresh: dict[str, tuple[float, dict[str, Any] | None]] = {}
        for place in sorted(order, key=lambda place: known[place][0] if place in known else float("-inf")):
            if time.monotonic() >= until:
                if not self._fans_cut_said:
                    self._fans_cut_said = True
                    log.info("%s: not every fan could be read in one look; the others keep what was last read of them, and are read in turn", self.label)
                break
            try:
                fresh[place] = (time.monotonic(), fan_of(await self._get(place, vital=False)))
            except KvmError:
                continue
        self._fans_read = {place: fresh.get(place) or known[place] for place in order if place in fresh or place in known}
        return temperatures, [fan for _, fan in self._fans_read.values() if fan is not None]

    # --- what the wall asks ---------------------------------------------------------

    async def _itself(self, urgent: bool = False) -> dict[str, Any]:
        """What rarely changes about the controller itself: its firmware, where it hands out a way into its console, and
        whether it runs OpenBMC (and its console where it announces one). `known`: its own resource was read (or it lists
        none). One that could not be read just now is asked again after ABOUT_RETRY, and what was known before stands
        meanwhile: kept as "nothing" for ABOUT_TTL, it hid OpenBMC's console for ten minutes, and a picture went down the
        road of AMI's console, which an OpenBMC controller seems to have (it answers every address 401, sign in first).
        `urgent` (somebody asked, and waits): one that could not be read is asked again at once."""
        stale = time.monotonic() - self._controller_at > ABOUT_TTL or (urgent and not self._controller.get("known"))
        if not self._controller or stale:
            manager: dict[str, Any] = {}
            places = await self._find(urgent)
            place = places.get("manager")
            if place:
                try:
                    manager = await self._get(place, urgent, False)
                except KvmError:
                    if not self._controller.get("known"):
                        self._controller = {"version": None, "console": None, "rfb": None, "openbmc": False, "known": False}
                    self._controller_at = time.monotonic() - ABOUT_TTL + ABOUT_RETRY
                    return self._controller
            version = plain(manager.get("FirmwareVersion"), 40)
            if place and manager and manager.get("FirmwareVersion") is None:  # (not said at all: what is said and is no text, is not looked for elsewhere)
                version = await self._inventory_version(manager, place, places.get("update"), urgent)
            # "IKVM" is where AMI's controllers keep it, on the boards whose maker left it in.
            self._controller = {
                "version": version,
                "console": link(_dig(manager, "IKVM", "@odata.id")),
                "rfb": rfb_console(manager),  # OpenBMC's console (openbmc.py)
                "openbmc": is_openbmc(manager),
                "known": True,
            }
            self._controller_at = time.monotonic()
            if self._controller["openbmc"]:
                # Its console is the one it announces, or none: it has no web page of AMI's, whose door it answers 401 as
                # AMI's does, and whose sign-in would be sent the controller's password and counted as a no (see `_hold_console`).
                self._has_console = False
        return self._controller

    async def _inventory_version(self, manager: dict[str, Any], own: str, update: str | None, urgent: bool) -> str | None:
        """The controller's firmware version out of its firmware inventory, where its own resource does not say it.

        bmcweb (OpenBMC) says it there only where it knows which of its images runs, and only then names that image
        (Links.ActiveSoftwareImage); OpenBMC's romulus image in QEMU (its master of October 2026) said neither, long after it started.
        In the standard's order: the image the controller says it runs; else, of the pieces of software in
        UpdateService's FirmwareInventory, those that name this very controller as what they are for (RelatedItem:
        bmcweb names it for every image of the BMC, and the computer's BIOS for the host's) and are in use
        (Status.State "Enabled": bmcweb's word for an image that is active). The version those agree on; where two
        active ones do not say one version, which of them runs is not known, and none is said. So nothing is said
        either where not every piece could be read: more of them than MOST_IMAGES, or than the list holds (another
        page), one listed that is no place on this controller, a read that failed, or the time up (no read begins
        after IMAGES_WITHIN). Every place through `link`, every value by its kind and cut.
        """
        until = time.monotonic() + IMAGES_WITHIN
        try:
            active = link(_dig(manager, "Links", "ActiveSoftwareImage", "@odata.id"))
            if active is not None:
                return plain((await self._get(active, urgent, False)).get("Version"), 40)
            inventory = link(_dig(await self._get(update, urgent, False), "FirmwareInventory", "@odata.id")) if update else None
            if inventory is None or time.monotonic() >= until:
                return None
            collection = await self._get(inventory, urgent, False)
        except KvmError:
            return None
        members = listed(collection.get("Members"))
        count = number(collection.get("Members@odata.count"), 0, 10**9)
        # Not every one would be read: there are more than are read, or than this page lists, or one is no place here.
        # One that was not read may be the other active image.
        places = [link(_dig(one, "@odata.id")) for one in members]
        if len(members) > MOST_IMAGES or "Members@odata.nextLink" in collection or (count is not None and count > len(members)) or None in places:
            return None
        own = own.rstrip("/")
        said: set[str | None] = set()
        for place in dict.fromkeys(place for place in places if place is not None):
            if time.monotonic() >= until:
                return None  # (the same)
            try:
                image = await self._get(place, urgent, False)
            except KvmError:
                return None  # (the same)
            for_whom = {(link(_dig(item, "@odata.id")) or "").rstrip("/") for item in listed(image.get("RelatedItem"))[:MOST_IMAGES]}
            if own in for_whom and _dig(image, "Status", "State") == "Enabled":
                said.add(plain(image.get("Version"), 40))  # (None for a version that is no text: an active image all the same)
        return next(iter(said)) if len(said) == 1 else None

    async def _read_about(self, system: dict[str, Any], urgent: bool = False) -> dict[str, Any]:
        return {"model": named(system.get("Model"), system.get("Manufacturer")), "version": (await self._itself(urgent))["version"]}

    async def identify(self) -> dict[str, Any]:
        # Added: the server is remembered by its numbers from here on (the server keeps spec.machine with the tile). Edited:
        # it is the server remembered, or the edit is refused (unless its password was typed, which takes the server that
        # answers now: see the server's update_device).
        system, _ = await self._checked_read((await self._find(urgent=True))["system"], urgent=True)
        # "" where its computer says no number and the tile knows it by its controller alone (said, and none: see the server's
        # `connect`); None where the computer said one when it was added and says none just now (taken for this one by its
        # controller, see `_judge`), which leaves the number it is known by as it is.
        number = own_number(system)
        if number is None:
            number = "" if marks_of(self.spec.machine)[0] in ("", SAID_NONE) else None
        return {**await self._read_about(system, urgent=True), "hostname": named(system.get("HostName")), "ident": number}

    # --- which server answers: the numbers it gives for itself, against those remembered ----------------------------------
    # A controller's maker may have put one certificate, and one key, on every board, and a fleet often has one password: after
    # a new lease another server's controller answers at a tile's address, takes the saved password, and would be switched off,
    # restarted into its setup and typed into from this tile. So a server is known by the number its computer gives for itself
    # (its UUID), which is asked before anything is sent to it, and by the number its controller's service root gives, which
    # anybody may read, asked before the password goes. Both are remembered when the tile is added (DeviceSpec.machine).

    async def _same_controller(self, client: httpx.AsyncClient) -> bool:
        """Where the controller's number is remembered, its service root is read (without the password) and its number
        compared, before the password goes: KvmError "another_machine" where another one answers, or one that says none; a
        root that is none just now (an error of its own, no answer) is said as that, and nothing is sent. True where it was
        compared (the session that follows is one this controller made: see `_controller_tokens`); False where nothing is
        remembered of it to compare with. (Only ever compared here: a number read without a session says nothing of which
        controller answers under one, so none is taken from this read, see `_controller_under`.)"""
        remembered = marks_of(self.spec.machine)[1]
        if remembered is None:
            return False
        usual = client.timeout
        waits = httpx.Timeout(ROOT_WAIT_TIMES * (usual.read or 20.0), connect=usual.connect, pool=usual.pool, write=usual.write)
        for again in (True, False):
            try:
                reply = await self._send(client, client.build_request("GET", ROOT, headers={"Accept": "application/json"}, timeout=waits), MAX_REPLY)
                break
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as ex:
                if again:  # (a connection the controller closed while it sat idle)
                    continue
                raise self._failed(_transport_error(ex, self.spec.tls)) from ex
            except httpx.HTTPError as ex:
                raise self._failed(_transport_error(ex, self.spec.tls)) from ex
            except KvmError as ex:
                raise self._failed(ex) from None
        self._answered()
        try:
            root = read_json(reply) if reply.status_code == 200 else None
        except ValueError:
            root = None
        if not isinstance(root, dict) or "RedfishVersion" not in root:
            # (Not a service root at all just now: one of its moments. Nothing is judged by that, and nothing is sent.)
            raise KvmError("bad_response", f"The controller did not show its service root (HTTP {reply.status_code}), which is read before its password goes")
        seen = controller_number(root)
        if seen != remembered:
            raise self._another(ANOTHER_CONTROLLER if seen is not None else NO_CONTROLLER_NUMBER)
        return True

    async def _controller_under(self, token: str | None) -> tuple[str | None, bool]:
        """The controller's number, as the controller that made the session `token` says it, and whether that could be asked
        under it: its service root's UUID, taken only where its manager, read under that session after the root, names the
        same, as the service it hosts (`ServiceEntryPointUUID`) or as itself (`UUID`: a real AMI board names the same in all
        three; bmcweb's manager names the service). The root is open to anybody, and says nothing of which controller made a
        session; the manager is read under the session, and another controller does not know it (401). (None, True) where
        either says none, or they differ; (None, False) where it could not be read under that session (asked again another
        time; once a session, so a controller that says none costs a read of each a session)."""
        root, under = self._root_seen
        if under is not None and under == token:
            return root, True
        found: str | None = None
        try:
            said, _ = await self._read(ROOT, urgent=True, vital=False)
            place = (await self._find(urgent=True)).get("manager")
            if place is not None:
                manager, _ = await self._read(place, urgent=True, vital=False)
                named = {_digest(manager.get("ServiceEntryPointUUID")), _digest(manager.get("UUID"))} - {None}
                number = controller_number(said)
                found = number if number is not None and number in named else None
        except KvmError as ex:
            if ex is RETIRED:
                raise
            return None, False
        if self._answered_token != token:
            return None, False  # (signed in anew meanwhile: the manager was not read under that session)
        self._root_seen = (found, token)
        return found, True

    async def _checked_read(self, place: str, urgent: bool = False, vital: bool = True, waits: httpx.Timeout | None = None) -> tuple[dict[str, Any], str | None]:
        """The computer at `place`, read and judged by the number it gives for itself (`_judge`): (what it says, its mark)."""
        system, mark = await self._read(place, urgent, vital, waits)
        await self._judge(own_number(system), self._answered_token)  # (the session of this answer: nothing ran since)
        return system, mark

    async def _same_server(self, urgent: bool) -> None:
        """Which server answers, asked afresh: the computer read and judged (see `_judge`)."""
        await self._checked_read((await self._find(urgent))["system"], urgent)

    async def _which_server_before_a_command(self, urgent: bool) -> None:
        """`_same_server`, before a command goes out under a session the computer was not asked under: KvmError
        "another_machine" as it is; anything else as a command that was not sent (NothingSent)."""
        try:
            await self._same_server(urgent)
        except KvmError as ex:
            if ex.code == "another_machine" or ex is RETIRED:
                raise ex.with_traceback(None) from None
            raise NothingSent("action_failed", f"Nothing was sent: which server answers could not be read ({ex.message})") from None

    async def _judge(self, seen: str | None, token: str | None) -> None:
        """Whether the server that answers under the session `token` is the one this tile was added for, by the number its
        computer gives for itself there (`seen`, as own_number makes it; None: none said) and its controller's. Nothing where
        it is (the session is noted as checked: `_checked_token`); KvmError "another_machine" where it is not.

        * Nothing remembered (a tile added while the server could not be reached, or from a file without its numbers): the
          numbers seen are taken from then on, and said in the log (trust on first use, as for a certificate): the
          computer's, or SAID_NONE where it gives none, and the controller's as it says it under this same session
          (`_controller_under`). Where neither says one, nothing is taken, and such a server is not told apart.
        * The computer said none when the tile was added (SAID_NONE): known by its controller alone, whose number was compared
          before this session was signed in (`_controller_tokens`); whatever the computer says now is not judged.
        * The computer's number remembered: it is compared. One that says none where one was given is this one's only where
          the controller's number is remembered and was compared before this very session (a controller that learns it
          from the server's firmware as it starts may say none while the server is off); else it is not taken for this
          one, at a look as before a button (what the tile shows is what its buttons would do). Where the controller's
          number is not remembered yet (a tile from 0.1.x, which kept the computer's alone, see store.machine_from_before),
          it is taken the first time the computer is found to be this one, under that same session."""
        remembered = self.spec.machine
        server, controller = marks_of(remembered)
        if not remembered:
            root, asked = await self._controller_under(token)
            if self.spec.machine:
                await self._judge(seen, token)  # (taken meanwhile, by another read: judged by that)
                return
            if seen is None and not asked:
                # (Its computer gives no number, and its controller's could not be asked just now: nothing is taken on the
                # strength of that, and it is said, as one of its moments. Asked again at the next look.)
                raise KvmError("bad_response", "Which server answers here could not be told just now: its computer gives no number, and its controller's could not be read")
            if seen is None and root is None:
                return
            taken = (seen or SAID_NONE) + (root or "")
            if taken == SAID_NONE:
                return  # (no computer's number, and no controller's: nothing to know it by)
            self.spec.machine = taken
            self._checked_token = token
            if root is not None and token is not None:
                self._controller_tokens.append(token)
            log.info("%s: the server at this address is known by the numbers it gives for itself from now on", self.label)
            if self.on_known is not None and not self._closed:
                await self.on_known("", taken)
            return
        compared = controller is not None and token is not None and token in self._controller_tokens
        if server == SAID_NONE and controller is not None:
            if not compared:
                # (A session this controller was not asked before: none is made otherwise, so this is said, not judged.)
                raise self._another(NO_CONTROLLER_NUMBER)
        elif seen is None:
            if not compared:
                raise self._another(NO_SERVER_NUMBER)
        elif seen != server:
            raise self._another(ANOTHER_SERVER)
        self._checked_token = token
        if self._other is not None:
            log.info("%s: the server this tile was added for answers at its address again", self.label)
            self._other = None
        if controller is None and remembered == server and server != SAID_NONE:
            root, _ = await self._controller_under(token)
            if root is not None and self.spec.machine == remembered:
                self.spec.machine = server + root
                if token is not None:
                    self._controller_tokens.append(token)
                log.info("%s: its controller is known by the number it gives for itself from now on, and asked before the password goes to it", self.label)
                if self.on_known is not None and not self._closed:
                    await self.on_known(remembered, self.spec.machine)

    def _another(self, words: str) -> KvmError:
        """Note that the server at the address is not this tile's: what is said from now on, until it is again."""
        if self._other is None or self._other.message != words:
            log.warning("%s: %s", self.label, words)
            self._status_at = 0.0  # (the tile says it at the next look, not up to LOOK_EVERY later)
            self._places_at = float("-inf")  # (where another server keeps things is looked up anew)
        self._other = KvmError("another_machine", words)
        # What was read of it is another server's: its power is not taken for this one's, nor what this one's tile last said
        # said again for a look that fails meanwhile (HICCUP); and no command goes under the session it signed in.
        self._good, self._power, self._checked_token = None, None, None
        return self._other

    def _console_with_a_picture(self, arrived: float) -> _Console:
        """The console that is open and has shown the screen; one is opened where none is. KvmError until then."""
        if self._has_console is False or self._closed:
            raise NO_PICTURE.with_traceback(None)
        console = self._console
        if console is None or console.done.is_set():
            if self._console_refusal is not None and arrived < self._console_retry_at:
                raise self._console_refusal.with_traceback(None)
            self._check_backoff()  # a controller that is down is not asked for its console either
            self._console = _Console()
            self._console_task = asyncio.create_task(self._run_console(self._console))
            raise KvmError("no_stream", "Opening the server's console", 503)
        if not console.frames:
            raise KvmError("no_stream", "Waiting for the server's screen", 503)
        return console

    @property
    def console_readable(self) -> bool:
        """Whether this controller has a console the wall reads, as far as is known: a server's live picture is that, and nothing else."""
        if self._other is not None:
            return False  # (another server answers at the address: see `_judge`)
        rfb_screen = self._openbmc_screen()
        if rfb_screen is not None:
            return rfb_screen.turned_away() is None  # (a console that failed is waited for; one turned away is not)
        return self._has_console is not False

    def _openbmc_screen(self) -> OpenBmcScreen | None:
        """OpenBMC's console, where the controller announces one (as the last look at it found); None for any other."""
        if not self._controller.get("rfb") or self._closed:
            return None
        if self._rfb_screen is None:
            from .openbmc import OpenBmcScreen

            self._rfb_screen = OpenBmcScreen(self.spec, self)
        return self._rfb_screen

    async def _openbmc_known(self) -> OpenBmcScreen | None:
        """`_openbmc_screen`, where what the controller is was not found out yet asked first (a picture may be asked for
        before the first look is over); None where it has none. KvmError where that cannot be told just now: a picture is
        not asked of AMI's console meanwhile, which an OpenBMC controller seems to have (see `_itself`), unless the
        controller's service root says it is AMI's (bmcweb's names no maker): its console is then asked for as before."""
        if not self._controller.get("known"):
            await self._itself()
            if not self._controller.get("known") and not self._ami_root:
                raise KvmError("no_stream", "Waiting for the controller to say what it is", 503)
        return self._openbmc_screen()

    async def rfb_socket(self) -> Any:
        """OpenBMC's console's WebSocket, signed in with this tile's Redfish session, to the controller and nowhere else.
        A session the controller no longer knows is signed in again once, counted as every sign-in is."""
        path = self._controller.get("rfb")
        if not isinstance(path, str):
            raise KvmError("no_picture", "This controller announces no console", 404)
        if self._other is not None:
            raise self._other.with_traceback(None)
        for attempt in range(2):
            token = self._token or await self._login()
            if self.spec.machine and token != self._checked_token:
                # (Opened only under the session the computer was found to be this tile's under, as a command goes: another
                # server's screen is not shown here. Asked, then the session as it is then.)
                await self._same_server(urgent=True)
                token = self._token or await self._login()
                if token != self._checked_token:
                    raise KvmError("no_stream", "The controller signed this program in anew while it was asked which server it is", 503)
            await self._http()  # (the certificate is known by now: the session came over it)
            try:
                return await ws_connect(
                    "ws" + self.spec.base_url[len("http") :] + path, additional_headers={"X-Auth-Token": token}, ssl=self._tls,
                    open_timeout=CONSOLE_OPENING, close_timeout=1, max_size=OPENBMC_MOST, max_queue=4,
                    ping_interval=None,  # (whether it is alive is seen by what arrives: see vncdevice's heartbeat)
                )  # fmt: skip
            except TimeoutError:
                raise KvmError("timeout", "The controller's console did not answer in time", 504) from None
            except InvalidStatus as ex:
                if ex.response.status_code == 401 and attempt == 0:
                    # Is the session no more (the controller restarted, it ran out), or is the console refused to this
                    # account? Asked with a request that needs the session: it signs in again only where the session is
                    # no more, which leaves none behind. (Signed in again whatever the answer, every refusal of the
                    # console left a session on the controller, and sent the password again.)
                    await self._request("GET", SESSIONS, urgent=True, vital=False)
                    if self._token == token:
                        raise KvmError("bad_response", "The controller does not let this account open its console (HTTP 401)") from None
                    continue
                raise KvmError("bad_response", f"The controller did not open its console (HTTP {ex.response.status_code})") from None
            except (OSError, WebSocketException) as ex:
                raise ws_error(ex, self.spec.tls) from None
        raise KvmError("bad_response", "The controller keeps refusing the session for its console")

    async def live_screen(self) -> tuple[int, int, int, bytearray]:
        """The server's screen as it stands, for the live line: how many frames have made it (another number, another picture), its width and height, and its pixels.

        The pixels are the bytes frames are being read into; whoever makes a picture of them does so in a thread, by `screen_jpeg`.
        """
        if self._other is not None:
            raise self._other.with_traceback(None)  # (another server answers at the address: see `_judge`)
        rfb_screen = await self._openbmc_known()
        if rfb_screen is not None:
            rfb_screen.live_seen()
            client = await rfb_screen.ready(OPENBMC_WAIT)
            if client.frames == 0:
                await rfb_screen.next_frame(0, OPENBMC_WAIT)
            now = rfb_screen.screen()
            if now is None:
                raise KvmError("no_stream", "Waiting for the server's screen", 503)
            return now
        arrived = self._console_wanted_at = time.monotonic()
        console = self._console_with_a_picture(arrived)
        width, height, shown = console.screen.shown
        return console.frames, width, height, shown

    # --- keys and the mouse, over the console this program holds (AMI's firmware only) ------------------------

    @property
    def takes_keys(self) -> bool:
        """Whether this console takes keyboard and mouse from qKVM, as far as is known: AMI's does, OpenBMC's does
        not yet. Said None (not asked yet) is taken as yes, as the screen is: whoever asks finds out (see `input_ready`)."""
        return self._controller.get("rfb") is None and self._has_console is not False and not self._closed

    @property
    def mouse_absolute(self) -> bool:
        """Whether the pointer is sent as an absolute place (where the server's mouse is absolute, as AMI's boards
        are by default) rather than as a relative move."""
        return self._mouse_mode != ami.RELATIVE

    def screen_size(self) -> tuple[int, int] | None:
        """The console screen's width and height, where a frame has said them; None before the first frame."""
        console = self._console
        if console is None or not console.frames:
            return None
        return console.screen.width, console.screen.height

    def _next_seq(self) -> int:
        self._hid_seq = (self._hid_seq + 1) & 0x7FFFFFFF
        return self._hid_seq

    def _input_ends(self, why: KvmError) -> None:
        """Keys and the pointer go no more over this session's console: whoever began in it is told `why`."""
        self._live_send = None
        self._can_input.clear()
        self._input_era += 1
        self._input_lost = why

    async def input_ready(self, within: float = INPUT_WAIT) -> int:
        """The console open and held by this program, so keys and the pointer may go; returns the era they go in (see
        `_input_era`), to be given with each of them. KvmError where they cannot (a controller of another make, or not
        known yet; somebody else holds its console; it was given to somebody at the controller's own page; the server
        is down): what a line asks before it begins, and a typing before its first key.

        Keys and the pointer go only through a console opened after the question which server answers (`_hold_console`),
        whose connection is to that server and to no other; and none while another server is said to answer there."""
        if self._other is not None:
            raise self._other.with_traceback(None)
        if await self._openbmc_known() is not None:
            raise KvmError("no_input", "This server's console (OpenBMC) takes no keyboard or mouse from qKVM yet", 409)
        if not self._controller:
            # (Not known to be AMI's: its web page is not offered the password on the strength of nothing.)
            raise KvmError("no_stream", "Waiting for the server's controller", 503)
        deadline = time.monotonic() + within
        while True:
            now = self._console_wanted_at = time.monotonic()
            console = self._console
            if self._handed_over and console is not None and not console.done.is_set():
                raise handed_over()
            if self._can_input.is_set() and self._live_send is not None:
                settle = self._input_from - now
                if settle <= 0:
                    return self._input_era
                await asyncio.sleep(min(settle, max(0.0, deadline - now)))  # (then asked again: it may have been given away meanwhile)
                if time.monotonic() >= deadline and self._input_from > time.monotonic():
                    raise KvmError("no_stream", "Waiting for the server's keyboard and mouse to be attached", 503)
                continue
            try:
                self._console_with_a_picture(now)  # opens the console, or says why there is no picture
            except KvmError as ex:
                if ex.code != "no_stream":
                    raise  # (no console of this kind, somebody holds it, the controller is down: said as it is)
            if self._accepted_at is not None and now - self._accepted_at > MASTER_WAIT:
                raise KvmError("in_use", "Another session holds this server's console: qKVM shows its screen and types nothing into it", 409)
            wait = deadline - time.monotonic()
            if wait <= 0:
                raise KvmError("no_stream", "Waiting for the server's console", 503)
            try:
                async with asyncio.timeout(min(wait, 0.5)):  # (not wait_for: it can lose a stop up to Python 3.11)
                    await self._can_input.wait()
            except TimeoutError:
                continue

    def _may_send(self, era: int) -> None:
        """KvmError where keys and the pointer of this era may go no more (the console changed hands, or ended)."""
        if era != self._input_era or self._live_send is None:
            raise self._input_lost.with_traceback(None)

    async def _send_hid(self, packet: bytes, era: int) -> None:
        send = self._live_send
        if era != self._input_era or send is None:
            raise self._input_lost.with_traceback(None)
        await send(packet, era)  # (the era is asked again under the console's lock: see `send_input`)

    async def send_keyboard(self, modifiers: int, keys: list[int], era: int) -> None:
        """The whole state of the keyboard (the modifier bits and the keys down) to the server's USB, over the console.
        `era`: what `input_ready` returned; KvmError where the console was given away or ended since."""
        self._may_send(era)  # (refused before anything is noted: a word that never goes holds nothing down)
        down = bool(modifiers or keys)
        self._held_keys = self._held_keys or down  # (may be down from the moment it goes out)
        self._key_notes += 1
        note = self._key_notes
        await self._send_hid(ami.keyboard(modifiers, keys, self._next_seq()), era)
        # Said what is down only by the report noted last (reports go out in the order they were noted: one lock, no
        # wait between): an earlier one finishing late would say "nothing" of a press that is on its way. And not where
        # the console was given away meanwhile: what was let go of then stays let go of.
        if era == self._input_era and note == self._key_notes:
            self._held_keys = down

    async def send_mouse(self, buttons: int, x: int, y: int, wheel: int = 0, *, era: int, relative: bool = False) -> None:
        """A mouse report to the server's USB: `x`, `y` are a place (0 to 32767) for an absolute mouse, or a move for a
        relative one. `era` as for `send_keyboard`."""
        self._may_send(era)
        self._held_buttons |= buttons
        # Noted before it goes, as the buttons are: a letting go that overtakes it lets go of them where it put them.
        self._mouse_at = None if relative else (x, y)
        self._button_notes += 1
        note = self._button_notes
        if relative:
            packet = ami.mouse_rel(buttons, x, y, wheel, self._next_seq())
        else:
            packet = ami.mouse_abs(buttons, x, y, wheel, self._next_seq())
        await self._send_hid(packet, era)
        if era == self._input_era and note == self._button_notes:  # (as for the keyboard)
            self._held_buttons = buttons

    def _let_go_soon(self, era: int) -> None:
        """A key may be down that nobody will let go of now (a typing was cut off between its press and its release):
        let go of in a task of its own, within a time, and never awaited by the task that was cut off."""
        if era != self._input_era:
            # (The console changed hands or ended: what was down was let go of then by this program, over the console,
            # before or as it changed hands and before the session's goodbye, and a real board lets go of what a
            # session left down as it ends; see `release_held`.)
            return
        going = asyncio.ensure_future(self._let_go_now(era))
        self._letting_go.add(going)
        going.add_done_callback(self._letting_go.discard)

    async def _let_go_now(self, era: int) -> None:
        try:
            async with asyncio.timeout(LET_GO_WITHIN):
                await self.send_keyboard(0, [], era)
        except (KvmError, TimeoutError, OSError):
            pass  # (the console is gone, and with its session what it held)

    def _not_typed(self, action: str, text: str, ex: KvmError, typeable: Callable[[str], bool]) -> KvmError:
        """What is said of a key or a text that cannot be sent. Of a text, where it went wrong and not what is there:
        it may be a saved secret, and what is said goes into the activity log."""
        if action == "text":
            at = next((place for place, char in enumerate(text.replace("\r\n", "\n"), 1) if not typeable(char)), None)
            where = f"Character {at} of the text" if at is not None else "A character of the text"
            return KvmError("invalid", f"{where} cannot be typed on a US keyboard layout", 422)
        return KvmError("invalid", ex.message.replace("A JetKVM", "This server's console").replace("a JetKVM", "this server's console"), 422)

    async def _type(self, action: str, *, keys: str = "", text: str = "", still: Callable[[], bool] | None = None) -> None:
        """Press a combination ('keys'), type a text ('text'), or send Ctrl+Alt+Del, over the console. Each report is
        the whole keyboard; a key held is let go of by a report without it, so a combination goes down together and
        a typed character is pressed and released. The console is kept from being given back while a long text goes."""
        from .jetkvm import key_report, text_reports  # (the USB HID key and character tables, shared with a JetKVM)

        def typeable(char: str) -> bool:
            try:
                text_reports(char)
            except KvmError:
                return False
            return True

        try:
            if action == "ctrl_alt_del":
                reports = [key_report("ControlLeft,AltLeft,Delete")]
            elif action == "keys":
                if not KEYS.fullmatch(keys):
                    raise KvmError("invalid", "Not a valid key combination", 422)
                reports = [key_report(keys)]
            else:  # text
                if not text or len(text) > MAX_TEXT:
                    raise KvmError("invalid", f"Text must be 1 to {MAX_TEXT} characters", 422)
                reports = text_reports(text)
        except KvmError as ex:
            if ex.code == "invalid" and "JetKVM" in ex.message:  # (the tables are a JetKVM's too, and name one)
                raise self._not_typed(action, text, ex, typeable) from None
            raise
        async with self._typing:  # two people typing at once would interleave on the one keyboard
            try:
                era = await self.input_ready()
            except KvmError:
                if not self.takes_keys:  # a controller of another make, or one with no console qKVM reads: it cannot do this
                    raise KvmError("invalid", "This server's controller has no console that qKVM can send a keyboard through", 422) from None
                raise  # (an AMI console that is held by somebody else, the server off, a moment of the controller's: said as it is)
            if still is not None and not still():
                raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
            for typed, (modifiers, codes) in enumerate(reports):
                # All that while it is this program pressing keys, and a long text takes a minute: keep the console
                # from being given back, and ask now and then whether whoever asked for it may still have it done.
                self._console_wanted_at = time.monotonic()
                if typed and typed % TYPE_ASK_EVERY == 0 and still is not None and not still():
                    raise KvmError("stopped", f"Typing was stopped after {typed} of {len(reports)} keys: whoever asked for it may no longer do that", 403)
                down = True  # (from the moment the press may have gone out)
                try:
                    await self.send_keyboard(modifiers, codes, era)
                    await asyncio.sleep(KEY_PAUSE if action == "text" else HOLD)
                    await self.send_keyboard(0, [], era)  # nothing stays down: a key held repeats on the server until it is let go
                    down = False
                except BaseException:
                    if down:
                        self._let_go_soon(era)  # (stopped in between, or the release did not go out: owed, in a task of its own)
                    raise
                await asyncio.sleep(KEY_PAUSE)

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """The server's screen, from its controller's console. The first one asked for opens the console."""
        if self._other is not None:
            raise self._other.with_traceback(None)  # (another server answers at the address: see `_judge`)
        rfb_screen = await self._openbmc_known()
        if rfb_screen is not None:
            return await rfb_screen.snapshot(width, fresh)
        arrived = self._console_wanted_at = time.monotonic()
        console = self._console_with_a_picture(arrived)
        # Its size and its bytes in one look: the next frame may be of another size, and is read in another thread.
        shown_width, shown_height, shown = console.screen.shown
        size = tier_for(width)
        if size != FULL and TIERS[size][0] >= shown_width:
            size = FULL
        async with self._encode_locks[size]:
            cached = console.encoded.get(size)
            # Nothing new since the last viewer asked, or nothing a viewer refreshing this slowly would notice.
            if cached and (cached[0] == console.frames or arrived - cached[1].taken_at < share_window(fresh)):
                return cached[1]
            asked, made_of = time.monotonic(), console.frames
            target = None if size == FULL else TIERS[size][0]
            try:
                data = await asyncio.to_thread(screen_jpeg, shown_width, shown_height, shown, target, QUANTIZER[size])
            except Exception:  # whatever the library that makes it says of a screen caught in the middle of a change
                raise KvmError("no_stream", "The server's screen changed while its picture was being made", 503) from None
            snap = Snapshot(data, "image/jpeg", True, asked)
            console.encoded[size] = (made_of, snap)
            return snap

    async def _run_console(self, console: _Console) -> None:
        try:
            await self._hold_console(console)
        except KvmError as ex:
            console.error = self._console_refusal = ex
            standing = ex.code in STANDING  # asking again will not change it soon
            if console.frames:
                self._console_failures = 0  # it worked until now: this is the first failure, not one more
            ran_its_time = ex.code == "console_time_up" and bool(console.frames) and time.monotonic() - console.since >= CONSOLE_SETTLED
            if ran_its_time:
                # No failure, and nothing to wait for: the next picture asked for opens it again, and the
                # tile keeps the one it has for the moment that takes.
                self._console_retry_at, self._no_screen = time.monotonic(), None
                log.info(
                    "%s: the controller ended its console session after %d minutes, as it does when no key is pressed in one; it is opened again",
                    self.label, round((time.monotonic() - console.since) / 60),
                )  # fmt: skip
                return
            self._console_failures += 1
            if ex.code == "console_held":
                wait = CONSOLE_HELD
            else:
                wait = CONSOLE_GIVE_UP if standing else CONSOLE_RETRY[min(self._console_failures, len(CONSOLE_RETRY)) - 1]
            # (Where its web page said no to the password, not before that may be offered again.)
            wait = max(wait, REJECTED.wait_left(REJECTED.what("web", self.spec)))
            self._console_retry_at = time.monotonic() + wait
            if self._has_console is False:
                # A controller of another make. Nothing is wrong with it, and its tile says how the server is.
                log.info("%s: this controller has no console qKVM reads; its tile shows how the server is", self.label)
            else:
                self._no_screen = ex.message if standing else None
                log.log(
                    logging.INFO if ex.code == "console_held" else logging.WARNING,
                    "%s: no picture of the server's screen: %s (its console said: %s; greeted %s; asked again in %d s)",
                    self.label, ex.message, ", ".join(console.heard) or "nothing",
                    "with 'complete' first" if self._complete_first else "with the pass", wait,
                )  # fmt: skip
        except asyncio.CancelledError:
            raise
        except Exception:  # whatever a controller sends must not take the wall down
            log.exception("%s: the server's console failed", self.label)
            console.error = self._console_refusal = KvmError("dropped", "The connection to the server's console failed")
            self._console_failures += 1
            self._console_retry_at = time.monotonic() + CONSOLE_RETRY[min(self._console_failures, len(CONSOLE_RETRY)) - 1]
        else:
            self._console_refusal = None
            self._console_failures = 0
        finally:
            console.done.set()
            # The screen (megabytes of it) is not kept beyond the connection it came over, and a frame of it
            # that is still being read is let go of: a thread cannot be told to stop, only to see that it may.
            console.encoded.clear()
            console.screen.given_up = True
            console.screen = Screen()

    async def _web(self, method: str, path: str, headers: dict[str, str] | None = None, **kwargs: Any) -> httpx.Response:
        """A request to the controller's own web page (not Redfish): the console is that page's."""
        client = await self._http()
        try:
            return await self._send(client, client.build_request(method, path, headers=headers, **kwargs), MAX_REPLY)
        except httpx.HTTPError as ex:
            raise _transport_error(ex, self.spec.tls) from ex
        finally:
            client.cookies.clear()  # what that page sets is for the console alone, not for every request that follows

    async def _which_server_for_the_console(self) -> None:
        """Which server answers, asked for the console (see `_judge`), with the Redfish session held: before its web page is
        offered the password, and again once its console is open, before anything of it is shown or typed into. Where a
        number is remembered, one of its moments is asked through again a few times, a second apart: the console is not held
        up for one, and nothing goes on the strength of nothing. Still none: a failure of the console's, asked again later
        as any. (Where none is remembered, a moment is no reason to stop: as before there was such a question.)"""
        for asked in range(1, QUESTION_TRIES + 1):
            try:
                await self._checked_read((await self._find())["system"], vital=False)
                return
            except KvmError as ex:
                if ex.code in ("auth_failed", "no_password", "no_sign_in", "another_machine") or ex.code in DOWN_CODES:
                    raise
                if not self.spec.machine:
                    return
                if asked == QUESTION_TRIES:
                    raise
            await asyncio.sleep(QUESTION_AGAIN)

    async def _hold_console(self, console: _Console) -> None:
        """Open the controller's console as its own web page does, and take the screen for as long as it is looked at."""
        if self._has_console is None:
            # AMI's firmware has this address and wants a sign-in for it. A controller that does not know it has another console.
            # (One that answers with an error of its own just then has said neither: asked once, at one of its
            # moments, the server's screen was gone until qKVM was started again.)
            asked = await self._web("GET", "/api/kvm/token")
            if asked.status_code not in (401, 404, 405, 410):
                # (Neither "sign in first" nor "there is no such thing here": too many requests, a moment of
                # its own. Nothing is settled by that, and it is asked again as the console is after a failure.)
                raise KvmError("bad_response", f"The controller did not say whether it has a console (HTTP {asked.status_code})")
            self._has_console = asked.status_code == 401
        if not self._has_console:
            raise KvmError("no_picture", "This controller has no console that qKVM reads yet", 404)
        if not self.spec.password:
            raise KvmError("no_password", "No password saved for this device")
        # The controller's own web page is signed in to with the same password, and a wrong one there counts
        # against the same account. So this road keeps the waits of a rejected password too (it was every ten
        # minutes for good, with the tile saying that all is well), on a count of its own: an account may be
        # let in by the one road and not by the other. And it is taken only once the controller has let this
        # program in the other way: told no there, that is what is said here, and nothing is offered. (It is
        # asked something with the session held, which signs in again where the controller has forgotten
        # that one: a session it no longer knows is no proof, and let the web page be offered the password
        # first, right after the controller was restarted with another one. Only a no stops here: an
        # answer that is one of its moments is none, and held the console up for half a minute and more.)
        # And it is asked strictly which server answers (see `_judge`): another one's web page is not offered the password,
        # and its screen is not shown here, nor typed into.
        await self._which_server_for_the_console()
        web = REJECTED.what("web", self.spec)
        if REJECTED.wait_left(web) > 0:
            if REJECTED.times(web):
                raise KvmError("no_picture", "The controller's web page rejected the saved login: it is not offered again yet", 404)
            # Not a no: its last sign-in there came to nothing (no answer, or one that says neither). Asked
            # again as the console is after any failure, and not said to be rejected.
            raise not_signing_in("the last sign-in to its web page came to nothing")
        # In a task of its own, which being told to stop does not end: the controller makes the session when it
        # answers, wanted or not, and has few. Retired in that very moment (the device taken off the wall, the
        # wall shut down), the answer is waited for all the same, for nothing but to sign out of it again.
        # (Counted as it goes out, like the other sign-in, see Rejected.sent: where that answer does not come
        # in time, nothing was noted of it, and the next connection offered the password here again at once.)
        before = REJECTED.sent(web)
        signing_in = asyncio.ensure_future(
            self._web("POST", "/api/session", data={"username": self.spec.username, "password": self.spec.password}, timeout=sign_in_waits())
        )
        signing_in.add_done_callback(lambda done: done.cancelled() or done.exception())  # (nobody may be left to hear how it ended)
        retired = False
        try:
            # (Not asyncio.shield: where the one who waited is gone and the sign-in fails after, that writes
            # the failure into the log as an error of the program, with where it happened. Waited for this
            # way, being told to stop ends the wait and not the sign-in, which is what is wanted.)
            await asyncio.wait({signing_in})
            signed_in = signing_in.result()
        except KvmError as ex:
            if not self._closed:  # (retired meanwhile, nobody heard how it ended: the mark it went out with stays)
                # Sorted as the other sign-ins are: what went out and came to nothing is held back (an answer
                # nothing is made of among it), what found no connection to be had was not sent.
                reached = ex.__cause__ is None or went_out(ex.__cause__)
                if reached and ex.code in ("timeout", "dropped", "bad_response"):
                    REJECTED.unanswered(web)  # it went out, and nothing came back: not sent again at once
                else:
                    REJECTED.put_back(web, before)  # no connection was to be had, or the like: nothing is kept of it
            raise
        except asyncio.CancelledError:
            retired = True
            # Whoever retires a device tells its tasks to stop more than once, and waits two seconds in all. For
            # that long the answer is waited for here, whatever is said meanwhile; after it the session, if one
            # was made, is left to run out by itself, as it was before.
            until = time.monotonic() + SIGN_IN_OWED
            while not signing_in.done() and time.monotonic() < until:
                try:
                    await asyncio.wait({signing_in}, timeout=max(0.0, until - time.monotonic()))
                except asyncio.CancelledError:
                    continue
            if not signing_in.done() or signing_in.cancelled() or signing_in.exception() is not None:
                raise asyncio.CancelledError from None
            signed_in = signing_in.result()
        try:
            said = read_json(signed_in) if signed_in.status_code == 200 else {}
        except ValueError:
            said = {}
        token = said.get("CSRFToken") if isinstance(said, dict) else None
        cookies = dict(signed_in.cookies.items())
        if not (isinstance(token, str) and HANDED.fullmatch(token) and cookies and all(HANDED.fullmatch(part) for pair in cookies.items() for part in pair)):
            # A no, in the numbers a wrong password is answered with (one says 400). Anything else is none:
            # too many sessions, a moment of its own, a page that is not what was expected. Those are asked
            # again after ten minutes, as before; taken for a no, the server's screen stayed away for an hour.
            if signed_in.status_code in (400, 401, 403):
                REJECTED.said_no(web)
            else:
                # (Neither yes nor no. In this connection the ten minutes stand; a connection made anew in them
                # knew of nothing, and offered the password again at once. Kept beside them, like the rest.)
                REJECTED.unanswered(web)
            raise KvmError("no_picture", f"The controller's web page did not sign this user in (HTTP {signed_in.status_code})", 404)
        REJECTED.accepted(web)
        headers = {"X-CSRFTOKEN": token, "Cookie": "; ".join(f"{name}={value}" for name, value in cookies.items())}
        try:
            if retired:
                raise asyncio.CancelledError
            # Asked again now that its web page has signed this program in, before it hands out the pass: the address that
            # answered that sign-in may have changed hands since the question before it, and its console (the screen on this
            # tile, the keys of a live line) is not opened to another server. (The moments between are not bound.)
            await self._which_server_for_the_console()
            asked = await self._web("GET", "/api/kvm/token", headers)
            try:
                given = read_json(asked) if asked.status_code == 200 else {}
            except ValueError:
                given = {}
            given = given if isinstance(given, dict) else {}
            console_pass, own, session = given.get("token"), as_text(given.get("client_ip")), as_text(given.get("session"))
            if not (isinstance(console_pass, str) and CONSOLE_PASS.fullmatch(console_pass)):
                raise KvmError("no_picture", f"The controller gave no pass for its console (HTTP {asked.status_code})", 404)
            if said_yes(given.get("automatic_off")) and said_yes(given.get("local_monitor_off")):
                # Whoever stands at the server would see that. It is not "only looking" any more.
                raise KvmError("no_picture", "The controller is set to switch the server's own monitor off while its console is open, so qKVM leaves the console alone", 404)
            if self._complete_first is None:
                # The firmware says what it can do. Whether a console may reconnect decides how it wants to be greeted.
                try:
                    can = await self._web("GET", "/api/configuration/project", headers)
                    self._complete_first = can.status_code == 200 and ami.RECONNECTS in can.text[:MAX_REPLY]
                except KvmError:
                    self._complete_first = False
                log.info("%s: its console is greeted %s", self.label, "with 'complete' first (its firmware lets a console reconnect)" if self._complete_first else "with the pass")
            host = urlsplit(self.spec.base_url).netloc
            await self._watch_console(console, headers["Cookie"], console_pass, own, as_text(given.get("server_ip") or "") or host, session)
        finally:
            # A controller has few web sessions to give out. This one is given back whatever happened: in a
            # task of its own, waited for here and, where this one is told to stop meanwhile, by whoever
            # retires the device (see close). Done in this task, it was cut short by the second telling,
            # half a second after the first, and a controller that took longer over it kept the session.
            client = self._client
            if client is not None:
                leaving = asyncio.ensure_future(self._leave_its_web_page(client, headers))
                self._leaving.add(leaving)
                leaving.add_done_callback(self._leaving.discard)
                await asyncio.wait({leaving})

    async def _watch_console(self, console: _Console, cookie: str, console_pass: str, own: str, controller: str, session: str) -> None:
        url = "ws" + self.spec.base_url[len("http"):] + "/kvm"
        origin = self.spec.base_url.rstrip("/")
        try:
            connection = await ws_connect(
                url, additional_headers={"Cookie": cookie}, origin=origin, subprotocols=["binary", "base64"],
                ssl=self._tls, open_timeout=CONSOLE_OPENING, close_timeout=1,
                # What may arrive in one go, and how much may wait to be read while a frame is: megabytes, not half a gigabyte.
                max_size=ami.LONGEST + 64, max_queue=2,
                # No pings of the library's own: a real controller does not answer them, and the library then hangs
                # up after forty seconds on a console that is sending the screen. Whether it is alive is seen by
                # what arrives (CONSOLE_QUIET): it asks "still there?" every few seconds itself.
                ping_interval=None,
            )  # fmt: skip
        except TimeoutError as ex:
            raise KvmError("timeout", "The controller's console did not answer in time", 504) from ex
        except (OSError, WebSocketException) as ex:
            raise KvmError("dropped", f"The controller's console could not be opened ({type(ex).__name__})") from ex
        plain_bytes = connection.subprotocol == "binary"
        mine = False  # the controller said this session's console is this program's, and has not given it to anybody since

        async def send(data: bytes) -> None:
            # Within a time: a controller that has stopped listening would hold this for ever, and with it the
            # two checks that end a session (nobody looking, nothing heard), which are made between two things said.
            # (Not wait_for, which up to Python 3.11 loses a stop that comes as the sending is done: this is said
            # in the loop that reads the console, and the loop went on. See Listening.message.)
            # Under a lock: keys and the mouse go out over this same connection, from the lines that hold them, while
            # this loop sends its own answers; two senders at once on one connection is the library's to forbid, not ours.
            # The time counts the wait for the lock too: behind keys that do not go, this loop would read nothing.
            try:
                async with asyncio.timeout(CONSOLE_SAY), self._say_lock:
                    await connection.send(data if plain_bytes else base64.b64encode(data).decode())
            except TimeoutError:
                raise KvmError("dropped", "The controller's console stopped taking what is said to it") from None
            except ConnectionClosed:
                # It has hung up. It may have said why just before (that the session's time is up, say), and
                # that has arrived and is not read yet: what it said counts before the fact that it left.
                # Whoever looks next for what arrived reads it, and is told there that the connection is closed.
                pass

        async def send_input(data: bytes, era: int) -> None:
            # Keys and the pointer, from whoever holds them: within a shorter time than the loop's own answers, never
            # into a console that was given to somebody meanwhile, has ended, or has changed hands since the era they
            # were begun in (asked once the lock is had, so that nothing gets in after the letting go that came before
            # the giving, and nothing of an earlier era once the console came back); and a connection that has closed
            # is said to be closed: a key, or its letting go, does not look delivered when it went nowhere.
            try:
                async with asyncio.timeout(INPUT_SAY), self._say_lock:
                    if self._handed_over:
                        raise handed_over()
                    if self._live_send is not send_input or era != self._input_era:
                        raise self._input_lost.with_traceback(None)
                    await connection.send(data if plain_bytes else base64.b64encode(data).decode())
            except TimeoutError:
                raise KvmError("dropped", "The server's console stopped taking keys and the mouse") from None
            except ConnectionClosed:
                raise KvmError("dropped", "The server's console was closed") from None

        async def release_held() -> None:
            # What this program has down on the server, as far as it has said, let go of over this session: before the
            # console is given to somebody, and before the session ends (a typing cut off by the tile's removal, say).
            if self._held_keys:
                self._held_keys = False
                await send(ami.keyboard(0, [], self._next_seq()))
            if self._held_buttons:
                self._held_buttons = 0
                if self._mouse_at is not None:
                    await send(ami.mouse_abs(0, *self._mouse_at, 0, self._next_seq()))
                else:
                    await send(ami.mouse_rel(0, 0, 0, 0, self._next_seq()))

        async def give_up_input() -> None:
            # The console goes to somebody else. What this program has down there is let go of: first, where it still
            # holds the console (it is about to let a person in); at once, where the controller has just said it is
            # another's. That one letting go is the only thing of this program's that goes into a console that is
            # another's: a key left down repeats on the server, while an empty report can at most lift for a moment a
            # key the newcomer holds, which their next report (the whole keyboard) puts down again. Then nothing more
            # of this program's goes, and whoever held the keyboard over a live line is told so at their next key.
            nonlocal mine
            self._handed_over = True
            self._input_ends(handed_over())
            if mine:  # (what was noted down was noted in this session's hold of the console)
                await release_held()
            mine = False
            self._held_keys, self._held_buttons = False, 0

        arriving, frames = ami.Messages(), ami.Frames()
        heard_at = said_at = time.monotonic()
        unread = 0
        greeted = accepted = read_any = False
        heard = Listening(connection, ami.LONGEST + 64)
        who, let_in = b"", 0  # whoever else is at the console, as the controller last named them; how much was said since they were let in
        answered = 0  # how often somebody asking for the console was let in
        try:
            while True:
                now = time.monotonic()
                if now - self._console_wanted_at > CONSOLE_IDLE:
                    return  # nobody is looking: the seat is given back
                if now - heard_at > CONSOLE_QUIET:
                    raise KvmError("dropped", "The controller's console went quiet")
                try:
                    data = await heard.message(1.0)
                except TimeoutError:
                    data = b""
                except WebSocketException as ex:
                    if greeted and not accepted:
                        # It closed on the greeting, without a word about the pass: it wants to be greeted the other way.
                        self._complete_first = not self._complete_first
                    raise KvmError("dropped", "The controller closed its console") from ex
                if isinstance(data, str):
                    try:
                        data = base64.b64decode(data, validate=True)
                    except ValueError:
                        raise KvmError("bad_response", "The controller's console sent something that is not its protocol") from None
                if data:
                    heard_at = time.monotonic()
                try:
                    messages = arriving.feed(data)
                except Garbled as ex:
                    raise KvmError("bad_response", f"The controller's console sent {ex}") from None
                for one in messages:
                    if len(console.heard) < 24:
                        console.heard.append(f"{one.kind}/{one.status}/{len(one.body)}")
                    if one.kind == ami.ALLOWED:
                        await send(ami.hello(console_pass, own, controller, complete_first=bool(self._complete_first)))
                        greeted = True
                    elif one.kind == ami.PASS_SEEN:
                        answer = one.body[0] if one.body else 0
                        if answer != 1:
                            raise KvmError("no_picture", f"The controller refused: {PASS_REFUSED.get(answer, f'its console answered {answer}')}", 404)
                        if accepted:
                            # Said a second time in one session, which a controller does not: what it means is not known.
                            # The session ends here, letting go of what was sent down first (see the finally).
                            raise KvmError("bad_response", "The server's console said its pass was taken a second time")
                        accepted = True
                        # A session of this program's, and nothing down in it yet; its report numbers begin again at zero,
                        # as the controller's own viewer's do. Keys and the pointer wait for "the console is yours" (below).
                        self._accepted_at = time.monotonic()
                        self._input_from = self._accepted_at + (HID_SETTLE if one.status == ami.FIRST_SESSION else 0.0)
                        self._hid_seq = 0
                        self._handed_over = False
                        self._held_keys, self._held_buttons, self._mouse_at = False, 0, None
                    elif one.kind == ami.MOUSE_MODE:
                        said = one.body[0] if one.body else 0
                        if said in (ami.ABSOLUTE, ami.RELATIVE):
                            self._mouse_mode = said
                    elif one.kind == ami.STILL_THERE:
                        await send(ami.message(ami.STILL_THERE))
                    elif one.kind == ami.OTHERS:
                        await send(ami.message(ami.FULL_SCREEN, 1))
                    elif one.kind == ami.LICENCE:
                        await send(ami.message(ami.WEB_SESSION, 0, session.encode("ascii", "replace")[:35].ljust(35, b"\0")))
                    elif one.kind == ami.TOO_MANY:
                        raise KvmError("in_use", "Every console seat of this controller is taken", 409)
                    elif one.kind in (ami.SHARING, ami.NEXT_HOLDER):
                        about, answer = one.status & 0xFF, one.status >> 8
                        if 0 < len(one.body) <= WHO:
                            who = one.body
                        if 0 < let_in <= 8:
                            let_in += 1
                            log.info("%s: after that its console said %d/%d (%d bytes)", self.label, one.kind, one.status, len(one.body))
                        if about == ami.BECAME_MASTER and one.kind == ami.NEXT_HOLDER and answer == ami.LET_IN and accepted and self._live_send is not send_input:
                            # "The console is yours" (a lone session is greeted so, and one that gets the console back):
                            # from here on keys and the pointer may go. Whoever began in an earlier era begins again. (Said
                            # again while it is this program's already, it changes nothing: a new era then would leave
                            # what a line has down with nobody to let it go.)
                            self._handed_over = False
                            self._input_era += 1
                            self._input_lost = KvmError("dropped", "The server's console changed hands: take its keyboard again")
                            self._live_send = send_input
                            self._can_input.set()
                            mine = True
                        elif about == ami.BECAME_MASTER and one.kind == ami.SHARING and mine:
                            # The console was switched to another session: what this program had down is let go of, and
                            # nothing more of its goes into it.
                            await give_up_input()
                        if about == ami.ASKED and who and answered < LET_IN_AT_MOST:
                            # Somebody opened the controller's own console while the wall has it, and the wall is asked
                            # whether they may. Nobody sits at the wall to answer, and unanswered they wait half a
                            # minute. They have the console at once, keys and all, and the wall goes on looking. What
                            # a live line had down on the server is let go of first, and the line has the keyboard no
                            # more. (A person asks once. A controller that asks without end is not answered without end.)
                            answered += 1
                            await give_up_input()
                            await send(ami.let_in(who))
                            if not let_in:
                                let_in = 1
                                log.info("%s: somebody opened the server's own console, and was let in at once (asked as %d/%d)", self.label, one.kind, one.status)
                        elif about == ami.WAITING or (about == ami.ANSWERED and answer in (ami.TURNED_AWAY, ami.SHUT_OUT)):
                            # Somebody had the console first, and is being asked whether the wall may look. A question
                            # on the screen of somebody at work, and unanswered the console would pass to the wall:
                            # the wall does not wait for the answer. It leaves, and looks again much later.
                            minutes = max(1, round(CONSOLE_HELD / 60))
                            again = "in a minute" if minutes == 1 else f"in {minutes} minutes"
                            raise KvmError("console_held", f"Somebody is using this server's console. The wall keeps out of their way, and looks again {again}", 409)
                    elif one.kind in (ami.STOP, ami.REFUSED):
                        why = ami.ENDED.get(one.status, f"its reason: {one.status}") if one.kind == ami.STOP else f"refused, its reason: {one.status}"
                        code = "console_time_up" if (one.kind, one.status) == (ami.STOP, ami.TIME_UP) else "dropped"
                        raise KvmError(code, f"The controller ended the console session ({why})")
                    elif one.kind == ami.VIDEO:
                        try:
                            whole = frames.piece(one.body)
                            if whole is not None:
                                began = time.perf_counter()
                                # Off the thread that serves every browser: a busy screen takes a second or two to read.
                                changed = await asyncio.get_running_loop().run_in_executor(_READERS, console.screen.read, whole[0], whole[1])
                                unread, read_any = 0, True
                                if not changed and not console.frames:
                                    # A console opened again begins with a frame that says "nothing changed" (a real
                                    # board's, of 16 bytes); the whole screen follows when asked for. Until it does
                                    # there is no picture, and a black one is not shown in its place.
                                    continue
                                console.frames += 1
                                if console.frames == 1:
                                    console.since = time.monotonic()
                                    log.info(
                                        "%s: the server's screen is on the wall (%d by %d; the first frame, %d bytes, read in %.2f s)",
                                        self.label, console.screen.width, console.screen.height, len(whole[1]), time.perf_counter() - began,
                                    )  # fmt: skip
                        except Garbled as ex:
                            frames, unread = ami.Frames(), unread + 1
                            if unread >= UNREADABLE:
                                raise KvmError("no_picture", f"The controller sends a picture qKVM does not read yet ({ex})", 404) from None
                if read_any and time.monotonic() - said_at > 1.0:
                    await send(ami.message(ami.BEHIND))  # "every frame so far has been drawn"
                    said_at = time.monotonic()
        except WebSocketException as ex:
            raise KvmError("dropped", "The controller closed its console") from ex
        finally:
            # Nothing more of any line's goes out over a console that is ending. A line that held the keyboard lets go
            # of what it had down through `release_all` while the console is still open (see live.py); what is still
            # down by this program's word (a typing cut off as the tile was removed) is let go of here, before the
            # goodbye, where this session still holds the console: into one that is somebody else's nothing goes.
            # (A real board also let go of a key left down when the session ended, by a goodbye or by a dropped
            # connection.)
            self._input_ends(KvmError("dropped", "The server's console was closed"))
            self._accepted_at, self._handed_over = None, False
            if not mine:
                self._held_keys, self._held_buttons = False, 0
            try:
                if greeted:
                    # Said as the controller's own page says it when its window is closed: a console that just goes
                    # away is waited for by the controller, which is then slow to answer anybody. Said from the
                    # greeting on, not from the pass being found good: who else is there is said before that.
                    async with asyncio.timeout(2):
                        await release_held()
                        await send(ami.goodbye())
            except (TimeoutError, OSError, WebSocketException, KvmError):
                pass  # it is not listening (which may be why this is the end): the connection is closed all the same
            except BaseException:
                # Told to stop once more while the goodbye was being said (whoever retires a device tells its tasks
                # again after half a second): the connection is ended here and now. Left to the close below, which
                # this skips, it stayed open, and the controller kept the console's seat for as long as it liked.
                connection.transport.abort()
                raise
            try:
                async with asyncio.timeout(3):
                    await connection.close()
            except (TimeoutError, OSError, WebSocketException):
                pass

    async def console(self) -> str:
        """The way into the server's own console, good for one use: a page on the controller, with a pass.

        Whoever holds the pass uses the console as the account this wall signs in with. It goes to the
        browser of the person who asked for it and nowhere else: not into the log, not into the activity log.
        Every call has the controller make out a new one, so this is asked when somebody wants in, not before.
        """
        await self._same_server(urgent=True)  # (another server's console is not handed out as this one's: see `_judge`)
        itself = await self._itself(urgent=True)
        if not itself["known"]:
            raise KvmError("bad_response", "The controller did not say where its console is just now")
        place = itself["console"]
        if place is None:
            raise KvmError("no_console", "This controller does not hand out a way into its console", 404)
        offered, _ = await self._read(place, urgent=True, command=True)  # (made out under the session the server was asked under)
        way_in = offered.get("URI")
        kind = offered.get("Interface")  # (said or not; a controller that says nothing of it hands out a page)
        for_a_browser = not kind or (isinstance(kind, str) and "html" in kind.lower())  # not a program to download and run
        if not for_a_browser or not isinstance(way_in, str) or not CONSOLE.fullmatch(way_in):
            raise KvmError("bad_response", "The controller's way into its console is not one a browser can simply open")
        return way_in

    def _stale(self) -> bool:
        return self._status is None or time.monotonic() - self._status_at > (RETRY_LOOK if self._hiccup else LOOK_EVERY)

    async def _read_status(self) -> dict[str, Any]:
        try:
            places = await self._find()
            # Which server answers, at every look, as before a button: what the tile shows of a server is this one's, and
            # another one's power, sensors and name do not go into its history, alerts and metrics.
            system, _ = await self._checked_read(places["system"])
        except KvmError as ex:
            if ex.code == "another_machine":
                # (Said at once, and not as one of its moments: nothing of the other server's is shown as this one's.)
                self._hiccup = False
                return {"state": "error", "error": ex.as_dict(), "kind": self.kind, "picture": False}
            if ex.code in ("auth_failed", "no_password", "no_sign_in", "bad_response"):
                ex = await self._gone_meanwhile(ROOT) or ex
            if ex.code in ("auth_failed", "no_password"):
                state = "auth"
            elif ex.code in ("cert_mismatch", "cert_invalid", "bad_response", "no_sign_in"):
                state = "error"
            else:
                state = "offline"
            # Not being let in, and not being who it was, are said at once. The rest may be one of its moments.
            passing = state != "auth" and ex.code not in ("cert_mismatch", "cert_invalid")
            if passing and self._good is not None and time.monotonic() - self._good_at < HICCUP:
                self._hiccup = True
                return self._good
            self._hiccup = False
            return {"state": state, "error": ex.as_dict(), "kind": self.kind, "picture": False}

        temperatures, fans = await self._sensors(places)
        about = await self._read_about(system)

        power = plain(system.get("PowerState"), 20)
        on = None if power is None else power not in ("Off", "PoweringOff")
        self._power = on
        processors = [t["celsius"] for t in temperatures if "cpu" in t["name"].lower()]
        health = plain(_dig(system, "Status", "HealthRollup") or _dig(system, "Status", "Health"), 20)
        # One board calls its processor "Intel Xeon E-2336 CPU      , 2900 Mhz, 6 Core(s), ...".
        processor = (named(_dig(system, "ProcessorSummary", "Model")) or "").split(",")[0].strip() or None
        unwell = [sensor["name"] for sensor in (*temperatures, *fans) if not sensor["ok"] and sensor["name"]]
        if health == "Critical":
            # Its own verdict on itself, and the one thing here that somebody has to come and look at.
            where = f" ({', '.join(unwell[:3])})" if unwell else ""
            state, error = "error", {"code": "health", "message": f"The server reports a critical fault{where}"}
            self._fault_at, self._fault_where = time.monotonic(), where
        elif self._fault_at is not None and time.monotonic() - self._fault_at < FAULT_HOLD:
            said = f"The server reported a critical fault{self._fault_where} a moment ago: it comes and goes"
            state, error = "error", {"code": "health", "message": said}
        else:
            # A server that is switched off is to the wall what a computer without a picture is: there, and dark.
            state, error = "no_signal" if on is False else "online", None
        showing = self._console.screen if self._console is not None and self._console.frames else None
        width, height = (showing.width, showing.height) if showing is not None else (None, None)
        # What stood in the way is said until it is time to ask again. Then the tile asks, and it is found out anew:
        # a setting may have been changed, whoever had the console may have left.
        no_screen = self._no_screen if time.monotonic() < self._console_retry_at else None
        itself = await self._itself()  # (first: it may say there is no console of either kind)
        has_screen = self._has_console is not False and no_screen is None
        rfb_screen = self._openbmc_screen()
        if rfb_screen is not None:
            # OpenBMC's console: what its last session said, and the size of the screen while one is open.
            no_screen = rfb_screen.refused_now()
            has_screen = no_screen is None
            width, height = rfb_screen.size() or (None, None)
        way_in = itself["console"] is not None  # "Open console" can lead straight in, signed in
        light = locator(system)[0]  # the light to find it by in a rack: on, off, or None where there is none
        # Where its screen is being had over AMI's console, so can keys, typed text and the pointer. Only once the
        # console is known to be AMI's (not optimistically, as the screen is): keys offered on a controller that
        # turns out to have none would mislead. OpenBMC's console (rfb_screen) is read only, and has no keys.
        keys_now = has_screen and rfb_screen is None and self._has_console is True and not self._handed_over
        # ...and not while a session of this program's is open that another holds (a holder coming back, picture only).
        keys_now = keys_now and (self._accepted_at is None or self._live_send is not None)
        found = {
            "state": state,
            "error": error,
            "kind": self.kind,
            "picture": False,
            # Whether a picture of its screen can be asked for (see `snapshot`). Asked for, it may still not come.
            "screen": has_screen,
            # (`live` with `screen`: the live line shows the same screen; over AMI's console it carries keyboard and mouse too.)
            "can": can_do(
                *self.can,
                "screen" if has_screen else None,
                "console" if way_in else None,
                "locator" if light is not None else None,
                "live" if has_screen else None,
                "bios_setup" if "BiosSetup" in boot_targets(system) else None,
                *(("keys", "text", "control") if keys_now else ()),
            ),
            "video": {"signal": on, "width": width, "height": height, "fps": None},
            "usb": {"keyboard": None, "mouse": None},
            "atx": {"enabled": True, "power": on, "hdd": None},
            "health": {"temp": max(processors or [t["celsius"] for t in temperatures], default=None), "cpu": None, "mem": None},
            "about": about,
            "ports": None,
            "console": way_in,
            "server": {
                "power": power,
                "health": health,
                "processor": processor,
                "processors": number(_dig(system, "ProcessorSummary", "Count"), 1, 1024),
                "memory_gib": number(_dig(system, "MemorySummary", "TotalSystemMemoryGiB"), 0, 1_000_000),
                "temperatures": temperatures,
                "fans": fans,
                "unwell": unwell[:MAX_SENSORS],  # the sensors the controller is not happy with, by name
                "locator": light,
                "no_screen": no_screen,  # why its screen is not shown, where it could be and is not
                # Where the controller is OpenBMC with its KVM: the WebSocket on it that carries RFB (see rfb_console),
                # which is the screen this tile shows (openbmc.py).
                "rfb_console": itself["rfb"],
            },
        }
        self._good, self._good_at, self._hiccup = found, time.monotonic(), False
        return found

    # --- the power button -----------------------------------------------------------

    async def _offered(self, resource: dict[str, Any], action: str) -> tuple[str | None, list[str]]:
        """Where an action of a resource is sent, and which kinds of it the controller offers ([]: it does not say)."""
        described = _dig(resource, "Actions", action)
        kinds = _dig(described, "ResetType@Redfish.AllowableValues")
        info = link(_dig(described, "@Redfish.ActionInfo"))
        if not isinstance(kinds, list) and info:
            try:
                parameters = (await self._get(info, urgent=True, vital=False)).get("Parameters")
            except KvmError:
                parameters = None
            kinds = next((p.get("AllowableValues") for p in listed(parameters) if isinstance(p, dict) and p.get("Name") == "ResetType"), None)
        return link(_dig(described, "target")), [kind for kind in listed(kinds) if isinstance(kind, str)]

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """What the wall's power buttons mean to a server:

        'power_on'        switch on; a server that is on is left as it is (AlreadySo)
        'power_off'       ask the operating system to shut down; a server that is off is left as it is
        'atx_power'       the power button: whichever of those two applies
        'atx_power_long'  hold the power button: off, now
        'atx_reset'       the reset button
        'reboot'          restart the controller itself; the server is not touched
        'bios_setup'      start into the BIOS setup once (set BootSourceOverrideTarget "BiosSetup", then power on or restart)
        'locate_on'       light the server up, for whoever is looking for it in the rack
        'locate_off'      and put that light out again

        And over its console, where that is AMI's and shows the screen: 'keys' presses a combination, 'text' types,
        'ctrl_alt_del' sends that one.
        """
        if action in ("locate_on", "locate_off"):
            await self._locate(action == "locate_on", still)
            return
        if action in ("keys", "text", "ctrl_alt_del"):
            await self._type(action, keys=keys, text=text, still=still)
            return
        if action == "bios_setup":
            await self._boot_into_setup(still)
            return
        if action not in ("reboot", "power_on", "power_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A management controller cannot do that", 422)
        places = await self._find(urgent=True)
        # Which server answers, asked before anything is sent to it (the controller's restart included): what decides the
        # command is this read, and the command goes under the session it was answered under (see `_request`).
        system, _ = await self._checked_read(places["system"], urgent=True)
        if action == "reboot":
            if "manager" not in places:
                raise KvmError("action_failed", "This controller does not say how to restart it")
            place, name, wanted = places["manager"], "#Manager.Reset", ["ForceRestart", "GracefulRestart"]
            resource = await self._get(place, urgent=True)
        else:
            place, name = places["system"], "#ComputerSystem.Reset"
            resource = system
            running = plain(resource.get("PowerState"), 20) not in ("Off", "PoweringOff")
            if action in ("power_on", "power_off") and running == (action == "power_on"):
                # Asked for by what is wanted, not by which button: forty servers ticked after a power cut,
                # of which some came back by themselves, are not to be sorted into two piles by hand first.
                raise AlreadySo("already on" if running else "already off")
            wanted = {
                "power_on": ["On"],
                "power_off": ["GracefulShutdown"],
                "atx_power": ["GracefulShutdown"] if running else ["On"],
                "atx_power_long": ["ForceOff"],
                "atx_reset": ["ForceRestart", "PowerCycle"],
            }[action]
        target, offered = await self._offered(resource, name)
        kind = next((kind for kind in wanted if not offered or kind in offered), None)
        if kind is None:
            raise KvmError("action_failed", f"This controller does not offer {wanted[0]}")
        target = target or f"{place.rstrip('/')}/Actions/{name[1:]}"
        try:
            # (Finding the way there took several questions, and a controller is slow over each: asked now.)
            reply = await self._request("POST", target, urgent=True, still=still, command=True, json={"ResetType": kind})
        except KvmError as ex:
            if action == "reboot" and ex.code in ("dropped", "timeout"):
                return  # a controller that is already going down may never answer
            raise
        self._accepted(reply)
        seen_by = {"On": True, "ForceOff": False}.get(kind) if name == "#ComputerSystem.Reset" else None
        if seen_by is not None:
            await self._carried_out(place, seen_by)

    async def _boot_into_setup(self, still: Callable[[], bool] | None) -> None:
        """Start the server into its BIOS firmware setup, once: set Boot.BootSourceOverrideTarget to "BiosSetup" with
        BootSourceOverrideEnabled "Once", where the controller says it allows that target, then switch the server on where
        it is off, or restart it where it is on.

        Nothing is set where the board does not allow "BiosSetup" (it is not offered the action), where another tool's
        override is set (it is not replaced), where the server is between states, or where the controller offers no such
        power change. From the moment the override may be set, every way out says whether it is: cleared again wherever no
        power change went out or one was refused for certain (no ordinary boot, an update at night or a crash, is to land
        in the setup), and left set, and said so, wherever a power change may have gone through. A press that has not come
        to its restart within SETUP_WITHIN goes no further (see `SetupSteps`); nothing under way is cut off for it."""
        steps = SetupSteps()
        try:
            await self._setup_steps(still, steps)
        except asyncio.CancelledError:
            if steps.at != "looking":
                # qKVM is being stopped: nothing is awaited here (it must not hold the stop up), and whoever reads the log
                # learns what may be left on the server.
                log.warning("%s: stopped while starting into the BIOS setup: its one-time boot override may be set for the next boot", self.label)
            raise

    async def _setup_steps(self, still: Callable[[], bool] | None, steps: SetupSteps) -> None:
        """`_boot_into_setup`'s steps, saying in `steps` how far they came."""
        try:
            place = (await self._find(urgent=True))["system"]
            system, mark = await self._checked_read(place, urgent=True)  # (which server answers: see `_judge`)
        except KvmError as ex:
            if ex is RETIRED or ex.code in ("timeout", "dropped"):
                # (Only a look so far: nothing was sent that changes anything.)
                why = "the tile was changed meanwhile" if ex is RETIRED else ex.message
                raise KvmError("action_failed", f"Nothing was done: the controller could not be read ({why}).") from None
            raise
        if "BiosSetup" not in boot_targets(system):
            raise KvmError("invalid", "This controller does not offer starting into the BIOS setup (it allows no 'BiosSetup' boot override)", 422)
        self._no_other_override(system)
        before = boot_override(system)
        running, kind, target = await self._setup_plan(system)
        if steps.overdue():
            raise KvmError("action_failed", f"Nothing was done: {took_too_long()}.")
        steps.at = "setting"
        reply = await self._set_setup_override(place, mark, still, before, steps)
        if reply.status_code in (412, 428):
            # The state changed since it was read, or the controller wants a mark it did not give (or does not take back the
            # mark it gave): nothing was set. Read again, and looked at again: another tool's override, or a power change
            # meanwhile, is not gone over. Then sent as meant whatever the state, as the locator light is.
            steps.at = "looking"
            try:
                system, _ = await self._checked_read(place, urgent=True, waits=BOOT_WAITS)
            except KvmError as ex:
                if ex.code == "another_machine":
                    raise ex.with_traceback(None) from None  # (nothing was set: said as it is)
                why = "the tile was changed meanwhile" if ex is RETIRED else ex.message
                raise KvmError("action_failed", f"Nothing was done: the controller did not take the BIOS setup boot override, and could not be read again ({why}).") from None
            self._no_other_override(system)
            before = boot_override(system)
            running, kind, target = await self._setup_plan(system)
            if steps.overdue():
                raise KvmError("action_failed", f"Nothing was done: {took_too_long()}.")
            steps.at = "setting"
            reply = await self._set_setup_override(place, "*", still, before, steps)
        if reply.status_code not in (200, 202, 204):
            raise self._refused(reply)  # (a 4xx: refused for certain, and nothing was set; any other is a "maybe", said above)
        steps.changed_at = time.monotonic()
        shown, seen = await self._setup_shown(place, reply, steps)
        pending, whole = shown is not True, shown is True  # (see `_clear_setup_override`)
        if shown is True and seen is not None and plain(seen.get("PowerState"), 20) is not None:
            # Read after the change (a 200 that shows it, or a read back after a 202): the power as that read has it decides
            # what goes out, not the read before the change. A server switched on meanwhile (at its button, by another tool)
            # is restarted, where "On" would be nothing to do to it and the override would wait for its next boot; one that
            # began to change its state is left alone, and the override cleared again. (After a 204 nothing is read: the
            # board this was built on answered no read for a minute then; see the README.)
            power = plain(seen.get("PowerState"), 20)
            try:
                running, kind, target = await self._setup_plan({**system, "PowerState": power})
            except KvmError as ex:
                steps.at = "clearing"
                left = await self._clear_setup_override(place, before, pending, whole)
                if power not in ("On", "Off", "Paused"):
                    lead = f"Nothing was restarted: the server began to change its state ({power}) while the BIOS setup boot override was being set"
                else:
                    lead = f"Nothing was restarted: the server is {str(power).lower()} now, and {ex.message[:1].lower()}{ex.message[1:]}"
                raise self._left(lead, left, pending) from None
        if steps.overdue():
            # Too late for a restart: whoever pressed may have stopped waiting for it. Nothing is restarted, and the override
            # cleared again.
            steps.at = "clearing"
            left = await self._clear_setup_override(place, before, pending, whole)
            raise self._left(f"Nothing was restarted: {took_too_long()} before the restart", left, pending)
        if shown is False:
            # It took the change and does not show it (or not yet): no restart, since it would not land in the setup, and the
            # override cleared, in case it is made later.
            steps.at = "clearing"
            left = await self._clear_setup_override(place, before, True, False)
            raise self._left("Nothing was restarted: the controller took the BIOS setup boot override and does not show it set", left, True)
        what = "restart" if running else "switching on"
        target = target or f"{place.rstrip('/')}/Actions/ComputerSystem.Reset"
        steps.at = "restarting"

        def in_time() -> bool:
            # Asked before the restart goes out, also again where the controller wanted a new sign-in first: not after the
            # press's time, nor once whoever pressed may no longer do it.
            return not steps.overdue() and (still is None or still())

        try:
            reply = await self._request("POST", target, urgent=True, still=in_time, command=True, json={"ResetType": kind}, timeout=BOOT_WAITS)
        except KvmError as ex:
            if not never_sent(ex):
                # Gone, or perhaps gone, and its answer lost or not read: the restart may have been done, and the override is
                # set for the next boot.
                why = "the tile was changed meanwhile" if ex is RETIRED else ex.message
                raise KvmError("timeout", f"The BIOS setup boot is set for the next boot, and the {what} may or may not have gone through ({why}). Look at the server: if it did not start, the next boot of any kind will land in the BIOS setup.", 504) from None
            steps.at = "clearing"
            left = await self._clear_setup_override(place, before, pending, whole)
            if ex.code == "stopped" and steps.overdue():
                raise self._left(f"Nothing was restarted: {took_too_long()} before the restart", left, pending) from None
            raise self._unset(ex, left, self._may_be_set(left, pending)) from None  # (it never went out)
        if 400 <= reply.status_code < 500:
            # Refused, for certain: the override is cleared again, so no ordinary boot lands in the setup.
            steps.at = "clearing"
            left = await self._clear_setup_override(place, before, pending, whole)
            raise self._unset(self._refused(reply), left, self._may_be_set(left, pending))
        if reply.status_code not in (200, 202, 204):
            # An error of the controller's own, or an answer no command has: whether the restart was done is not said. The
            # override is left set (it may be what the server is starting into now), and that is said.
            why = f"{'an error of its own' if reply.status_code >= 500 else 'an answer a command does not have'} ({self._said(reply) or f'HTTP {reply.status_code}'})"
            raise KvmError("timeout", f"The BIOS setup boot is set for the next boot, and the controller answered the {what} with {why}: it may or may not have gone through. Look at the server: if it did not start, the next boot of any kind will land in the BIOS setup.", 504)
        self._accepted(reply)
        if running:
            return
        steps.at = "waiting"
        # (Through the minute after the change in which the board answered no read, and CONFIRM_WITHIN after it.)
        busy = max(0.0, steps.changed_at + BOOT_BUSY - time.monotonic())
        try:
            await self._carried_out(place, True, within=busy + CONFIRM_WITHIN)
        except KvmError as ex:
            # Taken, and not seen done (or the wait cut short): the server may still start into its setup later, so the
            # override is left set (clearing it could race a slow start), and that is said.
            if ex is RETIRED:
                raise KvmError("timeout", "The server was told to switch on, and it was not seen to start, the tile being changed meanwhile: it may have been done. The BIOS setup boot override stays set for the server's next start.", 504) from None
            raise KvmError(ex.code, f"{ex.message} The BIOS setup boot override stays set for the server's next start.", ex.status) from None

    @staticmethod
    def _may_be_set(left: str | None, pending: bool) -> bool:
        """Whether what a clearing said (`_clear_setup_override`) leaves the override perhaps set: it could not be cleared;
        it showed off and was cleared before a change of this press's that may yet be made (CLEARED_LATE); or another tool's
        override was found where this press's change may yet be made."""
        return left in (NOT_CLEARED, CLEARED_LATE) or (pending and left is not None and left != SET_BEFORE)

    def _left(self, lead: str, left: str | None, pending: bool) -> KvmError:
        """What a press that restarted nothing says, `lead` first, then what became of the override."""
        if left is None:
            return KvmError("action_failed", f"{lead}; the BIOS setup boot override was cleared again.")
        if self._may_be_set(left, pending):
            return KvmError("timeout", f"{lead}; {left}. Look at the server's boot override, or start into BIOS setup again.", 504)
        return KvmError("action_failed", f"{lead}; {left}.")

    async def _setup_plan(self, system: dict[str, Any]) -> tuple[bool, str, str | None]:
        """For Start into BIOS setup, from the computer as read: whether it runs, which reset to send, and where (None: the
        usual place). KvmError, with nothing done, where the server is between states or no such power change is offered."""
        power = plain(system.get("PowerState"), 20)
        if power not in ("On", "Off", "Paused"):
            # Switching on, shutting down, or not said: neither "switch on" nor "restart" is sure to be right.
            said = f"changing its state just now ({power})" if power else "in a state its controller does not say"
            raise KvmError("action_failed", f"Nothing was done: the server is {said}. Try again in a moment.")
        running = power != "Off"
        wanted = ["ForceRestart", "GracefulRestart", "PowerCycle"] if running else ["On"]
        target, offered = await self._offered(system, "#ComputerSystem.Reset")
        kind = next((one for one in wanted if not offered or one in offered), None)
        if kind is None:
            # Nothing is set where it could not be carried out: the server is left as it is.
            raise KvmError("action_failed", f"This controller does not offer {'a restart' if running else 'switching on'} from the state it is in")
        return running, kind, target

    @staticmethod
    def _no_other_override(system: dict[str, Any]) -> None:
        """KvmError (409) where another tool's boot override is set: it is not replaced (a provisioning tool's network boot,
        say, or an override for every boot). One that is what this action sets (pressed before, and not booted since) is set
        again. Compared without regard to case (see `boot_override`)."""
        said = RedfishDevice._another_override(system)
        if said is not None:
            raise KvmError("action_failed", f"Nothing was done: the controller has a boot override set already ({said}). Clear it first.", 409)

    @staticmethod
    def _another_override(system: dict[str, Any]) -> str | None:
        """Another tool's boot override as the controller shows it ("Pxe, Once"); None where there is none, or only this
        action's own."""
        enabled, target = boot_override(system)
        if enabled in ("", "disabled") or (enabled, target) == SETUP_OVERRIDE:
            return None
        boot = _dig(system, "Boot")
        return f"{plain(_dig(boot, 'BootSourceOverrideTarget'), 30) or 'another target'}, {plain(_dig(boot, 'BootSourceOverrideEnabled'), 30)}"

    @staticmethod
    def _not_ours(system: dict[str, Any], before: tuple[str, str], whole: bool) -> str | None:
        """For the clearing: another tool's override as the controller shows it, or None where what shows may be this press's
        own: none, Once/BiosSetup, or, where its change was not seen whole (`whole`), Once with the target there was before
        (its change made in part: Once taken, the target not)."""
        enabled, target = boot_override(system)
        if not whole and enabled == "once" and before[0] in ("", "disabled") and target == before[1]:
            return None
        return RedfishDevice._another_override(system)

    async def _set_setup_override(self, place: str, mark: str | None, still: Callable[[], bool] | None, before: tuple[str, str], steps: SetupSteps) -> httpx.Response:
        """Send the change that sets the BIOS setup boot override, shown `mark` (If-Match; None: none shown), and hand back its
        answer where it says yes (200, 202, 204) or no (4xx). Where it went out and no answer came back, or another answer
        (an error of the controller's own, or one a change does not have), the override may be set: cleared again where the
        controller can be reached, and said either way (KvmError). `before`: the override as it was before (see `_not_ours`)."""
        try:
            reply = await self._request(
                "PATCH", place, urgent=True, headers={"If-Match": mark} if mark else {}, still=still, command=True, json=SETUP_CHANGE, timeout=BOOT_WAITS
            )
        except KvmError as ex:
            if never_sent(ex):
                raise  # (it never went out: nothing was set)
            if ex is RETIRED:
                raise KvmError("timeout", "Nothing was restarted, and the BIOS setup boot override may be set: the tile was changed while it was being set. Look at the server's boot override, or start into BIOS setup again.", 504) from None
            # (Gone, and no answer came back, or one that could not be read: it may have been made.)
            steps.at = "clearing"
            raise self._left(f"Nothing was restarted: the controller's answer to the BIOS setup boot override did not come or could not be read ({ex.message})", await self._clear_setup_override(place, before, True, False), True) from None
        if reply.status_code in (200, 202, 204) or 400 <= reply.status_code < 500:
            return reply
        how = "an error of its own" if reply.status_code >= 500 else "an answer a change does not have"
        steps.at = "clearing"
        left = await self._clear_setup_override(place, before, True, False)
        raise self._left(f"Nothing was restarted: the controller answered the BIOS setup boot override with {how} ({self._said(reply) or f'HTTP {reply.status_code}'})", left, True)

    async def _setup_shown(self, place: str, reply: httpx.Response, steps: SetupSteps) -> tuple[bool | None, dict[str, Any] | None]:
        """Whether the override just set shows as set: True; False where the controller shows that it is not (it took the
        change and did not keep it, or not within CONFIRM_WITHIN, nor before the press runs out of time); None where that
        could not be read (the restart goes out then: the controller said yes to the change, and the restart is what was
        asked for). And the computer as the answer or the read that showed it has it (None: nothing was read), whose power
        decides what goes out (see `_setup_steps`).

        A 204 is the standard's word that the change was made in full (DSP0266, the answer to a PATCH), and is taken as said:
        the real board this was built on answered 204, and two reads right after its change went unanswered (it was busy for
        about a minute). A 200 shows the resource as it now is; a 202 (accepted, to be done) or a 200 that does not show it
        is read back until it shows, as the server it is (another one that took the address meanwhile is no read of it)."""
        if reply.status_code == 204:
            return True, None
        if reply.status_code == 200:
            with contextlib.suppress(ValueError):
                answered = read_json(reply)
                if isinstance(answered, dict) and boot_override(answered) == SETUP_OVERRIDE:
                    return True, answered
        seen = None
        deadline = min(time.monotonic() + CONFIRM_WITHIN, steps.until)
        if steps.overdue():
            return None, None  # (no read past the press's time: it clears instead of restarting, see `_setup_steps`)
        while True:
            try:
                system, _ = await self._checked_read(place, urgent=True, vital=False)
                seen = boot_override(system)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    raise KvmError("timeout", "Nothing was restarted, and the BIOS setup boot override may be set: the tile was changed meanwhile. Look at the server's boot override, or start into BIOS setup again.", 504) from None
                if ex.code == "another_machine":
                    return None, None  # (nothing more is read of it: the restart, bound to this server's session, is refused)
            else:
                if seen == SETUP_OVERRIDE:
                    return True, system
            if time.monotonic() >= deadline:
                return (None if seen is None else False), None
            await asyncio.sleep(CONFIRM_EVERY)

    @staticmethod
    def _unset(ex: KvmError, left: str | None, maybe: bool) -> KvmError:
        """What a Start into BIOS setup whose power change was refused (or never went out) says: what became of the override."""
        if left is None:
            return KvmError(ex.code, f"Nothing was done: the power change did not go through ({ex.message}); the BIOS setup boot override was cleared again.", ex.status)
        if maybe:
            # (A "maybe" as everywhere else, and so in the history: the override may be set.)
            return KvmError("timeout", f"The power change did not go through ({ex.message}); {left}. Look at the server's boot override, or start into BIOS setup again.", 504)
        return KvmError(ex.code, f"Nothing was done: the power change did not go through ({ex.message}); {left}.", ex.status)

    async def _clear_setup_override(self, place: str, before: tuple[str, str], pending: bool, whole: bool) -> str | None:
        """Set the one-time boot override back to Disabled, to the end (each request bounded by its own wait, and nothing cut
        off for the press's time). None where the controller took that (a 200 or 202 only once it shows it); else what is to
        be said of it: SET_BEFORE (set before this press, and showing so still: left as it was), CLEARED_LATE (taken, where
        it showed off already), another tool's override (left as it is: only what may be this press's own is cleared), or
        NOT_CLEARED. Sent also where it shows no override: a change the controller accepted for later (202), or whose answer
        was lost, may be made after this read, and the clearing is to come after it.

        `pending`: this press's change may yet be made. `whole`: it was seen made in full (see `_not_ours`)."""
        change = {"Boot": {"BootSourceOverrideEnabled": "Disabled"}}
        late = ", though this press's change may yet be made late and set the BIOS setup boot" if pending else ""
        off_first = False
        try:
            for shown in ("mark", "*"):
                # (Read as the server it is: another one that took the address meanwhile is neither read for this one nor
                # cleared, and what this one has may be set still.)
                system, mark = await self._checked_read(place, urgent=True, waits=BOOT_WAITS)
                if before == SETUP_OVERRIDE and boot_override(system) == SETUP_OVERRIDE:
                    return SET_BEFORE
                other = self._not_ours(system, before, whole)
                if other is not None:
                    return f"the boot override is another tool's now ({other}), and was left as it is{late}"
                if shown == "mark":
                    off_first = boot_override(system)[0] in ("", "disabled")
                headers = {"If-Match": mark} if shown == "mark" and mark else {"If-Match": "*"} if shown == "*" else {}
                reply = await self._request("PATCH", place, urgent=True, headers=headers, command=True, json=change, timeout=BOOT_WAITS)
                if reply.status_code in (412, 428):
                    continue  # (the state changed meanwhile: read and looked at again, then "*")
                if reply.status_code in (200, 202):
                    left = await self._cleared_shown(place, before, whole, late)
                elif reply.status_code == 204:
                    left = None
                else:
                    return NOT_CLEARED
                # (Where it showed off before the clearing, its showing off now proves nothing of a change of this press's
                # that may come late: the clearing went after it, and that is what is said.)
                return CLEARED_LATE if left is None and pending and off_first else left
        except KvmError:
            pass
        return NOT_CLEARED

    async def _cleared_shown(self, place: str, before: tuple[str, str], whole: bool, late: str) -> str | None:
        """A clearing answered 200 or 202 ("accepted, to be done"): None once the override shows Disabled, read for up to
        CONFIRM_WITHIN; NOT_CLEARED where it does not by then, or cannot be read (a controller that accepts and does nothing
        has been met, for a reset); another tool's override where one shows."""
        deadline = time.monotonic() + CONFIRM_WITHIN
        while True:
            try:
                system, _ = await self._checked_read(place, urgent=True, vital=False)
            except KvmError as ex:
                if ex is RETIRED or self._closed or ex.code == "another_machine":
                    return NOT_CLEARED  # (another server's override says nothing of this one's)
            else:
                if isinstance(system.get("Boot"), dict) and boot_override(system)[0] == "disabled":
                    return None
                other = self._not_ours(system, before, whole)
                if other is not None:
                    return f"the boot override is another tool's now ({other}), and was left as it is{late}"
            if time.monotonic() >= deadline:
                return NOT_CLEARED
            await asyncio.sleep(CONFIRM_EVERY)

    async def _carried_out(self, place: str, on: bool, within: float | None = None) -> None:
        """Wait until the server is seen to be on (or off): only then was the command carried out (see CONFIRM_WITHIN; `within`:
        this long instead). Said not carried out only where a read in that time came back and showed it as it was; where none
        did (the controller busy, another server answering), whether it was done was not seen: "it may have been done"."""
        waited = CONFIRM_WITHIN if within is None else within
        deadline = time.monotonic() + waited
        seen: str | None = None
        while True:
            try:
                system, _ = await self._checked_read(place, urgent=True, vital=False)
                power = plain(system.get("PowerState"), 20)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    # The connection was taken away while this waited (the tile was saved, the last person
                    # signed out). Whether it was carried out was not seen, and that is what is said: taken
                    # for one of its moments, the wait ran out and said "was not carried out" of a
                    # server that may have been switching on.
                    raise RETIRED.with_traceback(None) from None
                power = None  # one of its moments (or another server, which says nothing of this one): it is asked again
            if power == ("On" if on else "Off"):
                return
            seen = power or seen
            if time.monotonic() >= deadline:
                if seen is None:
                    what = "switch on" if on else "switch off"
                    raise KvmError("timeout", f"The controller accepted this, and no look at the server came back in {waited:.0f} seconds to say whether it did {what}: it may have been done. Look at the server before pressing again.", 504)
                still = "off" if on else "on"
                raise KvmError("action_failed", f"The controller accepted this, but the server is still {still}. The command was not carried out.")
            await asyncio.sleep(CONFIRM_EVERY)

    @staticmethod
    def _said(reply: httpx.Response) -> str | None:
        """What the controller said in an error answer, in its own words (None: it said nothing that reads as words)."""
        try:
            said = read_json(reply)
            detail = _dig(said, "error", "@Message.ExtendedInfo") or []
            detail = _dig(detail[0], "Message") if detail else _dig(said, "error", "message")
        except (ValueError, LookupError, TypeError):  # not JSON, or not shaped the way an error is
            detail = None
        return plain(detail, 200)

    def _refused(self, reply: httpx.Response) -> KvmError:
        return KvmError("action_failed", self._said(reply) or f"The controller refused (HTTP {reply.status_code})")

    def _accepted(self, reply: httpx.Response) -> None:
        """Note that the controller did what was asked, or say in its own words why it did not. Only a 4xx is a no; an error
        of its own (5xx), or an answer a command does not have, says neither, and the command may have been done (504: a
        bulk run does not press it again as one that failed)."""
        if 400 <= reply.status_code < 500:
            raise self._refused(reply)
        if reply.status_code not in (200, 202, 204):
            how = "an error of its own" if reply.status_code >= 500 else "an answer a command does not have"
            said = self._said(reply) or f"HTTP {reply.status_code}"
            raise KvmError("timeout", f"The controller answered with {how} ({said}): it may or may not have been done. Look at the server before pressing again.", 504)
        self._status_at = 0.0  # what the tile says is out of date now,
        self._refresh_soon()  # and is read again without waiting to be asked,
        if self._following is not None:
            self._following.cancel()
        self._following = asyncio.create_task(self._follow_up())  # and again while the controller gets round to it

    async def _follow_up(self) -> None:
        """Look at the server again, several times, after something was done to it (see FOLLOW_UP)."""
        waited = 0.0
        for moment in FOLLOW_UP:
            await asyncio.sleep(moment - waited)
            waited = moment
            if self._closed:
                return
            self._status_at = 0.0
            self._refresh_soon()

    async def _locate(self, on: bool, still: Callable[[], bool] | None = None) -> None:
        place = (await self._find(urgent=True))["system"]
        system, mark = await self._checked_read(place, urgent=True)  # (which server answers: see `_judge`)
        change = locator(system)[1 if on else 2]
        if change is None:
            raise KvmError("action_failed", "This controller has no locator light to switch")
        # A controller wants to be shown the state the change was decided on. Where it will not take the
        # mark it gave out itself (some compare them more strictly than they hand them out), or gave none
        # and wants one all the same, it is told that the change is meant whatever the state.
        reply = await self._request("PATCH", place, urgent=True, headers={"If-Match": mark} if mark else {}, still=still, command=True, json=change)
        if reply.status_code in (412, 428):
            reply = await self._request("PATCH", place, urgent=True, headers={"If-Match": "*"}, still=still, command=True, json=change)
        self._accepted(reply)
