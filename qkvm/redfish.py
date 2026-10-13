"""Client for a server's management controller (BMC), over Redfish.

Redfish is the interface such controllers share: AMI MegaRAC (ASRock Rack, Gigabyte and
many more), Dell iDRAC, HPE iLO, Supermicro, Lenovo XCC and OpenBMC all speak it. What it
gives the wall is whether the server is on, how it is doing (health, temperatures, fans),
and its power button.

What it does not give is a picture of the screen: the standard has none, and the consoles
the vendors build on top each speak a protocol of their own. Where that protocol is one QKVM
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
import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import hashlib
from urllib.parse import unquote, urlsplit

import httpx
from websockets.exceptions import ConnectionClosed, WebSocketException

from . import ami
from .aspeed import Garbled, Screen
from .kvm import (
    ABOUT_TTL,
    DOWN_CODES,
    FULL,
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
)

log = logging.getLogger("qkvm")

ROOT = "/redfish/v1/"
SESSIONS = "/redfish/v1/SessionService/Sessions"  # where the standard puts signing in
MAX_SENSORS = 40  # temperatures and fans of one server the wall will list
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
# and the wall presses none. A session that ran at least this long before it was told so has simply run its
# time, and is opened again at once; one that is ended sooner is a console that cannot be had.
CONSOLE_SETTLED = 60.0
CONSOLE_SAY = 10.0  # what is said to a console is taken within this, or the controller has stopped listening
SIGN_IN_OWED = 1.8  # a sign-in under way when the device is retired is waited for this long, to sign out of it again
LET_IN_AT_MOST = 8  # times in one session that somebody asking for the console is let in: a person asks once
# Frames are read by these threads and no others. Reading is done in Python, and a screen that changes all over
# takes seconds: on the threads that check passwords and write the settings, a few busy screens (or a
# controller that means it) would keep people from signing in. Two at a time, the rest wait their turn.
_READERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="screen")
UNREADABLE = 3  # this many frames in a row that cannot be read, and it is not a picture QKVM reads
QUANTIZER = {"480": 3, "640": 3, "960": 2, FULL: 2}  # JPEG strength by size, as for the other pictures made here
# What a controller may hand out to be sent back to it in a header (a session, its token): what a cookie may be
# made of, which is nothing that could end the header line or begin another.
HANDED = re.compile(r"[!#-+\--:<-\[\]-~]{1,512}")
CONSOLE_PASS = re.compile(r"[!-~]{1,128}")  # (this one travels in a message of the console's own, not in a header)
PASS_REFUSED = {
    0: "its console did not accept the pass it had given out",
    2: "this user is not allowed to use its console",
    3: "its console did not accept what QKVM said of itself",
    8: "its console does not know the session any more",
}


def _jpeg(width: int, height: int, screen: bytearray, target: int | None, quantizer: int) -> bytes:
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


def own_number(system: dict[str, Any]) -> str | None:
    """The number a server gives for itself, as a mark to know it by; None where it gives none worth the name.

    Only ever compared with another: it is kept as a digest, since the number itself is nobody's business.
    Boards whose maker never set one answer all zeros, or all F: that is no number, and many boards have it.
    """
    number = system.get("UUID")
    if not isinstance(number, str) or not NUMBER.fullmatch(number) or len(set(number.replace("-", "").lower())) < 4:
        return None
    return "server:" + hashlib.sha256(number.lower().encode()).hexdigest()[:32]


def named(*values: Any) -> str | None:
    """The first of `values` that is a real name and not what a board says when nobody filled it in."""
    for value in values:
        text = plain(value, 60)
        if text and not PLACEHOLDER.fullmatch(text):
            return text
    return None


class RedfishDevice(Device):
    """A server's management controller, over Redfish."""

    kind = "redfish"
    picture = False

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
        self._has_console: bool | None = None  # whether this controller has a console QKVM reads; None: not asked yet
        self._console_failures = 0  # attempts in a row that came to nothing
        self._complete_first: bool | None = None  # how its console wants to be greeted (see ami.hello); None: not known yet
        self._encode_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

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
        if self._console_task is not None:
            self._console_task.cancel()  # it signs out of the controller's web page on its way out
            await stopped([self._console_task])
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
        **kwargs: Any,
    ) -> httpx.Response:
        """Send a signed-in request. `urgent`, `vital` and `still` mean what they mean for a KVM (see KvmDevice._request)."""
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = False
        while True:
            token = self._token or await self._login()
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

    async def _read(self, path: str, urgent: bool = False, vital: bool = True) -> tuple[dict[str, Any], str | None]:
        """What is at `path`, and the mark the controller puts on its present state (None: it puts none)."""
        reply = await self._request("GET", path, urgent=urgent, vital=vital)
        if reply.status_code != 200:
            raise KvmError("bad_response", f"{path} failed (HTTP {reply.status_code})")
        try:
            data = read_json(reply)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise KvmError("bad_response", f"{path} returned unexpected data")
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
        """Where this controller keeps the server, its chassis and itself."""
        if self._places and time.monotonic() - self._places_at < ABOUT_TTL:
            return self._places
        root = await self._get(ROOT, urgent)
        system = await self._first(root.get("Systems"), urgent, True)
        if system is None:
            raise KvmError("bad_response", "The controller lists no computer")
        places = {"system": system}
        for name, key in (("chassis", "Chassis"), ("manager", "Managers")):
            try:
                found = await self._first(root.get(key), urgent, False)
            except KvmError:
                found = None
            if found:
                places[name] = found
        if "chassis" in places:
            try:
                thermal = link(_dig(await self._get(places["chassis"], urgent, False), "Thermal", "@odata.id"))
            except KvmError:
                thermal = None
            if thermal:
                places["thermal"] = thermal
        self._places, self._places_at = places, time.monotonic()
        return places

    # --- what the wall asks ---------------------------------------------------------

    async def _itself(self, urgent: bool = False) -> dict[str, Any]:
        """What rarely changes about the controller itself: its firmware, and where it hands out a way into its console."""
        if not self._controller or time.monotonic() - self._controller_at > ABOUT_TTL:
            manager: dict[str, Any] = {}
            place = (await self._find(urgent)).get("manager")
            if place:
                try:
                    manager = await self._get(place, urgent, False)
                except KvmError:
                    manager = {}
            # "IKVM" is where AMI's controllers keep it, on the boards whose maker left it in.
            self._controller = {"version": plain(manager.get("FirmwareVersion"), 40), "console": link(_dig(manager, "IKVM", "@odata.id"))}
            self._controller_at = time.monotonic()
        return self._controller

    async def _read_about(self, system: dict[str, Any], urgent: bool = False) -> dict[str, Any]:
        return {"model": named(system.get("Model"), system.get("Manufacturer")), "version": (await self._itself(urgent))["version"]}

    async def identify(self) -> dict[str, Any]:
        system = await self._get((await self._find(urgent=True))["system"], urgent=True)
        return {**await self._read_about(system, urgent=True), "hostname": named(system.get("HostName")), "ident": own_number(system)}

    async def snapshot(self, width: int, fresh: float | None = None) -> Snapshot:
        """The server's screen, from its controller's console. The first one asked for opens the console."""
        arrived = self._console_wanted_at = time.monotonic()
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
                data = await asyncio.to_thread(_jpeg, shown_width, shown_height, shown, target, QUANTIZER[size])
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
                log.info("%s: this controller has no console QKVM reads; its tile shows how the server is", self.label)
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

    async def _hold_console(self, console: _Console) -> None:
        """Open the controller's console as its own web page does, and take the screen for as long as it is looked at."""
        if self._has_console is None:
            # AMI's firmware has this address and wants a sign-in for it. A controller that does not know it has another console.
            # (One that answers with an error of its own just then has said neither: asked once, at one of its
            # moments, the server's screen was gone until QKVM was started again.)
            asked = await self._web("GET", "/api/kvm/token")
            if asked.status_code not in (401, 404, 405, 410):
                # (Neither "sign in first" nor "there is no such thing here": too many requests, a moment of
                # its own. Nothing is settled by that, and it is asked again as the console is after a failure.)
                raise KvmError("bad_response", f"The controller did not say whether it has a console (HTTP {asked.status_code})")
            self._has_console = asked.status_code == 401
        if not self._has_console:
            raise KvmError("no_picture", "This controller has no console that QKVM reads yet", 404)
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
        try:
            await self._get((await self._find())["system"], vital=False)
        except KvmError as ex:
            if ex.code in ("auth_failed", "no_password", "no_sign_in") or ex.code in DOWN_CODES:
                raise
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
                raise KvmError("no_picture", "The controller is set to switch the server's own monitor off while its console is open, so QKVM leaves the console alone", 404)
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

        async def send(data: bytes) -> None:
            # Within a time: a controller that has stopped listening would hold this for ever, and with it the
            # two checks that end a session (nobody looking, nothing heard), which are made between two things said.
            try:
                await asyncio.wait_for(connection.send(data if plain_bytes else base64.b64encode(data).decode()), CONSOLE_SAY)
            except TimeoutError:
                raise KvmError("dropped", "The controller's console stopped taking what is said to it") from None
            except ConnectionClosed:
                # It has hung up. It may have said why just before (that the session's time is up, say), and
                # that has arrived and is not read yet: what it said counts before the fact that it left.
                # Whoever looks next for what arrived reads it, and is told there that the connection is closed.
                pass

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
                        accepted = True
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
                        if about == ami.ASKED and who and answered < LET_IN_AT_MOST:
                            # Somebody opened the controller's own console while the wall has it, and the wall is asked
                            # whether they may. Nobody sits at the wall to answer, and unanswered they wait half a
                            # minute. The wall only looks: they have the console at once, keys and all. (A person
                            # asks once. A controller that asks without end is not answered without end.)
                            answered += 1
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
                                raise KvmError("no_picture", f"The controller sends a picture QKVM does not read yet ({ex})", 404) from None
                if read_any and time.monotonic() - said_at > 1.0:
                    await send(ami.message(ami.BEHIND))  # "every frame so far has been drawn"
                    said_at = time.monotonic()
        except WebSocketException as ex:
            raise KvmError("dropped", "The controller closed its console") from ex
        finally:
            try:
                if greeted:
                    # Said as the controller's own page says it when its window is closed: a console that just goes
                    # away is waited for by the controller, which is then slow to answer anybody. Said from the
                    # greeting on, not from the pass being found good: who else is there is said before that.
                    await asyncio.wait_for(send(ami.goodbye()), 2)
            except (TimeoutError, OSError, WebSocketException, KvmError):
                pass  # it is not listening (which may be why this is the end): the connection is closed all the same
            try:
                await asyncio.wait_for(connection.close(), 3)
            except (TimeoutError, OSError, WebSocketException):
                pass

    async def console(self) -> str:
        """The way into the server's own console, good for one use: a page on the controller, with a pass.

        Whoever holds the pass uses the console as the account this wall signs in with. It goes to the
        browser of the person who asked for it and nowhere else: not into the log, not into the activity log.
        Every call has the controller make out a new one, so this is asked when somebody wants in, not before.
        """
        place = (await self._itself(urgent=True))["console"]
        if place is None:
            raise KvmError("no_console", "This controller does not hand out a way into its console", 404)
        offered = await self._get(place, urgent=True)
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
            system = await self._get(places["system"])
        except KvmError as ex:
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

        thermal: dict[str, Any] = {}
        if "thermal" in places:
            try:
                thermal = await self._get(places["thermal"], vital=False)  # the server is there; this is a detail
            except KvmError:
                thermal = {}
        about = await self._read_about(system)

        power = plain(system.get("PowerState"), 20)
        on = None if power is None else power not in ("Off", "PoweringOff")
        self._power = on
        temperatures: list[dict[str, Any]] = [
            {"name": plain(entry.get("Name"), 40) or "", "celsius": reading, "ok": _dig(entry, "Status", "Health") in (None, "OK")}
            for entry in listed(thermal.get("Temperatures"))[:MAX_SENSORS]
            if isinstance(entry, dict) and (reading := number(entry.get("ReadingCelsius"), -100, 300)) is not None
        ]
        fans: list[dict[str, Any]] = [
            {
                "name": plain(entry.get("Name"), 40) or "",
                "reading": number(entry.get("Reading"), 0, 1_000_000),
                "unit": "%" if entry.get("ReadingUnits") == "Percent" else "RPM",
                "ok": _dig(entry, "Status", "Health") in (None, "OK"),
            }
            for entry in listed(thermal.get("Fans"))[:MAX_SENSORS]
            if isinstance(entry, dict) and _dig(entry, "Status", "State") == "Enabled"  # a fan that is not fitted is not a fan
        ]
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
        # What stood in the way is said until it is time to ask again. Then the tile asks, and it is found out anew:
        # a setting may have been changed, whoever had the console may have left.
        no_screen = self._no_screen if time.monotonic() < self._console_retry_at else None
        found = {
            "state": state,
            "error": error,
            "kind": self.kind,
            "picture": False,
            # Whether a picture of its screen can be asked for (see `snapshot`). Asked for, it may still not come.
            "screen": self._has_console is not False and no_screen is None,
            "video": {"signal": on, "width": showing.width if showing else None, "height": showing.height if showing else None, "fps": None},
            "usb": {"keyboard": None, "mouse": None},
            "atx": {"enabled": True, "power": on, "hdd": None},
            "health": {"temp": max(processors or [t["celsius"] for t in temperatures], default=None), "cpu": None, "mem": None},
            "about": about,
            "ports": None,
            "console": (await self._itself())["console"] is not None,  # "Open console" can lead straight in, signed in
            "server": {
                "power": power,
                "health": health,
                "processor": processor,
                "processors": number(_dig(system, "ProcessorSummary", "Count"), 1, 1024),
                "memory_gib": number(_dig(system, "MemorySummary", "TotalSystemMemoryGiB"), 0, 1_000_000),
                "temperatures": temperatures,
                "fans": fans,
                "unwell": unwell[:MAX_SENSORS],  # the sensors the controller is not happy with, by name
                "locator": locator(system)[0],  # the light to find it by in a rack: on, off, or None where there is none
                "no_screen": no_screen,  # why its screen is not shown, where it could be and is not
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
        'locate_on'       light the server up, for whoever is looking for it in the rack
        'locate_off'      and put that light out again
        """
        if action in ("locate_on", "locate_off"):
            await self._locate(action == "locate_on", still)
            return
        if action not in ("reboot", "power_on", "power_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A management controller cannot do that", 422)
        places = await self._find(urgent=True)
        if action == "reboot":
            if "manager" not in places:
                raise KvmError("action_failed", "This controller does not say how to restart it")
            place, name, wanted = places["manager"], "#Manager.Reset", ["ForceRestart", "GracefulRestart"]
            resource = await self._get(place, urgent=True)
        else:
            place, name = places["system"], "#ComputerSystem.Reset"
            resource = await self._get(place, urgent=True)
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
            reply = await self._request("POST", target, urgent=True, still=still, json={"ResetType": kind})
        except KvmError as ex:
            if action == "reboot" and ex.code in ("dropped", "timeout"):
                return  # a controller that is already going down may never answer
            raise
        self._accepted(reply)
        seen_by = {"On": True, "ForceOff": False}.get(kind) if name == "#ComputerSystem.Reset" else None
        if seen_by is not None:
            await self._carried_out(place, seen_by)

    async def _carried_out(self, place: str, on: bool) -> None:
        """Wait until the server is seen to be on (or off): only then was the command carried out (see CONFIRM_WITHIN)."""
        deadline = time.monotonic() + CONFIRM_WITHIN
        while True:
            try:
                power = plain((await self._get(place, urgent=True, vital=False)).get("PowerState"), 20)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    # The connection was taken away while this waited (the tile was saved, the last person
                    # signed out). Whether it was carried out was not seen, and that is what is said: taken
                    # for one of its moments, the wait ran out and said "was not carried out" of a
                    # server that may have been switching on.
                    raise RETIRED.with_traceback(None) from None
                power = None  # one of its moments: it is asked again
            if power == ("On" if on else "Off"):
                return
            if time.monotonic() >= deadline:
                still = "off" if on else "on"
                raise KvmError("action_failed", f"The controller accepted this, but the server is still {still}. The command was not carried out.")
            await asyncio.sleep(CONFIRM_EVERY)

    def _accepted(self, reply: httpx.Response) -> None:
        """Note that the controller did what was asked, or say in its own words why it did not."""
        if reply.status_code not in (200, 202, 204):
            try:
                said = read_json(reply)
                detail = _dig(said, "error", "@Message.ExtendedInfo") or []
                detail = _dig(detail[0], "Message") if detail else _dig(said, "error", "message")
            except (ValueError, LookupError, TypeError):  # not JSON, or not shaped the way an error is
                detail = None
            raise KvmError("action_failed", plain(detail, 200) or f"The controller refused (HTTP {reply.status_code})")
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
        system, mark = await self._read(place, urgent=True)
        change = locator(system)[1 if on else 2]
        if change is None:
            raise KvmError("action_failed", "This controller has no locator light to switch")
        # A controller wants to be shown the state the change was decided on. Where it will not take the
        # mark it gave out itself (some compare them more strictly than they hand them out), or gave none
        # and wants one all the same, it is told that the change is meant whatever the state.
        reply = await self._request("PATCH", place, urgent=True, headers={"If-Match": mark} if mark else {}, still=still, json=change)
        if reply.status_code in (412, 428):
            reply = await self._request("PATCH", place, urgent=True, headers={"If-Match": "*"}, still=still, json=change)
        self._accepted(reply)
