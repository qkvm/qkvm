"""Kind "vnc": any machine that runs a VNC server, by address, port and password, read with the RFB reader.

A VNC server is a viewer's window onto a machine: the wall is that viewer, connected for as long as the
machine is on the wall, asking for what changed at the pace the wall wants it (every quarter second while
somebody looks, every few seconds while nobody does, faster for a live viewer), and reading all the same
what a server sends unasked. Its picture is the screen the reader keeps, made into a JPEG when a tile asks.
Keys go as X11 keysyms, the pointer as a position and buttons; both through `press` and `pointer` for a live
line, and through the wall's actions (key combinations, typed text) like any KVM's.

A VNC server has no number of its own to be known by: it is known by its address, and by the name it gives
itself (which the tile is named after). The password goes through the vault like every other, and what the
server says to it is counted beside the connections as for every device (kvm.REJECTED): a no is not offered
again and again. The transport is a TCP connection, or TLS over one where the address says `vncs://` (the
certificate remembered on first contact, as for every family). A connection that was opened another way
(OpenBMC's console behind its session, a hypervisor's ticket) can be given to the reader as it is: see
`rfb.Stream`; this file only knows the two plain ways.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from urllib.parse import urlsplit

from . import rfb
from .jetkvm import _USAGE as KEY_USAGES  # key names as browsers spell them -> HID usages, typed once for the JetKVM
from .kvm import (
    DOWN_CODES,
    ERROR_HOLD,
    FULL,
    KEEPALIVE_IDLE,
    KEEPALIVE_LASTS,
    KEYS,
    MAX_TEXT,
    NO_SAID,
    REJECTED,
    STILL_THERE_EVERY,
    TIERS,
    Device,
    DeviceSpec,
    KvmError,
    Sent,
    Snapshot,
    fetch_certificate,
    pinned_context,
    plain,
    share_window,
    stopped,
    system_context,
    tier_for,
    unverified_context,
)
from .redfish import QUANTIZER
from .redfish import screen_jpeg as rgb_jpeg  # a screen of three bytes a pixel as a JPEG, as the server's console is made into one
from .store import device_url

log = logging.getLogger("qkvm")

VNC_PORT = 5900
CONNECT_WAIT = 5.0  # seconds to get a connection, TLS included
HANDSHAKE_WAIT = 20.0  # seconds the whole handshake may take: a server that holds a no back on purpose is still heard
STATUS_WAIT = 2.0  # seconds a look at the status waits for a handshake that is under way
LOOK_PACE = 0.25  # seconds between two requests for what changed while the wall only looks
LIVE_PACE = 0.04  # ...while a viewer has the machine live (W2's line asks for that)
IDLE_PACE = 10.0  # ...while nobody has asked for a picture for a while (KEEPALIVE_IDLE)
NO_PASSWORD_HOLD = STILL_THERE_EVERY  # seconds before a server that wants a password nobody saved is connected to again
BAD_HOLD = 15.0  # seconds before a server that sent what this program does not take is connected to again,
BAD_HOLD_MAX = 240.0  # ...twice as long each time it does so again, up to this long
# A server whose screen does not change answers nothing for as long as that lasts, and one that hangs looks the same
# from here. After this long without an update, one pixel is asked for outright, which any server must answer.
HEARTBEAT = 60.0
SETTLED = 30.0  # a connection that lasted this long, or drew a frame and lasted KEEPALIVE_LASTS, is the server being there again; a handshake alone is not
KEYS_AT_ONCE = 32  # key events written in one piece, each piece waited for (the server takes them at its pace)

# The modifier keys as browsers spell them -> HID usages (the JetKVM's table has their report bits, not these).
MODIFIER_USAGES = {"ControlLeft": 0xE0, "ShiftLeft": 0xE1, "AltLeft": 0xE2, "MetaLeft": 0xE3, "ControlRight": 0xE4, "ShiftRight": 0xE5, "AltRight": 0xE6, "MetaRight": 0xE7}
CTRL_ALT_DEL = (0xFFE3, 0xFFE9, 0xFFFF)  # Control_L, Alt_L, Delete


def vnc_url(text: str) -> str:
    """'192.168.1.20', '192.168.1.20:5901', 'vnc://name:5901' or 'vncs://name' as it is kept: vnc://host[:port], the port left out where it is 5900.

    ValueError for what is no such address. `vncs://` is TLS from the first byte (as some controllers' VNC servers do it).
    """
    text = text.strip()
    scheme = "vnc"
    for prefix in ("vncs://", "vnc://"):
        if text.lower().startswith(prefix):
            scheme, text = prefix[:-3], text[len(prefix) :]
            break
    if "://" in text or "@" in text or not text:
        raise ValueError(f"not a VNC server address: {text!r}")
    text = text.split("/", 1)[0]  # (a path means nothing to a VNC server)
    parts = urlsplit(f"//{text}")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"not a VNC server address: {text!r}") from None
    if not parts.hostname:
        raise ValueError(f"not a VNC server address: {text!r}")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    host = device_url(f"https://{host}")[len("https://") :]  # (written the one way, as every device's address is)
    if port is None:
        port = VNC_PORT
    if not 1 <= port <= 65535:
        raise ValueError(f"not a VNC server address: {text!r}")
    return f"{scheme}://{host}" + ("" if port == VNC_PORT else f":{port}")


def address_of(url: str) -> tuple[str, int, bool]:
    """(host, port, over TLS) of an address as `vnc_url` writes it."""
    parts = urlsplit(url)
    return parts.hostname or "", parts.port or VNC_PORT, parts.scheme == "vncs"


def certificate_address(url: str) -> str:
    """Where the certificate of a `vncs://` server is asked for (kvm.fetch_certificate): its host and its port, written as
    an https address (an IPv6 address in brackets), since that is what the certificate is fetched by."""
    host, port, _ = address_of(url)
    return f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}"


def is_vnc(text: str) -> bool:
    """Whether an address as somebody typed it names a VNC server by its scheme."""
    return text.strip().lower().startswith(("vnc://", "vncs://"))


class LetGo(Exception):
    """Nobody looks, and the connection is closed for it: no failure (see VncDevice.LET_GO_AFTER)."""


class _Session:
    """One connection to the server, from its making to its end."""

    def __init__(self) -> None:
        self.client: rfb.Client | None = None  # set once the handshake is done
        self.ready = asyncio.Event()  # the handshake ended, one way or the other
        self.done = asyncio.Event()  # the connection is over
        self.error: KvmError | None = None  # what ended it, or stood in its way
        self.mark: Sent | None = None  # noted when the password went out (see kvm.Rejected.sent)
        # A password the door was handed for this one connection (a hypervisor's console hands one out with its
        # ticket): what RFB's VNC authentication is answered with in place of the saved one, and counted nowhere,
        # since it says nothing of the saved one. Let go of once the handshake is over.
        self.one_time: str | None = None
        self.since = time.monotonic()
        self.let_in_at: float | None = None  # when the handshake was over
        self.encoded: dict[str, tuple[int, Snapshot]] = {}  # the JPEG last made of each size, and of which frame


def _chord(keysyms: list[int]) -> list[tuple[int, bool]]:
    """Press these in order and let go of them in the other."""
    return [(keysym, True) for keysym in keysyms] + [(keysym, False) for keysym in reversed(keysyms)]


def key_events(keys: str) -> list[tuple[int, bool]]:
    """'ControlLeft,AltLeft,Delete' as key events: the keys pressed in order and let go of in the other. KvmError for a key there is none of."""
    if not KEYS.fullmatch(keys):
        raise KvmError("invalid", "Not a valid key combination", 422)
    keysyms = []
    for name in keys.split(","):
        usage = MODIFIER_USAGES.get(name, KEY_USAGES.get(name))
        keysym = rfb.keysym_for(usage) if usage is not None else None
        if keysym is None:
            raise KvmError("invalid", f"There is no {name} key to send to a VNC server", 422)
        keysyms.append(keysym)
    return _chord(keysyms)


def text_events(text: str, enter: bool = False) -> list[tuple[int, bool]]:
    """What to press, character by character, to type `text`: each as its keysym, which the server's own keyboard layout turns into a key."""
    if not text or len(text) > MAX_TEXT:
        raise KvmError("invalid", f"Text must be 1 to {MAX_TEXT} characters", 422)
    events = []
    for char in text.replace("\r\n", "\n") + ("\n" if enter else ""):
        keysym = rfb.keysym_of(char)
        if keysym is None:
            raise KvmError("invalid", f"{char!r} cannot be typed on a VNC server", 422)
        events += [(keysym, True), (keysym, False)]
    return events


class VncDevice(Device):
    """A VNC server on the wall."""

    kind = "vnc"
    can = ("screen", "keys", "text")  # (what a tile of this kind can be asked: see `act`; nothing of power, nothing of the KVM)
    # What a family whose door opens another way (see `_open`) may say and do otherwise: what it is called in what
    # a tile says, the encodings its server is told of, its paces, and how long nobody may look before the
    # connection is let go of (None: it is held for as long as the machine is on the wall).
    THING = "the VNC server"
    ENCODINGS: tuple[int, ...] = rfb.ENCODINGS
    GREETED_AS_38: tuple[bytes, ...] = ()  # (see rfb.Client)
    PIXELS = rfb.RGB888
    SIGNS_IN: tuple[int, ...] = (rfb.SECURITY_NONE, rfb.SECURITY_VNC)  # the RFB sign-ins taken (see rfb.Client)
    SETTLED_BY_A_FRAME = True  # a frame drawn on a connection that lasted KEEPALIVE_LASTS is the server there again (False: only one that lasted SETTLED is)
    # Whether the saved password answers RFB's VNC authentication where the door handed out none of its own (`one_time`).
    # Not behind a door whose saved secret is another thing (a Proxmox API token, a controller's password).
    SAVED_PASSWORD_TO_RFB = True
    LOOK_PACE, LIVE_PACE, IDLE_PACE = LOOK_PACE, LIVE_PACE, IDLE_PACE
    LET_GO_AFTER: float | None = None
    HEARTBEAT_AFTER: float | None = None  # seconds without an update before one pixel is asked for outright; None: HEARTBEAT
    # Whether refusals in a row are counted on until a session has served a while (settled), and not only until the next
    # handshake: behind a door each session is a task or a seat, and one that lets qKVM in and then sends what it does not
    # take must climb its ladder, not begin it again at every handshake.
    REFUSALS_COUNT_TILL_SETTLED = False
    # Whether to log a line each time a connection is made: a plain VNC server connects once and stays, so it is worth a
    # line; a family that opens a short session again and again (a PC with Intel AMT, a still every five minutes, a session
    # per live view) would flood the log with them, so it says nothing (the first failure is still logged).
    LOG_CONNECT = True

    def __init__(self, spec: DeviceSpec, on_pin: Callable[[str], Any] | None = None) -> None:
        super().__init__(spec, on_pin)
        self._session: _Session | None = None
        self._task: asyncio.Task[None] | None = None
        self._wanted_at = float("-inf")  # when a picture was last asked for
        self._wanted = asyncio.Event()  # set when somebody begins to look: the pacer wakes from its idle wait
        self._live = 0  # viewers that have the machine live: the pace is theirs while there is one
        self._refusal: KvmError | None = None  # what the server sent that this program does not take, while that holds
        self._refusal_until = 0.0
        self._bad = 0  # such connections in a row
        self._inputs = 0  # keys or the pointer on their way to the server now (see `inputting`)
        self._held_off = 0  # while above 0, no session is opened (see `no_session`)
        self._ended_at = float("-inf")  # when the last session ended, whichever way (see `session_ended_within`)
        self._why_held_off = ""
        self._encode_locks = {size: asyncio.Lock() for size in (*TIERS, FULL)}

    async def close(self) -> None:
        self._closed = True
        await super().close()  # (the status refresh first: one under way must not start a connection nobody would stop)
        await stopped([self._task])

    def tidy(self) -> None:
        session = self._session
        if session is not None and time.monotonic() - self._wanted_at > KEEPALIVE_IDLE:
            session.encoded.clear()  # nobody is watching: the last pictures need not be kept

    # --- the seam for a live line ------------------------------------------------------------------------

    def _the(self) -> str:
        return self.THING[:1].upper() + self.THING[1:]

    def _is_live(self) -> bool:
        """Whether a viewer has the machine live now: the pace is the viewer's then."""
        return self._live > 0

    def live(self, on: bool) -> None:
        """A viewer has the machine live (on), or has left it: the screen is then asked for at a viewer's pace."""
        self._live = max(0, self._live + (1 if on else -1))
        if on:
            self._looking()

    def _looking(self) -> None:
        """Somebody wants pictures now: the pacer is told, in case it was waiting out its idle pace."""
        self._wanted_at = time.monotonic()
        self._wanted.set()

    @contextmanager
    def inputting(self) -> Iterator[None]:
        """Keys or the pointer on their way, from the moment they are asked for to the moment they went out: the session is
        wanted all that while (opening it, waiting until the server takes input, typing a long text at its pace), and for
        LET_GO_AFTER after the last of them, not after the moment they were asked for."""
        self._inputs += 1
        self._looking()
        try:
            yield
        finally:
            self._inputs -= 1
            self._looking()

    @asynccontextmanager
    async def no_session(self, why: str) -> AsyncIterator[bool]:
        """No session while this lasts, for what a server will not do while one is open (Intel AMT's engine cuts no power
        then): the one that is open, or being opened, is closed and waited for, and none is opened meanwhile (what would
        open one is told `why`, as a moment of the screen's). Yields whether one was open."""
        self._held_off += 1
        self._why_held_off = why
        try:
            task = self._task
            had = task is not None and not task.done()
            await stopped([task])
            yield had
        finally:
            self._held_off -= 1

    def session_ended_within(self, seconds: float) -> bool:
        """Whether a session of this program's is open, or ended less than `seconds` ago."""
        task = self._task
        return (task is not None and not task.done()) or time.monotonic() - self._ended_at < seconds

    def screen(self) -> tuple[int, int, int, bytearray] | None:
        """The screen as it stands: (frames so far, width, height, three bytes a pixel), or None before the first frame."""
        client = self._connected_or_none()
        if client is None or client.frames == 0:
            return None
        width, height, rgb = client.shown
        return client.frames, width, height, rgb

    async def next_frame(self, after: int, within: float) -> int | None:
        """Wait up to `within` seconds for a frame newer than `after`: its number, or None where none came."""
        client = self._connected_or_none()
        if client is None:
            return None
        deadline = time.monotonic() + within
        while client.frames <= after:
            wait = deadline - time.monotonic()
            if wait <= 0 or client is not self._connected_or_none():
                return None
            client.updated.clear()
            if client.frames > after:
                break
            try:
                async with asyncio.timeout(wait):  # (not wait_for, which loses a stop up to Python 3.11: see rfb._in_time)
                    await client.updated.wait()
            except TimeoutError:
                return None
        return client.frames

    async def press(self, usage: int, down: bool) -> None:
        """A key by its HID usage, pressed or let go of (as a live line has them). KvmError for a key there is no keysym for."""
        keysym = rfb.keysym_for(usage)
        if keysym is None:
            raise KvmError("invalid", f"There is no key for usage {usage:#x} to send to a VNC server", 422)
        await self._to_server(lambda client: client.key(keysym, down))

    async def pointer(self, x: int, y: int, buttons: int = 0) -> None:
        """The pointer at (x, y) of the screen with these buttons held: bit 0 the left, 1 the middle, 2 the right, 3 and 4 the wheel."""
        await self._to_server(lambda client: client.pointer(x, y, buttons))

    # --- what the wall asks ----------------------------------------------------------------------------------

    async def identify(self) -> dict[str, Any]:
        """Connect and read what the server says of itself. Raises KvmError where that cannot be had."""
        self._looking()  # (whoever adds a machine looks at its tile next)
        session = self._start(urgent=True)
        await asyncio.wait({asyncio.ensure_future(session.ready.wait())}, timeout=CONNECT_WAIT + HANDSHAKE_WAIT + 1)
        if session.error is not None:
            raise session.error.with_traceback(None)
        client = session.client
        if client is None:
            raise KvmError("timeout", "The VNC server did not finish the handshake in time", 504)
        name = plain(client.name, 80)
        version = f"RFB {client.version[0]}.{client.version[1]}" if client.version else None
        return {"model": name, "version": version, "hostname": name}

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        self._looking()
        return await self._picture(width, fresh)

    async def _picture(self, width: int, fresh: float | None) -> Snapshot:
        """The screen of the session that is up, as a JPEG at least `width` wide (a session started where there is none),
        without its being counted as somebody looking (see `snapshot`)."""
        arrived = time.monotonic()
        client = self._connected()
        if client.frames == 0:
            raise KvmError("no_stream", "Waiting for the screen", 503)
        session = self._session
        assert session is not None
        shown_width, shown_height, shown = client.shown
        size = tier_for(width)
        if size != FULL and TIERS[size][0] >= shown_width:
            size = FULL
        async with self._encode_locks[size]:
            cached = session.encoded.get(size)
            if cached and (cached[0] == client.frames or arrived - cached[1].taken_at < share_window(fresh)):
                return cached[1]
            asked, made_of = time.monotonic(), client.frames
            target = None if size == FULL else TIERS[size][0]
            try:
                data = await asyncio.to_thread(rgb_jpeg, shown_width, shown_height, shown, target, QUANTIZER[size])
            except Exception:  # whatever the library says of a screen caught in the middle of a change of size
                raise KvmError("no_stream", "The screen changed while its picture was being made", 503) from None
            snap = Snapshot(data, "image/jpeg", True, asked)
            session.encoded[size] = (made_of, snap)
            return snap

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """'keys' presses a combination, 'text' types, 'ctrl_alt_del' is the one it says. A VNC server can do nothing else from here."""
        if action == "ctrl_alt_del":
            events = _chord(list(CTRL_ALT_DEL))
        elif action == "keys":
            events = key_events(keys)
        elif action == "text":
            events = text_events(text)
        else:
            raise KvmError("invalid", "A VNC server cannot do that", 422)
        if still is not None and not still():
            raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
        client = self._connected(urgent=True)
        try:
            for at in range(0, len(events), KEYS_AT_ONCE):
                await client.keys(events[at : at + KEYS_AT_ONCE])
        except rfb.RfbError as ex:
            raise self._not_taken(ex) from None

    async def _to_server(self, what: Callable[[rfb.Client], Any]) -> None:
        client = self._connected(urgent=True)
        try:
            await what(client)
        except rfb.RfbError as ex:
            raise self._not_taken(ex) from None

    def _not_taken(self, ex: rfb.RfbError) -> KvmError:
        return self._failed(KvmError("dropped", f"{self._the()} did not take it: {ex.message}"), in_passing=True)

    async def _read_status(self) -> dict[str, Any]:
        if self._closed:
            return {"state": "connecting", "error": None}  # retired: the client that took its place says how the device is
        session = self._session
        if session is None or session.done.is_set():
            standing = self._standing(time.monotonic())
            if standing is not None:
                if standing.code in ("auth_failed", "no_password", "no_sign_in"):
                    standing = await self._gone_meanwhile_vnc() or standing
                return self._state_of(standing)
            session = self._start()
        if not session.ready.is_set():
            await asyncio.wait({asyncio.ensure_future(session.ready.wait())}, timeout=STATUS_WAIT)
        if session.error is not None:
            return self._state_of(session.error)
        client = session.client
        if client is None:
            return {"state": "connecting", "error": None}
        return {
            "state": "online",
            "error": None,
            "video": {"signal": True, "width": client.width, "height": client.height, "fps": None},
            "usb": {"keyboard": None, "mouse": None},
            "atx": {"enabled": False, "power": None, "hdd": None},
            "health": {"temp": None, "cpu": None, "mem": None},
            "about": {"model": plain(client.name, 40), "version": f"RFB {client.version[0]}.{client.version[1]}" if client.version else None},
            "ports": None,
        }

    @staticmethod
    def _state_of(error: KvmError) -> dict[str, Any]:
        if error.code in ("auth_failed", "no_password"):
            state = "auth"
        elif error.code in ("no_sign_in", "bad_response", "cert_mismatch", "cert_invalid"):
            state = "error"  # it is there, and something is wrong: not "offline", which an alert would report as gone
        else:
            state = "offline"
        return {"state": state, "error": error.as_dict()}

    async def _gone_meanwhile_vnc(self) -> KvmError | None:
        """While a password waits to be offered again: whether the server is there at all, asked by its greeting, with nothing sent."""
        if self._heard_at is not None and time.monotonic() - self._heard_at < STILL_THERE_EVERY:
            return None
        host, port, tls = address_of(self.spec.base_url)
        try:
            # (A server at a `vncs://` address greets inside TLS, and never in the open: asked there, its certificate checked
            # as for every connection to it. Asked in the open, it said nothing, and its tile said it was gone.)
            said = await rfb.greeting(host, port, CONNECT_WAIT, await self._tls_for_vnc() if tls else None)
        except KvmError as ex:  # (the certificate saved for it cannot be read, or none could be had to remember)
            return self._failed(ex)
        except ssl.SSLCertVerificationError as ex:
            return self._failed(self._connect_error(ex, self.spec.tls))
        if said is None:
            return self._failed(KvmError("unreachable", "Device is unreachable"))
        self._answered()
        return None

    # --- the connection ------------------------------------------------------------------------------------

    def _standing(self, now: float) -> KvmError | None:
        """What keeps a connection from being made just now: a rejected password, a refusal, a server that is down."""
        if self._login_error is not None and now < self._login_retry_at:
            return self._login_error
        if self._refusal is not None and now < self._refusal_until:
            return self._refusal
        if self._down_error is not None and now < self._down_until:
            return self._down_error
        return None

    def _connected_or_none(self) -> rfb.Client | None:
        session = self._session
        return None if session is None or session.done.is_set() else session.client

    def _connected(self, urgent: bool = False) -> rfb.Client:
        """The client of the connection that is up, or the KvmError that says why there is none (which may start one)."""
        if self._closed:
            raise KvmError("no_stream", "Reconnecting to the KVM", 503)
        session = self._session
        if session is None or session.done.is_set():
            standing = self._standing(time.monotonic())
            if standing is not None and not (urgent and standing.code in DOWN_CODES):
                raise standing.with_traceback(None)
            self._start(urgent)
            raise KvmError("no_stream", f"Connecting to {self.THING}", 503)
        if session.client is None:
            raise KvmError("no_stream", f"Connecting to {self.THING}", 503)
        return session.client

    def _start(self, urgent: bool = False) -> _Session:
        """The session that is under way, or a new one where none is."""
        session = self._session
        if session is not None and not session.done.is_set():
            return session
        if self._closed:
            raise KvmError("no_stream", "Reconnecting to the KVM", 503)  # retired: it starts nothing
        if self._held_off:
            raise KvmError("no_stream", self._why_held_off, 503)  # (see `no_session`)
        session = self._session = _Session()
        self._task = asyncio.create_task(self._run(session, urgent))
        return session

    async def _open(self) -> rfb.Stream:
        """The bytes to and from the server: a TCP connection, with TLS over it where the address says so.

        The seam for a family whose door opens another way (OpenBMC's console behind its session, a hypervisor's
        ticket, AMT's redirection handshake): override this and hand back any `rfb.Stream` that is open already.
        """
        host, port, tls = address_of(self.spec.base_url)
        context = await self._tls_for_vnc() if tls else None
        try:
            return await rfb.open_tcp(host, port, context, CONNECT_WAIT)
        except OSError as ex:
            raise self._failed(self._connect_error(ex, self.spec.tls)) from None

    async def _tls_for_vnc(self) -> ssl.SSLContext:
        """How the server's certificate is checked, as for every device: remembered on first contact, or the system's list, or not at all."""
        spec = self.spec
        if spec.tls == "system":
            return await system_context()
        if spec.tls == "insecure":
            return unverified_context()
        if not spec.cert_pem:
            # Trust on first use, as for every device that shows a certificate: what it shows now is remembered,
            # and anything else at that address is refused from then on.
            spec.cert_pem = await fetch_certificate(certificate_address(spec.base_url))
            if self.on_pin and not self._closed:
                await self.on_pin(spec.cert_pem)
        try:
            return pinned_context(spec.cert_pem)
        except (ssl.SSLError, TypeError, ValueError):
            raise KvmError("cert_invalid", "The certificate saved for this device cannot be read. Look at its certificate and trust it again.") from None

    @staticmethod
    def _connect_error(ex: BaseException, tls_mode: str) -> KvmError:
        cause: BaseException | None = ex
        while cause is not None:
            if isinstance(cause, ssl.SSLCertVerificationError):
                if tls_mode == "pinned":
                    return KvmError("cert_mismatch", "Certificate does not match the one saved for this device")
                return KvmError("cert_invalid", "The device's certificate is not trusted")
            cause = cause.__cause__ or cause.__context__
        if isinstance(ex, TimeoutError):
            return KvmError("timeout", "Device did not respond in time", 504)
        if isinstance(ex, ssl.SSLError):
            return KvmError("dropped", "The device's TLS handshake failed")
        return KvmError("unreachable", "Device is unreachable")

    async def _run(self, session: _Session, urgent: bool) -> None:
        offered = REJECTED.what("login", self.spec)
        client: rfb.Client | None = None
        error: KvmError | None = None
        try:
            if not urgent:
                self._check_backoff()
            if self.spec.password:
                self._not_yet(offered, NO_SAID)
            stream = await self._open()
            one_time = session.one_time
            password = one_time if one_time is not None else (self.spec.password or None) if self.SAVED_PASSWORD_TO_RFB else None

            def sent() -> None:
                session.mark = REJECTED.sent(offered)

            client = rfb.Client(
                stream,
                password if rfb.SECURITY_VNC in self.SIGNS_IN else None,  # (never given where it is not to be sent)
                before_password=sent if one_time is None else None,  # (a password handed out for this connection alone is not the saved one)
                encodings=self.ENCODINGS,
                greeted_as_38=self.GREETED_AS_38,
                pixels=self.PIXELS,
                signs_in=self.SIGNS_IN,
            )
            try:
                async with asyncio.timeout(HANDSHAKE_WAIT):
                    await client.handshake()
            except TimeoutError:
                raise rfb.RfbError(rfb.TIMEOUT, "the server did not finish the handshake in time") from None
            session.one_time = client.password = one_time = password = None  # (used: kept nowhere for longer than it was needed)
            if session.mark is not None:
                REJECTED.accepted(offered)
            self._login_error, self._refusal = None, None
            if not self.REFUSALS_COUNT_TILL_SETTLED:
                self._bad = 0
            # Heard from, and not yet "well again": a server that lets this program in and hangs up at once would
            # otherwise count as a fresh start each time, and be connected to (password and all) once a second.
            self._down_error, self._last_ok, self._heard_at = None, time.time(), time.monotonic()
            session.let_in_at = time.monotonic()
            self._let_in()
            session.client = client
            session.ready.set()
            if not self._failures and self.LOG_CONNECT:
                log.info("%s: connected to %s %r (RFB %d.%d, %d by %d)", self.label, self.THING, plain(client.name, 60), *(client.version or (0, 0)), client.width, client.height)
            # The reading and the asking end together: a pacer that cannot ask any more, or that a silent server
            # never answers, ends the connection, where the reading alone would sit in a dead one for good.
            serving, pacing = asyncio.create_task(client.serve()), asyncio.create_task(self._pace(client))
            try:
                done, _ = await asyncio.wait({serving, pacing}, return_when=asyncio.FIRST_COMPLETED)
                first = serving if serving in done else pacing
                first.result()  # raises what ended it
                raise rfb.RfbError(rfb.CLOSED, "the connection ended")  # (neither returns without an error)
            finally:
                for task in (serving, pacing):
                    task.cancel()
                await asyncio.gather(serving, pacing, return_exceptions=True)
        except rfb.RfbError as ex:
            error = self._ended(session, offered, ex)
        except LetGo:
            # Nobody looked for a while, and this family is not held for nobody (LET_GO_AFTER): no failure, nothing
            # to wait out; the next picture asked for connects again.
            log.debug("%s: nobody looks: the connection to %s is closed", self.label, self.THING)
            if (self._failures or self._bad) and self._served(session):
                # It served for a while: well again, also where a still screen answered no request after its first in that
                # time (which is where it is found so otherwise), and nobody looked long enough for its heartbeat.
                self._settled()
        except KvmError as ex:
            error = ex  # (noted where it was raised)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            self._unexpected(f"the connection to {self.THING} failed", ex)
            error = KvmError("bad_response", f"The connection to {self.THING} failed inside qKVM")
        finally:
            self._ended_at = time.monotonic()
            session.error = error
            session.one_time = None
            session.encoded.clear()
            session.done.set()
            session.ready.set()
            if client is not None:
                await client.close()

    def _ended(self, session: _Session, offered: str, ex: rfb.RfbError) -> KvmError:
        """What a connection that ended this way says from now on, noted where it is kept."""
        now = time.monotonic()
        if ex.code == rfb.AUTH:
            self._login_error = KvmError("auth_failed", NO_SAID)
            self._login_retry_at = now + REJECTED.said_no(offered)
            log.warning("%s: login rejected (%s)", self.label, ex.message)
            return self._login_error
        if ex.code == rfb.NO_PASSWORD:
            self._login_error = KvmError("no_password", "No password saved for this device")
            self._login_retry_at = now + NO_PASSWORD_HOLD
            return self._login_error
        if ex.code in (rfb.CLOSED, rfb.TIMEOUT):
            if ex.code == rfb.TIMEOUT:
                error = KvmError("timeout", f"{self._the()}: {ex.message}", 504)
            else:
                error = KvmError("dropped", f"{self._the()}: {ex.message}", 502)
            if session.client is not None:
                # It served: an ordinary end of a connection, told as a device that is down until it answers again.
                log.info("%s: the connection ended after %d s: %s", self.label, round(now - session.since), ex.message)
                return self._failed(error)
            if session.mark is not None:
                return self._came_to_nothing(offered, error, NO_SAID, session.mark)
            return self._failed(error)
        if ex.code in (rfb.REFUSED, rfb.UNSUPPORTED):
            error = KvmError("bad_response", f"{self._the()} does not let qKVM in: {ex.message}")
            if session.mark is not None:
                return self._came_to_nothing(offered, error, NO_SAID, session.mark)
            return self._neither_yes_nor_no(offered, error, NO_SAID)
        # What arrived is not RFB as this program reads it, or more than it takes: said as that, and left alone for a while.
        return self._left_alone(KvmError("bad_response", f"{self._the()} sent what qKVM does not take: {ex.message}"))

    @staticmethod
    def _served(session: _Session) -> bool:
        """Whether a session served for a while: let in at least SETTLED ago, and answered at least one request since.
        (From the handshake, not from the first try: opening may take its half minute too, and that is not serving.)"""
        client = session.client
        return client is not None and client.updates > 0 and session.let_in_at is not None and time.monotonic() - session.let_in_at >= SETTLED

    def _let_in(self) -> None:
        """The server let this program in (the handshake is over): for a family to note, where it keeps more than this."""

    def _left_alone(self, refusal: KvmError, most: float = BAD_HOLD_MAX) -> KvmError:
        """Not connected to again for a while (BAD_HOLD, doubling, held to `most`); `refusal` is what is said meanwhile."""
        self._bad += 1
        self._refusal = refusal
        self._refusal_until = time.monotonic() + min(most, BAD_HOLD * 2 ** min(self._bad - 1, 5))
        if self._bad == 1:
            log.warning("%s: %s", self.label, refusal.message)
        return refusal

    def _settled(self) -> None:
        """The server is there again, as far as this connection can tell: it drew a frame and lasted a few seconds, or lasted."""
        if self._failures:
            log.info("%s: reachable again", self.label)
            self._failures = 0

    async def _pace(self, client: rfb.Client) -> None:
        """Ask for what changed, one request at a time, at the pace the wall wants it; and now and then whether the server is there at all."""
        full = True
        since = time.monotonic()
        while True:
            looking = self._watched()
            live = self._is_live()
            self._let_go_if_unwanted()
            client.drawing = looking or live
            if client.stale and client.drawing:
                full, client.stale = True, False
            seen = client.updates
            await client.request(incremental=not full)
            full = False
            heartbeat = self.HEARTBEAT_AFTER if self.HEARTBEAT_AFTER is not None else HEARTBEAT
            await self._answered_within(client, seen, heartbeat if client.updates == seen else 0.0, heartbeat=True)
            # Well again: a frame drawn on a connection that has lasted a few seconds too, or a connection that lasted. (A
            # frame alone settled one that drew a frame and hung up: each hang-up was the first failure again, and such a
            # server was connected to, its password answered, every second for good.)
            lasted = time.monotonic() - since
            if (self._failures or self._bad) and ((self.SETTLED_BY_A_FRAME and client.frames and lasted >= KEEPALIVE_LASTS) or lasted >= SETTLED):
                self._settled()
            if live or looking:
                await asyncio.sleep(self.LIVE_PACE if live else self.LOOK_PACE)
            else:
                # Nobody looks: the next request waits its idle pace, unless somebody begins to look meanwhile.
                self._wanted.clear()
                try:
                    async with asyncio.timeout(self.IDLE_PACE):
                        await self._wanted.wait()
                except TimeoutError:
                    pass

    def _watched(self) -> bool:
        """Whether pictures are wanted now: drawn, and asked for at a looking pace (else the idle one, and not drawn)."""
        return time.monotonic() - self._wanted_at < KEEPALIVE_IDLE

    async def _answered_within(self, client: rfb.Client, seen: int, wait: float, heartbeat: bool) -> None:
        """Wait for an update newer than `seen`. After `wait` seconds of none, one pixel is asked for outright (`heartbeat`),
        which any server answers within a message's time, or the connection is over: a server that hangs, or stopped
        answering, must not stay "online" with its last frame for ever."""
        deadline = time.monotonic() + wait
        while client.updates == seen:
            client.updated.clear()
            if client.updates != seen:
                break
            # (A still screen leaves a request unanswered for as long as it stays still: whether anybody still looks
            # is asked meanwhile too, where a family lets go of its connection for nobody.)
            unwanted_in = self._let_go_if_unwanted()
            left = deadline - time.monotonic()
            if left <= 0:
                if not heartbeat:
                    raise rfb.RfbError(rfb.TIMEOUT, "the server does not answer requests")
                await client.request(incremental=False, area=(0, 0, 1, 1))
                return await self._answered_within(client, seen, rfb.MESSAGE_WITHIN, heartbeat=False)
            try:
                async with asyncio.timeout(min(left, unwanted_in)):
                    await client.updated.wait()
            except TimeoutError:
                pass

    def _let_go_if_unwanted(self) -> float:
        """LetGo where nobody has looked for LET_GO_AFTER; else the seconds until that would be so (inf: never, for this family or now)."""
        if self.LET_GO_AFTER is None or self._is_live():
            return float("inf")
        if self._inputs:
            return self.LET_GO_AFTER  # (input is going: asked again at the latest when it could be LET_GO_AFTER after its end)
        unwanted_in = self._wanted_at + self.LET_GO_AFTER - time.monotonic()
        if unwanted_in <= 0:
            raise LetGo
        return max(0.05, unwanted_in)

    def _failed(self, error: KvmError, in_passing: bool = False) -> KvmError:
        noted = super()._failed(error, in_passing)
        if error.code in DOWN_CODES and not self._closed:
            self._down_until = max(self._down_until, time.monotonic() + ERROR_HOLD)  # (never asked again within the same look)
        return noted


# How the screens behind doors were last paced, by kind and address: (failures in a row, held until, what that was, and the
# same for a refusal; whether the run of failures has sessions in it that served and were cut, and began with one that was
# not said in the log; whether everyone waits out the hold; when it last failed). Kept here and not in the screen: a screen is made anew
# whenever its tile is edited, its certificate trusted, or the saved passwords locked and opened again, and the next one
# began at nothing, each a new console asked for at once (a task in Proxmox's log; a seat of an OpenBMC controller's four).
Paced = tuple[int, float, str, str, int, int, float, str, bool, bool, bool, float]
_PACED: dict[str, Paced] = {}
MOST_PACED = 2048  # of them; the oldest go first


def forget_pace(url: str) -> None:
    """A person has just done what may cure it (typed the password or token again, trusted a certificate again): the
    screens behind doors at this address are asked for as if for the first time."""
    for key in [key for key in _PACED if key.split("\0", 1)[1:] == [url]]:
        del _PACED[key]


class DoorScreen(VncDevice):
    """The screen of a machine whose tile is another driver's: a Proxmox guest's, a server's whose controller runs
    OpenBMC. That driver opens the door (`_open`, overridden) and decides whether a session may be opened at all;
    what it asks of the screen is here: whether a session is up and how large its screen is, a session waited for,
    keys and buttons let go of on the session that is open (and none opened only for that), and a live line's pace.

    A session is held while somebody looks, and let go of a minute after the last look: each one costs the machine
    something (a task in Proxmox's log; one of four seats on an OpenBMC controller), and none is held for nobody. One that
    fails, or is refused, is asked for again on a ladder of the family's own (`_retry`), and for whoever is in a hurry (a
    live line, a key) too, once it has failed more than once: a door that keeps failing is not knocked on at every key.
    """

    LET_GO_AFTER = 60.0
    LIVE_FOR = 2.0  # seconds after a live line last asked for the screen during which the pace is still a viewer's
    SAVED_PASSWORD_TO_RFB = False  # (behind a door, RFB is given the password the door was handed, or none: never the saved one)
    REFUSALS_COUNT_TILL_SETTLED = True
    # A still screen sends nothing, and asks nothing back: a proxy in front of the door (a reverse proxy before Proxmox, as
    # often as not) may take a quiet WebSocket for a dead one after a minute. One pixel is asked for well before that.
    HEARTBEAT_AFTER = 25.0
    # Seconds a session must serve, from its handshake, before a run of failures that has a cut one in it is over: one that
    # served for a while and was cut (Proxmox ending it, a proxy with a limit of its own) is opened again at once, and the
    # next one cut before this long is one more failure, on the ladder, until one serves this long. Under the round five
    # minutes a proxy may hold a connection for, which then cuts it a moment before five minutes from the handshake.
    AGAIN_SOON = 240.0
    # Seconds after the last failure after which what failed before says nothing any more, a run included (a wall looked at
    # in short visits has no session that serves AGAIN_SOON, and cuts a day apart climbed to the top rung). Longer than the
    # top rung of any door's ladder and AGAIN_SOON together, so that failures coming at the top rung's pace are never this
    # far apart.
    QUIET_AFTER = 3600.0

    def __init__(self, spec: DeviceSpec) -> None:
        super().__init__(spec, None)  # (a certificate is the owning tile's to remember, on its own first look)
        self._live_at = float("-inf")
        self._cut_in_run = False  # a session that served for a while ended since the last time all was forgiven
        self._quiet_first = False  # the first failure in this run was such an end, and was not said in the log
        self._everyone_waits = False  # the last failure was a moment of the machine's own: a live viewer waits it out too
        self._cut_run_before = False  # (whether a run stood before the failure being counted: see _in_run)
        self._failed_at = float("-inf")  # when a session last failed or was refused
        self._let_in_ended_at = float("-inf")  # when a session that let qKVM in last ended, failed or refused
        paced = _PACED.get(self._paced_as())
        if paced is not None:
            failures, down_until, code, message, status, bad, refusal_until, refused, cut, quiet, everyone, self._failed_at = paced
            self._failures, self._down_until, self._down_error = failures, down_until, KvmError(code, message, status) if code else None
            self._bad, self._refusal_until, self._refusal = bad, refusal_until, KvmError("bad_response", refused) if refused else None
            self._cut_in_run, self._quiet_first, self._everyone_waits = cut, quiet, everyone

    # --- the ladder ----------------------------------------------------------------------------------------

    def _retry(self) -> tuple[float, ...]:
        """Seconds after which a session that failed is asked for again, after the first failure, the second, and on."""
        return (15.0, 60.0, 300.0)

    def _hold(self, count: int) -> float:
        ladder = self._retry()
        return ladder[min(max(count, 1), len(ladder)) - 1]

    def _paced_as(self) -> str:
        return f"{self.kind}\0{self.spec.base_url}"

    def _keep_pace(self) -> None:
        if self._closed:
            return  # (retired: the screen that took its place says how it is paced)
        down, refusal = self._down_error, self._refusal
        _PACED.pop(self._paced_as(), None)  # (the newest last)
        _PACED[self._paced_as()] = (
            self._failures, self._down_until, down.code if down else "", down.message if down else "", down.status if down else 502,
            self._bad, self._refusal_until, refusal.message if refusal else "",
            self._cut_in_run, self._quiet_first, self._everyone_waits, self._failed_at,
        )  # fmt: skip
        while len(_PACED) > MOST_PACED:
            del _PACED[next(iter(_PACED))]

    def forgive(self) -> None:
        """What failed before says nothing any more (the machine was off since, or the session lasted): the next session
        is asked for at once."""
        if not self._closed:
            _PACED.pop(self._paced_as(), None)
        self._cut_in_run = self._quiet_first = self._everyone_waits = False
        if self._failures or self._bad:
            self._failures, self._down_error, self._down_until = 0, None, 0.0
            self._bad, self._refusal, self._refusal_until = 0, None, 0.0

    def _let_in(self) -> None:
        super()._let_in()
        # (A refusal that stood is over: the ladders go on as they were until the session has served a while, and are
        # written down so; with nothing on them, there is nothing to keep.)
        if self._failures or self._bad:
            self._keep_pace()
        elif not self._closed:
            _PACED.pop(self._paced_as(), None)

    def _connected(self, urgent: bool = False) -> rfb.Client:
        # Urgent (a live line, a key, the pointer) opens a session at once after a failure; not after two in a row, and
        # not within a moment of the machine's own (asked again at once, it fell into the same moment, and a second
        # failure held the viewer a whole minute where the tile waited fifteen seconds).
        return super()._connected(urgent and self._failures <= 1 and not self._everyone_waits)

    def _failed(self, error: KvmError, in_passing: bool = False, *, moment: bool = False) -> KvmError:
        """Every session that failed counts, one at a time as they are made: the device's own counting counts those that
        failed together once (requests in flight together), and a session asked for in a hurry within the pause after
        another failure was then never counted, and the next one was asked for in a hurry again. `moment`: the machine
        said it is not well just now (Proxmox's HTTP 5xx): everyone waits out the hold, a live viewer too."""
        if error.code not in DOWN_CODES or self._closed:
            return super()._failed(error, in_passing)
        if in_passing:
            # A key or a move that did not get through: the session it was sent on is ending, and its end is what
            # counts. (Counted as well, a viewer typing as a console ended found it held back a whole rung for nothing.)
            return error
        # The ordinary end of a session that served for a while (Proxmox or the controller ending it, a node handing the
        # guest over): what failed before it counts no more, and the next one is asked for at once; only one that fails
        # again after that is waited for. Not a session that stopped answering (the heartbeat's own end), and not one
        # more end of any kind in the same run (a proxy that cuts every console after a minute, and now and then fails
        # the next one too): those count, and climb the ladder (see `_in_run` and `_settled`).
        now = time.monotonic()
        self._forget_if_quiet(now)
        served = self._in_run()
        lasted = served and error.code != "timeout" and not self._cut_run_before
        if lasted:
            self.forgive()
            self._quiet_first = True
            self._in_run()  # (begun anew)
        self._failed_at = now
        self._everyone_waits = moment
        self._in_passing = in_passing
        self._failures += 1
        if (self._failures == 1 and not lasted) or (self._failures == 2 and self._quiet_first):
            log.warning("%s: %s", self.label, error.message)
        self._down_error = error
        self._down_until = time.monotonic() + (0.0 if lasted else self._hold(self._failures))
        self._keep_pace()
        return error

    def _left_alone(self, refusal: KvmError, most: float = BAD_HOLD_MAX) -> KvmError:
        # (`most` is a plain VNC server's ceiling: a door's console climbs a ladder of its own, `_hold`.)
        now = time.monotonic()
        self._forget_if_quiet(now)
        self._in_run()  # (a session that served and then sent what qKVM does not take, or was refused, is in a run too)
        self._failed_at = now
        self._bad += 1
        self._refusal = refusal
        self._refusal_until = time.monotonic() + self._hold(self._bad)
        if self._bad == 1:
            log.warning("%s: %s", self.label, refusal.message)
        self._keep_pace()
        return refusal

    def _in_run(self) -> bool:
        """Whether the session that ended served for a while (`_served`), whatever ended it; and the run kept up to date.

        A run begins with a session that served for a while and then ended, cut, hung or refused: what fails in it, of
        any kind, is counted on, and a session that serves after it is not well again at SETTLED but at AGAIN_SOON (see
        `_settled`), unless the last failure is QUIET_AFTER ago (see `_forget_if_quiet`). (Settled at SETTLED, a console
        cut every minute was opened every minute and a quarter for good; and where a failure of another kind ended the run,
        a proxy that cut consoles and failed the next one now and then escaped the ladder all the same.)"""
        session = self._session
        if session is not None and session.let_in_at is not None:
            self._let_in_ended_at = time.monotonic()
        self._cut_run_before = self._cut_in_run
        served = session is not None and self._served(session)
        self._cut_in_run = self._cut_in_run or served
        return served

    def _forget_if_quiet(self, now: float) -> None:
        """QUIET_AFTER and more since the last failure: what failed before says nothing any more, and the ladders and the run
        begin again. (Only a clean end was forgiven after a quiet night; a moment of Proxmox's at the morning's first
        console counted on from the evening's top rung.)"""
        if now - self._failed_at >= self.QUIET_AFTER and (self._failures or self._bad or self._cut_in_run):
            self.forgive()

    def _settled(self) -> None:
        # A run with a session in it that served and was cut is over once one serves AGAIN_SOON, not SETTLED: settled at
        # SETTLED, every cut was the first failure again, and a console cut a minute after it opened was opened again every
        # minute and a quarter, for good.
        session, now = self._session, time.monotonic()
        served_long = session is not None and session.let_in_at is not None and now - session.let_in_at >= self.AGAIN_SOON
        if self._cut_in_run and now - self._failed_at < self.QUIET_AFTER and not served_long:
            return
        super()._settled()
        self.forgive()

    # --- what the owning tile asks -------------------------------------------------------------------------

    def live_seen(self) -> None:
        """A live line asks for the screen now: the pace is a viewer's for the next moments."""
        self._live_at = time.monotonic()
        self._looking()

    def _is_live(self) -> bool:
        return super()._is_live() or time.monotonic() - self._live_at < self.LIVE_FOR

    def size(self) -> tuple[int, int] | None:
        """The screen's width and height, where a session has said them."""
        client = self._connected_or_none()
        return (client.width, client.height) if client is not None and client.width else None

    async def ready(self, within: float) -> rfb.Client:
        """The session's client, connecting where there is none, waited for up to `within` seconds. KvmError where none came."""
        try:
            return self._connected(urgent=True)
        except KvmError as ex:
            if ex.code != "no_stream" or self._session is None:
                raise
        session = self._session
        try:
            async with asyncio.timeout(within):  # (no waiting task is left behind when the time runs out, or the caller is stopped)
                await session.ready.wait()
        except TimeoutError:
            pass
        if session.error is not None:
            raise session.error.with_traceback(None)
        return self._connected(urgent=True)

    async def let_go_key(self, usage: int) -> None:
        """A key let go of, on the session that is open; with none open, nothing (and none is opened for it)."""
        client, keysym = self._connected_or_none(), rfb.keysym_for(usage)
        if client is not None and keysym is not None:
            try:
                await client.key(keysym, False)
            except rfb.RfbError:
                pass  # (the session is ending, and the server lets go of what it held with it)

    async def let_go_pointer(self, x: int, y: int, buttons: int) -> None:
        """Buttons let go of, on the session that is open; as `let_go_key`."""
        client = self._connected_or_none()
        if client is not None:
            try:
                await client.pointer(x, y, buttons)
            except rfb.RfbError:
                pass

    def turned_away(self) -> str | None:
        """What keeps the screen away whatever is asked meanwhile: a refusal, a certificate that is not the one remembered,
        or sessions that failed three times in a row. Not a session that failed once or twice, whose pause a live line
        waits out (asking costs nothing then: see `_connected`); None where nothing like that stands."""
        now = time.monotonic()
        if self._refusal is not None and now < self._refusal_until:
            return self._refusal.message
        down = self._down_error
        if down is not None and now < self._down_until and (down.code in ("cert_mismatch", "cert_invalid") or self._failures >= 3):
            return down.message
        return None

    def refused_now(self) -> str | None:
        """Why the screen is not shown just now, while that stands: a session that was refused, or failed twice in a row
        (which is when it is held back from whoever is in a hurry too: see `_connected`), said where the owning tile says
        how the machine is; None where nothing stands."""
        now = time.monotonic()
        if self._refusal is not None and now < self._refusal_until:
            return self._refusal.message
        down = self._down_error
        if down is not None and now < self._down_until and (down.code in ("cert_mismatch", "cert_invalid") or self._failures > 1):
            return down.message
        return None
