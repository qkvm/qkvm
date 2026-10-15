"""What the wall needs from a KVM, and the client for GLKVM / PiKVM (kvmd) devices."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
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
from websockets.exceptions import WebSocketException
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
MAC = re.compile(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}")
# Up to eight key names as browsers and kvmd spell them: "ControlLeft,AltLeft,Delete".
KEYS = re.compile(r"[A-Z][A-Za-z0-9]{1,15}(,[A-Z][A-Za-z0-9]{1,15}){0,7}")
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
MAX_REPLY = 2 * 1024 * 1024  # bytes a device may send in answer to anything but a picture
MAX_PICTURE = 32 * 1024 * 1024  # ...and as one picture (a 4K frame, uncompressed, is 25 MB)
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
        """A person has typed this password for this device just now: it is tried as if for the first time."""
        for road in ROADS:
            self._known.pop(self.what(road, spec), None)

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


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    content_type: str
    signal: bool  # False when the device captured its "no signal" placeholder
    taken_at: float  # when the device was asked for it (time.monotonic())


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


def _transport_error(ex: BaseException, tls: str) -> KvmError:
    cause: BaseException | None = ex
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            if tls == "pinned":
                return KvmError("cert_mismatch", "Certificate does not match the one saved for this device")
            return KvmError("cert_invalid", "The device's certificate is not trusted")
        cause = cause.__cause__ or cause.__context__
    if isinstance(ex, (httpx.ConnectError, httpx.ConnectTimeout)):
        return KvmError("unreachable", "Device is unreachable")
    if isinstance(ex, httpx.TimeoutException):
        return KvmError("timeout", "Device did not respond in time", 504)
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
        super().__init__(uri, proxy=None, compression=None, create_connection=_ToADevice, **options)

    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc  # "not here, over there" is an answer like any other that is not a connection


def number(value: Any, low: float = 0, high: float = 1_000_000) -> int | float | None:
    """A device's number if it is one and within reason, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        return None
    return value


def flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


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
    # Kept open for longer than the longest pause between two looks (a tile that is watched is asked every
    # second, one that is only watched over for alerts every fifteen): otherwise every look begins with a new
    # connection, and over HTTPS with a new handshake, at the device's cost as much as at ours.
    LIMITS = httpx.Limits(max_connections=8, max_keepalive_connections=4, keepalive_expiry=30.0)

    def __init__(self, spec: DeviceSpec, on_pin: Callable[[str], Awaitable[None]] | None = None) -> None:
        self.spec = spec
        self.on_pin = on_pin  # told when a certificate is trusted on first contact
        # Told when the device answers at its other address from now on (a JetKVM whose HTTPS mode was switched).
        self.on_move: Callable[[str], Awaitable[None]] | None = None
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

    async def snapshot(self, width: int, fresh: float | None = None) -> Snapshot:
        """Latest frame, at least `width` pixels wide when the source has that many.

        `fresh`: how old, in seconds, a frame may be and still do (see share_window).
        """
        raise NotImplementedError

    def tidy(self) -> None:
        """Let go of what is only kept for viewers, once there are none. Called every half minute."""

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
                            timeout=WAITS,
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
        return {**status, "last_seen_ago": seen}

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
    """A GLKVM / PiKVM device, over kvmd's HTTP API."""

    kind = "kvmd"

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
        self._single_port_at: float | None = None  # when the device last said it has no port switch
        self._port_seen: int | None = None  # which computer was on screen at the last look (a multi-port KVM)
        self._usb_unsure = False  # another one is since, and the device has not found its keyboard there yet
        self._keepalive: asyncio.Task[None] | None = None
        self._wanted_at = 0.0
        self._ended_said = float("-inf")  # when it was last written down that the connection which keeps the picture coming ended

    async def close(self) -> None:
        self._closed = True
        await stopped([self._keepalive, *self._fetching.values()])
        await super().close()

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
        self, method: str, path: str, *, urgent: bool = False, vital: bool = True, still: Callable[[], bool] | None = None, **kwargs: Any
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
        """
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = False
        while True:
            token = self._token or await self._login()
            client = await self._http()
            limit = MAX_PICTURE if path == "/api/streamer/snapshot" else MAX_REPLY
            try:
                request = client.build_request(method, path, headers={"Cookie": f"auth_token={token}"}, **kwargs)
                if still is not None and not still():
                    raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
                resp = await self._send(client, request, limit)
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
        version = await self._optional("/api/upgrade/version", urgent=True)
        hostname = await self._optional("/api/system/get_hostname", urgent=True)
        return {
            "model": plain(_dig(version, "model"), 40),
            "version": plain(_dig(version, "version"), 40),
            "hostname": plain(_dig(hostname, "hostname")),
        }

    # --- snapshots ----------------------------------------------------------

    async def snapshot(self, width: int, fresh: float | None = None) -> Snapshot:
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
        return Snapshot(
            data=resp.content,
            content_type=kind,
            signal=resp.headers.get("x-ustreamer-online", "true").lower() != "false",
            taken_at=asked,
        )

    def _start_keepalive(self) -> None:
        if self._keepalive is None or self._keepalive.done():
            self._keepalive = asyncio.create_task(self._hold_stream_open())

    async def _hold_stream_open(self) -> None:
        """Stay connected to the kvmd websocket, as a browser viewer would, while the wall is watched."""
        url = "ws" + self.spec.base_url[len("http"):] + "/api/ws"
        try:
            token = self._token or await self._login()
            async with ws_connect(
                # GLKVM's own web client passes the token both ways; do the same.
                f"{url}?stream=1&auth_token={token}",
                ssl=self._tls,
                additional_headers={"Cookie": f"auth_token={token}"},
                open_timeout=6,
                close_timeout=1,  # a device that is gone gets no ten seconds to say goodbye in
                max_size=2**20,  # what arrives is thrown away, but is held in memory first
            ) as ws:
                heard = Listening(ws, 2**20)
                while time.monotonic() - self._wanted_at < KEEPALIVE_IDLE:
                    try:
                        await heard.message(5)
                    except TimeoutError:
                        pass
        except (KvmError, OSError, WebSocketException, TimeoutError) as ex:
            # Why it ended is, for a connection the device closed, a text of the device's choosing: said as
            # one line, whatever it holds. And once a minute: a device can end one a second.
            now = time.monotonic()
            if now - self._ended_said >= SAY_AGAIN:
                self._ended_said = now
                log.info("%s: stream keepalive ended: %s", self.label, plain(str(ex), 200))

    # --- actions ------------------------------------------------------------

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """Run one of ACTIONS, or:

        'wol'   wake `mac` from the device's network
        'keys'  press the key combination `keys` on the connected computer
        'text'  type `text` on the connected computer
        'port'  show input `port` (counted from 0) of a multi-port KVM
        """
        extra: dict[str, Any] = {}
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
        try:
            resp = await self._request("POST", path, urgent=True, params=params, still=still, **extra)
        except KvmError as ex:
            # A KVM that is already going down may never answer its own reboot request.
            if action == "reboot" and ex.code in ("dropped", "timeout"):
                return
            raise
        if resp.status_code != 200:
            try:
                result = read_json(resp)["result"]
                detail = result.get("error_msg") or result.get("error")
            except (ValueError, KeyError, TypeError, AttributeError):
                detail = None
            raise KvmError("action_failed", plain(detail, 200) or f"The device refused (HTTP {resp.status_code})")
        if action == "port":
            # What was on screen belongs to the other computer now.
            self._frames.clear()
            self._unseen.clear()
            self._screen += 1
            if self._status and self._status.get("ports"):
                self._status["ports"]["active"] = port
            self._status_at = 0.0

    async def wol_targets(self) -> list[dict[str, str]]:
        """Machines the KVM has saved for Wake-on-LAN (GLKVM only)."""
        result = await self._optional("/api/wol/list", urgent=True)
        targets = []
        devices = _dig(result, "devices")
        for entry in devices if isinstance(devices, list) else []:
            mac = as_text(_dig(entry, "mac"))
            if MAC.fullmatch(mac):
                name = plain(_dig(entry, "name")) or plain(_dig(entry, "hostname")) or plain(_dig(entry, "ip")) or ""
                targets.append({"mac": mac, "name": name})
        return targets

    # --- status -------------------------------------------------------------

    async def _read_about(self) -> dict[str, Any]:
        if not self._about or time.monotonic() - self._about_at > ABOUT_TTL:
            version = await self._optional("/api/upgrade/version", vital=False)
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
        info, hid, atx, about, ports = await asyncio.gather(
            self._get_result("/api/info", vital=False),
            self._get_result("/api/hid", vital=False),
            self._get_result("/api/atx", vital=False),
            self._read_about(),
            self._read_ports(),
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
        keyboard, mouse = flag(_dig(hid, "keyboard", "online")), flag(_dig(hid, "mouse", "online"))
        active = ports.get("active") if isinstance(ports, dict) else None
        if active is not None and active != self._port_seen:
            # Another computer is on screen than at the last look. A multi-port KVM goes on saying "no keyboard"
            # after that until a key has been sent (a real Comet X did, for minutes, and found it at the first
            # Shift): that is not knowing, and is told as not knowing, not as a cable that is out.
            self._usb_unsure = self._port_seen is not None
            self._port_seen = active
        if keyboard is True:
            self._usb_unsure = False
        elif self._usb_unsure:
            keyboard = mouse = None
        return {
            "state": "no_signal" if signal is False else "online",
            "error": None,
            "video": {
                "signal": signal,
                "width": width,
                "height": number(_dig(source, "resolution", "height"), 1, 100_000),
                "fps": number(_dig(source, "captured_fps"), 0, 1000),
            },
            "usb": {"keyboard": keyboard, "mouse": mouse},
            "atx": {
                "enabled": flag(_dig(atx, "enabled")) is True,
                "power": flag(_dig(atx, "leds", "power")),
                "hdd": flag(_dig(atx, "leds", "hdd")),
            },
            "health": {
                "temp": number(_dig(health, "temp", "cpu"), -100, 300),
                "cpu": number(_dig(health, "cpu", "percent"), 0, 100),
                "mem": number(_dig(health, "mem", "percent"), 0, 100),
            },
            "about": {"model": _dig(about, "model"), "version": _dig(about, "version")},
            "ports": ports if isinstance(ports, dict) else None,
        }
