"""Images qKVM serves to a server's management controller, for as long as one is mounted there (0.3.0, A4).

A server's controller mounts an image by an address it fetches it from (Redfish's InsertMedia), and reads it piece by piece
for the whole of the mount, as the server reads its CD-ROM drive. It is only ever handed an address qKVM made for that one
mount: `<the wall's address as servers reach it>/media/<token>/<name>`, the token 256 random bits in the path (no query
string: some controllers refuse an address with ? or & in it), good for that image alone, answered to the controller's own
address alone, and ended when the image is taken out, when the tile is removed or its address changed, and when qKVM stops.
Over HTTPS it comes with a user and a password made for that mount as well (AMI's controllers want them), which every
request for the image has to bring.

The images are files in a folder the admin names (Settings, Server images): an ISO image directly in it, by a name qKVM hands
on (kvm.IMAGE_NAME), a file of its own and not a link. Nothing is written there. A file changed or replaced while it is
mounted is not served any more: what the controller reads is the image that was mounted.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import os
import re
import secrets
import socket
import stat
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, BinaryIO, NamedTuple
from urllib.parse import urlsplit

from .kvm import IMAGE_NAME, MOST_DEVICE_IMAGES

SUFFIX = ".iso"  # a server's virtual CD-ROM drive takes an ISO image (AMI's: "Only CD MediaType is supported in Redfish")
# A mount whose end was not seen (no answer to it, or the controller shows nothing in its drive yet) keeps its image served
# for this long; a look that finds the drive empty after it, or another image in it, ends it.
LEND_GRACE = 120.0
MOST_AT_ONCE = 8  # requests for one mounted image answered at once (a controller asks for a piece or two at a time)
# The images are opened, read and let go of by these threads and no others: a folder on a share that stalls holds them
# up, and nothing else of the wall's (a file's close waits for the read that holds it, as long as the share stalls).
READERS = ThreadPoolExecutor(max_workers=4, thread_name_prefix="served")
PIECE = 256 * 1024  # bytes read from the file at a time
MOST_REFUSED_SAID = 8  # other addresses that asked for one mounted image, each said in the log once
ADDRESS_WAIT = 5.0  # seconds the controller's name may take to be looked up, where its tile has a name and not an address
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")  # what secrets.token_urlsafe(32) makes: 256 bits
# The image's name in the address: what no controller takes for anything but a name (a space, a bracket, a plus each
# written as "_"), and the image itself is the one the token stands for.
URL_NAME = re.compile(r"[A-Za-z0-9._-]{1,200}")
# What a mounted image's address looks like, on whatever host: to know one qKVM made before it was restarted.
SERVED_PATH = re.compile(rf"/media/{TOKEN.pattern}/[A-Za-z0-9._-]{{1,200}}")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\]")


RANGE = re.compile(r"bytes=([0-9]{1,19})?-([0-9]{1,19})?")
# What has the shape of a token of qKVM's (TOKEN, standing alone), wherever a controller's words are passed on: a
# controller may say back the address it was handed, in a refusal, in its task, or as the name of what is in its drive.
_TOKEN_SAID = re.compile(rf"(?<![A-Za-z0-9_-]){TOKEN.pattern}(?![A-Za-z0-9_-])")
HIDDEN = "(hidden)"


def byte_range(header: str | None, size: int) -> tuple[int, int, bool] | None:
    """What a request's Range asks of an image of `size` bytes: (first, last, whether it is a part), the whole where it asks
    for none or for what is not one range of bytes (several of them, say: HTTP lets a server answer the whole then); None
    where the range begins past the end (answered 416)."""
    found = RANGE.fullmatch(header.strip()) if header else None
    if found is None or found.groups() == (None, None):
        return 0, size - 1, False
    first, last = found.groups()
    if first is None:
        wanted = int(last)
        return (max(0, size - wanted), size - 1, True) if wanted > 0 and size > 0 else None
    start = int(first)
    if last is not None and int(last) < start:
        return 0, size - 1, False  # (no range at all: one that ends before it begins)
    if start >= size:
        return None
    return start, min(size - 1 if last is None else int(last), size - 1), True


def basic_matches(header: str, credentials: tuple[str, str]) -> bool:
    """Whether an Authorization header brings this user and password (HTTP's Basic), compared in constant time."""
    scheme, _, said = header.strip().partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        user, sep, password = base64.b64decode(said.strip(), validate=True).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    same_user = hmac.compare_digest(user.encode(), credentials[0].encode())
    same_password = hmac.compare_digest(password.encode(), credentials[1].encode())
    return bool(sep) and same_user and same_password


def read_at(handle: BinaryIO, at: int, most: int) -> bytes:
    """`most` bytes of the file from `at` (in one of READERS)."""
    handle.seek(at)
    return handle.read(most)


def let_go_of(handle: BinaryIO) -> None:
    """The file closed (in one of READERS: it waits for a read of it under way)."""
    try:
        handle.close()
    except OSError:
        pass


class Slot:
    """A read's place among MOST_AT_ONCE, given back once, from whichever thread: by the reader threads where its file is
    let go of there, never by a loop that may have ended meanwhile (the outside review's second round, R2-M1: the places
    of reads cut off while their files were opened were given back by the listener's loop, which a restart of the
    listeners ends first: the eight stayed taken, and every read after was refused)."""

    def __init__(self, lending: Lending) -> None:
        self._lending = lending
        self._given = False

    def give_back(self) -> None:
        with self._lending.places:
            if not self._given:
                self._given = True
                self._lending.at_once -= 1


def let_go_and_give_back(handle: BinaryIO, slot: Slot) -> None:
    """The file closed, then its read's place given back (in one of READERS: the close waits for a read under way)."""
    try:
        let_go_of(handle)
    finally:
        slot.give_back()


class Opening:
    """A read's file being opened, owned by the reader thread that opens it: where the read is cut off meanwhile
    (`abandon`), the file is let go of and its place given back by that thread when it has it, whatever became of the loop
    that waited for it."""

    def __init__(self, lending: Lending, slot: Slot, readers: Callable[[], ThreadPoolExecutor]) -> None:
        self._lending, self._slot, self._readers = lending, slot, readers
        self._lock = threading.Lock()
        self._abandoned = False
        self._handle: BinaryIO | None = None
        self._failed = False
        self.pending: Future[BinaryIO | None] | None = None  # its job in the readers' queue, where it was handed there

    def run(self) -> BinaryIO | None:
        """In one of READERS: the file, opened (None where the read was cut off meanwhile: let go of, and its place given)."""
        try:
            handle = self._lending.opened()
        except BaseException:
            with self._lock:
                self._failed = True
                abandoned = self._abandoned
            if abandoned:
                self._slot.give_back()
            raise
        with self._lock:
            if not self._abandoned:
                self._handle = handle
                return handle
        let_go_and_give_back(handle, self._slot)
        return None

    def abandon(self) -> None:
        """The read was cut off: what is opened already is let go of (in a reader thread), what is not yet, once it is."""
        with self._lock:
            self._abandoned = True
            handle, self._handle = self._handle, None
            failed = self._failed
        if self.pending is not None and self.pending.cancel():
            self._slot.give_back()  # (it never started, and never will: nothing was opened)
            return
        if failed:
            self._slot.give_back()
        elif handle is not None:
            hand_to_readers(self._readers, let_go_and_give_back, handle, self._slot)


def hand_to_readers(readers: Callable[[], ThreadPoolExecutor], work: Callable[..., Any], *given: Any) -> None:
    """`work` done in one of the reader threads, waited for by nobody; here at once where they have stopped (qKVM stops);
    and where it was dropped from their queue unstarted (a pool stopped with its queue cancelled), there and then: so that
    no file stays open and no read's place stays taken (the outside review's third round found eight of each)."""
    try:
        future = readers().submit(work, *given)
    except RuntimeError:
        work(*given)
        return
    future.add_done_callback(lambda done: work(*given) if done.cancelled() else None)


def scrubbed(text: str, lending: Lending | None = None) -> str:
    """`text` (a controller's words) with nothing in it of what qKVM made for a mount: the address it handed the controller,
    the token, the mount's user and password (`lending`'s), and whatever has the shape of a token of qKVM's (another
    mount's, one from before a restart). Before the words are cut to their length, or a part of one would be left."""
    if lending is not None:
        for made in (lending.url, lending.token, *(lending.credentials or ())):
            text = text.replace(made, HIDDEN)
    return _TOKEN_SAID.sub(HIDDEN, text)


def url_name(name: str) -> str:
    """The image's name as it goes into the address handed to the controller."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def address_of(text: str) -> str | None:
    """`text` as the address servers reach the wall at: "http://" or "https://", a host and a port where it is not the
    scheme's own, and nothing else (no path, no query, no user); None where it is not such an address."""
    text = text.strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    netloc = parts.netloc
    host = netloc.rsplit(":", 1)[0] if port is not None else netloc
    if parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        return None
    if parts.path not in ("", "/") or not _HOST.fullmatch(host) or (port is not None and not 1 <= port <= 65535):
        return None
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
    return f"{parts.scheme}://{host.lower()}" + (f":{port}" if port is not None else "")


def same_address(text: str) -> str | None:
    """An address as it is compared: IPv4 written plainly (one mapped into IPv6 as itself); None for what is no address."""
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


async def addresses_of(base_url: str) -> frozenset[str]:
    """Where a controller at `base_url` (its tile's address) asks from: the address itself, or the addresses its name stands
    for, looked up now. Empty where its name stands for none just now."""
    host = urlsplit(base_url).hostname or ""
    plain = same_address(host)
    if plain is not None:
        return frozenset({plain})
    try:
        async with asyncio.timeout(ADDRESS_WAIT):
            found = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, TimeoutError):
        return frozenset()
    return frozenset(one for info in found if (one := same_address(str(info[4][0]))) is not None)


@dataclass(frozen=True)
class FolderImage:
    """An image in the folder, as it was found: where, how large, and the file it was (to know it again)."""

    name: str
    path: str
    size: int
    stamp: tuple[int, int, int]  # (st_ino, st_size, st_mtime_ns)


def _stamp(found: os.stat_result) -> tuple[int, int, int]:
    return (found.st_ino, found.st_size, found.st_mtime_ns)


def listing(folder: str) -> tuple[list[FolderImage], list[str], int]:
    """The images in `folder` (in a worker thread: a folder on a network share may be slow): (images, a sentence for what
    stands in the way, how many .iso entries were left out: a link, a folder, a name qKVM does not hand on)."""
    if not folder:
        return [], ["No folder for server images is named: an admin names one in Settings, Server images."], 0
    if not os.path.isabs(folder):
        return [], [f"The folder for server images ({folder}) is no whole path: name it again in Settings, Server images."], 0
    images: list[FolderImage] = []
    left_out = 0
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                if not entry.name.lower().endswith(SUFFIX):
                    continue
                try:
                    found = os.lstat(entry.path)  # (not the entry's own: on Windows its file number is always 0)
                except OSError:
                    left_out += 1
                    continue
                if not stat.S_ISREG(found.st_mode) or entry.is_symlink() or not IMAGE_NAME.fullmatch(entry.name) or len(images) >= MOST_DEVICE_IMAGES:
                    left_out += 1
                    continue
                images.append(FolderImage(entry.name, entry.path, found.st_size, _stamp(found)))
    except FileNotFoundError:
        return [], [f"The folder for server images ({folder}) is not there."], 0
    except NotADirectoryError:
        return [], [f"The folder for server images ({folder}) is a file, not a folder."], 0
    except OSError as ex:
        return [], [f"The folder for server images ({folder}) could not be read: {ex.strerror or type(ex).__name__}."], 0
    images.sort(key=lambda one: one.name.casefold())
    return images, [], left_out


class Superseded(Exception):
    """A mount that is not served as it was asked: its tile was changed while it was being mounted (Served.changed), or the
    address servers reach the wall at was."""


class Binding(NamedTuple):
    """What a mount under way is bound to, as it was when it was asked: its tile's controller (Lending.identity), its kind,
    and the tile's count of changes (Served.epoch)."""

    identity: tuple[str | None, str, str]
    kind: str
    epoch: int


# The identity of a tile kept beside another at its address ("Keep both"): qKVM's own label, "own:" and the tile's id.
OWN_LABEL = "own:"


def mark_extends(had: str, has: str) -> bool:
    """Whether a machine's mark `has` is `had` with a server's controller's number added: "server:" and the 32 hex digits of
    the computer's number, then the 32 of its controller's (redfish.marks_of). The one way a mark grows."""
    return re.fullmatch(r"server:[0-9a-f]{32}", had) is not None and re.fullmatch(re.escape(had) + r"[0-9a-f]{32}", has) is not None


def identity_follows(had: tuple[str | None, str, str], has: tuple[str | None, str, str]) -> tuple[str | None, str, str] | None:
    """The controller `has` (a certificate, a machine's mark, an identity) as the one `had` became, where it is that one; None
    where it may be another (the outside review's fourth round). A certificate compares whole. A mark compares whole, or
    grows by a server's controller's number (`mark_extends`). A field `had` did not know is learned only where something
    else it knew (an anchor) still matches: known by nothing, any identity is another's for all that can be told. A
    "Keep both" tile's identity (`own:<id>`) is qKVM's own label, which no controller said: compared, never an anchor
    (the outside review's fifth round)."""
    had_cert, had_machine, had_ident = had
    has_cert, has_machine, has_ident = has
    if had_cert != has_cert:
        return None
    anchored = bool(had_cert or had_machine or (had_ident and not had_ident.startswith(OWN_LABEL)))
    if has_machine != had_machine and not (mark_extends(had_machine, has_machine) or (not had_machine and anchored)):
        return None
    if has_ident != had_ident and not (not had_ident and anchored):
        return None
    return (had_cert, has_machine or had_machine, has_ident or had_ident)


@dataclass
class Lending:
    """One image, mounted on one server: what its controller may read, from where, and since when."""

    token: str
    device_id: str
    tile_url: str  # the tile's address when it was mounted: changed since, the image is not this tile's server's any more
    addresses: frozenset[str]  # where the controller's requests may come from
    image: FolderImage
    credentials: tuple[str, str] | None  # (user, password) every request must bring (over HTTPS)
    url: str  # what the controller was handed: said to it and to nobody else
    by: str
    # The controller's identity when it was mounted (its tile's pinned certificate, its `machine` and `ident`): another
    # controller accepted at the same address since is not this mount's (the outside review's second round, R2-M2)
    identity: tuple[str | None, str, str] = (None, "", "")
    kind: str = ""  # its tile's kind when it was mounted: changed since, another driver speaks for that tile
    at: float = field(default_factory=time.time)
    # The boot override set from qKVM for this mount (redfish.BootOverride), to be cleared again at the unmount.
    override: Any = None
    ended: bool = False
    at_once: int = 0  # reads taken and not given back (`take`, Slot): from the loop and from the reader threads, under `places`
    places: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    served: int = 0  # bytes the controller has read of it
    refused: set[str] = field(default_factory=set)  # other addresses that asked for it (said in the log, each once)

    @property
    def name(self) -> str:
        return self.image.name

    def take(self, most: int) -> bool:
        """A place among `most` reads at once, taken where there is one."""
        with self.places:
            if self.at_once >= most:
                return False
            self.at_once += 1
            return True

    @property
    def url_name(self) -> str:
        return url_name(self.image.name)

    def opened(self) -> BinaryIO:
        """The file, opened now, where it is still the image that was mounted (in one of READERS); OSError otherwise."""
        handle = open(self.image.path, "rb")  # (closed by whoever serves it)
        try:
            found = os.fstat(handle.fileno())
            if not stat.S_ISREG(found.st_mode) or _stamp(found) != self.image.stamp:
                raise FileNotFoundError("the image was changed or replaced since it was mounted")
        except BaseException:
            handle.close()
            raise
        return handle


class Served:
    """The images mounted on the wall's servers, one at a time per tile: kept by the wall while it runs (a tile is made anew at
    every edit, and its mount goes on), gone when it stops. `folder` and `address` say the settings as they are now."""

    def __init__(
        self, folder: Callable[[], str], address: Callable[[], str | None],
        identity: Callable[[str], tuple[str | None, str, str]] | None = None, https: Callable[[], bool] | None = None,
    ) -> None:
        self._folder = folder
        self._address = address
        # A tile's controller as it is known now (its saved record's pinned certificate, `machine` and `ident`): what a
        # mount is bound to (Lending.identity)
        self._identity = identity
        self._https = https  # whether the wall itself serves HTTPS (core.https): what the Media box advises depends on it
        # The controller each tile's mount under way is to be bound to, as it was known when that mount was asked: an edit
        # that slips in meanwhile changes the saved record, not this (the outside review's third round)
        self.binding: dict[str, Binding] = {}
        # Each tile's count of changes that end what is lent to it (`changed`): a mount asked before one hands out nothing
        self._epoch: dict[str, int] = {}
        self._of: dict[str, Lending] = {}  # tile id -> its image
        self._by_token: dict[str, Lending] = {}

    def serves_https(self) -> bool:
        """Whether the wall itself serves HTTPS (its address in Settings, Server images may still name plain HTTP)."""
        return bool(self._https is not None and self._https())

    def base(self) -> str | None:
        """The wall's address as servers reach it (the setting, or else where it listens on the network); None: none."""
        return self._address()

    async def images(self) -> tuple[list[FolderImage], list[str], int]:
        return await asyncio.to_thread(listing, self._folder())

    async def image(self, name: str) -> FolderImage | None:
        """The image of that name in the folder, as it is now; None where it is not there (or is no image qKVM serves)."""
        images, _, _ = await self.images()
        return next((one for one in images if one.name == name), None)

    def epoch(self, device_id: str) -> int:
        return self._epoch.get(device_id, 0)

    def changed(self, device_id: str) -> None:
        """A tile was changed in what it is (its address, its kind, how it is checked, its certificate, its controller), or
        removed: what is lent to it ends, and a mount of it under way hands out nothing (`lend`)."""
        self._epoch[device_id] = self.epoch(device_id) + 1
        self.end(device_id)

    def lend(
        self, device_id: str, tile_url: str, addresses: frozenset[str], image: FolderImage, *, base: str, by: str,
        identity: tuple[str | None, str, str] | None = None, cert_checked: str | None = None, kind: str = "",
    ) -> Lending:
        """Serve `image` to the controller of tile `device_id`, from `addresses` alone, at `base` (the one reading of the
        settings that makes its address, and whether it is HTTPS with a password): what it had before is ended. Bound to the
        controller its mount was asked of (Binding), and to the certificate the mounting driver checked where none was
        saved (`cert_checked`). Superseded where the tile or `base` was changed since."""
        if self.base() != base:
            raise Superseded("The address servers reach qKVM at was changed while it was being mounted")
        bound = self.binding.get(device_id)
        if bound is not None and bound.epoch != self.epoch(device_id):
            raise Superseded("The tile was changed while it was being mounted")
        if identity is None:
            identity = bound.identity if bound is not None else self._identity(device_id) if self._identity is not None else (None, "", "")
        if identity[0] is None and cert_checked:
            identity = (cert_checked, identity[1], identity[2])
        self.end(device_id)
        token = secrets.token_urlsafe(32)
        credentials = ("qkvm-" + secrets.token_hex(4), secrets.token_urlsafe(24)) if base.startswith("https://") else None
        lending = Lending(token, device_id, tile_url, addresses, image, credentials, f"{base}/media/{token}/{url_name(image.name)}", by,
            identity, bound.kind if bound is not None else kind,
        )
        self._of[device_id] = lending
        self._by_token[token] = lending
        return lending

    def end(self, device_id: str, lending: Lending | None = None) -> None:
        """Stop serving what is mounted on that tile's server (only `lending`, where it is named): at once, a reading under way
        included."""
        found = self._of.get(device_id)
        if found is None or (lending is not None and found is not lending):
            return
        found.ended = True
        del self._of[device_id]
        self._by_token.pop(found.token, None)

    def of(self, device_id: str) -> Lending | None:
        return self._of.get(device_id)

    def find(self, token: str) -> Lending | None:
        return self._by_token.get(token) if TOKEN.fullmatch(token) else None
