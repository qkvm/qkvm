"""Backups of the whole wall to a folder, always encrypted, and reading one back: to check it, or to restore it.

What a backup is: everything needed to bring the wall back on another computer. Its settings as the wall keeps them (devices,
saved actions, accounts with what their passwords open and their two-factor keys, tokens, alert destinations, the identity
provider's settings), but never a backup key (without_key); the wall's data key that every saved secret of those settings
is sealed with (vault.py); the files of the activity log with the log's key and the place its chain had come to (the
settings keep both); and, where asked for, the history (history.sqlite), copied by SQLite's online backup and never as the
bytes of a file in use.

How it is sealed. With the backup key, 32 random bytes the wall makes apart from every key it has (kept in its vault, so
that a run by the clock needs nobody; shown once as a recovery kit, `kit`). The kit is all it takes to read a backup: no
file of the computer it was made on (not the server storage key, `--vault-key-file`, which seals the settings there) is in
it or needed. Each file has a key of its own, derived from the backup key and 32 random bytes in its head (HKDF-SHA256),
and its content, compressed, is sealed with that key in frames of a mebibyte (AES-256-GCM), each frame's nonce its number
and whether it is the last, each frame bound to the file's head: a frame changed, moved, left out or added, a head changed,
a file cut short or with anything after its last frame is refused as a whole (the STREAM construction of Hoang,
Reyhanitabar, Rogaway and Vizar). The head says, in clear: that it is a backup of qKVM's, the version of the format and of
the program that made it, when, which key opens it (`key_id`, a mark of the key that gives nothing of it away) and the
random bytes. Nothing of the wall can be read off it but its size.

How it differs from an export (exchange.py): an export is for a person to take devices and settings to another wall, sealed
with a passphrase they choose, its every entry checked on the way in as if typed; it never holds accounts, tokens or
two-factor keys, which are locked to the wall's own key. A backup is the wall itself, made by the clock, sealed with a key
of the wall's that nobody types, and restored only into an empty data folder, as it was (`restore`): accounts, their rights
and their passwords, the identity provider as it was set up, the activity log that checks as it did.

What is written goes to a name that is no backup's (".qkvm-backup-<key id>-...partial") until it is whole, on the disk,
and has been read back whole with the key; only then does it take a backup's name ("qkvm-backup-<key id>-<time>"), and
only then do the oldest of this key's beyond those to keep go, never the new one. Another key's backups (another wall's
in the same folder, or this wall's under a key made before) and anything else in the folder are never touched. Every file
and folder it makes is the wall's account's alone.
"""

from __future__ import annotations

import asyncio
import base64
import calendar
import concurrent.futures
import contextlib
import datetime
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import threading
import time
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._folders import own_folder, private

FORMAT = "qkvm-backup"
VERSION = 1  # of the file: a later version of this program reads every earlier one, and refuses a later one
MAGIC = b"QKVM-BACKUP\n"
SUFFIX = ".qkvmbackup"
# A backup's name: the key it opens with (key_id) and when it was made (UTC), so that a wall knows its own among others' in
# one folder (another wall's, or its own under a key made before), and never touches theirs.
# (Digits as [0-9]: \d is any script's, and a name with other digits for its time would be read as a time.)
NAME = re.compile(r"qkvm-backup-([0-9a-f]{16})-([0-9]{8}-[0-9]{6})(?:-([0-9]{1,3}))?\.qkvmbackup")
PARTIAL = re.compile(r"\.qkvm-backup-([0-9a-f]{16})-[0-9]{8}-[0-9]{6}(?:-[0-9]{1,3})?\.partial")  # ...and one in the making, which is none
KEY_BYTES = 32
SEALED_FOR = "backup:key"  # what the backup key is sealed for in the vault (store.BackupSettings.secret)
CHUNK = 1 << 20  # bytes of the compressed content a frame seals; the last may have fewer
LAST = 1 << 31  # the bit of a frame's length that says it is the last
TAG = 16
MOST_HEAD = 4096  # bytes of a head, at the most
MOST_SETTINGS = 64 * 1024 * 1024  # bytes of the settings in a backup, at the most (as vault_storage.MAX_BYTES)
MOST_PART = 1 << 40  # bytes of any other part, at the most (a part says its size before it, and is read up to that)
BLOCK = 1 << 20  # bytes read and written at a time
LOGS = ("audit.log", *(f"audit.log.{number}" for number in range(1, 10)))  # the activity log's files (store.AuditLog)
HISTORY = "history.sqlite"
# Where a run copies the history to, in the data folder, before it goes in (History.copy_to): a name of each run's own, so
# that a run cut off by its bound and still going can never take the copy of the next from under it.
HISTORY_COPY = "backup-history-{}.tmp"
HISTORY_COPIES = re.compile(r"backup-history-[0-9]{1,20}\.tmp")
SETTINGS = "backup.json"  # the part that holds the settings and the data key: always the first
END = "end"  # ...and the last, which holds nothing
PARTS = frozenset({SETTINGS, *LOGS, HISTORY, END})
_INFO = b"qkvm-backup 1 file key"
_ID = b"qkvm backup key id"
_CHECK = b"qkvm backup key check"
_ALPHABET = re.compile(r"[A-Z2-7]{56}")
_IN_GROUPS = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9]{4}(?:[ -][A-Za-z0-9]{4}){13})(?![A-Za-z0-9])")


T = TypeVar("T")


class FolderTimeout(Exception):
    """Work on the folder came to its bound (FolderThreads.run): its thread goes on. Not a TimeoutError, which is an OSError,
    and which a folder of its own may raise (an NFS or SMB folder that answers ETIMEDOUT): that is the folder's to say."""


def place_of(folder: str) -> str:
    """A folder as it is compared with another (its whole path, in the case the system compares names in): "" for none."""
    return os.path.normcase(os.path.abspath(folder)) if folder else ""


def folder_identity(folder: Path, stat: Callable[[Path], os.stat_result] = os.stat, root: Callable[[Path, int], str | None] | None = None) -> tuple[Any, ...]:
    """What a folder is on the disk, by whatever name this computer gives it (a junction, a link, a short name, another
    spelling; on Windows a mapped drive and the share's UNC name): its device and file number (of the nearest folder above
    it that is there, with the rest of the path below that, where it is not there: FolderThreads makes it first,
    ready_folder, so that it is known by itself). Compared by same_place.

    Where the system gives no file number (some shares give 0), the folder cannot be told apart from another of its
    volume by any name it has: its whole volume, by its number (the fresh review of the fixes, N1), so that no run is begun
    beside one into any folder of a volume of that number, whatever share, server or name it is reached by. Only a volume
    numbered 0 is told apart by the root of the share it is on as well (`root`, share_root: on Windows the
    \\\\server\\share, from its name or the mapped drive's; on Linux the source of the mount; None where that cannot be
    had, which holds every volume numbered 0): some servers say 0 for every share of theirs, and two of them say it alike
    (the last look at the fixes of 0.4.0, L3). A root is made of the name the share is reached by, and the same share by two
    names of its server (its name and its address, say) has two: told apart by it wherever a volume had a number, a run
    began beside one cut off into the same folder (the final look at 0.4.0, M2). So such a share numbered 0, reached by
    two names of its server, is not known as one (each run's file in the making is its own all the same: make).

    On Linux a second mount of the same share usually has a device number of its own, and is not known as the same folder
    (a bind mount of it has the same number, and is).

    Asks the disk, which may never answer, and reads what is mounted: for a folder's own thread, never the event loop.
    OSError where nothing of it can be looked at."""
    rest: list[str] = []
    at = folder
    while True:
        try:
            seen = stat(at)
            break
        except FileNotFoundError:
            if at.parent == at:
                raise
            rest.append(at.name)
            at = at.parent
    if not seen.st_ino:
        return ("volume", seen.st_dev, (root or share_root)(at, seen.st_dev) if seen.st_dev == 0 else None)
    return ("file", seen.st_dev, seen.st_ino, os.path.normcase(os.sep.join(reversed(rest))))


def same_place(one: Any, other: Any) -> bool:
    """Whether two of what folders are on the disk (folder_identity) may be one folder: the same, or two folders of shares
    without file numbers on volumes of one number: any number but 0 whatever their roots, and 0 of one share's root or of
    one whose root was not to be had (the safe side). None, for a folder not yet looked at, is none."""
    if one is None or other is None:
        return False
    if one[0] == other[0] == "volume":
        return bool(one[1] == other[1] and (one[1] != 0 or one[2] is None or other[2] is None or one[2] == other[2]))
    return bool(one == other)


def share_root(folder: Path, device: int) -> str | None:
    """The root of the share `folder` (that is there) is on, as this computer says it, in a form two names of it give
    alike: on Windows \\\\server\\share in small letters, from its UNC name, or from what its drive is mapped to; on Linux
    the source of the mount of `device` (//server/share, server:/export). None where that is not to be had. Asks the system
    what is mounted: for a folder's own thread."""
    try:
        if sys.platform == "win32":
            return windows_share(str(folder), _mapped_drive)
        return mount_source(device)
    except Exception:  # (whatever goes wrong in asking is no root: the whole volume, the safe side; never the folder's thread ended)
        return None


def windows_share(path: str, mapped: Callable[[str], str | None]) -> str | None:
    """The \\\\server\\share a Windows path is on, in small letters: of its own UNC name (also written with forward
    slashes, or as \\\\?\\UNC\\server\\share), or of what its drive letter is mapped to (`mapped`: Z: to what it is mapped
    to, or None). None for any other path."""
    name = path.replace("/", "\\")
    if name[:4] in ("\\\\?\\", "\\\\.\\"):
        name = "\\\\" + name[8:] if name[4:8].upper() == "UNC\\" else name[4:]
    if len(name) >= 2 and name[1] == ":" and name[0].isascii() and name[0].isalpha():
        name = (mapped(name[:2].upper()) or "").replace("/", "\\")
    if not name.startswith("\\\\"):
        return None
    server, _, below = name[2:].partition("\\")
    share = below.partition("\\")[0]
    if not server or not share or server in ("?", "."):
        return None
    return f"\\\\{server}\\{share}".lower()


def _mapped_drive(drive: str) -> str | None:
    """What a drive letter (Z:) is mapped to for this account, as Windows says it (WNetGetConnectionW): \\\\server\\share;
    None where it is no mapped drive, or this cannot be asked. Asked only of a folder whose volume gives no file numbers."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    try:
        get = ctypes.WinDLL("mpr", use_last_error=True).WNetGetConnectionW
    except (OSError, AttributeError):
        return None
    get.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    get.restype = wintypes.DWORD
    size = wintypes.DWORD(1024)
    buffer = ctypes.create_unicode_buffer(size.value)
    if get(drive, buffer, ctypes.byref(size)) != 0:  # (NO_ERROR only: not mapped, not connected, or more than this)
        return None
    return buffer.value or None


MOUNTINFO = Path("/proc/self/mountinfo")


def mount_source(device: int, mountinfo: Path = MOUNTINFO) -> str | None:
    """The source of the mount of device number `device` (st_dev), as Linux says it: //server/share of an SMB share,
    server:/export of NFS. None where that is not said (not Linux, nothing mounted with that number)."""
    if sys.platform == "win32":
        return None
    return source_of(f"{os.major(device)}:{os.minor(device)}", mountinfo)


def source_of(numbers: str, mountinfo: Path = MOUNTINFO) -> str | None:
    """The source of the first mount listed in `mountinfo` (proc(5)) whose device is `numbers` (major:minor): the same for
    every mount of it (a bind mount of it says the same), however its folders are named. None where none is."""
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        mounted, between, described = line.partition(" - ")
        fields, said = mounted.split(" "), described.split(" ")
        if between and len(fields) >= 5 and fields[2] == numbers and len(said) >= 2 and said[1]:
            return re.sub(r"\\([0-7]{3})", lambda escaped: chr(int(escaped.group(1), 8)), said[1])  # (a blank is \040)
    return None


def ready_folder(folder: Path) -> None:
    """The backups' folder there: made where it is not, the wall's account's alone, and only where the folder above it is
    there (a share that is not mounted leaves its mount point empty, and the folders made below it would be on the computer's
    own disk, the backups with them, for as long as nobody looked). BackupError "no_folder" where that is not there."""
    if not folder.is_dir():
        if not folder.parent.is_dir():
            raise BackupError("no_folder", f"{folder.parent} is not there (a share not mounted?): the backups' folder is made only in a folder that is there")
        own_folder(folder)


@dataclass(frozen=True)
class Run:
    """What a run of the backups is made for, taken at one moment with its key and the settings it holds (server.back_up): its
    end is this folder's and this key's, and is Settings' last run only while backups still go there, with that key."""

    folder: str  # as it was given ("" for none)
    key: str = ""  # the id of the key it seals with (key_id), as the settings know it
    keep: int = 7
    history: bool = False
    how: str = ""  # "by the clock", or "by hand"
    began: float = 0.0  # when it was begun (time.time)


@dataclass
class Working:
    """Work on a folder that is under way, or held by the folder (FolderThreads.working)."""

    folder: str  # the folder it was begun for, as it was given ("" for work that names none)
    since: float
    cut_off: bool = False  # its waiter was told it took too long, or its bound came with nobody waiting: its thread goes on
    left: bool = False  # nobody waits for it any more (cut off, or its waiter stopped: the listeners opened anew)
    told: bool = False  # how it ended was handed to `late` (once, by whichever of the two comes to it first)
    # Its bound, on the clock that never steps (time.monotonic), kept with it and not with its waiter: a waiter stopped (the
    # listeners opened anew) takes no bound with it, and whoever looks next says it is cut off once that has come (overdue).
    deadline: float = math.inf
    within: float = 0.0  # ...how long that bound was
    for_run: Run | None = None  # a backup run's: what it was made for
    identity: Any = None  # what its folder is on the disk (folder_identity), once its thread has found that out


class FolderThreads:
    """Work on the backups' folder, on threads of its own and never on the wall's shared pool (asyncio.to_thread): a folder
    that does not answer (a hard NFS mount whose server is gone, a share that hangs) holds these threads alone, however long,
    and the wall's saves, seals and history go on. At most `most` at once. Each is waited for up to a bound, after which
    whoever asked is told so (TimeoutError), while the thread, which nothing can stop, keeps its place until the folder
    answers. Once every place is held, the folder is asked nothing more, and that is said at once (BackupError "busy").
    Daemon threads: a wall that stops does not wait for a folder that never answers. Kept with the program (core.Core), not
    with its listeners, which are opened anew now and then."""

    def __init__(self, most: int = 2, busy: str = "", same_folder: str = "") -> None:
        self.most = most
        self.busy = busy or "The backups' folder has not answered for a while (a share whose server is gone?): it is asked nothing more until it answers"
        # Where given: what is said of work into a folder that work of these holds already (one folder, one at a time: a run
        # cut off on a share that never answers holds that share alone, and work into another goes on). The folder is known
        # by its name, and by what it is on the disk (folder_identity), which each such work's thread finds out first: by
        # another name for it (a junction, a link, a short name), work begun beside the other would take away its file in
        # the making (the outside review of 0.4.0, bugs round, M6).
        self.same_folder = same_folder
        self._working: list[Working] = []
        self._known: dict[str, Any] = {}  # a folder's name (place_of) -> what it is on the disk, as found out last
        self._lock = threading.Lock()

    @property
    def held(self) -> int:
        """Threads at work on a folder, or held by it, at this moment."""
        return len(self._working)

    def working(self) -> list[Working]:
        """What these threads are at, or held by, at this moment."""
        with self._lock:
            return list(self._working)

    def holding(self, folder: str) -> Working | None:
        """The work that holds this folder, by its name, or by what it is on the disk where that is known of the name (found
        out by work into it before): never asking the disk itself, which may not answer."""
        with self._lock:
            return self._holding(place_of(folder))

    def _holding(self, place: str) -> Working | None:
        if not place:
            return None
        known = self._known.get(place)
        return next((each for each in self._working if place_of(each.folder) == place or same_place(each.identity, known)), None)

    def overdue(self) -> list[Working]:
        """Work its waiter left (stopped: the listeners opened anew) that is still under way past its bound: each cut off now, as
        its waiter would have said, and given back this once, for whoever looks to say so (the clock of whichever listeners
        there are). Never before its bound: a waiter stopped is no bound come. Its place is held until its thread ends."""
        now = time.monotonic()
        with self._lock:
            found = [each for each in self._working if each.left and not each.cut_off and not each.told and now >= each.deadline]
            for each in found:
                each.cut_off = True
            return found

    async def run(
        self, within: float, work: Callable[..., T], *given: Any, late: Callable[[T | None, BaseException | None], None] | None = None, folder: str = "",
        for_run: Run | None = None,
    ) -> T:  # fmt: skip
        """`work(*given)` on a thread of these, waited for `within` seconds. `late(result, failure)`: told, in that thread, how
        it ended where it ended after its waiter was told it took too long (a run cut off by its bound that its folder let go
        of later: what it made is to be kept and said), or was stopped. `folder`: the folder it works on, which no other work
        of these is begun into while it goes on (where `same_folder` says so). `for_run`: what a backup run is made for, kept
        with it (Working). FolderTimeout at the bound; FolderHeld ("busy") where the folder is held, by its name at once, or,
        by another name for it, as its thread finds out what it is; BackupError "busy" where every place is held, or no thread
        can be started."""
        place = place_of(folder)
        with self._lock:
            if self.same_folder and (holder := self._holding(place)) is not None:
                raise FolderHeld(self.same_folder, holder)
            if len(self._working) >= self.most:
                raise BackupError("busy", self.busy)
            mine = Working(folder, time.time(), deadline=time.monotonic() + within, within=within, for_run=for_run)
            self._working.append(mine)
        done: concurrent.futures.Future[T] = concurrent.futures.Future()
        done.set_running_or_notify_cancel()  # (running: never cancelled from outside, so its place is given up only as the thread ends)

        def held_by_another() -> Working | None:
            """(Its thread, before the work.) What the folder is on the disk, kept with this work, and the other work that holds
            it already, if any (this one's place then given back at once). The folder made first where it is not there (as a
            backup's is made, ready_folder): known by itself, never by the folder above it, which another name for it, made
            later, would not be (the fresh review of the fixes, N1). A folder that cannot be made or looked at is known by its
            name alone: no work can write into it either, and the work says why."""
            try:
                ready_folder(Path(folder))
                identity: Any = folder_identity(Path(folder))
            except (OSError, BackupError):
                identity = ("name", place)
            with self._lock:
                self._known.pop(place, None)
                self._known[place] = identity
                while len(self._known) > 64:
                    self._known.pop(next(iter(self._known)))
                holder = next((each for each in self._working if each is not mine and same_place(each.identity, identity)), None)
                if holder is None:
                    mine.identity = identity
                else:
                    self._working.remove(mine)
                    mine.told = True  # (nothing of it to tell: it never began)
                return holder

        def thread() -> None:
            result: T | None = None
            failure: BaseException | None = None
            if self.same_folder and place and (holder := held_by_another()) is not None:
                done.set_exception(FolderHeld(self.same_folder, holder))
                return
            try:
                result = work(*given)
            except BaseException as ex:  # (handed to whoever waits, where anybody still does)
                failure = ex
            if failure is None:
                done.set_result(result)  # type: ignore[arg-type]
            else:
                done.set_exception(failure)
            with self._lock:
                ended_late = mine.left and not mine.told
                mine.told = mine.told or ended_late
            # Told before its place is given back: given back first, another run could begin into the folder, and this late end
            # then be kept over what that one made (the last look of wave 3, 4).
            if ended_late and late is not None:
                try:
                    late(result, failure)
                except Exception:  # (telling it must not end the thread with a traceback for nobody)
                    pass
            with self._lock:
                self._working.remove(mine)

        try:
            threading.Thread(target=thread, name="backup-folder", daemon=True).start()
        except RuntimeError:  # (no thread to be had just now: its place is not held, and it is said as busy)
            with self._lock:
                self._working.remove(mine)
            raise BackupError("busy", "No thread could be started for the folder just now: try again in a moment") from None
        bound = asyncio.timeout(within)
        try:
            async with bound:
                return await asyncio.wrap_future(done)
        except asyncio.CancelledError:
            # Its waiter is stopped (the listeners opened anew, the wall stopping): its end is told to `late` all the same, by the
            # thread where it is still at work, or here where it ended just now and nobody was told. Its bound stays with it
            # (`deadline`): whoever looks once that has come says it is cut off (overdue), as its waiter would have.
            with self._lock:
                mine.left = True
                ended = done.done() and not mine.told
                mine.told = mine.told or ended
            if ended and late is not None:
                failure = done.exception()
                late(None if failure is not None else done.result(), failure)
            raise
        except TimeoutError:
            if not bound.expired():
                raise  # (the work's own: a folder that answered ETIMEDOUT)
            with self._lock:
                if done.done() and not done.cancelled():  # (it ended just as its time did: as ended in time)
                    return done.result()
                mine.cut_off = mine.left = True
            raise FolderTimeout(f"the folder did not answer within {within:g} s") from None


class BackupError(Exception):
    """A backup cannot be made or read. `code` is for the page, `message` for a person."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


class FolderHeld(BackupError):
    """("busy") Work into a folder that other work of FolderThreads holds, by its name or by another name for the same folder:
    none is begun beside it. `holder`: that work (cut off and waiting for the folder, or under way)."""

    def __init__(self, message: str, holder: Working) -> None:
        super().__init__("busy", message)
        self.holder = holder


# --- the key ---------------------------------------------------------------------------------------------------------


def new_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def key_id(key: bytes) -> str:
    """What a backup key is known by, in a backup's head, on its kit and on the page: a mark of it that gives nothing of the
    key away (HMAC-SHA256 of a fixed text, 64 bits of it)."""
    return hmac.new(key, _ID, hashlib.sha256).hexdigest()[:16]


def written(key: bytes) -> str:
    """The key as its kit shows it: in base32 (no 0, 1 or 8 to be misread), with three bytes of a check after it so that a
    slip of the hand is said as such, in fourteen groups of four."""
    check = hashlib.sha256(_CHECK + key).digest()[:3]
    text = base64.b32encode(key + check).decode("ascii")  # (35 bytes: 56 characters, no padding)
    return "-".join(text[at : at + 4] for at in range(0, len(text), 4))


def key_of(text: str) -> bytes:
    """The key from the way its kit writes it, however it was typed: any case, with or without its dashes or spaces, a 0, 1
    or 8 for the O, I or B the alphabet has instead. ValueError where it is none, or one with a slip in it."""
    tidy = "".join(ch for ch in text.upper().translate(str.maketrans("018", "OIB")) if ch.isalnum())
    if not _ALPHABET.fullmatch(tidy):
        raise ValueError("this is not a backup key: it is 56 letters and digits, in fourteen groups of four")
    raw = base64.b32decode(tidy)
    key, check = raw[:KEY_BYTES], raw[KEY_BYTES:]
    if not hmac.compare_digest(hashlib.sha256(_CHECK + key).digest()[:3], check):
        raise ValueError("this is not the backup key as its kit writes it: a group is mistyped")
    return key


def key_in_kit(text: str) -> bytes:
    """The key, from the text of its kit as the page saves it (or anything else that has it in its fourteen groups); or the
    key alone, as typed. ValueError where none is in it."""
    for found in _IN_GROUPS.findall(text):
        try:
            return key_of(found)
        except ValueError:
            continue
    return key_of(text)


def kit(key: bytes, made: float) -> str:
    """The recovery kit: a page to print or save, the only thing that is needed to restore a backup on a new computer. Plain
    ASCII. Shown once, when the key is made; the wall keeps the key sealed and never shows it again."""
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(made))
    return (
        "qKVM backup recovery kit\n"
        "\n"
        "Backup key:\n"
        "\n"
        f"    {written(key)}\n"
        "\n"
        f"Known as {key_id(key)}, made {when}.\n"
        "\n"
        "What it opens\n"
        "\n"
        "  Every backup this qKVM makes with this key: its machines and their passwords, its accounts,\n"
        "  its alert settings, its activity log and, where they are included, its history. Whoever has this\n"
        "  key and a backup file has all of that. Keep it as you keep a password: printed and put away, or\n"
        "  in a password manager. Not on the computer qKVM runs on, and not in the folder of the backups.\n"
        "\n"
        "  A backup made with an earlier key opens with that key's kit only. Made a new key? Keep the\n"
        "  earlier kit for as long as you keep the backups made with it.\n"
        "\n"
        "How to restore on a new computer\n"
        "\n"
        "  1. Install qKVM (pip install qkvm, or the Docker image qkvm/qkvm).\n"
        "  2. Save this kit as a text file there, or have the key at hand to type.\n"
        "  3. With an empty data folder, run:\n"
        "       python -m qkvm --restore BACKUP_FILE --backup-key KIT_FILE --data-dir NEW_FOLDER\n"
        "     (Without --backup-key it asks for the key.)\n"
        "  4. Start qKVM with that data folder and sign in with your password as before: the accounts,\n"
        "     their passwords and their second steps come back with the rest.\n"
        "  5. The restored qKVM has no backup key: make a new one in Settings > Backups, and keep its\n"
        "     kit, before you switch backups on there. This kit opens only the backups made with it.\n"
    )


# --- when ------------------------------------------------------------------------------------------------------------


def next_run(hour: int, after: float, *, clock: Callable[[float], time.struct_time] | None = None) -> float:
    """The next time the hour (0 to 23, local time) comes after `after`: on a day whose clock shows it twice (set back), the
    first; on one whose clock never shows it (set on), the first minute after it was skipped, that day. `clock`: what local
    time a moment is (time.localtime; another for a test)."""
    shown = clock or time.localtime
    hour = min(23, max(0, hour))
    day = shown(after)
    first = datetime.date(day.tm_year, day.tm_mon, day.tm_mday)
    for ahead in range(3):
        on = first + datetime.timedelta(days=ahead)
        at = first_at(on, hour, shown)
        if at > after:
            return at
    return after + 86400.0  # (not reached)


def first_at(day: datetime.date, hour: int, shown: Callable[[float], time.struct_time]) -> float:
    """The first moment the clock shows that day's hour, or a later moment of the day, or the day after: found by asking the
    clock (`shown`) of moments a quarter of an hour apart where every zone there is shows it (UTC-12 to UTC+14), and then of
    seconds. Never by mktime, which takes either of an hour shown twice, and goes either way from one never shown, by
    system (Windows ran at the second 01:00, and skipped the whole day for a 02:00 never shown: the outside review of
    0.4.0, bugs round)."""
    wanted = (day.year, day.month, day.day, hour, 0)

    def come(at: float) -> bool:
        local = shown(at)
        return (local.tm_year, local.tm_mon, local.tm_mday, local.tm_hour, local.tm_min) >= wanted

    as_utc = float(calendar.timegm((day.year, day.month, day.day, hour, 0, 0)))
    early, late = as_utc - 15 * 3600, as_utc + 13 * 3600  # (local time is UTC from 12 hours behind to 14 ahead)
    at = early
    while at <= late and not come(at):
        at += 900.0
    if at > late:
        return late  # (a clock that shows no such time: not reached)
    before = at - 900.0
    while at - before > 1.0:  # (zones are a quarter of an hour apart, and the first look is it; else to the second)
        middle = (before + at) // 2
        before, at = (before, middle) if come(middle) else (middle, at)
    return at


# --- writing ---------------------------------------------------------------------------------------------------------


def _file_key(key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_INFO).derive(key)


def _nonce(number: int, last: bool) -> bytes:
    return number.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


class _Sealed:
    """The content of a backup as it is written: compressed, then sealed in frames (see the module's text)."""

    def __init__(self, out: BinaryIO, key: bytes, head: bytes) -> None:
        salt = json.loads(head.split(b"\n")[1])["salt"]
        self._out = out
        self._aead = AESGCM(_file_key(key, base64.b64decode(salt)))
        self._bound = hashlib.sha256(head).digest()
        self._squeeze = zlib.compressobj(6)
        self._pending = bytearray()
        self._number = 0
        self._left = 0  # bytes the part being written still owes

    def part(self, name: str, size: int) -> None:
        if self._left:
            raise ValueError("the part before was not written whole")
        said = name.encode("ascii")
        self._put(len(said).to_bytes(2, "big") + said + size.to_bytes(8, "big"))
        self._left = size

    def write(self, data: bytes) -> None:
        if len(data) > self._left:
            raise ValueError("more written than the part said it holds")
        self._left -= len(data)
        self._put(data)

    def _put(self, data: bytes) -> None:
        self._pending += self._squeeze.compress(data)
        while len(self._pending) > CHUNK:
            self._frame(bytes(self._pending[:CHUNK]), last=False)
            del self._pending[:CHUNK]

    def close(self) -> None:
        if self._left:
            raise ValueError("the last part was not written whole")
        self._pending += self._squeeze.flush()
        while len(self._pending) > CHUNK:
            self._frame(bytes(self._pending[:CHUNK]), last=False)
            del self._pending[:CHUNK]
        self._frame(bytes(self._pending), last=True)
        self._pending.clear()

    def _frame(self, plain: bytes, last: bool) -> None:
        sealed = self._aead.encrypt(_nonce(self._number, last), plain, self._bound)
        self._out.write((len(sealed) | (LAST if last else 0)).to_bytes(4, "big") + sealed)
        self._number += 1


def _head(key: bytes, program: str, made: float) -> bytes:
    said = {"format": FORMAT, "version": VERSION, "program": program, "made": int(made), "key": key_id(key), "salt": base64.b64encode(os.urandom(32)).decode("ascii")}
    return MAGIC + json.dumps(said, separators=(",", ":")).encode("ascii") + b"\n"


def _copy(source: BinaryIO, size: int, into: _Sealed) -> None:
    """`size` bytes of an open file, from its beginning: all of them, or an error (a file that ends before is not taken
    for one that holds less)."""
    source.seek(0)
    left = size
    while left:
        data = source.read(min(BLOCK, left))
        if not data:
            raise OSError(5, "a file of the activity log ended before the length it had a moment ago")
        into.write(data)
        left -= len(data)


@contextlib.contextmanager
def log_files(audit: Any) -> Iterator[list[tuple[str, BinaryIO, int]]]:
    """The activity log's files as a backup takes them (store.AuditLog): all opened at once, so that the writer moving them on
    meanwhile neither has one read twice nor one left out (opened again where it did, as a check of the log opens them);
    the oldest first, each with how much of it goes in: the whole of an old one, and of the file being written what ends
    where a line ends (a line on its way is not cut in two: it is in the next backup). Shared with the writer (open_shared),
    whose files are moved on and removed while they are open here. BackupError where they kept being moved on."""
    from .store import open_shared

    opened: list[tuple[Path, BinaryIO]] = []
    try:
        for attempt in range(10):
            began = audit.rotations
            for path in audit.files():
                try:
                    opened.append((path, open_shared(path)))
                except FileNotFoundError:
                    continue
            if began % 2 == 0 and audit.rotations == began:
                break
            for _, file in opened:
                file.close()
            opened = []
            time.sleep(0.01 * (attempt + 1))
        else:
            raise BackupError("busy", "The activity log was being moved on all the while: try again in a moment")
        listed: list[tuple[str, BinaryIO, int]] = []
        for path, file in reversed(opened):
            end = file.seek(0, os.SEEK_END)
            if path == audit.path:
                end = _after_last_line(file, end)
            listed.append((path.name, file, end))
        yield listed
    finally:
        for _, file in opened:
            file.close()


def _after_last_line(file: BinaryIO, end: int) -> int:
    """Where the file's last whole line ends (just past its line feed); 0 where it has none."""
    at = end
    while at > 0:
        start = max(0, at - BLOCK)
        file.seek(start)
        found = file.read(at - start).rfind(b"\n")
        if found >= 0:
            return start + found + 1
        at = start
    return 0


@dataclass
class Made:
    """A backup that was made: its file's name, its size, and the backups that went to make room."""

    name: str
    size: int
    made: float
    held: Held
    pruned: list[str] = field(default_factory=list)
    folder: str = ""  # the folder it was made in, as it was given: a late end is the latest only of that folder


def _place(name: str) -> tuple[str, int] | None:
    """Where a backup's name puts it in time: (when, its number within that second); None for what is no backup's name."""
    named = NAME.fullmatch(name)
    return (named.group(2), int(named.group(3) or 0)) if named else None


def _backups(folder: Path) -> list[tuple[str, tuple[str, int], Path]]:
    """Every backup in the folder by its name (the key's id, its place in time, its path); only files, never a link."""
    try:
        entries = list(os.scandir(folder))
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        named = NAME.fullmatch(entry.name)
        if named and entry.is_file(follow_symlinks=False):
            found.append((named.group(1), (named.group(2), int(named.group(3) or 0)), Path(entry.path)))
    return found


def spelled_inside(folder: str, data_dir: Path) -> bool:
    """Whether `folder` is the data folder or in it by how both are written, asking the disk nothing (a share that does not
    answer cannot hold this up). Where it lies by links and other names is asked apart (unlock.lies_in)."""
    spelled, data = os.path.normcase(os.path.abspath(folder)), os.path.normcase(os.path.abspath(data_dir))
    return spelled == data or spelled.startswith(data.rstrip(os.sep) + os.sep)


def listed(folder: Path, key: str | None = None) -> list[Path]:
    """The backups in the folder made with the key known as `key` (key_id), or with any key where it is None: by their names
    alone, the newest first."""
    return [path for _, _, path in sorted((place, mark, path) for mark, place, path in _backups(folder) if key is None or mark == key)[::-1]]


def made_with(name: str, key: str) -> bool:
    """Whether a backup's name says it was made with the key known as `key`."""
    named = NAME.fullmatch(name)
    return named is not None and named.group(1) == key


def latest(folder: Path, key: str | None = None) -> Path | None:
    found = listed(folder, key)
    return found[0] if found else None


def others(folder: Path, key: str) -> int:
    """How many backups in the folder were made with another key than `key`: another wall's, or this wall's before its key
    was made new. They are never touched here; Settings says they are there."""
    return sum(1 for mark, _, _ in _backups(folder) if mark != key)


def _settle(folder: Path) -> None:
    """The folder itself on the disk (a name just given in it survives a power cut), where the system offers that."""
    if sys.platform == "win32":
        return
    try:
        descriptor = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def without_key(settings: dict[str, Any]) -> dict[str, Any]:
    """The settings as a backup holds them: without a backup key (store.BackupSettings.secret, its id and when it was made),
    this one or any. A kit opens the backups made with it, and nothing in them leads to another key: a backup that held the
    key sealed (beside the data key that opens it) gave a new key away to whoever had the kit before, and every backup made
    with it after (the outside review of 0.4.0, H1). A restored wall has none, and its admin makes it one (restore)."""
    backups = settings.get("backups")
    if not isinstance(backups, dict):
        return settings
    return {**settings, "backups": {**backups, "secret": None, "key_id": "", "key_made": 0.0}}


def make(
    folder: Path,
    key: bytes,
    *,
    settings: dict[str, Any],
    data_key: bytes,
    logs: list[tuple[str, BinaryIO, int]],
    history: Path | None,
    program: str,
    keep: int,
) -> Made:
    """Write a backup into `folder` (made where it is not there, the wall's alone), read it back whole, give it its name, and
    then let the oldest beyond `keep` go. Waits for the disk: for a worker thread.

    `settings`: as the wall keeps them (store.snapshot), which go in without their backup key (without_key); `data_key`: the
    vault's key, which every secret in them is sealed with; `logs`: the activity log's files, the oldest first, each opened,
    with the length of it that goes in; `history`: a copy of the history made for this (History.copy_to), or None.
    BackupError or OSError where nothing was made (and then nothing that was there before is touched). First it takes away
    the files in the making of this key's that a run cut off left, but never one of a run of this program's that has not
    ended (_MAKING), by whatever name its folder was given."""
    if len(key) != KEY_BYTES or len(data_key) != 32:
        raise BackupError("no_key", "The backup key is not one this program makes")
    ready_folder(folder)
    mine = key_id(key)
    made = time.time()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(made))
    with _MAKING_LOCK:
        partial = _making_name(folder, mine, stamp)
        _MAKING.add(partial.name)
    try:
        return _make(folder, key, mine, made, stamp, partial, settings=settings, data_key=data_key, logs=logs, history=history, program=program, keep=keep)
    finally:
        with _MAKING_LOCK:
            _MAKING.discard(partial.name)


# The names of the files in the making of this program's runs that have not ended (make): unique among them, and never taken
# away by another run's start, which takes away what a run cut off left. Two runs into one folder by two names for it, or into
# two folders that cannot be told apart, the second's start took the first's away, and that backup was lost (the final look at
# 0.4.0, M2). By the file's name, which no other run of this program's has: so whatever the folder is called.
_MAKING: set[str] = set()
_MAKING_LOCK = threading.Lock()


def _making_name(folder: Path, mine: str, stamp: str) -> Path:
    """(Under _MAKING_LOCK.) The name of a run's file in the making: of its key and second, numbered where a run of this
    program's that goes on makes one of that name."""
    for number in range(1000):
        name = f".qkvm-backup-{mine}-{stamp}{f'-{number}' if number else ''}.partial"
        if name not in _MAKING:
            return folder / name
    raise FileExistsError(17, "a thousand backups are in the making in this very second", str(folder))


def _make(
    folder: Path, key: bytes, mine: str, made: float, stamp: str, partial: Path, *, settings: dict[str, Any], data_key: bytes,
    logs: list[tuple[str, BinaryIO, int]], history: Path | None, program: str, keep: int,
) -> Made:  # fmt: skip
    """(make, with the name of its file in the making held as this run's.)"""
    for entry in os.scandir(folder):  # (what a run of this key's that was cut off left: no backup, and taken away)
        cut_off = PARTIAL.fullmatch(entry.name)
        if cut_off and cut_off.group(1) == mine and entry.is_file(follow_symlinks=False):
            with _MAKING_LOCK:
                going_on = entry.name in _MAKING  # (a run of this program's that has not ended, or this one's own: never)
            if not going_on:
                with contextlib.suppress(OSError):
                    os.unlink(entry.path)
    head = _head(key, program, made)
    manifest = json.dumps({"settings": without_key(settings), "data_key": data_key.hex()}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(manifest) > MOST_SETTINGS:
        raise BackupError("too_large", "The settings are larger than a backup holds")
    mine_there = False  # (whether the file of that name is this run's: one it could not make, another's, is never taken away)
    try:
        with private(partial, "xb") as out:
            mine_there = True
            out.write(head)
            sealed = _Sealed(out, key, head)
            sealed.part(SETTINGS, len(manifest))
            sealed.write(manifest)
            for name, file, size in logs:
                if name not in LOGS:
                    raise ValueError(f"not a file of the activity log: {name}")
                sealed.part(name, size)
                _copy(file, size, sealed)
            if history is not None:
                size = history.stat().st_size
                sealed.part(HISTORY, size)
                with history.open("rb") as copied:
                    _copy(copied, size, sealed)
            sealed.part(END, 0)
            sealed.close()
            out.flush()
            os.fsync(out.fileno())
        held = verify(partial, key)  # (read back whole with the key before it is a backup at all)
        number, final = 0, folder / f"qkvm-backup-{mine}-{stamp}{SUFFIX}"
        while final.exists() or final.is_symlink():
            number += 1
            if number > 999:
                raise FileExistsError(17, "the folder has a thousand backups of this very second", str(final))
            final = folder / f"qkvm-backup-{mine}-{stamp}-{number}{SUFFIX}"
        # (Not os.replace: on Windows a rename never goes over a file of that name. On POSIX it does: the name is the first
        # one free a moment ago, and only a file made under it since would be lost, as by a run of this key in this very
        # second into this folder by another way to it, which _MAKING does not see. The narrow look at 0.4.0.)
        os.rename(partial, final)
    except BaseException:
        if mine_there:
            with contextlib.suppress(OSError):
                os.unlink(partial)
        raise
    _settle(folder)
    size = final.stat().st_size
    # Of this key's backups, those older than the new one (by the time in their names) beyond those to keep, the new one
    # counted: never the new one, never one named later than it (made while the clock was ahead, or put there), and never
    # another key's (another wall's, or this wall's before its key was made new).
    pruned = []
    now = (stamp, number)
    older = [path for path in listed(folder, mine) if (_place(path.name) or now) < now]
    for old in older[max(0, keep - 1) :]:
        try:
            os.unlink(old)
            pruned.append(old.name)
        except OSError:
            continue  # (tried again at the next run)
    return Made(final.name, size, made, held, pruned, folder=str(folder))


# --- reading ---------------------------------------------------------------------------------------------------------


@dataclass
class Held:
    """What a backup holds, as read whole: what the page and the restore say of it."""

    made: float
    program: str
    key: str
    size: int
    devices: int = 0
    accounts: int = 0
    admins: int = 0
    tokens: int = 0
    actions: int = 0
    destinations: int = 0
    secrets: int = 0  # saved secrets in its settings (passwords, texts, keys)...
    not_opening: int = 0  # ...and those of them that do not open with its data key (damaged, or from before a reset)
    signin: bool = False  # an identity provider is set up
    logs: list[tuple[str, int]] = field(default_factory=list)  # the activity log's files: name, bytes
    history: int | None = None  # bytes of the history, or None where it is not in it

    def said(self) -> dict[str, Any]:
        return {
            "made": self.made, "program": self.program, "key_id": self.key, "size": self.size, "devices": self.devices, "accounts": self.accounts,
            "admins": self.admins, "tokens": self.tokens, "actions": self.actions, "destinations": self.destinations, "secrets": self.secrets,
            "not_opening": self.not_opening, "signin": self.signin, "activity_bytes": sum(size for _, size in self.logs),
            "activity_files": len(self.logs), "history": self.history,
        }  # fmt: skip


def _damaged(why: str) -> BackupError:
    return BackupError("damaged", f"The backup is damaged, or was changed: {why}. Nothing of it was used.")


def _newer(program: str) -> tuple[int, ...] | None:
    from .update import parse_version

    try:
        return parse_version(program)
    except ValueError:
        return None


class _Opened:
    """A backup being read: its head checked, then its content as it opens, frame by frame (`blocks`)."""

    def __init__(self, file: BinaryIO, key: bytes) -> None:
        from ._version import __version__

        start = file.read(len(MAGIC))
        if start != MAGIC:
            raise BackupError("not_a_backup", "This is not a backup of qKVM's")
        line = file.readline(MOST_HEAD + 1)
        try:
            said = json.loads(line) if line.endswith(b"\n") else None
        except (ValueError, RecursionError):
            said = None
        if not isinstance(said, dict) or said.get("format") != FORMAT:
            raise BackupError("not_a_backup", "This is not a backup of qKVM's")
        version, program, made, mark = said.get("version"), said.get("program"), said.get("made"), said.get("key")
        if not (isinstance(version, int) and not isinstance(version, bool) and version >= 1 and isinstance(program, str) and isinstance(mark, str)):
            raise _damaged("its head is not as qKVM writes one")
        if version > VERSION:
            raise BackupError("newer", f"This backup was made by a later version of qKVM ({program[:20]}) in a form this version cannot read. Restore it with that version or a later one.")
        mine, theirs = _newer(__version__), _newer(program)
        if mine is not None and theirs is not None and theirs > mine:
            raise BackupError("newer", f"This backup was made by qKVM {program[:20]}, a later version than this one ({__version__}). Restore it with {program[:20]} or a later one.")
        if not hmac.compare_digest(mark, key_id(key)):
            raise BackupError("wrong_key", f"This backup was made with another backup key (known as {mark[:16]}), not this one ({key_id(key)}). Use the kit of the key it names.")
        try:
            salt = base64.b64decode(str(said.get("salt")), validate=True)
        except ValueError:
            salt = b""
        if len(salt) != 32:
            raise _damaged("its head is not as qKVM writes one")
        self.made = float(made) if isinstance(made, (int, float)) and not isinstance(made, bool) else 0.0
        self.program, self.mark = program[:20], mark
        self._file = file
        self._aead = AESGCM(_file_key(key, salt))
        self._bound = hashlib.sha256(start + line).digest()

    def _frames(self) -> Iterator[bytes]:
        number = 0
        while True:
            said = self._file.read(4)
            if len(said) < 4:
                raise _damaged("it ends before its last part (cut short)")
            word = int.from_bytes(said, "big")
            last, length = bool(word & LAST), word & ~LAST
            if not TAG <= length <= CHUNK + TAG:
                raise _damaged("a part of it is not as qKVM writes one")
            sealed = self._file.read(length)
            if len(sealed) < length:
                raise _damaged("it ends before its last part (cut short)")
            try:
                yield self._aead.decrypt(_nonce(number, last), sealed, self._bound)
            except InvalidTag:
                raise _damaged("part of it does not open with its key") from None
            number += 1
            if last:
                if self._file.read(1):
                    raise _damaged("there is more after its end")
                return

    def blocks(self) -> Iterator[bytes]:
        """The content, decompressed, as it opens: a mebibyte at a time at the most, whatever it says."""
        opened = zlib.decompressobj()
        try:
            for frame in self._frames():
                data = frame
                while data:
                    out = opened.decompress(data, BLOCK)
                    if out:
                        yield out
                    data = opened.unconsumed_tail
            out = opened.flush()
            if out:
                yield out
        except zlib.error:
            raise _damaged("what is in it is not as qKVM writes it") from None
        if not opened.eof or opened.unused_data:
            raise _damaged("what is in it is not as qKVM writes it")


class _Plain:
    """The content as one stream to be read from: exactly so many bytes at a time, or the backup is damaged."""

    def __init__(self, blocks: Iterator[bytes]) -> None:
        self._blocks = blocks
        self._buffer = b""

    def read(self, most: int) -> bytes:
        """Up to `most` bytes (at least one); b"" where the content ends."""
        if not self._buffer:
            self._buffer = next(self._blocks, b"")
        data, self._buffer = self._buffer[:most], self._buffer[most:]
        return data

    def exactly(self, count: int) -> bytes:
        got = b""
        while len(got) < count:
            data = self.read(count - len(got))
            if not data:
                raise _damaged("what is in it ends in the middle of a part")
            got += data
        return got

    def ended(self) -> bool:
        return not self.read(1)


def read(path: Path, key: bytes, begin: Callable[[str], Any], take: Callable[[str, bytes], Any]) -> tuple[dict[str, Any], bytes, tuple[float, str]]:
    """Read a backup whole: its settings and data key, and when it was made and by which version (from the head this very
    reading checked every frame against: never from a look at the head apart from it, which could be another file's by
    then), given back; and every other part, handed over as it opens (`begin(name)`
    before each, `take(name, data)` for each piece of it). BackupError where it is not one, cannot be opened with this key,
    is of a later version, or is damaged in any way: what was handed over is then not to be used (the restore takes back
    what it wrote), since a change is found where it lies, which may be at the end. OSError where it cannot be read."""
    with path.open("rb") as file:
        opened = _Opened(file, key)
        plain = _Plain(opened.blocks())
        seen: set[str] = set()
        settings: dict[str, Any] | None = None
        data_key = b""
        while True:
            length = int.from_bytes(plain.exactly(2), "big")
            try:
                name = plain.exactly(length).decode("ascii")
            except UnicodeError:
                raise _damaged("a part of it has no name qKVM gives") from None
            size = int.from_bytes(plain.exactly(8), "big")
            if name not in PARTS or name in seen or (settings is None) != (name == SETTINGS):
                raise _damaged("a part of it is not one qKVM writes, or not where it writes it")
            seen.add(name)
            if size > (MOST_SETTINGS if name == SETTINGS else MOST_PART) or (name == END and size):
                raise _damaged("a part of it is larger than qKVM writes")
            if name == END:
                if not plain.ended():
                    raise _damaged("there is more after its end")
                break
            if name == SETTINGS:
                try:
                    said = json.loads(plain.exactly(size))
                    data_key = bytes.fromhex(said["data_key"])
                    settings = said["settings"]
                except (ValueError, KeyError, TypeError, RecursionError):
                    raise _damaged("its settings are not as qKVM writes them") from None
                if not isinstance(settings, dict) or len(data_key) != 32:
                    raise _damaged("its settings are not as qKVM writes them")
                continue
            begin(name)
            left = size
            while left:
                data = plain.read(min(BLOCK, left))
                if not data:
                    raise _damaged("what is in it ends in the middle of a part")
                take(name, data)
                left -= len(data)
    assert settings is not None
    return settings, data_key, (opened.made, opened.program)


def head_of(path: Path, key: bytes) -> tuple[float, str]:
    """When a backup was made and by which version, from its head alone, unchecked (BackupError as `read` says): for refusing
    what cannot be read before anything is done. What is said of a backup comes from `read`, which checks it."""
    with path.open("rb") as file:
        opened = _Opened(file, key)
        return opened.made, opened.program


def verify(path: Path, key: bytes) -> Held:
    """Read a backup whole with its key, without restoring anything, and say what it holds. Waits for the disk: for a worker
    thread. BackupError as `read` says."""
    sizes: dict[str, int] = {}
    settings, data_key, (made, program) = read(path, key, lambda name: sizes.setdefault(name, 0), lambda name, data: sizes.__setitem__(name, sizes[name] + len(data)))
    return _held(settings, data_key, made, program, key, path.stat().st_size, sizes)


def _settings_of(settings: dict[str, Any], where: Path) -> Any:
    """The settings of a backup as a wall would read them (store.Store.of_document): damaged where they would not load."""
    from .store import Store

    try:
        return Store.of_document(settings, where)
    except (ValueError, TypeError, AttributeError, RecursionError, OverflowError) as ex:
        raise _damaged(f"its settings would not load ({str(ex)[:200]})") from None


def _held(settings: dict[str, Any], data_key: bytes, made: float, program: str, key: bytes, size: int, sizes: dict[str, int]) -> Held:
    """What a backup read whole holds: its settings counted, and every secret in them tried with the data key it carries."""
    from .vault import Vault

    store = _settings_of(settings, Path("qkvm.json"))
    vault = Vault()
    vault.adopt(data_key)
    sealed = sealed_secrets(store)
    opening = sum(1 for blob, context in sealed if vault.read(blob, context) is not None)
    return Held(
        made=made, program=program, key=key_id(key), size=size, devices=len(store.devices), accounts=len(store.users),
        admins=sum(1 for user in store.users if user.role == "admin"), tokens=len(store.tokens), actions=len(store.actions),
        destinations=len(store.destinations), secrets=len(sealed), not_opening=len(sealed) - opening, signin=bool(store.oidc.issuer),
        logs=[(name, sizes[name]) for name in reversed(LOGS) if name in sizes], history=sizes.get(HISTORY),
    )  # fmt: skip


# --- restoring -------------------------------------------------------------------------------------------------------


@dataclass
class Restored:
    """A wall restored from a backup: what it holds, how its activity log checks (None where it has no chain to check, with
    why in `unchecked`), the storage key it was sealed with, and the folder its backups went to."""

    held: Held
    verdict: Any
    unchecked: str
    key_file: Path
    folder: str
    # What a restore into the same folder that was stopped before it finished had left there, and this one took away first
    # (names of _RESTORED); empty where there was none.
    cleared: list[str] = field(default_factory=list)


# What a restore may write into the data folder (and takes away again where it does not end well): the parts of a backup,
# the settings and their second copy, and what a write of them leaves for a moment.
_RESTORED = (*LOGS, HISTORY, "qkvm.json", "qkvm.bak", "qkvm.tmp", "qkvm.bak.new")
# A restore's hold on the folder it restores into (the outside review of 0.4.0, M1 and L1): this file, made in it before
# anything there is looked at, and locked for as long as the restore runs. Another restore into the folder, in this process
# or another, finds it held and is refused before it touches anything ("busy"); the lock goes with the process however it
# ends, so that a file of this name nobody holds is a restore that was stopped before it finished, which a restore into the
# folder takes over: it takes away what that one wrote (names of _RESTORED, nothing else) and begins again.
RESTORING = "qkvm.restoring"
HOLD_PATIENCE = 2.0  # seconds a hold found on a folder is asked for again: a process stopped a moment ago may still have it


def left_by_a_restore(data_dir: Path) -> bool:
    """Whether a folder holds only what a restore into it that was stopped before it finished left there (its RESTORING and
    names of _RESTORED): one a restore may go into, as into an empty one. (Whether that restore is still under way is found
    out by the restore itself, which is refused while it is.)"""
    try:
        names = {entry.name for entry in os.scandir(data_dir)}
    except OSError:
        return False
    return RESTORING in names and names <= {RESTORING, *_RESTORED} and "qkvm.json" not in names and not _said_done(data_dir / RESTORING)


def unfinished_restore(data_dir: Path) -> bool:
    """Whether a restore into this folder has not finished: under way, or stopped (its hold's file there, not saying it ended
    well, and no settings yet, which a restore writes last, nor their second copy, which a start would read in their
    place). A start refuses such a folder (cli.main): set up anew beside what the restore had written, it was a wall whose
    activity log checked broken, and the same --restore could not finish."""
    try:
        settings = (data_dir / "qkvm.json").exists() or (data_dir / "qkvm.bak").exists()
        return (data_dir / RESTORING).is_file() and not settings and not _said_done(data_dir / RESTORING)
    except OSError:
        return False


DONE = b"done\n"  # what a restore that ended well writes in its hold's file before it takes it away (_Hold.done)


def _said_done(path: Path) -> bool:
    """Whether a hold's file says that its restore ended well: one whose file could not be taken away after (the re-check of
    the outside review's fixes, N7). Unreadable (held by a restore under way): not said."""
    try:
        with open(path, "rb") as fh:
            return fh.read(len(DONE)) == DONE
    except OSError:
        return False


class _Hold:
    """A restore's hold on its data folder (RESTORING): taken, or BackupError "busy" where another restore has it."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / RESTORING
        self.found = False  # the file was there, and nobody held it: a restore stopped before it finished, now this one's
        try:
            self._file = private(self.path, "xb+")
        except FileExistsError:
            self.found = True
            try:
                self._file = private(self.path, "rb+")  # (never made here: one taken away meanwhile is no stopped restore's)
            except (FileNotFoundError, PermissionError):
                raise self._busy() from None
        except PermissionError:
            if sys.platform != "win32" or not self.path.parent.is_dir():
                raise
            raise self._busy() from None  # (on Windows, the file of a restore that is ending: taken away, and not gone yet)
        until = time.monotonic() + (HOLD_PATIENCE if self.found else 0.0)
        while not self._locked():
            if time.monotonic() >= until:
                self._file.close()
                raise self._busy()
            time.sleep(0.05)
        # Held, and still the folder's: one taken away (and perhaps made anew) after it was opened here is not this hold.
        try:
            same = os.path.samestat(os.fstat(self._file.fileno()), os.stat(self.path))
        except OSError:
            same = False
        if not same:
            self._file.close()
            raise self._busy()
        self.ended_well = False  # (found saying its restore ended well: a finished wall's, never taken over)
        if self.found:
            self._file.seek(0)
            self.ended_well = self._file.read(len(DONE)) == DONE

    def done(self) -> None:
        """Say in the hold's file that its restore ended well, while it is held: should the file not go after, the next restore
        into the folder finds a finished wall there, not a stopped restore's leavings (N7)."""
        with contextlib.suppress(OSError):
            self._file.seek(0)
            self._file.truncate()
            self._file.write(DONE)
            self._file.flush()
            os.fsync(self._file.fileno())

    def _locked(self) -> bool:
        try:
            if sys.platform == "win32":
                import msvcrt

                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _busy(self) -> BackupError:
        return BackupError("busy", f"Another restore into {self.path.parent} is under way: wait for it to end, or name another folder")

    def release(self, take_away: bool) -> None:
        """Let go of the folder; `take_away`: its file goes first, while it is still held (a hold that let go of it first, a
        moment, had another restore take what is there for a stopped one's)."""
        try:
            if take_away:
                with contextlib.suppress(OSError):
                    self.path.unlink()
        finally:
            self._file.close()


def restore(path: Path, key: bytes, data_dir: Path, vault_key_file: Path | None = None) -> Restored:
    """Bring a wall back from a backup into `data_dir`, which is not there or empty; its settings sealed with a storage key of
    the new folder's own (made beside it, or the one `vault_key_file` names), never with anything of the old computer's.

    As it was, but for what makes the restored wall less and never more: it carries on by itself only once somebody has
    signed in (the record that opened its saved passwords at a start, `unlock`, is not taken: its key is the old computer's);
    its backups are off until an admin switches them on (two walls must not both write, and prune, one folder); and it has
    no backup key (a backup holds none: without_key), so that its admin makes a new one, whose kit opens what it makes from
    then on, the kit used opening the backups made before. The activity log gets a line of its own that says it was
    restored, chained on from the backup's seal, and is checked as `python -m qkvm.checklog --data-dir` checks it.

    Refused before anything is written, with a sentence (BackupError): a folder with anything in it ("not_empty"), another
    key, a later version, what is no backup, another restore into the folder under way ("busy"). Refused after (a change
    found where it lies, which may be at its end; settings that would not load): what it wrote is taken away again, the
    folder too where it made it; the storage key is left as it is, whoever made it (another restore may have taken it up
    meanwhile), and the next restore into the folder uses it.

    The folder is held for the restore (RESTORING) before anything in it is looked at, in this process and any other, until
    it ends: two restores into one empty folder were both let in, and the one that failed took away the settings, the log
    and the storage key of the one that had ended well (the outside review of 0.4.0, M1). So what it takes away again is
    only ever its own: what is in the folder after the look, which nothing else wrote, and never a storage key. A
    restore stopped before it finished (the computer went down, the process was killed) is taken over by the next restore
    into the folder, which takes away what that one wrote and begins again (`cleared`): it was refused "not empty" (L1).
    Anything else in the folder beside it is refused as ever, and left as it is."""
    from . import checklog
    from .store import AuditLog, Store, position_of
    from .vault_storage import key_path, make_key

    def refused_not_empty() -> BackupError:
        return BackupError("not_empty", f"{data_dir} is not empty: a backup is restored into an empty data folder only")

    # (Asked once before anything is made, and again once the folder is held: what is said of a folder that is not empty is
    # said without a file of the restore's ever being put into it.)
    if data_dir.exists() and (not data_dir.is_dir() or (any(os.scandir(data_dir)) and not left_by_a_restore(data_dir))):
        raise refused_not_empty()
    head_of(path, key)  # (another key, a later version, no backup: refused before anything is made; what is said is read's)
    made_folder = not data_dir.exists()
    own_folder(data_dir)
    try:
        hold = _Hold(data_dir)
    except BaseException:
        if made_folder:
            with contextlib.suppress(OSError):
                data_dir.rmdir()  # (made here: empty again, or another restore's, which keeps it)
        raise
    opened: dict[str, BinaryIO] = {}
    sizes: dict[str, int] = {}
    selected: Path | None = None
    looked = False
    cleared: list[str] = []
    try:
        there = sorted(entry.name for entry in os.scandir(data_dir) if entry.name != RESTORING)
        # (A folder that holds its settings is never a stopped restore's leavings, whatever its hold's file says: a restore
        # writes them last, once all else is there; one whose hold could not say it ended well, nor go, was taken over and
        # lost its settings and its log. The re-check of the outside review's fixes, N7.)
        if there and (not hold.found or hold.ended_well or "qkvm.json" in there or not set(there) <= set(_RESTORED)):
            raise refused_not_empty()
        for name in there:  # (a stopped restore's, which this one holds now: its files, and nothing else, go)
            (data_dir / name).unlink()
            cleared.append(name)
        looked = True  # (from here, what is in the folder is this restore's)
        selected = key_path(data_dir, vault_key_file)  # (where it lies is judged by the folder, which is there now)

        def begin(name: str) -> None:
            opened[name] = private(data_dir / name, "xb")  # (a name of PARTS: read() takes no other)
            sizes[name] = 0

        def take(name: str, data: bytes) -> None:
            opened[name].write(data)
            sizes[name] += len(data)

        try:
            settings, data_key, (made, program) = read(path, key, begin, take)
            for file in opened.values():
                file.flush()
                os.fsync(file.fileno())
        finally:
            for file in opened.values():
                file.close()
        held = _held(settings, data_key, made, program, key, path.stat().st_size, sizes)
        document = without_key(dict(settings))  # (a backup holds no backup key: this restores none either, whatever it held)
        document["unlock"] = None
        backups = dict(document["backups"]) if isinstance(document.get("backups"), dict) else {}
        backups["enabled"] = False
        backups["told"] = []  # (the restored wall has told nobody of a failed backup: the wall before had)
        document["backups"] = backups
        settled = _settings_of(document, data_dir / "qkvm.json")
        # The line that says it was restored, and the log's check, before the settings: a folder with its settings in it is a
        # wall to the next restore, never a stopped one's leavings (N7), so a restore stopped between the two left a wall
        # without that line, which the same command then refused to finish (the outside review of 0.4.0, fifth round, M3).
        # Stopped before the settings, it is taken over by the next restore into the folder, which takes the log away first.
        verdict, unchecked = None, ""
        if settled.activity_key:
            activity_key, position = bytes.fromhex(settled.activity_key), position_of(settled.activity_position)
            log = AuditLog(data_dir / "audit.log", key=activity_key, held=lambda: position)
            log.write("wall_restored", "", file=path.name, made=round(made), program=program)
            log.close(within=30.0)
            files = [data_dir / name for name in reversed(LOGS) if (data_dir / name).exists()]
            try:
                verdict = checklog.check(files, activity_key, None, position)
            except checklog.CannotCheck as ex:
                unchecked = str(ex)
        else:
            unchecked = "the wall had no key for its activity log yet (it never ran 0.4.0)"
        # The folder's storage key, made here where there is none, and never taken away again: another restore into another
        # folder, named that file, may have taken it up meanwhile and ended well (the outside review 6.2 re-checks, R4 and M3). One a
        # restore that failed or was stopped made is used again by the next into the folder.
        make_key(selected)
        store = Store(data_dir / "qkvm.json", vault_key_file=vault_key_file, protected=True)
        store.write(document)  # (the settings last: from here on the folder is a wall)
        loaded = Store(data_dir / "qkvm.json", vault_key_file=vault_key_file, protected=True, read_only=True)  # (as a start reads it)
        restored = Restored(held, verdict, unchecked, loaded.key_file or selected, str(backups.get("folder") or ""), cleared)
    except BaseException:
        if looked:
            for name in _RESTORED:
                with contextlib.suppress(OSError):
                    (data_dir / name).unlink()
        # (The storage key is left where it is, whoever made it: see above.)
        # (Refused at the look, a stopped restore's file is left with what it left: the folder as it was found.)
        hold.release(take_away=looked or not hold.found)
        if made_folder:
            with contextlib.suppress(OSError):
                data_dir.rmdir()
        raise
    hold.done()  # (and should its file not go, it says so: N7)
    hold.release(take_away=True)  # (a whole wall now: its hold goes before it is let go of, and nobody takes it for a stopped one)
    return restored


def sealed_secrets(store: Any) -> list[tuple[Any, str]]:
    """Every secret the settings keep sealed with the data key, with what each is sealed for: a device's password, a saved
    text, a destination's secrets, an account's two-factor key, a browser's subscription, the provider's client secret, the
    wall's key for Web Push, the backup key (the wall's own: a backup's settings hold none, without_key)."""
    from . import oidc
    from .store import sealed_for

    found: list[tuple[Any, str]] = []
    found += [(device.secret, device.id) for device in store.devices if device.secret]
    found += [(action.secret, f"action:{action.id}") for action in store.actions if action.secret]
    found += [(one.secret, sealed_for(one.id)) for one in store.destinations if one.secret]
    found += [(user.totp, f"totp:{user.id}") for user in store.users if user.totp]
    found += [(push.secret, f"push:{push.id}") for push in store.pushes if push.secret]
    found += [(store.oidc.secret, oidc.SEALED_FOR)] if store.oidc.secret else []
    found += [(store.alerts.push_key, "alerts:push-key")] if store.alerts.push_key else []
    found += [(store.backups.secret, SEALED_FOR)] if store.backups.secret else []
    return found
