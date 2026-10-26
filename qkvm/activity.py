"""The activity log's index: its entries in SQLite as well, for the page's filters and its search, `audit.sqlite`.

The text files are the record (store.AuditLog: `audit.log` and the old files before it, JSON lines). They are written
first, as they always were, by a thread of their own; they are what is sent on to syslog, and what grep and tail read when
qKVM is down. Nothing here writes them, and nothing here is waited for by what writes them.

This is an index made from them and from nothing else. A thread of its own follows them as they are written (the text
log's thread tells it that there is more, and it looks by itself every second) and keeps what they hold: each entry as
its line, and beside it what it is looked for by (its time, its kind, the account, the machine, its words). It never
holds more than they do: the entries of a text file that is gone (the oldest, when the newest grew full) go from here as
well. A file of its own, and not a table beside the history: its size and its age are the text files', not the history's
days and megabytes, and anything of it can be thrown away and made again, which nothing of the history can. Where it is
damaged, missing, of another version, or does not match the text files (one put back by hand), it is removed and made
again from them: nothing is lost.

Nothing waits for it. A read waits a moment for it to have taken in what the text files hold at the time of asking, and
where it has not (it is being made, its disk refuses it, it is stuck), reads the text files themselves, as qKVM did
before there was an index: slower on a long log, and the same answer.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import itertools
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .store import LONGEST_LINE, AuditLog, entry_of, open_shared, read_only_uri

log = logging.getLogger("qkvm")

FILE = "audit.sqlite"
VERSION = 2  # of the tables and of what is taken from an entry; another one is made again from the text files
CHUNK = 1_000_000  # bytes of a text file taken in in one transaction, at the most
TAIL_KEPT = 4096  # bytes of a text file just before where it was read to, of which a hash is kept (see Index._take)
TICK = 1.0  # seconds between two looks at the text files where nobody said that there is more
CATCH_UP = 2.0  # seconds a read waits for the index to hold what the text files hold, before it reads them itself
READ_PATIENCE = 5.0  # seconds one read of the index may take before it is given up
WRITE_PATIENCE = 5.0  # seconds a write waits for the file (only a checkpoint of a reader's could hold it)
OPEN_PATIENCE = 60.0  # seconds the check of the file at its opening may take before it is taken as done
LOOK_AGAIN = 60.0  # seconds after which the old text files are looked at again, though the newest is the one it was
REFUSED = (5.0, 15.0, 60.0)  # seconds before the index is tried again after its disk refused it, the third and later every minute
GONE_AT_ONCE = 5000  # rows deleted in one transaction where a text file is gone
WAL_MOST = 16_000_000  # bytes the -wal file may take before what is in it is brought into the file and it begins again
CHECKPOINT_PATIENCE = 2 * READ_PATIENCE  # seconds that waits for the reads under way, longer than any of them may take
CHECKPOINT_AGAIN = 60.0  # seconds after one that did not get through before the next is tried
PAGE = 1000  # entries one page of a download reads at a time
PAGE_PATIENCE = 15.0  # seconds one page of a download may take where the text files are read (the index behind): under `qkvm stop`'s 25
SAY_EVERY = 60.0  # seconds between two lines in the log about the same trouble
UNREADABLE_SAID = 30  # rounds in a row a text file could not be opened before the log says so (a moment of it is a file being moved on)
MOST_WORDS, LONGEST_WORD = 20, 100  # words looked for at once, and characters of each

# What the entries are about, for whoever wants to see one kind of them. "change" is the rest, an event that is not
# known here included. (A file made of the wall, and one taken in, are changes: "export_made" and "import_done"; so is a
# download of this log, "activity_exported".) What each entry is of is kept in the index: a change to this table makes
# the index again (KINDS_MARK), so that it can never say the old kinds.
KINDS: dict[str, frozenset[str]] = {
    "signin": frozenset({"login", "login_failed", "login_code_asked", "logout", "setup", "password_recovered", "recovery_failed", "display_opened"}),
    "action": frozenset({"action", "action_failed", "console_opened", "console_failed", "live_control", "live_opened", "live_closed"}),
    "alert": frozenset({"alert", "alerts_paused", "alerts_resumed"}),
}
KIND_NAMES = ("signin", "action", "change", "alert")
KINDS_MARK = hashlib.sha256(json.dumps({kind: sorted(events) for kind, events in KINDS.items()}, sort_keys=True).encode()).hexdigest()[:16]
MADE = f"{VERSION}:{KINDS_MARK}"  # what the file says it was made as

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    # One row a text file taken in: the mark it is known by (its first line), how far it was read, a hash of the bytes just
    # before that (`_tail_of`), its entries' ids.
    "CREATE TABLE IF NOT EXISTS files (seq INTEGER PRIMARY KEY, mark TEXT NOT NULL UNIQUE, done INTEGER NOT NULL, "
    "tail TEXT NOT NULL DEFAULT '', first_id INTEGER, last_id INTEGER)",
    # One row an entry, its id in the order of the text files: `line` is the entry as written, the rest what it is found by.
    "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, t REAL NOT NULL, kind TEXT NOT NULL, who TEXT NOT NULL, "
    "device TEXT, device_id TEXT, said TEXT NOT NULL, line TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS entries_by_kind ON entries (kind, id)",
    "CREATE INDEX IF NOT EXISTS entries_by_who ON entries (who, id)",
    "CREATE INDEX IF NOT EXISTS entries_by_device_id ON entries (device_id, id) WHERE device_id IS NOT NULL",
    # (Entries from before 0.2.0 name a machine and do not give its id: those are found by the name it has now.)
    "CREATE INDEX IF NOT EXISTS entries_by_device ON entries (device, id) WHERE device_id IS NULL",
    "CREATE INDEX IF NOT EXISTS entries_by_time ON entries (t)",
)


class NotReadable(Exception):
    """A read of the activity log that cannot be answered: it took too long."""


class _Unusable(Exception):
    """An index this program does not use: damaged by its own check, of another version, or not of these text files."""


class _Moved(Exception):
    """What was to be taken in was taken in by another writer meanwhile: looked at again at the next round."""


class _Short(Exception):
    """The disk has less room than the text files are to keep for themselves: the index waits (see Index._room)."""


def _damaged(ex: BaseException) -> bool:
    """Whether an error says the index itself is damaged, is no database, or is not one this program uses as it is."""
    if isinstance(ex, _Unusable):
        return True
    code = getattr(ex, "sqlite_errorcode", None)
    return isinstance(ex, sqlite3.DatabaseError) and isinstance(code, int) and code & 0xFF in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)


def _clean(text: str) -> str:
    """A text as SQLite can keep it, and the same on both sides of a comparison: no half of a character (a lone surrogate,
    which a line of the file can name in its escapes, and which cannot be written as UTF-8), and no zero character, where
    some of SQLite's functions stop reading."""
    if text.isascii() and "\x00" not in text:
        return text
    return text.encode("utf-8", errors="replace").decode("utf-8").replace("\x00", " ")


def kind_of(event: str) -> str:
    return next((kind for kind, events in KINDS.items() if event in events), "change")


def _text_of(value: Any) -> str | None:
    return _clean(value) if isinstance(value, str) else None


class Facts:
    """What an entry is looked for by: kept beside it in the index, and made the same way where the text files are read
    (each when it is first asked for: a read of the text files that asks for a time only does not make the words).

    For an entry that entry_of took (a record whose event is a text and whose time is a moment)."""

    def __init__(self, entry: dict[str, Any]) -> None:
        self.entry = entry
        self.t = float(entry["time"])

    @staticmethod
    def of(entry: dict[str, Any]) -> Facts:
        return Facts(entry)

    @functools.cached_property
    def kind(self) -> str:
        return kind_of(self.entry["event"])

    @functools.cached_property
    def who(self) -> str:
        """The account that did it, as the entry names it ("user"), in one case; "" for qKVM itself."""
        return (_text_of(self.entry.get("user")) or "").casefold()

    @functools.cached_property
    def device(self) -> str | None:
        """The machine, as the entry names it."""
        return _text_of(self.entry.get("device"))

    @functools.cached_property
    def device_id(self) -> str | None:
        """...and its id, where the entry gives it (since 0.2.0)."""
        return _text_of(self.entry.get("device_id"))

    @functools.cached_property
    def said(self) -> str:
        """Every value of it, in one case: what words are looked for in."""
        return _clean(" ".join(str(value) for value in self.entry.values())).casefold()


@dataclass(frozen=True)
class Asked:
    """Which entries are asked for: all of these at once (and of the words, any one)."""

    words: tuple[str, ...] = ()  # in one case
    kind: str = ""  # one of KIND_NAMES, or "" for every kind
    before: float | None = None  # older than this moment: the next page of a long log
    since: float | None = None
    until: float | None = None
    who: str | None = None  # an account's name (or a token's, with " (token)"), in one case
    device_id: str | None = None  # a machine's id
    device_name: str | None = None  # ...and the name it has now: entries from before 0.2.0 give no id, and are found by it

    @staticmethod
    def of(
        texts: list[str] | None = None,
        kind: str = "",
        before: float | None = None,
        since: float | None = None,
        until: float | None = None,
        user: str | None = None,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> Asked:
        """From what a request asks. Several words, because what the page calls a thing is not what the log calls it ("Keep
        awake" is jiggler_on there): the page asks for what was typed and for what that is called in here."""
        words = tuple(_clean(text.strip()).casefold()[:LONGEST_WORD] for text in (texts or [])[:MOST_WORDS] if text.strip())
        return Asked(
            words=words,
            kind=kind,
            before=before,
            since=since,
            until=until,
            who=None if user is None else _clean(user).casefold(),
            device_id=None if device_id is None else _clean(device_id),
            device_name=None if device_name is None else _clean(device_name),
        )

    def wants(self, found: Facts) -> bool:
        """Whether an entry is one asked for: what `where` says to SQLite, said in Python for the text files."""
        if self.before is not None and not found.t < self.before:
            return False
        if self.since is not None and not found.t >= self.since:
            return False
        if self.until is not None and not found.t <= self.until:
            return False
        if self.kind and found.kind != self.kind:
            return False
        if self.who is not None and found.who != self.who:
            return False
        if self.device_id is not None and found.device_id != self.device_id:
            if not (found.device_id is None and self.device_name is not None and found.device == self.device_name):
                return False
        return not self.words or any(word in found.said for word in self.words)

    def where(self) -> tuple[str, list[Any]]:
        """The same as a WHERE clause of SQL, with its values."""
        terms: list[str] = []
        values: list[Any] = []
        for term, value in (("t < ?", self.before), ("t >= ?", self.since), ("t <= ?", self.until)):
            if value is not None:
                terms.append(term)
                values.append(value)
        if self.kind:
            terms.append("kind = ?")
            values.append(self.kind)
        if self.who is not None:
            terms.append("who = ?")
            values.append(self.who)
        if self.device_id is not None:
            if self.device_name is not None:
                terms.append("(device_id = ? OR (device_id IS NULL AND device = ?))")
                values += [self.device_id, self.device_name]
            else:
                terms.append("device_id = ?")
                values.append(self.device_id)
        if self.words:
            terms.append("(" + " OR ".join("instr(said, ?) > 0" for _ in self.words) + ")")
            values += self.words
        return (" WHERE " + " AND ".join(terms)) if terms else "", values


@dataclass
class Found:
    entries: list[dict[str, Any]]
    more: bool  # there are older ones that are asked for
    by: str  # "index", or "text" where the text files were read


def _mark(file: BinaryIO, newest: bool) -> str | None:
    """What a text file is known by: its first line, which holds the moment it was written to the millionth of a second.
    None where it has none yet (the newest, before its first line has ended)."""
    file.seek(0)
    head = file.read(LONGEST_LINE + 1)
    cut = head.find(b"\n")
    if cut >= 0:
        head = head[: cut + 1]
    elif len(head) > LONGEST_LINE:
        head = head[:LONGEST_LINE]  # (a first line longer than any entry: what of it is there is there for good)
    elif newest:
        return None
    return hashlib.sha256(head).hexdigest()[:32]


DOWNLOAD_NAMED = ("qkvm-download-", ".tmp")  # how a download of this log in the making is named in the data folder (server.audit_export)


def leftover_downloads(folder: Path) -> None:
    """Remove what downloads of the activity log in the making left in the data folder. Each is made to go when it is closed,
    or with the program; on Windows, a power cut leaves it there, part of the log in it, until somebody looks (the reviewer
    of FX-C). At a start, before any is made."""
    for path in folder.glob("*".join(DOWNLOAD_NAMED)):
        try:
            path.unlink()
        except OSError:
            pass  # (another time: nothing waits for it)


CONSOLE_SAID_AN_HOUR = 120  # a server's console opened (or not had): entries one account writes an hour, at the most (Allowance)
NAMED_AGAIN_AFTER = 3600.0  # seconds after which an entry about a machine is written again whatever an allowance says (Allowance)


class Allowance:
    """Entries of one kind that one account may write into the activity log: so many an hour, and an allowance of as many at
    once, as the entries of its live views (live.LIVE_SAID_AN_HOUR). Beyond it they are counted, and the next entry of that
    account says how many were left out (`unsaid`). (A script asking for a server's console in a loop wrote an entry a
    request, 251 a second against a controller that answers at once, and pushed out of the log what everybody had done
    before.) Where an entry names what it is about (`about`: a server whose console was opened), one about a machine that no
    entry of this kind and account has named for NAMED_AGAIN_AFTER is written all the same: the allowance spent on one
    server, the opening of another server's console was in no entry (the first reviewer of FX-C). So at most so many an hour,
    and each machine that was opened named at least once an hour. Used on the event loop only; one a kind, kept as long as
    the routes that write them. `an_hour` is asked at each entry (a module's setting, which a test may change)."""

    def __init__(self, an_hour: Callable[[], int]) -> None:
        self.an_hour = an_hour
        self._left: dict[str, tuple[float, float, int]] = {}  # account -> (entries it may still write, when counted, left out since)
        self._named: dict[str, dict[str, float]] = {}  # account -> machine -> when an entry of it was last written

    def take(self, who: str, about: str | None = None) -> int | None:
        """None where `who` has none left now, and `about` (a machine's id, or None for none) was named within the hour (this
        one is counted as left out); else how many were left out before it."""
        now, most = time.monotonic(), float(self.an_hour())
        left, at, unsaid = self._left.get(who, (most, now, 0))
        left = min(most, left + (now - at) * most / 3600)
        named = self._named.setdefault(who, {})
        for machine in [machine for machine, when in named.items() if now - when >= NAMED_AGAIN_AFTER]:
            del named[machine]  # (so many as there are machines at the most, and those of the last hour only)
        if left < 1 and (about is None or about in named):
            self._left[who] = (left, now, unsaid + 1)
            return None
        self._left[who] = (max(0.0, left - 1), now, 0)
        if about is not None:
            named[about] = now
        return unsaid


def _tail_of(file: BinaryIO, end: int) -> str:
    """A hash of the TAIL_KEPT bytes of a text file just before `end` (all of them, where it is shorter): by which the index
    knows, at its next look, that the file still holds what it read of it. (Several entries' worth, each with its own
    moment: the same bytes again there are the same entries.)"""
    start = max(0, end - TAIL_KEPT)
    file.seek(start)
    return hashlib.sha256(file.read(end - start)).hexdigest()[:32]


class Index:
    """The index of one activity log. Made with the program; its thread is started with the wall and never waited for."""

    def __init__(self, path: Path, text: AuditLog) -> None:
        self.path = path
        self.text = text
        self._wake = threading.Event()  # there may be more in the text files
        self._halt = threading.Event()  # the thread is to end
        self._done = threading.Condition()
        self._through = float("-inf")  # perf_counter time at which the last round that took in all there was began
        self._generation = 0  # one more whenever what the index held is thrown away (a read under way is then not believed)
        self._writer: threading.Thread | None = None
        self._starting = threading.Lock()
        self._again = False  # started again while a thread told to stop had not ended: that one starts the next as it ends
        self._conn: sqlite3.Connection | None = None
        self._opened: tuple[int, int] | None = None  # the writer's: (device, inode) of the file it has open
        self._newest: tuple[str, int] | None = None  # the writer's: (mark, seq) of the newest text file as last read
        self._rotations_seen = -1  # the writer's: the text log's rotation count at the last round that took in all there was
        self._looked = float("-inf")  # the writer's: monotonic time the old text files were last looked at
        self._refused = 0  # the writer's: rounds that its disk refused since one went through
        self._wal_again = 0.0  # the writer's: monotonic time before which the -wal file's size is not looked at again
        self._unreadable = 0  # the writer's: rounds in a row in which a text file could not be opened
        self._said: dict[str, float] = {}  # what trouble the log was last told of, and when
        self.made: float | None = None  # the writer's: seconds the last making from the start took (for whoever tests)

    # --- the wall's side: nothing here waits for the disk -------------------------------------------------------

    def start(self) -> None:
        """Start the thread that follows the text files: at the wall's start, and again after its listeners were opened anew
        (stop, in between). A second call while it runs changes nothing. Where a thread told to stop has not ended yet (a
        step on a slow disk), that one starts the next as it ends: refused here, the index stayed off until the listeners
        were opened anew another time, which may never come (the second reviewer of W4c)."""
        with self._starting:
            if self._writer is not None and self._writer.is_alive():
                if self._halt.is_set():
                    self._again = True
                return
            self._launch()

    def _launch(self) -> None:
        """(Holding _starting.) A thread of its own, from now on."""
        self._halt.clear()
        self._again = False
        self._writer = threading.Thread(target=self._run, name="activity-index", daemon=True)
        self._writer.start()

    def wake(self) -> None:
        """There is more in the text files (told by their writer: it must not wait, and does not)."""
        self._wake.set()

    def stop(self, within: float = 5.0) -> None:
        """End the thread, within a time (in a worker thread: the wall stopping). What it was taking in stays as far as it
        got, its file is closed, and what is in its -wal file goes into it; the next start reads on from there."""
        with self._starting:
            writer = self._writer
            self._again = False
            self._halt.set()
            self._wake.set()
        if writer is None:
            return
        writer.join(within)
        with self._starting:
            if self._writer is writer and not writer.is_alive():
                self._writer = None
        with self._done:
            self._through = float("-inf")  # (stopped: nothing it took in from here on, until it is started again)

    def caught_up(self, within: float = CATCH_UP) -> int | None:
        """Wait (in a worker thread) until the index holds what the text files held when this was asked: the
        generation of what it holds then, or None where it does not within the time (it is not started, being made,
        refused by its disk)."""
        # (perf_counter, not monotonic: on Windows before Python 3.13 that ticks every 15.6 ms, and a round that began before an
        # entry was written, in the tick in which this was asked, counted as one that began after it: the read missed it.)
        asked_at = time.perf_counter()
        if self._writer is None or not self._writer.is_alive():
            return None
        self._wake.set()
        deadline = asked_at + within
        with self._done:
            while self._through <= asked_at:
                left = deadline - time.perf_counter()
                if left <= 0:
                    return None
                self._done.wait(left)
            return self._generation

    # --- reading: for a worker thread, never for the event loop -------------------------------------------------

    def read(self, asked: Asked, limit: int) -> Found:
        """The newest `limit` entries asked for, newest first. From the index where it holds all the text files do,
        else from the text files themselves. NotReadable where the index took too long."""
        self.text.flush()  # what was done a moment ago is in what is read
        generation = self.caught_up()
        if generation is not None:
            try:
                rows = self._query(asked, limit + 1)
            except sqlite3.Error:
                rows = None  # (being made again, or its disk: the text files say the same)
            if rows is not None and generation == self._generation:
                entries = [entry for _, line in rows[:limit] if (entry := _loaded(line)) is not None]
                return Found(entries, len(rows) > limit, "index")
        found = self._from_text(asked, limit + 1, READ_PATIENCE)
        return Found(found[:limit], len(found) > limit, "text")

    def _from_text(self, asked: Asked, limit: int, patience: float) -> list[dict[str, Any]]:
        """The newest `limit` entries asked for, read from the text files themselves, within `patience` seconds: a word that is
        nowhere in 100 MB took 4 to 6 s here, longer on a slower computer, and the thread it ran in was the wall's.
        NotReadable where it takes longer (the index is behind: made, or refused by its disk)."""
        deadline = time.monotonic() + patience
        found: list[dict[str, Any]] = []
        with contextlib.closing(self.text.entries()) as entries:
            for count, entry in enumerate(entries):
                if count % 1000 == 0 and time.monotonic() > deadline:
                    raise NotReadable(
                        f"The activity log's index is not ready, and reading the log itself for this took longer than {patience:g} seconds. "
                        "Try again in a moment, or narrow it down: a machine, an account, a time."
                    )
                if asked.wants(Facts.of(entry)):
                    found.append(entry)
                    if len(found) >= limit:
                        break
        return found

    def pager(self, asked: Asked) -> Pager:
        """Every entry asked for, newest first, a page at a time (a download): see `pages`."""
        return Pager(self.pages(asked))

    def pages(self, asked: Asked) -> Iterator[list[dict[str, Any]]]:
        """Every entry asked for, newest first, PAGE at a time: each page read when it is asked for (in a worker thread),
        and none of them holds the index between two. Where the index is thrown away meanwhile, the rest comes from the
        text files, from the moment of the last entry handed over on."""
        self.text.flush()
        generation = self.caught_up()
        below: int | None = None
        last: float | None = None
        while generation is not None:
            try:
                rows = self._query(asked, PAGE, below)
            except sqlite3.Error:
                rows = None
            if rows is None or generation != self._generation:
                break
            entries = [entry for _, line in rows if (entry := _loaded(line)) is not None]
            if entries:
                yield entries
            if len(rows) < PAGE:
                return
            below, last = rows[-1][0], entries[-1]["time"] if entries else last
        rest = asked if last is None else dataclasses.replace(asked, before=last if asked.before is None else min(last, asked.before))
        page: list[dict[str, Any]] = []
        deadline = time.monotonic() + PAGE_PATIENCE
        with contextlib.closing(self.text.entries()) as reading:
            for count, entry in enumerate(reading):
                if count % 1000 == 0 and time.monotonic() > deadline:
                    raise NotReadable(f"The activity log's index is not ready, and reading the log itself took longer than {PAGE_PATIENCE:g} seconds for a page of the download")
                if rest.wants(Facts.of(entry)):
                    page.append(entry)
                    if len(page) >= PAGE:
                        yield page
                        page = []
                        deadline = time.monotonic() + PAGE_PATIENCE  # (the next page's own time: from when it is asked for)
        if page:
            yield page

    def _query(self, asked: Asked, limit: int, below: int | None = None) -> list[tuple[int, str]]:
        """(id, line) of the newest `limit` entries asked for, below the id `below` where it is given."""
        conn = sqlite3.connect(read_only_uri(self.path), uri=True, timeout=2.0)
        deadline = time.monotonic() + READ_PATIENCE
        try:
            conn.execute("PRAGMA query_only = 1")
            conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
            where, values = asked.where()
            if below is not None:
                where = f"{where} AND id < ?" if where else " WHERE id < ?"
                values.append(below)
            try:
                return [(row[0], row[1]) for row in conn.execute(f"SELECT id, line FROM entries{where} ORDER BY id DESC LIMIT ?", (*values, limit))]
            except sqlite3.OperationalError as ex:
                if "interrupted" in str(ex):
                    raise NotReadable(f"Looking through the activity log took longer than {READ_PATIENCE:g} seconds. Narrow it down: a machine, an account, a time.") from None
                raise
        finally:
            conn.close()

    # --- the thread that follows the text files ----------------------------------------------------------------

    def _say(self, what: str, line: str, *values: Any, traceback: bool = False) -> None:
        now = time.monotonic()
        if now - self._said.get(what, float("-inf")) >= SAY_EVERY:
            self._said[what] = now
            (log.exception if traceback else log.error)(line, *values)

    def _run(self) -> None:
        try:
            while not self._halt.is_set():
                self._wake.wait(TICK)
                self._wake.clear()
                if self._halt.is_set():
                    break
                began = time.perf_counter()  # (as caught_up counts: see there)
                try:
                    if self._conn is None and not self._open():
                        self._pause()
                        continue
                    if self._halt.is_set():
                        break  # (told to stop while the file was being opened and checked)
                    if self._follow():
                        with self._done:
                            self._through = began
                            self._done.notify_all()
                    self._refused = 0
                except Exception as ex:
                    self._trouble(ex)
        finally:
            self._close()
            with self._starting:
                if self._again and self._writer is threading.current_thread():
                    self._launch()  # (started again while this one was being stopped: see start)

    def _pause(self) -> None:
        """After a refusal: tried again in a while, a longer one each time up to a minute (only being told to end cuts it short)."""
        wait = REFUSED[min(self._refused, len(REFUSED) - 1)]
        self._refused += 1
        self._halt.wait(wait)
        self._wake.set()  # (and then at once: what came meanwhile is there to take in)

    def _trouble(self, ex: Exception) -> None:
        if isinstance(ex, _Moved):
            return  # (another writer took it in: looked at again at the next round, as it is then)
        if isinstance(ex, _Short):
            needed = 2 * self.text.max_bytes + 2 * WAL_MOST
            self._say("short", "the activity log's index waits: the disk has %d MB free, and the activity log's files are to have %d MB of it; the activity log is read from its files meanwhile", ex.args[0] // 1_000_000, needed // 1_000_000)
            self._pause()
            return
        if _damaged(ex):
            if not self._remove(str(ex)):
                self._pause()
            return
        self._close()
        if isinstance(ex, sqlite3.OperationalError):
            # The disk is full, or refuses for the moment: the text files have every entry, and are read meanwhile.
            self._say("write", "the activity log's index could not be written (%s): the activity log is read from its files meanwhile, which takes longer", ex)
        else:
            # A slip of this program's own: said with the traceback, once a minute, and tried again in a while.
            self._say("slip", "the activity log's index failed: the activity log is read from its files meanwhile", traceback=True)
        self._pause()

    def _close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
        self._opened = None
        self._newest = None

    def _forget_all(self) -> None:
        """What the index held is not to be believed from here on: a read under way is not, and none is until it is made again."""
        with self._done:
            self._generation += 1
            self._through = float("-inf")

    def _remove(self, why: str) -> bool:
        """Throw the index away, to be made again from the text files. False where its file cannot be removed just now (a
        read holds it open, on Windows): tried again at the next round."""
        self._forget_all()
        self._close()
        try:
            for tail in ("", "-wal", "-shm"):
                self.path.with_name(self.path.name + tail).unlink(missing_ok=True)
        except OSError as ex:
            self._say("remove", "the activity log's index is to be made again (%s), and could not be removed yet: %s", why, ex.strerror or ex)
            return False
        log.warning("the activity log's index is made again from the activity log's files (%s); nothing of the log is lost", why)
        self._wake.set()
        return True

    def _open(self) -> bool:
        """Open the index, making it where there is none; one that cannot be used is removed and made anew."""
        for attempt in (1, 2):
            try:
                conn = sqlite3.connect(self.path, timeout=WRITE_PATIENCE, isolation_level="DEFERRED")
            except sqlite3.Error as ex:
                self._say("open", "the activity log's index in %s could not be opened: %s", self.path.parent, ex)
                return False
            try:
                self._prepare(conn)
                found = os.stat(self.path)
            except Exception as ex:
                conn.close()
                if _damaged(ex):
                    if attempt == 1 and self._remove(str(ex)):
                        continue  # (made anew at once)
                    return False  # (said by _remove; tried again after a pause)
                if not isinstance(ex, (sqlite3.OperationalError, OSError)):
                    raise  # (a slip of this program's own: _trouble says it)
                self._say("open", "the activity log's index in %s could not be opened: %s", self.path.parent, ex)
                return False
            self._conn, self._opened = conn, (found.st_dev, found.st_ino)
            self._looked = float("-inf")
            return True
        return False

    def _prepare(self, conn: sqlite3.Connection) -> None:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, VERSION):
            raise _Unusable(f"made by another version of qKVM ({version})")
        deadline = time.monotonic() + OPEN_PATIENCE
        # (Given up where it takes longer than that, or where the thread is told to stop: the wall stopping waits for neither.)
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline or self._halt.is_set() else 0, 10_000)
        try:
            verdict = conn.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.OperationalError as ex:
            if "interrupted" not in str(ex):
                raise
            verdict = "ok"  # (a large file on a slow disk: taken as it is; what is wrong with it is met where it is)
        finally:
            conn.set_progress_handler(None, 0)
        if verdict != "ok":
            raise _Unusable(f"quick_check: {str(verdict)[:120]}")
        conn.execute("PRAGMA journal_mode = WAL")  # reads do not wait for the writer, nor it for them
        conn.execute("PRAGMA synchronous = NORMAL")  # a power cut may lose the last moments, never the file: and those are in the text files
        conn.execute(f"PRAGMA journal_size_limit = {WAL_MOST}").fetchall()
        with conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            made = conn.execute("SELECT value FROM meta WHERE key = 'made'").fetchone()
            if made is None and conn.execute("SELECT 1 FROM files LIMIT 1").fetchone() is None:
                conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('made', ?)", (MADE,))
            elif made is None or made[0] != MADE:
                raise _Unusable("made with other kinds of entries")
            conn.execute(f"PRAGMA user_version = {VERSION}")

    def _follow(self) -> bool:
        """One round: take in what is new in the text files, let go of what is gone from them. True where all there was is in."""
        conn = self._conn
        assert conn is not None
        # (Reading on in the newest file alone, only while the writer has not moved the files on since the last look at all of
        # them: a rotation whose last step failed left the newest where it was, and the oldest gone, which the index answered
        # for a minute; the third reviewer of W4c.)
        if self._newest is not None and time.monotonic() - self._looked < LOOK_AGAIN and self.text.rotations == self._rotations_seen:
            taken = self._take_newest(conn)
            if taken is not None:
                return taken
        self._looked = time.monotonic()
        try:
            found = os.stat(self.path)
            here = (found.st_dev, found.st_ino)
        except OSError:
            here = None
        if here != self._opened:
            # Its file was removed or replaced while it was open (somebody cleaning the folder, where a system lets an open
            # file go): what this one writes into would be read by nobody. Opened again, and made again.
            self._forget_all()
            self._close()
            self._wake.set()
            return False
        return self._reconcile(conn)

    def _take_newest(self, conn: sqlite3.Connection) -> bool | None:
        """Read on in the file being written, where it is still the one read last. None where it is not (a new one was begun,
        or it cannot be opened just now: on Windows, while it is being moved aside as the newest of the old ones)."""
        assert self._newest is not None
        mark, seq = self._newest
        try:
            with open_shared(self.text.path) as file:
                if _mark(file, newest=True) != mark:
                    return None
                return self._take(conn, file, seq, newest=True)
        except OSError:
            return None

    def _reconcile(self, conn: sqlite3.Connection) -> bool:
        """Every text file looked at: those that are new are taken in, oldest first, and then those that are gone go from here.

        What goes, goes only once every file there was seen to be the one it was listed as: the writer may move the files on
        while they are listed, and a file that moved from a place not yet looked at to one already looked at was missing from
        the list, though it was there (the first reviewer of W4c: it was let go of, and the whole index made again; a read in
        that moment was answered without it).
        """
        present: list[tuple[Path, str, bool]] = []  # oldest first: (where, its mark, the file being written)
        unsure = False  # a file could not be looked at: nothing is let go of this round
        # The writer's count of its moving the files on, as the listing begins. Where it is another one by the time something
        # is to be let go of, or odd (under way), nothing is: a file that moved past the listing was missing from it though it
        # was there, and the files below a gap (a young log, a step that had failed) move on without the listed ones changing
        # (the second reviewer of W4c: let go of, the index answered without it for a minute, and was made again).
        rotations = self.text.rotations
        self._newest = None  # (read on in alone only after a round that took in all there was: see the end)
        for path in reversed(self.text.files()):
            newest = path == self.text.path
            try:
                with open_shared(path) as file:
                    digest = _mark(file, newest)
            except FileNotFoundError:
                continue
            except OSError:
                unsure = True
                continue
            if digest is not None:
                present.append((path, digest, newest))
        # Nothing is taken in where the files were moved on while they were listed, nor where one could not be opened: a newer
        # file taken in past an older one whose rest was not had its entries before that rest, the order of the index was not
        # the files', and the older one's going later took the newer one's entries with it (the third reviewer of W4c).
        if rotations % 2 or self.text.rotations != rotations:
            self._wake.set()  # (looked at again at once, the files as they are now)
            return False
        if unsure:
            self._unreadable += 1
            if self._unreadable >= UNREADABLE_SAID:
                self._say("text", "a file of the activity log could not be opened for its index: it is tried again, and the activity log is read from its files meanwhile")
            return False
        known = {mark: (seq, done) for seq, mark, done in conn.execute("SELECT seq, mark, done FROM files ORDER BY seq")}
        if len({mark for _, mark, _ in present}) < len(present):
            # Two files that begin with the same line (a copy made by hand): which of them is which cannot be told by that, and
            # taken for each other, the index said what neither holds. It steps aside (thrown away now, made again from the
            # start once only one of them is there), and the text files are read meanwhile.
            self._newest = None
            if known and not self._remove("two of the activity log's files begin with the same line"):
                self._pause()
            self._say("doubled", "two of the activity log's files begin with the same line (a copy made by hand?): the activity log is read from its files until one of them goes")
            return False
        # The files it holds have to be the oldest of those that are there, in the order it took them in, and none of them
        # shorter than it read it: what is not so (a file put back by hand, a folder put together from two) is made again.
        newer, last = False, -1
        for _, mark, _ in present:
            if mark not in known:
                newer = True
            elif newer or known[mark][0] < last:
                if not self._remove("its files are not the activity log's files as they are now"):
                    self._pause()
                return False
            else:
                last = known[mark][0]
        gone = [seq for mark, (seq, _) in known.items() if mark not in {mark for _, mark, _ in present}]
        making = not known and bool(present)  # (from the start: after an upgrade, or where it was made again)
        began = time.monotonic()
        complete = True
        newest_taken: tuple[str, int] | None = None
        for path, mark, newest in present:
            if self._halt.is_set():
                return False
            if mark not in known:
                with conn:
                    conn.execute("INSERT OR IGNORE INTO files (seq, mark, done) VALUES ((SELECT COALESCE(MAX(seq), 0) + 1 FROM files), ?, 0)", (mark,))
                    seq, done = conn.execute("SELECT seq, done FROM files WHERE mark = ?", (mark,)).fetchone()
                known[mark] = (seq, done)
            seq = known[mark][0]
            try:
                with open_shared(path) as file:
                    if _mark(file, newest) != mark:
                        self._wake.set()  # (moved on since it was looked at: looked at again at once)
                        return False
                    complete = self._take(conn, file, seq, newest) and complete
            except FileNotFoundError:
                self._wake.set()  # (moved on: looked at again at once)
                return False
            except OSError as ex:
                # Not to be read just now (on Windows, while it is being moved on; or its permissions): looked at again at the
                # next round, and the text files are read meanwhile. Said where it lasts half a minute.
                self._unreadable += 1
                if self._unreadable >= UNREADABLE_SAID:
                    self._say("text", "a file of the activity log could not be read for its index (%s): it is tried again", ex.strerror or ex)
                return False
            if newest:
                newest_taken = (mark, seq)
        self._unreadable = 0
        if rotations % 2 or self.text.rotations != rotations:
            # (Nor is the round complete: a file that moved past the listing before it was ever seen was not taken in.)
            self._wake.set()  # (looked at again at once, the files as they are now)
            return False
        for seq in gone:  # (every file there was seen to be the one it was listed as: these are gone from the text files)
            self._let_go(conn, seq)
        self._hold_wal(conn)
        if complete:
            self._newest, self._rotations_seen = newest_taken, rotations
        # What SQLite knows of how the entries are spread, by which it picks an index for a question: one machine's alerts on
        # a day long ago took 130 ms over 630,000 entries without it (all the alerts walked), 0.1 ms with it. Made when the
        # index is made, and kept up as it grows (`optimize` does nothing where nothing has changed much). Of every row: what a
        # few rows of each index say (analysis_limit) took 1,000 entries of each kind for 150,000, and chose as badly as none.
        conn.set_progress_handler(lambda: 1 if self._halt.is_set() else 0, 10_000)  # (a stop does not wait for it either)
        try:
            conn.execute("ANALYZE" if making and complete else "PRAGMA optimize").fetchall()
        except sqlite3.OperationalError as ex:
            if "interrupted" not in str(ex):
                raise
        finally:
            conn.set_progress_handler(None, 0)
        if making and complete:
            self.made = time.monotonic() - began
            count = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            log.info("the activity log's index was made from its %d files in %.1f s: %d entries", len(present), self.made, count)
        return complete

    def _let_go(self, conn: sqlite3.Connection, seq: int) -> None:
        """The entries of a text file that is gone go (so many at a time), and then its row."""
        first, last = conn.execute("SELECT first_id, last_id FROM files WHERE seq = ?", (seq,)).fetchone()
        if first is not None and last is not None:
            for low in range(first, last + 1, GONE_AT_ONCE):
                with conn:
                    conn.execute("DELETE FROM entries WHERE id >= ? AND id <= ?", (low, min(last, low + GONE_AT_ONCE - 1)))
                self._hold_wal(conn)
        with conn:
            conn.execute("DELETE FROM files WHERE seq = ?", (seq,))

    def _take(self, conn: sqlite3.Connection, file: BinaryIO, seq: int, newest: bool) -> bool:
        """Take in what one text file holds beyond what was read of it, a transaction a CHUNK. True where it is all in.

        Of the file being written, only lines that have ended (as the text files are read: AuditLog.entries); of an old one,
        all of it: nothing more comes to it.
        """
        done, tail = conn.execute("SELECT done, tail FROM files WHERE seq = ?", (seq,)).fetchone()
        done = int(done)
        size = file.seek(0, os.SEEK_END)
        if size < done:
            raise _Unusable("a file of the activity log is shorter than when it was read")
        if done and _tail_of(file, done) != tail:
            # It holds other bytes where it was read to. The text files are not synced, the index is (at its checkpoints): a
            # power cut can take the last lines of the text file and leave them in the index, and once the next start has
            # written as many bytes again, its length says nothing. Read on from there, the index kept entries the record no
            # longer has and missed the first ones written after the restart (the reviewer of 0.2.0). Made again from the files.
            raise _Unusable("a file of the activity log no longer holds what was read of it")
        at = done
        while at < size and not self._halt.is_set():
            file.seek(at)
            data = file.read(min(CHUNK, size - at))
            if not data:
                break
            cut = data.rfind(b"\n")
            if cut >= 0:
                lines, used = data[:cut].split(b"\n"), cut + 1
            elif at + len(data) < size:
                # A line longer than a CHUNK, which no entry is: its end is looked for, and none of it is kept.
                ends = self._line_end(file, at + len(data), size)
                if ends is None:
                    if newest:
                        return True  # (its end has not been written: nothing more to take in now)
                    ends = size
                lines, used = [], ends - at
            elif not newest:
                lines, used = [data], len(data)  # (the last line of an old file, which will never end)
            else:
                # The rest of a line still on its way, or one written by hand without its end: taken in once it has ended,
                # which the text log's writer sees to before its next entry. (Taken as it stood, the writer's next entry was
                # written onto it in the file, and the index held two entries where the file holds none.)
                return True
            self._insert(conn, seq, lines, at, at + used, _tail_of(file, at + used))
            at += used
        return at >= size

    @staticmethod
    def _line_end(file: BinaryIO, at: int, size: int) -> int | None:
        """Where the line that goes on at `at` ends (just after its line feed), or None where it does not before `size`."""
        while at < size:
            file.seek(at)
            data = file.read(min(CHUNK, size - at))
            if not data:
                return None
            cut = data.find(b"\n")
            if cut >= 0:
                return at + cut + 1
            at += len(data)
        return None

    def _insert(self, conn: sqlite3.Connection, seq: int, lines: list[bytes], since: int, done: int, tail: str) -> None:
        """The entries of these lines (read from byte `since` of the file to byte `done`), and how far it is read (with `tail`,
        the hash of the bytes just before `done`), in one transaction. Where another writer read that part meanwhile (two
        walls of a test on one folder: one qKVM runs on a data folder at a time), nothing: the same entries are never put in
        twice."""
        rows = []
        for line in lines:
            entry = entry_of(line)
            if entry is None:
                continue
            found = Facts.of(entry)
            # (The machine's name only where the entry gives no id: it is looked for by its name only then.)
            device = found.device if found.device_id is None else None
            rows.append((found.t, found.kind, found.who, device, found.device_id, found.said, _clean(line.decode("utf-8", errors="replace"))))
        self._room()
        with conn:
            # First, and in the transaction: it takes the file for this writer, and says whether that part is still to be read.
            if conn.execute("UPDATE files SET done = ?, tail = ? WHERE seq = ? AND done = ?", (done, tail, seq, since)).rowcount != 1:
                raise _Moved
            if rows and conn.execute("SELECT 1 FROM files WHERE seq > ? AND last_id IS NOT NULL LIMIT 1", (seq,)).fetchone() is not None:
                # A newer file has entries already: these would come after them, the order of the index would not be the files',
                # and a file's entries would not be one range of ids (which is how they go when it goes). Never taken in so by
                # the rounds as they are; where it happens all the same, the index is made again.
                raise _Unusable("its entries would no longer be in the order of the files")
            if rows:
                first = (conn.execute("SELECT MAX(id) FROM entries").fetchone()[0] or 0) + 1
                conn.executemany(
                    "INSERT INTO entries (id, t, kind, who, device, device_id, said, line) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [(number, *row) for number, row in zip(itertools.count(first), rows)],
                )
                conn.execute("UPDATE files SET first_id = COALESCE(first_id, ?), last_id = ? WHERE seq = ?", (first, first + len(rows) - 1, seq))
        self._hold_wal(conn)

    def _room(self) -> None:
        """_Short where the disk has less free than the record is to have: the next text file and the one after it, and the
        -wal file's share twice. The index is two and a half times the text files' size; growing into the last of a disk, it
        took the room the record needed, and the activity log's next entries were not written. It waits instead (tried again
        after 5 s, 15 s, then every minute), and the text files are read meanwhile."""
        try:
            free = shutil.disk_usage(self.path.parent).free
        except OSError:
            return
        if free < 2 * self.text.max_bytes + 2 * WAL_MOST:
            raise _Short(free)

    def _hold_wal(self, conn: sqlite3.Connection) -> None:
        """Where the -wal file has grown past WAL_MOST (reads that overlapped kept SQLite from beginning it again), what is
        in it goes into the file, once the reads under way have ended: they end within READ_PATIENCE. Not again for a
        minute where that did not get through (something outside qKVM holds a read open)."""
        if time.monotonic() < self._wal_again:
            return
        try:
            if self.path.with_name(self.path.name + "-wal").stat().st_size <= WAL_MOST:
                return
        except OSError:
            return
        conn.execute(f"PRAGMA busy_timeout = {int(CHECKPOINT_PATIENCE * 1000)}").fetchall()
        try:
            busy = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        except sqlite3.OperationalError as ex:
            busy, why = 1, str(ex)
        else:
            why = "a read held it"
        finally:
            conn.execute(f"PRAGMA busy_timeout = {int(WRITE_PATIENCE * 1000)}").fetchall()
        if busy:
            self._wal_again = time.monotonic() + CHECKPOINT_AGAIN
            self._say("checkpoint", "the activity log's index could not be brought up to date from its -wal file: %s", why)


class Pager:
    """The pages of a download: each read by `next` in a worker thread, one at a time, and let go of by `close` from any
    thread (a download cut off), which waits for a page being read to be done rather than cut into it."""

    def __init__(self, pages: Iterator[list[dict[str, Any]]]) -> None:
        self._pages = pages
        self._lock = threading.Lock()
        self._closed = False

    def next(self) -> list[dict[str, Any]] | None:
        """The next page; None when there are no more."""
        with self._lock:
            if self._closed:
                return None
            return next(self._pages, None)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            close = getattr(self._pages, "close", None)
            if close is not None:
                close()  # (the text files it had open are closed)


def _loaded(line: str) -> dict[str, Any] | None:
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return entry if isinstance(entry, dict) else None


def size_of(folder: Path) -> tuple[int, int, int]:
    """(bytes the activity log's files take, how many there are, bytes its index takes) in a data folder. Only looks."""
    text = files = index = 0
    for path in AuditLog(folder / "audit.log").files():
        try:
            text += path.stat().st_size
            files += 1
        except OSError:
            pass
    for tail in ("", "-wal"):
        try:
            index += (folder / (FILE + tail)).stat().st_size
        except OSError:
            pass
    return text, files, index
