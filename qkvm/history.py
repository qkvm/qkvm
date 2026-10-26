"""What the wall saw of each machine, kept beside the settings: `history.sqlite` in the data folder.

The settings file says what the wall is; this says what happened to the machines on it. Four tables, each
row by a device's id and nothing else (no name, no address, no secret): the states a tile went through (a
row when the state changes, not at every look), the sensors a device reports at a slow pace, the power
events the wall pressed or noticed, and for each device when it was first and last heard from. The
activity log (who did what) stays what it is, JSON lines in audit.log.

Written by one thread of its own, from a bounded queue: whoever notes something is in the middle of
answering a request, on the one thread that serves everybody, and does not wait for a disk. A full queue
drops what comes and counts it, as the activity log does; what one device can put in it is held to a
pace, and a machine taken off the wall is never dropped (a list of its own). The writer trims by age and
by size (the file and its -wal file together), and a file it cannot read is moved aside and a fresh one
started, with a line in the log: a damaged history is not a reason for the wall not to come up.

Time is the clock on the wall (time.time()), which is how whoever reads a history wants it.
"""

from __future__ import annotations

import itertools
import logging
import math
import os
import queue
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import read_only_uri

log = logging.getLogger("qkvm")

FILE = "history.sqlite"
VERSION = 1  # of the tables, as this program makes them (PRAGMA user_version)
DEFAULT_DAYS = 90  # how long rows are kept, unless the settings say otherwise
DEFAULT_MB = 200  # how large the file may grow, in millions of bytes, unless the settings say otherwise
LEAST_DAYS, MOST_DAYS = 1, 3650
LEAST_MB, MOST_MB = 10, 100_000
SAMPLE_EVERY = 60.0  # seconds between two samples of a sensor whose reading holds still
SEEN_EVERY = 60.0  # seconds between two notes of when a device was last heard from, while nothing else changes
STALE = 180.0  # seconds without a look after which a device counts as unwatched, from its last look on
QUEUE_SIZE = 20_000  # rows waiting to be written, at the most; beyond that they are dropped and counted
BATCH = 500  # rows written in one transaction, at the most
TICK = 1.0  # seconds the writer waits for a row before it looks whether there is housekeeping to do
TRIM_EVERY = 600.0  # seconds between two trims by age and size
TRIM_PATIENCE = 30.0  # seconds one trim by size may go on deleting; what is still over the size allowed goes at the next
SLICES = 20  # steps of time a long cut is made in, every device to each in turn (see _delete_before)
SAY_EVERY = 60.0  # seconds between two lines in the log about the same trouble
READ_WAIT = 3.0  # seconds a read waits for the file to be opened
READ_PATIENCE = 5.0  # seconds a read may take before it is given up
WRITE_PATIENCE = 5.0  # seconds a write waits for the file (only a checkpoint of another connection could hold it)
# Seconds a checkpoint waits for the reads under way to end: longer than any read may take, so that it gets through
# however the reads come. (It waited the writer's five seconds, as long as a read may take, and reads of four or
# five seconds one after the other kept it from ever getting through.)
CHECKPOINT_PATIENCE = 2 * (READ_WAIT + READ_PATIENCE)
CHECKPOINT_AGAIN = 60.0  # seconds after a checkpoint that did not get through before one is tried again for the -wal's size
WAL_MOST = 8_000_000  # bytes the -wal file may take before it is brought into the file: this, or a tenth of the size allowed where that is less
OPEN_PATIENCE = 120.0  # seconds the check of a file at a start may take before it is taken as not done
MOST_ROWS = 5000  # rows one read hands over, at the most
DAY, WEEK = 86400.0, 7 * 86400.0
# How far a reading has to move before a sample is taken sooner than SAMPLE_EVERY, by the unit it is in.
STEP = {"C": 2.0, "RPM": 200.0, "%": 5.0, "W": 10.0}
UNWATCHED = "unwatched"  # the state a device is in while the wall is not looking at it: not a tile's state
ANSWERING = ("online", "no_signal", "auth", "busy")  # states in which the device itself is there (as metrics counts them)
WHAT = ("summary", "states", "samples", "events")  # what a read can be asked for
MOST_SENSORS = 64  # sensors kept per device: a controller with more is cut, as the status is
# Samples one device may hand the writer within SAMPLE_EVERY: each of its sensors once, and as many again for readings
# that move. A device that names its sensors anew at every look, or makes every reading jump, gets no more than that.
SAMPLES_PER_ROUND = 2 * MOST_SENSORS
# A history moved aside as damaged: the second it was moved aside, and a number where two were moved in one second.
_ASIDE = re.compile(r"history\.damaged-(\d{1,12})(?:-\d{1,6})?\.sqlite(?:-wal|-shm)?")
# The rows that are of one device, which is the second field of each.
_OF_A_DEVICE = frozenset(("state", "seen", "sample", "event", "power", "unwatched"))

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS states (device TEXT NOT NULL, t REAL NOT NULL, state TEXT NOT NULL, code TEXT NOT NULL DEFAULT '', PRIMARY KEY (device, t)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS samples (device TEXT NOT NULL, t REAL NOT NULL, sensor TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL DEFAULT '', PRIMARY KEY (device, t, sensor)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS events (device TEXT NOT NULL, t REAL NOT NULL, kind TEXT NOT NULL, what TEXT NOT NULL, ok INTEGER, note TEXT NOT NULL DEFAULT '')",
    "CREATE INDEX IF NOT EXISTS events_by_device ON events (device, t)",
    "CREATE TABLE IF NOT EXISTS devices (device TEXT NOT NULL PRIMARY KEY, first_seen REAL, last_seen REAL, looked REAL, state TEXT, state_at REAL, power TEXT) WITHOUT ROWID",
)


class NotReadable(Exception):
    """The history cannot be read just now: the file is being opened or replaced, or is damaged."""


class _Unreadable(Exception):
    """A file this program will not write into: one whose own check finds it damaged, or a later version's."""


class _NotNow(Exception):
    """The file is not open just now: what was to be done in it waits for the next turn."""


def _damaged(ex: BaseException) -> bool:
    """Whether an error says that the file itself is damaged, or is no database at all.

    Only that is a reason to move a file aside. Not a disk that refuses (OperationalError), and not a slip of this
    program's own (a constraint a row breaks, a value that cannot be bound): taken for damage, a mistake in the
    shape of a row would move a healthy history aside again and again, and the trim would later delete it.
    """
    if isinstance(ex, _Unreadable):
        return True
    code = getattr(ex, "sqlite_errorcode", None)
    return isinstance(ex, sqlite3.DatabaseError) and isinstance(code, int) and code & 0xFF in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)


def _number(value: Any) -> float | None:
    """`value` as a number that can be kept, or None: a bool is none, and neither is what has no end."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _short(value: Any, most: int) -> str:
    """A text of the program's own (a state, a code, a sensor's name as the driver cut it), held to a length."""
    return value[:most] if isinstance(value, str) else ""


def sensors_of(status: dict[str, Any]) -> Iterator[tuple[str, float, str]]:
    """The readings a status carries: (sensor, value, unit). A device's own temperature, and a server's sensors."""
    count = 0
    health = status.get("health")
    own = _number(health.get("temp")) if isinstance(health, dict) else None
    if own is not None:
        count += 1
        yield "device", own, "C"
    server = status.get("server")
    if not isinstance(server, dict):
        return
    temperatures = server.get("temperatures")
    for number, entry in enumerate(temperatures if isinstance(temperatures, list) else []):
        if not isinstance(entry, dict) or (celsius := _number(entry.get("celsius"))) is None or count >= MOST_SENSORS:
            continue
        count += 1
        yield _short(entry.get("name"), 40) or f"temperature {number + 1}", celsius, "C"
    fans = server.get("fans")
    for number, entry in enumerate(fans if isinstance(fans, list) else []):
        if not isinstance(entry, dict) or (reading := _number(entry.get("reading"))) is None or count >= MOST_SENSORS:
            continue
        count += 1
        unit = entry.get("unit")
        yield _short(entry.get("name"), 40) or f"fan {number + 1}", reading, unit if unit in ("RPM", "%") else ""
    watts = _number(server.get("power_watts"))  # (no driver reports it yet; the row is here for the one that will)
    if watts is not None and count < MOST_SENSORS:
        yield "power", watts, "W"


@dataclass
class _Known:
    """What was last noted of one device, on the event loop's side: the rows are made from how this changes."""

    state: str | None = None
    power: bool | None = None
    looked: float = 0.0  # when the wall last looked at it
    seen_written: float = 0.0  # when its "last heard from" was last handed to the writer
    # sensor -> (when, reading) last handed over, of the sensors it reported at its last look and no others: the names
    # come from the device, and one that names them anew at every look grew this by sixty-four at each.
    samples: dict[str, tuple[float, float]] = field(default_factory=dict)
    round_at: float = float("-inf")  # when the SAMPLE_EVERY in which its samples are counted began
    spent: int = 0  # samples handed over in it (SAMPLES_PER_ROUND at the most)


class History:
    """The store. Made with the program, opened by its writer thread when that is started, and never waited for.

    `limits`: how long and how large, asked each time the writer trims: (days, millions of bytes).
    """

    def __init__(self, path: Path, limits: Callable[[], tuple[int, int]] | None = None) -> None:
        self.path = path
        self._limits = limits or (lambda: (DEFAULT_DAYS, DEFAULT_MB))
        self._known: dict[str, _Known] = {}
        self._waiting: queue.Queue[tuple[Any, ...]] = queue.Queue(QUEUE_SIZE)
        self._writer: threading.Thread | None = None
        self._starting = threading.Lock()
        self._stopping = False
        self._ready = threading.Event()  # the file is open and can be read
        self._conn: sqlite3.Connection | None = None
        self.dropped = 0  # rows that found the queue full, or a file that could not be written, since the start
        self._said: dict[str, float] = {}  # what trouble the log was last told of, and when
        self.damaged: Path | None = None  # where a file that could not be read was moved to, if one was
        self._opened_once = False  # the first open is the program's start; later ones (after a slip, a damaged file) are not
        # Devices taken off the wall whose rows the writer is still to delete. Beside the queue and not in it: a row of
        # a full queue is dropped, and a machine removed while the queue was full kept its history for good.
        self._forgotten: list[str] = []
        self._forgetting = threading.Lock()
        self._skipping: set[str] = set()  # the writer's: devices forgotten whose rows may still be in the queue, and are not written
        self._wal_again = 0.0  # the writer's: monotonic time before which the -wal's size is not looked at again (a checkpoint failed)
        self._wal_retry_at = 0  # the writer's: the -wal's size at which a checkpoint is tried again all the same (0: none failed)
        self._gone = 0  # the writer's: rows deleted in the transaction under way (see _delete_rows)
        self._until: float | None = None  # the writer's: monotonic time at which a trim under way stops deleting
        self._stalled = False  # the writer's: a trim under way found that the -wal file could not be brought into the file
        self._done_some = False  # the writer's: the deletion under way in a trim committed a transaction's worth

    # --- the event loop's side: nothing here waits ---------------------------------------------------

    def start(self) -> None:
        """Start the writer, which opens the file. Done once; a second call changes nothing."""
        if self._writer is not None:
            return
        with self._starting:
            if self._writer is None:
                self._writer = threading.Thread(target=self._run, name="history", daemon=True)
                self._writer.start()

    def _put(self, row: tuple[Any, ...]) -> None:
        try:
            self._waiting.put_nowait(row)
        except queue.Full:
            self.dropped += 1
            self._say("full", "the history is not keeping up: rows are dropped (%d so far)", self.dropped)
        if self._writer is None:
            self.start()

    def observe(self, device_id: str, status: dict[str, Any], now: float | None = None) -> None:
        """Note what the wall sees of a device at this moment: its status as the drivers give it."""
        now = time.time() if now is None else now
        known = self._known.get(device_id)
        if known is None:
            known = self._known[device_id] = _Known()
        known.looked = now
        state = _short(status.get("state"), 20) or "error"
        error = status.get("error")
        code = _short(error.get("code"), 40) if isinstance(error, dict) else ""
        ago = _number(status.get("last_seen_ago"))
        last_seen = None if ago is None else now - ago
        if state != known.state:
            known.state = state
            self._put(("state", device_id, now, state, code))
            known.seen_written = now
            self._put(("seen", device_id, now, last_seen, state))
        elif now - known.seen_written >= SEEN_EVERY:
            known.seen_written = now
            self._put(("seen", device_id, now, last_seen, state))
        atx = status.get("atx")
        # Only where the device says it has a power board (or is a machine's controller): a KVM without one says "power": false
        # all the same, which is no machine switched off.
        power = atx.get("power") if isinstance(atx, dict) and atx.get("enabled") is True else None
        if isinstance(power, bool) and power != known.power:
            known.power = power
            self._put(("power", device_id, now, "on" if power else "off"))
        # The samples. Those that are due by the time first (a sensor not sampled within SAMPLE_EVERY, or not before),
        # then those whose reading moved: a reading that moves at every look does not keep the others from being kept.
        present: dict[str, tuple[float, float] | None] = {}
        due: list[tuple[str, float, str]] = []
        moved: list[tuple[str, float, str]] = []
        for sensor, value, unit in sensors_of(status):
            if sensor in present:
                continue  # (two of one name: the first is kept, as the file keeps one reading of a name at a time)
            before = present[sensor] = known.samples.get(sensor)
            if before is None or now - before[0] >= SAMPLE_EVERY:
                due.append((sensor, value, unit))
            elif abs(value - before[1]) >= STEP.get(unit, 1.0):
                moved.append((sensor, value, unit))
        if not known.round_at <= now < known.round_at + SAMPLE_EVERY:
            known.round_at, known.spent = now, 0
        for sensor, value, unit in itertools.chain(due, moved):
            if known.spent >= SAMPLES_PER_ROUND:
                break  # (the rest are taken at a later look: one that is due stays due)
            known.spent += 1
            present[sensor] = (now, value)
            self._put(("sample", device_id, now, sensor, value, unit))
        known.samples = {sensor: last for sensor, last in present.items() if last is not None}

    def pressed(self, device_id: str, action: str, ok: bool | None, note: str = "", now: float | None = None) -> None:
        """A power action was pressed from the wall: which, and whether the device took it (None: nobody knows), with a
        `note` (an error code where it did not, "already on", "retired" where the connection went while it was under way)."""
        self._put(("event", device_id, time.time() if now is None else now, "pressed", _short(action, 40), None if ok is None else int(ok), _short(note, 40)))

    def sweep(self, now: float | None = None) -> None:
        """Devices the wall has not looked at for a while are unwatched from their last look on. Called now and then."""
        now = time.time() if now is None else now
        for device_id, known in list(self._known.items()):
            if now - known.looked >= STALE:
                del self._known[device_id]  # (seen again, it gets a fresh row: a new stretch of being watched)
                self._put(("unwatched", device_id, known.looked))

    def forget(self, *device_ids: str) -> None:
        """Devices taken off the wall take their history with them. Never dropped: the writer takes them from a list
        of their own at each turn, whatever the queue holds, and a row in the queue only wakes it."""
        for device_id in device_ids:
            self._known.pop(device_id, None)
        with self._forgetting:
            self._forgotten.extend(device_ids)
        try:
            self._waiting.put_nowait(("forget",))  # (and has flush wait for it; where the queue is full, it is taken at the next turn)
        except queue.Full:
            pass
        if self._writer is None:
            self.start()

    def trim(self) -> None:
        """Have the writer trim by age and size now, and not at its own pace. For tests."""
        self._put(("housekeeping",))

    def flush(self, within: float = 5.0) -> None:
        """Have what was noted so far written, and the last look at each device with it, into the one file. Waits, though not for ever: for a worker thread."""
        if self._writer is None:
            return
        self._put(("looked", {device_id: known.looked for device_id, known in self._known.items()}))
        self._put(("checkpoint",))  # (what was written goes from the -wal file into the file itself: a program that ends leaves it there)
        deadline = time.monotonic() + within
        while self._waiting.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)

    def stop(self, within: float = 5.0) -> None:
        """End the writer: what was noted is written first, within a time. For tests, and for a program that ends."""
        self.flush(within)
        self._stopping = True
        if self._writer is not None:
            self._writer.join(within)

    # --- the writer's thread ---------------------------------------------------------------------------

    def _say(self, what: str, line: str, *values: Any) -> None:
        """A line in the log, once a minute for each kind of trouble: a disk that refuses does so at every row."""
        now = time.monotonic()
        if now - self._said.get(what, float("-inf")) >= SAY_EVERY:
            self._said[what] = now
            log.error(line, *values)

    def _run(self) -> None:
        last_trim = float("-inf")
        try:
            while not self._stopping:
                try:
                    last_trim = self._round(last_trim)
                except Exception:
                    # A slip of the program's own outside a write (opening, trimming): said with the traceback,
                    # once a minute, and the file is closed and opened anew. (A slip in a write is met in _write.)
                    self._said_with_traceback("writer", "the history's writer failed, and starts afresh")
                    self._close()
                    time.sleep(1)
        finally:
            self._close()  # (a stopped writer holds nothing: on Windows an open file cannot be moved aside or removed)

    def _said_with_traceback(self, what: str, line: str, *values: Any) -> None:
        now = time.monotonic()
        if now - self._said.get(what, float("-inf")) >= SAY_EVERY:
            self._said[what] = now
            log.exception(line, *values)

    def _round(self, last_trim: float) -> float:
        """One turn of the writer: open the file if it is not, write what waits, trim when it is time. Returns when the last trim was."""
        if self._conn is None:
            self._open()
            if self._conn is None:
                self._drop_all()  # the folder refuses: tried again in a while, and what comes meanwhile is dropped
                for _ in range(int(SAY_EVERY)):
                    if self._stopping:
                        return last_trim
                    time.sleep(1)
                return last_trim
            last_trim = float("-inf")
        try:
            first = self._waiting.get(timeout=TICK)
        except queue.Empty:
            first = None
        rows = [] if first is None else [first]
        drained = first is None  # (the queue was emptied in this turn: everything noted before it began is written)
        while len(rows) < BATCH:
            try:
                rows.append(self._waiting.get_nowait())
            except queue.Empty:
                drained = True
                break
        try:
            if rows:
                self._write(rows)
            self._forget_now(drained)
            asked = {row[0] for row in rows}
            if "housekeeping" in asked:  # (asked for: done before these rows count as written)
                last_trim = time.monotonic()
                self._housekeeping()
            elif "checkpoint" in asked:
                self._checkpoint()
            elif rows:
                self._hold_wal()
        finally:
            for _ in rows:
                self._waiting.task_done()
        if self._conn is not None and time.monotonic() - last_trim >= TRIM_EVERY:
            last_trim = time.monotonic()
            self._housekeeping()
        return last_trim

    def _forget_now(self, drained: bool) -> None:
        """The rows of devices taken off the wall go: those in the file now, and those still in the queue when they come.

        `drained`: this turn emptied the queue, and whatever was noted of a device before it was forgotten (before the
        turn began) has come and gone; what is forgotten from here on is skipped in the queue until it is emptied again.
        """
        with self._forgetting:
            ids, self._forgotten = self._forgotten, []
        skipping = set() if drained else self._skipping
        self._skipping = skipping | set(ids)
        conn = self._conn
        if not ids:
            return
        try:
            if conn is None:  # (closed in this turn: a file that went bad. Done in the fresh one, where it changes nothing.)
                raise _NotNow
            try:
                for device in ids:  # (so many rows at a time, as a trim deletes them: a machine with a long history has many)
                    for table in ("states", "samples", "events"):
                        self._delete_rows(conn, table, device, None)
                conn.executemany("DELETE FROM devices WHERE device = ?", [(device,) for device in ids])
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                self._gone = 0
        except Exception as ex:
            with self._forgetting:
                self._forgotten[:0] = ids  # tried again at the next turn: a machine taken off the wall is never left in its history
            if isinstance(ex, sqlite3.OperationalError):
                self._say("forget", "the history of machines taken off the wall could not be deleted yet (%s): it is tried again", ex)
            elif _damaged(ex):
                self._close()
                self._move_aside(str(ex))
            elif not isinstance(ex, _NotNow):
                raise

    def _drop_all(self) -> None:
        while True:
            try:
                self._waiting.get_nowait()
            except queue.Empty:
                return
            self.dropped += 1
            self._waiting.task_done()

    def _open(self) -> None:
        """Open the file, making it where there is none; move aside one that cannot be read, and start afresh."""
        self._ready.clear()
        for attempt in (1, 2):
            try:
                conn = sqlite3.connect(self.path, timeout=WRITE_PATIENCE, isolation_level="DEFERRED")
            except sqlite3.Error as ex:
                self._say("open", "the history in %s could not be opened: %s", self.path.parent, ex)
                return
            try:
                self._prepare(conn, at_start=not self._opened_once)
            except sqlite3.OperationalError as ex:
                # The disk, or the folder: not the file's fault. Nothing is moved aside for that.
                conn.close()
                self._say("open", "the history in %s could not be opened: %s", self.path.parent, ex)
                return
            except Exception as ex:
                conn.close()
                if not _damaged(ex):
                    # A slip of this program's own: not the file's fault either. Said with the traceback, and tried again in a while.
                    self._said_with_traceback("open", "the history in %s could not be opened", self.path.parent)
                    return
                if attempt == 2 or not self._move_aside(str(ex)):
                    self._say("open", "the history in %s could not be opened: %s", self.path.parent, ex)
                    return
                continue
            self._conn = conn
            self._opened_once = True
            self._ready.set()
            return

    def _prepare(self, conn: sqlite3.Connection, at_start: bool = True) -> None:
        """Have the file hold the tables, as this program makes them. _Unreadable, or a DatabaseError that says the file
        is damaged, where it cannot be read.

        `at_start`: this is the program's start, and whatever the file says was being watched is not any more.
        """
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > VERSION:
            raise _Unreadable(f"written by a later version of qKVM (its tables are version {version}, this program's are {VERSION})")
        deadline = time.monotonic() + OPEN_PATIENCE
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            verdict = conn.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.OperationalError as ex:
            if "interrupted" not in str(ex):
                raise
            verdict = "ok"  # (not checked to the end: a large file on a slow disk. Taken as it is; what is wrong with it is met where it is.)
            log.warning("the history could not be checked within %d s at this start, and is used as it is", int(OPEN_PATIENCE))
        finally:
            conn.set_progress_handler(None, 0)
        if verdict != "ok":
            raise _Unreadable(f"quick_check: {_short(verdict, 120)}")
        if version == 0:
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL")  # before the first table: pages freed by a trim can then be given back
        conn.execute("PRAGMA journal_mode = WAL")  # readers do not wait for the writer, nor it for them
        conn.execute("PRAGMA synchronous = NORMAL")  # a power cut may lose the last moments, never the file
        self._limit_wal(conn)
        with conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {VERSION}")
            # Whatever was being watched when the program last ran stopped being watched then: from its last
            # look on, until it is seen again. (A program that ended cleanly wrote down its last looks; one
            # that was cut off wrote them down within the minute before.) Not where the file is only opened
            # anew while the program runs: the machines are watched as before, and the rows go on.
            if at_start:
                self._unwatch(conn, conn.execute("SELECT device, looked, state_at FROM devices WHERE state IS NOT NULL AND state != ?", (UNWATCHED,)).fetchall())
        if version == 0:
            log.info("the history is kept in %s", self.path)

    @staticmethod
    def _unwatch(conn: sqlite3.Connection, rows: list[Any]) -> None:
        for device, looked, state_at in rows:
            at = max(looked or 0.0, (state_at or 0.0) + 0.001)  # (after the row that says what it was: never in its place)
            conn.execute("INSERT OR REPLACE INTO states (device, t, state, code) VALUES (?, ?, ?, '')", (device, at, UNWATCHED))
            conn.execute("UPDATE devices SET state = ?, state_at = ? WHERE device = ?", (UNWATCHED, at, device))

    def _move_aside(self, why: str) -> bool:
        """Put a file that cannot be read beside the new one, for somebody to look at. False where even that cannot be done.

        Named by the second it was moved aside, which is what its removal goes by (its own time is when it was last
        written, which may be long before), and by a number after that where another was moved aside in that second.
        """
        moved_at = int(time.time())
        aside = self.path.with_name(f"history.damaged-{moved_at}.sqlite")
        for number in itertools.count(2):
            if not any(aside.with_name(aside.name + tail).exists() for tail in ("", "-wal", "-shm")):
                break
            aside = self.path.with_name(f"history.damaged-{moved_at}-{number}.sqlite")
        try:
            os.replace(self.path, aside)
            for tail in ("-wal", "-shm"):  # what belongs to the old file goes with it; left here, it would be taken for the new one's
                old = self.path.with_name(self.path.name + tail)
                if old.exists():
                    os.replace(old, aside.with_name(aside.name + tail))
        except OSError as ex:
            log.error("the history could not be read (%s), and could not be moved aside either: %s", why, ex.strerror or ex)
            return False
        self.damaged = aside
        log.error("the history could not be read (%s): it was moved aside as %s, and a new one is started", why, aside.name)
        return True

    def _write(self, rows: list[tuple[Any, ...]]) -> None:
        conn = self._conn
        if conn is None:
            self.dropped += len(rows)
            return
        try:
            with conn:
                for row in rows:
                    if row[0] in _OF_A_DEVICE and row[1] in self._skipping:
                        continue  # (noted before its device was taken off the wall, and written after: it would be there for good)
                    self._write_one(conn, row)
        except sqlite3.OperationalError as ex:
            # The disk is full, or refuses for the moment: these rows are lost, the file is kept, the next ones are tried.
            self.dropped += len(rows)
            self._say("write", "the history could not be written (%s): %d rows are missing since the start", ex, self.dropped)
        except Exception as ex:
            self.dropped += len(rows)
            self._close()
            if _damaged(ex):
                # The file itself: moved aside, and a fresh one started at the next row.
                self._move_aside(str(ex))
            else:
                # A slip of this program's own, met in the thread that writes (a row of a shape the tables refuse is one,
                # and no damage): these rows are lost and counted, the file is closed and opened anew at the next rows,
                # and the log says so with the traceback, once a minute. Left to end the thread, it took the history
                # with it until the next start, silently.
                self._said_with_traceback("writer", "the history's writer failed, and starts afresh")

    def _close(self) -> None:
        self._ready.clear()
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    @staticmethod
    def _write_one(conn: sqlite3.Connection, row: tuple[Any, ...]) -> None:
        kind = row[0]
        if kind == "state":
            _, device, t, state, code = row
            conn.execute("INSERT OR REPLACE INTO states (device, t, state, code) VALUES (?, ?, ?, ?)", (device, t, state, code))
            conn.execute(
                "INSERT INTO devices (device, first_seen, looked, state, state_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (device) DO UPDATE SET looked = excluded.looked, state = excluded.state, state_at = excluded.state_at",
                (device, t, t, state, t),
            )
        elif kind == "seen":
            _, device, t, last_seen, _state = row
            conn.execute(
                "INSERT INTO devices (device, first_seen, last_seen, looked) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (device) DO UPDATE SET looked = excluded.looked, last_seen = COALESCE(excluded.last_seen, devices.last_seen), first_seen = COALESCE(devices.first_seen, excluded.first_seen)",
                (device, t, last_seen, t),
            )
        elif kind == "sample":
            _, device, t, sensor, value, unit = row
            conn.execute("INSERT OR REPLACE INTO samples (device, t, sensor, value, unit) VALUES (?, ?, ?, ?, ?)", (device, t, sensor, value, unit))
        elif kind == "event":
            _, device, t, what_kind, what, ok, note = row
            conn.execute("INSERT INTO events (device, t, kind, what, ok, note) VALUES (?, ?, ?, ?, ?, ?)", (device, t, what_kind, what, ok, note))
        elif kind == "power":
            _, device, t, what = row
            # A change from what was last seen, across a restart too: the first look after a start is not a change.
            before = conn.execute("SELECT power FROM devices WHERE device = ?", (device,)).fetchone()
            if before is None:
                conn.execute("INSERT INTO devices (device, power) VALUES (?, ?)", (device, what))
            elif before[0] != what:
                if before[0] is not None:
                    conn.execute("INSERT INTO events (device, t, kind, what, ok, note) VALUES (?, ?, 'power', ?, 1, '')", (device, t, what))
                conn.execute("UPDATE devices SET power = ? WHERE device = ?", (what, device))
        elif kind == "unwatched":
            _, device, looked = row
            found = conn.execute("SELECT looked, state_at FROM devices WHERE device = ? AND state IS NOT NULL AND state != ?", (device, UNWATCHED)).fetchone()
            if found is not None:
                History._unwatch(conn, [(device, max(looked, found[0] or 0.0), found[1])])
        elif kind == "looked":
            (_, looks) = row
            conn.executemany("UPDATE devices SET looked = ? WHERE device = ?", [(t, device) for device, t in looks.items()])
        # ("forget",) only wakes the writer, which takes what is forgotten from a list of its own (see _forget_now);
        # ("housekeeping",) and ("checkpoint",) are done once the rows with them are written (see _round).

    def _housekeeping(self) -> None:
        conn = self._conn
        if conn is None:
            return
        try:
            self._limit_wal(conn)  # (the size allowed may have been changed meanwhile)
            self._trim(conn)
            self._checkpoint()
        except sqlite3.OperationalError as ex:
            self._say("trim", "the history could not be trimmed: %s", ex)
        except Exception as ex:
            if _damaged(ex):
                self._close()
                self._move_aside(str(ex))
                return
            # A slip of this program's own in the trim: said with the traceback, and the file kept as it is, open; the
            # next trim is at its time. (Closed and opened anew, it was trimmed again at once, and met the slip again.)
            self._said_with_traceback("trim", "the history could not be trimmed, and is kept as it is")
            try:
                if conn.in_transaction:
                    conn.rollback()
            except sqlite3.Error:
                pass

    def _wal_most(self) -> int:
        """Bytes the -wal file may take: a share of the size allowed, which the file itself is trimmed to leave free."""
        return min(WAL_MOST, self.limits()[1] * 1_000_000 // 10)

    def _limit_wal(self, conn: sqlite3.Connection) -> None:
        # What SQLite leaves of the -wal file once everything in it is in the file and it begins again from the start.
        conn.execute(f"PRAGMA journal_size_limit = {self._wal_most()}").fetchall()

    def _hold_wal(self, most: int | None = None, now: bool = False) -> bool:
        """Once the -wal file has grown past its share of the size allowed (or `most` bytes), what is in it goes into the file.

        SQLite brings it in by itself every thousand pages, but cannot begin it again from the start while reads that
        began before are under way; reads that overlap, one beginning before the other ends, kept it growing for as long
        as they came (98 MB in two and a half minutes, with a cap of 10 MB). The checkpoint here waits for them.
        False where the -wal file is past that and stays so (a checkpoint did not get through, now or a moment ago, unless
        `now`: tried all the same); a trim under way then stops deleting and giving back (_stalled), which would only grow
        the -wal file.
        """
        if self._conn is None:
            return False
        try:
            size = self.path.with_name(self.path.name + "-wal").stat().st_size
        except OSError:
            return True
        if size <= (self._wal_most() if most is None else most):
            return True
        due = now or time.monotonic() >= self._wal_again or (self._wal_retry_at and size >= self._wal_retry_at)
        if due and self._checkpoint():
            return True
        if self._until is not None:
            self._stalled = True
        return False

    def _checkpoint(self) -> bool:
        """What is in the -wal file goes into the file itself, and the -wal file is emptied: a copy of the one file is then whole.

        Waits for the reads under way to end (CHECKPOINT_PATIENCE, which is longer than any read may take). False where
        it did not get through. Then it is tried again after CHECKPOINT_AGAIN, or once the -wal file has grown to twice
        what it was, whichever comes first, so that one refusal does not let it grow for a minute unchecked; and at the
        next look where another connection's checkpoint of the file turned it away, which SQLite says with the row
        (1, -1, -1), at once. (Not by the time it took: an error that keeps coming, a full disk, comes at once as well, and
        was tried at every batch.)
        """
        conn = self._conn
        if conn is None:
            return False
        began = time.monotonic()
        try:
            conn.execute(f"PRAGMA busy_timeout = {int(CHECKPOINT_PATIENCE * 1000)}").fetchall()
            try:
                busy, wal_frames, done_frames = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            finally:
                conn.execute(f"PRAGMA busy_timeout = {int(WRITE_PATIENCE * 1000)}").fetchall()
        except sqlite3.OperationalError as ex:
            busy, wal_frames, done_frames = 1, None, None
            why = f"{ex} (code {getattr(ex, 'sqlite_errorcode', None)})"
        else:
            why = f"it says {(busy, wal_frames, done_frames)}: the file is held by a read or a checkpoint of another connection"
        took = time.monotonic() - began
        if busy:
            try:
                size = self.path.with_name(self.path.name + "-wal").stat().st_size
            except OSError:
                size = 0
            turned_away = wal_frames == -1 and done_frames == -1  # (another checkpoint under way: SQLite does not wait for it)
            self._wal_again = time.monotonic() + (0.0 if turned_away else CHECKPOINT_AGAIN)
            self._wal_retry_at = 2 * max(size, self._wal_most())
            self._say("checkpoint", "the history's file could not be brought up to date from its -wal file (%.1f s): %s", took, why)
            return False
        self._wal_again, self._wal_retry_at = 0.0, 0
        return True

    def limits(self) -> tuple[int, int]:
        """How long and how large, as the settings say, held to what makes sense: nothing or less than nothing is the default."""
        try:
            days, megabytes = (int(each) for each in self._limits())
        except (TypeError, ValueError, ArithmeticError):
            days, megabytes = DEFAULT_DAYS, DEFAULT_MB
        days = DEFAULT_DAYS if days <= 0 else min(MOST_DAYS, max(LEAST_DAYS, days))
        megabytes = DEFAULT_MB if megabytes <= 0 else min(MOST_MB, max(LEAST_MB, megabytes))
        return days, megabytes

    def _trim(self, conn: sqlite3.Connection) -> None:
        """Rows older than the settings allow go; then the oldest go until the file is as small as they allow.

        As small as they allow is the size allowed less the -wal file's share (_wal_most), which checkpoints hold it to:
        what the history takes on the disk is the two together. Within TRIM_PATIENCE: the rows by age within the first
        half of it, the rows by size within the rest and never less than half of it (a deletion by age that took all of
        it kept the size from ever being looked at), each a transaction's worth at the least; what is left over goes at
        the next trim, and the writer gets on with the rows meanwhile. Not at all where the -wal file is past its share and
        cannot be brought into the file (something outside qKVM holds a read open): every deletion would grow it, trim
        after trim. And a file that was moved aside as damaged goes once it was moved aside longer ago than the rows are
        kept: it was left for somebody to look at, and nobody comes for it after that.
        """
        days, megabytes = self.limits()
        room = megabytes * 1_000_000 - self._wal_most()
        began = time.monotonic()
        self._until, self._stalled = began + TRIM_PATIENCE / 2, False
        try:
            self._forget_damaged(days)
            if not self._hold_wal(self._wal_most() // 4, now=True):
                return  # (stalled: see above. Tried at once, whenever the last try was: the read outside may have ended.)
            self._delete_before(conn, time.time() - days * DAY)
            self._until = max(began + TRIM_PATIENCE, time.monotonic() + TRIM_PATIENCE / 2)
            for turn in itertools.count():
                if self._stalled or (turn and time.monotonic() > self._until):
                    break
                # What the rows take: the pages that hold something. (Not the pages the file has: where a disk that was
                # full kept the freed ones from being given back, every trim deleted another share, and nothing shrank.)
                held = self._held(conn)
                if held <= room:
                    break
                cutoff = self._cutoff(conn, 1 - 0.9 * room / held)
                if cutoff is None:
                    break
                before = conn.total_changes
                self._delete_before(conn, cutoff)
                if conn.total_changes == before:
                    break  # (nothing could go: rows that are kept whatever their age)
                self._give_back(conn)
            self._give_back(conn)  # (and what an earlier trim could not give back)
        finally:
            self._until = None

    @staticmethod
    def _held(conn: sqlite3.Connection) -> int:
        page_count, free, page_size = (conn.execute(f"PRAGMA {name}").fetchone()[0] for name in ("page_count", "freelist_count", "page_size"))
        return int((page_count - free) * page_size)

    @staticmethod
    def _holding_rows(conn: sqlite3.Connection) -> tuple[list[str], set[str]]:
        """(every device the file holds rows of, those of them on the wall), each table read by its own order, a look a device.

        Beside those on the wall: strays, of which the file has no devices row (forgotten before this version kept them
        apart, or whose first row found the queue full). They go by age and by size as the others do, and keep no state.
        """
        found: set[str] = set()
        for table in ("samples", "events", "states"):
            device = conn.execute(f"SELECT MIN(device) FROM {table}").fetchone()[0]
            while device is not None:
                found.add(device)
                after = conn.execute(f"SELECT device FROM {table} WHERE device > ? ORDER BY device LIMIT 1", (device,)).fetchone()
                device = None if after is None else after[0]
        on_wall = {row[0] for row in conn.execute("SELECT device FROM devices").fetchall()}
        return sorted(found), on_wall

    @staticmethod
    def _cutoff(conn: sqlite3.Connection, share: float) -> float | None:
        """The time before which the oldest `share` of the rows that may go lies. None where there are none.

        Counted, not taken from the time they span: the rows are seldom spread evenly (a wall that had a hundred machines
        and has twenty, sensors taken at another pace since an upgrade), and a cut by the span alone, with the older rows
        denser, deleted three times the history it had to. They are counted by the hundredth of the span, and again by the
        hundredth of the hundredth where the cut falls, until what the cut takes beyond its share is a tenth of what is to
        stay at the most (or a second of time): a hundredth taken whole deleted all but 40 rows of 216,000 where the newest
        hours held nearly all of them. Each device by its own order (device, time), never by a scan of a whole table but
        the first count. Of the rows that can go: a device's newest state row stays, and must not anchor the span.
        """
        devices, on_wall = History._holding_rows(conn)
        ranges: list[tuple[str, str, str, tuple[Any, ...]]] = []  # (table, device, a further condition, its value)
        for device in devices:
            ranges.append(("samples", device, "", ()))
            ranges.append(("events", device, "", ()))
            newest_state = conn.execute("SELECT MAX(t) FROM states WHERE device = ?", (device,)).fetchone()[0]
            if newest_state is not None:
                ranges.append(("states", device, " AND t < ?", (newest_state,)) if device in on_wall else ("states", device, "", ()))
        oldest = newest = None
        for table, device, more, values in ranges:
            for which in ("MIN", "MAX"):  # (one each: the two together are a scan of the device's rows, each alone a look)
                found = conn.execute(f"SELECT {which}(t) FROM {table} WHERE device = ?{more}", (device, *values)).fetchone()[0]
                if found is not None:
                    oldest = found if oldest is None or found < oldest else oldest
                    newest = found if newest is None or found > newest else newest
        if oldest is None or newest is None or newest <= oldest:
            return None
        start = low = float(oldest)
        high, last = float(newest), True  # [low, high), and high itself where `last`
        going: float | None = None
        stay = 0.0
        parts = 100
        while True:
            width = (high - low) / parts
            counts = [0] * parts
            for table, device, more, values in ranges:
                upto = " AND t <= ?" if last else " AND t < ?"
                for part, count in conn.execute(
                    f"SELECT MIN(CAST((t - ?) / ? AS INTEGER), ?) AS part, COUNT(*) FROM {table} WHERE device = ? AND t >= ?{upto}{more} GROUP BY part",
                    (low, width, parts - 1, device, low, high, *values),
                ):
                    counts[max(0, part)] += count
            if going is None:
                total = sum(counts)
                going = total * min(1.0, max(0.0, share))
                stay = total - going
            part, gone = 0, 0
            while part < parts - 1 and gone + counts[part] < going:
                gone += counts[part]
                part += 1
            end = high if part == parts - 1 else low + width * (part + 1)
            if gone + counts[part] - going <= max(1.0, 0.1 * stay) or width <= 1.0:
                return max(end, start + 60)
            low, high, last, going = low + width * part, end, last and part == parts - 1, going - gone

    def _give_back(self, conn: sqlite3.Connection) -> None:
        """Pages the rows no longer use go back to the system, a share of the -wal file's at a time.

        Every page moved passes through the -wal file while the file is still as large as it was: given back all at
        once, the two together took nine megabytes more than the size allowed. A step at a time, with a checkpoint
        between them, the -wal file stays within its share; where the checkpoint does not get through, the rest waits
        for the next trim. (The pragma is run by `executescript`, which steps it to its end on every Python: `execute`
        steps it once, and `execute(...).fetchall()` does no more on 3.11, a pragma with no columns being stepped once.)
        """
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        most = self._wal_most() // 4
        step = max(16, most // page_size // 2)  # (a page given back writes one and a half into the -wal file, measured)
        while not self._stalled:
            free = conn.execute("PRAGMA freelist_count").fetchone()[0]
            if not free:
                return
            conn.executescript(f"PRAGMA incremental_vacuum({step});")
            if not self._hold_wal(most) or conn.execute("PRAGMA freelist_count").fetchone()[0] >= free:
                return  # (a checkpoint that did not get through, or a file that gives nothing back)
            if self._until is not None and time.monotonic() > self._until:
                return

    def _forget_damaged(self, days: int) -> None:
        cutoff = time.time() - days * DAY
        for path in self.path.parent.glob("history.damaged-*.sqlite*"):
            # By the second it was moved aside, which its name says. A name that says none is not one this program gave.
            named = _ASIDE.fullmatch(path.name)
            if named is None or int(named[1]) >= cutoff:
                continue
            try:
                path.unlink()
                log.info("removed %s from the data folder: a history that could not be read, moved aside longer ago than the history is kept", path.name)
            except OSError:
                pass

    def _delete_before(self, conn: sqlite3.Connection, cutoff: float) -> None:
        """The rows of every device older than `cutoff` go, in transactions of a bounded size (see _delete_rows).

        Within the trim's time (_stopped), and a transaction's worth at the least: each trim gets on, however slow the disk.
        Where the cut is long (more than SLICES trims' worth of time), it is made in SLICES steps of time, every device to
        the first, then every device to the next: a trim whose time ran out had cut the devices that sort first to the end,
        and none of the others, and the oldest rows were not the ones that went first.
        """
        devices, on_wall = self._holding_rows(conn)
        self._done_some = False
        oldest = None
        for device in devices:
            for table in ("samples", "events"):  # (not the states: the one each device keeps before a cut is old for good)
                found = conn.execute(f"SELECT MIN(t) FROM {table} WHERE device = ?", (device,)).fetchone()[0]
                oldest = found if found is not None and (oldest is None or found < oldest) else oldest
        edges = [cutoff]
        if oldest is not None and cutoff - oldest > SLICES * TRIM_EVERY:
            edges = [oldest + (cutoff - oldest) * step / SLICES for step in range(1, SLICES)] + [cutoff]
        try:
            for edge in edges:
                for device in devices:
                    if self._stopped():
                        break
                    # (Each device by itself: the rows are kept by device and time, and that is how they are found.)
                    self._delete_rows(conn, "samples", device, edge)
                    self._delete_rows(conn, "events", device, edge)
                    # The newest state row before the cutoff stays: it says what the device was at the start of a window
                    # that begins after the cutoff, and without it that time is nothing, not "online since". (The rule was
                    # its newest state row at all: a machine online for a hundred days that changed an hour ago was then
                    # watched for one hour of the week, where it was for all of it.) A stray's go: nobody reads them.
                    kept = conn.execute("SELECT MAX(t) FROM states WHERE device = ? AND t < ?", (device, edge)).fetchone()[0] if device in on_wall else edge
                    if kept is not None:
                        self._delete_rows(conn, "states", device, kept)
                if self._stopped():
                    break
            conn.commit()
        except BaseException:
            conn.rollback()  # (what was committed before stays gone: old rows, which go at the next trim anyway)
            raise
        finally:
            self._gone = 0
        self._hold_wal(self._wal_most() // 4)  # (before the pages are given back: what the last transaction wrote)

    def _stopped(self) -> bool:
        """A trim that is to stop deleting: the -wal file could not be brought into the file, or its time is over and a
        transaction's worth was deleted in this round."""
        return self._until is not None and (self._stalled or (self._done_some and time.monotonic() > self._until))

    def _rows_at_once(self) -> int:
        # Rows deleted in one transaction, at the least: what a quarter of the -wal file's share holds, at some sixty-four
        # bytes a row (measured: 30 for samples written in one go, 45 to 65 for those a wall writes). A transaction holds up
        # to twice that: the rows before it reached it, and one more lot.
        return max(1000, self._wal_most() // 4 // 64)

    def _delete_rows(self, conn: sqlite3.Connection, table: str, device: str, before: float | None) -> None:
        """Rows of one device older than `before` (None: all of them) go, so many at a time (_rows_at_once).

        Every page a deletion touches passes through the -wal file while the file is as large as it was: half of a file
        of 19 MB deleted in one transaction put 9.6 MB beside it, past the size allowed. Between two transactions the
        -wal file is brought into the file (_hold_wal). The oldest first, found by the rows' own order (device, time).
        A trim stops where it is to (_stopped); a machine taken off the wall is deleted to the end.
        """
        older, given = ("", ()) if before is None else (" AND t < ?", (before,))
        at_once = self._rows_at_once()
        while not self._stopped():
            # The time of the row after the first so many: whatever is older than it is one transaction's worth.
            edge = conn.execute(f"SELECT t FROM {table} WHERE device = ?{older} ORDER BY t LIMIT 1 OFFSET ?", (device, *given, at_once)).fetchone()
            if edge is None:
                self._some_gone(conn, conn.execute(f"DELETE FROM {table} WHERE device = ?{older}", (device, *given)).rowcount)
                return
            gone = conn.execute(f"DELETE FROM {table} WHERE device = ? AND t < ?", (device, edge[0])).rowcount
            if not gone:  # (more rows than that of one moment, which only events can have: that moment's, all of them)
                gone = conn.execute(f"DELETE FROM {table} WHERE device = ? AND t <= ?", (device, edge[0])).rowcount
            self._some_gone(conn, gone)

    def _some_gone(self, conn: sqlite3.Connection, rows: int) -> None:
        self._gone += max(0, rows)
        if self._gone >= self._rows_at_once():
            conn.commit()
            self._gone, self._done_some = 0, True
            # (What is left below it, and a transaction: three quarters of the share.) Where the checkpoint does not get
            # through, a trim stops deleting (_hold_wal): it would only grow the -wal file.
            self._hold_wal(self._wal_most() // 4)

    # --- reading: for a worker thread, never for the event loop ------------------------------------------

    def read(self, device_id: str, what: str, since: float, until: float, limit: int = 1000, every: int = 0, now: float | None = None) -> dict[str, Any]:
        """What the history says of one device, in [since, until]: see WHAT. Waits for the disk: for a worker thread.

        `limit`: rows at the most (a cut page says `more`). `every`: samples averaged over spans of that many seconds.
        NotReadable where the file cannot be read just now.
        """
        if what not in WHAT:
            raise ValueError(f"not something the history is asked for: {what!r}")
        now = time.time() if now is None else now
        limit = max(1, min(MOST_ROWS, limit))
        if not self._ready.wait(READ_WAIT):
            raise NotReadable("The history is not open just now. Try again in a moment.")
        try:
            conn = sqlite3.connect(read_only_uri(self.path), uri=True, timeout=2.0)  # (a data folder on a share too: see there)
        except sqlite3.Error as ex:
            raise NotReadable(f"The history could not be read ({_short(str(ex), 80)}). Try again in a moment.") from None
        deadline = time.monotonic() + READ_PATIENCE
        try:
            conn.execute("PRAGMA query_only = 1")
            conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
            if what == "summary":
                return self._summary(conn, device_id, since, until, now)
            if what == "states":
                rows = conn.execute("SELECT t, state, code FROM states WHERE device = ? AND t >= ? AND t <= ? ORDER BY t LIMIT ?", (device_id, since, until, limit + 1)).fetchall()
                return {"since": since, "until": until, "rows": [{"t": t, "state": state, "code": code} for t, state, code in rows[:limit]], "more": len(rows) > limit}
            if what == "events":
                rows = conn.execute("SELECT t, kind, what, ok, note FROM events WHERE device = ? AND t >= ? AND t <= ? ORDER BY t LIMIT ?", (device_id, since, until, limit + 1)).fetchall()
                return {"since": since, "until": until, "rows": [{"t": t, "kind": kind, "what": what_, "ok": None if ok is None else bool(ok), "note": note} for t, kind, what_, ok, note in rows[:limit]], "more": len(rows) > limit}
            if every > 0:
                # One series per sensor, its spans in order, the sensors one after the other: a page that is cut loses
                # whole sensors at its end and never the newest hours of every sensor. (`limit` counts the points.)
                rows = conn.execute(
                    "SELECT sensor, unit, CAST((t - ?) / ? AS INTEGER) AS span, AVG(value), MIN(value), MAX(value) FROM samples "
                    "WHERE device = ? AND t >= ? AND t <= ? GROUP BY sensor, unit, span ORDER BY sensor, unit, span LIMIT ?",
                    (since, float(every), device_id, since, until, limit + 1),
                ).fetchall()
                page = rows[:limit]
                if len(rows) > limit and page[-1][:2] == rows[limit][:2]:
                    # The cut fell inside a sensor's series: that sensor is left out, and not handed over with its oldest
                    # spans and without its newest. (The only one there was, too: `since` and `until` are narrowed then.)
                    page = [row for row in page if row[:2] != rows[limit][:2]]
                series: list[dict[str, Any]] = []
                for sensor, unit, span, value, low, high in page:
                    if not series or series[-1]["sensor"] != sensor or series[-1]["unit"] != unit:
                        series.append({"sensor": sensor, "unit": unit, "points": []})
                    series[-1]["points"].append([since + span * every, value, low, high])
                return {"since": since, "until": until, "every": every, "series": series, "more": len(rows) > limit}
            rows = conn.execute("SELECT t, sensor, unit, value FROM samples WHERE device = ? AND t >= ? AND t <= ? ORDER BY t, sensor LIMIT ?", (device_id, since, until, limit + 1)).fetchall()
            found = [{"t": t, "sensor": sensor, "unit": unit, "value": value} for t, sensor, unit, value in rows[:limit]]
            return {"since": since, "until": until, "every": 0, "rows": found, "more": len(rows) > limit}
        except sqlite3.Error as ex:
            said = "took too long" if "interrupted" in str(ex) else _short(str(ex), 80)
            raise NotReadable(f"The history could not be read ({said}). Try again in a moment.") from None
        finally:
            conn.close()

    @staticmethod
    def _summary(conn: sqlite3.Connection, device_id: str, since: float, until: float, now: float) -> dict[str, Any]:
        """How much of [since, until] the device was watched, and online; when it was first and last heard from."""
        found = conn.execute("SELECT first_seen, last_seen, state, power FROM devices WHERE device = ?", (device_id,)).fetchone()
        before = conn.execute("SELECT state FROM states WHERE device = ? AND t < ? ORDER BY t DESC LIMIT 1", (device_id, since)).fetchone()
        spent: dict[str, float] = {}
        state, at, changes = (before[0] if before else UNWATCHED), since, 0
        for t, next_state in conn.execute("SELECT t, state FROM states WHERE device = ? AND t >= ? AND t <= ? ORDER BY t", (device_id, since, until)):
            spent[state] = spent.get(state, 0.0) + (t - at)
            state, at, changes = next_state, t, changes + 1
        end = min(until, now)
        if end > at:
            spent[state] = spent.get(state, 0.0) + (end - at)
        watched = sum(seconds for name, seconds in spent.items() if name != UNWATCHED)
        online = spent.get("online", 0.0)
        answering = sum(spent.get(name, 0.0) for name in ANSWERING)
        events = conn.execute("SELECT COUNT(*) FROM events WHERE device = ? AND t >= ? AND t <= ?", (device_id, since, until)).fetchone()[0]
        sensors = conn.execute("SELECT DISTINCT sensor FROM samples WHERE device = ? AND t >= ? ORDER BY sensor LIMIT ?", (device_id, now - DAY, MOST_SENSORS)).fetchall()
        return {
            "since": since,
            "until": until,
            "first_seen": found[0] if found else None,
            "last_seen": found[1] if found else None,
            "state": found[2] if found else None,
            "power": found[3] if found else None,
            "watched": round(watched),
            "online": round(online),
            "answering": round(answering),
            "share": online / watched if watched > 0 else None,
            "answering_share": answering / watched if watched > 0 else None,
            "changes": changes,
            "events": events,
            "sensors": [row[0] for row in sensors],
        }


def size_of(folder: Path) -> int:
    """How many bytes the history takes in `folder`: its file, and what is not yet in it. Only looks; 0 where there is none."""
    total = 0
    for name in (FILE, FILE + "-wal"):
        try:
            total += (folder / name).stat().st_size
        except OSError:
            pass
    return total


def aside_in(folder: Path) -> tuple[int, int]:
    """(how many, how many bytes) of the histories that were moved aside as damaged in `folder`. Only looks."""
    count, total = 0, 0
    for path in folder.glob("history.damaged-*.sqlite"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
        count += 1
    return count, total


def said_size(size: int) -> str:
    """'12 MB', '340 kB', '0 bytes': for `qkvm status`."""
    if size >= 1_000_000:
        return f"{size / 1_000_000:.0f} MB" if size >= 10_000_000 else f"{size / 1_000_000:.1f} MB"
    if size >= 1000:
        return f"{size / 1000:.0f} kB"
    return f"{size} bytes"
