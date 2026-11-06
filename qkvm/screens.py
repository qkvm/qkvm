"""Screen watching: an alert where a machine has had no video signal for some minutes, or its screen has not changed.

Two watches, set per machine on its tile (minutes; 0 is off), told through the alerts (alerts.py) as the changes of state
are, each with the picture that set it off kept beside it, and each with a "back to normal" when it is over:

* No signal for N minutes: from the device's own signal flag, as the alert round sees it (the state "no_signal", settled
  over two looks: alerts.Watcher). Where a machine has this watch, the round's own "no video signal" and "a picture again"
  are left to the watch: told after N minutes, not after half a minute.
* Screen unchanged for N minutes (opt-in): from the pictures the wall gets anyway, as the tiles and views ask for them. No
  session is opened and nothing is asked of a device for it: where nobody has the machine's tile on a screen, there is
  nothing to compare, and nothing is said. Each picture compared is shrunk to 64 by 36 squares, each the average
  brightness (0 to 255) of its part of the screen; a picture counts as changed where at least SQUARES squares differ by
  more than LEVELS from the first picture of the run. So the noise of a capture and of JPEG does not count, and a moving
  pointer, a clock that ticks, a line of text does. "Unchanged" is not "hung": a screen nobody uses looks the same too,
  and a hung machine whose cursor blinks has a screen that changes.

What it costs: nothing for a machine without the watch. For one with it, at most one picture every look of the alert
round (fifteen seconds), only where a new one came: decoded in the video worker (a process of its own, without the
saved passwords, as every picture a device sends is, video.py; one such process while any machine has the watch), and
shrunk here in a thread, sampling up to LINES lines of each row of squares: a few hundredths of a second of one core for a
picture of 1920 by 1080, less for a tile's. A JPEG is compared; a PNG (a placeholder of no signal) is not.

The pictures kept (FOLDER in the data folder, the owner's alone): the last one per machine, replaced by the next alert's,
deleted after KEEP_DAYS days and when the machine leaves the wall. The activity log's entry of the alert names it by a
number (its stamp), and the wall hands it to whoever may see that machine. Which alerts stand is written down (FILE), so
that "back to normal" is told after a restart as well.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._folders import own_folder, private
from .kvm import Snapshot, picture_size

log = logging.getLogger("qkvm")

NO_SIGNAL, UNCHANGED = "no_signal", "unchanged"
WATCHES = (NO_SIGNAL, UNCHANGED)
MOST_MINUTES = 1440  # the longest a watch can be set to wait: a day
MINUTE = 60.0  # seconds in a minute (the tests make it shorter)
GAP_MINUTES = 11  # where no new picture came for longer than this, the run of "unchanged" starts again with the next one
GRID = (64, 36)  # squares across and down a picture is shrunk to
LEVELS = 10  # how far of 255 a square's brightness may move and still be the same
SQUARES = 2  # how many squares that moved further make a picture another one
LINES = 10  # lines of a row of squares that are read, at the most (spread over it)
MOST_PIXELS = 3840 * 2160  # a larger picture is not compared
ROUND_MOST = 10.0  # seconds of comparing in one round of the alerts, at the most; what is left waits for the next
KEEP_DAYS = 30  # how long a picture is kept, at the most
DAY = 86400.0
SWEEP_EVERY = 3600.0  # seconds between two looks through the kept pictures for old ones
FOLDER = "alert-pictures"
FILE = "screens.json"
MOST_KEPT = 10_000  # machines whose standing alerts are taken up from what was written down
MOST_PICTURE = 32 * 1024 * 1024  # bytes of a kept picture that are read back, at the most
TRY_AGAIN = 60.0  # seconds before what could not be written down is tried again, where nothing has changed since
STAMP = re.compile(r"[0-9]{1,16}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")  # (a tile's id, as store._ID)
_KINDS = {"image/jpeg": "jpg", "image/png": "png"}  # what is kept, by the file's last part
_TYPES = {ending: kind for kind, ending in _KINDS.items()}


def minutes(value: Any) -> int:
    """How long a watch waits, from what a tile keeps: 0 (off) for what is no whole number above 0, MOST_MINUTES at the most."""
    if type(value) is not int or value <= 0:
        return 0
    return min(value, MOST_MINUTES)


def fingerprint(rgb: bytes | memoryview, width: int, height: int) -> bytes:
    """A picture as GRID squares, each the average brightness of its part of the screen (R, G and B alike), 0 to 255.

    Up to LINES lines of each row of squares are read, spread over it: a picture of 1920 by 1080 is read on 360 of its
    lines, one of 640 by 360 on all of them. Each line is summed in GRID[0] pieces, which Python does in C."""
    across, down = GRID
    line = width * 3
    view = memoryview(rgb)
    edges = [(x * width // across) * 3 for x in range(across + 1)]
    squares = bytearray(across * down)
    for row in range(down):
        top, bottom = row * height // down, max((row + 1) * height // down, row * height // down + 1)
        step = max(1, (bottom - top) // LINES)
        read = range(top, min(bottom, height), step)
        sums = [0] * across
        for y in read:
            start = y * line
            for x in range(across):
                sums[x] += sum(view[start + edges[x] : start + edges[x + 1]])
        for x in range(across):
            values = len(read) * (edges[x + 1] - edges[x])
            squares[row * across + x] = sums[x] // values if values else 0
    return bytes(squares)


def differs(one: bytes, other: bytes) -> bool:
    """Whether two pictures (as `fingerprint` gives them) are of screens that look different."""
    if len(one) != len(other):
        return True
    moved = 0
    for a, b in zip(one, other, strict=True):
        if abs(a - b) > LEVELS:
            moved += 1
            if moved >= SQUARES:
                return True
    return False


@dataclass(frozen=True)
class Seen:
    """A picture the wall handed out of a machine."""

    data: bytes
    content_type: str
    signal: bool
    taken_at: float  # when the device was asked for it (time.monotonic(), as kvm.Snapshot)
    at: float  # when the wall handed it out (time.time())
    pixels: int  # width times height, as the picture says


@dataclass(frozen=True)
class Watched:
    """A machine to be watched in a round, as the alert round sees it."""

    device_id: str
    state: str | None  # as the alert round has it settled (alerts.Watcher.state); None before it knows
    no_signal: int  # minutes; 0: not watched for that
    unchanged: int  # minutes; 0: not watched for that


@dataclass
class Event:
    """A watch that went off, or is over (`back`)."""

    device_id: str
    watch: str  # NO_SIGNAL | UNCHANGED
    back: bool
    minutes: int  # what the watch is set to
    lasted: float  # seconds the screen was dark or the same, as far as the wall saw
    picture: Seen | None = None  # what set it off (not for "back")
    stamp: str = ""  # the picture's number, once it is kept ("" where none is)


@dataclass
class _Machine:
    pending: Seen | None = None  # the picture to compare at the next round: the smallest of those with a signal since the last
    dark_seen: bool = False  # a picture without a signal came since the last round
    last_lit: Seen | None = None  # the last picture with a signal that was compared
    last_taken: float = -math.inf  # `taken_at` of the last picture compared
    last_data: bytes | None = None  # ...and that picture itself (a reference): handed out again, it is not compared again
    reference: bytes | None = None  # the first picture of the run of "unchanged", shrunk
    same_since: float | None = None  # when that run began (time.monotonic())
    last_new: float | None = None  # when the last new picture of the run came
    dark_since: float | None = None  # since when the round has seen no signal
    told: set[str] = field(default_factory=set)  # the watches that went off and are not over


class ScreenWatch:
    """The two watches of every machine that has one, and the pictures kept for them. Kept with the program (core.Core), as
    the alert round's watcher is: the listeners are opened anew now and then, and it must not start from nothing each time.

    `saw` is called with every picture the wall hands out, on the thread that serves everybody: it keeps a reference and
    does nothing else. `round` is called by the alert round after each of its looks."""

    def __init__(self, data_dir: Path | None) -> None:
        self._folder = None if data_dir is None else data_dir / FOLDER
        self._file = None if data_dir is None else data_dir / FILE
        self._machines: dict[str, _Machine] = {}
        self._watched: set[str] = set()  # whose pictures are noted: those with the watch of "unchanged" or "no signal" on
        self._session: Any = None  # the video worker pictures are decoded in (video.VideoSession), while one is needed
        self._said: set[str] = set()  # what could not be done that the log has said once
        self._swept_at = -math.inf
        self._going: set[str] = set()  # machines that left the wall, whose pictures are deleted at the next round
        self._stamped = 0  # the last stamp given to a picture kept
        self._written, self._refused = "", ""
        self._failed_at: float | None = None  # when what `_refused` holds could not be written down (None: nothing is owed)
        if self._file is not None:
            self._load(self._file)

    # --- what stands, written down ---------------------------------------------------------------------

    def _load(self, path: Path) -> None:
        try:
            with path.open("rb") as fh:
                said = json.loads(fh.read(1_000_000))
        except (OSError, ValueError, RecursionError):
            return
        told = said.get("told") if isinstance(said, dict) else None
        if not isinstance(told, dict):
            return
        for device_id, watches in list(told.items())[:MOST_KEPT]:
            if isinstance(device_id, str) and _ID.fullmatch(device_id) and isinstance(watches, list):
                kept = {watch for watch in watches if watch in WATCHES}
                if kept:
                    self._machine(device_id).told = kept
        self._written = self._text()

    def _text(self) -> str:
        told = {device_id: sorted(machine.told) for device_id, machine in self._machines.items() if machine.told}
        return json.dumps({"told": told}, sort_keys=True)

    def _to_write(self) -> str | None:
        text = self._text()
        if self._file is None or text == self._written:
            return None
        if self._failed_at is not None and text == self._refused and time.monotonic() - self._failed_at < TRY_AGAIN:
            return None
        self._refused = text
        return text

    def _write(self, text: str) -> None:
        """Write down which alerts stand (`_to_write` gave it). Waits for the disk: for a worker thread."""
        assert self._file is not None
        try:
            being_written = self._file.with_name(self._file.name + ".new")
            being_written.unlink(missing_ok=True)
            with private(being_written, "x", encoding="ascii") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(being_written, self._file)
            self._written, self._failed_at = text, None
        except OSError as ex:
            if self._failed_at is None:
                log.warning("which screen alerts stand could not be written down: %s", ex.strerror or ex)
            self._failed_at = time.monotonic()

    # --- what the wall hands out -------------------------------------------------------------------------

    def _machine(self, device_id: str) -> _Machine:
        machine = self._machines.get(device_id)
        if machine is None:
            machine = self._machines[device_id] = _Machine()
        return machine

    def saw(self, device_id: str, frame: Snapshot) -> None:
        """A picture of a machine the wall has just handed out. Kept (a reference) where the machine is watched; for the next
        round, the smallest of those with a signal (the one that is quickest to compare)."""
        if device_id not in self._watched:
            return
        machine = self._machine(device_id)
        if not frame.signal:
            machine.dark_seen = True
            return
        # Compared already (a still, or a frame several viewers share, handed out again), older than that, or nothing that is
        # kept. (By the picture itself as well as its time: on Windows before Python 3.13 two pictures asked for within 15.6 ms
        # have one time.)
        if frame.data is machine.last_data or frame.taken_at < machine.last_taken or frame.content_type not in _KINDS:
            return
        pending = machine.pending
        if pending is not None and pending.data is frame.data:
            return
        size = picture_size(frame.data)
        pixels = size[0] * size[1] if size is not None else 0
        if pixels <= 0:
            return
        if pending is None or pixels <= pending.pixels:
            machine.pending = Seen(frame.data, frame.content_type, True, frame.taken_at, time.time(), pixels)

    def forget(self, device_id: str) -> None:
        """A machine left the wall: what is known of it goes, and its picture at the next round."""
        self._machines.pop(device_id, None)
        self._watched.discard(device_id)
        self._going.add(device_id)

    def standing(self, device_id: str) -> list[str]:
        """The watches of a machine that went off and are not over."""
        machine = self._machines.get(device_id)
        return sorted(machine.told) if machine is not None else []

    async def sweep(self, on_wall: set[str]) -> None:
        """Where there is no round (alerts off, or the saved passwords locked): the pictures kept are looked through all the
        same, every SWEEP_EVERY seconds, and those of machines that left the wall (`on_wall`: the ids of those on it), and
        those kept longer than KEEP_DAYS, deleted."""
        if time.monotonic() - self._swept_at < SWEEP_EVERY:
            return
        self._swept_at = time.monotonic()
        going, self._going = self._going - on_wall, set()
        await asyncio.to_thread(self._delete, going, on_wall)

    # --- a round --------------------------------------------------------------------------------------

    async def round(self, watched: Iterable[Watched], on_wall: set[str], paused: bool) -> list[Event]:
        """After a look of the alert round: what went off and what is over, with the pictures of the first kept. Nothing goes
        off and nothing is over while alerts are paused (`paused`): what is so when the pause ends is told then."""
        now = time.monotonic()
        machines = [each for each in watched if each.no_signal or each.unchanged]
        self._watched = {each.device_id for each in machines}
        for device_id in [device_id for device_id in self._machines if device_id not in self._watched]:
            # Not watched any more (the watch switched off, alerts off for it, off the wall): nothing of it stands.
            if device_id not in on_wall:
                self._going.add(device_id)
            del self._machines[device_id]
        todo = []
        for each in machines:
            machine = self._machine(each.device_id)
            if not each.unchanged:
                # (Watched for no signal alone: the last picture with a signal is kept in mind as it comes, for its alert.)
                machine.last_lit = machine.pending or machine.last_lit
                machine.pending = machine.reference = machine.same_since = machine.last_new = None
                machine.dark_seen = False
                machine.told.discard(UNCHANGED)
            elif machine.pending is not None:
                todo.append((each.device_id, machine.pending))
            if not each.no_signal:
                machine.dark_since = None
                machine.told.discard(NO_SIGNAL)
        going, self._going = self._going - on_wall, set()
        sweep = time.monotonic() - self._swept_at >= SWEEP_EVERY
        if sweep:
            self._swept_at = time.monotonic()
        shrunk: dict[str, bytes | None] = {}
        if todo or going or sweep or (self._session is not None and not any(each.unchanged for each in machines)):
            shrunk = await asyncio.to_thread(self._work, todo, going, on_wall if sweep else None, any(each.unchanged for each in machines))
        # (What was compared, by machine: a newer picture may have come meanwhile, which is the next round's.)
        compared = {device_id: (seen, shrunk[device_id]) for device_id, seen in todo if device_id in shrunk}
        events: list[Event] = []
        for each in machines:
            found = self._machines.get(each.device_id)
            if found is None:
                continue  # (taken off the wall while the pictures were compared)
            if each.no_signal:
                events.extend(self._dark(each, found, now, paused))
            if each.unchanged:
                events.extend(self._same(each, found, compared.get(each.device_id), now, paused))
        if any(not event.back and event.picture is not None for event in events):
            await asyncio.to_thread(self._keep_all, events)
        if (text := self._to_write()) is not None:
            await asyncio.to_thread(self._write, text)
        return events

    def _dark(self, each: Watched, machine: _Machine, now: float, paused: bool) -> list[Event]:
        state = each.state
        if state == "no_signal":
            if machine.dark_since is None:
                machine.dark_since = now
            lasted = now - machine.dark_since
            if NO_SIGNAL not in machine.told and not paused and lasted >= each.no_signal * MINUTE:
                machine.told.add(NO_SIGNAL)
                return [Event(each.device_id, NO_SIGNAL, False, each.no_signal, lasted, machine.last_lit)]
            return []
        if state is None or state in ("offline", "auth", "error"):
            # Not known to have a signal or none (it does not answer): the run of no signal is over, and what went off stands.
            machine.dark_since = None
            return []
        lasted = 0.0 if machine.dark_since is None else now - machine.dark_since
        machine.dark_since = None
        if state == "online" and NO_SIGNAL in machine.told and not paused:
            machine.told.discard(NO_SIGNAL)
            return [Event(each.device_id, NO_SIGNAL, True, each.no_signal, lasted)]
        return []

    def _same(self, each: Watched, machine: _Machine, compared: tuple[Seen, bytes | None] | None, now: float, paused: bool) -> list[Event]:
        dark, machine.dark_seen = machine.dark_seen, False
        if dark:
            # A picture without a signal: no picture of the screen. The run starts again with the next one that has it.
            machine.reference = machine.same_since = machine.last_new = None
        if compared is None:
            if machine.last_new is not None and now - machine.last_new > GAP_MINUTES * MINUTE:
                machine.reference = machine.same_since = machine.last_new = None  # nobody looked for a long while
            return []
        seen, found = compared
        if machine.pending is seen:
            machine.pending = None
        machine.last_taken, machine.last_data = max(machine.last_taken, seen.taken_at), seen.data  # (not compared again)
        if found is None:
            return []  # could not be compared (the log said why, once)
        machine.last_lit = seen
        if machine.reference is None or machine.same_since is None or (machine.last_new is not None and now - machine.last_new > GAP_MINUTES * MINUTE):
            machine.reference, machine.same_since, machine.last_new = found, now, now
            return []
        if differs(machine.reference, found):
            lasted = now - machine.same_since
            machine.reference, machine.same_since, machine.last_new = found, now, now
            if UNCHANGED in machine.told and not paused:
                machine.told.discard(UNCHANGED)
                return [Event(each.device_id, UNCHANGED, True, each.unchanged, lasted)]
            return []
        machine.last_new = now
        lasted = now - machine.same_since
        if UNCHANGED not in machine.told and not paused and lasted >= each.unchanged * MINUTE:
            machine.told.add(UNCHANGED)
            return [Event(each.device_id, UNCHANGED, False, each.unchanged, lasted, seen)]
        return []

    # --- in a worker thread ----------------------------------------------------------------------------

    def _work(self, todo: list[tuple[str, Seen]], going: set[str], on_wall: set[str] | None, wanted: bool) -> dict[str, bytes | None]:
        """Compare the pictures of `todo` (as long as ROUND_MOST allows: what is left waits for the next round), delete the
        pictures of machines that left the wall, and those kept too long (`on_wall`: where it is time to look); let the video
        worker go where no machine is watched for "unchanged" any more (`wanted`)."""
        shrunk: dict[str, bytes | None] = {}
        began = time.monotonic()
        for device_id, seen in todo:
            if time.monotonic() - began > ROUND_MOST:
                break
            shrunk[device_id] = self._shrink(seen)
        if not wanted and self._session is not None:
            session, self._session = self._session, None
            session.close()
        if going or on_wall is not None:
            self._delete(going, on_wall)
        return shrunk

    def _shrink(self, seen: Seen) -> bytes | None:
        if seen.content_type != "image/jpeg":
            return None
        size = picture_size(seen.data)
        if size is None or not 0 < size[0] * size[1] <= MOST_PIXELS:
            return None
        from .video import VideoError, VideoSession, decode_jpeg

        try:
            if self._session is None:
                self._session = VideoSession()
            rgb = decode_jpeg(seen.data, size[0], size[1], self._session)
        except (VideoError, OSError) as ex:
            self._say_once("decode", "a picture could not be compared for the watch of unchanged screens: %s", ex)
            return None
        return fingerprint(rgb, size[0], size[1])

    def _say_once(self, what: str, line: str, *values: Any) -> None:
        if what not in self._said:
            self._said.add(what)
            log.warning(line, *values)

    def _files(self) -> list[tuple[Path, str, str]]:
        """The pictures kept: (path, machine, stamp)."""
        if self._folder is None:
            return []
        try:
            names = os.listdir(self._folder)
        except OSError:
            return []
        found = []
        for name in names:
            stem, _, ending = name.rpartition(".")
            device_id, _, stamp = stem.rpartition("-")
            if ending in _TYPES and _ID.fullmatch(device_id) and STAMP.fullmatch(stamp):
                found.append((self._folder / name, device_id, stamp))
        return found

    def _delete(self, going: set[str], on_wall: set[str] | None) -> None:
        oldest = time.time() - KEEP_DAYS * DAY
        for path, device_id, _ in self._files():
            try:
                old = on_wall is not None and (device_id not in on_wall or path.stat().st_mtime < oldest)
                if device_id in going or old:
                    path.unlink()
            except OSError as ex:
                self._say_once("delete", "a picture kept for a screen alert could not be deleted: %s", ex.strerror or ex)

    def _keep_all(self, events: list[Event]) -> None:
        for event in events:
            if not event.back and event.picture is not None:
                event.stamp = self.keep(event.device_id, event.picture)

    def keep(self, device_id: str, seen: Seen) -> str:
        """Keep the picture that set off a machine's alert, in place of the one kept before. Its stamp; "" where it could not
        be kept. Waits for the disk: for a worker thread."""
        if self._folder is None or seen.content_type not in _KINDS:
            return ""
        # Milliseconds since 1970, and never one given before (two alerts of one round, a clock that steps 15.6 ms at a time).
        self._stamped = max(time.time_ns() // 1_000_000, self._stamped + 1)
        stamp = str(self._stamped)
        path = self._folder / f"{device_id}-{stamp}.{_KINDS[seen.content_type]}"
        try:
            own_folder(self._folder)
            being_written = path.with_name(path.name + ".new")
            being_written.unlink(missing_ok=True)
            with private(being_written, "xb") as fh:
                fh.write(seen.data)
            os.replace(being_written, path)
        except OSError as ex:
            self._say_once("keep", "the picture of a screen alert could not be kept: %s", ex.strerror or ex)
            return ""
        for other, whose, its in self._files():
            if whose == device_id and its != stamp:
                try:
                    other.unlink()
                except OSError:
                    pass
        return stamp

    def picture(self, device_id: str, stamp: str) -> tuple[bytes, str] | None:
        """The picture kept of a machine under that stamp, and its kind; None where it is not kept (any more). For a worker
        thread."""
        if self._folder is None or not _ID.fullmatch(device_id) or not STAMP.fullmatch(stamp):
            return None
        for ending, kind in _TYPES.items():
            try:
                with (self._folder / f"{device_id}-{stamp}.{ending}").open("rb") as fh:
                    data = fh.read(MOST_PICTURE + 1)
            except OSError:
                continue
            return (data, kind) if 0 < len(data) <= MOST_PICTURE else None
        return None

    def close(self) -> None:
        """Let the video worker go (at the end of the program). For a worker thread."""
        session, self._session = self._session, None
        if session is not None:
            session.close()
