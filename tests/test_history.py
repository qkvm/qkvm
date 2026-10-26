"""What the wall saw of each machine: kept in history.sqlite, read by one route, taken away with the machine.

The store by itself first (rows in, rows out, the writer that never makes the wall wait, a trim, a file that
cannot be read), then the wall: who may read a machine's history, what it says, and that a machine removed
from the wall takes its history with it.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import cli, exchange, history, kvm, server, update, vault
from qkvm.history import History
from qkvm.store import Store
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_tokens import script
from tests.test_users import account, browser
from tests.test_wall import add, wait_until, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    device = FakeKvm(FakeState(atx=True)).start()
    yield device
    device.stop()


@pytest.fixture
def kept(tmp_path: Path) -> Iterator[History]:
    """A store of its own, started, and stopped when the test is done (an open file cannot be removed on Windows)."""
    store = History(tmp_path / history.FILE)
    store.start()
    yield store
    store.stop()


ONLINE: dict[str, Any] = {
    "state": "online", "error": None, "last_seen_ago": 0,
    "atx": {"enabled": True, "power": True, "hdd": None},
    "health": {"temp": 42.5, "cpu": 17, "mem": 39.5},
    "server": {"temperatures": [{"name": "CPU0_TEMP", "celsius": 61, "ok": True}], "fans": [{"name": "CPU0_FAN", "reading": 1650, "unit": "RPM", "ok": True}]},
}  # fmt: skip
OFFLINE: dict[str, Any] = {"state": "offline", "error": {"code": "unreachable", "message": "Nothing answers"}, "last_seen_ago": 12}


def with_power(status: dict[str, Any], on: bool | None) -> dict[str, Any]:
    return {**status, "atx": {"enabled": on is not None, "power": on, "hdd": None}}


def with_temperature(status: dict[str, Any], celsius: float) -> dict[str, Any]:
    return {**status, "server": {**status["server"], "temperatures": [{"name": "CPU0_TEMP", "celsius": celsius, "ok": True}]}}


# How long a test waits for a trim it asked for to end: what one trim may hold the writer for (its time, TRIM_PATIENCE,
# and a checkpoint's wait for each of its two parts), with a minute beside it for the rows it counts first. A test looks
# at what a trim did once it has ended: looked at before (the writer still at it after the five seconds `flush` waits by
# default, which on a busy computer one trim took), a trim was caught halfway, 17 MB of 20 still on the disk.
def trim_ends_within() -> float:
    return history.TRIM_PATIENCE + 2 * history.CHECKPOINT_PATIENCE + 60


def trimmed(kept: History) -> None:
    """Have `kept` trim now, and wait until that trim has ended (and what was noted before it is written)."""
    kept.trim()
    within = trim_ends_within()
    kept.flush(within=within)
    assert kept._waiting.unfinished_tasks == 0, f"the trim had not ended after {within:.0f} s"


def rows_of(kept: History, what: str, device: str = "dev", since: float = 0.0, until: float = 1e11, **more: Any) -> list[dict[str, Any]]:
    found = kept.read(device, what, since, until, **more)["rows"]
    assert isinstance(found, list)
    return found


@contextmanager
def heard() -> Iterator[list[str]]:
    """What the program's own log says meanwhile, by a handler on that logger itself: a test that started the
    program the way it is started leaves the logger with a place of its own and no longer passing lines up,
    so pytest's own capture, which listens at the root, hears nothing from then on."""
    logger = logging.getLogger("qkvm")
    lines: list[str] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    handler, level = Keep(logging.INFO), logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield lines
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


# --- the store by itself -------------------------------------------------------------------------------------


def test_a_row_when_the_state_changes_and_not_at_every_look(kept: History) -> None:
    t0 = time.time() - 3600  # (recent: rows older than the retention would be trimmed at the first write)
    for second in range(0, 300):
        kept.observe("dev", ONLINE if second < 100 or second >= 200 else OFFLINE, now=t0 + second)
    kept.flush()
    states = rows_of(kept, "states")
    assert [(row["state"], row["code"], row["t"] - t0) for row in states] == [("online", "", 0), ("offline", "unreachable", 100), ("online", "", 200)]
    summary = kept.read("dev", "summary", t0, t0 + 300, now=t0 + 300)
    assert (summary["watched"], summary["online"], summary["changes"]) == (300, 200, 3)
    assert summary["share"] == pytest.approx(200 / 300)
    assert summary["first_seen"] == t0 and summary["last_seen"] == pytest.approx(t0 + 299)  # (the last look said "0 s ago")
    assert summary["state"] == "online" and summary["power"] == "on"
    # A window that begins while a state stands: what it was then counts from the window's start.
    middle = kept.read("dev", "summary", t0 + 150, t0 + 250, now=t0 + 300)
    assert (middle["watched"], middle["online"], middle["changes"]) == (100, 50, 1)
    assert middle["share"] == pytest.approx(0.5)


def test_samples_are_taken_at_a_slow_pace_or_when_a_reading_moves(kept: History) -> None:
    t0 = time.time() - 3600  # (recent: rows older than the retention would be trimmed at the first write)
    for second in range(0, 300):
        kept.observe("dev", ONLINE, now=t0 + second)  # the readings hold still: a sample a minute
    kept.observe("dev", with_temperature(ONLINE, 64), now=t0 + 290)  # the processor is 3 degrees warmer: that is a sample at once
    kept.observe("dev", with_temperature(ONLINE, 64.5), now=t0 + 291)  # half a degree is not
    kept.flush()
    samples = rows_of(kept, "samples")
    by_sensor: dict[str, list[float]] = {}
    for row in samples:
        by_sensor.setdefault(row["sensor"], []).append(row["t"] - t0)
    assert by_sensor == {"CPU0_FAN": [0, 60, 120, 180, 240], "CPU0_TEMP": [0, 60, 120, 180, 240, 290], "device": [0, 60, 120, 180, 240]}
    assert {row["unit"] for row in samples} == {"C", "RPM"}
    # ...and averaged over spans, one series per sensor, for a graph that is to stay small.
    spans = kept.read("dev", "samples", t0, t0 + 400, every=200)
    assert [series["sensor"] for series in spans["series"]] == ["CPU0_FAN", "CPU0_TEMP", "device"] and spans["more"] is False
    cpu = next(series for series in spans["series"] if series["sensor"] == "CPU0_TEMP")
    assert cpu["unit"] == "C" and [[t - t0, value, low, high] for t, value, low, high in cpu["points"]] == [[0, 61, 61, 61], [200, 62.5, 61, 64]]
    # A page that is cut loses whole sensors at its end, never the newest spans of every sensor: the graph says "last 24 h".
    # Nor of the last sensor it holds: one whose series does not fit whole is left out, and not handed over with its oldest
    # span and without its newest. (The page held CPU0_TEMP's first span only, and the graph drew it as the whole day.)
    cut = kept.read("dev", "samples", t0, t0 + 400, every=200, limit=3)
    assert [(series["sensor"], len(series["points"])) for series in cut["series"]] == [("CPU0_FAN", 2)] and cut["more"] is True
    # Cut where one series ends and the next begins, the last is whole and stays.
    for limit, whole in ((2, [("CPU0_FAN", 2)]), (4, [("CPU0_FAN", 2), ("CPU0_TEMP", 2)])):
        page = kept.read("dev", "samples", t0, t0 + 400, every=200, limit=limit)
        assert [(series["sensor"], len(series["points"])) for series in page["series"]] == whole and page["more"] is True
    # One sensor that does not fit by itself: nothing of it, and `more` says to narrow the window.
    alone = kept.read("dev", "samples", t0, t0 + 400, every=200, limit=1)
    assert alone["series"] == [] and alone["more"] is True


def test_power_events_pressed_from_the_wall_and_seen_on_the_machine(tmp_path: Path) -> None:
    t0 = time.time() - 3600  # (recent: rows older than the retention would be trimmed at the first write)
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("dev", with_power(ONLINE, True), now=t0)  # the first thing known of it is not a change
    kept.pressed("dev", "atx_power", True, now=t0 + 10)
    kept.observe("dev", with_power(ONLINE, False), now=t0 + 20)
    kept.pressed("dev", "power_on", False, "unreachable", now=t0 + 30)
    kept.observe("dev", with_power(ONLINE, None), now=t0 + 40)  # not said: nothing is made of it
    kept.observe("dev", with_power(ONLINE, True), now=t0 + 50)
    kept.flush()
    assert [(row["t"] - t0, row["kind"], row["what"], row["ok"], row["note"]) for row in rows_of(kept, "events")] == [
        (10, "pressed", "atx_power", True, ""),
        (20, "power", "off", True, ""),
        (30, "pressed", "power_on", False, "unreachable"),
        (50, "power", "on", True, ""),
    ]
    kept.stop()
    # A restart in between: the first look after it is not a change either, unless the machine is in another state now.
    again = History(tmp_path / history.FILE)
    again.start()
    again.observe("dev", with_power(ONLINE, True), now=t0 + 100)
    again.observe("dev", with_power(ONLINE, False), now=t0 + 110)
    again.flush()
    assert [(row["t"] - t0, row["what"]) for row in rows_of(again, "events") if row["kind"] == "power"] == [(20, "off"), (50, "on"), (110, "off")]
    again.stop()


def test_the_writer_never_makes_the_wall_wait_however_the_disk_behaves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A disk that stalls (a network share that went away, a full one that is slow to say so): the thread that
    # writes hangs in the write, and nothing else is to. Here the write is made to hang.
    stalled, in_the_write = threading.Event(), threading.Event()
    kept = History(tmp_path / history.FILE)
    writes = kept._write

    def hung(rows: list[tuple[Any, ...]]) -> None:
        in_the_write.set()
        stalled.wait()
        writes(rows)

    monkeypatch.setattr(kept, "_write", hung)
    kept.start()
    kept.observe("dev", ONLINE, now=time.time())
    assert in_the_write.wait(5), "the writer never took the first row"  # (and hangs in it from here on)
    slowest = 0.0
    began = time.monotonic()
    for number in range(history.QUEUE_SIZE + 2000):
        before = time.monotonic()
        kept.observe("dev", ONLINE if number % 2 else OFFLINE, now=time.time() + 1 + number)  # a change at every look: a row each
        slowest = max(slowest, time.monotonic() - before)
    # Nothing waited for the disk: the writer is still in its first write, and every note came back at once. (The
    # numbers are loose on purpose: a busy machine pauses a thread now and then, and that is not a note that waited.)
    assert not stalled.is_set() and kept._waiting.unfinished_tasks > 0
    assert slowest < 0.5, f"one note took {slowest:.3f} s with the disk stalled"
    assert time.monotonic() - began < 15.0
    assert kept.dropped >= 2000  # a full queue drops and counts, as the activity log does
    stalled.set()
    kept.flush(within=20)
    assert kept._waiting.unfinished_tasks == 0  # and what was kept is written once the disk is back
    assert len(rows_of(kept, "states", limit=history.MOST_ROWS)) == history.MOST_ROWS  # (bounded: a page, not the whole table)
    kept.stop()


def test_a_slip_in_the_writer_is_said_and_the_writer_goes_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Not the file's fault and not the disk's: a mistake in this program, met in the thread that writes. Left to end
    # that thread, the history was gone until the next start and nothing said so where the log is read.
    t0 = time.time() - 60
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("dev", ONLINE, now=t0)
    kept.flush()
    writes = History._write_one
    slip = [True]

    def slips(conn: sqlite3.Connection, row: tuple[Any, ...]) -> None:
        if slip and row[0] == "state":
            slip.clear()
            raise RuntimeError("a slip of the program's own")
        writes(conn, row)

    monkeypatch.setattr(History, "_write_one", staticmethod(slips))
    with heard() as said:
        kept.observe("dev", OFFLINE, now=t0 + 10)  # the row that meets the slip is lost and counted
        kept.flush(within=10)
        kept.observe("dev", ONLINE, now=t0 + 20)
        kept.flush(within=10)
    assert any("starts afresh" in line for line in said), said
    assert kept.dropped >= 1 and kept._waiting.unfinished_tasks == 0
    assert [round(row["t"] - t0) for row in rows_of(kept, "states")] == [0, 20]
    assert kept.read("dev", "summary", t0, t0 + 30)["state"] == "online"  # and it can be read
    kept.stop()


def test_limits_from_the_settings_are_held_to_what_makes_sense() -> None:
    def with_limits(days: Any, megabytes: Any) -> tuple[int, int]:
        return History(Path("nowhere") / history.FILE, limits=lambda: (days, megabytes)).limits()

    assert with_limits(90, 200) == (90, 200)
    assert with_limits(0, 0) == (history.DEFAULT_DAYS, history.DEFAULT_MB)  # nothing written, or null: the default
    assert with_limits(-5, -1) == (history.DEFAULT_DAYS, history.DEFAULT_MB)
    assert with_limits(1_000_000, 5) == (history.MOST_DAYS, history.LEAST_MB)
    assert with_limits("30", "x") == (history.DEFAULT_DAYS, history.DEFAULT_MB)  # (not what the settings file lets through; met all the same)


def test_retention_trims_by_age_and_keeps_what_the_window_start_needs(tmp_path: Path) -> None:
    t0 = time.time()
    limits = {"days": 365, "mb": 200}  # (the writer trims at its first rows as well: nothing is to go before the test looks)
    kept = History(tmp_path / history.FILE, limits=lambda: (limits["days"], limits["mb"]))
    kept.start()
    for day in (10, 5, 3, 1):  # a state change and a pressed button each day; samples on the days it was online
        at = t0 - day * history.DAY
        kept.observe("dev", ONLINE if day in (10, 3) else OFFLINE, now=at)
        kept.pressed("dev", "atx_power", True, now=at + 1)
    kept.observe("dev", ONLINE, now=t0 - history.DAY + 10)
    kept.flush()
    assert len(rows_of(kept, "states")) == 5 and len(rows_of(kept, "events")) == 4 and len(rows_of(kept, "samples")) == 3 * 3
    limits["days"] = 2
    trimmed(kept)
    # Of the states, the newest before the cutoff stays: what the machine was when the two days kept begin.
    assert [round((row["t"] - t0) / history.DAY) for row in rows_of(kept, "states")] == [-3, -1, -1]
    assert [round((row["t"] - t0) / history.DAY) for row in rows_of(kept, "events")] == [-1]
    assert len(rows_of(kept, "samples")) == 3  # (the one look within two days: its three readings)
    two_days = kept.read("dev", "summary", t0 - 2 * history.DAY, t0, now=t0)
    assert two_days["watched"] == pytest.approx(2 * history.DAY, abs=2) and two_days["online"] == pytest.approx(2 * history.DAY - 10, abs=2)
    # The newest state row of a device stays whatever its age: it says what the device was when a window begins.
    kept.observe("quiet", ONLINE, now=t0 - 30 * history.DAY)
    kept.flush()
    trimmed(kept)
    assert [row["state"] for row in rows_of(kept, "states", device="quiet")] == ["online"]
    assert kept.read("quiet", "summary", t0 - history.DAY, t0, now=t0)["online"] == pytest.approx(history.DAY, abs=2)
    kept.stop()


def test_retention_trims_by_size_to_under_the_cap_from_the_oldest_rows_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "LEAST_MB", 1)  # (a cap of one megabyte, so that a small file is already too large)
    t0 = time.time() - 40 * 3600
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    kept.start()
    kept.observe("dev", ONLINE, now=t0)
    kept.flush()
    kept.stop()
    # Forty hours of a controller with forty readings, written straight into the file: some four megabytes.
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany(
            "INSERT INTO samples (device, t, sensor, value, unit) VALUES ('dev', ?, ?, ?, 'C')",
            ((t0 + second, f"sensor {number:02d}", 40 + number + (second // 60) % 5) for second in range(0, 40 * 3600, 60) for number in range(40)),
        )
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()  # (into the file itself, so that its size says what it holds)
    conn.close()

    def size() -> int:
        with sqlite3.connect(tmp_path / history.FILE) as conn:
            pages, page = (int(conn.execute(f"PRAGMA {name}").fetchone()[0]) for name in ("page_count", "page_size"))
        conn.close()
        return pages * page

    assert size() > 3_000_000
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()  # (the first rows of a start trim as well; nothing else is written here)
    trimmed(again)
    assert size() <= 1_000_000  # the file is under the cap: the rows went, and the room they took was given back
    left = again.read("dev", "samples", 0, 1e11, every=3600)["series"]
    assert len(left) == 40 and all(series["points"][-1][0] == pytest.approx(t0 + 39 * 3600, abs=3600) for series in left)  # the newest hours stayed, of every sensor
    assert all(series["points"][0][0] > t0 + 10 * 3600 for series in left)  # the oldest went first, a tenth of the span at a time
    # The newest state row stays whatever its age: here the one the new start wrote (unwatched since the look at t0).
    assert [(round(row["t"] - t0), row["state"]) for row in rows_of(again, "states")] == [(0, "unwatched")]
    again.stop()


def test_a_file_that_cannot_be_read_is_moved_aside_and_a_fresh_one_started(tmp_path: Path) -> None:
    (tmp_path / history.FILE).write_bytes(b"not a database at all, whatever the name says" * 50)
    kept = History(tmp_path / history.FILE)
    with heard() as said:
        kept.start()
        kept.observe("dev", ONLINE)
        kept.flush()
    assert kept.damaged is not None and kept.damaged.exists() and kept.damaged.name.startswith("history.damaged-")
    assert any("moved aside" in line and "file is not a database" in line for line in said), said
    assert [row["state"] for row in rows_of(kept, "states")] == ["online"]  # the fresh one takes rows
    kept.stop()
    # A file this program's tables are older than (a later version's) is kept aside the same way, not written into.
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.execute("PRAGMA user_version = 99")
    conn.close()
    later = History(tmp_path / history.FILE)
    with heard() as said:
        later.start()
        later.observe("dev", OFFLINE)
        later.flush()
    assert later.damaged is not None and later.damaged != kept.damaged
    assert any("later version" in line for line in said), said
    assert [row["state"] for row in rows_of(later, "states")] == ["offline"]
    later.stop()


def test_a_file_that_goes_bad_while_it_is_written_is_moved_aside_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t0 = time.time() - 60
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("dev", ONLINE, now=t0 + 1)
    kept.flush()
    writes = History._write_one
    broken = [True]

    def malformed(conn: sqlite3.Connection, row: tuple[Any, ...]) -> None:
        if broken:
            broken.clear()
            damage = sqlite3.DatabaseError("database disk image is malformed")
            damage.sqlite_errorcode = sqlite3.SQLITE_CORRUPT_INDEX  # (as SQLite says it: damage, of an index)
            raise damage
        writes(conn, row)

    monkeypatch.setattr(History, "_write_one", staticmethod(malformed))
    with heard() as said:
        kept.observe("dev", OFFLINE, now=t0 + 2)
        kept.flush()
        kept.observe("dev", ONLINE, now=t0 + 3)
        kept.flush()
    assert kept.damaged is not None and any("malformed" in line for line in said), said
    assert [row["state"] for row in rows_of(kept, "states")] == ["online"]  # the row that met the fault is lost, the next is kept
    assert kept.dropped >= 1
    kept.stop()


def test_a_machine_is_unwatched_from_its_last_look_on_after_a_restart_and_after_a_while(tmp_path: Path) -> None:
    t0 = time.time() - 3600  # (recent: rows older than the retention would be trimmed at the first write)
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("dev", ONLINE, now=t0)
    kept.observe("dev", ONLINE, now=t0 + 100)  # (a minute on: "last heard from" is written again)
    kept.observe("dev", ONLINE, now=t0 + 130)  # (half a minute on: nothing is written for this look by itself)
    kept.flush()  # (as the program does when it stops: the last look, this one, is written down)
    kept.stop()
    again = History(tmp_path / history.FILE)
    again.start()
    again.observe("dev", ONLINE, now=t0 + 500)
    again.flush()
    states = [(round(row["t"] - t0), row["state"]) for row in rows_of(again, "states")]
    assert states == [(0, "online"), (130, "unwatched"), (500, "online")]
    summary = again.read("dev", "summary", t0, t0 + 1000, now=t0 + 1000)
    assert (summary["watched"], summary["online"]) == (630, 630)  # the 370 s nobody looked are nobody's
    # While the program runs: not looked at for a while (the wall locked itself), it is unwatched from the last look on.
    again.sweep(now=t0 + 500 + history.STALE - 1)  # not yet
    again.sweep(now=t0 + 500 + history.STALE)
    again.observe("dev", ONLINE, now=t0 + 2000)
    again.flush()
    states = [(round(row["t"] - t0), row["state"]) for row in rows_of(again, "states")]
    assert states == [(0, "online"), (130, "unwatched"), (500, "online"), (500, "unwatched"), (2000, "online")]
    summary = again.read("dev", "summary", t0, t0 + 2100, now=t0 + 2100)
    assert (summary["watched"], summary["online"]) == (230, 230)  # (watched: the first 130 s, and the 100 s since the last row)
    again.stop()


def test_a_read_that_takes_too_long_is_given_up(kept: History, monkeypatch: pytest.MonkeyPatch) -> None:
    t0 = time.time() - 3600
    for second in range(0, 3000):
        kept.observe("dev", ONLINE if second % 2 else OFFLINE, now=t0 + second)
    kept.flush()
    monkeypatch.setattr(history, "READ_PATIENCE", -1.0)  # out of patience before it begins
    with pytest.raises(history.NotReadable, match="took too long"):
        kept.read("dev", "summary", t0, t0 + 3000)
    monkeypatch.setattr(history, "READ_PATIENCE", 5.0)
    assert kept.read("dev", "summary", t0, t0 + 3000)["changes"] == 3000


def test_a_read_is_bounded_and_asks_for_known_things_only(kept: History) -> None:
    for second in range(0, 400):
        kept.observe("dev", ONLINE if second % 2 else OFFLINE, now=time.time() - 1000 + second)
    kept.flush()
    page = kept.read("dev", "states", 0, 1e11, limit=100)
    assert len(page["rows"]) == 100 and page["more"] is True
    whole = kept.read("dev", "states", 0, 1e11, limit=10**9)  # (a limit past MOST_ROWS is MOST_ROWS; the stalled-disk test above meets that cut)
    assert len(whole["rows"]) == 400 and whole["more"] is False
    assert page["rows"][0]["t"] < page["rows"][-1]["t"]  # oldest first
    with pytest.raises(ValueError):
        kept.read("dev", "everything", 0, 1e11)
    assert kept.read("nobody", "summary", 0, 1e11)["share"] is None  # nothing known: not "always online"


def test_what_a_status_carries_that_is_no_reading_is_left_out() -> None:
    odd = {
        "health": {"temp": True},  # a yes is no temperature
        "server": {
            "temperatures": [{"name": "A", "celsius": float("nan")}, {"name": "B", "celsius": "61"}, "not a sensor", {"name": "", "celsius": 20}],
            "fans": [{"name": "F", "reading": None, "unit": "RPM"}, {"name": "G", "reading": 1200, "unit": "knots"}],
            "power_watts": 230.5,
        },
    }
    assert list(history.sensors_of(odd)) == [("temperature 4", 20.0, "C"), ("G", 1200.0, ""), ("power", 230.5, "W")]
    assert list(history.sensors_of({})) == []


def test_the_size_is_said_in_plain_numbers(tmp_path: Path) -> None:
    assert history.size_of(tmp_path) == 0
    (tmp_path / history.FILE).write_bytes(b"x" * 1500)
    (tmp_path / (history.FILE + "-wal")).write_bytes(b"x" * 500)
    assert history.size_of(tmp_path) == 2000
    assert [history.said_size(n) for n in (0, 999, 2000, 1_500_000, 12_345_678)] == ["0 bytes", "999 bytes", "2 kB", "1.5 MB", "12 MB"]


def many_sensors(look: int, names: str = "s") -> dict[str, Any]:
    """A controller's status with sixty-four temperatures, named `names` and a number."""
    return {"state": "online", "server": {"temperatures": [{"name": f"{names}{n}", "celsius": 40.0 + look % 2} for n in range(history.MOST_SENSORS)], "fans": []}}


def test_reads_that_overlap_do_not_keep_the_wal_file_growing_past_its_share(tmp_path: Path) -> None:
    # SQLite brings the -wal file into the file by itself, but begins it again from the start only when no read is under
    # way that began before. Reads that overlap, one beginning before the other ends (three of the route's, staggered),
    # kept it growing for as long as they came: 98 MB in two and a half minutes beside a file of 2 MB, with a cap of
    # 10 MB, and the checkpoint every ten minutes, which waited five seconds, did not get through reads of five.
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 10))  # (the -wal file's share: a tenth, 1 MB)
    kept.start()
    kept.observe("w", ONLINE)
    kept.flush()
    share = 10 * 1_000_000 // 10
    stop = threading.Event()

    def reader(offset: float) -> None:
        stop.wait(offset)
        while not stop.is_set():
            conn = sqlite3.connect(f"{(tmp_path / history.FILE).resolve().as_uri()}?mode=ro", uri=True)
            conn.execute("BEGIN")
            conn.execute("SELECT COUNT(*) FROM states").fetchall()  # (a read under way: it holds what it began with)
            stop.wait(0.2)
            conn.rollback()
            conn.close()

    readers = [threading.Thread(target=reader, args=(n * 0.07,), daemon=True) for n in range(3)]
    for each in readers:
        each.start()
    wal = tmp_path / (history.FILE + "-wal")
    largest = 0
    t0 = time.time() - 2000 * 60
    with heard() as said:  # (what the log says meanwhile: where a checkpoint was turned away, how)
        try:
            for look in range(2000):  # (sixty-four readings a minute, of two thousand minutes: some 128,000 rows)
                kept.observe("w", many_sensors(look), now=t0 + look * 60)
                if look % 20 == 0:
                    time.sleep(0.01)  # (the writer takes what came meanwhile: transactions as a wall writes them)
                    largest = max(largest, wal.stat().st_size)
                    while kept._waiting.qsize() > history.QUEUE_SIZE // 2:  # (no faster than it writes: nothing is to be dropped)
                        time.sleep(0.01)
                        largest = max(largest, wal.stat().st_size)
            deadline = time.monotonic() + 60
            while kept._waiting.unfinished_tasks and time.monotonic() < deadline:
                largest = max(largest, wal.stat().st_size)
                time.sleep(0.01)
        finally:
            stop.set()
            for each in readers:
                each.join(5)
    assert kept._waiting.unfinished_tasks == 0 and kept.dropped == 0
    # Held to its share, give or take what one transaction writes (500 rows at the most): never what all of them wrote. (Or
    # twice that: a checkpoint turned away, as one was once in a whole run of the tests on a busy PC, is tried again once
    # the -wal file has doubled. See the test below.)
    assert largest <= 2 * (share + 500_000), f"the -wal file grew to {largest / 1e6:.1f} MB; the log said {said}"
    kept.stop()


def test_a_checkpoint_turned_away_is_tried_again_once_the_wal_file_has_doubled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A checkpoint that did not get through was not tried again for a minute, whatever came meanwhile: once, in a whole run
    # of the tests on a busy PC, the -wal file grew to 9.9 MB beside a share of 1 MB in that minute.
    monkeypatch.setattr(history, "CHECKPOINT_PATIENCE", 0.2)
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 10))  # (the -wal file's share: 1 MB)
    kept.start()
    kept.observe("w", ONLINE)
    kept.flush()
    wal = tmp_path / (history.FILE + "-wal")
    outside = sqlite3.connect(tmp_path / history.FILE)
    outside.execute("BEGIN")
    outside.execute("SELECT COUNT(*) FROM states").fetchall()  # (a read that holds the -wal file, for a while)
    t0 = time.time() - 4000 * 60
    look, refused_at = 0, 0
    with heard() as said:
        while not any("could not be brought up to date" in line for line in said) and look < 4000:
            kept.observe("w", many_sensors(look), now=t0 + look * 60)
            look += 1
            if look % 20 == 0:
                kept.flush(within=10)
        kept.flush(within=10)
        refused_at = wal.stat().st_size
    outside.rollback()
    outside.close()
    assert any("could not be brought up to date" in line for line in said), "no checkpoint was turned away"
    largest = 0
    for later in range(look, look + 2000):  # (some 128,000 rows more: four times what made it past its share)
        kept.observe("w", many_sensors(later), now=t0 + later * 60)
        if later % 20 == 0:  # (no flush: it asks for a checkpoint of its own, whenever the last was turned away)
            time.sleep(0.01)
            largest = max(largest, wal.stat().st_size)
            while kept._waiting.qsize() > history.QUEUE_SIZE // 2:
                time.sleep(0.01)
    deadline = time.monotonic() + 60
    while kept._waiting.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.01)
    assert kept._waiting.unfinished_tasks == 0, "the writer never caught up"
    largest = max(largest, wal.stat().st_size)
    assert largest <= 2 * max(refused_at, 1_000_000) + 500_000, f"the -wal file grew to {largest / 1e6:.1f} MB after a refusal at {refused_at / 1e6:.1f} MB"
    kept.stop()


def test_a_checkpoint_turned_away_by_another_is_tried_at_the_next_look_and_one_held_up_by_a_read_later(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two refusals that SQLite tells apart by its row: another connection's checkpoint holds the file's checkpoint lock,
    # (1, -1, -1) at once, and it is gone in a moment; a read holds the -wal file, (1, n, m) after the whole wait, and
    # may stay. The first is tried again at the next look, the second in a minute (or once the -wal file has doubled).
    monkeypatch.setattr(history, "CHECKPOINT_PATIENCE", 0.2)
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 10))
    kept._open()  # (the writer's connection, opened here: this test is the only thread that uses it)
    conn = kept._conn
    assert conn is not None
    with conn:
        conn.execute("INSERT INTO states (device, t, state, code) VALUES ('w', 1, 'online', '')")
    reader = sqlite3.connect(tmp_path / history.FILE)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM states").fetchall()  # (a read that holds what it began with)
    with conn:
        conn.execute("INSERT INTO states (device, t, state, code) VALUES ('w', 2, 'offline', '')")  # (and something after it)
    done = threading.Event()

    def another() -> None:  # (a checkpoint of another connection, which waits for the read, holding the checkpoint lock)
        other = sqlite3.connect(tmp_path / history.FILE, timeout=2.0)
        while not done.is_set():
            other.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        other.close()

    other = threading.Thread(target=another, daemon=True)
    other.start()
    outcomes: set[str] = set()
    try:
        for _ in range(100):
            assert not kept._checkpoint()
            outcomes.add("next look" if kept._wal_again <= time.monotonic() else "a minute" if kept._wal_again >= time.monotonic() + 50 else "?")
            if {"next look", "a minute"} <= outcomes:
                break
    finally:
        done.set()
        other.join(10)
        reader.rollback()
        reader.close()
        kept._close()
    assert outcomes == {"next look", "a minute"}, outcomes


def test_a_checkpoint_that_fails_with_an_error_is_not_tried_at_every_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A checkpoint that came back at once was tried again at the next batch, taken for one turned away by another's
    # checkpoint; but an error that keeps coming (a full disk) comes back at once as well, and was tried at every batch,
    # copying the -wal file again each time, for as long as the disk stayed full.
    tries = [0]

    class Full(sqlite3.Connection):
        def execute(self, sql: str, *given: Any) -> sqlite3.Cursor:  # type: ignore[override]
            if "wal_checkpoint" in sql:
                tries[0] += 1
                raise sqlite3.OperationalError("database or disk is full")
            return super().execute(sql, *given)

    connect = sqlite3.connect

    def connecting(database: Any, *given: Any, **more: Any) -> sqlite3.Connection:
        if str(database).endswith(history.FILE) and not more.get("uri"):
            more["factory"] = Full  # (the writer's connection; the reads' go by a URI)
        return connect(database, *given, **more)

    monkeypatch.setattr(sqlite3, "connect", connecting)
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 10))  # (the -wal file's share: 1 MB)
    kept.start()
    kept.observe("w", ONLINE)
    kept.flush()
    wal = tmp_path / (history.FILE + "-wal")
    t0 = time.time() - 3000 * 60
    before, past_share = tries[0], 0
    for look in range(3000):  # (some 190,000 rows: hundreds of batches, the -wal file past its share for most of them)
        kept.observe("w", many_sensors(look), now=t0 + look * 60)
        if look % 20 == 0:
            time.sleep(0.01)
            past_share += wal.stat().st_size > 1_000_000
            while kept._waiting.qsize() > history.QUEUE_SIZE // 2:
                time.sleep(0.01)
    deadline = time.monotonic() + 60
    while kept._waiting.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.01)
    assert past_share > 50, "the -wal file was never past its share: nothing was asked of the checkpoint"
    assert tries[0] - before <= 5, f"tried {tries[0] - before} times"
    kept.stop()


def test_a_device_that_names_its_sensors_anew_at_every_look_is_held_to_a_pace(tmp_path: Path) -> None:
    # The names come from the device. One that named its sensors anew at every look (sixty-four at each) grew what the
    # event loop keeps of it by sixty-four names a look, for as long as it was watched: 128,000 after 2,000 looks. And it put
    # sixty-four rows in the queue at each look, which filled it, and rows of every other machine were dropped.
    kept = History(tmp_path / history.FILE)
    kept._writer = threading.current_thread()  # (no writer: what is noted stays in the queue, to be counted)
    t0 = 1_000_000.0
    for look in range(500):  # a look every five seconds, for some forty minutes
        kept.observe("churn", many_sensors(look, names=f"T{look}-"), now=t0 + look * 5)
    assert len(kept._known["churn"].samples) <= history.MOST_SENSORS  # only what it reports now is remembered
    minutes = 500 * 5 / history.SAMPLE_EVERY + 1
    samples = [row for row in kept._waiting.queue if row[0] == "sample"]
    assert len(samples) <= minutes * history.SAMPLES_PER_ROUND and kept.dropped == 0
    # A controller whose names hold still is not held back: every sensor once a minute, and a reading that moves at once.
    steady = History(tmp_path / "steady.sqlite")
    steady._writer = threading.current_thread()
    for second in range(0, 600, 5):
        steady.observe("server", many_sensors(0), now=t0 + second)
    per_sensor: dict[str, int] = {}
    for row in steady._waiting.queue:
        if row[0] == "sample":
            per_sensor[row[3]] = per_sensor.get(row[3], 0) + 1
    assert len(per_sensor) == history.MOST_SENSORS and set(per_sensor.values()) == {10}  # (ten minutes: ten each)


def test_readings_that_jump_at_every_look_do_not_keep_the_other_sensors_out(tmp_path: Path) -> None:
    # Within its pace, those due by the time go first: ten readings that jump at every look do not take the others' places.
    kept = History(tmp_path / history.FILE)
    kept._writer = threading.current_thread()
    t0 = 1_000_000.0
    for second in range(0, 300, 2):
        status = many_sensors(0)
        for n, entry in enumerate(status["server"]["temperatures"][:10]):
            entry["celsius"] = 40.0 + 30 * ((second // 2 + n) % 2)  # (thirty degrees up and down at every look)
        kept.observe("server", status, now=t0 + second)
    by_sensor: dict[str, list[float]] = {}
    for row in kept._waiting.queue:
        if row[0] == "sample":
            by_sensor.setdefault(row[3], []).append(row[2] - t0)
    quiet = [times for sensor, times in by_sensor.items() if int(sensor[1:]) >= 10]
    assert len(quiet) == history.MOST_SENSORS - 10 and all(times == [0, 60, 120, 180, 240] for times in quiet)
    assert sum(len(times) for times in by_sensor.values()) <= 5 * 2 * history.MOST_SENSORS  # (five minutes: each sensor once, and as many again, a minute)


def test_one_trim_brings_a_file_far_over_the_size_allowed_under_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A tenth of the time the rows span, twelve times at the most: a file three times too large was left one and a half
    # times too large, and the next tenth went ten minutes later (42 MB at a cap of 10 MB: 11.9 MB after the first trim).
    monkeypatch.setattr(history, "LEAST_MB", 1)
    # (What is tried here is how much one trim takes away, not how fast this computer is: given all the time it needs.
    # A trim's own limit, TRIM_PATIENCE, is held by test_every_trim_gets_on_with_the_size_however_long_the_rows_by_age_take;
    # with its half minute, the whole suites of four Pythons at once beside four on Windows had one trim end at its
    # time with 15 MB of 20 left. It took 4 s alone.)
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    t0 = time.time() - 200 * 3600
    kept = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    kept.start()
    kept.observe("dev", ONLINE, now=t0)
    kept.flush()
    kept.stop()
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany(
            "INSERT INTO samples (device, t, sensor, value, unit) VALUES ('dev', ?, ?, ?, 'C')",
            ((t0 + second, f"sensor {number:02d}", 40 + number) for second in range(0, 200 * 3600, 60) for number in range(40)),
        )
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    assert (tmp_path / history.FILE).stat().st_size > 8_000_000  # (eight times the size allowed, and more)
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()
    trimmed(again)
    again.stop()
    on_disk = history.size_of(tmp_path)  # the file and its -wal file
    assert on_disk <= 1_000_000, f"{on_disk / 1e6:.1f} MB after one trim"
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        newest = conn.execute("SELECT MAX(t) FROM samples").fetchone()[0]
    conn.close()
    assert newest == t0 + 200 * 3600 - 60  # (the newest went last: they are all still there)


def history_of(folder: Path, t0: float, rows: Iterator[tuple[float, str]]) -> None:
    """A history in `folder` with one device, looked at once at `t0`, and samples (t, sensor) written straight into it."""
    made = History(folder / history.FILE, limits=lambda: (365, 100_000))
    made.start()
    made.observe("dev", ONLINE, now=t0)
    made.flush()
    made.stop()
    with sqlite3.connect(folder / history.FILE) as conn:
        conn.executemany("INSERT INTO samples (device, t, sensor, value, unit) VALUES ('dev', ?, ?, 40, 'C')", rows)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()


def samples_in(folder: Path) -> tuple[int, float]:
    """(how many samples, the oldest one's time) in the history in `folder`."""
    with sqlite3.connect(folder / history.FILE) as conn:
        count, oldest = conn.execute("SELECT COUNT(*), MIN(t) FROM samples").fetchone()
    conn.close()
    return int(count), float(oldest)


def test_a_trim_keeps_as_much_as_fits_where_the_older_rows_are_denser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cut by the time the rows span, as if they were spread evenly: where the older ones were denser (a wall that had five
    # times the machines, or sensors taken at another pace before an upgrade), one trim left a third of what fitted.
    monkeypatch.setattr(history, "LEAST_MB", 1)
    # (What is tried here is how much one trim takes away, not how fast this computer is: given all the time it needs.
    # A trim's own limit, TRIM_PATIENCE, is held by test_every_trim_gets_on_with_the_size_however_long_the_rows_by_age_take;
    # with its half minute, the whole suites of four Pythons at once beside four on Windows had one trim end at its
    # time with 15 MB of 20 left. It took 4 s alone.)
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    t0 = time.time() - 200 * 3600
    dense = ((t0 + second, f"sensor {number:02d}") for second in range(0, 100 * 3600, 60) for number in range(40))
    sparse = ((t0 + second, f"sensor {number:02d}") for second in range(100 * 3600, 200 * 3600, 60) for number in range(8))
    history_of(tmp_path, t0, itertools.chain(dense, sparse))
    before, _ = samples_in(tmp_path)
    cap, room = 3_000_000, 3_000_000 - 300_000
    assert (tmp_path / history.FILE).stat().st_size > 3 * room
    again = History(tmp_path / history.FILE, limits=lambda: (365, 3))
    again.start()
    trimmed(again)
    again.stop()
    on_disk = history.size_of(tmp_path)
    left, oldest = samples_in(tmp_path)
    assert on_disk <= cap, f"{on_disk / 1e6:.1f} MB"
    assert on_disk >= 0.6 * room, f"{on_disk / 1e6:.2f} MB kept of the {room / 1e6:.1f} MB that fit ({left} of {before} rows, from {(t0 + 200 * 3600 - oldest) / 3600:.0f} h back)"
    assert oldest < t0 + 100 * 3600  # (every row of the sparser, newer half fits, and some of the denser half with it)


def test_a_trim_gives_the_room_back_a_share_of_the_wal_file_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Every page the trim moves passes through the -wal file while the file is still as large as it was: given back all at
    # once, a file twice the size allowed took half as much again beside it for the moment (19 MB and 9.3 MB at a cap of
    # 10 MB). A share of the -wal file's at a time, with a checkpoint between them.
    # Check disk-space bounds independently of runner speed; deadline behavior has its own regressions.
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    t0 = time.time() - 300 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 300 * 3600, 60) for number in range(30)))
    share = 10 * 1_000_000 // 10
    start = history.size_of(tmp_path)
    assert start > 15_000_000
    again = History(tmp_path / history.FILE, limits=lambda: (365, 10))
    largest, done = [0], threading.Event()

    def watch() -> None:
        while not done.is_set():
            largest[0] = max(largest[0], history.size_of(tmp_path))  # (the file and its -wal file, as they are on the disk)

    watching = threading.Thread(target=watch, daemon=True)
    watching.start()
    try:
        again.start()
        trimmed(again)
        again.stop()
    finally:
        done.set()
        watching.join(5)
    assert history.size_of(tmp_path) <= 10_000_000
    # (Never more than what was there, and the -wal file's share beside it: a bound on sizes, whatever the pace of the disk.)
    assert largest[0] <= start + share, f"{largest[0] / 1e6:.1f} MB on the disk while the trim ran, from {start / 1e6:.1f} MB"


def test_a_trim_deletes_no_rows_for_pages_that_were_not_given_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The size it went by was the file's pages, free ones too. Where they could not be given back (a disk that was full
    # says so at the vacuum, after the rows are deleted), each trim deleted another share of the rows, and nothing shrank.
    monkeypatch.setattr(history, "LEAST_MB", 1)
    t0 = time.time() - 100 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 100 * 3600, 60) for number in range(20)))
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.execute("DELETE FROM samples WHERE sensor != 'sensor 00'")  # (the rows gone, the pages kept: as after such a trim)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    rows, _ = samples_in(tmp_path)
    assert (tmp_path / history.FILE).stat().st_size > 3_000_000 and rows == 100 * 60  # (one sensor's, a hundred hours of them)
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()
    trimmed(again)
    again.stop()
    assert samples_in(tmp_path)[0] == rows  # what is left fits: nothing more goes
    assert history.size_of(tmp_path) <= 1_000_000  # and the pages are given back


def test_a_trim_keeps_as_much_as_fits_where_nearly_all_rows_are_the_newest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Counted by the hundredth of the span and cut at the end of the hundredth where the share fell: an hour of one KVM
    # tried eighty-five days ago, and a day of servers since, put nearly every row into the last hundredth, which went
    # whole: 40 rows were left of 216,000, where 185,000 fitted.
    monkeypatch.setattr(history, "LEAST_MB", 1)
    # (What is tried here is how much one trim takes away, not how fast this computer is: given all the time it needs.
    # A trim's own limit, TRIM_PATIENCE, is held by test_every_trim_gets_on_with_the_size_however_long_the_rows_by_age_take;
    # with its half minute, the whole suites of four Pythons at once beside four on Windows had one trim end at its
    # time with 15 MB of 20 left. It took 4 s alone.)
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    now = time.time()
    trial = ((now - 85 * history.DAY + minute * 60, "trial") for minute in range(60))
    servers = ((now - 18 * 3600 + second, f"sensor {number:02d}") for second in range(0, 18 * 3600, 60) for number in range(40))
    history_of(tmp_path, now - 85 * history.DAY, itertools.chain(trial, servers))
    room = 1_000_000 - 100_000
    assert (tmp_path / history.FILE).stat().st_size > room
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()
    trimmed(again)
    again.stop()
    left, oldest = samples_in(tmp_path)
    on_disk = history.size_of(tmp_path)
    assert room * 0.6 <= on_disk <= 1_000_000, f"{on_disk / 1e6:.2f} MB kept ({left} rows, from {(now - oldest) / 3600:.1f} h back)"


def test_the_cut_of_a_file_far_over_the_size_allowed_keeps_what_fits(tmp_path: Path) -> None:
    # Where all but half a percent of the rows had to go, the cut fell in the last hundredth of the span and took it whole.
    t0 = time.time() - 100 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 100 * 3600, 60) for number in range(20)))
    rows, _ = samples_in(tmp_path)
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        cutoff = History._cutoff(conn, 0.995)
        assert cutoff is not None
        staying = conn.execute("SELECT COUNT(*) FROM samples WHERE t >= ?", (cutoff,)).fetchone()[0]
    conn.close()
    assert 0.004 * rows <= staying <= 0.006 * rows, f"{staying} of {rows} rows stay"


def test_a_trim_keeps_the_state_a_machine_was_in_when_the_window_begins(tmp_path: Path) -> None:
    # The newest state row of a device stayed whatever its age, and the one before it went with the rest: a server online
    # for a hundred days that was refused a sign-in an hour ago had been watched for one hour of this week, and online for none.
    now = time.time()
    kept = History(tmp_path / history.FILE, limits=lambda: (90, 200))
    kept.start()
    kept.observe("server", ONLINE, now=now - 100 * history.DAY)
    kept.observe("server", ONLINE, now=now - 2 * 3600)  # (looked at all along: nothing changed until an hour ago)
    kept.observe("server", {**ONLINE, "state": "auth"}, now=now - 3600)
    kept.flush()
    trimmed(kept)
    week = kept.read("server", "summary", now - history.WEEK, now, now=now)
    assert week["watched"] == pytest.approx(history.WEEK, abs=2) and week["online"] == pytest.approx(history.WEEK - 3600, abs=2), week
    assert [row["state"] for row in rows_of(kept, "states", device="server")] == ["online", "auth"]
    kept.stop()


def test_a_trim_ends_where_more_events_than_it_deletes_at_once_share_one_moment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Deleted so many at a time, older than the time of the row after that many: where more rows than that had the same
    # time (events, which no key keeps apart), nothing was older, nothing went, and the writer went round for ever.
    monkeypatch.setattr(history, "LEAST_MB", 1)  # (the least size: a thousand rows at a time)
    t0 = time.time() - 30 * history.DAY
    kept = History(tmp_path / history.FILE, limits=lambda: (1, 1))
    kept.start()
    kept.observe("dev", ONLINE, now=time.time())
    kept.flush()
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany("INSERT INTO events (device, t, kind, what, ok, note) VALUES ('dev', ?, 'pressed', 'atx_power', 1, '')", [(t0,)] * 1500)
    conn.close()
    trimmed(kept)
    assert kept._waiting.unfinished_tasks == 0, "the trim never ended"
    assert rows_of(kept, "events") == []
    kept.stop()


def test_a_trim_stops_deleting_where_the_wal_file_cannot_be_brought_into_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Something outside qKVM that keeps a read open (a database browser) keeps the -wal file from being brought into the
    # file. The trim gave the pages back no more then, but went on deleting, and every deletion grew the -wal file: 28.8 MB
    # beside a share of 1 MB. It stopped then, but began again at the next trim: half a megabyte more every ten minutes for
    # as long as the read stayed open. Now a trim does nothing while the -wal file is past its share and cannot be brought in.
    monkeypatch.setattr(history, "CHECKPOINT_PATIENCE", 0.2)  # (the read outside will not end: no need to wait long for it)
    t0 = time.time() - 300 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 300 * 3600, 60) for number in range(30)))
    outside = sqlite3.connect(tmp_path / history.FILE)
    outside.execute("BEGIN")
    outside.execute("SELECT COUNT(*) FROM states").fetchall()  # (a read under way, and it stays so)
    wal = tmp_path / (history.FILE + "-wal")
    largest, done = [0], threading.Event()

    def watch() -> None:
        while not done.is_set():
            largest[0] = max(largest[0], wal.stat().st_size if wal.exists() else 0)

    watching = threading.Thread(target=watch, daemon=True)
    watching.start()
    again = History(tmp_path / history.FILE, limits=lambda: (365, 10))
    try:
        again.start()
        for _ in range(4):  # (four trims, as forty minutes would bring)
            trimmed(again)
    finally:
        done.set()
        watching.join(5)
        outside.rollback()
        outside.close()
    again.stop()
    assert largest[0] <= 10 * 1_000_000 // 10, f"the -wal file grew to {largest[0] / 1e6:.1f} MB"


def test_every_trim_gets_on_with_the_size_however_long_the_rows_by_age_take(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The half minute a trim may take was one for both: where the rows by age (and a scan of every table for strays) took
    # all of it, the size was never looked at, at this trim or the next, and the file grew past the size allowed for good.
    # Each part has its own time now, and gets a transaction's worth done at the least. (No time at all here: a slow disk.)
    monkeypatch.setattr(history, "LEAST_MB", 1)  # (a thousand rows a transaction)
    monkeypatch.setattr(history, "TRIM_PATIENCE", -1.0)  # (over before it begins, also by a clock that ticks every 16 ms)
    t0 = time.time() - 72 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 72 * 3600, 60) for number in range(20)))
    before, _ = samples_in(tmp_path)
    for days, from_both in ((365, False), (1, True)):  # the size alone; and rows by age as well
        again = History(tmp_path / history.FILE, limits=lambda days=days: (days, 1))  # type: ignore[misc]
        again.start()
        trimmed(again)
        again.stop()
        left, _ = samples_in(tmp_path)
        assert before - left >= (2000 if from_both else 1000), f"{before - left} rows went in one trim"
        before = left


def test_a_trim_short_of_time_cuts_every_machine_along_one_line_of_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cut device after device, a trim whose time ran out had cut the machines that sort first to the end and none of the
    # others: after forty trims of a slow disk two machines went back ten hours and the rest thirty-six.
    monkeypatch.setattr(history, "LEAST_MB", 1)
    monkeypatch.setattr(history, "TRIM_PATIENCE", -1.0)  # (a slow disk: a transaction's worth a trim)
    t0 = time.time() - 40 * 3600
    history_of(tmp_path, t0, iter(()))
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany(
            "INSERT INTO samples (device, t, sensor, value, unit) VALUES (?, ?, ?, 40, 'C')",
            ((f"dev{machine}", t0 + second, f"sensor {number}") for machine in range(6) for second in range(0, 40 * 3600, 60) for number in range(10)),
        )
        conn.executemany("INSERT INTO devices (device, first_seen) VALUES (?, ?)", [(f"dev{machine}", t0) for machine in range(6)])
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()
    for _ in range(8):
        trimmed(again)
    again.stop()
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        reach = [conn.execute("SELECT MIN(t) FROM samples WHERE device = ?", (f"dev{machine}",)).fetchone()[0] for machine in range(6)]
    conn.close()
    assert max(reach) > t0, "nothing was cut"
    assert max(reach) - min(reach) <= 3 * 3600, f"the machines reach back from {(time.time() - max(reach)) / 3600:.1f} to {(time.time() - min(reach)) / 3600:.1f} h"


def test_a_trim_tries_the_wal_file_at_once_where_a_read_outside_has_ended(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A checkpoint that did not get through is not tried again for a minute, and a trim that began within it did nothing,
    # though the read outside that held the -wal file had ended: ten minutes over the size allowed, to the next trim.
    # Allow the size trim to finish; the checkpoint retry and writer deadline are tested separately.
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    monkeypatch.setattr(history, "CHECKPOINT_PATIENCE", 0.2)
    t0 = time.time() - 300 * 3600
    history_of(tmp_path, t0, ((t0 + second, f"sensor {number:02d}") for second in range(0, 300 * 3600, 60) for number in range(30)))
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany("INSERT INTO samples (device, t, sensor, value, unit) VALUES ('old', ?, ?, 40, 'C')", ((t0 + second, f"s{number}") for second in range(0, 300 * 3600, 60) for number in range(2)))
        conn.execute("INSERT INTO devices (device, first_seen) VALUES ('old', ?)", (t0,))
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    outside = sqlite3.connect(tmp_path / history.FILE)
    outside.execute("BEGIN")
    outside.execute("SELECT COUNT(*) FROM states").fetchall()
    again = History(tmp_path / history.FILE, limits=lambda: (365, 10))
    try:
        again.start()
        again.flush(within=60)
        again.forget("old")  # (deleted to the end, the -wal file growing, its checkpoints refused)
        again.flush(within=60)
    finally:
        outside.rollback()
        outside.close()
    assert (tmp_path / (history.FILE + "-wal")).stat().st_size > 10 * 1_000_000 // 10 // 4
    trimmed(again)  # (within the minute after the last refusal)
    again.stop()
    assert history.size_of(tmp_path) <= 10_000_000, f"{history.size_of(tmp_path) / 1e6:.1f} MB"


def test_rows_of_a_device_the_file_has_no_row_of_go_by_size_as_well(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Rows of a device without its devices row (forgotten before the forget was kept apart, or whose first row found the
    # queue full) went by age only: the machines on the wall were cut to fit around them, and the file stayed over the size.
    monkeypatch.setattr(history, "LEAST_MB", 1)
    # (What is tried here is how much one trim takes away, not how fast this computer is: given all the time it needs.
    # A trim's own limit, TRIM_PATIENCE, is held by test_every_trim_gets_on_with_the_size_however_long_the_rows_by_age_take;
    # with its half minute, the whole suites of four Pythons at once beside four on Windows had one trim end at its
    # time with 15 MB of 20 left. It took 4 s alone.)
    monkeypatch.setattr(history, "TRIM_PATIENCE", 600.0)
    now = time.time()
    history_of(tmp_path, now - 100 * 3600, ((now - 100 * 3600 + second, f"sensor {number:02d}") for second in range(0, 100 * 3600, 60) for number in range(10)))
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        conn.executemany(
            "INSERT INTO samples (device, t, sensor, value, unit) VALUES ('stray', ?, ?, 40, 'C')",
            ((now - 30 * 3600 + second, f"sensor {number:02d}") for second in range(0, 30 * 3600, 60) for number in range(20)),
        )
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    again = History(tmp_path / history.FILE, limits=lambda: (365, 1))
    again.start()
    trimmed(again)
    again.stop()
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        (strays, stray_oldest), (_, dev_oldest) = (conn.execute("SELECT COUNT(*), MIN(t) FROM samples WHERE device = ?", (device,)).fetchone() for device in ("stray", "dev"))
    conn.close()
    assert history.size_of(tmp_path) <= 1_000_000 and strays < 36_000
    assert abs(stray_oldest - dev_oldest) <= 3600, "the stray and the machine on the wall were not cut at one time"


def test_a_file_moved_aside_stays_as_long_as_the_history_from_when_it_was_moved(tmp_path: Path) -> None:
    # It went by its own time, which is when it was last written (and stays so through the move): a damaged history last
    # written three days ago, kept for one day, was moved aside and deleted in the same minute, never there to be looked at.
    damaged = tmp_path / history.FILE
    damaged.write_bytes(b"not a database at all, whatever the name says" * 50)
    three_days_ago = time.time() - 3 * history.DAY
    os.utime(damaged, (three_days_ago, three_days_ago))
    kept = History(damaged, limits=lambda: (1, 200))
    kept.start()
    kept.observe("dev", ONLINE)
    kept.flush()
    trimmed(kept)
    assert kept.damaged is not None and kept.damaged.exists(), "moved aside and deleted at once"
    # One moved aside two days ago, as its name says, goes; and a file of that kind of name that this program did not name stays.
    longer_ago = tmp_path / f"history.damaged-{int(time.time() - 2 * history.DAY)}.sqlite"
    longer_ago.write_bytes(b"x")
    (tmp_path / (longer_ago.name + "-wal")).write_bytes(b"x")
    not_ours = tmp_path / "history.damaged-mine.sqlite"
    not_ours.write_bytes(b"x")
    trimmed(kept)
    assert not longer_ago.exists() and not (tmp_path / (longer_ago.name + "-wal")).exists()
    assert kept.damaged.exists() and not_ours.exists()
    kept.stop()


def test_two_files_moved_aside_in_one_second_are_both_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Named by the second alone, the second one replaced the first.
    stopped = time.time()
    monkeypatch.setattr(history, "time", SimpleNamespace(time=lambda: stopped, monotonic=time.monotonic, sleep=time.sleep))
    kept = History(tmp_path / history.FILE)
    for number in range(3):
        (tmp_path / history.FILE).write_bytes(f"damaged history number {number}".encode() * 50)
        assert kept._move_aside("a test")
    aside = sorted(tmp_path.glob("history.damaged-*.sqlite"), key=lambda path: path.read_bytes())
    assert [path.read_bytes() for path in aside] == [f"damaged history number {n}".encode() * 50 for n in range(3)]
    assert history.aside_in(tmp_path)[0] == 3


def test_a_row_the_tables_refuse_is_a_slip_of_the_program_and_no_damage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Every DatabaseError was taken for a damaged file, a constraint a row breaks as well: a slip in the shape of a row
    # would move a healthy history aside at every row of that shape, and the trim later deleted it.
    t0 = time.time() - 60
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("dev", ONLINE, now=t0)
    kept.flush()
    writes = History._write_one
    slip = [True]

    def without_a_state(conn: sqlite3.Connection, row: tuple[Any, ...]) -> None:
        if slip and row[0] == "state":
            slip.clear()
            row = (*row[:3], None, row[4])  # (a state of None: the table refuses it, as SQLite says, IntegrityError)
        writes(conn, row)

    monkeypatch.setattr(History, "_write_one", staticmethod(without_a_state))
    with heard() as said:
        kept.observe("dev", OFFLINE, now=t0 + 10)
        kept.flush(within=10)
        kept.observe("dev", ONLINE, now=t0 + 20)
        kept.flush(within=10)
    assert kept.damaged is None and list(tmp_path.glob("history.damaged-*")) == [], said
    assert any("starts afresh" in line for line in said), said
    assert [round(row["t"] - t0) for row in rows_of(kept, "states")] == [0, 20]  # the history before it is all there
    # The same of a slip in the trim: said, and the file kept.
    monkeypatch.undo()

    def slipping(conn: sqlite3.Connection) -> None:
        raise sqlite3.ProgrammingError("a slip of the program's own in the trim")

    monkeypatch.setattr(kept, "_trim", slipping)
    with heard() as said:
        trimmed(kept)
    assert kept.damaged is None and list(tmp_path.glob("history.damaged-*")) == [], said
    assert any("could not be trimmed" in line for line in said), said
    assert [round(row["t"] - t0) for row in rows_of(kept, "states")] == [0, 20]
    kept.stop()


def test_a_machine_taken_off_while_the_queue_is_full_takes_its_history_with_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Taking a machine's history away was a row of the queue like any other, and of a full queue rows are dropped: its rows
    # stayed for good (its newest state, and when it was last seen, are never trimmed).
    t0 = time.time() - 600
    kept = History(tmp_path / history.FILE)
    kept.start()
    kept.observe("gone", ONLINE, now=t0)
    kept.pressed("gone", "atx_power", True, now=t0 + 1)
    kept.flush()
    stalled, in_the_write = threading.Event(), threading.Event()
    writes = kept._write

    def hung(rows: list[tuple[Any, ...]]) -> None:
        in_the_write.set()
        stalled.wait(30)
        writes(rows)

    monkeypatch.setattr(kept, "_write", hung)
    kept.observe("other", ONLINE, now=t0 + 2)
    assert in_the_write.wait(5), "the writer never took the row"
    kept.observe("gone", OFFLINE, now=t0 + 3)  # (noted before it was taken off, and written after)
    number = 0
    while not kept._waiting.full():
        number += 1
        kept.observe("other", ONLINE if number % 2 else OFFLINE, now=t0 + 4 + number / 1000)
    kept.forget("gone")
    stalled.set()
    kept.flush(within=30)
    assert kept._waiting.unfinished_tasks == 0
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE device = 'gone'").fetchone()[0] for table in ("states", "samples", "events", "devices")}
    conn.close()
    assert counts == {"states": 0, "samples": 0, "events": 0, "devices": 0}
    assert kept.read("other", "summary", t0, t0 + 600)["state"] in ("online", "offline")  # (and the others' rows are written)
    kept.stop()


# --- the wall -------------------------------------------------------------------------------------------------


def hist(device_id: str, **query: Any) -> str:
    return f"/api/v1/devices/{device_id}/history" + ("?" + "&".join(f"{k}={v}" for k, v in query.items()) if query else "")


def seen(client: TestClient, device_id: str, state: str = "online") -> None:
    """Wait until the history has the machine in this state: what the page's own looks at the status put there."""

    def there() -> bool:
        client.get("/api/v1/status")
        reply = client.get(hist(device_id))
        return reply.status_code == 200 and reply.json()["state"] == state

    wait_until(there, f"the history never saw {device_id} {state}", timeout=10)


def test_the_route_tells_what_the_wall_saw_to_those_who_may_see_the_machine(tmp_path: Path, fake: FakeKvm) -> None:
    other = FakeKvm(FakeState(colour=(10, 20, 30))).start()
    try:
        with wall(tmp_path) as admin:
            one = add(admin, fake.url, name="One", group="rack 1")
            two = add(admin, other.url, name="Two", group="rack 2")
            seen(admin, one)
            seen(admin, two)
            wait_until(lambda: admin.get(hist(one)).json()["watched"] >= 1, "a second of watching never came")
            summary = admin.get(hist(one)).json()
            assert summary["state"] == "online" and summary["share"] == 1.0 and summary["online"] == summary["watched"] >= 1
            assert summary["sensors"] == ["device"]  # the KVM's own temperature, as the stand-in reports it
            assert summary["until"] - summary["since"] == pytest.approx(history.WEEK)
            states = admin.get(hist(one, what="states")).json()
            assert states["rows"][-1]["state"] == "online" and states["more"] is False
            samples = admin.get(hist(one, what="samples")).json()
            assert samples["rows"] and samples["rows"][0]["sensor"] == "device" and samples["rows"][0]["value"] == 42.5
            assert samples["until"] - samples["since"] == pytest.approx(history.DAY)
            series = admin.get(hist(one, what="samples", every=900)).json()["series"]
            assert [(each["sensor"], each["unit"], len(each["points"])) for each in series] == [("device", "C", 1)]
            # A power button pressed from the wall is an event, taken or not; a key is not.
            assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "atx_power"}).status_code == 200
            assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "keys", "keys": "KeyA"}).status_code == 200
            refused = admin.post(f"/api/v1/devices/{two}/actions", json={"action": "atx_power"})  # no power board on that one
            assert refused.status_code >= 400, refused.text
            wait_until(lambda: admin.get(hist(two, what="events")).json()["rows"], "the refused press never reached the history")
            events = admin.get(hist(one, what="events")).json()["rows"]
            assert [(row["kind"], row["what"], row["ok"], row["note"]) for row in events] == [("pressed", "atx_power", True, "")]
            (failed,) = admin.get(hist(two, what="events")).json()["rows"]
            assert (failed["kind"], failed["what"], failed["ok"], failed["note"]) == ("pressed", "atx_power", False, refused.json()["code"])
            # Nothing in any row is more than the device's id, a state, a code, a number: no name, no address, no secret.
            everything = json.dumps([admin.get(hist(one, what=what)).json() for what in ("summary", "states", "samples", "events")])
            assert "One" not in everything and "127.0.0.1" not in everything and "secret" not in everything
            keys = {key for what in ("states", "samples", "events") for row in admin.get(hist(one, what=what)).json()["rows"] for key in row}
            assert keys == {"t", "state", "code", "sensor", "unit", "value", "kind", "what", "ok", "note"}  # (as the README lists them)

            # Who may read it: whoever may see the machine, and nobody else; a token as a script, within its machines.
            account(admin, "victor", "viewer", devices=[one])
            account(admin, "olga", "operator", devices=[], groups=["rack 2"])
            victor, olga = browser(admin, "victor"), browser(admin, "olga", port=50002)
            assert victor.get(hist(one)).status_code == 200 and victor.get(hist(two)).status_code == 404
            assert olga.get(hist(two)).status_code == 200 and olga.get(hist(one)).status_code == 404
            assert olga.get(hist(two, what="events")).status_code == 200
            token = admin.post("/api/v1/tokens", json={"name": "graphs", "role": "viewer", "devices": [two]}).json()["token"]
            runner = script(admin, token)
            assert runner.get(hist(two)).status_code == 200 and runner.get(hist(one)).status_code == 404
            assert runner.get(hist("nobody")).status_code == 404
            assert script(admin, None, port=51001).get(hist(one)).status_code == 401
            # What is asked for is checked: a window that ends before it begins, a page of nothing, a kind nobody has.
            assert admin.get(hist(one, since=200, until=100)).status_code == 422
            assert admin.get(hist(one, limit=0)).status_code == 422
            assert admin.get(hist(one, what="everything")).status_code == 422
            assert admin.get(hist(one, since="yesterday")).status_code == 422
    finally:
        other.stop()


def test_a_machine_removed_from_the_wall_takes_its_history_with_it(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        one = add(admin, fake.url)
        seen(admin, one)
        assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "atx_power"}).status_code == 200
        kept: History = admin.core.history  # type: ignore[attr-defined]
        store = admin.core.store  # type: ignore[attr-defined]
        kept.flush()
        # Removed while a read of it is under way: what the read found is not handed over.
        record = store.device(one)
        reads = kept.read

        def read_while_it_goes(*given: Any, **more: Any) -> dict[str, Any]:
            found = reads(*given, **more)
            store.devices.remove(record)  # (as the route that removes a device does, with the turn for changes; here, bluntly)
            return found

        monkeypatch.setattr(kept, "read", read_while_it_goes)
        assert admin.get(hist(one)).status_code == 404
        monkeypatch.undo()
        store.devices.append(record)
        assert admin.get(hist(one)).status_code == 200
        assert admin.delete(f"/api/v1/devices/{one}").status_code == 200
        assert admin.get(hist(one)).status_code == 404
        kept.flush()
        with sqlite3.connect(tmp_path / history.FILE) as conn:
            counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE device = ?", (one,)).fetchone()[0] for table in ("states", "samples", "events", "devices")}
        conn.close()
        assert counts == {"states": 0, "samples": 0, "events": 0, "devices": 0}


def test_so_many_reads_at_once_and_the_next_is_told_to_come_back(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "HISTORY_READS_AT_ONCE", 1)
    with wall(tmp_path) as admin:
        one = add(admin, fake.url)
        seen(admin, one)
        kept: History = admin.core.history  # type: ignore[attr-defined]
        reads, hold = kept.read, threading.Event()

        def slowly(*given: Any, **more: Any) -> dict[str, Any]:
            hold.wait(5)
            return reads(*given, **more)

        monkeypatch.setattr(kept, "read", slowly)
        account(admin, "victor", "viewer")
        other = browser(admin, "victor", port=50003)  # (somebody else: a second read of the same account waits its turn instead)
        answers: list[int] = []
        first = threading.Thread(target=lambda: answers.append(admin.get(hist(one)).status_code))
        first.start()
        wait_until(lambda: not kept._waiting.unfinished_tasks and hold is not None, "")  # (a moment for the first to get its thread)
        time.sleep(0.3)
        second = other.get(hist(one))
        hold.set()
        first.join(10)
        assert answers == [200] and (second.status_code, second.json()["code"]) == (503, "busy") and second.headers["Retry-After"] == "2"
        assert admin.get(hist(one)).status_code == 200  # the moment over, it is answered again


def test_one_account_or_token_reads_one_at_a_time_and_cannot_keep_everybody_else_out(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Three reads at once were answered, from everybody together, and no more: a viewer whose token asked three times at
    # once, again and again, had all three, and every other account was told to come back (every enlarged view too).
    with wall(tmp_path) as admin:
        one = add(admin, fake.url)
        seen(admin, one)
        kept: History = admin.core.history  # type: ignore[attr-defined]
        reads, hold = kept.read, threading.Event()
        under_way: list[str] = []
        times: list[tuple[float, float]] = []

        def held(*given: Any, **more: Any) -> dict[str, Any]:
            began = time.monotonic()
            under_way.append("read")
            hold.wait(10)
            try:
                return reads(*given, **more)
            finally:
                times.append((began, time.monotonic()))

        monkeypatch.setattr(kept, "read", held)
        token = admin.post("/api/v1/tokens", json={"name": "graphs", "role": "viewer", "devices": [one]}).json()["token"]
        scripts = [script(admin, token, port=51010 + n) for n in range(3)]
        answers: dict[str, Any] = {}

        def ask(name: str, client: TestClient) -> threading.Thread:
            asking = threading.Thread(target=lambda: answers.__setitem__(name, client.get(hist(one, what="states"))), daemon=True)
            asking.start()
            return asking

        first = ask("first", scripts[0])
        wait_until(lambda: len(under_way) == 1, "the first read never began")
        # Two more at once: whichever comes first waits its turn, and the other, with one under way and one waiting, is
        # told to come back at once.
        others = [ask("second", scripts[1]), ask("third", scripts[2])]
        wait_until(lambda: "second" in answers or "third" in answers, "neither of the token's next two reads was answered", timeout=10)
        refused = answers["second"] if "second" in answers else answers["third"]
        assert (refused.status_code, refused.json().get("code"), refused.headers.get("Retry-After")) == (503, "busy", "2"), "the token had a second read under way, or a third"
        everybody = ask("admin", admin)  # and anybody else is answered meanwhile
        wait_until(lambda: len(under_way) >= 2, "nobody else's read began while the token's was under way")
        assert len(under_way) == 2  # (the token's first, and the admin's: not the token's next)
        hold.set()
        for asking in (first, *others, everybody):
            asking.join(30)
        assert sorted(answers[name].status_code for name in ("first", "second", "third", "admin")) == [200, 200, 200, 503]
        # The token's waiting read began after its first had ended, and after a pause as long again as the first took.
        (first_began, first_ended), *_ = sorted(times)
        next_began = sorted(times)[-1][0]
        assert next_began >= first_ended + (first_ended - first_began) - 0.05


def test_a_machine_whose_adding_was_not_saved_leaves_no_history(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Looked at while the settings were being written, a machine whose adding then failed (the disk full) was taken off the
    # wall again and its rows stayed in the history for good: nothing had told the history to forget it.
    with wall(tmp_path) as admin:
        kept: History = admin.core.history  # type: ignore[attr-defined]
        before = {device["id"] for device in admin.core.store.snapshot()["devices"]}  # type: ignore[attr-defined]
        noted: list[str] = []

        def full(self: Store, data: dict[str, Any]) -> None:
            for device in data.get("devices", []):
                if device["id"] not in before:
                    kept.observe(device["id"], ONLINE)  # (its tile looked at meanwhile, as the wall does)
                    noted.append(device["id"])
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
        refused = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"})
        plain = {"format": exchange.FORMAT, "version": 1, "devices": [{"url": "http://127.0.0.1:9", "kind": "kvmd", "name": "Nowhere"}]}
        not_taken = admin.post("/api/v1/import", json={"file": json.dumps(plain), "take": ["devices"]})
        monkeypatch.undo()
        assert (refused.status_code, not_taken.status_code) == (507, 507) and len(noted) == 2
        kept.flush()
        with sqlite3.connect(tmp_path / history.FILE) as conn:
            left = {table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE device IN (?, ?)", noted).fetchone()[0] for table in ("states", "samples", "events", "devices")}
        conn.close()
        assert left == {"states": 0, "samples": 0, "events": 0, "devices": 0}


def test_the_history_is_written_down_when_the_wall_stops_and_swept_while_it_runs(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "HISTORY_LOOK_EVERY", 0.1)
    swept: list[float] = []
    with wall(tmp_path) as admin:
        one = add(admin, fake.url)
        kept: History = admin.core.history  # type: ignore[attr-defined]
        monkeypatch.setattr(kept, "sweep", lambda now=None: swept.append(time.time()))
        seen(admin, one)
        wait_until(lambda: len(swept) >= 2, "the history never swept for machines nobody looks at")
    # Stopped: what was noted is in the file, and the file is whole by itself (its -wal file holds nothing more).
    assert kept._waiting.unfinished_tasks == 0
    assert (tmp_path / (history.FILE + "-wal")).stat().st_size == 0
    with sqlite3.connect(tmp_path / history.FILE) as conn:
        looked, state = conn.execute("SELECT looked, state FROM devices WHERE device = ?", (one,)).fetchone()
    conn.close()
    assert state == "online" and time.time() - looked < 30


def test_the_history_looks_by_itself_while_nobody_does(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "HISTORY_LOOK_EVERY", 0.1)
    with wall(tmp_path) as admin:
        one = add(admin, fake.url)
        # Nobody asks for the status, no alerts are on: the history's own look is the only one.
        wait_until(lambda: admin.get(hist(one)).json()["state"] == "online", "the history never looked by itself", timeout=10)
        wait_until(lambda: admin.get(hist(one)).json()["watched"] >= 1, "nothing was counted as watched", timeout=10)


def test_the_limits_come_from_the_settings_file(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        kept: History = admin.core.history  # type: ignore[attr-defined]
        assert kept._limits() == (90, 200)
    saved = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))
    assert (saved["server"]["history_days"], saved["server"]["history_mb"]) == (90, 200)
    saved["server"]["history_days"], saved["server"]["history_mb"] = 7, 50
    for name in ("qkvm.json", "qkvm.bak"):
        write_settings_text(tmp_path / name, json.dumps(saved), encoding="utf-8")
    with wall(tmp_path) as admin:
        assert admin.core.history._limits() == (7, 50)  # type: ignore[attr-defined]


def test_a_servers_sensors_and_its_power_are_kept(tmp_path: Path) -> None:
    bmc = FakeBmc(BmcState(cpu_temperature=61)).start()
    try:
        with wall(tmp_path) as admin:
            one = add(admin, bmc.url, username="admin", password=bmc.state.password, kind="auto")
            seen(admin, one)
            summary = admin.get(hist(one)).json()
            assert set(summary["sensors"]) >= {"CPU0_TEMP", "CPU1_TEMP", "CPU0_FAN", "device"} and summary["power"] == "on"
            fans = [row for row in admin.get(hist(one, what="samples")).json()["rows"] if row["unit"] == "RPM"]
            assert {row["sensor"] for row in fans} == {"CPU0_FAN", "CPU1_FAN"}
            # Switched off from the wall: the press, and then the state its controller shows, are both events.
            assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "power_off"}).status_code == 200
            seen(admin, one, "no_signal")
            wait_until(lambda: len(admin.get(hist(one, what="events")).json()["rows"]) >= 2, "the power events never came")
            events = admin.get(hist(one, what="events")).json()["rows"]
            assert [(row["kind"], row["what"]) for row in events] == [("pressed", "power_off"), ("power", "off")]
    finally:
        bmc.stop()


def test_a_press_is_kept_at_the_moment_it_was_pressed_where_the_wall_waits_to_see_it_done(tmp_path: Path) -> None:
    # Switching a PC on is waited for until the PC is seen on (13 s on a real one with Intel AMT): the press was written when
    # that wait ended, after the "on" the tile had seen meanwhile, and the history read as if the PC came on before anybody
    # pressed anything.
    pc = FakeAmt(AmtState(power=8, power_takes=2.0)).start()
    try:
        with wall(tmp_path) as admin:
            one = add(admin, pc.url)
            seen(admin, one, "no_signal")
            pressed_at = time.time()
            assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "power_on"}).status_code == 200
            assert time.time() - pressed_at >= 1.5  # (done means seen: it waited)
            seen(admin, one)
            wait_until(lambda: len(admin.get(hist(one, what="events")).json()["rows"]) >= 2, "the power events never came")
            events = admin.get(hist(one, what="events")).json()["rows"]
            assert [(row["kind"], row["what"]) for row in events] == [("pressed", "power_on"), ("power", "on")]
            assert events[0]["t"] - pressed_at < 0.5
    finally:
        pc.stop()


def test_a_kvm_without_a_power_board_has_no_power_in_its_history(tmp_path: Path) -> None:
    # A KVM that says it has no power board (a GL.iNet Comet without its ATX board says "power": false all the same) was kept
    # as switched off.
    bare = FakeKvm(FakeState(atx=False)).start()
    try:
        with wall(tmp_path) as admin:
            one = add(admin, bare.url)
            seen(admin, one)
            wait_until(lambda: admin.get(hist(one)).json()["watched"] >= 1, "nothing was counted as watched")
            assert admin.get(hist(one)).json()["power"] is None
            assert admin.get(hist(one, what="events")).json()["rows"] == []
    finally:
        bare.stop()


def test_qkvm_status_says_how_large_the_history_is(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    assert not any(line.startswith("  the history takes ") for line in capsys.readouterr().out.splitlines())
    (tmp_path / history.FILE).write_bytes(b"x" * 2_500_000)
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    said = capsys.readouterr().out
    assert "the history takes 2.5 MB" in said and "could not be read" not in said
    (tmp_path / "history.damaged-1700000000.sqlite").write_bytes(b"x" * 500_000)
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    assert "and 1 copy of it that could not be read takes 500 kB" in capsys.readouterr().out
    assert sorted(p.name for p in tmp_path.iterdir()) == ["history.damaged-1700000000.sqlite", history.FILE]  # asking changed nothing in the folder
