"""The activity log's index (activity.py): the same entries as its text files, in SQLite, for the page's filters and search.

The text files stay the record: written first, never rewritten, read where the index is behind or broken. The index is
made from them and from nothing else: made again where it is damaged or missing, made at the first start from the files
0.1.x wrote, never holding more than they hold, and never in the way of the text log or of the wall. Then the wall: the
filters by machine, account, kind and time, the download, one read at a time of each account, what is written down now
that was not, the size the settings give the log, and a search of a long log answered without reading it all.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import random
import sqlite3
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import activity, cli, kvm, store, update, vault
from qkvm.store import AuditLog
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_users import account, browser
from tests.test_wall import PASSWORD, add, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    device = FakeKvm(FakeState(atx=True)).start()
    yield device
    device.stop()


@pytest.fixture
def followed(tmp_path: Path) -> Iterator[tuple[AuditLog, activity.Index]]:
    """A text log of small files (rotated every few kB), and its index, started; stopped at the end."""
    text = AuditLog(tmp_path / "audit.log", max_bytes=4000)
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    index.start()
    yield text, index
    index.stop()


def in_index(folder: Path) -> int:
    """How many entries the index file in `folder` holds, read by SQLite itself."""
    with sqlite3.connect(folder / activity.FILE) as conn:
        count = int(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0])
    conn.close()
    return count


def caught_up(index: activity.Index, within: float = 30.0) -> None:
    assert index.caught_up(within) is not None, "the index did not take in what the text files hold"


def everything(text: AuditLog) -> list[dict[str, Any]]:
    return text.tail(10**9)


# --- what 0.1.x wrote, and what a busy wall writes -------------------------------------------------------------------


def old_entries(start: float, machines: list[str], count: int, seed: int = 1) -> list[dict[str, Any]]:
    """Entries as 0.1.x wrote them: a machine by its name only, no id."""
    rng = random.Random(seed)
    made: list[dict[str, Any]] = []
    for number in range(count):
        at = start + number * 60.0
        pick = number % 5
        if pick == 0:
            made.append({"time": at, "event": "alert", "ip": "", "device": rng.choice(machines), "state": "offline", "was": "online"})
        elif pick == 1:
            made.append({"time": at, "event": "action", "ip": "192.168.1.20", "user": rng.choice(("olga", "ivan")), "device": rng.choice(machines), "action": "atx_power"})
        elif pick == 2:
            made.append({"time": at, "event": "login", "ip": "192.168.1.20", "user": rng.choice(("olga", "ivan", "admin"))})
        elif pick == 3:
            made.append({"time": at, "event": "device_changed", "ip": "192.168.1.21", "user": "admin", "device": rng.choice(machines), "url": "https://192.168.1.40"})
        else:
            made.append({"time": at, "event": "login_failed", "ip": "192.168.1.99", "user": "olga"})
    return made


def written(folder: Path, entries: list[dict[str, Any]], files: int) -> None:
    """The entries into `files` text files as the writer rotates them: the oldest in audit.log.<files - 1>, the newest in audit.log."""
    names = [f"audit.log.{number}" for number in range(files - 1, 0, -1)] + ["audit.log"]
    each = -(-len(entries) // files)
    for number, name in enumerate(names):
        (folder / name).write_bytes(b"".join((json.dumps(entry) + "\n").encode() for entry in entries[number * each : (number + 1) * each]))


BUSY_MACHINES = [(f"rack{number // 16 + 1}-node{number % 16 + 1:02d}", f"{number * 2654435761 % 2**32:08x}") for number in range(64)]


def busy_lines(megabytes: float, end: float, seed: int = 4) -> list[bytes]:
    """The last `megabytes` of a busy wall's activity log ending at `end`, in the shapes the program writes (the hand-back of
    W4c has the model: 64 machines with alerts, three operators and an admin, about 1,200 entries a day)."""
    rng = random.Random(seed)
    users, addresses = ("operator1", "operator2", "operator3"), ("192.0.2.21", "192.0.2.22", "192.0.2.23")
    lines: list[bytes] = []
    size, day = 0, 0
    while size < megabytes * 1_000_000:
        start = end - (day + 1) * 86400
        entries: list[dict[str, Any]] = []
        for number, (name, ident) in enumerate(BUSY_MACHINES):
            for change in range(48 if number < 4 else 4):
                entries.append({"time": start + rng.random() * 86400, "event": "alert", "ip": "", "device": name, "device_id": ident, "state": ("offline", "online")[change % 2], "was": ("online", "offline")[change % 2]})
        for person, address in zip(users, addresses, strict=True):
            for _ in range(40):
                name, ident = rng.choice(BUSY_MACHINES)
                opened = start + rng.random() * 86000
                entries.append({"time": opened, "event": "live_opened", "ip": address, "user": person, "device": name, "device_id": ident})
                entries.append({"time": opened + 300, "event": "live_closed", "ip": address, "user": person, "device": name, "device_id": ident, "seconds": 300, "why": "closed"})
            for _ in range(60):
                name, ident = rng.choice(BUSY_MACHINES)
                entries.append({"time": start + rng.random() * 86400, "event": "action", "ip": address, "user": person, "device": name, "device_id": ident, "action": rng.choice(("keys", "atx_power", "reboot", "jiggler_on"))})
            for _ in range(7):
                entries.append({"time": start + rng.random() * 86400, "event": "login", "ip": address, "user": person})
        for _ in range(2):
            entries.append({"time": start + rng.random() * 86400, "event": "login", "ip": "192.0.2.5", "user": "admin"})
        entries.sort(key=lambda entry: float(entry["time"]))
        day_lines = [(json.dumps(entry) + "\n").encode() for entry in entries]
        lines[:0] = day_lines
        size += sum(len(line) for line in day_lines)
        day += 1
    while size > megabytes * 1_000_000:
        size -= len(lines.pop(0))
    return lines


def written_lines(folder: Path, lines: list[bytes], files: int = 10) -> None:
    names = [f"audit.log.{number}" for number in range(files - 1, 0, -1)] + ["audit.log"]
    each = -(-len(lines) // files)
    for number, name in enumerate(names):
        (folder / name).write_bytes(b"".join(lines[number * each : (number + 1) * each]))


# --- the index by itself ---------------------------------------------------------------------------------------------


ODD = [
    b'{"time": 1700000000.5, "event": "login", "ip": "", "user": "O\\u0301lga", "note": "caf\\u00e9 STRASSE stra\\u00dfe"}',
    b'{"time": 1700000001, "event": "action", "ip": "", "user": "half \\ud800 a character", "device": "x\\u0000y", "action": "keys"}',
    b'{"time": 1700000002, "event": "action", "ip": "", "user": "ivan", "device": "rack-1", "device_id": 7, "action": "reboot"}',
    b'{"time": 1700000003, "event": "login", "ip": "", "x": NaN}',
    b'{"time": 1700000004, "event": "login", "ip": "", "x": 1e999}',
    b'{"time": 1700000005, "event": "login", "ip": "", "more": {"a": {"b": {"c": [1]}}}}',
    b'{"time": 1700000006, "event": "login", "ip": "", "more": {"a": [1, 2]}, "flag": true}',
    b"not json at all",
    b"",
    b'{"time": 1700000007, "event": "logout", "ip": "", "user": "\xff\xfeolga"}',
    b'{"time": 1700000008, "event": "login", "ip": "", "user": "' + b"a" * 70_000 + b'"}',
    b'{"time": 1700000009, "event": "login", "ip": "", "user": "olga"}\r',
    b'{"time": 1700000010, "event": "login", "ip": ""}\r{"time": 1700000011, "event": "login", "ip": ""}',
]
WORDS = ["olga", "OLGA", "rack", "STRASSE", "strasse", chr(0xE9), "caf", "x y", "true", "keys", "reboot", "none", "1700000005", "'b'", "a" * 5, " "]


def test_the_index_answers_every_question_as_the_text_files_do(tmp_path: Path) -> None:
    # The index must never say what the text files do not: an entry they do not hold, one left out, another order, another
    # entry for the same question. Every kind of line the reading of the text files meets (other cases, characters SQLite
    # cannot keep as they are, numbers that are none, lines too long, cut, joined, nested), rotated over several files,
    # asked every way the page and the API ask, by the index and by the text files: the same answers, in the same order.
    text = AuditLog(tmp_path / "audit.log", max_bytes=3000)
    rng = random.Random(7)
    machines = [("rack-1", "0000aaaa"), ("rack-2", "0000bbbb"), ("Rack-1", None)]
    for number in range(400):
        name, ident = rng.choice(machines)
        detail: dict[str, Any] = {"user": rng.choice(["olga", "Olga", "ivan", "admin (token)"]), "device": name}
        if ident is not None and number % 3:
            detail["device_id"] = ident
        text.write(rng.choice(["action", "alert", "login", "live_opened", "device_changed", "export_made", "unheard_of"]), "192.168.1.5", **detail, n=number)
        if number % 37 == 0:
            text.flush(60)
            with (tmp_path / "audit.log").open("ab") as file:
                file.write(rng.choice(ODD) + b"\n")
    text.flush(60)
    with (tmp_path / "audit.log").open("ab") as file:
        file.write(b'{"time": 1800000000, "event": "login", "ip": "", "user": "the last one, as it stands"}')  # (no line feed yet)
    index = activity.Index(tmp_path / activity.FILE, text)
    index.start()
    try:
        caught_up(index)
        assert len(list(tmp_path.glob("audit.log*"))) >= 5
        questions: list[activity.Asked] = [activity.Asked()]
        for _ in range(250):
            chosen = rng.choice([None, *machines])
            questions.append(
                activity.Asked.of(
                    rng.sample(WORDS, rng.randint(0, 2)),
                    rng.choice(["", *activity.KIND_NAMES]),
                    before=rng.choice([None, None, rng.uniform(1.7e9, 1.9e9), float("nan"), float("inf")]),
                    since=rng.choice([None, rng.uniform(1.7e9, 1.8e9)]),
                    until=rng.choice([None, rng.uniform(1.8e9, 1.9e9)]),
                    user=rng.choice([None, "olga", "OLGA", "ivan", "admin (token)", "nobody"]),
                    device_id=chosen[1] if chosen else None,
                    device_name=chosen[0] if chosen and rng.random() < 0.7 else None,
                )
            )
        for asked in questions:
            limit = rng.choice([1, 5, 50, 10_000])
            found = index.read(asked, limit)
            by_text = text.tail(limit + 1, lambda entry, asked=asked: asked.wants(activity.Facts.of(entry)))  # type: ignore[misc]
            assert found.by == "index"
            assert (found.entries, found.more) == (by_text[:limit], len(by_text) > limit), asked
            pages = [entry for page in iter(index.pager(asked).next, None) for entry in page]
            assert pages == text.tail(10**9, lambda entry, asked=asked: asked.wants(activity.Facts.of(entry))), asked  # type: ignore[misc]
        # (The newest file's last line, not ended: an entry for neither until it has ended, which the writer sees to.)
        assert "the last one, as it stands" not in str(index.read(activity.Asked(), 10**6).entries)
    finally:
        index.stop()


def test_the_index_never_holds_more_than_the_text_files_and_keeps_to_their_size(followed: tuple[AuditLog, activity.Index], tmp_path: Path) -> None:
    # The text files are ten of a few kB here: written on for long enough, the oldest goes again and again. What it held goes
    # from the index too (the index is never more than the text files: made again from them, it would say less), and the
    # index's file stops growing once the text files have.
    text, index = followed
    sizes = []
    for round_ in range(12):
        for number in range(150):
            text.write("action", "192.168.1.5", user="olga", device="rack-1", device_id="0000aaaa", n=round_ * 150 + number)
        text.flush(60)
        caught_up(index)
        assert in_index(tmp_path) == len(everything(text))
        with sqlite3.connect(tmp_path / activity.FILE) as conn:  # (what it takes, the -wal file's pages counted: as SQLite sees it)
            sizes.append(conn.execute("PRAGMA page_count").fetchone()[0])
        conn.close()
    numbers = [entry["n"] for entry in index.read(activity.Asked(), 10**6).entries]
    assert numbers == [entry["n"] for entry in everything(text)] and numbers[0] == 1799 and numbers[-1] > 1000  # (the oldest went, from both)
    assert len(list(tmp_path.glob("audit.log*"))) == 10
    assert max(sizes[6:]) <= 1.5 * sizes[5], sizes


def test_a_damaged_index_is_made_again_from_the_text_files(tmp_path: Path, fake: FakeKvm) -> None:
    # An index whose file is garbage, cut short, or whose pages were written over: made again from the text files, which
    # hold every entry, at the start; the page then finds all of it by the machine and the account it asks for.
    with wall(tmp_path) as admin:
        one = add(admin, fake.url, name="rack-1")
        account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        for _ in range(3):
            assert olga.post(f"/api/v1/devices/{one}/actions", json={"action": "reboot"}).status_code == 200
    held = len(AuditLog(tmp_path / "audit.log").tail(10**6))
    damages = {
        "garbage": lambda data: b"this is no database at all" * 200,
        "cut short": lambda data: data[: len(data) // 3],
        "written over": lambda data: data[:4096] + random.Random(3).randbytes(len(data) - 4096),  # (all but its first page)
    }
    for name, damage in damages.items():
        path = tmp_path / activity.FILE
        path.write_bytes(damage(path.read_bytes()))
        for tail in ("-wal", "-shm"):
            (tmp_path / (activity.FILE + tail)).unlink(missing_ok=True)
        with wall(tmp_path, sign_in=False) as admin:
            assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200  # (two accounts now: by name)
            index: activity.Index = admin.core.activity  # type: ignore[attr-defined]
            caught_up(index)
            mine = admin.get("/api/v1/audit", params={"device": one, "user": "olga", "limit": 50}).json()["entries"]
            assert [(entry["event"], entry["action"]) for entry in mine] == [("action", "reboot")] * 3, name
            assert in_index(tmp_path) >= held, name  # (and the file is an index again, holding the whole log)


def test_a_missing_index_is_made_again_from_the_text_files(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        one = add(admin, fake.url, name="rack-1")
        assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "reboot"}).status_code == 200
    for tail in ("", "-wal", "-shm"):
        (tmp_path / (activity.FILE + tail)).unlink(missing_ok=True)
    with wall(tmp_path) as admin:
        caught_up(admin.core.activity)  # type: ignore[attr-defined]
        assert [entry["event"] for entry in admin.get("/api/v1/audit", params={"device": one}).json()["entries"]] == ["action", "device_added"]
        assert in_index(tmp_path) == len(AuditLog(tmp_path / "audit.log").tail(10**6))


def test_an_index_removed_while_it_is_open_is_made_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Somebody cleaning the data folder while qKVM runs: where the system lets an open file go (not Windows), the index wrote
    # on into a file nobody could read any more, and every read went to the text files for as long as it ran.
    monkeypatch.setattr(activity, "LOOK_AGAIN", 0.0)
    text = AuditLog(tmp_path / "audit.log")
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    index.start()
    try:
        text.write("login", "", user="olga")
        text.flush(60)
        caught_up(index)
        try:
            (tmp_path / activity.FILE).unlink()
        except PermissionError:
            pytest.skip("this system does not let an open file be removed")
        text.write("login", "", user="ivan")
        text.flush(60)
        wait_until(lambda: (tmp_path / activity.FILE).exists() and index.caught_up(1) is not None and in_index(tmp_path) == 2, "the index was not made again")
        assert [entry["user"] for entry in index.read(activity.Asked(), 10).entries] == ["ivan", "olga"]
    finally:
        index.stop()


def test_an_index_of_another_version_or_of_other_files_is_made_again(tmp_path: Path) -> None:
    text = AuditLog(tmp_path / "audit.log", max_bytes=2000)
    for number in range(100):
        text.write("alert", "", device=f"rack-{number % 3}", n=number)
    text.flush(60)

    def made() -> activity.Index:
        index = activity.Index(tmp_path / activity.FILE, text)
        index.start()
        caught_up(index)
        return index

    first = made()
    first.stop()
    held = in_index(tmp_path)
    assert held == 100
    # Made with other kinds of entries (a later version files an event elsewhere): its kinds would be wrong.
    with sqlite3.connect(tmp_path / activity.FILE) as conn:
        conn.execute("UPDATE meta SET value = 'another' WHERE key = 'made'")
        conn.execute("UPDATE entries SET kind = 'signin'")
    conn.close()
    second = made()
    assert [entry["n"] for entry in second.read(activity.Asked(kind="alert"), 1000).entries] == list(range(99, -1, -1))
    second.stop()
    # An old file put back by hand, older than any it holds: the index cannot put its entries before the others, and is made again.
    oldest = sorted(tmp_path.glob("audit.log.*"), key=lambda path: int(path.suffix[1:]))[-1]
    number = int(oldest.suffix[1:])
    (tmp_path / f"audit.log.{number + 1}").write_text(json.dumps({"time": 1.0, "event": "login", "ip": "", "user": "put back"}) + "\n", encoding="utf-8")
    third = made()
    assert third.read(activity.Asked(), 1000).entries[-1]["user"] == "put back"
    assert in_index(tmp_path) == held + 1
    third.stop()


@pytest.mark.parametrize("files", [10, 3], ids=["ten files", "a young log of three"])
def test_files_moved_on_while_they_are_listed_lose_nothing_and_throw_nothing_away(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: int) -> None:
    # The first reviewer of W4c: the writer moves the files on while a round lists them, oldest first; a file that moved from a
    # place not yet looked at to one already looked at was missing from the list though it was there, its entries were let go
    # of, the next round found it again among the known ones and made the whole index again, and a read in that moment was
    # answered without it, by the index. The second: in a log of fewer than ten files (a young one, or after a step that
    # failed) the files below the gap move without the listed ones changing, and the same happened.
    text = AuditLog(tmp_path / "audit.log", max_bytes=10_000)
    for number in range(files):
        lines = [json.dumps({"time": 1700000000.0 + (9 - number) * 100 + k, "event": "login", "ip": "", "n": (9 - number) * 100 + k}) + "\n" for k in range(50)]
        (tmp_path / ("audit.log" if number == 0 else f"audit.log.{number}")).write_text("".join(lines), encoding="utf-8")
    where = "audit.log.5" if files == 10 else "audit.log.2"  # (a file the listing comes to after the one the rotation fills)
    index = activity.Index(tmp_path / activity.FILE, text)
    index.start()
    try:
        caught_up(index)
        thrown: list[str] = []
        let_go: list[int] = []
        real_remove, real_let_go, real_open = activity.Index._remove, activity.Index._let_go, activity.open_shared
        monkeypatch.setattr(activity.Index, "_remove", lambda self, why: thrown.append(why) or real_remove(self, why))
        monkeypatch.setattr(activity.Index, "_let_go", lambda self, conn, seq: let_go.append(seq) or real_let_go(self, conn, seq))
        moved = {"not yet": True}

        def opened(path: Path) -> Any:
            if moved["not yet"] and path.name == where:
                moved["not yet"] = False
                text._rotate()  # (as the writer does when the newest is full, right after the round looked at this one)
                (tmp_path / "audit.log").write_text(json.dumps({"time": 1800000000.0, "event": "login", "ip": "", "n": 9999}) + "\n", encoding="utf-8")
            return real_open(path)

        monkeypatch.setattr(activity, "open_shared", opened)
        monkeypatch.setattr(activity, "LOOK_AGAIN", 0.0)
        index.wake()
        wait_until(lambda: not moved["not yet"], "the round never looked at the files")
        caught_up(index)
        found = index.read(activity.Asked(), 10**6)
        assert thrown == [] and len(let_go) == (1 if files == 10 else 0), (thrown, let_go)  # (only the oldest of ten, which went)
        assert (found.by, found.entries) == ("index", text.tail(10**6))
        assert [entry["n"] for entry in found.entries][:2] == [9999, 949]
        assert found.entries[-1]["n"] == (100 if files == 10 else 700)
    finally:
        index.stop()


def test_two_files_that_begin_with_the_same_line_make_the_index_step_aside(tmp_path: Path) -> None:
    # A copy of a file made by hand: the first reviewer of W4c showed the index answering, by itself, an entry of a file that
    # was gone and not one of a file that was there, once the older of the two went. Now the text files are read while there
    # are two, and the index is made again once there is one.
    text = AuditLog(tmp_path / "audit.log", max_bytes=10_000)
    first = json.dumps({"time": 1700000000.0, "event": "login", "ip": "", "user": "first"}) + "\n"
    (tmp_path / "audit.log.3").write_text(first + json.dumps({"time": 1700000001.0, "event": "login", "ip": "", "user": "only-in-3"}) + "\n", encoding="utf-8")
    (tmp_path / "audit.log.2").write_text(json.dumps({"time": 1700000002.0, "event": "login", "ip": "", "user": "in-2"}) + "\n", encoding="utf-8")
    (tmp_path / "audit.log").write_text(json.dumps({"time": 1700000009.0, "event": "login", "ip": "", "user": "newest"}) + "\n", encoding="utf-8")
    index = activity.Index(tmp_path / activity.FILE, text)
    index.start()
    try:
        caught_up(index)
        assert index.read(activity.Asked(), 100).by == "index"
        index.stop()
        # The copy, put in place of audit.log.2 by hand: two files begin with the same line.
        (tmp_path / "audit.log.2").write_text(first + json.dumps({"time": 1700000003.0, "event": "login", "ip": "", "user": "only-in-2"}) + "\n", encoding="utf-8")
        index.start()
        doubled = index.read(activity.Asked(), 100)
        assert (doubled.by, doubled.entries) == ("text", text.tail(100))
        (tmp_path / "audit.log.3").unlink()  # (and the older of the two goes)
        wait_until(lambda: index.caught_up(1) is not None, "the index was not made again once one of the two was left")
        found = index.read(activity.Asked(), 100)
        assert (found.by, [entry["user"] for entry in found.entries]) == ("index", ["newest", "only-in-2", "first"])
    finally:
        index.stop()


def test_a_read_sees_what_was_written_before_it_was_asked_on_a_clock_that_ticks_coarsely(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # On Windows before Python 3.13 time.monotonic ticks every 15.6 ms: a round that began before an entry was written, in the
    # tick in which the read was asked, counted as one that began after it, and the read missed the entry (the first reviewer
    # of W4c, with a clock held still). Held still here: the read waits for a round that began later.
    import types

    text = AuditLog(tmp_path / "audit.log")
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    text.write("login", "", user="olga", n=0)
    text.flush(60)
    index.start()
    try:
        caught_up(index)
        # From here, the index's clocks (both of them) stand still but where the test moves them, above any time it saw so far.
        base = max(time.monotonic(), time.perf_counter()) + 1000.0
        clock = [base]
        monkeypatch.setattr(activity, "time", types.SimpleNamespace(monotonic=lambda: clock[0], perf_counter=lambda: clock[0]))
        real_follow = activity.Index._follow
        held, go_on, next_on = threading.Event(), threading.Event(), threading.Event()
        rounds = {"count": 0}

        def follow(self: activity.Index) -> bool:
            rounds["count"] += 1
            if rounds["count"] == 2:
                next_on.wait(10)  # (the round after it, which would take the entry in, holds until the read has had its answer)
            done = real_follow(self)
            if rounds["count"] == 1:
                held.set()  # (it has looked at the files: the entry below is not there yet)
                go_on.wait(10)
            return done

        monkeypatch.setattr(activity.Index, "_follow", follow)
        index.wake()  # (one tick, in which the round begins, the entry is written and the read is asked)
        assert held.wait(10)
        text.write("action", "", user="olga", device="rack-1", n=1)
        text.flush(60)
        answer: dict[str, activity.Found] = {}
        reader = threading.Thread(target=lambda: answer.setdefault("found", index.read(activity.Asked(), 10)), daemon=True)
        reader.start()
        time.sleep(0.3)  # (the read waits, asked in that tick)
        go_on.set()
        time.sleep(0.5)  # (where the read took the held round for one after it was asked, it has its answer by now)
        clock[0] = base + 1.0  # (the next tick: the next rounds begin in it)
        next_on.set()
        index.wake()
        reader.join(10)
        assert [entry["n"] for entry in answer["found"].entries] == [1, 0]
    finally:
        index.stop()


def test_a_read_of_the_text_files_takes_no_longer_than_a_read_of_the_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Where the index is behind (being made, its disk refusing), a read went to the text files with no limit of time: a word
    # that is nowhere in 100 MB took 4 to 6 s here, longer on a smaller computer, in a thread of the wall's (the first
    # reviewer of W4c). Now it is given up at the same time as a read of the index, and said so (503 activity_unavailable).
    monkeypatch.setattr(activity, "READ_PATIENCE", -1.0)  # (no time at all: a stand-in for a log too long to read in time)
    monkeypatch.setattr(activity.Index, "start", lambda self: None)  # (an index that is never there: every read goes to the text files)
    with wall(tmp_path) as admin:
        refused = admin.get("/api/v1/audit", params={"q": "no-such-word"})
        assert (refused.status_code, refused.json()["code"]) == (503, "activity_unavailable") and "narrow it down" in refused.json()["message"]
    monkeypatch.setattr(activity, "PAGE_PATIENCE", -1.0)
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/audit/export", params={"q": "no-such-word"}).status_code == 503


def test_the_index_leaves_the_room_the_record_needs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The index is two and a half times the text files' size: growing into the last of a disk, it took the room the record
    # needed, and the activity log's next entries were not written (the first reviewer of W4c). Below twice a text file and
    # twice its -wal file's share free, it waits, and the text files are read meanwhile.
    from collections import namedtuple

    # (Heard on the program's logger itself: a test before this one in the whole suite (the command line's) leaves "qkvm" not
    # passing its lines on, as the program's own logging has it, and pytest's caplog then heard nothing of them.)
    said: list[str] = []
    heard = logging.Handler(logging.ERROR)
    heard.emit = lambda record: said.append(record.getMessage())  # type: ignore[method-assign]
    ours = logging.getLogger("qkvm")
    monkeypatch.setattr(ours, "handlers", [*ours.handlers, heard])  # (and as they were, afterwards)
    usage = namedtuple("usage", "total used free")
    room = {"free": 10**12}
    monkeypatch.setattr(activity.shutil, "disk_usage", lambda folder: usage(10**12, 10**12 - room["free"], room["free"]))
    monkeypatch.setattr(activity, "REFUSED", (0.2, 0.2, 0.2))
    text = AuditLog(tmp_path / "audit.log", max_bytes=1_000_000)
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    text.write("login", "", user="olga")
    text.flush(60)
    index.start()
    try:
        caught_up(index)
        room["free"] = 2 * 1_000_000 + 2 * activity.WAL_MOST - 1
        text.write("login", "", user="ivan")
        text.flush(60)
        found = index.read(activity.Asked(), 10)
        assert (found.by, [entry["user"] for entry in found.entries]) == ("text", ["ivan", "olga"])
        assert in_index(tmp_path) == 1
        wait_until(lambda: any("waits" in line for line in said), "the log did not say why the index waits")
        room["free"] = 10**12
        caught_up(index)
        assert index.read(activity.Asked(), 10).by == "index" and in_index(tmp_path) == 2
    finally:
        index.stop()


def test_a_line_naming_half_a_character_is_no_entry_and_breaks_nothing(tmp_path: Path) -> None:
    # A line written by hand with an escaped lone surrogate: no answer can carry it, and every read of the log that held it was
    # an error (500), a download stopped there (the first reviewer of W4c). A pair of halves is one character, and is shown.
    with wall(tmp_path) as admin:
        admin.core.audit.flush(60)  # type: ignore[attr-defined]
        with (tmp_path / "audit.log").open("ab") as file:
            file.write(b'{"time": 1700000000, "event": "login", "ip": "", "user": "half \\ud800 of one"}\n')
            file.write(b'{"time": 1700000001, "event": "login", "ip": "", "user": "a whole \\ud83d\\ude00 one"}\n')
        answer = admin.get("/api/v1/audit")
        assert answer.status_code == 200 and "half" not in answer.text
        assert any(entry.get("user", "").startswith("a whole ") for entry in answer.json()["entries"])
        lines = admin.get("/api/v1/audit/export", params={"format": "jsonl"}).text.splitlines()
        assert json.loads(lines[-1])["event"] == "setup"  # (all of it, to its oldest)


def test_a_line_written_by_hand_without_its_end_is_the_same_for_the_index_and_the_files(tmp_path: Path) -> None:
    # Taken in as it stood, the index held it and the writer's next entry; in the file, the writer wrote that entry onto the
    # same line, and neither was an entry there (the first reviewer of W4c). Now the newest file's last line is no entry
    # until it has ended, for both. (The writer looks for an unended line at its first entry: one a person writes in later is
    # run into by the next entry, as in 0.1.x, and both say so alike.)
    text = AuditLog(tmp_path / "audit.log")
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    text.write("login", "", user="olga")
    text.flush(60)
    index.start()
    try:
        caught_up(index)
        with (tmp_path / "audit.log").open("ab") as file:
            file.write(b'{"time": 1900000000, "event": "login", "ip": "", "user": "by hand"}')
        for asked in (index.read(activity.Asked(), 10).entries, text.tail(10)):
            assert [entry["user"] for entry in asked] == ["olga"]
        text.write("login", "", user="ivan")
        text.flush(60)
        found = index.read(activity.Asked(), 10)
        assert found.by == "index" and found.entries == text.tail(10)
        # ...and a new start ends what was left unended before its first entry.
        with (tmp_path / "audit.log").open("ab") as file:
            file.write(b'{"time": 1900000001, "event": "login", "ip": "", "user": "cut off"}')
        again = AuditLog(tmp_path / "audit.log")
        index.text = again
        again.write("login", "", user="petra")
        again.flush(60)
        found = index.read(activity.Asked(), 10)
        assert found.by == "index" and [entry["user"] for entry in found.entries][:2] == ["petra", "cut off"] and found.entries == again.tail(10)
    finally:
        index.stop()


def test_a_reading_of_the_text_files_is_of_the_files_as_they_were_when_it_began(tmp_path: Path) -> None:
    # A download read from the text files opened each when it came to it: the writer moving them on meanwhile had it read one
    # file twice and leave the oldest out (the first reviewer of W4c). Now all of them are opened at its start.
    text = AuditLog(tmp_path / "audit.log", max_bytes=2000)
    number = 0
    while not (tmp_path / "audit.log.9").exists():
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    before = [entry["n"] for entry in text.tail(10**6)]
    reading = text.entries()
    first = [next(reading)["n"] for _ in range(5)]
    oldest = (tmp_path / "audit.log.9").read_bytes()
    for _ in range(150):  # (the writer moves the files on, three times or more: the oldest goes)
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    assert (tmp_path / "audit.log.9").read_bytes() != oldest
    rest = [entry["n"] for entry in reading]
    assert first + rest == before


def test_a_reading_of_the_text_files_opens_none_of_them_twice_where_they_are_moved_on_while_it_opens_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Opened one after the other, the newest first, a file the writer moved on in between was opened under its old name and
    # its new one: its entries read twice (the second reviewer of W4c). Opened again where the files moved meanwhile.
    text = AuditLog(tmp_path / "audit.log", max_bytes=2000)
    number = 0
    while not (tmp_path / "audit.log.4").exists():
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    before = [entry["n"] for entry in text.tail(10**6)]
    real = store.open_shared
    moved = {"not yet": True}

    def opened(path: Path) -> Any:
        file = real(path)
        if moved["not yet"] and path.name == "audit.log":
            moved["not yet"] = False
            text._rotate()  # (right after the newest was opened: it is audit.log.1 by the time that name is opened)
        return file

    monkeypatch.setattr(store, "open_shared", opened)
    read = [entry["n"] for entry in text.entries()]
    assert not moved["not yet"] and read == before


def test_a_download_that_cannot_be_made_whole_is_refused_and_not_sent_in_part(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Sent as it was read, a download whose second page could not be read in time (or whose asker was signed out meanwhile)
    # ended as a whole one does: a file that looked complete, with part of the log missing (the second reviewer of W4c). It is
    # made whole before anything is sent now, and sent with its length; one that cannot be made whole is refused.
    written(tmp_path, old_entries(1_760_000_000.0, ["rack-1"], 2 * activity.PAGE + 50), 2)
    real = activity.Pager.next
    pages = {"read": 0}

    def next_page(self: activity.Pager) -> Any:
        pages["read"] += 1
        if pages["read"] == 2:
            raise activity.NotReadable("a stand-in for a page that took too long")
        return real(self)

    with wall(tmp_path) as admin:
        caught_up(admin.core.activity)  # type: ignore[attr-defined]
        monkeypatch.setattr(activity.Pager, "next", next_page)
        refused = admin.get("/api/v1/audit/export", params={"format": "jsonl"})
        assert (refused.status_code, refused.json()["code"]) == (503, "activity_unavailable")
        monkeypatch.undo()
        assert not [entry for entry in admin.core.audit.tail(10) if entry["event"] == "activity_exported"]  # type: ignore[attr-defined]  # (nothing was taken)
        whole = admin.get("/api/v1/audit/export", params={"format": "jsonl"})
        assert whole.status_code == 200 and int(whole.headers["content-length"]) == len(whole.content)
        assert len(whole.text.splitlines()) == len(admin.core.audit.tail(10**6)) - 1  # type: ignore[attr-defined]  # (all but its own entry)


def test_an_index_whose_stop_took_longer_than_was_waited_for_is_started_again_all_the_same(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The listeners opened anew while the index's thread was in a step that took longer than the five seconds a stop waits:
    # start() refused, the old thread ended, and nothing started a new one; every read went to the text files until the next
    # time the listeners were opened, which may never come (the second reviewer of W4c).
    text = AuditLog(tmp_path / "audit.log")
    text.write("login", "", user="olga")
    text.flush(60)
    index = activity.Index(tmp_path / activity.FILE, text)
    real = activity.Index._prepare
    slow, go_on = threading.Event(), threading.Event()

    def prepare(self: activity.Index, conn: sqlite3.Connection) -> None:
        if not slow.is_set():
            slow.set()
            go_on.wait(10)  # (a step on a slow disk)
        real(self, conn)

    monkeypatch.setattr(activity.Index, "_prepare", prepare)
    index.start()
    try:
        assert slow.wait(10)
        index.stop(within=0.2)  # (the wall stopping: it does not wait long)
        index.start()  # (and its listeners opened anew)
        go_on.set()
        wait_until(lambda: index.caught_up(1) is not None, "the index was not started again", timeout=15)
        assert index.read(activity.Asked(), 10).by == "index"
    finally:
        index.stop()


def test_nothing_newer_is_taken_in_past_a_file_that_could_not_be_opened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The index behind on the newest file when it was moved on, and that file (audit.log.1 now) not to be opened in the next
    # round (a sharing violation, its permissions): the round took in the new audit.log past it, counted as complete, and the
    # older file's rest came after it, in another order; its going later took the newer one's entries with it (the third
    # reviewer of W4c). Now nothing is taken in past it, and the text files are read meanwhile.
    text = AuditLog(tmp_path / "audit.log")
    for number in range(20):
        text.write("login", "", n=number)
    text.flush(60)
    index = activity.Index(tmp_path / activity.FILE, text)
    index.start()
    try:
        caught_up(index)
        index.stop()
        for number in range(20, 30):
            text.write("login", "", n=number)  # (the rest of the newest, not taken in: the index is stopped)
        text.flush(60)
        text._rotate()
        for number in range(30, 40):
            text.write("login", "", n=number)  # (the new newest)
        text.flush(60)
        real = activity.open_shared
        held = {"on": True}

        def opened(path: Path) -> Any:
            if held["on"] and path.name == "audit.log.1":
                raise PermissionError(32, "The process cannot access the file because it is being used by another process")
            return real(path)

        monkeypatch.setattr(activity, "open_shared", opened)
        index.start()
        time.sleep(2.5)  # (rounds come and go)
        found = index.read(activity.Asked(), 100)
        assert (found.by, found.entries) == ("text", text.tail(100))
        assert in_index(tmp_path) == 20  # (nothing of the new newest taken in past the file it could not open)
        held["on"] = False
        caught_up(index)
        found = index.read(activity.Asked(), 100)
        assert (found.by, [entry["n"] for entry in found.entries]) == ("index", list(range(39, -1, -1)))
    finally:
        index.stop()


def test_a_rotation_whose_last_step_failed_is_seen_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The oldest removed, the others moved on, and the last step (the newest to audit.log.1) refused by a program holding it:
    # the newest file is the one it was, and reading on in it alone, the index answered the removed file's entries for a
    # minute (the third reviewer of W4c). Now it reads on alone only while the files were not moved on since its last look.
    text = AuditLog(tmp_path / "audit.log", max_bytes=600)
    number = 0
    while not (tmp_path / "audit.log.9").exists():
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    index.start()
    try:
        caught_up(index)
        real = os.replace
        refused = {"once": True}

        def moved(source: Any, target: Any) -> None:
            if refused["once"] and Path(source).name == "audit.log":
                refused["once"] = False
                raise PermissionError(32, "The process cannot access the file because it is being used by another process")
            real(source, target)

        monkeypatch.setattr(os, "replace", moved)
        while refused["once"]:
            text.write("login", "", n=number)
            number += 1
            text.flush(60)
        caught_up(index)
        found = index.read(activity.Asked(), 10**6)
        assert (found.by, found.entries) == ("index", text.tail(10**6))
    finally:
        index.stop()


def test_downloads_are_held_to_a_few_at_once_and_one_of_each_account() -> None:
    from qkvm import server

    downloads = server.Downloads(3)
    olga = downloads.take("olga")
    assert olga is not None and downloads.take("olga") is None  # (one of each account)
    others = [downloads.take(name) for name in ("ivan", "petra")]
    assert all(others) and downloads.take("rosa") is None  # (three from everybody together)
    olga()
    olga()  # (given back once, however often it is called)
    assert downloads.take("rosa") is not None and downloads.take("victor") is None


def test_a_download_takes_none_of_the_room_the_record_needs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Made in a temporary file beyond a few megabytes, a download of a long log as large as the log: on the data folder's disk
    # (as a rule) it took the room the record needed (the third reviewer of W4c). Refused where it would.
    from collections import namedtuple

    from qkvm import server

    written(tmp_path, old_entries(1_760_000_000.0, ["rack-1"], 3000), 2)
    monkeypatch.setattr(server, "SPOOL_IN_MEMORY", 10_000)  # (on the disk at once: a stand-in for a log of gigabytes)
    usage = namedtuple("usage", "total used free")
    with wall(tmp_path) as admin:
        caught_up(admin.core.activity)  # type: ignore[attr-defined]
        monkeypatch.setattr(server.shutil, "disk_usage", lambda folder: usage(10**12, 10**12 - 30_000_000, 30_000_000))
        refused = admin.get("/api/v1/audit/export", params={"format": "csv"})
        assert (refused.status_code, refused.json()["code"]) == (507, "not_saved")
        monkeypatch.setattr(server.shutil, "disk_usage", lambda folder: usage(10**12, 0, 10**12))
        assert admin.get("/api/v1/audit/export", params={"format": "csv"}).status_code == 200


def test_a_download_is_made_in_the_data_folder_and_waits_for_no_disk_on_the_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Its room was asked of the system's temporary folder (another disk where the data folder is a container's volume; memory
    # where it is a tmpfs), what the log holds was left there, and the room was asked and the file let go of on the event
    # loop (the reviewer of 0.2.0). In the data folder now, where the record is, and asked and let go of in threads; named so
    # that a start finds what a power cut left of one (the reviewer of FX-C).
    import asyncio
    import shutil
    import tempfile

    from qkvm import server

    def on_the_loop() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return False
        return True

    written(tmp_path, old_entries(1_760_000_000.0, ["rack-1"], 3000), 2)
    monkeypatch.setattr(server, "SPOOL_IN_MEMORY", 10_000)  # (on the disk at once)
    usage, spooled = shutil.disk_usage, tempfile.SpooledTemporaryFile
    asked: list[tuple[Path, bool]] = []
    made: list[Any] = []
    closed: list[bool] = []

    def disk_usage(folder: Any) -> Any:
        asked.append((Path(folder), on_the_loop()))
        return usage(folder)

    def spool(*args: Any, **kwargs: Any) -> Any:
        file = spooled(*args, **kwargs)
        made.append((Path(kwargs["dir"]), kwargs.get("prefix"), kwargs.get("suffix")))
        close = file.close

        def closing() -> None:
            closed.append(on_the_loop())
            close()

        file.close = closing  # type: ignore[method-assign]
        return file

    # What a power cut left of one in the making (on Windows a file made to go when it is closed stays then) goes at a start;
    # nothing else of the folder does.
    (tmp_path / "qkvm-download-abc123.tmp").write_bytes(b'{"time": 1, "event": "login"}\n')
    (tmp_path / "qkvm-download-notes.txt").write_text("not one of them", encoding="utf-8")
    with wall(tmp_path) as admin:
        assert not (tmp_path / "qkvm-download-abc123.tmp").exists() and (tmp_path / "qkvm-download-notes.txt").exists()
        caught_up(admin.core.activity)  # type: ignore[attr-defined]
        monkeypatch.setattr(server.shutil, "disk_usage", disk_usage)
        monkeypatch.setattr(server.tempfile, "SpooledTemporaryFile", spool)
        reply = admin.get("/api/v1/audit/export", params={"format": "csv"})
        assert reply.status_code == 200 and len(reply.content) > 10_000
        wait_until(lambda: bool(closed), "the download's file was never let go of")
    assert made == [(tmp_path, "qkvm-download-", ".tmp")], made
    assert asked and all(folder == tmp_path and not loop for folder, loop in asked), asked
    assert closed == [False], closed


def test_a_read_that_waited_asks_again_whether_its_asker_may_still_have_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The hardening rule: a read that waits asks again before it hands over. A read of the activity log waits its turn and for
    # the index; an admin made an operator meanwhile was handed the log all the same (the first reviewer of W4c).
    hold = threading.Event()
    real = AuditLog.flush

    def held(self: AuditLog, within: float = 5.0) -> None:
        if threading.current_thread() is not threading.main_thread() and getattr(hold, "on", False):
            hold.wait(20)
        real(self, within)

    monkeypatch.setattr(AuditLog, "flush", held)
    with wall(tmp_path) as admin:
        olga_id = account(admin, "olga", "admin")
        olga = browser(admin, "olga")
        answers: dict[str, Any] = {}
        hold.on = True  # type: ignore[attr-defined]
        asking = threading.Thread(target=lambda: answers.__setitem__("olga", olga.get("/api/v1/audit")), daemon=True)
        asking.start()
        time.sleep(0.5)
        hold.on = False  # type: ignore[attr-defined]
        assert admin.put(f"/api/v1/users/{olga_id}", json={"name": "olga", "role": "operator"}).status_code == 200
        hold.set()
        asking.join(20)
        assert answers["olga"].status_code == 403 and "entries" not in answers["olga"].text


# --- the text log: never weaker -------------------------------------------------------------------------------------


def test_a_rotation_step_that_fails_loses_no_old_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A file held open by something else just now (on Windows) makes one step of moving the files on fail. The next try moved
    # the files above that step on all the same, and the oldest of them went: a file of the log lost for every step that
    # failed, though the log keeps ten.
    text = AuditLog(tmp_path / "audit.log", max_bytes=500)
    number = 0
    while not (tmp_path / "audit.log.9").exists():
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    before = {entry["n"] for entry in text.tail(10**6)}
    real = os.replace
    failed: list[str] = []

    def held_once(source: Any, target: Any) -> None:
        if str(source).endswith("audit.log.4") and not failed:
            failed.append(str(source))
            raise PermissionError(32, "The process cannot access the file because it is being used by another process")
        real(source, target)

    monkeypatch.setattr(os, "replace", held_once)
    while not failed:
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    for _ in range(3):  # (the next entries: the files are moved on again)
        text.write("login", "", n=number)
        number += 1
        text.flush(60)
    monkeypatch.undo()
    after = {entry["n"] for entry in text.tail(10**6)}
    oldest = sorted(before)[: len(before) // 10 + 3]  # (about a file of the oldest: what the log is to let go of, and no more)
    assert before - after <= set(oldest), sorted(before - after)
    assert sorted(path.name for path in tmp_path.glob("audit.log*"))[:1] == ["audit.log"] and len(list(tmp_path.glob("audit.log*"))) == 10


def test_a_line_cut_off_by_a_crash_does_not_swallow_the_first_entry_after_the_restart(tmp_path: Path) -> None:
    (tmp_path / "audit.log").write_bytes(json.dumps({"time": 1700000000, "event": "login", "ip": "", "user": "before"}).encode() + b"\n" + b'{"time": 17000000')
    text = AuditLog(tmp_path / "audit.log")
    text.write("unlocked_at_start", "")
    text.write("login", "", user="after")
    text.flush(60)
    assert [entry["event"] for entry in text.tail(10)] == ["login", "unlocked_at_start", "login"]
    on_disk = (tmp_path / "audit.log").read_bytes().replace(b"\r\n", b"\n")  # (Windows ends a line of a text file so)
    assert on_disk.startswith(b'{"time": 1700000000, "event": "login", "ip": "", "user": "before"}\n{"time": 17000000\n{"time": ')


@pytest.mark.parametrize(("cut", "many", "lost", "after"), [("lost", 30, 10, 15), ("zeros", 30, 10, 15), ("lost", 400, 200, 300), ("lost", 30, 1, 15)])
def test_after_a_power_cut_that_took_what_the_index_had_read_the_index_holds_what_the_record_holds(tmp_path: Path, cut: str, many: int, lost: int, after: int) -> None:
    # The text files are never synced; the index is, at SQLite's checkpoints. A power cut can take the last lines of the text
    # file (or leave zeros where they were) and keep them in the index. The next start writes its first entries before the
    # index looks: once the file is as long as the index had read it, its length says nothing, and the index (on 6d0bed7)
    # kept entries the record no longer has and never took in the first ones written after the restart (the reviewer of
    # 0.2.0: 10 not in the record, 11 of it missing). (200 lines lost: more than the bytes of which a hash is kept; one: fewer.)
    text = AuditLog(tmp_path / "audit.log")
    index = activity.Index(tmp_path / activity.FILE, text)
    text.on_written = index.wake
    index.start()
    try:
        for number in range(many):
            text.write("login", "", user=f"before{number}")
        text.flush(60)
        caught_up(index)
    finally:
        index.stop()
    log = tmp_path / "audit.log"
    lines = log.read_bytes().splitlines(keepends=True)
    if cut == "lost":
        log.write_bytes(b"".join(lines[:-lost]))
    else:
        log.write_bytes(b"".join(lines[:-lost]) + bytes(sum(len(line) for line in lines[-lost:])))  # (its length as it was)
    again = AuditLog(tmp_path / "audit.log")
    for number in range(after):
        again.write("login", "", user=f"after{number}")
    again.flush(60)
    index = activity.Index(tmp_path / activity.FILE, again)
    again.on_written = index.wake
    index.start()
    try:
        caught_up(index)
        said = index.read(activity.Asked(), many + 100)
        held = [entry["user"] for entry in again.tail(many + 100)]
        assert said.by == "index"
        assert [entry["user"] for entry in said.entries] == held, (
            f"the index answers {len(said.entries)} entries, the record holds {len(held)}; only in the index: "
            f"{sorted({entry['user'] for entry in said.entries} - set(held))[:12]}; only in the record: {sorted(set(held) - {entry['user'] for entry in said.entries})[:12]}"
        )
        assert held[:after] == [f"after{number}" for number in range(after - 1, -1, -1)] and len(held) == many - lost + after
    finally:
        index.stop()


def test_the_index_never_stands_in_the_way_of_the_text_log_and_a_refusing_disk_leaves_the_log_as_it_was(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # The index's disk refuses (full), and then hangs: every entry is written to the text files at once, every request of the
    # wall is answered as fast as before, the page reads the text files meanwhile (the whole log, in a moment); once the
    # disk takes writes again, the index takes in all it missed, and the page reads it.
    real = activity.Index._insert
    hold = threading.Event()
    mode = {"now": "full"}

    def refusing(self: activity.Index, conn: sqlite3.Connection, seq: int, lines: list[bytes], since: int, done: int, tail: str) -> None:
        if mode["now"] == "full":
            raise sqlite3.OperationalError("database or disk is full")
        if mode["now"] == "hung":
            hold.wait(30)
        real(self, conn, seq, lines, since, done, tail)

    monkeypatch.setattr(activity.Index, "_insert", refusing)
    monkeypatch.setattr(activity, "REFUSED", (0.2, 0.2, 0.2))
    with wall(tmp_path) as admin:
        one = add(admin, fake.url, name="rack-1")
        index: activity.Index = admin.core.activity  # type: ignore[attr-defined]
        for now in ("full", "hung"):
            mode["now"] = now
            began = time.monotonic()
            for _ in range(5):
                assert admin.post(f"/api/v1/devices/{one}/actions", json={"action": "reboot"}).status_code == 200
            acting = time.monotonic() - began
            admin.core.audit.flush(60)  # type: ignore[attr-defined]
            on_disk = (tmp_path / "audit.log").read_text(encoding="utf-8")
            assert on_disk.count('"action": "reboot"') == (5 if now == "full" else 10), now
            began = time.monotonic()
            answer = admin.get("/api/v1/audit", params={"device": one, "limit": 100})
            reading = time.monotonic() - began
            assert answer.status_code == 200 and [entry["event"] for entry in answer.json()["entries"]].count("action") == (5 if now == "full" else 10)
            assert acting < 3.0 and reading < activity.CATCH_UP + 3.0, (now, acting, reading)
        mode["now"] = "well"
        hold.set()
        caught_up(index)
        assert in_index(tmp_path) == len(admin.core.audit.tail(10**6))  # type: ignore[attr-defined]


def test_reads_of_the_activity_log_are_one_at_a_time_of_each_account_and_three_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # W4b's rule for the history, for the activity log as well: an admin's script that asked again and again had the wall's
    # threads to itself (a search of a long log takes seconds where the index is behind). Each read is held here in its
    # first step, the waiting for what is still being written, which the reading of 4c849f5 took as well.
    hold = threading.Event()
    under_way: list[str] = []
    real = AuditLog.flush

    def held(self: AuditLog, within: float = 5.0) -> None:
        if threading.current_thread() is not threading.main_thread() and getattr(hold, "on", False):
            under_way.append(threading.current_thread().name)
            hold.wait(20)
        real(self, within)

    monkeypatch.setattr(AuditLog, "flush", held)
    with wall(tmp_path) as admin:
        for name in ("ivan", "olga", "petra", "rosa"):
            account(admin, name, "admin")
        second = browser(admin, "admin", password=PASSWORD, port=50071)
        others = [browser(admin, name, port=50080 + number) for number, name in enumerate(("ivan", "olga", "petra", "rosa"))]
        answers: dict[str, Any] = {}

        def ask(name: str, client: TestClient) -> threading.Thread:
            asking = threading.Thread(target=lambda: answers.__setitem__(name, client.get("/api/v1/audit")), daemon=True)
            asking.start()
            return asking

        hold.on = True  # type: ignore[attr-defined]
        first = ask("first", admin)
        wait_until(lambda: len(under_way) == 1, "the first read never began")
        # The same account again, from its second browser, twice: one waits its turn, the other is told to come back.
        same = [ask("same 1", second), ask("same 2", second)]
        wait_until(lambda: "same 1" in answers or "same 2" in answers, "neither of the account's next two reads was answered", timeout=10)
        refused = answers.get("same 1") or answers["same 2"]
        assert (refused.status_code, refused.json()["code"], refused.headers.get("Retry-After")) == (503, "busy", "2")
        assert len(under_way) == 1  # (not the account's next, while its first is under way)
        # Other admins meanwhile: two more are let in (three at once from everybody), and the next is told to come back.
        theirs = [ask("ivan", others[0]), ask("olga", others[1])]
        wait_until(lambda: len(under_way) == 3, "the others' reads did not begin")
        late = ask("petra", others[2])
        late.join(10)
        assert (answers["petra"].status_code, answers["petra"].json()["code"]) == (503, "busy")
        hold.set()
        for asking in (first, *same, *theirs):
            asking.join(30)
        assert sorted(answer.status_code for answer in answers.values()) == [200, 200, 200, 200, 503, 503]
        hold.on = False  # type: ignore[attr-defined]


def test_a_search_of_a_long_log_is_answered_from_the_index_without_reading_the_log(tmp_path: Path) -> None:
    # 30 MB of a busy wall's log, some 190,000 entries over five months (the default size is 100 MB: the hand-back of W4c
    # has those numbers, of this PC). The questions the page asks that reading the text files answers slowest: a word that is
    # nowhere, the oldest page, one machine's alerts on a day long ago. Answered through the wall, they are to take a
    # fraction of what reading the text files takes on the same computer (4c849f5 read them for every one of them).
    end = 1_790_000_000.0
    written_lines(tmp_path, busy_lines(30, end))
    text = AuditLog(tmp_path / "audit.log")
    readings = []
    for _ in range(2):  # (the quicker of two: this PC runs other work beside the tests, and the comparison is of the readers)
        began = time.monotonic()
        by_text = text.tail(201, lambda entry: "no-such-word-anywhere" in " ".join(str(value) for value in entry.values()).casefold())
        readings.append(time.monotonic() - began)
        assert by_text == []
    reading = min(readings)
    with wall(tmp_path) as admin:
        index: activity.Index = admin.core.activity  # type: ignore[attr-defined]
        caught_up(index, within=300)
        machine, ident = BUSY_MACHINES[37]
        oldest = min(float(entry["time"]) for entry in AuditLog(tmp_path / "audit.log.9").tail(10**6) if entry["event"] != "setup")
        questions = {
            "a word that is nowhere": {"q": "no-such-word-anywhere"},
            "the oldest page": {"before": oldest + 3600},
            "a machine's alerts on one day": {"device": ident, "kind": "alert", "since": end - 100 * 86400, "until": end - 99 * 86400},
            "one account, a week long ago": {"user": "operator2", "since": end - 120 * 86400, "until": end - 113 * 86400},
        }
        took: dict[str, float] = {}
        for name, asked in questions.items():
            for _ in range(3):  # (the quickest of three, as above)
                began = time.monotonic()
                answer = admin.get("/api/v1/audit", params={**asked, "limit": 200})
                this = time.monotonic() - began
                took[name] = min(took.get(name, float("inf")), this)
                time.sleep(this)  # (an account's next read waits as long as its last took: not counted here)
            assert answer.status_code == 200, (name, answer.text)
            if name == "a machine's alerts on one day":
                assert answer.json()["entries"] and {entry["device"] for entry in answer.json()["entries"]} == {machine}
        print(f"reading the text files {reading:.2f} s; through the wall {', '.join(f'{name} {seconds * 1000:.0f} ms' for name, seconds in took.items())}")
        assert max(took.values()) < reading / 4, (reading, took)


# --- the wall --------------------------------------------------------------------------------------------------------


def test_the_files_of_0_1_are_read_in_at_the_first_start_and_found_by_machine_account_kind_and_time(tmp_path: Path, fake: FakeKvm) -> None:
    # A wall that ran 0.1.x has ten files of the old shape (a machine by its name only). At the first start of this version
    # they are read in once, and from then on the page finds what was done to a machine (by its name, for what was written
    # before entries gave its id), by an account, of a kind, in a window of time: the whole log, from the first day.
    with wall(tmp_path) as admin:
        one = add(admin, fake.url, name="rack3-node07")
    for tail in ("", "-wal", "-shm"):
        (tmp_path / (activity.FILE + tail)).unlink(missing_ok=True)
    start = 1_760_000_000.0
    old = old_entries(start, ["rack3-node07", "rack1-node02", "rack2-node11"], 3000)
    now = [json.loads(line) for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    written(tmp_path, old, 10)
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.writelines(json.dumps(entry) + "\n" for entry in now)  # (what this version wrote at the start above, after them)
    with wall(tmp_path) as admin:
        index: activity.Index = admin.core.activity  # type: ignore[attr-defined]
        caught_up(index)

        def asked(**params: Any) -> list[dict[str, Any]]:
            reply = admin.get("/api/v1/audit", params={"limit": 500, **params})
            assert reply.status_code == 200, reply.text
            return list(reply.json()["entries"])

        mine = asked(device=one)
        expected_old = [entry for entry in reversed(old) if entry.get("device") == "rack3-node07"]
        assert len(expected_old) > 500 and len(mine) == 500
        assert (mine[0]["event"], mine[0]["device_id"]) == ("device_added", one)  # (written with its id by this version)
        assert mine[1:] == expected_old[:499]  # (and before it, what 0.1.x wrote of it, by its name)
        assert {entry["user"] for entry in asked(user="OLGA")} == {"olga"} and len(asked(user="olga", kind="signin")) == 500
        window = asked(since=start + 600 * 60, until=start + 700 * 60)
        assert [entry["time"] for entry in window] == [start + minute * 60 for minute in range(700, 599, -1)]
        assert asked(device=one, kind="alert", since=start, until=start + 50 * 60) == [
            entry for entry in reversed(old[:51]) if entry["event"] == "alert" and entry["device"] == "rack3-node07"
        ]
        assert in_index(tmp_path) == len(AuditLog(tmp_path / "audit.log").tail(10**6)) > len(old)
        assert admin.get("/api/v1/audit", params={"since": 5, "until": 4}).status_code == 422
        assert admin.get("/api/v1/audit", params={"since": -1}).status_code == 422 and admin.get("/api/v1/audit", params={"until": "nan"}).status_code == 422


def test_what_is_done_to_a_machine_is_found_by_its_id_through_a_rename_and_downloaded_the_same(tmp_path: Path, fake: FakeKvm) -> None:
    other = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            one, two = add(admin, fake.url, name="rack-1"), add(admin, other.url, name="rack-2")
            account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            assert olga.post(f"/api/v1/devices/{one}/actions", json={"action": "reboot"}).status_code == 200
            renamed = admin.put(f"/api/v1/devices/{one}", json={"name": "rack-1-renamed", "url": fake.url, "username": "admin", "password": ""})
            assert renamed.status_code == 200, renamed.text
            assert olga.post(f"/api/v1/devices/{one}/actions", json={"action": "jiggler_on"}).status_code == 200
            assert admin.post(f"/api/v1/devices/{two}/actions", json={"action": "reboot"}).status_code == 200
            entries = admin.get("/api/v1/audit", params={"device": one}).json()["entries"]
            assert [(entry["event"], entry.get("action"), entry["device"]) for entry in entries] == [
                ("action", "jiggler_on", "rack-1-renamed"), ("device_changed", None, "rack-1-renamed"), ("action", "reboot", "rack-1"), ("device_added", None, "rack-1"),
            ]  # fmt: skip
            assert all(entry["device_id"] == one for entry in entries)
            table = admin.get("/api/v1/audit/export", params={"format": "csv", "device": one, "user": "olga"})
            rows = list(csv.reader(io.StringIO(table.text)))
            assert rows[0][:6] == ["time", "event", "user", "ip", "device", "action"] and [row[5] for row in rows[1:]] == ["jiggler_on", "reboot"]
            lines = admin.get("/api/v1/audit/export", params={"format": "jsonl", "device": two}).text.splitlines()
            assert [json.loads(line)["event"] for line in lines] == ["action", "device_added"]
            assert admin.get("/api/v1/audit/export", params={"since": 5, "until": 4}).status_code == 422
            assert browser(admin, "olga", port=50002).get("/api/v1/audit", params={"device": one}).status_code == 403
    finally:
        other.stop()


def test_a_download_of_a_long_log_is_made_a_page_at_a_time_and_sent_whole(tmp_path: Path) -> None:
    written(tmp_path, old_entries(1_760_000_000.0, ["rack-1"], 3 * activity.PAGE + 17), 3)
    with wall(tmp_path) as admin:
        caught_up(admin.core.activity)  # type: ignore[attr-defined]
        download = admin.get("/api/v1/audit/export", params={"format": "csv"})
        assert int(download.headers["content-length"]) == len(download.content)  # (made whole, then sent with its length)
        rows = list(csv.reader(io.StringIO(download.text)))
        assert rows[0][0] == "time" and sum(1 for row in rows if row[0] == "time") == 1
        assert len(rows) == 1 + len(admin.core.audit.tail(10**6)) - 1  # type: ignore[attr-defined]  # (all of it but the download's own entry, written after it was read)
        times = [row[0] for row in rows[1:]]
        assert times == sorted(times, reverse=True)


def test_what_an_admin_wants_after_an_incident_is_written_down(tmp_path: Path, fake: FakeKvm) -> None:
    # Who looked at a machine's screen and for how long, who took the activity log away and what of it, and a server's console
    # that could not be opened: none of it was in the log. Each entry about a machine gives its id beside its name.
    from tests.test_live import Viewer, Wall

    with Wall(tmp_path) as running:
        admin = running.browser()
        one = running.add(admin, fake.url, name="rack-1")
        viewer = Viewer(running, one, running.ticket(admin, one))
        viewer.word("state")
        time.sleep(1.1)
        viewer.close()
        assert admin.post(f"/api/v1/devices/{one}/console", json={}).status_code == 404  # (a KVM has none: nothing tried, nothing written)
        assert admin.get("/api/v1/audit/export", params={"format": "jsonl", "kind": "action"}).status_code == 200
        wait_until(lambda: any(entry["event"] == "live_closed" for entry in running.core.audit.tail(20)), "the end of the live view was not written down")
        entries = {entry["event"]: entry for entry in running.core.audit.tail(50)}
        assert entries["live_opened"] | {"time": 0} == {"time": 0, "event": "live_opened", "ip": "127.0.0.1", "user": "admin", "device": "rack-1", "device_id": one}
        closed = entries["live_closed"]
        assert (closed["user"], closed["device_id"], closed["why"]) == ("admin", one, "closed") and 1 <= closed["seconds"] <= 5
        assert (entries["activity_exported"]["format"], entries["activity_exported"]["asked"]) == ("jsonl", {"kind": "action"})
        assert entries["device_added"]["device_id"] == one and "console_failed" not in entries
        kinds = {entry["event"] for entry in admin.get("/api/v1/audit", params={"kind": "action"}).json()["entries"]}
        assert {"live_opened", "live_closed"} <= kinds


def test_what_is_done_from_the_command_line_is_in_the_activity_log(tmp_path: Path) -> None:
    # An account's second step switched off, every account and saved password erased: from the command line where qKVM runs,
    # said in qkvm.log only, and not where whoever looks into what happened looks.
    with wall(tmp_path) as admin:
        account(admin, "olga", "operator")
    assert cli.main(["--data-dir", str(tmp_path), "--disable-2fa", "olga"]) == 0
    assert cli.main(["--data-dir", str(tmp_path), "--reset-password"]) == 0
    newest = AuditLog(tmp_path / "audit.log").tail(2)
    assert [(entry["event"], entry.get("account")) for entry in newest] == [("accounts_reset", None), ("totp_disabled", "olga")]
    assert all("command line" in entry["note"] for entry in newest)


def test_a_script_opening_live_views_in_a_loop_cannot_push_the_log_out(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two entries a live view: a script that opened and closed lines in a loop wrote them as fast as it could, and the log is
    # of a size. An account's live views write so many an hour; the rest is counted, and the next entry says how many.
    from qkvm import live
    from tests.test_live import Viewer, Wall

    monkeypatch.setattr(live, "LIVE_SAID_AN_HOUR", 6)
    with Wall(tmp_path) as running:
        admin = running.browser()
        one = running.add(admin, fake.url, name="rack-1")
        for _ in range(10):
            viewer = Viewer(running, one, running.ticket(admin, one))
            viewer.word("state")
            viewer.close()
            time.sleep(0.1)
        time.sleep(0.5)
        running.core.audit.flush(60)
        said = [entry for entry in running.core.audit.tail(100) if entry["event"].startswith("live_")]
        assert len(said) == 6, said
        monkeypatch.setattr(live, "LIVE_SAID_AN_HOUR", 3600)  # (an allowance that comes back within a second)
        time.sleep(1.1)
        viewer = Viewer(running, one, running.ticket(admin, one))
        viewer.word("state")
        viewer.close()
        wait_until(lambda: any(entry.get("unsaid") for entry in running.core.audit.tail(5)), "the entries left out were not said")
        assert next(entry for entry in running.core.audit.tail(5) if entry.get("unsaid"))["unsaid"] == 14


def test_a_script_asking_for_a_servers_console_in_a_loop_cannot_push_the_log_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An operator's script asking for a server's console in a loop wrote an entry a request, 251 a second against a stand-in
    # that answers at once (the reviewer of 0.2.0), and the log is of a size. A console opened, and one not had, each write so
    # many an hour of one account, as its live views do; the rest is counted, and the next entry of that account says how
    # many. And the opening of a server's console that no entry of the hour named is written all the same: spent on one
    # server, the allowance hid the opening of another (the reviewer of FX-C).
    from qkvm import redfish
    from tests import fake_redfish
    from tests.fake_redfish import FakeBmc

    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(activity, "CONSOLE_SAID_AN_HOUR", 3)
    spare, payroll = FakeBmc().start(), FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            one, other = add(admin, spare.url, name="spare server"), add(admin, payroll.url, name="payroll server")
            account(admin, "olga", "operator")
            olga = browser(admin, "olga", port=50002)
            monkeypatch.setattr(fake_redfish, "WAY_IN", "javascript:alert(1)?abc")  # (a way in the wall refuses: 502, not had)
            assert {olga.post(f"/api/v1/devices/{one}/console").status_code for _ in range(6)} == {502}
            assert olga.post(f"/api/v1/devices/{other}/console").status_code == 502  # (not had: nobody got in, nothing named)
            monkeypatch.setattr(fake_redfish, "WAY_IN", fake_redfish.UNSET)
            assert {olga.post(f"/api/v1/devices/{one}/console").status_code for _ in range(5)} == {200}
            assert olga.post(f"/api/v1/devices/{other}/console").status_code == 200
            assert admin.post(f"/api/v1/devices/{one}/console").status_code == 200  # (another account's allowance is its own)

            def written() -> list[tuple[str, str, str, int]]:
                admin.core.audit.flush(60)  # type: ignore[attr-defined]
                return [
                    (entry["user"], entry["event"], entry["device"], entry.get("unsaid", 0))
                    for entry in admin.core.audit.tail(1000)  # type: ignore[attr-defined]
                    if entry["event"].startswith("console_")
                ]

            assert written() == [
                ("admin", "console_opened", "spare server", 0),
                ("olga", "console_opened", "payroll server", 2),  # (written though the allowance was spent; two left out before it)
                *[("olga", "console_opened", "spare server", 0)] * 3,  # (the failures before took none of these)
                *[("olga", "console_failed", "spare server", 0)] * 3,
            ], written()
            monkeypatch.setattr(activity, "CONSOLE_SAID_AN_HOUR", 3600)  # (an allowance that comes back within a second)
            time.sleep(1.1)
            monkeypatch.setattr(fake_redfish, "WAY_IN", "javascript:alert(1)?abc")
            assert olga.post(f"/api/v1/devices/{one}/console").status_code == 502
            assert written()[0] == ("olga", "console_failed", "spare server", 4)  # (four not had were left out)
    finally:
        spare.stop()
        payroll.stop()


def test_an_allowance_writes_each_machine_once_an_hour_whatever_is_left_of_it(monkeypatch: pytest.MonkeyPatch) -> None:
    allowed = activity.Allowance(lambda: 2)
    assert [allowed.take("olga", "a") for _ in range(4)] == [0, 0, None, None]
    assert allowed.take("olga", "b") == 2  # (a machine not named this hour: written, with the count of what was left out)
    assert allowed.take("olga", "b") is None and allowed.take("ivan", "a") == 0  # (each account its own)
    monkeypatch.setattr(activity, "NAMED_AGAIN_AFTER", 0.0)  # (an hour on: named again)
    assert allowed.take("olga", "a") == 1 and allowed.take("olga", "a") == 0
    # Entries that name nothing (a console not had: nobody got in) have the allowance alone, however many machines there are.
    failures = activity.Allowance(lambda: 1)
    assert [failures.take("olga") for _ in range(3)] == [0, None, None]


def test_the_settings_file_says_how_large_the_activity_log_grows(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        assert admin.core.audit.max_bytes == 10_000_000  # type: ignore[attr-defined]  # (100 MB in ten files, as it comes)
    for said, each in ((20, 2_000_000), (0, 10_000_000), (-5, 10_000_000), (3, 1_000_000), (10**9, 10_000_000_000), ("50", 10_000_000), (True, 10_000_000), (12.5, 10_000_000), (None, 10_000_000)):
        saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
        saved["server"]["activity_mb"] = said
        (tmp_path / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
        with wall(tmp_path) as admin:
            assert admin.core.audit.max_bytes == each, said  # type: ignore[attr-defined]
    assert store.activity_file_bytes(100) == 10_000_000


def test_qkvm_status_says_how_large_the_activity_log_and_its_index_are(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "audit.log").write_bytes(b"x" * 1_500_000)
    (tmp_path / "audit.log.1").write_bytes(b"x" * 2_000_000)
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    assert "the activity log takes 3.5 MB in 2 files (audit.log)" in capsys.readouterr().out
    (tmp_path / activity.FILE).write_bytes(b"x" * 8_000_000)
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    assert "the activity log takes 3.5 MB in 2 files (audit.log), and its index 8.0 MB (audit.sqlite)" in capsys.readouterr().out
    assert sorted(path.name for path in tmp_path.iterdir()) == ["audit.log", "audit.log.1", "audit.sqlite"]  # (it only looks)


if sys.platform == "win32":

    def test_a_reader_of_the_text_files_does_not_keep_them_from_being_moved_on(tmp_path: Path) -> None:
        # On Windows a file that is open cannot be renamed or removed, unless it was opened saying it may be. The index reads
        # the text files all the time; opened the usual way, the writer could not move the full file on in that moment.
        text = AuditLog(tmp_path / "audit.log", max_bytes=200)
        for number in range(10):
            (tmp_path / ("audit.log" if number == 0 else f"audit.log.{number}")).write_text(json.dumps({"time": 1.0 + number, "event": "x", "ip": ""}) + "\n" * 300, encoding="utf-8")
        with store.open_shared(tmp_path / "audit.log") as newest, store.open_shared(tmp_path / "audit.log.9") as oldest:
            text.write("login", "", user="olga")
            text.flush(60)
            assert newest.read(1) == b"{" and oldest.read(1) == b"{"
        assert json.loads((tmp_path / "audit.log").read_text(encoding="utf-8"))["user"] == "olga"
        assert json.loads((tmp_path / "audit.log.1").read_text(encoding="utf-8").splitlines()[0])["time"] == 1.0

    def test_a_data_folder_on_a_share_is_read_through_its_index_and_its_history(tmp_path: Path) -> None:
        # A path on a share is file://server/share/... to Python, which SQLite refuses ("invalid uri authority"): every read
        # of the index went to the text files, and every read of the history failed, for as long as qKVM ran (the first
        # reviewer of W4c). This computer's own administrative share stands in for a file server.
        from qkvm import history

        share = Path("\\\\localhost\\" + tmp_path.drive[0] + "$" + str(tmp_path)[2:])
        if not share.exists():
            pytest.skip("no administrative share on this computer")
        text = AuditLog(share / "audit.log")
        index = activity.Index(share / activity.FILE, text)
        text.write("login", "", user="olga")
        text.flush(60)
        index.start()
        try:
            caught_up(index)
            assert index.read(activity.Asked(), 10).by == "index"
        finally:
            index.stop()
        kept = history.History(share / history.FILE)
        kept.observe("dev", {"state": "online", "error": None, "last_seen_ago": 0})
        kept.flush(60)
        try:
            assert kept.read("dev", "states", 0, 1e11)["rows"][0]["state"] == "online"
        finally:
            kept.stop()
