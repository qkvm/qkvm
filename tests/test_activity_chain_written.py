"""The activity log's chain as the writer writes it (store.AuditLog with the wall's key): into the files, from several
threads at once, over a crash and a refused write, as the oldest file goes, over a log an earlier version wrote; and
each way of editing the files by hand, caught by a check of the files as the wall makes it.

The check itself, line by line, is in test_activity_chain.py; the page and the offline check in test_activity_check.py.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import activity, chain, kvm, store, update, vault
from qkvm.core import Core
from qkvm.store import AuditLog, Store
from tests.settings_file import settings_text
from tests.test_wall import wall

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def written(path: Path) -> list[dict[str, Any]]:
    """The entries of one file, as they are there, the first first (lines that are no entry left out)."""
    found = []
    for line in path.read_bytes().split(b"\n"):
        entry = store.entry_of(line) if line else None
        if entry is not None:
            found.append(entry)
    return found


def check(log: AuditLog, key: bytes | None = KEY, anchors: dict[int, bytes] | None = None) -> chain.Verdict:
    """The files checked as the wall checks them: with the writer's own head where it has written (AuditLog.check)."""
    return log.check(chain.Walk(key, anchors))


def problems(verdict: chain.Verdict) -> list[tuple[int | None, str]]:
    return [(problem.line, problem.what) for problem in verdict.problems]


def a_log(folder: Path, lines: int, max_bytes: int = 10**9, key: bytes = KEY, forward: list[str] | None = None) -> AuditLog:
    log = AuditLog(folder / "audit.log", max_bytes=max_bytes, key=key, forward=forward.append if forward is not None else None)
    for number in range(lines):
        log.write(("login", "action", "device_changed")[number % 3], "192.0.2.10", user="olga", device="rack1-node02", device_id="0a1b2c3d", n=number)
    log.flush(30)
    return log


def plain_files(folder: Path, files: int, each: int) -> list[bytes]:
    """Files as an earlier version wrote them: audit.log.<files - 1> the oldest, audit.log the newest. Their bytes, oldest first."""
    names = [f"audit.log.{number}" for number in range(files - 1, 0, -1)] + ["audit.log"]
    made = []
    for index, name in enumerate(names):
        lines = [json.dumps({"time": 1700000000.0 + index * 1000 + number, "event": "login", "ip": "192.0.2.20", "user": f"user{number % 3}"}) + "\n" for number in range(each)]
        data = "".join(lines).encode()
        (folder / name).write_bytes(data)
        made.append(data)
    return made


# --- as it is written --------------------------------------------------------------------------------------------


def test_each_line_is_chained_and_signed_as_it_is_written(tmp_path: Path) -> None:
    sent: list[str] = []
    log = a_log(tmp_path, 50, forward=sent)
    entries = written(tmp_path / "audit.log")
    # The first line of a new log is its genesis seal: nothing came before it.
    assert entries[0]["event"] == chain.SEALED and (entries[0]["why"], entries[0]["before"], entries[0]["files"]) == ("genesis", 0, [])
    assert entries[0]["key"] == chain.key_id(KEY)
    assert [entry["chain"]["n"] for entry in entries] == list(range(1, 52))
    assert all(set(entry["chain"]) == {"n", "prev", "mac"} for entry in entries)
    verdict = check(log)
    assert verdict.intact and (verdict.first, verdict.last, verdict.chained) == (1, 51, 51), verdict.summary()
    assert log.head is not None and verdict.head == log.head[1].hex() and log.head[0] == 51
    # What is sent on (syslog) is what is written, the chain with it: every line a head kept outside the wall.
    assert [json.loads(line) for line in sent] == entries
    assert chain.anchors_in("\n".join(sent)) == {number: chain.link(chain.hex_head(entry["chain"]["prev"]) or b"", number, chain.digest(entry)) for number, entry in enumerate(entries, 1)}
    log.close()


def test_without_a_key_lines_are_written_as_before(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log")
    log.write("login", "192.0.2.10", user="olga")
    assert log.seal("start") is None
    log.close()
    [entry] = written(tmp_path / "audit.log")
    assert "chain" not in entry and entry["event"] == "login"


def test_a_field_called_chain_is_never_taken_for_the_chain(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log", key=KEY)
    log.write("device_changed", "192.0.2.10", chain={"n": 1, "prev": "00" * 32, "mac": "00" * 16})
    log.close()
    entry = written(tmp_path / "audit.log")[-1]
    assert entry["chain_"] == {"n": 1, "prev": "00" * 32, "mac": "00" * 16} and entry["chain"]["n"] == 2
    assert check(log).intact


def test_many_threads_writing_at_once_chain_every_line_once_and_in_order(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log", max_bytes=200_000, key=KEY)
    barrier = threading.Barrier(8)

    def busy(who: int) -> None:
        barrier.wait()
        for number in range(400):
            log.write("action", "192.0.2.10", user=f"user{who}", n=number)
            if number % 100 == 0:
                log.seal("daily")

    threads = [threading.Thread(target=busy, args=(who,)) for who in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    log.close(30)
    verdict = check(log)
    assert verdict.intact, verdict.summary()
    # Every line once: 3,200 entries and 32 seals asked for, with the genesis, and the seals of the files that went.
    lines = [entry for path in reversed(log.files()) if path.exists() for entry in written(path)]
    numbers = [entry["chain"]["n"] for entry in lines]
    assert numbers == list(range(numbers[0], numbers[0] + len(numbers)))
    assert sum(entry["event"] == "action" for entry in lines) + verdict.let_go >= 3200


def test_a_line_a_crash_cut_off_leaves_a_log_that_checks_to_its_last_line(tmp_path: Path) -> None:
    log = a_log(tmp_path, 20)
    log.close()
    path = tmp_path / "audit.log"
    whole = path.read_bytes()
    last = whole.rstrip(b"\n").rsplit(b"\n", 1)[1]
    # Cut off in the middle of its last line: that line is no line of the log, and the rest checks.
    path.write_bytes(whole[: -len(last) // 2])
    assert check(AuditLog(path, key=KEY)).intact
    again = a_log(tmp_path, 5)
    verdict = check(again)
    assert verdict.intact and verdict.last == 25, verdict.summary()  # (the genesis and 20 lines; the last of them lost; 5 more)
    again.close()
    # Cut off just before its line feed: the line is whole, and is the last of the chain once it is ended. Its number is
    # never given again.
    whole = path.read_bytes()
    path.write_bytes(whole[:-1])
    after = a_log(tmp_path, 3)
    verdict = check(after)
    assert verdict.intact and verdict.last == 28, verdict.summary()
    after.seal("stop")
    after.close()
    # A line an earlier version wrote after the wall stopped, cut off just before its line feed (rolled back, and that one's
    # power cut): it is a line of the log once it is ended, and is taken in with the others the next start finds without the
    # chain.
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}))
    last = a_log(tmp_path, 2)
    verdict = check(last)
    assert verdict.intact and verdict.unchained == 1, verdict.summary()
    last.close()


def test_a_write_the_disk_refused_gives_no_number_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = a_log(tmp_path, 5)
    real = store.private
    refusals = ["nothing", "all but its end"]  # how the next writes into audit.log go, one each

    class Refusing:
        """A file that takes nothing, or all but the end of what it is given, and then refuses (a disk that just became full)."""

        def __init__(self, inner: Any, how: str) -> None:
            self.inner, self.how = inner, how

        def __enter__(self) -> Refusing:
            return self

        def __exit__(self, *_: Any) -> None:
            self.inner.close()

        def write(self, text: str) -> int:
            if self.how != "nothing":
                self.inner.write(text[:-20])
            raise OSError(28, "No space left on device")

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

    def private(path: Any, mode: str = "w", **how: Any) -> Any:
        opened = real(path, mode, **how)
        if refusals and Path(path).name == "audit.log":
            return Refusing(opened, refusals.pop(0))
        return opened

    monkeypatch.setattr(store, "private", private)
    log.write("login", "192.0.2.10", user="lost")
    # Then the hole is said before the next line, and that write is cut short: the hole's line is whole on the disk, the next
    # one is not. Where the chain stands is read again from the file, and the hole's number is not given again.
    log.write("login", "192.0.2.10", user="lost too")
    log.write("login", "192.0.2.10", user="kept")
    log.flush()
    assert log.missing is not None and log.missing["count"] == 2
    verdict = check(log)
    assert verdict.intact, verdict.summary()
    lines = written(tmp_path / "audit.log")
    assert [entry.get("user") for entry in lines[-3:]] == [None, None, "kept"] and [entry["event"] for entry in lines[-3:]] == ["log_gap", "log_gap", "login"]
    log.close()


# --- what goes, and what came before ------------------------------------------------------------------------------


def test_the_oldest_file_goes_with_a_seal_and_the_rest_checks_intact(tmp_path: Path) -> None:
    log = a_log(tmp_path, 400, max_bytes=3000)
    assert (tmp_path / "audit.log.9").exists()
    seals = [entry for path in log.files() if path.exists() for entry in written(path) if entry["event"] == chain.SEALED and entry["why"] == "pruned"]
    assert seals and all(isinstance(seal["to"], int) and len(seal["head"]) == 64 for seal in seals)
    verdict = check(log)
    assert verdict.intact, verdict.summary()
    assert verdict.let_go > 0 and verdict.first == verdict.let_go + 1
    log.close()
    # The oldest file taken away by hand: nothing says it was let go.
    (tmp_path / "audit.log.9").unlink()
    verdict = check(AuditLog(tmp_path / "audit.log", key=KEY))
    assert [what for _, what in problems(verdict)] == ["pruned"], verdict.summary()


def test_a_log_an_earlier_version_wrote_is_taken_in_and_never_broken(tmp_path: Path) -> None:
    before = plain_files(tmp_path, 3, 40)
    log = a_log(tmp_path, 10)
    # Nothing that was there is changed: the new lines come after the old ones.
    assert (tmp_path / "audit.log.2").read_bytes() == before[0] and (tmp_path / "audit.log").read_bytes().startswith(before[2])
    genesis = written(tmp_path / "audit.log")[40]
    assert (genesis["why"], genesis["before"], genesis["chain"]["n"]) == ("genesis", 120, 121)
    assert [cut[0] for cut in genesis["files"]] == [40, 80, 120]
    verdict = check(log)
    assert verdict.intact and verdict.before == 120 and (verdict.first, verdict.last) == (121, 131), verdict.summary()
    assert "120 from before the chain" in verdict.summary()
    log.close()
    # One of those lines changed since.
    oldest = tmp_path / "audit.log.2"
    oldest.write_bytes(oldest.read_bytes().replace(b'"user": "user1"', b'"user": "admin"', 1))
    assert problems(check(AuditLog(tmp_path / "audit.log", key=KEY))) == [(121, "before")]


def test_files_from_before_the_chain_go_as_the_log_grows_and_the_rest_checks(tmp_path: Path) -> None:
    plain_files(tmp_path, 10, 30)
    log = a_log(tmp_path, 30, max_bytes=3000)
    # The oldest files, from before the chain, went one at a time, each with its seal: how many lines it held.
    seals = [entry for path in log.files() if path.exists() for entry in written(path) if entry.get("why") == "pruned"]
    assert seals and all(seal["to"] is None and seal["let_go"] == 30 for seal in seals)
    verdict = check(log)
    assert verdict.intact, verdict.summary()
    assert verdict.let_go == 30 * len(seals) and verdict.before == 300 - verdict.let_go
    # And on, until every file from before the chain went, and the genesis seal's with them.
    for number in range(300):
        log.write("action", "192.0.2.10", user="olga", n=number)
    log.flush(30)
    verdict = check(log)
    assert verdict.intact and verdict.before == 0 and verdict.let_go > 300, verdict.summary()
    log.close()


def test_lines_an_earlier_version_wrote_in_between_are_sealed_at_the_next_start(tmp_path: Path) -> None:
    first = a_log(tmp_path, 10)
    first.seal("stop")
    first.close()
    # Rolled back to 0.3.2 for a while (qkvm --roll-back), after this one stopped: its lines carry no chain.
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        for number in range(4):
            file.write(json.dumps({"time": 1763300100.0 + number, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    log = a_log(tmp_path, 3)
    seal = written(tmp_path / "audit.log")[16]
    assert (seal["event"], seal["why"], seal["count"]) == (chain.SEALED, "unchained", 4)
    verdict = check(log)
    # Intact where it is chained, and said as not proved: who wrote those four, nothing says.
    assert verdict.intact and verdict.unchained == 4 and verdict.unchained_after == 12, verdict.summary()
    assert verdict.summary().startswith("Intact where it is chained, and not all of it proved: 4 lines written without the chain after the wall stopped at line 12")
    log.close()


# --- every way of editing the files by hand ---------------------------------------------------------------------


def edited(path: Path, change: Any) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text("".join(change(lines)), encoding="utf-8")


def field_changed(lines: list[str]) -> list[str]:
    lines[20] = lines[20].replace('"user": "olga"', '"user": "ivan"')
    return lines


def taken_out(lines: list[str]) -> list[str]:
    return lines[:20] + lines[21:]


def swapped(lines: list[str]) -> list[str]:
    lines[20], lines[21] = lines[21], lines[20]
    return lines


def put_in(lines: list[str]) -> list[str]:
    return lines[:20] + [json.dumps({"time": 1763300000.0, "event": "login", "ip": "192.0.2.66", "user": "admin"}) + "\n"] + lines[20:]


def rewritten_without_the_key(lines: list[str]) -> list[str]:
    """From line 21 on written anew, the chain worked out again with a key of the editor's own (the wall's is in the vault)."""
    entries = [json.loads(line) for line in lines]
    number, head = entries[19]["chain"]["n"], chain.link(bytes.fromhex(entries[19]["chain"]["prev"]), entries[19]["chain"]["n"], chain.digest(entries[19]))
    out = lines[:20]
    for entry in entries[20:]:
        if entry["event"] == "action":
            continue
        entry.pop("chain")
        line = json.dumps(entry) + "\n"
        number += 1
        stamped, head = chain.stamp(line, json.loads(line), number, head, OTHER_KEY)
        out.append(stamped)
    return out


@pytest.mark.parametrize(
    ("change", "found"),
    [(field_changed, (21, "unsigned")), (taken_out, (21, "missing")), (swapped, (21, "order")), (put_in, (21, "inserted")), (rewritten_without_the_key, (21, "unsigned"))],
)
def test_each_edit_of_the_files_by_hand_is_caught(tmp_path: Path, change: Any, found: tuple[int, str]) -> None:
    a_log(tmp_path, 40).close()
    assert check(AuditLog(tmp_path / "audit.log", key=KEY)).intact
    edited(tmp_path / "audit.log", change)
    verdict = check(AuditLog(tmp_path / "audit.log", key=KEY))
    assert problems(verdict)[0] == found, verdict.summary()
    assert verdict.summary().startswith(f"Broken at line {found[0]}")


def test_a_log_rewritten_with_the_key_is_caught_by_the_heads_syslog_kept(tmp_path: Path) -> None:
    sent: list[str] = []
    a_log(tmp_path, 40, forward=sent).close()
    kept = chain.anchors_in("\n".join(sent))

    def with_the_key(lines: list[str]) -> list[str]:
        entries = [json.loads(line) for line in lines]
        number, head = 20, chain.link(bytes.fromhex(entries[19]["chain"]["prev"]), 20, chain.digest(entries[19]))
        out = lines[:20]
        for entry in entries[20:]:
            entry.pop("chain")
            entry["user"] = "ivan" if entry.get("user") == "olga" else entry.get("user")
            line = json.dumps(entry) + "\n"
            number += 1
            stamped, head = chain.stamp(line, json.loads(line), number, head, KEY)
            out.append(stamped)
        return out

    edited(tmp_path / "audit.log", with_the_key)
    assert check(AuditLog(tmp_path / "audit.log", key=KEY)).intact  # (the key alone cannot tell)
    verdict = check(AuditLog(tmp_path / "audit.log", key=KEY), anchors=kept)
    assert problems(verdict)[0] == (21, "anchor"), verdict.summary()


def test_the_end_cut_off_while_the_wall_runs_is_caught_by_its_writers_head(tmp_path: Path) -> None:
    log = a_log(tmp_path, 30)
    path = tmp_path / "audit.log"
    lines = path.read_bytes().split(b"\n")
    path.write_bytes(b"\n".join(lines[:-6]) + b"\n")  # (the last five lines gone)
    verdict = check(log)
    assert problems(verdict) == [(27, "cut")], verdict.summary()
    log.close()


# --- seals of the writer's own ----------------------------------------------------------------------------------


def test_a_seal_is_written_every_so_often_while_lines_come_and_not_while_none_do(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "SEAL_EVERY", 0.3)
    log = a_log(tmp_path, 3)
    deadline = time.monotonic() + 10
    while not any(entry.get("why") == "hourly" for entry in written(tmp_path / "audit.log")):
        assert time.monotonic() < deadline, "no seal was written after lines were"
        time.sleep(0.05)
    count = len(written(tmp_path / "audit.log"))
    time.sleep(1.0)
    assert len(written(tmp_path / "audit.log")) == count  # (nothing written since: no seal)
    assert check(log).intact
    log.close()


def test_a_wall_that_writes_all_the_time_is_sealed_every_so_often_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The writer's own seal came where it waited for a line longer than SEAL_EVERY: a wall that writes a line every few seconds
    # (alerts of many machines) was never sealed between its start and its stop, and the settings kept no later place of its
    # chain than its start. It is sealed every SEAL_EVERY now, however busy.
    monkeypatch.setattr(store, "SEAL_EVERY", 0.3)
    kept = Kept()
    log = AuditLog(tmp_path / "audit.log", key=KEY, held=lambda: kept.at)
    log.on_sealed = kept.keep
    until = time.monotonic() + 1.5
    while time.monotonic() < until:
        log.write("alert", "", device="rack1-node02", state="online")
        time.sleep(0.02)
    log.flush(30)
    hourly = [entry for entry in written(tmp_path / "audit.log") if entry.get("why") == "hourly"]
    assert len(hourly) >= 3, len(hourly)
    assert kept.at is not None and kept.at[0] == hourly[-1]["chain"]["n"]
    log.close()


def test_a_seal_the_disk_refuses_is_tried_again_at_its_next_time_and_not_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "SEAL_EVERY", 0.3)
    log = a_log(tmp_path, 3)
    real = store.private

    def full(path: Any, mode: str = "w", **how: Any) -> Any:
        if Path(path).name == "audit.log":
            raise OSError(28, "No space left on device")
        return real(path, mode, **how)

    monkeypatch.setattr(store, "private", full)
    time.sleep(1.5)
    # One try a SEAL_EVERY at the most (each counted as an entry not written): not one every few hundredths of a second.
    assert log.missing is not None and 1 <= log.missing["count"] <= 6, log.missing
    monkeypatch.setattr(store, "private", real)
    log.close()


def test_a_seal_says_when_it_was_asked_for_and_one_the_writer_writes_before_a_line_that_lines_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The writer's first look at a long log takes seconds (3 s for 50 MB). The genesis it writes then said the moment it was
    # written, after the start seal asked for before it and the lines given meanwhile: the log's times went backwards there,
    # and a download of a long log on a slow runner was out of the order of its times.
    plain_files(tmp_path, 2, 10)
    real = AuditLog._begin

    def slowly(self: AuditLog, *args: Any) -> list[str]:
        time.sleep(1.1)
        return real(self, *args)

    monkeypatch.setattr(AuditLog, "_begin", slowly)
    log = AuditLog(tmp_path / "audit.log", key=KEY)
    log.seal("start")
    log.write("login", "192.0.2.10", user="olga")
    log.close(30)
    genesis, start, login = written(tmp_path / "audit.log")[10:]
    assert (genesis["why"], start["why"], login["event"]) == ("genesis", "start", "login")
    assert genesis["time"] == start["time"] <= login["time"] < start["time"] + 1, (genesis["time"], start["time"], login["time"])
    assert check(log).intact


def test_a_seal_asked_for_says_its_place_in_the_chain(tmp_path: Path) -> None:
    log = a_log(tmp_path, 3)
    place = log.sealed("daily")
    assert place is not None and place == log.head
    last = written(tmp_path / "audit.log")[-1]
    assert (last["why"], last["chain"]["n"]) == ("daily", place[0])
    assert chain.link(bytes.fromhex(last["chain"]["prev"]), place[0], chain.digest(last)) == place[1]
    log.close()


# --- the wall: its key, its seals, a folder 0.3.2 left -------------------------------------------------------------


def test_a_wall_of_0_3_2_starts_with_its_log_its_index_and_its_settings_as_they_were(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with wall(tmp_path):
        pass
    # The folder as 0.3.2 left it: its settings without the activity log's key, its log without the chain, its index of it.
    settings = Store(tmp_path / "qkvm.json")
    document = settings.snapshot()
    document.pop("activity_key")
    document.pop("activity_position")  # (neither is in the settings of 0.3.2)
    settings.write(document)
    old = [{"time": 1763000000.0 + number, "event": ("login", "action")[number % 2], "ip": "192.0.2.20", "user": "olga", "device": "rack1-node02"} for number in range(60)]
    (tmp_path / "audit.log").write_text("".join(json.dumps(entry) + "\n" for entry in old), encoding="utf-8")
    for tail in ("", "-wal", "-shm"):
        (tmp_path / (activity.FILE + tail)).unlink(missing_ok=True)
    text = AuditLog(tmp_path / "audit.log")
    index = activity.Index(tmp_path / activity.FILE, text)
    index.start()
    assert index.caught_up(30) is not None
    index.stop()
    caplog.clear()
    with wall(tmp_path) as admin:
        key = admin.core.store.activity_key  # type: ignore[attr-defined]
        assert len(key) == 64 and json.loads(settings_text(tmp_path / "qkvm.json"))["activity_key"] == key
        shown = admin.get("/api/v1/audit", params={"limit": 500}).json()["entries"]
        assert [entry for entry in shown if "chain" not in entry] == old[::-1]  # (each as it was)
        genesis = next(entry for entry in shown if entry.get("why") == "genesis")
        assert (genesis["before"], genesis["chain"]["n"]) == (60, 61)
    assert not [record for record in caplog.records if "made again" in record.getMessage()]  # (the index of 0.3.2 kept)
    # The key in the clear nowhere in the data folder: the settings are sealed, and the log holds what it signed, not it.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert key.encode() not in path.read_bytes() and bytes.fromhex(key) not in path.read_bytes(), path.name
    verdict = AuditLog(tmp_path / "audit.log", key=bytes.fromhex(key)).check(chain.Walk(bytes.fromhex(key)))
    assert verdict.intact and verdict.before == 60, verdict.summary()
    whys = [entry.get("why") for entry in written(tmp_path / "audit.log") if entry["event"] == chain.SEALED]
    assert whys == ["genesis", "start", "stop"]


def test_a_wall_seals_each_start_and_end_and_a_run_cut_short_shows(tmp_path: Path) -> None:
    for _ in range(2):
        with wall(tmp_path) as admin:
            admin.post("/api/v1/logout")
    key = bytes.fromhex(Store(tmp_path / "qkvm.json").activity_key)
    whys = [entry.get("why") for entry in written(tmp_path / "audit.log") if entry["event"] == chain.SEALED]
    assert whys == ["genesis", "start", "stop", "start", "stop"]
    verdict = AuditLog(tmp_path / "audit.log", key=key).check(chain.Walk(key))
    assert verdict.intact and verdict.notes == [], verdict.summary()
    # The settings keep where the chain had come to: the last seal, the stop.
    *_, stop = (entry for entry in written(tmp_path / "audit.log") if entry["event"] == chain.SEALED)
    head = chain.link(bytes.fromhex(stop["chain"]["prev"]), stop["chain"]["n"], chain.digest(stop))
    assert Store(tmp_path / "qkvm.json").activity_position == {"n": stop["chain"]["n"], "head": head.hex()}
    # A run cut short (a crash: lines after its last seal, and no stop seal): said at the next start, and not broken.
    crashed = Core(tmp_path)
    crashed.audit.seal("start")
    crashed.audit.write("login", "192.0.2.10", user="admin")
    crashed.audit.close(30)
    with wall(tmp_path):
        pass
    verdict = AuditLog(tmp_path / "audit.log", key=key).check(chain.Walk(key))
    assert verdict.intact and len(verdict.notes) == 1 and "ended without its stop seal" in verdict.notes[0], verdict.summary()
    # Its end taken away while the wall was stopped (no power cut takes a seal: each is on the disk before it is kept): the
    # next start finds the chain ending before where the settings say it had come to, and says so in a seal every check
    # counts as a problem.
    path = tmp_path / "audit.log"
    lines = path.read_bytes().split(b"\n")
    path.write_bytes(b"\n".join(lines[:-2]) + b"\n")
    with wall(tmp_path):
        pass
    verdict = AuditLog(tmp_path / "audit.log", key=key).check(chain.Walk(key))
    assert [problem.what for problem in verdict.problems] == ["found"], verdict.summary()
    assert "the chain ends at line" in verdict.problems[0].said and "the wall had written it up to line" in verdict.problems[0].said


# --- edits made while the log is out of the wall's hands (the review of wave 2, H1) -------------------------------


class Kept:
    """Where the chain had come to, as the wall keeps it in its sealed settings (here in memory): the place of every seal."""

    def __init__(self) -> None:
        self.at: tuple[int, bytes] | None = None

    def keep(self, why: str, number: int, head: bytes) -> None:
        self.at = (number, head)


def a_run(folder: Path, kept: Kept, lines: int = 40, stop: bool = True) -> AuditLog:
    """A run of the wall: its start, lines (the 21st a press of the power button), its stop; every seal's place kept."""
    log = AuditLog(folder / "audit.log", key=KEY, held=lambda: kept.at)
    log.on_sealed = kept.keep
    log.seal("start")
    for number in range(lines):
        log.write("action", "192.0.2.10", user="olga", device="rack1", action="atx_power" if number == 20 else "keys", n=number)
    if stop:
        log.seal("stop")
    log.flush(30)
    return log


def started_again(folder: Path, kept: Kept | None) -> chain.Verdict:
    """The next start, a line, and a check as the page makes it."""
    log = AuditLog(folder / "audit.log", key=KEY, held=(lambda: kept.at) if kept is not None else None)
    log.seal("start")
    log.write("login", "192.0.2.10", user="admin")
    log.flush(30)
    verdict = log.check(chain.Walk(KEY))
    log.close()
    return verdict


def stripped(path: Path, start: int, power: bool = True) -> None:
    """The chain taken away from line `start` of the file on, and the press of the power button taken out (no key needed)."""
    out = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(keepends=True)):
        if index >= start:
            entry = json.loads(line)
            entry.pop("chain", None)
            if power and entry.get("action") == "atx_power":
                continue
            line = json.dumps(entry) + "\n"
        out.append(line)
    path.write_text("".join(out), encoding="utf-8")


def found(verdict: chain.Verdict) -> list[str]:
    return [problem.said for problem in verdict.problems if problem.what == "found"]


def test_a_tail_stripped_of_its_chain_and_edited_is_not_taken_in_at_the_next_start(tmp_path: Path) -> None:
    # The review's probe 1: the chain taken away from line 10 on, the press of the power button taken out, a restart. The
    # writer took the stripped lines in as written by an earlier version, signed with the real key, and the check said
    # "Intact". Now lines without the chain are taken in only right after a stop seal: these come after line 9.
    kept = Kept()
    a_run(tmp_path, kept).close()
    stripped(tmp_path / "audit.log", 10)
    verdict = started_again(tmp_path, kept)
    assert not verdict.intact and found(verdict), verdict.summary()
    assert "the chain ends at line 10, and the wall had written it up to line 43" in found(verdict)[0]
    # And so where nothing was kept (a wall whose settings are gone): they do not come after a stop.
    other = tmp_path / "other"
    other.mkdir()
    a_run(other, Kept()).close()
    stripped(other / "audit.log", 10)
    verdict = started_again(other, None)
    assert not verdict.intact and "lines without the chain after line 10, where the wall did not stop" in found(verdict)[0], verdict.summary()


def test_a_log_stripped_of_every_chain_is_not_begun_again(tmp_path: Path) -> None:
    # Probe 1 again: every line stripped, the press taken out: the writer began the chain anew over all of it ("from before
    # the chain"). A genesis now only where the settings know of no chain, and only over lines none of which is a seal.
    kept = Kept()
    a_run(tmp_path, kept).close()
    stripped(tmp_path / "audit.log", 0)
    verdict = started_again(tmp_path, kept)
    assert not verdict.intact and "no line of the log has the chain, and the wall had written it up to line 43" in found(verdict)[0], verdict.summary()
    other = tmp_path / "other"
    other.mkdir()
    a_run(other, Kept()).close()
    stripped(other / "audit.log", 0)
    verdict = started_again(other, None)
    assert not verdict.intact and "of the lines found are seals of the chain with their chain taken away" in found(verdict)[0], verdict.summary()


def test_the_end_of_a_log_cut_off_while_the_wall_was_stopped_is_caught_by_what_its_settings_keep(tmp_path: Path) -> None:
    # Probe 1, the last part: the tail (the press, the stop seal) cut off while the wall was stopped. Only the settings know.
    kept = Kept()
    a_run(tmp_path, kept).close()
    path = tmp_path / "audit.log"
    path.write_text("".join(path.read_text(encoding="utf-8").splitlines(keepends=True)[:20]), encoding="utf-8")
    verdict = started_again(tmp_path, kept)
    assert not verdict.intact and "the chain ends at line 20, and the wall had written it up to line 43" in found(verdict)[0], verdict.summary()


def test_a_tail_stripped_while_the_wall_runs_is_not_taken_in_after_a_refused_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The review's probe 3: no restart. One write the disk refuses makes the writer read where the chain stands again before
    # its next line; the tail stripped meanwhile was taken in. It is held to the head it wrote last now.
    log = a_run(tmp_path, Kept(), stop=False)
    real = store.private
    refused: list[int] = []

    def full_once(path: Any, mode: str = "w", **how: Any) -> Any:
        if not refused and Path(path).name == "audit.log":
            refused.append(1)
            raise OSError(28, "No space left on device")
        return real(path, mode, **how)

    monkeypatch.setattr(store, "private", full_once)
    log.write("login", "192.0.2.10", user="nobody")
    log.flush(30)
    monkeypatch.setattr(store, "private", real)
    stripped(tmp_path / "audit.log", 10)
    log.write("login", "192.0.2.10", user="admin")
    log.flush(30)
    verdict = log.check(chain.Walk(KEY))
    assert not verdict.intact and "the chain ends at line 10, and the wall had written it up to line 42" in found(verdict)[0], verdict.summary()
    log.close()


def test_lines_after_the_stop_seal_are_taken_in_only_where_none_of_them_is_a_seal(tmp_path: Path) -> None:
    # A stop seal whose chain is taken away, and lines put in after it: the run looks as if it never stopped, and the lines
    # as if an earlier version wrote them. Seals among them are seals of this program's: not taken in.
    kept = Kept()
    a_run(tmp_path, kept).close()
    path = tmp_path / "audit.log"
    stripped(path, 42, power=False)  # (the stop seal, line 43: the file's 43rd)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    verdict = started_again(tmp_path, None)
    assert not verdict.intact and found(verdict), verdict.summary()
    # Lines an earlier version wrote after a stop seal that is there: taken in, and said as not proved.
    other = tmp_path / "other"
    other.mkdir()
    kept = Kept()
    a_run(other, kept).close()
    with (other / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    verdict = started_again(other, kept)
    assert verdict.intact and verdict.unchained == 1 and verdict.summary().startswith("Intact where it is chained, and not all of it proved"), verdict.summary()


def test_a_run_that_stopped_as_it_should_starts_again_intact(tmp_path: Path) -> None:
    kept = Kept()
    a_run(tmp_path, kept).close()
    assert kept.at is not None and kept.at[0] == 43
    verdict = started_again(tmp_path, kept)
    assert verdict.intact and verdict.summary().startswith("Intact: lines 1 to 45"), verdict.summary()


@pytest.mark.parametrize("how", ["its fsync fails", "all but its end is written"])
def test_a_seal_of_what_goes_the_disk_refuses_refuses_its_line_with_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # The review of wave 2, L3 (its probe 4): the seal written before the oldest file goes failed (its fsync), the line being
    # written went in all the same, without the chain (the writer's place unknown then), and nothing said it was refused.
    # Now the line is refused with the seal, counted, and the next start of a line is where a line ends.
    path = tmp_path / "audit.log"
    log = AuditLog(path, max_bytes=2000, key=KEY)
    while not log._old(AuditLog.OLD_FILES).exists():
        log.write("action", "192.0.2.10", user="olga")
        log.flush(30)
    while path.stat().st_size <= log.max_bytes:
        log.write("action", "192.0.2.10", user="olga", filler=True)
        log.flush(30)
    real_fsync, real_private = store.os.fsync, store.private
    failed: list[int] = []

    def fsync_fails(descriptor: int) -> None:
        if not failed:
            failed.append(1)
            raise OSError(5, "Input/output error")
        real_fsync(descriptor)

    class Cut:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def __enter__(self) -> Cut:
            return self

        def __exit__(self, *_: Any) -> None:
            self.inner.close()

        def write(self, text: str) -> int:
            self.inner.write(text[:-20])
            raise OSError(28, "No space left on device")

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

    def private_cut(where: Any, mode: str = "w", **kept: Any) -> Any:
        opened = real_private(where, mode, **kept)
        if not failed and Path(where).name == "audit.log":
            failed.append(1)
            return Cut(opened)
        return opened

    if how == "its fsync fails":
        monkeypatch.setattr(store.os, "fsync", fsync_fails)
    else:
        monkeypatch.setattr(store, "private", private_cut)
    log.write("action", "192.0.2.10", user="olga", action="atx_power", marker="THE-LINE")
    log.flush(30)
    monkeypatch.setattr(store.os, "fsync", real_fsync)
    monkeypatch.setattr(store, "private", real_private)
    log.write("login", "192.0.2.10", user="admin")
    log.flush(30)
    assert log.missing is not None and log.missing["count"] == 1, how
    lines = [entry for name in reversed(log.files()) if name.exists() for entry in written(name)]
    assert all("chain" in entry for entry in lines if entry.get("marker") == "THE-LINE"), how
    assert lines[-1]["event"] == "login" and lines[-2]["event"] == "log_gap", how
    verdict = check(log)
    assert verdict.intact and verdict.unchained == 0, (how, verdict.summary())
    log.close()


def test_a_line_with_a_name_twice_is_no_entry_of_the_log(tmp_path: Path) -> None:
    # The review of wave 2, L4: a reader of JSON keeps the last of two fields of one name. A "user" put in before the real
    # one left the hash, the page and the check as they were, and whoever reads the file as text (grep, a collector) read
    # the other name. Such a line is no entry now, for the page, the downloads and the check alike: in the chain, missing.
    assert store.entry_of(b'{"time": 1763300000.0, "event": "login", "ip": "", "user": "ivan", "user": "olga"}') is None
    assert store.entry_of(b'{"time": 1763300000.0, "event": "activity_exported", "ip": "", "asked": {"q": ["a"], "q": ["b"]}}') is None
    assert store.entry_of(b'{"time": 1763300000.0, "event": "login", "ip": "", "user": "olga"}') is not None
    a_log(tmp_path, 10).close()
    path = tmp_path / "audit.log"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    assert lines[5].startswith('{"time": ')
    lines[5] = '{"user": "ivan", ' + lines[5][1:]
    path.write_text("".join(lines), encoding="utf-8")
    verdict = check(AuditLog(path, key=KEY))
    assert [(problem.line, problem.what) for problem in verdict.problems] == [(6, "missing")], verdict.summary()


def test_a_line_made_up_with_any_number_never_keeps_the_wall_from_starting(tmp_path: Path) -> None:
    # The re-review of wave 2, N1: a line with a chain made up (no key needed), numbered 2**63 - 1, was taken by the next start
    # for where the chain stands; its seals were numbered past 2**63, that place was kept in the sealed settings, and the start
    # after could not read them (both copies): the wall did not start, and its accounts and saved passwords were lost. A line
    # whose signature does not check is never relied on now: it is a line without the wall's chain, so the start says broken.
    with wall(tmp_path):
        pass
    made_up = {"time": 1763000000.0, "event": "action", "ip": "192.0.2.66", "user": "ivan", "chain": {"n": 2**63 - 1, "prev": "0" * 64, "mac": "0" * 32}}
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps(made_up) + "\n")
    with wall(tmp_path):
        pass
    with wall(tmp_path):  # (the start after: the settings read, the wall up)
        pass
    kept = Store(tmp_path / "qkvm.json").activity_position
    assert kept is not None and kept["n"] < 100, kept
    key = bytes.fromhex(Store(tmp_path / "qkvm.json").activity_key)
    verdict = AuditLog(tmp_path / "audit.log", key=key).check(chain.Walk(key))
    assert "found" in {problem.what for problem in verdict.problems}, verdict.summary()
    assert any("carry a chain the wall did not sign" in said for said in found(verdict)), found(verdict)


def test_a_line_made_up_after_the_stop_seal_is_not_where_the_chain_stands(tmp_path: Path) -> None:
    # The same with a number that fits: a line made up right after the stop seal, linked to it, signed with a key of its
    # own. The next start does not go on from it: it says it found a line the wall did not sign.
    kept = Kept()
    a_run(tmp_path, kept).close()
    after = made_up_after(tmp_path / "audit.log")
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps(after) + "\n")
    verdict = started_again(tmp_path, kept)
    assert any("carry a chain the wall did not sign" in said for said in found(verdict)), verdict.summary()


def made_up_after(path: Path) -> dict[str, Any]:
    """A line made up after the last line of `path`, linked to it, signed with somebody else's key."""
    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    number = last["chain"]["n"]
    head = chain.link(bytes.fromhex(last["chain"]["prev"]), number, chain.digest(last))
    line = json.dumps({"time": last["time"] + 1, "event": "action", "ip": "192.0.2.66", "user": "ivan", "action": "atx_power"}) + "\n"
    stamped, _ = chain.stamp(line, json.loads(line), number + 1, head, OTHER_KEY)
    return dict(json.loads(stamped))


def test_a_place_the_settings_would_not_read_back_is_never_kept(tmp_path: Path) -> None:
    # (Whoever holds the key can sign a line at the last number there is: the seals after it are past what the settings read
    # back. That place is not kept, and the wall starts again.)
    with wall(tmp_path):
        pass
    key = bytes.fromhex(Store(tmp_path / "qkvm.json").activity_key)
    path = tmp_path / "audit.log"
    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    head = chain.link(bytes.fromhex(last["chain"]["prev"]), last["chain"]["n"], chain.digest(last))
    line = json.dumps({"time": last["time"] + 1, "event": "action", "ip": "192.0.2.66", "user": "ivan"}) + "\n"
    stamped, _ = chain.stamp(line, json.loads(line), 2**63 - 1, head, key)
    with path.open("a", encoding="utf-8") as file:
        file.write(stamped)
    kept = Store(tmp_path / "qkvm.json").activity_position
    with wall(tmp_path):
        pass
    with wall(tmp_path):
        pass
    assert Store(tmp_path / "qkvm.json").activity_position == kept


def test_the_stop_seals_place_is_saved_by_the_stop_itself_whoever_kept_it_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The re-review of wave 2, N4: the writer's callback kept the stop seal's place in memory first and set a save going in the
    # background; the stop then found it kept, and did not wait for a save. A save that still waited for its turn as the
    # program ended was let go of, and the settings kept the place of the hour before. The stop waits for it now.
    import asyncio

    taken: list[tuple[Any, str]] = []
    real = Store.snapshot

    def watched(self: Store) -> dict[str, Any]:
        data = real(self)
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None  # (a save outside the event loop: the key made at the first start)
        taken.append((data.get("activity_position"), task.get_coro().__qualname__ if task is not None else ""))  # type: ignore[union-attr]
        return data

    monkeypatch.setattr(Store, "snapshot", watched)
    with wall(tmp_path):
        pass
    stop = written(tmp_path / "audit.log")[-1]
    assert stop.get("why") == "stop"
    by_the_stop = [whose for position, whose in taken if position and position["n"] == stop["chain"]["n"] and not whose.endswith("save_position")]
    assert by_the_stop, taken
