"""Checking the activity log's chain: on the page (POST /api/v1/audit/check, an admin's) and away from the wall
(python -m qkvm.checklog, from a download). Each way of editing the log that the chain catches (test_activity_chain*.py)
is said by both, with its line; what they read is what the wall wrote, nothing else.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import chain, checklog, kvm, server, update, vault
from qkvm.store import Store
from tests.test_alert_destinations import added, services  # noqa: F401  (a fixture, by name)
from tests.test_users import account, browser
from tests.test_wall import PASSWORD, wall

KEY_FILE_START = "QKVM-ACTIVITY-KEY-1:"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def busy(admin: Any, count: int = 12) -> None:
    """Things an admin does that the log writes down: accounts added."""
    for number in range(count):
        account(admin, f"user{number}", "viewer")


def edit_first(path: Path, event: str, old: str, new: str) -> int:
    """The first line of an event changed by hand, in the file: its number in the chain."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    at = next(index for index, line in enumerate(lines) if f'"event": "{event}"' in line)
    assert old in lines[at]
    lines[at] = lines[at].replace(old, new)
    path.write_text("".join(lines), encoding="utf-8")
    return int(json.loads(lines[at])["chain"]["n"])


# --- on the page ------------------------------------------------------------------------------------------------


def test_the_page_checks_the_log_and_says_where_it_was_edited(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        busy(admin)
        answer = admin.post("/api/v1/audit/check")
        assert answer.status_code == 200, answer.text
        said = answer.json()
        assert said["running"] is False and said["by"] == "admin" and said["said"].startswith("Intact: lines 1 to ")
        result = said["result"]
        assert result["intact"] is True and result["keyed"] is True and result["first"] == 1 and result["problems"] == []
        # The check is in the log itself: who made it, what it found, and the head it found.
        checked = admin.get("/api/v1/audit", params={"limit": 1}).json()["entries"][0]
        assert (checked["event"], checked["user"], checked["intact"], checked["last"], checked["head"]) == ("log_checked", "admin", True, result["last"], result["head"])
        assert admin.get("/api/v1/audit/check").json() == said  # (kept for the page until the next)
        # A line edited by hand while the wall runs: where, and how.
        admin.core.audit.flush()  # type: ignore[attr-defined]
        line = edit_first(tmp_path / "audit.log", "user_added", '"ip": "127.0.0.1"', '"ip": "192.0.2.99"')
        said = admin.post("/api/v1/audit/check").json()
        assert said["result"]["intact"] is False and said["said"].startswith(f"Broken at line {line}: line {line} is not as the wall wrote it")
        assert said["result"]["problems"][0] == {"line": line, "what": "unsigned", "said": said["result"]["problems"][0]["said"]}
        checked = admin.get("/api/v1/audit", params={"limit": 1}).json()["entries"][0]
        assert (checked["event"], checked["intact"], checked["broken_at"], checked["what"]) == ("log_checked", False, line, "unsigned")
        # The end of the log cut off while it runs: the wall's own last head says so.
        admin.core.audit.flush()  # type: ignore[attr-defined]
        whole = (tmp_path / "audit.log").read_bytes()
        (tmp_path / "audit.log").write_bytes(whole[: whole.rstrip(b"\n").rfind(b"\n") + 1])
        said = admin.post("/api/v1/audit/check").json()
        assert any(problem["what"] == "cut" for problem in said["result"]["problems"]), said


def test_only_an_admin_checks_the_log(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        assert olga.post("/api/v1/audit/check").status_code == 403 and olga.get("/api/v1/audit/check").status_code == 403


def test_a_long_check_is_answered_with_how_far_it_got_and_asked_after(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    taken = chain.Walk.take

    def slowly(walk: chain.Walk, entry: Any) -> None:
        time.sleep(0.02)
        taken(walk, entry)

    with wall(tmp_path) as admin:
        busy(admin, 20)
        monkeypatch.setattr(server, "CHECK_WAIT", 0.05)
        monkeypatch.setattr(chain.Walk, "take", slowly)
        first = admin.post("/api/v1/audit/check")
        assert first.status_code == 202 and first.json()["running"] is True and first.json()["result"] is None
        # Asked again meanwhile: the same check, not a second one beside it.
        again = admin.post("/api/v1/audit/check")
        assert again.status_code == 202 and again.json()["began"] == first.json()["began"]
        deadline = time.monotonic() + 30
        while (state := admin.get("/api/v1/audit/check").json())["running"]:
            assert time.monotonic() < deadline, "the check did not end"
            time.sleep(0.1)
        assert state["result"]["intact"] is True and state["result"]["entries"] > 20
        events = [entry["event"] for entry in admin.get("/api/v1/audit", params={"limit": 100}).json()["entries"]]
        assert events.count("log_checked") == 1


# --- away from the wall: a download, and python -m qkvm.checklog --------------------------------------------------


def download(admin: Any, folder: Path, form: str = "jsonl") -> Path:
    reply = admin.get("/api/v1/audit/export", params={"format": form})
    assert reply.status_code == 200
    path = folder / f"activity.{form}"
    path.write_bytes(reply.content)
    return path


def test_a_download_carries_the_chain_and_checks_away_from_the_wall(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data, away = tmp_path / "data", tmp_path / "away"
    away.mkdir()
    sent: list[str] = []
    with wall(data) as admin:
        admin.core.audit.forward = sent.append  # type: ignore[attr-defined]  # (as syslog would: every line, kept elsewhere)
        busy(admin)
        exported = download(admin, away)
        table = download(admin, away, "csv")
    lines = [json.loads(line) for line in exported.read_text(encoding="utf-8").splitlines()]
    assert all(set(entry["chain"]) == {"n", "prev", "mac"} for entry in lines)  # (newest first, as the page downloads it)
    assert '"chain"' in table.read_text(encoding="utf-8").splitlines()[1]  # (in the table too, with the rest of an entry)
    # Without the key: how the lines hang together.
    assert checklog.main([str(exported)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Intact: lines 1 to ") and "no key was given" in out
    assert "Intact cannot show an older copy of the whole data folder put back" in out  # (what it cannot prove, said with it)
    # With the key, read from the wall's sealed settings (its vault key beside the data folder, as it comes). The wall wrote on
    # after the download (its stop seal, which the settings keep): held to that as the whole log, the download falls short of
    # it; checked as what it is, a part of the log (--part), it is intact as far as it goes and not said to be complete.
    assert checklog.main([str(exported), "--data-dir", str(data)]) == 1
    assert "the wall's settings say its chain had come to line" in capsys.readouterr().out
    assert checklog.main([str(exported), "--data-dir", str(data), "--part"]) == 4
    said = capsys.readouterr().out
    assert said.startswith("Intact as far as it goes, and not proved complete: lines 1 to ") and "with their signatures" in said, said
    # With the key saved for a check elsewhere: a file of its own, made once, private.
    key_file = away / "activity.key"
    assert checklog.main(["--save-key", str(key_file), "--data-dir", str(data)]) == 0
    assert key_file.read_text(encoding="ascii").startswith(KEY_FILE_START)
    assert key_file.read_text(encoding="ascii").strip().endswith(Store(data / "qkvm.json").activity_key)
    if sys.platform != "win32":
        assert key_file.stat().st_mode & 0o077 == 0
    assert checklog.main(["--save-key", str(key_file), "--data-dir", str(data)]) == 2  # (never over one that is there)
    capsys.readouterr()
    assert checklog.main([str(exported), "--key-file", str(key_file)]) == 0
    # With the heads syslog kept: each holds. (Those of lines written after the download, its own entry among them, are said
    # of it as a part; of the whole log they would be lines cut off its end.)
    heads = away / "syslog.txt"
    heads.write_text("".join(f"<109>1 2026-11-16T10:00:00.000Z wall qkvm - x - {line}" for line in sent), encoding="utf-8")
    capsys.readouterr()
    assert checklog.main([str(exported), "--key-file", str(key_file), "--heads", str(heads), "--part"]) == 4
    said = capsys.readouterr().out
    within = sum(json.loads(line)["chain"]["n"] <= lines[0]["chain"]["n"] for line in sent)
    assert within >= 12 and f"{within} fall within the log, {within} of them hold" in said and "written after it was downloaded" in said
    assert checklog.main([str(exported), "--key-file", str(key_file), "--heads", str(heads)]) == 1
    capsys.readouterr()
    # The same lines as the log's own files, the oldest first.
    assert checklog.main([str(data / "audit.log"), "--key-file", str(key_file)]) == 0
    capsys.readouterr()

    # Edited: a field of one line.
    edited = away / "edited.jsonl"
    edited.write_text(exported.read_text(encoding="utf-8").replace('"ip": "127.0.0.1"', '"ip": "192.0.2.99"', 1), encoding="utf-8")
    assert checklog.main([str(edited), "--key-file", str(key_file)]) == 1
    assert "Broken at line" in capsys.readouterr().out
    # Written anew with the key, from the first line syslog kept on (its address changed): it checks with the key, and not
    # with the heads.
    entries = list(reversed(lines))
    # (From line 2 at the earliest: on a loaded computer syslog was attached before the wall wrote its first line, and kept
    # line 1 too, which has no line before it to go on from.)
    first = max(json.loads(sent[0])["chain"]["n"], 2)
    at = next(index for index, entry in enumerate(entries) if entry["chain"]["n"] == first)
    before = entries[at - 1]
    number, head = first - 1, chain.link(bytes.fromhex(before["chain"]["prev"]), first - 1, chain.digest(before))
    key = bytes.fromhex(Store(data / "qkvm.json").activity_key)
    anew = entries[:at]
    for entry in entries[at:]:
        entry = {name: value for name, value in entry.items() if name != "chain"}
        entry["ip"] = "192.0.2.99"
        line = json.dumps(entry) + "\n"
        number += 1
        stamped, head = chain.stamp(line, json.loads(line), number, head, key)
        anew.append(json.loads(stamped))
    rewritten = away / "rewritten.jsonl"
    rewritten.write_text("".join(json.dumps(entry) + "\n" for entry in reversed(anew)), encoding="utf-8")
    assert checklog.main([str(rewritten), "--key-file", str(key_file)]) == 0
    capsys.readouterr()
    assert checklog.main([str(rewritten), "--key-file", str(key_file), "--heads", str(heads)]) == 1
    assert f"Broken at line {first}: line {first} is not as it was when its head was kept outside the wall" in capsys.readouterr().out
    # Lines taken out of the middle of a download.
    taken = away / "taken.jsonl"
    taken.write_text("".join(line for index, line in enumerate(exported.read_text(encoding="utf-8").splitlines(keepends=True)) if index != 4), encoding="utf-8")
    assert checklog.main([str(taken)]) == 1 and "is missing" in capsys.readouterr().out


def test_what_cannot_be_checked_says_so_and_ends_with_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data, away = tmp_path / "data", tmp_path / "away"
    away.mkdir()
    with wall(data) as admin:
        busy(admin, 3)
        exported = download(admin, away)
        table = download(admin, away, "csv")
    assert checklog.main([str(table)]) == 2 and "CSV" in capsys.readouterr().err
    older = away / "older.jsonl"
    older.write_text(json.dumps({"time": 1700000000.0, "event": "login", "ip": ""}) + "\n", encoding="utf-8")
    assert checklog.main([str(older)]) == 2 and "before 0.4.0" in capsys.readouterr().err
    assert checklog.main([str(away / "nowhere.jsonl")]) == 2
    wrong = away / "wrong.key"
    wrong.write_text(f"{KEY_FILE_START}{'ab' * 32}\n", encoding="ascii")
    assert checklog.main([str(exported), "--key-file", str(wrong)]) == 2 and "not the one this log was signed with" in capsys.readouterr().err
    nonsense = away / "nonsense.key"
    nonsense.write_text("not a key", encoding="ascii")
    assert checklog.main([str(exported), "--key-file", str(nonsense)]) == 2
    assert checklog.main([str(exported), "--data-dir", str(away)]) == 2 and "no settings of a wall" in capsys.readouterr().err
    # As JSON, for a script.
    assert checklog.main([str(exported), "--json"]) == 0
    said = json.loads(capsys.readouterr().out)
    assert said["checked"] is True and said["intact"] is True and said["head"] and said["said"].startswith("Intact")


def test_the_check_runs_as_python_minus_m(tmp_path: Path) -> None:
    with wall(tmp_path / "data") as admin:
        exported = download(admin, tmp_path)
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    said = subprocess.run([sys.executable, "-m", "qkvm.checklog", str(exported)], capture_output=True, text=True, timeout=120, env=env)
    assert said.returncode == 0 and said.stdout.startswith("Intact"), said.stdout + said.stderr


# --- the daily seal to an alert destination ------------------------------------------------------------------------


def test_a_destination_that_asked_for_it_is_told_the_logs_head_daily_and_quietly(tmp_path: Path, services: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: F811
    from qkvm import alerts
    from tests.fake_alerts import HOOKS, NTFY

    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(server, "LOG_SEAL_FIRST", 0.3)
    monkeypatch.setattr(server, "LOG_SEAL_LOOK", 0.1)
    monkeypatch.setattr(server, "LOG_SEAL_EVERY", 3600.0)
    with wall(tmp_path) as admin:
        hook = added(admin, kind="webhook", url=f"https://{HOOKS}/seal", log_seal=True)["destination"]
        quiet = added(admin, kind="ntfy", url=f"https://{NTFY}/topic", log_seal=True)["destination"]
        added(admin, kind="ntfy", url=f"https://{NTFY}/other")  # (not asked for it: told nothing)
        assert (hook["log_seal"], quiet["log_seal"]) == (True, True)
        deadline = time.monotonic() + 30
        while not (services.at(HOOKS) and services.at(NTFY)):
            assert time.monotonic() < deadline, "no seal arrived"
            time.sleep(0.05)
        time.sleep(0.5)  # (once a day: nothing more meanwhile)
        [arrived] = services.at(HOOKS)
        said = json.loads(arrived.body)
        assert (said["event"], said["what"], said["severity"]) == ("log_seal", "log_seal", "info")
        # Quiet: no trouble, at ntfy's default priority; and only where it was asked for.
        [told] = services.at(NTFY)
        assert told.path.endswith("/topic") and told.headers["Priority"] == "default"
        # It is a seal of the log, written for it: the head is its own. (Each destination's: one added after the first round,
        # on a loaded computer, is sealed at the next look, with a seal of its own; each is told one, once.)
        admin.core.audit.flush()  # type: ignore[attr-defined]
        seals = {entry["chain"]["n"]: entry for entry in (json.loads(line) for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()) if entry.get("why") == "daily"}
        for title in (said["title"], told.headers["Title"]):
            [(number, head)] = chain.anchors_in(title).items()
            seal = seals[number]
            assert chain.link(bytes.fromhex(seal["chain"]["prev"]), number, chain.digest(seal)) == head
        exported = download(admin, tmp_path)
    # No secret in what went out: the head and its number, and the words around them.
    assert set(said) >= {"title", "message"} and Store(tmp_path / "qkvm.json").activity_key not in arrived.body.decode()
    # Kept there, it holds the log to that line: the message itself is the file of heads.
    heads = tmp_path / "seal.txt"
    heads.write_text(said["title"] + "\n", encoding="utf-8")
    assert checklog.main([str(exported), "--heads", str(heads)]) == 0
    assert "1 fall within the log, 1 of them hold" in capsys.readouterr().out


def test_a_log_edited_while_the_wall_was_stopped_is_broken_on_the_page(tmp_path: Path) -> None:
    # The review of wave 2, H1, as the page sees it: the chain taken away from the end of the log and a line taken out
    # while the wall was stopped, without the vault key. The next start holds the files to where its settings say the chain
    # had come to, and says what it found in a seal the check counts as a problem.
    with wall(tmp_path) as admin:
        busy(admin, 5)
    path = tmp_path / "audit.log"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    kept, tail = lines[:-4], [json.loads(line) for line in lines[-4:]]
    path.write_text("".join(kept + [json.dumps({name: value for name, value in entry.items() if name != "chain"}) + "\n" for entry in tail[1:]]), encoding="utf-8")
    with wall(tmp_path, sign_in=False) as admin:
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        said = admin.post("/api/v1/audit/check").json()
        assert said["result"]["intact"] is False and said["said"].startswith("Broken at line"), said
        assert [problem["what"] for problem in said["result"]["problems"]] == ["found"]
        assert "the wall had written it up to line" in said["result"]["problems"][0]["said"]


def test_the_offline_check_with_the_data_folder_holds_the_log_to_the_place_its_settings_keep(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The re-review of wave 2, N2: with --data-dir the offline check opened the sealed settings for the key only. A log cut
    # back to an earlier stop seal while the wall was stopped checked intact there, until the wall started again.
    with wall(tmp_path):
        pass
    path = tmp_path / "audit.log"
    first_run = len(path.read_text(encoding="utf-8").splitlines(keepends=True))
    with wall(tmp_path) as admin:
        admin.post("/api/v1/logout", json={})
    assert checklog.main([str(path), "--data-dir", str(tmp_path)]) == 0
    capsys.readouterr()
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text("".join(lines[:first_run]), encoding="utf-8")  # (cut back to the first run's stop seal, the wall stopped)
    assert checklog.main([str(path), "--data-dir", str(tmp_path)]) == 1
    said = capsys.readouterr().out
    assert said.startswith(f"Broken at line {first_run + 1}: the log ends at line {first_run}, and the wall's settings say its chain had come to line"), said
    # The same line changed in its place: written anew with the key from there on, say.
    kept = Store(tmp_path / "qkvm.json").activity_position
    assert kept is not None
    path.write_text("".join(lines), encoding="utf-8")
    walk = chain.Walk(bytes.fromhex(Store(tmp_path / "qkvm.json").activity_key), kept=(kept["n"], bytes(32)))
    for entry in (json.loads(line) for line in lines):
        walk.take(entry)
    assert [problem.what for problem in walk.end().problems] == ["found"]


def two_runs(data: Path) -> tuple[list[bytes], int]:
    """A wall run twice, the second time with a press of a machine's power button in its log: the lines of the first run as
    the file holds them, and the line the sealed settings keep at the end (the second run's stop seal)."""
    with wall(data):
        pass
    first = (data / "audit.log").read_bytes().splitlines(keepends=True)
    with wall(data) as admin:
        admin.core.audit.write("atx_power", "127.0.0.1", user="operator", device="rack1-node02")  # type: ignore[attr-defined]
    kept = Store(data / "qkvm.json").activity_position
    assert kept is not None and kept["n"] > len(first)
    return first, int(kept["n"])


ORDERS = ("reversed", "newest first, as a download writes them", "shuffled, the last first and the first last")


def other_orders(lines: list[bytes]) -> dict[str, list[bytes]]:
    """The same signed lines in other orders, as somebody without the key can put them: no line written anew."""
    entries = [json.loads(line) for line in lines]
    middle = lines[1:-1]
    made = {
        "reversed": list(reversed(lines)),
        "newest first, as a download writes them": [(json.dumps(entry, ensure_ascii=False) + "\n").encode() for entry in reversed(entries)],
        "shuffled, the last first and the first last": [lines[-1], *middle[1::2], *middle[::2], lines[0]],
    }
    assert tuple(made) == ORDERS
    return made


def test_the_order_of_a_cut_back_log_never_lets_the_check_against_its_data_folder_pass_the_end_it_keeps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The outside review of 0.4.0, M3: the offline check took the order of the lines (bytes anybody who edits the data folder
    # writes) as whether they were a download, and a download's end short of the place the sealed settings keep was a note.
    # A log cut back to an earlier stopped run and turned round checked intact with --data-dir.
    first, kept = two_runs(tmp_path)
    path, settings = tmp_path / "audit.log", (tmp_path / "qkvm.json").read_bytes()
    path.write_bytes(b"".join(first))
    assert checklog.main([str(path), "--data-dir", str(tmp_path)]) == 1  # (as it was written: the control)
    capsys.readouterr()
    for order, lines in other_orders(first).items():
        path.write_bytes(b"".join(lines))
        assert checklog.main([str(path), "--data-dir", str(tmp_path), "--json"]) == 1, order
        said = json.loads(capsys.readouterr().out)
        assert said["intact"] is False and said["said"].startswith("Broken"), (order, said)
        cut = [problem for problem in said["problems"] if problem["what"] == "cut"]
        assert cut and f"the wall's settings say its chain had come to line {kept}" in cut[0]["said"], (order, said)
        assert said["later"] is None and said["part"] is False, order
        assert (tmp_path / "qkvm.json").read_bytes() == settings  # (nothing of the key was needed to do it)
    # The same as words, for a person: broken, and where a download is checked.
    path.write_bytes(b"".join(reversed(first)))
    assert checklog.main([str(path), "--data-dir", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"Broken at line {len(first) + 1}: the log ends at line {len(first)}, and the wall's settings say its chain had come to line {kept}"), out
    assert "--part" in out


def test_a_part_of_the_log_is_checked_as_one_only_when_asked_and_is_never_said_to_be_complete_where_more_is_known(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # (M3, and what it leaves open on purpose.) A download ends where it was made, and the wall writes on: checked against
    # the data folder, or against heads kept outside, it is a part of the log. That is the person's word (--part), never
    # the order of its lines; and the verdict then says how far it goes, and that it does not prove the log complete.
    first, kept = two_runs(tmp_path)
    path = tmp_path / "audit.log"
    whole = path.read_bytes().splitlines(keepends=True)
    part = tmp_path / "part.jsonl"
    for order, lines in {"as written": first, **other_orders(first)}.items():
        if order.startswith("shuffled"):
            continue  # (out of its order: broken, part or not)
        part.write_bytes(b"".join(lines))
        assert checklog.main([str(part), "--data-dir", str(tmp_path), "--part", "--json"]) == 4, order
        said = json.loads(capsys.readouterr().out)
        assert (said["intact"], said["part"], said["later"], said["last"], said["problems"]) == (True, True, kept, len(first), []), (order, said)
        assert said["said"].startswith(f"Intact as far as it goes, and not proved complete: lines 1 to {len(first)}"), said
        assert f"the log is known to go on to line {kept}, which this part does not hold" in said["said"], said
    assert checklog.main([str(part), "--data-dir", str(tmp_path), "--part"]) == 4
    assert "not proved complete" in capsys.readouterr().out
    # Asked of the whole log, that has nothing more to say: intact, and 0.
    part.write_bytes(b"".join(reversed(whole)))
    assert checklog.main([str(part), "--data-dir", str(tmp_path), "--part"]) == 0
    assert capsys.readouterr().out.startswith(f"Intact: lines 1 to {kept}, with their signatures")
    # Out of its order, a part is broken all the same.
    part.write_bytes(b"".join(other_orders(first)["shuffled, the last first and the first last"]))
    assert checklog.main([str(part), "--data-dir", str(tmp_path), "--part"]) == 1
    capsys.readouterr()
    # Heads kept outside the wall that name lines after its end are the same: a problem of the whole log, said of a part.
    heads = tmp_path / "heads.txt"
    heads.write_text("".join(line.decode() for line in whole), encoding="utf-8")  # (as a collector keeps every line)
    key = tmp_path / "activity.key"
    assert checklog.main(["--save-key", str(key), "--data-dir", str(tmp_path)]) == 0
    capsys.readouterr()
    part.write_bytes(b"".join(first))
    assert checklog.main([str(part), "--key-file", str(key), "--heads", str(heads), "--json"]) == 1
    said = json.loads(capsys.readouterr().out)
    assert [problem["what"] for problem in said["problems"]] == ["cut"] and f"up to line {kept}" in said["problems"][0]["said"], said
    assert checklog.main([str(part), "--key-file", str(key), "--heads", str(heads), "--part", "--json"]) == 4
    said = json.loads(capsys.readouterr().out)
    assert (said["intact"], said["later"]) == (True, kept), said


def test_a_cut_back_log_in_another_order_is_broken_at_the_next_start_and_on_the_page(tmp_path: Path) -> None:
    # (M3, the checks on the wall.) The start holds the files to the place its settings keep, and the page's check to the head
    # the wall wrote last and to that place: neither takes the order of the lines for anything. (The page's check held the
    # log to the head alone: after a start over such a log, its words said lines out of their order, and nothing of where
    # the wall had come to, which only the start's own seal said.)
    for number, order in enumerate(ORDERS):
        data = tmp_path / f"order{number}"
        first, kept = two_runs(data)
        (data / "audit.log").write_bytes(b"".join(other_orders(first)[order]))
        with wall(data) as admin:
            said = admin.post("/api/v1/audit/check").json()
            assert said["result"]["intact"] is False, (order, said)
            cut = [problem for problem in said["result"]["problems"] if problem["what"] == "cut"]
            assert cut and f"the wall's settings say its chain had come to line {kept}" in cut[0]["said"], (order, said)
            admin.core.audit.flush()  # type: ignore[attr-defined]
        seals = [entry for entry in map(json.loads, (data / "audit.log").read_text(encoding="utf-8").splitlines()) if entry.get("why") == "broken"]
        assert seals and f"the wall had written it up to line {kept}" in seals[0]["said"], (order, seals)
    # While the wall runs: cut back and turned round under it, the page's check says so.
    data = tmp_path / "running"
    with wall(data) as admin:
        busy(admin, 4)
        admin.core.audit.flush()  # type: ignore[attr-defined]
        lines = (data / "audit.log").read_bytes().splitlines(keepends=True)
        for order, reordered in other_orders(lines[: len(lines) // 2]).items():
            # (Written when the writer is done with the check's own line before: a write of its that the rewrite gets in the
            # way of on Windows makes it look at the files again, and say what it found there in a seal of its own, which a
            # run showed once in place of the cut.)
            admin.core.audit.flush()  # type: ignore[attr-defined]
            (data / "audit.log").write_bytes(b"".join(reordered))
            said = admin.post("/api/v1/audit/check").json()
            whats = [problem["what"] for problem in said["result"]["problems"]]
            found_by_the_writer = b'"why": "broken"' in (data / "audit.log").read_bytes()
            assert said["result"]["intact"] is False and ("cut" in whats or found_by_the_writer), (order, said)


def test_every_place_that_says_what_intact_is_says_what_it_cannot_show() -> None:
    # The outside review of 0.4.0 put an older copy of the whole data folder back (the sealed settings and the log of one
    # moment, together) and both checks said intact, as they must: nothing in the folder says it is old. That was said once,
    # among what is not caught; it is said now wherever intact is explained, as the residual limit it is.
    app = Path(__file__).resolve().parents[1]
    guide = (app / "GUIDE.md").read_text(encoding="utf-8")
    page = (app / "qkvm" / "static" / "app.js").read_text(encoding="utf-8")

    def paragraph(starting: str) -> str:
        at = guide.index(starting)
        return " ".join(guide[at : guide.index("\n- **", at + 1)].split())

    for start in ("- **Check the log**", "- **Away from the wall:**"):
        assert "cannot show an older copy of the whole data folder put back" in paragraph(start), start
    assert "Intact cannot show an older copy of the whole data folder put back" in checklog.WHAT_INTACT_CANNOT_SHOW
    assert "Intact cannot show an older copy of the whole data folder put back" in (checklog.__doc__ or "")
    assert "It cannot show an older copy of the whole data folder put back" in page
    # ...and a download is a part of the log by the person's word: the guide says how it is checked.
    assert "--part" in paragraph("- **Away from the wall:**") and "4 (`--part`)" in paragraph("- **Away from the wall:**")


def test_a_part_known_to_go_on_says_so_first_where_lines_in_it_are_not_proved_either(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The fresh review of the fixes, N6: a part (--part) that held lines taken in without proof, and was known to go on,
    # ended with 3 (lines not proved): that it is not the whole was said in the words and the JSON only. One order of the
    # exit statuses: 1 broken; 4 a part known to go on; 3 lines not proved; 0 intact. The words and the JSON say both.
    with wall(tmp_path):
        pass
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    with wall(tmp_path):
        pass
    lines = (tmp_path / "audit.log").read_bytes().splitlines(keepends=True)
    taken = next(index for index, line in enumerate(lines) if b'"why": "unchained"' in line)
    part = tmp_path / "part.jsonl"
    part.write_bytes(b"".join(lines[: taken + 2]))  # (the seal that took it in, and the line after it: the wall went on)
    assert checklog.main([str(part), "--data-dir", str(tmp_path), "--part", "--json"]) == 4
    said = json.loads(capsys.readouterr().out)
    assert (said["intact"], said["unproved"], said["part"]) == (True, 1, True) and said["later"] is not None, said
    assert said["said"].startswith("Intact where it is chained, and not all of it proved") and "the log is known to go on to line" in said["said"]
    # The whole log, as before: 3.
    assert checklog.main([str(tmp_path / "audit.log"), "--data-dir", str(tmp_path), "--part"]) == 3
    capsys.readouterr()


def test_lines_not_proved_are_never_said_as_plainly_intact(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The re-review of wave 2, N3: lines taken in after a stop (an earlier version run in between, or put in while the wall
    # was stopped) were said as not proved by the page's box only. The answer, the check's own line in the log and the
    # offline check's exit status said intact.
    with wall(tmp_path):
        pass
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    with wall(tmp_path) as admin:
        result = admin.post("/api/v1/audit/check").json()["result"]
        assert (result["intact"], result["unproved"]) == (True, 1), result
        checked = admin.get("/api/v1/audit", params={"limit": 1}).json()["entries"][0]
        assert (checked["event"], checked["intact"], checked["unproved"]) == ("log_checked", True, 1)
    # Away from the wall: an exit status of its own, 3, and the same in JSON.
    assert checklog.main([str(tmp_path / "audit.log"), "--data-dir", str(tmp_path)]) == 3
    assert capsys.readouterr().out.startswith("Intact where it is chained, and not all of it proved: 1 line written without the chain")
    assert checklog.main([str(tmp_path / "audit.log"), "--data-dir", str(tmp_path), "--json"]) == 3
    said = json.loads(capsys.readouterr().out)
    assert (said["intact"], said["unproved"]) == (True, 1)
