"""Brackets within brackets, thousands deep, wherever the program reads JSON.

Python's reader gives up on that with an error of a kind of its own (RecursionError, which is no ValueError),
on the Pythons before 3.13 at about a thousand deep; the newest reads it without a word. So a reader that took
"this is not JSON" and not that one was a fault only where nobody develops: found by the suite's run on 3.11,
in what a JetKVM says (see `test_a_jetkvm_that_closes_what_it_is_asked_over.py`). Here, each of the others.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from qkvm import __main__ as starter
from qkvm import cli, discover, forward, kvm, update, vault
from qkvm.core import Core
from qkvm.store import AuditLog, StoreError
from qkvm.update import Updater
from tests.fake_github import make_wheel
from tests.fake_kvm import FakeKvm
from tests.test_wall import add, wall

DEEP = "[" * 100_000 + "0" + "]" * 100_000
HALF = "[" * 100_000  # (never closed: the same to a reader that gives up on the way in)
BOTH = pytest.mark.parametrize("said", [DEEP, HALF], ids=["closed", "never closed"])
# What is read, and what gives up on it afterwards, are different depths on every Python (measured by a
# reviewer, lists / records: 3.14 on Windows reads 16,920 / 14,317, compares 31,021 / 13,295, writes out
# as JSON 15,510 / 9,306, copies 496; 3.11 reads, compares and writes about 990, and copies 496; the
# framework's writer stops at 255). So what is beside a reader is tried at depths on both sides of each.
DEPTHS = (300, 600, 1_500, 9_500, 12_000, 14_000, 16_000)


def lists(depth: int) -> str:
    return "[" * depth + "0" + "]" * depth


def records(depth: int) -> str:
    return '{"a":' * depth + "0" + "}" * depth


NESTED = [pytest.param(make(depth), id=f"{name} {depth}") for depth in DEPTHS for name, make in (("lists", lists), ("records", records))]


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@BOTH
def test_the_note_of_which_version_runs(tmp_path: Path, said: str) -> None:
    # The starter reads it before anything else: an error here is a wall that does not start.
    (tmp_path / "updates").mkdir()
    (tmp_path / "updates" / "current.json").write_text(said, encoding="utf-8")
    assert starter.pointer(tmp_path) is None
    assert starter.active_update(tmp_path) is None
    assert starter.roll_back(tmp_path) is False
    # Whether the reader gives up on it or reads it is the Python's own affair: on Linux the newest reads the
    # closed one without a word, as a list, and for that one case "gone back" was said and the file deleted.
    # What is read and is no record is no note of an update either, on any of them: the same with a short one.
    for no_record in ("[1, 2]", "7", '"a text"', "{}", '{"a": [1]}'):
        (tmp_path / "updates" / "current.json").write_text(no_record, encoding="utf-8")
        assert starter.pointer(tmp_path) is None and starter.roll_back(tmp_path) is False, no_record
        assert (tmp_path / "updates" / "current.json").read_text(encoding="utf-8") == no_record  # and it is left as it lies


@BOTH
def test_the_same_note_when_an_update_is_installed(tmp_path: Path, said: str) -> None:
    (tmp_path / "updates").mkdir()
    (tmp_path / "updates" / "current.json").write_text(said, encoding="utf-8")
    Updater(tmp_path, "", current="1.0.0")._activate("9.9.9", make_wheel("9.9.9"))
    assert json.loads((tmp_path / "updates" / "current.json").read_text(encoding="utf-8")) == {"version": "9.9.9", "previous": None, "previous_proven": False}


@BOTH
def test_the_list_of_folders_walls_were_started_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, said: str) -> None:
    monkeypatch.setattr(cli, "home_folder", lambda: tmp_path)
    (tmp_path / cli.KNOWN).write_text(said, encoding="utf-8")
    assert cli.known_folders() == []


@BOTH
def test_a_line_of_the_activity_log(tmp_path: Path, said: str) -> None:
    activity = AuditLog(tmp_path / "activity.log")
    activity.write("before", "127.0.0.1")
    activity.flush()
    with (tmp_path / "activity.log").open("a", encoding="utf-8") as file:
        file.write(said + "\n")
    activity.write("after", "127.0.0.1")
    assert [entry["event"] for entry in activity.tail(10)] == ["after", "before"]


@pytest.mark.parametrize("said", [DEEP, HALF, "[1]", "null", "7", '"text"', ""], ids=["closed", "never closed", "a list", "null", "a number", "a text", "nothing"])
def test_a_line_sent_on_to_a_collector(said: str) -> None:
    # (What is sent on is what the program wrote itself, a record each time. Whatever else it is given is sent
    # as it stands, with the time of now, and is no error in the thread that sends: that would end the sending.)
    message = forward.Syslog("127.0.0.1:5514").message(said)
    assert message.startswith(b"<") and b" qkvm - - - " in message


@pytest.mark.parametrize("said", [DEEP, HALF, '{"Peer": ' + DEEP + "}"], ids=["closed", "never closed", "inside"])
def test_what_the_tailscale_command_prints(monkeypatch: pytest.MonkeyPatch, said: str) -> None:
    def ran(*asked: Any, **how: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(asked, 0, stdout=said, stderr="")

    monkeypatch.setattr(discover, "tailscale_command", lambda: "tailscale")
    monkeypatch.setattr(discover.subprocess, "run", ran)
    assert discover._tailscale_peers() == []


@pytest.mark.parametrize("depth", [300, 1_500, 12_000, 30_000])
def test_what_a_browser_sends_before_anybody_is_signed_in(tmp_path: Path, depth: int) -> None:
    # Read by the framework, which answers "this is not what is asked for here": held, since it is the one
    # reader of JSON anybody on the network can write to without a password. (As first written, this sent
    # 200 kB where a request may have 64: every one was refused for its size, and nothing ever read them.)
    with wall(tmp_path) as admin:
        admin.post("/api/v1/logout", json={})
        for said in (lists(depth), "[" * depth, '{"password": ' + lists(depth) + "}", '{"password": ' + records(min(depth, 9_000)) + "}"):
            assert len(said) < 64 * 1024
            for path in ("/api/v1/login", "/api/v1/recover", "/api/v1/setup"):
                reply = admin.post(path, content=said.encode(), headers={"content-type": "application/json"})
                assert reply.status_code in (400, 403, 409, 422), (path, depth, reply.status_code, reply.text[:200])
        assert admin.get("/healthz").status_code == 200


# --- beside the readers: what is done with what was read --------------------------------------------------------


@pytest.mark.parametrize("beside", NESTED)
def test_the_note_of_which_version_runs_with_something_nested_beside_a_proper_version(tmp_path: Path, beside: str) -> None:
    # A proper version, and beside it something nested deep: read (where this Python reads that deep), the
    # update is on trial, the wall starts, and half a minute later the starter compares the note with
    # itself and writes it again. Both gave up where the reader had not: an error in the starter, and the
    # wall stopped with it. Only what is a plain value is handed on by whoever reads the note.
    (tmp_path / "updates").mkdir()
    file = tmp_path / "updates" / "current.json"
    file.write_text('{"version": "9.9.9", "previous": null, "more": ' + beside + ', "previous_proven": false}', encoding="utf-8")
    said = starter.pointer(tmp_path)
    assert said in (None, {"version": "9.9.9", "previous": None, "previous_proven": False})  # not read at all, or read without it
    starter.proven(tmp_path, "9.9.9")
    if said is not None:
        assert json.loads(file.read_text(encoding="utf-8")) == {"version": "9.9.9", "previous": None, "previous_proven": False, "proven": True}
    assert starter.gone_back(tmp_path) is (said is not None)
    assert not file.exists() or said is None  # gone back to the files the program came with


@pytest.mark.parametrize("beside", NESTED)
def test_the_same_note_where_the_version_before_is_no_version(tmp_path: Path, beside: str) -> None:
    (tmp_path / "updates").mkdir()
    file = tmp_path / "updates" / "current.json"
    file.write_text('{"version": "9.9.9", "previous": ' + beside + "}", encoding="utf-8")
    read = starter.pointer(tmp_path) is not None
    assert starter.gone_back(tmp_path) is read  # (never an error: where it was read, there was nothing to go back to but the shipped files)
    assert not file.exists() or not read
    # ...and installing over a note whose own version is such a thing writes a version's name or nothing.
    file.write_text('{"version": ' + beside + ', "proven": true}', encoding="utf-8")
    Updater(tmp_path, "", current="1.0.0")._activate("9.9.8", make_wheel("9.9.8"))
    assert json.loads(file.read_text(encoding="utf-8")) == {"version": "9.9.8", "previous": None, "previous_proven": False}


def test_a_folder_in_the_list_of_walls_whose_name_no_folder_can_have(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A zero byte in a name: asking the system about such a folder is an error of another kind than "not there".)
    monkeypatch.setattr(cli, "home_folder", lambda: tmp_path)
    (tmp_path / cli.KNOWN).write_text(json.dumps(["a" + chr(0) + "b", str(tmp_path / "nowhere")]), encoding="utf-8")
    assert len(cli.known_folders()) == 2
    assert cli.running_elsewhere() == []


ODD_LINES = {
    "an event that is a list": '{"time": 1700000000, "event": ["x"], "ip": ""}',
    "an event that is a record": '{"time": 1700000000, "event": {"x": 1}, "ip": ""}',
    "no event": '{"time": 1700000000, "ip": ""}',
    "a time that is none": '{"time": 1e400, "event": "login", "ip": "", "user": "(no moment)"}',
    "a time that is a text": '{"time": "now", "event": "login", "ip": "", "user": "(no moment)"}',
    "a time that is yes": '{"time": true, "event": "login", "ip": "", "user": "(no moment)"}',
    "something nested 300": '{"time": 1700000000, "event": "login", "ip": "", "more": ' + lists(300) + "}",
    "something nested 2000": '{"time": 1700000000, "event": "login", "ip": "", "more": ' + lists(2000) + "}",
    "records nested 12000": '{"time": 1700000000, "event": "login", "ip": "", "more": ' + records(12000) + "}",
    "bytes that are no text": "",
}
ASKS = [
    "/api/v1/audit", "/api/v1/audit?kind=signin", "/api/v1/audit?kind=change", "/api/v1/audit?kind=action", "/api/v1/audit?q=login",
    "/api/v1/audit/export?format=csv", "/api/v1/audit/export?format=jsonl", "/api/v1/audit/export?format=csv&kind=action",
]  # fmt: skip


@pytest.mark.parametrize("line", list(ODD_LINES))
def test_a_line_of_the_activity_log_that_is_a_record_and_no_entry(tmp_path: Path, line: str) -> None:
    # The log was "something went wrong inside qKVM" for whoever opened it, or asked for it as a file: a list
    # where the event belongs cannot be looked up among the kinds of event, and a value nested a few
    # hundred deep is more than the framework writes out. An entry is what the program writes; a line
    # that is something else is no entry, and the entries around it are shown.
    with wall(tmp_path) as admin:
        admin.core.audit.flush()  # type: ignore[attr-defined]
        with (tmp_path / "audit.log").open("ab") as file:
            file.write((ODD_LINES[line].encode() or b'{"time": 1700000000, "event": "lo\xff\xfegin", "ip": "\x81"}') + b"\n")
        answers = {ask: admin.get(ask).status_code for ask in ASKS}
        assert set(answers.values()) == {200}, (line, answers)
        entries = admin.get("/api/v1/audit?limit=50").json()["entries"]
        events = [entry["event"] for entry in entries]
        assert "login" in events or "setup" in events, events  # what the program wrote is still there to read
        assert all(type(entry["time"]) in (int, float) for entry in entries) and "(no moment)" not in str(entries)
        assert "(no moment)" not in admin.get("/api/v1/audit/export?format=jsonl").text


@pytest.mark.parametrize("where", ["a device's password", "a saved text", "an account's password", "the recovery key", "the alerts' address"])
@pytest.mark.parametrize("depth", [30, 400, 1000])
def test_something_nested_inside_what_the_settings_file_keeps_sealed(tmp_path: Path, where: str, depth: int) -> None:
    # Any record that is not empty was taken for a sealed one, whatever was in it. Nested a thousand deep,
    # the wall started, and from then on every change was answered "not saved": what is read is copied at
    # every save, and the copying gives up far earlier than the reading. Nothing qKVM writes is nested
    # like that, anywhere in the file: such a file is a damaged one, and the second copy is used.
    folder = tmp_path / "wall"
    fake = FakeKvm().start()
    try:
        with wall(folder) as admin:
            add(admin, fake.url)
            assert admin.post("/api/v1/actions", json={"name": "Types", "kind": "text", "text": "abc"}).status_code == 201
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://example.net/hook"}).status_code == 200
        good = {name: (folder / name).read_text(encoding="utf-8") for name in ("qkvm.json", "qkvm.bak")}

        def spoiled(text: str) -> str:
            saved = json.loads(text)
            sealed = {
                "a device's password": lambda: saved["devices"][0]["secret"],
                "a saved text": lambda: saved["actions"][0]["secret"],
                "an account's password": lambda: saved["users"][0]["auth"],
                "the recovery key": lambda: saved["recovery"],
                "the alerts' address": lambda: saved["alerts"]["webhook"],
            }[where]()
            sealed["more"] = "(nested)"
            return json.dumps(saved).replace('"(nested)"', records(depth), 1)

        (folder / "qkvm.json").write_text(spoiled(good["qkvm.json"]), encoding="utf-8")
        with wall(folder, sign_in=False) as admin:
            assert admin.core.store.restored  # type: ignore[attr-defined]
            assert admin.get("/healthz").status_code == 200
        for name in good:
            (folder / name).write_text(spoiled(good["qkvm.json"]), encoding="utf-8")
        with pytest.raises(StoreError):
            Core(folder)
    finally:
        fake.stop()
