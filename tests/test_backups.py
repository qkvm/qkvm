"""Backups of the wall to a folder, as an admin sets them up in Settings > Backups (0.4.0): the key, shown once as its
recovery kit and never again; a run by the clock or by hand; Verify; a failed run said in the activity log, in Settings and
to the alert destinations; and a wall of 0.3.2 that loads as it was, with nothing run until an admin switches them on."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, backup, exchange, kvm, server, update, vault
from qkvm._version import __version__
from qkvm.store import Store
from tests.settings_file import settings_text
from tests.test_alerts import Inbox
from tests.test_backup_file import another_name_for
from tests.test_wall import PASSWORD, add, closed_port, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.05, 0.1, 0.2))
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def inbox() -> Iterator[Inbox]:
    box = Inbox()
    yield box
    box.close()


def made_key(admin: Any) -> dict[str, Any]:
    reply = admin.post("/api/v1/backups/key", json={"password": PASSWORD})
    assert reply.status_code == 200, reply.text
    return dict(reply.json())


def set_up(admin: Any, folder: Path, **more: Any) -> None:
    reply = admin.put("/api/v1/backups", json={"enabled": True, "folder": str(folder), "hour": 3, "keep": 7, "history": False, **more})
    assert reply.status_code == 200, reply.text


def events(admin: Any, name: str) -> list[dict[str, Any]]:
    return [entry for entry in admin.core.audit.tail(500) if entry["event"] == name]


def test_off_until_an_admin_switches_them_on_and_a_wall_of_0_3_2_loads_as_it_was(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True)
    # What 0.3.2 wrote: no "backups" at all.
    store = Store(tmp_path / "qkvm.json")
    document = store.snapshot()
    document.pop("backups")
    store.write(document)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    with wall(tmp_path) as admin:
        shown = admin.get("/api/v1/backups").json()
        assert (shown["enabled"], shown["key"], shown["last"], shown["next"], shown["folder"]) == (False, None, None, None, "")
        assert (shown["hour"], shown["keep"], shown["history"]) == (3, 7, False)
        loaded = admin.core.store.snapshot()
        assert {part: value for part, value in loaded.items() if part != "backups"} == {part: value for part, value in document.items() if part != "activity_position"} | {"activity_position": loaded["activity_position"]}
        time.sleep(0.5)  # (some looks of the clock)
        assert admin.core.store.backups.last_at == 0.0 and not events(admin, "backup_made") and not events(admin, "backup_failed")


def test_the_key_takes_the_password_and_is_shown_once_and_never_again(tmp_path: Path) -> None:
    folder = tmp_path / "backups"
    with wall(tmp_path / "data") as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True)
        assert admin.post("/api/v1/backups/key", json={"password": "not the password"}).status_code == 401
        assert admin.get("/api/v1/backups").json()["key"] is None
        made = made_key(admin)
        key = backup.key_of(made["key"])
        assert made["id"] == backup.key_id(key) and made["key"] in made["kit"] and backup.key_in_kit(made["kit"]) == key
        shown = admin.get("/api/v1/backups").json()
        assert shown["key"] == {"id": made["id"], "made": made["made"]}
        set_up(admin, folder)
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        [file] = backup.listed(folder)
        assert backup.verify(file, key).devices == 1  # (the kit opens it)
        # And nowhere else, in any of the ways it could be written down: the answers, the settings file, the activity
        # log, the program's own log, an export with every secret in it.
        export = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "a passphrase of ten", "parts": list(exchange.PARTS)})
        assert export.status_code == 200
        opened = exchange.unpack(export.text, "a passphrase of ten")
        answers = [admin.get(path).text for path in ("/api/v1/backups", "/api/v1/settings", "/api/v1/audit", "/api/v1/alerts", "/api/v1/security")]
        answers.append(admin.post("/api/v1/backups/verify").text)
        written = [settings_text(tmp_path / "data" / "qkvm.json"), *(path.read_text(encoding="utf-8", errors="replace") for path in (tmp_path / "data").glob("*.log*"))]
        everything = "\n".join([*answers, *written, json.dumps(exchange.gather(admin.core.store, admin.core.vault, set(exchange.PARTS), secrets=True)), repr(opened)])
        for form in (made["key"], made["key"].replace("-", ""), key.hex(), key.hex().upper(), backup.written(key)[:19]):
            assert form not in everything, form
        # A new key: a new kit, the kit before it no longer opens what is made from now on, and says which it needs.
        again = made_key(admin)
        assert again["id"] != made["id"]
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        newest = backup.latest(folder, again["id"])  # (the new key's, by its name)
        assert newest is not None and newest != file
        with pytest.raises(backup.BackupError) as refused:
            backup.verify(newest, key)
        assert refused.value.code == "wrong_key" and again["id"] in refused.value.message
        assert backup.verify(file, key).devices == 1  # (and the earlier backups open with the earlier kit, as its kit says)
        made_lines = events(admin, "backup_key_made")
        assert [line["key"] for line in made_lines] == [again["id"], made["id"]] and made_lines[0]["replaced"] == made["id"]


def test_switching_them_on_takes_a_key_and_a_folder_of_its_own(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        said = {"enabled": True, "folder": str(tmp_path / "backups"), "hour": 3, "keep": 7, "history": False}
        refused = admin.put("/api/v1/backups", json=said)
        assert (refused.status_code, refused.json()["code"]) == (409, "no_key")
        made_key(admin)
        for wrong in ({"folder": ""}, {"folder": "backups"}, {"folder": str(data / "backups")}, {"hour": 24}, {"hour": -1}, {"keep": 0}, {"keep": 1000}):
            reply = admin.put("/api/v1/backups", json={**said, **wrong})
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), wrong
        assert admin.get("/api/v1/backups").json()["enabled"] is False
        assert admin.post("/api/v1/backups/run").json()["code"] == "no_folder"
        set_up(admin, tmp_path / "backups", hour=5, keep=3, history=True)
        shown = admin.get("/api/v1/backups").json()
        assert (shown["enabled"], shown["folder"], shown["hour"], shown["keep"], shown["history"]) == (True, str(tmp_path / "backups"), 5, 3, True)
        assert shown["next"] == backup.next_run(5, admin.core.store.backups.since)
        [changed] = events(admin, "backup_settings_changed")
        assert (changed["enabled"], changed["folder"], changed["hour"]) == (True, str(tmp_path / "backups"), 5)


def test_back_up_now_and_verify_the_latest_say_what_it_holds(tmp_path: Path) -> None:
    folder = tmp_path / "backups"
    with wall(tmp_path / "data") as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True)
        assert admin.post("/api/v1/backups/verify").json()["code"] == "no_key"
        made_key(admin)
        set_up(admin, folder, history=True)
        assert admin.post("/api/v1/backups/verify").json()["code"] == "no_backup"
        admin.core.history.observe(admin.core.store.devices[0].id, {"state": "offline"})  # (so that there is a history)
        admin.core.history.flush()
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is True and backup.NAME.fullmatch(done["name"]) and done["size"] > 0
        shown = admin.get("/api/v1/backups").json()
        assert (shown["last"]["ok"], shown["last"]["name"], shown["last"]["size"]) == (True, done["name"], done["size"])
        assert shown["latest"] == {"name": done["name"], "size": done["size"]} and shown["running"] is False
        checked = admin.post("/api/v1/backups/verify").json()
        assert (checked["name"], checked["devices"], checked["accounts"], checked["admins"], checked["not_opening"]) == (done["name"], 1, 1, 1, 0)
        assert checked["secrets"] == 1 and checked["activity_bytes"] > 0 and checked["history"] > 0  # (the device's password: never the backup key)
        [line] = events(admin, "backup_made")
        assert (line["file"], line["size"], line["history"]) == (done["name"], done["size"], True)
        assert events(admin, "backup_verified")[0]["file"] == done["name"]
        # Nothing of the copy of the history it was made from is left in the data folder.
        assert not [name for name in os.listdir(tmp_path / "data") if "backup" in name]


def test_another_walls_backups_in_the_folder_are_left_alone_and_said(tmp_path: Path) -> None:
    # Two walls on one share (or this wall's backups under a key made before): each keeps to its own, and Settings says that
    # the folder holds backups of another key, which this wall never touches. (The review of wave 3, M1.)
    folder, other = tmp_path / "backups", backup.new_key()
    theirs = backup.make(folder, other, settings=Store.of_document({}, Path("qkvm.json")).snapshot(), data_key=bytes(32), logs=[], history=None, program=__version__, keep=7)
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, folder, keep=1)
        for _ in range(2):
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
            time.sleep(1.05)
        mine = backup.listed(folder, admin.core.store.backups.key_id)
        assert len(mine) == 1 and (folder / theirs.name).exists()
        shown = admin.get("/api/v1/backups").json()
        assert shown["others"] == 1 and shown["latest"]["name"] == mine[0].name
        assert admin.post("/api/v1/backups/verify").json()["name"] == mine[0].name  # (its own latest, not another key's)


def test_a_run_by_the_clock_at_its_hour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    folder = tmp_path / "backups"
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, folder, hour=time.localtime().tm_hour)
        time.sleep(0.3)
        assert backup.listed(folder) == []  # (switched on within the hour: its first run is the next time the hour comes)
        admin.core.store.backups.since = time.time() - 2 * 86400  # (as if switched on two days ago)
        wait_until(lambda: len(backup.listed(folder)) == 1, "the clock made a backup at its hour")
        time.sleep(0.3)
        assert len(backup.listed(folder)) == 1  # (and only one: the next is tomorrow)
        assert admin.get("/api/v1/backups").json()["next"] == backup.next_run(time.localtime().tm_hour, admin.core.store.backups.last_at)


def test_a_failed_run_is_said_in_the_activity_log_in_settings_and_to_the_alert_destinations(tmp_path: Path, inbox: Inbox) -> None:
    nowhere = tmp_path / "not mounted" / "backups"  # (a share not mounted: its folder is never made on the disk below it)
    with wall(tmp_path / "data") as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        hook = admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True, "events": ["backup", "recovered"]})
        assert hook.status_code == 201, hook.text
        made_key(admin)
        set_up(admin, nowhere)
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is False and "not mounted" in done["error"]
        assert not nowhere.exists() and not nowhere.parent.exists()
        shown = admin.get("/api/v1/backups").json()["last"]
        assert (shown["ok"], shown["error"], shown["good"]) == (False, done["error"], 0.0)
        [line] = events(admin, "backup_failed")
        assert line["why"] == done["error"] and line["told"] is True
        wait_until(lambda: inbox.received, "the alert of the failed run arrived")
        said = json.loads(inbox.received[0]["body"])
        assert (said["what"], said["event"], said["severity"], said["title"]) == ("backup", "backup", "error", "Backup failed")
        assert done["error"] in said["message"]
        # Put right: the next run makes one, and the destination told of the failure is told that it is over.
        set_up(admin, tmp_path / "backups")
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        wait_until(lambda: len(inbox.received) == 2, "the alert that backups are made again arrived")
        again = json.loads(inbox.received[1]["body"])
        assert (again["what"], again["severity"]) == ("recovered", "info") and again["title"] == "Backups are made again"


def test_a_folder_that_never_answers_is_said_and_holds_up_nothing_else(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A hard NFS mount whose server is gone: whatever touches the folder waits for ever. A run is said to have failed after
    # its bound, and alerted, though its thread never comes back; the work on the folder is on threads of its own, so
    # neither Settings nor Verify ties a thread of the wall's shared pool; once those few threads are held, the folder is
    # asked nothing more, and that is said at once. (The review of wave 3, M2.)
    import threading

    gone = threading.Event()  # (the server of the share: let go at the end, so that no thread outlives the test)

    def hangs(*given: Any, **said: Any) -> Any:
        gone.wait(30)
        raise OSError(5, "the share went away")

    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    try:
        with wall(tmp_path / "data") as admin:
            made_key(admin)
            set_up(admin, tmp_path / "backups")
            assert admin.post("/api/v1/backups/run").json()["ok"] is True  # (one made, before the share went away)
            monkeypatch.setattr(backup, "make", hangs)
            monkeypatch.setattr(backup, "verify", hangs)
            monkeypatch.setattr(backup, "listed", hangs)
            started = time.monotonic()
            done = admin.post("/api/v1/backups/run").json()
            assert done["ok"] is False and "did not finish" in done["error"] and time.monotonic() - started < 10
            [failed] = events(admin, "backup_failed")
            assert failed["why"] == done["error"]
            # Settings answers from what was saved, at once, while the thread is held.
            shown = admin.get("/api/v1/backups").json()
            assert (shown["running"], shown["last"]["ok"], shown["latest"]["name"]) == (False, False, admin.core.store.backups.last_name)
            assert [thread.name for thread in threading.enumerate()].count("backup-folder") == 1
            # Verify is held to a bound of its own on those threads: the second, and then there is none left.
            monkeypatch.setattr(server, "VERIFY_WITHIN", 0.5)
            refused = admin.post("/api/v1/backups/verify")
            assert (refused.status_code, refused.json()["code"]) == (504, "timeout")
            assert [thread.name for thread in threading.enumerate()].count("backup-folder") == 2
            started = time.monotonic()
            for refused in (admin.post("/api/v1/backups/verify"), admin.post("/api/v1/backups/run")):
                said = refused.json()
                assert said.get("code") == "busy" or "has not answered" in said.get("error", ""), said
            assert time.monotonic() - started < 5 and [thread.name for thread in threading.enumerate()].count("backup-folder") == 2
            assert admin.get("/api/v1/backups").json()["last"]["ok"] is False
    finally:
        gone.set()


def test_a_run_due_by_the_clock_while_one_is_going_is_said(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    let_go = threading.Event()
    real = backup.make

    def slow(*given: Any, **said: Any) -> Any:
        let_go.wait(30)
        return real(*given, **said)

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    monkeypatch.setattr(server, "RUN_WAIT", 0.1)
    try:
        with wall(tmp_path / "data") as admin:
            made_key(admin)
            set_up(admin, tmp_path / "backups", hour=time.localtime().tm_hour)
            monkeypatch.setattr(backup, "make", slow)
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            admin.core.store.backups.since = time.time() - 2 * 86400  # (due by the clock now, with a run going)
            wait_until(lambda: events(admin, "backup_not_started"), "the clock said that its run was not started")
            time.sleep(0.3)
            [said] = events(admin, "backup_not_started")  # (once, not at every look)
            assert "being made" in said["why"]
            let_go.set()
            wait_until(lambda: events(admin, "backup_made"), "the run going ended")
            time.sleep(0.3)
            assert len(backup.listed(tmp_path / "backups")) == 1  # (and the clock's is that one: none after it today)
    finally:
        let_go.set()


def test_an_error_nobody_foresaw_is_a_failed_run_said_once_and_not_tried_at_every_look(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of wave 3, L1: an error of no foreseen kind left the run unrecorded, and the clock began another at every
    # look, sealing the activity log each time, with nothing said.) Said by its kind, its words in the program's log only.
    from qkvm import chain

    def slips(*given: Any, **said: Any) -> Any:
        raise RuntimeError("a slip of the program with who knows what in it")

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups", hour=time.localtime().tm_hour)
        monkeypatch.setattr(backup, "make", slips)
        admin.core.store.backups.since = time.time() - 2 * 86400  # (due by the clock)
        wait_until(lambda: events(admin, "backup_failed"), "the run that slipped was said to have failed")
        time.sleep(0.5)  # (some ten looks of the clock)
        [failed] = events(admin, "backup_failed")
        assert "RuntimeError" in failed["why"] and "who knows what" not in failed["why"]
        assert admin.core.store.backups.last_at > 0 and admin.core.store.backups.last_ok is False
        seals = [entry for entry in admin.core.audit.tail(500) if entry["event"] == chain.SEALED and entry.get("why") == "backup"]
        assert len(seals) == 1


def test_a_history_busy_for_a_moment_is_asked_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Its own checkpoint holds the history for a moment now and then (store.Gate): a run at 03:00 that met one is not a
    # failed backup. Asked again, three times in all, and only then said.
    from qkvm import history

    monkeypatch.setattr(server, "HISTORY_AGAIN", 0.05)
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups", history=True)
        admin.core.history.observe(add(admin, f"http://127.0.0.1:{closed_port()}", force=True), {"state": "offline"})
        admin.core.history.flush()
        real, asked = history.History.copy_to, []

        def busy_twice(self: Any, target: Path) -> bool:
            asked.append(target)
            if len(asked) < 3:
                raise history.NotReadable("The history is busy just now. Try again in a moment.")
            return real(self, target)

        monkeypatch.setattr(history.History, "copy_to", busy_twice)
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is True and len(asked) == 3
        assert backup.verify(tmp_path / "backups" / done["name"], backup_key_of(admin)).history
        asked.clear()
        monkeypatch.setattr(history.History, "copy_to", lambda self, target: (asked.append(target), (_ for _ in ()).throw(history.NotReadable("The history is busy just now")))[1])
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is False and "busy" in done["error"] and len(asked) == 3


def backup_key_of(admin: Any) -> bytes:
    """The backup key as the wall keeps it, opened (a test's look into the vault)."""
    return bytes.fromhex(admin.core.vault.read(admin.core.store.backups.secret, backup.SEALED_FOR))


def test_accounts_reset_take_the_backup_key_with_them(tmp_path: Path) -> None:
    # The key is sealed with the vault's, which a reset erases: kept, it opens nothing, and backups would fail every day.
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        admin.core.reset_password()
        kept = admin.core.store.backups
        assert (kept.secret, kept.key_id, kept.enabled) == (None, "", False)
        assert kept.folder == str(tmp_path / "backups")  # (where they went is no secret: kept for when a key is made again)


def test_a_locked_wall_makes_no_backup_and_says_why(tmp_path: Path) -> None:
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        admin.core.vault.lock()
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is False and "locked" in done["error"]
        assert backup.listed(tmp_path / "backups") == []


def test_only_one_run_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        real = backup.make
        monkeypatch.setattr(backup, "make", lambda *given, **said: (time.sleep(1.0), real(*given, **said))[1])
        monkeypatch.setattr(server, "RUN_WAIT", 0.2)
        first = admin.post("/api/v1/backups/run").json()
        assert first == {"running": True}
        busy = admin.post("/api/v1/backups/run")
        assert (busy.status_code, busy.json()["code"]) == (409, "busy")
        assert admin.get("/api/v1/backups").json()["running"] is True
        wait_until(lambda: not admin.get("/api/v1/backups").json()["running"], "the run ended")
        assert len(backup.listed(tmp_path / "backups")) == 1


def test_a_run_cut_off_by_its_bound_has_none_beside_it_and_its_late_end_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-review of wave 3, N1.) A run said failed after its hour goes on in its thread, which nothing stops. Begun
    # beside it, the next one shared its copy of the history and its partial files: a healthy run was said failed, and the
    # late one pruned the backup Settings named. None is begun while it goes on, by hand or by the clock (said once), and
    # what it made once its folder answers is kept and said.
    import threading

    let_go, calls = threading.Event(), []
    real = backup.make

    def stuck_once(*given: Any, **said: Any) -> Any:
        calls.append(said.get("history"))
        if len(calls) == 1:
            let_go.wait(30)  # (the share's server gone, for a while)
        return real(*given, **said)

    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    folder = tmp_path / "backups"
    try:
        with wall(tmp_path / "data") as admin:
            made_key(admin)
            set_up(admin, folder, hour=time.localtime().tm_hour, keep=1, history=True)
            admin.core.history.observe(add(admin, f"http://127.0.0.1:{closed_port()}", force=True), {"state": "offline"})
            admin.core.history.flush()
            monkeypatch.setattr(backup, "make", stuck_once)
            done = admin.post("/api/v1/backups/run").json()
            assert done["ok"] is False and "did not finish" in done["error"]
            refused = admin.post("/api/v1/backups/run")
            assert (refused.status_code, refused.json()["code"]) == (409, "busy") and "still waiting" in refused.json()["message"]
            kept = admin.core.store.backups
            kept.since, kept.last_at = time.time() - 2 * 86400, 0.0  # (due by the clock, with the run cut off still going)
            wait_until(lambda: events(admin, "backup_not_started"), "the clock said that its run was not begun")
            time.sleep(0.3)
            [said] = events(admin, "backup_not_started")  # (once)
            assert "still waiting" in said["why"] and len(calls) == 1
            kept.last_at = time.time()  # (the clock satisfied: what follows is the late run's alone)
            let_go.set()
            wait_until(lambda: events(admin, "backup_ended_late"), "the late run's end was said")
            [late] = events(admin, "backup_ended_late")
            [made] = backup.listed(folder)
            assert late["ok"] is True and late["file"] == made.name
            shown = admin.get("/api/v1/backups").json()
            assert (shown["last"]["ok"], shown["latest"]["name"]) == (True, made.name)
            assert admin.post("/api/v1/backups/verify").json()["name"] == made.name
            # And each run has a copy of the history of its own, which goes with it.
            names = []
            real_copy = server.history.History.copy_to

            def copied(self: Any, target: Path) -> bool:
                names.append(target.name)
                return real_copy(self, target)

            monkeypatch.setattr(server.history.History, "copy_to", copied)
            (tmp_path / "data" / "backup-history-1.tmp").write_bytes(b"left by a run cut off")
            for _ in range(2):
                time.sleep(1.05)
                assert admin.post("/api/v1/backups/run").json()["ok"] is True
            assert len(set(names)) == 2 and all(backup.HISTORY_COPIES.fullmatch(name) for name in names)
            assert not [name for name in os.listdir(tmp_path / "data") if "backup" in name]
    finally:
        let_go.set()


def test_a_run_cut_off_never_takes_away_the_history_copy_of_a_run_begun_after_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, bugs round 2, M1.) A run takes away the copies of the history that runs before left, but
    # never one a run still holds: it took the names held as it began, then looked through the data folder. Cut off by its
    # hour between the two (a slow disk), its thread went on later, found the copy of a run begun after it, and took it away:
    # that run failed. Each copy is judged by the names held at the moment it is taken away.
    import threading

    data, first, second = tmp_path / "data", tmp_path / "first", tmp_path / "second"
    real_scandir, real_copy, real_make = os.scandir, server.history.History.copy_to, backup.make
    looking, go_on, looked = threading.Event(), threading.Event(), threading.Event()
    slow: list[threading.Thread] = []
    seen: list[bool] = []

    def scandir(path: Any = None) -> Any:
        if path is not None and Path(path) == data and threading.current_thread().name == "backup-folder" and not slow:
            slow.append(threading.current_thread())  # (the first run's look through the data folder, held)
            looking.set()
            assert go_on.wait(30)
        return real_scandir(path)

    def copy_to(self: Any, target: Path) -> bool:
        if threading.current_thread() in slow:
            looked.set()  # (the first run has looked through the data folder, and taken away what it would)
            return False
        return bool(real_copy(self, target))

    def make(folder: Path, *given: Any, **said: Any) -> Any:
        if folder == second:
            assert said["history"] is not None and said["history"].exists()
            go_on.set()
            assert looked.wait(30)
            seen.append(said["history"].exists())
        return real_make(folder, *given, **said)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(server.history.History, "copy_to", copy_to)
    monkeypatch.setattr(backup, "make", make)
    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    with wall(data) as admin:
        try:
            made_key(admin)
            admin.core.history.observe(add(admin, f"http://127.0.0.1:{closed_port()}", force=True), {"state": "offline"})
            admin.core.history.flush()
            set_up(admin, first, history=True)
            cut_off = admin.post("/api/v1/backups/run").json()
            assert looking.is_set() and cut_off["ok"] is False and "did not finish" in cut_off["error"], cut_off
            set_up(admin, second, history=True)  # (another folder: not held by the run cut off)
            monkeypatch.setattr(server, "BACKUP_STUCK", 30)
            done = admin.post("/api/v1/backups/run").json()
            assert seen == [True] and done["ok"] is True, (seen, done)
            [made] = backup.listed(second)
            assert backup.verify(made, backup_key_of(admin)).history  # (with the history it copied)
        finally:
            go_on.set()
            wait_until(lambda: admin.core.backup_runs.held == 0, "the run cut off never ended", 20)
    assert not [name for name in os.listdir(data) if backup.HISTORY_COPIES.fullmatch(name)]


def test_verify_the_run_and_the_folders_look_each_have_a_thread_of_their_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-review of wave 3, N2a.) Two Verifies held the two threads the folder had, and a run begun meanwhile failed at
    # once, alerted as a dead folder. Each kind of work has its own now: a second Verify is told busy, as busy.
    import threading

    let_go = threading.Event()
    real = backup.verify

    def reading(*given: Any) -> Any:
        let_go.wait(30)
        return real(*given)

    with wall(tmp_path / "data") as admin:
        reader: threading.Thread | None = None
        try:
            made_key(admin)
            set_up(admin, tmp_path / "backups")
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
            monkeypatch.setattr(backup, "verify", reading)
            first: list[Any] = []
            reader = threading.Thread(target=lambda: first.append(admin.post("/api/v1/backups/verify")))
            reader.start()
            wait_until(lambda: admin.core.backup_reads.held == 1, "the first Verify reads")
            second = admin.post("/api/v1/backups/verify")
            assert (second.status_code, second.json()["code"]) == (409, "busy") and "Verify" in second.json()["message"]
            time.sleep(1.05)
            assert admin.post("/api/v1/backups/run").json()["ok"] is True  # (the run has its own thread)
            assert not events(admin, "backup_failed")
            let_go.set()
            reader.join(30)
            assert first and first[0].status_code == 200
        finally:
            let_go.set()
            if reader is not None:
                reader.join(30)


def test_a_folder_that_does_not_answer_never_locks_the_backup_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-review of wave 3, N2b.) Every save looked at where the folder lies, the one saved too: with a dead share named,
    # no save went through (504) until a restart, not even backups switched off, nor a move to a healthy folder. A folder
    # unchanged is not looked at again; a look still waiting for a dead one is said as busy, never as the typed folder's
    # fault; the data folder is still refused wherever it is named.
    import threading

    from qkvm import unlock

    gone = threading.Event()
    dead, other_dead, healthy = tmp_path / "nas" / "qkvm", tmp_path / "nas2" / "qkvm", tmp_path / "disk" / "qkvm"
    for each in (dead, other_dead, healthy):
        each.parent.mkdir(parents=True)
    real = unlock.lies_in

    def lies_in(path: Path, folder: Path) -> bool:
        if "nas" in str(path):
            gone.wait(30)
            raise OSError(5, "the share went away")
        return real(path, folder)

    def saved(where: Path, enabled: bool) -> Any:
        return admin.put("/api/v1/backups", json={"enabled": enabled, "folder": str(where), "hour": 3, "keep": 7, "history": False})

    monkeypatch.setattr(server, "FOLDER_WITHIN", 0.5)
    with wall(tmp_path / "data") as admin:
        try:
            made_key(admin)
            set_up(admin, dead)
            monkeypatch.setattr(unlock, "lies_in", lies_in)  # (the share's server goes)
            assert saved(dead, False).status_code == 200  # (switched off, the folder as the page shows it: not looked at again)
            assert saved(healthy, True).status_code == 200  # (moved to a healthy one)
            timed_out = saved(other_dead, True)
            assert (timed_out.status_code, timed_out.json()["code"]) == (504, "timeout") and str(other_dead) in timed_out.json()["message"]
            stuck_again = saved(dead, True)  # (the second look, at another dead folder, holds the last thread)
            assert stuck_again.status_code == 504
            busy = saved(tmp_path / "disk" / "elsewhere", True)
            assert (busy.status_code, busy.json()["code"]) == (409, "busy") and "elsewhere" not in busy.json()["message"]
            assert saved(healthy, False).status_code == 200  # (the one saved: no look, whatever waits)
            assert admin.core.store.backups.folder == str(healthy) and admin.core.store.backups.enabled is False
            gone.set()
            wait_until(lambda: admin.core.backup_looks.held == 0, "the looks let go")
            refused = saved(tmp_path / "data" / "backups", True)
            assert (refused.status_code, refused.json()["code"]) == (422, "invalid")
        finally:
            gone.set()


def test_a_folder_error_that_is_a_time_out_is_said_as_the_folders_and_not_as_the_hour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-review of wave 3, a nit.) An NFS or SMB folder answering ETIMEDOUT is an OSError that Python makes a TimeoutError:
    # it was said as the run's hour gone by, and Verify's as its ten minutes. Each is said as what the folder said.
    import errno

    def timed_out(*given: Any, **said: Any) -> Any:
        raise OSError(errno.ETIMEDOUT, "Connection timed out")

    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        monkeypatch.setattr(backup, "make", timed_out)
        monkeypatch.setattr(backup, "verify", timed_out)
        done = admin.post("/api/v1/backups/run").json()
        assert done["ok"] is False and "Connection timed out" in done["error"] and "did not finish" not in done["error"]
        checked = admin.post("/api/v1/backups/verify")
        assert (checked.status_code, checked.json()["code"]) == (409, "unreadable") and "Connection timed out" in checked.json()["message"]


def test_where_a_folder_lies_that_cannot_be_looked_at_is_not_taken_for_outside_the_data_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-review of wave 3, a nit.) What could not be looked at was taken for "not in the data folder", and saved.
    from qkvm import unlock

    def cannot(*given: Any) -> bool:
        raise OSError(13, "Permission denied")

    with wall(tmp_path / "data") as admin:
        made_key(admin)
        monkeypatch.setattr(unlock, "lies_in", cannot)
        refused = admin.put("/api/v1/backups", json={"enabled": True, "folder": str(tmp_path / "elsewhere"), "hour": 3, "keep": 7, "history": False})
        assert (refused.status_code, refused.json()["code"]) == (422, "invalid") and "could not be looked at" in refused.json()["message"]
        assert admin.core.store.backups.folder == ""


def test_verify_after_a_new_key_reads_this_keys_backup_or_says_there_is_none_yet(tmp_path: Path) -> None:
    # (The re-review of wave 3, a nit.) It read the last name saved, made with the key before: wrong_key, written down as a
    # failed Verify, where the guide says "this key's newest".
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        made_key(admin)  # (a new key)
        assert admin.get("/api/v1/backups").json()["latest"] is None
        none_yet = admin.post("/api/v1/backups/verify")
        assert (none_yet.status_code, none_yet.json()["code"]) == (404, "no_backup") and "this key" in none_yet.json()["message"]
        assert not events(admin, "backup_verified")
        time.sleep(1.05)
        done = admin.post("/api/v1/backups/run").json()
        assert admin.post("/api/v1/backups/verify").json()["name"] == done["name"]


def test_a_saved_folder_in_the_data_folder_is_refused_too_and_never_backed_up_into(tmp_path: Path) -> None:
    # (The last look of wave 3, 3.) A restored wall keeps the folder its backups went to on the old computer, which may be
    # where its data folder is now. The saved folder was not looked at again on a save, the data folder's refusal with it:
    # switched on as Settings showed it, the backups went into the data folder. The refusal by spelling asks the disk
    # nothing and is made whatever was saved; and a run refuses such a folder as well.
    import shutil

    old_backups = tmp_path / "new" / "qkvm" / "backups"
    old_backups.parent.mkdir(parents=True)
    with wall(tmp_path / "old") as admin:
        kit = made_key(admin)
        set_up(admin, old_backups)
        name = admin.post("/api/v1/backups/run").json()["name"]
    carried = tmp_path / "carried.qkvmbackup"
    shutil.copy(old_backups / name, carried)
    shutil.rmtree(tmp_path / "new")
    data = tmp_path / "new" / "qkvm"
    backup.restore(carried, backup.key_of(kit["key"]), data)
    with wall(data) as admin:
        shown = admin.get("/api/v1/backups").json()
        assert shown["folder"] == str(old_backups) and shown["enabled"] is False and shown["key"] is None
        made_key(admin)  # (a restored wall has no backup key: its admin makes a new one)
        on = admin.put("/api/v1/backups", json={"enabled": True, "folder": shown["folder"], "hour": 3, "keep": 7, "history": False})
        assert (on.status_code, on.json()["code"]) == (422, "invalid") and "data folder" in on.json()["message"]
        done = admin.post("/api/v1/backups/run").json()  # (Back up now, with them off and that folder saved)
        assert done["ok"] is False and "data folder" in done["error"]
        assert not old_backups.exists()


def test_a_folder_that_never_answers_holds_only_itself_and_what_waits_is_said_until_a_restart(tmp_path: Path, inbox: Inbox, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The last look of wave 3, 1.) A run cut off on a share that never answers held the one thread runs had, and no backup
    # was made again until a restart, even into a healthy folder. It holds its own folder alone now; its copy of the history
    # is left to it; and while it waits, Settings says so, and once a day at the hour an alert says what waits and that a
    # restart frees it.
    import threading

    gone = threading.Event()
    dead, healthy = tmp_path / "nas" / "qkvm", tmp_path / "disk" / "qkvm"
    for each in (dead, healthy):
        each.parent.mkdir(parents=True)
    real = backup.make

    def make(folder: Path, *given: Any, **said: Any) -> Any:
        if "nas" in str(folder):
            gone.wait(30)  # (a hard NFS mount whose server is gone: for good, in the real case)
            raise OSError(5, "the share went away")
        return real(folder, *given, **said)

    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    with wall(tmp_path / "data") as admin:
        try:
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True}).status_code == 201
            made_key(admin)
            admin.core.history.observe(add(admin, f"http://127.0.0.1:{closed_port()}", force=True), {"state": "offline"})
            admin.core.history.flush()
            set_up(admin, dead, hour=time.localtime().tm_hour, history=True)
            monkeypatch.setattr(backup, "make", make)
            cut = admin.post("/api/v1/backups/run").json()
            assert cut["ok"] is False and "did not finish" in cut["error"]
            [in_use] = [name for name in os.listdir(tmp_path / "data") if backup.HISTORY_COPIES.fullmatch(name)]
            refused = admin.post("/api/v1/backups/run")
            assert (refused.status_code, refused.json()["code"]) == (409, "busy") and "still waiting" in refused.json()["message"]
            waiting = admin.get("/api/v1/backups").json()["waiting"]
            assert [each["folder"] for each in waiting] == [str(dead)] and waiting[0]["since"] > 0
            # Moved to a healthy folder: backups are made there, the one waiting left as it is.
            assert admin.put("/api/v1/backups", json={"enabled": True, "folder": str(healthy), "hour": time.localtime().tm_hour, "keep": 7, "history": True}).status_code == 200
            time.sleep(1.05)
            done = admin.post("/api/v1/backups/run").json()
            assert done["ok"] is True and (healthy / done["name"]).exists()
            assert (tmp_path / "data" / in_use).exists()  # (the copy the run waiting holds: never taken from under it)
            assert [each["folder"] for each in admin.get("/api/v1/backups").json()["waiting"]] == [str(dead)]
            # Once a day at the hour, while it waits: an alert of what waits and that a restart frees it, and a line.
            [held] = admin.core.backup_runs.working()
            held.since -= 2 * 86400  # (as if it had waited since two days ago)
            wait_until(lambda: events(admin, "backup_still_waiting"), "what waits was said at the hour")
            time.sleep(0.3)
            [said] = events(admin, "backup_still_waiting")
            assert said["folders"] == [str(dead)]
            wait_until(lambda: any("still waiting" in json.loads(item["body"])["title"] for item in inbox.received), "the alert arrived")
            told = next(json.loads(item["body"]) for item in inbox.received if "still waiting" in json.loads(item["body"])["title"])
            assert str(dead) in told["message"] and "restart" in told["message"]
        finally:
            gone.set()


@pytest.mark.parametrize("cut_off", [False, True])
def test_a_runs_end_reaches_the_listeners_opened_anew_and_a_run_never_cut_off_is_not_said_to_be(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cut_off: bool) -> None:
    # (The last look of wave 3, 2.) The listeners are opened anew now and then (an address that moved, HTTPS switched on): the
    # same program, a new app and event loop. A run under way then was stopped where it was waited for and never said it had
    # given up, so its end was lost; one cut off told its end to the old loop, closed. Its end reaches the loop there is now,
    # or the next look of the clock; and "Back up now" meanwhile says a backup is being made, not that one was cut off.
    import threading

    from fastapi.testclient import TestClient

    from qkvm.server import create_app
    from tests.test_wall import CSRF

    go, calls = threading.Event(), []
    real = backup.make

    def held_once(*given: Any, **said: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:
            go.wait(30)
        return real(*given, **said)

    monkeypatch.setattr(server, "BACKGROUND_OWED", 0.2)
    folder = tmp_path / "backups"
    try:
        with wall(tmp_path / "data") as admin:
            made_key(admin)
            set_up(admin, folder, keep=1)
            # (The run before, waited for as every run is: shortened first, its answer was "still running" on a loaded computer,
            # GitHub's Windows runner, 3.12.)
            done = admin.post("/api/v1/backups/run").json()
            assert done.get("ok") is True, done
            first = done["name"]
            monkeypatch.setattr(server, "BACKUP_STUCK", 0.5 if cut_off else 60.0)
            monkeypatch.setattr(server, "RUN_WAIT", 0.2)
            monkeypatch.setattr(backup, "make", held_once)
            time.sleep(1.05)
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            # (At its folder before the listeners close: one still waiting for its seal on a slow machine was stopped there,
            # before any of it was the folder's, and the test then saw a run begun anew after the restart.)
            wait_until(lambda: calls, "the run is at its folder", 20)
            if cut_off:
                wait_until(lambda: events(admin, "backup_failed"), "the run was cut off")
            core = admin.core
        with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as again:  # (the listeners opened anew)
            assert again.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            refused = again.post("/api/v1/backups/run")
            assert (refused.status_code, refused.json()["code"]) == (409, "busy")
            assert ("still waiting" in refused.json()["message"]) is cut_off and ("being made" in refused.json()["message"]) is not cut_off
            go.set()
            # (Its end as every run's where it was never cut off: "made"; and "ended late" only of one cut off: the fresh
            # review of the fixes, N4.)
            said = "backup_ended_late" if cut_off else "backup_made"
            wait_until(lambda: any(entry["event"] == said and entry.get("file") != first for entry in core.audit.tail(500)), "the run's end was said", 20)
            [made] = backup.listed(folder)
            assert made.name != first
            shown = again.get("/api/v1/backups").json()
            assert (shown["latest"]["name"], shown["last"]["ok"]) == (made.name, True)
            assert again.post("/api/v1/backups/verify").json()["name"] == made.name
    finally:
        go.set()


def test_a_late_end_in_the_folder_before_is_not_the_new_folders_latest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The last look of wave 3, 4.) A run cut off on a share, the backups moved to a healthy folder, and then the share answers:
    # its backup is made there, and is said so, but it is not the latest of the folder backups go to now (Verify would look
    # for it there, and find nothing).
    import threading

    gone = threading.Event()
    dead, healthy = tmp_path / "nas" / "qkvm", tmp_path / "disk" / "qkvm"
    for each in (dead, healthy):
        each.parent.mkdir(parents=True)
    real = backup.make

    def make(folder: Path, *given: Any, **said: Any) -> Any:
        if "nas" in str(folder):
            gone.wait(30)
        return real(folder, *given, **said)

    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    with wall(tmp_path / "data") as admin:
        try:
            made_key(admin)
            set_up(admin, dead)
            monkeypatch.setattr(backup, "make", make)
            assert admin.post("/api/v1/backups/run").json()["ok"] is False
            set_up(admin, healthy)
            gone.set()  # (the share's server is back)
            wait_until(lambda: events(admin, "backup_ended_late"), "the late end was said")
            [late] = events(admin, "backup_ended_late")
            [there] = backup.listed(dead)
            assert (late["ok"], late["file"], late["folder"]) == (True, there.name, str(dead))
            shown = admin.get("/api/v1/backups").json()
            assert shown["latest"] is None and shown["last"]["ok"] is False
            assert admin.post("/api/v1/backups/verify").json()["code"] == "no_backup"
        finally:
            gone.set()


def keys_held(file: Path, key: bytes) -> list[tuple[str, str | None]]:
    """What a backup's settings say of a backup key, opened with its kit as whoever has it would: the key's own fields, and
    every secret they keep sealed with the data key the backup holds, opened (what each is sealed for, and what it opens to)."""
    settings, data_key, _ = backup.read(file, key, lambda name: None, lambda name, data: None)
    opened = vault.Vault()
    opened.adopt(data_key)
    kept = settings["backups"]
    sealed = backup.sealed_secrets(Store.of_document(settings, Path("qkvm.json")))
    return [("secret", json.dumps(kept.get("secret"))), ("key_id", kept.get("key_id")), *((context, opened.read(blob, context)) for blob, context in sealed)]


def test_a_key_made_new_while_a_run_waits_for_its_seal_is_that_runs_key_and_no_backup_holds_a_backup_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, H1.) A run read the backup key, waited for the activity log's seal, and only then took the
    # settings: a key made new in that moment was in the settings of a backup sealed with the key before, beside the data key
    # that opens it. Whoever had the kit before (the reason for a new key, as a rule) opened that backup, took the new key
    # out of it, and with it every backup made after. The run takes its key with the settings it holds now, at one moment
    # after the seal: nothing taken after the new kit was shown opens with the kit before. And no backup holds a backup key
    # at all, its own or another: a kit opens the backups made with it, and nothing in them leads to another key.
    import threading

    entered, go = threading.Event(), threading.Event()
    monkeypatch.setattr(server, "RUN_WAIT", 0.1)
    folder = tmp_path / "backups"
    with wall(tmp_path / "data") as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True)
        before = backup.key_of(made_key(admin)["key"])
        set_up(admin, folder)
        real = admin.core.audit.sealed

        def held(why: str, *given: Any, **said: Any) -> Any:
            if why == "backup":
                entered.set()
                go.wait(30)
            return real(why, *given, **said)

        monkeypatch.setattr(admin.core.audit, "sealed", held)
        try:
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            assert entered.wait(10)
            now = backup.key_of(made_key(admin)["key"])  # (the new kit, shown while the run waits for its seal)
        finally:
            go.set()
        wait_until(lambda: events(admin, "backup_made"), "the run ended", 15)
        assert backup.listed(folder, backup.key_id(before)) == []  # (nothing made after the new kit opens with the kit before)
        [made] = backup.listed(folder)
        assert admin.get("/api/v1/backups").json()["latest"]["name"] == made.name
        time.sleep(1.05)
        monkeypatch.setattr(server, "RUN_WAIT", 60.0)  # (waited for, on a loaded computer too)
        after = admin.post("/api/v1/backups/run").json()
        assert after.get("ok") is True, after  # (and one made the ordinary way, after)
        every = backup.listed(folder)
        assert len(every) == 2
        for file in every:
            said = keys_held(file, now)
            assert said[:2] == [("secret", "null"), ("key_id", "")], file.name
            assert not [context for context, _ in said[2:] if context == backup.SEALED_FOR], file.name
            assert not [opened for _, opened in said if opened and (before.hex() in opened or now.hex() in opened)], file.name
            assert backup.verify(file, now).devices == 1  # (and all else is in it, as it was)


def test_a_change_refused_while_a_run_waits_for_its_seal_is_none_of_that_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, H1, the same kind nearby.) A run took the backups' settings as it began, and read how many to
    # keep and whether the history goes in from them after the seal it waited for: a save refused by the disk meanwhile, taken
    # back, was still what it pruned by. What a run is for is taken with its key and its settings, after the seal.
    import threading

    entered, go = threading.Event(), threading.Event()
    folder = tmp_path / "backups"
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, folder, keep=7)
        for _ in range(2):
            done = admin.post("/api/v1/backups/run").json()
            assert done.get("ok") is True, done
        monkeypatch.setattr(server, "RUN_WAIT", 0.1)  # (the next run's answer: not waited for)
        real, write = admin.core.audit.sealed, Store.write

        def held(why: str, *given: Any, **said: Any) -> Any:
            if why == "backup":
                entered.set()
                go.wait(30)
            return real(why, *given, **said)

        def full(self: Store, data: dict[str, Any]) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(admin.core.audit, "sealed", held)
        try:
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            assert entered.wait(10)
            monkeypatch.setattr(Store, "write", full)
            refused = admin.put("/api/v1/backups", json={"enabled": True, "folder": str(folder), "hour": 3, "keep": 1, "history": False})
            monkeypatch.setattr(Store, "write", write)
            assert refused.status_code == 507 and admin.get("/api/v1/backups").json()["keep"] == 7
        finally:
            go.set()
        wait_until(lambda: len(events(admin, "backup_made")) == 3, "the run ended", 15)
        assert len(backup.listed(folder)) == 3  # (kept as the 7 saved say: the 1 refused pruned nothing)


@pytest.mark.parametrize("ends", ["made", "failed", "after a new key"])
def test_a_run_that_ends_after_what_it_was_for_was_changed_is_said_as_its_own_and_leaves_settings_as_they_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inbox: Inbox, ends: str
) -> None:
    # (The outside review of 0.4.0, M1.) A late end kept to its own folder; an ordinary one did not: a run still writing into the
    # folder before when the admin chose another ended as the new folder's last run and latest backup, which Verify then
    # looked for there and did not find, and its time moved the clock's next run on by a day. Every end is the folder's and
    # the key's it was made for: said in the activity log with that folder, and Settings' last run, latest and next changed
    # only where they are still the run's; nothing alerted for the folder or the key before.
    import threading

    entered, go = threading.Event(), threading.Event()
    real = backup.make

    def held(*given: Any, **said: Any) -> Any:
        entered.set()
        go.wait(30)
        if ends == "failed":
            raise OSError(5, "the share went away")
        return real(*given, **said)

    monkeypatch.setattr(server, "RUN_WAIT", 0.1)
    old, new = tmp_path / "old", tmp_path / "new"
    with wall(tmp_path / "data") as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        hook = admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True, "events": ["backup", "recovered"]})
        assert hook.status_code == 201, hook.text
        made_key(admin)
        set_up(admin, old)
        monkeypatch.setattr(backup, "make", held)
        try:
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            assert entered.wait(10)
            if ends == "after a new key":
                made_key(admin)
            else:
                set_up(admin, new)
        finally:
            go.set()
        name = "backup_failed" if ends == "failed" else "backup_made"
        wait_until(lambda: events(admin, name), "the run ended", 15)
        shown = admin.get("/api/v1/backups").json()
        assert (shown["last"], shown["latest"]) == (None, None), shown
        assert admin.core.store.backups.last_at == 0.0  # (the clock's next run is not moved on by what was not this one)
        checked = admin.post("/api/v1/backups/verify")
        assert (checked.status_code, checked.json()["code"]) == (404, "no_backup")
        [line] = events(admin, name)
        assert (line["folder"], line["current"]) == (str(old), False)
        assert len(backup.listed(old)) == (0 if ends == "failed" else 1) and backup.listed(new) == []
        time.sleep(0.5)
        assert inbox.received == []


def test_a_run_whose_listeners_were_opened_anew_keeps_its_hour_and_is_said_failed_and_alerted_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inbox: Inbox) -> None:
    # (The outside review of 0.4.0, M2.) Opened anew (an address that moved, HTTPS switched on), the listeners stopped the run's
    # waiter, and its hour went with it: a share that never answered held the run for ever, never said failed nor alerted,
    # while Settings said nothing waited and Back up now was refused as busy. The hour is the run's own, kept with it by the
    # program whichever listeners there are: once it has passed, the run is said to have failed, once, alerted once, and
    # shown as waiting for its folder, which it holds until its thread ends; never before (a waiter stopped is no hour gone by).
    import threading

    from fastapi.testclient import TestClient

    from qkvm.server import create_app
    from tests.test_wall import CSRF

    gone, entered = threading.Event(), threading.Event()
    real = backup.make

    def hangs(*given: Any, **said: Any) -> Any:
        entered.set()
        gone.wait(60)  # (a share whose server is gone: for good, in the real case)
        return real(*given, **said)

    monkeypatch.setattr(server, "BACKUP_STUCK", 2.0)  # (the hour, shortened)
    monkeypatch.setattr(server, "RUN_WAIT", 0.1)
    monkeypatch.setattr(server, "BACKGROUND_OWED", 0.05)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    folder = tmp_path / "backups"
    try:
        with wall(tmp_path / "data") as admin:
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            hook = admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True, "events": ["backup", "recovered"]})
            assert hook.status_code == 201, hook.text
            made_key(admin)
            set_up(admin, folder)
            monkeypatch.setattr(backup, "make", hangs)
            began = time.time()
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            assert entered.wait(20)  # (at its folder before the listeners close)
            core = admin.core
        with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as again:  # (the listeners opened anew)
            assert again.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200

            def failures() -> list[dict[str, Any]]:
                return [entry for entry in core.audit.tail(500) if entry["event"] == "backup_failed"]

            wait_until(failures, "the run was said to have failed once its hour had passed", 20)
            [failed] = failures()
            assert failed["time"] - began >= 2.0 and "did not finish" in failed["why"] and failed["folder"] == str(folder)
            [working] = core.backup_runs.working()
            assert working.cut_off and working.left
            shown = again.get("/api/v1/backups").json()
            assert [each["folder"] for each in shown["waiting"]] == [str(folder)] and shown["running"] is False
            assert (shown["last"]["ok"], shown["last"]["error"]) == (False, failed["why"])
            refused = again.post("/api/v1/backups/run")
            assert (refused.status_code, refused.json()["code"]) == (409, "busy") and "still waiting" in refused.json()["message"]
            wait_until(lambda: inbox.received, "the failure was alerted")
            time.sleep(0.5)  # (some ten looks of the clock)
            assert len(failures()) == 1 and inbox.titles() == ["Backup failed"]
            # The folder answers: its thread ends, the backup it made is kept and said, and the folder is free again.
            gone.set()
            wait_until(lambda: any(entry["event"] == "backup_ended_late" for entry in core.audit.tail(500)), "the run's late end was said", 20)
            wait_until(lambda: core.backup_runs.held == 0, "the run let go of its folder", 20)
            [made] = backup.listed(folder)
            shown = again.get("/api/v1/backups").json()
            assert (shown["waiting"], shown["latest"]["name"], shown["last"]["ok"]) == ([], made.name, True)
            wait_until(lambda: inbox.titles() == ["Backup failed", "Backups are made again"], "it was told that backups are made again")
    finally:
        gone.set()


def test_a_folder_saved_anew_has_no_latest_until_a_backup_is_made_there(tmp_path: Path) -> None:
    # (The outside review of 0.4.0, bugs round, M2.) Saved anew, the folder kept the last backup made in the one before as its
    # latest: Settings named a backup the new folder does not hold, Verify looked for it there (404), and the count of
    # another key's backups was the other folder's. What was made is the folder's it was made in: said as there, and the
    # latest again once backups go there again.
    a, b = tmp_path / "a", tmp_path / "b"
    theirs = backup.make(a, backup.new_key(), settings={}, data_key=bytes(32), logs=[], history=None, program=__version__, keep=7)
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, a)
        made = admin.post("/api/v1/backups/run").json()
        assert made["ok"] is True and (a / theirs.name).exists()
        shown = admin.get("/api/v1/backups").json()
        assert (shown["latest"]["name"], shown["others"]) == (made["name"], 1)
        set_up(admin, b)
        shown = admin.get("/api/v1/backups").json()
        assert (shown["latest"], shown["others"]) == (None, 0), shown
        assert (shown["last"]["ok"], shown["last"]["name"], shown["last"]["folder"]) == (True, made["name"], str(a))  # (said where it is)
        checked = admin.post("/api/v1/backups/verify")
        assert (checked.status_code, checked.json()["code"]) == (404, "no_backup") and str(a) in checked.json()["message"]
        set_up(admin, a)  # (back: the backup there is its latest again)
        assert admin.get("/api/v1/backups").json()["latest"]["name"] == made["name"]
        assert admin.post("/api/v1/backups/verify").json()["name"] == made["name"]
        set_up(admin, b)
        time.sleep(1.05)
        again = admin.post("/api/v1/backups/run").json()
        shown = admin.get("/api/v1/backups").json()
        assert (shown["latest"]["name"], shown["last"]["folder"], shown["others"]) == (again["name"], str(b), 0) and (b / again["name"]).exists()
        assert admin.post("/api/v1/backups/verify").json()["name"] == again["name"]


@pytest.mark.parametrize("held", [False, True], ids=["told at once", "held by quiet hours"])
def test_who_was_told_a_backup_failed_is_told_it_is_over_after_a_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inbox: Inbox, held: bool) -> None:
    # (The outside review of 0.4.0, bugs round, M3.) Who had been told that a backup failed was known in memory alone: after a
    # restart, or the listeners opened anew, the backup made again was told to nobody, and an incident PagerDuty had opened
    # for the failure stayed open for good. Kept with the backups' settings now: told once a backup is made again, at once,
    # or once quiet hours that held it back are over, a restart between.
    from qkvm import destinations

    real_make, real_quiet = backup.make, destinations.quiet

    def full(*given: Any, **said: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    data = tmp_path / "data"
    with wall(data) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        hook = admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True, "events": ["backup", "recovered"]})
        assert hook.status_code == 201, hook.text
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        monkeypatch.setattr(backup, "make", full)
        assert admin.post("/api/v1/backups/run").json()["ok"] is False
        wait_until(lambda: inbox.titles() == ["Backup failed"], "the failure was told")
        if held:
            monkeypatch.setattr(backup, "make", real_make)
            monkeypatch.setattr(destinations, "quiet", lambda one, now: True)
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
            time.sleep(0.5)
            assert inbox.titles() == ["Backup failed"]  # (held back by the quiet hours)
    monkeypatch.setattr(backup, "make", real_make)
    monkeypatch.setattr(destinations, "quiet", real_quiet)
    with wall(data) as admin:
        if not held:
            assert admin.get("/api/v1/backups").json()["last"]["ok"] is False
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
        wait_until(lambda: inbox.titles() == ["Backup failed", "Backups are made again"], "it was told that backups are made again")
        time.sleep(0.5)  # (some ten looks of the clock)
        assert inbox.titles() == ["Backup failed", "Backups are made again"] and admin.core.store.backups.told == []


@pytest.mark.parametrize("which", ["last run ahead", "switched on ahead", "clock behind"])
def test_times_saved_while_the_clock_was_ahead_hold_no_backup_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str) -> None:
    # (The outside review of 0.4.0, bugs round, M5.) The clock's next run counts from the last run, or from when backups were
    # switched on: saved while the computer's clock was months ahead, and that clock then set right, no backup was made by
    # the clock until that date came round, and nothing said so. A time saved days ahead of the clock is set right now, and
    # said in the activity log; the next run is the next time the hour comes. A clock that was behind makes the one backup
    # it owes, and no more.
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    folder, hour = tmp_path / "backups", time.localtime().tm_hour
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, folder, hour=hour)
        kept, now = admin.core.store.backups, time.time()
        if which == "clock behind":
            kept.since, kept.last_at = now - 181 * 86400, now - 180 * 86400
            wait_until(lambda: len(backup.listed(folder)) == 1, "the clock made the backup it owes")
            time.sleep(0.5)
            kept = admin.core.store.backups
            assert len(backup.listed(folder)) == 1 and not events(admin, "backup_times_mended")
            assert admin.get("/api/v1/backups").json()["next"] == backup.next_run(hour, kept.last_at) <= time.time() + 25 * 3600
            return
        ahead = now + 180 * 86400
        if which == "last run ahead":
            kept.last_at = kept.last_good = ahead
        else:
            kept.since = ahead
        assert now < admin.get("/api/v1/backups").json()["next"] <= now + 25 * 3600
        wait_until(lambda: events(admin, "backup_times_mended"), "the times ahead were set right, and said")
        time.sleep(0.5)
        [said] = events(admin, "backup_times_mended")
        assert said["last_at" if which == "last run ahead" else "since"] == ahead
        kept = admin.core.store.backups
        assert max(kept.last_at, kept.since, kept.last_good) <= time.time()
        shown = admin.get("/api/v1/backups").json()["next"]
        assert shown == backup.next_run(hour, max(kept.last_at, kept.since)) and now < shown <= now + 25 * 3600
        assert backup.listed(folder) == []  # (none was owed: the next is at the hour)


def test_another_name_for_the_folder_a_run_holds_is_that_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, bugs round, M6.) The run cut off on a share holds its folder until its thread ends, by the
    # folder's name: saved by another name for the same folder (a junction, a link, a short name), a second run was begun
    # beside it, and took away its file in the making. The folder is known by what it is on the disk, looked at on the
    # folder's own threads: by any name, a run into it is refused as busy, and the clock's is said not begun.
    import threading

    folder, alias = tmp_path / "backups", tmp_path / "alias"
    folder.mkdir()
    another_name_for(folder, alias)
    entered, let_go = threading.Event(), threading.Event()
    close = backup._Sealed.close

    def held_once(self: Any) -> None:
        if not entered.is_set():
            entered.set()
            let_go.wait(30)  # (the share's server gone, its file in the making)
        close(self)

    monkeypatch.setattr(backup._Sealed, "close", held_once)
    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    hour = time.localtime().tm_hour
    with wall(tmp_path / "data") as admin:
        try:
            made_key(admin)
            set_up(admin, folder, hour=hour)
            first = admin.post("/api/v1/backups/run").json()
            # (Cut off by its hour; its thread, slow on a loaded computer, still comes to its file in the making and is held there.)
            assert first.get("ok") is False and "did not finish" in first["error"] and entered.wait(20), first
            set_up(admin, alias, hour=hour)
            for _ in range(2):  # (looked at on its thread the first time; known by that name the next)
                refused = admin.post("/api/v1/backups/run")
                assert (refused.status_code, refused.json()["code"]) == (409, "busy") and "still waiting" in refused.json()["message"], refused.text
            admin.core.store.backups.since = time.time() - 2 * 86400  # (due by the clock)
            wait_until(lambda: any("still waiting" in each["why"] for each in events(admin, "backup_not_started")), "the clock's run was said not begun")
            time.sleep(0.3)
            assert len(events(admin, "backup_failed")) == 1  # (the first run's, cut off: no run refused is said to have failed)
            admin.core.store.backups.since = time.time()  # (the clock satisfied: what follows is the first run's alone)
        finally:
            let_go.set()
        wait_until(lambda: events(admin, "backup_ended_late"), "the first run's late end was said")
        [late] = events(admin, "backup_ended_late")
        assert late["ok"] is True and backup.listed(folder) == [folder / late["file"]]  # (its file in the making was left to it)


@pytest.mark.parametrize("spelling", ["junction or link", "long-path prefix"])
def test_another_name_for_a_folder_the_first_run_made_is_that_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str) -> None:
    # (The fresh review of the fixes, N1: M6 by another road.) A folder not there yet was known by the folder above it and the
    # name below; the first run then made it, and by another name (a junction to it, or the same path with \\?\ before it) it
    # was the folder's own: known as another, a second run was begun beside the first and took away its file in the making.
    # The folder is made first, on the run's own thread (only where the folder above it is there, as a backup's is), and known
    # by what it is itself.
    import threading

    if spelling == "long-path prefix" and sys.platform != "win32":
        pytest.skip("a name with \\\\?\\ before it is Windows' own")
    share = tmp_path / "share"
    share.mkdir()
    folder = share / "backups"  # (not there yet: the first run makes it)
    alias = tmp_path / "alias" if spelling == "junction or link" else Path("\\\\?\\" + str(folder))
    entered, let_go = threading.Event(), threading.Event()
    close = backup._Sealed.close

    def held_once(self: Any) -> None:
        if not entered.is_set():
            entered.set()
            let_go.wait(30)  # (the share slow to answer, its file in the making)
        close(self)

    monkeypatch.setattr(backup._Sealed, "close", held_once)
    monkeypatch.setattr(server, "BACKUP_STUCK", 0.5)
    with wall(tmp_path / "data") as admin:
        try:
            made_key(admin)
            set_up(admin, folder)
            first = admin.post("/api/v1/backups/run").json()
            # (Cut off by its hour; its thread, slow on a loaded computer, still comes to its file in the making and is held there.)
            assert first.get("ok") is False and "did not finish" in first["error"] and entered.wait(20) and folder.is_dir(), first
            if spelling == "junction or link":
                another_name_for(folder, alias)
            assert os.path.samefile(folder, alias)
            set_up(admin, alias)
            second = admin.post("/api/v1/backups/run")
            assert (second.status_code, second.json()["code"]) == (409, "busy") and "still waiting" in second.json()["message"], second.text
        finally:
            let_go.set()
        wait_until(lambda: events(admin, "backup_ended_late"), "the first run's late end was said")
        [late] = events(admin, "backup_ended_late")
        assert late["ok"] is True and backup.listed(folder) == [folder / late["file"]]  # (its file in the making was left to it)


@pytest.mark.parametrize("ends", ["failed", "made"])
def test_a_run_whose_listeners_were_opened_anew_ends_as_every_run_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inbox: Inbox, ends: str) -> None:
    # (The fresh review of the fixes, N4.) A run under way when the listeners were opened anew (an address, a port, HTTPS) that
    # then ended before its hour was kept as a late end: one that failed (a full disk) was a line of the activity log alone,
    # Settings still saying the run before made a backup, and nobody alerted; one that made a backup was not counted by the
    # clock, which began another at once. A run never cut off ends as every run does: Settings' last run, the clock's next,
    # the alerts, and "made" or "failed" in the activity log (never "cut off, ended late").
    import threading

    from fastapi.testclient import TestClient

    from qkvm.server import create_app
    from tests.test_wall import CSRF

    entered, go = threading.Event(), threading.Event()
    real = backup.make

    def held(*given: Any, **said: Any) -> Any:
        entered.set()
        go.wait(30)
        if ends == "failed":
            raise OSError(28, "No space left on device")
        return real(*given, **said)

    monkeypatch.setattr(server, "BACKGROUND_OWED", 0.05)
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    folder = tmp_path / "backups"
    try:
        with wall(tmp_path / "data") as admin:
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            hook = admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": inbox.url, "private": True, "events": ["backup", "recovered"]})
            assert hook.status_code == 201, hook.text
            made_key(admin)
            set_up(admin, folder, hour=time.localtime().tm_hour)
            done = admin.post("/api/v1/backups/run").json()  # (the run before: Settings say it made one)
            assert done.get("ok") is True, done
            before = done["name"]
            time.sleep(1.05)
            monkeypatch.setattr(server, "RUN_WAIT", 0.1)
            monkeypatch.setattr(backup, "make", held)
            assert admin.post("/api/v1/backups/run").json() == {"running": True}
            assert entered.wait(20)  # (at its folder before the listeners close)
            core = admin.core
        with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as again:  # (the listeners opened anew)
            assert again.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            core.store.backups.last_at -= 2 * 86400  # (and the clock's run due meanwhile: the one under way counts as it)
            go.set()
            wait_until(lambda: not core.backup_runs.held, "the run's thread ended", 20)
            name = "backup_failed" if ends == "failed" else "backup_made"
            wait_until(lambda: any(entry["event"] == name and entry.get("file") != before for entry in core.audit.tail(500)), "the run's end was said", 20)
            time.sleep(0.5)  # (some ten looks of the clock)
            shown = again.get("/api/v1/backups").json()
            lines = [entry for entry in reversed(core.audit.tail(500)) if entry["event"] in ("backup_made", "backup_failed", "backup_ended_late")]  # (the oldest first)
            assert not [entry for entry in lines if entry["event"] == "backup_ended_late"]  # (never said to have been cut off)
            assert shown["last"]["at"] > time.time() - 60 and shown["next"] > time.time()  # (the clock counts from this run)
            if ends == "failed":
                assert (shown["last"]["ok"], shown["latest"]["name"]) == (False, before) and "No space left" in shown["last"]["error"]
                assert [entry["event"] for entry in lines] == ["backup_made", "backup_failed"] and lines[1]["told"] is True
                wait_until(lambda: inbox.titles() == ["Backup failed"], "the failure was alerted")
            else:
                [made] = [path for path in backup.listed(folder) if path.name != before]
                assert (shown["last"]["ok"], shown["latest"]["name"]) == (True, made.name) and len(backup.listed(folder)) == 2
                assert [entry["event"] for entry in lines] == ["backup_made", "backup_made"] and inbox.received == []
    finally:
        go.set()
