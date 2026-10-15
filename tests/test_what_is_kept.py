"""What is kept, and what a file can make the program do: nothing typed by mistake in the activity log, no more work for a password than the program asks for, no record under a name that is another's."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, cli, kvm, update, vault
from qkvm.alerts import Watcher
from qkvm.core import Core
from qkvm.kvm import DeviceSpec
from qkvm.store import AuditLog, StoreError
from qkvm.vault import Vault
from tests.fake_kvm import FakeKvm
from tests.test_users import OTHER, visitor
from tests.test_wall import PASSWORD, add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def test_asking_about_a_name_that_is_nobodys_costs_what_a_wrong_password_costs_from_the_first_time_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The stand-in record that a nobody's password is checked against was made at the first such question
    # (the work of one check) and then checked against as well (the work of another): twice as long as a
    # wrong password for a real account, once per start, and enough to tell that the name is nobody's.
    work: list[str] = []
    real_create, real_open = Vault.create, Vault.open

    def create(self: Vault, password: str) -> dict[str, Any]:
        work.append("made")
        return real_create(self, password)

    def opened(record: dict[str, Any], password: str) -> bytes | None:
        work.append("checked")
        return real_open(record, password)

    with wall(tmp_path) as admin:
        monkeypatch.setattr(Vault, "create", create)
        monkeypatch.setattr(Vault, "open", staticmethod(opened))
        for number, guesser in enumerate((visitor(admin, 50011), visitor(admin, 50012), visitor(admin, 50013))):
            before = len(work)
            who = {"name": "nobody of that name"} if number < 2 else {}
            assert guesser.post("/api/v1/login", json={**who, "password": "a guess"}).status_code == 401
            assert len(work) - before == 1, work  # one piece of work each: the first nobody, the next nobody, and the admin


def test_what_was_typed_as_a_name_is_not_kept_unless_it_is_one(tmp_path: Path, fake: FakeKvm) -> None:
    # Often enough it is the password, typed a field too early: it was in the activity log in clear, in what
    # the page shows of it, in both downloads, and on the wire to a syslog collector.
    typed = "Password-typed-in-the-wrong-field-1"
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        stranger = visitor(admin, 50021)
        assert stranger.post("/api/v1/login", json={"name": typed, "password": "x"}).status_code == 401
        assert stranger.post("/api/v1/login", json={"name": "ADMIN", "password": "x"}).status_code == 401
        assert stranger.post("/api/v1/recover", json={"name": typed, "recovery_key": "x" * 20, "new_password": OTHER}).status_code == 401
        # A saved text is typed without its length going into the log; a text typed by hand says how long it was.
        saved = admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "a passphrase of 31 characters!!"}).json()["action"]
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": saved["id"]}).status_code == 200
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "hello"}).status_code == 200
        admin.core.audit.flush()  # type: ignore[attr-defined]
        written = (tmp_path / "audit.log").read_text(encoding="utf-8")
        entries = admin.get("/api/v1/audit?limit=500").json()["entries"]
    assert typed not in written and typed.lower() not in written.lower()
    failed = [entry for entry in entries if entry["event"] in ("login_failed", "recovery_failed")]
    assert sorted((entry["user"], entry.get("no_such_account", False)) for entry in failed) == [("", True), ("", True), ("admin", False)]
    typing = {entry.get("name") or entry["action"]: entry for entry in entries if entry["event"] == "action"}
    assert "chars" not in typing["Unlock disk"] and typing["text"]["chars"] == 5


def test_a_password_check_costs_no_more_than_this_program_asks_for(tmp_path: Path) -> None:
    # What the settings file says a check costs was believed up to nine seconds and a gigabyte a check, two
    # at a time; and one setting inside those bounds ended a start in a traceback.
    record = Vault().create("right")
    assert Vault.open(record, "right") is not None and Vault.open(record, "wrong") is None
    for change in ({"n": 2**20, "r": 8}, {"n": 2**20, "r": 7, "p": 4}, {"r": 0}, {"p": 0}, {"n": 2**18, "r": 16}, {"n": 3000}, {"name": "pbkdf2"}):
        costly = {**record, "kdf": {**record["kdf"], **change}}
        began = time.monotonic()
        assert Vault.open(costly, "right") is None, change
        assert time.monotonic() - began < 1.0, change
    for broken in ({}, {"kdf": {}}, {"kdf": record["kdf"]}, {**record, "key": "not a sealed key"}, {**record, "kdf": {**record["kdf"], "salt": 7}}):
        assert Vault.open(broken, "right") is None, broken
    # ...and what this program writes is well inside what it takes.
    assert record["kdf"]["n"] * record["kdf"]["r"] * record["kdf"]["p"] <= 2**21 and 2**17 * 8 * 1 <= 2**21


def test_a_record_under_a_name_that_is_anothers_is_a_damaged_file(tmp_path: Path, fake: FakeKvm) -> None:
    # A saved text is sealed for "action:" and its id, an authenticator's key for "totp:" and the account's.
    # A device given such an id by an edit of the file had that secret for its "password", and sent it to
    # whatever address the same edit named.
    with wall(tmp_path) as admin:
        add(admin, fake.url)
        action = admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "the passphrase"}).json()["action"]
    said = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    secret = said["actions"][0]["secret"]
    said["devices"][0].update(id=f"action:{action['id']}", secret=secret, url="http://127.0.0.1:9")
    for file in ("qkvm.json", "qkvm.bak"):
        (tmp_path / file).write_text(json.dumps(said), encoding="utf-8")
    with pytest.raises(StoreError):
        Core(tmp_path)
    for odd in ("alerts:webhook", "", "x" * 65, 7, None):
        said["devices"][0]["id"] = odd
        for file in ("qkvm.json", "qkvm.bak"):
            (tmp_path / file).write_text(json.dumps(said), encoding="utf-8")
        with pytest.raises(StoreError):
            Core(tmp_path)
    said["devices"][0]["id"] = "admin"  # what this program gave as an id at one time: still one
    (tmp_path / "qkvm.json").write_text(json.dumps(said), encoding="utf-8")
    assert Core(tmp_path).store.devices[0].id == "admin"


def test_a_hole_in_the_activity_log_is_written_into_it_when_it_can_be_written_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # What is known of it in memory is gone with the next restart, and the log then read as if nothing were missing.
    log = AuditLog(tmp_path / "audit.log")
    log.write("before", "192.0.2.1")
    log.flush()
    real_open = Path.open
    full = {"disk": True}

    def open_unless_full(self: Path, *args: Any, **kwargs: Any) -> Any:
        if full["disk"] and self.name == "audit.log" and args[:1] == ("a",):
            raise OSError(28, "No space left on device")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_unless_full)
    for _ in range(3):
        log.write("lost", "192.0.2.1")
    log.flush()
    full["disk"] = False
    log.write("after", "192.0.2.1")
    log.flush()
    monkeypatch.undo()
    events = [json.loads(line) for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert [entry["event"] for entry in events] == ["before", "log_gap", "after"]
    assert events[1]["count"] == 3 and "space" in events[1]["why"].lower() and events[1]["since"] <= events[2]["time"]
    assert log.missing is not None and log.missing["count"] == 3  # and whoever opens the log before a restart is told at its top, as before
    log.write("later", "192.0.2.1")
    log.flush()
    assert (tmp_path / "audit.log").read_text(encoding="utf-8").count("log_gap") == 1  # said once


def test_what_the_machines_were_last_seen_as_is_tried_again_where_it_could_not_be_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A write that failed was marked as done: if the last change before a power cut was a machine coming
    # back, the file still said "down", and that machine not coming back afterwards was news to nobody.
    watcher = Watcher(tmp_path / "watch.json")
    for _ in range(4):
        watcher.observe("a", "online")
    first = watcher.to_write()
    assert first is not None
    watcher.write(first)
    for _ in range(4):
        watcher.observe("a", "offline")
    changed = watcher.to_write()
    assert changed is not None
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    watcher.write(changed)
    assert watcher.to_write() is None  # not again at once: every quarter of a minute would be a line in the log each
    monkeypatch.setattr(alerts, "TRY_AGAIN", 0.0)
    again = watcher.to_write()
    assert again == changed  # but again after a while, although nothing has changed since
    monkeypatch.setattr(os, "replace", real_replace)
    watcher.write(again)
    assert watcher.to_write() is None and json.loads((tmp_path / "watch.json").read_text(encoding="ascii"))["stable"] == {"a": "offline"}


def test_a_devices_password_is_in_nothing_that_shows_how_it_is_talked_to() -> None:
    spec = DeviceSpec("a1b2c3d4", "Rack KVM", "https://192.168.1.20", "admin", "THE-DEVICE-PASSWORD")
    assert "THE-DEVICE-PASSWORD" not in repr(spec) and "THE-DEVICE-PASSWORD" not in str(spec) and "Rack KVM" in repr(spec)


def test_starting_over_leaves_nobody_with_a_way_in_that_an_account_gave_out(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url)
        token = admin.post("/api/v1/metrics/token", json={"password": PASSWORD}).json()["token"]
        collector = visitor(admin, 50031)
        assert collector.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert cli.main(["--data-dir", str(tmp_path), "--reset-password"]) == 0
    assert json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))["server"]["metrics_token"] == ""
    with wall(tmp_path) as admin:  # set up again, by whoever started over
        assert visitor(admin, 50032).get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code in (401, 404)


def test_a_certificate_that_was_made_anew_is_served_and_not_only_shown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Saving any setting made the certificate anew where its names had changed (a new address of the
    # computer), and showed the new one's fingerprint, while browsers went on being served the old one
    # until the next restart: whoever compared the two saw an attack that was none.
    with wall(tmp_path) as admin:
        core = admin.core  # type: ignore[attr-defined]
        restarts: list[bool] = []
        monkeypatch.setattr(core, "request_restart", lambda: restarts.append(True))
        settings = {"bind": ["local"], "port": 8787, "https": True, "interval": 2}
        assert admin.put("/api/v1/settings", json=settings).json()["restart"] is True  # HTTPS switched on
        shown = admin.get("/api/v1/settings").json()["cert_fingerprint"]

        def another(addresses: list[str]) -> Any:
            # Another first byte than the real one's: a fingerprint that begins with AA by chance (one in 256) is no other.
            core.cert_fingerprint = ("AB:" if shown.startswith("AA:") else "AA:") + shown[3:]
            return tmp_path / "tls" / "cert.pem", tmp_path / "tls" / "key.pem"

        same = admin.put("/api/v1/settings", json={**settings, "interval": 3}).json()
        assert same["restart"] is False and same["cert_fingerprint"] == shown  # nothing made anew: nothing reopened
        monkeypatch.setattr(core, "prepare_tls", another)
        anew = admin.put("/api/v1/settings", json={**settings, "interval": 4}).json()
        assert anew["cert_fingerprint"] != shown and anew["restart"] is True

        def no_room(addresses: list[str]) -> Any:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(core, "prepare_tls", no_room)
        refused = admin.put("/api/v1/settings", json={**settings, "interval": 5})
        assert (refused.status_code, refused.json()["code"]) == (507, "no_certificate")


@pytest.mark.skipif(os.name != "posix", reason="who may read a file is kept another way on Windows, and not looked at there")
def test_a_data_folder_that_others_can_read_is_said_at_start(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with wall(tmp_path):
        pass
    os.chmod(tmp_path, 0o755)
    for name in ("qkvm.json", "unlock.key"):
        os.chmod(tmp_path / name, 0o644)
    assert cli._others_read(tmp_path / "qkvm.json") and not cli._others_read(tmp_path / "there-is-no-such-file")
    capsys.readouterr()
    # (Half of a pair of options: the program ends over that, after the folder was looked at and before anything is served.)
    assert cli.main(["--data-dir", str(tmp_path), "--tls-cert", "x.pem"]) == 2
    said = capsys.readouterr().err
    assert "qkvm.json" in said and "unlock.key" in said and "can be read by other users" in said, said
    assert stat.S_IMODE((tmp_path / "qkvm.json").stat().st_mode) == 0o644  # said, not changed: it may be meant
    # A folder that is its owner's alone lets nobody else as far as the files, whatever they say of themselves.
    os.chmod(tmp_path, 0o700)
    assert cli.main(["--data-dir", str(tmp_path), "--tls-cert", "x.pem"]) == 2
    assert "can be read by other users" not in capsys.readouterr().err

