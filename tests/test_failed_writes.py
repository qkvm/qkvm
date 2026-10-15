"""What is true after a write that failed or was cut short: nothing is called done that a restart would undo,
nothing that was taken away comes back, and nothing is left half-made for a later start to pick up."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from qkvm.core import Core
from qkvm.store import Store
from tests.fake_kvm import FakeKvm
from tests.test_wall import PASSWORD, add, wall

FULL = OSError(28, "No space left on device")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def refuse_writes(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """Make Store.write fail while disk["full"] is set. Returns the switch."""
    disk = {"full": False}
    real_write = Store.write

    def write(self: Store, data: dict[str, Any]) -> None:
        if disk["full"]:
            raise OSError(28, "No space left on device")
        real_write(self, data)

    monkeypatch.setattr(Store, "write", write)
    return disk


# --- F0: the settings file set aside before its replacement is on disk ---------------------------------------


def test_a_start_that_could_not_finish_restoring_the_backup_does_not_leave_a_wall_for_anybody_to_claim(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        add(admin, fake.url)
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # one more change: qkvm.bak has the device too
    assert json.loads((data / "qkvm.bak").read_text(encoding="utf-8"))["devices"]

    # The settings file is unreadable at the next start (an editor that saved it on a full disk leaves it cut short),
    # and the disk is still full when qKVM, having read the backup, writes the settings anew.
    (data / "qkvm.json").write_text('{"version": 1, "server": {', encoding="utf-8")
    disk = refuse_writes(monkeypatch)
    disk["full"] = True
    with pytest.raises(OSError):
        Core(data)  # this start ends in a traceback; a service manager starts qKVM again
    print("after the failed start:", sorted(p.name for p in data.iterdir()))

    disk["full"] = False  # (it makes no difference whether there is room again)
    with wall(data, sign_in=False) as anybody:
        said = anybody.get("/api/v1/session").json()
        print("the next start says:", {k: said[k] for k in ("initialized", "authenticated")})
        claimed = anybody.post("/api/v1/setup", json={"name": "stranger", "password": "whoever comes first"})
        print("a stranger's first-run setup:", claimed.status_code, "role:", claimed.json().get("user", {}).get("role"))
        # The owner's settings are still in qkvm.bak at this point. The second thing the stranger saves replaces them.
        print("qkvm.bak holds the owner's devices:", len(json.loads((data / "qkvm.bak").read_text(encoding="utf-8"))["devices"]))
        anybody.put("/api/v1/alerts", json={"enabled": False})
        kept = json.loads((data / "qkvm.bak").read_text(encoding="utf-8"))
        print("after one more change, qkvm.bak holds devices:", len(kept["devices"]), "accounts:", [u["name"] for u in kept["users"]])
        assert said["initialized"] is True, "the wall came up as a new one, with the owner's settings lying beside it in qkvm.bak"


# --- F1: changes that are saved without `saved(...)`: a refused write is answered 500, and memory is left changed ---


def test_a_device_whose_removal_could_not_be_saved_is_not_shown_as_removed(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data) as admin:
        device = add(admin, fake.url)
        disk["full"] = True
        answer = admin.delete(f"/api/v1/devices/{device}")
        print("DELETE with the disk full:", answer.status_code, answer.json())
        on_wall = [d["id"] for d in admin.get("/api/v1/wall").json()["devices"]]
        again = admin.delete(f"/api/v1/devices/{device}")
        print("the wall lists:", on_wall, "| asked to remove it again:", again.status_code, again.json()["message"])
        disk["full"] = False
    saved = json.loads((data / "qkvm.json").read_text(encoding="utf-8"))["devices"]
    print("in qkvm.json:", [(d["name"], "password saved" if d["secret"] else "no password") for d in saved])
    with wall(data) as later:
        back = [d["id"] for d in later.get("/api/v1/wall").json()["devices"]]
        print("after a restart the wall lists:", back)
    # Either it was never gone (the refusal put memory back), or it is gone for good.
    assert (device in on_wall) == (device in back), "removed as far as anybody could see, and back with its saved password after a restart"


def test_where_qkvm_listens_is_not_changed_by_a_later_save_after_the_change_itself_was_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data) as admin:
        before = admin.get("/api/v1/settings").json()
        disk["full"] = True
        answer = admin.put("/api/v1/settings", json={"bind": ["all"], "port": before["port"], "https": False, "interval": 1.0})
        print("PUT /api/v1/settings with the disk full:", answer.status_code, answer.json())
        disk["full"] = False
        # Something unrelated is saved, by anybody, any time later.
        assert admin.post("/api/v1/tokens", json={"name": "a script"}).status_code == 201
        print("activity log, newest first:", [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]])
    on_disk = json.loads((data / "qkvm.json").read_text(encoding="utf-8"))["server"]["bind"]
    print("bind before:", before["bind"], "| bind in qkvm.json now:", on_disk)
    assert on_disk == before["bind"], "the refused change was written by the next save: at the next start qKVM listens on every address"


def test_a_setup_that_could_not_be_saved_has_not_set_the_wall_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data, sign_in=False) as first:
        disk["full"] = True
        answer = first.post("/api/v1/setup", json={"password": PASSWORD})
        print("setup with the disk full:", answer.status_code, answer.json())
        disk["full"] = False
        again = first.post("/api/v1/setup", json={"password": PASSWORD})
        print("setup again:", again.status_code, again.json().get("message"))
        signed_in = first.post("/api/v1/login", json={"password": PASSWORD})
        said = first.get("/api/v1/session").json()
        shown = "recovery_key" in answer.json() or "recovery_key" in again.json()
        print("sign-in with that password:", signed_in.status_code, "| a recovery key exists:", said["recovery"], "| shown to anybody:", shown)
        assert not said["recovery"] or shown, "the wall is set up, with a recovery key that nobody was ever shown"


def test_an_alert_address_that_was_to_be_forgotten_is_not_back_after_a_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "http://127.0.0.1:9/hook"}).status_code == 200
        disk["full"] = True
        answer = admin.put("/api/v1/alerts", json={"enabled": False, "forget_webhook": True})
        shown = admin.get("/api/v1/alerts").json()
        print("forget the address, disk full:", answer.status_code, "| the page then shows:", {k: shown[k] for k in ("enabled", "has_webhook")})
        disk["full"] = False
    with wall(data) as later:
        after = later.get("/api/v1/alerts").json()
        print("after a restart:", {k: after[k] for k in ("enabled", "has_webhook")})
    assert (shown["has_webhook"], shown["enabled"]) == (after["has_webhook"], after["enabled"]), "forgotten on the page, in use again after a restart"


def test_an_alert_address_that_was_refused_with_the_rest_of_the_form_is_not_in_use(tmp_path: Path) -> None:
    # No failed write here: the handler changes what is saved, finds the next field wrong, and answers 422 without undoing it.
    data = tmp_path / "data"
    with wall(data) as admin:
        answer = admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "http://127.0.0.1:9/elsewhere", "link": "not an address"})
        shown = admin.get("/api/v1/alerts").json()
        print("refused as a whole:", answer.status_code, answer.json()["message"], "| has_webhook now:", shown["has_webhook"])
        assert admin.post("/api/v1/tokens", json={"name": "a script"}).status_code == 201  # something unrelated is saved
    on_disk = json.loads((data / "qkvm.json").read_text(encoding="utf-8"))["alerts"]["webhook"]
    print("an address is saved in qkvm.json:", on_disk is not None)
    assert on_disk is None, "the address from the refused form is saved, and is where alerts go once they are switched on"


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="how Windows shares an open file")
def test_on_windows_a_program_that_is_reading_the_settings_file_is_all_it_takes(tmp_path: Path, fake: FakeKvm) -> None:
    # Nothing is made to fail here: another program (a backup, a scanner, an editor) has qkvm.json open, as this test has.
    data = tmp_path / "data"
    with wall(data) as admin:
        device = add(admin, fake.url)
        with (data / "qkvm.json").open("rb"):
            answer = admin.delete(f"/api/v1/devices/{device}")
        print("DELETE while qkvm.json is open elsewhere:", answer.status_code, answer.json()["code"])
        on_wall = [d["id"] for d in admin.get("/api/v1/wall").json()["devices"]]
    with wall(data) as later:
        back = [d["id"] for d in later.get("/api/v1/wall").json()["devices"]]
    print("on the wall after the answer:", on_wall, "| after a restart:", back)
    assert (device in on_wall) == (device in back)


# --- F2: qkvm.bak is the state before the last change, and falling back to it undoes that change ---------------


def test_a_token_that_was_taken_back_does_not_work_again_when_the_settings_are_read_from_the_backup(tmp_path: Path) -> None:
    from tests.test_unlock import fits
    from tests.test_wall import wait_until

    new = "the one chosen after the leak"
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        token = admin.post("/api/v1/tokens", json={"name": "a script"}).json()
        key, token_id = token["token"], token["record"]["id"]
        gone = admin.delete(f"/api/v1/tokens/{token_id}")
        print("token taken back:", gone.status_code, gone.json())  # the last change: qkvm.bak is the state just before it
    # A hand edit (the page itself sends people to edit allowed_hosts in this file) that left one brace too many.
    path = data / "qkvm.json"
    path.write_text(path.read_text(encoding="utf-8") + "}", encoding="utf-8")
    with wall(data, sign_in=False) as later:
        print("started from the backup; damaged file set aside as:", later.core.store.recovered_from.name)  # type: ignore[attr-defined]
        later.cookies.clear()
        works = later.get("/api/v1/wall", headers={"Authorization": f"Bearer {key}"})
        print("the token that was taken back:", works.status_code)
        print("activity log, newest first:", [entry["event"] for entry in later.core.audit.tail(3)])  # type: ignore[attr-defined]

    # The same for a password that was replaced because somebody else had it.
    other = tmp_path / "other"
    with wall(other) as admin:
        changed = admin.post("/api/v1/password", json={"current": PASSWORD, "new": new})
        print("password changed:", changed.status_code)
    (other / "qkvm.json").write_text((other / "qkvm.json").read_text(encoding="utf-8") + "}", encoding="utf-8")
    with wall(other, sign_in=False) as later:
        old, newer = later.post("/api/v1/login", json={"password": PASSWORD}), later.post("/api/v1/login", json={"password": new})
        print("after a start from the backup: the old password", old.status_code, "| the new one", newer.status_code)
    assert works.status_code == 401 and old.status_code == 401, "what the last change took away is back after a start from qkvm.bak, and no entry in the activity log says so"


def test_reset_password_leaves_nothing_of_the_accounts_or_the_saved_passwords_in_the_data_folder(tmp_path: Path, fake: FakeKvm, capsys: pytest.CaptureFixture[str]) -> None:
    from qkvm import cli
    from qkvm.vault import Vault
    from tests.test_unlock import fits
    from tests.test_wall import wait_until

    data = tmp_path / "data"
    with wall(data) as admin:
        device = add(admin, fake.url)  # saved with the password "secret"
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    assert cli.main(["--data-dir", str(data), "--reset-password"]) == 0
    print(capsys.readouterr().out.strip())
    # The second copy of the settings is of what was just saved: nothing of what was erased is in it either.
    for name in ("qkvm.json", "qkvm.bak"):
        left = json.loads((data / name).read_text(encoding="utf-8"))
        assert not left["users"] and left["recovery"] is None and left["unlock"] is None, name
        assert [d["id"] for d in left["devices"]] == [device] and all(d["secret"] is None for d in left["devices"]), name
        assert left["alerts"]["webhook"] is None, name  # (encrypted for the accounts as well: it would go nowhere)
    assert not any(Vault.open(found, (data / "unlock.key").read_text(encoding="ascii").strip()) for found in [left["unlock"]] if found)
    # And the accounts are not one unreadable settings file away from being back:
    (data / "qkvm.json").write_text("", encoding="utf-8")
    with wall(data, sign_in=False) as later:
        assert later.get("/api/v1/session").json()["initialized"] is False
        assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 409


def test_what_the_key_before_opened_the_folder_with_is_gone_after_the_start_that_takes_it_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm.vault import Vault
    from tests.test_unlock import fits
    from tests.test_wall import wait_until

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # (the copy from before a change has it by now)
    kept_copy = (data / "unlock.key").read_text(encoding="ascii").strip()  # somebody kept a copy of the key

    with wall(data, sign_in=False, locked_start=True) as later:
        assert later.get("/healthz").json()["locked"] is True
    for name in ("qkvm.json", "qkvm.bak"):  # one save takes it out of both: the second copy is of what was saved last
        left = json.loads((data / name).read_text(encoding="utf-8")).get("unlock")
        assert left is None or Vault.open(left, kept_copy) is None, f"{name}: README, 'a copy of it that somebody kept opens nothing afterwards'"


def test_the_same_when_only_the_copy_to_qkvm_bak_is_refused_which_nobody_is_told(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    import shutil

    from qkvm.vault import Vault
    from tests.test_unlock import fits
    from tests.test_wall import wait_until

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    kept_copy = (data / "unlock.key").read_text(encoding="ascii").strip()
    real_copy, real_unlink = shutil.copy2, os.unlink
    held = {"too": False}

    def copy_unless_held(source: Any, target: Any, *args: Any, **kwargs: Any) -> Any:
        if str(target).endswith("qkvm.bak.new"):
            raise PermissionError(13, "Permission denied")  # the folder takes no new file just now
        return real_copy(source, target, *args, **kwargs)

    def unlink_unless_held(path: Any, *args: Any, **kwargs: Any) -> None:
        if held["too"] and str(path).endswith("qkvm.bak"):
            raise PermissionError(13, "Permission denied")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", copy_unless_held)
    monkeypatch.setattr(os, "unlink", unlink_unless_held)
    # Where the second copy cannot be renewed, it is taken away: no copy rather than one from before.
    with wall(data, sign_in=False, locked_start=True) as later:
        assert later.get("/healthz").json()["locked"] is True
    assert not (data / "qkvm.bak").exists()
    assert json.loads((data / "qkvm.json").read_text(encoding="utf-8"))["unlock"] is None

    # Where it can be neither renewed nor taken away, it still holds what the old key opens, and that is said to
    # whoever starts qKVM: it is theirs to remove.
    monkeypatch.undo()
    data = tmp_path / "another"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    kept_copy = (data / "unlock.key").read_text(encoding="ascii").strip()
    held["too"] = True
    monkeypatch.setattr(shutil, "copy2", copy_unless_held)
    monkeypatch.setattr(os, "unlink", unlink_unless_held)
    core = Core(data, locked_start=True)
    told = core.unlock_at_start()
    assert told is not None and "qkvm.bak" in told and "remove that file by hand" in told
    left = json.loads((data / "qkvm.bak").read_text(encoding="utf-8")).get("unlock")
    assert left is not None and Vault.open(left, kept_copy) is not None  # (which is why it has to be said)


# --- F3: the activity log --------------------------------------------------------------------------------------


def test_an_action_that_could_not_be_written_to_the_activity_log_is_at_least_said_somewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from tests.fake_kvm import FakeState

    state = FakeState(atx=True)
    machine = FakeKvm(state).start()
    disk = {"full": False}
    real_open = Path.open

    def open_while_there_is_room(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if disk["full"] and self.name == "audit.log" and "a" in mode:
            raise OSError(28, "No space left on device")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_while_there_is_room)
    try:
        with caplog.at_level(logging.DEBUG, logger="qkvm"), wall(tmp_path / "data") as admin:
            device = add(admin, machine.url)
            admin.core.audit.flush()  # type: ignore[attr-defined]
            disk["full"] = True
            pressed = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
            removed = admin.post("/api/v1/tokens", json={"name": "made unseen"})
            admin.core.audit.flush()  # type: ignore[attr-defined]
            disk["full"] = False
            events = [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]
            said = [record.getMessage() for record in caplog.records if "activity" in record.getMessage().lower() or "audit" in record.getMessage().lower()]
            print("power button held:", pressed.status_code, pressed.json(), "| the machine got:", state.actions)
            print("a token made:", removed.status_code)
            print("activity log:", events)
            print("lines in qkvm.log about the activity log:", said)
            assert pressed.status_code == 200 and removed.status_code == 201 and "action" not in events
            # Done all the same (a full disk must not keep anybody from the power button), and said to whoever reads the log.
            missing = admin.get("/api/v1/audit").json()["missing"]
            assert missing["count"] == 2 and "space" in missing["why"].lower() and missing["since"] > 0, missing
            assert said is not None
    finally:
        machine.stop()


def test_an_action_that_reached_the_machine_is_in_the_activity_log_though_the_listeners_were_reopened_meanwhile(tmp_path: Path) -> None:
    import threading
    import time

    import httpx

    from qkvm import cli
    from tests.fake_kvm import FakeState
    from tests.test_hardening import LiveWall
    from tests.test_wall import CSRF

    state = FakeState(atx=True)
    machine = FakeKvm(state).start()
    data = tmp_path / "data"
    answers: list[Any] = []
    try:
        live = LiveWall(data, **cli.SERVER_OPTIONS)  # as the program runs it: three seconds for what is under way, then it is cut off
        with live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": machine.url, "password": "secret"}).json()["device"]["id"]
            state.slow_action = 6.0  # a KVM that answers when it has done it: typing a long text takes one far longer

            def press() -> None:
                try:
                    answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code)
                except httpx.HTTPError as ex:
                    answers.append(type(ex).__name__)

            pressing = threading.Thread(target=press)
            pressing.start()
            deadline = time.monotonic() + 5
            while "atx power_long" not in state.actions and time.monotonic() < deadline:
                time.sleep(0.02)
            # Where qKVM listens was changed in the settings, or its Tailscale address is another one: the listeners are reopened.
            live._server.should_exit = True  # what Core.request_restart does, through core.stop
            pressing.join(timeout=20)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        events = [(line["event"], line.get("action")) for line in lines]
        print("the machine got:", state.actions, "| whoever pressed was answered:", answers)
        print("audit.log:", events)
        assert any(event in ("action", "action_failed") for event, _ in events), "the power button was held on the machine, and the activity log has no line of it"
    finally:
        machine.stop()


# --- F4: an installed update is taken back for a start that failed over the disk -------------------------------


def test_an_installed_update_is_not_taken_back_because_a_write_failed_at_start(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    import shutil
    import signal

    import qkvm
    from qkvm import __main__ as starter
    from tests.test_unlock import fits
    from tests.test_wall import wait_until

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    # An update was installed from inside the app some time ago, and has been running since.
    package = data / "updates" / "9.9.9" / "qkvm"
    shutil.copytree(Path(qkvm.__file__).parent, package, ignore=shutil.ignore_patterns("__pycache__"))
    (package / "_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (data / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None}), encoding="utf-8")
    # Now it is started with --locked-start, and the settings cannot be written at that moment: here, because
    # something lies where the file being written goes. (A full disk does the same, and so does a certificate
    # that cannot be written where HTTPS is on.)
    (data / "qkvm.tmp").mkdir()
    before = signal.getsignal(signal.SIGTERM)
    try:
        status = starter.supervise(["--data-dir", str(data), "--locked-start", "--bind", "local"])
    finally:
        signal.signal(signal.SIGTERM, before)
    said = capfd.readouterr().err
    print("exit status:", status)
    print("said:", [line for line in said.splitlines() if line.startswith("qkvm:") or "Error" in line])
    print("updates/current.json still there:", (data / "updates" / "current.json").exists())
    assert (data / "updates" / "current.json").exists(), "the update was taken back, and it was the disk that would not be written to"


# --- F5: kept sign-ins that a locked start could not take away ------------------------------------------------


def test_a_sign_in_ended_while_started_locked_stays_ended_when_qkvm_is_started_as_it_comes_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from tests.test_unlock import fits, kept_sign_in, let_in
    from tests.test_wall import wait_until

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(admin)  # "keep this browser signed in for 30 days"
        admin.core.sessions.flush()  # type: ignore[attr-defined]

    held = {"on": True}
    real_unlink = os.unlink

    def unlink_what_is_not_held(path: Any, *args: Any, **kwargs: Any) -> None:
        if held["on"] and str(path).endswith("sessions.json"):
            raise PermissionError(13, "Permission denied")  # a backup program has the file open (Windows), or it is read-only
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink_what_is_not_held)
    with wall(data, locked_start=True) as locked:  # started with --locked-start, and signed in to anew
        me = locked.get("/api/v1/session").json()["user"]["id"]
        everywhere = locked.post(f"/api/v1/users/{me}/logout")
        out = locked.post("/api/v1/logout", json={"scope": "all"})
        print("sign out everywhere, started locked:", everywhere.status_code, out.status_code, out.json())
    held["on"] = False
    print("sessions.json still lies in the folder:", (data / "sessions.json").exists())
    with wall(data, sign_in=False) as later:  # started as it comes again
        back = let_in(later, cookie)
        print("the browser from before is signed in again:", back)
        assert not back, "signed out everywhere and answered as done; in again after the next start as it comes"
