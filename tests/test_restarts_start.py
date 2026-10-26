"""Over a restart, continued: going from one way of starting to another, a key that cannot be read, accounts that were reset."""

from __future__ import annotations

import errno
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, kvm, unlock, update, vault
from qkvm.cli import main as run_cli
from qkvm.vault import Vault
from tests.fake_kvm import FakeKvm
from tests.test_alerts import Inbox
from tests.test_unlock import fits, kept_sign_in, let_in
from tests.test_wall import PASSWORD, add, snap, wait_until, wall
from tests.settings_file import settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


@pytest.fixture
def inbox() -> Iterator[Inbox]:
    box = Inbox()
    yield box
    box.close()


def test_reset_password_from_the_command_line_leaves_no_saved_password_in_the_folder(tmp_path: Path, fake: FakeKvm, capsys: Any) -> None:
    # README: "qkvm --reset-password forgets every account and the recovery key ... The saved KVM passwords were
    # encrypted for those accounts, so they are erased and must be entered again".
    data = tmp_path / "data"
    with wall(data) as admin:
        device = add(admin, fake.url)  # its password is "secret"
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    assert run_cli(["--data-dir", str(data), "--reset-password"]) == 0
    assert "Accounts cleared" in capsys.readouterr().out
    now = json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))
    assert now["users"] == [] and now["devices"][0]["secret"] is None and not now["unlock"] and not now["recovery"]
    found: list[tuple[str, str]] = []
    for path in sorted(p for p in data.iterdir() if p.is_file() and p.name != "qkvm.json"):
        try:
            left = json.loads(settings_text(path, encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(left, dict):
            continue
        ways = []
        if left.get("unlock") and (data / "unlock.key").exists():
            ways.append(("the key lying beside it", Vault.open(left["unlock"], (data / "unlock.key").read_text(encoding="ascii").strip())))
        for user in left.get("users") or []:
            ways.append((f"the password {user['name']} had", Vault.open(user["auth"], PASSWORD)))
        for how, key in ways:
            if key is None:
                continue
            opened = Vault()
            opened.adopt(key)
            for saved in left.get("devices") or []:
                if saved["id"] == device and saved["secret"]:
                    found.append((f"{path.name}, with {how}", opened.decrypt(saved["secret"], device)))
    print("\nread out of the data folder after --reset-password:", found)
    assert not found


def test_after_forgetting_the_accounts_alerts_are_not_said_to_be_set_up_when_they_go_nowhere(tmp_path: Path, inbox: Inbox) -> None:
    # --reset-password makes a new key for everything at the next setup. The address alerts go to was saved
    # under the old one. The devices' passwords and the saved texts are taken out for that reason; the address is not.
    data = tmp_path / "data"
    fake = FakeKvm().start()
    try:
        with wall(data) as admin:
            add(admin, fake.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            admin.core.reset_password()  # type: ignore[attr-defined]
        with wall(data) as again:  # set up anew, with the same password as it happens
            said = again.get("/api/v1/alerts").json()
            devices = again.get("/api/v1/wall").json()["devices"]
            assert again.put(f"/api/v1/devices/{devices[0]['id']}", json={"name": "Build server", "url": fake.url, "password": "secret"}).status_code == 200
            assert again.get(snap(devices[0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            time.sleep(2.0)
            logged = [(e["was"], e["state"]) for e in again.get("/api/v1/audit").json()["entries"] if e["event"] == "alert"]
            print("\nalerts page says: enabled", said["enabled"], "| has an address", said["has_webhook"], "| last error", said["last_error"])
            print("in the activity log as told:", logged, "| arrived:", inbox.titles(), "| last error now:", again.get("/api/v1/alerts").json()["last_error"])
            assert not (said["enabled"] and said["has_webhook"]) or inbox.titles(), "alerts are shown as on, with an address, and none can ever be sent"
    finally:
        fake.stop()


def test_one_start_in_which_its_key_could_not_be_read_does_not_end_carrying_on_for_good(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # README: "Carrying on after a restart: qKVM opens the saved device passwords itself at start". unlock.py:
    # "OSError: none could be kept ... and then qKVM starts as with --locked-start."
    data = tmp_path / "data"
    with wall(data) as admin:
        cookie = kept_sign_in(admin)
        wait_until(lambda: fits(admin), "never made to fit")

    def not_just_now(folder: Path) -> str:
        raise PermissionError(errno.EACCES, "Permission denied", str(folder / unlock.OWN))  # held by something else at that moment

    with monkeypatch.context() as once:
        once.setattr(unlock, "own_secret", not_just_now)
        with wall(data, sign_in=False) as hindered:
            assert hindered.get("/healthz").json()["locked"] is True  # as it should be, this once
            said = [e["event"] for e in hindered.core.audit.tail(3)]  # type: ignore[attr-defined]
    with wall(data, sign_in=False) as later:  # the next start, with nothing in its way
        locked = later.get("/healthz").json()["locked"]
        print("\nafter one start in which unlock.key could not be read: the activity log said", said, "| key still there:", (data / "unlock.key").exists(), "| locked at the next start:", locked, "| kept browser let in:", let_in(later, cookie))
        assert locked is False, "nobody asked for --locked-start, and it no longer carries on by itself"
