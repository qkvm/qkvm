"""What is saved sealed is nothing, or something: never something that reads as nothing."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, store, update, vault
from qkvm.store import ActionRecord, AlertSettings, DeviceRecord, UserRecord
from tests.fake_kvm import FakeKvm
from tests.test_wall import add, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


NEITHER = [False, 0, [], {}, True, 7, "text", ["x"], {"a": 1}, None]


@pytest.mark.parametrize("value", NEITHER, ids=repr)
def test_an_action_whose_text_is_not_there_types_nothing_and_presses_nothing(tmp_path: Path, fake: FakeKvm, value: Any) -> None:
    # A saved action that types a text and presses Enter after it. Its sealed text damaged in the settings
    # file to `false`, 0, an empty list or record (a slip of a hand, or of a script) read as "no text": the
    # action typed nothing and pressed Enter, and whatever stood at that machine's prompt was sent off.
    # Found by an outside reviewer, on a JetKVM. An action that types has a text, or is not run.
    folder = tmp_path / "wall"
    with wall(folder) as admin:
        device = add(admin, fake.url)
        made = admin.post("/api/v1/actions", json={"name": "Restart the spooler", "kind": "text", "text": "net stop spooler", "enter": True})
        assert made.status_code == 201, made.text
        action = made.json()["action"]["id"]
        ran = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": action})
        assert ran.status_code == 200 and fake.state.actions == ["type 'net stop spooler\\n'"], (ran.text, fake.state.actions)
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads(settings_text(folder / name, encoding="utf-8"))
        saved["actions"][0]["secret"] = value
        write_settings_text(folder / name, json.dumps(saved), encoding="utf-8")
    fake.state.actions.clear()
    with wall(folder) as admin:
        assert not admin.core.store.restored  # type: ignore[attr-defined]  # (no reason not to start, or to go back a copy)
        reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": action})
        assert reply.status_code == 409 and reply.json()["code"] == "no_text", reply.text
        assert fake.state.actions == []  # no key, Enter included
        # It is still in the list, to be opened and typed again; and the wall is there.
        assert [each["name"] for each in admin.get("/api/v1/actions").json()["actions"]] == ["Restart the spooler"]
        assert admin.get("/api/v1/wall").status_code == 200


def test_what_is_saved_sealed_is_nothing_or_something_whatever_the_file_made_of_it() -> None:
    # The same asked where the file is read, for all four of the kind: a device's password, a text to type,
    # the address alerts go to, the key of a second step. Nothing saved is null and stays null; a sealed one
    # stays as it is; anything else is kept as something that opens with no key, and is never "none saved".
    sealed = {"nonce": "AAAA", "data": "BBBB"}
    for make, name in (
        (lambda value: DeviceRecord(id="ab12cd34", name="A KVM", url="https://192.168.1.20", secret=value), "secret"),
        (lambda value: ActionRecord(id="ab12cd35", name="Types", kind="text", secret=value), "secret"),
        (lambda value: AlertSettings(webhook=value), "webhook"),
        (lambda value: UserRecord(id="admin", name="admin", totp=value), "totp"),
    ):
        for value in (False, 0, [], {}, True, 7, "text", ["x"]):
            record = make(value)
            store._as_declared(record, "this one")
            kept = getattr(record, name)
            assert isinstance(kept, dict) and kept and kept != sealed, (name, value, kept)
        nothing, something = make(None), make(dict(sealed))
        store._as_declared(nothing, "this one")
        store._as_declared(something, "this one")
        assert getattr(nothing, name) is None and getattr(something, name) == sealed


def test_a_devices_password_that_is_neither_is_not_no_password(tmp_path: Path, fake: FakeKvm) -> None:
    # (What the wall then says of it is what it says of one that is damaged in any other way: saved, and does
    # not open. The device is not signed in to with an empty password as if none had ever been given.)
    folder = tmp_path / "wall"
    with wall(folder) as admin:
        device = add(admin, fake.url)
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads(settings_text(folder / name, encoding="utf-8"))
        saved["devices"][0]["secret"] = False
        write_settings_text(folder / name, json.dumps(saved), encoding="utf-8")
    with wall(folder) as admin:
        shown = next(each for each in admin.get("/api/v1/wall").json()["devices"] if each["id"] == device)
        assert shown["has_password"] is True
        assert isinstance(admin.core.store.device(device).secret, dict)  # type: ignore[attr-defined]


def test_a_text_that_is_sealed_as_it_should_be_and_opens_to_no_text_at_all(tmp_path: Path) -> None:
    # (The second half of the rule: no form saves an empty text, and one that opens to that is not typed
    # either. Without it, the Enter that follows was all that was sent. Held by nothing until a reviewer
    # took that half out and every test passed.)
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            action = admin.post("/api/v1/actions", json={"name": "Types", "kind": "text", "text": "abc", "enter": True}).json()["action"]["id"]
            record = next(saved for saved in admin.core.store.actions if saved.id == action)  # type: ignore[attr-defined]
            record.secret = admin.core.vault.encrypt("", f"action:{action}")  # type: ignore[attr-defined]
            before = list(fake.state.actions)
            reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": action})
            assert reply.status_code == 409 and reply.json()["code"] == "no_text", reply.text
            assert fake.state.actions == before  # nothing was typed, and no Enter pressed
    finally:
        fake.stop()
