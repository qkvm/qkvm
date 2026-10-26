"""What a saved secret that does not open must not turn into.

* A device whose saved password does not open is sent no sign-in at all (not an empty password, which
  a controller counts as a wrong one and locks its account for): its tile says that none is saved.
* A second step whose key does not open lets nobody in: not with a code, not without one, and the
  answer sets no cookie. A one-time code that was handed out still signs in (the way back in from the page).
* A saved text that does not open is not typed as nothing, with its Enter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_totp import code_for
from tests.test_wall import PASSWORD, add, snap, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_device_whose_saved_password_does_not_open_is_sent_no_sign_in(tmp_path: Path) -> None:
    device = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            tile = add(admin, device.url)
            assert admin.get(snap(tile)).status_code == 200
        saved = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))
        saved["devices"][0]["secret"]["nonce"] = "!"
        write_settings_text(tmp_path / "qkvm.json", json.dumps(saved), encoding="utf-8")
        device.state.tokens.clear()  # (the device has forgotten who was signed in, as after its restart)
        before = device.state.logins
        with wall(tmp_path) as admin:
            for _ in range(10):
                state = admin.get("/api/v1/status").json()[tile]
                picture = admin.get(snap(tile))
            ran = admin.post(f"/api/v1/devices/{tile}/actions", json={"action": "ctrl_alt_del"})
        print(f">>> ten looks and an action at a device whose password does not open: {device.state.logins - before} sign-ins sent to it; its tile: {state['state']} {state['error']}; a picture: {picture.status_code}; the action: {ran.status_code}")
        assert device.state.logins == before, "a sign-in was sent to the device without its password"
        assert state["state"] == "auth" and state["error"]["code"] == "no_password"
        assert ran.status_code != 200 and device.state.actions == []
    finally:
        device.stop()


def test_a_second_step_that_does_not_open_lets_nobody_in_but_a_one_time_code_does(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        begun = admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()
        enabled = admin.post("/api/v1/totp/enable", json={"code": code_for(begun["secret"])}).json()
        codes = enabled["recovery_codes"]
        user = admin.core.store.users[0]  # type: ignore[attr-defined]
        user.totp = {"nonce": "!", "data": user.totp["data"]}
        assert admin.post("/api/v1/logout", json={}).status_code == 200
        for body in ({"password": PASSWORD}, {"password": PASSWORD, "code": code_for(begun["secret"])}, {"password": PASSWORD, "code": "000000"}):
            answer = admin.post("/api/v1/login", json=body)
            assert answer.status_code in (401, 409) and "set-cookie" not in answer.headers, answer.text
            assert admin.get("/api/v1/wall").status_code == 401
        way_back = admin.post("/api/v1/login", json={"password": PASSWORD, "code": codes[0]})
        assert way_back.status_code == 200 and admin.get("/api/v1/wall").status_code == 200
        assert admin.post("/api/v1/logout", json={}).status_code == 200
        assert admin.post("/api/v1/login", json={"password": PASSWORD, "code": codes[0]}).status_code == 409  # used up: once


def test_the_way_out_the_answer_names_works_on_a_key_that_does_not_open(tmp_path: Path) -> None:
    from qkvm.cli import main as run_cli

    with wall(tmp_path) as admin:
        begun = admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()
        assert admin.post("/api/v1/totp/enable", json={"code": code_for(begun["secret"])}).status_code == 200
    saved = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))
    saved["users"][0]["totp"]["nonce"] = "!"
    write_settings_text(tmp_path / "qkvm.json", json.dumps(saved), encoding="utf-8")
    with wall(tmp_path, sign_in=False) as visitor:
        refused = visitor.post("/api/v1/login", json={"password": PASSWORD, "code": code_for(begun["secret"])})
        assert (refused.status_code, refused.json()["code"]) == (409, "no_second_step")
    assert run_cli(["--data-dir", str(tmp_path), "--disable-2fa", "admin"]) == 0  # (with qKVM stopped: it says so otherwise)
    with wall(tmp_path, sign_in=False) as visitor:
        assert visitor.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200


def test_a_saved_text_that_does_not_open_types_nothing_and_presses_no_enter(tmp_path: Path) -> None:
    device = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            tile = add(admin, device.url)
            action = admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "THE-PASSPHRASE", "enter": True}).json()["action"]
            saved = admin.core.store.actions[0]  # type: ignore[attr-defined]
            saved.secret = {"nonce": "AAAA", "data": saved.secret["data"]}
            ran = admin.post(f"/api/v1/devices/{tile}/actions", json={"action": "custom", "custom_id": action["id"]})
            assert ran.status_code == 409 and device.state.actions == [], (ran.text, device.state.actions)
            # ...and the way out the answer names works: the text typed again in an edit.
            assert admin.put(f"/api/v1/actions/{action['id']}", json={"name": "Unlock disk", "kind": "text", "text": "THE-PASSPHRASE", "enter": True}).status_code == 200
            assert admin.post(f"/api/v1/devices/{tile}/actions", json={"action": "custom", "custom_id": action["id"]}).status_code == 200
    finally:
        device.stop()
