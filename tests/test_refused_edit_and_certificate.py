"""A refused edit of a saved action leaves no button that runs something its holder did not see; and the listeners are not reopened at every save of a setting."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from qkvm import server as server_module
from qkvm.store import Store
from tests.fake_kvm import FakeKvm
from tests.test_refused_changes import in_background
from tests.test_users import account, browser
from tests.test_wall import add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_button_that_showed_a_refused_edit_does_not_run_what_the_action_still_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # test_refused_changes.test_a_button_that_showed_a_refused_edit_does_not_run_what_the_action_became_later, without the
    # "later": the edit is refused and taken back, and the action as it stands again carries the number the refused edit
    # was shown under.
    holding, go_on = threading.Event(), threading.Event()
    real_write = Store.write
    disk = {"held": False}

    def write(self: Store, data: dict[str, Any]) -> None:
        if disk["held"]:
            holding.set()
            go_on.wait(20)
            raise OSError(28, "No space left on device")
        real_write(self, data)

    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            made = admin.post("/api/v1/actions", json={"name": "Shut down", "kind": "text", "text": "shutdown -h now", "enter": True, "danger": True})
            action = made.json()["action"]
            monkeypatch.setattr(Store, "write", write)
            disk["held"] = True
            # The admin makes something harmless of it; the disk does not take it.
            editing, edited = in_background(lambda: admin.put(f"/api/v1/actions/{action['id']}", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}))
            assert holding.wait(10)
            seen = olga.get("/api/v1/actions").json()["actions"][0]  # olga opens the list in that moment
            disk["held"] = False
            go_on.set()
            editing.join(20)
            assert edited[0].status_code == 507
            now = admin.get("/api/v1/actions").json()["actions"][0]
            ran = olga.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": action["id"], "custom_changed": seen["changed"]})
            print(f"\n[action] olga saw: {seen['name']!r} ({seen['kind']}, edit {seen['changed']}); the action is: {now['name']!r} ({now['kind']}, edit {now['changed']})")
            print(f"         she clicks what she saw: {ran.status_code}; the machine got: {fake.state.actions}")
            assert ran.status_code == 409, "the button showed a key combination; what ran was the text it had been before the refused edit"
    finally:
        fake.stop()


def test_saving_a_setting_does_not_reopen_the_listeners_every_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        core = admin.core  # type: ignore[attr-defined]
        restarts: list[bool] = []
        monkeypatch.setattr(core, "request_restart", lambda: restarts.append(True))
        # (The address need not exist on this computer to be written into a certificate.)
        monkeypatch.setattr(server_module, "resolve", lambda names: (["127.0.0.1", "fe80::1%3"], []))
        settings = {"bind": ["local", "fe80::1%3"], "port": 8787, "https": True, "interval": 2}
        first = admin.put("/api/v1/settings", json=settings)
        assert first.status_code == 200, first.text  # HTTPS switched on
        again = [admin.put("/api/v1/settings", json={**settings, "interval": 3 + number}).json() for number in range(3)]
        print("\n[https] listening on a link-local IPv6 address too; three saves that change the refresh interval only:")
        print("        restart:", [answer["restart"] for answer in again], "| fingerprints:", [first.json()["cert_fingerprint"][:8]] + [answer["cert_fingerprint"][:8] for answer in again])
        assert not any(answer["restart"] for answer in again)
