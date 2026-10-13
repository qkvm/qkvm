"""Two things that are said, and where somebody would look for them.

* "Password right, second step asked for" (`login_code_asked`) is written so that somebody who has an
  account's password and nothing else can be seen. It is found under the activity log's "Signing in".
* "The saved address does not open any more" is said where the page shows how the last alert went. A
  save of the alert settings that leaves that address where it is (another kind of alert ticked) does
  not take the sentence away for good: it is said again at the next look.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from tests.test_totp import switch_on
from tests.test_wall import PASSWORD, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_right_password_without_its_code_is_found_under_signing_in(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        switch_on(admin, PASSWORD)
        assert admin.post("/api/v1/login", json={"password": PASSWORD}).json()["code"] == "code_required"
        found = {kind: [entry["event"] for entry in admin.get(f"/api/v1/audit?limit=500&kind={kind}").json()["entries"]] for kind in ("signin", "change")}
    print(f">>> login_code_asked is shown under 'Signing in': {'login_code_asked' in found['signin']}; under 'Changes': {'login_code_asked' in found['change']}")
    assert "login_code_asked" in found["signin"], "the one line that says somebody had the password right is not among the sign-ins"
    assert "login_code_asked" not in found["change"]


def test_the_word_about_an_address_that_does_not_open_outlasts_a_save_that_leaves_it_there(tmp_path: Path) -> None:
    settings = {"enabled": True, "format": "auto", "offline": True, "no_signal": True, "problem": True, "recovered": True}
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={**settings, "webhook": "http://127.0.0.1:9/hook"}).status_code == 200
        saved = admin.core.store.alerts.webhook  # type: ignore[attr-defined]
        admin.core.store.alerts.webhook = {"nonce": "!", "data": saved["data"]}  # type: ignore[attr-defined]  # (as a hand or a disk leaves it)
        first = admin.get("/api/v1/alerts").json()
        assert first["has_webhook"] is False and "does not open any more" in (first["last_error"] or "")
        # Somebody unticks one kind of alert and saves. No address is typed: the form says to leave it empty to keep the saved one.
        after_save = admin.put("/api/v1/alerts", json={**settings, "recovered": False}).json()
        later = admin.get("/api/v1/alerts").json()
    print(f">>> before the save: last_error={first['last_error']!r}")
    print(f">>> after a save that types no address: enabled={later['enabled']} has_webhook={later['has_webhook']} last_error={later['last_error']!r} (in the save's own answer: {after_save['last_error']!r})")
    assert later["enabled"] is True and later["has_webhook"] is False
    assert "does not open any more" in (later["last_error"] or ""), "alerts are on, the saved address still does not open, and nothing says so any more"
