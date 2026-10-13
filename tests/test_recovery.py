from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from qkvm.vault import new_recovery_key, tidy_recovery_key
from tests.fake_kvm import FakeKvm
from tests.test_totp import code_for, switch_on
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import CSRF, PASSWORD, add, snap, wall

NEW = "a brand new password"


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


def test_recovery_keys_are_easy_to_type_back() -> None:
    key = new_recovery_key()
    assert len(key) == 39 and key.count("-") == 7 and key != new_recovery_key()
    assert tidy_recovery_key(key.lower().replace("-", " ")) == key.replace("-", "")
    assert tidy_recovery_key("abc0-1de8") == "ABCOIDEB"  # 0, 1 and 8 are not in the alphabet: misread O, I, B


def test_a_forgotten_password_is_replaced_with_the_recovery_key(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path, sign_in=False) as client:
        assert client.get("/api/v1/session").json()["recovery"] is False
        made = client.post("/api/v1/setup", json={"password": PASSWORD}).json()
        key = made["recovery_key"]  # shown once, at setup
        device = add(client, fake.url)
        session = client.get("/api/v1/session").json()
        assert session["recovery"] is True and session["recovery_created"] > 0
        assert key.replace("-", "") not in (tmp_path / "qkvm.json").read_text()  # only a locked copy is kept

    with wall(tmp_path, sign_in=False) as client:  # some time later: restarted, and the password is forgotten
        assert client.get("/api/v1/session").json()["recovery_created"] is None  # not a detail for strangers
        wrong = client.post("/api/v1/recover", json={"recovery_key": new_recovery_key(), "new_password": NEW})
        assert (wrong.status_code, wrong.json()["code"]) == (401, "bad_recovery")
        assert client.post("/api/v1/recover", json={"recovery_key": key, "new_password": "short"}).status_code == 422
        assert client.get("/api/v1/wall").status_code == 401

        typed = key.lower().replace("-", " ")  # however it is typed back
        assert client.post("/api/v1/recover", json={"recovery_key": typed, "new_password": NEW}).status_code == 200
        assert client.get("/api/v1/wall").status_code == 401  # it sets the password; signing in is still a step
        assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 401
        assert client.post("/api/v1/login", json={"password": NEW}).status_code == 200
        assert client.get(snap(device)).status_code == 200  # the saved KVM password survived
        events = [e["event"] for e in client.get("/api/v1/audit").json()["entries"]]
    assert "recovery_failed" in events and "password_recovered" in events


def test_recovery_with_several_accounts_and_two_factor(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as admin:
        key = admin.post("/api/v1/setup", json={"password": PASSWORD}).json()["recovery_key"]
        account(admin, "victor", "viewer")
        secret = switch_on(admin, PASSWORD)
        guest = visitor(admin, 50021)
        body = {"recovery_key": key, "new_password": NEW}
        assert guest.post("/api/v1/recover", json=body).json()["code"] == "name_required"
        unknown = guest.post("/api/v1/recover", json={**body, "name": "nobody"})
        wrong = guest.post("/api/v1/recover", json={**body, "name": "admin", "recovery_key": new_recovery_key()})
        assert unknown.status_code == wrong.status_code == 401 and unknown.json() == wrong.json()  # says nothing about who exists

        assert guest.post("/api/v1/recover", json={**body, "name": "admin"}).status_code == 200
        assert admin.get("/api/v1/wall").status_code == 401  # the account was signed out everywhere
        # The second step is not skipped: the key replaces the password, not the phone.
        assert guest.post("/api/v1/login", json={"name": "admin", "password": NEW}).json()["code"] == "code_required"
        code = code_for(secret, steps_from_now=1)
        assert guest.post("/api/v1/login", json={"name": "admin", "password": NEW, "code": code}).status_code == 200
        # It works for any account, which is why only admins ever see it.
        assert guest.post("/api/v1/recover", json={**body, "name": "victor"}).status_code == 200
        assert visitor(admin, 50022).post("/api/v1/login", json={"name": "victor", "password": NEW}).status_code == 200


def test_a_new_key_replaces_the_old_one_and_only_admins_get_one(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as admin:
        old = admin.post("/api/v1/setup", json={"password": PASSWORD}).json()["recovery_key"]
        account(admin, "olga", "operator")
        operator = visitor(admin, 50023)
        assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert operator.post("/api/v1/recovery", json={"password": OTHER}).status_code == 403

        assert admin.post("/api/v1/recovery", json={"password": "not my password"}).status_code == 401
        new = admin.post("/api/v1/recovery", json={"password": PASSWORD}).json()["recovery_key"]
        assert new != old
        guest = visitor(admin, 50024)
        body = {"name": "admin", "new_password": NEW}
        assert guest.post("/api/v1/recover", json={**body, "recovery_key": old}).status_code == 401
        assert guest.post("/api/v1/recover", json={**body, "recovery_key": new}).status_code == 200


def test_wrong_keys_lock_the_address_out_like_wrong_passwords(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        client.post("/api/v1/setup", json={"password": PASSWORD})
        client.cookies.clear()
        statuses = [
            client.post("/api/v1/recover", json={"recovery_key": new_recovery_key(), "new_password": NEW}).status_code
            for _ in range(7)
        ]
    assert statuses[:5] == [401] * 5 and statuses[-1] == 429


def test_recovery_needs_no_session_but_does_need_to_come_from_the_page(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        key = client.post("/api/v1/setup", json={"password": PASSWORD}).json()["recovery_key"]
        client.cookies.clear()
        body = {"recovery_key": key, "new_password": NEW}
        headers = {name: "" for name in CSRF}  # a request some other website made the browser send
        assert client.post("/api/v1/recover", json=body, headers=headers).status_code == 403
        assert client.post("/api/v1/recover", json=body).status_code == 200


def test_a_key_or_password_that_could_not_be_saved_has_not_replaced_the_one_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The disk is full, or the settings file is held by a backup program at that moment. The answer was an
    # error, and no key was shown; but in memory the new key had already taken the old one's place, and the
    # next thing saved would have made that permanent: the key the admin has in the drawer worked no more,
    # with nobody the wiser until the day a password is forgotten.
    from qkvm.store import Store

    with wall(tmp_path) as admin:
        first = admin.post("/api/v1/recovery", json={"password": PASSWORD}).json()["recovery_key"]
        real_write = Store.write
        attempts: list[int] = []

        def full_once(self: Store, data: dict[str, object]) -> None:
            attempts.append(1)
            if len(attempts) == 1:
                raise OSError(28, "No space left on device")
            real_write(self, data)

        monkeypatch.setattr(Store, "write", full_once)
        refused = admin.post("/api/v1/recovery", json={"password": PASSWORD})
        assert refused.status_code == 507 and "recovery_key" not in refused.json() and "saved" in refused.json()["message"]
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # the disk is fine again; something else is saved
        monkeypatch.setattr(Store, "write", real_write)

        # The same for a password: an error means the old one is still the password.
        attempts.clear()
        monkeypatch.setattr(Store, "write", full_once)
        changed = admin.post("/api/v1/password", json={"current": PASSWORD, "new": OTHER})
        assert changed.status_code == 507
        monkeypatch.setattr(Store, "write", real_write)

    with wall(tmp_path, sign_in=False) as later:  # restarted, and the password forgotten
        assert later.post("/api/v1/login", json={"password": OTHER}).status_code == 401
        assert later.post("/api/v1/recover", json={"recovery_key": first, "new_password": OTHER}).status_code == 200
        assert later.post("/api/v1/login", json={"password": OTHER}).status_code == 200


def test_a_password_an_admin_set_for_somebody_and_could_not_save_is_not_their_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm.store import Store

    with wall(tmp_path) as admin:
        olga = account(admin, "olga", "operator")
        hers = browser(admin, "olga")
        real_write = Store.write
        full = [True]

        def write(self: Store, data: dict[str, object]) -> None:
            if full[0]:
                raise OSError(28, "No space left on device")
            real_write(self, data)

        monkeypatch.setattr(Store, "write", write)
        refused = admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "password": NEW})
        assert refused.status_code == 507
        assert hers.get("/api/v1/session").json()["authenticated"] is True  # and she was not signed out over it
        # The same for the other things that decide who gets in: an account made, one removed, the collector's token.
        assert admin.post("/api/v1/users", json={"name": "piet", "role": "viewer", "password": OTHER}).status_code == 507
        assert admin.delete(f"/api/v1/users/{olga}").status_code == 507
        assert admin.post("/api/v1/metrics/token").status_code == 507
        full[0] = False
        assert [u["name"] for u in admin.get("/api/v1/users").json()["users"]] == ["admin", "olga"]
        assert admin.get("/api/v1/metrics").json()["enabled"] is False
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # the disk is fine again, and something else is saved
    with wall(tmp_path, sign_in=False) as later:
        guest = visitor(later, 50031)
        assert guest.post("/api/v1/login", json={"name": "olga", "password": NEW}).status_code == 401
        assert guest.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
