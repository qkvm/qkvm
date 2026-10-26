"""Nothing in a field of the settings file (null) means what it meant: off, no text, none.

It is not what the field is when it is not written at all. Taken for that:

* an account's `"role": null` was an admin (the field is declared with "admin"), where it had been an
  account that signs in and is then answered 500 to everything: whoever had that account's password
  gained the wall by an update. It is the least there is, a viewer.
* a token's `"kind": null` was an API token that works, where it had been no token.
* a device's `"alerts": null`, the alert settings' `"offline": null`, the server's `"update_check": null`
  were on, where they had been off (nothing is not yes): alerts sent for a machine that was to be left
  out, and GitHub asked for releases once a day.

The program writes none of these nulls. A hand does, or a script that fills the file in.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from tests.test_users import OTHER, account
from tests.test_wall import PASSWORD, add, closed_port, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def nothing_in(folder: Path, change: Any) -> None:
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads(settings_text(folder / name, encoding="utf-8"))
        change(saved)
        write_settings_text(folder / name, json.dumps(saved, indent=2), encoding="utf-8")


def test_an_account_with_nothing_for_its_role_is_no_admin(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        account(admin, "olga", "viewer")
    nothing_in(tmp_path, lambda saved: saved["users"][1].__setitem__("role", None))
    with wall(tmp_path, sign_in=False) as hers:
        signed = hers.post("/api/v1/login", json={"name": "olga", "password": OTHER})
        role = (signed.json().get("user") or {}).get("role")
        accounts, token = hers.get("/api/v1/users").status_code, hers.post("/api/v1/tokens", json={"name": "mine", "role": "operator"}).status_code
        made = hers.post("/api/v1/users", json={"name": "mallory", "role": "admin", "password": "a password of my own"}).status_code
    print(f">>> the account whose role is null: signs in {signed.status_code}, as {role!r}; lists the accounts: {accounts}; makes a token: {token}; makes an admin: {made}")
    assert (accounts, token, made) != (200, 201, 201), "an account with no role at all administers the wall"
    assert role != "admin"


def test_a_token_with_nothing_for_its_kind_is_no_token(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        key = admin.post("/api/v1/tokens", json={"name": "a script"}).json()["token"]
    nothing_in(tmp_path, lambda saved: saved["tokens"][0].__setitem__("kind", None))
    with wall(tmp_path) as admin:
        admin.cookies.clear()
        let_in = admin.get("/api/v1/wall", headers={"Authorization": f"Bearer {key}"}).status_code
    print(f">>> the token whose kind is null: {let_in}")
    assert let_in == 401, "what was no token of any kind to the build before is let in as a script's"


SWITCHES: dict[str, tuple[Any, Any]] = {
    'a device\'s "alerts"': (lambda saved: saved["devices"][0].__setitem__("alerts", None), lambda admin: admin.get("/api/v1/wall").json()["devices"][0]["alerts"]),
    'the alert settings\' "offline"': (lambda saved: saved["alerts"].__setitem__("offline", None), lambda admin: admin.get("/api/v1/alerts").json()["offline"]),
    'the server\'s "update_check"': (lambda saved: saved["server"].__setitem__("update_check", None), lambda admin: admin.get("/api/v1/update").json()["auto_check"]),
}


@pytest.mark.parametrize("what", list(SWITCHES))
def test_nothing_where_yes_or_no_belongs_is_not_yes(tmp_path: Path, what: str) -> None:
    change, asked = SWITCHES[what]
    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", alerts=False)
        assert admin.put("/api/v1/alerts", json={"enabled": False, "offline": False}).status_code == 200
        assert admin.put("/api/v1/update", json={"auto_check": False}).status_code == 200
    nothing_in(tmp_path, change)
    with wall(tmp_path, sign_in=False) as admin:
        assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        now = asked(admin)
    print(f">>> {what}: null (the build before took it for no) is now {now!r}")
    assert not now, f"{what} was off, by a null that the build before took for off, and is on after the update"
