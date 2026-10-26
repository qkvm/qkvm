"""What the forms let through into the records: the names of the groups an account or a token is limited to.

Every text a form takes is held to a length or a pattern, and the library that checks those refuses half
a character (a lone surrogate, written `\\ud800` in a request) on the way. Two were not: the group names
in an account's or a token's limits (`UserIn.groups`, `TokenIn.groups`).

Such a name was saved. The settings file was read back without complaint (it was "a list of texts"), and
from then on the list of accounts, or of tokens, was an error at every look, a restart later too: the page
had no way left to remove what did it. The request itself was answered 500, although the account or the
token had been made.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from qkvm.store import Store
from tests.test_wall import PASSWORD, wall
from tests.settings_file import settings_text

JSON = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def sent(body: dict[str, Any]) -> bytes:
    return json.dumps(body).encode("ascii")  # (as a script writes it: \ud800, six characters of plain text)


CASES = {
    "an account's groups": ("/api/v1/users", {"name": "olga", "role": "viewer", "password": "another long password", "devices": [], "groups": ["Rack \ud800"]}, "/api/v1/users"),
    "a token's groups": ("/api/v1/tokens", {"name": "a script", "devices": [], "groups": ["Rack \ud800"]}, "/api/v1/tokens"),
}


@pytest.mark.parametrize("what", list(CASES))
def test_half_a_character_in_a_group_name_does_not_take_the_list_away(tmp_path: Path, what: str) -> None:
    make, body, listed = CASES[what]
    with wall(tmp_path) as admin:
        made = admin.post(make, content=sent(body), headers=JSON)
        look = admin.get(listed)
        in_file = "\\ud800" in settings_text(tmp_path / "qkvm.json", encoding="utf-8")
    again = Store(tmp_path / "qkvm.json")  # (a start reads it: it is a list of texts)
    with wall(tmp_path, sign_in=False) as admin:
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        later = admin.get(listed)
        others = {path: admin.get(path).status_code for path in ("/api/v1/wall", "/api/v1/session", "/api/v1/settings")}
    print(f">>> {what}: the request was answered {made.status_code}; half a character in the settings file: {in_file}; read at the next start without complaint: {not again.restored}")
    print(f">>> GET {listed}: {look.status_code} at once, {later.status_code} after a restart; the rest of the wall: {others}")
    assert made.status_code in (201, 422), f"answered {made.status_code}, and what was asked for was {'made all the same' if in_file else 'not made'}"
    assert look.status_code == 200 and later.status_code == 200, f"GET {listed} is an error from then on ({look.status_code}, and {later.status_code} after a restart)"


def test_an_edit_of_an_account_takes_it_as_well(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        user = admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": "another long password"}).json()["user"]["id"]
        edit = admin.put(f"/api/v1/users/{user}", content=sent({"name": "olga", "role": "viewer", "devices": [], "groups": ["\ud800"]}), headers=JSON)
        look = admin.get("/api/v1/users")
    print(f">>> an edit that gives an account such a group: {edit.status_code}; the list of accounts after it: {look.status_code}")
    assert look.status_code == 200
