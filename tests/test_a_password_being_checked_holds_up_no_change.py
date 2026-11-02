"""A password or a recovery key being checked holds up nobody else's change.

The wall makes its changes one at a time (server._CHANGES, `one_change`). POST /api/v1/recover was one of them, and it
checked the recovery key, a deliberate half second of scrypt, inside that turn: anybody may send it, and twelve strangers'
guesses held an admin's change for 3.65 s in the review of 0.2.0 (web\\probe_recover_holds_the_change_lock.py); the cap of
six checks at once was only ever reached inside the turn. /password, /totp/codes, /totp/disable and /recovery checked the
account's own password inside it alike. Now the check is made beside everything else, as a sign-in's is, and the turn is
taken for the change alone, where what was checked is asked again: the account, its password, the recovery key.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from qkvm.vault import Vault, tidy_recovery_key
from tests.test_meanwhile import in_background
from tests.test_totp import switch_on
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import CSRF, PASSWORD, wall

PATIENCE = 5.0  # seconds a change may take while somebody else's check is held: it takes a moment, unheld


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class Held:
    """Every check of `password` waits, once it has begun, until the end of the `with`. What is sent meanwhile is waited
    for at the end as well, so that nothing is left asking a wall that is being stopped."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, password: str) -> None:
        self.holding, self.go_on = threading.Event(), threading.Event()
        self.threads: list[threading.Thread] = []
        real_open = Vault.open

        def open_and_wait(record: Any, typed: str) -> Any:
            if typed == password and not self.go_on.is_set():
                self.holding.set()
                self.go_on.wait(20)
            return real_open(record, typed)

        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))

    def __enter__(self) -> Held:
        return self

    def __exit__(self, kind: type[BaseException] | None, ex: BaseException | None, trace: TracebackType | None) -> None:
        self.go_on.set()
        for thread in self.threads:
            thread.join(20)

    def held(self, call: Callable[[], Any]) -> list[Any]:
        """Send the request whose check is held; wait until it is. What it is answered comes into the list, after the `with`."""
        thread, answers = in_background(call)
        self.threads.append(thread)
        assert self.holding.wait(10), "the check was never begun"
        return answers

    def meanwhile(self, call: Callable[[], Any]) -> Any:
        """Send another request while the check is held. Its answer, or None where it is still waiting after PATIENCE."""
        thread, answers = in_background(call)
        self.threads.append(thread)
        thread.join(PATIENCE)
        return answers[0] if answers and not isinstance(answers[0], BaseException) else None


def stranger(admin: TestClient, address: str) -> TestClient:
    client = TestClient(admin.app, headers=CSRF, client=(address, 40000))
    client.portal = admin.portal  # type: ignore[attr-defined]
    return client


def an_admins_change(admin: TestClient) -> Callable[[], Any]:
    return lambda: admin.post("/api/v1/actions", json={"name": "lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"})


def status(answer: Any) -> int | None:
    return None if answer is None else int(answer.status_code)


def test_a_recovery_key_being_checked_holds_up_nobody_elses_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        guess = {"name": "admin", "recovery_key": "HOLD-THIS-AAAA-BBBB", "new_password": "does not matter at all"}
        with Held(monkeypatch, tidy_recovery_key(guess["recovery_key"])) as check:
            answers = check.held(lambda: stranger(admin, "203.0.113.9").post("/api/v1/recover", json=guess))
            assert status(check.meanwhile(an_admins_change(admin))) == 201, "an admin's change waited for a stranger's recovery key to be checked"
        assert (answers[0].status_code, answers[0].json()["code"]) == (401, "bad_recovery")


@pytest.mark.parametrize(
    "path,body,role,second_step",
    [
        ("/api/v1/password", {"current": OTHER, "new": "a new password for olga"}, "operator", False),
        ("/api/v1/totp/codes", {"password": OTHER}, "operator", True),
        ("/api/v1/totp/disable", {"password": OTHER}, "operator", True),
        ("/api/v1/recovery", {"password": OTHER}, "admin", False),
    ],
)
def test_an_accounts_own_password_being_checked_holds_up_nobody_elses_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, body: dict[str, str], role: str, second_step: bool
) -> None:
    with wall(tmp_path) as admin:
        account(admin, "olga", role)
        olga = browser(admin, "olga")
        if second_step:
            switch_on(olga, OTHER)
        with Held(monkeypatch, OTHER) as check:
            answers = check.held(lambda: olga.post(path, json=body))
            assert status(check.meanwhile(an_admins_change(admin))) == 201, f"an admin's change waited for olga's password to be checked for {path}"
        assert answers[0].status_code == 200, answers[0].text


def test_a_recovery_key_replaced_while_it_was_checked_changes_no_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        key = admin.post("/api/v1/recovery", json={"password": PASSWORD}).json()["recovery_key"]
        right = {"name": "admin", "recovery_key": key, "new_password": "taken over with an old key"}
        with Held(monkeypatch, tidy_recovery_key(key)) as check:
            answers = check.held(lambda: stranger(admin, "203.0.113.10").post("/api/v1/recover", json=right))
            renewed = check.meanwhile(lambda: admin.post("/api/v1/recovery", json={"password": PASSWORD}))
            assert status(renewed) == 200, "the admin's new recovery key waited for the old one to be checked"
        assert (answers[0].status_code, answers[0].json()["code"]) == (401, "bad_recovery"), answers[0].text
        assert visitor(admin, 50070).post("/api/v1/login", json={"password": PASSWORD}).status_code == 200  # the password is as it was


def test_a_password_replaced_by_an_admin_while_the_old_one_was_checked_is_not_replaced_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        who = account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        with Held(monkeypatch, OTHER) as check:
            answers = check.held(lambda: olga.post("/api/v1/password", json={"current": OTHER, "new": "what olga chose herself"}))
            given = check.meanwhile(lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "password": "what the admin gave olga"}))
            assert status(given) == 200, "the admin's change of olga's password waited for her own to be checked"
        assert answers[0].status_code == 401, answers[0].text  # signed out everywhere by the admin's change meanwhile
        assert visitor(admin, 50071).post("/api/v1/login", json={"name": "olga", "password": "what the admin gave olga"}).status_code == 200
        assert visitor(admin, 50072).post("/api/v1/login", json={"name": "olga", "password": "what olga chose herself"}).status_code == 401


def test_new_codes_are_not_made_for_a_second_step_switched_off_while_the_password_was_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        who = account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        switch_on(olga, OTHER)
        with Held(monkeypatch, OTHER) as check:
            answers = check.held(lambda: olga.post("/api/v1/totp/codes", json={"password": OTHER}))
            lost = check.meanwhile(lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "totp_off": True}))
            assert status(lost) == 200, "the admin's change waited for olga's password to be checked"
        assert (answers[0].status_code, answers[0].json()["code"]) == (409, "not_enabled"), answers[0].text
        olga_now = next(user for user in admin.get("/api/v1/users").json()["users"] if user["name"] == "olga")
        assert olga_now["totp"] is False
