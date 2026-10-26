from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from qkvm.server import required_role
from tests.fake_kvm import FakeKvm
from tests.test_wall import CSRF, PASSWORD, add, snap, wall
from tests.settings_file import settings_text

OTHER = "another long password"


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
def fake() -> Any:
    server = FakeKvm().start()
    yield server
    server.stop()


def account(admin: TestClient, name: str, role: str, **extra: Any) -> str:
    reply = admin.post("/api/v1/users", json={"name": name, "role": role, "password": OTHER, **extra})
    assert reply.status_code == 201, reply.text
    return str(reply.json()["user"]["id"])


def visitor(admin: TestClient, port: int) -> TestClient:
    """Another browser looking at the same wall, not signed in."""
    client = TestClient(admin.app, headers=CSRF, client=("127.0.0.1", port))
    client.portal = admin.portal  # the same running server, not a second one
    return client


def browser(admin: TestClient, name: str, password: str = OTHER, port: int = 50001) -> TestClient:
    """Another browser, signed in to the same wall as `name`."""
    client = visitor(admin, port)
    reply = client.post("/api/v1/login", json={"name": name, "password": password})
    assert reply.status_code == 200, reply.text
    return client


def test_each_role_can_do_what_it_should_and_no_more(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        act = f"/api/v1/devices/{device}/actions"

        viewer = browser(admin, "victor")
        assert viewer.get("/api/v1/session").json()["user"]["role"] == "viewer"
        assert viewer.get("/api/v1/wall").status_code == 200
        assert viewer.get("/api/v1/status").status_code == 200
        assert viewer.get(snap(device)).status_code == 200
        for method, path in (
            ("POST", act), ("GET", f"/api/v1/devices/{device}/wol"), ("GET", "/api/v1/actions"),
            ("GET", "/api/v1/users"), ("GET", "/api/v1/settings"), ("GET", "/api/v1/audit"), ("GET", "/api/v1/update"),
            ("DELETE", f"/api/v1/devices/{device}"), ("POST", "/api/v1/devices"), ("POST", "/api/v1/users"),
        ):  # fmt: skip
            reply = viewer.request(method, path, json={"action": "reboot"})
            assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), (method, path)

        operator = browser(admin, "olga", port=50002)
        assert operator.post(act, json={"action": "ctrl_alt_del"}).status_code == 200
        assert operator.get("/api/v1/actions").status_code == 200
        for method, path in (
            ("GET", "/api/v1/users"), ("PUT", "/api/v1/settings"), ("DELETE", f"/api/v1/devices/{device}"),
            ("POST", "/api/v1/actions"), ("GET", "/api/v1/audit"),
        ):  # fmt: skip
            assert operator.request(method, path, json={}).status_code == 403, (method, path)

        log = admin.get("/api/v1/audit").json()["entries"]
    assert fake.state.actions == ["shortcut ControlLeft,AltLeft,Delete"]
    assert next(e for e in log if e["event"] == "action")["user"] == "olga"  # the log says who did it
    assert {e["user"] for e in log if e["event"] == "login"} == {"olga", "victor"}
    assert next(e for e in log if e["event"] == "user_added")["user"] == "admin"


def test_whatever_is_not_listed_takes_an_admin() -> None:
    assert required_role("GET", "/api/v1/wall") == "viewer"
    assert required_role("GET", "/api/v1/devices/abc/snapshot") == "viewer"
    assert required_role("POST", "/api/v1/devices/abc/actions") == "operator"
    assert required_role("GET", "/api/v1/devices/abc/snapshot/../../users") == "admin"
    assert required_role("DELETE", "/api/v1/devices/abc") == "admin"
    assert required_role("GET", "/api/v1/something-added-later") == "admin"
    assert required_role("GET", "/api/something-added-later") == "admin"  # (and what has no version in its path at all)
    assert required_role("GET", "/api/v2/wall") == "admin" and required_role("GET", "/api/wall") == "admin"


def test_an_account_limited_to_some_kvms_sees_only_those(tmp_path: Path, fake: FakeKvm) -> None:
    second = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            mine, hidden = add(admin, fake.url), add(admin, second.url)
            account(admin, "olga", "operator", devices=[mine, "no-such-kvm"])
            operator = browser(admin, "olga")
            assert [d["id"] for d in operator.get("/api/v1/wall").json()["devices"]] == [mine]
            assert list(operator.get("/api/v1/status").json()) == [mine]
            assert operator.get(snap(mine)).status_code == 200
            assert operator.get(snap(hidden)).status_code == 404  # as if it did not exist
            assert operator.post(f"/api/v1/devices/{hidden}/actions", json={"action": "reboot"}).status_code == 404
            assert operator.get(f"/api/v1/devices/{hidden}/wol").status_code == 404
            listed = {u["name"]: u for u in admin.get("/api/v1/users").json()["users"]}
            assert listed["olga"]["devices"] == [mine]  # the unknown id was dropped
            assert len(admin.get("/api/v1/wall").json()["devices"]) == 2
    finally:
        second.stop()
    assert second.state.actions == []


def test_signing_in_with_several_accounts(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/session").json()["ask_name"] is False
        account(admin, "Victor", "viewer")
        assert admin.get("/api/v1/session").json()["ask_name"] is True
        guest = visitor(admin, 50003)
        assert guest.post("/api/v1/login", json={"password": OTHER}).json()["code"] == "name_required"
        wrong_name = guest.post("/api/v1/login", json={"name": "nobody", "password": OTHER})
        wrong_password = guest.post("/api/v1/login", json={"name": "victor", "password": PASSWORD})
        # Neither answer says whether the account exists.
        assert wrong_name.status_code == wrong_password.status_code == 401
        assert wrong_name.json() == wrong_password.json()
        assert guest.post("/api/v1/login", json={"name": "VICTOR", "password": OTHER}).status_code == 200  # any case
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer", "password": OTHER}).status_code == 409
        assert admin.post("/api/v1/users", json={"name": "bad name!", "role": "viewer", "password": OTHER}).status_code == 422
        assert admin.post("/api/v1/users", json={"name": "shorty", "role": "viewer", "password": "short"}).status_code == 422


def test_a_viewer_alone_can_open_the_wall_after_a_restart(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        account(admin, "victor", "viewer")
    with wall(tmp_path, sign_in=False) as client:  # restarted: the saved KVM passwords are locked again
        assert client.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200
        assert client.get(snap(device)).status_code == 200  # their password unlocked them
    assert OTHER not in settings_text(tmp_path / "qkvm.json") and PASSWORD not in settings_text(tmp_path / "qkvm.json")


def test_the_last_admin_cannot_be_lost(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        me = admin.get("/api/v1/session").json()["user"]
        other = account(admin, "olga", "operator")
        same = {"name": "admin", "role": "admin"}
        assert admin.delete(f"/api/v1/users/{me['id']}").json()["code"] == "yourself"
        assert admin.put(f"/api/v1/users/{me['id']}", json={**same, "role": "viewer"}).json()["code"] == "own_role"
        assert admin.put(f"/api/v1/users/{me['id']}", json={**same, "name": "boss"}).status_code == 200  # renaming is fine

        # A second admin may remove or demote the first, but then becomes the only one.
        assert admin.put(f"/api/v1/users/{other}", json={"name": "olga", "role": "admin"}).status_code == 200
        second = browser(admin, "olga")
        assert second.put(f"/api/v1/users/{me['id']}", json={"name": "boss", "role": "viewer"}).status_code == 200
        assert admin.get("/api/v1/users").status_code == 403  # demoted while signed in: it applies at once
        assert second.delete(f"/api/v1/users/{me['id']}").status_code == 200
        assert admin.get("/api/v1/wall").status_code == 401  # removed: signed out
        assert second.put(f"/api/v1/users/{other}", json={"name": "olga", "role": "viewer"}).json()["code"] == "own_role"


def test_passwords_can_be_changed_and_reset(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        user = account(admin, "victor", "viewer")
        viewer = browser(admin, "victor")
        second_screen = browser(admin, "victor", port=50004)

        # The viewer changes their own: needs the current one, and signs their other browsers out.
        assert viewer.post("/api/v1/password", json={"current": "wrong wrong wrong", "new": "brand new password"}).status_code == 401
        assert viewer.post("/api/v1/password", json={"current": OTHER, "new": "brand new password"}).status_code == 200
        assert viewer.get("/api/v1/wall").status_code == 200
        assert second_screen.get("/api/v1/wall").status_code == 401
        assert admin.get("/api/v1/wall").status_code == 200  # other accounts are left alone

        # An admin sets a new one without knowing the old: the account is signed out everywhere.
        reset = admin.put(f"/api/v1/users/{user}", json={"name": "victor", "role": "viewer", "password": "set by the admin"})
        assert reset.status_code == 200
        assert viewer.get("/api/v1/wall").status_code == 401
        guest = visitor(admin, 50005)
        assert guest.post("/api/v1/login", json={"name": "victor", "password": "brand new password"}).status_code == 401
        assert guest.post("/api/v1/login", json={"name": "victor", "password": "set by the admin"}).status_code == 200
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200  # unchanged


def test_forgetting_the_accounts_from_the_command_line(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url)
        account(admin, "victor", "viewer")
        admin.core.reset_password()  # type: ignore[attr-defined]
    with wall(tmp_path, sign_in=False) as client:
        assert client.get("/api/v1/session").json()["initialized"] is False
        assert client.post("/api/v1/setup", json={"name": "root", "password": PASSWORD}).status_code == 200
        assert client.get("/api/v1/session").json()["user"]["name"] == "root"
        assert [u["name"] for u in client.get("/api/v1/users").json()["users"]] == ["root"]


def test_signing_in_as_oneself_does_not_wipe_the_guesses_made_at_another_account(tmp_path: Path) -> None:
    # Somebody with an account of their own guesses at the admin's password. Each time they are one guess
    # short of being locked out they sign in as themselves; if that forgot every wrong guess from their
    # address, they could go on for ever.
    with wall(tmp_path) as admin:
        account(admin, "victor", "viewer")
        guesser = visitor(admin, 50009)
        statuses = []
        for _ in range(3):
            statuses += [guesser.post("/api/v1/login", json={"name": "admin", "password": "a wrong guess"}).status_code for _ in range(4)]
            guesser.post("/api/v1/login", json={"name": "victor", "password": OTHER})
        assert statuses[:4] == [401] * 4 and 429 in statuses[4:], statuses
        assert guesser.post("/api/v1/login", json={"name": "admin", "password": "a wrong guess"}).status_code == 429


def test_ones_own_wrong_passwords_are_forgotten_once_the_right_one_is_typed(tmp_path: Path) -> None:
    # The other half: four slips of one's own, then the right password, is not four fifths of the way to a lock.
    with wall(tmp_path) as admin:
        account(admin, "victor", "viewer")
        clumsy = visitor(admin, 50010)
        for _ in range(3):
            assert [clumsy.post("/api/v1/login", json={"name": "victor", "password": "not it"}).status_code for _ in range(4)] == [401] * 4
            assert clumsy.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200


# --- the activity log ----------------------------------------------------------------------------------


def test_nobody_can_push_what_they_did_out_of_the_activity_log(tmp_path: Path) -> None:
    # The log is of a limited size, and what falls off its end is gone. A request that every account may
    # make, costs nothing and wrote an entry each time (signing out one's other browsers, when there are
    # none) was a way to make the entries before it fall off: a few thousand of those, and what was done
    # just before is on record nowhere.
    with wall(tmp_path) as admin:
        admin.core.audit.max_bytes = 3000  # type: ignore[attr-defined]
        account(admin, "victor", "viewer")
        viewer = browser(admin, "victor")
        for _ in range(300):
            assert viewer.post("/api/v1/logout", json={"scope": "others"}).status_code == 200
        entries = admin.get("/api/v1/audit?limit=500").json()["entries"]
        assert any(entry["event"] == "user_added" for entry in entries)  # what the admin did is still there
        assert sum(entry["event"] == "logout" for entry in entries) == 0  # nothing happened, nothing is logged
        # Something that did happen is logged: the other browser of the same account is signed out.
        browser(admin, "victor", port=50002)
        assert viewer.post("/api/v1/logout", json={"scope": "others"}).status_code == 200
        newest = admin.get("/api/v1/audit").json()["entries"]
        assert [entry["scope"] for entry in newest if entry["event"] == "logout"] == ["others"]


def test_the_activity_log_keeps_what_it_is_given_and_makes_nobody_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os
    import time

    from qkvm.store import AuditLog

    # Older entries are kept in files of their own, and found again from there.
    log = AuditLog(tmp_path / "audit.log", max_bytes=1500)
    for number in range(100):
        log.write("something_done", "192.0.2.1", number=number)
    assert [entry["number"] for entry in log.tail(100)] == list(range(99, -1, -1))  # newest first, none missing
    kept = sorted(path.name for path in tmp_path.glob("audit.log*"))
    assert "audit.log" in kept and "audit.log.1" in kept and len(kept) <= 1 + AuditLog.OLD_FILES

    # A file that cannot be moved aside just now (something has it open) is written on: the entry is not lost.
    def refuses(*_: object) -> None:
        raise PermissionError("in use by another program")

    monkeypatch.setattr(os, "replace", refuses)
    log.write("after_the_file_could_not_be_moved", "192.0.2.1")
    assert log.tail(1)[0]["event"] == "after_the_file_could_not_be_moved"
    monkeypatch.undo()

    # Whoever makes an entry does not wait for the disk: it is written by a thread of its own, in order.
    slow = AuditLog(tmp_path / "slow.log")
    append = slow._append

    def slowly(line: str) -> None:
        time.sleep(0.4)
        append(line)

    slow._append = slowly  # type: ignore[method-assign]
    began = time.monotonic()
    for number in range(3):
        slow.write("made_without_waiting", "192.0.2.1", number=number)
    assert time.monotonic() - began < 0.2
    assert [entry["number"] for entry in slow.tail(10)] == [2, 1, 0]  # and reading it waits for what was just written


def test_what_only_an_admin_needs_to_know_about_a_device_is_told_to_an_admin_only(tmp_path: Path, fake: FakeKvm) -> None:
    # The wall needs a name, an address to show and a link to the console. How qKVM signs in to the device,
    # and whether its certificate is checked, is for whoever edits it: every account that may look at the
    # wall used to be handed the lot.
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        account(admin, "victor", "viewer")
        account(admin, "olga", "operator")
        full = admin.get("/api/v1/wall").json()["devices"][0]
        assert full["username"] == "admin" and full["url"] == fake.url and full["has_password"] is True and "tls" in full
        for name in ("victor", "olga"):
            told = browser(admin, name).get("/api/v1/wall").json()["devices"][0]
            assert told["id"] == device and told["name"] and told["host"] and told["open_url"]
            assert not {"username", "url", "tls", "fingerprint", "has_password", "custom_open_url"} & set(told), name
        # A console link is shown to all of them, so it is not the place for a password either.
        with_login = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "open_url": "https://admin:secret@console.example/"})
        assert with_login.status_code == 422 and "password" in with_login.json()["message"]


def test_an_account_limited_to_a_group_has_what_is_in_it_now_and_later(tmp_path: Path) -> None:
    # Limits were lists of machines, ticked one by one: a machine added to the lab next month was not on the
    # list of the colleague who looks after the lab, and nobody noticed until they needed it.
    first, second, third = FakeKvm().start(), FakeKvm().start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            lab = add(admin, first.url, name="Lab 1", group="Lab")
            office = add(admin, second.url, name="Front desk", group="Office")
            olga = account(admin, "olga", "operator", devices=[], groups=["Lab", " lab ", "Not there yet"])
            listed = {u["name"]: u for u in admin.get("/api/v1/users").json()["users"]}
            assert listed["olga"]["groups"] == ["Lab", "Not there yet"] and listed["olga"]["devices"] == []
            hers = browser(admin, "olga", port=50051)

            def sees() -> list[str]:
                return [d["name"] for d in hers.get("/api/v1/wall").json()["devices"]]

            assert sees() == ["Lab 1"]
            assert hers.get(f"/api/v1/devices/{office}/snapshot").status_code == 404
            assert hers.post(f"/api/v1/devices/{office}/actions", json={"action": "reboot"}).status_code == 404
            assert hers.post(f"/api/v1/devices/{lab}/actions", json={"action": "reboot"}).status_code == 200
            assert list(hers.get("/api/v1/status").json()) == [lab]
            # Added to the group later, it is hers without anybody ticking anything.
            add(admin, third.url, name="Lab 2", group="Lab")
            assert sees() == ["Lab 1", "Lab 2"]
            # A machine she is given by itself, on top of the group; and one that leaves the group leaves her wall.
            edit = {"name": "olga", "role": "operator", "devices": [office], "groups": ["Lab"]}
            assert admin.put(f"/api/v1/users/{olga}", json=edit).status_code == 200
            assert sees() == ["Lab 1", "Front desk", "Lab 2"]
            assert admin.put(f"/api/v1/devices/{lab}", json={"name": "Lab 1", "url": first.url, "password": "", "group": "Storage"}).status_code == 200
            assert sees() == ["Front desk", "Lab 2"]
            # "All of them" has no use for a list, and neither has an admin.
            assert admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "devices": None, "groups": ["Lab"]}).status_code == 200
            assert admin.get("/api/v1/users").json()["users"][1]["groups"] == [] and len(sees()) == 3

            # The same for a token: the machines of a group, whichever they are on the day.
            token = admin.post("/api/v1/tokens", json={"name": "lab script", "role": "viewer", "devices": [], "groups": ["Lab"]}).json()
            assert token["record"]["groups"] == ["Lab"]
            robot = TestClient(admin.app, headers={"Authorization": f"Bearer {token['token']}"}, client=("192.0.2.50", 51020))
            robot.portal = admin.portal
            assert [d["name"] for d in robot.get("/api/v1/wall").json()["devices"]] == ["Lab 2"]
    finally:
        for server in (first, second, third):
            server.stop()


def test_an_account_can_be_suspended_without_being_removed(tmp_path: Path) -> None:
    # Somebody is away for three months, or under a cloud for a week. Removing the account loses its limits
    # and its second step; changing its password is a lie about what happened.
    with wall(tmp_path) as admin:
        olga = account(admin, "olga", "operator")
        hers = browser(admin, "olga", port=50052)
        assert hers.get("/api/v1/wall").status_code == 200
        me = admin.get("/api/v1/users").json()["users"][0]["id"]
        on_hold = {"name": "olga", "role": "operator", "suspended": True}
        refused = admin.put(f"/api/v1/users/{me}", json={"name": "admin", "role": "admin", "suspended": True})
        assert (refused.status_code, refused.json()["code"]) == (409, "yourself")
        assert admin.put(f"/api/v1/users/{olga}", json=on_hold).status_code == 200
        assert admin.get("/api/v1/users").json()["users"][1]["suspended"] is True
        assert hers.get("/api/v1/wall").status_code == 401  # out at once, wherever she was signed in
        guest = visitor(admin, 50053)
        wrong = guest.post("/api/v1/login", json={"name": "olga", "password": "not her password"})
        assert (wrong.status_code, wrong.json()["code"]) == (401, "bad_password")  # told only to who knows the password
        told = guest.post("/api/v1/login", json={"name": "olga", "password": OTHER})
        assert (told.status_code, told.json()["code"]) == (403, "suspended")
        assert guest.get("/api/v1/wall").status_code == 401
        events = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] in ("user_suspended", "login_failed")]
        assert [e["event"] for e in events][-1] == "user_suspended" and events[0].get("suspended") is True

        # A second admin who is suspended is not an admin to fall back on.
        other = account(admin, "anna", "admin")
        assert admin.put(f"/api/v1/users/{other}", json={"name": "anna", "role": "admin", "suspended": True}).status_code == 200
        demote = admin.put(f"/api/v1/users/{me}", json={"name": "admin", "role": "viewer"})
        assert demote.status_code == 409

        # Lifted, everything is as it was: the same password, the same role.
        assert admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "suspended": False}).status_code == 200
        assert guest.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert guest.post("/api/v1/devices/nope/actions", json={"action": "reboot"}).status_code == 404  # an operator again
    with wall(tmp_path, sign_in=False) as later:  # and it is kept across a restart
        assert later.post("/api/v1/login", json={"name": "anna", "password": OTHER}).json()["code"] == "suspended"


def test_an_admin_can_sign_somebody_out_everywhere_without_changing_anything_else(tmp_path: Path) -> None:
    # A laptop was left on a train. Until now the way to end its session was to give the account a new password.
    with wall(tmp_path) as admin:
        olga = account(admin, "olga", "operator")
        here, there = browser(admin, "olga", port=50071), browser(admin, "olga", port=50072)
        assert here.post(f"/api/v1/users/{olga}/logout").status_code == 403  # not hers to do to herself by this door
        ended = admin.post(f"/api/v1/users/{olga}/logout")
        assert ended.status_code == 200 and ended.json()["ended"] == 2
        assert here.get("/api/v1/wall").status_code == 401 and there.get("/api/v1/wall").status_code == 401
        assert browser(admin, "olga", port=50073).get("/api/v1/wall").status_code == 200  # the same password signs her in again
        me = admin.get("/api/v1/users").json()["users"][0]["id"]
        assert admin.post(f"/api/v1/users/{me}/logout").json()["ended"] == 0 and admin.get("/api/v1/wall").status_code == 200  # not the browser asking
        assert admin.post("/api/v1/users/nobody/logout").status_code == 404
        entry = next(e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "user_signed_out" and e["account"] == "olga")
        assert entry["sessions"] == 2


def test_about_says_what_is_running_and_under_which_licences(tmp_path: Path) -> None:
    from qkvm._version import __version__

    with wall(tmp_path) as admin:
        about = admin.get("/api/v1/about").json()
        assert (about["version"], about["licence"]) == (__version__, "AGPL-3.0-only")
        assert about["python"].count(".") >= 1 and about["system"]
        by_name = {library["name"]: library for library in about["libraries"]}
        assert {"fastapi", "starlette", "uvicorn", "httpx", "websockets", "cryptography"} <= set(by_name)
        assert all(library["version"] and library["licence"] and len(library["licence"]) < 90 for library in about["libraries"])
        assert "license" not in by_name["cryptography"]["licence"].lower() or len(by_name["cryptography"]["licence"]) < 60  # a name, not the text
        # What it runs on, to the version, is for those who look after it.
        account(admin, "victor", "viewer")
        assert browser(admin, "victor", port=50081).get("/api/v1/about").json() == {"version": __version__, "licence": "AGPL-3.0-only"}


def test_a_sign_in_under_way_does_not_outlast_what_an_admin_does_to_the_account_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Checking a password takes a moment, on purpose, and is done beside everything else. An admin who
    # replaces the password in that moment, or removes or suspends the account, has signed it out everywhere:
    # the sign-in that was still being checked against what the account was must not come out signed in.
    import threading

    from qkvm.vault import Vault

    checked, go_on = threading.Event(), threading.Event()
    real_open = Vault.open

    def open_and_wait(record: Any, password: str) -> Any:
        key = real_open(record, password)
        if password == OTHER and key is not None:  # right, at this moment
            checked.set()
            go_on.wait(10)
        return key

    with wall(tmp_path) as admin:
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))
        meanwhile = {
            "olga": lambda who: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "password": "replaced by the admin"}),
            "rosa": lambda who: admin.delete(f"/api/v1/users/{who}"),
            "sam": lambda who: admin.put(f"/api/v1/users/{who}", json={"name": "sam", "role": "operator", "suspended": True}),
        }
        expected = {"olga": (401, "bad_password"), "rosa": (401, "bad_password"), "sam": (403, "suspended")}
        for port, (name, change) in enumerate(meanwhile.items(), start=50002):
            who = account(admin, name, "operator")
            checked.clear(), go_on.clear()
            late, answers = visitor(admin, port), []

            def sign_in(late: TestClient = late, name: str = name, answers: list[Any] = answers) -> None:
                answers.append(late.post("/api/v1/login", json={"name": name, "password": OTHER, "remember": True}))

            signing_in = threading.Thread(target=sign_in)
            signing_in.start()
            assert checked.wait(10), name
            changed = change(who)
            go_on.set()
            signing_in.join(10)
            assert changed.status_code == 200, name
            assert (answers[0].status_code, answers[0].json()["code"]) == expected[name], name
            assert "set-cookie" not in answers[0].headers, name
            assert late.get("/api/v1/wall").status_code == 401, name
