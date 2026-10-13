"""Using QKVM without a person signing in: a token for a script, and a link for a screen on the wall."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_wall import PASSWORD, add, snap, wait_until, wall

SECRET = "what-is-in-the-file-that-is-kept-somewhere-else"


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


@pytest.fixture
def pair() -> Iterator[tuple[FakeKvm, FakeKvm]]:
    one, two = FakeKvm().start(), FakeKvm().start()
    yield one, two
    one.stop()
    two.stop()


def script(admin: TestClient, token: str | None, port: int = 51000) -> TestClient:
    """Something that is not a browser: no cookie, none of the page's headers, only the token it was given."""
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    client = TestClient(admin.app, headers=headers, client=("192.0.2.50", port))
    client.portal = admin.portal
    return client


def screen(admin: TestClient, port: int) -> TestClient:
    """A browser on a wall screen, with the page loaded and nobody signed in."""
    client = TestClient(admin.app, headers={"X-QKVM": "1"}, client=("192.0.2.60", port))
    client.portal = admin.portal
    return client


def test_a_script_acts_with_a_token_of_its_own(tmp_path: Path, pair: tuple[FakeKvm, FakeKvm]) -> None:
    # "Reboot the build machines at night", "show me which are down" from a script: until now that took an
    # account's password, in the script. A token is for one job: a role, the machines it is for, an end date.
    one, two = pair
    with wall(tmp_path) as admin:
        mine, other = add(admin, one.url, name="Build server"), add(admin, two.url, name="NAS")
        assert admin.post("/api/v1/tokens", json={"name": "nightly", "role": "admin"}).status_code == 422  # never one that can do everything
        made = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator", "devices": [mine], "days": 30})
        assert made.status_code == 201, made.text
        token, record = made.json()["token"], made.json()["record"]
        assert token.startswith("qkvm_") and record["role"] == "operator" and record["devices"] == [mine]
        assert 29 * 86400 < record["expires"] - time.time() <= 30 * 86400
        listed = admin.get("/api/v1/tokens").json()["tokens"]
        assert [(t["name"], t["kind"], t["used"]) for t in listed] == [("nightly", "api", None)]
        assert token not in admin.get("/api/v1/tokens").text and token not in (tmp_path / "qkvm.json").read_text()

        robot = script(admin, token)
        assert [d["name"] for d in robot.get("/api/v1/wall").json()["devices"]] == ["Build server"]  # what it is for, no more
        assert "username" not in robot.get("/api/v1/wall").json()["devices"][0]
        wait_until(lambda: robot.get("/api/v1/status").json().get(mine, {}).get("state") == "online", "the script never saw the device")
        assert list(robot.get("/api/v1/status").json()) == [mine]
        assert robot.get(snap(mine)).status_code == 200 and robot.get(snap(other)).status_code == 404
        # It changes things without being a browser: the page's own header is not asked of it.
        assert robot.post(f"/api/v1/devices/{mine}/actions", json={"action": "reboot"}).status_code == 200
        assert one.state.actions == ["reboot"]
        assert robot.post(f"/api/v1/devices/{other}/actions", json={"action": "reboot"}).status_code == 404
        entry = admin.get("/api/v1/audit").json()["entries"][0]
        assert (entry["event"], entry["action"], entry["user"]) == ("action", "reboot", "nightly (token)")  # by whom is written down
        assert admin.get("/api/v1/tokens").json()["tokens"][0]["used"] is not None

        # What an account does for itself, and what takes an admin, it cannot do.
        for method, path, body in (
            ("GET", "/api/v1/users", None), ("GET", "/api/v1/tokens", None), ("POST", "/api/v1/tokens", {"name": "x", "role": "viewer"}),
            ("PUT", "/api/v1/security", {"require_totp": ""}), ("POST", "/api/v1/password", {"current": "x" * 12, "new": "y" * 12}),
            ("POST", "/api/v1/totp/begin", {"password": "x" * 12}), ("DELETE", f"/api/v1/devices/{mine}", None),
        ):
            assert robot.request(method, path, json=body).status_code == 403, path
        # Without a token, with a wrong one, or with the right one where a cookie is expected: nobody.
        assert script(admin, None).get("/api/v1/wall").status_code == 401
        assert script(admin, "qkvm_" + "x" * 43).get("/api/v1/wall").status_code == 401
        assert script(admin, token.upper()).get("/api/v1/wall").status_code == 401
        assert screen(admin, 51001).post("/api/v1/display", json={"key": token}).status_code == 401  # not that kind

        watcher = admin.post("/api/v1/tokens", json={"name": "status page", "role": "viewer"}).json()["token"]
        reader = script(admin, watcher, 51002)
        assert len(reader.get("/api/v1/wall").json()["devices"]) == 2  # every machine, to look at
        assert reader.post(f"/api/v1/devices/{mine}/actions", json={"action": "reboot"}).status_code == 403

        # Past its date, or withdrawn, it is nobody again.
        admin.core.store.tokens[0].expires = time.time() - 1  # type: ignore[attr-defined]
        assert robot.get("/api/v1/wall").status_code == 401
        gone = admin.get("/api/v1/tokens").json()["tokens"][1]["id"]
        assert admin.delete(f"/api/v1/tokens/{gone}").status_code == 200
        assert reader.get("/api/v1/wall").status_code == 401
        assert admin.delete(f"/api/v1/tokens/{gone}").status_code == 404


def test_a_token_reaches_nothing_while_nobody_has_unlocked_the_wall(tmp_path: Path, pair: tuple[FakeKvm, FakeKvm]) -> None:
    one, _ = pair
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        device = add(admin, one.url)
        token = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator"}).json()["token"]
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
    with wall(data, sign_in=False) as nobody:  # restarted, and no unlock file: the devices cannot be reached
        locked = script(nobody, token).get("/api/v1/wall")
        assert (locked.status_code, locked.json()["code"]) == (503, "locked")
    with wall(data, sign_in=False, unlock_secret=SECRET) as nobody:  # a script runs at night, when nobody signs in
        assert nobody.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert nobody.post("/api/v1/logout", json={}).status_code == 200
        wait_until(lambda: nobody.core.store.unlock is not None, "never made to fit again")  # type: ignore[attr-defined]
    with wall(data, sign_in=False, unlock_secret=SECRET) as nobody:
        robot = script(nobody, token)
        assert robot.get("/api/v1/wall").status_code == 200
        assert robot.post(f"/api/v1/devices/{device}/actions", json={"action": "reboot"}).status_code == 200


def test_a_screen_on_the_wall_stays_on_across_restarts_with_a_link_of_its_own(tmp_path: Path, pair: tuple[FakeKvm, FakeKvm]) -> None:
    # A wall screen was a viewer account "kept signed in": for thirty days, and until QKVM restarted, after
    # which somebody had to stand at the screen with a keyboard. A display link is opened there once.
    one, two = pair
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        lobby, other = add(admin, one.url, name="Lobby"), add(admin, two.url, name="Lab")
        made = admin.post("/api/v1/tokens", json={"name": "screen in the hall", "kind": "display", "role": "operator", "devices": [lobby]})
        assert made.status_code == 201 and made.json()["record"]["role"] == "viewer"  # a screen looks, whatever was asked for
        key, shown = made.json()["token"], made.json()["record"]["id"]

        wall_screen = screen(admin, 51010)
        assert wall_screen.post("/api/v1/display", json={"key": "qkvm_" + "x" * 43}).status_code == 401
        opened = wall_screen.post("/api/v1/display", json={"key": key})
        assert opened.status_code == 200 and opened.json()["user"] == {
            "id": f"token:{shown}", "name": "screen in the hall (token)", "role": "viewer", "totp": False, "must_enroll": False,
            "recovery_codes": 0, "token": True, "sso": False,
        }
        assert "httponly" in opened.headers["set-cookie"].lower()
        assert [d["name"] for d in wall_screen.get("/api/v1/wall").json()["devices"]] == ["Lobby"]
        assert wall_screen.get(snap(lobby)).status_code == 200 and wall_screen.get(snap(other)).status_code == 404
        assert wall_screen.post(f"/api/v1/devices/{lobby}/actions", json={"action": "reboot"}).status_code == 403
        assert wall_screen.post("/api/v1/password", json={"current": "x" * 12, "new": "y" * 12}).status_code == 403
        assert script(admin, key, 51011).get("/api/v1/wall").status_code == 401  # a link for a browser, not a token for a script
        # A rule that everybody has two-factor sign-in is about accounts: a screen has no phone.
        assert admin.get("/api/v1/session").json()["user"]["token"] is False
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]

    with wall(data, sign_in=False, unlock_secret=SECRET) as restarted:  # the power was out; nobody is in yet
        wall_screen = screen(restarted, 51012)
        assert wall_screen.get("/api/v1/wall").status_code == 401  # the session it had is gone with the restart
        assert wall_screen.post("/api/v1/display", json={"key": key}).status_code == 200  # and the page asks for another
        wait_until(lambda: wall_screen.get("/api/v1/status").json().get(lobby, {}).get("state") == "online", "the screen shows nothing")
        assert wall_screen.get(snap(lobby)).status_code == 200

        # Taken back by an admin, it is off at once: on the screen that is showing, and for whoever kept the link.
        assert restarted.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert restarted.delete(f"/api/v1/tokens/{shown}").status_code == 200
        assert wall_screen.get("/api/v1/wall").status_code == 401
        assert wall_screen.post("/api/v1/display", json={"key": key}).status_code == 401
        events = [e["event"] for e in restarted.get("/api/v1/audit").json()["entries"]]
        assert {"token_created", "token_removed", "display_opened"} <= set(events)


def test_a_token_cannot_fill_the_activity_log_or_the_memory(tmp_path: Path, pair: tuple[FakeKvm, FakeKvm]) -> None:
    one, _ = pair
    with wall(tmp_path) as admin:
        add(admin, one.url)
        token = admin.post("/api/v1/tokens", json={"name": "status page", "role": "viewer"}).json()["token"]
        key = admin.post("/api/v1/tokens", json={"name": "screen", "kind": "display"}).json()["token"]
        core = admin.core  # type: ignore[attr-defined]
        written = len(core.audit.tail(10_000))
        robot = script(admin, token)
        # Signing out is for a browser. A script has nothing to sign out of, and each try used to be written down.
        assert [robot.post("/api/v1/logout", json={}).status_code for _ in range(20)] == [403] * 20
        assert len(core.audit.tail(10_000)) == written

        wall_screen = screen(admin, 51030)
        assert wall_screen.post("/api/v1/display", json={"key": key}).status_code == 200
        sessions, written = len(core.sessions), len(core.audit.tail(10_000))
        for _ in range(30):  # the page of a screen that is on asks again now and then: it is the same screen
            assert wall_screen.post("/api/v1/display", json={"key": key}).status_code == 200
        assert len(core.sessions) == sessions and len(core.audit.tail(10_000)) == written
        # Whoever has the link and calls without end gets no more than a handful of sessions out of it, and a line now and then.
        for port in range(51100, 51160):
            assert screen(admin, port).post("/api/v1/display", json={"key": key}).status_code == 200
        assert len(core.sessions) <= sessions + 10 and len(core.audit.tail(10_000)) <= written + 2
        assert wall_screen.get("/api/v1/wall").status_code in (200, 401)  # (the oldest of them may have given way)


def test_a_token_is_not_handed_what_is_saved_for_people(tmp_path: Path, pair: tuple[FakeKvm, FakeKvm]) -> None:
    # A saved text is typed on a machine by whoever may run it there, and can then be read off its screen. An
    # operator may; a token made for one machine would have had every saved passphrase with it.
    one, _ = pair
    with wall(tmp_path) as admin:
        device = add(admin, one.url)
        typed = admin.post("/api/v1/actions", json={"name": "Unlock the disk", "kind": "text", "text": "the passphrase of another machine"}).json()["action"]
        keys = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
        token = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator", "devices": [device]}).json()["token"]
        robot = script(admin, token)
        act = f"/api/v1/devices/{device}/actions"
        refused = robot.post(act, json={"action": "custom", "custom_id": typed["id"]})
        assert (refused.status_code, refused.json()["code"]) == (403, "not_allowed")
        assert one.state.actions == []
        assert robot.post(act, json={"action": "custom", "custom_id": keys["id"]}).status_code == 200  # keys are not a secret
        assert robot.post(act, json={"action": "text", "text": "its own text"}).status_code == 200  # and what it brings itself is its own
        assert robot.post(f"/api/v1/devices/{device}/console").status_code == 403  # a way into a console is for a person's browser
        assert admin.post(act, json={"action": "custom", "custom_id": typed["id"]}).status_code == 200  # a person may, as before
