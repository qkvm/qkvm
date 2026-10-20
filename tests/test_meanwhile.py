"""What was checked is still true when it is acted on: an account that lost a right, a device that was edited, a wall that was locked, while a request waited for something."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, server, update, vault
from qkvm.store import Store
from qkvm.vault import Vault
from tests.fake_kvm import FakeKvm
from tests.fake_redfish import FakeBmc
from tests.test_totp import code_for, switch_on
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import CSRF, PASSWORD, add, wait_until, wall


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
    device = FakeKvm().start()
    yield device
    device.state.stall, device.state.slow_login = 0, 0
    device.state.slow.clear()
    device.stop()


def in_background(call: Any) -> tuple[threading.Thread, list[Any]]:
    """Run `call` in a thread of its own; what it returns (or raises) ends up in the list."""
    answers: list[Any] = []

    def run() -> None:
        try:
            answers.append(call())
        except BaseException as ex:
            answers.append(ex)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, answers


# --- 1: an action that is waiting for its device, and the account behind it ---------------------------------


@pytest.mark.parametrize("how", ["removed", "suspended", "limited", "viewer"])
def test_a_power_button_is_not_pressed_for_an_account_that_lost_the_right_while_the_device_was_waited_for(
    tmp_path: Path, fake: FakeKvm, how: str
) -> None:
    fake.state.atx = True
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        who = account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        assert olga.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power"}).status_code == 200
        assert fake.state.actions == ["atx power"]

        # The device has forgotten the wall's session (it restarted), and is slow to sign anybody in: the
        # wall has not sent the press yet, and will only once it is signed in again.
        fake.state.tokens.clear()
        fake.state.slow["/api/auth/login"] = 30
        asked = fake.state.requests
        pressing, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}))
        wait_until(lambda: fake.state.requests >= asked + 2, "the wall never tried to sign in to the device again")
        assert fake.state.actions == ["atx power"]  # nothing has been pressed yet

        change = {
            "removed": lambda: admin.delete(f"/api/v1/users/{who}"),
            "suspended": lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "suspended": True}),
            "limited": lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "devices": []}),
            "viewer": lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "viewer"}),
        }[how]()
        assert change.status_code == 200, change.text
        assert olga.get("/api/v1/wall").status_code in (200, 401)

        fake.state.slow.clear()
        pressing.join(20)
        print(f"\n[{how}] answer to the press: {answers[0].status_code} {answers[0].text}; the device was told: {fake.state.actions}")
        assert fake.state.actions == ["atx power"], f"held down for an account that was {how} before the wall sent it"


# --- 2: a JetKVM is typed on key by key, by the wall itself -------------------------------------------------


def test_typing_stops_when_the_account_that_typed_is_suspended(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import jetkvm
    from tests.fake_jetkvm import FakeJetKvm

    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 0.01)  # (0.004 as it comes: the whole text then takes some ten seconds here)
    jet = FakeJetKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, jet.url)
            who = account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            text = "rm -rf /srv/everything ; " * 40  # 1000 characters
            typing, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": text}))
            wait_until(lambda: len(jet.state.typed) >= 20, "nothing was typed", timeout=30)
            suspended = admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "suspended": True})
            assert suspended.status_code == 200
            at_that_moment = len(jet.state.typed)
            typing.join(120)
            print(f"\nkeys down when she was suspended: {at_that_moment}; when the wall stopped typing: {len(jet.state.typed)} of {len(text)}; answer {answers[0].status_code}")
            assert len(jet.state.typed) < at_that_moment + 20, "the wall went on typing for an account that was suspended"
    finally:
        jet.stop()


# --- 3: the pass into a server's console ---------------------------------------------------------------------


def test_no_pass_into_a_console_is_handed_to_an_account_suspended_while_the_controller_made_it_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qkvm.redfish import RedfishDevice

    made, go_on = threading.Event(), threading.Event()
    real = RedfishDevice.console

    async def console_and_wait(self: Any) -> str:
        way_in = await real(self)
        made.set()
        await asyncio.to_thread(go_on.wait, 10)  # the controller is slow to answer
        return way_in

    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            who = account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            monkeypatch.setattr(RedfishDevice, "console", console_and_wait)
            asking, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/console"))
            assert made.wait(10)
            assert admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "suspended": True}).status_code == 200
            go_on.set()
            asking.join(10)
            print(f"\nanswer to the suspended account: {answers[0].status_code} {answers[0].text}")
            assert answers[0].status_code != 200, "a pass into the server's console went to an account that was suspended"
    finally:
        bmc.stop()


# --- 4: two ways of saying who is asking, in one request ----------------------------------------------------


def test_a_request_that_was_let_in_as_an_account_does_not_go_on_as_that_account_once_it_is_removed(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A request says who is asking twice: the session cookie of an operator who may use every machine, and a
    # token that is for one machine only. It is let in as the account. While its body is on its way (the
    # sender sets the pace: up to 20 seconds) the account is removed. The guard asks again, finds the token
    # good, and lets the request go on - as the account that no longer exists, with what that account could do.
    from starlette.requests import Request

    arrived, go_on = threading.Event(), threading.Event()
    real_body = Request.body

    async def slow_body(self: Request) -> bytes:
        body = await real_body(self)
        if self.scope["path"].endswith("/actions") and not go_on.is_set():
            arrived.set()
            await asyncio.to_thread(go_on.wait, 10)  # the rest of the request takes its time to arrive
        return body

    other = FakeKvm().start()
    other.state.atx = True
    try:
        with wall(tmp_path) as admin:
            for_the_token, production = add(admin, fake.url), add(admin, other.url)
            who = account(admin, "olga", "operator")  # every machine
            token = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator", "devices": [for_the_token]}).json()["token"]
            olga = browser(admin, "olga")
            monkeypatch.setattr(Request, "body", slow_body)
            both = {"Authorization": f"Bearer {token}"}
            parked, answers = in_background(lambda: olga.post(f"/api/v1/devices/{production}/actions", json={"action": "atx_power_long"}, headers=both))
            assert arrived.wait(10)
            assert admin.delete(f"/api/v1/users/{who}").status_code == 200  # olga is gone, and signed out everywhere
            go_on.set()
            parked.join(10)
            entries = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "action"]
            print(f"\nanswer: {answers[0].status_code} {answers[0].text}; the machine the token is not for was told: {other.state.actions}; activity log: {entries[:1]}")
            # The token alone, on that machine: not there for it.
            alone = TestClient(admin.app, headers=both, client=("192.0.2.50", 51000))
            alone.portal = admin.portal
            assert alone.post(f"/api/v1/devices/{production}/actions", json={"action": "atx_power_long"}).status_code == 404
            assert other.state.actions == [], "a removed account's request was carried out on a machine its token is not for"
    finally:
        other.stop()


# --- 5: the limit on wrong codes of the second step ---------------------------------------------------------


def test_the_sixth_wrong_code_is_not_judged_however_the_guesses_are_timed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # "After five of them, from wherever they came, the second step of that account is refused." Whether the
    # account is held is looked at before a sign-in waits for its turn to be judged, and not again when the
    # turn comes. Whoever has the password sends the guesses while something else has the turn (here: a
    # request to /api/v1/recover from another address, which anybody may send and which checks a key meanwhile).
    holding, go_on = threading.Event(), threading.Event()
    real_open = Vault.open

    def open_and_wait(record: Any, password: str) -> Any:
        key = real_open(record, password)
        if password.startswith("NOTT"):  # the recovery key that was typed (tidied): not the right one
            holding.set()
            go_on.wait(20)
        return key

    with wall(tmp_path) as admin:
        who = account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        secret = switch_on(olga, OTHER)
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))

        elsewhere = TestClient(admin.app, headers=CSRF, client=("198.51.100.7", 40000))
        elsewhere.portal = admin.portal
        recovering, _ = in_background(lambda: elsewhere.post("/api/v1/recover", json={"name": "olga", "recovery_key": "NOTT-HERE-AAAA-BBBB", "new_password": "does not matter!"}))
        assert holding.wait(10)

        guesses = []
        for number in range(12):
            guesser = visitor(admin, 41000 + number)
            guesses.append(in_background(lambda guesser=guesser, number=number: guesser.post("/api/v1/login", json={"name": "olga", "password": OTHER, "code": f"{number:06d}"})))
            time.sleep(0.15)  # each has its password checked, and then waits for its turn
        # The thirteenth carries the right code. Twelve wrong ones are ahead of it.
        code = code_for(secret, steps_from_now=1)
        last = visitor(admin, 41999)
        winner = in_background(lambda: last.post("/api/v1/login", json={"name": "olga", "password": OTHER, "code": code}))
        time.sleep(0.3)
        go_on.set()
        recovering.join(20)
        for thread, _ in (*guesses, winner):
            thread.join(20)
        judged = [(answers[0].status_code, answers[0].json().get("code")) for _, answers in guesses]
        wrong = sum(1 for answer in judged if answer == (401, "bad_code"))
        print(f"\nwrong codes that were judged: {wrong} of {len(judged)}: {judged}")
        print(f"the thirteenth, with the right code: {winner[1][0].status_code} {winner[1][0].json().get('code', 'signed in')}")
        assert wrong <= 5, f"{wrong} wrong codes were judged for one account in one go, where five hold it"
        assert who


# --- 6: the limit on wrong passwords -------------------------------------------------------------------------


def test_the_sixth_wrong_password_from_one_address_is_not_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    started, go_on = threading.Event(), threading.Event()
    real_open = Vault.open
    checked: list[str] = []

    def open_and_wait(record: Any, password: str) -> Any:
        if password.startswith("guess"):
            started.set()
            go_on.wait(20)
            checked.append(password)
        return real_open(record, password)

    with wall(tmp_path) as admin:
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))
        guesses = []
        for number in range(6):
            guesser = visitor(admin, 42000 + number)  # six connections from one address
            guesses.append(in_background(lambda guesser=guesser, number=number: guesser.post("/api/v1/login", json={"password": f"guess number {number}"})))
        assert started.wait(10)
        time.sleep(0.5)  # all six are in: two being checked, four waiting for that
        go_on.set()
        for thread, _ in guesses:
            thread.join(20)
        said = [answers[0].status_code for _, answers in guesses]
        print(f"\nsix guesses sent at once from one address: {said}; passwords that were checked: {len(checked)}")
        assert len(checked) <= 5, "six wrong passwords from one address were all checked, where the fifth locks it out"


# --- 7: who the identity proxy says it is, after the session was made ----------------------------------------


def test_a_session_made_on_the_proxys_word_is_not_somebody_elses_when_the_proxy_names_another(tmp_path: Path) -> None:
    from tests.test_sso import STARTED, through_proxy

    with wall(tmp_path, **STARTED) as admin:
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "admin"}).status_code == 201
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer"}).status_code == 201
        shared = through_proxy(admin, "olga")  # a browser in the control room; olga signs in at the identity provider
        assert shared.get("/api/v1/session").json()["user"]["name"] == "olga"
        # She signs out there and goes home. Victor signs in there, in the same browser: the proxy now says "victor".
        his = {"Remote-User": "victor"}
        session = shared.get("/api/v1/session", headers=his).json()
        users = shared.get("/api/v1/users", headers=his)
        print(f"\nthe proxy says victor (a viewer); qKVM says: {session['user']['name']} ({session['user']['role']}); the list of accounts, which takes an admin: HTTP {users.status_code}")
        assert session["user"]["name"] == "victor", "the proxy names victor, and qKVM goes on treating the browser as olga"


# --- 8: first-run setup, and the round that locks up when nobody is signed in --------------------------------


def test_setting_up_a_wall_started_locked_leaves_it_open_for_whoever_set_it_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeKvm) -> None:
    # Started with --locked-start, the saved passwords are locked whenever nobody is signed in: a round every
    # half minute sees to that. Setting up makes the key first and signs in last, with two password hashes
    # and a write to disk in between (most of a second, as it comes).
    monkeypatch.setattr(server, "HOUSEKEEPING_EVERY", 0.05)
    writing, go_on = threading.Event(), threading.Event()
    real_write = Store.write

    def write_and_wait(self: Store, data: dict[str, Any]) -> None:
        real_write(self, data)
        writing.set()
        go_on.wait(10)

    with wall(tmp_path, sign_in=False, locked_start=True) as client:
        monkeypatch.setattr(Store, "write", write_and_wait)
        setting_up, answers = in_background(lambda: client.post("/api/v1/setup", json={"password": PASSWORD}))
        assert writing.wait(10)
        time.sleep(0.3)  # a housekeeping round comes by
        go_on.set()
        setting_up.join(10)
        monkeypatch.setattr(Store, "write", real_write)
        added = client.post("/api/v1/devices", json={"url": fake.url, "password": "secret"})
        print(f"\nsetup answered {answers[0].status_code}; signed in: {client.get('/api/v1/session').json()['authenticated']}; the saved passwords are open: {client.core.vault.unlocked}; adding a device: {added.status_code} {added.text}")  # type: ignore[attr-defined]
        assert answers[0].status_code == 200
        assert client.core.vault.unlocked, "whoever has just set the wall up is signed in to one that is locked"  # type: ignore[attr-defined]


# --- 9: the last sign-out locks up; a request of the same browser is still under way ------------------------


def test_what_the_last_sign_out_locked_is_not_opened_again_by_a_request_that_was_under_way(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checked, go_on = threading.Event(), threading.Event()
    real_open = Vault.open

    def open_and_wait(record: Any, password: str) -> Any:
        key = real_open(record, password)
        checked.set()
        go_on.wait(10)
        return key

    with wall(tmp_path, locked_start=True) as admin:
        core = admin.core  # type: ignore[attr-defined]
        assert core.vault.unlocked
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))
        changing, answers = in_background(lambda: admin.post("/api/v1/password", json={"current": PASSWORD, "new": "a new one, chosen in another tab"}))
        assert checked.wait(10)
        out = visitor(admin, 50009)
        out.cookies.update(admin.cookies)  # the same browser, another tab
        assert out.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        assert not core.vault.unlocked and len(core.sessions) == 0  # nobody is signed in: locked up
        go_on.set()
        changing.join(10)
        print(f"\nthe change of password, from a browser that had signed out meanwhile: {answers[0].status_code} {answers[0].text}; sessions: {len(core.sessions)}; the saved passwords are open: {core.vault.unlocked}")
        assert not core.vault.unlocked, "nobody is signed in, and the saved passwords are open again"


# --- 10: an action is under way, and somebody edits the device ---------------------------------------------


def test_an_action_that_was_carried_out_is_not_called_failed_because_its_device_was_edited_meanwhile(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.atx = True
    fake.state.slow_action = 2.0  # the device presses the button, and takes its time to say so
    with wall(tmp_path) as admin:
        device = add(admin, fake.url, name="Build server")
        account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        pressing, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power"}))
        wait_until(lambda: fake.state.actions == ["atx power"], "the button was never pressed")
        # An admin gives the tile a group in that moment. Nothing about how the device is talked to changes.
        assert admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Build server", "group": "Lab"}).status_code == 200
        pressing.join(20)
        logged = [e["event"] for e in admin.get("/api/v1/audit").json()["entries"] if e["event"].startswith("action")]
        print(f"\nthe device pressed: {fake.state.actions}; the operator was told: {answers[0].status_code} {answers[0].text}; the activity log says: {logged}")
        assert answers[0].status_code == 200 or answers[0].json()["code"] in ("timeout", "network"), "said to have failed, and offered again, though the button was pressed"


# --- 11: a long text on a JetKVM that nobody is looking at -------------------------------------------------


def test_a_long_text_is_typed_to_the_end_on_a_jetkvm_nobody_is_looking_at(tmp_path: Path) -> None:
    from tests.fake_jetkvm import FakeJetKvm, JetState

    jet = FakeJetKvm(JetState(together=0)).start()  # (each key is waited for: what arrives together is no question here)
    try:
        with wall(tmp_path) as admin:
            device = add(admin, jet.url)
            text = "0123456789" * 200  # 2000 characters, the most one action takes
            began = time.monotonic()
            reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": text})  # as a script would: no tile is asking for pictures
            print(f"\n{len(jet.state.typed)} of {len(text)} characters typed in {time.monotonic() - began:.0f} s; answer {reply.status_code} {reply.text}")
            assert (reply.status_code, len(jet.state.typed)) == (200, len(text))
    finally:
        jet.stop()
