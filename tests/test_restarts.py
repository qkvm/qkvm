"""Promises that have to hold over a restart of qKVM, and whatever the computer's clock does: alerts, kept sign-ins, lock-outs, pauses, the settings file."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qkvm import alerts, kvm, update, vault
from qkvm.core import Core
from qkvm.security import COOKIE, Limiter, Sessions
from qkvm.server import create_app
from tests.fake_kvm import FakeKvm
from tests.test_alerts import Inbox
from tests.test_unlock import SECRET, fits, kept_sign_in, let_in
from tests.test_wall import CSRF, PASSWORD, add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(alerts, "STARTING", 0.3)  # (two minutes, as it comes: how long a start is given to find its network)


@pytest.fixture
def inbox() -> Iterator[Inbox]:
    box = Inbox()
    yield box
    box.close()


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def written_down(core: Core, device: str, state: str) -> bool:
    """Whether the alert watcher has written the machine down as `state` (watch.json): what a start takes up again, and
    what the next change is told against. (A fixed 0.6 s for that, a busy computer had not written it yet.) Asked of the
    watcher, which keeps what it wrote last: read from the file itself, the test held it open at the moment the watcher
    replaced it, which Windows refused ("Access is denied"), and the watcher tries again only a minute later."""
    try:
        return bool(json.loads(core.watcher._written or "{}")["stable"].get(device) == state)
    except (ValueError, KeyError):
        return False


def told(inbox: Inbox, title: str) -> bool:
    return title in inbox.titles()


def state_of(client: TestClient, device: str) -> str | None:
    said = client.get("/api/v1/status").json().get(device) or {}
    return said.get("state")


# --- alerts ---------------------------------------------------------------------------------------------------


def test_a_machine_that_did_not_come_back_with_qkvm_is_told(tmp_path: Path, inbox: Inbox) -> None:
    # README: "After a restart qKVM goes on alerting by itself, as it goes on watching." The power cut is what
    # that was built for. qKVM comes back from it; one machine does not.
    data = tmp_path / "data"
    fake = FakeKvm().start()
    try:
        with wall(data) as admin:
            device = add(admin, fake.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            wait_until(lambda: fits(admin), "never made to fit")
            assert admin.get(snap(device)).status_code == 200
            wait_until(lambda: written_down(admin.core, device, "online"), "the watcher never wrote it down as online", timeout=30)  # type: ignore[attr-defined]
            assert state_of(admin, device) == "online"
        fake.stop()  # the power cut: qKVM and the machine go down together, and only qKVM comes back
        with wall(data, sign_in=False) as later:
            assert later.get("/healthz").json()["locked"] is False  # it carries on by itself, as promised
            assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200  # only to look at the state
            wait_until(lambda: state_of(later, device) == "offline", "never seen as offline", timeout=30)
            wait_until(lambda: told(inbox, "Build server is offline"), f"it was online before the restart and is offline after it, and nobody was told: {inbox.titles()}", timeout=30)
    finally:
        fake.stop()


def test_what_a_pause_held_back_is_told_after_it_although_qkvm_was_restarted_meanwhile(tmp_path: Path, inbox: Inbox) -> None:
    # README: "Pause for an hour ... sends nothing while machines are worked on, restarts included. When the pause
    # is over, what is not as it was before it is told then, so nothing that went wrong meanwhile stays unseen".
    data = tmp_path / "data"
    fake = FakeKvm().start()
    try:
        with wall(data) as admin:
            device = add(admin, fake.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            wait_until(lambda: fits(admin), "never made to fit")
            assert admin.get(snap(device)).status_code == 200
            wait_until(lambda: written_down(admin.core, device, "online"), "the watcher never wrote it down as online", timeout=30)  # type: ignore[attr-defined]
            assert admin.post("/api/v1/alerts/pause", json={"minutes": 60}).status_code == 200
            fake.state.signal = False  # goes wrong within the pause

            def held() -> bool:
                return any(e["event"] == "alert" and e.get("held") for e in admin.get("/api/v1/audit").json()["entries"])

            wait_until(held, "the change was never noticed")
        with wall(data) as later:  # restarted within the pause (an update of qKVM was part of the maintenance)
            assert later.get("/api/v1/alerts").json()["paused_until"] is not None  # the pause outlasted the restart...
            time.sleep(0.6)
            assert later.post("/api/v1/alerts/pause", json={"minutes": 0}).status_code == 200  # ...and is over now
            wait_until(lambda: told(inbox, "Build server has no video signal"), f"what went wrong within the pause was never told: {inbox.titles()}", timeout=30)
            assert state_of(later, device) == "no_signal"  # still wrong
    finally:
        fake.stop()


def test_a_change_is_told_although_the_listeners_were_reopened_meanwhile(tmp_path: Path, inbox: Inbox) -> None:
    # The listeners are re-opened, with the program running on, when the port or the addresses are changed in
    # the settings, and by themselves when an address qKVM listens on by name changes (a new lease, Tailscale
    # coming up after the computer did): cli.serve calls create_app(core) again.
    data = tmp_path / "data"
    fake = FakeKvm().start()
    try:
        core = Core(data)
        core.unlock_at_start()
        with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = add(admin, fake.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            wait_until(lambda: written_down(core, device, "online"), "the watcher never wrote it down as online", timeout=30)
            assert state_of(admin, device) == "online"
            cookie = str(admin.cookies.get(COOKIE))
        fake.state.signal = False  # while the listeners are being re-opened
        with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as again:
            again.cookies.set(COOKIE, cookie)
            wait_until(lambda: state_of(again, device) == "no_signal", "never seen without a picture", timeout=20)
            wait_until(lambda: told(inbox, "Build server has no video signal"), f"the change was never told: {inbox.titles()}", timeout=30)
    finally:
        fake.stop()


# --- the throttle ---------------------------------------------------------------------------------------------


def test_a_clock_set_back_does_not_make_the_throttle_endless(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = Limiter()
    for _ in range(Limiter.FREE):
        limiter.fail("203.0.113.9")
    assert 0 < limiter.retry_after("203.0.113.9") <= Limiter.BASE + 0.02  # (give or take what a clock can tell)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() - 365 * 86400)  # the clock was a year ahead, and is put right
    wait = limiter.retry_after("203.0.113.9")
    print(f"\nlocked out for another {wait:.0f} s ({wait / 86400:.0f} days)")
    assert wait <= Limiter.LONGEST + 0.02, "the longest lock-out there is, is fifteen minutes"


# --- sessions and the clock -----------------------------------------------------------------------------------


# --- alerts and the clock -------------------------------------------------------------------------------------


# --- the three ways of starting -------------------------------------------------------------------------------


def test_a_browser_kept_signed_in_is_not_let_in_to_a_wall_that_did_not_open(tmp_path: Path, fake: FakeKvm) -> None:
    # core.py: "Browsers that asked to be kept signed in outlast a restart, where the saved passwords open by
    # themselves after one. Where they do not, a sign-in that outlasted it would be one to a wall that shows nothing."
    # README: "Going from one way to another takes one start and one sign-in."
    data = tmp_path / "data"
    with wall(data) as admin:
        device = add(admin, fake.url)
        cookie = kept_sign_in(admin)
        wait_until(lambda: fits(admin), "never made to fit")
    with wall(data, sign_in=False, unlock_secret=SECRET) as later:  # from now on with --unlock-file
        assert later.get("/healthz").json()["locked"] is True  # the file fits from the next sign-in on
        later.cookies.set(COOKIE, cookie)
        session = later.get("/api/v1/session").json()
        status = later.get("/api/v1/status").json()
        picture = later.get(snap(device))
        print("\nkept browser: authenticated", session["authenticated"], "| status", status, "| picture", picture.status_code, picture.text[:80])
        time.sleep(1.0)
        print("still locked after the kept browser looked:", later.get("/healthz").json()["locked"], "| fits:", fits(later))
        later.cookies.clear()
        assert not let_in(later, cookie), "kept signed in to a wall that is locked: nothing asks this browser for the sign-in that would open it"


def test_a_sign_in_ends_when_its_time_is_up_whatever_the_clock_was_set_to(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions = Sessions()
    real_time, real_forward = time.time, time.monotonic
    clock, passed = {"off": 0.0}, {"by": 0.0}
    monkeypatch.setattr(time, "time", lambda: real_time() + clock["off"])
    monkeypatch.setattr(time, "monotonic", lambda: real_forward() + passed["by"])
    idle = sessions.create("203.0.113.9", remember=False, user="ab12cd34")
    kept = sessions.create("203.0.113.9", remember=True, user="ab12cd34", mark="m")
    clock["off"] = -365 * 86400.0  # the clock was a year ahead when they signed in, and is put right
    assert sessions.get(idle) is not None and sessions.get(kept) is not None  # which ends nobody's sign-in
    passed["by"] = 13 * 3600.0  # thirteen hours later, nobody having touched it
    assert sessions.get(idle) is None  # twelve idle hours are twelve hours, not a year and twelve hours
    assert sessions.get(kept) is not None
    passed["by"] = 31 * 86400.0
    assert sessions.get(kept) is None  # and thirty days are thirty days


def test_a_pause_does_not_outlast_the_clock_being_put_right(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = time.time
    clock = {"off": 365 * 86400.0}  # the clock is a year ahead (no battery, no time server yet)
    monkeypatch.setattr(time, "time", lambda: real() + clock["off"])
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/alerts/pause", json={"minutes": 60}).status_code == 200
        assert admin.get("/api/v1/alerts").json()["paused_until"] is not None
        clock["off"] = 0.0  # ...and is put right: an hour's pause would now be a year of saying nothing
        assert admin.get("/api/v1/alerts").json()["paused_until"] is None
