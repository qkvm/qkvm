"""Two things only an admin asks for wait on something slow before they are done: switching a PC's Intel AMT KVM on
or off waits on its engine (a look it lets finish first, the question which PC answers), and installing an update waits
on its download. Meanwhile the admin may be signed out everywhere, suspended, or made a viewer. What they asked for is
then not done: nothing is written to the engine, nothing is installed, and the answer says so, as for an action.
Found by the independent review of 0.2.0 (W4), with a probe that reproduced it three times of three.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import amt, kvm, update, vault
from qkvm._version import __version__
from qkvm.kvm import REJECTED
from qkvm.update import Updater
from tests.fake_amt import FakeAmt
from tests.fake_github import FakeGitHub, make_wheel
from tests.test_redfish import status_of
from tests.test_users import OTHER, account, browser
from tests.test_wall import PASSWORD, wall

SAP_ON = ("CIM_KVMRedirectionSAP", "2")
LISTENER_ON = ("AMT_RedirectionService", "ListenerEnabled=true")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(amt, "LOOK_EVERY", 0)
    monkeypatch.setattr(amt, "FOLLOW_UP", ())
    monkeypatch.setattr(amt, "HICCUP", 0)
    monkeypatch.setattr(amt, "KVM_TTL", 0)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    REJECTED.clear()


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt().start()
    machine.state.kvm, machine.state.listener = "disabled", False  # as an engine set up by hand comes
    yield machine
    machine.stop()


@pytest.fixture
def github() -> Iterator[FakeGitHub]:
    server = FakeGitHub().start()
    yield server
    server.stop()


class Held:
    """One call of `what` on `owner`, the first that `when` picks, held until the test lets it go on: the wait a slow
    engine or a slow line makes, made exact."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, owner: Any, what: str, when: Callable[..., bool]) -> None:
        self.asked, self.let_go = threading.Event(), threading.Event()
        original = getattr(owner, what)

        async def slowly(this: Any, *args: Any, **kwargs: Any) -> Any:
            if not self.asked.is_set() and when(*args, **kwargs):
                self.asked.set()
                assert await asyncio.to_thread(self.let_go.wait, 20)
            return await original(this, *args, **kwargs)

        monkeypatch.setattr(owner, what, slowly)

    def while_waiting(self, ask: Callable[[], Any], meanwhile: Callable[[], None]) -> Any:
        """`ask` is sent; while it waits at the held call, `meanwhile` is done; then it goes on, and its answer is returned."""
        with ThreadPoolExecutor(max_workers=1) as other_thread:
            pending = other_thread.submit(ask)
            try:
                assert self.asked.wait(20), "the request never came to the call that is held"
                meanwhile()
            finally:
                self.let_go.set()
            return pending.result(timeout=60)


WAYS = ["signed out everywhere", "suspended", "made a viewer", "removed"]


def ended(admin: TestClient, how: str, user: str, name: str) -> None:
    """An admin takes away the right of another admin, in one of the ways there are. (An admin is never limited to some
    machines, and a token is never an admin: those ways do not come to these two routes.)"""
    if how == "signed out everywhere":
        reply = admin.post(f"/api/v1/users/{user}/logout")
    elif how == "suspended":
        reply = admin.put(f"/api/v1/users/{user}", json={"name": name, "role": "admin", "suspended": True})
    elif how == "made a viewer":
        reply = admin.put(f"/api/v1/users/{user}", json={"name": name, "role": "viewer"})
    else:
        reply = admin.delete(f"/api/v1/users/{user}")
    assert reply.status_code == 200, reply.text


def written(admin: TestClient, *events: str) -> list[dict[str, Any]]:
    return [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] in events]


# --- a PC's KVM, switched on its engine ----------------------------------------------------------------------


def a_pc_on_the_wall(admin: TestClient, pc: FakeAmt) -> str:
    reply = admin.post("/api/v1/devices", json={"url": pc.url, "password": "secret"})
    assert reply.status_code == 201, reply.text
    device = str(reply.json()["device"]["id"])
    status_of(admin, device, state="online")
    assert pc.state.changes == []  # (a look changes nothing on the PC)
    return device


def while_the_engine_is_asked_which_pc_it_is(monkeypatch: pytest.MonkeyPatch) -> Held:
    # The question a switch asks before it writes anything (a look asks it too, but not urgently). Held here as a slow
    # engine holds it, or as a look the switch waits for behind `_quiet` would.
    return Held(monkeypatch, amt.AmtDevice, "_same_machine", lambda *args, **kwargs: kwargs.get("urgent", args[0] if args else False) is True)


@pytest.mark.parametrize("how", WAYS)
def test_a_pcs_kvm_is_not_switched_on_for_an_admin_who_lost_the_right_while_the_engine_was_asked(
    tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    with wall(tmp_path) as admin:
        device = a_pc_on_the_wall(admin, pc)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        held = while_the_engine_is_asked_which_pc_it_is(monkeypatch)
        reply = held.while_waiting(lambda: hers.post(f"/api/v1/devices/{device}/kvm", json={"on": True}), lambda: ended(admin, how, ada, "ada"))
        print(f"\n[{how}] answer: {reply.status_code} {reply.text}; changes on the engine: {pc.state.changes}")
        assert pc.state.changes == [], f"the PC's KVM was switched on for an admin who was {how} before anything was written"
        assert (pc.state.kvm, pc.state.listener) == ("disabled", False)
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text
        assert reply.json()["message"] == "It was not done: whoever asked for it may no longer do that"
        assert written(admin, "kvm_switched") == []
        (failed,) = written(admin, "kvm_switch_failed")
        assert failed["on"] is True and failed["error"] == reply.json()["message"]


def test_nor_switched_off(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    pc.state.kvm, pc.state.listener = "enabled", True
    with wall(tmp_path) as admin:
        device = a_pc_on_the_wall(admin, pc)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        held = while_the_engine_is_asked_which_pc_it_is(monkeypatch)
        reply = held.while_waiting(lambda: hers.post(f"/api/v1/devices/{device}/kvm", json={"on": False}), lambda: ended(admin, "made a viewer", ada, "ada"))
        assert pc.state.changes == [] and pc.state.kvm == "enabled", pc.state.changes
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text


def test_nor_is_the_second_half_of_a_switch_written_once_the_right_is_gone(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Taken away between the two writes: the KVM's access point was switched on while the admin still might, and the
    # redirection listener is not. What was done, and what not, is said.
    with wall(tmp_path) as admin:
        device = a_pc_on_the_wall(admin, pc)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        held = Held(monkeypatch, amt.AmtDevice, "_get", lambda resource, *args, **kwargs: resource == amt.REDIRECTION and kwargs.get("urgent") is True and pc.state.changes == [SAP_ON])
        reply = held.while_waiting(lambda: hers.post(f"/api/v1/devices/{device}/kvm", json={"on": True}), lambda: ended(admin, "made a viewer", ada, "ada"))
        assert pc.state.changes == [SAP_ON] and pc.state.listener is False, pc.state.changes
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text
        assert reply.json()["message"] == "Its KVM was switched on on the engine, and its redirection listener was not: whoever asked for it may no longer do that"
        assert written(admin, "kvm_switched") == []
        (failed,) = written(admin, "kvm_switch_failed")
        assert failed["on"] is True and failed["error"] == reply.json()["message"]


def test_an_admin_who_still_may_has_the_kvm_switched_whatever_happened_to_others_meanwhile(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # The other side of it: somebody else lost a right while the engine was asked. Nothing stops the switch.
    with wall(tmp_path) as admin:
        device = a_pc_on_the_wall(admin, pc)
        account(admin, "ada", "admin")
        other = account(admin, "otto", "admin")
        hers = browser(admin, "ada")
        held = while_the_engine_is_asked_which_pc_it_is(monkeypatch)
        reply = held.while_waiting(lambda: hers.post(f"/api/v1/devices/{device}/kvm", json={"on": True}), lambda: ended(admin, "suspended", other, "otto"))
        assert reply.status_code == 200 and reply.json() == {"ok": True}, reply.text
        assert pc.state.changes == [SAP_ON, LISTENER_ON]
        assert [entry["on"] for entry in written(admin, "kvm_switched")] == [True]


# --- an update, installed ------------------------------------------------------------------------------------


def while_the_package_downloads(monkeypatch: pytest.MonkeyPatch) -> Held:
    # The program itself, the largest of the downloads and the last: held as a slow line holds it.
    return Held(monkeypatch, Updater, "_download", lambda client, url, limit: url.endswith(".whl"))


def an_update_to_install(admin: TestClient, github: FakeGitHub, data: Path) -> Updater:
    github.publish("9.9.9", make_wheel("9.9.9"))
    assert admin.put("/api/v1/update", json={"auto_check": False}).status_code == 200  # (no check of the wall's own alongside)
    updater = Updater(data, github.repo, api=github.url, keys=(), current=__version__, allow_unsigned=True)
    admin.core.updater = updater  # type: ignore[attr-defined]
    assert admin.post("/api/v1/update/check").json()["available"] is True
    return updater


@pytest.mark.parametrize("how", WAYS)
def test_an_update_is_not_installed_for_an_admin_who_lost_the_right_while_it_downloaded(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    with wall(tmp_path) as admin:
        updater = an_update_to_install(admin, github, tmp_path)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        held = while_the_package_downloads(monkeypatch)
        reply = held.while_waiting(lambda: hers.post("/api/v1/update/install", json={"password": OTHER}), lambda: ended(admin, how, ada, "ada"))
        print(f"\n[{how}] answer: {reply.status_code} {reply.text}")
        assert not (tmp_path / "updates").exists(), f"an update was installed for an admin who was {how} while it downloaded"
        assert updater.installed is None
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text
        assert reply.json()["message"] == "It was not installed: whoever asked for it may no longer do that"
        assert written(admin, "update_installed") == []
        (failed,) = written(admin, "update_failed")
        assert failed["error"] == reply.json()["message"]
        # Nothing is left half done or under way, nor said to have failed: the admin who still may installs it.
        assert (updater.state, updater.error) == ("idle", None)
        again = admin.post("/api/v1/update/install", json={"password": PASSWORD})
        assert again.status_code == 200 and again.json()["installed"] == "9.9.9", again.text
        assert (tmp_path / "updates" / "9.9.9").is_dir()


@pytest.mark.parametrize("supervised", [True, False])
def test_an_update_written_while_the_right_was_lost_does_not_restart_the_wall_for_them(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch, supervised: bool
) -> None:
    # Taken away while the package is written (in a thread of its own, which is not stopped half way; asked just before):
    # it is installed, and takes effect at the next start, as said. The wall is not restarted for them, and they are
    # handed nothing of the update's state.
    with wall(tmp_path) as admin:
        updater = an_update_to_install(admin, github, tmp_path)
        admin.core.supervised = supervised  # type: ignore[attr-defined]  # (under a starter, the new version would run at once)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        asked, let_go = threading.Event(), threading.Event()
        original = Updater._activate

        def slowly(this: Updater, version: str, wheel: bytes) -> None:
            asked.set()
            assert let_go.wait(20)
            original(this, version, wheel)

        monkeypatch.setattr(Updater, "_activate", slowly)
        with ThreadPoolExecutor(max_workers=1) as other_thread:
            pending = other_thread.submit(lambda: hers.post("/api/v1/update/install", json={"password": OTHER}))
            try:
                assert asked.wait(20), "the package was never written"
                ended(admin, "signed out everywhere", ada, "ada")
            finally:
                let_go.set()
            reply = pending.result(timeout=60)
        # (Under a starter a restart is asked for a second after the answer: looked for three times as long. Without one there is
        # none to look for.)
        until = time.monotonic() + (3.0 if supervised else 0.0)
        while True:
            assert admin.core.exit_status is None, "the wall was restarted for an admin who was signed out while the update was written"  # type: ignore[attr-defined]
            if time.monotonic() >= until:
                break
            time.sleep(0.05)
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text
        assert "latest" not in reply.json() and "installed" not in reply.json()
        assert updater.installed == "9.9.9" and (tmp_path / "updates" / "9.9.9").is_dir()
        (entry,) = written(admin, "update_installed")
        assert entry["version"] == "9.9.9"
        if supervised:
            assert reply.json()["message"] == "It was installed, and takes effect the next time qKVM starts. qKVM was not restarted: whoever asked for it may no longer do that"
            assert entry["note"] == "not restarted: whoever asked for it may no longer do that"
        else:  # (there was no restart to hold back)
            assert reply.json()["message"] == "It was installed, and takes effect the next time qKVM starts. Whoever asked for it may not see more of it now"
            assert entry["note"] == "whoever asked for it lost the right while it was being installed"
        # What other admins are shown: installed, waiting for a restart (the page says so: test_in_a_browser).
        shown = admin.get("/api/v1/update").json()
        assert (shown["state"], shown["installed"], shown["supervised"]) == ("ready", "9.9.9", supervised)


def test_an_admin_who_still_may_has_the_update_installed_whatever_happened_to_others_meanwhile(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    with wall(tmp_path) as admin:
        updater = an_update_to_install(admin, github, tmp_path)
        account(admin, "ada", "admin")
        other = account(admin, "otto", "admin")
        hers = browser(admin, "ada")
        held = while_the_package_downloads(monkeypatch)
        reply = held.while_waiting(lambda: hers.post("/api/v1/update/install", json={"password": OTHER}), lambda: ended(admin, "made a viewer", other, "otto"))
        assert reply.status_code == 200 and reply.json()["installed"] == "9.9.9", reply.text
        assert updater.installed == "9.9.9" and (tmp_path / "updates" / "9.9.9").is_dir()
        assert len(written(admin, "update_installed")) == 1


@pytest.mark.parametrize("how", WAYS)
def test_an_update_that_fails_after_the_right_was_lost_tells_them_nothing_of_why(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # (Left open by W4's agent: the failure was answered with a 502 and the updater's words, without asking again. Those
    # words are for whoever may still ask; the activity log keeps them.)
    with wall(tmp_path) as admin:
        updater = an_update_to_install(admin, github, tmp_path)
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        real = Updater._download

        async def failing(this: Updater, client: Any, url: str, limit: int) -> bytes:
            if url.endswith(".whl"):
                raise update.UpdateError("The download failed (503)")
            return await real(this, client, url, limit)

        monkeypatch.setattr(Updater, "_download", failing)
        held = while_the_package_downloads(monkeypatch)
        reply = held.while_waiting(lambda: hers.post("/api/v1/update/install", json={"password": OTHER}), lambda: ended(admin, how, ada, "ada"))
        assert (reply.status_code, reply.json()["code"]) == (403, "stopped"), reply.text
        assert reply.json()["message"] == "It was not installed: whoever asked for it may no longer do that"
        assert "503" not in reply.text
        (failed,) = written(admin, "update_failed")
        assert failed["error"] == "The download failed (503)"
        assert updater.installed is None and updater.error == "The download failed (503)"


@pytest.mark.parametrize("failing", [True, False])
@pytest.mark.parametrize("how", WAYS)
def test_a_check_for_updates_hands_nothing_over_once_the_right_was_lost(
    tmp_path: Path, github: FakeGitHub, monkeypatch: pytest.MonkeyPatch, how: str, failing: bool
) -> None:
    # (The same for the check, which waits on GitHub: its answer, or why it failed, is for whoever may still ask.)
    with wall(tmp_path) as admin:
        github.publish("9.9.9", make_wheel("9.9.9"))
        assert admin.put("/api/v1/update", json={"auto_check": False}).status_code == 200
        updater = Updater(tmp_path, github.repo, api=github.url, keys=(), current=__version__, allow_unsigned=True)
        admin.core.updater = updater  # type: ignore[attr-defined]
        ada = account(admin, "ada", "admin")
        hers = browser(admin, "ada")
        if failing:
            async def refused(this: Updater, client: Any, url: str, limit: int) -> tuple[int, bytes]:
                raise update.UpdateError("The download came packed, which was not asked for")

            monkeypatch.setattr(Updater, "_fetch", refused)
        held = Held(monkeypatch, Updater, "_fetch", lambda client, url, limit: url.endswith("/releases/latest"))
        reply = held.while_waiting(lambda: hers.post("/api/v1/update/check"), lambda: ended(admin, how, ada, "ada"))
        assert reply.status_code in (401, 403), reply.text
        assert "packed" not in reply.text and "9.9.9" not in reply.text, reply.text
