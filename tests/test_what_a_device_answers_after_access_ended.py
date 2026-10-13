"""A device takes its time to answer. Whoever asked may be let in no longer by the time it has."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from qkvm.kvm import Snapshot
from tests.fake_kvm import FakeKvm
from tests.test_users import account, browser
from tests.test_wall import add, snap, wall

AFTERWARDS = b"a picture taken after the door was closed"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


class Held:
    """What a device is asked, held until the test lets it be answered: the wait a slow device makes, made exact."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, what: str, answer: Any) -> None:
        self.asked, self.let_go = threading.Event(), threading.Event()

        async def slowly(device: Any, *_: Any, **__: Any) -> Any:
            self.asked.set()
            assert await asyncio.to_thread(self.let_go.wait, 20)
            return answer

        monkeypatch.setattr(kvm.KvmDevice, what, slowly)

    @contextmanager
    def while_waiting(self, ask: Callable[[], Any]) -> Iterator[list[Any]]:
        """`ask` is sent, and is waiting for the device while the block runs; what it was answered is in the list afterwards."""
        answered: list[Any] = []
        with ThreadPoolExecutor(max_workers=1) as other_thread:
            pending = other_thread.submit(ask)
            try:
                assert self.asked.wait(10), "the device was never asked"
                yield answered
            finally:
                self.let_go.set()
            answered.append(pending.result(timeout=20))


def ended(admin: TestClient, how: str, user: str, device: str) -> None:
    """An admin closes the door on `user`, in one of the ways there are."""
    if how == "limited to other machines":
        reply = admin.put(f"/api/v1/users/{user}", json={"name": "vera", "role": "viewer", "devices": []})
    elif how == "suspended":
        reply = admin.put(f"/api/v1/users/{user}", json={"name": "vera", "role": "viewer", "suspended": True})
    elif how == "signed out everywhere":
        reply = admin.post(f"/api/v1/users/{user}/logout")
    elif how == "removed":
        reply = admin.delete(f"/api/v1/users/{user}")
    else:
        reply = admin.delete(f"/api/v1/devices/{device}")  # the tile itself taken off the wall
    assert reply.status_code == 200, reply.text


WAYS = ["limited to other machines", "suspended", "signed out everywhere", "removed", "the tile taken off"]


@pytest.mark.parametrize("how", WAYS)
def test_a_picture_asked_for_while_allowed_is_not_handed_over_once_it_is_not(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # The handler asked whether this account may see this machine, then waited for the device, then handed
    # over what came. An admin who took the machine from the account in between, or suspended it, or signed
    # it out everywhere, was answered "done", and the picture taken after that went out all the same: to a
    # request that would not have been let in any more. Found by an outside reviewer.
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        user = account(admin, "vera", "viewer")
        hers = browser(admin, "vera")
        assert hers.get(snap(device)).status_code == 200  # (let in, to begin with)
        held = Held(monkeypatch, "snapshot", Snapshot(AFTERWARDS, "image/jpeg", True, 0))
        with held.while_waiting(lambda: hers.get(snap(device))) as answered:
            ended(admin, how, user, device)
        (reply,) = answered
        assert reply.status_code in (401, 404), reply.status_code
        assert AFTERWARDS not in reply.content
        assert reply.status_code == (404 if how in ("limited to other machines", "the tile taken off") else 401)


@pytest.mark.parametrize("how", WAYS)
def test_nor_is_how_a_machine_is_doing(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        user = account(admin, "vera", "viewer")
        hers = browser(admin, "vera")
        assert device in hers.get("/api/v1/status").json()
        held = Held(monkeypatch, "status", {"online": True, "about": {"model": "said after the door was closed"}})
        with held.while_waiting(lambda: hers.get("/api/v1/status")) as answered:
            ended(admin, how, user, device)
        (reply,) = answered
        assert "said after the door was closed" not in reply.text
        if how in ("limited to other machines", "the tile taken off"):
            assert reply.status_code == 200 and reply.json() == {}  # still signed in, and shown nothing of it
        else:
            assert reply.status_code == 401


def test_nor_what_a_device_can_wake(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        user = account(admin, "vera", "operator")  # (what a device can wake is shown to those who may wake it)
        hers = browser(admin, "vera")
        held = Held(monkeypatch, "wol_targets", [{"name": "said after the door was closed", "mac": "00:11:22:33:44:55"}])
        with held.while_waiting(lambda: hers.get(f"/api/v1/devices/{device}/wol")) as answered:
            assert admin.put(f"/api/v1/users/{user}", json={"name": "vera", "role": "operator", "devices": []}).status_code == 200
        (reply,) = answered
        assert reply.status_code == 404 and "said after the door was closed" not in reply.text


def test_a_token_taken_back_while_its_request_waits_is_answered_nothing(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        made = admin.post("/api/v1/tokens", json={"name": "a script", "role": "viewer"}).json()
        script = TestClient(admin.app, headers={"Authorization": f"Bearer {made['token']}"}, client=("127.0.0.1", 51000))
        script.portal = admin.portal  # the same running server, not a second one
        assert script.get(snap(device)).status_code == 200
        held = Held(monkeypatch, "snapshot", Snapshot(AFTERWARDS, "image/jpeg", True, 0))
        with held.while_waiting(lambda: script.get(snap(device))) as answered:
            assert admin.delete(f"/api/v1/tokens/{made['record']['id']}").status_code == 200
        (reply,) = answered
        assert reply.status_code == 401 and AFTERWARDS not in reply.content


def test_whoever_is_still_allowed_is_handed_what_the_device_answered(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # The other side of it: nothing changed while the device took its time, or something changed for
    # somebody else. The picture is theirs.
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        account(admin, "vera", "viewer")
        other = account(admin, "otto", "viewer")
        hers = browser(admin, "vera")
        held = Held(monkeypatch, "snapshot", Snapshot(AFTERWARDS, "image/jpeg", True, 0))
        with held.while_waiting(lambda: hers.get(snap(device))) as answered:
            assert admin.put(f"/api/v1/users/{other}", json={"name": "otto", "role": "viewer", "suspended": True}).status_code == 200
        (reply,) = answered
        assert reply.status_code == 200 and reply.content == AFTERWARDS
