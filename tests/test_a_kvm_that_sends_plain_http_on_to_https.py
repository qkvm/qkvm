"""A KVM whose plain address sends everybody on to HTTPS at the same host (the owner's GL.iNet Comet Pro on a new GLKVM
firmware, 2026-11-15: nginx in front of kvmd answers http://<host> with 301 to https://<host>).

Added as http://<host>, it was refused with only "The device does not sign qKVM in (Login failed (HTTP 301))". Now the add,
and an edit, say that the KVM answers on HTTPS and offer that address (`use`, code `https_only`), as qKVM already looks for
a JetKVM's HTTPS: never followed by itself (the password would go wherever a redirect says), and never to another host.
Where the kind is found by asking (an add, an edit to another address), that is known before any password goes out.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.responses import JSONResponse

from qkvm import kvm, update, vault
from qkvm.kvm import DeviceSpec
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_wall import add, wait_until, wall

LOGIN = "POST /api/auth/login"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def secure(tmp_path: Path) -> Iterator[FakeKvm]:
    """The KVM over HTTPS, as its own certificate has it."""
    fake = FakeKvm(FakeState(), tls_dir=tmp_path / "tls").start()
    yield fake
    fake.stop()


@pytest.fixture
def front(secure: FakeKvm) -> Iterator[FakeKvm]:
    """Its plain address, at the same host (127.0.0.1), which sends every request on to the HTTPS one."""
    fake = FakeKvm(FakeState(https_at=secure.url)).start()
    yield fake
    fake.stop()


def refused_with_https(reply: Any, secure: FakeKvm) -> None:
    said = reply.json()
    assert (reply.status_code, said.get("code"), said.get("use")) == (422, "https_only", secure.url), reply.text
    assert said["message"] == f"This KVM answers on HTTPS: its plain address sends everybody to {secure.url}. To use it there, type {secure.url}"


def test_a_sign_in_sent_on_to_https_is_said_so_held_back_and_not_followed(secure: FakeKvm, front: FakeKvm) -> None:
    # (A tile with no session yet signs in with its saved password, as it did before: where that is answered by sending it on
    # to HTTPS, the tile says so, the password is not sent again at every look, and nothing goes to the HTTPS address.)
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="Comet", base_url=front.url, username="admin", password="secret"))

    async def run() -> None:
        try:
            for _ in range(3):
                said = await device._read_status()
                assert said["state"] == "error" and said["error"]["code"] == "https_only", said
                assert secure.url in said["error"]["message"]
        finally:
            await device.close()

    asyncio.run(run())
    assert front.state.asked.count(LOGIN) == 1 and secure.state.logins == 0


@pytest.mark.parametrize("kind", ["auto", "kvmd"])
def test_an_add_at_the_plain_address_says_the_kvm_answers_on_https_and_offers_that_address(tmp_path: Path, secure: FakeKvm, front: FakeKvm, kind: str) -> None:
    with wall(tmp_path / "wall") as admin:
        reply = admin.post("/api/v1/devices", json={"url": front.url, "password": "secret", "kind": kind})
        refused_with_https(reply, secure)
        assert admin.get("/api/v1/wall").json()["devices"] == []
        assert secure.state.logins == 0  # (not followed: nothing went to the HTTPS address by itself)
        assert LOGIN not in front.state.asked  # (found before the password went out, unencrypted, to the plain address)
        # The address offered, taken: added there, over HTTPS, its certificate remembered on first contact.
        added = admin.post("/api/v1/devices", json={"url": reply.json()["use"], "password": "secret"})
        assert added.status_code == 201, added.text
        assert added.json()["device"]["url"] == secure.url and added.json()["device"]["kind"] == "kvmd" and secure.state.logins == 1


def test_a_redirect_to_another_host_is_neither_followed_nor_offered(tmp_path: Path, secure: FakeKvm) -> None:
    elsewhere = secure.url.replace("127.0.0.1", "localhost")
    plain = FakeKvm(FakeState(https_at=elsewhere)).start()
    try:
        with wall(tmp_path / "wall") as admin:
            for kind in ("auto", "kvmd"):
                reply = admin.post("/api/v1/devices", json={"url": plain.url, "password": "secret", "kind": kind})
                assert reply.status_code == 422 and reply.json().get("code") != "https_only" and "use" not in reply.json(), reply.text
            assert secure.state.logins == 0
    finally:
        plain.stop()


def test_a_tile_whose_kvm_sends_its_plain_address_on_to_https_since_says_so_and_an_edit_offers_the_address(tmp_path: Path, secure: FakeKvm) -> None:
    plain = FakeKvm(FakeState()).start()  # (on the wall over plain HTTP first; HTTPS made its only way in afterwards)
    try:
        with wall(tmp_path / "wall") as admin:
            device = add(admin, plain.url, name="Comet")
            plain.state.https_at = secure.url
            # The tile says what it is, and is no machine gone: "error", not "offline" (which an alert reports as gone).
            status: dict[str, Any] = {}

            def says_so() -> bool:
                status.update(admin.get("/api/v1/status").json()[device])
                return (status.get("error") or {}).get("code") == "https_only"

            wait_until(says_so, "the tile never said that the KVM answers on HTTPS", 10)
            assert status["state"] == "error" and secure.url in status["error"]["message"]
            # An edit that keeps the address says so too, and offers it, before the saved password goes out; nothing is changed.
            signed_in = plain.state.asked.count(LOGIN)
            reply = admin.put(f"/api/v1/devices/{device}", json={"name": "Comet", "url": plain.url})
            refused_with_https(reply, secure)
            assert plain.state.asked.count(LOGIN) == signed_in and secure.state.logins == 0
            assert admin.get("/api/v1/wall").json()["devices"][0]["url"] == plain.url
            # Moved there by whoever edits it, with its password typed (nothing knows it there by itself): it is on HTTPS.
            moved = admin.put(f"/api/v1/devices/{device}", json={"name": "Comet", "url": secure.url, "password": "secret"})
            assert moved.status_code == 200, moved.text
            assert moved.json()["device"]["url"] == secure.url and secure.state.logins >= 1
    finally:
        plain.stop()


def test_a_tile_whose_kvm_sends_its_plain_address_on_to_https_is_still_renamed_when_saved_without_checking(tmp_path: Path, secure: FakeKvm) -> None:
    # (The independent review of 0.3.2, L1.) The question whether its plain address sends everybody on to HTTPS was asked at
    # every edit of a kvmd tile at a plain address, before anything else: a tile whose KVM does so since could not be given
    # another name or group, nor have its alerts turned off, while it keeps that address, saved without checking or not,
    # where 0.3.1 saved it without checking. Saved without checking, it is now, where its address, kind, certificate check,
    # user name and password stay as they are; the tile goes on saying that the KVM answers on HTTPS, and holds its sign-in
    # back.
    plain = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path / "wall") as admin:
            device = add(admin, plain.url, name="Comet")
            plain.state.https_at = secure.url
            status: dict[str, Any] = {}

            def says_so() -> bool:
                status.update(admin.get("/api/v1/status").json()[device])
                return (status.get("error") or {}).get("code") == "https_only"

            wait_until(says_so, "the tile never said that the KVM answers on HTTPS", 10)
            signed_in = plain.state.asked.count(LOGIN)
            # Checked, as every edit is: said, with the address offered, and nothing sent the plain way or changed.
            for body in ({"name": "Comet (old rack)", "url": plain.url}, {"name": "Comet", "url": plain.url, "group": "spare"}, {"name": "Comet", "url": plain.url, "alerts": False}):
                refused_with_https(admin.put(f"/api/v1/devices/{device}", json=body), secure)
            assert plain.state.asked.count(LOGIN) == signed_in
            # Anything about how it is signed in to changed is asked first, saved without checking or not: a password typed is
            # never sent the plain way to a KVM that says it answers on HTTPS, nor is the saved one under another check.
            for body in ({"name": "Comet", "url": plain.url, "password": "secret", "force": True}, {"name": "Comet", "url": plain.url, "tls": "insecure", "force": True}):
                refused_with_https(admin.put(f"/api/v1/devices/{device}", json=body), secure)
            assert plain.state.asked.count(LOGIN) == signed_in
            shown = admin.get("/api/v1/wall").json()["devices"][0]
            assert (shown["name"], shown["url"], shown["group"], shown["alerts"], shown["kind"], shown["tls"]) == ("Comet", plain.url, "", True, "kvmd", "pinned")
            # Saved without checking: renamed, given a group, its alerts off, at the address it has.
            reply = admin.put(f"/api/v1/devices/{device}", json={"name": "Comet (old rack)", "url": plain.url, "group": "spare", "alerts": False, "force": True})
            assert reply.status_code == 200, reply.text
            shown = admin.get("/api/v1/wall").json()["devices"][0]
            assert (shown["name"], shown["url"], shown["group"], shown["alerts"], shown["kind"]) == ("Comet (old rack)", plain.url, "spare", False, "kvmd")
            # The tile goes on saying so, and its sign-in is held back: not sent at every look (once at the save, as in 0.3.1).
            status.clear()
            wait_until(says_so, "the tile no longer says that the KVM answers on HTTPS", 10)
            for _ in range(5):
                admin.get("/api/v1/status")
            assert plain.state.asked.count(LOGIN) <= signed_in + 1 and secure.state.logins == 0
    finally:
        plain.stop()


def test_an_add_whose_kvm_sends_only_its_api_on_to_https_is_said_so_before_the_password_goes_out(tmp_path: Path, secure: FakeKvm) -> None:
    # (The outside review of 0.3.2, its L4.) The kind found by asking (kvmd, where nothing else answers) knew of HTTPS only where the
    # plain address sent its recognition paths on, and a web server that sends on its API alone was sent the password typed,
    # the plain way, before the add said that the KVM answers on HTTPS. The same question as for a kvmd chosen by hand is
    # asked now, without credentials, before any sign-in.
    front = FakeKvm(FakeState(https_at=secure.url))
    sent_on = front._server.config.app

    async def the_api_alone(scope: Any, receive: Any, send: Any) -> None:  # (nginx in front: the API on to HTTPS, nothing else there)
        if scope["type"] == "http" and not scope["path"].startswith("/api/"):
            await JSONResponse({}, status_code=404)(scope, receive, send)
            return
        await sent_on(scope, receive, send)

    front._server.config.app = the_api_alone
    front.start()
    try:
        with wall(tmp_path / "wall") as admin:
            for kind in ("auto", "kvmd"):
                refused_with_https(admin.post("/api/v1/devices", json={"url": front.url, "password": "secret", "kind": kind}), secure)
            assert admin.get("/api/v1/wall").json()["devices"] == []
            assert LOGIN not in front.state.asked and secure.state.logins == 0
    finally:
        front.stop()
