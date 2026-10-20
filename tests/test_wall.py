from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from qkvm.core import Core
from qkvm.netbind import BindError, normalize, resolve
from qkvm.security import Limiter, host_allowed
from qkvm.server import create_app
from qkvm.store import InstanceLock, Store, StoreError, device_url
from qkvm.tlscert import ensure_certificate
from tests import fake_kvm
from tests.fake_kvm import FakeKvm, FakeState

PASSWORD = "correct horse battery"
CSRF = {"X-QKVM": "1"}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)  # real cost is ~0.5 s per password check
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)  # tests want the real status, not "connecting"
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")  # tests never ask the real GitHub for releases


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


@contextmanager
def wall(data: Path, *, sign_in: bool = True, address: str = "127.0.0.1", **options: Any) -> Iterator[TestClient]:
    """A browser talking to a freshly started wall process that keeps its state in `data`. `options`: how it was started."""
    core = Core(data, **options)
    core.unlock_at_start()  # as the program does before it serves anybody
    with TestClient(create_app(core), headers=CSRF, client=(address, 50000)) as client:
        client.core = core  # type: ignore[attr-defined]
        if sign_in:
            path = "/api/v1/login" if core.initialized else "/api/v1/setup"
            assert client.post(path, json={"password": PASSWORD}).status_code == 200
        yield client


def add(client: TestClient, url: str, **extra: Any) -> str:
    reply = client.post("/api/v1/devices", json={"url": url, "password": "secret", **extra})
    assert reply.status_code == 201, reply.text
    return str(reply.json()["device"]["id"])


def snap(device_id: str) -> str:
    return f"/api/v1/devices/{device_id}/snapshot"


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until(condition: Any, message: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, message
        time.sleep(0.05)


# --- setup, login, sessions ---------------------------------------------------


def test_first_run_setup_then_login(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        assert client.get("/api/v1/session").json()["initialized"] is False
        assert client.get("/api/v1/wall").status_code == 401
        assert client.post("/api/v1/setup", json={"password": "too short"}).status_code == 422

        reply = client.post("/api/v1/setup", json={"password": PASSWORD})
        assert reply.status_code == 200
        cookie = reply.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
        # Made to carry on by itself after a restart, which is done beside the sign-in and takes a moment:
        # whether it is done yet when the next request arrives is up to the machine, so it is waited for.
        wait_until(lambda: client.core.store.unlock is not None, "qKVM's own key was never made to fit")  # type: ignore[attr-defined]
        session = client.get("/api/v1/session").json()
        account = session.pop("user")
        assert session.pop("recovery") is True and session.pop("recovery_created") > 0  # setup made the recovery key
        assert session == {
            "initialized": True, "authenticated": True, "ask_name": False, "setup_code_required": False, "min_password": 10,
            "unlocks_at_start": True,
        }  # fmt: skip
        assert (account["name"], account["role"]) == ("admin", "admin")  # the first account runs everything
        assert client.get("/api/v1/wall").json() == {"interval": 1.0, "live": 2, "devices": []}
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 409

    with wall(tmp_path, sign_in=False) as client:  # the wall was restarted
        assert client.get("/api/v1/wall").status_code == 401
        assert client.post("/api/v1/login", json={"password": "not the password"}).status_code == 401
        assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert client.get("/api/v1/wall").status_code == 200


def test_setting_up_from_another_machine_takes_a_password_and_nothing_else(tmp_path: Path) -> None:
    # The first-run page of a wall just installed on a small server asked for a setup code: a step no other
    # program of this kind has, met by the first person who installed one. The rule since: the default is an
    # install in three easy steps. A code printed where qKVM runs was asked of everybody who set it up from
    # another computer, which is everybody who installs it on a server. It is asked where qKVM was started
    # with --setup-code, and nowhere else.
    with wall(tmp_path, sign_in=False, address="192.168.1.50") as client:
        assert client.core.setup_code is None  # type: ignore[attr-defined]
        assert client.get("/api/v1/session").json()["setup_code_required"] is False
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        assert client.get("/api/v1/wall").status_code == 200


def test_started_with_the_option_setup_from_another_machine_needs_the_code(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False, address="192.168.1.50", setup_code=True) as client:
        code = client.core.setup_code  # type: ignore[attr-defined]
        assert code is not None and len(code) == 8
        assert client.get("/api/v1/session").json()["setup_code_required"] is True
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 403
        assert client.post("/api/v1/setup", json={"password": PASSWORD, "setup_code": "00000000"}).status_code == 403
        assert client.post("/api/v1/setup", json={"password": PASSWORD, "setup_code": code}).status_code == 200


def test_setup_through_a_local_proxy_needs_the_code_too(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False, setup_code=True) as client:
        proxied = {"X-Forwarded-For": "203.0.113.7"}
        assert client.get("/api/v1/session", headers=proxied).json()["setup_code_required"] is True
        assert client.post("/api/v1/setup", json={"password": PASSWORD}, headers=proxied).status_code == 403


def test_wrong_passwords_lock_the_address_out(tmp_path: Path) -> None:
    with wall(tmp_path) as client:
        client.post("/api/v1/logout", json={"scope": "this"})
        wrong = [client.post("/api/v1/login", json={"password": "guess"}).status_code for _ in range(Limiter.FREE)]
        assert wrong == [401] * Limiter.FREE
        locked = client.post("/api/v1/login", json={"password": PASSWORD})  # even the right one has to wait now
        assert locked.status_code == 429
        assert 0 < int(locked.headers["retry-after"]) <= Limiter.BASE


def test_logout_locks_the_vault(tmp_path: Path) -> None:
    # Where qKVM is started locked. As it comes it keeps a key of its own and goes on watching (see test_unlock.py).
    with wall(tmp_path, locked_start=True) as client:
        core = client.core  # type: ignore[attr-defined]
        assert core.vault.unlocked
        assert client.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        assert not core.vault.unlocked
        assert client.get("/api/v1/wall").status_code == 401


def test_change_password(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.post("/api/v1/password", json={"current": "wrong one", "new": "a brand new password"}).status_code == 401
        assert client.post("/api/v1/password", json={"current": PASSWORD, "new": "short"}).status_code == 422
        assert client.post("/api/v1/password", json={"current": PASSWORD, "new": "a brand new password"}).status_code == 200
        assert client.get(snap(device)).status_code == 200  # still signed in, still unlocked

    with wall(tmp_path, sign_in=False) as client:
        assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 401
        assert client.post("/api/v1/login", json={"password": "a brand new password"}).status_code == 200
        assert client.get(snap(device)).status_code == 200  # the KVM password survived the re-key


def test_reset_password_erases_the_saved_kvm_passwords(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
    Core(tmp_path).reset_password()
    with wall(tmp_path) as client:  # runs setup again
        assert client.get("/api/v1/wall").json()["devices"][0]["has_password"] is False
        assert client.get(snap(device)).json()["code"] == "no_password"


# --- request checks ----------------------------------------------------------


def test_changes_need_to_come_from_the_wall_page(tmp_path: Path) -> None:
    with wall(tmp_path) as client:
        body = {"scope": "this"}
        assert client.post("/api/v1/logout", json=body, headers={"X-QKVM": ""}).status_code == 403
        assert client.post("/api/v1/logout", json=body, headers={"Origin": "http://evil.example"}).status_code == 403
        assert client.post("/api/v1/logout", json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.get("/api/v1/wall").status_code == 200  # none of those signed us out


def test_security_headers_and_assets(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "script-src 'self'" in page.headers["content-security-policy"]
        assert "unsafe-inline" not in page.headers["content-security-policy"]
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["x-content-type-options"] == "nosniff"
        assert "<style" not in page.text and "onclick=" not in page.text  # nothing the policy would block
        assert client.get("/static/app.js").headers["content-type"].startswith("text/javascript")
        assert client.get("/static/app.css").status_code == 200
        assert client.get("/static/server.py").status_code == 404
        assert client.get("/static/index.html").status_code == 404  # the page is served at / only
        etag = page.headers["etag"]
        assert client.get("/", headers={"If-None-Match": etag}).status_code == 304
        assert client.get("/api/v1/session").headers["cache-control"] == "no-store"


def test_the_api_has_its_version_in_its_path_and_the_health_check_says_which(tmp_path: Path) -> None:
    # What a script or another program is written against is /api/v1/...: a change that would break it gets
    # a path of its own beside this one. Nothing is served under /api/ without a version, to anybody.
    with wall(tmp_path) as admin:
        assert admin.get("/healthz").json()["api"] == ["v1"]
        assert admin.get("/api/v1/session").json()["authenticated"] is True
        for path in ("/api/session", "/api/wall", "/api/status", "/api/v2/wall", "/api/v1", "/api/", "/api/v1/"):
            assert admin.get(path).status_code == 404, path
        assert admin.post("/api/login", json={"password": PASSWORD}).status_code == 404
        assert admin.post("/api/v1/logout", json={}).status_code == 200
        # Not signed in: the same request is answered as any other that needs a sign-in, and never as a sign-in page.
        for path in ("/api/session", "/api/wall", "/api/v2/wall"):
            reply = admin.get(path)
            assert reply.status_code in (401, 404) and reply.headers["content-type"].startswith("application/json"), path
        assert admin.post("/api/login", json={"password": PASSWORD}).status_code in (401, 404)
        assert admin.get("/api/v1/session").json()["authenticated"] is False  # (and the old path signed nobody in)


def test_health_check_needs_no_login(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        assert client.get("/healthz").json()["status"] == "ok"


def test_oversized_and_unsized_requests_are_refused(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False) as client:
        huge = client.post("/api/v1/login", json={"password": "x" * 100_000})
        assert huge.status_code == 413

        def endless():
            yield b'{"password": "'

        assert client.post("/api/v1/login", content=endless()).status_code == 411


def test_a_bug_in_a_handler_is_contained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as client:
        monkeypatch.setattr(client.core.activity, "read", lambda asked, limit: 1 / 0)  # type: ignore[attr-defined]
        broken = client.get("/api/v1/audit")
        assert broken.status_code == 500
        assert broken.json() == {"code": "internal", "message": "Something went wrong inside qKVM. The details are in its log."}
        assert "x-frame-options" in broken.headers
        assert client.get("/api/v1/wall").status_code == 200  # still serving


def test_unknown_dns_names_are_refused(tmp_path: Path) -> None:
    assert host_allowed("127.0.0.1:8787")
    assert host_allowed("100.101.102.103:8787")
    assert host_allowed("[::1]:8787")
    assert host_allowed("localhost:8787")
    assert host_allowed("desk.tail1234.ts.net:8787")
    assert host_allowed("wall.example.com", extra=("wall.example.com",))
    assert not host_allowed("evil.example.com:8787")
    assert not host_allowed("")
    with wall(tmp_path, sign_in=False) as client:
        assert client.get("/api/v1/session", headers={"host": "evil.example.com"}).status_code == 400
        assert client.get("/api/v1/session", headers={"host": "127.0.0.1:8787"}).status_code == 200


def test_a_crafted_host_header_cannot_pass_a_request_off_as_a_public_one(tmp_path: Path) -> None:
    # The address a request "seems" to have is built from its Host header. A header with a path in
    # it once made the sign-in check look at /static/... while the request went to /api/...
    crafted = ("127.0.0.1:8787/static/x?", "127.0.0.1/healthz#", "127.0.0.1:8787/?", "127.0.0.1/api/v1/login?", "127.0.0.1 x")
    for header in crafted:
        assert not host_allowed(header), header
    with wall(tmp_path) as admin:
        stranger = TestClient(admin.app, headers=CSRF, client=("10.0.0.9", 50030))
        stranger.portal = admin.portal  # type: ignore[attr-defined]
        new_admin = {"name": "mallory", "role": "admin", "password": "long enough password"}
        for header in crafted:
            for path in ("/api/v1/audit", "/api/v1/settings", "/api/v1/users", "/api/v1/wall"):
                assert stranger.get(path, headers={"host": header}).status_code == 400, (header, path)
            assert stranger.post("/api/v1/users", json=new_admin, headers={"host": header}).status_code == 400
        assert [u["name"] for u in admin.get("/api/v1/users").json()["users"]] == ["admin"]


def test_the_sign_in_check_looks_at_the_path_that_is_served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Even if such a header got past the host check, what decides is the path the request is routed by.
    from qkvm import server

    monkeypatch.setattr(server, "host_allowed", lambda host, extra=(): True)
    with wall(tmp_path) as admin:
        stranger = TestClient(admin.app, headers=CSRF, client=("10.0.0.9", 50031))
        stranger.portal = admin.portal  # type: ignore[attr-defined]
        header = {"host": "127.0.0.1:8787/static/x?"}
        assert stranger.get("/api/v1/audit", headers=header).status_code == 401
        new_admin = {"name": "mallory", "role": "admin", "password": "long enough password"}
        assert stranger.post("/api/v1/users", json=new_admin, headers=header).status_code == 401
        assert [u["name"] for u in admin.get("/api/v1/users").json()["users"]] == ["admin"]


# --- devices -------------------------------------------------------------------


def test_add_edit_remove_device(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.hostname = "rack-kvm"
    fake.state.password = kvm_password = "kvm-pass-9471"
    with wall(tmp_path) as client:
        rejected = client.post("/api/v1/devices", json={"url": fake.url, "password": "wrong"})
        assert rejected.status_code == 422
        assert rejected.json()["code"] == "auth_failed"
        assert client.get("/api/v1/wall").json()["devices"] == []

        created = client.post("/api/v1/devices", json={"url": fake.url + "/#/", "password": kvm_password})
        assert created.status_code == 201
        device = created.json()["device"]
        assert created.json()["about"] == {"model": "RM10", "version": "V1.10.1 release2", "hostname": "rack-kvm"}
        assert device["name"] == "rack-kvm"
        assert device["url"] == fake.url
        assert device["has_password"] is True
        assert kvm_password not in created.text
        saved = (tmp_path / "qkvm.json").read_text(encoding="utf-8")
        assert kvm_password not in saved and PASSWORD not in saved
        assert client.post("/api/v1/devices", json={"url": fake.url, "password": kvm_password}).status_code == 409
        assert client.get(snap(device["id"])).status_code == 200

        edit = {"name": "Rack 1", "url": fake.url, "username": "admin", "password": ""}
        renamed = client.put(f"/api/v1/devices/{device['id']}", json=edit)
        assert renamed.status_code == 200
        assert renamed.json()["device"]["name"] == "Rack 1"
        assert client.get(snap(device["id"])).status_code == 200  # empty password kept the saved one

        assert client.put(f"/api/v1/devices/{device['id']}", json={**edit, "password": "wrong"}).status_code == 422
        assert client.get(snap(device["id"])).status_code == 200  # the failed edit changed nothing

        assert client.delete(f"/api/v1/devices/{device['id']}").status_code == 200
        assert client.get("/api/v1/wall").json()["devices"] == []
        assert client.get(snap(device["id"])).status_code == 404
        events = [entry["event"] for entry in client.get("/api/v1/audit").json()["entries"]]
        assert events[:3] == ["device_removed", "device_changed", "device_added"]


def test_unreachable_device_can_be_added_anyway(tmp_path: Path) -> None:
    url = f"http://127.0.0.1:{closed_port()}"
    with wall(tmp_path) as client:
        refused = client.post("/api/v1/devices", json={"url": url, "password": "secret"})
        assert refused.status_code == 422
        assert refused.json()["code"] == "unreachable"
        device = add(client, url, force=True)
        assert client.get("/api/v1/wall").json()["devices"][0]["name"] == url.removeprefix("http://")
        assert client.get("/api/v1/status").json()[device]["state"] == "offline"
        assert client.post("/api/v1/devices", json={"url": "not a url!", "password": "x"}).status_code == 422


def test_saved_passwords_survive_a_restart_but_need_a_login(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
    with wall(tmp_path, sign_in=False) as client:
        assert client.get(snap(device)).status_code == 401
        assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert client.get(snap(device)).status_code == 200


def test_snapshot_is_proxied_with_one_login(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        thumb = client.get(snap(device))
        medium = client.get(snap(device), params={"w": 700})  # a tile 700 px wide gets the next size up
        large = client.get(snap(device), params={"w": 1100})  # beyond the largest: the frame as captured
        assert client.get(snap(device), params={"w": 0}).status_code == 422
    assert thumb.status_code == 200
    assert thumb.headers["content-type"] == "image/png"
    assert thumb.headers["x-kvm-signal"] == "1"
    assert thumb.content.startswith(b"\x89PNG")
    assert medium.status_code == large.status_code == 200
    assert fake.state.logins == 1  # the login that checked the device when it was added is reused
    assert [q.get("preview_max_width") for q in fake.state.snapshot_queries] == ["640", "960", None]


def test_no_upscaling_once_the_source_size_is_known(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.width, fake.state.height = 800, 600
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get("/api/v1/status").json()[device]["video"]["width"] == 800
        client.get(snap(device), params={"w": 700})  # the 960 size would be larger than the source itself
        client.get(snap(device), params={"w": 500})
    assert [q.get("preview_max_width") for q in fake.state.snapshot_queries] == [None, "640"]


def test_viewers_share_a_fresh_frame(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 30)
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).content == client.get(snap(device)).content
    assert len(fake.state.snapshot_queries) == 1


def test_logs_in_again_when_the_kvm_session_expires(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        logins = fake.state.logins
        fake.state.tokens.clear()  # as if kvmd restarted
        assert client.get(snap(device)).status_code == 200
    assert fake.state.logins == logins + 1


def test_rejected_password_is_not_retried_on_every_refresh(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        fake.state.password = "changed on the device"
        fake.state.tokens.clear()
        logins = fake.state.logins
        replies = [client.get(snap(device)) for _ in range(3)]
        status = client.get("/api/v1/status").json()[device]
    assert [r.status_code for r in replies] == [502, 502, 502]
    assert replies[0].json()["code"] == "auth_failed"
    assert status["state"] == "auth"
    assert fake.state.logins == logins + 1


def test_idle_stream_is_woken_by_connecting_as_a_viewer(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        fake.state.idle_until_viewer = True
        first = client.get(snap(device))
        assert first.status_code == 503
        assert first.json()["code"] == "no_stream"
        wait_until(lambda: client.get(snap(device)).status_code == 200, "stream never woke up")
        assert fake.state.viewers == 1
    wait_until(lambda: fake.state.viewers == 0, "keepalive outlived the wall")


def test_status_reports_video_and_model(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.signal = False
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        status = client.get("/api/v1/status").json()[device]
        frame = client.get(snap(device))
    assert status["state"] == "no_signal"
    assert status["video"] == {"signal": False, "width": 1920, "height": 1080, "fps": 60}
    assert status["health"]["temp"] == 42.5
    assert status["about"] == {"model": "RM10", "version": "V1.10.1 release2"}
    assert frame.headers["x-kvm-signal"] == "0"


def test_status_never_waits_for_a_dead_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 0.05)
    with wall(tmp_path) as client:
        device = add(client, f"http://127.0.0.1:{closed_port()}", force=True)
        began = time.monotonic()
        first = client.get("/api/v1/status").json()[device]
        assert time.monotonic() - began < 1.0
        # What is known by then depends on the system underneath: Windows keeps trying a closed port for two
        # seconds, so the answer is "connecting"; Linux is refused at once, and may know already.
        # (What it can be asked is the driver's list, there being no look at the device yet that could add to it.)
        can = kvm.can_do(*kvm.KvmDevice.can)
        nobody_there = {"can": can, "state": "offline", "error": {"code": "unreachable", "message": "Device is unreachable"}, "last_seen_ago": None}
        assert first in ({"can": can, "state": "connecting", "error": None, "last_seen_ago": None}, nobody_there)
        wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "offline", "never reported offline")


def test_dead_device_is_left_alone_between_attempts(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        assert client.get("/api/v1/status").json()[device]["last_seen_ago"] == 0
        monkeypatch.setattr(kvm, "ERROR_HOLD", 30)
        fake.stop()
        assert client.get(snap(device)).json()["code"] in ("unreachable", "dropped")
        began = time.monotonic()
        for _ in range(5):  # answered from memory: no new connection attempts for a while
            assert client.get(snap(device)).status_code == 502
        assert time.monotonic() - began < 0.5


def test_survives_the_kvm_restarting(tmp_path: Path) -> None:
    first = FakeKvm().start()
    with wall(tmp_path) as client:
        device = add(client, first.url)
        assert client.get(snap(device)).status_code == 200
        first.stop()
        second = FakeKvm(first.state, port=first.port).start()  # same KVM, back after a reboot
        try:
            assert client.get(snap(device)).status_code == 200  # no error surfaced for the dead connection
        finally:
            second.stop()


# --- actions -------------------------------------------------------------------


def test_actions_reach_the_device_and_the_audit_log(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.wol = [{"mac": "AA:BB:CC:DD:EE:FF", "name": "nas"}, {"mac": "junk"}]
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "reboot"}).status_code == 200
        assert client.post(act, json={"action": "ctrl_alt_del"}).status_code == 200

        no_board = client.post(act, json={"action": "atx_power"})
        assert no_board.status_code == 502
        assert no_board.json() == {"code": "action_failed", "message": "ATX is not available"}
        fake.state.atx = True
        for action in ("atx_power", "atx_power_long", "atx_reset"):
            assert client.post(act, json={"action": action}).status_code == 200

        assert client.get(f"/api/v1/devices/{device}/wol").json() == {"targets": [{"mac": "AA:BB:CC:DD:EE:FF", "name": "nas"}]}
        assert client.post(act, json={"action": "wol", "mac": "AA:BB:CC:DD:EE:FF"}).status_code == 200
        assert client.post(act, json={"action": "wol", "mac": "nope"}).status_code == 422
        assert client.post(act, json={"action": "format_disk"}).status_code == 422
        assert client.post("/api/v1/devices/nope/actions", json={"action": "reboot"}).status_code == 404

        log = client.get("/api/v1/audit").json()["entries"]
    assert fake.state.actions == [
        "reboot",
        "shortcut ControlLeft,AltLeft,Delete",
        "atx power",
        "atx power_long",
        "atx reset",
        "wol AA:BB:CC:DD:EE:FF",
    ]
    assert [e["action"] for e in log if e["event"] == "action"][-1] == "reboot"
    assert any(e["event"] == "action_failed" and e["action"] == "atx_power" for e in log)


def test_keys_text_and_keep_awake(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
        assert client.post(act, json={"action": "keys", "keys": "not keys!"}).status_code == 422
        assert client.post(act, json={"action": "keys"}).status_code == 422
        assert client.post(act, json={"action": "text", "text": "ipconfig /all", "enter": True}).status_code == 200
        assert client.post(act, json={"action": "text", "text": ""}).status_code == 422
        assert client.post(act, json={"action": "jiggler_on", "batch": "run-1"}).status_code == 200
        assert client.post(act, json={"action": "jiggler_off"}).status_code == 200
        log = client.get("/api/v1/audit").json()["entries"]
    assert fake.state.actions == ["shortcut MetaLeft,KeyL", "type 'ipconfig /all\\n'", "jiggler 1", "jiggler 0"]
    typed = next(e for e in log if e["event"] == "action" and e.get("action") == "text")
    assert typed["chars"] == 13 and "ipconfig" not in str(log)  # what was typed stays out of the log
    assert next(e for e in log if e.get("action") == "jiggler_on")["batch"] == "run-1"


def test_multi_port_kvm_lists_its_ports_and_switches(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.ports = [(150, 80, 40), None, (40, 110, 130), (95, 70, 140)]
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        ports = client.get("/api/v1/status").json()[device]["ports"]
        assert ports["active"] == 0
        assert [port["signal"] for port in ports["list"]] == [True, False, True, True]
        assert client.get(snap(device)).headers["x-kvm-signal"] == "1"

        assert client.post(act, json={"action": "port", "port": 1}).status_code == 200
        assert client.get("/api/v1/status").json()[device]["ports"]["active"] == 1
        assert client.get(snap(device)).headers["x-kvm-signal"] == "0"  # nothing is plugged into that one
        assert client.post(act, json={"action": "port", "port": 4}).status_code == 422
        log = client.get("/api/v1/audit").json()["entries"]
    assert fake.state.actions == ["port 1"]
    switched = next(e for e in log if e["event"] == "action" and e.get("action") == "port")
    assert switched["port"] == 2  # counted from 1, as on the device


def test_after_another_computer_is_put_on_screen_the_keyboard_is_not_called_unplugged(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real Comet X, switched to another port and back: "USB not connected" on its tile from then on, for as
    # long as nobody sent a key. One Shift press, and it was connected again. It goes on saying "no keyboard"
    # after a switch until it has tried one, which is not knowing, and is told as not knowing.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    fake.state.ports = [(150, 80, 40), None, (40, 110, 130), (95, 70, 140)]
    fake.state.forgets_keyboard = True
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"

        def usb_says(keyboard: bool | None) -> None:
            wanted = {"keyboard": keyboard, "mouse": keyboard}
            wait_until(lambda: client.get("/api/v1/status").json()[device]["usb"] == wanted, f"the status never said {wanted}")

        usb_says(True)
        assert client.post(act, json={"action": "port", "port": 2}).status_code == 200
        usb_says(None)  # not known since the switch: nothing is said of a cable
        assert client.post(act, json={"action": "keys", "keys": "ShiftLeft"}).status_code == 200
        usb_says(True)  # a key was sent, and the device found its keyboard there
        fake.state.keyboard_online = False  # and now, with the same computer on screen, a cable did come out
        usb_says(False)


def test_a_keyboard_that_is_not_connected_is_said_of_an_ordinary_kvm(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    fake.state.keyboard_online = False
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get("/api/v1/status").json()[device]["usb"] == {"keyboard": False, "mouse": False}


def test_ordinary_kvm_has_no_ports(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get("/api/v1/status").json()[device]["ports"] is None
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "port", "port": 1})
    assert reply.status_code == 422 and fake.state.actions == []
    # An empty shell of the switch state, as a device without a switch might send, is not a switch either.
    assert kvm._ports_from({"model": {"ports": []}, "summary": {"active_port": 0}, "video": {"links": []}}) is None
    assert kvm._ports_from({"model": {"ports": [{}, {}, {}, {}]}, "summary": {}}) is None


def test_saved_actions(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post("/api/v1/actions", json={"name": "Nothing", "kind": "keys"}).status_code == 422
        assert client.post("/api/v1/actions", json={"name": "Nothing", "kind": "text"}).status_code == 422

        lock = client.post("/api/v1/actions", json={"name": "Lock screen", "kind": "keys", "keys": "MetaLeft,KeyL"})
        assert lock.status_code == 201
        login = client.post(
            "/api/v1/actions", json={"name": "Log in", "kind": "text", "text": "hunter2-on-the-box", "enter": True}
        )
        assert login.status_code == 201
        assert "hunter2" not in login.text
        saved = (tmp_path / "qkvm.json").read_text(encoding="utf-8")
        assert "hunter2" not in saved and "Lock screen" in saved
        listed = client.get("/api/v1/actions").json()["actions"]
        assert [a["name"] for a in listed] == ["Lock screen", "Log in"]
        assert "text" not in listed[1]

        lock_id, login_id = lock.json()["action"]["id"], login.json()["action"]["id"]
        assert client.post(act, json={"action": "custom", "custom_id": lock_id}).status_code == 200
        assert client.post(act, json={"action": "custom", "custom_id": login_id}).status_code == 200
        assert client.post(act, json={"action": "custom", "custom_id": "gone"}).status_code == 404

        # Renaming without retyping keeps the saved text; switching kind drops it.
        renamed = client.put(f"/api/v1/actions/{login_id}", json={"name": "Sign in", "kind": "text", "enter": False})
        assert renamed.status_code == 200
        assert client.post(act, json={"action": "custom", "custom_id": login_id}).status_code == 200
        assert client.delete(f"/api/v1/actions/{lock_id}").status_code == 200
        assert client.post(act, json={"action": "custom", "custom_id": lock_id}).status_code == 404
        log = client.get("/api/v1/audit").json()["entries"]
    assert fake.state.actions == [
        "shortcut MetaLeft,KeyL",
        "type 'hunter2-on-the-box\\n'",
        "type 'hunter2-on-the-box'",
    ]
    assert "hunter2" not in str(log)
    assert [e["name"] for e in log if e["event"] == "action"] == ["Sign in", "Log in", "Lock screen"]

    with wall(tmp_path) as client:  # after a restart the saved text is still usable
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": login_id}).status_code == 200


def test_actions_need_a_login(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        client.post("/api/v1/logout", json={"scope": "this"})
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "reboot"}).status_code == 401
    assert fake.state.actions == []


# --- certificate pinning -------------------------------------------------------


def test_pinned_certificate_protects_the_kvm_password(tmp_path: Path) -> None:
    state = FakeState()
    original = FakeKvm(state, tls_dir=tmp_path / "cert-a").start()
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, original.url)  # the fake's certificate "expired" in 1979, like a Comet's
            pinned = client.get("/api/v1/wall").json()["devices"][0]["fingerprint"]
            assert pinned and len(pinned.split(":")) == 32
            assert client.get(snap(device)).status_code == 200

            # Something else now answers at the KVM's address, with a certificate of its own.
            original.stop()
            impostor = FakeKvm(FakeState(), port=original.port, tls_dir=tmp_path / "cert-b").start()
            try:
                wait_until(
                    lambda: client.get(snap(device)).json().get("code") == "cert_mismatch",
                    "the changed certificate was not noticed",
                )
                assert client.get("/api/v1/status").json()[device]["error"]["code"] == "cert_mismatch"
                assert impostor.state.logins == 0  # the password was never offered to it

                cert = client.get(f"/api/v1/devices/{device}/certificate").json()
                assert cert["saved"] == pinned
                assert cert["presented"] != pinned
                trust = f"/api/v1/devices/{device}/trust"
                assert client.post(trust, json={"fingerprint": pinned}).status_code == 409
                assert client.post(trust, json={"fingerprint": cert["presented"]}).status_code == 200
                assert client.get(snap(device)).status_code == 200
                assert impostor.state.logins == 1
            finally:
                impostor.stop()
    finally:
        original.stop()


# --- settings ------------------------------------------------------------------


def usage(digital_signature: bool = False, key_cert_sign: bool = False, crl_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature, key_cert_sign=key_cert_sign, crl_sign=crl_sign, content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False,
    )  # fmt: skip


def an_authority() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "an authority this computer trusts")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(usage(digital_signature=True, key_cert_sign=True, crl_sign=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issued_by(authority: tuple[ec.EllipticCurvePrivateKey, x509.Certificate], directory: Path) -> tuple[Path, Path]:
    # A certificate as a front door on the internet shows it: for the name asked for, valid today, signed by an authority.
    signer, signer_cert = authority
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kvm.example.test")]))
        .issuer_name(signer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=20))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        .add_extension(usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(signer, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def test_a_device_behind_a_front_door_is_checked_like_a_web_site_and_not_remembered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cloudflare, a company's proxy, a name under ts.net: the certificate is one this computer trusts as it
    # is, and it is replaced every few weeks. Remembered, it would raise a false alarm at the first renewal.
    authority = an_authority()
    trusted = ssl.create_default_context(cadata=authority[1].public_bytes(serialization.Encoding.PEM).decode())

    async def this_computer_trusts() -> ssl.SSLContext:
        return trusted

    monkeypatch.setattr(kvm, "system_context", this_computer_trusts)
    like_a_comet = fake_kvm.make_device_certificate
    monkeypatch.setattr(fake_kvm, "make_device_certificate", lambda directory: issued_by(authority, directory))
    state = FakeState()
    first = FakeKvm(state, tls_dir=tmp_path / "cert-a").start()
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, first.url)
            listed = client.get("/api/v1/wall").json()["devices"][0]
            assert (listed["tls"], listed["fingerprint"]) == ("system", None)  # checked every time, and nothing remembered
            assert client.get(snap(device)).status_code == 200
            # The front door renews its certificate, as it does every few weeks. Nothing is the matter.
            first.stop()
            renewed = FakeKvm(state, port=first.port, tls_dir=tmp_path / "cert-b").start()
            try:
                assert client.get(snap(device)).status_code == 200
                assert client.put(f"/api/v1/devices/{device}", json={"url": first.url}).status_code == 200
                assert client.get("/api/v1/wall").json()["devices"][0]["tls"] == "system"  # an edit that says nothing about it leaves it
                assert client.get(snap(device)).status_code == 200
            finally:
                renewed.stop()
            # Something else at that address, with a certificate nobody vouches for, is not talked to.
            monkeypatch.setattr(fake_kvm, "make_device_certificate", like_a_comet)
            impostor = FakeKvm(FakeState(), port=first.port, tls_dir=tmp_path / "cert-c").start()
            try:
                refused = client.get(snap(device))
                assert (refused.status_code, refused.json()["code"]) == (502, "cert_invalid")
                assert impostor.state.logins == 0  # and the password was not sent to it
            finally:
                impostor.stop()
    finally:
        first.stop()


def test_a_kvm_on_a_shelf_is_still_remembered_and_whoever_asks_for_a_way_gets_it(tmp_path: Path) -> None:
    comet = FakeKvm(FakeState(), tls_dir=tmp_path / "cert").start()  # its own certificate, "valid" in the seventies
    try:
        with wall(tmp_path / "data") as client:
            add(client, comet.url)
            listed = client.get("/api/v1/wall").json()["devices"][0]
            assert listed["tls"] == "pinned" and listed["fingerprint"]
            # An edit says how it wants the certificate checked, and that is how it is checked.
            edited = client.put(f"/api/v1/devices/{listed['id']}", json={"url": comet.url, "tls": "insecure"})
            assert edited.status_code == 200 and edited.json()["device"]["tls"] == "insecure"
            assert client.delete(f"/api/v1/devices/{listed['id']}").status_code == 200
            asked = client.post("/api/v1/devices", json={"url": comet.url, "password": "secret", "tls": "insecure"})
            assert asked.status_code == 201 and asked.json()["device"]["tls"] == "insecure"  # said outright when adding: taken as said
    finally:
        comet.stop()


def test_network_settings_are_validated_saved_and_applied(tmp_path: Path) -> None:
    with wall(tmp_path) as client:
        core = client.core  # type: ignore[attr-defined]
        settings = client.get("/api/v1/settings").json()
        assert settings["bind"] == ["local"] and settings["https"] is False

        same = client.put("/api/v1/settings", json={"bind": ["local"], "port": 8787, "https": False, "interval": 2})
        assert same.json()["restart"] is False
        assert Store(tmp_path / "qkvm.json").server.interval == 2

        bad = client.put("/api/v1/settings", json={"bind": ["nowhere"], "port": 8787, "https": False, "interval": 1})
        assert bad.status_code == 422

        changed = client.put("/api/v1/settings", json={"bind": ["192.0.2.10"], "port": 9000, "https": True, "interval": 1})
        assert changed.json()["restart"] is True
        assert changed.json()["urls"] == ["https://127.0.0.1:9000/", "https://192.0.2.10:9000/"]
        assert len(changed.json()["cert_fingerprint"].split(":")) == 32
        assert (tmp_path / "tls" / "key.pem").exists()
        assert Store(tmp_path / "qkvm.json").server.bind == ["local", "192.0.2.10"]
        wait_until(lambda: core.restart_requested, "the listeners were never restarted")


# --- building blocks -----------------------------------------------------------


def test_vault_round_trip_and_wrong_password() -> None:
    box = vault.Vault()
    record = box.create("first password!")
    sealed = box.encrypt("kvm-secret", "device-1")
    assert "kvm-secret" not in str(record) + str(sealed)

    assert vault.Vault.open(record, "not it") is None
    fresh = vault.Vault()
    with pytest.raises(vault.VaultLocked):
        fresh.decrypt(sealed, "device-1")
    key = vault.Vault.open(record, "first password!")
    assert key is not None
    fresh.adopt(key)
    assert fresh.decrypt(sealed, "device-1") == "kvm-secret"
    with pytest.raises(InvalidTag):  # a secret can't be moved to another device
        fresh.decrypt(sealed, "device-2")


def test_store_refuses_a_damaged_file(tmp_path: Path) -> None:
    (tmp_path / "qkvm.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(StoreError):
        Store(tmp_path / "qkvm.json")


def test_store_falls_back_to_its_second_copy(tmp_path: Path) -> None:
    store = Store(tmp_path / "qkvm.json")
    store.server.port = 9001
    store.save()
    store.server.port = 9002
    store.save()  # qkvm.bak is a copy of this, not of what was there before: falling back to it undoes nothing
    assert (tmp_path / "qkvm.bak").read_bytes() == (tmp_path / "qkvm.json").read_bytes()
    (tmp_path / "qkvm.json").write_text('{"server": ', encoding="utf-8")  # a hand edit gone wrong

    recovered = Store(tmp_path / "qkvm.json")
    assert recovered.server.port == 9002 and recovered.restored
    assert recovered.recovered_from is not None and recovered.recovered_from.exists()
    again = Store(tmp_path / "qkvm.json")
    assert again.recovered_from is None and not again.restored  # the repaired file is good again

    # No settings file at all, and a second copy: a start that was cut off while putting it back. Not a new wall.
    (tmp_path / "qkvm.json").unlink()
    back = Store(tmp_path / "qkvm.json")
    assert back.server.port == 9002 and back.restored and back.recovered_from is None
    assert (tmp_path / "qkvm.json").exists()


def test_only_one_wall_per_data_folder(tmp_path: Path) -> None:
    first, second = InstanceLock(tmp_path), InstanceLock(tmp_path)
    assert first.acquire()
    assert not second.acquire()
    first.release()
    assert second.acquire()
    second.release()


def test_the_label_of_the_stored_key_does_not_change() -> None:
    # It is mixed into the encryption of the stored key: "tidying" it would lock every data folder for good.
    assert vault._KEY_CONTEXT == "kvm-wall data key"


def test_device_addresses() -> None:
    assert device_url("192.168.1.20") == "https://192.168.1.20"
    assert device_url(" https://192.168.1.21/#/ ") == "https://192.168.1.21"
    assert device_url("http://kvm.lan:8080/x") == "http://kvm.lan:8080"
    for bad in ("", "ftp://kvm.lan", "https://user:pw@kvm.lan", "kvm.lan:99999", "two words"):
        with pytest.raises(ValueError):
            device_url(bad)


def test_bind_names() -> None:
    assert normalize(["Tailscale", "127.0.0.1", "192.168.1.5"]) == ["local", "tailscale", "192.168.1.5"]
    assert resolve([]) == (["127.0.0.1"], [])
    assert resolve(["all"])[0] == ["0.0.0.0"]
    with pytest.raises(BindError):
        normalize(["nowhere"])


def test_wall_certificate_is_reused_until_it_no_longer_fits(tmp_path: Path) -> None:
    _, key, first = ensure_certificate(tmp_path, ["100.64.0.1"])
    assert key.exists()
    assert ensure_certificate(tmp_path, ["100.64.0.1"])[2] == first
    assert ensure_certificate(tmp_path, ["100.64.0.1", "192.168.1.9"])[2] != first


def test_an_address_that_changes_is_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Told to listen on "the local network", qKVM looked up what address that is once, when it started. A
    # new lease from the router, or a cable moved to another network, and the wall answered only on the
    # computer it runs on until somebody restarted it.
    from qkvm import server

    now = {"lan": "192.0.2.10"}
    monkeypatch.setattr(server, "resolve", lambda names: (["127.0.0.1", now["lan"]] if now["lan"] else ["127.0.0.1"], [] if now["lan"] else ["lan"]))
    monkeypatch.setattr(server, "HOUSEKEEPING_EVERY", 0.05)
    with wall(tmp_path, bind_override=["local", "lan"]) as client:
        core = client.core  # type: ignore[attr-defined]
        core.addresses, core.missing = ["127.0.0.1", "192.0.2.10"], []  # what the listeners were opened on
        time.sleep(0.4)
        assert core.restart_requested is False  # nothing has changed: nothing is reopened
        now["lan"] = "192.0.2.77"
        wait_until(lambda: core.restart_requested, "the listeners were not reopened on the new address")
        # Gone altogether (the cable is out), there is nothing new to listen on: what is open stays open.
        core.restart_requested = False
        core.addresses, core.missing = ["127.0.0.1", "192.0.2.77"], []
        now["lan"] = ""
        time.sleep(0.4)
        assert core.restart_requested is True  # ...but the one that is gone is let go of, and looked for from then on


def test_a_certificate_and_a_key_that_do_not_belong_together_are_made_anew(tmp_path: Path) -> None:
    # The two are two files. Power lost between writing the one and the other left a certificate with the
    # key of another: the web server would not start with that, again and again, until it gave up.
    _, key_path, first = ensure_certificate(tmp_path, ["100.64.0.1"])
    stranger = ec.generate_private_key(ec.SECP256R1())
    key_path.write_bytes(stranger.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path, key_path, second = ensure_certificate(tmp_path, ["100.64.0.1"])
    assert second != first
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    same = serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    assert certificate.public_key().public_bytes(*same) == key.public_key().public_bytes(*same)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["cert.pem", "key.pem"]  # nothing half-written is left lying about
    key_path.write_bytes(b"not a key at all")
    assert ensure_certificate(tmp_path, ["100.64.0.1"])[2] != second


def test_a_saved_action_that_was_changed_since_it_was_looked_at_is_not_run_unseen(tmp_path: Path, fake: FakeKvm) -> None:
    # An operator has the list of actions open, with "Lock" in it: a key combination, run at a click. An
    # admin changes that entry into text that is typed, a command with Enter. The click, a moment later,
    # used to type the command: the button still said "Lock", and no question was asked.
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        made = client.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
        assert made["changed"] == 0
        seen = client.get("/api/v1/actions").json()["actions"][0]
        edited = client.put(f"/api/v1/actions/{made['id']}", json={"name": "Lock", "kind": "text", "text": "shutdown now", "enter": True})
        assert edited.json()["action"]["changed"] == 1
        done_before = list(fake.state.actions)
        refused = client.post(act, json={"action": "custom", "custom_id": seen["id"], "custom_changed": seen["changed"]})
        assert (refused.status_code, refused.json()["code"]) == (409, "changed")
        assert fake.state.actions == done_before  # nothing was typed
        # Looked at again, it runs; and whoever does not say what they saw (a script) gets it as it is.
        again = client.get("/api/v1/actions").json()["actions"][0]
        assert client.post(act, json={"action": "custom", "custom_id": again["id"], "custom_changed": again["changed"]}).status_code == 200
        assert client.post(act, json={"action": "custom", "custom_id": again["id"]}).status_code == 200


def test_one_thing_at_a_time_is_done_to_a_machine(tmp_path: Path, fake: FakeKvm) -> None:
    # The page holds back a second action while the first is out, but only that page: another tab, another
    # operator, a run on many machines started meanwhile do not know. A power button pressed twice is off
    # after on. The second request for the same machine is refused for as long as the first is under way.
    fake.state.atx, fake.state.slow_action = True, 1.0
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        act = f"/api/v1/devices/{device}/actions"
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(client.post, act, json={"action": "atx_power"})
            time.sleep(0.3)
            second = client.post(act, json={"action": "atx_power"})
            assert (second.status_code, second.json()["code"]) == (409, "busy")
            assert first.result().status_code == 200
        assert fake.state.actions.count("atx power") == 1
        fake.state.slow_action = 0.0
        assert client.post(act, json={"action": "atx_power"}).status_code == 200  # over, the next one goes through


def test_the_activity_log_can_be_searched_and_taken_away(tmp_path: Path, fake: FakeKvm) -> None:
    # Two hundred lines, newest first, was all there was: "who pressed reset on that machine last week" meant
    # reading the file on the server. And a log that cannot leave the program is no evidence for anybody.
    import csv
    import io
    import json as json_lines

    with wall(tmp_path, locked_start=True) as client:  # (as it comes, the log has one more entry, made a moment after the first)
        device = add(client, fake.url, name="=HYPERLINK(1)")  # what a spreadsheet would take for a formula
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "reboot"}).status_code == 200
        assert client.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "a password for olga"}).status_code == 201
        assert client.post("/api/v1/login", json={"name": "olga", "password": "not her password"}).status_code == 401

        def events(query: str) -> list[str]:
            return [e["event"] for e in client.get(f"/api/v1/audit?{query}").json()["entries"]]

        assert events("limit=50") == ["login_failed", "user_added", "action", "device_added", "setup"]
        assert events("kind=signin") == ["login_failed", "setup"]
        assert events("kind=action") == ["action"] and events("kind=change") == ["user_added", "device_added"]
        assert events("q=OLGA") == ["login_failed", "user_added"]  # in whatever case it is typed
        assert events("q=reboot") == ["action"] and events("q=nothing-like-this") == []
        # What the page shows is called something else in here: it asks under both names, and either finds it.
        assert events("q=Reboot+KVM&q=reboot") == ["action"] and events("q=x-ray&q=yankee") == []
        assert client.get("/api/v1/audit?kind=everything").status_code == 422
        # Older than a moment in time, for the next page of a long log.
        entries = client.get("/api/v1/audit?limit=2").json()
        assert [e["event"] for e in entries["entries"]] == ["login_failed", "user_added"] and entries["more"] is True
        older = client.get(f"/api/v1/audit?limit=50&before={entries['entries'][-1]['time']}").json()
        assert [e["event"] for e in older["entries"]] == ["action", "device_added", "setup"] and older["more"] is False

        # As a file: a table for a spreadsheet, or the lines as they are for a program.
        table = client.get("/api/v1/audit/export?format=csv&kind=action")
        assert table.status_code == 200 and table.headers["content-type"].startswith("text/csv")
        assert "attachment" in table.headers["content-disposition"] and ".csv" in table.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(table.text)))
        assert rows[0][:5] == ["time", "event", "user", "ip", "device"] and len(rows) == 2
        assert rows[1][1:4] == ["action", "admin", "127.0.0.1"] and rows[1][0].endswith("Z")
        # A name that begins like a formula is not one in the file: whoever opens it runs nothing.
        assert rows[1][4] == "'=HYPERLINK(1)"
        lines = client.get("/api/v1/audit/export?format=jsonl").text.splitlines()
        # (The download of a moment ago is in the log itself, with what it was of: the activity log taken away is something done.)
        exported, *rest = [json_lines.loads(line) for line in lines]
        assert [entry["event"] for entry in rest] == ["login_failed", "user_added", "action", "device_added", "setup"]
        assert (exported["event"], exported["format"], exported["asked"], exported["user"]) == ("activity_exported", "csv", {"kind": "action"}, "admin")
        assert client.get("/api/v1/audit/export?format=pdf").status_code == 422

        olga = TestClient(client.app, headers=CSRF, client=("127.0.0.1", 50041))
        olga.portal = client.portal
        assert olga.post("/api/v1/login", json={"name": "olga", "password": "a password for olga"}).status_code == 200
        assert olga.get("/api/v1/audit").status_code == 403 and olga.get("/api/v1/audit/export?format=csv").status_code == 403


def test_the_tiles_stand_in_the_order_an_admin_gave_them(tmp_path: Path) -> None:
    # The wall showed its machines in the order they had been added, for ever. Whoever looks at a wall all
    # day wants the firewall top left and the rack in the order it stands in: an order of their own making,
    # kept on the server, so that every browser and every screen on the wall shows the same one.
    first, second, third = FakeKvm().start(), FakeKvm().start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            a, b, c = add(admin, first.url, name="A"), add(admin, second.url, name="B"), add(admin, third.url, name="C")

            def order(client: TestClient = admin) -> list[str]:
                return [d["name"] for d in client.get("/api/v1/wall").json()["devices"]]

            assert order() == ["A", "B", "C"]
            arranged = admin.put("/api/v1/wall/order", json={"ids": [c, a, b]})
            assert arranged.status_code == 200 and order() == ["C", "A", "B"]
            # Only some of them named: those first, in that order; the rest follow as they stood.
            assert admin.put("/api/v1/wall/order", json={"ids": [b]}).status_code == 200 and order() == ["B", "C", "A"]
            # What is not a machine of this wall, or is named twice, changes nothing about the others.
            assert admin.put("/api/v1/wall/order", json={"ids": [a, "nothing", a, c]}).status_code == 200 and order() == ["A", "C", "B"]
            assert admin.put("/api/v1/wall/order", json={"ids": "ACB"}).status_code == 422
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "a password for olga"}).status_code == 201
            olga = TestClient(admin.app, headers=CSRF, client=("127.0.0.1", 50091))
            olga.portal = admin.portal
            assert olga.post("/api/v1/login", json={"name": "olga", "password": "a password for olga"}).status_code == 200
            assert olga.put("/api/v1/wall/order", json={"ids": [b, a, c]}).status_code == 403  # the wall's order is its admins' to set
            assert order(olga) == ["A", "C", "B"]  # and everybody sees it
            assert any(e["event"] == "wall_arranged" for e in admin.get("/api/v1/audit").json()["entries"])
        with wall(tmp_path, sign_in=False) as later:  # kept across a restart
            assert later.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
            assert [d["name"] for d in later.get("/api/v1/wall").json()["devices"]] == ["A", "C", "B"]
    finally:
        for server in (first, second, third):
            server.stop()
