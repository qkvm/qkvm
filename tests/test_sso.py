"""Signing in where the company signs in: a reverse proxy in front of qKVM says who it is (--sso-header)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import cli, kvm, update, vault
from tests.test_totp import switch_on
from tests.test_users import OTHER
from tests.test_wall import PASSWORD, wait_until, wall

SECRET = "what-is-in-the-file-that-is-kept-somewhere-else"
PROXY = "10.0.0.5"
STARTED = {"trusted_proxies": (PROXY,), "sso_header": "Remote-User", "unlock_secret": SECRET}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def through_proxy(admin: TestClient, said: str | None, port: int = 52000, address: str = PROXY) -> TestClient:
    """A browser that reaches qKVM through the proxy, which says who it has signed in."""
    headers = {"X-QKVM": "1", "X-Forwarded-For": "192.0.2.9", **({} if said is None else {"Remote-User": said})}
    client = TestClient(admin.app, headers=headers, client=(address, port))
    client.portal = admin.portal
    return client


def test_whoever_the_proxy_has_signed_in_is_signed_in(tmp_path: Path) -> None:
    # A company signs its people in in one place, with its own second step and its own way of taking access
    # away. A tool with accounts and passwords of its own is what its security team turns down first.
    with wall(tmp_path, **STARTED) as admin:
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
        made = admin.post("/api/v1/users", json={"name": "olga@example.org", "role": "operator"})  # no password of her own here
        assert made.status_code == 201, made.text
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer", "password": OTHER}).status_code == 201
        assert admin.get("/api/v1/session").json()["sso"] == {"on": True, "name": None, "known": False}

        hers = through_proxy(admin, "olga@example.org")
        first = hers.get("/api/v1/session")
        said = first.json()
        assert said["authenticated"] is True and said["user"]["name"] == "olga@example.org" and said["user"]["sso"] is True
        assert said["sso"] == {"on": True, "name": "olga@example.org", "known": True}
        assert "httponly" in first.headers["set-cookie"].lower()
        assert hers.get("/api/v1/wall").status_code == 200 and hers.get("/api/v1/users").status_code == 403  # the role is qKVM's to give
        assert hers.get("/api/v1/session").headers.get("set-cookie") is None  # signed in once, not at every look
        entry = next(e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "login")
        assert (entry["user"], entry["sso"], entry["ip"]) == ("olga@example.org", True, "192.0.2.9")  # who, how, and from where

        # She has no password here: nothing signs her in but the proxy, and there is none to change.
        direct = TestClient(admin.app, headers={"X-QKVM": "1"}, client=("192.0.2.9", 52001))
        direct.portal = admin.portal
        for guess in ("", OTHER, "olga@example.org"):
            assert direct.post("/api/v1/login", json={"name": "olga@example.org", "password": guess}).status_code in (401, 422)
        refused = hers.post("/api/v1/password", json={"current": "whatever it was", "new": "a new one she made up"})
        assert (refused.status_code, refused.json()["code"]) == (409, "no_password")

        # The header is the proxy's to say. From anybody else it says nothing: not from the visitor's own
        # address, not from this computer, and not twice (one of two lines may be the visitor's).
        for caller in (
            through_proxy(admin, "olga@example.org", address="192.0.2.9", port=52002),
            through_proxy(admin, "olga@example.org", address="127.0.0.1", port=52003),
        ):
            assert caller.get("/api/v1/session").json()["authenticated"] is False
            assert caller.get("/api/v1/wall").status_code == 401
        twice: Any = [("Remote-User", "admin"), ("Remote-User", "olga@example.org")]
        doubled = through_proxy(admin, None, port=52004)
        assert doubled.get("/api/v1/session", headers=twice).json()["authenticated"] is False
        assert doubled.get("/api/v1/wall", headers=twice).status_code == 401
        # Somebody the proxy knows and qKVM does not is told so, and is nobody here.
        stranger = through_proxy(admin, "nobody@example.org", port=52005)
        assert stranger.get("/api/v1/session").json()["sso"] == {"on": True, "name": "nobody@example.org", "known": False}
        assert stranger.get("/api/v1/wall").status_code == 401

        # Access is taken away where it is given: suspended here, the proxy's word no longer opens anything.
        olga = next(u["id"] for u in admin.get("/api/v1/users").json()["users"] if u["name"] == "olga@example.org")
        assert admin.put(f"/api/v1/users/{olga}", json={"name": "olga@example.org", "role": "operator", "suspended": True}).status_code == 200
        assert hers.get("/api/v1/wall").status_code == 401 and hers.get("/api/v1/session").json()["authenticated"] is False


def test_the_second_step_is_the_identity_providers_for_those_it_signs_in(tmp_path: Path) -> None:
    with wall(tmp_path, **STARTED) as admin:
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator"}).status_code == 201
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer", "password": OTHER}).status_code == 201
        switch_on(admin, PASSWORD)
        assert admin.put("/api/v1/security", json={"require_totp": "viewer"}).json()["without"] == ["olga", "victor"]
        hers = through_proxy(admin, "olga", port=52010)
        assert hers.get("/api/v1/session").json()["user"]["must_enroll"] is False and hers.get("/api/v1/wall").status_code == 200
        # Who signs in here with a password is asked for the second step here.
        his = TestClient(admin.app, headers={"X-QKVM": "1"}, client=("192.0.2.9", 52011))
        his.portal = admin.portal
        assert his.post("/api/v1/login", json={"name": "victor", "password": OTHER}).json()["user"]["must_enroll"] is True
        assert his.get("/api/v1/wall").status_code == 403


def test_without_being_asked_to_qkvm_believes_no_header_about_who_somebody_is(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with wall(tmp_path, trusted_proxies=(PROXY,)) as admin:
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator"}).status_code == 422  # an account has a password
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
        caller = through_proxy(admin, "olga", port=52020)
        assert caller.get("/api/v1/session").json()["authenticated"] is False and "sso" not in caller.get("/api/v1/session").json()
        assert caller.get("/api/v1/wall").status_code == 401
    # What it takes is said at start: a proxy that was named, and a way to open the saved passwords without anybody's
    # (which qKVM has as it comes, and has not where it is started locked).
    key = tmp_path / "elsewhere.key"
    for options, complaint in (
        (["--sso-header", "Remote-User"], "--trusted-proxy"),
        (["--sso-header", "Remote-User", "--trusted-proxy", PROXY, "--locked-start"], "--locked-start"),
        (["--sso-header", "Remote User", "--trusted-proxy", PROXY, "--unlock-file", str(key)], "header"),
    ):
        assert cli.main(["--data-dir", str(tmp_path), *options, "--disable-2fa", "nobody"]) == 2, options
        assert complaint in capsys.readouterr().err, options
