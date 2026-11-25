"""A destination's saved password, token or key goes only where it was saved for (the review of 0.4.0's first wave, H1).

A secret left empty in an edit keeps the one saved. It did so whatever else changed: an ntfy destination pointed at
another host took its saved access token there as a Bearer header, a mail destination given another server logged in
there with the saved password. Whoever sat at an admin's open browser had both. Where a destination is reached changes
(its host, its port, its scheme, PagerDuty's region), the secret is typed again, or the change is refused. Against
stand-ins on loopback.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import alerts, server, update, vault
from tests.fake_alerts import HOOKS, NTFY, FakeService
from tests.fake_smtp import Behaviour, FakeSmtp
from tests.test_wall import wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(server, "TEST_EVERY", 0.0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeService]:
    fake = FakeService(tmp_path / "services", monkeypatch)
    yield fake
    fake.close()


def test_an_ntfy_token_does_not_follow_its_destination_to_another_host(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        made = admin.post("/api/v1/alerts/destinations", json={"kind": "ntfy", "url": f"https://{NTFY}/alerts", "token": "tk_KEPTsecretTOKEN"})
        place = made.json()["destination"]["id"]
        moved = admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "ntfy", "url": f"https://{HOOKS}/collect"})
        assert moved.status_code == 422 and "again" in moved.json()["message"], moved.text
        assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
        assert services.at(HOOKS) == [] and services.at(NTFY)[0].headers["Authorization"] == "Bearer tk_KEPTsecretTOKEN"  # as it was
        # Another topic on the same server keeps it; another host takes one typed for it, or none where it is forgotten.
        assert admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "ntfy", "url": f"https://{NTFY}/other"}).status_code == 200
        assert admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "ntfy", "url": f"https://{HOOKS}/collect", "token": "tk_NEW"}).status_code == 200
        assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
        assert services.at(HOOKS)[-1].headers["Authorization"] == "Bearer tk_NEW"
        assert admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "ntfy", "url": f"https://{NTFY}:8443/alerts"}).status_code == 422  # (another port)
        forgotten = admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "ntfy", "url": f"https://{NTFY}/alerts", "forget_token": True})
        assert forgotten.status_code == 200 and forgotten.json()["destination"]["has_token"] is False


def test_a_mail_password_does_not_follow_its_destination_to_another_server(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    smtp = FakeSmtp(tmp_path / "smtp", Behaviour())
    smtp.put_in_place(monkeypatch)
    services.trust(smtp.authority, monkeypatch)
    try:
        with wall(tmp_path) as admin:
            said = {"kind": "email", "host": "smtp.example.com", "port": 587, "user": "alerts@example.com", "sender": "alerts@example.com", "to": ["ops@example.com"]}
            place = admin.post("/api/v1/alerts/destinations", json={**said, "password": "KEPT-app-password"}).json()["destination"]["id"]
            for elsewhere in ({"host": "mail.example.org"}, {"port": 465}):
                moved = admin.put(f"/api/v1/alerts/destinations/{place}", json={**said, **elsewhere})
                assert moved.status_code == 422 and "password" in moved.json()["message"], moved.text
            # Other recipients, or another sender, on the same server: the saved password stays.
            assert admin.put(f"/api/v1/alerts/destinations/{place}", json={**said, "to": ["oncall@example.com"]}).status_code == 200
            assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
            assert [password for _, password, _ in smtp.seen.logins] == ["KEPT-app-password"] and smtp.seen.sni == ["smtp.example.com"]
            assert admin.put(f"/api/v1/alerts/destinations/{place}", json={**said, "host": "mail.example.org", "password": "typed for it"}).status_code == 200
            assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
            assert [password for _, password, _ in smtp.seen.logins] == ["KEPT-app-password", "typed for it"] and smtp.seen.sni[-1] == "mail.example.org"
    finally:
        smtp.close()


def test_a_routing_key_does_not_follow_pagerduty_to_its_other_region(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        key = "R0UT1NGKEY0123456789abcdefABCDEF"
        place = admin.post("/api/v1/alerts/destinations", json={"kind": "pagerduty", "key": key, "region": "us"}).json()["destination"]["id"]
        assert admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "pagerduty", "region": "eu"}).status_code == 422
        assert admin.put(f"/api/v1/alerts/destinations/{place}", json={"kind": "pagerduty", "region": "eu", "key": key}).status_code == 200


def test_the_api_of_0_3_2_does_not_take_a_saved_token_to_another_address(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        made = admin.post("/api/v1/alerts/destinations", json={"kind": "ntfy", "url": f"https://{NTFY}/alerts", "token": "tk_KEPTsecretTOKEN"})
        assert made.status_code == 201
        moved = admin.put("/api/v1/alerts", json={"enabled": True, "webhook": f"https://{HOOKS}/collect", "format": "ntfy"})
        assert moved.status_code == 422 and "again" in moved.json()["message"], moved.text
        assert admin.post("/api/v1/alerts/test").status_code == 200
        assert services.at(HOOKS) == []
