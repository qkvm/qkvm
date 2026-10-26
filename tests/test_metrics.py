"""Numbers for a monitoring system to collect, and who may collect them."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, metrics, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_users import account, browser
from tests.test_wall import CSRF, PASSWORD, add, wait_until, wall
from tests.settings_file import settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def collector(admin: TestClient, token: str = "") -> TestClient:
    """Something that is not a browser and has no session: a monitoring system, with or without the token."""
    client = TestClient(admin.app, client=("192.0.2.50", 40000), headers={"Authorization": f"Bearer {token}"} if token else {})
    client.portal = admin.portal
    return client


def samples(text: str) -> dict[str, float]:
    """The numbers in what was collected: 'name{labels}' -> value. Every line that is not a comment has to be one."""
    found = {}
    for line in text.splitlines():
        if line.startswith("#"):
            assert re.fullmatch(r"# (HELP|TYPE) qkvm_[a-z_]+ .+", line), line
            continue
        sample = re.fullmatch(r'(qkvm_[a-z_]+(?:\{(?:[a-z_]+="(?:[^"\\\n]|\\.)*",?)*\})?) (-?[0-9.]+(?:e[+-]?[0-9]+)?)', line)
        assert sample, f"not a line a collector can read: {line!r}"
        assert sample.group(1) not in found, f"said twice: {sample.group(1)}"
        found[sample.group(1)] = float(sample.group(2))
    return found


def test_metrics_are_off_until_an_admin_makes_a_token_and_need_it_from_then_on(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url, name="NAS", group="rack 1")
        assert collector(admin).get("/metrics").status_code == 404  # nothing there until it is switched on
        assert admin.get("/api/v1/metrics").json() == {"enabled": False, "created": None}
        account(admin, "olga", "operator")
        assert browser(admin, "olga").post("/api/v1/metrics/token").status_code == 403

        made = admin.post("/api/v1/metrics/token").json()
        token = made["token"]
        assert len(token) > 40 and token.startswith("qkvm_")
        assert token not in settings_text(tmp_path / "qkvm.json", encoding="utf-8")  # what is kept cannot be used to collect
        state = admin.get("/api/v1/metrics").json()
        assert state["enabled"] is True and "token" not in state  # shown once

        refused = collector(admin).get("/metrics")
        assert refused.status_code == 401 and refused.headers["www-authenticate"] == "Bearer"
        assert collector(admin, "qkvm_" + "x" * 43).get("/metrics").status_code == 401
        assert admin.get("/metrics").status_code == 401  # being signed in at the page is not what opens this

        wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "the stand-in never came online")
        collected = collector(admin, token).get("/metrics")
        assert collected.status_code == 200 and collected.headers["content-type"].startswith("text/plain; version=0.0.4")
        said = samples(collected.text)
        assert said[f'qkvm_info{{version="{metrics.__version__}"}}'] == 1
        assert said["qkvm_unlocked"] == 1 and said["qkvm_sessions"] == 2 and said["qkvm_devices_configured"] == 1  # the admin and olga
        assert said['qkvm_devices{state="online"}'] == 1 and said['qkvm_devices{state="offline"}'] == 0
        labels = f'id="{device}",device="NAS",kind="kvmd",group="rack 1"'
        assert said[f"qkvm_device_up{{{labels}}}"] == 1 and said[f"qkvm_device_picture{{{labels}}}"] == 1
        assert said[f"qkvm_device_last_seen_seconds{{{labels}}}"] <= 5
        assert said[f'qkvm_device_temperature_celsius{{{labels},sensor="device"}}'] == 42.5

        # A new token takes the place of the one before; switched off, there is nothing there again.
        newer = admin.post("/api/v1/metrics/token").json()["token"]
        assert newer != token and collector(admin, token).get("/metrics").status_code == 401
        assert collector(admin, newer).get("/metrics").status_code == 200
        assert admin.delete("/api/v1/metrics/token").status_code == 200
        assert collector(admin, newer).get("/metrics").status_code == 404
        events = [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]
        assert events.count("metrics_token_created") == 2 and events.count("metrics_switched_off") == 1


def test_names_cannot_break_what_is_collected(tmp_path: Path, fake: FakeKvm) -> None:
    # A device is called what its admin calls it, and two may be called the same. Neither may make a line
    # that a collector cannot read, or two lines that claim to be one thing: it would then reject them all.
    other = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            odd = 'rack "A"' + chr(92) + "top"
            first = add(admin, fake.url, name=odd)
            second = add(admin, other.url, name=odd)
            token = admin.post("/api/v1/metrics/token").json()["token"]
            said = samples(collector(admin, token).get("/metrics").text)
            spelt = 'device="rack ' + chr(92) + '"A' + chr(92) + '"' + chr(92) + chr(92) + 'top"'
            assert sum(1 for name in said if name.startswith("qkvm_device_up{") and spelt in name) == 2
            assert any(f'id="{first}"' in name for name in said) and any(f'id="{second}"' in name for name in said)
    finally:
        other.stop()
    assert metrics.label('a"b' + chr(92) + "c" + chr(10) + "d") == 'a' + chr(92) + '"b' + chr(92) + chr(92) + "c" + chr(92) + "nd"


def test_with_metrics_on_the_devices_stay_watched_after_the_last_sign_out(tmp_path: Path, fake: FakeKvm) -> None:
    # As with alerts: what is collected at night should not be "nobody is looking, so nothing is known".
    # (Started locked, which is where this is not so anyway: as it comes, the devices stay watched whatever is on.)
    with wall(tmp_path, locked_start=True) as admin:
        add(admin, fake.url)
        token = admin.post("/api/v1/metrics/token").json()["token"]
        assert admin.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        said = samples(collector(admin, token).get("/metrics").text)
        assert said["qkvm_unlocked"] == 1 and said["qkvm_sessions"] == 0
        assert any(name.startswith("qkvm_device_up{") for name in said)
    with wall(tmp_path, sign_in=False, locked_start=True) as later:  # restarted: until somebody signs in, the devices cannot be asked
        said = samples(collector(later, token).get("/metrics").text)
        assert said["qkvm_unlocked"] == 0 and said["qkvm_devices_configured"] == 1
        assert not any(name.startswith("qkvm_device_up{") for name in said)  # not known is not the same as down
        assert later.post("/api/v1/login", json={"password": PASSWORD}, headers=CSRF).status_code == 200
        assert samples(collector(later, token).get("/metrics").text)["qkvm_unlocked"] == 1


def test_a_servers_readings_are_collected_by_sensor() -> None:
    record = type("Record", (), {"id": "ab12", "name": "db-01", "kind": "redfish", "group": ""})()
    status = {
        "state": "online", "last_seen_ago": 3, "health": {"temp": None},
        "server": {"health": "Warning", "temperatures": [{"name": "CPU0_TEMP", "celsius": 61, "ok": True}, {"name": "odd", "celsius": None, "ok": True}]},
    }  # fmt: skip
    said = samples(metrics.render(started=1.0, unlocked=True, sessions=0, devices=[(record, status)], update_available=True))
    labels = 'id="ab12",device="db-01",kind="redfish",group=""'
    assert said[f'qkvm_device_temperature_celsius{{{labels},sensor="CPU0_TEMP"}}'] == 61
    assert said[f"qkvm_server_healthy{{{labels}}}"] == 0 and said["qkvm_update_available"] == 1
    assert not any('sensor="odd"' in name for name in said)  # a sensor without a reading is not a reading of nought
