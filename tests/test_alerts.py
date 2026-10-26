from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, kvm, update, vault
from qkvm.alerts import Alert, Watcher
from tests.fake_kvm import FakeKvm
from tests.test_users import OTHER, account, visitor
from tests.test_wall import add, snap, wait_until, wall
from tests.settings_file import settings_text


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


class Inbox:
    """A stand-in for the service alerts are posted to: keeps what arrives."""

    def __init__(self, status: int = 200, fail_first: int = 0) -> None:
        self.received: list[dict[str, Any]] = []
        self.fail_first = fail_first  # this many posts are answered "try later" before `status` is
        inbox = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                inbox.received.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(503 if len(inbox.received) <= inbox.fail_first else status)
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/hook"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def titles(self) -> list[str]:
        return [json.loads(item["body"])["title"] for item in self.received]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def inbox() -> Iterator[Inbox]:
    box = Inbox()
    yield box
    box.close()


def baseline() -> None:
    """Give the watcher time for the two looks after which it knows what "normal" is for each KVM."""
    time.sleep(0.6)


def test_a_change_counts_once_it_has_settled() -> None:
    watcher = Watcher()
    assert watcher.observe("a", "online") is None
    assert watcher.observe("a", "online") is None  # the first thing known about a KVM is not news
    assert watcher.observe("a", "offline") is None  # one bad look could be a hiccup
    assert watcher.observe("a", "online") is None
    assert watcher.observe("a", "offline") is None
    assert watcher.observe("a", "connecting") is None  # in-between states say nothing either way
    assert watcher.observe("a", "offline") == ("online", "offline")
    assert watcher.observe("a", "offline") is None  # told once
    assert watcher.observe("a", "no_signal") is None
    assert watcher.observe("a", "no_signal") == ("offline", "no_signal")
    watcher.forget("a")
    assert watcher.observe("a", "offline") is None and watcher.observe("a", "offline") is None


def test_each_service_is_spoken_to_in_its_own_way() -> None:
    alert = alerts.describe("Büro PC", "10.0.0.5", "online", "offline")
    assert (alert.kind, alert.title) == ("offline", "Büro PC is offline")
    assert alerts.describe("x", "", "no_signal", "online").title == "x has a picture again"
    assert alerts.describe("x", "", "offline", "online").kind == "recovered"
    assert alerts.describe("x", "", "online", "auth").kind == "problem"

    assert alerts.request_for("https://discord.com/api/webhooks/1/abc", "auto", alert)["json"]["content"].startswith("**Büro PC")
    assert "text" in alerts.request_for("https://hooks.slack.com/services/T/B/x", "auto", alert)["json"]
    ntfy = alerts.request_for("https://ntfy.sh/my-topic", "auto", alert)
    assert ntfy["headers"] == {"Title": "Bro PC is offline", "Tags": "warning", "Priority": "high"}
    assert ntfy["content"] == "The KVM stopped answering.".encode()
    generic = alerts.request_for("https://example.org/hook", "auto", alert)["json"]
    assert (generic["event"], generic["device"], generic["state"], generic["previous"]) == ("offline", "Büro PC", "offline", "online")
    assert "json" in alerts.request_for("https://ntfy.sh/topic", "json", alert)  # the admin's choice wins over the guess
    with pytest.raises(ValueError):
        alerts.check_url("ftp://example.org/x")
    with pytest.raises(ValueError):
        alerts.check_url("not an address")
    for odd in ("https://example.org/a" + chr(9) + "b", "https://example.org/a b", "https://exa" + chr(0) + "mple.org/x"):
        with pytest.raises(ValueError):  # the sender would choke on these later, with nobody watching
            alerts.check_url(odd)


def test_alerts_are_posted_when_a_kvm_changes(tmp_path: Path, inbox: Inbox) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            assert admin.post("/api/v1/alerts/test").status_code == 409  # nowhere to send it yet
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "nonsense"}).status_code == 422
            saved = admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url})
            assert saved.status_code == 200 and saved.json()["has_webhook"] is True
            assert inbox.url not in settings_text(tmp_path / "qkvm.json")  # stored encrypted: it may hold a token
            assert inbox.url not in json.dumps(admin.get("/api/v1/alerts").json())  # and never sent back to a browser

            assert admin.post("/api/v1/alerts/test").status_code == 200
            assert inbox.titles() == ["Test alert from qKVM"]
            assert admin.get(snap(device)).status_code == 200
            baseline()

            fake.state.signal = False
            wait_until(lambda: "Build server has no video signal" in inbox.titles(), "no alert for the lost signal")
            fake.state.signal = True
            wait_until(lambda: "Build server has a picture again" in inbox.titles(), "no alert for the signal coming back")
            fake.stop()
            wait_until(lambda: "Build server is offline" in inbox.titles(), "no alert for the KVM going offline", timeout=20)
            assert len(inbox.titles()) == 4  # each change told once, not on every look

            events = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "alert"]
            assert [(e["was"], e["state"]) for e in events][::-1] == [
                ("online", "no_signal"), ("no_signal", "online"), ("online", "offline"),
            ]  # fmt: skip
    finally:
        fake.stop()


def test_only_the_wanted_kinds_and_only_admins(tmp_path: Path, inbox: Inbox) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="NAS")
            account(admin, "olga", "operator")
            operator = visitor(admin, 50011)
            assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
            assert operator.get("/api/v1/alerts").status_code == 403
            assert operator.put("/api/v1/alerts", json={"enabled": False}).status_code == 403

            settings = {"enabled": True, "webhook": inbox.url, "no_signal": False}
            assert admin.put("/api/v1/alerts", json=settings).json()["no_signal"] is False
            baseline()
            fake.state.signal = False
            fake.state.password = "changed on the device"
            fake.state.tokens.clear()
            wait_until(lambda: "NAS: login rejected" in inbox.titles(), "no alert for the rejected login", timeout=20)
            assert "NAS has no video signal" not in inbox.titles()  # that kind was switched off
            # Keeping the address while changing something else, then forgetting it.
            assert admin.put("/api/v1/alerts", json={"enabled": True}).json()["has_webhook"] is True
            assert admin.put("/api/v1/alerts", json={"enabled": True, "forget_webhook": True}).json()["has_webhook"] is False
    finally:
        fake.stop()


def test_a_failing_address_is_reported_not_hidden(tmp_path: Path) -> None:
    broken = Inbox(status=500)
    try:
        with wall(tmp_path) as admin:
            admin.put("/api/v1/alerts", json={"enabled": True, "webhook": broken.url})
            reply = admin.post("/api/v1/alerts/test")
            assert (reply.status_code, reply.json()["code"]) == (502, "not_delivered")
            assert "HTTP 500" in admin.get("/api/v1/alerts").json()["last_error"]
    finally:
        broken.close()


def test_with_alerts_on_the_kvms_stay_watched_after_signing_out(tmp_path: Path, inbox: Inbox) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="NAS")
            admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url})
            assert admin.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
            assert admin.get("/api/v1/wall").status_code == 401
            assert admin.core.vault.unlocked is True  # type: ignore[attr-defined]
            wait_until(lambda: len(admin.core.sessions) == 0, "still signed in")  # type: ignore[attr-defined]
            baseline()
            fake.state.signal = False
            wait_until(lambda: "NAS has no video signal" in inbox.titles(), "nobody was watching", timeout=20)
        with wall(tmp_path / "other", locked_start=True) as admin:  # without alerts, and started locked: signing out locks everything
            assert admin.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
            assert admin.core.vault.unlocked is False  # type: ignore[attr-defined]
    finally:
        fake.stop()


def test_alert_objects_are_plain_data() -> None:
    assert Alert("test", "a", "b", "online", "online", "t", "x").kind == "test"


def test_an_alert_says_where_to_look_in_each_services_own_way() -> None:
    alert = alerts.describe("Build server", "10.0.0.5", "online", "offline")
    alert.link = "https://wall.example:8787/#tile=ab12cd34"
    assert alerts.request_for("https://example.org/hook", "auto", alert)["json"]["link"] == alert.link
    assert alerts.request_for("https://ntfy.sh/topic", "auto", alert)["headers"]["Click"] == alert.link  # a tap on the notification opens it
    assert alerts.request_for("https://hooks.slack.com/services/T/B/x", "auto", alert)["json"]["text"].endswith(alert.link)
    assert alerts.request_for("https://discord.com/api/webhooks/1/abc", "auto", alert)["json"]["content"].endswith(alert.link)
    plain = alerts.describe("Build server", "10.0.0.5", "online", "offline")
    assert alerts.request_for("https://example.org/hook", "auto", plain)["json"]["link"] is None  # none was given: none is made up


def test_a_muted_kvm_and_a_pause_keep_quiet_and_what_is_still_wrong_is_told_afterwards(tmp_path: Path, inbox: Inbox) -> None:
    quiet, loud = FakeKvm().start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            bench = add(admin, quiet.url, name="Test bench")
            build = add(admin, loud.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url, "link": "ftp://wall.example"}).status_code == 422
            saved = admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url, "link": "https://wall.example:8787/#display"})
            assert saved.status_code == 200 and saved.json()["link"] == "https://wall.example:8787/"
            # A machine on the test bench is switched on and off all day: nobody wants to hear about that one.
            edit = {"name": "Test bench", "url": quiet.url, "password": "", "alerts": False}
            assert admin.put(f"/api/v1/devices/{bench}", json=edit).status_code == 200
            assert [d["alerts"] for d in admin.get("/api/v1/wall").json()["devices"]] == [False, True]
            # Changing something else about it leaves that as it is.
            assert admin.put(f"/api/v1/devices/{bench}", json={"name": "Bench", "url": quiet.url, "password": ""}).status_code == 200
            assert admin.get("/api/v1/wall").json()["devices"][0]["alerts"] is False
            for device in (bench, build):
                assert admin.get(snap(device)).status_code == 200
            baseline()

            quiet.state.signal = loud.state.signal = False
            wait_until(lambda: "Build server has no video signal" in inbox.titles(), "no alert for the lost signal")
            time.sleep(0.5)
            assert inbox.titles() == ["Build server has no video signal"]  # and none about the bench
            assert json.loads(inbox.received[-1]["body"])["link"] == f"https://wall.example:8787/#tile={build}"
            loud.state.signal = True
            wait_until(lambda: inbox.titles()[1:] == ["Build server has a picture again"], "no alert for the signal coming back")

            # Maintenance: for an hour nothing is sent...
            paused = admin.post("/api/v1/alerts/pause", json={"minutes": 60})
            assert paused.status_code == 200 and paused.json()["paused_until"] > time.time() + 3500
            assert admin.get("/api/v1/alerts").json()["paused_until"] == paused.json()["paused_until"]
            assert '"paused_until"' in settings_text(tmp_path / "qkvm.json")  # a restart in the middle of it does not end it
            loud.state.signal = False
            time.sleep(1.0)
            assert len(inbox.titles()) == 2
            events = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "alert"]
            assert (events[0]["was"], events[0]["state"], events[0]["held"]) == ("online", "no_signal", True)  # written down all the same
            # ...and when it is over, what is not as it was before is told: nothing went wrong unseen.
            assert admin.post("/api/v1/alerts/pause", json={"minutes": 0}).json()["paused_until"] is None
            wait_until(lambda: inbox.titles()[2:] == ["Build server has no video signal"], "what went wrong during the pause was never told")

            # What went wrong and was put right within the pause is nobody's news afterwards.
            loud.state.signal = True
            wait_until(lambda: len(inbox.titles()) == 4, "no alert for the signal coming back")
            assert admin.post("/api/v1/alerts/pause", json={"minutes": 5}).status_code == 200
            loud.state.signal = False
            time.sleep(0.8)
            loud.state.signal = True
            time.sleep(0.8)
            assert admin.post("/api/v1/alerts/pause", json={"minutes": 0}).status_code == 200
            time.sleep(0.6)
            assert len(inbox.titles()) == 4

            account(admin, "olga", "operator")
            operator = visitor(admin, 50012)
            assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
            assert operator.post("/api/v1/alerts/pause", json={"minutes": 60}).status_code == 403
            assert "alerts" not in operator.get("/api/v1/wall").json()["devices"][0]  # how a tile is set up is for those who set it up
    finally:
        quiet.stop()
        loud.stop()


def test_a_link_that_a_service_could_not_be_sent_is_refused_when_it_is_typed(tmp_path: Path, inbox: Inbox) -> None:
    # An address with a letter outside ASCII in it was taken, and then every alert to ntfy failed where nobody
    # looks: the link travels in a header, which cannot carry it.
    with pytest.raises(ValueError):
        alerts.wall_link("https://wall.example/caf\u00e9/")
    with wall(tmp_path) as admin:
        refused = admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url, "link": "https://wall.example/caf\u00e9/"})
        assert refused.status_code == 422
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url, "link": "https://wall.example/caf%C3%A9/"}).status_code == 200
