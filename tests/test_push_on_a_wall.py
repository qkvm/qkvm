"""Alerts by Web Push on a wall: each account subscribes its own browsers, and is told what it may see.

Against a stand-in push service (tests/fake_push.py) that keeps every request as it came: what an alert says is proved
by decrypting what arrived with the browser's keys, as a phone does, and the wall's signature is checked with the key
the page is given. The push service's address is guarded as the wall's own network is: no request goes there.
"""

from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, kvm, server, update, vault, webpush
from qkvm.core import Core
from qkvm.store import Store
from qkvm.vault_storage import key_path
from tests.fake_kvm import FakeKvm
from tests.fake_push import NAMES, Browser, FakePush, signed
from tests.settings_file import settings_text
from tests.test_users import account, browser, visitor
from tests.test_wall import add, wait_until, wall


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
    monkeypatch.setattr(webpush, "RETRY_AFTER", (0.05, 0.1, 0.2))
    monkeypatch.setattr(server, "PUSH_TEST_EVERY", 0.0)  # (but where the pacing itself is tried)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakePush]:
    push = FakePush(tmp_path / "push")
    push.put_in_place(monkeypatch)
    yield push
    push.close()


def subscribe(client: Any, phone: Browser, name: str = "Chrome on Android", origin: str = "http://testserver") -> dict[str, Any]:
    """What the page does when "Turn on" is pressed: the wall's key first (made where there is none), then the subscription.
    `origin`: where the page was reached (the Origin a browser sends, which the wall holds to the Host it was asked by)."""
    key = client.post("/api/v1/push/key")
    assert key.status_code == 200, key.text
    host = origin.split("//", 1)[1]
    reply = client.post("/api/v1/push", json=phone.subscription(name, key=key.json()["key"]), headers={"Origin": origin, "Host": host})
    assert reply.status_code == 201, reply.text
    return dict(reply.json())


def test_a_browser_subscribes_and_its_test_alert_arrives_encrypted_and_signed(tmp_path: Path, service: FakePush) -> None:
    phone = Browser()
    with wall(tmp_path) as admin:
        state = admin.get("/api/v1/push").json()
        assert state == {"key": None, "alerts": False, "browsers": []}  # no key until somebody asks for one
        made = subscribe(admin, phone, origin="http://testserver")
        key = admin.get("/api/v1/push").json()["key"]
        assert key and admin.post("/api/v1/push/key").json()["key"] == key  # made once
        assert made["name"] == "Chrome on Android" and made["service"] == NAMES[0] and made["mine"] is True and made["account"] == "admin"
        # Nothing of it in clear in the settings file: neither the wall's key nor where the browser is told, nor its keys.
        text = settings_text(tmp_path / "qkvm.json")
        assert phone.endpoint not in text and phone.keys["auth"] not in text and phone.keys["p256dh"] not in text
        store = admin.core.store  # type: ignore[attr-defined]
        assert '"push_key"' in text and store.alerts.push_key is not None and webpush.WallKey(admin.core.vault.read(store.alerts.push_key, "alerts:push-key")).public_text == key  # type: ignore[attr-defined]
        assert json.dumps(admin.get("/api/v1/push").json()).count(phone.endpoint) == 0  # and never handed back to a page

        reply = admin.post(f"/api/v1/push/{made['id']}/test")
        assert reply.status_code == 200, reply.text
        assert reply.json()["last_sent"] is not None and reply.json()["last_error"] is None
        [got] = service.received
        said = phone.read(got)
        assert said["title"] == "Test alert from qKVM" and set(said) == {"title", "body", "tile", "kind", "at"} and said["kind"] == "test"
        claims, public = signed(got.headers["Authorization"])
        assert public == key and claims["aud"] == f"https://{NAMES[0]}"
        assert claims["sub"] == webpush.CONTACT
        assert got.headers["Urgency"] == "normal" and got.headers["TTL"] == str(webpush.TTL)


def test_the_contact_the_push_services_are_given_is_one_apples_takes() -> None:
    # (Before the release of 0.3.0: Apple's push service answers 403 BadJwtToken to a "sub" that is not a URL or a mailto:
    # on a name of the internet, localhost among them (web-push's own warning; Apple's list of the token's faults). It was
    # mailto:qkvm@localhost, and no alert would have reached an iPhone or Safari. It names the software, never the wall.)
    scheme, _, rest = webpush.CONTACT.partition(":")
    host = rest.removeprefix("//").split("/")[0] if scheme == "https" else rest.rpartition("@")[2]
    assert scheme in ("https", "mailto") and (scheme == "mailto") == ("@" in rest), webpush.CONTACT
    assert webpush.CONTACT.isascii() and " " not in webpush.CONTACT and "<" not in webpush.CONTACT
    labels = host.lower().split(".")
    assert len(labels) >= 2 and all(labels) and not labels[-1].isdigit(), host  # (a name, with a dot, and not a number)
    assert labels[-1] not in ("localhost", "local", "test", "invalid", "example", "internal", "lan", "home"), host
    assert webpush.CONTACT == "https://qkvm.com"


def test_the_wall_tells_the_push_service_nothing_of_its_address_as_whose_the_alerts_are(tmp_path: Path, service: FakePush) -> None:
    # (Changed by the final review of 0.3.0: the "sub" was the wall's https address as the browser reached it, else the
    # address alerts lead to, which told every push service where the wall is. It is a fixed contact that names neither.)
    phone = Browser()
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": False, "link": "https://kvm.example.net/"}).status_code == 200
        admin.core.store.server.allowed_hosts = ["wall.example.org"]  # type: ignore[attr-defined]  # (a name the wall is reached by)
        first = subscribe(admin, phone, origin="https://Wall.Example.org:8443")
        assert admin.post(f"/api/v1/push/{first['id']}/test").status_code == 200
        assert signed(service.received[-1].headers["Authorization"])[0]["sub"] == webpush.CONTACT == "https://qkvm.com"
        subscribe(admin, phone, origin="http://testserver")
        assert admin.post(f"/api/v1/push/{first['id']}/test").status_code == 200
        assert signed(service.received[-1].headers["Authorization"])[0]["sub"] == webpush.CONTACT
        kept = json.dumps([dataclasses.asdict(p) for p in admin.core.store.pushes])  # type: ignore[attr-defined]
        assert "wall.example.org" not in kept and "kvm.example.net" not in kept  # (nor kept)


def test_a_machines_alert_reaches_the_browsers_of_the_accounts_that_may_see_it_and_says_no_more(tmp_path: Path, service: FakePush) -> None:
    fake, other = FakeKvm().start(), FakeKvm().start()
    phones = {name: Browser(f"/send/{name}") for name in ("admin", "olga", "victor", "ivan")}
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server", group="Rack 1")
            hidden = add(admin, other.url, name="Mail server")
            account(admin, "olga", "viewer", devices=[], groups=["rack 1"])  # sees Rack 1
            account(admin, "victor", "operator", devices=[hidden])  # sees the other one only
            account(admin, "ivan", "viewer")
            subscribe(admin, phones["admin"])
            for name in ("olga", "victor", "ivan"):
                subscribe(browser(admin, name, port=50100 + len(name)), phones[name])
            suspended = admin.put("/api/v1/users/" + store_id(admin, "ivan"), json={"name": "ivan", "role": "viewer", "suspended": True})
            assert suspended.status_code == 200, suspended.text  # told nothing while suspended
            # Alerts on, with no webhook at all: the browsers are where they go.
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            time.sleep(0.6)  # (two looks: what is normal for each machine)
            fake.state.signal = False
            wait_until(lambda: len(service.received) >= 2, "no alert reached the browsers", timeout=20)
            time.sleep(0.5)
            reached = {got.path.rsplit("/", 1)[1]: got for got in service.received}
            assert set(reached) == {"admin", "olga"}  # not victor (another machine's), not ivan (suspended)
            said = phones["olga"].read(reached["olga"])
            assert said == {"title": "Build server has no video signal", "body": said["body"], "tile": device, "kind": "no_signal", "at": said["at"]}
            assert "plugged" in said["body"] and abs(said["at"] - time.time()) < 60
            whole = json.dumps(said)
            assert fake.url.split("//")[1] not in whole and "secret" not in whole and "testserver" not in whole  # no address, password or link
            assert reached["olga"].headers["Urgency"] == "high"
            # Paused: nothing goes to a browser either.
            assert admin.post("/api/v1/alerts/pause", json={"minutes": 60}).status_code == 200
            count = len(service.received)
            fake.state.signal = True
            time.sleep(1.0)
            assert len(service.received) == count
    finally:
        fake.stop()
        other.stop()


def store_id(admin: Any, name: str) -> str:
    return next(user["id"] for user in admin.get("/api/v1/users").json()["users"] if user["name"] == name)


def test_each_account_lists_and_removes_its_own_and_an_admin_everybodys(tmp_path: Path, service: FakePush) -> None:
    with wall(tmp_path) as admin:
        account(admin, "olga", "viewer")
        account(admin, "victor", "operator")
        olga, victor = browser(admin, "olga", port=50201), browser(admin, "victor", port=50202)
        hers = subscribe(olga, Browser("/send/olga"), name="Safari on iPhone")
        his = subscribe(victor, Browser("/send/victor"), name="Firefox on Windows")
        mine = subscribe(admin, Browser("/send/admin"))
        assert [b["id"] for b in olga.get("/api/v1/push").json()["browsers"]] == [hers["id"]]
        assert {b["id"]: b["account"] for b in admin.get("/api/v1/push").json()["browsers"]} == {hers["id"]: "olga", his["id"]: "victor", mine["id"]: "admin"}
        # Nobody else's, but for an admin; and a test only to one's own.
        assert olga.delete(f"/api/v1/push/{his['id']}").status_code == 404
        assert olga.post(f"/api/v1/push/{his['id']}/test").status_code == 404
        assert admin.post(f"/api/v1/push/{his['id']}/test").status_code == 404
        assert service.received == []
        assert admin.delete(f"/api/v1/push/{his['id']}").status_code == 200
        assert olga.delete(f"/api/v1/push/{hers['id']}").status_code == 200
        assert [b["id"] for b in admin.get("/api/v1/push").json()["browsers"]] == [mine["id"]]
        events = [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"].startswith("push_")]
        assert [(e["event"], e.get("browser"), e.get("why")) for e in events][::-1][-2:] == [("push_removed", "Firefox on Windows", "removed"), ("push_removed", "Safari on iPhone", "removed")]
        # An account that goes takes its browsers with it.
        theirs = subscribe(victor, Browser("/send/victor-again"))
        assert admin.delete("/api/v1/users/" + store_id(admin, "victor")).status_code == 200
        assert theirs["id"] not in {b["id"] for b in admin.get("/api/v1/push").json()["browsers"]}
        # The same browser again, by another account signed in there now: one record, for whoever turned it on last.
        shared = Browser("/send/shared")
        first = subscribe(olga, shared)
        again = subscribe(admin, shared, name="Edge on Windows")
        assert again["id"] == first["id"] and again["account"] == "admin" and olga.get("/api/v1/push").json()["browsers"] == []
        # ...where that is its own account or an admin. Not another (the final review of 0.3.0): whoever has a browser's
        # address would have had it told their alerts, and the account it was told them for none.
        key = olga.post("/api/v1/push/key").json()["key"]
        taken = olga.post("/api/v1/push", json=shared.subscription("Chrome on Android", key=key), headers={"Origin": "http://testserver", "Host": "testserver"})
        assert (taken.status_code, taken.json()["code"]) == (409, "conflict") and "another account's" in taken.json()["message"]
        assert {b["id"]: (b["account"], b["name"]) for b in admin.get("/api/v1/push").json()["browsers"]}[first["id"]] == ("admin", "Edge on Windows")


def test_a_token_has_no_browser_and_an_odd_subscription_is_refused(tmp_path: Path, service: FakePush) -> None:
    with wall(tmp_path) as admin:
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        bearer = {"Authorization": f"Bearer {token}"}
        script = visitor(admin, 50301)
        assert script.get("/api/v1/wall", headers=bearer).status_code == 200  # (the token works)
        for method, path in (("GET", "/api/v1/push"), ("POST", "/api/v1/push/key"), ("POST", "/api/v1/push")):
            reply = script.request(method, path, headers=bearer, json=Browser().subscription())
            assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), (method, path)
        key = admin.post("/api/v1/push/key").json()["key"]
        phone = Browser()
        for endpoint in ("http://push.example.com/x", "https://127.0.0.1/x", "https://10.0.0.5/x", "https://push.example.com:8443/x", "https://router/x", "https://nas.local/x"):
            reply = admin.post("/api/v1/push", json={**phone.subscription(), "endpoint": endpoint})
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), endpoint
        reply = admin.post("/api/v1/push", json={**phone.subscription(), "keys": {"p256dh": phone.keys["auth"], "auth": phone.keys["auth"]}})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid")
        # Subscribed with a key the wall no longer has: said, and not taken.
        reply = admin.post("/api/v1/push", json=phone.subscription(key=webpush.WallKey(webpush.new_key()).public_text))
        assert (reply.status_code, reply.json()["code"]) == (409, "changed")
        assert admin.post("/api/v1/push", json=phone.subscription(key=key)).status_code == 201
        assert admin.get("/api/v1/push").json()["browsers"][0]["name"] == "Chrome on Android"
        named = admin.post("/api/v1/push", json={**Browser("/send/2").subscription(), "name": "line\nbreak"})
        assert named.json()["name"] == "A browser"
        assert service.received == []


def test_a_browser_its_push_service_says_is_gone_is_taken_off(tmp_path: Path, service: FakePush) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="NAS")
            gone, kept = Browser("/send/gone"), Browser("/send/kept")
            first, second = subscribe(admin, gone), subscribe(admin, kept)
            service.service.then = [410]
            reply = admin.post(f"/api/v1/push/{first['id']}/test")
            assert (reply.status_code, reply.json()["code"]) == (502, "not_delivered") and "taken off the list" in reply.json()["message"]
            assert [b["id"] for b in admin.get("/api/v1/push").json()["browsers"]] == [second["id"]]
            # ...and at an alert as well, in the background.
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            time.sleep(0.6)
            service.service.then = [404]
            fake.state.signal = False
            wait_until(lambda: admin.get("/api/v1/push").json()["browsers"] == [], "a browser its push service said is gone is still listed", timeout=20)

            def removed() -> list[str]:
                return [e["why"] for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "push_removed"]

            # (Off the list as soon as it is taken off, and in the activity log once that is saved: waited for.)
            wait_until(lambda: len(removed()) >= 2, "the browser taken off is not in the activity log")
            assert removed() == ["gone", "gone"]
    finally:
        fake.stop()


def test_an_account_sends_itself_a_test_once_in_a_few_seconds(tmp_path: Path, service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    # A test goes to whatever address a browser gave: not as fast as a script can press the button.
    monkeypatch.setattr(server, "PUSH_TEST_EVERY", 5.0)
    with wall(tmp_path) as admin:
        account(admin, "olga", "viewer")
        olga = browser(admin, "olga", port=50401)
        mine, hers = subscribe(admin, Browser("/send/admin")), subscribe(olga, Browser("/send/olga"))
        assert admin.post(f"/api/v1/push/{mine['id']}/test").status_code == 200
        again = admin.post(f"/api/v1/push/{mine['id']}/test")
        assert (again.status_code, again.json()["code"]) == (429, "rate_limited") and 1 <= int(again.headers["retry-after"]) <= 5
        assert olga.post(f"/api/v1/push/{hers['id']}/test").status_code == 200  # (each account by itself)
        assert len(service.received) == 2


def test_a_push_service_that_is_away_is_said_beside_its_browser_and_the_others_carry_on(tmp_path: Path, service: FakePush) -> None:
    with wall(tmp_path) as admin:
        made = subscribe(admin, Browser())
        service.service.status = 503
        reply = admin.post(f"/api/v1/push/{made['id']}/test")
        assert (reply.status_code, reply.json()["code"]) == (502, "not_delivered") and "HTTP 503" in reply.json()["message"]
        assert "HTTP 503" in admin.get("/api/v1/push").json()["browsers"][0]["last_error"]
        assert admin.get("/api/v1/push").json()["browsers"][0]["id"] == made["id"]  # away is not gone


def test_a_name_that_leads_into_the_walls_own_network_is_never_sent_to(tmp_path: Path, service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        asked.append(host)
        return {"inside.example.com": ["192.168.1.20"], "rebound.example.com": ["142.250.74.10", "127.0.0.1"], "v6.example.com": ["fd00::7"]}[host]

    monkeypatch.setattr(webpush, "resolve", resolve)
    with wall(tmp_path) as admin:
        for host in ("inside.example.com", "rebound.example.com", "v6.example.com"):
            made = subscribe(admin, Browser(f"/send/{host}", host=host))
            reply = admin.post(f"/api/v1/push/{made['id']}/test")
            assert (reply.status_code, reply.json()["code"]) == (502, "not_delivered"), host
            assert "not on the internet" in reply.json()["message"] and "192.168" not in reply.json()["message"]
        assert asked == ["inside.example.com", "rebound.example.com", "v6.example.com"] and service.received == []


def test_the_key_and_the_browsers_are_kept_over_a_restart_and_go_with_a_reset(tmp_path: Path, service: FakePush) -> None:
    phone = Browser()
    with wall(tmp_path) as admin:
        made = subscribe(admin, phone)
        key = admin.get("/api/v1/push").json()["key"]
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/push").json()["key"] == key
        assert admin.post(f"/api/v1/push/{made['id']}/test").status_code == 200
        assert phone.read(service.received[-1])["kind"] == "test"
    # The settings file as a start reads it, by itself.
    store = Store(tmp_path / "qkvm.json", vault_key_file=key_path(tmp_path), protected=True)
    assert [p.id for p in store.pushes] == [made["id"]] and store.alerts.push_key is not None
    core = Core(tmp_path)
    core.reset_password()
    assert core.store.pushes == [] and core.store.alerts.push_key is None


def test_a_subscription_that_does_not_open_is_said_and_sent_nothing(tmp_path: Path, service: FakePush) -> None:
    with wall(tmp_path) as admin:
        made = subscribe(admin, Browser())
        store = admin.core.store  # type: ignore[attr-defined]
        store.pushes[0].secret = {"nonce": "AAAA", "data": "AAAA"}
        listed = admin.get("/api/v1/push").json()["browsers"][0]
        assert "does not open" in listed["last_error"]
        reply = admin.post(f"/api/v1/push/{made['id']}/test")
        assert (reply.status_code, reply.json()["code"]) == (502, "not_delivered")
        assert service.received == []


def test_an_alert_waiting_for_a_browser_is_not_sent_once_its_account_is_suspended(tmp_path: Path, service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.3.0, Codex's L1: whether an account may be told an alert was asked when it was put in, and
    # not again: one waiting to be tried again went out after the account was suspended.)
    monkeypatch.setattr(webpush, "RETRY_AFTER", (3.0,))
    seen: list[tuple[Any, str, bytes]] = []
    put = webpush.Pusher.put

    def noted(self: Any, target: Any, said: bytes, *more: Any, **named: Any) -> None:
        seen.append((self, target.id, said))
        put(self, target, said, *more, **named)

    monkeypatch.setattr(webpush.Pusher, "put", noted)
    fake = FakeKvm().start()
    phone = Browser("/send/suspended")
    try:
        with wall(tmp_path / "wall") as admin:
            device = add(admin, fake.url, name="build-01")
            user_id = account(admin, "viewer", "viewer", devices=[device])
            viewer = browser(admin, "viewer", port=50841)
            subscription = subscribe(viewer, phone)
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            time.sleep(0.6)
            service.service.status = 503  # (its push service away: the alert waits to be tried again)
            fake.state.signal = False
            wait_until(lambda: len(service.received) >= 1, "the first alert was never tried", 15)
            fake.state.signal = True
            wait_until(lambda: any(b'"kind":"recovered"' in said for _, _, said in seen), "the second alert was never put in", 5)
            pusher = seen[-1][0]
            reply = admin.put(f"/api/v1/users/{user_id}", json={"name": "viewer", "role": "viewer", "devices": [device], "suspended": True})
            assert reply.status_code == 200, reply.text
            service.service.status = 201
            wait_until(lambda: not pusher.waiting(subscription["id"]), "what waited was never let go of", 10)
            assert not [phone.read(got) for got in service.received if phone.read(got)["kind"] == "recovered"]
    finally:
        fake.stop()
