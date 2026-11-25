"""Several places for the alerts (0.4.0): each set up in its own way, sent to by itself, its deliveries logged, its test
answered in its service's own words, and every secret of it kept in the vault. Against stand-ins on loopback."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, destinations, egress, kvm, screens, server, update, vault
from tests.fake_alerts import DISCORD, HOOKS, NTFY, PAGERDUTY, RESEND, SLACK, TEAMS, TELEGRAM, Answer, FakeService
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_smtp import Behaviour, FakeSmtp
from tests.settings_file import settings_text
from tests.test_screens_on_a_wall import picture
from tests.test_screens_on_a_wall import shown as on_a_screen
from tests.test_users import OTHER, account, visitor
from tests.test_wall import add, snap, wait_until, wall


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
    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.05, 0.1, 0.2))
    monkeypatch.setattr(server, "TEST_EVERY", 0.5)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeService]:
    fake = FakeService(tmp_path / "services", monkeypatch)
    yield fake
    fake.close()


SLACK_URL = f"https://{SLACK}/services/T0/B0/S3CRETslackTOKEN"
PD_KEY = "R0UT1NGKEY0123456789abcdefABCDEF"
TG_TOKEN = "123456789:AAH-S3CRET_telegram"
# The token in the address of a Discord that refuses: with letters past f, so that no hex digits of the activity log's chain
# (each line's prev and mac) can hold it by chance ("abc" was in them once in some fifty runs).
REFUSED_TOKEN = "R3FUSEDdiscordTOKEN"


def added(admin: Any, **said: Any) -> dict[str, Any]:
    reply = admin.post("/api/v1/alerts/destinations", json=said)
    assert reply.status_code == 201, reply.text
    return dict(reply.json())


def listed(admin: Any) -> list[dict[str, Any]]:
    return list(admin.get("/api/v1/alerts/destinations").json()["destinations"])


def test_each_kind_is_set_up_tested_and_logged_with_its_secrets_kept_in_the_vault(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        made = [
            added(admin, kind="slack", name="Ops channel", url=SLACK_URL),
            added(admin, kind="teams", url=f"https://{TEAMS}/workflows/abc/triggers/manual/paths/invoke?sig=S1GteamsSECRET"),
            added(admin, kind="telegram", token=TG_TOKEN, chat="-1001234567890"),
            added(admin, kind="discord", url=f"https://{DISCORD}/api/webhooks/1/D1SCORDsecretTOKEN"),
            added(admin, kind="pagerduty", key=PD_KEY),
            added(admin, kind="resend", key="re_RESENDsecret_123", sender="qKVM <alerts@example.com>", to=["ops@example.com"]),
            added(admin, kind="ntfy", url=f"https://{NTFY}/alerts", token="tk_NTFYsecretTOKEN"),
        ]
        shown = json.dumps(admin.get("/api/v1/alerts/destinations").json())
        text = settings_text(tmp_path / "qkvm.json")
        for secret in ("S3CRETslackTOKEN", "S1GteamsSECRET", "AAH-S3CRET_telegram", "D1SCORDsecretTOKEN", PD_KEY, "RESENDsecret", "NTFYsecretTOKEN"):
            assert secret not in shown, secret  # never sent back to a browser
            assert secret not in text, secret  # sealed in the vault
        assert [one["destination"]["host"] for one in made] == [SLACK, TEAMS, TELEGRAM, DISCORD, PAGERDUTY, RESEND, NTFY]
        assert listed(admin)[-1]["has_token"] is True
        for one in made:
            reply = admin.post(f"/api/v1/alerts/destinations/{one['destination']['id']}/test")
            assert reply.status_code == 200, reply.text
        for host in (SLACK, TEAMS, TELEGRAM, DISCORD, PAGERDUTY, RESEND, NTFY):
            [arrived] = services.at(host)
            assert arrived.sni == host and "Test alert from qKVM" in arrived.body.decode(errors="replace") + json.dumps(arrived.headers)
        assert services.at(TELEGRAM)[0].path == f"/bot{TG_TOKEN}/sendMessage"
        assert services.at(PAGERDUTY)[0].path == "/v2/enqueue" and json.loads(services.at(PAGERDUTY)[0].body)["routing_key"] == PD_KEY
        assert services.at(RESEND)[0].headers["Authorization"] == "Bearer re_RESENDsecret_123"
        assert services.at(NTFY)[0].headers["Authorization"] == "Bearer tk_NTFYsecretTOKEN"
        log = admin.get(f"/api/v1/alerts/destinations/{made[0]['destination']['id']}/log").json()["deliveries"]
        assert [(each["ok"], each["test"], each["attempts"], each["said"]) for each in log] == [(True, True, 1, "HTTP 200")]


def test_a_test_says_the_services_own_answer_with_its_secrets_taken_out(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    services.answers[SLACK] = [Answer(403, b"invalid_token")]
    services.answers[TELEGRAM] = [Answer(400, b'{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}')]
    services.answers[HOOKS] = [Answer(400, b"no such hook: /hooks/W3BHOOKsecretPATH")]
    smtp = FakeSmtp(tmp_path / "smtp", Behaviour(login_ok=False))
    smtp.put_in_place(monkeypatch)
    services.trust(smtp.authority, monkeypatch)
    try:
        with wall(tmp_path) as admin:
            slack = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
            telegram = added(admin, kind="telegram", token=TG_TOKEN, chat="-100123")["destination"]["id"]
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/hooks/W3BHOOKsecretPATH")["destination"]["id"]
            mail = added(
                admin, kind="email", host="smtp.example.com", port=587, user="alerts@example.com", password="app-pass-word", sender="alerts@example.com", to=["ops@example.com"]
            )["destination"]["id"]
            said = {each: admin.post(f"/api/v1/alerts/destinations/{each}/test") for each in (slack, telegram, hook, mail)}
            assert {reply.status_code for reply in said.values()} == {502}
            assert said[slack].json()["message"] == "HTTP 403: invalid_token"
            assert said[telegram].json()["message"] == "HTTP 400: Bad Request: chat not found"
            assert said[hook].json()["message"] == "HTTP 400: no such hook: [hidden]"  # (its whole path: a token is in it)
            assert said[mail].json()["message"].startswith("535 5.7.8 Username and Password not accepted")
            assert "app-pass-word" not in json.dumps([reply.json() for reply in said.values()])
            shown = {one["id"]: one for one in listed(admin)}
            assert shown[slack]["last_error"] == "HTTP 403: invalid_token"
            # A test is one at a time for a destination. (A minute between two here: the half second of the other tests ran
            # out on Linux while the test before it looked up this computer's own addresses.)
            monkeypatch.setattr(server, "TEST_EVERY", 60.0)
            assert admin.post(f"/api/v1/alerts/destinations/{slack}/test").status_code == 429
    finally:
        smtp.close()


def parts_of(secret: str, length: int = 6) -> list[str]:
    """Every run of `length` characters of a secret that has a sign in it that is no hex digit (six hex digits may stand in
    a head of the activity log's chain by chance): a part of it, wherever it stands."""
    return [run for at in range(len(secret) - length + 1) if set(run := secret[at : at + length]) - set("0123456789abcdef")]


HOOK_LOGIN = f"https://hook-user:Hook-Pass-W0rd@{HOOKS}/qkvm"
HOOK_BASIC = base64.b64encode(b"hook-user:Hook-Pass-W0rd").decode()
TG_SAID = "123456789:AAH-S3CRET_TGb0t"  # (no run of six of it is a word the page says: "telegr" is in the kind's name)

# Each kind, as it is set up; what of it is secret (as it is typed, and as it is sent); and what its service says back of
# what it got: a part of it, as a service that cuts or masks what it repeats says it, or the form it was sent in. (Secrets
# with no word of six letters in them that the answers say anyway: "secret" is in the names of their fields.)
SAID_BACK: dict[str, tuple[dict[str, Any], list[str], str, Answer]] = {
    "slack": (dict(kind="slack", url=SLACK_URL), ["S3CRETslackTOKEN", "/T0/B0/S3CRETslackTOKEN"], SLACK, Answer(404, echo=lambda got: b"no_service " + got.path.encode()[:25])),
    "teams": (
        dict(kind="teams", url=f"https://{TEAMS}/workflows/abc/triggers/manual/paths/invoke?sig=S1GteamsSECRET"), ["S1GteamsSECRET"], TEAMS,
        Answer(400, b'{"error": {"code": "InvalidSignature", "message": "sig S1GteamsSE is not valid"}}'),
    ),
    "telegram": (
        dict(kind="telegram", token=TG_SAID, chat="-1001234567890"), [TG_SAID], TELEGRAM,
        Answer(404, echo=lambda got: json.dumps({"ok": False, "error_code": 404, "description": f"Not Found: {got.path[:22]}"}).encode()),
    ),
    "discord": (
        dict(kind="discord", url=f"https://{DISCORD}/api/webhooks/1/D1SCORDs3cr3tT0KEN"), ["D1SCORDs3cr3tT0KEN"], DISCORD,
        Answer(401, b'{"message": "Invalid Webhook Token D1SCORDs3cr", "code": 50027}'),
    ),
    "pagerduty": (
        dict(kind="pagerduty", key=PD_KEY), [PD_KEY], PAGERDUTY,
        Answer(400, echo=lambda got: json.dumps({"status": "invalid event", "message": "Event object is invalid", "errors": [f"routing_key {json.loads(got.body)['routing_key'][:14]} unknown"]}).encode()),
    ),
    "resend": (
        dict(kind="resend", key="re_RESENDs3cr3t_123", sender="qKVM <alerts@example.com>", to=["ops@example.com"]), ["re_RESENDs3cr3t_123"], RESEND,
        Answer(403, echo=lambda got: json.dumps({"name": "validation_error", "message": f"API key {got.headers['Authorization'][7:19]} is invalid"}).encode()),
    ),
    "ntfy": (
        dict(kind="ntfy", url=f"https://{NTFY}/alerts", token="tk_NTFYs3cr3tT0KEN"), ["tk_NTFYs3cr3tT0KEN"], NTFY,
        Answer(401, echo=lambda got: json.dumps({"code": 40101, "http": 401, "error": f"unauthorized: {got.headers['Authorization'][:20]}"}).encode()),
    ),
    "a webhook with a login in its address": (
        dict(kind="webhook", url=HOOK_LOGIN), ["Hook-Pass-W0rd", HOOK_BASIC], HOOKS,
        Answer(401, echo=lambda got: b"Unauthorized: " + got.headers["Authorization"].encode()),
    ),
}


@pytest.mark.parametrize("kind", list(SAID_BACK))
def test_what_a_service_says_back_of_what_it_was_sent_never_holds_a_secret_whole_or_in_part(
    tmp_path: Path, services: FakeService, caplog: pytest.LogCaptureFixture, kind: str
) -> None:
    # The outside review of 0.4.0, L1, swept through every alert destination: each service's own words are shown, with
    # the destination's secrets taken out whole. A part of one (a token cut, or the start of it masked) was not, nor the
    # Basic header a login in an address is sent as. Nothing a request carried as a secret comes back in an answer, the
    # delivery log, a log line or the activity log, whole or in part.
    caplog.set_level(logging.DEBUG)
    form, secrets, host, answer = SAID_BACK[kind]
    services.answers[host] = [answer]
    with wall(tmp_path) as admin:
        made = added(admin, **form)["destination"]["id"]
        reply = admin.post(f"/api/v1/alerts/destinations/{made}/test")
        assert reply.status_code == 502 and services.at(host), reply.text
        assert "[hidden]" in reply.json()["message"], reply.json()
        said = [
            reply.text, json.dumps(listed(admin)), json.dumps(admin.get(f"/api/v1/alerts/destinations/{made}/log").json()),
            json.dumps(admin.get("/api/v1/audit").json()), *(record.getMessage() for record in caplog.records),
        ]  # fmt: skip
    for secret in secrets:
        for text in said:
            assert secret not in text, (kind, text)
            assert not [part for part in parts_of(secret) if part in text], (kind, secret, text)


def test_a_mail_server_that_says_back_the_login_it_got_is_shown_without_it(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # (L1, the mail destination.) smtplib sends the password inside SMTP's AUTH, in base64 with the name (PLAIN): a server
    # that says that back showed it, as did one that repeats the password itself. (A person's password goes whole only, in
    # any spelling, never a part of it, so that a server's own words stay: the last look at the fixes of 0.4.0, L1. So the
    # server here says it back in another spelling, where it said back a part of it before that rule.)
    caplog.set_level(logging.DEBUG)
    password = "app-pass-word-S3CRET"
    plain = base64.b64encode(f"\0alerts@example.com\0{password}".encode()).decode()
    for behaviour, shown in (
        (Behaviour(login_ok=False, refusal=b"535 5.7.8 Authentication failed for", echo_auth=True), "535 5.7.8 Authentication failed for [hidden]"),
        (Behaviour(login_ok=False, refusal=b"535 5.7.8 bad password APP_PASS_WORD_S3CRET"), "535 5.7.8 bad password [hidden]"),
    ):
        smtp = FakeSmtp(tmp_path / f"smtp{behaviour.echo_auth}", behaviour)
        smtp.put_in_place(monkeypatch)
        services.trust(smtp.authority, monkeypatch)
        try:
            with wall(tmp_path / f"wall{behaviour.echo_auth}") as admin:
                mail = added(
                    admin, kind="email", host="smtp.example.com", port=587, user="alerts@example.com", password=password, sender="alerts@example.com", to=["ops@example.com"]
                )["destination"]["id"]
                reply = admin.post(f"/api/v1/alerts/destinations/{mail}/test")
                assert reply.status_code == 502 and reply.json()["message"] == shown, reply.text
                assert smtp.seen.logins == [("alerts@example.com", password, True)]
                said = [reply.text, json.dumps(listed(admin)), json.dumps(admin.get(f"/api/v1/alerts/destinations/{mail}/log").json()), *(record.getMessage() for record in caplog.records)]
        finally:
            smtp.close()
        for secret in (password, plain):
            for text in said:
                assert secret not in text, (behaviour, text)
                assert not [part for part in parts_of(secret) if part in text], (behaviour, secret, text)


def test_a_mail_password_logs_in_as_it_was_typed_and_one_too_short_to_hide_is_refused(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, round 6.2, M8 and H2, the whole way.) The blanks at a typed password's ends
    # were left out, and the server was sent another password. One of fewer than egress.LEAST_WHOLE characters is refused:
    # what the server says back is shown, and a password that short could not be told apart from its words.
    monkeypatch.setattr(server, "TEST_EVERY", 0.0)  # (two tests of one destination, one after the other)
    smtp = FakeSmtp(tmp_path / "smtp", Behaviour())
    smtp.put_in_place(monkeypatch)
    services.trust(smtp.authority, monkeypatch)
    said = {"kind": "email", "host": "smtp.example.com", "port": 587, "user": "alerts@example.com", "sender": "alerts@example.com", "to": ["ops@example.com"]}
    try:
        with wall(tmp_path) as admin:
            for short in ("q7z", "  ab  "):
                refused = admin.post("/api/v1/alerts/destinations", json={**said, "password": short})
                assert refused.status_code == 422 and "characters at the least" in refused.json()["message"], refused.text
            assert listed(admin) == []
            place = added(admin, **said, password="  spaced app password  ")["destination"]["id"]
            assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
            # Saved again with nothing typed, the saved one stays as it was typed; one too short typed in an edit is refused.
            assert admin.put(f"/api/v1/alerts/destinations/{place}", json={**said, "password": "", "to": ["oncall@example.com"]}).status_code == 200
            assert admin.post(f"/api/v1/alerts/destinations/{place}/test").status_code == 200
            assert admin.put(f"/api/v1/alerts/destinations/{place}", json={**said, "password": "OK"}).status_code == 422
            assert smtp.seen.logins == [("alerts@example.com", "  spaced app password  ", True)] * 2
    finally:
        smtp.close()


def delivered_by_a_courier(said: dict[str, Any]) -> alerts.Delivery:
    """An alert about a machine, delivered to the mail destination `said` sets up as the wall delivers one (alerts.Courier:
    its tries, after alerts.RETRY_AFTER): the line its delivery log gets."""
    config, secrets, _ = destinations.check("email", said, {})
    target = alerts.Target("mail", "email", config, secrets, False, False, "")

    async def own() -> egress.Own:
        return egress.Own(frozenset(), frozenset())

    courier = alerts.Courier(lambda _: target, own, lambda *_: None)
    asyncio.run(courier._deliver(target.id, [alerts.describe("Build server", "", "online", "offline", device_id="ab12cd34")]))
    [delivery] = courier.log[target.id]
    return delivery


MAILED = {"host": "smtp.example.com", "port": 587, "user": "alerts@example.com", "password": "app-pass-word", "sender": "alerts@example.com"}


def test_a_mail_refused_for_some_of_its_addresses_is_said_so_and_sent_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, round 6.2, M5, as an alert goes.) One address took the alert and the other
    # refused it, and the delivery was logged as a success: the one on call there missed every alert while the destination
    # looked well. Not delivered, the log says, and which address refused it, in the server's words with the password
    # taken out; and not tried again, for a "not now" either: the other address has it once.
    for refusal in (b"550 5.1.1 <oncall@example.com> unknown, login app-pass-word", b"451 4.3.0 Try again later"):
        smtp = FakeSmtp(tmp_path / f"smtp{refusal[:3].decode()}", Behaviour(refuse_rcpt_for={"oncall@example.com": refusal}))
        smtp.put_in_place(monkeypatch)
        try:
            delivery = delivered_by_a_courier({**MAILED, "to": ["ops@example.com", "oncall@example.com"]})
        finally:
            smtp.close()
        assert (delivery.ok, delivery.attempts) == (False, 1), delivery
        assert delivery.said.startswith("Delivered to 1 of 2 addresses, not tried again: refused for oncall@example.com (" + refusal[:9].decode()), delivery
        assert "app-pass-word" not in delivery.said
        assert [sent.to for sent in smtp.seen.messages] == [["ops@example.com"]]


def test_a_mail_the_server_took_is_delivered_once_whatever_comes_after(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2, M6, as an alert goes.) The server took the alert and hung up: it was logged as failed after four tries,
    # and the server had four copies of it.
    smtp = FakeSmtp(tmp_path / "smtp", Behaviour(hang_up_after_data=True))
    smtp.put_in_place(monkeypatch)
    try:
        delivery = delivered_by_a_courier({**MAILED, "to": ["ops@example.com"]})
    finally:
        smtp.close()
    assert (delivery.ok, delivery.attempts, delivery.said) == (True, 1, "250 2.0.0 OK queued as 12345")
    assert len(smtp.seen.messages) == 1


def test_a_webhooks_signing_secret_is_never_said_back_for_it_never_travels(tmp_path: Path, services: FakeService) -> None:
    # (L1, the signed webhook.) Its secret signs each alert and goes nowhere: a receiver that says back everything it got
    # (each header, the signature among them, and the body) has none of it to say.
    services.answers[HOOKS] = [Answer(400, echo=lambda got: json.dumps(got.headers).encode() + got.body)]
    with wall(tmp_path) as admin:
        made = added(admin, kind="webhook", url=f"https://{HOOKS}/signed")
        secret = made["signing_secret"]
        reply = admin.post(f"/api/v1/alerts/destinations/{made['destination']['id']}/test")
        assert reply.status_code == 502 and "webhook-signature" in services.at(HOOKS)[0].headers
        said = reply.text + json.dumps(listed(admin)) + json.dumps(admin.get(f"/api/v1/alerts/destinations/{made['destination']['id']}/log").json())
    assert secret not in said and not [part for part in parts_of(secret.removeprefix("whsec_")) if part in said]


def test_a_webhooks_signing_secret_is_shown_once_and_signs_every_alert(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        made = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")
        secret, hook = made["signing_secret"], made["destination"]["id"]
        assert secret.startswith("whsec_") and made["destination"]["signed"] is True
        assert secret not in json.dumps(admin.get("/api/v1/alerts/destinations").json()) and secret not in settings_text(tmp_path / "qkvm.json")
        assert admin.post(f"/api/v1/alerts/destinations/{hook}/test").status_code == 200
        [arrived] = services.at(HOOKS)

        def verified(arrived: Any, key: str) -> bool:
            head = arrived.headers
            mac = hmac.new(base64.b64decode(key[6:]), f"{head['webhook-id']}.{head['webhook-timestamp']}.".encode() + arrived.body, hashlib.sha256)
            return bool(head["webhook-signature"] == "v1," + base64.b64encode(mac.digest()).decode())

        assert verified(arrived, secret) and json.loads(arrived.body)["app"] == "QKVM"
        # A new one: the old one no longer checks out.
        again = admin.post(f"/api/v1/alerts/destinations/{hook}/secret").json()["signing_secret"]
        time.sleep(destinations_test_every())
        assert again != secret and admin.post(f"/api/v1/alerts/destinations/{hook}/test").status_code == 200
        latest = services.at(HOOKS)[-1]
        assert verified(latest, again) and not verified(latest, secret)


def destinations_test_every() -> float:
    return server.TEST_EVERY


def test_this_computer_and_its_network_are_not_sent_to_whatever_is_typed(tmp_path: Path) -> None:
    import socket

    with socket.socket() as listening:
        listening.bind(("127.0.0.1", 0))
        listening.listen()
        listening.settimeout(0.3)
        port = listening.getsockname()[1]
        with wall(tmp_path) as admin:
            made = added(admin, kind="webhook", url=f"http://127.0.0.1:{port}/hook")["destination"]["id"]
            reply = admin.post(f"/api/v1/alerts/destinations/{made}/test")
            assert reply.status_code == 502 and "this computer (loopback)" in reply.json()["message"], reply.text
            # The wall itself, on this computer or on its own address: never, switch or no switch (the owner's decision of
            # 2026-11-17; this wall's port, as its settings say).
            wall_port = admin.core.store.server.port  # type: ignore[attr-defined]
            for private in (False, True):
                itself = added(admin, kind="webhook", url=f"http://127.0.0.1:{wall_port}/api/v1/wall", private=private)["destination"]["id"]
                reply = admin.post(f"/api/v1/alerts/destinations/{itself}/test")
                assert reply.status_code == 502 and "this wall" in reply.json()["message"], reply.text
            metadata = added(admin, kind="webhook", url="http://169.254.169.254/latest/meta-data/", private=True)["destination"]["id"]
            assert "link-local" in admin.post(f"/api/v1/alerts/destinations/{metadata}/test").json()["message"]
            lan = added(admin, kind="ntfy", url="http://192.168.1.20/topic")["destination"]["id"]
            assert "private address" in admin.post(f"/api/v1/alerts/destinations/{lan}/test").json()["message"]
        with pytest.raises(socket.timeout):
            listening.accept()  # nothing ever came


def test_what_a_destination_does_not_take_is_refused_when_it_is_typed(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        for said in (
            {"kind": "teams", "url": "https://contoso.webhook.office.com/webhookb2/a@b/IncomingWebhook/c/d"},
            {"kind": "telegram", "token": "123:abc@attacker.example/x", "chat": "1"},
            {"kind": "email", "host": "smtp.example.com", "port": 25, "user": "u", "password": "p", "sender": "a@example.com", "to": ["b@example.com"]},
            {"kind": "slack", "url": "javascript:alert(1)"},
            {"kind": "carrier-pigeon"},
            {"kind": "slack", "url": SLACK_URL, "least": "apocalyptic"},
            {"kind": "slack", "url": SLACK_URL, "quiet_from": 600},
            {"kind": "slack", "url": SLACK_URL, "remind": 7},
        ):
            reply = admin.post("/api/v1/alerts/destinations", json=said)
            assert reply.status_code == 422, (said, reply.text)
        assert "retired" in admin.post("/api/v1/alerts/destinations", json={"kind": "teams", "url": "https://outlook.office.com/webhook/x"}).json()["message"]
        assert listed(admin) == []


def test_only_an_admin_sees_or_changes_where_alerts_go(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        one = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
        account(admin, "olga", "operator")
        operator = visitor(admin, 50021)
        assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        for method, path in (
            ("GET", "/api/v1/alerts/destinations"), ("POST", "/api/v1/alerts/destinations"), ("PUT", f"/api/v1/alerts/destinations/{one}"),
            ("DELETE", f"/api/v1/alerts/destinations/{one}"), ("POST", f"/api/v1/alerts/destinations/{one}/test"),
            ("GET", f"/api/v1/alerts/destinations/{one}/log"), ("POST", f"/api/v1/alerts/destinations/{one}/secret"),
        ):  # fmt: skip
            assert operator.request(method, path, json={"kind": "slack"}).status_code == 403, (method, path)


def test_a_change_goes_to_each_destination_that_asked_for_it_and_a_saved_secret_is_kept(tmp_path: Path, services: FakeService) -> None:
    rack, desk = FakeKvm().start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            in_rack = add(admin, rack.url, name="Rack server", group="Rack 3")
            add(admin, desk.url, name="Desk PC")
            everything = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
            critical = added(admin, kind="pagerduty", key=PD_KEY, least="critical")["destination"]["id"]
            rack_only = added(admin, kind="discord", url=f"https://{DISCORD}/api/webhooks/1/abc", groups=["rack 3"], devices=[])["destination"]["id"]
            # Changed without typing its secret again: the saved one is kept.
            assert admin.put(f"/api/v1/alerts/destinations/{rack_only}", json={"kind": "discord", "name": "Rack room", "groups": ["Rack 3"], "devices": []}).status_code == 200
            assert admin.put(f"/api/v1/alerts/destinations/{rack_only}", json={"kind": "slack"}).status_code == 422  # a destination keeps its kind
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            for device in admin.get("/api/v1/wall").json()["devices"]:
                assert admin.get(snap(device["id"])).status_code == 200
            time.sleep(0.6)
            rack.state.signal = desk.state.signal = False  # a picture lost: a warning
            def slack_said() -> str:
                return " ".join(json.loads(each.body)["text"] for each in services.at(SLACK))

            wait_until(lambda: len(services.at(DISCORD)) >= 1 and "Rack server" in slack_said() and "Desk PC" in slack_said(), "nothing was told", timeout=20)
            time.sleep(0.5)
            assert services.at(PAGERDUTY) == []  # it asked for critical alone
            assert "Rack server" in json.loads(services.at(DISCORD)[0].body)["content"] and "Desk PC" not in json.dumps([json.loads(each.body) for each in services.at(DISCORD)])
            rack.stop()  # offline: critical
            wait_until(lambda: len(services.at(PAGERDUTY)) >= 1, "PagerDuty was not told", timeout=20)
            event = json.loads(services.at(PAGERDUTY)[0].body)
            assert (event["event_action"], event["dedup_key"], event["payload"]["severity"]) == ("trigger", f"qkvm/{in_rack}/down", "critical")
            log = admin.get(f"/api/v1/alerts/destinations/{everything}/log").json()["deliveries"]
            assert log and all(each["ok"] for each in log)
            assert admin.delete(f"/api/v1/alerts/destinations/{critical}").status_code == 200
            assert [one["id"] for one in listed(admin)] == [everything, rack_only]
    finally:
        rack.stop()
        desk.stop()


@pytest.mark.parametrize("edit", ["its address", "its name and what it hears"])
def test_a_destination_edited_to_send_elsewhere_starts_with_nothing_known(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, edit: str) -> None:
    # (The outside review of 0.4.0, bugs round 2, M6.) What a destination was told was kept by its id: edited to send to
    # another room, the new room was told that a machine was back to normal, and that backups were made again, of troubles
    # told to the old one, and reminded of them. Edited to another receiver (address, chat, routing key, recipients) it
    # starts with nothing known, and what waits for it is dropped; its name or what it is told of keeps what it knows.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    monkeypatch.setattr(server, "REMINDER_MINUTE", 0.01)  # (a reminder after 30 minutes: 0.3 s here)
    answering, let_go, busy = held_busy()
    real = backup.make
    fake = FakeKvm().start()

    def at(path: str) -> list[str]:
        return [json.loads(each.body)["event"] for each in services.at(HOOKS) if each.path == path]

    try:
        with wall(tmp_path / "data") as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/old-room", remind=30)["destination"]["id"]
            path = f"/api/v1/alerts/destinations/{hook}"
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            made_key(admin)
            set_up(admin, tmp_path / "backups")
            monkeypatch.setattr(backup, "make", backup_failing)
            assert admin.post("/api/v1/backups/run").json()["ok"] is False
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            wait_until(lambda: at("/old-room")[:2] == ["backup", "no_signal"], "the old room was never told", 20)
            if edit == "its address":
                changed = {"kind": "webhook", "url": f"https://{HOOKS}/new-room", "remind": 30}
            else:
                changed = {"kind": "webhook", "name": "Ops", "events": ["no_signal", "backup", "recovered"], "remind": 30}
            assert admin.put(path, json=changed).status_code == 200
            time.sleep(1.0)  # (still dark: a reminder there is due three times by now)
            monkeypatch.setattr(backup, "make", real)
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
            fake.state.signal = True
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            if edit != "its address":
                wait_until(lambda: at("/old-room").count("recovered") == 2, "the old room was never told both ends", 10)
                return
            time.sleep(1.0)
            assert at("/new-room") == [], f"the new room was told what the old one knew: {at('/new-room')}"
            assert admin.core.store.backups.told == []  # type: ignore[attr-defined]
            # What waits for it when it is edited to send elsewhere goes to neither receiver.
            services.answers[HOOKS] = [busy, Answer(200, b"ok")]
            fake.state.signal = False
            assert answering.wait(20), "the new room was never told of the next trouble"
            changed["url"] = f"https://{HOOKS}/third-room"
            assert admin.put(path, json=changed).status_code == 200
            let_go.set()
            wait_until(lambda: any(dropped_said(each) for each in admin.get(path + "/log").json()["deliveries"]), "what waited was never dropped", 10)
            assert any("elsewhere" in each["said"] for each in admin.get(path + "/log").json()["deliveries"] if dropped_said(each))
            fake.state.signal = True
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            time.sleep(1.0)
            assert (at("/new-room"), at("/third-room")) == (["no_signal"], []), (at("/new-room"), at("/third-room"))
    finally:
        let_go.set()
        fake.stop()


def test_a_service_that_is_away_is_tried_again_one_that_says_no_is_not_and_the_activity_log_is_not_flooded(tmp_path: Path, services: FakeService) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            busy = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
            refusing = added(admin, kind="discord", url=f"https://{DISCORD}/api/webhooks/1/{REFUSED_TOKEN}")["destination"]["id"]
            services.answers[SLACK] = [Answer(503, b"busy"), Answer(429, b"rate_limited", {"Retry-After": "1"}), Answer(200, b"ok")]
            services.answers[DISCORD] = [Answer(400, b'{"message":"Invalid Webhook Token","code":50027}')]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            wait_until(lambda: any(each["ok"] for each in admin.get(f"/api/v1/alerts/destinations/{busy}/log").json()["deliveries"]), "never delivered", timeout=20)
            [done] = admin.get(f"/api/v1/alerts/destinations/{busy}/log").json()["deliveries"]
            assert done["attempts"] == 3
            arrivals = [each for each in services.arrived if each.host == SLACK]
            assert len(arrivals) == 3
            wait_until(lambda: admin.get(f"/api/v1/alerts/destinations/{refusing}/log").json()["deliveries"], "no try at Discord", timeout=10)
            [refused] = admin.get(f"/api/v1/alerts/destinations/{refusing}/log").json()["deliveries"]
            assert (refused["ok"], refused["attempts"], refused["said"]) == (False, 1, "HTTP 400: Invalid Webhook Token")
            fake.state.signal = True
            wait_until(lambda: len(services.at(DISCORD)) >= 2, "the second alert never went to Discord", timeout=20)
            time.sleep(0.3)
            entries = admin.get("/api/v1/audit").json()["entries"]
            failed = [each for each in entries if each["event"] == "alert_not_delivered"]
            assert len(failed) == 1 and failed[0]["said"] == "HTTP 400: Invalid Webhook Token" and REFUSED_TOKEN not in json.dumps(failed)
            services.answers[DISCORD] = [Answer(204, b"")]
            time.sleep(destinations_test_every())
            fake.state.signal = False
            wait_until(lambda: any(each["event"] == "alert_delivered_again" for each in admin.get("/api/v1/audit").json()["entries"]), "never said it works again", timeout=20)
    finally:
        fake.stop()


def stopped(admin: Any, hook: str, how: str) -> None:
    """Alerts stopped, in one of the ways an admin stops them: the destination switched off, all of them, a pause, or its
    quiet hours, set to begin now."""
    if how == "the destination switched off":
        reply = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "enabled": False})
    elif how == "alerts switched off":
        reply = admin.put("/api/v1/alerts", json={"enabled": False})
    elif how == "a pause":
        reply = admin.post("/api/v1/alerts/pause", json={"minutes": 60})
    else:
        now = time.localtime()
        minute = now.tm_hour * 60 + now.tm_min
        reply = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "quiet_from": minute, "quiet_to": (minute + 120) % 1440})
    assert reply.status_code == 200, reply.text


# What a switch does to what waits for a destination: the destination switched off, or alerts as a whole. A pause and quiet
# hours are no switch: they stop new alerts only (judged when an alert is routed), and what was handed to a destination
# before they began goes as it would have.
OFFS = ["the destination switched off", "alerts switched off"]
WINDOWS = ["a pause", "its quiet hours"]


def dropped_said(said: dict[str, Any]) -> bool:
    """Whether a delivery's line says it was not sent by the wall's own rule (a switch, while it waited): no failure."""
    return bool(said["ok"] is False and said["withheld"] and said["said"].startswith("Not sent: "))


def switched_on(admin: Any, hook: str, how: str) -> None:
    """What `stopped` switched off, on again."""
    if how == "the destination switched off":
        reply = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "enabled": True})
    else:
        reply = admin.put("/api/v1/alerts", json={"enabled": True})
    assert reply.status_code == 200, reply.text


@pytest.mark.parametrize("how", OFFS)
def test_what_waits_to_be_tried_again_is_not_sent_once_alerts_are_switched_off(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # The second outside review of 0.4.0, M4: a delivery waiting to be tried again asked before each try only whether its
    # destination was still there and its secrets opened: switched off, it was sent all the same. Switched off (the
    # destination, or alerts), what waits is dropped, and its delivery log says why; nothing of it is told later.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.0,))
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)
            stopped(admin, hook, how)
            wait_until(lambda: admin.get(f"/api/v1/alerts/destinations/{hook}/log").json()["deliveries"], "the delivery was never said", timeout=10)
            time.sleep(0.3)
            assert len(services.at(HOOKS)) == 1, f"tried again after {how}"
            [said] = admin.get(f"/api/v1/alerts/destinations/{hook}/log").json()["deliveries"]
            assert said["attempts"] == 1 and dropped_said(said), said
            switched_on(admin, hook, how)
            time.sleep(1.5)
            assert len(services.at(HOOKS)) == 1, f"what {how} dropped was told after all"
    finally:
        fake.stop()


def held_busy() -> tuple[threading.Event, threading.Event, Answer]:
    """A service's busy answer (503), held until `let_go` is set (`answering` is set as it is asked): what follows waits
    behind it, and its retry comes after whatever the test did meanwhile, however slow the computer."""
    answering, let_go = threading.Event(), threading.Event()

    def busy(arrived: Any) -> bytes:
        answering.set()
        let_go.wait(20)
        return b"busy"

    return answering, let_go, Answer(503, echo=busy)


@pytest.mark.parametrize("how", OFFS)
def test_what_waited_when_a_switch_was_turned_off_goes_no_more_though_it_is_on_again_before_its_next_try(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # (The outside review of 0.4.0, bugs round 2, M3.) The switches were asked at each try: switched off and on again before
    # the next try of what waited, it went, and was logged as delivered. What was handed to a destination before its switch,
    # or alerts', was turned off is dropped at its next try, whatever the switch says by then; what is handed over after it
    # is on again goes as ever.
    answering, let_go, busy = held_busy()
    services.answers[HOOKS] = [busy, Answer(200, b"ok")]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            assert answering.wait(20), "the alert was never sent"
            stopped(admin, hook, how)
            switched_on(admin, hook, how)
            let_go.set()  # (busy: tried again once it is on again)
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: admin.get(log).json()["deliveries"], "its next try was never said", 10)
            time.sleep(0.3)
            assert len(services.at(HOOKS)) == 1, f"what waited went after {how} and on again: {events_told(services)}"
            [said] = admin.get(log).json()["deliveries"]
            assert said["attempts"] == 1 and dropped_said(said), said
            fake.state.signal = True  # (back: no news there, its trouble was dropped)
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            fake.state.signal = False  # (in trouble again, handed over after the switch is on: told)
            services.wait_for(HOOKS, 2, timeout=20)
            assert events_told(services) == ["no_signal", "no_signal"], events_told(services)
    finally:
        let_go.set()
        fake.stop()


def events_told(services: FakeService) -> list[str]:
    return [json.loads(each.body)["event"] for each in services.at(HOOKS)]


@pytest.mark.parametrize("how", OFFS)
def test_a_trouble_a_switch_dropped_is_not_followed_by_back_to_normal_or_a_reminder_alone(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # (The final look at 0.4.0, M1.) What a destination knows of a machine was written down as the alert was handed to it:
    # a trouble a switch dropped while it waited to be tried again left it saying that trouble was told there, so once
    # switched on again the destination was reminded of it, and told the machine was back to normal, of a trouble it never
    # heard of (PagerDuty: a resolve with no incident). Dropped, it knows of the machine what it knew before: nothing of it
    # is told there until the machine is in trouble again, and that trouble, and its end, are told as any other.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.0,))
    monkeypatch.setattr(server, "REMINDER_MINUTE", 0.01)  # (a reminder after 30 minutes: a third of a second here)
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm", remind=30)["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)  # (503: it waits to be tried again)
            stopped(admin, hook, how)
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: any(dropped_said(each) for each in admin.get(log).json()["deliveries"]), "it was never dropped", timeout=10)
            if how == "the destination switched off":
                on = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "enabled": True, "remind": 30})
            else:
                on = admin.put("/api/v1/alerts", json={"enabled": True})
            assert on.status_code == 200, on.text
            time.sleep(1.5)  # (still without a picture: a reminder of what was told would be due by now)
            assert len(services.at(HOOKS)) == 1, f"reminded of a trouble it never heard of: {events_told(services)}"
            fake.state.signal = True
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            time.sleep(1.5)
            assert len(services.at(HOOKS)) == 1, f"back to normal told where its trouble never arrived: {events_told(services)}"
            fake.state.signal = False  # (in trouble again: told, and its end after it)
            services.wait_for(HOOKS, 2, timeout=20)
            fake.state.signal = True
            wait_until(lambda: events_told(services)[-1] == "recovered", "its end was never told", timeout=20)
            assert events_told(services)[1] == "no_signal", events_told(services)
    finally:
        fake.stop()


@pytest.mark.parametrize("how", OFFS)
def test_back_to_normal_waiting_behind_a_trouble_a_switch_dropped_goes_no_more(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # (M1, its end on its way.) A machine back while its trouble waits to be tried again: its "back to normal" waits behind
    # the trouble. A switch drops the trouble at its next try; switched on again before the end's turn came, the end went
    # there alone. It is dropped too: nothing of that trouble was told there.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (3.0,))
    monkeypatch.setitem(destinations.SPACING, "webhook", 3.0)  # (room between the two, as a kind a person reads has)
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)  # (503: it waits three seconds to be tried again)
            fake.state.signal = True
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            stopped(admin, hook, how)
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: admin.get(log).json()["deliveries"], "the trouble's try was never said", timeout=10)
            [first] = admin.get(log).json()["deliveries"]
            assert first["attempts"] == 1 and dropped_said(first), f"the machine was seen back only after the trouble's retry: {first}"
            switched_on(admin, hook, how)
            wait_until(lambda: len(admin.get(log).json()["deliveries"]) == 2 or len(services.at(HOOKS)) > 1, "its end never had its turn", timeout=10)
            time.sleep(0.3)
            assert len(services.at(HOOKS)) == 1, f"back to normal told where its trouble never arrived: {events_told(services)}"
            end = admin.get(log).json()["deliveries"][0]
            assert dropped_said(end) and end["events"] == ["recovered"], end
    finally:
        fake.stop()


def test_a_trouble_dropped_while_alerts_are_switched_off_stays_untold_over_a_restart(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The narrow look at 0.4.0, M1.) What a destination knows of a machine was written down after each look of the alert
    # round, and there is no look while alerts are switched off: a trouble they dropped was taken back out of it in memory
    # alone. Restarted before they were switched on again, the wall took that trouble for told there, and its "back to
    # normal" went there alone. It is written down whatever the switches say, and once more as qKVM stops.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.0,))
    monkeypatch.setattr(alerts, "STARTING", 0.5)
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    data = tmp_path / "data"
    fake = FakeKvm().start()
    try:
        with wall(data) as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)  # (503: it waits to be tried again)
            assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: any(dropped_said(each) for each in admin.get(log).json()["deliveries"]), "it was never dropped", timeout=10)
        with wall(data) as admin:  # (restarted at once, alerts still switched off)
            known = dict(admin.core.watcher.heard.get(hook) or {})  # type: ignore[attr-defined]
            assert known.get(device) == "", f"the trouble dropped came back as told there: {known}"
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            time.sleep(1.0)  # (STARTING: what differs from what was written down is believed after it)
            fake.state.signal = True
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 20)  # type: ignore[attr-defined]
            time.sleep(1.5)
            assert len(services.at(HOOKS)) == 1, f"back to normal told where its trouble never arrived: {events_told(services)}"
    finally:
        fake.stop()


def watched_for_no_signal(admin: Any, fake: FakeKvm) -> str:
    """A tile with a screen, watched for no signal for a minute (screens.MINUTE)."""
    office = add(admin, fake.url, name="Office PC")
    edit = {"name": "Office PC", "url": fake.url, "password": "", "no_signal_minutes": 1}
    assert admin.put(f"/api/v1/devices/{office}", json=edit).status_code == 200
    return office


def seen_lit(admin: Any, office: str) -> None:
    """Alerts on: the tile on a screen until the wall holds a picture of it with a signal, and the alert round knows it as
    online."""

    def kept() -> bool:
        on_a_screen(admin, office, 0.1)
        machine = admin.core.screens._machines.get(office)
        return machine is not None and machine.last_lit is not None and admin.core.watcher.state(office) == "online"

    wait_until(kept, "the wall kept no picture of the tile with a signal", 30)


def switched(admin: Any, hook: str, how: str, on: bool) -> None:
    """As `stopped` and `switched_on`, with the destination's reminders kept (every 30 minutes): a form without them sets none."""
    if how == "the destination switched off":
        reply = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "enabled": on, "remind": 30})
    else:
        reply = admin.put("/api/v1/alerts", json={"enabled": on})
    assert reply.status_code == 200, reply.text


def titles_told(services: FakeService) -> list[str]:
    return [json.loads(each.body)["title"] for each in services.at(HOOKS)]


@pytest.mark.parametrize("how", OFFS)
def test_a_screen_watchs_alert_a_switch_dropped_is_followed_there_by_no_reminder_and_no_end(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str, a_video_worker_first: None
) -> None:
    # (The narrow look at 0.4.0, M2.) A screen watch's alert was registered for reminders as it was handed over, and nothing
    # of it was taken back where a switch dropped it; its end went wherever "back to normal" is heard. A destination that
    # never heard "no video signal for 1 min" was reminded of it, and told "a picture again" alone. Its end goes only where
    # its start was handed over and not dropped, and a start dropped takes its reminders with it. The next time the screen
    # goes dark, that is told there, and its end, as any other.
    monkeypatch.setattr(screens, "MINUTE", 0.5)  # (a minute is half a second here)
    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.5,))
    monkeypatch.setattr(server, "REMINDER_MINUTE", 0.02)  # (a reminder after 30 minutes: 0.6 s here)
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    fake = FakeKvm(FakeState(picture=picture(90), picture_type="image/jpeg")).start()
    try:
        with wall(tmp_path) as admin:
            office = watched_for_no_signal(admin, fake)
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm", remind=30)["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            seen_lit(admin, office)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)  # (the watch's alert, refused: tried again in a second and a half)
            assert titles_told(services) == ["Office PC has had no video signal for 1 min"], titles_told(services)
            switched(admin, hook, how, on=False)
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: any(dropped_said(each) for each in admin.get(log).json()["deliveries"]), "it was never dropped", timeout=10)
            switched(admin, hook, how, on=True)
            time.sleep(1.5)  # (still dark: a reminder of what was told would be due twice by now)
            assert len(services.at(HOOKS)) == 1, f"reminded of a dark screen it never heard of: {titles_told(services)}"
            fake.state.signal = True
            wait_until(lambda: admin.core.screens.standing(office) == [], "the watch was never over", 20)  # type: ignore[attr-defined]
            time.sleep(1.0)
            assert len(services.at(HOOKS)) == 1, f"'a picture again' told where its dark screen never arrived: {titles_told(services)}"
            fake.state.signal = False  # (dark again: told, and its end after it)
            services.wait_for(HOOKS, 2, timeout=20)
            fake.state.signal = True
            wait_until(lambda: titles_told(services)[-1] == "Office PC has a picture again", "its end was never told", timeout=20)
            assert titles_told(services)[1] == "Office PC has had no video signal for 1 min", titles_told(services)
    finally:
        fake.stop()


def test_a_screen_watch_that_goes_off_within_a_destinations_quiet_hours_is_not_followed_there_by_its_end(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None
) -> None:
    # (M2, by quiet hours.) A screen watch that goes off within a destination's quiet hours is not told there; once they were
    # over, its end was told there all the same: "a picture again" of a dark screen it never heard of. Its end goes where
    # its start went, here the other destination, which has no quiet hours.
    monkeypatch.setattr(screens, "MINUTE", 0.5)
    fake = FakeKvm(FakeState(picture=picture(90), picture_type="image/jpeg")).start()
    try:
        with wall(tmp_path) as admin:
            office = watched_for_no_signal(admin, fake)
            added(admin, kind="webhook", url=f"https://{HOOKS}/told")
            quiet = added(admin, kind="webhook", url=f"https://{HOOKS}/quiet")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            seen_lit(admin, office)
            stopped(admin, quiet, "its quiet hours")
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)
            assert admin.core.screens.standing(office) == ["no_signal"]  # type: ignore[attr-defined]
            stop_ended(admin, quiet, "its quiet hours")
            fake.state.signal = True
            services.wait_for(HOOKS, 2, timeout=20)
            time.sleep(1.0)
            told = [(each.path, json.loads(each.body)["event"]) for each in services.at(HOOKS)]
            assert told == [("/told", "no_signal"), ("/told", "recovered")], told
    finally:
        fake.stop()


@pytest.mark.parametrize("meanwhile", ["back within them", "back and dark again within them"])
def test_a_screen_watchs_end_within_quiet_hours_is_told_when_they_end_where_its_start_was_told(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None, meanwhile: str
) -> None:
    # (The outside review of 0.4.0, bugs round 2, M5.) A screen watch that went off before a destination's quiet hours, and
    # was over within them, was told there as gone dark and never as over: quiet hours tell what a machine's state changed
    # to, and a watch's end is no change of state. Its end is told when they end, where the screen is still back then; dark
    # again by then, the destination knows it as it is, and the end of that watch goes there.
    monkeypatch.setattr(screens, "MINUTE", 0.5)
    fake = FakeKvm(FakeState(picture=picture(90), picture_type="image/jpeg")).start()
    try:
        with wall(tmp_path) as admin:
            office = watched_for_no_signal(admin, fake)
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/quiet")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            seen_lit(admin, office)
            fake.state.signal = False
            log = f"/api/v1/alerts/destinations/{hook}/log"
            wait_until(lambda: any(each["ok"] for each in admin.get(log).json()["deliveries"]), "the watch's start was never delivered", 20)
            stopped(admin, hook, "its quiet hours")
            fake.state.signal = True
            wait_until(lambda: admin.core.screens.standing(office) == [], "the watch was never over", 20)  # type: ignore[attr-defined]
            if meanwhile == "back and dark again within them":
                fake.state.signal = False
                wait_until(lambda: admin.core.screens.standing(office) == ["no_signal"], "the watch never went off again", 20)  # type: ignore[attr-defined]
            time.sleep(0.6)
            assert len(services.at(HOOKS)) == 1, titles_told(services)  # (nothing within them)
            stop_ended(admin, hook, "its quiet hours")
            started, over = "Office PC has had no video signal for 1 min", "Office PC has a picture again"
            if meanwhile == "back within them":
                services.wait_for(HOOKS, 2, timeout=10)
            else:
                time.sleep(1.5)
                assert titles_told(services) == [started], titles_told(services)  # (dark, as it was told)
                fake.state.signal = True
                services.wait_for(HOOKS, 2, timeout=20)
            time.sleep(0.5)
            assert titles_told(services) == [started, over], titles_told(services)
    finally:
        fake.stop()


def pagerduty_said(services: FakeService) -> list[tuple[str, str]]:
    return [(json.loads(each.body)["event_action"], json.loads(each.body)["dedup_key"]) for each in services.at(PAGERDUTY)]


def test_a_pagerduty_change_whose_first_event_went_goes_whole_whatever_a_switch_says_since(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (The narrow look at 0.4.0, L3.) A machine's change from one kind of trouble to another is two events for PagerDuty: the
    # incident of the trouble that is over resolved, and the one of the trouble that begins triggered. The switches were
    # asked before each: alerts switched off while the first was on the line held the second back, and the change was taken
    # back as untold though its resolve went; the machine without a picture again was then no news there, and no incident
    # was open while it was down. They are asked before a change's first message only: once that went, the rest goes.
    entered, let_go = threading.Event(), threading.Event()

    def slow(arrived: Any) -> bytes:
        entered.set()
        let_go.wait(10)
        return b'{"status":"success"}'

    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            pd = added(admin, kind="pagerduty", key=PD_KEY)["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            services.answers[PAGERDUTY] = [Answer(202, b'{"status":"success"}')]
            fake.state.signal = False
            services.wait_for(PAGERDUTY, 1, timeout=20)  # (no picture: its incident ".../down" triggered)
            services.answers[PAGERDUTY] = [Answer(202, echo=slow), Answer(202, b'{"status":"success"}')]
            fake.state.https_at = "https://127.0.0.1:9"  # (its plain address sends everybody on to HTTPS: a problem of its own)
            assert entered.wait(30), f"the change was never sent: {pagerduty_said(services)}"
            assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            let_go.set()
            services.wait_for(PAGERDUTY, 3, timeout=10)  # (the problem's trigger, once the resolve went)
            down, problem = f"qkvm/{device}/down", f"qkvm/{device}/problem"
            assert pagerduty_said(services) == [("trigger", down), ("resolve", down), ("trigger", problem)], pagerduty_said(services)
            log = f"/api/v1/alerts/destinations/{pd}/log"
            wait_until(lambda: len(admin.get(log).json()["deliveries"]) == 2, "the change was never said", timeout=10)
            change = admin.get(log).json()["deliveries"][0]
            assert (change["ok"], change["withheld"], change["attempts"]) == (True, False, 1), change
            fake.state.https_at = ""  # (without a picture again: its problem resolved, ".../down" triggered)
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            services.wait_for(PAGERDUTY, 5, timeout=30)
            assert pagerduty_said(services)[3:] == [("resolve", problem), ("trigger", down)], pagerduty_said(services)
    finally:
        let_go.set()
        fake.stop()


def test_a_pagerduty_change_tried_again_sends_only_what_did_not_go(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, bugs round 2, a low one.) A change between two kinds of trouble is two events: the
    # incident of the one that is over resolved, the other's triggered. Where the trigger was busy (503), the retry began
    # at the first again: the resolve that went went twice. It goes on from the first that did not go.
    from qkvm import egress

    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.0,))
    seen: list[tuple[str, str]] = []
    deliveries: list[alerts.Delivery] = []

    async def post(url: str, body: bytes, headers: dict[str, str], *, still: Any, **rules: Any) -> egress.Reply:
        assert still()
        sent = json.loads(body)
        seen.append((sent["event_action"], sent["dedup_key"]))
        return egress.Reply(503 if len(seen) == 2 else 202, "", {}, b"")

    async def own() -> egress.Own:
        return egress.Own(frozenset(), frozenset())

    async def run() -> None:
        target = alerts.Target("pd", "pagerduty", {}, {"key": PD_KEY}, False, False, "")
        courier = alerts.Courier(lambda _: target, own, lambda _, delivery: deliveries.append(delivery))
        change = alerts.Alert("problem", "Build", "", "error", "offline", "Build has a problem", "", device_id="build", event="problem")
        await courier._deliver("pd", [change])

    monkeypatch.setattr(egress, "post", post)
    asyncio.run(run())
    assert len(deliveries) == 1 and deliveries[0].ok and deliveries[0].attempts == 2, deliveries
    assert seen == [("resolve", "qkvm/build/down"), ("trigger", "qkvm/build/problem"), ("trigger", "qkvm/build/problem")], seen


@pytest.mark.parametrize("kind", ["webhook", "pagerduty"])
def test_a_reminder_waiting_behind_a_trouble_a_switch_dropped_goes_no_more(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    # (The narrow look at 0.4.0, L4.) A trouble that waits long to be tried again (half an hour, where alerts queue for one
    # destination that is away) has its reminders put behind it. A switch that dropped the trouble took with it the
    # reminders still to come, and not those already waiting: switched on again before their turn, they went, of a trouble
    # never heard there (to PagerDuty a reminder of a machine offline is a trigger: an incident whose end then went nowhere).
    # A reminder goes only while its destination is still said to know the trouble of it.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (3.0,))
    monkeypatch.setattr(server, "REMINDER_MINUTE", 0.02)  # (a reminder after 30 minutes: 0.6 s here)
    monkeypatch.setitem(destinations.SPACING, kind, 2.0)  # (two seconds between two messages, as Telegram has three)
    host = HOOKS if kind == "webhook" else PAGERDUTY
    services.answers[host] = [Answer(503, b"busy"), Answer(202, b'{"status":"success"}')]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            if kind == "webhook":
                dest = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm", remind=30)["destination"]["id"]
            else:
                dest = added(admin, kind="pagerduty", key=PD_KEY, remind=30)["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.stop()  # (offline: a trigger to PagerDuty, and so is each reminder of it)
            services.wait_for(host, 1, timeout=20)  # (503: tried again in three seconds)
            time.sleep(1.4)  # (reminders put behind it meanwhile)
            assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            log = f"/api/v1/alerts/destinations/{dest}/log"
            wait_until(lambda: any(dropped_said(each) for each in admin.get(log).json()["deliveries"]), "the trouble was never dropped", timeout=10)
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            wait_until(lambda: len(admin.get(log).json()["deliveries"]) >= 3, "the reminders never had their turn", timeout=15)
            fake = FakeKvm(fake.state, port=fake.port).start()  # (back at its address)
            wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 20)  # type: ignore[attr-defined]
            time.sleep(1.0)
            assert len(services.at(host)) == 1, f"reminded of a trouble it never heard of: {[json.loads(each.body) for each in services.at(host)]}"
            assert all(dropped_said(each) for each in admin.get(log).json()["deliveries"]), admin.get(log).json()["deliveries"]
    finally:
        fake.stop()


def stop_ended(admin: Any, hook: str, how: str) -> None:
    """A pause or quiet hours over."""
    if how == "a pause":
        reply = admin.post("/api/v1/alerts/pause", json={"minutes": 0})
    else:
        reply = admin.put(f"/api/v1/alerts/destinations/{hook}", json={"kind": "webhook", "quiet_from": -1, "quiet_to": -1})
    assert reply.status_code == 200, reply.text


def states_told(services: FakeService) -> list[str]:
    return [json.loads(each.body)["state"] for each in services.at(HOOKS)]


@pytest.mark.parametrize("how", WINDOWS)
@pytest.mark.parametrize("meanwhile", ["still down", "back to normal"])
def test_what_waits_to_be_tried_again_when_a_pause_or_quiet_hours_begin_is_delivered_as_it_would_have_been(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str, meanwhile: str
) -> None:
    # Three review rounds found ways to lose or falsely tell what a pause or quiet hours held of an alert already on its way
    # (the fresh review of the fixes, N2; the last look, M1 to M5). The rule since: a pause or quiet hours stop new alerts
    # only, judged when an alert is routed. One already handed to a destination is delivered as it would have been, its
    # retries bounded (5, 30 and 120 s): its last try some two and a half minutes after its own first. What changes within
    # them is held and told when they end, as before.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.0,))
    services.answers[HOOKS] = [Answer(503, b"busy"), Answer(200, b"ok")]
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            services.wait_for(HOOKS, 1, timeout=20)  # (503: it waits to be tried again)
            stopped(admin, hook, how)
            services.wait_for(HOOKS, 2, timeout=10)  # (its retry, within them)
            [said] = admin.get(f"/api/v1/alerts/destinations/{hook}/log").json()["deliveries"]
            assert (said["ok"], said["withheld"], said["attempts"]) == (True, False, 2), said
            assert states_told(services) == ["no_signal", "no_signal"], states_told(services)
            if meanwhile == "back to normal":
                fake.state.signal = True
                wait_until(lambda: admin.core.watcher.state(device) == "online", "it was never seen back", 10)  # type: ignore[attr-defined]
            time.sleep(1.0)
            assert len(services.at(HOOKS)) == 2, states_told(services)  # (nothing new while they last)
            stop_ended(admin, hook, how)
            if meanwhile == "still down":
                time.sleep(1.5)
                assert len(services.at(HOOKS)) == 2, states_told(services)  # (told: not told again when they end)
            else:
                services.wait_for(HOOKS, 3, timeout=10)  # (what changed within them, told when they end)
                assert json.loads(services.at(HOOKS)[-1].body)["event"] == "recovered", states_told(services)
    finally:
        fake.stop()


def held_at_its_address(monkeypatch: pytest.MonkeyPatch) -> tuple[threading.Event, threading.Event]:
    """A send held while its name is looked up (`looking` set), until `go` is set."""
    from qkvm import egress

    looking, go = threading.Event(), threading.Event()
    real = egress.vetted

    async def slow(host: str, port: int, **rules: Any) -> tuple[list[str], int]:
        looking.set()
        while not go.is_set():
            await asyncio.sleep(0.02)
        return await real(host, port, **rules)

    monkeypatch.setattr(egress, "vetted", slow)
    return looking, go


@pytest.mark.parametrize("how", [*OFFS, *WINDOWS])
def test_a_send_that_waited_for_its_address_is_not_made_once_alerts_are_switched_off_and_is_made_through_a_pause(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    # (M4, the last moment.) A send waits for its turn and for its name to be looked up before anything goes: switched off
    # meanwhile, nothing goes. A pause or quiet hours begun meanwhile stop nothing that was on its way.
    looking, go = held_at_its_address(monkeypatch)
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            assert looking.wait(20), "the alert was never sent"
            stopped(admin, hook, how)
            go.set()
            wait_until(lambda: admin.get(f"/api/v1/alerts/destinations/{hook}/log").json()["deliveries"], "the delivery was never said", timeout=10)
            [said] = admin.get(f"/api/v1/alerts/destinations/{hook}/log").json()["deliveries"]
            if how in OFFS:
                assert services.at(HOOKS) == [], f"sent after {how}"
                assert dropped_said(said), said
            else:
                assert len(services.at(HOOKS)) == 1 and json.loads(services.at(HOOKS)[0].body)["state"] == "no_signal", f"not sent after {how}"
                assert (said["ok"], said["withheld"]) == (True, False), said
    finally:
        go.set()
        fake.stop()


def test_a_change_being_gathered_when_quiet_hours_begin_is_sent_when_its_gathering_ends(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The rule above, with no service away at all.) A kind a person reads waits a look and a second to gather what changes
    # with it: quiet hours that begin in those seconds stop nothing of what it gathers (they held it once: N2, then M1 to M5).
    monkeypatch.setattr(alerts, "CHECK_EVERY", 1.0)  # (the gathering: a look and a second, two seconds here)
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            slack = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(1.2)
            fake.state.signal = False
            wait_until(lambda: any(each["event"] == "alert" for each in admin.core.audit.tail(50)), "no alert", 10)  # type: ignore[attr-defined]
            now = time.localtime()
            minute = now.tm_hour * 60 + now.tm_min
            assert admin.put(f"/api/v1/alerts/destinations/{slack}", json={"kind": "slack", "quiet_from": minute, "quiet_to": (minute + 120) % 1440}).status_code == 200
            assert services.at(SLACK) == []  # (its quiet hours began while it was being gathered)
            services.wait_for(SLACK, 1, timeout=15)
            assert "Build server" in json.loads(services.at(SLACK)[0].body)["text"]
            [said] = admin.get(f"/api/v1/alerts/destinations/{slack}/log").json()["deliveries"]
            assert (said["ok"], said["withheld"]) == (True, False), said
    finally:
        fake.stop()


# --- the backups' alerts: a failure and its end ---------------------------------------------------------------------


def backup_failing(*args: Any, **kwargs: Any) -> Any:
    raise OSError(28, "No space left on the backup disk")


def pagerduty_actions(services: FakeService) -> list[str]:
    return [json.loads(each.body)["event_action"] for each in services.at(PAGERDUTY)]


def quiet_now() -> dict[str, int]:
    now = time.localtime()
    minute = now.tm_hour * 60 + now.tm_min
    return {"quiet_from": minute, "quiet_to": (minute + 120) % 1440}


def pause(admin: Any, minutes: int) -> None:
    assert admin.post("/api/v1/alerts/pause", json={"minutes": minutes}).status_code == 200


@pytest.mark.parametrize("how", ["a pause", "a restart"])
def test_a_backup_recovery_on_its_way_reaches_pagerduty_through_a_pause_and_after_a_restart(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # (N2, the backups.) Who was told that a backup failed was taken off the list the moment the recovery was handed over:
    # lost with a restart while it waited to be tried again, the incident PagerDuty opened for the failure was never
    # resolved. The list keeps a destination until the recovery is delivered (or given up on). A pause begun while it waits
    # to be tried again stops nothing of it: it was on its way.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(alerts, "RETRY_AFTER", (30.0,) if how == "a restart" else (1.0,))
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    real = backup.make
    data = tmp_path / "data"
    with wall(data) as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        added(admin, kind="pagerduty", key=PD_KEY, events=["backup", "recovered"], least="info")
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        monkeypatch.setattr(backup, "make", backup_failing)
        assert admin.post("/api/v1/backups/run").json()["ok"] is False
        services.wait_for(PAGERDUTY, 1, timeout=10)  # (the incident opened)
        monkeypatch.setattr(backup, "make", real)
        services.answers[PAGERDUTY] = [Answer(503, b"busy"), Answer(202, b'{"status":"success"}')]
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        services.wait_for(PAGERDUTY, 2, timeout=10)  # (the recovery's first try: 503, it waits to be tried again)
        if how == "a pause":
            pause(admin, 60)
            services.wait_for(PAGERDUTY, 3, timeout=10)  # (its next try, within the pause)
            # (Delivered: owed no more. Taken off the list once the courier has the answer, a moment after the stand-in got
            # the request: waited for, as a busy Windows runner was seen to look in between.)
            deadline = time.monotonic() + 10
            while admin.core.store.backups.told and time.monotonic() < deadline:  # type: ignore[attr-defined]
                time.sleep(0.05)
            assert admin.core.store.backups.told == []  # type: ignore[attr-defined]
            pause(admin, 0)
            time.sleep(1.0)  # (and not told again when the pause ends)
    if how == "a restart":
        with wall(data) as admin:
            services.wait_for(PAGERDUTY, 3, timeout=10)
    assert pagerduty_actions(services) == ["trigger", "resolve", "resolve"]


@pytest.mark.parametrize("meanwhile", ["backups still fail", "backups made again"])
def test_a_backup_failure_on_its_way_when_a_pause_begins_is_delivered_and_what_follows_within_it_told_at_its_end(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, meanwhile: str
) -> None:
    # (The rule for what is on its way, and the review's M4 case of a pause, by the backups.) A failure waiting for its
    # retry when a pause begins is delivered; backups made again within the pause are told when it ends, as a machine back
    # to normal within it is.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(alerts, "RETRY_AFTER", (1.0,))
    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    real = backup.make
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        added(admin, kind="pagerduty", key=PD_KEY, events=["backup", "recovered"], least="info")
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        services.answers[PAGERDUTY] = [Answer(503, b"busy"), Answer(202, b'{"status":"success"}')]
        monkeypatch.setattr(backup, "make", backup_failing)
        assert admin.post("/api/v1/backups/run").json()["ok"] is False
        services.wait_for(PAGERDUTY, 1, timeout=10)  # (the failure's first try: busy, it waits to be tried again)
        pause(admin, 60)
        services.wait_for(PAGERDUTY, 2, timeout=10)  # (its retry, within the pause)
        assert pagerduty_actions(services) == ["trigger", "trigger"]
        if meanwhile == "backups made again":
            monkeypatch.setattr(backup, "make", real)
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
        time.sleep(1.0)
        assert len(services.at(PAGERDUTY)) == 2  # (nothing new within the pause)
        pause(admin, 0)
        if meanwhile == "backups made again":
            services.wait_for(PAGERDUTY, 3, timeout=10)
            assert pagerduty_actions(services) == ["trigger", "trigger", "resolve"]
        else:
            time.sleep(1.5)
            assert pagerduty_actions(services) == ["trigger", "trigger"]  # (told once: not again when the pause ends)


@pytest.mark.parametrize("meanwhile", ["backups still fail", "backups made again"])
def test_a_backup_failure_within_a_pause_is_told_when_it_ends_only_where_backups_still_fail(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, meanwhile: str
) -> None:
    # The last look, L2: a failure within a pause was never told, even where backups still failed when it ended (while a
    # machine's change within a pause is). One rule now: held, and told when the pause ends where backups still fail; over
    # within it, nobody's news.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    real = backup.make
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        added(admin, kind="pagerduty", key=PD_KEY, events=["backup", "recovered"], least="info")
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        pause(admin, 60)
        monkeypatch.setattr(backup, "make", backup_failing)
        assert admin.post("/api/v1/backups/run").json()["ok"] is False
        if meanwhile == "backups made again":
            monkeypatch.setattr(backup, "make", real)
            assert admin.post("/api/v1/backups/run").json()["ok"] is True
        time.sleep(0.5)
        assert services.at(PAGERDUTY) == []  # (nothing within the pause)
        pause(admin, 0)
        if meanwhile == "backups made again":
            time.sleep(1.5)
            assert services.at(PAGERDUTY) == [], pagerduty_actions(services)
            return
        services.wait_for(PAGERDUTY, 1, timeout=10)
        assert pagerduty_actions(services) == ["trigger"]
        # Told, its end is owed there.
        monkeypatch.setattr(backup, "make", real)
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        services.wait_for(PAGERDUTY, 2, timeout=10)
        assert pagerduty_actions(services) == ["trigger", "resolve"]


@pytest.mark.parametrize("meanwhile", ["backups made again within a pause", "backups made again"])
def test_a_backup_failure_held_back_is_never_told_once_backups_are_made_again(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, meanwhile: str) -> None:
    # The last look, M2: a failure held back (here by quiet hours) stayed owed where backups were made again while alerts
    # were paused, and was told when both were over ("Backup failed" paged for a trouble that was over). Owed no more once
    # backups are made again.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    real = backup.make
    with wall(tmp_path / "data") as admin:
        made_key(admin)
        set_up(admin, tmp_path / "backups")
        pd = added(admin, kind="pagerduty", key=PD_KEY, events=["backup", "recovered"], least="info", **quiet_now())["destination"]["id"]
        assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
        monkeypatch.setattr(backup, "make", backup_failing)
        assert admin.post("/api/v1/backups/run").json()["ok"] is False  # (held back by its quiet hours)
        if meanwhile.endswith("within a pause"):
            pause(admin, 60)
        monkeypatch.setattr(backup, "make", real)
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        if meanwhile.endswith("within a pause"):
            pause(admin, 0)
        time.sleep(0.5)
        assert admin.put(f"/api/v1/alerts/destinations/{pd}", json={"kind": "pagerduty", "quiet_from": -1, "quiet_to": -1}).status_code == 200
        time.sleep(1.5)
        assert services.at(PAGERDUTY) == [], pagerduty_actions(services)


@pytest.mark.parametrize("case", ["two failures", "one told and one more", "a failure, its end and a failure", "a failure, and its end after off and on"])
def test_a_backup_failure_a_switch_dropped_takes_back_only_what_it_put_on_the_told_list(
    tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    # (The outside review of 0.4.0, bugs round 2, M2.) Who was told that backups fail is owed "Backups are made again". A
    # failure a switch dropped took the destination off that list only where its own hand-over had put it there, and only
    # the last hand-over was remembered: two failures dropped left it on the list, and the next backup made told a receiver
    # that never heard of either that backups were made again. A failure dropped takes back what it put there and no more:
    # one told before it is owed the end still; one whose every failure was dropped, nothing. And an end handed over behind
    # a failure that waited (alerts switched off and on again meanwhile, M3) goes no more where that failure was dropped.
    from qkvm import backup
    from tests.test_backups import made_key, set_up

    monkeypatch.setattr(server, "BACKUP_LOOK", 0.05)
    real = backup.make
    answering, let_go, busy = held_busy()  # (the service slow to say it is busy: what follows waits behind it)

    def run(ok: bool) -> None:
        monkeypatch.setattr(backup, "make", real if ok else backup_failing)
        assert admin.post("/api/v1/backups/run").json()["ok"] is ok

    try:
        with wall(tmp_path / "data") as admin:
            made_key(admin)
            set_up(admin, tmp_path / "backups")
            hook = added(admin, kind="webhook", url=f"https://{HOOKS}/backup", events=["backup", "recovered"])["destination"]["id"]
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            log = f"/api/v1/alerts/destinations/{hook}/log"
            if case == "one told and one more":
                run(ok=False)
                wait_until(lambda: any(each["ok"] for each in admin.get(log).json()["deliveries"]), "the first failure was never delivered", 10)
            services.answers[HOOKS] = [busy, Answer(200, b"ok")]
            run(ok=False)
            assert answering.wait(10), "the failure was never sent"
            if case == "two failures":
                run(ok=False)
            elif case == "a failure, its end and a failure":
                run(ok=True)
                run(ok=False)
            assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            if case == "a failure, and its end after off and on":
                assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
                run(ok=True)  # (its end, handed over behind the failure, after the switch is on again)
            let_go.set()  # (busy: tried again, and dropped then, with what waited behind it)
            dropped = 1 if case == "one told and one more" else 3 if case == "a failure, its end and a failure" else 2
            wait_until(lambda: sum(dropped_said(each) for each in admin.get(log).json()["deliveries"]) == dropped, "what waited was never dropped", 15)
            told = list(admin.core.store.backups.told)  # type: ignore[attr-defined]
            assert told == ([hook] if case == "one told and one more" else []), told
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            run(ok=True)
            if case == "one told and one more":
                wait_until(lambda: events_told(services)[-1] == "recovered", "the end owed was never told", 10)
                assert events_told(services) == ["backup", "backup", "recovered"], events_told(services)
            else:
                time.sleep(1.0)
                assert events_told(services) == ["backup"], f"told backups are made again where no failure arrived: {events_told(services)}"
    finally:
        let_go.set()


def test_a_saved_secret_that_does_not_open_is_said_and_sent_nowhere(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        one = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
        record = admin.core.store.destinations[0]  # type: ignore[attr-defined]
        record.secret = {"nonce": "!", "data": record.secret["data"]}  # (as a hand or a disk leaves it)
        shown = listed(admin)[0]
        assert "does not open any more" in shown["last_error"]
        reply = admin.post(f"/api/v1/alerts/destinations/{one}/test")
        assert reply.status_code == 502 and "does not open any more" in reply.json()["message"]
        assert services.at(SLACK) == []
        # Entered again, it is sent to.
        assert admin.put(f"/api/v1/alerts/destinations/{one}", json={"kind": "slack", "url": SLACK_URL}).status_code == 200
        time.sleep(destinations_test_every())
        assert admin.post(f"/api/v1/alerts/destinations/{one}/test").status_code == 200


def test_the_api_of_0_3_2_speaks_of_the_first_destination(tmp_path: Path, services: FakeService) -> None:
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": f"https://{NTFY}/topic", "format": "ntfy"}).json()["format"] == "ntfy"
        added(admin, kind="pagerduty", key=PD_KEY)
        [first, second] = listed(admin)
        assert (first["kind"], first["host"], second["kind"]) == ("ntfy", NTFY, "pagerduty")
        assert admin.post("/api/v1/alerts/test").status_code == 200 and services.at(NTFY) and not services.at(PAGERDUTY)
        # Another address for it: the first destination's, which stays where it is.
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": f"https://{SLACK}/services/A/B/C", "format": "slack"}).status_code == 200
        assert [(one["id"], one["kind"]) for one in listed(admin)] == [(first["id"], "slack"), (second["id"], "pagerduty")]
        assert admin.put("/api/v1/alerts", json={"enabled": True, "forget_webhook": True}).json()["has_webhook"] is True  # (the next one is first now)
        assert [one["kind"] for one in listed(admin)] == ["pagerduty"]
        assert admin.get("/api/v1/alerts").json()["format"] == "pagerduty"


def test_many_machines_at_once_are_one_message_where_a_person_reads_and_each_change_where_a_program_does(tmp_path: Path, services: FakeService) -> None:
    machines = [FakeKvm().start() for _ in range(6)]
    try:
        with wall(tmp_path) as admin:
            for number, fake in enumerate(machines):
                add(admin, fake.url, name=f"Rack {number}")
            added(admin, kind="slack", url=SLACK_URL)
            added(admin, kind="webhook", url=f"https://{HOOKS}/qkvm")
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            for device in admin.get("/api/v1/wall").json()["devices"]:
                assert admin.get(snap(device["id"])).status_code == 200
            time.sleep(0.6)
            for fake in machines:
                fake.state.signal = False  # the power strip of their rack goes: all of them in the same moment
            wait_until(lambda: len(services.at(HOOKS)) >= 6, "the webhook was not told each one", timeout=30)
            time.sleep(1.5)
            said = [json.loads(each.body)["text"] for each in services.at(SLACK)]
            assert len(said) == 1 and said[0].startswith("*6 changes on the wall*"), said
            assert all(f"Rack {number} has no video signal" in said[0] for number in range(6))
            assert sorted(json.loads(each.body)["device"] for each in services.at(HOOKS)) == [f"Rack {number}" for number in range(6)]
    finally:
        for fake in machines:
            fake.stop()


def test_quiet_hours_hold_what_happens_and_tell_what_is_still_so_when_they_end(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    quiet = {"now": True}
    monkeypatch.setattr(destinations, "quiet", lambda destination, now: quiet["now"] and destination.name == "Night")
    flaky, down = FakeKvm().start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, flaky.url, name="Flaky")
            add(admin, down.url, name="Down")
            added(admin, kind="slack", name="Night", url=SLACK_URL, quiet_from=22 * 60, quiet_to=7 * 60)
            added(admin, kind="discord", name="Always", url=f"https://{DISCORD}/api/webhooks/1/abc")
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            for device in admin.get("/api/v1/wall").json()["devices"]:
                assert admin.get(snap(device["id"])).status_code == 200
            time.sleep(0.6)
            flaky.state.signal = down.state.signal = False
            wait_until(lambda: len(services.at(DISCORD)) >= 1, "the destination without quiet hours was not told", timeout=20)
            flaky.state.signal = True  # put right within the quiet hours: nobody's news there afterwards
            wait_until(lambda: "picture again" in " ".join(json.loads(each.body)["content"] for each in services.at(DISCORD)), "it never came back", timeout=20)
            assert services.at(SLACK) == []
            quiet["now"] = False
            wait_until(lambda: len(services.at(SLACK)) >= 1, "nothing was told when the quiet hours ended", timeout=20)
            time.sleep(1.5)
            said = " ".join(json.loads(each.body)["text"] for each in services.at(SLACK))
            assert "Down has no video signal" in said and "Flaky" not in said, said
    finally:
        flaky.stop()
        down.stop()


def test_a_reminder_only_where_asked_and_only_while_it_is_still_so(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "REMINDER_MINUTE", 0.01)  # a minute of a reminder is six hundredths of a second here
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            added(admin, kind="slack", url=SLACK_URL, remind=30)
            added(admin, kind="discord", url=f"https://{DISCORD}/api/webhooks/1/abc")  # (no reminders: the default)
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            wait_until(lambda: any("Still" in json.loads(each.body)["text"] for each in services.at(SLACK)), "no reminder", timeout=20)
            assert all("Still" not in json.loads(each.body)["content"] for each in services.at(DISCORD))
            fake.state.signal = True
            wait_until(lambda: "picture again" in json.loads(services.at(SLACK)[-1].body)["text"], "it never came back", timeout=20)
            told = len(services.at(SLACK))
            time.sleep(1.5)
            assert len(services.at(SLACK)) == told  # nothing to remind of any more
    finally:
        fake.stop()


def test_an_encrypted_export_carries_each_destination_as_it_is_and_a_plain_one_none(tmp_path: Path) -> None:
    from qkvm import exchange
    from tests.test_wall import PASSWORD

    fake = FakeKvm().start()
    try:
        with wall(tmp_path / "one") as admin:
            device = add(admin, fake.url, name="Rack server")
            said = {
                "kind": "slack", "name": "Ops", "url": SLACK_URL, "least": "error", "devices": [device], "groups": ["Rack 3"],
                "quiet_from": 22 * 60, "quiet_to": 7 * 60, "quiet_days": ["sat", "sun"], "remind": 60, "private": True, "minimal": True,
                "events": ["offline", "recovered"],
            }  # fmt: skip
            added(admin, **said)
            added(admin, kind="telegram", token=TG_TOKEN, chat="-100123")
            sealed = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "a passphrase of the file", "parts": list(exchange.PARTS)}).text
            plain = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": list(exchange.PARTS)}).text
        for secret in ("S3CRETslackTOKEN", "S3CRET_telegram", SLACK):
            assert secret not in sealed and secret not in plain, secret
        assert "destinations" not in plain  # not even where they would be
        with wall(tmp_path / "two") as admin:
            taken = admin.post("/api/v1/import", json={"file": sealed, "passphrase": "a passphrase of the file", "take": list(exchange.PARTS)})
            assert taken.status_code == 200, taken.text
            ops, telegram = listed(admin)
            here = admin.get("/api/v1/wall").json()["devices"][0]["id"]
            assert (ops["name"], ops["host"], ops["least"], ops["devices"], ops["groups"], ops["remind"], ops["private"], ops["minimal"]) == (
                "Ops", SLACK, "error", [here], ["Rack 3"], 60, True, True,
            )  # fmt: skip
            assert (ops["quiet_from"], ops["quiet_to"], ops["quiet_days"], ops["events"]) == (22 * 60, 7 * 60, ["sat", "sun"], ["offline", "recovered"])
            assert telegram["config"] == {"chat": "-100123"} and telegram["host"] == TELEGRAM
            record = admin.core.store.destinations[0]  # type: ignore[attr-defined]
            assert json.loads(admin.core.vault.read(record.secret, f"destination:{record.id}"))["url"] == SLACK_URL  # type: ignore[attr-defined]
    finally:
        fake.stop()


def test_after_a_power_cut_the_incident_is_resolved_and_a_picture_lost_told_where_offline_was_not(tmp_path: Path, services: FakeService) -> None:
    # (The review of 0.4.0's first wave, M1.) The KVM goes, comes back without a picture, then the computer boots. PagerDuty
    # (errors and worse) was told it was offline; the end was judged by "no signal" alone (a warning), and never resolved
    # the incident. A chat that hears pictures lost and not machines offline heard nothing of it at all.
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            added(admin, kind="pagerduty", key=PD_KEY, least="error")
            added(admin, kind="discord", url=f"https://{DISCORD}/api/webhooks/1/abc", events=["no_signal", "recovered"])
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)
            fake.stop()
            wait_until(lambda: len(services.at(PAGERDUTY)) >= 1, "PagerDuty was not told", timeout=20)
            fake.state.signal = False
            fake = FakeKvm(fake.state, port=fake.port).start()  # (back at its address, with no picture)
            wait_until(lambda: len(services.at(DISCORD)) >= 1, "the picture lost was told nowhere", timeout=20)
            assert "Build server has no video signal" in json.loads(services.at(DISCORD)[0].body)["content"]
            fake.state.signal = True
            wait_until(lambda: len(services.at(PAGERDUTY)) >= 2, "the incident was never resolved", timeout=20)
            events = [(json.loads(each.body)["event_action"], json.loads(each.body)["dedup_key"]) for each in services.at(PAGERDUTY)]
            assert events == [("trigger", f"qkvm/{device}/down"), ("resolve", f"qkvm/{device}/down")], events
            wait_until(lambda: len(services.at(DISCORD)) >= 2, "the picture coming back was told nowhere", timeout=20)
    finally:
        fake.stop()


def test_an_unexpected_error_in_a_delivery_is_said_where_a_delivery_is(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of 0.4.0's first wave, L2.) A delivery that ended in an error of qKVM's own left a line in the program's log
    # and nothing else: no line in the destination's log, no last error, nothing in the activity log; and a test was a 500.
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("something nobody thought of")

    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            add(admin, fake.url, name="Build server")
            place = added(admin, kind="slack", url=SLACK_URL)["destination"]["id"]
            monkeypatch.setattr(destinations, "outgoing", broken)
            tried = admin.post(f"/api/v1/alerts/destinations/{place}/test")
            assert tried.status_code == 502 and "RuntimeError" in tried.json()["message"], tried.text
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(admin.get("/api/v1/wall").json()["devices"][0]["id"])).status_code == 200
            time.sleep(0.6)
            fake.state.signal = False
            wait_until(lambda: any(each["event"] == "alert_not_delivered" for each in admin.get("/api/v1/audit").json()["entries"]), "nothing in the activity log", timeout=20)
            deliveries = admin.get(f"/api/v1/alerts/destinations/{place}/log").json()["deliveries"]
            assert [each["ok"] for each in deliveries] == [False, False] and "RuntimeError" in deliveries[0]["said"]
            assert "RuntimeError" in listed(admin)[0]["last_error"]
    finally:
        fake.stop()


def test_a_service_on_this_computer_is_sent_to_with_the_switch(tmp_path: Path) -> None:
    # The owner's decision of 2026-11-17: an ntfy or a relay on the wall's own computer, with "May be a private address".
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    got: list[bytes] = []

    class Taking(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            got.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *said: Any) -> None:
            pass

    taking = ThreadingHTTPServer(("127.0.0.1", 0), Taking)
    import threading

    threading.Thread(target=taking.serve_forever, daemon=True).start()
    try:
        with wall(tmp_path) as admin:
            made = added(admin, kind="webhook", url=f"http://127.0.0.1:{taking.server_port}/relay", private=True)["destination"]["id"]
            assert admin.post(f"/api/v1/alerts/destinations/{made}/test").status_code == 200
            assert json.loads(got[0])["app"] == "QKVM"
    finally:
        taking.shutdown()
        taking.server_close()


def test_the_wall_itself_is_the_port_it_was_started_on_and_the_ports_it_listens_on(tmp_path: Path) -> None:
    # (The second review of 0.4.0's first wave, M1.) "The wall itself" was judged by the port saved in its settings, not
    # the one it listens on: started with --port, or with its port changed and not yet restarted, the wall's own API was
    # an address like any other of this computer's.
    import socket

    def free() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    started, listening = free(), free()
    with wall(tmp_path, port_override=started) as admin:
        admin.core.ports = [listening]  # type: ignore[attr-defined]  # (as the program records the ports it opened)
        for port in (started, listening):
            made = added(admin, kind="webhook", url=f"http://127.0.0.1:{port}/api/v1/wall", private=True)["destination"]["id"]
            said = admin.post(f"/api/v1/alerts/destinations/{made}/test")
            assert said.status_code == 502 and "this wall itself" in said.json()["message"], (port, said.text)


def test_this_computers_own_addresses_need_the_switch_as_loopback_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second review, L5.) The owner's rule: the switch is what lets this computer through. Its own addresses (here one
    # that stands for its public one) at another port than the wall's went out with the switch off; and a wall that listens
    # on this computer alone did not know them at all.
    from qkvm import egress

    monkeypatch.setattr(egress, "this_computer", lambda: {"8.8.4.4"})
    with wall(tmp_path) as admin:
        made = added(admin, kind="webhook", url="http://8.8.4.4:6379/hook")["destination"]["id"]
        said = admin.post(f"/api/v1/alerts/destinations/{made}/test")
        assert said.status_code == 502 and "this computer" in said.json()["message"], said.text


def test_what_is_left_of_a_change_does_not_follow_an_edit_to_another_routing_key(tmp_path: Path, services: FakeService, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-check of the outside review's fixes, N1.) Once a message of a change went, the rest of it goes whatever the
    # switches say since; but PagerDuty's resolve went to one routing key, the trigger came back busy, the admin edited the key,
    # and the trigger went to the new key on its retry: an incident opened with a service that never heard of the machine's
    # trouble before, and none where it was resolved. What is left of a change goes to the receiver its first message went to,
    # or to nobody.
    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.1,))
    answering, let_go, busy = held_busy()
    new_key = "N" * 32
    success = Answer(202, b'{"status":"success"}')
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            pd = added(admin, kind="pagerduty", key=PD_KEY)["destination"]["id"]
            path = f"/api/v1/alerts/destinations/{pd}"
            assert admin.put("/api/v1/alerts", json={"enabled": True}).status_code == 200
            assert admin.get(snap(device)).status_code == 200
            wait_until(lambda: admin.core.watcher.state(device) == "online", "the picture was never seen", 10)
            services.answers[PAGERDUTY] = [success]
            fake.state.signal = False
            wait_until(lambda: any(line["ok"] for line in admin.get(path + "/log").json()["deliveries"]), "the first trigger was not taken", 20)
            services.answers[PAGERDUTY] = [success, busy, success]
            fake.state.https_at = "https://127.0.0.1:9"  # (no picture, then offline: a change of two events, resolve and trigger)
            assert answering.wait(20), "the change's second event never reached the service"
            assert admin.put(path, json={"kind": "pagerduty", "key": new_key}).status_code == 200
            let_go.set()
            wait_until(lambda: len(admin.get(path + "/log").json()["deliveries"]) == 2, "the change never settled", 12)
            keys = {PD_KEY: "the first", new_key: "the new"}
            reached = [(sent["event_action"], keys[sent["routing_key"]]) for each in services.at(PAGERDUTY) for sent in [json.loads(each.body)]]
            assert reached == [("trigger", "the first"), ("resolve", "the first"), ("trigger", "the first")], reached
    finally:
        let_go.set()
        fake.stop()
