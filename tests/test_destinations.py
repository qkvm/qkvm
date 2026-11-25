"""The kinds of place an alert can go (destinations.py): what each takes when it is set up, what each is sent, and how
each one's answer is read. No network here: what goes out is looked at as it would go out."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from email import message_from_bytes, policy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from qkvm import alerts, destinations, egress
from qkvm.destinations import Mail, Post

OFFLINE = alerts.describe("Build server", "10.0.0.5", "online", "offline", device_id="ab12cd34")
LINK = "https://wall.example:8787/#tile=ab12cd34"


def checked(kind: str, said: dict[str, Any], kept: dict[str, str] | None = None) -> tuple[dict[str, Any], dict[str, str], str]:
    return destinations.check(kind, said, kept or {})


def one(kind: str, config: dict[str, Any], secrets: dict[str, str], alert: alerts.Alert = OFFLINE, **options: Any) -> Any:
    sent = destinations.outgoing(kind, config, secrets, [alert], **{"link": LINK, "minimal": False, **options})
    assert len(sent) == 1, sent
    return sent[0]


def body(post: Post) -> Any:
    return json.loads(post.body)


# --- what each kind takes --------------------------------------------------------------------------------------------


def test_each_kind_takes_what_it_needs_and_shows_only_its_host() -> None:
    config, secrets, host = checked("slack", {"url": "https://hooks.slack.com/services/T0/B0/s3cret"})
    assert (config, secrets, host) == ({}, {"url": "https://hooks.slack.com/services/T0/B0/s3cret"}, "hooks.slack.com")
    assert checked("ntfy", {"url": "https://ntfy.example.org/alerts", "token": "tk_abcdefghijklmnopqrstuvwxyz123"})[1]["token"].startswith("tk_")
    assert checked("telegram", {"token": "123456789:AAH-abc_DEF", "chat": "-1001234567890"})[:3] == ({"chat": "-1001234567890"}, {"token": "123456789:AAH-abc_DEF"}, "api.telegram.org")
    assert checked("pagerduty", {"key": "R0UT1NGKEY0123456789abcdefABCDEF", "region": "eu"})[2] == "events.eu.pagerduty.com"
    assert checked("pagerduty", {"key": "R0UT1NGKEY0123456789abcdefABCDEF"})[2] == "events.pagerduty.com"
    config, secrets, host = checked("resend", {"key": "re_123456789_abcdefghij", "sender": "qKVM <alerts@example.com>", "to": ["ops@example.com"]})
    assert (config, host) == ({"sender": "qKVM <alerts@example.com>", "to": ["ops@example.com"]}, "api.resend.com")
    config, secrets, host = checked("email", {"host": "smtp.gmail.com", "port": 587, "user": "me@gmail.com", "password": "abcd efgh ijkl mnop", "sender": "me@gmail.com", "to": ["ops@example.com", "oncall@example.com"]})
    assert config == {"host": "smtp.gmail.com", "port": 587, "user": "me@gmail.com", "sender": "me@gmail.com", "to": ["ops@example.com", "oncall@example.com"]}
    assert secrets == {"password": "abcd efgh ijkl mnop"} and host == "smtp.gmail.com"
    assert checked("webhook", {"url": "https://example.org/hook", "format": "auto"})[0] == {"format": "auto"}


def test_a_secret_left_empty_is_the_one_kept() -> None:
    kept = {"url": "https://hooks.slack.com/services/T0/B0/s3cret"}
    assert checked("slack", {"url": ""}, kept)[1] == kept
    assert checked("telegram", {"token": "", "chat": "@my_channel"}, {"token": "1:abc"})[1] == {"token": "1:abc"}
    assert checked("email", {"host": "smtp.example.com", "port": 465, "user": "u", "password": "", "sender": "a@example.com", "to": ["b@example.com"]}, {"password": "kept"})[1] == {"password": "kept"}
    with pytest.raises(ValueError):
        checked("slack", {"url": ""})  # nothing typed, nothing kept


def test_another_receiver_is_another_address_chat_routing_key_or_recipients_and_nothing_else() -> None:
    # (The outside review of 0.4.0, bugs round 2, M6.) What a destination was told goes with its receiver: edited to another
    # one it starts with nothing known (server.change_destination). Wider than where a credential goes (`reached`).
    def receiver(kind: str, said: dict[str, Any], kept: dict[str, str] | None = None) -> str:
        config, secrets, _ = destinations.check(kind, said, kept or {})
        return destinations.receiver(kind, config, secrets)

    room = {"url": "https://hooks.example.com/old-room", "format": "json"}
    assert receiver("webhook", room) == receiver("webhook", {**room, "format": "auto"}) == receiver("webhook", room, {"signing": "whsec_" + "A" * 32})
    assert receiver("webhook", room) != receiver("webhook", {**room, "url": "https://hooks.example.com/new-room"})
    assert receiver("webhook", room) != receiver("webhook", {**room, "url": "https://other.example.com/old-room"})
    assert receiver("ntfy", {"url": "https://ntfy.sh/a"}) == receiver("ntfy", {"url": "https://ntfy.sh/a", "token": "tk_x"}) != receiver("ntfy", {"url": "https://ntfy.sh/b"})
    chat = {"token": "123456789:AAH-one", "chat": "-1001"}
    assert receiver("telegram", chat) == receiver("telegram", {**chat, "token": "987654321:AAH-two"}) != receiver("telegram", {**chat, "chat": "-1002"})
    key = {"key": "R0UT1NGKEY0123456789abcdefABCDEF"}
    assert receiver("pagerduty", key) != receiver("pagerduty", {"key": "R0UT1NGKEY0123456789abcdefABCDEX"})
    assert receiver("pagerduty", key) != receiver("pagerduty", {**key, "region": "eu"})
    mail = {"host": "smtp.example.com", "port": 587, "user": "u", "password": "one-1", "sender": "a@example.com", "to": ["b@example.com", "c@example.com"]}
    assert receiver("email", mail) == receiver("email", {**mail, "password": "two-2", "sender": "z@example.com", "to": ["c@EXAMPLE.com", "b@example.com"]})
    assert receiver("email", mail) != receiver("email", {**mail, "to": ["b@example.com"]}) != receiver("email", {**mail, "host": "smtp.example.net"})
    # (The outside review 6.2 re-check, R8.) The part before the @ is the mailbox's own, as its mail server reads it, and goes on the
    # wire as it is: another case of it may be another mailbox, which was sent a recovery of a trouble it never heard of.
    assert receiver("email", mail) != receiver("email", {**mail, "to": ["C@example.com", "b@example.com"]})
    mailed = {"key": "re_123456789_abcdefghij", "sender": "a@example.com", "to": ["b@example.com"]}
    assert receiver("resend", mailed) == receiver("resend", {**mailed, "key": "re_987654321_abcdefghij"}) != receiver("resend", {**mailed, "to": ["d@example.com"]})
    assert "old-room" not in receiver("webhook", room) and key["key"] not in receiver("pagerduty", key)  # (a mark: never the secret)


@pytest.mark.parametrize(
    "kind, said",
    [
        ("slack", {"url": "ftp://hooks.slack.com/x"}),
        ("slack", {"url": "https://hooks.slack.com/a b"}),
        ("teams", {"url": "http://prod-01.westeurope.logic.azure.com/workflows/x"}),  # Microsoft's are https
        ("telegram", {"token": "123:abc@attacker.example:8080/x", "chat": "1"}),  # a token that would move the address
        ("telegram", {"token": "123:abc", "chat": "1; drop"}),
        ("telegram", {"token": "abc", "chat": "1"}),
        ("pagerduty", {"key": "short"}),
        ("pagerduty", {"key": "R0UT1NGKEY0123456789abcdefABCDEF", "region": "mars"}),
        ("resend", {"key": "not-a-resend-key", "sender": "a@example.com", "to": ["b@example.com"]}),
        ("resend", {"key": "re_123456789_abcdefghij", "sender": "a@example.com", "to": []}),
        ("email", {"host": "smtp.example.com", "port": 25, "password": "xxxx", "sender": "a@example.com", "to": ["b@example.com"]}),
        ("email", {"host": "https://smtp.example.com", "port": 587, "password": "xxxx", "sender": "a@example.com", "to": ["b@example.com"]}),
        ("email", {"host": "smtp.example.com", "port": 587, "password": "xxxx", "sender": "a@example.com\r\nBcc: all@example.com", "to": ["b@example.com"]}),
        ("email", {"host": "smtp.example.com", "port": 587, "password": "xxxx", "sender": "a@example.com", "to": ["b@example.com\nBcc: x@example.com"]}),
        ("email", {"host": "smtp.example.com", "port": 587, "password": "xxxx", "sender": "a@example.com", "to": [f"b{n}@example.com" for n in range(11)]}),
        ("webhook", {"url": "https://example.org/hook", "format": "xml"}),
        ("carrier-pigeon", {"url": "https://example.org/hook"}),
    ],
)  # fmt: skip
def test_what_a_kind_does_not_take(kind: str, said: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        checked(kind, said)


@pytest.mark.parametrize(
    "url",
    [
        "https://outlook.office.com/webhook/a@b/IncomingWebhook/c/d",
        "https://outlook.office365.com/webhook/a@b/IncomingWebhook/c/d",
        "https://contoso.webhook.office.com/webhookb2/a@b/IncomingWebhook/c/d",
    ],
)
def test_the_retired_office_365_connectors_of_teams_are_refused_with_the_reason(url: str) -> None:
    with pytest.raises(ValueError) as refused:
        checked("teams", {"url": url})
    assert "retired" in str(refused.value) and "Workflows" in str(refused.value)
    assert checked("teams", {"url": "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=S1G"})[2] == "prod-12.westeurope.logic.azure.com"


NBSP = chr(0xA0)  # (a blank that is no space: str.strip() takes it off too)
MAIL = {"host": "smtp.example.com", "port": 587, "user": "alerts@example.com", "sender": "alerts@example.com", "to": ["ops@example.com"]}


def test_a_typed_mail_password_is_kept_as_it_was_typed() -> None:
    # (The outside review of 0.4.0, round 6.2, M8.) A mail password was taken as a host's name is, with the blanks
    # at its ends left out: a relay whose password has them refused every login, and every alert with it. Typed, it is kept
    # sign for sign; nothing typed is still the one saved; a control character is still no part of a line.
    for typed in ("  example fixture  ", " leading-blank", f"trailing-blank{NBSP}", "in  the  middle"):
        assert checked("email", {**MAIL, "password": typed})[1] == {"password": typed}, repr(typed)
    assert checked("email", {**MAIL, "password": ""}, {"password": "  kept as typed  "})[1] == {"password": "  kept as typed  "}
    assert checked("email", {**MAIL, "password": None}, {"password": "  kept as typed  "})[1] == {"password": "  kept as typed  "}
    for wrong in ("tab\tinside", "line\nbreak", "nul\x00", "del\x7f", 1234):
        with pytest.raises(ValueError, match="password"):
            checked("email", {**MAIL, "password": wrong})
    # Typed with its blanks for another server, it is the one typed for it: not a saved one taken elsewhere.
    assert destinations.check("email", {**MAIL, "host": "mail.example.org", "password": "  typed for it  "}, {"password": "kept-pass"}, "smtp://smtp.example.com:587")[1] == {"password": "  typed for it  "}
    with pytest.raises(ValueError, match="password again"):
        destinations.check("email", {**MAIL, "host": "mail.example.org", "password": ""}, {"password": "kept-pass"}, "smtp://smtp.example.com:587")


@pytest.mark.parametrize("password", ["q7z", "OK", "x", "  ab  ", "   ", f" {NBSP}abc{NBSP} "])
def test_a_mail_password_too_short_to_be_told_from_the_servers_words_is_refused_typed_or_saved(password: str) -> None:
    # (The outside review 6.2, H2.) What a mail server says is shown (Send test, the delivery log, the activity log), a password said
    # back in it taken out (scrub). One shorter than what egress looks for (egress.LEAST_WHOLE) came back whole: "Login
    # refused (q7z)" stayed as it was. Taken out, a password that short could not be told apart from the server's own words
    # ("250 2.0.0 OK" of "OK"), and what was taken out would say which word it is. It is refused where it is typed, and a
    # saved one as it is used (server.destination_target checks what is saved so): nothing goes out with it, and the
    # delivery log says why.
    with pytest.raises(ValueError) as typed:
        checked("email", {**MAIL, "password": password})
    with pytest.raises(ValueError) as saved:
        checked("email", MAIL, {"password": password})
    for refused in (typed, saved):
        assert f"{egress.LEAST_WHOLE} characters at the least" in str(refused.value) and password.strip() not in str(refused.value).split(), str(refused.value)
    assert checked("email", {**MAIL, "password": "q7z!"})[1] == {"password": "q7z!"}  # (four: taken)
    assert checked("email", {**MAIL, "user": ""})[1] == {}  # (a server that takes mail without a login: no password at all)


def test_a_mail_password_said_back_without_the_blanks_at_its_ends_is_taken_out() -> None:
    # (M8's other side.) Kept with its blanks, a password a server says back without them is the password all the same.
    for password in ("  abcd  ", " Mail2024! ", f"{NBSP}hunter2{NBSP}"):
        said = destinations.scrub(f"535 5.7.8 password {password.strip()} not accepted", {"password": password})
        # (Where the blanks stand around it too, the password is found whole with them, and they go with it.)
        assert said in ("535 5.7.8 password [hidden] not accepted", "535 5.7.8 password[hidden]not accepted"), (password, said)
    assert destinations.scrub("535 5.7.8 abcdef not accepted", {"password": "  abcd  "}) == "535 5.7.8 abcdef not accepted"  # (whole only, as ever)


# --- what each kind is sent ------------------------------------------------------------------------------------------


def test_slack_is_sent_text_with_nothing_in_it_that_calls_people() -> None:
    noisy = alerts.describe("<!channel> rack 3", "10.0.0.5", "online", "offline", device_id="x")
    post = one("slack", {}, {"url": "https://hooks.slack.com/services/T/B/x"}, noisy)
    assert post.url == "https://hooks.slack.com/services/T/B/x"
    text = body(post)["text"]
    assert text.startswith("*&lt;!channel&gt; rack 3 is offline*") and "<!channel>" not in text and text.endswith(LINK)


def test_discord_is_sent_its_content_and_may_mention_nobody() -> None:
    sent = body(one("discord", {}, {"url": "https://discord.com/api/webhooks/1/abc"}))
    assert sent["content"].startswith("**Build server is offline**") and sent["content"].endswith(LINK)
    assert sent["allowed_mentions"] == {"parse": []}


def test_teams_is_sent_an_adaptive_card_with_a_button_to_the_wall() -> None:
    sent = body(one("teams", {}, {"url": "https://prod-12.westeurope.logic.azure.com/workflows/abc"}))
    assert sent["type"] == "message"
    card = sent["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    content = card["content"]
    assert content["type"] == "AdaptiveCard" and content["body"][0]["text"] == "Build server is offline"
    assert content["actions"] == [{"type": "Action.OpenUrl", "title": "Open the wall", "url": LINK}]
    # Words a device sent cannot be made into a link of somebody else's.
    sly = alerts.describe("x", "", "online", "error", "[click here](https://evil.example)", device_id="x")
    assert "](" not in json.dumps(body(one("teams", {}, {"url": "https://prod-12.westeurope.logic.azure.com/workflows/abc"}, sly)))


def test_telegram_is_sent_plain_text_to_its_chat() -> None:
    post = one("telegram", {"chat": "-1001234567890"}, {"token": "123456789:AAH-abc_DEF"})
    assert post.url == "https://api.telegram.org/bot123456789:AAH-abc_DEF/sendMessage"
    sent = body(post)
    assert sent["chat_id"] == "-1001234567890" and "parse_mode" not in sent
    assert sent["text"].startswith("Build server is offline\nThe KVM stopped answering.") and sent["text"].endswith(LINK)


def test_ntfy_is_sent_what_0_3_2_sent_and_a_token_where_there_is_one() -> None:
    post = one("ntfy", {}, {"url": "https://ntfy.sh/my-topic"})
    assert post.headers == {"Title": "Build server is offline", "Tags": "warning", "Priority": "high", "Click": LINK}
    assert post.body == "The KVM stopped answering.".encode()
    assert one("ntfy", {}, {"url": "https://ntfy.example.org/t", "token": "tk_x"}).headers["Authorization"] == "Bearer tk_x"


def test_the_json_webhook_keeps_the_fields_of_0_3_2_and_signs_by_standard_webhooks() -> None:
    plain = one("webhook", {"format": "json"}, {"url": "https://example.org/hook"})
    sent = body(plain)
    assert {key: sent[key] for key in ("app", "event", "device", "address", "state", "previous", "title", "message", "link")} == {
        "app": "QKVM", "event": "offline", "device": "Build server", "address": "10.0.0.5", "state": "offline",
        "previous": "online", "title": "Build server is offline", "message": "The KVM stopped answering.", "link": LINK,
    }  # fmt: skip
    assert time.time() - time.mktime(time.strptime(sent["time"], "%Y-%m-%dT%H:%M:%SZ")) < 86400 * 2
    assert "webhook-signature" not in plain.headers  # (no secret: as 0.3.2 sent it)
    secret = destinations.new_signing_secret()
    assert secret.startswith("whsec_") and len(base64.b64decode(secret[6:])) == 32
    signed = one("webhook", {"format": "json"}, {"url": "https://example.org/hook", "signing": secret})
    msg_id, stamp = signed.headers["webhook-id"], signed.headers["webhook-timestamp"]
    expected = base64.b64encode(hmac.new(base64.b64decode(secret[6:]), f"{msg_id}.{stamp}.".encode() + signed.body, hashlib.sha256).digest()).decode()
    assert signed.headers["webhook-signature"] == f"v1,{expected}" and abs(int(stamp) - time.time()) < 60
    assert msg_id.startswith("msg_") and body(signed)["id"] == msg_id


def test_the_signature_is_the_one_the_standard_webhooks_test_vector_gives() -> None:
    said = destinations.sign("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, b'{"test": 2432232314}')
    assert said == "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


def test_an_address_of_0_3_2_whose_service_was_worked_out_is_worked_out_still() -> None:
    assert "content" in body(one("webhook", {"format": "auto"}, {"url": "https://discord.com/api/webhooks/1/abc"}))
    assert "text" in body(one("webhook", {"format": "auto"}, {"url": "https://hooks.slack.com/services/T/B/x"}))
    assert one("webhook", {"format": "auto"}, {"url": "https://ntfy.sh/topic"}).headers["Tags"] == "warning"
    assert body(one("webhook", {"format": "auto"}, {"url": "https://example.org/hook"}))["app"] == "QKVM"


def test_pagerduty_opens_and_resolves_one_incident_per_machine_and_kind_of_trouble() -> None:
    secrets, config = {"key": "R0UT1NGKEY0123456789abcdefABCDEF"}, {"region": "us"}

    def events(alert: alerts.Alert) -> list[dict[str, Any]]:
        sent = destinations.outgoing("pagerduty", config, secrets, [alert], link=LINK, minimal=False)
        assert all(isinstance(post, Post) and post.url == "https://events.pagerduty.com/v2/enqueue" for post in sent)
        return [json.loads(post.body) for post in sent if isinstance(post, Post)]

    [opened] = events(OFFLINE)
    assert (opened["event_action"], opened["dedup_key"], opened["routing_key"]) == ("trigger", "qkvm/ab12cd34/down", secrets["key"])
    assert opened["payload"]["severity"] == "critical" and opened["payload"]["summary"] == "Build server is offline"
    assert opened["links"] == [{"href": LINK, "text": "Open the wall"}]
    back = events(alerts.describe("Build server", "10.0.0.5", "offline", "online", device_id="ab12cd34"))
    assert [(e["event_action"], e["dedup_key"]) for e in back] == [("resolve", "qkvm/ab12cd34/down")]
    # Another kind of trouble: the one before is over, this one opens.
    moved = events(alerts.describe("Build server", "10.0.0.5", "auth", "offline", device_id="ab12cd34"))
    assert [(e["event_action"], e["dedup_key"]) for e in moved] == [("resolve", "qkvm/ab12cd34/login"), ("trigger", "qkvm/ab12cd34/down")]
    # Offline, then answering with no picture: the same trouble (the machine is down), nothing new to open or close.
    assert events(alerts.describe("Build server", "10.0.0.5", "offline", "no_signal", device_id="ab12cd34")) == []
    fault = events(alerts.describe("DB", "10.0.0.9", "online", "error", "The server reports a critical fault", server=True, device_id="cd34", code="health"))
    assert fault[0]["payload"]["severity"] == "critical" and fault[0]["dedup_key"] == "qkvm/cd34/problem"


def test_mail_carries_the_alert_and_nothing_of_where_the_wall_is() -> None:
    config = {"host": "smtp.example.com", "port": 587, "user": "u", "sender": "qKVM <alerts@example.com>", "to": ["ops@example.com", "b@example.com"]}
    mail = one("email", config, {"password": "pw"})
    assert isinstance(mail, Mail) and (mail.host, mail.port, mail.login) == ("smtp.example.com", 587, ("u", "pw"))
    assert mail.sender == "alerts@example.com" and mail.to == ["ops@example.com", "b@example.com"]
    read = message_from_bytes(mail.message.as_bytes(), policy=policy.default)
    assert read["Subject"] == "Build server is offline" and read["To"] == "ops@example.com, b@example.com"
    assert read["Auto-Submitted"] == "auto-generated" and read["Message-ID"].endswith("@example.com>")
    assert LINK in read.get_content() and "The KVM stopped answering." in read.get_content()
    # A name with a line break in it cannot add a header.
    sly = alerts.describe("x\r\nBcc: all@example.com", "", "online", "offline", device_id="x")
    assert b"\nBcc:" not in one("email", config, {"password": "pw"}, sly).message.as_bytes()


def test_resend_is_sent_its_json_with_the_key_as_a_bearer() -> None:
    post = one("resend", {"sender": "qKVM <alerts@example.com>", "to": ["ops@example.com"]}, {"key": "re_123456789_abcdefghij"})
    assert post.url == "https://api.resend.com/emails" and post.headers["Authorization"] == "Bearer re_123456789_abcdefghij"
    sent = body(post)
    assert (sent["from"], sent["to"], sent["subject"]) == ("qKVM <alerts@example.com>", ["ops@example.com"], "Build server is offline")
    assert LINK in sent["text"]


def test_minimal_content_is_the_machine_the_event_and_the_link() -> None:
    sent = body(one("webhook", {"format": "json"}, {"url": "https://example.org/hook"}, minimal=True))
    assert sent["address"] == "" and sent["message"] == "" and sent["title"] == "Build server is offline" and sent["link"] == LINK
    assert body(one("slack", {}, {"url": "https://hooks.slack.com/services/T/B/x"}, minimal=True))["text"] == f"*Build server is offline*\n{LINK}"


def test_many_changes_at_once_are_one_message() -> None:
    many = [alerts.describe(f"Machine {n}", f"10.0.0.{n}", "online", "offline", device_id=f"m{n}") for n in range(40)]
    sent = destinations.outgoing("slack", {}, {"url": "https://hooks.slack.com/services/T/B/x"}, many, link="https://wall.example/", minimal=False)
    assert len(sent) == 1
    text = body(sent[0])["text"]
    assert text.startswith("*40 changes on the wall*") and "Machine 0 is offline" in text and "and 10 more" in text
    # ...but a program reading the JSON webhook, and PagerDuty's incidents, are told each change by itself.
    assert len(destinations.outgoing("webhook", {"format": "json"}, {"url": "https://example.org/hook"}, many, link="", minimal=False)) == 40
    assert len(destinations.outgoing("pagerduty", {"region": "us"}, {"key": "R0UT1NGKEY0123456789abcdefABCDEF"}, many, link="", minimal=False)) == 40


# --- how an answer is read -------------------------------------------------------------------------------------------


def reply(status: int, said: bytes = b"", **headers: str) -> egress.Reply:
    return egress.Reply(status, "", {name.replace("_", "-"): value for name, value in headers.items()}, said)


def test_an_answer_says_how_it_went_in_the_services_own_words() -> None:
    assert destinations.outcome("slack", reply(200, b"ok"), {}).ok
    refused = destinations.outcome("slack", reply(403, b"invalid_token"), {})
    assert (refused.ok, refused.again, refused.said) == (False, False, "HTTP 403: invalid_token")
    telegram = destinations.outcome("telegram", reply(400, b'{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}'), {})
    assert telegram.said == "HTTP 400: Bad Request: chat not found" and not telegram.again
    pagerduty = destinations.outcome("pagerduty", reply(400, b'{"status":"invalid event","message":"Event object is invalid","errors":["Length of \'routing_key\' is incorrect"]}'), {})
    assert pagerduty.said == "HTTP 400: Event object is invalid (Length of 'routing_key' is incorrect)"
    assert destinations.outcome("pagerduty", reply(202, b'{"status":"success"}'), {}).ok
    assert destinations.outcome("discord", reply(204), {}).ok and destinations.outcome("teams", reply(202), {}).ok
    assert not destinations.outcome("webhook", reply(302), {}).ok and "redirect" in destinations.outcome("webhook", reply(302), {}).said


def test_a_busy_or_broken_service_is_tried_again_and_its_wait_honoured() -> None:
    busy = destinations.outcome("slack", reply(429, b"rate_limited", retry_after="7"), {})
    assert (busy.again, busy.wait) == (True, 7.0)
    telegram = destinations.outcome("telegram", reply(429, b'{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}'), {})
    assert (telegram.again, telegram.wait) == (True, 30.0)
    discord = destinations.outcome("discord", reply(429, b'{"message":"You are being rate limited.","retry_after":1.5,"global":false}'), {})
    assert (discord.again, discord.wait) == (True, 1.5)
    assert destinations.outcome("webhook", reply(503), {}).again and destinations.outcome("webhook", reply(500), {}).again
    for status in (400, 401, 403, 404, 410, 413, 422):
        assert not destinations.outcome("webhook", reply(status), {}).again, status
    assert destinations.outcome("webhook", reply(429, retry_after="99999"), {}).wait == destinations.LONGEST_WAIT


def test_no_secret_is_in_what_is_said() -> None:
    secrets = {"url": "https://hooks.example.com/services/T0KEN/S3CRETPATH?sig=Q1W2E3R4T5", "token": "123456:ABCDEF-tok"}
    echo = destinations.outcome("webhook", reply(400, b"bad request to /services/T0KEN/S3CRETPATH?sig=Q1W2E3R4T5 with 123456:ABCDEF-tok"), secrets)
    for piece in ("T0KEN", "S3CRETPATH", "Q1W2E3R4T5", "ABCDEF-tok"):
        assert piece not in echo.said
    assert "[hidden]" in echo.said
    # The host stays: the page shows it anyway, and a sentence about it is no use without it.
    assert destinations.scrub("hooks.example.com did not answer in time", secrets) == "hooks.example.com did not answer in time"
    assert destinations.scrub("535 5.7.8 login failed for pw=hunter2hunter2", {"password": "hunter2hunter2"}) == "535 5.7.8 login failed for pw=[hidden]"
    # One printable line, and short.
    assert destinations.outcome("webhook", reply(400, b"a\r\nb\x00c" + b"x" * 5000), {}).said.startswith("HTTP 400: a b c")
    assert len(destinations.outcome("webhook", reply(400, b"x" * 5000), {}).said) <= 300


def test_a_password_a_person_chose_goes_whole_in_any_spelling_and_the_services_own_words_stay() -> None:
    # (The last look at the fixes of 0.4.0, L1.) A mail login's password is a person's: taken out whole only (in any case,
    # and with every sign that is no letter or digit left out of both), never a part of it, so that the service's own words
    # stay and nothing says which words the password holds. The rest of a destination's secrets are a machine's, and every
    # run of them goes, as before; since the final look, L5, an address's password too (below).
    mail = {"password": "PASSWORD2024!"}
    assert destinations.scrub("535 5.7.8 Username and Password not accepted", mail) == "535 5.7.8 Username and Password not accepted"
    assert destinations.scrub("535 5.7.8 bad password: Password_2024", mail) == "535 5.7.8 bad password: [hidden]"
    passphrase = {"password": "correct-horse-battery-staple"}
    said = '{"error": "bad credentials", "user": "ops", "password": "correct horse battery staple"}'
    assert destinations.scrub(said, passphrase) == '{"error": "bad credentials", "user": "ops", "password": "[hidden]"}'
    assert destinations.scrub("550 incorrect horse in the battery", passphrase) == "550 incorrect horse in the battery"


def test_an_addresss_password_is_a_machines_and_every_run_of_it_goes() -> None:
    # (The final look at 0.4.0, L5.) A password in an address was taken for a person's, and went whole only: a key carried
    # that way (Basic sign-in to an API, ntfy's own login) that a service said back cut came back in part. It is a
    # machine's now, as the rest of an address's secrets are: every run of six of it goes, wherever it stands, a word of the
    # service's that holds six of its signs in a row too ("server" of "WinterServer2024!"). Only a mail login's password
    # is a person's (above).
    api = {"url": "https://api:key-3ax6xnjp29jd6fds4gc373sgvjxteol0@api.example.com/v3/hook"}
    assert destinations.scrub("HTTP 401: Invalid private key: key-3ax6xnjp29jd...", api) == "HTTP 401: Invalid private key: [hidden]..."
    ntfy = {"url": "https://alice:Q7xK2mPz9TwR4vLs@ntfy.example.com/alerts"}
    assert destinations.scrub("HTTP 401: unauthorized: password Q7xK2mPz9T... rejected", ntfy) == "HTTP 401: unauthorized: password [hidden]... rejected"
    hook = {"url": "https://ops:correct-horse-battery-staple@hooks.example.com/qkvm"}
    said = '{"error": "bad credentials", "user": "ops", "password": "correct horse battery staple"}'
    assert destinations.scrub(said, hook) == '{"error": "bad credentials", "user": "ops", "password": "[hidden]"}'
    assert destinations.scrub("HTTP 401: login refused for correct-horse-batt", hook) == "HTTP 401: login refused for [hidden]"
    winter = {"url": "https://ops:WinterServer2024!@hooks.example.com/qkvm/Q7xK2mPz9TwR"}
    assert destinations.scrub("HTTP 401: no such user on this server", winter) == "HTTP 401: no such user on this [hidden]"
    assert destinations.scrub("HTTP 401: bad login WINTERSERVER2024", winter) == "HTTP 401: bad login [hidden]"
    assert destinations.scrub("HTTP 404: no hook xK2mPz9T", winter) == "HTTP 404: no hook [hidden]"  # (the address's token, in part)


@pytest.mark.parametrize(
    "kind, url, said",
    [
        ("discord", "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOp_-AbCdEfGh", '{"message": "Unknown Webhook. Check the webhook settings in the channel", "code": 10015}'),
        # (Made up, and of no shape a real one has: a hook's address of the real shape is taken for a secret by GitHub.)
        ("slack", "https://hooks.slack.com/services/T0QKVMTEST/B0QKVMTEST/not-a-real-hook-qkvm-test", "invalid_payload: this service supports blocks only"),
        (
            "teams", "https://prod-00.westus.logic.azure.com:443/workflows/0a1b2c3d4e5f/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=Q7xK2mPz9TwR4vLs8NbYc3Df",
            "The trigger stopped: manually disabled workflow, invoked by nobody",
        ),
    ],
)
def test_the_words_of_an_address_never_hide_the_services_own_words(kind: str, url: str, said: str) -> None:
    # (The final look at 0.4.0, L3.) A word of an address's path ("webhooks", "services", "triggers", "manual") was looked
    # for with the signs between its letters left out, anywhere: across two of the service's words ("Check the
    # [hidden]ettings"), or within one ("[hidden]ly disabled"). It goes only where it stands whole now; the token of the
    # address wherever it stands, as before.
    assert destinations.scrub(said, {"url": url}) == said
    assert "[hidden]" in destinations.scrub(f"{said} at {urlsplit(url).path}", {"url": url})


def test_a_secret_of_small_letters_goes_as_a_token_does_and_only_an_addresss_words_whole_only() -> None:
    # (The narrow look at 0.4.0, L7.) Every secret of small letters alone was taken out only where it stood whole, and of an
    # address never in part: an ntfy topic, a webhook's id in its path (as Home Assistant's), a token or key of small
    # letters showed cut by a service, written fast to a letter, or in escapes. Of an address, only what stands between its
    # slashes (or is a value of its query) in small letters alone is taken for a word of its own, which a service's own
    # words may hold ("services", "manual"), and goes whole only; anything with another sign among its letters (a dash, a
    # digit, a capital) goes wherever it stands and in every run of six, as every other secret does.
    ntfy = {"url": "https://ntfy.example.org/qkvm-office-alerts", "token": "tk_abcdefghijklmnopqrstuvwxyzabc"}
    assert destinations.scrub("Not Found: the topic xqkvm-office-alertsx is not there", ntfy) == "Not Found: the topic x[hidden]x is not there"
    assert destinations.scrub("Not Found: topic qkvm-offi... not found", ntfy) == "Not Found: topic [hidden]... not found"
    escaped = "".join(f"&#{ord(sign)};" for sign in "tk_abcdefghijklmnopqrstuvwxyzabc")
    assert destinations.scrub(f"401: bad token x{escaped}", ntfy) == "401: bad token x[hidden]"
    home = {"url": "https://ha.example.com/api/webhook/qkvm-alerts-mysecret"}
    assert destinations.scrub("404: no hook named qkvm-alerts-my", home) == "404: no hook named [hidden]"
    assert destinations.scrub("404: no hook named Xqkvm-alerts-mysecret", home) == "404: no hook named X[hidden]"
    # Its words stay words: "webhook settings" holds no "webhooks", nor "manually" "manual".
    teams = {"url": "https://prod-00.westus.logic.azure.com:443/workflows/0a1b2c3d4e5f/triggers/manual/paths/invoke?sp=%2Ftriggers%2Fmanual%2Frun&sig=Q7xK2m"}
    assert destinations.scrub("The trigger stopped: manually disabled workflow, invoked by nobody", teams) == "The trigger stopped: manually disabled workflow, invoked by nobody"


# --- routing ---------------------------------------------------------------------------------------------------------


def test_each_event_has_a_severity_said_in_the_guide() -> None:
    assert destinations.SEVERITY == {
        "offline": "critical", "fault": "critical", "certificate": "error", "auth": "error", "problem": "error", "backup": "error",
        "no_signal": "warning", "unchanged": "warning", "recovered": "info",
    }  # fmt: skip
    assert alerts.describe("x", "", "online", "offline", device_id="x").event == "offline"
    assert alerts.describe("x", "", "online", "offline", code="cert_mismatch", device_id="x").event == "certificate"
    assert alerts.describe("x", "", "online", "error", code="cert_invalid", device_id="x").event == "certificate"
    assert alerts.describe("x", "", "online", "error", code="health", server=True, device_id="x").event == "fault"
    assert alerts.describe("x", "", "online", "error", code="bad_response", device_id="x").event == "problem"
    assert alerts.describe("x", "", "online", "auth", device_id="x").event == "auth"
    assert alerts.describe("x", "", "online", "no_signal", device_id="x").event == "no_signal"
    assert alerts.describe("x", "", "offline", "online", device_id="x").event == "recovered"
    assert alerts.describe_watch("x", "", "unchanged", 30, back=False).event == "unchanged"


def test_a_destination_hears_the_events_it_asked_for_from_the_severity_it_asked_for() -> None:
    critical = {"events": list(destinations.EVENTS), "least": "critical"}
    assert destinations.passes(critical, OFFLINE)
    assert not destinations.passes(critical, alerts.describe("x", "", "online", "no_signal", device_id="x"))
    # "Back to normal" is heard where the trouble it ends was: an incident opened is closed.
    assert destinations.passes(critical, alerts.describe("x", "", "offline", "online", device_id="x"))
    assert not destinations.passes(critical, alerts.describe("x", "", "no_signal", "online", device_id="x"))
    picky = {"events": ["offline"], "least": "info"}
    assert destinations.passes(picky, OFFLINE) and not destinations.passes(picky, alerts.describe("x", "", "offline", "online", device_id="x"))
    assert destinations.passes(picky, alerts.Alert("test", "qKVM", "", "online", "online", "t", "x", event="test"))  # a test goes to whoever is tried


def test_which_machines_as_an_account_is_limited_to_some() -> None:
    assert destinations.covers({"devices": None, "groups": []}, "any", "")
    chosen = {"devices": ["a1"], "groups": ["Rack 3"]}
    assert destinations.covers(chosen, "a1", "")
    assert destinations.covers(chosen, "new", "rack 3")  # a new machine in a chosen group is told, as for an account
    assert not destinations.covers(chosen, "new", "Rack 4")


def test_quiet_hours_recur_and_may_run_past_midnight() -> None:
    night = {"quiet_from": 22 * 60, "quiet_to": 7 * 60, "quiet_days": []}

    def at(day: int, hour: int, minute: int = 0) -> time.struct_time:
        return time.struct_time((2026, 11, 16 + day, hour, minute, 0, day, 320 + day, 0))  # (2026-11-16 is a Monday: day 0)

    assert destinations.quiet(night, at(0, 23)) and destinations.quiet(night, at(1, 6, 59))
    assert not destinations.quiet(night, at(1, 7)) and not destinations.quiet(night, at(0, 12))
    weekend = {"quiet_from": 0, "quiet_to": 24 * 60, "quiet_days": ["sat", "sun"]}
    assert destinations.quiet(weekend, at(5, 12)) and not destinations.quiet(weekend, at(4, 12))
    assert not destinations.quiet({"quiet_from": -1, "quiet_to": -1, "quiet_days": []}, at(0, 3))


def test_a_night_past_midnight_belongs_to_the_day_it_starts_on() -> None:
    # (The second outside review of 0.4.0 found no test held this: the part after midnight counted as that morning's day,
    # and the test above stayed green.) Friday's night runs into Saturday morning, and is Friday's: Saturday's early hours
    # are quiet, Friday's are not (Thursday's night was not chosen), and Saturday's own night is not.
    friday_night = {"quiet_from": 22 * 60, "quiet_to": 7 * 60, "quiet_days": ["fri"]}

    def at(day: int, hour: int, minute: int = 0) -> time.struct_time:
        return time.struct_time((2026, 11, 16 + day, hour, minute, 0, day % 7, 320 + day, 0))  # (day 4 is Friday 2026-11-20)

    assert destinations.quiet(friday_night, at(4, 22)) and destinations.quiet(friday_night, at(4, 23, 59))
    assert destinations.quiet(friday_night, at(5, 0)) and destinations.quiet(friday_night, at(5, 3)) and destinations.quiet(friday_night, at(5, 6, 59))
    assert not destinations.quiet(friday_night, at(5, 7)) and not destinations.quiet(friday_night, at(5, 22))
    assert not destinations.quiet(friday_night, at(4, 3)) and not destinations.quiet(friday_night, at(4, 21, 59))
    # Sunday's night runs into Monday, the week's first day: Sunday's.
    sunday_night = {"quiet_from": 22 * 60, "quiet_to": 7 * 60, "quiet_days": ["sun"]}
    assert destinations.quiet(sunday_night, at(7, 3)) and not destinations.quiet(sunday_night, at(6, 3))


# --- a recovery goes where the trouble was told (the review of 0.4.0's first wave, M1) --------------------------------


def test_back_to_normal_goes_where_the_trouble_was_told_whatever_came_between() -> None:
    pagerduty = {"events": list(destinations.EVENTS), "least": "error"}
    machine = "ab12cd34"

    def change(previous: str, state: str, code: str = "", server: bool = False) -> alerts.Alert:
        return alerts.describe("Build server", "10.0.0.5", previous, state, device_id=machine, code=code, server=server)

    def again(previous: str) -> alerts.Alert:
        return change(previous, "online")

    # A power cut: the KVM goes, comes back without a picture (no news to whoever was told it was offline), then the
    # computer boots. Judged by the last state alone (a warning), the recovery was dropped and PagerDuty's incident stayed.
    told = destinations.fitted(pagerduty, change("online", "offline"), None)
    assert told is not None and told.state == "offline"
    assert destinations.fitted(pagerduty, change("offline", "no_signal"), "offline") is None
    back = destinations.fitted(pagerduty, change("no_signal", "online"), "offline", again)
    assert back is not None and back.previous == "offline" and back.title == "Build server is back"
    [resolve] = destinations.outgoing("pagerduty", {"region": "us"}, {"key": "K" * 32}, [back], link="", minimal=False)
    assert json.loads(resolve.body)["event_action"] == "resolve" and json.loads(resolve.body)["dedup_key"] == f"qkvm/{machine}/down"  # type: ignore[union-attr]
    # A server's critical fault told to a destination of critical alerts alone: its end is told there too.
    critical = {"events": list(destinations.EVENTS), "least": "critical"}
    fault = change("online", "error", code="health", server=True)
    assert destinations.fitted(critical, fault, None) is not None
    assert destinations.fitted(critical, change("error", "online", server=True), "error") is not None
    # Where the trouble was not told, its end is not either; where nothing is known (before 0.4.0), as the state says.
    assert destinations.fitted(pagerduty, change("no_signal", "online"), "") is None
    assert destinations.fitted(pagerduty, change("no_signal", "online"), None) is None
    assert destinations.fitted(pagerduty, change("offline", "online"), None) is not None
    # And "back to normal" is not told where it was not asked for, trouble told or not.
    assert destinations.fitted({"events": ["offline"], "least": "info"}, change("offline", "online"), "offline") is None


def test_a_picture_lost_after_offline_is_told_where_offline_was_not() -> None:
    pictures = {"events": ["no_signal", "recovered"], "least": "info"}  # not "offline"
    alert = alerts.describe("Desk PC", "", "offline", "no_signal", device_id="m1")
    assert destinations.fitted(pictures, alerts.describe("Desk PC", "", "online", "offline", device_id="m1"), None) is None
    told = destinations.fitted(pictures, alert, "")
    assert told is not None and told.title == "Desk PC has no video signal"
    assert destinations.fitted({"events": list(destinations.EVENTS), "least": "info"}, alert, "offline") is None
    # What is known after each, for the next.
    assert destinations.noted(None, alerts.describe("x", "", "online", "offline", device_id="m1"), told=True) == "offline"
    assert destinations.noted(None, alerts.describe("x", "", "online", "offline", device_id="m1"), told=False) == ""
    assert destinations.noted("auth", alerts.describe("x", "", "auth", "offline", device_id="m1"), told=False) == "auth"
    assert destinations.noted("offline", alerts.describe("x", "", "offline", "online", device_id="m1"), told=True) is None


def test_what_each_destination_was_told_is_known_after_a_restart(tmp_path: Path) -> None:
    # A power cut takes the wall down with the machines: what each destination was told before it is written down with the
    # machines' states, so that "back to normal" goes where the trouble went after the restart too.
    kept = tmp_path / "alert-states.json"
    watcher = alerts.Watcher(kept)
    watcher.heard["d1"] = {"m1": "offline", "m2": ""}
    watcher.write(watcher.to_write() or "")
    assert alerts.Watcher(kept).heard == {"d1": {"m1": "offline", "m2": ""}}
    watcher.forget("m1")
    assert watcher.heard == {"d1": {"m2": ""}}
    # What is no state, no id or too long is not taken up.
    kept.write_text(json.dumps({"stable": {}, "heard": {"d1": {"m1": "on fire", "m2": 7, "x" * 65: "offline", "m3": "auth"}, "d2": ["x"]}}), encoding="ascii")
    assert alerts.Watcher(kept).heard == {"d1": {"m3": "auth"}}


def test_a_secret_is_taken_out_before_what_is_said_is_cut_or_its_blanks_closed_up() -> None:
    # (The review of 0.4.0's first wave, L4.) What a service said was cut at 4000 characters and its blanks closed up before
    # its secrets were taken out: 3990 blanks and then a token showed the token's start; a password with two blanks in it
    # was not found once they were one; and the reason phrase of an answer that went well was shown as it came.
    token = {"token": "TOKEN1234567890abcdef"}
    assert "TOKEN1" not in destinations.scrub(" " * 3990 + "TOKEN1234567890abcdef", token)
    assert "TOKEN1" not in destinations.scrub("x" * 3995 + "TOKEN1234567890abcdef", token)
    assert "efgh" not in destinations.scrub("login abcd  efgh failed", {"password": "abcd  efgh"})
    went = destinations.outcome("webhook", egress.Reply(200, "OK for TOKEN1234567890abcdef", {}, b""), token)
    assert went.ok and "TOKEN1" not in went.said
    refused = destinations.outcome("webhook", egress.Reply(403, "Forbidden TOKEN1234567890abcdef", {}, b""), token)
    assert "TOKEN1" not in refused.said


def test_a_picture_lost_after_offline_is_told_from_online_where_nothing_was_told_before() -> None:
    # (The second review, L6.) A destination that hears pictures lost and not machines offline was told "offline, then no
    # picture" with "offline" as what came before: PagerDuty took it for the same trouble, and nothing was opened.
    pictures = {"events": ["no_signal", "recovered"], "least": "info"}

    def again(previous: str) -> alerts.Alert:
        return alerts.describe("Desk PC", "", previous, "no_signal", device_id="m1")

    told = destinations.fitted(pictures, alerts.describe("Desk PC", "", "offline", "no_signal", device_id="m1"), "", again)
    assert told is not None and told.previous == "online"
    [opened] = destinations.outgoing("pagerduty", {"region": "us"}, {"key": "K" * 32}, [told], link="", minimal=False)
    assert json.loads(opened.body)["event_action"] == "trigger"  # type: ignore[union-attr]


def test_the_retype_refusal_says_only_what_fits_the_kind() -> None:
    kept_mail = {"password": "kept-pw"}  # (one of four characters at the least: H2)
    said = {"host": "mail.example.org", "port": 587, "user": "u", "sender": "a@example.com", "to": ["b@example.com"]}
    with pytest.raises(ValueError) as mail:
        destinations.check("email", said, kept_mail, "smtp://smtp.example.com:587")
    assert "password again" in str(mail.value) and "ntfy" not in str(mail.value)
    with pytest.raises(ValueError) as ntfy:
        destinations.check("ntfy", {"url": "https://other.example/t"}, {"url": "https://ntfy.example.org/t", "token": "tk_x"}, "https://ntfy.example.org:443")
    assert "forget" in str(ntfy.value)
