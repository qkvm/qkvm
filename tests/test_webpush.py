"""Web Push by itself (webpush.py): the encryption against RFC 8291's example, the signature against RFC 8292's, the
addresses a push service may and may not be at, and the sending, against a stand-in push service (tests/fake_push.py):
what arrives is read with the browser's keys, as a phone reads it.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from qkvm import webpush
from qkvm.alerts import Alert
from tests.fake_push import NAMES, Browser, FakePush, signed, verified

# RFC 8291, Appendix A: what a push message from an application server looks like, with every key and secret given.
RFC_8291 = {
    "plaintext": "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24",
    "as_public": "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "ua_private": "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "auth_secret": "BTBZMqHH6r4Tts7J_aSIgg",
    "cek": "oIhVW04MRdy2XN9CiKLxTg",
    "nonce": "4h_95klXJ5E_qnoN",
    "body": (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_"
        "yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    ),
}
# RFC 8292, section 2.4 and 3: a request's Authorization, and the public key it is signed with.
RFC_8292_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0."
    "i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA"
)
RFC_8292_KEY = "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs"


def private(text: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(webpush.unb64(text), "big"), ec.SECP256R1())


# --- the RFCs' examples ------------------------------------------------------------------------------------------------


def test_a_message_is_encrypted_as_rfc_8291_s_example_is() -> None:
    v = {name: webpush.unb64(value) for name, value in RFC_8291.items() if name not in ("as_private", "ua_private")}
    as_private, ua_private = private(RFC_8291["as_private"]), private(RFC_8291["ua_private"])
    assert webpush._point(as_private) == v["as_public"] and webpush._point(ua_private) == v["ua_public"]  # (the example is read right)
    shared = as_private.exchange(ec.ECDH(), webpush._browsers(v["ua_public"]))
    assert webpush._keys(shared, v["auth_secret"], v["ua_public"], v["as_public"], v["salt"]) == (v["cek"], v["nonce"])
    # The whole message, to the byte: with the example's key and salt, and no padding (the example has none).
    body = webpush.encrypt(v["plaintext"], v["ua_public"], v["auth_secret"], salt=v["salt"], own=as_private, pad_to=1)
    assert webpush.b64(body) == RFC_8291["body"]
    # ...and the example's message is read as a browser reads it.
    assert webpush.decrypt(v["body"], ua_private, v["auth_secret"]) == b"When I grow up, I want to be a watermelon"


def test_a_signature_is_made_and_checked_as_rfc_8292_s_example_is() -> None:
    # The RFC's own token holds for its own key (the check below is the one every test of the wall's signature uses).
    assert verified(RFC_8292_TOKEN, RFC_8292_KEY) == {"aud": "https://push.example.net", "exp": 1453523768, "sub": "mailto:push@example.com"}
    with pytest.raises(InvalidSignature):
        verified(RFC_8292_TOKEN.replace("eyJhdWQ", "eyJBdWQ"), RFC_8292_KEY)  # (a claim changed: it holds no longer)
    key = webpush.WallKey(webpush.new_key())
    now = 1_800_000_000.0
    claims, public = signed(key.authorization("https://push.example.com", "https://wall.example.org", now=now))
    assert public == key.public_text and len(webpush.unb64(public)) == 65 and webpush.unb64(public)[0] == 4
    assert claims == {"aud": "https://push.example.com", "exp": int(now) + webpush.SIGNED_FOR, "sub": "https://wall.example.org"}
    assert claims["exp"] - now <= 24 * 3600  # what RFC 8292 allows at the most
    # One signature for a while, then a new one; and one for each push service.
    assert key.authorization("https://push.example.com", "https://wall.example.org", now=now + 600) == key.authorization("https://push.example.com", "https://wall.example.org", now=now)
    later = signed(key.authorization("https://push.example.com", "https://wall.example.org", now=now + webpush.SIGNED_FOR - 1800))[0]
    assert later["exp"] > claims["exp"]
    assert signed(key.authorization("https://updates.push.example.org", "https://wall.example.org", now=now))[0]["aud"] == "https://updates.push.example.org"
    # A clock put back meanwhile: not a signature that is good for longer than a day from the time it now says.
    assert signed(key.authorization("https://push.example.com", "https://wall.example.org", now=now - 86400))[0]["exp"] == int(now - 86400) + webpush.SIGNED_FOR


def test_the_walls_key_is_its_private_number_and_nothing_else_is_taken_for_one() -> None:
    text = webpush.new_key()
    assert len(webpush.unb64(text)) == 32 and webpush.WallKey(text).public == webpush.WallKey(text).public
    assert webpush.WallKey(text).public != webpush.WallKey(webpush.new_key()).public
    for wrong in ("", "AAAA", "A" * 43, webpush.b64(bytes(32)), webpush.b64(b"\xff" * 32), "not+base64/", text + "AA"):
        with pytest.raises(ValueError):
            webpush.WallKey(wrong)


def test_a_message_is_read_with_the_browsers_keys_and_with_nothing_else() -> None:
    phone = Browser()
    point = webpush.unb64(phone.keys["p256dh"])
    said = json.dumps({"title": "Büro PC is offline", "body": "The KVM stopped answering."}).encode()
    body = webpush.encrypt(said, point, phone.auth)
    assert webpush.decrypt(body, phone.key, phone.auth) == said
    # Every message has a key of its own: the same words are another message each time.
    assert webpush.encrypt(said, point, phone.auth)[86:] != body[86:]
    # Padded: a short name and a long one come out the same length (to the push service, which sees only the length).
    short = webpush.encrypt(b'{"title":"A"}', point, phone.auth)
    long = webpush.encrypt(b'{"title":"' + b"A" * 200 + b'"}', point, phone.auth)
    assert len(short) == len(long) == 86 + webpush.PAD_TO + 16
    with pytest.raises(ValueError):
        webpush.decrypt(body, Browser().key, phone.auth)  # another browser's key
    with pytest.raises(ValueError):
        webpush.decrypt(body, phone.key, bytes(16))  # another secret
    with pytest.raises(ValueError):
        webpush.decrypt(body[:-1] + bytes([body[-1] ^ 1]), phone.key, phone.auth)  # changed on its way
    with pytest.raises(ValueError):
        webpush.encrypt(b"x" * (webpush.MOST_SAID + 1), point, phone.auth)


def test_what_an_alert_carries_is_its_words_its_tile_and_when() -> None:
    alert = Alert("offline", "Build server", "10.20.30.40:443", "offline", "online", "Build server is offline", "The KVM stopped answering.", "https://wall.example.org/#tile=ab12cd34")
    said = json.loads(webpush.payload(alert, "ab12cd34", at=1_800_000_000.4))
    assert said == {"title": "Build server is offline", "body": "The KVM stopped answering.", "tile": "ab12cd34", "kind": "offline", "at": 1_800_000_000}
    # The longest a name and a text can be, in the widest letters, is still one message.
    wide = Alert("problem", "x", "", "error", "online", "\U0001f525" * 500, "\U0001f525" * 5000)
    assert len(webpush.payload(wide)) <= webpush.MOST_SAID
    assert (webpush.urgency("offline"), webpush.urgency("unchanged"), webpush.urgency("recovered"), webpush.urgency("test")) == ("high", "high", "normal", "normal")


# --- where a push service may be -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://fcm.googleapis.com/fcm/send/abc:def",
        "https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
        "https://web.push.apple.com/QGuFeHvVmUZ2bLDs",
        "https://wns2-par02p.notify.windows.com/w/?token=BQYAAAB",
        "https://web.push.apple.com:443/QGuF",
        "https://xn--bro-hoa.example/x",
    ],
)
def test_the_push_services_addresses_are_taken(endpoint: str) -> None:
    assert webpush.check_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://fcm.googleapis.com/fcm/send/abc",  # not https
        "https://fcm.googleapis.com:8443/fcm/send/abc",  # a port of its own
        "https://127.0.0.1/send",  # a number, not a name
        "https://[::1]/send",
        "https://[fe80::1]/send",
        "https://10.0.0.5/send",
        "https://2130706433/send",  # (127.0.0.1, as one number)
        "https://127.1/send",  # (and as two)
        "https://0x7f.1/send",
        "https://localhost/send",
        "https://push.localhost/send",
        "https://router/send",  # a name of this network only
        "https://nas.local/send",
        "https://kvm.lan/send",
        "https://wall.internal/send",
        "https://box.home.arpa/send",
        "https://pc.tail1234.ts.net/send",
        "https://user:pass@fcm.googleapis.com/send",  # a name and a password in the address
        "https://fcm.googleapis.com/send#part",
        "https://fcm.googleapis.com/send abc",
        "https://fcm.googleapis.com/" + "a" * webpush.LONGEST_ENDPOINT,
        "https://bücher.example/x",  # (to be written in its xn-- form)
        "ftp://fcm.googleapis.com/x",
        "",
        None,
        42,
    ],
)
def test_no_address_into_this_network_or_of_another_kind_is_taken(endpoint: Any) -> None:
    with pytest.raises(ValueError):
        webpush.check_endpoint(endpoint)


def test_a_subscription_has_a_browsers_keys() -> None:
    phone = Browser()
    taken = webpush.check(phone.endpoint, phone.keys["p256dh"], phone.keys["auth"])
    assert (taken.endpoint, taken.auth, taken.host) == (phone.endpoint, phone.auth, NAMES[0])
    off_the_curve = webpush.b64(b"\x04" + bytes(64))
    for p256dh, auth in ((off_the_curve, phone.keys["auth"]), (phone.keys["p256dh"], webpush.b64(bytes(15))), (phone.keys["auth"], phone.keys["auth"]), (phone.keys["p256dh"] + "!", phone.keys["auth"]), (None, phone.keys["auth"])):
        with pytest.raises(ValueError):
            webpush.check(phone.endpoint, p256dh, auth)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5", "172.16.3.4", "192.168.1.10", "127.0.0.1", "127.8.9.10", "0.0.0.0", "169.254.169.254", "100.64.0.1",  # private, loopback, link-local (a cloud's metadata), CGNAT
        "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "192.0.2.1", "198.18.0.1",  # multicast, kept aside, for documentation and tests
        "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1",  # IPv6: loopback, link-local, unique local, multicast, documentation
        "fec0::1", "feff::8.8.8.8",  # IPv6's old site-local: a network's own, as unique local is now (Python counts it global)
        "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "64:ff9b::7f00:1", "2002:a00:1::1", "2002:c0a8:101::1", "::10.0.0.1",  # an IPv4 one inside
        "fe80::1%eth0", "not an address", "",
        # The local-use NAT64 prefix (RFC 8215): where its IPv4 sits is its translator's to choose, at /64 here 10.0.0.8,
        # which read as /96 is 8.0.0.0 (the outside review of 0.3.0, Codex's M5); and at /96 a public one, all the same
        "64:ff9b:1:abcd:a:0:800:0", "64:ff9b:1::808:808",
    ],
)  # fmt: skip
def test_no_address_of_this_network_is_public(address: str) -> None:
    assert webpush.public(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "17.253.144.10", "142.250.74.10", "2001:4860:4860::8888", "2a00:1450:4001:82a::200a", "::ffff:8.8.8.8", "64:ff9b::808:808"])
def test_the_internets_addresses_are_public(address: str) -> None:
    assert webpush.public(address) is True


def test_a_name_is_followed_only_where_every_address_it_leads_to_is_public(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: dict[str, list[str]] = {
        "push.example.com": ["142.250.74.10", "2a00:1450:4001:82a::200a"],
        "inside.example.com": ["10.0.0.5"],  # a public name that leads into this network (rebinding, or a DNS server somebody runs)
        "both.example.com": ["142.250.74.10", "192.168.1.1"],  # one of each: not followed either
        "v6.example.com": ["fd00::5"],
        "mapped.example.com": ["::ffff:192.168.1.1"],
        "nowhere.example.com": [],
    }
    asked: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        asked.append(host)
        if host == "slow.example.com":
            await asyncio.sleep(10)
        return answers[host]

    monkeypatch.setattr(webpush, "resolve", resolve)
    monkeypatch.setattr(webpush, "RESOLVE_TIMEOUT", 0.2)
    assert asyncio.run(webpush.vetted("push.example.com", 443)) == ("142.250.74.10", 443)
    for host in ("inside.example.com", "both.example.com", "v6.example.com", "mapped.example.com"):
        with pytest.raises(webpush.NotPublic):
            asyncio.run(webpush.vetted(host, 443))
    with pytest.raises(OSError):
        asyncio.run(webpush.vetted("nowhere.example.com", 443))
    with pytest.raises(TimeoutError):
        asyncio.run(webpush.vetted("slow.example.com", 443))


# --- sending, to a stand-in push service ---------------------------------------------------------------------------


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakePush]:
    push = FakePush(tmp_path / "push")
    push.put_in_place(monkeypatch)
    monkeypatch.setattr(webpush, "RETRY_AFTER", (0.05, 0.1, 0.2))
    yield push
    push.close()


def target(phone: Browser, push_id: str = "ab12cd34") -> webpush.Target:
    return webpush.Target(push_id, webpush.check(phone.endpoint, phone.keys["p256dh"], phone.keys["auth"]))


class Sent:
    """A Pusher with the wall's key, and the browsers it was told are gone."""

    def __init__(self) -> None:
        self.key = webpush.WallKey(webpush.new_key())
        self.gone: list[str] = []

        async def gone(push_id: str) -> None:
            self.gone.append(push_id)

        self.pusher = webpush.Pusher(lambda: self.key, gone)


def run(work: Any) -> Any:
    return asyncio.run(work)


async def until(happened: Any, what: str, seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while not happened():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.01)


def test_an_alert_arrives_encrypted_signed_and_at_the_name_it_was_sent_to(service: FakePush) -> None:
    phone, sent = Browser(), Sent()
    said = webpush.payload(Alert("no_signal", "NAS", "", "no_signal", "online", "NAS has no video signal", "The computer is off."), "ab12cd34")

    async def once() -> None:
        await sent.pusher.send(target(phone), said, "high")
        await sent.pusher.close()

    run(once())
    [got] = service.received
    assert got.path == "/send/a-phone" and got.asked_for == NAMES[0]  # to the name: in the TLS handshake (whose certificate is for it)...
    assert got.headers["Host"] == NAMES[0]  # ...and in the request
    assert (got.headers["TTL"], got.headers["Urgency"], got.headers["Content-Type"]) == (str(webpush.TTL), "high", "application/octet-stream")
    assert phone.read(got) == json.loads(said)
    claims, public = signed(got.headers["Authorization"])
    assert public == sent.key.public_text and claims["aud"] == f"https://{NAMES[0]}" and claims["sub"] == webpush.CONTACT
    assert time.time() < claims["exp"] <= time.time() + 24 * 3600


def test_a_push_service_that_is_away_is_tried_again_and_one_that_says_gone_is_not(service: FakePush) -> None:
    phone, sent = Browser(), Sent()

    async def deliver(statuses: list[int]) -> None:
        service.service.then = statuses
        sent.pusher.put(target(phone), b'{"title":"x"}')
        await until(lambda: not sent.pusher.waiting("ab12cd34"), "still sending")

    async def scenario() -> None:
        await deliver([503, 429])  # away, busy: tried again, and it arrives
        assert len(service.received) == 3 and sent.pusher.told["ab12cd34"][1] is None and sent.gone == []
        await deliver([400])  # refused for good: not again
        assert len(service.received) == 4 and "HTTP 400" in str(sent.pusher.told["ab12cd34"][1])
        await deliver([410])  # no longer subscribed: taken off the list, and not tried again
        assert len(service.received) == 5 and sent.gone == ["ab12cd34"]
        await deliver([404])
        assert len(service.received) == 6 and sent.gone == ["ab12cd34", "ab12cd34"]
        service.service.status = 503
        await deliver([])  # away for good: four tries, then given up
        assert len(service.received) == 10 and "HTTP 503" in str(sent.pusher.told["ab12cd34"][1])
        await sent.pusher.close()

    run(scenario())


def test_a_refusal_says_the_services_reason_and_no_more_of_its_answer(service: FakePush) -> None:
    phone, sent = Browser(), Sent()
    service.service.status = 403
    service.service.body = b'{"reason":"BadJwtToken","more":"' + b"x" * 100_000 + b'"}'

    async def once() -> str:
        try:
            await sent.pusher.send(target(phone), b"{}")
        except webpush.NotDelivered as ex:
            return str(ex)
        finally:
            await sent.pusher.close()
        raise AssertionError("delivered")

    said = run(once())
    assert "HTTP 403, BadJwtToken" in said and "x" * 10 not in said
    service.service.body = b'{"reason":"<script>alert(1)</script>"}'
    assert "script" not in run(once())


def test_a_push_service_that_never_answers_holds_up_no_other_browser(service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webpush, "SEND_TIMEOUT", 0.5)
    monkeypatch.setattr(webpush, "RETRY_AFTER", ())
    stuck, fine, sent = Browser("/send/stuck"), Browser("/send/fine", host=NAMES[1]), Sent()

    async def scenario() -> float:
        service.service.hanging = {"/send/stuck"}
        sent.pusher.put(target(stuck, "stuck111"), b'{"title":"one"}')
        await until(lambda: service.received, "nothing reached the push service")
        started = time.monotonic()
        sent.pusher.put(target(fine, "fine2222"), b'{"title":"two"}')
        await until(lambda: "fine2222" in sent.pusher.told, "the other browser was not told")
        took = time.monotonic() - started
        await until(lambda: "stuck111" in sent.pusher.told, "the push service that never answers was waited for")
        await sent.pusher.close()
        return took

    took = run(scenario())
    assert took < 0.4  # the other browser's alert went at once, while the first one's push service kept it waiting
    assert sent.pusher.told["fine2222"][1] is None
    assert sent.pusher.told["stuck111"] == (None, "The push service could not be reached (TimeoutError)")  # ...which was given up on in time


def test_a_browsers_alerts_arrive_in_order_and_no_more_than_so_many_wait(service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    phone, sent = Browser(), Sent()
    service.service.delay = 0.05

    async def scenario() -> None:
        for number in range(webpush.MOST_WAITING + 5):
            sent.pusher.put(target(phone), json.dumps({"title": str(number)}).encode())
        await until(lambda: not sent.pusher.waiting("ab12cd34"), "still sending")
        await sent.pusher.close()

    run(scenario())
    titles = [phone.read(got)["title"] for got in service.received]
    # All of them were put in at once (a power cut, and every machine gone together): the oldest gave way, the newest
    # MOST_WAITING were sent, in the order they happened.
    assert titles == [str(n) for n in range(5, webpush.MOST_WAITING + 5)]


def test_a_name_that_leads_into_this_network_is_not_sent_to(service: FakePush, monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str, port: int) -> list[str]:
        return ["192.168.1.20"]

    monkeypatch.setattr(webpush, "resolve", resolve)
    phone, sent = Browser(host="inside.example.com"), Sent()

    async def once() -> webpush.NotDelivered:
        try:
            await sent.pusher.send(target(phone), b"{}")
        except webpush.NotDelivered as ex:
            return ex
        finally:
            await sent.pusher.close()
        raise AssertionError("delivered")

    refused = run(once())
    assert refused.again is False and "not on the internet" in str(refused) and "192.168" not in str(refused)
    assert service.received == []


def test_without_the_walls_key_nothing_is_sent(service: FakePush) -> None:
    phone = Browser()

    async def gone(push_id: str) -> None:
        raise AssertionError(push_id)

    pusher = webpush.Pusher(lambda: None, gone)

    async def once() -> None:
        with pytest.raises(webpush.NotDelivered, match="key for push does not open"):
            await pusher.send(target(phone), b"{}")
        await pusher.close()

    run(once())
    assert service.received == []


@pytest.mark.parametrize("wait_at", ["the name", "a place to send"])
def test_an_alert_is_asked_once_more_after_its_sends_waits(monkeypatch: pytest.MonkeyPatch, wait_at: str) -> None:
    # (The outside review's second round, R2-L1: the account was asked before a send, and the send then waited for a
    # place among those at once and for its push service's name: an account suspended meanwhile was told all the same.)
    async def run() -> None:
        allowed_now = True
        asked, named, go_on = asyncio.Event(), asyncio.Event(), asyncio.Event()
        posted: list[httpx.Request] = []

        def allowed(push_id: str, about: str | None) -> bool:
            assert (push_id, about) == ("phone", "private-device")
            asked.set()
            return allowed_now

        async def resolve(host: str, port: int) -> list[str]:
            named.set()
            await go_on.wait()
            return ["8.8.8.8"]

        async def context() -> Any:
            return None

        async def gone(push_id: str) -> None:
            raise AssertionError("its push service said nothing of the kind")

        async def receive(request: httpx.Request) -> httpx.Response:
            posted.append(request)
            return httpx.Response(201, request=request)

        monkeypatch.setattr(webpush, "resolve", resolve)
        monkeypatch.setattr(webpush, "public_context", context)
        phone = Browser()
        target = webpush.Target("phone", webpush.check(phone.endpoint, phone.keys["p256dh"], phone.keys["auth"]))
        key = webpush.WallKey(webpush.new_key())
        pusher = webpush.Pusher(lambda: key, gone, allowed)
        pusher._client = httpx.AsyncClient(transport=httpx.MockTransport(receive))
        if wait_at == "a place to send":
            pusher._at_once = asyncio.Semaphore(0)
            go_on.set()
        work = asyncio.create_task(pusher._deliver(target, b'{"title":"told while it was allowed"}', "normal", "private-device"))
        try:
            await asyncio.wait_for(asked.wait(), 2)
            if wait_at == "the name":
                await asyncio.wait_for(named.wait(), 2)
            allowed_now = False  # (suspended meanwhile)
            if wait_at == "the name":
                go_on.set()
            else:
                pusher._at_once.release()
            await asyncio.wait_for(work, 2)
            assert posted == [] and "phone" not in pusher.told
        finally:
            if not work.done():
                work.cancel()
                await asyncio.gather(work, return_exceptions=True)
            await pusher.close()

    asyncio.run(run())
