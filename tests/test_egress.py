"""Where an alert may be sent, and how it gets there (egress.py): the outbound rules of 0.4.0.

Every address a name leads to is judged before anything is sent, and the connection goes to the address that was judged,
with the name where the service looks for it (the Host header, and TLS's SNI and certificate). No redirect is followed,
and no more of an answer is read than says how it went. The stand-ins here are on loopback, which the rules themselves
never let through: they are reached by putting a test's own `vetted` in place, as the Web Push tests do.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qkvm import egress
from tests.test_wall import an_authority, usage

OWN = frozenset({"203.0.113.40", "2001:db8::40"})  # where the wall of these tests listens


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254", "169.254.1.1", "fe80::1", "fe80::a:b:c",  # link-local, the clouds' metadata service among them
        "0.0.0.0", "::", "0.1.2.3",  # unspecified, "this network"
        "224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2",  # multicast
        "::ffff:169.254.169.254", "::ffff:0.0.0.0",  # the same, in IPv4-mapped IPv6
        "64:ff9b::a9fe:a9fe",  # ...through a NAT64 gateway (RFC 6052): 169.254.169.254
        "64:ff9b:1::a00:1",  # the local-use NAT64 prefix, where the IPv4 sits is the translator's to choose
        "2002:a9fe:a9fe::1",  # ...in 6to4
        "::169.254.1.1",  # ...and in the old IPv4-compatible form
        "240.0.0.1", "255.255.255.255",  # reserved, the broadcast
        "192.0.2.1", "198.51.100.7", "2001:db8::1",  # kept for documentation: on no network at all
    ],
)  # fmt: skip
def test_what_is_always_refused(address: str) -> None:
    assert egress.judge(address, private_ok=False, own=OWN) is not None
    assert egress.judge(address, private_ok=True, own=OWN) is not None, "the switch for private addresses lets this through"


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1", "10.255.255.254", "172.16.5.4", "172.31.0.1", "192.168.1.20",  # RFC 1918
        "100.64.0.1", "100.100.100.100", "100.127.255.254",  # shared address space (RFC 6598): Tailscale's addresses are in it
        "fd00::1", "fc00::1", "fd7a:115c:a1e0::1",  # unique local (fc00::/7): Tailscale's IPv6 among them
        "::ffff:192.168.1.20", "64:ff9b::c0a8:114", "2002:c0a8:114::1",  # 192.168.1.20 mapped, through NAT64, in 6to4
    ],
)  # fmt: skip
def test_a_private_address_only_with_its_switch(address: str) -> None:
    refused = egress.judge(address, private_ok=False, own=OWN)
    assert refused is not None and "private" in refused
    assert egress.judge(address, private_ok=True, own=OWN) is None


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2a00:1450:4001::1"])
def test_the_internets_addresses_are_let_through(address: str) -> None:
    assert egress.judge(address, private_ok=False, own=OWN) is None


def test_what_is_no_address_is_refused() -> None:
    for odd in ("", "localhost", "fe80::1%eth0", "1.2.3", "not an address"):
        assert egress.judge(odd, private_ok=True, own=OWN) is not None


def test_the_wall_itself_is_refused_whatever_else_it_is() -> None:
    # The owner's decision of 2026-11-17: an alert is never sent to the wall itself, its listen port on any of its addresses
    # and on this computer's loopback, switch or no switch; another port there is what the address otherwise is.
    ports = frozenset({8787})
    assert egress.judge("8.8.4.4", private_ok=False, own=frozenset({"8.8.4.4"}), port=8787, own_ports=ports) is not None
    assert egress.judge("::ffff:8.8.4.4", private_ok=False, own=frozenset({"8.8.4.4"}), port=8787, own_ports=ports) is not None
    assert egress.judge("192.168.1.5", private_ok=True, own=frozenset({"192.168.1.5"}), port=8787, own_ports=ports) is not None
    for loopback in ("127.0.0.1", "127.3.2.1", "::1", "::ffff:127.0.0.1"):
        assert "this wall" in (egress.judge(loopback, private_ok=True, own=frozenset(), port=8787, own_ports=ports) or ""), loopback
    # (Another port at an address of its own: this computer, which the switch lets through, the second review's L5.)
    assert egress.judge("8.8.4.4", private_ok=False, own=frozenset({"8.8.4.4"}), port=443, own_ports=ports) is not None
    assert egress.judge("8.8.4.4", private_ok=True, own=frozenset({"8.8.4.4"}), port=443, own_ports=ports) is None
    assert egress.judge("192.168.1.5", private_ok=True, own=frozenset({"192.168.1.5"}), port=8080, own_ports=ports) is None
    assert egress.judge("192.168.1.6", private_ok=True, own=frozenset({"192.168.1.5"}), port=8787, own_ports=ports) is None


@pytest.mark.parametrize("address", ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "::127.0.0.1"])
def test_this_computer_only_with_the_switch_for_private_addresses(address: str) -> None:
    # The owner's decision of 2026-11-17: loopback is no longer refused whatever the switch. A self-hosted ntfy or a relay
    # on the wall's own computer is a real use (and 0.3.2 sent to one): with "May be a private address", as a network's are.
    refused = egress.judge(address, private_ok=False, own=OWN, port=8080, own_ports=frozenset({8787}))
    assert refused is not None and "this computer" in refused
    assert egress.judge(address, private_ok=True, own=OWN, port=8080, own_ports=frozenset({8787})) is None


def run(job: Any) -> Any:
    return asyncio.run(job)


def test_a_name_is_followed_only_where_every_address_it_leads_to_may_be(monkeypatch: pytest.MonkeyPatch) -> None:
    leads: dict[str, list[str]] = {
        "hooks.example.com": ["8.8.8.8", "2606:4700:4700::1111"],
        "mixed.example.com": ["8.8.8.8", "10.1.2.3"],  # one of them inside: none of them is gone to
        "rebind.example.com": ["::ffff:169.254.169.254"],  # (the metadata service: refused with the switch too; loopback is not since 2026-11-17)
        "lan.example.com": ["192.168.1.20"],
        "nowhere.example.com": [],
    }

    async def resolve(host: str, port: int) -> list[str]:
        return leads[host]

    monkeypatch.setattr(egress, "resolve", resolve)
    assert run(egress.vetted("hooks.example.com", 443, private_ok=False, own=OWN)) == (["8.8.8.8", "2606:4700:4700::1111"], 443)
    for host in ("mixed.example.com", "rebind.example.com", "lan.example.com"):
        with pytest.raises(egress.Refused):
            run(egress.vetted(host, 443, private_ok=False, own=OWN))
    assert run(egress.vetted("lan.example.com", 8080, private_ok=True, own=OWN)) == (["192.168.1.20"], 8080)
    with pytest.raises(egress.Refused):
        run(egress.vetted("rebind.example.com", 443, private_ok=True, own=OWN))
    with pytest.raises(egress.NotReached):
        run(egress.vetted("nowhere.example.com", 443, private_ok=False, own=OWN))
    # An address written as one is judged as it is, with no name looked up.
    with pytest.raises(egress.Refused):
        run(egress.vetted("169.254.169.254", 80, private_ok=True, own=OWN))
    assert run(egress.vetted("2606:4700:4700::1111", 443, private_ok=False, own=OWN)) == (["2606:4700:4700::1111"], 443)


def test_a_name_that_takes_too_long_to_look_up_is_not_waited_for(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str, port: int) -> list[str]:
        await asyncio.sleep(30)
        return ["8.8.8.8"]

    monkeypatch.setattr(egress, "resolve", resolve)
    monkeypatch.setattr(egress, "RESOLVE_TIMEOUT", 0.2)
    started = time.monotonic()
    with pytest.raises(egress.NotReached):
        run(egress.vetted("slow.example.com", 443, private_ok=False, own=OWN))
    assert time.monotonic() - started < 5


def test_a_url_is_taken_only_as_a_web_address_with_nothing_hidden_in_it() -> None:
    assert egress.check_url("https://hooks.slack.com/services/T/B/x") == "https://hooks.slack.com/services/T/B/x"
    assert egress.check_url("  http://ntfy.example.org:8080/topic  ") == "http://ntfy.example.org:8080/topic"
    # A name in another script is written as the internet writes it, and so is a path: as plain characters.
    assert egress.check_url("https://büro.example/café?x=é") == "https://xn--bro-hoa.example/caf%C3%A9?x=%C3%A9"
    assert egress.check_url("https://example.org/hook#part") == "https://example.org/hook"  # (a fragment is never sent)
    for odd in (
        "ftp://example.org/x", "not an address", "https://", "https:///path", "file:///etc/passwd",
        "https://example.org/a" + chr(9) + "b", "https://example.org/a b", "https://exa" + chr(0) + "mple.org/x",
        "https://example.org:0/x", "https://example.org:99999/x", "javascript:alert(1)", "https://[::1/x",
        "https://example.org/" + "x" * 3000,
    ):  # fmt: skip
        with pytest.raises(ValueError):
            egress.check_url(odd)
    with pytest.raises(ValueError):
        egress.check_url("http://example.org/x", https_only=True)


# --- the HTTP stand-in ------------------------------------------------------------------------------------------------

NAMES = ("hooks.example.com", "chat.example.org")  # what the stand-in's certificate is for


class Stand:
    """HTTPS (or plain HTTP) on loopback, answering as it is told, keeping what arrived and the name TLS asked for."""

    def __init__(self, folder: Path, tls: bool = True) -> None:
        self.received: list[dict[str, Any]] = []
        self.status, self.headers, self.body, self.hang = 200, {}, b"", 0.0
        self.authority = an_authority()
        named: dict[int, str | None] = {}
        stand = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                stand.received.append({"path": self.path, "headers": dict(self.headers), "body": body, "sni": named.get(id(self.connection))})
                if stand.hang:
                    time.sleep(stand.hang)
                    return
                self.send_response(stand.status)
                for name, value in stand.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(stand.body)))
                self.end_headers()
                self.wfile.write(stand.body)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*self._certificate(folder))

            def asked(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
                named[id(sock)] = name

            context.sni_callback = asked  # type: ignore[assignment]
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def _certificate(self, folder: Path) -> tuple[Path, Path]:
        signer, signer_cert = self.authority
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAMES[0])]))
            .issuer_name(signer_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in NAMES]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256())
        )
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / "stand-cert.pem", folder / "stand-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    def put_in_place(self, monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...] = (*NAMES, "other.example.net")) -> None:
        """The wall's sends for these names reach this stand-in, checked against its authority alone."""
        context = ssl.create_default_context(cadata=self.authority[1].public_bytes(serialization.Encoding.PEM).decode())

        async def vetted(host: str, port: int, *, private_ok: bool, own: frozenset[str], own_ports: frozenset[int] = frozenset()) -> tuple[list[str], int]:
            assert host in names, host
            return ["127.0.0.1"], self.port

        async def trusted() -> ssl.SSLContext:
            return context

        monkeypatch.setattr(egress, "vetted", vetted)
        monkeypatch.setattr(egress, "public_context", trusted)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def stand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stand]:
    server = Stand(tmp_path)
    server.put_in_place(monkeypatch)
    yield server
    server.close()


def post(url: str, body: bytes = b"{}", **options: Any) -> egress.Reply:
    return run(egress.post(url, body, {"Content-Type": "application/json"}, private_ok=False, own=OWN, **options))


def test_a_post_goes_to_the_vetted_address_with_the_name_where_the_service_looks_for_it(stand: Stand) -> None:
    stand.status, stand.body = 202, b'{"ok":true}'
    reply = post("https://hooks.example.com/services/T0KEN?x=1", b'{"text":"hello"}')
    assert (reply.status, reply.body) == (202, b'{"ok":true}')
    arrived = stand.received[0]
    assert arrived["path"] == "/services/T0KEN?x=1" and arrived["body"] == b'{"text":"hello"}'
    assert arrived["sni"] == "hooks.example.com" and arrived["headers"]["Host"] == "hooks.example.com"
    assert arrived["headers"]["Accept-Encoding"] == "identity" and arrived["headers"]["User-Agent"] == "qKVM"
    # A name and a password in the address are sent as the service expects them, never as part of the path.
    post("https://bot:s3cret@hooks.example.com/hook")
    assert stand.received[-1]["headers"]["Authorization"] == "Basic Ym90OnMzY3JldA==" and stand.received[-1]["path"] == "/hook"


def test_a_secret_is_taken_out_of_what_a_service_says_whole_or_in_part() -> None:
    # (The outside review of 0.4.0, L1: what a request carried never comes back in what is said of its answer.) Whole
    # wherever it stands, and every run of PART of its characters or more, which is how a part of it stands where a service
    # cut it or masked its start; a run of fewer is no part. Runs side by side are one.
    token = "nbp_TheTokenOfAServiceUser0123456789"
    assert egress.hidden(f"bad token {token}, really", [token]) == "bad token [hidden], really"
    assert egress.hidden(f"bad token {token[:14]}...", [token]) == "bad token [hidden]..."
    assert egress.hidden(f"token ****{token[-12:]} not valid", [token]) == "token ****[hidden] not valid"
    assert egress.hidden(f"a {token[:5]} b {token[10:15]} c", [token]) == f"a {token[:5]} b {token[10:15]} c"
    # Parts of what is given as parts only; the whole of what is given as secrets only.
    assert egress.hidden("route S3CRETslack to /services", ["/services"], ["S3CRETslackTOKEN"]) == "route [hidden] to [hidden]"
    assert egress.hidden("abc", ["abc"]) == "abc"  # (three signs are no secret)
    # The Basic header a login in an address is sent as, which a service may say back.
    assert egress.basic("https://bot:s3cret@hooks.example.com/hook") == "Basic Ym90OnMzY3JldA=="
    assert egress.basic("https://hooks.example.com/hook") is None


@pytest.mark.parametrize(
    "password, said",
    [
        ("Password2024!", "535 5.7.8 Username and Password not accepted. Learn more at https://support.example.com/mail/?p=BadCredentials"),
        ("server-alerts", "550 5.1.1 alerts mailbox unavailable on this server"),
        ("WinterServer2024!", "550 5.1.1 mailbox unavailable on this server"),
        ("PASSWORD2024!", "535 5.7.8 Username and Password not accepted"),
        ("MyAlertsMail99", "550 5.1.1 alerts mailbox unavailable"),
        ("Password2024!", "535 5.7.8 Passwords are case sensitive"),
    ],
)
def test_the_servers_own_words_stay_whatever_words_a_persons_password_holds_in_whatever_case(password: str, said: str) -> None:
    # The fresh review of the fixes, N5, and the last look at them, L1: every run of six of a password was taken out
    # wherever it stood, the server's own words too ("Username and [hidden] not accepted" of a password with "Password" in
    # it), which hid what went wrong and said which words the password holds; N5's rule kept such a word only where the
    # password wrote it in small letters or with one capital ("WinterServer2024!" still hid "server", "PASSWORD2024!"
    # "Password", "MyAlertsMail99" "alerts", and "Password2024!" made "Passwords" "[hidden]s"). A password a person chose is
    # taken out whole only, never a part of it: a server's words stay, whatever the password holds.
    assert egress.hidden(said, egress.mail_secrets(("alerts@example.com", password))) == said


def test_a_persons_password_goes_whole_in_any_case_and_spelling_and_never_in_part() -> None:
    # (The last look, L1.) Whole, in any case, and with every sign that is no letter or digit left out of both when it is
    # looked for: a passphrase said back with "+" or "_" between its words (N5's rule kept "correct+horse+battery+staple"
    # whole), a password without its "!".
    mail = egress.mail_secrets(("alerts@example.com", "correct horse battery staple"))
    assert egress.hidden("535 5.7.8 Authentication failed for correct+horse+battery+staple", mail) == "535 5.7.8 Authentication failed for [hidden]"
    dashed = egress.mail_secrets(("alerts@example.com", "Correct-Horse-Battery-Staple"))
    assert egress.hidden("535 rejected: Correct_Horse_Battery_Staple", dashed) == "535 rejected: [hidden]"
    assert egress.hidden("535 rejected: correcthorsebatterystaple.", dashed) == "535 rejected: [hidden]."
    weak = egress.mail_secrets(("alerts@example.com", "server-alerts"))
    assert egress.hidden("rejected: server-alerts, SERVER_ALERTS, Server Alerts", weak) == "rejected: [hidden], [hidden], [hidden]"
    word = egress.mail_secrets(("alerts@example.com", "Password2024!"))
    assert egress.hidden("bad password Password2024", word) == "bad password [hidden]"
    assert egress.hidden("rejected: PASSWORD2024!", word) == "rejected: [hidden]"
    # Never a part: "server-alert" of "server-alerts" stays, as a word of the server's that holds as many of its letters
    # would, and "Passwords" stays whole.
    assert egress.hidden("rejected: server-alert", weak) == "rejected: server-alert"
    assert egress.hidden("rejected: Passwords", word) == "rejected: Passwords"
    # Its base64, as a Basic header carries it after a name, wherever its first byte falls; and as SMTP's AUTH sends it.
    for name in ("ops:", "op:", "o:"):
        encoded = base64.b64encode(f"{name}Correct-Horse-Battery-Staple".encode()).decode()
        cleaned = egress.hidden(f"Authorization: Basic {encoded}", [egress.Password("Correct-Horse-Battery-Staple")])
        assert "[hidden]" in cleaned and not [encoded[at : at + 8] for at in range(8, len(encoded) - 12) if encoded[at : at + 8] in cleaned], (name, cleaned)
    plain = base64.b64encode(b"\0alerts@example.com\0Correct-Horse-Battery-Staple").decode()
    assert egress.hidden(f"535 5.7.8 AUTH PLAIN {plain} refused", dashed) == "535 5.7.8 AUTH PLAIN [hidden] refused"


def test_a_persons_password_said_back_in_html_another_composition_or_with_few_letters_goes_where_it_stands_whole() -> None:
    # (The final look at 0.4.0, L4.) An HTML page that says back a login writes its "&" as "&amp;" or "&#38;": the password
    # came back whole, as did one written composed that was typed decomposed (or the other way round), and one of fewer than
    # six letters and digits with a blank put in (its letters and digits were looked for from six up). HTML's character
    # references are read as the signs they stand for, both texts are compared composed (NFC), and the letters and digits of
    # a person's password are looked for however few: only where they stand whole, the first and the last of them at the
    # edges of runs of letters and digits of the text, so that a word of the server's that holds them stays.
    import unicodedata

    mail = egress.mail_secrets(("alerts@example.com", "Tr0ub4dor&3xyz"))
    for said in ("Tr0ub4dor&amp;3xyz", "Tr0ub4dor&#38;3xyz", "Tr0ub4dor&#x26;3xyz", "&#84;r0ub4dor&amp;3xyz", "<b>Tr0ub4dor&amp;3xyz</b>"):
        assert egress.hidden(f"535 rejected {said}", mail) == f"535 rejected {said}".replace(said.removeprefix("<b>").removesuffix("</b>"), "[hidden]"), said
    composed = "Pässwörter-Zwölf"
    for typed, written in ((composed, unicodedata.normalize("NFD", composed)), (unicodedata.normalize("NFD", composed), composed)):
        assert egress.hidden(f"535 bad password {written}", egress.mail_secrets(("alerts@example.com", typed))) == "535 bad password [hidden]"
    short = egress.mail_secrets(("alerts@example.com", "x9!Q#z"))
    assert egress.hidden("535 rejected x9!Q #z", short) == "535 rejected [hidden]"
    assert egress.hidden("535 rejected X9-q-Z.", short) == "535 rejected [hidden]."
    assert egress.hidden("535 x9qzz and ax9qz rejected", short) == "535 x9qzz and ax9qz rejected"  # (words of the server's own)
    # Whole only, at every length: a word of the server's that holds the password's letters stays whole too.
    alerts = egress.mail_secrets(("alerts@example.com", "alerts-mail"))
    assert egress.hidden("550 5.1.1 alertsmailbox unavailable", alerts) == "550 5.1.1 alertsmailbox unavailable"
    assert egress.hidden("535 bad password alerts_mail", alerts) == "535 bad password [hidden]"


def test_a_word_of_an_address_goes_only_where_it_stands_whole_and_a_token_wherever_it_stands() -> None:
    # (The final look at 0.4.0, L3.) The words of an address's path ("services", "webhooks", "manual") are taken out where
    # they stand whole, and each was looked for with the signs between letters left out, anywhere: across two words of the
    # service's ("webhook settings" held "webhooks"), or within one ("manually" held "manual"). A word of an address (Word,
    # as the caller marks it) is taken out only where it stands whole; a token wherever it stands, also where it is written
    # fast to the service's words (Telegram's bot path).
    webhooks = egress.Word("webhooks")
    assert egress.hidden("Unknown Webhook. Check the webhook settings in the channel", [webhooks], ()) == "Unknown Webhook. Check the webhook settings in the channel"
    assert egress.hidden("invalid_payload: this service supports blocks only", [egress.Word("services")], ()) == "invalid_payload: this service supports blocks only"
    words = [egress.Word(word) for word in ("triggers", "manual", "workflows")]
    assert egress.hidden("The trigger stopped: manually disabled workflow", words, ()) == "The trigger stopped: manually disabled workflow"
    assert egress.hidden("no hook at /api/WEBHOOKS/1 or web-hooks", [webhooks], ()) == "no hook at /api/[hidden]/1 or [hidden]"
    telegram = "123456789:AAH-S3CRETtelegramTOKEN"
    assert egress.hidden("Not Found: /bot" + telegram.replace(":", "") + "x", [telegram], ()) == "Not Found: /bot[hidden]x"


def test_a_secret_of_small_letters_alone_goes_wherever_it_stands_as_a_token_does() -> None:
    # (The narrow look at 0.4.0, L7.) The rule that takes a word of an address out only where it stands whole took in every
    # secret of small letters alone: an ntfy topic, a webhook's id in its path, a token or a key of small letters. Written
    # fast to a letter in escapes, or cut, they showed. Only what the caller marks as a word of an address (Word) goes whole
    # only; every other secret, whatever its letters, wherever it stands, in any spelling, and in every run of six.
    topic = "qkvmofficealerts"
    escaped = "".join(f"&#{ord(sign)};" for sign in topic)
    assert egress.hidden(f"denied: x{escaped}x", [topic]) == "denied: x[hidden]x"
    assert egress.hidden(f"denied: Q{topic.upper()}Q", [topic], ()) == "denied: Q[hidden]Q"
    assert egress.hidden(f"topic {topic[:7]}... not found", [topic]) == "topic [hidden]... not found"
    key = "abcdefabcdefabcdefabcdefabcdefab"  # (a PagerDuty routing key of small letters)
    said = "bad key x" + chr(92) + "u0061" + key[1:] + " here"  # (JSON's escape of its first letter, written fast to an x)
    assert egress.hidden(said, [key]) == "bad key x[hidden] here"
    # A word of an address stays a word of the service's where it is not one of its own.
    assert egress.hidden(f"denied: x{escaped}x", [egress.Word(topic)]) == f"denied: x{escaped}x"


def test_a_short_persons_password_of_one_run_of_letters_and_digits_goes_by_its_own_spelling_alone() -> None:
    # (The narrow look at 0.4.0, L8.) A person's password of fewer than six letters and digits was looked for by those alone,
    # however few, wherever they stood whole: "Mail!" hid the "mail" of the server's own link, "!!!7" the 7 of its code, "a!!!"
    # an "a", which said what the password holds. One of a single run of letters and digits is looked for in its own spelling
    # alone (in any case); one of two runs or more, by its letters and digits where the text shows them in as many runs.
    gmail = "535 5.7.8 Username and Password not accepted. For more information, go to https://support.google.com/mail/?p=BadCredentials (2024, a 7th try)"
    for password in ("Mail!", "!mail!", "#2024!", "!!!7", "a!!!"):
        mail = egress.mail_secrets(("alerts@example.com", password))
        assert egress.hidden(gmail, mail) == gmail, password
        assert egress.hidden(f"535 rejected {password.upper()} for alerts", mail) == "535 rejected [hidden] for alerts", password
    short = egress.mail_secrets(("alerts@example.com", "x9!Q#z"))
    assert egress.hidden("535 rejected x9 q z", short) == "535 rejected [hidden]"
    assert egress.hidden("535 x9q z and x9 qz rejected", short) == "535 x9q z and x9 qz rejected"  # (in other runs: no)


def test_a_machines_secret_goes_whole_in_any_spelling_and_every_run_of_it_with_no_word_kept() -> None:
    # (The last look, L1.) A token, a key, a signing secret, the secret part of a webhook's address: made by a machine, no
    # words. Every run of PART of its signs goes, in any case: also one of letters that reads as a word, which N5's rule
    # kept (an ntfy token's run of small letters said back as a word of its own; one with a capital and small letters).
    assert egress.hidden("denied: mytopicaccess", ["tk_mytopicaccess7Rq2ZK4"]) == "denied: [hidden]"
    assert egress.hidden("Opaque token", ["nbp_9Opaque3Kx7Lm2Qw"]) == "[hidden] token"
    # Whole, with the signs between its letters and digits changed, left out or put in, as a service or what carries its
    # words may do: split over two lines, a blank every fifth sign, its colon and dash left out, an address's escapes,
    # JSON's escapes.
    telegram = "123456789:AAH-S3CRETtelegramTOKEN"
    netbird = "nbp_R3viewTokenOpaque0123456789abcdef"
    assert egress.hidden("error: token 123456789:AAH-S3CRE\nTtelegramTOKEN rejected", [telegram]) == "error: token [hidden] rejected"
    assert egress.hidden("error: token 123456789:AAH-S3CRE\\nTtelegramTOKEN rejected", [telegram]) == "error: token [hidden] rejected"
    assert egress.hidden("got " + " ".join(netbird[at : at + 5] for at in range(0, len(netbird), 5)) + " here", [netbird]) == "got [hidden] here"
    assert egress.hidden("bad 123456789AAHS3CRETtelegramTOKEN", [telegram]) == "bad [hidden]"
    assert egress.hidden("Not Found: /bot" + quote(telegram, safe="") + "/sendMessage", [telegram]) == "Not Found: /bot[hidden]/sendMessage"
    escaped = json.dumps({"echo": netbird}).replace("Token", "\\u0054oken")
    assert egress.hidden(escaped, [netbird]) == '{"echo": "[hidden]"}'
    # (A run is looked for as it stands: with the signs between left out, the letters of the next word would be taken for
    # the run going on, as "to" after "slack" of S3CRETslackTOKEN, one time in thirty-six of a random token.)
    assert egress.hidden("route S3CRETslack to /services", ["/services"], ["S3CRETslackTOKEN"]) == "route [hidden] to [hidden]"


def test_a_secret_said_back_in_another_case_or_in_base64_goes_too() -> None:
    # (N5's misses.) A service that says a token back in small letters, or the header it came in as base64.
    token = "123456789:AAH-S3CRETtelegramTOKEN"
    assert egress.hidden(f"error: token {token.lower()} rejected", [token]) == "error: token [hidden] rejected"
    assert egress.hidden("error: token aah-s3crettele rejected", [token]) == "error: token [hidden] rejected"
    netbird = "nbp_R3viewTokenOpaque0123456789abcdef"
    for header in (f"Token {netbird}", f"Bearer {netbird}", f"x:{netbird}"):  # (its first byte at each of three places)
        encoded = base64.b64encode(header.encode()).decode()
        cleaned = egress.hidden(f"got {encoded} here", [netbird])
        assert "[hidden]" in cleaned and not [encoded[at : at + 8] for at in range(8, len(encoded) - 12) if encoded[at : at + 8] in cleaned], (header, cleaned)


def test_what_a_send_raises_names_the_host_and_nothing_of_the_address_after_it(stand: Stand) -> None:
    # (L1, egress itself.) A path or a query carries a token (Slack's, Telegram's bot): what is raised says the host only.
    for url in ("https://hooks.example.com:0/T0KENsecret1", "https://hooks.example.com/T0KENsecret1\tx", "ftp://hooks.example.com/T0KENsecret1"):
        with pytest.raises(egress.Refused) as refused:
            post(url)
        assert "T0KEN" not in str(refused.value), url
    stand.close()
    with pytest.raises(egress.NotReached) as away:
        post("https://bot:Pa55word@hooks.example.com/T0KENsecret1?sig=S1Gsecret")
    assert "hooks.example.com" in str(away.value) and not any(part in str(away.value) for part in ("T0KEN", "S1G", "Pa55", "Ym90"))


def test_a_certificate_for_another_name_is_refused_and_nothing_is_sent(stand: Stand) -> None:
    with pytest.raises(egress.NotReached) as refused:
        post("https://other.example.net/hook")
    assert "certificate" in str(refused.value) and refused.value.again is False
    assert stand.received == []


def test_a_redirect_is_not_followed(stand: Stand) -> None:
    stand.status, stand.headers = 302, {"Location": "http://169.254.169.254/latest/meta-data/"}
    reply = post("https://hooks.example.com/hook")
    assert reply.status == 302 and len(stand.received) == 1  # said as it came, and gone nowhere else


def test_no_more_of_an_answer_is_read_than_says_how_it_went(stand: Stand) -> None:
    stand.status, stand.body = 400, b"x" * (5 * 1024 * 1024)
    reply = post("https://hooks.example.com/hook")
    assert reply.status == 400 and len(reply.body) == egress.MOST_READ


def test_a_service_that_never_answers_is_let_go_of(stand: Stand, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(egress, "SEND_TIMEOUT", 0.5)
    stand.hang = 20
    started = time.monotonic()
    with pytest.raises(egress.NotReached) as late:
        post("https://hooks.example.com/hook")
    assert late.value.again is True and time.monotonic() - started < 5
    # ...and its connection is closed, not left to its thread: a thread held by every such service would be the wall's last.
    deadline = time.monotonic() + 5
    while egress.under_way():
        assert time.monotonic() < deadline, "the send's thread is still held"
        time.sleep(0.05)


def test_plain_http_where_the_address_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plain = Stand(tmp_path, tls=False)
    try:
        plain.put_in_place(monkeypatch)
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # a proxy the system names is not used for alerts
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        reply = post("http://chat.example.org:8080/topic", b"hello")
        assert reply.status == 200 and plain.received[0]["headers"]["Host"] == "chat.example.org:8080"
    finally:
        plain.close()


def test_the_real_rules_stand_between_a_send_and_this_computer(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as listening:
        listening.bind(("127.0.0.1", 0))
        listening.listen()
        listening.settimeout(0.5)
        port = listening.getsockname()[1]
        for url in (f"http://127.0.0.1:{port}/hook", f"http://[::ffff:127.0.0.1]:{port}/hook", f"http://localhost:{port}/hook"):
            with pytest.raises(egress.Refused):
                run(egress.post(url, b"{}", {}, private_ok=False, own=OWN))
            with pytest.raises(egress.Refused):  # (the wall's own port: never, switch or no switch)
                run(egress.post(url, b"{}", {}, private_ok=True, own=OWN, own_ports=frozenset({port})))
        with pytest.raises(socket.timeout):
            listening.accept()  # nothing ever came


@pytest.mark.parametrize("address", ["fd00:ec2::254", "100.100.100.200", "::ffff:100.100.100.200"])
def test_the_clouds_metadata_services_in_private_ranges_are_refused_whatever_the_switch(address: str) -> None:
    # (The review of 0.4.0's first wave, L1.) AWS's over IPv6 and Alibaba's sit in ranges that "May be a private address"
    # lets through: never sent to all the same, as 169.254.169.254 is not.
    for private_ok in (False, True):
        why = egress.judge(address, private_ok=private_ok, own=OWN)
        assert why is not None and "metadata" in why, why


WALL_V6 = "2003:db8::8888"  # (an address of the internet, as a wall's own may be: judged, never reached)


def no_connection(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """No connection is made, whatever is judged: where one would have been, it is noted and refused here (a test of what
    is refused never reaches an address that is not this computer's, the code before a fix included)."""
    tried: list[str] = []

    async def connect(addresses: list[str], *rest: Any) -> Any:
        tried.extend(addresses)
        raise ConnectionRefusedError("no connection in this test")

    def connected(addresses: list[str], *rest: Any) -> Any:
        tried.extend(addresses)
        raise ConnectionRefusedError("no connection in this test")

    monkeypatch.setattr(egress, "_connect", connect)
    monkeypatch.setattr(egress, "_connected", connected)
    return tried


@pytest.mark.parametrize("zone", ["%1", "%25", "%eth0", "%251", "%25eth0"])
def test_an_ipv6_address_with_a_zone_is_refused_everywhere(zone: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The second outside review of 0.4.0, M1: Python's ipaddress keeps an IPv6 zone (%1, an interface of this computer) in
    # what an address is, and fd00:ec2::254%1 is then not the metadata service fd00:ec2::254, nor the wall's own address
    # with %1 the wall: the switch let the first through, and the wall's own port at its address was let through without
    # it. A literal went that way to the connection, zone and all. An address that names an interface is refused, in an
    # address typed (raw, or written %25 as a web address writes it) and wherever it is judged.
    tried = no_connection(monkeypatch)
    where = f"[fd00:ec2::254{zone}]"
    with pytest.raises(ValueError, match="interface"):
        egress.check_url(f"http://{where}:19463/hook")
    for private_ok in (False, True):
        why = egress.judge(f"fd00:ec2::254{zone}", private_ok=private_ok, own=OWN)
        assert why is not None and "interface" in why, why
    why = egress.judge(f"{WALL_V6}{zone}", private_ok=False, own={WALL_V6}, port=19463, own_ports={19463})
    assert why is not None, why
    with pytest.raises(egress.Refused):
        run(egress.vetted(f"fd00:ec2::254{zone}", 19463, private_ok=True, own=OWN))
    with pytest.raises(egress.Refused):
        run(egress.request("GET", f"https://{where}/hook", None, {}, private_ok=True, own=OWN))
    # A name that leads to such an address (a DNS server somebody runs) is not followed there either.

    async def resolve(host: str, port: int) -> list[str]:
        return [f"fd00:ec2::254{zone}"]

    monkeypatch.setattr(egress, "resolve", resolve)
    with pytest.raises(egress.Refused):
        run(egress.vetted("zoned.example.com", 443, private_ok=True, own=OWN))
    assert tried == []


def test_the_walls_own_addresses_are_its_own_with_a_zone_or_without() -> None:
    # (M1, the other way round.) An own address that came with a zone is the address: the wall's own port there is refused
    # whatever the switch, as it is without one.
    for own in ({f"{WALL_V6}%1"}, {f"{WALL_V6}%eth0"}, {WALL_V6}):
        for private_ok in (False, True):
            why = egress.judge(WALL_V6, private_ok=private_ok, own=own, port=19463, own_ports={19463})
            assert why is not None and "this wall itself" in why, (own, why)


def test_this_computers_own_addresses_are_found_on_every_interface() -> None:
    # A wall that listens on every address never sends to one of them: through a second network card, or its global IPv6, it
    # would be sending to itself. What the computer's name leads to and its route out were all that was known; now every
    # interface's address is, where the system says them (Linux, Windows), with those two besides.
    import ipaddress
    import socket
    import subprocess
    import sys

    found = egress.this_computer()
    assert found and all(ipaddress.ip_address(address) for address in found)
    if sys.platform.startswith("linux"):
        with open("/proc/net/if_inet6", encoding="ascii") as listed:
            for line in listed:
                written = line.split()[0]
                address = str(ipaddress.IPv6Address(int(written, 16)))
                assert address in found, address
        try:
            said = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=10).stdout
        except OSError:
            said = ""
        for line in said.splitlines():
            address = line.split()[3].split("/")[0]
            if line.split()[1] != "lo" and address.count(".") == 3 and " secondary " not in line:
                assert address in found, (address, found)
    else:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            assert str(info[4][0]).split("%")[0] in found


@pytest.mark.parametrize("name", ["faß.de", "σοφίας.gr", "ex‍ample.com", "ex‌ample.com"])
def test_a_name_whose_letters_the_two_idna_standards_read_apart_is_refused(name: str) -> None:
    # (The review of 0.4.0's first wave, L3.) Python's idna codec is IDNA 2003, which maps a sharp s to "ss", a final sigma
    # to a sigma, and drops the joiners; IDNA 2008, which browsers and registries go by, keeps them. "faß.de" became
    # "fass.de", somebody else's name with a certificate of its own. Such a name is refused, with a sentence saying why.
    from qkvm import destinations

    with pytest.raises(ValueError) as refused:
        egress.check_url(f"https://{name}/hook")
    assert "xn--" in str(refused.value)
    with pytest.raises(ValueError) as refused:
        destinations.check("email", {"host": name, "port": 587, "sender": "a@example.com", "to": ["b@example.com"]}, {})
    assert "xn--" in str(refused.value)
    # Other names in other scripts are taken as before, in their plain form.
    assert egress.check_url("https://bücher.example/hook") == "https://xn--bcher-kva.example/hook"


def test_a_name_that_leads_to_both_families_is_reached_at_whichever_answers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # (The full Linux suite of the merged 0.4.0, 2026-11-17.) There `localhost` leads to ::1 first and 127.0.0.1 second;
    # only the first was connected to, and a service listening on 127.0.0.1 alone was "refused". Every address is judged
    # before any is connected to (no other address comes in between), then each is tried in turn, within the one time.
    plain = Stand(tmp_path, tls=False)
    try:
        async def resolve(host: str, port: int) -> list[str]:
            return ["::1", "127.0.0.1"]

        monkeypatch.setattr(egress, "resolve", resolve)
        reply = run(egress.post(f"http://both.example:{plain.port}/hook", b"{}", {}, private_ok=True, own=OWN))
        assert reply.status == 200 and len(plain.received) == 1
        assert run(egress.vetted("both.example", 8080, private_ok=True, own=OWN)) == (["::1", "127.0.0.1"], 8080)
    finally:
        plain.close()


def test_an_address_of_this_computers_own_is_judged_as_loopback_is() -> None:
    # (The second review, L5.) Refused unless the switch is on; at the wall's own port, always.
    own, ports = frozenset({"8.8.4.4", "2a00:1450:4001:80b::200e"}), frozenset({8787})
    for address in ("8.8.4.4", "::ffff:8.8.4.4", "2a00:1450:4001:80b::200e"):
        refused = egress.judge(address, private_ok=False, own=own, port=6379, own_ports=ports)
        assert refused is not None and "this computer" in refused, address
        assert egress.judge(address, private_ok=True, own=own, port=6379, own_ports=ports) is None
        assert "this wall itself" in (egress.judge(address, private_ok=True, own=own, port=8787, own_ports=ports) or "")
    # Never a way past what is refused whatever the switch: a link-local address of the computer's own stays refused.
    assert egress.judge("fe80::1", private_ok=True, own=frozenset({"fe80::1"}), port=80, own_ports=ports) is not None
