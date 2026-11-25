"""Where the alerts of the tests may arrive: the stand-ins on loopback, by names of their own.

The wall's outbound rules (egress.py) never let an alert through to loopback, and nothing a request can set does. A stand-in
registers a name here with its port; for the tests, egress.vetted leads such a name, and only such a name, to it on
127.0.0.1 (conftest.alert_stand_ins). Every other address is judged by the real rules, in the tests too: a test that posts
to http://127.0.0.1 sees it refused.

`FakeService` stands in for the HTTPS services (Slack, Teams, Telegram, Discord, PagerDuty, Resend, ntfy) under their own
names, with a certificate for them from an authority the test trusts in place of the public ones; it keeps every request
as it came, and answers each name as it is told to.
"""

from __future__ import annotations

import datetime
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qkvm import egress
from tests.stand_ins import STAND_INS, stand_in
from tests.test_wall import an_authority, usage

__all__ = ["STAND_INS", "FakeService", "stand_in"]

SLACK = "hooks.slack.com"
TEAMS = "prod-12.westeurope.logic.azure.com"
TELEGRAM = "api.telegram.org"
DISCORD = "discord.com"
PAGERDUTY = "events.pagerduty.com"
RESEND = "api.resend.com"
NTFY = "ntfy.example.org"
HOOKS = "hooks.example.com"
SERVICES = (SLACK, TEAMS, TELEGRAM, DISCORD, PAGERDUTY, RESEND, NTFY, HOOKS)


@dataclass
class Arrived:
    host: str
    path: str
    headers: dict[str, str]
    body: bytes
    sni: str | None


@dataclass
class Answer:
    status: int = 200
    body: bytes = b"ok"
    headers: dict[str, str] = field(default_factory=dict)
    echo: Callable[[Arrived], bytes] | None = None  # the body made of what arrived (a service that says back what it was sent)


class FakeService:
    """The HTTPS services alerts go to, on loopback. `answers[name]`: what that name answers, in turn (the last for good)."""

    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.arrived: list[Arrived] = []
        self.answers: dict[str, list[Answer]] = {}
        self.authority = an_authority()
        self._lock = threading.Lock()
        named: dict[int, str | None] = {}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self._certificate(folder))

        def asked(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
            named[id(sock)] = name

        context.sni_callback = asked  # type: ignore[assignment]
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                host = (self.headers.get("Host") or "").split(":")[0]
                arrived = Arrived(host, self.path, dict(self.headers), body, named.get(id(self.connection)))
                with fake._lock:
                    fake.arrived.append(arrived)
                    said = fake.answers.get(host) or [Answer()]
                    answer = said.pop(0) if len(said) > 1 else said[0]
                sent = answer.echo(arrived) if answer.echo is not None else answer.body
                self.send_response(answer.status)
                for name, value in answer.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(sent)))
                self.end_headers()
                self.wfile.write(sent)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        for name in SERVICES:
            STAND_INS[name] = self.port
        # Trusted in place of the public authorities: this stand-in's, and whatever a test adds (a stand-in mail server's).
        self.trusted = ssl.create_default_context(cadata=self.authority[1].public_bytes(serialization.Encoding.PEM).decode())
        monkeypatch.setattr(egress, "public_context", self.public_context)

    def _certificate(self, folder: Path) -> tuple[Path, Path]:
        signer, signer_cert = self.authority
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVICES[0])]))
            .issuer_name(signer_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in SERVICES]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256())
        )
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / "services-cert.pem", folder / "services-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    async def public_context(self) -> ssl.SSLContext:
        return self.trusted

    def trust(self, authority: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Trust another stand-in's authority as well (one that put its own trust in place: put back to both)."""
        self.trusted.load_verify_locations(cadata=authority[1].public_bytes(serialization.Encoding.PEM).decode())
        monkeypatch.setattr(egress, "public_context", self.public_context)

    def at(self, host: str) -> list[Arrived]:
        return [each for each in self.arrived if each.host == host]

    def wait_for(self, host: str, count: int, timeout: float = 10.0) -> list[Arrived]:
        deadline = time.monotonic() + timeout
        while len(self.at(host)) < count:
            assert time.monotonic() < deadline, f"{host} got {len(self.at(host))} of {count}"
            time.sleep(0.02)
        return self.at(host)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
