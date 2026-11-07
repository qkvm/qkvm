"""A stand-in push service for the Web Push tests (webpush.py), and a stand-in browser that subscribes to it.

The push service is HTTPS on loopback, with a certificate for the names it stands in for, signed by an authority the
test trusts in place of the public ones; it keeps every request as it came (the encrypted body, the headers, the name
the TLS handshake asked for), and answers with the statuses it is told to. The browser has its own keys, as a real
one has, and reads what arrives with them: what an alert says is proved by decrypting it, as a phone would.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from qkvm import webpush
from tests.test_wall import an_authority, usage

NAMES = ("push.example.com", "updates.push.example.org")  # what the stand-in answers for


@dataclass
class Received:
    path: str
    headers: dict[str, str]
    body: bytes
    asked_for: str | None  # the name the TLS handshake asked for (SNI)


@dataclass
class Service:
    """How the stand-in answers: the statuses to give in turn (then `status`), and how long to take first."""

    status: int = 201
    then: list[int] = field(default_factory=list)
    delay: float = 0.0
    hanging: set[str] = field(default_factory=set)  # paths answered nothing at all
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class FakePush:
    def __init__(self, folder: Path) -> None:
        self.received: list[Received] = []
        self.service = Service()
        self.authority = an_authority()
        self._lock = threading.Lock()
        cert, key = self._certificate(folder)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        named: dict[int, str | None] = {}

        def asked(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
            named[id(sock)] = name

        tls.sni_callback = asked  # type: ignore[assignment]
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                with fake._lock:
                    fake.received.append(Received(self.path, dict(self.headers), body, named.get(id(self.connection))))
                    service = fake.service
                    status = service.then.pop(0) if service.then else service.status
                if self.path in service.hanging:
                    time.sleep(30)
                    return
                if service.delay:
                    time.sleep(service.delay)
                self.send_response(status)
                for name, value in service.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(service.body)))
                self.end_headers()
                self.wfile.write(service.body)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
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
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256())
        )
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / "push-cert.pem", folder / "push-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    def trusting(self) -> ssl.SSLContext:
        """A client's TLS context that trusts this stand-in's authority, and only that: in place of the public list."""
        context = ssl.create_default_context(cadata=self.authority[1].public_bytes(serialization.Encoding.PEM).decode())
        return context

    def put_in_place(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Have the wall's sends reach this stand-in for its names (on loopback, which `vetted` itself never lets through),
        checked against its authority. Any other name is asked of the real `vetted`."""
        real = webpush.vetted
        context = self.trusting()

        async def vetted(host: str, port: int) -> tuple[str, int]:
            return ("127.0.0.1", self.port) if host in NAMES else await real(host, port)

        async def trusted() -> ssl.SSLContext:
            return context

        monkeypatch.setattr(webpush, "vetted", vetted)
        monkeypatch.setattr(webpush, "public_context", trusted)

    def wait_for(self, count: int, timeout: float = 10.0) -> list[Received]:
        deadline = time.monotonic() + timeout
        while len(self.received) < count:
            assert time.monotonic() < deadline, f"the push service got {len(self.received)} of {count}"
            time.sleep(0.02)
        return self.received

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class Browser:
    """A browser's side of a subscription: its keys, and what it reads of what arrives."""

    def __init__(self, path: str = "/send/a-phone", host: str = NAMES[0]) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = os.urandom(16)
        self.endpoint = f"https://{host}{path}"
        point = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.keys = {"p256dh": b64(point), "auth": b64(self.auth)}

    def subscription(self, name: str = "Chrome on Android", key: str | None = None) -> dict[str, Any]:
        """What the page hands the wall for this browser."""
        return {"endpoint": self.endpoint, "keys": self.keys, "name": name, **({"key": key} if key is not None else {})}

    def read(self, received: Received) -> dict[str, Any]:
        """What arrived, as this browser reads it."""
        assert received.headers["Content-Encoding"] == "aes128gcm"
        return dict(json.loads(webpush.decrypt(received.body, self.key, self.auth)))


def signed(authorization: str) -> tuple[dict[str, Any], str]:
    """The claims of a request's Authorization ("vapid t=..., k=..."), where its signature holds for its own key; and that key."""
    scheme, _, rest = authorization.partition(" ")
    assert scheme == "vapid", authorization
    said = dict(part.strip().split("=", 1) for part in rest.split(","))
    return verified(said["t"], said["k"]), said["k"]


def verified(token: str, public: str) -> dict[str, Any]:
    """The claims of a JSON Web Token signed ES256 with this public key (base64url of its point). AssertionError otherwise."""
    head, claims, signature = token.split(".")
    assert json.loads(webpush.unb64(head)) == {"typ": "JWT", "alg": "ES256"}
    raw = webpush.unb64(signature)
    assert len(raw) == 64
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), webpush.unb64(public))
    key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    return dict(json.loads(webpush.unb64(claims)))
