"""NetBird's management API, on loopback, for the tests: `GET /api/peers` for the holder of its token, and nothing else.

Served over HTTPS under a name of its own (MANAGEMENT), with a certificate from an authority the test trusts in place of
the public ones, as fake_oidc.FakeIdp is: the wall reaches it by that name only (conftest.alert_stand_ins leads the name,
and nothing else, to 127.0.0.1). `peers` is what it lists; `answer` puts a status and a body in place of the list;
`asked` keeps what it was asked (method, path, the Authorization header).
"""

from __future__ import annotations

import datetime
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qkvm import egress
from tests.stand_ins import STAND_INS
from tests.test_wall import an_authority, usage

MANAGEMENT = "netbird.example.org"
URL = f"https://{MANAGEMENT}"
TOKEN = "nbp_TheTokenOfAServiceUser0123456789"


def peer(name: str, address: str, connected: bool = True) -> dict[str, Any]:
    return {
        "id": f"id-{name}", "name": name, "ip": address, "connected": connected, "dns_label": f"{name}.netbird.selfhosted",
        "hostname": name, "os": "Linux", "groups": [{"id": "g1", "name": "All"}], "ssh_enabled": False,
    }  # fmt: skip


class FakeNetbird:
    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.peers: list[Any] = []
        self.answer: tuple[int, bytes] | None = None
        self.asked: list[tuple[str, str, str]] = []
        self.authority = an_authority()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self._certificate(folder))
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                said = self.headers.get("Authorization", "")
                fake.asked.append(("GET", self.path, said))
                if fake.answer is not None:
                    status, body = fake.answer
                elif self.path != "/api/peers":
                    status, body = 404, b'{"message":"not found","code":404}'
                elif said != f"Token {TOKEN}":
                    status, body = 401, b'{"message":"token invalid","code":401}'
                else:
                    status, body = 200, json.dumps(fake.peers).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        STAND_INS[MANAGEMENT] = self.port
        self.trusted = ssl.create_default_context(cadata=self.authority[1].public_bytes(serialization.Encoding.PEM).decode())
        monkeypatch.setattr(egress, "public_context", self.public_context)

    async def public_context(self) -> ssl.SSLContext:
        return self.trusted

    def _certificate(self, folder: Path) -> tuple[Path, Path]:
        signer, signer_cert = self.authority
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MANAGEMENT)]))
            .issuer_name(signer_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(MANAGEMENT)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256())
        )
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / "netbird-cert.pem", folder / "netbird-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
