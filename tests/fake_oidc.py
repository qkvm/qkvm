"""An identity provider of OpenID Connect, on loopback, for the tests: what it says of itself, its keys (RSA and EC, turned
over at will), its authorization endpoint (asked by the test, in the person's place), its token endpoint (which holds the
code to its PKCE challenge, its redirect address and its client, as a real one does) and its userinfo endpoint.

Served over HTTPS under a name of its own (IDP), with a certificate from an authority the test trusts in place of the
public ones (fake_alerts.FakeService does the same for the alert services). The wall reaches it by that name only:
egress.vetted leads the name, and nothing else, to 127.0.0.1 (conftest.alert_stand_ins).

Everything it does can be made wrong on purpose: `tamper` changes an ID token's header and claims before it is signed,
`signed_as` signs it another way ("none", HS256 with the public key as its secret, a key that is not in the set, a kid
the set does not have), `said` adds to or replaces what it says of itself, and `answers` puts a status and a body in
place of its token endpoint's.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from qkvm import egress
from tests.stand_ins import STAND_INS
from tests.test_wall import an_authority, usage

IDP = "idp.example.org"
ISSUER = f"https://{IDP}/realms/team"
CLIENT = "qkvm-wall"
SECRET = "the-client-secret-S3CRET"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def number(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@dataclass
class SigningKey:
    kid: str
    alg: str  # "RS256" | "ES256"
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

    @staticmethod
    def made(alg: str = "RS256", kid: str | None = None) -> SigningKey:
        private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
        private = rsa.generate_private_key(65537, 2048) if alg == "RS256" else ec.generate_private_key(ec.SECP256R1())
        return SigningKey(kid or secrets.token_hex(6), alg, private)

    def jwk(self) -> dict[str, Any]:
        public = self.private.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            numbers = public.public_numbers()
            return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256", "n": number(numbers.n), "e": number(numbers.e)}
        assert isinstance(public, ec.EllipticCurvePublicKey)
        point = public.public_numbers()
        return {"kty": "EC", "kid": self.kid, "use": "sig", "alg": "ES256", "crv": "P-256", "x": b64(point.x.to_bytes(32, "big")), "y": b64(point.y.to_bytes(32, "big"))}

    def sign(self, data: bytes) -> bytes:
        if isinstance(self.private, rsa.RSAPrivateKey):
            return self.private.sign(data, padding.PKCS1v15(), hashes.SHA256())
        r, s = decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def token_of(header: dict[str, Any], claims: dict[str, Any], sign: Callable[[bytes], bytes]) -> str:
    head = b64(json.dumps(header).encode())
    body = b64(json.dumps(claims).encode())
    return f"{head}.{body}.{b64(sign(f'{head}.{body}'.encode('ascii')))}"


@dataclass
class Person:
    sub: str
    email: str = ""
    email_verified: bool = True
    name: str = ""
    groups: list[str] = field(default_factory=list)
    more: dict[str, Any] = field(default_factory=dict)  # other claims (hd, preferred_username, _claim_names)


@dataclass
class Code:
    person: Person
    client: str
    redirect: str
    challenge: str
    method: str
    nonce: str
    made: float = field(default_factory=time.time)
    used: bool = False


@dataclass
class Asked:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class FakeIdp:
    """The provider. `people` by their login; `groups_in_token` False: groups are said by userinfo alone."""

    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.keys = [SigningKey.made("RS256", "rsa-1")]
        self.signing = self.keys[0]
        self.people: dict[str, Person] = {}
        self.codes: dict[str, Code] = {}
        self.access: dict[str, Person] = {}
        self.asked: list[Asked] = []
        self.said: dict[str, Any] = {}  # added to (or put in place of) what it says of itself; a value of None takes a field away
        self.groups_in_token = True
        self.says_iss = True  # it puts iss into the address it sends a browser back by (RFC 9207)
        self.tamper: Callable[[dict[str, Any], dict[str, Any]], None] | None = None
        self.signed_as: Callable[[bytes], bytes] | None = None  # signs in place of the key named in the header
        self.answers: list[tuple[int, bytes]] = []  # what the token endpoint answers in place of a token, in turn
        self.before_token: Callable[[], None] | None = None  # done before the token endpoint answers (while the wall waits)
        self.before_discovery: Callable[[], None] | None = None  # ...and before it says what it is
        self.userinfo_type = "application/json"
        self.userinfo_extra: dict[str, Any] = {}
        self.authority = an_authority()
        self._lock = threading.Lock()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self._certificate(folder))
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _answer(self, status: int, body: bytes, kind: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                fake._note(self, b"")
                path = urlsplit(self.path).path
                if path == "/realms/team/.well-known/openid-configuration":
                    if fake.before_discovery is not None:
                        fake.before_discovery()
                    self._answer(200, json.dumps(fake.discovery()).encode())
                elif path == "/realms/team/keys":
                    with fake._lock:
                        keys = [key.jwk() for key in fake.keys]
                    self._answer(200, json.dumps({"keys": keys}).encode())
                elif path == "/realms/team/userinfo":
                    status, body = fake.userinfo(self.headers.get("Authorization", ""))
                    self._answer(status, body, fake.userinfo_type if status == 200 else "application/json")
                else:
                    self._answer(404, b'{"error":"not_found"}')

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                fake._note(self, body)
                if urlsplit(self.path).path == "/realms/team/token":
                    status, said = fake.token(self.headers.get("Authorization", ""), body)
                    self._answer(status, said)
                else:
                    self._answer(404, b'{"error":"not_found"}')

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        STAND_INS[IDP] = self.port
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
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, IDP)]))
            .issuer_name(signer_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(IDP)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256())
        )
        folder.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = folder / "idp-cert.pem", folder / "idp-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    def _note(self, handler: BaseHTTPRequestHandler, body: bytes) -> None:
        with self._lock:
            self.asked.append(Asked(handler.command, handler.path, dict(handler.headers), body))

    def at(self, path: str) -> list[Asked]:
        with self._lock:
            return [each for each in self.asked if urlsplit(each.path).path == path]

    # --- what it is ------------------------------------------------------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        said: dict[str, Any] = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/auth",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/keys",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "authorization_response_iss_parameter_supported": self.says_iss,
        }
        said.update(self.said)
        return {key: value for key, value in said.items() if value is not None}

    def rotate(self, alg: str = "RS256", drop_old: bool = False) -> SigningKey:
        """A new key, published and signed with from now on (the old one stays published unless dropped)."""
        made = SigningKey.made(alg)
        with self._lock:
            self.keys = [made] if drop_old else [*self.keys, made]
            self.signing = made
        return made

    def person(self, login: str, **said: Any) -> Person:
        self.people[login] = Person(sub=said.pop("sub", f"sub-{login}-{secrets.token_hex(4)}"), **said)
        return self.people[login]

    # --- the browser's part, done by the test ----------------------------------------------------------------------

    def authorize(self, url: str, login: str, *, state: str | None = None) -> str:
        """The person signs in at the provider: the path and query (on the wall) the browser is sent back to."""
        parts = urlsplit(url)
        assert f"https://{parts.netloc}{parts.path}" == f"{ISSUER}/auth", url
        asked = {key: values[0] for key, values in parse_qs(parts.query).items()}
        assert asked["response_type"] == "code" and asked["code_challenge_method"] == "S256" and "openid" in asked["scope"].split()
        code = secrets.token_urlsafe(24)
        with self._lock:
            self.codes[code] = Code(self.people[login], asked["client_id"], asked["redirect_uri"], asked["code_challenge"], asked["code_challenge_method"], asked["nonce"])
        back = urlsplit(asked["redirect_uri"])
        query = {"code": code, "state": state if state is not None else asked["state"], **({"iss": ISSUER} if self.says_iss else {})}
        return f"{back.path}?{urlencode(query)}"

    def code_for(self, login: str, challenge: str, nonce: str, redirect: str) -> str:
        """A code issued at the provider for a sign-in somebody else began (another challenge, another nonce)."""
        code = secrets.token_urlsafe(24)
        with self._lock:
            self.codes[code] = Code(self.people[login], CLIENT, redirect, challenge, "S256", nonce)
        return code

    # --- the token endpoint, and userinfo --------------------------------------------------------------------------

    def token(self, authorization: str, body: bytes) -> tuple[int, bytes]:
        if self.before_token is not None:
            self.before_token()
        if self.answers:
            return self.answers.pop(0)
        form = dict(parse_qsl(body.decode("ascii")))
        client, secret = form.get("client_id", ""), form.get("client_secret")
        if authorization.startswith("Basic "):
            client, _, secret = base64.b64decode(authorization[6:]).decode().partition(":")
        if client != CLIENT or secret != SECRET:
            return 401, b'{"error":"invalid_client"}'
        with self._lock:
            code = self.codes.get(form.get("code", ""))
            if code is None or code.used or time.time() - code.made > 60 or code.client != CLIENT or code.redirect != form.get("redirect_uri"):
                return 400, b'{"error":"invalid_grant"}'
            code.used = True
        verifier = form.get("code_verifier", "")
        if b64(hashlib.sha256(verifier.encode()).digest()) != code.challenge:
            return 400, b'{"error":"invalid_grant","error_description":"PKCE verification failed"}'
        access = secrets.token_urlsafe(24)
        self.access[access] = code.person
        return 200, json.dumps({"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": self.id_token(code.person, code.nonce)}).encode()

    def claims_of(self, person: Person, nonce: str) -> dict[str, Any]:
        now = int(time.time())
        claims: dict[str, Any] = {"iss": ISSUER, "sub": person.sub, "aud": CLIENT, "exp": now + 300, "iat": now, "nonce": nonce, "auth_time": now}
        if person.email:
            claims.update(email=person.email, email_verified=person.email_verified)
        if person.name:
            claims["name"] = person.name
        if self.groups_in_token:
            claims["groups"] = list(person.groups)
        claims.update(person.more)
        return claims

    def id_token(self, person: Person, nonce: str) -> str:
        key = self.signing
        header: dict[str, Any] = {"alg": key.alg, "typ": "JWT", "kid": key.kid}
        claims = self.claims_of(person, nonce)
        if self.tamper is not None:
            self.tamper(header, claims)
        return token_of(header, claims, self.signed_as or key.sign)

    def userinfo(self, authorization: str) -> tuple[int, bytes]:
        person = self.access.get(authorization.removeprefix("Bearer ")) if authorization.startswith("Bearer ") else None
        if person is None:
            return 401, b'{"error":"invalid_token"}'
        said: dict[str, Any] = {"sub": person.sub, "groups": list(person.groups), **({"email": person.email, "email_verified": person.email_verified} if person.email else {})}
        said.update(self.userinfo_extra)
        return 200, json.dumps(said).encode()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def hs256_with(secret: bytes) -> Callable[[bytes], bytes]:
    """Signs as HS256 with `secret` (the provider's public key, as an attacker would use it)."""
    return lambda data: hmac.new(secret, data, hashlib.sha256).digest()
