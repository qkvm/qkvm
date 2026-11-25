"""A stand-in mail server for the alert tests (egress.send_mail), on loopback, written on socketserver (the standard
library's smtpd is gone, and aiosmtpd would be a dependency).

It speaks enough SMTP for a client that sends one message: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, NOOP, RSET,
QUIT. It is told how to behave (`Behaviour`): implicit TLS (port 465's way) or STARTTLS offered, a login taken or
refused with a 535 of a real server's words, an answer of endless lines, nothing at all, or plain text pushed in right
after its answer to STARTTLS (what an attacker on the line does); some recipients refused, and the line hung up or
nothing more said once it took a message. It keeps what it was sent: each message, each login and whether the line was
encrypted when it came, and the name TLS asked for (SNI).
"""

from __future__ import annotations

import base64
import datetime
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qkvm import egress
from tests.test_wall import an_authority, usage

NAMES = ("smtp.example.com", "mail.example.org")  # what its certificate is for
REFUSED = b"535-5.7.8 Username and Password not accepted. For more information, go to\r\n535 5.7.8  https://support.example.com/mail/?p=BadCredentials x1-20020a"


@dataclass
class Behaviour:
    implicit_tls: bool = False  # TLS from the first byte (465); otherwise plain, with STARTTLS offered where `starttls`
    starttls: bool = True
    login_ok: bool = True
    endless: bool = False  # its greeting is an answer that never ends
    silent: bool = False  # it never says anything
    inject: bool = False  # it pushes a line in right after its 220 to STARTTLS, in the clear
    refuse_rcpt: bytes = b""  # an answer to RCPT TO in place of 250
    refuse_rcpt_for: dict[str, bytes] = field(default_factory=dict)  # ...to RCPT TO of these addresses alone
    hang_up_after_data: bool = False  # it closes the line right after its 250 to the message's end
    quiet_after_data: bool = False  # ...or answers nothing more after it, until the other end closes the line
    delay: float = 0.0  # seconds it takes before it greets (a busy server)
    refusal: bytes = REFUSED  # what it says to a login it refuses
    echo_auth: bool = False  # ...with what the AUTH command carried put after it (a server that says back what it got)


@dataclass
class Sent:
    sender: str
    to: list[str]
    data: bytes


@dataclass
class Seen:
    messages: list[Sent] = field(default_factory=list)
    logins: list[tuple[str, str, bool]] = field(default_factory=list)  # (user, password, encrypted when it came)
    sni: list[str | None] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


class FakeSmtp:
    def __init__(self, folder: Path, behaviour: Behaviour | None = None) -> None:
        self.behaviour = behaviour or Behaviour()
        self.seen = Seen()
        self.authority = an_authority()
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(*self._certificate(folder))
        fake = self

        def asked(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
            fake.seen.sni.append(name)

        self.tls.sni_callback = asked  # type: ignore[assignment]

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                fake._talk(self.request)

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
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
        cert_path, key_path = folder / "smtp-cert.pem", folder / "smtp-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    def trusting(self) -> ssl.SSLContext:
        return ssl.create_default_context(cadata=self.authority[1].public_bytes(serialization.Encoding.PEM).decode())

    def put_in_place(self, monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...] = (*NAMES, "other.example.net")) -> None:
        """The wall's mail for these names comes here (on loopback, which the rules never let through), checked against
        this stand-in's authority alone."""
        context = self.trusting()
        real = egress.vetted

        async def vetted(host: str, port: int, *, private_ok: bool, own: frozenset[str], own_ports: frozenset[int] = frozenset()) -> tuple[list[str], int]:
            if host in names:
                return ["127.0.0.1"], self.port
            return await real(host, port, private_ok=private_ok, own=own, own_ports=own_ports)

        async def trusted() -> ssl.SSLContext:
            return context

        monkeypatch.setattr(egress, "vetted", vetted)
        monkeypatch.setattr(egress, "public_context", trusted)

    # --- the conversation -------------------------------------------------------------------------------------------

    def _talk(self, sock: socket.socket) -> None:
        how = self.behaviour
        line = _Lines(sock)
        encrypted = False
        try:
            if how.silent:
                time.sleep(30)
                return
            if how.delay:
                time.sleep(how.delay)
            if how.implicit_tls:
                line.sock = self.tls.wrap_socket(sock, server_side=True)
                encrypted = True
            if how.endless:
                while True:
                    line.say(b"220-" + b"x" * 200)
            line.say(b"220 smtp.example.com ESMTP stand-in")
            sender, to, data = "", [], b""
            while True:
                said = line.read()
                if said is None:
                    return
                command = said.decode("utf-8", "replace")
                verb = command.split(" ", 1)[0].upper()
                self.seen.commands.append(verb)
                if verb in ("EHLO", "HELO"):
                    offers = [b"250-smtp.example.com", b"250-AUTH PLAIN"]
                    if how.starttls and not encrypted:
                        offers.append(b"250-STARTTLS")
                    line.say(b"\r\n".join(offers + [b"250 8BITMIME"]))
                elif verb == "STARTTLS" and how.starttls and not encrypted:
                    line.say(b"220 2.0.0 Ready to start TLS" + (b"\r\n250 injected" if how.inject else b""))
                    line.sock = self.tls.wrap_socket(line.sock, server_side=True)
                    line.left = b""
                    encrypted = True
                elif verb == "AUTH":
                    parts = command.split(" ")
                    pair = base64.b64decode(parts[2]).split(b"\0") if len(parts) > 2 else [b"", b"", b""]
                    self.seen.logins.append((pair[1].decode(), pair[2].decode(), encrypted))
                    refused = how.refusal + (b" " + parts[2].encode() if how.echo_auth and len(parts) > 2 else b"")
                    line.say(b"235 2.7.0 Accepted" if how.login_ok else refused)
                elif verb == "MAIL":
                    sender = command.split(":", 1)[1].strip().strip("<>").split(">")[0]
                    line.say(b"250 2.1.0 OK")
                elif verb == "RCPT":
                    address = command.split(":", 1)[1].strip().strip("<>")
                    if refusal := how.refuse_rcpt or how.refuse_rcpt_for.get(address, b""):
                        line.say(refusal)
                        continue
                    to.append(address)
                    line.say(b"250 2.1.5 OK")
                elif verb == "DATA":
                    line.say(b"354 Go ahead")
                    data = line.until_dot()
                    self.seen.messages.append(Sent(sender, to, data))
                    line.say(b"250 2.0.0 OK queued as 12345")
                    if how.hang_up_after_data:
                        line.sock.shutdown(socket.SHUT_RDWR)
                        line.sock.close()
                        return
                    if how.quiet_after_data:
                        while (more := line.read()) is not None:
                            self.seen.commands.append(more.decode("utf-8", "replace").split(" ", 1)[0].upper())
                        return
                elif verb in ("NOOP", "RSET"):
                    line.say(b"250 2.0.0 OK")
                elif verb == "QUIT":
                    line.say(b"221 2.0.0 Bye")
                    return
                else:
                    line.say(b"502 5.5.2 Not implemented")
        except (OSError, ssl.SSLError, ValueError):
            return

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _Lines:
    def __init__(self, sock: Any) -> None:
        self.sock = sock
        self.left = b""

    def say(self, text: bytes) -> None:
        self.sock.sendall(text + b"\r\n")

    def read(self) -> bytes | None:
        while b"\r\n" not in self.left:
            piece = self.sock.recv(4096)
            if not piece:
                return None
            self.left += piece
        said, _, self.left = self.left.partition(b"\r\n")
        return said

    def until_dot(self) -> bytes:
        got = b""
        while True:
            said = self.read()
            if said is None or said == b".":
                return got
            got += (said[1:] if said.startswith(b"..") else said) + b"\r\n"
