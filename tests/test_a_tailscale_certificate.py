"""A wall reached at https://<name>.<tailnet>.ts.net serves Tailscale's certificate for that name (--tls-tailscale), and its own
for everything else; Tailscale's is checked before it is served, kept privately, renewed before it ends, and said at start.

Tailscale is stood in for twice: its command (this Python, run in a folder that holds a script called "status" and one
called "cert", as in test_what_the_tailscale_command_prints_as_it_arrives.py), and its local API on a Unix socket
(fake_tailscaled.py; on Linux only). The certificates are made here, by an authority the test trusts. Nothing is asked of
any tailnet, and Funnel never.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fastapi.testclient import TestClient

from qkvm import cli, tailcert, tailnet, update, vault
from qkvm.core import Core
from qkvm.server import create_app
from qkvm.tlscert import ensure_certificate
from tests.test_wall import an_authority, port_to_listen_on, usage, wall

NAME = "wall.tail0test.ts.net"
AUTHORITY = an_authority()
unix_only = pytest.mark.skipif(sys.platform == "win32", reason="Tailscale's local API is a Unix socket here; on Windows a named pipe, not asked (its command is)")
# What the command stand-in runs: it notes what it was asked, and writes what it was given for that, byte for byte.
ANSWERS = "import sys\nopen(sys.argv[0] + '.asked', 'a').write(' '.join(sys.argv[1:]) + '\\n')\nsys.stdout.buffer.write(open(sys.argv[0] + '.out', 'rb').read())\n"


def pair(name: str = NAME, days: float = 90, began: float = -1, key: ec.EllipticCurvePrivateKey | None = None, cert_key: Any = None, order: str = "key first") -> bytes:
    """A key and its certificate for `name`, as Tailscale hands them out: the key, then the certificate and its issuer's."""
    signer, signer_cert = AUTHORITY
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(signer_cert.subject)
        .public_key((cert_key or key).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=began))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        .add_extension(usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(signer, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    chain = cert.public_bytes(serialization.Encoding.PEM) + signer_cert.public_bytes(serialization.Encoding.PEM)
    return key_pem + chain if order == "key first" else chain + key_pem


def leaf_of(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificates(pem)[0]


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(tailnet, "netbird_command", lambda: None)
    monkeypatch.setattr(tailnet, "SOCKETS", ())
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: None)


@pytest.fixture
def command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str, bytes], Path]:
    """`command("status", b"...")`, `command("cert", b"...")`: what Tailscale's command answers to each; what it was asked
    is noted beside it (`<name>.asked`). (In the folder the certificate is kept in: the command is run there.)"""
    work = tmp_path / "data" / "tls"
    work.mkdir(parents=True)
    monkeypatch.chdir(work)
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: sys.executable)

    def said(asked: str, answer: bytes) -> Path:
        (work / asked).write_text(ANSWERS, encoding="ascii")
        (work / (asked + ".out")).write_bytes(answer)
        return work / (asked + ".asked")

    return said


def status(*names: Any) -> bytes:
    return json.dumps({"Self": {"HostName": "wall", "DNSName": NAME + "."}, "CertDomains": list(names)}).encode()


def held(tmp_path: Path) -> tailcert.TailscaleCert:
    return tailcert.TailscaleCert(tmp_path / "data" / "tls")


def renew(holder: tailcert.TailscaleCert) -> bool:
    return asyncio.run(holder.renew())


# --- what is taken -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("order", ["key first", "certificates first"])
def test_a_key_and_its_certificate_for_the_name_are_taken(order: str) -> None:
    taken = tailcert.check(pair(order=order), NAME)
    assert taken.name == NAME and taken.ends > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=89)
    # Kept as the web server reads it: the certificate and its chain first, then the key.
    assert taken.pem.index(b"BEGIN CERTIFICATE") < taken.pem.index(b"PRIVATE KEY")
    assert taken.fingerprint.replace(":", "") == leaf_of(taken.pem).fingerprint(hashes.SHA256()).hex().upper()


@pytest.mark.parametrize(
    ("made", "why"),
    [
        (lambda: pair(name="other.tail0test.ts.net"), "it is not for wall.tail0test.ts.net"),
        (lambda: pair(days=-1, began=-91), "it ended on"),
        (lambda: pair(began=2), "it begins only on"),
        (lambda: pair(cert_key=ec.generate_private_key(ec.SECP256R1())), "the key is not the certificate's"),
        (lambda: pair().split(b"-----BEGIN CERTIFICATE")[0], "no certificate in it"),
        (lambda: pair()[pair().index(b"-----BEGIN CERTIFICATE") :], "no key in it, or more than one"),
        (lambda: pair() + pair().split(b"-----BEGIN CERTIFICATE")[0], "no key in it, or more than one"),
        (lambda: b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n" + pair().split(b"-----BEGIN CERTIFICATE")[0], "it cannot be read"),
        (lambda: b"", "no certificate in it"),
        (lambda: b"\xff\xfe garbage", "no certificate in it"),
    ],
    ids=["another name", "ended", "not yet begun", "another key", "no certificate", "no key", "two keys", "not readable", "nothing", "no text"],
)
def test_what_is_not_a_key_and_its_certificate_for_the_name_now_is_refused(made: Callable[[], bytes], why: str) -> None:
    with pytest.raises(tailcert.Refused) as said:
        tailcert.check(made(), NAME)
    assert why in str(said.value)


@pytest.mark.parametrize(
    ("said", "name"),
    [
        ([NAME], NAME), ([NAME.upper() + "."], NAME), (["example.com", NAME], NAME),
        ([], None), (["wall.example.com"], None), (["../../etc.ts.net"], None), (["-wall.tail0test.ts.net"], None),
        (["wall..ts.net"], None), ([7, None], None), ("wall.tail0test.ts.net", None), (["a" * 64 + ".ts.net"], None),
    ],
    ids=["its name", "written larger, with a dot", "the first under ts.net", "none", "not ts.net", "a path", "a hyphen first", "an empty part", "no names", "not a list", "a part too long"],
)  # fmt: skip
def test_the_name_is_the_one_tailscale_says_and_one_of_ts_net(said: Any, name: str | None) -> None:
    assert tailcert.name_of({"CertDomains": said}) == name


# --- asked of Tailscale's command ------------------------------------------------------------------------------------


def test_the_certificate_is_asked_of_the_command_kept_privately_and_served(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    asked = command("cert", pair())
    holder = held(tmp_path)
    assert renew(holder) is True and holder.held is not None and holder.held.name == NAME and holder.said is None
    # Written to standard output only (never a file of Tailscale's making), for the name, and nothing else was asked.
    assert asked.read_text().split() == ["--cert-file", "-", "--key-file", "-", NAME]  # (to the script called "cert")
    kept = tmp_path / "data" / "tls" / "tailscale.pem"
    assert kept.read_bytes() == holder.held.pem
    if sys.platform != "win32":
        assert kept.stat().st_mode & 0o077 == 0
    # The same again: nothing new.
    assert renew(holder) is False
    # A new one (renewed by Tailscale): taken.
    command("cert", pair())
    before = holder.held.fingerprint
    assert renew(holder) is True and holder.held.fingerprint != before


def test_without_https_certificates_in_the_tailnet_none_is_asked_for_and_it_is_said(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status())
    asked = command("cert", pair())
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert holder.said is not None and "HTTPS certificates" in holder.said and "admin console" in holder.said
    assert not asked.exists()


def test_a_refusal_of_the_command_is_said_in_its_own_words(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    (Path.cwd() / "cert").write_text("import sys\nsys.stderr.write('Access denied: cert access denied\\n')\nsys.exit(1)\n", encoding="ascii")
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert holder.said is not None and "cert access denied" in holder.said


def test_without_tailscale_it_is_said_and_nothing_is_served(tmp_path: Path) -> None:
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert holder.said is not None and "Tailscale" in holder.said


def test_something_that_is_not_a_certificate_is_not_kept(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    command("cert", pair(name="other.tail0test.ts.net"))
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None and "not for wall.tail0test.ts.net" in (holder.said or "")
    assert not (tmp_path / "data" / "tls" / "tailscale.pem").exists()


def test_too_much_from_the_command_is_not_taken(tmp_path: Path, command: Callable[[str, bytes], Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailcert, "PAIR_MOST", 2048)
    command("status", status(NAME))
    command("cert", pair() + b"\n" * 4096)
    holder = held(tmp_path)
    assert renew(holder) is False and "more than" in (holder.said or "")


# --- asked of Tailscale's local API --------------------------------------------------------------------------------


@pytest.fixture
def tailscaled(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    from tests.fake_tailscaled import FakeTailscaled

    fake = FakeTailscaled().start()
    monkeypatch.setattr(tailnet, "SOCKETS", (str(fake.path),))
    yield fake
    fake.stop()


@unix_only
def test_the_certificate_is_asked_of_the_local_api_where_there_is_no_command(tmp_path: Path, tailscaled: Any) -> None:
    tailscaled.answers["/localapi/v0/status"] = (200, status(NAME))
    tailscaled.answers[f"/localapi/v0/cert/{NAME}"] = (200, pair())
    holder = held(tmp_path)
    assert renew(holder) is True and holder.held is not None and holder.held.name == NAME
    # Its status and the certificate for the name, as a key and its certificate together, and nothing else (no Funnel).
    assert [target for _, target, _ in tailscaled.asked] == ["/localapi/v0/status", f"/localapi/v0/cert/{NAME}?type=pair"]


@unix_only
def test_a_refusal_of_the_local_api_says_how_qkvm_may_be_let_ask(tmp_path: Path, tailscaled: Any) -> None:
    tailscaled.answers["/localapi/v0/status"] = (200, status(NAME))
    tailscaled.answers[f"/localapi/v0/cert/{NAME}"] = (403, b"cert access denied\n")
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert "403: cert access denied" in (holder.said or "") and "TS_PERMIT_CERT_UID" in (holder.said or "")


@unix_only
def test_a_length_no_number_holds_is_said_and_ends_nothing(tmp_path: Path, tailscaled: Any) -> None:
    # (A Content-Length of 5000 digits, which Python reads as no number: a renewal at a start ended in that error, and the
    # wall did not start.)
    tailscaled.raw = b"HTTP/1.0 200 OK\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n{}"
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert "sent more than this program reads" in (holder.said or "")


def test_an_error_of_the_programs_own_in_a_renewal_is_said_and_ends_nothing(tmp_path: Path, command: Callable[[str, bytes], Path], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # Whatever goes wrong in asking for it is no reason for the wall not to start, nor for its keeper to stop.
    async def broken(*given: Any) -> bytes:
        raise RuntimeError("a bug, with words of its own")

    command("status", status(NAME))
    monkeypatch.setattr(tailcert, "fetch", broken)
    holder = held(tmp_path)
    assert renew(holder) is False and holder.held is None
    assert holder.said == "Tailscale's certificate was not asked for: an error of qKVM's own (RuntimeError); qkvm.log has it"
    assert any(record.exc_info and isinstance(record.exc_info[1], RuntimeError) for record in caplog.records)


@unix_only
def test_a_local_api_that_does_not_answer_in_time_is_given_up_on(tmp_path: Path, tailscaled: Any) -> None:
    tailscaled.answers["/localapi/v0/status"] = (200, status(NAME))
    tailscaled.answers[f"/localapi/v0/cert/{NAME}"] = (200, pair())
    tailscaled.hold = 30.0
    holder = held(tmp_path)
    began = time.monotonic()
    assert asyncio.run(holder.renew(within=0.5)) is False
    assert time.monotonic() - began < 10.0 and "did not answer" in (holder.said or "")


# --- kept, and when it is asked again ---------------------------------------------------------------------------------


def test_a_kept_copy_in_its_time_is_served_from_the_start(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    command("cert", pair())
    renew(held(tmp_path))
    holder = held(tmp_path)
    holder.resume()
    assert holder.held is not None and holder.held.name == NAME


@pytest.mark.parametrize("what", ["ended", "a link", "garbage"])
def test_a_kept_copy_that_will_not_do_is_not_served(tmp_path: Path, what: str) -> None:
    folder = tmp_path / "data" / "tls"
    folder.mkdir(parents=True)
    kept = folder / "tailscale.pem"
    if what == "ended":
        kept.write_bytes(pair(days=-1, began=-91))
    elif what == "a link":
        if sys.platform == "win32":
            pytest.skip("a link needs a right of its own on Windows")
        elsewhere = tmp_path / "elsewhere.pem"
        elsewhere.write_bytes(tailcert.check(pair(), NAME).pem)
        kept.symlink_to(elsewhere)
    else:
        kept.write_bytes(b"garbage")
    holder = held(tmp_path)
    holder.resume()
    assert holder.held is None


def test_it_is_asked_again_before_it_ends_and_soon_after_a_failure(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    holder = held(tmp_path)
    # Nothing held: soon, then less and less often, an hour at the most.
    waits = []
    for _ in range(9):
        renew(holder)  # (no Tailscale: fails)
        waits.append(holder.due())
    assert waits[0] == tailcert.RETRY_FIRST and waits == sorted(waits) and waits[-1] == tailcert.RETRY_MOST
    # Held, far from its end: every six hours. Near its end: every hour.
    command("status", status(NAME))
    command("cert", pair(days=60))
    renew(holder)
    assert holder.due() == tailcert.RECHECK
    command("cert", pair(days=10))
    renew(holder)
    assert holder.due() == tailcert.RETRY_MOST


@pytest.mark.parametrize("failed", [10, 1030, 100_000, sys.maxsize])
def test_after_any_number_of_failures_it_is_asked_again_within_the_hour(tmp_path: Path, failed: int) -> None:
    # The second outside review of 0.4.0, a LOW: the wait was worked out as RETRY_FIRST times two to the failures, and cut to
    # the hour after. After 1030 failures in a row (some 43 days of hourly asks without Tailscale) that number is past what
    # a float holds, and OverflowError ended the keeper for good.
    holder = held(tmp_path)
    holder.failed = failed
    assert holder.due() == tailcert.RETRY_MOST


def test_an_error_in_working_out_when_to_ask_again_ends_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # (The same review: the keeper asked when it was due outside what it guards, so that any error there was its last ask.)
    asked: list[float] = []

    class Holder(tailcert.TailscaleCert):
        def due(self) -> float:
            if len(asked) < 2:
                asked.append(time.monotonic())
                raise OverflowError("a wait past what a float holds")
            return 0.01

        async def renew(self, within: float | None = None) -> bool:
            asked.append(time.monotonic())
            return False

    monkeypatch.setattr(tailcert, "RETRY_MOST", 0.05)  # (where the keeper waits after such an error: soon, in a test)
    data = tmp_path / "data"
    core = Core(data)
    core.tailscale_cert = Holder(data / "tls")
    core.unlock_at_start()
    with TestClient(create_app(core)):
        deadline = time.monotonic() + 10
        while len(asked) < 4:
            assert time.monotonic() < deadline, f"the keeper stopped after {len(asked)} looks"
            time.sleep(0.02)
    assert any(record.exc_info and isinstance(record.exc_info[1], OverflowError) for record in caplog.records)


# --- served -------------------------------------------------------------------------------------------------------------


async def hello(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"hello"})


def shown(port: int, name: str | None) -> x509.Certificate:
    """The certificate the server on `port` shows a browser that asks for `name` (None: by its address, as no name)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as line, context.wrap_socket(line, server_hostname=name) as tls:
        der = tls.getpeercert(binary_form=True)
    assert der is not None
    return x509.load_der_x509_certificate(der)


def test_the_name_is_served_tailscales_certificate_and_the_rest_the_walls_own_and_a_renewal_without_a_restart(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    command("cert", pair())
    core = Core(tmp_path / "data", tailscale_cert=True)
    assert core.https_forced and core.tailscale_cert is not None
    holder = core.tailscale_cert
    assert renew(holder) is True
    own_cert, own_key, _ = ensure_certificate(tmp_path / "data" / "tls", ["127.0.0.1"])
    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    port = listening.getsockname()[1]
    config = uvicorn.Config(hello, **cli.served_as(core, str(own_cert), str(own_key)), log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    serving = threading.Thread(target=lambda: server.run(sockets=[listening]), daemon=True)
    serving.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started:
            assert time.monotonic() < deadline and serving.is_alive(), "the server did not start"
            time.sleep(0.05)
        own = x509.load_pem_x509_certificate(own_cert.read_bytes())
        first = leaf_of(holder.held.pem) if holder.held else None
        assert shown(port, NAME) == first
        assert shown(port, NAME.upper()) == first  # (a name is a name, however it is written)
        assert shown(port, None) == own and shown(port, "localhost") == own and shown(port, "other.tail0test.ts.net") == own
        # A browser that trusts the authority takes it for the name, as a browser trusts Let's Encrypt's.
        trusting = ssl.create_default_context(cadata=AUTHORITY[1].public_bytes(serialization.Encoding.PEM).decode())
        with socket.create_connection(("127.0.0.1", port), timeout=10) as line, trusting.wrap_socket(line, server_hostname=NAME) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n".encode())
            answer = b""
            while piece := tls.recv(4096):
                answer += piece
            assert answer.startswith(b"HTTP/1.1 200") and answer.split(b"\r\n")[-4] == b"hello"  # (in one piece of a length)
        # Renewed while it serves: the next connection is shown the new one, and the listeners were not opened again.
        command("cert", pair())
        assert asyncio.run(holder.renew()) is True
        assert shown(port, NAME) == leaf_of(holder.held.pem) != first
        assert shown(port, None) == own
    finally:
        server.should_exit = True
        serving.join(timeout=10)


def test_without_one_held_every_name_is_served_the_walls_own(tmp_path: Path) -> None:
    core = Core(tmp_path / "data", tailscale_cert=True)
    own_cert, own_key, _ = ensure_certificate(tmp_path / "data" / "tls", ["127.0.0.1"])
    options = cli.served_as(core, str(own_cert), str(own_key))
    config = uvicorn.Config(hello, **options)
    config.load()
    assert config.ssl is not None and config.ssl.sni_callback is not None
    # (Nothing held: the callback leaves the wall's own in place.)
    assert core.tailscale_cert is not None and core.tailscale_cert.held is None


def test_without_the_option_nothing_of_it_is_there(tmp_path: Path) -> None:
    core = Core(tmp_path / "data")
    assert core.tailscale_cert is None
    assert "ssl_context_factory" not in cli.served_as(core, "c.pem", "k.pem")


# --- said -------------------------------------------------------------------------------------------------------------


def test_what_the_start_says_of_it(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    holder = held(tmp_path)
    renew(holder)
    lines = holder.lines(8787)
    assert len(lines) == 1 and lines[0].startswith("  Tailscale's certificate: none yet (") and "the wall's own is served meanwhile" in lines[0]
    command("status", status(NAME))
    command("cert", pair())
    renew(holder)
    lines = holder.lines(8787)
    assert lines[0].startswith(f"  https://{NAME}:8787/ with Tailscale's certificate for that name, until 20")
    assert holder.lines(443)[0].startswith(f"  https://{NAME}/ with")


def test_the_settings_say_which_certificate_is_served_for_the_name(tmp_path: Path, command: Callable[[str, bytes], Path]) -> None:
    command("status", status(NAME))
    command("cert", pair())
    with wall(tmp_path / "data", tailscale_cert=True) as admin:
        core: Core = admin.core  # type: ignore[attr-defined]
        assert core.tailscale_cert is not None
        renew(core.tailscale_cert)
        said = admin.get("/api/v1/settings").json()["tailscale_certificate"]
        assert said["name"] == NAME and said["until"].startswith("20") and len(said["fingerprint"]) == 95 and said["said"] is None
        assert "PRIVATE" not in json.dumps(said)


@pytest.mark.parametrize("there", [True, False], ids=["Tailscale hands it over", "the tailnet gives none"])
def test_a_start_asks_for_it_says_so_and_serves_it(tmp_path: Path, command: Callable[[str, bytes], Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], there: bool) -> None:
    command("status", status(NAME) if there else status())
    command("cert", pair())
    seen: list[uvicorn.Config] = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: seen.append(self.config))  # (it got as far as serving)
    port = port_to_listen_on()
    core = Core(tmp_path / "data", bind_override=["local"], port_override=port, tailscale_cert=True)
    core.unlock_at_start()
    capsys.readouterr()
    assert cli.serve(core) == 0
    said = capsys.readouterr().out
    assert f"https://127.0.0.1:{port}/" in said  # (HTTPS, as --tls-tailscale says: on every address, with the wall's own)
    if there:
        assert f"  https://{NAME}:{port}/ with Tailscale's certificate for that name, until 20" in said
    else:
        assert "  Tailscale's certificate: none yet (this tailnet gives no HTTPS certificates" in said
    assert len(seen) == 1 and seen[0].ssl_context_factory == core.tailscale_cert.factory  # type: ignore[union-attr]
