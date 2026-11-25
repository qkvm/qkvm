"""Tailscale's certificate for this computer's name in its tailnet, served beside the wall's own (--tls-tailscale, 0.4.0).

A browser that asks for that name (https://<name>.<tailnet>.ts.net, said by TLS's SNI) is shown Tailscale's certificate,
which browsers trust (Let's Encrypt's, which tailscaled fetches and renews); one that asks for anything else (an address,
localhost, another name) is shown the wall's own, as before (or --tls-cert's). Nothing else changes: the wall answers that
name as every name under ts.net (security.host_allowed).

The name is the one Tailscale says is this computer's (CertDomains of its status), and is held to be one: a name under
ts.net, of letters, digits and hyphens. The certificate comes from Tailscale on this computer: from its command where that
is installed (`tailscale cert --cert-file - --key-file -`: written to standard output, never to a file of its making), else
from its local API over its socket (`/localapi/v0/cert/<name>?type=pair`, tailnet.ask_local_api). What comes back is held
to be a key and its certificate for that name, in its time, before it is kept (tls/tailscale.pem in the data folder, the
account's own, as the wall's own key is) and served. A start serves the copy it kept, while it is in its time, until
Tailscale answers.

Asked again every six hours (tailscaled renews it some thirty days before it ends), every hour while the one held ends
within two weeks, and after a failure soon and then less and less often, an hour at the most. A new one is served from the
next connection on: the listeners are not opened again. Funnel (Tailscale putting the wall on the internet) is never
asked for, nor anything else of Tailscale's that changes something.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import re
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from uvicorn.config import create_ssl_context

from . import tailnet
from ._folders import not_ours
from .kvm import plain
from .netbind import NO_WINDOW
from .tlscert import NotOurs, keep_private, tls_folder

log = logging.getLogger("qkvm")

FILE = "tailscale.pem"  # in the wall's folder of certificates: the certificate, the chain that leads to it, and its key
PAIR_MOST = 64 * 1024  # bytes of a key and its certificates taken at the most
CERT_WITHIN = 90.0  # seconds Tailscale has to hand it over (where it has none, it fetches one from Let's Encrypt meanwhile)
START_WITHIN = 15.0  # ...at a start, which waits for it before it listens: what has not come by then is served when it comes
RECHECK = 6 * 3600.0  # seconds between two asks while the one held is far from its end
RETRY_FIRST = 60.0  # seconds after a failure before it is asked again; twice as long after each one more...
RETRY_MOST = 3600.0  # ...an hour at the most; and every hour while the one held ends within ENDS_SOON
DOUBLINGS_MOST = 32  # doublings of RETRY_FIRST that are counted: far past RETRY_MOST, and far within what a float holds
ENDS_SOON = datetime.timedelta(days=14)
EARLY = datetime.timedelta(minutes=5)  # a certificate that begins this little after now is taken (two machines' clocks)
_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ts\.net")
_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]{1,40})-----(.*?)-----END \1-----", re.DOTALL)


class Refused(Exception):
    """No certificate of Tailscale's was taken this time: the message says why, in a sentence for whoever runs the wall."""


@dataclass(frozen=True)
class Pair:
    """A key and its certificate, as served: the certificate and the chain that leads to it, then the key (`pem`)."""

    name: str
    pem: bytes
    ends: datetime.datetime
    fingerprint: str  # the certificate's SHA-256, as browsers show it


def name_of(status: Any) -> str | None:
    """The name Tailscale gives this computer a certificate for, of its status (CertDomains): the first that is a name under
    ts.net, written in lower case without a dot at its end. None where it gives none (HTTPS is off in the tailnet)."""
    domains = status.get("CertDomains") if isinstance(status, dict) else None
    for said in domains if isinstance(domains, list) else []:
        if isinstance(said, str):
            name = said.strip().rstrip(".").lower()
            if len(name) <= 253 and _NAME.fullmatch(name):
                return name
    return None


def _refused(why: str) -> Refused:
    return Refused(f"Tailscale's certificate was not taken: {why}")


def _names(cert: x509.Certificate) -> list[str]:
    try:
        said = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []
    return [name.lower().rstrip(".") for name in said]


def check(pem: bytes, name: str | None, now: datetime.datetime | None = None) -> Pair:
    """What Tailscale handed over, held to be one key and its certificate (with the chain after it) for `name` (None: for the
    name under ts.net it is for), in its time now. Refused, with why, where it is not."""
    blocks = [(found.group(1), found.group(0)) for found in _BLOCK.finditer(pem[: PAIR_MOST + 1])]
    certs = [block for kind, block in blocks if kind == b"CERTIFICATE"]
    keys = [block for kind, block in blocks if kind.endswith(b"PRIVATE KEY")]
    if not certs:
        raise _refused("no certificate in it")
    if len(keys) != 1:
        raise _refused("no key in it, or more than one")
    if len(certs) + len(keys) != len(blocks):
        raise _refused("something else than a key and its certificates in it")
    try:
        chain = [x509.load_pem_x509_certificate(block) for block in certs]
        key = serialization.load_pem_private_key(keys[0], None)
    except (ValueError, TypeError):
        raise _refused("it cannot be read") from None
    leaf = chain[0]
    names = _names(leaf)
    if name is None:
        name = next((each for each in names if _NAME.fullmatch(each)), None)
        if name is None:
            raise _refused("it is for no name under ts.net")
    elif name not in names:
        raise _refused(f"it is not for {name}")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if leaf.not_valid_after_utc <= now:
        raise _refused(f"it ended on {leaf.not_valid_after_utc:%Y-%m-%d}")
    if leaf.not_valid_before_utc > now + EARLY:
        raise _refused(f"it begins only on {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} UTC")
    spelt = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spelt) != leaf.public_key().public_bytes(*spelt):
        raise _refused("the key is not the certificate's")
    digest = leaf.fingerprint(hashes.SHA256()).hex().upper()
    served = b"".join(block + b"\n" for block in (*certs, keys[0]))
    return Pair(name, served, leaf.not_valid_after_utc, ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)))


async def this_name() -> str:
    """The name Tailscale gives this computer a certificate for. Refused, with why, where it gives none or cannot be asked."""
    try:
        status = await tailnet.tailscale_status()
    except tailnet.Unasked as ex:
        raise Refused(str(ex)) from None
    if status is None:
        raise Refused("Tailscale is not on this computer, or did not say what it calls it (neither its command nor its local API answered)")
    name = name_of(status)
    if name is None:
        raise Refused("this tailnet gives no HTTPS certificates: switch HTTPS certificates on in Tailscale's admin console (DNS), and qKVM asks again")
    return name


def _by_command(command: str, name: str, folder: Path, within: float) -> bytes:
    """The key and its certificates as Tailscale's command writes them to standard output. (Run in the folder they are kept
    in, the account's own: a command that took "-" for a file's name would write there, and nowhere else.)"""
    try:
        done = subprocess.run(
            [command, "cert", "--cert-file", "-", "--key-file", "-", name], capture_output=True, timeout=within, cwd=folder, check=False, creationflags=NO_WINDOW
        )
    except subprocess.TimeoutExpired:
        raise Refused(f"Tailscale's command did not hand it over within {within:g} seconds") from None
    except OSError as ex:
        raise Refused(f"Tailscale's command could not be run ({ex.strerror or type(ex).__name__})") from None
    if done.returncode != 0:
        told = plain(done.stderr[:400].decode("utf-8", "replace"), 160) or "it said nothing more"
        raise Refused(f"Tailscale's command did not hand it over ({told})")
    if len(done.stdout) > PAIR_MOST:
        raise Refused(f"Tailscale's command sent more than this program reads of a certificate ({PAIR_MOST // 1024} KB)")
    return bytes(done.stdout)


async def fetch(name: str, folder: Path, within: float) -> bytes:
    """The key and its certificates for `name`, from Tailscale on this computer. Refused, with why, where it gives none."""
    command = tailnet.tailscale_command()
    if command is not None:
        return await asyncio.to_thread(_by_command, command, name, folder, within)
    where = tailnet.local_api_socket()
    if where is None:
        raise Refused("neither Tailscale's command nor its local API is on this computer")
    try:
        status, body = await tailnet.ask_local_api(where, f"/localapi/v0/cert/{name}?type=pair", PAIR_MOST, within)
    except tailnet.Unasked as ex:
        raise Refused(str(ex)) from None
    if status != 200:
        told = plain(body[:400].decode("utf-8", "replace"), 120) or "nothing more"
        raise Refused(
            f"Tailscale's local API did not hand it over ({status}: {told}). Where qKVM does not run as root, tailscaled lets it "
            "ask with TS_PERMIT_CERT_UID set to qKVM's account in tailscaled's environment"
        )
    return body


class TailscaleCert:
    """Tailscale's certificate for this computer's name, as the wall holds and serves it (see the module's description)."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder  # the wall's folder of certificates (tls in the data folder)
        self.file = folder / FILE
        self.held: Pair | None = None
        self.said: str | None = None  # why the last ask brought none; None after one that did
        self.failed = 0  # asks in a row that brought none
        self._context: ssl.SSLContext | None = None
        self._build: Callable[[Path], ssl.SSLContext] | None = None  # (the listeners' own way of making one: see factory)

    def resume(self) -> None:
        """Serve the copy kept at the last ask, where it is the account's own and still in its time."""
        try:
            if not_ours(self.file) is not None:
                return
            pair = check(self.file.read_bytes()[: PAIR_MOST + 1], None)
        except (OSError, Refused):
            return
        self.held = pair
        try:
            self._context = self._made()
        except (OSError, ssl.SSLError):
            self.held, self._context = None, None

    async def renew(self, within: float = CERT_WITHIN) -> bool:
        """Ask Tailscale for it; True where another one than the one held is served from now on."""
        try:
            async with asyncio.timeout(within):
                name = await this_name()
                await asyncio.to_thread(tls_folder, self.folder)
                pem = await fetch(name, self.folder, within)
            got = check(pem, name)
            if self.held is not None and got.pem == self.held.pem:
                self._fine()
                return False
            await asyncio.to_thread(keep_private, self.file, got.pem)
            held, self.held = self.held, got
            try:
                self._context = self._made()
            except BaseException:
                self.held = held
                raise
        except TimeoutError:
            self._failing(f"Tailscale did not answer within {within:g} seconds")
            return False
        except (Refused, NotOurs) as ex:
            self._failing(str(ex))
            return False
        except (OSError, ssl.SSLError) as ex:
            self._failing(f"Tailscale's certificate could not be kept or loaded ({getattr(ex, 'strerror', None) or ex})")
            return False
        except Exception as ex:
            # An error of the program's own is no reason for the wall not to start (a renewal is made before it listens), nor
            # for its keeper to stop: said by its kind (its words may hold what Tailscale sent), the whole of it in the log.
            log.error("Tailscale's certificate could not be asked for", exc_info=ex)
            self._failing(f"Tailscale's certificate was not asked for: an error of qKVM's own ({type(ex).__name__}); qkvm.log has it")
            return False
        self._fine()
        log.info("Tailscale's certificate for %s is served, until %s (SHA-256 %s)", got.name, f"{got.ends:%Y-%m-%d}", got.fingerprint)
        return True

    def _fine(self) -> None:
        self.said, self.failed = None, 0

    def _failing(self, why: str) -> None:
        if why != self.said:
            log.warning("%s", why)  # (once for each new reason: an hourly line saying the same is no news)
        self.said, self.failed = why, self.failed + 1

    def due(self) -> float:
        """Seconds until it is asked again."""
        if self.failed or self.held is None:
            # (Twice as long after each failure, the doubling counted only so far as it can matter: worked out first and cut
            # after, 1030 failures in a row, some 43 days without Tailscale, were a number past what a float holds, and the
            # OverflowError ended the asking. The second outside review of 0.4.0.)
            doublings = min(max(self.failed - 1, 0), DOUBLINGS_MOST)
            return min(RETRY_FIRST * 2.0**doublings, RETRY_MOST)
        if self.held.ends - datetime.datetime.now(datetime.timezone.utc) < ENDS_SOON:
            return RETRY_MOST
        return RECHECK

    def _made(self) -> ssl.SSLContext | None:
        return self._build(self.file) if self._build is not None and self.held is not None else None

    def factory(self, config: Any, default: Callable[[], ssl.SSLContext]) -> ssl.SSLContext:
        """The listeners' TLS (uvicorn's ssl_context_factory): the wall's own certificate, and Tailscale's for its name."""
        main = default()
        alpn = getattr(config.http_protocol_class, "alpn_protocols", None)

        def build(pem: Path) -> ssl.SSLContext:
            # Made as the web server makes its own, with the same settings: only the certificate is another.
            return create_ssl_context(
                certfile=pem, keyfile=pem, password=None, ssl_version=config.ssl_version, cert_reqs=config.ssl_cert_reqs,
                ca_certs=config.ssl_ca_certs, ciphers=config.ssl_ciphers, alpn_protocols=alpn,
            )  # fmt: skip

        self._build = build
        try:
            self._context = self._made()
        except (OSError, ssl.SSLError) as ex:
            self._context = None
            log.warning("Tailscale's certificate could not be loaded (%s): the wall's own is served for its name meanwhile", getattr(ex, "strerror", None) or ex)
        main.sni_callback = self._choose
        return main

    def _choose(self, line: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
        """(TLS's SNI, as a browser opens a connection.) Tailscale's certificate for its name; the wall's own for any other."""
        held, context = self.held, self._context
        if held is not None and context is not None and name is not None and name.lower().rstrip(".") == held.name:
            line.context = context

    def lines(self, port: int) -> list[str]:
        """What a start says of it, under the addresses it listens on."""
        held = self.held
        if held is None:
            return [f"  Tailscale's certificate: none yet ({self.said or 'not asked yet'}); asked again shortly, the wall's own is served meanwhile"]
        where = held.name if port == 443 else f"{held.name}:{port}"
        return [f"  https://{where}/ with Tailscale's certificate for that name, until {held.ends:%Y-%m-%d}"]

    def view(self) -> dict[str, Any]:
        """What the settings show of it: the name and until when it is served for, its fingerprint; why none, where none."""
        held = self.held
        return {
            "name": held.name if held else None, "until": held.ends.isoformat() if held else None,
            "fingerprint": held.fingerprint if held else None, "said": self.said,
        }  # fmt: skip
