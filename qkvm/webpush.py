"""Alerts to phones and other browsers by Web Push: one more way the alerts are told (alerts.py), beside the webhook.

The wall has a key of its own (VAPID, RFC 8292), made once and kept sealed in the vault. A browser subscribes on the
page: its push service (Apple's, Google's, Mozilla's or Microsoft's, whichever its maker runs) gives it an address,
and it gives the wall that address and two keys of its own. Each alert is then encrypted for that browser alone
(RFC 8291, aes128gcm) and posted to that address, signed with the wall's key: the push service carries it and cannot
read it. What an alert carries is the least that says it (`payload`): never a password, a token, a machine's address,
the wall's address or a picture.

Sending is bounded. Each browser's alerts go one after the other, in the order they happened, by a task of its own,
so a slow push service holds up only the browsers that use it, never the alert round or the webhook (AT_ONCE sends
at a time from the whole wall, each within SEND_TIMEOUT, again after RETRY_AFTER where the service was away or busy,
MOST_WAITING waiting for one browser). A push service that says a browser is no longer subscribed (404, 410) has it
taken off the wall's list. And the address is the push service's alone: taken only from the subscription, it has to
be https to a name on port 443 (`check_endpoint`), and every address that name leads to has to be one of the
internet's (`vetted`), connected to as it was vetted: no request goes into the wall's own network this way.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .kvm import public_context
from .security import PRIVATE_SUFFIXES

log = logging.getLogger("qkvm")

RECORD = 4096  # bytes of the one record a message is (RFC 8291's rs); a push service takes 4096 of a body at least (RFC 8030)
MOST_SAID = 3000  # bytes of what one alert says, before it is encrypted: within one record with its padding and tag
PAD_TO = 256  # what an alert says is padded to a multiple of this: the push service is not told how long a machine's name is
TTL = 24 * 3600  # seconds a push service keeps an alert for a browser that is away (a phone that is switched off)
# Who the wall says it is to a push service (RFC 8292's "sub", which Apple's requires): the software's own site, which
# names nothing of the wall (its address would tell every push service where the wall is). A URL or a mailto: on a name
# of the internet: Apple's answers 403 BadJwtToken to one on localhost, so no alert would reach an iPhone or Safari.
CONTACT = "https://qkvm.com"
SIGNED_FOR = 12 * 3600  # seconds the wall's signature on its requests is good for (RFC 8292: 24 hours at the most)
SEND_TIMEOUT = 15.0  # seconds one attempt may take, start to finish: the name looked up, the request sent, its status read
RESOLVE_TIMEOUT = 5.0  # ...of which the name may take this many
RETRY_AFTER = (5.0, 30.0, 120.0)  # seconds before an alert that did not arrive is tried again, and again
LONGEST_WAIT = 600.0  # the longest a push service's own Retry-After is waited for
AT_ONCE = 8  # sends under way at once, to all push services together
MOST_WAITING = 20  # alerts waiting for one browser; when its push service is away for long, the oldest give way
MOST_READ = 512  # bytes read of a push service's answer to a refusal, for the reason it may give (Apple's does)
LONGEST_ENDPOINT = 2048  # characters of a push service's address (Microsoft's are the longest, at some hundreds)

_B64 = re.compile(r"[A-Za-z0-9_-]*={0,2}")
_REASON = re.compile(rb'"reason"\s*:\s*"([A-Za-z]{1,40})"')
_TOP = re.compile(r"[a-z][a-z0-9-]*")  # the last part of a name on the internet: letters (or xn--), never a number
# The well-known NAT64 prefix (RFC 6052), whose IPv4 is its last 32 bits. The local-use one (64:ff9b:1::/48, RFC 8215)
# is refused outright: where its IPv4 sits is its translator's to choose (/48 to /96), and read as /96 a private one
# passed for public (the outside review of 0.3.0, Codex's M5).
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"),)
_LOCAL_NAT64 = ipaddress.ip_network("64:ff9b:1::/48")


def b64(data: bytes) -> str:
    """base64url without its padding, as Web Push writes keys."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: Any) -> bytes:
    """What base64url (with or without its padding) holds. ValueError for anything else."""
    if not isinstance(text, str) or not _B64.fullmatch(text):
        raise ValueError("not base64url")
    text = text.rstrip("=")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _point(key: ec.EllipticCurvePrivateKey) -> bytes:
    """The public half of a P-256 key, as Web Push sends it: the uncompressed point, 65 bytes."""
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _browsers(point: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


# --- the wall's own key (RFC 8292) ------------------------------------------------------------------------------------


def new_key() -> str:
    """A new key for the wall, as the text that is sealed in the vault: the private number of a P-256 key, base64url."""
    key = ec.generate_private_key(ec.SECP256R1())
    return b64(key.private_numbers().private_value.to_bytes(32, "big"))


class WallKey:
    """The wall's key for Web Push: its public half is what each browser subscribes with (the page's
    applicationServerKey), and the private half signs every request to a push service, which tells by it that the
    request comes from whom the browser subscribed to."""

    def __init__(self, text: str) -> None:
        raw = unb64(text)
        if len(raw) != 32:
            raise ValueError("not a key of the wall's")
        self._key = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())  # (ValueError for 0, or past the curve's order)
        self.public = _point(self._key)
        self.public_text = b64(self.public)
        self._signed: dict[tuple[str, str], tuple[str, int]] = {}  # (audience, subject) -> (token, when it runs out)

    def token(self, audience: str, subject: str, expires: int) -> str:
        """A JSON Web Token (ES256) that says the request is the wall's, for this push service, until `expires`."""
        head = b64(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        claims = b64(json.dumps({"aud": audience, "exp": expires, "sub": subject}, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self._key.sign(f"{head}.{claims}".encode("ascii"), ec.ECDSA(hashes.SHA256())))
        return f"{head}.{claims}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def authorization(self, audience: str, subject: str, now: float | None = None) -> str:
        """The Authorization header of a request to the push service at `audience` (its origin). A token is made for an
        hour or more of use and then again: one signature for every alert of a busy hour, not one each."""
        now = time.time() if now is None else now
        kept = self._signed.get((audience, subject))
        if kept is None or not 3600 < kept[1] - now <= SIGNED_FOR:  # (and anew where the clock was put back meanwhile)
            if len(self._signed) >= 64:
                self._signed.clear()
            expires = int(now) + SIGNED_FOR
            kept = (self.token(audience, subject, expires), expires)
            self._signed[(audience, subject)] = kept
        return f"vapid t={kept[0]}, k={self.public_text}"


# --- the message (RFC 8291, with RFC 8188's aes128gcm) --------------------------------------------------------------


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _keys(shared: bytes, auth: bytes, ua_public: bytes, as_public: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """The content key and the nonce of a message (RFC 8291 section 3.4, RFC 8188 section 2.2): HKDF-SHA-256, written out."""
    prk_key = _hmac(auth, shared)
    ikm = _hmac(prk_key, b"WebPush: info\x00" + ua_public + as_public + b"\x01")
    prk = _hmac(salt, ikm)
    return _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16], _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]


def encrypt(said: bytes, ua_public: bytes, auth: bytes, *, salt: bytes | None = None, own: ec.EllipticCurvePrivateKey | None = None, pad_to: int = PAD_TO) -> bytes:
    """`said`, as it is sent to the browser whose keys these are: one record of aes128gcm under a key made for this message
    alone. `salt` and `own` (that key) are new for every message; a test gives the RFC's example's, with `pad_to` 1."""
    if len(said) > MOST_SAID:
        raise ValueError("more than one alert says")
    browser = _browsers(ua_public)
    own = own if own is not None else ec.generate_private_key(ec.SECP256R1())
    salt = salt if salt is not None else os.urandom(16)
    as_public = _point(own)
    cek, nonce = _keys(own.exchange(ec.ECDH(), browser), auth, ua_public, as_public, salt)
    padding = -(len(said) + 1) % pad_to
    sealed = AESGCM(cek).encrypt(nonce, said + b"\x02" + bytes(padding), None)  # (0x02: the last record, and the only one)
    return salt + RECORD.to_bytes(4, "big") + bytes([len(as_public)]) + as_public + sealed


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth: bytes) -> bytes:
    """What a browser reads of a message `encrypt` made: for the tests, and a stand-in browser. ValueError where it does not open."""
    if len(body) < 21:
        raise ValueError("too short to be a message")
    salt, size, length = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public, sealed = body[21 : 21 + length], body[21 + length :]
    if length != 65 or not 17 <= len(sealed) <= size:
        raise ValueError("not one record of a message")
    cek, nonce = _keys(ua_private.exchange(ec.ECDH(), _browsers(as_public)), auth, _point(ua_private), as_public, salt)
    try:
        plain = AESGCM(cek).decrypt(nonce, sealed, None)
    except InvalidTag as ex:
        raise ValueError("it does not open with these keys") from ex
    plain = plain.rstrip(b"\x00")
    if not plain.endswith(b"\x02"):
        raise ValueError("not the last record")
    return plain[:-1]


def payload(alert: Any, tile: str = "", at: float | None = None) -> bytes:
    """What a browser is told of an alert (alerts.Alert): its title and its text, the tile it is about (by its id: a tap
    opens the wall there), its kind and when it happened. Nothing else of it: not the machine's address, nor the wall's."""
    said = {"title": alert.title[:120], "body": alert.text[:400], "tile": tile, "kind": alert.kind, "at": round(time.time() if at is None else at)}
    return json.dumps(said, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")


def urgency(kind: str) -> str:
    """How soon a phone is to be woken for an alert of this kind (RFC 8030's Urgency): what is over can wait a little."""
    return "normal" if kind in ("recovered", "test") else "high"


# --- the subscription, and where its address may lead -------------------------------------------------------------


@dataclass(frozen=True)
class Subscription:
    """A browser's subscription, as it gives it: where its push service takes messages for it, and its two keys."""

    endpoint: str
    p256dh: bytes  # the browser's public key (P-256, 65 bytes)
    auth: bytes  # the secret it shares with whoever it subscribed to (16 bytes)

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).hostname or ""


def check_endpoint(url: Any) -> str:
    """The address a browser's push service gave it, where it can be one: https on port 443 to a name on the internet.
    ValueError with a sentence fit for showing otherwise. (Where that name leads is asked at each send: `vetted`.)"""
    usable = isinstance(url, str) and 0 < len(url) <= LONGEST_ENDPOINT and url.isascii() and not any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url)
    host = ""
    if usable:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            usable = parts.scheme == "https" and bool(host) and parts.port in (None, 443) and parts.username is None and parts.password is None and "#" not in url
        except ValueError:
            usable = False
    if not usable:
        raise ValueError("A push service's address starts with https:// and has no port of its own")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("A push service is reached by its name, not by a number")
    if not _TOP.fullmatch(host.rstrip(".").rsplit(".", 1)[-1]) or "." not in host.strip(".") or host == "localhost" or host.endswith((".localhost", *PRIVATE_SUFFIXES)):
        raise ValueError("A push service is a name on the internet, not one of this network")
    return str(url)


def check(endpoint: Any, p256dh: Any, auth: Any) -> Subscription:
    """A browser's subscription as the page hands it in, or ValueError with a sentence fit for showing."""
    endpoint = check_endpoint(endpoint)
    try:
        key, secret = unb64(p256dh), unb64(auth)
        usable = len(key) == 65 and len(secret) == 16
        if usable:
            _browsers(key)  # (a point on the curve: ValueError for one that is not)
    except ValueError:
        usable = False
    if not usable:
        raise ValueError("The browser's keys for push are not what a browser gives")
    return Subscription(endpoint, key, secret)


def public(address: str) -> bool:
    """Whether an address is one of the internet's: not this computer's, nor a private network's, nor link-local, nor one
    kept aside for something else. Where an IPv6 address carries an IPv4 one (mapped, NAT64, 6to4, the old compatible
    form), that one is asked too: through a NAT64 gateway, 64:ff9b::a00:1 is 10.0.0.1."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False  # (an address with a zone after it, fe80::1%eth0, is link-local anyway)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return public(str(ip.ipv4_mapped))  # (a connection to ::ffff:8.8.8.8 is one to 8.8.8.8)
        if ip in _LOCAL_NAT64:
            return False
        if any(ip in net for net in _NAT64):
            return public(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))  # ...and through a NAT64 gateway, to the IPv4 one
        if int(ip) >> 32 == 0:
            return False  # (::, ::1 and the old IPv4-compatible form: none of them is on the internet)
        if ip.is_site_local:
            return False  # (fec0::/10, a network's own before unique local took its place: Python counts it global)
        if ip.sixtofour is not None and not public(str(ip.sixtofour)):
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


class NotPublic(ValueError):
    """A push service's name leads to an address that is not on the internet."""


async def resolve(host: str, port: int) -> list[str]:
    """The addresses a name leads to, in the order they are to be tried. (A test puts its own in place of this.)"""
    found = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(str(entry[4][0]) for entry in found))


async def vetted(host: str, port: int) -> tuple[str, int]:
    """Where to connect for the push service of this name: the first address it leads to, where every one is public.

    NotPublic where one is not: a name that leads into the wall's own network (written so, or answered so by a DNS server
    somebody runs) is not followed there, and the connection goes to the address that was asked about, not to whatever
    the name leads to a moment later. OSError or TimeoutError where it leads nowhere just now."""
    async with asyncio.timeout(RESOLVE_TIMEOUT):
        addresses = await resolve(host, port)
    if not addresses:
        raise OSError(f"{host} leads nowhere")
    if not all(public(address) for address in addresses):
        log.warning("a push service's name leads to an address that is not on the internet, and was not sent to: %s -> %s", host, ", ".join(addresses[:4]))
        raise NotPublic("The push service's name leads to an address that is not on the internet: nothing was sent")
    return addresses[0], port


# --- sending ----------------------------------------------------------------------------------------------------------


class NotDelivered(Exception):
    """An alert did not reach a browser's push service. The message is a sentence fit for showing."""

    def __init__(self, message: str, again: bool, gone: bool = False, wait: float = 0.0) -> None:
        super().__init__(message)
        self.again = again  # worth another try: the service was away or busy
        self.gone = gone  # the service says the browser is no longer subscribed: it is taken off the list
        self.wait = wait  # seconds the service asked to be left alone for (Retry-After)


@dataclass(frozen=True)
class Target:
    """A browser to tell, as the wall has it for one send: its subscription, opened from the vault."""

    id: str  # of its record (store.PushRecord)
    subscription: Subscription


def retry_after(said: str | None) -> float:
    """A Retry-After given as seconds; 0 for nothing, or anything else (a date is not taken)."""
    return float(said) if said is not None and said.strip().isdigit() else 0.0


class Pusher:
    """Sends the alerts to the browsers subscribed to them: one task per browser while it has something to send.

    `key`: the wall's key at the moment (None where it does not open); `gone`: called (and waited for, by that
    browser's task alone) for a browser its push service says is no longer subscribed.
    """

    def __init__(
        self, key: Callable[[], WallKey | None], gone: Callable[[str], Awaitable[None]], allowed: Callable[[str, str | None], bool] | None = None
    ) -> None:
        self._key = key
        self._gone = gone
        # `allowed`: whether a browser may be told an alert about a machine (its id, or None) at this moment: asked before
        # every attempt, not only when it is put in
        self.allowed = allowed
        self._waiting: dict[str, deque[tuple[Target, bytes, str, str | None]]] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._dropping: set[str] = set()  # browsers whose oldest alert gave way, and it was said, since they last had none waiting
        self._at_once = asyncio.Semaphore(AT_ONCE)
        self._client: httpx.AsyncClient | None = None
        self.told: dict[str, tuple[float | None, str | None]] = {}  # push id -> (when an alert last arrived, what went wrong last), in memory

    def put(self, target: Target, said: bytes, how_soon: str = "high", about: str | None = None) -> None:
        """Have `said` sent to this browser, after what waits for it already (`about`: the machine it is about). Never waits
        itself."""
        waiting = self._waiting.setdefault(target.id, deque())
        if len(waiting) >= MOST_WAITING:
            waiting.popleft()
            if target.id not in self._dropping:  # (said once for a run of them: a line for each would be a flood)
                self._dropping.add(target.id)
                log.warning("alerts for a browser gave way, too many were waiting for its push service (%s)", target.subscription.host)
        waiting.append((target, said, how_soon, about))
        if target.id not in self._workers:
            self._workers[target.id] = asyncio.create_task(self._work(target.id))

    def waiting(self, push_id: str) -> int:
        """How many alerts wait for this browser, the one being sent included."""
        return len(self._waiting.get(push_id, ())) + (push_id in self._workers)

    def forget(self, push_id: str) -> None:
        """This browser is told nothing more: what waits for it goes, and what is under way for it is let go of."""
        self._waiting.pop(push_id, None)
        self.told.pop(push_id, None)
        self._dropping.discard(push_id)
        task = self._workers.pop(push_id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _work(self, push_id: str) -> None:
        waiting = self._waiting[push_id]
        try:
            while waiting:
                target, said, how_soon, about = waiting.popleft()
                try:
                    await self._deliver(target, said, how_soon, about)
                except Exception:  # whatever goes wrong with one alert must not be the end of this browser's others
                    log.exception("an alert could not be sent to a browser (%s)", target.subscription.host)
        finally:
            if self._waiting.get(push_id) is waiting:
                del self._waiting[push_id]
            if self._workers.get(push_id) is asyncio.current_task():
                del self._workers[push_id]
            self._dropping.discard(push_id)

    async def _deliver(self, target: Target, said: bytes, how_soon: str, about: str | None = None) -> None:
        for pause in (*RETRY_AFTER, None):
            # Asked again before each attempt: an account suspended, or a machine no longer its, since it was put in (the
            # outside review of 0.3.0, Codex's L1: one waiting to be tried again went out after the account was suspended).
            if self.allowed is not None and not self.allowed(target.id, about):
                return
            try:
                sent = await self.send(target, said, how_soon, still=lambda: self.allowed is None or self.allowed(target.id, about))
            except NotDelivered as ex:
                self.told[target.id] = (self.told.get(target.id, (None, None))[0], str(ex))
                if ex.gone:
                    self._waiting.get(target.id, deque()).clear()
                    log.info("a browser is no longer subscribed, says its push service (%s): taken off the list", target.subscription.host)
                    await self._gone(target.id)
                    return
                if pause is None or not ex.again:
                    log.warning("alert not delivered to a browser (%s): %s", target.subscription.host, ex)
                    return
                await asyncio.sleep(max(pause, min(ex.wait, LONGEST_WAIT)))
            else:
                if sent:
                    self.told[target.id] = (time.time(), None)
                return

    async def send(self, target: Target, said: bytes, how_soon: str = "normal", still: Callable[[], bool] | None = None) -> bool:
        """One attempt at telling one browser. Raises NotDelivered where it did not arrive.

        Encrypting and signing take about a fifth of a millisecond of the event loop, for each alert and browser."""
        key = self._key()
        if key is None:
            raise NotDelivered("The wall's key for push does not open (the settings file was edited, or is damaged)", again=False)
        subscription = target.subscription
        try:
            parts = urlsplit(check_endpoint(subscription.endpoint))  # (as it was checked when it was given: asked again, all the same)
        except ValueError as ex:
            raise NotDelivered(str(ex), again=False) from ex
        host = parts.hostname or ""
        async with self._at_once:
            try:
                async with asyncio.timeout(SEND_TIMEOUT):
                    address, port = await vetted(host, parts.port or 443)
                    tls = await public_context()
                    if self._client is None:
                        # A connection of its own for every send, never one kept: a connection is to an address, which was
                        # vetted for one name, and a kept one would carry the next request for another name there.
                        self._client = httpx.AsyncClient(verify=tls, timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False, limits=httpx.Limits(max_keepalive_connections=0))
                    client = self._client
                    headers = {
                        "Host": host,
                        "TTL": str(TTL),
                        "Urgency": how_soon,
                        "Content-Type": "application/octet-stream",
                        "Content-Encoding": "aes128gcm",
                        "Authorization": key.authorization(f"https://{host}", CONTACT),
                    }
                    url = parts._replace(netloc=f"[{address}]:{port}" if ":" in address else f"{address}:{port}").geturl()
                    # To the vetted address, with the name where the push service looks for it: in the request, and in
                    # the TLS handshake, whose certificate is checked for that name.
                    request = client.build_request("POST", url, content=encrypt(said, subscription.p256dh, subscription.auth), headers=headers, extensions={"sni_hostname": host})
                    if still is not None and not still():
                        # (Asked once more after the waits for a place and for the name, right before it goes: an account
                        # suspended meanwhile is told nothing. The outside review's second round, R2-L1.)
                        return False
                    reply = await client.send(request, stream=True)
                    try:
                        reason = await _reason(reply) if reply.status_code >= 300 else ""
                    finally:
                        await reply.aclose()
            except NotPublic as ex:
                raise NotDelivered(str(ex), again=False) from ex
            except (httpx.HTTPError, httpx.InvalidURL, TimeoutError, OSError) as ex:
                raise NotDelivered(f"The push service could not be reached ({type(ex).__name__})", again=True) from ex
        status = reply.status_code
        if status < 300:
            return True
        why = f", {reason}" if reason else ""
        if status in (404, 410):
            raise NotDelivered(f"The push service says this browser is no longer subscribed (HTTP {status}{why})", again=False, gone=True)
        if status in (401, 403):
            raise NotDelivered(f"The push service refused the wall's signature (HTTP {status}{why}). Is this computer's clock right?", again=False)
        again = status in (408, 425, 429) or status >= 500
        raise NotDelivered(f"The push service answered with an error (HTTP {status}{why})", again, wait=retry_after(reply.headers.get("retry-after")))

    async def close(self) -> None:
        for task in self._workers.values():
            task.cancel()
        await asyncio.gather(*self._workers.values(), return_exceptions=True)
        self._workers.clear()
        self._waiting.clear()
        if self._client is not None:
            await self._client.aclose()
            self._client = None


async def _reason(reply: httpx.Response) -> str:
    """The reason a push service gives for a refusal, where it gives one in a word (Apple's: "BadJwtToken"). Read as it came,
    never unpacked, and no more of it than MOST_READ."""
    got = b""
    async for chunk in reply.aiter_raw():
        got += chunk
        if len(got) >= MOST_READ:
            break
    found = _REASON.search(got[:MOST_READ])
    return found.group(1).decode("ascii") if found else ""
