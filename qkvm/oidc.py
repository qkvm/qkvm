"""Signing in through an identity provider by OpenID Connect (0.4.0): Entra ID, Google, Authentik, Keycloak, any provider
that speaks it. The provider says who somebody is and which groups they are in; the wall's settings say which role each
group gives (store.OidcSettings).

The flow is the authorization code flow with PKCE (RFC 7636, S256), and nothing else:

- A sign-in is begun on the wall's page (`Starts.begin`): a `state`, a `nonce` and a PKCE verifier are made for it, kept on
  the wall for STARTED_WITHIN at the most, and bound to the browser that began it by a cookie of its own (only a hash of
  which is kept). The browser is sent to the provider with the state, the nonce, the PKCE challenge and the exact redirect
  address the admin saw on the page and entered at the provider.
- The provider sends the browser back with a code. The state is taken once (a second use of it is refused, as one that is
  not known), only from the browser that holds the cookie, and only while the settings are still those it was begun with.
- The code is exchanged at the provider's token endpoint, by the wall itself, with the client secret and the PKCE verifier.
- The ID token that comes back is checked in full before anybody is let in on it (`Verifier.checked`): signed by a key
  of the provider's published set with RS256 or ES256 (never `none`, never HS256 or any other algorithm, never a key the
  token itself names or carries; a `kid` the set does not have is refused, after one fetch of the set at the most every
  KEYS_AGAIN_AFTER), its `iss`, `aud`, `azp` where there is one (and where there are several audiences), `exp`, `iat`,
  `nbf` with LEEWAY, and its `nonce`.
- Groups are read from the ID token, or from the userinfo endpoint where the token has none (its `sub` the token's).
  Entra's "too many groups to put in the token" (`_claim_names`) is said as what it is, and the sign-in refused: the
  groups somewhere else are not fetched behind the admin's back.

Everything the provider sends is read as a device's answer is (FOR-THE-DESKTOP-APP.md part 3): over HTTPS only, by the
wall's outbound rules (egress.py: the address judged, no redirect followed, no proxy), up to a size, within a time, and
by kind. No token, code, secret or verifier is ever written to a log, the activity log, an error text or a URL of the
wall's own; a refusal says why in words of this program's own.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import egress
from .store import ROLES, OidcSettings, as_a_line

CALLBACK = "/api/v1/oidc/callback"  # where the provider sends a browser back to, on this wall
COOKIE = "qkvm_oidc"  # what binds a sign-in under way to the browser that began it (only its hash is kept on the wall)
SECURE_COOKIE = "__Host-" + COOKIE  # ...over HTTPS: the host's alone (see cookie_for)


def cookie_for(secure: bool) -> tuple[str, str]:
    """The name and path of the cookie that binds a sign-in to its browser, for a wall served over HTTPS (`secure`) or not.

    Over HTTPS a __Host- cookie: a browser takes one only with Secure, the path / and no Domain, so a page on a name beside
    the wall's (a sibling subdomain) cannot set one for it, to have the victim's browser finish a sign-in of the attacker's
    own. The prefix asks for the path /: it is bound to the way back by its value, which only the way back reads. Over plain
    HTTP there is no such thing to be had; there it is the way back's alone by its path."""
    return (SECURE_COOKIE, "/") if secure else (COOKIE, CALLBACK)
SEALED_FOR = "oidc:client"  # what the client secret is sealed for by the vault (no record's id has a colon: nothing else opens as it)

# The two algorithms a provider's ID token may be signed with, and the kind of key each takes. `none`, every HMAC
# algorithm (HS256 and its kin, whose "key" would be whatever the token's sender likes, the provider's public key
# included) and everything else are refused by being absent here.
ALGORITHMS = {"RS256": "RSA", "ES256": "EC"}
LEEWAY = 120.0  # seconds the wall's clock and the provider's may differ by, for exp, iat and nbf
# The longest a sign-in by the provider lasts, however much it is used: a working day. The role is read from the groups at
# sign-in; taken away at the provider, it is gone here this long after at the latest (at once with "Sign them out").
# Not the ID token's exp: that says how long the token may be handed on (five minutes with Keycloak as it comes, an hour
# with Entra and Google), not how long the person's sign-in at the provider lasts, and the button signs in again without a
# question where that one still holds.
SIGNED_IN_FOR = 8 * 3600.0
STARTED_WITHIN = 600.0  # seconds a sign-in may take at the provider, from the press of the button to the way back
MOST_UNDER_WAY = 1000  # sign-ins under way at once, from everybody together
MOST_UNDER_WAY_OF_ONE = 20  # ...and from one address (an IPv6 network counts as one, as for wrong passwords)
KEYS_AGAIN_AFTER = 300.0  # seconds before the provider's keys are fetched again for a token whose key they do not have
KEPT_FOR = 3600.0  # seconds what the provider says of itself, and its keys, are kept before they are asked for anew
TRIED_AGAIN_AFTER = 10.0  # seconds a provider that could not be asked is not asked again (everybody's button says why)
MOST_DOCUMENT = 64 * 1024  # bytes of what a provider says of itself (/.well-known/openid-configuration)
MOST_KEY_SET = 256 * 1024  # bytes of its set of keys
MOST_TOKENS = 256 * 1024  # bytes of the token endpoint's answer, and of userinfo's (an ID token with many groups is long)
MOST_TOKEN = 128 * 1024  # characters of one ID token
MOST_KEYS = 50  # keys of a set that are looked at
MOST_GROUPS = 1000  # groups of one person that are looked at
MOST_GROUP = 256  # characters of a group's name
SMALLEST_RSA = 2048  # bits of an RSA key, at the least
LARGEST_RSA = 8192  # ...and at the most (a larger one is work for nothing at every sign-in)
GOOGLE = "https://accounts.google.com"  # Google's issuer: it says a Workspace account's domain in `hd`, and is held to it

_STATE = re.compile(r"[A-Za-z0-9_-]{43}")  # what this program makes a state as (secrets.token_urlsafe(32))
_CODE = re.compile(r"[\x21-\x7e]{1,4096}")  # an authorization code: printable, no blank, of a sane length
_B64 = re.compile(r"[A-Za-z0-9_-]*")
_CLAIM = re.compile(r"[A-Za-z0-9_.:/-]{1,100}")  # the name of the claim that carries groups ("groups", "roles", "realm_access.roles")
_SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{1,100}")  # one scope (RFC 6749 3.3)
_CLIENT = re.compile(r"[\x21-\x7e]{1,256}")  # a client id: printable, no blank
_SECRET = re.compile(r"[\x20-\x7e]{1,512}")  # a client secret
_DOMAIN = re.compile(r"(?=.{3,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
_ERROR = re.compile(r"[a-z_]{1,40}")  # an error code of OAuth (access_denied, invalid_grant), as it may be repeated


def a_code(text: str) -> bool:
    """Whether what came back as an authorization code can be one (printable, no blank, of a sane length)."""
    return _CODE.fullmatch(text) is not None


def error_word(text: str) -> str:
    """An OAuth error code a provider sent (access_denied), where it is one; "" for anything else, which is not repeated."""
    return text if _ERROR.fullmatch(text) else ""


class Refusal(Exception):
    """A sign-in through the provider that is not let in. `code` is a word for the page and the activity log; `said`, a
    sentence of this program's own, fit for both. Neither ever holds a token, a code, a secret or a verifier."""

    def __init__(self, code: str, said: str) -> None:
        super().__init__(said)
        self.code, self.said = code, said


# --- settings, as an admin enters them ---------------------------------------------------------------------------------


def issuer_url(text: str) -> str:
    """An issuer as it may be saved: https://, a host, a path, no query, no fragment, no user name. ValueError otherwise.

    Kept exactly as typed otherwise (a slash at its end included): the provider's own word for itself has to be the same
    to the character (OpenID Connect Discovery 4.3), and the wall says which it is where they differ."""
    text = text.strip()
    if not text or len(text) > 500 or any(ch.isspace() or ord(ch) < 32 or ord(ch) > 126 for ch in text):
        raise ValueError("The issuer is an address starting with https://")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:  # ("https://[not an address", a port that is no number)
        raise ValueError("The issuer is an address starting with https://") from None
    if parts.scheme != "https" or not parts.hostname or port == 0 or parts.username is not None or parts.password is not None:
        raise ValueError("The issuer is an address starting with https:// (an identity provider is spoken to over HTTPS only)")
    if parts.query or parts.fragment or "#" in text or "?" in text:
        raise ValueError("The issuer has no ? or # in it: it is the provider's address, as it says it of itself")
    return text


def scopes_of(text: str) -> str:
    """What is asked of the provider, as it may be saved: scopes separated by blanks, `openid` among them. ValueError."""
    said = text.split()
    if not said or len(said) > 20 or not all(_SCOPE.fullmatch(scope) for scope in said):
        raise ValueError("Scopes are words separated by blanks, such as: openid profile email")
    if "openid" not in said:
        raise ValueError("The scopes have to include openid")
    return " ".join(dict.fromkeys(said))


def groups_claim(text: str) -> str:
    text = text.strip()
    if text and not _CLAIM.fullmatch(text):
        raise ValueError("The groups claim is a name such as groups, roles or realm_access.roles")
    return text


def client_id(text: str) -> str:
    text = text.strip()
    if not _CLIENT.fullmatch(text):
        raise ValueError("The client ID is the one the provider gave this application (printable characters, no blanks)")
    return text


def client_secret(text: str) -> str:
    if not _SECRET.fullmatch(text):
        raise ValueError("The client secret is printable characters, 512 at the most")
    return text


def email_domain(text: str) -> str:
    text = text.strip().lower().removeprefix("@")
    if text and not _DOMAIN.fullmatch(text):
        raise ValueError("The email domain is a domain such as example.org")
    return text


def roles_of(pairs: Collection[tuple[str, str]]) -> dict[str, str]:
    """Groups and the role each gives, as they may be saved. ValueError for a group's name that is no line, or a role that is none."""
    kept: dict[str, str] = {}
    for group, role in pairs:
        line = as_a_line(group.strip())
        if not line or len(line) > MOST_GROUP:
            raise ValueError(f"A group's name is one line of {MOST_GROUP} characters at the most")
        if role not in ROLES:
            raise ValueError(f"A group gives one of the roles: {', '.join(ROLES)}")
        if line in kept and kept[line] != role:
            raise ValueError(f"The group {line} is given two roles")
        kept[line] = role
    return kept


def button_name(text: str) -> str:
    line = as_a_line(text.strip())
    if line is None or len(line) > 40:
        raise ValueError("The name on the button is one line of 40 characters at the most")
    return line


def redirect_uri(text: str, host_header: str) -> str:
    """The address the provider sends a browser back to, as the page that saves the settings computed it: this wall's own,
    at the very address (host and port) the admin is looking at it by. ValueError otherwise.

    It is begun from, and comes back to, one address: a browser's cookies are its host's, and the one that binds a sign-in to
    its browser is set where the button was pressed."""
    text = text.strip()
    wrong = "The redirect address is this wall's own address, followed by " + CALLBACK
    try:
        parts = urlsplit(text)
        usable = parts.scheme in ("http", "https") and bool(parts.hostname) and parts.port != 0 and text.isascii()
    except ValueError:
        raise ValueError(wrong) from None
    if not usable or parts.username is not None or parts.password is not None or parts.query or parts.fragment or "#" in text or "?" in text:
        raise ValueError(wrong)
    if parts.path != CALLBACK:
        raise ValueError("The redirect address ends in " + CALLBACK)
    if not same_host(parts.netloc, host_header):
        raise ValueError("The redirect address is the one this page is looked at by: save these settings from the address your team opens qKVM at")
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path, "", ""))


def same_host(netloc: str, host_header: str) -> bool:
    """Whether a browser that sent this Host header is at the host and port of `netloc` (as written, in any case)."""
    return bool(host_header) and hmac.compare_digest(netloc.lower().encode("ascii", "replace"), host_header.strip().lower().encode("ascii", "replace"))


def offered(settings: OidcSettings) -> bool:
    """Whether the sign-in page offers the provider's button: switched on, and with everything it takes."""
    return settings.enabled and bool(settings.issuer and settings.client_id and settings.secret and settings.redirect_uri)


def called(settings: OidcSettings) -> str:
    """What the button says after "Sign in with"."""
    return settings.name or urlsplit(settings.issuer).hostname or "your identity provider"


def open_to_the_world(settings: OidcSettings) -> str | None:
    """Why these settings would let in anybody at all, where they would; None where they would not. Google signs in any
    Google account there is (where its consent screen is External, of anybody in the world): "anybody else" from Google
    without an email domain is anybody. Another provider's accounts are its organisation's (the page warns all the same)."""
    if settings.issuer == GOOGLE and settings.anyone and not settings.domain:
        return "Google signs in any Google account there is: to let in anybody else it signs in, set the email domain of your Workspace"
    return None


def granted_by(settings: OidcSettings) -> str:
    """A mark of everything in the settings that decides who the provider signs in here, and as what: a sign-in made under
    other settings is over (its role was read under them). Not the button's name, the redirect address or the private
    switch, which give nobody anything."""
    said = [settings.enabled, settings.issuer, settings.client_id, settings.scopes, settings.groups_claim, sorted(settings.roles.items()), settings.anyone, settings.domain]
    return hashlib.sha256(json.dumps(said, sort_keys=True).encode()).hexdigest()


def mark_of(settings: OidcSettings) -> str:
    """A mark of what a sign-in under way was begun with: where it was sent, as whom, and back to where. A sign-in begun
    before any of that changed is not finished after it (the admin switched it off, or to another provider)."""
    said = [settings.enabled, settings.issuer, settings.client_id, settings.redirect_uri, settings.secret]
    return hashlib.sha256(json.dumps(said, sort_keys=True, default=str).encode()).hexdigest()


# --- a sign-in under way -----------------------------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def challenge_of(verifier: str) -> str:
    """The PKCE challenge of a verifier, S256 (RFC 7636 4.2)."""
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


def browser_mark(cookie: str) -> str:
    return hashlib.sha256(cookie.encode("utf-8", "replace")).hexdigest()


@dataclass
class Start:
    """A sign-in under way: what it was begun with, kept on the wall and never handed to the browser but for the state."""

    nonce: str
    verifier: str  # PKCE: only its challenge went to the provider; the verifier goes to its token endpoint with the code
    browser: str  # the hash of the cookie of the browser that began it
    mark: str  # mark_of the settings it was begun with
    address: str  # what it is counted under (security.Limiter.counted_as)
    at: float = field(default_factory=time.monotonic)


class Starts:
    """The sign-ins under way: each taken once, from the browser that began it, within STARTED_WITHIN."""

    def __init__(self) -> None:
        self._under_way: dict[str, Start] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        self._under_way = {state: start for state, start in self._under_way.items() if now - start.at <= STARTED_WITHIN}

    def begin(self, settings: OidcSettings, address: str) -> tuple[str, Start, str] | None:
        """A new one: (its state, what is kept of it, the cookie for the browser). None where too many are under way, from
        this address or from everybody: the oldest are not pushed out for a new one, or anybody could push out everybody's."""
        self._prune()
        if len(self._under_way) >= MOST_UNDER_WAY or sum(1 for start in self._under_way.values() if start.address == address) >= MOST_UNDER_WAY_OF_ONE:
            return None
        state, cookie = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        start = Start(nonce=secrets.token_urlsafe(32), verifier=secrets.token_urlsafe(48), browser=browser_mark(cookie), mark=mark_of(settings), address=address)
        self._under_way[state] = start
        return state, start, cookie

    def take(self, state: str, cookie: str | None) -> Start:
        """The sign-in this state was made for, taken out (a second use of it is one of a state not known). Refusal where it
        is not known, has run out, or was begun in another browser."""
        start = self._under_way.pop(state, None) if _STATE.fullmatch(state) else None
        if start is None or time.monotonic() - start.at > STARTED_WITHIN:
            raise Refusal("state", "This sign-in was not begun here, took longer than ten minutes, or was finished already")
        if not cookie or not hmac.compare_digest(browser_mark(cookie), start.browser):
            raise Refusal("browser", "This sign-in was begun in another browser")
        return start

    def __len__(self) -> int:
        self._prune()
        return len(self._under_way)


def authorization_url(provider: Provider, settings: OidcSettings, state: str, start: Start) -> str:
    """Where the browser is sent to sign in at the provider."""
    parts = urlsplit(provider.authorization_endpoint)
    asked = {
        "response_type": "code", "client_id": settings.client_id, "redirect_uri": settings.redirect_uri, "scope": settings.scopes,
        "state": state, "nonce": start.nonce, "code_challenge": challenge_of(start.verifier), "code_challenge_method": "S256",
    }  # fmt: skip
    # (What the provider's own address carries, it keeps; what the wall asks for is the wall's.)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key not in asked] + list(asked.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


# --- what the provider says of itself, and its keys --------------------------------------------------------------------


@dataclass(frozen=True)
class Provider:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    basic: bool  # the client secret goes in the Authorization header (client_secret_basic), or else in the form (client_secret_post)
    says_issuer: bool  # it puts `iss` into the address it sends a browser back by (RFC 9207): one without it is refused


@dataclass(frozen=True)
class Key:
    kid: str
    kty: str  # "RSA" or "EC" (P-256)
    alg: str | None  # where the set names the one algorithm it is for
    public: rsa.RSAPublicKey | ec.EllipticCurvePublicKey


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object of a token, where a name may come once: twice, another reader of the same token may read the other."""
    made: dict[str, Any] = {}
    for name, value in pairs:
        if name in made:
            raise ValueError(f"{name!r} twice")
        made[name] = value
    return made


def _object(data: bytes, what: str, unique: bool = False) -> dict[str, Any]:
    """`data` as a JSON object. Refusal where it is not one."""
    try:
        said = json.loads(data.decode("utf-8"), object_pairs_hook=_unique if unique else None)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refusal("unreadable", f"What {what} sent is not JSON") from None
    if not isinstance(said, dict):
        raise Refusal("unreadable", f"What {what} sent is not a JSON object")
    return said


def _endpoint(said: dict[str, Any], name: str, required: bool = True) -> str | None:
    """An endpoint the provider names: https://, without a user name or password in it. Refusal otherwise."""
    value = said.get(name)
    if value is None and not required:
        return None
    if isinstance(value, str) and value.startswith("https://") and "@" not in urlsplit(value).netloc:
        try:
            return egress.check_url(value, https_only=True)
        except ValueError:
            pass
    raise Refusal("discovery", f"The provider names no {name} at an https:// address")


def provider_from(said: dict[str, Any], issuer: str) -> Provider:
    """What a provider says of itself (OpenID Connect Discovery 1.0), as far as the wall uses it. Refusal otherwise."""
    if said.get("issuer") != issuer:
        theirs = said.get("issuer")
        shown = theirs if isinstance(theirs, str) and len(theirs) <= 300 and theirs.isprintable() else "something else"
        raise Refusal("discovery", f"The provider calls itself {shown}, not {issuer}: enter the issuer exactly as it says it")
    types = said.get("response_types_supported")
    if isinstance(types, list) and "code" not in types:
        raise Refusal("discovery", "The provider does not offer the authorization code flow")
    methods = said.get("code_challenge_methods_supported")
    if isinstance(methods, list) and "S256" not in methods:
        raise Refusal("discovery", "The provider does not offer PKCE with S256")
    auth = said.get("token_endpoint_auth_methods_supported")
    auth = auth if isinstance(auth, list) else ["client_secret_basic"]  # (the default, where it says none: Discovery 3)
    if "client_secret_basic" not in auth and "client_secret_post" not in auth:
        raise Refusal("discovery", "The provider takes no client secret at its token endpoint")
    return Provider(
        issuer=issuer,
        authorization_endpoint=str(_endpoint(said, "authorization_endpoint")),
        token_endpoint=str(_endpoint(said, "token_endpoint")),
        jwks_uri=str(_endpoint(said, "jwks_uri")),
        userinfo_endpoint=_endpoint(said, "userinfo_endpoint", required=False),
        basic="client_secret_basic" in auth,
        says_issuer=said.get("authorization_response_iss_parameter_supported") is True,
    )


def _number(text: Any) -> int:
    """A base64url field of a key, as the big-endian number it is."""
    if not isinstance(text, str) or not _B64.fullmatch(text) or len(text) > 4096:
        raise ValueError("not base64url")
    return int.from_bytes(_unpadded(text), "big")


def _unpadded(text: str) -> bytes:
    if len(text) % 4 == 1:
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not base64url") from None


def key_from(said: Any) -> Key | None:
    """One key of a set, where it is one a token may be checked with: RSA of SMALLEST_RSA to LARGEST_RSA bits, or EC on
    P-256; for signing; with a kid. None for any other (an `oct` key above all: a secret shared with nobody here)."""
    if not isinstance(said, dict):
        return None
    kid, kty, alg = said.get("kid"), said.get("kty"), said.get("alg")
    if not isinstance(kid, str) or not 0 < len(kid) <= 200 or kty not in ("RSA", "EC"):
        return None
    if said.get("use", "sig") != "sig" or (alg is not None and (not isinstance(alg, str) or ALGORITHMS.get(alg) != kty)):
        return None
    ops = said.get("key_ops")
    if ops is not None and not (isinstance(ops, list) and "verify" in ops):
        return None
    try:
        public: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
        if kty == "RSA":
            n, e = _number(said.get("n")), _number(said.get("e"))
            if not SMALLEST_RSA <= n.bit_length() <= LARGEST_RSA or not 3 <= e < 2**32 or e % 2 == 0:
                return None
            public = rsa.RSAPublicNumbers(e, n).public_key()
        else:
            if said.get("crv") != "P-256":
                return None
            x, y = said.get("x"), said.get("y")
            if not (isinstance(x, str) and isinstance(y, str) and len(_unpadded(x)) == 32 and len(_unpadded(y)) == 32):
                return None
            public = ec.EllipticCurvePublicNumbers(_number(x), _number(y), ec.SECP256R1()).public_key()  # (ValueError off the curve)
    except ValueError:
        return None
    return Key(kid, kty, alg, public)


def keys_from(said: dict[str, Any]) -> list[Key]:
    found = said.get("keys")
    if not isinstance(found, list):
        raise Refusal("keys", "The provider's set of keys holds no keys")
    return [key for key in (key_from(each) for each in found[:MOST_KEYS]) if key is not None]


# --- the ID token ------------------------------------------------------------------------------------------------------


def _parts(token: Any) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """A token's header, its claims, what was signed, and the signature. Refusal where it is not a signed JWT (JWS compact)."""
    if not isinstance(token, str) or not 0 < len(token) <= MOST_TOKEN:
        raise Refusal("token", "The ID token is missing, or longer than any is")
    pieces = token.split(".")
    if len(pieces) != 3 or not all(_B64.fullmatch(piece) for piece in pieces):
        raise Refusal("token", "The ID token is not a signed token (three parts of base64url)")
    try:
        header_bytes, claims_bytes, signature = (_unpadded(piece) for piece in pieces)
    except ValueError:
        raise Refusal("token", "The ID token is not a signed token (three parts of base64url)") from None
    header = _object(header_bytes, "the ID token's header", unique=True)
    claims = _object(claims_bytes, "the ID token", unique=True)
    return header, claims, f"{pieces[0]}.{pieces[1]}".encode("ascii"), signature


def _header(header: dict[str, Any]) -> tuple[str, str]:
    """The algorithm and the key's id a token's header names, where it is one this program checks a token with."""
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALGORITHMS:
        shown = alg if isinstance(alg, str) and re.fullmatch(r"[A-Za-z0-9]{1,10}", alg) else "none it names"
        raise Refusal("algorithm", f"The ID token is signed with {shown}: only RS256 and ES256 are taken")
    if "crit" in header:
        raise Refusal("token", "The ID token's header asks for extensions this program does not know (crit)")
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.lower() not in ("jwt", "application/jwt")):
        raise Refusal("token", "The ID token is of another type than an ID token (typ)")
    kid = header.get("kid")
    if not isinstance(kid, str) or not 0 < len(kid) <= 200:
        raise Refusal("key", "The ID token names no key of the provider's (kid)")
    # (`jku`, `jwk`, `x5u` and `x5c` are never looked at: a key is the provider's because its set says so, not the token.)
    return alg, kid


def _signed(alg: str, keys: list[Key], kid: str, signing_input: bytes, signature: bytes) -> bool:
    """Whether a key of the set, of this kid and of the algorithm's kind, made this signature."""
    for key in keys:
        if key.kid != kid or key.kty != ALGORITHMS[alg] or (key.alg is not None and key.alg != alg):
            continue
        try:
            if isinstance(key.public, rsa.RSAPublicKey):
                key.public.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
                return True
            if len(signature) != 64:  # (JWA 3.4: R and S of 32 bytes each, nothing else; not DER)
                continue
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            key.public.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


def _a_time(claims: dict[str, Any], name: str) -> float:
    value = claims.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value < 1e11:
        raise Refusal("token", f"The ID token's {name} is missing, or is not a time")
    return float(value)


def claims_checked(claims: dict[str, Any], *, issuer: str, client: str, nonce: str, now: float) -> dict[str, Any]:
    """The claims of a token whose signature was found good, held to what this sign-in asked for (OpenID Connect Core
    3.1.3.7). Refusal otherwise."""
    if claims.get("iss") != issuer:
        raise Refusal("issuer", "The ID token was issued by another provider than this one (iss)")
    aud = claims.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) and all(isinstance(each, str) for each in aud) else []
    if client not in audiences:
        raise Refusal("audience", "The ID token is for another application (aud)")
    azp = claims.get("azp")
    if (len(audiences) > 1 or azp is not None) and azp != client:
        # (Several audiences, and none of them said to be the one it was given to: Core 3.1.3.7, items 4 and 5, taken as rules.)
        raise Refusal("audience", "The ID token was given to another application (azp)")
    expires, issued = _a_time(claims, "exp"), _a_time(claims, "iat")
    not_before = _a_time(claims, "nbf") if "nbf" in claims else None
    if now > expires + LEEWAY:
        raise Refusal("expired", "The ID token has run out (exp)")
    if issued > now + LEEWAY or (not_before is not None and not_before > now + LEEWAY):
        raise Refusal("not_yet", "The ID token is not valid yet (iat, nbf): is this computer's clock right?")
    if issued < now - STARTED_WITHIN - LEEWAY:
        raise Refusal("expired", "The ID token was issued longer ago than a sign-in takes (iat)")
    said_nonce = claims.get("nonce")
    if not isinstance(said_nonce, str) or not hmac.compare_digest(said_nonce.encode("utf-8", "replace"), nonce.encode("ascii")):
        raise Refusal("nonce", "The ID token is not the one this sign-in asked for (nonce)")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not 0 < len(sub) <= 255 or not sub.isprintable():
        raise Refusal("token", "The ID token says nobody (sub)")
    return claims


# --- groups, and what they give ---------------------------------------------------------------------------------------


def _claim(said: dict[str, Any], name: str) -> Any:
    """A claim by its name; or, where there is none of that name and it has dots in it, by its path (realm_access.roles)."""
    if name in said:
        return said[name]
    found: Any = said
    for part in name.split(".") if "." in name else ():
        if not isinstance(found, dict) or part not in found:
            return None
        found = found[part]
    return found if "." in name else None


def overage(said: dict[str, Any], name: str) -> bool:
    """Whether the provider says the groups are too many for the token, and are to be fetched elsewhere (Entra ID's
    `_claim_names`, or `hasgroups`)."""
    names = said.get("_claim_names")
    return (isinstance(names, dict) and name in names) or (name == "groups" and said.get("hasgroups") is True)


def groups_in(said: dict[str, Any], name: str) -> list[str] | None:
    """The groups `said` names under `name`; None where it says nothing of them. Refusal where what it says is no list of names."""
    if not name:
        return []
    found = _claim(said, name)
    if found is None:
        return None
    if isinstance(found, str):
        found = [found]
    if not isinstance(found, list) or not all(isinstance(each, str) for each in found):
        raise Refusal("groups", f"What the provider sends as {name} is not a list of group names")
    return [each for each in found[:MOST_GROUPS] if len(each) <= MOST_GROUP]


def role_for(groups: list[str], settings: OidcSettings) -> str | None:
    """The role these groups give (the highest of them); for a person in none of them, the role for anybody else (who else
    may sign in); None: this person is not let in.

    Who else may sign in is for those in no group that gives a role, never beside a group's role: taken with them and the
    highest of all given, an auditor whose group gives viewer signed in as an admin where anybody else is let in as one (the
    outside review of 0.4.0, round 6.2, H1). Compared exactly as the provider writes them, as the admin entered
    them: a group whose name differs in case from one that gives a role is another group (some providers let their users
    make groups of their own)."""
    given = {settings.roles[group] for group in groups if group in settings.roles}
    if not given:
        return settings.anyone or None
    return next((role for role in ROLES if role in given), None)  # (most to least)


def domain_refusal(claims: dict[str, Any], settings: OidcSettings) -> Refusal | None:
    """Why this person is not let in for their email domain; None where the rule lets them in, or there is none."""
    if not settings.domain:
        return None
    # Compared as plain ASCII only, lowered (the domain is saved so): str.lower() makes letters of other alphabets into
    # plain ones (the Kelvin sign into k), and an address written with one is not an address at the domain.
    email = claims.get("email")
    if not isinstance(email, str) or not email.isascii() or email.rpartition("@")[2].lower() != settings.domain or not email.rpartition("@")[0]:
        return Refusal("email_domain", f"The provider says no email address at {settings.domain} for this person")
    if claims.get("email_verified") is not True:
        return Refusal("email_unverified", "The provider does not say that this person's email address is verified (email_verified)")
    hd = claims.get("hd")
    if (hd is not None or settings.issuer == GOOGLE) and (not isinstance(hd, str) or not hd.isascii() or hd.lower() != settings.domain):
        # Google says the domain of a Workspace account in `hd`; an account of Google's own made with an address at the
        # domain has a verified address there and none of that. Where `hd` is said, by any provider, it is held to as well.
        return Refusal("email_domain", f"The provider does not say that this is an account of {settings.domain} (hd)")
    return None


# --- the provider, spoken to -------------------------------------------------------------------------------------------


Own = Callable[[], Awaitable[egress.Own]]


class Client:
    """What the wall knows of the provider at the moment (what it says of itself, its keys), and the requests made to it."""

    def __init__(self, own: Own) -> None:
        self._own = own  # this wall's own addresses, which nothing is sent to (egress.judge)
        self._provider: tuple[str, float, Provider] | None = None  # (issuer, when it was asked, what it said)
        self._keys: tuple[str, float, list[Key]] | None = None  # (where they were fetched, when, what they are)
        self._failed: tuple[str, float, Refusal] | None = None  # (issuer, when, why) of the last ask that failed
        self.fetches = 0  # how often its keys were fetched (for the tests: no more than KEYS_AGAIN_AFTER lets)

    def forget(self) -> None:
        """The settings changed: nothing is taken from the provider as it was."""
        self._provider = self._keys = self._failed = None

    async def _get(self, url: str, settings: OidcSettings, most: int, what: str, headers: dict[str, str] | None = None) -> egress.Reply:
        try:
            wall = await self._own()  # the wall itself: its addresses and the ports it really listens on (never sent to)
            reply = await egress.request(
                "GET", url, None, {"Accept": "application/json", **(headers or {})}, private_ok=settings.private, own=wall.addresses,
                own_ports=wall.ports, most=most + 1, https_only=True,
            )
        except (egress.Refused, egress.NotReached) as ex:
            raise Refusal("not_reached", f"{what} could not be asked: {ex}") from None
        if len(reply.body) > most:
            raise Refusal("unreadable", f"What {what} sent is larger than it can be")
        return reply

    async def provider(self, settings: OidcSettings) -> Provider:
        """What the provider says of itself: asked once in a while (KEPT_FOR), and not again for a while where that failed."""
        now = time.monotonic()
        if self._provider is not None and self._provider[0] == settings.issuer and now - self._provider[1] < KEPT_FOR:
            return self._provider[2]
        if self._failed is not None and self._failed[0] == settings.issuer and now - self._failed[1] < TRIED_AGAIN_AFTER:
            raise self._failed[2]
        try:
            reply = await self._get(settings.issuer.rstrip("/") + "/.well-known/openid-configuration", settings, MOST_DOCUMENT, "The provider")
            if reply.status != 200:
                raise Refusal("discovery", f"The provider answered HTTP {reply.status} where it says what it is (/.well-known/openid-configuration)")
            found = provider_from(_object(reply.body, "the provider"), settings.issuer)
        except Refusal as ex:
            self._failed = (settings.issuer, time.monotonic(), ex)
            raise
        self._provider, self._failed = (settings.issuer, time.monotonic(), found), None
        return found

    async def keys(self, provider: Provider, settings: OidcSettings, kid: str | None = None) -> list[Key]:
        """The provider's keys: fetched anew where they are older than KEPT_FOR, or where `kid` is not among them and they
        were fetched longer ago than KEYS_AGAIN_AFTER (a token that names a key nobody has makes one fetch, not one each)."""
        now = time.monotonic()
        if self._keys is not None and self._keys[0] == provider.jwks_uri:
            age = now - self._keys[1]
            known = kid is None or any(key.kid == kid for key in self._keys[2])
            if age < KEPT_FOR and (known or age < KEYS_AGAIN_AFTER):
                return self._keys[2]
        reply = await self._get(provider.jwks_uri, settings, MOST_KEY_SET, "The provider's set of keys")
        self.fetches += 1
        if reply.status != 200:
            raise Refusal("keys", f"The provider answered HTTP {reply.status} for its set of keys")
        found = keys_from(_object(reply.body, "the provider's set of keys"))
        self._keys = (provider.jwks_uri, time.monotonic(), found)
        return found

    async def exchange(self, provider: Provider, settings: OidcSettings, secret: str, code: str, verifier: str) -> dict[str, Any]:
        """The code, exchanged at the provider's token endpoint with the client secret and the PKCE verifier: its answer."""
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri, "code_verifier": verifier, "client_id": settings.client_id}
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        if provider.basic:
            # (RFC 6749 2.3.1: each of the two form-encoded first, then put together.)
            pair = f"{urlencode({'': settings.client_id})[1:]}:{urlencode({'': secret})[1:]}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode("ascii")).decode("ascii")
        else:
            form["client_secret"] = secret
        try:
            wall = await self._own()  # the wall itself: its addresses and the ports it really listens on (never sent to)
            reply = await egress.request(
                "POST", provider.token_endpoint, urlencode(form).encode("ascii"), headers, private_ok=settings.private,
                own=wall.addresses, own_ports=wall.ports, most=MOST_TOKENS + 1, https_only=True,
            )
        except (egress.Refused, egress.NotReached) as ex:
            raise Refusal("not_reached", f"The provider's token endpoint could not be asked: {ex}") from None
        if len(reply.body) > MOST_TOKENS:
            raise Refusal("unreadable", "What the provider's token endpoint sent is larger than it can be")
        if reply.status != 200:
            said = _object(reply.body, "the provider's token endpoint") if reply.body[:1] == b"{" else {}
            error = said.get("error")
            # (Its code of OAuth, where it is one: invalid_grant for a code that is not good, or one issued for another PKCE
            # challenge; invalid_client for a wrong secret. Never its description, which is the provider's text; nor a code
            # that holds what was sent, whole or in part: a client secret, a code or a verifier of small letters and
            # underscores is one, said back, and the refusal goes into the activity log. The outside review of 0.4.0, L1.)
            carried = [secret, code, verifier, headers.get("Authorization", "").removeprefix("Basic ")]
            word = f" ({error})" if isinstance(error, str) and _ERROR.fullmatch(error) and egress.hidden(error, carried) == error else ""
            raise Refusal("exchange", f"The provider's token endpoint refused the code: HTTP {reply.status}{word}")
        said = _object(reply.body, "the provider's token endpoint")
        kind = said.get("token_type")
        if kind is not None and (not isinstance(kind, str) or kind.lower() not in ("bearer", "dpop")):
            raise Refusal("exchange", "The provider's token endpoint answered with a token of another kind")
        return said

    async def userinfo(self, provider: Provider, settings: OidcSettings, access_token: Any, sub: str) -> dict[str, Any]:
        """What the provider's userinfo endpoint says of this person: its `sub` has to be the ID token's (Core 5.3.4)."""
        if provider.userinfo_endpoint is None or not isinstance(access_token, str) or not 0 < len(access_token) <= 16384 or not access_token.isprintable():
            return {}
        reply = await self._get(provider.userinfo_endpoint, settings, MOST_TOKENS, "The provider's userinfo endpoint", {"Authorization": f"Bearer {access_token}"})
        if reply.status != 200:
            raise Refusal("userinfo", f"The provider's userinfo endpoint answered HTTP {reply.status}")
        if reply.headers.get("content-type", "").split(";")[0].strip().lower() == "application/jwt":
            raise Refusal("userinfo", "The provider's userinfo endpoint answers signed (application/jwt), which this program does not read: have it answer JSON")
        said = _object(reply.body, "the provider's userinfo endpoint")
        if said.get("sub") != sub:
            raise Refusal("userinfo", "The provider's userinfo endpoint speaks of somebody else (sub)")
        return said


class Verifier:
    """The ID token, checked in full against the provider's keys and this sign-in."""

    def __init__(self, client: Client) -> None:
        self._client = client

    async def checked(self, token: Any, provider: Provider, settings: OidcSettings, nonce: str, now: float | None = None) -> dict[str, Any]:
        header, claims, signing_input, signature = _parts(token)
        alg, kid = _header(header)
        keys = await self._client.keys(provider, settings, kid)
        if not any(key.kid == kid for key in keys):
            raise Refusal("key", "The ID token names a key the provider's set does not have (kid)")
        if not _signed(alg, keys, kid, signing_input, signature):
            raise Refusal("signature", "The ID token's signature is not the provider's")
        return claims_checked(claims, issuer=provider.issuer, client=settings.client_id, nonce=nonce, now=time.time() if now is None else now)
