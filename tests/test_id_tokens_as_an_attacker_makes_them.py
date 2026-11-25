"""What an ID token is held to before anybody is let in on it (oidc.Verifier), refusal by refusal: each made as somebody
who wants in would make it, and handed to the wall the whole way, by the stand-in provider's token endpoint after a sign-in
that was begun on the wall as a real one is. Each is refused with its own word, said in the activity log, and lets nobody in.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import oidc
from tests.fake_oidc import CLIENT, FakeIdp, SigningKey, b64, hs256_with, token_of
from tests.test_signing_in_through_an_identity_provider import ROLES, entries, fast, idp, refused_as, set_up, signed_in_by, stranger  # noqa: F401  (fixtures, by name)
from tests.test_wall import wall

Case = Callable[[FakeIdp], None]


def header(**said: Any) -> Case:
    return lambda fake: setattr(fake, "tamper", lambda head, claims: head.update(said))


def claims(**said: Any) -> Case:
    return lambda fake: setattr(fake, "tamper", lambda head, body: body.update(said))


def without(name: str) -> Case:
    return lambda fake: setattr(fake, "tamper", lambda head, body: body.pop(name, None))


def now() -> int:
    return int(time.time())


def none_at_all(fake: FakeIdp) -> None:
    fake.tamper = lambda head, body: head.update(alg="none")
    fake.signed_as = lambda data: b""


def hs256_with_the_public_key(fake: FakeIdp) -> None:
    # The classic confusion: the provider's public key, which anybody can fetch, taken as an HMAC secret.
    fake.tamper = lambda head, body: head.update(alg="HS256")
    fake.signed_as = hs256_with(fake.signing.public_pem())


def a_key_of_nobodys(fake: FakeIdp) -> None:
    fake.signed_as = SigningKey.made("RS256").sign  # (under the kid of the provider's own key)


def a_signature_with_a_bit_changed(fake: FakeIdp) -> None:
    sign = fake.signing.sign
    fake.signed_as = lambda data: bytes([sign(data)[0] ^ 1]) + sign(data)[1:]


def a_key_the_token_carries(fake: FakeIdp) -> None:
    # Signed with a key of the sender's own, which the header carries (jwk) and points to (jku, x5u): never looked at.
    theirs = SigningKey.made("RS256", "theirs")
    fake.tamper = lambda head, body: head.update(kid="theirs", jwk=theirs.jwk(), jku="https://evil.example.org/keys", x5u="https://evil.example.org/x5u")
    fake.signed_as = theirs.sign


def a_key_the_token_carries_under_the_providers_kid(fake: FakeIdp) -> None:
    theirs = SigningKey.made("RS256", fake.signing.kid)
    fake.tamper = lambda head, body: head.update(jwk=theirs.jwk())
    fake.signed_as = theirs.sign


def es256_written_as_der(fake: FakeIdp) -> None:
    # ES256 is R and S, 32 bytes each (JWA 3.4): the DER a library makes by default is no such signature.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = fake.rotate("ES256")
    private = key.private
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    fake.signed_as = lambda data: private.sign(data, ec.ECDSA(hashes.SHA256()))


def an_rsa_key_too_small(fake: FakeIdp) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    small = SigningKey("small", "RS256", rsa.generate_private_key(65537, 1024))
    fake.keys = [*fake.keys, small]
    fake.signing = small


def an_ec_key_said_to_be_rsa(fake: FakeIdp) -> None:
    key = fake.rotate("ES256")
    fake.tamper = lambda head, body: head.update(alg="RS256", kid=key.kid)


def a_name_twice(fake: FakeIdp) -> None:
    # Two `sub` in one token, signed by the provider's own key: which of them a reader takes is up to the reader.
    key, claims_of = fake.signing, fake.claims_of

    def id_token(person: Any, nonce: str) -> str:
        text = json.dumps(claims_of(person, nonce))[:-1] + ', "sub": "admin"}'
        head = b64(json.dumps({"alg": key.alg, "typ": "JWT", "kid": key.kid}).encode())
        body = b64(text.encode())
        return f"{head}.{body}.{b64(key.sign(f'{head}.{body}'.encode('ascii')))}"

    fake.id_token = id_token  # type: ignore[method-assign]


def encrypted_instead(fake: FakeIdp) -> None:
    real = fake.id_token
    fake.id_token = lambda person, nonce: real(person, nonce) + ".AAAA.BBBB"  # type: ignore[method-assign]


def no_id_token(fake: FakeIdp) -> None:
    fake.answers = [(200, json.dumps({"access_token": "x", "token_type": "Bearer"}).encode())]


def a_redirect_from_the_token_endpoint(fake: FakeIdp) -> None:
    fake.answers = [(302, b"")]


def an_answer_larger_than_any(fake: FakeIdp) -> None:
    fake.answers = [(200, b'{"id_token": "' + b"a" * (oidc.MOST_TOKENS + 10) + b'"}')]


CASES: dict[str, tuple[Case, str]] = {
    "alg none": (none_at_all, "algorithm"),
    "HS256 with the provider's public key as its secret": (hs256_with_the_public_key, "algorithm"),
    "RS512, an algorithm not taken": (header(alg="RS512"), "algorithm"),
    "a kid the set does not have": (header(kid="not-in-the-set"), "key"),
    "no kid": (lambda fake: setattr(fake, "tamper", lambda head, body: head.pop("kid")), "key"),
    "signed by a key that is nobody's": (a_key_of_nobodys, "signature"),
    "a signature with a bit changed": (a_signature_with_a_bit_changed, "signature"),
    "a key the token carries, and names": (a_key_the_token_carries, "key"),
    "a key the token carries, under the provider's kid": (a_key_the_token_carries_under_the_providers_kid, "signature"),
    "ES256 written as DER": (es256_written_as_der, "signature"),
    "an RSA key of 1024 bits": (an_rsa_key_too_small, "key"),
    "an EC key used as RSA": (an_ec_key_said_to_be_rsa, "signature"),
    "another issuer": (claims(iss="https://evil.example.org/realms/team"), "issuer"),
    "another application": (claims(aud="another-client"), "audience"),
    "several audiences, and no azp": (claims(aud=[CLIENT, "another-client"]), "audience"),
    "several audiences, azp another's": (claims(aud=[CLIENT, "another-client"], azp="another-client"), "audience"),
    "one audience, azp another's": (claims(azp="another-client"), "audience"),
    "run out": (lambda fake: claims(exp=now() - int(oidc.LEEWAY) - 30)(fake), "expired"),
    "no exp": (without("exp"), "token"),
    "issued an hour ago": (lambda fake: claims(iat=now() - 3600, exp=now() + 300)(fake), "expired"),
    "issued in the future": (lambda fake: claims(iat=now() + int(oidc.LEEWAY) + 60)(fake), "not_yet"),
    "not valid before a time to come": (lambda fake: claims(nbf=now() + int(oidc.LEEWAY) + 60)(fake), "not_yet"),
    "exp written as a text": (lambda fake: claims(exp=str(now() + 300))(fake), "token"),
    "no nonce": (without("nonce"), "nonce"),
    "another nonce": (claims(nonce="a nonce of somebody else's sign-in"), "nonce"),
    "nobody (no sub)": (without("sub"), "token"),
    "of another type (an access token)": (header(typ="at+jwt"), "token"),
    "with extensions it insists on (crit)": (header(crit=["exp"]), "token"),
    "a name twice": (a_name_twice, "unreadable"),
    "encrypted (five parts)": (encrypted_instead, "token"),
    "no ID token at all": (no_id_token, "token"),
    "a redirect from the token endpoint": (a_redirect_from_the_token_endpoint, "exchange"),
    "an answer larger than any": (an_answer_larger_than_any, "unreadable"),
}


@pytest.fixture
def ready(tmp_path: Path, idp: FakeIdp) -> Iterator[tuple[TestClient, FakeIdp]]:  # noqa: F811
    with wall(tmp_path) as admin:
        set_up(admin)
        assert refused_as(signed_in_by(stranger(admin, 51100), idp, "olga")) == ""  # (a good one first: the keys are fetched)
        yield admin, idp


@pytest.mark.parametrize("name", list(CASES))
def test_a_token_made_wrong_lets_nobody_in(name: str, ready: tuple[TestClient, FakeIdp], monkeypatch: pytest.MonkeyPatch) -> None:
    admin, fake = ready
    monkeypatch.setattr(oidc, "KEYS_AGAIN_AFTER", 0.0)  # (a key put into the set by a case is fetched: what is refused is the token)
    case, code = CASES[name]
    case(fake)
    hers = stranger(admin, 51101)
    assert refused_as(signed_in_by(hers, fake, "olga")) == code
    assert hers.get("/api/v1/session").json()["authenticated"] is False and hers.get("/api/v1/wall").status_code == 401
    [failed] = [entry for entry in entries(admin, "login_failed") if entry.get("provider")]
    assert failed["why"] == code and failed["said"]
    exchanged = fake.at("/realms/team/token")[-1].body.decode()
    written = (admin.core.data_dir / "audit.log").read_text(encoding="utf-8")  # type: ignore[attr-defined]
    assert exchanged.split("code=", 1)[1].split("&", 1)[0] not in written  # (no code, token or verifier in the log)


def test_tokens_within_the_leeway_and_of_both_algorithms_are_taken(ready: tuple[TestClient, FakeIdp], monkeypatch: pytest.MonkeyPatch) -> None:
    admin, fake = ready
    monkeypatch.setattr(oidc, "KEYS_AGAIN_AFTER", 0.0)  # (the EC key turned over to is fetched at once)
    for port, case in enumerate(
        (
            claims(exp=now() - 60),  # (a clock a minute apart)
            claims(iat=now() + 60, nbf=now() + 60),
            claims(aud=[CLIENT, "another-client"], azp=CLIENT),
            claims(aud=[CLIENT]),
            lambda fake: fake.rotate("ES256"),
        ),
        start=51110,
    ):
        fake.tamper = fake.signed_as = None
        case(fake)
        assert refused_as(signed_in_by(stranger(admin, port), fake, "olga")) == "", port


def test_keys_turned_over_are_fetched_again_and_a_kid_nobody_has_only_so_often(ready: tuple[TestClient, FakeIdp], monkeypatch: pytest.MonkeyPatch) -> None:
    admin, fake = ready
    fetched = len(fake.at("/realms/team/keys"))  # (by the check of the settings as they were saved, and by the first sign-in)
    # A token that names a key nobody has: the set is not fetched again for it within KEYS_AGAIN_AFTER, however often.
    fake.tamper = lambda head, body: head.update(kid="nobodys")
    for port in (51120, 51121, 51122):
        assert refused_as(signed_in_by(stranger(admin, port), fake, "olga")) == "key"
    assert len(fake.at("/realms/team/keys")) == fetched
    # The provider turns its key over: a token under the new kid is taken once the set may be fetched again.
    fake.tamper = None
    fake.rotate("RS256")
    assert refused_as(signed_in_by(stranger(admin, 51123), fake, "olga")) == "key"  # (within the few minutes: not yet)
    monkeypatch.setattr(oidc, "KEYS_AGAIN_AFTER", 0.0)
    assert refused_as(signed_in_by(stranger(admin, 51124), fake, "olga")) == ""
    assert len(fake.at("/realms/team/keys")) == fetched + 1
    # ...and the old one, taken out of the set, signs nobody in once what the wall fetched is older than KEPT_FOR (an hour:
    # until then a key the set had is taken, as every library of OpenID Connect keeps a set for a while).
    old = fake.keys[0]
    fake.rotate("RS256", drop_old=True)
    fake.signing = old
    assert refused_as(signed_in_by(stranger(admin, 51125), fake, "olga")) == ""
    monkeypatch.setattr(oidc, "KEPT_FOR", 0.0)
    assert refused_as(signed_in_by(stranger(admin, 51126), fake, "olga")) == "key"
    assert len(fake.at("/realms/team/keys")) == fetched + 2


def test_a_set_of_keys_takes_only_keys_for_signing_of_the_two_kinds() -> None:
    good = SigningKey.made("RS256", "good").jwk()
    ec_key = SigningKey.made("ES256", "ec").jwk()
    assert [key.kid for key in oidc.keys_from({"keys": [good, ec_key]})] == ["good", "ec"]
    for wrong in (
        {"kty": "oct", "kid": "shared", "k": b64(b"a secret anybody may have")},  # a secret, not a public key
        {**good, "use": "enc"},
        {**good, "alg": "ES256"},
        {**good, "key_ops": ["encrypt"]},
        {**good, "kid": ""},
        {**good, "e": b64((2).to_bytes(1, "big"))},
        {**ec_key, "crv": "P-384"},
        {**ec_key, "x": b64(b"\x01" * 32)},  # (not on the curve)
        {**good, "n": "not base64url!"},
        "not a key",
    ):
        assert oidc.keys_from({"keys": [wrong]}) == [], wrong
    with pytest.raises(oidc.Refusal):
        oidc.keys_from({"no": "keys"})


def test_what_a_token_says_twice_or_in_parts_is_no_token() -> None:
    key = SigningKey.made("RS256", "k")
    made = token_of({"alg": "RS256", "kid": "k"}, {"sub": "x"}, key.sign)
    for wrong in (made + "=", made.replace(".", "..", 1), "a.b", 7, "", "x" * (oidc.MOST_TOKEN + 1), made[:-1] + "+"):
        with pytest.raises(oidc.Refusal):
            oidc._parts(wrong)
