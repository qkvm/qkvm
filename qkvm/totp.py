"""Time-based one-time codes (RFC 6238), as authenticator apps make them."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30  # seconds a code is shown for
DIGITS = 6
ONE_TIME_CODES = 10  # handed out when the second step is switched on, each good for one sign-in


def new_one_time_codes() -> list[str]:
    """Codes that each stand in, once, for a code from the app: for a phone that is lost, broken or at home."""
    made = [secrets.token_hex(5) for _ in range(ONE_TIME_CODES)]  # 40 random bits each, behind the lock on wrong guesses
    return [f"{code[:5]}-{code[5:]}" for code in made]


def as_issued(code: str) -> str:
    """A one-time code as it was made, however it was typed: any case, with or without the dash or spaces."""
    return "".join(ch for ch in code.lower() if ch.isalnum())


def new_secret() -> str:
    """A fresh key, in the base32 spelling authenticator apps take."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def code_at(secret: str, step: int) -> str:
    """The code an app holding `secret` shows during time step `step`."""
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step `code` belongs to, if it is the current one or a neighbour; else None.

    A neighbour is accepted because phones and servers rarely agree on the time to the second.
    """
    digits = "".join(ch for ch in code if ch in "0123456789")  # not isdigit(): that takes digits of other scripts too
    if len(digits) != DIGITS:
        return None
    current = int((time.time() if now is None else now) // STEP)
    found = None
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(code_at(secret, step), digits):  # every candidate is compared: no early exit
            found = step
    return found


def setup_uri(secret: str, account: str, issuer: str = "qKVM") -> str:
    """What an authenticator app opens (or reads from a QR code) to add the account."""
    # Algorithm, digits and period are left out: they are every app's defaults, and a shorter
    # address makes a QR code that is easier to scan.
    return f"otpauth://totp/{quote(f'{issuer}:{account}')}?secret={secret}&issuer={quote(issuer)}"


def spaced(secret: str) -> str:
    """The key in groups of four, which is easier to type."""
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
