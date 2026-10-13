"""Password-derived encryption for the secrets the wall stores.

The admin password is never stored. scrypt turns it into a key that wraps a
random data key, and the data key encrypts each KVM password. Unwrapping the
data key doubles as the password check, so the file on disk is useless without
the password.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N = 2**17  # ~130 MB and a few hundred milliseconds per guess
SCRYPT_R = 8
SCRYPT_P = 1
# Part of the stored format: changing it would make every existing data folder impossible to unlock.
_KEY_CONTEXT = "kvm-wall data key"


class VaultLocked(Exception):
    """A secret was needed before anyone logged in."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class NotARecord(ValueError):
    """What was handed over as a record is none that anything opens. (Not: the work of opening it could not be done.)"""


class NoMemory(Exception):
    """The work of checking a password could not be done: the memory it takes was not to be had.

    An error of its own, and no ValueError: that is what a damaged secret is, a text that is none, and much
    else that has nothing to do with memory, and all of it was answered and written down as "no memory".
    """


def _derive(password: str, kdf: dict[str, Any]) -> bytes:
    try:
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        salt = base64.b64decode(kdf["salt"])
        # No more work than twice what this program itself asks for (n * r * p of 2**20: a third of a second
        # and 130 MB). What the file says is what every check of a password costs, and the file can be
        # edited: at the most that used to be let through, a check took nine seconds and a gigabyte.
        fits = kdf.get("name") == "scrypt" and 2**10 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4 and n * r * p <= 2**21
        fits = fits and n < 2 ** (16 * r)  # (what the work itself insists on, said here, where it is a record that is wrong)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as ex:  # (OverflowError: a number written as 1e999)
        raise NotARecord("not key derivation settings") from ex
    if not fits:
        raise NotARecord("unsupported key derivation settings")
    secret = password.encode("utf-8")
    # What goes wrong from here on is the work itself not getting done, and is nobody's wrong password: it
    # is not caught as one. (The numbers were looked at above and any salt will do, so what is left is the
    # memory: Python's own error for that, or the library's, which comes as a ValueError.)
    try:
        return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=256 * n * r)
    except (MemoryError, ValueError) as ex:
        raise NoMemory(f"{type(ex).__name__}: {ex}") from ex


def _seal(key: bytes, plaintext: bytes, context: str) -> dict[str, str]:
    nonce = os.urandom(12)
    return {"nonce": _b64(nonce), "data": _b64(AESGCM(key).encrypt(nonce, plaintext, context.encode()))}


def _open(key: bytes, blob: dict[str, str], context: str) -> bytes:
    return AESGCM(key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["data"]), context.encode())


def new_recovery_key() -> str:
    """A random key for the owner to keep somewhere safe: 160 bits, as eight groups of four characters."""
    raw = base64.b32encode(os.urandom(20)).decode("ascii")
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def tidy_recovery_key(text: str) -> str:
    """The key as it was issued, however it was typed: any case, with or without dashes and spaces.

    The alphabet has no 0, 1 or 8, so those can only be a misread O, I or B.
    """
    return "".join(ch for ch in text.upper().translate(str.maketrans("018", "OIB")) if ch.isalnum())


class Vault:
    def __init__(self) -> None:
        self._key: bytes | None = None

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultLocked("the vault is locked")
        return self._key

    def create(self, password: str) -> dict[str, Any]:
        """Start a new vault, leave it unlocked, and return the record to store."""
        self._key = AESGCM.generate_key(256)
        return self.rewrap(password)

    def rewrap(self, password: str) -> dict[str, Any]:
        """Record that lets `password` unlock the current data key."""
        key = self._require_key()
        kdf = {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(os.urandom(16))}
        return {"kdf": kdf, "key": _seal(_derive(password, kdf), key, _KEY_CONTEXT)}

    @staticmethod
    def open(record: dict[str, Any], password: str) -> bytes | None:
        """The data key if `password` is right, else None. Slow by design; run it off the event loop.

        None as well for a record that nothing opens: one that was edited into something else, or is not a
        record at all. Whoever asks is asking whether this password opens it, and it does not.

        Not None, but the error itself, where the check could not be made: the 130 MB it takes were not to
        be had. Answered as "wrong", the right password was refused five times and its owner locked out,
        with nothing in the log to say why.
        """
        try:
            derived = _derive(password, record["kdf"])
        except (NotARecord, KeyError, TypeError):
            return None
        try:
            return _open(derived, record["key"], _KEY_CONTEXT)
        except (InvalidTag, KeyError, TypeError, ValueError):
            return None

    def adopt(self, key: bytes) -> None:
        self._key = key

    def lock(self) -> None:
        self._key = None

    def mark(self, text: str, context: str) -> str:
        """What can be kept of `text` to know it again by, and is of no use to whoever has the file but not the key.

        For secrets too short to be kept as a plain hash: forty random bits are tried through in minutes.
        """
        key = hmac.new(self._require_key(), f"qkvm mark:{context}".encode(), hashlib.sha256).digest()
        return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def encrypt(self, text: str, context: str) -> dict[str, str]:
        """Encrypt `text`; `context` (the device id) ties the result to its owner."""
        return _seal(self._require_key(), text.encode("utf-8"), context)

    def decrypt(self, blob: dict[str, str], context: str) -> str:
        return _open(self._require_key(), blob, context).decode("utf-8")

    def read(self, blob: Any, context: str) -> str | None:
        """What a saved secret holds, or None where it does not open. VaultLocked where nothing opens just now.

        It does not open where it was sealed under a key from before a reset, and where it is not what this
        program writes: a settings file that was edited by hand, or damaged. Both are "nothing is saved" to
        whoever asks, here in one place: asked for with `decrypt` and only the first kind caught, one damaged
        device password was an error at every start of the wall, and the wall did not start.
        """
        key = self._require_key()
        try:
            return _open(key, blob, context).decode("utf-8")
        except (InvalidTag, KeyError, TypeError, ValueError):  # (what is no text, and what is no base64, are ValueErrors)
            return None
