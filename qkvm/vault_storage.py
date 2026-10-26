"""Authenticated settings encryption with a server key outside the data directory.

Account passwords and the legacy inner data key cannot open this envelope. The
storage key must be backed up separately and is never reconstructed from a login.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .unlock import lies_in

MAGIC = b"QKVM-VAULT-2\n"
RECOVERY_MAGIC = b"QKVM-VAULT-MIGRATION-1\n"
KEY_MAGIC = b"QKVM-STORAGE-KEY-1:"
MAX_BYTES = 64 * 1024 * 1024


class StorageError(ValueError):
    """The protected settings or their required key cannot be used safely."""


class UnsupportedFormat(StorageError):
    """A newer protected format must not silently fall back to an older backup."""


class MigrationRequired(StorageError):
    """Legacy settings must be migrated explicitly while the server is stopped."""


def key_path(data_dir: Path, selected: Path | None = None) -> Path:
    if selected is None:
        root = data_dir.resolve()
        if not root.name:
            raise StorageError("a vault key file outside the data directory must be specified")
        selected = root.with_name(root.name + ".keys") / "vault.key"
    if lies_in(selected, data_dir):
        raise StorageError("the vault key file must be outside the data directory and its backups")
    return selected.absolute()


def _regular_private(path: Path) -> None:
    found = path.lstat()
    if not stat.S_ISREG(found.st_mode) or path.is_symlink() or found.st_nlink != 1:
        raise StorageError("the vault key must be a regular private file, not a link")
    if sys.platform != "win32":
        if found.st_uid != os.getuid() or found.st_mode & 0o077:
            raise StorageError("the vault key must belong to the server account and have permissions 0600 or 0400")
    elif os.name == "nt":
        from ._vault_windows import validate_private
        validate_private(path)


def read_key(path: Path) -> bytes:
    try:
        _regular_private(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before, opened = path.lstat(), os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise StorageError("the vault key file changed while opening it")
            raw = stream.read(257)
        if len(raw) > 256 or not raw.startswith(KEY_MAGIC) or len(raw.strip()) != len(KEY_MAGIC) + 64:
            raise StorageError("the vault key file is not a qKVM storage key")
        key = bytes.fromhex(raw[len(KEY_MAGIC):].decode("ascii").strip())
        if len(key) != 32:
            raise StorageError("the vault key has the wrong length")
        return key
    except FileNotFoundError:
        raise StorageError("the vault key file is missing; restore the original key from its separate backup") from None
    except (UnicodeError, ValueError) as ex:
        if isinstance(ex, StorageError):
            raise
        raise StorageError("the vault key file is invalid") from None


def create_key(path: Path) -> bytes:
    """Persist a private key before any vault data is replaced; never replace an existing key."""
    if path.exists() or path.is_symlink():
        return read_key(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise StorageError("the vault key directory must belong to the server and not be writable by others")
    key = AESGCM.generate_key(256)
    try:
        if os.name == "nt":
            from ._vault_windows import create_private
            descriptor = create_private(path)
        else:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return read_key(path)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(KEY_MAGIC + key.hex().encode("ascii") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    # The caller also syncs its settings directory; this sync keeps key creation durable first.
    if sys.platform != "win32":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if read_key(path) != key:
        raise StorageError("the saved vault key could not be verified")
    return key


class StorageCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise StorageError("a 256-bit server storage key is required")
        self._cipher = AESGCM(key)

    def seal(self, plaintext: bytes, *, context: bytes = MAGIC) -> bytes:
        if len(plaintext) > MAX_BYTES:
            raise StorageError("the vault exceeds the supported size")
        nonce = os.urandom(12)
        sealed = self._cipher.encrypt(nonce, plaintext, context)
        return context + base64.b64encode(nonce + sealed) + b"\n"

    def open(self, data: bytes, *, context: bytes = MAGIC) -> bytes:
        if not data.startswith(context) or len(data) > MAX_BYTES * 2:
            raise StorageError("unsupported or damaged protected vault format")
        try:
            payload = base64.b64decode(data[len(context):].rstrip(b"\n"), validate=True)
            if len(payload) < 28:
                raise ValueError("short envelope")
            return self._cipher.decrypt(payload[:12], payload[12:], context)
        except (InvalidTag, ValueError):
            raise StorageError("the vault cannot be authenticated with this key; restore the matching data and key backups") from None

    def encode(self, data: dict[str, Any]) -> bytes:
        return self.seal(json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False).encode("utf-8"))

    def decode(self, data: bytes) -> dict[str, Any]:
        result = json.loads(self.open(data))
        if not isinstance(result, dict):
            raise StorageError("the protected settings are not an object")
        return result
