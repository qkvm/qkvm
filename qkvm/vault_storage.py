"""Authenticated settings encryption with a server key outside the data directory.

Account passwords and the legacy inner data key cannot open this envelope. The
storage key must be backed up separately and is never reconstructed from a login.
"""
from __future__ import annotations

import base64
from collections.abc import Iterator
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
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
    opened = _as_windows_opens(selected.name)
    if opened == LOCK_NAME or PART.fullmatch(opened):
        # (Named as what qKVM keeps beside a key while it makes one, it could be taken away with that: the outside review 6.2 narrow look at
        # the third re-check's fixes, HIGH 1. Judged as Windows opens the name: ".qkvm-key-<hex>.part." was the file a key is written
        # into, and the next first key made in its folder took it away for good. The review of Z2, L2.)
        raise StorageError(f"the vault key file may not be named {selected.name}: qKVM keeps a file of that name beside a key while it makes one. Choose another name with --vault-key-file")
    if lies_in(selected, data_dir):
        raise StorageError("the vault key file must be outside the data directory and its backups")
    return selected.absolute()


def _as_windows_opens(name: str) -> str:
    """A file's name as Windows opens it, in any letter case: up to a ":" (what follows names a stream of that file,
    "::$DATA" its own data), and without the dots and spaces it ends in. Judged so on every system: a key folder may be on
    a volume Windows opens, or be carried to one."""
    return name.split(":", 1)[0].rstrip(". ").lower()


def _regular_private(path: Path) -> None:
    found = path.lstat()
    if not stat.S_ISREG(found.st_mode) or path.is_symlink() or found.st_nlink != 1:
        raise StorageError("the vault key must be a regular private file, not a link")
    if sys.platform != "win32":
        if found.st_uid != os.getuid() or found.st_mode & 0o077:
            raise StorageError("the vault key must belong to the server account and have permissions 0600 or 0400")
    elif os.name == "nt":
        from ._folders import keeps_no_permissions
        from ._vault_windows import validate_private

        # (On a drive that keeps no permissions, FAT or exFAT, there is no owner or ACL to judge: said at every start, not
        # refused. The round 5 review, M3.)
        if keeps_no_permissions(path) is None:
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
    return make_key(path)[0]


# The file a key is written into before it is put in its place (make_key): `.qkvm-key-<16 hex>.part` beside it, of one short
# length whatever the key's own name (named after the key, 23 bytes longer, a key named near the longest a folder takes could
# not be made at all: the outside review 6.2 third re-check, M2). No key may be named so, nor as the lock (key_path).
PART = re.compile(r"\.qkvm-key-[0-9a-f]{16}\.part")


def _parts_of(path: Path) -> list[Path]:
    """The files keys are written into beside `path` (PART), of that form exactly (`.vault.key.standby.part` is no such file:
    another wall's key may be called so)."""
    try:
        return [entry for entry in path.parent.iterdir() if PART.fullmatch(entry.name)]
    except OSError:
        return []


LOCK_NAME = ".qkvm-key.lock"  # beside a key once one was made there (_making_here)
LOCK_WAIT = 30.0  # seconds another one making a key in that folder is waited for


@contextlib.contextmanager
def _making_here(folder: Path) -> Iterator[bool]:
    """One process at a time makes a key in this folder: True while this one does. Two restores making the first key of one
    place at once took each other's file for a stopped one's leavings, or found the other's key with two names for a moment
    and refused it as a link (the outside review 6.2 third re-check, M1 and its bugs round). False where the volume takes no lock at
    all: nothing is waited for, and nothing left beside the key is taken away. On Linux and macOS its file stays, empty and the
    server's alone: only the lock on it is let go of, and a file of that name that was there is never taken away (one taken
    away as the lock was let go of could have been an operator's: the outside review 6.2 narrow look at the third re-check's fixes,
    HIGH 1). On Windows each one makes a file of its own, never one that was there, which goes as it is closed (also by a
    process that stopped dead)."""
    place = folder / LOCK_NAME
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        if sys.platform == "win32":
            try:
                descriptor = os.open(place, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_TEMPORARY | os.O_NOINHERIT | os.O_BINARY)
                break
            except (FileExistsError, PermissionError):
                pass  # (held by another, or going as it was let go of)
        else:
            import fcntl

            descriptor = os.open(place, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
            except OSError:
                os.close(descriptor)
                yield False
                return
            else:
                try:
                    here = os.path.samestat(os.fstat(descriptor), place.lstat())
                except FileNotFoundError:
                    here = False
                if here:
                    break
                os.close(descriptor)  # (a file taken away meanwhile: the lock is on no name any more)
        if time.monotonic() > deadline:
            raise StorageError(f"another qKVM has been making a vault key in {folder} for {LOCK_WAIT:.0f} seconds; try again")
        time.sleep(0.02)
    try:
        yield True
    finally:
        os.close(descriptor)


def _two_names(path: Path) -> bool:
    """Whether the file at `path` has another name too (a key between the two steps of its putting in place by another, which
    the one holding the folder sees through: _published)."""
    try:
        return path.lstat().st_nlink > 1
    except OSError:
        return False


def _published(path: Path, held: bool) -> bytes:
    """The key in its place, made by another: read as it is, where a second name of its own file that a publication had not
    taken away yet (one of _parts_of that is this file) is taken away first, only while this one holds the folder (`held`:
    _making_here): nothing of anybody's goes with it."""
    with contextlib.suppress(OSError):
        if held and path.lstat().st_nlink == 2:
            for part in _parts_of(path):
                if os.path.samefile(part, path):
                    part.unlink()
    return read_key(path)


def make_key(path: Path) -> tuple[bytes, bool]:
    """create_key, and whether this call made the key file (False: one was there, made by another, and is read).

    The key is written whole into a private file of its own beside its place, synced, and only then put in its place, where
    nothing is there by then (never over another): stopped at any moment, it leaves either no key there or a whole one, never
    one cut short, which a retry would refuse as none (the outside review 6.2 second re-check, M4). One process at a time makes a key in
    a folder (_making_here), and takes away nothing there but its own file and what one that stopped dead left of that form.
    Where the volume takes no second name of a file (a hard link), or shows the file to others whatever is asked, no key is
    made: refused before any key is written (the outside review 6.2 narrow look at the third re-check's fixes, HIGH 2 and 3)."""
    if (path.exists() or path.is_symlink()) and not _two_names(path):
        return _published(path, held=False), False
    if sys.platform == "win32":
        # Its folder its owner's alone from its first instant, on every Python (before 3.12.4 mkdir ignores the mode on
        # Windows): whoever may change the folder can take the key away, or put another in its place.
        from ._folders import keeps_no_permissions, not_alone, private_folder

        private_folder(path.parent)
        # One that is found is used as it is found, and judged as on Linux: no key is made where another account may take it
        # away or put another in its place (the round 4 review, L5). Not on a drive that keeps no permissions at all (FAT,
        # exFAT), where no setting changes that: said at every start, not refused (the round 5 review, M3).
        if (why := not_alone(path.parent)) is not None and keeps_no_permissions(path.parent) is None:
            raise StorageError(f"the vault key directory must belong to the server and not be writable by others ({path.parent} {why})")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise StorageError("the vault key directory must belong to the server and not be writable by others")
    with _making_here(path.parent) as alone:
        if path.exists() or path.is_symlink():
            return _published(path, alone), False  # (made by another while this one waited: whole, it held the folder until then)
        if alone:
            # What one that was stopped dead as it made a key here left: every one alive holds the folder while its file is
            # there. (Nothing is taken away where the volume takes no lock: it may be another's, being written.)
            for left in _parts_of(path):
                with contextlib.suppress(OSError):
                    left.unlink()
        key = AESGCM.generate_key(256)
        record = KEY_MAGIC + key.hex().encode("ascii") + b"\n"
        part = path.with_name(f".qkvm-key-{os.urandom(8).hex()}.part")
        if os.name == "nt":
            from ._vault_windows import create_private
            descriptor = create_private(part)
        else:
            descriptor = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if sys.platform != "win32":
                # Private as read_key will ask, on the open file, before any key is in it: a volume that shows every file to
                # others (a FAT or exFAT mount) left a whole key there, refused only once it was in its place (HIGH 3).
                made = os.fstat(descriptor)
                if made.st_uid != os.getuid() or made.st_mode & 0o077:
                    os.close(descriptor)
                    raise StorageError(
                        f"the vault key would not be private in {path.parent}: its volume lets other accounts read the files on it, whatever "
                        "qKVM asks (a FAT or exFAT mount, say). No key was made: choose a folder on another volume with --vault-key-file"
                    )  # fmt: skip
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(record)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                if os.name == "nt":
                    os.rename(part, path)  # (refused where a file is there by then: never put over one)
                else:
                    os.link(part, path)  # (likewise; its second name goes below)
            except FileExistsError:
                return _published(path, alone), False  # (made by another meanwhile, one that took no lock: that one is the key)
            except OSError as ex:
                if os.name == "nt":
                    raise
                # A volume that takes no second name of a file (EPERM, EOPNOTSUPP, ENOSYS, EXDEV, ... on exFAT, FAT, some network
                # shares): no key is made at all, and none was put in its place (written there itself, it was there before it was
                # whole and synced, and could be cut short or taken up by another restore meanwhile: HIGH 2).
                raise StorageError(
                    f"the vault key could not be put in its place in {path.parent} ({ex.strerror or ex}): the folder of the vault key "
                    "must be on a volume that takes hard links on this system. No key was made: choose another place with --vault-key-file"
                ) from None
        finally:
            # (Whole or not, its own name goes: a disk full as it was written left no key, and the next try, once there was room,
            # makes one. The outside review 6.2 re-check, R5.)
            with contextlib.suppress(OSError):
                part.unlink()  # (where it would not go, the key with two names is refused below as no key, and the next try takes it away)
        # The caller also syncs its settings directory; this sync keeps key creation durable first.
        if sys.platform != "win32":
            descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if read_key(path) != key:
            raise StorageError("the saved vault key could not be verified")
    return key, True


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
