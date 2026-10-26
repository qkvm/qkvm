"""Offline, restartable migration of legacy settings to external-key storage."""
from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
import secrets
import stat
from typing import Any

from .store import Store, _replace_settings, holds_nothing, sealed_beside
from .vault_storage import MAGIC, RECOVERY_MAGIC, StorageCipher, StorageError, create_key, key_path, read_key

ARCHIVE = "vault-migration.recovery"


def _settle(directory: Path) -> None:
    # Migration durability errors must be reported, not treated as a completed migration.
    # Windows has no folder to sync: there os.replace (MoveFileEx without MOVEFILE_WRITE_THROUGH) leaves the rename to
    # the file system's journal, which keeps it whole but may write it out a moment later. A power cut right after a
    # step can undo that step (the earlier complete file is in place), and the migration is run again.
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, data: bytes) -> None:
    temp = path.with_name(path.name + ".migration-" + secrets.token_hex(8))
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_settings(temp, path)
        _settle(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _read_archive(path: Path, cipher: StorageCipher) -> dict[str, bytes]:
    document = json.loads(cipher.open(path.read_bytes(), context=RECOVERY_MAGIC))
    if not isinstance(document, dict) or document.get("format") != 1 or not isinstance(document.get("files"), dict):
        raise StorageError("the migration recovery archive is invalid")
    files: dict[str, bytes] = {}
    for name, encoded in document["files"].items():
        # Names are never used as paths without validation, including when inspecting a restored archive.
        if not isinstance(name, str) or Path(name).name != name or "/" in name or "\\" in name or ":" in name:
            raise StorageError("the migration archive contains an invalid file name")
        files[name] = base64.b64decode(encoded, validate=True)
    return files


def migrate(data_dir: Path, selected_key: Path) -> dict[str, Any]:
    """Caller holds InstanceLock. Never starts listeners or asks for account passwords."""
    primary, backup = data_dir / "qkvm.json", data_dir / "qkvm.bak"
    selected = key_path(data_dir, selected_key)
    if not primary.exists() and not backup.exists():
        raise StorageError("there is no existing vault to migrate; start a new server normally")
    archive = data_dir / ARCHIVE
    for file in (primary, backup, archive, *data_dir.glob("qkvm.damaged-*.json"), data_dir / "qkvm.tmp", data_dir / "qkvm.bak.new"):
        if file.is_symlink():
            raise StorageError("migration refuses linked settings or recovery files")
        if file.exists():
            found = file.lstat()
            if not stat.S_ISREG(found.st_mode) or found.st_nlink != 1:
                raise StorageError("migration requires regular, unlinked settings files")
    # Validate every legacy field before making a key or replacing a settings file.
    original = Store(primary, vault_key_file=selected, read_only=True)
    before = original.snapshot()
    current_protected = primary.exists() and primary.read_bytes().startswith(MAGIC)
    # Run again after it was cut off, the recovery archive it wrote is here: its key is asked for, never made anew where
    # the real one is to go (a new one was made, the archive then could not be opened, and the new key stayed behind).
    # Every leftover is read before a key is made or asked for: one that cannot be read was taken for one that may be
    # sealed, and a first migration then asked for a key that never was, without naming the file.
    for remnant in (*data_dir.glob("qkvm.damaged-*.json"), data_dir / "qkvm.tmp", data_dir / "qkvm.bak.new", archive):
        if remnant.is_file():
            try:
                remnant.read_bytes()
            except OSError as ex:
                raise StorageError(f"{remnant.name} in the data folder cannot be read ({ex.strerror or ex}): give the account "
                                   "qKVM runs as access to it, or move it out of the folder, and run this again") from None
    key = read_key(selected) if current_protected or sealed_beside(data_dir) else create_key(selected)
    cipher = StorageCipher(key)
    # What a power cut left of a write holds nothing (store.holds_nothing): it is neither legacy input to archive nor a
    # change since the archive was made. It is taken away at the end, and an empty second copy is written anew below.
    every = [*data_dir.glob("qkvm.damaged-*.json"), data_dir / "qkvm.tmp", data_dir / "qkvm.bak.new"]
    empty_left = [p for p in (backup, *every) if p.exists() and holds_nothing(p.read_bytes())]
    # A damaged file a start set aside sealed (Store._load) is inside the vault: no plaintext remnant to archive or remove,
    # and the copy kept for diagnosis. It was counted as one, and a migration run again refused or tried to remove it.
    remnants = [p for p in every if p not in empty_left and not (p.exists() and p.read_bytes().startswith(MAGIC))]
    source = {p.name: p.read_bytes() for p in (primary, backup, *remnants) if p.exists() and p not in empty_left}
    if archive.exists():
        captured = _read_archive(archive, cipher)
    elif current_protected:
        # Already-protected data is not a new legacy migration. Do not erase unexplained remnants.
        if any(p.exists() for p in remnants):
            raise StorageError("settings remnants need a verified migration recovery archive before cleanup")
        captured = {}
    else:
        captured = source
        encoded = json.dumps({"format": 1, "files": {name: base64.b64encode(raw).decode("ascii") for name, raw in captured.items()}}).encode("ascii")
        _write(archive, cipher.seal(encoded, context=RECOVERY_MAGIC))
        if _read_archive(archive, cipher) != captured:
            raise StorageError("the migration recovery archive could not be verified")
    # A restart uses the original capture. Changed plaintext is never discarded or called safely archived.
    for name, raw in source.items():
        if not raw.startswith(MAGIC) and captured.get(name) != raw:
            raise StorageError("legacy settings changed since the recovery archive was made; preserve both and investigate before migration")
    encoded = cipher.encode(before)
    if cipher.decode(encoded) != before:
        raise StorageError("the protected vault failed its pre-write verification")
    # Backup first: after the primary commits, an older binary has no plaintext fallback.
    _write(backup, encoded)
    _write(primary, encoded)
    checked = Store(primary, vault_key_file=selected, read_only=True)
    if checked.snapshot() != before or backup.read_bytes() != primary.read_bytes():
        raise StorageError("the migrated primary and backup could not be verified")
    leftover = []
    for path in empty_left:
        if path == backup or not path.exists() or not holds_nothing(path.read_bytes()):
            continue  # (the second copy was written anew above; anything written meanwhile is not taken away)
        try:
            path.unlink()
        except OSError:
            leftover.append(path.name)
    for path in remnants:
        if not path.exists():
            continue
        if captured.get(path.name) != path.read_bytes():
            leftover.append(path.name)
            continue
        try:
            path.unlink()
        except OSError:
            leftover.append(path.name)
    _settle(data_dir)
    if leftover:
        raise StorageError("vault migrated, but archived plaintext remnants could not be removed: " + ", ".join(leftover))
    return {"protected": True, "accounts": len(checked.users), "devices": len(checked.devices),
            "recovery_archive": archive.name if archive.exists() else None, "already_protected": current_protected}


def verify(data_dir: Path, selected_key: Path) -> dict[str, Any]:
    """Read-only paired restore verification; no live-device traffic or credential output."""
    selected = key_path(data_dir, selected_key)
    if not (data_dir / "qkvm.json").exists() or not (data_dir / "qkvm.bak").exists():
        raise StorageError("both protected settings copies are required for verification")
    store = Store(data_dir / "qkvm.json", vault_key_file=selected, protected=True, read_only=True)
    cipher = StorageCipher(read_key(selected))
    if holds_nothing(store.backup.read_bytes()):
        # (What a power cut leaves of the copy: verification changes nothing, and a start writes it anew.)
        raise StorageError("the second copy of the settings (qkvm.bak) holds nothing, as an interrupted write leaves it: start qKVM once, which writes it anew, then verify again")
    if cipher.decode(store.path.read_bytes()) != cipher.decode(store.backup.read_bytes()):
        raise StorageError("the primary and backup do not contain the same settings")
    archive = data_dir / ARCHIVE
    if archive.exists():
        _read_archive(archive, cipher)
    for path in [*data_dir.glob("qkvm.damaged-*.json"), data_dir / "qkvm.tmp", data_dir / "qkvm.bak.new"]:
        if path.exists() and not (raw := path.read_bytes()).startswith(MAGIC) and not holds_nothing(raw):
            raise StorageError("an unprotected settings remnant remains: " + path.name)
    return {"protected": True, "accounts": len(store.users), "devices": len(store.devices), "recovery_archive_verified": archive.exists()}


def configure(data_dir: Path, selected_key: Path, source: Path) -> dict[str, Any]:
    """Offline replacement for documented hand edits, restricted to non-secret server settings."""
    with source.open("rb") as stream:
        raw = stream.read(16_385)
    if len(raw) > 16_384:
        raise StorageError("the server settings input exceeds 16 KiB")
    try:
        changes = json.loads(raw)
    except (ValueError, RecursionError):
        raise StorageError("server settings must be a JSON object") from None
    limits = {"history_days": (1, 3650), "history_mb": (10, 100000), "activity_mb": (10, 100000)}
    if not isinstance(changes, dict) or not changes or set(changes) - {"allowed_hosts", *limits}:
        raise StorageError("only allowed_hosts, history_days, history_mb and activity_mb can be configured here")
    for name, value in changes.items():
        if name == "allowed_hosts":
            if not isinstance(value, list) or len(value) > 100 or any(
                not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,252}", host) for host in value
            ):
                raise StorageError("allowed_hosts must be a list of at most 100 host names, without URLs, ports or wildcards")
            changes[name] = list(dict.fromkeys(host.lower().rstrip(".") for host in value))
        elif type(value) is not int or (value != 0 and not limits[name][0] <= value <= limits[name][1]):
            raise StorageError(f"{name} must be 0 (default) or an integer between {limits[name][0]} and {limits[name][1]}")
    verify(data_dir, selected_key)  # refuse missing, mixed or damaged data before writing anything
    store = Store(data_dir / "qkvm.json", vault_key_file=selected_key, protected=True)
    for name, value in changes.items():
        setattr(store.server, name, value)
    store.save()
    return verify(data_dir, selected_key)
