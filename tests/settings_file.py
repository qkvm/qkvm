"""Explicit access to the inner settings document for validation/fault-injection tests.

These helpers do not alter application behavior or bypass its storage checks.
Tests of the envelope, migration, copying and missing keys use raw file I/O.
Legacy fixtures without an external key remain legacy fixtures.
"""
from __future__ import annotations

from pathlib import Path
import re

from qkvm.vault_storage import MAGIC, StorageCipher, key_path, read_key

_SETTINGS = re.compile(r"qkvm\.(?:json|bak|tmp|bak\.new|damaged-.*\.json)\Z")


def settings_text(path: Path, encoding: str = "utf-8", errors: str | None = None) -> str:
    raw = path.read_bytes()
    if raw.startswith(MAGIC):
        raw = StorageCipher(read_key(key_path(path.parent))).open(raw)
    return raw.decode(encoding, errors or "strict")


def write_settings_text(path: Path, text: str, encoding: str = "utf-8", errors: str | None = None) -> int:
    raw = text.encode(encoding, errors or "strict")
    # Nothing, or zeros only, is written as it is: what a power cut leaves of a write is never an envelope, and sealed
    # here it hid from the tests the start that such a file locked out (the review of 850745e, W3).
    if _SETTINGS.fullmatch(path.name) and not raw.startswith(MAGIC) and raw.strip(b"\0"):
        selected = key_path(path.parent)
        if selected.exists():
            raw = StorageCipher(read_key(selected)).seal(raw)
    path.write_bytes(raw)
    return len(text)
