"""Automatic unlocking of the inner credential key after server startup.

The complete settings file always needs its independent external storage key
(vault_storage.py). The choices here control the additional inner lock:

* own_secret: an automatic-unlock secret in the data folder;
* --unlock-file: that automatic-unlock secret outside the data folder;
* --locked-start: no automatic-unlock secret; a successful account sign-in is required.

None of these secrets, nor an account password, replaces the external storage key.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path

SHORTEST = 32  # characters; a secret that somebody made up themselves is refused below this
LONGEST = 4096  # bytes; a secret is a line, not whatever file the option happened to be pointed at
OWN = "unlock.key"  # the key qKVM keeps for itself, in the data folder


def own_secret(data_dir: Path) -> str:
    """The key qKVM keeps in its data folder to carry on by itself after a restart. Made if it is not there.

    For its owner alone, and never over a file that appeared in the meantime. OSError: none could be kept
    (a folder that cannot be written to), and then qKVM starts as with --locked-start.
    """
    path = data_dir / OWN
    for _ in range(2):
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "w", encoding="ascii") as fh:
                fh.write(secrets.token_urlsafe(32) + "\n")
        try:
            secret = path.read_bytes()[:LONGEST].decode("ascii").strip()
        except UnicodeDecodeError:
            secret = ""
        if len(secret) >= SHORTEST:
            return secret
        path.unlink()  # not a key (cut short by a full disk, say): another is made, and fits at the next sign-in
    raise OSError(errno.EIO, "no key could be kept", str(path))


def forget_own(data_dir: Path) -> None:
    """Take qKVM's own key out of the data folder: it was started with a key kept elsewhere, or with none.

    Raises OSError where it can be neither removed nor emptied: it then still lies there, and still opens
    whatever copy of the settings it fits. Whoever asked for it to be gone has to hear of that.
    """
    path = data_dir / OWN
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        with open(path, "w", encoding="ascii"):  # emptied, it is no key any more
            pass


def lies_in(path: Path, folder: Path) -> bool:
    """Whether `path` is somewhere inside `folder`: by the place itself, however the way there is written.

    One folder has many names (\\\\?\\C:\\..., a share of this same computer, a link to it), and comparing
    spellings takes each of them for somewhere else. Each folder above the file is asked whether it *is*
    the folder. OSError: it could not be found out.
    """
    above = {path.absolute().parent, *path.absolute().parents, path.resolve().parent, *path.resolve().parents}
    return any(place.exists() and os.path.samefile(place, folder) for place in above)


def secret_in(path: Path, data_dir: Path) -> tuple[str, bool]:
    """The secret in the unlock file, and whether the file was made just now (it is, if it is not there).

    ValueError says, for whoever started qKVM, why this file will not do.
    """
    try:
        inside = lies_in(path, data_dir)
    except (OSError, RuntimeError) as ex:  # (RuntimeError: a link that leads to itself, as Python before 3.13 says it)
        # Not taken for "somewhere else" because it could not be looked at.
        raise ValueError(f"{path}: where the unlock file lies could not be checked ({getattr(ex, 'strerror', None) or ex})") from None
    if inside:
        raise ValueError(
            f"{path}: the unlock file cannot be kept in the data folder. It would be copied with it, "
            "and open every copy. Keep it somewhere the data folder's backups do not go."
        )
    made = False
    try:
        if not path.exists():
            # For its owner alone, and never over a file that appeared in the meantime.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as fh:
                fh.write(secrets.token_urlsafe(32) + "\n")
            made = True
        with path.open("rb") as fh:
            raw = fh.read(LONGEST + 1)
        if len(raw) > LONGEST:
            raise ValueError(f"{path}: this is too long to be an unlock file ({LONGEST} bytes at most). Is it the right file?")
        secret = raw.decode("utf-8").strip()
    except OSError as ex:
        raise ValueError(f"{path}: the unlock file cannot be {'read' if path.exists() else 'made'} ({ex.strerror or ex})") from None
    except UnicodeDecodeError:
        raise ValueError(f"{path}: the unlock file cannot be read: it is not text") from None
    if len(secret) < SHORTEST:
        raise ValueError(
            f"{path}: what is in the unlock file is too short to protect anything "
            f"({len(secret)} characters, where {SHORTEST} are the least). Delete it and qKVM makes one."
        )
    return secret, made


def open_to_others(path: Path) -> bool:
    """Whether other users of this computer can read the file (where the system has such a notion)."""
    if os.name != "posix":
        return False
    try:
        return bool(stat.S_IMODE(path.stat().st_mode) & 0o077)
    except OSError:
        return False
