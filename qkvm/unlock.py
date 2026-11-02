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
import shlex
import stat
import sys
from pathlib import Path

SHORTEST = 32  # characters; a secret that somebody made up themselves is refused below this
LONGEST = 4096  # bytes; a secret is a line, not whatever file the option happened to be pointed at
OWN = "unlock.key"  # the key qKVM keeps for itself, in the data folder


def _made(path: Path) -> None:
    """Make a new key at `path`: for its owner alone, never over a file that appeared in the meantime (FileExistsError), and
    on the disk before it is used. A key that was only in the disk's cache at a power cut comes back as zeros of its length
    (NTFS and XFS keep the length: store.holds_nothing), and the next sign-in fitted the data folder to that."""
    if sys.platform == "win32":
        # (Mode 0o600 is not kept by Windows: the file would take its folder's entries. Made with this account's, SYSTEM's
        # and the Administrators' alone from its first moment, as a storage key is.)
        from ._vault_windows import create_private

        descriptor = create_private(path)  # (FileExistsError where one appeared in the meantime)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as fh:
        fh.write((secrets.token_urlsafe(32) + "\n").encode("ascii"))
        fh.flush()
        os.fsync(fh.fileno())
    if sys.platform != "win32":  # ...and its name in the folder (as store._settle; Windows has no such asking, its journal keeps it)
        try:
            folder = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(folder)
        except OSError:
            pass
        finally:
            os.close(folder)


def own_secret(data_dir: Path) -> str:
    """The key qKVM keeps in its data folder to carry on by itself after a restart. Made if it is not there.

    For its owner alone, and never over a file that appeared in the meantime. OSError: none could be kept
    (a folder that cannot be written to), and then qKVM starts as with --locked-start.
    """
    path = data_dir / OWN
    for _ in range(2):
        try:
            _made(path)
        except FileExistsError:
            pass
        try:
            secret = path.read_bytes()[:LONGEST].decode("ascii").strip()
        except UnicodeDecodeError:
            secret = ""
        if len(secret) >= SHORTEST and "\0" not in secret:
            return secret
        # Not a key: cut short by a full disk, or zeros where a power cut came before it reached the disk (in whole or in
        # part). Another is made, and fits at the next sign-in.
        path.unlink()
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
            # For its owner alone, never over a file that appeared in the meantime, and on the disk before it is used.
            _made(path)
            made = True
        with path.open("rb") as fh:
            raw = fh.read(LONGEST + 1)
        if len(raw) > LONGEST:
            raise ValueError(f"{path}: this is too long to be an unlock file ({LONGEST} bytes at most). Is it the right file?")
        if b"\0" in raw:
            # What a power cut leaves of a file whose data never reached the disk (store.holds_nothing), in whole or in part:
            # taken for a secret, it was a constant anybody can write, and the next sign-in fitted the data folder to it.
            raise ValueError(
                f"{path}: the unlock file has zeros in it, as a power cut leaves a file that was being written: it is no key. "
                "Delete it, and qKVM makes a new one (it fits after the next sign-in)."
            )
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


# The entries of a POSIX access ACL (linux/posix_acl_xattr.h): what a tag says of whom, and the bit that is reading.
_USER_OBJ, _USER, _GROUP_OBJ, _GROUP, _MASK, _OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_READ, _WRITE = 4, 2


def readers(uid: int, gid: int, mode: int, acl: list[tuple[int, int, int]] | None, me: int, bit: int = _READ) -> list[str]:
    """Who besides `me` and root may read a file of this owner, group and mode, and this access ACL (None: it has none).

    By the ACL where there is one: a named user's or group's entry, and the owning group's, read only what its mask lets
    them (the mode's group bits are the mask then, not the group's). Root as the owner or the group is nobody else: root
    reads whatever it likes anyway. `bit`: what is asked about, reading (4) or, for `writers`, writing (2). An owner who is
    another account counts whatever its own bits say: the owner of a file may change its mode and its ACL at any moment.
    """
    trusted = {me, 0}
    found = [f"its owner (uid {uid})"] if uid not in trusted else []
    if acl is None:
        found += [f"group {gid}"] if gid != 0 and mode & (bit << 3) else []
        return found + (["everybody"] if mode & bit else [])
    mask = next((perm for tag, perm, _ in acl if tag == _MASK), 7)
    for tag, perm, who in acl:
        if tag == _USER_OBJ:
            continue  # (the owner: above)
        elif tag == _USER and perm & mask & bit and who not in trusted:
            found.append(f"user {who}")
        elif tag == _GROUP_OBJ and perm & mask & bit and gid != 0:
            found.append(f"group {gid}")
        elif tag == _GROUP and perm & mask & bit and who != 0:
            found.append(f"group {who}")
        elif tag == _OTHER and perm & bit:
            found.append("everybody")
    return found


def writers(uid: int, gid: int, mode: int, acl: list[tuple[int, int, int]] | None, me: int) -> list[str]:
    """Who besides `me` and root may change such a file (readers, of writing). Whoever may can swap the key for one of
    their own, which the next sign-in fits the data folder to."""
    return readers(uid, gid, mode, acl, me, _WRITE)


def _access_acl(path: Path) -> list[tuple[int, int, int]] | None:
    """The file's POSIX access ACL as (tag, permissions, id) entries; None where it has none, or the system keeps none.

    ValueError for what is no such list: not taken for "none".
    """
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return None
    try:
        raw = getxattr(path, "system.posix_acl_access")
    except OSError:  # (none on this file; or a file system, or a system, that keeps none)
        return None
    if len(raw) < 4 or (len(raw) - 4) % 8 or int.from_bytes(raw[:4], "little") != 2:
        raise ValueError("not a POSIX ACL")
    return [
        (int.from_bytes(raw[at : at + 2], "little"), int.from_bytes(raw[at + 2 : at + 4], "little"), int.from_bytes(raw[at + 4 : at + 8], "little"))
        for at in range(4, len(raw), 8)
    ]


def what_others_may(path: Path) -> list[str]:
    """What users of this computer besides the one qKVM runs as (and root) may do with the file: "read", "changed", both,
    or nothing ([]). Nothing where the system has no such notion.

    By the file's ACL where it has one (readers, writers): systemd hands a service its unlock file (LoadCredential) as
    root's, mode 0440, with an ACL entry for the service's user alone, and by its mode alone that was "readable by its
    group", with advice (chmod 600) that cannot be followed on a credential. A file in the unit's own credentials folder
    ($CREDENTIALS_DIRECTORY, which systemd makes for the unit alone) is the unit's alone. On Windows by its owner and its
    ACL (_folders.not_alone): one of another account's may be read and changed by that account.
    """
    return _judged(path)[0]


def _folders_of(path: Path) -> list[Path]:
    """The folder the file is given in, and the one it lies in where it is reached through a link (whoever may change either
    may put another file in its place)."""
    given = path.absolute().parent
    try:
        real = path.resolve().parent
    except (OSError, RuntimeError):  # (a link that leads to itself, as Python before 3.13 says it)
        return [given]
    return [given] if os.path.normcase(str(real)) == os.path.normcase(str(given)) else [given, real]


def _judged(path: Path) -> tuple[list[str], list[str]]:
    """What others may do with the file (what_others_may), and what to do about each reason for it (warning)."""
    if sys.platform == "win32":
        from ._folders import READ, WRITE, _a_link, judged as judged_here, not_alone

        # The file as given and, where that is a symlink, the file it leads to: Windows reads a link's own security.
        files = [path]
        try:
            if os.path.normcase(str(path.resolve())) != os.path.normcase(str(path.absolute())):
                files.append(path.resolve())
        except (OSError, RuntimeError):
            pass
        found = [{"read": not_alone(file, READ), "changed": not_alone(file, WRITE)} for file in files]
        if any("cannot be looked at" in each.values() for each in found):
            return [], []  # (as on POSIX: what cannot be looked at is said where it is read)
        judged = {what: next((each[what] for each in found if each[what] is not None), None) for what in ("read", "changed")}
        open_folders = [folder for folder in _folders_of(path) if not_alone(folder) not in (None, "cannot be looked at")]
        said = [what for what, why in judged.items() if why is not None or (what == "changed" and open_folders)]
        # What to do: each one's own line, the file's and, where it is given by a symlink, the link's by itself (/L).
        advice: list[str] = []
        for file in files:
            what = judged_here(file, READ | WRITE, link=file != files[-1])
            line = None if what is None else f"it belongs to another account: {what[1]}" if what[0].startswith("belongs to another user") else what[1]
            if line and line not in advice:
                advice.append(line)
        # A folder's own lines, where it is for the file alone (one shared with other things is not to be shut to them on
        # the file's account: keep the file elsewhere); a folder given by a link is set by the link's line (/L).
        for folder in open_folders:
            what = judged_here(folder, link=_a_link(folder))
            lines = f" (where the folder is for it alone: {what[1]})" if what is not None and what[1] else ""
            advice.append(f"its folder {folder} can be changed by others: keep it in a folder only you, SYSTEM and the Administrators may change{lines}")
        return said, advice
    if os.name != "posix":
        return [], []
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials and _in_credentials(path, Path(credentials)):
        return [], []
    try:
        found = path.stat()
        acl = _access_acl(path)
        around = [(folder, folder.stat(), _access_acl(folder)) for folder in _folders_of(path)]
    except (OSError, RuntimeError):
        return [], []
    except ValueError:
        return ["read", "changed"], [f"chmod 600 {shlex.quote(str(path))} makes it yours alone"]  # (an ACL that cannot be read is not taken for none)
    me = os.getuid()
    whose = (found.st_uid, found.st_gid, stat.S_IMODE(found.st_mode), acl, me)
    reading, writing = readers(*whose), writers(*whose)
    # Whoever may change its folder may put another file in its place: but not in a folder with the sticky bit (/tmp), where
    # nobody but the file's owner may remove or rename it. The folder it is given in, and the one it lies in (a link).
    open_folders = [
        folder
        for folder, kept, folder_acl in around
        if not kept.st_mode & stat.S_ISVTX and writers(kept.st_uid, kept.st_gid, stat.S_IMODE(kept.st_mode), folder_acl, me)
    ]
    # Each with its line, the file and each folder named (chmod and chown follow a link to what it leads to: what was judged).
    given = shlex.quote(str(path))
    advice = []
    if found.st_uid not in (me, 0):
        advice.append(f"it belongs to uid {found.st_uid}: chown it to the account qKVM runs as, or to root (as root: chown {me} {given})")
    if [who for who in reading + writing if not who.startswith("its owner")]:
        advice.append(f"chmod 600 {given} makes it yours alone")
    for folder, kept, _ in around:
        if folder in open_folders:
            named = shlex.quote(str(folder))
            line = f"chmod go-w {named}" if kept.st_uid in (me, 0) else f"as root, chown {me} {named} && chmod go-w {named}"
            advice.append(f"its folder {folder} can be changed by others: keep it in a folder only you, or root, may change (where the folder is for it alone: {line})")
    said = [what for what, who in (("read", reading), ("changed", writing or open_folders)) if who]
    return said, advice


def _in_credentials(path: Path, credentials: Path) -> bool:
    """Whether the file is in the unit's credentials folder as both are found: their links followed and ".." gone. (Asked as
    written, a path through that folder and out of it again with ".." was taken for the unit's own; lies_in keeps "..".)
    What cannot be found out is not taken for inside."""
    try:
        real, folder = path.resolve(), credentials.resolve()
        return any(place.exists() and os.path.samefile(place, folder) for place in real.parents)
    except (OSError, RuntimeError):  # (RuntimeError: a link that leads to itself, as Python before 3.13 says it)
        return False


def open_to_others(path: Path) -> bool:
    """Whether users of this computer besides the one qKVM runs as (and root) may read or change the file (what_others_may)."""
    return bool(what_others_may(path))


def warning(path: Path) -> str | None:
    """What the start says of an unlock file others may read or change, with what to do about each reason for it; None
    where they may not."""
    others_may, advice = _judged(path)
    if not others_may:
        return None
    said = "; ".join(advice)
    if sys.platform == "win32":
        from ._folders import for_consoles

        said = for_consoles(said)  # (with the console its lines are for)
    return f"{path} can be {' and '.join(others_may)} by other users of this computer ({said})"
