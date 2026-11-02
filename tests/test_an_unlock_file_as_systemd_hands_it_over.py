"""An unlock file handed to qKVM as a systemd credential is not called readable by others.

`LoadCredential=qkvm-unlock:/etc/qkvm/unlock.key` (README, "Keeping it running") gives the service its unlock file as
systemd lays out every credential: under $CREDENTIALS_DIRECTORY, owned by root, mode 0440, with a POSIX ACL entry for the
service's user and nobody else (its mask is what the group's bits show). On the owner's walls (2026-10-26, Ubuntu 24.04,
systemd 255, DynamicUser) qKVM said at every start that the file "can be read by other users of this computer (chmod
600 makes it yours alone)": its check read the mode alone and counted every bit of the group's and the others', and the
advice cannot be followed on a credential. The storage review of 0.2.0 found the same (storage\\probes\\linux_acl_probe.py).
Now read access alone counts, by the file's ACL where it has one, with its mask; root's is fine; and a file in the unit's
own credentials folder is the unit's alone.

And write access counts as well, the same way (the coordinator's decision of 2026-11-01): whoever may change the file can
swap the key for one of their own, which the next sign-in fits the data folder to. Said as what it is: "changed".
"""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

import pytest

from qkvm import unlock

USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20  # the tags of acl_ea.h
NOBODY = 0xFFFFFFFF  # (the id of an entry that is not about a named user or group)
SERVICE, STRANGER = 61234, 61235  # the service's own (dynamic) user, and another user of the computer
AS_SYSTEMD_LAYS_IT_OUT = [(USER_OBJ, 4, NOBODY), (USER, 4, SERVICE), (GROUP_OBJ, 0, NOBODY), (MASK, 4, NOBODY), (OTHER, 0, NOBODY)]


def acl(entries: list[tuple[int, int, int]]) -> bytes:
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, who) for tag, perm, who in entries)


def test_who_besides_the_service_may_read_a_credential_as_systemd_lays_it_out() -> None:
    assert unlock.readers(0, 0, 0o440, AS_SYSTEMD_LAYS_IT_OUT, SERVICE) == []
    strangers = [*AS_SYSTEMD_LAYS_IT_OUT[:2], (USER, 4, STRANGER), (GROUP, 4, 1000), *AS_SYSTEMD_LAYS_IT_OUT[2:]]
    assert unlock.readers(0, 0, 0o440, strangers, SERVICE) == [f"user {STRANGER}", "group 1000"]
    masked = [(USER_OBJ, 6, NOBODY), (USER, 4, STRANGER), (GROUP_OBJ, 4, NOBODY), (MASK, 0, NOBODY), (OTHER, 0, NOBODY)]
    assert unlock.readers(SERVICE, 1000, 0o600, masked, SERVICE) == []  # the mask lets no named entry read: as `chmod 600` leaves it
    assert unlock.readers(0, 0, 0o444, [*AS_SYSTEMD_LAYS_IT_OUT[:4], (OTHER, 4, NOBODY)], SERVICE) == ["everybody"]
    # Without an ACL, by the mode: reading alone counts; root as its owner, or its group, is fine.
    assert unlock.readers(SERVICE, 1000, 0o622, None, SERVICE) == []  # (others may write it, and read nothing)
    assert unlock.readers(0, 0, 0o440, None, SERVICE) == []
    assert unlock.readers(SERVICE, 1000, 0o640, None, SERVICE) == ["group 1000"]
    assert unlock.readers(STRANGER, 1000, 0o400, None, SERVICE) == [f"its owner (uid {STRANGER})"]
    assert unlock.readers(SERVICE, 1000, 0o604, None, SERVICE) == ["everybody"]


@pytest.mark.skipif(not hasattr(os, "setxattr"), reason="POSIX ACLs are kept on Linux")
def test_an_unlock_file_is_judged_by_its_acl_and_its_mask(tmp_path: Path) -> None:
    given = tmp_path / "qkvm-unlock"
    given.write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(given, 0o400)
    me = os.getuid()
    try:
        os.setxattr(given, "system.posix_acl_access", acl([(USER_OBJ, 4, NOBODY), (USER, 4, me), (GROUP_OBJ, 0, NOBODY), (MASK, 4, NOBODY), (OTHER, 0, NOBODY)]))
    except OSError as ex:
        pytest.skip(f"this file system keeps no POSIX ACL ({ex.strerror})")
    assert stat.S_IMODE(given.stat().st_mode) == 0o440  # what the mode says of such a file: the mask, where the group's bits are
    assert unlock.open_to_others(given) is False
    os.setxattr(given, "system.posix_acl_access", acl([(USER_OBJ, 4, NOBODY), (USER, 4, me), (USER, 4, STRANGER), (GROUP_OBJ, 0, NOBODY), (MASK, 4, NOBODY), (OTHER, 0, NOBODY)]))
    assert unlock.open_to_others(given) is True  # another user named in it reads it
    os.chmod(given, 0o600)  # (what the warning advises: the mask goes to nothing, and no named entry reads it then)
    assert unlock.open_to_others(given) is False


@pytest.mark.skipif(os.name != "posix", reason="who may read a file is not kept this way on Windows")
def test_a_file_in_the_units_own_credentials_folder_is_the_units_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    credentials, elsewhere = tmp_path / "credentials", tmp_path / "elsewhere"
    for folder in (credentials, elsewhere):
        folder.mkdir()
        (folder / "qkvm-unlock").write_text("x" * 44 + "\n", encoding="ascii")
        os.chmod(folder / "qkvm-unlock", 0o444)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    assert unlock.open_to_others(credentials / "qkvm-unlock") is True
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))  # as systemd starts the unit
    assert unlock.open_to_others(credentials / "qkvm-unlock") is False
    assert unlock.open_to_others(elsewhere / "qkvm-unlock") is True


# --- who may change it: a writer can swap the key -----------------------------------------------------------------


def test_who_besides_the_service_may_change_a_credential() -> None:
    assert unlock.writers(0, 0, 0o440, AS_SYSTEMD_LAYS_IT_OUT, SERVICE) == []
    assert unlock.writers(SERVICE, 1000, 0o620, None, SERVICE) == ["group 1000"]
    assert unlock.writers(SERVICE, 1000, 0o602, None, SERVICE) == ["everybody"]
    assert unlock.writers(SERVICE, 1000, 0o644, None, SERVICE) == []  # (read by others, changed by none)
    assert unlock.writers(0, 0, 0o660, None, SERVICE) == []  # root's, and its group root's
    assert unlock.writers(STRANGER, 1000, 0o600, None, SERVICE) == [f"its owner (uid {STRANGER})"]
    named = [(USER_OBJ, 6, NOBODY), (USER, 6, STRANGER), (GROUP, 6, 1000), (GROUP_OBJ, 4, NOBODY), (MASK, 6, NOBODY), (OTHER, 0, NOBODY)]
    assert unlock.writers(SERVICE, 1000, 0o660, named, SERVICE) == [f"user {STRANGER}", "group 1000"]
    masked = [*named[:4], (MASK, 4, NOBODY), (OTHER, 2, NOBODY)]
    assert unlock.writers(SERVICE, 1000, 0o642, masked, SERVICE) == ["everybody"]  # the mask spares nobody of the others' entry


@pytest.mark.skipif(os.name != "posix", reason="who may change a file is not kept this way on Windows")
def test_an_unlock_file_others_may_change_is_said_to_be_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    given = tmp_path / "qkvm-unlock"
    given.write_text("x" * 44 + "\n", encoding="ascii")
    for mode, said in ((0o622, ["changed"]), (0o666, ["read", "changed"]), (0o644, ["read"]), (0o600, [])):
        os.chmod(given, mode)
        assert (unlock.what_others_may(given), unlock.open_to_others(given)) == (said, bool(said)), oct(mode)
    if hasattr(os, "setxattr"):
        me = os.getuid()
        try:
            os.setxattr(given, "system.posix_acl_access", acl([(USER_OBJ, 6, NOBODY), (USER, 6, me), (USER, 2, STRANGER), (GROUP_OBJ, 0, NOBODY), (MASK, 6, NOBODY), (OTHER, 0, NOBODY)]))
        except OSError:
            pass  # (a file system that keeps no POSIX ACL: the modes above were all there is to see)
        else:
            assert unlock.what_others_may(given) == ["changed"]  # another user named in it may write it, and read it not
            os.chmod(given, 0o640)  # (the mask down to reading: the named writer writes nothing then)
            assert unlock.what_others_may(given) == []
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "qkvm-unlock").write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(credentials / "qkvm-unlock", 0o666)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    assert unlock.what_others_may(credentials / "qkvm-unlock") == []  # the unit's alone, as systemd makes that folder


@pytest.mark.skipif(os.name != "posix", reason="systemd's credentials are a Linux thing")
def test_only_what_is_in_the_credentials_folder_as_it_is_found_is_the_units(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The review of 2026-11-01 (L7, review-core\probes\linux_unlock_judgement.py case 2): the path was asked of as written, and
    # ".." kept: /run/credentials/qkvm.service/../../../tmp/x, mode 0666, was taken for the unit's own.
    credentials, elsewhere = tmp_path / "credentials", tmp_path / "elsewhere"
    for folder in (credentials, elsewhere):
        folder.mkdir()
    loose = elsewhere / "qkvm-unlock"
    loose.write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(loose, 0o666)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    assert unlock.what_others_may(Path(f"{credentials}/../elsewhere/qkvm-unlock")) == ["read", "changed"]
    (credentials / "linked").symlink_to(loose)  # (a link in the folder to a file outside it is the file outside it)
    assert unlock.what_others_may(credentials / "linked") == ["read", "changed"]
    (credentials / "own").write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(credentials / "own", 0o444)
    assert unlock.what_others_may(Path(f"{elsewhere}/../credentials/own")) == []  # (and what is in it, however it is written)


# --- whose it is, and whose its folder is (the review of 2026-11-01, L6) -----------------------------------------------


def test_a_file_of_another_account_may_be_read_and_changed_by_that_account_whatever_its_bits() -> None:
    # The owner of a file may change its mode and its ACL at any moment: what its bits say of it this moment holds nothing.
    assert unlock.writers(STRANGER, 1000, 0o400, None, SERVICE) == [f"its owner (uid {STRANGER})"]
    assert unlock.readers(STRANGER, 1000, 0o000, None, SERVICE) == [f"its owner (uid {STRANGER})"]
    only_for_the_service = [(USER_OBJ, 0, NOBODY), (USER, 4, SERVICE), (GROUP_OBJ, 0, NOBODY), (MASK, 4, NOBODY), (OTHER, 0, NOBODY)]
    assert unlock.writers(STRANGER, 1000, 0o040, only_for_the_service, SERVICE) == [f"its owner (uid {STRANGER})"]
    assert unlock.writers(0, 0, 0o040, only_for_the_service, SERVICE) == []  # (root's: as systemd's credentials are)


@pytest.mark.skipif(os.name != "posix", reason="who may change a file is not kept this way on Windows")
def test_an_unlock_file_in_a_folder_others_may_change_or_of_another_account_is_said_with_what_fits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    folder = tmp_path / "keys"
    folder.mkdir()
    given = folder / "qkvm-unlock"
    given.write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(given, 0o600)
    assert unlock.what_others_may(given) == [] and unlock.warning(given) is None
    os.chmod(folder, 0o777)  # whoever may change the folder may put another file in this one's place
    assert unlock.what_others_may(given) == ["changed"]
    said = unlock.warning(given)
    assert said is not None and f"its folder {folder}" in said and "chmod 600" not in said, said
    os.chmod(folder, 0o1777)  # (with the sticky bit, as /tmp: nobody but its owner may remove or rename it)
    assert unlock.what_others_may(given) == []
    os.chmod(folder, 0o700)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(given).st_uid + 1)  # qKVM as another account than the file's owner
    assert unlock.what_others_may(given) == ["read", "changed"]
    said = unlock.warning(given)
    assert said is not None and "chown" in said, said


@pytest.mark.skipif(os.name != "posix", reason="who may change a file is not kept this way on Windows")
def test_an_unlock_file_reached_through_a_link_is_judged_by_the_folder_it_lies_in_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The round 2 review (LOW-5, review-core2\probes\linux_unlock_link_folder.py): the folder of the link was looked at, not
    # that of the file it leads to: a file in a folder anybody may change, reached through a link from a private one, was
    # said to be nobody else's.
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    opened, private = tmp_path / "open", tmp_path / "private"
    for folder, mode in ((opened, 0o777), (private, 0o700)):
        folder.mkdir()
        os.chmod(folder, mode)
    key = opened / "qkvm-unlock"
    key.write_text("x" * 44 + "\n", encoding="ascii")
    os.chmod(key, 0o600)
    link = private / "unlock"
    link.symlink_to(key)
    assert unlock.what_others_may(link) == ["changed"]
    said = unlock.warning(link)
    assert said is not None and f"its folder {opened}" in said, said
