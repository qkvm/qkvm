"""An unlock key a power cut left behind, or a wrong one given once, and what the data folder keeps to recover from.

The storage review of 0.2.0 (storage\\probes\\unlock_zero_filled_probe.py): unlock.key was written without being put on
the disk (fsync), and NTFS and XFS keep the length of a file whose data never got there, with zeros for it
(store.holds_nothing). Such a file was taken for a key: forty-four zero characters, which the next sign-in then fitted the
data folder to, a constant anybody can write. A key that did not fit (a new one made, or one start with a wrong
--unlock-file) then took out of the folder, with what the key before had opened, the migration's recovery archive and the
damaged copies set aside: what the folder keeps to recover from, lost to a key that did not fit. Now a key is written to
the disk before it is used, one that holds zeros is no key, and a key that does not fit takes nothing but itself.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from qkvm import kvm, unlock, update, vault
from qkvm.core import Core
from qkvm.store import Store
from qkvm.vault import Vault
from tests.test_unlock import SECRET, fits
from tests.test_wall import PASSWORD, wait_until, wall

ASIDE = ("qkvm.damaged-1700000000.json", "vault-migration.recovery")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_an_unlock_key_a_power_cut_left_as_zeros_is_no_key(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / unlock.OWN).write_bytes(b"\0" * 44)  # as long as token_urlsafe(32) and a line feed: what reached the disk was its length
    made = unlock.own_secret(data)
    assert "\0" not in made and len(made) >= unlock.SHORTEST, repr(made[:8])
    assert (data / unlock.OWN).read_text(encoding="ascii").strip() == made
    (data / unlock.OWN).write_bytes(made[:20].encode("ascii") + b"\0" * 24)  # half of it got there
    again = unlock.own_secret(data)
    assert "\0" not in again and again != made


@pytest.mark.parametrize("left", [b"\0" * 44, b"\0" * 4096, b"x" * 40 + b"\0" * 4], ids=["zeros", "a page of zeros", "cut short by zeros"])
def test_an_unlock_file_of_zeros_is_refused(tmp_path: Path, left: bytes) -> None:
    data = tmp_path / "data"
    data.mkdir()
    given = tmp_path / "qkvm-unlock"
    given.write_bytes(left)
    with pytest.raises(ValueError, match="zeros"):
        unlock.secret_in(given, data)


def test_a_key_is_on_the_disk_before_it_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    synced: list[int] = []
    real_fsync = os.fsync

    def fsync(descriptor: int) -> None:
        synced.append(os.fstat(descriptor).st_size)
        real_fsync(descriptor)

    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(os, "fsync", fsync)
    assert unlock.own_secret(data)
    assert (data / unlock.OWN).stat().st_size in synced, "unlock.key was used before it was on the disk"
    synced.clear()
    _, made = unlock.secret_in(tmp_path / "elsewhere.key", data)
    assert made and (tmp_path / "elsewhere.key").stat().st_size in synced, "the unlock file made was used before it was on the disk"


def test_a_key_that_does_not_fit_takes_nothing_the_folder_keeps_to_recover_from(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    for name in ASIDE:  # (stand-ins: the settings as they were, sealed with the storage key, as both are)
        (data / name).write_bytes((data / "qkvm.json").read_bytes())
    core = Core(data, unlock_secret=SECRET.upper())  # one start with another file than the one that fits
    told = core.unlock_at_start()
    core.audit.flush(10)
    assert core.store.unlock is None and Store(data / "qkvm.json").snapshot().get("unlock") is None  # what it fitted is out of the settings
    assert all((data / name).exists() for name in ASIDE), sorted(p.name for p in data.iterdir())
    assert told is not None and all(name in told for name in ASIDE), told  # and it is said that they are kept, and why


def test_a_zero_filled_key_of_its_own_neither_fits_the_folder_to_zeros_nor_takes_what_it_keeps(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:  # as it comes: a key of its own in the data folder
        wait_until(lambda: fits(admin), "never made to fit")
    (data / "qkvm.damaged-1700000000.json").write_bytes((data / "qkvm.json").read_bytes())
    length = (data / unlock.OWN).stat().st_size
    (data / unlock.OWN).write_bytes(b"\0" * length)  # the power went before the key reached the disk
    with wall(data, sign_in=False) as later:
        assert later.get("/healthz").json()["locked"] is True  # nothing opens it now: somebody signs in
        assert (data / "qkvm.damaged-1700000000.json").exists()
        assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        wait_until(lambda: fits(later), "never made to fit again")
        fitted = later.core.store.unlock  # type: ignore[attr-defined]
    assert Vault.open(fitted, "\0" * (length - 1)) is None and Vault.open(fitted, "\0" * length) is None
    assert b"\0" not in (data / unlock.OWN).read_bytes()
