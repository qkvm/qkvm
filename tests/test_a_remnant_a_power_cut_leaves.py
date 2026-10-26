"""What a power cut leaves of a settings write beside a protected vault is nothing, and locks nobody out.

The review of 850745e (W3): a protected wall whose second copy (qkvm.bak), temporary file (qkvm.tmp) or second copy in
the making (qkvm.bak.new) was left empty, or filled with zeros (the length written, the data never: what NTFS and XFS
keep of a file whose data had not reached the disk), refused every start, --verify-vault and --migrate-vault with advice
that did not help ("a legacy settings remnant remains"). Such a file holds no settings: it is no remnant of the old
format. A legacy remnant that holds something (a whole legacy file, or a fragment of one) still blocks a start until
it is archived, as tests/test_vault_migration.py decides.

The remnants are planted here with raw writes: tests/settings_file.py seals what it writes under these names, and a
sealed remnant is not what a power cut leaves.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from qkvm import store as store_module
from qkvm import update, vault, vault_migration
from qkvm.core import Core
from qkvm.store import Store, UserRecord
from qkvm.vault_storage import MAGIC, MigrationRequired, StorageCipher, StorageError, read_key
from tests.test_vault_migration import legacy

PASSWORD = "remnant administrator password"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def migrated(tmp_path: Path) -> tuple[Path, Path]:
    """A wall of 0.1.x, migrated: two accounts and a device, protected by a key outside its folder."""
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    vault_migration.migrate(data, key)
    return data, key


def made_protected(tmp_path: Path) -> tuple[Path, Path]:
    """A wall that 0.2.0 set up itself."""
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    data.mkdir(parents=True)
    store = Store(data / "qkvm.json", vault_key_file=key, protected=True)
    store.users = [UserRecord(id="admin1", name="admin", role="admin", auth=vault.Vault().create(PASSWORD), created=1)]
    store.save()
    return data, key


def zeros(path: Path) -> None:
    path.write_bytes(b"\0" * max(path.stat().st_size if path.exists() else 0, 600))


def empty(path: Path) -> None:
    path.write_bytes(b"")


WALLS: dict[str, Callable[[Path], tuple[Path, Path]]] = {"migrated": migrated, "made by 0.2.0": made_protected}
LEFT: dict[str, tuple[str, Callable[[Path], None]]] = {
    "second copy filled with zeros": ("qkvm.bak", zeros),
    "second copy empty": ("qkvm.bak", empty),
    "temporary file empty": ("qkvm.tmp", empty),
    "temporary file filled with zeros": ("qkvm.tmp", zeros),
    "second copy in the making filled with zeros": ("qkvm.bak.new", zeros),
    "second copy in the making empty": ("qkvm.bak.new", empty),
}


def both_copies_whole(data: Path, key: Path) -> None:
    """The settings and their second copy are the same protected settings again, as a start or a save leaves them."""
    cipher = StorageCipher(read_key(key))
    primary, backup = (data / "qkvm.json").read_bytes(), (data / "qkvm.bak").read_bytes()
    assert primary.startswith(MAGIC) and backup.startswith(MAGIC)
    assert cipher.decode(primary) == cipher.decode(backup)


@pytest.mark.parametrize("wall", list(WALLS))
@pytest.mark.parametrize("left", list(LEFT))
def test_a_protected_wall_starts_over_what_a_power_cut_left(tmp_path: Path, wall: str, left: str) -> None:
    data, key = WALLS[wall](tmp_path)
    name, damage = LEFT[left]
    accounts = len(Store(data / "qkvm.json", vault_key_file=key, protected=True, read_only=True).users)
    damage(data / name)
    core = Core(data, vault_key_file=key)  # (was: MigrationRequired, "a legacy settings remnant remains")
    assert len(core.store.users) == accounts and not core.store.restored
    # What held nothing is gone, and the second copy is whole again: verification passes as it did before the cut.
    assert not (data / "qkvm.tmp").exists() and not (data / "qkvm.bak.new").exists()
    both_copies_whole(data, key)
    assert vault_migration.verify(data, key)["accounts"] == accounts


@pytest.mark.parametrize("left", list(LEFT))
def test_migration_run_again_over_what_a_power_cut_left_puts_it_right(tmp_path: Path, left: str) -> None:
    # Whoever follows the old advice and runs --migrate-vault again is helped, not told that legacy settings changed.
    data, key = migrated(tmp_path)
    name, damage = LEFT[left]
    damage(data / name)
    result = vault_migration.migrate(data, key)
    assert result["protected"] and result["already_protected"] and result["accounts"] == 2
    assert not (data / "qkvm.tmp").exists() and not (data / "qkvm.bak.new").exists()
    both_copies_whole(data, key)


@pytest.mark.parametrize("left", ["temporary file empty", "second copy in the making filled with zeros"])
def test_verification_does_not_call_an_empty_leftover_unprotected(tmp_path: Path, left: str) -> None:
    data, key = migrated(tmp_path)
    name, damage = LEFT[left]
    damage(data / name)
    assert vault_migration.verify(data, key)["accounts"] == 2  # (was: MigrationRequired)
    assert (data / name).exists()  # (verification changes nothing)


def test_verification_of_an_empty_second_copy_says_how_to_put_it_right(tmp_path: Path) -> None:
    data, key = migrated(tmp_path)
    zeros(data / "qkvm.bak")
    with pytest.raises(StorageError, match="start qKVM once"):  # (was: MigrationRequired, whose advice did not help)
        vault_migration.verify(data, key)


def test_a_legacy_remnant_that_holds_something_still_blocks_a_start(tmp_path: Path) -> None:
    # The decision of tests/test_vault_migration.py stands: a whole legacy file beside the envelope holds password-openable
    # records, and is not set aside without the archive. Only what holds nothing is passed over.
    data, key = migrated(tmp_path)
    (data / "qkvm.tmp").write_bytes(b'{"users": [], "devices": []}')
    with pytest.raises(MigrationRequired):
        Core(data, vault_key_file=key)
    (data / "qkvm.tmp").write_bytes(b"\0" * 300 + b'{"users": [')  # zeros, then the start of a legacy write
    with pytest.raises(MigrationRequired):
        Core(data, vault_key_file=key)


@pytest.mark.parametrize("wall", list(WALLS))
def test_migration_run_again_after_a_damaged_file_was_sealed_aside_leaves_that_copy_alone(tmp_path: Path, wall: str) -> None:
    # The settings themselves left as zeros: a start goes on from the second copy and keeps the damaged bytes, sealed, as
    # qkvm.damaged-*.json. That copy is inside the vault, no plaintext remnant: --migrate-vault run again over it refused
    # ("settings remnants need a verified migration recovery archive before cleanup"), or tried to remove it and said it
    # could not remove "archived plaintext remnants". It goes on, and leaves the sealed copy where it is.
    data, key = WALLS[wall](tmp_path)
    zeros(data / "qkvm.json")
    assert Core(data, vault_key_file=key).store.restored
    sealed = list(data.glob("qkvm.damaged-*.json"))
    assert len(sealed) == 1 and sealed[0].read_bytes().startswith(MAGIC)
    kept = sealed[0].read_bytes()
    result = vault_migration.migrate(data, key)
    assert result["protected"] and result["already_protected"]
    assert sealed[0].read_bytes() == kept
    both_copies_whole(data, key)


def test_the_second_copy_is_on_the_disk_before_it_takes_the_place_of_the_last_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The second copy was copied and renamed into place without being flushed to the disk: after a power cut its name could
    # be there with its data never written (the zero-filled qkvm.bak above). Each copy is synced before its rename.
    data, key = made_protected(tmp_path)
    store = Store(data / "qkvm.json", vault_key_file=key, protected=True)
    happened: list[str] = []
    real_fsync, real_replace = store_module.os.fsync, store_module._replace_settings

    def fsync(descriptor: int) -> None:
        happened.append("fsync")
        real_fsync(descriptor)

    def replace(source: Path, destination: Path) -> None:
        happened.append(f"replace {source.name} -> {destination.name}")
        real_replace(source, destination)

    monkeypatch.setattr(store_module.os, "fsync", fsync)
    monkeypatch.setattr(store_module, "_replace_settings", replace)
    store.save()
    into_place = happened.index("replace qkvm.bak.new -> qkvm.bak")
    after_primary = happened.index("replace qkvm.tmp -> qkvm.json")
    assert "fsync" in happened[after_primary + 1 : into_place], happened


def test_the_folder_is_written_out_after_the_second_copy_takes_its_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fresh review of 46146cc, its L9: the folder was written out after the settings took their place, and not after
    # the second copy took its own: a power cut a moment later could undo that rename, on a system that writes the folder
    # apart from the file.)
    done: list[tuple[str, str]] = []
    replace, settle = store_module._replace_settings, store_module._settle

    def replacing(source: Path, destination: Path) -> None:
        replace(source, destination)
        done.append(("replaced", destination.name))

    def settling(folder: Path) -> None:
        settle(folder)
        done.append(("settled", ""))

    monkeypatch.setattr(store_module, "_replace_settings", replacing)
    monkeypatch.setattr(store_module, "_settle", settling)
    kept = Store(tmp_path / "qkvm.json")
    done.clear()
    kept.write({"users": [], "devices": []})
    assert done[-2:] == [("replaced", "qkvm.bak"), ("settled", "")], done
