"""No new storage key is made in a folder that already holds files sealed with one (the review of 850745e, L-W5).

A key is made where none is found: at the first start of a new wall, and by --migrate-vault. Where the data folder
already holds what was sealed with a key (the migration's recovery archive, a damaged copy set aside sealed, what a
write left), a key that is not found is a key that was not mounted or not restored yet, never one to make anew: a new
one was written where the owner would put the real one back, and a migration then failed at the archive with "cannot be
authenticated" and left that key behind. The missing key is asked for now, and nothing is written.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import update, vault, vault_migration
from qkvm.core import Core
from qkvm.vault_storage import StorageError
from tests.test_vault_migration import legacy


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def files(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file() and p.name not in ("qkvm.lock", "qkvm.log")}


@pytest.mark.parametrize("left", ["vault-migration.recovery", "qkvm.damaged-1.json"])
def test_a_start_beside_sealed_files_asks_for_the_key_instead_of_making_one(tmp_path: Path, left: str) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    vault_migration.migrate(data, keyfile)
    sealed = (data / "qkvm.json").read_bytes()
    for name in ("qkvm.json", "qkvm.bak"):
        (data / name).unlink()  # (the settings not restored yet, or lost; what was sealed beside them is still there)
    if left != "vault-migration.recovery":
        (data / "vault-migration.recovery").unlink()
        (data / left).write_bytes(sealed)
    before = files(data)
    elsewhere = tmp_path / "not-mounted" / "vault.key"
    with pytest.raises(StorageError, match="missing"):
        Core(data, vault_key_file=elsewhere)
    assert not elsewhere.exists()
    assert files(data) == before


def test_a_migration_run_again_without_its_key_asks_for_it_instead_of_making_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    replace = vault_migration._replace_settings

    def cut_off(source: Path, destination: Path) -> None:
        if destination.name == "qkvm.bak":
            raise PermissionError("cut off once the recovery archive was written")
        replace(source, destination)

    monkeypatch.setattr(vault_migration, "_replace_settings", cut_off)
    with pytest.raises(PermissionError):
        vault_migration.migrate(data, keyfile)
    monkeypatch.setattr(vault_migration, "_replace_settings", replace)
    assert (data / "vault-migration.recovery").exists()
    before = files(data)
    elsewhere = tmp_path / "not-mounted" / "vault.key"
    with pytest.raises(StorageError, match="missing"):
        vault_migration.migrate(data, elsewhere)
    assert not elsewhere.exists()
    assert files(data) == before
    assert vault_migration.migrate(data, keyfile)["protected"]  # (with its own key it finishes)


def test_a_file_beside_the_settings_that_cannot_be_read_makes_no_key_and_no_traceback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second fresh review, its finding 9: one that could not be opened, a damaged copy left by a run as another
    # account, say, ended the start or the migration in a traceback, which the starter takes for a broken update.)
    from qkvm import store as store_module

    data = tmp_path / "data"
    data.mkdir()
    (data / "qkvm.damaged-1.json").write_bytes(b"QKVM-VAULT-2" + b"x" * 40)
    real_open = Path.open

    def refusing(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "qkvm.damaged-1.json":
            raise PermissionError(13, "Permission denied", str(self))
        return real_open(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Path, "open", refusing)
    assert store_module.sealed_beside(data) is True  # (what cannot be read may be sealed: no key is made beside it)


def test_a_first_migration_beside_a_leftover_it_cannot_read_names_that_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final review of 1e21777, its finding 6: the leftover could not be read, so it counted as maybe sealed, and a
    # first migration said that the key file is missing, for a key that never was; the file was never named.)
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    (data / "qkvm.damaged-1.json").write_text("{}", encoding="utf-8")
    real_open = Path.open

    def refusing(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "qkvm.damaged-1.json":
            raise PermissionError(13, "Permission denied", str(self))
        return real_open(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Path, "open", refusing)
    monkeypatch.setattr(Path, "read_bytes", lambda self: real_open(self, "rb").read() if self.name != "qkvm.damaged-1.json" else refusing(self))
    with pytest.raises(StorageError) as said:
        vault_migration.migrate(data, keyfile)
    assert "qkvm.damaged-1.json" in str(said.value) and "missing" not in str(said.value), str(said.value)
    assert not keyfile.exists()
