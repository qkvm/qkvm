"""The storage key's folder: on Windows a key is not made in one that is another account's or open, as on Linux; and the
folder of a new data folder's key is made, private, with the data folder (the round 4 review, L5).

create_key judged the folder's owner and mode on Linux and refused; on Windows it made the key in whatever it found
(private_folder leaves a found folder as it is): a .keys folder others may change took a new key, which they could take
away or replace. And <data>.keys was made only when the key was, after the start had named the folder (remember), which
left the name for another account to take first in a folder above that is open.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import cli
from qkvm.vault_storage import StorageError, create_key
from tests.test_what_another_account_planted import another_owner

windows = pytest.mark.skipif(sys.platform != "win32", reason="who may write a folder is kept in its ACL on Windows")


@windows
def test_a_key_is_not_made_in_a_folder_others_may_change_on_windows(tmp_path: Path) -> None:
    keys = tmp_path / "data.keys"
    keys.mkdir()
    subprocess.run(["icacls", str(keys), "/grant", "*S-1-5-11:(OI)(CI)M"], check=True, capture_output=True)
    with pytest.raises(StorageError, match="must belong to the server and not be writable by others"):
        create_key(keys / "vault.key")
    assert not (keys / "vault.key").exists()


@windows
def test_a_key_is_not_made_in_a_folder_of_another_account_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = tmp_path / "data.keys"
    keys.mkdir()
    another_owner(monkeypatch, keys)
    with pytest.raises(StorageError, match="must belong to the server"):
        create_key(keys / "vault.key")
    assert not (keys / "vault.key").exists()


def test_a_key_is_made_in_a_folder_of_its_own(tmp_path: Path) -> None:
    create_key(tmp_path / "data.keys" / "vault.key")  # (made by it, its own: taken)
    assert (tmp_path / "data.keys" / "vault.key").is_file()


def test_a_new_data_folders_key_folder_is_made_before_the_folder_is_named_anywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "walls" / "new"
    keys = data.with_name("new.keys")
    seen: list[bool] = []
    real_remember = cli.remember
    monkeypatch.setattr(cli, "remember", lambda folder: (seen.append(keys.is_dir()), real_remember(folder))[1])
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    assert seen == [True], seen  # (made with the data folder, before remember named it at home)
    if sys.platform == "win32":
        from qkvm import _folders

        assert _folders.not_alone(keys) is None
    else:
        assert os.stat(keys).st_mode & 0o077 == 0
