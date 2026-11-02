"""Every folder qKVM makes names the account it runs as, so that an elevated run never locks the same person out (the round
4 review, M3; review-core4\\probes\\p7_elevated_then_not.py, p6_judge_only.py).

Python's mkdir(mode=0o700) gives, on Windows since 3.12.4, SYSTEM, the Administrators and OWNER RIGHTS; what an elevated
token makes belongs to the Administrators. ~/.qkvm made by an elevated run (remember, at any start with --data-dir
elsewhere) refused the same person's plain run: "cannot keep settings ... Permission denied", with a hint about uid 10001,
which is the container's. An update installed by an elevated run was not taken by a plain one. Now every folder qKVM
makes is made by private_folder on Windows (this account, SYSTEM and the Administrators, named), the folders above it it
makes as well, and the uid hint is given in a container only.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from qkvm import _folders, cli, update
from tests.fake_github import make_wheel

FULL = 0x1F01FF  # FILE_ALL_ACCESS


def names_its_owner(folder: Path) -> bool:
    """Whether the folder is this account's to use, whoever owns it (an elevated run's: the Administrators): on Windows an
    entry of its own for this account, in a protected ACL; on POSIX mode 0700, its own."""
    if sys.platform != "win32":
        found = folder.stat()
        return found.st_uid == os.getuid() and stat.S_IMODE(found.st_mode) == 0o700
    win = _folders._windows()
    me = _folders._me(win)
    _, entries = _folders._security(win, folder)
    return entries is not None and any(kind == 0 and whose == me and rights & FULL == FULL and not flags & 0x10 for kind, flags, rights, whose in entries)


def test_the_folder_kept_at_home_is_made_naming_its_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "profile" / ".qkvm"  # (the profile's folder too: made above it as its own)
    monkeypatch.setattr(cli, "home_folder", lambda: home)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cli.remember(elsewhere)
    assert (home / cli.KNOWN).is_file()
    assert names_its_owner(home) and names_its_owner(home.parent)


def test_an_updates_folders_are_made_naming_their_owner(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    update.unpack(make_wheel("9.9.9"), "9.9.9", data / "updates" / "9.9.9")
    made = [data / "updates", *(path for path in (data / "updates").rglob("*") if path.is_dir())]
    assert len(made) >= 3 and [folder for folder in made if not names_its_owner(folder)] == [], made


def test_a_folder_made_with_those_above_it_names_its_owner_in_each(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c"
    _folders.own_folder(deep)
    assert all(names_its_owner(folder) for folder in (tmp_path / "a", tmp_path / "a" / "b", deep))


@pytest.mark.parametrize("container", [False, True])
def test_the_uid_of_the_container_is_named_in_a_container_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], container: bool) -> None:
    def refused(*args: object, **kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(cli, "private_folder", refused)
    monkeypatch.setattr(Path, "mkdir", refused)
    if container:
        monkeypatch.setenv("QKVM_CONTAINER", "1")
    else:
        monkeypatch.delenv("QKVM_CONTAINER", raising=False)
    assert cli.main(["--data-dir", str(tmp_path / "data"), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert "cannot keep settings in" in said and ("uid 10001" in said) == container, said
    assert container or "elevated run" in said, said
