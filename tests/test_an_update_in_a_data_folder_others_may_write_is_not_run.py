"""The starter judges the data folder, and every link on the way to it, before it runs an update in it (the round 4 review,
M4).

It judged updates/, current.json, the version's folder and everything in the package, and not the folder they lie in: in a
data folder others may write, an update whose own folders were private was run, though whoever may write the data folder
may rename updates/ and put one of their own in its place between the look and the run, or point a link on the way at a
folder of theirs. Now the data folder and each link on the way (_folders.places) by the same rule first: an update in a
data folder others may write is not run, on both systems.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import __main__ as starter
from qkvm import _folders
from tests.test_update import an_update_that_leaves_a_mark, typed
from tests.test_what_another_account_planted import link

WINDOWS = sys.platform == "win32"


def opened(folder: Path) -> None:
    """Everybody signed in may change what is in it (Windows, its own entry: not passed to what is in it); mode 0777 elsewhere."""
    if WINDOWS:
        subprocess.run(["icacls", str(folder), "/grant", "*S-1-5-11:M"], check=True, capture_output=True)
    else:
        os.chmod(folder, 0o777)


def test_an_update_whose_folders_are_its_owners_in_a_data_folder_others_may_write_is_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    mark = an_update_that_leaves_a_mark(data)
    assert starter.active_update(data) is not None  # (its own folders and the data folder its owner's alone)
    opened(data)  # (the entry on the data folder only: updates/ and all in it stay their owner's)
    assert starter.not_own(data / "updates") is None and starter.not_whole(data / "updates" / "9.9.9" / "qkvm") is None
    assert starter.active_update(data, tell=True) is None
    said = capsys.readouterr().err
    assert f"the update in {data / 'updates'} is not used: {data} can be written to by other" in said, said
    done = typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path)
    assert not mark.exists() and "is not used" in done.stderr, done.stderr


def test_an_update_in_a_data_folder_reached_through_a_link_others_may_change_is_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    real = tmp_path / "real"
    an_update_that_leaves_a_mark(real)
    way = tmp_path / "way"
    way.mkdir()
    link(way / "data", real)
    data = way / "data"
    assert starter.active_update(data) is not None
    if WINDOWS:
        subprocess.run(["icacls", str(data), "/grant", "*S-1-5-11:M", "/L"], check=True, capture_output=True)  # the link itself
        why = "can be written to by other users"
    else:
        real_lstat = os.lstat  # (a link another account made: its owner told so)
        owner = real_lstat(data).st_uid
        monkeypatch.setattr(os, "lstat", lambda at, *a, **k: os.stat_result((*real_lstat(at, *a, **k)[:4], owner + 1, *real_lstat(at, *a, **k)[5:])) if Path(at) == data else real_lstat(at, *a, **k))
        why = "belongs to another user"
    assert starter.active_update(data, tell=True) is None
    said = capsys.readouterr().err
    assert f"{data} {why}" in said, said


def test_a_way_to_the_data_folder_that_cannot_be_followed_runs_no_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    an_update_that_leaves_a_mark(data)
    monkeypatch.setattr(_folders, "_walk", lambda folder: ([Path(os.path.abspath(folder))], False))
    monkeypatch.setattr(starter, "_folders", [_folders])  # (this copy's _folders, as the starter loads it, with that walk)
    assert starter.active_update(data, tell=True) is None
    assert "cannot be looked at" in capsys.readouterr().err
