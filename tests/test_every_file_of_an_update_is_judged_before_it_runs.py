"""The starter judges every file and folder of an installed update before it runs it (the first review of 0.2.1, I3).

It judged four paths (updates/, current.json, the version's folder, its qkvm folder) for who may write them, and nothing in
the package: a file in it that another account may change, or a link in it to another place, had that account's code run
as the wall, by the account that holds every device password. Now all of it, on Windows and on POSIX, by the same rule,
without following a link: a link is refused, whatever it leads to.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import __main__ as starter
from tests.test_update import an_update_that_leaves_a_mark, typed

AUTHENTICATED_USERS = "S-1-5-11"  # everybody who signs in to the computer
windows = pytest.mark.skipif(os.name != "nt", reason="who may write a file is kept in its ACL on Windows")
posix = pytest.mark.skipif(os.name != "posix", reason="who may write a file is kept in its mode on POSIX")


def an_update(data: Path) -> Path:
    """An installed update with a folder in it, and a file in that, as a real one has (static/): returns its qkvm folder."""
    an_update_that_leaves_a_mark(data)
    package = data / "updates" / "9.9.9" / "qkvm"
    (package / "static").mkdir()
    (package / "static" / "app.js").write_text("// the page\n", encoding="utf-8")
    (package / "video.py").write_text("# run as the wall\n", encoding="utf-8")
    assert starter.active_update(data) == package  # (the tests' folders are their runner's alone, as a data folder is)
    return package


def open_to_others(path: Path) -> None:
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/grant", f"*{AUTHENTICATED_USERS}:(M)"], check=True, capture_output=True)
    else:
        os.chmod(path, 0o777 if path.is_dir() else 0o666)


def link(at: Path, to: Path) -> None:
    """A link at `at` to `to`: a symlink (a junction where Windows will not let this account make one, to a folder)."""
    try:
        at.symlink_to(to, target_is_directory=to.is_dir())
    except OSError:
        if os.name != "nt" or not to.is_dir():
            pytest.skip("this account may not make a symlink here")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(at), str(to)], check=True, capture_output=True)


@pytest.mark.parametrize("inside", ["video.py", "static", "static/app.js", "__init__.py"])
def test_a_file_or_folder_in_the_update_that_others_may_change_has_it_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str], inside: str) -> None:
    data = tmp_path / "data"
    package = an_update(data)
    if inside == "__init__.py":
        (package / inside).write_text("", encoding="utf-8")
    open_to_others(package / inside)
    assert starter.active_update(data, tell=True) is None
    said = capsys.readouterr().err
    assert f"{package / inside} can be written to by others" in said or f"{package / inside} can be written to by other users" in said, said


@pytest.mark.parametrize("what", ["a file", "a folder"])
def test_a_link_in_the_update_is_refused_whatever_it_leads_to(tmp_path: Path, capsys: pytest.CaptureFixture[str], what: str) -> None:
    # (To something of this account's alone: a link is not followed, and so not judged by where it leads.)
    data = tmp_path / "data"
    package = an_update(data)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "tiles.py").write_text("# somebody's\n", encoding="utf-8")
    at = package / ("tiles.py" if what == "a file" else "more")
    link(at, elsewhere / "tiles.py" if what == "a file" else elsewhere)
    assert starter.active_update(data, tell=True) is None
    said = capsys.readouterr().err
    assert f"{at} is a link" in said, said


def test_an_update_whose_qkvm_folder_is_a_link_is_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    package = an_update(data)
    moved = tmp_path / "moved-qkvm"
    package.rename(moved)
    link(package, moved)
    assert starter.active_update(data, tell=True) is None
    assert f"{package} is a link" in capsys.readouterr().err


def test_a_real_package_is_run_and_judged_in_a_few_milliseconds(tmp_path: Path) -> None:
    # (No refusal of what is well: this copy's own package, with what Python wrote beside its code, as an update.)
    import time

    data = tmp_path / "data"
    package = data / "updates" / "9.9.9" / "qkvm"
    # (Written anew, as the installer writes it, and not copied with the modes of the tree the tests run from: in WSL a
    # Windows drive shows every file as everybody's to write.)
    source = Path(starter.__file__).parent
    for path in sorted(source.rglob("*")):
        if path.is_dir():
            (package / path.relative_to(source)).mkdir(parents=True, exist_ok=True)
        else:
            (package / path.relative_to(source)).parent.mkdir(parents=True, exist_ok=True)
            (package / path.relative_to(source)).write_bytes(path.read_bytes())
    (package / "_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (data / "updates" / "current.json").write_text('{"version": "9.9.9", "previous": null}', encoding="utf-8")
    starter.active_update(data)  # (the first look loads what judges a file on Windows)
    began = time.perf_counter()
    assert starter.active_update(data) == package
    assert time.perf_counter() - began < 1.0  # (generous: a slow machine; what it costs is said in the report)


@posix
def test_what_python_writes_beside_the_update_under_a_lenient_umask_does_not_refuse_it_later(tmp_path: Path) -> None:
    # The update's code is imported by an offline command typed in a shell whose umask lets a group write (002): Python
    # made __pycache__ by that umask, the next start judged it with the package, and passed the update over for good.
    data = tmp_path / "data"
    mark = an_update_that_leaves_a_mark(data)
    before = os.umask(0o002)
    try:
        # (Python writing what it compiles, as it does unless told otherwise: the test runner may have told it.)
        assert typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path, PYTHONDONTWRITEBYTECODE="").returncode == 0 and mark.exists()
    finally:
        os.umask(before)
    cache = data / "updates" / "9.9.9" / "qkvm" / "__pycache__"
    assert cache.is_dir() and not stat.S_IMODE(cache.stat().st_mode) & 0o022, oct(cache.stat().st_mode)
    assert starter.active_update(data) is not None


@windows
def test_a_file_in_the_update_whose_entry_lets_others_change_it_is_named_on_windows(tmp_path: Path) -> None:
    # A real start, as typed: nothing of the update runs.
    data = tmp_path / "data"
    mark = an_update_that_leaves_a_mark(data)
    open_to_others(data / "updates" / "9.9.9" / "qkvm" / "cli.py")
    said = typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path)
    assert not mark.exists(), said.stderr
    assert "cli.py can be written to by other users" in said.stderr and "is not used" in said.stderr, said.stderr


@pytest.mark.skipif(sys.platform != "win32" or not hasattr(os, "symlink"), reason="a junction is Windows'")
def test_a_junction_in_the_update_is_refused(tmp_path: Path) -> None:
    data = tmp_path / "data"
    package = an_update(data)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(package / "static" / "more"), str(elsewhere)], check=True, capture_output=True)
    assert starter.active_update(data) is None
    assert starter.not_whole(package) == (package / "static" / "more", "is a link")
