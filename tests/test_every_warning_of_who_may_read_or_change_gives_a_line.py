"""The two warnings that gave only words give the lines to run, as the others do, and each works as printed (round 4,
after the report: the coordinator's point 3).

- Files in the data folder that others may read (qkvm.json, qkvm.bak, unlock.key): "Restrict data-folder access" alone;
  on POSIX with chmod -R over the whole folder.
- An unlock file whose folder others may change: "keep it in a folder only you ... may change" alone.
Now each with its own line, POSIX and Windows: run as printed, the start or the warning says nothing more of it.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from qkvm import unlock
from qkvm.cli import main as run_cli
from tests.printed_lines import run_printed

USERS, AUTHENTICATED_USERS = "S-1-5-32-545", "S-1-5-11"
windows = pytest.mark.skipif(os.name != "nt", reason="who may read a file is kept in its ACL on Windows")
posix = pytest.mark.skipif(os.name != "posix", reason="who may read a file is kept in its mode on POSIX")


def icacls(path: Path, *arguments: str) -> None:
    subprocess.run(["icacls", str(path), *arguments], check=True, capture_output=True)


def said_at_start(data: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2  # (an offline command: it ends before serving)
    return " ".join(capsys.readouterr().err.split())


def ran(line: str) -> None:
    done = run_printed(line)
    assert done.returncode == 0, (line, done.stdout, done.stderr)


def a_key(path: Path) -> Path:
    path.write_text("k" * 44 + "\n", encoding="ascii")
    return path


# --- files in the data folder that others may read --------------------------------------------------------------------


@posix
def test_the_files_others_may_read_in_the_data_folder_are_given_their_lines_on_posix(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o755)
    os.chmod(data, 0o755)
    for name in (unlock.OWN, "qkvm.bak"):
        os.chmod(a_key(data / name), 0o644)
    said = said_at_start(data, capsys)
    folder = shlex.quote(str(data.resolve()))
    line = f"chmod go-rwx {folder} && chmod 600 {shlex.quote(str(data.resolve() / unlock.OWN))} {shlex.quote(str(data.resolve() / 'qkvm.bak'))}"
    assert "can be read by other users" in said and line in said and "chmod -R" not in said, (line, said)
    ran(line)
    assert "can be read by other users" not in said_at_start(data, capsys)


@windows
@pytest.mark.parametrize("how", ["granted on the files", "taken from the folder"])
def test_the_files_others_may_read_in_the_data_folder_are_given_their_lines_on_windows(tmp_path: Path, capsys: pytest.CaptureFixture[str], how: str) -> None:
    from qkvm import _folders

    data = tmp_path / "data"
    data.mkdir()
    key, kept = a_key(data / unlock.OWN), a_key(data / "qkvm.bak")
    if how == "granted on the files":
        icacls(key, "/grant", f"*{USERS}:(R)")
        icacls(kept, "/grant", f"*{AUTHENTICATED_USERS}:(R)")
        lines = [f'icacls "{key}" /remove:g *{USERS}', f'icacls "{kept}" /remove:g *{AUTHENTICATED_USERS}']
    else:
        icacls(data, "/grant", f"*{USERS}:(OI)(RX)")  # (reading: the folder itself is not open to change)
        lines = [_folders.fix_line(key), _folders.fix_line(kept)]
    said = said_at_start(data, capsys)
    assert "can be read by other users" in said and all(line in said for line in lines), (lines, said)
    for line in lines:
        ran(line)
    assert "can be read by other users" not in said_at_start(data, capsys)


# --- an unlock file whose folder others may change ----------------------------------------------------------------------


@posix
def test_an_unlock_files_open_folder_is_given_its_line_on_posix(tmp_path: Path) -> None:
    folder = tmp_path / "keys"
    folder.mkdir()
    os.chmod(folder, 0o777)
    key = a_key(folder / "qkvm-unlock")
    os.chmod(key, 0o644)
    said = unlock.warning(key)
    lines = [f"chmod 600 {shlex.quote(str(key))}", f"chmod go-w {shlex.quote(str(folder))}"]
    assert said is not None and all(line in said for line in lines) and "where the folder is for it alone" in said, (lines, said)
    for line in lines:
        ran(line)
    assert unlock.warning(key) is None


@windows
@pytest.mark.parametrize("how", ["granted on the folder", "taken from above"])
def test_an_unlock_files_open_folder_is_given_its_line_on_windows(tmp_path: Path, how: str) -> None:
    from qkvm import _folders

    above = tmp_path / "drive"
    above.mkdir()
    if how == "granted on the folder":
        folder = above / "keys"
        folder.mkdir()
        icacls(folder, "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M")
        line = f'icacls "{folder}" /remove:g *{AUTHENTICATED_USERS}'
    else:
        icacls(above, "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M")
        folder = above / "keys"
        folder.mkdir()
        line = _folders.fix_line(folder)
    key = a_key(folder / "qkvm-unlock")
    icacls(key, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-3-4:F")  # the file itself its owner's alone
    said = unlock.warning(key)
    assert said is not None and line in said and "where the folder is for it alone" in said, (line, said)
    ran(line)
    assert unlock.warning(key) is None
