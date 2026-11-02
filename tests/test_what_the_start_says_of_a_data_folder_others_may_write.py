"""What the start says of a data folder others may write is so, and the line it gives works as printed (round 4, after the
report: the coordinator's points 2 and 3).

It said whoever can write there "can put there what it runs after an update": the starter runs no update from a folder
others may write (POSIX since 0.2.0, Windows since 0.2.1, every file of the update since r4-I3). What they can do is stop
qKVM and change its files: that is said, with the line that makes the folder yours alone.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from qkvm.cli import main as run_cli
from tests.printed_lines import run_printed
from tests.test_update import an_update_that_leaves_a_mark, typed

AUTHENTICATED_USERS = "S-1-5-11"  # everybody who signs in to the computer


def opened(tmp_path: Path) -> Path:
    """A data folder others may write, with an update in it that one of them may have put there."""
    if os.name == "nt":
        drive = tmp_path / "drive"  # (as the root of a drive other than the system's: everybody signed in may change what is made)
        drive.mkdir()
        subprocess.run(["icacls", str(drive), "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M"], check=True, capture_output=True)
        data = drive / "data"
        an_update_that_leaves_a_mark(data)
    else:
        data = tmp_path / "data"
        an_update_that_leaves_a_mark(data)
        for folder in (data, data / "updates"):
            os.chmod(folder, 0o777)
    return data


def said_at_start(data: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2  # (an offline command: it ends before serving)
    return " ".join(capsys.readouterr().err.split())


def test_what_the_start_says_others_can_do_in_an_open_data_folder_is_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = opened(tmp_path)
    said = said_at_start(data, capsys)
    assert "can put there what it runs" not in said, said
    assert "Whoever can write there can stop qKVM and change its files; it runs no update from a folder others may write" in said, said
    # Held: what was put there as an update is not run, by a real start as typed.
    done = typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path)
    assert not (data / "the-update-ran").exists() and "is not used" in done.stderr, done.stderr


def test_the_readme_says_the_same_of_who_may_write_the_data_folder() -> None:
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    passage = " ".join(readme.split("**whoever can write to its data folder**", 1)[1].split("Stopping it this way", 1)[0].split())
    assert "can put there what qKVM runs" not in passage and "can change its files" in passage, passage


def test_the_line_given_for_an_open_data_folder_works_as_printed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = opened(tmp_path)
    said = said_at_start(data, capsys)
    if os.name == "nt":
        from qkvm import _folders

        line = _folders.fix_line(data)
    else:
        line = f"chmod go-w {shlex.quote(str(data.resolve()))}"
    assert line in said, (line, said)
    assert run_printed(line).returncode == 0
    assert "can be written to by other users" not in said_at_start(data, capsys)
