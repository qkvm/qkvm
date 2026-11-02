"""The lines the start gives on Windows say which console they are for, and where a path holds a character PowerShell would
expand ($, a backtick) the PowerShell form is given too (the round 4 review, L2; review-core4\\probes\\p3_dollar.ps1).

The lines were for Command Prompt and did not say so. Pasted into PowerShell (Windows Terminal's default), a data folder
named qkvm$zz9 became "qkvm" (the variable $zz9 is empty), and the line made the folder beside it private, not the data
folder, which stayed open. Now: "in Command Prompt: ..."; and with such a path "in PowerShell: ..." as well, the paths in
single quotes (nothing expanded), and del and rmdir through cmd (PowerShell's own would go into what a link leads to).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import _folders
from qkvm.cli import main as run_cli

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Command Prompt and PowerShell are Windows'")


def opened(folder: Path) -> Path:
    folder.mkdir(parents=True)
    subprocess.run(["icacls", str(folder), "/grant", "*S-1-5-11:(OI)(CI)M"], check=True, capture_output=True)
    return folder


def said_at_start(data: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    return " ".join(capsys.readouterr().err.split())


def test_the_lines_say_their_console_and_a_path_with_a_dollar_has_the_powershell_form_that_works(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = opened(tmp_path / "drive")  # (what is made in it takes its entries: the line for each is fix_line)
    data, beside = base / "qkvm$zz9", base / "qkvm"  # (beside: where $zz9, expanded to nothing, took the line)
    data.mkdir()
    beside.mkdir()
    before = subprocess.run(["icacls", str(beside)], capture_output=True, text=True).stdout
    said = said_at_start(data, capsys)
    cmd_line = _folders.fix_line(data)
    assert f"(in Command Prompt: {cmd_line}; in PowerShell: " in said, said
    me = _folders._name(_folders._windows(), _folders._me(_folders._windows()))
    powershell = f"icacls '{data}' /inheritance:r /grant:r '{me}:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'"
    assert f"in PowerShell: {powershell}" in said, said
    ran = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell], capture_output=True, text=True)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert _folders.folder_judged(data) is None  # the data folder, made its owner's alone
    assert subprocess.run(["icacls", str(beside)], capture_output=True, text=True).stdout == before  # and nothing beside it


def test_a_path_without_such_a_character_is_given_the_command_prompt_form_alone(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = opened(tmp_path / "drive") / "data"
    data.mkdir()
    said = said_at_start(data, capsys)
    assert f"(in Command Prompt: {_folders.fix_line(data)})" in said and "in PowerShell" not in said, said
    assert subprocess.run(_folders.fix_line(data), shell=True, capture_output=True).returncode == 0  # (cmd, as printed)
    assert _folders.folder_judged(data) is None


def test_a_removal_line_in_powershell_removes_the_link_alone(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # (Since the round 5 review, below: by PowerShell's own, never through cmd /c. A link to a folder by
    # [System.IO.Directory]::Delete, which removes the link alone: Windows PowerShell's Remove-Item asks there whether to
    # remove all the children as well, and fails where it may not ask.)
    data = tmp_path / "data$x"
    data.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "kept.txt").write_text("not the wall's\n", encoding="utf-8")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(data / "tls"), str(elsewhere)], check=True, capture_output=True)
    said = said_at_start(data, capsys)
    powershell = f"[System.IO.Directory]::Delete('{data / 'tls'}')"
    assert f'in Command Prompt: rmdir "{data / "tls"}"' in said and f"in PowerShell: {powershell}" in said, said
    ran = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell], capture_output=True, text=True)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert not (data / "tls").exists() and (elsewhere / "kept.txt").exists()


def test_the_powershell_form_of_a_removal_keeps_its_path_whole(tmp_path: Path) -> None:
    # The round 5 review (a LOW, review-core5\probes\p7_powershell_form.py): the PowerShell form handed the path to cmd /c in
    # single quotes, which PowerShell takes off: cmd got it bare. A data folder named "wall$1&old": the form of the line that
    # removes its tls folder removed the folder beside it, "wall$1", and left tls. Now by PowerShell's own, the path whole.
    from qkvm.cli import _removal

    data = tmp_path / "wall$1&old"
    (data / "tls").mkdir(parents=True)
    (data / "tls" / "key.pem").write_text("k", encoding="utf-8")
    (data / "qkvm.log").write_text("", encoding="utf-8")
    beside = tmp_path / "wall$1"
    beside.mkdir()
    (beside / "keep.txt").write_text("not to be removed", encoding="utf-8")
    forms = []
    for entry, expected in ((data / "tls", f"Remove-Item -LiteralPath '{data / 'tls'}' -Recurse"), (data / "qkvm.log", f"Remove-Item -LiteralPath '{data / 'qkvm.log'}'")):
        said = _folders.for_consoles(_removal(entry))
        form = said.split("; in PowerShell: ", 1)[1]
        assert form == expected and "cmd /c" not in said, said
        forms.append(form)
    ran = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "; ".join(forms)], capture_output=True, text=True, cwd=tmp_path)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert sorted(p.name for p in data.iterdir()) == [] and (beside / "keep.txt").exists()
