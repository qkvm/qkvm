"""What the README says of who may write the data folder is what the program does (the review of 2026-11-01, L4 and L8).

It said "on Windows it is for you to look": since 0.2.1 the program makes the data folder and its storage key's folder
its owner's alone on Windows, says at start when a folder it finds is not, with the line that changes it, and runs no
update from a folder others may write. The lines the README offers are the ones the start prints (the round 3 review, L8).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

README = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
PASSAGE = README.split("**whoever can write to its data folder**", 1)[1].split("Stopping it this way", 1)[0]
WORDS = " ".join(PASSAGE.split())


def test_the_readme_says_what_the_program_does_with_the_data_folder_on_windows() -> None:
    assert "for you to look" not in WORDS, WORDS
    for said in ("runs no update from a folder others may write", "`<data folder>.keys`", "junction", "never changed, by any command", "takeown", "FAT or exFAT"):
        assert said in WORDS, (said, WORDS)
    assert "it makes so at a real start" not in WORDS and "drops those of whole groups" not in WORDS, WORDS  # (rounds 2 and 3; not any more)


def test_the_readme_offers_the_lines_the_start_prints_and_none_goes_into_what_is_inside() -> None:
    # (The round 3 review, L8: the README offered no line; the start's own were to be offered, as they are printed.)
    for line in (
        'icacls "D:\\qkvm-data" /inheritance:r /grant:r "PC\\you:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"',
        'icacls "D:\\qkvm-data" /remove:g *S-1-5-',
        'icacls "D:\\qkvm-data" /setowner "PC\\you"',
        'takeown /F "D:\\qkvm-data"',
        "`/L`",
    ):
        assert line in WORDS, (line, WORDS)
    offered = [line for line in PASSAGE.replace("`", "\n").splitlines() if line.startswith(("icacls ", "takeown "))]
    assert len(offered) == 4 and not [line for line in offered if {"/T", "/R", "/D"} & set(line.split())], offered


def test_the_security_policy_says_who_may_put_there_what_runs_after_an_update() -> None:
    # It said anybody who can write to the data folder can put there what qKVM runs after an update: the starter runs none
    # from a folder others may write (0.2.1), and a folder it finds is never changed, only said.
    policy = " ".join((Path(__file__).resolve().parent.parent / "SECURITY.md").read_text(encoding="utf-8").split())
    said = policy.split("- Whoever can write to the data folder", 1)[1].split("- The network between", 1)[0]
    assert "runs no update from a folder anybody else may write" in said and "never changed" in said, said


@pytest.mark.skipif(sys.platform != "win32", reason="the line the start prints on Windows")
def test_the_line_the_readme_offers_for_an_open_folder_is_the_one_the_start_prints(tmp_path: Path) -> None:
    from qkvm import _folders

    win = _folders._windows()
    printed = _folders.fix_line(tmp_path).replace(str(tmp_path), "D:\\qkvm-data").replace(_folders._name(win, _folders._me(win)), "PC\\you")
    assert printed in WORDS, (printed, WORDS)
    printed = _folders.owner_line(tmp_path).replace(str(tmp_path), "D:\\qkvm-data").replace(_folders._name(win, _folders._me(win)), "PC\\you")
    for line in ('icacls "D:\\qkvm-data" /setowner "PC\\you"', 'takeown /F "D:\\qkvm-data"'):
        assert line in printed and line in WORDS, (line, printed)


def test_the_readme_says_which_console_the_lines_are_for() -> None:
    # (The round 4 review, L2: pasted into PowerShell, a path with a $ in it named another folder.)
    for said in ("the lines are for Command Prompt", "`$`", "PowerShell form as well", "single quotes", "`cmd /c`"):
        assert said in WORDS, (said, WORDS)
