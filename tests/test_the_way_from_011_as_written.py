"""What the README and the security policy tell a 0.1.x owner to do is what 0.2.0 needs (the review of 850745e, W2).

The README's "From 0.1.x to 0.2.0, and back" was written before the settings were sealed with a storage key: it said to
upgrade by starting the new version on the same data folder (0.2.0 refuses a folder of 0.1.x until --migrate-vault has
converted it), and that "back to 0.1.1 works on the same data folder" (0.1.1 refuses the converted folder, and advises
moving the files aside, which leaves a new wall that anyone may claim). Going back now means the copy made before the
conversion, and every command the texts give is one the program takes.
"""
from __future__ import annotations

from pathlib import Path
import re

APP = Path(__file__).resolve().parent.parent


def section() -> str:
    readme = (APP / "README.md").read_text(encoding="utf-8")
    start = readme.index("### From 0.1.x to 0.2.0, and back")
    return readme[start : readme.index("\n### ", start + 4)]


def test_going_back_is_to_the_copy_made_before_the_conversion() -> None:
    told = section()
    assert "works on the same data folder" not in told
    assert "--migrate-vault" in told and "--verify-vault" in told
    assert re.search(r"copy (the data folder|the data volume) aside", told)
    assert "qkvm-data-before-0.2.0:/data" in told  # 0.1.1 is started on the copy, not on the converted volume


def test_a_container_is_converted_with_its_key_on_a_volume_of_its_own() -> None:
    for told in (section(), (APP / "SECURITY.md").read_text(encoding="utf-8")):
        runs = [line for line in told.splitlines() if line.startswith("docker run") and "-vault" in line]
        assert {"--migrate-vault", "--verify-vault"} <= {flag for line in runs for flag in re.findall(r"--\w+-vault", line)}
        assert runs and all("-v qkvm-keys:/keys" in line and "-v qkvm-data:/data" in line for line in runs), runs


def test_every_option_the_texts_name_is_one_the_program_takes() -> None:
    program = (APP / "qkvm" / "cli.py").read_text(encoding="utf-8")
    told = section() + (APP / "SECURITY.md").read_text(encoding="utf-8")
    commands = [line for line in told.splitlines() if re.match(r"\s*`?qkvm |\s*docker run .*qkvm/qkvm", line)]
    named = {flag for line in commands for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]+", line) if not line.lstrip().startswith("docker") or "qkvm/qkvm" in line.split(flag)[0]}
    assert {"--migrate-vault", "--verify-vault", "--vault-key-file", "--data-dir"} <= named, named
    assert all(f'"{flag}"' in program for flag in named), sorted(flag for flag in named if f'"{flag}"' not in program)


def test_a_command_that_names_a_folder_from_home_has_its_windows_form_beside_it() -> None:
    # (The fresh review of 7820bd4: `~` is a Unix shell's. cmd and Windows PowerShell hand it to qKVM as typed, and qKVM,
    # 0.1.1 as 0.2.0, takes it as typed: the way back to 0.1.1 on Windows made a new, empty wall in a folder named `~`.)
    told = section()
    backslash = chr(92)
    for folder in (".qkvm", ".qkvm.keys" + backslash + "vault.key", ".qkvm-before-0.2.0"):
        assert "%USERPROFILE%" + backslash + folder in told, folder
        assert "$HOME" + backslash + folder in told, folder
