"""What has the name of qKVM's own and is a link, or another account's, is refused at every start; anything else so is named
at every start (the round 4 review, M2; review-core4\\probes\\p4_planted_after_the_fix.py, p4_linux.sh).

It was named only while the data folder was open, and written through: a qkvm.log planted as a link while the folder was
open took the setup code into the other account's file, at that start and at every start after the folder was closed
(nothing said of it any more). Now: refused before anything is opened in the folder, as `tls` was (nothing written through
it, a plain message naming each with the line that removes it, status 2); other links and entries of another account at
its top are named at every start, open folder or not. On both systems.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import uvicorn

from qkvm import cli, screens
from qkvm.store import InstanceLock
from tests.printed_lines import run_printed
from tests.test_control import free_port, served_and_left
from tests.test_what_another_account_planted import another_owner, link

WINDOWS = sys.platform == "win32"


def file_link(made: Path, to: Path) -> None:
    """A link to a file: a symlink (on Windows where this account may make one)."""
    try:
        made.symlink_to(to)
    except OSError as ex:
        pytest.skip(f"this account may not make a symlink here: {ex}")


def lines_in(said: str) -> list[str]:
    """The lines given in the parentheses of what was said: each a command."""
    inside = said.rsplit("(in Command Prompt: " if WINDOWS else "(", 1)[1].rsplit(")", 1)[0]  # (the console named: on Windows, since L2)
    return [line.strip() for line in inside.split(";")]


def lines_after(said: str, words: str) -> list[str]:
    """The lines given in the parentheses that follow `words` in what was said: each a command."""
    inside = said.split(words, 1)[1].split(")", 1)[0]
    return [line.strip() for line in inside.removeprefix("in Command Prompt: ").split(";")]


def lines_below(printed: str, words: str) -> list[str]:
    """The lines printed each by itself below the one that says `words` (Windows' take-over lines): each a command, to be run
    as it is in Command Prompt, which has no ";" between two commands (the final review of 0.3.0)."""
    printed_lines = printed.splitlines()
    at = next(number for number, line in enumerate(printed_lines) if words in line)
    found = []
    for line in printed_lines[at + 1 :]:
        if not line.startswith("        "):
            break
        found.append(line.strip())
    return found


BELOW = "in an elevated console, with the lines below, each by itself in Command Prompt"


def test_a_log_planted_as_a_link_is_refused_at_a_start_of_a_closed_folder_and_nothing_is_written_through_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    data.mkdir()  # (the tests' folders are their runner's alone: closed, as after its owner ran the line given for it)
    theirs = tmp_path / "theirs.txt"
    theirs.write_text("theirs\n", encoding="utf-8")
    file_link(data / "qkvm.log", theirs)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    assert theirs.read_text(encoding="utf-8") == "theirs\n", "written through the planted link"
    assert f"qkvm: in {data}, qkvm.log (a link) is not qKVM's own: another account may have put it there, and nothing is written through it. qKVM was not started." in said, said
    assert not (data / "qkvm.json").exists() and not (data / "qkvm.lock").exists()  # (refused before anything was opened there)
    (line,) = lines_in(said)
    assert line == (f'del "{data / "qkvm.log"}"' if WINDOWS else f"rm {data / 'qkvm.log'}"), line
    assert run_printed(line).returncode == 0
    assert theirs.read_text(encoding="utf-8") == "theirs\n" and not (data / "qkvm.log").exists()
    assert cli.main(["--data-dir", str(data), "--port", free_port()]) == 0  # made its own


def test_folders_and_files_of_qkvms_own_names_that_are_links_or_another_accounts_are_all_refused_with_their_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "kept.txt").write_text("not the wall's\n", encoding="utf-8")
    link(data / "tls", elsewhere)
    link(data / "updates", elsewhere)
    (data / "audit.log").write_text("theirs\n", encoding="utf-8")
    another_owner(monkeypatch, data / "audit.log")
    # A folder another account put there, with a link in it that leads out of the data folder: its line removes it, and
    # nothing where the link leads.
    (data / "history.sqlite-wal").mkdir()
    link(data / "history.sqlite-wal" / "out", elsewhere)
    another_owner(monkeypatch, data / "history.sqlite-wal")
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    printed = capsys.readouterr().err
    said = " ".join(printed.split())
    for named in ("audit.log (another account's)", "history.sqlite-wal (another account's)", "tls (a link)", "updates (a link)"):
        assert named in said, (named, said)
    # The links are deleted, as links (as the round 3 test asked of them); what another account owns is taken over, never
    # deleted (the round 5 review, M1: it may be the wall's own; test_files_of_qkvms_own_names_another_account_owns_...).
    assert "delete them while qKVM is stopped (the links alone: what they lead to is left as it is), and it makes its own" in said, said
    removals = lines_after(said, "and it makes its own (")
    assert removals == ([f'rmdir "{data / "tls"}"', f'rmdir "{data / "updates"}"'] if WINDOWS else [f"rm {data / 'tls'}", f"rm {data / 'updates'}"]), removals
    taken = lines_below(printed, BELOW) if WINDOWS else lines_after(said, "as root (")
    assert taken == [*take_over_lines(data / "audit.log"), *take_over_lines(data / "history.sqlite-wal")], taken
    for line in removals + taken:
        assert run_printed(line).returncode == 0, line
    assert sorted(p.name for p in elsewhere.iterdir()) == ["kept.txt"] and sorted(p.name for p in data.iterdir()) == ["audit.log", "history.sqlite-wal"]
    assert sorted(p.name for p in (data / "history.sqlite-wal").iterdir()) == ["out"]
    monkeypatch.undo()
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    assert "not qKVM's own" not in capsys.readouterr().err


def test_the_screen_watchs_files_and_pictures_are_qkvms_own_names_and_refused_when_planted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The final review of 0.3.0 (core M1, review-core\probes\test_probe_screens_names.py): what the screen watching keeps in
    # the data folder (0.3.0) was not among the names a start refuses when planted, and a link named alert-pictures had
    # the alerts' pictures written where it led, and what was put there handed to admins as an alert's picture.
    for name in (screens.FILE, screens.FILE + ".new", screens.FOLDER):
        assert cli._own_name(tmp_path / name), name
    data = tmp_path / "data"
    data.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link(data / screens.FOLDER, elsewhere)
    (data / screens.FILE).write_text("{}\n", encoding="utf-8")
    another_owner(monkeypatch, data / screens.FILE)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    for named in (f"{screens.FOLDER} (a link)", f"{screens.FILE} (another account's)", f"that loses the screen alerts that stand ({screens.FILE})"):
        assert named in said, (named, said)
    assert list(elsewhere.iterdir()) == []


def take_over_lines(path: Path) -> list[str]:
    """The lines that make what is at `path` the account the tests run as: on Windows icacls /setowner, and the account's
    own entry (owning a file lets nobody read it by itself, and the entry for OWNER RIGHTS the tests' folders have, as
    Python's mkdir(mode=0o700) and 0.2.0's data folder make it, is for what is made inside only once the owner is set: the
    file was SYSTEM's and the Administrators' alone, and a run that was not elevated could not read it); chown elsewhere."""
    if WINDOWS:
        from qkvm import _folders

        win = _folders._windows()
        me = _folders._name(win, _folders._me(win))
        return [f'icacls "{path}" /setowner "{me}"', f'icacls "{path}" /grant "{me}:F"']
    import pwd

    return [f"chown {pwd.getpwuid(os.getuid()).pw_name} {path}"]


def test_files_of_qkvms_own_names_another_account_owns_are_taken_over_and_never_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The round 5 review (M1, review-core5\probes\p3_refused.py, p3_linux_root.py): a wall's folder restored with its owners
    # kept, or a service's folder where an administrator (root) runs an offline command: the files are the wall's own, and
    # another account's. The lines given deleted them, and with qkvm.json and qkvm.bak every account and saved password. Now
    # each such file is taken over (made the account qKVM runs as), never deleted, and the words say what deleting loses.
    data = tmp_path / "data"
    data.mkdir()
    names = ("audit.log", "history.sqlite", "qkvm.bak", "qkvm.json", "unlock.key")
    for name in names:
        (data / name).write_text("the wall's own\n", encoding="utf-8")
        another_owner(monkeypatch, data / name)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    printed = capsys.readouterr().err
    said = " ".join(printed.split())
    for removal in ("del ", "rm ", "rmdir", "Remove-Item"):
        assert removal not in said, (removal, said)
    assert "do not delete them, that loses every account and saved password (qkvm.bak, qkvm.json)" in said, said
    lines = lines_below(printed, BELOW) if WINDOWS else lines_after(said, "as root (")
    assert lines == [line for name in names for line in take_over_lines(data / name)], lines
    for line in lines:
        assert run_printed(line).returncode == 0, line
    assert all((data / name).read_text(encoding="utf-8") == "the wall's own\n" for name in names)
    monkeypatch.undo()  # (taken over: the account the tests run as owns them, as it really does)
    cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"])
    assert "not qKVM's own" not in capsys.readouterr().err


@pytest.mark.skipif(WINDOWS, reason="the image is Linux")
def test_in_the_image_the_take_over_lines_say_they_are_the_containers_and_name_its_user_by_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # (0.3.0, section 5; a low of 0.2.1's final review.) Inside the image the lines named paths inside the container and its
    # user by the name it has there (qkvm), which the host does not know: run as printed on the host, they took nothing over.
    # The user is named by its number, the same on the host, and the words say where the paths are and how to run the lines.
    data = tmp_path / "data"
    data.mkdir()
    (data / "qkvm.json").write_text("the wall's own\n", encoding="utf-8")
    another_owner(monkeypatch, data / "qkvm.json")
    monkeypatch.setenv("QKVM_CONTAINER", "1")
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    assert lines_after(said, "as root (") == [f"chown {os.getuid()} {data / 'qkvm.json'}"], said
    assert "paths inside the container" in said and "docker run --rm -u root" in said, said


def test_beside_a_running_copy_another_copy_is_running_is_said_and_not_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The round 5 review (M2, review-core5\probes\p11_running_service_lock.py): a wall that runs as a service (its files the
    # service's), and an administrator's start for the same folder. The refusal came before the lock was asked, and its lines
    # deleted the running wall's qkvm.lock: run as printed, a second wall wrote the same folder. The lock is asked first.
    data = tmp_path / "data"
    data.mkdir()
    running = InstanceLock(data)
    assert running.acquire()
    try:
        (data / "qkvm.log").write_text("", encoding="utf-8")
        for name in ("qkvm.lock", "qkvm.log"):
            another_owner(monkeypatch, data / name)
        assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
        said = " ".join(capsys.readouterr().err.split())
        assert f"qkvm: another copy is already running with {data}" in said, said
        assert "not qKVM's own" not in said and str(data / "qkvm.lock") not in said, said
    finally:
        running.release()


def test_no_line_given_touches_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # (Where no copy holds the lock now: the refusal, and no line for qkvm.lock in it, a link or another account's; the lock is
    # what a copy that runs holds, and one may start between the refusal and the line.)
    data = tmp_path / "data"
    data.mkdir()
    (data / "qkvm.lock").write_text("", encoding="utf-8")
    (data / "qkvm.json").write_text("the wall's own\n", encoding="utf-8")
    for name in ("qkvm.lock", "qkvm.json"):
        another_owner(monkeypatch, data / name)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    printed = capsys.readouterr().err
    said = " ".join(printed.split())
    assert "qkvm.json (another account's), qkvm.lock (another account's) are not qKVM's own" in said, said
    taken = lines_below(printed, BELOW) if WINDOWS else lines_after(said, "as root (")
    assert str(data / "qkvm.lock") not in said and taken == take_over_lines(data / "qkvm.json"), said
    assert "no line is given for it: once no copy of qKVM runs with this folder" in said, said


def test_what_qkvm_reads_beside_its_own_files_is_refused_as_they_are_and_by_any_case_its_file_system_ignores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The round 5 review (a LOW): files qKVM reads were not among its own names, and another account's (or a link) was read:
    # SQLite's rollback journals (a hot one is played into its database when that is opened), the migration's recovery
    # archive, settings set aside as damaged. And an own name is one by any case where the file system ignores case.
    data = tmp_path / "data"
    data.mkdir()
    (data / "case").write_text("", encoding="utf-8")
    ignores_case = (data / "CASE").exists()
    (data / "case").unlink()
    names = ["Audit.SQLite-Journal", "history.sqlite-journal", "qkvm.damaged-1700000000.json", "vault-migration.recovery"]
    for name in names:
        (data / name).write_text("theirs\n", encoding="utf-8")
        another_owner(monkeypatch, data / name)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    refused = said.split(" not qKVM's own", 1)[0] if " not qKVM's own" in said else ""
    for name in names[1:]:
        assert f"{name} (another account's)" in refused, (name, said)
    assert ("Audit.SQLite-Journal (another account's)" in refused) == ignores_case, said


def test_other_links_at_the_top_of_a_closed_data_folder_are_named_at_every_start(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    data.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link(data / "notes", elsewhere)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    assert f"qkvm: in {data}, notes (a link) may have been put there by somebody else." in said, said
    assert "not qKVM's own" not in said and "there is no account called nobody" in said, said  # (named, not refused)
    (line,) = lines_in(said.split("may have been put there by somebody else.", 1)[1].split("qkvm:", 1)[0])
    assert line == (f'rmdir "{data / "notes"}"' if WINDOWS else f"rm {data / 'notes'}"), line


@pytest.mark.skipif(os.name != "posix", reason="a link on POSIX")
def test_a_log_planted_as_a_link_in_an_open_folder_on_posix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # (p4_linux.sh: the folder open, the link planted, the start: the setup code in the file outside.)
    data = tmp_path / "data"
    data.mkdir()
    os.chmod(data, 0o777)
    theirs = tmp_path / "log.txt"
    theirs.write_text("", encoding="utf-8")
    (data / "qkvm.log").symlink_to(theirs)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 2
    assert theirs.read_text(encoding="utf-8") == "" and "qkvm.log (a link) is not qKVM's own" in capsys.readouterr().err
