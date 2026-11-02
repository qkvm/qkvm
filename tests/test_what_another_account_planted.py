"""What another account put in the data folder while it was open stays that account's: not used as qKVM's own, and said.

The round 3 review (M1, review-core3\\probes\\p4_planted_files_keep_their_owner.py): the owner of a file may always read
and change its ACL, whatever the folder above says. Files another account planted while the data folder was open (a 0.2.0
wall's folder on a drive that gives Authenticated Users Modify, all its life) stayed that account's: qkvm.log took the
setup code into a file that account owns, and a junction planted as `tls` took the wall's HTTPS key into a folder of that
account's. On both systems now: a `tls` that is a link, or another account's, is refused by ensure_certificate (nothing is
written into it); a certificate or key in it that is a link, or another account's, is not used and is replaced; and where
the data folder is open, every start names the entries in it that are links or another account's. (Since the round 4
review, M2: at every start, open or not, and those with a name of qKVM's own, as tls and qkvm.log below, are refused: the
last test here is one of those now; tests/test_what_was_planted_is_refused_at_every_start.py.)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import _folders, tlscert
from qkvm.cli import main as run_cli

WINDOWS = sys.platform == "win32"


def link(made: Path, to: Path) -> None:
    """A link to a folder: a junction on Windows (no right needed to make one), a symlink elsewhere."""
    if WINDOWS:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(made), str(to)], check=True, capture_output=True)
    else:
        made.symlink_to(to, target_is_directory=True)


def another_owner(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """`path` stands for what another account made (making one takes an elevated console, or root): its owner is told so."""
    if WINDOWS:
        real_security = _folders._security
        monkeypatch.setattr(_folders, "_security", lambda win, at: ("S-1-5-19", []) if Path(at) == path else real_security(win, at))
    else:
        owner = os.lstat(path).st_uid
        real_lstat = os.lstat
        monkeypatch.setattr(os, "lstat", lambda at, *a, **k: os.stat_result((*real_lstat(at, *a, **k)[:4], owner + 1, *real_lstat(at, *a, **k)[5:])) if Path(at) == path else real_lstat(at, *a, **k))


def open_folder(folder: Path) -> Path:
    """A folder everybody may change: as a drive other than the system's gives it on Windows, mode 0777 elsewhere."""
    folder.mkdir(parents=True)
    if WINDOWS:
        subprocess.run(["icacls", str(folder), "/grant", "*S-1-5-11:(OI)(CI)M"], check=True, capture_output=True)
    else:
        os.chmod(folder, 0o777)
    return folder


def test_a_tls_folder_that_is_a_link_is_refused_and_nothing_is_written_into_it(tmp_path: Path) -> None:
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    link(data / "tls", theirs)
    with pytest.raises(tlscert.NotOurs, match="is a link"):
        tlscert.ensure_certificate(data / "tls", ["127.0.0.1"])
    assert list(theirs.iterdir()) == []  # the wall's HTTPS key is not written into a folder of somebody else's


def test_a_tls_folder_of_another_account_is_refused_and_nothing_is_written_into_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tls = tmp_path / "data" / "tls"
    tls.mkdir(parents=True)
    another_owner(monkeypatch, tls)
    with pytest.raises(tlscert.NotOurs, match="belongs to another account"):
        tlscert.ensure_certificate(tls, ["127.0.0.1"])
    assert list(tls.iterdir()) == []


def test_a_key_in_the_tls_folder_that_is_another_accounts_is_not_used_but_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tls = tmp_path / "data" / "tls"
    _, key, first = tlscert.ensure_certificate(tls, ["127.0.0.1"])
    another_owner(monkeypatch, key)  # (planted by another account, who knows what is in it)
    _, _, second = tlscert.ensure_certificate(tls, ["127.0.0.1"])
    assert second != first  # a pair of the wall's own, made anew


def test_where_the_data_folder_is_open_what_is_in_it_and_is_a_link_or_another_accounts_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = open_folder(tmp_path / "data")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link(data / "tls", elsewhere)
    (data / "qkvm.log").write_text("", encoding="utf-8")
    another_owner(monkeypatch, data / "qkvm.log")
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert "tls (a link)" in said and "qkvm.log (another account's)" in said, said
    # (The link deleted, as a link; qkvm.log taken over, never deleted: it may be the wall's own. The round 5 review, M1.)
    said = " ".join(said.split())
    assert "delete it while qKVM is stopped (the link alone" in said and "do not delete it, that loses the log (qkvm.log). Take it over" in said, said
