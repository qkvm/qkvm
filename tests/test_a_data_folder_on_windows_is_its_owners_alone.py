"""On Windows, the data folder is its owner's alone (with SYSTEM and the Administrators), and no update that others may
write is run.

The storage review of 0.2.0 (storage\\probes\\win_acl_probe.py, win_starter_runs_planted.py): on Windows nothing looked at
who may write the data folder. The starter's check (__main__.not_own) said "fine" without looking, and the data folder took
whatever its drive gives: on a drive other than the system's, Authenticated Users may change it (Python before 3.12.4
ignores the mode mkdir is given there, too). Any user of the computer could put an update in updates/, have it named in
current.json, and write "restart" into qkvm.ask: their code ran as the wall, with every device password. And what is in
the folder (tls\\key.pem, qkvm.log with the setup code, unlock.key, audit.log, history.sqlite) was theirs to read.

Now (the owner's decision of 2026-11-01: on Windows as on Linux) what qKVM makes is its own from its first instant: the
data folder and <data>.keys with a protected ACL (this account, SYSTEM, the Administrators) given as they are made, and
every file it writes in them (_folders.open_private). A folder it finds, any link on the way and the folder behind a link
are never changed, by any command, elevated or not: every start says what they let others do, with the lines that change
it, for whoever owns them to run. The starter runs no update from a data folder, a way to it, an update folder,
current.json, a version folder or a file in the package that is not this account's (or SYSTEM's, or the
Administrators') or that others may write, as _vault_windows.validate_private refuses a key.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

import qkvm
from qkvm import __main__ as starter
from qkvm.cli import main as run_cli
from tests.test_update import an_update_that_leaves_a_mark, typed
from tests.test_wall import closed_port

pytestmark = pytest.mark.skipif(os.name != "nt", reason="who may write a folder is kept in its ACL on Windows")

AUTHENTICATED_USERS = "S-1-5-11"  # everybody who signs in to the computer ("AU" in the language of ACLs)
USERS = "S-1-5-32-545"  # the computer's Users group ("BU")
LOCAL_SERVICE = "S-1-5-19"  # ("LS"): stands in for a service's account
APP = Path(qkvm.__file__).resolve().parent.parent


def icacls(path: Path, *arguments: str) -> str:
    done = subprocess.run(["icacls", str(path), *arguments], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def entries(path: Path, scratch: Path) -> list[tuple[str, str, str]]:
    """The access entries of what is at `path`, as icacls saves them (the language of ACLs): (kind and flags, rights, whose)."""
    saved = scratch / "acl.txt"
    saved.unlink(missing_ok=True)
    icacls(path, "/save", str(saved))
    text = saved.read_bytes().decode("utf-16-le").splitlines()[1]
    return [(f"{kind};{flags}", rights, whose) for kind, flags, rights, whose in re.findall(r"\(([A-Z]+);([A-Z]*);([^;]*);[^;]*;[^;]*;([^;)]+)\)", text.split("D:", 1)[1])]


def open_to_everybody_signed_in(folder: Path) -> Path:
    """A folder in which everybody who signs in to the computer may change what is made: as the root of a drive other than
    the system's gives it."""
    folder.mkdir(parents=True)
    icacls(folder, "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M")
    return folder


def test_a_data_folder_made_where_everybody_may_write_is_its_owners_alone(tmp_path: Path) -> None:
    drive = open_to_everybody_signed_in(tmp_path / "drive")
    data = drive / "data"
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2  # (a start that ends at once: no such account)
    whose = {whose for _, _, whose in entries(data, tmp_path)}
    assert "AU" not in whose and AUTHENTICATED_USERS not in whose, entries(data, tmp_path)
    assert whose >= {"SY", "BA"}, whose
    assert all("ID" not in kind for kind, _, _ in entries(data, tmp_path))  # protected: nothing taken from the drive
    for made in (data / "qkvm.log", data / "qkvm.json"):
        if made.exists():
            assert "AU" not in {whose for _, _, whose in entries(made, tmp_path)}, made


def started_once(data: Path, tmp_path: Path) -> str:
    """A real start of the wall on `data` (it serves), stopped again once it answers. What it said at start."""
    environment = {**os.environ, "PYTHONPATH": str(APP), "QKVM_CHILD": "1", "PYTHONDONTWRITEBYTECODE": "1"}  # (the program itself, no starter)
    port = closed_port()
    said = tmp_path / f"started-{port}.txt"
    with said.open("w", encoding="utf-8") as out:
        wall = subprocess.Popen(
            [sys.executable, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", str(port), "--bind", "local"],
            env=environment, cwd=tmp_path, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT,
        )  # fmt: skip
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert wall.poll() is None and time.monotonic() < deadline, said.read_text(encoding="utf-8")
            time.sleep(0.3)
    finally:
        environment.pop("QKVM_CHILD")
        subprocess.run([sys.executable, "-P", "-m", "qkvm", "stop", "--data-dir", str(data)], env=environment, cwd=tmp_path, capture_output=True, timeout=90)
        try:
            wall.wait(60)
        except subprocess.TimeoutExpired:
            wall.kill()
            wall.wait(10)
    return said.read_text(encoding="utf-8")


def test_a_data_folder_found_open_to_others_is_left_as_it_is_found_and_said_at_a_real_start(tmp_path: Path) -> None:
    # (Rounds 1 to 3 made it private at a real start, and what was in it with it. The owner's decision of 2026-11-01: a
    # found folder is never changed; it is said, with a fix that works.)
    drive = open_to_everybody_signed_in(tmp_path / "drive")
    data = drive / "data"
    data.mkdir()  # as a person makes it, with Explorer or mkdir: it takes the drive's entries
    (data / "unlock.key").write_text("a key that somebody else could have read until now, long enough\n", encoding="ascii")
    (data / "tls").mkdir()
    (data / "tls" / "key.pem").write_text("not a real key\n", encoding="ascii")
    looked_at = (data, data / "unlock.key", data / "tls", data / "tls" / "key.pem")
    before = [entries(path, tmp_path) for path in looked_at]
    said = started_once(data, tmp_path)
    assert [entries(path, tmp_path) for path in looked_at] == before
    assert f"{data} can be written to by other users" in said and "unlock.key" in said, said


def linked(kind: str, tmp_path: Path) -> tuple[Path, Path]:
    """A data folder reached through a link (`mklink /J`, a junction, or `/D`, a folder symlink), as Windows people move a
    folder to another drive: the folder itself where everybody signed in may change it. (The link, the folder.)"""
    drive = open_to_everybody_signed_in(tmp_path / "drive")
    real = drive / "qkvm"
    (real / "tls").mkdir(parents=True)
    (real / "tls" / "key.pem").write_text("not a real key\n", encoding="ascii")
    link = tmp_path / ".qkvm"
    made = subprocess.run(["cmd", "/c", "mklink", kind, str(link), str(real)], capture_output=True, text=True)
    if made.returncode != 0:  # (a folder symlink takes the right to make one: Developer Mode, or an elevated console)
        pytest.skip(f"this account may not make a link with mklink {kind} here: {made.stdout.strip()} {made.stderr.strip()}")
    return link, real


@pytest.mark.parametrize("kind", ["/J", "/D"], ids=["junction", "symlink"])
def test_a_data_folder_reached_by_a_link_is_said_to_be_open_where_its_files_are(tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str) -> None:
    # The review of 2026-11-01 (M2, review-core\probes\test_review_core_junction_data_folder.py): the link was read and set,
    # the folder where everything lies kept the drive's entries, and the start said nothing. An offline command changes
    # nothing (L3): it says that the folder the link leads to is open.
    from qkvm import _folders

    link, real = linked(kind, tmp_path)
    assert run_cli(["--data-dir", str(link), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert _folders.not_alone(real) is not None
    assert f"leads to {real}" in said and "can be written to by other users" in said, said


@pytest.mark.parametrize("kind", ["/J", "/D"], ids=["junction", "symlink"])
def test_a_data_folder_reached_by_a_link_is_left_as_it_is_found_and_said_at_a_real_start(tmp_path: Path, kind: str) -> None:
    # (4484841 made the link and the folder behind it private at a real start. Under the owner's decision both are left as
    # they are found, and said.)
    link, real = linked(kind, tmp_path)
    looked_at = (link, real, real / "tls" / "key.pem")
    before = [entries(path, tmp_path) for path in looked_at]
    said = started_once(link, tmp_path)
    assert [entries(path, tmp_path) for path in looked_at] == before
    assert f"{link} leads to {real}, which can be written to by other users" in said, said


def test_the_storage_keys_folder_made_where_everybody_may_write_is_its_owners_alone_on_every_python(tmp_path: Path) -> None:
    # The review of 2026-11-01 (L1, review-core\probes\win_upgrade_020_to_021.py): <data>.keys was made with mkdir(mode=0o700),
    # which Python before 3.12.4 ignores on Windows; any user of the computer could take the key folder away or put another
    # in its place (the key itself is private: the wall then does not start).
    from qkvm import vault_storage

    drive = open_to_everybody_signed_in(tmp_path / "drive")
    vault_storage.create_key(drive / "data.keys" / "vault.key")
    assert {whose for _, _, whose in entries(drive / "data.keys", tmp_path)} >= {"SY", "BA"}
    assert "AU" not in {whose for _, _, whose in entries(drive / "data.keys", tmp_path)}, entries(drive / "data.keys", tmp_path)
    assert all("ID" not in kind for kind, _, _ in entries(drive / "data.keys", tmp_path))


def test_the_storage_keys_folder_found_open_is_said_and_left_as_it_is_found(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # (42aa447 made it private at a real start. Under the owner's decision it is said, by every command, and left as found.)
    drive = open_to_everybody_signed_in(tmp_path / "drive")
    data, keys = drive / "qkvm", drive / "qkvm.keys"
    keys.mkdir()  # as 0.2.0 made it on Python 3.11: it took the drive's entries
    before = entries(keys, tmp_path)
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert f"{keys}, where the storage key is kept, can be written to by other users" in said, said
    # A real start makes no key in it (the round 4 review, L5: as on Linux, create_key refuses such a folder): it ends, said,
    # and the folder is left as it was found. (It started, and made the key there, before.)
    environment = {**os.environ, "PYTHONPATH": str(APP), "QKVM_CHILD": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", str(closed_port()), "--bind", "local"], env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    said = done.stdout + done.stderr
    assert done.returncode == 2 and "the vault key directory must belong to the server and not be writable by others" in said, said
    assert entries(keys, tmp_path) == before and not (keys / "vault.key").exists()
    assert "where the storage key is kept, can be written to by other users" in said, said


def test_an_unlock_file_qkvm_makes_is_its_owners_alone_from_its_first_moment(tmp_path: Path) -> None:
    # The review of 2026-11-01 (L2, review-core\probes\win_unlock_file_unchecked.out.txt): made with mode 0o600, which Windows
    # does not keep, the file took its folder's entries: `qkvm --unlock-file D:\keys\qkvm-unlock` made a key any user of the
    # computer could read and change, and nothing was said.
    from qkvm import unlock

    drive = open_to_everybody_signed_in(tmp_path / "drive")
    data = tmp_path / "data"
    data.mkdir()
    given, made = unlock.secret_in(drive / "qkvm-unlock", data)
    assert made and len(given) >= unlock.SHORTEST
    assert "AU" not in {whose for _, _, whose in entries(drive / "qkvm-unlock", tmp_path)}, entries(drive / "qkvm-unlock", tmp_path)
    assert unlock.secret_in(drive / "qkvm-unlock", data) == (given, False)  # (and read back as it was written)
    own = unlock.own_secret(drive)  # qKVM's own key, in a folder of its own that others may change: the same
    assert "AU" not in {whose for _, _, whose in entries(drive / unlock.OWN, tmp_path)} and len(own) >= unlock.SHORTEST


def test_an_unlock_file_others_may_read_or_change_is_said_to_be_so_on_windows(tmp_path: Path) -> None:
    from qkvm import _folders, unlock

    given = tmp_path / "qkvm-unlock"
    given.write_text("x" * 44 + "\n", encoding="ascii")
    assert unlock.what_others_may(given) == [] and unlock.warning(given) is None  # (the tests' folders are their runner's alone)
    icacls(given, "/grant", f"*{USERS}:(R)")
    assert unlock.what_others_may(given) == ["read"]
    icacls(given, "/grant", f"*{AUTHENTICATED_USERS}:(M)")
    assert unlock.what_others_may(given) == ["read", "changed"]
    said = unlock.warning(given)
    # (Both entries were granted on the file itself, which a line that sets its own entries keeps: each is removed by a
    # line of its own, printed.)
    lines = [f'icacls "{given}" /remove:g *{USERS}', f'icacls "{given}" /remove:g *{AUTHENTICATED_USERS}']
    assert said is not None and "can be read and changed by other users" in said and all(line in said for line in lines) and "chmod" not in said, said
    for line in lines:
        assert subprocess.run(line, shell=True, capture_output=True).returncode == 0  # (each line as printed, run)
    assert unlock.what_others_may(given) == [] and _folders.not_alone(given) is None


# --- what the start says to do (the review of 2026-11-01, L8) ---------------------------------------------------------


def test_a_data_folder_of_another_account_is_said_with_how_to_take_it_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # (Another owner takes an elevated console to set: what the ACL says is stood in for.) The advice was the folder's
    # entries in its Properties, which do not change who owns it: every start said "belongs to another user" again.
    from qkvm import _folders

    data = tmp_path / "data"
    data.mkdir()
    real_security = _folders._security
    monkeypatch.setattr(_folders, "_security", lambda win, path: ("S-1-5-19", []) if Path(path) == data else real_security(win, path))
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    # takeown makes the console's own account the owner; a service's folder is to be the service account's: the line that
    # names the owner is given beside it (the round 2 review's note 7), with the account qKVM runs as here filled in. Neither
    # goes into what is in the folder (no /T, no /R: the round 3 review, L6, as a junction inside would be followed).
    me = _folders._name(_folders._windows(), _folders._me(_folders._windows()))
    assert "belongs to another user" in said and f'takeown /F "{data}" ' in said and f'icacls "{data}" /setowner "{me}" ' in said, said
    assert "service's account" in said and "/T" not in said and "/R" not in said, said


def test_an_entry_of_one_account_of_its_own_is_named_with_how_to_remove_it(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # An entry of one account of its own: Explorer's Continue, pressed on a folder that the account looking cannot open,
    # gives one; so may an admin's start (whose account is kept now: round 2 review, LOW-1), or a grant on purpose. Every
    # update was refused as "can be written to by other users", and nothing said which entry. It is named, with how to
    # remove it, and with where it may come from: not with Explorer's story told as what happened (the review, LOW-1 c).
    from qkvm import _folders

    win = _folders._windows()
    guest = _folders._me(win).rsplit("-", 1)[0] + "-501"  # this computer's Guest account: another account that is always there
    data = tmp_path / "data"
    data.mkdir()
    icacls(data, "/grant", f"*{guest}:(OI)(CI)F")
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert "can be written to by other users" in said and f'icacls "{data}" /remove:g *{guest}' in said, said
    assert "it may come from Explorer's Continue, an admin's start, or a grant on purpose" in said and "as Explorer gives" not in said, said


def test_a_drive_whose_file_system_keeps_no_permissions_is_named_as_such(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # (FAT and exFAT keep no ACL: what the drive says of itself is stood in for.) Every start said the folder can be written
    # to by others, every update was refused, and nothing said that no setting of the folder can change that.
    from qkvm import _folders

    monkeypatch.setattr(_folders, "_kept", lambda win, path: (False, "exFAT"))
    data = tmp_path / "data"
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert "exFAT" in said and "keeps no permissions" in said and "NTFS" in said, said
    assert _folders.not_alone(data) is not None  # (and nothing in the data folder is run on its word: the starter's check says so)


def test_a_wall_on_a_drive_that_keeps_no_permissions_is_said_once_at_every_start_and_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The round 5 review (M3, review-core5\probes\p8_fat_owner.py; stood in, as there: no FAT drive here). On FAT and exFAT
    # Windows keeps no owner and no ACL, and answers for every file with the world's (owner Everyone, no DACL). A new wall's
    # key folder was refused, and an existing wall refused at every start: its own qkvm.lock and qkvm.log "another account's".
    # The decision is "said, not refused": nothing is refused for owners or ACLs there, and it is said once per start.
    import uvicorn

    from qkvm import _folders, _vault_windows, cli
    from tests.test_control import free_port, served_and_left

    monkeypatch.setattr(_folders, "_security", lambda win, path: ("S-1-1-0", None))
    monkeypatch.setattr(_folders, "_kept", lambda win, path: (False, "FAT32"))

    def as_on_fat(path: Path) -> None:
        raise PermissionError("the vault key has no access restrictions")

    monkeypatch.setattr(_vault_windows, "validate_private", as_on_fat)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    data = tmp_path / "usb" / "qkvm"
    for _ in ("a new wall", "the same wall again"):
        assert run_cli(["--data-dir", str(data), "--port", free_port()]) == 0, capsys.readouterr().err
        cli.stop_logging()
        said = " ".join(capsys.readouterr().err.split())
        assert said.count("keeps no permissions") == 1 and "FAT32" in said and "NTFS" in said, said
        for not_said in ("not qKVM's own", "may have been put there", "can be read by other users", "must belong to the server"):
            assert not_said not in said, (not_said, said)


def test_what_is_open_on_the_way_is_said_under_the_name_given_and_which_of_link_or_folder_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The round 2 review (LOW-2, review-core2\probes\m2_link_wording.py): the start named the folder the link leads to before
    # the words, "<folder> leads to <folder>, which ...", and a link that was open or another account's was reported under
    # the folder's name, of a folder that was neither. The data folder is named as it was given; the words say which.
    from qkvm import _folders

    def said(data: Path) -> str:
        assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
        return capsys.readouterr().err

    opened = open_to_everybody_signed_in(tmp_path / "drive")
    # 1. the link is private, the folder it leads to open
    target, link = opened / "qkvm", tmp_path / ".qkvm"
    target.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    assert f"qkvm: {link} leads to {target}, which can be written to by other users of this computer." in said(link)
    # 2. the link is open (made in the folder everybody may change), the folder it leads to private
    private, open_link = tmp_path / "private", opened / "qkvm-link"
    private.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(open_link), str(private)], check=True, capture_output=True)
    assert f"qkvm: {open_link} (a link to {private}) can be written to by other users of this computer." in said(open_link)
    # 3. the link is another account's (what its ACL says stood in for: setting another owner takes an elevated console)
    real_security = _folders._security
    monkeypatch.setattr(_folders, "_security", lambda win, path: ("S-1-5-19", []) if Path(path) == open_link else real_security(win, path))
    told = said(open_link)
    assert f"qkvm: {open_link} (a link to {private}) belongs to another user." in told and f'"{open_link}"' in told, told


def chained(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A data folder reached through two links: `.qkvm` (a junction in a private folder) to `middle` (a junction in a folder
    everybody signed in may change) to `real` (a private folder). (The first link, the middle one, the folder.)"""
    opened = open_to_everybody_signed_in(tmp_path / "drive")
    real, middle, link = tmp_path / "real", opened / "middle", tmp_path / ".qkvm"
    real.mkdir()
    for made, to in ((middle, real), (link, middle)):
        subprocess.run(["cmd", "/c", "mklink", "/J", str(made), str(to)], check=True, capture_output=True)
    return link, middle, real


def test_a_link_in_the_middle_of_a_chain_is_said_where_others_may_point_it_elsewhere(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The round 2 review (LOW-3, review-core2\probes\m2_links.py, chain and swapped): only the link given and the folder at
    # the end were looked at. The middle link, in a folder anybody may change, was neither said nor protected: anybody could
    # point it at a folder of their own, and the wall then started there as a new wall.
    from qkvm import _folders

    link, middle, _ = chained(tmp_path)
    assert middle in _folders.places(link)
    assert run_cli(["--data-dir", str(link), "--disable-2fa", "nobody"]) == 2
    said = capsys.readouterr().err
    assert f"leads through the link {middle}, which can be written to by other users" in said, said


def test_a_link_in_the_middle_of_a_chain_is_left_as_it_is_found_and_said_at_a_real_start(tmp_path: Path) -> None:
    # (ce2e3ae made it its owner's alone at a real start. Under the owner's decision it is said, and left as found.)
    link, middle, _ = chained(tmp_path)
    before = entries(middle, tmp_path)
    said = started_once(link, tmp_path)
    assert entries(middle, tmp_path) == before
    assert f"leads through the link {middle}, which can be written to by other users" in said, said


def test_an_unlock_file_in_a_folder_others_may_change_is_said_to_be_so_on_windows_and_through_a_link(tmp_path: Path) -> None:
    # The round 2 review (LOW-5): on Windows no folder of an unlock file was looked at; whoever may change the folder may put
    # another file in this one's place. Neither the folder it is given in, nor (through a link) the one it lies in.
    from qkvm import unlock

    opened = open_to_everybody_signed_in(tmp_path / "drive")
    key = opened / "qkvm-unlock"
    key.write_text("x" * 44 + "\n", encoding="ascii")
    icacls(key, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-3-4:F")  # the file itself its owner's alone
    assert unlock.what_others_may(key) == ["changed"]
    said = unlock.warning(key)
    assert said is not None and f"its folder {opened}" in said, said
    private = tmp_path / "private"
    private.mkdir()
    link = private / "unlock"
    made = subprocess.run(["cmd", "/c", "mklink", str(link), str(key)], capture_output=True, text=True)
    if made.returncode != 0:  # (a symlink takes the right to make one: Developer Mode, or an elevated console)
        pytest.skip(f"this account may not make a symlink here: {made.stdout.strip()} {made.stderr.strip()}")
    assert unlock.what_others_may(link) == ["changed"]
    said = unlock.warning(link)
    assert said is not None and f"its folder {opened}" in said, said


def test_an_unlock_file_reached_through_a_file_symlink_is_judged_by_the_file_it_leads_to(tmp_path: Path) -> None:
    # The round 3 review (L1, review-core3\probes\p1_links.py case A): GetNamedSecurityInfoW reads a link's own security; the
    # file a symlink leads to was not looked at on Windows, and a key everybody may read was said to be nobody else's.
    from qkvm import unlock

    private = tmp_path / "private"
    private.mkdir()
    key = private / "qkvm-unlock"
    key.write_text("k" * 44 + "\n", encoding="ascii")
    icacls(key, "/grant", "*S-1-1-0:R")  # the file itself: everybody may read it
    link = private / "unlock-link"
    made = subprocess.run(["cmd", "/c", "mklink", str(link), str(key)], capture_output=True, text=True)
    if made.returncode != 0:  # (a symlink takes the right to make one: Developer Mode, or an elevated console)
        pytest.skip(f"this account may not make a symlink here: {made.stdout.strip()} {made.stderr.strip()}")
    assert unlock.what_others_may(key) == ["read"]
    assert unlock.what_others_may(link) == ["read"]
    said = unlock.warning(link)
    assert said is not None and "can be read by other users" in said, said


def test_the_way_to_the_data_folder_is_followed_past_a_volumes_own_name(tmp_path: Path) -> None:
    # The round 3 review (L2, review-core3\probes\p1_links.py case C): a junction whose target is written by the volume's own
    # name (\\?\Volume{...}\..., as a volume mounted in a folder is) cut the walk short: a later link on the way, in a folder
    # anybody may change, was neither listed nor said.
    import ctypes
    import _winapi

    from qkvm import _folders

    name = ctypes.create_unicode_buffer(64)
    assert ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(str(tmp_path.anchor), name, 64)
    opened = open_to_everybody_signed_in(tmp_path / "open")
    real = tmp_path / "real"
    (real / "data").mkdir(parents=True)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(opened / "mid"), str(real)], check=True, capture_output=True)
    by_volume = name.value + str(opened)[3:]  # (the same folder, by its volume's name: \\?\Volume{...}\...)
    if subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "vol"), by_volume], capture_output=True).returncode != 0:
        _winapi.CreateJunction(by_volume[4:], str(tmp_path / "vol"))  # (which writes the \\?\ before it itself)
    said = _folders.folder_judged(tmp_path / "vol" / "mid" / "data")
    assert said is not None and "leads through the link" in said[0] and "mid, which can be written to by other users" in said[0], said


def test_a_way_through_more_links_than_are_followed_cannot_be_looked_at(tmp_path: Path) -> None:
    # (The same review, case D: a chain of fifty junctions was cut at forty, and an open link after that was not said.)
    from qkvm import _folders

    links = [tmp_path / f"link{index:02d}" for index in range(50)]
    real = tmp_path / "real"
    real.mkdir()
    for index, made in enumerate(links):
        subprocess.run(["cmd", "/c", "mklink", "/J", str(made), str(links[index + 1] if index + 1 < len(links) else real)], check=True, capture_output=True)
    said = _folders.folder_judged(links[0])
    assert said is not None and "cannot be looked at" in said[0], said


def test_an_entry_that_passes_to_the_files_in_a_folder_only_counts_in_judging_the_folder(tmp_path: Path) -> None:
    # The round 3 review (L4, review-core3\probes\p7_kept_inherit_only_entry.py): an entry the folder holds inherit-only (the
    # folder above gives "this folder and files", (OI) without (CI)) grants nothing on the folder itself, and was passed
    # over; but every file made in it takes it. LOCAL SERVICE stands in for the account it is for.
    from qkvm import _folders

    parent = tmp_path / "above"
    parent.mkdir()
    icacls(parent, "/grant", f"*{LOCAL_SERVICE}:(OI)F")
    data = parent / "data"
    data.mkdir()
    assert any("IO" in kind and whose in ("LS", LOCAL_SERVICE) for kind, _, whose in entries(data, tmp_path))  # (inherit-only there)
    assert _folders.not_alone(data) == "can be written to by other users of this computer"
    assert _folders.not_alone(data, _folders.READ) == "can be read by other users of this computer"


def test_the_storage_keys_folder_is_named_as_it_is_given_and_which_of_link_or_folder_is_open(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The round 3 review (L5, review-core3\probes\p5_keys_link_wording.py): the key folder's line named it by Path.resolve:
    # "<target>, where the storage key is kept, leads to <target>", as the data folder's line did before 00a53dd.
    def said(data: Path) -> str:
        assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
        return capsys.readouterr().err

    opened = open_to_everybody_signed_in(tmp_path / "open")
    # 1. <data>.keys a private junction to a folder others may change
    (tmp_path / "one").mkdir()
    (opened / "keys-one").mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "one.keys"), str(opened / "keys-one")], check=True, capture_output=True)
    assert f"qkvm: {tmp_path / 'one.keys'}, where the storage key is kept, leads to {opened / 'keys-one'}, which can be written to" in said(tmp_path / "one")
    # 2. <data>.keys a junction others may change (made in such a folder), to a private folder
    two = opened / "two"
    two.mkdir()
    icacls(two, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-3-4:(OI)(CI)F")
    (tmp_path / "keys-two").mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(opened / "two.keys"), str(tmp_path / "keys-two")], check=True, capture_output=True)
    assert f"qkvm: {opened / 'two.keys'}, where the storage key is kept, (a link to {tmp_path / 'keys-two'}) can be written to" in said(two)


def test_the_line_given_for_an_open_folder_works_as_printed_and_changes_nothing_outside_it(tmp_path: Path) -> None:
    # The round 3 review (L6): no printed line may go through a junction into what lies outside the folder. The line for an
    # open folder sets the folder's own entries (no /T): what inherits takes them, and Windows does not carry them through a
    # junction. Tried here with a junction planted inside, to a folder outside with a file in it.
    from qkvm import _folders

    data = open_to_everybody_signed_in(tmp_path / "drive") / "data"
    data.mkdir()
    (data / "qkvm.log").write_text("the wall's\n", encoding="utf-8")
    outside = open_to_everybody_signed_in(tmp_path / "outside")
    (outside / "theirs.txt").write_text("not the wall's\n", encoding="utf-8")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(data / "planted"), str(outside)], check=True, capture_output=True)
    untouched = {str(path): entries(path, tmp_path) for path in (outside, outside / "theirs.txt")}
    me = _folders._name(_folders._windows(), _folders._me(_folders._windows()))
    _, advice = _folders.folder_judged(data) or ("", "")
    line = f'icacls "{data}" /inheritance:r /grant:r "{me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"'
    assert line in advice and "/T" not in advice, advice
    assert subprocess.run(line, shell=True, capture_output=True).returncode == 0
    assert _folders.folder_judged(data) is None and _folders.not_alone(data / "qkvm.log", _folders.READ) is None
    assert {str(path): entries(path, tmp_path) for path in (outside, outside / "theirs.txt")} == untouched


def test_the_lines_given_for_a_link_name_the_link_and_its_folder_each_on_its_own(tmp_path: Path) -> None:
    # (The same review, L6.) A link that is open is set by a line of its own, with /L (the link, not where it leads), and
    # the folder it leads to by a line of its own: where both are open, both lines are given.
    from qkvm import _folders

    opened = open_to_everybody_signed_in(tmp_path / "open")
    real = open_to_everybody_signed_in(tmp_path / "real")
    link = opened / "qkvm-link"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], check=True, capture_output=True)
    me = _folders._name(_folders._windows(), _folders._me(_folders._windows()))
    grants = f'/inheritance:r /grant:r "{me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"'
    _, advice = _folders.folder_judged(link) or ("", "")
    # (The folder was given Authenticated Users' Modify itself: a line of its own removes it. The link has its entries from
    # the folder it lies in: the link's own line, /L, sets them.)
    for line in (f'icacls "{real}" /remove:g *{AUTHENTICATED_USERS}', f'icacls "{link}" {grants} /L'):
        assert line in advice, (line, advice)
        assert subprocess.run(line, shell=True, capture_output=True).returncode == 0
    assert _folders.folder_judged(link) is None


def test_an_offline_command_changes_no_data_folder_it_finds_and_says_what_it_found(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A service's account given the folder above (stand-in: LOCAL SERVICE, Modify, inherited by the data folder). An admin
    # runs an offline command once, as themselves (--disable-2fa here): the folder was protected to that admin, SYSTEM and
    # the Administrators, and the service's grant was gone (the review of 2026-11-01, L3). An offline command changes no
    # folder it finds: it says what it found.
    parent = tmp_path / "service"
    parent.mkdir()
    icacls(parent, "/grant", f"*{LOCAL_SERVICE}:(OI)(CI)M")
    data = parent / "data"
    data.mkdir()
    before = entries(data, tmp_path)
    for offline in (["--disable-2fa", "nobody"], ["--reset-password"]):
        run_cli(["--data-dir", str(data), *offline])
        assert entries(data, tmp_path) == before, (offline, entries(data, tmp_path))
        assert "can be written to by other users" in capsys.readouterr().err, offline


def a_service_folder(tmp_path: Path) -> Path:
    """A data folder whose service account (LOCAL SERVICE stands in) has its access from the folder above, made by an admin
    for the service, with a file of the service's in it; in a folder everybody signed in may change, as another drive gives."""
    parent = open_to_everybody_signed_in(tmp_path / "service")
    icacls(parent, "/grant", f"*{LOCAL_SERVICE}:(OI)(CI)M")
    data = parent / "data"
    data.mkdir()
    (data / "the-services-notes.txt").write_text("kept by the service", encoding="ascii")  # (a file of the service's)
    return data


def test_a_real_start_leaves_every_folder_it_finds_as_it_found_it_and_says_it(tmp_path: Path) -> None:
    # The owner's decision (2026-11-01, after the round 3 review): on Windows as on Linux. What qKVM makes is private from
    # its first moment; a folder it finds (the data folder, a link on the way, the folder behind it, a service's folder) is
    # never changed, by any command, elevated or not: it is said at every real start, with a fix that works. Changing found
    # folders cost a stopped service its group's access, and left planted files with the account that planted them.
    open_found = open_to_everybody_signed_in(tmp_path / "drive") / "data"
    open_found.mkdir()
    (open_found / "tls").mkdir()
    link, middle, real = chained(tmp_path / "chain")
    service = a_service_folder(tmp_path / "svc")
    for data, looked_at in ((open_found, [open_found, open_found / "tls"]), (link, [link, middle, real]), (service, [service, service / "the-services-notes.txt"])):
        before = {str(path): entries(path, tmp_path) for path in looked_at}
        said = started_once(data, tmp_path)
        assert {str(path): entries(path, tmp_path) for path in looked_at} == before, data
        assert "can be written to by other users" in said, said


def test_a_start_that_finds_another_copy_running_changes_nothing(tmp_path: Path) -> None:
    # The round 2 review (LOW-1, review-core2\probes\l3_real_start_by_an_admin.py): an admin's plain start on a running
    # service's folder ended "another copy is already running", but the folder and its files had already lost the service's
    # entry and gained the admin's: the folder was protected before the lock was taken. Now nothing is changed before then.
    from qkvm.store import InstanceLock

    data = a_service_folder(tmp_path)
    before = {path.name: entries(path, tmp_path) for path in (data, data / "the-services-notes.txt")}
    held = InstanceLock(data)  # the service's wall, running
    assert held.acquire()
    try:
        environment = {**os.environ, "PYTHONPATH": str(APP), "QKVM_CHILD": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        done = subprocess.run(
            [sys.executable, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", str(closed_port()), "--bind", "local"],
            env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=120,
        )  # fmt: skip
    finally:
        held.release()
    assert done.returncode == 2 and "already running" in done.stderr, done.stderr
    assert {path.name: entries(path, tmp_path) for path in (data, data / "the-services-notes.txt")} == before


def test_a_folder_that_is_there_is_left_exactly_as_it_is_found_by_what_makes_folders(tmp_path: Path) -> None:
    # (b27513e changed this account's found folder at a real start, stood in for. private_folder makes a folder that is not
    # there, and leaves one that is, whoever owns it and whatever it lets others do.)
    from qkvm import _folders

    data = open_to_everybody_signed_in(tmp_path / "drive") / "data"
    data.mkdir()
    before = entries(data, tmp_path)
    _folders.private_folder(data)
    assert entries(data, tmp_path) == before
    made = tmp_path / "made"
    _folders.private_folder(made)
    assert all("ID" not in kind for kind, _, _ in entries(made, tmp_path))


def test_what_was_granted_on_the_data_folder_itself_is_kept_and_said(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    data.mkdir()
    icacls(data, "/grant", f"*{USERS}:(OI)(CI)M")  # somebody gave the computer's users the folder, on purpose or not: theirs to undo
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    assert "BU" in {whose for _, _, whose in entries(data, tmp_path)}
    said = capsys.readouterr().err
    assert "can be written to by other users" in said, said


def test_an_update_in_a_folder_others_can_write_to_is_not_run_on_windows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    an_update_that_leaves_a_mark(data)
    assert starter.active_update(data) is not None  # (the tests' folders are their runner's alone, as a data folder is)
    for opened in (data / "updates", data / "updates" / "current.json", data / "updates" / "9.9.9", data / "updates" / "9.9.9" / "qkvm"):
        icacls(opened, "/grant", f"*{AUTHENTICATED_USERS}:(M)")
        assert starter.active_update(data, tell=True) is None, opened
        assert "is not used" in capsys.readouterr().err
        icacls(opened, "/remove:g", f"*{AUTHENTICATED_USERS}")
        assert starter.active_update(data) is not None, opened
    icacls(data / "updates", "/grant", f"*{USERS}:(RX)")  # reading it is nobody's harm: the code is the release's
    assert starter.active_update(data) is not None


def test_an_update_planted_in_a_data_folder_everybody_may_write_is_not_run(tmp_path: Path) -> None:
    drive = open_to_everybody_signed_in(tmp_path / "drive")
    data = drive / "data"
    mark = an_update_that_leaves_a_mark(data)  # put there by somebody: everybody signed in may
    said = typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path)
    assert not mark.exists(), said.stderr
    assert "is not used" in said.stderr, said.stderr


@pytest.mark.parametrize(
    "beside",
    [
        None,  # missing
        "def broken(:\n",  # a syntax error
        "raise RuntimeError('a file that raises at import')\n",
        "def not_alone(path, rights=0):\n    raise AttributeError('function GetNamedSecurityInfoW not found')\n",  # raises when asked
    ],
    ids=["missing", "syntax error", "raises at import", "raises when asked"],
)
def test_a_starter_without_its_folders_file_runs_no_update_and_does_not_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], beside: str | None
) -> None:
    # The review of 2026-11-01 (round 2, LOW-4, review-core2\probes\m1_starter_without_folders.py): own_folders caught an
    # ImportError only; a copy without _folders.py beside the starter raised FileNotFoundError, and the starter ended in a
    # traceback wherever an update was named in current.json. Its docstring says: nothing in the data folder is run. And
    # round 3 (review-core3\probes\p3_starter_folders_variants.py): one that does not import, or fails when asked, alike.
    data = tmp_path / "data"
    an_update_that_leaves_a_mark(data)
    copy = tmp_path / "a copy without it"
    copy.mkdir()
    (copy / "_version.py").write_text('__version__ = "0.0.1"\n', encoding="utf-8")  # (an older copy: the update is newer)
    if beside is not None:
        (copy / "_folders.py").write_text(beside, encoding="utf-8")
    monkeypatch.setattr(starter, "__file__", str(copy / "__main__.py"))
    monkeypatch.setattr(starter, "_folders", [])
    assert starter.active_update(data, tell=True) is None
    assert "cannot be looked at" in capsys.readouterr().err


def test_who_may_read_a_file_is_said_as_reading_and_nothing_more(tmp_path: Path) -> None:
    # (The masks of reading and of writing share GENERIC_ALL: a question about reading was answered in the words of writing.)
    from qkvm import _folders

    secret = tmp_path / "unlock.key"
    secret.write_text("a key, long enough for what this asks\n", encoding="ascii")
    icacls(secret, "/grant", f"*{USERS}:(R)")
    assert _folders.not_alone(secret, _folders.READ) == "can be read by other users of this computer"
    assert _folders.not_alone(secret) is None  # reading it is all they may do


def test_a_data_folder_of_another_account_and_open_to_others_is_given_every_line_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # The round 4 review (L4): a folder both another account's and open to others got the owner's line alone; run, the next
    # start gave the entries' line. Both at once now, the owner's first (whoever owns it may change its entries). (Another
    # owner stood in for: what the ACL says of its entries is the folder's own.)
    from qkvm import _folders

    data = tmp_path / "data"
    data.mkdir()
    icacls(data, "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M")
    real_security = _folders._security
    monkeypatch.setattr(_folders, "_security", lambda win, path: ("S-1-5-19", real_security(win, path)[1]) if Path(path) == data else real_security(win, path))
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    me = _folders._name(_folders._windows(), _folders._me(_folders._windows()))
    owner, entry = f'icacls "{data}" /setowner "{me}"', f'icacls "{data}" /remove:g *{AUTHENTICATED_USERS}'
    assert f"qkvm: {data} belongs to another user, and can be written to by other users of this computer." in said, said
    assert owner in said and entry in said and said.index(owner) < said.index(entry), said
    monkeypatch.undo()
    for line in (owner, entry):
        assert subprocess.run(line, shell=True, capture_output=True).returncode == 0, line
    assert _folders.folder_judged(data) is None


def test_an_acl_that_cannot_be_looked_at_is_said_so_and_not_as_what_others_may_do(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # The round 4 review's notes: a file whose ACL cannot be read was said to be readable by other users, and a data folder
    # whose ACL cannot be read was given "Whoever can write there can stop qKVM ...". (An ACL that cannot be read stood in for.)
    from qkvm import _folders

    data = tmp_path / "data"
    data.mkdir()
    (data / "qkvm.bak").write_text("made before\n", encoding="utf-8")
    real_security = _folders._security

    def unreadable(win: object, path: object) -> object:
        if Path(str(path)) in (data, data / "qkvm.bak"):
            raise PermissionError(13, "Access is denied")
        return real_security(win, path)

    monkeypatch.setattr(_folders, "_security", unreadable)
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    assert f"qkvm: {data} cannot be looked at." in said and "Who may write there cannot be told, and no update is run from it" in said, said
    assert "who may read qkvm.bak cannot be told: its ACL cannot be looked at." in said, said
    assert "can be read by other users" not in said and "Whoever can write there" not in said, said
