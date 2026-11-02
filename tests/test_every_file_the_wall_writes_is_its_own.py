"""Every file qKVM writes in its data folder is its owner's alone from its first moment, in a folder it found open too (the
round 4 review, M1).

On Windows a file made in a folder takes the folder's inheritable entries: in a found data folder that everybody signed in
may change (as the root of a drive other than the system's gives it), the log, which holds the setup code, the settings,
the activity log, its index and the history were everybody's to read; only the storage key and the unlock key were made
with an ACL of their own. Now each is made with a protected ACL of this account, SYSTEM and the Administrators in the call
that makes it (_folders.open_private), and SQLite is made to make no file of its own (store.sqlite_open, into_wal). On
POSIX umask 077 made them 0600 already, and still does. The found folder itself is left as it is.
"""

from __future__ import annotations

import ctypes
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from qkvm import __main__ as starter
from qkvm import _folders, activity, cli, store
from qkvm.alerts import Watcher
from qkvm.security import Sessions
from tests.test_control import free_port, served_and_left

AUTHENTICATED_USERS = "S-1-5-11"  # everybody who signs in to the computer


def found_open(folder: Path) -> Path:
    """A folder qKVM finds, which everybody signed in may change (and so take what is made in it from it, on Windows)."""
    folder.mkdir(parents=True)
    if os.name == "nt":
        subprocess.run(["icacls", str(folder), "/grant", f"*{AUTHENTICATED_USERS}:(OI)(CI)M"], check=True, capture_output=True)
    else:
        os.chmod(folder, 0o777)
    return folder


def whose(path: Path) -> str | None:
    """Why the file is not its owner's alone (to read or to change), or None where it is."""
    if os.name == "nt":
        return _folders.not_alone(path, _folders.READ | _folders.WRITE)
    found = path.lstat()
    if found.st_uid != os.getuid():
        return "belongs to another user"
    return f"mode {oct(stat.S_IMODE(found.st_mode))}" if stat.S_IMODE(found.st_mode) & 0o077 else None


def everything_in(folder: Path, but: set[str] = frozenset()) -> dict[str, str | None]:  # type: ignore[assignment]
    return {str(path.relative_to(folder)): whose(path) for path in sorted(folder.rglob("*")) if path.is_file() and path.name not in but}


def test_a_real_start_and_an_offline_command_in_a_found_open_folder_make_every_file_their_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = found_open(tmp_path / "drive" / "data")
    folder_before = subprocess.run(["icacls", str(data)], capture_output=True, text=True).stdout if os.name == "nt" else oct(data.stat().st_mode)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 0
    assert cli.main(["--data-dir", str(data), "--reset-password"]) == 0
    assert cli.main(["--data-dir", str(data), "--port", free_port()]) == 0
    made = everything_in(data)
    for name in ("qkvm.log", "qkvm.json", "qkvm.bak", "audit.log", "unlock.key", "qkvm.lock"):  # (the databases: below)
        assert name in made, (name, made)
    assert {name: why for name, why in made.items() if why is not None} == {}, made
    assert "first run - setup code" in (data / "qkvm.log").read_text(encoding="utf-8")  # (the log that holds it: its own)
    keys = data.with_name("data.keys")
    assert whose(keys / "vault.key") is None
    # The found folder itself as it was found.
    assert (subprocess.run(["icacls", str(data)], capture_output=True, text=True).stdout if os.name == "nt" else oct(data.stat().st_mode)) == folder_before


def test_each_file_of_the_log_and_of_the_activity_log_is_made_its_own_as_they_are_moved_on(tmp_path: Path) -> None:
    import logging

    folder = found_open(tmp_path / "open")
    handler = cli._PrivateLog(folder / "qkvm.log", maxBytes=300, backupCount=3, encoding="utf-8")
    logger = logging.getLogger("test-every-file")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        for number in range(40):
            logger.warning("line %d of what the wall says, the setup code among them", number)
    finally:
        logger.removeHandler(handler)
        handler.close()
    audit = store.AuditLog(folder / "audit.log", max_bytes=300)
    for number in range(40):
        audit.write("login", "127.0.0.1", user=f"olga{number}")
    audit.flush()
    made = everything_in(folder)
    assert {"qkvm.log", "qkvm.log.1", "qkvm.log.3", "audit.log"} <= set(made), made
    assert {name: why for name, why in made.items() if why is not None} == {}, made


def test_what_is_kept_over_a_restart_and_what_the_starter_writes_are_their_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = found_open(tmp_path / "open")
    sessions = Sessions(folder / "sessions.json")
    sessions._write("{}")
    Watcher(folder / "watch.json").write("{}")
    cli.leave_request(folder, "stop")
    (folder / "updates").mkdir()
    starter.written(folder / "updates" / "current.json", '{"version": "9.9.9"}')
    starter.noted(folder, "a line of the starter's")
    home = found_open(tmp_path / "home-qkvm")
    monkeypatch.setattr(cli, "home_folder", lambda: home)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cli.remember(elsewhere)
    made = {**everything_in(folder), **everything_in(home)}
    assert {"sessions.json", "watch.json", cli.ASK_FILE, str(Path("updates") / "current.json"), "qkvm.log", cli.KNOWN} <= set(made), made
    assert {name: why for name, why in made.items() if why is not None} == {}, made


def test_a_download_of_the_activity_log_beyond_memory_is_its_own_and_gone_when_closed(tmp_path: Path) -> None:
    folder = found_open(tmp_path / "open")
    spool = activity.Spool(100, folder)
    spool.write(b"x" * 50)
    assert list(folder.iterdir()) == []  # (in memory)
    spool.write(b"y" * 100)
    if os.name == "nt":
        (held,) = folder.glob("*".join(activity.DOWNLOAD_NAMED))
        assert whose(held) is None, whose(held)
    else:
        assert list(folder.iterdir()) == []  # (removed as soon as it was open)
    spool.seek(0)
    assert spool.read() == b"x" * 50 + b"y" * 100 and spool.tell() == 150
    spool.close()
    assert list(folder.iterdir()) == []


# --- SQLite makes no file of its own -----------------------------------------------------------------------------------


class Watched:
    """Every name made in a folder while it is watched, in order (Windows: ReadDirectoryChangesW): a file that comes and goes
    (a rollback journal) is seen too."""

    def __init__(self, folder: Path) -> None:
        from ctypes import wintypes as w

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.c_void_p]
        self.kernel.ReadDirectoryChangesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, w.DWORD, w.BOOL, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.kernel.CreateFileW(str(folder), 0x1, 7, None, 3, 0x02000000, None)  # FILE_LIST_DIRECTORY, BACKUP_SEMANTICS
        self.made: list[str] = []
        self.thread = threading.Thread(target=self._watch, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def _watch(self) -> None:
        from ctypes import wintypes as w

        buffer, got = ctypes.create_string_buffer(65536), w.DWORD()
        while self.kernel.ReadDirectoryChangesW(self.handle, buffer, len(buffer), False, 0x1, ctypes.byref(got), None, None):
            offset = 0
            while got.value:
                following, action, length = (int.from_bytes(buffer.raw[offset + i : offset + i + 4], "little") for i in (0, 4, 8))
                if action == 1:  # FILE_ACTION_ADDED
                    self.made.append(buffer.raw[offset + 12 : offset + 12 + length].decode("utf-16-le"))
                if not following:
                    break
                offset += following

    def stop(self) -> list[str]:
        time.sleep(0.3)
        self.kernel.CancelIoEx(self.handle, None)
        self.thread.join(5)
        self.kernel.CloseHandle(self.handle)
        return self.made


def opened_as_the_history_opens_it(path: Path) -> Any:
    conn = store.sqlite_open(path, timeout=5.0, isolation_level="DEFERRED")
    conn.execute("PRAGMA user_version").fetchone()
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
    store.into_wal(conn, path)
    conn.execute("PRAGMA synchronous = NORMAL")
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS seen (t REAL, what TEXT)")
        for number in range(200):
            conn.execute("INSERT INTO seen VALUES (?, ?)", (number, "what the wall saw of a machine"))
    return conn


@pytest.mark.skipif(os.name != "nt", reason="SQLite makes its files with its database's mode on POSIX, which umask 077 makes 0600")
def test_sqlite_makes_no_file_of_its_own_beside_a_database_in_a_found_open_folder(tmp_path: Path) -> None:
    folder = found_open(tmp_path / "open")
    path = folder / "history.sqlite"
    watched = Watched(folder)
    conn = opened_as_the_history_opens_it(path)
    reader = store.sqlite_open(path, read=True, timeout=2.0)
    assert reader.execute("SELECT count(*) FROM seen").fetchone() == (200,)
    while_open = everything_in(folder)
    reader.close()
    conn.close()  # (the last connection: SQLite removes its -wal and -shm)
    assert sorted(p.name for p in folder.iterdir()) == ["history.sqlite"]
    conn = opened_as_the_history_opens_it(path)  # the next start: made again, by this program
    again = everything_in(folder)
    conn.execute("PRAGMA incremental_vacuum(10)").fetchall()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.close()
    made = watched.stop()
    assert set(while_open) == set(again) == {"history.sqlite", "history.sqlite-wal", "history.sqlite-shm"}, (while_open, again)
    assert {name: why for name, why in {**while_open, **again}.items() if why is not None} == {}, (while_open, again)
    assert not [name for name in made if name.endswith("-journal")], made  # (not even for a moment)


def test_the_history_and_the_activity_logs_index_are_their_own_in_a_found_open_folder(tmp_path: Path) -> None:
    from qkvm.history import History

    folder = found_open(tmp_path / "open")
    watched = Watched(folder) if os.name == "nt" else None
    kept = History(folder / "history.sqlite")
    kept.start()
    text = store.AuditLog(folder / "audit.log", max_bytes=4000)
    index = activity.Index(folder / activity.FILE, text)
    text.on_written = index.wake
    index.start()
    try:
        kept.observe("rack-1", {"state": "online", "error": None, "last_seen_ago": 0})
        kept.flush()
        for number in range(30):
            text.write("login", "127.0.0.1", user=f"olga{number}")
        text.flush()
        assert index.caught_up(30.0) is not None
        assert kept.read("rack-1", "summary", 0, time.time() + 60) is not None
        while_open = everything_in(folder)
    finally:
        index.stop()
        kept.stop()
    made = watched.stop() if watched is not None else []
    assert {"history.sqlite", "audit.sqlite", "audit.log"} <= set(while_open), while_open
    assert {name: why for name, why in while_open.items() if why is not None} == {}, while_open
    assert not [name for name in made if name.endswith("-journal")], made


@pytest.mark.skipif(os.name != "nt", reason="SQLite makes its files with its database's mode on POSIX, which umask 077 makes 0600")
def test_without_it_sqlite_gave_its_files_the_folders_entries(tmp_path: Path) -> None:
    # (What the test above holds against: sqlite3 as it comes, in the same folder.)
    import sqlite3

    folder = found_open(tmp_path / "open")
    watched = Watched(folder)
    conn = sqlite3.connect(folder / "history.sqlite")
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
    conn.execute("PRAGMA journal_mode = WAL")
    with conn:
        conn.execute("CREATE TABLE seen (t REAL)")
    found = everything_in(folder)
    conn.close()
    made = watched.stop()
    assert found["history.sqlite-wal"] is not None and "history.sqlite-journal" in made, (found, made)
    assert sys.platform == "win32"


def test_a_log_made_before_that_others_may_read_is_said_with_what_it_holds(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # One made by 0.2.0 in a folder that gave others its entries is kept as it is (qKVM changes nothing it finds); the start
    # names it, and every other file of its own others may read, with what the log holds.
    data = tmp_path / "data"
    data.mkdir()
    for name in ("qkvm.log", "history.sqlite", "sessions.json"):
        (data / name).write_text("made before\n", encoding="utf-8")
        if os.name == "nt":
            subprocess.run(["icacls", str(data / name), "/grant", "*S-1-5-32-545:(R)"], check=True, capture_output=True)
        else:
            os.chmod(data / name, 0o644)
    if os.name != "nt":
        os.chmod(data, 0o755)
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2
    said = " ".join(capsys.readouterr().err.split())
    assert "qkvm.log, history.sqlite, sessions.json can be read by other users of this computer (the log holds what a start printed, a setup code among it)" in said, said
