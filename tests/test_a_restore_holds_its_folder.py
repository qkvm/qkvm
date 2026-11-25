"""A restore holds the folder it restores into, and takes away only what it wrote (the outside review of 0.4.0, M1, L1).

Two restores into one empty folder were both let in: the second ended well, and the first, failing on a file the second had
made, took away every restored file and the storage key with it, while the second had said it was done. A restore holds its
folder now, in this process and any other, before anything there is looked at: a second one is refused before it touches
anything. And a restore stopped before it finished (the computer went down, the process was killed) left a folder a retry
refused as not empty; the next restore into it takes that over now, and takes away what it wrote, never anything else.
"""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from qkvm import backup, cli
from qkvm.store import Store
from qkvm.vault_storage import LOCK_NAME, StorageError, key_path
from tests.test_backup_file import KEY, made
from tests.test_wall import wait_until

APP = Path(__file__).resolve().parent.parent  # (a child process finds qkvm and tests from here, as the tests do)
# What stays beside a key once one was made in its folder: the lock's empty file, on Linux and macOS (on Windows it goes as it is
# let go of). Never anything else.
LOCK_LEFT = [] if sys.platform == "win32" else [LOCK_NAME]

# A restore in a process of its own, held as it begins to read the backup (it says so in a file) until a file says go.
HELD_ELSEWHERE = """
import sys, time
from pathlib import Path
from qkvm import backup
from tests.test_backup_file import KEY
real = backup.read
def held_up(*given, **said):
    Path(sys.argv[4]).write_text("reading", encoding="utf-8")
    while not Path(sys.argv[3]).exists():
        time.sleep(0.02)
    return real(*given, **said)
backup.read = held_up
backup.restore(Path(sys.argv[1]), KEY, Path(sys.argv[2]))
"""

# A restore in a process of its own, stopped dead once it has written and synced what the backup holds, before its settings.
STOPPED = """
import os, sys
from pathlib import Path
from qkvm import backup
from tests.test_backup_file import KEY
backup._held = lambda *given, **said: os._exit(73)
backup.restore(Path(sys.argv[1]), KEY, Path(sys.argv[2]))
"""


def child(code: str, *argv: Any) -> subprocess.Popen[str]:
    # The child takes qkvm from where these tests took it (in the image's run, the installed program), then these tests,
    # then whatever the run had on its path already (in the image's run, the only place pytest is, which the tests import).
    # -P: nothing from the working folder ahead of them. (A path of APP alone left the image's run without pytest.)
    paths = [str(Path(backup.__file__).resolve().parents[1]), str(APP), *filter(None, os.environ.get("PYTHONPATH", "").split(os.pathsep))]
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(dict.fromkeys(paths)), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.Popen([sys.executable, "-P", "-c", code, *map(str, argv)], cwd=APP, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def whole(target: Path) -> None:
    """The folder is a restored wall: its settings, its log and its storage key there, and nothing of the restore's hold."""
    missing = [path.name for path in (target / "qkvm.json", target / "audit.log", key_path(target)) if not path.is_file()]
    assert not missing, missing
    assert not (target / backup.RESTORING).exists()


def test_a_second_restore_into_the_folder_is_refused_and_takes_nothing_from_the_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    target.mkdir()
    reading, go_on = threading.Event(), threading.Event()
    real = backup.read
    first = True

    def held_up(*given: Any, **said: Any) -> Any:
        nonlocal first
        if first:  # (the first restore, held once it holds the folder and before it has written anything)
            first = False
            reading.set()
            assert go_on.wait(30)
        return real(*given, **said)

    monkeypatch.setattr(backup, "read", held_up)
    with ThreadPoolExecutor(max_workers=1) as pool:
        slow = pool.submit(backup.restore, archive, KEY, target)
        try:
            assert reading.wait(10), "the first restore never came to its reading"
            with pytest.raises(backup.BackupError) as refused:
                backup.restore(archive, KEY, target)
            assert refused.value.code == "busy" and "under way" in refused.value.message
        finally:
            go_on.set()
        done = slow.result(timeout=60)
    assert done.held.devices == 1 and done.cleared == []
    whole(target)


def test_a_restore_in_another_process_holds_the_folder_as_well(tmp_path: Path) -> None:
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    go, reading = tmp_path / "go", tmp_path / "reading"
    elsewhere = child(HELD_ELSEWHERE, archive, target, go, reading)
    try:
        wait_until(lambda: reading.exists() or elsewhere.poll() is not None, "the other process never came to its reading", timeout=60)
        assert elsewhere.poll() is None, elsewhere.communicate()
        with pytest.raises(backup.BackupError) as refused:
            backup.restore(archive, KEY, target)
        assert refused.value.code == "busy"
        assert sorted(path.name for path in target.iterdir()) == [backup.RESTORING]  # (nothing of this one's, nothing of the other's taken)
    finally:
        go.write_text("go", encoding="utf-8")
        _, said = elsewhere.communicate(timeout=60)
    assert elsewhere.returncode == 0, said
    whole(target)


def test_a_restore_stopped_before_it_finished_is_taken_over_by_the_next_into_its_folder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    stopped = child(STOPPED, archive, target)
    _, said = stopped.communicate(timeout=60)
    assert stopped.returncode == 73, said
    left = sorted(path.name for path in target.iterdir())
    assert "audit.log" in left and "qkvm.json" not in left, left  # (what the backup holds written, its settings not yet)
    kit = tmp_path / "kit.txt"
    kit.write_text(backup.kit(KEY, 0.0), encoding="utf-8")
    status = cli.main(["--restore", str(archive), "--backup-key", str(kit), "--data-dir", str(target)])
    out = capsys.readouterr()
    assert status == 0, out
    assert "had been stopped before it finished" in out.out
    whole(target)


def test_what_a_stopped_restore_left_beside_anything_else_is_refused_and_left_as_it_is(tmp_path: Path) -> None:
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    stopped = child(STOPPED, archive, target)
    stopped.communicate(timeout=60)
    assert stopped.returncode == 73
    (target / "notes.txt").write_text("mine", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in target.iterdir()}
    with pytest.raises(backup.BackupError) as refused:
        backup.restore(archive, KEY, target)
    assert refused.value.code == "not_empty"
    assert {path.name: path.read_bytes() for path in target.iterdir()} == before


def test_a_key_file_named_for_a_restore_is_left_where_it_is_when_the_restore_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 re-check, R4.) A restore that failed took away the key file named for it (`--vault-key-file`) where it
    # had made it: a restore into another folder, named the same file, had taken it up meanwhile and ended well, and was left
    # with settings no key opens. A rollback takes no key away (nor one made in its own place beside the folder: below, M3).
    archive = made(tmp_path / "backups")
    named = tmp_path / "keys" / "wall.key"

    def full(*given: Any, **said: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as scoped:
        scoped.setattr(Store, "write", full)
        with pytest.raises(OSError):
            backup.restore(archive, KEY, tmp_path / "first", named)
    assert named.is_file() and not (tmp_path / "first").exists()
    other = backup.restore(archive, KEY, tmp_path / "second", named)  # (the one that takes it up)
    assert other.key_file == named and other.held.devices == 1


def test_a_key_made_beside_a_folder_and_taken_up_by_another_restore_is_left_when_its_maker_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 second re-check, M3.) The restore into the first folder made its key in its own place beside it; a
    # restore into a second folder was named that file, took it up and ended well; then the first failed at its settings, and
    # took the key away as its own: the second wall was left with settings no key opens. No rollback takes a key away.
    archive = made(tmp_path / "backups")
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()  # (where the key beside it is, is judged by the folder: key_path)
    shared = key_path(first)
    writing, go_on = threading.Event(), threading.Event()
    write = Store.write

    def fails_in_the_first(store: Store, data: Any) -> None:
        if store.path.parent == first:
            writing.set()
            assert go_on.wait(30)
            raise OSError(errno.ENOSPC, "No space left on device")
        write(store, data)

    monkeypatch.setattr(Store, "write", fails_in_the_first)
    with ThreadPoolExecutor(max_workers=1) as pool:
        failing = pool.submit(backup.restore, archive, KEY, first)
        try:
            assert writing.wait(30), "the first restore never came to its settings"
            done = backup.restore(archive, KEY, second, shared)
            assert done.key_file == shared and done.held.devices == 1
        finally:
            go_on.set()
        with pytest.raises(OSError):
            failing.result(timeout=60)
    assert list(first.iterdir()) == []  # (what the failed one wrote went)
    assert shared.is_file(), "the key the second wall's settings are sealed with was taken away"
    assert len(Store(second / "qkvm.json", vault_key_file=shared, protected=True, read_only=True).devices) == 1  # (it opens them)


# A restore in a process of its own, stopped dead as it writes the folder's first storage key (its first byte not written).
STOPPED_IN_ITS_KEY = """
import os, sys, types
from pathlib import Path
from qkvm import backup, vault_storage
from tests.test_backup_file import KEY
class Dying:
    def __enter__(self):
        return self
    def __exit__(self, *given):
        return False
    def write(self, data):
        os._exit(73)
vault_storage.os = types.SimpleNamespace(**{name: getattr(os, name) for name in dir(os) if not name.startswith("__")})
vault_storage.os.fdopen = lambda *given, **said: Dying()
backup.restore(Path(sys.argv[1]), KEY, Path(sys.argv[2]))
"""


def test_a_restore_stopped_as_it_writes_the_first_key_leaves_none_and_a_retry_ends_well(tmp_path: Path) -> None:
    # (The outside review 6.2 second re-check, M4.) The key file was made under its own name before its key was in it: a restore stopped
    # there left an empty one, and the retry the guide promises refused it as no key. A key is written whole elsewhere first.
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    stopped = child(STOPPED_IN_ITS_KEY, archive, target)
    _, said = stopped.communicate(timeout=60)
    assert stopped.returncode == 73, said
    assert backup.left_by_a_restore(target) and not key_path(target).exists()
    done = backup.restore(archive, KEY, target)
    assert done.held.devices == 1 and done.key_file == key_path(target)
    whole(target)
    assert sorted(path.name for path in key_path(target).parent.iterdir()) == [*LOCK_LEFT, "vault.key"]  # (nothing of the stopped one's left)


def test_a_key_put_in_its_place_by_a_second_name_that_did_not_go_is_taken_up_whole(tmp_path: Path) -> None:
    # (M4, on a system where the key is put in its place by a second name of the file it was written into.) Stopped between
    # the two, the key had two names, and is refused as a link: the next one to make it takes the second name away first.
    from qkvm import vault_storage

    place = tmp_path / "keys" / "vault.key"
    key = vault_storage.create_key(place)
    os.link(place, place.with_name(".qkvm-key-0123456789abcdef.part"))
    with pytest.raises(vault_storage.StorageError):
        vault_storage.read_key(place)
    assert vault_storage.make_key(place) == (key, False)
    assert sorted(path.name for path in place.parent.iterdir()) == [*LOCK_LEFT, "vault.key"]


@pytest.mark.skipif(not hasattr(os, "pathconf"), reason="the longest name a folder takes is asked of Linux and macOS")
def test_a_first_key_is_made_where_its_name_is_as_long_as_its_folder_takes(tmp_path: Path) -> None:
    # (The outside review 6.2 third re-check, M2.) The file a first key is written into was named after the key, 23 bytes longer: a key
    # named near the longest a folder takes could not be made at all (ENAMETOOLONG). That file's name is of one short length.
    from qkvm import vault_storage

    place = tmp_path / "keys" / ("k" * os.pathconf(tmp_path, "PC_NAME_MAX"))
    key = vault_storage.create_key(place)
    assert vault_storage.read_key(place) == key
    assert sorted(path.name for path in place.parent.iterdir()) == [*LOCK_LEFT, place.name]


@pytest.mark.skipif(sys.platform == "win32", reason="a key is put in its place by a second name of its file on Linux and macOS")
@pytest.mark.parametrize("refusal", ["EPERM", "EOPNOTSUPP", "ENOTSUP", "ENOSYS", "EXDEV"])
def test_no_first_key_is_made_where_the_volume_takes_no_second_name_of_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refusal: str) -> None:
    # (The outside review 6.2 narrow look at the third re-check's fixes, HIGH 2 and 3, and its MEDIUM on ENOSYS.) Where the volume took no
    # hard link (EPERM, EOPNOTSUPP), the key was written into its place itself: there before it was whole and synced, another
    # restore could take it up while the first could still take it away, and one the volume shows to others stayed there; ENOSYS
    # and EXDEV failed with the system's word alone. No key is made there at all now: refused in plain words before any is in
    # its place, and nothing is left beside it.
    number = getattr(errno, refusal)
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    target.mkdir()
    selected = key_path(target)
    link = os.link

    def no_second_names(source: Any, destination: Any, *given: Any, **said: Any) -> Any:
        if Path(destination) == selected:
            raise OSError(number, os.strerror(number))
        return link(source, destination, *given, **said)

    monkeypatch.setattr(os, "link", no_second_names)
    with pytest.raises(StorageError, match="must be on a volume that takes hard links") as refused:
        backup.restore(archive, KEY, target)
    assert "No key was made" in str(refused.value) and "--vault-key-file" in str(refused.value)
    assert sorted(path.name for path in selected.parent.iterdir()) == LOCK_LEFT  # (no key, and not the file it was written into)
    assert list(target.iterdir()) == []  # (and nothing restored)


@pytest.mark.skipif(sys.platform == "win32", reason="a key's file is judged by its mode and owner on Linux and macOS")
@pytest.mark.parametrize("shown", ["to every account", "as another account's"])
def test_no_key_is_written_into_a_file_its_volume_does_not_keep_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shown: str) -> None:
    # (HIGH 3.) A volume that shows every file to others whatever is asked (a FAT or exFAT mount) had the whole key written, and
    # refused only once it was in its place. The file it is to be written into is judged as it is made, on the open file, as a
    # key is judged when it is read: nothing is written into it there, and it goes.
    from qkvm import vault_storage

    place = tmp_path / "keys" / "vault.key"
    fstat, fdopen = os.fstat, os.fdopen
    modes: list[Any] = []

    def as_the_volume_shows(descriptor: int, *given: Any, **said: Any) -> Any:
        found = fstat(descriptor, *given, **said)
        if stat.S_ISREG(found.st_mode) and any(vault_storage.PART.fullmatch(one.name) and os.path.samestat(found, one.lstat()) for one in place.parent.iterdir()):
            fields = list(found)
            if shown == "to every account":
                fields[0] |= 0o044
            else:
                fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return found

    def opened(descriptor: int, *given: Any, **said: Any) -> Any:
        modes.append(given[0] if given else said.get("mode", "r"))
        return fdopen(descriptor, *given, **said)

    monkeypatch.setattr(os, "fstat", as_the_volume_shows)
    monkeypatch.setattr(os, "fdopen", opened)
    with pytest.raises(StorageError, match="would not be private") as refused:
        vault_storage.make_key(place)
    assert "No key was made" in str(refused.value) and "--vault-key-file" in str(refused.value)
    assert "wb" not in modes  # (nothing was written)
    assert sorted(path.name for path in place.parent.iterdir()) == LOCK_LEFT


def test_making_a_key_never_takes_away_a_file_named_as_its_lock_and_leaves_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (HIGH 1.) On Linux and macOS the lock of the folder a key is made in opened the file of its name that was there, and took it
    # away as it let go: an operator's file of that name (another wall's only key, say) went with it. Nothing takes it away now:
    # the lock's own file stays, empty and the server's alone, and only the lock on it is let go of. On Windows each makes a file
    # of its own, never one that was there, which goes as it is closed.
    from qkvm import vault_storage

    folder = tmp_path / "keys"
    folder.mkdir(mode=0o700)
    found = folder / LOCK_NAME
    found.write_text("an operator's", encoding="utf-8")
    if sys.platform == "win32":
        monkeypatch.setattr(vault_storage, "LOCK_WAIT", 0.3)
        with pytest.raises(StorageError, match="another qKVM"):
            vault_storage.create_key(folder / "vault.key")
    else:
        vault_storage.create_key(folder / "vault.key")
    assert found.read_text(encoding="utf-8") == "an operator's"
    other = tmp_path / "other"
    vault_storage.create_key(other / "vault.key")
    vault_storage.create_key(other / "second.key")  # (the folder taken again by the next, and let go again)
    assert sorted(path.name for path in other.iterdir()) == [*LOCK_LEFT, "second.key", "vault.key"]
    if sys.platform != "win32":
        left = (other / LOCK_NAME).stat()
        assert left.st_size == 0 and not left.st_mode & 0o077


@pytest.mark.parametrize("name", [
    LOCK_NAME, ".qkvm-key-0123456789abcdef.part", ".QKVM-Key-0123456789ABCDEF.PART",
    # (The review of Z2, L2.) Named so as Windows opens it: without the dots and spaces it ends in, up to a ":" (what follows
    # names a stream of that file, "::$DATA" its own data). Judged so on every system.
    ".qkvm-key-0123456789abcdef.part.", ".qkvm-key-0123456789abcdef.part ", ".qkvm-key-0123456789abcdef.part::$DATA",
    ".QKVM-KEY.LOCK. .", ".qkvm-key.lock::$DATA", ".qkvm-key.lock:stream",
])  # fmt: skip
@pytest.mark.parametrize("where", ["--vault-key-file", "restore"])
def test_no_key_may_be_named_as_what_is_kept_beside_a_key_as_one_is_made(tmp_path: Path, name: str, where: str) -> None:
    # (HIGH 1.) A key chosen under the name of a folder's lock, or of the file a key is written into, could be taken away by the
    # lock as it let go of it, or by the clean-up of what a stopped one left. Such a name is refused wherever a key's place is
    # taken: at a start (--vault-key-file) and by a restore. Nothing is made. (On Windows a key named ".qkvm-key-<hex>.part." was
    # opened as the file a key is written into, and the next first key made in its folder took it away for good: Z2's L2.)
    chosen = tmp_path / "keys" / name
    if where == "restore":
        archive = made(tmp_path / "backups")
        with pytest.raises(StorageError, match="may not be named") as refused:
            backup.restore(archive, KEY, tmp_path / "restored", chosen)
        assert not (tmp_path / "restored").exists()
    else:
        (tmp_path / "wall").mkdir()
        with pytest.raises(StorageError, match="may not be named") as refused:
            Store(tmp_path / "wall" / "qkvm.json", vault_key_file=chosen, protected=True)
        assert list((tmp_path / "wall").iterdir()) == []
    assert "--vault-key-file" in str(refused.value)
    assert not chosen.parent.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="file locks and second names of a file, as on Linux and macOS")
def test_where_the_volume_takes_no_lock_no_second_name_of_a_key_is_taken_away(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The narrow look, on the release notes' word that nothing beside a key is cleaned up where a volume takes no file lock.) A
    # key found with a second name of the form a key is written into had that name taken away all the same, by one holding no
    # lock: it may be another's, being put in its place. Only one holding the folder takes it away.
    import fcntl

    from qkvm import vault_storage

    place = tmp_path / "keys" / "vault.key"
    key = vault_storage.create_key(place)
    second = place.with_name(".qkvm-key-0123456789abcdef.part")
    os.link(place, second)

    def no_locks(*given: Any) -> None:
        raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))

    with monkeypatch.context() as scoped:
        scoped.setattr(fcntl, "flock", no_locks)
        with pytest.raises(StorageError, match="link"):
            vault_storage.make_key(place)
        assert second.exists() and os.path.samefile(second, place)
    assert vault_storage.make_key(place) == (key, False)  # (a volume that takes locks: the one holding the folder takes it away)
    assert sorted(path.name for path in place.parent.iterdir()) == [*LOCK_LEFT, "vault.key"]


def test_making_a_first_key_takes_nothing_of_anybody_elses_from_its_folder(tmp_path: Path) -> None:
    # (The outside review 6.2 third re-check, M1, and its bugs round.) Before it wrote a key, a restore took away every file beside the
    # key's place named like the one it writes a key into: an operator's notes, and another wall's key chosen under such a
    # name (`.vault.key.standby.part`), whose settings no longer opened. It takes nothing there but what it made itself.
    archive = made(tmp_path / "backups")
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    place = key_path(first)
    chosen = place.with_name(".vault.key.standby.part")
    assert backup.restore(archive, KEY, second, chosen).key_file == chosen
    notes = place.with_name(".vault.key.operator-notes.part")
    notes.write_text("kept", encoding="utf-8")
    assert backup.restore(archive, KEY, first).key_file == place
    assert chosen.is_file() and notes.read_text(encoding="utf-8") == "kept"
    assert len(Store(second / "qkvm.json", vault_key_file=chosen, protected=True, read_only=True).devices) == 1  # (it opens them)


def test_two_restores_making_the_first_key_of_one_place_at_once_both_end_with_that_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (M1.) The second, finding no key there yet, took the file the first had written and synced its key into for a stopped
    # one's leavings, and the first failed to put its key in its place. One makes the key of a folder at a time now; the other
    # finds it made, and reads it.
    archive = made(tmp_path / "backups")
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    shared = key_path(first)
    at_its_place, both = threading.Event(), threading.Barrier(2)
    put = {"link": os.link, "rename": os.rename}

    def meeting(how: str) -> Any:
        def putting(source: Any, destination: Any, *given: Any, **said: Any) -> Any:
            if Path(destination) == shared:
                if threading.current_thread().name.startswith("first"):
                    at_its_place.set()
                try:
                    both.wait(timeout=5)  # (where the second waits for the first to have made the key, they never meet)
                except threading.BrokenBarrierError:
                    pass
            return put[how](source, destination, *given, **said)
        return putting

    monkeypatch.setattr(os, "link", meeting("link"))
    monkeypatch.setattr(os, "rename", meeting("rename"))
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="first") as pool:
        pending = pool.submit(backup.restore, archive, KEY, first)
        assert at_its_place.wait(30), "the first never came to put its key in its place"
        assert backup.restore(archive, KEY, second, shared).key_file == shared
        assert pending.result(timeout=60).key_file == shared
    for target in (first, second):
        assert len(Store(target / "qkvm.json", vault_key_file=shared, protected=True, read_only=True).devices) == 1
    assert sorted(path.name for path in shared.parent.iterdir()) == [*LOCK_LEFT, "vault.key"]


@pytest.mark.skipif(sys.platform == "win32", reason="a key is put in its place by a second name of its file on Linux and macOS")
def test_the_restore_that_loses_the_race_to_put_the_first_key_in_place_reads_the_winners_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The bugs round of the third re-check.) Both got past the look for a key there; the first put its key in its place by a
    # second name of the file it wrote it into, and the second, refused there, read the key at once: with its two names for a
    # moment, it was refused as a link, and so was the restore. The second waits for the first, and reads the key it made.
    from qkvm import vault_storage

    archive = made(tmp_path / "backups")
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    shared = key_path(first)
    first_at_place, second_at_place, linked = threading.Event(), threading.Event(), threading.Event()
    link, parts = os.link, vault_storage._parts_of

    def ordered(source: Any, destination: Any, *given: Any, **said: Any) -> Any:
        if Path(destination) != shared:
            return link(source, destination, *given, **said)
        if threading.current_thread().name.startswith("first"):
            first_at_place.set()
            second_at_place.wait(5)  # (the second at its own place too, where it gets there)
            link(source, destination, *given, **said)
            linked.set()
            threading.Event().wait(1)  # (both names, for a moment)
            return None
        second_at_place.set()
        assert linked.wait(10)
        return link(source, destination, *given, **said)

    # (The second looked for a stopped one's leavings before the first had written anything: it saw none.)
    monkeypatch.setattr(vault_storage, "_parts_of", lambda path: [] if threading.current_thread().name == "MainThread" else parts(path))
    monkeypatch.setattr(os, "link", ordered)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="first") as pool:
        pending = pool.submit(backup.restore, archive, KEY, first)
        assert first_at_place.wait(30), "the first never came to put its key in its place"
        assert backup.restore(archive, KEY, second, shared).key_file == shared
        assert pending.result(timeout=60).key_file == shared
    for target in (first, second):
        assert len(Store(target / "qkvm.json", vault_key_file=shared, protected=True, read_only=True).devices) == 1


def test_a_finished_restore_whose_hold_could_not_be_taken_away_is_never_taken_for_a_stopped_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The re-check of the outside review's fixes, N7.) A restore that ended well takes its hold's file away last, and an
    # error there was let pass: the file stayed, and the next restore into the folder took the restored wall for one stopped
    # before it finished and took away its settings and its activity log. The hold says a restore ended well before it goes.
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    unlink = Path.unlink

    def held_on(path: Path, *given: Any, **said: Any) -> None:
        if path == target / backup.RESTORING:
            raise PermissionError(errno.EACCES, "the hold's file could not be taken away (as a scanner holding it would)")
        unlink(path, *given, **said)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "unlink", held_on)
        assert backup.restore(archive, KEY, target).held.devices == 1
    assert (target / backup.RESTORING).exists()
    assert not backup.left_by_a_restore(target)
    before = {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()}

    def failing(*given: Any, **said: Any) -> Any:
        raise backup.BackupError("damaged", "a read that fails after the backup's head was found good")

    monkeypatch.setattr(backup, "read", failing)
    with pytest.raises(backup.BackupError) as refused:
        backup.restore(archive, KEY, target)
    assert refused.value.code == "not_empty"
    assert {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()} == before


def test_a_finished_restore_whose_hold_could_neither_say_so_nor_go_is_never_taken_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second re-check, N7.) Where the hold's file could not be written that the restore ended well, nor be taken away,
    # the folder still holds the restored wall's settings, which a restore writes last: never a stopped restore's leavings.
    archive = made(tmp_path / "backups")
    target = tmp_path / "restored"
    unlink = Path.unlink

    def held_on(path: Path, *given: Any, **said: Any) -> None:
        if path == target / backup.RESTORING:
            raise PermissionError(errno.EACCES, "the hold's file could not be taken away")
        unlink(path, *given, **said)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "unlink", held_on)
        scoped.setattr(backup._Hold, "done", lambda self: None)  # (its file could not be written either)
        assert backup.restore(archive, KEY, target).held.devices == 1
    assert (target / backup.RESTORING).exists() and not backup.left_by_a_restore(target)
    before = {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()}

    def failing(*given: Any, **said: Any) -> Any:
        raise backup.BackupError("damaged", "a read that fails after the backup's head was found good")

    monkeypatch.setattr(backup, "read", failing)
    with pytest.raises(backup.BackupError) as refused:
        backup.restore(archive, KEY, target)
    assert refused.value.code == "not_empty"
    assert {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()} == before
