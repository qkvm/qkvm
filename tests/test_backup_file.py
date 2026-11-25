"""A backup of the wall as a file (backup.py): what it holds, how it is sealed, and what is refused.

Always encrypted with the backup key, a key apart from the vault's; authenticated, so that a byte changed anywhere, a file
cut short or one with more after its end is refused; refused with another key, and when a later version made it. Written
under a name that is no backup's until it is complete and reads back whole; the oldest go only after that.
"""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import backup
from qkvm._version import __version__
from qkvm.backup import BackupError
from qkvm.store import Store
from qkvm.vault import Vault

KEY = bytes(range(32))
DATA_KEY = bytes(range(100, 132))


def a_wall() -> dict[str, Any]:
    """Settings as a wall keeps them: a device whose password is sealed with the data key, an account."""
    vault = Vault()
    vault.adopt(DATA_KEY)
    settings = Store.of_document({}, Path("qkvm.json")).snapshot()
    settings["devices"] = [{"id": "ab12cd34", "name": "rack 1", "url": "https://127.0.0.1:9", "secret": vault.encrypt("the KVM's password", "ab12cd34")}]
    settings["users"] = [{"id": "u1", "name": "admin", "role": "admin", "auth": {"kdf": {}, "key": {}}}]
    settings["activity_key"] = "ab" * 32
    return settings


SETTINGS = a_wall()


def logs(*texts: bytes) -> list[tuple[str, Any, int]]:
    names = [f"audit.log.{number}" for number in range(len(texts) - 1, 0, -1)] + ["audit.log"]
    return [(name, io.BytesIO(text), len(text)) for name, text in zip(names, texts, strict=True)]


def made(folder: Path, key: bytes = KEY, **given: Any) -> Path:
    said: dict[str, Any] = {"settings": SETTINGS, "data_key": DATA_KEY, "logs": logs(b'{"event": "one"}\n', b'{"event": "two"}\n'), "history": None, "program": __version__, "keep": 7}
    said.update(given)
    done = backup.make(folder, key, **said)
    return folder / done.name


def test_a_backup_reads_back_with_everything_it_was_given(tmp_path: Path) -> None:
    history = tmp_path / "history-copy.sqlite"
    with sqlite3.connect(history) as conn:
        conn.execute("CREATE TABLE samples (t REAL, value REAL)")
        conn.executemany("INSERT INTO samples VALUES (?, ?)", [(each, each * 2.0) for each in range(1000)])
    conn.close()
    path = made(tmp_path / "backups", logs=logs(b'{"event": "old"}\n' * 3, b'{"event": "new"}\n'), history=history)
    assert backup.NAME.fullmatch(path.name) and path.is_file()
    held = backup.verify(path, KEY)
    assert (held.program, held.devices, held.accounts, held.secrets, held.not_opening) == (__version__, 1, 1, 1, 0)
    assert held.logs == [("audit.log.1", 3 * len(b'{"event": "old"}\n')), ("audit.log", len(b'{"event": "new"}\n'))]
    assert held.history == history.stat().st_size
    # What is in it is in it as it was given: the settings, the data key, every file's bytes.
    found: dict[str, bytes] = {}
    settings, data_key, (made_at, program) = backup.read(path, KEY, lambda name: found.setdefault(name, b""), lambda name, data: found.__setitem__(name, found[name] + data))
    assert settings == json.loads(json.dumps(SETTINGS)) and data_key == DATA_KEY
    assert (made_at, program) == backup.head_of(path, KEY) and program == __version__  # (the head the reading checked)
    assert found["audit.log.1"] == b'{"event": "old"}\n' * 3 and found["audit.log"] == b'{"event": "new"}\n'
    assert found["history.sqlite"] == history.read_bytes()


def test_nothing_of_the_wall_can_be_read_off_the_file(tmp_path: Path) -> None:
    path = made(tmp_path)
    raw = path.read_bytes()
    for clear in (b"rack 1", b"127.0.0.1", b"admin", b'"event"', DATA_KEY, DATA_KEY.hex().encode(), b"ab" * 32):
        assert clear not in raw, clear
    # Its head says what it is, which version made it, when, and which key opens it: no secret, and nothing of the wall.
    head = json.loads(raw.split(b"\n")[1])
    assert set(head) == {"format", "version", "program", "made", "key", "salt"} and head["key"] == backup.key_id(KEY)


@pytest.mark.parametrize("where", ["head", "first frame", "middle", "last byte"])
def test_a_byte_changed_anywhere_is_refused(tmp_path: Path, where: str) -> None:
    path = made(tmp_path, logs=logs(os.urandom(3 * backup.CHUNK), b'{"event": "new"}\n'))  # (random: it does not compress, so there are several frames)
    raw = bytearray(path.read_bytes())
    start = raw.index(b"\n", len(backup.MAGIC)) + 1
    at = {"head": raw.index(b'"made"') + 8, "first frame": start + 10, "middle": len(raw) // 2, "last byte": len(raw) - 1}[where]
    raw[at] ^= 0x01
    path.write_bytes(bytes(raw))
    with pytest.raises(BackupError) as refused:
        backup.verify(path, KEY)
    assert refused.value.code == "damaged", refused.value.message


@pytest.mark.parametrize("how", ["cut short", "cut at a frame", "cut at a frame, marked as the last", "more after its end", "a frame left out"])
def test_a_file_cut_short_or_added_to_is_refused(tmp_path: Path, how: str) -> None:
    path = made(tmp_path, logs=logs(os.urandom(3 * backup.CHUNK), b'{"event": "new"}\n'))
    raw = path.read_bytes()
    start = raw.index(b"\n", len(backup.MAGIC)) + 1
    first = int.from_bytes(raw[start : start + 4], "big") & ~backup.LAST
    if how == "cut short":
        raw = raw[:-5]
    elif how == "cut at a frame":
        raw = raw[: start + 4 + first]
    elif how == "cut at a frame, marked as the last":  # (the mark is in each frame's nonce: set on another frame, it does not open)
        raw = (first | backup.LAST).to_bytes(4, "big") + raw[start + 4 : start + 4 + first]
        raw = path.read_bytes()[:start] + raw
    elif how == "more after its end":
        raw = raw + raw[start : start + 4 + first]
    else:
        raw = raw[:start] + raw[start + 4 + first :]
    path.write_bytes(raw)
    with pytest.raises(BackupError) as refused:
        backup.verify(path, KEY)
    assert refused.value.code == "damaged", refused.value.message


def test_another_key_is_refused_and_said_to_be_another(tmp_path: Path) -> None:
    path = made(tmp_path)
    with pytest.raises(BackupError) as refused:
        backup.verify(path, bytes(32))
    assert refused.value.code == "wrong_key"
    assert backup.key_id(KEY) in refused.value.message  # (which kit it needs: the one of the key it names)


def test_a_backup_made_by_a_later_version_is_refused_with_a_sentence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import _version

    monkeypatch.setattr(_version, "__version__", "99.0.0")  # (as that version makes it: it reads its own back)
    later = made(tmp_path, program="99.0.0")
    monkeypatch.undo()
    with pytest.raises(BackupError) as refused:
        backup.verify(later, KEY)
    assert refused.value.code == "newer" and "99.0.0" in refused.value.message
    monkeypatch.setattr(backup, "VERSION", backup.VERSION + 1)
    other = made(tmp_path / "other")
    monkeypatch.undo()
    with pytest.raises(BackupError) as refused:
        backup.verify(other, KEY)
    assert refused.value.code == "newer"


def test_what_is_no_backup_is_said_to_be_none(tmp_path: Path) -> None:
    for text in (b"", b"QKVM-VAULT-2\nabc", b'{"format": "qkvm-export"}', backup.MAGIC + b"not json\n"):
        path = tmp_path / "file"
        path.write_bytes(text)
        with pytest.raises(BackupError) as refused:
            backup.verify(path, KEY)
        assert refused.value.code == "not_a_backup", text


def test_a_run_cut_off_in_the_middle_leaves_no_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "backups"
    first = made(folder)

    class Breaks(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise OSError(5, "the disk went away")

    with pytest.raises(OSError):
        made(folder, logs=[("audit.log", Breaks(b"x" * 100), 100)])
    # Nothing but the backup made before: no half file under a backup's name, and no half file left at all.
    assert sorted(os.listdir(folder)) == [first.name]
    # A half file a power cut left (under its name in the making) is never counted, and the next run takes it away.
    left = folder / f".qkvm-backup-{backup.key_id(KEY)}-20260101-030000.partial"
    left.write_bytes(first.read_bytes()[:100])
    assert backup.listed(folder) == [first]
    second = made(folder)
    assert not left.exists() and backup.listed(folder) == [second, first]


def test_the_oldest_go_only_after_a_new_one_is_written_and_reads_back_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "backups"
    kept = []
    for _ in range(3):
        kept.append(made(folder, keep=3))
        time.sleep(1.05)  # (a name a second)
    assert backup.listed(folder) == kept[::-1]
    # A run whose file does not read back whole: refused, and nothing goes.
    monkeypatch.setattr(backup, "verify", lambda path, key: (_ for _ in ()).throw(BackupError("damaged", "it does not read back")))
    with pytest.raises(BackupError):
        made(folder, keep=1)
    assert backup.listed(folder) == kept[::-1]
    monkeypatch.undo()
    newest = made(folder, keep=2)
    assert backup.listed(folder) == [newest, kept[2]]
    # Only what is a backup by its name is ever taken away: whatever else is in the folder stays.
    (folder / "notes.txt").write_text("mine", encoding="utf-8")
    made(folder, keep=1)
    assert (folder / "notes.txt").read_text(encoding="utf-8") == "mine"


def test_the_folder_and_the_files_are_the_walls_alone(tmp_path: Path) -> None:
    folder = tmp_path / "backups"
    path = made(folder)
    if sys.platform == "win32":
        from qkvm._folders import READ, not_alone

        assert not_alone(path, READ) is None and not_alone(folder) is None
    else:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_the_key_as_written_on_its_kit_gives_the_key_back_and_a_slip_is_caught() -> None:
    key = backup.new_key()
    assert len(key) == 32 and backup.new_key() != key
    written = backup.written(key)
    groups = written.split("-")
    assert len(groups) == 14 and all(len(group) == 4 for group in groups)
    assert backup.key_of(written) == key
    assert backup.key_of(written.lower().replace("-", " ")) == key  # (typed as it comes)
    assert backup.key_of(written.replace("O", "0").replace("I", "1").replace("B", "8")) == key  # (a 0 for an O: the alphabet has none)
    slip = written[:5] + ("A" if written[5] != "A" else "C") + written[6:]
    with pytest.raises(ValueError):
        backup.key_of(slip)
    kit = backup.kit(key, 1_763_000_000.0)
    assert written in kit and backup.key_id(key) in kit and backup.key_in_kit(kit) == key
    assert "--restore" in kit and kit.isascii()
    with pytest.raises(ValueError):
        backup.key_in_kit("no key in here at all")


def test_the_next_run_is_the_next_time_the_hour_comes(monkeypatch: pytest.MonkeyPatch) -> None:
    after = time.mktime((2026, 11, 17, 14, 30, 0, 0, 0, -1))
    assert backup.next_run(3, after) == time.mktime((2026, 11, 18, 3, 0, 0, 0, 0, -1))
    assert backup.next_run(15, after) == time.mktime((2026, 11, 17, 15, 0, 0, 0, 0, -1))
    assert backup.next_run(14, after) == time.mktime((2026, 11, 18, 14, 0, 0, 0, 0, -1))


def test_two_walls_on_one_folder_leave_each_others_backups_alone(tmp_path: Path) -> None:
    # Each wall prunes its own backups, known by its key in their names: another wall's (or this wall's under a key made
    # before) are never counted, pruned, or taken for a run of its own cut off. (The review of wave 3, M1: wall A with keep 1
    # deleted all three of wall B's.)
    folder, other = tmp_path / "share", bytes(range(1, 33))
    theirs = []
    for _ in range(3):
        theirs.append(made(folder, other, keep=7))
        time.sleep(1.05)  # (a name a second)
    mine = made(folder, KEY, keep=1)
    assert backup.key_id(KEY) in mine.name and backup.key_id(other) in theirs[0].name
    assert all(path.exists() for path in theirs) and mine.exists()
    assert backup.listed(folder, backup.key_id(KEY)) == [mine]
    assert backup.listed(folder, backup.key_id(other)) == theirs[::-1]
    assert (backup.others(folder, backup.key_id(KEY)), backup.others(folder, backup.key_id(other))) == (3, 1)
    assert backup.verify(backup.listed(folder, backup.key_id(other))[0], other).devices == 1
    # Their run in the making is theirs: only a run of this key's that was cut off is taken away.
    in_the_making = folder / f".qkvm-backup-{backup.key_id(other)}-20260101-030000.partial"
    left_of_mine = folder / f".qkvm-backup-{backup.key_id(KEY)}-20260101-030000.partial"
    for partial in (in_the_making, left_of_mine):
        partial.write_bytes(b"half")
    time.sleep(1.05)
    made(folder, KEY, keep=1)
    assert in_the_making.exists() and not left_of_mine.exists()
    assert all(path.exists() for path in theirs)


def test_a_backup_named_later_than_now_never_makes_the_new_one_go(tmp_path: Path) -> None:
    # A file whose name is later than the new one (made while the clock was ahead, or put there): it neither counts among
    # those kept nor takes the place of the new one, which is never pruned. Only this key's backups older than the new one go.
    folder = tmp_path / "backups"
    older = made(folder, keep=7)
    ahead = folder / re.sub(r"\d{8}-\d{6}", "20991117-030000", older.name)  # (named as this program names one, a year ahead)
    ahead.write_bytes(older.read_bytes())
    time.sleep(1.05)
    new = made(folder, keep=1)
    assert new.exists() and ahead.exists() and not older.exists()
    assert backup.verify(new, KEY).devices == 1


def test_a_thread_that_cannot_be_started_holds_no_place() -> None:
    # (The re-review of wave 3, a nit.) Counted before it was started, a thread the system would not start held its place for
    # good, and two such held the folder. It is busy now, said as busy, and nothing is held.
    import asyncio
    import threading

    lane = backup.FolderThreads(1, "said busy")
    real = threading.Thread.start

    def refused(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    threading.Thread.start = refused  # type: ignore[method-assign]
    try:
        with pytest.raises(BackupError) as busy:
            asyncio.run(lane.run(5.0, lambda: 1))
    finally:
        threading.Thread.start = real  # type: ignore[method-assign]
    assert busy.value.code == "busy" and lane.held == 0
    assert asyncio.run(lane.run(5.0, lambda: 2)) == 2 and lane.held == 0


def test_a_name_is_a_backups_with_its_digits_written_as_digits_are(tmp_path: Path) -> None:
    # (The re-review of wave 3, a nit.) A digit in a regular expression was any digit of any script: a name with Arabic-Indic
    # digits for its time was taken for a backup's, and its place in time read from them.
    folder = tmp_path / "backups"
    mine = made(folder)
    head = len("qkvm-backup-") + 16 + 1  # (its key id and the dash after it, as they are)
    odd = folder / (mine.name[:head] + mine.name[head:].replace("2", chr(0x0662)))  # (ARABIC-INDIC DIGIT TWO in its time)
    odd.write_bytes(mine.read_bytes())
    assert backup.listed(folder) == [mine] and backup.NAME.fullmatch(odd.name) is None


def test_a_late_end_is_told_before_its_place_is_given_back() -> None:
    # (The last look of wave 3, 4.) Told after, another run could begin into the folder first, and the late end then be kept
    # over what that one made. While it is told, its place is still held.
    import asyncio
    import threading

    lane = backup.FolderThreads(1, "said busy")
    let_go, told = threading.Event(), threading.Event()
    held_when_told: list[int] = []

    def late(result: Any, failure: BaseException | None) -> None:
        held_when_told.append(lane.held)
        told.set()

    with pytest.raises(backup.FolderTimeout):
        asyncio.run(lane.run(0.2, let_go.wait, 30, late=late, folder="/srv/backups"))
    let_go.set()
    assert told.wait(10) and held_when_told == [1]
    deadline = time.monotonic() + 10
    while lane.held and time.monotonic() < deadline:
        time.sleep(0.01)
    assert lane.held == 0


def another_name_for(folder: Path, alias: Path) -> None:
    """Another name for a folder that is there: a junction on Windows (which takes no rights to make), a link elsewhere."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(folder), str(alias))
    else:
        alias.symlink_to(folder, target_is_directory=True)
    assert os.path.samefile(folder, alias)


@pytest.mark.parametrize("named", ["as it was", "by another name", "by another name, made by the first"])
def test_work_on_a_folder_holds_that_folder_by_any_name_until_it_ends(tmp_path: Path, named: str) -> None:
    # (The outside review of 0.4.0, bugs round: the guard's own test, and M6.) Work into a folder whose bound cut it off holds
    # that folder until its thread ends, and no other is begun into it: by the name it was given, and by another name for the
    # same folder on the disk (a junction, a link, a short name; on Linux a second mount usually has a device number of its
    # own, and is not known as the same: folder_identity), whose work would have taken away the first
    # one's file in the making. (The fresh review of the fixes, N1: also a folder not there before the first work, which its
    # thread makes before it looks at what it is, so that it is known by itself and not by the folder above it.)
    import asyncio
    import threading

    folder = tmp_path / "folder"
    if named != "by another name, made by the first":
        folder.mkdir()
    other = folder if named == "as it was" else tmp_path / "alias"
    if named == "by another name":
        another_name_for(folder, other)
    entered, let_go = threading.Event(), threading.Event()
    begun: list[int] = []

    def stalled() -> None:
        entered.set()
        let_go.wait(30)

    async def both() -> None:
        lane = backup.FolderThreads(3, "every place is held", same_folder="one folder, one at a time")
        try:
            with pytest.raises(backup.FolderTimeout):
                await lane.run(0.2, stalled, folder=str(folder))
            assert entered.is_set() and lane.held == 1
            if named == "by another name, made by the first":
                assert folder.is_dir()  # (made on the work's own thread, before it was looked at)
                another_name_for(folder, other)
            with pytest.raises(BackupError, match="one folder, one at a time"):
                await lane.run(5.0, lambda: begun.append(1), folder=str(other))
            assert begun == [] and lane.held == 1
            assert lane.holding(str(other)) is not None  # (known by that name too, from now on)
        finally:
            let_go.set()
            for _ in range(1000):
                if not lane.held:
                    break
                await asyncio.sleep(0.01)
        assert lane.held == 0 and lane.holding(str(other)) is None
        assert await lane.run(5.0, lambda: begun.append(2), folder=str(other)) is None and begun == [2]  # (free once it has ended)

    asyncio.run(both())


def utc(*when: int) -> float:
    import calendar

    return float(calendar.timegm((*when, 0, 0)[:6]))


def numberless(path: Any, device: int | None = None) -> os.stat_result:
    """What the system says of a folder on a share whose server gives no file numbers (0): of this computer's own folder,
    with that, and the volume number given where one is (some such servers say 0 for that too)."""
    seen = os.stat(path)
    return os.stat_result((seen.st_mode, 0, seen.st_dev if device is None else device, seen.st_nlink, 0, 0, seen.st_size, 0, 0, 0))


def test_a_folder_on_a_volume_without_file_numbers_is_held_with_its_whole_volume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fresh review of the fixes, N1, by reading.) Where the system gives no file number for a folder (some shares give 0),
    # what it is cannot be told apart from another folder of the same volume by any name it has (a mapped drive and its
    # UNC name, a junction): where the share's root cannot be had either, the safe side, its whole volume, so that no run is
    # begun beside one into a folder of that volume. Another volume's folder is another.
    monkeypatch.setattr(backup, "share_root", lambda folder, device: None, raising=False)  # (no share's root to be had)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert backup.folder_identity(a) != backup.folder_identity(b)  # (with file numbers: each folder its own)
    assert backup.folder_identity(a, stat=numberless) == backup.folder_identity(b, stat=numberless)
    assert backup.folder_identity(a, stat=numberless) != backup.folder_identity(b, stat=lambda path: numberless(path, os.stat(path).st_dev + 1))


def test_shares_of_two_servers_without_file_numbers_are_two_volumes_though_they_report_one_number(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The last look at the fixes of 0.4.0, L3.) On Windows the volume number of a share is the one its server reports, and
    # two servers can report the same (some report 0): a folder on a share of one, held by a run that never ends, held every
    # folder of the other's too, where the backups were moved to because the first is gone. The share's own root (its
    # \\server\share, or the source of its mount on Linux) is part of what such a folder is; where it cannot be had, the
    # whole volume as before.
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    roots: dict[Path, str | None] = {a: "\\\\nas-a\\backups", b: "\\\\nas-b\\backups"}
    monkeypatch.setattr(backup, "share_root", lambda folder, device: roots[folder], raising=False)

    def zero(path: Any) -> os.stat_result:
        return numberless(path, 0)

    one, other = backup.folder_identity(a, stat=zero), backup.folder_identity(b, stat=zero)
    assert one != other, "two servers' shares that report the same volume number are taken for one volume"
    assert not backup.same_place(one, other)
    roots[b] = roots[a]  # (the same share, by another name for a folder of it)
    assert backup.same_place(one, backup.folder_identity(b, stat=zero))
    roots[b] = None  # (its root not to be had: held with the whole volume, against every share of that number)
    assert backup.same_place(one, backup.folder_identity(b, stat=zero)) and backup.same_place(backup.folder_identity(b, stat=zero), one)
    assert not backup.same_place(one, backup.folder_identity(b, stat=lambda path: numberless(path, 7)))  # (another volume)
    # A folder with file numbers is its own, whatever share it is on.
    assert not backup.same_place(backup.folder_identity(a), backup.folder_identity(b)) and backup.same_place(backup.folder_identity(a), backup.folder_identity(a))


@pytest.mark.parametrize(
    "path, root",
    [
        ("\\\\nas-a\\backups\\qkvm", "\\\\nas-a\\backups"),
        ("//NAS-A/Backups/qkvm/", "\\\\nas-a\\backups"),  # (another spelling: the same share)
        ("\\\\?\\UNC\\nas-a\\backups\\qkvm", "\\\\nas-a\\backups"),
        ("Z:\\qkvm", "\\\\nas-a\\backups"),  # a mapped drive: what it is mapped to
        ("z:/qkvm", "\\\\nas-a\\backups"),
        ("\\\\?\\Z:\\qkvm", "\\\\nas-a\\backups"),
        ("D:\\backups", None),  # (a drive that is mapped to nothing)
        ("\\\\nas-a", None),
        ("\\\\nas-a\\", None),
        ("\\\\.\\pipe\\qkvm", None),
        ("\\\\?\\Volume{0b1c2d3e-0000-0000-0000-000000000000}\\qkvm", None),
        ("backups", None),
    ],
)
def test_the_root_of_a_share_on_windows_is_its_server_and_share(path: str, root: str | None) -> None:
    mapped = {"Z:": "\\\\NAS-A\\Backups"}
    assert backup.windows_share(path, mapped.get) == root


def test_the_root_of_a_share_on_linux_is_the_source_of_its_mount(tmp_path: Path) -> None:
    info = tmp_path / "mountinfo"
    info.write_text(
        "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
        "40 22 0:52 / /mnt/nas\\040a rw,relatime shared:20 - cifs //nas-a/backups rw,vers=3.1.1\n"
        "41 22 0:52 /qkvm /mnt/again rw,relatime shared:20 - cifs //nas-a/backups rw,vers=3.1.1\n"  # (a bind mount of it)
        "42 22 0:53 / /mnt/nfs rw - nfs4 nas-b:/export/backups rw\n"
        "43 22 0:54 / /mnt/odd\\040one rw - cifs //nas-c/back\\040ups rw\n",
        encoding="utf-8",
    )
    assert backup.source_of("0:52", info) == "//nas-a/backups"
    assert backup.source_of("0:53", info) == "nas-b:/export/backups"
    assert backup.source_of("0:54", info) == "//nas-c/back ups"
    assert backup.source_of("0:99", info) is None and backup.source_of("0:52", tmp_path / "not there") is None
    if sys.platform != "win32":
        assert backup.mount_source(os.makedev(0, 53), info) == "nas-b:/export/backups"


def test_a_share_whose_root_cannot_be_asked_for_is_held_with_its_whole_volume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Whatever goes wrong in asking for a share's root is no root (the safe side), never an error that ends the folder's
    # thread before it gives its place back.
    def broken(*given: Any) -> str:
        raise RuntimeError("cannot say")

    monkeypatch.setattr(backup, "windows_share", broken)
    monkeypatch.setattr(backup, "mount_source", broken)
    assert backup.share_root(tmp_path, 0) is None


def test_work_into_a_share_without_file_numbers_holds_that_share_and_not_another_servers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (L3, through the folder's threads.) A run cut off on a share of one server, two servers whose shares say volume 0: a
    # run into the other server's share goes; one into the same share by another name, or into a share whose root cannot
    # be had, is not begun. The root is read on the folder's own thread, never the event loop's.
    import asyncio
    import threading

    one, two, same, unknown = (tmp_path / name for name in ("one", "two", "same", "unknown"))
    roots: dict[Path, str | None] = {one: "\\\\nas-a\\backups", two: "\\\\nas-b\\backups", same: "\\\\nas-a\\backups", unknown: None}
    asked_on: list[str] = []

    def root(folder: Path, device: int) -> str | None:
        asked_on.append(threading.current_thread().name)
        return roots[folder]

    real = backup.folder_identity
    monkeypatch.setattr(backup, "share_root", root, raising=False)
    monkeypatch.setattr(backup, "folder_identity", lambda folder: real(folder, stat=lambda path: numberless(path, 0)))
    entered, let_go = threading.Event(), threading.Event()
    begun: list[str] = []

    def stalled() -> None:
        entered.set()
        let_go.wait(30)

    async def scenario() -> None:
        lane = backup.FolderThreads(4, "every place is held", same_folder="one folder, one at a time")
        try:
            with pytest.raises(backup.FolderTimeout):
                await lane.run(0.2, stalled, folder=str(one))
            assert entered.is_set() and lane.held == 1
            assert await lane.run(5.0, lambda: begun.append("two"), folder=str(two)) is None, "another server's share was held"
            for held in (same, unknown):
                with pytest.raises(BackupError, match="one folder, one at a time"):
                    await lane.run(5.0, lambda: begun.append("held"), folder=str(held))
            assert begun == ["two"] and lane.held == 1
            assert lane.holding(str(same)) is not None and lane.holding(str(two)) is None
        finally:
            let_go.set()
            for _ in range(1000):
                if not lane.held:
                    break
                await asyncio.sleep(0.01)
        assert lane.held == 0

    asyncio.run(scenario())
    assert asked_on and set(asked_on) == {"backup-folder"}, asked_on


def test_a_share_without_file_numbers_on_a_volume_with_a_number_is_held_whole_by_any_name_of_its_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final look at 0.4.0, M2.) A share's root is made of the name it is reached by: \\nas-a\backups, \\192.0.2.10\backups,
    # \\nas-a.corp.example\backups (and \\nas-a\data, where that share's folder holds the other) are one folder by other
    # roots. Told apart by its root wherever its volume had a number, a run cut off on one, and one into the same folder by
    # the server's address, went on at once. The root tells shares apart only where the volume number is 0 (L3: some servers
    # say 0, two of them alike); a volume of any other number is held whole, by any name of any server.
    import asyncio
    import threading

    by_name, by_address, another_volume = (tmp_path / name for name in ("by-name", "by-address", "another-volume"))
    roots: dict[Path, str | None] = {by_name: "\\\\nas-a\\backups", by_address: "\\\\192.0.2.10\\backups", another_volume: "\\\\nas-a\\backups"}
    monkeypatch.setattr(backup, "share_root", lambda folder, device: roots[folder], raising=False)

    def numbered(path: Any) -> os.stat_result:
        return numberless(path, 0x5A17C0DE if Path(path) != another_volume else 0x5A17C0DF)

    for each in roots:
        each.mkdir()
    one, other = backup.folder_identity(by_name, stat=numbered), backup.folder_identity(by_address, stat=numbered)
    assert backup.same_place(one, other) and backup.same_place(other, one), "one volume of a share by two names of its server is taken for two"
    assert not backup.same_place(one, backup.folder_identity(another_volume, stat=numbered))  # (another volume)
    real = backup.folder_identity
    monkeypatch.setattr(backup, "folder_identity", lambda folder: real(folder, stat=numbered))
    entered, let_go = threading.Event(), threading.Event()
    begun: list[str] = []

    def stalled() -> None:
        entered.set()
        let_go.wait(30)

    async def scenario() -> None:
        lane = backup.FolderThreads(4, "every place is held", same_folder="one folder, one at a time")
        try:
            with pytest.raises(backup.FolderTimeout):
                await lane.run(0.2, stalled, folder=str(by_name))
            assert entered.is_set() and lane.held == 1
            with pytest.raises(BackupError, match="one folder, one at a time"):
                await lane.run(5.0, lambda: begun.append("by its address"), folder=str(by_address))
            assert await lane.run(5.0, lambda: begun.append("another volume"), folder=str(another_volume)) is None
            for _ in range(1000):  # (its thread gives its place back just after its waiter has its result)
                if lane.held == 1:
                    break
                await asyncio.sleep(0.01)
            assert begun == ["another volume"] and lane.held == 1
        finally:
            let_go.set()
            for _ in range(1000):
                if not lane.held:
                    break
                await asyncio.sleep(0.01)
        assert lane.held == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("when", ["in the same second", "a second later"])
def test_a_runs_start_never_takes_away_the_file_in_the_making_of_a_run_that_goes_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str) -> None:
    # (The final look at 0.4.0, M2.) A run takes away the files in the making of its key that a run cut off left. Two runs
    # into one folder at once (by two names that the folder's threads did not know as one), the second's start took away
    # the first's file in the making: the first wrote on into nothing, its name was gone, and its backup was lost, said as
    # failed. Begun in the same second, the second's file had the first's name, and its refusal took the first's away as its
    # own. A file in the making of a run of this program that has not ended is never touched, by any name for its folder,
    # and two runs never write under one name.
    import threading
    import types

    folder, alias = tmp_path / "backups", tmp_path / "alias"
    folder.mkdir()
    another_name_for(folder, alias)
    clock = [1_763_420_400.0]
    names = ("gmtime", "localtime", "monotonic", "sleep", "strftime", "struct_time")
    monkeypatch.setattr(backup, "time", types.SimpleNamespace(**{name: getattr(time, name) for name in names}, time=lambda: clock[0]))
    entered, let_go = threading.Event(), threading.Event()

    class Stalls(io.BytesIO):
        """An activity log that is read slowly: the first run is in the making until it is let go."""

        def read(self, size: int | None = -1) -> bytes:
            entered.set()
            let_go.wait(30)
            return super().read(size)

    text = b'{"event": "one"}\n'
    ended: list[Any] = []

    def first() -> None:
        try:
            ended.append(made(folder, logs=[("audit.log", Stalls(text), len(text))]))
        except BaseException as ex:  # (said below)
            ended.append(ex)

    worker = threading.Thread(target=first, daemon=True)
    worker.start()
    try:
        assert entered.wait(10), "the first run never began"
        [making] = [path for path in folder.iterdir() if backup.PARTIAL.fullmatch(path.name)]
        if when == "a second later":
            clock[0] += 1.0
        second = made(alias)
        assert making.exists(), "the second run's start took away the first run's file in the making"
    finally:
        let_go.set()
        worker.join(10)
    [first_made] = ended
    assert isinstance(first_made, Path) and first_made.exists(), f"the first run's backup was lost: {first_made!r}"
    assert backup.verify(first_made, KEY).logs == [("audit.log", len(text))] and backup.verify(second, KEY).devices == 1
    assert sorted(path.name for path in backup.listed(folder)) == sorted({first_made.name, second.name}) and len({first_made.name, second.name}) == 2
    assert not [path for path in folder.iterdir() if backup.PARTIAL.fullmatch(path.name)]


EDT_FROM, EDT_UNTIL = utc(2026, 3, 8, 7), utc(2026, 11, 1, 6)  # (07:00 UTC is 02:00 EST; 06:00 UTC is 02:00 EDT)


def in_new_york(at: float) -> time.struct_time:
    """The clock of a computer in New York in 2026 (EST, and EDT between those two moments), whatever this computer's own
    zone is: for which of an hour shown twice, or never, the clock's run is at."""
    return time.gmtime(at - (4 if EDT_FROM <= at < EDT_UNTIL else 5) * 3600)


@pytest.mark.parametrize(
    "hour, after, at",
    [
        (1, utc(2026, 11, 1, 4, 30), utc(2026, 11, 1, 5, 0)),  # 01:00 shown twice: the first (EDT), never the second
        (1, utc(2026, 11, 1, 5, 30), utc(2026, 11, 2, 6, 0)),  # ...and once the first has come, not the second, but tomorrow's
        (2, utc(2026, 3, 8, 6, 30), utc(2026, 3, 8, 7, 0)),  # 02:00 never shown: the next minute there is (03:00 EDT), that day
        (2, utc(2026, 3, 8, 7, 30), utc(2026, 3, 9, 6, 0)),  # ...and once that has come, tomorrow's
        (3, utc(2026, 6, 1, 12, 0), utc(2026, 6, 2, 7, 0)),  # a day like any other
        (23, utc(2026, 1, 1, 3, 0), utc(2026, 1, 1, 4, 0)),  # (22:00 EST on the last day of the year: 23:00 that day)
    ],
)
def test_the_clocks_hour_on_a_day_its_clock_is_set_back_or_on_is_its_first_or_the_next_real_minute(hour: int, after: float, at: float) -> None:
    # (The outside review of 0.4.0, bugs round, a LOW.) mktime picks either of an hour shown twice, and goes either way from
    # one never shown, by system: Windows ran the backup of a night the clock is set back at the second 01:00, and on the
    # night it is set on, asked for 02:00, skipped the whole day. The first, and where there is none, the next real minute.
    assert backup.next_run(hour, after, clock=in_new_york) == at


@pytest.mark.parametrize("season", ["fall", "spring"])
def test_the_clocks_hour_by_this_computers_own_clock_set_to_new_york(monkeypatch: pytest.MonkeyPatch, season: str) -> None:
    # The same by the system's own clock, its zone set for this process alone (TZ, as the C runtime reads it).
    import ctypes

    reset = time.tzset if hasattr(time, "tzset") else getattr(ctypes.CDLL("ucrtbase"), "_tzset", None) if sys.platform == "win32" else None
    if reset is None:
        pytest.skip("this system's zone cannot be set for one process")
    # With its rules said: a bare EST5EDT is New York's only where the system has a file of that name (Debian 13 moved
    # it to tzdata-legacy, and glibc then takes the US rules of before 2007). Windows' C runtime reads no rules and
    # knows only the US ones of today.
    monkeypatch.setenv("TZ", "EST5EDT" if sys.platform == "win32" else "EST5EDT,M3.2.0,M11.1.0")
    reset()
    try:
        hours = (time.localtime(utc(2026, 11, 1, 4, 30)).tm_hour, time.localtime(utc(2026, 7, 1, 4, 30)).tm_hour)
        if sys.platform == "win32" and hours == (23, 23):
            # GitHub's Windows machines, whose own zone is UTC: their C runtime takes TZ's five hours but no summer time
            # from it (on a machine whose own zone has a summer time it takes both), so New York cannot be had there.
            pytest.skip("this system's C runtime takes no summer time from TZ")
        assert hours == (0, 0)
        if season == "fall":
            assert backup.next_run(1, utc(2026, 11, 1, 4, 30)) == utc(2026, 11, 1, 5, 0)
        else:
            assert backup.next_run(2, utc(2026, 3, 8, 6, 30)) == utc(2026, 3, 8, 7, 0)
    finally:
        monkeypatch.undo()
        reset()


def test_a_backup_opens_with_a_reader_of_its_own(tmp_path: Path) -> None:
    # (The outside review of 0.4.0, bugs round: a gap in these tests.) Read here with nothing of backup.py's: the kit's key and
    # its check, the key's id, each file's key by HKDF made of HMACs (RFC 5869), and three frames and more, opened with
    # AES-GCM, bound to the head. A writer and a reader of one module agree with each other whatever they do: with the
    # file key derived from 32 zero bytes instead of the head's random ones, every other test here passed.
    import base64
    import hashlib
    import hmac
    import zlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes(range(32))
    written = backup.kit(key, time.time()).split("Backup key:\n\n")[1].splitlines()[0].strip()
    raw = base64.b32decode(written.replace("-", ""))
    assert raw[:32] == key and raw[32:] == hashlib.sha256(b"qkvm backup key check" + key).digest()[:3]
    assert backup.key_id(key) == hmac.new(key, b"qkvm backup key id", hashlib.sha256).hexdigest()[:16]
    log = b"".join(hashlib.sha256(number.to_bytes(8, "big")).digest() for number in range(70_000))  # (does not compress: frames)
    settings = {"review": "snowman ☃"}
    made = backup.make(tmp_path / "backups", key, settings=settings, data_key=b"D" * 32, logs=[("audit.log", io.BytesIO(log), len(log))], history=None, program=__version__, keep=2)
    content = (tmp_path / "backups" / made.name).read_bytes()
    end = content.index(b"\n", len(b"QKVM-BACKUP\n")) + 1
    head = content[:end]
    said = json.loads(head.splitlines()[1])
    extracted = hmac.new(base64.b64decode(said["salt"]), key, hashlib.sha256).digest()
    file_key = hmac.new(extracted, b"qkvm-backup 1 file key\x01", hashlib.sha256).digest()
    at, number, plain, last = end, 0, bytearray(), False
    while not last:
        word = int.from_bytes(content[at : at + 4], "big")
        at += 4
        last, length = bool(word & (1 << 31)), word & ((1 << 31) - 1)
        nonce = number.to_bytes(11, "big") + bytes([int(last)])
        plain += AESGCM(file_key).decrypt(nonce, content[at : at + length], hashlib.sha256(head).digest())
        at += length
        number += 1
    assert number >= 3 and at == len(content)
    unpacked, at, parts = zlib.decompress(bytes(plain)), 0, {}
    while at < len(unpacked):
        size = int.from_bytes(unpacked[at : at + 2], "big")
        name = unpacked[at + 2 : at + 2 + size].decode("ascii")
        at += 2 + size
        length = int.from_bytes(unpacked[at : at + 8], "big")
        parts[name] = unpacked[at + 8 : at + 8 + length]
        at += 8 + length
    assert list(parts) == ["backup.json", "audit.log", "end"] and parts["audit.log"] == log and parts["end"] == b""
    assert json.loads(parts["backup.json"]) == {"settings": settings, "data_key": (b"D" * 32).hex()}
