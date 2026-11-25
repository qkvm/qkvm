"""A wall brought back from its backup on a new computer: `python -m qkvm --restore FILE --backup-key KIT` (0.4.0).

Into an empty data folder only. With the kit alone: no file of the old computer (not its storage key) is needed. As it
was: every account with its rights and password, the identity provider as it was set up, every device's password, the
tokens, the destinations, and an activity log that checks intact as it did. Never weaker: nothing carries on by itself
until somebody signs in, and backups wait for an admin to switch them on where only this wall writes. Refused, leaving
nothing behind: a folder with anything in it, a changed file, another key, a later version.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from qkvm import backup, chain, checklog, cli, kvm, oidc, update, vault
from qkvm._version import __version__
from qkvm.store import OidcSettings, Store, position_of
from qkvm.vault_storage import key_path
from tests.test_a_restore_holds_its_folder import LOCK_LEFT
from tests.test_wall import PASSWORD, add, closed_port, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


OTHER = "another password 22"


def a_whole_wall(data: Path, folder: Path, bulky: bool = False) -> tuple[Path, str, dict[str, Any]]:
    """A wall with one of everything there is to bring back, and a backup of it. (The backup, its kit, the token made.)
    `bulky`: with an activity log that takes several frames of a backup, so that a restore has written much before its end."""
    with wall(data) as admin:
        core: Any = admin.core  # type: ignore[attr-defined]
        for _ in range(40) if bulky else ():
            core.audit.write("note", "", said=os.urandom(30_000).hex())  # (random: it does not compress below a frame)
        first = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, name="rack 1")
        add(admin, f"https://127.0.0.1:{closed_port()}", force=True, name="rack 2", group="lab")
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": OTHER, "devices": [first], "groups": ["lab"]}).status_code == 201
        ivan = admin.post("/api/v1/users", json={"name": "ivan", "role": "operator", "password": OTHER}).json()["user"]["id"]
        assert admin.put(f"/api/v1/users/{ivan}", json={"name": "ivan", "role": "operator", "suspended": True}).status_code == 200
        token = admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator", "devices": [first]}).json()["token"]
        assert admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        assert admin.post("/api/v1/actions", json={"name": "Hello", "kind": "text", "text": "a saved text"}).status_code == 201
        assert admin.post("/api/v1/alerts/destinations", json={"kind": "webhook", "url": "https://hooks.invalid/S3CRET"}).status_code == 201
        assert admin.post("/api/v1/recovery", json={"password": PASSWORD}).status_code == 200
        olga = core.store.user_named("olga")
        olga.totp = core.vault.encrypt("JBSWY3DPEHPK3PXP", f"totp:{olga.id}")  # (her app's key, as two-factor sign-in seals it)
        core.store.oidc = OidcSettings(
            enabled=True, name="Company", issuer="https://id.invalid", client_id="qkvm", secret=core.vault.encrypt("client S3CRET", oidc.SEALED_FOR),
            roles={"ops": "admin", "staff": "viewer"}, anyone="viewer", domain="example.com", redirect_uri="https://wall.invalid/api/v1/oidc/callback",
        )  # fmt: skip
        core.store.server.history_days = 30
        core.store.save()
        made = admin.post("/api/v1/backups/key", json={"password": PASSWORD}).json()
        assert admin.put("/api/v1/backups", json={"enabled": True, "folder": str(folder), "hour": 3, "keep": 7, "history": True}).status_code == 200
        assert admin.post("/api/v1/backups/run").json()["ok"] is True
        admin.post("/api/v1/logout")
    kit = data.parent / "kit.txt"
    kit.write_text(made["kit"], encoding="utf-8")
    [file] = backup.listed(folder)
    return file, str(kit), {"token": token, "key": made["key"]}


def restore(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    status = cli.main(["--restore", *argv])
    said = capsys.readouterr()
    return status, said.out + said.err


def settings_in(file: Path, key: str) -> dict[str, Any]:
    settings, _, _ = backup.read(file, backup.key_of(key), lambda name: None, lambda name, data: None)
    return settings


def test_a_wall_comes_back_whole_from_its_backup_and_its_kit_alone(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    file, kit, made = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    new = tmp_path / "new"
    status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(new))
    assert status == 0, said
    assert "3 accounts" in said and "2 machines" in said and "checks intact" in said and "Backups are off" in said
    assert "make a new backup key" in said and "opens what it makes" not in said  # (the kit used opens the backups before only)
    # The settings are the backup's as they were, but for what makes the restored wall less, never more: nothing opens the
    # saved passwords by itself until somebody signs in, and backups wait for an admin to switch them on.
    kept = settings_in(file, made["key"])
    restored = Store(new / "qkvm.json", protected=True).snapshot()
    assert kept["unlock"] is not None and restored["unlock"] is None
    assert kept["backups"]["enabled"] is True and restored["backups"]["enabled"] is False
    for part in ("unlock", "backups"):
        kept.pop(part), restored.pop(part)
    assert restored == kept
    # ...which is the wall as it was: accounts with their rights, tokens, devices, actions, destinations, the provider.
    old = Store(tmp_path / "old" / "qkvm.json", protected=True).snapshot()
    for part in ("users", "devices", "actions", "tokens", "destinations", "oidc", "recovery", "server", "activity_key"):
        assert restored[part] == old[part], part
    # The storage key is the new folder's own, made by the restore: the old computer's is no part of it.
    assert key_path(new).exists() and key_path(new).read_bytes() != key_path(tmp_path / "old").read_bytes()
    assert not (new / "unlock.key").exists() and not (new / "sessions.json").exists()
    # The history came with it, and the activity log checks intact: the backup's seal is where the settings hold it to, and
    # the restore's own line follows it in the chain.
    assert (new / "history.sqlite").stat().st_size > 0
    files = [new / name for name in reversed(backup.LOGS) if (new / name).exists()]
    key = bytes.fromhex(restored["activity_key"])
    verdict = checklog.check(files, key, None, position_of(restored["activity_position"]))
    assert verdict.intact and not verdict.problems, verdict.problems
    last = json.loads((new / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert last["event"] == "wall_restored" and last["file"] == file.name and chain.FIELD in last
    assert (last["program"], last["made"]) == (__version__, round(backup.head_of(file, backup.key_of(made["key"]))[0])) and last["made"] > 0
    # And it is the wall: its accounts sign in with their passwords, the saved passwords open, the token works.
    with wall(new, sign_in=False) as browser:
        assert browser.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        core: Any = browser.core  # type: ignore[attr-defined]
        device = core.store.devices[0]
        assert core.vault.read(device.secret, device.id) == "secret"
        assert core.vault.read(core.store.oidc.secret, oidc.SEALED_FOR) == "client S3CRET"
        olga = core.store.user_named("olga")
        assert olga.role == "viewer" and olga.devices == [device.id] and olga.groups == ["lab"] and core.vault.read(olga.totp, f"totp:{olga.id}")
        assert core.store.user_named("ivan").suspended is True
        assert core.store.oidc.enabled is True and core.store.oidc.roles == {"ops": "admin", "staff": "viewer"}
        # No backup key (the backup held none: the outside review of 0.4.0, H1), so nothing it makes opens with the kit used;
        # its admin makes a new one, whose kit opens what it makes from then on.
        shown = browser.get("/api/v1/backups").json()
        assert (shown["key"], shown["enabled"], shown["latest"]) == (None, False, None)
        assert core.store.backups.secret is None and core.store.backups.key_id == ""
        refused = browser.put("/api/v1/backups", json={"enabled": True, "folder": str(tmp_path / "elsewhere"), "hour": 3, "keep": 7, "history": False})
        assert (refused.status_code, refused.json()["code"]) == (409, "no_key")
        again = browser.post("/api/v1/backups/key", json={"password": PASSWORD}).json()
        assert again["id"] != backup.key_id(backup.key_of(made["key"]))
    # ...and from then on it carries on by itself, as the wall did, and the script's token works as before.
    with wall(new, sign_in=False) as script:
        assert script.core.vault.unlocked  # type: ignore[attr-defined]
        assert script.get("/api/v1/wall", headers={"Authorization": f"Bearer {made['token']}"}).status_code == 200


# A restore in a process of its own, stopped dead the moment its settings are written, or as it comes to its line in the log.
STOPPED_AT = """
import os, sys
from pathlib import Path
from qkvm import backup, store
real_write, real_line = store.Store.write, store.AuditLog.write
def settings_written(self, *given, **said):
    real_write(self, *given, **said)
    os._exit(73)
def line(self, event, *given, **said):
    if event == "wall_restored":
        os._exit(73)
    return real_line(self, event, *given, **said)
if sys.argv[4] == "after its settings":
    store.Store.write = settings_written
else:
    store.AuditLog.write = line
backup.restore(Path(sys.argv[1]), backup.key_of(sys.argv[3]), Path(sys.argv[2]))
"""


@pytest.mark.parametrize("where", ["after its settings", "before its line"])
def test_a_restore_stopped_near_its_end_never_leaves_a_wall_without_its_line_in_the_log(tmp_path: Path, capsys: pytest.CaptureFixture[str], where: str) -> None:
    # (The outside review of 0.4.0, fifth round, M3.) A folder with its settings in it is a wall to the next restore, never a
    # stopped one's leavings (N7); the line that says it was restored came after them, so a restore stopped between the two
    # left a wall without that line, which the same command then refused to finish. The line, and the log's check, come first.
    from tests.test_a_restore_holds_its_folder import child, whole

    file, kit, made = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    new = tmp_path / "new"
    stopped = child(STOPPED_AT, file, new, made["key"], where)
    _, said = stopped.communicate(timeout=120)
    assert stopped.returncode == 73, said
    lines = [json.loads(line)["event"] for line in (new / "audit.log").read_text(encoding="utf-8").splitlines()]
    if where == "after its settings":
        # A wall already, and its line is there: what is left is what a start does anyway (it reads the settings).
        assert (new / "qkvm.json").is_file() and lines.count("wall_restored") == 1 and lines[-1] == "wall_restored", lines
        assert not backup.left_by_a_restore(new)
        return
    # Stopped before its line: no settings yet, so the same command takes it over, and ends with the line, once.
    assert not (new / "qkvm.json").exists() and "wall_restored" not in lines and backup.left_by_a_restore(new)
    status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(new))
    assert status == 0 and "had been stopped before it finished" in said and "checks intact" in said, said
    whole(new)
    lines = [json.loads(line)["event"] for line in (new / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert lines.count("wall_restored") == 1 and lines[-1] == "wall_restored", lines


# A restore in a process of its own, stopped dead as it makes the storage key: after its line in the log, before its settings.
STOPPED_AT_THE_KEY = """
import os, sys
from pathlib import Path
from qkvm import backup, vault_storage
vault_storage.make_key = lambda *given, **said: os._exit(73)
backup.restore(Path(sys.argv[1]), backup.key_of(sys.argv[3]), Path(sys.argv[2]))
"""


def test_a_start_refuses_a_folder_whose_restore_has_not_finished_and_says_to_run_it_again(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of this round, L5.) Started on what a stopped restore left (its line in the log, its hold, no settings), the
    # wall was a first start: set up anew, beside the old wall's activity log, which then checked broken; and what it wrote
    # there kept the same --restore from finishing. A start refuses such a folder now, with what to do, and writes nothing.
    import uvicorn

    from tests.test_a_restore_holds_its_folder import child, whole
    from tests.test_wall import port_to_listen_on

    file, kit, made = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    new = tmp_path / "new"
    stopped = child(STOPPED_AT_THE_KEY, file, new, made["key"])
    _, said = stopped.communicate(timeout=120)
    assert stopped.returncode == 73, said
    assert backup.unfinished_restore(new) and not (new / "qkvm.json").exists()
    before = {path.name: path.read_bytes() for path in new.iterdir()}
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)  # (should it get as far as serving)
    status = cli.main(["--data-dir", str(new), "--port", str(port_to_listen_on()), "--bind", "local"])
    out = capsys.readouterr()
    assert status == 2, out
    assert "--restore" in out.err and "again" in out.err and "not finished" in out.err, out.err
    assert {path.name: path.read_bytes() for path in new.iterdir()} == before  # (nothing written: not even its lock)
    # The same command then finishes it, and the wall starts.
    status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(new))
    assert status == 0 and "had been stopped before it finished" in said, said
    whole(new)
    assert not backup.unfinished_restore(new)
    # A finished wall whose hold could neither say so nor go (N7) holds its settings: never taken for an unfinished one.
    (new / backup.RESTORING).write_bytes(b"")
    assert not backup.unfinished_restore(new)


def test_a_folder_with_anything_in_it_is_refused_and_left_as_it_is(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    file, kit, _ = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    for target in (tmp_path / "old", tmp_path / "other"):
        target.mkdir(exist_ok=True)
        (target / "notes.txt").write_text("mine", encoding="utf-8")
        before = sorted(path.name for path in target.iterdir())
        status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(target))
        assert status == 2 and "not empty" in said, said
        assert sorted(path.name for path in target.iterdir()) == before
    assert not (tmp_path / "other.keys").exists()


@pytest.mark.parametrize("what", ["changed", "another key", "later version", "no backup", "disk full"])
def test_what_cannot_be_restored_is_refused_with_a_sentence_and_leaves_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, what: str) -> None:
    file, kit, made = a_whole_wall(tmp_path / "old", tmp_path / "backups", bulky=what == "changed")
    if what == "changed":
        assert file.stat().st_size > backup.CHUNK + 4096  # (two frames at least: a frame's worth is written before the change is found)
        raw = bytearray(file.read_bytes())
        raw[-3] ^= 0x01  # (in its last frame: read and written up to there before it is found)
        file.write_bytes(bytes(raw))
    elif what == "another key":
        (tmp_path / "kit.txt").write_text(backup.kit(backup.new_key(), 0.0), encoding="utf-8")
    elif what == "later version":
        from qkvm import _version

        monkeypatch.setattr(_version, "__version__", "0.0.1")  # (this one older than the one that made it)
    elif what == "no backup":
        file = tmp_path / "nothing.qkvmbackup"
        file.write_bytes(b"not a backup")
    else:  # (the disk full as the settings are written: after the backup was read whole, and after the storage key was made)
        def full(*given: Any, **said: Any) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
    new = tmp_path / "new"
    status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(new))
    assert status == 2, said
    expected = {
        "changed": "damaged", "another key": backup.key_id(backup.key_of(made["key"])), "later version": "later version", "no backup": "not a backup",
        "disk full": "No space left",
    }[what]  # fmt: skip
    assert expected in said, said
    assert not new.exists()
    keys = new.parent / f"{new.name}.keys"
    if what == "disk full":  # (after its storage key was made: that is left whole, for another restore may have been given it, M3)
        assert sorted(path.name for path in keys.iterdir()) == [*LOCK_LEFT, "vault.key"]  # (and the empty file of its folder's lock)
    else:
        assert not keys.exists()


def test_what_is_said_of_a_backup_is_what_was_read_and_checked(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of wave 3, L4.) Its time and version come from the reading that checks the whole file against its head, never
    # from a look at the head apart from it: a file put in its place between the two would have them said unchecked.
    file, kit, made = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    real = backup.head_of
    monkeypatch.setattr(backup, "head_of", lambda path, key: (real(path, key), (1.0, "6.6.6"))[1])  # (another file's head, by then)
    status, said = restore(capsys, str(file), "--backup-key", kit, "--data-dir", str(tmp_path / "new"))
    assert status == 0, said
    last = json.loads((tmp_path / "new" / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert last["event"] == "wall_restored" and (last["program"], last["made"] > 1000) == (__version__, True)
    assert "6.6.6" not in said and f"by qKVM {__version__}" in said
    assert backup.verify(file, backup.key_of(made["key"])).program == __version__


@pytest.mark.parametrize("written", ["--restore", "--restore="])
def test_python_m_qkvm_restores_in_its_own_process_with_this_copys_own_program(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, written: str) -> None:
    # Not through the starter, which runs the wall as a child (whose input is a pipe: no key could be typed there) and
    # starts an installed update's code: a restore is a command of its own, as --reset-password is.
    from qkvm import __main__ as starter

    file, kit, _ = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    monkeypatch.delenv(starter.CHILD, raising=False)
    monkeypatch.setattr(starter, "supervise", lambda argv: pytest.fail("a restore was handed to the starter"))
    monkeypatch.setattr(starter, "active_update", lambda *given, **said: pytest.fail("an update's code was looked for"))
    given = [written, str(file)] if written == "--restore" else [f"--restore={file}"]
    monkeypatch.setattr(starter.sys, "argv", ["qkvm", *given, "--backup-key", kit, "--data-dir", str(tmp_path / "new")])
    assert starter.main() == 0, capsys.readouterr()
    assert (tmp_path / "new" / "qkvm.json").exists()


def test_without_a_kit_the_key_is_asked_for_and_never_taken_from_the_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    file, _, made = a_whole_wall(tmp_path / "old", tmp_path / "backups")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    typed: list[str] = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": typed.append(prompt) or made["key"].lower())
    status, said = restore(capsys, str(file), "--data-dir", str(tmp_path / "new"))
    assert status == 0, said
    assert typed and "key" in typed[0].lower()
    assert made["key"] not in said
    # Not a terminal to ask at (a service, a pipe): said, nothing done.
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    status, said = restore(capsys, str(file), "--data-dir", str(tmp_path / "newer"))
    assert status == 2 and "--backup-key" in said and not (tmp_path / "newer").exists()
