"""Vault migration preserves authentication while closing the copied-data/password attack."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qkvm import totp, update, vault, vault_migration
from qkvm.core import Core
from qkvm.store import ActionRecord, DeviceRecord, Store, StoreError, UserRecord
from qkvm.vault_storage import MAGIC, RECOVERY_MAGIC, MigrationRequired, StorageCipher, StorageError, create_key, key_path, read_key
from tests.fake_kvm import FakeKvm
from tests.test_totp import code_for
from tests.test_wall import wall

ADMIN = "migration administrator password"
VIEWER = "migration viewer password"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def legacy(data: Path, url: str = "http://127.0.0.1:9") -> tuple[dict[str, Any], bytes, str, str, list[str]]:
    data.mkdir(parents=True, exist_ok=True)
    safe = vault.Vault()
    admin = UserRecord(id="admin1", name="admin", role="admin", auth=safe.create(ADMIN), created=123)
    viewer = UserRecord(id="viewer1", name="viewer", role="viewer", auth=safe.rewrap(VIEWER), devices=["device1"], created=124)
    secret = totp.new_secret()
    codes = totp.new_one_time_codes()
    admin.totp = safe.encrypt(secret, "totp:admin1")
    admin.totp_codes = [safe.mark(f"admin1:{totp.as_issued(code)}", "one-time code") for code in codes]
    admin.totp_changes = 1
    store = Store(data / "qkvm.json")  # deliberate legacy fixture, outside the Core serving boundary
    store.users = [admin, viewer]
    store.devices = [DeviceRecord("device1", "fixture", url, secret=safe.encrypt("secret", "device1"))]
    store.actions = [ActionRecord("action1", "private text", "text", secret=safe.encrypt("saved text", "action:action1"))]
    store.alerts.webhook = safe.encrypt("https://example.invalid/private-hook", "alerts:webhook")
    recovery = vault.new_recovery_key()
    store.recovery = safe.rewrap(vault.tidy_recovery_key(recovery))
    store.recovery_created = time.time()
    document = store.snapshot()
    document["future_field"] = {"kept": ["unchanged", 7]}
    store.write(document)
    inner = vault.Vault.open(admin.auth, ADMIN)
    assert inner is not None
    return document, inner, recovery, secret, codes


def test_migration_preserves_all_fields_and_legacy_passwords_cannot_open_the_new_file(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "separate" / "vault.key"
    before, inner, _, _, _ = legacy(data)
    old_bytes = (data / "qkvm.json").read_bytes()
    # Demonstrate the pre-migration weakness with the actual legacy cryptography.
    viewer_key = vault.Vault.open(before["users"][1]["auth"], VIEWER)
    opened = vault.Vault()
    assert viewer_key == inner
    opened.adopt(viewer_key)
    assert opened.decrypt(before["devices"][0]["secret"], "device1") == "secret"
    result = vault_migration.migrate(data, keyfile)
    assert result["accounts"] == 2 and result["devices"] == 1
    assert Store(data / "qkvm.json", vault_key_file=keyfile, protected=True).snapshot() == before
    protected = (data / "qkvm.json").read_bytes()
    assert protected.startswith(MAGIC) and protected == (data / "qkvm.bak").read_bytes()
    for exposed in (ADMIN, VIEWER, "private-hook", "fixture", "viewer1", "future_field"):
        assert exposed.encode() not in protected
    with pytest.raises(StorageError, match="authenticated"):
        StorageCipher(inner).open(protected)
    with pytest.raises(ValueError):
        json.loads(protected)  # both copies are rejected by the old JSON-only reader
    cipher = StorageCipher(read_key(keyfile))
    archive = vault_migration._read_archive(data / vault_migration.ARCHIVE, cipher)
    assert archive["qkvm.json"] == old_bytes
    with pytest.raises(StorageError):
        StorageCipher(inner).open((data / vault_migration.ARCHIVE).read_bytes(), context=RECOVERY_MAGIC)
    assert vault_migration.verify(data, keyfile)["protected"]
    assert vault_migration.migrate(data, keyfile)["already_protected"]


def test_missing_key_and_legacy_start_are_read_only_and_never_offer_new_setup(tmp_path: Path) -> None:
    data = tmp_path / "data"
    legacy(data)
    before = {p.name: p.read_bytes() for p in data.iterdir()}
    with pytest.raises(MigrationRequired):
        Core(data, locked_start=True)
    assert {p.name: p.read_bytes() for p in data.iterdir()} == before
    assert not key_path(data).exists()
    keyfile = tmp_path / "keys" / "storage.key"
    vault_migration.migrate(data, keyfile)
    before = {p.name: p.read_bytes() for p in data.iterdir()}
    with pytest.raises(StorageError, match="missing"):
        Core(data, vault_key_file=tmp_path / "missing.key", locked_start=True)
    assert {p.name: p.read_bytes() for p in data.iterdir()} == before
    wrong = tmp_path / "keys" / "wrong.key"
    create_key(wrong)
    with pytest.raises(StoreError, match="authenticated"):
        Core(data, vault_key_file=wrong)
    assert {p.name: p.read_bytes() for p in data.iterdir()} == before


def test_migrated_accounts_mfa_codes_credentials_and_recovery_work_through_real_routes(tmp_path: Path) -> None:
    fake = FakeKvm().start()
    try:
        data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
        _, _, recovery, secret, codes = legacy(data, fake.url)
        vault_migration.migrate(data, keyfile)
        with wall(data, sign_in=False, locked_start=True, vault_key_file=keyfile) as client:
            assert client.get("/healthz").json()["locked"]
            assert client.post("/api/v1/login", json={"name": "admin", "password": ADMIN}).json()["code"] == "code_required"
            assert client.get("/healthz").json()["locked"]
            assert client.post("/api/v1/login", json={"name": "admin", "password": ADMIN, "code": codes[0]}).status_code == 200
            assert client.get("/api/v1/devices/device1/snapshot").status_code == 200
            current = client.core  # type: ignore[attr-defined]
            assert current.vault.decrypt(current.store.actions[0].secret, "action:action1") == "saved text"
            assert current.vault.decrypt(current.store.alerts.webhook, "alerts:webhook").endswith("private-hook")
            assert client.post("/api/v1/logout", json={}).status_code == 200
            assert client.post("/api/v1/login", json={"name": "viewer", "password": VIEWER}).status_code == 200
            assert client.get("/api/v1/users").status_code == 403
            assert client.get("/api/v1/devices/device1/snapshot").status_code == 200
        with wall(data, sign_in=False, locked_start=True, vault_key_file=keyfile) as client:
            assert client.post("/api/v1/login", json={"name": "admin", "password": ADMIN, "code": codes[0]}).json()["code"] == "bad_code"
            assert client.post("/api/v1/login", json={"name": "admin", "password": ADMIN, "code": code_for(secret)}).status_code == 200
            assert client.post("/api/v1/password", json={"current": ADMIN, "new": ADMIN + " changed"}).status_code == 200
            assert client.post("/api/v1/logout", json={}).status_code == 200
            assert client.post("/api/v1/recover", json={"name": "viewer", "recovery_key": recovery, "new_password": VIEWER + " changed"}).status_code == 200
            assert client.post("/api/v1/login", json={"name": "viewer", "password": VIEWER + " changed"}).status_code == 200
    finally:
        fake.stop()


@pytest.mark.parametrize("target", [vault_migration.ARCHIVE, "qkvm.bak", "qkvm.json"])
def test_interrupted_replacement_is_restartable_without_losing_accounts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    before, _, _, _, _ = legacy(data)
    replace = vault_migration._replace_settings
    def fail(source: Path, destination: Path) -> None:
        if destination.name == target:
            raise PermissionError("simulated held file")
        replace(source, destination)
    monkeypatch.setattr(vault_migration, "_replace_settings", fail)
    with pytest.raises(PermissionError):
        vault_migration.migrate(data, keyfile)
    assert Store(data / "qkvm.json", vault_key_file=keyfile, read_only=True).snapshot() == before
    monkeypatch.setattr(vault_migration, "_replace_settings", replace)
    assert vault_migration.migrate(data, keyfile)["protected"]
    assert Store(data / "qkvm.json", vault_key_file=keyfile).snapshot() == before


def test_cleanup_failure_is_reported_and_retried_without_plaintext_loss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    leftover = data / "qkvm.damaged-123.json"
    original = (data / "qkvm.json").read_bytes()
    leftover.write_bytes(original)
    unlink = Path.unlink
    def fail(path: Path, *args: Any, **kwargs: Any) -> None:
        if path == leftover:
            raise PermissionError("simulated held remnant")
        unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", fail)
    with pytest.raises(StorageError, match="remnants"):
        vault_migration.migrate(data, keyfile)
    assert (data / "qkvm.json").read_bytes().startswith(MAGIC)
    assert leftover.read_bytes() == original
    with pytest.raises(StorageError, match="remnant"):
        vault_migration.verify(data, keyfile)
    monkeypatch.setattr(Path, "unlink", unlink)
    vault_migration.migrate(data, keyfile)
    assert not leftover.exists()


def test_copied_data_needs_the_separate_key_and_restores_with_it(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    before, _, _, _, _ = legacy(data)
    vault_migration.migrate(data, keyfile)
    copy_dir = tmp_path / "restore"
    shutil.copytree(data, copy_dir)
    with pytest.raises(StorageError, match="missing"):
        Core(copy_dir)
    assert not key_path(copy_dir).exists()
    assert Store(copy_dir / "qkvm.json", vault_key_file=keyfile, protected=True).snapshot() == before
    assert vault_migration.verify(copy_dir, keyfile)["protected"]


def test_envelope_authentication_rejects_mutation_truncation_and_wrong_context() -> None:
    cipher = StorageCipher(AESGCM.generate_key(256))
    sealed = cipher.seal(b"private settings")
    assert cipher.open(sealed) == b"private settings"
    assert cipher.seal(b"private settings") != sealed
    for damaged in (sealed[:-9], sealed.replace(b"VAULT-2", b"VAULT-3"), sealed[:-5] + b"AAAA\n", b"{}"):
        with pytest.raises(StorageError):
            cipher.open(damaged)
    with pytest.raises(StorageError):
        cipher.open(cipher.seal(b"private settings", context=RECOVERY_MAGIC))


def test_key_must_be_separate_and_never_replaced_when_invalid(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    for inside in (data / "key", data / "a" / ".." / "key"):
        with pytest.raises(StorageError, match="outside"):
            key_path(data, inside)
    chosen = key_path(data)
    first = create_key(chosen)
    assert create_key(chosen) == first
    raw = chosen.read_bytes()
    chosen.write_bytes(b"truncated")
    with pytest.raises(StorageError):
        create_key(chosen)
    assert chosen.read_bytes() == b"truncated"
    chosen.write_bytes(raw)
    assert read_key(chosen) == first
    if os.name == "posix":
        chosen.chmod(0o644)
        with pytest.raises(StorageError, match="permissions"):
            read_key(chosen)


def test_migration_preserves_unknown_fields_even_when_resumed(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    before, _, _, _, _ = legacy(data)
    before["users"][0]["future_permission"] = {"limit": [1, 2]}
    for name in ("qkvm.json", "qkvm.bak"):
        (data / name).write_text(json.dumps(before))
    vault_migration.migrate(data, keyfile)
    restored = Store(data / "qkvm.json", vault_key_file=keyfile, protected=True)
    assert restored.snapshot() == before
    original = copy.deepcopy(before)
    restored.server.history_days = 7
    restored.save()
    original["server"]["history_days"] = 7
    assert Store(data / "qkvm.json", vault_key_file=keyfile).snapshot() == original


def test_unknown_vault_version_never_falls_back_to_an_older_backup(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    vault_migration.migrate(data, keyfile)
    primary = data / "qkvm.json"
    primary.write_bytes(primary.read_bytes().replace(MAGIC, b"QKVM-VAULT-3\n", 1))
    before = primary.read_bytes()
    with pytest.raises(StorageError, match="unsupported protected vault version"):
        Core(data, vault_key_file=keyfile)
    assert primary.read_bytes() == before


def test_corruption_recovers_only_from_the_authenticated_backup(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    before, _, _, _, _ = legacy(data)
    vault_migration.migrate(data, keyfile)
    primary, backup = data / "qkvm.json", data / "qkvm.bak"
    primary.write_bytes(b"cut short")
    restored = Store(primary, vault_key_file=keyfile, protected=True)
    assert restored.restored and restored.snapshot() == before
    assert primary.read_bytes() == backup.read_bytes()
    # A valid but plaintext backup must not bypass protected-format requirements.
    backup.write_text(json.dumps(before))
    primary.write_bytes(b"cut short")
    with pytest.raises(MigrationRequired):
        Store(primary, vault_key_file=keyfile, protected=True)


def test_verification_does_not_create_keys_or_files_on_an_empty_target(tmp_path: Path) -> None:
    data, selected = tmp_path / "empty", tmp_path / "keys" / "never.key"
    data.mkdir()
    with pytest.raises(StorageError):
        vault_migration.verify(data, selected)
    assert not selected.exists() and not list(data.iterdir())


def test_migration_primary_committed_then_directory_sync_failed_is_resumable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, selected = tmp_path / "data", tmp_path / "keys" / "vault.key"
    before, _, _, _, _ = legacy(data)
    settle = vault_migration._settle
    calls = 0
    def interrupted(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:  # archive, backup, primary has just been atomically replaced
            raise OSError("simulated interruption after primary commit")
        settle(path)
    monkeypatch.setattr(vault_migration, "_settle", interrupted)
    with pytest.raises(OSError):
        vault_migration.migrate(data, selected)
    assert (data / "qkvm.json").read_bytes().startswith(MAGIC)
    assert (data / "qkvm.bak").read_bytes().startswith(MAGIC)
    monkeypatch.setattr(vault_migration, "_settle", settle)
    assert vault_migration.migrate(data, selected)["already_protected"]
    assert Store(data / "qkvm.json", vault_key_file=selected).snapshot() == before


def test_key_link_into_the_data_folder_is_rejected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    selected = tmp_path / "keys" / "vault.key"
    create_key(selected)
    linked = data / "stolen.key"
    try:
        os.link(selected, linked)
    except OSError:
        pytest.skip("the filesystem does not support hard links")
    with pytest.raises(StorageError, match="link"):
        read_key(selected)


def test_offline_commands_preserve_accounts_and_do_not_start_a_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from qkvm import cli
    data, selected = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    def no_server(*args: Any, **kwargs: Any) -> None:
        pytest.fail("offline migration started the server")
    monkeypatch.setattr(cli, "Core", no_server)
    args = ["--data-dir", str(data), "--vault-key-file", str(selected)]
    assert cli.main([*args, "--migrate-vault"]) == 0
    assert cli.main([*args, "--verify-vault"]) == 0
    output = capsys.readouterr()
    assert "2 accounts, 1 devices" in output.out
    assert ADMIN not in output.out and VIEWER not in output.out
    assert selected.read_text().strip() not in output.out + output.err


def test_an_active_server_blocks_offline_migration(tmp_path: Path) -> None:
    from qkvm import cli
    from qkvm.store import InstanceLock
    data, selected = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    held = InstanceLock(data)
    assert held.acquire()
    try:
        assert cli.main(["--data-dir", str(data), "--vault-key-file", str(selected), "--migrate-vault"]) == 2
        assert not selected.exists()
        assert (data / "qkvm.json").read_bytes().startswith(b"{")
    finally:
        held.release()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL enforcement")
def test_windows_refuses_a_key_granted_to_everyone(tmp_path: Path) -> None:
    import subprocess
    keyfile = tmp_path / "keys" / "vault.key"
    create_key(keyfile)
    raw = keyfile.read_bytes()
    result = subprocess.run(["icacls", str(keyfile), "/grant", "*S-1-1-0:(R)"], capture_output=True)
    assert result.returncode == 0
    with pytest.raises(PermissionError, match="another Windows account"):
        read_key(keyfile)
    assert keyfile.read_bytes() == raw  # a permissive key is refused, never silently replaced


def test_corrupt_archive_or_changed_legacy_input_never_gets_discarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    original = (data / "qkvm.json").read_bytes()
    real = vault_migration._write
    def stop_after_archive(path: Path, raw: bytes) -> None:
        if path.name == "qkvm.bak":
            raise OSError("test interruption")
        real(path, raw)
    monkeypatch.setattr(vault_migration, "_write", stop_after_archive)
    with pytest.raises(OSError):
        vault_migration.migrate(data, keyfile)
    monkeypatch.setattr(vault_migration, "_write", real)
    archive = data / vault_migration.ARCHIVE
    captured = archive.read_bytes()
    archive.write_bytes(captured[:-12])
    with pytest.raises(StorageError):
        vault_migration.migrate(data, keyfile)
    assert (data / "qkvm.json").read_bytes() == original
    archive.write_bytes(captured)
    changed = original + b" "
    (data / "qkvm.json").write_bytes(changed)
    with pytest.raises(StorageError, match="changed since"):
        vault_migration.migrate(data, keyfile)
    assert (data / "qkvm.json").read_bytes() == changed
    assert archive.read_bytes() == captured


def test_malformed_legacy_remnant_blocks_start_until_it_is_archived(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    raw = (data / "qkvm.json").read_bytes()[:-20]
    vault_migration.migrate(data, keyfile)
    remnant = data / "qkvm.tmp"
    remnant.write_bytes(raw)
    with pytest.raises(MigrationRequired):
        Core(data, vault_key_file=keyfile)
    # It was not captured in the original archive: migration must refuse to discard it.
    with pytest.raises(StorageError, match="changed since"):
        vault_migration.migrate(data, keyfile)
    assert remnant.read_bytes() == raw


def test_reset_clears_the_migration_archive_and_preserves_the_server_key(tmp_path: Path) -> None:
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    vault_migration.migrate(data, keyfile)
    key_before = keyfile.read_bytes()
    core = Core(data, vault_key_file=keyfile)
    assert core.reset_password() == []
    assert not (data / vault_migration.ARCHIVE).exists()
    assert keyfile.read_bytes() == key_before
    result = vault_migration.verify(data, keyfile)
    assert result["accounts"] == 0 and result["devices"] == 1
    assert core.store.devices[0].secret is None


def test_offline_settings_preserve_secrets_and_validate_before_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import cli
    data, keyfile = tmp_path / "data", tmp_path / "keys" / "vault.key"
    original, _, _, _, _ = legacy(data)
    vault_migration.migrate(data, keyfile)
    config = tmp_path / "server-settings.json"
    config.write_text(json.dumps({"allowed_hosts": ["KVM.example.com"], "history_days": 31}))
    def no_server(*args: Any, **kwargs: Any) -> None:
        pytest.fail("offline configuration started a server")
    monkeypatch.setattr(cli, "Core", no_server)
    assert cli.main(["--data-dir", str(data), "--vault-key-file", str(keyfile), "--configure-server", str(config)]) == 0
    saved = Store(data / "qkvm.json", vault_key_file=keyfile).snapshot()
    expected = copy.deepcopy(original)
    expected["server"]["allowed_hosts"] = ["kvm.example.com"]
    expected["server"]["history_days"] = 31
    assert saved == expected
    raw = (data / "qkvm.json").read_bytes()
    for invalid in ({"users": []}, {"allowed_hosts": ["*"]}, {"allowed_hosts": ["https://host/path"]},
                    {"history_mb": True}, {"activity_mb": 1}, {"history_days": -1}):
        config.write_text(json.dumps(invalid))
        with pytest.raises(StorageError):
            vault_migration.configure(data, keyfile, config)
        assert (data / "qkvm.json").read_bytes() == raw



def test_an_oversized_key_is_refused_without_replacement(tmp_path: Path) -> None:
    selected = tmp_path / "keys" / "vault.key"
    create_key(selected)
    invalid = selected.read_bytes() + b" " * 300 + b"corruption"
    selected.write_bytes(invalid)
    with pytest.raises(StorageError):
        create_key(selected)
    assert selected.read_bytes() == invalid


def test_legacy_remnants_alone_never_start_a_new_setup(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    remnant = data / "qkvm.tmp"
    remnant.write_bytes(b'{"users": [{"name":"existing-owner"}]')
    with pytest.raises(MigrationRequired):
        Core(data)
    assert not key_path(data).exists() and not (data / "qkvm.json").exists()


def test_original_supervisor_returns_to_legacy_without_migrating_during_a_trial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import __main__ as starter
    from qkvm import cli
    from tests.test_update_startup_requirements import package_at
    original, _, _, _, _ = legacy(tmp_path)
    raw = {name: (tmp_path / name).read_bytes() for name in ("qkvm.json", "qkvm.bak")}
    package = package_at(tmp_path / "updates" / "9.9.9", requires="cryptography>=0")
    (tmp_path / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None}))
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    monkeypatch.setattr(starter.signal, "signal", lambda *args: None)
    statuses: list[int] = []

    class Child:
        def wait(self, timeout: float | None = None) -> int:
            return statuses[-1]

    def launch(command: list[str], **options: Any) -> Child:
        if not statuses:
            assert starter.active_update(tmp_path) == package
            with monkeypatch.context() as child:
                child.setenv("QKVM_CHILD", "1")
                statuses.append(cli.main(["--data-dir", str(tmp_path)]))
        else:
            assert starter.active_update(tmp_path) is None
            assert Store(tmp_path / "qkvm.json", read_only=True).snapshot() == original
            statuses.append(0)
        return Child()

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert statuses == [1, 0]
    assert {name: (tmp_path / name).read_bytes() for name in raw} == raw
    assert not key_path(tmp_path).exists() and not (tmp_path / vault_migration.ARCHIVE).exists()


@pytest.mark.parametrize("case", ["direct", "proven", "different-package", "archive", "mixed", "protected", "remnant", "migration-temp", "container"])
def test_migration_errors_cannot_trigger_legacy_fallback_outside_an_untouched_trial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    from qkvm import cli
    from tests.test_update_startup_requirements import package_at
    data = tmp_path / "data"
    legacy(data)
    package = package_at(data / "updates" / "9.9.9", requires="cryptography>=0")
    pointer = data / "updates" / "current.json"
    pointer.write_text(json.dumps({"version": "9.9.9", "previous": None, "proven": case == "proven"}))
    monkeypatch.setenv("QKVM_CHILD", "1")
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    if case == "direct":
        monkeypatch.delenv("QKVM_CHILD")
    elif case == "different-package":
        elsewhere = package_at(tmp_path / "elsewhere", requires="cryptography>=0")
        monkeypatch.setattr(cli, "__file__", str(elsewhere / "cli.py"))
    elif case == "archive":
        (data / vault_migration.ARCHIVE).write_bytes(b"interrupted migration")
    elif case == "mixed":
        cipher = StorageCipher(create_key(key_path(data)))
        (data / "qkvm.bak").write_bytes(cipher.encode(Store(data / "qkvm.json").snapshot()))
    elif case == "protected":
        vault_migration.migrate(data, key_path(data))
        key_path(data).unlink()  # missing key must stop, not cause a binary downgrade
    elif case == "remnant":
        (data / "qkvm.tmp").write_bytes((data / "qkvm.json").read_bytes())
    elif case == "migration-temp":
        (data / "vault-migration.recovery.migration-deadbeef").write_bytes(b"incomplete archive write")
    elif case == "container":
        monkeypatch.setenv("QKVM_CONTAINER", "1")
    before = {path.name: path.read_bytes() for path in data.iterdir() if path.is_file()}
    noted = pointer.read_bytes()
    assert not cli._legacy_vault_update_trial(data)
    assert cli.main(["--data-dir", str(data)]) == 2
    assert all((data / name).read_bytes() == raw for name, raw in before.items())
    assert pointer.read_bytes() == noted


@pytest.mark.parametrize("case", ["empty-tmp", "zeroed-bak-new", "empty-bak", "legacy-damaged", "only-bak"])
def test_a_trial_goes_back_over_what_0_1_x_itself_leaves_and_passes_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    # (L-W7 of the review of 850745e: an empty file left by a power cut, a damaged copy 0.1.x set aside itself, or the
    # second copy alone, which 0.1.x starts from, each held the trial at exit 2 with the wall down, where the data was
    # untouched 0.1.x data and 0.1.x would have started on it.)
    from qkvm import cli
    from tests.test_update_startup_requirements import package_at
    data = tmp_path / "data"
    legacy(data)
    package = package_at(data / "updates" / "9.9.9", requires="cryptography>=0")
    pointer = data / "updates" / "current.json"
    pointer.write_text(json.dumps({"version": "9.9.9", "previous": None}))
    monkeypatch.setenv("QKVM_CHILD", "1")
    monkeypatch.delenv("QKVM_CONTAINER", raising=False)
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    if case == "empty-tmp":
        (data / "qkvm.tmp").write_bytes(b"")
    elif case == "zeroed-bak-new":
        (data / "qkvm.bak.new").write_bytes(bytes(4096))
    elif case == "empty-bak":
        (data / "qkvm.bak").write_bytes(bytes(512))
    elif case == "legacy-damaged":
        (data / "qkvm.damaged-1700000000.json").write_bytes((data / "qkvm.json").read_bytes()[:-40])
    elif case == "only-bak":
        (data / "qkvm.json").unlink()
    before = {path.name: path.read_bytes() for path in data.iterdir() if path.is_file()}
    assert cli._legacy_vault_update_trial(data)
    assert cli.main(["--data-dir", str(data)]) == 1
    assert all((data / name).read_bytes() == raw for name, raw in before.items())
    assert not key_path(data).exists() and not (data / vault_migration.ARCHIVE).exists()


@pytest.mark.parametrize("case", ["sealed-damaged", "unreadable-name", "tmp-with-settings", "linked-tmp"])
def test_a_trial_still_stays_where_a_leftover_may_be_a_migrations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    # (The other side of the one above: what is sealed, or holds settings, or is no plain file, still keeps the trial
    # from going back, as test_migration_errors_cannot_trigger_legacy_fallback_outside_an_untouched_trial decided.)
    from qkvm import cli
    from tests.test_update_startup_requirements import package_at
    data = tmp_path / "data"
    legacy(data)
    package = package_at(data / "updates" / "9.9.9", requires="cryptography>=0")
    (data / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None}))
    monkeypatch.setenv("QKVM_CHILD", "1")
    monkeypatch.delenv("QKVM_CONTAINER", raising=False)
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    if case == "sealed-damaged":
        (data / "qkvm.damaged-1700000000.json").write_bytes(MAGIC + bytes(64))
    elif case == "unreadable-name":
        (data / "qkvm.damaged-1700000000.json").mkdir()
    elif case == "tmp-with-settings":
        (data / "qkvm.tmp").write_bytes(b" " + (data / "qkvm.json").read_bytes())
    elif case == "linked-tmp":
        try:
            (data / "qkvm.tmp").symlink_to(data / "nowhere")
        except OSError:
            pytest.skip("this system makes no symbolic link here")
    assert not cli._legacy_vault_update_trial(data)
