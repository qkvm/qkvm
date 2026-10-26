"""In a container the only storage key is never made where the container alone keeps it (the review of 850745e, W1).

The image declared `VOLUME /data /keys` and set QKVM_VAULT_KEY_FILE=/keys/vault.key. Every 0.1.x container mounted
/data only, so Docker gave /keys an anonymous volume of its own; the guard that asks for an explicit key never fired
(the image names one), and `docker run --rm -v qkvm-data:/data qkvm/qkvm:0.2.0 --migrate-vault` sealed every account,
authenticator secret and device password with a key in a volume that --rm deleted, and did not say where the key was.

Now /keys is no anonymous volume of the image, and a new key is made in a container only in a folder that is a mount of
its own (a named volume or a bind mount): elsewhere the start and the migration refuse, before anything is written,
and say what to mount. Where a key is made or used, its place (never its contents) is said.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

import pytest

from qkvm import cli, update, vault
from tests.test_vault_migration import legacy

APP = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def in_a_container(monkeypatch: pytest.MonkeyPatch, key: Path, *, mounted: bool) -> None:
    """As the image runs qkvm: QKVM_CONTAINER and the key's place set by it, the key folder a mount of its own or not."""
    monkeypatch.setenv("QKVM_CONTAINER", "1")
    monkeypatch.setenv("QKVM_VAULT_KEY_FILE", str(key))
    real = os.path.ismount
    monkeypatch.setattr(os.path, "ismount", lambda path: mounted if Path(path) == key.parent else real(path))


def files_in(folder: Path) -> dict[str, bytes]:
    """What the folder holds of settings: the lock and the log every run of the command keeps there are left out."""
    return {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file() and path.name not in ("qkvm.lock", "qkvm.log")}


def no_server(*args: Any, **kwargs: Any) -> None:
    pytest.fail("the server was started")


def test_a_migration_in_a_container_does_not_make_the_only_key_where_the_container_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    key.parent.mkdir()  # (as the image has it: the folder is there, private, and no mount)
    before = files_in(data)
    in_a_container(monkeypatch, key, mounted=False)
    monkeypatch.setattr(cli, "Core", no_server)
    assert cli.main(["--data-dir", str(data), "--migrate-vault"]) == 2  # (was: 0, and the key in a throwaway volume)
    said = capsys.readouterr().err
    assert "-v qkvm-keys:/keys" in said and str(key.parent) in said
    assert not key.exists() and files_in(data) == before  # nothing made, nothing sealed


def test_a_migration_in_a_container_with_the_key_folder_mounted_goes_on_and_says_where_the_key_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    key.parent.mkdir()
    in_a_container(monkeypatch, key, mounted=True)
    monkeypatch.setattr(cli, "Core", no_server)
    assert cli.main(["--data-dir", str(data), "--migrate-vault"]) == 0
    assert cli.main(["--data-dir", str(data), "--verify-vault"]) == 0
    said = capsys.readouterr().out
    assert key.exists() and said.count(str(key)) >= 2  # its place, after each
    assert key.read_text().strip() not in said  # never its contents


def test_a_first_start_in_a_container_does_not_make_a_key_that_would_go_with_the_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    data.mkdir()
    key.parent.mkdir()
    in_a_container(monkeypatch, key, mounted=False)
    monkeypatch.setattr(cli, "Core", no_server)
    assert cli.main(["--data-dir", str(data)]) == 2  # (was: a new wall sealed with a key in a throwaway volume)
    assert "-v qkvm-keys:/keys" in capsys.readouterr().err
    assert not key.exists() and files_in(data) == {}


def test_a_container_whose_key_is_there_is_not_asked_where_its_folder_comes_from(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A key handed in as a file of its own, a secret mounted read-only, a volume of an earlier container: only the
    # making of a new key is held to a mount. A key that is there is read as before, wherever it is.)
    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    from qkvm import vault_migration

    vault_migration.migrate(data, key)
    in_a_container(monkeypatch, key, mounted=False)
    monkeypatch.setattr(cli, "Core", no_server)
    assert cli.main(["--data-dir", str(data), "--verify-vault"]) == 0


def test_the_image_gives_the_key_no_anonymous_volume_and_its_own_trial_mounts_one() -> None:
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    volumes = " ".join(re.findall(r"^VOLUME (.+)$", dockerfile, flags=re.M))
    assert "/data" in volumes and "/keys" not in volumes
    action = (APP / ".github" / "security" / "action.yml").read_text(encoding="utf-8")
    started = action[action.index("docker run -d --name qkvm-security") :].split("qkvm:security", 1)[0]
    assert re.search(r"-v [A-Za-z0-9_.-]+:/keys\b", started), "the image's own start trial mounts a named key volume"


# What /proc/self/mountinfo says of a few folders mounted at /keys (the root within its source, and the file system).
LASTING = [
    ("/var/lib/docker/volumes/qkvm-keys/_data", "ext4"),  # a named volume
    ("/srv/qkvm/keys", "xfs"),  # a folder of the host's, bound in
    ("/var/lib/containers/storage/volumes/qkvm-keys/_data", "ext4"),  # Podman's named volume
]
THROWAWAY = [
    ("/", "tmpfs"),  # --tmpfs /keys
    ("/var/lib/docker/volumes/" + "3f" * 32 + "/_data", "ext4"),  # -v /keys: an anonymous volume, no later container's
    ("/var/lib/containers/storage/volumes/" + "a0" * 32 + "/_data", "xfs"),  # the same, of Podman's
    ("/var/lib/kubelet/pods/0b1c/volumes/kubernetes.io~empty-dir/keys", "ext4"),  # a pod's emptyDir
]


@pytest.mark.parametrize(("root", "kind"), THROWAWAY)
def test_a_mount_that_does_not_outlast_the_container_is_no_place_for_a_new_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root: str, kind: str
) -> None:
    # (The fresh review of e279a31, its L10: a mount of its own was all that was asked, and a tmpfs, an anonymous volume or
    # an emptyDir is one: the only key went with the container all the same.)
    key = tmp_path / "keys" / "vault.key"
    key.parent.mkdir()
    in_a_container(monkeypatch, key, mounted=True)
    monkeypatch.setattr(cli, "_mount_of", lambda folder: (root, kind) if Path(folder) == key.parent else None, raising=False)
    said = cli._key_would_go_with_the_container(key)
    assert said is not None and "-v qkvm-keys:/keys" in said, said


@pytest.mark.parametrize(("root", "kind"), LASTING)
def test_a_mount_that_outlasts_the_container_takes_a_new_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root: str, kind: str) -> None:
    key = tmp_path / "keys" / "vault.key"
    key.parent.mkdir()
    in_a_container(monkeypatch, key, mounted=True)
    monkeypatch.setattr(cli, "_mount_of", lambda folder: (root, kind) if Path(folder) == key.parent else None, raising=False)
    assert cli._key_would_go_with_the_container(key) is None


def test_mountinfo_is_read_as_the_kernel_writes_it(tmp_path: Path) -> None:
    told = tmp_path / "mountinfo"
    told.write_text(
        "22 1 0:21 / / rw,relatime - overlay overlay rw\n"
        "35 22 8:1 /var/lib/docker/volumes/qkvm-keys/_data /keys rw,relatime master:1 - ext4 /dev/sda1 rw\n"
        "36 22 0:40 / /my\\040keys rw,nosuid shared:2 - tmpfs tmpfs rw,size=1024k\n",
        encoding="utf-8",
    )
    assert cli._mount_of(Path("/keys"), told) == ("/var/lib/docker/volumes/qkvm-keys/_data", "ext4")
    assert cli._mount_of(Path("/my keys"), told) == ("/", "tmpfs")
    assert cli._mount_of(Path("/elsewhere"), told) is None
    assert cli._mount_of(Path("/keys"), tmp_path / "no-such-file") is None


def test_a_folder_with_sealed_files_and_no_settings_is_not_told_a_key_would_be_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # (Its L10 too: since b1206c6 no key is made beside sealed files, and the start asks for the missing one instead.)
    from qkvm import vault_migration

    data, key = tmp_path / "data", tmp_path / "keys" / "vault.key"
    legacy(data)
    vault_migration.migrate(data, tmp_path / "elsewhere" / "vault.key")
    for name in ("qkvm.json", "qkvm.bak"):
        (data / name).unlink()
    key.parent.mkdir()
    in_a_container(monkeypatch, key, mounted=False)
    monkeypatch.setattr(cli, "create_app", no_server)  # (the store itself is the one to refuse, as a start has it)
    assert cli.main(["--data-dir", str(data)]) == 2
    said = capsys.readouterr().err
    assert "would be made" not in said and "missing" in said, said
    assert not key.exists()
