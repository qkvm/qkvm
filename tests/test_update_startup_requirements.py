from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import __main__ as starter
from qkvm import cli, update
from qkvm.update import UpdateError, check_startup_requirements


def package_at(root: Path, version: str = "9.9.9", requires: str = "uvicorn>=0.54") -> Path:
    package = root / "qkvm"
    package.mkdir(parents=True)
    (package / "_version.py").write_text(f'__version__ = "{version}"\n')
    metadata = root / f"qkvm-{version}.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: qkvm\nVersion: {version}\n"
        f"Requires-Python: >=3.11\nRequires-Dist: {requires}\n"
    )
    return package


def test_startup_checks_metadata_beside_selected_code_before_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    package = package_at(tmp_path / "selected")
    data = tmp_path / "settings"
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    monkeypatch.setattr(update.importlib.metadata, "version", lambda name: "0.46.0")
    monkeypatch.setattr(cli, "Core", lambda *args, **kwargs: pytest.fail("settings migration must not run"))
    monkeypatch.setattr(cli, "InstanceLock", lambda *args, **kwargs: pytest.fail("settings must not be opened"))
    assert cli.main(["--data-dir", str(data)]) == 1
    assert not data.exists()
    assert "uvicorn>=0.54" in capsys.readouterr().err


def test_first_upgrade_can_be_rolled_back_by_the_original_supervisor_without_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The original supervisor is unchanged: code installed by the 0.1.1 updater can protect itself
    # without teaching that immutable starter about the new dependency check.
    package = package_at(tmp_path / "updates" / "9.9.9")
    pointer = tmp_path / "updates" / "current.json"
    pointer.write_text(json.dumps({"version": "9.9.9", "previous": None, "previous_proven": False}))
    settings = tmp_path / "qkvm.json"
    settings.write_text('{"schema": "before migration"}\n')
    before = settings.read_bytes()
    monkeypatch.delenv(starter.CONTAINER, raising=False)
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    monkeypatch.setattr(cli, "__version__", "9.9.9")
    monkeypatch.setattr(update.importlib.metadata, "version", lambda name: "0.46.0")
    monkeypatch.setattr(cli, "Core", lambda *args, **kwargs: pytest.fail("settings migration must not run"))
    monkeypatch.setattr(starter.signal, "signal", lambda *args: None)
    statuses: list[int] = []

    class Child:
        def wait(self, timeout: float | None = None) -> int:
            return statuses[-1]

    def launch(command: list[str], **options: Any) -> Child:
        if not statuses:
            assert starter.active_update(tmp_path) == package
            statuses.append(cli.main(["--data-dir", str(tmp_path)]))
        else:
            assert starter.active_update(tmp_path) is None
            statuses.append(0)  # the original program starts after the pointer is rolled back
        return Child()

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert statuses == [1, 0]
    assert starter.active_update(tmp_path) is None
    assert settings.read_bytes() == before


def test_startup_accepts_compatible_selected_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = package_at(tmp_path)
    monkeypatch.setattr(update.importlib.metadata, "version", lambda name: "0.54.0")
    check_startup_requirements(package, "9.9.9")


def test_source_and_editable_packages_ignore_metadata_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unrelated or older installation on sys.path must not set the source checkout's requirements.
    package_at(tmp_path / "site-packages", requires="missing-package>=999")
    package = tmp_path / "checkout" / "qkvm"
    package.mkdir(parents=True)
    monkeypatch.syspath_prepend(str(tmp_path / "site-packages"))
    monkeypatch.setattr(update.importlib.metadata, "version", lambda name: pytest.fail("source metadata is absent"))
    check_startup_requirements(package, "9.9.9")


@pytest.mark.parametrize(
    "metadata",
    [
        "Name: unrelated\nVersion: 9.9.9\n",
        "Name: qkvm\nVersion: 0.1.1\n",
        "Name: qkvm\nVersion: not-a-version\n",
        "Name: qkvm\nName: qkvm\nVersion: 9.9.9\n",
        "Name: qkvm\nVersion: 9.9.9\nVersion: 9.9.9\n",
        "Name: qkvm\n",
        "",
    ],
)
def test_startup_refuses_selected_metadata_that_does_not_match_code(tmp_path: Path, metadata: str) -> None:
    package = package_at(tmp_path)
    (tmp_path / "qkvm-9.9.9.dist-info" / "METADATA").write_text(metadata)
    with pytest.raises(UpdateError, match="does not match"):
        check_startup_requirements(package, "9.9.9")


def test_startup_refuses_an_installed_package_with_missing_metadata(tmp_path: Path) -> None:
    package = package_at(tmp_path)
    (tmp_path / "qkvm-9.9.9.dist-info" / "METADATA").unlink()
    with pytest.raises(UpdateError, match="missing its package metadata"):
        check_startup_requirements(package, "9.9.9")


def test_status_and_version_remain_available_when_dependencies_do_not_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "check_startup_requirements", lambda *args: pytest.fail("not starting the server"))
    monkeypatch.setattr(cli, "ask", lambda *args: 0)
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 0
    with pytest.raises(SystemExit) as stopped:
        cli.main(["--version"])
    assert stopped.value.code == 0
