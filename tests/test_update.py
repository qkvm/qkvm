from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from qkvm import __main__ as starter
from qkvm import release, vault
from qkvm import update as update_module
from qkvm._version import __version__
from qkvm.cli import main as run_cli
from qkvm.core import RESTART, Core
from qkvm.server import create_app
from qkvm.update import UpdateError, Updater, parse_version
from tests.fake_github import FakeGitHub, make_wheel

PASSWORD = "correct horse battery"


@pytest.fixture
def github() -> Iterator[FakeGitHub]:
    server = FakeGitHub().start()
    yield server
    server.stop()


def updater(github: FakeGitHub, data: Path, **options: Any) -> Updater:
    defaults = {"keys": (), "current": "1.0.0", "allow_unsigned": True}  # most tests are not about signatures
    return Updater(data, github.repo, api=github.url, **{**defaults, **options})


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_versions() -> None:
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("2.0") == (2, 0, 0)
    assert parse_version("1.10.0") > parse_version("1.9.9")
    for junk in ("", "latest", "v1", "1.2.3-rc1", "1.2.3.4"):
        with pytest.raises(ValueError):
            parse_version(junk)


def test_finds_a_newer_release(github: FakeGitHub, tmp_path: Path) -> None:
    update = updater(github, tmp_path)
    run(update.check())  # the repository has no releases yet
    assert update.latest is None and not update.available

    github.publish("1.0.0", make_wheel("1.0.0"))
    run(update.check())
    assert not update.available  # that is what is running already

    github.publish("1.1.0", make_wheel("1.1.0"), notes="Faster tiles.")
    run(update.check())
    view = update.view()
    assert view["available"] is True
    assert view["latest"]["version"] == "1.1.0" and view["latest"]["notes"] == "Faster tiles."
    assert view["checked_ago"] == 0

    github.tag = "nightly"  # not a version: nothing to offer
    run(update.check())
    assert update.latest is None


def test_install_puts_the_new_version_in_front_and_can_go_back(github: FakeGitHub, tmp_path: Path) -> None:
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    assert run(update.install()) == "9.9.9"
    assert update.state == "ready" and not update.available  # installed, waiting for a restart

    package = tmp_path / "updates" / "9.9.9" / "qkvm"
    assert (package / "cli.py").exists() and (package / "static" / "index.html").exists()
    assert json.loads((tmp_path / "updates" / "current.json").read_text()) == {"version": "9.9.9", "previous": None, "previous_proven": False}
    # What `python -m qkvm` does with it at the next start:
    assert starter.active_update(tmp_path) == package
    assert starter.roll_back(tmp_path) is True
    assert starter.active_update(tmp_path) is None
    assert starter.roll_back(tmp_path) is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permission regression")
@pytest.mark.parametrize("mask", [0o000, 0o002])
@pytest.mark.parametrize("existing", [False, True])
def test_installation_is_private_under_a_permissive_umask(github: FakeGitHub, tmp_path: Path, mask: int, existing: bool) -> None:
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    if existing:
        update.directory.mkdir()
        update.directory.chmod(0o777)
        pointer = update.directory / "current.json"
        pointer.write_text("{}", encoding="utf-8")
        pointer.chmod(0o666)
    before = os.umask(mask)
    try:
        assert run(update.install()) == "9.9.9"
    finally:
        os.umask(before)
    assert starter.active_update(tmp_path) == tmp_path / "updates" / "9.9.9" / "qkvm"
    directory = tmp_path / "updates"
    for path in (directory, *directory.rglob("*")):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600), path


def test_an_update_older_than_the_program_is_ignored(tmp_path: Path) -> None:
    older = "0.0.1"
    package = tmp_path / "updates" / older / "qkvm"
    package.mkdir(parents=True)
    (package / "_version.py").write_text(f'__version__ = "{older}"\n')
    (tmp_path / "updates" / "current.json").write_text(json.dumps({"version": older, "previous": None}))
    assert parse_version(__version__) > parse_version(older)
    assert starter.active_update(tmp_path) is None  # e.g. after the program itself was upgraded with pip


def test_a_download_that_does_not_match_its_checksum_is_refused(github: FakeGitHub, tmp_path: Path) -> None:
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    github.files["qkvm-9.9.9-py3-none-any.whl"] = make_wheel("9.9.9", extra={"qkvm/backdoor.py": b"x = 1"})
    with pytest.raises(UpdateError, match="checksum"):
        run(update.install())
    assert update.state == "failed"
    assert not (tmp_path / "updates" / "current.json").exists()

    github.publish("9.9.9", make_wheel("9.9.9"), sums=False)  # nothing to verify against at all
    run(update.check())
    with pytest.raises(UpdateError, match="no checksums"):
        run(update.install())


def test_signed_releases(github: FakeGitHub, tmp_path: Path) -> None:
    key_file = tmp_path / "signing.key"
    public = release.keygen(key_file)
    with pytest.raises(SystemExit):
        release.keygen(key_file)  # never overwrites a key
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path / "data", keys=(public,))
    run(update.check())

    with pytest.raises(UpdateError, match="not signed"):  # no signature attached
        run(update.install())

    stranger = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    github.files["SHA256SUMS.sig"] = release.sign(base64.b64encode(stranger).decode(), github.files["SHA256SUMS"]).encode()
    run(update.check())
    with pytest.raises(UpdateError, match="trusted key"):
        run(update.install())

    github.files["SHA256SUMS.sig"] = release.sign(key_file.read_text(), github.files["SHA256SUMS"]).encode()
    run(update.check())
    assert run(update.install()) == "9.9.9"


def test_signed_update_requires_compatible_installed_dependencies(
    github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A correct publisher signature and checksum do not make an old dependency compatible. The old
    # updater accepted this exact 0.1.1 -> 0.2.0 floor change, and marked the package ready to run.
    key_file = tmp_path / "signing.key"
    public = release.keygen(key_file)
    github.publish("0.2.0", make_wheel("0.2.0", requires=("uvicorn>=0.54",)), signed_by=key_file.read_text())
    update = updater(github, tmp_path / "data", keys=(public,), current="0.1.1", allow_unsigned=False)
    installed = {"uvicorn": "0.46.0"}
    monkeypatch.setattr(update_module.importlib.metadata, "version", installed.__getitem__)
    run(update.check())
    with pytest.raises(UpdateError, match=r"uvicorn.*pip install --upgrade qkvm"):
        run(update.install())
    assert update.state == "failed" and update.installed is None
    assert not (tmp_path / "data" / "updates" / "current.json").exists()
    assert not (tmp_path / "data" / "updates" / "0.2.0").exists()
    # After the operator upgrades the library, the same signed package is accepted.
    installed["uvicorn"] = "0.54.0"
    assert run(update.install()) == "0.2.0"
    assert json.loads((tmp_path / "data" / "updates" / "current.json").read_text())["version"] == "0.2.0"


def test_deeply_nested_signed_dependency_marker_fails_without_leaving_update_busy(
    github: FakeGitHub, tmp_path: Path
) -> None:
    key_file = tmp_path / "signing.key"
    public = release.keygen(key_file)
    requirement = "fastapi; " + "(" * 500 + 'python_version >= "3"' + ")" * 500
    github.publish("9.9.9", make_wheel("9.9.9", requires=(requirement,)), signed_by=key_file.read_text())
    update = updater(github, tmp_path / "data", keys=(public,), allow_unsigned=False)
    run(update.check())
    with pytest.raises(UpdateError, match="requirements could not be verified"):
        run(update.install())
    assert update.state == "failed" and update.installed is None
    assert not (tmp_path / "data" / "updates" / "current.json").exists()
    assert not (tmp_path / "data" / "updates" / "9.9.9").exists()
    # A failed parser cannot leave "installing" latched or prevent a later valid package.
    github.publish("9.9.9", make_wheel("9.9.9"), signed_by=key_file.read_text())
    assert run(update.install()) == "9.9.9"


@pytest.mark.parametrize(
    ("specifier", "installed", "accepted"),
    [
        (">=1.2,<2", "1.2.0", True),
        (">=1.2,<2", "2.0.0", False),
        ("~=1.4.2", "1.4.9", True),
        ("~=1.4.2", "1.5.0", False),
        (">=1,!=1.2.3", "1.2.3", False),
        ("==1.2.*", "1.2.9", True),
        (">=1.2", "1.2rc1", False),
        (">=1.2rc1", "1.2rc1", True),
        (">=1", "not-a-version", False),
    ],
)
def test_update_checks_dependency_version_specifiers(
    monkeypatch: pytest.MonkeyPatch, specifier: str, installed: str, accepted: bool
) -> None:
    monkeypatch.setattr(update_module.importlib.metadata, "version", lambda name: installed)
    metadata = f"Requires-Dist: some-package{specifier}\n"
    if accepted:
        update_module._check_requirements(metadata)
    else:
        with pytest.raises(UpdateError, match="pip install --upgrade qkvm"):
            update_module._check_requirements(metadata)


@pytest.mark.parametrize(
    ("requirement", "active"),
    [
        ('absent-package; python_version < "0"', False),
        ('absent-package; sys_platform == "no-such-platform"', False),
        ('absent-package; extra == "video"', False),
        ('absent-package[video] @ https://example.invalid/a.whl ; extra == "video"', False),
        ('absent-package; extra == "video" or python_version >= "3"', True),
        ('absent-package; extra != "video"', True),
        ('absent-package; extra == ""', True),
    ],
)
def test_update_evaluates_environment_and_optional_extra_markers(
    monkeypatch: pytest.MonkeyPatch, requirement: str, active: bool
) -> None:
    looked_up = []

    def absent(name: str) -> str:
        looked_up.append(name)
        raise update_module.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(update_module.importlib.metadata, "version", absent)
    metadata = f"Requires-Dist: {requirement}\n"
    if active:
        with pytest.raises(UpdateError, match="not installed"):
            update_module._check_requirements(metadata)
        assert looked_up == ["absent-package"]
    else:
        update_module._check_requirements(metadata)
        assert looked_up == []


@pytest.mark.parametrize(
    ("specifier", "accepted"),
    [(">=3.11", True), (">=3.13.2", False), (">=3.11,<3.13", False), ("!=3.13.1", False), ("~=3.13.0", True)],
)
def test_update_checks_the_complete_python_requirement(monkeypatch: pytest.MonkeyPatch, specifier: str, accepted: bool) -> None:
    monkeypatch.setattr(update_module.platform, "python_version", lambda: "3.13.1")
    metadata = f"Requires-Python: {specifier}\n"
    if accepted:
        update_module._check_requirements(metadata)
    else:
        with pytest.raises(UpdateError, match="needs Python"):
            update_module._check_requirements(metadata)


@pytest.mark.parametrize(
    "metadata",
    [
        "Requires-Dist: not a requirement\n",
        "Requires-Dist: some-package>=no-version\n",
        "Requires-Dist: some-package; unknown_marker == 'x'\n",
        "Requires-Python: not a specifier\n",
        "Requires-Python: >=3.11\nRequires-Python: <3.0\n",
        "Requires-Dist: some-package[video]>=1\n",
        "Requires-Dist: some-package @ https://example.invalid/a.whl\n",
    ],
)
def test_update_refuses_requirements_it_cannot_verify(metadata: str) -> None:
    with pytest.raises(UpdateError, match="pip install --upgrade qkvm"):
        update_module._check_requirements(metadata)


def test_update_reads_folded_metadata_but_not_requirements_in_the_description(monkeypatch: pytest.MonkeyPatch) -> None:
    looked_up = []

    def installed(name: str) -> str:
        looked_up.append(name)
        return "1.5"

    monkeypatch.setattr(update_module.importlib.metadata, "version", installed)
    update_module._check_requirements("Requires-Dist: some-package>=1,\n <2\n\nRequires-Dist: absent-package>=999\n")
    assert looked_up == ["some-package"]


def test_update_requires_one_unambiguous_metadata_file(tmp_path: Path) -> None:
    wheel = make_wheel("9.9.9")
    with zipfile.ZipFile(update_module.io.BytesIO(wheel)) as original:
        for duplicate in (False, True):
            buffer = update_module.io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as changed:
                for member in original.infolist():
                    if duplicate or not member.filename.endswith(".dist-info/METADATA"):
                        changed.writestr(member, original.read(member))
                if duplicate:
                    changed.writestr("other-1.0.dist-info/METADATA", "Name: other\nVersion: 1.0\n")
            with pytest.raises(UpdateError, match="exactly one dependency metadata"):
                update_module.unpack(buffer.getvalue(), "9.9.9", tmp_path / "new-version")
            assert not (tmp_path / "new-version").exists()


@pytest.mark.parametrize(
    ("wheel", "problem"),
    [
        pytest.param(make_wheel("9.9.9", extra={"../outside.py": b""}), "should not", id="path traversal"),
        pytest.param(make_wheel("9.9.9", extra={"other_package/__init__.py": b""}), "should not", id="unexpected package"),
        pytest.param(make_wheel("9.9.9", declared="9.9.8"), "not the version", id="version mismatch"),
        pytest.param(make_wheel("9.9.9", requires=("surely-not-installed-anywhere>=1",)), "not installed", id="missing dependency"),
        pytest.param(b"this is not a zip file", "not a valid package", id="invalid archive"),
        # Names that Windows takes for another file's, written after the one that was checked:
        pytest.param(make_wheel("9.9.9", extra={"qkvm/cli.py.": b"REPLACED = 1\n"}), "should not", id="a name that ends in a dot"),
        pytest.param(make_wheel("9.9.9", extra={"qkvm/_VERSION.PY": b'__version__ = "1234.0.0"\n'}), "should not", id="a name twice but for its capitals"),
        pytest.param(make_wheel("9.9.9", extra={"qkvm/cli.py ": b""}), "should not", id="a name that ends in a space"),
        pytest.param(make_wheel("9.9.9", extra={f"qkvm/empty{number}.py": b"" for number in range(2001)}), "larger than expected", id="thousands of files"),
    ],
)
def test_packages_that_are_not_a_proper_release_are_refused(
    github: FakeGitHub, tmp_path: Path, wheel: bytes, problem: str
) -> None:
    github.publish("9.9.9", wheel)
    update = updater(github, tmp_path)
    run(update.check())
    with pytest.raises(UpdateError, match=problem):
        run(update.install())
    assert not (tmp_path / "updates" / "9.9.9").exists()
    assert not (tmp_path / "outside.py").exists()


def test_checking_needs_a_repository(tmp_path: Path) -> None:
    update = Updater(tmp_path, "")
    with pytest.raises(UpdateError, match="No release repository"):
        run(update.check())
    with pytest.raises(ValueError):
        Updater(tmp_path, "https://github.com/owner/wall")  # owner/name only


# --- through the app -------------------------------------------------------------------------------


def test_update_from_the_app(github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    github.publish("9.9.9", make_wheel("9.9.9"), notes="Bulk actions.")
    core = Core(tmp_path)
    core.updater = updater(github, tmp_path, current=__version__)
    core.supervised = True
    with TestClient(create_app(core), headers={"X-QKVM": "1"}, client=("127.0.0.1", 50000)) as client:
        assert client.get("/api/v1/update").status_code == 401
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200

        status = client.get("/api/v1/update").json()
        assert status["current"] == __version__ and status["repo"] == "owner/wall"
        assert status["auto_check"] is True and status["latest"] is None
        assert client.put("/api/v1/update", json={"auto_check": False}).json()["auto_check"] is False

        checked = client.post("/api/v1/update/check").json()
        assert checked["available"] is True and checked["latest"]["notes"] == "Bulk actions."

        assert client.post("/api/v1/update/install", json={"password": "not the password"}).status_code == 401
        assert not (tmp_path / "updates").exists()
        installed = client.post("/api/v1/update/install", json={"password": PASSWORD})
        assert installed.status_code == 200
        assert installed.json()["restarting"] is True and installed.json()["installed"] == "9.9.9"

        deadline = time.monotonic() + 5
        while core.exit_status is None:
            assert time.monotonic() < deadline, "the wall never asked to be restarted"
            time.sleep(0.05)
        assert core.exit_status == RESTART
        events = [entry["event"] for entry in client.get("/api/v1/audit").json()["entries"]]
        assert "update_installed" in events


def test_a_container_is_updated_by_replacing_its_image(github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setenv("QKVM_CONTAINER", "1")
    github.publish("9.9.9", make_wheel("9.9.9"))
    core = Core(tmp_path)
    core.updater = updater(github, tmp_path, current=__version__)
    with TestClient(create_app(core), headers={"X-QKVM": "1"}, client=("127.0.0.1", 50000)) as client:
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        status = client.post("/api/v1/update/check").json()
        assert status["available"] is True and status["container"] is True  # it still says what is new
        refused = client.post("/api/v1/update/install", json={"password": PASSWORD})
        assert refused.status_code == 409 and refused.json()["code"] == "container"
    assert not (tmp_path / "updates").exists()


def test_page_carries_the_server_version(tmp_path: Path) -> None:
    with TestClient(create_app(Core(tmp_path)), client=("127.0.0.1", 50000)) as client:
        page = client.get("/").text
        assert f'content="{__version__}"' in page and "{{version}}" not in page
        said = client.get("/healthz").json()
        assert {key: value for key, value in said.items() if key != "page"} == {"status": "ok", "version": __version__, "api": ["v1"], "locked": False}


# --- the starter -------------------------------------------------------------------------------------


class FakeChild:
    def __init__(self, status: int) -> None:
        self.status = status

    def wait(self, timeout: float | None = None) -> int:
        return self.status


def test_starter_runs_the_wall_again_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = [starter.RESTART, starter.RESTART, 0]
    launches: list[list[str]] = []

    def launch(command: list[str], env: dict[str, str], stdin: Any, stdout: Any, stderr: Any) -> FakeChild:
        launches.append(command)
        assert env[starter.CHILD] == "1"
        assert stdin == starter.subprocess.PIPE  # the wall watches this pipe to notice the starter dying
        assert stdout is None and stderr is None  # started from a terminal, it writes to that terminal
        return FakeChild(statuses.pop(0))

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert len(launches) == 3 and launches[0][-2:] == ["--data-dir", str(tmp_path)]
    assert starter.data_dir(["-p", "9000"]) == Path.home() / ".qkvm"
    assert starter.data_dir([f"--data-dir={tmp_path}"]) == tmp_path


def test_starter_rolls_back_an_update_that_will_not_start(
    github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    run(update.install())
    statuses = [1, 0]  # the new version crashes at once; the old one then runs fine

    monkeypatch.setattr(starter.subprocess, "Popen", lambda command, **options: FakeChild(statuses.pop(0)))
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert statuses == [] and starter.active_update(tmp_path) is None

    statuses = [2]  # "could not start" (port taken, bad option) is not a reason to roll anything back
    run(update.check())
    update.installed = None
    run(update.install())
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 2
    assert starter.active_update(tmp_path) is not None


def test_being_told_to_stop_is_not_a_failure_and_rolls_nothing_back(
    github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A service manager stops the wall with SIGTERM, a person with Ctrl+C. The wall then ends the way a
    # process that a signal ended does (the web server winds down and hands the signal on), within
    # seconds of starting if the stop comes then: none of which is the new version failing to start.
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    run(update.install())
    handlers: dict[int, Any] = {}
    monkeypatch.setattr(starter.signal, "signal", lambda number, handler: handlers.__setitem__(number, handler))
    launches: list[list[str]] = []

    class Stopped(FakeChild):
        handed_on = 0

        def wait(self, timeout: float | None = None) -> int:
            handlers[starter.signal.SIGTERM](starter.signal.SIGTERM, None)  # the stop arrives while the wall runs
            return -15

        def terminate(self) -> None:
            Stopped.handed_on += 1

    def launch(command: list[str], **options: Any) -> FakeChild:
        launches.append(command)
        return Stopped(0)

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0  # and not 241, which systemd and Docker show as "failed"
    assert len(launches) == 1 and Stopped.handed_on == 1  # the wall was told, and was not started again
    assert starter.active_update(tmp_path) is not None  # the update that was installed a moment ago is still there

    class Interrupted(FakeChild):
        waits = 0

        def wait(self, timeout: float | None = None) -> int:
            Interrupted.waits += 1
            if Interrupted.waits == 1:
                raise KeyboardInterrupt  # Ctrl+C reaches the starter and the wall alike
            return 3221225786  # what Windows gives as the status of a process that Ctrl+C ended

    monkeypatch.setattr(starter.subprocess, "Popen", lambda command, **options: Interrupted(0))
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert starter.active_update(tmp_path) is not None


# --- where the settings are ------------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home folder that is nobody's, for whoever asks where home is."""
    folder = tmp_path / "home"
    folder.mkdir()
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.setenv("USERPROFILE", str(folder))
    return folder


def test_settings_are_in_one_place_whatever_folder_it_is_started_in(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Installed with pip, `qkvm` is typed wherever one happens to be. Settings kept next to that would be a
    # new, empty wall every time: the first-run page again, and "where have my KVMs gone".
    for name in ("here", "there"):
        (tmp_path / name).mkdir()
        monkeypatch.chdir(tmp_path / name)
        assert starter.data_dir([]) == home / ".qkvm"  # where the starter looks for an installed update
        assert run_cli(["--disable-2fa", "nobody"]) == 2  # and the program proper, asked the same way: no such account
    assert (home / ".qkvm" / "qkvm.log").is_file()
    assert sorted(found.name for found in tmp_path.iterdir()) == ["here", "home", "there"]
    assert list((tmp_path / "here").iterdir()) == [] and list((tmp_path / "there").iterdir()) == []
    # Told where, that is where: a service and a container have no home to speak of.
    assert starter.data_dir(["--data-dir", "elsewhere"]) == Path("elsewhere")
    assert run_cli(["--data-dir", str(tmp_path / "elsewhere"), "--disable-2fa", "nobody"]) == 2
    assert (tmp_path / "elsewhere" / "qkvm.log").is_file()


def test_without_a_home_folder_it_asks_to_be_told_where(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def nowhere() -> Path:
        raise RuntimeError("Could not determine home directory.")  # a container started under a number nobody has

    monkeypatch.setattr(Path, "home", staticmethod(nowhere))
    assert starter.data_dir(["--data-dir", "/data"]) == Path("/data")  # said where: nobody asks for a home
    with pytest.raises(SystemExit) as stopped:
        starter.data_dir([])
    assert stopped.value.code == 2 and "--data-dir" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="on Windows a profile is its user's alone by other means")
def test_a_folder_it_makes_for_its_settings_is_its_owners_alone(home: Path, tmp_path: Path) -> None:
    # The encrypted passwords, the log of who did what, the key of its certificate: nothing in there is for
    # the other people who have an account on the same computer.
    assert run_cli(["--disable-2fa", "nobody"]) == 2
    assert stat.S_IMODE((home / ".qkvm").stat().st_mode) == 0o700
    # And what it writes there is too, also where the folder is somebody else's making and open to more.
    assert all(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0 for path in (home / ".qkvm").iterdir())
    # A folder that was there already is as its owner made it, and stays so.
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o750)
    assert run_cli(["--data-dir", str(shared), "--disable-2fa", "nobody"]) == 2
    assert stat.S_IMODE(shared.stat().st_mode) == 0o750
    assert all(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0 for path in shared.iterdir())


# --- started without a window ---------------------------------------------------------------------------


def test_having_nowhere_to_print_to_does_not_stop_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Started with pythonw or as a scheduled task (the way the README gives for Windows), or from a terminal
    # that has since been closed, output goes nowhere. "Nowhere" must not be an error: the first line printed
    # after the listeners are open used to end the program.
    from qkvm import cli

    class Broken:
        def write(self, text: str) -> int:
            raise OSError(22, "Invalid argument")

        def flush(self) -> None:
            raise OSError(22, "Invalid argument")

    monkeypatch.setattr(cli.sys, "stdout", Broken())
    monkeypatch.setattr(cli.sys, "stderr", Broken())
    cli.say("qKVM 0.1.0 - 3 devices")
    cli.say("qkvm: something to complain about", error=True)

    # And the starter, itself without a window, gives the wall a real "nowhere" to write to: what it would
    # hand down otherwise is a handle that fails on the first use.
    given: list[dict[str, Any]] = []

    def launch(command: list[str], **options: Any) -> FakeChild:
        given.append(options)
        return FakeChild(0)

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    monkeypatch.setattr(starter.sys, "stdout", None)
    monkeypatch.setattr(starter.sys, "stderr", None)
    assert starter.supervise(["--data-dir", "anywhere"]) == 0
    assert given[0]["stdout"] == starter.subprocess.DEVNULL and given[0]["stderr"] == starter.subprocess.DEVNULL
    assert given[0]["stdin"] == starter.subprocess.PIPE  # which the wall still watches


def broken_inside(wheel: bytes) -> bytes:
    """`wheel` with one byte of a file's contents changed: its list of files reads as before, the file itself no longer does."""
    with zipfile.ZipFile(__import__("io").BytesIO(wheel)) as archive:
        at = archive.getinfo("qkvm/static/index.html").header_offset
    start = wheel.index(b"<!doctype html>", at)
    return wheel[:start] + b"?" + wheel[start + 1 :]


def test_a_package_that_is_broken_inside_is_a_failed_update_like_any_other(github: FakeGitHub, tmp_path: Path) -> None:
    # It passed its checksum (whoever made the list made it of this file) and cannot be unpacked: that came out
    # as an error nobody had named, the page was answered "something went wrong inside qKVM", and the
    # update stayed "installing".
    github.publish("9.9.9", broken_inside(make_wheel("9.9.9")))
    update = updater(github, tmp_path)
    run(update.check())
    with pytest.raises(UpdateError, match="could not be unpacked"):
        run(update.install())
    assert update.state != "installing" and starter.active_update(tmp_path) is None


def an_update_that_leaves_a_mark(data: Path, version: str = "9.9.9") -> Path:
    """Put what looks like an installed update into `data`. Run, it writes a file there; returns that file."""
    package = data / "updates" / version / "qkvm"
    package.mkdir(parents=True)
    mark = data / "the-update-ran"
    (package / "_version.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (package / "cli.py").write_text(f"import pathlib\ndef main(argv=None):\n    pathlib.Path({str(mark)!r}).write_text('ran')\n    return 0\n", encoding="utf-8")
    (data / "updates" / "current.json").write_text(json.dumps({"version": version, "previous": None}), encoding="utf-8")
    return mark


def typed(arguments: list[str], where: Path, tmp_path: Path, **environment: str) -> subprocess.CompletedProcess[str]:
    """Run the `qkvm` command in the folder `where`, the way the command pip installs runs it."""
    command = tmp_path / "bin" / "qkvm_command.py"  # (pip's own lies in a folder of commands: that folder is no place Python then looks in for the program)
    command.parent.mkdir(exist_ok=True)
    command.write_text("import sys\nfrom qkvm.__main__ import main\nsys.exit(main())\n", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    installed = str(Path(starter.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": installed, "HOME": str(home), "USERPROFILE": str(home), **environment}
    env.pop(starter.CHILD, None)
    return subprocess.run([sys.executable, str(command), *arguments], cwd=where, env=env, capture_output=True, text=True, timeout=120)


def test_nothing_that_lies_in_the_folder_it_is_started_in_is_run(tmp_path: Path) -> None:
    # `python -m qkvm`, which is how the wall proper is started, looks for the program in the current folder
    # first. A folder called qkvm lying there, or a file called json.py, was run in its place: as the account
    # that holds every device password, by whoever can write to Downloads, to /tmp, to a share.
    where = tmp_path / "downloads"
    (where / "qkvm").mkdir(parents=True)
    planted = "import pathlib\npathlib.Path(%r).write_text('ran')\n"
    (where / "qkvm" / "__init__.py").write_text("", encoding="utf-8")
    (where / "qkvm" / "__main__.py").write_text(planted % str(tmp_path / "planted-program-ran"), encoding="utf-8")
    (where / "json.py").write_text(planted % str(tmp_path / "planted-library-ran"), encoding="utf-8")
    # (Half of a pair of options: the real program says so and ends, with status 2, before it serves anything.)
    done = typed(["--data-dir", str(tmp_path / "data"), "--tls-cert", "x.pem"], where, tmp_path)
    assert done.returncode == 2 and "go together" in done.stderr, done.stderr
    assert not (tmp_path / "planted-program-ran").exists() and not (tmp_path / "planted-library-ran").exists()


def test_what_lies_in_the_data_folder_is_not_run_to_answer_a_question_nor_in_a_container(tmp_path: Path) -> None:
    # An update installed from the app lies in the data folder, and is run from there. But not for a question
    # (somebody who asks `qkvm --version --data-dir /var/lib/qkvm` as root is more than whoever can write
    # there), and not in a container, where the program installs none and a volume is not a place for code.
    data = tmp_path / "data"
    mark = an_update_that_leaves_a_mark(data)
    assert starter.active_update(data) is not None  # it is one the starter would run
    said = typed(["--version", "--data-dir", str(data)], tmp_path, tmp_path)
    assert said.returncode == 0 and __version__ in said.stdout and not mark.exists(), said.stderr
    assert typed(["--help", "--data-dir", str(data)], tmp_path, tmp_path).returncode == 0 and not mark.exists()
    boxed = typed(["--data-dir", str(data), "--tls-cert", "x.pem"], tmp_path, tmp_path, QKVM_CONTAINER="1")
    assert boxed.returncode == 2 and not mark.exists(), boxed.stderr
    # Where it is run: asked to do something, by whoever the folder belongs to.
    assert typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path).returncode == 0 and mark.exists()


def test_only_what_is_named_as_a_version_is_run_as_one(tmp_path: Path) -> None:
    for name in ("../../somewhere-else", "8.0.0.tmp", "9.9.9/../9.9.9", "", "9"):
        data = tmp_path / str(abs(hash(name)))
        an_update_that_leaves_a_mark(data)
        (data / "updates" / "current.json").write_text(json.dumps({"version": name, "previous": None}), encoding="utf-8")
        assert starter.active_update(data) is None, name
    for not_a_name in (9, None, ["9.9.9"]):
        (data / "updates" / "current.json").write_text(json.dumps({"version": not_a_name}), encoding="utf-8")
        assert starter.active_update(data) is None


@pytest.mark.skipif(os.name != "posix", reason="who a folder belongs to is kept another way on Windows, and not looked at there")
def test_an_update_in_a_folder_others_can_write_to_is_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    an_update_that_leaves_a_mark(data)
    assert starter.active_update(data) is not None
    os.chmod(data / "updates", 0o777)
    assert starter.active_update(data, tell=True) is None
    assert "is not used" in capsys.readouterr().err
    os.chmod(data / "updates", 0o755)
    os.chmod(data / "updates" / "9.9.9" / "qkvm", 0o775)
    assert starter.active_update(data) is None


def test_an_update_that_has_run_is_not_taken_back_by_a_later_start_that_ends_badly(
    github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # "It died within half a minute of starting" was asked at every start for as long as the update was in
    # use. Weeks later, a start that ended badly for a reason of its own (no memory left, somebody's
    # doing) put the wall back on the version before, with the fix the update was installed for.
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    run(update.install())

    class StaysUp(FakeChild):
        def wait(self, timeout: float | None = None) -> int:
            if timeout is not None:
                raise subprocess.TimeoutExpired("qkvm", timeout)  # still running when the trial is over
            return self.status

    children: list[FakeChild] = [StaysUp(starter.RESTART), FakeChild(1)]  # it runs, is started again, and that start ends badly at once
    monkeypatch.setattr(starter.subprocess, "Popen", lambda command, **options: children.pop(0))
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 1
    assert children == [] and starter.active_update(tmp_path) is not None
    assert json.loads((tmp_path / "updates" / "current.json").read_text(encoding="utf-8"))["proven"] is True
    assert "going back" not in capsys.readouterr().err
    # (One that never got that far is taken back as before, and that is in the program's log too.)
    update.installed = None
    github.publish("9.9.10", make_wheel("9.9.10"))
    run(update.check())
    run(update.install())
    children[:] = [FakeChild(1), FakeChild(0)]
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert "9.9.10" in (tmp_path / "qkvm.log").read_text(encoding="utf-8")
    assert starter.version_of(starter.active_update(tmp_path)) == (9, 9, 9)  # type: ignore[arg-type]


def test_the_starter_and_the_program_read_where_the_data_is_alike(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The program took a shortened option (--data) and the starter did not know it: an update installed from
    # the app was then never used, and going back to the version before was done in another folder.
    assert starter.data_dir([f"-d{tmp_path}"]) == tmp_path
    assert starter.data_dir(["-d", str(tmp_path)]) == tmp_path
    with pytest.raises(SystemExit) as ended:
        run_cli(["--data", str(tmp_path), "status"])
    assert ended.value.code == 2 and "--data" in capsys.readouterr().err


def test_the_wall_proper_is_started_from_this_copy_of_the_program(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    launches: list[tuple[list[str], dict[str, str]]] = []

    def launch(command: list[str], env: dict[str, str], **options: Any) -> FakeChild:
        launches.append((command, env))
        return FakeChild(0)

    monkeypatch.setattr(starter.subprocess, "Popen", launch)
    monkeypatch.setenv("PYTHONPATH", "somewhere-of-the-owners")
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    command, env = launches[0]
    assert command[1:4] == ["-P", "-m", "qkvm"]
    assert env["PYTHONPATH"].split(os.pathsep) == [str(Path(starter.__file__).resolve().parent.parent), "somewhere-of-the-owners"]


def test_a_release_that_no_copy_would_install_is_not_made(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # What the release workflow runs with the signing key. A missing key used to skip the signing, and the
    # release went out all the same: of a version with a key built in, that is a release nobody can install.
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("0" * 64 + "  qkvm-9.9.9-py3-none-any.whl\n", encoding="ascii")
    signature = tmp_path / "SHA256SUMS.sig"
    public = release.keygen(tmp_path / "signing.key")
    key = (tmp_path / "signing.key").read_text(encoding="ascii")
    other = release.keygen(tmp_path / "another.key")

    assert "unsigned" in release.publish(sums, "", ())  # a copy built without a key, as a fork may be: nothing to sign with, and said
    assert not signature.exists()
    with pytest.raises(SystemExit, match="no copy installs"):
        release.publish(sums, "", (public,))
    with pytest.raises(SystemExit, match="not one of the keys"):
        release.publish(sums, key, (other,))
    assert not signature.exists()
    release.publish(sums, key, (other, public))
    from qkvm.update import verify_signature

    verify_signature(sums.read_bytes(), signature.read_bytes(), (public,))
    # The keys are read out of the program's own file, without loading it (and the libraries it needs).
    assert release.built_in_keys() == update_module.RELEASE_KEYS
    source = tmp_path / "update.py"
    source.write_text(f'import httpx_is_not_needed_for_this\nRELEASE_KEYS: tuple[str, ...] = ("{public}",)\n', encoding="utf-8")
    assert release.built_in_keys(source) == (public,)


def test_the_publishers_key_is_built_in_and_is_the_one_it_is(tmp_path: Path) -> None:
    # One key, the publisher's (made on 2026-10-12; its other half is nowhere in this repository and in no
    # test). Changed on purpose only: every installed copy takes its updates from whoever holds the other
    # half of what stands here, and from nobody else. With it built in, nothing lets an unsigned release in.
    assert update_module.RELEASE_KEYS == ("R9V9vqrwqFnxx4j6mf0ZSG7Af5PTFILqZd1Qc6F1JpI=",)
    for key in update_module.RELEASE_KEYS:
        assert len(base64.b64decode(key, validate=True)) == 32
    as_shipped = Updater(tmp_path, "owner/wall")
    assert as_shipped.keys == update_module.RELEASE_KEYS and as_shipped.view()["signed"] is True and as_shipped.view()["installable"] is True
    lenient = Updater(tmp_path, "owner/wall", allow_unsigned=True)
    assert lenient.keys == update_module.RELEASE_KEYS  # (the option takes no key away)
    with pytest.raises(UpdateError, match="not signed by a trusted key"):
        update_module.verify_signature(b"anything", base64.b64encode(b"x" * 64), update_module.RELEASE_KEYS)


def test_typed_as_python_m_the_starter_takes_no_library_from_the_folder_it_is_typed_in(tmp_path: Path) -> None:
    # `python -m qkvm` is the same command where `qkvm` is not on the path, and how a task at log-on starts it.
    # Python then looks in the current folder first, for everything: the part that starts the wall proper
    # was itself the one that ran a json.py lying there.
    # (What this part imports, that is. What Python itself loads to find a module named with -m, before a
    # line of this program has run, it takes from that folder all the same: types.py on every version, and
    # more on the older ones. Only `python -P -m qkvm`, or the command `qkvm`, looks there for nothing.)
    where = tmp_path / "downloads"
    where.mkdir()
    planted = "import pathlib\npathlib.Path(%r).write_text('ran')\nraise ImportError('not the real one')\n"
    for name in ("__future__", "json", "re", "signal", "subprocess", "time", "pathlib", "argparse"):
        (where / f"{name}.py").write_text(planted % str(tmp_path / f"planted-{name}-ran"), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    installed = str(Path(starter.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": installed, "HOME": str(home), "USERPROFILE": str(home)}
    env.pop(starter.CHILD, None)
    env.pop("PYTHONSAFEPATH", None)
    for asked in (["--data-dir", str(tmp_path / "data"), "--tls-cert", "x.pem"], ["--version"]):
        done = subprocess.run([sys.executable, "-m", "qkvm", *asked], cwd=where, env=env, capture_output=True, text=True, timeout=120)
        assert done.returncode == (0 if asked == ["--version"] else 2), done.stderr
    assert [file.name for file in tmp_path.glob("planted-*")] == []


def test_where_the_data_is_is_read_alike_also_when_it_is_given_as_nothing(home: Path) -> None:
    for given in (["--data-dir", ""], ["--data-dir="], ["-d", ""], ["-d="]):
        assert starter.data_dir(given) == home / ".qkvm", given


def test_a_version_gone_back_to_is_on_trial_again_unless_it_ever_ran(github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Gone back to, the version before was marked as one that had run. Where it never had (installed, and the
    # next one installed before it got through a start), and did not start either, the wall was left trying
    # it for good, with the shipped files one more step back and never taken.
    update = updater(github, tmp_path)
    for version in ("9.9.2", "9.9.3"):
        github.publish(version, make_wheel(version))
        run(update.check())
        update.installed = None
        run(update.install())
    said = json.loads((tmp_path / "updates" / "current.json").read_text(encoding="utf-8"))
    assert (said["version"], said["previous"], said["previous_proven"]) == ("9.9.3", "9.9.2", False)
    children = [FakeChild(1), FakeChild(1), FakeChild(0)]  # 9.9.3 does not start, 9.9.2 does not either, what was shipped does
    monkeypatch.setattr(starter.subprocess, "Popen", lambda command, **options: children.pop(0))
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 0
    assert children == [] and starter.active_update(tmp_path) is None and not (tmp_path / "updates" / "current.json").exists()

    # One that did run is gone back to as that: a later start of it that ends badly is not its doing.
    for version in ("9.9.4", "9.9.5"):
        github.publish(version, make_wheel(version))
        run(update.check())
        update.installed = None
        run(update.install())
        if version == "9.9.4":
            starter.proven(tmp_path, "9.9.4")
    children[:] = [FakeChild(1), FakeChild(1)]  # 9.9.5 does not start; then 9.9.4 ends badly once, for a reason of its own
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 1
    assert children == [] and starter.version_of(starter.active_update(tmp_path)) == (9, 9, 4)  # type: ignore[arg-type]


def test_marking_an_update_as_one_that_ran_does_not_put_back_what_was_installed_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    an_update_that_leaves_a_mark(tmp_path, "9.9.2")
    read = starter.pointer
    looks = 0

    def installed_in_between(data: Path) -> Any:
        nonlocal looks
        looks += 1
        if looks == 2:  # between the look that decides and the write: the program installs a newer one
            (data / "updates" / "current.json").write_text(json.dumps({"version": "9.9.3", "previous": "9.9.2"}), encoding="utf-8")
        return read(data)

    monkeypatch.setattr(starter, "pointer", installed_in_between)
    starter.proven(tmp_path, "9.9.2")
    assert json.loads((tmp_path / "updates" / "current.json").read_text(encoding="utf-8")) == {"version": "9.9.3", "previous": "9.9.2"}
    monkeypatch.undo()
    starter.proven(tmp_path, "9.9.3")
    assert json.loads((tmp_path / "updates" / "current.json").read_text(encoding="utf-8"))["proven"] is True


@pytest.mark.skipif(os.name != "posix", reason="who may write a file is kept another way on Windows, and not looked at there")
def test_what_the_starter_writes_is_its_owners_alone_whatever_the_shell_lets_others_do(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The program writes with others shut out; the part that starts it wrote as the shell it was typed in does.
    # On a desktop where a user's group may write what the user makes, marking an update as one that ran made
    # its pointer "writable by others", and the next start passed the update over for that: back on the
    # shipped version, with a line that blamed the folder.
    mark = an_update_that_leaves_a_mark(tmp_path)
    os.chmod(tmp_path / "updates" / "current.json", 0o600)
    before = os.umask(0o002)
    try:
        starter.proven(tmp_path, "9.9.9")
        assert stat.S_IMODE((tmp_path / "updates" / "current.json").stat().st_mode) == 0o600
        assert starter.active_update(tmp_path) is not None
        (tmp_path / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": "9.9.8", "previous_proven": True}), encoding="utf-8")
        assert starter.roll_back(tmp_path)
        assert stat.S_IMODE((tmp_path / "updates" / "current.json").stat().st_mode) == 0o600
        # And where an update is passed over, the line says which file and why, not "that folder".
        (tmp_path / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None}), encoding="utf-8")
        os.chmod(tmp_path / "updates" / "current.json", 0o664)
        assert starter.active_update(tmp_path, tell=True) is None
        said = capsys.readouterr().err
        assert "current.json can be written to by others" in said, said
    finally:
        os.umask(before)
    assert not mark.exists()


def test_going_back_that_cannot_be_written_down_is_said_and_ends_nothing(github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    github.publish("9.9.9", make_wheel("9.9.9"))
    update = updater(github, tmp_path)
    run(update.check())
    run(update.install())

    def no_room(data: Path) -> bool:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(starter, "roll_back", no_room)
    monkeypatch.setattr(starter.subprocess, "Popen", lambda command, **options: FakeChild(1))
    assert starter.supervise(["--data-dir", str(tmp_path)]) == 1  # the version stays, and its bad end is what is handed on
    assert "could not be written down" in capsys.readouterr().err and starter.active_update(tmp_path) is not None


def test_started_in_a_folder_that_is_gone_it_still_starts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def gone() -> str:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    assert starter._here() == ""


@pytest.mark.skipif(sys.platform == "win32", reason="on Windows a folder cannot be removed while a program is in it")
def test_started_in_a_folder_that_is_gone_with_a_data_folder_given_from_there_it_says_so(tmp_path: Path) -> None:
    # Started in a folder that is gone, it starts; with a data folder that is said from there ("data"), it
    # cannot, and said so with a page of Python's own: the line that tells where settings could not be kept
    # asked for the folder's full name, which a folder under one that is gone does not have.
    gone = tmp_path / "gone"
    gone.mkdir()
    env = {**os.environ, "PYTHONPATH": str(Path(starter.__file__).resolve().parent.parent)}
    env.pop(starter.CHILD, None)
    typed = 'cd "$1" && rmdir "$1" && exec "$2" -P -m qkvm --data-dir data --port 1 --bind local'
    done = subprocess.run(["sh", "-c", typed, "sh", str(gone), sys.executable], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 2, (done.returncode, done.stderr)
    assert "cannot keep settings in data" in done.stderr and "Traceback" not in done.stderr, done.stderr
