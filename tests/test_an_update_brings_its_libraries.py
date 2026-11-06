"""An update that needs a newer pure-Python library and a newer native one than this computer has is installed in place,
runs with them, and is rolled back from with each version's set kept: real processes, a stand-in for GitHub and PyPI's
file host only (the owner's decisions of 2026-11-03; roadmap/design-updates-in-place.md, 3.15).

The two libraries are made here from what the test environment has, with no download and no compiler: a small library of
the tests' own at 2.0, and the installed google-crc32c repacked as 1.9.0.post1 (its native module, and on Linux the shared
library beside it). The new version is this tree's program, requiring both, in a release signed with a key of the test's
own whose lock points at the stand-in. Then the same under the starters of 0.2.0 and 0.2.2, kept as they shipped: an
in-app update never replaces the starter, and its code runs under the old one's loaded modules.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

import qkvm
from qkvm._version import __version__
from qkvm.update import Updater
from tests import libraries_kit as kit
from tests.fake_github import FakeGitHub, with_key
from tests.test_update_for_real import PASSWORD, SIGNING, TRUSTED, Running, later

PROGRAM = Path(qkvm.__file__).resolve().parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
NEEDS = (f"{kit.PURE}==2.0", f"{kit.NATIVE}==1.9.0.post1")


def needing(version: str, starts: bool = True) -> bytes:
    """This tree's program as `version`, requiring both libraries (and trusting the test's key); one that fails at its
    start where told so (it loads: the trial before it is named loads it)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(PROGRAM.rglob("*")):
            if file.is_dir() or "__pycache__" in file.parts:
                continue
            name = "qkvm/" + file.relative_to(PROGRAM).as_posix()
            data = file.read_bytes()
            if name == "qkvm/_version.py":
                data = f'__version__ = "{version}"\n'.encode()
            elif name == "qkvm/update.py":
                data = with_key(data, TRUSTED)
            elif name == "qkvm/cli.py" and not starts:
                data += b'\n\ndef main(*args, **kwargs):\n    raise RuntimeError("this version does not start")\n'
            archive.writestr(name, data)
        archive.writestr(
            f"qkvm-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: qkvm\nVersion: {version}\nRequires-Python: >=3.11\nRequires-Dist: fastapi>=0.110\n" + "".join(f"Requires-Dist: {need}\n" for need in NEEDS),
        )
    return buffer.getvalue()


LIBRARIES = [kit.pure("2.0"), kit.native("1.9.0.post1")]


def tree(folder: Path) -> dict[str, str]:
    """Every file of a version's folder by its hash (Python's caches aside): what is "untouched"."""
    return {path.relative_to(folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(folder.rglob("*")) if path.is_file() and "__pycache__" not in path.parts}


@pytest.fixture
def github() -> Iterator[FakeGitHub]:
    server = FakeGitHub().start()
    yield server
    server.stop()


def stopped(wall: Running) -> int | None:
    """`qkvm stop`, asked of the running wall by this tree's copy (an old starter's fixture has no program to ask with)."""
    kept = wall.env["PYTHONPATH"]
    wall.env["PYTHONPATH"] = str(PROGRAM.parent)
    try:
        return wall.stop()
    finally:
        wall.env["PYTHONPATH"] = kept


def own(wall: Running) -> list[str]:
    view = wall.browser.get("/api/v1/update").json()
    return sorted(view["own_libraries"])


@pytest.mark.skipif(os.environ.get("QKVM_CONTAINER") == "1", reason="a container is replaced, never updated in place, and its /tmp runs nothing")
def test_an_update_needing_newer_libraries_is_installed_in_place_runs_them_and_is_rolled_back_from(github: FakeGitHub, tmp_path: Path) -> None:
    wall, newer, broken = Running(tmp_path, github), later(1), later(2)
    wall.env["QKVM_UPDATE_FILES"] = github.url
    try:
        wall.start()
        assert wall.version(__version__) == __version__
        assert wall.sign_in() == 200
        github.publish(newer, needing(newer), signed_by=SIGNING, libraries=LIBRARIES)
        found = wall.browser.post("/api/v1/update/check").json()
        assert found["in_place"] is True and sorted(found["libraries"]["fetch"]) == [f"{kit.NATIVE} 1.9.0.post1", f"{kit.PURE} 2.0"], found
        taken = wall.browser.post("/api/v1/update/install", json={"password": PASSWORD})
        assert taken.status_code == 200 and taken.json()["restarting"] is True, taken.text
        assert wall.version(newer) == newer  # the restart runs the new version (its start check passed: both found at those versions),
        assert wall.sign_in() == 200
        assert own(wall) == [f"{kit.NATIVE} 1.9.0.post1", f"{kit.PURE} 2.0"]  # from its own folder,
        folder = wall.data / "updates" / newer
        assert (folder / "lib" / "qkvm_proof_pure" / "__init__.py").is_file() and [path for path in (folder / "lib" / "google_crc32c").iterdir() if path.suffix in (".pyd", ".so")]
        entries = [json.loads(line) for line in (wall.data / "audit.log").read_text(encoding="utf-8").splitlines() if '"update_installed"' in line]
        assert [entry["libraries"] for entry in entries] == [[f"{kit.PURE} 2.0", f"{kit.NATIVE} 1.9.0.post1"]], entries  # (its activity entry names them)
        before = tree(folder)

        # A version that dies at its start is installed like any other, its libraries copied from the running version's
        # folder (nothing fetched again), and gone back from: the version before it, with its own set, untouched.
        asked = len(github.asked)
        github.publish(broken, needing(broken, starts=False), signed_by=SIGNING, libraries=LIBRARIES)
        assert wall.browser.post("/api/v1/update/check").json()["libraries"]["fetch"] == []
        taken = wall.browser.post("/api/v1/update/install", json={"password": PASSWORD})
        assert taken.status_code == 200, taken.text
        assert not [path for path in github.asked[asked:] if path.startswith("/packages/")]
        time.sleep(3)
        assert wall.version(newer) == newer
        assert tree(folder) == before and (wall.data / "updates" / broken / "lib" / "qkvm_proof_pure").is_dir()
        assert wall.stop() == 0

        # And back by hand to the copy that was installed, with the computer's own libraries.
        back = subprocess.run([*wall.command, "--roll-back", "--data-dir", str(wall.data)], env=wall.env, cwd=tmp_path, capture_output=True, text=True, timeout=60)
        assert back.returncode == 0 and "Back on the previous version" in back.stdout, back
        subprocess.run([*wall.command, "--roll-back", "--data-dir", str(wall.data)], env=wall.env, cwd=tmp_path, capture_output=True, timeout=60)
        wall.start()
        assert wall.version(__version__) == __version__
        assert wall.sign_in() == 200 and own(wall) == []
    finally:
        wall.stop()
        wall.browser.close()


def installed_here(github: FakeGitHub, data: Path, version: str, current: str) -> None:
    """Install `version` into `data` with this tree's updater (what a wall of this version does), in this process."""
    github.publish(version, needing(version), signed_by=SIGNING, libraries=LIBRARIES)
    update = Updater(data, github.repo, api=github.url, keys=(TRUSTED,), current=current, files=github.url)
    asyncio.run(update.check())
    assert update.in_place is True, update.view()
    assert asyncio.run(update.install()) == version


@pytest.mark.skipif(os.environ.get("QKVM_CONTAINER") == "1", reason="a container is replaced, never updated in place, and its /tmp runs nothing")
@pytest.mark.parametrize("old", ["0.2.0", "0.2.2"])
def test_under_the_starters_already_out_there_the_libraries_are_put_in_place_and_a_version_that_cannot_steps_back(github: FakeGitHub, tmp_path: Path, old: str) -> None:
    first, second = later(1), later(2)
    wall = Running(tmp_path, github)
    wall.env["PYTHONPATH"] = str(FIXTURES / f"starter-{old}")  # (the copy pip installed: that version's starter, and nothing else of it)
    wall.env["PYTHONDONTWRITEBYTECODE"] = "1"
    installed_here(github, wall.data, first, __version__)
    try:
        wall.start()
        assert wall.version(first) == first
        assert wall.sign_in() == 200 and own(wall) == [f"{kit.NATIVE} 1.9.0.post1", f"{kit.PURE} 2.0"]
        assert stopped(wall) == 0

        # The next version, whose libraries were brought for another Python (one upgraded under it): it steps back by itself
        # with 75, which that starter takes for "start me again", and the version before it runs, with its own set.
        installed_here(github, wall.data, second, first)
        note = wall.data / "updates" / second / "libraries.json"
        note.write_text(json.dumps({**json.loads(note.read_text(encoding="utf-8")), "target": "cp39-linux-armv7l"}), encoding="utf-8")
        before = tree(wall.data / "updates" / first)
        wall.start()
        assert wall.version(first) == first
        said = (wall.data / "qkvm.log").read_text(encoding="utf-8", errors="replace")
        assert f"version {second} is not started on this computer: its libraries were brought for cp39-linux-armv7l" in said, said[-2000:]
        assert json.loads((wall.data / "updates" / "current.json").read_text(encoding="utf-8"))["version"] == first
        assert wall.sign_in() == 200 and own(wall) == [f"{kit.NATIVE} 1.9.0.post1", f"{kit.PURE} 2.0"]
        assert tree(wall.data / "updates" / first) == before
    finally:
        stopped(wall)
        wall.browser.close()


@pytest.mark.skipif(os.environ.get("QKVM_CONTAINER") == "1", reason="a container is replaced, never updated in place, and its /tmp runs nothing")
def test_this_versions_starter_passes_over_libraries_brought_for_another_python(github: FakeGitHub, tmp_path: Path) -> None:
    first = later(1)
    data = tmp_path / "data"
    installed_here(github, data, first, __version__)
    note = data / "updates" / first / "libraries.json"
    note.write_text(json.dumps({**json.loads(note.read_text(encoding="utf-8")), "target": "cp39-linux-armv7l"}), encoding="utf-8")
    environment = {**os.environ, "PYTHONPATH": str(PROGRAM.parent)}
    environment.pop("QKVM_CHILD", None)
    said = subprocess.run([sys.executable, "-P", "-m", "qkvm", "--version", "--data-dir", str(data)], env=environment, capture_output=True, text=True, timeout=60)
    assert said.stdout.strip() == f"qkvm {__version__}"
    from qkvm import __main__ as starter

    assert starter.active_update(data, tell=True) is None
    assert "names libraries for cp39-linux-armv7l, and this Python is" in starter.TOLD[-1]
