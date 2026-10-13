"""The update with the program itself: real processes and a real package of the program, a stand-in for GitHub only.

The other tests of the update hand the updater a package of five files and stand in for the wall with
something that returns a number. Here the program is copied to a folder as an installed copy lies in one,
started as `python -P -m qkvm` (the starter, which runs the wall proper as its child), told where to ask
for releases with the two environment variables it has for that, and sent the requests the page sends:
a newer version is seen, installed, started into with the settings as they were; and one that does not
start is gone back from.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

import qkvm
from qkvm._version import __version__
from tests.fake_github import FakeGitHub, a_key, with_key
from tests.test_wall import CSRF, closed_port

PROGRAM = Path(qkvm.__file__).resolve().parent
PASSWORD = "a wall only for this test 7"
# The copy that is run here takes releases signed with this key, built into it in place of the publisher's
# (whose other half nobody but the publisher has): every release below is signed in earnest, or refused.
SIGNING, TRUSTED = a_key()
SOMEBODY_ELSES, _ = a_key()


def later(by: int) -> str:
    major, minor, patch = (int(part) for part in __version__.split("."))
    return f"{major}.{minor}.{patch + by}"


def a_release(version: str, starts: bool = True) -> bytes:
    """A package of this very program, saying it is `version`; one that does not start, where told so."""
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
                data = with_key(data, TRUSTED)  # (the version after this one trusts the same key: it installs the next)
            elif name == "qkvm/cli.py" and not starts:
                data = b'raise RuntimeError("this version does not start")\n'
            archive.writestr(name, data)
        archive.writestr(f"qkvm-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: qkvm\nVersion: {version}\nRequires-Python: >=3.11\nRequires-Dist: fastapi>=0.110\n")
    return buffer.getvalue()


class Running:
    """An installed copy of the program, its data folder, and the process that runs it."""

    def __init__(self, folder: Path, github: FakeGitHub) -> None:
        self.folder, self.data, self.port = folder, folder / "data", closed_port()
        shutil.copytree(PROGRAM, folder / "installed" / "qkvm", ignore=shutil.ignore_patterns("__pycache__"))
        built = folder / "installed" / "qkvm" / "update.py"
        built.write_bytes(with_key(built.read_bytes(), TRUSTED))
        self.env = {**os.environ, "PYTHONPATH": str(folder / "installed"), "QKVM_UPDATE_API": github.url, "QKVM_UPDATE_REPO": github.repo}
        for name in ("QKVM_CHILD", "QKVM_CONTAINER", "QKVM_UNLOCK_FILE"):
            self.env.pop(name, None)
        self.command = [sys.executable, "-P", "-m", "qkvm"]
        self.browser = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", headers=CSRF, timeout=60)
        self.process: subprocess.Popen[bytes] | None = None
        self.options: list[str] = []  # what it is started with, beside where it keeps its data and listens

    def start(self) -> None:
        self.terminal = open(self.folder / "terminal.txt", "ab")
        # (Started as anybody starts it. With a key built in, nothing it could be started with lets an unsigned release in.)
        asked = [*self.command, "--data-dir", str(self.data), "--port", str(self.port), "--bind", "local", *self.options]
        self.process = subprocess.Popen(asked, cwd=self.folder, env=self.env, stdout=subprocess.DEVNULL, stderr=self.terminal, stdin=subprocess.DEVNULL)

    def version(self, wanted: str, within: float = 90.0) -> str:
        seen, until = "nothing answers", time.monotonic() + within
        while time.monotonic() < until:
            try:
                seen = self.browser.get("/healthz", timeout=3).json()["version"]
                if seen == wanted:
                    return seen
            except (httpx.HTTPError, ValueError, KeyError):
                seen = "nothing answers"
            if self.process is not None and self.process.poll() is not None:
                return f"the starter ended with {self.process.returncode}"
            time.sleep(0.3)
        return seen

    def stop(self) -> int | None:
        if self.process is None:
            return None
        try:
            subprocess.run([*self.command, "stop", "--data-dir", str(self.data)], cwd=self.folder, env=self.env, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            pass  # asked, and not answered in time (a machine with no processor to spare): what follows ends it all the same
        try:
            status: int | None = self.process.wait(40)
        except subprocess.TimeoutExpired:
            self.process.kill()
            status = None
        self.terminal.close()
        self.process = None
        return status

    def sign_in(self) -> int:
        self.browser.cookies.clear()
        path = "/api/v1/login" if self.browser.get("/api/v1/session").json().get("initialized") else "/api/v1/setup"
        return self.browser.post(path, json={"password": PASSWORD}).status_code

    def take(self, github: FakeGitHub, version: str, starts: bool = True, signed_by: str | None = SIGNING) -> httpx.Response:
        github.publish(version, a_release(version, starts), signed_by=signed_by)
        assert self.browser.post("/api/v1/update/check").json()["latest"]["version"] == version
        return self.browser.post("/api/v1/update/install", json={"password": PASSWORD})


@pytest.fixture
def github() -> Iterator[FakeGitHub]:
    server = FakeGitHub().start()
    yield server
    server.stop()


def test_a_release_is_installed_from_the_page_and_one_that_does_not_start_is_gone_back_from(github: FakeGitHub, tmp_path: Path) -> None:
    wall, newer, broken = Running(tmp_path, github), later(1), later(2)
    try:
        wall.start()
        assert wall.version(__version__) == __version__
        assert wall.sign_in() == 200
        added = wall.browser.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "password": "secret", "name": "A KVM", "kind": "kvmd", "force": True})
        assert added.status_code == 201, added.text

        # Signed by nobody, or by somebody else: not installed, and said why. The program runs on as it was.
        nobodys = wall.take(github, newer, signed_by=None)
        assert nobodys.status_code != 200 and "not signed" in nobodys.json()["message"], nobodys.text
        strangers = wall.take(github, newer, signed_by=SOMEBODY_ELSES)
        assert strangers.status_code != 200 and "not signed by a trusted key" in strangers.json()["message"], strangers.text
        assert not (wall.data / "updates" / newer).exists() and wall.version(__version__) == __version__

        taken = wall.take(github, newer)
        assert taken.status_code == 200 and taken.json()["restarting"] is True, taken.text
        assert wall.version(newer) == newer  # the starter runs the new version,
        assert wall.sign_in() == 200  # with the same password,
        assert [tile["name"] for tile in wall.browser.get("/api/v1/wall").json()["devices"]] == ["A KVM"]  # and the settings as they were,
        assert wall.browser.get("/healthz").json()["locked"] is False  # opened by themselves.
        pointer = json.loads((wall.data / "updates" / "current.json").read_text(encoding="utf-8"))
        assert pointer["version"] == newer and (wall.data / "updates" / newer / "qkvm" / "cli.py").exists()
        assert hashlib.sha256((wall.data / "updates" / newer / "qkvm" / "_version.py").read_bytes()).hexdigest() != hashlib.sha256((PROGRAM / "_version.py").read_bytes()).hexdigest()

        taken = wall.take(github, broken, starts=False)  # installed like any other: whether it starts is found out by starting it
        assert taken.status_code == 200, taken.text
        time.sleep(3)  # (the answer is given a second before the program leaves)
        assert wall.version(newer) == newer  # it does not start, and the starter goes back to the version before:
        said = [line for line in (wall.data / "qkvm.log").read_text(encoding="utf-8", errors="replace").splitlines() if "going back to the previous one" in line]
        assert len(said) == 1 and broken in said[0], said
        assert wall.sign_in() == 200
        assert [tile["name"] for tile in wall.browser.get("/api/v1/wall").json()["devices"]] == ["A KVM"]
        assert wall.stop() == 0
    finally:
        wall.stop()
        wall.browser.close()
