"""A stand-in for the two things the updater needs from GitHub: the newest release and its files."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import re
import socket
import zipfile
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response, StreamingResponse

from tests import ServerThread

DRIP = 4096  # bytes of the package at a time, where it comes slowly (FakeGitHub.drip)


def a_key() -> tuple[str, str]:
    """A release key of a test's own: (the private half as a key file holds it, the public half as it is built in)."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def with_key(update_py: bytes, public: str) -> bytes:
    """The program's `update.py` with `public` built in as the one key it takes releases from, in place of the publisher's.

    The program itself has the publisher's key built in, and no test has the other half of that. Where a
    test runs the program itself and has it install something, it runs a copy that trusts a key of the
    test's own: the same code, checking a signature in earnest.
    """
    text = update_py.decode("utf-8")
    line = re.compile(r"^RELEASE_KEYS: tuple\[str, \.\.\.\] = \(.*\)$", re.MULTILINE)
    assert len(line.findall(text)) == 1, "the line that holds the release keys is not where it was"
    return line.sub(f'RELEASE_KEYS: tuple[str, ...] = ("{public}",)', text).encode("utf-8")


def make_wheel(
    version: str = "9.9.9",
    *,
    declared: str | None = None,
    requires: tuple[str, ...] = ("fastapi>=0.110",),
    extra: dict[str, bytes] | None = None,
) -> bytes:
    """A release package: the files a real wheel of the program has, just a lot fewer of them."""
    files = {
        "qkvm/__init__.py": b"",
        "qkvm/_version.py": f'__version__ = "{declared or version}"\n'.encode(),
        "qkvm/cli.py": b"def main(argv=None):\n    return 0\n",
        "qkvm/static/index.html": b"<!doctype html><title>new</title>",
        f"qkvm-{version}.dist-info/METADATA": (
            f"Metadata-Version: 2.1\nName: qkvm\nVersion: {version}\nRequires-Python: >=3.11\n"
            + "".join(f"Requires-Dist: {r}\n" for r in requires)
        ).encode(),
        **(extra or {}),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class FakeGitHub:
    """Serves one repository ("owner/wall") whose newest release can be changed between requests."""

    repo = "owner/wall"

    def __init__(self) -> None:
        self.tag: str | None = None  # None: the repository has no releases
        self.notes = ""
        self.files: dict[str, bytes] = {}
        self.packages: dict[str, bytes] = {}  # what PyPI's file host holds, by its path there
        self.drip = 0.0  # seconds between the package's chunks of DRIP bytes, where it comes slowly (a slow line)
        self.answer_drip = 0.0  # ...and between the release's description's chunks of 32 bytes
        self.asked: list[str] = []  # the files asked for, in order
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        self._server = uvicorn.Server(uvicorn.Config(self._app(), log_level="error", access_log=False))
        self._serving = ServerThread("fake GitHub", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)

    def publish(
        self, version: str, wheel: bytes, *, notes: str = "", sums: bool = True, signed_by: str | None = None,
        libraries: list[tuple[str, bytes]] | None = None, targets: tuple[str, ...] | None = None, lock: bytes | None = None,
    ) -> None:  # fmt: skip
        """Make `version` the newest release, with a correct checksum list unless told otherwise.

        `signed_by`: the private half of a release key (as a key file holds it); the list is then signed with it.
        `libraries`: wheels (file name, bytes) the release lists in its lock, for `targets` (this Python's alone where not
        said), served at this stand-in as PyPI's file host lays them out; `lock`: a lock of the test's own instead.
        """
        name = f"qkvm-{version}-py3-none-any.whl"
        self.tag, self.notes, self.files = f"v{version}", notes, {name: wheel}
        if libraries is not None and lock is None:
            lock = self.lock(version, libraries, targets)
        if lock is not None:
            self.files[f"qkvm-{version}-libraries.json"] = lock
        if sums:
            self.files["SHA256SUMS"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {file}\n" for file, data in self.files.items()).encode()
        if signed_by is not None:
            key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(signed_by))
            self.files["SHA256SUMS.sig"] = base64.b64encode(key.sign(self.files["SHA256SUMS"])) + b"\n"

    def address(self, file: str, data: bytes) -> str:
        """Where PyPI's file host would keep `data` under the name `file` (its own layout: a hash in three parts), here."""
        digest = hashlib.blake2b(data, digest_size=32).hexdigest()
        path = f"/packages/{digest[:2]}/{digest[2:4]}/{digest[4:]}/{file}"
        self.packages[path] = data
        return self.url + path

    def lock(self, version: str, libraries: list[tuple[str, bytes]], targets: tuple[str, ...] | None = None) -> bytes:
        """A release's lock (as the release workflow writes it) of these wheels, for `targets`, each served here."""
        from packaging.utils import parse_wheel_filename

        from qkvm import _libraries

        entries: dict[str, dict[str, Any]] = {}
        for file, data in libraries:
            name, version_of, _build, _tags = parse_wheel_filename(file)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                unpacked = sum(member.file_size for member in archive.infolist() if not member.is_dir())
            entry = entries.setdefault(name, {"name": name, "version": str(version_of), "wheels": []})
            entry["wheels"].append({"file": file, "url": self.address(file, data), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "unpacked": unpacked})
        chosen = targets if targets is not None else (_libraries.target(),)
        return json.dumps({"format": 1, "version": version, "targets": {target: {"libraries": list(entries.values())} for target in chosen}}).encode()

    def _app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/packages/{a}/{b}/{c}/{file}")
        async def package(a: str, b: str, c: str, file: str) -> Response:
            path = f"/packages/{a}/{b}/{c}/{file}"
            self.asked.append(path)
            if path not in self.packages:
                return Response(status_code=404)
            return Response(self.packages[path], media_type="application/octet-stream")

        @app.get("/repos/owner/wall/releases/latest")
        async def latest() -> Any:
            if self.tag is None:
                return JSONResponse({"message": "Not Found"}, status_code=404)
            said = {
                "tag_name": self.tag,
                "body": self.notes,
                "html_url": f"{self.url}/owner/wall/releases/tag/{self.tag}",
                "published_at": "2026-10-01T12:00:00Z",
                "assets": [
                    {"name": name, "browser_download_url": f"{self.url}/download/{name}"} for name in self.files
                ],
            }
            if not self.answer_drip:
                return said
            text = json.dumps(said).encode()

            async def dripping() -> AsyncIterator[bytes]:
                for at in range(0, len(text), 32):
                    yield text[at : at + 32]
                    await asyncio.sleep(self.answer_drip)

            return StreamingResponse(dripping(), media_type="application/json")

        @app.get("/download/{name}")
        async def download(name: str) -> Response:
            self.asked.append(name)
            if name not in self.files:
                return Response(status_code=404)
            data = self.files[name]
            if self.drip and name.endswith(".whl"):

                async def dripping() -> AsyncIterator[bytes]:
                    for at in range(0, len(data), DRIP):
                        yield data[at : at + DRIP]
                        await asyncio.sleep(self.drip)

                return StreamingResponse(dripping(), media_type="application/octet-stream")
            return Response(data, media_type="application/octet-stream")

        return app

    def start(self) -> FakeGitHub:
        self._serving.start()
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._serving.join(timeout=10)
