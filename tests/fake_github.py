"""A stand-in for the two things the updater needs from GitHub: the newest release and its files."""

from __future__ import annotations

import base64
import hashlib
import io
import re
import socket
import threading
import time
import zipfile
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response


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
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        self._server = uvicorn.Server(uvicorn.Config(self._app(), log_level="error", access_log=False))
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def publish(self, version: str, wheel: bytes, *, notes: str = "", sums: bool = True, signed_by: str | None = None) -> None:
        """Make `version` the newest release, with a correct checksum list unless told otherwise.

        `signed_by`: the private half of a release key (as a key file holds it); the list is then signed with it.
        """
        name = f"qkvm-{version}-py3-none-any.whl"
        self.tag, self.notes, self.files = f"v{version}", notes, {name: wheel}
        if sums:
            self.files["SHA256SUMS"] = f"{hashlib.sha256(wheel).hexdigest()}  {name}\n".encode()
        if signed_by is not None:
            key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(signed_by))
            self.files["SHA256SUMS.sig"] = base64.b64encode(key.sign(self.files["SHA256SUMS"])) + b"\n"

    def _app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/repos/owner/wall/releases/latest")
        async def latest() -> Any:
            if self.tag is None:
                return JSONResponse({"message": "Not Found"}, status_code=404)
            return {
                "tag_name": self.tag,
                "body": self.notes,
                "html_url": f"{self.url}/owner/wall/releases/tag/{self.tag}",
                "published_at": "2026-10-01T12:00:00Z",
                "assets": [
                    {"name": name, "browser_download_url": f"{self.url}/download/{name}"} for name in self.files
                ],
            }

        @app.get("/download/{name}")
        async def download(name: str) -> Response:
            if name not in self.files:
                return Response(status_code=404)
            return Response(self.files[name], media_type="application/octet-stream")

        return app

    def start(self) -> FakeGitHub:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake GitHub did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
