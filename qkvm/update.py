"""Checking for a newer release on GitHub and installing it.

A release is a GitHub release tagged v<version> with these files attached:

    qkvm-<version>-py3-none-any.whl    the program
    SHA256SUMS                             "<sha256>  <file name>" for the wheel
    SHA256SUMS.sig                         Ed25519 signature of SHA256SUMS, base64 (optional)

An update is never unpacked over the running program. It goes into the data folder
(updates/<version>/) and python -m qkvm puts it in front of the files it shipped
with on the next start. The previous version stays on disk, so going back is one step.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import importlib.metadata
import io
import json
import logging
import os
import platform
import re
import shutil
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.markers import UndefinedComparison
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ._version import __version__
from .kvm import public_context

log = logging.getLogger("qkvm")

GITHUB_API = "https://api.github.com"
# "owner/name" of the GitHub repository releases are published in. Empty: updates are off.
# Only set this to a repository you control - whoever can publish a release there can
# run code on every machine that installs it.
DEFAULT_REPO = "qkvm/qkvm"
# Ed25519 public keys (base64) allowed to sign releases; make one with
# `python -m qkvm.release keygen`. A copy in which this is empty installs no update by itself
# (or, started with --allow-unsigned-updates, one checked against its checksum only, which
# catches a broken download but not a tampered release). With a key here, a release is
# installed only if one of these signed it, whatever the program was started with.
# The first is the publisher's, made on 2026-10-12. A fork that publishes its own releases
# puts its own key here in its place.
RELEASE_KEYS: tuple[str, ...] = ("R9V9vqrwqFnxx4j6mf0ZSG7Af5PTFILqZd1Qc6F1JpI=",)

PACKAGE = "qkvm"
MAX_WHEEL = 30_000_000  # bytes; the real thing is well under one megabyte
MAX_UNPACKED = 60_000_000
MAX_MEMBERS = 2000  # files in a package; this program is some fifty
MAX_HOPS = 5  # times a download may be sent on to another address
MAX_ANSWER = 1_000_000  # bytes of what GitHub says about a release; it is a few thousand
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")


class UpdateError(Exception):
    """An update could not be found, trusted or installed. The message is fit to show."""


@dataclass(frozen=True)
class Release:
    version: str
    notes: str
    url: str  # the release's page, for reading more
    published: str
    wheel_name: str
    wheel_url: str
    sums_url: str | None
    signature_url: str | None


def parse_version(text: str) -> tuple[int, ...]:
    """'v1.2.3' or '1.2' -> (1, 2, 3) / (1, 2, 0). Anything else (pre-releases included) raises ValueError."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", text.strip())
    if not match:
        raise ValueError(f"not a release version: {text!r}")
    return tuple(int(part or 0) for part in match.groups())


def verify_signature(data: bytes, signature: bytes, keys: tuple[str, ...]) -> None:
    """Raise UpdateError unless one of `keys` signed `data`."""
    try:
        raw = base64.b64decode(signature.strip(), validate=True)
    except binascii.Error:
        raise UpdateError("The release's signature is not readable") from None
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(raw, data)
            return
        except (InvalidSignature, ValueError):
            continue
    raise UpdateError("The release is not signed by a trusted key")


def _checksum_for(sums: bytes, name: str) -> str:
    for line in sums.decode("utf-8", "replace").splitlines():
        digest, _, listed = line.strip().partition(" ")
        if listed.strip().lstrip("*") == name and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            return digest.lower()
    raise UpdateError("The release's checksum list does not cover the download")


def _check_requirements(metadata: str) -> None:
    """An update replaces only this program: the installed Python and active dependencies must already satisfy it."""
    use_pip = "Install the new version with pip instead: pip install --upgrade qkvm"
    headers = Parser().parsestr(metadata)
    if headers.defects or len(headers.get_all("Requires-Python", [])) > 1:
        raise UpdateError(f"The release has invalid dependency metadata. {use_pip}")
    # Core metadata permits folded headers; the package description after the blank line is not metadata.
    def unfolded(value: str) -> str:
        return " ".join(value.splitlines()).strip()

    try:
        python_spec = SpecifierSet(unfolded(headers.get("Requires-Python", "")))
        python_version = Version(platform.python_version())
        if not python_spec.contains(python_version, prereleases=True):
            raise UpdateError(f"This version needs Python {python_spec}; this copy runs {python_version}. {use_pip}")
        for value in headers.get_all("Requires-Dist", []):
            requirement = Requirement(unfolded(value))
            # The app installs no optional extras. Evaluate the whole marker: a literal substring such as
            # 'extra ==' may be only one branch of a condition that still applies to the base installation.
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            if requirement.url or requirement.extras:
                # A name/version cannot prove the origin of a direct URL, or that an extra's dependencies
                # are installed. Leave those installations to pip instead of accepting incomplete proof.
                raise UpdateError(f"This version needs an installation of '{requirement.name}' that the in-app updater cannot verify. {use_pip}")
            try:
                installed = Version(importlib.metadata.version(requirement.name))
            except importlib.metadata.PackageNotFoundError:
                raise UpdateError(f"This version needs the Python package '{requirement.name}', which is not installed. {use_pip}") from None
            if not requirement.specifier.contains(installed, prereleases=True):
                raise UpdateError(f"This version needs '{requirement.name}{requirement.specifier}'; installed is {installed}. {use_pip}")
    except (InvalidRequirement, InvalidSpecifier, InvalidVersion, UndefinedComparison, KeyError, RecursionError):
        raise UpdateError(f"The release's dependency requirements could not be verified. {use_pip}") from None


def check_startup_requirements(package: Path, version: str) -> None:
    """Check the selected package before it opens settings, including updates installed by an older updater."""
    # An in-app update changes qkvm.__path__, not sys.path: looking up qkvm through importlib.metadata
    # would find the original installation's requirements. Read the metadata beside the code being run.
    # A source checkout or editable install has no metadata beside its source package and is left alone.
    metadata_dir = package.parent / f"{PACKAGE}-{version}.dist-info"
    try:
        metadata = (metadata_dir / "METADATA").read_text(encoding="utf-8")
    except FileNotFoundError:
        if not metadata_dir.exists():
            return
        raise UpdateError("This copy is missing its package metadata. Reinstall it with: pip install --upgrade qkvm") from None
    except (OSError, UnicodeError):
        raise UpdateError("This copy's package metadata could not be read. Reinstall it with: pip install --upgrade qkvm") from None
    headers = Parser().parsestr(metadata)
    try:
        valid = (
            not headers.defects
            and len(headers.get_all("Name", [])) == 1
            and headers["Name"].strip().lower() == PACKAGE
            and len(headers.get_all("Version", [])) == 1
            and Version(headers["Version"].strip()) == Version(version)
        )
    except InvalidVersion:
        valid = False
    if not valid:
        raise UpdateError("This copy's package metadata does not match its code. Reinstall it with: pip install --upgrade qkvm")
    _check_requirements(metadata)


def _write_private(path: Path, data: bytes) -> None:
    """Replace an update file atomically with an owner-only file, regardless of the caller's umask."""
    descriptor, name = tempfile.mkstemp(prefix=".qkvm-update-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def unpack(wheel: bytes, version: str, destination: Path) -> None:
    """Unpack a release wheel into `destination`, refusing anything that is not what a release looks like."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(wheel))
    except zipfile.BadZipFile:
        raise UpdateError("The download is not a valid package") from None
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > MAX_MEMBERS or sum(m.file_size for m in members) > MAX_UNPACKED:
            raise UpdateError("The package is larger than expected")
        for member in members:
            parts = member.filename.split("/")
            inside = parts[0] == PACKAGE or parts[0].endswith(".dist-info")
            # No absolute paths, no climbing out, no drive letters, nothing outside the two known folders.
            if not inside or "" in parts or ".." in parts or "\\" in member.filename or ":" in member.filename:
                raise UpdateError("The package contains files it should not")
            # And no name that Windows takes for another one ("cli.py." is cli.py there): written after the
            # file that was checked, it would take its place.
            if any(part != part.rstrip(". ") for part in parts):
                raise UpdateError("The package contains files it should not")
        names = {m.filename for m in members}
        if len({name.lower() for name in names}) != len(members):  # the same name twice, or twice but for its capitals
            raise UpdateError("The package contains files it should not")
        if f"{PACKAGE}/cli.py" not in names or f"{PACKAGE}/_version.py" not in names:
            raise UpdateError("The package is not this program")
        declared = re.search(r'__version__\s*=\s*"([^"]+)"', archive.read(f"{PACKAGE}/_version.py").decode("utf-8", "replace"))
        if declared is None or parse_version(declared.group(1)) != parse_version(version):
            raise UpdateError("The package is not the version the release says it is")
        metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise UpdateError("The package must contain exactly one dependency metadata file")
        _check_requirements(archive.read(metadata[0]).decode("utf-8", "replace"))

        staging = destination.with_name(destination.name + ".tmp")
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(mode=0o700)
        for member in members:
            parts = member.filename.split("/")
            parent = staging
            for part in parts[:-1]:
                parent = parent / part
                parent.mkdir(mode=0o700, exist_ok=True)
            _write_private(parent / parts[-1], archive.read(member))
    shutil.rmtree(destination, ignore_errors=True)
    staging.rename(destination)


class Updater:
    def __init__(
        self,
        data_dir: Path,
        repo: str | None = None,
        *,
        api: str = GITHUB_API,
        keys: tuple[str, ...] | None = None,
        current: str = __version__,
        allow_unsigned: bool = False,
    ) -> None:
        repo = DEFAULT_REPO if repo is None else repo
        if repo and not REPO.fullmatch(repo):
            raise ValueError(f"not a GitHub repository (owner/name): {repo!r}")
        self.directory = data_dir / "updates"
        self.repo = repo
        self.api = api.rstrip("/")
        self.keys = RELEASE_KEYS if keys is None else keys
        # Without a release key a checksum only shows that the download is complete, not who made it.
        # Installing on that basis has to be asked for when the program is started.
        self.allow_unsigned = allow_unsigned
        self.current = current
        self.state = "idle"  # idle | checking | installing | ready | failed
        self.error: str | None = None
        self.latest: Release | None = None
        self.checked_at: float | None = None
        self.installed: str | None = None  # the version waiting for a restart
        self._running = False  # one check or install at a time (a plain flag: this object outlives event loops)

    @property
    def available(self) -> bool:
        """Is the newest release newer than what is running (and not already installed)?"""
        if self.latest is None or self.installed == self.latest.version:
            return False
        return parse_version(self.latest.version) > parse_version(self.current)

    def view(self) -> dict[str, Any]:
        latest = self.latest
        return {
            "current": self.current,
            "repo": self.repo,
            "state": self.state,
            "error": self.error,
            "checked_ago": None if self.checked_at is None else max(0, round(time.time() - self.checked_at)),
            "available": self.available,
            "installed": self.installed,
            "signed": bool(self.keys),
            "installable": bool(self.keys) or self.allow_unsigned,
            "latest": latest
            and {"version": latest.version, "notes": latest.notes, "url": latest.url, "published": latest.published},
        }

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=await public_context(),
            timeout=httpx.Timeout(20.0, connect=8.0),
            # GitHub hands downloads over to its file servers. Followed by hand (see _fetch): left to the HTTP
            # library, the whole of every answer on the way is read, and unpacked, before any limit is asked.
            follow_redirects=False,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"qkvm/{self.current}",
                "Accept-Encoding": "identity",  # as it is: see _fetch
            },
        )

    def _trusted(self, url: str) -> bool:
        """Downloads are only followed to GitHub itself (or, in tests, to the stand-in server)."""
        parts = urlsplit(url)
        if self.api == GITHUB_API:
            return parts.scheme == "https" and parts.hostname == "github.com"
        return f"{parts.scheme}://{parts.netloc}" == self.api

    def _release(self, data: dict[str, Any]) -> Release | None:
        try:
            version = ".".join(str(part) for part in parse_version(str(data["tag_name"])))
        except ValueError:
            return None  # a tag that is not a plain version: not something to offer
        assets = {str(a["name"]): str(a["browser_download_url"]) for a in data.get("assets", [])}
        wheel = next((n for n in assets if n.startswith(f"{PACKAGE}-") and n.endswith(".whl")), None)
        if wheel is None or not all(self._trusted(url) for url in assets.values()):
            return None
        return Release(
            version=version,
            notes=str(data.get("body") or "")[:20_000],
            url=str(data.get("html_url") or ""),
            published=str(data.get("published_at") or ""),
            wheel_name=wheel,
            wheel_url=assets[wheel],
            sums_url=assets.get("SHA256SUMS"),
            signature_url=assets.get("SHA256SUMS.sig"),
        )

    async def check(self) -> None:
        """Ask GitHub for the newest release. Raises UpdateError when that fails."""
        if not self.repo:
            raise UpdateError("No release repository is set, so there is nowhere to look for updates")
        self._begin("checking")
        try:
            async with await self._client() as client:
                status, said = await self._fetch(client, f"{self.api}/repos/{self.repo}/releases/latest", MAX_ANSWER)
            if status == 404:
                self.latest = None  # the repository has no releases yet
            elif status != 200:
                raise UpdateError(f"GitHub answered with an error ({status})")
            else:
                self.latest = self._release(json.loads(said))
        except UpdateError as ex:
            self._failed(ex)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            self._failed(UpdateError("GitHub could not be reached"))
        finally:
            self._running = False
        self.checked_at = time.time()
        self.state = "idle"

    def _begin(self, state: str) -> None:
        if self._running:
            raise UpdateError("An update check or installation is already under way")
        self._running = True
        self.state, self.error = state, None

    def _failed(self, error: UpdateError) -> None:
        self.state, self.error = "failed", str(error)
        log.warning("update: %s", error)
        raise error

    async def _fetch(self, client: httpx.AsyncClient, url: str, limit: int) -> tuple[int, bytes]:
        """What is at `url`: (the status it was answered with, at most `limit` bytes of what came).

        Read as it is sent, and it is asked for unpacked (see _client). The HTTP library would unpack what
        comes packed all the same, all of it, before any of it could be counted: so that is not taken at all.
        """
        chunks: list[bytes] = []
        size = 0
        ask = client.build_request("GET", url)
        for _ in range(MAX_HOPS + 1):
            try:
                reply = await client.send(ask, stream=True)
            except httpx.InvalidURL:  # (the library's error for a "Location" that is no address; none of its usual ones)
                raise UpdateError("The download was sent on to an address that is none") from None
            try:
                if reply.next_request is not None:
                    if url.startswith("https://") and reply.next_request.url.scheme != "https":
                        raise UpdateError("The download was sent on to an address that is not HTTPS")
                    ask = reply.next_request  # sent on: what this answer itself holds is not read at all
                    continue
                if reply.headers.get("content-encoding", "").strip().lower() not in ("", "identity"):
                    raise UpdateError("The download came packed, which was not asked for")
                async for chunk in reply.aiter_raw():
                    size += len(chunk)
                    if size > limit:
                        raise UpdateError("The download is larger than expected")
                    chunks.append(chunk)
                return reply.status_code, b"".join(chunks)
            finally:
                await reply.aclose()
        raise UpdateError("The download was sent on from place to place too many times")

    async def _download(self, client: httpx.AsyncClient, url: str, limit: int) -> bytes:
        status, data = await self._fetch(client, url, limit)
        if status != 200:
            raise UpdateError(f"The download failed ({status})")
        return data

    async def install(self) -> str:
        """Download the newest release, check it, and make it the version used from the next start.

        Returns the version installed. The running program is not touched.
        """
        release = self.latest
        if release is None or not self.available:
            raise UpdateError("There is no newer version to install")
        self._begin("installing")
        try:
            if not self.keys and not self.allow_unsigned:
                raise UpdateError(
                    "This copy has no release key built in, so it cannot tell who published an update and "
                    "does not install one by itself. Install the new version by hand, or start qKVM with "
                    "--allow-unsigned-updates."
                )
            if release.sums_url is None:
                raise UpdateError("The release has no checksums, so the download cannot be verified")
            async with await self._client() as client:
                sums = await self._download(client, release.sums_url, 64_000)
                if self.keys:
                    if release.signature_url is None:
                        raise UpdateError("The release is not signed")
                    verify_signature(sums, await self._download(client, release.signature_url, 4_000), self.keys)
                wheel = await self._download(client, release.wheel_url, MAX_WHEEL)
            if hashlib.sha256(wheel).hexdigest() != _checksum_for(sums, release.wheel_name):
                raise UpdateError("The download does not match its checksum")
            await asyncio.to_thread(self._activate, release.version, wheel)
        except UpdateError as ex:
            self._failed(ex)
        except httpx.HTTPError:
            self._failed(UpdateError("The download was interrupted"))
        except (OSError, ValueError, zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError) as ex:
            # (A package that passed its checksum and is broken inside all the same: said like any other failure.)
            self._failed(UpdateError(f"The update could not be unpacked: {ex}"))
        finally:
            self._running = False
        self.installed = release.version
        self.state = "ready"
        log.warning("update: version %s installed, taking effect at the next start", release.version)
        return release.version

    def _activate(self, version: str, wheel: bytes) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            self.directory.chmod(0o700)
        unpack(wheel, version, self.directory / version)
        pointer = self.directory / "current.json"
        try:
            before = json.loads(pointer.read_text(encoding="utf-8"))
            previous, ran = before.get("version"), before.get("proven") is True
        except (OSError, ValueError, AttributeError, RecursionError):
            previous, ran = None, False
        if not isinstance(previous, str):
            previous, ran = None, False  # (what is written below is a version's name or nothing: never whatever stood there)
        # (Whether the one before got through its first half minute is kept with it: the starter goes back to
        # it as a version that ran, or as one that is still on trial. See __main__.roll_back.)
        _write_private(pointer, json.dumps({"version": version, "previous": previous, "previous_proven": ran}).encode("utf-8"))
        # Keep the new version and the one to fall back to; older ones only take up space.
        for entry in self.directory.iterdir():
            if entry.is_dir() and entry.name not in (version, previous):
                shutil.rmtree(entry, ignore_errors=True)
