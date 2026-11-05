"""Checking for a newer release on GitHub and installing it.

A release is a GitHub release tagged v<version> with these files attached:

    qkvm-<version>-py3-none-any.whl    the program
    qkvm-<version>-libraries.json      the exact wheels of every library it runs, for each Python and system (_libraries)
    SHA256SUMS                             "<sha256>  <file name>" for the wheel, the libraries' list (and more)
    SHA256SUMS.sig                         Ed25519 signature of SHA256SUMS, base64 (optional)

An update is never unpacked over the running program. It goes into the data folder
(updates/<version>/) and python -m qkvm puts it in front of the files it shipped
with on the next start. The previous version stays on disk, so going back is one step.

Where the release lists its libraries, the new version brings those it needs into updates/<version>/lib (fetched from
PyPI's file host by the address and hash the signed list names, or copied from the running version's folder), is tried
in a throwaway process, and only then named: it runs exactly the libraries its release was tested with (_libs.py puts
them in place at its start). A release without such a list is taken only where this computer's libraries satisfy it.
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
import shlex
import shutil
import secrets
import subprocess
import sys
import time
import zipfile
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.markers import UndefinedComparison
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from . import _libraries, _libs
from ._folders import open_private, own_folder
from ._version import __version__
from .kvm import public_context
from .store import _settle

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
# What updates a copy that runs in a container, as the README says it: with compose, and without (then the container is
# removed and run again). Said by the server, not written into the page: the page is the demo's too, which names no image.
IMAGE_COMMANDS = ("docker compose pull && docker compose up -d", "docker pull qkvm/qkvm")
MAX_WHEEL = 30_000_000  # bytes; the real thing is well under one megabyte
MAX_UNPACKED = 60_000_000
MAX_MEMBERS = 2000  # files in a package; this program is some fifty
MAX_HOPS = 5  # times a download may be sent on to another address
MAX_ANSWER = 1_000_000  # bytes of what GitHub says about a release; it is a few thousand
JUDGE_WITHIN = 120.0  # seconds a release's judging may take, its package's download with it (see Updater._judge)
TRIAL_WITHIN = 300.0  # seconds the trial of a new version may take (the first load of ~100 MB of new native files is scanned)
# (The trial's own way of starting a process, kept at import: what the starter's tests put in place of the module's, for the
# wall's child, is not what the updater runs.)
_Popen = subprocess.Popen
SPARE = 100_000_000  # bytes left free on the data folder's disk beyond twice what an install unpacks
# Seconds the newest release's description may take to come, as a whole (each read has 20 s: one that came a piece at a time
# held a check, and every other check and installation, as long as it came). With JUDGE_WITHIN after it, a check's bound.
CHECK_WITHIN = 60.0
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")


class UpdateError(Exception):
    """An update could not be found, trusted or installed. The message is fit to show."""


def upgrade_command(executable: str | None = None, *, windows: bool | None = None) -> str:
    """The command that installs the newest release over this copy with pip, typed on the computer it runs on: pip, run by
    the Python this copy runs under (`executable`, `windows`: that Python, and whether it is on Windows; this one's)."""
    executable = sys.executable if executable is None else executable
    windows = os.name == "nt" if windows is None else windows
    command = "-m pip install --upgrade qkvm"
    if not executable:
        return f"python {command}"  # (a Python that cannot say where it is)
    if not windows:
        return f"{shlex.quote(executable)} {command}"
    path = PureWindowsPath(executable)
    if path.name.lower() == "pythonw.exe":
        path = path.with_name("python.exe")  # (the one beside it, which says what it does: pythonw has no window to say it in)
    if re.fullmatch(r"[A-Za-z0-9_.:\\/-]+", str(path)):
        return f"{path} {command}"
    # PowerShell, the shell Windows opens: a quoted program is run with '&', and nothing in single quotes is expanded.
    return "& '{}' {}".format(str(path).replace("'", "''"), command)


class Unfit(UpdateError):
    """A release this copy cannot take in place: the Python it runs under, or a library beside it, is not what the release
    needs (or the release's requirements cannot be read). `reason` says what; the message, what and how to install it.
    `pip`: whether pip, run by this copy's Python, installs it (not where it needs another Python: there pip keeps the
    version there is, and no command is named)."""

    def __init__(self, reason: str, *, pip: bool = True) -> None:
        super().__init__(f"{reason} Install the new version with pip instead: {upgrade_command()}" if pip else reason)
        self.reason, self.pip = reason, pip


class NoLongerAllowed(Exception):
    """Whoever asked for an installation lost the right to it while it was under way: nothing was installed, and nothing
    failed (the next one who may, installs it). The message is fit to show."""


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
    lock_url: str | None = None  # its list of libraries (qkvm-<version>-libraries.json), where it has one

    @property
    def lock_name(self) -> str:
        return self.wheel_name.replace("-py3-none-any.whl", "-libraries.json")


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


def _check_requirements(metadata: str, installed: Callable[[str], str | None] | None = None, *, libraries: bool = True) -> None:
    """The Python this copy runs under, and the libraries the new version will run (`installed`: the version of each by its
    name, None where there is none; without it, what this process finds), must satisfy the release's requirements.
    `libraries`: False, the Python only.

    Unfit where they do not (and where that cannot be told): its message names the command that installs it with pip."""
    headers = Parser().parsestr(metadata)
    if headers.defects or len(headers.get_all("Requires-Python", [])) > 1:
        raise Unfit("The release has invalid dependency metadata.")
    # Core metadata permits folded headers; the package description after the blank line is not metadata.
    def unfolded(value: str) -> str:
        return " ".join(value.splitlines()).strip()

    try:
        python_spec = SpecifierSet(unfolded(headers.get("Requires-Python", "")))
        python_version = Version(platform.python_version())
        if not python_spec.contains(python_version, prereleases=True):
            raise Unfit(f"This version needs Python {python_spec}; this copy runs {python_version}.", pip=False)
        for value in headers.get_all("Requires-Dist", []) if libraries else []:
            requirement = Requirement(unfolded(value))
            # The app installs no optional extras. Evaluate the whole marker: a literal substring such as
            # 'extra ==' may be only one branch of a condition that still applies to the base installation.
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            if requirement.url or requirement.extras:
                # A name/version cannot prove the origin of a direct URL, or that an extra's dependencies
                # are installed. Leave those installations to pip instead of accepting incomplete proof.
                raise Unfit(f"This version needs an installation of '{requirement.name}' that the in-app updater cannot verify.")
            try:
                there = importlib.metadata.version(requirement.name) if installed is None else installed(requirement.name)
                if there is None:
                    raise importlib.metadata.PackageNotFoundError(requirement.name)
                found = Version(there)
            except importlib.metadata.PackageNotFoundError:
                raise Unfit(f"This version needs the Python package '{requirement.name}', which is not installed.") from None
            if not requirement.specifier.contains(found, prereleases=True):
                raise Unfit(f"This version needs '{requirement.name}{requirement.specifier}'; installed is {found}.")
    except (InvalidRequirement, InvalidSpecifier, InvalidVersion, UndefinedComparison, KeyError, RecursionError):
        raise Unfit("The release's dependency requirements could not be verified.") from None


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
    """Replace an update file atomically with an owner-only file, regardless of the caller's umask.

    On the disk before it takes the name (fsync): a power cut leaves the length of a file whose data never got there, with
    zeros for it, and an update whose files came back so was named, and run, at every start, ending at once.
    """
    # (Under a name of its own, made by this program: tempfile's is given the folder's entries on Windows.)
    temporary = path.with_name(f".qkvm-update-{secrets.token_hex(8)}")
    descriptor = open_private(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _opened(wheel: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(wheel))
    except zipfile.BadZipFile:
        raise UpdateError("The download is not a valid package") from None


def metadata_of(wheel: bytes, version: str) -> str:
    """A release package's dependency metadata, checked as `unpack` checks the package: UpdateError where it is no release."""
    with _opened(wheel) as archive:
        return _examined(archive, version)[1]


def _examined(archive: zipfile.ZipFile, version: str) -> tuple[list[zipfile.ZipInfo], str]:
    """A release package's files and its dependency metadata, refusing anything that is not what a release looks like."""
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
    return members, archive.read(metadata[0]).decode("utf-8", "replace")


def unpack(wheel: bytes, version: str, destination: Path) -> None:
    """Unpack a release wheel into `destination`, refusing anything that is not what a release looks like."""
    staging = destination.with_name(destination.name + ".tmp")
    _staged(wheel, version, staging, _check_requirements)
    _named(staging, destination)


def _staged(wheel: bytes, version: str, staging: Path, check: Callable[[str], None] | None) -> None:
    """Unpack the program's own wheel into `staging`, made anew (what a cut-off install left there is removed first): its
    package and its dist-info, every file its owner's alone; `check`, given its dependency metadata, before anything is
    written."""
    with _opened(wheel) as archive:
        members, metadata = _examined(archive, version)
        if check is not None:
            check(metadata)
        shutil.rmtree(staging, ignore_errors=True)
        own_folder(staging)  # (this account named in its ACL on Windows: _folders.own_folder)
        for member in members:
            parts = member.filename.split("/")
            parent = staging
            for part in parts[:-1]:
                parent = parent / part
                own_folder(parent)
            _write_private(parent / parts[-1], archive.read(member))


def _named(staging: Path, destination: Path) -> None:
    """Give the staged version its name. Every file is on the disk (written so), and so is every folder's list of them,
    before the whole takes its name; and that name, before the pointer names the version (Updater._activate)."""
    for folder, _folders, _files in os.walk(staging, topdown=False):
        _settle(Path(folder))
    shutil.rmtree(destination, ignore_errors=True)
    staging.rename(destination)
    _settle(destination.parent)


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
        files: str = _libraries.FILES,
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
        # Whether this copy can take the newest release in place, judged when it is found (see _judge): the version judged,
        # and why it cannot, where it cannot (and whether pip on this Python installs it: Unfit.pip). A container is replaced
        # as a whole and judges nothing.
        self.container = os.environ.get("QKVM_CONTAINER") == "1"
        self.judged: str | None = None
        self.unfit: str | None = None
        self.by_pip = True
        # The judged release's metadata, from its checked package, and its list of libraries (None: it has none).
        self._metadata: tuple[Release, str, _libraries.Lock | None] | None = None
        self._running = False  # one check or install at a time (a plain flag: this object outlives event loops)
        self.files = files.rstrip("/")  # where the libraries a release lists are fetched from (PyPI's file host; a stand-in)
        self.plan: _libraries.Plan | None = None  # what the judged release brings, and from where (see _libraries.plan)
        self.progress: str | None = None  # how far an installation is, in words, while it runs
        self.brought: list[str] = []  # the libraries the last installation brought ("websockets 17.5"), for its activity entry

    @property
    def available(self) -> bool:
        """Is the newest release newer than what is running (and not already installed)?"""
        if self.latest is None or self.installed == self.latest.version:
            return False
        return parse_version(self.latest.version) > parse_version(self.current)

    @property
    def installable(self) -> bool:
        """Does this copy install a release by itself at all? (Without a key, only where it was started to.)"""
        return bool(self.keys) or self.allow_unsigned

    @property
    def in_place(self) -> bool | None:
        """Can the newest release be installed here, in place? None: not known (not judged, or it could not be)."""
        if self.latest is None or self.judged != self.latest.version:
            return None
        return self.unfit is None

    def view(self) -> dict[str, Any]:
        latest = self.latest
        in_place = self.in_place
        return {
            "current": self.current,
            "repo": self.repo,
            "state": self.state,
            "error": self.error,
            "checked_ago": None if self.checked_at is None else max(0, round(time.time() - self.checked_at)),
            "available": self.available,
            "installed": self.installed,
            "signed": bool(self.keys),
            "installable": self.installable,
            "in_place": in_place,
            "unfit": self.unfit if in_place is False else None,
            # What installs it with pip instead, on the computer this copy runs on: none where it needs another Python.
            "command": upgrade_command() if in_place is not False or self.by_pip else None,
            "image_commands": list(IMAGE_COMMANDS),  # and what updates a container (said by the server: see IMAGE_COMMANDS)
            # What installing it brings beside the program, where it brings libraries: those it downloads and how much.
            "libraries": None if not in_place or self.plan is None else {
                "fetch": [f"{step.library.name} {step.library.version}" for step in self.plan.fetched],
                "size": self.plan.size,
                "brought": len(self.plan.brought),
            },
            "progress": self.progress if self.state == "installing" else None,
            # The libraries this copy runs from its own folder (brought by the update it is), where it runs any.
            "own_libraries": [f"{each.get('name')} {each.get('version')}" for each in (_libs.recorded or {}).get("libraries", [])],
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
        # The wheel of the tag's own version, by its exact name: never another wheel a release happens to carry (one
        # attached to it by hand, whatever order GitHub lists its files in).
        wheel = f"{PACKAGE}-{str(data['tag_name']).strip().removeprefix('v')}-py3-none-any.whl"
        if wheel not in assets or not all(self._trusted(url) for url in assets.values()):
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
            lock_url=assets.get(wheel.replace("-py3-none-any.whl", "-libraries.json")),
        )

    async def check(self) -> None:
        """Ask GitHub for the newest release. Raises UpdateError when that fails."""
        if not self.repo:
            raise UpdateError("No release repository is set, so there is nowhere to look for updates")
        self._begin("checking")
        try:
            async with await self._client() as client:
                try:
                    async with asyncio.timeout(CHECK_WITHIN):
                        status, said = await self._fetch(client, f"{self.api}/repos/{self.repo}/releases/latest", MAX_ANSWER)
                except TimeoutError:
                    raise UpdateError(f"GitHub did not answer within {CHECK_WITHIN:g} s") from None
                if status == 404:
                    self.latest = None  # the repository has no releases yet
                elif status != 200:
                    raise UpdateError(f"GitHub answered with an error ({status})")
                else:
                    self.latest = self._release(json.loads(said))
                    if self.latest is not None and self.available and self.installable and not self.container:
                        await self._judge(client, self.latest)
        except UpdateError as ex:
            self._failed(ex)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            self._failed(UpdateError("GitHub could not be reached"))
        finally:
            self._running = False
        self.checked_at = time.time()
        self.state = "idle"

    async def _judge(self, client: httpx.AsyncClient, release: Release) -> None:
        """Whether this copy can take `release` in place: what its installation checks, but for writing it, made when it is
        found, so that what cannot be installed here is never offered (0.2.0 asked for the password, and only then said
        that the update needed a newer library). The package is fetched and checked as `install` does, once per release;
        the requirements are asked at every look (a library upgraded meanwhile counts). Never raises: where it could not
        be judged, `error` says why and nothing is offered. Within JUDGE_WITHIN: a package that comes slower than that is not
        judged, and asked for again at the next check (each read has 20 s, and the whole had no end on a slow line)."""
        self.judged = self.unfit = None
        self.plan = None
        try:
            if self._metadata is None or self._metadata[0] != release:
                async with asyncio.timeout(JUDGE_WITHIN):
                    wheel, lock = await self._fetch_verified(client, release)
                    self._metadata = (release, await asyncio.to_thread(metadata_of, wheel, release.version), lock)
            # (What it brings is worked out without fetching any library: a daily check never downloads one.)
            self.plan = await asyncio.to_thread(self._fit, self._metadata[1], self._metadata[2])
        except Unfit as ex:
            self.judged, self.unfit, self.by_pip = release.version, ex.reason, ex.pip
        except UpdateError as ex:
            self.error = f"Version {release.version} could not be checked against this copy: {ex}"
            log.warning("update: %s", self.error)
        except TimeoutError:
            self.error = f"Version {release.version} could not be checked against this copy: its package did not come within {JUDGE_WITHIN:g} s (it is asked for again at the next check)"
            log.warning("update: %s", self.error)
        except Exception as ex:
            # (Whatever else the download or the reading of the package raises: the HTTP library's errors and its InvalidURL,
            # which is none of them; the unpacking's BadZipFile, zlib.error, EOFError, LZMAError and the like.)
            self.error = f"Version {release.version} could not be checked against this copy: its package could not be fetched or read"
            log.warning("update: %s (%s)", self.error, type(ex).__name__)
        else:
            self.judged = release.version

    async def _fetch_verified(self, client: httpx.AsyncClient, release: Release) -> tuple[bytes, _libraries.Lock | None]:
        """The release's package and its list of libraries (None where it has none), checked against its checksum list, and
        that list against a release key where there is one."""
        if release.sums_url is None:
            raise UpdateError("The release has no checksums, so the download cannot be verified")
        sums = await self._download(client, release.sums_url, 64_000)
        if self.keys:
            if release.signature_url is None:
                raise UpdateError("The release is not signed")
            verify_signature(sums, await self._download(client, release.signature_url, 4_000), self.keys)
        wheel = await self._download(client, release.wheel_url, MAX_WHEEL)
        if hashlib.sha256(wheel).hexdigest() != _checksum_for(sums, release.wheel_name):
            raise UpdateError("The download does not match its checksum")
        # Whether it has a list of libraries is the checksums' to say, which are signed, not its list of assets, which is
        # not (the outside review of 0.3.0, Codex's M4: one left out of the assets was taken without it).
        try:
            listed: str | None = _checksum_for(sums, release.lock_name)
        except UpdateError:
            listed = None
        if release.lock_url is None:
            if listed is not None:
                raise Unfit("The release's checksums name its list of libraries, and the release does not offer it.")
            return wheel, None  # (a release made before releases listed their libraries, or a fork's: judged by what is here)
        if listed is None:
            raise Unfit("The release's list of libraries is not in its checksums.")
        lock = await self._download(client, release.lock_url, _libraries.MAX_LOCK)
        if hashlib.sha256(lock).hexdigest() != listed:
            raise UpdateError("The release's list of libraries does not match its checksum")
        try:
            return wheel, _libraries.read(lock, release.version, self.files)
        except _libraries.LockError as ex:
            raise Unfit(f"The release's list of libraries cannot be read: {ex}.") from None

    def _lookup(self) -> Callable[[str], str | None] | None:
        """How the version of a library on this computer is found for what the new version runs beside the libraries it
        brings: None, as this process finds it (the running version brought none); otherwise in the base only, every place on
        the path but the running version's own libraries, which the new version does not have."""
        if _libs.placed is None:
            return None
        inside = os.path.normcase(os.path.abspath(self.directory))
        base = [path for path in sys.path if not os.path.normcase(os.path.abspath(path or ".")).startswith(inside + os.sep)]
        versions = _libraries.found(base)
        return lambda name: versions.get(canonicalize_name(name))

    def _fit(self, metadata: str, lock: _libraries.Lock | None) -> _libraries.Plan | None:
        """Whether this copy can take the release in place, and what it then brings from where (None: it brings nothing, and
        runs on what is here). Unfit where it cannot. Blocking: off the event loop."""
        lookup = self._lookup()
        if lock is None:
            _check_requirements(metadata, lookup)
            return None
        _check_requirements(metadata, libraries=False)  # (its Python first: where it needs another, no pip command is named)

        def installed(name: str) -> str | None:
            if lookup is not None:
                return lookup(name)
            try:
                return importlib.metadata.version(name)
            except (importlib.metadata.PackageNotFoundError, KeyError):  # (KeyError: what a test's table of them says)
                return None

        here = _libraries.target()
        base = {library.name: installed(library.name) for library in lock.targets.get(here, ())}
        running = (_libs.placed, _libs.recorded) if _libs.placed is not None and _libs.recorded is not None else None
        try:
            plan = _libraries.plan(lock, {name: version for name, version in base.items() if version is not None}, running, here=here)
        except _libraries.NoBuild as ex:
            raise Unfit(str(ex)) from None
        provided = plan.versions
        _check_requirements(metadata, lambda name: provided.get(canonicalize_name(name)) or installed(name))
        return plan

    def _begin(self, state: str) -> None:
        if self._running:
            raise UpdateError("An update check or installation is already under way")
        self._running = True
        self.state, self.error = state, None

    def _failed(self, error: UpdateError) -> None:
        # (What stands in the way of a release this copy cannot take is said by `unfit`, with how to install it instead: once.)
        self.state, self.error = "failed", None if isinstance(error, Unfit) else str(error)
        log.warning("update: %s", error)
        raise error

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, limit: int, sink: Callable[[bytes], Awaitable[None]] | None = None
    ) -> tuple[int, bytes]:
        """What is at `url`: (the status it was answered with, at most `limit` bytes of what came). `sink`: handed what comes,
        piece by piece, where it is not to be held in memory (then nothing is returned of it); only for an answer of 200.

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
                if sink is not None and reply.status_code != 200:
                    return reply.status_code, b""
                async for chunk in reply.aiter_raw():
                    size += len(chunk)
                    if size > limit:
                        raise UpdateError("The download is larger than expected")
                    if sink is not None:
                        await sink(chunk)
                    else:
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

    async def install(self, still: Callable[[], bool] | None = None) -> str:
        """Download the newest release, check it, and make it the version used from the next start.

        Returns the version installed. The running program is not touched.

        In steps, each of which leaves the pointer and every named folder as they were where it stops: the program's package
        and the release's list of libraries, downloaded and checked; what it brings, worked out again (this computer may have
        changed since it was found); the package and the libraries put into updates/<version>.tmp (copied from the running
        version's folder, or fetched by the list's address and held to its hash, and unpacked); a throwaway process of this
        Python that loads the new version as a start would; and only then the name, and the pointer.

        `still`: whether whoever asked may still have it installed, asked once the download is in and checked, right before
        anything is written (the download takes seconds, and more on a slow line), and again once all of it is written and
        tried, right before it is named: NoLongerAllowed where not, and nothing is named.
        """
        release = self.latest
        if release is None or not self.available:
            raise UpdateError("There is no newer version to install")
        self._begin("installing")
        self.progress, self.brought = "Downloading the new version", []
        staging: Path | None = None
        try:
            if not self.keys and not self.allow_unsigned:
                raise UpdateError(
                    "This copy has no release key built in, so it cannot tell who published an update and "
                    "does not install one by itself. Install the new version by hand, or start qKVM with "
                    "--allow-unsigned-updates."
                )
            async with await self._client() as client:
                wheel, lock = await self._fetch_verified(client, release)
                metadata = await asyncio.to_thread(metadata_of, wheel, release.version)
                plan = await asyncio.to_thread(self._fit, metadata, lock)
                if still is not None and not still():
                    raise NoLongerAllowed("It was not installed: whoever asked for it may no longer do that")
                staging = self.directory / f"{release.version}.tmp"
                await asyncio.to_thread(self._stage, release.version, wheel, plan)
                if plan is not None:
                    await self._bring(client, plan, staging)
            self.progress = f"Trying version {release.version} on this computer"
            await asyncio.to_thread(self._try, release.version, staging, plan)
            if still is not None and not still():
                raise NoLongerAllowed("It was not installed: whoever asked for it may no longer do that")
            self.progress = f"Installing version {release.version}"
            await asyncio.to_thread(self._activate, release.version, staging)
            staging = None
        except asyncio.CancelledError:
            # (Stopped with the wall: nothing is awaited here. What it left in <version>.tmp the next install removes. Said
            # as failed, not left "installing" for good: where it was cut off as it named the version, that is named all
            # the same, and offered again here until a start, which names it again as the same one: see _activate.)
            self._running, self.progress = False, None
            self.state, self.error = "failed", "It was stopped before it was done (qKVM was stopped, or its listeners opened again): install it again."
            raise
        except NoLongerAllowed:
            await self._discard(staging)
            self.state = "idle"  # (nothing was named, and nothing failed)
            raise
        except UpdateError as ex:
            await self._discard(staging)
            if isinstance(ex, Unfit):  # (what the page says from now on: not offered, and how to install it instead)
                self.judged, self.unfit, self.by_pip = release.version, ex.reason, ex.pip
            self._failed(ex)
        except httpx.HTTPError:
            await self._discard(staging)
            self._failed(UpdateError("The download was interrupted"))
        except _libraries.Refused as ex:
            await self._discard(staging)
            self._failed(UpdateError(f"The update was refused: {ex}"))
        except (OSError, ValueError, zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError) as ex:
            # (A package that passed its checksum and is broken inside all the same: said like any other failure.)
            await self._discard(staging)
            self._failed(UpdateError(f"The update could not be unpacked: {ex}"))
        except Exception as ex:
            # (Any other: a library's error of a kind not named above, a slip. It left the update "installing" for good.)
            log.warning("update: the installation failed (%s)", type(ex).__name__, exc_info=True)
            await self._discard(staging)  # (as every other failure: what it began in <version>.tmp goes)
            self._failed(UpdateError(f"The update could not be installed ({type(ex).__name__})"))
        finally:
            self._running = False
            self.progress = None
        self.installed = release.version
        self.brought = [f"{step.library.name} {step.library.version}" for step in plan.brought] if plan is not None else []
        self.state = "ready"
        log.warning("update: version %s installed, taking effect at the next start%s", release.version, f" (it brought {', '.join(self.brought)})" if self.brought else "")
        return release.version

    async def _discard(self, staging: Path | None) -> None:
        if staging is not None:
            await asyncio.to_thread(shutil.rmtree, staging, True)

    def _stage(self, version: str, wheel: bytes, plan: _libraries.Plan | None) -> Path:
        """The program's package unpacked into updates/<version>.tmp, made anew; refused first where the data folder's disk
        has too little room for what the version brings. Blocking: off the event loop."""
        own_folder(self.directory)
        if os.name == "posix":
            self.directory.chmod(0o700)
        staging = self.directory / f"{version}.tmp"
        if plan is not None and plan.brought:
            shutil.rmtree(staging, ignore_errors=True)  # (what a cut-off install left: not counted as room taken)
            needs, free = 2 * plan.unpacked + SPARE, shutil.disk_usage(self.directory).free
            if free < needs:
                raise UpdateError(f"The update needs {_libraries.in_words(needs)} free in {self.directory}; there is {_libraries.in_words(free)}.")
        _staged(wheel, version, staging, None if plan is not None else lambda metadata: _check_requirements(metadata, self._lookup()))
        return staging

    async def _bring(self, client: httpx.AsyncClient, plan: _libraries.Plan, staging: Path) -> None:
        """Put the libraries the version brings into `staging`/lib, and its note of them beside it: each copied from the
        running version's folder where that holds the very wheel (every file held to its record; one that differs has the
        wheel fetched instead), every other one fetched by the list's address, held to its hash and size, and unpacked."""
        placed = _libraries.Placed(staging / "lib")
        await asyncio.to_thread(placed.folder, [])
        wheels = staging / ".wheels"
        entries: list[dict[str, Any]] = []
        total, done = plan.size, 0
        for step in plan.brought:
            name = f"{step.library.name} {step.library.version}"
            if step.how == "copy" and plan.reuse is not None:
                self.progress = f"Copying {name} from the running version"
                try:
                    entries.append(await asyncio.to_thread(_libraries.copy, step, plan.reused[step.library.name], plan.reuse, placed))
                    continue
                except _libraries.Damaged:
                    log.warning("update: %s in the running version's folder is not what its wheel held; it is fetched instead", name)
                    total += step.wheel.size
            self.progress = f"Downloading {name} ({_libraries.in_words(done)} of {_libraries.in_words(total)})"
            await asyncio.to_thread(own_folder, wheels)
            path = wheels / step.wheel.file
            await self._fetch_wheel(client, step.wheel, path)
            done += step.wheel.size
            self.progress = f"Unpacking {name}"
            entries.append(await asyncio.to_thread(_libraries.unpack, path, step, placed))
            await asyncio.to_thread(path.unlink)
        await asyncio.to_thread(shutil.rmtree, wheels, True)
        await asyncio.to_thread(_write_private, staging / _libraries.NOTE, _libraries.note(plan, entries))

    async def _fetch_wheel(self, client: httpx.AsyncClient, wheel: _libraries.Wheel, path: Path) -> None:
        """Stream the wheel at its address into a new private file at `path`, hashed as it comes and cut off past its size,
        written and hashed off the event loop; refused, and removed, unless it is the very file the list names."""
        stream = os.fdopen(await asyncio.to_thread(open_private, path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)), "wb")
        digest, size = hashlib.sha256(), [0]

        def write(chunk: bytes) -> None:
            digest.update(chunk)
            size[0] += stream.write(chunk)

        def finish() -> None:
            stream.flush()
            os.fsync(stream.fileno())

        async def sink(chunk: bytes) -> None:
            await asyncio.to_thread(write, chunk)

        try:
            try:
                status, _ = await self._fetch(client, wheel.url, wheel.size, sink)
                await asyncio.to_thread(finish)
            finally:
                await asyncio.to_thread(stream.close)
            if status != 200:
                raise UpdateError(f"{wheel.file} could not be downloaded ({status})")
            if digest.hexdigest() != wheel.sha256 or size[0] != wheel.size:
                raise UpdateError(f"{wheel.file} is not the file the release names: its checksum differs")
        except BaseException:
            await asyncio.to_thread(path.unlink, True)
            raise

    def _try(self, version: str, staging: Path, plan: _libraries.Plan | None) -> None:
        """The trial: a throwaway process of this Python (no data folder, no port, a time limit) loads the new version as a
        start would (its libraries judged and put first, its program, every native module it brought) before it is named.
        Unfit where that fails, saying why: what would have failed at its start (a data folder on a disk that runs no
        programs, a policy that refuses shared libraries there, a build this computer cannot load) is said here instead,
        and nothing is named. Blocking: off the event loop."""
        import qkvm

        modules = _libraries.extension_modules(staging / "lib") if plan is not None and (staging / "lib").is_dir() else []
        if plan is not None and not (staging / "qkvm" / "_libs.py").is_file():
            raise Unfit(f"Version {version} brings libraries and has nothing that puts them in place.")
        shipped = str(Path(list(qkvm.__path__)[-1]).parent)  # (the copy installed: what a start loads first, as the starter does)
        environment = {key: value for key, value in os.environ.items() if key not in ("QKVM_CHILD", "PYTHONSTARTUP")}
        environment["PYTHONPATH"] = os.pathsep.join(part for part in (shipped, os.environ.get("PYTHONPATH", "")) if part)
        command = [sys.executable, "-B", "-P", "-c", TRIAL, str(staging), "1" if plan is not None else "0", *modules]
        with _Popen(
            command, cwd=staging, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ) as trial:  # fmt: skip
            try:
                out, _ = trial.communicate(timeout=TRIAL_WITHIN)
            except subprocess.TimeoutExpired:
                trial.kill()
                trial.communicate()
                log.warning("update: the trial of version %s did not end within %g s", version, TRIAL_WITHIN)
                raise Unfit(f"Version {version} could not be tried on this computer: loading it did not end within {TRIAL_WITHIN:g} s.") from None
        said = out.decode("utf-8", "replace")[-4000:].strip()
        if trial.returncode != 0:
            last = (said.splitlines() or ["no word"])[-1][:300]
            log.warning("update: the trial of version %s ended with %s:\n%s", version, trial.returncode, said)
            raise Unfit(f"Version {version} does not load on this computer ({last}).")

    def _activate(self, version: str, staged: bytes | Path) -> None:
        """Name the staged version (or a package of it, staged here first, with its requirements checked), then point the
        next start at it, and keep only it and the version before it."""
        if isinstance(staged, bytes):
            staged = self._stage(version, staged, None)
        _named(staged, self.directory / version)
        pointer = self.directory / "current.json"
        try:
            before = json.loads(pointer.read_text(encoding="utf-8"))
            previous, ran = before.get("version"), before.get("proven") is True
        except (OSError, ValueError, AttributeError, RecursionError):
            previous, ran = None, False
        if not isinstance(previous, str):
            previous, ran = None, False  # (what is written below is a version's name or nothing: never whatever stood there)
        if previous == version:
            # Named again (an install cut off once it had named it, offered again): what it goes back to stays what it
            # went back to, and not itself.
            previous, ran = before.get("previous"), before.get("previous_proven") is True
            if not isinstance(previous, str) or previous == version:
                previous, ran = None, False
        # (Whether the one before got through its first half minute is kept with it: the starter goes back to
        # it as a version that ran, or as one that is still on trial. See __main__.roll_back.)
        _write_private(pointer, json.dumps({"version": version, "previous": previous, "previous_proven": ran}).encode("utf-8"))
        _settle(self.directory)  # (the pointer's own name in the folder: a start after a power cut finds what was written)
        # Keep the new version and the one to fall back to, each with its own libraries, and the one running now (where it
        # runs from here); older ones only take up space.
        for entry in self.directory.iterdir():
            if entry.is_dir() and entry.name not in (version, previous, self.current):
                shutil.rmtree(entry, ignore_errors=True)


# What the trial runs (Updater._try), in a process of its own: the new version's package put in front of the installed one
# as the starter puts it, its libraries judged and put first as its own _libs does at a start, its program loaded, and
# every native module it brought. Standard library only until the version's own code takes over. The installed _where is
# loaded first, as every start loads it (the starter asks it where the data folder is) before the package is put in front.
TRIAL = """
import sys
from pathlib import Path

staging = Path(sys.argv[1])
import qkvm
import qkvm._where

qkvm.__path__.insert(0, str(staging / "qkvm"))
if sys.argv[2] == "1":
    from qkvm import _libs

    _libs.trial(staging)
import qkvm.cli

for name in sys.argv[3:]:
    __import__(name)
print("qkvm: the trial of", staging.name, "went well", flush=True)
"""
