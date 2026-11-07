"""The libraries an update brings with it: the release's signed list of them (its lock), which of them this computer
takes from where, and how they are put into the new version's folder.

A release lists, in `qkvm-<version>-libraries.json` (named in its signed SHA256SUMS), the exact wheels of every library
its version runs, for each Python and system it is built for (its targets), each with the address PyPI's file host
keeps it at, its SHA-256 and its size. The version installed in place runs exactly that set (the owner's decision of
2026-11-03): a library the computer's own Python has at the locked version is taken from there; one the running version
brought from the very wheel the lock names is copied from its folder, file by file held to the record of that wheel;
every other one is fetched by its address, held to its hash, and unpacked. No pip, no index, no build: nothing in a
wheel runs at its install. See update.py for the install, _libs.py for how a start puts the set in place.

Read with the standard library and packaging only: the release workflow reads the lock it made with this file
(`python -m qkvm.release libraries`), where nothing else of the program is installed.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.machinery
import importlib.metadata
import io
import json
import os
import platform
import re
import stat
import sys
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path
from typing import IO, Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import Tag, sys_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

FILES = "https://files.pythonhosted.org"  # PyPI's file host: where every wheel the lock names is fetched from
FORMAT = 1
MAX_LOCK = 1_000_000  # bytes of a lock; the real one is some 150 KB
MAX_WHEEL = 100_000_000  # bytes of one wheel (the largest, av, is about 35 MB)
MAX_TARGET = 250_000_000  # bytes of one target's libraries, unpacked (about 145 MB on Linux)
MAX_MEMBERS = 5000  # files in one wheel (av has some 400)
MAX_LIBRARIES = 200  # libraries in one target (32 today)
MAX_WHEELS = 64  # builds of one library's version listed for one target (two glibc baselines at most, today)
MAX_RECORD = 2_000_000  # bytes of a library's record, where the running version's folder is copied from
PYTHONS = (11, 12, 13, 14)  # 3.11 to 3.14 (the owner's decision of 2026-11-03)
SYSTEMS = ("linux-x86_64", "linux-aarch64", "win-amd64")  # Linux x86-64 and ARM64 with glibc, Windows x86-64
TARGETS = tuple(f"cp3{minor}-{system}" for minor in PYTHONS for system in SYSTEMS)
NOTE = "libraries.json"  # beside the version's package: what its lib/ holds (read by _libs at every start)
RECORD = "RECORD"
CANONICAL = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256 = re.compile(r"[0-9a-f]{64}")
PYPI_PATH = re.compile(r"/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/")  # how PyPI's file host lays out its files
# Names a file of a library may not have anywhere in its path: what Windows takes for a device, whatever follows the dot.
DEVICES = frozenset({"con", "prn", "aux", "nul", *(f"com{n}" for n in range(10)), *(f"lpt{n}" for n in range(10))})
# Names no library may have at its top: the standard library's (a folder first on the path comes before it), and those
# Python or this program loads by name. (_libs.NEVER, which judges them again at every start.)
NEVER = frozenset({"qkvm", "__main__", "sitecustomize", "usercustomize"})


class LockError(ValueError):
    """A release's lock that is not what a lock is. The message says what, fit to show."""


class NoBuild(Exception):
    """The release has no build of what this version needs for this computer. The message says what, fit to show."""


class Refused(ValueError):
    """A wheel that is not what the lock says it is, or holds what no library may. The message says what, fit to show."""


class Damaged(Exception):
    """A file of the running version's libraries is not the one its wheel held: the wheel is fetched instead."""


@dataclass(frozen=True)
class Wheel:
    file: str
    url: str
    sha256: str
    size: int
    unpacked: int

    @property
    def tags(self) -> frozenset[Tag]:
        return parse_wheel_filename(self.file)[3]

    @property
    def native(self) -> bool:
        return any(tag.platform != "any" for tag in self.tags)


@dataclass(frozen=True)
class Library:
    name: str  # as packaging normalizes it
    version: str
    wheels: tuple[Wheel, ...]


@dataclass(frozen=True)
class Lock:
    version: str
    sha256: str  # of the lock as it came, held to SHA256SUMS
    targets: Mapping[str, tuple[Library, ...]]


@dataclass(frozen=True)
class Step:
    library: Library
    wheel: Wheel
    how: str  # "base": the computer's own Python has it; "copy": from the running version's folder; "fetch"


@dataclass(frozen=True)
class Plan:
    lock: str
    target: str
    steps: tuple[Step, ...]
    reuse: Path | None = None  # the running version's lib/, where some are copied from it
    reused: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)  # its note's entry of each library copied

    @property
    def versions(self) -> dict[str, str]:
        return {step.library.name: step.library.version for step in self.steps}

    @property
    def fetched(self) -> list[Step]:
        return [step for step in self.steps if step.how == "fetch"]

    @property
    def brought(self) -> list[Step]:
        return [step for step in self.steps if step.how != "base"]

    @property
    def size(self) -> int:
        """Bytes to download."""
        return sum(step.wheel.size for step in self.fetched)

    @property
    def unpacked(self) -> int:
        """Bytes the version's lib/ holds."""
        return sum(step.wheel.unpacked for step in self.brought)


def _exactly(value: Any, keys: set[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LockError(f"{what} is not as a lock writes it")
    return value


def _whole(value: Any, low: int, high: int, what: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise LockError(f"{what} is not a size a lock allows")
    return value


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 300 or not value.isprintable():
        raise LockError(f"{what} is not a name a lock gives")
    return value


def read(data: bytes, version: str, files: str = FILES) -> Lock:
    """A release's lock, read exactly (as release.listed reads SHA256SUMS): known keys only, names and versions as
    packaging normalizes them, every file a wheel of that very library and version at PyPI's file host (`files`: its
    address, or a stand-in's), sizes whole numbers under fixed limits. LockError where anything is not so."""
    if len(data) > MAX_LOCK:
        raise LockError("it is larger than a lock is")
    try:
        said = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise LockError("it is not readable") from None
    said = _exactly(said, {"format", "version", "targets"}, "it")
    if type(said["format"]) is not int or said["format"] != FORMAT:
        raise LockError("it is of a format this copy does not read")
    try:
        if Version(_text(said["version"], "its version")) != Version(version):
            raise LockError("it is the lock of another version")
    except InvalidVersion:
        raise LockError("its version is not one") from None
    targets = said["targets"]
    if not isinstance(targets, dict) or not targets:
        raise LockError("it names no target")
    read_targets: dict[str, tuple[Library, ...]] = {}
    for target, entry in targets.items():
        if target not in TARGETS:
            raise LockError(f"it names a target this copy does not know ({str(target)[:40]!r})")
        libraries = _exactly(entry, {"libraries"}, f"target {target}")["libraries"]
        if not isinstance(libraries, list) or len(libraries) > MAX_LIBRARIES:
            raise LockError(f"target {target} is not as a lock writes it")
        read_targets[target] = tuple(_library(item, target, files) for item in libraries)
        names = [library.name for library in read_targets[target]]
        if len(set(names)) != len(names):
            raise LockError(f"target {target} names a library twice")
        if sum(max(wheel.unpacked for wheel in library.wheels) for library in read_targets[target]) > MAX_TARGET:
            raise LockError(f"target {target} is larger than a lock allows")
    return Lock(version=str(Version(said["version"])), sha256=hashlib.sha256(data).hexdigest(), targets=read_targets)


def _library(item: Any, target: str, files: str) -> Library:
    entry = _exactly(item, {"name", "version", "wheels"}, f"a library of target {target}")
    name = _text(entry["name"], "a library's name")
    if not CANONICAL.fullmatch(name) or canonicalize_name(name) != name or name == "qkvm":
        raise LockError(f"{name[:40]!r} is not a library's name as a lock gives it")
    try:
        version = Version(_text(entry["version"], f"the version of {name}"))
    except InvalidVersion:
        raise LockError(f"the version of {name} is not one") from None
    if str(version) != entry["version"]:
        raise LockError(f"the version of {name} is not written as a lock writes it")
    wheels = entry["wheels"]
    if not isinstance(wheels, list) or not 1 <= len(wheels) <= MAX_WHEELS:
        raise LockError(f"{name} is not as a lock writes it")
    read_wheels = []
    for each in wheels:
        wheel = _exactly(each, {"file", "url", "sha256", "size", "unpacked"}, f"a wheel of {name}")
        file = _text(wheel["file"], f"a wheel of {name}")
        try:
            listed_name, listed_version, _build, _tags = parse_wheel_filename(file)
        except (InvalidWheelFilename, InvalidVersion):
            raise LockError(f"a wheel of {name} is not named as a wheel is") from None
        if "/" in file or "\\" in file or listed_name != name or listed_version != version:
            raise LockError(f"{file[:80]!r} is not a wheel of {name} {version}")
        url = _text(wheel["url"], f"the address of {file}")
        middle = url[len(files) : len(url) - len(file)]
        if not url.startswith(files + "/packages/") or not url.endswith("/" + file) or not PYPI_PATH.fullmatch(middle):
            raise LockError(f"{file} is not at PyPI's file host")
        if not isinstance(wheel["sha256"], str) or not SHA256.fullmatch(wheel["sha256"]):
            raise LockError(f"the SHA-256 of {file} is not one")
        read_wheels.append(
            Wheel(file, url, wheel["sha256"], _whole(wheel["size"], 1, MAX_WHEEL, f"{file}"), _whole(wheel["unpacked"], 0, MAX_TARGET, f"{file}"))
        )
    if len({wheel.file for wheel in read_wheels}) != len(read_wheels):
        raise LockError(f"{name} names a wheel twice")
    return Library(name, str(version), tuple(read_wheels))


def target() -> str:
    """This Python as a lock names its targets (the starter's own rule: __main__.target, this version's copy)."""
    from ._libs import rules

    return str(rules().target())


def described() -> str:
    """This Python and computer, in words: "Python 3.13 on Linux aarch64"."""
    name = target()
    words = f"Python {platform.python_version()}{' (free-threaded)' if name.split('-')[0].endswith('t') else ''} on {platform.system()} {platform.machine()}"
    return words + (" (32-bit)" if sys.maxsize <= 2**32 else "")


def chosen(library: Library, tags: list[Tag]) -> Wheel | None:
    """The wheel of `library` that fits best, in the order of `tags` (packaging's sys_tags: what pip would take)."""
    rank = {tag: at for at, tag in enumerate(tags)}
    fitting = [(min(rank[tag] for tag in wheel.tags if tag in rank), wheel) for wheel in library.wheels if wheel.tags & rank.keys()]
    return min(fitting, key=lambda pair: pair[0])[1] if fitting else None


def found(path: Iterable[str]) -> dict[str, str]:
    """The version of every library on `path` (the first found of each name, as an import finds it)."""
    versions: dict[str, str] = {}
    for distribution in importlib.metadata.distributions(path=list(path)):
        name = distribution.metadata["Name"] if distribution.metadata else None
        if isinstance(name, str) and name:
            versions.setdefault(canonicalize_name(name), distribution.version)
    return versions


def _same(a: str | None, b: str) -> bool:
    try:
        return a is not None and Version(a) == Version(b)
    except InvalidVersion:
        return False


def plan(lock: Lock, base: Mapping[str, str], running: tuple[Path, Mapping[str, Any]] | None = None, tags: list[Tag] | None = None, here: str | None = None) -> Plan:
    """What this computer takes from where to run exactly the lock's set: `base`, the versions the computer's own Python has
    (every place on the path but the folders under updates/); `running`, the running version's lib/ and its note, where it
    brought libraries; `tags`, `here`: this Python's tags and target (sys_tags, target()). NoBuild where the lock has no
    build for this computer."""
    here = target() if here is None else here
    tags = list(sys_tags()) if tags is None else tags
    libraries = lock.targets.get(here)
    if libraries is None:
        raise NoBuild(f"This version brings its libraries, and the release has no build of them for this computer ({described()}).")
    held: dict[str, Mapping[str, Any]] = {}
    if running is not None:
        for entry in running[1].get("libraries", []):
            if isinstance(entry, Mapping) and isinstance(entry.get("sha256"), str):
                held[entry["sha256"]] = entry
    steps = []
    for library in libraries:
        wheel = chosen(library, tags)
        if wheel is None:
            raise NoBuild(f"This version needs {library.name} {library.version}, and the release has no build of it for this computer ({described()}).")
        if _same(base.get(library.name), library.version):
            how = "base"
        elif wheel.sha256 in held:
            how = "copy"
        else:
            how = "fetch"
        steps.append(Step(library, wheel, how))
    reused = {step.library.name: held[step.wheel.sha256] for step in steps if step.how == "copy"}
    return Plan(lock.sha256, here, tuple(steps), running[0] if running is not None and reused else None, reused)


def _plain(parts: list[str]) -> bool:
    """A file's name in a wheel, part by part, that names that file and no other on every system."""
    for part in parts:
        if not part or part in (".", "..") or part != part.rstrip(". ") or any(ch in part for ch in '\\:*?"<>|') or not part.isprintable():
            return False
        if part.split(".")[0].lower() in DEVICES:
            return False
    return True




def _module(top: str, folder: bool) -> str | None:
    """The importable name a top-level folder or file of a library gives, or None (av.libs, a dist-info folder, a licence)."""
    if folder:
        return top if top.isidentifier() else None
    stem = top.partition(".")[0]
    # (What this Python imports a module from, and what one on the other systems does: .pyw and .pyd on Windows, .so elsewhere.)
    module = any(top.endswith(suffix) for suffix in (*importlib.machinery.all_suffixes(), ".py", ".pyw", ".pyc", ".pyd", ".so"))
    return stem if module and stem.isidentifier() else None


def _of(folder: str, suffix: str, library: Library) -> bool:
    """Whether a wheel's `<name>-<version><suffix>` folder is of `library` (by packaging's rules: the name escaped, the
    version as its file name writes it)."""
    if not folder.endswith(suffix):
        return False
    name, _dash, version = folder[: -len(suffix)].rpartition("-")
    try:
        return canonicalize_name(name) == library.name and Version(version) == Version(library.version)
    except InvalidVersion:
        return False


def _hash(digest: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _new(path: Path, source: IO[bytes], limit: int) -> tuple[bytes, int]:
    """Write what `source` gives into a new file at `path`, its owner's alone from its first moment and on the disk before
    this returns; (its SHA-256, its size). Refused past `limit` bytes."""
    from ._folders import open_private

    descriptor = open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
    digest, size = hashlib.sha256(), 0
    with os.fdopen(descriptor, "wb") as stream:
        while chunk := source.read(1 << 20):
            size += len(chunk)
            if size > limit:
                raise Refused(f"{path.name} is larger than its library says")
            digest.update(chunk)
            stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    return digest.digest(), size


@dataclass
class Placed:
    """What has been put into a lib/ so far: every file (by its name in any capitals: the name as written, and which library
    wrote it) and every folder made, so that no file is written by two libraries, a library found damaged half way is taken
    back whole, and every folder is on the disk before the version is named."""

    lib: Path
    files: dict[str, tuple[str, str]] = field(default_factory=dict)
    folders: set[Path] = field(default_factory=set)

    def claim(self, name: str, library: str) -> None:
        key = name.lower()
        if key in self.files:
            raise Refused(f"{name} is in {self.files[key][1]} and in {library}: no file may be written by two libraries")
        self.files[key] = (name, library)

    def folder(self, parts: list[str]) -> Path:
        """lib/ and the folders of `parts` under it, made where they are not there, each its owner's alone."""
        from ._folders import own_folder

        parent = self.lib
        for part in parts:
            parent = parent / part
            if parent not in self.folders:
                own_folder(parent)
                self.folders.add(parent)
        return parent

    def forget(self, library: str) -> None:
        """Take back what `library` wrote: its files removed, their names free again (its folders stay, empty or shared)."""
        for key, (name, owner) in list(self.files.items()):
            if owner == library:
                try:
                    self.lib.joinpath(*name.split("/")).unlink()
                except OSError:
                    pass
                del self.files[key]


def unpack(path: Path, step: Step, placed: Placed) -> dict[str, Any]:
    """Unpack the wheel at `path` (held to the lock's hash and size already) into `placed.lib` by the rules every library is
    held to, and return its entry for the version's note. Refused where it is not what the lock says or holds what no
    library may: a name that would be another file, a .data folder but the code's own, a .pth file, a module named like
    one of the standard library's, metadata of another library or version, a file another library wrote. Nothing of it is
    run, and every file is written by this program (no link, no mode from the archive)."""
    library, wheel = step.library, step.wheel
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise Refused(f"{wheel.file} is not a wheel") from None
    with archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) > MAX_MEMBERS or sum(member.file_size for member in members) > wheel.unpacked:
            raise Refused(f"{wheel.file} is larger than the release says")
        where: list[tuple[list[str], zipfile.ZipInfo]] = []
        for member in members:
            parts = member.filename.split("/")
            if not _plain(parts):
                raise Refused(f"{wheel.file} holds a file named so that it would be another ({member.filename[:80]!r})")
            if parts[0].endswith(".data"):
                # A wheel's .data folder is installed elsewhere by pip: only what goes beside the code is taken (merged into
                # lib/); scripts, headers and data files are nothing a library of this program brings.
                if not _of(parts[0], ".data", library) or len(parts) < 3 or parts[1] not in ("purelib", "platlib"):
                    raise Refused(f"{wheel.file} holds {member.filename[:80]!r}, which no library of this program may bring")
                parts = parts[2:]
            where.append((parts, member))
        dist_infos = {parts[0] for parts, _member in where if parts[0].endswith(".dist-info")}
        if len(dist_infos) != 1 or len({"/".join(parts).lower() for parts, _member in where}) != len(where):
            raise Refused(f"{wheel.file} is not laid out as a wheel is")
        (dist_info,) = dist_infos
        if not _of(dist_info, ".dist-info", library):
            raise Refused(f"{wheel.file} holds the record of another library")
        top: set[str] = set()
        for parts, _member in where:
            if parts[0] == dist_info:
                continue
            if len(parts) == 1 and parts[0].lower().endswith(".pth"):
                raise Refused(f"{wheel.file} holds a .pth file, which Python would run at every start")
            name = _module(parts[0], len(parts) > 1)
            if name is not None:
                if name in NEVER or name in sys.stdlib_module_names:
                    raise Refused(f"{wheel.file} holds a module named {name!r}, which no library may be called")
                top.add(name)
        try:
            headers = Parser().parsestr(archive.read(f"{dist_info}/METADATA").decode("utf-8"))
            same = (
                not headers.defects
                and len(headers.get_all("Name", [])) == 1
                and canonicalize_name(str(headers["Name"]).strip()) == library.name
                and len(headers.get_all("Version", [])) == 1
                and Version(str(headers["Version"]).strip()) == Version(library.version)
            )
            python = SpecifierSet(" ".join(str(headers.get("Requires-Python", "")).split()))
        except (KeyError, UnicodeDecodeError, InvalidVersion, InvalidSpecifier):
            same = False
        if not same:
            raise Refused(f"{wheel.file} is not {library.name} {library.version}, as the release says")
        if not python.contains(platform.python_version(), prereleases=True):
            raise Refused(f"{library.name} {library.version} does not run on Python {platform.python_version()}")
        lines = []
        try:
            for parts, member in where:
                placed.claim("/".join(parts), library.name)
                if parts[0] == dist_info and parts[1:] in ([RECORD], ["RECORD.jws"], ["RECORD.p7s"]):
                    continue  # (written anew below: what was written where)
                with archive.open(member) as source:
                    digest, size = _new(placed.folder(parts[:-1]) / parts[-1], source, member.file_size)
                lines.append(f"{'/'.join(parts)},{_hash(digest)},{size}")
            record = "".join(line + "\n" for line in [*lines, f"{dist_info}/{RECORD},,"]).encode("utf-8")
            if f"{dist_info}/{RECORD}".lower() not in placed.files:
                placed.claim(f"{dist_info}/{RECORD}", library.name)
            _new(placed.folder([dist_info]) / RECORD, io.BytesIO(record), len(record))
        except BaseException:
            placed.forget(library.name)
            raise
    return {
        "name": library.name, "version": library.version, "file": wheel.file, "sha256": wheel.sha256,
        "record": hashlib.sha256(record).hexdigest(), "dist_info": dist_info, "top": sorted(top),
    }  # fmt: skip


ENTRY = ("name", "version", "file", "sha256", "record", "dist_info", "top")


def copy(step: Step, entry: Mapping[str, Any], source: Path, placed: Placed) -> dict[str, Any]:
    """Copy `step`'s library from the running version's lib/ (`source`) into `placed.lib`, every file held to the record its
    own install wrote, and that record to the hash the running version's note gives. Damaged where any of it is not what it
    was: what was copied of it is taken back, and the wheel is fetched instead."""
    library = step.library
    if not all(isinstance(entry.get(key), str) for key in ENTRY[:-1]) or not isinstance(entry.get("top"), list):
        raise Damaged(library.name)
    dist_info = str(entry["dist_info"])
    if not _plain([dist_info]) or not _of(dist_info, ".dist-info", library) or entry["sha256"] != step.wheel.sha256:
        raise Damaged(library.name)
    try:
        with open(source / dist_info / RECORD, "rb") as stream:
            record = stream.read(MAX_RECORD + 1)
        if len(record) > MAX_RECORD or hashlib.sha256(record).hexdigest() != entry["record"]:
            raise Damaged(library.name)
        rows = [line.rsplit(",", 2) for line in record.decode("utf-8").splitlines() if line]
        if not rows or any(len(row) != 3 for row in rows) or len(rows) > MAX_MEMBERS:
            raise Damaged(library.name)
        for name, digest, size in rows:
            parts = name.split("/")
            if not _plain(parts):
                raise Damaged(library.name)
            placed.claim(name, library.name)
            if parts == [dist_info, RECORD]:
                continue
            original = source.joinpath(*parts)
            found = os.lstat(original)
            if not stat.S_ISREG(found.st_mode) or not size.isdigit() or found.st_size != int(size):
                raise Damaged(library.name)
            with open(original, "rb") as stream:
                written, length = _new(placed.folder(parts[:-1]) / parts[-1], stream, int(size))
            if _hash(written) != digest or length != int(size):
                raise Damaged(library.name)
        _new(placed.folder([dist_info]) / RECORD, io.BytesIO(record), len(record))
    except (Damaged, Refused, OSError, UnicodeDecodeError):
        placed.forget(library.name)
        raise Damaged(library.name) from None
    return {key: entry[key] for key in ENTRY}


def extension_modules(lib: Path) -> list[str]:
    """The dotted names of every native module in `lib` (what the trial loads: each with the shared libraries it needs)."""
    suffixes = sorted({*importlib.machinery.EXTENSION_SUFFIXES}, key=len, reverse=True)
    names = []
    for path in sorted(lib.rglob("*")):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        suffix = next((suffix for suffix in suffixes if path.name.endswith(suffix)), None)
        if suffix is not None:
            parts = [*path.relative_to(lib).parts[:-1], path.name[: -len(suffix)]]
            if all(part.isidentifier() for part in parts):
                names.append(".".join(parts))
    return names


def note(plan: Plan, entries: list[dict[str, Any]]) -> bytes:
    """The version's note of its libraries (libraries.json), which _libs reads at every start: the lock it came from, the
    Python it was brought for, and each library in lib/ with its wheel, its record's hash and its importable names."""
    return json.dumps({"format": FORMAT, "lock": plan.lock, "target": plan.target, "libraries": entries}, indent=1).encode("utf-8")


def in_words(size: int) -> str:
    return f"{size / 1_000_000:.1f} MB" if size >= 100_000 else f"{max(1, round(size / 1000))} KB"
