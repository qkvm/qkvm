"""Make a release's lock: the exact wheels of every library the version runs, for every target an update is installed in
place on (Python 3.11 to 3.14 on Linux x86-64 and ARM64 with glibc, and on Windows x86-64), each held to the hash PyPI
gives for it. Run by the release workflow's job `libraries`, with pip and packaging pinned by hash:

    python -I .github/security/make-libraries.py --version X --wheel release/qkvm-X-py3-none-any.whl --work DIR --out libraries

For each target, pip resolves the built wheel's closure as it would install it there (`--dry-run --report`, the target's
platforms, Python and implementation, wheels only), and the markers of every dependency are judged again by the target's
own (pip judges them by the Python that runs it, whatever target it is told): what pip left out that the target needs is
asked of it by name, and what it took that the target does not need is left out. Every wheel of each version that fits
the target is then listed (both
glibc builds where a project makes two, so that a wall takes what pip would take there), from PyPI's own listing of that
version, downloaded, held to the SHA-256 PyPI gives (and the one pip chose to the hash in its report), and measured.
What is written: `qkvm-X-libraries.json`, read back with the program's own reader (qkvm/_libraries.py) before it is
written; `requirements/<target>.txt`, the lock of each target as pip takes it (`--require-hashes --no-deps`), for the
jobs that install what walls will run and for the image; and `LIBRARIES.sums`, the SHA-256 of each of those files.

Python's own library, packaging and pip only. Nothing of a wheel is run here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # (the checkout: the program's own reader of the lock)

from packaging.requirements import Requirement
from packaging.tags import Tag, compatible_tags, cpython_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

from qkvm import _libraries

GLIBC = 39  # the newest glibc a build may need: Ubuntu 24.04's (2.39), the runners the lock is tested on
PLATFORMS = {
    "linux-x86_64": [*(f"manylinux_2_{minor}_x86_64" for minor in range(GLIBC, 4, -1)), "manylinux2014_x86_64", "manylinux2010_x86_64", "manylinux1_x86_64"],
    "linux-aarch64": [*(f"manylinux_2_{minor}_aarch64" for minor in range(GLIBC, 16, -1)), "manylinux2014_aarch64"],
    "win-amd64": ["win_amd64"],
}
PYPI = "https://pypi.org/pypi"
MACHINES = {"linux-x86_64": "x86_64", "linux-aarch64": "aarch64", "win-amd64": "AMD64"}  # platform.machine() there
MOST_ROUNDS = 8  # resolutions of one target, each asking for what the one before left out, at the most


def tags(target: str) -> set[Tag]:
    """Every tag a wheel may have to fit `target` (cp313-linux-x86_64): what pip, there, would take."""
    python, system = target.split("-", 1)
    version = (3, int(python[3:]))
    platforms = PLATFORMS[system]
    return {*cpython_tags(version, [python], platforms), *compatible_tags(version, python, platforms)}


def environments(target: str) -> list[dict[str, str]]:
    """The marker environments (PEP 508) of `target`, as a Python of it has them: of its first and of a late patch release
    (a dependency any of them takes is locked: one a wall does not take is never loaded there)."""
    python, system = target.split("-", 1)
    version, windows = f"3.{python[3:]}", system.startswith("win")
    return [
        {
            "implementation_name": "cpython", "implementation_version": f"{version}.{patch}", "os_name": "nt" if windows else "posix",
            "platform_machine": MACHINES[system], "platform_python_implementation": "CPython", "platform_release": "",
            "platform_system": "Windows" if windows else "Linux", "platform_version": "", "python_full_version": f"{version}.{patch}",
            "python_version": version, "sys_platform": "win32" if windows else "linux",
        }
        for patch in (0, 99)
    ]  # fmt: skip


def needed(items: list[dict[str, Any]], target: str) -> tuple[set[str], list[str]]:
    """Of pip's report (`items`: the wheel's closure as pip resolved it, the markers judged by the Python that ran pip), what
    `target` needs by its own markers: the names of the libraries pip chose that it needs, and the requirements it needs that
    pip left out (without their markers: asked of pip as they are)."""
    by_name = {canonicalize_name(item["metadata"]["name"]): item for item in items}
    needs: set[str] = set()
    missing: set[str] = set()
    todo: list[tuple[str, frozenset[str]]] = [("qkvm", frozenset())]
    seen: set[tuple[str, frozenset[str]]] = set()
    while todo:
        name, extras = todo.pop()
        if (name, extras) in seen or name not in by_name:
            continue
        seen.add((name, extras))
        for text in by_name[name]["metadata"].get("requires_dist") or []:
            requirement = Requirement(text)
            marker, requirement.marker = requirement.marker, None
            if marker is not None and not any(marker.evaluate({**env, "extra": extra}) for env in environments(target) for extra in (sorted(extras) or [""])):
                continue
            dependency = canonicalize_name(requirement.name)
            if dependency in by_name:
                needs.add(dependency)
                todo.append((dependency, frozenset(requirement.extras)))
            else:
                missing.add(str(requirement))  # (each as it is said: pip takes them all together)
    return needs, sorted(missing)


def resolved(wheel: Path, target: str, work: Path) -> list[dict[str, Any]]:
    """pip's resolution of the wheel's closure for `target`, by the target's markers: (name, version, the file pip chose, its
    hash) of each library."""
    python, system = target.split("-", 1)
    report = work / f"report-{target}.json"
    asked: list[str] = []
    for _round in range(MOST_ROUNDS):
        command = [
            sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-cache-dir", "--quiet", "--disable-pip-version-check",
            "--report", str(report), "--only-binary", ":all:", "--implementation", "cp", "--python-version", f"3.{python[3:]}", "--abi", python,
            *(option for platform in PLATFORMS[system] for option in ("--platform", platform)), str(wheel), *asked,
        ]  # fmt: skip
        subprocess.run(command, check=True)
        items = json.loads(report.read_text(encoding="utf-8"))["install"]
        needs, missing = needed(items, target)
        if not missing:
            break
        asked = sorted({*asked, *missing})
    else:
        raise SystemExit(f"pip did not resolve what {target} needs by its markers: {', '.join(missing)}")
    chosen = []
    for item in items:
        name = canonicalize_name(item["metadata"]["name"])
        if name not in needs:
            continue  # (qkvm itself; and what pip took by the markers of the Python that ran it, which the target does not need)
        info = item["download_info"]
        url, digest = info["url"], info.get("archive_info", {}).get("hashes", {}).get("sha256")
        if not url.startswith(_libraries.FILES + "/packages/") or not digest:
            raise SystemExit(f"pip chose {url} for {name} on {target}, which is not a wheel of PyPI's with its hash")
        chosen.append({"name": name, "version": str(item["metadata"]["version"]), "file": url.rsplit("/", 1)[1], "sha256": digest})
    return chosen


TRIES = 4  # times a lookup or a download is tried before the job ends
PAUSES = (5.0, 15.0, 45.0)  # seconds between them


def fetched(url: str, timeout: float) -> bytes:
    """What `url` answers, tried again after a pause where the connection stalled, was cut or the server faltered (a
    5xx). The lock is made of dozens of these, one after the other: one handshake that timed out ended the job (seen
    before the release of 0.3.0). An answer that is no fault of the moment (a 404, a 403) is said at once."""
    for attempt in range(TRIES):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as reply:
                return bytes(reply.read())
        except urllib.error.HTTPError as ex:
            if ex.code < 500 or attempt == TRIES - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == TRIES - 1:
                raise
        time.sleep(PAUSES[attempt])
    raise AssertionError("not reached")


def listing(name: str, version: str) -> list[dict[str, Any]]:
    """PyPI's own listing of the files of a library's version."""
    return list(json.loads(fetched(f"{PYPI}/{name}/{version}/json", 60))["urls"])


def lock(version: str, chosen: dict[str, list[dict[str, Any]]], listings: dict[tuple[str, str], list[dict[str, Any]]], unpacked: dict[str, int]) -> bytes:
    """The lock of what pip chose for each target (`chosen`), with every wheel of each version that fits the target
    (`listings`: PyPI's listing of each), and the size of each unpacked (`unpacked`, by file name)."""
    targets: dict[str, Any] = {}
    for target, libraries in sorted(chosen.items()):
        fits, entries = tags(target), []
        for library in sorted(libraries, key=lambda each: each["name"]):
            wheels = []
            for file in listing_wheels(listings[(library["name"], library["version"])]):
                if parse_wheel_filename(file["filename"])[3] & fits:
                    wheels.append({"file": file["filename"], "url": file["url"], "sha256": file["digests"]["sha256"], "size": file["size"], "unpacked": unpacked[file["filename"]]})
            picked = [wheel for wheel in wheels if wheel["file"] == library["file"]]
            if len(picked) != 1 or picked[0]["sha256"] != library["sha256"]:
                raise SystemExit(f"{library['file']}, which pip chose for {target}, is not the one PyPI lists with that hash")
            entries.append({"name": library["name"], "version": library["version"], "wheels": sorted(wheels, key=lambda wheel: wheel["file"])})
        targets[target] = {"libraries": entries}
    return json.dumps({"format": _libraries.FORMAT, "version": version, "targets": targets}, indent=1, sort_keys=True).encode("utf-8") + b"\n"


def listing_wheels(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [file for file in files if file.get("packagetype") == "bdist_wheel" and not file.get("yanked") and str(file.get("filename", "")).endswith(".whl")]


def requirements(read: _libraries.Lock, target: str) -> str:
    """A target's lock as pip installs it: every library at its version, with the hash of each of its wheels."""
    return "".join(
        f"{library.name}=={library.version} " + " ".join(f"--hash=sha256:{wheel.sha256}" for wheel in library.wheels) + "\n"
        for library in read.targets[target]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args(argv)
    options.work.mkdir(parents=True, exist_ok=False)
    chosen = {target: resolved(options.wheel, target, options.work) for target in _libraries.TARGETS}
    listings = {(each["name"], each["version"]): listing(each["name"], each["version"]) for libraries in chosen.values() for each in libraries}
    unpacked: dict[str, int] = {}
    wanted = {target: tags(target) for target in chosen}
    for (name, version), files in sorted(listings.items()):
        for file in listing_wheels(files):
            if file["filename"] in unpacked or not any(parse_wheel_filename(file["filename"])[3] & fits for fits in wanted.values()):
                continue
            path = options.work / file["filename"]
            path.write_bytes(fetched(file["url"], 300))
            if hashlib.sha256(path.read_bytes()).hexdigest() != file["digests"]["sha256"] or path.stat().st_size != file["size"]:
                raise SystemExit(f"{file['filename']} is not the file PyPI lists for {name} {version}")
            with zipfile.ZipFile(path) as archive:
                unpacked[file["filename"]] = sum(member.file_size for member in archive.infolist() if not member.is_dir())
    made = lock(options.version, chosen, listings, unpacked)
    read = _libraries.read(made, options.version)  # (the program's own reader: what no wall would take is not written)
    options.out.mkdir(parents=True, exist_ok=True)
    (options.out / "requirements").mkdir()
    name = f"qkvm-{options.version}-libraries.json"
    (options.out / name).write_bytes(made)
    written = [name]
    for target in _libraries.TARGETS:
        (options.out / "requirements" / f"{target}.txt").write_text(requirements(read, target), encoding="utf-8", newline="\n")
        written.append(f"requirements/{target}.txt")
    sums = "".join(f"{hashlib.sha256((options.out / file).read_bytes()).hexdigest()}  {file}\n" for file in written)
    (options.out / "LIBRARIES.sums").write_text(sums, encoding="ascii", newline="\n")
    print(f"{name}: {sum(len(libraries) for libraries in read.targets.values())} libraries in {len(read.targets)} targets, {len(made)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
