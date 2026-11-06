"""The libraries an update brings (the owner's decisions of 2026-11-03): the release's signed lock, read exactly; which build
of each library this computer takes, and from where; and the rules every library's wheel is unpacked by."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from packaging.tags import Tag

from qkvm import __main__ as starter
from qkvm import _libraries
from qkvm._libraries import Library, LockError, NoBuild, Placed, Refused, Step, Wheel
from qkvm.update import Unfit, UpdateError, Updater
from tests import libraries_kit as kit
from tests.fake_github import FakeGitHub, make_wheel

HOST = _libraries.FILES
HERE = _libraries.target()


def entry(file: str, data: bytes = b"x", host: str = HOST, **changed: Any) -> dict[str, Any]:
    digest = hashlib.blake2b(data, digest_size=32).hexdigest()
    return {
        "file": file, "url": f"{host}/packages/{digest[:2]}/{digest[2:4]}/{digest[4:]}/{file}",
        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "unpacked": 10, **changed,
    }  # fmt: skip


def lock(libraries: list[dict[str, Any]] | None = None, version: str = "9.9.9", targets: tuple[str, ...] = (HERE,), **top: Any) -> bytes:
    libraries = libraries if libraries is not None else [{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl")]}]
    return json.dumps({"format": 1, "version": version, "targets": {target: {"libraries": libraries} for target in targets}, **top}).encode()


# --- the lock, read exactly ----------------------------------------------------------------------------------------------


def test_a_lock_as_the_release_writes_it_is_read() -> None:
    read = _libraries.read(lock(), "9.9.9")
    (library,) = read.targets[HERE]
    assert (library.name, library.version, library.wheels[0].file) == ("websockets", "17.5", "websockets-17.5-py3-none-any.whl")
    assert read.sha256 == hashlib.sha256(lock()).hexdigest() and not library.wheels[0].native


@pytest.mark.parametrize(
    ("made", "said"),
    [
        (lambda: b"{" * 10, "not readable"),
        (lambda: lock(extra=1), "not as a lock writes it"),
        (lambda: lock(version="9.9.8"), "another version"),
        (lambda: lock(targets=("cp310-linux-x86_64",)), "does not know"),
        (lambda: lock([{"name": "Websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl")]}]), "not a library's name"),
        (lambda: lock([{"name": "qkvm", "version": "17.5", "wheels": [entry("qkvm-17.5-py3-none-any.whl")]}]), "not a library's name"),
        (lambda: lock([{"name": "websockets", "version": "17.05", "wheels": [entry("websockets-17.5-py3-none-any.whl")]}]), "not written as a lock writes it"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.4-py3-none-any.whl")]}]), "is not a wheel of websockets 17.5"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", host="https://evil.example")]}]), "not at PyPI's file host"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", url=f"{HOST}/packages/websockets-17.5-py3-none-any.whl")]}]), "not at PyPI's file host"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", sha256="0" * 63)]}]), "not one"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", size=True)]}]), "not a size"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", size=_libraries.MAX_WHEEL + 1)]}]), "not a size"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl", unpacked=_libraries.MAX_TARGET)]}] * 1), None),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl")]}] * 2), "names a library twice"),
        (lambda: lock([{"name": "websockets", "version": "17.5", "wheels": [entry("websockets-17.5-py3-none-any.whl")] * 2}]), "names a wheel twice"),
        (lambda: b" " * (_libraries.MAX_LOCK + 1), "larger than a lock is"),
    ],
)
def test_anything_a_lock_does_not_write_is_refused(made: Any, said: str | None) -> None:
    if said is None:
        _libraries.read(made(), "9.9.9")  # (at the limit: still read)
        return
    with pytest.raises(LockError, match=said):
        _libraries.read(made(), "9.9.9")


def test_a_target_larger_than_a_lock_allows_is_refused() -> None:
    big = [{"name": f"lib{n}", "version": "1.0", "wheels": [entry(f"lib{n}-1.0-py3-none-any.whl", unpacked=_libraries.MAX_TARGET // 2)]} for n in range(3)]
    with pytest.raises(LockError, match="larger than a lock allows"):
        _libraries.read(lock(big), "9.9.9")


# --- which build, and from where ---------------------------------------------------------------------------------------------


def library(name: str, version: str, *files: str) -> Library:
    return Library(name, version, tuple(Wheel(file, f"{HOST}/x/{file}", hashlib.sha256(file.encode()).hexdigest(), 100, 1000) for file in files))


def plan_of(*libraries: Library, base: dict[str, str] | None = None, running: Any = None, tags: list[Tag] | None = None, here: str = "cp313-linux-x86_64") -> _libraries.Plan:
    read = _libraries.Lock("9.9.9", "f" * 64, {"cp313-linux-x86_64": libraries})
    return _libraries.plan(read, base or {}, running, tags=tags or [Tag("cp313", "cp313", "manylinux_2_28_x86_64"), Tag("cp313", "cp313", "manylinux_2_17_x86_64"), Tag("cp313", "abi3", "manylinux_2_17_x86_64"), Tag("py3", "none", "any")], here=here)


def test_the_best_fitting_build_is_taken_as_pip_takes_it() -> None:
    av = library("av", "17.2.0", "av-17.2.0-cp311-abi3-manylinux_2_17_x86_64.whl", "av-17.2.0-cp313-cp313-manylinux_2_28_x86_64.whl", "av-17.2.0-cp313-cp313-musllinux_1_2_x86_64.whl")
    (step,) = plan_of(av).steps
    assert step.wheel.file == "av-17.2.0-cp313-cp313-manylinux_2_28_x86_64.whl" and step.how == "fetch" and step.wheel.native


def test_a_computer_the_release_has_no_build_for_is_told_so_with_what_it_needs() -> None:
    av = library("av", "17.2.0", "av-17.2.0-cp313-cp313-win_amd64.whl")
    with pytest.raises(NoBuild, match=r"This version needs av 17\.2\.0, and the release has no build of it for this computer \(Python "):
        plan_of(av)
    with pytest.raises(NoBuild, match="the release has no build of them for this computer"):
        plan_of(av, here="cp314t-linux-x86_64")  # (a free-threaded Python: no target of the lock is it)


def test_what_the_base_has_at_the_locked_version_is_kept_and_any_other_version_is_shadowed() -> None:
    kept, newer, older = library("h11", "0.16.0", "h11-0.16.0-py3-none-any.whl"), library("idna", "3.20", "idna-3.20-py3-none-any.whl"), library("anyio", "4.16.0", "anyio-4.16.0-py3-none-any.whl")
    made = plan_of(kept, newer, older, base={"h11": "0.16.0", "idna": "3.21", "anyio": "4.15"})
    assert [(step.library.name, step.how) for step in made.steps] == [("h11", "base"), ("idna", "fetch"), ("anyio", "fetch")]
    assert made.versions == {"h11": "0.16.0", "idna": "3.20", "anyio": "4.16.0"} and made.size == 200 and made.unpacked == 2000


def test_the_running_versions_own_copy_of_the_very_wheel_is_copied_and_not_fetched(tmp_path: Path) -> None:
    websockets = library("websockets", "17.5", "websockets-17.5-py3-none-any.whl")
    held = {"libraries": [{"name": "websockets", "sha256": websockets.wheels[0].sha256}, {"name": "other", "sha256": "0" * 64}]}
    made = plan_of(websockets, running=(tmp_path, held))
    assert [step.how for step in made.steps] == ["copy"] and made.size == 0 and made.reuse == tmp_path
    other = library("websockets", "17.5", "websockets-17.5-py3-none-any.whl")
    other = Library(other.name, other.version, (Wheel(other.wheels[0].file, other.wheels[0].url, "1" * 64, 100, 1000),))
    assert [step.how for step in plan_of(other, running=(tmp_path, held)).steps] == ["fetch"]  # (another build of it: fetched)


# --- the rules every wheel is unpacked by -------------------------------------------------------------------------------------


def step_for(file: str, data: bytes, name: str, version: str) -> Step:
    import zipfile
    import io

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        unpacked = sum(member.file_size for member in archive.infolist() if not member.is_dir())
    wheel = Wheel(file, f"{HOST}/x/{file}", hashlib.sha256(data).hexdigest(), len(data), unpacked)
    return Step(Library(name, version, (wheel,)), wheel, "fetch")


def unpacked(tmp_path: Path, file: str, data: bytes, name: str = "demo-lib", version: str = "1.0", placed: Placed | None = None) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / file
    path.write_bytes(data)
    placed = placed or Placed(tmp_path / "lib")
    placed.folder([])
    return _libraries.unpack(path, step_for(file, data, name, version), placed)


def test_a_wheel_is_unpacked_with_a_record_of_what_was_written_where(tmp_path: Path) -> None:
    file, data = kit.wheel("demo-lib", "1.0", {"demo_lib/__init__.py": b"X = 1\n", "demo_lib-1.0.data/purelib/demo_extra.py": b"Y = 2\n"})
    said = unpacked(tmp_path, file, data)
    lib = tmp_path / "lib"
    assert (lib / "demo_lib" / "__init__.py").read_bytes() == b"X = 1\n" and (lib / "demo_extra.py").read_bytes() == b"Y = 2\n"
    assert said["top"] == ["demo_extra", "demo_lib"] and said["dist_info"] == "demo_lib-1.0.dist-info"
    record = (lib / "demo_lib-1.0.dist-info" / "RECORD").read_bytes()
    assert said["record"] == hashlib.sha256(record).hexdigest() and b"demo_extra.py,sha256=" in record and not (lib / "demo_lib-1.0.data").exists()
    if os.name == "posix":
        assert all(oct(path.stat().st_mode & 0o777) in ("0o600", "0o700") for path in lib.rglob("*"))


@pytest.mark.parametrize(
    ("files", "said"),
    [
        ({"json/__init__.py": b""}, "a module named 'json'"),
        ({"sitecustomize.py": b""}, "a module named 'sitecustomize'"),
        ({"email.pyw": b""}, "a module named 'email'"),  # (a source file to Python on Windows: the final review of 0.3.0)
        ({"qkvm/__init__.py": b""}, "a module named 'qkvm'"),
        ({"evil.pth": b"import os"}, "a .pth file"),
        ({"demo_lib-1.0.data/scripts/run": b"#!/bin/sh"}, "which no library of this program may bring"),
        ({"demo_lib-1.0.data/data/etc/x": b""}, "which no library of this program may bring"),
        ({"demo_lib/con.py": b""}, "named so that it would be another"),
        ({"demo_lib/a.py.": b""}, "named so that it would be another"),
        ({"demo_lib/../x.py": b""}, "named so that it would be another"),
        ({"demo_lib/a\\b.py": b""}, "named so that it would be another"),
    ],
)
def test_what_no_library_may_hold_is_refused_and_nothing_of_it_is_left(tmp_path: Path, files: dict[str, bytes], said: str) -> None:
    if os.name == "nt" and any("\\" in name for name in files):
        pytest.skip("Python's zip reader on Windows reads a backslash in a name as a folder's")
    file, data = kit.wheel("demo-lib", "1.0", files)
    with pytest.raises(Refused, match=said):
        unpacked(tmp_path, file, data)
    assert [path for path in (tmp_path / "lib").rglob("*") if path.is_file()] == []


def test_a_wheel_whose_metadata_is_not_the_locks_library_is_refused(tmp_path: Path) -> None:
    file, data = kit.wheel("demo-lib", "1.0", {"demo_lib/__init__.py": b""}, metadata="Metadata-Version: 2.1\nName: demo-lib\nVersion: 1.1\n")
    with pytest.raises(Refused, match=r"is not demo-lib 1\.0"):
        unpacked(tmp_path, file, data)
    file, data = kit.wheel("demo-lib", "1.0", {"demo_lib/__init__.py": b""}, metadata="Metadata-Version: 2.1\nName: demo-lib\nVersion: 1.0\nRequires-Python: <3.0\n")
    with pytest.raises(Refused, match="does not run on Python"):
        unpacked(tmp_path / "b", file, data)


def test_no_file_is_written_by_two_libraries(tmp_path: Path) -> None:
    placed = Placed(tmp_path / "lib")
    unpacked(tmp_path, *kit.wheel("one-lib", "1.0", {"shared/__init__.py": b"one"}), name="one-lib", placed=placed)
    with pytest.raises(Refused, match="no file may be written by two libraries"):
        unpacked(tmp_path, *kit.wheel("two-lib", "1.0", {"shared/__init__.py": b"two"}), name="two-lib", placed=placed)
    assert (tmp_path / "lib" / "shared" / "__init__.py").read_bytes() == b"one"
    # (A folder two libraries share, a namespace package, is no file: both are taken.)
    unpacked(tmp_path, *kit.wheel("three-lib", "1.0", {"shared/three.py": b"3"}), name="three-lib", placed=placed)


def test_a_copy_from_the_running_version_is_held_to_its_record_and_a_damaged_file_takes_it_all_back(tmp_path: Path) -> None:
    file, data = kit.wheel("demo-lib", "1.0", {"demo_lib/__init__.py": b"X = 1\n", "demo_lib/more.py": b"Y = 1\n"})
    said = unpacked(tmp_path / "old", file, data)
    step = step_for(file, data, "demo-lib", "1.0")
    copied = _libraries.copy(step, said, tmp_path / "old" / "lib", Placed(tmp_path / "new" / "lib"))
    assert copied == said and (tmp_path / "new" / "lib" / "demo_lib" / "more.py").read_bytes() == b"Y = 1\n"
    (tmp_path / "old" / "lib" / "demo_lib" / "more.py").write_bytes(b"Y = 2\n")  # (the same length, other bytes)
    placed = Placed(tmp_path / "again" / "lib")
    with pytest.raises(_libraries.Damaged):
        _libraries.copy(step, said, tmp_path / "old" / "lib", placed)
    assert placed.files == {} and [path for path in (tmp_path / "again").rglob("*") if path.is_file()] == []


def test_the_native_modules_of_a_lib_are_found_by_their_dotted_names(tmp_path: Path) -> None:
    import importlib.machinery

    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    for name in (f"pkg/sub/_fast{suffix}", f"top{suffix}", f"pkg.libs/libz{suffix}", "pkg/__init__.py"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(b"")
    assert _libraries.extension_modules(tmp_path) == ["pkg.sub._fast", "top"]


# --- the updater, with a release that lists its libraries -------------------------------------------------------------------


@pytest.fixture
def github() -> Iterator[FakeGitHub]:
    server = FakeGitHub().start()
    yield server
    server.stop()


def updater(github: FakeGitHub, data: Path) -> Updater:
    return Updater(data, github.repo, api=github.url, keys=(), current="1.0.0", allow_unsigned=True, files=github.url)


def release_with(github: FakeGitHub, *libraries: tuple[str, bytes], requires: tuple[str, ...] = (), **options: Any) -> None:
    github.publish("9.9.9", make_wheel("9.9.9", requires=requires, extra=kit.loader()), libraries=list(libraries), **options)


def test_a_release_that_needs_newer_libraries_than_this_computer_has_is_installed_in_place_with_them(github: FakeGitHub, tmp_path: Path) -> None:
    pure = kit.pure("2.0")
    release_with(github, pure, requires=(f"{kit.PURE}>=2", "fastapi>=0.110"))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    view = update.view()
    assert view["in_place"] is True and view["libraries"] == {"fetch": [f"{kit.PURE} 2.0"], "size": len(pure[1]), "brought": 1}, view
    assert not any(path.startswith("/packages/") for path in github.asked)  # (found and judged: no library fetched for that)
    assert asyncio.run(update.install()) == "9.9.9" and update.brought == [f"{kit.PURE} 2.0"]
    folder = tmp_path / "updates" / "9.9.9"
    assert (folder / "lib" / "qkvm_proof_pure" / "__init__.py").read_text() == 'VERSION = "2.0"\n'
    note = json.loads((folder / "libraries.json").read_text())
    assert note["target"] == HERE and [each["name"] for each in note["libraries"]] == [kit.PURE] and note["libraries"][0]["top"] == ["qkvm_proof_pure"]
    assert not (tmp_path / "updates" / "9.9.9.tmp").exists() and not (folder / ".wheels").exists()
    assert starter.active_update(tmp_path) == folder / "qkvm"  # (the starter judges the whole folder, lib/ with it, and takes it)


def test_a_tampered_wheel_is_refused_and_nothing_is_named(github: FakeGitHub, tmp_path: Path) -> None:
    file, data = kit.pure("2.0")
    release_with(github, (file, data), requires=(f"{kit.PURE}>=2",))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    for path in github.packages:
        github.packages[path] = data[:100] + bytes([data[100] ^ 1]) + data[101:]  # (the same length, one bit other)
    with pytest.raises(UpdateError, match="is not the file the release names: its checksum differs"):
        asyncio.run(update.install())
    assert starter.pointer(tmp_path) is None and sorted(os.listdir(tmp_path / "updates")) == []


def test_a_wheel_larger_than_the_lock_says_is_cut_off(github: FakeGitHub, tmp_path: Path) -> None:
    file, data = kit.pure("2.0")
    release_with(github, (file, data), requires=(f"{kit.PURE}>=2",))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    for path in github.packages:
        github.packages[path] = data + b"\0" * 100_000
    with pytest.raises(UpdateError, match="larger than expected"):
        asyncio.run(update.install())
    assert starter.pointer(tmp_path) is None and os.listdir(tmp_path / "updates") == []


def test_a_lock_the_checksums_name_is_not_done_without_where_the_release_leaves_it_out(github: FakeGitHub, tmp_path: Path) -> None:
    # (The outside review of 0.3.0, Codex's M4: whether a release has a list of libraries was read from its own list of
    # assets, which is not signed. One with the list left out of it, its signed checksums naming it all the same, was
    # taken without it: on whatever libraries the computer has, the tested ones not brought.)
    release_with(github, kit.pure("2.0"), requires=(f"{kit.PURE}>=2",))
    name = next(name for name in github.files if name.endswith("-libraries.json"))
    del github.files[name]  # (left out of the release's assets; its checksum, signed, stays)
    assert name.encode() in github.files["SHA256SUMS"]
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    assert update.view()["in_place"] is False and "does not offer it" in update.view()["unfit"], update.view()
    with pytest.raises((Unfit, UpdateError)):
        asyncio.run(update.install())
    assert starter.pointer(tmp_path) is None


def test_a_lock_the_checksums_do_not_name_is_not_taken_in_place(github: FakeGitHub, tmp_path: Path) -> None:
    release_with(github, kit.pure("2.0"), requires=(f"{kit.PURE}>=2",))
    sums = github.files["SHA256SUMS"].decode().splitlines()
    github.files["SHA256SUMS"] = "".join(line + "\n" for line in sums if "libraries.json" not in line).encode()
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    assert update.view()["in_place"] is False and "not in its checksums" in update.view()["unfit"]
    assert update.view()["command"].endswith("-m pip install --upgrade qkvm")


def test_a_lock_with_no_build_for_this_computer_is_said_with_the_pip_command(github: FakeGitHub, tmp_path: Path) -> None:
    other = next(target for target in _libraries.TARGETS if target != HERE)
    release_with(github, kit.pure("2.0"), requires=(f"{kit.PURE}>=2",), targets=(other,))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    view = update.view()
    assert view["in_place"] is False and "the release has no build of them for this computer" in view["unfit"] and view["command"]


def test_not_enough_room_on_the_disk_is_said_before_any_library_is_fetched(github: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_with(github, kit.pure("2.0"), requires=(f"{kit.PURE}>=2",))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    monkeypatch.setattr(shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(10**9, 10**9 - 50_000_000, 50_000_000))  # type: ignore[attr-defined]
    with pytest.raises(UpdateError, match=r"needs 100\.0 MB free in .*; there is 50\.0 MB"):
        asyncio.run(update.install())
    assert not any(path.startswith("/packages/") for path in github.asked) and starter.pointer(tmp_path) is None


def test_a_version_that_does_not_load_in_the_trial_is_not_named(github: FakeGitHub, tmp_path: Path) -> None:
    wheel = make_wheel("9.9.9", requires=(f"{kit.PURE}>=2",), extra={**kit.loader(), "qkvm/cli.py": b"import qkvm_proof_pure\nraise ImportError('libavcodec.so.61: cannot open shared object file')\n"})
    github.publish("9.9.9", wheel, libraries=[kit.pure("2.0")])
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    with pytest.raises(Unfit, match=r"does not load on this computer \(ImportError: libavcodec"):
        asyncio.run(update.install())
    assert starter.pointer(tmp_path) is None and os.listdir(tmp_path / "updates") == []
    assert update.view()["in_place"] is False and update.view()["command"]  # (not offered again; pip is named)


def test_a_release_without_a_lock_is_judged_by_what_this_computer_has(github: FakeGitHub, tmp_path: Path) -> None:
    github.publish("9.9.9", make_wheel("9.9.9", requires=(f"{kit.PURE}>=2",)))
    update = updater(github, tmp_path)
    asyncio.run(update.check())
    assert update.view()["in_place"] is False and f"'{kit.PURE}', which is not installed" in update.view()["unfit"]
    assert update.view()["libraries"] is None


# --- _libs, at a start --------------------------------------------------------------------------------------------------------


def installed(github: FakeGitHub, data: Path) -> Path:
    release_with(github, kit.pure("2.0"), requires=(f"{kit.PURE}>=2",))
    update = updater(github, data)
    asyncio.run(update.check())
    asyncio.run(update.install())
    return data / "updates" / "9.9.9"


def test_libs_judges_the_libraries_by_the_starters_rules_and_says_why_not(github: FakeGitHub, tmp_path: Path) -> None:
    from qkvm import _libs

    folder = installed(github, tmp_path)
    assert _libs.judged(tmp_path, folder)[0] is None
    note = json.loads((folder / "libraries.json").read_text())
    (folder / "libraries.json").write_text(json.dumps({**note, "target": "cp39-linux-armv7l"}))
    assert "were brought for cp39-linux-armv7l, and this Python is" in str(_libs.judged(tmp_path, folder)[0])
    assert starter.active_update(tmp_path) is None  # (and this version's starter passes it over, saying why)
    (folder / "libraries.json").write_text(json.dumps({**note, "libraries": [{**note["libraries"][0], "top": ["pytest"]}]}))
    assert "pytest was loaded before this version could put its own in place" in str(_libs.judged(tmp_path, folder)[0])
    (folder / "libraries.json").write_text(json.dumps({**note, "libraries": [{**note["libraries"][0], "top": ["os"]}]}))
    assert "a module named 'os'" in str(_libs.judged(tmp_path, folder)[0])
    (folder / "libraries.json").write_text("{")
    assert "cannot be read" in str(_libs.judged(tmp_path, folder)[0])


def test_libs_refuses_a_link_in_the_libraries(github: FakeGitHub, tmp_path: Path) -> None:
    from qkvm import _libs

    folder = installed(github, tmp_path)
    elsewhere = tmp_path / "elsewhere.py"
    elsewhere.write_text("")
    try:
        os.symlink(elsewhere, folder / "lib" / "planted.py")
    except OSError:
        pytest.skip("this account may not make links here")
    assert "planted.py is a link" in str(_libs.judged(tmp_path, folder)[0])
    assert starter.active_update(tmp_path) is None


@pytest.mark.skipif(os.name != "posix", reason="modes")
def test_libs_refuses_a_library_others_may_write(github: FakeGitHub, tmp_path: Path) -> None:
    from qkvm import _libs

    folder = installed(github, tmp_path)
    (folder / "lib" / "qkvm_proof_pure" / "__init__.py").chmod(0o666)
    assert "can be written to by others" in str(_libs.judged(tmp_path, folder)[0])


@pytest.mark.skipif(sys.platform != "win32", reason="ACLs")
def test_libs_refuses_a_library_whose_acl_lets_others_in(github: FakeGitHub, tmp_path: Path) -> None:
    import subprocess

    from qkvm import _libs

    folder = installed(github, tmp_path)
    target = folder / "lib" / "qkvm_proof_pure" / "__init__.py"
    subprocess.run(["icacls", str(target), "/grant", "*S-1-5-11:(M)"], check=True, capture_output=True)  # Authenticated Users
    assert str(target) in str(_libs.judged(tmp_path, folder)[0])


def test_a_version_that_steps_back_points_the_next_start_at_the_one_before_it(github: FakeGitHub, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from qkvm import _libs

    folder = installed(github, tmp_path)
    with pytest.raises(SystemExit) as ended:
        _libs.step_back(tmp_path, folder, "its libraries were brought for another Python")
    assert ended.value.code == 75 == starter.RESTART
    assert starter.pointer(tmp_path) is None and (folder / "lib").is_dir()  # (back to the shipped copy; the folder as it was)
    assert "is not started on this computer: its libraries were brought for another Python" in (tmp_path / "qkvm.log").read_text(encoding="utf-8")


def test_libs_takes_nothing_from_the_starter_and_is_the_first_import_of_cli() -> None:
    import ast

    package = Path(_libraries.__file__).parent
    tree = ast.parse((package / "cli.py").read_text(encoding="utf-8"))
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert isinstance(imports[0], ast.ImportFrom) and imports[0].module == "__future__"
    assert isinstance(imports[1], ast.ImportFrom) and imports[1].level == 1 and [alias.name for alias in imports[1].names] == ["_libs"]
    loaded = ast.parse((package / "_libs.py").read_text(encoding="utf-8"))
    for node in ast.walk(loaded):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in sys.stdlib_module_names for alias in node.names), ast.dump(node)
        elif isinstance(node, ast.ImportFrom):
            assert (node.level == 0 and (node.module or "").split(".")[0] in sys.stdlib_module_names | {"__future__"}) or (node.level == 1 and node.module == "_version"), ast.dump(node)
    # The rules it loads under a name of their own (__main__.py) import nothing of the package at their top.
    main = ast.parse((package / "__main__.py").read_text(encoding="utf-8"))
    assert not [node for node in main.body if isinstance(node, ast.ImportFrom) and node.level >= 1]
