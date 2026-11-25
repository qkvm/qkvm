"""Every wall of 0.4.0 on glibc Linux keeps two malloc arenas and a fixed trim threshold, however it came to 0.4.0.

The starter of 0.4.0 sets MALLOC_ARENA_MAX and MALLOC_TRIM_THRESHOLD_ for the wall (test_update.py, ..._two_arenas_...). A
wall updated to 0.4.0 from inside the app runs the starter it was installed with, which sets neither (the review of this
round, L4): the wall asks glibc itself with mallopt() as it starts, before its first thread, where whoever started it set
neither, nor either in GLIBC_TUNABLES. Nothing on another system or C library; what fails is said in the log.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import __main__ as starter
from qkvm import _allocator, cli

APP = Path(__file__).resolve().parent.parent


class Libc:
    """A C library that notes what mallopt() was asked, and answers `answer` (1: done, as glibc does)."""

    def __init__(self, answer: int = 1) -> None:
        self.asked: list[tuple[int, int]] = []
        self.answer = answer

    def mallopt(self, parameter: int, value: int) -> int:
        self.asked.append((parameter, value))
        return self.answer


@pytest.fixture
def on_glibc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_allocator, "glibc", lambda: True)


def test_what_is_asked_of_glibc_and_what_whoever_started_the_wall_set_wins(on_glibc: None) -> None:
    both = [(_allocator.M_ARENA_MAX, 2), (_allocator.M_TRIM_THRESHOLD, 131072)]
    for environment, asked in (
        ({}, both),
        ({"MALLOC_ARENA_MAX": "4"}, both[1:]),
        ({"MALLOC_TRIM_THRESHOLD_": "1"}, both[:1]),
        ({"GLIBC_TUNABLES": "glibc.malloc.arena_max=8"}, both[1:]),
        ({"GLIBC_TUNABLES": "glibc.malloc.tcache_count=0:glibc.malloc.trim_threshold=99"}, both[:1]),
        ({"MALLOC_ARENA_MAX": "2", "MALLOC_TRIM_THRESHOLD_": "131072"}, []),  # (what the starter of 0.4.0 sets: glibc took it)
        ({"GLIBC_TUNABLES": "glibc.malloc.arena_max=8:glibc.malloc.trim_threshold=99"}, []),
    ):
        libc = Libc()
        done, said = _allocator.apply(environment, libc)
        assert libc.asked == asked and said == [] and len(done) == len(asked), (environment, libc.asked, said)
    # What glibc refuses, or a C library without mallopt, is said; nothing is raised.
    done, said = _allocator.apply({}, Libc(answer=0))
    assert done == [] and len(said) == 1 and "refused arena_max, trim_threshold" in said[0], said
    done, said = _allocator.apply({}, object())
    assert done == [] and len(said) == 1 and "could not be made" in said[0], said
    # The same values as the starter's.
    assert (_allocator.ARENAS, _allocator.TRIM_THRESHOLD) == (starter.ARENAS, starter.TRIM_THRESHOLD)


def test_nothing_is_asked_of_another_c_library(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = Libc()
    monkeypatch.setattr(_allocator.sys, "platform", "win32")
    assert _allocator.apply({}, libc) == ([], []) and libc.asked == []
    monkeypatch.setattr(_allocator.sys, "platform", "linux")
    monkeypatch.setattr(_allocator.os, "confstr", lambda name: None, raising=False)  # (musl, as on Alpine)
    assert _allocator.apply({}, libc) == ([], []) and libc.asked == []


def test_the_walls_start_asks_before_its_first_thread_and_says_what_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    from tests.test_wall import port_to_listen_on

    order: list[str] = []
    monkeypatch.setattr(_allocator, "apply", lambda *given, **said: (order.append("asked"), ([], ["glibc's malloc refused arena_max: memory freed may pile up faster"]))[1])
    setup = cli.setup_logging
    monkeypatch.setattr(cli, "setup_logging", lambda *given, **said: (order.append("logging"), setup(*given, **said))[1])
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)  # (if it gets as far as serving, it has started)
    data = tmp_path / "data"
    try:
        assert cli.main(["--data-dir", str(data), "--port", str(port_to_listen_on()), "--bind", "local"]) == 0
    finally:
        cli.stop_logging()
    assert order[:2] == ["asked", "logging"], order  # (before the log's own thread, the first the wall starts)
    assert "glibc's malloc refused arena_max" in (data / "qkvm.log").read_text(encoding="utf-8")


# Sixteen threads that allocate at once, and the arenas glibc made for them, as malloc_info counts them.
ARENAS_SEEN = r"""
import ctypes, sys, tempfile, threading
if sys.argv[1] == "set":
    from qkvm import _allocator
    print("SET", _allocator.apply())
libc = ctypes.CDLL(None)
libc.fdopen.restype = ctypes.c_void_p  # (a FILE *: not an int, which would cut it to 32 bits)
libc.fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
libc.malloc_info.argtypes = [ctypes.c_int, ctypes.c_void_p]
libc.fflush.argtypes = [ctypes.c_void_p]
barrier = threading.Barrier(17)
def work():
    kept = [ctypes.create_string_buffer(2000) for _ in range(2000)]
    barrier.wait()
threads = [threading.Thread(target=work) for _ in range(16)]
for thread in threads:
    thread.start()
barrier.wait()
with tempfile.TemporaryFile("w+") as file:
    stream = libc.fdopen(file.fileno(), b"w")
    libc.malloc_info(0, stream)
    libc.fflush(stream)
    file.seek(0)
    print("ARENAS", file.read().count("<heap nr="))
for thread in threads:
    thread.join()
"""


@pytest.mark.skipif(not _allocator.glibc(), reason="glibc's own arenas, counted by glibc")
def test_glibc_keeps_to_two_arenas_once_asked() -> None:
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("MALLOC_", "GLIBC_TUNABLES"))}
    environment["PYTHONPATH"] = str(APP)

    def arenas(mode: str) -> int:
        done = subprocess.run([sys.executable, "-P", "-c", ARENAS_SEEN, mode], env=environment, capture_output=True, text=True, timeout=120, cwd=APP)
        found = [line for line in done.stdout.splitlines() if line.startswith("ARENAS")]
        assert found, done.stdout + done.stderr
        return int(found[0].split()[1])

    assert arenas("as it comes") > 2  # (what is counted: an arena for each thread that allocates, up to eight a core)
    assert arenas("set") <= 2
