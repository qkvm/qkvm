"""glibc's malloc, held to two arenas and a fixed trim threshold in the wall's own process (Linux with glibc only).

On Linux with glibc the soaks' wall grew 1 to 3 MB an hour while Python's own memory stayed level: memory freed and kept by
malloc, fragmented over its arenas. The starter of 0.4.0 sets MALLOC_ARENA_MAX and MALLOC_TRIM_THRESHOLD_ in the wall's
environment (__main__.allocator), and that is all a wall started by it needs. But a wall that came to 0.4.0 by Settings >
Updates runs the starter it was installed with, which an in-app update cannot replace, and that sets neither: so the wall
itself asks glibc for the same with mallopt() as it starts, before it starts a thread, wherever whoever started it set
neither (MALLOC_ARENA_MAX, MALLOC_TRIM_THRESHOLD_, or either in GLIBC_TUNABLES: theirs win, each by itself). Nothing on any
other system, nor with another C library (musl, as on Alpine). What cannot be set is said in the log, and the wall starts.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any

M_TRIM_THRESHOLD = -1  # glibc's <malloc.h>
M_ARENA_MAX = -8
ARENAS = 2
# Set, the threshold is also fixed (glibc's own grows to 32 MB, and with it the size from which a block is a mapping of its
# own). What a farm wall of 250 stand-ins did with each, 2.5 hours: see __main__.TRIM_THRESHOLD, which this is the same as.
TRIM_THRESHOLD = 131072


def glibc() -> bool:
    """Whether this is Linux with glibc."""
    asked = getattr(os, "confstr", None)
    if not sys.platform.startswith("linux") or asked is None:
        return False
    try:
        return str(asked("CS_GNU_LIBC_VERSION") or "").startswith("glibc")
    except (ValueError, OSError):
        return False


def wanted(environment: Mapping[str, str]) -> list[tuple[int, int, str]]:
    """What is still to be asked of mallopt, given what whoever started the wall set: (parameter, value, name)."""
    tunables = {part.split("=", 1)[0].strip() for part in environment.get("GLIBC_TUNABLES", "").split(":") if "=" in part}
    asks = []
    if "MALLOC_ARENA_MAX" not in environment and "glibc.malloc.arena_max" not in tunables:
        asks.append((M_ARENA_MAX, ARENAS, "arena_max"))
    if "MALLOC_TRIM_THRESHOLD_" not in environment and "glibc.malloc.trim_threshold" not in tunables:
        asks.append((M_TRIM_THRESHOLD, TRIM_THRESHOLD, "trim_threshold"))
    return asks


def apply(environment: Mapping[str, str] | None = None, libc: Any = None) -> tuple[list[str], list[str]]:
    """Ask glibc for what is wanted (`libc`: the C library to ask, for the tests). Returns what was set (names) and what is to
    be said in the log as a warning (where something could not be)."""
    if not glibc():
        return [], []
    asks = wanted(os.environ if environment is None else environment)
    if not asks:
        return [], []
    try:
        if libc is None:
            import ctypes

            libc = ctypes.CDLL(None)  # (the C library this Python runs on, loaded already)
            libc.mallopt.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.mallopt.restype = ctypes.c_int
        mallopt = libc.mallopt
    except Exception as ex:  # (no ctypes in this Python, no mallopt in this C library: any of them)
        return [], [f"glibc's malloc settings could not be made here ({type(ex).__name__}: {ex}): memory freed may pile up faster"]
    done: list[str] = []
    failed: list[str] = []
    for parameter, value, name in asks:
        try:
            (done if mallopt(parameter, value) == 1 else failed).append(name)
        except Exception:
            failed.append(name)
    said = [f"glibc's malloc refused {', '.join(failed)}: memory freed may pile up faster"] if failed else []
    return done, said
