"""Runs tests the way a busy computer runs them, so that a failure that comes only under load happens on purpose.

    python tools/under_load.py [options] [-- pytest arguments]

Run from the folder that holds pyproject.toml, with the Python the tests are run with. What it can add, alone or
together:

    --copies N      N copies of the same pytest run at once, each with a folder of its own for its files
    --burners N     N processes beside them that each keep a core busy
    --cores LIST    everything above held to these cores (0-3, or 0,2,4-5): the tests and the burners share them
    --late MS[:EVERY]
                    every event loop in the tests' processes (the wall's, each stand-in device's, a test's own)
                    is held up MS milliseconds every EVERY milliseconds (0: at every turn of the loop; 10 when it
                    is left out), as when the thread that runs it gets no core for that long
    --repeat N      all of that N times over
    --left-running  say after each test the threads it left running (what it left takes time from every test after it)

It says how each run ended, and at the end how often each test failed, with the whole output of every run kept in
--out (a new folder under the system's temporary folder where it is left out). Each failure is written into that
output as it happens, whole, and not only at the end of the run: a run that is stopped keeps what it found. A test
that fails here and passes alone takes something for granted about time: the README's Development chapter says what
to do about it.

The same file is the pytest plugin that does those (`-p under_load`, with this folder on PYTHONPATH: the loops made late
where QKVM_LATE says MS:EVERY, the threads said where QKVM_LEFT_RUNNING is set); the runner passes it to every copy.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FAILED = re.compile(r"^(FAILED|ERROR) (\S+)")
AS_IT_HAPPENED = "!!! failed as it happened:"


# --- the plugin: every event loop late, and each failure said at once -------------------------------------------


def pytest_configure(config: Any) -> None:
    """(pytest's hook, where this file is loaded as a plugin.)"""
    said = os.environ.get("QKVM_LATE", "")
    if said:
        make_loops_late(*parse_late(said))


def pytest_report_header(config: Any) -> str:
    """(pytest's hook: the first lines of a run say whether its loops are made late, and by how much.)"""
    held, every = parse_late(os.environ.get("QKVM_LATE", "") or "0")
    return f"every event loop held up {held:g} ms every {every:g} ms" if held else "event loops as they are"


_BEFORE: set[int] = set()


def pytest_runtest_logstart(nodeid: str, location: Any) -> None:
    """(pytest's hook: the threads alive before a test begins, for QKVM_LEFT_RUNNING.)"""
    _BEFORE.clear()
    _BEFORE.update(thread.ident or 0 for thread in threading.enumerate())


def pytest_runtest_logreport(report: Any) -> None:
    """(pytest's hook: a failure is written out whole as it happens, with the moment it happened. And where
    QKVM_LEFT_RUNNING is set, a test that leaves threads running once it is torn down is said, with their names: what it
    left goes on taking the computer's time in every test after it.)"""
    if report.failed:
        print(f"\n{AS_IT_HAPPENED} {report.nodeid} ({report.when}, {time.strftime('%H:%M:%S')}, after {report.duration:.1f} s)\n{report.longreprtext}\n", flush=True)
    if report.when == "teardown" and os.environ.get("QKVM_LEFT_RUNNING"):
        left = [thread.name for thread in threading.enumerate() if (thread.ident or 0) not in _BEFORE]
        if left:
            print(f"\n!!! left running after {report.nodeid}: {', '.join(sorted(left))}", flush=True)


def parse_late(text: str) -> tuple[float, float]:
    """MS or MS:EVERY, in milliseconds."""
    held, _, every = text.partition(":")
    return float(held), float(every) if every else 10.0


def make_loops_late(held_ms: float, every_ms: float) -> None:
    """From now on, every event loop that runs in this process is held up `held_ms` every `every_ms` (0: every turn).

    The thread that runs it sleeps meanwhile, as one that gets no core does; the other threads of the process go on.
    One chain of holdings per loop, however often the loop is started again."""
    running = asyncio.BaseEventLoop.run_forever
    if getattr(running, "made_late", False):
        return
    held, every = held_ms / 1000.0, every_ms / 1000.0
    lock = threading.Lock()

    def hold(loop: asyncio.AbstractEventLoop) -> None:
        time.sleep(held)
        if loop.is_closed():
            return
        if every <= 0:
            loop.call_soon(hold, loop)
        else:
            loop.call_later(every, hold, loop)

    def run_forever(self: asyncio.BaseEventLoop) -> None:
        with lock:
            first = not getattr(self, "_made_late", False)
            self._made_late = True  # type: ignore[attr-defined]
        if first:
            self.call_soon(hold, self)
        running(self)

    run_forever.made_late = True  # type: ignore[attr-defined]
    asyncio.BaseEventLoop.run_forever = run_forever  # type: ignore[method-assign]


# --- the runner ----------------------------------------------------------------------------------------------


def parse_cores(text: str) -> list[int]:
    cores: list[int] = []
    for part in text.split(","):
        first, _, last = part.strip().partition("-")
        cores.extend(range(int(first), int(last or first) + 1))
    if not cores:
        raise SystemExit("--cores names no core")
    return sorted(set(cores))


def hold_to(cores: list[int]) -> None:
    """Hold this process to these cores; what it starts from now on inherits that."""
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, cores)
    elif sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        if not kernel32.SetProcessAffinityMask(kernel32.GetCurrentProcess(), sum(1 << core for core in cores)):
            raise SystemExit(f"this process could not be held to cores {cores} (Windows error {ctypes.get_last_error()})")
    else:
        raise SystemExit("this system does not let a program choose its cores: leave --cores out")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run tests the way a busy computer runs them.", epilog="Everything after -- goes to pytest.")
    parser.add_argument("--copies", type=int, default=1, help="copies of the pytest run at once (1)")
    parser.add_argument("--burners", type=int, default=0, help="processes that each keep a core busy (0)")
    parser.add_argument("--cores", help="hold the tests and the burners to these cores, as 0-3 or 0,2,4-5 (all)")
    parser.add_argument("--late", help="hold every event loop up MS milliseconds every EVERY ms, as MS:EVERY (EVERY 0: at every turn)")
    parser.add_argument("--repeat", type=int, default=1, help="do it all this many times (1)")
    parser.add_argument("--left-running", action="store_true", help="say after each test the threads it left running")
    parser.add_argument("--out", type=Path, help="where the output of each run is kept (a new temporary folder)")
    parser.add_argument("pytest", nargs=argparse.REMAINDER, help="the pytest arguments, after --")
    options = parser.parse_args()
    args = options.pytest[1:] if options.pytest[:1] == ["--"] else options.pytest
    out = options.out or Path(tempfile.mkdtemp(prefix="under_load_"))
    out.mkdir(parents=True, exist_ok=True)

    if options.cores:
        hold_to(parse_cores(options.cores))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(HERE), env.get("PYTHONPATH")]))
    env.pop("QKVM_LATE", None)
    env.pop("QKVM_LEFT_RUNNING", None)
    if options.left_running:
        env["QKVM_LEFT_RUNNING"] = "1"
    if options.late:
        parse_late(options.late)  # (said wrong, it fails here and not in every copy)
        env["QKVM_LATE"] = options.late
    print(
        f"{options.copies} cop{'y' if options.copies == 1 else 'ies'} at once, {options.burners} burner(s), cores {options.cores or 'all'},"
        f" loops late {options.late or 'no'}; Python {sys.version.split()[0]}; output in {out}",
        flush=True,
    )

    burners = [subprocess.Popen([sys.executable, "-I", "-c", "while True: pass"]) for _ in range(options.burners)]
    failures: Counter[str] = Counter()
    bad_runs = 0
    copies: list[tuple[str, Any, subprocess.Popen[bytes]]] = []
    try:
        for run in range(1, options.repeat + 1):
            began = time.monotonic()
            copies = []
            for copy in range(1, options.copies + 1):
                name = f"run{run}_copy{copy}"
                kept = open(out / f"{name}.txt", "w", encoding="utf-8", errors="replace")  # (closed below, once the copy has ended)
                command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "under_load", f"--basetemp={out / name}", *args]
                copies.append((name, kept, subprocess.Popen(command, cwd=ROOT, env=env, stdout=kept, stderr=subprocess.STDOUT)))
            for name, kept, process in copies:
                code = process.wait()
                kept.close()
                text = (out / f"{name}.txt").read_text(encoding="utf-8", errors="replace").splitlines()
                failed = [match.group(2) for line in text if (match := FAILED.match(line))]
                failures.update(failed)
                bad_runs += code != 0
                summary = next((line for line in reversed(text) if " in " in line and ("passed" in line or "failed" in line or "error" in line)), "(no summary)")
                print(f"{name}: exit {code} after {time.monotonic() - began:.0f} s: {summary.strip('= ')}", flush=True)
                for test in failed:
                    print(f"    {test}", flush=True)
    finally:
        for _, _, process in copies:
            if process.poll() is None:
                process.kill()
        for burner in burners:
            burner.kill()
        for burner in burners:
            burner.wait()
    runs = options.repeat * options.copies
    print(f"{runs - bad_runs} of {runs} runs passed", flush=True)
    for test, count in failures.most_common():
        print(f"  {count:3d} x {test}", flush=True)
    return 1 if bad_runs else 0


if __name__ == "__main__":
    sys.exit(main())
