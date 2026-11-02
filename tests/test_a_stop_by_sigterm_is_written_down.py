"""A wall stopped by SIGTERM (`docker stop`, a service manager, the starter passing it on) ends as one stopped by Ctrl+C
does: "stopped" in its log, and everything logged before it written out (register row 23 of 0.2.1, r1-upgrade).

uvicorn takes SIGTERM while it serves, shuts down cleanly, and then raises the signal again, for whoever had it before.
Nobody had: the process ended there and then, by the signal, before "stopped" was logged and before the thread that
writes the log had written what was still waiting; `docker stop` left the log of a wall that seemed to have died.
Ctrl+C was never so: Python turns SIGINT into KeyboardInterrupt, which the program catches.

The program itself, started as it is started; on Linux and macOS, where a stop is a SIGTERM."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from qkvm import cli
from tests.test_wall import closed_port


@pytest.mark.skipif(sys.platform == "win32", reason="a stop is a SIGTERM on Linux and macOS; on Windows the program is stopped otherwise")
@pytest.mark.parametrize("told", ["the starter", "the wall itself"])
def test_a_wall_stopped_by_sigterm_writes_that_it_stopped(tmp_path: Path, told: str) -> None:
    port, data = closed_port(), tmp_path / "data"
    env = {**os.environ, "PYTHONPATH": str(Path(cli.__file__).resolve().parent.parent), "HOME": str(tmp_path)}
    env.pop("QKVM_CHILD", None)
    module = "qkvm" if told == "the starter" else "qkvm.cli"  # (the starter passes it on to the wall it started)
    wall = subprocess.Popen(
        [sys.executable, "-P", "-m", module, "--data-dir", str(data), "--port", str(port), "--bind", "local"],
        cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        for _ in range(120):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2).read()
                break
            except OSError:
                assert wall.poll() is None, "the program ended before it answered"
                time.sleep(0.25)
        wall.send_signal(signal.SIGTERM)
        ended = wall.wait(30)
    finally:
        if wall.poll() is None:
            wall.kill()
    lines = (data / "qkvm.log").read_text(encoding="utf-8", errors="replace").splitlines()
    print(f">>> SIGTERM to {told}: exit status {ended}; the log ends with {lines[-2:]}")
    assert lines and lines[-1].endswith("qkvm: stopped"), lines[-3:]
    assert ended == 0
