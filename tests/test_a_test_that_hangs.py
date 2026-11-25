"""A test that hangs ends the run, and says where every thread was, rather than holding the runner until its job is cancelled.

0.2.2 on GitHub's Windows 3.12: after a test of the activity log nothing more was said for twenty minutes, and the job's
ninety ran out with nothing to show for where it hung (it did not hang again in two runs, nor here). pytest's own
faulthandler gives every test a time (pyproject.toml), and at its end writes out the stack of every thread and stops.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path

APP = Path(__file__).resolve().parent.parent

HANGS = '''
import threading


def test_that_waits_for_ever() -> None:
    threading.Event().wait()
'''


def test_every_test_is_given_a_time_after_which_the_run_ends() -> None:
    said = tomllib.loads((APP / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert 0 < float(said["faulthandler_timeout"]) <= 1800 and said["faulthandler_exit_on_timeout"] is True, said


def test_a_test_that_hangs_ends_the_run_with_where_it_hung(tmp_path: Path) -> None:
    (tmp_path / "test_hangs.py").write_text(HANGS, encoding="utf-8")
    # The run in a folder of its own, its temporary files too: run beside other test processes on Windows (each with a
    # temporary folder of its own beside this one's), it met another's as that one was taken away, and failed on that.
    own = tmp_path / "temp"
    own.mkdir()
    began = time.monotonic()
    # The project's own settings, with the time made two seconds: the stand-in test waits for ever.
    ran = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-c", str(APP / "pyproject.toml"), "--rootdir", str(tmp_path),
         "--confcutdir", str(tmp_path), "--basetemp", str(tmp_path / "basetemp"), "-o", "faulthandler_timeout=2", str(tmp_path / "test_hangs.py")],
        capture_output=True, text=True, timeout=120, cwd=tmp_path, env={**os.environ, "TEMP": str(own), "TMP": str(own), "TMPDIR": str(own)},
    )  # fmt: skip
    assert time.monotonic() - began < 60
    assert ran.returncode != 0, ran.stdout[-2000:]
    said = ran.stdout + ran.stderr
    assert "Timeout" in said and "test_that_waits_for_ever" in said, said[-3000:]
