"""A data folder that has no full name: every line that says where the settings are says it all the same.

The start said "cannot keep settings in data" when the data folder is named from a current folder that
is gone; the lines beside it asked for the full name by themselves:

* `qkvm status`, `qkvm stop` and `qkvm restart` (`cli.ask`) ended in a traceback there.
* A way that leads through a link to itself is, before Python 3.13, a RuntimeError from `Path.resolve()`
  and no OSError: on 3.11 and 3.12 the start ended in a traceback, with status 1, which the starter takes
  for a version that does not work (and takes an update on trial back for).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import qkvm.__main__ as starter

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="on Windows a folder cannot be removed while a program is in it, and a link needs a right most accounts have not got")


def typed(folder: Path, setup: str, *words: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(Path(starter.__file__).resolve().parent.parent), "HOME": str(folder / "home")}
    env.pop(starter.CHILD, None)
    # Prepare the same filesystem state without requiring a shell in the image.
    script = "import os, sys; os.chdir(sys.argv[1]); " + setup + "; os.execv(sys.executable, [sys.executable, *sys.argv[2:]])"
    return subprocess.run([sys.executable, "-P", "-c", script, str(folder / "here"), *words], env=env, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("command", ["status", "stop", "restart"])
def test_asked_from_a_folder_that_is_gone_about_a_data_folder_named_from_there_it_says_so(tmp_path: Path, command: str) -> None:
    (tmp_path / "here").mkdir()
    done = typed(tmp_path, 'os.rmdir(sys.argv[1])', "-P", "-m", "qkvm", command, "--data-dir", "data")
    print(f">>> qkvm {command} --data-dir data, typed in a folder that is gone: status {done.returncode}; {done.stderr.strip().splitlines()[-1:]}")
    assert "Traceback" not in done.stderr, done.stderr[-600:]


def test_started_with_a_data_folder_behind_a_link_to_itself_it_says_so(tmp_path: Path) -> None:
    (tmp_path / "here").mkdir()
    done = typed(tmp_path, 'os.symlink("loop", "loop")', "-P", "-m", "qkvm", "--data-dir", "loop/data", "--port", "1", "--bind", "local")
    print(f">>> qkvm --data-dir loop/data on Python {sys.version_info.major}.{sys.version_info.minor}: status {done.returncode}; {done.stderr.strip().splitlines()[-1:]}")
    assert "Traceback" not in done.stderr, done.stderr[-600:]
    assert done.returncode == 2, "not 'could not start' to the starter, which takes any other status for a version that does not work"
