"""An unlock file behind a link that leads to itself: said, on every Python, and not a traceback.

`unlock.lies_in` asks `path.resolve()` of the unlock file's own path. Before Python 3.13 such a link is
a RuntimeError there and no OSError, and `unlock.secret_in` caught the one only: with --unlock-file (or
QKVM_UNLOCK_FILE) naming a way through a link to itself, the start ended in a traceback with status 1,
the status the starter takes for a version that does not work, and takes an update on trial back for.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import qkvm.__main__ as starter

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="a link needs a right most accounts on Windows have not got")


def typed(folder: Path, shell: str, *words: str, **more: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(Path(starter.__file__).resolve().parent.parent), "HOME": str(folder / "home"), **more}
    env.pop(starter.CHILD, None)
    return subprocess.run(["sh", "-c", shell, "sh", str(folder / "here"), sys.executable, *words], env=env, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("how", ["--unlock-file", "QKVM_UNLOCK_FILE"])
def test_started_with_an_unlock_file_behind_a_link_to_itself_it_says_so(tmp_path: Path, how: str) -> None:
    (tmp_path / "here").mkdir()
    words = ["-P", "-m", "qkvm", "--data-dir", "data", "--port", "1", "--bind", "local"]
    if how == "--unlock-file":
        done = typed(tmp_path, 'cd "$1" && ln -s loop loop && shift && exec "$@"', *words, "--unlock-file", "loop/key")
    else:
        done = typed(tmp_path, 'cd "$1" && ln -s loop loop && shift && exec "$@"', *words, QKVM_UNLOCK_FILE="loop/key")
    print(f">>> qkvm {how} loop/key on Python {sys.version_info.major}.{sys.version_info.minor}: status {done.returncode}; {done.stderr.strip().splitlines()[-1:]}")
    assert "Traceback" not in done.stderr, done.stderr[-600:]
    assert done.returncode == 2, "not 'could not start' to the starter, which takes any other status for a version that does not work"
