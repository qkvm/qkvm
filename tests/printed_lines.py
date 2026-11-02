"""A line the start printed, run in the shell it is given for.

Where there is no shell to run it in (qKVM's own image has none, on purpose), the test that asks for it is skipped there:
what the line does is held on every system the tests run on outside the image.
"""

from __future__ import annotations

import os
import subprocess

import pytest


def run_printed(line: str) -> subprocess.CompletedProcess[str]:
    if os.name == "posix" and not os.path.exists("/bin/sh"):
        pytest.skip("no shell to run a printed line in (qKVM's image has none)")
    return subprocess.run(line, shell=True, capture_output=True, text=True)
