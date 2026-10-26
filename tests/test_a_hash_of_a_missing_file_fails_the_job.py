"""A hash of a file that is not there fails the job, not an empty output (fresh review of web-020-pipe, 8).

The image jobs' hashes step wrote `echo "scan=$(sha256sum ... | cut ...)"`: a missing file made sha256sum fail inside
the command substitution, which set -e does not see in an argument, and the job ended green with an empty output.
Now each hash is taken into a variable first (an assignment whose substitution fails stops the step under set -e and
pipefail), must be 64 hex digits, and only then is written out. The step is run here in bash on a folder where one
file is missing, and on one where all are.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps


def hashes_step() -> str:
    every = [step for job in jobs(WORKFLOWS / "release.yml").values() for step in steps(job)]
    every += steps((SECURITY / "action.yml").read_text(encoding="utf-8"))
    found = [step for step in every if step.startswith("id: hashes\n")]
    assert found, "a hashes step"
    return found[0]


def a_bash() -> str | None:
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", "/bin/bash", shutil.which("bash")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


BASH = a_bash()


def run(folder: Path) -> tuple[int, str]:
    step = hashes_step()
    script = step[step.index("run: |\n") + len("run: |\n") :]
    indent = len(script) - len(script.lstrip(" "))
    script = "\n".join(line[indent:] for line in script.splitlines())
    output = folder / "output"
    output.write_text("", encoding="utf-8")
    assert BASH
    done = subprocess.run([BASH, "-c", script], cwd=folder, capture_output=True, text=True, timeout=60,
                          env={**os.environ, "ARCH": "amd64", "GITHUB_OUTPUT": str(output)})
    return done.returncode, output.read_text(encoding="utf-8")


@pytest.mark.skipif(BASH is None, reason="no bash here")
def test_a_missing_file_fails_the_step_and_writes_no_output(tmp_path: Path) -> None:
    evidence = tmp_path / "image-amd64" / "evidence"
    evidence.mkdir(parents=True)
    (tmp_path / "image-amd64" / "image.tar").write_bytes(b"archive")
    (evidence / "scanned-image.json").write_text("{}", encoding="utf-8")
    code, written = run(tmp_path)  # native-versions.json is missing
    assert code != 0 and "native=" not in written, written
    (evidence / "native-versions.json").write_text("{}", encoding="utf-8")
    code, written = run(tmp_path)
    assert code == 0, written
    lines = dict(line.split("=", 1) for line in written.splitlines())
    assert set(lines) == {"archive", "scan", "native"} and all(len(value) == 64 for value in lines.values()), written
