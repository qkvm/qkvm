"""Every hash a job hands on is taken into a variable first, so that a missing file fails its step (delta-g review of
web-020-pipe, a nit after 465d7ba).

465d7ba mended the image jobs' hashes, but `build`, `sign` and `published` still wrote `echo "x=$(sha256sum ...)"`:
a failing substitution in an argument of echo passes set -e unseen, and the step would hand on an empty hash. Now no
step of the workflows or the shared action writes an output from a substitution in an argument; each hash is taken
into a variable (an assignment whose substitution fails stops the step under set -e and pipefail), must be 64 hex
digits, and only then is written. `sign`'s step is run here in bash with the signature missing, and with both files.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps, uncommented

RELEASE = WORKFLOWS / "release.yml"


def test_no_output_is_written_from_a_substitution_in_an_argument() -> None:
    for path in (RELEASE, WORKFLOWS / "tests.yml", SECURITY / "action.yml"):
        text = uncommented(path.read_text(encoding="utf-8"))
        assert not re.search(r'echo "[A-Za-z_]+=\$\(', text), path.name


def test_each_hash_is_checked_before_it_is_handed_on() -> None:
    every = jobs(RELEASE)
    for job, step_id, names in (("build", "sums", ("sums",)), ("sign", "signed", ("sums", "sig")), ("published", "checked", ("sums",))):
        step = next(item for item in steps(every[job]) if item.startswith(f"id: {step_id}\n"))
        assert "set -euo pipefail" in step, job
        for name in names:
            taken = re.search(rf"^\s*{name}=\$\(sha256sum .+ \| cut -d ' ' -f 1\)$", step, flags=re.M)
            written = step.index(f'echo "{name}=${name}" >> "$GITHUB_OUTPUT"')
            assert taken and taken.start() < written, (job, name)
            checked = re.search(rf'\[\[ [^\n]*"\${name}" =~ \^\[0-9a-f\]\{{64\}}\$ [^\n]*\]\]', step)
            assert checked and taken.start() < checked.start() < written, (job, name)


def a_bash() -> str | None:
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", "/bin/bash", shutil.which("bash")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


BASH = a_bash()


def run_signed_step(folder: Path) -> tuple[int, str]:
    step = next(item for item in steps(jobs(RELEASE)["sign"]) if item.startswith("id: signed\n"))
    script = step[step.index("run: |\n") + len("run: |\n") :]
    indent = len(script) - len(script.lstrip(" "))
    script = "\n".join(line[indent:] for line in script.splitlines())
    output = folder / "output"
    output.write_text("", encoding="utf-8")
    assert BASH
    done = subprocess.run([BASH, "-c", script], cwd=folder, capture_output=True, text=True, timeout=60,
                          env={**os.environ, "GITHUB_OUTPUT": str(output)})
    return done.returncode, output.read_text(encoding="utf-8")


@pytest.mark.skipif(BASH is None, reason="no bash here")
def test_a_missing_signature_fails_the_step_and_writes_nothing(tmp_path: Path) -> None:
    (tmp_path / "release").mkdir()
    (tmp_path / "release" / "SHA256SUMS").write_text("x  y\n", encoding="utf-8")
    code, written = run_signed_step(tmp_path)  # SHA256SUMS.sig is missing
    assert code != 0 and written == "", written
    (tmp_path / "release" / "SHA256SUMS.sig").write_bytes(b"signature")
    code, written = run_signed_step(tmp_path)
    assert code == 0, written
    lines = dict(line.split("=", 1) for line in written.splitlines())
    assert set(lines) == {"sums", "sig"} and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in lines.values()), written
