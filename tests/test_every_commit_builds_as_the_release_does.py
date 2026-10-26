"""Every commit builds as the release does: the same pinned tools, the same commands (delta review of web-020-pipe, 2).

The hash-pinned build without isolation ran first at a release's tag, where a failure costs the version. Now the
required Tests job `package` (Linux, Python 3.13) runs the very install and build the release's build job runs, with
the same requirements file, so that every commit to main proves them before any tag.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps


def build_lines(path_name: str, job: str) -> list[str]:
    step = next(step for step in steps(jobs(WORKFLOWS / path_name)[job]) if "python -m build" in step)
    body = step[step.index("run: |\n") + len("run: |\n") :]
    return [line.strip() for line in body.splitlines() if line.strip()]


def test_the_package_job_builds_with_the_releases_own_commands() -> None:
    released = build_lines("release.yml", "build")
    assert released == [
        "python -m pip install --require-hashes --no-deps --only-binary :all: -r .github/security/build-requirements.txt",
        "python -m build --no-isolation",
    ]
    assert build_lines("tests.yml", "package") == released


def test_that_job_is_linux_python_3_13_and_required() -> None:
    package = jobs(WORKFLOWS / "tests.yml")["package"]
    assert re.search(r"^    runs-on: ubuntu-", package, flags=re.M)
    assert 'python-version: "3.13"' in package
    required = (SECURITY / "check-required-ci.py").read_text(encoding="utf-8")
    assert '"package"' in required
