"""Every commit tries the packages as the release does, on the release's runner (fresh review of web-020-pipe, 6).

The required Tests job `package` built with the release's own commands but ran on ubuntu-latest, where the release
builds on ubuntu-24.04, and it neither held the source archive to the wheel (`check-sdist.py`, with Python's own library
only) nor installed the source archive by itself: a commit could pass Tests and its tag still fail there, costing the
version. Now the job runs on the release build's runner and runs both, with the release's own lines, on the packages it
built; it keeps its id, and no name of its own, so the required check is still called `package`.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps

CHECK = "python -I -S .github/security/check-sdist.py dist/*.whl dist/*.tar.gz"


def runner(job: str) -> str:
    found = re.search(r"^    runs-on: (\S+)$", job, flags=re.M)
    assert found, job
    return found.group(1)


def test_the_package_job_runs_on_the_runner_the_release_builds_on() -> None:
    release, tests = jobs(WORKFLOWS / "release.yml"), jobs(WORKFLOWS / "tests.yml")
    assert runner(release["build"]) == runner(release["packages"]) == "ubuntu-24.04"
    assert runner(tests["package"]) == runner(release["build"])
    # The required check's name is the job's id while the job has no name of its own.
    assert not re.search(r"^    name:", tests["package"], flags=re.M)
    assert '"package"' in (SECURITY / "check-required-ci.py").read_text(encoding="utf-8")


def test_it_holds_the_source_archive_to_the_wheel_and_installs_it_by_itself() -> None:
    released = steps(jobs(WORKFLOWS / "release.yml")["packages"])
    assert any(step.rstrip().endswith(f"run: {CHECK}") for step in released), "the release's own line"
    order = steps(jobs(WORKFLOWS / "tests.yml")["package"])
    built = next(index for index, step in enumerate(order) if "python -m build --no-isolation" in step)
    checked = next(index for index, step in enumerate(order) if step.rstrip().endswith(f"run: {CHECK}"))
    twine = next(index for index, step in enumerate(order) if "pip install twine" in step)
    assert built < checked < twine, "before anything is installed beside the packages"
    source = next(step for step in order if "pip install dist/*.tar.gz" in step)
    assert "python -m venv /tmp/from-source\n" in source and "/tmp/from-source/bin/pip install dist/*.tar.gz\n" in source
    assert "runpy.run_path('qkvm/_version.py')['__version__']" in source
    assert 'cd /tmp && test "$(/tmp/from-source/bin/qkvm --version)" = "qkvm $version"' in source
