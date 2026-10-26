"""Every commit builds and checks the image on the runners the release's image jobs use (delta-g review of
web-020-pipe, 3).

The Tests job `image` ran its amd64 leg on ubuntu-latest while the release's `images_amd64` runs on ubuntu-24.04: a
commit could pass Tests on one Ubuntu release and its tag fail on the other. Now each leg runs on the runner of the
release's image job of its architecture. The required checks keep their names, "image (amd64)" and "image (arm64)",
before and after: GitHub names a matrix job by its matrix values, here the architecture only, and the job has no name of
its own.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs


def runner(job: str) -> str:
    found = re.search(r"^    runs-on: (.+)$", job, flags=re.M)
    assert found, job
    return found.group(1).strip()


def test_each_leg_runs_on_the_runner_of_the_releases_image_job() -> None:
    release, tests = jobs(WORKFLOWS / "release.yml"), jobs(WORKFLOWS / "tests.yml")
    amd64, arm64 = runner(release["images_amd64"]), runner(release["images_arm64"])
    assert (amd64, arm64) == ("ubuntu-24.04", "ubuntu-24.04-arm")
    assert runner(tests["image"]) == f"${{{{ matrix.arch == 'arm64' && '{arm64}' || '{amd64}' }}}}"


def test_the_required_checks_keep_their_names() -> None:
    image = jobs(WORKFLOWS / "tests.yml")["image"]
    assert not re.search(r"^    name:", image, flags=re.M), "a name of its own would rename the checks"
    assert re.search(r"^      matrix:\n        arch: \[amd64, arm64\]\n    steps:", image, flags=re.M), "the architecture is the only matrix value"
    required = (SECURITY / "check-required-ci.py").read_text(encoding="utf-8")
    assert '"image (amd64)", "image (arm64)"' in required
