"""The packages are checked before anything is installed beside them (delta review of web-020-pipe, 4).

check-sdist.py ran with the interpreter that twine and the wheel had been installed into, after the suite had run:
whatever they installed could have been imported by it. Now it runs right after the copy is held to the build's
checksum, before any install, as `python -I -S` (no environment variables, no user or site packages: Python's own
library only, which is all it needs).
"""
from __future__ import annotations

from tests.workflow_text import WORKFLOWS, jobs, steps

CHECK = "python -I -S .github/security/check-sdist.py dist/*.whl dist/*.tar.gz"


def test_check_sdist_runs_isolated_right_after_the_hold() -> None:
    order = steps(jobs(WORKFLOWS / "release.yml")["packages"])
    held = next(index for index, step in enumerate(order) if "needs.build.outputs.sums" in step)
    assert CHECK in order[held + 1], order[held + 1]
    assert all("pip install" not in step for step in order[: held + 2]), "nothing installed before"
    every_call = [step for step in order if "check-sdist.py" in step]
    assert every_call == [order[held + 1]], "run once, and only so"
