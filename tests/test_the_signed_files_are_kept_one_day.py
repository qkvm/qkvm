"""The signed files of an unpublished build are kept a day, not 90 (third review of web-020-pipe, 4).

The artifact `signed` holds SHA256SUMS and a valid signature over a build nobody has published yet; on a public
repository anyone can download a run's artifacts, for as long as they are kept, and it was kept 90 days. Only the same
run reads it (the signature and draft jobs), so it is kept one day.
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS, jobs, steps


def test_the_signed_artifact_is_kept_one_day() -> None:
    upload = next(step for step in steps(jobs(WORKFLOWS / "release.yml")["sign"]) if "actions/upload-artifact@" in step)
    assert "name: signed" in upload and "retention-days: 1\n" in upload, upload


def test_the_readme_says_what_that_means_for_a_run_again() -> None:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].split())
    assert "kept one day" in publishing and "signs anew" in publishing
