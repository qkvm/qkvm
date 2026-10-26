"""A tag's run that failed can be run again, whichever way GitHub keeps an earlier attempt's artifacts, and the README
says exactly how (delta-g review of web-020-pipe, 1).

After the draft began to hold the image archives to the IDs the image jobs handed on, a run again could stop the draft
for good: no upload said `overwrite`, so where GitHub refuses a name twice in a run the run again failed at its upload
(and the evidence is uploaded even when an image job fails after the scan), and where it keeps the earlier attempt's
archive beside the new one, the draft refused that one. Now every upload of the tag's run (and of Tests, and of the
shared action) replaces one of its name, every reader holds what it reads to its maker's outputs, and the draft lets
an earlier attempt's archive (a lower ID) be while it refuses a later one (image-digests.py's tests). The README says
which run again to use when, that after the signed files' one day `sign` is run again with "Re-run this job", and
what never to do.
"""
from __future__ import annotations

import re

from tests.workflow_text import APP, SECURITY, WORKFLOWS, jobs, steps


def uploads(text: str) -> list[str]:
    return [step for step in steps(text) if "actions/upload-artifact@" in step]


def test_every_upload_replaces_one_of_its_name() -> None:
    found = 0
    for workflow in (WORKFLOWS / "release.yml", WORKFLOWS / "tests.yml"):
        for name, job in jobs(workflow).items():
            if "steps:" not in job:
                continue
            for step in uploads(job):
                found += 1
                assert re.search(r"^          overwrite: true$", step, flags=re.M), (workflow.name, name)
    shared = uploads((SECURITY / "action.yml").read_text(encoding="utf-8"))
    assert shared and all(re.search(r"^        overwrite: true$", step, flags=re.M) for step in shared)
    assert found >= 6


def publishing() -> str:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    return " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].replace("`", "").split())


def test_the_readme_says_which_run_again_to_use_and_what_never_to_do() -> None:
    text = publishing()
    for said in (
        "If a job of the tag's run fails, use Re-run failed jobs",
        "the signed files are kept one day",
        "open the job sign and use Re-run this job: it signs anew, and signature and draft run after it",
        # (delta-i review, 2) Neither GitHub behaviour is claimed: an approval may or may not be asked again.
        "GitHub may or may not ask again for the approval of an environment when a job that names it runs again",
        "the key then signs again, in a run a person already let it sign in, the same bytes held to the same hashes",
        "no job reaches a secret unless a person let it holds for each run, not for each attempt of it",
        # (The tag run's jobs named exactly: test_a_failed_publication_can_be_run_again.)
        "Never, once the tag has a draft or a published release, use Re-run all jobs in the tag's run",
        "Never make, change or add to a release of the tag by hand",
        "within 30 days",
    ):
        assert said in text, said
    assert "Re-run all jobs signs anew" not in text
    assert "approve release again" not in text
    # (delta-i review, a nit) The IDs are those of each image job's latest successful run, which need not be the
    # latest attempt of the run (Re-run failed jobs leaves an image job that passed as it was).
    assert "the IDs the image jobs of the latest attempt handed on" not in text
    assert "the IDs each image job handed on in its latest successful run" in text


def test_the_workflows_notes_say_the_same_of_an_approval() -> None:
    top = " ".join((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0].replace("#", " ").split())
    assert "unless a person let it in that run (GitHub may or may not ask again when a job of it runs again)" in top
