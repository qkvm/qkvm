"""The README says what to do when a job of the publication's run fails, and its "never" names the tag run's jobs
(delta-i review of web-020-pipe, 1).

Nothing said what to do when `published`, `image` or `pypi` failed, and the sentence that forbade running "an image
job" again once a draft exists read as forbidding the very mend, as the publication's job is called `image` (the tag
run's are images_amd64 and images_arm64). On a first release a wrong Docker Hub token or a ghcr.io package without
write access is the likeliest failure: `image` fails and `pypi` is skipped. Now the README says, for each, that Re-run
failed jobs in the publication's run is safe and why, what is known of PyPI and a file sent again (as far as it is
known), and names the tag run's jobs exactly in the "never", with Re-run this job on tested_commit or build, which runs
the image jobs again too.
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS, jobs


def publishing() -> str:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    return " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].replace("`", "").split())


def test_the_readme_says_what_to_do_for_each_failing_publication_job() -> None:
    text = publishing()
    for said in (
        "If a job of the publication's run fails, mend what it says and use Re-run failed jobs in that run (the "
        "publication's run, not the tag's): that is safe for each of its jobs.",
        "published failed: nothing has gone anywhere",
        "image failed",
        "a wrong Docker Hub token or a ghcr.io package without write access for this repository; pypi is then skipped",
        "pypi failed: run it again",
        "PyPI never takes a second, different file under a name it has had, even one deleted since",
        "as far as is known",
    ):
        assert said in text, said


def test_the_never_names_the_tag_runs_jobs() -> None:
    every = jobs(WORKFLOWS / "release.yml")
    assert {"tested_commit", "build", "images_amd64", "images_arm64", "image"} <= set(every)
    text = publishing()
    assert "or run an image job again" not in text
    assert ("Never, once the tag has a draft or a published release, use Re-run all jobs in the tag's run, or run "
            "images_amd64 or images_arm64 again, or a job they wait for (tested_commit, build: Re-run this job on either "
            "runs the image jobs again too, as it runs again every job that waits for it)") in text


def test_the_readme_says_that_a_version_is_lost_where_the_never_is_done() -> None:
    # (delta-i review, 4) With overwrite on every upload, the forbidden run again replaces the archives the signed
    # record names: once the release is published, the version can then never be published. (The last review: while
    # the tag has only a draft, it can be saved, and the README said it was lost.)
    text = publishing()
    never = text.index("Never, once the tag has a draft or a published release")
    saved = text.index('Done anyway while the tag has only a draft, sign runs again with the new archives and signs them: delete the draft, then use Re-run failed jobs for the draft job that stopped on it (more than a day after sign ran, Re-run this job on sign).')
    lost = text.index('Done once the release is published, the archives its signed record names are replaced (every upload replaces one of its name), and that version is lost: the publication refuses it, and only the next version can be published.')
    assert never < saved < lost < text.index("Never make, change or add to a release of the tag by hand")
    assert "Done anyway, the archives the signed record names are replaced" not in text
