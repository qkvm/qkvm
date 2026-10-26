"""Three small things of the third review of web-020-pipe (7).

The security README still said the job that makes the draft signs (it is `sign`, and `draft` has no key). The image
jobs' concurrency group, release-moving-image-tags, could be the workflow's own group of a run for a tag named
moving-image-tags (that group is release-<tag>); it has a name no tag's group can be. And the comment on the runners
said they name a runner image; they name an Ubuntu release, whose image GitHub still updates every week.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs


def test_the_security_readme_says_who_signs_and_who_makes_the_draft() -> None:
    first = next(part for part in (SECURITY / "README.md").read_text(encoding="utf-8").split("\n\n") if part.startswith("Releases are made draft first."))
    assert "the job that makes the draft release waits" not in first
    assert "`sign`" in first and "`signature`" in first and "`draft`" in first, first[:400]


def test_the_image_jobs_group_is_no_tags_group() -> None:
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    workflow_group = re.search(r"^concurrency:\n  group: ([^$\n]*)\$\{\{", text, flags=re.M)
    assert workflow_group and workflow_group.group(1) == "release-"
    job_group = re.search(r"^    concurrency:\n      group: (\S+)$", jobs(WORKFLOWS / "release.yml")["image"], flags=re.M)
    assert job_group and not job_group.group(1).startswith(workflow_group.group(1)), job_group.group(1) if job_group else None


def test_the_runner_comment_says_it_names_an_ubuntu_release_not_an_image() -> None:
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    comment = " ".join(text[: text.index("\njobs:\n")].rsplit("\n\n", 1)[-1].replace("#", " ").split())
    assert "Ubuntu release" in comment and "every week" in comment, comment
