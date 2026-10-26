"""Whether `latest` and `X.Y` move is decided where they move, one publication at a time (second review of
web-020-pipe, 1).

The publication's first job decided it, and the image job moved the tags later, after the registries' approval:
two versions published close together (a fix to an older line and a new minor) each decided with the other not yet
out, or the image job of an older version run again after a newer one was out used the outputs of its first run, and
`latest` could move back. Now the image job reads which versions are released right before the tags move, and image
jobs run one at a time across every tag (a concurrency group of the job, not the tag's).
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"


def test_image_jobs_run_one_at_a_time_across_every_tag() -> None:
    image = jobs(RELEASE)["image"]
    # (A name no tag's run can have as its own group, release-<tag>: see test_the_small_things_of_the_third_review.)
    assert re.search(r"^    concurrency:\n      group: image-tags-of-every-release\n      cancel-in-progress: false\n", image, flags=re.M), image[:400]


def test_the_image_job_reads_the_released_versions_right_before_the_tags_are_named() -> None:
    order = steps(jobs(RELEASE)["image"])
    newest = next(index for index, step in enumerate(order) if step.startswith("id: newest\n"))
    named = next(index for index, step in enumerate(order) if step.startswith("id: names\n"))
    moved = next(index for index, step in enumerate(order) if "imagetools create" in step)
    assert newest == named - 1 and named < moved, "decided at the last step before the tags are named, and moved after"
    step = order[newest]
    assert 'gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --slurp > "$RUNNER_TEMP/releases.json"' in step
    assert re.search(r'python3 \.github/security/newest-release\.py "\$RUNNER_TEMP/releases\.json" "\$TAG" --github-latest "\$github_latest" >> "\$GITHUB_OUTPUT"', step)
    assert "MINOR: ${{ steps.newest.outputs.minor }}" in order[named]
    assert "LATEST: ${{ steps.newest.outputs.latest }}" in order[named]


def test_nothing_decided_earlier_is_used() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert "needs.published.outputs.latest" not in text and "needs.published.outputs.minor" not in text
    first = jobs(RELEASE)["published"]
    assert "newest-release.py" not in first and "outputs.latest" not in first and "outputs.minor" not in first
