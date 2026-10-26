"""Every artifact is downloaded by its exact name, never by a pattern (fresh review of web-020-pipe, 5).

`sign` took the scans with `pattern: container-security-*`, and `published` and `image` the archives with
`pattern: release-image-*`: an artifact added to the run under a name the pattern matches landed in the job's folder
beside the ones that were made (nothing read it, but nothing kept it out). Now each download names one artifact, made
by one job, into a folder of its own, and nothing else can land anywhere.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
TESTS = WORKFLOWS / "tests.yml"


def downloads(job: str) -> list[str]:
    return [step for step in steps(job) if "actions/download-artifact@" in step]


def test_no_download_takes_a_pattern() -> None:
    for workflow in (RELEASE, TESTS):
        for name, job in jobs(workflow).items():
            if "steps:" not in job:
                continue
            for step in downloads(job):
                assert "pattern:" not in step and "merge-multiple:" not in step, (workflow.name, name)
                assert re.search(r"^\s*name: [A-Za-z0-9_.-]+$", step, flags=re.M), (workflow.name, name, "one exact name")


def test_the_scans_and_the_archives_are_each_taken_by_name_into_a_folder_of_their_own() -> None:
    every = jobs(RELEASE)
    taken = {(match.group(1), match.group(2)) for step in downloads(every["sign"])
             for match in [re.search(r"name: (\S+)\n\s*path: (\S+)", step)] if match}
    assert {("container-security-amd64", "evidence/container-security-amd64/"),
            ("container-security-arm64", "evidence/container-security-arm64/")} <= taken
    for name, run in (("published", "${{ steps.checked.outputs.run }}"), ("image", "${{ needs.published.outputs.run }}")):
        fetched = downloads(every[name])
        assert len(fetched) == 2, name
        for arch, step in zip(("amd64", "arm64"), fetched, strict=True):
            assert re.search(rf"name: release-image-{arch}\n\s*path: images/release-image-{arch}/\n", step), (name, arch)
            assert f"run-id: {run}" in step and "github-token: ${{ github.token }}" in step, (name, arch)
