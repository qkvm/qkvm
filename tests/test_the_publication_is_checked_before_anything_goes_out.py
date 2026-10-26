"""The publication checks everything it will publish before anything goes anywhere, and PyPI comes last (review of
web-020-pipe, F1).

`pypi` and `image` were independent jobs of the publication's run, and an upload to PyPI cannot be undone: a draft
published after the image archives had expired, a run of the tag again after the draft existed (its archives perhaps
replaced), or an approval of the `release` environment refused or let lapse for `image`, left the version on PyPI and
never in the registries. Now a first job, with no secret and no environment, downloads every file of the published
release and checks all of them against the signature, fetches the archives the signed image record names and holds
both to what the scan saw; both publishing jobs wait for it, and PyPI waits for the registries (they can be
corrected; PyPI cannot). The draft's text says by when it must be published.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def test_a_first_job_without_secrets_checks_every_published_file_and_both_archives() -> None:
    every = jobs(RELEASE)
    first = every["published"]
    assert re.search(r"^    if: github\.event_name == 'release'$", first, flags=re.M)
    assert not waits_for(every, "published")
    assert "environment:" not in first and "secrets." not in first, "no secret where the release is checked"
    permissions = re.search(r"^    permissions:\n((?:      .+\n)+)", first, flags=re.M)
    assert permissions and sorted(line.split(":")[0].strip() for line in permissions.group(1).splitlines()) == ["actions", "contents"]
    assert "actions: read" in permissions.group(1) and "contents: read" in permissions.group(1)
    order = steps(first)
    checked = next(index for index, step in enumerate(order) if "image-digests.py from-release" in step)
    step = order[checked]
    download = re.search(r'gh release download "\$TAG" --repo "\$GITHUB_REPOSITORY" --dir "\$RUNNER_TEMP/published"\n', step)
    assert download, "every file of the published release, not a chosen few"
    assert 'case "${path##*/}" in SHA256SUMS|SHA256SUMS.sig) ;; *) files+=("$path") ;; esac' in step
    verify = re.search(r'/usr/bin/python3 -m qkvm\.release verify --all --signed "\$RUNNER_TEMP/published/SHA256SUMS" "\$\{files\[@\]\}"', step)
    assert verify and download.start() < verify.start() < step.index("image-digests.py from-release")
    assert re.search(r'from-release --version "\$\{TAG#v\}" --commit "\$GITHUB_SHA" "\$RUNNER_TEMP/published/qkvm-\$\{TAG#v\}-image\.json" "\$RUNNER_TEMP/records"', step)
    assert re.search(r'^\s*echo "run=\$run" >> "\$GITHUB_OUTPUT"$', step, flags=re.M)
    assert step.startswith("id: checked\n"), "its outputs are named by this step"
    fetched = next(index for index, item in enumerate(order) if "actions/download-artifact@" in item)
    assert fetched > checked and "run-id: ${{ steps.checked.outputs.run }}" in order[fetched]
    held = next(index for index, item in enumerate(order) if "image-digests.py check-archive" in item)
    assert held > fetched
    assert re.search(r'for arch in amd64 arm64; do\s+\(cd "images/release-image-\$arch" && sha256sum --check --strict SHA256SUMS\)\s+'
                     r'python3 \.github/security/image-digests\.py check-archive --arch "\$arch" "\$RUNNER_TEMP/records/scanned-image-\$arch\.json" "images/release-image-\$arch/image\.tar"', order[held])


def test_both_publishing_jobs_wait_for_it_and_pypi_comes_last() -> None:
    every = jobs(RELEASE)
    assert "published" in waits_for(every, "image")
    assert {"published", "image"} <= waits_for(every, "pypi"), "the registries can be corrected; PyPI cannot"


def test_the_draft_says_by_when_it_must_be_published() -> None:
    draft = "\n".join(steps(jobs(RELEASE)["draft"]))
    # (The date is when the archives really expire, less a margin: test_the_draft_says_when_its_archives_really_expire.)
    assert re.search(r'until=\$\(python3 \.github/security/image-digests\.py publish-before "\$RUNNER_TEMP/artifacts\.json" --margin-days 2 '
                     r'--artifact-id "amd64=\$AMD64_ARTIFACT" --artifact-id "arm64=\$ARM64_ARTIFACT"\)', draft)
    assert re.search(r'--notes "[^"\n]*Publish this draft before \$until[^"\n]*"', draft)
