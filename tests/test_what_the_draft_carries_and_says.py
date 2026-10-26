"""What the draft carries and what the README says of making it (review of web-020-pipe, the further points).

The tag was pasted into the programs given to jq (`select(.tag_name == "$TAG")`): a tag is made by an admin, but a
program built from text is a program that text can change; jq is now handed the tag as a value (`--arg`). What each
image said of the native code the scanner cannot see is kept with the release itself, in its signed image record, not
only in an artifact that expires. And the README says what a run of the draft job again depends on: GitHub's window
for running a run again, and the repository's artifact retention, which must be at least the 90 days the archives
are asked to be kept.
"""
from __future__ import annotations

import re

from tests.workflow_text import APP, WORKFLOWS, jobs, steps, uncommented

RELEASE = WORKFLOWS / "release.yml"


def test_no_jq_program_is_built_from_the_tag() -> None:
    text = uncommented(RELEASE.read_text(encoding="utf-8"))
    for line in text.splitlines():
        if re.search(r"\bjq\b|--jq\b", line):
            # On a line that runs jq, the tag is only ever handed to it as a value.
            assert "$TAG" not in line.replace('--arg tag "$TAG"', ""), line.strip()
            assert not re.search(r'--jq "[^"]*\$', line), line.strip()
    assert '\\"$TAG\\"' not in text
    draft = "\n".join(steps(jobs(RELEASE)["draft"]))
    assert draft.count("""jq --arg tag "$TAG" '.[] | select(.tag_name == $tag) | .id'""") == 2


def test_the_signed_image_record_keeps_what_each_image_said_of_its_native_code() -> None:
    signing = "\n".join(steps(jobs(RELEASE)["sign"]))
    record = signing[signing.index("image-digests.py release-record") :].split("\n\n", 1)[0]
    for arch in ("amd64", "arm64"):
        assert f"--native evidence/container-security-{arch}/native-versions.json" in record, arch
        assert f"evidence/container-security-{arch}/scanned-image.json" in record, arch


def test_the_readme_says_what_a_run_again_and_the_archives_depend_on() -> None:
    readme = (APP / "README.md").read_text(encoding="utf-8")
    publishing = " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].split())
    assert "within 30 days" in publishing and "run again" in publishing
    assert "artifact and log retention" in publishing and "at least 90 days" in publishing
