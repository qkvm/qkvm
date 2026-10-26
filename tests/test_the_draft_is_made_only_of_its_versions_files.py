"""The draft is made only of its version's files, and a version has no leading zeros (third review of web-020-pipe, 6).

The draft was made before the "exactly these three files" check: a tag like v0.2.01 passed the tag's check while the
build named the files 0.2.1 (packaging normalises versions), and the draft existed, unchecked, until the read-back
refused it. Now the tag's pattern refuses a number with a leading zero, the draft job checks the names on the signed
list before it makes the draft (and again on what the draft holds), and the README says to publish only a draft
whose run is green.
"""
from __future__ import annotations

import importlib.util
import re

import pytest

from tests.workflow_text import APP, SECURITY, WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
THREE_NAMES = 'test "$listed" = "qkvm-${TAG#v}-image.json qkvm-${TAG#v}-py3-none-any.whl qkvm-${TAG#v}.tar.gz "'


def tag_pattern() -> str:
    first = steps(jobs(RELEASE)["tested_commit"])[0]
    found = re.search(r"^\s*version='([^']+)'$", first, flags=re.M)
    assert found and '[[ "$TAG" =~ $version ]]' in first, first
    return found.group(1)


@pytest.mark.parametrize("tag", ["v0.2.0", "v1.10.3", "v10.0.0", "v0.0.1"])
def test_a_version_tag_passes(tag: str) -> None:
    assert re.fullmatch(tag_pattern(), tag)


@pytest.mark.parametrize("tag", ["v0.2.01", "v01.2.3", "v0.02.3", "v0.2", "v0.2.0.1", "v0.2.0-rc1", "0.2.0", "v0.2.0 ", "V0.2.0"])
def test_any_other_tag_is_refused(tag: str) -> None:
    assert not re.fullmatch(tag_pattern(), tag)


def test_the_image_record_refuses_a_leading_zero_too() -> None:
    spec = importlib.util.spec_from_file_location("image_digests", SECURITY / "image-digests.py")
    assert spec and spec.loader
    digests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(digests)
    with pytest.raises(digests.Refused, match="version"):
        digests.release_record("0.2.01", "a" * 40, 1, [], [])


def test_the_names_are_checked_before_the_draft_is_made() -> None:
    order = steps(jobs(RELEASE)["draft"])
    before = next(index for index, step in enumerate(order) if 'awk \'{print $2}\' release/SHA256SUMS' in step)
    made = next(index for index, step in enumerate(order) if "gh release create" in step)
    assert before < made and THREE_NAMES in order[before]
    assert THREE_NAMES in order[made], "and again on what the draft holds"


def test_the_readme_says_to_publish_only_a_draft_whose_run_is_green() -> None:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].split())
    assert "publish only a draft whose run is green" in publishing.lower()
