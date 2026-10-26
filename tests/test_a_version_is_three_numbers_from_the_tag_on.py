"""A version is three numbers from the tag on, and the draft holds exactly its version's files (second review of
web-020-pipe, 3).

The tag's run took a tag like v0.3 or v0.3.0.1 (the image record took any number of parts), and only the
publication refused it, after a person had published an immutable release of it. And that the signed list names
exactly the wheel, the source archive and the image record of the version was checked only at publication. Now the
tag's run refuses any tag but vX.Y.Z first of all, the image record takes three numbers only, and the draft's
read-back checks the three names as the publication does.
"""
from __future__ import annotations

import importlib.util
import re

import pytest

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
THREE_NAMES = 'test "$listed" = "qkvm-${TAG#v}-image.json qkvm-${TAG#v}-py3-none-any.whl qkvm-${TAG#v}.tar.gz "'
LISTED = """listed=$(awk '{print $2}' "$drafted/SHA256SUMS" | LC_ALL=C sort | tr '\\n' ' ')"""


def test_the_tags_run_refuses_any_tag_but_three_numbers_first_of_all() -> None:
    # (The pattern itself, leading zeros refused too, is tried in test_the_draft_is_made_only_of_its_versions_files.)
    first = steps(jobs(RELEASE)["tested_commit"])[0]
    assert re.search(r"version='\^v\(0\|\[1-9\]\[0-9\]\*\)\\\.\(0\|\[1-9\]\[0-9\]\*\)\\\.\(0\|\[1-9\]\[0-9\]\*\)\$'", first), first
    assert re.search(r'\[\[ "\$TAG" =~ \$version \]\] \|\| \{ echo "[^"\n]+" >&2; exit 1; \}', first), first


def test_the_image_record_takes_three_numbers_only() -> None:
    spec = importlib.util.spec_from_file_location("image_digests", SECURITY / "image-digests.py")
    assert spec and spec.loader
    digests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(digests)
    for version in ("0.3", "0.3.0.1", "v0.3.0", "0.3.0rc1"):
        with pytest.raises(digests.Refused, match="version"):
            digests.release_record(version, "a" * 40, 1, [], [])


def test_the_drafts_read_back_checks_the_three_names() -> None:
    made = next(step for step in steps(jobs(RELEASE)["draft"]) if "gh release create" in step)
    assert LISTED in made and THREE_NAMES in made, made[-900:]
    assert made.index("-m qkvm.release verify") < made.index(THREE_NAMES) < made.index("made and checked")
