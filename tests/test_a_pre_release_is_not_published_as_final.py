"""A release ticked "pre-release" when it is published goes nowhere (second review of web-020-pipe, 2).

The publication took any published release of a v* tag as final: one ticked "pre-release" went to PyPI as the
version and could take the image tags. The draft is made as a final release; a pre-release is no state this
workflow publishes, so the publication's first job refuses it before anything goes out.
"""
from __future__ import annotations

import re

from tests.workflow_text import APP, WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def test_the_publications_first_step_refuses_a_pre_release() -> None:
    every = jobs(RELEASE)
    first = steps(every["published"])[0]
    assert "PRERELEASE: ${{ github.event.release.prerelease }}" in first, first
    assert re.search(r'if \[ "\$PRERELEASE" != "false" \]; then\n\s+echo "[^"\n]*pre-release[^"\n]*" >&2\n\s+exit 1\n\s+fi', first), first
    for name in ("image", "pypi"):
        assert "published" in waits_for(every, name), name


def test_the_readme_says_it_is_refused_and_what_mends_it() -> None:
    # (Third review, 5: the publication's event says pre-release whatever is changed afterwards, so a run again is
    # refused again; the release is immutable; only a new version mends it.)
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].split())
    assert "is refused" in publishing[publishing.index("Set as a pre-release") :][:400]
    assert "only a new version mends it" in publishing and "refused again" in publishing
