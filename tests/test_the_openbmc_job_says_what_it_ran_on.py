"""The OpenBMC job says exactly which firmware build it ran on (final review of web-020-pipe, 6).

The required job controllers-openbmc downloads OpenBMC's latest master build of the romulus image, unpinned. It is not
pinned yet: OpenBMC's Jenkins keeps its last three daily builds only and publishes no checksum of them, so a pinned
build number is gone within days and the job, which a release requires, would fail from then on. Until the image is
kept somewhere of the project's own, the job takes the last good build by its number, downloads that build by number,
and writes the number and the SHA-256 of what it ran on into the run's summary, so that a green run says exactly what it
was green on (and a pin can be made from it).
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps


def test_the_build_is_taken_by_number_and_its_checksum_written_down() -> None:
    fetched = next(step for step in steps(jobs(WORKFLOWS / "tests.yml")["controllers-openbmc"]) if "romulus" in step and "curl" in step)
    assert "lastSuccessfulBuild/artifact" not in fetched, "not whatever is newest at the moment of the download"
    assert re.search(r'build=\$\(curl -fsSL "\$job/lastSuccessfulBuild/buildNumber"\)', fetched)
    assert '[[ "$build" =~ ^[0-9]+$ ]]' in fetched
    assert re.search(r'curl -fsSL -o /tmp/romulus\.mtd "\$job/\$build/artifact/openbmc/build/tmp/deploy/images/romulus/obmc-phosphor-image-romulus\.static\.mtd"', fetched)
    assert re.search(r'echo "OpenBMC romulus build \$build, sha256 \$\(sha256sum /tmp/romulus\.mtd \| cut -d \' \' -f 1\)" \| tee -a "\$GITHUB_STEP_SUMMARY"', fetched)
