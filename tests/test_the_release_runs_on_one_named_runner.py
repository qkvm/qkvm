"""Every job of the release runs on a named runner image, ubuntu-24.04, not ubuntu-latest (second review of web-020-pipe).

A draft is published up to 88 days after its tag's run. With ubuntu-latest, the publication could run on another
Ubuntu (another openssl, Python, skopeo) than the one its draft was made and tested on. Every job of release.yml names
ubuntu-24.04 (the arm64 images ubuntu-24.04-arm), so that both runs use the runner they were written and tried for;
moving to a newer one is a change made on purpose, here.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, uncommented

RELEASE = WORKFLOWS / "release.yml"
PINNED = {"ubuntu-24.04", "ubuntu-24.04-arm"}


def test_every_release_job_names_ubuntu_24_04() -> None:
    assert "ubuntu-latest" not in uncommented(RELEASE.read_text(encoding="utf-8"))
    for name, job in jobs(RELEASE).items():
        runner = re.search(r"^    runs-on: (.+)$", job, flags=re.M)
        assert runner and runner.group(1).strip() in PINNED, f"{name}: {runner.group(1) if runner else None}"
