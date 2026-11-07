"""Every job of the release runs on a named runner image, ubuntu-24.04, not ubuntu-latest (second review of web-020-pipe).

A draft is published up to 88 days after its tag's run. With ubuntu-latest, the publication could run on another
Ubuntu (another openssl, Python, skopeo) than the one its draft was made and tested on. Every job of release.yml names
ubuntu-24.04 (the arm64 images ubuntu-24.04-arm), so that both runs use the runner they were written and tried for;
moving to a newer one is a change made on purpose, here. The trial of the libraries' lock (libraries_tested) runs on each
system the lock is for, and names each runner image as well: Windows as windows-2025.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, uncommented

RELEASE = WORKFLOWS / "release.yml"
PINNED = {"ubuntu-24.04", "ubuntu-24.04-arm"}
TRIED_ON = {"ubuntu-24.04", "ubuntu-24.04-arm", "windows-2025"}  # (the lock's trial: Linux x86-64 and ARM64, Windows)


def test_every_release_job_names_ubuntu_24_04() -> None:
    assert "ubuntu-latest" not in uncommented(RELEASE.read_text(encoding="utf-8"))
    for name, job in jobs(RELEASE).items():
        runner = re.search(r"^    runs-on: (.+)$", job, flags=re.M)
        if runner and runner.group(1).strip() == "${{ matrix.runner }}":
            listed = re.search(r"^        runner: \[(.+)\]$", job, flags=re.M)
            assert name == "libraries_tested" and listed and {each.strip() for each in listed.group(1).split(",")} == TRIED_ON, name
            continue
        assert runner and runner.group(1).strip() in PINNED, f"{name}: {runner.group(1) if runner else None}"
