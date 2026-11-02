"""The README is published as it is, from app/ alone: it may point only to files that are published beside it, and
it says of a run on GitHub what that run did (register row 24 of 0.2.1: it pointed to FOR-THE-DESKTOP-APP.md, which
lives in the private repository only, and called the OpenBMC run in QEMU not yet seen on GitHub after it had passed
there, in the qualifying run of 0.2.0)."""
from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
README = (APP / "README.md").read_text(encoding="utf-8")


def test_every_file_the_readme_names_is_published_beside_it() -> None:
    named = set(re.findall(r"`([A-Za-z0-9_./-]+\.md)`", README))
    named |= set(re.findall(r"\]\(([A-Za-z0-9_./-]+\.md)(?:#[^)]*)?\)", README))
    assert named, "the README names no file at all: the pattern no longer finds them"
    missing = sorted(name for name in named if not (APP / name).is_file())
    assert missing == []


def test_the_openbmc_run_in_qemu_is_said_to_have_passed_on_github() -> None:
    row = next(line for line in README.splitlines() if line.startswith("| Servers through Redfish, OpenBMC |"))
    assert "not been seen on GitHub" not in row
    assert "passed on GitHub" in row
