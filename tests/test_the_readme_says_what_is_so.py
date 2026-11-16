"""The README is published as it is, from app/ alone: it may point only to files that are published beside it, and
it says of a run on GitHub what that run did (register row 24 of 0.2.1: it pointed to FOR-THE-DESKTOP-APP.md, which
lives in the private repository only, and called the OpenBMC run in QEMU not yet seen on GitHub after it had passed
there, in the qualifying run of 0.2.0)."""
from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
README = (APP / "GUIDE.md").read_text(encoding="utf-8")


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


def told(beginning: str) -> str:
    """The README's bulleted paragraph that begins so, its lines joined."""
    lines = README.splitlines()
    first = next(number for number, line in enumerate(lines) if line.startswith(beginning))
    rest = lines[first + 1 :]
    end = next((number for number, line in enumerate(rest) if not line.startswith("  ")), len(rest))
    return " ".join(" ".join([lines[first], *rest[:end]]).split())


def test_the_readme_says_how_long_a_download_waits_and_how_many_connections_are_kept() -> None:
    # The review of 0.3.2's fixes (two LOWs): the README said that a download went on from the text files after two seconds
    # of a checkpoint (a page after the first waits 15 s since 0.3.2, and goes on from the files after the last entry it was
    # given, each entry once, or is refused), and said a kept connection's 130 s without the number of them held at once,
    # to the admin of a proxy in front as well.
    from qkvm import activity, cli

    index = told("- **The page reads an index of it**")
    assert "and a download goes on from the files" not in index
    assert f"each page after it up to {activity.PAGE_PATIENCE:g} s" in index and "each entry once" in index and "refused with 503" in index
    for said in (told("- **A proxy that keeps its connections to qKVM open"), told("- **Nobody holds a connection for nothing.**")):
        assert f"{cli.SERVER_OPTIONS['timeout_keep_alive']} seconds" in said and f"{cli.IDLE_KEPT_MOST} " in said and "kept longest" in said, said
        # (Fewer where the system allows fewer open files than four times that: cli.idle_kept_most, the independent review of 0.3.2.)
        assert "a quarter of the open files the system allows" in said, said
