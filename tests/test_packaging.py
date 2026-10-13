"""What installing QKVM pulls in is decided on purpose, not by accident."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

PROJECT = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8"))["project"]

# Every package QKVM asks for, and what for. Each is something to keep up to date, to trust, and to
# answer for when it has a hole. One more needs a reason that fits on a line here, and that the
# standard library or a few lines of our own would not do.
NEEDED = {
    "fastapi": "the routes, and the checking of what a browser sends",
    "starlette": "what fastapi is built on; named for a minimum version without a known hole",
    "uvicorn": "the web server",
    "httpx": "talking to the KVMs, the alert address and GitHub",
    "sniffio": "looked for by httpx on every request; without it, each look costs most of a millisecond",
    "websockets": "keeps a KVM's video stream awake; JetKVM signalling",
    "cryptography": "the vault, the signature on updates, QKVM's own certificate",
    "aiortc": "a JetKVM sends its picture as WebRTC video and nothing else; by far the largest of these, loaded only for a JetKVM",
    "anyio": "used by the above; named for a minimum version without a known hole",
    "idna": "used by the above; named for a minimum version without a known hole",
    "h11": "reads every request, for uvicorn; named for a minimum version without a known hole",
}


def names(requirements: list[str]) -> list[str]:
    return sorted(re.split(r"[\s<>=!~\[;]", requirement, maxsplit=1)[0].lower() for requirement in requirements)


def test_the_packages_asked_for_are_the_few_that_are_needed() -> None:
    assert names(PROJECT["dependencies"]) == sorted(NEEDED)
    # Nothing is left for "extras": whoever installs QKVM can add every device it knows. A JetKVM that
    # answered "install another package first" was the first thing its owner met.
    assert "optional-dependencies" not in PROJECT


def test_each_package_has_a_lowest_version_it_is_known_to_work_with() -> None:
    for requirement in PROJECT["dependencies"]:
        assert ">=" in requirement, f"{requirement}: say from which version on"


def test_the_page_brings_everything_it_needs() -> None:
    # No script, style or font from somebody else's server: nothing to trust, and nothing that tells them who looks.
    static = Path(__file__).parent.parent / "qkvm" / "static"
    page = (static / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"""(src|href)\s*=\s*["'](https?:)?//""", page)
    for sheet in static.glob("*.css"):
        assert not re.search(r"@import|url\(\s*[\"']?(https?:)?//", sheet.read_text(encoding="utf-8")), sheet.name


def test_the_versions_looked_for_at_start_are_the_ones_asked_for_on_installing() -> None:
    # The program checks at every start what pip was told on the day it was installed: an environment put
    # together some other way, or grown old, is told so. Two lists that say the same thing have to.
    from qkvm.cli import SAFE_FROM

    asked = {re.split(r"[\s<>=!~\[;]", requirement, maxsplit=1)[0].lower(): requirement.split(">=", 1)[1] for requirement in PROJECT["dependencies"]}
    for name, minimum in SAFE_FROM.items():
        numbers = tuple(int(part) for part in asked[name].split("."))
        assert numbers + (0,) * (3 - len(numbers)) == minimum, name


def test_a_library_with_a_known_hole_is_named_so_that_it_can_be_updated(monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import cli

    monkeypatch.setattr(cli, "SAFE_FROM", {"pytest": (999, 0, 0), "nothing-of-this-name": (1, 0, 0)})
    found = cli.outdated_libraries()
    # By name, because that is what has to be typed after `pip install --upgrade`; one that is not installed is not an old one.
    assert list(found) == ["pytest"] and found["pytest"].endswith("(safe from 999.0.0)")
