"""What installing qKVM pulls in is decided on purpose, not by accident."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

PROJECT = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8"))["project"]

# Every package qKVM asks for, and what for. Each is something to keep up to date, to trust, and to
# answer for when it has a hole. One more needs a reason that fits on a line here, and that the
# standard library or a few lines of our own would not do.
NEEDED = {
    "fastapi": "the routes, and the checking of what a browser sends",
    "starlette": "what fastapi is built on; named for a minimum version without a known hole",
    "uvicorn": "the web server",
    "httpx": "talking to the KVMs, the alert address and GitHub",
    "sniffio": "looked for by httpx on every request; without it, each look costs most of a millisecond",
    "websockets": "keeps a KVM's video stream awake; JetKVM signalling",
    "cryptography": "the vault, the signature on updates, qKVM's own certificate",
    "aiortc": "a JetKVM sends its picture as WebRTC video and nothing else; by far the largest of these, loaded only for a JetKVM",
    "av": "direct JPEG decoding and JetKVM video; enforce the audited native-library baseline",
    "anyio": "used by the above; named for a minimum version without a known hole",
    "idna": "used by the above; named for a minimum version without a known hole",
    "dnspython": "used by aiortc's ICE (a JetKVM's .local candidates); named for a minimum version without a known hole",
    "certifi": "outbound TLS trust bundle; excludes the compromised emSign trust chain",
    "h11": "reads every request, for uvicorn, and a server controller's answers on qKVM's own connections; a minimum version without a known hole",
    "packaging": "validates update dependency versions and environment markers before activation",
}


# What a library's floor keeps out: the first version past a hole known in the ones before it, and the advisory. What is
# asked for on installing, and looked for at every start, is at least that (the dependency audit of 2026-11-01).
PAST_KNOWN_HOLES = {
    "websockets": ((17, 4, 0), "GHSA-6m5v-9gmr-5665: endless empty continuation frames, and the client side every device connection uses was not capped"),
    "cryptography": ((50, 0, 2), "50.0.0 and 50.0.1 bundle OpenSSL 4.0.1 and 4.0.2 (CVE-2026-84782 in DTLS, and four more); 50.0.2 bundles 4.0.3"),
    "dnspython": ((2, 9, 0), "CVE-2026-114605: excessive CPU in dns.name.from_wire_parser(), reached through aioice's mDNS lookup of a JetKVM's .local candidates"),
}


def names(requirements: list[str]) -> list[str]:
    return sorted(re.split(r"[\s<>=!~\[;]", requirement, maxsplit=1)[0].lower() for requirement in requirements)


def floors() -> dict[str, tuple[int, ...]]:
    """The lowest version of each package asked for on installing, as three numbers."""
    found = {}
    for requirement in PROJECT["dependencies"]:
        name, _, version = re.split(r"(>=|==)", requirement.split("#")[0].strip(), maxsplit=1)
        numbers = tuple(int(part) for part in version.split("."))
        found[name.strip().lower()] = numbers + (0,) * (3 - len(numbers))
    return found


def test_the_packages_asked_for_are_the_few_that_are_needed() -> None:
    assert names(PROJECT["dependencies"]) == sorted(NEEDED)
    # Nothing is left for "extras": whoever installs qKVM can add every device it knows. A JetKVM that
    # answered "install another package first" was the first thing its owner met.
    assert "optional-dependencies" not in PROJECT


def test_each_package_has_a_lowest_version_it_is_known_to_work_with() -> None:
    for requirement in PROJECT["dependencies"]:
        if requirement.startswith("aiortc"):
            assert requirement == "aiortc==1.15.0", "review the decoder boundary before changing its receiver"
        else:
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

    asked = {re.split(r"[\s<>=!~\[;]", requirement, maxsplit=1)[0].lower(): re.split(r">=|==", requirement, maxsplit=1)[1] for requirement in PROJECT["dependencies"]}
    for name, minimum in SAFE_FROM.items():
        numbers = tuple(int(part) for part in asked[name].split("."))
        assert numbers + (0,) * (3 - len(numbers)) == minimum, name


def test_each_library_with_a_known_hole_is_asked_for_and_looked_for_past_it() -> None:
    from qkvm.cli import SAFE_FROM

    asked = floors()
    for name, (fixed, why) in PAST_KNOWN_HOLES.items():
        assert asked.get(name, (0, 0, 0)) >= fixed, f"pyproject.toml asks for {name} from {asked.get(name)}: {why}"
        assert SAFE_FROM.get(name, (0, 0, 0)) >= fixed, f"the start looks for {name} from {SAFE_FROM.get(name)}: {why}"


def test_a_version_of_two_numbers_is_the_same_as_with_a_third_of_nought(monkeypatch: pytest.MonkeyPatch) -> None:
    # websockets says "17.4": taken as 17, 4 and nothing, it was older than 17.4.0, and a start in an environment that had
    # exactly what was asked for would have said to update it.
    import importlib.metadata

    from qkvm import cli

    monkeypatch.setattr(cli, "SAFE_FROM", {"websockets": (17, 4, 0)})
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "17.4")
    assert cli.outdated_libraries() == {}
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "17.3")
    assert list(cli.outdated_libraries()) == ["websockets"]


@pytest.mark.parametrize(
    ("name", "installed", "older"),
    [
        ("websockets", "17.4", False), ("websockets", "17.4.0", False), ("websockets", "17.3", True),
        ("websockets", "17.4rc1", True), ("websockets", "17.4.0rc1", True), ("websockets", "17.4a1", True),
        ("websockets", "17.4b2", True), ("websockets", "17.4.dev0", True), ("websockets", "17.4.post1", False),
        ("websockets", "17.3.post1", True), ("websockets", "17.3+deb12", True), ("websockets", "17.4+local", False),
        ("websockets", "1!17.0", False), ("websockets", "18.0rc1", False), ("websockets", "17.10", False),
        ("websockets", "17.4-custom-build", True),
        ("cryptography", "50.0.2", False), ("cryptography", "50.0.1", True), ("cryptography", "50.0", True),
        ("cryptography", "50.0+local3", True), ("cryptography", "50.0.1+cust2", True), ("cryptography", "50.0.2rc1", True),
        ("cryptography", "50.0.2.dev0", True), ("cryptography", "50.0.1.post9", True), ("cryptography", "50.1", False),
        ("dnspython", "2.9.0", False), ("dnspython", "2.9", False), ("dnspython", "2.9.0.dev0", True),
        ("dnspython", "2.9.0rc1", True), ("dnspython", "2.8.0.post2", True), ("dnspython", "2.8+9", True), ("dnspython", "2.10", False),
    ],
)  # fmt: skip
def test_a_version_below_its_floor_is_named_however_it_is_spelled(name: str, installed: str, older: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    # The first three numbers of a version were compared, and whatever came after them was not read: a release candidate,
    # an alpha, a dev release of the floor itself (17.4rc1 is before 17.4, by PEP 440, and has its hole), or a local
    # version of one below it (50.0+local3 was taken for 50.0.3), was taken to be past the floor; 1!17.0, past it, was
    # named. Compared as pip compares them; a spelling that is no version at all is not known to be past the floor.
    import importlib.metadata

    from qkvm import cli

    monkeypatch.setattr(cli, "SAFE_FROM", {name: cli.SAFE_FROM[name]})
    monkeypatch.setattr(importlib.metadata, "version", lambda asked: installed)
    found = cli.outdated_libraries()
    assert (name in found) is older, found


def test_a_version_that_is_no_version_is_said_to_be_not_known_to_be_past_its_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    # A distribution's own spelling (17.4-1ubuntu2) is no version by PEP 440: it is named, as one not known to be safe, but
    # the start said it was below the floor, as a fact.
    import importlib.metadata

    from qkvm import cli

    monkeypatch.setattr(cli, "SAFE_FROM", {"websockets": (17, 4, 0)})
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "17.4-1ubuntu2")
    found = cli.outdated_libraries()
    assert list(found) == ["websockets"], found
    assert "not known to be past the required minimum 17.4.0" in found["websockets"], found
    headline = cli.outdated_headline(found)
    assert "not known to be past" in headline and headline.endswith("pip install --upgrade websockets"), headline
    # ...and one that is plainly older is below it, as before.
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "17.3")
    found = cli.outdated_libraries()
    assert found["websockets"].endswith("(required minimum 17.4.0)") and "not known" not in cli.outdated_headline(found)


def test_a_library_with_a_known_hole_is_named_so_that_it_can_be_updated(monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import cli

    monkeypatch.setattr(cli, "SAFE_FROM", {"pytest": (999, 0, 0), "nothing-of-this-name": (1, 0, 0)})
    found = cli.outdated_libraries()
    # By name, because that is what has to be typed after `pip install --upgrade`; one that is not installed is not an old one.
    assert list(found) == ["pytest"] and found["pytest"].endswith("(required minimum 999.0.0)")
