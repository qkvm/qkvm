"""The README is the landing page of GitHub and PyPI, and the guide (GUIDE.md) is the manual (2026-11-16). What the landing page
says in short is what the guide says: its commands are the guide's, word for word; every page of the documentation it
sends to is a chapter of the guide or a page made beside them; and every file of the repository it names is published.
PyPI shows the same text away from the repository, so every link in it is a whole address, or a heading of its own."""

from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
README = (APP / "README.md").read_text(encoding="utf-8")
GUIDE = (APP / "GUIDE.md").read_text(encoding="utf-8")
DOCS = "https://docs.qkvm.com/"
REPOSITORY = "https://github.com/qkvm/qkvm/blob/main/"
# (Pages of the documentation that are not chapters of this guide: the policy, the changes, the Desktop App's own.)
BESIDE = {"security-policy", "changes", "desktop", "desktop-install"}


def slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def links(text: str) -> list[str]:
    return re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'\b(?:href|src|srcset)="([^"]+)"', text)


def test_the_landing_page_is_short_and_the_guide_has_the_rest() -> None:
    assert len(README.splitlines()) < 250 and len(GUIDE.splitlines()) > 3000
    assert "## Run it" in GUIDE and "## How it is protected" in GUIDE and "## Run it" not in README


def test_every_command_on_the_landing_page_is_the_guides() -> None:
    blocks = re.findall(r"(?ms)^```[a-z]*\n(.*?)^```", README)
    assert len(blocks) >= 2, blocks
    for block in blocks:
        for line in block.splitlines():
            assert line in GUIDE, f"the landing page says {line!r}, which the guide does not"


def test_every_link_on_the_landing_page_is_a_whole_address_or_a_heading_of_its_own() -> None:
    headings = {slug(title) for title in re.findall(r"(?m)^#{2,3} +(.+)$", README)}
    for link in links(README):
        if link.startswith("#"):
            assert link[1:] in headings, link
        else:
            assert link.startswith("https://"), f"{link}: PyPI shows this page away from the repository"


def test_every_page_and_file_the_landing_page_sends_to_is_there() -> None:
    chapters = {slug(title) for title in re.findall(r"(?m)^## +(.+)$", GUIDE)} | BESIDE
    pages = {link[len(DOCS) :].split("#")[0] for link in links(README) if link.startswith(DOCS) and link != DOCS}
    assert len(pages) > 20 and pages <= chapters, sorted(pages - chapters)
    files = {link[len(REPOSITORY) :] for link in links(README) if link.startswith(REPOSITORY)}
    assert {"GUIDE.md", "LICENSE", "CONTRIBUTING.md"} <= files
    assert sorted(name for name in files if not (APP / name).is_file()) == []
