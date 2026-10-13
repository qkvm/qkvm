"""The page's script, read as text: what can be told about it without a browser."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).resolve().parent.parent / "qkvm" / "static" / "app.js").read_text(encoding="utf-8")


def block(opening: str) -> str:
    """The text between `opening` and the line that closes what it opens."""
    start = SCRIPT.index(opening)
    return SCRIPT[start : SCRIPT.index("\n};", start)]


def test_every_icon_the_page_asks_for_is_one_it_has() -> None:
    # A settings tab was added without an icon of its own. Drawing "no icon" threw, in the middle of
    # building the dialog, and Settings did not open for any admin; nothing but a click on it showed that.
    drawn = set(re.findall(r"^  (\w+): \[\[", block("const ICONS = {"), re.M))
    assert len(drawn) > 30
    asked = set(re.findall(r"\b(?:icon|menuItem|quick|power)\('(\w+)'", SCRIPT))
    asked |= set(re.findall(r"\bicon: '(\w+)'", SCRIPT))
    for table in ("const TAB_ICONS = {", "const ROW_ICONS = {"):
        asked |= set(re.findall(r": '(\w+)'", block(table) if "\n};" in SCRIPT[SCRIPT.index(table) :][:400] else SCRIPT[SCRIPT.index(table) :].split("\n", 1)[0]))
    asked |= set(re.findall(r": '(\w+)'", SCRIPT[SCRIPT.index("const VEIL_ICONS = {") :].split("\n", 1)[0]))
    assert asked - drawn == set()

    # And every section of the settings has one.
    sections = set(re.findall(r"^    \['(\w+)', '", SCRIPT[SCRIPT.index("const SETTINGS = [") : SCRIPT.index("function settingsDialog(")], re.M))
    with_icon = set(re.findall(r"(\w+): '\w+'", block("const TAB_ICONS = {")))
    assert len(sections) >= 11 and sections - with_icon == set()


def test_every_part_of_the_page_the_script_reaches_for_is_there() -> None:
    # The top bar was rebuilt, and controls moved into menus or went away. The script reaches for parts of
    # the page by their id as it starts; one that is gone is a null, and the wall does not come up at all.
    page = (Path(__file__).resolve().parent.parent / "qkvm" / "static" / "index.html").read_text(encoding="utf-8")
    there = set(re.findall(r'\bid="([\w-]+)"', page)) | set(re.findall(r"\bid: '([\w-]+)'", SCRIPT))
    asked = set(re.findall(r"\$\('#([A-Za-z][\w-]*)'", SCRIPT))
    assert len(asked) > 50 and {"arrange", "view-toggle", "me-toggle"} <= asked
    assert asked - there == set()


def test_what_lies_on_a_tile_does_not_lie_over_the_bars_of_the_page() -> None:
    # While the tiles were being arranged, the layer on each of them (the place number and its arrows) lay
    # over the bar that holds "Save this order": the layer had a higher z-index than the bar, and a tile was
    # no stacking context of its own, so the two were compared with each other. Save could only be reached
    # through the gaps between the tiles. A tile keeps what is on it to itself, whatever its z-index.
    styles = (Path(__file__).resolve().parent.parent / "qkvm" / "static" / "app.css").read_text(encoding="utf-8")
    tile = styles[styles.index("\n.tile {") :]
    assert "isolation: isolate;" in tile[: tile.index("}")]
    # And the last row can be scrolled clear of that bar, as it can while machines are being picked.
    assert re.search(r"\.shell\.arranging \.wall[^{]*\{ padding-bottom: \d+px; \}", styles)


def test_a_page_left_open_fetches_itself_again_when_its_files_changed_and_the_version_did_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The wall was restarted on new page files three times in an evening, signed in to each time on the tab
    # that had been open all along, and went on running the script from before: a page compared itself with
    # the program by version only, and the version had not changed. What is compared now changes with the files.
    import shutil

    from fastapi.testclient import TestClient

    from qkvm import server, vault
    from tests.test_wall import wall

    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    with wall(tmp_path / "one", sign_in=False) as client:
        said = client.get("/healthz").json()
        page = client.get("/").text
        assert said["page"] and f'<meta name="qkvm-page" content="{said["page"]}">' in page
    changed = tmp_path / "static"
    shutil.copytree(server.STATIC, changed)
    (changed / "app.js").write_text((changed / "app.js").read_text(encoding="utf-8") + " // another line", encoding="utf-8")
    monkeypatch.setattr(server, "STATIC", changed)
    with wall(tmp_path / "two", sign_in=False) as client:
        assert isinstance(client, TestClient) and client.get("/healthz").json()["page"] != said["page"]
    # ...and the page compares both.
    check = SCRIPT[SCRIPT.index("async function reloadIfOutdated()") :][:900]
    assert "qkvm-page" in check and "said.page" in check


def test_a_change_of_the_page_that_the_next_one_overtakes_is_no_fault() -> None:
    # A key held down in the search box narrows the wall thirty times a second. Each time the movement of
    # the change before is given up for the next, and the browser says so by refusing a promise of the
    # earlier one. Nobody took that refusal: it fell into the page's net for what nothing else caught, and
    # the wall said "Something went wrong on this page. Reload it if anything looks stuck." to somebody who
    # had typed a word. Found by the first test that ran the page in a browser (test_in_a_browser.py), and
    # held here as well for where no browser is: every movement is started in one place, which takes it.
    assert len(re.findall(r"document\.startViewTransition\(", SCRIPT)) == 2
    moving = SCRIPT[SCRIPT.index("function moving(update) {") :]
    assert "movement.ready.catch(() => {});" in moving[: moving.index("\n}")]
    theme = SCRIPT[SCRIPT.index("document.startViewTransition(applyTheme)") :]  # the theme's own, which takes it too
    assert ".catch(applyTheme);" in theme[: theme.index("\n}")]
