"""The activity log's check on the page, in a real browser: Settings > Activity log > "Check the log" says intact, or
where the log was edited and how, in a box of its own; the check itself is then in the log.

Beside tests/test_in_a_browser.py, whose helpers it borrows. Playwright and a browser, or the test is skipped; the page
throws nothing and breaks none of its rules (the helpers see to that).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

import httpx

from tests.test_hardening import KEPT_AS_THE_PROGRAM, LiveWall
from tests.test_in_a_browser import CSRF, PASSWORD, a_wall, browser, fast, looking, settings, sign_in, top  # noqa: F401  (fixtures, by name)

OLGA = "a password for olga, long enough"


def test_the_activity_section_checks_the_log_and_shows_where_it_was_edited(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin):
        for number in range(3):
            assert admin.post("/api/v1/users", json={"name": f"user{number}", "role": "viewer", "password": OLGA}).status_code == 201
        with looking(browser, live) as page:
            sign_in(page, live, name="admin")
            pane = settings(page, "activity")
            section = top(page)
            check = section.get_by_role("button", name="Check the log")
            # At the top right of the section, beside its downloads, which keep their places.
            downloads = section.get_by_role("button", name="Download CSV")
            assert check.bounding_box()["y"] == downloads.bounding_box()["y"]  # type: ignore[index]
            check.click()
            box = top(page)
            expect(box.locator("h2")).to_have_text("The activity log is intact")
            expect(box.locator("[data-check=intact]")).to_contain_text(re.compile(r"^Intact: lines 1 to \d+, with their signatures"))
            expect(box.locator("code.fingerprint")).to_have_text(re.compile(r"^[0-9a-f]{64}$"))
            # What intact cannot show, beside it: an older copy of the whole data folder put back (the outside review of 0.4.0).
            expect(box.locator("[data-check-limits]")).to_contain_text("It cannot show an older copy of the whole data folder put back")
            box.get_by_role("button", name="Close").click()
            # The check is in the log itself, and the list shows it.
            expect(pane.locator("table.rows tbody tr").first).to_contain_text("Activity log checked")
            expect(pane.locator("table.rows tbody tr").first).to_contain_text("intact")

            # A line edited by hand in the data folder: the next check says which, and how.
            path = tmp_path / "audit.log"
            deadline = time.monotonic() + 10
            while '"event": "user_added"' not in path.read_text(encoding="utf-8"):
                assert time.monotonic() < deadline, "the accounts' lines were not written"
                time.sleep(0.05)
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            at = next(index for index, line in enumerate(lines) if '"event": "user_added"' in line)
            number = json.loads(lines[at])["chain"]["n"]
            lines[at] = lines[at].replace('"account": "user0"', '"account": "somebody else"')
            path.write_text("".join(lines), encoding="utf-8")
            check.click()
            box = top(page)
            expect(box.locator("h2")).to_have_text("The activity log is broken")
            expect(box.locator("[data-check=broken]")).to_contain_text(f"Broken at line {number}")
            expect(box.locator("ul.check-found li").first).to_contain_text(f"Line {number}: line {number} is not as the wall wrote it")
            # The box keeps its size whatever it found: its list scrolls.
            assert box.locator("ul.check-found").evaluate("list => getComputedStyle(list).overflowY") == "auto"
            box.get_by_role("button", name="Close").click()
            expect(pane.locator("table.rows tbody tr").first).to_contain_text(f"broken at line {number}")


def test_a_check_with_lines_not_proved_is_said_so_in_the_list_and_the_box(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # (The re-review of wave 2, N3: the list said "intact" of a check that took lines in without proof.)
    with a_wall(tmp_path):
        pass
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
        file.write(json.dumps({"time": 1763300100.0, "event": "login", "ip": "192.0.2.30", "user": "back"}) + "\n")
    with LiveWall(tmp_path, **KEPT_AS_THE_PROGRAM) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
        assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        with looking(browser, live) as page:
            sign_in(page, live)
            pane = settings(page, "activity")
            top(page).get_by_role("button", name="Check the log").click()
            box = top(page)
            expect(box.locator("h2")).to_have_text("The activity log is intact where it is chained")
            expect(box.locator("[data-check=unproved]")).to_contain_text("not all of it proved")
            box.get_by_role("button", name="Close").click()
            expect(pane.locator("table.rows tbody tr").first).to_contain_text("intact where it is chained, 1 line not proved")
