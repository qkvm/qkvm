"""The activity log in a real browser: a machine's own activity beside its history in the enlarged view, and the activity
section's filters (machine, account, kind, from and to) beside its search and its downloads.

Beside tests/test_in_a_browser.py, whose helpers it borrows. Playwright and a browser, or the test is skipped; the page
throws nothing and breaks none of its rules (the helpers see to that).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import CSRF, a_wall, browser, fast, looking, settings, sign_in, tile, told, top  # noqa: F401  (fixtures, by name)

OLGA = "a password for olga, long enough"


def test_an_admin_sees_what_was_done_to_a_machine_beside_its_history_and_all_of_it_a_click_away(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    first, second = FakeKvm(FakeState(atx=True)).start(), FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", first), ("Mail server", second)) as (live, admin):
            ids = {device["name"]: device["id"] for device in admin.get("/api/v1/wall").json()["devices"]}
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as olga:
                assert olga.post("/api/v1/login", json={"name": "olga", "password": OLGA}).status_code == 200
                assert olga.post(f"/api/v1/devices/{ids['Build server']}/actions", json={"action": "reboot"}).status_code == 200
                assert olga.post(f"/api/v1/devices/{ids['Mail server']}/actions", json={"action": "jiggler_on"}).status_code == 200
            with looking(browser, live) as page:
                sign_in(page, live, name="admin")
                tile(page, "Build server").focus()
                page.keyboard.press("Enter")
                done = page.locator("#focus-history .history-done")
                # Who did what to it, newest first, beside the history; its own live view (the enlarged view opens one) is not
                # among the three lines, nor what was done to the other machine.
                expect(done.locator(".done-list li").first).to_contain_text("olga Reboot KVM")
                expect(done).to_contain_text("admin KVM added")
                expect(done).not_to_contain_text("Keep awake")
                expect(done).not_to_contain_text("Live view")
                expect(page.locator("#focus-history .history-line")).to_contain_text("Last seen")
                # All of it: the activity section, on this machine.
                done.get_by_role("button", name="All of it").click()
                pane = top(page).locator("[role=tabpanel]")
                expect(pane.locator("select[aria-label='Which machine']")).to_have_value(ids["Build server"])
                rows = pane.locator("table.rows tbody tr")
                expect(rows.first).to_contain_text("Build server")
                expect(pane.locator("table.rows")).not_to_contain_text("Mail server")
                expect(pane.locator("table.rows")).to_contain_text("Live view opened")  # (the full log has the looks)
    finally:
        first.stop()
        second.stop()


def test_the_activity_section_narrows_to_a_machine_an_account_and_a_time_and_downloads_what_it_shows(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    first, second = FakeKvm(FakeState(atx=True)).start(), FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", first), ("Mail server", second)) as (live, admin):
            ids = {device["name"]: device["id"] for device in admin.get("/api/v1/wall").json()["devices"]}
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
            with httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as olga:
                assert olga.post("/api/v1/login", json={"name": "olga", "password": OLGA}).status_code == 200
                assert olga.post(f"/api/v1/devices/{ids['Mail server']}/actions", json={"action": "jiggler_on"}).status_code == 200
            # An account that is gone is in the log all the same, and is typed: it is no longer among those offered.
            assert admin.delete(f"/api/v1/users/{next(user['id'] for user in admin.get('/api/v1/users').json()['users'] if user['name'] == 'olga')}").status_code == 200
            with looking(browser, live) as page:
                asked: list[str] = []
                page.on("request", lambda request: asked.append(request.url) if "/api/v1/audit" in request.url else None)
                sign_in(page, live)
                pane = settings(page, "activity")
                table = pane.locator("table.rows")
                expect(table).to_contain_text("Build server")
                pane.locator("select[aria-label='Which machine']").select_option(ids["Mail server"])
                expect(table).not_to_contain_text("Build server")
                expect(table).to_contain_text("Keep awake")
                who = pane.locator("input[aria-label^='Whose']")
                who.fill("OLGA")
                who.press("Enter")
                expect(pane.locator("table.rows tbody tr")).to_have_count(1)
                expect(table).to_contain_text("olga")
                last = parse_qs(urlsplit(asked[-1]).query)
                assert (last["device"], last["user"]) == ([ids["Mail server"]], ["OLGA"]), asked[-1]
                # A time window: from a minute from now on there is nothing; and "from" after "to" is said, not asked.
                later = page.evaluate("() => { const at = new Date(Date.now() + 120000); at.setMinutes(at.getMinutes() - at.getTimezoneOffset()); return at.toISOString().slice(0, 16); }")
                pane.locator("input[aria-label='From']").fill(later)
                expect(pane.locator("p.nothing")).to_be_visible()
                assert "since" in parse_qs(urlsplit(asked[-1]).query)
                pane.locator("input[aria-label='To']").fill("2020-01-01T00:00")
                told(page, '"From" has to be before "To"')
                pane.locator("input[aria-label='From']").fill("")
                pane.locator("input[aria-label='To']").fill("")
                expect(pane.locator("table.rows tbody tr")).to_have_count(1)
                # The download is of what is shown: the same machine and account.
                with page.expect_download() as download:
                    top(page).get_by_role("button", name="Download CSV").click()
                got = Path(download.value.path()).read_text(encoding="utf-8").splitlines()
                assert got[0].startswith("time,event,user,ip,device") and len(got) == 2 and ",action,olga," in got[1]
                exported = parse_qs(urlsplit(next(url for url in reversed(asked) if "/export" in url)).query)
                assert (exported["device"], exported["user"]) == ([ids["Mail server"]], ["OLGA"])
    finally:
        first.stop()
        second.stop()


def test_a_machine_looked_at_often_says_so_and_not_that_nothing_was_done_to_it(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # Each enlarging writes two entries of a live view, which the column leaves out: twenty entries asked for, ten enlargings
    # pushed everything else out of them, and the column said "Nothing done to it in the activity log yet" (the first reviewer
    # of W4c). A hundred are asked for, and where all of them are looks, that is what it says.
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
            ident = admin.get("/api/v1/wall").json()["devices"][0]["id"]
            looks = "".join(
                json.dumps({"time": 1_790_000_000.0 + n, "event": "live_opened", "ip": "", "user": "olga", "device": "Build server", "device_id": ident}) + "\n"
                for n in range(150)
            )
            # By hand, while nothing else writes: once the wall's own writer has written that the machine was added (it writes
            # in a thread of its own), and before anybody signs in in a browser.
            for _ in range(100):
                if '"device_added"' in (tmp_path / "audit.log").read_text(encoding="utf-8"):
                    break
                time.sleep(0.05)
            with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
                file.write(looks)
            with looking(browser, live) as page:
                sign_in(page, live)
                tile(page, "Build server").focus()
                page.keyboard.press("Enter")
                expect(page.locator("#focus-history .history-done .done-list")).to_contain_text("Nothing but live views in its last 100 entries")
    finally:
        fake.stop()


def test_who_did_what_to_a_machine_is_shown_to_admins_only(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # The activity log is an admin's to read (the README's table of roles): an operator's enlarged view has its history, and
    # nothing of who did what, which it could not read either.
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
            with looking(browser, live) as page:
                asked: list[str] = []
                page.on("request", lambda request: asked.append(request.url) if "/api/v1/audit" in request.url else None)
                sign_in(page, live, password=OLGA, name="olga")
                tile(page, "Build server").focus()
                page.keyboard.press("Enter")
                expect(page.locator("#focus-history .history-line")).to_contain_text("Last seen")
                page.wait_for_timeout(500)
                expect(page.locator("#focus-history .history-done")).to_have_count(0)
                assert asked == []  # (not asked for at all: an operator could not read it either)
    finally:
        fake.stop()


def test_show_older_comes_to_every_entry_of_a_moment_that_a_pages_edge_cut_through(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # On Windows before Python 3.13 the clock ticks every 15.6 ms: a removal of many machines, or a file taken in, writes
    # hundreds of entries of one time. "Show older" asked for what is older than the oldest entry shown, and the rest of a
    # moment that a page's edge cut through was never shown (the reviewer of 0.2.0: 200 of 250). The page asks for what is
    # that old or older, and leaves out what it shows already. A moment of more entries than the route gives at once (500) is
    # shown as far as that, and the page goes on past it to what is older: it is not stuck.
    now = time.time()
    early = [{"time": now - 3000 + n, "event": "login", "ip": "", "user": f"early-{n:03d}"} for n in range(100)]
    many = [{"time": now - 2000, "event": "device_removed", "ip": "", "user": "admin", "device": f"many-{n:03d}"} for n in range(650)]
    tied = [{"time": now - 1000, "event": "device_removed", "ip": "", "user": "admin", "device": f"tied-{n:03d}"} for n in range(250)]
    (tmp_path / "audit.log").write_text("".join(json.dumps(entry) + "\n" for entry in (*early, *many, *tied)), encoding="utf-8")
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _admin):
            with looking(browser, live) as page:
                asked: list[str] = []
                page.on("request", lambda request: asked.append(request.url) if "/api/v1/audit?" in request.url else None)
                sign_in(page, live)
                pane = settings(page, "activity")
                rows = pane.locator("table.rows tbody tr")
                expect(rows).to_have_count(200)
                older = pane.get_by_role("button", name="Show older")
                for _ in range(10):
                    if not older.is_visible():
                        break
                    shown = rows.count()
                    older.click()
                    expect(rows).not_to_have_count(shown)
                expect(older).to_be_hidden()
                said: list[list[str]] = rows.evaluate_all("rows => rows.map(row => [...row.cells].map(cell => cell.textContent))")
                details = [cells[3] for cells in said]
                tied_shown = sorted(detail for detail in details if detail.startswith("tied-"))
                assert tied_shown == sorted(entry["device"] for entry in tied), f"{len(tied_shown)} of the 250 entries of one moment shown"
                assert len([detail for detail in details if detail.startswith("many-")]) == 500  # (as many as the route gives at once)
                assert len([cells for cells in said if cells[1].startswith("early-")]) == 100  # (and on past it: not stuck there)
                assert len(said) == len({tuple(cells) for cells in said}), "an entry was shown twice"
                assert not any("before=" in url for url in asked[:3]), asked  # (by time, that old or older: until)
    finally:
        fake.stop()


def test_show_older_shows_nothing_twice_where_more_of_the_oldest_moment_was_written_meanwhile(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # Entries of the very moment of the oldest entry shown, written while the page is open (a second burst in one tick of a
    # coarse clock), come first in the next answer: left out by their count, as many entries shown already came again (the
    # reviewer of FX-C: 10 shown twice). They are left out by what they are, and the new ones are shown.
    moment = time.time() - 1000
    early = [{"time": moment - 3000 + n, "event": "login", "ip": "", "user": f"early-{n:03d}"} for n in range(50)]
    tied = [{"time": moment, "event": "device_removed", "ip": "", "user": "admin", "device": f"tied-{n:03d}"} for n in range(250)]
    (tmp_path / "audit.log").write_text("".join(json.dumps(entry) + "\n" for entry in (*early, *tied)), encoding="utf-8")
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _admin):
            with looking(browser, live) as page:
                sign_in(page, live)
                pane = settings(page, "activity")
                rows = pane.locator("table.rows tbody tr")
                expect(rows).to_have_count(200)
                late = [{"time": moment, "event": "device_removed", "ip": "", "user": "admin", "device": f"late-{n:03d}"} for n in range(10)]
                with (tmp_path / "audit.log").open("a", encoding="utf-8") as file:
                    file.write("".join(json.dumps(entry) + "\n" for entry in late))
                older = pane.get_by_role("button", name="Show older")
                for _ in range(10):
                    if not older.is_visible():
                        break
                    shown = rows.count()
                    older.click()
                    expect(rows).not_to_have_count(shown)
                expect(older).to_be_hidden()
                said: list[list[str]] = rows.evaluate_all("rows => rows.map(row => [...row.cells].map(cell => cell.textContent))")
                details = [cells[3] for cells in said]
                assert len(said) == len({tuple(cells) for cells in said}), "an entry was shown twice"
                assert sum(detail.startswith("tied-") for detail in details) == 250 and sum(detail.startswith("late-") for detail in details) == 10
                assert sum(cells[1].startswith("early-") for cells in said) == 50
    finally:
        fake.stop()


def test_show_older_after_a_narrowing_typed_and_not_yet_asked_shows_only_what_it_narrows_to(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # A name typed into "Whose" and "Show older" clicked without Enter: the box's change came first and the click overtook it,
    # going on from the old list's oldest entry with the new question; the list held what the box left out (the second
    # reviewer of FX-C: 98 of another account). "Show older" goes on only with the question the list answers.
    now = time.time() - 5000
    entries = [{"time": now + n, "event": "login", "ip": "", "user": "anna" if n % 2 else "zed"} for n in range(600)]
    (tmp_path / "audit.log").write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _admin):
            with looking(browser, live) as page:
                sign_in(page, live)
                pane = settings(page, "activity")
                rows = pane.locator("table.rows tbody tr")
                expect(rows).to_have_count(200)
                pane.locator("input[aria-label^='Whose']").fill("zed")
                pane.get_by_role("button", name="Show older").click()
                expect(rows).to_have_count(200)
                expect(rows.first).to_contain_text("zed")
                page.wait_for_timeout(1000)  # (and nothing else comes after it)
                users: list[str] = rows.evaluate_all("rows => rows.map(row => row.cells[1].textContent)")
                assert set(users) == {"zed"} and len(users) == 200, f"anna {users.count('anna')}, zed {users.count('zed')}"
    finally:
        fake.stop()
