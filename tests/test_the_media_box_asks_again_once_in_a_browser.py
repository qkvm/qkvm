"""The Media box's look asked again, as the outside review's fourth round (Codex, a LOW) found it: through a failure that
went on it asked every five seconds, and a newer look that got no answer found the older one's turn taken and was never
asked again. One look asked again, by the newest look's turn; and nothing a device or the wall says is markup.
"""
import itertools
import time
from contextlib import contextmanager

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import expect

from tests.fake_redfish import BmcState, FakeBmc
from tests.test_in_a_browser import a_wall, looking, sign_in, tile, top
from tests.test_push_in_a_browser import chromium  # noqa: F401
from tests.test_virtual_media_on_a_server_in_a_browser import add_the_server, open_the_box


@contextmanager
def media_page(tmp_path, chromium):  # noqa: F811 (the fixture, by name)
    fake = FakeBmc(BmcState(virtual_media="standard", hostname="db-01")).start()
    try:
        with a_wall(tmp_path / "wall") as (live, admin), looking(chromium, live) as page:
            add_the_server(admin, fake)
            sign_in(page, live)
            expect(tile(page, "db-01")).to_have_attribute("data-state", "online", timeout=30_000)
            yield page
    finally:
        fake.stop()


def test_persistent_failure_counts_retries_and_close_stops_requests(tmp_path, chromium):  # noqa: F811 (the fixture, by name)
    with media_page(tmp_path, chromium) as page:
        times = []
        def lookup(route):
            assert route.request.method == "GET"
            times.append(time.monotonic())
            route.fulfill(status=504, json={"code": "timeout", "message": f"miss {len(times)}"})
        page.route("**/api/v1/devices/*/media", lookup)
        box = open_the_box(page)
        said = box.locator(".media-said")
        expect(said).to_contain_text("miss 1.")
        expect(box.get_by_role("button", name="Unmount", exact=True)).to_be_disabled()
        # A single failed automatic retry should be the final look for this open.
        expect(said).to_contain_text("miss 2.", timeout=9_000)
        page.wait_for_timeout(5_700)
        while_open = len(times)
        box.get_by_role("button", name="Close", exact=True).click()
        page.wait_for_timeout(5_700)
        print(f"one open through continuous failure: GETs={while_open}, after closing={len(times)}, "
              f"intervals={[round(b - a, 2) for a, b in itertools.pairwise(times)]}")
        assert len(times) == while_open, "closed Media box sent another retry"
        assert while_open == 2, "one failing lookup started more than one automatic retry"


def test_newer_failed_look_owns_its_retry_and_keeps_text_and_unmount_safe(tmp_path, chromium):  # noqa: F811 (the fixture, by name)
    marker = '<mark data-review-probe="">board words</mark>'
    result = f"completed {marker}"
    known = {"offers": {"where": "qkvm", "drives": ["cd"], "boot": [], "writable": [],
                        "upload": False, "delete": False, "restart": False},
             "images": [{"id": "review.iso", "name": marker, "size": 4096, "where": marker}],
             "notes": [marker], "unseen": [], "served_from": marker,
             "mounted": {"image": "review.iso", "name": marker, "where": "qKVM",
                         "drive": "cd", "read_only": True, "by": marker}}
    with media_page(tmp_path, chromium) as page:
        gets, posts = [], []
        def lookup(route):
            if route.request.method == "POST":
                posts.append(route.request.method)
                route.fulfill(status=200, json={"said": result, "note": marker})
                return
            assert route.request.method == "GET"
            gets.append(time.monotonic())
            if len(gets) in (2, 3):
                route.fulfill(status=504, json={"code": "timeout", "message": f"miss {len(gets)} {marker}"})
            else:
                route.fulfill(status=200, json=known)
        page.route("**/api/v1/devices/*/media", lookup)
        box = open_the_box(page)
        said = box.locator(".media-said")
        now = box.locator(".media-now")
        unmount = box.get_by_role("button", name="Unmount", exact=True)
        expect(said).to_contain_text(marker)
        expect(now).to_contain_text(marker)
        expect(unmount).to_be_enabled()
        expect(box.locator("[data-review-probe]")).to_have_count(0)
        radio = box.get_by_role("radio")
        radio.check()
        for number in (2,3):
            box.get_by_role("button", name="Mount", exact=True).click()
            top(page).get_by_role("button", name="Mount", exact=True).click()
            expect(said).to_contain_text(f"{result} miss {number} {marker}")
            expect(now).to_contain_text("Not known just now")
            expect(unmount).to_be_disabled()
            expect(radio).to_be_visible()
            expect(box.locator("[data-review-probe]")).to_have_count(0)
        assert gets[2] - gets[1] < 4.8, "the second failure missed the pending timer"
        page.wait_for_timeout(5_700)
        print(f"success with known mount, two consecutive action-triggered failures: "
              f"GETs={len(gets)}, POSTs={len(posts)}, unmount_disabled={unmount.is_disabled()}")
        assert len(posts) == 2
        assert len(gets) == 4, "old timer ignored newer failure, automatic recovery lookup was lost"
        expect(now).to_contain_text(marker)
