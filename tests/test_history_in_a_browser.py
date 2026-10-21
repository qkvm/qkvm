"""The history under the enlarged picture, in a real browser: the line, and a server's graphs.

A file of its own beside tests/test_in_a_browser.py, whose helpers it borrows: what it tests is a box of its
own in the enlarged view, and the view's picture and bar are somebody else's to change. The same holds as
there: Playwright and a browser, or the test is skipped; the page throws nothing and breaks none of its rules.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_in_a_browser import a_wall, browser, fast, looking, sign_in, tile  # noqa: F401  (fixtures, by name)


def test_the_enlarged_view_says_when_the_machine_was_seen_and_how_much_it_was_online(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    fake = FakeKvm(FakeState(atx=True)).start()
    bmc = FakeBmc(BmcState(cpu_temperature=61)).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
            reply = admin.post("/api/v1/devices", json={"url": bmc.url, "username": "admin", "password": bmc.state.password, "name": "Database server"})
            assert reply.status_code == 201, reply.text
            with looking(browser, live) as page:
                sign_in(page, live)
                tile(page, "Build server").focus()
                page.keyboard.press("Enter")
                box = page.locator("#focus-history")
                expect(box).to_be_visible()
                # The line: when it was last seen, and how much of the week it was online, of the time it was watched.
                expect(box.locator(".history-line")).to_contain_text("Last seen just now")
                # (A machine added a moment ago: "Online since just now"; a minute later, a share of this week.)
                expect(box.locator(".history-line")).to_contain_text(re.compile(r"Online (since just now|\d+ % .*this week)"))
                # A KVM reports its own temperature: one graph, of the last day, drawn on a canvas of real pixels.
                expect(box.locator("figure[data-unit='C']")).to_have_count(1)
                expect(box.locator("figcaption").first).to_contain_text("Temperature")
                page.wait_for_function("() => { const c = document.querySelector('#focus-history canvas'); return c && c.width > 10 && c.height > 10; }")
                assert "last day" in page.locator("#focus-history canvas").first.get_attribute("aria-label")
                # The next tile is the server: its temperatures and its fans, a graph each.
                page.keyboard.press("ArrowRight")
                expect(page.locator("#focus-name")).to_have_text("Database server")
                expect(box.locator("figure[data-unit='C']")).to_be_visible()
                expect(box.locator("figure[data-unit='RPM']")).to_be_visible()
                expect(box.locator("figure[data-unit='RPM'] figcaption")).to_contain_text("Fans")
                # Closed with the view, and empty then: nothing of one machine is shown over the next.
                page.keyboard.press("Escape")
                expect(page.locator("#focus")).to_be_hidden()
                expect(box).to_be_hidden()
                assert page.locator("#focus-history").inner_html() == ""
    finally:
        fake.stop()
        bmc.stop()


def test_a_viewer_sees_the_history_of_the_machines_they_may_see(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
            assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer", "password": "another long password"}).status_code == 201
            with looking(browser, live) as page:
                sign_in(page, live, password="another long password", name="victor")
                tile(page, "Build server").focus()
                page.keyboard.press("Enter")
                box = page.locator("#focus-history")
                expect(box.locator(".history-line")).to_contain_text("Last seen")
                expect(box.locator(".history-line")).to_contain_text("Online")
                expect(box.locator(".history-line")).not_to_contain_text("could not be read")
    finally:
        fake.stop()


def test_a_history_that_cannot_be_read_is_asked_for_less_and_less_often(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # The enlarged view looked at the history once a minute, and every 5 s where it could not be read: a wall that said
    # "busy" was asked twelve times as often by every enlarged view on every screen. Now 5 s, then 10, 20, and so on.
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
            page.clock.install()  # (time goes on as it does, until it is held below)
            sign_in(page, live)
            asked: list[str] = []

            def busy(route: Any) -> None:
                asked.append(route.request.url)
                route.fulfill(status=503, json={"code": "busy", "message": "The history is being read by others just now."}, headers={"Retry-After": "2"})

            page.route("**/api/v1/devices/*/history*", busy)
            tile(page, "Build server").focus()
            page.keyboard.press("Enter")
            box = page.locator("#focus-history")
            expect(box.locator(".history-line")).to_contain_text("could not be read")
            page.clock.pause_at(page.evaluate("Date.now()") + 100)
            before = len(asked)
            for _ in range(12):  # a minute, five seconds at a time
                page.clock.fast_forward(5000)
                page.wait_for_timeout(300)  # (the page's request, answered)
            again = len(asked) - before
            assert 2 <= again <= 3, f"asked {again} times in a minute after the first refusal"
    finally:
        fake.stop()


@pytest.mark.parametrize("body", ["", "null", '{"entries":null}', '{"entries":[null]}'])
def test_unreadable_activity_beside_busy_history_is_unavailable_and_recovers(tmp_path: Path, browser: Browser, body: str) -> None:  # noqa: F811
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            audit = "**/api/v1/audit?*"
            history = "**/api/v1/devices/*/history*"
            page.route(audit, lambda route: route.fulfill(status=200, content_type="application/json", body=body))
            page.route(history, lambda route: route.fulfill(status=503, json={"code": "busy", "message": "History busy"}))
            tile(page, "Build server").focus()
            with page.expect_response(audit):
                page.keyboard.press("Enter")
            expect(page.locator("#focus-history .history-line")).to_contain_text("could not be read")
            expect(page.locator("#focus-history .history-done")).to_have_count(0)
            # A later usable answer is still shown; a failed optional activity
            # request neither breaks the page nor poisons subsequent views.
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            page.unroute(audit)
            page.unroute(history)
            tile(page, "Build server").focus()
            page.keyboard.press("Enter")
            expect(page.locator("#focus-history .history-line")).to_contain_text("Last seen")
            expect(page.locator("#focus-history .history-done")).to_be_visible()
    finally:
        fake.stop()


def test_an_incomplete_successful_history_response_is_reported_as_unreadable(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            page.route("**/api/v1/devices/*/history*", lambda route: route.fulfill(status=200, content_type="application/json", body=""))
            tile(page, "Build server").focus()
            page.keyboard.press("Enter")
            expect(page.locator("#focus-history .history-line")).to_contain_text("qKVM returned an unreadable response")
    finally:
        fake.stop()
