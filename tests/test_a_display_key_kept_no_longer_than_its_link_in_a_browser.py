"""A wall screen keeps its display link's key as long as the link is valid by the wall's clock, and no longer.

The page keeps the key behind `#key=` in the browser (localStorage `qkvm.display-key`), to sign the screen in again after
a restart or a power cut. It was kept there with no end (web review of 0.2.0). 5dc3805 kept the link's end beside it and
compared that with the screen's own time of day: a screen whose clock runs ahead (a small computer without a clock chip,
after a power cut, before it has asked the network for the time) forgot a key that was still good, and needed the link
again (the review of 2026-11-01, L5). Now the wall says how many seconds the link has left (`expires_in`) whenever the key
is handed in, and the page counts them on its own steady clock from that moment; the screen's time of day decides
nothing. A key the wall refuses (the link taken back, or run out by the wall's clock) is forgotten at once, as before.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does.
"""

from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm
from tests.test_in_a_browser import a_wall, browser, fakes, fast, looking  # noqa: F401

KEPT = "() => localStorage.getItem('qkvm.display-key') || ''"


def test_a_display_key_is_not_forgotten_because_the_screens_clock_runs_ahead(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as screen:
        made = admin.post("/api/v1/tokens", json={"name": "Hall, for a day", "kind": "display", "days": 1})
        assert made.status_code == 201, made.text
        key = made.json()["token"]
        with screen.expect_response(lambda reply: reply.url.endswith("/api/v1/display")) as handed_in:
            screen.goto(f"{live.url}/#display&key={key}")
        told = handed_in.value.json()
        expect(screen.locator("#wall article")).to_have_count(1)
        assert screen.evaluate(KEPT) == key
        # The power comes back, and the screen's clock says two days later than it is: the link is good, and so is the key.
        screen.clock.set_system_time(datetime.datetime.fromtimestamp(time.time() + 2 * 86400, tz=datetime.timezone.utc))
        screen.reload()
        expect(screen.locator("#wall article")).to_have_count(1)
        screen.wait_for_timeout(1000)
        assert screen.evaluate(KEPT) == key, "a screen whose clock runs ahead forgot a display key that is still good"
        assert 86400 - 60 < told.get("expires_in", 0) <= 86400, told  # what the link has left, by the wall's clock


def test_a_display_key_is_forgotten_once_the_time_the_wall_gave_it_has_passed_on_the_page(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as screen:
        key = admin.post("/api/v1/tokens", json={"name": "Hall, for a day", "kind": "display", "days": 1}).json()["token"]
        screen.clock.install()  # (the page's own timers, and its steady clock, to be moved on by the test)
        screen.goto(f"{live.url}/#display&key={key}")
        expect(screen.locator("#wall article")).to_have_count(1)
        assert screen.evaluate(KEPT) == key
        screen.clock.fast_forward("25:00:00")  # a day and an hour pass on the page: the link has run out
        screen.wait_for_function("() => !localStorage.getItem('qkvm.display-key')", timeout=10_000)


def test_a_display_key_without_an_end_is_kept_until_the_wall_refuses_it(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as screen:
        made = admin.post("/api/v1/tokens", json={"name": "Hall", "kind": "display"})
        key, token = made.json()["token"], made.json()["record"]["id"]
        screen.goto(f"{live.url}/#display&key={key}")
        expect(screen.locator("#wall article")).to_have_count(1)
        assert screen.evaluate(KEPT) == key  # a link until it is taken back: so is its key
        assert admin.delete(f"/api/v1/tokens/{token}").status_code == 200
        expect(screen.get_by_role("heading", name="Sign in")).to_be_visible(timeout=40_000)
        assert screen.evaluate(KEPT) == ""


def test_a_display_key_is_kept_while_a_proxy_in_front_of_the_wall_answers_for_it(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    # (The round 2 review's note 6.) The key was forgotten on any answer that was not a network error: a reverse proxy's 502
    # or 503 while the wall behind it restarts is no refusal of the wall's, and the screen needed its link again after every
    # restart behind a proxy. Only the wall's own refusal (bad_key, invalid) forgets the key; anything else is asked again.
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as screen:
        key = admin.post("/api/v1/tokens", json={"name": "Hall", "kind": "display"}).json()["token"]
        answered: list[int] = []

        def proxy(route: object) -> None:
            if len(answered) < 2:  # the wall behind it is restarting: the proxy answers for it
                answered.append(502 if not answered else 503)
                route.fulfill(status=answered[-1], content_type="text/html", body="<html><body>Bad Gateway</body></html>")  # type: ignore[attr-defined]
            else:
                answered.append(200)
                route.continue_()  # type: ignore[attr-defined]

        screen.route("**/api/v1/display", proxy)
        screen.goto(f"{live.url}/#display&key={key}")
        expect(screen.locator("#wall article")).to_have_count(1, timeout=40_000)
        assert answered[:3] == [502, 503, 200], answered
        assert screen.evaluate(KEPT) == key
