"""The page, in a browser, against the program as it is started: for what only the two together show.

An update installed from the page, and a change of where the wall listens, each end with the program
starting again under the page that asked for it. The tests in `test_in_a_browser.py` run the app inside
the test's own process, where nothing restarts. Here it is the real starter and the real wall on a port
of their own, a stand-in for GitHub only, and a browser.

Walked first by an outside reviewer; needs Playwright, like the other browser tests, and is skipped without.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm._version import __version__
from tests.fake_github import FakeGitHub
from tests.test_in_a_browser import PATIENCE, browser, settings, sign_in, top  # noqa: F401  (`browser` is the fixture)
from tests.test_update_for_real import PASSWORD, SIGNING, Running, a_release, later


@pytest.fixture
def running(tmp_path: Path) -> Iterator[tuple[Running, FakeGitHub]]:
    """The program itself, started and set up, and what it takes for GitHub."""
    github = FakeGitHub().start()
    run = Running(tmp_path, github)
    try:
        run.start()
        assert run.version(__version__, within=60) == __version__
        assert run.sign_in() == 200
        run.url = str(run.browser.base_url).rstrip("/")  # type: ignore[attr-defined]  # (what `sign_in` of the browser tests goes to)
        yield run, github
    finally:
        run.stop()
        run.browser.close()
        github.stop()


def test_an_update_is_seen_and_installed_from_the_page_and_the_page_follows_the_restart(running: tuple[Running, FakeGitHub], browser: Browser) -> None:  # noqa: F811
    run, github = running
    context = browser.new_context()
    context.set_default_timeout(PATIENCE)
    thrown: list[str] = []
    try:
        page = context.new_page()
        page.on("pageerror", lambda error: thrown.append(str(error)))
        sign_in(page, run, password=PASSWORD)  # type: ignore[arg-type]
        pane = settings(page, "updates")
        daily = pane.get_by_label("Check automatically once a day")
        daily.uncheck()
        expect(daily).not_to_be_checked()
        # What a release says of itself is its publisher's text, and is shown as text.
        github.publish(later(1), a_release(later(1)), notes='<img src=x onerror="window.reached=5">', signed_by=SIGNING)
        first_line = pane.locator(".section-head")
        first_line.get_by_role("button", name="Check for updates", exact=True).click()
        install = first_line.get_by_role("button", name=f"Install {later(1)}", exact=True)
        expect(install).to_be_visible(timeout=40_000)
        expect(pane).to_contain_text(f"Version {later(1)}")
        assert page.locator("img[src='x']").count() == 0 and page.evaluate("window.reached") is None
        install.click()
        asked = top(page)
        asked.locator("input[type=password]").fill("not the password of this wall")
        asked.get_by_role("button", name="Install", exact=True).click()
        expect(asked.locator("p.error")).to_be_visible()  # new code is installed for nobody who cannot say the password
        assert run.version(__version__, within=5) == __version__
        asked.locator("input[type=password]").fill(PASSWORD)
        asked.get_by_role("button", name="Install", exact=True).click()
        # The program starts again as the new version; the page waits for it and fetches itself anew.
        expect(page.get_by_role("heading", name="Sign in", exact=True)).to_be_visible(timeout=120_000)
        assert run.version(later(1), within=10) == later(1)
        assert thrown == []
    finally:
        context.close()


def test_the_wall_is_put_on_https_from_the_page_and_the_page_leads_to_where_it_now_is(running: tuple[Running, FakeGitHub], browser: Browser) -> None:  # noqa: F811
    run, _ = running
    context = browser.new_context(ignore_https_errors=True)  # (its certificate is one it made itself a moment ago)
    context.set_default_timeout(PATIENCE)
    thrown: list[str] = []
    try:
        page = context.new_page()
        page.on("pageerror", lambda error: thrown.append(str(error)))
        sign_in(page, run, password=PASSWORD)  # type: ignore[arg-type]
        pane = settings(page, "network")
        first_line = pane.locator(".section-head")
        pane.get_by_label("Tile refresh (seconds)").fill("0.7")
        first_line.get_by_role("button", name="Save", exact=True).click()
        expect(page.locator("#toasts")).to_contain_text("Settings saved")  # nothing about where it listens changed: no restart
        assert run.browser.get("/api/v1/settings").json()["interval"] == 0.7
        pane.get_by_label("Encrypt connections (HTTPS)").check()
        first_line.get_by_role("button", name="Save", exact=True).click()
        expect(page.get_by_role("heading", name="Network settings saved")).to_be_visible()
        secure = run.url.replace("http:", "https:")  # type: ignore[attr-defined]
        expect(page.get_by_role("link", name=secure + "/")).to_have_count(1)
        until = time.monotonic() + 40
        with httpx.Client(verify=False, timeout=2) as asking:  # (a certificate of its own making, on this computer)
            while True:
                try:
                    if asking.get(secure + "/healthz").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                assert time.monotonic() < until, "the wall did not come back on HTTPS"
                time.sleep(0.2)
        page.get_by_role("link", name=secure + "/").click()
        # The same program, listening anew: whoever was signed in still is, and the wall is there at its new address.
        expect(page.locator("#shell")).to_be_visible(timeout=30_000)
        expect(page.locator("#wall .empty")).to_be_visible()
        assert page.url.startswith("https://")
        with pytest.raises(httpx.HTTPError):
            httpx.get(run.url + "/healthz", timeout=3)  # type: ignore[attr-defined]  # nothing answers there in the clear any more
        assert thrown == []
    finally:
        context.close()
