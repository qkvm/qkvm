"""Compact console controls remain accessible without taking space from video."""
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import a_wall, browser, fast, looking, sign_in, tile  # noqa: F401


@pytest.mark.parametrize("width,height", [(1485, 1000), (900, 1400), (390, 844)])
def test_compact_controls_and_video_fit(tmp_path: Path, browser: Browser, width: int, height: int) -> None:  # noqa: F811
    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live, viewport={"width": width, "height": height}) as page:
            sign_in(page, live)
            tile(page, "Build server").click()
            expect(page.locator("#focus")).to_be_visible()
            expect(page.locator("#focus-history")).to_be_hidden()
            expect(page.locator(".focus-title")).to_have_attribute("data-state", "online")
            assert page.locator(".focus-title .dot").evaluate("e => getComputedStyle(e).backgroundColor") == page.locator(".tile .dot").first.evaluate("e => getComputedStyle(e).backgroundColor")
            expect(page.locator("#focus-fullscreen")).to_be_visible()
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_text("Give back")
            expect(page.locator("#focus-release-hint")).to_be_visible()
            expect(page.locator("#focus-cad")).to_be_hidden()
            page.locator("#focus-keys > summary").click()
            for ident in ("cad", "win", "alt-tab", "alt-f4", "prtsc", "type", "relative"):
                expect(page.locator("#focus-" + ident)).to_be_visible()
            box = page.locator(".focus-keys").bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= width
            page.keyboard.press("Escape")
            expect(page.locator("#focus-cad")).to_be_hidden()
            assert not [event for event in fake.state.hid if event["event_type"] == "key"]
            expect(page.locator("#focus")).to_be_visible()
            page.locator("#focus-details > summary").click()
            page.locator("#focus-activity").click()
            expect(page.locator("#focus-history")).to_be_visible()
            page.locator("#focus-details > summary").click()
            page.locator("#focus-activity").click()
            expect(page.locator("#focus-history")).to_be_hidden()
            bar = page.locator("#focus-bar").bounding_box()
            screen = page.locator("#focus-screen").bounding_box()
            assert bar and screen and bar["height"] < height * .30
            assert screen["height"] > height * .65
            assert page.locator("#focus").evaluate("e => e.scrollWidth <= e.clientWidth")
            page.locator("#focus-keys > summary").click()
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
            expect(page.locator("#focus-keys")).to_be_hidden()
    finally:
        fake.stop()
