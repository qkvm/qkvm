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
            before = page.locator("#focus-screen").bounding_box()
            header_before = page.locator("#focus-bar").bounding_box()
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            expect(page.locator("#focus-release-hint")).to_be_visible()
            for ident in ("cad", "win", "alt-tab", "alt-f4", "prtsc", "type", "relative"):
                expect(page.locator("#focus-" + ident)).to_be_visible()
            box = page.locator("#focus-keys").bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= width
            assert page.locator("#focus-screen").bounding_box() == before
            assert page.locator("#focus-bar").bounding_box() == header_before
            expect(page.locator("#focus-control")).to_have_text("Control")
            page.locator("#focus-details > summary").click()
            page.keyboard.press("Escape")
            expect(page.locator("#focus-activity")).to_be_hidden()
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
            page.locator("#focus-win").focus()
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
            expect(page.locator("#focus-keys")).to_be_hidden()
            assert page.locator("#focus-screen").bounding_box() == before
            assert page.locator("#focus-bar").bounding_box() == header_before
    finally:
        fake.stop()


def test_screen_keyboard_sends_balanced_chords_only_while_controlled(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    from tests.test_live_in_a_browser import kvm_keys, until

    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            tile(page, "Build server").click()
            toggle = page.locator("#focus-keyboard-toggle")
            keyboard = page.locator("#focus-keyboard")
            def key(code: str):
                return keyboard.locator(f'[data-code="{code}"]')
            expect(toggle).to_be_hidden()
            toggle.evaluate("e => e.click()")
            key("KeyA").evaluate("e => e.click()")
            assert kvm_keys(fake) == []
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            before = page.locator("#focus-screen").bounding_box()
            toggle.click()
            expect(keyboard).to_be_visible()
            assert page.locator("#focus-screen").bounding_box() == before
            key("ShiftLeft").click()
            expect(key("ShiftLeft")).to_have_attribute("aria-pressed", "true")
            assert kvm_keys(fake) == []  # armed locally, never held remotely between clicks
            key("KeyA").click()
            key("KeyB").click()
            until(page, lambda: len(kvm_keys(fake)) >= 6, "screen keys did not arrive")
            assert kvm_keys(fake) == [("ShiftLeft", True), ("KeyA", True), ("KeyA", False), ("ShiftLeft", False), ("KeyB", True), ("KeyB", False)]
            expect(key("ShiftLeft")).to_have_attribute("aria-pressed", "false")
            for code in ("F12", "ArrowLeft", "Escape", "Enter", "Digit1"):
                key(code).click()
            until(page, lambda: len(kvm_keys(fake)) >= 16, "function and navigation keys did not arrive")
            assert kvm_keys(fake)[6:] == [(code, down) for code in ("F12", "ArrowLeft", "Escape", "Enter", "Digit1") for down in (True, False)]
            key("ControlLeft").click()
            page.evaluate("window.dispatchEvent(new Event('blur'))")
            expect(key("ControlLeft")).to_have_attribute("aria-pressed", "false")
            key("AltLeft").click()
            toggle.click()
            expect(keyboard).to_be_hidden()
            toggle.click()
            expect(key("AltLeft")).to_have_attribute("aria-pressed", "false")
            key("ShiftLeft").click()
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "false")
            expect(keyboard).to_be_hidden()
            key("KeyA").evaluate("e => e.click()")
            page.wait_for_timeout(200)
            assert len(kvm_keys(fake)) == 16
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            toggle.click()
            expect(key("ShiftLeft")).to_have_attribute("aria-pressed", "false")
    finally:
        fake.stop()
