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
            home_header = page.locator(".top").bounding_box()
            tile(page, "Build server").click()
            expect(page.locator("#focus")).to_be_visible()
            expect(page.locator("#focus-history")).to_be_hidden()
            expect(page.locator(".focus-title")).to_have_attribute("data-state", "online")
            assert page.locator(".focus-title .dot").evaluate("e => getComputedStyle(e).backgroundColor") == page.locator(".tile .dot").first.evaluate("e => getComputedStyle(e).backgroundColor")
            expect(page.locator("#focus-fullscreen")).to_be_visible()
            expect(page.locator("#focus-control")).to_be_visible()
            button = page.locator("#focus-open")
            button.hover()  # reveal it in the horizontally scrollable phone toolbar
            page.mouse.move(0, 0)
            resting = button.bounding_box()
            button.hover()
            assert button.bounding_box() == resting
            button.focus()
            assert button.bounding_box() == resting
            page.mouse.down()
            assert button.bounding_box() == resting
            assert button.evaluate("e => getComputedStyle(e).transform") == "none"
            assert page.locator(".focus-tools").evaluate("e => e.scrollHeight <= e.clientHeight")
            page.mouse.move(0, 0)
            page.mouse.up()
            before = page.locator("#focus-screen").bounding_box()
            header_before = page.locator("#focus-bar").bounding_box()
            assert header_before["height"] == home_header["height"]
            assert page.locator("#focus-statusbar").bounding_box()["height"] <= 28
            assert page.locator("#focus-bar #focus-control").count() == 1
            alert = page.locator("#focus-live-alert")
            old_status = alert.text_content()
            alert.evaluate("e => {e.hidden = false; e.textContent = 'No live picture: stills — connection to qKVM lost. '.repeat(5)}")
            status_box = alert.bounding_box()
            title_box = page.locator("#focus-name").bounding_box()
            assert status_box["y"] >= title_box["y"] + title_box["height"]
            assert abs(status_box["x"] - title_box["x"]) < 2
            assert page.locator("#focus-screen").bounding_box() == before
            assert page.locator("#focus-bar").bounding_box() == header_before
            alert.evaluate("(e, text) => e.textContent = text", old_status)
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            for ident in ("cad", "win", "alt-tab", "alt-f4", "prtsc", "type", "relative"):
                expect(page.locator("#focus-" + ident)).to_be_visible()
            box = page.locator("#focus-keys").bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= width
            assert page.locator("#focus-screen").bounding_box() == before
            assert page.locator("#focus-bar").bounding_box() == header_before
            expect(page.locator("#focus-control")).to_have_text("Control")
            expect(page.locator("#focus-tools-toggle")).to_have_count(0)
            page.locator("#focus-details > summary").click()
            page.keyboard.press("Escape")
            expect(page.locator("#focus-history")).to_be_hidden()
            assert not [event for event in fake.state.hid if event["event_type"] == "key"]
            expect(page.locator("#focus")).to_be_visible()
            page.locator("#focus-details > summary").click()
            expect(page.locator("#focus-history")).to_be_visible()
            page.locator("#focus-details > summary").click()
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
            initial = keyboard.bounding_box()
            handle = page.locator("#keyboard-drag").bounding_box()
            page.mouse.move(handle["x"] + 30, handle["y"] + 15)
            page.mouse.down()
            page.mouse.move(handle["x"] - 70, handle["y"] - 65, steps=5)
            page.mouse.up()
            moved = keyboard.bounding_box()
            assert moved["x"] < initial["x"] and moved["y"] < initial["y"]
            page.locator("#keyboard-resize").focus()
            page.keyboard.press("ArrowLeft")
            assert keyboard.bounding_box()["width"] < moved["width"]
            assert page.locator("#focus-screen").bounding_box() == before
            assert kvm_keys(fake) == []
            page.locator("#keyboard-reset").click()
            assert keyboard.bounding_box() == initial
            grip = page.locator("#keyboard-resize").bounding_box()
            page.mouse.move(grip["x"] + 8, grip["y"] + 8)
            page.mouse.down()
            page.mouse.move(grip["x"] - 92, grip["y"] - 52, steps=4)
            page.mouse.up()
            assert keyboard.bounding_box()["width"] < initial["width"]
            assert keyboard.bounding_box()["height"] < initial["height"]
            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_timeout(100)
            small = keyboard.bounding_box()
            assert 0 <= small["x"] and small["x"] + small["width"] <= 390
            assert 0 <= small["y"] and small["y"] + small["height"] <= 844
            page.set_viewport_size({"width": 1280, "height": 720})
            page.locator("#keyboard-reset").click()
            assert kvm_keys(fake) == []
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


def test_type_text_releases_own_control_after_confirmation(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    from tests.test_in_a_browser import top
    from tests.test_live_in_a_browser import until

    fake = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            tile(page, "Build server").click()
            page.locator("#focus-control").click()
            expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
            for cancel in [True, False]:
                page.locator("#focus-type").click()
                top(page).locator("textarea").fill("test123")
                top(page).get_by_label("Press Enter afterwards").uncheck()
                top(page).get_by_role("button", name="Continue", exact=True).click()
                expect(top(page)).to_contain_text("Control is briefly released")
                expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
                if cancel:
                    top(page).get_by_role("button", name="Cancel", exact=True).click()
                    assert not [a for a in fake.state.actions if a.startswith("type ")]
                    expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
                else:
                    top(page).get_by_role("button", name="Type text", exact=True).click()
                    until(page, lambda: "type 'test123'" in fake.state.actions, "text did not arrive")
                    expect(page.locator("#focus-control")).to_have_attribute("aria-pressed", "true")
                    assert [a for a in fake.state.actions if a.startswith("type ")] == ["type 'test123'"]
                    expect(page.locator("#toasts")).not_to_contain_text("at this moment")
            # A lost release acknowledgement must never turn into a text request.
            page.evaluate("focus.live.answered = () => {}")
            page.locator("#focus-type").click()
            top(page).locator("textarea").fill("must-not-send")
            top(page).get_by_role("button", name="Continue", exact=True).click()
            top(page).get_by_role("button", name="Type text", exact=True).click()
            expect(page.locator("#toasts")).to_contain_text("no text was sent")
            assert [a for a in fake.state.actions if a.startswith("type ")] == ["type 'test123'"]
    finally:
        fake.stop()
