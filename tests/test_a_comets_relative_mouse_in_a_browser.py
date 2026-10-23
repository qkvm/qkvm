"""The enlarged view of a KVM whose mouse moves by steps only, in a browser, over the program's own line.

A real Comet set to a relative mouse dropped every place the page sent (2026-10-18): the pointer on its computer never
moved. The line says how the machine's pointer is moved; the page then sends no places there, and a click on the picture
hands the pointer over (the browser's pointer lock, as the KVM's own page does it) instead of being a click. On a KVM
whose mouse takes places only, the page's "Relative mouse" is not offered: its steps would be dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Page, expect

from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import browser, fast, looking, sign_in, until  # noqa: F401  (the fixtures)
from tests.test_live_in_a_browser import enlarged, jpeg_picture, picture_box, the_program

SPY = """() => {
  window.lockAsked = 0;
  const was = HTMLCanvasElement.prototype.requestPointerLock;
  HTMLCanvasElement.prototype.requestPointerLock = function (...how) { window.lockAsked += 1; return was.apply(this, how); };
}"""


def on_the_picture(page: Page) -> tuple[float, float]:
    """The middle of the picture, once the picture is what a pointer there is over (the view settles into place a moment
    after keyboard and mouse were taken: a click made in that moment met no element at all)."""
    box = picture_box(page)
    x, y = box["left"] + box["x"] + box["w"] / 2, box["top"] + box["y"] + box["h"] / 2
    page.wait_for_function(f"() => document.elementFromPoint({x}, {y})?.id === 'focus-canvas'")
    return x, y


def pointer_events(fake: FakeKvm) -> list[str]:
    return [event["event_type"] for event in fake.state.hid if event["event_type"].startswith("mouse")]


def test_a_kvm_whose_mouse_moves_by_steps_is_handed_the_pointer_by_a_click(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.evaluate(SPY)
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            expect(page.locator("#focus-keys-note")).to_contain_text("moves by steps only: click the picture to hand it the pointer")
            expect(page.locator("#focus-relative")).to_be_enabled()
            middle = on_the_picture(page)
            page.mouse.move(*middle)
            page.mouse.move(middle[0] + 30, middle[1] + 20, steps=5)
            page.mouse.click(*middle)
            page.wait_for_function("() => window.lockAsked >= 1")
            page.wait_for_timeout(400)
            assert "mouse_move" not in pointer_events(comet), f"places went to a KVM that drops them: {comet.state.hid}"
            assert "mouse_button" not in pointer_events(comet), f"the click that hands the pointer over was a click on the machine: {comet.state.hid}"
            # Handed over (the browser of these tests gives the lock): the mouse goes by steps, and a second button pressed
            # while one is held (which a browser says as a move) reaches the machine as well.
            page.wait_for_function("() => document.pointerLockElement?.id === 'focus-canvas'")
            page.mouse.move(middle[0] + 40, middle[1] + 20, steps=4)
            page.mouse.down(button="left")
            page.mouse.move(middle[0] + 50, middle[1] + 30, steps=2)
            page.mouse.down(button="right")
            page.mouse.move(middle[0] + 60, middle[1] + 40, steps=2)
            page.mouse.up(button="right")
            page.mouse.up(button="left")
            buttons = lambda: [(e["event"]["button"], e["event"]["state"]) for e in comet.state.hid if e["event_type"] == "mouse_button"]  # noqa: E731
            until(page, lambda: len(buttons()) >= 4, f"the buttons did not arrive: {comet.state.hid}")
            assert buttons() == [("left", True), ("right", True), ("right", False), ("left", False)], buttons()
            assert "mouse_relative" in pointer_events(comet) and "mouse_move" not in pointer_events(comet)
            # Keys go as ever.
            page.keyboard.press("KeyA")
            until(page, lambda: [e["event"]["key"] for e in comet.state.hid if e["event_type"] == "key"] == ["KeyA", "KeyA"], f"the key did not arrive: {comet.state.hid}")
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
    finally:
        comet.stop()


def test_a_kvm_whose_mouse_takes_places_only_is_not_offered_steps(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 160, 60)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=True)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            expect(page.locator("#focus-relative")).to_be_disabled()
            expect(page.locator("#focus-keys-note")).not_to_contain_text("steps only")
            page.mouse.click(*on_the_picture(page))
            until(page, lambda: pointer_events(comet).count("mouse_button") == 2, f"the click did not arrive: {comet.state.hid}")
            assert "mouse_move" in pointer_events(comet) and comet.state.pointer_dropped == 0
            page.keyboard.press("ControlRight")
            expect(page.locator("#focus-control")).to_have_text("Control")
    finally:
        comet.stop()


def test_the_click_that_hands_the_pointer_over_is_no_click_where_the_lock_comes_before_the_button_is_let_go(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # The browser may give the lock while the button of that click is still held: the next move of the hand then carried
    # that button, which went to the machine as a press (and the up as a release): a click, and a little drag, wherever
    # the machine's pointer was.
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-keys-note")).to_contain_text("moves by steps only")
            middle = on_the_picture(page)
            page.mouse.move(*middle)
            page.mouse.down(button="left")
            page.wait_for_function("() => document.pointerLockElement?.id === 'focus-canvas'")
            page.mouse.move(middle[0] + 3, middle[1] + 2, steps=3)
            page.mouse.up(button="left")
            page.mouse.move(middle[0] + 30, middle[1] + 20, steps=3)
            until(page, lambda: "mouse_relative" in pointer_events(comet), f"the moves did not arrive: {comet.state.hid}")
            page.wait_for_timeout(300)
            assert "mouse_button" not in pointer_events(comet), f"the click that handed the pointer over reached the machine: {comet.state.hid}"
    finally:
        comet.stop()


def test_a_click_after_a_hand_over_whose_button_was_let_go_elsewhere_reaches_the_machine_whole(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # The lock refused, and the button of that click let go beside the picture: its up never came, and the page went on
    # taking a button as the one of the hand-over. Relative mouse pressed then, the next click's press went to the machine
    # and its release did not: the button stayed down there until the hand moved.
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            middle = on_the_picture(page)
            page.evaluate("""() => {
              window.lockWas = HTMLCanvasElement.prototype.requestPointerLock;
              HTMLCanvasElement.prototype.requestPointerLock = () => Promise.reject(new Error('refused'));
            }""")
            page.mouse.move(*middle)
            page.mouse.down(button="left")
            page.mouse.move(5, 5, steps=2)  # (beside the picture, where its up does not come to the picture)
            page.mouse.up(button="left")
            page.evaluate("() => { HTMLCanvasElement.prototype.requestPointerLock = window.lockWas; }")
            page.locator("#focus-keys > summary").click()
            page.locator("#focus-relative").click()
            page.wait_for_function("() => document.pointerLockElement?.id === 'focus-canvas'")
            expect(page.locator("#focus-relative")).to_have_attribute("aria-pressed", "true")
            page.mouse.down(button="left")
            page.mouse.up(button="left")
            buttons = lambda: [(e["event"]["button"], e["event"]["state"]) for e in comet.state.hid if e["event_type"] == "mouse_button"]  # noqa: E731
            until(page, lambda: len(buttons()) >= 2, f"the click did not arrive whole: {comet.state.hid}")
            assert buttons() == [("left", True), ("left", False)], buttons()
    finally:
        comet.stop()


def test_keyboard_and_mouse_given_back_with_the_pointer_handed_over_and_taken_again_start_from_the_picture(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # Given back while the pointer was the machine's, the page went on taking the mouse as handed over when they were taken
    # again, with no lock: a click on the picture went to the machine as a click, and on a KVM that takes places only the
    # mouse sent steps it drops.
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            page.mouse.click(*on_the_picture(page))
            page.wait_for_function("() => document.pointerLockElement?.id === 'focus-canvas'")
            expect(page.locator("#focus-relative")).to_have_attribute("aria-pressed", "true")  # (the page has taken it as handed over)
            page.evaluate("() => document.querySelector('#focus-control').click()")  # Give back, with the pointer still locked
            expect(page.locator("#focus-control")).to_have_text("Control")
            page.wait_for_function("() => document.pointerLockElement === null")
            expect(page.locator("#focus-control")).to_be_enabled()  # (once the machine has said the giving back is through)
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            expect(page.locator("#focus-keys-note")).to_contain_text("moves by steps only")
            expect(page.locator("#focus-relative")).to_have_attribute("aria-pressed", "false")
            page.evaluate(SPY)
            page.mouse.click(*on_the_picture(page))
            page.wait_for_function("() => window.lockAsked >= 1")
            page.wait_for_timeout(300)
            assert "mouse_button" not in pointer_events(comet), f"a click went to the machine: {comet.state.hid}"
    finally:
        comet.stop()


def test_a_pointer_lock_granted_after_keyboard_and_mouse_were_given_back_is_let_go_of(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # Firefox and Safari answer the page's request for the pointer lock with nothing, and grant it when they grant it: a lock
    # that came after keyboard and mouse were given back kept this PC's pointer in the picture until Esc, with nothing of
    # it reaching the machine. (Played here by a request that says nothing and is granted when the test says.)
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            page.evaluate("""() => {
              window.lockAsked = 0;
              window.locked = [];
              document.addEventListener('pointerlockchange', () => window.locked.push(document.pointerLockElement?.id || null));
              const was = HTMLCanvasElement.prototype.requestPointerLock;
              HTMLCanvasElement.prototype.requestPointerLock = function (...how) {
                window.lockAsked += 1;
                window.grantLock = () => was.call(this);  // (as the page asks again where the first way is refused)
                return undefined;
              };
            }""")
            page.mouse.click(*on_the_picture(page))  # (hands the pointer over: the lock is asked for)
            page.wait_for_function("() => window.lockAsked >= 1")
            page.evaluate("() => document.querySelector('#focus-control').click()")  # Give back, before the lock came
            expect(page.locator("#focus-control")).to_have_text("Control")
            # Granted now, at the next click anywhere (a browser grants the lock only within a gesture of the hand).
            page.evaluate("""() => document.addEventListener('pointerdown', () => { window.grantLock()?.catch(() => {}); }, { once: true, capture: true })""")
            page.locator("#focus-name").click()
            page.wait_for_function("() => window.locked.includes('focus-canvas')")
            page.wait_for_function("() => document.pointerLockElement === null")
            page.wait_for_timeout(300)
            assert page.evaluate("() => document.pointerLockElement") is None
            assert "mouse_button" not in pointer_events(comet), f"a click went to the machine: {comet.state.hid}"
    finally:
        comet.stop()


def test_a_view_opened_after_one_whose_keyboard_was_given_back_hands_its_pointer_over(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # (The first review of this track.) The listener that lets go of a lock granted late was left by every give-back
    # without a lock, and the picture's canvas is every view's: in the next view, the first click that hands the pointer
    # over had the lock taken away again as it came.
    comet = FakeKvm(FakeState(picture=jpeg_picture(320, 240, (40, 60, 200)), picture_type="image/jpeg", width=320, height=240, mouse_absolute=False)).start()
    try:
        with the_program(tmp_path, comet) as live, looking(browser, live) as page:
            sign_in(page, live)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            page.keyboard.press("ControlRight")  # given back, with no lock asked for
            expect(page.locator("#focus-control")).to_have_text("Control")
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            expect(page.locator("#focus-control")).to_be_enabled()
            page.keyboard.press("c")
            expect(page.locator("#focus-control")).to_have_text("Give back")
            page.mouse.click(*on_the_picture(page))
            page.wait_for_function("() => document.pointerLockElement?.id === 'focus-canvas'")
            page.wait_for_timeout(500)
            assert page.evaluate("() => document.pointerLockElement?.id") == "focus-canvas", "the lock was taken away as it came"
            expect(page.locator("#focus-relative")).to_have_attribute("aria-pressed", "true")
            assert "mouse_button" not in pointer_events(comet), f"a click went to the machine: {comet.state.hid}"
    finally:
        comet.stop()
