"""The enlarged view's size of the picture, in a browser: Fit (the default) or a scale of the machine's own pixels.

At the bottom of the enlarged view, beside the stream's numbers: Fit, 50, 75, 100, 125, 140 and 200 %, one machine pixel to
so many of this screen's (100 %: one to one, whatever the system's scaling). Smaller than the view, the picture is centred;
larger, it scrolls: by its scroll bars and the wheel, or by a drag while nobody here holds the machine's keyboard and mouse.
While they are held, keys, clicks, drags and the wheel are the machine's as ever, and a click lands on the machine's pixel it
was made on at every size. The choice is kept by the browser for each machine, by its id.

Against the live line's stand-in (tests/test_live_in_a_browser.py): a JPEG picture of 640 by 480, and what the page says of
the pointer, read as the machine's pixels.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Page, expect

from tests.fake_kvm import FakeKvm
from tests.test_in_a_browser import browser, fast, looking, sign_in, until  # noqa: F401  (the fixtures)
from tests.test_live_in_a_browser import FARTHEST, KEY_A, Line, LiveStandIn, a_live_wall, enlarged, fakes, jpeg_picture, take_control  # noqa: F401

WIDTH, HEIGHT = 640, 480  # the machine's screen, as the stand-in's line sends it
SIZES = {"50": 0.5, "75": 0.75, "100": 1.0, "125": 1.25, "140": 1.4, "200": 2.0}


def a_wall_with_a_picture(tmp_path: Path, fakes: list[FakeKvm]) -> LiveStandIn:  # noqa: F811
    picture = jpeg_picture(WIDTH, HEIGHT, (40, 90, 160))
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=[(True, picture)], codec="jpeg", width=WIDTH, height=HEIGHT, pace=5)
    return stand_in


def live_drawn(page: Page) -> None:
    page.wait_for_function(f"() => Number(document.querySelector('#focus-live').dataset.drawn) >= 2 && document.querySelector('#focus-live').dataset.width === '{WIDTH}'")


def sized(page: Page, scale: float) -> dict[str, float]:
    """Once the canvas has the size of the picture at this scale (0: fitted into the view): where it lies, and how large it is."""
    if scale:
        page.wait_for_function(f"() => document.querySelector('#focus-canvas').width === {round(WIDTH * scale)} && document.querySelector('#focus-canvas').height === {round(HEIGHT * scale)}")
    found: dict[str, float] = page.evaluate("""() => {
      const canvas = document.querySelector('#focus-canvas'), scroller = document.querySelector('#focus-scroll');
      const at = canvas.getBoundingClientRect(), view = scroller.getBoundingClientRect();
      return { left: at.left, top: at.top, width: at.width, height: at.height, pixels: canvas.width, rows: canvas.height,
               ratio: window.devicePixelRatio, viewLeft: view.left, viewTop: view.top, viewWidth: scroller.clientWidth,
               viewHeight: scroller.clientHeight, scrollWidth: scroller.scrollWidth, scrollHeight: scroller.scrollHeight,
               scrollLeft: scroller.scrollLeft, scrollTop: scroller.scrollTop };
    }""")
    return found


def choose(page: Page, value: str) -> None:
    page.locator("#focus-scale").select_option(value)


def pixel_said(line: Line, before: int) -> tuple[float, float]:
    """Where the machine's pointer was put right before the first press after word number `before`, in the machine's pixels."""
    words = line.words[before:]
    at = next(number for number, word in enumerate(words) if word.get("t") == "mb")
    place = next(word for word in reversed(words[:at]) if word.get("t") == "m")
    return place["x"] * WIDTH / FARTHEST, place["y"] * HEIGHT / FARTHEST


def click_on_pixel(page: Page, line: Line, box: dict[str, float], scale: float, pixel: tuple[int, int]) -> tuple[float, float]:
    """A click in the middle of this pixel of the machine's screen, as it lies on the page now; where the page said it was."""
    css = scale / box["ratio"]  # CSS pixels a machine pixel takes
    x, y = box["left"] + (pixel[0] + 0.5) * css, box["top"] + (pixel[1] + 0.5) * css
    assert box["viewLeft"] <= x < box["viewLeft"] + box["viewWidth"] and box["viewTop"] <= y < box["viewTop"] + box["viewHeight"], (x, y, box)
    before = len(line.words)
    page.mouse.click(x, y)
    until(page, lambda: len([word for word in line.words[before:] if word.get("t") == "mb"]) >= 2, f"the click did not arrive: {line.words[before:]}")
    return pixel_said(line, before)


def on_the_pixel(said: tuple[float, float], pixel: tuple[int, int]) -> bool:
    return math.floor(said[0]) == pixel[0] and math.floor(said[1]) == pixel[1]


def test_each_size_is_the_machines_pixels_at_that_scale_and_fit_is_the_default(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    stand_in = a_wall_with_a_picture(tmp_path, fakes)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 800}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            live_drawn(page)
            pick = page.locator("#focus-scale")
            expect(pick).to_have_value("fit")
            expect(page.locator("#focus-scale-pick svg.icon").first).to_be_visible()
            assert [option.strip() for option in pick.locator("option").all_inner_texts()] == ["Fit", "50 %", "75 %", "100 %", "125 %", "140 %", "200 %"]
            fit = sized(page, 0)
            assert abs(fit["width"] - fit["viewWidth"]) < 1.5 and abs(fit["height"] - fit["viewHeight"]) < 1.5, fit  # (the box: as before)
            for value, scale in SIZES.items():
                choose(page, value)
                box = sized(page, scale)
                assert abs(box["width"] - WIDTH * scale) < 0.6 and abs(box["height"] - HEIGHT * scale) < 0.6, (value, box)
                larger = WIDTH * scale > box["viewWidth"] or HEIGHT * scale > box["viewHeight"]
                if not larger:  # smaller than the view: in its middle
                    assert abs(box["left"] - box["viewLeft"] - (box["viewWidth"] - box["width"]) / 2) <= 1, (value, box)
                    assert abs(box["top"] - box["viewTop"] - (box["viewHeight"] - box["height"]) / 2) <= 1, (value, box)
                else:  # larger: it scrolls, from its edge
                    assert box["scrollWidth"] >= round(box["width"]) - 1 and box["scrollHeight"] >= round(box["height"]) - 1, (value, box)
            choose(page, "fit")
            fit_again = sized(page, 0)
            assert abs(fit_again["width"] - fit["width"]) < 1 and page.locator("#focus-screen.scaled").count() == 0
        # 100 % is one machine pixel to one pixel of the screen, not of the page: on a screen of twice the density, half as wide.
        with looking(browser, stand_in, viewport={"width": 1280, "height": 800}, device_scale_factor=2) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            live_drawn(page)
            choose(page, "100")
            box = sized(page, 1.0)
            assert box["ratio"] == 2 and box["pixels"] == WIDTH and abs(box["width"] - WIDTH / 2) < 0.6, box
    finally:
        stand_in.__exit__()


def test_a_click_lands_on_the_machines_pixel_at_half_and_at_twice_the_size_and_a_drag_moves_a_large_picture(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    stand_in = a_wall_with_a_picture(tmp_path, fakes)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 720}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            live_drawn(page)
            choose(page, "200")
            box = sized(page, 2.0)
            assert box["scrollHeight"] > box["viewHeight"], box  # (larger than the view: it scrolls)
            # Viewing: a drag moves the picture, and nothing goes to the machine.
            line = stand_in.line()
            before = len(line.words)
            middle = (box["viewLeft"] + box["viewWidth"] / 2, box["viewTop"] + box["viewHeight"] / 2)
            page.mouse.move(*middle)
            page.mouse.down()
            page.mouse.move(middle[0] - 150, middle[1] - 120, steps=5)
            page.mouse.up()
            moved = sized(page, 2.0)
            assert moved["scrollTop"] > 60, moved
            assert [word for word in line.words[before:] if word.get("t") in ("m", "mb")] == []
            # Holding keyboard and mouse: a click lands on the machine pixel it was made on, scrolled as it is.
            line = take_control(page, stand_in)
            box = sized(page, 2.0)
            first_row = math.ceil(box["scrollTop"] / 2) + 2  # (a row of the machine's that is in the view now)
            for pixel in [(101, first_row + 10), (37, first_row + 3)]:
                said = click_on_pixel(page, line, box, 2.0, pixel)
                assert on_the_pixel(said, pixel), (pixel, said)
            # The same at half the size, centred; and a size chosen while the keys are the machine's keeps them so.
            choose(page, "50")
            box = sized(page, 0.5)
            page.keyboard.press("KeyA")
            until(page, lambda: (KEY_A, True) in line.keys(), f"a key after the choice did not go to the machine: {line.keys()}")
            for pixel in [(320, 240), (13, 470), (633, 7)]:
                said = click_on_pixel(page, line, box, 0.5, pixel)
                assert on_the_pixel(said, pixel), (pixel, said)
            # While keyboard and mouse are held, a drag is the machine's: the picture stays where it is.
            choose(page, "200")
            box = sized(page, 2.0)
            before = len(line.words)
            page.mouse.move(box["viewLeft"] + 300, box["viewTop"] + 300)
            page.mouse.down()
            page.mouse.move(box["viewLeft"] + 150, box["viewTop"] + 150, steps=5)
            page.mouse.up()
            until(page, lambda: len([word for word in line.words[before:] if word.get("t") == "mb"]) >= 2, "the drag did not go to the machine")
            assert sized(page, 2.0)["scrollTop"] == box["scrollTop"]
    finally:
        stand_in.__exit__()


def test_the_size_is_kept_across_a_reload_for_each_machine_of_its_own(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:  # noqa: F811
    stand_in = a_wall_with_a_picture(tmp_path, fakes)
    try:
        with looking(browser, stand_in, viewport={"width": 1280, "height": 800}) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            live_drawn(page)
            choose(page, "140")
            sized(page, 1.4)
            page.keyboard.press("ArrowRight")  # the next machine: its own, untouched, is Fit
            expect(page.locator("#focus-name")).to_have_text("Machine 2")
            expect(page.locator("#focus-scale")).to_have_value("fit")
            choose(page, "75")
            page.reload()
            expect(page.locator("#shell")).to_be_visible()
            enlarged(page, "Machine 1")
            expect(page.locator("#focus-scale")).to_have_value("140")
            live_drawn(page)
            sized(page, 1.4)
            page.keyboard.press("ArrowRight")
            expect(page.locator("#focus-name")).to_have_text("Machine 2")
            expect(page.locator("#focus-scale")).to_have_value("75")
            kept: Any = page.evaluate("() => Object.keys(localStorage).filter(key => key.startsWith('qkvm.scale.')).sort()")
            assert len(kept) == 2 and all(len(key) == len("qkvm.scale.") + 8 for key in kept), kept  # (by each machine's id)
    finally:
        stand_in.__exit__()
