"""The confirmation names a person but sends the exact observed control reference."""
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm
from tests.test_in_a_browser import browser, fast, looking, sign_in, top, until  # noqa: F401
from tests.test_live_in_a_browser import a_live_wall, enlarged, fakes, jpeg_picture  # noqa: F401


@pytest.mark.parametrize("fields,expected", [
    ({"from": "opaque-control-grant-42"}, "opaque-control-grant-42"),
    ({}, "a" * 60 + "1111"),  # compatibility with older servers, only when the reference is absent
    ({"from": None}, None),
    ({"from": ""}, None),
    ({"from": "x" * 201}, None),
    ({"from": {"wrong": "type"}}, None),
], ids=["opaque", "legacy", "null", "empty", "oversize", "object"])
def test_takeover_keeps_the_full_name_and_uses_only_a_valid_reference(tmp_path: Path, browser: Browser, fakes: list[FakeKvm], fields: dict[str, Any], expected: str | None) -> None:  # noqa: F811
    name = "a" * 60 + "1111" if not fields else "Alice"
    stand_in, _ = a_live_wall(tmp_path, fakes, pictures=[(True, jpeg_picture(320, 240, (40, 80, 120)))], codec="jpeg", width=320, height=240, pace=10)
    stand_in.refuse_control = {"code": "taken", "message": "Another viewer holds control", "by": name, **fields}
    try:
        with looking(browser, stand_in) as page:
            sign_in(page, stand_in)
            enlarged(page, "Machine 1")
            page.wait_for_function("() => Number(document.querySelector('#focus-live').dataset.drawn) >= 1")
            page.locator("#focus-control").click()
            line = stand_in.line()
            expect(page.locator("#focus-control")).to_contain_text(name)
            if expected is None:
                expect(page.locator("#focus-control")).to_have_text(f"Controlled by {name}")
                page.locator("#focus-control").click()
                until(page, lambda: len(line.said("control")) == 2, "ordinary control was not requested")
                expect(page.locator("dialog[open]")).to_have_count(0)
                assert not any(word.get("take") for word in line.said("control"))
                return
            expect(page.locator("#focus-control")).to_have_text(f"Take over from {name}")
            page.locator("#focus-control").click()
            dialog = top(page)
            expect(dialog).to_contain_text(f"{name} has the keyboard and mouse")
            expect(dialog).to_have_css("opacity", "1")
            expect(dialog).to_have_css("flex-direction", "column")
            dialog.screenshot(path=str(tmp_path / "takeover-open.png"))
            assert line.said("control") == [{"t": "control", "on": True}]
            dialog.get_by_role("button", name="Take over", exact=True).click()
            until(page, lambda: len(line.said("control")) == 2, "confirmed takeover was not requested")
            assert line.said("control")[1] == {"t": "control", "on": True, "take": True, "from": expected}
    finally:
        stand_in.__exit__()
