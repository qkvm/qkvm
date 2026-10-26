"""A Fingerbot paired with a Comet, in a browser: its tile, its buttons in the actions, a run over several, its Edit box.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import kvm
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, tile, told, top, until  # noqa: F401  (fixtures, by name)


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    # (Times the Comet takes: 500 ms, or whole seconds. raising=False: on a program without them the tests run all the same.)
    monkeypatch.setattr(kvm, "FINGERBOT_PRESSES", {"fingerbot_power": 0.5, "fingerbot_power_long": 1.0}, raising=False)
    monkeypatch.setattr(kvm, "FINGERBOT_BACK", 0.0, raising=False)


def test_a_fingerbot_is_on_its_tile_and_presses_from_the_actions(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # The tile says a Fingerbot is there, and that its battery is low; the actions offer its two presses beside a power
    # board's, under its own name; each is asked first, with what it does; the answer is said.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_battery=12, atx=True, fingerbot_answer=0.2)).start()
    try:
        with a_wall(tmp_path, ("Bench PC", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            shown = tile(page, "Bench PC")
            expect(shown.locator(".meta")).to_contain_text("Fingerbot battery low (12%)")
            shown.hover()
            shown.get_by_role("button", name="Actions for Bench PC").click()
            menu = top(page)
            expect(menu.locator(".note.warn", has_text="Fingerbot")).to_contain_text("The battery of its Fingerbot is low (12 %)")
            for name in ("Press power button", "Hold power button", "Press with Fingerbot", "Hold with Fingerbot"):
                expect(menu.get_by_role("button", name=name)).to_be_visible()
            menu.get_by_role("button", name="Hold with Fingerbot").click()
            asking = top(page)
            expect(asking).to_contain_text("The Fingerbot holds the power button for 8 seconds, which cuts the power.")
            asking.get_by_role("button", name="Hold with Fingerbot").click()
            told(page, "Bench PC: held by the Fingerbot")
            assert fake.state.presses == [("1000", "2")] and fake.state.actions == ["fingerbot 1000 2"]
    finally:
        fake.stop()


def test_a_run_over_several_presses_where_a_fingerbot_is_and_says_where_none_is(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # A run goes to every machine picked; one without a Fingerbot is refused before anything is sent to it, and that
    # is a failure the page offers again (nothing went out), not "no answer".
    with_bot, without = FakeKvm(FakeState(fingerbot=True)).start(), FakeKvm(FakeState(hostname="other")).start()
    try:
        with a_wall(tmp_path, ("With", with_bot), ("Without", without)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "With").locator(".meta")).to_contain_text("Fingerbot")
            expect(page.locator('#wall article[data-state="online"]')).to_have_count(2)
            page.locator("#select-toggle").click()
            page.locator("#bulk-all").click()
            page.locator("#bulk-run").click()
            top(page).get_by_role("button", name="Press with Fingerbot").click()
            asking = top(page)
            asking.get_by_label("Yes, do this on all 2 machines").check()
            asking.get_by_role("button", name="Run on 2 KVMs").click()
            run = page.locator("dialog[open]").filter(has=page.locator("ul.progress"))
            expect(run.locator("p[role=status]")).to_have_text("1 succeeded, 1 failed.")
            expect(run.locator("ul.progress li.ok")).to_contain_text("pressed by the Fingerbot")
            expect(run.locator("ul.progress li.bad")).to_contain_text("No Fingerbot is paired with this KVM")
            expect(run.get_by_role("button", name="Retry failed")).to_be_visible()
            assert with_bot.state.presses == [("500", "2")] and without.state.presses == []
    finally:
        with_bot.stop()
        without.stop()


def test_how_hard_it_presses_is_set_in_the_edit_box(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    fake = FakeKvm(FakeState(fingerbot=True)).start()
    plain = FakeKvm(FakeState(hostname="plain")).start()
    try:
        with a_wall(tmp_path, ("Bench PC", fake), ("Plain", plain)) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "Bench PC").locator(".meta")).to_contain_text("Fingerbot")
            # Not offered where the KVM has none.
            tile(page, "Plain").hover()
            tile(page, "Plain").get_by_role("button", name="Actions for Plain").click()
            top(page).get_by_role("button", name="Edit...").click()
            expect(top(page).get_by_label("Fingerbot")).to_have_count(0)
            top(page).get_by_role("button", name="Cancel").click()
            page.keyboard.press("Escape")
            tile(page, "Bench PC").hover()
            tile(page, "Bench PC").get_by_role("button", name="Actions for Bench PC").click()
            top(page).get_by_role("button", name="Edit...").click()
            box = top(page)
            expect(box.get_by_label("Fingerbot")).to_have_value("firm")
            box.get_by_label("Fingerbot").select_option("light")
            box.get_by_role("button", name="Save").click()
            told(page, "Bench PC saved")
            device = next(d for d in admin.get("/api/v1/wall").json()["devices"] if d["name"] == "Bench PC")
            assert device["fingerbot_strength"] == "light"
            assert admin.post(f"/api/v1/devices/{device['id']}/actions", json={"action": "fingerbot_power"}).status_code == 200
            until(page, lambda: fake.state.presses == [("500", "1")], f"pressed as {fake.state.presses}")
    finally:
        fake.stop()
        plain.stop()
