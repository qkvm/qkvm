"""The tile of a KVM with a power board, in a browser, as a real Comet with its ATX board showed it (2026-10-14).

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Route, expect

from qkvm import kvm
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, tile, top  # noqa: F401  (fixtures, by name)


@pytest.fixture(autouse=True)
def as_the_wall_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Comet takes five or six seconds over each picture asked of it while its computer is off; the wall waits a
    # second and a half for one. Both shorter here, in the same order.
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 0.3)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)


def test_a_computer_its_kvms_board_says_is_off_is_off_or_asleep_on_its_tile(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # Off, a Comet's computer sends no picture, and every picture asked of the Comet is answered with nothing, seconds
    # later. The tile said "Connecting... The KVM is slow to answer" for as long as the computer was off, the count of
    # tiles without a signal stayed at nought, and the footer said "USB not connected" of a computer that had no USB.
    fake = FakeKvm(FakeState(atx=True, computer_on=False, signal=False, keyboard_online=False, no_signal_snapshot=1.0)).start()
    try:
        with a_wall(tmp_path, ("Demo PC", fake)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            shown = tile(page, "Demo PC")
            expect(shown).to_have_attribute("data-state", "no_signal")
            expect(shown.locator(".veil")).to_contain_text("No signal")
            expect(shown.locator(".veil")).to_contain_text("Its power board says the computer is off or asleep.")
            expect(page.locator('#filters button[data-filter="no_signal"] b')).to_have_text("1")
            expect(shown.locator(".meta")).to_contain_text("Power off")
            page.wait_for_timeout(3000)  # (some pictures asked for, and answered with nothing, meanwhile)
            expect(shown).to_have_attribute("data-state", "no_signal")
            expect(shown.locator(".meta")).not_to_contain_text("USB not connected")
            # Switched on: its picture, and the board's word in the footer.
            fake.state.computer_on = fake.state.signal = fake.state.keyboard_online = True
            expect(shown).to_have_attribute("data-state", "online")
            expect(shown.locator(".meta")).to_contain_text("Power on")
            # Its picture gone while the board says it is on (a screen asleep): no signal, said as before.
            fake.state.signal = False
            expect(shown).to_have_attribute("data-state", "no_signal")
            expect(shown.locator(".veil")).to_contain_text("The computer is off, asleep or not plugged into the KVM.")
    finally:
        fake.stop()


def test_a_power_button_whose_answer_is_no_answer_of_the_walls_own_is_not_offered_again(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # qKVM stopped while a board held the long press: the web server cut the request off with a bare 500, which the
    # page took for a refusal and offered under "Retry failed", which would press the button again. So it did with
    # `dropped` (sent, and its answer broken on the way: it may have been done) and with a slip of the wall's own.
    # (A page of its own here, without `looking`'s watch, which counts any 500 as the wall's error: this one is meant.)
    fakes = [FakeKvm(FakeState(atx=True, hostname=name)).start() for name in ("first", "second", "third")]
    try:
        with a_wall(tmp_path, ("First", fakes[0]), ("Second", fakes[1]), ("Third", fakes[2])) as (live, _):
            context = browser.new_context()
            try:
                page = context.new_page()
                answers = iter([
                    {"status": 500, "content_type": "text/plain; charset=utf-8", "body": "Internal Server Error"},
                    {"status": 502, "content_type": "application/json", "body": '{"code": "dropped", "message": "The answer broke off"}'},
                    {"status": 500, "content_type": "application/json", "body": '{"code": "internal", "message": "Something went wrong"}'},
                ])

                def answer(route: Route) -> None:
                    route.fulfill(**next(answers))

                sign_in(page, live)
                expect(page.locator('#wall article[data-state="online"]')).to_have_count(3)
                # (Each board heard of before the actions are offered: the menu offers what the selected machines can do as
                # it is opened, and opened before a busy computer had heard of the boards, it had no "Hold power button".)
                for name in ("First", "Second", "Third"):
                    expect(tile(page, name).locator(".meta")).to_contain_text("Power on")
                page.route("**/api/v1/devices/*/actions", answer)
                page.locator("#select-toggle").click()
                page.locator("#bulk-all").click()
                page.locator("#bulk-run").click()
                top(page).get_by_role("button", name="Hold power button").click()
                asking = top(page)
                asking.get_by_label("Yes, do this on all 3 machines").check()
                asking.locator("select").select_option(label="One after the other")
                asking.get_by_role("button", name="Run on 3 KVMs").click()
                run = page.locator("dialog[open]").filter(has=page.locator("ul.progress"))
                expect(run.locator(".actions button.primary")).to_have_text("Close")
                expect(run.locator(".actions button.primary")).to_be_visible()
                expect(run.locator("ul.progress li.unknown")).to_have_count(3)
                expect(run.locator("ul.progress")).to_contain_text("No answer. It may have been done.")
                expect(run.get_by_role("button", name="Retry failed")).to_be_hidden()
                expect(run.locator("p[role=status]")).to_have_text("0 succeeded, 3 without an answer.")
            finally:
                context.close()
    finally:
        for fake in fakes:
            fake.stop()
