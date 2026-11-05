"""The three views of a PC with Intel AMT, in a browser: the Actions box offers them, the tile and its large view say which
one the PC is in, and health only leaves the PC alone.

An admin and an operator change the view under Actions (an operator edits no tile otherwise); somebody who may only look is
not offered it. Health only: the tile and the large view show how the PC is, with the words that say how to change the
view, and the page asks the PC for no picture and no live line, so no KVM session is opened (counted at the stand-in). The
view is the server's: kept across a reload. See tests/test_amt_views.py for what each view does at the PC.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Page, expect

from qkvm.amt import HEALTH_ONLY
from tests.fake_amt import AmtState, FakeAmt
from tests.test_in_a_browser import a_wall, browser, fast, looking, sign_in, tile, told, top, until  # noqa: F401  (the fixtures)
from tests.test_users import OTHER


def views_box(page: Page, name: str) -> None:
    page.get_by_role("button", name=f"Actions for {name}").click()
    expect(top(page).get_by_role("heading", name="View")).to_be_visible()


def view_button(page: Page, which: str):  # type: ignore[no-untyped-def]
    return top(page).get_by_role("button", name=re.compile(rf"^{which}"))


def test_the_actions_box_offers_the_three_views_and_health_only_leaves_the_pc_alone(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    pc = FakeAmt(AmtState()).start()
    try:
        with a_wall(tmp_path, ("A PC", pc)) as (live, admin), looking(browser, live) as page:  # type: ignore[arg-type]
            sign_in(page, live)
            pc_tile = tile(page, "A PC")
            # A new tile: stills, and the tile says so with the age of the still it shows.
            expect(pc_tile.locator(".meta")).to_contain_text(re.compile(r"Stills, \d+ (s|min) ago"), timeout=40_000)
            views_box(page, "A PC")
            for which in ("Health only", "Stills", "Live KVM"):
                expect(view_button(page, which).locator("svg.icon")).to_have_count(1)  # (every button with its icon)
            expect(view_button(page, "Stills")).to_be_disabled()
            expect(view_button(page, "Stills")).to_contain_text("now")
            view_button(page, "Health only").click()
            told(page, "A PC: Health only")
            expect(page.locator("dialog[open]")).to_have_count(0)
            # The tile shows how the PC is, and says why there is no screen and how to change that.
            expect(pc_tile.locator(".meta")).to_contain_text("Health only")
            expect(pc_tile.locator(".panel-why")).to_contain_text(HEALTH_ONLY)
            expect(pc_tile).to_have_class(re.compile(r"\bhas-panel\b"))  # (its last still is not shown as its screen)
            expect(pc_tile).not_to_have_class(re.compile(r"\bpictured\b"))
            # Its large view as well: no picture, no live line, no Control, and no size for a picture.
            asked: list[str] = []
            page.on("request", lambda request: asked.append(request.url) if "/snapshot" in request.url or request.url.endswith("/live") else None)
            pc_tile.click()
            expect(page.locator("#focus")).to_be_visible()
            expect(page.locator("#focus-meta")).to_contain_text("Health only")
            expect(page.locator("#focus-panel .panel-why")).to_contain_text(HEALTH_ONLY)
            expect(page.locator("#focus-control")).to_be_hidden()
            expect(page.locator("#focus-live")).to_have_text("No live picture: health only")
            expect(page.locator("#focus-scale-pick")).to_be_hidden()
            sessions = pc.state.kvm_sessions
            until(page, lambda: pc.state.redirection_open == 0, "the session of the still outlived the change")
            page.wait_for_timeout(2500)
            assert [url for url in asked if "/devices/" in url] == [], asked
            assert (pc.state.kvm_sessions, pc.state.redirection_open) == (sessions, 0)
            # The Actions box of the large view offers the way back; and the server keeps the view: a reload shows it.
            page.locator("#focus-actions").click()
            expect(view_button(page, "Health only")).to_be_disabled()
            expect(top(page).get_by_role("button", name="Type text...")).to_have_count(0)  # (no keys, no text: no session)
            page.keyboard.press("Escape")
            page.reload()
            expect(page.locator("#shell")).to_be_visible()
            expect(tile(page, "A PC").locator(".meta")).to_contain_text("Health only", timeout=40_000)
            written = [(entry.get("view"), entry.get("was")) for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "amt_view_changed"]
            assert written == [("health", "stills")], written
    finally:
        pc.stop()


def test_an_operator_changes_the_view_and_a_viewer_is_not_offered_it(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    pc = FakeAmt(AmtState()).start()
    try:
        with a_wall(tmp_path, ("A PC", pc)) as (live, admin):  # type: ignore[arg-type]
            for name, role in (("olga", "operator"), ("victor", "viewer")):
                assert admin.post("/api/v1/users", json={"name": name, "role": role, "password": OTHER}).status_code == 201
            with looking(browser, live) as page:
                sign_in(page, live, OTHER, name="olga")
                pc_tile = tile(page, "A PC")
                expect(pc_tile).to_have_attribute("data-state", "online", timeout=40_000)
                views_box(page, "A PC")
                view_button(page, "Live KVM").click()
                told(page, "A PC: Live KVM")
                expect(pc_tile.locator(".meta")).to_contain_text("Live KVM")
                # Shown on the wall, a tile set to live KVM holds its session: one, open while it is shown.
                until(page, lambda: pc.state.redirection_open == 1, "the shown tile holds no session")
                page.wait_for_timeout(1500)  # (the short session of the still it showed before may have been the one open)
                held = pc.state.kvm_sessions
                page.wait_for_timeout(2500)
                assert (pc.state.kvm_sessions, pc.state.redirection_open) == (held, 1)
            assert [entry.get("user") for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "amt_view_changed"] == ["olga"]
            with looking(browser, live) as page:
                # Somebody who may only look is told which view it is in, and has no Actions box to change it in.
                sign_in(page, live, OTHER, name="victor")
                expect(tile(page, "A PC").locator(".meta")).to_contain_text("Live KVM", timeout=40_000)
                expect(page.get_by_role("button", name="Actions for A PC")).to_be_hidden()
                tile(page, "A PC").click()
                expect(page.locator("#focus-meta")).to_contain_text("Live KVM")
                expect(page.locator("#focus-actions")).to_be_hidden()
    finally:
        pc.stop()
