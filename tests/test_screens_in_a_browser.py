"""The screen watch in a browser: set in a machine's Edit box, and the picture an alert kept, shown from the activity log.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import alerts, screens
from qkvm.video import RGBFrame, encode_jpeg
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_alerts import Inbox
from tests.test_in_a_browser import a_wall, browser, looking, settings, sign_in, tile, told, top, until  # noqa: F401  (fixtures, by name)


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.1)
    monkeypatch.setattr(screens, "MINUTE", 0.5)  # (a minute is half a second here)


def test_the_watches_are_set_in_the_edit_box_and_an_alerts_picture_is_shown_from_the_log(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    still = encode_jpeg(RGBFrame(320, 180, bytes([70, 90, 120]) * (320 * 180)), None, 3)
    inbox = Inbox()
    fake = FakeKvm(FakeState(picture=still, picture_type="image/jpeg")).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin), looking(browser, live) as page:
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            sign_in(page, live)
            shown = tile(page, "Build server")
            shown.hover()
            shown.get_by_role("button", name="Actions for Build server").click()
            top(page).get_by_role("button", name="Edit...").click()
            box = top(page)
            expect(box.get_by_label("No signal for")).to_have_value("")
            expect(box.get_by_label("Screen unchanged for")).to_have_value("")
            box.get_by_label("No signal for").fill("15")
            box.get_by_label("Screen unchanged for").fill("1")
            box.get_by_role("button", name="Save").click()
            told(page, "Build server saved")
            device = admin.get("/api/v1/wall").json()["devices"][0]
            assert (device["no_signal_minutes"], device["unchanged_minutes"]) == (15, 1)
            # The tile is on this screen: the wall has its pictures, and they look the same.
            until(page, lambda: "Build server: screen unchanged for 1 min" in inbox.titles(), f"the screen was never told: {inbox.titles()}")
            pane = settings(page, "activity")
            line = pane.locator("tr", has_text="Screen unchanged for 1 minute")
            expect(line).to_have_count(1)
            line.get_by_role("button", name="Picture").click()
            seen = top(page)
            expect(seen.locator("h2")).to_have_text("Build server: Screen unchanged for 1 minute")
            picture = seen.locator("img.alert-picture")
            expect(picture).to_be_visible()
            until(page, lambda: picture.evaluate("shown => shown.complete && shown.naturalWidth") == 320, "the picture was never drawn")
            expect(seen).to_contain_text("Seen by the wall")
            # One that is no longer kept says so, where the picture would be (on a page that had not shown it yet).
            entry = next(e for e in admin.get("/api/v1/audit", params={"kind": "alert"}).json()["entries"] if e.get("picture"))
            assert entry["device_id"] == device["id"]
            for kept in (tmp_path / screens.FOLDER).iterdir():
                kept.unlink()
            page.reload()
            expect(page.locator("#shell")).to_be_visible()
            settings(page, "activity").locator("tr", has_text="Screen unchanged for 1 minute").get_by_role("button", name="Picture").click()
            expect(top(page).get_by_text("This picture is no longer kept")).to_be_visible()
            expect(top(page).locator("img.alert-picture")).to_have_count(0)
    finally:
        fake.stop()
        inbox.close()
