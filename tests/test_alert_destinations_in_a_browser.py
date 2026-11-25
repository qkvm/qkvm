"""Settings > Alerts in a browser (0.4.0): destinations added in a box of their kind, which holds still, tried with Send
test, their log read, and no secret of theirs ever on the page.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Locator, Page, expect

from qkvm import alerts
from tests.fake_alerts import SLACK, TELEGRAM, Answer, FakeService
from tests.test_in_a_browser import a_wall, browser, looking, settings, sign_in, told, top, until  # noqa: F401  (fixtures, by name)

SLACK_URL = f"https://{SLACK}/services/T0/B0/S3CRETslackTOKEN"
TG_TOKEN = "123456789:AAH-S3CRET_telegram"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.1)


@pytest.fixture
def services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeService]:
    fake = FakeService(tmp_path / "services", monkeypatch)
    yield fake
    fake.close()


def add_box(page: Page, pane: Locator, kind: str) -> Locator:
    pane.locator(".section-head").get_by_role("button", name="Add destination").click()
    choose = top(page)
    choose.locator(".setting", has_text=kind).get_by_role("button", name="Choose").click()
    box = top(page)
    expect(box.locator(".dialog-head h2")).to_have_text(f"Add {kind}")
    return box


def where(box: Locator) -> tuple[float, float, float, float, float]:
    """The box's place and size, and where its Add button stands: once it has settled (it fades and grows in as it opens)."""
    box.evaluate("el => Promise.all(el.getAnimations({ subtree: true }).map(each => each.finished))")
    frame, button = box.bounding_box(), box.get_by_role("button", name="Add", exact=True).bounding_box()
    assert frame is not None and button is not None
    return (round(frame["x"]), round(frame["width"]), round(frame["height"]), round(button["x"]), round(button["y"]))


def address(box: Locator) -> Locator:
    return box.get_by_role("textbox", name=re.compile("^Address"))


def test_a_destination_is_added_in_a_box_that_holds_still_tried_and_its_log_read(tmp_path: Path, browser: Browser, services: FakeService) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "alerts")
        expect(pane.locator("p.nothing", has_text="None yet")).to_be_visible()
        # Every kind's box is one size, with its buttons where they stand, however much or little its kind asks.
        seen = set()
        for kind in ("Slack", "Email (SMTP)", "Telegram", "Webhook (JSON)"):
            box = add_box(page, pane, kind)
            seen.add(where(box))
            box.get_by_role("button", name="Cancel").click()
        assert len(seen) == 1, seen
        box = add_box(page, pane, "Slack")
        box.get_by_role("textbox", name=re.compile("^Name")).fill("Ops channel")
        address(box).fill(SLACK_URL)
        box.get_by_role("button", name="Add", exact=True).click()
        told(page, "Destination added")
        row = pane.locator("tr", has_text="Ops channel")
        expect(row).to_contain_text(SLACK)
        assert "S3CRETslackTOKEN" not in page.content()  # stored sealed, and never handed back to the page
        row.get_by_role("button", name="Send test").click()
        told(page, "Test alert delivered (HTTP 200)")
        until(page, lambda: len(services.at(SLACK)) == 1, "the test alert never arrived")
        assert "Test alert from qKVM" in json.loads(services.at(SLACK)[0].body)["text"]
        row.get_by_role("button", name="Log").click()
        log = top(page)
        expect(log.locator("tbody tr")).to_have_count(1)
        expect(log.locator("tbody tr").first).to_contain_text("Delivered")
        expect(log.locator("tbody tr").first).to_contain_text("A test")
        log.get_by_role("button", name="Close").click()
        # Edited without its address: the saved one is kept, and said to be.
        row.get_by_role("button", name="Edit").click()
        box = top(page)
        expect(address(box)).to_have_value("")
        expect(address(box)).to_have_attribute("placeholder", "Saved. Enter another to replace it.")
        box.locator("select").filter(has_text="Critical only").select_option("critical")
        box.get_by_role("button", name="Save", exact=True).click()
        told(page, "Destination saved")
        [saved] = admin.get("/api/v1/alerts/destinations").json()["destinations"]
        assert saved["least"] == "critical" and saved["host"] == SLACK and saved["name"] == "Ops channel"


def test_a_test_that_fails_says_the_services_own_words_and_the_list_keeps_them(tmp_path: Path, browser: Browser, services: FakeService) -> None:  # noqa: F811
    services.answers[TELEGRAM] = [Answer(400, b'{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}')]
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "alerts")
        box = add_box(page, pane, "Telegram")
        box.get_by_label("Bot token").fill(TG_TOKEN)
        box.get_by_label("Chat").fill("-1001234567890")
        box.get_by_role("button", name="Add", exact=True).click()
        told(page, "Destination added")
        row = pane.locator("tr", has_text="Telegram")
        row.get_by_role("button", name="Send test").click()
        told(page, "HTTP 400: Bad Request: chat not found")
        expect(pane.locator("tr", has_text="Telegram")).to_contain_text("Not delivered: HTTP 400: Bad Request: chat not found")
        assert "S3CRET_telegram" not in page.content()
        # Removed: alerts go there no more.
        pane.locator("tr", has_text="Telegram").get_by_role("button", name="Remove").click()
        top(page).get_by_role("button", name="Remove", exact=True).click()
        told(page, "Destination removed")
        assert admin.get("/api/v1/alerts/destinations").json()["destinations"] == []


def test_a_webhooks_signing_secret_is_shown_once_in_its_box(tmp_path: Path, browser: Browser, services: FakeService) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "alerts")
        box = add_box(page, pane, "Webhook (JSON)")
        address(box).fill("https://hooks.example.com/qkvm")
        before = where(box)
        box.get_by_role("button", name="Add", exact=True).click()
        secret = box.get_by_label("Signing secret").input_value()
        assert secret.startswith("whsec_")
        box.evaluate("el => Promise.all(el.getAnimations({ subtree: true }).map(each => each.finished))")
        frame = box.bounding_box()
        assert frame is not None and (round(frame["x"]), round(frame["width"]), round(frame["height"])) == before[:3]  # the same box
        box.get_by_role("button", name="I have it").click()
        expect(pane.locator("tr", has_text="hooks.example.com")).to_be_visible()
        assert secret not in page.content()
        assert admin.get("/api/v1/alerts/destinations").json()["destinations"][0]["signed"] is True


def test_the_section_shows_what_it_does_only_with_what_it_does_it_to(tmp_path: Path, browser: Browser, services: FakeService) -> None:  # noqa: F811
    # The Alerts section asks for two things, the alert settings and the destinations. Its Save came into its first line
    # with the first answer, while the second was still on its way: whoever scrolled the section in that moment (a test of
    # every section did, on a slow runner) had it filled in under them, and its footnote was out of sight.
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        assert admin.post("/api/v1/alerts/destinations", json={"kind": "slack", "url": SLACK_URL}).status_code == 201
        sign_in(page, live)
        held: list[object] = []
        page.route("**/api/v1/alerts/destinations", lambda route: held.append(route))
        page.locator("#open-settings").click()
        box = top(page)
        box.locator('[role=tab][data-tab="alerts"]').click()
        pane = box.locator("[role=tabpanel]")
        until(page, lambda: bool(held), "the destinations were never asked for")
        page.wait_for_timeout(300)
        expect(pane.locator(".section-head button")).to_have_count(0)  # nothing to press while the section is not there
        held[0].continue_()  # type: ignore[attr-defined]
        page.unroute("**/api/v1/alerts/destinations")
        save = pane.locator(".section-head").get_by_role("button", name="Save")
        expect(save).to_be_visible()
        expect(pane.locator("tr", has_text=SLACK)).to_be_visible()
        pane.evaluate("el => el.scrollTo(0, el.scrollHeight)")
        expect(pane.locator("p.footnote")).to_be_in_viewport()
        expect(save).to_be_in_viewport()


def test_the_box_asks_for_a_saved_password_again_where_the_destination_is_reached_elsewhere(tmp_path: Path, browser: Browser, services: FakeService) -> None:  # noqa: F811
    # (The review of 0.4.0's first wave, H1.) The password field said "Saved. Enter another to replace it." while the mail
    # server stayed editable: a saved password went with the destination to another server.
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        said = {"kind": "email", "host": "smtp.example.com", "port": 587, "user": "alerts@example.com", "password": "KEPT-app-password",
                "sender": "alerts@example.com", "to": ["ops@example.com"]}  # fmt: skip
        assert admin.post("/api/v1/alerts/destinations", json=said).status_code == 201
        sign_in(page, live)
        pane = settings(page, "alerts")
        pane.locator("tr", has_text="smtp.example.com").get_by_role("button", name="Edit").click()
        box = top(page)
        password = box.get_by_role("textbox", name=re.compile("^Password"))
        expect(password).to_have_attribute("placeholder", "Saved. Enter another to replace it.")
        box.get_by_role("textbox", name=re.compile("^Mail server")).fill("mail.example.org")
        expect(password).to_have_attribute("placeholder", "Type it again: it is reached elsewhere now")
        assert password.evaluate("el => el.required") is True
        box.get_by_role("button", name="Save", exact=True).click()
        assert password.evaluate("el => el.validity.valueMissing") is True  # the box holds it back
        assert admin.get("/api/v1/alerts/destinations").json()["destinations"][0]["config"]["host"] == "smtp.example.com"
        box.get_by_role("textbox", name=re.compile("^Mail server")).fill("smtp.example.com")
        assert password.evaluate("el => el.required") is False  # (back where it was saved for: the saved one stays)
        box.get_by_role("textbox", name=re.compile("^Mail server")).fill("mail.example.org")
        password.fill("typed for it")
        box.get_by_role("button", name="Save", exact=True).click()
        told(page, "Destination saved")
        assert admin.get("/api/v1/alerts/destinations").json()["destinations"][0]["config"]["host"] == "mail.example.org"
