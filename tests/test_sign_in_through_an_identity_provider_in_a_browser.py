"""Signing in through an identity provider, in a browser (0.4.0): the box in Settings > Accounts that sets it up, which
holds still and never shows the client secret again; and the button on the sign-in page, followed to the provider and
back as a browser follows it, its cookies held to their SameSite rules by the browser itself.

The provider is the stand-in of tests/fake_oidc.py. A browser cannot reach it by its name, so its authorization page is
played by the test: the browser's request to it is answered with the redirect back to the wall that a person's sign-in
there ends with (Playwright's route). Its token endpoint and its keys are reached by the wall itself, as for real.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Page, Route, expect

from tests.fake_oidc import CLIENT, IDP, ISSUER, SECRET, FakeIdp
from tests.test_in_a_browser import PATIENCE, a_wall, browser, fast, looking, settings, sign_in, told, top  # noqa: F401  (fixtures, by name)

ROLES = [{"group": "wall-ops", "role": "operator"}]


@pytest.fixture
def idp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeIdp]:
    fake = FakeIdp(tmp_path / "idp", monkeypatch)
    fake.person("olga", email="olga@example.org", groups=["wall-ops"])
    yield fake
    fake.close()


def where(box: Any) -> tuple[float, ...]:
    """The box's place and size, and where its Save stands: once it has settled."""
    box.evaluate("el => Promise.all(el.getAnimations({ subtree: true }).map(each => each.finished))")
    frame, button = box.bounding_box(), box.get_by_role("button", name="Save", exact=True).bounding_box()
    assert frame is not None and button is not None
    return (round(frame["x"]), round(frame["width"]), round(frame["height"]), round(button["x"]), round(button["y"]))


def test_the_provider_is_set_up_in_a_box_that_holds_still_and_keeps_its_secret(tmp_path: Path, browser: Browser, idp: FakeIdp) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "users")
        block = pane.locator("section.block", has_text="Identity provider")
        expect(block).to_contain_text("Off")
        block.get_by_role("button", name="Set up").click()
        box = top(page)
        expect(box.locator(".dialog-head h2")).to_have_text("Identity provider")
        # The redirect address is this wall's own, as the browser is looking at it: what is entered at the provider.
        expect(box.get_by_role("textbox", name="Redirect URI", exact=True)).to_have_value(f"{live.url}/api/v1/oidc/callback")
        empty = where(box)
        box.get_by_role("textbox", name=re.compile("^Issuer")).fill(ISSUER)
        box.get_by_role("textbox", name=re.compile("^Client ID")).fill(CLIENT)
        box.get_by_label("Client secret").fill(SECRET)
        for number in range(8):  # (more groups than the box has room for: only its inside scrolls)
            box.get_by_role("button", name="Add a group").click()
            box.get_by_role("textbox", name="Group", exact=True).last.fill("wall-ops" if number == 0 else f"group-{number}")
        assert where(box) == empty, "the box moved, or its Save did, as it filled"
        # Anybody else let in, and no email domain: said where it is chosen, for every provider (review L1).
        anyone = box.get_by_role("combobox", name=re.compile("^Who else may sign in"))
        warning = box.locator(".note.warn", has_text="Anybody")
        expect(warning).to_be_hidden()
        anyone.select_option("viewer")
        expect(warning).to_be_visible()
        box.get_by_role("textbox", name=re.compile("^Email domain")).fill("example.org")
        expect(warning).to_be_hidden()
        box.get_by_role("textbox", name=re.compile("^Email domain")).fill("")
        anyone.select_option("")
        expect(warning).to_be_hidden()
        assert where(box) == empty, "the box moved, or its Save did, with the warning"
        box.get_by_role("combobox", name="Role it gives", exact=True).first.select_option("operator")
        box.get_by_role("button", name="Save", exact=True).click()
        told(page, "Identity provider saved")
        expect(block).to_contain_text(f'On: "Sign in with {IDP}"')
        assert SECRET not in page.content()  # sealed by the wall, and never handed back
        saved = admin.get("/api/v1/oidc").json()
        assert saved["enabled"] is True and saved["roles"][0] == {"group": "wall-ops", "role": "operator"} and len(saved["roles"]) == 8
        assert saved["redirect_uri"] == f"{live.url}/api/v1/oidc/callback"
        # Opened again: the secret is said to be saved, and is not there to be read.
        block.get_by_role("button", name="Change").click()
        box = top(page)
        expect(box.get_by_label("Client secret")).to_have_value("")
        expect(box.get_by_label("Client secret")).to_have_attribute("placeholder", "Saved. Enter another to replace it.")
        # Another issuer, and the saved secret is not sent to it: it is asked for again.
        box.get_by_role("textbox", name=re.compile("^Issuer")).fill(ISSUER + "/")
        box.get_by_role("button", name="Save", exact=True).click()
        expect(box.locator("p.error")).to_contain_text("enter the client secret (again")
        # A provider that calls itself otherwise is refused, in the box, and nothing is saved.
        box.get_by_label("Client secret").fill(SECRET)
        box.get_by_role("button", name="Save", exact=True).click()
        expect(box.locator("p.error")).to_contain_text(f"calls itself {ISSUER}")
        assert admin.get("/api/v1/oidc").json()["issuer"] == ISSUER


def provider_page(page: Page, idp: FakeIdp, base: str, login: str) -> None:
    """The provider's own page, played by the test: whoever arrives there is `login`, signed in, and sent back."""

    def signed_in_there(route: Route) -> None:
        route.fulfill(status=302, headers={"Location": base + idp.authorize(route.request.url, login), "Cache-Control": "no-store"})

    page.route(f"https://{IDP}/**", signed_in_there)


def test_the_button_signs_in_through_the_provider_and_back(tmp_path: Path, browser: Browser, idp: FakeIdp) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin):
        made = admin.put("/api/v1/oidc", json={
            "enabled": True, "name": "Team SSO", "issuer": ISSUER, "client_id": CLIENT, "client_secret": SECRET, "roles": ROLES,
            "redirect_uri": f"{live.url}/api/v1/oidc/callback",
        })  # fmt: skip
        assert made.status_code == 200, made.text
        context = browser.new_context()
        context.set_default_timeout(PATIENCE)
        page = context.new_page()
        thrown: list[str] = []
        page.on("pageerror", lambda error: thrown.append(str(error)))
        page.on("console", lambda said: thrown.append(said.text) if "Content Security Policy" in said.text else None)
        try:
            provider_page(page, idp, live.url, "olga")
            page.goto(live.url)
            button = page.get_by_role("button", name="Sign in with Team SSO")
            expect(button).to_be_visible()
            expect(page.locator("#auth-card input[type=password]")).to_be_visible()  # (the wall's own password stays beside it)
            button.click()
            expect(page.locator("#shell")).to_be_visible()
            expect(page.locator("#me-name")).to_have_text("olga@example.org")
            assert page.url == f"{live.url}/"
            cookies = {cookie["name"]: cookie for cookie in context.cookies()}
            assert cookies["qkvm_session"]["sameSite"] == "Strict" and cookies["qkvm_session"]["httpOnly"] is True
            assert "qkvm_oidc" not in cookies  # (what bound the sign-in to this browser is gone with it)

            # Out of every group that gives a role: back at the sign-in page, told why, with nothing left in the address.
            idp.people["olga"].groups = ["lunch-club"]
            page.locator("#me-toggle").click()
            page.locator("#sign-out").click()
            top(page).get_by_role("button", name="Sign out", exact=True).click()
            expect(button).to_be_visible()
            button.click()
            expect(page.locator("#auth-card p.error[role=alert]")).to_contain_text("in no group that gives a role on this wall")
            assert page.url == f"{live.url}/" and "#" not in page.url
            expect(page.locator("#shell")).to_be_hidden()
        finally:
            context.close()
        assert not thrown, thrown
