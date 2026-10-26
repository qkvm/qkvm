"""The page, in a browser: what a person presses, and what they then see.

Every other test here asks the program as a script would, over HTTP. None of them runs the page's own
script, and that is where a person meets the wall. Here a real browser is driven through it, against the
app on a port of its own and stand-in KVMs. Three things are held for every page of every test, whatever
else it is about: the script throws nothing, it breaks none of the rules the server sets for the page
(the Content-Security-Policy), and it asks nobody but its own wall for anything.

Needs Playwright and a browser for it. Both are for these tests only and nothing a wall is installed
with; where they are missing the tests are skipped:

    pip install playwright && python -m playwright install chromium
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Error, Locator, Page, Request, expect, sync_playwright

from qkvm import exchange, kvm, update, vault
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import BmcState, FakeBmc
from tests.scripted_device import Scripted, as_json
from tests.test_hardening import LiveWall
from tests.test_totp import code_for, switch_on
from tests.test_users import OTHER
from tests.test_wall import CSRF, PASSWORD, closed_port

DEVICE_PASSWORD = FakeState().password
PATIENCE = 15_000  # milliseconds something on the page may take to come, on a machine that is busy with other things
expect.set_options(timeout=PATIENCE)


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")  # tests never ask the real GitHub for releases


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        try:
            chromium = playwright.chromium.launch()
        except Error as ex:
            if os.environ.get("CI"):
                raise  # where these tests are meant to run, a browser that is missing is a failure and no reason to skip
            pytest.skip(f"no browser for Playwright (python -m playwright install chromium): {str(ex).splitlines()[0]}")
        yield chromium
        chromium.close()


@pytest.fixture
def fakes() -> Iterator[list[FakeKvm]]:
    """Two stand-in KVMs: one with a power board, both with a picture."""
    made = [FakeKvm(FakeState(atx=True)).start(), FakeKvm(FakeState(colour=(135, 74, 32), hostname="mail")).start()]
    yield made
    for fake in made:
        fake.stop()


@contextmanager
def a_wall(data: Path, *devices: tuple[str, FakeKvm], **options: Any) -> Iterator[tuple[LiveWall, httpx.Client]]:
    """A wall on a port of its own with its first account made, and that account as a script beside the browser."""
    with LiveWall(data) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        for name, fake in devices:
            reply = admin.post("/api/v1/devices", json={"url": fake.url, "password": DEVICE_PASSWORD, "name": name, **options})
            assert reply.status_code == 201, reply.text
        yield live, admin


class Watch:
    """What a page did besides what it was asked to."""

    def __init__(self, page: Page, origin: str) -> None:
        self.thrown: list[str] = []
        self.against_the_rules: list[str] = []
        self.elsewhere: list[str] = []
        self.errors_of_the_wall: list[str] = []
        ours = (origin + "/", "data:", "blob:")
        page.on("pageerror", lambda error: self.thrown.append(str(error)))
        page.on("console", lambda said: self.against_the_rules.append(said.text) if "Content Security Policy" in said.text else None)
        page.on("request", lambda request: None if request.url.startswith(ours) else self.elsewhere.append(request.url))
        page.on("response", lambda reply: self.errors_of_the_wall.append(f"{reply.status} {reply.url}") if reply.status == 500 else None)

    def said(self) -> str:
        found = {
            "the page's script threw": self.thrown,
            "the page broke its own Content-Security-Policy": self.against_the_rules,
            "the page asked somebody other than its wall": self.elsewhere,
            "the wall answered with an error of its own": self.errors_of_the_wall,
        }
        return "; ".join(f"{what}: {which}" for what, which in found.items() if which)


@contextmanager
def looking(browser: Browser, live: LiveWall, **options: Any) -> Iterator[Page]:
    """A browser of its own (cookies, storage), looking at this wall. What it must never do is checked when it is done."""
    context = browser.new_context(**options)
    context.set_default_timeout(PATIENCE)
    page = context.new_page()
    watch = Watch(page, live.url)
    try:
        yield page
    except BaseException as ex:
        if watch.said():
            ex.add_note(watch.said())  # why a button never came is often said here
        raise
    finally:
        context.close()
    assert not watch.said(), watch.said()


def sign_in(page: Page, live: LiveWall, password: str = PASSWORD, name: str = "", then: str = "") -> None:
    page.goto(live.url + "/" + then)
    if name:
        page.locator("#auth-card input[autocomplete=username]").fill(name)
    page.locator("#auth-card input[type=password]").fill(password)
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator("#shell")).to_be_visible()


def top(page: Page) -> Locator:
    """The dialog that lies on top: the only one anything can be pressed in."""
    return page.locator("dialog[open]").last


def told(page: Page, text: str) -> None:
    """The page said so, in one of the notices at its edge."""
    expect(page.locator("#toasts .toast", has_text=text).first).to_be_visible()


def tile(page: Page, name: str) -> Locator:
    return page.locator(f'#wall article[aria-label="{name}. Press Enter to enlarge."]')


def settings(page: Page, tab: str) -> Locator:
    """Settings, opened from its button, at one of its sections. What comes back is the section."""
    page.locator("#open-settings").click()
    top(page).locator(f'[role=tab][data-tab="{tab}"]').click()
    pane = top(page).locator("[role=tabpanel]")
    expect(pane.locator("p.loading")).to_have_count(0)
    return pane


def until(page: Page, happened: Callable[[], bool], or_else: str) -> None:
    """Waits for something that happens outside the page (at a stand-in device), while the page carries on."""
    for _ in range(150):
        if happened():
            return
        page.wait_for_timeout(100)
    raise AssertionError(or_else)


ASK = """async ([method, path, body]) => (await fetch(path, { method, cache: 'no-store',
  headers: { 'X-QKVM': '1', 'Content-Type': 'application/json' }, body: body === null ? undefined : JSON.stringify(body) })).status"""


def asks(page: Page, method: str, path: str, body: Any = None) -> int:
    """What the wall answers when this page's own script asks, with everything the page has: the number."""
    return int(page.evaluate(ASK, [method, path, body]))


def test_the_first_run_from_a_password_to_a_picture(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with LiveWall(tmp_path) as live, looking(browser, live) as page:
        page.goto(live.url)
        expect(page.get_by_role("heading", name="Create your password")).to_be_visible()
        both = page.locator("#auth-card input[type=password]")
        both.nth(0).fill(PASSWORD)
        both.nth(1).fill(PASSWORD + " not the same")
        page.get_by_role("button", name="Continue").click()
        expect(page.locator("#auth-card p.error")).to_be_visible()  # two passwords that differ make no account
        assert httpx.get(live.url + "/api/v1/session").json()["initialized"] is False
        both.nth(1).fill(PASSWORD)
        page.get_by_role("button", name="Continue").click()

        # The recovery key is shown this once, and there is no going on until it is said to be kept.
        expect(page.get_by_role("heading", name="Keep your recovery key")).to_be_visible()
        key = page.get_by_label("Recovery key", exact=True).input_value()
        assert len(key) >= 20
        onward = page.get_by_role("button", name="Continue")
        expect(onward).to_be_disabled()
        page.get_by_label("I have saved the recovery key").check()
        onward.click()

        expect(page.get_by_role("heading", name="Where should qKVM be reachable?")).to_be_visible()
        page.get_by_role("button", name="Continue").click()

        expect(page.get_by_role("heading", name="Add your KVMs")).to_be_visible()
        page.locator("#auth-card textarea").fill(fakes[0].url)
        page.locator("#auth-card input[type=password]").fill(DEVICE_PASSWORD)
        page.get_by_role("button", name="Check and add").click()
        expect(page.locator("#auth-card ul.results li.ok")).to_contain_text("added")
        page.get_by_role("button", name="Finish").click()

        # The wall, with the one KVM on it and its picture drawn.
        expect(page.locator("#wall article.has-frame")).to_have_count(1)
        expect(page.locator("#wall article")).to_have_attribute("data-state", "online")

        # The key the page showed is the key: it sets a new password.
        reset = httpx.post(live.url + "/api/v1/recover", headers=CSRF, json={"recovery_key": key, "new_password": OTHER})
        assert reset.status_code == 200, reset.text


def test_signing_in_with_a_wrong_password_and_then_the_right_one(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1])) as (live, _), looking(browser, live) as page:
        page.goto(live.url)
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
        assert "Build server" not in page.content()  # nothing of the wall is in the page of somebody who is not signed in
        page.locator("#auth-card input[type=password]").fill("not the password at all")
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#auth-card p.error")).to_be_visible()
        expect(page.locator("#shell")).to_be_hidden()
        assert page.locator("#wall article").count() == 0

        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#wall article")).to_have_count(2)
        expect(page.locator("#wall article.has-frame")).to_have_count(2)
        expect(page.locator("#auth")).to_be_hidden()

        # What signs this browser in is out of reach of any script in the page, and goes to no other site.
        assert page.evaluate("document.cookie") == ""
        cookies = page.context.cookies()
        assert len(cookies) == 1 and cookies[0]["httpOnly"] is True and cookies[0]["sameSite"] == "Strict", cookies
        kept = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])")
        assert PASSWORD not in kept and cookies[0]["value"] not in kept, kept

        # A page fetched again is still signed in; the password is asked once.
        page.reload()
        expect(page.locator("#wall article")).to_have_count(2)


MARKUP = '<img src=x onerror="window.reached=1">'
NAMED = '<b onclick="window.reached=3">Build</b> server'
NOTHING_MADE_OF_IT = "img[src='x'], [onerror], [onclick], b[onclick], script:not([src]), u, i.rack"


def test_what_a_device_or_a_person_wrote_is_shown_as_it_was_written(tmp_path: Path, browser: Browser) -> None:
    # A device says what it is called and what it is; an import file brings names; an admin types them. All of
    # it ends up in the page, and none of it is anything but text there.
    fake = FakeKvm(FakeState(model=MARKUP, hostname="<script>window.reached=2</script>", atx=True)).start()
    try:
        with a_wall(tmp_path, (NAMED, fake), group="<i class=rack>Rack</i>") as (live, admin), looking(browser, live) as page:
            made = admin.post("/api/v1/actions", json={"name": "<u>Lock</u>", "kind": "keys", "keys": "MetaLeft,KeyL"})
            assert made.status_code == 201, made.text
            sign_in(page, live)

            def nothing_was_made_of_it() -> None:
                assert page.evaluate("window.reached") is None
                assert page.locator(NOTHING_MADE_OF_IT).count() == 0

            expect(page.locator("#wall article .name")).to_have_text(NAMED)
            expect(page.locator("#wall article")).to_have_attribute("data-state", "online")
            nothing_was_made_of_it()

            page.get_by_role("button", name=f"Actions for {NAMED}").click()
            expect(top(page).locator("h2")).to_have_text(NAMED)
            expect(top(page).locator("p.muted").first).to_contain_text(MARKUP)  # what the device says it is
            expect(top(page).get_by_role("button", name="<u>Lock</u>")).to_be_visible()
            nothing_was_made_of_it()
            top(page).get_by_role("button", name="Lock screen").click()
            told(page, f"{NAMED}: Win+L sent")
            top(page).get_by_role("button", name="Ctrl+Alt+Del").click()
            expect(top(page).locator("p").first).to_have_text(f"Ctrl+Alt+Del on {NAMED}?")
            nothing_was_made_of_it()
            top(page).get_by_role("button", name="Cancel").click()
            top(page).get_by_role("button", name="Enlarge").click()
            expect(page.locator("#focus-name")).to_have_text(NAMED)
            nothing_was_made_of_it()
            page.keyboard.press("Escape")
            expect(page.locator("#focus")).to_be_hidden()

            expect(page.locator("#group option", has_text="Rack")).to_have_text("<i class=rack>Rack</i>")
            for tab in ("devices", "actions", "activity"):
                pane = settings(page, tab)
                expect(pane).to_contain_text({"devices": NAMED, "actions": "<u>Lock</u>", "activity": NAMED}[tab])
                nothing_was_made_of_it()
                top(page).get_by_role("button", name="Close").click()
                expect(page.locator("dialog[open]")).to_have_count(0)
    finally:
        fake.stop()


def test_a_picture_that_is_none_is_said_on_its_tile_and_troubles_no_other(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # It begins as a picture does and says a size, which is all the wall looks at before passing it on: the
    # browser is the one that has to read it.
    broken = b"\x89PNG\r\n\x1a\n" + (13).to_bytes(4, "big") + b"IHDR" + (640).to_bytes(4, "big") + (360).to_bytes(4, "big") + bytes(range(256)) * 40
    odd = FakeKvm(FakeState(picture=broken)).start()
    try:
        with a_wall(tmp_path, ("Odd one", odd), ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "Build server")).to_have_class(re.compile(r"\bhas-frame\b"))
            expect(tile(page, "Odd one").locator(".veil")).to_contain_text("The KVM sent a picture that could not be shown")
            expect(tile(page, "Odd one")).not_to_have_class(re.compile(r"\bhas-frame\b"))
            # Enlarged, the same is said, and stepping on from it shows the next one's picture.
            tile(page, "Odd one").focus()
            page.keyboard.press("Enter")
            expect(page.locator("#focus-veil")).to_contain_text("could not be shown")
            page.keyboard.press("ArrowRight")
            expect(page.locator("#focus-name")).to_have_text("Build server")
            page.wait_for_function("() => document.querySelector('#focus-canvas').width > 1")
            expect(page.locator("#toasts .toast.error")).to_have_count(0)
    finally:
        odd.stop()


def test_a_key_is_sent_at_a_click_and_what_can_cost_work_only_after_a_yes(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    fake = fakes[0]
    with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
        page.get_by_role("button", name="Actions for Build server").click()
        menu = top(page)
        menu.get_by_role("button", name="Lock screen").click()
        told(page, "Build server: Win+L sent")
        assert fake.state.actions == ["shortcut MetaLeft,KeyL"]

        def asked_first(button: str, sent: str, warning: str = "") -> None:
            """Pressed, it asks. "Cancel" sends nothing; the button that names the thing sends it, once."""
            before = list(fake.state.actions)
            menu.get_by_role("button", name=button).click()
            expect(page.locator("dialog[open]")).to_have_count(2)
            expect(top(page).locator("h2")).to_have_text(button)
            if warning:
                expect(top(page).locator(".note.warn")).to_have_text(warning)
            top(page).get_by_role("button", name="Cancel").click()
            expect(page.locator("dialog[open]")).to_have_count(1)
            page.wait_for_timeout(400)
            assert fake.state.actions == before  # not sent
            menu.get_by_role("button", name=button).click()
            page.keyboard.press("Escape")  # nor by the key that closes a dialog
            expect(page.locator("dialog[open]")).to_have_count(1)
            page.wait_for_timeout(400)
            assert fake.state.actions == before
            menu.get_by_role("button", name=button).click()
            top(page).locator(".actions button").last.click()
            until(page, lambda: fake.state.actions != before, f"{button}: never sent")
            expect(page.locator("dialog[open]")).to_have_count(1)
            assert fake.state.actions == before + [sent], fake.state.actions

        asked_first("Ctrl+Alt+Del", "shortcut ControlLeft,AltLeft,Delete")
        asked_first("Press reset button", "atx reset", "A hard reset. Unsaved work is lost.")
        asked_first("Hold power button", "atx power_long", "A long press cuts the power. Unsaved work is lost.")


def test_a_tile_is_enlarged_and_left_again_by_the_keyboard(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        expect(page.locator("#wall article.has-frame")).to_have_count(2)
        tile(page, "Build server").focus()
        page.keyboard.press("Enter")
        expect(page.locator("#focus")).to_be_visible()
        expect(page.locator("#focus-name")).to_have_text("Build server")
        page.wait_for_function("() => document.querySelector('#focus-canvas').width > 1")  # its picture, and not a blank
        # The wall behind it is out of reach of the Tab key while it is covered.
        assert page.evaluate("[document.querySelector('#wall').inert, document.querySelector('.top').inert]") == [True, True]
        page.keyboard.press("ArrowRight")
        expect(page.locator("#focus-name")).to_have_text("Mail server")
        page.keyboard.press("Escape")
        expect(page.locator("#focus")).to_be_hidden()
        assert page.evaluate("[document.querySelector('#wall').inert, document.querySelector('.top').inert]") == [False, False]
        assert page.evaluate("document.activeElement.getAttribute('aria-label')") == "Mail server. Press Enter to enlarge."

        # A link to one tile opens that tile; a link to none, or to something that is no tile's name, opens nothing.
        mail = next(d["id"] for d in admin.get("/api/v1/wall").json()["devices"] if d["name"] == "Mail server")
        page.goto(f"{live.url}/#tile={mail}")
        page.reload()
        expect(page.locator("#focus-name")).to_have_text("Mail server")
        for odd in ("#tile=nosuchtile", "#tile=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "#tile=" + "a" * 500):
            page.goto(f"{live.url}/{odd}")
            page.reload()
            expect(page.locator("#wall article")).to_have_count(2)
            expect(page.locator("#focus")).to_be_hidden()


def test_a_kvm_is_added_from_the_wall(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(page.locator("#wall .empty")).to_contain_text("Add your KVMs to see their screens here.")
        page.locator("#add-device").click()
        form = top(page)
        expect(form.locator("h2")).to_have_text("Add KVMs")

        # With a wrong password for the device nothing is added, and the address stays in the box to try again.
        form.locator("textarea").fill(fakes[0].url)
        form.locator("input[type=password]").fill("not its password")
        form.get_by_role("button", name="Check and add").click()
        expect(form.locator("ul.results li.bad")).to_have_count(1)
        expect(form.locator("ul.results li.bad button")).to_have_count(0)  # no "add anyway" for a password that is wrong
        assert form.locator("textarea").input_value() == fakes[0].url
        assert page.locator("#wall article").count() == 0

        form.locator("input[type=password]").fill(DEVICE_PASSWORD)
        form.locator('input[placeholder="None"]').fill("Rack 1")
        form.get_by_role("button", name="Check and add").click()
        expect(form.locator("ul.results li.ok")).to_contain_text("over plain HTTP")  # said, where the password crosses unencrypted
        expect(page.locator("#wall article")).to_have_count(1)
        # The try with the wrong password is no longer true of that address, and its line went: one line per address.
        expect(form.locator("ul.results li")).to_have_count(1)
        expect(form.locator("ul.results li.bad")).to_have_count(0)

        # One that does not answer can be added all the same, when the person says so.
        nobody = f"http://127.0.0.1:{closed_port()}"
        form.locator("textarea").fill(nobody)
        form.get_by_role("button", name="Check and add").click()
        expect(form.locator("ul.results li.bad")).to_have_count(1)
        assert page.locator("#wall article").count() == 1
        form.get_by_role("button", name="Add anyway").click()
        expect(form.locator("ul.results li.ok")).to_have_count(2)
        form.get_by_role("button", name="Close").click()
        expect(page.locator("#wall article")).to_have_count(2)
        expect(page.locator("#wall article.has-frame")).to_have_count(1)
        expect(page.locator("#group option", has_text="Rack 1")).to_have_count(1)


TABS = {
    "devices": "KVMs", "actions": "Actions", "alerts": "Alerts", "files": "Export and import", "users": "Accounts", "tokens": "Tokens",
    "security": "Security", "network": "Network", "metrics": "Metrics", "activity": "Activity", "updates": "Updates", "about": "About",
}


def test_every_section_of_settings_opens(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        page.locator("#open-settings").click()
        box = top(page)
        expect(box.locator("[role=tab]")).to_have_text(list(TABS.values()))  # all of them, for an admin
        pane = box.locator("[role=tabpanel]")
        for key, called in TABS.items():
            box.locator(f'[role=tab][data-tab="{key}"]').click()
            expect(box.locator(f'[role=tab][data-tab="{key}"]')).to_have_attribute("aria-selected", "true")
            expect(pane.locator(".section-head strong")).to_have_text(called)
            expect(pane.locator("p.loading")).to_have_count(0)
            expect(pane.locator("p.error:visible")).to_have_count(0)
            assert pane.locator(":scope > *").count() >= 2, key  # its heading, and something under it
        # The arrow keys go from one to the next, as in any list of tabs.
        box.locator('[role=tab][data-tab="about"]').focus()
        page.keyboard.press("ArrowUp")
        expect(pane.locator(".section-head strong")).to_have_text("Updates")
        # Opened again, it is where it was left.
        page.keyboard.press("Escape")
        expect(page.locator("dialog[open]")).to_have_count(0)
        page.locator("#open-settings").click()
        expect(top(page).locator("[role=tabpanel] .section-head strong")).to_have_text("Updates")


@pytest.mark.parametrize("supervised", [True, False])
def test_an_update_installed_and_waiting_for_a_restart_is_said_under_a_starter_too(tmp_path: Path, browser: Browser, supervised: bool) -> None:
    # Under a starter the page follows the restart that comes after an install, and this was never seen. That restart is
    # not made where whoever asked lost the right while the package was written (test_what_an_admin_asked_for_is_not_done_
    # once_they_may_not): the next admin to look is told that it waits for one, not that this copy is the newest.
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        status = admin.get("/api/v1/update").json()
        installed = {
            **status, "repo": "owner/wall", "state": "ready", "checked_ago": 5, "available": False, "installed": "9.9.9",
            "supervised": supervised, "latest": {"version": "9.9.9", "notes": "", "url": "", "published": ""},
        }  # fmt: skip
        page.route("**/api/v1/update", lambda route: route.fulfill(json=installed) if route.request.method == "GET" else route.continue_())
        sign_in(page, live)
        pane = settings(page, "updates")
        if supervised:
            expect(pane.locator("div.note")).to_have_text(["Version 9.9.9 is installed and is used from the next start of qKVM. qkvm restart on its computer starts it now."])
        else:
            expect(pane.locator("div.note")).to_have_text(["Version 9.9.9 is installed. Restart qKVM to start using it."])
        expect(pane).not_to_contain_text("You have the newest version")


MADE_OF = """(pane) => {
  const odd = [];
  const part = el => `${el.tagName.toLowerCase()}${el.className ? '.' + String(el.className).trim().replace(/ +/g, '.') : ''}`;
  const known = /^(header\\.section-head|p\\.intro|p\\.footnote|section\\.block(\\.text)?|form|div\\.note(\\.warn|\\.bad)?|div\\.toolbar|div\\.about-lead|div\\.made)$/;
  for (const child of pane.children) {
    if (child.hidden) continue;
    if (!known.test(part(child))) odd.push(`in the section: ${part(child)}`);
    if (child.tagName === 'FORM') for (const inner of child.children) if (!/^section\\.block$/.test(part(inner))) odd.push(`in its form: ${part(inner)}`);
  }
  const line = /^(div\\.setting|a\\.setting|label\\.field|label\\.check|table\\.rows(\\.libraries)?|p\\.nothing|div\\.lines-foot)$/;
  for (const frame of pane.querySelectorAll('.lines')) {
    for (const child of frame.children) if (!child.hidden && !line.test(part(child))) odd.push(`in a block: ${part(child)}`);
  }
  // What a section does as a whole is in its first line, and nowhere further down.
  for (const button of pane.querySelectorAll('button.primary, [type=submit]')) {
    if (!button.closest('.section-head')) odd.push(`a main button below the first line: ${button.textContent.trim()}`);
  }
  if (pane.querySelector('.actions')) odd.push('a row of buttons at the foot of something');
  // What is done to one line is at that line's right end.
  const edge = pane.getBoundingClientRect().right;
  for (const does of pane.querySelectorAll('.setting > .does > button, .rows td:last-child > button')) {
    const row = does.closest('.setting, tr').getBoundingClientRect();
    if (does.getBoundingClientRect().left < row.left + row.width / 2) odd.push(`a button at the left of its line: ${does.textContent.trim()}`);
  }
  // And nothing explains from under a button: what explains is the intro, or the footnote after the last block.
  const foot = pane.querySelector('p.footnote');
  if (foot && foot !== [...pane.children].filter(el => !el.hidden).pop()) odd.push('something after the footnote');
  return odd;
}"""


def test_every_section_of_settings_is_made_the_same_way(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # Twelve sections had grown twelve ways: a Save at the foot of one, in the middle of another, buttons as wide
    # as the page in a third, a sentence hanging under a button in a fourth. One shape now: what a section does
    # as a whole is at the right of its first line, which stays in sight; under it, blocks of lines that each
    # say what they are at the left and have what one does about it at the right. This holds every section to it.
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as page:
        assert admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        assert admin.post("/api/v1/tokens", json={"name": "A script"}).status_code == 201
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://hooks.invalid/x"}).status_code == 200
        assert admin.post("/api/v1/metrics/token").status_code == 200
        sign_in(page, live)
        page.locator("#open-settings").click()
        box = top(page)
        pane = box.locator("[role=tabpanel]")
        for key in TABS:
            box.locator(f'[role=tab][data-tab="{key}"]').click()
            expect(pane.locator("p.loading")).to_have_count(0)
            expect(pane.locator(".section-head strong")).to_have_text(TABS[key])
            assert pane.evaluate(MADE_OF) == [], key
        # The first line stays where it is while the rest moves under it: its button is in reach at the end too.
        box.locator('[role=tab][data-tab="alerts"]').click()
        save = pane.locator(".section-head").get_by_role("button", name="Save")
        expect(save).to_be_visible()
        pane.evaluate("el => el.scrollTo(0, el.scrollHeight)")
        expect(pane.locator("p.footnote")).to_be_in_viewport()
        expect(save).to_be_in_viewport()
        assert pane.evaluate("el => el.scrollTop") > 100


def test_a_section_is_saved_by_the_button_in_its_first_line(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "alerts")
        pane.get_by_label("It is over").uncheck()
        pane.get_by_label("Watch the KVMs and send alerts").check()
        pane.locator(".section-head").get_by_role("button", name="Save").click()
        told(page, "Alerts saved")
        saved = admin.get("/api/v1/alerts").json()
        assert saved["enabled"] is True and saved["recovered"] is False and saved["offline"] is True
        # Enter in one of its boxes saves as well: the button is outside the form, and still the form's.
        expect(pane.locator("p.loading")).to_have_count(0)
        pane.get_by_label("A KVM goes offline").uncheck()
        pane.get_by_label("Link in alerts").fill("https://wall.invalid:8787/")
        pane.get_by_label("Link in alerts").press("Enter")
        expect(page.locator("#toasts .toast", has_text="Alerts saved")).to_have_count(2)
        saved = admin.get("/api/v1/alerts").json()
        assert saved["offline"] is False and saved["link"] == "https://wall.invalid:8787/"

        top(page).locator('[role=tab][data-tab="network"]').click()
        expect(pane.locator(".section-head strong")).to_have_text("Network")
        pane.get_by_label("Tile refresh (seconds)").fill("2")
        pane.locator(".section-head").get_by_role("button", name="Save").click()
        told(page, "Settings saved")
        assert admin.get("/api/v1/settings").json()["interval"] == 2


def test_ones_own_password_is_changed_in_its_dialog(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "security")
        pane.get_by_role("button", name="Change password...").click()
        form = top(page)
        expect(form.locator("h2")).to_have_text("Change password")
        boxes = form.locator("input[type=password]")
        boxes.nth(0).fill("not my password at all")
        boxes.nth(1).fill(OTHER)
        boxes.nth(2).fill(OTHER)
        form.get_by_role("button", name="Change password").click()
        expect(form.locator("p.error")).to_be_visible()  # the one it replaces has to be right
        boxes.nth(0).fill(PASSWORD)
        boxes.nth(2).fill(OTHER + " not the same")
        form.get_by_role("button", name="Change password").click()
        expect(form.locator("p.error")).to_be_visible()  # and the new one typed the same twice
        boxes.nth(2).fill(OTHER)
        form.get_by_role("button", name="Change password").click()
        told(page, "Password changed")
        expect(page.locator("dialog[open]")).to_have_count(1)  # the dialog is gone, Settings is still there
        # Cancel leaves everything as it was.
        pane.get_by_role("button", name="Change password...").click()
        top(page).get_by_role("button", name="Cancel").click()
        expect(page.locator("dialog[open]")).to_have_count(1)

        pane.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
        page.locator("#auth-card input[type=password]").fill(PASSWORD)  # the old one opens nothing any more
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#auth-card p.error")).to_be_visible()
        page.locator("#auth-card input[type=password]").fill(OTHER)
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#wall article")).to_have_count(1)


def test_an_action_of_ones_own_is_saved_and_run_and_its_text_not_shown_again(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    fake = fakes[0]
    with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
        pane = settings(page, "actions")
        pane.get_by_role("button", name="New action").click()
        form = top(page)
        form.locator('input[placeholder="Restart print spooler"]').fill("Say uptime")
        form.locator("input[type=radio][value=text]").check()
        form.locator("textarea").fill("uptime")
        form.get_by_role("button", name="Save").click()
        told(page, "Say uptime saved")
        expect(pane.locator("table.rows tbody tr")).to_have_count(1)
        expect(pane.locator("table.rows tbody tr")).to_contain_text("Types saved text, then Enter")

        # What it types is kept encrypted and is not handed back to any page, the one it was typed into included.
        pane.get_by_role("button", name="Edit").click()
        assert top(page).locator("textarea").input_value() == ""
        expect(top(page).locator("textarea")).to_have_attribute("placeholder", "Leave empty to keep the saved text")
        assert "uptime" not in page.content().replace("Say uptime", "")
        top(page).get_by_role("button", name="Cancel").click()
        page.keyboard.press("Escape")
        expect(page.locator("dialog[open]")).to_have_count(0)

        # On a tile it is one of the buttons. Text typed into the wrong window can do anything: it asks first.
        page.get_by_role("button", name="Actions for Build server").click()
        top(page).get_by_role("button", name="Say uptime").click()
        expect(page.locator("dialog[open]")).to_have_count(2)
        page.wait_for_timeout(300)
        assert fake.state.actions == []
        top(page).locator(".actions button").last.click()
        told(page, "Build server: Say uptime sent")
        assert fake.state.actions == ["type 'uptime\\n'"], fake.state.actions


def test_the_wall_goes_into_a_file_and_comes_back_out_of_it(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    fake = fakes[0]
    with a_wall(tmp_path / "wall", ("Build server", fake)) as (live, _), looking(browser, live, accept_downloads=True) as page:
        sign_in(page, live)
        expect(page.locator("#wall article.has-frame")).to_have_count(1)
        pane = settings(page, "files")
        pane.get_by_role("button", name="Export...", exact=True).click()
        form = top(page)
        secrets = form.locator("input[type=password]")
        secrets.nth(0).fill("short")
        secrets.nth(1).fill(PASSWORD)
        form.get_by_role("button", name="Download").click()
        expect(form.locator("p.error")).to_contain_text("10 characters")  # a passphrase that would not hold is not taken
        secrets.nth(0).fill("the passphrase of the file")
        with page.expect_download() as got:
            form.get_by_role("button", name="Download").click()
        told(page, "Exported. The file opens with its passphrase only")
        assert got.value.suggested_filename.endswith(".qkvm")
        file = tmp_path / got.value.suggested_filename
        got.value.save_as(file)
        written = file.read_text(encoding="utf-8")
        assert "sealed" in json.loads(written) and DEVICE_PASSWORD not in written and fake.url not in written

        # The KVM is taken off the wall, by its button.
        top(page).locator('[role=tab][data-tab="devices"]').click()
        pane.get_by_role("button", name="Remove").click()
        expect(top(page).locator("h2")).to_have_text("Remove Build server?")
        top(page).locator("button.danger").click()
        told(page, "Build server removed")
        expect(page.locator("#wall article")).to_have_count(0)

        # And comes back from the file: with the wrong passphrase nothing of it, with the right one all of it.
        top(page).locator('[role=tab][data-tab="files"]').click()
        pane.get_by_role("button", name="Import...", exact=True).click()
        form = top(page)
        form.locator("input[type=file]").set_input_files(file)
        expect(form.locator("input[type=password]")).to_be_visible()  # a sealed file: its passphrase is asked for
        form.locator("input[type=password]").fill("not the passphrase of it")
        form.get_by_role("button", name="Read the file").click()
        expect(form.locator("p.error")).to_be_visible()
        expect(form.get_by_role("button", name="Take in")).to_be_hidden()
        form.locator("input[type=password]").fill("the passphrase of the file")
        form.get_by_role("button", name="Read the file").click()
        expect(form).to_contain_text("KVMs and servers: 1 to add")
        expect(form.locator(".picklist")).to_contain_text("Build server")
        logins = fake.state.logins
        form.get_by_role("button", name="Take in").click()
        told(page, "1 device added")
        page.keyboard.press("Escape")
        # The password came back with it: the device lets the wall in again, and its picture is drawn.
        expect(page.locator("#wall article.has-frame")).to_have_count(1)
        assert fake.state.logins > logins


def test_an_account_that_only_looks_is_offered_nothing_else_and_refused_what_it_asks_for_anyway(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1])) as (live, admin), looking(browser, live) as page:
        # An admin makes the account, on the page.
        sign_in(page, live)
        pane = settings(page, "users")
        pane.get_by_role("button", name="Add account").click()
        form = top(page)
        form.locator("input[type=text]").first.fill("vera")
        assert form.locator("select").first.input_value() == "viewer"  # the least is what is offered first
        form.locator("input[type=password]").fill(OTHER)
        form.get_by_role("button", name="Add account").click()
        told(page, "vera added")
        expect(pane).to_contain_text("vera")
        build, mail = (next(d["id"] for d in admin.get("/api/v1/wall").json()["devices"] if d["name"] == name) for name in ("Build server", "Mail server"))

        with looking(browser, live) as hers:
            sign_in(hers, live, OTHER, name="vera")
            expect(hers.locator("#wall article.has-frame")).to_have_count(2)
            for hidden in ("#add-device", "#select-toggle", "#arrange"):
                expect(hers.locator(hidden)).to_be_hidden()
            expect(hers.get_by_role("button", name="Actions for Build server")).to_be_hidden()
            tile(hers, "Build server").click()
            expect(hers.locator("#focus")).to_be_visible()
            expect(hers.locator("#focus-actions")).to_be_hidden()
            hers.keyboard.press("Escape")
            expect(hers.locator("#focus")).to_be_hidden()
            hers.locator("#open-settings").click()
            expect(top(hers).locator("[role=tab]")).to_have_text(["Security", "About"])
            hers.keyboard.press("Escape")

            # What the page does not offer, its script asks for all the same: refused by the wall, each of them.
            assert asks(hers, "POST", f"api/v1/devices/{build}/actions", {"action": "keys", "keys": "MetaLeft,KeyL"}) == 403
            assert asks(hers, "POST", f"api/v1/devices/{build}/actions", {"action": "atx_reset"}) == 403
            assert asks(hers, "DELETE", f"api/v1/devices/{build}") == 403
            assert asks(hers, "GET", "api/v1/users") == 403
            assert asks(hers, "GET", "api/v1/audit") == 403
            assert asks(hers, "POST", "api/v1/export", {"password": OTHER, "passphrase": "", "parts": ["devices"]}) == 403
            assert fakes[0].state.actions == []

            # Limited to one machine, her page has that one and not a word of the other.
            account = next(u for u in admin.get("/api/v1/users").json()["users"] if u["name"] == "vera")
            limited = admin.put(f"/api/v1/users/{account['id']}", json={"name": "vera", "role": "viewer", "devices": [build]})
            assert limited.status_code == 200, limited.text
            hers.reload()
            expect(hers.locator("#wall article")).to_have_count(1)
            expect(tile(hers, "Build server")).to_be_visible()
            assert "Mail server" not in hers.content()
            assert asks(hers, "GET", f"api/v1/devices/{mail}/snapshot") in (403, 404)


def test_signing_out_and_a_session_that_was_ended_from_elsewhere(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        expect(page.locator("#wall article")).to_have_count(1)
        page.locator("#me-toggle").click()
        expect(page.locator("#me-name")).to_have_text("admin")
        page.locator("#sign-out").click()
        expect(top(page).locator("h2")).to_have_text("Sign out?")
        top(page).get_by_role("button", name="Cancel").click()
        expect(page.locator("#wall article")).to_have_count(1)  # asked, and answered no: still here
        page.locator("#me-toggle").click()
        page.locator("#sign-out").click()
        top(page).get_by_role("button", name="Sign out").click()
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
        assert page.locator("#wall article").count() == 0 and "Build server" not in page.content()
        assert asks(page, "GET", "api/v1/wall") == 401
        page.reload()
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
        assert page.locator("#wall article").count() == 0

        # Signed in again, with Settings open on the accounts; then every other browser of the account is
        # signed out from somewhere else. The page notices by itself, and leaves nothing of what it showed.
        sign_in(page, live)
        pane = settings(page, "users")
        expect(pane).to_contain_text("admin")
        assert admin.post("/api/v1/logout", json={"scope": "others"}).status_code == 200
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible(timeout=40_000)
        expect(page.locator("#auth-card")).to_contain_text("Your session ended")
        expect(page.locator("dialog[open]")).to_have_count(0)
        expect(page.locator("#shell")).to_be_hidden()


def test_a_second_step_is_set_up_on_the_page_and_asked_for_from_then_on(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        page.locator("#me-toggle").click()
        page.locator("#my-security").click()
        pane = top(page).locator("[role=tabpanel]")
        pane.get_by_role("button", name="Add a second step").click()
        form = top(page)
        form.locator("input[type=password]").fill("not my password at all")
        form.get_by_role("button", name="Continue").click()
        expect(form.locator("p.error")).to_be_visible()  # the password is asked for again, and has to be right
        form.locator("input[type=password]").fill(PASSWORD)
        form.get_by_role("button", name="Continue").click()
        expect(form.locator("svg.qr")).to_be_visible()
        secret = form.locator("input.mono").input_value()
        form.get_by_label("Code", exact=True).fill("000000" if code_for(secret) != "000000" else "111111")
        form.get_by_role("button", name="Turn on").click()
        expect(form.locator("p.error")).to_be_visible()  # a code that is not the app's switches nothing on
        form.get_by_label("Code", exact=True).fill(code_for(secret))
        form.get_by_role("button", name="Turn on").click()
        told(page, "Two-factor sign-in is on")
        codes = form.locator("pre.codes").inner_text().split()
        assert len(codes) == 10 and len(set(codes)) == 10
        form.get_by_role("button", name="I have kept them").click()

        def sign_out() -> None:
            page.keyboard.press("Escape")
            expect(page.locator("dialog[open]")).to_have_count(0)
            page.locator("#me-toggle").click()
            page.locator("#sign-out").click()
            top(page).get_by_role("button", name="Sign out").click()
            expect(page.get_by_role("heading", name="Sign in")).to_be_visible()

        # From now on the password alone shows nothing: the code is asked for, and a one-time code stands in once.
        sign_out()
        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        code = page.locator("#auth-card input[autocomplete=one-time-code]")
        expect(code).to_be_visible()
        expect(page.locator("#shell")).to_be_hidden()
        assert asks(page, "GET", "api/v1/wall") == 401
        page.get_by_role("button", name="No phone at hand? Use a one-time code").click()
        code.fill(codes[0])
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#wall article")).to_have_count(1)

        sign_out()
        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        expect(code).to_be_visible()
        page.get_by_role("button", name="No phone at hand? Use a one-time code").click()
        code.fill(codes[0])  # the same one a second time
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#auth-card p.error")).to_be_visible()
        expect(page.locator("#shell")).to_be_hidden()
        code.fill(codes[1])
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#wall article")).to_have_count(1)


def test_where_a_second_step_is_required_nothing_is_shown_until_it_is_set_up(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, admin), looking(browser, live) as page:
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
        switch_on(admin, PASSWORD)  # whoever makes the rule has done it themselves
        assert admin.put("/api/v1/security", json={"require_totp": "operator"}).status_code == 200
        build = admin.get("/api/v1/wall").json()["devices"][0]["id"]

        page.goto(live.url)
        page.locator("#auth-card input[autocomplete=username]").fill("olga")
        page.locator("#auth-card input[type=password]").fill(OTHER)
        page.get_by_role("button", name="Sign in").click()
        expect(page.get_by_role("heading", name="One more step")).to_be_visible()
        expect(page.locator("#shell")).to_be_hidden()
        assert page.locator("#wall article").count() == 0 and "Build server" not in page.content()
        # The password alone opens nothing, whatever the page's script asks for.
        assert asks(page, "GET", "api/v1/wall") == 403
        assert asks(page, "GET", f"api/v1/devices/{build}/snapshot") == 403
        assert asks(page, "POST", f"api/v1/devices/{build}/actions", {"action": "keys", "keys": "MetaLeft,KeyL"}) == 403
        assert fakes[0].state.actions == []
        page.reload()  # and a page fetched again is the same page
        expect(page.get_by_role("heading", name="One more step")).to_be_visible()

        page.get_by_role("button", name="Set it up").click()
        form = top(page)
        form.locator("input[type=password]").fill(OTHER)
        form.get_by_role("button", name="Continue").click()
        secret = form.locator("input.mono").input_value()
        form.get_by_label("Code", exact=True).fill(code_for(secret))
        form.get_by_role("button", name="Turn on").click()
        expect(form.locator("pre.codes")).to_be_visible()
        # Before the wall is shown, it is asked once more who this is. An answer that does not come at that
        # moment (qKVM busy, a cable out) left the person on a page with nothing more to press, under a notice
        # that something went wrong. What switching the second step on answered is enough to go on with.
        page.route("**/api/v1/session", lambda route: route.abort())
        form.get_by_role("button", name="I have kept them").click()
        expect(page.locator("#wall article")).to_have_count(1)
        expect(page.locator("#auth")).to_be_hidden()
        expect(page.get_by_role("button", name="Actions for Build server")).to_be_visible()  # an operator's wall
        expect(page.locator("#toasts .toast.error")).to_have_count(0)


def test_a_certificate_that_changed_is_shown_and_nothing_is_sent_until_it_is_trusted(tmp_path: Path, browser: Browser) -> None:
    known = FakeKvm(tls_dir=tmp_path / "known").start()
    other: FakeKvm | None = None
    try:
        with a_wall(tmp_path / "wall", ("Build server", known)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "Build server")).to_have_class(re.compile(r"\bhas-frame\b"))
            # At the same address something answers with another certificate: the device after a factory reset,
            # or something else that would like to be told the device's password.
            known.stop()
            other = FakeKvm(port=known.port, tls_dir=tmp_path / "other").start()
            review = tile(page, "Build server").get_by_role("button", name="Review certificate")
            expect(review).to_be_visible(timeout=60_000)
            review.click()
            asked = top(page)
            expect(asked.locator("h2")).to_have_text("Build server certificate")
            shown = asked.locator("code.fingerprint").all_inner_texts()
            assert len(shown) == 2 and shown[0] != shown[1] and all(len(mark) >= 40 for mark in shown), shown
            expect(asked.locator(".note.bad")).to_contain_text("do not trust it")
            asked.get_by_role("button", name="Cancel").click()
            page.wait_for_timeout(1500)
            expect(review).to_be_visible()
            # Shown, looked at, and declined: the one that answers there now has been told no password.
            assert other.state.logins == 0 and other.state.tokens == set()

            review.click()
            top(page).get_by_role("button", name="Trust this certificate").click()
            told(page, "Build server: certificate trusted")
            expect(tile(page, "Build server")).to_have_attribute("data-state", "online", timeout=60_000)
            assert other.state.logins >= 1
    finally:
        known.stop()
        if other is not None:
            other.stop()


def test_a_forgotten_password_is_replaced_with_the_recovery_key_on_the_page(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with LiveWall(tmp_path) as live, looking(browser, live) as page:
        made = httpx.post(live.url + "/api/v1/setup", headers=CSRF, json={"password": PASSWORD})
        assert made.status_code == 200, made.text
        key = made.json()["recovery_key"]
        page.goto(live.url)
        page.get_by_role("button", name="Forgot your password?").click()
        form = top(page)
        both = form.locator("input[type=password]")
        wrong = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
        form.locator("input[placeholder^=XXXX]").fill(wrong)
        both.nth(0).fill(OTHER)
        both.nth(1).fill(OTHER)
        form.get_by_role("button", name="Set the new password").click()
        expect(form.locator("p.error")).to_be_visible()  # a key that is not the key changes nothing
        form.locator("input[placeholder^=XXXX]").fill(key)
        form.get_by_role("button", name="Set the new password").click()
        told(page, "Password changed. Sign in with the new one.")
        expect(page.locator("dialog[open]")).to_have_count(0)

        page.locator("#auth-card input[type=password]").fill(PASSWORD)  # the old one opens nothing any more
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#auth-card p.error")).to_be_visible()
        expect(page.locator("#shell")).to_be_hidden()
        page.locator("#auth-card input[type=password]").fill(OTHER)
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#shell")).to_be_visible()
        expect(page.locator("#wall .empty")).to_be_visible()


def test_a_link_for_a_wall_screen_is_made_on_the_page_shown_once_and_opens_the_wall(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "tokens")
        pane.get_by_role("button", name="Link for a wall screen").click()
        form = top(page)
        form.locator('input[placeholder="Screen in the hall"]').fill("Hall")
        form.get_by_role("button", name="Make the link").click()
        link = form.get_by_label("Display link", exact=True).input_value()
        assert re.fullmatch(re.escape(live.url) + r"/#display&key=qkvm_[A-Za-z0-9_-]{20,80}", link), link
        form.get_by_role("button", name="I have it").click()
        expect(pane).to_contain_text("Hall")
        key = link.split("key=")[1]
        assert key not in page.content()  # shown the once, and in the page no longer

        with looking(browser, live) as screen:
            screen.goto(link)
            expect(screen.locator("#wall article.has-frame")).to_have_count(1)
            assert screen.evaluate("location.href") == f"{live.url}/#display"
            expect(screen.locator("#open-settings")).to_be_hidden()


def test_a_kvm_is_renamed_and_keeps_the_password_that_was_saved_for_it(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    fake = fakes[0]
    with a_wall(tmp_path, ("Build server", fake)) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
        page.get_by_role("button", name="Actions for Build server").click()
        top(page).get_by_role("button", name="Edit...").click()
        form = top(page)
        expect(form.locator("h2")).to_have_text("Edit Build server")
        # The password that is saved is not in the page: its box is empty, and left empty it is kept.
        assert form.locator("input[type=password]").input_value() == ""
        assert DEVICE_PASSWORD not in page.content()
        form.locator("input[type=text]").first.fill("Web server")
        form.get_by_role("button", name="Save", exact=True).click()
        told(page, "Web server saved")
        expect(tile(page, "Web server")).to_have_attribute("data-state", "online")
        expect(tile(page, "Web server")).to_have_class(re.compile(r"\bhas-frame\b"))
        assert page.locator("#wall article").count() == 1
        saved = admin.get("/api/v1/wall").json()["devices"][0]
        assert saved["name"] == "Web server" and saved["has_password"] is True

        # A name that is no name is refused where it is typed, and the tile keeps the one it has.
        page.get_by_role("button", name="Actions for Web server").click()
        top(page).get_by_role("button", name="Edit...").click()
        form = top(page)
        form.locator("input[type=text]").first.fill("two" + chr(0x2028) + "lines")
        form.get_by_role("button", name="Save", exact=True).click()
        expect(form.locator("p.error")).to_be_visible()
        assert admin.get("/api/v1/wall").json()["devices"][0]["name"] == "Web server"


def test_a_spinner_goes_on_turning_where_the_system_asks_for_less_motion(tmp_path: Path, browser: Browser) -> None:
    # Everything else is cut short there; a spinner that stood still said that the work had stopped, while it went on
    # (seen on a computer with Windows' animations switched off, adding a slow server's controller).
    with a_wall(tmp_path) as (live, _), looking(browser, live, reduced_motion="reduce") as page:
        sign_in(page, live)
        turning = page.evaluate(
            """() => {
                const button = document.createElement('button');
                button.className = 'primary';
                button.setAttribute('aria-busy', 'true');
                const spinner = document.createElement('span');
                spinner.className = 'spinner';
                document.body.append(button, spinner);
                const said = [getComputedStyle(button, '::after'), getComputedStyle(spinner)].map(style => [style.animationName, style.animationIterationCount]);
                button.remove();
                spinner.remove();
                return said;
            }"""
        )
        assert turning == [["spin", "infinite"], ["spin", "infinite"]], turning


def test_what_is_no_kvm_is_not_added_anyway_and_a_tile_that_signs_nobody_in_is_still_renamed(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # For a day the page offered "Add anyway" for whatever answers its sign-in with an error. An address that
    # is no KVM at all does that (a mistyped one, a printer, a router's page), and once added it was sent the
    # password every five minutes for good. The button is for a device that cannot be reached; and "Save
    # without checking" also for a tile whose device signs nobody in just now, as long as the address, the
    # user name and the password are left as they are: it can then still be given another name.
    fake = fakes[0]
    elsewhere = Scripted(lambda method, path, head, body: as_json(404, {"error": "there is no such thing here"})).start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
            page.locator("#add-device").click()
            form = top(page)
            form.locator("textarea").fill(elsewhere.url)
            form.locator("input[type=password]").fill("what would be sent there from then on")
            form.get_by_role("button", name="Check and add").click()
            expect(form.locator("ul.results li.bad")).to_have_count(1)
            expect(form.locator("ul.results li.bad")).to_contain_text("does not sign qKVM in")
            expect(form.locator("ul.results li.bad button")).to_have_count(0)
            form.get_by_role("button", name="Close").click()
            assert page.locator("#wall article").count() == 1 and len(elsewhere.asked("POST", "/api/auth/login")) == 1

            # The KVM on the wall forgets its session and answers every sign-in with an error of its own.
            fake.state.tokens.clear()
            fake.state.login_status = 503
            expect(tile(page, "Build server")).to_have_attribute("data-state", "error", timeout=20_000)
            page.get_by_role("button", name="Actions for Build server").click()
            top(page).get_by_role("button", name="Edit...").click()
            form = top(page)
            address = form.locator("input[type=text]").nth(1)
            as_it_is = address.input_value()
            form.locator("input[type=text]").first.fill("Web server")
            form.get_by_role("button", name="Save", exact=True).click()
            expect(form.locator("p.error")).to_contain_text("does not sign qKVM in")
            anyway = form.get_by_role("button", name="Save without checking")
            expect(anyway).to_be_visible()
            # It is offered for what was refused, as it was sent. Another address in the box, and it is gone at
            # once: left there, it saved unchecked whatever was typed after.
            address.fill(elsewhere.url)
            expect(anyway).to_be_hidden()
            # And for another address it is not offered, with the password for it typed as well: that would be
            # adding what is there. (It answers its sign-in with an error too: the same words, and no button.)
            form.locator("input[type=password]").fill("what would be sent there from then on")
            form.get_by_role("button", name="Save", exact=True).click()
            expect(form.locator("p.error")).to_contain_text("does not sign qKVM in")
            expect(anyway).to_be_hidden()
            address.fill(as_it_is)
            form.locator("input[type=password]").fill("")
            form.get_by_role("button", name="Save", exact=True).click()
            expect(anyway).to_be_visible()
            anyway.click()
            told(page, "Web server saved")
            saved = admin.get("/api/v1/wall").json()["devices"][0]
            assert saved["name"] == "Web server" and saved["has_password"] is True
            assert len(elsewhere.asked("POST", "/api/auth/login")) <= 2  # (asked once more at most, for the address that was tried)
    finally:
        elsewhere.stop()


def test_the_computer_on_screen_is_switched_from_the_tile_of_a_kvm_with_several_ports(tmp_path: Path, browser: Browser) -> None:
    several = FakeKvm(FakeState(ports=[(200, 30, 30), (30, 200, 30), None], active_port=0)).start()
    try:
        with a_wall(tmp_path, ("Rack KVM", several)) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            strip = tile(page, "Rack KVM").locator(".ports")
            expect(strip.locator("button")).to_have_count(3)
            expect(strip.locator("button").nth(0)).to_have_attribute("aria-pressed", "true")
            expect(strip.locator("button").nth(2)).to_have_attribute("aria-label", "Port 3 of Rack KVM: nothing connected")
            strip.locator("button").nth(1).click()
            told(page, "Rack KVM: showing Port 2")
            expect(strip.locator("button").nth(1)).to_have_attribute("aria-pressed", "true")
            assert several.state.actions == ["port 1"] and several.state.active_port == 1
            expect(page.locator("#focus")).to_be_hidden()  # a press on a port is no press on the tile

            # Somebody who only looks sees which computer is on screen, and cannot change it.
            assert admin.post("/api/v1/users", json={"name": "vera", "role": "viewer", "password": OTHER}).status_code == 201
            with looking(browser, live) as hers:
                sign_in(hers, live, OTHER, name="vera")
                ports = tile(hers, "Rack KVM").locator(".ports button")
                expect(ports).to_have_count(3)
                expect(ports.nth(1)).to_have_attribute("aria-pressed", "true")
                expect(ports.nth(0)).to_be_disabled()
                build = admin.get("/api/v1/wall").json()["devices"][0]["id"]
                assert asks(hers, "POST", f"api/v1/devices/{build}/actions", {"action": "port", "port": 0}) == 403
            assert several.state.actions == ["port 1"]
    finally:
        several.stop()


def test_several_are_ticked_and_one_action_run_on_all_of_them(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(page.locator('#wall article[data-state="online"]')).to_have_count(2)
        expect(page.locator("#bulkbar")).to_be_hidden()
        tile(page, "Build server").click()  # not picking: a click enlarges
        expect(page.locator("#focus")).to_be_visible()
        page.keyboard.press("Escape")
        expect(page.locator("#focus")).to_be_hidden()

        page.locator("#select-toggle").click()
        expect(page.locator("#bulk-count")).to_have_text("0 selected")
        expect(page.locator("#bulk-run")).to_be_disabled()
        tile(page, "Build server").click()  # picking: a click ticks
        expect(page.locator("#focus")).to_be_hidden()
        expect(page.locator("#bulk-count")).to_have_text("1 selected")
        page.locator("#bulk-all").click()
        expect(page.locator("#bulk-count")).to_have_text("2 selected")
        page.locator("#bulk-run").click()
        menu = top(page)
        expect(menu.locator("h2")).to_have_text("2 KVMs selected")

        # Even a harmless key asks first when it goes to several; nothing is sent by opening the question.
        menu.get_by_role("button", name="Lock screen").click()
        asking = top(page)
        expect(asking.locator("ul.targets li")).to_have_count(2)
        asking.get_by_role("button", name="Cancel").click()
        page.wait_for_timeout(400)
        assert fakes[0].state.actions == [] and fakes[1].state.actions == []

        # What can cost somebody their work wants a tick besides.
        menu.get_by_role("button", name="Reboot KVM").click()
        asking = top(page)
        run = asking.get_by_role("button", name="Run on 2 KVMs")
        expect(run).to_be_disabled()
        asking.get_by_label("Yes, do this on all 2 machines").check()
        expect(run).to_be_enabled()
        asking.get_by_role("button", name="Cancel").click()
        page.wait_for_timeout(400)
        assert fakes[0].state.actions == [] and fakes[1].state.actions == []

        menu.get_by_role("button", name="Lock screen").click()
        top(page).get_by_role("button", name="Run on 2 KVMs").click()
        until(page, lambda: all(fake.state.actions for fake in fakes), "the key was not sent to both")
        page.wait_for_timeout(400)
        for fake in fakes:
            assert fake.state.actions == ["shortcut MetaLeft,KeyL"], fake.state.actions  # each of them, and each once


def test_several_are_ticked_and_removed_at_once_after_a_question_that_names_them(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    spares = [FakeKvm(FakeState(colour=(20, 120, 60), hostname="spare-a")).start(), FakeKvm(FakeState(colour=(90, 30, 120), hostname="spare-b")).start()]
    try:
        named = (("Build server", fakes[0]), ("Mail server", fakes[1]), ("Spare A", spares[0]), ("Spare B", spares[1]))
        with a_wall(tmp_path, *named) as (live, admin), looking(browser, live) as page:
            ids = {device["name"]: device["id"] for device in admin.get("/api/v1/wall").json()["devices"]}
            sign_in(page, live)
            expect(page.locator("#wall article")).to_have_count(4)
            page.locator("#select-toggle").click()
            remove = page.locator("#bulk-remove")
            expect(remove).to_be_visible()
            expect(remove).to_be_disabled()  # (nothing ticked yet)
            for name in ("Build server", "Mail server", "Spare A"):
                tile(page, name).click()
            expect(page.locator("#bulk-count")).to_have_text("3 selected")

            # The question names each of them with its address, says what goes, and wants the tick before anything is sent.
            remove.click()
            asking = top(page)
            expect(asking.locator("h2")).to_have_text("Remove 3 KVMs?")
            expect(asking.locator("ul.targets li")).to_have_count(3)
            for name, fake in named[:3]:
                expect(asking.locator("ul.targets li", has_text=name)).to_contain_text(fake.url.split("://", 1)[1])
            expect(asking).to_contain_text("Their saved passwords and their history go with them, for good: this cannot be undone.")
            expect(asking).to_contain_text("Settings > Export and import")
            go = asking.get_by_role("button", name="Remove 3 KVMs")
            expect(go).to_be_disabled()
            asking.get_by_label("Yes, remove all 3 machines").check()
            expect(go).to_be_enabled()
            # Cancelled: nothing goes, and the selection is as it was.
            asking.get_by_role("button", name="Cancel").click()
            expect(page.locator("dialog[open]")).to_have_count(0)
            remove.click()
            page.keyboard.press("Escape")  # (and so is a question closed with Esc)
            expect(page.locator("dialog[open]")).to_have_count(0)
            page.wait_for_timeout(300)
            assert len(admin.get("/api/v1/wall").json()["devices"]) == 4
            expect(page.locator("#bulk-count")).to_have_text("3 selected")

            # One of them is taken off by somebody else while the question is open: nothing goes, and that is said.
            remove.click()
            asking = top(page)
            asking.get_by_label("Yes, remove all 3 machines").check()
            assert admin.delete(f"/api/v1/devices/{ids['Spare A']}").status_code == 200
            asking.get_by_role("button", name="Remove 3 KVMs").click()
            expect(asking.locator("p[role=status]")).to_have_text("Spare A is no longer on the wall, so nothing was removed. Look at the selection again.")
            expect(asking.locator("ul.progress li.bad")).to_have_text(re.compile("Spare A.*No longer on the wall"))
            expect(asking.locator("ul.progress li.skipped")).to_have_count(2)
            asking.locator(".actions").get_by_role("button", name="Close").click()
            expect(page.locator("#wall article")).to_have_count(3)
            expect(page.locator("#bulk-count")).to_have_text("2 selected")  # (what is left of the selection)
            assert [device["name"] for device in admin.get("/api/v1/wall").json()["devices"]] == ["Build server", "Mail server", "Spare B"]

            # And now for good: they go, the wall shows what is left, and select mode is left with them.
            remove.click()
            asking = top(page)
            expect(asking.locator("h2")).to_have_text("Remove 2 KVMs?")
            asking.get_by_label("Yes, remove all 2 machines").check()
            asking.get_by_role("button", name="Remove 2 KVMs").click()
            expect(asking.locator("p[role=status]")).to_have_text("2 KVMs removed.")
            expect(asking.locator("h2")).to_have_text("Remove 2 KVMs")  # (a question no more)
            expect(asking.locator("ul.progress li.ok")).to_have_count(2)
            expect(page.locator("#wall article")).to_have_count(1)
            expect(tile(page, "Spare B")).to_be_visible()
            expect(page.locator("#bulkbar")).to_be_hidden()
            expect(page.locator("#select-toggle")).to_have_attribute("aria-pressed", "false")
            asking.locator(".actions").get_by_role("button", name="Close").click()
            assert [device["name"] for device in admin.get("/api/v1/wall").json()["devices"]] == ["Spare B"]
            entries = admin.get("/api/v1/audit", params={"q": "device_removed"}).json()["entries"]
            assert sorted(entry["device"] for entry in entries if entry["event"] == "device_removed") == ["Build server", "Mail server", "Spare A"]

            # An operator has select mode, and no Remove in it; asked for all the same, the wall refuses.
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
            with looking(browser, live) as hers:
                sign_in(hers, live, OTHER, name="olga")
                expect(hers.locator("#wall article")).to_have_count(1)
                hers.locator("#select-toggle").click()
                expect(hers.locator("#bulkbar")).to_be_visible()
                expect(hers.locator("#bulk-remove")).to_be_hidden()
                assert asks(hers, "POST", "api/v1/devices/remove", {"ids": [ids["Spare B"]]}) == 403
            assert len(admin.get("/api/v1/wall").json()["devices"]) == 1

            # One machine alone: no tick, the question in the singular.
            page.locator("#select-toggle").click()
            tile(page, "Spare B").click()
            remove.click()
            asking = top(page)
            expect(asking.locator("h2")).to_have_text("Remove Spare B?")
            expect(asking).to_contain_text("Its saved password and its history go with it")
            expect(asking.get_by_role("checkbox")).to_have_count(0)
            # Its question closed while the request is out (held here on its way): no second Remove until it is answered,
            # and then what became of it is said where it can still be seen.
            held: list[Any] = []
            page.route("**/api/v1/devices/remove", lambda route: held.append(route))
            asking.get_by_role("button", name="Remove", exact=True).click()
            until(page, lambda: bool(held), "the request never went out")
            page.keyboard.press("Escape")
            expect(page.locator("dialog[open]")).to_have_count(0)
            expect(remove).to_be_disabled()
            expect(page.locator("#bulk-count")).to_have_text("1 selected")
            held[0].continue_()
            told(page, "Spare B removed.")
            expect(page.locator("#wall article")).to_have_count(0)
            expect(page.locator("#bulkbar")).to_be_hidden()
            page.unroute("**/api/v1/devices/remove")
            assert admin.get("/api/v1/wall").json()["devices"] == []
    finally:
        for spare in spares:
            spare.stop()


def test_the_search_and_the_filters_narrow_the_wall_and_typing_presses_no_shortcut(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    dark = FakeKvm(FakeState(signal=False)).start()
    try:
        with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1]), ("Dark one", dark)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(page.locator("#wall article:visible")).to_have_count(3)
            expect(page.locator('#filters button[data-filter="no_signal"] b')).to_have_text("1")
            page.locator("#search").fill("mail")
            expect(page.locator("#wall article:visible")).to_have_count(1)
            expect(tile(page, "Mail server")).to_be_visible()
            # Letters that are shortcuts on the wall (display mode, select, fullscreen) are letters in a box.
            page.locator("#search").press_sequentially("dsf")
            expect(page.locator("#no-match")).to_be_visible()
            expect(page.locator("#display-bar")).to_be_hidden()
            expect(page.locator("#bulkbar")).to_be_hidden()
            assert page.evaluate("document.fullscreenElement") is None
            page.locator("#search").press("Escape")
            expect(page.locator("#wall article:visible")).to_have_count(3)

            # A key held down repeats some thirty times a second, and each one narrows the wall anew before the
            # movement of the one before is over. That is typing, and the page does not call it a fault. (It did:
            # "Something went wrong on this page. Reload it if anything looks stuck.")
            page.locator("#search").focus()
            for _ in range(10):
                page.keyboard.down("m")
                page.wait_for_timeout(33)
            page.keyboard.up("m")
            expect(page.locator("#no-match")).to_be_visible()
            page.wait_for_timeout(500)
            expect(page.locator("#toasts .toast.error")).to_have_count(0)
            page.locator("#search").press("Escape")
            expect(page.locator("#wall article:visible")).to_have_count(3)

            page.locator('#filters button[data-filter="no_signal"]').click()
            expect(page.locator("#wall article:visible")).to_have_count(1)
            expect(tile(page, "Dark one")).to_be_visible()
            page.locator('#filters button[data-filter="no_signal"]').click()  # pressed again: all of them
            expect(page.locator("#wall article:visible")).to_have_count(3)
    finally:
        dark.stop()


def test_a_screen_on_the_wall_opens_with_its_link_and_goes_dark_when_the_link_is_taken_back(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0]), ("Mail server", fakes[1])) as (live, admin), looking(browser, live) as page:
        made = admin.post("/api/v1/tokens", json={"name": "Hall", "kind": "display"})
        assert made.status_code == 201, made.text
        key, token = made.json()["token"], made.json()["record"]["id"]
        build = next(d["id"] for d in admin.get("/api/v1/wall").json()["devices"] if d["name"] == "Build server")
        page.goto(f"{live.url}/#display&key={key}")
        expect(page.locator("#wall article.has-frame")).to_have_count(2)
        # The key is taken out of the address, where it would be on show for whoever walks past the screen.
        assert page.evaluate("location.href") == f"{live.url}/#display"
        assert key not in page.content()
        # A screen looks. It is offered nothing to press, and what its script asks for anyway is refused.
        for hidden in ("#add-device", "#select-toggle", "#open-settings"):
            expect(page.locator(hidden)).to_be_hidden()
        assert asks(page, "POST", f"api/v1/devices/{build}/actions", {"action": "keys", "keys": "MetaLeft,KeyL"}) == 403
        assert asks(page, "GET", "api/v1/tokens") == 403
        assert asks(page, "POST", "api/v1/password", {"current": key, "new": OTHER}) == 403
        assert fakes[0].state.actions == []

        # The power comes back after a cut, the browser starts again on the address it has: the wall is there.
        page.reload()
        expect(page.locator("#wall article")).to_have_count(2)

        # Taken back by an admin, the screen goes dark by itself and asks for a sign-in.
        assert admin.delete(f"/api/v1/tokens/{token}").status_code == 200
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible(timeout=40_000)
        expect(page.locator("#shell")).to_be_hidden()
        assert asks(page, "GET", "api/v1/wall") == 401


def test_another_site_cannot_show_the_wall_inside_itself(tmp_path: Path, browser: Browser) -> None:
    with a_wall(tmp_path) as (live, _):
        context = browser.new_context()
        try:
            page = context.new_page()
            # (Answered here, by the test: nothing is asked of any network for it.)
            page.route("http://another.invalid/**", lambda route: route.fulfill(content_type="text/html", body=f'<iframe src="{live.url}/"></iframe>'))
            page.goto("http://another.invalid/")
            page.wait_for_load_state("load")
            page.wait_for_timeout(500)
            inside = page.frames[-1]
            assert inside is not page.main_frame
            assert inside.locator("#auth, #shell, script").count() == 0, inside.url
            # ...while the same address by itself is the page.
            page.goto(live.url)
            expect(page.locator("#auth-card")).to_be_visible()
        finally:
            context.close()


def test_a_page_from_another_port_of_the_same_address_cannot_press_anything(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # A browser keeps cookies by name and not by port: whatever else is served from the address the wall is
    # looked at under (a KVM's own page, another program on the same computer) is sent the wall's cookie along
    # with every request it makes to the wall. The cookie is therefore not what a change is believed by.
    fake = fakes[0]
    with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
        build = admin.get("/api/v1/wall").json()["devices"][0]["id"]
        context = browser.new_context()
        try:
            page = context.new_page()
            sign_in(page, live)
            press = f"{live.url}/api/v1/devices/{build}/actions"
            went: list[Request] = []
            context.on("request", lambda request: went.append(request) if request.url == press else None)
            attack = f"""<script>
              const what = JSON.stringify({{ action: 'keys', keys: 'MetaLeft,KeyL' }});
              window.tried = Promise.allSettled([
                fetch('{press}', {{ method: 'POST', mode: 'no-cors', credentials: 'include', headers: {{ 'Content-Type': 'text/plain' }}, body: what }}),
                fetch('{press}', {{ method: 'POST', credentials: 'include', headers: {{ 'Content-Type': 'application/json', 'X-QKVM': '1' }}, body: what }}),
              ]).then(all => all.map(one => one.status));
            </script>
            <form method="post" action="{press}" enctype="text/plain"><input name='{{"action":"keys","keys":"MetaLeft,KeyL","x":"' value='"}}'></form>"""
            other = f"http://127.0.0.1:{closed_port()}"
            # (Answered here, by the test: nothing listens on that port.)
            page.route(other + "/**", lambda route: route.fulfill(content_type="text/html", body=attack))
            page.goto(other + "/")
            # A script there asks twice: plainly, and with the header a change needs. Neither comes to anything.
            assert page.evaluate("window.tried") == ["rejected", "rejected"]
            # A form is the oldest way. The browser goes where it points, cookie and all, and shows what the wall says.
            with page.expect_navigation():
                page.evaluate("document.querySelector('form').submit()")
            assert json.loads(page.locator("body").inner_text()) == {"code": "forbidden", "message": "Cross-site request refused"}
            page.wait_for_timeout(300)
            assert fake.state.actions == []
            # It was not for want of the cookie: that went along each time, as said above.
            cookies = [request.all_headers().get("cookie", "") for request in went]
            assert len(cookies) >= 2 and all("qkvm_session=" in cookie for cookie in cookies), cookies
            # (From the wall's own page the same request is a key press: that it is refused is not for any other reason.)
            page.goto(live.url)
            expect(page.locator("#wall article")).to_have_count(1)
            assert asks(page, "POST", f"api/v1/devices/{build}/actions", {"action": "keys", "keys": "MetaLeft,KeyL"}) == 200
            assert fake.state.actions == ["shortcut MetaLeft,KeyL"]
        finally:
            context.close()


def test_the_page_is_served_with_its_rules_and_keeps_to_them(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        reply = page.goto(live.url)
        assert reply is not None
        rules = reply.headers.get("content-security-policy", "")
        said = dict(part.strip().split(" ", 1) for part in rules.split(";") if " " in part.strip())
        assert said.get("default-src") == "'self'" or said.get("script-src") == "'self'", rules
        assert "unsafe-inline" not in said.get("script-src", said.get("default-src", "")) and "unsafe-eval" not in rules, rules
        assert said.get("frame-ancestors") == "'none'", rules
        assert reply.headers.get("x-content-type-options") == "nosniff"
        # What the rules forbid, tried from inside the page: a script written into it does not run, nor one from elsewhere.
        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#wall article")).to_have_count(1)
    # (Outside `looking`: this page breaks the rules on purpose, and is told so.)
    with a_wall(tmp_path / "second") as (live, _):
        context = browser.new_context()
        try:
            page = context.new_page()
            refused: list[str] = []
            page.on("console", lambda message: refused.append(message.text) if "Content Security Policy" in message.text else None)
            page.goto(live.url)
            page.evaluate("""() => { const s = document.createElement('script'); s.textContent = 'window.inline = 1'; document.head.append(s);
              const d = document.createElement('div'); d.innerHTML = '<img src="x" onerror="window.handler = 1">'; document.body.append(d); }""")
            page.wait_for_timeout(500)
            assert page.evaluate("[window.inline, window.handler]") == [None, None]
            assert len(refused) >= 2, refused
        finally:
            context.close()


@pytest.mark.parametrize("motion", ["reduce", "no-preference"])
def test_nothing_is_typed_into_a_machine_by_keys_meant_for_the_page(tmp_path: Path, browser: Browser, fakes: list[FakeKvm], motion: str) -> None:
    # The wall looks; it is no console. Whatever is typed while a tile has the focus, or while one is
    # enlarged, stays with the page: the machine behind it gets none of it.
    fake = fakes[0]
    with a_wall(tmp_path, ("Build server", fake)) as (live, _), looking(browser, live) as page:
        page.emulate_media(reduced_motion=motion)
        sign_in(page, live)
        expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
        tile(page, "Build server").focus()
        page.keyboard.type("rm")
        page.keyboard.press("Space")
        # The first space opens the view and focuses its Close button. A later
        # space can activate that button, so settle the opening before typing
        # the rest; do not assume the whole string leaves the view open.
        expect(page.locator("#focus")).to_be_visible()
        page.keyboard.type("-rf /")
        page.keyboard.press("Control+Alt+Delete")
        page.keyboard.press("Escape")  # whatever the letters opened
        page.keyboard.press("Escape")
        expect(page.locator("#focus")).to_be_hidden()
        tile(page, "Build server").focus()
        expect(tile(page, "Build server")).to_be_focused()
        page.keyboard.press("Enter")
        expect(page.locator("#focus")).to_be_visible()
        page.keyboard.type("shutdown now")
        page.keyboard.press("Delete")
        page.wait_for_timeout(500)
        assert fake.state.actions == []


def test_escape_cancels_queued_enlargements_and_older_openings_do_not_return(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Build server", fakes[0])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "Build server")).to_have_attribute("data-state", "online")
        # Control transition callback delivery rather than depending on the runner's
        # animation speed. The normal keyboard handlers still receive every key.
        page.evaluate("""() => {
          window.openings = [];
          document.startViewTransition = update => {
            window.openings.push(update);
            return { ready: Promise.resolve(), finished: Promise.resolve() };
          };
        }""")
        tile(page, "Build server").focus()
        page.keyboard.press("Enter")
        assert page.evaluate("window.openings.length") == 1
        page.keyboard.press("Escape")
        page.evaluate("window.openings.shift()()")
        expect(page.locator("#focus")).to_be_hidden()
        expect(tile(page, "Build server")).to_be_focused()

        page.keyboard.press("Enter")
        page.keyboard.press("Enter")
        assert page.evaluate("window.openings.length") == 2
        page.evaluate("window.openings.pop()()")  # newest opening delivered first
        expect(page.locator("#focus")).to_be_visible()
        page.keyboard.press("Escape")  # queue its closing
        page.evaluate("window.openings.shift()()")  # stale opening must do nothing
        page.evaluate("window.openings.shift()()")  # close the requested view
        expect(page.locator("#focus")).to_be_hidden()
        expect(tile(page, "Build server")).to_be_focused()
        assert fakes[0].state.actions == []


# --- what an outside reviewer walked through, and what it found on the way ------------------------------------


def arranging(page: Page) -> None:
    page.locator("#view-toggle").click()
    page.locator("#arrange").click()
    expect(page.get_by_role("toolbar", name="Arrange the tiles")).to_be_visible()


def test_the_places_of_the_tiles_are_counted_after_one_has_moved(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # A tile moved one place on, with the movement on screen that a browser shows as it comes: the tiles
    # changed places and kept each other's numbers. (Counted right away, and moved a moment later.)
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        arranging(page)
        page.get_by_role("button", name="Alpha: one place later", exact=True).click()
        expect(page.locator("#wall article").first).to_have_attribute("data-id", admin.get("/api/v1/wall").json()["devices"][1]["id"])
        expect(page.get_by_label("Place of Alpha", exact=True)).to_have_value("2")
        expect(page.get_by_label("Place of Beta", exact=True)).to_have_value("1")


def test_an_order_is_saved_for_everybody_and_one_that_is_left_is_not(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, admin), looking(browser, live, reduced_motion="reduce") as page:
        sign_in(page, live)
        as_added = [device["id"] for device in admin.get("/api/v1/wall").json()["devices"]]
        arranging(page)
        assert page.evaluate("document.querySelector('.top').inert") is True  # the top bar rests meanwhile
        page.get_by_label("Place of Alpha", exact=True).fill("2")
        page.get_by_label("Place of Alpha", exact=True).press("Tab")
        page.get_by_role("button", name="Save this order", exact=True).click()
        expect(page.locator("#shell")).not_to_have_class(re.compile("arranging"))
        assert [device["id"] for device in admin.get("/api/v1/wall").json()["devices"]] == as_added[::-1]
        page.reload()
        expect(page.locator("#wall article").first).to_have_attribute("data-id", as_added[1])
        arranging(page)
        page.get_by_role("button", name="Beta: one place later", exact=True).click()
        page.keyboard.press("Escape")  # left: as it was
        expect(page.get_by_role("toolbar", name="Arrange the tiles")).to_have_count(0)
        expect(page.locator("#wall article").first).to_have_attribute("data-id", as_added[1])
        assert [device["id"] for device in admin.get("/api/v1/wall").json()["devices"]] == as_added[::-1]


def test_a_session_that_ends_while_the_tiles_are_being_arranged_takes_the_arranging_with_it(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # Signed out from elsewhere in the middle of it, and signed in again on the same page: the tiles were
    # back, and so were the bar for arranging them and a top bar that took no click, until the page was
    # fetched anew.
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        arranging(page)
        assert admin.post("/api/v1/logout", json={"scope": "all"}).status_code == 200
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible(timeout=40_000)
        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.locator("#wall article")).to_have_count(2)
        assert page.evaluate("document.querySelector('.top').inert") is False
        expect(page.get_by_role("toolbar", name="Arrange the tiles")).to_have_count(0)
        expect(page.locator("#shell")).not_to_have_class(re.compile("arranging"))
        expect(page.locator("#wall .arrange")).to_have_count(0)
        page.locator("#open-settings").click()  # and the top bar takes a click
        expect(top(page).locator("h2")).to_have_text("Settings")


def test_an_order_still_being_saved_when_the_session_ended_leaves_the_next_arranging_alone(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    # "Save this order" pressed, and before the wall's answer arrived the session ended from elsewhere;
    # signed in again on the same page and arranging once more. Then the answer about the first order
    # came: it ended an arranging that was not its own (the top bar took clicks again, the tiles lost
    # their handles, and the bar "Arrange" stayed for good, with a Cancel that did nothing).
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        arranging(page)
        held: list[Any] = []
        page.route("**/api/v1/wall/order", lambda route: held.append((route, route.fetch())))
        page.get_by_role("button", name="Save this order").click()
        until(page, lambda: bool(held), "the order was never sent")
        assert admin.post("/api/v1/logout", json={"scope": "all"}).status_code == 200
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible(timeout=40_000)
        page.locator("#auth-card input[type=password]").fill(PASSWORD)
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.locator("#wall article")).to_have_count(2)
        arranging(page)
        route, answer = held.pop()
        route.fulfill(response=answer)  # the wall's answer about the first order, only now
        page.wait_for_timeout(700)
        assert page.locator("#toasts .toast", has_text="The order is saved").count() == 0  # (looked at now, not waited for: it is not said to somebody who is arranging anew)
        bar = page.get_by_role("toolbar", name="Arrange the tiles")
        expect(bar).to_have_count(1)
        expect(page.locator("#shell")).to_have_class(re.compile("arranging"))
        assert page.evaluate("document.querySelector('.top').inert") is True
        bar.get_by_role("button", name="Cancel").click()  # and this arranging is still left the way it is left
        expect(bar).to_have_count(0)
        expect(page.locator("#shell")).not_to_have_class(re.compile("arranging"))
        assert page.evaluate("document.querySelector('.top').inert") is False


def test_what_is_taken_in_from_a_file_is_what_its_summary_showed(tmp_path: Path, browser: Browser) -> None:
    # A file chosen and "Read the file" pressed; then, before the wall had answered, another file chosen.
    # The first one's summary came up, with a "Take in" that took the second: a list approved, another one
    # taken. An answer about a file that is no longer the chosen one is not shown, and what is taken is what
    # the summary on show was made from.
    first = json.dumps({"format": exchange.FORMAT, "version": 1, "actions": [{"name": "A harmless key", "kind": "keys", "keys": "ShiftLeft"}]})
    second = json.dumps({"format": exchange.FORMAT, "version": 1, "actions": [{"name": "Another key altogether", "kind": "keys", "keys": "ControlLeft,AltLeft,Delete"}]})
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        settings(page, "files").get_by_role("button", name="Import...", exact=True).click()
        form = top(page)
        held: list[Any] = []
        page.route("**/api/v1/import/read", lambda route: held.append((route, route.fetch())))
        page.evaluate("""() => { window.filesRead = 0; const read = File.prototype.text;
          File.prototype.text = async function () { const text = await read.call(this); window.filesRead += 1; return text; }; }""")
        picker = form.locator("input[type=file]")
        picker.set_input_files({"name": "first.json", "mimeType": "application/json", "buffer": first.encode()})
        form.get_by_role("button", name="Read the file").click()
        until(page, lambda: bool(held), "the first file was never sent to be read")
        picker.set_input_files({"name": "second.json", "mimeType": "application/json", "buffer": second.encode()})
        page.wait_for_function("window.filesRead === 2")  # the second is the chosen one now, and is read in
        route, answer = held.pop()
        route.fulfill(response=answer)  # ...and only then does the wall's answer about the first arrive
        page.wait_for_timeout(600)
        assert "A harmless key" not in form.inner_text()  # nothing of the first is on show
        expect(form.get_by_role("button", name="Take in", exact=True)).to_be_hidden()
        assert admin.get("/api/v1/actions").json()["actions"] == []
        # Read again, it is the second that is shown, and the second that is taken.
        page.unroute("**/api/v1/import/read")
        form.get_by_role("button", name="Read the file").click()
        expect(form).to_contain_text("Another key altogether")
        assert "A harmless key" not in form.inner_text()
        form.get_by_role("button", name="Take in", exact=True).click()
        told(page, "saved actions")
        assert [action["name"] for action in admin.get("/api/v1/actions").json()["actions"]] == ["Another key altogether"]


def test_a_console_over_vncs_is_said_to_be_encrypted_and_how_its_certificate_is_checked(tmp_path: Path, browser: Browser) -> None:
    # The summary of a file said "its certificate is not checked" only of addresses with https://, and the list of KVMs
    # called every other one "Unencrypted (http)": a console over vncs:// whose certificate is not checked was neither.
    file = json.dumps({
        "format": exchange.FORMAT,
        "version": 1,
        "devices": [
            {"url": "vncs://unchecked.invalid:5901", "kind": "vnc", "name": "Unchecked console", "tls": "insecure"},
            {"url": "vnc://plain.invalid:5901", "kind": "vnc", "name": "Plain console"},
        ],
    })  # fmt: skip
    with a_wall(tmp_path) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        settings(page, "files").get_by_role("button", name="Import...", exact=True).click()
        form = top(page)
        form.locator("input[type=file]").set_input_files({"name": "consoles.json", "mimeType": "application/json", "buffer": file.encode()})
        form.get_by_role("button", name="Read the file").click()
        expect(form.locator(".picklist div", has_text="Unchecked console")).to_contain_text("its certificate is not checked")
        expect(form.locator(".picklist div", has_text="Plain console")).not_to_contain_text("certificate")
        form.get_by_role("button", name="Take in", exact=True).click()
        told(page, "2 devices added")
        top(page).locator('[role=tab][data-tab="devices"]').click()  # (Settings, which the import was opened from)
        pane = top(page).locator("[role=tabpanel]")
        expect(pane.locator("tr", has_text="Unchecked console")).to_contain_text("Not checked")
        expect(pane.locator("tr", has_text="Unchecked console")).not_to_contain_text("Unencrypted")
        expect(pane.locator("tr", has_text="Plain console")).to_contain_text("Unencrypted (vnc)")


def test_metrics_are_switched_on_given_a_new_token_and_switched_off(tmp_path: Path, browser: Browser) -> None:
    with a_wall(tmp_path) as (live, _), looking(browser, live) as page, httpx.Client(base_url=live.url) as collector:
        sign_in(page, live)
        pane = settings(page, "metrics")
        assert collector.get("/metrics").status_code == 404  # off: nothing is there
        pane.get_by_role("button", name="Switch on and make a token").click()
        token = pane.get_by_label("Metrics token").input_value()
        assert collector.get("/metrics").status_code == 401
        assert collector.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        pane.get_by_role("button", name="Make a new token").click()
        top(page).get_by_role("button", name="Make a new token").click()  # asked first: the one in use stops working
        expect(pane.get_by_label("Metrics token")).not_to_have_value(token)
        newer = pane.get_by_label("Metrics token").input_value()
        assert collector.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 401
        assert collector.get("/metrics", headers={"Authorization": f"Bearer {newer}"}).status_code == 200
        pane.get_by_role("button", name="Switch off", exact=True).click()
        expect(pane.get_by_role("button", name="Switch on and make a token")).to_be_visible()
        assert collector.get("/metrics", headers={"Authorization": f"Bearer {newer}"}).status_code != 200


def test_a_token_for_a_script_does_what_its_role_may_and_nothing_once_taken_back(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "tokens")
        pane.get_by_role("button", name="Token for a script").click()
        form = top(page)
        form.locator('input[placeholder^="Nightly"]').fill("A script that looks")
        form.get_by_role("combobox").first.select_option("viewer")
        form.get_by_role("button", name="Make the token").click()
        token = form.get_by_label("Token", exact=True).input_value()
        with httpx.Client(base_url=live.url, headers={**CSRF, "Authorization": f"Bearer {token}"}) as script:
            seen = script.get("/api/v1/wall").json()["devices"]
            assert len(seen) == 2
            assert script.post(f"/api/v1/devices/{seen[0]['id']}/actions", json={"action": "reboot"}).status_code == 403
            assert script.get("/api/v1/users").status_code == 403
            form.get_by_role("button", name="I have it").click()
            pane.get_by_role("button", name="Take back", exact=True).click()
            top(page).get_by_role("button", name="Take it back", exact=True).click()
            told(page, "A script that looks taken back")
            assert script.get("/api/v1/wall").status_code == 401
        assert fakes[0].state.actions == []


def test_alerts_are_set_up_tried_paused_and_their_address_forgotten(tmp_path: Path, browser: Browser) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received: list[bytes] = []

    class Taking(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *said: Any) -> None:
            pass

    taking = ThreadingHTTPServer(("127.0.0.1", 0), Taking)  # where the alerts of this test go: this computer, and nowhere else
    worker = threading.Thread(target=taking.serve_forever, daemon=True)
    worker.start()
    try:
        with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            pane = settings(page, "alerts")
            first_line = pane.locator(".section-head")
            expect(first_line.get_by_role("button", name="Send a test alert")).to_be_disabled()  # nowhere to send one yet
            pane.get_by_label("Watch the KVMs and send alerts").check()
            pane.get_by_role("textbox", name=re.compile("^Address")).fill(f"http://127.0.0.1:{taking.server_port}/notice")
            pane.get_by_role("combobox", name=re.compile("^Service")).select_option("json")
            pane.get_by_label("Link in alerts").fill(live.url)
            first_line.get_by_role("button", name="Save", exact=True).click()
            told(page, "Alerts saved")
            expect(first_line.get_by_role("button", name="Send a test alert")).to_be_enabled()
            first_line.get_by_role("button", name="Send a test alert").click()
            until(page, lambda: len(received) == 1, "the test alert never arrived")
            assert json.loads(received[0])
            assert f"127.0.0.1:{taking.server_port}" not in page.content()  # the address is kept sealed, and not handed back to the page
            pane.get_by_role("button", name="For an hour").click()
            told(page, "Alerts paused")
            assert (admin.get("/api/v1/alerts").json()["paused_until"] or 0) > time.time()
            expect(pane).to_contain_text("Paused until")
            pane.get_by_role("button", name="Send alerts again").click()
            told(page, "Alerts are sent again")
            assert not admin.get("/api/v1/alerts").json()["paused_until"]
            pane.get_by_label("Forget the saved address").check()
            first_line.get_by_role("button", name="Save", exact=True).click()
            until(page, lambda: not admin.get("/api/v1/alerts").json()["has_webhook"], "the address was not forgotten")
    finally:
        taking.shutdown()
        taking.server_close()
        worker.join(5)


def test_a_screen_on_the_wall_goes_from_one_group_to_the_next_by_itself(tmp_path: Path, browser: Browser, fakes: list[FakeKvm]) -> None:
    with a_wall(tmp_path, ("Alpha", fakes[0]), ("Beta", fakes[1])) as (live, admin), looking(browser, live) as page:
        for device, group in zip(admin.get("/api/v1/wall").json()["devices"], ("First", "Second"), strict=True):
            assert admin.put(f"/api/v1/devices/{device['id']}", json={"name": device["name"], "url": device["url"], "group": group}).status_code == 200
        sign_in(page, live)
        page.locator("#group").select_option("First")
        page.locator("#view-toggle").click()
        page.locator("#display").click()
        page.locator("#display-rotate").check()
        expect(page.locator("#display-group")).to_have_text("Second", timeout=30_000)
        expect(tile(page, "Beta")).to_be_visible()
        expect(tile(page, "Alpha")).to_be_hidden()
        page.locator("#display-exit").click()
        expect(page.locator("#display-bar")).to_be_hidden()


def test_a_jetkvm_on_the_wall_its_picture_what_it_can_wake_and_no_signal(tmp_path: Path, browser: Browser) -> None:
    jet = FakeJetKvm(JetState(extension="atx-power", wol=[{"name": "The build machine", "macAddress": "02:00:00:00:00:01"}])).start()
    try:
        with a_wall(tmp_path, ("A JetKVM", jet)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "A JetKVM")).to_have_attribute("data-state", "online", timeout=40_000)
            expect(tile(page, "A JetKVM")).to_have_class(re.compile(r"\bhas-frame\b"))
            page.get_by_role("button", name="Actions for A JetKVM").click()
            wake = top(page).get_by_role("button", name="Wake The build machine", exact=True)
            wake.click()
            assert not any(action.startswith("wol ") for action in jet.state.actions)  # asked first
            top(page).locator(".actions button").last.click()
            until(page, lambda: any(action.startswith("wol ") for action in jet.state.actions), "the machine was never woken")
            jet.state.signal = False
            expect(tile(page, "A JetKVM")).to_have_attribute("data-state", "no_signal", timeout=30_000)
            expect(tile(page, "A JetKVM").locator(".veil")).to_contain_text("No signal")
    finally:
        jet.stop()


def test_a_server_on_the_wall_has_a_power_button_and_no_keyboard(tmp_path: Path, browser: Browser) -> None:
    server = FakeBmc(BmcState(model='<img src=x onerror="window.reached=4">')).start()
    try:
        with a_wall(tmp_path, ("A server", server)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "A server")).to_have_attribute("data-state", "online", timeout=40_000)
            page.get_by_role("button", name="Actions for A server").click()
            menu = top(page)
            expect(menu.get_by_role("button", name="Send keys...")).to_have_count(0)  # a controller has no keyboard to type on
            expect(menu.get_by_role("button", name="Shut down", exact=True)).to_be_visible()
            assert page.locator("img[src='x']").count() == 0 and page.evaluate("window.reached") is None
            menu.get_by_role("button", name="Locator light on", exact=True).click()
            until(page, lambda: server.state.led == "Lit", "the light was never switched on")
            assert server.state.power == "On"  # nothing else was touched
    finally:
        server.stop()


def test_a_server_is_started_into_its_bios_setup_after_a_question_that_names_it(tmp_path: Path, browser: Browser) -> None:
    # Start into BIOS setup on the page: in the machine's own menu where its controller allows it; asked first, with the
    # server named and that it restarts (Cancel sends nothing); a yes opens its large view and sends the press with
    # `watching`; the controller is given the one-time override, then the restart.
    server = FakeBmc().start()
    try:
        with a_wall(tmp_path, ("A server", server)) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            expect(tile(page, "A server")).to_have_attribute("data-state", "online", timeout=40_000)
            deadline = time.monotonic() + 30
            while True:  # (offered once the page's look at the server says the controller allows it: a menu shows what was known when it opened)
                page.get_by_role("button", name="Actions for A server").click()
                menu = top(page)
                if menu.get_by_role("button", name="Start into BIOS setup").count():
                    break
                assert time.monotonic() < deadline, "Start into BIOS setup was never offered"
                page.keyboard.press("Escape")
                page.wait_for_timeout(500)
            menu.get_by_role("button", name="Start into BIOS setup").click()
            expect(top(page).locator("h2")).to_have_text("Start into BIOS setup")
            expect(top(page)).to_contain_text("A server will restart now and start straight into its BIOS setup screen, once.")
            top(page).get_by_role("button", name="Cancel").click()
            page.wait_for_timeout(400)
            assert server.state.actions == [] and not any("Boot" in change for change in server.state.changes)
            page.get_by_role("button", name="Actions for A server").click()  # (the menu closed as the question opened)
            top(page).get_by_role("button", name="Start into BIOS setup").click()
            with page.expect_request(lambda request: request.method == "POST" and request.url.endswith("/actions")) as sent:
                top(page).get_by_role("button", name="Restart into setup").click()
            assert sent.value.post_data_json == {"action": "bios_setup", "watching": True}
            expect(page.locator("#focus-name")).to_have_text("A server")  # its large view, to watch the setup
            until(page, lambda: server.state.actions == ["system ForceRestart"], "the server was never restarted")
            boots = [change["Boot"] for change in server.state.changes if "Boot" in change]
            assert boots == [{"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "BiosSetup"}]
    finally:
        server.stop()


def test_a_pc_with_intel_amt_says_what_it_is_and_why_its_screen_is_not_shown_and_an_admin_switches_its_kvm_on(tmp_path: Path, browser: Browser) -> None:
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()  # as an engine set up by hand comes: its KVM off on the engine
    try:
        with a_wall(tmp_path, ("A PC", pc)) as (live, _), looking(browser, live) as page:  # type: ignore[arg-type]
            sign_in(page, live)
            pc_tile = tile(page, "A PC")
            expect(pc_tile).to_have_attribute("data-state", "online", timeout=40_000)
            # The tile says what the machine is (not "Server"), and why its screen is not shown, on the tile itself.
            expect(pc_tile.locator(".panel-power")).to_contain_text("PC with Intel AMT")
            expect(pc_tile.locator(".panel-why")).to_contain_text("Its screen is not shown: Its KVM is switched off on its management engine.")
            pc_tile.focus()
            page.keyboard.press("Enter")
            expect(page.locator("#focus")).to_be_visible()
            switch = page.locator("#focus-panel").get_by_role("button", name="Switch on its KVM")
            expect(switch).to_be_visible()
            switch.click()
            asked = top(page)
            expect(asked).to_contain_text("This changes a setting of the PC")
            assert pc.state.changes == []  # (asked first: nothing is changed before the yes)
            asked.get_by_role("button", name="Switch on", exact=True).click()
            told(page, "Its KVM is on")
            until(page, lambda: pc.state.changes == [("CIM_KVMRedirectionSAP", "2"), ("AMT_RedirectionService", "ListenerEnabled=true")], f"the PC was told {pc.state.changes}")
            page.wait_for_function("() => document.querySelector('#focus-canvas').width > 1", timeout=40_000)  # its screen, enlarged
            page.keyboard.press("Escape")
            expect(pc_tile).to_have_class(re.compile(r"\bhas-frame\b"), timeout=40_000)  # and on its tile
            # The way back is an admin's too, under Actions; asked first as well.
            page.get_by_role("button", name="Actions for A PC").click()
            top(page).get_by_role("button", name="Switch off its KVM").click()
            top(page).get_by_role("button", name="Switch off", exact=True).click()
            told(page, "Its KVM is off")
            until(page, lambda: pc.state.changes[2:] == [("CIM_KVMRedirectionSAP", "3")], f"the PC was told {pc.state.changes}")
    finally:
        pc.stop()


def test_the_enlarged_view_of_a_machine_with_a_live_picture_holds_its_panel_still(tmp_path: Path, browser: Browser) -> None:
    # (The demo found it: over the live picture of a server or a PC with Intel AMT, the panel of how it is came and went
    # once a second, because a class was toggled with a value that could be undefined, which flips it instead of setting
    # it. The same went for whether a tile counts as pictured before its first frame.)
    pc = FakeAmt(AmtState(kvm="enabled")).start()
    try:
        with a_wall(tmp_path, ("A PC", pc)) as (live, _), looking(browser, live) as page:  # type: ignore[arg-type]
            sign_in(page, live)
            pc_tile = tile(page, "A PC")
            expect(pc_tile).to_have_attribute("data-state", "online", timeout=40_000)
            pc_tile.focus()
            page.keyboard.press("Enter")
            expect(page.locator("#focus")).to_be_visible()
            page.wait_for_function("() => document.querySelector('#focus-canvas').width > 1", timeout=40_000)
            seen = page.evaluate(
                """async () => {
                    const seen = [];
                    for (let i = 0; i < 16; i++) {
                        const focus = document.querySelector('#focus');
                        seen.push([focus.classList.contains('has-panel'), focus.classList.contains('pictured')]);
                        await new Promise(done => setTimeout(done, 250));
                    }
                    return seen;
                }"""
            )
            assert all(sample == seen[0] for sample in seen), f"the panel came and went over four seconds: {seen}"
            assert seen[0] == [False, True], seen  # the picture shown, the panel a button away
    finally:
        pc.stop()


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_an_account_limited_to_one_machine_has_that_one_and_no_way_to_the_other(tmp_path: Path, browser: Browser, fakes: list[FakeKvm], role: str) -> None:
    with a_wall(tmp_path, ("Allowed", fakes[0]), ("Kept from them", fakes[1])) as (live, admin), looking(browser, live) as page:
        allowed, kept = (device["id"] for device in admin.get("/api/v1/wall").json()["devices"])
        assert admin.post("/api/v1/users", json={"name": "limited", "password": OTHER, "role": role, "devices": [allowed]}).status_code == 201
        sign_in(page, live, OTHER, name="limited")
        expect(page.locator("#wall article")).to_have_count(1)
        expect(page.locator("#wall article")).to_have_attribute("data-id", allowed)
        assert "Kept from them" not in page.content()
        assert asks(page, "GET", "api/v1/users") == 403
        assert asks(page, "GET", "api/v1/settings") == 403
        assert asks(page, "GET", f"api/v1/devices/{kept}/snapshot") == 404
        # What may be done to the one that is theirs goes by the role; to the other, nothing by either.
        pressed = asks(page, "POST", f"api/v1/devices/{allowed}/actions", {"action": "keys", "keys": "ShiftLeft"})
        assert pressed == (200 if role == "operator" else 403)
        assert asks(page, "POST", f"api/v1/devices/{kept}/actions", {"action": "keys", "keys": "ShiftLeft"}) in (403, 404)
        assert fakes[1].state.actions == [] and fakes[0].state.actions == (["shortcut ShiftLeft"] if role == "operator" else [])
        if role == "operator":
            expect(page.get_by_role("button", name="Actions for Allowed")).to_be_visible()
        # A link to the tile that is kept from them opens nothing.
        page.goto(f"{live.url}/#tile={kept}")
        page.reload()
        expect(page.locator("#wall article")).to_have_count(1)
        expect(page.locator("#focus")).to_be_hidden()


def test_a_vnc_server_is_added_from_the_wall_by_choosing_the_kind(tmp_path: Path, browser: Browser) -> None:
    from tests.fake_vnc import FakeVnc, VncState

    server = FakeVnc(VncState(width=320, height=200, name="vm-one")).start()
    try:
        with a_wall(tmp_path) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            page.locator("#add-device").click()
            form = top(page)
            form.get_by_label("What to add").select_option("vnc")
            expect(form.locator("label.field", has_text="Addresses")).to_contain_text("VNC server")  # the hint follows the choice
            expect(form.get_by_role("textbox", name=re.compile(r"^User name"))).to_be_disabled()  # a VNC server has no user name
            form.locator("textarea").fill(f"127.0.0.1:{server.port}")
            form.locator("input[type=password]").fill("secret")
            form.get_by_role("button", name="Check and add").click()
            expect(form.locator("ul.results li.ok")).to_contain_text("vm-one added")  # named after what it calls itself
            form.get_by_role("button", name="Close").click()
            expect(tile(page, "vm-one")).to_have_attribute("data-state", "online", timeout=40_000)
            expect(tile(page, "vm-one")).to_have_class(re.compile(r"\bhas-frame\b"))
            # Its edit dialog says what it is and has no user name box.
            page.get_by_role("button", name="Actions for vm-one").click()
            top(page).get_by_role("button", name="Edit...").click()
            expect(top(page).get_by_text("Type: VNC server")).to_be_visible()
            assert top(page).get_by_role("textbox", name=re.compile(r"^User name")).count() == 0
    finally:
        server.stop()


def test_a_vnc_server_over_tls_whose_certificate_changed_is_shown_and_trusted_again(tmp_path: Path, browser: Browser) -> None:
    # (The final review's F3.) The dialog showed nothing for a vncs:// address (the wall answered null for both), and its
    # Trust fetched the certificate at port 443: such a server could not be trusted again from the page.
    from tests.fake_vnc import FakeVnc, VncState

    known = FakeVnc(VncState(width=64, height=48, name="lab box"), tls_dir=tmp_path / "known").start()
    other: FakeVnc | None = None
    try:
        with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live) as page:
            added = admin.post("/api/v1/devices", json={"url": known.url, "password": "secret", "name": "Lab box"})
            assert added.status_code == 201, added.text
            sign_in(page, live)
            expect(tile(page, "Lab box")).to_have_class(re.compile(r"\bhas-frame\b"))
            known.stop()
            other = FakeVnc(VncState(width=64, height=48, name="reinstalled"), port=known.port, tls_dir=tmp_path / "other").start()
            review = tile(page, "Lab box").get_by_role("button", name="Review certificate")
            expect(review).to_be_visible(timeout=60_000)
            review.click()
            asked = top(page)
            expect(asked.locator("h2")).to_have_text("Lab box certificate")
            expect(asked.locator("code.fingerprint")).to_have_count(2)
            shown = asked.locator("code.fingerprint").all_inner_texts()
            assert len(shown) == 2 and shown[0] != shown[1] and all(len(mark) >= 40 for mark in shown), shown
            expect(asked.locator(".note.bad")).to_contain_text("do not trust it")
            assert other.state.password_tries == 0  # (shown, not trusted: told nothing)
            asked.get_by_role("button", name="Trust this certificate").click()
            told(page, "Lab box: certificate trusted")
            expect(tile(page, "Lab box")).to_have_attribute("data-state", "online", timeout=60_000)
            assert other.state.password_tries >= 1
            # Its edit dialog says which certificate is remembered and offers to review it, as for an https address.
            page.get_by_role("button", name="Actions for Lab box").click()
            top(page).get_by_role("button", name="Edit...").click()
            expect(top(page).get_by_text(f"Remembered SHA-256: {shown[1]}")).to_be_visible()
            expect(top(page).get_by_role("button", name="Review certificate")).to_be_visible()
    finally:
        known.stop()
        if other is not None:
            other.stop()


def test_virtual_machines_on_proxmox_are_picked_from_its_list_and_added(tmp_path: Path, browser: Browser) -> None:
    from tests.fake_proxmox import SECRET, TOKEN_ID, FakeProxmox, Guest, PveState
    from tests.fake_vnc import VncState

    guests = {100: Guest(100, "web", screen=VncState(width=320, height=200)), 101: Guest(101, "db", status="stopped"), 102: Guest(102, "mail")}
    pve = FakeProxmox(PveState(guests=guests, containers=[300]), tls_dir=tmp_path / "pve").start()
    try:
        with a_wall(tmp_path) as (live, _), looking(browser, live) as page:
            sign_in(page, live)
            page.locator("#add-device").click()
            form = top(page)
            form.get_by_label("What to add").select_option("proxmox")
            expect(form.locator("label.field", has_text="Addresses")).to_contain_text("API token")  # the hint follows the choice
            user = form.get_by_role("textbox", name=re.compile(r"^User name"))
            expect(user).to_have_value("")  # (no "admin": a token's ID goes there)
            user.fill(TOKEN_ID)
            form.locator("input[type=password]").fill(SECRET)
            # One Proxmox, no guest named: its guests are listed, nothing ticked, the container said apart.
            form.locator("textarea").fill(f"127.0.0.1:{pve.port}")
            form.get_by_role("button", name="Check and add").click()
            asked = form.locator("ul.results > li.ask")
            expect(asked).to_contain_text("3 virtual machines the token may see")
            expect(asked).to_contain_text("1 container is not listed")
            expect(asked.get_by_label(re.compile(r"^101 · db"))).not_to_be_checked()
            asked.get_by_label(re.compile(r"^100 · web")).check()
            asked.get_by_role("button", name="Add the ticked ones").click()
            expect(asked.locator("li.ok")).to_contain_text("web added")
            expect(asked.get_by_label(re.compile(r"^100 · web"))).to_be_disabled()  # on the wall now
            # One guest named by its ID: added at once.
            form.locator("textarea").fill(f"127.0.0.1:{pve.port}/102")
            form.get_by_role("button", name="Check and add").click()
            expect(form.locator(f'li.ok[data-url="127.0.0.1:{pve.port}/102"]')).to_contain_text("mail added")
            assert pve.state.in_the_clear == []
            form.get_by_role("button", name="Close").click()
            expect(tile(page, "web")).to_have_attribute("data-state", "online", timeout=40_000)
            expect(tile(page, "web")).to_have_class(re.compile(r"\bhas-frame\b"))
            # Its edit dialog says what it is, and asks for the token where a login is asked for.
            page.get_by_role("button", name="Actions for web").click()
            top(page).get_by_role("button", name="Edit...").click()
            expect(top(page).get_by_text("Type: Proxmox VM")).to_be_visible()
            expect(top(page).get_by_role("textbox", name=re.compile(r"^API token ID"))).to_have_value(TOKEN_ID)
    finally:
        pve.stop()
