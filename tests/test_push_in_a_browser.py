"""Alerts by Web Push in a browser: Settings > Alerts > This browser, turned on, tried and turned off.

The page's service worker (static/push.js) is registered for real, by Chromium on http://127.0.0.1 (a secure context),
and shows what is handed to it as a real push would be (by the browser's DevTools, which is how a test hands one in).
What a browser's push service does is stood in for on both sides of the wall: the browser's subscription is made in
the page by a stand-in for PushManager (a real one would ask Google's service, and nothing here leaves this
computer), and the wall's sends go to the stand-in push service (tests/fake_push.py), where what arrived is read with
that subscription's keys.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Error, Page, expect, sync_playwright

from qkvm import webpush
from qkvm.alerts import Alert
from tests.fake_push import Browser as Phone
from tests.fake_push import FakePush
from tests.test_in_a_browser import a_wall, looking, settings, sign_in, told, until
from tests.test_users import OTHER

# PushManager as a browser has it, but for its push service: a subscription with the keys of `given`, made in the page.
STAND_IN = """(() => {
  const given = %s;
  const bytes = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length %% 4)) %% 4)), c => c.charCodeAt(0)).buffer;
  let held = null;
  window.__pushes = { subscribed: 0, unsubscribed: 0 };
  PushManager.prototype.subscribe = async function (options) {
    window.__pushes.subscribed += 1;
    window.__pushes.key = btoa(String.fromCharCode(...new Uint8Array(options.applicationServerKey)));
    held = {
      endpoint: given.endpoint, expirationTime: null,
      options: { userVisibleOnly: options.userVisibleOnly, applicationServerKey: new Uint8Array(options.applicationServerKey).buffer },
      getKey: name => bytes(given[name]),
      toJSON: () => ({ endpoint: given.endpoint, expirationTime: null, keys: { p256dh: given.p256dh, auth: given.auth } }),
      unsubscribe: async () => { held = null; window.__pushes.unsubscribed += 1; return true; },
    };
    return held;
  };
  PushManager.prototype.getSubscription = async function () { return held; };
})();"""


def stand_in_for(page: Page, phone: Phone) -> None:
    page.add_init_script(STAND_IN % json.dumps({"endpoint": phone.endpoint, **phone.keys}))


def scope_of(live: object) -> str:
    return f"{live.url}/static/push/"  # type: ignore[attr-defined]


@pytest.fixture(scope="module")
def chromium() -> Iterator[Browser]:
    """Chromium itself, headless. (The headless shell the other browser tests run in shows no notification at all.)"""
    with sync_playwright() as playwright:
        try:
            made = playwright.chromium.launch(channel="chromium")
        except Error as ex:
            if os.environ.get("CI"):
                raise
            pytest.skip(f"no Chromium for Playwright (python -m playwright install chromium): {str(ex).splitlines()[0]}")
        yield made
        made.close()


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakePush]:
    push = FakePush(tmp_path / "push")
    push.put_in_place(monkeypatch)
    yield push
    push.close()


def test_this_browser_is_turned_on_tried_shown_an_alert_and_turned_off(tmp_path: Path, chromium: Browser, service: FakePush) -> None:
    phone = Phone("/send/from-the-page")
    with a_wall(tmp_path) as (live, admin), looking(chromium, live, permissions=["notifications"]) as page:
        stand_in_for(page, phone)
        sign_in(page, live)
        assert page.locator('link[rel="manifest"]').get_attribute("href") == "static/manifest.webmanifest"
        assert httpx.get(live.url + "/static/manifest.webmanifest").json()["display"] == "standalone"  # (what an iPhone adds to its Home Screen)
        pane = settings(page, "alerts")
        line = pane.locator(".setting", has_text="This browser")
        expect(line).to_contain_text("Off.")
        expect(pane.locator(".block", has_text="Browsers told the alerts")).to_contain_text("No browser is told the alerts yet.")
        line.get_by_role("button", name="Turn on").click()
        told(page, "This browser is told the alerts now")
        expect(line).to_contain_text("On, as Chrome on")
        expect(pane.locator(".block", has_text="Browsers told the alerts").locator("tbody tr")).to_have_count(1)
        expect(pane.locator("tbody tr").first).to_contain_text("(this one)")

        # The wall has it, for the account that turned it on, with the key the page was given.
        [listed] = admin.get("/api/v1/push").json()["browsers"]
        assert listed["name"].startswith("Chrome on") and listed["service"] == "push.example.com" and listed["account"] == "admin"
        key = admin.get("/api/v1/push").json()["key"]
        assert webpush.unb64(key) == base64.b64decode(page.evaluate("window.__pushes.key"))
        # ...and the worker is the page's own, in its own scope, and running.
        scope, state = page.evaluate("""async scope => { const r = await navigator.serviceWorker.getRegistration(scope);
          return [r && r.scope, r && r.active && r.active.state]; }""", scope_of(live))
        assert (scope, state) == (scope_of(live), "activated")
        assert page.evaluate("navigator.serviceWorker.controller") is None  # it controls no page: no request of the wall's passes it

        line.get_by_role("button", name="Send a test").click()
        told(page, "Test alert sent")
        until(page, lambda: len(service.received) == 1, "the test alert did not reach the push service")
        assert phone.read(service.received[0])["title"] == "Test alert from qKVM"

        # What the worker does with a push: shows it, as the wall said it.
        cdp = page.context.new_cdp_session(page)
        registrations: list[dict[str, str]] = []
        cdp.on("ServiceWorker.workerRegistrationUpdated", lambda event: registrations.extend(event["registrations"]))
        cdp.send("ServiceWorker.enable")
        until(page, lambda: any(r["scopeURL"] == scope_of(live) for r in registrations), "the worker's registration was not seen")
        registration = next(r["registrationId"] for r in registrations if r["scopeURL"] == scope_of(live))
        said = json.loads(webpush.payload(Alert("offline", "Build server", "", "offline", "online", "Build server is offline", "The KVM stopped answering."), "ab12cd34"))
        cdp.send("ServiceWorker.deliverPushMessage", {"origin": live.url, "registrationId": registration, "data": json.dumps(said)})
        shown: list[dict[str, object]] = []

        def notified() -> bool:
            shown[:] = page.evaluate("""async scope => (await (await navigator.serviceWorker.getRegistration(scope)).getNotifications())
              .map(n => ({ title: n.title, body: n.body, tile: n.data && n.data.tile }))""", scope_of(live))
            return bool(shown)

        until(page, notified, "the worker showed nothing")
        assert shown == [{"title": "Build server is offline", "body": "The KVM stopped answering.", "tile": "ab12cd34"}]

        line.get_by_role("button", name="Turn off").click()
        told(page, "is told the alerts no more")
        expect(line).to_contain_text("Off.")
        expect(pane.locator(".block", has_text="Browsers told the alerts")).to_contain_text("No browser is told the alerts yet.")
        assert admin.get("/api/v1/push").json()["browsers"] == []
        assert page.evaluate("window.__pushes") == {"subscribed": 1, "unsubscribed": 1, "key": page.evaluate("window.__pushes.key")}


def test_a_viewer_turns_on_its_own_browser_and_an_admin_sees_and_removes_it(tmp_path: Path, chromium: Browser, service: FakePush) -> None:
    phone = Phone("/send/viewer")
    with a_wall(tmp_path) as (live, admin):
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer", "password": OTHER}).status_code == 201
        with looking(chromium, live, permissions=["notifications"]) as page:
            stand_in_for(page, phone)
            sign_in(page, live, password=OTHER, name="victor")
            pane = settings(page, "alerts")
            expect(pane.get_by_text("Watch the KVMs and send alerts")).to_have_count(0)  # what is set for the wall is an admin's
            line = pane.locator(".setting", has_text="This browser")
            expect(line).to_contain_text("Alerts are off on this wall just now")
            line.get_by_role("button", name="Turn on").click()
            told(page, "This browser is told the alerts now")
            expect(line).to_contain_text("On, as")
        with looking(chromium, live) as page:
            sign_in(page, live, name="admin")
            pane = settings(page, "alerts")
            rows = pane.locator(".block", has_text="Browsers told the alerts").locator("tbody tr")
            expect(rows).to_have_count(1)
            expect(rows.first).to_contain_text("victor")
            # This browser of the admin's has none: Chromium on 127.0.0.1 could, and is offered it.
            expect(pane.locator(".setting", has_text="This browser").get_by_role("button", name="Turn on")).to_be_visible()
            rows.first.get_by_role("button", name="Remove").click()
            told(page, "is told the alerts no more")
            expect(rows).to_have_count(0)
        assert admin.get("/api/v1/push").json()["browsers"] == []
