"""The Media box of a machine, in a browser (0.3.0): an admin's, opened from the tile's Actions; one box that holds still
(one size and place, its controls where they stood through every change it knows, only its list scrolling), its main
button at the right of its first line; every mount and unmount asked first, naming the machine and the image; and the
tile saying what is in the drive.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Locator, Page, expect

from qkvm import kvm, proxmox
from tests.fake_proxmox import SECRET, TOKEN_ID, FakeProxmox, Guest, PveState, Storage
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, tile, told, top  # noqa: F401  (fixtures, by name)
from tests.test_users import OTHER

DEBIAN = "local:iso/debian-13.iso"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(proxmox, "LOOK_EVERY", 0.2)
    monkeypatch.setattr(proxmox, "SAME_GUEST_EVERY", 0.5)
    monkeypatch.setattr(proxmox, "FOLLOW_UP", ())
    monkeypatch.setattr(proxmox, "CONFIRM_EVERY", 0.05)
    proxmox._MOUNTED.clear()
    proxmox._BOOT_WAS.clear()


@pytest.fixture
def pve(tmp_path: Path) -> Iterator[FakeProxmox]:
    # Enough images on its storage for the list to scroll, and one of them the one to mount.
    images = {"debian-13.iso": 700_000_000, **{f"rescue-{n:02}.iso": 50_000_000 + n for n in range(40)}}
    fake = FakeProxmox(PveState(guests={100: Guest(100, "web")}, storages={"local": Storage(images)}), tls_dir=tmp_path / "pve").start()
    yield fake
    fake.stop()


def add_the_guest(admin: Any, fake: FakeProxmox) -> None:
    reply = admin.post("/api/v1/devices", json={"url": fake.guest_url(100), "username": TOKEN_ID, "password": SECRET, "kind": "proxmox"})
    assert reply.status_code == 201, reply.text


def open_the_box(page: Page) -> Locator:
    tile(page, "web").get_by_role("button", name="Actions for web").click()
    top(page).get_by_role("button", name="Media...").click()
    box = top(page)
    expect(box.locator("h2")).to_have_text("Virtual media of web")
    return box


def where_everything_stands(page: Page, box: Locator) -> dict[str, Any]:
    """Where the box and each of its controls stand, to the pixel."""
    page.wait_for_timeout(350)  # (a dialog settles in over a quarter of a second)
    found: dict[str, Any] = {}
    for name, control in {
        "box": box,
        "close": box.get_by_role("button", name="Close"),
        "mount": box.get_by_role("button", name="Mount", exact=True),
        "upload": box.get_by_role("button", name="Upload..."),  # (0.3.0, A2: beside Mount, disabled where there are no uploads)
        "delete": box.get_by_role("button", name="Delete", exact=True),
        "unmount": box.get_by_role("button", name="Unmount", exact=True),
        "mount as": box.get_by_label("Mount as"),
        "start from it": box.get_by_label("Start from it"),
        "restart": box.get_by_role("checkbox", name=re.compile(r"^Restart it now")),
        "list": box.locator(".media-list"),
        "said": box.locator(".media-said"),
    }.items():
        shape = control.bounding_box()
        assert shape is not None, name
        found[name] = tuple(round(shape[key]) for key in ("x", "y", "width", "height"))
    return found


def test_the_media_box_holds_still_and_mounts_what_its_question_named(tmp_path: Path, browser: Browser, pve: FakeProxmox) -> None:  # noqa: F811
    pve.state.images_take = 1.5  # (a slow storage: the box is seen while it is still looking)
    guest = pve.state.guests[100]
    with a_wall(tmp_path) as (live, admin), looking(browser, live, viewport={"width": 1280, "height": 860}) as page:
        add_the_guest(admin, pve)
        sign_in(page, live)
        expect(tile(page, "web")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        mount, unmount = box.get_by_role("button", name="Mount", exact=True), box.get_by_role("button", name="Unmount", exact=True)
        how, restart = box.get_by_label("Start from it"), box.get_by_role("checkbox", name=re.compile(r"^Restart it now"))
        expect(box.locator(".media-list")).to_contain_text("Looking for images...")
        expect(mount).to_be_disabled()
        expect(unmount).to_be_disabled()
        looking_for_them = where_everything_stands(page, box)
        # Its main button at the right of its first line, above everything else it has.
        assert looking_for_them["mount"][1] < looking_for_them["unmount"][1] < looking_for_them["start from it"][1] < looking_for_them["list"][1]
        assert looking_for_them["mount"][0] > looking_for_them["box"][0] + looking_for_them["box"][2] / 2

        debian = box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))
        expect(debian).to_be_visible(timeout=20_000)
        expect(box.locator(".media-now")).to_have_text("Nothing is mounted.")
        listed = where_everything_stands(page, box)
        assert listed == looking_for_them  # (forty-one images came: the list scrolls, and nothing else moved)
        assert box.locator(".media-list").evaluate("list => list.scrollHeight > list.clientHeight + 100")
        expect(mount).to_be_disabled()
        # A guest's images are Proxmox's: nothing to upload or delete here, and a CD-ROM drive is all it takes them as.
        expect(box.get_by_role("button", name="Upload...")).to_be_disabled()
        expect(box.get_by_role("button", name="Delete", exact=True)).to_be_disabled()
        assert box.get_by_label("Mount as").evaluate("select => [...select.options].filter(option => !option.disabled).map(option => option.value)") == ["cd"]
        debian.check()
        expect(mount).to_be_enabled()
        # How it is to start: "once" restarts, always; leaving the order as it is restarts nothing.
        how.select_option("once")
        expect(restart).to_be_checked()
        expect(restart).to_be_disabled()
        how.select_option("until_unmounted")
        expect(restart).to_be_enabled()
        how.select_option("none")
        expect(restart).not_to_be_checked()
        expect(restart).to_be_disabled()
        assert where_everything_stands(page, box) == listed

        # Asked first, naming the machine and the image; cancelled, nothing is sent.
        mount.click()
        question = top(page)
        expect(question.locator("h2")).to_have_text("Mount debian-13.iso")
        expect(question).to_contain_text("web gets debian-13.iso (on local) in its CD-ROM drive, read-only, and its boot order is left as it is.")
        question.get_by_role("button", name="Cancel").click()
        assert pve.state.changes == []
        mount.click()
        top(page).get_by_role("button", name="Mount", exact=True).click()
        told(page, "web: Mount debian-13.iso done")
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso on local · read-only · not first in its boot order · mounted by admin at")
        expect(unmount).to_be_enabled()
        expect(box.locator(".media-list label", has_text="debian-13.iso")).to_contain_text("mounted now")
        assert guest.config["ide2"] == f"{DEBIAN},media=cdrom"
        assert where_everything_stands(page, box) == listed

        # A refusal is said in its line, in Proxmox's words, and nothing moves for it.
        guest.may_cdrom = False
        box.get_by_role("radio", name=re.compile(r"^rescue-00\.iso")).check()
        mount.click()
        top(page).get_by_role("button", name="Mount", exact=True).click()
        expect(box.locator(".media-said")).to_contain_text("VM.Config.CDROM")
        expect(box.locator(".media-said")).to_have_class(re.compile(r"\berror\b"))
        assert where_everything_stands(page, box) == listed
        guest.may_cdrom = True

        # The tile says what is in the drive, to whoever looks at it.
        box.get_by_role("button", name="Close").click()
        expect(tile(page, "web").locator(".meta")).to_contain_text("CD: debian-13.iso")

        # Unmounted: asked first, naming both; and the tile says nothing is in it any more.
        box = open_the_box(page)
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso on local", timeout=20_000)
        box.get_by_role("button", name="Unmount", exact=True).click()
        question = top(page)
        expect(question.locator("h2")).to_have_text("Unmount debian-13.iso")
        expect(question).to_contain_text("debian-13.iso is taken out of the drive of web.")
        question.get_by_role("button", name="Unmount", exact=True).click()
        told(page, "web: Unmount debian-13.iso done")
        expect(box.locator(".media-now")).to_have_text("Nothing is mounted.")
        expect(box.get_by_role("button", name="Unmount", exact=True)).to_be_disabled()
        assert guest.config["ide2"] == "none,media=cdrom"
        box.get_by_role("button", name="Close").click()
        expect(tile(page, "web").locator(".meta")).not_to_contain_text("CD:")


def test_the_media_box_is_an_admins(tmp_path: Path, browser: Browser, pve: FakeProxmox) -> None:  # noqa: F811
    with a_wall(tmp_path) as (live, admin), looking(browser, live) as page:
        add_the_guest(admin, pve)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
        sign_in(page, live, password=OTHER, name="olga")
        expect(tile(page, "web")).to_have_attribute("data-state", "online", timeout=30_000)
        tile(page, "web").get_by_role("button", name="Actions for web").click()
        actions = top(page)
        expect(actions.get_by_role("button", name="Press reset button")).to_be_visible()  # (an operator's buttons are there)
        expect(actions.get_by_role("button", name="Media...")).to_be_hidden()
