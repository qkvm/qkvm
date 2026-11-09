"""The screen watch on a wall: set on a tile, told through the alerts, the picture kept and handed to an admin, carried in a file."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, exchange, kvm, screens, update, vault
from qkvm.video import RGBFrame, encode_jpeg
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_alerts import Inbox
from tests.test_users import account, browser
from tests.test_wall import PASSWORD, add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(screens, "MINUTE", 0.5)  # (a minute is half a second here)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def inbox() -> Iterator[Inbox]:
    box = Inbox()
    yield box
    box.close()


def picture(shade: int, mark: int = 0) -> bytes:
    """A JPEG of a screen of one shade, with a bright bar `mark` squares in (0: none)."""
    width, height = 320, 180
    rgb = bytearray(bytes([shade]) * (width * height * 3))
    if mark:
        for y in range(40, 60):
            rgb[(y * width + mark * 5) * 3 : (y * width + mark * 5 + 40) * 3] = b"\xff" * 120
    return encode_jpeg(RGBFrame(width, height, bytes(rgb)), None, 3)


def shown(client: Any, device: str, seconds: float) -> None:
    """The tile on a screen: its picture asked for, as the page asks."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        client.get(snap(device), params={"w": 320})
        time.sleep(0.05)


def alert_entries(admin: Any) -> list[dict[str, Any]]:
    return [entry for entry in admin.get("/api/v1/audit", params={"kind": "alert"}).json()["entries"] if entry.get("watch")][::-1]


def test_a_screen_that_looks_the_same_is_told_with_its_picture_and_again_when_it_changes(tmp_path: Path, inbox: Inbox) -> None:
    fake = FakeKvm(FakeState(picture=picture(60), picture_type="image/jpeg")).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server", unchanged_minutes=2)
            assert admin.get("/api/v1/wall").json()["devices"][0]["unchanged_minutes"] == 2
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            # Nobody has its tile on a screen: nothing to compare, nothing said, and nothing asked of the KVM for it.
            asked = len(fake.state.snapshot_queries)
            time.sleep(screens.MINUTE * 3)
            assert inbox.titles() == [] and len(fake.state.snapshot_queries) == asked
            until = time.monotonic() + 20
            while "Build server: screen unchanged for 2 min" not in inbox.titles():
                assert time.monotonic() < until, f"the screen that looked the same was never told: {inbox.titles()}"
                shown(admin, device, 0.3)
            told = json.loads(inbox.received[-1]["body"])
            assert (told["event"], told["state"], told["previous"]) == ("unchanged", "unchanged", "online")
            assert "not always a hang" in told["message"]
            [entry] = alert_entries(admin)
            assert (entry["watch"], entry["minutes"], entry["device"], entry["device_id"], entry.get("back")) == ("unchanged", 2, "Build server", device, None)
            kept = admin.get(f"/api/v1/devices/{device}/alert-picture/{entry['picture']}")
            assert kept.status_code == 200 and kept.content == picture(60) and kept.headers["content-type"] == "image/jpeg"
            assert kept.headers["cache-control"] == "no-store" and abs(entry["picture_at"] - time.time()) < 60
            # For an admin, as the activity log that names it is.
            account(admin, "olga", "operator")
            assert browser(admin, "olga").get(f"/api/v1/devices/{device}/alert-picture/{entry['picture']}").status_code == 403
            assert admin.get(f"/api/v1/devices/{device}/alert-picture/12345").json()["code"] == "no_picture"
            assert admin.get(f"/api/v1/devices/nosuch01/alert-picture/{entry['picture']}").status_code == 404
            # Told once; then the screen changes, and that is told.
            shown(admin, device, 1.0)
            assert inbox.titles().count("Build server: screen unchanged for 2 min") == 1
            fake.state.picture = picture(60, mark=10)
            wait_until(lambda: (shown(admin, device, 0.2), "Build server: the screen changes again" in inbox.titles())[1], "the change was never told")
            back = alert_entries(admin)[-1]
            assert (back["watch"], back["back"], back["state"], back["was"]) == ("unchanged", True, "online", "unchanged") and "picture" not in back
            # The tile taken off the wall: its picture goes with it.
            assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
            wait_until(lambda: not list((tmp_path / screens.FOLDER).glob(f"{device}-*")), "the picture stayed after the tile went")
    finally:
        fake.stop()


def test_no_signal_is_told_after_its_minutes_and_not_at_once(tmp_path: Path, inbox: Inbox) -> None:
    watched, plain = FakeKvm(FakeState(picture=picture(90), picture_type="image/jpeg")).start(), FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            office = add(admin, watched.url, name="Office PC")
            other = add(admin, plain.url, name="Lab PC")
            edit = {"name": "Office PC", "url": watched.url, "password": "", "no_signal_minutes": 2}
            assert admin.put(f"/api/v1/devices/{office}", json=edit).status_code == 200
            assert [(d["no_signal_minutes"], d["unchanged_minutes"]) for d in admin.get("/api/v1/wall").json()["devices"]] == [(2, 0), (0, 0)]
            assert admin.put(f"/api/v1/devices/{office}", json={**edit, "no_signal_minutes": 1441}).status_code == 422
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            # Its last picture with a signal, which the alert keeps: shown until the wall holds one. (A tile's pictures are
            # noted once a round knows the machine is watched; shown for 0.3 s alone, on a slow Linux runner, 3.11, no round
            # came in that time and the alert went out with no picture.)
            def kept() -> bool:
                shown(admin, office, 0.1)
                machine = admin.core.screens._machines.get(office)
                return machine is not None and machine.last_lit is not None

            wait_until(kept, "the wall kept no picture of the tile with a signal", 30)
            admin.get(snap(other))
            # (The round's looks after which it knows what is normal for each, and has kept the last picture with a signal: two
            # were given 0.6 s, and on GitHub's Windows runner, 3.13, the alert twice went out before one was kept.)
            time.sleep(2.0)
            watched.state.signal = plain.state.signal = False
            wait_until(lambda: "Lab PC has no video signal" in inbox.titles(), "no alert for the machine without the watch")
            wait_until(lambda: "Office PC has had no video signal for 2 min" in inbox.titles(), "no alert for the dark screen", 20)
            assert "Office PC has no video signal" not in inbox.titles()  # what is told at once is left to the watch
            [entry] = alert_entries(admin)
            # Two minutes after the round settled on "no signal", the look at which the other machine's alert went out.
            at_once = next(e for e in admin.get("/api/v1/audit", params={"kind": "alert"}).json()["entries"] if e["device"] == "Lab PC")
            # (The other machine's alert is written a moment after that look, later on a loaded computer: on Linux 3.14 with
            # four whole suites at once, 0.054 s after it, past the 0.05 s this allowed. A quarter of a minute still tells
            # "after its two minutes" from "at once", which is the point.)
            assert entry["time"] - at_once["time"] >= 2 * screens.MINUTE - screens.MINUTE / 4, (entry, at_once)
            assert admin.get(f"/api/v1/devices/{office}/alert-picture/{entry['picture']}").content == picture(90)
            watched.state.signal = plain.state.signal = True
            wait_until(lambda: "Office PC has a picture again" in inbox.titles() and "Lab PC has a picture again" in inbox.titles(), "no alert for the signal back")
            time.sleep(0.5)
            assert inbox.titles().count("Office PC has a picture again") == 1
            # A screen dark for less than its minutes is nobody's news.
            watched.state.signal = False
            time.sleep(screens.MINUTE * 0.8)
            watched.state.signal = True
            time.sleep(0.8)
            assert inbox.titles().count("Office PC has a picture again") == 1 and len([t for t in inbox.titles() if t.startswith("Office")]) == 2
    finally:
        watched.stop()
        plain.stop()


def test_the_pictures_kept_go_with_time_and_with_their_machine_while_alerts_are_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final review of 0.3.0, core L6.) The pictures were looked through only in a round of the alerts: a wall whose
    # alerts were switched off kept them for good, past the 30 days SECURITY.md says, and with machines removed since.
    monkeypatch.setattr(screens, "SWEEP_EVERY", 0.2)
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            assert admin.get("/api/v1/alerts").json()["enabled"] is False
            folder = tmp_path / screens.FOLDER
            folder.mkdir(exist_ok=True)
            old = time.time() - (screens.KEEP_DAYS + 1) * screens.DAY
            (folder / f"{device}-1.jpg").write_bytes(b"\xff\xd8 kept too long")
            os.utime(folder / f"{device}-1.jpg", (old, old))
            (folder / f"{device}-2.jpg").write_bytes(b"\xff\xd8 kept")
            (folder / "ab12cd34-3.jpg").write_bytes(b"\xff\xd8 of a machine that left the wall")
            wait_until(lambda: sorted(path.name for path in folder.iterdir()) == [f"{device}-2.jpg"], "the pictures were not looked through", 10)
    finally:
        fake.stop()


def test_the_watches_go_into_a_file_and_come_back_out_of_it(tmp_path: Path) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path / "one") as admin:
            add(admin, fake.url, name="Rack KVM", no_signal_minutes=15, unchanged_minutes=30)
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
            assert made.status_code == 200
            file = made.text
            [entry] = json.loads(file)["devices"]
            assert (entry["no_signal_minutes"], entry["unchanged_minutes"]) == (15, 30)
        with wall(tmp_path / "one") as admin:  # (and they are in the settings file, for the next start)
            [device] = admin.get("/api/v1/wall").json()["devices"]
            assert (device["no_signal_minutes"], device["unchanged_minutes"]) == (15, 30)
        with wall(tmp_path / "two") as admin:
            # One with a time no form takes is left out, as the form refuses it; none said is none.
            said = json.loads(file)
            said["devices"] = [said["devices"][0], {**said["devices"][0], "url": "http://127.0.0.1:9", "unchanged_minutes": 2000}, {**said["devices"][0], "url": "http://127.0.0.1:10"}]
            del said["devices"][2]["no_signal_minutes"]
            content = exchange.unpack(json.dumps(said), "")
            assert [(d.no_signal_minutes, d.unchanged_minutes) for d in content.devices] == [(15, 30), (0, 30)]
            assert len(content.left_out) == 1 and "watched" in content.left_out[0]
            taken = admin.post("/api/v1/import", json={"file": file, "take": ["devices"]})
            assert taken.status_code == 200 and taken.json()["devices"] == 1
            [device] = admin.get("/api/v1/wall").json()["devices"]
            assert (device["no_signal_minutes"], device["unchanged_minutes"]) == (15, 30)
    finally:
        fake.stop()
