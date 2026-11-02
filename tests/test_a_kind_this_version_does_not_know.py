"""A tile of a kind of machine this version does not know, as a later version writes one (register row 2 of 0.2.1,
r1-upgrade F5): somebody tries a later version, which adds a kind, and goes back to this one with its settings.

Such a tile was read as a KVM: at an http or https address it was given kvmd's driver, and its saved password was
posted to that address as a KVM's sign-in; at an address of its own (spice://, ssh://) the settings were not read at
all, and the wall did not start. Now it is kept as it is (written back unchanged with every save, for the version that
made it), its tile says what it is, and it is left alone: no driver talks to it, its password is never opened, an
edit is refused, removing it works. An import refuses such a kind, as before (test_exchange)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.fake_kvm import FakeKvm
from tests.settings_file import settings_text, write_settings_text
from tests.test_wall import add, closed_port, fast, snap, wall  # noqa: F401  (the fixture)


def devices_saved(folder: Path) -> list[dict[str, Any]]:
    return list(json.loads(settings_text(folder / "qkvm.json", encoding="utf-8"))["devices"])


def test_a_tile_of_a_kind_this_version_does_not_know_is_kept_said_and_left_alone(tmp_path: Path) -> None:
    device = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            later = add(admin, device.url, name="Later")  # its password saved, for the KVM at this address
            other = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="Elsewhere")
            kept = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="A KVM")
        # What a later version that adds two kinds made of the first two: one at an http address, one at an address of
        # its own.
        for name in ("qkvm.json", "qkvm.bak"):
            saved = json.loads(settings_text(tmp_path / name, encoding="utf-8"))
            saved["devices"][0]["kind"] = "kvmd2"
            saved["devices"][1].update(kind="spice", url="spice://192.0.2.10:5900")
            write_settings_text(tmp_path / name, json.dumps(saved), encoding="utf-8")
        as_written = devices_saved(tmp_path)[:2]
        assert as_written[0]["secret"] is not None
        device.state.tokens.clear()  # (the KVM has forgotten who was signed in, as after its restart)
        logins = device.state.logins
        with wall(tmp_path) as admin:
            for _ in range(5):
                states = admin.get("/api/v1/status").json()
            listed = {entry["id"]: entry for entry in admin.get("/api/v1/wall").json()["devices"]}
            for tile, kind in ((later, "kvmd2"), (other, "spice")):
                state = states[tile]
                assert state["state"] == "error" and state["error"]["code"] == "unknown_kind", state
                assert f"({kind})" in state["error"]["message"] and "this version" in state["error"]["message"]
                assert listed[tile]["kind"] == kind and listed[tile]["picture"] is False  # (no pictures asked for)
                assert admin.get(snap(tile)).status_code != 200
                ran = admin.post(f"/api/v1/devices/{tile}/actions", json={"action": "ctrl_alt_del"})
                assert ran.status_code == 409 and ran.json()["code"] == "unknown_kind", ran.text
                edited = admin.put(f"/api/v1/devices/{tile}", json={"url": device.url, "name": "Renamed", "password": ""})
                assert edited.status_code == 409 and edited.json()["code"] == "unknown_kind", edited.text
                trusted = admin.post(f"/api/v1/devices/{tile}/trust", json={"fingerprint": "AB"})
                assert trusted.status_code == 409 and trusted.json()["code"] == "unknown_kind", trusted.text
                shown = admin.get(f"/api/v1/devices/{tile}/certificate")
                assert shown.status_code == 409 and shown.json()["code"] == "unknown_kind", shown.text
            # Another change is saved: the two are written as they were read.
            assert admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
            assert devices_saved(tmp_path)[:2] == as_written
            assert admin.delete(f"/api/v1/devices/{other}").status_code == 200
            assert [entry["id"] for entry in devices_saved(tmp_path)] == [later, kept]
        print(f">>> five looks, an action, an edit and a trust at a tile of a kind this version does not know: {device.state.logins - logins} sign-ins sent")
        assert device.state.logins == logins and device.state.actions == []
    finally:
        device.stop()


def test_one_at_a_kvms_own_address_is_sent_no_sign_in(tmp_path: Path) -> None:
    # The half of it that harmed: alone (the other tile above kept 0.2.0 from starting at all), a tile of a later kind at
    # an http address was given kvmd's driver, and its saved password went to that address as a KVM's sign-in.
    device = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            later = add(admin, device.url, name="Later")
        for name in ("qkvm.json", "qkvm.bak"):
            saved = json.loads(settings_text(tmp_path / name, encoding="utf-8"))
            saved["devices"][0]["kind"] = "kvmd2"
            write_settings_text(tmp_path / name, json.dumps(saved), encoding="utf-8")
        device.state.tokens.clear()
        logins = device.state.logins
        with wall(tmp_path) as admin:
            for _ in range(5):
                state = admin.get("/api/v1/status").json()[later]
            ran = admin.post(f"/api/v1/devices/{later}/actions", json={"action": "ctrl_alt_del"})
        print(f">>> five looks and an action at a tile of kind kvmd2 at a KVM's address: {device.state.logins - logins} sign-ins sent; its tile: {state['state']} {state['error']}; the action: {ran.status_code}")
        assert device.state.logins == logins and device.state.actions == []
        assert state["error"]["code"] == "unknown_kind"
    finally:
        device.stop()
