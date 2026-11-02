"""Which JetKVM answers at a tile's address: a JetKVM is known by the number it gives for itself (its deviceId).

A JetKVM serves plain HTTP out of its box, and many are on the wall that way: nothing there tells one from another but what
it says. A fleet often has one password, and a JetKVM takes its address from DHCP: after a new lease another JetKVM answers
at a tile's address, and the tile signed in to it, connected to its screen and sent it whatever was pressed (keys, text, its
ATX power and reset buttons, its own restart). Now the number it gives for itself is remembered when the tile is added
(DeviceSpec.machine, kept in the settings) and asked before anything is sent: before every video connection is offered, over
which every key, text and press goes. A JetKVM gives that number only to whoever is signed in to it, so its sign-in is the
one thing that goes to another JetKVM with the same password (over plain HTTP the password goes in the clear to whatever
answers in any case); nothing after it does. In these tests another JetKVM is the same stand-in with another number, which
does not take the wall's session (a JetKVM makes its own).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import jetkvm, kvm, update, vault
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.settings_file import settings_text, write_settings_text
from tests.test_jetkvm import other_ways, saved
from tests.test_wall import PASSWORD, add, snap, wait_until, wall

A_NUMBER, B_NUMBER = "9f1c2e7ab4d05836", "3c5e7a9b1d2f4068"
A_MARK = "jetkvm:" + hashlib.sha256(A_NUMBER.encode()).hexdigest()[:32]
B_MARK = "jetkvm:" + hashlib.sha256(B_NUMBER.encode()).hexdigest()[:32]
PRESSES = ("atx_power_long", "atx_reset", "atx_power", "reboot", "jiggler_on", "ctrl_alt_del", "wol")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(jetkvm, "SAME_JETKVM_EVERY", 0.5)  # (asked again once a minute while another answers: here, at once)


def jetkvm_a(password: str = "secret") -> FakeJetKvm:
    return FakeJetKvm(JetState(password=password, device_id=A_NUMBER, extension="atx-power")).start()


def another_jetkvm(jet: FakeJetKvm) -> dict[str, int]:
    """From now on another JetKVM answers at the address (a new lease): the same password, a number of its own, and none of
    the wall's session; the connection the wall had ends with the one it was to. What it is sent is counted from here."""
    jet.drop()
    state = jet.state
    state.device_id, state.token = B_NUMBER, None
    state.actions.clear()
    state.typed.clear()
    state.reports.clear()
    state.mouse.clear()
    return {"logins": state.logins, "sessions": state.sessions, "offers": len(state.video_offers)}


def this_jetkvm_again(jet: FakeJetKvm) -> None:
    jet.drop()
    jet.state.device_id, jet.state.token = A_NUMBER, None


def said(reply: httpx.Response) -> tuple[int, str]:
    return reply.status_code, str(reply.json().get("code"))


def status_of(client: Any, device: str) -> dict[str, Any]:
    return dict(client.get("/api/v1/status").json()[device])


def refused_for_another(client: Any, device: str) -> dict[str, Any]:
    wait_until(lambda: (status_of(client, device).get("error") or {}).get("code") == "another_machine", "the tile never said that another JetKVM answers", 20)
    status = status_of(client, device)
    assert status["state"] == "error", status
    return status


def test_another_jetkvm_at_the_address_is_sent_no_key_no_press_and_no_video_connection(tmp_path: Path) -> None:
    jet = jetkvm_a()
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url)
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]  # kept with the tile
            wait_until(lambda: client.get(snap(device)).status_code == 200, "the JetKVM never showed its screen", 20)
            before = another_jetkvm(jet)
            status = refused_for_another(client, device)
            assert "Another JetKVM answers at this address" in status["error"]["message"]
            act = f"/api/v1/devices/{device}/actions"
            for action in PRESSES:
                assert said(client.post(act, json={"action": action, "mac": "AA:BB:CC:DD:EE:FF"})) == (502, "another_machine"), action
            assert said(client.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL"})) == (502, "another_machine")
            assert said(client.post(act, json={"action": "text", "text": "what is typed into this tile's computer"})) == (502, "another_machine")
            assert client.get(snap(device)).json()["code"] == "another_machine"
            # Nothing went to it after the sign-in it gives its number for: no video connection was offered (each takes its
            # one viewer), no key, no press.
            state = jet.state
            assert (state.actions, state.typed, state.reports, state.mouse) == ([], [], [], [])
            assert (state.sessions, len(state.video_offers)) == (before["sessions"], before["offers"])
            assert state.logins - before["logins"] <= 1  # (once: the session it gave is kept, and not asked for again at every look)
            # This tile's JetKVM answers there again: the tile says how it is, and its buttons are its own again.
            this_jetkvm_again(jet)
            wait_until(lambda: status_of(client, device)["state"] == "online", "the tile's own JetKVM was not taken back", 20)
            assert client.post(act, json={"action": "atx_power_long"}).status_code == 200 and state.actions == ["atx power-long"]
    finally:
        jet.stop()


def test_a_jetkvm_without_a_password_is_known_by_its_number_too(tmp_path: Path) -> None:
    jet = jetkvm_a(password="")
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url, password="")
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            before = another_jetkvm(jet)
            refused_for_another(client, device)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
            assert jet.state.actions == [] and (jet.state.sessions, len(jet.state.video_offers)) == (before["sessions"], before["offers"])
    finally:
        jet.stop()


def test_an_edit_takes_the_jetkvm_that_answers_now_only_where_its_password_is_typed(tmp_path: Path) -> None:
    jet = jetkvm_a()
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url, name="Bench")
            another_jetkvm(jet)
            edit = f"/api/v1/devices/{device}"
            renamed = client.put(edit, json={"name": "Bench, renamed", "url": jet.url, "password": ""})
            assert said(renamed) == (422, "another_machine"), renamed.text
            # "Save anyway" without the password keeps the JetKVM it was added for.
            forced = client.put(edit, json={"name": "Bench, renamed", "url": jet.url, "password": "", "force": True})
            assert forced.status_code == 200 and client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            # Whoever types the password says "this is the JetKVM": the one that answers now is the tile's from then on.
            typed = client.put(edit, json={"name": "Bench", "url": jet.url, "password": "secret"})
            assert typed.status_code == 200, typed.text
            assert client.core.store.device(device).machine == B_MARK  # type: ignore[attr-defined]
            wait_until(lambda: status_of(client, device)["state"] == "online", "the JetKVM taken by the edit is not shown", 20)
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}).status_code == 200 and jet.state.actions == ["atx reset"]
    finally:
        jet.stop()


def as_written_by_0_2_0(data: Path) -> None:
    """The settings as a wall of 0.2.0 wrote them for the same tile: its JetKVM's number in `ident` (for telling it from the
    others), and no machine (0.2.0 checked none for a JetKVM)."""
    for name in ("qkvm.json", "qkvm.bak"):
        written = json.loads(settings_text(data / name, encoding="utf-8"))
        for device in written["devices"]:
            device["machine"] = ""
        write_settings_text(data / name, json.dumps(written), encoding="utf-8")


def test_a_tile_from_0_2_0_knows_its_jetkvm_by_the_number_it_kept_and_trusts_nothing_that_answers_first(tmp_path: Path) -> None:
    jet = jetkvm_a()
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, jet.url)
        as_written_by_0_2_0(data)
        kept = json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))["devices"][0]
        assert (kept["machine"], kept["ident"]) == ("", A_MARK)
        # Upgraded while another JetKVM answers at the address: it is not taken for the tile's.
        another_jetkvm(jet)
        with wall(data) as client:
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
            assert jet.state.actions == []
            refused_for_another(client, device)
    finally:
        jet.stop()


def test_an_export_carries_the_jetkvms_number_and_a_file_of_0_2_0_gives_it_the_number_it_kept(tmp_path: Path) -> None:
    jet = jetkvm_a()
    try:
        with wall(tmp_path / "wall") as client:
            add(client, jet.url, name="Bench")
            made = client.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
            assert made.status_code == 200, made.text
            file = made.text
        written = json.loads(file)
        entry = written["devices"][0] if "devices" in written else written["parts"]["devices"][0]
        assert (entry["machine"], entry["ident"]) == (A_MARK, A_MARK)
        # A file made by 0.2.0 has the JetKVM's number in `ident`, and none as its machine.
        entry["machine"] = ""
        with wall(tmp_path / "other") as client:
            assert client.post("/api/v1/import", json={"file": json.dumps(written), "take": ["devices"]}).json()["devices"] == 1
            assert [record.machine for record in client.core.store.devices] == [A_MARK]  # type: ignore[attr-defined]
    finally:
        jet.stop()


def test_a_tile_that_knows_no_jetkvm_takes_the_first_it_sees_and_keeps_it(tmp_path: Path) -> None:
    # A tile kept beside its twin ("own:..."), or one whose JetKVM said no number when it was added, kept none: the first one
    # seen is taken (trust on first use, as for a certificate), and kept as every change of what is saved is.
    jet = jetkvm_a()
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, jet.url)
        for name in ("qkvm.json", "qkvm.bak"):
            written = json.loads(settings_text(data / name, encoding="utf-8"))
            written["devices"][0].update(machine="", ident=f"own:{device}")
            write_settings_text(data / name, json.dumps(written), encoding="utf-8")
        with wall(data) as client:
            assert client.core.store.device(device).machine == ""  # type: ignore[attr-defined]
            wait_until(lambda: status_of(client, device)["state"] == "online", "the JetKVM was not shown", 20)
            wait_until(
                lambda: json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))["devices"][0].get("machine") == A_MARK,
                "the JetKVM's number was not kept",
                10,
            )
            another_jetkvm(jet)
            refused_for_another(client, device)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})) == (502, "another_machine")
            assert jet.state.actions == []
    finally:
        jet.stop()


def number_has_a_moment(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """The JetKVM's /device, where its number is, does not answer in time the next `left` times it is asked (a JetKVM busy
    for a moment). What comes back holds how many are left."""
    real = jetkvm.JetKvmDevice._own_number
    fail = {"left": 0}

    async def busy(self: jetkvm.JetKvmDevice, token: str | None) -> str | None:
        if fail["left"] > 0:
            fail["left"] -= 1
            raise kvm.KvmError("timeout", "Device did not respond in time", 504)
        return await real(self, token)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_own_number", busy)
    return fail


def test_a_jetkvm_whose_number_cannot_be_read_as_it_is_added_is_not_added_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second review's F4, the class 708a39b closed for Proxmox.) Its number not read just then was taken for "none": the tile
    # was added knowing no JetKVM, and took whichever answered there next on first use. Which one it is could not be told: it is
    # not added (nothing taken, nothing added unknown), and the next try adds it.
    jet = jetkvm_a()
    fail = number_has_a_moment(monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            fail["left"] = 1
            first = client.post("/api/v1/devices", json={"url": jet.url, "password": "secret"})
            assert (first.status_code, first.json()["code"]) == (422, "timeout"), first.text
            assert "could not be told" in first.json()["message"] and client.core.store.devices == []  # type: ignore[attr-defined]
            device = add(client, jet.url)
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
    finally:
        jet.stop()


def test_an_edit_with_the_password_typed_while_the_number_cannot_be_read_keeps_the_jetkvm_it_was_for(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Whoever types the password takes the JetKVM that answers now: which one that is could not be read, and the edit saved the
    # tile with no number at all; then the next JetKVM to answer there was taken on first use, and its power held. Refused now,
    # with the number kept; "Save anyway" keeps it too.
    jet = jetkvm_a()
    fail = number_has_a_moment(monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url, name="Bench")
            edit = f"/api/v1/devices/{device}"
            fail["left"] = 1
            refused = client.put(edit, json={"name": "Bench", "url": jet.url, "password": "secret"})
            assert (refused.status_code, refused.json()["code"]) == (422, "timeout"), refused.text
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            fail["left"] = 1
            anyway = client.put(edit, json={"name": "Bench", "url": jet.url, "password": "secret", "force": True})
            assert anyway.status_code == 200 and client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            another_jetkvm(jet)
            refused_for_another(client, device)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
            assert jet.state.actions == []
    finally:
        jet.stop()


# --- following a JetKVM onto HTTPS: only where what answers there is that JetKVM (server.moved) ------------------------
# A JetKVM on the wall over plain HTTP is asked now and then whether it offers HTTPS by now, and its tile goes there when it
# does. What answered at the HTTPS address was trusted on first contact and never asked which it is: a gateway whose port
# for A's HTTPS led to B had tile A taken over by B, B's certificate remembered for A, and with one password for both, the
# keys typed at A's tile landing on B's computer (the desktop's item 6, the web review's finding 3).

C_NUMBER = "5a7c9e1b3d5f7092"


def not_followed(caplog: pytest.LogCaptureFixture) -> bool:
    return any("what answers there is not followed" in line.getMessage() for line in caplog.records if line.levelno == logging.WARNING)


@pytest.mark.parametrize("same_password", [False, True], ids=["passwords of their own", "one password"])
def test_a_plain_jetkvm_is_not_followed_onto_https_that_shows_another_tiles_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, same_password: bool
) -> None:
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    caplog.set_level(logging.INFO, logger="qkvm")
    state_a = JetState(password="secret-of-a", device_id=A_NUMBER, colour=(200, 0, 0))
    state_b = JetState(password="secret-of-a" if same_password else "secret-of-b", device_id=B_NUMBER, colour=(0, 0, 200))
    a = FakeJetKvm(state_a).start()
    b1 = FakeJetKvm(state_b, tls_dir=tmp_path / "b").start()
    b2 = FakeJetKvm(state_b, tls_dir=tmp_path / "b").start()  # B at a second address: the same JetKVM, the same certificate
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password=state_a.password, name="A")
            add(client, b1.url, password=state_b.password, name="B")
            logins_b = state_b.logins
            other_ways(monkeypatch, {a.url: b2.url})  # A's HTTPS port leads to B
            wait_until(lambda: (client.get("/api/v1/status"), not_followed(caplog))[1], "the wall never looked at A's HTTPS address", 20)
            assert any("shows the certificate of B" in line.getMessage() for line in caplog.records)
            assert (saved(client, tile_a)["url"], saved(client, tile_a)["fingerprint"]) == (a.url, None)
            assert state_b.logins == logins_b  # (the certificate was looked at first: B was not sent A's password)
            assert not [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "device_moved"]
            typed_a, typed_b = len(state_a.typed), len(state_b.typed)
            assert client.post(f"/api/v1/devices/{tile_a}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
            assert (len(state_a.typed) - typed_a, len(state_b.typed) - typed_b) == (1, 0)
    finally:
        for fake in (a, b1, b2):
            fake.stop()


def test_a_plain_jetkvm_is_not_followed_onto_https_where_another_jetkvm_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A JetKVM that is on no tile answers at A's HTTPS address, with a certificate of its own and the same password: its
    # sign-in is all it is sent (it gives its number for that alone), and the tile stays where it was.
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    caplog.set_level(logging.INFO, logger="qkvm")
    a = FakeJetKvm(JetState(device_id=A_NUMBER)).start()
    state_c = JetState(device_id=C_NUMBER)
    c = FakeJetKvm(state_c, tls_dir=tmp_path / "c").start()
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, name="A")
            other_ways(monkeypatch, {a.url: c.url})
            wait_until(lambda: (client.get("/api/v1/status"), not_followed(caplog))[1], "the wall never looked at A's HTTPS address", 20)
            assert any("Another JetKVM answers at this address" in line.getMessage() for line in caplog.records)
            assert (saved(client, tile_a)["url"], saved(client, tile_a)["fingerprint"]) == (a.url, None)
            assert client.core.store.device(tile_a).machine == A_MARK  # type: ignore[attr-defined]
            assert (state_c.sessions, state_c.video_offers, state_c.typed, state_c.actions) == (0, [], [], [])
            assert set(state_c.passwords_over) <= {"https"}
            assert client.post(f"/api/v1/devices/{tile_a}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
            assert state_c.typed == []
    finally:
        a.stop()
        c.stop()


def test_a_tile_that_knows_no_number_is_not_followed_onto_https_where_another_tile_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # (A tile whose JetKVM said no number when it was added, or one from a file without it: what answers at its HTTPS address
    # would be taken on first use. Not where it says it is another tile's JetKVM, whatever certificate it shows there.)
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    caplog.set_level(logging.INFO, logger="qkvm")
    state_b = JetState(device_id=B_NUMBER)
    a = FakeJetKvm(JetState(device_id=A_NUMBER)).start()
    b1 = FakeJetKvm(state_b, tls_dir=tmp_path / "b").start()
    b2 = FakeJetKvm(state_b, tls_dir=tmp_path / "b-again").start()  # B again, behind a gateway that shows a certificate of its own
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, name="A")
            add(client, b1.url, name="B")
            record = client.core.store.device(tile_a)  # type: ignore[attr-defined]
            record.machine = record.ident = ""
            other_ways(monkeypatch, {a.url: b2.url})
            wait_until(lambda: (client.get("/api/v1/status"), not_followed(caplog))[1], "the wall never looked at A's HTTPS address", 20)
            assert any("it says it is B" in line.getMessage() for line in caplog.records)
            assert saved(client, tile_a)["url"] == a.url and (state_b.typed, state_b.actions) == ([], [])
    finally:
        for fake in (a, b1, b2):
            fake.stop()


# --- an edit of a plain JetKVM, which takes it to its HTTPS address where it offers it (server.parse, update_device) -------
# An edit signs in again, with the password typed or the one saved, and for a JetKVM at a plain address it first asks whether
# it offers HTTPS by now and goes there. That road had none of the checks the tile's own move has (the second review's F1):
# the saved password went to whatever showed another tile's certificate there, and with the password typed the tile became
# that other tile's JetKVM, its keys going to B's computer.


def a_and_b_behind_a_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, password: str = "fleet") -> tuple[FakeJetKvm, FakeJetKvm, FakeJetKvm]:
    """JetKVM A on plain HTTP; JetKVM B over HTTPS at b1, and again at b2 (a gateway forwarding A's HTTPS port to B): the same
    certificate. One password for both, as a fleet often has. A's HTTPS address leads to b2."""
    a = FakeJetKvm(JetState(password=password, device_id=A_NUMBER, extension="atx-power", colour=(200, 0, 0))).start()
    state_b = JetState(password=password, device_id=B_NUMBER, extension="atx-power", colour=(0, 0, 200))
    b1 = FakeJetKvm(state_b, tls_dir=tmp_path / "b").start()
    b2 = FakeJetKvm(state_b, tls_dir=tmp_path / "b").start()
    return a, b1, b2


@pytest.mark.parametrize("typed", ["", "fleet"], ids=["password not typed", "password typed"])
def test_an_edit_does_not_take_a_plain_jetkvm_onto_https_where_another_tiles_certificate_is_shown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, typed: str
) -> None:
    a, b1, b2 = a_and_b_behind_a_gateway(tmp_path, monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="fleet", name="A")
            tile_b = add(client, b1.url, password="fleet", name="B")
            other_ways(monkeypatch, {a.url: b2.url})
            logins_b = b1.state.logins
            edit = client.put(f"/api/v1/devices/{tile_a}", json={"name": "A renamed", "url": a.url, "password": typed})
            assert edit.status_code == 200, edit.text  # (made at the plain address typed, as it stands)
            assert "not followed" in edit.json().get("note", "").lower() and "certificate of B" in edit.json()["note"]
            record = client.core.store.device(tile_a)  # type: ignore[attr-defined]
            assert (record.url, record.name, record.machine) == (a.url, "A renamed", A_MARK)
            assert record.machine != client.core.store.device(tile_b).machine  # type: ignore[attr-defined]
            assert b1.state.logins == logins_b  # (B was looked at by its certificate, and sent no password)
            typed_a, typed_b = len(a.state.typed), len(b1.state.typed)
            assert client.post(f"/api/v1/devices/{tile_a}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
            assert (len(a.state.typed) - typed_a, len(b1.state.typed) - typed_b) == (1, 0)
            changed = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "device_changed"]
            assert changed and "not followed" in changed[0].get("note", "").lower(), changed
    finally:
        for fake in (a, b1, b2):
            fake.stop()


def test_an_edit_typed_with_the_https_address_of_another_tiles_jetkvm_is_refused_in_true_words(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Typed by the person: refused, and said of the address typed, not "Another JetKVM answers at this address" of A's.)
    a, b1, b2 = a_and_b_behind_a_gateway(tmp_path, monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="fleet", name="A")
            add(client, b1.url, password="fleet", name="B")
            other_ways(monkeypatch, {a.url: b2.url})
            logins_b = b1.state.logins
            refused = client.put(f"/api/v1/devices/{tile_a}", json={"name": "A", "url": b2.url, "password": ""})
            assert (refused.status_code, refused.json()["code"]) == (422, "another_machine"), refused.text
            message = refused.json()["message"]
            assert b2.url in message and "certificate of B" in message and "Another JetKVM answers at this address" not in message, message
            assert client.core.store.device(tile_a).url == a.url and b1.state.logins == logins_b  # type: ignore[attr-defined]
    finally:
        for fake in (a, b1, b2):
            fake.stop()


def certificate_not_seen(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one handshake onto_https makes to look at the certificate gets no answer (a port that drops one connection)."""
    from qkvm import server

    async def no_answer(url: str) -> str:
        raise kvm.KvmError("unreachable", "Could not connect to the device")

    monkeypatch.setattr(server, "fetch_certificate", no_answer)


@pytest.mark.parametrize("typed", ["", "fleet"], ids=["password not typed", "password typed"])
def test_saved_without_checking_where_https_could_not_be_checked_it_stays_at_the_plain_address_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, typed: str
) -> None:
    # The JetKVM/Proxmox review (F1, review-jet2\probes\probe_f1_save_anyway_skips_the_https_checks.py): where onto_https
    # ended in a KvmError, "Save without checking" (and "Keep both", which sends force too) fell through to an unchecked
    # connect at the HTTPS address: trust on first use, no comparison with other tiles' certificates, the number taken from
    # what answers, no twin refused. Tile A became B's JetKVM (its keys went to B), or B was sent A's saved password. Now
    # a forced save there is made at the plain address typed, as where what answers is not followed.
    a, b1, b2 = a_and_b_behind_a_gateway(tmp_path, monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="fleet", name="A")
            tile_b = add(client, b1.url, password="fleet", name="B")
            other_ways(monkeypatch, {a.url: b2.url})
            certificate_not_seen(monkeypatch)
            logins_b = b1.state.logins
            edit = client.put(f"/api/v1/devices/{tile_a}", json={"name": "A", "url": a.url, "password": typed, "force": True})
            assert edit.status_code == 200, edit.text
            assert "not followed" in edit.json().get("note", "").lower(), edit.text
            record = client.core.store.device(tile_a)  # type: ignore[attr-defined]
            assert (record.url, record.machine, record.cert_pem) == (a.url, A_MARK, None)
            assert record.machine != client.core.store.device(tile_b).machine and b1.state.logins == logins_b  # type: ignore[attr-defined]
            typed_a, typed_b = len(a.state.typed), len(b1.state.typed)
            assert client.post(f"/api/v1/devices/{tile_a}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
            assert (len(a.state.typed) - typed_a, len(b1.state.typed) - typed_b) == (1, 0)
    finally:
        for fake in (a, b1, b2):
            fake.stop()


def test_saved_without_checking_with_the_https_address_typed_where_that_could_not_be_checked_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    a, b1, b2 = a_and_b_behind_a_gateway(tmp_path, monkeypatch)
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="fleet", name="A")
            add(client, b1.url, password="fleet", name="B")
            other_ways(monkeypatch, {a.url: b2.url})
            certificate_not_seen(monkeypatch)
            logins_b = b1.state.logins
            refused = client.put(f"/api/v1/devices/{tile_a}", json={"name": "A", "url": b2.url, "password": "fleet", "force": True, "keep_both": True})
            assert refused.status_code == 422 and b2.url in refused.json()["message"], refused.text
            record = client.core.store.device(tile_a)  # type: ignore[attr-defined]
            assert (record.url, record.machine) == (a.url, A_MARK) and b1.state.logins == logins_b
    finally:
        for fake in (a, b1, b2):
            fake.stop()


def test_an_edit_does_not_take_a_plain_jetkvm_onto_https_where_another_jetkvm_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A JetKVM on no tile answers at A's HTTPS address, with a certificate of its own and the same password: asked which it is
    # (its sign-in is what it is sent for that), it is not followed; the edit is made at A's plain address.
    a = FakeJetKvm(JetState(password="fleet", device_id=A_NUMBER)).start()
    state_c = JetState(password="fleet", device_id=C_NUMBER)
    c = FakeJetKvm(state_c, tls_dir=tmp_path / "c").start()
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="fleet", name="A")
            other_ways(monkeypatch, {a.url: c.url})
            edit = client.put(f"/api/v1/devices/{tile_a}", json={"name": "A", "url": a.url, "password": "fleet"})
            assert edit.status_code == 200 and "another number" in edit.json().get("note", ""), edit.text
            record = client.core.store.device(tile_a)  # type: ignore[attr-defined]
            assert (record.url, record.machine) == (a.url, A_MARK)
            assert (state_c.sessions, state_c.typed, state_c.actions) == (0, [], [])
    finally:
        a.stop()
        c.stop()


@pytest.mark.parametrize("where", ["another JetKVM on no tile", "tile B behind a gateway"])
def test_a_jetkvm_without_a_password_is_not_left_for_whatever_asks_for_one_at_its_https_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, where: str
) -> None:
    # (The second review's F2.) A tile without a password went to whatever asked for a password at its HTTPS address ("it asks
    # for one now, and none is saved: nothing could be sent"): true, and it left a healthy JetKVM, which still let anybody in at
    # its plain address, for another device; "Update login" with the fleet password then made it that one's. Its own JetKVM
    # says its number to anybody at the plain address: where it still does, its owner switched no password on, and the tile
    # stays. (Where the plain address asks for a password too, it goes: test_jetkvm.py, a password switched on after it was
    # added plain.)
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    caplog.set_level(logging.INFO, logger="qkvm")
    state_a = JetState(password="", device_id=A_NUMBER)
    state_c = JetState(password="fleet", device_id=B_NUMBER)
    a = FakeJetKvm(state_a).start()
    c = FakeJetKvm(state_c, tls_dir=tmp_path / "c").start()
    b1 = FakeJetKvm(state_c, tls_dir=tmp_path / "b1").start() if where == "tile B behind a gateway" else None
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, password="", name="A")
            if b1 is not None:
                add(client, b1.url, password="fleet", name="B")
            wait_until(lambda: status_of(client, tile_a)["state"] == "online", "A was never shown", 20)
            other_ways(monkeypatch, {a.url: c.url})
            wait_until(lambda: (client.get("/api/v1/status"), not_followed(caplog))[1], "the wall never looked at A's HTTPS address", 20)
            assert any("lets anybody in at its plain address" in line.getMessage() for line in caplog.records)
            assert saved(client, tile_a)["url"] == a.url and status_of(client, tile_a)["state"] == "online"
            if b1 is None:  # (where it is tile B's, B's own tile signs in to it and connects, as ever)
                assert state_c.passwords_over == [] and state_c.sessions == 0
    finally:
        for fake in (a, c, b1):
            if fake is not None:
                fake.stop()


def test_a_move_refused_after_signing_in_does_not_sign_in_again_at_every_round(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # (The second review's F5.) Another JetKVM at a tile's HTTPS address is told apart only once signed in to, and each sign-in
    # signs out every browser on its own page (a JetKVM has one session). Asked again at every round (ten minutes), the move
    # signed in again each time. While that address shows the certificate refused last, it is not signed in to again.
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.3)
    caplog.set_level(logging.INFO, logger="qkvm")
    a = FakeJetKvm(JetState(device_id=A_NUMBER)).start()
    state_c = JetState(device_id=C_NUMBER)
    c = FakeJetKvm(state_c, tls_dir=tmp_path / "c").start()
    try:
        with wall(tmp_path / "wall") as client:
            tile_a = add(client, a.url, name="A")
            other_ways(monkeypatch, {a.url: c.url})
            wait_until(lambda: (client.get("/api/v1/status"), not_followed(caplog))[1], "the wall never looked at A's HTTPS address", 20)
            state_c.token = "the session of somebody at its own page"
            first = state_c.logins
            until = time.monotonic() + 4  # (a dozen rounds)
            while time.monotonic() < until:
                client.get("/api/v1/status")
                client.get(snap(tile_a))
                time.sleep(0.2)
            assert state_c.logins == first and state_c.token == "the session of somebody at its own page", state_c.logins - first
            assert saved(client, tile_a)["url"] == a.url
    finally:
        a.stop()
        c.stop()


@pytest.mark.parametrize("who", ["another JetKVM", "its own JetKVM"])
def test_a_jetkvm_without_a_password_is_told_apart_before_the_saved_password_goes(tmp_path: Path, who: str) -> None:
    # (The second review's F3.) A tile with a password, after a restart of the wall (no session kept), and at its address a JetKVM
    # without a password: the saved password went to it over plain HTTP, in the clear, before its number was asked, though a
    # JetKVM without a password says its number to anybody. Asked first now: another one is sent nothing, and the tile's own
    # (its owner switched its password off) is asked for no session at all.
    jet = jetkvm_a(password="secret-of-a")
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, jet.url, password="secret-of-a")
        jet.state.password, jet.state.token = "", None
        if who == "another JetKVM":
            jet.state.device_id = B_NUMBER
        jet.state.passwords_over.clear()
        with wall(data) as client:
            if who == "another JetKVM":
                refused_for_another(client, device)
                assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
                assert jet.state.actions == []
            else:
                wait_until(lambda: status_of(client, device)["state"] == "online", "its own JetKVM was not shown", 20)
                assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}).status_code == 200
            assert jet.state.passwords_over == []  # (the saved password went nowhere)
    finally:
        jet.stop()


def test_a_tile_without_a_password_says_that_the_jetkvm_at_its_address_asks_for_one_and_may_be_another(tmp_path: Path) -> None:
    # (The second review's F8.) A tile without a password, its number known, and after a new lease another JetKVM with a password
    # at its address: the tile said "This JetKVM asks for a password", and "Update login" with the fleet password took the other
    # one with nothing said. It says that the JetKVM there may be another one now; and an edit that takes a JetKVM with another
    # number than the one the tile knew says so in the activity log.
    jet = jetkvm_a(password="")
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url, password="")
            wait_until(lambda: status_of(client, device)["state"] == "online", "the JetKVM was never shown", 20)
            jet.drop()
            jet.state.device_id, jet.state.password, jet.state.token = B_NUMBER, "fleet", None
            wait_until(lambda: (status_of(client, device).get("error") or {}).get("code") == "no_password", "the tile never said that a password is asked for", 20)
            status = status_of(client, device)
            assert status["state"] == "auth" and "may be another JetKVM" in status["error"]["message"], status
            taken = client.put(f"/api/v1/devices/{device}", json={"name": "Bench", "url": jet.url, "password": "fleet"})
            assert taken.status_code == 200 and client.core.store.device(device).machine == B_MARK  # type: ignore[attr-defined]
            changed = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "device_changed"]
            assert changed and "another" in changed[0].get("note", ""), changed
    finally:
        jet.stop()
