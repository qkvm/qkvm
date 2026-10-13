from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import discover, jetkvm, kvm, server, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_wall import add, closed_port, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)  # tests want the real status, not "connecting"
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def jet() -> Iterator[FakeJetKvm]:
    server = FakeJetKvm().start()
    yield server
    server.stop()


def picture(client: object, device: str) -> object:
    """Ask for the tile's picture until the video connection has delivered one."""
    reply = None

    def arrived() -> bool:
        nonlocal reply
        reply = client.get(snap(device))  # type: ignore[attr-defined]
        return bool(reply.status_code == 200)

    wait_until(arrived, "the JetKVM never produced a picture", timeout=20)
    return reply


def test_jetkvm_is_recognised_and_shows_its_screen(tmp_path: Path, jet: FakeJetKvm) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": jet.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        body = reply.json()
        device = body["device"]["id"]
        assert body["device"]["kind"] == "jetkvm"
        assert body["about"] == {"model": "JetKVM", "version": "0.5.9", "hostname": None}
        assert jet.state.sessions == 0  # adding it took nobody's picture

        frame = picture(client, device)
        assert frame.content[:3] == b"\xff\xd8\xff" and frame.headers["x-kvm-signal"] == "1"  # type: ignore[attr-defined]
        status = client.get("/api/v1/status").json()[device]
        assert status["state"] == "online" and status["kind"] == "jetkvm"
        assert status["video"] == {"signal": True, "width": 640, "height": 360, "fps": 60}
        assert status["about"] == {"model": "JetKVM", "version": "0.5.9"}
        assert status["usb"] == {"keyboard": True, "mouse": True}
        small = client.get(snap(device), params={"w": 300})
        assert small.status_code == 200 and len(small.content) < len(frame.content)  # type: ignore[attr-defined]
    assert jet.state.logins == 1 and jet.state.sessions == 1  # one login, one connection, however many requests


def test_an_address_typed_without_http_still_finds_a_jetkvm(tmp_path: Path, jet: FakeJetKvm) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": f"127.0.0.1:{jet.port}", "password": "secret"})
        assert reply.status_code == 201, reply.text
        assert reply.json()["device"]["url"] == jet.url  # plain http, as the device serves it
        assert reply.json()["device"]["kind"] == "jetkvm"


def test_jetkvm_actions(tmp_path: Path, jet: FakeJetKvm) -> None:
    jet.state.wol = [{"name": "nas", "macAddress": "AA:BB:CC:DD:EE:FF"}]
    with wall(tmp_path) as client:
        device = add(client, jet.url)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "ctrl_alt_del"}).status_code == 200
        assert client.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
        assert client.post(act, json={"action": "text", "text": "Hi!", "enter": True}).status_code == 200
        assert client.post(act, json={"action": "text", "text": "café"}).status_code == 422  # not on a US keyboard
        assert client.post(act, json={"action": "jiggler_on"}).status_code == 200
        assert client.post(act, json={"action": "wol", "mac": "AA:BB:CC:DD:EE:FF"}).status_code == 200
        assert client.post(act, json={"action": "port", "port": 1}).status_code == 422
        assert client.get(f"/api/v1/devices/{device}/wol").json() == {"targets": [{"mac": "AA:BB:CC:DD:EE:FF", "name": "nas"}]}

        refused = client.post(act, json={"action": "atx_power"})
        assert refused.status_code == 502 and "ATX" in refused.json()["message"]
        jet.state.extension = "atx-power"
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200
        assert client.get("/api/v1/status").json()[device]["atx"] == {"enabled": True, "power": True, "hdd": False}
        assert client.post(act, json={"action": "reboot"}).status_code == 200
    assert jet.state.typed == [
        (0x05, [0x4C]),  # Ctrl+Alt+Del
        (0x08, [0x0F]),  # Win+L
        (0x02, [0x0B]), (0x00, [0x0C]), (0x02, [0x1E]), (0x00, [0x28]),  # H i ! Enter
    ]  # fmt: skip
    assert jet.state.actions == ["jiggler True", "wol AA:BB:CC:DD:EE:FF", "atx power-long", "reboot"]


def test_the_wall_steps_aside_for_someone_using_the_console(tmp_path: Path, jet: FakeJetKvm) -> None:
    async def open_console() -> None:
        """Someone signs in at the JetKVM's own page and looks at the screen."""
        other = jetkvm.JetKvmDevice(DeviceSpec("x", "console", jet.url, "", "secret", kind="jetkvm"))
        await other._connected()
        await asyncio.sleep(1.0)  # long enough for the device to drop the previous viewer
        await other.close()

    with wall(tmp_path) as client:
        device = add(client, jet.url)
        picture(client, device)
        asyncio.run(open_console())

        def displaced() -> bool:
            return bool(client.get("/api/v1/status").json()[device]["state"] == "busy")

        wait_until(displaced, "the wall never noticed the other viewer")
        refused = client.get(snap(device))
        assert refused.status_code == 409 and refused.json()["code"] == "in_use"
        for _ in range(5):  # ...and it stays away: coming back would throw the person out
            client.get(snap(device))
            client.get("/api/v1/status")
        assert jet.state.sessions == 2

        # "Show here": the login made at the console replaced the wall's token, so it signs in again.
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "resume"}).status_code == 200
        picture(client, device)
        assert client.get("/api/v1/status").json()[device]["state"] == "online"
    assert jet.state.sessions == 3 and jet.state.logins == 3


def test_wrong_password_and_no_password(tmp_path: Path, jet: FakeJetKvm) -> None:
    with wall(tmp_path) as client:
        wrong = client.post("/api/v1/devices", json={"url": jet.url, "password": "nope"})
        assert wrong.status_code == 422 and wrong.json()["code"] == "auth_failed"
        missing = client.post("/api/v1/devices", json={"url": jet.url})
        assert missing.status_code == 422 and missing.json()["code"] == "no_password"

        jet.state.password = ""  # the owner switched the password off
        device = add(client, jet.url, password="")
        picture(client, device)
    assert jet.state.sessions == 1


# --- over HTTPS or plain HTTP: whichever the JetKVM offers ---------------------------------------------------


def other_ways(monkeypatch: pytest.MonkeyPatch, ways: dict[str, str]) -> None:
    """Where a JetKVM's other address is. A real one's are ports 80 and 443 of one host; a stand-in's are two ports."""
    both = {**ways, **{there: here for here, there in ways.items()}}
    for module in (kvm, server, discover, jetkvm):
        monkeypatch.setattr(module, "other_way", both.get)


def saved(client: object, device: str) -> dict:
    return next(d for d in client.get("/api/v1/wall").json()["devices"] if d["id"] == device)  # type: ignore[attr-defined]


@pytest.fixture
def both_ways(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[FakeJetKvm, FakeJetKvm]]:
    """One JetKVM with its HTTPS mode on: it answers over plain HTTP, and over HTTPS beside it."""
    state = JetState()
    plain, secure = FakeJetKvm(state).start(), FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
    other_ways(monkeypatch, {plain.url: secure.url})
    yield plain, secure
    plain.stop()
    secure.stop()


def test_the_other_way_of_an_address() -> None:
    assert kvm.other_way("http://192.168.1.40") == "https://192.168.1.40" and kvm.other_way("https://jet.lan") == "http://jet.lan"
    assert kvm.other_way("http://192.168.1.40:80") == "https://192.168.1.40" and kvm.other_way("https://[fd00::7]:443") == "http://[fd00::7]"
    # A port of its own is somebody's own arrangement: where the other way would be is not known.
    assert kvm.other_way("http://192.168.1.40:8080") is None and kvm.other_way("https://kvm.example.org:8443") is None


def test_a_jetkvm_that_offers_https_is_added_over_https_whatever_was_typed(tmp_path: Path, both_ways: tuple[FakeJetKvm, FakeJetKvm]) -> None:
    # With its HTTPS mode on, a JetKVM goes on answering over plain HTTP as well. Typed with http://, or found by
    # a search, it was talked to that way for good, password and all, with HTTPS a port away.
    plain, secure = both_ways
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": plain.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]
        assert (device["url"], device["kind"]) == (secure.url, "jetkvm")
        assert device["fingerprint"] and device["tls"] == "pinned"  # the certificate of its own making is remembered, as a Comet's is
        frame = picture(client, device["id"])
        assert frame.content[:3] == b"\xff\xd8\xff"  # type: ignore[attr-defined]
        assert client.get("/api/v1/status").json()[device["id"]]["state"] == "online"


def test_an_address_typed_with_https_is_never_answered_the_plain_way(tmp_path: Path, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Out of its box a JetKVM serves plain HTTP only. Its address pasted with https:// in front was taken
    # for a KVM of another make, and refused with words about a connection. For a day it was then added the
    # plain way instead, with the password typed beside it: whoever can keep port 443 quiet for a second had
    # that password in the clear, from somebody who had typed "https". It is said, and theirs to type.
    typed = f"https://127.0.0.1:{closed_port()}"
    other_ways(monkeypatch, {typed: jet.url})
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": typed, "password": "secret"})
        assert (reply.status_code, reply.json()["code"]) == (422, "plain_only") and jet.url in reply.json()["message"]
        assert jet.state.passwords_over == [] and jet.state.logins == 0
        reply = client.post("/api/v1/devices", json={"url": jet.url, "password": "secret"})
        assert reply.status_code == 201, reply.text


def test_a_search_finds_a_jetkvm_at_its_https_address_where_it_has_one(tmp_path: Path, both_ways: tuple[FakeJetKvm, FakeJetKvm], monkeypatch: pytest.MonkeyPatch) -> None:
    plain, secure = both_ways
    monkeypatch.setattr(discover, "targets", lambda: ([discover.Target("127.0.0.1", "http://127.0.0.1:9", plain.url)], ["test network"]))
    with wall(tmp_path) as client:
        found = client.post("/api/v1/discover").json()["found"]
        assert [(entry["kind"], entry["url"]) for entry in found] == [("jetkvm", secure.url)]
        assert plain.state.logins == 0


def test_a_jetkvm_whose_https_mode_is_switched_on_later_is_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Its address on the wall was the plain one for good, and its password went on travelling in the clear.
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    state = JetState()
    plain = FakeJetKvm(state).start()
    secure = None
    try:
        with wall(tmp_path) as client:
            device = add(client, plain.url)
            picture(client, device)
            before = client.core.store.device(device)
            secure = FakeJetKvm(state, tls_dir=tmp_path / "jet").start()  # its owner turns its HTTPS mode on
            other_ways(monkeypatch, {plain.url: secure.url})
            wait_until(lambda: (client.get("/api/v1/status"), saved(client, device)["url"])[1] == secure.url, "it went on being talked to over plain HTTP")
            # (Its certificate is remembered at the first contact over HTTPS, which is a moment after the move.)
            wait_until(lambda: (client.get("/api/v1/status"), saved(client, device)["fingerprint"])[1], "its certificate was never remembered", timeout=15)
            # A new record in the old one's place, as an edit makes one: somebody who was editing the old one
            # at that moment is told that it changed under them, and does not put the plain address back.
            assert client.core.store.device(device) is not before and before.url == plain.url
            picture(client, device)
            assert client.get("/api/v1/status").json()[device]["state"] == "online"
            # The activity log says what the wall did by itself. (Written once the old connection is closed, which
            # on a slow machine is a moment after the tile is on its new address: waited for, not looked for once.)
            said = lambda: [entry for entry in client.get("/api/v1/audit").json()["entries"] if entry["event"] == "device_moved"]  # noqa: E731
            wait_until(lambda: bool(said()), "the activity log never said that it moved", timeout=15)
            moved = said()
            assert len(moved) == 1 and (moved[0]["url"], moved[0]["was"]) == (secure.url, plain.url)
    finally:
        plain.stop()
        if secure is not None:
            secure.stop()


def test_https_and_a_password_switched_on_after_it_was_added_plain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # What the owner of a real one did: it was on the wall over plain HTTP, without a password; then, at the
    # device's own page, HTTPS on and a password set. Its tile said "login failed" at the plain address, and
    # the password typed there went out in the clear before anything looked whether HTTPS was on offer.
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    state = JetState(password="")
    plain = FakeJetKvm(state).start()
    secure = None
    try:
        with wall(tmp_path) as client:
            device = add(client, plain.url, password="")
            secure = FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
            other_ways(monkeypatch, {plain.url: secure.url})
            state.password = "secret"
            # The tile moves to HTTPS by itself, and there it asks for the password it now needs.
            wait_until(lambda: (client.get("/api/v1/status"), saved(client, device)["url"])[1] == secure.url, "it was not followed to HTTPS", timeout=15)
            wait_until(lambda: client.get("/api/v1/status").json()[device].get("error", {}) is not None and (client.get("/api/v1/status").json()[device].get("error") or {}).get("code") == "no_password", "it never asked for its password", timeout=15)
            assert client.get("/api/v1/status").json()[device]["state"] == "auth"
            changed = client.put(f"/api/v1/devices/{device}", json={"url": secure.url, "password": "secret"})
            assert changed.status_code == 200, changed.text
            picture(client, device)
            assert state.passwords_over and set(state.passwords_over) == {"https"}
    finally:
        plain.stop()
        if secure is not None:
            secure.stop()


def test_a_password_typed_for_a_plain_jetkvm_goes_over_https_where_that_is_offered_by_now(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ...and the same for whoever is quicker than the wall: "Update login" at the plain address, before the
    # tile has moved. What is typed is about to be sent: where to is looked at again first.
    state = JetState(password="")
    plain = FakeJetKvm(state).start()
    secure = None
    try:
        with wall(tmp_path) as client:
            device = add(client, plain.url, password="")
            secure = FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
            other_ways(monkeypatch, {plain.url: secure.url})
            state.password = "secret"
            changed = client.put(f"/api/v1/devices/{device}", json={"url": plain.url, "password": "secret"})
            assert changed.status_code == 200, changed.text
            assert changed.json()["device"]["url"] == secure.url and changed.json()["device"]["fingerprint"]
            picture(client, device)
            assert state.passwords_over and set(state.passwords_over) == {"https"}
    finally:
        plain.stop()
        if secure is not None:
            secure.stop()


@pytest.mark.parametrize("password", ["", "secret"])
def test_a_jetkvm_whose_https_mode_is_switched_off(tmp_path: Path, both_ways: tuple[FakeJetKvm, FakeJetKvm], monkeypatch: pytest.MonkeyPatch, password: str) -> None:
    # Then it answers over plain HTTP only, and is not followed there by itself, with a password or without:
    # that it was its owner who switched HTTPS off is the word of whatever answers now, and over plain HTTP
    # nothing is checked any more. The tile says so, and a person decides.
    monkeypatch.setattr(jetkvm, "WAY_WHEN_DOWN", 0.2)
    monkeypatch.setattr(jetkvm, "WAY_PATIENCE", 0.5)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    plain, secure = both_ways
    plain.state.password = password
    with wall(tmp_path) as client:
        device = add(client, plain.url, password=password)
        assert saved(client, device)["url"] == secure.url
        logins = plain.state.logins
        mark = saved(client, device)["fingerprint"]
        secure.stop()  # its owner turns its HTTPS mode off (with nobody looking at the wall just then)
        wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "error", "it was never said why it does not answer", timeout=20)
        status = client.get("/api/v1/status").json()[device]
        assert status["error"]["code"] == "plain_only" and "plain HTTP" in status["error"]["message"] and plain.url in status["error"]["message"]
        assert ("password" in status["error"]["message"]) == bool(password)
        time.sleep(0.6)
        client.get("/api/v1/status")
        assert (saved(client, device)["url"], saved(client, device)["fingerprint"]) == (secure.url, mark)
        assert plain.state.logins == logins  # asked for nothing over plain HTTP


def test_the_certificate_remembered_for_a_jetkvm_is_not_let_go_of_by_itself(tmp_path: Path, both_ways: tuple[FakeJetKvm, FakeJetKvm], monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a review, and shown: a JetKVM without a password was followed to plain HTTP when its HTTPS went
    # quiet for two minutes, and back to HTTPS when that answered again, where the certificate shown then was
    # remembered as if it were the first. Whoever could keep one port quiet, and then answer on it, had the
    # tile: its picture theirs to make up, what is typed at it theirs to read. Nobody had been asked.
    for name, value in (("WAY_WHEN_DOWN", 0.2), ("WAY_PATIENCE", 0.5), ("WAY_EVERY", 0.2)):
        monkeypatch.setattr(jetkvm, name, value)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    plain, secure = both_ways
    plain.state.password = ""
    impostor = None
    with wall(tmp_path) as client:
        device = add(client, plain.url, password="")
        mark = saved(client, device)["fingerprint"]
        secure.stop()
        wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "error", "it was never said that only plain HTTP answers", timeout=20)
        try:
            impostor = FakeJetKvm(JetState(password=""), port=secure.port, tls_dir=tmp_path / "another").start()
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                client.get("/api/v1/status")
                client.get(snap(device))
                time.sleep(0.2)
            assert (saved(client, device)["url"], saved(client, device)["fingerprint"]) == (secure.url, mark)
            assert impostor.state.sessions == 0 and client.get(snap(device)).status_code != 200
        finally:
            if impostor is not None:
                impostor.stop()


def test_an_edit_of_a_plain_jetkvm_sends_its_saved_password_over_https_where_that_is_offered_by_now(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Any edit signs in to the device again, to see that it is still it. A new name for a JetKVM whose owner
    # had switched HTTPS on since sent the saved password over plain HTTP once more.
    state = JetState()
    plain = FakeJetKvm(state).start()
    secure = None
    try:
        with wall(tmp_path) as client:
            device = add(client, plain.url)
            state.passwords_over.clear()
            secure = FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
            other_ways(monkeypatch, {plain.url: secure.url})
            renamed = client.put(f"/api/v1/devices/{device}", json={"url": plain.url, "name": "Bench", "password": ""})
            assert renamed.status_code == 200, renamed.text
            assert (renamed.json()["device"]["url"], renamed.json()["device"]["name"]) == (secure.url, "Bench")
            picture(client, device)
            assert state.passwords_over and set(state.passwords_over) == {"https"}
    finally:
        plain.stop()
        if secure is not None:
            secure.stop()


def test_a_jetkvm_that_does_not_answer_is_still_a_jetkvm_when_its_password_is_typed_again(tmp_path: Path, jet: FakeJetKvm) -> None:
    # Looking where its password is about to go asked what it is as well, and what does not answer was taken
    # for a KVM of another make, for good.
    with wall(tmp_path) as client:
        device = add(client, jet.url)
        jet.stop()
        saved_anyway = client.put(f"/api/v1/devices/{device}", json={"url": jet.url, "password": "another", "force": True})
        assert saved_anyway.status_code == 200, saved_anyway.text
        assert (saved(client, device)["kind"], saved(client, device)["url"]) == ("jetkvm", jet.url)


def test_a_look_for_the_alerts_that_finds_it_there_forgets_that_it_was_ever_away(jet: FakeJetKvm) -> None:
    # How long it has been away was only ever reset where somebody watches. With nobody watching, one look
    # that failed days ago made the next one count as "away for more than two minutes".
    async def run() -> tuple[float | None, str | None]:
        device = jetkvm.JetKvmDevice(DeviceSpec(id="j", name="j", base_url=jet.url, username="", password="secret", kind="jetkvm"))
        device._down_since, device._plain_only = 1.0, "http://192.168.1.40"
        try:
            assert await device.probe() != "offline"
            return device._down_since, device._plain_only
        finally:
            await device.close()

    assert asyncio.run(run()) == (None, None)




def test_a_jetkvm_that_is_starting_up_is_not_taken_to_have_given_up_https(tmp_path: Path, both_ways: tuple[FakeJetKvm, FakeJetKvm], monkeypatch: pytest.MonkeyPatch) -> None:
    # It serves plain HTTP at once and HTTPS a little later, in every restart. Followed back in that moment, a
    # JetKVM without a password would be on plain HTTP for the ten minutes until it is asked again, each time.
    monkeypatch.setattr(jetkvm, "WAY_WHEN_DOWN", 0.1)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    plain, secure = both_ways
    plain.state.password = ""
    with wall(tmp_path) as client:
        device = add(client, plain.url, password="")
        secure.stop()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            client.get("/api/v1/status")
            time.sleep(0.2)
        assert saved(client, device)["url"] == secure.url


def test_one_jetkvm_under_two_addresses_is_one_device(tmp_path: Path) -> None:
    # A Comet is known again by its certificate. A JetKVM over plain HTTP shows none, and one found on the
    # network and again over the VPN was on the wall twice. It gives a number for itself.
    state = JetState()
    here, there = FakeJetKvm(state).start(), FakeJetKvm(state).start()
    other = FakeJetKvm(JetState(device_id="0123456789abcdef")).start()
    try:
        with wall(tmp_path) as client:
            first = add(client, here.url)
            again = client.post("/api/v1/devices", json={"url": there.url, "password": "secret"})
            assert again.status_code == 409 and again.json()["code"] == "same_device" and again.json()["same_as"]["id"] == first
            assert "says it is the same device" in again.json()["message"]  # its own word: a certificate proves, a number is said
            add(client, other.url)  # another JetKVM is another device
            assert here.state.device_id not in client.core.store.path.read_text(encoding="utf-8")  # kept as a digest: the number is nobody's business
    finally:
        for server_ in (here, there, other):
            server_.stop()


def test_a_jetkvm_fresh_from_its_box_is_said_to_be_that(tmp_path: Path, jet: FakeJetKvm) -> None:
    # Before anybody has chosen at its own page how it is signed in to, it lets nobody in, and the wall said
    # "check the password" about a device that has none yet.
    jet.state.setup = False
    with wall(tmp_path) as client:
        for typed in ("secret", ""):
            reply = client.post("/api/v1/devices", json={"url": jet.url, "password": typed})
            assert (reply.status_code, reply.json()["code"]) == (422, "not_set_up") and "set up" in reply.json()["message"]


def test_a_password_switched_on_at_the_jetkvm_later_is_asked_for_and_then_used(tmp_path: Path, jet: FakeJetKvm) -> None:
    jet.state.password = ""  # added while it had none
    with wall(tmp_path) as client:
        device = add(client, jet.url, password="")
        jet.state.password = "secret"  # its owner switches its authentication mode to a password
        wait_until(lambda: client.get(snap(device)).json().get("code") == "no_password", "it was never said that it asks for a password now")
        status = client.get("/api/v1/status").json()[device]
        assert status["state"] == "auth" and status["error"]["code"] == "no_password"
        changed = client.put(f"/api/v1/devices/{device}", json={"url": jet.url, "password": "secret"})
        assert changed.status_code == 200, changed.text
        picture(client, device)


def whole_png(data: bytes) -> bool:
    """Whether a PNG is one a browser shows: every part of it carries the checksum it should."""
    import struct
    import zlib

    if data[:8] != bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]):
        return False
    at, kinds = 8, []
    while at + 12 <= len(data):
        (length,) = struct.unpack(">I", data[at : at + 4])
        kind, body = data[at + 4 : at + 8], data[at + 8 : at + 8 + length]
        (said,) = struct.unpack(">I", data[at + 8 + length : at + 12 + length])
        if zlib.crc32(kind + body) != said:
            return False
        if kind == b"IDAT":
            zlib.decompress(body)
        kinds.append(kind)
        at += 12 + length
    return at == len(data) and kinds[:1] == [b"IHDR"] and kinds[-1:] == [b"IEND"] and b"IDAT" in kinds


def test_no_signal_is_reported_not_guessed(tmp_path: Path, jet: FakeJetKvm) -> None:
    jet.state.signal = False
    with wall(tmp_path) as client:
        device = add(client, jet.url)
        frame = picture(client, device)
        assert frame.headers["x-kvm-signal"] == "0"  # type: ignore[attr-defined]
        assert client.get("/api/v1/status").json()[device]["state"] == "no_signal"
        # What is sent in place of a picture has to be one a browser shows. The one that was sent had a wrong
        # checksum in it, which Chrome does not forgive: the tile of a real JetKVM whose computer was switched
        # off said "Problem: the KVM sent a picture that could not be shown" where "No signal" belonged.
        assert frame.headers["content-type"] == "image/png" and whole_png(frame.content)  # type: ignore[attr-defined]


def test_a_jetkvm_that_falls_silent_is_not_shown_as_if_it_were_live(
    tmp_path: Path, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qkvm import jetkvm

    monkeypatch.setattr(jetkvm, "FRAME_STALE", 1.0)
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 1.0)
    with wall(tmp_path) as client:
        device = add(client, jet.url)
        picture(client, device)
        assert client.get("/api/v1/status").json()[device]["state"] == "online"
        jet.state.frozen = True  # it reboots, or loses power: the video connection itself takes half a minute to notice
        began = time.monotonic()
        wait_until(lambda: client.get(snap(device)).status_code != 200, "the last picture went on being passed off as the screen")
        wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "offline", "it went on being called online", timeout=10)
        assert time.monotonic() - began < 10
        jet.state.frozen = False  # and when it is back, the wall has it again without being told
        picture(client, device)
        wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "online", "it was not called online again")
        assert client.get("/api/v1/status").json()[device]["last_seen_ago"] <= 2  # heard from just now, and says so


def test_without_the_webrtc_package_the_wall_says_what_to_install(
    tmp_path: Path, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jetkvm, "webrtc_available", lambda: False)
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": jet.url, "password": "secret"})
    assert reply.status_code == 422 and "pip install aiortc" in reply.json()["message"]


def test_a_jetkvm_is_found_when_looking_for_kvms(tmp_path: Path, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import discover

    wanted = [discover.Target("127.0.0.1", "http://127.0.0.1:9", jet.url)]
    monkeypatch.setattr(discover, "targets", lambda: (wanted, ["test network"]))
    with wall(tmp_path) as client:
        found = client.post("/api/v1/discover").json()["found"]
    assert found == [{"address": "127.0.0.1", "kind": "jetkvm", "url": jet.url, "name": "", "also": [], "known": False, "known_as": None, "known_id": None, "moved_from": None}]
    assert jet.state.logins == 0 and jet.state.sessions == 0  # looking takes nobody's picture


def test_keys_and_text_as_keyboard_reports() -> None:
    assert jetkvm.key_report("ControlLeft,AltLeft,Delete") == (0x05, [0x4C])
    assert jetkvm.key_report("ShiftRight,F12,KeyA") == (0x20, [0x45, 0x04])
    with pytest.raises(KvmError):
        jetkvm.key_report("Hyper")
    assert jetkvm.text_reports("a Z?\r\n") == [(0, [0x04]), (0, [0x2C]), (2, [0x1D]), (2, [0x38]), (0, [0x28])]


def test_answer_gets_the_addresses_that_arrive_after_it() -> None:
    answer = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:1\r\n"
    candidate = "candidate:1 1 udp 2130706431 192.168.1.50 53211 typ host"
    merged = jetkvm.with_candidates(answer, [candidate, ""])
    assert merged.count(f"a={candidate}\r\n") == 2  # once per media section
    assert merged.index("a=mid:0") < merged.index(f"a={candidate}") < merged.index("m=application")
    assert jetkvm.with_candidates(answer, []) == answer


def watched_by_the_alerts(jet: FakeJetKvm, look: object) -> None:
    """Run `look(device)` with a JetKVM that somebody had on screen a moment ago and nobody has now."""

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("x", "wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            deadline = time.monotonic() + 20
            while True:  # somebody looks at the wall
                try:
                    await device.snapshot(640)
                    break
                except KvmError:
                    assert time.monotonic() < deadline, "the JetKVM never produced a picture"
                    await asyncio.sleep(0.2)
            await device.status()
            await look(device)  # type: ignore[operator]
        finally:
            await device.close()

    asyncio.run(run())


def test_watching_over_a_jetkvm_for_alerts_does_not_hold_on_to_its_picture(jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # With alerts on, every device is looked at every fifteen seconds. For a JetKVM that somebody had on
    # screen once, each of those looks counted as somebody watching: the video connection, which costs a good
    # part of a processor and is the one viewer a JetKVM allows, was never given back.
    monkeypatch.setattr(jetkvm, "KEEPALIVE_IDLE", 1.0)

    async def look(device: jetkvm.JetKvmDevice) -> None:
        assert await device.probe() == "online"
        deadline = time.monotonic() + 8
        while device._session is not None and device._session.live:  # nobody looks any more; the watcher goes on asking
            assert time.monotonic() < deadline, "the connection was kept although nobody was looking"
            await device.probe()
            await asyncio.sleep(0.1)
        assert await device.probe() == "online"  # and the JetKVM is still known to be there
        assert jet.state.sessions == 1  # asking that did not connect to it again

    watched_by_the_alerts(jet, look)


def test_what_is_told_about_a_jetkvm_does_not_change_with_whether_somebody_is_looking(
    jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without a connection a JetKVM only says that it is there. Calling that "online" made the computer
    # behind it, switched off, lose its picture each time somebody opened the wall and get it back each
    # time they left: two alerts for nothing, every time.
    monkeypatch.setattr(jetkvm, "KEEPALIVE_IDLE", 1.0)
    jet.state.signal = False

    async def look(device: jetkvm.JetKvmDevice) -> None:
        assert await device.probe() == "no_signal"
        deadline = time.monotonic() + 8
        while device._session is not None and device._session.live:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.1)
        assert await device.probe() == "no_signal"  # nothing has been seen that says otherwise
        jet.stop()
        assert await device.probe() == "offline"  # that it is gone is seen without a connection, and told

    watched_by_the_alerts(jet, look)


def test_a_jetkvm_whose_picture_somebody_else_took_is_still_watched_over(jet: FakeJetKvm) -> None:
    # Somebody opens the JetKVM's own console: the wall steps aside and waits to be asked back. That used
    # to be the last thing the alerts ever learned about it: it could lose power days later, unnoticed.
    async def look(device: jetkvm.JetKvmDevice) -> None:
        device._displaced = True  # as when the JetKVM says another viewer has taken over
        assert await device.probe() == "busy"  # there, and in use: nothing to tell anybody
        jet.stop()
        assert await device.probe() == "offline"

    watched_by_the_alerts(jet, look)


def test_collecting_metrics_does_not_count_as_watching_either(jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # What the alerts' rounds no longer did, the collector did in their place: every look for /metrics held
    # the JetKVM's video connection, or made a new one, taking the picture from whoever had it.
    monkeypatch.setattr(jetkvm, "KEEPALIVE_IDLE", 1.0)

    async def look(device: jetkvm.JetKvmDevice) -> None:
        assert (await device.glance())["state"] == "online"
        deadline = time.monotonic() + 8
        while device._session is not None and device._session.live:
            assert time.monotonic() < deadline, "the connection was kept although only a collector was asking"
            await device.glance()
            await asyncio.sleep(0.3)
        for _ in range(3):
            said = await device.glance()
            assert said["state"] == "online" and "last_seen_ago" in said  # still known to be there
            await asyncio.sleep(0.2)
        assert jet.state.sessions == 1  # and asking did not connect to it again

    watched_by_the_alerts(jet, look)
    assert jetkvm._parse("[" * 60_000) == {}  # (a message nested too deep to read is no message, and no error)
