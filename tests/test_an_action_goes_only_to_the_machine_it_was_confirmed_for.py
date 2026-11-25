"""An action goes to the machine it was confirmed for, or nowhere (the outside review of 0.4.0, H3).

A tile keeps its id when an admin points it at another machine: an operator who was shown "Power off rack 1" a moment
before sent that button, by the same id, to whatever the tile was at by the time it arrived. The tile's view says which
machine it is at (`target`), the page sends that with what it was confirmed for, and the wall refuses it, nothing sent,
where the tile is at another machine by then (409 `machine_changed`). A script that sends no `target` acts as before.
The same for a live line: a pass asked for the machine seen, and a pass given before an edit, open no line to the machine
put in its place.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from websockets.exceptions import ConnectionClosed

from qkvm import kvm
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Viewer, Wall, a_jpeg, fast, pytestmark  # noqa: F401  (the fixture, and what is said of a line held open)
from tests.test_users import account, browser
from tests.test_wall import PASSWORD, add, wait_until, wall


@pytest.fixture
def two() -> Iterator[list[FakeKvm]]:
    """Two stand-in KVMs, each with a power board: the machine a tile is at, and the one an edit puts in its place."""
    made = [FakeKvm(FakeState(atx=True)).start(), FakeKvm(FakeState(atx=True, hostname="mail")).start()]
    yield made
    for fake in made:
        fake.stop()


def tile_of(client: Any, device: str) -> dict[str, Any]:
    return next(shown for shown in client.get("/api/v1/wall").json()["devices"] if shown["id"] == device)


def pointed_at(admin: Any, device: str, url: str, name: str = "rack 1") -> None:
    """An admin's edit that puts another machine under the tile, its password typed (as another address wants)."""
    reply = admin.put(f"/api/v1/devices/{device}", json={"name": name, "url": url, "username": "admin", "password": "secret"})
    assert reply.status_code == 200, reply.text


def test_each_tile_says_the_machine_it_is_at_and_only_another_machine_changes_it(tmp_path: Path, two: list[FakeKvm]) -> None:
    first, second = two
    with wall(tmp_path) as admin:
        device = add(admin, first.url, name="rack 1")
        account(admin, "victor", "viewer")
        seen = tile_of(admin, device)["target"]
        assert isinstance(seen, str) and len(seen) == 32
        assert tile_of(browser(admin, "victor"), device)["target"] == seen  # (to whoever may see the tile: nothing secret in it)
        assert first.url not in seen and "secret" not in str(tile_of(admin, device))
        pointed_at(admin, device, first.url, name="Rack 1, renamed")  # the same machine, named otherwise
        assert tile_of(admin, device)["target"] == seen
        pointed_at(admin, device, second.url)
        moved = tile_of(admin, device)["target"]
        assert moved != seen
        kept = admin.put(f"/api/v1/devices/{device}", json={"name": "rack 1", "url": second.url, "username": "admin"})  # (its saved password)
        assert kept.json()["device"]["target"] == moved, kept.text
        pointed_at(admin, device, first.url)  # back where it was: the machine it was at, and its mark, again
        assert tile_of(admin, device)["target"] == seen


def test_each_status_says_the_machine_it_was_found_at(tmp_path: Path, two: list[FakeKvm], monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2's narrow look, HIGH 6.) The status was keyed by the tile's id alone: a page that still had the wall as it was
    # before an edit took the status of the machine put under the tile (its ports; a KVM of one input) under the old one's name,
    # and once the edit was taken back the old one's `target` was good again for what the page then offered. Each row says the
    # machine it was found at, as the wall's view of the tile says it, taken with the connection that was asked.
    first, second = two
    with wall(tmp_path) as admin:
        device = add(admin, first.url, name="rack 1")
        account(admin, "victor", "viewer")
        seen = tile_of(admin, device)["target"]
        assert admin.get("/api/v1/status").json()[device]["target"] == seen
        assert browser(admin, "victor").get("/api/v1/status").json()[device]["target"] == seen  # (to whoever may see the tile)
        pointed_at(admin, device, second.url)
        moved = tile_of(admin, device)["target"]
        assert moved != seen and admin.get("/api/v1/status").json()[device]["target"] == moved
        pointed_at(admin, device, first.url)  # taken back: the first machine's mark again
        assert admin.get("/api/v1/status").json()[device]["target"] == seen

        # Asked of the first machine's connection, and answered only after an edit put the second machine under the tile: the
        # row is the first machine's, and says so (not the mark the tile has by the time it is answered).
        plain = kvm.KvmDevice.status
        hold, entered, gate = [True], threading.Event(), threading.Event()

        async def held(self: kvm.KvmDevice) -> dict[str, Any]:
            found = await plain(self)
            if hold[0] and self.spec.id == device:
                hold[0] = False
                entered.set()
                while not gate.is_set():
                    await asyncio.sleep(0.01)
            return found

        monkeypatch.setattr(kvm.KvmDevice, "status", held)
        answers: list[Any] = []
        asking = threading.Thread(target=lambda: answers.append(admin.get("/api/v1/status")))
        asking.start()
        try:
            assert entered.wait(15), "the status was never asked of the first machine"
            pointed_at(admin, device, second.url)
        finally:
            gate.set()
            asking.join(30)
        assert answers and answers[0].status_code == 200, answers
        assert answers[0].json()[device]["target"] == seen != tile_of(admin, device)["target"]


ACTIONS = {
    "keys": {"action": "keys", "keys": "ControlLeft,AltLeft,Delete"},
    "text": {"action": "text", "text": "shutdown -h now", "enter": True},
    "power": {"action": "atx_power_long"},
    "a bulk run's":{"action": "keys", "keys": "MetaLeft,KeyL", "batch": "run-1"},
}


@pytest.mark.parametrize("what", [*ACTIONS, "saved"])
def test_an_action_confirmed_for_one_machine_is_not_sent_to_the_one_put_in_its_place(tmp_path: Path, two: list[FakeKvm], what: str) -> None:
    first, second = two
    with wall(tmp_path) as admin:
        device = add(admin, first.url, name="rack 1")
        account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        if what == "saved":
            saved = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
            body: dict[str, Any] = {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}
        else:
            body = dict(ACTIONS[what])
        seen = tile_of(olga, device)  # what her confirmation named: rack 1, at the first KVM
        pointed_at(admin, device, second.url)  # and meanwhile an admin puts another machine under the tile
        refused = olga.post(f"/api/v1/devices/{device}/actions", json={**body, "target": seen["target"]})
        said = refused.json()
        assert (refused.status_code, said["code"]) == (409, "machine_changed"), refused.text
        assert "rack 1" in said["message"] and "Nothing was sent" in said["message"] and "look at it again" in said["message"]
        assert first.state.actions == [] and second.state.actions == [], (first.state.actions, second.state.actions)
        # Looked at again, and confirmed for the machine it is at now: it goes there.
        again = olga.post(f"/api/v1/devices/{device}/actions", json={**body, "target": tile_of(olga, device)["target"]})
        assert again.status_code == 200, again.text
        assert len(second.state.actions) == 1 and first.state.actions == []


def test_keys_and_text_seen_for_one_input_go_nowhere_once_another_computer_is_on_screen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 re-check, R2.) A KVM with several inputs is one tile for several computers, and the one lit is the one
    # its keys and text go to. They went to whichever was on screen when they arrived: switched at the KVM's own buttons
    # meanwhile, another computer had them. They name the input seen now (`input`), and go nowhere where qKVM saw another.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(atx=True, ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            saved = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
            sends = [ACTIONS["keys"], ACTIONS["text"], {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}]

            def on_screen() -> int | None:
                return (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active")

            wait_until(lambda: on_screen() == 0, "the wall never saw the first input")
            switch.state.active_port = 1  # (switched at the KVM itself)
            wait_until(lambda: on_screen() == 1, "the wall never saw the other input")
            for body in sends:
                refused = admin.post(act, json={**body, "input": 0})
                said = refused.json()
                assert (refused.status_code, said.get("code")) == (409, "input_changed"), (refused.text, switch.state.actions)
                assert "rack 1" in said["message"] and "Nothing was sent" in said["message"], said
            assert switch.state.actions == []
            for body in sends:  # (named as it is on screen now: sent)
                assert admin.post(act, json={**body, "input": 1}).status_code == 200
            assert len(switch.state.actions) == 3
            # Power is the KVM's own, whichever computer is on screen; and a client that names no input acts as before.
            assert admin.post(act, json={"action": "atx_power_long", "input": 0}).status_code == 200
            assert admin.post(act, json={"action": "keys", "keys": "ShiftLeft"}).status_code == 200
            # Switched by qKVM, the input it put on screen is the one known from then on.
            assert admin.post(act, json={"action": "port", "port": 0}).status_code == 200
            assert admin.post(act, json={"action": "keys", "keys": "ShiftLeft", "input": 0}).status_code == 200
            assert len(switch.state.actions) == 7
    finally:
        switch.stop()


def test_keys_go_only_where_the_kvm_itself_says_the_input_named_is_on_screen_as_they_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The owner's design for a KVM with several inputs; the outside review 6.2 second re-check, H4 and H5.) What qKVM saw at its last
    # look, or as it switched the KVM itself, can be older than a switch at the KVM's own buttons: keys and text, by every
    # spelling that sends keys, go only where the KVM itself, asked right before they go, says the input named is on screen.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)  # (the wall's last look stays as it was: only the KVM itself knows of the switch)
    switch = FakeKvm(FakeState(atx=True, ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            saved = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
            sends = [ACTIONS["keys"], ACTIONS["text"], {"action": "ctrl_alt_del"}, {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}]
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            switch.state.active_port = 1  # (switched at the KVM itself, after the wall's last look)
            for body in sends:
                refused = admin.post(act, json={**body, "input": 0})
                said = refused.json()
                assert (refused.status_code, said.get("code")) == (409, "input_changed"), (body, refused.text, switch.state.actions)
                assert "rack 1" in said["message"] and "input 2 is on screen" in said["message"] and "Nothing was sent" in said["message"], said
            assert switch.state.actions == []
            for body in sends:  # (named as the KVM has it, whatever the wall's last look said: sent)
                assert admin.post(act, json={**body, "input": 1}).status_code == 200, body
            assert len(switch.state.actions) == 4
            # Where the KVM does not say which input is on screen, nothing goes either.
            switch.state.switch_fails = 1
            unknown = admin.post(act, json={**ACTIONS["keys"], "input": 1})
            said = unknown.json()
            assert (unknown.status_code, said.get("code")) == (409, "input_changed"), unknown.text
            assert "could not tell" in said["message"] and "Nothing was sent" in said["message"], said
            assert len(switch.state.actions) == 4
            # Power is the KVM's own, and a request that names no input (a client before 0.4.0) acts as before: the KVM is
            # not asked which input is on screen for either.
            asked = sum(1 for one in list(switch.state.asked) if one == "GET /api/switch")
            assert admin.post(act, json={"action": "atx_power_long", "input": 0}).status_code == 200
            assert admin.post(act, json={"action": "keys", "keys": "ShiftLeft"}).status_code == 200
            assert sum(1 for one in list(switch.state.asked) if one == "GET /api/switch") == asked
            assert len(switch.state.actions) == 6
    finally:
        switch.stop()


def test_the_input_is_read_after_signing_in_again_right_before_the_keys_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (H4, its second part.) The KVM forgot qKVM's session, and somebody switched it at its own buttons while qKVM signed in
    # again: the input it was asked for before the sign-in is no witness of the computer the keys reach after it.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            switch.state.tokens.clear()  # (the KVM restarted, say: qKVM signs in again at its next request)
            switch.state.slow_login = 2.0
            logins = switch.state.logins
            answers: list[Any] = []
            sending = threading.Thread(target=lambda: answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={**ACTIONS["keys"], "input": 0})))
            sending.start()
            wait_until(lambda: switch.state.logins > logins, "qKVM never signed in again")
            switch.state.active_port = 1  # (switched at the KVM while qKVM was signing in)
            sending.join(30)
            assert answers, "the action was never answered"
            said = answers[0].json()
            assert (answers[0].status_code, said.get("code")) == (409, "input_changed"), (answers[0].text, switch.state.actions)
            assert switch.state.actions == []
    finally:
        switch.stop()


@pytest.mark.parametrize("kind", ["keys", "text", "ctrl_alt_del", "saved keys", "saved text"])
def test_the_input_is_read_again_where_the_keys_own_request_has_qkvm_sign_in_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    # (The outside review 6.2 third re-check, its correctness half: the probe that checks the input is not judged only before
    # the first try of the keys' own request.) The KVM answers the keys' request itself that qKVM is to sign in again, and is
    # switched at its own buttons meanwhile: the input is read again after that sign-in, and the keys go nowhere. Each spelling
    # that sends keys: switch, keys (401), sign-in, switch, and no second try of the keys.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    send, login = kvm.KvmDevice._send, kvm.KvmDevice._login
    first_post = True
    trace: list[tuple[str, str, int]] = []

    async def dispatch(self: kvm.KvmDevice, client: Any, request: Any, limit: int, within: float | None = None) -> Any:
        nonlocal first_post
        path = request.url.path
        if path == "/api/switch" or (request.method == "POST" and path.startswith("/api/hid/")):
            trace.append((request.method, path, switch.state.active_port))
        if request.method == "POST" and path.startswith("/api/hid/") and first_post:
            first_post = False
            return httpx.Response(401, request=request)
        return await send(self, client, request, limit, within)

    async def sign_in(self: kvm.KvmDevice) -> str:
        if not first_post:
            switch.state.active_port = 1  # (switched at the KVM while qKVM signs in again)
            trace.append(("login", "", 1))
        return await login(self)

    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            if kind.startswith("saved"):
                kept = {"kind": "keys", "keys": "ShiftLeft"} if kind.endswith("keys") else {"kind": "text", "text": "desk label"}
                saved = admin.post("/api/v1/actions", json={"name": "Sample", **kept}).json()["action"]
                body: dict[str, Any] = {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}
            else:
                body = {"action": kind, "keys": "ShiftLeft", "text": "desk label"}
            monkeypatch.setattr(kvm.KvmDevice, "_send", dispatch)
            monkeypatch.setattr(kvm.KvmDevice, "_login", sign_in)
            act = f"/api/v1/devices/{device}/actions"
            refused = admin.post(act, json={**body, "input": 0})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), (refused.text, trace)
            assert [one[0] for one in trace] == ["GET", "POST", "login", "GET"], trace
            assert trace[-1][2] == 1 and switch.state.actions == []
            trace.clear()
            assert admin.post(act, json={**body, "input": 1}).status_code == 200
            assert [one[0] for one in trace] == ["GET", "POST"] and len(switch.state.actions) == 1, trace
    finally:
        switch.stop()


def test_a_kvm_that_has_shown_several_inputs_says_so_while_its_switch_does_not_answer_and_is_asked_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (H3.) One answer of its switch that was no yes (a 502 while kvmd restarts), and it was taken for a KVM of one input for
    # ten minutes: `ports` null and nothing to say it has several, so the page offered keys that named no input, and they
    # went to whichever computer was on screen. It says so apart from which input is on, and its switch is asked again.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch, desk = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start(), FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            device, single = add(admin, switch.url, name="rack 1"), add(admin, desk.url, name="desk")

            def status(of: str) -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[of])

            wait_until(lambda: (status(device).get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            assert status(device)["several_inputs"] is True
            assert "several_inputs" not in status(single)  # (a KVM of one input: as before)
            switch.state.switch_fails = 1
            wait_until(lambda: status(device)["ports"] is None, "its switch's 502 was never seen")
            assert status(device)["several_inputs"] is True
            wait_until(lambda: status(device)["ports"] is not None, "its switch was not asked again at the next look")
    finally:
        switch.stop()
        desk.stop()


def test_a_kvm_whose_switch_lists_several_inputs_and_not_which_is_on_screen_says_it_has_several(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 third re-check, H3.) Its switch listed two inputs and said none of them is on screen: that was taken for a
    # KVM of one input, `ports` null and nothing to say it has several, and the page offered keys that named no input. It says
    # it has several; which one is on screen is not known, and keys that name one go nowhere.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)], active_port=-1)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "it never answered a look")
            status = admin.get("/api/v1/status").json()[device]
            assert "GET /api/switch" in list(switch.state.asked)
            assert (status["ports"], status.get("several_inputs")) == (None, True), status
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**ACTIONS["keys"], "input": 0})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            assert switch.state.actions == []
    finally:
        switch.stop()


@pytest.mark.parametrize("active", [0, 5, None])
def test_the_read_right_before_keys_go_says_the_kvm_has_several_inputs_and_none_known_where_it_names_none(active: int | None, monkeypatch: pytest.MonkeyPatch) -> None:
    # (H3.) The KVM's switch, asked right before keys went, listed two inputs: where that was the first answer of its switch
    # (the looks' went unanswered), nothing remembered that it has several. Where it named an input it has not got, or none,
    # which one is on screen is not known: refused, and what the status says of the input it last named goes too.
    device = kvm.KvmDevice(kvm.DeviceSpec("rack", "rack 1", "http://127.0.0.1:9", "admin", "secret", tls="system"))
    device._status = {"state": "online", "error": None, "ports": {"active": 0, "list": [{"name": "", "signal": True}] * 2}}

    async def switch_only(method: str, path: str, **given: Any) -> httpx.Response:
        assert (method, path) == ("GET", "/api/switch")
        state = {"model": {"ports": [{}, {}]}, "summary": {} if active is None else {"active_port": active}}
        return httpx.Response(200, json={"ok": True, "result": state})

    monkeypatch.setattr(device, "_request", switch_only)

    async def asked() -> None:
        try:
            if active == 0:
                await device._input_still(0)
            else:
                with pytest.raises(kvm.KvmError) as refused:
                    await device._input_still(0)
                assert refused.value.code == "input_changed"
                assert device._status["ports"] is None
        finally:
            await device.close()

    asyncio.run(asked())
    assert device.several_inputs()


def test_a_kvm_that_has_shown_several_inputs_says_so_after_the_wall_was_locked_and_opened_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (H3, the bugs round of the same re-check.) Started locked, the wall locks as the last person signs out, and its clients
    # of the KVMs are closed. Opened again while the KVM's switch did not answer, the client made anew knew nothing of its
    # inputs: a KVM of one input, and the page offered keys that named none. What it has shown stays known while qKVM runs.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path, locked_start=True) as admin:
            device = add(admin, switch.url, name="rack 1")

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: status().get("several_inputs") is True, "the wall never heard from its switch")
            assert admin.post("/api/v1/logout", json={}).status_code == 200
            assert not admin.core.vault.unlocked  # type: ignore[attr-defined]
            switch.state.switch_fails = 10**6
            assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            wait_until(lambda: status()["state"] == "online", "no look after signing in again")
            after = status()
            assert (after["ports"], after.get("several_inputs")) == (None, True), after
    finally:
        switch.stop()


def test_where_the_read_right_before_keys_goes_unanswered_the_status_says_no_input_is_known(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The bugs round of the third re-check, LOW.) Refused because the KVM's switch did not answer right before the keys went,
    # the status fetched again at once still said the input of the last look, and the page offered keys for it again.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: (status().get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            switch.state.switch_fails = 10**6
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**ACTIONS["keys"], "input": 0})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            assert switch.state.actions == []
            after = status()
            assert (after["ports"], after.get("several_inputs")) == (None, True), after
    finally:
        switch.stop()


def test_keys_sent_as_for_a_kvm_of_one_input_go_nowhere_where_it_has_several(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 narrow look at the third re-check's fixes, HIGH 5 and the MEDIUM on a failed first contact.) A page that
    # took a KVM for one of a single input (an older status, a failed first contact) sent keys naming no input, and they went
    # to whichever computer was on screen. It says so now (`one_input`), and the wall holds it to that: refused, nothing sent,
    # where it knows the KVM has several, or the KVM's switch, asked right before they go, lists several.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)  # (no look of the wall's comes between: what is known is what this test made so)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)], switch_fails=10**6)).start()
    desk, stock = FakeKvm(FakeState()).start(), FakeKvm(FakeState(stock=True)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            saved = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
            sends = [ACTIONS["keys"], ACTIONS["text"], {"action": "ctrl_alt_del"}, {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}]
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "it never answered a look")
            assert "several_inputs" not in admin.get("/api/v1/status").json()[device]  # (its switch never answered: one input, as far as is known)
            switch.state.switch_fails = 0  # (and answers now, right before the keys go)
            for body in sends:
                refused = admin.post(act, json={**body, "one_input": True})
                said = refused.json()
                assert (refused.status_code, said.get("code")) == (409, "input_changed"), (body, refused.text, switch.state.actions)
                assert "rack 1 has several inputs" in said["message"] and "Nothing was sent" in said["message"], said
            assert switch.state.actions == []
            assert admin.get("/api/v1/status").json()[device]["several_inputs"] is True
            # Known by now to have several: refused before its switch is asked again, also while that does not answer.
            switch.state.switch_fails = 10**6
            asked = sum(1 for one in list(switch.state.asked) if one == "GET /api/switch")
            refused = admin.post(act, json={**ACTIONS["keys"], "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            assert sum(1 for one in list(switch.state.asked) if one == "GET /api/switch") == asked and switch.state.actions == []
            # Both at once say two things: refused, nothing sent. Neither, as a script before 0.4.0 sends: as before.
            switch.state.switch_fails = 0
            assert admin.post(act, json={**ACTIONS["keys"], "input": 0, "one_input": True}).status_code == 422
            assert switch.state.actions == []
            assert admin.post(act, json={**ACTIONS["keys"]}).status_code == 200 and len(switch.state.actions) == 1
            # A KVM of one input, without a switch (its route says it is not there) or with an empty one (stock kvmd): sent.
            for fake, name in ((desk, "desk"), (stock, "stock")):
                single = add(admin, fake.url, name=name)
                for body in sends:
                    sent = admin.post(f"/api/v1/devices/{single}/actions", json={**body, "one_input": True})
                    assert sent.status_code == 200, (name, body, sent.text)
                assert len(fake.state.actions) == len(sends), (name, fake.state.actions)
    finally:
        for fake in (switch, desk, stock):
            fake.stop()


def test_the_activity_log_says_which_input_keys_were_for_and_the_keys_the_wall_refused_before_they_went(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The supervised key test on a real KVM of four inputs, 2026-11-23.) Keys sent as for a KVM of one input, refused on what the
    # wall knew of its inputs (409 `input_changed`), were in no activity log, where the KVM's own refusal was; and a key action
    # that went did not say the input it was for. Each refusal is in it as an action that failed, in its words; each key action
    # that went says the input it named, as people count them, or that it was sent as for a KVM of one input. Never the text.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    desk = FakeKvm(FakeState()).start()
    typed = "hunter2 is not a password"
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            single = add(admin, desk.url, name="desk")
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("several_inputs") is True, "the wall never saw its inputs")
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"]["active"] == 0, "the wall never saw the first input")

            def logged() -> list[dict[str, Any]]:
                return [e for e in admin.get("/api/v1/audit").json()["entries"][::-1] if e["event"] in ("action", "action_failed")]

            assert admin.post(act, json={**ACTIONS["keys"], "input": 0}).status_code == 200
            assert admin.post(act, json={"action": "text", "text": typed, "input": 0}).status_code == 200
            assert admin.post(act, json={**ACTIONS["keys"], "input": 1}).json()["code"] == "input_changed"  # (the KVM's own word)
            one = admin.post(act, json={**ACTIONS["keys"], "one_input": True})
            assert (one.status_code, one.json()["code"]) == (409, "input_changed"), one.text  # (the wall's own knowledge)
            assert admin.post(act, json={**ACTIONS["keys"], "input": 0, "one_input": True}).status_code == 422  # (asked wrong: not an action)
            assert admin.post(act, json={**ACTIONS["keys"]}).status_code == 200  # (neither, as a script before 0.4.0)
            assert admin.post(f"/api/v1/devices/{single}/actions", json={**ACTIONS["keys"], "one_input": True}).status_code == 200
            assert len(switch.state.actions) == 3 and len(desk.state.actions) == 1, (switch.state.actions, desk.state.actions)  # (what went)
            seen =[(e["event"], e.get("device"), e["action"], e.get("input"), e.get("one_input"), e.get("error")) for e in logged()]
            refusal = one.json()["message"]
            assert [row[:5] for row in seen] == [
                ("action", "rack 1", "keys", 1, None),
                ("action", "rack 1", "text", 1, None),
                ("action_failed", "rack 1", "keys", 2, None),
                ("action_failed", "rack 1", "keys", None, True),
                ("action", "rack 1", "keys", None, None),
                ("action", "desk", "keys", None, True),
            ], seen
            assert seen[2][5] and "input 1 is on screen" in seen[2][5] and seen[3][5] == refusal, seen
            assert typed not in str(admin.get("/api/v1/audit").json())  # (how long it was, not what)
    finally:
        switch.stop()
        desk.stop()


def test_keys_sent_as_for_one_input_are_refused_in_words_that_say_what_the_wall_knows_of_the_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of Builder HB's round, L3.) Refused on what the wall knew, keys sent as for a KVM of one input were said to go to "a
    # KVM that has several inputs" also where its inputs were not known at the moment (its switch did not answer the last look,
    # and the status said `several_inputs` with no `ports`). The words say what is known: several inputs, or maybe several.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("list"), "the wall never saw its inputs")
            known = admin.post(act, json={**ACTIONS["keys"], "one_input": True})
            assert (known.status_code, known.json()["code"]) == (409, "input_changed"), known.text
            assert "rack 1 has several inputs" in known.json()["message"] and "may have" not in known.json()["message"]
            switch.state.switch_fails = 10**6  # (its switch answers no more: the status says several_inputs and no ports)
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("ports", "") is None, "the status never lost its ports")
            assert admin.get("/api/v1/status").json()[device]["several_inputs"] is True
            unknown = admin.post(act, json={**ACTIONS["keys"], "one_input": True})
            said = unknown.json()
            assert (unknown.status_code, said["code"]) == (409, "input_changed"), unknown.text
            assert "rack 1 has several inputs, or may have (qKVM does not know at the moment how many)" in said["message"], said["message"]
            assert "Nothing was sent" in said["message"]
            assert switch.state.actions == []
    finally:
        switch.stop()


def test_a_machine_with_no_inputs_to_choose_from_takes_keys_sent_as_for_one_input(tmp_path: Path) -> None:
    # (HIGH 5.) A JetKVM, a PC with Intel AMT, a server, Proxmox and a VNC server have no inputs to choose from: keys sent as
    # for one of a single input go there, as the page sends them now with every keyboard action; naming an input is refused.
    from tests.fake_vnc import FakeVnc, VncState

    server = FakeVnc(VncState(width=160, height=100)).start()
    try:
        with wall(tmp_path) as admin:
            reply = admin.post("/api/v1/devices", json={"url": server.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            act = f"/api/v1/devices/{reply.json()['device']['id']}/actions"
            assert admin.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL", "one_input": True}).status_code == 200
            named = admin.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL", "input": 0})
            assert (named.status_code, named.json().get("code")) == (409, "input_changed"), named.text
            wait_until(lambda: len(server.state.keys) >= 4, "the keys never arrived")
            assert server.state.keys == [(0xFFEB, True), (0x6C, True), (0x6C, False), (0xFFEB, False)]  # (once: Super_L, l)
    finally:
        server.stop()


def test_a_pcs_kvm_switched_for_the_pc_seen_is_not_switched_on_the_one_put_in_its_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fresh review of the HA round, H1.) The switch of a PC's Intel AMT KVM went by the tile's id alone: "Switch off its KVM"
    # confirmed for Desk 7, the first PC, switched off the KVM of the PC an admin had put under the tile meanwhile. It names the PC
    # it was asked for (`target`), and is refused, nothing changed on either engine, where the tile is at another by then.
    from qkvm import amt
    from tests.fake_amt import OTHER_GUID, AmtState, FakeAmt
    from tests.test_redfish import status_of

    for name, value in (("LOOK_EVERY", 0), ("FOLLOW_UP", ()), ("HICCUP", 0), ("KVM_TTL", 0)):
        monkeypatch.setattr(amt, name, value)
    first, second = FakeAmt().start(), FakeAmt(AmtState(guid=OTHER_GUID)).start()
    try:
        with wall(tmp_path) as admin:
            device = admin.post("/api/v1/devices", json={"url": first.url, "password": "secret", "name": "Desk 7"}).json()["device"]["id"]
            status_of(admin, device, state="online")
            seen = tile_of(admin, device)["target"]
            edited = admin.put(f"/api/v1/devices/{device}", json={"name": "Desk 7", "url": second.url, "username": "admin", "password": "secret", "kind": "amt"})
            assert edited.status_code == 200 and edited.json()["device"]["target"] != seen, edited.text
            status_of(admin, device, state="online")
            route = f"/api/v1/devices/{device}/kvm"
            for on in (False, True):
                refused = admin.post(route, json={"on": on, "target": seen})
                assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
                assert "Nothing was sent" in refused.json()["message"]
            assert first.state.changes == second.state.changes == [] and second.state.kvm == "enabled"
            # Asked for the PC the tile is at now: switched there. Named for none (a script, a client before 0.4.0): as before.
            assert admin.post(route, json={"on": False, "target": edited.json()["device"]["target"]}).status_code == 200
            assert second.state.changes == [("CIM_KVMRedirectionSAP", "3")] and first.state.changes == []
            assert admin.post(route, json={"on": True}).status_code == 200 and first.state.changes == []
    finally:
        first.stop()
        second.stop()


def test_a_way_into_a_console_and_open_in_links_asked_for_the_machine_seen_go_nowhere_once_its_tile_is_at_another(tmp_path: Path) -> None:
    # (The fresh review of the HA round, L1.) A server's signed-in way into its console, and a machine's "Open in" links, went by the
    # tile's id alone: a page with the wall as it was got a way into the console of the server an edit had put under the tile,
    # and links saved for one machine landed on the other's tile. Both name the machine they were asked for (`target`).
    from tests.fake_redfish import BmcState, FakeBmc

    first, second = FakeBmc(BmcState()).start(), FakeBmc(BmcState()).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, first.url, name="rack 1")
            seen = tile_of(admin, device)["target"]
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("console") is True, "the server never said it has a console")
            assert admin.post(f"/api/v1/devices/{device}/console?target={seen}", json={}).status_code == 200  # (the machine it is at)
            pointed_at(admin, device, second.url)
            now = tile_of(admin, device)["target"]
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("console") is True, "the new server never said it has a console")
            opened = len([e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "console_opened"])
            refused = admin.post(f"/api/v1/devices/{device}/console?target={seen}", json={})
            assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
            assert len([e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "console_opened"]) == opened
            assert second.state.passes == []  # (none made out by the server put under the tile)
            links = {"meshcentral": "", "rustdesk": "123 456 789", "rdp": ""}
            refused = admin.put(f"/api/v1/devices/{device}/open-in", json={**links, "target": seen})
            assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
            assert "open_in" not in tile_of(admin, device) or not tile_of(admin, device)["open_in"]
            # For the machine it is at now, and for none (a script, a client before 0.4.0): as before.
            assert admin.post(f"/api/v1/devices/{device}/console?target={now}", json={}).status_code == 200
            assert admin.post(f"/api/v1/devices/{device}/console", json={}).status_code == 200
            assert admin.put(f"/api/v1/devices/{device}/open-in", json={**links, "target": now}).json()["open_in"] == {"rustdesk": "123456789"}
            assert admin.put(f"/api/v1/devices/{device}/open-in", json=links).status_code == 200
    finally:
        first.stop()
        second.stop()


def test_a_picture_asked_for_the_machine_seen_is_refused_once_its_tile_is_at_another(tmp_path: Path, two: list[FakeKvm]) -> None:
    # (The fresh review of the HA round, L2.) A tile's picture was asked by its id alone: a page with the wall as it was showed the
    # screen of the machine an edit had put under the tile, under the old one's name, until it fetched the wall again. A picture
    # may name the machine it is for (`target`): refused (409 `machine_changed`), nothing asked of either, where the tile is at another.
    first, second = two
    with wall(tmp_path) as admin:
        device = add(admin, first.url, name="rack 1")
        seen = tile_of(admin, device)["target"]
        wait_until(lambda: admin.get(f"/api/v1/devices/{device}/snapshot?target={seen}").status_code == 200, "no picture of the first machine")
        pointed_at(admin, device, second.url)
        now = tile_of(admin, device)["target"]
        asked = len(second.state.asked)
        refused = admin.get(f"/api/v1/devices/{device}/snapshot?target={seen}&w=640")
        assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
        assert [one for one in list(second.state.asked)[asked:] if "snapshot" in one] == []  # (no picture asked of the new one)
        wait_until(lambda: admin.get(f"/api/v1/devices/{device}/snapshot?target={now}").status_code == 200, "no picture of the machine it is at")
        assert admin.get(f"/api/v1/devices/{device}/snapshot").status_code == 200  # (none named: as before)


def test_a_certificate_shown_and_trusted_for_the_machine_seen_is_not_the_one_of_the_machine_put_in_its_place(tmp_path: Path) -> None:
    # (The second fresh review of the HA round, L2.) "Review certificate" and its Trust went by the tile's id alone: on a page with the
    # wall as it was, the box opened for one machine showed the certificate at the address of the one an edit had put under the
    # tile, under the old one's name, and Trust pinned it there. Both name the machine they were asked for (`target`).
    first, second = FakeKvm(tls_dir=tmp_path / "first").start(), FakeKvm(tls_dir=tmp_path / "second").start()
    try:
        with wall(tmp_path / "wall") as admin:
            device = add(admin, first.url, name="rack 1")
            seen = tile_of(admin, device)["target"]
            assert admin.get(f"/api/v1/devices/{device}/certificate", params={"target": seen}).status_code == 200
            pointed_at(admin, device, second.url)
            now = tile_of(admin, device)["target"]
            shown = admin.get(f"/api/v1/devices/{device}/certificate").json()  # (as a client before 0.4.0 asks: as before)
            assert shown["presented"], shown
            refused = admin.get(f"/api/v1/devices/{device}/certificate", params={"target": seen})
            assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
            pinned = tile_of(admin, device)["fingerprint"]
            refused = admin.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": shown["presented"], "target": seen})
            assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
            assert tile_of(admin, device)["fingerprint"] == pinned and not [e for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "certificate_trusted"]
            assert admin.get(f"/api/v1/devices/{device}/certificate", params={"target": now}).json() == shown
            assert admin.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": shown["presented"], "target": now}).status_code == 200
    finally:
        first.stop()
        second.stop()


def test_the_computers_to_wake_listed_for_the_machine_seen_are_not_those_of_the_one_put_in_its_place(tmp_path: Path) -> None:
    # (The sweep of the second fresh review of the HA round.) The Actions menu's "Wake ..." buttons came from GET .../wol by the
    # tile's id alone: a menu of a page with the wall as it was offered the computers the other KVM wakes, under the old one's
    # name (the Wake itself names its machine, and was refused). The list names the machine it is for (`target`).
    first = FakeKvm(FakeState(wol=[{"mac": "02:00:00:00:00:01", "name": "build-01"}])).start()
    second = FakeKvm(FakeState(wol=[{"mac": "02:00:00:00:00:02", "name": "only-there"}])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, first.url, name="rack 1")
            seen = tile_of(admin, device)["target"]
            wait_until(lambda: admin.get(f"/api/v1/devices/{device}/wol", params={"target": seen}).json().get("targets"), "no computers to wake listed")
            pointed_at(admin, device, second.url)
            refused = admin.get(f"/api/v1/devices/{device}/wol", params={"target": seen})
            assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
            now = tile_of(admin, device)["target"]
            assert [t["name"] for t in admin.get(f"/api/v1/devices/{device}/wol", params={"target": now}).json()["targets"]] == ["only-there"]
            assert admin.get(f"/api/v1/devices/{device}/wol").status_code == 200  # (none named: as before)
    finally:
        first.stop()
        second.stop()


@pytest.mark.parametrize("route", ["media", "wol", "certificate", "snapshot"])
def test_an_empty_target_on_a_read_older_than_0_4_0_is_taken_as_none_as_before(tmp_path: Path, route: str) -> None:
    # (The third fresh review of the HA round, a nit.) These reads answered whatever `target=` came along before 0.4.0; an empty one
    # (a client that fills it from a field it has not got yet) was refused 422 once `target` was read. It is taken as none again.
    # (What acts, an action, a console's way in, keeps refusing an empty one: nothing goes for a machine it cannot name.)
    images = {"debian-13.iso": {"complete": True, "removable": True, "size": 700_000_000, "mod_ts": 1.0, "sha256": ""}}
    fake = FakeKvm(FakeState(msd=True, msd_images=images, wol=[{"mac": "02:00:00:00:00:01", "name": "build-01"}])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="rack 1")
            wait_until(lambda: admin.get("/api/v1/status").status_code == 200 and admin.get(f"/api/v1/devices/{device}/{route}").status_code == 200, "never answered")
            assert admin.get(f"/api/v1/devices/{device}/{route}?target=").status_code == 200
    finally:
        fake.stop()


def test_a_script_that_names_no_machine_acts_as_before(tmp_path: Path, two: list[FakeKvm]) -> None:
    first, second = two
    with wall(tmp_path) as admin:
        device = add(admin, first.url, name="rack 1")
        token = admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator"}).json()["token"]
        pointed_at(admin, device, second.url)
        script = TestClient(admin.app, client=("127.0.0.1", 50002), headers={"Authorization": f"Bearer {token}"})
        script.portal = admin.portal  # type: ignore[attr-defined]  (the same running server, not a second one)
        assert script.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
        assert second.state.actions == ["shortcut MetaLeft,KeyL"] and first.state.actions == []
        # One that names a machine is held to it, a token's as a person's.
        stale = {"action": "keys", "keys": "MetaLeft,KeyL", "target": "0" * 32}
        assert script.post(f"/api/v1/devices/{device}/actions", json=stale).json()["code"] == "machine_changed"
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "MetaLeft,KeyL", "target": ""}).status_code == 422
        assert len(second.state.actions) == 1


@pytest.fixture
def comets() -> Iterator[list[FakeKvm]]:
    """Two stand-in Comets, whose pictures are JPEG of two colours."""
    made = [FakeKvm(FakeState(picture=a_jpeg(colour), picture_type="image/jpeg")).start() for colour in ((32, 74, 135), (135, 74, 32))]
    yield made
    for fake in made:
        fake.stop()


def test_a_live_picture_asked_for_the_machine_seen_is_refused_once_its_tile_is_at_another(tmp_path: Path, comets: list[FakeKvm]) -> None:
    first, second = comets
    with Wall(tmp_path) as live:
        admin = live.browser()
        device = live.add(admin, first.url, name="rack 1")
        seen = tile_of(admin, device)["target"]
        assert admin.post(f"/api/v1/devices/{device}/live", params={"target": seen}).status_code == 200
        pointed_at(admin, device, second.url)
        refused = admin.post(f"/api/v1/devices/{device}/live", params={"target": seen})
        assert (refused.status_code, refused.json()["code"]) == (409, "machine_changed"), refused.text
        assert admin.post(f"/api/v1/devices/{device}/live", params={"target": tile_of(admin, device)["target"]}).status_code == 200
        assert admin.post(f"/api/v1/devices/{device}/live").status_code == 200  # (none named: as before)


def test_a_pass_given_before_its_tile_was_pointed_elsewhere_opens_no_line_to_the_machine_put_there(tmp_path: Path, comets: list[FakeKvm]) -> None:
    first, second = comets
    with Wall(tmp_path) as live:
        admin = live.browser()
        device = live.add(admin, first.url, name="rack 1")
        ticket = live.ticket(admin, device)  # asked while the tile was at the first Comet
        pointed_at(admin, device, second.url)
        line = Viewer(live, device, ticket)
        try:
            said = line.word()
            assert said["t"] == "bye" and said["code"] == "gone", said
            line.closed()
        except ConnectionClosed:
            raise AssertionError("closed with no word of why") from None
        finally:
            line.close()
        assert second.state.hid == [] and first.state.hid == []
        # A pass asked for now opens a line to the machine the tile is at now, and its keys go there.
        line = live.line(admin, device)
        try:
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
        finally:
            line.close()
