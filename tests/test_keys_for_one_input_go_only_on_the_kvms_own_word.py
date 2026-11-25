"""Keys go as for a KVM of one input only where kvmd itself says it has no switch (the review of Z2, M1, and what was found
beside it).

A wall knows a KVM has several inputs once its switch has listed them. Before that (a wall just started), keys sent as for a
KVM of one input (`one_input`) went wherever the switch read right before them failed in any way: kvmd restarting behind its
web server (a 502), no answer, a proxy's page. A KVM of two inputs got them on the computer on screen, and its switch was
not asked again for ten minutes. Now they go only on kvmd's own word that it has no switch: an answer of its switch that
lists fewer than two inputs, or its own word that it has none (a GLKVM of one input: UnavailableError; a kvmd from before
switches: a route its web server has not got). Anything else is refused, nothing sent, and the switch is asked again at the
next look.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm
from qkvm.store import Store
from tests.fake_kvm import FakeKvm, FakeState
from tests.settings_file import settings_text, settings_while_saved, write_settings_text
from tests.test_wall import PASSWORD, add, wait_until, wall

TWO = [(150, 80, 40), (40, 110, 130)]
KEYS = {"action": "keys", "keys": "MetaLeft,KeyL"}


def asked_switch(fake: FakeKvm) -> int:
    return sum(1 for one in list(fake.state.asked) if one == "GET /api/switch")


@pytest.mark.parametrize("reply", [
    "bad_gateway", "server_error", "proxy_not_found", "portal", "kvmd_error", "cut",
    # (The review of this round, M2: a 200 that is not the empty state of a kvmd without a switch, or that says ok false.)
    "error_at_200", "unit_found", "unit_found_not_in_step", "empty_not_in_step", "one_port",
    # (The narrow re-review of HB's third round, L4: a model that says neither its units nor its ports.)
    "bare_model",
])  # fmt: skip
def test_keys_sent_as_for_one_input_go_nowhere_where_the_switch_read_never_came_to_kvmds_own_word(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)  # (one look, then none: what is known is what that look and the keys found)
    switch = FakeKvm(FakeState(ports=TWO, switch_reply=reply)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: status()["state"] == "online", "it never answered a look")
            assert "several_inputs" not in status() and not status().get("ports")  # (no word of its switch yet: the page sends one_input)
            sent = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            said = sent.json()
            assert (sent.status_code, said.get("code")) == (409, "input_changed"), (sent.text, switch.state.actions)
            assert "could not tell" in said["message"] and "Nothing was sent" in said["message"], said
            assert switch.state.actions == []
            # No word of kvmd's is no word that it has no switch: it is asked again at the next look, and once it answers,
            # it is known to have several (it was not asked for ten minutes).
            switch.state.switch_reply = ""
            monkeypatch.setattr(kvm, "STATUS_TTL", 0)
            wait_until(lambda: status().get("several_inputs") is True, "its switch was not asked again")
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            assert switch.state.actions == []
    finally:
        switch.stop()


@pytest.mark.parametrize("reply", [
    "unavailable", "no_route", "empty",
    # (The narrow re-review of HB's second round, L3: stock kvmd's empty state as it may come, an unplugged switch's too.)
    "unplugged", "empty_without_units", "empty_without_links", "empty_without_synced",
])  # fmt: skip
def test_keys_sent_as_for_one_input_go_where_kvmd_itself_says_it_has_no_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    # A GLKVM of one input (its error object), a kvmd from before switches (its web server's own 404), stock kvmd (an empty
    # one): kvmd's own word. Sent; and its switch is not asked again at every look for a while (as before).
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    desk = FakeKvm(FakeState(switch_reply=reply, stock=reply == "empty")).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, desk.url, name="desk")

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: status()["state"] == "online" and asked_switch(desk) >= 1, "it never answered a look")
            looks = list(desk.state.asked).count("GET /api/streamer")
            wait_until(lambda: bool(status()) and list(desk.state.asked).count("GET /api/streamer") >= looks + 3, "no more looks")
            assert asked_switch(desk) == 1, list(desk.state.asked)  # (only the first look asked it)
            assert "several_inputs" not in status()
            for body in (KEYS, {"action": "text", "text": "hello"}, {"action": "ctrl_alt_del"}):
                sent = admin.post(f"/api/v1/devices/{device}/actions", json={**body, "one_input": True})
                assert sent.status_code == 200, (body, sent.text)
            assert len(desk.state.actions) == 3 and asked_switch(desk) == 4, (desk.state.actions, list(desk.state.asked))
    finally:
        desk.stop()


@pytest.mark.parametrize("kvm_of", ["one input", "two inputs"])
def test_the_switch_read_right_before_keys_go_has_a_short_wait_of_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kvm_of: str) -> None:
    # (The review of Z2, L1.) Every keyboard action to a kvmd KVM reads its switch right before the keys go. Where that route
    # hung, the action waited as long as any request to the KVM may (eight seconds and more). It has a short wait of its own,
    # and a read that does not answer within it refuses the keys, nothing sent; one that answers within it takes them.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    fake = FakeKvm(FakeState(ports=TWO if kvm_of == "two inputs" else [])).start()
    body = {**KEYS, "input": 0} if kvm_of == "two inputs" else {**KEYS, "one_input": True}
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "it never answered a look")
            fake.state.slow["/api/switch"] = 0.5  # (slow, and within the wait)
            assert admin.post(act, json=body).status_code == 200
            fake.state.slow["/api/switch"] = 10.0  # (a route that hangs)
            began = time.monotonic()
            refused = admin.post(act, json=body)
            took = time.monotonic() - began
            said = refused.json()
            assert (refused.status_code, said.get("code")) == (409, "input_changed"), refused.text
            assert "could not tell" in said["message"] and "Nothing was sent" in said["message"], said
            # (Its wait is two seconds, kvm.INPUT_READ_WAIT: the bound leaves room for a loaded machine, and is short of the
            # eight seconds any request to the KVM may wait for its next piece.)
            assert took < 6.0, f"the keys waited {took:.1f} s for the switch"
            assert fake.state.actions == ["shortcut MetaLeft,KeyL"]
    finally:
        fake.state.slow.clear()
        fake.stop()


def a_client(index: int, url: str = "") -> kvm.KvmDevice:
    return kvm.KvmDevice(kvm.DeviceSpec(str(index), f"kvm {index}", url or f"http://127.0.0.1:{20000 + index}", "admin", "secret"))


def test_what_a_kvm_has_shown_of_its_inputs_is_not_let_go_of_as_one_input_past_the_most_remembered() -> None:
    # (The outside review 6.2 narrow look, HIGH 7.) Which KVMs have shown several inputs is kept for a client made anew (the wall
    # locked and opened again), the earliest let go of past SEVERAL_MOST: a client made anew for one let go of said one input.
    first, other = a_client(0), a_client(1)
    first._saw_several()
    assert not a_client(1).several_inputs() and not other.several_inputs()  # (none let go of yet: another KVM is not said to have several)
    for index in range(2, kvm.SEVERAL_MOST + 1):
        a_client(index)._saw_several()
    first._saw_several()  # (seen again at a look: kept as the last seen, not the earliest)
    a_client(kvm.SEVERAL_MOST + 1)._saw_several()  # (one more than are kept: the one seen longest ago goes)
    assert len(kvm.SEVERAL_SEEN) == kvm.SEVERAL_MOST
    assert a_client(0)._shown_several, "one seen again was let go of as the earliest"
    for index in range(kvm.SEVERAL_MOST + 2, 2 * kvm.SEVERAL_MOST + 2):
        a_client(index)._saw_several()  # (every one of them let go of by now, the first too)
    assert first.several_inputs()  # (its own client knows)
    made_anew = a_client(0)
    assert made_anew.several_inputs() and not made_anew._shown_several  # (not known: never "one input")
    assert a_client(10**6).several_inputs()  # (nor of any KVM not kept: it may be one let go of)
    kvm.SEVERAL_SEEN.clear()
    assert not a_client(10**6).several_inputs()


def test_a_kvm_whose_inputs_are_not_known_takes_no_keys_as_for_one_input_until_kvmd_itself_says(monkeypatch: pytest.MonkeyPatch) -> None:
    # Not known (one let go of), a KVM's inputs are known again by kvmd's own word: its switch lists them, or says it has none.
    # Until then keys sent as for one input are refused, nothing sent, also where its switch does not answer.
    for index in range(1, kvm.SEVERAL_MOST + 2):
        a_client(index)._saw_several()  # (one more than are kept: the earliest let go of)
    switch, desk = FakeKvm(FakeState(ports=TWO, switch_reply="bad_gateway")).start(), FakeKvm(FakeState()).start()

    async def asked() -> None:
        two, one = a_client(0, switch.url), a_client(-1, desk.url)
        try:
            assert two.several_inputs() and one.several_inputs()
            assert await one._read_ports() is None  # (kvmd's word: a GLKVM of one input says it has no switch)
            assert not one.several_inputs()
            await one._input_still(kvm.ONE_INPUT)
            assert await two._read_ports() is None  # (no word of kvmd's)
            assert two.several_inputs()
            with pytest.raises(kvm.KvmError) as refused:
                await two._input_still(kvm.ONE_INPUT)
            assert refused.value.code == "input_changed"
            switch.state.switch_reply = ""
            assert (await two._read_ports() or {}).get("active") == 0
            assert two.several_inputs() and two._shown_several
        finally:
            await two.close()
            await one.close()

    try:
        asyncio.run(asked())
        assert switch.state.actions == [] and desk.state.actions == []
    finally:
        switch.stop()
        desk.stop()


def test_a_kvm_that_has_shown_several_inputs_is_not_taken_for_one_after_the_wall_was_locked_past_the_most_remembered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (HIGH 7.) Locked as the last person signed out, the wall's clients are closed; opened again, the client made anew knew its
    # KVM has several inputs only while that was among the SEVERAL_MOST kept. Past them, with its switch not answering, it was
    # a KVM of one input, and the page offered keys that named none.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path, locked_start=True) as admin:
            device = add(admin, switch.url, name="rack 1")

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: status().get("several_inputs") is True, "the wall never heard from its switch")
            assert admin.post("/api/v1/logout", json={}).status_code == 200
            assert not admin.core.vault.unlocked  # type: ignore[attr-defined]
            for index in range(1, kvm.SEVERAL_MOST + 1):  # (while it is locked: other KVMs seen since, as many as are kept)
                a_client(index)._saw_several()
            switch.state.switch_reply = "bad_gateway"
            assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            wait_until(lambda: status()["state"] == "online", "no look after signing in again")
            after = status()
            assert (after["ports"], after.get("several_inputs")) == (None, True), after
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            assert switch.state.actions == []
    finally:
        switch.stop()


def test_keys_naming_an_input_go_nowhere_while_the_switch_says_it_is_not_in_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 third re-check, Low "summary.synced".) kvmd's switch says whether what it says is in step with the
    # switch itself (`summary.synced`). Its active input was taken as it said it, also where it said it was not: keys named for
    # that input went to whichever computer the switch had on screen. Not in step, which input is on screen is not known.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"

            def status() -> dict[str, Any]:
                return dict(admin.get("/api/v1/status").json()[device])

            wait_until(lambda: (status().get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            assert admin.post(act, json={**KEYS, "input": 0}).status_code == 200
            switch.state.switch_synced = False
            for body in (KEYS, {"action": "text", "text": "hello"}, {"action": "ctrl_alt_del"}):
                refused = admin.post(act, json={**body, "input": 0})
                said = refused.json()
                assert (refused.status_code, said.get("code")) == (409, "input_changed"), (body, refused.text)
                assert "could not tell" in said["message"] and "Nothing was sent" in said["message"], said
            assert switch.state.actions == ["shortcut MetaLeft,KeyL"]
            assert (status()["ports"], status().get("several_inputs")) == (None, True)
            monkeypatch.setattr(kvm, "STATUS_TTL", 0)  # (and a look says the same: inputs, none known to be on screen)
            looks = list(switch.state.asked).count("GET /api/streamer")
            wait_until(lambda: bool(status()) and list(switch.state.asked).count("GET /api/streamer") > looks + 1, "no look")
            assert (status()["ports"], status().get("several_inputs")) == (None, True)
            switch.state.switch_synced = True
            wait_until(lambda: (status().get("ports") or {}).get("active") == 0, "the input in step again was not seen")
            assert admin.post(act, json={**KEYS, "input": 0}).status_code == 200
    finally:
        switch.stop()


@pytest.mark.parametrize("when", ["while its switch is read", "as its switch has answered"])
def test_keys_whose_tile_is_changed_as_its_switch_is_read_are_said_not_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str) -> None:
    # (The outside review 6.2 third re-check, MEDIUM 4.) The tile edited (or removed, or the wall locked) while the KVM's switch
    # was being read right before the keys: its client is retired, and nothing went out. That was answered and written down as
    # "it may have been done all the same" (504), and a person was told to look at the machine for keys that never left.
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            if when == "while its switch is read":
                switch.state.slow["/api/switch"] = 1.5
                asked = asked_switch(switch)
                answers: list[Any] = []
                sending = threading.Thread(target=lambda: answers.append(admin.post(act, json={**KEYS, "input": 0})))
                sending.start()
                wait_until(lambda: asked_switch(switch) > asked, "its switch was never asked")
                edited = admin.put(f"/api/v1/devices/{device}", json={"name": "rack 2", "url": switch.url, "username": "admin"})
                assert edited.status_code == 200, edited.text
                sending.join(30)
                assert answers, "the action was never answered"
                answer = answers[0]
            else:
                read = kvm.KvmDevice._switch_said

                async def then_retired(self: kvm.KvmDevice, **asked: Any) -> Any:
                    said = await read(self, **asked)
                    if kvm.INPUT_ASKED.get() is not None:
                        await self.close()  # (retired as its answer came: before anything else of this request's)
                    return said

                monkeypatch.setattr(kvm.KvmDevice, "_switch_said", then_retired)
                answer = admin.post(act, json={**KEYS, "input": 0})
            said = answer.json()
            assert (answer.status_code, said.get("code")) == (409, "input_changed"), answer.text
            assert "Nothing was sent" in said["message"] and "may have been done" not in said["message"], said
            assert switch.state.actions == []
            entry = next(one for one in admin.get("/api/v1/audit").json()["entries"] if one.get("event") == "action_failed")
            assert "Nothing was sent" in entry["error"] and "may have been done" not in entry["error"], entry
    finally:
        switch.state.slow.clear()
        switch.stop()


def test_the_switch_read_right_before_keys_waits_for_a_connection_kept_to_the_kvm_as_any_request_does() -> None:
    # (The review of this round, L2.) The read's short wait was also a second for a free one of the connections kept to the
    # KVM: where qKVM's own requests held them all for a moment (pictures of several sizes and a look, a busy KVM), keys to a
    # KVM of one input were refused for the wall's own load. It waits for one as every request does; the KVM's own answer
    # keeps its short wait.
    desk = FakeKvm(FakeState()).start()

    async def asked() -> None:
        device = kvm.KvmDevice(kvm.DeviceSpec("desk", "desk", desk.url, "admin", "secret"))
        try:
            await device._get_result("/api/streamer")  # (signed in)
            desk.state.slow["/api/info"] = 2.5
            busy = [asyncio.create_task(device._get_result("/api/info", vital=False)) for _ in range(device.LIMITS.max_connections or 8)]
            await asyncio.sleep(0.4)  # (every connection kept to it in use)
            named = kvm.INPUT_ASKED.set(kvm.ONE_INPUT)
            try:
                await device.act("keys", keys="ShiftLeft")
            finally:
                kvm.INPUT_ASKED.reset(named)
                await asyncio.gather(*busy, return_exceptions=True)
        finally:
            await device.close()

    try:
        asyncio.run(asked())
        assert desk.state.actions == ["shortcut ShiftLeft"]
    finally:
        desk.state.slow.clear()
        desk.stop()


def test_keys_whose_tile_is_removed_while_their_own_request_signs_in_are_said_not_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of this round, L1.) The keys' own request has no session (kvmd restarted, or a 401 ended it) and signs in
    # first, before the switch is read; the tile is removed meanwhile (an edit, which signs in to check, waits for that sign-in).
    # Nothing went out: that is said, as for a power button, not "it may have been done" (504).
    monkeypatch.setattr(kvm, "STATUS_TTL", 3600)
    original = kvm.KvmDevice._request

    async def without_a_session(self: kvm.KvmDevice, method: str, path: str, **asked: Any) -> Any:
        if method == "POST" and path.startswith("/api/hid/"):
            self._token = None  # (its session gone: the keys' own request signs in first)
        return await original(self, method, path, **asked)

    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 0, "the wall never saw the first input")
            monkeypatch.setattr(kvm.KvmDevice, "_request", without_a_session)
            switch.state.slow_login = 2.0
            logins = switch.state.logins
            answers: list[Any] = []
            sending = threading.Thread(target=lambda: answers.append(admin.post(act, json={**KEYS, "input": 0})))
            sending.start()
            wait_until(lambda: switch.state.logins > logins, "the keys' request never signed in")
            removed = admin.delete(f"/api/v1/devices/{device}")
            assert removed.status_code in (200, 204), removed.text
            sending.join(30)
            assert answers, "the action was never answered"
            said = answers[0].json()
            assert (answers[0].status_code, said.get("code")) == (409, "input_changed"), answers[0].text
            assert "Nothing was sent" in said["message"] and "may have been done" not in said["message"], said
            assert switch.state.actions == []
            entry = next(one for one in admin.get("/api/v1/audit").json()["entries"] if one.get("event") == "action_failed")
            assert "Nothing was sent" in entry["error"] and "may have been done" not in entry["error"], entry
    finally:
        switch.state.slow_login = 0.0
        switch.stop()


def saved_tile(data: Path, device: str) -> dict[str, Any]:
    """The tile's record as the settings hold it on disk ({} while they are being written)."""
    saved = settings_while_saved(data / "qkvm.json") or {}
    return next((one for one in saved.get("devices", []) if one.get("id") == device), {})


@pytest.mark.parametrize("reply", ["unavailable", "empty"])
def test_a_kvm_that_has_shown_several_inputs_is_known_so_after_a_restart_while_its_switch_is_not_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    # (The review of this round, M1.) What the wall learned, that a KVM has shown several inputs, was kept while the program
    # ran. Started again while kvmd's switch was not up yet (its UnavailableError; stock kvmd's empty switch, as it is before its
    # units are found), the KVM was one of a single input, and keys sent as for one went to the computer on screen. It is kept
    # with the tile's record.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("several_inputs") is True, "the wall never saw two inputs")
            wait_until(lambda: bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
        kvm.SEVERAL_SEEN.clear()  # (started again: nothing of it in memory)
        switch.state.switch_reply = reply
        with wall(tmp_path) as admin:
            wait_until(lambda: admin.get("/api/v1/status").json().get(device, {}).get("state") == "online", "no look after the start")
            status = admin.get("/api/v1/status").json()[device]
            assert (status["ports"], status.get("several_inputs")) == (None, True), status
            switch.state.active_port = 1  # (switched at the KVM's own buttons)
            act = f"/api/v1/devices/{device}/actions"
            for body in ({**KEYS, "one_input": True}, {**KEYS, "input": 0}, {**KEYS, "input": 1}):
                refused = admin.post(act, json=body)
                assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), (body, refused.text)
            assert switch.state.actions == []
    finally:
        switch.stop()


def test_what_a_kvm_has_shown_of_its_inputs_is_written_once_and_a_record_of_0_3_2_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Written with the tile's record when it is first seen, and not at every look after; a record written by 0.3.2, which has no
    # such field, loads as one that says nothing of it, and learns it again.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: bool(admin.get("/api/v1/status").json()) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
            writes: list[int] = []
            write = Store.write
            monkeypatch.setattr(Store, "write", lambda self, data: (writes.append(1), write(self, data))[1])
            looks = list(switch.state.asked).count("GET /api/switch")
            wait_until(lambda: bool(admin.get("/api/v1/status").json()) and list(switch.state.asked).count("GET /api/switch") >= looks + 5, "no more looks")
            assert writes == [], f"{len(writes)} writes of the settings while nothing changed"
        monkeypatch.setattr(Store, "write", write)
        place = tmp_path / "qkvm.json"
        saved = json.loads(settings_text(place))
        for one in saved["devices"]:
            del one["several_inputs_at"]  # (as 0.3.2 wrote a tile)
        write_settings_text(place, json.dumps(saved, indent=2))
        kvm.SEVERAL_SEEN.clear()
        with wall(tmp_path) as admin:
            assert admin.get("/api/v1/status").json()[device]["state"] in ("online", "connecting")
            wait_until(lambda: bool(admin.get("/api/v1/status").json()) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "not learned again")
    finally:
        switch.stop()


def test_a_tile_pointed_at_another_machine_keeps_nothing_of_the_inputs_the_one_before_showed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Kept with the tile only while it is at that machine: an edit that points it at another (its `target` changes) starts afresh,
    # and that is written with the edit; a KVM of one input put there takes keys as for one.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch, desk = FakeKvm(FakeState(ports=TWO)).start(), FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: bool(admin.get("/api/v1/status").json()) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
            moved = admin.put(f"/api/v1/devices/{device}", json={"name": "rack 1", "url": desk.url, "username": "admin", "password": "secret"})
            assert moved.status_code == 200, moved.text
            wait_until(lambda: saved_tile(tmp_path, device).get("url") == desk.url, "the edit was not written")
            assert saved_tile(tmp_path, device).get("several_inputs_at") == ""
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look at the KVM put there")
            assert "several_inputs" not in admin.get("/api/v1/status").json()[device]
            assert admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True}).status_code == 200
        kvm.SEVERAL_SEEN.clear()
        with wall(tmp_path) as admin:
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look after the start")
            assert "several_inputs" not in admin.get("/api/v1/status").json()[device]
            assert admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True}).status_code == 200
        assert desk.state.actions == ["shortcut MetaLeft,KeyL"] * 2 and switch.state.actions == []
    finally:
        switch.stop()
        desk.stop()


def test_the_switch_read_right_before_keys_has_its_whole_answer_within_its_short_wait_of_having_a_connection() -> None:
    # (The narrow re-review of HB's second round, L2.) Its wait for a free connection made as long as any request's, the read's
    # whole limit grew with it: a switch whose answer trickled in (each piece within the two seconds) held keys some ten
    # seconds, and they then went on a state that old. Its whole answer is to come within INPUT_READ_WAIT of having a
    # connection; else refused, nothing sent.
    desk = FakeKvm(FakeState(switch_reply="trickle")).start()
    took: list[float] = []

    async def asked() -> None:
        device = kvm.KvmDevice(kvm.DeviceSpec("desk", "desk", desk.url, "admin", "secret"))
        try:
            await device._get_result("/api/streamer")  # (signed in, a connection kept)
            named = kvm.INPUT_ASKED.set(kvm.ONE_INPUT)
            began = time.monotonic()
            try:
                with pytest.raises(kvm.KvmError) as refused:
                    await device.act("keys", keys="ShiftLeft")
            finally:
                took.append(time.monotonic() - began)
                kvm.INPUT_ASKED.reset(named)
            assert refused.value.code == "input_changed" and "Nothing was sent" in refused.value.message
        finally:
            await device.close()

    try:
        asyncio.run(asked())
        # (Two seconds of its answer; the bound leaves room for a loaded machine, and is short of the eight its answer takes.)
        assert took[0] < kvm.INPUT_READ_WAIT + 2.0, f"the keys waited {took[0]:.1f} s on the switch read"
        assert desk.state.actions == []
    finally:
        desk.state.switch_reply = ""
        desk.stop()


@pytest.mark.parametrize("how", ["its own", "with others"])
def test_a_tile_added_again_where_one_was_removed_starts_afresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # (The narrow re-review of HB's second round, M1.) A tile removed left its KVM's mark among those seen with several inputs
    # (SEVERAL_SEEN): a tile added at that address, for a KVM of one input there now, was held to several inputs for good, its
    # record marked too. A tile removed lets go of it (and nothing else is taken for not known by it).
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    switch, other = FakeKvm(FakeState(ports=TWO)).start(), FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            old = add(admin, switch.url, name="rack 1")
            beside = add(admin, other.url, name="desk")
            wait_until(lambda: admin.get("/api/v1/status").json()[old].get("several_inputs") is True, "the wall never saw two inputs")
            if how == "its own":
                assert admin.delete(f"/api/v1/devices/{old}").status_code == 200
            else:
                assert admin.post("/api/v1/devices/remove", json={"ids": [old, beside]}).status_code == 200
            assert not kvm.SEVERAL_SEEN.forgot
            switch.state.ports, switch.state.active_port = [], 0  # (another KVM, of one input, at that address)
            new = add(admin, switch.url, name="desk 2")
            wait_until(lambda: admin.get("/api/v1/status").json()[new]["state"] == "online", "no look at the new tile")
            assert "several_inputs" not in admin.get("/api/v1/status").json()[new]
            assert admin.post(f"/api/v1/devices/{new}/actions", json={**KEYS, "one_input": True}).status_code == 200
            assert saved_tile(tmp_path, new).get("several_inputs_at") == ""
        kvm.SEVERAL_SEEN.clear()
        with wall(tmp_path) as admin:
            wait_until(lambda: admin.get("/api/v1/status").json()[new]["state"] == "online", "no look after the start")
            assert admin.post(f"/api/v1/devices/{new}/actions", json={**KEYS, "one_input": True}).status_code == 200
        assert switch.state.actions == ["shortcut MetaLeft,KeyL"] * 2
    finally:
        switch.stop()
        other.stop()


def several(admin: Any, device: str) -> bool:
    return admin.get("/api/v1/status").json()[device].get("several_inputs") is True


@pytest.mark.parametrize("reply", ["unavailable", "unplugged", "empty"])
def test_what_a_kvm_showed_of_its_inputs_is_let_go_of_once_kvmd_has_said_it_has_no_switch_long_enough(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    # (The narrow re-review of HB's second round, M1.) Kept with the tile, the mark never let go: a KVM whose switch was taken
    # off, or a KVM of one input put at its address, offered no keys for good. It is let go of (the tile's record and
    # SEVERAL_SEEN) once kvmd's own word that there is no switch has held at every look for NO_SWITCH_LETS_GO (ten minutes; a
    # switch that starts takes seconds to a minute) without a break; until then keys as for one input are refused.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", 1.5, raising=False)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: several(admin, device) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
        switch.state.ports, switch.state.active_port = [], 0  # (its switch taken off)
        switch.state.switch_reply = reply if reply != "unavailable" else ""  # (a GLKVM of one input: UnavailableError)
        switch.state.stock = reply == "empty"
        kvm.SEVERAL_SEEN.clear()  # (and the wall started again)
        with wall(tmp_path) as admin:
            act = f"/api/v1/devices/{device}/actions"
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look after the start")
            began = time.monotonic()
            assert several(admin, device)
            refused = admin.post(act, json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            wait_until(lambda: not several(admin, device), "never let go of", timeout=15)
            assert time.monotonic() - began >= 1.0, "let go of before kvmd had said so long enough"
            wait_until(lambda: saved_tile(tmp_path, device).get("several_inputs_at") == "", "the tile's record still says so")
            assert admin.post(act, json={**KEYS, "one_input": True}).status_code == 200
        kvm.SEVERAL_SEEN.clear()
        with wall(tmp_path) as admin:
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look after the start")
            assert not several(admin, device)
            assert admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True}).status_code == 200
        assert switch.state.actions == ["shortcut MetaLeft,KeyL"] * 2
    finally:
        switch.stop()


@pytest.mark.parametrize("break_", ["its switch lists its inputs again", "its web server's 502"])
def test_a_switch_that_comes_back_within_that_time_keeps_what_it_showed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, break_: str) -> None:
    # A switch that starts, or kvmd that restarts, says "no switch" for a while and then lists its inputs; any look that is not
    # kvmd's word of no switch is a break, and the time starts again from the next that is.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", 3.0, raising=False)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: several(admin, device) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")

            def no_switch_for(seconds: float) -> None:
                switch.state.switch_reply = "unavailable"
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    assert several(admin, device), "let go of within the time"
                    time.sleep(0.1)

            no_switch_for(2.0)
            asked = asked_switch(switch)
            switch.state.switch_reply = "" if break_.startswith("its switch") else "bad_gateway"
            wait_until(lambda: bool(admin.get("/api/v1/status").json()) and asked_switch(switch) >= asked + 2, "no look saw it")
            no_switch_for(2.0)  # (more than the time since the first word of no switch; not since the break)
            assert bool(saved_tile(tmp_path, device).get("several_inputs_at"))
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
            wait_until(lambda: not several(admin, device), "never let go of after the break", timeout=15)
        assert switch.state.actions == []
    finally:
        switch.state.switch_reply = ""
        switch.stop()


def test_looks_further_apart_than_the_gap_are_no_word_held_without_a_break(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two looks that said "no switch" with nobody looking in between (no viewer, no alerts) are no word that it held all along.
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", 0.6, raising=False)
    monkeypatch.setattr(kvm, "NO_SWITCH_GAP", 0.3, raising=False)
    switch = FakeKvm(FakeState(ports=TWO)).start()

    async def asked() -> None:
        device = a_client(0, switch.url)
        try:
            assert await device._read_ports() is not None and device.several_inputs()
            switch.state.switch_reply = "unavailable"
            for _ in range(4):  # (1.6 s of looks 0.4 s apart: each a break)
                await asyncio.sleep(0.4)
                await device._read_ports()
                assert device.several_inputs()
            for _ in range(20):  # (looks 0.1 s apart: held without a break)
                await asyncio.sleep(0.1)
                await device._read_ports()
            assert not device.several_inputs() and kvm._several_mark(device.spec) not in kvm.SEVERAL_SEEN
        finally:
            await device.close()

    try:
        asyncio.run(asked())
    finally:
        switch.state.switch_reply = ""
        switch.stop()


def test_a_certificate_trusted_anew_at_the_same_address_keeps_what_the_kvm_showed_of_its_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The narrow re-review of HB's second round, L1.) The same KVM of two inputs, its certificate made anew (reflashed, say),
    # its switch not up yet: its certificate trusted again, the client made anew was taken for one of a single input (its mark
    # was of the certificate before), and keys sent as for one went to input 2's computer. A certificate trusted anew at the
    # same address and kind keeps the mark, fail closed (let go of only as any, by NO_SWITCH_LETS_GO), and its record says so.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    data = tmp_path / "wall"
    data.mkdir()
    first = FakeKvm(FakeState(ports=TWO), tls_dir=tmp_path / "a").start()
    second: FakeKvm | None = None
    try:
        with wall(data) as admin:
            device = add(admin, first.url, name="rack 1")
            wait_until(lambda: several(admin, device) and bool(saved_tile(data, device).get("several_inputs_at")), "the tile's record never said so", timeout=10)
            before = saved_tile(data, device)["several_inputs_at"]
            first.stop()
            second = FakeKvm(FakeState(ports=TWO, switch_reply="unavailable"), port=first.port, tls_dir=tmp_path / "b").start()
            shown = admin.get(f"/api/v1/devices/{device}/certificate").json()
            trusted = admin.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": shown["presented"]})
            assert trusted.status_code == 200, trusted.text
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look after the trust", timeout=10)
            assert several(admin, device)
            kept = saved_tile(data, device).get("several_inputs_at")
            assert kept and kept != before, "the record does not say so of the certificate trusted now"
            second.state.active_port = 1  # (switched at its own buttons)
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
        kvm.SEVERAL_SEEN.clear()
        with wall(data) as admin:
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "no look after the start", timeout=10)
            assert several(admin, device)
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={**KEYS, "one_input": True})
            assert (refused.status_code, refused.json().get("code")) == (409, "input_changed"), refused.text
        assert second.state.actions == []
    finally:
        (second or first).stop()


def test_a_tile_edited_to_another_address_leaves_nothing_for_a_new_tile_at_the_old_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The narrow re-review of HB's third round, L1.) An edit that points a tile at another address left the old address's mark
    # among those seen: a tile added at the old one, for a KVM of one input there now, was held to several inputs and marked.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    old, moved = FakeKvm(FakeState(ports=TWO)).start(), FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, old.url, name="rack 1")
            wait_until(lambda: several(admin, device), "the wall never saw two inputs")
            edited = admin.put(f"/api/v1/devices/{device}", json={"name": "rack 1", "url": moved.url, "username": "admin", "password": "secret"})
            assert edited.status_code == 200, edited.text
            old.state.ports, old.state.active_port = [], 0  # (a KVM of one input at the old address now)
            new = add(admin, old.url, name="desk")
            wait_until(lambda: admin.get("/api/v1/status").json()[new]["state"] == "online", "no look at the new tile")
            assert not several(admin, new)
            assert admin.post(f"/api/v1/devices/{new}/actions", json={**KEYS, "one_input": True}).status_code == 200
            wait_until(lambda: several(admin, device), "the tile edited lost what its own KVM showed")  # (the KVM it is at now: two inputs)
        assert old.state.actions == ["shortcut MetaLeft,KeyL"]
    finally:
        old.stop()
        moved.stop()


@pytest.mark.parametrize("named", ["input 1", "one input"])
def test_keys_whose_own_request_waits_for_a_connection_after_the_read_go_nowhere(named: str) -> None:
    # (The narrow re-review of HB's third round, M1, older than its round.) The read right before the keys says input 1 is on
    # screen; the keys' own request then waits for a free connection as long as any request may (eight seconds), the wall's
    # own requests holding them all, and the input is changed at the KVM's own buttons meanwhile: the keys reached input 2's
    # computer. They are to leave within KEYS_AFTER_READ of the read that judged them; later, refused, nothing sent.
    switch = FakeKvm(FakeState(ports=TWO if named == "input 1" else [])).start()
    seen: dict[str, Any] = {}

    async def asked() -> None:
        device = kvm.KvmDevice(kvm.DeviceSpec("0", "rack 1", switch.url, "admin", "secret"))
        try:
            await device._get_result("/api/streamer")  # (signed in)
            await device._read_ports()
            switch.state.slow["/api/info"] = 3.0
            most = device.LIMITS.max_connections or 8
            busy = [asyncio.create_task(device._get_result("/api/info", vital=False)) for _ in range(most - 1)]
            await asyncio.sleep(0.4)  # (seven of its eight connections in use)
            switch.state.slow["/api/switch"] = 0.5
            name = kvm.INPUT_ASKED.set(0 if named == "input 1" else kvm.ONE_INPUT)
            try:
                keys = asyncio.create_task(device.act("keys", keys="ShiftLeft"))
                await asyncio.sleep(0.2)  # (the switch read on the eighth)
                busy.append(asyncio.create_task(device._get_result("/api/info", vital=False)))  # (one more of the wall's own, before the keys)
                await asyncio.sleep(0.6)  # (the read has answered)
                switch.state.active_port = 1 if named == "input 1" else 0  # (switched at its own buttons)
                try:
                    await keys
                    seen["sent"] = True
                except kvm.KvmError as ex:
                    seen["refused"] = (ex.code, ex.message)
            finally:
                kvm.INPUT_ASKED.reset(name)
                await asyncio.gather(*busy, return_exceptions=True)
        finally:
            switch.state.slow.clear()
            await device.close()

    try:
        asyncio.run(asked())
        assert switch.state.actions == [], f"keys judged on a read gone old went out: {seen}"
        code, message = seen["refused"]
        assert code == "input_changed" and "Nothing was sent" in message, seen
    finally:
        switch.stop()


@pytest.mark.parametrize("how", ["a lock and unlock", "an edit of its name"])
def test_a_lock_or_an_edit_that_keeps_the_machine_does_not_start_the_ten_minutes_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # (The narrow re-review of HB's third round, L5(b).) The ten minutes of kvmd's word of no switch were counted by each client:
    # a lock (a wall used in short sessions) or an edit that keeps the machine started them again, and such a wall might never
    # let go. They are counted by the machine's mark (SEVERAL_SEEN); a restart of the program starts them again (fail closed).
    window = 3.0
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", window)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path, locked_start=True) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: several(admin, device) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
            switch.state.switch_reply = "unavailable"
            first = time.monotonic()
            until = first + 2.0
            while time.monotonic() < until:
                assert several(admin, device), "let go of within the time"
                time.sleep(0.1)
            if how == "a lock and unlock":
                assert admin.post("/api/v1/logout", json={}).status_code == 200
                assert not admin.core.vault.unlocked  # type: ignore[attr-defined]
                assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            else:
                edited = admin.put(f"/api/v1/devices/{device}", json={"name": "rack 2", "url": switch.url, "username": "admin"})
                assert edited.status_code == 200, edited.text
            after = time.monotonic()
            wait_until(lambda: not several(admin, device), "never let go of", timeout=15)
            assert time.monotonic() - first >= window - 0.3, "let go of before the time"
            assert time.monotonic() - after < window - 0.5, f"the time started again with {how}"
        assert switch.state.actions == []
    finally:
        switch.state.switch_reply = ""
        switch.stop()


def test_after_a_let_go_a_switch_plugged_in_again_is_seen_at_the_next_look(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The narrow re-review of HB's third round, L5(c).) Let go of, a KVM was asked of its switch no more for ten minutes (as one
    # of a single input): a switch plugged in again showed as one input until the first keys sent as for one were refused. For
    # an hour after a let-go its switch is asked at every look.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", 1.5)
    switch = FakeKvm(FakeState(ports=TWO)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, switch.url, name="rack 1")
            wait_until(lambda: several(admin, device) and bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the tile's record never said so")
            switch.state.switch_reply = "unplugged"
            wait_until(lambda: not several(admin, device), "never let go of", timeout=15)
            wait_until(lambda: saved_tile(tmp_path, device).get("several_inputs_at") == "", "the record still says so")
            switch.state.switch_reply, switch.state.active_port = "", 1  # (plugged in again, on input 2)
            wait_until(lambda: several(admin, device), "not seen at the next looks", timeout=5)
            wait_until(lambda: (admin.get("/api/v1/status").json()[device].get("ports") or {}).get("active") == 1, "its input on screen not said")
            wait_until(lambda: bool(saved_tile(tmp_path, device).get("several_inputs_at")), "the mark not written again")
        assert switch.state.actions == []
    finally:
        switch.state.switch_reply = ""
        switch.stop()
