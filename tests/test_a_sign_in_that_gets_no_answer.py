"""A sign-in that gets no answer, and what a tile says while a wait stands.

What a second reviewer found in the fixes of the first, again by counting at a stand-in device with
real time scaled down:

* A sign-in that went out and was not answered in time, or was hung up on, was noted nowhere: once a
  wait was over the password went out at every look, every fifteen to twenty-five seconds, the tile
  saying "offline" while the device answered everything else. And a no that came later than the eight
  seconds anything is waited for was not heard as a no.
* After a no, an answer that was neither yes nor no made the wait longer, as intended, and was shown
  as what it was: the tile said "offline" for the whole of that wait (five minutes, a quarter of an
  hour, an hour), the device was not asked whether it was there, and a JetKVM over HTTPS was said to
  answer over plain HTTP only.
* The web page of a controller was counted as saying no only where it said 401 or 403.
* Where the wall held a session that the controller had forgotten, its web page was offered the
  password before the other sign-in had been told no.
* A device that answered the question "are you there" with something this program makes nothing of
  was asked again at every look.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from qkvm import jetkvm, kvm, redfish
from qkvm.kvm import DeviceSpec, KvmError
from tests import fake_jetkvm, fake_redfish
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import BmcState, FakeBmc
from tests.scripted_device import Scripted, as_json
from tests.conftest import SCALE, TICK
from tests.test_a_rejected_password_by_every_road import HALF_HOUR, HOUR, a_controller
from tests.test_jetkvm import other_ways
from tests.test_wall import closed_port, fast, wall  # noqa: F401

S = 60.0  # for the first tests here every wait of the program is a sixtieth of what it is: a minute is a second
PASSWORD = "the-saved-password-1"
WATCHED = 375 / S  # six minutes and a quarter
LATE = 12 / S  # an answer after twelve seconds: later than anything else is waited for (eight), sooner than a sign-in is (twenty)
NEVER = 60 / S  # and one after a minute: nothing is waited for that long


@pytest.fixture
def sixtieth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "LOGIN_BACKOFFS", tuple(wait / S for wait in kvm.LOGIN_BACKOFFS))
    for driver in (kvm, redfish, jetkvm):
        monkeypatch.setattr(driver, "LOGIN_RETRY", kvm.LOGIN_RETRY / S)
    for name in ("STATUS_TTL", "ERROR_HOLD", "BACKOFF_MAX", "STILL_THERE_EVERY", "TRANSFER_TIME", "STATUS_FIRST_WAIT", "UNANSWERED_MOST"):
        monkeypatch.setattr(kvm, name, getattr(kvm, name) / S)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(8.0 / S, connect=4.0 / S))
    monkeypatch.setattr(redfish, "LOOK_EVERY", redfish.LOOK_EVERY / S)
    monkeypatch.setattr(redfish, "RETRY_LOOK", redfish.RETRY_LOOK / S)


# --- a sign-in that went out, and nothing came back ---------------------------------------------------

NO = as_json(403, {})
HOW: dict[str, tuple[Any, int]] = {
    # how the device answers its sign-ins (by their number), and how often the password may go out in the time
    "a no every time": (lambda number: NO, 3),
    "a no, and from then on it hangs up": (lambda number: NO if number == 1 else "drop", 8),
    "a no, and from then on the no comes late": (lambda number: NO if number == 1 else ("after", LATE, NO), 3),
    "every no comes late": (lambda number: ("after", LATE, NO), 3),
    "a no, and from then on nothing in time": (lambda number: NO if number == 1 else ("after", NEVER, NO), 7),
    "never anything in time": (lambda number: ("after", NEVER, NO), 6),
}


def watched(device: kvm.Device, server: Scripted, sign_in: str) -> tuple[list[int], list[str]]:
    """Look at the device's tile for the time, as a wall does: (the seconds at which the password went out, what the tile said)."""
    states: list[str] = []

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < WATCHED:
                state = (await device.status())["state"]
                if not states or states[-1] != state:
                    states.append(state)
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    sent = [one for one in server.asked("POST", sign_in) if PASSWORD.encode() in one[4]]
    return [round((one[0] - sent[0][0]) * S) for one in sent], states


@pytest.mark.parametrize("kind", ["a KVM", "a server's controller"])
@pytest.mark.parametrize("how", list(HOW))
def test_a_password_is_not_sent_again_and_again_to_a_device_that_does_not_answer_its_sign_in(kind: str, how: str, sixtieth: None) -> None:
    answers, most = HOW[how]
    sign_in = redfish.SESSIONS if kind == "a server's controller" else "/api/auth/login"
    count = 0

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        nonlocal count
        if method == "POST" and path == sign_in:
            count += 1
            return answers(count)
        return as_json(401, {"ok": False})  # everything else it answers at once, as a device that is there does

    server = Scripted(answer).start()
    spec = DeviceSpec(id="ab12", name="Device", base_url=server.url, username="admin", password=PASSWORD, kind="redfish" if kind == "a server's controller" else "kvmd")
    device: kvm.Device = redfish.RedfishDevice(spec) if kind == "a server's controller" else kvm.KvmDevice(spec)
    sent, states = watched(device, server, sign_in)
    assert 2 <= len(sent) <= most, f"{how}: in six minutes the password went out at seconds {sent}; the tile said {states}"
    if how != "never anything in time":
        assert "auth" in states, states  # it said no once: that is what its owner is told, whatever came after
    else:
        # It answers everything but its sign-in: a problem, and said as one, from the first try to the last.
        # Never "offline": said so for some seconds after each try, the round that sends alerts reported it as
        # gone and as back with a problem, a pair for every try, for as long as it lasted.
        assert set(states) <= {"connecting", "error"} and "error" in states, states


def test_a_no_that_comes_late_is_heard_as_a_no(sixtieth: None) -> None:
    # Twelve seconds: anything else would have been given up on after eight, and nothing counted.
    server = Scripted(lambda method, path, head, body: ("after", LATE, NO) if path == "/api/auth/login" else as_json(401, {})).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        try:
            with pytest.raises(KvmError) as failed:
                await device._login()
            assert failed.value.code == "auth_failed"
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_what_is_kept_of_sign_ins_that_nothing_answered() -> None:
    spec = DeviceSpec(id="ab12", name="KVM", base_url="https://192.168.1.50", username="admin", password="secret")
    known = kvm.Rejected()
    what = known.what("login", spec)

    def goes_out() -> None:
        """The next sign-in: the wait that stood has passed (nothing is sent before), and it is counted as it goes."""
        if what in known._known:
            times, silent, _ = known._known[what]
            known._known[what] = (times, silent, 0.0)
        known.sent(what)

    def came_to_nothing() -> int:
        goes_out()
        return round(known.unanswered(what))

    # Not a no, and not sent at every look either: ten seconds, twice that each time, five minutes at the most.
    assert [came_to_nothing() for _ in range(8)] == [10, 20, 40, 80, 160, 300, 300, 300]
    assert known.times(what) == 0 and 290 < known.wait_left(what) <= 300 + TICK
    # The first no after them is the first no. What comes to nothing after a no is still not a no: how often
    # it was told no stays, and the short waits begin again.
    goes_out()
    assert known.said_no(what) == 60 and known.times(what) == 1
    assert [came_to_nothing(), came_to_nothing()] == [10, 20] and known.times(what) == 1
    goes_out()
    assert known.said_no(what) == 300 and known.times(what) == 2  # the next no is the second, and waits as that
    # A device that says when to come back is given that, and it counts as nothing.
    goes_out()
    assert known.later(what, 400) == 400 and known.times(what) == 2 and 390 < known.wait_left(what) <= 400 + TICK
    known.accepted(what)
    assert known.times(what) == 0 and known.wait_left(what) == 0 and came_to_nothing() == 10
    # One that goes out stands as unanswered until its answer is noted (somebody may retire the connection
    # before it comes), and one that did not go out after all leaves things as they were.
    known.accepted(what)
    first = known.sent(what)
    assert first[0] is None and 9 < known.wait_left(what) <= 10 + TICK and known.silent(what) == 1
    second = known.sent(what)
    assert known.silent(what) == 2 and 19 < known.wait_left(what) <= 20 + TICK
    known.put_back(what, second)
    assert known.silent(what) == 1 and known.wait_left(what) <= 10 + TICK
    known.put_back(what, first)
    assert known.silent(what) == 0 and known.wait_left(what) == 0
    # Only where nothing was noted since. Two connections to one device, both signing in: the one hears a
    # no, the other finds no connection to be had after that. Taking its own mark back, it took the no with
    # it, and the password went out again at once.
    one, other = known.sent(what), known.sent(what)
    known.said_no(what)
    known.put_back(what, one)
    known.put_back(what, other)
    assert known.times(what) == 1 and 50 < known.wait_left(what) <= 60 + TICK
    known.accepted(what)
    # And nothing here shortens a wait that stands: an hour stays an hour, whatever is noted in it.
    for _ in range(4):
        goes_out()
        known.said_no(what)
    assert 3590 < known.wait_left(what) <= 3600 + TICK
    assert known.unanswered(what) > 3590 and known.wait_left(what) > 3590
    assert known.later(what, 60) == 60  # (a verdict of the device's own replaces it)
    known.forget(spec)
    assert known.wait_left(what) == 0


def test_a_new_connection_does_not_send_what_the_last_one_got_no_answer_to() -> None:
    server = Scripted(lambda method, path, head, body: "drop" if path == "/api/auth/login" else as_json(401, {})).start()
    spec = DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD)

    async def run() -> None:
        first = kvm.KvmDevice(spec)
        try:
            with pytest.raises(KvmError) as failed:
                await first._login()
            assert failed.value.code == "no_sign_in"
        finally:
            await first.close()
        second = kvm.KvmDevice(spec)  # (the saved passwords locked and opened again, say)
        try:
            with pytest.raises(KvmError) as again:
                await second._login()
            assert again.value.code == "no_sign_in"  # not "login rejected": nothing said no. And not "no answer": nothing was asked
            assert len(server.asked("POST", "/api/auth/login")) == 1
        finally:
            await second.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


# --- what the tile says while a wait stands that something other than a no made longer ----------------


@pytest.mark.parametrize("answers", [("no", "yes"), ("no", 500, "yes"), ("no", "no", 502, "yes"), ("no", "drop", "yes")], ids=str)
def test_after_a_no_the_tile_goes_on_saying_that_the_login_was_rejected_whatever_the_device_says_next(answers: tuple[Any, ...], scaled: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", kvm.STILL_THERE_EVERY / SCALE)
    left, token = list(answers), "tok-abc123"
    questions: list[float] = []

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        if method == "POST" and path == "/api/auth/login":
            said = left.pop(0) if left else "yes"
            if said == "yes":
                return as_json(200, {"ok": True, "result": {"token": token}})
            return "drop" if said == "drop" else as_json(403 if said == "no" else said, {"ok": False})
        if f"auth_token={token}" in head:
            return as_json(200, {"ok": True, "result": {}})
        if "cookie:" not in head.lower():
            questions.append(time.monotonic())
        return as_json(401, {"ok": False})

    server = Scripted(answer).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))
    line: list[tuple[int, str]] = []

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < 6.0:
                state = (await device.status())["state"]
                if not line or line[-1][1] != state:
                    line.append((round((time.monotonic() - began) * SCALE), state))
                if state == "online":
                    break
                await asyncio.sleep(0.01)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    said = [state for _, state in line]
    assert said[-1] == "online", line  # set right on the device, it is back at the next try
    # Until then: that its login was rejected. Never "offline" while it answers (which an alert would have told somebody).
    allowed = {"connecting", "auth", "online"} | ({"offline"} if "drop" in answers else set())  # (hung up on, it is away for that moment)
    assert set(said) <= allowed and "auth" in said, line
    if "drop" not in answers:
        assert said[-2] == "auth", line  # "rejected" is what it says until it is let in
    if len(answers) > 2:
        assert questions, "while that longer wait stood it was not asked whether it is there"


@pytest.mark.parametrize("kind", ["a KVM", "a server's controller"])
def test_a_device_that_goes_off_while_such_a_wait_stands_is_seen_to(kind: str, scaled: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", kvm.STILL_THERE_EVERY / SCALE)
    sign_in = redfish.SESSIONS if kind == "a server's controller" else "/api/auth/login"
    gone = False
    count = 0

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        nonlocal count
        if gone:
            return "drop"  # off: whatever connects is hung up on
        if method == "POST" and path == sign_in:
            count += 1
            return as_json(401 if count == 1 else 503, {})
        return as_json(401, {})

    server = Scripted(answer).start()
    spec = DeviceSpec(id="ab12", name="Device", base_url=server.url, username="admin", password=PASSWORD, kind="redfish" if kind == "a server's controller" else "kvmd")
    device: kvm.Device = redfish.RedfishDevice(spec) if kind == "a server's controller" else kvm.KvmDevice(spec)
    before: set[str] = set()
    after: list[str] = []

    async def run() -> None:
        nonlocal gone
        began = time.monotonic()
        try:
            while time.monotonic() - began < 1.5:
                state = (await device.status())["state"]
                if gone:
                    after.append(state)
                else:
                    before.add(state)
                if count >= 2 and not gone and time.monotonic() - began > 0.5:
                    gone = True  # the machine goes off, two and a half minutes after it said no and then something else
                await asyncio.sleep(0.01)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert before <= {"connecting", "auth"}, before
    assert after and after[-1] == "offline", after[-10:]


class Odd:
    """What a stand-in does differently in a test here."""

    sign_in_says: int | None = None  # a JetKVM: what its sign-in answers, whatever the password
    web_no: Any = None  # a controller: how its web page says no to a wrong password (a status, or several taken in turn)
    web_silent_from = 0  # a controller: from this sign-in on (0: never), its web page takes longer to answer than is waited for
    web_takes = 0.0  # ...this long
    web_says: int | None = None  # a controller: what its web page answers to a sign-in, whatever the password
    web_sends_on_to = ""  # ...and where that answer sends on to, if anywhere
    token_says_once: int | None = None  # a controller: what it answers, once, when asked whether it has a console
    system_says_once: int | None = None  # ...and, once, when asked about the server with the session held
    system_path = ""  # (where that is asked)
    sign_in_takes = 0.0  # a JetKVM: how long its sign-in takes to answer


@pytest.fixture
def odd(monkeypatch: pytest.MonkeyPatch) -> Odd:
    how = Odd()
    a_jetkvm, a_bmc = fake_jetkvm.make_fake_jetkvm, fake_redfish.make_fake_bmc

    def jet(state: JetState) -> FastAPI:
        app = a_jetkvm(state)

        @app.middleware("http")
        async def differently(request: Request, call_next: Any) -> Any:
            answer = await call_next(request)
            if request.method == "POST" and request.url.path == "/auth/login-local" and how.sign_in_takes:
                await asyncio.sleep(how.sign_in_takes)
            if request.method == "POST" and request.url.path == "/auth/login-local" and how.sign_in_says is not None:
                return JSONResponse({"error": "busy with itself"}, status_code=how.sign_in_says)
            return answer

        return app

    def bmc(state: BmcState) -> FastAPI:
        app = a_bmc(state)

        @app.middleware("http")
        async def differently(request: Request, call_next: Any) -> Any:
            path = request.url.path.rstrip("/")
            if request.method == "GET" and path == "/api/kvm/token" and how.token_says_once is not None:
                status, how.token_says_once = how.token_says_once, None
                return JSONResponse({"error": "busy with itself"}, status_code=status)
            if request.method == "GET" and how.system_path and path == how.system_path and how.system_says_once is not None:
                status, how.system_says_once = how.system_says_once, None
                return JSONResponse({"error": "busy with itself"}, status_code=status)
            answer = await call_next(request)
            if request.method == "POST" and request.url.path == "/api/session" and how.web_silent_from and state.web_logins >= how.web_silent_from:
                await asyncio.sleep(how.web_takes)
            if request.method == "POST" and request.url.path == "/api/session" and how.web_says is not None:
                return JSONResponse({"error": "busy with itself"}, status_code=how.web_says, headers={"Location": how.web_sends_on_to} if how.web_sends_on_to else None)
            if request.method == "POST" and request.url.path == "/api/session" and answer.status_code == 401 and how.web_no is not None:
                status = how.web_no if isinstance(how.web_no, int) else how.web_no[(state.web_logins - 1) % len(how.web_no)]
                return JSONResponse({"cc": 7, "error": "Invalid Authentication"}, status_code=status)
            return answer

        return app

    monkeypatch.setattr(fake_jetkvm, "make_fake_jetkvm", jet)
    monkeypatch.setattr(fake_redfish, "make_fake_bmc", bmc)
    return how


def test_a_jetkvm_over_https_that_answers_one_sign_in_oddly_is_not_said_to_answer_over_plain_http_only(tmp_path: Path, odd: Odd, scaled: None, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("WAY_PATIENCE", "WAY_WHEN_DOWN", "RETRY_PAUSE"):
        monkeypatch.setattr(jetkvm, name, getattr(jetkvm, name) / SCALE)
    state = JetState()
    plain, secure = FakeJetKvm(state).start(), FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
    other_ways(monkeypatch, {plain.url: secure.url})
    try:
        with wall(tmp_path / "wall") as admin:
            state.password = "changed on the device"
            added = admin.post("/api/v1/devices", json={"url": secure.url, "password": "secret", "kind": "jetkvm", "name": "Jet", "force": True})
            assert added.status_code == 201, added.text
            device = added.json()["device"]["id"]
            line: list[tuple[int, str, str]] = []
            began = time.monotonic()
            while time.monotonic() - began < 2.5:
                status = admin.get("/api/v1/status").json()[device]
                said = (status["state"], ((status.get("error") or {}).get("message") or "")[:120])
                if not line or line[-1][1:] != said:
                    line.append((round((time.monotonic() - began) * SCALE), *said))
                odd.sign_in_says = 500 if state.logins == 1 else None  # the second sign-in, and only that one
                time.sleep(0.02)
            assert state.logins >= 2, line
            assert not [entry for entry in line if "plain HTTP" in entry[2]], line
            assert line[-1][1] == "auth" and set(state.passwords_over) == {"https"}, line
    finally:
        plain.stop()
        secure.stop()


def test_a_jetkvm_that_was_away_for_a_moment_is_not_taken_to_have_been_away_ever_since(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Away for a moment, then answering for a long while (with a no: its password had been changed), then away
    # for another moment. Since when it was away the first time was left standing through all those answers, so
    # the second moment counted as two minutes of silence and more: its other address was asked at once, and
    # one that answers there over plain HTTP was said to answer over plain HTTP only.
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(jetkvm, "WAY_PATIENCE", 0.4)
    monkeypatch.setattr(jetkvm, "WAY_WHEN_DOWN", 0.0)
    monkeypatch.setattr(jetkvm, "other_way", lambda url: "http://127.0.0.1:9")  # (it has another address to be asked at)
    state = JetState()
    state.password = "changed on the device"
    servers = [FakeJetKvm(state, tls_dir=tmp_path).start()]  # over HTTPS: one over plain HTTP is asked now and then anyway
    port = servers[0].port
    device = jetkvm.JetKvmDevice(DeviceSpec(id="ab12", name="JetKVM", base_url=servers[0].url, username="", password="secret", kind="jetkvm"))
    asked: list[str] = []

    async def moved(to: str) -> None:
        return None

    async def ask(twin: str) -> None:
        asked.append(twin)

    device.on_move = moved
    monkeypatch.setattr(device, "_ask_the_other_way", ask)

    async def run() -> None:
        try:
            assert (await device._read_status())["state"] == "auth"
            await asyncio.to_thread(servers[-1].stop)
            assert (await device._read_status())["state"] == "offline"  # away: for the first time, and not for long yet
            await asyncio.sleep(0.05)
            assert asked == []
            servers.append(FakeJetKvm(state, port=port, tls_dir=tmp_path).start())  # and back
            assert (await device._read_status())["state"] == "auth"
            await asyncio.sleep(0.6)  # (longer than the patience there is with one that is away)
            assert (await device._read_status())["state"] == "auth"
            await asyncio.to_thread(servers[-1].stop)
            assert (await device._read_status())["state"] == "offline"
            await asyncio.sleep(0.05)
            assert asked == [], "away for a moment, it was taken to have been away since the time before"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        for server in servers:
            server.stop()


# --- the web page of a controller ---------------------------------------------------------------------


@pytest.mark.parametrize("web_no", [400, 429], ids=str)
def test_however_its_web_page_says_no_the_old_password_is_not_offered_to_it_for_good(web_no: Any, odd: Odd, scaled: None) -> None:
    # 400 is a no in another number. 429 (or 409, or 500) is not about the password: too many sessions, one of
    # its moments. That is asked again every ten minutes, as it always was; taken for a no, the server's
    # screen stayed away for up to an hour after the controller was well.
    odd.web_no = web_no
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)
    offered: list[int] = []

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            server.state.password = "changed on the controller"
            server.state.web_sessions.clear()
            began = time.monotonic()
            while time.monotonic() - began < HOUR:
                status = await device.status()
                if status.get("screen") is True:
                    try:
                        await device.snapshot(640)
                    except KvmError:
                        pass
                if len(offered) != server.state.web_logins:
                    offered.append(round((time.monotonic() - began) * SCALE))
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    least, most = (2, 4) if web_no == 400 else (5, 7)
    assert least <= len(offered) <= most, f"its web page says {web_no}: the password went to it at these seconds of an hour: {offered}"


def test_a_new_connection_does_not_say_rejected_of_a_web_page_that_did_not_answer(odd: Odd, monkeypatch: pytest.MonkeyPatch) -> None:
    # Its web page took too long over one sign-in. A connection made anew in the time that is waited after
    # that sends it nothing, and says what happened: not that the login was rejected, and not for ten minutes.
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(0.4, connect=4.0))  # (a sign-in is waited for two and a half times that)
    odd.web_silent_from, odd.web_takes = 1, 2.0
    server = FakeBmc(BmcState(own_console=True)).start()

    async def refused(device: redfish.RedfishDevice) -> KvmError:
        """Ask for the picture until the console has given up on its sign-in: what it says then."""
        assert (await device.status())["state"] == "online"
        for _ in range(100):
            try:
                await device.snapshot(640)
            except KvmError:
                pass
            if device._console_refusal is not None:
                return device._console_refusal
            await asyncio.sleep(0.05)
        raise AssertionError("the console never said how its sign-in went")

    async def run() -> None:
        first = a_controller(server)
        try:
            assert (await refused(first)).code == "timeout" and server.state.web_logins == 1
        finally:
            await first.close()
        second = a_controller(server)  # (the saved passwords locked and opened again, say)
        try:
            said = await refused(second)
            assert said.code == "no_sign_in" and "rejected" not in said.message, said.message
            assert server.state.web_logins == 1  # nothing was sent to it again
            assert second._console_retry_at - time.monotonic() < redfish.CONSOLE_GIVE_UP / 2  # and it is asked again soon
        finally:
            await second.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


@pytest.mark.parametrize("once", [503, 429, 403, 408])
def test_a_controller_asked_about_its_console_at_a_bad_moment_is_asked_again(once: int, odd: Odd, scaled: None) -> None:
    # Whether it has a console was asked once, and whatever it answered but "sign in first" meant no. One 503
    # just then (or "too many requests", or "too slow"), and the server's screen was gone until QKVM was
    # started again. "No" is "there is no such thing here", and nothing else.
    odd.token_says_once = once
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            began = time.monotonic()
            while time.monotonic() - began < 3.0 and not server.state.web_logins:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.02)
            assert device._has_console is True and server.state.web_logins >= 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_one_of_its_moments_at_the_question_before_the_web_sign_in_does_not_hold_the_console_up(odd: Odd) -> None:
    # The question is there to hear a no. A 503 to it is none: taken for a failure of the console, the
    # screen came half a minute later, and after two of them a minute and a half.
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            odd.system_path, odd.system_says_once = (await device._find())["system"].rstrip("/"), 503
            began = time.monotonic()
            while time.monotonic() - began < 5.0 and not server.state.web_logins:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert odd.system_says_once is None  # (it was asked, and answered 503)
            assert server.state.web_logins == 1, "its console was not opened in five seconds"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_a_session_the_controller_has_forgotten_is_no_proof_that_it_lets_this_program_in(scaled: None) -> None:
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            # The controller restarts (every session forgotten) with another password: the wall still holds its token.
            server.state.password = "changed on the controller"
            server.state.tokens.clear()
            server.state.web_sessions.clear()
            began = time.monotonic()
            while time.monotonic() - began < HALF_HOUR:
                try:
                    await device.snapshot(640)  # the picture is asked for before the tile is next looked at
                except KvmError:
                    pass
                if time.monotonic() - began > 0.1:
                    await device.status()
                await asyncio.sleep(0.01)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert server.state.web_logins == 0, "its web page was offered the password before the other sign-in had been told no"
    assert server.state.logins <= 1 + 4, server.state.logins


# --- "are you there", answered with something this program makes nothing of ---------------------------


def test_an_answer_that_is_made_nothing_of_is_an_answer_and_the_question_is_not_asked_at_every_look(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.3)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.0)
    questions: list[float] = []

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        if method == "POST":
            return NO
        questions.append(time.monotonic())
        return 302, {"Location": "http:x"}, b""  # it points somewhere that is no address

    server = Scripted(answer).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < 1.5:
                assert (await device._read_status())["state"] == "auth"
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert 2 <= len(questions) <= 7, f"asked {len(questions)} times in a second and a half, where every third of a second is the most"


# --- only a no climbs: a device that is there, with the right password saved ---------------------------


def test_a_device_that_said_no_once_as_it_started_is_back_soon_after_it_is_well(sixtieth: None) -> None:
    # One 401 as it comes up, then 503 for six minutes and forty seconds, then well: the right password is
    # saved all the while. Each 503 counted as one more no, so it was back a quarter of an hour after it was
    # well, and an hour after had its trouble lasted a little longer.
    token, count, began = "tok-abc123", 0, [0.0]
    well_after = 400 / S

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        nonlocal count
        if method == "POST" and path == "/api/auth/login":
            count += 1
            if count == 1:
                return NO
            if time.monotonic() - began[0] < well_after:
                return as_json(503, {"ok": False})
            return as_json(200, {"ok": True, "result": {"token": token}})
        if f"auth_token={token}" in head:
            return as_json(200, {"ok": True, "result": {}})
        return as_json(401, {"ok": False})

    server = Scripted(answer).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))
    back: list[float] = []

    async def run() -> None:
        began[0] = time.monotonic()
        try:
            while time.monotonic() - began[0] < well_after + 360 / S:
                if (await device.status())["state"] == "online":
                    back.append((time.monotonic() - began[0]) * S)
                    break
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert back, f"not back six minutes after it was well; it was signed in to {count} times"
    assert back[0] - 400 <= 330, f"back {round(back[0] - 400)} seconds after it was well"  # five minutes at the most, and a look


def test_what_stands_after_a_sign_in_that_came_to_nothing_is_not_called_no_answer() -> None:
    # An operator's button pressed in that time is refused at once, and nothing is sent. Said as "no answer",
    # the page told them that it "may have been done all the same: look before sending it again".
    server = Scripted(lambda method, path, head, body: "drop" if path == "/api/auth/login" else as_json(401, {})).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        try:
            with pytest.raises(KvmError) as first:
                await device._login()
            # (From the first: an operator's button that finds the session gone signs in again, and it was that
            # press which was answered "no answer", with the button never having reached the device.)
            assert (first.value.code, first.value.status) == ("no_sign_in", 503)
            before = len(server.seen)
            with pytest.raises(KvmError) as pressed:
                await device._request("POST", "/api/atx/click", urgent=True, params={"button": "power"})
            assert (pressed.value.code, pressed.value.status) == ("no_sign_in", 503), pressed.value.code
            assert len(server.seen) == before
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_a_kvm_that_does_not_sign_this_program_in_and_then_goes_off_is_seen_to(monkeypatch: pytest.MonkeyPatch) -> None:
    # While such a hold stands nothing is asked that needs a sign-in. So it is asked whether it is there, like
    # one whose password was rejected: a problem while it answers, offline when it no longer does.
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    gone = False

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        return "drop" if gone or path == "/api/auth/login" else as_json(401, {})

    server = Scripted(answer).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        nonlocal gone
        try:
            with pytest.raises(KvmError):
                await device._login()  # hung up on: for ten seconds nothing is sent to it
            assert (await device._read_status())["state"] == "error"
            gone = True
            assert (await device._read_status())["state"] == "offline"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert len(server.asked("POST", "/api/auth/login")) == 1


def test_a_sign_in_answered_with_something_made_nothing_of_is_not_sent_again_at_every_look() -> None:
    answers = {"/api/auth/login": (302, {"Location": "http:x"}, b"")}  # it points somewhere that is no address
    server = Scripted(lambda method, path, head, body: answers.get(path) or as_json(401, {})).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        try:
            for _ in range(20):
                with pytest.raises(KvmError):
                    await device._login()
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert len(server.asked("POST", "/api/auth/login")) == 1


def test_a_new_connection_does_not_send_again_what_was_answered_with_an_error_a_moment_ago() -> None:
    # The ten seconds after such an answer were kept in the connection: five connections made one after the
    # other sent the password five times.
    server = Scripted(lambda method, path, head, body: as_json(503 if path == "/api/auth/login" else 401, {})).start()
    spec = DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD)

    async def run() -> None:
        for number in range(5):
            device = kvm.KvmDevice(spec)
            try:
                with pytest.raises(KvmError) as failed:
                    await device._login()
                assert failed.value.code == "no_sign_in" and ("503" in failed.value.message) == (number == 0)
            finally:
                await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert len(server.asked("POST", "/api/auth/login")) == 1


def test_what_cannot_have_reached_the_device_is_not_counted_as_sent() -> None:
    for never in (httpx.ConnectError("refused"), httpx.ConnectTimeout("no answer to the connection"), httpx.PoolTimeout("no connection was free")):
        assert not kvm.went_out(never), never
    for maybe in (httpx.ReadTimeout("nothing came back"), httpx.ReadError("hung up on"), httpx.RemoteProtocolError("hung up on"), httpx.WriteError("hung up on")):
        assert kvm.went_out(maybe), maybe
    # A device that nothing connects to was sent nothing: nothing is kept of it, and it is asked again as any device that is down.
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=f"http://127.0.0.1:{closed_port()}", username="admin", password=PASSWORD))

    async def run() -> None:
        try:
            with pytest.raises(KvmError) as failed:
                await device._login()
            assert failed.value.code == "unreachable"
            assert kvm.REJECTED.wait_left(kvm.REJECTED.what("login", device.spec)) == 0 and device._login_error is None
        finally:
            await device.close()

    asyncio.run(run())


def test_a_sign_in_that_found_no_free_connection_was_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every connection this program has to the device is busy: the sign-in waited for one, and gave up. That is
    # "no answer in time" by its name, and nothing left this computer.
    server = Scripted(lambda method, path, head, body: as_json(401, {})).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def no_connection_free(*told: Any, **named: Any) -> Any:
        raise httpx.PoolTimeout("no connection was free")

    async def run() -> None:
        monkeypatch.setattr(device, "_send", no_connection_free)
        try:
            with pytest.raises(KvmError) as failed:
                await device._login()
            assert failed.value.code == "timeout"
            assert kvm.REJECTED.wait_left(kvm.REJECTED.what("login", device.spec)) == 0 and device._login_error is None
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert not server.asked("POST", "/api/auth/login")


def test_a_jetkvm_over_https_whose_sign_in_goes_unanswered_is_not_said_to_answer_over_plain_http_only(tmp_path: Path, odd: Odd, scaled: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # It is there, and answers everything but its sign-in. Shown as "offline" without being asked, it counted
    # as silent for two minutes, its other address was asked, and its owner was told to move it to plain HTTP.
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(0.3, connect=4.0))  # (a sign-in is waited for two and a half times that)
    for name in ("WAY_PATIENCE", "WAY_WHEN_DOWN", "RETRY_PAUSE"):
        monkeypatch.setattr(jetkvm, name, getattr(jetkvm, name) / SCALE)
    odd.sign_in_takes = 1.5
    state = JetState()
    plain, secure = FakeJetKvm(state).start(), FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
    other_ways(monkeypatch, {plain.url: secure.url})
    try:
        with wall(tmp_path / "wall") as admin:
            added = admin.post("/api/v1/devices", json={"url": secure.url, "password": "secret", "kind": "jetkvm", "name": "Jet", "force": True})
            assert added.status_code == 201, added.text
            device = added.json()["device"]["id"]
            line: list[tuple[str, str]] = []
            began = time.monotonic()
            while time.monotonic() - began < 4.0:
                status = admin.get("/api/v1/status").json()[device]
                said = (status["state"], ((status.get("error") or {}).get("message") or "")[:120])
                if not line or line[-1] != said:
                    line.append(said)
                time.sleep(0.02)
            assert not [entry for entry in line if "plain HTTP" in entry[1]], line
            assert "error" in {shown for shown, _ in line} and set(state.passwords_over) == {"https"}, line
    finally:
        plain.stop()
        secure.stop()


# --- what a fourth reading found: what the wall says, and does, while a sign-in is held back ----------


def test_a_sign_in_cut_off_by_retiring_its_connection_is_not_sent_again_by_the_next() -> None:
    # A wall started to lock itself: the last person signs out, every connection is retired, and a sign-in that
    # was under way was noted nowhere, since only its answer was. Each new connection sent the password again:
    # six in two seconds, by a viewer signing in and out, to a device that takes a second and a half over its no.
    server = Scripted(lambda method, path, head, body: ("after", 1.5, NO) if path == "/api/auth/login" else as_json(401, {})).start()
    spec = DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD)

    async def run() -> None:
        for _ in range(5):
            device = kvm.KvmDevice(spec)
            signing_in = asyncio.ensure_future(device._login())
            await asyncio.sleep(0.2)
            await device.close()
            with pytest.raises(KvmError):
                await signing_in

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert len(server.asked("POST", "/api/auth/login")) == 1


def test_a_kvm_whose_sign_in_is_answered_with_an_error_is_a_problem_and_not_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    # The wait after such an answer had grown from ten seconds to as much as five minutes, and the tile said
    # "offline" for all of it, with nothing asking whether the KVM was there: it answered everything else.
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    questions: list[str] = []

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        if path == "/api/auth/login":
            return as_json(503, {"ok": False})
        questions.append(path)
        return as_json(401, {"ok": False})

    server = Scripted(answer).start()
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password=PASSWORD))

    async def run() -> None:
        try:
            for _ in range(3):
                said = await device._read_status()
                assert said["state"] == "error" and "503" in said["error"]["message"], said
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert len(server.asked("POST", "/api/auth/login")) == 1 and questions


def test_a_jetkvm_whose_sign_in_came_to_nothing_once_is_no_problem_for_good_to_a_look_that_makes_no_connection(odd: Odd, monkeypatch: pytest.MonkeyPatch) -> None:
    # Somebody has the wall open, the JetKVM answers one sign-in with an error, they close the wall. The round
    # that sends alerts looks without making a connection and takes what the last connection showed to be so
    # still: it said "has a problem" for as long as nobody opened the wall again, and "is back" never came.
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    odd.sign_in_says = 503
    server = FakeJetKvm().start()
    device = jetkvm.JetKvmDevice(DeviceSpec(id="ab12", name="JetKVM", base_url=server.url, username="", password="secret", kind="jetkvm"))

    async def run() -> None:
        try:
            assert (await device._read_status())["state"] == "error"  # looked at: it is there, and signs nobody in
            assert await device.probe() == "online"  # not looked at: it is there, which is all that look can tell
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_a_jetkvm_that_needs_no_password_leaves_nothing_standing_behind_its_sign_in() -> None:
    # A sign-in is counted as it goes out, and stands as unanswered until its answer is noted. A JetKVM set to
    # "no password", with one saved here from before, answers the sign-in with "there is none": that lets this
    # program in, and has to be noted as that. Left standing, the next connection (the tile saved under another
    # name) was told for ten seconds that the device signs nobody in.
    server = FakeJetKvm(JetState(password="")).start()
    spec = DeviceSpec(id="ab12", name="JetKVM", base_url=server.url, username="", password="secret", kind="jetkvm")

    async def run() -> None:
        for _ in range(2):
            device = jetkvm.JetKvmDevice(spec)
            try:
                assert await device._login() is None
            finally:
                await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert kvm.REJECTED.wait_left(kvm.REJECTED.what("login", spec)) == 0


def test_a_jetkvm_s_no_is_noted_before_anything_else_is_asked_of_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # After its no a JetKVM is asked whether it is fresh from its box (the tile says so then). The no was
    # noted after that question: a connection retired while it was asked had heard a no and noted nothing,
    # and the next one offered the password again in ten seconds where it is a minute.
    server = FakeJetKvm(JetState(password="another one")).start()
    spec = DeviceSpec(id="ab12", name="JetKVM", base_url=server.url, username="", password="secret", kind="jetkvm")
    device = jetkvm.JetKvmDevice(spec)

    async def retired_just_then() -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(device, "_fresh_from_its_box", retired_just_then)

    async def run() -> None:
        try:
            with pytest.raises(asyncio.CancelledError):
                await device._login()
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    what = kvm.REJECTED.what("login", spec)
    assert kvm.REJECTED.times(what) == 1 and kvm.REJECTED.wait_left(what) > 50


def test_its_web_page_is_not_offered_the_password_where_the_other_sign_in_answered_with_an_error(scaled: None) -> None:
    # The question before the web page is signed in to stops only for a no. An error of the controller's own at
    # the other sign-in was taken for "one of its moments" too, and the web page was offered a password that
    # the controller had not let in: a wrong one, where it had been changed on the controller.
    server = FakeBmc(BmcState(own_console=True)).start()
    server.state.password = "changed on the controller"
    server.state.login_status = 503
    device = a_controller(server)

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < 1.5:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert server.state.web_logins == 0 and server.state.logins >= 1


async def what_its_console_says(device: redfish.RedfishDevice) -> KvmError:
    """Ask for the server's screen until the console has said why there is none."""
    assert (await device.status())["state"] == "online"
    for _ in range(100):
        try:
            await device.snapshot(640)
        except KvmError:
            pass
        if device._console_refusal is not None:
            return device._console_refusal
        await asyncio.sleep(0.05)
    raise AssertionError("the console never said how its sign-in went")


def test_a_sign_in_to_its_web_page_that_is_cut_off_by_retiring_the_connection_is_not_sent_again_by_the_next(odd: Odd, caplog: pytest.LogCaptureFixture) -> None:
    # The same on the other road the password takes. A connection retired while its web page is being signed in
    # to waits a little for the answer, to sign out again; a controller slower than that had the password
    # offered to its web page by every connection made anew, for nothing was noted until an answer came.
    odd.web_silent_from, odd.web_takes = 1, redfish.SIGN_IN_OWED + 1.2
    server = FakeBmc(BmcState(own_console=True)).start()

    async def run() -> None:
        first = a_controller(server)
        try:
            assert (await first.status())["state"] == "online"
            for _ in range(100):
                try:
                    await first.snapshot(640)
                except KvmError:
                    pass
                if server.state.web_logins:
                    break
                await asyncio.sleep(0.05)
            assert server.state.web_logins == 1 and first._console_refusal is None  # it is under way
        finally:
            await first.close()
        await asyncio.sleep(0.2)
        # (How that sign-in ended, with nobody left to hear it, is no error of the program's to be logged with a traceback.)
        assert not [record.getMessage() for record in caplog.records if record.name == "asyncio"]
        second = a_controller(server)
        try:
            said = await what_its_console_says(second)
            assert said.code == "no_sign_in" and "rejected" not in said.message, said.message
            assert server.state.web_logins == 1
        finally:
            await second.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_its_web_page_is_not_offered_the_password_by_a_new_connection_right_after_an_error_of_its_own(odd: Odd) -> None:
    # Its web page answers the sign-in with an error: too many sessions, one of its moments. The connection
    # that heard it waits ten minutes. One made anew in that time knew of nothing and offered the password
    # again at once: as often as the saved passwords were locked and opened again, or the tile was saved.
    odd.web_says = 503
    server = FakeBmc(BmcState(own_console=True)).start()

    async def run() -> None:
        first = a_controller(server)
        try:
            said = await what_its_console_says(first)
            assert said.code == "no_picture" and "503" in said.message and server.state.web_logins == 1
        finally:
            await first.close()
        second = a_controller(server)
        try:
            said = await what_its_console_says(second)
            assert said.code == "no_sign_in" and "rejected" not in said.message, said.message
            assert server.state.web_logins == 1
        finally:
            await second.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


@pytest.mark.parametrize("how", ["it could not be reached", "no connection was free"])
def test_what_cannot_have_reached_its_web_page_is_not_counted_as_sent(how: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # No connection to it was to be had for that sign-in (the server's controller went off in that moment, or
    # every connection was taken, which comes back as running out of time): nothing went out, and nothing
    # stands against the next one.
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)
    as_it_is = device._web

    async def web(method: str, path: str, *more: Any, **named: Any) -> Any:
        if method == "POST" and path == "/api/session":
            if how == "it could not be reached":
                raise KvmError("unreachable", "Cannot reach the device", 502)
            raise KvmError("timeout", "Device did not respond in time", 504) from httpx.PoolTimeout("no connection was free")
        return await as_it_is(method, path, *more, **named)

    monkeypatch.setattr(device, "_web", web)

    async def run() -> None:
        try:
            assert (await what_its_console_says(device)).code == ("unreachable" if how == "it could not be reached" else "timeout")
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert kvm.REJECTED.wait_left(kvm.REJECTED.what("web", device.spec)) == 0


def test_a_connection_made_while_another_is_signing_in_keeps_no_wait_of_its_own() -> None:
    # A sign-in is counted as it goes out, so a second connection made in that moment (a tile saved under
    # another name) is held back. It was told that the last sign-in had come to nothing, which was not so, and
    # it copied the wait: after the first had been let in and nothing stood any more, it went on refusing.
    fake = FakeKvm(FakeState(slow_login=0.6)).start()
    spec = DeviceSpec(id="ab12", name="KVM", base_url=fake.url, username="admin", password=FakeState().password)

    async def run() -> None:
        first, second = kvm.KvmDevice(spec), kvm.KvmDevice(spec)
        try:
            signing_in = asyncio.ensure_future(first._login())
            what = kvm.REJECTED.what("login", spec)
            for _ in range(500):  # until it has gone out (a first connection reads the system's certificates before it does)
                if kvm.REJECTED.silent(what) == 1:
                    break
                await asyncio.sleep(0.01)
            with pytest.raises(KvmError) as held:
                await second._login()
            assert held.value.code == "no_sign_in" and "under way" in held.value.message
            await signing_in
            await second._login()  # nothing stands any more, here or anywhere
        finally:
            await first.close()
            await second.close()

    try:
        asyncio.run(run())
    finally:
        fake.stop()
    assert fake.state.logins == 2


def test_its_web_page_is_not_offered_the_password_again_at_once_after_an_answer_nothing_is_made_of(odd: Odd) -> None:
    # Its web page answers the sign-in by sending on to an address that is none. The password went out, and
    # what came back says neither yes nor no: held back, as the other sign-ins hold that back. It was put back
    # as if nothing had been sent, and a connection made anew offered the password again at once.
    odd.web_says, odd.web_sends_on_to = 302, "http:x"
    server = FakeBmc(BmcState(own_console=True)).start()

    async def run() -> None:
        first = a_controller(server)
        try:
            assert (await what_its_console_says(first)).code == "bad_response" and server.state.web_logins == 1
        finally:
            await first.close()
        second = a_controller(server)
        try:
            assert (await what_its_console_says(second)).code == "no_sign_in" and server.state.web_logins == 1
        finally:
            await second.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


@pytest.mark.parametrize("takes", [0.3, 0.8, 1.6])
def test_a_console_s_session_is_given_back_however_long_the_controller_takes_over_it(takes: float, monkeypatch: pytest.MonkeyPatch) -> None:
    # Retired while its console is open, a controller is signed out of twice: its web page, and Redfish. The
    # first was done inside the task that is being stopped, which is told again every half second: a
    # controller that takes longer than that over a sign-out (they do) kept the session, and it has few.
    left: list[str] = []
    as_it_is = fake_redfish.make_fake_bmc

    def slowly(state: BmcState) -> FastAPI:
        app = as_it_is(state)

        @app.middleware("http")
        async def taking_its_time(request: Request, call_next: Any) -> Any:
            if request.method == "DELETE" and request.url.path == "/api/session":
                await asyncio.sleep(takes)
                if await request.is_disconnected():
                    left.append("hung up on")  # (whoever asked has gone: this stand-in then does not do it)
                    return JSONResponse({}, status_code=499)
            return await call_next(request)

        return app

    monkeypatch.setattr(fake_redfish, "make_fake_bmc", slowly)
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            for _ in range(100):
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                if server.state.web_sessions:
                    break
                await asyncio.sleep(0.05)
            assert len(server.state.web_sessions) == 1
        finally:
            await device.close()
        await asyncio.sleep(0.3)

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert not server.state.web_sessions and not left, (server.state.web_sessions, left)
    assert not server.state.tokens  # and the other session too


def test_a_session_given_while_the_connection_was_being_closed_is_given_back(monkeypatch: pytest.MonkeyPatch) -> None:
    # Closing read the session it has to give back first, and then waited for the console to stop. A sign-in
    # that was answered in that wait had a session nobody gave back: the controller kept it for half an hour.
    as_it_is = fake_redfish.make_fake_bmc

    def slowly(state: BmcState) -> FastAPI:
        app = as_it_is(state)

        @app.middleware("http")
        async def taking_its_time(request: Request, call_next: Any) -> Any:
            answer = await call_next(request)
            if request.method == "POST" and request.url.path.rstrip("/") == redfish.SESSIONS.rstrip("/"):
                await asyncio.sleep(0.25)  # the session is made, and the answer that says so is on its way
            return answer

        return app

    monkeypatch.setattr(fake_redfish, "make_fake_bmc", slowly)
    server = FakeBmc(BmcState()).start()
    device = a_controller(server)

    async def run() -> None:
        signing_in = asyncio.ensure_future(device._login())

        async def a_console_that_takes_a_moment_to_stop() -> None:
            # However often it is told to: it has stopped once the sign-in beside it has its answer.
            while not signing_in.done():
                try:
                    await asyncio.sleep(0.02)
                except asyncio.CancelledError:
                    continue
            raise asyncio.CancelledError

        device._console_task = asyncio.ensure_future(a_console_that_takes_a_moment_to_stop())
        for _ in range(200):
            if server.state.logins:
                break
            await asyncio.sleep(0.01)
        await device.close()
        assert signing_in.done() and not signing_in.cancelled() and signing_in.exception() is None

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert server.state.logins == 1 and not server.state.tokens


def test_the_page_lets_a_tile_be_saved_in_spite_of_a_device_that_signs_nobody_in_just_now() -> None:
    # "Save without checking" is offered where a device could not be reached. A tile whose device is there and
    # signs nobody in for the moment could not be given another name: the save was refused, and the page had
    # no button for it. It has one where nothing about how the device is signed in to was changed. Not where
    # a device is added, and not for another address: whatever is at an address that is no KVM answers its
    # sign-in that way, and once added was sent the password every five minutes for good. (Both are seen in
    # a browser, in test_in_a_browser.py; this holds the two lines.)
    script = (Path(kvm.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    assert "const CANNOT_BE_REACHED = ['unreachable', 'timeout', 'dropped'];" in script and "CANNOT_BE_CHECKED" not in script
    assert "if (CANNOT_BE_REACHED.includes(ex.code)) {" in script
    assert "saveAnyway.hidden = !(CANNOT_BE_REACHED.includes(ex.code) || (ex.code === 'no_sign_in' && asItWas));" in script
