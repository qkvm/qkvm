"""GL.iNet's Fingerbot, paired with a Comet, presses a machine's power button from the wall (as a real one did, 2026-10-18).

The Comet says whether one is paired only in a `fingerbot` event on its line for events (`{"exist": true}`), which the wall
holds anyway while somebody watches the KVM's picture; where nobody has, a line is opened before a press to ask. A press is
POST /api/fingerbot/click with the time to hold in milliseconds and the strength (`angle_enum`, 2 firm, 1 light), and the
real one answered "success" about two seconds after it was sent, for half a second, three and eight alike: the wall holds
the machine for the press's own time after that, as one thing at a time. "Failed to click" is a failure; no answer may have
been pressed. Nothing of the computer's power comes from a Fingerbot.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from qkvm import kvm
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_history import hist
from tests.test_wall import CSRF, PASSWORD, add, wait_until, wall


@pytest.fixture(autouse=True)
def looked_at_often(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """The presses made short (the long one held 1.2 s, not 8), and no moment after them for the arm to come back."""
    presses = {"fingerbot_power": 0.5, "fingerbot_power_long": 1.2}
    # (raising=False: on a program without them, the tests run all the same, and fail on what they prove.)
    monkeypatch.setattr(kvm, "FINGERBOT_PRESSES", presses, raising=False)
    monkeypatch.setattr(kvm, "FINGERBOT_BACK", 0.0, raising=False)
    return presses


def press(client: Any, device: str, action: str, **extra: Any) -> tuple[float, Any]:
    began = time.monotonic()
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": action, **extra})
    return time.monotonic() - began, reply


def status_of(client: Any, device: str) -> dict[str, Any]:
    found: dict[str, Any] = client.get("/api/v1/status").json()[device]
    return found


def watched(client: Any, device: str) -> dict[str, Any]:
    """The tile looked at as a page that shows it looks: its picture asked for (which has the wall hold the KVM's line)."""
    client.get(f"/api/v1/devices/{device}/snapshot", params={"w": 480})
    return status_of(client, device)


def offered(client: Any, device: str) -> bool:
    return "fingerbot" in watched(client, device)["can"]


def audit(client: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = client.get("/api/v1/audit").json()["entries"]
    return entries


def test_what_a_comet_says_of_its_fingerbot_is_read_by_kind() -> None:
    # The `fingerbot` event of a real Comet with one, and of one without (by its size, in a record that kept each event's keys).
    assert kvm.fingerbot_heard({"exist": True}) is True
    assert kvm.fingerbot_heard({"exist": False}) is False
    for nothing in ({"exist": "true"}, {"exist": 1}, {"exist": None}, {}, None, [], "exist", True):
        assert kvm.fingerbot_heard(nothing) is None, nothing
    assert kvm.event_of('{"event_type": "fingerbot", "event": {"exist": true}}') == ("fingerbot", {"exist": True})
    # Its battery: the real one said 101 (the Comet's own page counts anything from 70 up as full); what is no number, none.
    assert [kvm.battery_said({"battery": value}) for value in (101, 100, 12, 0, 12.4)] == [100, 100, 12, 0, 12]
    for nothing in ({"battery": -1}, {"battery": 256}, {"battery": "50"}, {"battery": True}, {"battery": None}, {}, None, [50]):
        assert kvm.battery_said(nothing) is None, nothing
    # What is sent: the Comet's own page's half second and eight seconds, and its two strengths (firm its default).
    assert kvm.FINGERBOT_PRESSES == {"fingerbot_power": 0.5, "fingerbot_power_long": 8.0}
    assert kvm.FINGERBOT_STRENGTHS == {"firm": "2", "light": "1"}
    assert "fingerbot" in kvm.ABILITIES


def test_a_kvm_whose_events_say_a_fingerbot_is_there_offers_its_presses(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_event_after=0.3)).start()
    plain = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as client:
            device, other = add(client, fake.url), add(client, plain.url)
            wait_until(lambda: offered(client, device), "a KVM whose events say a Fingerbot is there never offered it", timeout=10)
            # Its battery, asked once it is known (101 on the real one: full), and not low.
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 100, "low": False}, "its battery was never said")
            # Nothing of the computer's power comes from it, and no power board's buttons either.
            status = watched(client, device)
            assert status["atx"] == {"enabled": False, "power": None, "hdd": None}
            assert "power" not in status["can"] and "reset" not in status["can"]
            # A KVM without one says so on its line, and offers nothing.
            for _ in range(10):
                watched(client, other)
                time.sleep(0.05)
            assert "fingerbot" not in watched(client, other)["can"] and watched(client, other)["fingerbot"] is None
            # Unpaired, it goes from the tile (the KVM says so on its line, as it said it was there).
            fake.state.fingerbot = False
            wait_until(lambda: not offered(client, device), "a Fingerbot the KVM said is gone was still offered")
            assert watched(client, device)["fingerbot"] is None
    finally:
        fake.stop()
        plain.stop()


def test_a_press_is_answered_once_the_comet_took_it_and_its_time_is_over(tmp_path: Path, quick: dict[str, float]) -> None:
    # The real Comet answered every press about two seconds after it came, for half a second, three and eight alike: its
    # "success" says the Fingerbot took it, not that it is over. Answered then, a long press would still be holding the
    # button when the wall let go of the machine, and a second press would go to an arm that is down.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_answer=0.4)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            took, reply = press(client, device, "fingerbot_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert took >= 0.4 + quick["fingerbot_power"], f"answered after {took:.2f} s: before the press was over"
            took, reply = press(client, device, "fingerbot_power_long")
            assert reply.status_code == 200, reply.text
            assert took >= 0.4 + quick["fingerbot_power_long"], f"answered after {took:.2f} s: before the press was over"
            # As the Comet's own page sends a press: the time in milliseconds, firm (2) unless the machine says otherwise.
            assert fake.state.presses == [("500", "2"), ("1200", "2")]
            # The history keeps that it was pressed; the tile's power is what it was: nothing.
            events = client.get(hist(device, what="events")).json()["rows"]
            assert [(row["kind"], row["what"], row["ok"]) for row in events] == [("pressed", "fingerbot_power", True), ("pressed", "fingerbot_power_long", True)]
            assert status_of(client, device)["atx"]["power"] is None
    finally:
        fake.stop()


def test_a_second_press_while_one_runs_is_refused(tmp_path: Path, quick: dict[str, float]) -> None:
    # One thing at a time per machine, for the whole of the press: a second press is refused before anything is sent, a
    # power board's button on the same machine too.
    fake = FakeKvm(FakeState(fingerbot=True, atx=True, fingerbot_answer=0.2)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            first: list[Any] = []
            holding = threading.Thread(target=lambda: first.append(press(client, device, "fingerbot_power_long")))
            holding.start()
            wait_until(lambda: len(fake.state.presses) == 1, "the press was never sent")
            time.sleep(0.4)  # (the Comet has answered; the press goes on)
            for action in ("fingerbot_power", "atx_power"):
                _, second = press(client, device, action)
                assert (second.status_code, second.json()["code"]) == (409, "busy"), second.text
            holding.join(10)
            assert first[0][1].status_code == 200
            assert len(fake.state.presses) == 1 and "atx power" not in fake.state.actions
            # Once it is over, the next one goes.
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            assert len(fake.state.presses) == 2
    finally:
        fake.stop()


def test_press_failed_is_said_as_a_failure(tmp_path: Path, quick: dict[str, float]) -> None:
    # The Comet's "Press Failed" is its 400 "Failed to click" (a real one, for a press sent 0.3 s into another, from its own
    # page or another program): nothing was pressed as far as it knows, and that is a failure, offered again by the page.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_taking=1.0, fingerbot_fail_after=0.1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            # Somebody else's press (the Comet's own page) is being taken when the wall's comes.
            fake.state.tokens.add("somebody-else")
            with httpx.Client(base_url=fake.url, cookies={"auth_token": "somebody-else"}, timeout=5) as other:
                assert other.post("/api/fingerbot/click", params={"press_time": "500", "angle_enum": "2"}).status_code == 200
            _, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 502, reply.text
            assert reply.json() == {"code": "action_failed", "message": 'The Fingerbot did not press: the KVM said "Failed to click"'}
            time.sleep(1.0)
            fake.state.fingerbot_fails = True
            assert press(client, device, "fingerbot_power_long")[1].json()["code"] == "action_failed"
            events = client.get(hist(device, what="events")).json()["rows"]
            assert [(row["what"], row["ok"]) for row in events] == [("fingerbot_power", False), ("fingerbot_power_long", False)]
            failed = [entry for entry in audit(client) if entry["event"] == "action_failed"][::-1]  # (the log: newest first)
            assert [(entry["action"], entry["error"]) for entry in failed] == [
                ("fingerbot_power", 'The Fingerbot did not press: the KVM said "Failed to click"'),
                ("fingerbot_power_long", 'The Fingerbot did not press: the KVM said "Failed to click"'),
            ]
    finally:
        fake.stop()


def events_once_there(client: TestClient, device: str) -> list[dict[str, Any]]:
    """The machine's history of presses, once the press just answered is in it: the history's writer puts a row there a
    moment after the answer has gone out (the board's tests wait the same way)."""
    wait_until(lambda: client.get(hist(device, what="events")).json()["rows"], "the press never reached the history")
    rows: list[dict[str, Any]] = client.get(hist(device, what="events")).json()["rows"]
    return rows


def test_a_press_whose_answer_never_comes_may_have_been_done(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # The Comet's own page gives a press eight seconds beside its own time. No answer by then is no refusal: the press may
    # have gone, and is not to be sent again blindly (the page's "No answer. It may have been done." is for 504 `timeout`).
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 0.5, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_silent=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            took, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 504, reply.text
            assert reply.json()["code"] == "timeout" and "may have" in reply.json()["message"], reply.text
            assert took < 5, f"waited {took:.1f} s"
            events = events_once_there(client, device)
            assert [(row["what"], row["ok"]) for row in events] == [("fingerbot_power", None)]
            # Not taken as the KVM gone: its tile goes on as it was.
            fake.state.fingerbot_silent = False
            assert watched(client, device)["state"] == "online"
    finally:
        fake.state.fingerbot_silent = False
        fake.stop()


def test_how_hard_it_presses_is_the_machines_own(tmp_path: Path, quick: dict[str, float]) -> None:
    # Per machine, in its Edit box: the button and how the Fingerbot sits on it are that machine's. Firm unless said (the
    # Comet's own page's default; a light press did not move the first real button it was tried on).
    fake = FakeKvm(FakeState(fingerbot=True)).start()
    try:
        with wall(tmp_path / "one") as client:
            device = add(client, fake.url, fingerbot_strength="light")
            listed = next(d for d in client.get("/api/v1/wall").json()["devices"] if d["id"] == device)
            assert listed["fingerbot_strength"] == "light"
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            edited = {"url": fake.url, "username": "admin", "fingerbot_strength": "firm"}
            assert client.put(f"/api/v1/devices/{device}", json=edited).status_code == 200
            # (Saved anew, the tile keeps what the KVM said of its Fingerbot: no need to watch it again.)
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            assert [angle for _, angle in fake.state.presses] == ["1", "2"]
            # An edit that does not say keeps it; what is not a strength is refused.
            assert client.put(f"/api/v1/devices/{device}", json={**edited, "fingerbot_strength": "light"}).status_code == 200
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "username": "admin"}).status_code == 200
            assert client.put(f"/api/v1/devices/{device}", json={**edited, "fingerbot_strength": "hard"}).status_code == 422
            assert next(d for d in client.get("/api/v1/wall").json()["devices"] if d["id"] == device)["fingerbot_strength"] == "light"
            # It goes along in a file, and comes back from one.
            file = client.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]}).text
        assert json.loads(file)["devices"][0]["fingerbot_strength"] == "light"
        with wall(tmp_path / "two") as other:
            assert other.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
            assert other.get("/api/v1/wall").json()["devices"][0]["fingerbot_strength"] == "light"
            # A file that says something else of it leaves that machine out, and says why.
            odd = json.loads(file)
            odd["devices"][0]["fingerbot_strength"] = "hard"
            read = other.post("/api/v1/import/read", json={"file": json.dumps(odd)}).json()
            assert read["devices"] == [] and any("Fingerbot" in why for why in read["left_out"]), read
            # Nothing said of it (null), as the form has it: firm, and the machine is taken.
            odd["devices"][0]["fingerbot_strength"] = None
            read = other.post("/api/v1/import/read", json={"file": json.dumps(odd)}).json()
            assert len(read["devices"]) == 1 and read["left_out"] == [], read
    finally:
        fake.stop()


def test_a_kvm_without_a_fingerbot_is_sent_no_press(tmp_path: Path, quick: dict[str, float]) -> None:
    # One that said it has none is refused before anything goes to it; so is a stock PiKVM (no Fingerbot is anybody's but
    # GL.iNet's), which is not even asked.
    fake = FakeKvm(FakeState()).start()
    stock = FakeKvm(FakeState(stock=True)).start()
    try:
        with wall(tmp_path) as client:
            device, pikvm = add(client, fake.url), add(client, stock.url)
            for _ in range(10):
                watched(client, device)
                watched(client, pikvm)
                time.sleep(0.05)
            for which, why in ((device, "No Fingerbot is paired with this KVM"), (pikvm, "This KVM has no Fingerbot: that is a GL.iNet Comet's")):
                _, reply = press(client, which, "fingerbot_power")
                assert (reply.status_code, reply.json()) == (422, {"code": "invalid", "message": why}), reply.text
            assert fake.state.presses == [] and stock.state.presses == []
            assert not any(question.startswith("POST /api/fingerbot") for question in list(stock.state.asked))
            assert "stream=0" not in "".join(stock.state.ws_queries)
    finally:
        fake.stop()
        stock.stop()


def test_where_nobody_has_watched_its_picture_the_kvm_is_asked_before_a_press(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # The Comet says whether a Fingerbot is paired only on a line to its events, which the wall holds while somebody watches
    # the picture. A script that presses after qKVM started, with nobody watching: a line is opened to ask (the press goes
    # to the machine anyway), and the press goes where it says one is.
    monkeypatch.setattr(kvm, "FINGERBOT_ASK_WITHIN", 1.5, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_event_after=0.5)).start()
    quiet = FakeKvm(FakeState(fingerbot=True, fingerbot_events=False)).start()
    try:
        with wall(tmp_path) as client:
            device, other = add(client, fake.url), add(client, quiet.url)
            assert fake.state.ws_streams == []  # (nobody watched: no line held)
            _, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 200, reply.text
            assert fake.state.ws_streams == ["0"] and fake.state.presses == [("500", "2")]
            wait_until(lambda: "fingerbot" in status_of(client, device)["can"], "what the line said was not kept for the tile")
            # A KVM that says nothing of it within the time: nothing is pressed, and that is a failure (nothing went out).
            took, reply = press(client, other, "fingerbot_power")
            assert reply.status_code == 502 and reply.json()["code"] == "action_failed", reply.text
            assert "Nothing was pressed" in reply.json()["message"] and took >= kvm.FINGERBOT_ASK_WITHIN - 0.5
            assert quiet.state.presses == []
            wait_until(lambda: quiet.state.viewers == 0, "the line opened to ask was never closed")
            # Asked again at once, it would have a line opened at every press of a script that tries again (a line can wake
            # the computer): refused without one for a while.
            took, reply = press(client, other, "fingerbot_power")
            assert reply.status_code == 502 and "a moment ago" in reply.json()["message"] and took < 1.0, reply.text
            assert quiet.state.ws_streams.count("0") == 1
    finally:
        fake.stop()
        quiet.stop()


def test_a_kvm_slow_to_say_whether_a_fingerbot_is_paired_is_waited_for_longer_than_the_real_one_took(tmp_path: Path, quick: dict[str, float]) -> None:
    # The real one said it 0.2 to 2.0 s after a line opened, and twice 4.3 s, while another line was open to it. Asked for
    # five seconds, that press was nearly refused; it is waited for ten.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_event_after=5.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            took, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 200, reply.text
            assert took >= 5.5 and fake.state.presses == [("500", "2")]
    finally:
        fake.stop()


def test_a_comet_that_says_its_fingerbot_again_has_the_tile_looked_at_no_more_often(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real Comet says it again on every line open to it whenever another line is told (somebody else's page opened, say).
    # The same word again is no news: the tile is not looked at anew for it, every question of a look with it.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_resend=0.1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            monkeypatch.setattr(kvm, "STATUS_TTL", 4.0)
            looks = sum(1 for question in list(fake.state.asked) if question == "GET /api/streamer")
            sent = fake.state.fingerbot_events_sent
            until = time.monotonic() + 3.0
            while time.monotonic() < until:
                watched(client, device)
                time.sleep(0.1)
            assert fake.state.fingerbot_events_sent >= sent + 20, "the stand-in did not say it again: the test proves nothing"
            more = sum(1 for question in list(fake.state.asked) if question == "GET /api/streamer") - looks
            assert more <= 2, f"the tile was looked at {more} times in three seconds while the KVM said the same again"
            assert "fingerbot" in watched(client, device)["can"]
    finally:
        fake.stop()


def test_who_may_press_and_what_the_activity_log_says(tmp_path: Path, quick: dict[str, float]) -> None:
    # An operator or an admin, as for every action; a viewer may not. Each press is a line of the activity log with who
    # pressed what where, and a run over several machines ties its lines together.
    fake = FakeKvm(FakeState(fingerbot=True)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: offered(admin, device), "the Fingerbot was never offered")
            for name, role in (("olga", "operator"), ("vera", "viewer")):
                assert admin.post("/api/v1/users", json={"name": name, "role": role, "password": f"a password for {name}"}).status_code == 201
            people = {}
            for port, name in ((50091, "olga"), (50092, "vera")):
                person = TestClient(admin.app, headers=CSRF, client=("127.0.0.1", port))
                person.portal = admin.portal  # type: ignore[attr-defined]
                assert person.post("/api/v1/login", json={"name": name, "password": f"a password for {name}"}).status_code == 200
                people[name] = person
            assert press(people["vera"], device, "fingerbot_power")[1].status_code == 403
            assert fake.state.presses == []
            assert press(people["olga"], device, "fingerbot_power", batch="run-7")[1].status_code == 200
            assert press(admin, device, "fingerbot_power_long")[1].status_code == 200
            name = next(d["name"] for d in admin.get("/api/v1/wall").json()["devices"] if d["id"] == device)
            done = [entry for entry in audit(admin) if entry["event"] == "action"][::-1]  # (the log: newest first)
            assert [(entry["user"], entry["device"], entry["action"], entry["strength"], entry.get("batch")) for entry in done] == [
                ("olga", name, "fingerbot_power", "firm", "run-7"), ("admin", name, "fingerbot_power_long", "firm", None),
            ]  # fmt: skip
    finally:
        fake.stop()


def test_its_battery_is_asked_seldom_and_a_low_one_is_said(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Its battery is a round trip to the Fingerbot (0.6 to 0.7 s on the real one): asked once it is known, then once an hour,
    # not at every look; below a quarter it is low, as the Comet's own page shows it. (Here once every three seconds.)
    monkeypatch.setattr(kvm, "FINGERBOT_BATTERY_EVERY", 3.0, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_battery=12)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 12, "low": True}, "a low battery was never said")
            for _ in range(20):
                watched(client, device)
                time.sleep(0.02)
            assert fake.state.battery_asked == 1, f"asked {fake.state.battery_asked} times in 20 looks"
            # Once it is time again, asked again.
            fake.state.fingerbot_battery = 80
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 80, "low": False}, "the battery was never asked again", timeout=8)
            assert fake.state.battery_asked == 2
    finally:
        fake.stop()


def test_a_kvm_with_a_board_and_a_fingerbot_has_both(tmp_path: Path, quick: dict[str, float]) -> None:
    # The board's buttons stay the power buttons; the Fingerbot's are beside them, under its own name, and each goes where
    # it says.
    fake = FakeKvm(FakeState(fingerbot=True, atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            assert {"power", "reset", "fingerbot"} <= set(watched(client, device)["can"])
            assert press(client, device, "atx_power")[1].status_code == 200
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            assert "atx power" in fake.state.actions and fake.state.presses == [("500", "2")]
    finally:
        fake.stop()


def test_a_press_cut_off_by_qkvm_stopping_after_the_comet_took_it_is_written_down_as_pressed(tmp_path: Path) -> None:
    # The web server gives a request three seconds when qKVM stops, and a long press is held eight after the Comet's answer:
    # cut off then, it was pressed, and the log says so (not "may have been done", which the page would offer again).
    from qkvm import cli
    from tests.test_hardening import LiveWall

    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_answer=0.2)).start()
    data = tmp_path / "data"
    try:
        with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()["device"]["id"]

            def hold() -> None:
                try:
                    admin.post(f"/api/v1/devices/{device}/actions", json={"action": "fingerbot_power_long"})
                except httpx.HTTPError:
                    pass

            pressing = threading.Thread(target=hold)
            pressing.start()
            wait_until(lambda: len(fake.state.presses) == 1, "the press was never sent", timeout=15)
            time.sleep(0.8)  # the Comet has answered; the press goes on
            live._server.should_exit = True
            pressing.join(30)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        pressed = [(line["event"], line.get("note")) for line in lines if line["event"] in ("action", "action_failed")]
        assert pressed == [("action", "qKVM was stopped after the KVM had taken the press: it was pressed")], pressed
    finally:
        fake.stop()


# --- from the review of the first version ---------------------------------------------------------------------------


def test_an_answer_that_is_neither_yes_nor_no_may_have_pressed(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Only the Comet's 4xx is a no ("Failed to click"). Its own error, or a proxy's before it, comes after the Fingerbot
    # may have been told, and so may a yes of another shape or an answer that broke off: said as "did not press", the page
    # offered it under "Retry failed", and a power button pressed twice undoes itself. (After each, the Fingerbot is left
    # alone for as long as that press can last: the time for an answer made short here, and waited out.)
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 0.3, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            unknown = [
                (500, '{"ok": false, "result": {"error": "ServerError", "error_msg": "Internal error"}}'),
                (502, "<html><body>Bad Gateway</body></html>"),
                (504, "<html><body>Gateway Time-out</body></html>"),
                (200, '{"ok": true, "result": {"result": "fail"}}'),
                (200, "<html>not kvmd</html>"),
                (0, ""),  # (broken off on its way)
            ]
            for reply in unknown:
                fake.state.fingerbot_reply = reply
                _, answer = press(client, device, "fingerbot_power")
                assert answer.json()["code"] in ("timeout", "dropped") and "may have" in answer.json()["message"], (reply, answer.text)
                time.sleep(0.9)
            fake.state.fingerbot_reply = (404, '{"ok": false, "result": {"error": "NotFoundError", "error_msg": "Not found"}}')
            _, answer = press(client, device, "fingerbot_power")
            assert answer.json() == {"code": "action_failed", "message": 'The Fingerbot did not press: the KVM said "Not found"'}
            events = client.get(hist(device, what="events")).json()["rows"]
            assert [row["ok"] for row in events] == [None] * len(unknown) + [False]
            assert len(fake.state.presses) == len(unknown) + 1
    finally:
        fake.stop()


def test_a_kvm_that_said_it_has_no_fingerbot_is_not_asked_again_at_every_press(tmp_path: Path, quick: dict[str, float]) -> None:
    # A line opened to a Comet woke its sleeping PC three times in five (FOR-THE-DESKTOP-APP.md, rule 23). One opened to ask
    # a KVM that said it has no Fingerbot is opened for nothing: no press follows. Once one is paired it says so on the
    # line held while its picture is watched.
    fake = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: watched(client, device) and fake.state.fingerbot_events_sent >= 1, "the KVM never said it has none")
            time.sleep(0.3)
            for _ in range(3):
                _, reply = press(client, device, "fingerbot_power")
                assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
            assert fake.state.ws_streams.count("0") == 0, f"{fake.state.ws_streams.count('0')} lines opened to ask it again"
            fake.state.fingerbot = True
            wait_until(lambda: offered(client, device), "a Fingerbot paired since was never offered")
            assert press(client, device, "fingerbot_power")[1].status_code == 200 and fake.state.presses == [("500", "2")]
    finally:
        fake.stop()


def test_a_tile_saved_anew_during_a_press_asks_no_battery_while_the_button_is_held(tmp_path: Path, quick: dict[str, float]) -> None:
    # The Comet talks to its Fingerbot one request at a time. A tile renamed during a hold made a new client, whose turn was
    # free: it asked the battery with the arm down (its battery was due: the press had just taught the wall of the Fingerbot).
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_answer=0.2)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            answers: list[Any] = []
            holding = threading.Thread(target=lambda: answers.append(press(client, device, "fingerbot_power_long")))
            holding.start()
            wait_until(lambda: len(fake.state.presses) == 1, "the press was never sent")
            time.sleep(0.4)  # (the Comet has answered: the button is held)
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "username": "admin", "name": "Renamed"}).status_code == 200
            while holding.is_alive():
                status_of(client, device)
                time.sleep(0.05)
            assert answers[0][1].status_code == 200, answers[0][1].text
            wait_until(lambda: status_of(client, device)["fingerbot"] == {"battery": 100, "low": False}, "the battery was never asked after the press")
            held_until = fake.state.presses_at[0] + 0.2 + quick["fingerbot_power_long"]
            assert fake.state.battery_at[0] >= held_until - 0.1, f"the battery was asked {held_until - fake.state.battery_at[0]:.2f} s before the press was over"
    finally:
        fake.stop()


def test_a_battery_question_under_way_holds_a_press_up_for_seconds_at_most(tmp_path: Path, quick: dict[str, float]) -> None:
    # A press waits for a question of the battery that is under way (one request to the Fingerbot at a time). A Fingerbot
    # slow to answer, or out of reach, held a person's press up for as long as the answer took, up to half a minute.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_battery_answer=6.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device) and fake.state.battery_asked == 1, "the battery was never asked")
            began = time.monotonic()
            _, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 200, reply.text
            assert fake.state.presses_at[0] - began < kvm.FINGERBOT_BATTERY_WAIT + 1.0, f"the press went {fake.state.presses_at[0] - began:.1f} s after it was asked for"
            assert status_of(client, device)["fingerbot"] == {"battery": None, "low": None}  # (not answered in time: not known)
    finally:
        fake.stop()


def test_a_tile_saved_anew_while_the_kvm_is_asked_presses_nothing_and_says_so(tmp_path: Path, quick: dict[str, float]) -> None:
    # Nothing was sent: the KVM was only being asked whether a Fingerbot is paired. "It may have been done all the same"
    # would be untrue, and the history would keep that nobody knows.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_event_after=1.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "fingerbot_power")))
            pressing.start()
            wait_until(lambda: fake.state.key_lines == 1, "the KVM was never asked")
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "username": "admin", "name": "Renamed"}).status_code == 200
            pressing.join(15)
            reply = answers[0][1]
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and reply.json()["message"].startswith("Nothing was pressed"), reply.text
            assert fake.state.presses == []
            events = events_once_there(client, device)
            assert [(row["what"], row["ok"]) for row in events] == [("fingerbot_power", False)]
    finally:
        fake.stop()


def test_a_fingerbot_paired_anew_has_its_battery_asked_again_soon_not_an_hour_later(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Unpaired, its battery went from the tile, and the next question was still an hour away: one paired again (or another
    # one, with a low battery) had no battery on its tile for that hour. Now within the retry time of the last question
    # (ten minutes; one second here), and not at every word of a KVM that says yes and no in turn (see below).
    monkeypatch.setattr(kvm, "FINGERBOT_BATTERY_RETRY", 1.0, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_battery=80)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 80, "low": False}, "its battery was never said")
            fake.state.fingerbot = False
            wait_until(lambda: not offered(client, device), "a Fingerbot the KVM said is gone was still offered")
            fake.state.fingerbot_battery, fake.state.fingerbot = 12, True
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 12, "low": True}, "the battery of one paired anew was not asked")
    finally:
        fake.stop()


# --- from the review of the fixes -----------------------------------------------------------------------------------


def test_a_none_said_a_while_ago_is_asked_again_and_a_fingerbot_paired_since_presses(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Nobody watches the picture (a script, a token). Told once that none is paired, the wall refused every press for good,
    # with nothing to say to the script how to change that: also after one was paired. It is asked again after a while.
    monkeypatch.setattr(kvm, "FINGERBOT_ASK_AGAIN", 1.5, raising=False)
    fake = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            for _ in range(2):
                _, reply = press(client, device, "fingerbot_power")
                assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
            assert fake.state.ws_streams == ["0"]  # (asked once; the second within the time, not asked)
            # (Saved anew, the tile keeps what the KVM said a moment ago: not asked at once again.)
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "username": "admin", "name": "Renamed"}).status_code == 200
            assert press(client, device, "fingerbot_power")[1].status_code == 422 and fake.state.ws_streams == ["0"]
            fake.state.fingerbot = True
            assert press(client, device, "fingerbot_power")[1].status_code == 422  # (what it said a moment ago stands)
            time.sleep(1.6)
            _, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 200, reply.text
            assert fake.state.ws_streams == ["0", "0"] and fake.state.presses == [("500", "2")]
    finally:
        fake.stop()


def test_a_press_with_no_clear_answer_leaves_the_fingerbot_alone_for_as_long_as_it_may_press(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # The Comet takes a press sent a second into another. After one whose answer said neither yes nor no, the wall let go
    # of the machine at once, and a second press (another person, a script, the button again) went to the Fingerbot while
    # the first may still have been pressing. Also where the tile was saved anew while the press was on its way.
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 0.5, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_answer=0.2, fingerbot_reply=(200, '{"ok": true, "result": {}}'))).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            _, first = press(client, device, "fingerbot_power")
            assert first.json()["code"] == "timeout", first.text
            fake.state.fingerbot_reply = None
            _, second = press(client, device, "fingerbot_power")
            assert (second.status_code, second.json()["code"]) == (409, "busy") and "may still be pressing" in second.json()["message"], second.text
            assert len(fake.state.presses) == 1
            time.sleep(1.1)  # (the answer's time, the press's and the arm's, from when it was sent)
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            # Saved anew while the press is on its way: it may have been done, and the new client leaves it alone too.
            fake.state.fingerbot_answer = 1.0
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "fingerbot_power")))
            pressing.start()
            wait_until(lambda: len(fake.state.presses) == 3, "the press was never sent")
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "username": "admin", "name": "Renamed"}).status_code == 200
            pressing.join(15)
            assert answers[0][1].json()["code"] == "timeout", answers[0][1].text
            _, after = press(client, device, "fingerbot_power")
            assert (after.status_code, after.json()["code"]) == (409, "busy"), after.text
            assert len(fake.state.presses) == 3
    finally:
        fake.stop()


def test_a_battery_answer_that_trickles_holds_a_press_up_for_seconds_at_most(tmp_path: Path, quick: dict[str, float]) -> None:
    # The battery's answer was waited for three seconds a piece, and the whole of it some half a minute: one that came a
    # byte at a time held a person's press up for 27 s.
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_battery_trickle=2.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device) and fake.state.battery_asked == 1, "the battery was never asked")
            began = time.monotonic()
            _, reply = press(client, device, "fingerbot_power")
            assert reply.status_code == 200, reply.text
            assert fake.state.presses_at[0] - began < 9.0, f"the press went {fake.state.presses_at[0] - began:.1f} s after it was asked for"
    finally:
        fake.state.fingerbot_battery_trickle = 0.0
        fake.stop()


def test_a_comet_that_says_yes_and_no_in_turn_has_its_battery_asked_no_more_often(tmp_path: Path) -> None:
    # Each question of the battery is a round trip on the Fingerbot's own battery. A KVM that said yes and no in turn had it
    # asked at every yes (17 times in five seconds in a probe), where once an hour is the rule.
    fake = FakeKvm(FakeState(fingerbot=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: watched(client, device)["fingerbot"] == {"battery": 100, "low": False}, "its battery was never said")
            sent = fake.state.fingerbot_events_sent
            until = time.monotonic() + 3.0
            while time.monotonic() < until:
                fake.state.fingerbot = not fake.state.fingerbot
                watched(client, device)
                time.sleep(0.1)
            assert fake.state.fingerbot_events_sent >= sent + 10, "the stand-in did not say yes and no: the test proves nothing"
            assert fake.state.battery_asked == 1, f"asked {fake.state.battery_asked} times"
    finally:
        fake.stop()


def test_a_press_cut_off_by_qkvm_stopping_while_the_kvm_is_asked_pressed_nothing(tmp_path: Path) -> None:
    # Stopped while the KVM was only being asked whether a Fingerbot is paired, the log said "it may have been done" of a
    # press that never went out, and the history kept that nobody knows.
    from qkvm import cli
    from tests.test_hardening import LiveWall

    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_event_after=6.0)).start()
    data = tmp_path / "data"
    try:
        with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()["device"]["id"]

            def ask() -> None:
                try:
                    admin.post(f"/api/v1/devices/{device}/actions", json={"action": "fingerbot_power"})
                except httpx.HTTPError:
                    pass

            pressing = threading.Thread(target=ask)
            pressing.start()
            wait_until(lambda: fake.state.key_lines == 1, "the KVM was never asked", timeout=15)
            time.sleep(0.5)
            live._server.should_exit = True
            pressing.join(30)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        pressed = [(line["event"], line.get("error")) for line in lines if line["event"] in ("action", "action_failed")]
        assert pressed == [("action_failed", "qKVM was stopped before the press went out: nothing was pressed")], pressed
        assert fake.state.presses == []
    finally:
        fake.stop()


# --- from the review of the second round of fixes -------------------------------------------------------------------


def test_a_press_never_answered_leaves_the_fingerbot_alone_from_the_504_on(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # The time a press may last was counted from before it was sent: a press never answered came back as 504 when that
    # time was all but over, and a script that tried again on 504 pressed a second time a second later. It is counted from
    # the moment the wall gives up: the Comet may take the press as late as that.
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 0.5, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_silent=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            _, first = press(client, device, "fingerbot_power")
            assert first.json()["code"] == "timeout", first.text
            gave_up = time.monotonic()
            fake.state.fingerbot_silent = False
            for wait in (0.0, 0.6):  # (the hold: the answer's time, the press's and the arm's: 0.5 + 0.5 + 0 here)
                time.sleep(max(0.0, gave_up + wait - time.monotonic()))
                _, again = press(client, device, "fingerbot_power")
                assert (again.status_code, again.json()["code"]) == (409, "busy"), (wait, again.text)
            time.sleep(max(0.0, gave_up + 1.1 - time.monotonic()))
            assert press(client, device, "fingerbot_power")[1].status_code == 200
            assert len(fake.state.presses) == 2
    finally:
        fake.state.fingerbot_silent = False
        fake.stop()


def test_a_board_button_waits_while_its_fingerbot_may_be_pressing(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Two power buttons of one machine, pressed together: the one undoes the other. After a Fingerbot press with no clear
    # answer, the board's button was pressed at once.
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 1.0, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, atx=True, fingerbot_reply=(502, "<html>Bad Gateway</html>"))).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device), "the Fingerbot was never offered")
            assert press(client, device, "fingerbot_power")[1].json()["code"] == "timeout"
            _, board = press(client, device, "atx_power")
            assert (board.status_code, board.json()["code"]) == (409, "busy") and "Fingerbot" in board.json()["message"], board.text
            assert "atx power" not in fake.state.actions
    finally:
        fake.stop()


def test_a_press_cut_off_by_qkvm_stopping_while_its_click_is_out_may_have_been_done(tmp_path: Path) -> None:
    # The other side of "nothing was pressed" (above): once the click is on its way, a stop says it may have been done.
    from qkvm import cli
    from tests.test_hardening import LiveWall

    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_silent=True)).start()
    data = tmp_path / "data"
    try:
        with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()["device"]["id"]

            def ask() -> None:
                try:
                    admin.post(f"/api/v1/devices/{device}/actions", json={"action": "fingerbot_power"})
                except httpx.HTTPError:
                    pass

            pressing = threading.Thread(target=ask)
            pressing.start()
            wait_until(lambda: len(fake.state.presses) == 1, "the press was never sent", timeout=15)
            time.sleep(0.3)
            live._server.should_exit = True
            pressing.join(30)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        pressed = [(line["event"], line.get("error")) for line in lines if line["event"] in ("action", "action_failed")]
        assert pressed == [("action_failed", "qKVM was stopped or restarted before the machine answered: it may have been done")], pressed
    finally:
        fake.state.fingerbot_silent = False
        fake.stop()


def test_no_battery_question_goes_to_a_fingerbot_that_may_be_pressing(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # (A guard: after a press with no clear answer the Fingerbot is left alone, its battery included, however due.)
    monkeypatch.setattr(kvm, "FINGERBOT_ANSWER", 1.0, raising=False)
    monkeypatch.setattr(kvm, "FINGERBOT_BATTERY_EVERY", 0.2, raising=False)
    monkeypatch.setattr(kvm, "FINGERBOT_BATTERY_RETRY", 0.2, raising=False)
    fake = FakeKvm(FakeState(fingerbot=True, fingerbot_reply=(200, '{"ok": true, "result": {}}'))).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: offered(client, device) and fake.state.battery_asked >= 2, "the battery was never asked")
            assert press(client, device, "fingerbot_power")[1].json()["code"] == "timeout"
            gave_up = time.monotonic()
            while time.monotonic() < gave_up + 1.4:  # (held: 1.0 + 0.5 + 0)
                watched(client, device)
                time.sleep(0.05)
            assert not [at for at in fake.state.battery_at if gave_up < at < gave_up + 1.4], "the battery was asked while the Fingerbot may have been pressing"
            asked = fake.state.battery_asked
            wait_until(lambda: watched(client, device) and fake.state.battery_asked > asked, "the battery was never asked again after the hold")
    finally:
        fake.stop()


def test_a_none_said_again_on_the_held_line_keeps_standing(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # (A guard: a "none" the KVM says again on the line held for its picture is as fresh as the last time it said it, and
    # no line is opened to ask it once the first word is older than the time it stands for.)
    monkeypatch.setattr(kvm, "FINGERBOT_ASK_AGAIN", 1.0, raising=False)
    fake = FakeKvm(FakeState(fingerbot_resend=0.3)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            until = time.monotonic() + 2.0
            while time.monotonic() < until:
                watched(client, device)
                time.sleep(0.1)
            _, reply = press(client, device, "fingerbot_power")
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
            assert fake.state.ws_streams.count("0") == 0
    finally:
        fake.stop()
