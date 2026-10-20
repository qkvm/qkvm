"""Stock PiKVM: kvmd as its own test environment answered (kvmd 4.226, see tools/pikvm-testenv.md), where that differs
from GL.iNet's firmware, which the kvmd driver was built against. The stand-in is fake_kvm's stock mode.

What was found there and is held here: it says what it is in /api/info, not at GL.iNet's routes, which it has not got
(nor a restart of itself, nor Wake-on-LAN); its session is not to be put in the address of its event line, where its
log writes it down; its streamer runs on for a while after somebody else's viewer has gone, and is held from the
wall's first picture on; keep-awake that its settings switch off is not offered. And what it does differently that the
driver already took as it comes: its session as a cookie only, 403 for a session it has forgotten, its health under
`hw`, an empty switch, a Redfish root of its own, and a media line that answers 502 while kvmd-media is not running.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import discover, kvm, live, update, vault
from qkvm.discover import Target
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Wall, a_jpeg
from tests.test_wall import add, snap, wait_until, wall

# (A live line is opened and held by a `Viewer` for as long as a test wants it, not in a `with`: the library would rather it were.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(live, "STANDING_EVERY", 0.2)


@pytest.fixture
def stock() -> Iterator[FakeKvm]:
    """A stock PiKVM: its streamer idle until somebody holds /api/ws open, as kvmd's is, and its pictures JPEG."""
    fake = FakeKvm(FakeState(stock=True, idle_until_viewer=True, picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    yield fake
    fake.stop()


def looked_at(admin: object, device: str) -> dict:
    """The status, once a look at the device has got through (its `can` then says what the look found)."""
    status: dict = {}

    def came() -> bool:
        status.update(admin.get("/api/v1/status").json()[device])  # type: ignore[attr-defined]
        return status.get("state") == "online"

    wait_until(came, "the KVM was never seen online")
    return status


def test_a_stock_pikvm_is_named_and_described_by_what_its_info_says(tmp_path: Path, stock: FakeKvm) -> None:
    # GL.iNet's firmware says its model and version at a route of its own, which stock kvmd has not got: there, the
    # tile said nothing of what it was. kvmd says it in /api/info: the platform's model, its own version, its name.
    stock.state.server_host = "rack-3-kvm"
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/devices", json={"url": stock.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        assert reply.json()["about"] == {"model": "test_model", "version": "kvmd 4.226", "hostname": "rack-3-kvm"}
        assert reply.json()["device"]["name"] == "rack-3-kvm" and reply.json()["device"]["kind"] == "kvmd"
        device = reply.json()["device"]["id"]
        assert looked_at(admin, device)["about"] == {"model": "test_model", "version": "kvmd 4.226"}

        # One that goes by kvmd's own name for itself is named by its address, as a Comet that goes by "glkvm" is.
        other =FakeKvm(FakeState(stock=True, server_host="pikvm")).start()
        try:
            reply = admin.post("/api/v1/devices", json={"url": other.url, "password": "secret"})
            assert reply.json()["device"]["name"] == f"127.0.0.1:{other.port}"
        finally:
            other.stop()


def test_what_a_stock_pikvm_says_it_is_is_taken_by_kind_and_cut(tmp_path: Path, stock: FakeKvm) -> None:
    stock.state.platform = {"model": ["v4plus"], "base": "Raspberry Pi"}  # not a text
    stock.state.kvmd_version = {"major": 4}
    stock.state.server_host = "a name\nthat goes on " + "and on " * 40
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/devices", json={"url": stock.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        about = reply.json()["about"]
        assert about["model"] is None and about["version"] is None
        assert "\n" not in about["hostname"] and len(about["hostname"]) <= 80
        assert looked_at(admin, reply.json()["device"]["id"])["about"] == {"model": None, "version": None}
        # A model far too long is cut; a version that is a number is said as one.
        other = FakeKvm(FakeState(stock=True, platform={"model": "x" * 500}, kvmd_version=4.226)).start()
        try:
            device = add(admin, other.url)
            assert looked_at(admin, device)["about"] == {"model": "x" * 40, "version": "kvmd 4.226"}
        finally:
            other.stop()


def test_a_stock_pikvm_is_offered_neither_a_restart_nor_wake_on_lan_which_it_has_not_got(tmp_path: Path, stock: FakeKvm) -> None:
    # Both are GL.iNet's own routes. Offered on a stock PiKVM, each was pressed and answered "The device refused (HTTP 404)".
    stock.state.atx = True
    with wall(tmp_path) as admin:
        device = add(admin, stock.url)
        can = looked_at(admin, device)["can"]
        assert "reboot" not in can and "wol" not in can
        assert {"screen", "keys", "text", "jiggler", "power", "reset", "live", "control"} <= set(can)
        assert admin.get("/api/v1/wall").json()["devices"][0]["can"] == can
        for body in ({"action": "reboot"}, {"action": "wol", "mac": "52:54:00:12:34:56"}):
            reply = admin.post(f"/api/v1/devices/{device}/actions", json=body)
            assert reply.status_code == 422 and reply.json()["code"] == "invalid", reply.text
        assert admin.get(f"/api/v1/devices/{device}/wol").json() == {"targets": []}
        assert not [asked for asked in stock.state.asked if "/upgrade/reboot" in asked or "/wol/" in asked]
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power"}).status_code == 200
        assert stock.state.actions == ["atx power"]


def test_a_glkvm_is_still_offered_its_restart_and_wake_on_lan(tmp_path: Path) -> None:
    comet = FakeKvm(FakeState(wol=[{"mac": "52:54:00:12:34:56", "name": "desk"}])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, comet.url)
            can = looked_at(admin, device)["can"]
            assert "reboot" in can and "wol" in can
            assert admin.get(f"/api/v1/devices/{device}/wol").json() == {"targets": [{"mac": "52:54:00:12:34:56", "name": "desk"}]}
            for body in ({"action": "wol", "mac": "52:54:00:12:34:56"}, {"action": "reboot"}):
                assert admin.post(f"/api/v1/devices/{device}/actions", json=body).status_code == 200
            assert comet.state.actions == ["wol 52:54:00:12:34:56", "reboot"]
    finally:
        comet.stop()


def test_the_session_of_a_stock_pikvm_is_not_put_in_the_address_of_its_event_line(tmp_path: Path, stock: FakeKvm) -> None:
    # GL.iNet's own page sends it both ways, and so does the wall to a Comet. Stock kvmd takes the cookie, and writes
    # the address of every request into its log: the wall's session to it stood there, for whoever reads that log.
    with Wall(tmp_path) as wall_:
        admin = wall_.browser()
        device = wall_.add(admin, stock.url)
        looked_at(admin, device)
        wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture came", timeout=10)  # (the stream is woken through /api/ws)
        line = wall_.line(admin, device, video=["jpeg"])
        line.picture()
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x04, d=True)
        line.say(t="k", u=0x04, d=False)
        wait_until(lambda: [said["event"] for said in stock.state.hid if said["event_type"] == "key"] == [{"key": "KeyA", "state": True}, {"key": "KeyA", "state": False}], "the keys never came")
        line.close()
        queries = list(stock.state.ws_queries)
        assert not [query for query in queries if "auth_token" in query], queries
        assert "stream=1" in queries and "stream=0" in queries, queries  # the stream held for the picture, and the line for keys


def test_the_session_is_not_put_in_the_address_while_it_is_not_known_whether_the_kvm_is_a_glkvm(tmp_path: Path, stock: FakeKvm) -> None:
    # Which of the two it is, is found out from its answer at a route of GL.iNet's own. While that answer is an error of the
    # moment, it is not known: the session went into the address all the same, and stock kvmd's log wrote it down.
    stock.state.version_fails = 10**6  # (its web server answers that route 502 for as long as this test lasts)
    with Wall(tmp_path) as wall_:
        admin = wall_.browser()
        device = wall_.add(admin, stock.url)
        looked_at(admin, device)
        wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture came", timeout=10)  # (the stream is woken through /api/ws)
        line = wall_.line(admin, device, video=["jpeg"])
        line.picture()
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x04, d=True)
        line.say(t="k", u=0x04, d=False)
        wait_until(lambda: [said["event"] for said in stock.state.hid if said["event_type"] == "key"] == [{"key": "KeyA", "state": True}, {"key": "KeyA", "state": False}], "the keys never came")
        line.close()
        assert "GET /api/upgrade/version" in stock.state.asked  # (it was asked, and the answer said neither)
        queries = list(stock.state.ws_queries)
        assert "stream=1" in queries and "stream=0" in queries, queries
        assert not [query for query in queries if "auth_token" in query], queries


def test_the_session_still_goes_both_ways_to_a_glkvm(tmp_path: Path) -> None:
    comet = FakeKvm(FakeState(idle_until_viewer=True)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, comet.url)
            looked_at(admin, device)
            wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture came", timeout=10)
            assert [query for query in comet.state.ws_queries if query.startswith("stream=1&auth_token=")], list(comet.state.ws_queries)
    finally:
        comet.stop()


def test_the_streamer_is_held_from_the_first_picture_on_though_somebody_else_had_it_running(tmp_path: Path, stock: FakeKvm) -> None:
    # Somebody's own page had the KVM's stream open and has just been closed: kvmd's streamer goes on by itself for ten
    # seconds, and then stops. The wall held it only once a picture had been refused, so its pictures came, then for a
    # moment none ("waking it up"), and then the KVM's own placeholder, "no live video", while its streamer started again.
    stock.state.streamer_until = time.monotonic() + 600  # still running, with nobody
    with wall(tmp_path) as admin:
        device = add(admin, stock.url)
        looked_at(admin, device)
        assert admin.get(snap(device)).status_code == 200
        wait_until(lambda: stock.state.streams == 1, "the wall did not hold the KVM's stream while it took its pictures")
        stock.state.streamer_until = 0.0  # the ten seconds are over
        for _ in range(5):
            assert admin.get(snap(device)).status_code == 200


def test_keep_awake_that_a_stock_pikvm_has_switched_off_is_not_offered(tmp_path: Path, stock: FakeKvm) -> None:
    # Switched off in kvmd's settings, it answers yes to being switched on and does nothing: the wall said "done".
    stock.state.jiggler_enabled = False
    with wall(tmp_path) as admin:
        device = add(admin, stock.url)
        assert "jiggler" not in looked_at(admin, device)["can"]
        reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "jiggler_on"})
        assert reply.status_code == 422 and reply.json()["code"] == "invalid", reply.text
        assert not [asked for asked in stock.state.asked if "set_params" in asked]
        stock.state.jiggler_enabled = True  # switched on in its settings since
        wait_until(lambda: "jiggler" in admin.get("/api/v1/status").json()[device]["can"], "keep-awake was never offered")
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "jiggler_on"}).status_code == 200
        assert stock.state.jiggler is True


def test_a_stock_pikvm_as_it_answers(tmp_path: Path, stock: FakeKvm) -> None:
    """What stock kvmd does otherwise than GL.iNet's firmware, and the driver already took as it comes."""
    stock.state.atx = True
    with wall(tmp_path) as admin:
        device = add(admin, stock.url)  # (found to be a kvmd, though it answers a Redfish root as well: see below)
        assert admin.get("/api/v1/wall").json()["devices"][0]["kind"] == "kvmd"
        assert stock.state.logins == 1 and stock.state.tokens  # its session came as a cookie, and nothing else
        status = looked_at(admin, device)
        assert status["health"] == {"temp": 42.5, "cpu": 17, "mem": 39.5}  # under `hw`, where stock kvmd keeps it
        assert status["usb"] == {"keyboard": True, "mouse": True} and status["atx"] == {"enabled": True, "power": True, "hdd": False}
        assert status["ports"] is None and "ports" not in status["can"]  # an empty switch is none
        wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture came", timeout=10)  # 503 until /api/ws is held
        assert stock.state.streams == 1
        wait_until(lambda: admin.get("/api/v1/status").json()[device]["video"]["width"] == 1920, "the video was never described")
        for body in ({"action": "keys", "keys": "ControlLeft,AltLeft,Delete"}, {"action": "text", "text": "hello"}, {"action": "jiggler_on"}):
            assert admin.post(f"/api/v1/devices/{device}/actions", json=body).status_code == 200
        assert stock.state.actions == ["shortcut ControlLeft,AltLeft,Delete", "type 'hello'", "jiggler 1"]
        # kvmd was restarted, and has forgotten every session: 403 for the one the wall has, and it signs in again, once.
        stock.state.tokens.clear()
        wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online" and stock.state.logins == 2, "it did not sign in again")
        assert admin.get(snap(device)).status_code == 200
        assert stock.state.logins == 2


def test_a_stock_pikvm_that_rejects_the_password_says_so(tmp_path: Path, stock: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/devices", json={"url": stock.url, "password": "wrong"})
        assert reply.status_code == 422 and reply.json()["code"] == "auth_failed", reply.text  # 403 at its login


def test_a_stock_pikvm_is_found_by_the_search_and_is_no_server_for_its_redfish_root(tmp_path: Path, stock: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Stock kvmd answers a Redfish service root to anybody, at /redfish/v1 (and sends /redfish/v1/ there). It is a KVM.
    monkeypatch.setattr(discover, "targets", lambda: ([Target("127.0.0.1", stock.url, "http://127.0.0.1:9", "pikvm")], ["test network"]))
    with wall(tmp_path) as admin:
        found = admin.post("/api/v1/discover").json()["found"]
        assert [(each["kind"], each["url"]) for each in found] == [("kvmd", stock.url)]
        assert stock.state.logins == 0


def test_a_stock_pikvm_without_its_media_service_gives_its_pictures_one_by_one(tmp_path: Path, stock: FakeKvm) -> None:
    # Its nginx has the H.264 line, and answers 502 while kvmd-media is not running (its test environment does not start
    # it). That is a KVM with no H.264 line for the moment: a viewer that can show JPEG gets that.
    with Wall(tmp_path) as wall_:
        admin = wall_.browser()
        device = wall_.add(admin, stock.url)
        line = wall_.line(admin, device)  # (asks for H.264 first, then JPEG)
        assert line.word("video", timeout=10)["codec"] == "jpeg"
        assert line.picture(timeout=10).kind == 2
        line.close()


# --- what the fresh reviewer found in the above ------------------------------------------------------------------


def a_client(fake: FakeKvm) -> kvm.KvmDevice:
    return kvm.KvmDevice(kvm.DeviceSpec(id="k", name="kvm", base_url=fake.url, username="admin", password="secret"))


def test_a_client_taken_off_the_wall_opens_no_line_to_hold_the_kvms_stream(stock: FakeKvm) -> None:
    # A picture still asked of a client that was retired (its tile edited or removed while the request waited) began a
    # keepalive before it found out: a line to the KVM with the old session, holding its streamer, that nothing stopped.
    async def run() -> None:
        device = a_client(stock)
        stock.state.streamer_until = time.monotonic() + 600  # (pictures come without anybody holding the stream)
        await device.live_picture("640")
        await device.close()
        stock.state.ws_queries.clear()
        with pytest.raises(kvm.KvmError) as stopped:
            await device.live_picture("640")
        assert stopped.value.code == "no_stream"  # RETIRED: the tile asks again, and reaches the client that replaced it
        await asyncio.sleep(0.5)
        assert list(stock.state.ws_queries) == []

    asyncio.run(run())


def test_a_kvm_that_refuses_the_line_for_its_stream_is_not_asked_for_it_at_every_picture(stock: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # It gives pictures and refuses /api/ws (a proxy in front of it that passes no WebSocket on, say): every picture began
    # another attempt, thirty a second for a live line. Now again only after a pause that grows, as for a device that is down.
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)
    stock.state.streamer_until = time.monotonic() + 600
    stock.state.ws_moved = "ws://127.0.0.1:9/elsewhere"

    async def run() -> None:
        device = a_client(stock)
        try:
            for _ in range(10):
                await device.live_picture("640")
                await asyncio.sleep(0.08)
        finally:
            await device.close()

    asyncio.run(run())
    assert 1 <= len(stock.state.ws_queries) <= 2, list(stock.state.ws_queries)


def test_the_session_stays_out_of_the_address_before_the_first_look_too(stock: FakeKvm) -> None:
    # A client that has not looked at the KVM yet (qKVM just started, or the tile was just saved) put the session in the
    # address while it did not know the family, and a stock kvmd's log wrote it down. It asks first.
    async def run() -> None:
        device = a_client(stock)
        try:
            line = await device.input_line()
            await line.close()
        finally:
            await device.close()

    asyncio.run(run())
    assert list(stock.state.ws_queries) == ["stream=0"]


def test_one_odd_answer_does_not_hide_a_glkvms_restart_and_wake_on_lan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # One 500 from its version route left the family unknown for ten minutes, and its tile without its restart and its
    # Wake-on-LAN meanwhile, while either could still be sent. Unknown is offered as before, and asked again soon.
    monkeypatch.setattr(kvm, "ABOUT_RETRY", 0.0)
    comet = FakeKvm(FakeState(version_fails=2)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, comet.url)  # (one 500 at adding it, one at its first look)
            assert {"reboot", "wol"} <= set(looked_at(admin, device)["can"])
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["about"]["model"] == "RM10", "it was not asked again")
    finally:
        comet.stop()


def test_a_glkvm_whose_version_sends_qkvm_nowhere_can_be_added(tmp_path: Path) -> None:
    # Its version route answering with a redirect to what is no address was "no version" before, and became a failure to add it.
    comet = FakeKvm(FakeState(version_moved="http:x")).start()
    try:
        with wall(tmp_path) as admin:
            reply = admin.post("/api/v1/devices", json={"url": comet.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            assert reply.json()["about"]["version"] is None
    finally:
        comet.stop()


def test_a_picture_is_not_held_back_while_the_kvm_is_asked_which_family_it_is(stock: FakeKvm) -> None:
    # (The reviewer's second reading.) The family was asked on the picture's own way, before it was handed over: a version
    # route slow to answer held the picture back as long, and handed it over as new when it was that old. It is asked in
    # the task that holds the stream, and the session still stays out of its address.
    stock.state.streamer_until = time.monotonic() + 600
    stock.state.slow["/api/upgrade/version"] = 3.0

    async def run() -> float:
        device = a_client(stock)
        try:
            began = time.monotonic()
            await device.live_picture("640")
            took = time.monotonic() - began
            for _ in range(100):  # the line that holds the stream, once the family is known
                if stock.state.ws_queries:
                    break
                await asyncio.sleep(0.1)
            return took
        finally:
            await device.close()

    took = asyncio.run(run())
    assert took < 2.0, f"the picture came after {took:.1f} s"
    assert list(stock.state.ws_queries) == ["stream=1"]


def test_the_line_that_holds_the_stream_goes_with_the_session_the_family_question_brought() -> None:
    # (The reviewer's third reading.) The session was taken before the KVM was asked which family it is. A GLKVM asks who
    # is asking first: where the question found the session gone (the KVM restarted) and signed in anew, the line went
    # with the old session, and was refused. (Stock kvmd answers that question before it asks: there it does not arise.)
    comet = FakeKvm(FakeState()).start()

    async def run() -> int:
        device = a_client(comet)
        try:
            device._token = "0" * 32  # (a session it has forgotten)
            device._wanted_at = time.monotonic()
            device._start_keepalive()
            for _ in range(40):
                if comet.state.streams:
                    break
                await asyncio.sleep(0.05)
            return comet.state.streams
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == 1, f"the line that holds the stream was refused: {list(comet.state.ws_queries)}"
        assert comet.state.logins == 1
    finally:
        comet.stop()
