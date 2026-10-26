"""The screen of a server whose controller runs OpenBMC: its console, the WebSocket /kvm/0, signed in with the tile's
Redfish session, carrying RFB from obmc-ikvm; one of four seats, held while somebody looks.

Against the stand-in (fake_redfish.py, layout "openbmc"), built from bmcweb's source; test_controllers.py asks OpenBMC's
romulus image in QEMU about the console's sign-in where one is named in the environment (that build has no console).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, redfish, update, vault, vncdevice
from qkvm.kvm import REJECTED, DeviceSpec, KvmError
from qkvm.openbmc import OpenBmcScreen
from qkvm.redfish import RedfishDevice
from tests.fake_redfish import BmcState, FakeBmc
from tests.fake_vnc import VncState
from tests.test_redfish import status_of
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(OpenBmcScreen, "LOOK_PACE", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    REJECTED.clear()
    vncdevice._PACED.clear()


def ikvm(**manners: Any) -> VncState:
    """obmc-ikvm as the stand-in has it: no password, full frames at its own pace whatever is asked."""
    return VncState(**{"password": None, "width": 320, "height": 240, "name": "obmc-ikvm", "pushes": True, "push_every": 0.2, **manners})


def an_openbmc(**state: Any) -> FakeBmc:
    return FakeBmc(BmcState(**{"layout": "openbmc", "kvm_screen": ikvm(), **state})).start()


def a_server(bmc: FakeBmc) -> RedfishDevice:
    return RedfishDevice(DeviceSpec(id="ab12", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))


async def picture_of(device: Any, within: float = 15.0) -> kvm.Snapshot:
    deadline = time.monotonic() + within
    while True:
        try:
            return await device.snapshot(4000)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.05)


def test_a_server_under_openbmc_shows_its_screen_through_its_console(tmp_path: Path) -> None:
    bmc = an_openbmc()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert status["screen"] is True and status["server"]["rfb_console"] == "/kvm/0"
            assert "screen" in status["can"] and "live" in status["can"] and "control" not in status["can"]  # (no keyboard there yet)

            def arrived() -> bool:
                return bool(client.get(snap(device)).status_code == 200)

            wait_until(arrived, "the server's screen never came", timeout=20)
            frame = client.get(snap(device))
            assert frame.content[:3] == b"\xff\xd8\xff"
            wait_until(lambda: client.get("/api/v1/status").json()[device]["video"]["width"] == 320, "the screen's size is not said")
            # Signed in with the session the tile holds: no second sign-in, the token in the upgrade's header, one seat.
            assert bmc.state.logins == 1 and bmc.state.kvm_upgrades == ["token"] and bmc.state.kvm_open == 1
            assert bmc.state.kvm_screen.password_tries == 0 and bmc.state.kvm_screen.shared == [1]
            assert bmc.state.web_logins == 0  # (no AMI web page on a controller of another make)
        # The tile gone (the wall stopped): its seat is given back, and before the session it was opened with.
        wait_until(lambda: bmc.state.signed_out == 1, "the session was not given back")
        assert bmc.state.kvm_open == 0 and bmc.state.kvm_open_at_sign_out == [0]
    finally:
        bmc.stop()


def test_a_console_whose_vnc_server_is_not_there_is_said_on_the_tile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.2, 60.0))  # (as for its other console: half a minute, a minute, ...)
    bmc = an_openbmc(kvm_screen=None)  # bmcweb takes the upgrade and closes it: no obmc-ikvm behind it
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            deadline = time.monotonic() + 20
            said = None
            while time.monotonic() < deadline and said is None:
                assert client.get(snap(device)).status_code != 200
                said = client.get("/api/v1/status").json()[device]["server"]["no_screen"]
                time.sleep(0.1)
            assert said is not None  # said on the tile, after a few tries
            status = client.get("/api/v1/status").json()[device]
            assert status["screen"] is False and status["state"] == "online"  # the server is there; only its screen is not
            tries = len(bmc.state.kvm_upgrades)
            time.sleep(1.0)
            assert len(bmc.state.kvm_upgrades) - tries <= 1  # asked again less and less often
            assert bmc.state.logins == 1
    finally:
        bmc.stop()


def test_a_manager_read_that_failed_once_does_not_hide_the_console_or_send_the_password_to_another_makers_page(monkeypatch: pytest.MonkeyPatch) -> None:
    # The controller's own resource answered an error of the moment at the first look: kept as "nothing" for ten minutes,
    # the console it announces was not known, a picture went down the road of AMI's console, whose door bmcweb answers
    # 401 as AMI's does (sign in first), and the controller's password was sent to an AMI web page that is not there,
    # answered 401, and counted as a no: "the controller's web page rejected the login".
    monkeypatch.setattr(redfish, "ABOUT_RETRY", 0.3, raising=False)  # (not there before the fix: added, unused)
    bmc = an_openbmc(manager_fails=1)

    async def run() -> None:
        device = a_server(bmc)
        # (Its numbers known, as for a tile added before: what this is about is what the controller is, not which one.)
        device.spec.machine = str(redfish.own_number({"UUID": bmc.state.uuid})) + str(redfish.controller_number({"UUID": bmc.state.root_uuid}))
        try:
            await device.status()  # (the first look: the manager's read failed)
            assert bmc.state.manager_reads == 1
            snap = await picture_of(device)
            assert snap.data[:3] == b"\xff\xd8\xff"
            assert bmc.state.manager_reads >= 2 and bmc.state.kvm_upgrades  # read again, soon: the picture came from the console
            assert bmc.state.web_asked == []  # nothing was asked of a web page this controller has not got...
            assert REJECTED.times(REJECTED.what("web", device.spec)) == 0  # ...and nothing counted against the password there
            assert bmc.state.logins == 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        bmc.stop()


def test_an_openbmc_controller_without_its_console_is_not_taken_for_another_makers(tmp_path: Path) -> None:
    # As OpenBMC's romulus image in QEMU: its manager says it is OpenBmc and announces no console. Asked for a picture, the
    # road of AMI's console was taken, whose door bmcweb answers 401 (sign in first), so it seemed to be there, and the
    # controller's password went to a sign-in that is not there and was counted as a no.
    bmc = an_openbmc(graphical_console=False)
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert status["screen"] is False and status["server"]["rfb_console"] is None and "live" not in status["can"]
            for _ in range(10):
                assert client.get(snap(device)).status_code != 200
                time.sleep(0.05)
            assert client.get("/api/v1/status").json()[device]["screen"] is False
            assert bmc.state.web_asked == [] and bmc.state.kvm_upgrades == []  # (the password went to Redfish's sign-in, and nowhere else)
    finally:
        bmc.stop()


def test_a_console_that_asks_for_a_password_is_answered_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    # The only password here is the controller's own, which goes to its sign-in and nowhere else: not as a VNC answer.
    bmc = an_openbmc(kvm_screen=ikvm(password="secret"))

    async def run() -> None:
        device = a_server(bmc)
        try:
            await device.status()
            with pytest.raises(KvmError) as refused:
                await picture_of(device)
            assert refused.value.code == "bad_response" and "does not let qKVM in" in refused.value.message
            assert bmc.state.kvm_screen.password_tries == 0
            assert REJECTED.times(REJECTED.what("login", device.spec)) == 0  # nor is the controller's password blamed
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        bmc.stop()


def test_a_session_the_controller_forgot_is_signed_in_again_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OpenBmcScreen, "LET_GO_AFTER", 0.5)
    bmc = an_openbmc()

    async def run() -> None:
        device = a_server(bmc)
        try:
            await device.status()
            await picture_of(device)
            deadline = time.monotonic() + 5
            while bmc.state.kvm_open and time.monotonic() < deadline:  # nobody looks: the seat is given back
                await asyncio.sleep(0.05)
            assert bmc.state.kvm_open == 0
            bmc.state.tokens.clear()  # the controller restarted, say, and forgot every session
            await picture_of(device)
            assert bmc.state.logins == 2 and bmc.state.kvm_upgrades == ["token", "token", "token"]  # (the second refused, once)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        bmc.stop()


def test_a_controller_with_every_seat_taken_is_said_so(tmp_path: Path) -> None:
    bmc = an_openbmc(kvm_seats=0)
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            for _ in range(20):
                reply = client.get(snap(device))
                assert reply.status_code != 200
                time.sleep(0.05)
            assert bmc.state.kvm_open == 0
    finally:
        bmc.stop()


def test_a_server_under_openbmc_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_live import Wall

    monkeypatch.setattr(OpenBmcScreen, "LIVE_PACE", 0.02)
    bmc = an_openbmc()
    try:
        with Wall(tmp_path) as live_wall:
            admin = live_wall.browser()
            device = live_wall.add(admin, bmc.url, kind="redfish")
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the server's screen is not said to be there")
            line = live_wall.line(admin, device, max_fps=5)
            assert line.word("video", timeout=20) == {"t": "video", "codec": "jpeg", "w": 320, "h": 240}
            came = line.picture(timeout=20)
            assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
            line.say(t="control", on=True)
            refused = line.word("control")
            assert refused["on"] is False and refused["code"] == "no_input"  # (no keyboard on a server's console yet)
            line.close()
    finally:
        bmc.stop()


def test_a_console_refused_to_the_account_leaves_no_session_behind_and_sends_no_password_again(monkeypatch: pytest.MonkeyPatch) -> None:
    # The console's upgrade answered 401 while the session is good for everything else: the console is refused to this
    # account. Asked whether the session still holds, the controller says it does: nothing is signed in again. (Signed in
    # again at every such answer, the password went out each time and every refusal left a session on the controller.)
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.3, 0.6, 60.0))
    bmc = an_openbmc(kvm_refuses=True)

    async def run() -> None:
        device = a_server(bmc)
        try:
            await device.status()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert bmc.state.logins == 1 and len(bmc.state.tokens) == 1, (bmc.state.logins, len(bmc.state.tokens))
            assert len(bmc.state.kvm_upgrades) <= 3  # (and asked less and less often: 0.3, 0.6, then a minute)
            assert device.console_readable is False  # said: there is no screen to be had just now
        finally:
            await device.close()
        assert bmc.state.tokens == {}  # the one session given back

    try:
        asyncio.run(run())
    finally:
        bmc.stop()


def test_a_console_whose_upgrade_fails_is_asked_for_less_and_less_often(monkeypatch: pytest.MonkeyPatch) -> None:
    # The upgrade itself not answered, or the connection refused: on the console's own ladder, as a session that failed later is.
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.3, 60.0))
    asked: list[float] = []

    async def refused(*_: Any, **__: Any) -> Any:
        asked.append(time.monotonic())
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(redfish, "ws_connect", refused)
    bmc = an_openbmc()

    async def run() -> None:
        device = a_server(bmc)
        try:
            await device.status()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert len(asked) <= 2, f"{len(asked)} upgrades in three seconds"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        bmc.stop()
