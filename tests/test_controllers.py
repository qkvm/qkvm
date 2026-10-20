"""Servers through controllers of other makes, without hardware.

The Redfish driver was built from what two AMI MegaRAC boards report (see fake_redfish.py). Here it meets
the layouts of other makers and of the standard itself: the stand-in laid out as OpenBMC's bmcweb lays
things out (its names, the newer shape of the sensors, a reset whose kinds are said in a ResetActionInfo),
a chassis list that begins with a disk enclosure (as iDRAC's does), a controller that answers an error
with HTTP 200; and, where an address for one is given in the environment, each maker's own emulator or
capture, served on this computer's loopback:

    QKVM_TEST_RACKMOUNT  DMTF's Redfish-Mockup-Server serving DSP2043's public-rackmount1: the standard's own example
    QKVM_TEST_IDRAC      the same server serving a Dell iDRAC9 capture out of dell/iDRAC-Redfish-Scripting
    QKVM_TEST_ILO        HPE's ilo-redfish-emulator (an iLO 5 on a DL360 Gen10 Plus), over its own HTTPS
    QKVM_TEST_SUSHY      sushy-tools with its fake systems driver: the standard's shapes, and power that really switches, a few seconds late
    QKVM_TEST_OPENBMC    OpenBMC's romulus image in QEMU (bmcweb, root / 0penBmc)
    QKVM_TEST_CAPTURES   the owner's own boards, captured with DMTF's Redfish-Mockup-Creator and served by the
                         mockup server: one address or several, separated by commas

Without an address the test for it is skipped. GitHub's `controllers` job (app/.github/workflows/tests.yml)
starts all but the last and gives their addresses; on a developer's PC they are started by hand (the job
says how) and the captures, which name real boards, stay with the owner.

Some emulators lack a manner of a real controller, and a loopback proxy (`Manners`) stands between the
driver and such an emulator, putting right the one thing named and nothing else: DMTF's mockup server
answers a sign-in with 204 where the standard says 201 (DSP0266: a session is "Created"); HPE's emulator
wants the sign-in itself signed in (Basic) and names no Location for the session it made; sushy-tools has
no session service, so the proxy keeps the sessions and the emulator sees requests without a token. The
driver is not changed for any of these, and the proxy also keeps a list of what went through, which is how
a test sees what the driver sent.

With sushy-tools over libvirt (GitHub's `controllers-libvirt` job) the machine behind it is a guest with
nothing on it, and QKVM_TEST_SUSHY_NO_OS=1 says so: a graceful shutdown is accepted and ignored, as a real
server with nothing on it does, and a reset is not seen as "off" in between.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request, Response

from qkvm import redfish
from qkvm.redfish import fan_of, readings_of, rfb_console
from tests import local_socket
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_redfish import fast, status_of  # noqa: F401  (`fast` is a fixture, and takes effect by being imported)
from tests.test_wall import add, wait_until, wall

# --- the stand-in, laid out as other makers lay things out ------------------------------------------------


def test_the_chassis_the_computer_points_to_is_the_one_whose_sensors_are_read(tmp_path: Path) -> None:
    # An iDRAC lists the disk enclosures as chassis of their own, and may list one first. Those have no
    # sensors: the computer says which chassis is its own, and that one is read.
    bmc = FakeBmc(BmcState(enclosures_first=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert [t["name"] for t in status["server"]["temperatures"]] == ["CPU0_TEMP", "CPU1_TEMP", "DIMM_A_TEMP"]
            assert status["health"]["temp"] == 61 and len(status["server"]["fans"]) == 2
            assert not any("Enclosure" in request for request in bmc.state.requests if request.endswith("/Thermal"))
    finally:
        bmc.stop()


class Trap:
    """Somewhere else on this computer: a listener that counts whoever connects to it, and answers nothing."""

    def __init__(self) -> None:
        self._sock = local_socket()
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        self.hits = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._count, daemon=True)
        self._thread.start()

    def _count(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            self.hits += 1
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


def test_a_chassis_the_computer_claims_somewhere_else_is_not_followed(tmp_path: Path) -> None:
    # What the computer says of its chassis is a link like any other: a place on the controller, or nothing.
    # Said to be elsewhere (here: another listener on this computer, which counts whoever comes), it is not
    # followed there, and the first chassis the controller lists is taken instead.
    elsewhere = Trap()
    bmc = FakeBmc(BmcState(enclosures_first=True, chassis_claimed=f"{elsewhere.url}/redfish/v1/Chassis/Self")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert status["server"]["temperatures"] == [] and status["server"]["fans"] == []  # the enclosure has none
            assert status["server"]["power"] == "On"
            assert any(request.endswith("/Chassis/Enclosure.Internal.0-1") for request in bmc.state.requests)
            assert elsewhere.hits == 0
    finally:
        bmc.stop()
        elsewhere.stop()


def test_a_controller_laid_out_as_openbmc_shows_its_sensors_and_says_where_its_console_is(tmp_path: Path) -> None:
    bmc = FakeBmc(BmcState(layout="openbmc", locating=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            server = status["server"]
            # The temperatures come from ThermalMetrics, named after the sensor each reading points to; no health is said there.
            assert server["temperatures"] == [
                {"name": "temperature_CPU0_TEMP", "celsius": 61, "ok": True},
                {"name": "temperature_CPU1_TEMP", "celsius": 55, "ok": True},
                {"name": "temperature_DIMM_A_TEMP", "celsius": 45, "ok": True},
            ]
            assert status["health"]["temp"] == 61
            # The fans are a collection, each read on its own; one says revolutions, one a share, and the absent one is no fan.
            assert server["fans"] == [
                {"name": "CPU0_FAN", "reading": 1650, "unit": "RPM", "ok": True},
                {"name": "CPU1_FAN", "reading": 18, "unit": "%", "ok": False},
            ]
            assert server["unwell"] == ["CPU1_FAN"]
            assert status["about"] == {"model": "SRV-2200", "version": "1.42.0"}
            # Its console is a WebSocket on the controller that carries RFB: said, and read where a picture is asked for
            # (test_openbmc_console.py); none is asked for here.
            assert server["rfb_console"] == "/kvm/0"
            assert status["console"] is False  # (no page with a pass is handed out, as AMI's controllers do)
            # The locator light is LocationIndicatorActive alone, and the kinds of reset are read from the ResetActionInfo.
            assert server["locator"] is False
            act = f"/api/v1/devices/{device}/actions"
            assert client.post(act, json={"action": "locate_on"}).status_code == 200
            assert bmc.state.changes == [{"LocationIndicatorActive": True}]
            assert client.post(act, json={"action": "atx_power"}).status_code == 200
            assert client.post(act, json={"action": "reboot"}).status_code == 200
            assert bmc.state.actions == ["system GracefulShutdown", "controller ForceRestart"]
            assert bmc.state.web_logins == 0  # no AMI web page is signed in to on a controller of another make
    finally:
        bmc.stop()


def firmware_said(tmp_path: Path, **state: Any) -> tuple[str | None, list[str]]:
    """What the tile says of the firmware of a controller laid out as OpenBMC, and what the controller was asked."""
    bmc = FakeBmc(BmcState(layout="openbmc", **state)).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": bmc.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            on_adding = reply.json()["about"]["version"]
            version = status_of(client, reply.json()["device"]["id"], state="online")["about"]["version"]
            assert on_adding == version
            return version, list(bmc.state.requests)
    finally:
        bmc.stop()


def test_an_openbmc_that_does_not_say_its_version_in_its_manager_says_it_in_its_firmware_inventory(tmp_path: Path) -> None:
    # OpenBMC's romulus image in QEMU (its master of October 2026) says neither its firmware's version nor the image it runs in its Manager:
    # bmcweb says those only where it knows which image runs. Its firmware inventory has the image, with its version,
    # naming the controller as what it is for. The tile said no version at all. (The first in the list is the host's.)
    version, asked = firmware_said(tmp_path / "neither", manager_says="neither")
    assert version == "1.42.0"
    assert "GET /redfish/v1/UpdateService/FirmwareInventory/7ed25e88" in asked
    # Said by the controller, the inventory is not asked; where it names the image it runs, that image is read, and no other.
    version, asked = firmware_said(tmp_path / "both", manager_says="both", firmware="1.43.0")
    assert version == "1.43.0" and not [one for one in asked if "UpdateService" in one]
    version, asked = firmware_said(tmp_path / "image", manager_says="image", images=[("aa11", "BMC", "StandbySpare", "1.41.0"), ("bb22", "BMC", "Enabled", "1.42.7")])
    assert version == "1.42.7" and [one for one in asked if "FirmwareInventory" in one] == ["GET /redfish/v1/UpdateService/FirmwareInventory/bb22"]


@pytest.mark.parametrize(
    ("images", "image_link", "said"),
    [
        # The active one of the controller's images, and not the one standing by, nor the host's.
        ([("aa11", "BMC", "StandbySpare", "1.41.0"), ("cc33", "Host", "Enabled", "9.9"), ("bb22", "BMC", "Enabled", "1.42.0")], None, "1.42.0"),
        # Two active ones that say two versions: which runs is not known, and is not guessed.
        ([("aa11", "BMC", "Enabled", "1.41.0"), ("bb22", "BMC", "Enabled", "1.42.0")], None, None),
        # ...and two that say one version, that one.
        ([("aa11", "BMC", "Enabled", "1.42.0"), ("bb22", "BMC", "Enabled", "1.42.0")], None, "1.42.0"),
        # None active: none.
        ([("aa11", "BMC", "Disabled", "1.42.0")], None, None),
        # An image for another controller, or for a place that is no place on this one, is not this controller's.
        ([("aa11", "BMC", "Enabled", "1.42.0")], "/redfish/v1/Managers/other", None),
        ([("aa11", "BMC", "Enabled", "1.42.0")], "https://elsewhere.example/redfish/v1/Managers/bmc", None),
        ([("aa11", "BMC", "Enabled", "1.42.0")], "/redfish/v1/Managers/../Managers/bmc", None),
        ([("aa11", "BMC", "Enabled", "1.42.0")], ["/redfish/v1/Managers/bmc"], None),
        # A version that is no text is none; a long one is cut, and said on one line.
        ([("aa11", "BMC", "Enabled", {"major": 1})], None, None),
        ([("aa11", "BMC", "Enabled", "1.42.0\n" + "x" * 300)], None, "1.42.0 " + "x" * 33),
    ],
)
def test_the_firmware_inventory_is_read_by_kind_and_only_the_controllers_own_active_image_counts(tmp_path: Path, images: Any, image_link: Any, said: str | None) -> None:
    version, _ = firmware_said(tmp_path, manager_says="neither", images=images, image_link=image_link)
    assert version == said


@pytest.mark.parametrize(
    ("more", "says"),
    [
        ([{"@odata.id": "https://elsewhere.example/redfish/v1/UpdateService/FirmwareInventory/x"}], {}),  # a member not read: it is no place here
        (["/redfish/v1/UpdateService/FirmwareInventory/x"], {}),  # ...nor is a member that is no record
        ([], {"Members@odata.nextLink": "/redfish/v1/UpdateService/FirmwareInventory?$skip=2"}),  # more of them on another page
        ([], {"Members@odata.count": 40}),  # more of them than the list holds
    ],
)
def test_an_inventory_not_all_of_which_can_be_read_says_no_version(tmp_path: Path, more: list[Any], says: dict[str, Any]) -> None:
    # (The reviewer's second reading.) One of its images not read may be the other one that is active.
    version, _ = firmware_said(tmp_path, manager_says="neither", inventory_more=more, inventory_says=says)
    assert version is None


def test_a_long_firmware_inventory_is_not_read(tmp_path: Path) -> None:
    # A controller that lists every piece of firmware it has (some list dozens) is not asked about each of them. Nor is
    # what the first few say taken: one that was not read may be the other active image of the controller (the fresh
    # reviewer's finding: the first of two, the second listed seventeenth, was said to be the one that runs).
    images = [(f"i{at:03}", "Host", "Enabled", f"9.{at}") for at in range(200)] + [("zz", "BMC", "Enabled", "1.42.0")]
    version, asked = firmware_said(tmp_path / "long", manager_says="neither", images=images)
    assert version is None and not [one for one in asked if "/FirmwareInventory/" in one]
    two = [("aa", "BMC", "Enabled", "1.41.0"), *[(f"h{at}", "Host", "Enabled", f"9.{at}") for at in range(redfish.MOST_IMAGES - 1)], ("bb", "BMC", "Enabled", "1.42.0")]
    assert firmware_said(tmp_path / "two", manager_says="neither", images=two)[0] is None
    assert firmware_said(tmp_path / "one", manager_says="neither", images=two[:-1])[0] == "1.41.0"  # (all of them read: that one)


@pytest.mark.parametrize("said_as", ["record", "text"])
def test_an_error_answered_with_200_is_not_taken_for_the_state_of_the_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, said_as: str) -> None:
    # Some controllers say "service unavailable" with HTTP 200 and an error body where the resource belongs,
    # in the standard's shape (a record) or as a bare text. That is one of the controller's moments, like a
    # 503: the tile keeps saying what the last good look found, not "online" with nothing in it.
    monkeypatch.setattr(redfish, "HICCUP", 5.0)
    monkeypatch.setattr(redfish, "RETRY_LOOK", 0.05)
    bmc = FakeBmc(BmcState(errors_in_200=said_as)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            assert status_of(client, device, state="online")["server"]["power"] == "On"
            bmc.state.unwell_until = time.monotonic() + 0.8
            while time.monotonic() < bmc.state.unwell_until:
                status = client.get("/api/v1/status").json()[device]
                assert (status["state"], status["server"]["power"]) == ("online", "On"), status
                time.sleep(0.05)
            status_of(client, device, state="online")
    finally:
        bmc.stop()


@pytest.mark.parametrize("claimed", ["elsewhere", "/redfish/v1/Chassis/chassis/ThermalSubsystem/Fans/fan_CPU0_FAN?x=1", "/redfish/v1/Chassis/chassis/ThermalSubsystem/Fans/fan_CPU0_FAN"])
def test_a_fan_listed_somewhere_else_or_twice_is_not_read(tmp_path: Path, claimed: str) -> None:
    # A fan listed somewhere else (another listener on this computer, counting) is not asked for there. One
    # listed by a path the driver refuses (a query string) would be answered by the stand-in if it were
    # followed, and CPU0_FAN would then be listed twice; the same for one listed twice over, word for word.
    elsewhere = Trap()
    link_claimed = f"{elsewhere.url}/redfish/v1/Chassis/chassis/ThermalSubsystem/Fans/x" if claimed == "elsewhere" else claimed
    bmc = FakeBmc(BmcState(layout="openbmc", fan_claimed=link_claimed)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert [fan["name"] for fan in status["server"]["fans"]] == ["CPU0_FAN", "CPU1_FAN"]
            assert elsewhere.hits == 0
            assert sum(1 for request in bmc.state.requests if request.endswith("/Fans/fan_CPU0_FAN")) == 1
    finally:
        bmc.stop()
        elsewhere.stop()


def test_a_look_does_not_wait_for_every_slow_fan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # In the newer shape every fan is a read of its own. A controller with forty of them that answers each
    # slowly (a byte at a time, a hostile one) would hold one look for twenty minutes, the tile saying the
    # look before all the while. So the sensors get a time within one look: once it is up, no further fan
    # is asked for, and a fan not asked for is not listed. What the time promises is the look's length and
    # that the fans listed are the first ones, in the controller's order; how many got in before it was up
    # depends on the machine, and is not promised.
    monkeypatch.setattr(redfish, "SENSORS_WITHIN", 1.0)
    bmc = FakeBmc(BmcState(layout="openbmc", more_fans=30, fan_takes=0.3)).start()
    try:
        with wall(tmp_path) as client:
            began = time.monotonic()
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert time.monotonic() - began < 6.0  # not the ten seconds thirty-three fans at 0.3 s would take
            listed = [fan["name"] for fan in status["server"]["fans"]]
            in_order = ["CPU0_FAN", "CPU1_FAN", *(f"EXTRA_{n}" for n in range(30))]  # (SYS_FAN5 is absent, and not a fan)
            assert len(listed) <= 6 and listed == in_order[: len(listed)]
            assert status["server"]["temperatures"][0]["celsius"] == 61  # the temperatures, one read, are all there
    finally:
        bmc.stop()


def test_a_look_whose_time_is_up_before_the_list_of_fans_does_not_ask_for_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The time the sensors get is looked at before the list of fans too, not only before each fan: with
    # none at all, the temperatures (one read) are there and nothing about the fans is asked for.
    monkeypatch.setattr(redfish, "SENSORS_WITHIN", 0.0)
    bmc = FakeBmc(BmcState(layout="openbmc")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)

            def looked_at_three_times() -> bool:
                client.get("/api/v1/status")  # (a look is made when the status is asked for)
                return sum(1 for request in bmc.state.requests if request.endswith("/ThermalMetrics")) >= 3

            wait_until(looked_at_three_times, "the server was not looked at three times")
            status = status_of(client, device, state="online")
            assert status["server"]["temperatures"][0]["celsius"] == 61 and status["server"]["fans"] == []
            assert [request for request in bmc.state.requests if "/ThermalSubsystem/Fans" in request] == []
    finally:
        bmc.stop()


def fan_reads(bmc: FakeBmc) -> int:
    return sum(1 for request in bmc.state.requests if "/ThermalSubsystem/Fans/" in request)


def test_a_fan_the_look_had_no_time_for_keeps_what_was_last_read_of_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A controller that turns slow must not make a fan that is not well drop off the tile: a look that
    # has no time left for a fan keeps what the last look read of it, and the fans not read for longest
    # are asked for first, so that every fan is read again in turn.
    monkeypatch.setattr(redfish, "SENSORS_WITHIN", 1.0)
    bmc = FakeBmc(BmcState(layout="openbmc", more_fans=6, last_fan_unwell=True)).start()
    every = ["CPU0_FAN", "CPU1_FAN", *(f"EXTRA_{n}" for n in range(6))]
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert [fan["name"] for fan in status["server"]["fans"]] == every and status["server"]["unwell"] == ["CPU1_FAN", "EXTRA_5"]
            bmc.state.fan_takes = 0.4  # from now on a look has time for two or three fans, not eight
            read_before = fan_reads(bmc)

            def read_again_twice_over() -> bool:
                client.get("/api/v1/status")  # (a look is made when the status is asked for)
                return fan_reads(bmc) - read_before >= 2 * len(every)

            wait_until(read_again_twice_over, "the fans were not all read again in turn", timeout=30)
            for _ in range(10):
                status = client.get("/api/v1/status").json()[device]
                assert [fan["name"] for fan in status["server"]["fans"]] == every, status["server"]["fans"]
                assert status["server"]["unwell"] == ["CPU1_FAN", "EXTRA_5"]
                time.sleep(0.2)
            # Every one of them was asked for again, the last ones in the list too.
            assert all(any(request.endswith(f"/Fans/fan_{name}") for request in bmc.state.requests[read_before:]) for name in every)
    finally:
        bmc.stop()


def test_a_reading_in_the_newer_shape_can_be_unwell_too(tmp_path: Path) -> None:
    # A reading in ThermalMetrics may carry its health, as a temperature in Thermal does; one that says
    # it is not well is named among the unwell, as in the older shape. (Without one, a reading is well.)
    bmc = FakeBmc(BmcState(layout="openbmc", temperature_health="Critical")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status = status_of(client, device, state="online")
            assert status["server"]["temperatures"][0] == {"name": "temperature_CPU0_TEMP", "celsius": 61, "ok": False}
            assert status["server"]["unwell"] == ["temperature_CPU0_TEMP", "CPU1_FAN"]
    finally:
        bmc.stop()


def test_what_a_controller_says_in_the_newer_shape_is_taken_by_kind() -> None:
    readings = readings_of({"TemperatureReadingsCelsius": [
        {"Reading": 41.5, "DeviceName": "Intake", "DataSourceUri": "/redfish/v1/Chassis/1U/Sensors/IntakeTemp"},  # named by the device, where it is
        {"Reading": 30, "DataSourceUri": "/redfish/v1/Chassis/1U/Sensors/CPU1Temp"},  # else by the sensor the reading points to
        {"Reading": 29, "DataSourceUri": "https://elsewhere.example/redfish/v1/Chassis/1U/Sensors/x"},  # which is a link, or no name
        {"Reading": "hot", "DeviceName": "Exhaust"}, {"Reading": 900, "DeviceName": "Sun"}, {"Reading": None, "DeviceName": "Absent"},  # not readings
        {"DeviceName": "x" * 100, "Reading": 20}, 7, None, "CPU",
        {"DeviceName": "Hot", "Reading": 95, "Status": {"Health": "Critical"}}, {"DeviceName": "Odd", "Reading": 50, "Status": "fine"},  # its health, where said
    ]})  # fmt: skip
    assert readings == [
        {"name": "Intake", "celsius": 41.5, "ok": True}, {"name": "CPU1Temp", "celsius": 30, "ok": True},
        {"name": "", "celsius": 29, "ok": True}, {"name": "x" * 40, "celsius": 20, "ok": True},
        {"name": "Hot", "celsius": 95, "ok": False}, {"name": "Odd", "celsius": 50, "ok": True},
    ]  # fmt: skip
    assert readings_of({"TemperatureReadingsCelsius": {"Reading": 30}}) == [] and readings_of({}) == []
    assert fan_of({"Name": "Fan 1", "SpeedPercent": {"Reading": 45, "SpeedRPM": 2200}, "Status": {"State": "Enabled", "Health": "OK"}}) == {
        "name": "Fan 1", "reading": 2200, "unit": "RPM", "ok": True,
    }  # fmt: skip  (both said: the revolutions, which is what the other shape gives)
    assert fan_of({"Name": "Fan 2", "SpeedPercent": {"Reading": 45}, "Status": {"State": "Enabled", "Health": "Warning"}}) == {"name": "Fan 2", "reading": 45, "unit": "%", "ok": False}
    assert fan_of({"Name": "Fan 3", "SpeedPercent": {"SpeedRPM": "fast"}, "Status": {"State": "Enabled"}}) == {"name": "Fan 3", "reading": None, "unit": "RPM", "ok": True}
    # Revolutions said as nothing beside a share that is a number: the number.
    assert fan_of({"Name": "Fan 6", "SpeedPercent": {"SpeedRPM": None, "Reading": 40}, "Status": {"State": "Enabled"}}) == {"name": "Fan 6", "reading": 40, "unit": "%", "ok": True}
    # Only a share, and that unreadable, or nothing at all: no reading, and not called revolutions.
    assert fan_of({"Name": "Fan 7", "SpeedPercent": {"Reading": "fast"}, "Status": {"State": "Enabled"}}) == {"name": "Fan 7", "reading": None, "unit": "%", "ok": True}
    assert fan_of({"Name": "Fan 8", "SpeedPercent": {}, "Status": {"State": "Enabled"}}) == {"name": "Fan 8", "reading": None, "unit": "%", "ok": True}
    for not_a_fan in ({"Name": "Fan 4", "Status": {"State": "Absent"}}, {"Name": "Fan 5"}, {"SpeedPercent": 3, "Status": {"State": "Enabled"}}, [], None):
        assert fan_of(not_a_fan) is None, not_a_fan
    assert fan_of({"SpeedPercent": {"Reading": 1}, "Status": {"State": "Enabled"}}) == {"name": "", "reading": 1, "unit": "%", "ok": True}


def test_which_controller_is_openbmc_and_has_its_console_switched_on() -> None:
    console = {"ServiceEnabled": True, "MaxConcurrentSessions": 4, "ConnectTypesSupported": ["KVMIP"]}
    assert rfb_console({"Model": "OpenBmc", "GraphicalConsole": console}) == "/kvm/0"
    assert rfb_console({"Oem": {"OpenBmc": {"Fan": {}}}, "GraphicalConsole": console}) == "/kvm/0"
    # Built without its KVM, or with the console switched off, or another make with the same console entry.
    for other in (
        {"Model": "OpenBmc"}, {"Model": "OpenBmc", "GraphicalConsole": {**console, "ServiceEnabled": False}},
        {"Model": "OpenBmc", "GraphicalConsole": {**console, "ConnectTypesSupported": ["Oem"]}},
        {"Model": "OpenBmc", "GraphicalConsole": {**console, "ConnectTypesSupported": "KVMIP"}},
        {"Model": "iLO 6", "GraphicalConsole": console}, {"Oem": {"OpenBmc": "yes"}, "GraphicalConsole": console}, {},
    ):
        assert rfb_console(other) is None, other


# --- the makers' emulators and captures, where they are running ----------------------------------------------


class Manners:
    """A loopback proxy between the driver and an emulator, putting right the one manner named (see the top of this file)."""

    SESSIONS = "/redfish/v1/SessionService/Sessions"

    def __init__(
        self, upstream: str, *, created_201: bool = False, basic: tuple[str, str] | None = None, gives_sessions: bool = False, location_from_message: bool = False
    ) -> None:
        """`created_201`: a sign-in's 204 becomes the 201 the standard says. `basic`: the sign-in itself is sent
        signed in, with this user and password. `gives_sessions`: this proxy keeps the sessions (the emulator has
        none). `location_from_message`: the session's address, which the standard puts in the Location header,
        is taken from the "message" of the emulator's own answer and put there."""
        self.upstream = upstream.rstrip("/")
        self.created_201, self.basic, self.gives_sessions, self.location_from_message = created_201, basic, gives_sessions, location_from_message
        self.user, self.password = "admin", "secret"  # (where this proxy keeps the sessions itself)
        self.requests: list[str] = []  # what the driver sent, as "METHOD path"
        self.actions: list[str] = []  # the kinds of reset the driver asked for
        self.signed_in = self.signed_out = 0
        self._tokens: dict[str, str] = {}
        self._sock = local_socket()
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        self._server = uvicorn.Server(uvicorn.Config(self._app(), log_level="error", access_log=False))
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def _app(self) -> FastAPI:
        # (verify=False: an emulator's own self-signed certificate, between this proxy and it, in a test and nowhere else.)
        client = httpx.AsyncClient(base_url=self.upstream, verify=False, timeout=30.0)

        @asynccontextmanager
        async def closing(_: FastAPI) -> AsyncIterator[None]:
            yield
            await client.aclose()

        app = FastAPI(lifespan=closing)
        proxy = self

        @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"])
        async def through(path: str, request: Request) -> Response:
            at = "/" + path
            body = await request.body()
            proxy.requests.append(f"{request.method} {at}")
            headers = {name: value for name, value in request.headers.items() if name.lower() not in ("host", "content-length", "connection", "accept-encoding")}
            if "/Actions/" in at and request.method == "POST":
                try:
                    proxy.actions.append(str(json.loads(body).get("ResetType")))
                except (ValueError, AttributeError):
                    proxy.actions.append("?")
            signing_in = request.method == "POST" and at == proxy.SESSIONS
            if proxy.gives_sessions:
                if signing_in:
                    try:
                        said = json.loads(body)
                    except ValueError:
                        said = {}
                    proxy.signed_in += 1
                    if not isinstance(said, dict) or (said.get("UserName"), said.get("Password")) != (proxy.user, proxy.password):
                        return Response(json.dumps({"error": {"message": "Invalid credentials"}}), status_code=401, media_type="application/json")
                    token, session = secrets.token_hex(16), str(len(proxy._tokens) + 1)
                    proxy._tokens[token] = session
                    return Response(json.dumps({"Id": session}), status_code=201, media_type="application/json", headers={"X-Auth-Token": token, "Location": f"{proxy.SESSIONS}/{session}"})
                if request.method == "DELETE" and at.startswith(proxy.SESSIONS + "/"):
                    gone = [token for token, session in proxy._tokens.items() if session == at.rsplit("/", 1)[1]]
                    for token in gone:
                        del proxy._tokens[token]
                    proxy.signed_out += len(gone)
                    return Response(status_code=204 if gone else 404)
                if at.rstrip("/") not in ("/redfish/v1", "/redfish") and headers.pop("x-auth-token", None) not in proxy._tokens:
                    return Response(json.dumps({"error": {"message": "Sign in first"}}), status_code=401, media_type="application/json")
            if signing_in and proxy.basic:
                headers["Authorization"] = "Basic " + base64.b64encode(":".join(proxy.basic).encode()).decode()
            if signing_in:
                proxy.signed_in += 1
            if request.method == "DELETE" and at.startswith(proxy.SESSIONS + "/"):
                proxy.signed_out += 1
            query = request.url.query
            answer = await client.request(request.method, at + (f"?{query}" if query else ""), headers=headers, content=body)
            status = answer.status_code
            if signing_in and proxy.created_201 and status == 204:
                status = 201
            kept = {name: value for name, value in answer.headers.items() if name.lower() in ("content-type", "etag", "location", "x-auth-token", "allow")}
            if signing_in and proxy.location_from_message and status == 201 and "location" not in {name.lower() for name in kept}:
                try:
                    kept["Location"] = str(json.loads(answer.content).get("message"))
                except (ValueError, AttributeError):
                    pass
            return Response(answer.content, status_code=status, headers=kept)

        return app

    def start(self) -> Manners:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("the proxy did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def emulator(name: str) -> str:
    """Where the emulator called `name` is listening, or the test is skipped."""
    address = os.environ.get(f"QKVM_TEST_{name}")
    if not address:
        pytest.skip(f"QKVM_TEST_{name} is not set: that emulator is not running here")
    return address


def lit(client: Any, device: str, wanted: object) -> None:
    wait_until(lambda: client.get("/api/v1/status").json()[device]["server"]["locator"] is wanted, f"the tile never said the light is {wanted}", timeout=15)


def through(client: Any, device: str, action: str) -> httpx.Response:
    return client.post(f"/api/v1/devices/{device}/actions", json={"action": action})


def switch_the_light_and_back(client: Any, device: str, status: dict[str, Any]) -> None:
    """The locator light, switched the other way and back (a mockup keeps what it was last told, from one run to the next)."""
    was = status["server"]["locator"]
    assert was in (True, False)
    assert through(client, device, "locate_off" if was else "locate_on").status_code == 200
    lit(client, device, not was)
    assert through(client, device, "locate_on" if was else "locate_off").status_code == 200
    lit(client, device, was)


def test_the_standards_own_example_served_by_dmtfs_mockup_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 1.0)
    proxy = Manners(emulator("RACKMOUNT"), created_201=True).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": proxy.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["about"] == {"model": "3500", "version": "1.45.455b66-rev4", "hostname": "web483"}
            status = status_of(client, device, state="online")
            server = status["server"]
            assert (server["power"], server["health"], server["processors"], server["memory_gib"]) == ("On", "OK", 2, 96)
            assert server["temperatures"] == [{"name": "CPU1 Temp", "celsius": 41, "ok": True}, {"name": "Chassis Intake Temp", "celsius": 25, "ok": True}]
            assert [fan["reading"] for fan in server["fans"]] == [2100, 2050] and {fan["unit"] for fan in server["fans"]} == {"RPM"}
            assert status["health"]["temp"] == 41
            assert any(request.endswith("/Chassis/1U/Thermal") for request in proxy.requests)
            switch_the_light_and_back(client, device, status)
            # It offers every kind of reset the wall uses, and answers "done" to each; being a mockup, nothing
            # changes, which the wall sees where it looks for the change: a power cut that leaves the server on
            # is not called done.
            assert through(client, device, "atx_power").status_code == 200  # on: a shutdown is asked for
            assert through(client, device, "atx_reset").status_code == 200
            reply = through(client, device, "atx_power_long")
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and "still on" in reply.json()["message"]
            assert through(client, device, "reboot").status_code == 200
            assert proxy.actions == ["GracefulShutdown", "ForceRestart", "ForceOff", "ForceRestart"]
            assert through(client, device, "power_on").status_code == 200  # already on: left as it is, nothing sent
            assert len(proxy.actions) == 4
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            assert (proxy.signed_in, proxy.signed_out) == (1, 1)
    finally:
        proxy.stop()


def test_a_dell_idrac9_capture_served_by_dmtfs_mockup_server(tmp_path: Path) -> None:
    proxy = Manners(emulator("IDRAC"), created_201=True).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": proxy.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["about"] == {"model": "PowerEdge R660xs", "version": "7.20.10.05", "hostname": "exampleserver"}
            status = status_of(client, device, state="online")
            server = status["server"]
            assert (server["power"], server["health"], server["processors"], server["memory_gib"]) == ("On", "OK", 2, 64)
            assert server["processor"] == "Intel(R) Xeon(R) Gold 5415+"
            assert [t["name"] for t in server["temperatures"]][:2] == ["CPU1 Temp", "CPU2 Temp"] and status["health"]["temp"] == 38
            assert len(server["fans"]) == 14 and server["fans"][0] == {"name": "System Board Fan1A", "reading": 8040, "unit": "RPM", "ok": True}
            # The computer's own chassis is the one read, named as the computer names it; the disk enclosures are not.
            assert any(request.endswith("/Chassis/System.Embedded.1/Thermal") for request in proxy.requests)
            assert not any("Enclosure" in request for request in proxy.requests)
            # The light is the newer kind here, whatever IndicatorLED says beside it.
            assert server["locator"] is False
            switch_the_light_and_back(client, device, status)
            assert through(client, device, "atx_power").status_code == 200
            assert through(client, device, "atx_reset").status_code == 200
            assert through(client, device, "reboot").status_code == 200  # the one kind of restart it offers its controller
            assert proxy.actions == ["GracefulShutdown", "ForceRestart", "GracefulRestart"]
            assert server["rfb_console"] is None
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            assert (proxy.signed_in, proxy.signed_out) == (1, 1)
    finally:
        proxy.stop()


def test_hpes_ilo_emulator(tmp_path: Path) -> None:
    # The emulator speaks HTTPS with a certificate it makes for itself; that is between the proxy and it. The
    # driver speaks plain HTTP to the proxy, so nothing of the driver's certificate handling meets iLO's here
    # (that is tried against the stand-in's certificate in test_device_over_tls.py).
    proxy = Manners(emulator("ILO"), basic=("root", "root_password"), location_from_message=True).start()
    try:
        with wall(tmp_path) as client:
            # (The emulator answers a wrong password with 400, "invalid credentials", where the standard and a
            # real iLO say 401: to the wall that is a sign-in that came to nothing, not a no, and the device is
            # not added either way.)
            refused = client.post("/api/v1/devices", json={"url": proxy.url, "username": "root", "password": "not it"})
            assert (refused.status_code, refused.json()["code"]) == (422, "no_sign_in")
            reply = client.post("/api/v1/devices", json={"url": proxy.url, "username": "root", "password": "root_password"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["about"] == {"model": "ProLiant DL360 Gen10 Plus - SIMULATED", "version": "iLO 5 v3.11", "hostname": None}
            # The emulator carries a power command out at once, and keeps the state from one run to the next: on first.
            if status_of(client, device, kind="redfish")["server"]["power"] != "On":
                assert through(client, device, "power_on").status_code == 200
            status = status_of(client, device, state="online")
            server = status["server"]
            assert (server["power"], server["health"], server["processors"], server["memory_gib"]) == ("On", "OK", 2, 192)
            assert len(server["temperatures"]) == redfish.MAX_SENSORS  # it has 48: the wall lists its first forty
            assert server["temperatures"][:2] == [{"name": "01-Inlet Ambient", "celsius": 21, "ok": True}, {"name": "02-CPU 1", "celsius": 40, "ok": True}]
            assert status["health"]["temp"] == 40  # the processors, not the hottest of everything
            assert server["fans"][0] == {"name": "Fan 1", "reading": 26, "unit": "%", "ok": True} and len(server["fans"]) == 7
            assert server["locator"] is False
            switch_the_light_and_back(client, device, status)
            sent = len(proxy.actions)
            assert through(client, device, "atx_power").status_code == 200  # on: asked to shut down, and it does
            assert status_of(client, device, state="no_signal")["server"]["power"] == "Off"
            assert through(client, device, "power_on").status_code == 200  # seen to be on before it is "done"
            assert status_of(client, device, state="online")["server"]["power"] == "On"
            assert through(client, device, "atx_power_long").status_code == 200  # a power cut, seen to be off
            assert status_of(client, device, state="no_signal")["server"]["power"] == "Off"
            assert through(client, device, "power_on").status_code == 200
            assert status_of(client, device, state="online")["server"]["power"] == "On"
            assert through(client, device, "atx_reset").status_code == 200
            assert through(client, device, "reboot").status_code == 200
            assert proxy.actions[sent:] == ["GracefulShutdown", "On", "ForceOff", "On", "ForceRestart", "ForceRestart"]
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            assert (proxy.signed_in, proxy.signed_out) == (2, 1)  # (the refused one made no session to give back)
            assert any(request.startswith("DELETE /redfish/v1/SessionService/Sessions/") for request in proxy.requests)
    finally:
        proxy.stop()


def test_sushy_tools_switches_the_power_for_real(tmp_path: Path) -> None:
    # The fake driver of sushy-tools carries a command out one to eleven seconds after accepting it, and a
    # restart goes through "off" first: as a real server does, and what the wall's "accepted is not done" is for.
    # (sushy-tools has no sessions: the sign-in and sign-out counted below are the proxy's own bookkeeping, and
    # say that the driver signed in once and gave that session back, not anything about the emulator.)
    proxy = Manners(emulator("SUSHY"), gives_sessions=True).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": proxy.url, "username": "admin", "password": "secret"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["about"]["model"] == "Sushy Emulator"

            def seen(power: str) -> dict[str, Any]:
                """The status once the controller has been seen to say the server is `power` (the looks take a moment)."""
                return status_of(client, device, state="online" if power == "On" else "no_signal")

            status = status_of(client, device, kind="redfish")
            if status["server"]["power"] != "On":  # (as it was left by the last run: the emulator starts it off)
                assert through(client, device, "power_on").status_code == 200
                seen("On")
            assert through(client, device, "power_on").status_code == 200  # already on: nothing sent
            assert proxy.actions in ([], ["On"])
            sent = len(proxy.actions)
            assert through(client, device, "atx_power_long").status_code == 200  # ForceOff: accepted, and seen to be off before it is "done"
            assert proxy.actions[sent:] == ["ForceOff"]
            assert seen("Off")["server"]["power"] == "Off"
            assert through(client, device, "power_on").status_code == 200  # On: seen to be on
            assert seen("On")["server"]["power"] == "On"
            no_os = os.environ.get("QKVM_TEST_SUSHY_NO_OS") == "1"
            assert through(client, device, "power_off").status_code == 200  # a graceful shutdown: accepted, and the looks that follow see what came of it
            if no_os:
                time.sleep(3)  # nobody on the machine answers it: the server stays on, and the wall says so
                assert status_of(client, device, state="online")["server"]["power"] == "On"
                assert through(client, device, "atx_power_long").status_code == 200
                seen("Off")
            else:
                wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "no_signal", "the server never went off", timeout=20)
            assert through(client, device, "power_on").status_code == 200
            seen("On")
            assert through(client, device, "atx_reset").status_code == 200  # ForceRestart: off at once, then on again by itself (the fake driver), or a reset of the guest (libvirt)
            if not no_os:
                wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "no_signal", "the server never went off for its restart", timeout=20)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "online", "the server never came back", timeout=20)
            expected = ["ForceOff", "On", "GracefulShutdown", *(["ForceOff"] if no_os else []), "On", "ForceRestart"]
            assert proxy.actions[sent:] == expected
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            assert (proxy.signed_in, proxy.signed_out) == (1, 1)
    finally:
        proxy.stop()


def test_openbmc_in_qemu(tmp_path: Path) -> None:
    # bmcweb has proper sessions and its own certificate, so the driver talks to it directly. QEMU's
    # board has no host behind it and no sensors to speak of: what is read is the controller itself.
    address = emulator("OPENBMC")
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": address, "username": "root", "password": "0penBmc"})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]["id"]
        assert reply.json()["about"]["version"]  # bmcweb says its firmware version
        status = status_of(client, device, state="no_signal")  # the host is off, and stays off
        assert status["server"]["power"] == "Off"
        # "/kvm/0" where the image was built with bmcweb's KVM (its default); None where not. The image is
        # OpenBMC's latest master build until a build number is pinned, so either is taken here, and a value
        # of any other kind is not.
        assert status["server"]["rfb_console"] in ("/kvm/0", None)
        assert status["console"] is False
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200


def test_openbmcs_console_is_signed_in_to_with_the_session_in_qemu() -> None:
    # The console's WebSocket is signed in to as every request of bmcweb's: the driver sends its Redfish session's token
    # in a header (openbmc.py). bmcweb says so before anything else: 401 without it, or with a session it does not know,
    # and with it the console, or, where the image was built without one (romulus's latest build), "not found".
    from websockets.exceptions import InvalidStatus

    from qkvm.kvm import DeviceSpec, KvmError, unverified_context, ws_connect
    from qkvm.redfish import RedfishDevice

    address = emulator("OPENBMC")
    uri = "wss://" + address.split("://", 1)[1] + "/kvm/0"

    async def refused_with(headers: dict[str, str]) -> int:
        try:
            ws = await ws_connect(uri, ssl=unverified_context(), additional_headers=headers, open_timeout=20, close_timeout=1)
        except InvalidStatus as ex:
            return int(ex.response.status_code)
        await ws.close()
        return 101

    async def run() -> None:
        assert await refused_with({}) == 401
        assert await refused_with({"X-Auth-Token": "A" * 20}) == 401
        device = RedfishDevice(DeviceSpec(id="obmc", name="romulus", base_url=address, username="root", password="0penBmc", kind="redfish"))
        try:
            await device.status()
            announced = device._controller.get("rfb")
            device._controller["rfb"] = "/kvm/0"  # (asked whether it is announced or not: the sign-in is what is tried)
            try:
                ws = await device.rfb_socket()
            except KvmError as ex:
                assert announced is None and ex.message.endswith("(HTTP 404)"), ex.message  # signed in, and there is no console
            else:
                await ws.close()
            assert device._token is not None and await refused_with({"X-Auth-Token": device._token}) in (101, 404)
        finally:
            await device.close()

    asyncio.run(run())


def test_the_owners_boards_as_captured(tmp_path: Path) -> None:
    captures = [address.strip() for address in emulator("CAPTURES").split(",") if address.strip()]
    for address in captures:
        proxy = Manners(address, created_201=True).start()
        try:
            with wall(tmp_path / address.rsplit(":", 1)[-1]) as client:
                reply = client.post("/api/v1/devices", json={"url": proxy.url, "password": "secret"})
                assert reply.status_code == 201, reply.text
                device = reply.json()["device"]["id"]
                assert reply.json()["about"]["model"] and reply.json()["about"]["version"]
                status = status_of(client, device, state="online")
                server = status["server"]
                assert server["temperatures"] and server["fans"] and status["health"]["temp"] is not None
                assert server["locator"] in (True, False)
                assert server["rfb_console"] is None
                assert client.delete(f"/api/v1/devices/{device}").status_code == 200
                assert (proxy.signed_in, proxy.signed_out) == (1, 1)
        finally:
            proxy.stop()
