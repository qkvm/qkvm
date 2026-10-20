"""A password a device rejects, again and again.

Seen in the log of a wall that ran for days: one KVM answered "login rejected" once a minute, for as
long as the wall looked at it. That is 1,440 wrong passwords a day offered to one device. A server's
controller locks an account after a few of them, for the people who run the machine as well; a JetKVM
locks the wall's address out after five. A password that was rejected does not become right by being
offered again, so each rejection in a row has the wall wait longer before the next one, up to an hour.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterator
from itertools import pairwise
from typing import Any

import pytest

from qkvm import amt, jetkvm, kvm, redfish
from qkvm.kvm import Device, DeviceSpec, KvmError
from tests.fake_amt import FakeAmt
from tests.fake_jetkvm import FakeJetKvm
from tests.fake_kvm import FakeKvm
from tests.fake_redfish import FakeBmc
from tests.conftest import TICK

MINUTE = 60.0
WAITS = [1 * MINUTE, 5 * MINUTE, 15 * MINUTE, 60 * MINUTE, 60 * MINUTE, 60 * MINUTE]


def test_the_waits_grow_from_a_minute_to_an_hour_and_stay_there() -> None:
    waits = [kvm.wait_after_rejections(times) for times in range(1, 40)]
    assert waits[: len(WAITS)] == WAITS and set(waits[len(WAITS) :]) == {60 * MINUTE}
    assert waits[0] == kvm.LOGIN_BACKOFF  # the first is what it always was
    assert kvm.wait_after_rejections(0) == kvm.LOGIN_BACKOFF  # (asked before anything was rejected: never less)
    # A day of it, as times of the day: where there were 1,440 tries there are under thirty,
    tries, at = [0.0], 0.0
    for wait in waits:
        at += wait
        if at < 24 * 3600:
            tries.append(at)
    assert len(tries) <= 30
    # and no half hour has more than four of them. (A controller that locks an account after five wrong
    # passwords in that time is not made to by the wall alone. One that locks after three is, once; it
    # was for good before, a try a minute.)
    assert max(sum(1 for other in tries if 0 <= other - one < 30 * MINUTE) for one in tries) == 4
    assert all(later - earlier >= 60 * MINUTE for earlier, later in pairwise(tries[3:]))


Made = tuple[Device, Callable[[], int], Callable[[str], None]]


def that_long_has_passed(device: Device) -> None:
    """The wait is over: for this connection, and in what is kept beside the connections of what was rejected."""
    device._login_retry_at = 0.0  # type: ignore[attr-defined]
    for what, (times, unanswered, _) in list(kvm.REJECTED._known.items()):
        kvm.REJECTED._known[what] = (times, unanswered, 0.0)


def a_kvm(server: Any) -> Made:
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password="secret"))
    return device, lambda: server.state.logins, lambda password: setattr(server.state, "password", password)


def a_controller(server: Any) -> Made:
    device = redfish.RedfishDevice(DeviceSpec(id="ab12", name="Server", base_url=server.url, username="admin", password="secret", kind="redfish"))
    return device, lambda: server.state.logins, lambda password: setattr(server.state, "password", password)


def a_jetkvm(server: Any) -> Made:
    device = jetkvm.JetKvmDevice(DeviceSpec(id="ab12", name="JetKVM", base_url=server.url, username="", password="secret", kind="jetkvm"))
    return device, lambda: server.state.logins, lambda password: setattr(server.state, "password", password)


def an_amt_pc(server: Any) -> Made:
    # (Digest signs every request: a "login" is the first that carries the password, and the count at the
    # stand-in is of requests that carried one. While the password is wrong, those are the sign-ins.)
    device = amt.AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=server.url, username="admin", password="secret", kind="amt"))
    return device, lambda: server.state.logins, lambda password: setattr(server.state, "password", password)


KINDS: dict[str, tuple[Callable[[], Any], Callable[[Any], Made]]] = {
    "a KVM": (FakeKvm, a_kvm),
    "a server's controller": (FakeBmc, a_controller),
    "a JetKVM": (FakeJetKvm, a_jetkvm),
    "an Intel AMT PC": (FakeAmt, an_amt_pc),
}


@pytest.fixture(params=list(KINDS))
def made(request: pytest.FixtureRequest) -> Iterator[Made]:
    stand_in, make = KINDS[request.param]
    server = stand_in().start()
    yield make(server)
    server.stop()


def test_each_rejection_in_a_row_has_the_wall_wait_longer_and_an_accepted_login_starts_it_over(made: Made) -> None:
    device, logins, set_password = made

    async def rejected(expected: float) -> None:
        before = logins()
        with pytest.raises(KvmError) as failed:
            await device._login()  # type: ignore[attr-defined]
        assert failed.value.code == "auth_failed" and logins() == before + 1
        wait = device._login_retry_at - time.monotonic()  # type: ignore[attr-defined]
        assert expected - 5 <= wait <= expected + TICK, (wait, expected)
        # Meanwhile it is not offered at all, however often the tile is looked at.
        for _ in range(3):
            with pytest.raises(KvmError) as again:
                await device._login()  # type: ignore[attr-defined]
            assert again.value.code == "auth_failed"
        assert logins() == before + 1

    async def run() -> None:
        try:
            set_password("changed on the device")
            for expected in WAITS:
                await rejected(expected)
                that_long_has_passed(device)
            # Somebody sets the device back to what is saved here: the next try is accepted,
            set_password("secret")
            that_long_has_passed(device)
            await device._login()  # type: ignore[attr-defined]
            assert device._login_error is None  # type: ignore[attr-defined]
            # and a password rejected after that is the first again, not the seventh.
            set_password("changed again")
            device._token = None  # type: ignore[attr-defined]  # (the device has forgotten the session)
            await rejected(WAITS[0])
        finally:
            await device.close()

    asyncio.run(run())


def test_a_jetkvm_that_says_how_long_it_refuses_is_still_given_that_long() -> None:
    # Its own lock on the address, after five wrong passwords: it names the time, and the wall keeps to it
    # where that is longer than its own wait (and to an hour at the most, whatever it names).
    server = FakeJetKvm().start()
    device, _, _ = a_jetkvm(server)

    async def run() -> None:
        try:
            # (What it asks for, and a minute at the least. That is no verdict on the password, and is not counted
            # as a no: counted, one that asked for half a minute a second time was left alone for five.)
            for asks, least, most in (("400", 395.0, 400.0), ("30", 55.0, 60.0), ("86400", 3595.0, 3600.0)):
                server.state.locked_for = asks
                that_long_has_passed(device)
                with pytest.raises(KvmError):
                    await device._login()  # type: ignore[attr-defined]
                wait = device._login_retry_at - time.monotonic()  # type: ignore[attr-defined]
                assert least <= wait <= most + TICK, (asks, wait)
                assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 0
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
