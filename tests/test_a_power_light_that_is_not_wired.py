"""A KVM's power board that says the power light is off while the screen shows a picture: its power-LED wires are probably
not connected (the owner's stock PiKVM V4, 2026-11-15).

The wall already took such a light for no witness of the computer's power: a computer that sends a picture is on, and the
tile said neither "Power on" nor "Power off". It said nothing of why either. The status says it now, in the wall's words, as
a code (words.json) and a sentence beside the board's word (`atx.note`), for the tile and its Details to show; and only
then: a light that is on, or one that is off beside no picture (a computer that is off), says nothing more.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_wall import add, wait_until, wall

UNWIRED = {
    "code": "power_led_unwired",
    "message": "The KVM's board says the power light is off while the screen shows a picture: its power-LED wires are probably not connected.",
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture(params=["stock kvmd's light", "GLKVM's word"])
def unwired(request: pytest.FixtureRequest) -> Iterator[FakeKvm]:
    """A KVM with a power board whose light (stock kvmd), or whose word for the power (GLKVM), says off, and a picture."""
    stock = request.param == "stock kvmd's light"
    # (Stock kvmd's streamer says whether there is a picture while it runs: as it does for a while after a viewer left.)
    running = time.monotonic() + 600 if stock else 0.0
    fake = FakeKvm(FakeState(atx=True, atx_words=not stock, stock=stock, computer_on=False, signal=True, streamer_until=running)).start()
    yield fake
    fake.stop()


def atx_of(admin: Any, device: str, **wanted: Any) -> dict[str, Any]:
    """The status's `atx`, once a look has found the board and the picture as wanted."""
    status: dict[str, Any] = {}

    def came() -> bool:
        status.update(admin.get("/api/v1/status").json()[device])
        atx = status.get("atx") or {}
        return status.get("state") in ("online", "no_signal") and atx.get("enabled") is True and all(atx.get(key) == value for key, value in wanted.items())

    wait_until(came, f"the board was never seen as {wanted}: {status}", 10)
    return dict(status["atx"])


def test_a_power_light_that_says_off_beside_a_picture_is_said_to_be_probably_not_wired(tmp_path: Path, unwired: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, unwired.url)
        atx = atx_of(admin, device, power=False)
        assert atx.get("note") == UNWIRED, atx
        assert admin.get("/api/v1/status").json()[device]["state"] == "online"  # (it is shown as it is: a picture)
        # Its picture gone, a light that says off is a computer off: nothing more is said. Nor is `note`, which only a board
        # with something to say has: the board as it was before 0.3.2 (`enabled`, `power`, `hdd`), for whoever reads all of
        # it as one (tests/test_a_comets_board_on_its_line_for_events.py, the Desktop App).
        unwired.state.signal = False
        assert set(atx_of(admin, device, power=False, note=None)) == {"enabled", "power", "hdd"}
        # Lit, it is the computer's power, said as ever.
        unwired.state.computer_on = unwired.state.signal = True
        assert set(atx_of(admin, device, power=True, note=None)) == {"enabled", "power", "hdd"}


@pytest.mark.parametrize("stock", [True, False], ids=["stock kvmd's light", "GLKVM's word"])
def test_a_kvm_with_several_inputs_says_nothing_of_the_wires(tmp_path: Path, stock: bool) -> None:
    # On a KVM that switches between computers (a Comet X), the board may be wired to one computer while the screen is
    # another's: a light that says off beside a picture says nothing of its wires there, and the note would be wrong (the
    # review of 0.3.2). The board is no witness of the power all the same: the page says "Power unknown", without a why.
    running = time.monotonic() + 600 if stock else 0.0
    fake = FakeKvm(FakeState(atx=True, atx_words=not stock, stock=stock, computer_on=False, signal=True, streamer_until=running, ports=[(32, 74, 135), (135, 74, 32)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"] is not None, "its inputs were never seen", 10)
            atx = atx_of(admin, device, power=False)
            status = admin.get("/api/v1/status").json()[device]
            assert set(atx) == {"enabled", "power", "hdd"}, atx
            assert status["state"] == "online" and status["video"]["signal"] is True and status["ports"]["active"] == 0
    finally:
        fake.stop()


@pytest.mark.parametrize("stock", [True, False], ids=["stock kvmd's light", "GLKVM's word"])
def test_a_kvm_that_showed_several_inputs_says_nothing_of_the_wires_while_its_switch_does_not_answer(tmp_path: Path, stock: bool) -> None:
    # One answer of its switch that was not a yes (a 502 of its web server while kvmd restarts) and it was taken for a KVM with
    # one input, for ten minutes (kvm.ABOUT_TTL), and the note came back meanwhile (the review of 0.3.2's fixes). A KVM that
    # has shown several inputs gives none: its board may be another computer's all the same. (Its switch is asked again at
    # the next look since 0.4.0: without the input on screen its keys and text are not offered.)
    running = time.monotonic() + 600 if stock else 0.0
    fake = FakeKvm(FakeState(atx=True, atx_words=not stock, stock=stock, computer_on=False, signal=True, streamer_until=running, ports=[(32, 74, 135), (135, 74, 32)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"] is not None, "its inputs were never seen", 10)
            fake.state.switch_fails = 1
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"] is None, "its switch's 502 was never seen", 10)
            for _ in range(3):  # (a few looks, with its switch's answer or without)
                atx = atx_of(admin, device, power=False)
                assert set(atx) == {"enabled", "power", "hdd"}, atx
            assert fake.state.switch_fails == 0
    finally:
        fake.stop()


@pytest.mark.parametrize("stock", [True, False], ids=["stock kvmd's light", "GLKVM's word"])
def test_a_kvm_that_showed_several_inputs_says_nothing_of_the_wires_after_an_edit_of_its_tile(tmp_path: Path, stock: bool) -> None:
    # The same while its switch keeps failing, through an edit of the tile that changes its group only: the edit makes a new
    # client for the KVM, which began as one that had never seen its inputs, and the note came back (the second and third
    # reviews of 0.3.2), at the edit's own look before the new client took over too. That the KVM has shown several inputs
    # is carried to the client that takes over from the one that saw it, as what else is the same device's is.
    running = time.monotonic() + 600 if stock else 0.0
    fake = FakeKvm(FakeState(atx=True, atx_words=not stock, stock=stock, computer_on=False, signal=True, streamer_until=running, ports=[(32, 74, 135), (135, 74, 32)])).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"] is not None, "its inputs were never seen", 10)
            fake.state.switch_fails = 1000  # (it keeps failing, through the edit and after it)
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["ports"] is None, "its switch's 502 was never seen", 10)
            assert set(atx_of(admin, device, power=False)) == {"enabled", "power", "hdd"}
            edited = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "the same KVM", "group": "rack 2"})
            assert edited.status_code == 200, edited.text
            for _ in range(4):  # (the first the edit's own look, the others the new client's)
                atx = atx_of(admin, device, power=False)
                assert set(atx) == {"enabled", "power", "hdd"}, atx
            assert admin.get("/api/v1/status").json()[device]["ports"] is None  # (its switch still answers nothing)
    finally:
        fake.stop()


def test_what_a_kvm_has_shown_of_its_inputs_goes_only_to_a_client_of_the_same_kvm() -> None:
    # Carried where the client that takes over talks to the KVM the one before it saw (the same address, which is when one
    # takes over from the other at all, and the same check). Also over a certificate taken anew, fail closed, since the narrow
    # re-review of HB's second round (L1): the same KVM reflashed was taken for one of a single input while its switch was not
    # up; another one there, of one input, is let go of once its switch has said long enough that it has none
    # (kvm.NO_SWITCH_LETS_GO). A note the new client's first look made before it took over goes from what it says.
    # And the same machine and what else it is known by: a check of its certificate changed (another KVM may answer where
    # none is checked), a machine or an identity remembered anew are each another KVM's as far as anything tells. (With
    # the certificate alone looked at, this test passed: the second round of the reviews of 0.3.2, its third's L2.)
    def client(cert: str, note: bool, **spec: str) -> kvm.KvmDevice:
        mark = {"tls": "pinned", "machine": "machine-1", "ident": "own:kvm-1", **spec}
        made = kvm.KvmDevice(kvm.DeviceSpec("k1", "KVM", "https://127.0.0.1:9", "admin", "x", cert_pem=cert, **mark))
        made._status = {"state": "online", "atx": {"enabled": True, "power": False, "hdd": None, **({"note": dict(UNWIRED)} if note else {})}}
        return made

    kvm.SEVERAL_SEEN.clear()  # (what a KVM has shown is kept by its mark, across clients: none kept from another test)
    saw = client("first", note=False)
    saw._shown_several = True
    same, other = client("first", note=True), client("taken anew", note=True)
    # (A KVM of its own: what the first one showed is kept by its mark, so a client of that same KVM is held to it too.)
    never = client("first", note=True, ident="own:kvm-never")
    same.takes_over(saw)
    other.takes_over(saw)
    never.takes_over(client("first", note=False, ident="own:kvm-never"))
    assert same._shown_several and same._status is not None and set(same._status["atx"]) == {"enabled", "power", "hdd"}
    assert other._shown_several and other._status is not None and set(other._status["atx"]) == {"enabled", "power", "hdd"}
    assert not never._shown_several and never._status is not None and never._status["atx"]["note"] == UNWIRED
    for changed in ({"tls": "system"}, {"tls": "insecure"}, {"machine": "machine-2"}, {"machine": ""}, {"ident": "own:kvm-2"}, {"ident": ""}):
        another = client("first", note=True, **changed)
        another.takes_over(saw)
        assert not another._shown_several, changed
        assert another._status is not None and another._status["atx"]["note"] == UNWIRED, changed
