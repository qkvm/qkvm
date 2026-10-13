"""What every test gets."""

from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import jetkvm, kvm, redfish

TICK = 0.02  # what a clock may be out by: on Windows before Python 3.13 it ticks every sixteen thousandths of a second
SCALE = 300.0  # how much shorter every wait is for a test that asks for `scaled`: a minute is a fifth of a second


@pytest.fixture(autouse=True)
def home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home folder that is nobody's. QKVM keeps things at home (its settings when it is told no other place,
    and a note of the other places walls were started with): the tests are not to leave any of that with
    whoever runs them, nor to find there what that person's own wall left."""
    folder = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.setenv("USERPROFILE", str(folder))
    return folder


@pytest.fixture(autouse=True)
def nobody_asked_about_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Where a wall of a test looks for a newer version, nothing is listening: never the real place.

    Most tests switch that looking off, each in its own way, and one of those ways switches nothing off (an
    empty QKVM_UPDATE_REPO is taken to mean "the usual one"). A test that names a place of its own, a
    stand-in on this computer, sets this again and is not hindered; the programs tests start inherit it.
    """
    monkeypatch.setenv("QKVM_UPDATE_API", "http://127.0.0.1:9")


@pytest.fixture(autouse=True)
def nothing_rejected_before() -> None:
    """Which passwords devices said no to is remembered beside the connections to them, for as long as the
    program runs. The stand-in device of one test may be given the port another one's had: it is not to
    find that one's rejected password waiting for it."""
    kvm.REJECTED.clear()


@pytest.fixture
def scaled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every wait that paces a sign-in is a three-hundredth of what it is, and nothing else is changed.

    For the tests that count at a stand-in device how often a password arrives in a half hour: they let
    real time pass and ask the device the way the wall asks it. Setting a time back by hand tests the
    table of waits, and not the program around it.
    """
    monkeypatch.setattr(kvm, "LOGIN_BACKOFFS", tuple(wait / SCALE for wait in kvm.LOGIN_BACKOFFS))
    monkeypatch.setattr(kvm, "UNANSWERED_MOST", kvm.UNANSWERED_MOST / SCALE)
    for driver in (kvm, redfish, jetkvm):
        monkeypatch.setattr(driver, "LOGIN_RETRY", kvm.LOGIN_RETRY / SCALE)
    monkeypatch.setattr(redfish, "CONSOLE_GIVE_UP", redfish.CONSOLE_GIVE_UP / SCALE)
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", tuple(wait / SCALE for wait in redfish.CONSOLE_RETRY))
    monkeypatch.setattr(redfish, "LOOK_EVERY", redfish.LOOK_EVERY / SCALE)
    monkeypatch.setattr(redfish, "RETRY_LOOK", redfish.RETRY_LOOK / SCALE)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.02)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
