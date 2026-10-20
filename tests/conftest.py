"""What every test gets."""

from __future__ import annotations

import queue
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import activity, amt, history, jetkvm, kvm, redfish

TICK = 0.02  # what a clock may be out by: on Windows before Python 3.13 it ticks every sixteen thousandths of a second
SCALE = 300.0  # how much shorter every wait is for a test that asks for `scaled`: a minute is a fifth of a second


@pytest.fixture(autouse=True)
def home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home folder that is nobody's. qKVM keeps things at home (its settings when it is told no other place,
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
def no_history_left_writing() -> Iterator[None]:
    """Every history a test started is stopped at the test's end. A wall of a test is never stopped as the program is:
    its history's writer went on with the file open, trimming it every ten minutes, beside the writer of the next wall a
    test started on the same folder; a checkpoint one of them could not get through was then said in the log of whatever
    test ran at the time, and failed one that looks at what the program writes. Told to stop and woken, each is waited
    for two seconds at the most: one in the middle of a checkpoint or a trim finishes that on its own. (A patch of this
    fixture's own: a test that undoes its patches midway does not undo this one.)"""
    patched = pytest.MonkeyPatch()
    started: list[history.History] = []
    starting = history.History.start

    def start(self: history.History) -> None:
        if self._writer is None:
            started.append(self)
        starting(self)

    patched.setattr(history.History, "start", start)
    try:
        yield
    finally:
        patched.undo()
        for kept in started:
            kept._stopping = True
            try:
                kept._waiting.put_nowait(("forget",))  # (a row that does nothing: the writer waits for rows, a second at a time)
            except queue.Full:
                pass
        deadline = time.monotonic() + 2.0
        for kept in started:
            if kept._writer is not None:
                kept._writer.join(max(0.0, deadline - time.monotonic()))


@pytest.fixture(autouse=True)
def no_activity_index_left_following() -> Iterator[None]:
    """Every index of the activity log a test started is stopped at the test's end, as every history is (above): a wall of a
    test is never stopped as the program is, and its index's thread went on following the files of a folder the next test
    may start another wall on. Told to stop, each is waited for two seconds at the most."""
    patched = pytest.MonkeyPatch()
    started: list[activity.Index] = []
    starting = activity.Index.start

    def start(self: activity.Index) -> None:
        if self._writer is None:
            started.append(self)
        starting(self)

    patched.setattr(activity.Index, "start", start)
    try:
        yield
    finally:
        patched.undo()
        for index in started:
            index._again = False
            index._halt.set()
            index._wake.set()
        deadline = time.monotonic() + 2.0
        for index in started:
            if index._writer is not None:
                index._writer.join(max(0.0, deadline - time.monotonic()))


@pytest.fixture(autouse=True)
def nothing_rejected_before() -> None:
    """Which passwords devices said no to is remembered beside the connections to them, for as long as the
    program runs. The stand-in device of one test may be given the port another one's had: it is not to
    find that one's rejected password waiting for it."""
    kvm.REJECTED.clear()


@pytest.fixture(autouse=True)
def power_buttons_let_go_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A KVM's power board holds a button for half a second after answering, six and a half the long press, and the
    change a press must bring is looked for up to twenty seconds after (kvm.HELD, SEEN_WITHIN). The stand-ins hold
    nothing, and their computer does not follow a press unless a test says so: those waits are short here, and the
    tests of them make them as long as they need."""
    monkeypatch.setattr(kvm, "HELD", dict.fromkeys(kvm.HELD, 0.0))
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 0.2)
    monkeypatch.setattr(kvm, "SEEN_EVERY", 0.05)


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
    for looker in (redfish, amt):
        monkeypatch.setattr(looker, "LOOK_EVERY", looker.LOOK_EVERY / SCALE)
        monkeypatch.setattr(looker, "RETRY_LOOK", looker.RETRY_LOOK / SCALE)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.02)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
