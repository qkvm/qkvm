"""What every test gets."""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import activity, amt, egress, history, jetkvm, kvm, netbind, redfish, tailnet, video
from tests import stand_ins

# Where qKVM looks for the tailnets of the computer it runs on, as the program has it: kept for the tests of the lookups
# themselves, which put a lookup back over no_tailnet_of_the_computer's nothing (with a PATH of their own).
THE_COMPUTERS_OWN: dict[str, Any] = {
    "sockets": tailnet.SOCKETS,
    "tailscale_command": netbind.tailscale_command,
    "netbird_command": netbind.netbird_command,
}

TICK = 0.02  # what a clock may be out by: on Windows before Python 3.13 it ticks every sixteen thousandths of a second
SCALE = 300.0  # how much shorter every wait is for a test that asks for `scaled`: a minute is a fifth of a second
# The step the clock the program waits by (time.monotonic) moves in, as this Python says: a sixty-fourth of a second on
# Windows before Python 3.13, next to nothing elsewhere.
CLOCK_STEP = time.get_clock_info("monotonic").resolution


def at_least(seconds: float) -> float:
    """The least a test measures by time.monotonic of a wait of the program's of `seconds`, made of one sleep and a deadline
    after it where there is one (a press: the board's hold, then the wait for the change), where it ended when it was to end.

    The event loop runs what is due within one step of that clock (asyncio's own rule), so the sleep ends up to a step early
    by its readings. The deadline is looked at by a reading, which is never early, and the test's own two readings are of the
    same clock: one step in all, and no more. (A long press on a Windows runner of Python 3.11 was measured 3.187 s, where
    the program's waits were 3.2 s: the first run of 0.2.2.)"""
    return seconds - CLOCK_STEP


@pytest.fixture(autouse=True, scope="session")
def folders_of_their_own(tmp_path_factory: pytest.TempPathFactory) -> None:
    """On Windows, the tests' folders are their runner's alone, as qKVM keeps a data folder (and as Python 3.12.4 and later
    make the folder pytest asks for with mode 0o700: the earlier ones ignore the mode there, and the folders took whatever
    their drive gives everybody). The starter runs no update from a folder others may write to (_folders.not_alone): in a
    folder that is everybody's, no test of an update would see one run."""
    if os.name != "nt":
        return
    subprocess.run(
        ["icacls", str(tmp_path_factory.getbasetemp()), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-3-4:(OI)(CI)F"],
        check=True, capture_output=True,
    )  # fmt: skip


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
def deployment_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests select their deployment mode explicitly, independent of their host.

    Native update tests exercise native installs even when pytest runs in an
    image. Container-specific tests set this flag themselves; image startup and
    runtime checks separately verify the actual image's container default.
    """
    monkeypatch.delenv("QKVM_CONTAINER", raising=False)
    monkeypatch.delenv("QKVM_VAULT_KEY_FILE", raising=False)


@pytest.fixture(autouse=True)
def no_tailnet_of_the_computer(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test asks the tailnets of the computer it runs on: no tailscale or netbird command is found, and Tailscale's
    local API is looked for nowhere. A runner of the tests may be in a tailnet, tailscaled running and its socket where
    qKVM looks for it: a search there asked that tailnet's machines, and the tests read what the runner's tailscaled said
    in place of their stand-ins. A test that wants a tailnet sets a stand-in of its own over this (a command, a socket in a
    folder of its own); the tests of the lookups themselves put them back from THE_COMPUTERS_OWN, with a PATH of their own.
    (What a test starts as a process of its own is not held by this: none of those searches, or asks for a certificate.)"""
    monkeypatch.setattr(tailnet, "SOCKETS", ())
    for module in (tailnet, netbind):
        monkeypatch.setattr(module, "tailscale_command", lambda: None)
        monkeypatch.setattr(module, "netbird_command", lambda: None)


@pytest.fixture(autouse=True)
def alert_stand_ins(monkeypatch: pytest.MonkeyPatch) -> None:
    """The alerts of a test reach its stand-ins on loopback, by the names they registered (stand_ins.py, fake_alerts.py), and nothing
    else there: every other address is judged by the wall's real outbound rules (egress.vetted), in the tests too."""
    stand_ins.STAND_INS.clear()
    real = egress.vetted

    async def vetted(host: str, port: int, *, private_ok: bool, own: frozenset[str], own_ports: frozenset[int] = frozenset()) -> tuple[list[str], int]:
        if host in stand_ins.STAND_INS:
            return ["127.0.0.1"], stand_ins.STAND_INS[host]
        return await real(host, port, private_ok=private_ok, own=own, own_ports=own_ports)

    monkeypatch.setattr(egress, "vetted", vetted)


@pytest.fixture(autouse=True)
def nobody_asked_about_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Where a wall of a test looks for a newer version, nothing is listening: never the real place.

    Most tests switch that looking off, each in its own way, and one of those ways switches nothing off (an
    empty QKVM_UPDATE_REPO is taken to mean "the usual one"). A test that names a place of its own, a
    stand-in on this computer, sets this again and is not hindered; the programs tests start inherit it.
    """
    monkeypatch.setenv("QKVM_UPDATE_API", "http://127.0.0.1:9")
    monkeypatch.setenv("QKVM_UPDATE_FILES", "http://127.0.0.1:9")  # (and where the libraries a release lists are fetched)


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


LOGGERS_THE_PROGRAM_SETS_UP = ("qkvm", "uvicorn.error", "asyncio", "httpx", "httpcore", "websockets", "aiortc", "aioice")


@pytest.fixture(autouse=True)
def logging_as_it_was() -> Iterator[None]:
    """The loggers the program sets up are as they were before the test, after it. A test that runs the command line
    (or sets up the program's logging itself) leaves `qkvm` and the web server's logger at the level asked for,
    writing to a queue nobody reads any more and passing nothing on, the event loop at its errors and the libraries
    at their warnings, as the program has it until it ends: a test after it that listened at the finest level heard
    nothing finer, and one that holds what must never be logged held it to nothing (register row 26 of 0.2.1). What
    pytest itself puts on a logger for one part of a test is its own, and is left to it."""

    def own(handlers: list[logging.Handler]) -> list[logging.Handler]:
        return [handler for handler in handlers if not type(handler).__module__.startswith("_pytest")]

    kept = {}
    for name in LOGGERS_THE_PROGRAM_SETS_UP:
        logger = logging.getLogger(name)
        kept[name] = (own(logger.handlers), logger.filters[:], logger.propagate, logger.level, logger.disabled)
    try:
        yield
    finally:
        for name, (handlers, filters, propagate, level, disabled) in kept.items():
            logger = logging.getLogger(name)
            logger.handlers[:] = handlers + [handler for handler in logger.handlers if handler not in handlers and not own([handler])]
            logger.filters[:], logger.propagate, logger.disabled = filters, propagate, disabled
            logger.setLevel(level)


@pytest.fixture(autouse=True)
def nothing_rejected_before() -> None:
    """Which passwords devices said no to is remembered beside the connections to them, for as long as the
    program runs. The stand-in device of one test may be given the port another one's had: it is not to
    find that one's rejected password waiting for it. (Nor one an engine with Intel AMT took: amt._SIGN_INS.)"""
    kvm.REJECTED.clear()
    amt._SIGN_INS.clear()
    amt._LAST_TRIED.clear()


@pytest.fixture(autouse=True)
def nothing_paced_before() -> None:
    """What paces a KVM's power buttons and the questions to its Fingerbot is kept beside the connections as well, by the
    KVM's address and its pinned certificate, for as long as the program runs (kvm.PACED): the stand-in of one test, at the port
    another one's had, or a KVM with the same certificate, is not to find that one's press still held. (And a JetKVM's
    connections made anew in a row for a key frame it did not send, jetkvm._DEAF, by address too; and which KVMs have shown
    several inputs, kvm.SEVERAL_SEEN: a stand-in of one input at a port another test's switch had is not to be said to have several.)"""
    kvm.PACED.clear()
    kvm.SEVERAL_SEEN.clear()
    jetkvm._DEAF.clear()


@pytest.fixture(autouse=True)
def video_not_said_unavailable_before() -> None:
    """Why video cannot start on this computer is kept for as long as the program runs (video.unavailable(), which /healthz
    says): a worker of one test that could not start (a stand-in's, or one that took too long on a slow machine) is not to
    be said of the next test's wall; nor its starts that took too long be counted with the next test's."""
    video._unavailable = None
    video._slow_starts = 0
    video._last_started = video._last_slow_ended = float("-inf")


@pytest.fixture
def a_video_worker_first() -> None:
    """The process's first isolated video worker, made and closed before the test, for as long as that takes. On Windows the
    first start copies Python and PyAV into a bundle of their own and launches from there, scanned, which no bound of the
    wall's covers: on the Windows test VM running 16 test files at a time, 3 to 16 s, 8 starts of 20 past the wall's own
    START_WITHIN (then "slow to start", and asked again); the starts after it in the same process, one for each console or
    session that makes a picture, mostly 1 to 13 s, and now and then past it too. (There every test process put its workers
    on the same two processors: each places its own on the pair it has used least, and knows nothing of the others.) A
    wait for the condition: the minutes are room only. (As tests/test_a_comets_keys_and_mouse_as_the_real_one_took_them.py
    does for its pointer.)"""
    deadline = time.monotonic() + 300
    while True:
        try:
            video.Worker().close()
            return
        except video.VideoError:
            assert time.monotonic() < deadline, "no isolated video worker could be started"  # (one that took too long: again)
        time.sleep(0.05)


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
