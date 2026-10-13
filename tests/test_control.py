"""`qkvm status`, `qkvm stop` and `qkvm restart`, and what a person at a terminal meets when stopping it."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from qkvm import __main__ as starter
from qkvm import cli
from qkvm.core import RESTART
from qkvm.store import InstanceLock
from tests import local_socket


def free_port() -> str:
    """A port nothing listens on (the default one may well be taken, by the wall of whoever runs the tests)."""
    with local_socket() as sock:
        return str(sock.getsockname()[1])


class Running:
    """A wall that runs with a data folder, as far as another `qkvm` can tell: the lock, and an ear for what is asked."""

    def __init__(self, folder: Path, answers: bool = True) -> None:
        self.folder, self.lock = folder, InstanceLock(folder)
        self.exit_status: int | None = None
        self.supervised = True  # started by `python -m qkvm`, which runs it again when it asks for that
        self.stop: Any = lambda: self.asked.set()
        self.asked, self.done = threading.Event(), threading.Event()
        self.answers = answers
        assert self.lock.acquire()
        self.lock.say(pid=os.getpid(), since=1_700_000_000.0, version="0.1.0", listening=["http://127.0.0.1:8787/"])
        self.thread = threading.Thread(target=self.live, daemon=True)
        self.thread.start()

    def restart_program(self) -> None:
        self.exit_status = RESTART
        self.stop()

    def live(self) -> None:
        asks = cli.Asks(self.folder, self)  # type: ignore[arg-type]
        while not self.done.is_set():
            if self.answers:
                asks.look()
            if self.asked.is_set():
                self.asked.clear()
                if self.exit_status == RESTART:  # the starter runs it again: a new process takes the lock
                    self.exit_status = None
                    self.lock.say(pid=os.getpid(), since=time.time(), version="0.1.0", listening=["http://127.0.0.1:8787/"])
                else:
                    self.lock.release()
                    return
            time.sleep(0.02)

    def end(self) -> None:
        self.done.set()
        self.thread.join(5)
        self.lock.release()


@pytest.fixture
def running(tmp_path: Path) -> Iterator[Running]:
    wall = Running(tmp_path)
    yield wall
    wall.end()


def test_a_second_copy_is_told_which_one_runs_and_how_to_stop_it(tmp_path: Path, running: Running, capsys: pytest.CaptureFixture[str]) -> None:
    # "another copy is already running - stop it first", and not a word on where it runs or how that is done.
    # The person who met it had started the wall in another window an hour before, and tried `qkvm stop`.
    assert cli.main(["--data-dir", str(tmp_path)]) == 2
    told = capsys.readouterr().err
    assert f"process {os.getpid()}" in told and f"qkvm stop --data-dir {tmp_path}" in told
    assert "Traceback" not in told


def test_status_says_whether_it_runs_and_where(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3  # as a service manager counts: 3 is "not running"
    assert "not running" in capsys.readouterr().out
    wall = Running(tmp_path)
    try:
        assert cli.main(["status", "--data-dir", str(tmp_path)]) == 0
        said = capsys.readouterr().out
        assert "QKVM 0.1.0 is running" in said and f"process {os.getpid()}" in said and "http://127.0.0.1:8787/" in said
    finally:
        wall.end()
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3  # and it leaves nothing behind that says it still runs
    assert InstanceLock(tmp_path).holder() is None


def test_stop_asks_the_running_copy_and_comes_back_when_it_is_gone(tmp_path: Path, running: Running, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["stop", "--data-dir", str(tmp_path)]) == 0
    assert "stopped" in capsys.readouterr().out
    assert running.exit_status == 0  # it left as a program does that was asked to, not as one that fell over
    assert not (tmp_path / "qkvm.ask").exists()
    assert cli.main(["stop", "--data-dir", str(tmp_path)]) == 0  # nothing to stop is not a failure
    assert "not running" in capsys.readouterr().out


def test_restart_asks_it_to_be_started_again_and_waits_for_the_new_one(tmp_path: Path, running: Running, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["restart", "--data-dir", str(tmp_path)]) == 0
    assert "restarted" in capsys.readouterr().out
    assert (InstanceLock(tmp_path).holder() or {}).get("since", 0) > 1_700_000_000.0


def test_a_wall_that_nothing_would_start_again_is_not_ended_by_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # Run as `python -m qkvm.cli`, there is no starter: leaving "to be started again" would be leaving for good.
    monkeypatch.setattr(cli, "ASK_PATIENCE", 0.4)
    wall = Running(tmp_path)
    wall.supervised = False
    try:
        assert cli.main(["restart", "--data-dir", str(tmp_path)]) == 1
        assert wall.exit_status is None and "did not restart" in capsys.readouterr().err
        assert cli.main(["status", "--data-dir", str(tmp_path)]) == 0  # it is still there
    finally:
        wall.end()


def test_restart_of_nothing_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["restart", "--data-dir", str(tmp_path)]) == 1
    assert "not running" in capsys.readouterr().err


def test_a_copy_that_does_not_answer_is_named_and_no_request_is_left_lying(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # An older version, or one that hangs. What was asked must not lie there and stop the next one that starts.
    monkeypatch.setattr(cli, "ASK_PATIENCE", 0.4)
    wall = Running(tmp_path, answers=False)
    try:
        assert cli.main(["stop", "--data-dir", str(tmp_path)]) == 1
        told = capsys.readouterr().err
        assert f"process {os.getpid()}" in told and ("taskkill" in told) == (sys.platform == "win32")
        assert not (tmp_path / "qkvm.ask").exists()
    finally:
        wall.end()


def test_what_was_asked_of_an_earlier_run_does_not_stop_this_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "qkvm.ask").write_text("stop", encoding="utf-8")
    served = []

    def serve(self: uvicorn.Server, sockets: Any = None) -> None:
        served.append((tmp_path / "qkvm.ask").exists())
        self.should_exit = True

    monkeypatch.setattr(uvicorn.Server, "run", serve)
    assert cli.main(["--data-dir", str(tmp_path), "--port", free_port()]) == 0
    assert served == [False]


def test_ctrl_c_ends_it_without_a_page_of_traceback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The web server closes what is open on Ctrl+C and then hands the signal on, which Python makes a
    # KeyboardInterrupt of. Nothing caught it: every stop by hand ended in forty lines of traceback, and the
    # log never said "stopped".
    def interrupted(self: uvicorn.Server, sockets: Any = None) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(uvicorn.Server, "run", interrupted)
    assert cli.main(["--data-dir", str(tmp_path), "--port", free_port()]) == 0
    assert "stopped" in (tmp_path / "qkvm.log").read_text(encoding="utf-8")


def test_what_the_terminal_is_told_in_words_of_its_own_is_not_logged_at_it_as_well(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The libraries with known holes were listed for whoever started it, and the log line about the same
    # thing landed in the middle of the list.
    cli.setup_logging(tmp_path, "info")
    try:
        logging.getLogger("qkvm").warning("told already, in a friendlier way", extra=cli.SAID)
        logging.getLogger("qkvm").warning("not told any other way")
    finally:
        cli.stop_logging()
    shown = capsys.readouterr().err
    assert "not told any other way" in shown and "told already" not in shown
    assert "told already, in a friendlier way" in (tmp_path / "qkvm.log").read_text(encoding="utf-8")  # the log has both


def test_the_command_comes_first_and_start_is_the_plain_way_to_run_it(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # `qkvm start` is `qkvm`: it runs in this window. (--disable-2fa for nobody ends it before it serves.)
    assert cli.main(["start", "--data-dir", str(tmp_path), "--disable-2fa", "nobody"]) == 2
    with pytest.raises(SystemExit):
        cli.main(["--data-dir", str(tmp_path), "stop"])  # a word that is not an option, where no word belongs
    assert "qkvm [start|stop|restart|status]" in capsys.readouterr().err


def test_asking_the_running_copy_starts_no_copy_of_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # `python -m qkvm` runs the wall as a child it can start again. A question about the one that runs is no wall.
    monkeypatch.delenv(starter.CHILD, raising=False)
    monkeypatch.setattr(starter, "supervise", lambda argv: pytest.fail("started a wall to ask about one"))
    for command, status in (("status", 3), ("stop", 0), ("restart", 1)):
        monkeypatch.setattr(sys, "argv", ["qkvm", command, "--data-dir", str(tmp_path)])
        assert starter.main() == status


def test_what_a_first_start_says_about_setting_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(tmp_path / "plain"), "--port", free_port()]) == 0
    said = capsys.readouterr().out
    assert "First run" in said and "Setup code" not in said
    assert cli.main(["--data-dir", str(tmp_path / "coded"), "--port", free_port(), "--setup-code"]) == 0
    said = capsys.readouterr().out
    assert "Setup code" in said and "Setup code" in (tmp_path / "coded" / "qkvm.log").read_text(encoding="utf-8").replace("setup code", "Setup code")


def test_an_option_that_changes_nothing_in_this_copy_is_said_to(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # --allow-unsigned-updates is for a copy built without a release key. In one that has a key built in, as
    # published ones do, it lets nothing in: and its help still said "let the app install an update that is not
    # signed", with nothing at start to say otherwise. (That it lets nothing in is held by the tests of updates.)
    from qkvm import update

    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert update.RELEASE_KEYS  # the publisher's
    assert cli.main(["--data-dir", str(tmp_path / "asked"), "--port", free_port(), "--allow-unsigned-updates"]) == 0
    assert "--allow-unsigned-updates changes nothing" in capsys.readouterr().out
    assert cli.main(["--data-dir", str(tmp_path / "not asked"), "--port", free_port()]) == 0
    assert "allow-unsigned" not in capsys.readouterr().out
    monkeypatch.setattr(update, "RELEASE_KEYS", ())  # a copy somebody built without one: there it means something
    assert cli.main(["--data-dir", str(tmp_path / "no key"), "--port", free_port(), "--allow-unsigned-updates"]) == 0
    assert "changes nothing" not in capsys.readouterr().out


# --- a command that asks only reads ---------------------------------------------------------------------------
# Found by a review: whoever asks may be more than whoever owns the folder (an administrator looking at a
# service account's wall), and the folders looked into without being named come from a note that anybody
# may have written.


def test_asking_runs_nothing_from_the_folder_it_asks_about(tmp_path: Path) -> None:
    # An update installed from inside the app lives in the data folder and is put in front of the program's own
    # files when it starts. A question about a folder did the same: it ran whatever lay in that folder.
    planted = tmp_path / "updates" / "99.0.0" / "qkvm"
    planted.mkdir(parents=True)
    (tmp_path / "updates" / "current.json").write_text(json.dumps({"version": "99.0.0", "previous": None}), encoding="utf-8")
    (planted / "_version.py").write_text('__version__ = "99.0.0"\n', encoding="utf-8")
    ran = tmp_path / "ran"
    (planted / "cli.py").write_text(f"from pathlib import Path\n\n\ndef main(argv):\n    Path({str(ran)!r}).write_text('ran')\n    return 0\n", encoding="utf-8")
    where = Path(cli.__file__).resolve().parent.parent
    for command in ("status", "stop", "restart"):
        done = subprocess.run([sys.executable, "-m", "qkvm", command, "--data-dir", str(tmp_path)], cwd=where, capture_output=True, text=True, timeout=60)
        assert not ran.exists(), (command, done.stdout, done.stderr)
        assert "not running" in done.stdout + done.stderr


def test_asking_changes_nothing_in_the_folder_it_asks_about(tmp_path: Path) -> None:
    # It found out whether a wall runs by taking the lock itself: that made a lock file where there was none,
    # and cut one that was there down to its first byte.
    assert cli.main(["status", "--data-dir", str(tmp_path)]) == 3
    assert list(tmp_path.iterdir()) == []
    left = b"\n" + json.dumps({"pid": 4321, "since": 1_700_000_000.0}).encode()
    (tmp_path / "qkvm.lock").write_bytes(left)  # as a wall that was cut off leaves it
    for command, status in (("status", 3), ("stop", 0), ("restart", 1)):
        assert cli.main([command, "--data-dir", str(tmp_path)]) == status
        assert (tmp_path / "qkvm.lock").read_bytes() == left and sorted(p.name for p in tmp_path.iterdir()) == ["qkvm.lock"]


@pytest.mark.skipif(sys.platform == "win32", reason="making a link takes a privilege there that an ordinary account has not got")
def test_nothing_is_written_through_a_link_in_the_folder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    kept = tmp_path / "somebody-elses-file"
    kept.write_text("theirs", encoding="utf-8")
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "qkvm.lock").symlink_to(kept)
    assert cli.main(["status", "--data-dir", str(folder)]) != 0  # a link where the lock belongs is not looked through
    assert kept.read_text(encoding="utf-8") == "theirs"
    (folder / "qkvm.lock").unlink()
    wall = Running(folder)
    try:
        for name in ("qkvm.asking", "qkvm.ask"):
            (folder / name).symlink_to(kept)
        assert cli.main(["stop", "--data-dir", str(folder)]) == 0
        assert kept.read_text(encoding="utf-8") == "theirs" and wall.exit_status == 0
    finally:
        wall.end()


def test_what_a_lock_file_says_is_not_taken_at_its_word(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # It is read by whoever asks, and may have been written by anybody: printed as it stood, it could move the
    # cursor of the terminal it was printed in, and a date out of all range ended the command in a traceback.
    wall = Running(tmp_path)
    try:
        for said in (
            {"pid": "4321; rm -rf /", "since": 1e300, "version": "\x1b[2J0.1.0", "listening": 5},
            {"pid": -7, "since": float("nan"), "version": 3, "listening": ["\x1b]0;gone\x07http://127.0.0.1/", "http://127.0.0.1:8787/", {}]},
            {"pid": True, "since": "yesterday", "listening": ["x" * 5000]},
        ):
            wall.lock._said = {}
            wall.lock.say(**said)
            assert cli.main(["status", "--data-dir", str(tmp_path)]) == 0
            shown = capsys.readouterr()
            assert "is running" in shown.out and "\x1b" not in shown.out + shown.err and "rm -rf" not in shown.out and len(shown.out) < 600
        wall.lock._write(b"[" * 8000)  # nested deeper than anything that reads it will follow
        assert cli.main(["status", "--data-dir", str(tmp_path)]) == 0
        assert "is running" in capsys.readouterr().out
    finally:
        wall.end()


def test_it_stops_before_it_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A window that is not taking output (text selected in it, on Windows) holds whatever prints to it. The wall
    # said "stopping" first: whoever asked was told it did not stop, and it stopped at the next key pressed there.
    said = threading.Event()
    monkeypatch.setattr(cli, "say", lambda *words, **how: said.wait(30))
    wall = Running(tmp_path, answers=False)
    try:
        (tmp_path / "qkvm.ask").write_text("stop", encoding="utf-8")
        threading.Thread(target=cli.Asks(tmp_path, wall).look, daemon=True).start()  # type: ignore[arg-type]
        wall.thread.join(5)  # it ends once it was told to stop
        assert not wall.thread.is_alive() and wall.exit_status == 0
    finally:
        said.set()
        wall.end()


def test_stop_is_not_taken_for_done_in_the_moment_between_two_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # A wall that is being started again (an update, a restart asked for a moment ago) holds no lock for a
    # moment, and the copy that comes up throws away what was asked of the one before. "QKVM stopped", said in
    # that moment, was said of a wall that then went on running.
    monkeypatch.setattr(cli, "GONE_FOR", 1.0)
    lock = InstanceLock(tmp_path)
    assert lock.acquire()
    lock.say(pid=os.getpid(), since=1_700_000_000.0, version="0.1.0", listening=["http://127.0.0.1:8787/"])
    ended = threading.Event()

    def wall() -> None:
        request = tmp_path / "qkvm.ask"
        deadline = time.monotonic() + 20
        while not request.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        lock.release()  # it was on its way out to be started again when the request came
        time.sleep(0.4)
        assert lock.acquire(patience=2)
        lock.say(pid=os.getpid(), since=time.time(), version="0.1.0", listening=["http://127.0.0.1:8787/"])
        request.unlink(missing_ok=True)  # as a copy that starts does with what was asked of the one before
        while not request.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        request.unlink(missing_ok=True)
        lock.release()
        ended.set()

    thread = threading.Thread(target=wall, daemon=True)
    thread.start()
    try:
        assert cli.main(["stop", "--data-dir", str(tmp_path)]) == 0
        assert ended.is_set() and "stopped" in capsys.readouterr().out
    finally:
        thread.join(25)
        lock.release()


@pytest.mark.skipif(os.name != "posix", reason="who may write a folder is said in other ways on Windows, and not looked at there")
def test_a_data_folder_that_others_can_write_to_is_said_at_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # Whoever can write there can stop the wall, and can put there what it runs after an update.
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    folder = tmp_path / "open"
    folder.mkdir()
    folder.chmod(0o777)
    assert cli.main(["--data-dir", str(folder), "--port", free_port()]) == 0
    assert "can be written to by other users" in capsys.readouterr().err
    private = tmp_path / "private"
    assert cli.main(["--data-dir", str(private), "--port", free_port()]) == 0
    assert "other users" not in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="a folder has an owner to compare with on POSIX")
def test_a_folder_in_the_note_that_is_somebody_elses_is_not_looked_into(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # The note at home outlives the folders in it: one under /tmp may be somebody else's by now.
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    cli.remember(theirs)
    wall = Running(theirs)
    try:
        monkeypatch.setattr(os, "geteuid", lambda: os.stat(theirs).st_uid + 1)
        assert cli.main(["status"]) == 3 and wall.exit_status is None
    finally:
        wall.end()


# --- typed without saying where ------------------------------------------------------------------------------


def served_and_left(self: uvicorn.Server, sockets: Any = None) -> None:
    self.should_exit = True


def test_a_wall_started_with_a_folder_elsewhere_is_found_without_saying_where(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # `qkvm stop`, typed twice by somebody whose wall keeps its settings in a folder of their choosing: "QKVM is
    # not running" in the folder at home, which was true and of no use. The place was known the day it started.
    elsewhere = tmp_path / "walls" / "data"
    elsewhere.mkdir(parents=True)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(elsewhere), "--port", free_port()]) == 0
    assert cli.known_folders() == [elsewhere.resolve()]
    assert cli.main(["status"]) == 3  # it is known, and it does not run

    wall = Running(elsewhere)
    try:
        capsys.readouterr()
        assert cli.main(["status"]) == 0
        assert str(elsewhere.resolve()) in capsys.readouterr().out
        assert cli.main(["stop"]) == 0
        said = capsys.readouterr().out
        assert "stopped" in said and str(elsewhere.resolve()) in said and wall.exit_status == 0
    finally:
        wall.end()


def test_a_wall_in_the_folder_at_home_leaves_no_note_of_itself(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--port", free_port()]) == 0
    assert (home / ".qkvm" / "qkvm.json").exists() or (home / ".qkvm" / "qkvm.log").exists()
    assert cli.known_folders() == []


def test_with_two_walls_running_it_asks_which(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    walls = []
    try:
        for folder in (first, second):
            folder.mkdir()
            cli.remember(folder)
            walls.append(Running(folder))
        assert cli.main(["stop"]) == 2
        told = capsys.readouterr().err
        assert "--data-dir" in told and str(first.resolve()) in told and str(second.resolve()) in told
        assert all(wall.exit_status is None for wall in walls)  # neither was touched
        assert cli.main(["status"]) == 0  # ...and status says both
        said = capsys.readouterr().out
        assert str(first.resolve()) in said and str(second.resolve()) in said
    finally:
        for wall in walls:
            wall.end()


def test_a_folder_that_is_gone_is_forgotten(tmp_path: Path) -> None:
    gone, there = tmp_path / "gone", tmp_path / "there"
    for folder in (gone, there):
        folder.mkdir()
        cli.remember(folder)
    assert set(cli.known_folders()) == {gone.resolve(), there.resolve()}
    gone.rmdir()
    cli.remember(there)
    assert cli.known_folders() == [there.resolve()]
