"""The setup code is not written into a log others may read (round 5, after the report: the coordinator's point on open
point 1).

qkvm.log made by 0.2.0 in a folder that gave others its entries is kept as it is (qKVM changes nothing it finds), and is
named at every start; until its owner ran the line, a start with --setup-code wrote the code into it, for whoever may read
it to set the wall up first. Now, where the log (or the file it goes to) can be read by others, the code is shown where
qKVM was started and not written into the log, whose line says where it was shown; started without a console, the log
says it was shown nowhere, and what to do. On both systems.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import uvicorn

from qkvm import cli
from tests.test_control import free_port, served_and_left


def a_log_others_may_read(data: Path) -> None:
    data.mkdir()
    (data / "qkvm.log").write_text("made before\n", encoding="utf-8")
    if sys.platform == "win32":
        subprocess.run(["icacls", str(data / "qkvm.log"), "/grant", "*S-1-5-32-545:(R)"], check=True, capture_output=True)
    else:
        os.chmod(data, 0o755)
        os.chmod(data / "qkvm.log", 0o644)


def shown(said: str) -> str:
    found = re.search(r"Setup code \(asked for when setting up from another machine\): (\S+)", said)
    assert found is not None, said
    return found.group(1)


def test_a_setup_code_is_not_written_into_a_log_others_may_read_and_the_log_says_where_it_was_shown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    a_log_others_may_read(data)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 0
    code = shown(capsys.readouterr().out)
    cli.stop_logging()
    written = (data / "qkvm.log").read_text(encoding="utf-8")
    assert code not in written, written
    assert "the setup code was shown where qKVM was started and not written here: qkvm.log can be read by other users of this computer" in written, written


def test_a_setup_code_is_written_into_a_log_of_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"  # (made by the start: the log its own, as every file it makes)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 0
    code = shown(capsys.readouterr().out)
    cli.stop_logging()
    assert f"setup code for setting up from another machine: {code}" in (data / "qkvm.log").read_text(encoding="utf-8")  # (a wall started without a terminal)


def test_without_a_console_the_log_says_the_code_was_shown_nowhere_and_what_to_do(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    a_log_others_may_read(data)
    monkeypatch.setattr(uvicorn.Server, "run", served_and_left)
    monkeypatch.setattr(sys, "stdout", None)  # (pythonw, a scheduled task)
    assert cli.main(["--data-dir", str(data), "--port", free_port(), "--setup-code"]) == 0
    cli.stop_logging()
    written = (data / "qkvm.log").read_text(encoding="utf-8")
    assert not re.search(r"setup code for setting up from another machine: \S", written), written
    assert "the setup code was shown nowhere: qkvm.log can be read by other users of this computer, and qKVM was started without a console" in written, written


def test_a_wall_whose_starter_has_no_console_says_the_code_was_shown_nowhere(tmp_path: Path) -> None:
    # The round 5 review (a LOW, review-core5\probes\p5_setup_code_pythonw.py): as the README starts a wall on Windows
    # without a console (pythonw, a task at log-on), the starter hands its child a real nowhere (DEVNULL) for the stdout it
    # does not have, and the child took that for a console: the code went to NUL, and the log said it was shown where qKVM
    # was started. The starter tells its child that there is no console. A real starter and its child, as started so.
    import qkvm

    data = tmp_path / "data"
    a_log_others_may_read(data)
    environment = {name: value for name, value in os.environ.items() if name not in ("QKVM_CHILD", "QKVM_NO_CONSOLE")}
    environment.update(PYTHONPATH=str(Path(qkvm.__file__).resolve().parent.parent), PYTHONDONTWRITEBYTECODE="1")
    options: dict[str, object]
    if sys.platform == "win32":
        python = str(Path(sys.executable).with_name("pythonw.exe"))
        options = {"creationflags": 0x8, "close_fds": True}  # DETACHED_PROCESS, no handles: as a task at log-on starts it
        closer: list[str] = []
    else:
        # No stdout and no stderr, as a starter without a console has. A small Python closes them and then becomes the
        # starter (exec); a function run in the child before it starts would have this whole test process copied by fork(),
        # which a machine that counts the memory it promised refuses once the suite has grown the process (GitHub's Ubuntu
        # 26.04 runners, 2026-11-16: "Cannot allocate memory" on every Python, with the rest of the suite passing).
        python = sys.executable
        options = {"stdin": subprocess.DEVNULL}
        closer = ["-P", "-c", "import os, sys; os.close(1); os.close(2); os.execv(sys.executable, [sys.executable, *sys.argv[1:]])"]
    command = [python, *closer, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", free_port(), "--bind", "local", "--setup-code"]
    wall = subprocess.Popen(command, env=environment, cwd=tmp_path, **options)  # type: ignore[call-overload]
    written = ""
    try:
        deadline = time.monotonic() + 60
        while "first run" not in written and time.monotonic() < deadline and wall.poll() is None:
            time.sleep(0.2)
            written = (data / "qkvm.log").read_text(encoding="utf-8", errors="replace")
    finally:
        subprocess.run([sys.executable, "-P", "-m", "qkvm", "stop", "--data-dir", str(data)], env=environment, cwd=tmp_path, capture_output=True, timeout=90)
        try:
            wall.wait(60)
        except subprocess.TimeoutExpired:
            wall.kill()
    assert not re.search(r"setup code for setting up from another machine: \S", written), written
    assert "the setup code was shown nowhere: qkvm.log can be read by other users of this computer, and qKVM was started without a console" in written, written


def test_nothing_has_the_whole_process_copied_to_start_a_program() -> None:
    # The fault above, wherever else it could come: a function to run in the child before the program starts (what Popen
    # calls preexec) makes Popen copy the whole process with fork(), the test process grown by the suite or a wall grown by its
    # day. Every other way of starting shares the memory until the program is loaded, which no machine refuses.
    word = "preexec" + "_fn"
    here = Path(__file__).resolve().parent
    import qkvm

    places = [*here.glob("*.py"), *Path(qkvm.__file__).resolve().parent.rglob("*.py")]
    assert len(places) > 100
    assert [path.name for path in places if word in path.read_text(encoding="utf-8")] == []
