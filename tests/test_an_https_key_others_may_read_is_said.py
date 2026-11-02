"""A key of the HTTPS certificate that others may read is said at every start, with what to do (the round 4 review, L3;
review-core4\\probes\\p5_tls.py case 2).

0.2.0 made tls\\key.pem in the data folder as the folder gave it: in a folder others may read, the key was theirs to read,
and they could pose as the wall. qKVM changes nothing it finds; nothing was said of it. Now it is said, with the line that
removes the tls folder; a new pair, its own, is made where it is gone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import tlscert
from qkvm.cli import main as run_cli
from tests.printed_lines import run_printed


def said_at_start(data: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "nobody"]) == 2  # (an offline command: it ends before serving)
    return " ".join(capsys.readouterr().err.split())


def test_an_https_key_others_may_read_is_said_with_the_line_that_has_a_new_one_made(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    data.mkdir()
    _, key, first = tlscert.ensure_certificate(data / "tls", ["127.0.0.1"])
    assert "certificate for HTTPS" not in said_at_start(data, capsys)  # (its own: nothing to say)
    if sys.platform == "win32":
        subprocess.run(["icacls", str(key), "/grant", "*S-1-5-32-545:(R)"], check=True, capture_output=True)
        line = f'rmdir /S /Q "{data / "tls"}"'
    else:
        for path, mode in ((data, 0o755), (data / "tls", 0o755), (key, 0o644)):
            os.chmod(path, mode)
        line = f"rm -r {data / 'tls'}"
    said = said_at_start(data, capsys)
    assert f"qkvm: {key}, the key of the certificate for HTTPS, can be read by other users of this computer: whoever read it can pose as this wall." in said, said
    given = f"in Command Prompt: {line}" if sys.platform == "win32" else line  # (the console named on Windows: L2)
    assert f"Delete the tls folder while qKVM is stopped, and a new pair is made, its own ({given})" in said, said
    assert run_printed(line).returncode == 0
    assert "certificate for HTTPS" not in said_at_start(data, capsys)
    _, _, second = tlscert.ensure_certificate(data / "tls", ["127.0.0.1"])
    assert second != first
