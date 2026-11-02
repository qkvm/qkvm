"""A test that runs the command line leaves logging as it found it for the tests after it (register row 26 of 0.2.1,
w4c Open): the command line sets up the program's logging (`qkvm` and the web server's logger at the level asked for,
writing to a queue of their own and passing nothing on, the event loop kept to its errors and the libraries that talk
to devices to their warnings) and, in a program that ends there, rightly gives none of that back. A test after it
then heard less than it asked for: one that listens at the finest level to see that a token is never logged
(test_proxmox's, for one) heard nothing finer than `qkvm`'s info and the libraries' warnings, and passed on nothing.
(Before pytest 9, whose `caplog` also listens on a logger that passes nothing on, it heard nothing of `qkvm` at all.)

The two tests run in the order written: the first runs the command line, the second listens."""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

import pytest

from qkvm.cli import main as run_cli


def test_the_command_line_sets_up_the_programs_logging(tmp_path: Path) -> None:
    assert run_cli(["--data-dir", str(tmp_path), "--disable-2fa", "nobody"]) == 2  # (no such account: said and ended)
    ours = logging.getLogger("qkvm")
    # As the program has it, which is what the test after this one must not find:
    assert ours.propagate is False and ours.level == logging.INFO
    assert logging.getLogger("httpx").level == logging.WARNING and logging.getLogger("asyncio").level == logging.ERROR


def test_a_test_after_it_hears_everything_it_listens_for(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("qkvm").warning("a warning of the program")
    logging.getLogger("qkvm.proxmox").debug("a fine line of a part of it")
    logging.getLogger("httpx").debug("a fine line of a library that talks to devices")
    logging.getLogger("asyncio").warning("a warning of the event loop")
    heard = [record.getMessage() for record in caplog.records]
    assert heard == [
        "a warning of the program",
        "a fine line of a part of it",
        "a fine line of a library that talks to devices",
        "a warning of the event loop",
    ]
    ours = logging.getLogger("qkvm")
    assert ours.propagate is True and not [h for h in ours.handlers if isinstance(h, logging.handlers.QueueHandler)]
