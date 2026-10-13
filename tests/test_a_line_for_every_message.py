"""A line in the log for every message of a device, of this program's own writing.

What a library, the event loop and the web server say is held to one line of each kind a minute. A line
of this program's own that a device got written once for every message it sent: a JetKVM's "somebody
else connected" (jetkvm.py, `_on_message`: "in use from another browser"). The session is ended for it
at the next look, up to a second later; every further message that arrived until it was gone was another
line. qkvm.log keeps 2 MB and three files.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from aiortc import RTCDataChannel

from qkvm import kvm, update, vault
from tests.fake_jetkvm import FakeJetKvm
from tests.test_wall import add, wait_until, wall

MANY = int(os.environ.get("QKVM_TEST_MANY", "5000"))  # of about 80 bytes each: what a device on the same network sends in well under a second


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def jet() -> Iterator[FakeJetKvm]:
    server = FakeJetKvm().start()
    yield server
    server.stop()


class Counted(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_a_jetkvm_that_says_somebody_else_connected_many_times_is_one_line_in_the_log(tmp_path: Path, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # The stand-in's own end of the data channel, made hostile: after the last thing it says of itself when
    # a viewer connects ("usbState"), it says "otherSessionConnected" MANY times, as fast as they are taken.
    real = RTCDataChannel.send
    sent = [0]

    def send(self: Any, data: Any) -> None:
        real(self, data)
        if isinstance(data, str) and '"usbState"' in data:
            for _ in range(MANY):
                real(self, json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None}))
                sent[0] += 1

    monkeypatch.setattr(RTCDataChannel, "send", send)
    heard, ours = Counted(), logging.getLogger("qkvm")
    level = ours.level
    ours.addHandler(heard)
    ours.setLevel(logging.INFO)  # as the program sets it, started without --log-level
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            client.get(f"/api/v1/devices/{device}/snapshot")  # somebody looks at the wall: the video connection is made
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "busy", "the JetKVM was never taken to be in use", timeout=30)
            wait_until(lambda: sent[0] >= MANY, "the stand-in did not get to say it all", timeout=30)
            time.sleep(2.0)  # what was on its way has arrived, or the connection is gone
    finally:
        ours.removeHandler(heard)
        ours.setLevel(level)
    lines = [line for line in heard.lines if "in use from another browser" in line]
    print(f">>> the JetKVM said 'somebody else connected' {sent[0]} times in one session: {len(lines)} lines in the log ({sum(len(line) + 40 for line in lines)} bytes of the 2,000,000 a log file holds)")
    assert len(lines) <= 1, f"{len(lines)} lines in the log for one session of one device"
