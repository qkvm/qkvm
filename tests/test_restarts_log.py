"""What was done to a machine is in the activity log although qKVM was stopped before the machine answered."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn

from qkvm import kvm, redfish, update, vault
from qkvm.cli import SERVER_OPTIONS
from qkvm.core import Core
from qkvm.server import create_app
from tests.fake_redfish import FakeBmc
from tests.test_wall import CSRF, PASSWORD, closed_port, wait_until


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def bmc() -> Iterator[FakeBmc]:
    server = FakeBmc().start()
    yield server
    server.stop()


def test_a_power_cut_that_went_out_is_in_the_activity_log_though_qkvm_was_stopped_right_after(tmp_path: Path, bmc: FakeBmc) -> None:
    # README: "The activity log records the account behind every sign-in, change and action."
    # A power command is written down once the server is seen in its new state, up to 25 seconds after it went out.
    bmc.state.power_takes = 20.0  # the controller says "accepted", and the server is off twenty seconds later
    core = Core(tmp_path)
    core.unlock_at_start()
    port = closed_port()
    server = uvicorn.Server(uvicorn.Config(create_app(core), host="127.0.0.1", port=port, **SERVER_OPTIONS))
    serving = threading.Thread(target=server.run, daemon=True)
    serving.start()
    wait_until(lambda: server.started, "the web server never came up", timeout=20)
    answered: list[object] = []
    with httpx.Client(base_url=f"http://127.0.0.1:{port}", headers=CSRF, timeout=60, trust_env=False) as browser:
        assert browser.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        added = browser.post("/api/v1/devices", json={"url": bmc.url, "password": "secret", "name": "Database"})
        assert added.status_code == 201, added.text
        device = added.json()["device"]["id"]

        def press() -> None:
            try:
                answered.append(browser.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code)
            except Exception as ex:  # the program went away under it
                answered.append(type(ex).__name__)

        pressing = threading.Thread(target=press, daemon=True)
        pressing.start()
        wait_until(lambda: bmc.state.actions == ["system ForceOff"], "the command never went out", timeout=20)
        time.sleep(0.5)
        # qKVM is stopped, or its listeners are re-opened: what core.stop does (an update is installed, the port
        # is changed in the settings, `qkvm restart`, the service manager).
        server.should_exit = True
        serving.join(30)
        pressing.join(30)
    entries = [(e["event"], e.get("action"), e.get("device"), e.get("user")) for e in core.audit.tail(50) if e["event"].startswith("action")]
    print("\nsent to the controller:", bmc.state.actions, "| the browser was answered:", answered, "| in the activity log:", entries)
    assert entries, "a server's power was cut, and the activity log does not say that it was, or by whom"
