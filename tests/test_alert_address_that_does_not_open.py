"""An alert address that is saved and does not open any more: alerts go nowhere, and that is said.

With nothing said, the page showed alerts as set up, a machine went down, the activity log had its
"alert" entry, and nothing was sent.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from qkvm import alerts, kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_alerts import Inbox
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class Heard(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[tuple[int, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append((record.levelno, record.getMessage()))


def test_an_alert_that_goes_nowhere_because_its_address_does_not_open_is_said(tmp_path: Path) -> None:
    inbox, fake, heard = Inbox(), FakeKvm().start(), Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Build server")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            assert admin.post("/api/v1/alerts/test").status_code == 200 and inbox.titles() == ["Test alert from qKVM"]
            assert admin.get(snap(device)).status_code == 200
            time.sleep(0.6)  # (the two looks after which the watcher knows what is normal)

            saved = admin.core.store.alerts.webhook  # type: ignore[attr-defined]
            admin.core.store.alerts.webhook = {"nonce": "!", "data": saved["data"]}  # type: ignore[attr-defined]
            heard.lines.clear()
            fake.state.signal = False
            wait_until(lambda: any(entry["event"] == "alert" for entry in admin.get("/api/v1/audit").json()["entries"]), "the watcher never saw the signal go", timeout=20)
            time.sleep(1.0)  # (what was put into the outbox has had its turn)
            shown = admin.get("/api/v1/alerts").json()
            worse = [line for level, line in heard.lines if level >= logging.WARNING]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
        fake.stop()
        inbox.close()
    print(f">>> the page is told: enabled={shown['enabled']} has_webhook={shown['has_webhook']} last_error={shown['last_error']!r}")
    print(f">>> arrived at the address: {inbox.titles()[1:]}; qkvm.log at WARNING or worse: {worse}; all lines: {[line for _, line in heard.lines]}")
    assert inbox.titles() == ["Test alert from qKVM"], "it was delivered after all"
    # To whoever looks: alerts are switched on, and there is no address they go to; why, in the place
    # where the page shows how the last alert went, and once in the log.
    assert shown["enabled"] is True and shown["has_webhook"] is False
    assert "does not open any more" in (shown["last_error"] or ""), shown
    assert len([line for line in worse if "alerts go nowhere" in line]) == 1, worse
