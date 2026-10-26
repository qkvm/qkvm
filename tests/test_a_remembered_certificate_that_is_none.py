"""A tile whose remembered certificate is none (`kvm.Device._tls_context`).

Measured with the waits the program really has (no `ERROR_HOLD = 0`): a wall that is looked at ten times a
second for twelve seconds. How often the certificate is tried, how many lines the log gets, whether anything
at all is sent to the device meanwhile, what the tile is told, and whether "Trust this certificate" puts it right.

And what the page offers: the tile's sentence says "Look at its certificate and trust it again", and the
button that does that is on the tile.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_wall import add, snap, wait_until, wall
from tests.settings_file import settings_text, write_settings_text

NONE_OF_THEM: dict[str, Any] = {
    "cut short": lambda pem: pem[:400],
    "a number": lambda pem: 5,
    "a list": lambda pem: [pem],
    "dressed as one": lambda pem: "-----BEGIN CERTIFICATE-----\nQUJDQUJDQUJD\n-----END CERTIFICATE-----\n",
    "a text that is not ASCII": lambda pem: "-----BEGIN CERTIFICATE-----\nÄÖÜ\n-----END CERTIFICATE-----\n",
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.said: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.said.append(f"{record.levelname} {record.getMessage()}{' +traceback' if record.exc_info else ''}")


@pytest.mark.parametrize("what", list(NONE_OF_THEM))
def test_a_tile_whose_certificate_is_none_is_left_alone_says_so_once_and_can_be_put_right(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, what: str) -> None:
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    lines = Lines()
    logging.getLogger("qkvm").addHandler(lines)
    try:
        with wall(tmp_path / "wall") as admin:
            tile = add(admin, device.url, name="Build server")
            real = admin.get("/api/v1/wall").json()["devices"][0]["fingerprint"]
        for name in ("qkvm.json", "qkvm.bak"):
            saved = json.loads(settings_text(tmp_path / "wall" / name, encoding="utf-8"))
            saved["devices"][0]["cert_pem"] = NONE_OF_THEM[what](saved["devices"][0]["cert_pem"])
            write_settings_text(tmp_path / "wall" / name, json.dumps(saved), encoding="utf-8")
        tried = []
        made = kvm.pinned_context
        monkeypatch.setattr(kvm, "pinned_context", lambda pem: (tried.append(time.monotonic()), made(pem))[1])
        logins, requests = device.state.logins, device.state.requests
        lines.said.clear()
        with wall(tmp_path / "wall") as admin:
            assert admin.core.store.restored is False  # type: ignore[attr-defined]
            started, pictures, states = time.monotonic(), [], []
            while time.monotonic() - started < 12:
                pictures.append(admin.get(snap(tile)).status_code)
                states.append(admin.get("/api/v1/status").json()[tile])
                time.sleep(0.1)
            about = [line for line in lines.said if "Build server" in line or "traceback" in line]
            shown = admin.get("/api/v1/wall").json()["devices"][0]["fingerprint"]
            print(f">>> {what}: {len(pictures)} looks in 12 s; the certificate was tried {len(tried)} times; lines in the log: {about}")
            print(f">>> pictures answered {sorted(set(pictures))}; the tile: {states[-1]['state']} / {states[-1]['error']}; sent to the device meanwhile: {device.state.requests - requests} requests, {device.state.logins - logins} sign-ins")
            assert set(pictures) <= {502, 503} and all(state["state"] == "error" and state["error"]["code"] == "cert_invalid" for state in states)
            assert len(about) == 1 and not any("traceback" in line for line in lines.said), about
            assert len(tried) <= 6, f"tried {len(tried)} times in twelve seconds"
            assert (device.state.requests, device.state.logins) == (requests, logins), "something was sent to a device whose certificate could not be checked"
            # ...and the way out: the dialog shows what the device presents, and trusting it replaces what was none.
            asked = admin.get(f"/api/v1/devices/{tile}/certificate").json()
            assert asked["presented"] == real
            assert admin.post(f"/api/v1/devices/{tile}/trust", json={"fingerprint": real}).status_code == 200
            # (Its picture comes once the new connection is up: 503 "Connecting" meanwhile, which a busy computer answered.)
            wait_until(lambda: admin.get(snap(tile)).status_code == 200, "trusting the certificate did not bring the picture back", timeout=30)
            print(f">>> {what}: the fingerprint shown for the tile before it was put right: {shown}; in the dialog, as remembered: {asked['saved']}")
            assert shown is None and asked["saved"] is None, "the tile says its certificate cannot be read, and the dialog shows a fingerprint as remembered for it"
    finally:
        logging.getLogger("qkvm").removeHandler(lines)
        device.stop()


def test_the_tile_that_says_to_look_at_its_certificate_offers_the_button_for_it() -> None:
    # The sentence of `cert_invalid` ends "Look at its certificate and trust it again." The button for that
    # is offered on the tile and in the tile's dialog for it, as it is for a certificate that changed
    # (app.js: veilContent, and `certProblem` in the actions dialog). It was offered for the one only, and the
    # way to the other led through Edit, which the sentence does not say.
    import qkvm

    page = (Path(qkvm.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    offered = [line.strip() for line in page.splitlines() if "cert_mismatch" in line]
    print(f">>> the page's lines that offer 'Review certificate' by the tile's error: {len(offered)}; of them naming cert_invalid: {sum('cert_invalid' in line for line in offered)}")
    assert len(offered) >= 2 and all("cert_invalid" in line for line in offered[:2]), offered
