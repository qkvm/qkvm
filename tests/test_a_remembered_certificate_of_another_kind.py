"""What is remembered as a device's certificate is a certificate, or nothing: and only nothing is nothing."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmDevice, KvmError
from tests.fake_kvm import FakeKvm
from tests.test_wall import add, snap, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


OF_ANOTHER_KIND = [False, 0, [], {}, True, 7, 1.5, ["-----BEGIN CERTIFICATE-----"], {"pem": "x"}]


def edited(folder: Path, value: Any) -> None:
    """Both copies of the settings file as a hand or a script left them: the first device's certificate is `value`."""
    for name in ("qkvm.json", "qkvm.bak"):
        state = json.loads(settings_text(folder / name, encoding="utf-8"))
        state["devices"][0]["cert_pem"] = value
        write_settings_text(folder / name, json.dumps(state), encoding="utf-8")


@pytest.mark.parametrize("value", OF_ANOTHER_KIND, ids=repr)
def test_something_that_is_no_text_where_a_certificate_was_trusts_nobody_new(tmp_path: Path, value: Any) -> None:
    # A device over HTTPS has its certificate remembered at first contact, and the wall talks to nothing else
    # at that address from then on. Nothing remembered is what lets a first certificate in. In the settings
    # file, `false`, 0 or an empty list in that place (a slip of a hand, or of a script that writes the file)
    # read as nothing as well: the next thing to answer at the address was trusted, and sent the device's
    # saved password, with nobody asked. Found by an outside reviewer, with a stand-in swapped for another.
    known = FakeKvm(tls_dir=tmp_path / "known").start()
    folder = tmp_path / "wall"
    try:
        with wall(folder) as admin:
            tile = add(admin, known.url, name="Build server")
            assert admin.core.store.device(tile).cert_pem and admin.get(snap(tile)).status_code == 200  # type: ignore[attr-defined]
    finally:
        known.stop()
    edited(folder, value)
    other = FakeKvm(port=known.port, tls_dir=tmp_path / "other").start()  # the same address, another certificate
    try:
        with wall(folder) as admin:
            store = admin.core.store  # type: ignore[attr-defined]
            # No reason not to start, and no reason to go back to the second copy: the wall is there, ...
            assert not store.restored and admin.get("/api/v1/wall").status_code == 200
            # ...the tile says that its certificate cannot be read, and what answers there now is told nothing.
            reply = admin.get(snap(tile))
            assert reply.status_code != 200 and reply.json()["code"] == "cert_invalid", reply.text
            assert admin.get("/api/v1/status").json()[tile]["error"]["code"] == "cert_invalid"
            assert other.state.logins == 0 and other.state.tokens == set()
            assert isinstance(store.device(tile).cert_pem, str) and store.device(tile).cert_pem  # kept, as a text that is none
            # A person looks at what the device shows now, and says that it is to be trusted: then, and only then.
            shown = admin.get(f"/api/v1/devices/{tile}/certificate").json()
            assert shown["saved"] is None and shown["presented"]
            assert other.state.logins == 0
            assert admin.post(f"/api/v1/devices/{tile}/trust", json={"fingerprint": shown["presented"]}).status_code == 200
            assert admin.get(snap(tile)).status_code == 200 and other.state.logins >= 1
    finally:
        other.stop()


@pytest.mark.parametrize("value", [False, 0, [], {}], ids=repr)
def test_the_device_itself_trusts_afresh_only_where_nothing_is_remembered(tmp_path: Path, value: Any) -> None:
    # The same asked where the trust is given, whoever hands the device what is remembered: the reader of
    # the settings file is one door, and not the only one there will ever be.
    there = FakeKvm(tls_dir=tmp_path / "there").start()
    try:

        async def asked() -> str:
            device = KvmDevice(DeviceSpec("d", "Build server", there.url, "admin", "secret", cert_pem=value))
            try:
                await device.snapshot(640)
            except KvmError as ex:
                return ex.code
            finally:
                await device.close()
            return "talked to"

        assert asyncio.run(asked()) == "cert_invalid"
        assert there.state.logins == 0
    finally:
        there.stop()


def test_nothing_remembered_is_still_nothing_and_a_text_that_is_no_certificate_still_starts(tmp_path: Path) -> None:
    # What this does not touch. Nothing (null, or no text at all) is what a device has that was never
    # reached: it is trusted at first contact, as ever. And a text that is no certificate is what it was:
    # its tile says that the certificate cannot be read, and the rest of the wall is there.
    known = FakeKvm(tls_dir=tmp_path / "known").start()
    folder = tmp_path / "wall"
    try:
        with wall(folder) as admin:
            tile = add(admin, known.url, name="Build server")
            remembered = admin.core.store.device(tile).cert_pem  # type: ignore[attr-defined]
        for nothing in (None, ""):
            edited(folder, nothing)
            with wall(folder) as admin:
                assert not admin.core.store.restored  # type: ignore[attr-defined]
                assert admin.get(snap(tile)).status_code == 200
                assert admin.core.store.device(tile).cert_pem == remembered  # type: ignore[attr-defined]
        logins = known.state.logins
        edited(folder, "false")
        with wall(folder) as admin:
            assert not admin.core.store.restored  # type: ignore[attr-defined]
            reply = admin.get(snap(tile))
            assert reply.status_code != 200 and reply.json()["code"] == "cert_invalid", reply.text
            assert admin.get("/api/v1/wall").status_code == 200
        assert known.state.logins == logins  # not talked to, on the strength of something that is no certificate
    finally:
        known.stop()
