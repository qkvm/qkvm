"""A data folder made by the released 0.3.2, opened by this version: everything is there and works (0.4.0, Q2).

tests/fixtures/data-0.3.2.tar was made by tools/make_0_3_2_data.py with the published 0.3.2 (commit dd19556), run as a
person runs it, through its own API: an admin and an operator with two-factor sign-in, an API token, five devices of four
kinds with their passwords (stand-ins on loopback), two saved actions, its one alert address, activity lines, a minute of
history, and an export encrypted with a passphrase. Its made.json says what each was given.

This version opens that folder (the storage key restored beside it as a person restores it: private to the account), and
then each account signs in as it did (the operator with a code of the app, and with one of the codes that work once),
the token reads the wall, each device is reached with the password 0.3.2 saved for it, the alert address is the first
destination and is sent to, the actions are there, the activity log of 0.3.2 is "from before the chain" and the chain
after it is intact, the history 0.3.2 kept is there, and the export imports on a wall of its own with every password.
After that first start the settings still hold the alert address where 0.3.2 reads it, as 0.3.2 sealed it; and where
QKVM_RELEASED_0_3_2 names the released 0.3.2's source, that 0.3.2 itself is started on the folder and finds it.

Nothing here listens at a port of its own choosing (the Linux runner, many files at once: one was taken). Today's
stand-ins take ports that are free, and the devices are moved to them before the first start, in the settings and
nothing else, as if each had been given a new port while the wall was stopped: the password 0.3.2 saved then goes to
the device at its new place. What this version sends to the alert address is taken where it leaves (egress.post), after
the program's own judgement of that address; nothing listens at it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from qkvm import egress, kvm, totp, update
from qkvm.store import FROM_0_3_2
from tests import fake_amt, fake_kvm, fake_redfish, fake_vnc
from tests.settings_file import settings_text, write_settings_text
from tests.test_control import free_port
from tests.test_wall import CSRF, wait_until, wall

APP = Path(__file__).resolve().parent.parent
FIXTURE = APP / "tests" / "fixtures" / "data-0.3.2.tar"
# The folder holds a storage key, made up for this test alone: it is kept in the maintainers' repository and not
# published (no key goes out). tools/make_0_3_2_data.py makes one anew from the released 0.3.2.
pytestmark = pytest.mark.skipif(not FIXTURE.exists(), reason="tests/fixtures/data-0.3.2.tar is not here: make it with tools/make_0_3_2_data.py")
RELEASED = os.environ.get("QKVM_RELEASED_0_3_2", "")  # the released 0.3.2's source (git archive v0.3.2), where it is at hand
TEST_ALERT = "Test alert from qKVM"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)  # (the real status, not "connecting")
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")  # (the folder's settings check for updates: never the real GitHub)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """What this version sends to an alert address, taken where it leaves: the address, the headers, and what the
    program's own judgement says of that address (None: it may go there). Answered as a service that took it."""
    told: list[dict[str, Any]] = []

    async def post(url: str, body: bytes, headers: Any, *, private_ok: bool, own: Any, own_ports: Any = (), still: Any = None) -> egress.Reply:
        if still is not None and not still():  # (as egress.post: asked right before it goes)
            raise egress.Withheld("Not sent: what it was for was stopped while it waited")
        where = urlsplit(url)
        judged = egress.judge(where.hostname or "", private_ok=private_ok, own=own, port=where.port or 80, own_ports=own_ports)
        told.append({"url": url, "headers": dict(headers), "body": body, "judged": judged})
        return egress.Reply(200)

    monkeypatch.setattr(egress, "post", post)
    return told


def unpacked(where: Path) -> dict[str, Any]:
    """The fixture in `where`: data/, data.keys/ (the storage key restored private to this account, as from a backup: an
    archive carries no Windows ACL), devices/ (the certificates of the two HTTPS stand-ins), the export. Its made.json."""
    with tarfile.open(FIXTURE) as archive:
        archive.extractall(where, filter="data")
    key = where / "data.keys" / "vault.key"
    raw = key.read_bytes()
    key.unlink()
    key.parent.rmdir()
    if sys.platform == "win32":
        from qkvm import _folders, _vault_windows

        _folders.private_folder(key.parent)
        descriptor = _vault_windows.create_private(key)
    else:
        key.parent.mkdir(mode=0o700)
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    made: dict[str, Any] = json.loads((where / "made.json").read_text(encoding="utf-8"))
    assert made["version"] == "0.3.2"
    return made


@contextmanager
def stand_ins(made: dict[str, Any], where: Path) -> Iterator[dict[str, Any]]:
    """Today's stand-ins for the devices of the fixture, each on a port that is free, with the password 0.3.2 was given for
    it (and the HTTPS ones with the certificate they showed it, the server's controller with the numbers it gave). By the
    device's name: the stand-in, and its address."""
    started: dict[str, Any] = {}
    try:
        for device in made["devices"]:
            tls = where / "devices" / device["tls"] if "tls" in device else None
            if device["kind"] == "kvmd":
                started[device["name"]] = fake_kvm.FakeKvm(fake_kvm.FakeState(password=device["password"]), tls_dir=tls).start()
            elif device["kind"] == "redfish":
                state = fake_redfish.BmcState(username=device["username"], password=device["password"], uuid=device["uuid"], root_uuid=device["root_uuid"])
                started[device["name"]] = fake_redfish.FakeBmc(state, tls_dir=tls).start()
            elif device["kind"] == "vnc":
                started[device["name"]] = fake_vnc.FakeVnc(fake_vnc.VncState(password=device["password"])).start()
            else:
                assert device["kind"] == "amt"
                started[device["name"]] = fake_amt.FakeAmt(fake_amt.AmtState(username=device["username"], password=device["password"])).start()
        yield started
    finally:
        for each in started.values():
            each.stop()


def moved(data: Path, started: dict[str, Any]) -> None:
    """Each device of the wall in `data` at the address its stand-in has now (by name), in its settings (and their second
    copy), sealed again with the folder's own storage key; nothing else of them changes."""
    for name in ("qkvm.json", "qkvm.bak"):
        settings = json.loads(settings_text(data / name))
        for device in settings["devices"]:
            device["url"] = started[device["name"]].url
        write_settings_text(data / name, json.dumps(settings))


def sign_in(client: TestClient, name: str, password: str, code: str = "") -> Any:
    return client.post("/api/v1/login", json={"name": name, "password": password, **({"code": code} if code else {})})


def all_online(client: TestClient, ids: list[str]) -> bool:
    status = client.get("/api/v1/status").json()
    return all(status.get(device, {}).get("state") == "online" for device in ids)


def test_this_version_opens_a_data_folder_of_0_3_2_and_everything_is_there_and_works(tmp_path: Path, sent: list[dict[str, Any]]) -> None:
    made = unpacked(tmp_path)
    data = tmp_path / "data"
    written_before = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
    sealed_before = json.loads(settings_text(data / "qkvm.json"))["alerts"]["webhook"]
    names = [device["name"] for device in made["devices"]]
    with stand_ins(made, tmp_path) as stood:
        moved(data, stood)
        with wall(data, sign_in=False) as client:
            assert client.get("/api/v1/session").json()["initialized"] is True
            # The token 0.3.2 gave out reads the wall, before anybody signs in.
            listed = client.get("/api/v1/wall", headers={"Authorization": f"Bearer {made['token']}"})
            assert listed.status_code == 200, listed.text
            assert sorted(device["name"] for device in listed.json()["devices"]) == sorted(names)
            # The admin, with the password 0.3.2 took.
            assert sign_in(client, "ada", "a wrong one").status_code == 401
            assert sign_in(client, "ada", made["accounts"]["ada"]["password"]).status_code == 200
            devices = {device["name"]: device for device in client.get("/api/v1/wall").json()["devices"]}
            for device in made["devices"]:
                here = devices[device["name"]]
                assert (here["id"], here["group"], here["has_password"], here["url"]) == (made["ids"][device["name"]], device["group"], True, stood[device["name"]].url), here
            # Every device reached with the password 0.3.2 saved for it: each stand-in lets in its own password alone.
            ids = [made["ids"][name] for name in names]
            wait_until(lambda: all_online(client, ids), f"not every device of 0.3.2 came online: {client.get('/api/v1/status').json()}", timeout=90)
            assert stood["Rack KVM"].state.logins >= 1
            # The saved actions.
            assert [(action["name"], action["kind"]) for action in client.get("/api/v1/actions").json()["actions"]] == [(action["name"], action["kind"]) for action in made["actions"]]
            # The one alert address of 0.3.2: the first destination, said as before, and sent to in ntfy's way.
            alerts = client.get("/api/v1/alerts").json()
            assert (alerts["enabled"], alerts["has_webhook"], alerts["format"]) == (True, True, "ntfy"), alerts
            [first] = client.get("/api/v1/alerts/destinations").json()["destinations"]
            assert (first["id"], first["kind"]) == (FROM_0_3_2, "ntfy"), first
            assert client.post("/api/v1/alerts/test").status_code == 200
            [test] = [each for each in sent if each["headers"].get("Title") == TEST_ALERT]
            assert test["url"] == made["alerts"] and test["judged"] is None, test
            # The activity log of 0.3.2: every line there, from before the chain, and the chain after them intact.
            events = [entry["event"] for entry in client.get("/api/v1/audit", params={"limit": 500}).json()["entries"]]
            for entry in written_before:
                assert entry["event"] in events
            checked = client.post("/api/v1/audit/check").json()
            assert checked["result"]["intact"] is True and checked["result"]["unproved"] == 0, checked
            assert checked["result"]["before"] == len(written_before), checked
            # The history 0.3.2 kept: each device seen from before this version started.
            for name in names:
                summary = client.get(f"/api/v1/devices/{made['ids'][name]}/history", params={"what": "summary", "since": made["made"] - 3600}).json()
                assert summary["first_seen"] is not None and summary["first_seen"] <= made["made"], (name, summary)
            assert client.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
            # The operator: the password alone is not enough, a code of the app is, and so is one of the codes that work once.
            otto = made["accounts"]["otto"]["password"]
            assert sign_in(client, "otto", otto).json()["code"] == "code_required"
            assert sign_in(client, "otto", otto, totp.code_at(made["totp_secret"], int(time.time() // 30))).status_code == 200
            assert client.get("/api/v1/session").json()["user"]["role"] == "operator"
            assert client.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
            assert sign_in(client, "otto", otto, made["one_time_codes"][0]).status_code == 200
            assert sign_in(client, "otto", otto, made["one_time_codes"][0]).status_code == 401, "a code that works once worked twice"
        # The export of 0.3.2 imports, with every password, on a wall of its own (its devices then moved as these were).
        file = (tmp_path / made["export"]["file"]).read_text(encoding="utf-8")
        other = tmp_path / "another"
        with wall(other) as admin:
            there = admin.post("/api/v1/import/read", json={"file": file, "passphrase": made["export"]["passphrase"]}).json()
            assert there["encrypted"] and sorted(device["name"] for device in there["devices"]) == sorted(names) and all(device["password"] for device in there["devices"])
            taken = admin.post("/api/v1/import", json={"file": file, "passphrase": made["export"]["passphrase"], "take": ["devices", "actions"]})
            assert taken.status_code == 200 and (taken.json()["devices"], taken.json()["actions"]) == (5, 2), taken.text
        moved(other, stood)
        with wall(other) as admin:
            imported = [device["id"] for device in admin.get("/api/v1/wall").json()["devices"]]
            assert len(imported) == 5
            wait_until(lambda: all_online(admin, imported), f"not every device of the export came online: {admin.get('/api/v1/status').json()}", timeout=90)
    # After this first start, the alert address is still where 0.3.2 reads it, as 0.3.2 sealed it.
    saved = json.loads(settings_text(data / "qkvm.json"))
    assert saved["alerts"]["webhook"] == sealed_before and saved["alerts"]["format"] == "ntfy" and saved["alerts"]["enabled"] is True
    assert saved["destinations"][0]["id"] == FROM_0_3_2 and saved["destinations"][0]["secret"] == sealed_before


@pytest.mark.skipif(not RELEASED, reason="QKVM_RELEASED_0_3_2 does not name the released 0.3.2's source")
def test_0_3_2_started_again_after_this_version_finds_its_alert_address(tmp_path: Path, sent: list[dict[str, Any]]) -> None:
    # (Nothing listens at the address: 0.3.2's test alert finds it, opens it and is not delivered, which it says so, 502
    # not_delivered. One whose address it did not find, or could not open, it answers 409 no_webhook.)
    import httpx

    source = Path(RELEASED)
    assert '__version__ = "0.3.2"' in (source / "qkvm" / "_version.py").read_text(encoding="utf-8")
    made = unpacked(tmp_path)
    data = tmp_path / "data"
    with wall(data, sign_in=False) as client:  # (this version's first start: it signs in, sends a test alert, and saves)
        assert sign_in(client, "ada", made["accounts"]["ada"]["password"]).status_code == 200
        assert client.post("/api/v1/alerts/test").status_code == 200 and sent
    port = free_port()
    environment = {name: value for name, value in os.environ.items() if not name.startswith("QKVM_")}
    environment.update(PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
    started = subprocess.Popen([sys.executable, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", port, "--bind", "local"], env=environment, cwd=tmp_path)
    try:
        base = f"http://127.0.0.1:{port}"

        def up() -> bool:
            try:
                return httpx.get(base + "/healthz", timeout=5).status_code == 200
            except httpx.HTTPError:
                assert started.poll() is None, "0.3.2 did not start on the folder this version had opened"
                return False

        wait_until(up, "0.3.2 did not come up", timeout=120)
        with httpx.Client(base_url=base, headers=CSRF, timeout=60) as released:
            assert released.post("/api/v1/login", json={"name": "ada", "password": made["accounts"]["ada"]["password"]}).status_code == 200
            alerts = released.get("/api/v1/alerts").json()
            assert (alerts["enabled"], alerts["has_webhook"], alerts["format"]) == (True, True, "ntfy"), alerts
            tried = released.post("/api/v1/alerts/test")
            assert tried.status_code == 200 or (tried.status_code == 502 and tried.json()["code"] == "not_delivered"), tried.text
    finally:
        subprocess.run([sys.executable, "-P", "-m", "qkvm", "stop", "--data-dir", str(data)], env=environment, cwd=tmp_path, capture_output=True, timeout=120)
        try:
            started.wait(60)
        except subprocess.TimeoutExpired:
            started.kill()
