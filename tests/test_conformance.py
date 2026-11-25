"""`python -m qkvm.conformance`: a client holds a running wall to the promise of /api/v1, reading only.

The Desktop App's joint test, a phone app and a script run it against a wall with a token. Here it is run against a wall
on a real localhost port with a stand-in of every kind of machine, over the network as a client is, with an operator's
token and a viewer's: every promised read answers as promised (shapes, kinds, codes, headers), it changes nothing and
presses nothing (nothing but GET leaves it, and the activity log says nothing of its token), the token is never shown,
and what it cannot check (a wall out of reach, a token the wall does not take, a certificate it does not trust) ends it
with its own exit code. A wall that answers otherwise is told, by name, with exit code 1.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from packaging.version import Version

from qkvm import about, conformance, kvm, live, server, update, vault
from qkvm.tlscert import ensure_certificate
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_proxmox import SECRET as PVE_SECRET
from tests.fake_proxmox import TOKEN_ID as PVE_TOKEN_ID
from tests.fake_proxmox import FakeProxmox, Guest, PveState
from tests.fake_redfish import BmcState, FakeBmc
from tests.fake_vnc import FakeVnc, VncState
from tests.test_live import Wall
from tests.test_wall import closed_port, wait_until

APP = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class Machines:
    """A stand-in of every kind of machine a wall shows, started; and one address where nothing answers."""

    def __init__(self, tmp_path: Path) -> None:
        self.kvm = FakeKvm(FakeState(
            atx=True, ports=[(32, 74, 135), None], wol=[{"mac": "02:00:00:00:00:01", "name": "The build machine"}],
            msd=True, msd_images={"rescue.iso": {"complete": True, "removable": True, "size": 1000, "mod_ts": 1.0, "sha256": ""}},
        ))  # fmt: skip
        self.jet = FakeJetKvm(JetState(extension="atx-power"))
        self.bmc = FakeBmc(BmcState())
        self.pc = FakeAmt(AmtState())
        self.vnc = FakeVnc(VncState(width=64, height=48, seed=4, name="a VNC desktop"))
        self.pve = FakeProxmox(PveState(guests={100: Guest(100, "web", screen=VncState(width=64, height=48, seed=5)), 101: Guest(101, "backup", status="stopped")}), tls_dir=tmp_path / "pve")
        self.all = (self.kvm, self.jet, self.bmc, self.pc, self.vnc, self.pve)

    def __enter__(self) -> Machines:
        for fake in self.all:
            fake.start()
        return self

    def __exit__(self, *_: object) -> None:
        for fake in self.all:
            fake.stop()

    def on(self, wall: Wall, admin: httpx.Client) -> list[str]:
        ids = [
            wall.add(admin, self.kvm.url, name="A KVM"),
            wall.add(admin, self.jet.url, name="A JetKVM"),
            wall.add(admin, self.bmc.url, name="A server"),
            wall.add(admin, self.pc.url, name="A PC"),
            wall.add(admin, self.vnc.url, name="A VNC desktop", kind="vnc"),
            wall.add(admin, self.pve.guest_url(100), name="A guest", kind="proxmox", username=PVE_TOKEN_ID, password=PVE_SECRET),
            wall.add(admin, self.pve.guest_url(101), name="A stopped guest", kind="proxmox", username=PVE_TOKEN_ID, password=PVE_SECRET),
        ]
        ids.append(wall.add(admin, f"http://127.0.0.1:{closed_port()}", name="Nothing there", kind="kvmd", force=True))

        def settled() -> bool:
            states = admin.get("/api/v1/status").json()
            return all(states[i]["state"] in ("online", "no_signal") for i in ids[:-1]) and states[ids[-1]]["state"] == "offline"

        wait_until(settled, "the machines never all came online", timeout=60)
        return ids


def token(admin: httpx.Client, folder: Path, role: str, **more: Any) -> tuple[str, Path]:
    made = admin.post("/api/v1/tokens", json={"name": f"conformance {role}", "role": role, **more})
    assert made.status_code == 201, made.text
    file = folder / f"{role}.token"
    file.write_text(made.json()["token"] + "\n", encoding="utf-8")
    return made.json()["token"], file


def checked(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = conformance.run(list(argv), out=out)
    return code, out.getvalue()


def lines(report: str, level: str) -> list[str]:
    return [line for line in report.splitlines() if line.startswith(level)]


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every request the checker sends, as (method, path): it sends them through httpx, here as anywhere."""
    seen: list[tuple[str, str]] = []
    send = httpx.Client.send

    def recorded(self: httpx.Client, request: httpx.Request, **options: Any) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return send(self, request, **options)

    monkeypatch.setattr(httpx.Client, "send", recorded)
    return seen


def test_a_wall_answers_every_promised_read_as_promised_and_is_left_as_it_was(tmp_path: Path, sent: list[tuple[str, str]]) -> None:
    with Machines(tmp_path) as machines, Wall(tmp_path / "wall") as wall:
        admin = wall.browser()
        ids = machines.on(wall, admin)
        operators, operator_file = token(admin, tmp_path, "operator")
        viewers, viewer_file = token(admin, tmp_path, "viewer", devices=ids[:2])
        settings = (tmp_path / "wall" / "qkvm.json").read_bytes()
        before = len(admin.get("/api/v1/audit", params={"limit": 500}).json()["entries"])
        sent.clear()

        code, report = checked(wall.url, "--token-file", str(operator_file), "--strict", "--every-machine")
        assert code == 0 and not lines(report, "FAIL"), report
        assert operators not in report
        # What it read: the wall, how each machine is, about, words.json; of every machine its history, its picture where
        # it has a screen, what it can wake where it can; the saved actions (an operator's); and what a token is refused.
        for read in ("GET /healthz", "GET /api/v1/session", "GET /static/words.json", "GET /api/v1/about", "GET /api/v1/wall", "GET /api/v1/status", "GET /api/v1/actions"):
            assert any(line.startswith("ok") and read in line for line in report.splitlines()), (read, report)
        for device_id in ids:
            assert f"GET /api/v1/devices/{device_id}/history" in report, (device_id, report)
        assert f"GET /api/v1/devices/{ids[0]}/snapshot" in report and f"GET /api/v1/devices/{ids[0]}/wol" in report
        assert f"GET /api/v1/devices/{ids[2]}/wol" not in report  # (a server has nothing to wake from: no `wol` in its `can`)
        for refused in ("401 unauthorized", "403 not_allowed", "404 not_found", "422 invalid"):
            assert refused in report, (refused, report)
        assert "GET /api/v1/tokens" in report and "GET /api/v1/alerts" in report  # (an admin's: refused to a token, as promised)
        assert {method for method, _ in sent} == {"GET"}, sorted(set(sent))

        # A viewer's token, for two of the machines: the saved actions and what can be woken are refused to it, as promised.
        code, report = checked(wall.url, "--token-file", str(viewer_file), "--strict")
        assert code == 0 and not lines(report, "FAIL"), report
        assert viewers not in report and "GET /api/v1/actions: 403 not_allowed" in report
        assert {method for method, _ in sent} == {"GET"}

        # Nothing was changed, nothing pressed: the settings are as they were, and the log has nothing of either token's.
        # (A token's `used` is kept in memory and written with the next change of the settings, of which there was none.)
        assert (tmp_path / "wall" / "qkvm.json").read_bytes() == settings
        entries = admin.get("/api/v1/audit", params={"limit": 500}).json()["entries"]
        assert len(entries) == before and not [entry for entry in entries if "(token)" in str(entry.get("user"))]

        # And as a client runs it, from the command line.
        run = subprocess.run(
            [sys.executable, "-P", "-m", "qkvm.conformance", wall.url, "--token-file", str(operator_file)],
            capture_output=True, text=True, timeout=300, env={**os.environ, "PYTHONPATH": str(APP)}, cwd=tmp_path,
        )  # fmt: skip
        assert run.returncode == 0, run.stdout + run.stderr
        assert operators not in run.stdout + run.stderr and "as promised" in run.stdout


def test_a_wall_that_answers_otherwise_is_told_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKvm().start()
    try:
        with Wall(tmp_path / "wall") as wall:
            admin = wall.browser()
            wall.add(admin, fake.url, name="A KVM")
            _, file = token(admin, tmp_path, "viewer")
            monkeypatch.setattr(live, "FORM", "2")  # the wall's `live`, said as a text where the promise says a number
            code, report = checked(wall.url, "--token-file", str(file))
            assert code == 1, report
            assert any("GET /api/v1/wall" in line and "live" in line for line in lines(report, "FAIL")), report
    finally:
        fake.stop()


def test_an_older_wall_is_not_held_to_what_was_promised_after_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with Wall(tmp_path / "wall") as wall:
        admin = wall.browser()
        _, file = token(admin, tmp_path, "operator")
        monkeypatch.setattr(server, "__version__", "0.3.0")
        monkeypatch.setattr(about, "__version__", "0.3.0")
        code, report = checked(wall.url, "--token-file", str(file))
        assert code == 0, report
        assert any("GET /api/v1/alerts" in line and "0.4.0" in line for line in lines(report, "skip")), report
        assert any("GET /api/v1/audit" in line and "0.3.2" in line for line in lines(report, "skip")), report
        monkeypatch.setattr(server, "__version__", "0.1.1")  # (older than the promise the list describes: not judged at all)
        monkeypatch.setattr(about, "__version__", "0.1.1")
        code, report = checked(wall.url, "--token-file", str(file))
        assert code == 2 and "0.1.1" in report and not lines(report, "FAIL"), report


def test_a_wall_of_0_3_2_is_held_to_the_refusal_words_of_0_3_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review of 0.4.0, bugs round 2.) The codes every request or every device may answer with were looked for
    # in a wall's words whatever its version: a released 0.3.2, whose words have no `no_video` (0.4.0), was told it fails the
    # promise. They are looked for from the version that brought them (`codes_since`). The words are 0.3.2's own, as it
    # shipped them (tests/fixtures/words-0.3.2.json, from the released wall), served by this wall at that version.
    released = (APP / "tests" / "fixtures" / "words-0.3.2.json").read_bytes()
    assert b'"no_video"' not in released
    real = server.load_assets

    def as_released() -> dict[str, tuple[bytes, str, str]]:
        assets = real()
        assets["words.json"] = (released, "application/json", '"words-0.3.2"')
        return assets

    monkeypatch.setattr(server, "load_assets", as_released)
    with Wall(tmp_path / "wall") as wall:
        admin = wall.browser()
        _, file = token(admin, tmp_path, "operator")
        monkeypatch.setattr(server, "__version__", "0.3.2")
        monkeypatch.setattr(about, "__version__", "0.3.2")
        code, report = checked(wall.url, "--token-file", str(file))
        assert code == 0 and not lines(report, "FAIL"), report
        monkeypatch.setattr(server, "__version__", "0.4.0")  # (a wall of 0.4.0 without them fails, as the promise has it)
        monkeypatch.setattr(about, "__version__", "0.4.0")
        code, report = checked(wall.url, "--token-file", str(file))
        assert code == 1 and any("no_video" in line for line in lines(report, "FAIL")), report


def test_an_absent_id_is_found_whatever_ids_the_wall_has() -> None:
    # (The outside review of 0.4.0, bugs round 2.) An id no machine has was looked for among the first sixteen: a wall that
    # had all of them stopped the checker with a traceback.
    for ids in ([], [f"{number:08x}" for number in range(16)], [f"{number:08x}" for number in range(300)][::-1]):
        found = conformance.Check.unknown_id(ids)
        assert len(found) == 8 and found not in ids


def test_what_cannot_be_checked_is_said_and_ends_with_its_own_code(tmp_path: Path) -> None:
    nowhere = f"http://127.0.0.1:{closed_port()}"
    file = tmp_path / "token"
    file.write_text("qkvm_not-a-token-of-any-wall\n", encoding="utf-8")
    code, report = checked(nowhere, "--token-file", str(file))
    assert code == 2 and "qkvm_not-a-token" not in report, report
    code, report = checked(nowhere, "--token-file", str(tmp_path / "no such file"))
    assert code == 2, report
    code, report = checked("127.0.0.1:8787", "--token-file", str(file))  # (an address without http:// or https://)
    assert code == 2 and "http" in report, report
    with Wall(tmp_path / "wall") as wall:
        wall.browser()
        code, report = checked(wall.url, "--token-file", str(file))
        assert code == 2 and "qkvm_not-a-token" not in report and "token" in report, report


def test_a_wall_over_https_is_checked_only_with_a_certificate_it_trusts(tmp_path: Path) -> None:
    cert, key, _ = ensure_certificate(tmp_path / "tls", ["127.0.0.1"])
    with Wall(tmp_path / "wall", serving={"ssl_certfile": str(cert), "ssl_keyfile": str(key)}) as wall:
        wall.url = wall.url.replace("http://", "https://")
        client = httpx.Client(base_url=wall.url, headers={"X-QKVM": "1"}, verify=str(cert), timeout=10)
        wall.clients.append(client)
        assert client.post("/api/v1/setup", json={"password": "correct horse battery"}).status_code == 200
        secret, file = token(client, tmp_path, "viewer")
        code, report = checked(wall.url, "--token-file", str(file))  # (its own certificate, which nothing else vouches for)
        assert code == 2 and "certificate" in report and secret not in report, report
        code, report = checked(wall.url, "--token-file", str(file), "--cafile", str(cert))
        assert code == 0, report


def test_a_field_a_client_has_not_met_is_a_note_to_it_and_a_failure_where_the_wall_is_its_own_version() -> None:
    account = {"id": "ab12cd34", "name": "olga", "role": "operator", "totp": False, "must_enroll": False, "sso": False, "recovery_codes": 0, "token": False}
    found = conformance.judged({**account, "zoom": 2}, "account", conformance.Reading(version=None, strict=False))
    assert [level for level, _ in found] == ["note"] and "zoom" in found[0][1]
    found = conformance.judged({**account, "zoom": 2}, "account", conformance.Reading(version=None, strict=True))
    assert [level for level, _ in found] == ["fail"]
    found = conformance.judged({**account, "totp": "no"}, "account", conformance.Reading(version=None, strict=False))
    assert [level for level, _ in found] == ["fail"] and "totp" in found[0][1] and "'no'" not in found[0][1]  # (its kind, never its value)
    missing = {key: value for key, value in account.items() if key != "role"}
    assert [level for level, _ in conformance.judged(missing, "account", conformance.Reading(version=None, strict=False))] == ["fail"]
    # An admin's field shown to a token is a failure whatever the version: the promise says who sees it.
    tile = {"id": "ab12cd34", "name": "x", "host": "h", "open_url": "", "kind": "kvmd", "picture": True, "group": "", "same_as": [], "can": [], "target": "0" * 32, "username": "admin"}
    found = conformance.judged(tile, "machine", conformance.Reading(version=None, strict=False))
    assert [level for level, _ in found] == ["fail"] and "username" in found[0][1]
    # (A wall of 0.3.2 says no `target`, added in 0.4.0: not missed there.)
    older = {key: value for key, value in tile.items() if key not in ("username", "target")}
    assert conformance.judged(older, "machine", conformance.Reading(version=Version("0.3.2"), strict=False)) == []
    # A field promised since a later version than the wall's is not missed there (a wall screen's `expires`: 0.2.1).
    screen = {"ok": True, "user": {**account, "token": True}}
    assert conformance.judged(screen, "display", conformance.Reading(version=Version("0.2.0"), strict=False)) == []
    assert [level for level, _ in conformance.judged(screen, "display", conformance.Reading(version=Version("0.2.1"), strict=False))] == ["fail", "fail"]
    assert conformance.judged(1.5, "int|null", conformance.Reading(version=None, strict=False))[0][0] == "fail"
    assert conformance.judged(True, "int", conformance.Reading(version=None, strict=False))[0][0] == "fail"  # (a boolean is no number)
