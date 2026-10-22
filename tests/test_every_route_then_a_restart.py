"""Nothing the program itself saves is refused by the check a start makes.

Every route that changes what is saved is driven, with ordinary values and with the odd ones a form or a
script may send (a whole number where a time is declared, a number written as a text, a port with ".0"),
for every kind of machine the wall takes (a KVM of each family, a server's controller, a VNC server over
vnc:// and vncs://, a PC with Intel AMT, a guest of Proxmox), and every field a tile keeps (how hard a
Fingerbot presses, the number its machine gave for itself). After every single change the settings file as
it then lies on disk is read by `Store` by itself, with no second copy beside it, and so is the second copy
(qkvm.bak) by itself, as a start reads it where the file is damaged: a refusal there is a wall that does not
start after a restart. (The VNC server's address, vnc://, was refused so on 6d0bed7: a wall with one did not
start again, nor did `--disable-2fa` or `--reset-password` run on its folder.)
"""

from __future__ import annotations

import json
import shutil
import socket
import time
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import discover, exchange, jetkvm, kvm, server, totp, update, vault
from qkvm.cli import main as run_cli
from qkvm.core import Core
from qkvm.store import Store, StoreError
from tests.fake_amt import FakeAmt
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_proxmox import SECRET, TOKEN_ID, FakeProxmox, Guest, PveState
from tests.fake_redfish import FakeBmc
from tests.fake_vnc import FakeVnc, VncState
from tests.test_totp import code_for, switch_on
from tests.test_users import account, browser, visitor
from tests.test_wall import PASSWORD, add, closed_port, wait_until, wall

F = {"format": exchange.FORMAT, "version": 1}
PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 5)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 5)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 5)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture(autouse=True)
def distinct_closed_ports(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Keep these addresses unavailable to other sockets until the test ends.
    # Closing immediately lets the OS hand the same port to a later spare device.
    with ExitStack() as sockets:
        def reserved() -> int:
            sock = sockets.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])  # bound, not listening: still unreachable

        monkeypatch.setitem(globals(), "closed_port", reserved)
        yield


class Reads:
    """Reads the settings file as a start would, by itself, after every change, and its second copy by itself as a start
    reads it where the file is damaged; keeps what was refused."""

    def __init__(self, folder: Path, scratch: Path) -> None:
        self.folder, self.scratch, self.refused, self.asked = folder, scratch, [], 0

    def __call__(self, after: str) -> None:
        self.asked += 1
        for copy in ("qkvm.json", "qkvm.bak"):
            alone = self.scratch / f"read{self.asked}{copy[-4:]}"
            alone.mkdir()
            shutil.copy2(self.folder / copy, alone / copy)
            try:
                store = Store(alone / "qkvm.json")
                assert store.restored is (copy == "qkvm.bak")
            except StoreError as ex:
                said = str(ex)
                self.refused.append(f"after {after} ({copy}): {said[said.index('cannot be read'):][:160]}")
            shutil.rmtree(alone, ignore_errors=True)


def ok(reply: Any, *codes: int) -> Any:
    assert reply.status_code in (codes or (200, 201)), f"{reply.request.method} {reply.request.url.path}: {reply.status_code} {reply.text[:300]}"
    return reply


def test_every_changing_route_leaves_a_file_that_a_start_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder, scratch = tmp_path / "data", tmp_path / "scratch"
    scratch.mkdir()
    reads = Reads(folder, scratch)
    plain_kvm = FakeKvm(FakeState(hostname="rack-3 kvm")).start()
    tls_kvm = FakeKvm(FakeState(hostname="glkvm"), tls_dir=tmp_path / "tls1").start()
    second_tls = FakeKvm(FakeState(hostname=12345), tls_dir=tmp_path / "tls2").start()  # type: ignore[arg-type]
    bmc = FakeBmc(tls_dir=tmp_path / "bmc").start()
    jet_state = JetState()
    jet_plain = FakeJetKvm(jet_state).start()
    jet_secure: FakeJetKvm | None = None
    vnc_plain = FakeVnc(VncState(width=160, height=100)).start()
    vnc_bare = FakeVnc(VncState(width=64, height=48, seed=2)).start()
    vnc_tls = FakeVnc(VncState(width=64, height=48, seed=3), tls_dir=tmp_path / "vnc").start()
    amt_pc = FakeAmt().start()
    pve = FakeProxmox(PveState(guests={
        100: Guest(100, "web", screen=VncState(width=320, height=200, name="QEMU (web)")),
        101: Guest(101, "db", status="stopped", screen=VncState(width=64, height=48, name="QEMU (db)", seed=4)),
    }), tls_dir=tmp_path / "pve").start()  # fmt: skip
    proxmox_token = {"username": TOKEN_ID, "password": SECRET, "kind": "proxmox"}
    monkeypatch.setattr(jetkvm, "WAY_EVERY", 0.2)
    try:
        with wall(folder) as admin:
            store = admin.core.store  # type: ignore[attr-defined]
            wait_until(lambda: store.unlock is not None, "the key of its own was never fitted")
            reads("setup")

            # --- devices: add, edit, bulk, trust, order, remove ---------------------------------------
            one = add(admin, plain_kvm.url)  # (no name: the device's own)
            reads("a device added over plain HTTP, named by itself")
            two = add(admin, tls_kvm.url, name="  Over TLS  ", group="  Rack   1 ", username="  ", open_url="https://console.invalid/x", alerts=False)
            reads("a device added over HTTPS (certificate remembered)")
            three = add(admin, second_tls.url, tls="insecure", keep_both=True)
            reads("a device whose host name is a number, certificate not checked")
            gone = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd")
            reads("a device that does not answer, saved anyway")
            server_id = add(admin, bmc.url, username="admin", password=bmc.state.password, kind="auto")
            reads("a server's controller (says what it is: ident)")
            jet = add(admin, jet_plain.url, password=jet_state.password)
            reads("a JetKVM on plain HTTP")

            # --- the kinds 0.2.0 adds, and the fields of a tile it keeps ------------------------------------------------
            vnc_one = add(admin, vnc_plain.url, name="A VNC server")  # (kept as vnc://host:port)
            assert store.device(vnc_one).url.startswith("vnc://")
            reads("a VNC server added by its address (vnc://)")
            add(admin, f"127.0.0.1:{vnc_bare.port}", kind="vnc")  # (named by its address; as the network search's result is added)
            reads("a VNC server added by the kind chosen")
            vnc_secure = add(admin, vnc_tls.url, name="Over vncs")  # (TLS from the first byte: its certificate remembered)
            assert store.device(vnc_secure).url.startswith("vncs://") and store.device(vnc_secure).cert_pem
            reads("a VNC server over vncs:// (certificate remembered)")
            add(admin, f"vnc://[::1]:{closed_port()}", force=True)
            reads("a VNC server at an IPv6 address that does not answer, saved anyway")
            for body in (
                {"url": vnc_plain.url, "name": "Renamed VNC", "group": "Rack 2", "alerts": False, "fingerbot_strength": "light"},
                {"url": f"VNC://127.0.0.1:{vnc_plain.port}/", "kind": "auto", "password": "secret", "open_url": "https://console.invalid/vnc"},
            ):
                ok(admin.put(f"/api/v1/devices/{vnc_one}", json=body))
                reads(f"an edit of a VNC server ({sorted(body)})")
            ok(admin.put(f"/api/v1/devices/{vnc_secure}", json={"url": vnc_tls.url, "name": "Over vncs", "tls": "insecure"}))
            reads("a VNC server over vncs:// not to have its certificate checked")
            pc = add(admin, amt_pc.url, name="Desk 7")
            assert store.device(pc).kind == "amt" and store.device(pc).machine.startswith("amt:"), store.device(pc)
            reads("a PC with Intel AMT (the number its machine gives for itself kept)")
            ok(admin.put(f"/api/v1/devices/{pc}", json={"url": amt_pc.url, "name": "Desk 7", "password": "secret", "fingerbot_strength": "light"}))
            reads("a PC with Intel AMT, its password typed again (its machine taken as it answers)")
            guest = add(admin, pve.guest_url(100), **proxmox_token)
            reads("a guest of Proxmox")
            stopped_guest = add(admin, f"127.0.0.1:{pve.port}/101", **proxmox_token)  # (its node looked up with the token)
            reads("a guest of Proxmox named by its number alone")
            ok(admin.put(f"/api/v1/devices/{guest}", json={"url": pve.guest_url(100), "name": "web server", "kind": "auto", "username": TOKEN_ID}))
            reads("an edit of a guest of Proxmox")
            for strength in ("light", None, "firm"):
                ok(admin.put(f"/api/v1/devices/{one}", json={"url": plain_kvm.url, "name": "", "fingerbot_strength": strength}))
                reads(f"how hard a Fingerbot presses: {strength}")
            light = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", fingerbot_strength="light")
            reads("a KVM added with its Fingerbot set to press lightly")
            spare_vnc = add(admin, f"vncs://127.0.0.1:{closed_port()}", force=True, name="Spare VNC")
            ok(admin.post("/api/v1/devices/remove", json={"ids": [spare_vnc, stopped_guest, light]}))
            reads("a VNC server, a guest of Proxmox and a KVM removed at once")
            for body in (
                {"url": tls_kvm.url, "name": "Renamed", "group": "", "tls": "pinned", "alerts": True, "username": "root"},
                {"url": tls_kvm.url, "name": "", "group": "g" * 40, "alerts": None, "tls": None, "open_url": ""},
                {"url": tls_kvm.url, "name": "x" * 80, "kind": "kvmd", "tls": "system", "force": True},
                {"url": tls_kvm.url, "name": "again pinned", "tls": "pinned", "password": "secret"},
            ):
                ok(admin.put(f"/api/v1/devices/{two}", json=body), 200, 422)
                reads(f"an edit of a device ({sorted(body)})")
            shown = ok(admin.get(f"/api/v1/devices/{two}/certificate")).json()
            ok(admin.post(f"/api/v1/devices/{two}/trust", json={"fingerprint": shown["presented"]}))
            reads("a certificate trusted")
            ok(admin.put("/api/v1/wall/order", json={"ids": [three, "nobody", one, one]}))
            reads("the tiles put in an order")
            ok(admin.delete(f"/api/v1/devices/{gone}"))
            reads("a device removed")
            several = [add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name=f"Spare {n}") for n in (1, 2, 3)]
            ok(admin.post("/api/v1/devices/remove", json={"ids": [several[2], several[0], several[2]]}))
            reads("several devices removed at once")
            ok(admin.post("/api/v1/devices/remove", json={"ids": [several[1], "nobody"]}), 404)
            reads("several devices not removed: one of them is not on the wall")
            ok(admin.post("/api/v1/devices/remove", json={"ids": [several[1]]}))
            reads("the last of them removed the same way")
            for target in (one, two, server_id):
                admin.get(f"/api/v1/devices/{target}/snapshot")
            admin.get("/api/v1/status")
            reads("pictures fetched (a certificate may be remembered by that)")

            # --- a JetKVM that offers HTTPS by now is followed there -------------------------------------
            jet_secure = FakeJetKvm(jet_state, tls_dir=tmp_path / "jet").start()
            both = {jet_plain.url: jet_secure.url, jet_secure.url: jet_plain.url}
            for module in (kvm, server, discover, jetkvm):
                monkeypatch.setattr(module, "other_way", both.get)
            url_of = lambda: next(d for d in admin.get("/api/v1/wall").json()["devices"] if d["id"] == jet)["url"]  # noqa: E731
            wait_until(lambda: (admin.get("/api/v1/status"), url_of())[1] == jet_secure.url, "the JetKVM was not followed to HTTPS", timeout=20)  # type: ignore[union-attr]
            reads("a JetKVM followed to HTTPS")

            # --- accounts ------------------------------------------------------------------------------------
            olga = account(admin, "olga", "operator", devices=[one, "nobody"], groups=["  Rack 1 ", "rack 1", "", "x" * 90])
            reads("an account limited to devices and groups")
            victor = account(admin, "victor@example.org", "viewer", devices=None, groups=["a"], suspended=None)
            reads("an account with every device")
            second_admin = account(admin, "second", "admin", devices=[one], groups=["a"])
            reads("a second admin")
            for body in (
                {"name": "olga", "role": "viewer", "devices": [], "groups": [], "suspended": True},
                {"name": "olga", "role": "operator", "devices": None, "suspended": False, "password": "another password of hers"},
                {"name": "Olga2", "role": "operator", "devices": [two, three], "groups": ["Rack 1"], "suspended": None, "totp_off": True},
                {"name": "olga", "role": "admin", "devices": [two]},
                {"name": "olga", "role": "operator", "devices": [two], "groups": ["g"]},
            ):
                ok(admin.put(f"/api/v1/users/{olga}", json=body))
                reads(f"an edit of an account ({body})")
            ok(admin.post(f"/api/v1/users/{victor}/logout"))
            ok(admin.delete(f"/api/v1/users/{second_admin}"))
            reads("an account removed")

            # --- the second step: on, a code used, one-time codes, off, by an admin, required ---------------
            hers = browser(admin, "olga", "another password of hers", port=50021)
            key = switch_on(hers, "another password of hers")
            reads("two-factor sign-in switched on")
            ok(hers.post("/api/v1/totp/codes", json={"password": "another password of hers"}))
            reads("new one-time codes")
            guest = visitor(admin, 50022)
            ok(guest.post("/api/v1/login", json={"name": "olga", "password": "another password of hers"}), 401)
            ok(guest.post("/api/v1/login", json={"name": "olga", "password": "another password of hers", "code": code_for(key, 1)}))
            reads("a sign-in with a code of the app (its time step is kept)")
            codes = ok(hers.post("/api/v1/totp/codes", json={"password": "another password of hers"})).json()["recovery_codes"]
            another = visitor(admin, 50023)
            ok(another.post("/api/v1/login", json={"name": "olga", "password": "another password of hers", "code": codes[0], "remember": True}))
            reads("a sign-in with a one-time code")
            ok(hers.post("/api/v1/totp/disable", json={"password": "another password of hers"}))
            reads("two-factor sign-in switched off by its owner")
            switch_on(hers, "another password of hers")
            ok(admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "devices": [two], "totp_off": True}))
            reads("two-factor sign-in switched off by an admin")
            mine = switch_on(admin, PASSWORD)
            for level in ("viewer", "operator", "admin", ""):
                ok(admin.put("/api/v1/security", json={"require_totp": level}))
                reads(f"two-factor sign-in required of {level or 'nobody'}")
            ok(admin.post("/api/v1/password", json={"current": PASSWORD, "new": "a brand new password"}))
            ok(admin.post("/api/v1/password", json={"current": "a brand new password", "new": PASSWORD}))
            reads("the admin's password changed twice")

            # --- recovery ------------------------------------------------------------------------------------
            recovery = ok(admin.post("/api/v1/recovery", json={"password": PASSWORD})).json()["recovery_key"]
            reads("a new recovery key")
            ok(visitor(admin, 50024).post("/api/v1/recover", json={"name": "victor@example.org", "recovery_key": recovery, "new_password": "victor's new password"}))
            reads("a password set with the recovery key")

            # --- tokens and display links --------------------------------------------------------------------
            made = []
            for body in (
                {"name": "a script"},
                {"name": "  a   script  for a day ", "role": "operator", "days": 1, "devices": [one, "nobody"], "groups": ["Rack 1", ""]},
                {"name": "ten years", "days": 3650, "devices": []},
                {"name": "a screen", "kind": "display", "role": "operator", "days": None},
                {"name": " ", "kind": "api", "days": 7.0},  # (a number with ".0" is a whole number to the form's reader)
                {"name": "days as a text", "days": "30"},
            ):
                reply = ok(admin.post("/api/v1/tokens", json=body), 201, 422)
                reads(f"a token made ({body})")
                if reply.status_code == 201:
                    made.append(reply.json())
            script, screen = made[0], made[3]
            ok(visitor(admin, 50025).get("/api/v1/wall", headers={"Authorization": f"Bearer {script['token']}"}))
            ok(visitor(admin, 50026).post("/api/v1/display", json={"key": screen["token"]}))
            ok(admin.put("/api/v1/update", json={"auto_check": False}))  # (a save, which writes down when the tokens were used)
            reads("a token and a display link used")
            ok(admin.delete(f"/api/v1/tokens/{made[1]['record']['id']}"))
            reads("a token taken back")

            # --- saved actions ---------------------------------------------------------------------------------
            lock = ok(admin.post("/api/v1/actions", json={"name": "  Lock ", "kind": "keys", "keys": "MetaLeft,KeyL", "enter": True, "danger": True})).json()["action"]["id"]
            typed = ok(admin.post("/api/v1/actions", json={"name": "Type it", "kind": "text", "text": "hunter2", "enter": True})).json()["action"]["id"]
            reads("two saved actions")
            ok(admin.put(f"/api/v1/actions/{lock}", json={"name": "Lock", "kind": "text", "text": "now a text"}))
            ok(admin.put(f"/api/v1/actions/{typed}", json={"name": "Type it", "kind": "keys", "keys": "Enter"}))
            ok(admin.put(f"/api/v1/actions/{typed}", json={"name": "Type it", "kind": "text", "text": ""}), 422)
            reads("saved actions edited")
            ok(admin.delete(f"/api/v1/actions/{typed}"))
            reads("a saved action removed")

            # --- alerts ------------------------------------------------------------------------------------------
            for body in (
                {"enabled": True, "webhook": "https://hooks.invalid/a-topic", "format": "ntfy", "link": "https://wall.invalid/"},
                {"enabled": True, "offline": False, "no_signal": False, "problem": False, "recovered": False, "link": ""},
                {"enabled": False, "forget_webhook": True, "link": None},
                {"enabled": True, "webhook": "http://127.0.0.1:9/hook", "format": "json"},
            ):
                ok(admin.put("/api/v1/alerts", json=body), 200, 422)
                reads(f"the alert settings ({body})")
            for minutes in (1, 7 * 24 * 60, 0, 5.0, "15", 0):
                ok(admin.post("/api/v1/alerts/pause", json={"minutes": minutes}))
                reads(f"alerts paused for {minutes!r} minutes")

            # --- metrics, updates, where it listens ---------------------------------------------------------------
            ok(admin.post("/api/v1/metrics/token"))
            reads("the metrics token made")
            ok(admin.delete("/api/v1/metrics/token"))
            reads("metrics switched off")
            ok(admin.post("/api/v1/metrics/token"))
            for flag in (True, False, "true", 0):
                ok(admin.put("/api/v1/update", json={"auto_check": flag}))
                reads(f"looking for updates: {flag!r}")
            monkeypatch.setattr(Core, "request_restart", lambda self: None)  # (the listeners of a test are not reopened)
            port = store.server.port
            for body in (
                {"bind": ["local"], "port": port, "https": False, "interval": 1},  # a whole number of seconds
                {"bind": [" LOCAL ", "127.0.0.1", "localhost"], "port": float(port), "https": False, "interval": "2.5"},
                {"bind": [], "port": str(port), "https": "false", "interval": 60},
                {"bind": ["local", "::1"], "port": port, "https": False, "interval": 0.2},
                {"bind": ["local"], "port": port, "https": True, "interval": 1.0},
                {"bind": ["local"], "port": port, "https": False, "interval": 1e0},
            ):
                ok(admin.put("/api/v1/settings", json=body), 200, 422)
                reads(f"the settings ({body})")

            # --- a file taken in ----------------------------------------------------------------------------------
            file = {
                **F,
                "devices": [
                    {"url": f"https://127.0.0.1:{closed_port()}", "name": "", "kind": "kvmd", "group": "", "tls": "pinned", "alerts": False, "password": "from the file", "ident": "sn:" + "ab" * 16},
                    {"url": "http://kvm-" + "a" * 200 + ".invalid", "kind": "jetkvm", "username": ""},  # (named by its address, which is long)
                    {"url": f"https://127.0.0.1:{closed_port()}", "kind": "redfish", "name": "A server\n", "keep_both": True, "open_url": "https://console.invalid/"},
                    {"url": "VNC://vnc-of-a-file.invalid", "kind": "vnc", "name": "VNC of a file", "password": "from the file"},  # (5900: no port kept)
                    {"url": f"vncs://[::1]:{closed_port()}", "kind": "vnc", "tls": "insecure"},
                    {"url": f"https://127.0.0.1:{closed_port()}/nodes/pve1/qemu/100", "kind": "proxmox", "username": TOKEN_ID, "password": SECRET},
                    {"url": f"http://127.0.0.1:{closed_port()}", "kind": "amt", "machine": "amt:" + "0123456789abcdef" * 2, "fingerbot_strength": "light"},
                ],
                "actions": [{"name": "From a file", "kind": "text", "text": "typed", "enter": True, "danger": True}, {"name": "Keys of a file", "kind": "keys", "keys": "F1"}],
                "alerts": {"enabled": False, "format": "slack", "offline": False, "webhook": "https://hooks.invalid/x"},
                "wall": {"interval": 3, "update_check": False},  # (3, not 3.0)
            }
            said = ok(admin.post("/api/v1/import/read", json={"file": json.dumps(file)})).json()
            assert len(said["devices"]) == len(file["devices"]), said  # (every one of them taken: none left out as no address)
            ok(admin.post("/api/v1/import", json={"file": json.dumps(file), "take": list(exchange.PARTS)}))
            reads("a plain file taken in, all four parts")
            whole = ok(admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": list(exchange.PARTS)})).text
            said = ok(admin.post("/api/v1/import/read", json={"file": whole, "passphrase": PASSPHRASE})).json()
            # (What the wall writes into its own file it reads back, every tile of every kind: none left out.)
            assert len(said["devices"]) == len(store.devices) and not said["left_out"], said["left_out"]
            ok(admin.post("/api/v1/import", json={"file": whole, "passphrase": PASSPHRASE, "take": list(exchange.PARTS)}))
            reads("the wall's own sealed file taken in again")
            mine = mine  # (kept: the admin's second step stays on over the restart below)

        # --- from the command line, and starts of other kinds -------------------------------------------------------
        reads("the wall stopped")
        # How large the activity log and the history grow is said in the file, by hand (no form sets it): every start
        # and save after this one reads it and keeps it.
        settings = json.loads((folder / "qkvm.json").read_text(encoding="utf-8"))
        settings["server"].update(activity_mb=12, history_days=30, history_mb=50)
        (folder / "qkvm.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")
        reads("the sizes of the activity log and the history set by hand")
        assert run_cli(["--data-dir", str(folder), "--disable-2fa", "admin"]) == 0, f"qkvm --disable-2fa did not run; refused so far: {reads.refused}"
        reads("qkvm --disable-2fa")
        with wall(folder, sign_in=False, locked_start=True) as admin:  # (takes what the key in the folder fitted out of the file)
            assert admin.core.store.restored is False  # type: ignore[attr-defined]
            ok(admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}))
            ok(admin.post("/api/v1/alerts/pause", json={"minutes": 30}))
            reads("a start with --locked-start, and a pause")
        with wall(folder, sign_in=False) as admin:  # ...and back: the key is fitted again at the next sign-in
            assert admin.core.store.restored is False  # type: ignore[attr-defined]
            ok(admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}))
            wait_until(lambda: admin.core.store.unlock is not None, "the key of its own was never fitted again")  # type: ignore[attr-defined]
            reads("a start that keeps a key again")
        assert run_cli(["--data-dir", str(folder), "--reset-password"]) == 0, f"qkvm --reset-password did not run; refused so far: {reads.refused}"
        reads("qkvm --reset-password")
        with wall(folder) as admin:  # (sets the wall up again)
            assert admin.core.store.restored is False  # type: ignore[attr-defined]
            reads("set up again after the reset")
    finally:
        for stand_in in (plain_kvm, tls_kvm, second_tls, bmc, jet_plain, jet_secure, vnc_plain, vnc_bare, vnc_tls, amt_pc, pve):
            if stand_in is not None:
                stand_in.stop()
    print(f">>> the file and its copy were read {reads.asked} times, after as many changes; refused: {reads.refused or 'never'}")
    assert not reads.refused, "\n".join(reads.refused)
    assert not list(folder.glob("qkvm.damaged-*")), "a start of this run set the settings file aside"
    # ...and what was set is what is there, after every start and the reset: each kind, vnc:// and vncs:// both, the
    # Fingerbot's strength, the machine's number, and the sizes set by hand.
    final = json.loads((folder / "qkvm.json").read_text(encoding="utf-8"))
    devices = final["devices"]
    assert {"kvmd", "jetkvm", "redfish", "vnc", "amt", "proxmox"} <= {device["kind"] for device in devices}, devices
    assert {"vnc", "vncs"} <= {device["url"].split("://")[0] for device in devices}, devices
    assert any(device["fingerbot_strength"] == "light" for device in devices) and any(device["machine"] for device in devices)
    assert (final["server"]["activity_mb"], final["server"]["history_days"], final["server"]["history_mb"]) == (12, 30, 50)


@pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")  # (as in test_live.py)
def test_a_take_over_and_the_live_views_leave_files_that_a_start_reads(tmp_path: Path) -> None:
    # What a live view and a take-over of keyboard and mouse write (the activity log, with the machine's id, who took them
    # from whom; nothing in the settings) is read back by the next start, and found there by the machine.
    from tests.test_live import Wall, a_jpeg

    folder, scratch = tmp_path / "data", tmp_path / "scratch"
    scratch.mkdir()
    reads = Reads(folder, scratch)
    comet = FakeKvm(FakeState(picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    try:
        with Wall(folder) as first:
            admin = first.browser()
            device = first.add(admin, comet.url, fingerbot_strength="light")
            ok(admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}), 201)
            reads("a KVM and an account")
            hers = first.line(first.browser("olga", "olga may act here"), device)
            hers.say(t="control", on=True)
            assert hers.word("control")["on"] is True
            mine = first.line(admin, device)
            mine.say(t="control", on=True, take=True, **{"from": "olga"})
            assert mine.word("control") == {"t": "control", "on": True}
            assert hers.word("control")["code"] == "taken"
            hers.close()
            mine.close()
            wait_until(lambda: len(first.audit(admin, "live_closed")) == 2, "the live views' ends were not written down")
            reads("a take-over, and two live views ended")
        with Wall(folder) as again:
            admin = again.browser("admin")
            reads("a start after a take-over")
            for asked in ({"q": "live_control"}, {"device": device, "kind": "action"}):
                found: list[Any] = []

                def answered(asked: dict[str, Any] = asked, found: list[Any] = found) -> bool:
                    reply = admin.get("/api/v1/audit", params=asked)
                    found[:] = reply.json()["entries"] if reply.status_code == 200 else [reply.status_code, reply.text[:200]]
                    said = {(e["user"], e["on"], e.get("by"), e.get("from"), e["device_id"]) for e in found if isinstance(e, dict) and e["event"] == "live_control"}
                    # (her keyboard taken, taken from her by the admin, and taken by him from her: each of this machine)
                    return {("olga", True, None, None, device), ("olga", False, "admin", None, device), ("admin", True, None, "olga", device)} <= said

                wait_until(answered, f"the take-over is not found again after a restart ({asked}): {found}", timeout=20)
    finally:
        comet.stop()
    assert not reads.refused, "\n".join(reads.refused)


def test_a_field_that_holds_what_the_program_gives_it_is_what_it_is_declared_as(tmp_path: Path) -> None:
    # The same, asked of the records in memory at the end of a small run: every field by its declared kind,
    # so that a field no route above reaches by an odd value is at least seen as the program fills it.
    from dataclasses import fields

    from qkvm import store as st

    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd")
        account(admin, "olga", "operator", devices=[], groups=["a"])
        ok(admin.post("/api/v1/tokens", json={"name": "t", "days": 2}), 201)
        ok(admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}), 201)
        store = admin.core.store  # type: ignore[attr-defined]
        wrong = []
        for record in (store.server, store.alerts, *store.users, *store.devices, *store.actions, *store.tokens):
            for each in fields(record):
                if each.name in st._OPENED_LATER:
                    continue
                kinds = [kind.strip() for kind in str(each.type).split("|")]
                value = getattr(record, each.name)
                if value is None and "None" in kinds:
                    continue
                if not any(st._HOLDS[kind](value) for kind in kinds if kind != "None"):
                    wrong.append(f"{type(record).__name__}.{each.name} = {value!r}")
        assert not wrong, wrong
    assert time.time() > 0 and totp.STEP == 30 and TestClient is not None
