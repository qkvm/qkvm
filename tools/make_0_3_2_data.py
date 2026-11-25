"""Make tests/fixtures/data-0.3.2.tar: a data folder as the released qKVM 0.3.2 leaves it, for the test that opens it with
the version of today (tests/test_a_data_folder_of_0_3_2.py).

    git -C <a clone of github.com/qkvm/qkvm> archive v0.3.2 | tar -x -C SOURCE       (0.3.2 as published: commit dd19556)
    python tools/make_0_3_2_data.py --source SOURCE

Run from app/ with the Python the tests run with: 0.3.2 runs from SOURCE, in a throwaway venv that sees that Python's
libraries (nothing is installed, nothing is fetched), as `python -m qkvm`, started and stopped as a person would; its
own stand-ins (SOURCE/tests) stand in for the devices, each on a port that was free (the test moves them to where
today's stand-ins are: no port is taken for granted), and the alert address is on 127.83.2.9, which nothing else uses
(the test never listens there: what this version sends is taken where it leaves). Through 0.3.2's own API, as the page does it: an admin (ada)
and an operator (otto) with two-factor sign-in, an API token, five devices of four kinds with their passwords (a
PiKVM-style KVM over HTTP and a Comet-style one over HTTPS, a server's controller over Redfish, a VNC server, a PC with
Intel AMT), two saved actions, the one alert address of 0.3.2 (sent a test alert), a wrong password, a minute of the
devices watched (the history), and an export encrypted with a passphrase; then 0.3.2 is stopped.

The archive holds data/ (qkvm.log left out: it names the folders of the computer that made it), data.keys/ (the server
storage key, outside the data folder, as 0.3.2 keeps it by default), the certificates the two HTTPS stand-ins showed
(devices/<name>/), the export, and made.json: every name, address and secret above, made up for this and for nothing
else. Kept as an archive because a data folder holds files no commit takes as they are (a key, a log, settings).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import site
import socket
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent.parent  # app/
VERSION = "0.3.2"
# What the devices, the accounts and the export are given: made up for this fixture, and for nothing else.
ADA, OTTO = "ada-0.3.2-fixture-password", "otto-0.3.2-fixture-password"
EXPORT = "export-0.3.2-fixture-passphrase"
ALERTS = "127.83.2.9"  # the alert address's host: loopback, and nothing else's (its port, any that was free, is in made.json)
DEVICES: list[dict[str, Any]] = [
    {"name": "Rack KVM", "kind": "kvmd", "username": "admin", "password": "rack-kvm-fixture", "group": "lab"},
    {"name": "Comet", "kind": "kvmd", "username": "admin", "password": "comet-fixture", "group": "lab", "tls": "comet"},
    {"name": "Server", "kind": "redfish", "username": "admin", "password": "server-fixture", "group": "", "tls": "server",
     "uuid": "5e7e0a32-0000-4000-8000-00000000c0de", "root_uuid": "5e7e0a32-0000-4000-8000-0000000005e7"},
    {"name": "Desk", "kind": "vnc", "username": "admin", "password": "vncpass1", "group": ""},
    {"name": "Office PC", "kind": "amt", "username": "admin", "password": "Office-PC-fixture-1", "group": "office"},
]  # fmt: skip
ACTIONS = [{"name": "Type the user name", "kind": "text", "text": "operator", "enter": True}, {"name": "Task manager", "kind": "keys", "keys": "ControlLeft,ShiftLeft,Escape"}]
WATCHED = 60  # seconds the devices are watched by 0.3.2, for its history


def stand_ins(tls: Path) -> tuple[list[Any], Any]:
    """0.3.2's own stand-ins for the devices, each on a port that was free (port 0), and an inbox for the alerts on one of
    127.83.2.9's. Each device's address goes into DEVICES (its "url"), the inbox's into its own "url"."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from tests import fake_amt, fake_kvm, fake_redfish, fake_vnc

    started: list[Any] = []
    for device in DEVICES:
        if device["kind"] == "kvmd":
            started.append(fake_kvm.FakeKvm(fake_kvm.FakeState(password=device["password"]), tls_dir=tls / device["tls"] if "tls" in device else None).start())
        elif device["kind"] == "redfish":
            state = fake_redfish.BmcState(username=device["username"], password=device["password"], uuid=device["uuid"], root_uuid=device["root_uuid"])
            started.append(fake_redfish.FakeBmc(state, tls_dir=tls / device["tls"]).start())
        elif device["kind"] == "vnc":
            started.append(fake_vnc.FakeVnc(fake_vnc.VncState(password=device["password"])).start())
        else:
            started.append(fake_amt.FakeAmt(fake_amt.AmtState(username=device["username"], password=device["password"])).start())
        device["url"] = started[-1].url
    received: list[dict[str, Any]] = []

    class Inbox(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append({"path": self.path, "body": self.rfile.read(int(self.headers.get("content-length", "0")))})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    inbox = HTTPServer((ALERTS, 0), Inbox)
    inbox.received = received  # type: ignore[attr-defined]
    inbox.url = f"http://{ALERTS}:{inbox.server_address[1]}/qkvm-alerts"  # type: ignore[attr-defined]
    Thread(target=inbox.serve_forever, daemon=True).start()
    return started, inbox


def asked(reply: Any, *statuses: int) -> Any:
    if reply.status_code not in statuses:
        raise SystemExit(f"0.3.2 answered {reply.request.method} {reply.request.url.path} with {reply.status_code}: {reply.text[:500]}")
    return reply.json() if reply.content and reply.headers.get("content-type", "").startswith("application/json") else reply


def made(source: Path, root: Path) -> dict[str, Any]:
    """The data folder, made by 0.3.2 running from `source`, in `root`; what was given and shown, for made.json."""
    import httpx

    from qkvm import totp  # (0.3.2's: SOURCE is first on the path)

    data, tls = root / "data", root / "devices"
    devices, inbox = stand_ins(tls)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    environment = {name: value for name, value in os.environ.items() if not name.startswith("QKVM_")}
    environment.update(PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "-m", "qkvm", "--data-dir", str(data), "--port", str(port), "--bind", "local"]
    wall = subprocess.Popen(command, env=environment, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shown: dict[str, Any] = {}
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 120
        while True:
            try:
                if httpx.get(base + "/healthz", timeout=5).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if wall.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("0.3.2 did not start")
            time.sleep(0.5)
        with httpx.Client(base_url=base, headers={"X-QKVM": "1"}, timeout=120) as ada, httpx.Client(base_url=base, headers={"X-QKVM": "1"}, timeout=120) as otto:
            shown["recovery_key"] = asked(ada.post("/api/v1/setup", json={"name": "ada", "password": ADA}), 200)["recovery_key"]
            asked(ada.post("/api/v1/users", json={"name": "otto", "role": "operator", "password": OTTO}), 200, 201)
            shown["token"] = asked(ada.post("/api/v1/tokens", json={"name": "monitoring", "role": "viewer"}), 201)["token"]
            ids = {}
            for device in DEVICES:
                body = {"url": device["url"], "username": device["username"], "password": device["password"], "name": device["name"], "group": device["group"]}
                ids[device["name"]] = asked(ada.post("/api/v1/devices", json=body), 201)["device"]["id"]
            for action in ACTIONS:
                asked(ada.post("/api/v1/actions", json=action), 201)
            asked(ada.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url, "format": "ntfy", "offline": True, "no_signal": True, "problem": True, "recovered": True}), 200)
            asked(ada.post("/api/v1/alerts/test"), 200)
            if not inbox.received:
                raise SystemExit("0.3.2 sent no test alert to its address")
            asked(otto.post("/api/v1/login", json={"name": "otto", "password": OTTO}), 200)
            secret = asked(otto.post("/api/v1/totp/begin", json={"password": OTTO}), 200)["secret"].replace(" ", "")
            code = totp.code_at(secret, int(time.time() // 30))
            shown["totp_secret"] = secret
            shown["one_time_codes"] = asked(otto.post("/api/v1/totp/enable", json={"code": code}), 200)["recovery_codes"]
            asked(ada.post("/api/v1/login", json={"name": "ada", "password": "not the password"}), 401)  # (a line of its own in the activity log)
            time.sleep(WATCHED)
            watched = asked(ada.get("/api/v1/status"), 200)
            shown["states"] = {name: watched[device]["state"] for name, device in ids.items()}
            if set(shown["states"].values()) != {"online"}:
                raise SystemExit(f"0.3.2 did not reach every device: {shown['states']}")
            export = ada.post("/api/v1/export", json={"password": ADA, "passphrase": EXPORT, "parts": ["devices", "actions", "alerts", "wall"]})
            asked(export, 200)
            (root / "export-0.3.2.qkvm").write_bytes(export.content)
            asked(ada.post("/api/v1/logout", json={"scope": "this"}), 200)
            shown["ids"] = ids
            shown["alerts"] = inbox.url
    finally:
        subprocess.run([sys.executable, "-m", "qkvm", "stop", "--data-dir", str(data)], env=environment, cwd=root, capture_output=True, timeout=120)
        try:
            wall.wait(60)
        except subprocess.TimeoutExpired:
            wall.kill()
            raise SystemExit("0.3.2 did not stop") from None
        for device in devices:
            device.stop()
        inbox.shutdown()
    if wall.returncode != 0:
        raise SystemExit(f"0.3.2 ended with {wall.returncode}")
    return shown


def archive(root: Path, out: Path) -> None:
    """data/, data.keys/, devices/, the export and made.json, as they are (each file's mode kept), named by nobody."""

    def anonymous(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if info.name == "data/qkvm.log":
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for name in ("data", "data.keys", "devices", "export-0.3.2.qkvm", "made.json"):
            tar.add(root / name, arcname=name, filter=anonymous)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="the released 0.3.2, as git archive leaves it")
    parser.add_argument("--out", type=Path, default=HERE / "tests" / "fixtures" / "data-0.3.2.tar")
    parser.add_argument("--work", type=Path, help=argparse.SUPPRESS)  # (the child's: where the parent's venv put it to work)
    options = parser.parse_args(argv)
    source = options.source.resolve()
    said = (source / "qkvm" / "_version.py").read_text(encoding="utf-8")
    if f'__version__ = "{VERSION}"' not in said:
        raise SystemExit(f"{source} is not qKVM {VERSION}")
    if options.work is None:
        # A throwaway venv that sees this Python's libraries (a .pth file), with 0.3.2 first on its path: nothing installed.
        with tempfile.TemporaryDirectory(prefix="qkvm-0.3.2-") as temporary:
            work = Path(temporary)
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(work / "venv")], check=True)
            python = work / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            places = {*site.getsitepackages(), sysconfig.get_paths()["purelib"], sysconfig.get_paths()["platlib"]}
            inside = subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], check=True, capture_output=True, text=True).stdout.strip()
            Path(inside, "_libraries_of_the_tests.pth").write_text("".join(f"{place}\n" for place in sorted(places)), encoding="utf-8")
            environment = {name: value for name, value in os.environ.items() if not name.startswith("QKVM_")}
            environment.update(PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
            child = [str(python), str(Path(__file__).resolve()), "--source", str(source), "--out", str(options.out.resolve()), "--work", str(work / "made")]
            return subprocess.run(child, env=environment, cwd=work, check=False).returncode
    import qkvm

    if Path(qkvm.__file__).resolve().parent != source / "qkvm":
        raise SystemExit(f"qkvm comes from {qkvm.__file__}, not from {source}")
    root = options.work
    root.mkdir()
    shown = made(source, root)
    record = {
        "version": VERSION, "made": int(time.time()), "accounts": {"ada": {"role": "admin", "password": ADA}, "otto": {"role": "operator", "password": OTTO}},
        "export": {"file": "export-0.3.2.qkvm", "passphrase": EXPORT}, "devices": DEVICES, "actions": ACTIONS, **shown,
    }  # fmt: skip
    (root / "made.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    archive(root, options.out)
    print(f"{options.out}: {options.out.stat().st_size} bytes, a data folder of qKVM {VERSION}")
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
