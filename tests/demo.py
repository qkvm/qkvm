"""Run the wall against fake KVMs and servers, one per tile state.

    python -m tests.demo        then open http://127.0.0.1:8788/ and sign in with DEMO_PASSWORD

State lives in a temporary folder and is thrown away on exit. Pass --fresh to start
without a password or devices, to walk through the first-run setup instead.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import uvicorn

from qkvm.core import Core
from qkvm.server import create_app
from qkvm.store import DeviceRecord, UserRecord
from qkvm.update import Updater
from tests.aspeed_frames import console_screen
from tests.fake_github import FakeGitHub, make_wheel
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_proxmox import SECRET as PVE_SECRET
from tests.fake_proxmox import TOKEN_ID as PVE_TOKEN
from tests.fake_proxmox import FakeProxmox, Guest, PveState
from tests.fake_redfish import BmcState, FakeBmc
from tests.fake_vnc import FakeVnc, VncState

PORT = 8788
DEMO_PASSWORD = "demo-wall-password"
KVM_PASSWORD = "secret"


def main() -> None:
    os.environ.setdefault("QKVM_DEV", "1")  # serve the page files from disk, so edits show on reload
    fakes = {
        "Build server": FakeKvm(FakeState(colour=(32, 74, 135), atx=True)),
        "NAS": FakeKvm(FakeState(colour=(46, 110, 78), wol=[{"mac": "AA:BB:CC:DD:EE:FF", "name": "nas"}])),
        "Idle stream": FakeKvm(FakeState(colour=(120, 60, 130), idle_until_viewer=True)),
        "Rack (4 ports)": FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130), None, (95, 70, 140)], active_port=1)),
        "No signal": FakeKvm(FakeState(signal=False)),
        "Wrong password": FakeKvm(FakeState(password="something else")),
    }
    # Servers, seen through their management controller: running with one slow fan, switched off, and faulty.
    servers = {
        # As a real controller does: it takes a change and shows it a few seconds later.
        # These two are of the make whose console qKVM reads: their tiles show their screens.
        "Database server": FakeBmc(BmcState(health="Warning", console=None, slow_to_act=4.0, blink_lasts=15.0, own_console=True, screen=[console_screen(seed=3)])),
        # This one hands out a way into its console, so "Open console" leads straight in.
        "Spare server": FakeBmc(BmcState(power="Off", model="SRV-1100")),
        "Storage server": FakeBmc(BmcState(health="Critical", temperature_health="Critical", console=None, own_console=True, screen=[console_screen(1024, 768, 22, seed=8)])),
        # A controller running OpenBMC, whose console (/kvm/0) is VNC: obmc-ikvm pushes the screen at its own pace.
        "OpenBMC server": FakeBmc(BmcState(layout="openbmc", model="SRV-3300", kvm_screen=VncState(password=None, width=800, height=600, seed=6, name="obmc-ikvm", pushes=True, push_every=0.5))),
    }
    for fake in (*fakes.values(), *servers.values()):
        fake.start()
    jet = FakeJetKvm(JetState(colour=(30, 90, 110), width=1280, height=720)).start()
    # A machine with a VNC server on it (a virtual machine, say): its screen is read with the RFB reader.
    vnc = FakeVnc(VncState(width=800, height=500, seed=4, name="a VNC desktop", encoding="mixed")).start()
    # A Proxmox VE with two virtual machines, one running and one stopped, seen through its API with a made-up token.
    pve = FakeProxmox(PveState(guests={
        100: Guest(100, "web", screen=VncState(width=1024, height=640, seed=5, name="QEMU (web)")),
        101: Guest(101, "backup", status="stopped"),
    })).start()  # fmt: skip

    # A stand-in for GitHub with a newer release on it, so Settings -> Updates has something to show.
    github = FakeGitHub().start()
    github.publish("9.9.9", make_wheel("9.9.9"), notes="Faster tiles.\nBulk actions remember the last selection.\nFixes for KVMs with two screens.")

    with tempfile.TemporaryDirectory() as folder:
        core = Core(Path(folder))
        core.updater = Updater(Path(folder), github.repo, api=github.url, keys=(), allow_unsigned=True)
        if "--fresh" in sys.argv:
            print("Fake KVMs to add (password: %s):" % KVM_PASSWORD)
            for name, fake in (*fakes.items(), *servers.items()):
                print(f"  {fake.url}   {name}")
            if jet:
                print(f"  {jet.url}   JetKVM")
            print(f"  {vnc.url}   VNC server (choose VNC servers, or type the address as it stands)")
            print(f"  {pve.url}   Proxmox VE (choose Virtual machines on Proxmox VE; token {PVE_TOKEN}, secret {PVE_SECRET})")
        else:
            core.store.users = [UserRecord(id="demo", name="admin", role="admin", auth=core.vault.create(DEMO_PASSWORD))]
            urls = {name: fake.url for name, fake in fakes.items()}
            urls["Powered off"] = "http://127.0.0.1:9"  # nothing listens there
            kinds = dict.fromkeys(servers, "redfish")
            urls.update({name: fake.url for name, fake in servers.items()})
            urls["JetKVM"] = jet.url
            kinds["JetKVM"] = "jetkvm"
            urls["VNC desktop"] = vnc.url
            kinds["VNC desktop"] = "vnc"
            for name, vmid in (("Web VM", 100), ("Backup VM", 101)):
                urls[name] = pve.guest_url(vmid)
                kinds[name] = "proxmox"
            # One KVM on the wall twice, as happens when it is added under its address on the network and on the VPN.
            urls["NAS (over the VPN)"] = fakes["NAS"].url.replace("127.0.0.1", "localhost")
            for number, (name, url) in enumerate(urls.items()):
                group = "Rack A" if number < 4 else "Office"
                kind = kinds.get(name, "kvmd")
                record = DeviceRecord(id=f"demo{number}", name=name, url=url, kind=kind, group=group, username=PVE_TOKEN if kind == "proxmox" else "admin")
                if name.startswith("NAS"):
                    record.ident = "cert:" + "5a" * 32  # what the two would be known by, had they a certificate
                record.secret = core.vault.encrypt(PVE_SECRET if kind == "proxmox" else KVM_PASSWORD, record.id)
                core.store.devices.append(record)
            core.store.save()
            core.vault.lock()  # like a real start: nothing works until someone signs in
        print(f"Demo wall: http://127.0.0.1:{PORT}/", flush=True)
        uvicorn.run(create_app(core), host="127.0.0.1", port=PORT, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
