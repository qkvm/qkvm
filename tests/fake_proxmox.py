"""A stand-in for Proxmox VE: as much of its API as the wall asks for, and its guests' consoles.

Typed from what a real Proxmox VE 9.2 answered (2026-10-15, a throwaway one with two guests and a token of its own), and
from its documentation of the API:

- every request is signed in with the API token in the `Authorization` header (`PVEAPIToken=<id>=<secret>`); without it,
  or with another one, 401, held back a while (Proxmox holds every 401 three seconds: `refuse_after`);
- what the token may do is said per guest (VM.Audit to see it, VM.Console for its console, VM.PowerMgmt for its power),
  and a refusal is 403 "Permission check failed (/vms/<id>, VM.Audit)"; a guest asked on a node it is not on is 500
  "Configuration file 'nodes/<node>/qemu-server/<id>.conf' does not exist" (and a node there is none of, "hostname
  lookup '<node>' failed");
- `POST .../vncproxy` with websocket=1 answers a ticket (`<password>:PVEVNC:<time>::<signature>`), its port (as a
  text) and its password (eight printable characters), and leaves a task; the port waits `window` seconds for one
  connection; after that, or for a ticket used a second time, the upgrade gets no answer at all (it hangs); a ticket
  older than `ticket_life` is refused 401; a stopped guest's upgrade is taken, and closed half a second later with no
  greeting; the password expires `password_life` seconds after the connection;
- `GET .../vncwebsocket?port=&vncticket=` carries the guest's VNC server (tests/fake_vnc.py) in binary frames of at most
  128 KiB, as Proxmox sends them;
- a power command answers the name of the task it started (UPID:<node>:...:<type>:<vmid>:<user>:), and
  `GET /nodes/<node>/tasks/<upid>/status` says how that stands: `running`, or `stopped` with its `exitstatus` ("OK",
  or what went wrong); a guest under Proxmox's high availability is started or stopped by it, the command's own task
  (`hastart`, `hastop`) ending at once.

And its virtual media, as Proxmox's own source says it (qemu-server's Qemu.pm and QemuServer.pm, pve-storage's
Storage.pm; the research of 0.3.0, kept beside it), for the 0.3.0 media of a guest:

- `GET /nodes/<node>/storage?content=iso` lists the storages of that node that hold ISO images and that the token may
  see (Datastore.Audit or Datastore.AllocateSpace on /storage/<id>; one it may not is not listed at all), and
  `GET /nodes/<node>/storage/<id>/content?content=iso` the images on one (`volid` `<id>:iso/<name>`, `format`, `size`),
  refused 403 "Permission check failed (/storage/<id>, Datastore.AllocateSpace|Datastore.Audit)" where it may not;
- `GET .../config` holds the guest's drives (`ide2: local:iso/x.iso,media=cdrom` or `none,media=cdrom`) and its boot
  order (`boot: order=scsi0;ide2;net0`), with what is pending merged in, and `digest`, the SHA-1 of the file;
- `PUT .../config` (answered at once) and `POST .../config` (answered with a task) change them: a disc in a CD-ROM
  drive needs VM.Config.CDROM (a new CD-ROM drive as well), the boot order VM.Config.Disk, an image on a storage
  Datastore.Audit there; a `digest` that is not the file's is refused 500 "checksum mismatch (file change by other
  user?)". A running guest has a new disc at once, and a new boot order, or a new drive, only from its next start
  (Proxmox's `start`, which a `reset` is not);
- `download-url` and `upload` are not served: a test asks of `requests` that nothing went there.

What the wall did is kept for the tests to look at: every request, every task, every ticket, every upgrade, every change
of a guest's settings, and what each start and reset of a guest began from.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response, StreamingResponse

from tests import ServerThread, local_socket
from tests.fake_kvm import make_device_certificate
from tests.fake_vnc import Behind, VncState

API = "/api2/json"
TOKEN_ID = "wall@pve!qkvm"  # made up, as is the secret: the lab's own are in no file of the repository
SECRET = "0b9e4f2a-5c1d-4e8f-9a3b-7d6c5e4f3a2b"
FRAME = 128 * 1024  # the most Proxmox sends in one frame
PASSWORD_LETTERS = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789%<@+&"


@dataclass
class Guest:
    vmid: int
    name: str = "web"
    node: str = "pve1"
    status: str = "running"  # "running" | "stopped"
    paused: bool = False
    cpus: int = 2
    maxmem: int = 2 * 2**30
    uuid: str = field(default_factory=lambda: str(uuid4()))
    may_see: bool = True  # the token has VM.Audit on it
    may_console: bool = True  # ...VM.Console
    may_power: bool = True  # ...VM.PowerMgmt
    ignores_shutdown: bool = False  # nothing in it answers ACPI: asked to shut down, it goes on running
    console_fails: bool = False  # its console's worker fails: the upgrade is taken and closed with no greeting
    uptime: int = 1234  # seconds its process has run, while it runs (less than before: Proxmox started it again)
    uptime_falls: bool = False  # a Proxmox that says at every look that the guest began again since the last
    # A Proxmox that says "stopped" and "running" by turns of so many seconds, whatever the guest does (0: it does not).
    stopped_by_turns: float = 0.0
    said_stopped: int = 0  # (how often it said so)
    ha: bool = False  # under Proxmox's high availability: started and stopped by it, `power_takes` after the command's task
    screen: VncState = field(default_factory=lambda: VncState(width=320, height=200, name="QEMU (web)"))
    # Its drives and its boot order, as its settings file has them; and what is pending, for its next start.
    config: dict[str, str] = field(default_factory=lambda: {
        "boot": "order=scsi0;ide2;net0", "ide2": "none,media=cdrom", "scsi0": "local-lvm:vm-disk-0,size=8G",
        "net0": "virtio=BC:24:11:5E:1A:01,bridge=vmbr0",
    })  # fmt: skip
    pending: dict[str, str] = field(default_factory=dict)
    may_cdrom: bool = True  # the token has VM.Config.CDROM on it
    may_disk: bool = True  # ...VM.Config.Disk
    running_order: str = ""  # the boot order its running process was started with
    booted: list[str] = field(default_factory=list)  # what each start and reset began from: "ide2 local:iso/x.iso", "scsi0"

    def __post_init__(self) -> None:
        if self.status == "running" and not self.running_order:
            self.running_order = self.config.get("boot", "")


@dataclass
class Storage:
    """A storage of Proxmox's, with the ISO images on it (name: bytes)."""

    images: dict[str, int] = field(default_factory=dict)
    may_see: bool = True  # the token has Datastore.Audit (or Datastore.AllocateSpace) on it
    active: bool = True
    content: str = "iso,vztmpl,backup"
    nodes: list[str] | None = None  # the nodes it is on; None: shared, on every node


DRIVE = re.compile(r"(ide[0-3]|sata[0-5]|scsi([0-9]|[12][0-9]|30)|virtio([0-9]|1[0-5]))")


@dataclass
class Ticket:
    vmid: int
    port: str
    password: str
    ticket: str
    made: float
    task: dict[str, Any]
    used: bool = False


@dataclass
class PveState:
    token_id: str = TOKEN_ID
    secret: str = SECRET
    nodes: list[str] = field(default_factory=lambda: ["pve1"])
    guests: dict[int, Guest] = field(default_factory=lambda: {100: Guest(100)})
    storages: dict[str, Storage] = field(default_factory=lambda: {"local": Storage({"debian-13.iso": 700_000_000, "alpine-3.21.iso": 62_000_000})})
    containers: list[int] = field(default_factory=list)  # containers it has besides (listed, never asked about)
    version: str = "9.2.21"
    refuse_after: float = 0.0  # seconds a 401 is held back (a real one: 3)
    version_takes: float = 0.0  # seconds its version (a sign-in) takes to be answered
    secret_after_version: str = ""  # the token's secret once a version was answered (the token made anew in Proxmox just then)
    window: float = 10.0  # seconds a console's port waits for its one connection
    ticket_life: float = 40.0
    password_life: float = 30.0  # seconds after the connection after which the console's password no longer opens it
    power_takes: float = 0.0  # seconds between a power command and the guest being seen in its new state
    task_takes: float = 0.0  # seconds a power command's task runs (the guest is in its new state as it ends, `power_takes` after)
    task_fails: str = ""  # what a power command's task ends with instead of "OK" (the guest stays as it was, but for "WARNINGS: n")
    tasks_hidden: bool = False  # the token may not read how a task stands (403)
    hostile: str = ""  # a way to misbehave: see make_fake_proxmox
    unwell_until: float = 0.0  # until then (time.monotonic()), every question is answered 500
    # A power command is carried out, and its answer lost on its way back: answered with this HTTP status instead (0: it is
    # not). Proxmox's own for a request it hands on to another node (596: TLS, sending, or waiting for the head of the
    # answer; 597: reading its body), or a proxy's in front of it (502, 503, 504). 595: the node could not be connected to,
    # and nothing is carried out.
    power_answer: int = 0
    # What happened, for the tests to look at.
    requests: list[str] = field(default_factory=list)  # "GET /path" of every request that carried the token
    refused: int = 0  # requests answered 401
    refused_paths: list[str] = field(default_factory=list)  # ...and what each asked for ("GET /version": a sign-in)
    tickets: list[Ticket] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)  # each: upid, type, vmid, status ("running", "OK", or why not)
    upgrades: int = 0
    hung: int = 0  # upgrades that got no answer
    consoles: int = 0  # consoles open right now
    in_the_clear: list[str] = field(default_factory=list)  # any request whose address had the token's secret in it
    changes: list[dict[str, Any]] = field(default_factory=list)  # every change of a guest's settings taken: vmid and what it set
    images_take: float = 0.0  # seconds the images of a storage take to be listed (a slow storage: NFS, say)


def task(state: PveState, kind: str, vmid: int, status: str = "OK") -> dict[str, Any]:
    made = {
        "upid": f"UPID:{state.nodes[0]}:{os.getpid():08X}:{len(state.tasks):08X}:{int(time.time()):08X}:{kind}:{vmid}:{state.token_id}:",
        "type": kind, "vmid": vmid, "status": status, "at": time.monotonic(),
    }  # fmt: skip
    state.tasks.append(made)
    return made


def settings_of(guest: Guest) -> dict[str, str]:
    """A guest's drives and boot order as `GET .../config` says them: with what is pending merged in, as Proxmox does."""
    return {**guest.config, **guest.pending}


def digest_of(guest: Guest) -> str:
    """The SHA-1 of the guest's settings file, as Proxmox says it with them (`digest`): anything of it changed changes it."""
    return hashlib.sha1(json.dumps([guest.uuid, guest.name, guest.config, guest.pending], sort_keys=True).encode()).hexdigest()


def began_from(guest: Guest, order: str) -> str:
    """What a start (or a reset) of the guest begins from, by a boot order: the first of its devices that holds something to
    start from. An empty CD-ROM drive is passed over, as SeaBIOS and OVMF pass it over."""
    for device in order.removeprefix("order=").split(";"):
        said = guest.config.get(device)
        if said is None:
            continue
        if ",media=cdrom" in said:
            disc = said.split(",", 1)[0]
            if disc != "none":
                return f"{device} {disc}"
            continue
        return device
    return "nothing"


def started(guest: Guest) -> None:
    """A start by Proxmox: a new process, which takes what was pending (the boot order, a drive added), and begins."""
    guest.config.update(guest.pending)
    guest.pending.clear()
    guest.running_order = guest.config.get("boot", "")
    guest.booted.append(began_from(guest, guest.running_order))


def become(guest: Guest, status: str) -> None:
    if status == "running" and guest.status != "running":
        started(guest)
    guest.status = status


def make_fake_proxmox(state: PveState, stopping: asyncio.Event | None = None) -> FastAPI:
    app = FastAPI()
    consoles: dict[int, Behind] = {}
    # (For a test: a guest's consoles ended, as they are when it stops; and when it is deleted, its VNC server gone with it,
    # so that a guest made later under its number has a console of its own. Called in the stand-in's own loop.)
    app.state.end_consoles = lambda vmid: consoles[vmid]._drop() if vmid in consoles else None
    app.state.forget_console = lambda vmid: consoles.pop(vmid)._drop() if vmid in consoles else None

    def console_of(guest: Guest) -> Behind:
        if guest.vmid not in consoles:
            consoles[guest.vmid] = Behind(guest.screen)
        return consoles[guest.vmid]

    def signed(headers: Any) -> bool:
        return bool(headers.get("authorization") == f"PVEAPIToken={state.token_id}={state.secret}")

    def refusal(status: int, message: str) -> JSONResponse:
        return JSONResponse({"data": None, "message": message + "\n"}, status_code=status)

    @app.middleware("http")
    async def the_token(request: Request, call_next: Any) -> Any:
        if state.secret in str(request.url):
            state.in_the_clear.append(str(request.url.path))
        if request.url.path.startswith(API):
            if not signed(request.headers):
                state.refused += 1
                state.refused_paths.append(f"{request.method} {request.url.path[len(API):]}")
                if state.refuse_after:
                    await asyncio.sleep(state.refuse_after)
                return Response(status_code=401)
            state.requests.append(f"{request.method} {request.url.path[len(API):]}")
            if time.monotonic() < state.unwell_until:
                return refusal(500, "unable to read file: busy")
            if state.hostile == "echo" and request.url.path.endswith(("/status/current", "/vncproxy")):
                # (A proxy in the way, or a Proxmox, that says back the request's headers when it fails.)
                return refusal(503, f"upstream failed; the request had Authorization: {request.headers.get('authorization')}")
        return await call_next(request)

    @app.get("/")
    async def page() -> Response:
        return Response("<!doctype html><title>Proxmox VE (stand-in)</title>", media_type="text/html")

    @app.get(API + "/version")
    async def version() -> Response:
        if state.hostile == "deep":
            return Response("[" * 100_000, media_type="application/json")
        if state.hostile == "not_proxmox":
            return JSONResponse({"data": {"product": "something else"}})
        if state.version_takes:
            await asyncio.sleep(state.version_takes)
        if state.secret_after_version:
            state.secret = state.secret_after_version
        return JSONResponse({"data": {"version": state.version, "release": state.version.rsplit(".", 1)[0], "repoid": "0123456789abcdef"}})

    @app.get(API + "/cluster/resources")
    async def resources(request: Request) -> Response:
        if state.hostile == "huge_list":
            # Some sixteen megabytes of guests, sent as they are made: built whole first (a json.dumps of all of them in
            # this thread), a busy computer took longer than the wall waits for a first byte, and the wall said "timeout"
            # where what is tried is that it reads no more than its limit.
            async def filler() -> Any:
                yield b'{"data": ['
                for start in range(0, 60_000, 500):
                    yield ",".join(
                        f'{{"vmid": {1000 + n}, "type": "qemu", "node": "pve1", "name": "{"x" * 200}", "status": "running"}}' for n in range(start, start + 500)
                    ).encode() + (b"," if start + 500 < 60_000 else b"")
                yield b"]}"

            return StreamingResponse(filler(), media_type="application/json")
        listed: list[dict[str, Any]] = [
            {"id": f"qemu/{g.vmid}", "type": "qemu", "vmid": g.vmid, "node": g.node, "name": g.name, "status": [] if state.hostile == "odd_status" else g.status, "template": 0, "maxmem": g.maxmem, "maxcpu": g.cpus}
            for g in state.guests.values() if g.may_see
        ]  # fmt: skip
        listed += [{"id": f"lxc/{vmid}", "type": "lxc", "vmid": vmid, "node": state.nodes[0], "name": f"ct{vmid}", "status": "running"} for vmid in state.containers]
        listed.append({"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"})  # (asked for guests, a real one also lists other kinds now and then)
        return JSONResponse({"data": listed})

    def guest_at(node: str, vmid: int, need: str) -> Guest | Response:
        guest = state.guests.get(vmid)
        allowed = guest is not None and {"VM.Audit": guest.may_see, "VM.Console": guest.may_console, "VM.PowerMgmt": guest.may_power}[need]
        if guest is None or not allowed:
            return refusal(403, f"Permission check failed (/vms/{vmid}, {need})")
        if node not in state.nodes:
            return refusal(500, f"hostname lookup '{node}' failed - failed to get address info for: {node}: Name or service not known")
        if guest.node != node:
            return refusal(500, f"Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist")
        return guest

    @app.get(API + "/nodes/{node}/qemu/{vmid}/status/current")
    async def current(node: str, vmid: int) -> Response:
        guest = guest_at(node, vmid, "VM.Audit")
        if isinstance(guest, Response):
            return guest
        if state.hostile == "lost_guest":  # it says the guest is not on its node, and lists it there all the same
            return refusal(500, f"Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist")
        if state.hostile == "null_status":
            return JSONResponse({"data": None})
        if state.hostile == "odd_status":
            return JSONResponse({"data": {"status": [], "qmpstatus": {}, "name": ["x"], "cpus": "2", "maxmem": None}})
        if state.hostile == "trickle":

            async def a_byte_at_a_time() -> Any:
                for _ in range(400):
                    yield b" "
                    await asyncio.sleep(0.25)

            return StreamingResponse(a_byte_at_a_time(), media_type="application/json")
        running = guest.status == "running"
        if guest.stopped_by_turns and running and int(time.monotonic() / guest.stopped_by_turns) % 2:
            guest.said_stopped += 1
            return JSONResponse({"data": {"vmid": guest.vmid, "name": guest.name, "status": "stopped", "qmpstatus": "stopped", "cpus": guest.cpus, "maxmem": guest.maxmem, "uptime": 0}})
        if guest.uptime_falls:
            guest.uptime = max(0, guest.uptime - 100)
        return JSONResponse({"data": {
            "vmid": guest.vmid, "name": guest.name, "status": guest.status,
            "qmpstatus": ("paused" if guest.paused else "running") if running else "stopped",
            "cpus": guest.cpus, "maxmem": guest.maxmem, "mem": guest.maxmem // 4 if running else 0,
            "cpu": 0.03 if running else 0, "uptime": guest.uptime if running else 0, "ha": {"managed": 0},
        }})  # fmt: skip

    @app.get(API + "/nodes/{node}/qemu/{vmid}/config")
    async def config(node: str, vmid: int) -> Response:
        guest = guest_at(node, vmid, "VM.Audit")
        if isinstance(guest, Response):
            return guest
        smbios = {"smbios1": f"uuid={guest.uuid}"} if guest.uuid else {}  # (a guest made before Proxmox gave each one has none)
        return JSONResponse({"data": {
            "name": guest.name, **smbios, "cores": guest.cpus, "memory": str(guest.maxmem // 2**20), **settings_of(guest), "digest": digest_of(guest),
        }})  # fmt: skip

    async def change_config(node: str, vmid: int, request: Request, as_a_task: bool) -> Response:
        """`PUT` (answered when done) and `POST` (answered with a task) of a guest's settings: its drives and its boot order,
        each checked as Proxmox checks it."""
        guest = guest_at(node, vmid, "VM.Audit")
        if isinstance(guest, Response):
            return guest
        asked = dict(parse_qsl((await request.body()).decode(), keep_blank_values=True))
        digest = asked.pop("digest", None)
        if any(key != "boot" and not DRIVE.fullmatch(key) for key in asked):
            return refusal(400, f"only drives and the boot order are spoken here, not {sorted(asked)}")
        # (What is no drive is checked first, before the file is read: the boot order is one of the disk options.)
        if "boot" in asked and not guest.may_disk:
            return refusal(403, f"Permission check failed (/vms/{vmid}, VM.Config.Disk)")
        if digest is not None and digest != digest_of(guest):
            return refusal(500, "checksum mismatch (file change by other user?)")
        now = settings_of(guest)
        for key, value in asked.items():
            if key == "boot":
                if not re.fullmatch(r"order=[a-z0-9]+(;[a-z0-9]+)*", value):
                    return refusal(400, f"invalid format - format error\nboot.order: invalid boot device '{value}'")
                continue
            disc, *options = value.split(",")
            cdrom = "media=cdrom" in options
            was = now.get(key)
            if was is not None and ",media=cdrom" not in was and not guest.may_disk:
                return refusal(403, f"Permission check failed (/vms/{vmid}, VM.Config.Disk)")  # (a disk changed into something else)
            if not (guest.may_cdrom if cdrom else guest.may_disk):
                return refusal(403, f"Permission check failed (/vms/{vmid}, {'VM.Config.CDROM' if cdrom else 'VM.Config.Disk'})")
            if disc not in ("none", "cdrom"):
                storage_id, _, volume = disc.partition(":")
                storage = state.storages.get(storage_id)
                if storage is None or not volume.startswith("iso/") or volume[4:] not in storage.images:
                    return refusal(500, f"volume '{disc}' does not exist")
                if not storage.may_see:
                    return refusal(403, f"Permission check failed (/storage/{storage_id}, Datastore.AllocateSpace|Datastore.Audit)")
                if not cdrom:
                    return refusal(400, f"unable to use volume {disc} - content type needs to be 'images'")
        for key, value in asked.items():
            # A disc goes into a running guest's drive at once; a new boot order, and a new drive, wait for its next start.
            if guest.status == "running" and (key == "boot" or key not in guest.config):
                guest.pending[key] = value
            else:
                guest.config[key] = value
                guest.pending.pop(key, None)
        state.changes.append({"vmid": vmid, **asked})
        if as_a_task:
            return JSONResponse({"data": task(state, "qmconfig", vmid)["upid"]})
        return JSONResponse({"data": None})

    @app.put(API + "/nodes/{node}/qemu/{vmid}/config")
    async def put_config(node: str, vmid: int, request: Request) -> Response:
        return await change_config(node, vmid, request, as_a_task=False)

    @app.post(API + "/nodes/{node}/qemu/{vmid}/config")
    async def post_config(node: str, vmid: int, request: Request) -> Response:
        return await change_config(node, vmid, request, as_a_task=True)

    @app.get(API + "/nodes/{node}/storage")
    async def storages(node: str, content: str = "") -> Response:
        if node not in state.nodes:
            return refusal(500, f"hostname lookup '{node}' failed - failed to get address info for: {node}: Name or service not known")
        listed: list[Any] = [
            {"storage": name, "type": "dir", "content": one.content, "active": int(one.active), "enabled": 1, "shared": int(one.nodes is None),
             "total": 100 * 2**30, "used": sum(one.images.values()), "avail": 100 * 2**30 - sum(one.images.values())}
            for name, one in state.storages.items()
            if one.may_see and (one.nodes is None or node in one.nodes) and (not content or content in one.content.split(","))
        ]  # fmt: skip
        if state.hostile == "odd_storages":
            listed += [None, "local", {"storage": 5}, {"storage": "../x", "content": "iso", "active": 1}, {"storage": "zz", "content": "iso", "active": 0}]
        return JSONResponse({"data": listed})

    @app.get(API + "/nodes/{node}/storage/{storage}/content")
    async def images(node: str, storage: str, content: str = "") -> Response:
        one = state.storages.get(storage)
        if one is None or not (one.nodes is None or node in one.nodes):
            return refusal(500, f"storage '{storage}' does not exist")
        if not one.may_see:
            return refusal(403, f"Permission check failed (/storage/{storage}, Datastore.AllocateSpace|Datastore.Audit)")
        if not one.active:
            return refusal(500, f"storage '{storage}' is not online")
        if state.images_take:
            await asyncio.sleep(state.images_take)
        listed: list[Any] = [
            {"volid": f"{storage}:iso/{name}", "format": "iso", "size": size, "ctime": 1762000000, "content": "iso"}
            for name, size in one.images.items() if content in ("", "iso")
        ]  # fmt: skip
        if state.hostile == "odd_images":
            listed += [
                None, "x", {"volid": 5}, {"volid": f"other:iso/{storage}.iso", "content": "iso"}, {"volid": f"{storage}:images/vm-100-disk-0.raw", "content": "images"},
                {"volid": f"{storage}:iso/../../etc/passwd.iso", "content": "iso"}, {"volid": f"{storage}:iso/two.iso,media=disk", "content": "iso"},
                {"volid": f"{storage}:iso/odd.iso", "content": "iso", "size": "big"},
            ]  # fmt: skip
        return JSONResponse({"data": listed})

    @app.post(API + "/nodes/{node}/qemu/{vmid}/vncproxy")
    async def vncproxy(node: str, vmid: int, request: Request) -> Response:
        guest = guest_at(node, vmid, "VM.Console")
        if isinstance(guest, Response):
            return guest
        form = (await request.body()).decode()
        if "websocket=1" not in form:
            return refusal(400, "only the websocket way is spoken here")
        password = "".join(secrets.choice(PASSWORD_LETTERS) for _ in range(8))
        signature = base64.b64encode(os.urandom(256)).decode()
        ticket = f"{password}:PVEVNC:{int(time.time()):08X}::{signature}"
        port = str(5900 + len(state.tickets) % 100)
        made = Ticket(vmid, port, password, ticket, time.monotonic(), task(state, "vncproxy", vmid, "running"))
        state.tickets.append(made)
        said: dict[str, Any] = {"ticket": ticket, "port": port, "password": password, "user": state.token_id, "cert": "-----BEGIN CERTIFICATE-----\n...", "upid": made.task["upid"]}
        if state.hostile == "bad_ticket":
            said = {**said, "ticket": "x" * 5000}
        elif state.hostile == "bad_port":
            said = {**said, "port": "99999"}
        elif state.hostile == "no_password":
            said = {key: value for key, value in said.items() if key != "password"}
        elif state.hostile == "redirect":
            return Response(status_code=302, headers={"Location": "https://elsewhere.example/api2/json/vncproxy"})
        return JSONResponse({"data": said})

    @app.post(API + "/nodes/{node}/qemu/{vmid}/status/{verb}")
    async def power(node: str, vmid: int, verb: str) -> Response:
        guest = guest_at(node, vmid, "VM.PowerMgmt")
        if isinstance(guest, Response):
            return guest
        if verb not in ("start", "stop", "shutdown", "reset", "reboot", "suspend", "resume"):
            return refusal(501, f"Method 'POST /nodes/{node}/qemu/{vmid}/status/{verb}' not implemented")
        if state.power_answer == 595:
            return JSONResponse({"data": None}, status_code=595)  # (the node it is for could not be connected to: nothing reached it)
        handed = guest.ha and verb in ("start", "stop", "shutdown")
        kind = ("hastart" if verb == "start" else "hastop") if handed else f"qm{verb}"
        runs = state.task_takes and not handed
        made = task(state, kind, vmid, "running" if runs else state.task_fails if state.task_fails and not handed else "OK")
        becomes = {"start": "running", "stop": "stopped", "shutdown": "running" if guest.ignores_shutdown else "stopped"}.get(verb)
        loop = asyncio.get_running_loop()

        def carried_out() -> None:
            if not (made["status"] == "OK" or made["status"].startswith("WARNINGS: ")):  # (warnings: done all the same)
                return
            if verb == "reset" and guest.status == "running":
                # (The same process begins again: what is pending stays pending, and it begins from the order it started with.)
                guest.booted.append(began_from(guest, guest.running_order))
            if becomes is None:
                return
            if state.power_takes:
                loop.call_later(state.power_takes, become, guest, becomes)
            else:
                become(guest, becomes)

        def ended() -> None:
            made["status"] = state.task_fails or "OK"
            carried_out()

        if runs:
            loop.call_later(state.task_takes, ended)
        else:
            carried_out()
        if state.power_answer:
            return JSONResponse({"data": None}, status_code=state.power_answer)
        return JSONResponse({"data": made["upid"]})

    @app.get(API + "/nodes/{node}/tasks/{upid}/status")
    async def task_status(node: str, upid: str) -> Response:
        if state.tasks_hidden:
            return refusal(403, f"Permission check failed (/nodes/{node}, Sys.Audit)")
        found = next((one for one in state.tasks if one["upid"] == upid), None)
        if found is None or node not in state.nodes:
            return refusal(500, f"no such task '{upid}'")
        said: dict[str, Any] = {"upid": upid, "node": node, "type": found["type"], "id": str(found["vmid"]), "user": state.token_id, "pid": os.getpid()}
        if found["status"] == "running":
            return JSONResponse({"data": {**said, "status": "running"}})
        return JSONResponse({"data": {**said, "status": "stopped", "exitstatus": found["status"]}})

    async def deny(websocket: WebSocket, status: int) -> None:
        try:
            await websocket.send_denial_response(Response(status_code=status))
        except RuntimeError:  # (a web server that cannot say it otherwise: refused all the same)
            await websocket.close(code=1008)

    async def hang(websocket: WebSocket) -> None:
        """No answer at all, as Proxmox gives to a port whose window is over (it leaves the request hanging)."""
        state.hung += 1
        try:
            async with asyncio.timeout(60):
                if stopping is not None:
                    await stopping.wait()
                else:
                    await asyncio.sleep(60)
        except TimeoutError:
            pass
        await deny(websocket, 503)

    @app.websocket(API + "/nodes/{node}/qemu/{vmid}/vncwebsocket")
    async def vncwebsocket(websocket: WebSocket, node: str, vmid: int) -> None:
        state.upgrades += 1
        if state.secret in str(websocket.url):
            state.in_the_clear.append(websocket.url.path)
        if not signed(websocket.headers):
            state.refused += 1
            if state.refuse_after:
                await asyncio.sleep(state.refuse_after)
            await deny(websocket, 401)
            return
        if state.hostile == "upgrade_500":
            await deny(websocket, 500)
            return
        port, given = websocket.query_params.get("port", ""), websocket.query_params.get("vncticket", "")
        found = next((t for t in state.tickets if t.ticket == given), None)
        if found is None or found.vmid != vmid or found.port != port or state.guests.get(vmid) is None or state.guests[vmid].node != node:
            await deny(websocket, 401)  # "permission denied - invalid PVEVNC ticket"
            return
        if found.used or time.monotonic() - found.made > state.window or state.hostile == "silent_upgrade":
            if not found.used and found.task["status"] == "running":
                found.task["status"] = "connection timed out"
            await hang(websocket)
            return
        if time.monotonic() - found.made > state.ticket_life:
            await deny(websocket, 401)
            return
        found.used = True
        guest = state.guests[vmid]
        wanted = websocket.headers.get("sec-websocket-protocol", "")
        await websocket.accept(subprotocol="binary" if "binary" in wanted else None)
        if guest.status != "running" or guest.console_fails:
            found.task["status"] = "Failed to run vncproxy."
            await asyncio.sleep(0.5)
            await websocket.close()
            return
        if state.hostile in ("text_frame", "huge_frame"):
            try:
                if state.hostile == "text_frame":
                    await websocket.send_text("RFB 003.008\n")
                else:
                    await websocket.send_bytes(b"RFB 003.008\n" + bytes(4 * 1024 * 1024))
                await asyncio.sleep(1)
                await websocket.close()
            except Exception:  # (the wall hung up on it, as it should: nothing more to say)
                pass
            return
        guest.screen.password = found.password  # (what `qm vncproxy` sets as the guest's VNC password, for this connection)
        expiry = asyncio.get_running_loop().call_later(state.password_life, _expire, guest.screen, found.password)
        state.consoles += 1
        try:
            await console_of(guest).serve(websocket, FRAME)
        finally:
            state.consoles -= 1
            found.task["status"] = "OK"
            expiry.cancel()

    return app


def _expire(screen: VncState, password: str) -> None:
    if screen.password == password:
        screen.password = secrets.token_hex(8)  # (none that anybody was given)


class FakeProxmox:
    """Runs make_fake_proxmox() over HTTPS on a localhost port in a background thread. `url`: its address, at the port."""

    def __init__(self, state: PveState | None = None, tls_dir: Path | None = None) -> None:
        self.state = state or PveState()
        self._sock = local_socket()
        self.port: int = self._sock.getsockname()[1]
        # (Its own certificate, made in the folder given: two stand-ins given one folder show one certificate, as the
        # nodes of one Proxmox do not, and one Proxmox seen at two addresses does.)
        cert, key = make_device_certificate(tls_dir or Path(tempfile.mkdtemp(prefix="fake-proxmox-")))
        self.url = f"https://127.0.0.1:{self.port}"
        self._stopping: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        config = uvicorn.Config(self._app, interface="asgi3", log_level="error", access_log=False, ssl_certfile=str(cert), ssl_keyfile=str(key), ws_max_size=FRAME)
        self._server = uvicorn.Server(config)
        self._serving = ServerThread("fake Proxmox", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)
        self._made: FastAPI | None = None

    async def _app(self, scope: Any, receive: Any, send: Any) -> None:
        if self._made is None:
            self._loop = asyncio.get_running_loop()
            self._stopping = asyncio.Event()  # (upgrades that hang are let go of when the stand-in stops)
            self._made = make_fake_proxmox(self.state, self._stopping)
        await self._made(scope, receive, send)

    def stop_guest(self, vmid: int) -> None:
        """The guest stops: its consoles end with it, as QEMU's VNC server does."""
        self.state.guests[vmid].status = "stopped"
        self.end_consoles(vmid)

    def end_consoles(self, vmid: int) -> None:
        """The guest's consoles end, the guest running on (Proxmox restarted, the guest handed to another node)."""
        if self._loop is not None and self._made is not None:
            self._loop.call_soon_threadsafe(self._made.state.end_consoles, vmid)

    def delete_guest(self, vmid: int) -> None:
        """The guest is deleted (stopped and destroyed): its consoles end, and its number is free."""
        del self.state.guests[vmid]
        if self._loop is not None and self._made is not None:
            self._loop.call_soon_threadsafe(self._made.state.forget_console, vmid)

    def make_guest(self, name: str, node: str | None = None, **more: Any) -> Guest:
        """A new virtual machine, numbered as Proxmox numbers one (/cluster/nextid: the lowest free number from 100 on), so
        that it has the number of a guest deleted before it; with an SMBIOS UUID of its own, as Proxmox gives every new one,
        and a screen of its own."""
        vmid = next(number for number in range(100, 1_000_000) if number not in self.state.guests)
        more.setdefault("screen", VncState(width=320, height=200, name=f"QEMU ({name})", seed=vmid % 7 + 3))
        made = Guest(vmid, name, node=node or self.state.nodes[0], **more)
        self.state.guests[vmid] = made
        return made

    def guest_url(self, vmid: int = 100, node: str | None = None) -> str:
        return f"{self.url}/nodes/{node or self.state.guests[vmid].node}/qemu/{vmid}"

    def start(self) -> FakeProxmox:
        self._serving.start()
        return self

    def stop(self) -> None:
        if self._stopping is not None and self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._stopping.set)
        self._server.should_exit = True
        self._serving.join(timeout=10)
