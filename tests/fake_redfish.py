"""A stand-in for a server's management controller: as much of Redfish as the wall asks for.

Laid out the way AMI MegaRAC lays it out (as read from an ASRock Rack and a Gigabyte board),
which is one computer, one chassis and one controller, each called "Self". Or, with
`layout="openbmc"`, the way OpenBMC's bmcweb lays it out (read from its source, 2026): the
computer is "system", the chassis "chassis", the controller "bmc" and says it is OpenBmc; the
sensors are in the newer shape of the standard (ThermalSubsystem with ThermalMetrics and a
collection of Fans, each read on its own) and there is no Thermal; the locator light is
LocationIndicatorActive alone; which kinds of reset exist is said in a ResetActionInfo; the
software it has is in UpdateService's FirmwareInventory, each image naming what it is for, and the
controller says its firmware's version itself, or not (as OpenBMC's romulus in QEMU did not).

It also has what such a controller has besides Redfish: the sign-in of its own web page, and the
console that page opens, which sends the server's screen (see qkvm/ami.py).
"""

from __future__ import annotations

import asyncio
import secrets
import struct
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response, StreamingResponse

from qkvm import ami
from tests import ServerThread, local_socket
from tests.fake_kvm import make_device_certificate
from tests.fake_vnc import Behind

PROCESSOR = "Intel Xeon Silver 4410Y"
UNSET = object()
WAY_IN: object = UNSET  # set by a test: what the controller answers, word for word, as the way into its console
# What the computer, the chassis and the controller are called, by layout.
NAMES = {"ami": ("Self", "Self", "Self"), "openbmc": ("system", "chassis", "bmc")}
ENCLOSURE = "Enclosure.Internal.0-1"  # a disk enclosure: a chassis of its own, without sensors (iDRAC lists such)

@dataclass
class BmcState:
    username: str = "admin"
    password: str = "secret"
    power: str = "On"
    health: str = "OK"
    model: object = "SRV-2200"
    manufacturer: object = "Example Systems"
    hostname: object = None
    uuid: object = field(default_factory=lambda: str(uuid4()))  # the number a server gives for itself: every one its own
    # The number its controller's Redfish service gives for itself, in the service root that anybody may read (a real AMI
    # board says its controller's own there, not the computer's; bmcweb one it made). None: the root says none.
    root_uuid: object = field(default_factory=lambda: str(uuid4()))
    # ...and what its manager names as the service it hosts (ServiceEntryPointUUID; a real AMI board: the root's). UNSET: the
    # root's; None: not said.
    entry_uuid: object = UNSET
    firmware: object = "1.42.0"
    # (openbmc layout) What its controller says of its firmware: "both" its version and the image it runs
    # (Links.ActiveSoftwareImage), as bmcweb does where it knows which image runs; "image" the image alone; "neither",
    # as OpenBMC's romulus image in QEMU did (its master of October 2026), where the version is in the firmware inventory alone.
    manager_says: str = "both"
    # (openbmc layout) The firmware inventory, in its order: (id, purpose, state, version), as bmcweb lists the software
    # it has: an image of purpose BMC names the controller as its RelatedItem, one of purpose Host the computer's BIOS;
    # its state is "Enabled" where the image is active. None: a Host image first, then the controller's own, which is `firmware`.
    images: list[tuple[str, str, str, object]] | None = None
    image_link: object = None  # (openbmc layout) what the controller's own image names as what it is for, instead of the controller
    inventory_more: list[Any] = field(default_factory=list)  # (openbmc layout) more entries of the inventory's list, as they are
    inventory_says: dict[str, Any] = field(default_factory=dict)  # (openbmc layout) more that the inventory says of itself (a next page, a count)
    cpu_temperature: object = 61
    offered: list[str] = field(default_factory=lambda: ["On", "ForceOff", "GracefulShutdown", "ForceRestart"])
    system_link: str | None = None  # what the controller claims its computer is called (None: the usual name of its layout)
    layout: str = "ami"  # "ami" or "openbmc": see the top of this file
    enclosures_first: bool = False  # the list of chassis begins with a disk enclosure, which has no sensors; the computer says which chassis is its own
    chassis_claimed: str | None = None  # what the computer claims its chassis is (None: the right one)
    fan_claimed: str | None = None  # one more fan in the list of fans (openbmc layout), wherever this says it is
    more_fans: int = 0  # so many fans more than the three, each fitted and well (openbmc layout)
    last_fan_unwell: bool = False  # ...but the last of them says it is not well
    fan_takes: float = 0.0  # seconds each fan takes to answer (openbmc layout)
    # At one of its moments it answers an error with HTTP 200, as some controllers do, instead of 503: as a
    # record ({"error": {"message": ...}}, the standard's shape) or as a text ({"error": "..."}). None: 503.
    errors_in_200: str | None = None
    dawdles: bool = False  # answers a sign-out a byte at a time
    console: object = "/viewer.html?{pass}"  # what it hands out as the way into its console; None: it has none
    console_kind: str = "HTML 5"
    passes: list[str] = field(default_factory=list)  # the passes to the console it made out
    # Starting into the BIOS setup: which one-time boot targets the controller allows (None: it says none), and the boot
    # override as it stands (enabled, target). A real AMI board allows "BiosSetup"; a board that does not is not offered it.
    boot_targets: object = field(default_factory=lambda: ["None", "Pxe", "Hdd", "BiosSetup", "Usb", "Cd"])
    boot_override: tuple[str, str] = ("Disabled", "None")
    # A change of the boot override is answered with this (the real AMI board: 204, measured 2026-10-19, where the light's
    # change is answered 202); and kept (False: answered as taken, and the override left as it was).
    boot_status: int = 204
    boot_kept: bool = True
    clear_status: int | None = None  # ...and a change back to Disabled with this (None: as any other)
    clear_kept: bool = True
    boot_partial: bool = False  # takes BootSourceOverrideEnabled of a change and not its target (and says nothing of it)
    reset_answer_takes: float = 0.0  # seconds a reset is answered after it was done
    reset_signs_out_once: bool = False  # the next reset is answered 401 (after `reset_answer_takes`), every session forgotten, and not done
    boot_moved_once: bool = False  # the next change of the boot override is made, and answered "moved" to an address that is none
    slow_boot_changes: int = 0  # so many changes of the boot override, from the first, are made and answered `slow_boot_by` seconds late
    slow_boot_by: float = 3.0
    # Seconds after a change of the boot override during which a read of the computer is answered only late (the real board
    # answered none for about a minute, while it took a restart sent right after the change), and until when (monotonic).
    busy_after_boot_change: float = 0.0
    reads_busy_until: float = 0.0
    override_meanwhile: tuple[str, str] | None = None  # another tool sets this override just before the wall's change comes (once)
    override_after: tuple[str, str] | None = None  # ...or just after the wall's change was taken (once)
    power_meanwhile: str | None = None  # the server's power becomes this just before the wall's change of the boot override comes (once)
    reset_refused: bool = False  # a reset it offers is answered 400 all the same (a controller that changes its mind)
    reset_status: int | None = None  # a reset is answered with this (an error of its own, 500 say), and nothing is done
    manager_reset_status: int | None = None  # ...and the controller's own restart
    light_status: int | None = None  # ...and a change of the locator light
    busy_after_reset: float = 0.0  # seconds after a reset was taken during which a read of the computer is answered only late
    power_after_change: str | None = None  # the server's power becomes this once a change of the boot override was taken (once; its mark as it was)
    led: object = "Off"  # the light to find the server by
    led_kinds: object = field(default_factory=lambda: ["Lit", "Blinking", "Off"])
    locating: object = None  # the newer way of saying the same: True, False, or None where the controller has not got it
    mark: str = '"1791401332"'  # what it puts on the state of the server, to be shown with every change
    strict_marks: bool = False  # hands its marks out as weak ones and then does not take them back
    temperature_health: str = "OK"
    changes: list[dict[str, Any]] = field(default_factory=list)  # every change made to the server's entry
    ignores_shutdown: bool = False  # takes a request to shut down and stays on: a server with nothing on it to answer
    # As a real one did once: "accepted", and nothing happens. The kinds of reset that go that way.
    drops: list[str] = field(default_factory=list)
    # Answers a power command with "accepted" and a record of its own to ask about, as AMI's controllers do.
    keeps_tasks: bool = False
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    # One of its moments: until this time (time.monotonic()), whatever is asked is answered with an error.
    unwell_until: float = 0.0
    comes_back_after: float | None = None  # seconds after which a server that went off is on again by itself
    power_takes: float = 0.0  # seconds between a power command being accepted and the server being seen in its new state
    power_later: tuple[float, str] | None = None
    # As measured on a real board: a change is "accepted" and shows some seconds later, and a light told
    # to blink goes out again by itself.
    slow_to_act: float = 0.0
    blink_lasts: float | None = None
    later: list[tuple[float, object]] = field(default_factory=list)  # (when, what the light is then)
    back_on_at: float = 0.0
    restart_takes: float = 0.0  # seconds the controller is away after it was told to restart, having forgotten every session
    away_until: float = 0.0
    tokens: dict[str, str] = field(default_factory=dict)  # session token -> session id
    logins: int = 0
    login_status: int = 201  # another number: signing in fails with it, whatever the password
    signed_out: int = 0
    requests: list[str] = field(default_factory=list)  # every signed-in request, as "GET /path"
    roots_unsigned: int = 0  # how often the service root was read without a session
    system_unwell: bool = False  # its computer's resource is answered with an error of its own (503), the rest as ever
    actions: list[str] = field(default_factory=list)  # what the wall asked it to do
    # Its own web page's sign-in, and the console that page opens (AMI's). False: a controller of another make,
    # which answers "no such thing" to all of it.
    own_console: bool = False
    # Firmware that lets a console reconnect after a break (a real Gigabyte board's): it wants to be told
    # "connection complete" before the pass, and closes without a word on a console that begins otherwise.
    reconnects: bool = False
    says_what_it_can: bool = True  # False: asked for the list of what it can do, it has none to give
    screen: list[Any] = field(default_factory=list)  # what is on the server's screen: frames (tests.aspeed_frames.Frame), sent in this order
    piece: int = 700  # a frame is sent in pieces of this many bytes
    # A real board, to a console opened again: first a frame that says "nothing changed", and the whole screen
    # only when it is asked for, a moment later.
    begins_with_nothing: bool = False
    seats: int = 2  # how many may have the console open at once
    monitor_goes_dark: bool = False  # set to switch the server's own monitor off while a console is open
    web_sessions: dict[str, str] = field(default_factory=dict)  # the web page's sessions: cookie -> the token to send with every request
    web_logins: int = 0
    web_signed_out: int = 0
    console_passes: set[str] = field(default_factory=set)
    watching: int = 0  # consoles open right now
    sign_in_takes: float = 0.0  # seconds its web page takes to answer a sign-in, with the session made at once
    root_takes: float = 0.0  # seconds the root of its Redfish service takes to answer (an older AMI firmware: 3.2 s, measured)
    # Seconds after which it ends a console session, saying that its time is up (a real board: half an hour
    # in which no key was pressed). 0: never.
    session_lasts: float = 0.0
    # Somebody else at the console, at the controller's own page. Who they are, as the console says it (name, address).
    held_by: bytes = b""  # they had it first: whoever comes is told to wait while they are asked, and gets no picture meanwhile
    shut_out: bool = False  # ...or they have set that nobody else comes in, and whoever comes is told so at once
    holder_returning: bool = False  # nobody is there, but the one whose console dropped may come back (a real board says so, and sends the picture)
    asks: list[tuple[int, bytes]] = field(default_factory=list)  # put in by a test: somebody asks whoever holds the console for it (kind of message, who)
    answers: list[tuple[int, int, bytes, float]] = field(default_factory=list)  # what was answered: kind, number, who, seconds after the question
    heard: list[tuple[int, int, int]] = field(default_factory=list)  # what was sent to the console: (kind, status, bytes)
    mouse_mode: int = ami.ABSOLUTE  # which mouse the console tells the viewer the server shows (sent once the pass is good)
    # Keyboard and mouse the console was sent, decoded: ("key", modifiers, [usages]); ("abs", buttons, x, y, wheel);
    # ("rel", buttons, dx, dy, wheel). A HID packet whose signature or checksum does not check out is in `bad_hid` instead.
    hid: list[tuple[Any, ...]] = field(default_factory=list)
    bad_hid: list[str] = field(default_factory=list)
    token_asks: int = 0  # how often the console pass of its web page was asked for, signed in or not
    # Every session is a first one (the controller answers the pass with 2, and attaches its keyboard and mouse only
    # then): a report that comes sooner than `hid_settles` seconds after the pass is lost, as on a real board.
    first_session: bool = False
    hid_settles: float = 0.0
    hid_lost: int = 0  # reports that came too soon and were lost
    says: list[tuple[int, int, bytes]] = field(default_factory=list)  # put in by a test: what the console says next (kind, number, body)
    # OpenBMC's console (layout "openbmc"): the WebSocket /kvm/0, signed in as every request of bmcweb's, which hands
    # it on to obmc-ikvm, a VNC server (tests/fake_vnc.py: pushing frames at its own pace, no password). None: no
    # obmc-ikvm runs, and bmcweb closes the console at once (as on a controller whose video engine is missing).
    kvm_screen: Any = None
    kvm_seats: int = 4  # bmcweb's most at a time
    kvm_refuses: bool = False  # the console is refused to this account (401) while its session is good for the rest
    kvm_open: int = 0
    kvm_upgrades: list[str] = field(default_factory=list)  # how each upgrade was signed in: "token", "cookie", or "nothing"
    kvm_open_at_sign_out: list[int] = field(default_factory=list)  # consoles still open at each sign-out
    graphical_console: bool = True  # (openbmc layout) whether its manager announces the console (False: as romulus's latest build in QEMU)
    manager_fails: int = 0  # its manager answers so many reads with 503 first (one of its moments)
    manager_reads: int = 0
    # Every request to an address of AMI's web page (/api/...), whatever the layout, as "POST /api/session". bmcweb (layout
    # "openbmc") has none of them, and answers every request that is not signed in with 401 before it looks for the path.
    web_asked: list[str] = field(default_factory=list)


def make_fake_bmc(state: BmcState) -> FastAPI:
    app = FastAPI()
    v1 = "/redfish/v1"

    def names() -> tuple[str, str, str]:
        """What this controller calls the computer, the chassis and itself."""
        return NAMES[state.layout]

    def system_path() -> str:
        return state.system_link or f"{v1}/Systems/{names()[0]}"

    def not_there() -> Response:
        return JSONResponse({"error": {"code": "Base.1.5.0.ResourceMissingAtURI", "message": "No such resource"}}, status_code=404)

    @app.middleware("http")
    async def signed_in(request: Request, call_next: Any) -> Any:
        path = request.url.path.rstrip("/")
        if time.monotonic() < max(state.away_until, state.unwell_until):  # restarting, or busy with itself: there, and not ready
            # (Some controllers say so with HTTP 200 and an error body where the resource belongs.)
            said: Any = "Service Unavailable" if state.errors_in_200 == "text" else {"message": "Service Unavailable"}
            return JSONResponse({"error": said}, status_code=200 if state.errors_in_200 else 503)
        open_to_all = path in (v1, "/viewer.html") or (path == f"{v1}/SessionService/Sessions" and request.method == "POST")
        if path == v1 and request.headers.get("x-auth-token") not in state.tokens:
            state.roots_unsigned += 1
        if path.startswith("/api/"):
            state.web_asked.append(f"{request.method} {path}")
            # The web page's own requests: they have a sign-in of their own (AMI's). bmcweb asks every request for its session first.
            open_to_all = open_to_all or state.layout != "openbmc"
        if not open_to_all:
            if request.headers.get("x-auth-token") not in state.tokens:
                return JSONResponse({"error": {"code": "Base.1.5.0.NoValidSession", "message": "Sign in first"}}, status_code=401)
            state.requests.append(f"{request.method} {path}")
        return await call_next(request)

    @app.get(v1)
    @app.get(v1 + "/")
    async def root() -> dict[str, Any]:
        if state.root_takes:
            await asyncio.sleep(state.root_takes)
        # (bmcweb's root names no product and no vendor: OpenBMC is known by its controller, not here.)
        made_by = {"Product": "AMI Redfish Server", "Vendor": "AMI"} if state.layout == "ami" else {"UpdateService": {"@odata.id": f"{v1}/UpdateService"}}
        return {
            "RedfishVersion": "1.15.1", **made_by, **({"UUID": state.root_uuid} if state.root_uuid is not None else {}),
            "Systems": {"@odata.id": f"{v1}/Systems"}, "Chassis": {"@odata.id": f"{v1}/Chassis"},
            "Managers": {"@odata.id": f"{v1}/Managers"}, "Links": {"Sessions": {"@odata.id": f"{v1}/SessionService/Sessions"}},
        }  # fmt: skip

    @app.post(v1 + "/SessionService/Sessions")
    async def sign_in(request: Request) -> Response:
        body = await request.json()
        state.logins += 1
        if state.login_status != 201:  # every session it has is given out, say: nothing to do with the password
            return JSONResponse({"error": {"message": "No more sessions"}}, status_code=state.login_status)
        if body.get("UserName") != state.username or body.get("Password") != state.password:
            return JSONResponse({"error": {"message": "Invalid credentials"}}, status_code=401)
        token, session = secrets.token_hex(16), secrets.token_hex(4)
        state.tokens[token] = session
        return JSONResponse({"Id": session}, status_code=201, headers={"X-Auth-Token": token, "Location": f"{v1}/SessionService/Sessions/{session}"})

    @app.delete(v1 + "/SessionService/Sessions/{session}")
    async def sign_out(session: str) -> Response:
        state.kvm_open_at_sign_out.append(state.kvm_open)
        for token, known in list(state.tokens.items()):
            if known == session:
                del state.tokens[token]
                state.signed_out += 1
        if state.dawdles:

            async def a_little_at_a_time() -> AsyncIterator[bytes]:
                for _ in range(100):  # ten seconds of it, never long enough between two pieces to be given up on
                    yield b" "
                    await asyncio.sleep(0.1)

            return StreamingResponse(a_little_at_a_time(), media_type="application/json")
        return Response(status_code=204)

    @app.get(v1 + "/Systems")
    async def systems() -> dict[str, Any]:
        return {"Members": [{"@odata.id": system_path()}], "Members@odata.count": 1}

    def shown_mark() -> str:
        return ("W/" if state.strict_marks else "") + state.mark

    @app.get(v1 + "/Systems/{name}")
    async def system(name: str) -> Response:
        if name != names()[0]:
            return not_there()
        if state.system_unwell:
            return JSONResponse({"error": {"message": "Service Unavailable"}}, status_code=503)
        if time.monotonic() < state.reads_busy_until:
            await asyncio.sleep(state.reads_busy_until - time.monotonic())  # (busy after a change: answered after the wall stopped waiting)
        if state.power == "Off" and state.back_on_at and time.monotonic() >= state.back_on_at:
            state.power, state.back_on_at = "On", 0.0
        while state.later and time.monotonic() >= state.later[0][0]:
            state.led = state.later.pop(0)[1]
        if state.power_later and time.monotonic() >= state.power_later[0]:
            state.power, state.power_later = state.power_later[1], None
        light: dict[str, Any] = {"IndicatorLED": state.led, "IndicatorLED@Redfish.AllowableValues": state.led_kinds}
        if state.locating is not None or state.layout == "openbmc":  # (bmcweb has retired IndicatorLED)
            light = {"LocationIndicatorActive": state.locating}
        return JSONResponse(headers={"ETag": shown_mark()}, content={
            **light, "@odata.etag": shown_mark(),
            "Id": name, "Model": state.model, "Manufacturer": state.manufacturer, "HostName": state.hostname,
            "PowerState": state.power, "BiosVersion": "F12", "SerialNumber": "SN0000000000", "UUID": state.uuid,
            "Status": {"Health": "OK", "HealthRollup": state.health, "State": "Enabled"},
            "ProcessorSummary": {"Count": 2, "Model": PROCESSOR},
            "MemorySummary": {"TotalSystemMemoryGiB": 256},
            "Boot": {
                "BootSourceOverrideEnabled": state.boot_override[0],
                "BootSourceOverrideTarget": state.boot_override[1],
                **({"BootSourceOverrideTarget@Redfish.AllowableValues": state.boot_targets} if state.boot_targets is not None else {}),
            },
            # Which chassis is the computer's own, and which controller manages it: the standard's way of saying it.
            "Links": {
                "Chassis": [{"@odata.id": state.chassis_claimed or f"{v1}/Chassis/{names()[1]}"}],
                "ManagedBy": [{"@odata.id": f"{v1}/Managers/{names()[2]}"}],
            },
            "Actions": {"#ComputerSystem.Reset": {
                "@Redfish.ActionInfo": f"{v1}/Systems/{name}/ResetActionInfo",
                "target": f"{v1}/Systems/{name}/Actions/ComputerSystem.Reset",
            }},
        })  # fmt: skip

    @app.patch(v1 + "/Systems/{name}")
    async def change_system(name: str, request: Request) -> Response:
        if name != names()[0]:
            return not_there()
        change = await request.json()
        if "Boot" in change and state.override_meanwhile is not None:
            # Another tool, between the wall's look and its change: the override is its, and the state has a new mark.
            state.boot_override, state.override_meanwhile = state.override_meanwhile, None
            state.mark = f'"{int(state.mark.strip(chr(34))) + 1}"'
        if "Boot" in change and state.power_meanwhile is not None:
            state.power, state.power_meanwhile = state.power_meanwhile, None  # (shutting down, say, as the change comes)
            state.mark = f'"{int(state.mark.strip(chr(34))) + 1}"'
        # As AMI's controllers do it: no change without being shown the state it was decided on.
        shown = request.headers.get("if-match")
        if shown is None:
            return JSONResponse({"error": {"message": "If-Match or If-None-Match header is required"}}, status_code=428)
        if shown != "*" and (shown != state.mark or state.strict_marks):
            return JSONResponse({"error": {"message": "The resource changed, or the mark is not a strong one"}}, status_code=412)
        if state.light_status is not None and ("IndicatorLED" in change or "LocationIndicatorActive" in change):
            return JSONResponse({"error": {"message": "Internal error"}}, status_code=state.light_status)
        state.changes.append(change)
        if "IndicatorLED" in change:
            if not isinstance(state.led_kinds, list) or change["IndicatorLED"] not in state.led_kinds:
                return JSONResponse({"error": {"message": "Not a value this light can take"}}, status_code=400)
            due = time.monotonic() + state.slow_to_act
            state.later = [(due, change["IndicatorLED"])]
            if change["IndicatorLED"] == "Blinking" and state.blink_lasts is not None:
                state.later.append((due + state.blink_lasts, "Off"))
            if not state.slow_to_act:
                state.led = state.later.pop(0)[1]
        if "LocationIndicatorActive" in change:
            state.locating = change["LocationIndicatorActive"]
        if "Boot" in change:
            boot = change["Boot"] if isinstance(change["Boot"], dict) else {}
            target = boot.get("BootSourceOverrideTarget")
            if state.boot_targets is not None and target is not None and target not in state.boot_targets:
                return JSONResponse({"error": {"message": f"BootSourceOverrideTarget {target} is not allowed"}}, status_code=400)
            clearing = boot.get("BootSourceOverrideEnabled") == "Disabled"
            if state.clear_kept if clearing else state.boot_kept:
                if state.boot_partial and not clearing:
                    target = None  # (the target is not taken)
                state.boot_override = (boot.get("BootSourceOverrideEnabled", state.boot_override[0]), target or state.boot_override[1])
            if state.override_after is not None:
                state.boot_override, state.override_after = state.override_after, None  # (another tool, right after)
            state.mark = f'"{int(state.mark.strip(chr(34))) + 1}"'
            if state.power_after_change is not None:
                state.power, state.power_after_change = state.power_after_change, None  # (switched on at its button, say, meanwhile)
            if state.busy_after_boot_change:
                state.reads_busy_until = time.monotonic() + state.busy_after_boot_change
            if state.slow_boot_changes > 0:
                state.slow_boot_changes -= 1
                await asyncio.sleep(state.slow_boot_by)  # (made, and answered after the wall stopped waiting)
            if state.boot_moved_once:
                state.boot_moved_once = False
                return Response(status_code=307, headers={"Location": "http:x"})  # (made, and an answer that cannot be read)
            return Response(status_code=state.clear_status if clearing and state.clear_status is not None else state.boot_status)
        state.mark = f'"{int(state.mark.strip(chr(34))) + 1}"'
        return Response(status_code=202)  # "accepted", which is what the real one says

    @app.get(v1 + "/Systems/{name}/ResetActionInfo")
    async def reset_info(name: str) -> Response:
        if name != names()[0]:
            return not_there()
        return JSONResponse({"Parameters": [{"Name": "ResetType", "Required": True, "AllowableValues": state.offered}]})

    @app.post(v1 + "/Systems/{name}/Actions/ComputerSystem.Reset")
    async def reset(name: str, request: Request) -> Response:
        if name != names()[0]:
            return not_there()
        kind = (await request.json()).get("ResetType")
        if state.reset_signs_out_once:
            state.reset_signs_out_once = False
            if state.reset_answer_takes:
                await asyncio.sleep(state.reset_answer_takes)
            state.tokens.clear()  # (as a controller that restarted its web service: sign in again, the reset not done)
            return JSONResponse({"error": {"message": "Sign in first"}}, status_code=401)
        if state.reset_status is not None:
            return JSONResponse({"error": {"message": "Internal error"}}, status_code=state.reset_status)
        if kind not in state.offered or state.reset_refused:
            said = {"error": {"@Message.ExtendedInfo": [{"Message": f"The value {kind} for the property ResetType is not in the list of acceptable values."}]}}
            return JSONResponse(said, status_code=400)
        state.actions.append(f"system {kind}")
        dropped = (kind == "GracefulShutdown" and state.ignores_shutdown) or kind in state.drops
        if state.keeps_tasks:
            at = str(len(state.tasks) + 1)
            state.tasks[at] = {
                "Id": at, "Name": "Reset", "TaskState": "Exception" if dropped else "Completed", "TaskStatus": "Critical" if dropped else "OK",
                "Messages": [{"MessageId": "Base.1.5.0.GeneralError", "Message": "The power command could not be carried out."}] if dropped else [],
                "Payload": {"SerialNumber": "SN0000000000"},  # what does not belong in anybody's report
            }  # fmt: skip
            where = f"{v1}/TaskService/Tasks/{at}"
            if dropped:
                return JSONResponse({"@odata.id": where, "Id": at, "TaskState": "New"}, status_code=202, headers={"Location": where})
        if dropped:
            return Response(status_code=202)  # accepted, and that is all that comes of it
        becomes = "Off" if kind in ("ForceOff", "GracefulShutdown") else "On"
        boots = kind != "On" or state.power != "On"  # ("On" to a server that is on is nothing to do: no boot, as a real controller takes it)
        if becomes == "On" and boots and state.boot_override[0] == "Once":
            state.boot_override = ("Disabled", "None")  # a one-time boot override clears when it is booted
        if state.busy_after_reset:
            state.reads_busy_until = time.monotonic() + state.busy_after_reset
        if state.power_takes:
            state.power_later = (time.monotonic() + state.power_takes, becomes)
            return Response(status_code=202)
        state.power = becomes
        if state.power == "Off" and state.comes_back_after is not None:
            state.back_on_at = time.monotonic() + state.comes_back_after
        if state.reset_answer_takes:
            await asyncio.sleep(state.reset_answer_takes)  # (done, and answered late)
        return Response(status_code=204)

    @app.get(v1 + "/TaskService/Tasks/{at}")
    async def task(at: str) -> Response:
        return JSONResponse(state.tasks[at]) if at in state.tasks else Response(status_code=404)

    @app.get(v1 + "/Chassis")
    async def chassis_list() -> dict[str, Any]:
        own = {"@odata.id": f"{v1}/Chassis/{names()[1]}"}
        return {"Members": [{"@odata.id": f"{v1}/Chassis/{ENCLOSURE}"}, own] if state.enclosures_first else [own]}

    @app.get(v1 + "/Chassis/{name}")
    async def chassis(name: str) -> Response:
        where = f"{v1}/Chassis/{name}"
        if name == ENCLOSURE and state.enclosures_first:
            return JSONResponse({"Id": name, "ChassisType": "StorageEnclosure", "Model": "Backplane"})  # no sensors to speak of
        if name != names()[1]:
            return not_there()
        if state.layout == "openbmc":
            sensors = {"ThermalSubsystem": {"@odata.id": f"{where}/ThermalSubsystem"}, "Sensors": {"@odata.id": f"{where}/Sensors"}}
        else:
            sensors = {"Thermal": {"@odata.id": f"{where}/Thermal"}}
        return JSONResponse({"Id": name, "Model": state.model, **sensors})

    fine = {"Health": "OK", "State": "Enabled"}

    def temperatures() -> list[tuple[str, Any, dict[str, Any]]]:
        """(name, reading, status) of every temperature, in whichever shape it is then said."""
        return [
            ("CPU0_TEMP", state.cpu_temperature, {"Health": state.temperature_health, "State": "Enabled"}),
            ("CPU1_TEMP", 55, fine), ("DIMM_A_TEMP", 45, fine), ("M2_TEMP", None, {"State": "Absent"}),
        ]  # fmt: skip

    @app.get(v1 + "/Chassis/{name}/Thermal")
    async def thermal(name: str) -> Response:
        if name != names()[1] or state.layout != "ami":
            return not_there()
        return JSONResponse({
            "Temperatures": [
                {"Name": sensor, "ReadingCelsius": reading, "UpperThresholdCritical": 98, "Status": status}
                for sensor, reading, status in temperatures()
            ],
            "Fans": [
                {"Name": "CPU0_FAN", "Reading": 1650, "ReadingUnits": "RPM", "Status": fine},
                {"Name": "CPU1_FAN", "Reading": 450, "ReadingUnits": "RPM", "Status": {"Health": "Warning", "State": "Enabled"}},
                {"Name": "SYS_FAN5", "Reading": None, "ReadingUnits": "RPM", "Status": {"State": "Absent"}},
            ],
        })  # fmt: skip

    # --- the newer shape of the same sensors (OpenBMC has only this one) ---------------------------------
    # A fan says its speed as a share of its most (Reading), as revolutions (SpeedRPM), or both.
    FANS = {
        "fan_CPU0_FAN": {"Name": "CPU0_FAN", "SpeedPercent": {"SpeedRPM": 1650}, "Status": fine},
        "fan_CPU1_FAN": {"Name": "CPU1_FAN", "SpeedPercent": {"Reading": 18}, "Status": {"Health": "Warning", "State": "Enabled"}},
        "fan_SYS_FAN5": {"Name": "SYS_FAN5", "SpeedPercent": {"SpeedRPM": None}, "Status": {"State": "Absent"}},
    }

    @app.get(v1 + "/Chassis/{name}/ThermalSubsystem")
    async def thermal_subsystem(name: str) -> Response:
        if name != names()[1] or state.layout != "openbmc":
            return not_there()
        where = f"{v1}/Chassis/{name}/ThermalSubsystem"
        return JSONResponse({"Id": "ThermalSubsystem", "Fans": {"@odata.id": f"{where}/Fans"}, "ThermalMetrics": {"@odata.id": f"{where}/ThermalMetrics"}})

    @app.get(v1 + "/Chassis/{name}/ThermalSubsystem/ThermalMetrics")
    async def thermal_metrics(name: str) -> Response:
        if name != names()[1] or state.layout != "openbmc":
            return not_there()
        # As bmcweb says a reading: its value, and where the sensor itself is; no name. The first carries its
        # health as the older shape does (bmcweb's do not; a controller may), so that a reading can be unwell.
        readings = [{"Reading": reading, "DataSourceUri": f"{v1}/Chassis/{name}/Sensors/temperature_{sensor}"} for sensor, reading, _ in temperatures()]
        readings[0]["Status"] = {"Health": state.temperature_health}
        return JSONResponse({"Id": "ThermalMetrics", "TemperatureReadingsCelsius": readings})

    def every_fan() -> dict[str, dict[str, Any]]:
        more = {f"fan_EXTRA_{n}": {"Name": f"EXTRA_{n}", "SpeedPercent": {"SpeedRPM": 1000 + n}, "Status": fine} for n in range(state.more_fans)}
        if more and state.last_fan_unwell:
            more[f"fan_EXTRA_{state.more_fans - 1}"]["Status"] = {"Health": "Warning", "State": "Enabled"}
        return {**FANS, **more}

    @app.get(v1 + "/Chassis/{name}/ThermalSubsystem/Fans")
    async def fans(name: str) -> Response:
        if name != names()[1] or state.layout != "openbmc":
            return not_there()
        members = [{"@odata.id": f"{v1}/Chassis/{name}/ThermalSubsystem/Fans/{fan}"} for fan in every_fan()]
        if state.fan_claimed:
            members.append({"@odata.id": state.fan_claimed})
        return JSONResponse({"Members": members, "Members@odata.count": len(members)})

    @app.get(v1 + "/Chassis/{name}/ThermalSubsystem/Fans/{fan}")
    async def one_fan(name: str, fan: str) -> Response:
        known = every_fan()
        if name != names()[1] or state.layout != "openbmc" or fan not in known:
            return not_there()
        if state.fan_takes:
            await asyncio.sleep(state.fan_takes)
        return JSONResponse({"Id": fan, **known[fan]})

    @app.get(v1 + "/Managers")
    async def managers() -> dict[str, Any]:
        return {"Members": [{"@odata.id": f"{v1}/Managers/{names()[2]}"}]}

    @app.get("/viewer.html")
    async def viewer(request: Request) -> Response:
        # Where the real thing has its console. This one says whether the pass it was shown is one it made out.
        known = request.url.query in state.passes
        said = "the pass is one this controller made out" if known else "no pass this controller knows"
        return Response(f"<!doctype html><title>Console (stand-in)</title><p>The console of a stand-in server: {said}.</p>", media_type="text/html")

    @app.get(v1 + "/Managers/{name}/IKVM")
    async def console(name: str) -> Response:
        if name != names()[2] or state.layout != "ami":
            return not_there()
        made = secrets.token_hex(8)  # a new one every time it is asked, as on the real thing
        state.passes.append(made)
        way_in = str(state.console).replace("{pass}", made) if WAY_IN is UNSET else WAY_IN
        return JSONResponse({"Access": "One time", "Interface": state.console_kind, "URI": way_in})

    @app.get(v1 + "/Managers/{name}")
    async def manager(name: str) -> Response:
        if name != names()[2]:
            return not_there()
        state.manager_reads += 1
        if state.manager_fails > 0:
            state.manager_fails -= 1
            return JSONResponse({"error": {"message": "Service Unavailable"}}, status_code=503)
        where = f"{v1}/Managers/{name}"
        entry = state.root_uuid if state.entry_uuid is UNSET else state.entry_uuid
        hosts = {"ServiceEntryPointUUID": entry} if entry is not None else {}
        if state.layout == "ami" and state.root_uuid is not None:
            hosts["UUID"] = state.root_uuid  # (a real AMI board's manager names itself by its service's number, too)
        if state.layout == "openbmc":
            # As bmcweb describes itself: the model is the firmware's name, and the console is announced here. Its firmware's
            # version, and the image it runs, are said where bmcweb knows which of its images runs (`manager_says`).
            running = next((each for each in firmware_images() if each[1] == "BMC" and each[2] == "Enabled"), None)
            said: dict[str, Any] = {}
            if state.manager_says == "both":
                said["FirmwareVersion"] = state.firmware
            if state.manager_says in ("both", "image") and running is not None:
                said["Links"] = {"ActiveSoftwareImage": {"@odata.id": f"{v1}/UpdateService/FirmwareInventory/{running[0]}"}}
            return JSONResponse({
                "Id": name, "Name": "OpenBmc Manager", "Model": "OpenBmc", "ManagerType": "BMC", **said, **hosts,
                **({"GraphicalConsole": {"ServiceEnabled": True, "MaxConcurrentSessions": 4, "ConnectTypesSupported": ["KVMIP"]}} if state.graphical_console else {}),
                "Actions": {"#Manager.Reset": {"target": f"{where}/Actions/Manager.Reset", "@Redfish.ActionInfo": f"{where}/ResetActionInfo"}},
            })  # fmt: skip
        return JSONResponse({
            **({"IKVM": {"@odata.id": f"{where}/IKVM"}} if state.console is not None else {}),
            "Id": name, "ManagerType": "BMC", "FirmwareVersion": state.firmware, **hosts,
            "Actions": {"#Manager.Reset": {"target": f"{where}/Actions/Manager.Reset", "ResetType@Redfish.AllowableValues": ["ForceRestart"]}},
        })  # fmt: skip

    def firmware_images() -> list[tuple[str, str, str, object]]:
        return state.images if state.images is not None else [("3d6f0a11", "Host", "Enabled", "host-2.13"), ("7ed25e88", "BMC", "Enabled", state.firmware)]

    @app.get(v1 + "/UpdateService")
    async def update_service() -> Response:
        if state.layout != "openbmc":
            return not_there()
        return JSONResponse({
            "@odata.id": f"{v1}/UpdateService", "@odata.type": "#UpdateService.v1_11_1.UpdateService", "Id": "UpdateService",
            "Name": "Update Service", "ServiceEnabled": True, "FirmwareInventory": {"@odata.id": f"{v1}/UpdateService/FirmwareInventory"},
        })  # fmt: skip

    @app.get(v1 + "/UpdateService/FirmwareInventory")
    async def firmware_inventory() -> Response:
        if state.layout != "openbmc":
            return not_there()
        members = [{"@odata.id": f"{v1}/UpdateService/FirmwareInventory/{each[0]}"} for each in firmware_images()] + state.inventory_more
        return JSONResponse({
            "@odata.id": f"{v1}/UpdateService/FirmwareInventory", "@odata.type": "#SoftwareInventoryCollection.SoftwareInventoryCollection",
            "Members": members, "Members@odata.count": len(members), "Name": "Software Inventory Collection", **state.inventory_says,
        })  # fmt: skip

    @app.get(v1 + "/UpdateService/FirmwareInventory/{image}")
    async def firmware_image(image: str) -> Response:
        """One piece of software, as bmcweb describes it (read from a romulus build in QEMU, and from bmcweb's update_service.hpp)."""
        found = next((each for each in firmware_images() if each[0] == image), None)
        if state.layout != "openbmc" or found is None:
            return not_there()
        _, purpose, active, version = found
        if purpose == "BMC":
            related: object = state.image_link if state.image_link is not None else f"{v1}/Managers/{names()[2]}"
        else:
            related = f"{v1}/Systems/{names()[0]}/Bios"
        return JSONResponse({
            "@odata.id": f"{v1}/UpdateService/FirmwareInventory/{image}", "@odata.type": "#SoftwareInventory.v1_1_0.SoftwareInventory",
            "Description": f"{purpose} image", "Id": image, "Name": "Software Inventory",
            "RelatedItem": [{"@odata.id": related}], "RelatedItem@odata.count": 1,
            "Status": {"Health": "OK", "HealthRollup": "OK", "State": active}, "Updateable": False, "Version": version,
        })  # fmt: skip

    @app.get(v1 + "/Managers/{name}/ResetActionInfo")
    async def manager_reset_info(name: str) -> Response:
        if name != names()[2] or state.layout != "openbmc":
            return not_there()
        return JSONResponse({"Parameters": [{"Name": "ResetType", "Required": True, "AllowableValues": ["GracefulRestart", "ForceRestart"]}]})

    @app.post(v1 + "/Managers/{name}/Actions/Manager.Reset")
    async def manager_reset(name: str, request: Request) -> Response:
        if name != names()[2]:
            return not_there()
        if state.manager_reset_status is not None:
            return JSONResponse({"error": {"message": "Internal error"}}, status_code=state.manager_reset_status)
        state.actions.append(f"controller {(await request.json()).get('ResetType')}")
        if state.restart_takes:
            state.away_until = time.monotonic() + state.restart_takes
            state.tokens.clear()
        return Response(status_code=204)

    # --- the web page's own sign-in, and its console ---------------------------------------------------------

    def web_session(request: Request) -> str | None:
        cookie = request.cookies.get("QSESSIONID", "")
        return cookie if cookie in state.web_sessions and request.headers.get("x-csrftoken") == state.web_sessions[cookie] else None

    NOT_THERE = JSONResponse({"error": "Not Found"}, status_code=404)

    @app.post("/api/session")
    async def web_sign_in(request: Request) -> Response:
        if not state.own_console:
            return NOT_THERE
        form = {name: values[0] for name, values in parse_qs((await request.body()).decode()).items()}
        state.web_logins += 1
        if form.get("username") != state.username or form.get("password") != state.password:
            return JSONResponse({"cc": 7, "error": "Invalid Authentication"}, status_code=401)
        cookie, token = secrets.token_hex(12), secrets.token_urlsafe(6)
        state.web_sessions[cookie] = token
        if state.sign_in_takes:
            await asyncio.sleep(state.sign_in_takes)
        answer = JSONResponse({"ok": 0, "privilege": 4, "CSRFToken": token})
        answer.set_cookie("QSESSIONID", cookie)
        return answer

    @app.delete("/api/session")
    async def web_sign_out(request: Request) -> Response:
        if not state.own_console:
            return NOT_THERE
        cookie = web_session(request)
        if cookie is None:
            return JSONResponse({"cc": 7, "error": "Invalid Authentication"}, status_code=401)
        del state.web_sessions[cookie]
        state.web_signed_out += 1
        return JSONResponse({"ok": 0})

    @app.get("/api/configuration/project")
    async def what_it_can_do(request: Request) -> Response:
        if not state.own_console or not state.says_what_it_can:
            return NOT_THERE
        if web_session(request) is None:
            return JSONResponse({"cc": 7, "error": "Invalid Authentication"}, status_code=401)
        return JSONResponse([{"id": 1, "feature": "KVM"}, {"id": 2, "feature": "VMEDIA"}, *([{"id": 3, "feature": ami.RECONNECTS}] if state.reconnects else [])])

    @app.get("/api/kvm/token")
    async def console_pass(request: Request) -> Response:
        state.token_asks += 1
        if not state.own_console:
            return NOT_THERE
        if web_session(request) is None:
            return JSONResponse({"cc": 7, "error": "Invalid Authentication"}, status_code=401)
        made = secrets.token_hex(16)
        state.console_passes.add(made)
        dark = 1 if state.monitor_goes_dark else 0
        return JSONResponse({
            "client_ip": "127.0.0.1", "token": made, "session": secrets.token_hex(8), "server_ip": "127.0.0.1",
            "kvm_service_status": 1, "automatic_off": dark, "local_monitor_off": dark, "power_save_mode": 0,
        })  # fmt: skip

    def pieces(frame: Any) -> list[bytes]:
        """A frame as the console sends it: its facts with the first piece, and its data cut up."""
        header, data = frame.header, frame.data
        facts = bytearray(86)
        facts[4:6], facts[6:8] = header.width.to_bytes(2, "little"), header.height.to_bytes(2, "little")
        facts[13:15], facts[15:17] = header.grid_width.to_bytes(2, "little"), header.grid_height.to_bytes(2, "little")
        facts[44], facts[45], facts[47], facts[55] = header.strength, int(header.luma_for_colour), header.correction_strength, int(header.half_colour)
        facts[69:72] = len(data).to_bytes(3, "little")
        cut = [data[at : at + state.piece] for at in range(0, len(data), state.piece)] or [b""]
        return [ami.message(ami.VIDEO, 0, number.to_bytes(2, "little") + (bytes(facts) if not number else b"") + part) for number, part in enumerate(cut)]

    def decode_hid(body: bytes) -> tuple[Any, ...] | str:
        """A keyboard or mouse report the console was sent, decoded; a reason, where the packet does not check out.

        The layout is the controller's (see qkvm/ami.py): an eight-byte "IUSB" signature, then a thirty-two byte
        header the controller checks sums to zero, then one byte of report length, then the USB HID report.
        """
        if len(body) < 33 or body[:8] != b"IUSB    ":
            return "no IUSB signature"
        if sum(body[:32]) & 0xFF != 0:
            return "the header does not sum to zero"
        report = body[33:]
        if body[32] != len(report):
            return "the report length byte is wrong"
        if tuple(body[8:11]) != (1, 0, 32) or int.from_bytes(body[12:16], "little") != len(report) + 1:
            return "the header's version, length or data length is wrong"
        dev_type = body[17]
        if (body[19], body[20]) != (0x80, 2) or (body[18], body[21]) != {0x30: (0x10, 0), 0x31: (0x20, 1)}.get(dev_type):
            return "the header's direction, protocol, device or interface is wrong"
        if dev_type == 0x30:  # a keyboard
            if len(report) != 8:
                return "a keyboard report that is not eight bytes"
            return ("key", report[0], [usage for usage in report[2:8] if usage])
        if dev_type == 0x31:  # a mouse
            if len(report) == 6:
                buttons, x, y, wheel = struct.unpack("<BHHb", report)
                return ("abs", buttons, x, y, wheel)
            if len(report) == 4:
                buttons, dx, dy, wheel = struct.unpack("<Bbbb", report)
                return ("rel", buttons, dx, dy, wheel)
            return "a mouse report of an unexpected size"
        return f"a report for an unknown device ({dev_type})"

    @app.websocket("/kvm")
    async def console_stream(websocket: WebSocket) -> None:
        if not state.own_console:
            await websocket.close()
            return
        await websocket.accept(subprotocol="binary")
        if state.watching >= state.seats:
            await websocket.send_bytes(ami.message(ami.TOO_MANY))
            await websocket.close()
            return
        state.watching += 1
        arriving, sent, complete, waiting, asked_at = ami.Messages(), False, False, False, 0.0
        passed_at = float("inf")  # when the pass was taken
        began = time.monotonic()
        try:
            await websocket.send_bytes(ami.message(ami.ALLOWED, 2))
            while True:
                if state.session_lasts and time.monotonic() - began > state.session_lasts:
                    await websocket.send_bytes(ami.message(ami.STOP, 9))  # "the session's time is up"
                    await websocket.close()
                    return
                while sent and state.asks:
                    kind, who = state.asks.pop(0)
                    asked_at = time.monotonic()
                    await websocket.send_bytes(ami.message(kind, ami.ASKED, who))
                while sent and state.says:
                    kind, number, body = state.says.pop(0)
                    await websocket.send_bytes(ami.message(kind, number, body))
                try:
                    data = await asyncio.wait_for(websocket.receive_bytes(), timeout=0.3)
                except TimeoutError:
                    await websocket.send_bytes(ami.message(ami.STILL_THERE))
                    continue
                for one in arriving.feed(data):
                    state.heard.append((one.kind, one.status, len(one.body)))
                    if one.kind == ami.COMPLETE:
                        complete = True
                    elif one.kind == ami.STOP:
                        await websocket.close()
                        return
                    elif one.kind == ami.PASS:
                        if state.reconnects and not complete:
                            await websocket.close()  # not how this firmware is greeted
                            return
                        shown = one.body[1:130].split(b"\0", 1)[0].decode()
                        good = shown in state.console_passes
                        if good:
                            # Who else is there is said before the word on the pass, as a real board says it.
                            if state.holder_returning:
                                await websocket.send_bytes(ami.message(ami.SHARING, ami.ANSWERED | ami.HOLDER_RETURNING << 8))
                            elif state.held_by and state.shut_out:
                                waiting = True
                                await websocket.send_bytes(ami.message(ami.SHARING, ami.ANSWERED | ami.SHUT_OUT << 8, state.held_by))
                            elif state.held_by:
                                waiting = True
                                await websocket.send_bytes(ami.message(ami.SHARING, ami.WAITING, state.held_by))
                        await websocket.send_bytes(ami.message(ami.PASS_SEEN, ami.FIRST_SESSION if state.first_session else 0, bytes([1 if good else 0, 0])))
                        passed_at = time.monotonic()
                        if not good:
                            await websocket.close()
                            return
                        state.console_passes.discard(shown)  # a pass is for one session
                        alone = not (state.held_by or state.holder_returning)
                        await websocket.send_bytes(ami.message(ami.LICENCE) + ami.message(ami.OTHERS, 0, bytes(134 if alone else 268)))
                        await websocket.send_bytes(ami.message(ami.MOUSE_MODE, 0, bytes([state.mouse_mode])))  # which mouse the server shows
                        if alone:
                            await websocket.send_bytes(ami.message(ami.NEXT_HOLDER, 6))  # "the console is yours": a real board, to the only one there
                    elif one.kind == ami.HID:
                        decoded = decode_hid(one.body)
                        if not isinstance(decoded, str) and state.first_session and time.monotonic() - passed_at < state.hid_settles:
                            state.hid_lost += 1  # (the keyboard and mouse are not attached yet)
                            continue
                        (state.bad_hid if isinstance(decoded, str) else state.hid).append(decoded)
                    elif one.kind in (ami.SHARING, ami.NEXT_HOLDER):
                        state.answers.append((one.kind, one.status, one.body, time.monotonic() - asked_at))
                    elif one.kind == ami.RESUME and state.begins_with_nothing and not waiting:
                        if state.screen:
                            nothing = type(state.screen[0])(state.screen[0].header.width, state.screen[0].header.height)
                            for part in pieces(nothing):
                                await websocket.send_bytes(part)
                    elif one.kind in (ami.RESUME, ami.FULL_SCREEN) and not sent and not waiting:
                        sent = True
                        if state.begins_with_nothing:
                            await asyncio.sleep(0.6)
                        for frame in state.screen:
                            for part in pieces(frame):
                                await websocket.send_bytes(part)
        except WebSocketDisconnect:
            pass
        finally:
            state.watching -= 1

    # --- OpenBMC's console (bmcweb's /kvm/0, handed on to obmc-ikvm) ---------------------------------------------

    @app.websocket("/kvm/0")
    async def openbmc_console(websocket: WebSocket) -> None:
        if state.layout != "openbmc":
            await websocket.close()
            return
        # Signed in as every request of bmcweb's: the session's token in its header (or its web page's cookie, which
        # this stand-in has not got). Without one: 401, and nothing else is said.
        token = websocket.headers.get("x-auth-token")
        state.kvm_upgrades.append("token" if token else "cookie" if websocket.headers.get("cookie") else "nothing")
        if token not in state.tokens or state.kvm_refuses:
            try:
                await websocket.send_denial_response(Response(status_code=401))
            except RuntimeError:
                await websocket.close(code=1008)
            return
        await websocket.accept()
        if state.kvm_open >= state.kvm_seats:
            await websocket.close(reason="Max sessions are already connected")
            return
        if state.kvm_screen is None:
            await websocket.close(reason="Error in connecting to KVM port")
            return
        state.kvm_open += 1
        try:
            await Behind(state.kvm_screen).serve(websocket, 50 * 1024)  # (bmcweb hands obmc-ikvm's bytes on 50 KB at a time)
        finally:
            state.kvm_open -= 1

    return app


class FakeBmc:
    """Runs make_fake_bmc() on a localhost port in a background thread."""

    def __init__(self, state: BmcState | None = None, port: int = 0, tls_dir: Path | None = None) -> None:
        """`tls_dir`: serve HTTPS with the certificate kept in that folder (two that are given one folder show one certificate)."""
        self.state = state or BmcState()
        self._sock = local_socket(port)
        self.port: int = self._sock.getsockname()[1]
        tls = {}
        if tls_dir is not None:
            cert, key = make_device_certificate(tls_dir)
            tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        self._server = uvicorn.Server(uvicorn.Config(make_fake_bmc(self.state), log_level="error", access_log=False, **tls))
        self._serving = ServerThread("fake controller", lambda: self._server.run(sockets=[self._sock]), lambda: self._server.started)
        self._thread = self._serving.thread

    def start(self) -> FakeBmc:
        self._serving.start()
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
