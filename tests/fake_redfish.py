"""A stand-in for a server's management controller: as much of Redfish as the wall asks for.

Laid out the way AMI MegaRAC lays it out (as read from an ASRock Rack and a Gigabyte board),
which is one computer, one chassis and one controller, each called "Self".

It also has what such a controller has besides Redfish: the sign-in of its own web page, and the
console that page opens, which sends the server's screen (see qkvm/ami.py).
"""

from __future__ import annotations

import asyncio
import secrets
import threading
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
from tests import local_socket
from tests.fake_kvm import make_device_certificate

PROCESSOR = "Intel Xeon Silver 4410Y"
UNSET = object()
WAY_IN: object = UNSET  # set by a test: what the controller answers, word for word, as the way into its console

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
    firmware: object = "1.42.0"
    cpu_temperature: object = 61
    offered: list[str] = field(default_factory=lambda: ["On", "ForceOff", "GracefulShutdown", "ForceRestart"])
    system_link: str = "/redfish/v1/Systems/Self"  # what the controller claims its computer is called
    dawdles: bool = False  # answers a sign-out a byte at a time
    console: object = "/viewer.html?{pass}"  # what it hands out as the way into its console; None: it has none
    console_kind: str = "HTML 5"
    passes: list[str] = field(default_factory=list)  # the passes to the console it made out
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


def make_fake_bmc(state: BmcState) -> FastAPI:
    app = FastAPI()
    v1 = "/redfish/v1"

    @app.middleware("http")
    async def signed_in(request: Request, call_next: Any) -> Any:
        path = request.url.path.rstrip("/")
        if time.monotonic() < max(state.away_until, state.unwell_until):  # restarting, or busy with itself: there, and not ready
            return JSONResponse({"error": {"message": "Service Unavailable"}}, status_code=503)
        open_to_all = path in (v1, "/viewer.html") or (path == f"{v1}/SessionService/Sessions" and request.method == "POST")
        open_to_all = open_to_all or path.startswith("/api/")  # the web page's own requests: they have a sign-in of their own
        if not open_to_all:
            if request.headers.get("x-auth-token") not in state.tokens:
                return JSONResponse({"error": {"code": "Base.1.5.0.NoValidSession", "message": "Sign in first"}}, status_code=401)
            state.requests.append(f"{request.method} {path}")
        return await call_next(request)

    @app.get(v1)
    @app.get(v1 + "/")
    async def root() -> dict[str, Any]:
        return {
            "RedfishVersion": "1.15.1", "Product": "AMI Redfish Server", "Vendor": "AMI",
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
        return {"Members": [{"@odata.id": state.system_link}], "Members@odata.count": 1}

    def shown_mark() -> str:
        return ("W/" if state.strict_marks else "") + state.mark

    @app.get(v1 + "/Systems/Self")
    async def system() -> JSONResponse:
        if state.power == "Off" and state.back_on_at and time.monotonic() >= state.back_on_at:
            state.power, state.back_on_at = "On", 0.0
        while state.later and time.monotonic() >= state.later[0][0]:
            state.led = state.later.pop(0)[1]
        if state.power_later and time.monotonic() >= state.power_later[0]:
            state.power, state.power_later = state.power_later[1], None
        light: dict[str, Any] = {"IndicatorLED": state.led, "IndicatorLED@Redfish.AllowableValues": state.led_kinds}
        if state.locating is not None:
            light = {"LocationIndicatorActive": state.locating}
        return JSONResponse(headers={"ETag": shown_mark()}, content={
            **light, "@odata.etag": shown_mark(),
            "Id": "Self", "Model": state.model, "Manufacturer": state.manufacturer, "HostName": state.hostname,
            "PowerState": state.power, "BiosVersion": "F12", "SerialNumber": "SN0000000000", "UUID": state.uuid,
            "Status": {"Health": "OK", "HealthRollup": state.health, "State": "Enabled"},
            "ProcessorSummary": {"Count": 2, "Model": PROCESSOR},
            "MemorySummary": {"TotalSystemMemoryGiB": 256},
            "Actions": {"#ComputerSystem.Reset": {
                "@Redfish.ActionInfo": f"{v1}/Systems/Self/ResetActionInfo",
                "target": f"{v1}/Systems/Self/Actions/ComputerSystem.Reset",
            }},
        })  # fmt: skip

    @app.patch(v1 + "/Systems/Self")
    async def change_system(request: Request) -> Response:
        # As AMI's controllers do it: no change without being shown the state it was decided on.
        shown = request.headers.get("if-match")
        if shown is None:
            return JSONResponse({"error": {"message": "If-Match or If-None-Match header is required"}}, status_code=428)
        if shown != "*" and (shown != state.mark or state.strict_marks):
            return JSONResponse({"error": {"message": "The resource changed, or the mark is not a strong one"}}, status_code=412)
        change = await request.json()
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
        state.mark = f'"{int(state.mark.strip(chr(34))) + 1}"'
        return Response(status_code=202)  # "accepted", which is what the real one says

    @app.get(v1 + "/Systems/Self/ResetActionInfo")
    async def reset_info() -> dict[str, Any]:
        return {"Parameters": [{"Name": "ResetType", "Required": True, "AllowableValues": state.offered}]}

    @app.post(v1 + "/Systems/Self/Actions/ComputerSystem.Reset")
    async def reset(request: Request) -> Response:
        kind = (await request.json()).get("ResetType")
        if kind not in state.offered:
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
        if state.power_takes:
            state.power_later = (time.monotonic() + state.power_takes, becomes)
            return Response(status_code=202)
        state.power = becomes
        if state.power == "Off" and state.comes_back_after is not None:
            state.back_on_at = time.monotonic() + state.comes_back_after
        return Response(status_code=204)

    @app.get(v1 + "/TaskService/Tasks/{at}")
    async def task(at: str) -> Response:
        return JSONResponse(state.tasks[at]) if at in state.tasks else Response(status_code=404)

    @app.get(v1 + "/Chassis")
    async def chassis_list() -> dict[str, Any]:
        return {"Members": [{"@odata.id": f"{v1}/Chassis/Self"}]}

    @app.get(v1 + "/Chassis/Self")
    async def chassis() -> dict[str, Any]:
        return {"Id": "Self", "Model": state.model, "Thermal": {"@odata.id": f"{v1}/Chassis/Self/Thermal"}}

    @app.get(v1 + "/Chassis/Self/Thermal")
    async def thermal() -> dict[str, Any]:
        fine = {"Health": "OK", "State": "Enabled"}
        return {
            "Temperatures": [
                {"Name": "CPU0_TEMP", "ReadingCelsius": state.cpu_temperature, "UpperThresholdCritical": 98,
                 "Status": {"Health": state.temperature_health, "State": "Enabled"}},
                {"Name": "CPU1_TEMP", "ReadingCelsius": 55, "Status": fine},
                {"Name": "DIMM_A_TEMP", "ReadingCelsius": 45, "Status": fine},
                {"Name": "M2_TEMP", "ReadingCelsius": None, "Status": {"State": "Absent"}},
            ],
            "Fans": [
                {"Name": "CPU0_FAN", "Reading": 1650, "ReadingUnits": "RPM", "Status": fine},
                {"Name": "CPU1_FAN", "Reading": 450, "ReadingUnits": "RPM", "Status": {"Health": "Warning", "State": "Enabled"}},
                {"Name": "SYS_FAN5", "Reading": None, "ReadingUnits": "RPM", "Status": {"State": "Absent"}},
            ],
        }

    @app.get(v1 + "/Managers")
    async def managers() -> dict[str, Any]:
        return {"Members": [{"@odata.id": f"{v1}/Managers/Self"}]}

    @app.get("/viewer.html")
    async def viewer(request: Request) -> Response:
        # Where the real thing has its console. This one says whether the pass it was shown is one it made out.
        known = request.url.query in state.passes
        said = "the pass is one this controller made out" if known else "no pass this controller knows"
        return Response(f"<!doctype html><title>Console (stand-in)</title><p>The console of a stand-in server: {said}.</p>", media_type="text/html")

    @app.get(v1 + "/Managers/Self/IKVM")
    async def console() -> dict[str, Any]:
        made = secrets.token_hex(8)  # a new one every time it is asked, as on the real thing
        state.passes.append(made)
        way_in = str(state.console).replace("{pass}", made) if WAY_IN is UNSET else WAY_IN
        return {"Access": "One time", "Interface": state.console_kind, "URI": way_in}

    @app.get(v1 + "/Managers/Self")
    async def manager() -> dict[str, Any]:
        return {
            **({"IKVM": {"@odata.id": f"{v1}/Managers/Self/IKVM"}} if state.console is not None else {}),
            "Id": "Self", "ManagerType": "BMC", "FirmwareVersion": state.firmware,
            "Actions": {"#Manager.Reset": {"target": f"{v1}/Managers/Self/Actions/Manager.Reset", "ResetType@Redfish.AllowableValues": ["ForceRestart"]}},
        }  # fmt: skip

    @app.post(v1 + "/Managers/Self/Actions/Manager.Reset")
    async def manager_reset(request: Request) -> Response:
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
                        await websocket.send_bytes(ami.message(ami.PASS_SEEN, 0, bytes([1 if good else 0, 0])))
                        if not good:
                            await websocket.close()
                            return
                        state.console_passes.discard(shown)  # a pass is for one session
                        alone = not (state.held_by or state.holder_returning)
                        await websocket.send_bytes(ami.message(ami.LICENCE) + ami.message(ami.OTHERS, 0, bytes(134 if alone else 268)))
                        if alone:
                            await websocket.send_bytes(ami.message(ami.NEXT_HOLDER, 6))  # "the console is yours": a real board, to the only one there
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
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def start(self) -> FakeBmc:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake controller did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
