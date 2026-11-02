"""Which server answers at a tile's address: a server's controller is known by the numbers it gives for itself.

A controller's maker may have put one certificate, and its key, on every board, and a fleet often has one password. After a
new lease (a controller on DHCP) another server answers at a tile's address, and before this was there the tile signed in to
it with the saved password and sent it whatever was pressed: Power, Reset, Start into BIOS setup, the keys of its console,
the way into that console. Now the number its computer gives for itself (its UUID) is remembered when the tile is added and
asked before anything is sent; and the number its controller's service root gives (which anybody may read) before the
password goes. In these tests another server is the same stand-in with other numbers and no session of the wall's: the same
certificate and the same password, as a board of the same make in the same rack.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import kvm, redfish, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from qkvm.redfish import RedfishDevice, controller_number, own_number
from qkvm.store import machine_from_before
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_openbmc_console import ikvm
from tests.test_redfish import status_of
from tests.test_wall import PASSWORD, add, snap, wait_until, wall
from tests.settings_file import settings_text, write_settings_text

A_SYSTEM, A_ROOT = "4c4c4544-0042-3510-8054-b9c04f4a3532", "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
B_SYSTEM, B_ROOT = "4c4c4544-0042-3510-8054-c7c04f4a3533", "9f8e7d6c-5b4a-4f9e-8d7c-6b5a4f3e2d1c"
A_MARK = "server:" + hashlib.sha256(A_SYSTEM.lower().encode()).hexdigest()[:32] + hashlib.sha256(A_ROOT.lower().encode()).hexdigest()[:32]


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def server_a(tmp_path: Path, **more: Any) -> FakeBmc:
    """A server of a make that puts one certificate on every board (the stand-ins given one folder show one certificate)."""
    return FakeBmc(BmcState(**{"uuid": A_SYSTEM, "root_uuid": A_ROOT, "model": "SRV-A", **more}), tls_dir=tmp_path / "the-makers").start()


def another_server(bmc: FakeBmc, root: object = B_ROOT, system: object = B_SYSTEM) -> None:
    """From now on another server of the same make answers at the address (a new lease): the same certificate and password,
    numbers of its own, and none of the wall's sessions. What it is sent is counted from here."""
    state = bmc.state
    state.uuid, state.root_uuid, state.model = system, root, "SRV-B"
    state.tokens.clear()
    state.web_sessions.clear()
    state.actions.clear()
    state.changes.clear()
    state.hid.clear()
    state.passes.clear()
    state.logins = state.web_logins = 0


def this_server_again(bmc: FakeBmc) -> None:
    state = bmc.state
    state.uuid, state.root_uuid, state.model = A_SYSTEM, A_ROOT, "SRV-A"
    state.tokens.clear()


def said(reply: httpx.Response) -> tuple[int, str]:
    return reply.status_code, str(reply.json().get("code"))


def at_the_open_root(device: RedfishDevice, before: Any, after: Any = None) -> None:
    """Have `before()` happen as the device reads the controller's open service root (without a session) and `after()` once
    that read is answered: a new lease made to come at that moment."""
    sent = device._send

    async def then(client: Any, request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
        open_root = request.method == "GET" and request.url.path.rstrip("/") == "/redfish/v1" and "x-auth-token" not in request.headers
        if not open_root:
            return await sent(client, request, *args, **kwargs)
        before()
        try:
            return await sent(client, request, *args, **kwargs)
        finally:
            if after is not None:
                after()

    device._send = then  # type: ignore[method-assign]


ACTIONS = ("atx_power_long", "atx_reset", "atx_power", "power_on", "power_off", "reboot", "locate_on", "bios_setup")


def test_a_server_that_took_the_address_is_sent_neither_the_password_nor_anything_pressed(tmp_path: Path) -> None:
    bmc = server_a(tmp_path, own_console=True)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]  # both numbers, kept with the tile
            status_of(client, device, state="online")
            another_server(bmc)
            act = f"/api/v1/devices/{device}/actions"
            for action in ACTIONS:
                assert said(client.post(act, json={"action": action})) == (502, "another_machine"), action
            assert said(client.post(act, json={"action": "text", "text": "what is typed into this tile's server"})) == (502, "another_machine")
            assert said(client.post(f"/api/v1/devices/{device}/console")) == (502, "another_machine")
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and "its controller gives another number" in status["error"]["message"]
            assert client.get(snap(device)).json()["code"] == "another_machine"
            # Nothing went to it: no command, no change, no key, and not the password, by either road.
            assert (bmc.state.actions, bmc.state.changes, bmc.state.hid, bmc.state.logins, bmc.state.web_logins) == ([], [], [], 0, 0)
            assert bmc.state.passes == []  # (no way into its console was made out)
            # This tile's server answers there again: the tile says how it is, and its buttons are its own again.
            this_server_again(bmc)
            status_of(client, device, state="online")
            assert client.post(act, json={"action": "atx_power_long"}).status_code == 200 and bmc.state.actions == ["system ForceOff"]
    finally:
        bmc.stop()


def test_a_server_whose_controller_gives_the_same_number_is_still_sent_nothing(tmp_path: Path) -> None:
    # The reviewer's case: another computer behind a controller whose service root says the number this tile's did (one that
    # gives the same number on every board, or none checked yet). The password goes, and nothing else: its computer is asked.
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            another_server(bmc, root=A_ROOT)
            act = f"/api/v1/devices/{device}/actions"
            for action in ACTIONS:
                assert said(client.post(act, json={"action": action})) == (502, "another_machine"), action
            status = status_of(client, device, state="error")
            assert "Another server answers at this address: it gives another number for itself" in status["error"]["message"]
            assert (bmc.state.actions, bmc.state.changes) == ([], [])
    finally:
        bmc.stop()


@pytest.mark.parametrize("root", [B_ROOT, A_ROOT])
def test_the_server_is_asked_before_the_password_goes_and_before_its_web_page_is_offered_it(tmp_path: Path, root: str) -> None:
    # The first thing asked for after the new lease is the screen, before any look has seen the other server: its console's
    # web page has a sign-in of its own, which is not offered the password, and its screen is not shown.
    bmc = server_a(tmp_path, own_console=True)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            another_server(bmc, root=root)

            def shown() -> str:
                reply = client.get(snap(device))
                return "a picture" if reply.status_code == 200 else str(reply.json().get("code"))

            wait_until(lambda: shown() == "another_machine", "the tile did not say that another server answers", 15)
            assert bmc.state.web_logins == 0 and bmc.state.watching == 0
            assert bmc.state.logins == (0 if root == B_ROOT else 1)  # (the controller's number asked first, where it is another)
    finally:
        bmc.stop()


def test_the_consoles_own_sign_in_waits_while_which_server_answers_cannot_be_read(tmp_path: Path) -> None:
    # Its computer answers an error of its own just then: which server answers is not known, and the console's web page is
    # not offered the password on the strength of nothing (where a number is remembered). Asked again as after any failure.
    bmc = server_a(tmp_path, own_console=True)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            bmc.state.system_unwell = True
            wait_until(lambda: client.get(snap(device)).json().get("code") == "bad_response", "the console's attempt did not end on the read", 10)
            assert bmc.state.token_asks > 0 and bmc.state.web_logins == 0
            bmc.state.system_unwell = False
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
    finally:
        bmc.stop()


def test_a_console_whose_web_sign_in_met_another_server_is_not_opened(tmp_path: Path) -> None:
    # (The first review's finding 6.) The new lease comes between the question before the console's own sign-in and that
    # sign-in (a moment, made to happen here): the other server's web page signs this program in, and hands out a console
    # pass. It is asked again which server answers before its console is opened: nothing of it is shown, nothing typed into it.
    bmc = server_a(tmp_path, own_console=True)

    async def run() -> KvmError:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        try:
            assert (await device.status())["state"] == "online"
            web = device._web

            async def a_new_lease_at_the_sign_in(method: str, path: str, *args: Any, **kwargs: Any) -> httpx.Response:
                if (method, path) == ("POST", "/api/session") and bmc.state.uuid == A_SYSTEM:
                    another_server(bmc, root=A_ROOT)
                return await web(method, path, *args, **kwargs)

            device._web = a_new_lease_at_the_sign_in  # type: ignore[method-assign]
            deadline = asyncio.get_running_loop().time() + 15
            while True:
                try:
                    await device.snapshot(640)
                except KvmError as ex:
                    if ex.code != "no_stream" or asyncio.get_running_loop().time() > deadline:
                        return ex
                await asyncio.sleep(0.05)
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine", (refused.code, refused.message)
        assert bmc.state.web_logins == 1 and bmc.state.heard == [] and bmc.state.hid == []  # (its console never opened)
    finally:
        bmc.stop()


def test_a_command_goes_only_under_the_session_the_server_was_asked_under(tmp_path: Path) -> None:
    # The new lease comes between the question which server answers and the command (a moment, made long here): the command
    # goes under the session it was asked under, which the other server does not know (401). It is not sent under the session
    # the other server hands out until that server was asked which it is.
    bmc = server_a(tmp_path)

    async def run() -> KvmError:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        try:
            assert (await device.status())["state"] == "online"
            checked = device._checked_read

            async def then_a_new_lease(*args: Any, **kwargs: Any) -> Any:
                found = await checked(*args, **kwargs)
                if bmc.state.uuid == A_SYSTEM:
                    another_server(bmc, root=A_ROOT)  # (its controller says this tile's number: the password goes, the command not)
                return found

            device._checked_read = then_a_new_lease  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power_long")
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine" and bmc.state.actions == [], (refused.code, refused.message, bmc.state.actions)
    finally:
        bmc.stop()


def settings_of(data: Path) -> dict[str, Any]:
    # The background save replaces this file atomically. Windows can briefly deny an open
    # while the old file is being replaced; a permanent permission problem must still fail.
    deadline = time.monotonic() + 1.0
    while True:
        try:
            return json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))
        except PermissionError:
            # The Windows C runtime reports sharing violations as EACCES without winerror.
            if sys.platform != "win32" or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def as_written_by_0_1(data: Path, ident: str | None = None) -> None:
    """The settings as a wall of 0.1.x wrote them for the same tile: no `machine`, and the server's number in `ident` (or
    `ident` as given: "own:..." for a tile kept beside its twin)."""
    for name in ("qkvm.json", "qkvm.bak"):
        written = json.loads(settings_text(data / name, encoding="utf-8"))
        for device in written["devices"]:
            device.pop("machine", None)
            if ident is not None:
                device["ident"] = ident
        write_settings_text(data / name, json.dumps(written), encoding="utf-8")


def test_a_servers_tile_from_0_1_knows_its_server_by_what_it_kept_and_trusts_nothing_that_answers_first(tmp_path: Path) -> None:
    bmc = server_a(tmp_path)
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, bmc.url)
        as_written_by_0_1(data)
        kept = settings_of(data)["devices"][0]
        assert "machine" not in kept and kept["ident"] == A_MARK[: redfish.SERVER_MARK]
        # Upgraded while another server answers at the address: it is not taken for the tile's.
        another_server(bmc)
        with wall(data) as client:
            assert client.core.store.device(device).machine == A_MARK[: redfish.SERVER_MARK]  # type: ignore[attr-defined]
            refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
            assert said(refused) == (502, "another_machine") and bmc.state.actions == []
            assert status_of(client, device, state="error")["error"]["code"] == "another_machine"
            # Its own server there again: known, and its controller's number taken beside it, under the session it was found under.
            this_server_again(bmc)
            status_of(client, device, state="online")
            wait_until(lambda: settings_of(data)["devices"][0].get("machine") == A_MARK, "the controller's number was not kept", 10)
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200
    finally:
        bmc.stop()


def test_a_tile_that_knows_no_server_takes_the_first_it_sees_and_keeps_it_as_a_change_of_its_own(tmp_path: Path) -> None:
    # A tile of 0.1.x kept beside its twin ("own:...") kept no number of its server: the first one seen is taken (trust on first
    # use, as for a certificate), and kept the way every change of what is saved is: a new record in the old one's place,
    # in its turn among the changes (so that an edit under way notices), never the record changed where it is.
    bmc = server_a(tmp_path)
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, bmc.url)
        as_written_by_0_1(data, ident="own:" + device)
        with wall(data) as client:
            before = client.core.store.device(device)  # type: ignore[attr-defined]
            assert before.machine == ""
            status_of(client, device, state="online")
            wait_until(lambda: settings_of(data)["devices"][0].get("machine") == A_MARK, "the server's numbers were not kept", 10)
            assert client.core.store.device(device).machine == A_MARK and before.machine == ""  # type: ignore[attr-defined]
            another_server(bmc)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})) == (502, "another_machine")
            assert bmc.state.actions == [] and bmc.state.logins == 0
    finally:
        bmc.stop()


def test_an_edit_takes_the_server_that_answers_now_only_where_its_password_is_typed(tmp_path: Path) -> None:
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url, name="db-01")
            another_server(bmc)
            edit = f"/api/v1/devices/{device}"
            renamed = client.put(edit, json={"name": "db-01, renamed", "url": bmc.url, "username": "admin", "password": ""})
            assert said(renamed) == (422, "another_machine") and bmc.state.logins == 0
            # "Save anyway" without the password keeps the server it was added for.
            forced = client.put(edit, json={"name": "db-01, renamed", "url": bmc.url, "username": "admin", "password": "", "force": True})
            assert forced.status_code == 200 and client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            # Whoever types the password says "this is the server": the one that answers now is the tile's from then on.
            typed = client.put(edit, json={"name": "db-02", "url": bmc.url, "username": "admin", "password": "secret"})
            assert typed.status_code == 200, typed.text
            taken = client.core.store.device(device).machine  # type: ignore[attr-defined]
            assert taken == own_number({"UUID": B_SYSTEM}) + str(controller_number({"UUID": B_ROOT}))
            status_of(client, device, state="online")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200 and bmc.state.actions == ["system ForceOff"]
    finally:
        bmc.stop()


def test_the_right_server_is_not_refused_after_a_new_session_a_restart_or_an_edit(tmp_path: Path) -> None:
    bmc = server_a(tmp_path)
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, bmc.url, name="db-01")
            status_of(client, device, state="online")
            logins, roots = bmc.state.logins, bmc.state.roots_unsigned
            bmc.state.tokens.clear()  # (the session ran out: signed in again, the controller's number asked first)
            # (A look is made when the status is asked for: asked first, each time.)
            wait_until(lambda: not status_of(client, device, state="online")["error"] and bmc.state.logins > logins, "not signed in again", 10)
            asked = len(bmc.state.requests)  # (and the sign-in's answer taken: a request under its session came after it)
            wait_until(lambda: not status_of(client, device, state="online")["error"] and len(bmc.state.requests) > asked, "not asked again", 10)
            assert bmc.state.roots_unsigned > roots
            assert client.put(f"/api/v1/devices/{device}", json={"name": "db-01, renamed", "url": bmc.url, "username": "admin", "password": ""}).status_code == 200
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
        with wall(data) as client:
            status_of(client, device, state="online")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}).status_code == 200
            assert bmc.state.actions == ["system ForceRestart"]
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
    finally:
        bmc.stop()


def test_a_controller_that_says_no_number_where_one_was_given_is_not_sent_the_password(tmp_path: Path) -> None:
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            another_server(bmc, root=None)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_off"})) == (502, "another_machine")
            status = status_of(client, device, state="error")
            assert "does not say which it is" in status["error"]["message"] and bmc.state.logins == 0
    finally:
        bmc.stop()


def test_a_server_whose_controller_says_no_number_is_told_apart_by_its_computer(tmp_path: Path) -> None:
    bmc = server_a(tmp_path, root_uuid=None)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == own_number({"UUID": A_SYSTEM})  # type: ignore[attr-defined]
            another_server(bmc, root=None)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_off"})) == (502, "another_machine")
            assert bmc.state.actions == []
    finally:
        bmc.stop()


def test_an_export_carries_the_servers_numbers_and_a_file_of_0_1_gives_its_server_the_number_it_kept(tmp_path: Path) -> None:
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            add(client, bmc.url, name="db-01")
            made = client.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
            assert made.status_code == 200, made.text
            file = made.text
        written = json.loads(file)
        entry = written["devices"][0] if "devices" in written else written["parts"]["devices"][0]
        assert entry["machine"] == A_MARK
        with wall(tmp_path / "other") as client:
            assert client.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
            assert [record.machine for record in client.core.store.devices] == [A_MARK]  # type: ignore[attr-defined]
        # A file made by 0.1.x has the server's number in `ident` and no `machine`.
        entry.pop("machine")
        with wall(tmp_path / "third") as client:
            assert client.post("/api/v1/import", json={"file": json.dumps(written), "take": ["devices"]}).json()["devices"] == 1
            assert [record.machine for record in client.core.store.devices] == [A_MARK[: redfish.SERVER_MARK]]  # type: ignore[attr-defined]
    finally:
        bmc.stop()


ZERO = "00000000-0000-0000-0000-000000000000"  # what a board says whose maker never set its computer's number


def test_a_server_whose_computer_gives_no_number_is_known_by_its_controllers(tmp_path: Path) -> None:
    # (The first review's finding 2.) Its computer says no number, its controller's service root says one: that one is
    # remembered and asked before the password goes, and the tile does not take another server's computer for its own.
    bmc = server_a(tmp_path, uuid=ZERO)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == redfish.SAID_NONE + str(controller_number({"UUID": A_ROOT}))  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            another_server(bmc)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
            assert (bmc.state.logins, bmc.state.actions) == (0, [])
            # Its own controller there again, its computer still saying none: known, and its buttons its own.
            bmc.state.uuid, bmc.state.root_uuid, bmc.state.model = ZERO, A_ROOT, "SRV-A"
            bmc.state.tokens.clear()
            status_of(client, device, state="online")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
            assert client.core.store.device(device).machine.startswith(redfish.SAID_NONE)  # type: ignore[attr-defined]
    finally:
        bmc.stop()


def test_another_server_whose_computer_gives_no_number_is_not_shown_as_this_one(tmp_path: Path) -> None:
    # (The first review's finding 5.) A tile that knows its server by its computer's number alone (its controller's root said
    # none when it was added); another server answers whose controller says none either, and whose computer says none: the look
    # says so, and does not show the other server's power, name and sensors as this one's (nor give them to the alerts).
    bmc = server_a(tmp_path, root_uuid=None)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == own_number({"UUID": A_SYSTEM})  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            another_server(bmc, root=None, system=None)
            bmc.state.power = "Off"
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and "does not say which it is" in status["error"]["message"]
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})) == (502, "another_machine")
            assert bmc.state.actions == []
    finally:
        bmc.stop()


def test_saving_without_checking_with_the_password_typed_keeps_the_server_it_was_for(tmp_path: Path) -> None:
    # (The first review's finding 1.) The controller is gone; its tile is saved with the new password without being checked.
    # The server it was added for stands: a board that takes the address later is not taken for it at the first look.
    bmc = server_a(tmp_path)
    other: FakeBmc | None = None
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url, name="db-01")
            status_of(client, device, state="online")
            port, url = bmc.port, bmc.url
            bmc.stop()
            edit = {"name": "db-01", "url": url, "username": "admin", "password": "secret"}
            assert said(client.put(f"/api/v1/devices/{device}", json=edit))[0] == 422
            assert client.put(f"/api/v1/devices/{device}", json={**edit, "force": True}).status_code == 200
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            other = FakeBmc(BmcState(uuid=B_SYSTEM, root_uuid=B_ROOT, model="SRV-B"), port=port, tls_dir=tmp_path / "the-makers").start()
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine"
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})) == (502, "another_machine")
            assert (other.state.logins, other.state.actions) == (0, [])
    finally:
        if other is not None:
            other.stop()


def test_a_board_put_in_that_gives_no_number_stays_its_tiles_after_a_restart(tmp_path: Path) -> None:
    # (The first review's finding 3.) The board is replaced by one whose computer gives no number, and the password is typed:
    # what it gives is the tile's from then on, and the number the old board gave is not taken back at the next start.
    bmc = server_a(tmp_path)
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, bmc.url, name="db-01")
            another_server(bmc, system=ZERO)
            assert client.put(f"/api/v1/devices/{device}", json={"name": "db-01", "url": bmc.url, "username": "admin", "password": "secret"}).status_code == 200
            record = client.core.store.device(device)  # type: ignore[attr-defined]
            assert record.machine == redfish.SAID_NONE + str(controller_number({"UUID": B_ROOT})) and record.ident == ""
        with wall(data) as client:
            status_of(client, device, state="online")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
    finally:
        bmc.stop()


def test_open_console_is_not_refused_where_asking_for_it_takes_the_controllers_number(tmp_path: Path) -> None:
    # (The first review's finding 4.) The first thing asked after an upgrade from 0.1.x is the way into the console: asking
    # takes the controller's number, and with it the tile's record is a new one; the console is handed out all the same.
    bmc = server_a(tmp_path)
    data = tmp_path / "wall"
    try:
        with wall(data) as client:
            device = add(client, bmc.url)
        as_written_by_0_1(data)
        with wall(data) as client:
            reply = client.post(f"/api/v1/devices/{device}/console")
            assert reply.status_code == 200, reply.text
    finally:
        bmc.stop()


def test_a_server_whose_computer_stops_giving_its_number_is_known_by_its_controllers_meanwhile(tmp_path: Path) -> None:
    # (The second review's L2.) Both numbers remembered; the controller (compared before this very session) is this tile's, and
    # its computer gives no number just now (a controller that learns it from the server's firmware as it starts may say none
    # while the server is off): not refused, Power on above all.
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            bmc.state.uuid, bmc.state.power = ZERO, "Off"
            status_of(client, device, state="no_signal")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
            assert bmc.state.actions == ["system On"]
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]  # (nothing of it changed)
    finally:
        bmc.stop()


def test_a_server_known_by_its_controller_is_not_refused_for_an_answer_under_the_session_before(tmp_path: Path) -> None:
    # (The second review's L1.) Its computer gave no number when added. A button's read is answered late, under a session the
    # controller lets go of meanwhile; a look signs in anew (its controller compared again). The late answer is no less this
    # controller's: the button goes through.
    bmc = server_a(tmp_path, uuid=ZERO)

    async def run() -> str:
        machine = redfish.SAID_NONE + str(controller_number({"UUID": A_ROOT}))
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=machine))
        try:
            assert (await device.status())["state"] == "online"
            places = await device._find()
            first = device._token
            assert first is not None
            bmc.state.reads_busy_until = time.monotonic() + 1.5  # (the computer's read is answered late)
            pressed = asyncio.create_task(device.act("locate_on"))
            await asyncio.sleep(0.5)  # (its read is past the controller's door, under the first session)
            del bmc.state.tokens[first]  # (the controller lets that session go)
            await device._get(places["chassis"], urgent=True)  # (a look's read: 401, signed in again, its controller compared)
            assert device._token != first
            try:
                await pressed
            except KvmError as ex:
                return f"{ex.code}: {ex.message}"
            return "done"
        finally:
            await device.close()

    try:
        outcome = asyncio.run(run())
        assert outcome == "done", outcome
    finally:
        bmc.stop()


def test_a_controllers_number_is_taken_only_as_the_controller_that_made_the_session_says_it(tmp_path: Path) -> None:
    # (The second review's L3.) A tile that knows its server by its computer's number alone, whose controller begins to give
    # a number: it is taken under the session the computer was found to be this one under. A new lease between that read and
    # the controller's (whose service root is open to anybody) does not have another controller's number taken for this one.
    bmc = server_a(tmp_path, root_uuid=None)
    b_mark = str(own_number({"UUID": A_SYSTEM})) + str(controller_number({"UUID": B_ROOT}))

    async def run() -> str:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=own_number({"UUID": A_SYSTEM}) or ""))
        try:
            assert (await device.status())["state"] == "online" and device.spec.machine == own_number({"UUID": A_SYSTEM})
            bmc.state.root_uuid = A_ROOT  # (it says its number from now on)
            bmc.state.tokens.clear()  # (a new session: the next look asks the controller for its number afresh)

            def a_new_lease() -> None:
                if bmc.state.uuid == A_SYSTEM and device._token is not None:
                    another_server(bmc)  # (B: another computer, another controller, none of A's sessions)

            # (At the root's read, which is the open one, without a session, since 0.2.1: until then it was read under the session.)
            at_the_open_root(device, a_new_lease)
            device._status_at = 0.0
            await device.status()
            for _ in range(40):
                await asyncio.sleep(0.05)
                if device._status_task is None or device._status_task.done():
                    break
            return device.spec.machine
        finally:
            await device.close()

    try:
        learned = asyncio.run(run())
        assert learned != b_mark and learned == own_number({"UUID": A_SYSTEM})
    finally:
        bmc.stop()


def test_a_controllers_number_is_not_taken_where_its_manager_names_another(tmp_path: Path) -> None:
    # (The same, the other way round.) The open service root says one number and the manager, read under the session the
    # computer was found to be this one under, names another as the service it hosts: neither is taken.
    bmc = server_a(tmp_path, root_uuid=None, entry_uuid=A_ROOT)

    async def run() -> str:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=own_number({"UUID": A_SYSTEM}) or ""))
        try:
            assert (await device.status())["state"] == "online"

            def another_root_for_a_moment() -> None:
                bmc.state.root_uuid = B_ROOT  # (the open root answered by another controller, for that one read)

            def as_it_was() -> None:
                bmc.state.root_uuid = None

            at_the_open_root(device, another_root_for_a_moment, as_it_was)
            bmc.state.tokens.clear()  # (a new session: the controller is asked for its number afresh)
            device._status_at = 0.0
            await device.status()
            for _ in range(40):
                await asyncio.sleep(0.05)
                if device._status_task is None or device._status_task.done():
                    break
            return device.spec.machine
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == own_number({"UUID": A_SYSTEM})
    finally:
        bmc.stop()


def test_an_edit_while_the_computer_says_no_number_keeps_what_the_server_is_known_by(tmp_path: Path) -> None:
    # (The third review's 1.) Its computer says no number just now (taken for this one by its controller); the tile is renamed
    # meanwhile: what it is known by stays, and the same server added at another address is still said to be on the wall.
    bmc = server_a(tmp_path)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url, name="db-01")
            before = client.core.store.device(device).ident  # type: ignore[attr-defined]
            bmc.state.uuid = ZERO
            assert client.put(f"/api/v1/devices/{device}", json={"name": "db-01, renamed", "url": bmc.url, "username": "admin", "password": ""}).status_code == 200
            assert client.core.store.device(device).ident == before  # type: ignore[attr-defined]
            bmc.state.uuid = A_SYSTEM
            again = client.post("/api/v1/devices", json={"url": f"https://localhost:{bmc.port}", "password": "secret", "kind": "redfish"})
            assert (again.status_code, again.json().get("code")) == (409, "same_device")
    finally:
        bmc.stop()


def test_a_controller_whose_manager_names_itself_by_its_services_number_is_known_by_it(tmp_path: Path) -> None:
    # (The third review's 2.) Its manager says nothing of the service it hosts, and names itself by the same number as its
    # service root (as a real AMI board's does): that is the controller's number, asked before the password goes.
    bmc = server_a(tmp_path, entry_uuid=None)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == A_MARK  # type: ignore[attr-defined]
            another_server(bmc)
            assert said(client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})) == (502, "another_machine")
            assert (bmc.state.logins, bmc.state.actions) == (0, [])
    finally:
        bmc.stop()


def test_a_controller_that_says_its_number_only_to_a_session_is_not_refused_for_it(tmp_path: Path) -> None:
    # (The desktop's follow-up 3, 0.2.1.) Its service root says its number (UUID) only to a request under one of its sessions.
    # The number asked before the password goes is the one the root says to anybody, without a session: the controller's
    # number is learnt from that root too, or it is refused for good after its next sign-in (it says none where one is kept).
    # Here it says none to anybody: the server is known by its computer's number, as one whose controller says none.
    bmc = server_a(tmp_path, root_uuid_signed_only=True)
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            logins = bmc.state.logins
            bmc.state.tokens.clear()  # (the session ran out: the next sign-in asks the root first, without one)
            act = f"/api/v1/devices/{device}/actions"
            assert client.post(act, json={"action": "locate_on"}).status_code == 200
            assert bmc.state.logins > logins
            assert status_of(client, device, state="online")["error"] is None
            assert client.core.store.device(device).machine == own_number({"UUID": A_SYSTEM})  # type: ignore[attr-defined]
            # ...and told apart by that number: another server is sent nothing.
            another_server(bmc)
            assert said(client.post(act, json={"action": "atx_power_long"})) == (502, "another_machine") and bmc.state.actions == []
    finally:
        bmc.stop()


def test_a_server_that_gives_no_number_while_its_controllers_cannot_be_read_is_not_added_unknown(tmp_path: Path) -> None:
    # (The third review's 3.) Its computer gives no number, and its controller's manager answers an error of the moment as it
    # is added: the add says which server it is could not be told (nothing is taken, nor added unknown), and the next try adds it.
    bmc = server_a(tmp_path, uuid=ZERO, manager_fails=1)
    try:
        with wall(tmp_path / "wall") as client:
            first = client.post("/api/v1/devices", json={"url": bmc.url, "password": "secret"})
            assert first.status_code == 422 and "could not be told" in first.json()["message"], first.text
            device = add(client, bmc.url)
            assert client.core.store.device(device).machine == redfish.SAID_NONE + str(controller_number({"UUID": A_ROOT}))  # type: ignore[attr-defined]
    finally:
        bmc.stop()


def test_a_number_that_could_not_be_read_during_an_edit_leaves_what_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second review's L4.) A driver that could not read the number just now says nothing of it (None), which is not
    # "it says none": a Proxmox guest whose config read has a moment during an edit keeps what it is known by.
    from qkvm import core, proxmox
    from tests.fake_proxmox import SECRET, TOKEN_ID, FakeProxmox
    from tests.test_proxmox import two_guests

    pve = FakeProxmox(two_guests(), tls_dir=tmp_path / "pve").start()
    try:
        with wall(tmp_path / "wall") as client:
            reply = client.post("/api/v1/devices", json={"url": pve.guest_url(100), "username": TOKEN_ID, "password": SECRET, "kind": "proxmox"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            before = client.core.store.device(device).ident  # type: ignore[attr-defined]
            original = proxmox.ProxmoxGuest._guest

            async def config_has_a_moment(self: Any, method: str, what: str, *args: Any, **kwargs: Any) -> Any:
                if what == "config":
                    raise KvmError("timeout", "Proxmox did not answer in time", 504)
                return await original(self, method, what, *args, **kwargs)

            monkeypatch.setattr(proxmox.ProxmoxGuest, "_guest", config_has_a_moment)
            edit = client.put(f"/api/v1/devices/{device}", json={"url": pve.guest_url(100), "username": TOKEN_ID, "password": "", "kind": "proxmox", "name": "web, renamed"})
            assert edit.status_code == 200, edit.text
            record = client.core.store.device(device)  # type: ignore[attr-defined]
            assert before.startswith("proxmox:") and record.ident == before and core.identity(record) == before
    finally:
        pve.stop()


def test_a_connection_the_controller_closed_while_it_sat_idle_is_tried_once_more_before_a_sign_in(tmp_path: Path) -> None:
    # (The second review's N8.) The service root, read before the password goes, on a pooled connection the controller closed
    # meanwhile: read once more on a new one, as every other read is, and not taken for a controller that is gone.
    bmc = server_a(tmp_path)

    async def run() -> str:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        try:
            sent = device._send
            broken = [True]

            async def closed_while_idle(client: Any, request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
                if broken[0] and request.method == "GET" and request.url.path.rstrip("/") == "/redfish/v1" and "x-auth-token" not in request.headers:
                    broken[0] = False
                    raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)
                return await sent(client, request, *args, **kwargs)

            device._send = closed_while_idle  # type: ignore[method-assign]
            return str((await device.status())["state"])
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == "online"
    finally:
        bmc.stop()


def test_only_a_file_of_0_1_has_its_servers_number_taken_from_what_it_kept(tmp_path: Path) -> None:
    # A file this version wrote has the field (where nothing is known of the server, ""): that stands, whatever `ident` says.
    from qkvm.store import Store

    number = own_number({"UUID": A_SYSTEM})
    device = {"id": "ab12cd34", "name": "db-01", "url": "https://192.168.1.40", "kind": "redfish", "ident": number}
    for written, kept in (({**device}, number), ({**device, "machine": ""}, "")):
        path = tmp_path / f"{len(written)}.json"
        path.write_text(json.dumps({"version": 1, "devices": [written]}), encoding="utf-8")
        assert Store(path).devices[0].machine == kept, written


def test_what_a_tile_of_0_1_kept_is_taken_for_a_server_and_for_nothing_else() -> None:
    number = own_number({"UUID": A_SYSTEM})
    assert machine_from_before("redfish", number, "") == number
    assert machine_from_before("redfish", number, A_MARK) == A_MARK  # (one kept already stands)
    for kind, ident in (("amt", number), ("proxmox", number), ("redfish", "own:ab12"), ("redfish", ""), ("redfish", "server:" + "a" * 31), ("redfish", None)):
        assert machine_from_before(kind, ident, "") == "", (kind, ident)


def test_the_screen_of_an_openbmc_server_is_not_opened_under_another_servers_session(tmp_path: Path) -> None:
    # OpenBMC's console is opened with the tile's Redfish session: one another server handed out is not used before that server
    # was asked which it is, and its screen is not shown.
    bmc = FakeBmc(BmcState(layout="openbmc", uuid=A_SYSTEM, root_uuid=A_ROOT, kvm_screen=ikvm())).start()

    async def run() -> KvmError:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", machine=A_MARK))
        try:
            assert (await device.status())["state"] == "online"
            another_server(bmc, root=A_ROOT)
            bmc.state.kvm_upgrades.clear()
            with pytest.raises(KvmError) as refused:
                await device.rfb_socket()
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        # (The one upgrade is the session of this tile's server, which the other refuses: none under the other's own session.)
        assert refused.code == "another_machine" and bmc.state.kvm_upgrades == ["token"] and bmc.state.kvm_open == 0
    finally:
        bmc.stop()


# --- the console's roads, each bound to the controller compared on its own connection (0.2.1) -----------------------------


def a_tile_of_a(bmc: FakeBmc) -> RedfishDevice:
    return RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))


async def the_console_refused(device: RedfishDevice, within: float = 15.0) -> KvmError:
    """What the server's screen is refused with in the end, asked for as a tile asks until it is not "under way"."""
    deadline = asyncio.get_running_loop().time() + within
    while True:
        try:
            await device.snapshot(640)
        except KvmError as ex:
            if ex.code != "no_stream" or asyncio.get_running_loop().time() > deadline:
                return ex
        await asyncio.sleep(0.05)


def a_new_lease_to_b(bmc: FakeBmc) -> None:
    """Another server answers from now on: another computer, another controller (its own number), which knows none of the
    wall's sessions, cookies or console passes."""
    another_server(bmc)
    bmc.state.console_passes.clear()


def test_the_consoles_web_sign_in_goes_only_where_the_controller_was_compared_on_its_connection(tmp_path: Path) -> None:
    # (The desktop's follow-up 7 and the reviewer's addition, 0.2.1.) Which server answers is asked over the Redfish session;
    # the console's web page is signed in to with the password on another connection, made a moment later. A new lease in
    # between: the other server's web page was offered the password. The sign-in goes on a connection of its own, on which
    # the controller's open root is read first and its number compared: here it is another's, and nothing goes on it. (The
    # lease comes as that connection is made: since round 2 it is made alongside the question, and the stand-in, which only
    # changes its state, cannot keep a connection made before it with the server it had, as a real address would.)
    bmc = server_a(tmp_path, own_console=True)

    async def run() -> KvmError:
        device = a_tile_of_a(bmc)
        try:
            assert (await device.status())["state"] == "online"
            opening, opened = device._open_line, []

            async def a_new_lease_as_it_is_made(*args: Any, **kwargs: Any) -> Any:
                opened.append(1)
                if len(opened) == 1:
                    a_new_lease_to_b(bmc)
                return await opening(*args, **kwargs)

            device._open_line = a_new_lease_as_it_is_made  # type: ignore[method-assign]
            return await the_console_refused(device)
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine", (refused.code, refused.message)
        assert (bmc.state.web_logins, bmc.state.heard, bmc.state.watching) == (0, [], 0)  # (not offered the password, no console)
    finally:
        bmc.stop()


def test_the_consoles_own_connection_goes_only_where_the_controller_was_compared_on_it(tmp_path: Path) -> None:
    # (The same, the console's WebSocket.) A new lease after the web page handed out the console's pass: the console was a
    # connection made anew, which took the web page's cookie and the pass (and would have taken the keys) to the other server.
    # It is opened on the connection the controller's number was compared on (the sign-in's), and where that one has ended (a
    # new lease ends it, as here), on one made anew on which the controller's open root is read first and its number compared.
    bmc = server_a(tmp_path, own_console=True)

    async def run() -> KvmError:
        device = a_tile_of_a(bmc)
        try:
            assert (await device.status())["state"] == "online"
            device._complete_first = False  # (how its console is greeted is known: the pass is the last the web page is asked)
            web = device._web

            async def a_new_lease_after_the_pass(method: str, path: str, *args: Any, **kwargs: Any) -> httpx.Response:
                answer = await web(method, path, *args, **kwargs)
                if (method, path) == ("GET", "/api/kvm/token") and args and bmc.state.uuid == A_SYSTEM:  # (the signed-in one)
                    a_new_lease_to_b(bmc)
                    if kwargs.get("line") is not None:
                        kwargs["line"].close()  # (the connection the pass came on ends with the lease)
                return answer

            device._web = a_new_lease_after_the_pass  # type: ignore[method-assign]
            return await the_console_refused(device)
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine", (refused.code, refused.message)
        assert (bmc.state.heard, bmc.state.watching, bmc.state.hid) == ([], 0, [])  # (no console: no cookie, no pass, no key)
    finally:
        bmc.stop()


def test_an_openbmc_console_goes_only_where_the_controller_was_compared_on_its_connection(tmp_path: Path) -> None:
    # (The same, OpenBMC's console, which bmcweb opens with the tile's Redfish session.) Another server at the address,
    # another controller: the session's token went to it with the console's upgrade (it refused it, not knowing it). The
    # console is opened on a connection on which the controller's open root is read first: nothing goes to another.
    bmc = FakeBmc(BmcState(layout="openbmc", uuid=A_SYSTEM, root_uuid=A_ROOT, kvm_screen=ikvm())).start()

    async def run() -> KvmError:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", machine=A_MARK))
        try:
            assert (await device.status())["state"] == "online"
            another_server(bmc)
            bmc.state.kvm_upgrades.clear()
            with pytest.raises(KvmError) as refused:
                await device.rfb_socket()
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine" and bmc.state.kvm_upgrades == [] and bmc.state.kvm_open == 0, (refused.code, bmc.state.kvm_upgrades)
    finally:
        bmc.stop()


def test_the_sign_ins_password_goes_on_the_connection_the_controllers_number_was_compared_on(tmp_path: Path) -> None:
    # (The coordinator's decision (a), 0.2.1.) The controller's open root was read, and its number compared, on whichever pooled
    # connection the HTTP library had; the password went on whichever it had next. The controller closes the connection after
    # its root's answer, and a new lease comes in that moment: the password went, on a connection made anew, to the other
    # server. It goes on the very connection the root was read and compared on, and where that one was closed, on one made
    # anew and compared anew: here another controller answers there, and is sent nothing.
    bmc = server_a(tmp_path)

    async def run() -> dict[str, Any]:
        device = a_tile_of_a(bmc)
        try:
            assert (await device.status())["state"] == "online"
            bmc.state.tokens.clear()  # (the session ran out: the next look signs in again)
            bmc.state.close_after_open_root = True
            bmc.state.after_open_root = lambda: another_server(bmc)
            return await device._read_status()
        finally:
            await device.close()

    try:
        status = asyncio.run(run())
        assert (status["state"], status["error"]["code"]) == ("error", "another_machine"), status
        assert bmc.state.logins == 0  # (not sent the password)
    finally:
        bmc.stop()


def test_a_controller_that_closes_the_connection_after_every_answer_gets_no_console_and_is_told_why(tmp_path: Path) -> None:
    # (The coordinator's decision (c), 0.2.1.) What must reach the controller goes on the connection its number was compared on
    # (see redfish._Line). One that closes the connection after every answer cannot be compared on a connection that then
    # carries anything: its console ends at once with a plain word that names the cause, is not asked for again at every
    # look, and nothing goes on a connection that was not compared (no web sign-in at all, no console). A sign-in of its
    # Redfish service (its number remembered) is not sent the password either, and the tile says so. No hang, no crash.
    bmc = server_a(tmp_path, own_console=True)
    cause = "closes the connection after every answer"

    async def run() -> tuple[KvmError, KvmError, int, dict[str, Any], dict[str, Any]]:
        device = a_tile_of_a(bmc)
        try:
            async with asyncio.timeout(60):
                assert (await device.status())["state"] == "online"  # (signed in while it kept its connections open)
                bmc.state.closes_every_connection = True
                refused = await the_console_refused(device)
                asked = len(bmc.state.web_asked)
                again = await the_console_refused(device, within=1.0)  # (asked again at once: said again, and nothing asked of it)
                assert len(bmc.state.web_asked) == asked
                status = await device._read_status()
                bmc.state.tokens.clear()  # (its session ran out: a sign-in now)
                logins = bmc.state.logins
                signed = await device._read_status()
                return refused, again, bmc.state.logins - logins, status, signed
        finally:
            await device.close()

    try:
        refused, again, logins, status, signed = asyncio.run(run())
        assert refused.code == "no_picture" and cause in refused.message, (refused.code, refused.message)
        assert (again.code, again.message) == (refused.code, refused.message)
        assert cause in str(status["server"]["no_screen"]) and status["screen"] is False, status["server"]["no_screen"]
        assert (bmc.state.web_logins, bmc.state.watching, bmc.state.heard) == (0, 0, [])
        assert logins == 0 and signed["state"] == "error" and cause in signed["error"]["message"], signed["error"]
    finally:
        bmc.stop()


def test_a_sign_in_refused_before_its_password_went_is_not_counted_as_sent(tmp_path: Path) -> None:
    # (The second review's smaller point, 0.2.1.) The controller sends more than its root's answer on the connection its number is
    # compared on (bytes nobody asked for). The sign-in's request is not written there: nothing of the password went, and it is
    # not counted as a sign-in that went out and came to nothing (held back as one, and said "does not sign qKVM in").
    asked: list[str] = []

    async def device_side(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
                asked.append(head.split("\r\n", 1)[0])
                if head.startswith("GET /redfish/v1/ "):
                    body = json.dumps({"RedfishVersion": "1.15.1", "UUID": A_ROOT}).encode()
                    answer = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body) + body
                    writer.write(answer + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")  # (and an answer nobody asked for)
                else:
                    writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def run() -> tuple[KvmError, float]:
        server = await asyncio.start_server(device_side, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        spec = DeviceSpec(id="ab12", name="db-01", base_url=f"http://127.0.0.1:{port}", username="admin", password="secret", kind="redfish", machine=A_MARK)
        device = RedfishDevice(spec)
        try:
            with pytest.raises(KvmError) as refused:
                await device._login()
            return refused.value, kvm.REJECTED.wait_left(kvm.REJECTED.what("login", spec))
        finally:
            await device.close()
            server.close()

    refused, held = asyncio.run(run())
    assert not any(one.startswith("POST") for one in asked), asked  # (nothing of the password went)
    assert held == 0 and "does not sign qKVM in" not in refused.message, (held, refused.code, refused.message)


async def what_the_console_gives(device: RedfishDevice, within: float = 20.0) -> str:
    """"a picture" once the server's screen is there; else the code and words it is refused with in the end."""
    deadline = asyncio.get_running_loop().time() + within
    while True:
        try:
            await device.snapshot(640)
            return "a picture"
        except KvmError as ex:
            if ex.code != "no_stream" or asyncio.get_running_loop().time() > deadline:
                return f"{ex.code}: {ex.message}"
        await asyncio.sleep(0.05)


@pytest.mark.parametrize("how", ["pinned", "pinned, and another tile shows its certificate", "plain HTTP"])
def test_a_controller_that_closes_every_connection_goes_on_fresh_pinned_ones_only_where_its_certificate_is_the_tiles(tmp_path: Path, how: str) -> None:
    # (The second review's L4, 0.2.1; probe review-bmc/probes/p8_closes_every_answer_from_the_start.py.) A controller that closes
    # the connection after every answer cannot carry the password, the pass or the keys on the connection its number was compared
    # on. Where its certificate is pinned and no other tile shows it, each of those goes on a connection made afresh right after
    # the compare, checked against the very same certificate (which binds it to the controller compared); over plain HTTP, with
    # the certificate not checked (test_a_controller_that_closes_the_connection_after_every_answer_...), or with a certificate
    # another tile shows too (a maker's one for every board, say), nothing is sent, as before. It had been refused for good.
    from qkvm.kvm import fetch_certificate
    from tests.test_redfish import a_screen

    https = how != "plain HTTP"
    state = BmcState(uuid=A_SYSTEM, root_uuid=A_ROOT, model="SRV-A", own_console=True, screen=a_screen())
    bmc = FakeBmc(state, tls_dir=tmp_path / "the-makers" if https else None).start()

    async def run() -> tuple[str, int, str, list[Any]]:
        pem = await fetch_certificate(bmc.url) if https else None
        spec = DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="pinned", cert_pem=pem, machine=A_MARK)
        device = RedfishDevice(spec)
        twin = RedfishDevice(DeviceSpec(id="cd34", name="db-02", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="pinned", cert_pem=pem)) if "another tile" in how else None
        try:
            async with asyncio.timeout(60):
                assert (await device.status())["state"] == "online"  # (signed in while it kept its connections open)
                bmc.state.closes_every_connection = True
                bmc.state.tokens.clear()  # (its session ran out: a sign-in now)
                logins = bmc.state.logins
                status = await device._read_status()
                signed = "signed in" if bmc.state.logins == logins + 1 and status["state"] == "online" else f"{status['state']}: {(status.get('error') or {}).get('message')}"
                console = await what_the_console_gives(device)
                if console == "a picture":
                    await device.act("keys", keys="KeyA")
                    for _ in range(100):
                        if bmc.state.hid[-2:] == [("key", 0, [0x04]), ("key", 0, [])]:
                            break
                        await asyncio.sleep(0.05)
                return signed, bmc.state.web_logins, console, list(bmc.state.hid)
        finally:
            await device.close()
            if twin is not None:
                await twin.close()

    try:
        signed, web_logins, console, hid = asyncio.run(run())
        if how == "pinned":
            assert signed == "signed in" and console == "a picture" and web_logins == 1, (signed, console)
            assert hid[-2:] == [("key", 0, [0x04]), ("key", 0, [])], hid
        else:
            cause = "closes the connection after every answer"
            assert cause in signed and cause in console, (signed, console)  # (the console: its Redfish sign-in, or its own line)
            assert (web_logins, hid) == (0, [])
    finally:
        bmc.stop()


@pytest.mark.parametrize("how", ["plain HTTP", "TLS not checked"])
def test_after_a_new_lease_no_session_token_reaches_the_other_server_on_any_road(tmp_path: Path, how: str) -> None:
    # (The owner's rule for 0.2.1: the token gap fixed.) The session a sign-in opens is a token every later request carries. It
    # went on the HTTP library's connections, which are not compared: after a new lease (which ends the connections to the
    # server that had the address) the first request on a connection made anew handed this tile's token to whatever answered.
    # Over plain HTTP and with the certificate not checked, every request that carries it goes on a connection of the program's
    # own, compared when it is made (see redfish._Lines): another server is sent no token by a look, a button, the light, Start
    # into BIOS setup, the way into the console, or the sign-out of the session as the tile is retired.
    bmc = FakeBmc(BmcState(uuid=A_SYSTEM, root_uuid=A_ROOT, model="SRV-A"), tls_dir=tmp_path / "the-makers" if how == "TLS not checked" else None).start()

    async def run() -> tuple[list[str], set[str], list[str]]:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        said: list[str] = []
        try:
            assert (await device.status())["state"] == "online"
            assert client_of(device) is not None
            this_tiles = set(bmc.state.tokens)  # (the tokens this server gave this tile)
            another_server(bmc)
            bmc.drop_connections()
            await asyncio.sleep(0.2)
            heard = len(bmc.state.tokens_heard)
            status = await device._read_status()
            said.append(f"look: {(status.get('error') or {}).get('code')}")
            for action in ACTIONS:
                try:
                    await device.act(action)
                    said.append(f"{action}: done")
                except KvmError as ex:
                    said.append(f"{action}: {ex.code}")
            try:
                await device.console()
                said.append("console: handed out")
            except KvmError as ex:
                said.append(f"console: {ex.code}")
        finally:
            await device.close()  # (the session's sign-out, as the tile is retired)
        return bmc.state.tokens_heard[heard:], this_tiles, said

    try:
        heard, this_tiles, said = asyncio.run(run())
        assert not set(heard) & this_tiles, f"this tile's token went to the other server: {said}"
        assert all(one.endswith("another_machine") for one in said), said
    finally:
        bmc.stop()


def test_a_sign_out_on_a_line_made_for_it_goes_to_this_tiles_server_and_to_no_other(tmp_path: Path) -> None:
    # (With the sign-out's fix of 0.2.1: GitHub's controllers job.) Where no line of the tile's waits as it is retired, the
    # sign-out makes one, compared as it is made: for a server known by its computer alone, by reading the computer under the
    # session being given back. Another server that took the address does not know that session (its answer is 401): it is
    # sent no DELETE, and this tile's session runs out by itself on the server that made it.
    bmc = server_a(tmp_path, root_uuid=None)
    seen: dict[str, Any] = {}

    async def run() -> None:
        device = RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=own_number({"UUID": A_SYSTEM}) or ""))
        try:
            assert (await device.status())["state"] == "online"
            another_server(bmc, root=None)
            bmc.drop_connections()  # (a new lease ends the connections to the server that had the address)
            await asyncio.sleep(0.2)
            seen["waiting"] = device._lines.waiting()
            seen["ports"] = set(bmc.state.conversations)
        finally:
            await device.close()

    try:
        asyncio.run(run())
        assert seen["waiting"] is False  # (the sign-out makes a line of its own)
        after = [said for port, heard in bmc.state.conversations.items() if port not in seen["ports"] for said in heard]
        assert any(said.startswith("GET /redfish/v1/Systems/") for said in after), after  # (the compare, under the session)
        assert not any(said.startswith("DELETE") for said in after), after
        assert bmc.state.signed_out == 0
    finally:
        bmc.stop()


def client_of(device: RedfishDevice) -> object:
    return device._client
