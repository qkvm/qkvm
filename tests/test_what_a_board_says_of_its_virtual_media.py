"""What a server's controller says of its virtual media, as the outside review's fourth round (Codex, R4-M3 and LOWs)
read it: a board that named another description of its InsertMedia at every read grew a cache of the strings it named;
links it names stay on it; its remote media's status is read as a string; and a mount whose settings changed while it
was under way was sent with an HTTPS address and no password.
"""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from starlette.responses import JSONResponse
from qkvm import redfish
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_live import Wall
from tests.test_redfish import fast  # noqa: F401 (ephemeral wall + fast status looks)
from tests.test_virtual_media_on_a_server import a_server, media, media_settings, mount


def test_rotating_actioninfo_retains_unknown_strings_on_one_live_tile(tmp_path, monkeypatch):
    # Real socket requests for the drive and descriptors. Only observation in
    # qKVM is retaining the driver reference so its cache can be measured.
    fake = FakeBmc(BmcState(virtual_media="ami", rmedia=True, ami_standard_drive=True, ami_described=True))
    backend = fake._server.config.app
    revision = 0
    size = 64 * 1024
    requested = []
    seen = []
    original = redfish.RedfishDevice._told_kinds

    async def observe(self, drive, urgent):
        await original(self, drive, urgent)
        if self not in seen:
            seen.append(self)
    monkeypatch.setattr(redfish.RedfishDevice, "_told_kinds", observe)

    async def board(scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] == "http" and scope["method"] == "GET":
            if path.endswith("/VirtualMedia/CD1"):
                body = {"@odata.id": path, "Id": "CD1", "MediaTypes": ["CD"],
                        "Oem": {"Ami": {}}, "Actions": {"#VirtualMedia.InsertMedia": {
                            "@Redfish.ActionInfo": f"/redfish/v1/ReviewInfo/{revision}"}}}
                return await JSONResponse(body)(scope, receive, send)
            if path.startswith("/redfish/v1/ReviewInfo/"):
                suffix = path.rsplit("/", 1)[1]
                requested.append(suffix)
                token = ("X" * (size - len(suffix))) + suffix
                answer = {"Parameters": [{"Name": "TransferProtocolType", "AllowableValues": ["HTTP", token]}]}
                return await JSONResponse(answer)(scope, receive, send)
        await backend(scope, receive, send)

    fake._server.config.app = board
    fake.start()
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            tile = a_server(admin, fake)
            for revision in range(1, 9):  # noqa: B007 (read by the board above, as it answers)
                response = admin.get(media(tile))
                assert response.status_code == 200, response.text
            # The same link is cached. The old eight distinct strings remain
            # resident after a fresh look, not merely in flight during parsing.
            before = requested.count("8")
            assert before >= 1
            assert admin.get(media(tile)).status_code == 200
            assert requested.count("8") == before
            device = next(d for d in reversed(seen) if d.spec.id == tile)
            # (One answer kept, of the last description read, and nothing of the names it gave that qKVM does not know.)
            assert device._insert_told == ("/redfish/v1/ReviewInfo/8", True)
    finally:
        fake.stop()


def test_actioninfo_cannot_supply_another_destination_or_escape_redfish():
    unsafe = [None, {}, "https://elsewhere.invalid/redfish/v1/x", "//elsewhere.invalid/redfish/v1/x",
              "/redfish/v10/x", "/redfish/v1/../x", "/redfish/v1/%2e%2E/x",
              "/redfish/v1/%252e%252e/x", "/redfish/v1/%2fx", "/redfish/v1/%5Cx",
              "/redfish/v1/%00", "/redfish/v1/x?next=x", "/redfish/v1/%C0%AE", "/redfish/v1/" + "x" * 300]
    async def run():
        calls = []
        async def get(path, urgent, vital):
            calls.append((path, urgent, vital))
            return {"Parameters": [{"Name": "TransferProtocolType", "AllowableValues": [None, {"bad": True}, "HTTPS"]}]}
        obj = SimpleNamespace(_get=get, _insert_told=None)
        for info in [*unsafe, "/redfish/v1/Managers/Self/CD1/Info"]:
            drive = {"Actions": {"#VirtualMedia.InsertMedia": {"@Redfish.ActionInfo": info}}}
            await redfish.RedfishDevice._told_kinds(obj, drive, False)
        assert calls == [("/redfish/v1/Managers/Self/CD1/Info", False, False)]
        assert obj._insert_told == ("/redfish/v1/Managers/Self/CD1/Info", False)
    asyncio.run(run())


@pytest.mark.parametrize(("value", "expected"), [(" Disabled ", True), ("Enabled", False), (False, False), ([], False), (None, False)])
def test_remote_media_manager_status_is_read_as_a_string(value, expected):
    async def run():
        calls = []
        async def get(path, urgent, vital):
            calls.append((path, urgent, vital))
            return {"Oem": {"Ami": {"VirtualMedia": {"RMediaStatus": value}}}}
        manager = "/redfish/v1/Managers/1"
        obj = SimpleNamespace(_get=get, _places={"manager": manager})
        assert await redfish.RedfishDevice._rmedia_off(obj) is expected
        assert calls == [(manager, True, False)]
    asyncio.run(run())


@pytest.mark.parametrize("change_while_waiting", [False, True], ids=["fixed-https-control", "http-to-https-during-mount"])
def test_mount_address_and_transport_choice_are_from_one_setting(tmp_path, monkeypatch, change_while_waiting):
    # A rejecting fixture records InsertMedia without fetching the image.
    # The Async gate widens the wait between the two reads of media settings.
    # The real wall and actual HTTP admin settings/mount routes are used.
    entered, resume = threading.Event(), threading.Event()
    before_drive = redfish.RedfishDevice._drive_for_a_mount
    async def drive_for_mount(self, still):
        entered.set()
        assert await asyncio.to_thread(resume.wait, 7), "review gate timed out"
        return await before_drive(self, still)
    monkeypatch.setattr(redfish.RedfishDevice, "_drive_for_a_mount", drive_for_mount)
    fake = FakeBmc(BmcState(virtual_media="ami", rmedia=True, ami_standard_drive=True, ami_described=True,
                            media_insert_status=400)).start()
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            other_admin = live.browser()
            tile = a_server(admin, fake)
            images = tmp_path / "images"
            images.mkdir()
            (images / "review.iso").write_bytes(b"review fixture")
            https = live.url.replace("http://", "https://", 1)
            media_settings(admin, images, live.url if change_while_waiting else https)
            with ThreadPoolExecutor(1) as pool:
                work = pool.submit(mount, admin, tile, "review.iso")
                try:
                    assert entered.wait(6), "mount did not reach drive check"
                    if change_while_waiting:
                        media_settings(other_admin, images, https)
                finally:
                    resume.set()
                answer = work.result(10)
            assert answer.status_code >= 400
            (asked,) = fake.state.media_said
            assert urlsplit(asked["Image"]).scheme == "https"
            credentials = bool(asked.get("UserName") and asked.get("Password"))
            print(f"Selected scheme=https; InsertMedia URL scheme=https, transfer={asked['TransferProtocolType']}, "
                  f"mount credentials present={credentials}; settings changed={change_while_waiting}")
            assert (asked["TransferProtocolType"], credentials) == ("HTTPS", True)
    finally:
        resume.set()
        fake.stop()


def test_https_wall_serves_without_basic_if_its_setting_changed_during_mount(tmp_path, monkeypatch):
    """GET on a genuinely TLS-serving socket, owner switched from HTTP to HTTPS mid-mount."""
    import httpx
    from tests.fake_kvm import make_device_certificate
    from tests.test_wall import CSRF, PASSWORD
    from tests.test_virtual_media_on_a_server import reader

    entered, resume = threading.Event(), threading.Event()
    open_drive = redfish.RedfishDevice._drive_for_a_mount
    async def wait_before_drive(self, still):
        entered.set()
        assert await asyncio.to_thread(resume.wait, 8)
        return await open_drive(self, still)

    monkeypatch.setattr(redfish.RedfishDevice, "_drive_for_a_mount", wait_before_drive)
    monkeypatch.setattr(redfish, "TASK_EVERY", 0.05)
    cert, key = make_device_certificate(tmp_path / "tls")
    # (A controller that takes HTTPS: the one of AMI's that refuses it, the owner's, would refuse this mount for that.)
    fake = FakeBmc(BmcState(virtual_media="standard")).start()
    try:
        with Wall(tmp_path / "wall", serving={"ssl_certfile": str(cert), "ssl_keyfile": str(key)}) as live:
            http = live.url
            live.url = http.replace("http://", "https://", 1)
            with httpx.Client(base_url=live.url, headers=CSRF, verify=False, timeout=20) as admin:
                assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
                tile = a_server(admin, fake)
                images = tmp_path / "images"
                images.mkdir()
                payload = b"TLS read of synthetic image\n" * 100
                (images / "review.iso").write_bytes(payload)
                media_settings(admin, images, http)
                with ThreadPoolExecutor(1) as pool:
                    pending = pool.submit(mount, admin, tile, "review.iso")
                    try:
                        assert entered.wait(6)
                        media_settings(admin, images, live.url)
                    finally:
                        resume.set()
                    mounted = pending.result(10)
                assert mounted.status_code == 200, mounted.text
                (posted,) = fake.state.media_said
                assert posted["Image"].startswith(live.url + "/media/")
                with reader() as controller:
                    without_basic = controller.get(posted["Image"])
                print(f"TLS listener: mount={mounted.status_code}, transfer={posted['TransferProtocolType']}, "
                      f"username present={'UserName' in posted}, password present={'Password' in posted}, "
                      f"GET without Basic={without_basic.status_code}, exact image={without_basic.content == payload}")
                assert (without_basic.status_code, without_basic.content == payload) == (401, False)
    finally:
        resume.set()
        fake.stop()


@pytest.mark.parametrize("empty", [False, True], ids=["missing-list", "empty-list"])
def test_actioninfo_for_drive_with_no_listed_protocols(empty):
    gets=[]
    info="/redfish/v1/Managers/Self/ActionInfo"
    description={"@Redfish.ActionInfo":info}
    if empty:
        description["TransferProtocolType@Redfish.AllowableValues"]=[]
    drive={"Oem":{"Ami":{}}, "Actions":{"#VirtualMedia.InsertMedia":description}}
    async def get(path, urgent, vital):
        gets.append(path)
        return {"Parameters":[{"Name":"TransferProtocolType","AllowableValues":["HTTPS","HTTP"]}]}
    device=SimpleNamespace(_get=get,_insert_told=None)
    asyncio.run(redfish.RedfishDevice._told_kinds(device,drive,True))
    https_only=redfish.RedfishDevice._https_only(device,drive)
    print(f"explicit empty list={empty}, ActionInfo GETs={len(gets)}, HTTPS-only={https_only}")
    assert gets == [info] and not https_only
