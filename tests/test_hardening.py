"""Things that must hold however the outside world behaves: hostile devices, simultaneous changes, unsigned updates."""

from __future__ import annotations

import asyncio
import gzip
import os
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from qkvm import kvm, netbind, server, update, vault
from qkvm.core import Core
from qkvm.kvm import KvmError, bounded
from qkvm.server import _CHANGES, create_app
from qkvm.update import UpdateError, Updater
from tests.fake_github import FakeGitHub, make_wheel
from tests.fake_kvm import FakeKvm
from tests.test_users import OTHER, visitor
from tests.test_wall import CSRF, PASSWORD, add, snap, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


class AsItCame(httpx.AsyncByteStream):
    """A body handed over the way a device's arrives: as it was sent, unpacked by nobody yet."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._body


def answer_with(body: bytes, headers: dict[str, str] | None = None, asked: list[httpx.Request] | None = None) -> httpx.AsyncClient:
    """A client whose every request is answered with `body`, as a device of our choosing would. `asked`: the requests it got."""

    def reply(request: httpx.Request) -> httpx.Response:
        if asked is not None:
            asked.append(request)
        return httpx.Response(200, stream=AsItCame(body), headers={"content-length": str(len(body)), **(headers or {})})

    return httpx.AsyncClient(transport=httpx.MockTransport(reply), base_url="http://device")


def test_an_answer_is_read_only_up_to_the_limit() -> None:
    async def run() -> None:
        async with answer_with(b"x" * 500) as client:
            reply = await bounded(client, client.build_request("GET", "/"), 500)
            assert reply.content == b"x" * 500 and reply.status_code == 200
            with pytest.raises(KvmError):
                await bounded(client, client.build_request("GET", "/"), 499)
        # A few bytes on the wire that unpack to megabytes are measured by what they unpack to.
        bomb = gzip.compress(b"\0" * 5_000_000)
        assert len(bomb) < 10_000
        async with answer_with(bomb, {"content-encoding": "gzip"}) as client:
            with pytest.raises(KvmError):
                await bounded(client, client.build_request("GET", "/"), 100_000)
            small = gzip.compress(b'{"ok": true}')
        async with answer_with(small, {"content-encoding": "gzip", "set-cookie": "auth_token=abc"}) as client:
            reply = await bounded(client, client.build_request("GET", "/"), 100_000)
            assert reply.json() == {"ok": True}  # unpacked once, not twice
            assert reply.cookies.get("auth_token") == "abc"

    asyncio.run(run())


def test_a_packed_answer_is_unpacked_no_further_than_the_limit() -> None:
    # The HTTP library unpacks whatever arrives in one go, however much comes out of it, and hands that
    # over to be counted: a hundred bytes on the wire were megabytes in memory before anything was refused.
    # So unpacking is not left to it. A device is asked not to pack; what one packs all the same is
    # unpacked here, a piece at a time, and never beyond what is accepted.
    import tracemalloc
    import zlib

    async def refused(body: bytes, packing: str) -> str:
        async with answer_with(body, {"content-encoding": packing}) as client:
            with pytest.raises(KvmError) as error:
                await bounded(client, client.build_request("GET", "/"), 100_000)
        return error.value.code

    async def run() -> None:
        once = gzip.compress(bytes(16 << 20))
        assert len(once) < 20_000
        asked: list[httpx.Request] = []
        async with answer_with(once, {"content-encoding": "gzip"}, asked) as client:
            tracemalloc.start()
            try:
                with pytest.raises(KvmError) as error:
                    await bounded(client, client.build_request("GET", "/"), 100_000)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        assert error.value.code == "dropped"
        assert peak < 1_000_000, f"{peak} bytes were held while an answer of at most 100 000 was read"
        assert [request.headers.get("accept-encoding") for request in asked] == ["identity"]  # asked not to pack at all

        # Packed twice, or in a way nobody offers to unpack: not unpacked at all. ("dropped", like a connection
        # that broke off: what is tried again after it is tried with a pause that grows, a sign-in above all.)
        assert await refused(gzip.compress(once), "gzip, gzip") == "dropped"
        assert await refused(once, "gzip, deflate") == "dropped"
        assert await refused(zlib.compress(b'{"ok": true}'), "deflate") == "dropped"
        assert await refused(once, "br") == "dropped"
        # Said to be packed, and is not: the device's mistake, and said as that.
        assert await refused(b"this was never packed", "gzip") == "dropped"
        assert await refused(gzip.compress(b"x" * 5000)[:-12], "gzip") == "dropped"  # ...or it stops before its end
        assert await refused(once[: len(once) // 2], "gzip") == "dropped"  # (half of too much is still too much)
        # What arrives and yields nothing is read no further than a little over the limit, not for as long as there is time.
        nothing = bytes([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3]) + bytes([0, 0, 0, 255, 255]) * 60_000  # a gzip header, then 300 kB of blocks with nothing in them
        assert await refused(nothing, "gzip") == "dropped"
        # Nothing at all, said to be packed, is an answer with nothing in it.
        async with answer_with(b"", {"content-encoding": "gzip"}) as client:
            assert (await bounded(client, client.build_request("GET", "/"), 100_000)).content == b""

        # gzip under its other name, "identity" said out loud, and something after the end of what was packed: all read.
        small = gzip.compress(b'{"ok": true}')
        for body, packing in ((small, "x-gzip"), (small, "GZip"), (b'{"ok": true}', "identity"), (small + b"and more", "gzip")):
            async with answer_with(body, {"content-encoding": packing}) as client:
                reply = await bounded(client, client.build_request("GET", "/"), 100_000)
                assert reply.json() == {"ok": True}, packing
        # Exactly as much as is accepted is accepted, packed or not.
        async with answer_with(gzip.compress(b"x" * 500), {"content-encoding": "gzip"}) as client:
            assert (await bounded(client, client.build_request("GET", "/"), 500)).content == b"x" * 500
            with pytest.raises(KvmError):
                await bounded(client, client.build_request("GET", "/"), 499)

    asyncio.run(run())


def test_a_download_is_counted_as_it_is_sent_and_not_taken_packed(tmp_path: Path) -> None:
    # The same for what an update is made of: its size is that of what was sent, and nothing unpacks it on the way.
    updater = Updater(tmp_path, "someone/qkvm", keys=())

    async def run() -> None:
        async with answer_with(gzip.compress(bytes(16 << 20)), {"content-encoding": "gzip"}) as client:
            with pytest.raises(UpdateError, match="packed"):
                await updater._fetch(client, "http://files/wheel", 100_000)
        async with answer_with(b"x" * 501) as client:
            assert await updater._fetch(client, "http://files/wheel", 501) == (200, b"x" * 501)
            with pytest.raises(UpdateError, match="larger"):
                await updater._fetch(client, "http://files/wheel", 500)

    asyncio.run(run())


def test_a_kvm_that_sends_too_much_is_cut_off(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        monkeypatch.setattr(kvm, "MAX_PICTURE", 300)  # smaller than any picture the stand-in sends
        refused = client.get(snap(device))
        assert refused.status_code == 502 and refused.json()["code"] == "dropped"
        monkeypatch.setattr(kvm, "MAX_PICTURE", 32 * 1024 * 1024)
        monkeypatch.setattr(kvm, "MAX_REPLY", 20)  # ...and smaller than any status it sends
        assert client.get("/api/v1/status").json()[device]["state"] == "offline"
        assert client.get("/api/v1/wall").status_code == 200  # the wall itself is unharmed


def test_what_a_device_says_about_itself_is_not_taken_at_face_value(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.hostname = "rack-3" + chr(10) + "2026-10-07 qkvm WARNING admin signed in from 6.6.6.6" + chr(27) + "[31m"
    fake.state.model = {"not": "a name"}
    with wall(tmp_path) as client:
        made = client.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()
        device = made["device"]["id"]
        name = made["device"]["name"]
        assert chr(10) not in name and chr(27) not in name and name.startswith("rack-3 2026")  # one line: nothing to forge a log entry with
        assert made["about"]["model"] is None
        assert client.get("/api/v1/status").json()[device]["about"]["model"] is None

        # A "picture" that is a web page would be shown to whoever opens the picture's address.
        fake.state.picture_type = "text/html"
        refused = client.get(snap(device))
        assert refused.status_code == 502 and "not a picture" in refused.json()["message"]
        fake.state.picture_type = "image/png; charset=binary"
        assert client.get(snap(device)).headers["content-type"] == "image/png"


class LiveWall:
    """The app on a real localhost port, for what needs a real connection: a request that stops halfway."""

    def __init__(self, data: Path, **options: Any) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        config = uvicorn.Config(create_app(Core(data)), **{"log_level": "error", "access_log": False, **options})
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def __enter__(self) -> LiveWall:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            assert time.monotonic() < deadline, "the wall did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *_: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def test_a_request_sent_only_halfway_holds_up_nobody_else(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "BODY_TIMEOUT", 1.5)
    with LiveWall(tmp_path) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=10) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        # Somebody who is not signed in starts a request that changes things, and never finishes sending it.
        stalled = socket.create_connection(("127.0.0.1", live.port))
        head = "POST /api/v1/recover HTTP/1.1|Host: 127.0.0.1|X-QKVM: 1|Content-Type: application/json|Content-Length: 60000||{"
        stalled.sendall(head.replace("|", chr(13) + chr(10)).encode())
        time.sleep(0.3)
        started = time.monotonic()
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # changes still go through
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": OTHER}).status_code == 201
        assert time.monotonic() - started < 1.2  # ...at once, not when the other gives up
        stalled.settimeout(8)
        assert stalled.recv(32).startswith(b"HTTP/1.1 408")  # and the unfinished request is not waited for forever
        stalled.close()


def test_odd_input_before_sign_in_is_refused_not_crashed_on(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path, sign_in=False, address="10.0.0.9", setup_code=True) as stranger:
        # A setup code with a character outside ASCII: wrong like any other wrong code.
        reply = stranger.post("/api/v1/setup", json={"password": PASSWORD, "setup_code": "1234567" + chr(233)})
        assert (reply.status_code, reply.json()["code"]) == (403, "bad_setup_code")
        # An Origin header that is not an address: a cross-site request like any other, security headers and all.
        reply = stranger.post("/api/v1/login", json={"password": PASSWORD}, headers={"origin": "http://["})
        assert (reply.status_code, reply.json()["code"]) == (403, "forbidden")
        assert "frame-ancestors 'none'" in reply.headers["content-security-policy"]
        assert reply.headers["x-content-type-options"] == "nosniff"
    with wall(tmp_path / "second") as admin:
        device = add(admin, fake.url)
        odd = admin.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": "AB:" + chr(233)})
        assert odd.status_code in (200, 409, 502)  # http device: nothing to trust; the point is that it is not a 500


def test_a_device_cannot_hand_out_a_session_token_that_breaks_requests(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.token_reply = "t" + chr(0x20AC) + chr(10) + "x"  # a euro sign and a line break
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"})
        assert (reply.status_code, reply.json()["code"]) == (422, "no_sign_in") and "no session token" in reply.json()["message"]
        fake.state.token_reply = None
        assert admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).status_code == 201


def test_two_simultaneous_changes_cannot_both_win(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        second = visitor(admin, 50040)
        assert second.post("/api/v1/login", json={"password": "correct horse battery"}).status_code == 200
        new_account = {"name": "olga", "role": "operator", "password": OTHER}
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda browser: browser.post("/api/v1/users", json=new_account), [admin, second]))
        assert sorted(reply.status_code for reply in replies) == [201, 409]
        assert [u["name"] for u in admin.get("/api/v1/users").json()["users"]] == ["admin", "olga"]


def test_which_requests_are_handled_one_at_a_time() -> None:
    for change in (
        "POST /api/v1/users", "PUT /api/v1/users/ab12", "DELETE /api/v1/users/ab12", "DELETE /api/v1/devices/ab12",
        "POST /api/v1/actions", "PUT /api/v1/actions/ab12", "DELETE /api/v1/actions/ab12", "PUT /api/v1/settings", "PUT /api/v1/update",
        "PUT /api/v1/alerts", "POST /api/v1/password", "POST /api/v1/recover", "POST /api/v1/recovery", "POST /api/v1/setup",
        "POST /api/v1/totp/enable", "POST /api/v1/totp/disable",
    ):  # fmt: skip
        assert _CHANGES.fullmatch(change), change
    for other in (
        "POST /api/v1/devices/ab12/actions",  # typing a long text on one KVM must not hold up everything else
        # These talk to the KVM first, which can take seconds, and take their turn only for what they save
        # (see tests/test_load.py).
        "POST /api/v1/devices", "PUT /api/v1/devices/ab12", "POST /api/v1/devices/ab12/trust",
        "POST /api/v1/login", "POST /api/v1/logout", "POST /api/v1/discover", "POST /api/v1/update/install", "GET /api/v1/users",
        "POST /api/v1/alerts/test",
    ):  # fmt: skip
        assert not _CHANGES.fullmatch(other), other


def test_an_update_nobody_signed_is_not_installed_unasked(tmp_path: Path) -> None:
    github = FakeGitHub().start()
    try:
        github.publish("2.0.0", make_wheel("2.0.0"))
        cautious = Updater(tmp_path, github.repo, api=github.url, keys=(), current="1.0.0")

        async def run() -> None:
            await cautious.check()
            assert cautious.available and cautious.view()["installable"] is False
            with pytest.raises(UpdateError, match="--allow-unsigned-updates"):
                await cautious.install()

        asyncio.run(run())
        assert not (tmp_path / "updates").exists() or not any((tmp_path / "updates").iterdir())  # nothing was unpacked
        assert Updater(tmp_path, github.repo, api=github.url, keys=(), allow_unsigned=True).view()["installable"] is True
    finally:
        github.stop()


def test_the_tailscale_tool_is_never_taken_from_the_current_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    name = "tailscale.exe" if os.name == "nt" else "tailscale"
    here = tmp_path / "started-here"
    here.mkdir()
    (here / name).write_text("not the real one")
    monkeypatch.chdir(here)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nothing-installed"))
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", "relative/bin"]))
    if os.name != "nt" and Path("/Applications/Tailscale.app").exists():
        pytest.skip("a real Tailscale is installed in its standard place")
    assert netbind.tailscale_command() is None
    installed = tmp_path / "bin"
    installed.mkdir()
    (installed / name).write_text("the installed one")
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(installed)]))
    assert netbind.tailscale_command() == str(installed / name)


# --- behind a proxy ------------------------------------------------------------------------------------


def test_a_proxy_that_was_named_is_believed_about_who_is_calling_and_no_other(tmp_path: Path) -> None:
    # Behind a reverse proxy on another address every visitor arrives from the proxy's address. Unless
    # qKVM is told that it is one, five wrong passwords by anybody lock everybody out, and the cookie
    # goes out as if the visitor had come without HTTPS.
    from tests.test_wall import PASSWORD, wall

    def sign_in(client: Any, password: str, came_from: str) -> Any:
        return client.post("/api/v1/login", json={"password": password}, headers={"X-Forwarded-For": came_from, "X-Forwarded-Proto": "https"})

    with wall(tmp_path):
        pass  # set up, from this computer
    with wall(tmp_path, sign_in=False, address="172.18.0.2") as client:  # not named: what it says about its visitors is not believed
        assert [sign_in(client, "wrong", "198.51.100.7").status_code for _ in range(5)] == [401] * 5
        assert sign_in(client, PASSWORD, "203.0.113.9").status_code == 429  # one address, as far as qKVM can tell

    core_options = {"trusted_proxies": ("172.18.0.0/16",)}
    with wall(tmp_path, sign_in=False, address="172.18.0.2", **core_options) as client:
        assert [sign_in(client, "wrong", "198.51.100.7").status_code for _ in range(5)] == [401] * 5
        assert sign_in(client, "wrong", "198.51.100.7").status_code == 429  # the one who guessed is locked out
        welcome = sign_in(client, PASSWORD, "203.0.113.9")  # and nobody else is
        assert welcome.status_code == 200
        assert "secure" in welcome.headers["set-cookie"].lower()  # the visitor came over HTTPS, the proxy says
        # Read from the right: what the visitor wrote into the header themselves comes before what the proxy added.
        assert sign_in(client, "wrong", "203.0.113.50, 198.51.100.7").status_code == 429
        entries = client.core.audit.tail(50)  # type: ignore[attr-defined]
        seen_from = [entry["ip"] for entry in entries if entry["event"] == "login_failed"]
        # The log, newest first: it names the one who guessed, and the proxy for as long as that was not believed.
        assert seen_from == ["198.51.100.7"] * 5 + ["172.18.0.2"] * 5


def test_once_a_proxy_is_named_this_computer_is_not_believed_as_one_unasked(tmp_path: Path) -> None:
    # A proxy on the same computer is believed without an option, so that one works as it comes. But so is
    # any program there that says it is one: each wrong guess "from" another address, never locked out, and
    # the activity log naming addresses of its choosing. Whoever names their proxies has said who is believed.
    from tests.test_wall import PASSWORD, wall

    def sign_in(client: Any, password: str, came_from: str) -> Any:
        return client.post("/api/v1/login", json={"password": password}, headers={"X-Forwarded-For": came_from})

    with wall(tmp_path):
        pass
    with wall(tmp_path, sign_in=False, address="127.0.0.1", trusted_proxies=("172.18.0.0/16",)) as client:
        assert [sign_in(client, "wrong", f"198.51.100.{number}").status_code for number in range(5)] == [401] * 5
        assert sign_in(client, PASSWORD, "203.0.113.9").status_code == 429  # all of them were this computer, and it is locked out
        assert {entry["ip"] for entry in client.core.audit.tail(50) if entry["event"] == "login_failed"} == {"127.0.0.1"}  # type: ignore[attr-defined]
    with wall(tmp_path, sign_in=False, address="127.0.0.1", trusted_proxies=("172.18.0.0/16", "127.0.0.1")) as client:
        assert [sign_in(client, "wrong", "198.51.100.7").status_code for _ in range(5)] == [401] * 5
        assert sign_in(client, PASSWORD, "203.0.113.9").status_code == 200  # named, it is believed as before
    with wall(tmp_path, sign_in=False, address="127.0.0.1") as client:  # and where none is named, as it comes
        assert [sign_in(client, "wrong", "198.51.100.8").status_code for _ in range(5)] == [401] * 5
        assert sign_in(client, PASSWORD, "203.0.113.9").status_code == 200


def test_the_addresses_of_one_ipv6_network_count_as_one(tmp_path: Path) -> None:
    # Whoever has one IPv6 address has the 18 million million million others of its /64 to guess from next.
    from qkvm.security import Limiter

    limiter = Limiter()
    for last in range(Limiter.FREE):
        limiter.fail(f"2001:db8:1:2::{last + 1:x}")
    assert limiter.retry_after("2001:db8:1:2:ffff::9") > 0  # the same /64
    assert limiter.retry_after("2001:db8:1:3::1") == 0  # the one next door
    assert limiter.retry_after("::ffff:192.0.2.1") == 0 and limiter.retry_after("192.0.2.1") == 0
    for _ in range(Limiter.FREE):
        limiter.fail("::ffff:192.0.2.1")  # an IPv4 address written the IPv6 way is that IPv4 address
    assert limiter.retry_after("192.0.2.1") > 0 and limiter.retry_after("192.0.2.2") == 0


def test_the_web_server_does_not_read_the_forwarding_headers_by_itself(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # It would, for a proxy on this computer and for whatever FORWARDED_ALLOW_IPS says in its environment:
    # a second opinion on who is calling, that nothing in qKVM's settings or documentation knows of.
    from qkvm import cli

    assert cli.SERVER_OPTIONS["proxy_headers"] is False
    # What is not an address is said at the start, not found out when the first visitor is misjudged.
    assert cli.main(["--data-dir", str(tmp_path), "--trusted-proxy", "the-proxy", "--disable-2fa", "nobody"]) == 2
    assert "the-proxy" in capsys.readouterr().err
    assert cli.main(["--data-dir", str(tmp_path), "--trusted-proxy", "10.0.0.5, 172.18.0.0/16", "--disable-2fa", "nobody"]) == 2  # no such account
    assert "no account called nobody" in capsys.readouterr().err


# --- what a device cannot make qKVM do -----------------------------------------------------------------


class Elsewhere:
    """An address that is not the device's: it counts who comes, and may give every caller the same answer."""

    def __init__(self, answer: bytes = b"") -> None:
        from tests import local_socket

        self._sock = local_socket()
        self._sock.listen()
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.callers = 0
        self._answer = answer
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                caller, _ = self._sock.accept()
            except OSError:
                return
            self.callers += 1
            with caller:
                try:
                    caller.settimeout(2)
                    caller.recv(65536)
                    if self._answer:
                        caller.sendall(self._answer)
                except OSError:
                    pass

    def close(self) -> None:
        self._sock.close()


def test_a_device_cannot_send_qkvm_on_to_another_address(fake: FakeKvm) -> None:
    # The connection that keeps a KVM's video awake is a websocket, and the library that makes it follows a
    # redirect, to any host, taking the KVM's session cookie along. A device does not get to point qKVM,
    # from where qKVM sits in the network, at something else.
    elsewhere = Elsewhere()
    fake.state.ws_moved = f"ws://127.0.0.1:{elsewhere.port}/any/path"

    async def connect() -> BaseException | None:
        try:
            async with kvm.ws_connect(f"ws://127.0.0.1:{fake.port}/api/ws", additional_headers={"Cookie": "auth_token=x"}, open_timeout=3):
                return None
        except Exception as ex:  # whatever it is, it is looked at below
            return ex

    refused = asyncio.run(connect())
    elsewhere.close()
    assert refused is not None and "302" in str(refused)
    assert elsewhere.callers == 0


def test_devices_are_talked_to_directly_whatever_proxy_this_computer_is_set_to_use(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A KVM is on the local network. Where the computer qKVM runs on is told to use a proxy for the web (in
    # a company, as a rule; Docker hands such settings on to its containers), the KVM's password must not
    # be sent there, and the KVM must not be "unreachable" because the proxy cannot see it.
    from tests.test_wall import add, snap, wall

    proxy = Elsewhere(b"HTTP/1.1 502 Bad Gateway" + bytes([13, 10]) + b"Content-Length: 0" + bytes([13, 10, 13, 10]))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "WS_PROXY", "WSS_PROXY"):
        monkeypatch.setenv(name, proxy.url)
        monkeypatch.setenv(name.lower(), proxy.url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200

    async def keep_awake() -> None:
        token = next(iter(fake.state.tokens))
        async with kvm.ws_connect(f"ws://127.0.0.1:{fake.port}/api/ws", additional_headers={"Cookie": f"auth_token={token}"}, open_timeout=3):
            pass

    asyncio.run(keep_awake())
    proxy.close()
    assert proxy.callers == 0


class Talkative:
    """The signalling connection of a JetKVM that says what it is told to, and then the same thing for ever."""

    def __init__(self, first: list[dict[str, Any]], then: dict[str, Any], pause: float = 0.002) -> None:
        self.first, self.then, self.said, self.pause = list(first), then, 0, pause

    async def recv_streaming(self) -> AsyncIterator[str]:  # (a message is read as the pieces it arrives in: here, one)
        import json

        await asyncio.sleep(self.pause)
        self.said += 1
        yield json.dumps(self.first.pop(0) if self.first else self.then)


def test_a_jetkvm_that_never_stops_talking_does_not_fill_the_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    # After the request for video a JetKVM sends its answer and then the addresses it can be reached at, one
    # message each. Every one was kept, for as long as they kept coming: whoever answers for a JetKVM (it
    # serves plain HTTP by default) could send them until the computer qKVM runs on had no memory left.
    import base64
    import json

    from qkvm import jetkvm

    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 0.3)
    monkeypatch.setattr(jetkvm, "CANDIDATE_WAIT", 0.3)
    address = {"type": "new-ice-candidate", "data": {"candidate": "candidate:1 1 udp 1 192.0.2.1 9 typ host " + "x" * 100_000}}

    async def within(seconds: float, ws: Talkative) -> Any:
        return await asyncio.wait_for(jetkvm._await_answer(kvm.Listening(ws, 2**20)), seconds)

    # No answer, only addresses, without end: given up on when the time for an answer is over.
    endless = Talkative([], address)
    with pytest.raises(KvmError) as gave_up:
        asyncio.run(within(5, endless))
    assert gave_up.value.code == "timeout"

    # An answer, and then addresses without end: taken as answered, with a few of them and each of a sane length.
    answer = {"type": "answer", "data": base64.b64encode(json.dumps({"sdp": "v=0"}).encode()).decode()}
    sdp, addresses = asyncio.run(within(5, Talkative([answer], address)))
    assert sdp == "v=0" and 0 < len(addresses) <= jetkvm.MAX_CANDIDATES and max(map(len, addresses)) <= 1000

    # Not shaped the way it should be, it is not an address, and not a reason to fall over either.
    odd = {"type": "new-ice-candidate", "data": ["not", "a", "dictionary"]}
    assert asyncio.run(within(5, Talkative([answer, odd, odd], {"type": "none of the above"})))[1] == []

    # Its refusal is one short line, whatever it sent: it ends up in the tile, the status and the activity log.
    refusal = Talkative([{"error": "no" + chr(10) + "video " + "x" * 500_000}], address)
    with pytest.raises(KvmError) as refused:
        asyncio.run(within(5, refusal))
    assert len(refused.value.message) < 300 and chr(10) not in refused.value.message and "no video" in refused.value.message


def test_an_answer_nested_too_deep_to_read_is_just_a_wrong_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Sixty thousand opening brackets are valid as the start of JSON and more than the reader can follow.
    # What it raises then is not the error for "this is not JSON", and went uncaught: any machine on the
    # network, asked "are you a KVM?" during a search, could make every search end in an error.
    from qkvm import discover
    from tests.test_wall import wall

    body = b"[" * 60_000
    head = "HTTP/1.1 200 OK|Content-Type: application/json|Content-Length: %d|Connection: close||" % len(body)
    deep = Elsewhere(head.replace("|", chr(13) + chr(10)).encode() + body)
    monkeypatch.setattr(discover, "targets", lambda: ([discover.Target("127.0.0.1", deep.url, deep.url)], ["test network"]))
    with wall(tmp_path) as admin:
        result = admin.post("/api/v1/discover")
        assert result.status_code == 200 and result.json()["found"] == []
        # Typed in as an address to add, the same machine is "not a KVM", not a crash.
        added = admin.post("/api/v1/devices", json={"url": deep.url, "password": "secret"})
        assert added.status_code == 422, added.text
    deep.close()
    assert deep.callers > 0

    assert kvm.plain("a" + chr(10) + "b" * 1_000_000, 20) == "a " + "b" * 18  # and a megabyte of "text" is cut before it is looked at


def test_a_picture_that_says_it_is_enormous_is_not_handed_to_a_browser(tmp_path: Path, fake: FakeKvm) -> None:
    # Sixteen thousand pixels square, all one colour: a hundred kilobytes to send, and a gigabyte for the
    # browser that unpacks it to see how to fit it into a tile. Every second, on every screen that shows
    # the wall. What a picture says its size is stands in its first bytes, and is read before it is passed on.
    from tests.fake_kvm import _png
    from tests.test_wall import add, snap, wall

    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        fake.state.picture = _png(16000, 16000, b"")
        refused = client.get(snap(device))
        assert refused.status_code == 502 and "16000 by 16000" in refused.json()["message"]
        fake.state.picture = b"GIF89a" + bytes(200)  # called a PNG by the device, and not one
        assert "not a picture" in client.get(snap(device)).json()["message"]
        fake.state.picture = b""
        assert client.get(snap(device)).status_code == 200

    assert kvm.picture_size(_png(1920, 1080, b"")) == (1920, 1080)
    # A JPEG: its start, a part to skip, a table to skip, and the part that says 1080 lines of 1920 pixels.
    jpeg = bytes.fromhex("ffd8" "ffe000104a46494600010100000100010000" "ffdb00040000" "ffc0001108" "0438" "0780" "03012200021101031101")
    assert kvm.picture_size(jpeg) == (1920, 1080)
    for not_one in (b"", bytes.fromhex("ffd8ff"), bytes.fromhex("ffd8ffe0"), b"<html>", jpeg[:20]):
        assert kvm.picture_size(not_one) is None


def test_a_connection_that_asks_for_nothing_is_not_kept_for_ever(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Nobody has to sign in to open a connection. One that then sends nothing, or the first half of a request
    # and no more, was kept for as long as its maker liked: enough of them, and there is no connection left
    # for a browser, or for qKVM to reach a device with. The web server only kept time between two requests.
    from qkvm import cli

    monkeypatch.setattr(cli, "HEADERS_WITHIN", 0.6)
    with LiveWall(tmp_path, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, timeout=10) as browser:
        silent = socket.create_connection(("127.0.0.1", live.port))
        halfway = socket.create_connection(("127.0.0.1", live.port))
        halfway.sendall("GET /healthz HTTP/1.1|Host: 127.0.0.1|X-Slow: ".replace("|", chr(13) + chr(10)).encode())
        assert browser.get("/healthz").status_code == 200
        for stalled in (silent, halfway):
            stalled.settimeout(5)
            assert stalled.recv(100) == b""  # closed, by qKVM
            stalled.close()
        # Whoever asks properly is served as before, a second time on the connection they have, and after a
        # pause longer than the clock for asking.
        assert browser.get("/healthz").status_code == 200
        time.sleep(1.0)
        assert browser.get("/healthz").json()["status"] == "ok"
        # There is nothing in qKVM that is talked to over a websocket, and so no way in for one.
        upgrade = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
        assert browser.get("/api/ws", headers=upgrade).status_code in (401, 404)


# --- who may come, and how -----------------------------------------------------------------------------


def test_only_the_addresses_that_were_named_get_an_answer(tmp_path: Path) -> None:
    # "Only from the management network": with --allow-from, anybody else is turned away before there is a
    # sign-in page to guess at. This computer itself is always let in; a monitor's check, and the way back
    # in for whoever got the list wrong, depend on that.
    from fastapi.testclient import TestClient

    from tests.test_wall import CSRF, PASSWORD, wall

    def from_address(admin: Any, address: str, **headers: str) -> Any:
        client = TestClient(admin.app, headers={**CSRF, **headers}, client=(address, 40000))
        client.portal = admin.portal
        return client

    with wall(tmp_path, allow_from=("192.0.2.0/24", "2001:db8::/32"), trusted_proxies=("10.0.0.5",)) as admin:  # set up from this computer
        assert admin.get("/healthz").status_code == 200
        inside = from_address(admin, "192.0.2.77")
        assert inside.get("/healthz").status_code == 200 and inside.get("/").status_code == 200
        assert inside.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert from_address(admin, "2001:db8:5::1").get("/healthz").status_code == 200
        outside = from_address(admin, "198.51.100.9")
        for path in ("/", "/healthz", "/api/v1/session", "/static/app.js", "/metrics"):
            turned_away = outside.get(path)
            assert turned_away.status_code == 403 and "not allowed" in turned_away.text, path
        assert outside.post("/api/v1/login", json={"password": PASSWORD}).status_code == 403
        # Through the proxy that was named, it is the visitor's address that counts, not the proxy's.
        assert from_address(admin, "10.0.0.5", **{"X-Forwarded-For": "192.0.2.8"}).get("/healthz").status_code == 200
        assert from_address(admin, "10.0.0.5", **{"X-Forwarded-For": "198.51.100.9"}).get("/healthz").status_code == 403
        assert from_address(admin, "10.0.0.5").get("/healthz").status_code == 403  # the proxy itself is nobody
        # A proxy may add a line of its own to a header the visitor has already sent one of (HAProxy does):
        # the visitor's line comes first, and is the visitor's word, however many lines it is spread over.
        forged = from_address(admin, "10.0.0.5").get("/healthz", headers=[("X-Forwarded-For", "192.0.2.8"), ("X-Forwarded-For", "198.51.100.9")])
        assert forged.status_code == 403
        # An IPv4 address written the IPv6 way is that IPv4 address.
        assert from_address(admin, "::ffff:192.0.2.77").get("/healthz").status_code == 200
        assert from_address(admin, "::ffff:198.51.100.9").get("/healthz").status_code == 403
        # A proxy on this computer passing somebody on is not "this computer".
        assert from_address(admin, "127.0.0.1", **{"X-Forwarded-For": "198.51.100.9"}).get("/healthz").status_code == 403

    with wall(tmp_path, sign_in=False) as anybody:  # without the option, as before
        assert from_address(anybody, "198.51.100.9").get("/healthz").status_code == 200


def test_https_from_the_first_request_with_a_certificate_of_ones_own(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Switched on in the settings, HTTPS begins after the first password has been chosen over plain HTTP. In a
    # container, where the port is published to the whole network, that password and the setup code went out
    # in clear. --https has it encrypted from the first request; --tls-cert and --tls-key bring a certificate
    # the company's browsers trust already.
    import ssl

    from qkvm import cli
    from qkvm.tlscert import ensure_certificate
    from tests.test_wall import wall

    cert, key, fingerprint = ensure_certificate(tmp_path / "own", ["127.0.0.1"])
    data = tmp_path / "data"
    with wall(data, https=True) as client:
        settings = client.get("/api/v1/settings").json()
        assert settings["https"] is True and settings["https_forced"] is True
        assert client.core.https is True and client.core.tls_files is None  # type: ignore[attr-defined]
        # It was said at start; the page cannot take it back.
        saved = client.put("/api/v1/settings", json={"bind": ["local"], "port": 8787, "https": False, "interval": 1})
        assert saved.status_code == 200 and client.get("/api/v1/settings").json()["https"] is True
    with wall(data, sign_in=False, tls_files=(cert, key)) as client:
        assert client.core.https is True and client.core.cert_fingerprint == fingerprint  # type: ignore[attr-defined]
    with wall(data, sign_in=False) as client:
        assert client.core.https is False  # type: ignore[attr-defined]

    # What does not fit together is said at start, not found out by the first browser.
    stray_key = ensure_certificate(tmp_path / "other", ["127.0.0.1"])[1]
    for options, complaint in (
        (["--tls-cert", str(cert)], "--tls-key"),
        (["--tls-cert", str(tmp_path / "nothing.pem"), "--tls-key", str(key)], "nothing.pem"),
        (["--tls-cert", str(cert), "--tls-key", str(stray_key)], "do not belong together"),
        (["--allow-from", "the-office"], "the-office"),
        (["--allow-from", ","], "--allow-from"),  # a list that turned out empty must not mean "everybody"
        (["--allow-from", ""], "--allow-from"),
        (["--trusted-proxy", " "], "--trusted-proxy"),
    ):
        assert cli.main(["--data-dir", str(data), *options, "--disable-2fa", "nobody"]) == 2
        assert complaint in capsys.readouterr().err, options
    assert isinstance(cli.tls_pair(str(cert), str(key)), tuple)
    with pytest.raises((ssl.SSLError, ValueError, OSError)):
        cli.tls_pair(str(cert), str(stray_key))


def test_the_health_check_says_when_nothing_is_being_watched(tmp_path: Path) -> None:
    # After a restart qKVM cannot reach a single device until somebody signs in: that is what keeps the saved
    # passwords from whoever takes the disk. It is also the moment (the power was out) when being told matters
    # most, and until now nothing said so: a monitor asking /healthz heard "ok".
    # (Started to keep no key of its own, which is where a restart leaves it locked. As it comes qKVM
    # keeps one and carries on by itself; this test ran that way, and passed only where the first wall was
    # closed before its key had been made to fit, which is a matter of a moment. A reviewer saw it fail.)
    from tests.test_wall import PASSWORD, wait_until, wall

    with wall(tmp_path, locked_start=True) as client:
        assert client.get("/healthz").json()["locked"] is False
    with wall(tmp_path, sign_in=False, locked_start=True) as client:
        assert client.get("/healthz").json()["locked"] is True
        assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert client.get("/healthz").json()["locked"] is False
    with wall(tmp_path / "new", sign_in=False) as client:  # not set up yet: nothing to be locked out of
        assert client.get("/healthz").json()["locked"] is False
    # As it comes: once its own key fits, a restart leaves nothing locked, and the health check says that too.
    with wall(tmp_path / "as it comes") as client:
        wait_until(lambda: client.core.store.unlock is not None, "qKVM's own key was never made to fit")  # type: ignore[attr-defined]
    with wall(tmp_path / "as it comes", sign_in=False) as client:
        assert client.get("/healthz").json()["locked"] is False


# --- what a second reading of the fixes found in the fixes -----------------------------------------------------


def test_a_key_that_cannot_be_read_is_said_at_start_in_a_sentence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ssl

    from qkvm import cli
    from qkvm.tlscert import ensure_certificate

    cert, key, _ = ensure_certificate(tmp_path, ["127.0.0.1"])

    def not_for_you(self: ssl.SSLContext, *args: Any, **options: Any) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", not_for_you)
    with pytest.raises(ValueError, match="cannot be read"):  # and not a traceback: the key belongs to root, the service does not
        cli.tls_pair(str(cert), str(key))
    monkeypatch.undo()

    # A key with a passphrase: the library would stop and ask for it on the terminal, where a service has nobody.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    locked = tmp_path / "locked.pem"
    locked.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"open sesame")))
    with pytest.raises(ValueError, match="passphrase"):
        cli.tls_pair(str(cert), str(locked))


def test_settings_that_could_not_be_listened_on_take_back_only_where_it_listens() -> None:
    # A port that turns out to be taken: qKVM goes back to where it listened before. It used to go back to
    # everything that was set at that time, a metrics token that had since been withdrawn included.
    from qkvm import cli
    from qkvm.store import ServerSettings

    settings = ServerSettings(bind=["local", "lan"], port=8787, https=True, metrics_token="the one that leaked")
    before = cli.listening_as(settings)
    settings.bind, settings.port, settings.https = ["local"], 80, False
    settings.metrics_token, settings.update_check = "its replacement", False
    cli.listen_again_as(settings, before)
    assert (settings.bind, settings.port, settings.https) == (["local", "lan"], 8787, True)
    assert settings.metrics_token == "its replacement" and settings.update_check is False


def test_ten_thousand_wrong_guesses_do_not_break_the_count() -> None:
    from qkvm.security import Limiter

    limiter = Limiter()
    for _ in range(1100):  # the lock doubles each time; left to itself, the sum stopped being a number at the 1029th
        limiter.fail("192.0.2.1", "admin")
    assert 0 < limiter.retry_after("192.0.2.1") <= Limiter.LONGEST


def test_the_wait_said_is_never_longer_than_the_lock_whatever_the_clock_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    # The lock's end is "now plus the lock", and the wait said is "that minus now". Where the clock stands
    # still between the two, as it does for sixteen thousandths of a second at a time on Windows before Python
    # 3.13, that is the same now, and for one value of it in five floating point makes (now + 900.0) - now a
    # hair more than 900.0: the wait said was 900.0000000000005 s, "try again in 901 s", and the test above
    # failed by what the clock happened to read. The same for the first lock of thirty seconds
    # (30.000000000000455: "try again in 31 s") and every length between. The clock here reads a value that
    # does both, and stands still.
    from qkvm import security
    from qkvm.security import Limiter

    standing_still = 4066.002
    for lock in (Limiter.BASE, Limiter.LONGEST):
        assert (standing_still + lock) - standing_still > lock  # a value that does what it is here for

    class Clock:
        monotonic = staticmethod(lambda: standing_still)
        time = staticmethod(time.time)

    monkeypatch.setattr(security, "time", Clock)
    limiter = Limiter()
    for _ in range(Limiter.FREE):
        limiter.fail("192.0.2.1", "admin")
    assert limiter.retry_after("192.0.2.1") == Limiter.BASE
    for _ in range(1100):
        limiter.fail("192.0.2.1", "admin")
    assert limiter.retry_after("192.0.2.1") == Limiter.LONGEST


def test_a_picture_is_judged_by_its_beginning_and_quickly(fake: FakeKvm) -> None:
    # Whether something is a picture, and of what size, stands in its first bytes. Thirty-two megabytes of
    # nothing that go on claiming to be the start of a JPEG were walked through byte by byte, on the thread
    # that serves every browser: seconds of nothing else happening, for every such "picture", every second.
    endless = bytes.fromhex("ffd8") + bytes([255]) * (32 * 2**20)
    segments = bytes.fromhex("ffd8") + bytes.fromhex("ffe00002") * (8 * 2**20)
    for data in (endless, segments):
        began = time.monotonic()
        assert kvm.picture_size(data) is None
        assert time.monotonic() - began < 0.3


def test_a_caller_who_never_reads_the_answer_is_let_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Asking properly and then not taking the answer is the same nuisance as not asking: the page's script is
    # there for anybody, and a connection waiting to hand it over is held for as long as its taker likes.
    from qkvm import cli

    monkeypatch.setattr(cli, "STALLED_AFTER", 0.5)
    live = LiveWall(tmp_path, **cli.SERVER_OPTIONS)
    # As over a network, where the system keeps little of an answer ready for a caller that takes none of it.
    # (On this computer alone it would swallow all of it, and nothing would be left waiting to be seen.)
    live._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    with live, httpx.Client(base_url=live.url, timeout=10) as browser:
        greedy = socket.socket()
        greedy.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        greedy.connect(("127.0.0.1", live.port))
        greedy.sendall("GET /static/app.js HTTP/1.1|Host: 127.0.0.1||".replace("|", chr(13) + chr(10)).encode())
        mine = greedy.getsockname()[1]

        def held() -> bool:
            return any(getattr(connection, "client", None) and connection.client[1] == mine for connection in live._server.server_state.connections)

        time.sleep(0.3)
        assert held()
        deadline = time.monotonic() + 6
        while held():
            assert time.monotonic() < deadline, "the connection was kept although nothing of the answer was taken"
            time.sleep(0.2)
        greedy.close()
        # Somebody who takes what is sent, however large, is served as before.
        assert len(browser.get("/static/app.js").content) > 100_000


def test_an_answer_that_is_not_taken_is_not_waited_with_for_ever(monkeypatch: pytest.MonkeyPatch) -> None:
    # The same, without a system's own buffers in between: how much of an answer those swallow before the
    # web server notices that nobody is taking it differs from one system to the next (Windows takes all of
    # the page's script), and with it what the test above is able to show.
    from uvicorn.server import ServerState

    from qkvm import cli

    monkeypatch.setattr(cli, "STALLED_AFTER", 0.1)

    class Line(asyncio.Transport):
        def __init__(self, waiting: int) -> None:
            super().__init__()
            self.waiting, self.dropped = waiting, False

        def get_write_buffer_size(self) -> int:
            return self.waiting

        def is_closing(self) -> bool:
            return self.dropped

        def abort(self) -> None:
            self.dropped = True

        def close(self) -> None:
            pass

    async def nothing(scope: Any, receive: Any, send: Any) -> None:
        return None

    async def handed_over(taken_each_time: int) -> bool:
        """Whether a connection with 200,000 bytes waiting is still there after half a second."""
        config = uvicorn.Config(nothing, **cli.SERVER_OPTIONS)
        line, http = Line(200_000), cli.Http(config, ServerState(), {})
        http.connection_made(line)
        http.pause_writing()  # what the system says when more is waiting than it keeps ready
        for _ in range(25):
            await asyncio.sleep(0.02)
            line.waiting = max(0, line.waiting - taken_each_time)
        http.connection_lost(None)
        return not line.dropped

    assert asyncio.run(handed_over(0)) is False  # takes nothing: let go
    assert asyncio.run(handed_over(20)) is False  # a few bytes now and then, to look alive: let go
    assert asyncio.run(handed_over(5_000)) is True  # slow, and getting there: waited for
    assert asyncio.run(handed_over(50_000)) is True  # took it all: nothing to wait for


def test_https_said_at_start_is_what_is_served(tmp_path: Path) -> None:
    # Not only a flag that says so: the program as it listens, asked the way a browser asks.
    from qkvm import cli
    from tests import local_socket

    with local_socket() as probe:
        port = probe.getsockname()[1]
    core = Core(tmp_path, bind_override=["local"], port_override=port, https=True)
    served = threading.Thread(target=cli.serve, args=(core,), daemon=True)
    served.start()
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                reply = httpx.get(f"https://127.0.0.1:{port}/healthz", verify=False, timeout=2)
                break
            except httpx.HTTPError:
                assert time.monotonic() < deadline, "nothing was served over HTTPS"
                time.sleep(0.2)
        assert reply.status_code == 200 and reply.json()["status"] == "ok"
        with pytest.raises(httpx.HTTPError):  # and nothing answers in clear
            httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2)
    finally:
        core.exit_status = 0
        while core.stop is None and served.is_alive():
            time.sleep(0.05)
        if core.stop:
            core.stop()
        served.join(timeout=10)


def test_an_address_that_is_locked_out_adds_nothing_more_to_the_activity_log(tmp_path: Path) -> None:
    # Each wrong guess is written down. Once an address is locked out its guesses are no longer looked at,
    # and no longer written down either: the log is not a thing a stranger gets to fill at will.
    from fastapi.testclient import TestClient

    with wall(tmp_path) as admin:
        stranger = TestClient(admin.app, headers=CSRF, client=("198.51.100.7", 40000))
        stranger.portal = admin.portal
        guesses = [stranger.post("/api/v1/login", json={"password": "not the password"}).status_code for _ in range(5)]
        assert guesses == [401] * 5
        audit = admin.core.audit  # type: ignore[attr-defined]

        def theirs() -> int:
            # (Counted by where it came from. Counted as everything in the log, this failed once on a slow
            # run: what a sign-in sets going and does not wait for, the key for the next start, was written
            # down between the two counts.)
            return len([entry for entry in audit.tail(500) if entry.get("ip") == "198.51.100.7"])

        written = theirs()
        assert written == 5
        for _ in range(40):
            assert stranger.post("/api/v1/login", json={"password": "not the password"}).status_code == 429
            assert stranger.post("/api/v1/recover", json={"recovery_key": "x" * 20, "new_password": OTHER}).status_code == 429
            assert stranger.post("/api/v1/logout", json={}).status_code in (200, 401)
        assert theirs() == written


def test_a_message_on_a_websocket_has_a_limit_on_its_pieces_and_on_how_many_come() -> None:
    # The library limits a message's bytes, counted piece by piece. A piece of no bytes counts for nothing and is
    # kept until the message ends: a device that sent empty pieces without end filled a gigabyte in a quarter
    # of a minute. And messages that are whole and tiny, by the hundred thousand, kept the one thread there is
    # busy reading them.
    import tracemalloc

    from websockets.asyncio.server import serve

    async def pieces_without_end(ws: Any) -> None:
        async def pieces() -> AsyncIterator[str]:
            yield "x"
            while True:
                await asyncio.sleep(0)  # (it shares this test's one thread with whoever it talks to)
                yield ""

        await ws.send(pieces())

    async def a_flood(ws: Any) -> None:
        while True:
            await asyncio.sleep(0)
            await ws.send("{}")

    async def as_a_device_does(ws: Any) -> None:
        await ws.send(iter(["he", "llo"]))
        await ws.send(bytes(5))
        await asyncio.sleep(0.5)

    async def talk(ws: Any) -> None:
        how = {"/pieces": pieces_without_end, "/flood": a_flood, "/device": as_a_device_does}[ws.request.path]
        try:
            await how(ws)
        except Exception:  # hung up on, as it is meant to be
            pass

    async def run() -> None:
        async with serve(talk, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            async with kvm.ws_connect(f"ws://127.0.0.1:{port}/device") as ws:
                heard = kvm.Listening(ws, 1000)
                assert await heard.message(2) == "hello" and await heard.message(2) == bytes(5)
                with pytest.raises(TimeoutError):
                    await heard.message(0.05)  # nothing comes: no harm done, the connection is as good as before
            tracemalloc.start()
            try:
                async with kvm.ws_connect(f"ws://127.0.0.1:{port}/pieces", max_size=2**20) as ws:
                    with pytest.raises(KvmError) as refused:
                        await asyncio.wait_for(kvm.Listening(ws, 2**20).message(2), 30)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            assert refused.value.code == "dropped" and peak < 8_000_000, peak
            async with kvm.ws_connect(f"ws://127.0.0.1:{port}/flood") as ws:
                heard, taken = kvm.Listening(ws, 2**20), 0
                with pytest.raises(KvmError) as refused:
                    while True:
                        await heard.message(2)
                        taken += 1
                assert refused.value.code == "dropped" and taken <= kvm.MOST_A_SECOND

    asyncio.run(run())


def test_a_device_gets_to_keep_no_cookies_here() -> None:
    # The HTTP library keeps every cookie an answer sets, and goes through all of them at every request: a
    # device that set new ones with each answer had a hundred megabytes of them within minutes.
    answers = 0

    def reply(request: httpx.Request) -> httpx.Response:
        nonlocal answers
        answers += 1
        cookies = [("set-cookie", f"c{answers}x{number}=1") for number in range(200)]
        return httpx.Response(200, stream=AsItCame(b"{}"), headers=[("content-length", "2"), *cookies])

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(reply), base_url="http://device") as client:
            for _ in range(5):
                got = await bounded(client, client.build_request("GET", "/"), 1000)
            assert len(client.cookies.jar) == 0
            assert got.cookies.get("c5x0") == "1"  # what an answer sets is read out of that answer, as the drivers do

    asyncio.run(run())
    assert "dropped" in kvm.DOWN_CODES  # (what `bounded` refuses counts as the device being down: tried again with a growing pause)


def test_a_packed_answer_leaves_its_connection_fit_for_the_next_request() -> None:
    # Read to its end, and not only as far as what was packed ends: a connection with something left unread on
    # it is closed, and a device that packs its answers then cost a new connection for every request.
    connections = 0
    packed = gzip.compress(b'{"ok": true}')

    async def serve_one(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        try:
            while await reader.readuntil(bytes([13, 10, 13, 10])):
                head = f"HTTP/1.1 200 OK|Content-Encoding: gzip|Content-Length: {len(packed)}||".replace("|", chr(13) + chr(10))
                writer.write(head.encode() + packed)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def run() -> None:
        server = await asyncio.start_server(serve_one, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server, httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
            for _ in range(5):
                assert (await bounded(client, client.build_request("GET", "/"), 1000)).json() == {"ok": True}
        assert connections == 1

    asyncio.run(run())


def test_what_an_update_is_sent_on_from_is_not_read(tmp_path: Path) -> None:
    # The address of a download sends on to where the file is. Left to the HTTP library, the whole of that
    # first answer was read, and unpacked, before any limit was asked: 300 kB there were 600 MB in memory.
    updater = Updater(tmp_path, "someone/qkvm", keys=())

    class Watched(AsItCame):
        read = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            Watched.read = True
            yield self._body

    def reply(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/asset":
            return httpx.Response(302, stream=Watched(gzip.compress(bytes(8 << 20))), headers={"location": "http://files/there", "content-encoding": "gzip"})
        if request.url.path == "/round":
            return httpx.Response(302, stream=AsItCame(b""), headers={"location": "http://files/round"})
        return httpx.Response(200, stream=AsItCame(b"the wheel"), headers={"content-length": "9"})

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(reply), follow_redirects=False) as client:
            assert await updater._fetch(client, "http://files/asset", 1000) == (200, b"the wheel")
            assert Watched.read is False
            with pytest.raises(UpdateError, match="too many times"):
                await updater._fetch(client, "http://files/round", 1000)

    asyncio.run(run())
