"""A password check that could not be made is not a wrong password; a hole in the activity log says its own size and date; HTTPS that cannot be had is not switched on; who is believed once a proxy is named."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from qkvm import cli, kvm, security, update, vault
from qkvm.core import Core
from qkvm.security import client_allowed, client_ip, is_local, is_secure, proxy_networks, sso_name
from qkvm.store import AuditLog, Store, StoreError
from tests.test_unlock import fits
from tests.test_users import OTHER, account, visitor
from tests.test_wall import PASSWORD, closed_port, wait_until, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class _Heard(logging.Handler):
    """What the program's own log (qkvm.log) is given, whatever an earlier test did to where it goes."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.format(record)  # (fills in exc_text)
        self.records.append(record)

    def clear(self) -> None:
        self.records.clear()

    def set_level(self, *args: Any, **kwargs: Any) -> None:
        logging.getLogger("qkvm").setLevel(logging.DEBUG)


@pytest.fixture
def caplog() -> Any:  # in place of pytest's: cli.main() cuts the "qkvm" logger off from the one pytest listens at
    heard = _Heard()
    logger = logging.getLogger("qkvm")
    level = logger.level
    logger.addHandler(heard)
    yield heard
    logger.removeHandler(heard)
    logger.setLevel(level)


# --- the key derivation: a check that could not be made is not a wrong password ------------------------------------


def test_a_password_check_that_could_not_be_made_is_not_answered_as_a_wrong_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    # Measured: with the memory for it not to be had, hashlib.scrypt raises
    # "ValueError: [digital envelope routines] malloc failure" on Python 3.11, 3.12, 3.13 and 3.14.
    from cryptography.exceptions import InvalidTag

    def no_memory(*args: Any, **kwargs: Any) -> bytes:
        raise ValueError("[digital envelope routines] malloc failure")

    def as_before(record: dict[str, Any], password: str) -> bytes | None:  # Vault.open as it was in 05b3d2d
        try:
            return vault._open(vault._derive(password, record["kdf"]), record["key"], vault._KEY_CONTEXT)
        except InvalidTag:
            return None

    seen: dict[str, Any] = {}
    for which in ("before", "now"):
        with monkeypatch.context() as patched, wall(tmp_path / which[:3]) as admin:
            wait_until(lambda admin=admin: fits(admin), "never made to fit")
            if which.startswith("before"):
                patched.setattr(vault.Vault, "open", staticmethod(as_before))
            patched.setattr(hashlib, "scrypt", no_memory)
            caplog.set_level(logging.DEBUG, logger="qkvm")
            caplog.clear()
            owner = visitor(admin, 50040)
            answers = [owner.post("/api/v1/login", json={"password": PASSWORD}) for _ in range(6)]
            said = [(reply.status_code, reply.json().get("code")) for reply in answers]
            lines = [record.getMessage() + (" + traceback ending: " + (record.exc_text or "").strip().splitlines()[-1] if record.exc_text else "") for record in caplog.records]
            patched.undo()
            after = owner.post("/api/v1/login", json={"password": PASSWORD})
            admin.core.audit.flush()  # type: ignore[attr-defined]
            logged = [entry for entry in admin.core.audit.tail(10) if entry["event"] == "login_failed"]  # type: ignore[attr-defined]
        seen[which] = said
        print(f"\n[vault] {which}: the right password six times while scrypt has no memory: {said}")
        print(f"        qkvm.log: {lines[:1]}{' (and so on, one each)' if len(lines) > 1 else ''} | 'login_failed' in the activity log: {len(logged)}")
        print(f"        memory is back, the right password once more: {after.status_code} {after.json().get('message', 'signed in')}")
    assert all(code != "bad_password" for _, code in seen["now"]), "a right password is answered 'Wrong password', counted toward the lock-out, and the log says nothing"


def test_what_this_program_writes_is_inside_the_bounds_and_so_is_twice_that(monkeypatch: pytest.MonkeyPatch) -> None:
    # As the program comes (2**17, 8, 1), as the tests have it (2**12), and what one doubling by a later version would write.
    costs = []
    for n, r, p, taken in ((2**17, 8, 1, True), (2**12, 8, 1, True), (2**18, 8, 1, True), (2**17, 16, 1, True), (2**19, 8, 1, False), (2**17, 8, 4, False), (2**20, 8, 1, False)):
        monkeypatch.setattr(vault, "SCRYPT_N", n)
        monkeypatch.setattr(vault, "SCRYPT_R", r)
        monkeypatch.setattr(vault, "SCRYPT_P", p)
        began = time.monotonic()
        try:
            record = vault.Vault().create("right")
        except ValueError:
            assert not taken, (n, r, p)
            continue
        assert taken and vault.Vault.open(record, "right") is not None and vault.Vault.open(record, "wrong") is None, (n, r, p)
        costs.append(f"n=2**{n.bit_length() - 1} r={r} p={p}: {(time.monotonic() - began) / 3:.2f} s a check")
    print("\n[vault] taken:", "; ".join(costs))


# --- the activity log's hole ------------------------------------------------------------------------------------------


class _NoRoom(io.RawIOBase):
    """A file on a disk with no room, as the system gives it: it opens, and every write to it is refused."""

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        raise OSError(28, "No space left on device")


def _on_a_full_disk() -> Any:
    # Python's own text file over it, as Path.open("a") makes one: what is written goes into its buffer, and
    # the system's refusal arrives when the buffer is written out, which is when the file is closed.
    return io.TextIOWrapper(io.BufferedWriter(_NoRoom()), encoding="utf-8")


def test_the_hole_in_the_activity_log_says_how_many_are_missing_on_a_disk_that_fails_at_the_flush(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = AuditLog(tmp_path / "audit.log")
    log.write("before", "192.0.2.1")
    log.flush()
    real_open = Path.open
    full = {"disk": True}

    def open_on_a_full_disk(self: Path, *args: Any, **kwargs: Any) -> Any:
        if full["disk"] and self.name == "audit.log" and args[:1] == ("a",):
            return _on_a_full_disk()  # the file is there and opens; there is no room for one more line
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_on_a_full_disk)
    for _ in range(5):
        log.write("lost", "192.0.2.1")
    log.flush()
    full["disk"] = False
    log.write("after", "192.0.2.1")
    log.flush()
    monkeypatch.undo()
    events = [json.loads(line) for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    gap = next(entry for entry in events if entry["event"] == "log_gap")
    print(f"\n[log] five entries lost (the error came at the flush); the log says of its hole: count={gap['count']}; in memory: {log.missing['count'] if log.missing else None}")
    assert gap["count"] == 5


def test_a_second_hole_in_the_activity_log_is_dated_as_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = AuditLog(tmp_path / "audit.log")
    real_open = Path.open
    full = {"disk": False}

    def open_unless_full(self: Path, *args: Any, **kwargs: Any) -> Any:
        if full["disk"] and self.name == "audit.log" and args[:1] == ("a",):
            raise OSError(28, "No space left on device")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_unless_full)
    real_time = time.time
    clock = {"at": 1_000_000.0}
    monkeypatch.setattr(time, "time", lambda: clock["at"])
    full["disk"] = True
    log.write("lost on monday", "192.0.2.1")
    log.flush()
    full["disk"] = False
    clock["at"] += 60
    log.write("fine again", "192.0.2.1")
    log.flush()
    clock["at"] += 4 * 86400  # four days of entries that were all written
    log.write("thursday", "192.0.2.1")
    log.flush()
    full["disk"] = True
    second_began = clock["at"] = clock["at"] + 86400
    log.write("lost on friday", "192.0.2.1")
    log.flush()
    full["disk"] = False
    clock["at"] += 60
    log.write("fine once more", "192.0.2.1")
    log.flush()
    monkeypatch.setattr(time, "time", real_time)
    monkeypatch.undo()
    gaps = [entry for entry in (json.loads(line) for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()) if entry["event"] == "log_gap"]
    print(f"\n[log] two holes, five days apart. The second is written as: count={gaps[1]['count']}, since={gaps[1]['since']:.0f} (it began at {second_began:.0f}; the first at {gaps[0]['since']:.0f})")
    assert len(gaps) == 2 and gaps[1]["since"] == second_began


# --- HTTPS switched on where no certificate can be made ---------------------------------------------------------------


def test_https_that_could_not_be_switched_on_does_not_keep_the_next_start_from_starting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import uvicorn

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        (data / "tls").write_text("", encoding="utf-8")  # something lies where the certificate's folder goes (as test_refused_changes has it)
        answer = admin.put("/api/v1/settings", json={"bind": ["local"], "port": 8787, "https": True, "interval": 1})
        shown = admin.get("/api/v1/settings").json()
    saved = json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))["server"]["https"]
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)  # (if it gets as far as serving, it has started)
    core = Core(data, bind_override=["local"], port_override=closed_port())
    core.unlock_at_start()
    capsys.readouterr()
    status = cli.serve(core)
    said = capsys.readouterr().err.strip()
    with capsys.disabled():
        print(f"\n[https] the answer: {answer.status_code} {answer.json()}")
        print(f"        saved https={saved}; the settings page then shows https={shown['https']}, fingerprint={shown['cert_fingerprint']}")
        print(f"        the next start: exit status {status}; said: {said[:120]!r}...")
    told = answer.status_code == 507 and "start" in answer.json()["message"].lower().replace("started", "")
    assert told or status == 0, "answered 'goes on listening as it did'; the next start does not start, and no option switches HTTPS off"


def test_a_certificate_that_cannot_be_made_for_another_reason_than_the_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import uvicorn

    data = tmp_path / "data"
    monkeypatch.setattr(socket, "gethostname", lambda: "büro-pc")  # a computer name Windows allows
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        answer = admin.put("/api/v1/settings", json={"bind": ["local"], "port": 8787, "https": True, "interval": 1})
    saved = json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))["server"]["https"]
    print(f"\n[https] on a computer called 'büro-pc': {answer.status_code} {answer.json()}; saved https={saved}")
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    core = Core(data, bind_override=["local"], port_override=closed_port())
    core.unlock_at_start()
    try:
        status: Any = cli.serve(core)
    except Exception as ex:
        status = f"a traceback: {type(ex).__name__}: {ex}"
    print(f"        the next start ends in: {status}")
    assert answer.status_code != 500 and status in (0, 2)


# --- a save that fails otherwise than by the disk -----------------------------------------------------------------------


def test_a_save_that_fails_inside_takes_the_change_back_and_a_cancelled_one_is_not_swallowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    with wall(tmp_path) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        real = Store.write
        monkeypatch.setattr(Store, "write", lambda self, data: (_ for _ in ()).throw(KeyError("a bug")))
        caplog.set_level(logging.ERROR, logger="qkvm")
        caplog.clear()
        refused = admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": OTHER})
        names = [u["name"] for u in admin.get("/api/v1/users").json()["users"]]
        lines = sum(len((record.exc_text or "").splitlines()) + 1 for record in caplog.records)
        print(f"\n[save] a KeyError inside the save: {refused.status_code} {refused.json()['code']}; accounts then: {names}; {len(caplog.records)} log record(s), {lines} lines")
        assert refused.status_code == 507 and names == ["admin"]

        def cancelled(self: Store, data: dict[str, Any]) -> None:
            raise asyncio.CancelledError

        monkeypatch.setattr(Store, "write", cancelled)
        try:
            answer: Any = admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": OTHER}).status_code
        except BaseException as ex:
            answer = type(ex).__name__
        print("        a CancelledError inside the save is answered:", answer, "(507 would mean it was taken for a failed save)")
        assert answer != 507
        monkeypatch.setattr(Store, "write", real)


# --- ids ---------------------------------------------------------------------------------------------------------------


def test_every_id_this_program_gives_is_one_it_takes_back(tmp_path: Path) -> None:
    from tests.fake_kvm import FakeKvm

    server = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            wait_until(lambda: fits(admin), "never made to fit")
            account(admin, "olga", "viewer")
            assert admin.post("/api/v1/devices", json={"url": server.url, "password": "secret"}).status_code == 201
            assert admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code in (200, 201)
            assert admin.post("/api/v1/tokens", json={"name": "a script"}).status_code == 201
            assert admin.post("/api/v1/tokens", json={"name": "a screen", "kind": "display"}).status_code == 201
    finally:
        server.stop()
    said = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))
    ids = {part: [thing["id"] for thing in said[part]] for part in ("users", "devices", "actions", "tokens")}
    print("\n[ids] as written:", ids)
    assert not Store(tmp_path / "qkvm.json").restored
    # The demo's own, and the owner's older "admin".
    for odd in ("demo", "demo12", "admin", "A-b_9"):
        said["users"][0]["id"] = odd
        write_settings_text(tmp_path / "qkvm.json", json.dumps(said), encoding="utf-8")
        (tmp_path / "qkvm.bak").unlink(missing_ok=True)
        assert Store(tmp_path / "qkvm.json").users[0].id == odd
    for refused in ("kvm.1", "a b", "own:1", "é"):
        said["users"][0]["id"] = refused
        write_settings_text(tmp_path / "qkvm.json", json.dumps(said), encoding="utf-8")
        (tmp_path / "qkvm.bak").unlink(missing_ok=True)
        with pytest.raises(StoreError):
            Store(tmp_path / "qkvm.json")
    print("      refused (a wall with such an id in its file does not start):", ["kvm.1", "a b", "own:1", "é"])


# --- clear_out ---------------------------------------------------------------------------------------------------------


def test_clear_out_removes_what_is_qkvms_and_says_what_it_could_not(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("somebody else's", encoding="utf-8")
    write_settings_text(data / "qkvm.damaged-1700000000.json", settings_text(data / "qkvm.json", encoding="utf-8"), encoding="utf-8")
    (data / "qkvm.damaged-folder.json").mkdir()
    write_settings_text(data / "qkvm.bak.new", "{}", encoding="utf-8")
    write_settings_text(data / "qkvm.tmp", "{}", encoding="utf-8")
    (data / "notes about qkvm.damaged-1.json.txt").write_text("mine", encoding="utf-8")
    (data / "qkvm.json.orig").write_text("mine", encoding="utf-8")
    linked = True
    try:
        os.symlink(elsewhere, data / "qkvm.damaged-link.json")
    except OSError:
        linked = False  # (Windows without the right to make links)
    path = data / "qkvm.json"
    write_settings_text(path, settings_text(path, encoding="utf-8") + "}", encoding="utf-8")  # the current file is damaged as well: this start sets one more aside
    status = cli.main(["--data-dir", str(data), "--reset-password"])
    said = capsys.readouterr()
    left = sorted(p.name for p in data.iterdir())
    print(f"\n[clear_out] --reset-password with a damaged qkvm.json: exit {status}; said: {said.err.strip().splitlines()[-1] if said.err.strip() else ''!r}")
    print("        in the folder afterwards:", left)
    print("        the link's target is still there:", elsewhere.read_text(encoding="utf-8") == "somebody else's", "| a link could be made:", linked)
    assert elsewhere.read_text(encoding="utf-8") == "somebody else's"
    assert "notes about qkvm.damaged-1.json.txt" in left and "qkvm.json.orig" in left
    assert not [name for name in left if name.startswith("qkvm.damaged-") and name != "qkvm.damaged-folder.json"] and "qkvm.tmp" not in left and "qkvm.bak.new" not in left
    assert status == 1 and "qkvm.damaged-folder.json" in said.err  # what could not be removed is named, and the command does not end as done


# --- who is believed ----------------------------------------------------------------------------------------------------


def asked(client: str, named: tuple[str, ...] = (), allow: tuple[str, ...] = (), **headers: str) -> Request:
    class App:
        class state:
            trusted_proxies = proxy_networks(named)
            allowed_clients = proxy_networks(allow)

    scope = {
        "type": "http", "method": "GET", "path": "/", "scheme": "http", "query_string": b"", "client": (client, 40000), "app": App,
        "headers": [(name.replace("_", "-").lower().encode(), value.encode()) for name, value in headers.items()],
    }  # fmt: skip
    return Request(scope)


def test_who_is_believed_once_a_proxy_is_named() -> None:
    front = dict(x_forwarded_for="100.101.102.103", x_forwarded_proto="https")
    rows = []
    for named in ((), ("10.0.0.5",), ("10.0.0.5", "127.0.0.1")):
        for what, request in (
            ("tailscale serve on this computer", asked("127.0.0.1", named, **front)),
            ("this computer's own browser / health check", asked("127.0.0.1", named)),
            ("the named proxy", asked("10.0.0.5", named, x_forwarded_for="203.0.113.9", x_forwarded_proto="https")),
            ("a program here that says it passes somebody on", asked("127.0.0.1", named, x_forwarded_for="192.168.1.50")),
        ):
            rows.append((named, what, client_ip(request), is_secure(request), is_local(request)))
    print("\n[believed] named proxies | who | counted as | over HTTPS | 'this computer'")
    for row in rows:
        print("          ", row)
    by = {(named, what): rest for named, what, *rest in rows}
    # No proxy named: as before.
    assert by[((), "tailscale serve on this computer")] == ["100.101.102.103", True, False]
    # One named, and not this computer: its word is no longer taken; it is not "this computer" either (it passes somebody on).
    assert by[(("10.0.0.5",), "tailscale serve on this computer")] == ["127.0.0.1", False, False]
    assert by[(("10.0.0.5",), "this computer's own browser / health check")] == ["127.0.0.1", False, True]
    assert by[(("10.0.0.5",), "the named proxy")] == ["203.0.113.9", True, False]
    assert by[(("10.0.0.5", "127.0.0.1"), "tailscale serve on this computer")] == ["100.101.102.103", True, False]
    # --allow-from: this computer is always answered; somebody passed on by an unnamed front here is the front's address, and is not.
    allow = ("192.168.1.0/24",)
    assert client_allowed(asked("127.0.0.1", ("10.0.0.5",), allow))  # health check, first-run setup from here
    assert not client_allowed(asked("127.0.0.1", ("10.0.0.5",), allow, x_forwarded_for="192.168.1.50"))  # was let through before: the address was of its choosing
    assert client_allowed(asked("127.0.0.1", (), allow, x_forwarded_for="192.168.1.50"))  # no proxy named: believed, as the README says
    assert client_allowed(asked("10.0.0.5", ("10.0.0.5",), allow, x_forwarded_for="192.168.1.50"))
    assert not client_allowed(asked("10.0.0.5", ("10.0.0.5",), allow, x_forwarded_for="198.51.100.1"))
    # The identity header: of a named proxy only, before and after.
    assert sso_name(asked("127.0.0.1", (), remote_user="olga"), "Remote-User") is None
    assert sso_name(asked("127.0.0.1", ("10.0.0.5",), remote_user="olga"), "Remote-User") is None
    assert sso_name(asked("10.0.0.5", ("10.0.0.5",), remote_user="olga"), "Remote-User") == "olga"
    assert sso_name(asked("127.0.0.1", ("127.0.0.1",), remote_user="olga"), "Remote-User") == "olga"


def test_first_run_setup_from_this_computer_with_a_proxy_named(tmp_path: Path) -> None:
    with wall(tmp_path, sign_in=False, trusted_proxies=["10.0.0.5"], setup_code=True, allow_from=["192.168.1.0/24"]) as here:
        assert here.get("/healthz").status_code == 200  # the container's own health check
        assert here.get("/api/v1/session").json()["setup_code_required"] is False
        through = visitor(here, 50050)
        through.headers["X-Forwarded-For"] = "192.168.1.50"
        print("\n[believed] through an unnamed front on this computer, with --allow-from:", through.get("/healthz").status_code)
        assert through.get("/healthz").status_code == 403
        assert here.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200  # from this computer: no code asked


def test_limiter_counts_one_network_as_one() -> None:
    limiter = security.Limiter()
    assert limiter.counted_as("2001:db8:1:2::1") == limiter.counted_as("2001:db8:1:2:ffff::9") != limiter.counted_as("2001:db8:1:3::1")
    assert limiter.counted_as("::ffff:192.0.2.7") == limiter.counted_as("192.0.2.7") == "192.0.2.7"
    assert limiter.counted_as("unknown") == "unknown" and limiter.counted_as("fe80::1%eth0") == limiter.counted_as("fe80::2%eth0")
