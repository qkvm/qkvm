"""What the README promises in "The API" is what the wall serves: every request in its table exists, takes who
the table says, answers the fields the table names, of the kinds a client reads them as, and refuses the way
the table says; what the wall serves beside is named there as the page's own. The README is the truth for
whoever writes a program against the wall, so the table is held to the program, row by row, against one
stand-in of each kind of device.

The README says more than a test can read (what a field means); what a test can read it reads: every
request written as `GET /path` in the table's first column, the role in its second, and every field and
code the answers were seen to have, which has to be named in the row, in backticks. A field that is added to
an answer and not to its row fails here; so does one named in the row that the answer does not have, where
the row says the answer has it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import jetkvm, kvm, server, update, vault
from qkvm.core import Core
from tests.fake_amt import AmtState, FakeAmt
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_meanwhile import in_background
from tests.test_redfish import a_screen
from tests.test_totp import code_for
from tests.test_users import OTHER, account, browser
from tests.test_wall import CSRF, PASSWORD, add, closed_port, snap, wait_until, wall

README = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
CHAPTER = README.split("\n## The API\n", 1)[1].split("\n## Clients and versions\n", 1)[0]
TABLE = CHAPTER.split("### The requests", 1)[1].split("### A machine", 1)[0]
PAGES_OWN = CHAPTER.split("### The page's own", 1)[1]
NAMED = re.compile(r"{[^}]+}")  # where a path has a name in it: {device_id}, {id}
# Served beside the API, and documented elsewhere: the page itself, its files, and the collector's numbers (Metrics).
OUTSIDE = {("GET", "/"), ("GET", "/static/{}"), ("GET", "/metrics")}

# What a value is read as, by a client. "null" where the table says it may be nothing.
STR, INT, NUM, BOOL, LIST, DICT = (str,), (int,), (int, float), (bool,), (list,), (dict,)
NULL = (type(None),)


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


def rows() -> dict[tuple[str, str], tuple[str, str]]:
    """(method, path with every name as {}) -> (the least role, the row's text), for every request of the table."""
    found = {}
    for line in TABLE.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        role = cells[1].split(",")[0].strip()
        assert role in ("nobody", "viewer", "operator", "admin"), line
        for method, path in re.findall(r"`(GET|POST|PUT|DELETE) (/[^`?]*)", cells[0]):
            found[(method, NAMED.sub("{}", path))] = (role, line)
    assert len(found) >= 25
    return found


def served(app: Any) -> dict[tuple[str, str], str]:
    """(method, path with every name as {}) -> the least role, for every request the wall serves."""
    found = {}
    for route in app.routes:
        sample = NAMED.sub("ab12cd34", route.path)
        if getattr(route, "methods", None) is None:
            continue  # a WebSocket (the live line, let in by a pass: its row in the table names no method, and the pass's row is asked)
        for method in route.methods:
            public = sample in server.PUBLIC or sample.startswith("/static/")
            found[(method, NAMED.sub("{}", route.path))] = "nobody" if public else server.required_role(method, sample)
    return found


def test_what_the_table_promises_is_served_and_the_rest_is_the_pages_own(tmp_path: Path) -> None:
    promised = rows()
    there = served(server.create_app(Core(tmp_path)))
    for request, (role, _) in promised.items():
        assert request in there, f"the README promises {request[0]} {request[1]}, which the wall does not serve"
        assert there[request] == role, f"{request[0]} {request[1]}: the README says {role}, the wall asks for {there[request]}"
    # Whatever else is served is the page's own, and is named as that: by the word after /api/v1/.
    own = set(re.findall(r"`([a-z]+)`", PAGES_OWN))
    assert {"setup", "devices", "users", "settings", "update"} <= own
    for method, path in there:
        if (method, path) in promised or (method, path) in OUTSIDE:
            continue
        assert path.startswith("/api/v1/"), f"{method} {path} is neither promised nor the page's own"
        assert path.split("/")[3] in own, f"{method} {path} is served and is neither promised in The API nor named as the page's own"


# --- the answers, against stand-ins of every kind ----------------------------------------------------------------


# Refusals that any request may answer with, said once in the chapter's table of errors and not in every row.
GENERIC = {"unauthorized", "not_allowed", "forbidden", "totp_required", "rate_limited", "invalid", "too_large", "length_required", "internal", "locked", "not_saved"}
Where = tuple[str, str] | str  # a row of the table, as (method, path); or a record described under a "### " heading of the chapter


class Seen:
    """What each request was seen to answer: fields and codes, to be found afterwards where the README describes them."""

    def __init__(self) -> None:
        self.rows = rows()
        self.names: dict[Where, set[str]] = {}

    @staticmethod
    def place(where: Where) -> Where:
        """The row a request falls under: with the machine's or the token's id, as it was asked, folded to the table's {}."""
        # (Not the request that removes several machines at once: `remove` there is no machine's id.)
        return where if isinstance(where, str) else (where[0], re.sub(r"/(devices|tokens)/(?!remove$)[^/]+", r"/\1/{}", NAMED.sub("{}", where[1])))

    def text(self, where: Where) -> str:
        if isinstance(where, str):
            return CHAPTER.split(f"### {where}", 1)[1].split("\n### ", 1)[0]
        return self.rows[where][1]

    def shaped(self, where: Where, answer: Any, shape: dict[str, tuple[type, ...]], exactly: bool = True) -> None:
        """`answer` has these fields (and no others, unless `exactly` is off), each of its kind; the README names each where it describes this."""
        assert isinstance(answer, dict), (where, answer)
        if exactly:
            assert set(answer) == set(shape), (where, set(answer) ^ set(shape))
        else:
            assert set(shape) <= set(answer), (where, set(shape) - set(answer))
        for field, kinds in shape.items():
            assert isinstance(answer[field], kinds), (where, field, answer[field])
        self.names.setdefault(self.place(where), set()).update(shape)

    def refused(self, method: str, path: str, reply: Any, status: int, code: str) -> None:
        assert (reply.status_code, reply.json()["code"]) == (status, code), (method, path, reply.status_code, reply.text[:200])
        assert reply.json()["message"], "a refusal without a sentence"
        self.names.setdefault(self.place((method, path)), set()).add(code)

    def all_where_the_readme_describes_them(self) -> None:
        errors = CHAPTER.split("### Errors", 1)[1].split("\n### ", 1)[0]
        assert all(f"`{code}`" in errors for code in GENERIC), [code for code in GENERIC if f"`{code}`" not in errors]
        unsaid = {where: sorted(name for name in names if f"`{name}`" not in self.text(where) and name not in GENERIC) for where, names in self.names.items()}
        assert all(not names for names in unsaid.values()), {where: names for where, names in unsaid.items() if names}
        # And every request of the table was asked.
        assert set(self.rows) - set(self.names) == set(), sorted(set(self.rows) - set(self.names))


ACCOUNT = {"id": STR, "name": STR, "role": STR, "totp": BOOL, "must_enroll": BOOL, "sso": BOOL, "recovery_codes": INT, "token": BOOL}
TILE = {"id": STR, "name": STR, "host": STR, "open_url": STR, "kind": STR, "picture": BOOL, "group": STR, "same_as": LIST, "can": LIST}
ADMINS_TILE = {**TILE, "url": STR, "custom_open_url": STR, "username": STR, "tls": STR, "fingerprint": STR + NULL, "has_password": BOOL, "alerts": BOOL, "fingerbot_strength": STR}
STATUS = {
    "can": LIST, "state": STR, "error": DICT + NULL, "last_seen_ago": INT + NULL, "video": DICT, "usb": DICT, "atx": DICT, "health": DICT,
    "about": DICT, "ports": DICT + NULL,
}  # fmt: skip
SAVED_ACTION = {"id": STR, "name": STR, "kind": STR, "keys": STR, "enter": BOOL, "danger": BOOL, "changed": INT}
TOKEN = {"id": STR, "name": STR, "kind": STR, "role": STR, "devices": LIST + NULL, "groups": LIST, "created": NUM, "expires": NUM + NULL, "used": NUM + NULL}
FILE_DEVICE = {"name": STR, "host": STR, "kind": STR, "group": STR, "password": BOOL, "tls": STR, "open_url": STR, "new": BOOL, "same_as": STR}
FILE_ACTION = {"name": STR, "kind": STR, "keys": STR, "text": STR, "enter": BOOL, "danger": BOOL, "new": BOOL}


@pytest.fixture
def one_of_each() -> Iterator[tuple[FakeKvm, FakeJetKvm, FakeBmc, FakeAmt]]:
    """A KVM with a power board and two inputs, a JetKVM with its ATX extension on, a server's controller (each with something to wake), and a PC
    with Intel AMT that asks for the code on its screen (so that it shows what a machine whose screen cannot be had answers; its screen is
    tests/test_amt_screen.py's)."""
    comet = FakeKvm(FakeState(atx=True, ports=[(32, 74, 135), None], wol=[{"mac": "02:00:00:00:00:01", "name": "The build machine"}])).start()
    jet = FakeJetKvm(JetState(extension="atx-power", wol=[{"name": "The other one", "macAddress": "02:00:00:00:00:02"}])).start()
    bmc = FakeBmc(BmcState()).start()
    pc = FakeAmt(AmtState(consent=True)).start()
    yield comet, jet, bmc, pc
    for fake in (comet, jet, bmc, pc):
        fake.stop()


def another(admin: TestClient, address: str, port: int) -> TestClient:
    """A browser at another address, not signed in: its wrong guesses are counted against that address, not the test's."""
    client = TestClient(admin.app, headers=CSRF, client=(address, port))
    client.portal = admin.portal
    return client


def test_every_promised_request_answers_as_the_table_says(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, one_of_each: tuple[FakeKvm, FakeJetKvm, FakeBmc, FakeAmt]) -> None:
    comet, jet, bmc, pc = one_of_each
    seen = Seen()
    with wall(tmp_path, sign_in=False) as admin:
        # --- before anybody: healthz, the session, the first-run setup (the page's own, done here to get the recovery key)
        health = admin.get("/healthz").json()
        seen.shaped(("GET", "/healthz"), health, {"status": STR, "version": STR, "api": LIST, "page": STR, "locked": BOOL})
        assert health["status"] == "ok" and health["api"] == ["v1"] and health["locked"] is False
        session = admin.get("/api/v1/session").json()
        session_fields = {
            "initialized": BOOL, "authenticated": BOOL, "user": DICT + NULL, "ask_name": BOOL, "recovery": BOOL, "recovery_created": NUM + NULL,
            "setup_code_required": BOOL, "min_password": INT, "unlocks_at_start": BOOL,
        }  # fmt: skip
        seen.shaped(("GET", "/api/v1/session"), session, session_fields)
        assert session["initialized"] is False and session["user"] is None
        made = admin.post("/api/v1/setup", json={"password": PASSWORD})
        assert made.status_code == 200, made.text
        recovery_key = made.json()["recovery_key"]
        session = admin.get("/api/v1/session").json()
        seen.shaped(("GET", "/api/v1/session"), session, session_fields)
        seen.shaped("An account", session["user"], ACCOUNT)
        assert session["authenticated"] is True and session["user"]["role"] == "admin" and session["recovery_created"] > 0

        # --- the machines: one of each kind, and until each has been looked at
        kvm_id, jet_id, bmc_id = add(admin, comet.url, name="A KVM"), add(admin, jet.url, name="A JetKVM"), add(admin, bmc.url, name="A server")
        amt_id = add(admin, pc.url, name="A PC")
        wait_until(lambda: {s["state"] for s in admin.get("/api/v1/status").json().values()} == {"online"}, "the four never came online", timeout=30)

        # --- signing in: as a person, with a name where there are several accounts, with a code where there is a second step
        stranger = another(admin, "192.0.2.11", 50011)
        seen.refused("POST", "/api/v1/login", stranger.post("/api/v1/login", json={"password": "not the password"}), 401, "bad_password")
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        seen.refused("POST", "/api/v1/login", stranger.post("/api/v1/login", json={"password": OTHER}), 422, "name_required")
        olga = browser(admin, "olga", port=50012)
        begun = olga.post("/api/v1/totp/begin", json={"password": OTHER})
        seen.shaped(("POST", "/api/v1/totp/begin"), begun.json(), {"secret": STR, "uri": STR, "qr": LIST})
        assert begun.json()["uri"].startswith("otpauth://totp/") and all(set(row) <= {"0", "1"} for row in begun.json()["qr"])
        seen.refused("POST", "/api/v1/totp/begin", olga.post("/api/v1/totp/begin", json={"password": "not her password"}), 401, "bad_password")
        seen.refused("POST", "/api/v1/totp/enable", olga.post("/api/v1/totp/enable", json={"code": "000000"}), 401, "bad_code")
        enabled = olga.post("/api/v1/totp/enable", json={"code": code_for(begun.json()["secret"])})
        seen.shaped(("POST", "/api/v1/totp/enable"), enabled.json(), {"ok": BOOL, "user": DICT, "recovery_codes": LIST})
        seen.shaped("An account", enabled.json()["user"], ACCOUNT)
        assert len(enabled.json()["recovery_codes"]) == 10 and enabled.json()["user"]["totp"] is True
        seen.refused("POST", "/api/v1/totp/begin", olga.post("/api/v1/totp/begin", json={"password": OTHER}), 409, "enabled")
        seen.refused("POST", "/api/v1/totp/enable", olga.post("/api/v1/totp/enable", json={"code": "000000"}), 409, "not_started")
        codes = olga.post("/api/v1/totp/codes", json={"password": OTHER})
        seen.shaped(("POST", "/api/v1/totp/codes"), codes.json(), {"ok": BOOL, "user": DICT, "recovery_codes": LIST})
        assert len(codes.json()["recovery_codes"]) == 10 and codes.json()["recovery_codes"] != enabled.json()["recovery_codes"]
        seen.refused("POST", "/api/v1/login", stranger.post("/api/v1/login", json={"name": "olga", "password": OTHER}), 401, "code_required")
        seen.refused("POST", "/api/v1/login", stranger.post("/api/v1/login", json={"name": "olga", "password": OTHER, "code": "000000"}), 401, "bad_code")
        signed_in = stranger.post("/api/v1/login", json={"name": "olga", "password": OTHER, "code": code_for(begun.json()["secret"], 1), "remember": True})
        assert signed_in.status_code == 200, signed_in.text
        seen.shaped(("POST", "/api/v1/login"), signed_in.json(), {"ok": BOOL, "user": DICT})
        seen.shaped("An account", signed_in.json()["user"], ACCOUNT)
        assert "qkvm_session=" in signed_in.headers["set-cookie"] and "httponly" in signed_in.headers["set-cookie"].lower()
        disabled = olga.post("/api/v1/totp/disable", json={"password": OTHER})
        seen.shaped(("POST", "/api/v1/totp/disable"), disabled.json(), {"ok": BOOL, "user": DICT})
        assert disabled.json()["user"]["totp"] is False
        seen.refused("POST", "/api/v1/totp/codes", olga.post("/api/v1/totp/codes", json={"password": OTHER}), 409, "not_enabled")
        olga_id = next(u["id"] for u in admin.get("/api/v1/users").json()["users"] if u["name"] == "olga")
        assert admin.put(f"/api/v1/users/{olga_id}", json={"name": "olga", "role": "operator", "suspended": True}).status_code == 200
        seen.refused("POST", "/api/v1/login", stranger.post("/api/v1/login", json={"name": "olga", "password": OTHER}), 403, "suspended")
        assert admin.put(f"/api/v1/users/{olga_id}", json={"name": "olga", "role": "operator", "suspended": False}).status_code == 200

        # --- signing out, and one's own password
        olga = browser(admin, "olga", port=50013)
        out = olga.post("/api/v1/logout", json={"scope": "this"})
        seen.shaped(("POST", "/api/v1/logout"), out.json(), {"ok": BOOL})
        assert 'qkvm_session=""' in out.headers["set-cookie"] or "max-age=0" in out.headers["set-cookie"].lower()
        seen.refused("GET", "/api/v1/wall", olga.get("/api/v1/wall"), 401, "unauthorized")
        seen.refused("POST", "/api/v1/password", admin.post("/api/v1/password", json={"current": "not it", "new": "a new long password"}), 401, "bad_password")
        changed = admin.post("/api/v1/password", json={"current": PASSWORD, "new": "a new long password"})
        seen.shaped(("POST", "/api/v1/password"), changed.json(), {"ok": BOOL})
        assert admin.post("/api/v1/password", json={"current": "a new long password", "new": PASSWORD}).status_code == 200

        # --- a forgotten password, and the recovery key: every session of that account ends
        stranger = another(admin, "192.0.2.12", 50014)
        seen.refused("POST", "/api/v1/recover", stranger.post("/api/v1/recover", json={"recovery_key": recovery_key, "new_password": PASSWORD}), 422, "name_required")
        seen.refused("POST", "/api/v1/recover", stranger.post("/api/v1/recover", json={"name": "admin", "recovery_key": "qKVM-not-the-key", "new_password": PASSWORD}), 401, "bad_recovery")
        recovered = stranger.post("/api/v1/recover", json={"name": "admin", "recovery_key": recovery_key, "new_password": PASSWORD})
        assert recovered.status_code == 200, recovered.text
        seen.shaped(("POST", "/api/v1/recover"), recovered.json(), {"ok": BOOL})
        assert admin.get("/api/v1/wall").status_code == 401
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200

        # --- a screen on the wall, with its link; tokens
        listed = admin.get("/api/v1/tokens")
        seen.shaped(("GET", "/api/v1/tokens"), listed.json(), {"tokens": LIST})
        assert listed.json()["tokens"] == []
        seen.refused("POST", "/api/v1/tokens", admin.post("/api/v1/tokens", json={"name": "nightly", "role": "admin"}), 422, "invalid")
        made = admin.post("/api/v1/tokens", json={"name": "The screen in the hall", "kind": "display"})
        assert made.status_code == 201, made.text
        seen.shaped(("POST", "/api/v1/tokens"), made.json(), {"token": STR, "record": DICT})
        seen.shaped(("GET", "/api/v1/tokens"), made.json()["record"], TOKEN)  # (the record "as listed": its fields are said once, there)
        link, display_id = made.json()["token"], made.json()["record"]["id"]
        robot_made = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator", "devices": [kvm_id, bmc_id], "days": 30})
        assert robot_made.status_code == 201
        seen.shaped(("GET", "/api/v1/tokens"), admin.get("/api/v1/tokens").json()["tokens"][0], TOKEN)
        screen = another(admin, "192.0.2.60", 50015)
        seen.refused("POST", "/api/v1/display", screen.post("/api/v1/display", json={"key": "qkvm_not-a-link-that-was-made"}), 401, "bad_key")
        shown = screen.post("/api/v1/display", json={"key": link})
        assert shown.status_code == 200, shown.text
        seen.shaped(("POST", "/api/v1/display"), shown.json(), {"ok": BOOL, "user": DICT})
        seen.shaped("An account", shown.json()["user"], ACCOUNT)
        assert shown.json()["user"]["token"] is True and shown.json()["user"]["role"] == "viewer"
        assert screen.get("/api/v1/wall").status_code == 200

        # --- about, the wall and how the machines are: to a viewer, and to an admin
        victor = browser(admin, "victor", port=50016)
        about = victor.get("/api/v1/about")
        seen.shaped(("GET", "/api/v1/about"), about.json(), {"version": STR, "licence": STR})
        seen.shaped(("GET", "/api/v1/about"), admin.get("/api/v1/about").json(), {"version": STR, "licence": STR}, exactly=False)
        the_wall = victor.get("/api/v1/wall").json()
        seen.shaped(("GET", "/api/v1/wall"), the_wall, {"interval": NUM, "live": INT, "devices": LIST})
        assert the_wall["live"] == 2  # (the form of the live line, read by a program as a number)
        for tile in the_wall["devices"]:
            seen.shaped("A machine, as the wall lists it", tile, TILE)
        for tile in admin.get("/api/v1/wall").json()["devices"]:
            seen.shaped("A machine, as the wall lists it", tile, ADMINS_TILE)
        by_id = {tile["id"]: tile for tile in the_wall["devices"]}
        assert by_id[kvm_id]["kind"] == "kvmd" and by_id[jet_id]["kind"] == "jetkvm" and by_id[bmc_id]["kind"] == "redfish" and by_id[amt_id]["kind"] == "amt"
        assert by_id[kvm_id]["picture"] is True and by_id[bmc_id]["picture"] is False and by_id[amt_id]["picture"] is False
        # What each can be asked: the driver's, and what the look at the device added (a power board, inputs, a light, a way in).
        assert by_id[kvm_id]["can"] == ["screen", "keys", "text", "jiggler", "power", "reset", "wol", "ports", "reboot", "live", "control"]
        assert by_id[jet_id]["can"] == ["screen", "keys", "text", "jiggler", "power", "reset", "wol", "reboot", "resume", "live", "control"]
        # (The server's screen: not asked for yet, and so not known to be missing; asking is what finds that out, below.)
        # (And Start into BIOS setup, where its controller allows the "BiosSetup" boot override, as the stand-in's does.)
        assert by_id[bmc_id]["can"] == ["screen", "power", "reset", "power_state", "reboot", "locator", "console", "live", "bios_setup"]
        # (No screen while it asks for its code, and no restart of the engine; Start into BIOS setup, which needs no screen.)
        assert by_id[amt_id]["can"] == ["power", "reset", "power_state", "bios_setup"]
        status = victor.get("/api/v1/status").json()
        assert set(status) == {kvm_id, jet_id, bmc_id, amt_id}
        seen.shaped("How a machine is", status[kvm_id], {**STATUS, "fingerbot": DICT + NULL})  # (null: no Fingerbot is paired with it)
        seen.shaped("How a machine is", status[jet_id], {**STATUS, "kind": STR})
        seen.shaped("How a machine is", status[bmc_id], {**STATUS, "kind": STR, "picture": BOOL, "screen": BOOL, "console": BOOL, "server": DICT})
        seen.shaped("How a machine is", status[amt_id], {**STATUS, "kind": STR, "picture": BOOL, "screen": BOOL, "console": BOOL, "server": DICT})
        for device_id in (kvm_id, jet_id, bmc_id, amt_id):
            assert status[device_id]["can"] == by_id[device_id]["can"], device_id  # (the status's list is the wall's, as of the same look)
            assert status[device_id]["state"] == "online" and status[device_id]["error"] is None
        seen.shaped("How a machine is", status[kvm_id]["video"], {"signal": BOOL + NULL, "width": INT + NULL, "height": INT + NULL, "fps": NUM + NULL})
        seen.shaped("How a machine is", status[kvm_id]["usb"], {"keyboard": BOOL + NULL, "mouse": BOOL + NULL})
        seen.shaped("How a machine is", status[kvm_id]["atx"], {"enabled": BOOL, "power": BOOL + NULL, "hdd": BOOL + NULL})
        seen.shaped("How a machine is", status[kvm_id]["health"], {"temp": NUM + NULL, "cpu": NUM + NULL, "mem": NUM + NULL})
        seen.shaped("How a machine is", status[kvm_id]["about"], {"model": STR + NULL, "version": STR + NULL})
        seen.shaped("How a machine is", status[kvm_id]["ports"], {"active": INT, "list": LIST})
        seen.shaped("How a machine is", status[kvm_id]["ports"]["list"][0], {"name": STR + NULL, "signal": BOOL + NULL}, exactly=False)
        seen.shaped(
            "How a machine is", status[bmc_id]["server"],
            {"power": STR + NULL, "health": STR + NULL, "processor": STR + NULL, "processors": INT + NULL, "memory_gib": NUM + NULL, "temperatures": LIST, "fans": LIST, "unwell": LIST, "locator": BOOL + NULL, "no_screen": STR + NULL, "rfb_console": STR + NULL},
        )  # fmt: skip
        seen.shaped("How a machine is", status[bmc_id]["server"]["temperatures"][0], {"name": STR, "celsius": NUM, "ok": BOOL})
        seen.shaped("How a machine is", status[bmc_id]["server"]["fans"][0], {"name": STR, "reading": NUM + NULL, "unit": STR, "ok": BOOL})
        assert status[bmc_id]["screen"] is True and status[bmc_id]["console"] is True and status[bmc_id]["server"]["locator"] is False
        # A PC with Intel AMT answers as a server does, with a record of its own in `server`; this one's screen cannot be had (consent).
        seen.shaped(
            "How a machine is", status[amt_id]["server"],
            {"power": STR + NULL, "health": STR + NULL, "processor": STR + NULL, "processors": INT + NULL, "memory_gib": NUM + NULL, "temperatures": LIST, "fans": LIST, "unwell": LIST, "locator": BOOL + NULL, "no_screen": STR + NULL, "rfb_console": NULL, "amt": DICT},
        )  # fmt: skip
        seen.shaped(
            "How a machine is", status[amt_id]["server"]["amt"],
            {"power": INT + NULL, "control": STR + NULL, "kvm": STR + NULL, "consent": BOOL + NULL, "listener": BOOL + NULL, "session_timeout": INT + NULL, "make": STR + NULL, "model": STR + NULL, "serial": STR + NULL, "bios": STR + NULL, "plain": BOOL},
        )  # fmt: skip
        assert status[amt_id]["screen"] is False and status[amt_id]["console"] is False and status[amt_id]["server"]["power"] == "On"

        # --- what the wall saw of a machine: its history, kept beside the settings
        hist = f"/api/v1/devices/{kvm_id}/history"
        wait_until(lambda: victor.get(hist).json()["state"] == "online", "the history never saw the KVM online", timeout=10)
        summary = victor.get(hist).json()
        seen.shaped(
            ("GET", hist), summary,
            {"since": NUM, "until": NUM, "first_seen": NUM + NULL, "last_seen": NUM + NULL, "state": STR + NULL, "power": STR + NULL, "watched": INT, "online": INT, "answering": INT, "share": NUM + NULL, "answering_share": NUM + NULL, "changes": INT, "events": INT, "sensors": LIST},
        )  # fmt: skip
        assert summary["sensors"] == ["device"] and summary["power"] == "on"
        states = victor.get(hist, params={"what": "states"}).json()
        seen.shaped(("GET", hist), states, {"since": NUM, "until": NUM, "rows": LIST, "more": BOOL})
        seen.shaped(("GET", hist), states["rows"][-1], {"t": NUM, "state": STR, "code": STR})
        samples = victor.get(hist, params={"what": "samples"}).json()
        seen.shaped(("GET", hist), samples, {"since": NUM, "until": NUM, "every": INT, "rows": LIST, "more": BOOL})
        seen.shaped(("GET", hist), samples["rows"][0], {"t": NUM, "sensor": STR, "unit": STR, "value": NUM})
        spans = victor.get(hist, params={"what": "samples", "every": 900}).json()
        seen.shaped(("GET", hist), spans, {"since": NUM, "until": NUM, "every": INT, "series": LIST, "more": BOOL})
        seen.shaped(("GET", hist), spans["series"][0], {"sensor": STR, "unit": STR, "points": LIST})
        assert len(spans["series"][0]["points"][0]) == 4  # [t, average, min, max]
        pressed = admin.post(f"/api/v1/devices/{kvm_id}/actions", json={"action": "atx_power"})
        assert pressed.status_code == 200, pressed.text
        wait_until(lambda: victor.get(hist, params={"what": "events"}).json()["rows"], "the pressed button never reached the history")
        events = victor.get(hist, params={"what": "events"}).json()
        seen.shaped(("GET", hist), events, {"since": NUM, "until": NUM, "rows": LIST, "more": BOOL})
        seen.shaped(("GET", hist), events["rows"][0], {"t": NUM, "kind": STR, "what": STR, "ok": BOOL + NULL, "note": STR})
        assert (events["rows"][0]["kind"], events["rows"][0]["what"], events["rows"][0]["ok"]) == ("pressed", "atx_power", True)
        seen.names.setdefault(("GET", "/api/v1/devices/{}/history"), set()).update({"what", "since", "until", "limit", "every"})
        seen.refused("GET", "/api/v1/devices/nosuch01/history", victor.get("/api/v1/devices/nosuch01/history"), 404, "not_found")
        seen.refused("GET", hist, victor.get(hist, params={"since": 2, "until": 1}), 422, "invalid")

        # --- a picture
        frame = victor.get(snap(kvm_id), params={"w": 320, "age": 1})
        assert frame.status_code == 200 and frame.headers["content-type"] in ("image/jpeg", "image/png") and frame.headers["x-kvm-signal"] == "1"
        assert frame.headers["cache-control"] == "no-store"
        seen.names.setdefault(("GET", "/api/v1/devices/{}/snapshot"), set()).update({"w", "age", "X-KVM-Signal"})
        wait_until(lambda: victor.get(snap(jet_id)).status_code == 200, "the JetKVM never produced a picture", timeout=20)
        not_yet = victor.get(snap(bmc_id))
        if not_yet.status_code == 503:  # (its controller's console is being opened: "not yet, ask again")
            seen.refused("GET", snap(bmc_id), not_yet, 503, "no_stream")
        wait_until(lambda: victor.get(snap(bmc_id)).status_code != 503, "the server's picture stayed at 'not yet'", timeout=20)
        seen.refused("GET", snap(bmc_id), victor.get(snap(bmc_id)), 404, "no_picture")
        # Asked for its screen once, this controller was found to have no console to read one from: the word goes, in both lists.
        wait_until(lambda: admin.get("/api/v1/status").json()[bmc_id]["screen"] is False, "the status went on saying that the server has a screen", timeout=10)
        assert "screen" not in admin.get("/api/v1/status").json()[bmc_id]["can"]
        assert "screen" not in next(tile for tile in admin.get("/api/v1/wall").json()["devices"] if tile["id"] == bmc_id)["can"]
        seen.refused("GET", snap(amt_id), victor.get(snap(amt_id)), 404, "no_picture")  # (a PC with Intel AMT that asks for its code: no session is opened)
        seen.refused("GET", snap("nosuch01"), victor.get(snap("nosuch01")), 404, "not_found")
        seen.refused("GET", snap(kvm_id), victor.get(snap(kvm_id), params={"w": 0}), 422, "invalid")

        # --- a pass for a live line (the line itself is a WebSocket: tests/test_live.py drives it, against the program on a port)
        given = victor.post(f"/api/v1/devices/{kvm_id}/live")
        assert given.status_code == 200, given.text
        seen.shaped(("POST", f"/api/v1/devices/{kvm_id}/live"), given.json(), {"v": INT, "ticket": STR})
        assert given.json()["v"] == 2 and re.fullmatch(r"[A-Za-z0-9_-]{16,200}", given.json()["ticket"])
        assert given.json()["ticket"] not in admin.get("/api/v1/audit").text
        seen.refused("POST", f"/api/v1/devices/{bmc_id}/live", victor.post(f"/api/v1/devices/{bmc_id}/live"), 404, "no_live")
        seen.refused("POST", f"/api/v1/devices/{amt_id}/live", victor.post(f"/api/v1/devices/{amt_id}/live"), 404, "no_live")  # (nor a live line)
        seen.refused("POST", "/api/v1/devices/nosuch01/live", victor.post("/api/v1/devices/nosuch01/live"), 404, "not_found")
        assert "live" not in admin.get("/api/v1/status").json()[bmc_id]["can"] and "live" in by_id[kvm_id]["can"] and "live" not in by_id[amt_id]["can"]

        # --- the saved actions, what can be woken, and doing something
        assert admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        assert admin.post("/api/v1/actions", json={"name": "Say hello", "kind": "text", "text": "uptime", "enter": True, "danger": True}).status_code == 201
        olga = browser(admin, "olga", port=50017)
        actions = olga.get("/api/v1/actions").json()
        seen.shaped(("GET", "/api/v1/actions"), actions, {"actions": LIST})
        for action in actions["actions"]:
            seen.shaped(("GET", "/api/v1/actions"), action, SAVED_ACTION)
        assert "uptime" not in olga.get("/api/v1/actions").text  # never the text
        by_name = {action["name"]: action for action in actions["actions"]}
        seen.refused("GET", "/api/v1/actions", victor.get("/api/v1/actions"), 403, "not_allowed")
        for device_id in (kvm_id, jet_id):
            targets = olga.get(f"/api/v1/devices/{device_id}/wol").json()
            seen.shaped(("GET", f"/api/v1/devices/{device_id}/wol"), targets, {"targets": LIST})
            seen.shaped(("GET", f"/api/v1/devices/{device_id}/wol"), targets["targets"][0], {"mac": STR, "name": STR})
        seen.refused("GET", "/api/v1/devices/nosuch01/wol", olga.get("/api/v1/devices/nosuch01/wol"), 404, "not_found")
        act = f"/api/v1/devices/{kvm_id}/actions"
        done = olga.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL", "batch": "run-1"})
        assert done.status_code == 200, done.text
        seen.shaped(("POST", act), done.json(), {"ok": BOOL, "note": STR + NULL})
        assert olga.post(act, json={"action": "port", "port": 1}).status_code == 200
        assert olga.post(act, json={"action": "custom", "custom_id": by_name["Lock the screen"]["id"], "custom_changed": 0}).status_code == 200
        seen.refused("POST", act, olga.post(act, json={"action": "custom", "custom_id": by_name["Lock the screen"]["id"], "custom_changed": 7}), 409, "changed")
        seen.refused("POST", act, olga.post(act, json={"action": "custom", "custom_id": "nosuch01"}), 404, "not_found")
        seen.refused("POST", act, olga.post(act, json={"action": "power_on"}), 422, "invalid")  # (a KVM presses buttons: `power_state` is not in its `can`)
        seen.refused("POST", act, olga.post(act, json={"action": "wol", "mac": "not a mac"}), 422, "invalid")
        seen.refused("POST", act, victor.post(act, json={"action": "keys", "keys": "Enter"}), 403, "not_allowed")
        seen.refused("POST", "/api/v1/devices/nosuch01/actions", olga.post("/api/v1/devices/nosuch01/actions", json={"action": "reboot"}), 404, "not_found")
        robot = another(admin, "192.0.2.50", 50018)
        robot.headers["Authorization"] = f"Bearer {robot_made.json()['token']}"
        seen.refused("POST", act, robot.post(act, json={"action": "custom", "custom_id": by_name["Say hello"]["id"]}), 403, "not_allowed")
        assert robot.post(act, json={"action": "text", "text": "ls", "enter": True}).status_code == 200  # its own text it may type
        on_the_server = f"/api/v1/devices/{bmc_id}/actions"
        already = olga.post(on_the_server, json={"action": "power_on"})
        assert (already.status_code, already.json()) == (200, {"ok": True, "note": "already on"}), already.text
        assert olga.post(on_the_server, json={"action": "locate_on"}).status_code == 200 and bmc.state.led == "Lit"
        assert olga.post(on_the_server, json={"action": "atx_reset"}).status_code == 200 and "ForceRestart" in bmc.state.actions[-1]
        seen.refused("POST", on_the_server, olga.post(on_the_server, json={"action": "keys", "keys": "Enter"}), 422, "invalid")
        on_the_pc = f"/api/v1/devices/{amt_id}/actions"
        already = olga.post(on_the_pc, json={"action": "power_on"})
        assert (already.status_code, already.json()) == (200, {"ok": True, "note": "already on"}), already.text
        assert olga.post(on_the_pc, json={"action": "atx_reset"}).status_code == 200 and pc.state.actions[-1] == 10
        seen.refused("POST", on_the_pc, olga.post(on_the_pc, json={"action": "reboot"}), 422, "invalid")  # (`reboot` is not in its `can`: the engine is not restarted from here)
        assert olga.post(f"/api/v1/devices/{jet_id}/actions", json={"action": "resume"}).status_code == 200
        assert olga.post(f"/api/v1/devices/{jet_id}/actions", json={"action": "atx_power"}).status_code == 200
        # One thing at a time per machine: a second one for the same machine, from wherever, is refused while the first is out.
        comet.state.slow["/api/hid/events/send_shortcut"] = 1.5
        arrived = comet.state.requests
        first, answers = in_background(lambda: olga.post(act, json={"action": "keys", "keys": "Enter"}))
        wait_until(lambda: comet.state.requests > arrived, "the first action never reached the KVM", timeout=5)
        seen.refused("POST", act, robot.post(act, json={"action": "reboot"}), 409, "busy")
        first.join(10)
        assert answers and answers[0].status_code == 200, answers
        del comet.state.slow["/api/hid/events/send_shortcut"]
        # The device's own refusal; and no answer at all, which may have been done.
        bmc.state.offered = ["On"]
        seen.refused("POST", on_the_server, olga.post(on_the_server, json={"action": "atx_power_long"}), 502, "action_failed")
        monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 1.0)
        jet.state.frozen = True
        seen.refused("POST", f"/api/v1/devices/{jet_id}/actions", olga.post(f"/api/v1/devices/{jet_id}/actions", json={"action": "jiggler_on"}), 504, "timeout")

        # --- a way into a server's own console, signed in: for a person who may act, and nobody else
        seen.refused("POST", f"/api/v1/devices/{kvm_id}/console", olga.post(f"/api/v1/devices/{kvm_id}/console", json={}), 404, "no_console")
        seen.refused("POST", f"/api/v1/devices/{bmc_id}/console", robot.post(f"/api/v1/devices/{bmc_id}/console", json={}), 403, "not_allowed")
        seen.refused("POST", f"/api/v1/devices/{bmc_id}/console", victor.post(f"/api/v1/devices/{bmc_id}/console", json={}), 403, "not_allowed")
        seen.refused("POST", "/api/v1/devices/nosuch01/console", olga.post("/api/v1/devices/nosuch01/console", json={}), 404, "not_found")
        way_in = olga.post(f"/api/v1/devices/{bmc_id}/console", json={})
        assert way_in.status_code == 200, way_in.text
        seen.shaped(("POST", f"/api/v1/devices/{bmc_id}/console"), way_in.json(), {"url": STR})
        assert way_in.json()["url"].startswith(bmc.url) and way_in.json()["url"] not in admin.get("/api/v1/audit").text

        # --- the order of the tiles, for everybody
        seen.refused("PUT", "/api/v1/wall/order", olga.put("/api/v1/wall/order", json={"ids": [bmc_id]}), 403, "not_allowed")
        arranged = admin.put("/api/v1/wall/order", json={"ids": [bmc_id]})
        seen.shaped(("PUT", "/api/v1/wall/order"), arranged.json(), {"ok": BOOL, "ids": LIST})
        assert arranged.json()["ids"] == [bmc_id, kvm_id, jet_id, amt_id]

        # --- the wall as a file, and a file taken in
        seen.refused("POST", "/api/v1/export", admin.post("/api/v1/export", json={"password": "not it", "parts": ["devices"]}), 401, "bad_password")
        seen.refused("POST", "/api/v1/export", admin.post("/api/v1/export", json={"password": PASSWORD, "parts": ["devices"], "passphrase": "short"}), 422, "invalid")
        seen.refused("POST", "/api/v1/export", robot.post("/api/v1/export", json={"password": PASSWORD, "parts": ["devices"]}), 403, "not_allowed")
        exported = admin.post("/api/v1/export", json={"password": PASSWORD, "parts": ["devices", "actions", "alerts", "wall"]})
        assert exported.status_code == 200, exported.text
        assert exported.headers["content-type"].startswith("application/json") and exported.headers["x-qkvm-not-opened"] == "0"
        assert re.fullmatch(r'attachment; filename="qkvm-\d{4}-\d{2}-\d{2}\.json"', exported.headers["content-disposition"])
        assert json.loads(exported.text)["format"] == "qkvm-export"
        seen.names.setdefault(("POST", "/api/v1/export"), set()).update({"X-QKVM-Not-Opened", "Content-Disposition"})
        seen.refused("POST", "/api/v1/import/read", admin.post("/api/v1/import/read", json={"file": "this is no file of qKVM's"}), 422, "not_a_file")
        read = admin.post("/api/v1/import/read", json={"file": exported.text})
        assert read.status_code == 200, read.text
        seen.shaped(
            ("POST", "/api/v1/import/read"), read.json(),
            {"encrypted": BOOL, "secrets": BOOL, "made": NUM, "program": STR, "devices": LIST + NULL, "actions": LIST + NULL, "alerts": DICT + NULL, "wall": DICT + NULL, "left_out": LIST},
        )  # fmt: skip
        for device in read.json()["devices"]:
            seen.shaped(("POST", "/api/v1/import/read"), device, FILE_DEVICE)
            assert device["new"] is False  # (each is on this wall already)
        for action in read.json()["actions"]:
            seen.shaped(("POST", "/api/v1/import/read"), action, FILE_ACTION)
        seen.shaped(("POST", "/api/v1/import/read"), read.json()["alerts"], {"enabled": BOOL, "address": BOOL, "host": STR, "format": STR, "kinds": LIST})
        seen.shaped(("POST", "/api/v1/import/read"), read.json()["wall"], {"interval": NUM, "update_check": BOOL})
        a_new_one = json.dumps({"format": "qkvm-export", "version": 1, "devices": [{"url": f"http://127.0.0.1:{closed_port()}", "kind": "kvmd", "name": "From a file"}]})
        taken = admin.post("/api/v1/import", json={"file": a_new_one, "take": ["devices"]})
        assert taken.status_code == 200, taken.text
        seen.shaped(("POST", "/api/v1/import"), taken.json(), {"devices": INT, "actions": INT, "alerts": BOOL, "wall": BOOL, "left_out": LIST})
        assert taken.json()["devices"] == 1 and len(admin.get("/api/v1/wall").json()["devices"]) == 5
        seen.refused("POST", "/api/v1/import", admin.post("/api/v1/import", json={"file": "no", "take": ["devices"]}), 422, "not_a_file")

        # --- several machines off the wall at once: every one of them, or none
        from_file = next(tile["id"] for tile in admin.get("/api/v1/wall").json()["devices"] if tile["name"] == "From a file")
        remove = "/api/v1/devices/remove"
        seen.refused("POST", remove, olga.post(remove, json={"ids": [from_file]}), 403, "not_allowed")
        seen.refused("POST", remove, robot.post(remove, json={"ids": [from_file]}), 403, "not_allowed")
        not_there = admin.post(remove, json={"ids": [from_file, "nosuch01"]})
        seen.refused("POST", remove, not_there, 404, "not_found")
        assert not_there.json()["unknown"] == ["nosuch01"] and len(admin.get("/api/v1/wall").json()["devices"]) == 5
        seen.names.setdefault(("POST", remove), set()).add("unknown")
        taken_off = admin.post(remove, json={"ids": [amt_id, from_file]})
        assert taken_off.status_code == 200, taken_off.text
        seen.shaped(("POST", remove), taken_off.json(), {"ok": BOOL, "removed": LIST})
        assert taken_off.json()["removed"] == [amt_id, from_file]  # (in the wall's order)
        assert [tile["id"] for tile in admin.get("/api/v1/wall").json()["devices"]] == [bmc_id, kvm_id, jet_id]

        # --- a token taken back: the screen that showed with it goes dark
        seen.refused("DELETE", "/api/v1/tokens/nosuch01", admin.delete("/api/v1/tokens/nosuch01"), 404, "not_found")
        gone = admin.delete(f"/api/v1/tokens/{display_id}")
        seen.shaped(("DELETE", f"/api/v1/tokens/{display_id}"), gone.json(), {"ok": BOOL})
        assert screen.get("/api/v1/wall").status_code == 401

        # --- what a token may not: sign out, change the account it has not got
        seen.refused("POST", "/api/v1/logout", robot.post("/api/v1/logout", json={}), 403, "not_allowed")
        seen.refused("POST", "/api/v1/password", robot.post("/api/v1/password", json={"current": PASSWORD, "new": "another long one"}), 403, "not_allowed")
        seen.refused("POST", "/api/v1/totp/begin", robot.post("/api/v1/totp/begin", json={"password": PASSWORD}), 403, "not_allowed")
        # --- and what everybody is refused without the page's header, or without being signed in
        bare = another(admin, "192.0.2.70", 50019)
        bare.headers.pop("X-QKVM", None)
        assert bare.post("/api/v1/login", json={"password": PASSWORD}, headers={"Origin": "https://elsewhere.example"}).status_code == 403
        seen.refused("GET", "/api/v1/status", bare.get("/api/v1/status"), 401, "unauthorized")

    seen.all_where_the_readme_describes_them()


def test_a_servers_screen_is_in_can_once_its_console_can_be_read(tmp_path: Path) -> None:
    bmc = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            wait_until(lambda: admin.get(snap(device)).status_code == 200, "the server's screen never came", timeout=20)
            status = admin.get("/api/v1/status").json()[device]
            assert status["screen"] is True and "screen" in status["can"] and "live" in status["can"]
            assert admin.get("/api/v1/wall").json()["devices"][0]["can"] == status["can"]
    finally:
        bmc.stop()


def test_a_device_that_cannot_be_reached_can_be_asked_what_its_driver_can(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd")
        wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "offline", "never reported offline")
        status = admin.get("/api/v1/status").json()[device]
        assert status["can"] == kvm.can_do(*kvm.KvmDevice.can) == admin.get("/api/v1/wall").json()["devices"][0]["can"]
        assert "power" not in status["can"] and "ports" not in status["can"]  # (what a look would add was not found: no look got through)
