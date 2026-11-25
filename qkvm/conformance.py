"""Hold a running wall to the promise of /api/v1, reading only.

    python -P -m qkvm.conformance https://wall.example:8787 --token-file token.txt [--cafile cert.pem]

For a client of a wall (the Desktop App's joint test, a phone app, a script) that wants to know that the wall it talks to
answers as the promise says: every promised read, with what it holds and of what kind (`qkvm/api_v1.json`, as this copy
of qKVM ships it), the refusals and their codes, the headers. It sends GET and nothing else: it adds, changes and presses
nothing, opens no live line and no console. It asks each machine it reads for one picture (with the age the wall's own
tiles allow), its history, and, with an operator's token, what its KVM can wake: one machine of each kind, or every one
with --every-machine. The token is read from a file, sent to the wall alone, and never written out. (A wall behind a proxy
that signs people in, started with --sso-header, is checked at its own address: through the proxy, GET /api/v1/session
signs in whoever the proxy names.)

It prints one line for each thing it checked, and exits 0 where the wall answered every one as promised, 1 where it did
not, and 2 where it could not check (the wall out of reach, a certificate it does not trust, a token the wall does not
take, a wall that is locked or older than the promise this copy describes). A wall newer than this copy may answer with
fields, codes and words added since: each is a note, not a failure. --strict makes them failures, and holds the wall to
everything this copy promises whatever version it says it is: for a wall that is this very version (qKVM's own tests).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

import httpx
from packaging.version import InvalidVersion, Version

from . import promise
from ._version import __version__

OK, FAIL, NOTE, SKIP = "ok", "fail", "note", "skip"
LABELS = {OK: "ok", FAIL: "FAIL", NOTE: "note", SKIP: "skip"}
AS_PROMISED, NOT_AS_PROMISED, NOT_CHECKED = 0, 1, 2
ROLES = ("viewer", "operator", "admin")  # each may what the ones before it may
ID = re.compile(r"[0-9a-f]{8}")  # a machine's id, as the promise has it
SAYABLE = re.compile(r"[A-Za-z0-9_.-]{1,64}")  # what the wall sent that is written out as it came: a name of a field, a code
MOST_TOKEN = 512
# A read answered "ask again" is asked again, as a client does, so many times in all: "busy" (a history read of the same token
# under way) after its Retry-After, and this many seconds at the most; "no_stream" (a picture not there yet) after a moment.
TRIES = 4
BUSY_WAIT = 10.0
NOT_YET_WAIT = 2.0
PICTURE_WIDTH = 320
# What a request with a variant of its answer is asked with, for a name the variant gives no value (`every`: samples in spans).
VARIANT_VALUES = {"every": "3600"}
# What a machine's `can` must have before it is asked this (nothing else is asked of a machine than it says it can be).
NEEDS = {"/api/v1/devices/{id}/snapshot": "screen", "/api/v1/devices/{id}/wol": "wol"}


class NotChecked(Exception):
    """Something that ends the check before it is through: said, and the exit code is 2."""


def _kind_of(value: Any) -> str:
    """What a value is, in words; never the value itself, which may be anything a wall holds."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true or false"
    if isinstance(value, int):
        return "a whole number"
    if isinstance(value, float):
        return "a number"
    if isinstance(value, str):
        return "a text"
    if isinstance(value, list):
        return "a list"
    return "an object" if isinstance(value, dict) else "something else"


def _said(name: Any) -> str:
    return str(name) if isinstance(name, str) and SAYABLE.fullmatch(name) else "(a name not written out)"


def _listed(value: Any) -> list[str]:
    """The texts of a list the wall sent (`can`), and nothing else of it."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _what(path: str, params: dict[str, str] | None) -> str:
    return f"GET {path}" + ("?" + "&".join(f"{name}={value}" for name, value in params.items()) if params else "")


def _is(value: Any, primitive: str) -> bool:
    if primitive == "null":
        return value is None
    if primitive == "bool":
        return isinstance(value, bool)
    if isinstance(value, bool):
        return False  # (a boolean is no number, as JSON has it)
    kinds: dict[str, type | tuple[type, ...]] = {"str": str, "int": int, "num": (int, float), "list": list, "dict": dict}
    return isinstance(value, kinds[primitive])


@dataclass
class Reading:
    """How an answer is read: against what the wall's version promised (None: everything this copy promises), how strictly
    (a field or a word this copy does not know is a failure, not a note), and as whom (an admin sees fields nobody else does)."""

    version: Version | None
    strict: bool
    admin: bool = False

    def later(self, since: str | None) -> bool:
        """Whether something promised since `since` came after the wall's version, and is not to be expected of it."""
        return since is not None and self.version is not None and not self.strict and Version(since) > self.version

    @property
    def unknown(self) -> str:
        return FAIL if self.strict else NOTE


def judged(value: Any, kind: str, reading: Reading, at: str = "the answer") -> list[tuple[str, str]]:
    """What is not as promised in `value`, which the promise says is of `kind`: (level, a sentence) each; [] where it is."""
    found: list[tuple[str, str]] = []
    _judge(value, kind, reading, at, found)
    return found


def _judge(value: Any, kind: str, reading: Reading, at: str, found: list[tuple[str, str]]) -> None:
    records = promise.the_list()["records"]
    for form, name in promise.parse(kind):
        if form == "[":
            if isinstance(value, list):
                for number, item in enumerate(value):
                    _judge(item, name, reading, f"{at}[{number}]", found)
                return
        elif form == "{":
            if isinstance(value, dict):
                for key, item in value.items():
                    _judge(item, name, reading, f"{at}[{_said(key)}]", found)
                return
        elif name in promise.PRIMITIVES:
            if _is(value, name):
                return
        elif isinstance(value, dict):
            _record(value, records[name], reading, at, found)
            return
    found.append((FAIL, f"{at}: {_kind_of(value)}, where the promise says {kind}"))


def _record(value: dict[str, Any], record: dict[str, Any], reading: Reading, at: str, found: list[tuple[str, str]]) -> None:
    since = record.get("since", {})
    seen = bool(record.get("seen_when")) and all(value.get(field) in states for field, states in record["seen_when"].items())
    for group in promise.GROUPS:
        for name, kind in record.get(group, {}).items():
            where = f"{at}.{name}"
            if group == "admin" and not reading.admin:
                if name in value:
                    found.append((FAIL, f"{where}: shown to whoever asked, where only an admin is to see it"))
                continue
            if name not in value:
                needed = group in ("fields", "admin") or (group == "seen" and seen)
                if needed and not reading.later(since.get(name)):
                    found.append((FAIL, f"{where}: missing"))
                continue
            _judge(value[name], kind, reading, where, found)
    if not record.get("open"):
        known = set(promise.names(record))
        for name in value:
            if name not in known:
                found.append((reading.unknown, f"{at}.{_said(name)}: not in the promise this checker knows (added since?)"))


class Report:
    """The lines a check prints, one for each thing checked, and what they came to."""

    def __init__(self, out: TextIO) -> None:
        self.out = out
        self.counts: Counter[str] = Counter()

    def say(self, level: str, what: str, why: str = "") -> None:
        self.counts[level] += 1
        print(f"{LABELS[level]:<5} {what}{': ' + why if why else ''}", file=self.out, flush=True)

    def tell(self, line: str) -> None:
        print(line, file=self.out, flush=True)

    def findings(self, what: str, found: list[tuple[str, str]], fine: str = "as promised") -> None:
        for level, why in found:
            self.say(level, what, why)
        if not any(level == FAIL for level, _ in found):
            self.say(OK, what, fine)


class Wall:
    """The wall over the network, as a client reaches it: GET, and nothing else."""

    def __init__(self, address: str, token: str, cafile: str | None, timeout: float) -> None:
        verify: ssl.SSLContext | bool = ssl.create_default_context(cafile=cafile) if cafile else True
        common: dict[str, Any] = {"base_url": address, "verify": verify, "timeout": timeout, "follow_redirects": False, "trust_env": False}
        self._anybody = httpx.Client(**common)
        self._token = httpx.Client(**common, headers={"Authorization": f"Bearer {token}"})

    def close(self) -> None:
        self._anybody.close()
        self._token.close()

    def get(self, path: str, params: dict[str, str] | None = None, *, token: bool = True, header: str | None = None) -> httpx.Response:
        """GET `path`: with the token, without (`token` false), or with another Authorization header (`header`)."""
        client = self._token if token and header is None else self._anybody
        try:
            return client.get(path, params=params, headers={"Authorization": header} if header else None)
        except httpx.ConnectError as ex:
            if "CERTIFICATE_VERIFY_FAILED" in str(ex) or isinstance(ex.__cause__, ssl.SSLCertVerificationError):
                raise NotChecked("the wall's certificate is not one this checker trusts: give its certificate (or its CA's) with --cafile, and reach it by a name the certificate is for") from None
            raise NotChecked(f"the wall cannot be reached ({type(ex).__name__})") from None
        except httpx.TimeoutException:
            raise NotChecked(f"the wall did not answer {path} in time (--timeout)") from None
        except httpx.HTTPError as ex:
            raise NotChecked(f"the wall's answer to {path} could not be read ({type(ex).__name__})") from None


def _json(response: httpx.Response) -> tuple[Any, str | None]:
    """An answer's JSON, and why it is not JSON (None where it is)."""
    kind = response.headers.get("content-type", "")
    if not kind.startswith("application/json"):
        return None, f"answered as {_said(kind.split(';')[0]) if kind else 'nothing said'}, where JSON was promised"
    try:
        return json.loads(response.content), None
    except (ValueError, RecursionError):
        return None, "answered with JSON that does not read"


class Check:
    """One check of one wall."""

    def __init__(self, wall: Wall, report: Report, *, strict: bool, every_machine: bool, pictures: bool) -> None:
        self.wall, self.report = wall, report
        self.strict, self.every_machine, self.pictures = strict, every_machine, pictures
        self.reading = Reading(version=None, strict=strict)
        self.role = "viewer"
        self.interval = 1.0

    # --- one request, as promised ----------------------------------------------------------------------------------------

    def headers(self, what: str, path: str, response: httpx.Response) -> bool:
        """The headers every answer of its place carries; False where one is missing (said)."""
        fine = True
        if path.startswith("/api/"):
            for name, value in promise.the_list()["every_answer_under_api"].items():
                if value not in response.headers.get(name, ""):
                    self.report.say(FAIL, what, f"answered without {name}: {value}")
                    fine = False
        return fine

    def answered(self, what: str, path: str, response: httpx.Response, entry: dict[str, Any], kind: str | None = None) -> Any:
        """An answer of `entry`'s request: judged as promised (or as the refusal it is); its JSON, where it was a good one."""
        self.headers(what, path, response)
        if response.status_code != entry.get("status", 200):
            self.refused(what, path, response, entry)
            return None
        if "content" in entry:
            kind_said = response.headers.get("content-type", "").split(";")[0].strip()
            found = [] if kind_said in entry["content"] else [(FAIL, f"answered as {_said(kind_said)}, where {' or '.join(entry['content'])} was promised")]
            for name, pattern in entry.get("headers", {}).items():
                if not re.fullmatch(pattern, response.headers.get(name, "")):
                    found.append((FAIL, f"its header {name} is missing, or not as promised"))
            for name, pattern in entry.get("optional_headers", {}).items():
                if name in response.headers and not re.fullmatch(pattern, response.headers[name]):
                    found.append((FAIL, f"its header {name} is not as promised"))
            self.report.findings(what, found, f"{kind_said}, as promised")
            return None
        body, wrong = _json(response)
        if wrong is not None:
            self.report.say(FAIL, what, wrong)
            return None
        self.report.findings(what, judged(body, kind or entry["answer"], self.reading))
        return body

    def refused(self, what: str, path: str, response: httpx.Response, entry: dict[str, Any], expected: tuple[int, str] | None = None) -> str | None:
        """A refusal, held to the promise: its shape, and its code with its status as the request may answer it. Its code."""
        status = response.status_code
        body, wrong = _json(response)
        if wrong is not None or not isinstance(body, dict):
            self.report.say(FAIL, what, f"refused with {status}, and {wrong or 'not as {code, message}'}")
            return None
        code, message = body.get("code"), body.get("message")
        if not isinstance(code, str) or not SAYABLE.fullmatch(code) or not isinstance(message, str) or not message.strip():
            self.report.say(FAIL, what, f"refused with {status}, and not as {{code, message}} with a sentence to show")
            return None
        if expected is not None and (status, code) != expected:
            self.report.say(FAIL, what, f"{status} {code}, where {expected[0]} {expected[1]} was promised")
            return code
        if status not in promise.may_refuse(entry, code):
            if code in promise.words()["refusals"]:
                self.report.say(FAIL, what, f"{status} {code}, which the promise does not name for this request")
            else:
                self.report.say(self.reading.unknown, what, f"{status} {code}, a code this checker does not know (added since?)")
            return code
        if (status == 429 or (status == 503 and code == "busy")) and not response.headers.get("retry-after", "").isdigit():
            self.report.say(FAIL, what, f"{status} {code} without Retry-After in seconds")
            return code
        self.report.say(OK, what, f"{status} {code}, as promised")
        return code

    def ask(self, entry: dict[str, Any], path: str, params: dict[str, str] | None = None, kind: str | None = None) -> Any:
        """A promised read, asked with the token and judged; asked again a little later while it is answered "busy"."""
        for attempt in range(TRIES):
            response = self.wall.get(path, params)
            body = _json(response)[0] if response.status_code in (429, 503) else None
            code, wait = body.get("code") if isinstance(body, dict) else None, response.headers.get("retry-after", "")
            pause = min(float(wait), BUSY_WAIT) if code == "busy" and wait.isdigit() else NOT_YET_WAIT if code == "no_stream" else None
            if pause is None or attempt == TRIES - 1:
                break
            time.sleep(pause)
        return self.answered(_what(path, params), path, response, entry, kind)

    # --- the check ---------------------------------------------------------------------------------------------------------

    def entry(self, method: str, path: str) -> dict[str, Any]:
        return promise.requests()[promise.key(method, path)]

    def promised_here(self, entry: dict[str, Any]) -> bool:
        """Whether the wall's version promises this request; said where it does not."""
        if self.reading.later(entry["since"]):
            self.report.say(SKIP, f"{entry['method']} {entry['path']}", f"promised since {entry['since']}, and this wall is {self.reading.version}")
            return False
        return True

    def run(self) -> int:
        healthz = self.first_looks()
        self.who_may_without_the_token()
        wall = self.ask(self.entry("GET", "/api/v1/wall"), "/api/v1/wall")
        if not isinstance(wall, dict) or not isinstance(wall.get("devices"), list):
            raise NotChecked("without the wall's machines nothing more can be checked")
        if isinstance(wall.get("interval"), (int, float)) and not isinstance(wall["interval"], bool):
            self.interval = float(wall["interval"])
        about = self.ask(self.entry("GET", "/api/v1/about"), "/api/v1/about")
        if isinstance(about, dict) and about.get("version") != healthz.get("version"):
            self.report.say(FAIL, "GET /api/v1/about", "says another version than GET /healthz")
        machines = [tile for tile in wall["devices"] if isinstance(tile, dict)]
        for tile in machines:
            if not isinstance(tile.get("id"), str) or not ID.fullmatch(tile["id"]):
                self.report.say(FAIL, "GET /api/v1/wall", "a machine's id is not eight hexadecimal digits, as promised")
        ids = [tile["id"] for tile in machines if isinstance(tile.get("id"), str) and ID.fullmatch(tile["id"])]
        status = self.statuses(ids)
        self.words_of(machines, status)
        actions = self.wall.get("/api/v1/actions")
        if actions.status_code == 403:
            self.refused("GET /api/v1/actions", "/api/v1/actions", actions, self.entry("GET", "/api/v1/actions"), (403, "not_allowed"))
        else:
            self.role = "operator"
            self.answered("GET /api/v1/actions", "/api/v1/actions", actions, self.entry("GET", "/api/v1/actions"))
        self.report.tell(f"      (the token is a{'n operator' if self.role == 'operator' else ' viewer'}'s, and sees {len(ids)} machines)")
        done = {("GET", "/healthz"), ("GET", "/api/v1/session"), ("GET", "/api/v1/wall"), ("GET", "/api/v1/about"), ("GET", "/api/v1/status"), ("GET", "/api/v1/actions")}
        chosen = self.chosen(machines, status)
        for key, entry in sorted(promise.requests().items()):
            if not entry["reads"] or key in done or not self.promised_here(entry):
                continue
            if ROLES.index(entry["who"] if entry["who"] != "nobody" else "viewer") > ROLES.index(self.role) or entry.get("person"):
                self.refused_to_a_token(entry, ids)
                continue
            self.read(entry, chosen, status)
        self.refusals(ids)
        return NOT_AS_PROMISED if self.report.counts[FAIL] else AS_PROMISED

    def first_looks(self) -> dict[str, Any]:
        """What the wall says of itself without a token: GET /healthz, the session, words.json. Raises NotChecked where the wall
        is no qKVM, speaks no v1, is older than the promise this checker describes, or is locked."""
        response = self.wall.get("/healthz", token=False)
        healthz, wrong = _json(response)
        if response.status_code != 200 or wrong is not None or not isinstance(healthz, dict):
            raise NotChecked(f"GET /healthz answered {response.status_code}, not as a qKVM wall does: is this the wall's address?")
        self.report.findings("GET /healthz", judged(healthz, "healthz", self.reading))
        api: list[Any] = healthz["api"] if isinstance(healthz.get("api"), list) else []
        if "v1" not in api:
            raise NotChecked("the wall does not speak v1 of the API (its healthz `api` does not list it): one of the two needs an update")
        version: Version | None = None
        try:
            version = Version(str(healthz.get("version")))
        except InvalidVersion:
            self.report.say(NOTE, "GET /healthz", "its version does not read as one: everything this checker knows is expected of it")
        listed = promise.the_list()
        if version is not None and version < Version(listed["oldest"]):
            raise NotChecked(f"the wall is qKVM {version}, older than {listed['oldest']}, the oldest wall the promise describes: nothing judged")
        if not self.strict:
            self.reading.version = version
        newer = version is not None and version > Version(__version__)
        self.report.tell(f"      (the wall is qKVM {version or 'of a version not said'}; this checker holds it to the promise of qKVM {__version__}{', strictly' if self.strict else ''}{': what it added since is noted, not judged' if newer and not self.strict else ''})")
        if healthz.get("locked") is True:
            self.refused("GET /api/v1/wall", "/api/v1/wall", self.wall.get("/api/v1/wall"), self.entry("GET", "/api/v1/wall"), (503, "locked"))
            raise NotChecked("the wall is locked (restarted with --locked-start, and nobody has signed in since): a token is answered 503 locked until somebody does")
        response = self.wall.get("/api/v1/session", token=False)
        session = self.answered("GET /api/v1/session (no sign-in)", "/api/v1/session", response, self.entry("GET", "/api/v1/session"))
        if isinstance(session, dict) and (session.get("authenticated") is not False or session.get("user") is not None):
            self.report.say(FAIL, "GET /api/v1/session (no sign-in)", "a request without a sign-in is said to be signed in")
        self.words_file()
        return healthz

    def words_file(self) -> None:
        """words.json, which every wall serves: what it holds, and every code the promise names, with its statuses."""
        for file in promise.the_list()["files"]:
            what = f"GET {file['path']}"
            if self.reading.later(file["since"]):
                self.report.say(SKIP, what, f"promised since {file['since']}")
                continue
            response = self.wall.get(file["path"], token=False)
            words, wrong = _json(response)
            if response.status_code != 200 or wrong is not None or not isinstance(words, dict):
                self.report.say(FAIL, what, wrong or f"answered {response.status_code}")
                continue
            found = [(FAIL, f"holds no `{part}`") for part in file["holds"] if not isinstance(words.get(part), dict)]
            refusals: dict[str, Any] = words["refusals"] if isinstance(words.get("refusals"), dict) else {}
            listed = promise.the_list()
            named: dict[str, set[int]] = {}
            # (A code every request or every device may answer with, promised later than the wall's version, is not looked
            # for in its words: a released 0.3.2 has no `no_video`. The outside review of 0.4.0, bugs round 2.)
            later = {code for code, since in listed.get("codes_since", {}).items() if self.reading.later(since)}
            for group in (listed["every_request_may"], listed["device_may"]):
                for code, statuses in group.items():
                    if code not in later:
                        named.setdefault(code, set()).update(statuses)
            for group in (entry.get("codes", {}) for entry in listed["requests"] if not self.reading.later(entry["since"])):
                for code, statuses in group.items():
                    if code not in later:  # (a code a request of before answers with since: machine_changed, 0.4.0)
                        named.setdefault(code, set()).update(statuses)
            for code, statuses in sorted(named.items()):
                there = refusals.get(code)
                if not isinstance(there, list) or not statuses <= set(there):
                    found.append((FAIL, f"refusals: {code} is not there with {sorted(statuses)}, as the promise has it"))
            self.report.findings(what, found)

    def who_may_without_the_token(self) -> None:
        """A promised read asked without a token, and with one that is none: 401 unauthorized, and nothing more."""
        entry = self.entry("GET", "/api/v1/wall")
        self.refused("GET /api/v1/wall (no token)", "/api/v1/wall", self.wall.get("/api/v1/wall", token=False), entry, (401, "unauthorized"))
        wrong = self.wall.get("/api/v1/wall", header="Bearer qkvm_conformance-this-is-no-token")
        self.refused("GET /api/v1/wall (a token that is none)", "/api/v1/wall", wrong, entry, (401, "unauthorized"))
        response = self.wall.get("/api/v1/wall")
        if response.status_code == 401:
            raise NotChecked("the wall does not take this token (taken back, run out, or not one of this wall's tokens for a script)")

    def statuses(self, ids: list[str]) -> dict[str, Any]:
        """How each machine is: GET /api/v1/status, of the same machines as the wall lists (read again once where it was not)."""
        found = self.answered("GET /api/v1/status", "/api/v1/status", self.wall.get("/api/v1/status"), self.entry("GET", "/api/v1/status"))
        if not isinstance(found, dict):
            return {}
        if set(found) != set(ids):
            # (A machine added or taken off between the two reads: both are read once more, and must agree then.)
            wall, _ = _json(self.wall.get("/api/v1/wall"))
            again, _ = _json(self.wall.get("/api/v1/status"))
            listed = {tile.get("id") for tile in wall.get("devices", []) if isinstance(tile, dict)} if isinstance(wall, dict) and isinstance(wall.get("devices"), list) else set()
            if not isinstance(again, dict) or set(again) != listed:
                self.report.say(FAIL, "GET /api/v1/status", "names other machines than GET /api/v1/wall lists, read twice")
            else:
                found = again
        return found

    def words_of(self, machines: list[dict[str, Any]], status: dict[str, Any]) -> None:
        """The words a client shows: each state, kind, code and word of `can` is one words.json has, or one added since."""
        words = promise.words()
        unknown: set[str] = set()
        for tile in machines:
            if tile.get("kind") not in words["kinds"]:
                unknown.add(f"kind {_said(tile.get('kind'))}")
            unknown |= {f"can {_said(word)}" for word in _listed(tile.get("can")) if word not in words["can"]}
        for record in status.values():
            if not isinstance(record, dict):
                continue
            if record.get("state") not in words["states"]:
                unknown.add(f"state {_said(record.get('state'))}")
            unknown |= {f"can {_said(word)}" for word in _listed(record.get("can")) if word not in words["can"]}
            error = record.get("error")
            if isinstance(error, dict) and error.get("code") not in words["codes"]:
                unknown.add(f"code {_said(error.get('code'))}")
        for word in sorted(unknown):
            self.report.say(self.reading.unknown, "the words of GET /api/v1/wall and /status", f"{word}: not one this checker knows (added since?)")
        if not unknown:
            self.report.say(OK, "the words of GET /api/v1/wall and /status", "every state, kind, code and word of `can` is in words.json")

    def chosen(self, machines: list[dict[str, Any]], status: dict[str, Any]) -> list[tuple[str, list[str]]]:
        """The machines each of whose own reads are asked, with what each can: every one, or one of each kind (one that is
        online or shows no signal, where there is one)."""
        found: dict[str, tuple[str, list[str], bool]] = {}
        for tile in machines:
            machine = tile.get("id")
            if not isinstance(machine, str) or not ID.fullmatch(machine):
                continue
            now: dict[str, Any] = status[machine] if isinstance(status.get(machine), dict) else {}
            # (What it can be asked: the status's, the fresher, as a client goes by; the wall's until there is a status.)
            can = _listed(now.get("can")) if "can" in now else _listed(tile.get("can"))
            looked = now.get("state") in ("online", "no_signal")
            key = machine if self.every_machine else str(tile.get("kind"))
            if key not in found or (looked and not found[key][2]):
                found[key] = (machine, can, looked)
        return [(machine, can) for machine, can, _ in found.values()]

    def read(self, entry: dict[str, Any], chosen: list[tuple[str, list[str]]], status: dict[str, Any]) -> None:
        """A promised read the token may ask: of the wall, or of each chosen machine (where it can be asked that)."""
        path = entry["path"]
        names = re.findall(r"{([^}]+)}", path)
        if not names:
            self.variants(entry, path)
            return
        if names != ["id"]:
            self.report.say(SKIP, f"GET {path}", f"this checker has nothing to ask it by ({', '.join('{' + name + '}' for name in names)})")
            return
        needs = NEEDS.get(path)
        if needs == "screen" and not self.pictures:
            self.report.say(SKIP, f"GET {path}", "no pictures asked for (--no-pictures)")
            return
        for machine, can in chosen:
            if needs is None or needs in can:
                self.variants(entry, path.replace("{id}", machine))

    def variants(self, entry: dict[str, Any], path: str) -> None:
        params: dict[str, str] = {}
        if entry["path"].endswith("/snapshot"):
            params = {"w": str(PICTURE_WIDTH), "age": str(max(1, min(3600, round(self.interval * 2))))}
        self.ask(entry, path, params or None)
        for variant, kind in entry.get("variants", {}).items():
            asked = dict(part.split("=", 1) if "=" in part else (part, VARIANT_VALUES[part]) for part in variant.split("&"))
            self.ask(entry, path, asked, kind)

    def refused_to_a_token(self, entry: dict[str, Any], ids: list[str]) -> None:
        """A promised read this token may not ask (a higher role's, or a person's only): 403 not_allowed, and nothing done."""
        nobody = self.unknown_id(ids)
        path = re.sub(r"{[^}]+}", "1", entry["path"].replace("{id}", nobody))  # (refused before anything is looked up)
        params = {name: nobody for name in entry.get("query", {}).get("fields", {})} or None
        whose = {"admin": "an admin's", "operator": "an operator's"}.get(entry["who"], f"a {entry['who']}'s") + (", in person" if entry.get("person") else "")
        self.refused(f"GET {entry['path']} ({whose})", path, self.wall.get(path, params), entry, (403, "not_allowed"))

    @staticmethod
    def unknown_id(ids: list[str]) -> str:
        """An id no machine of the wall has: one of the first as many numbers as there are ids, and one more, is none of them
        (of the first sixteen alone, a wall that had them all stopped the checker with a traceback)."""
        taken = set(ids)
        return next(candidate for candidate in (f"{number:08x}" for number in range(len(taken) + 1)) if candidate not in taken)

    def refusals(self, ids: list[str]) -> None:
        """What a client meets when it asks wrongly, asked in ways that reach no machine: a machine the wall has not, a width
        of nothing, a window that ends before it begins."""
        nobody = self.unknown_id(ids)
        snapshot, history = self.entry("GET", "/api/v1/devices/{id}/snapshot"), self.entry("GET", "/api/v1/devices/{id}/history")
        asked: list[tuple[dict[str, Any], str, dict[str, str] | None, tuple[int, str]]] = [
            (snapshot, f"/api/v1/devices/{nobody}/snapshot", None, (404, "not_found")),
            (history, f"/api/v1/devices/{nobody}/history", None, (404, "not_found")),
            (snapshot, f"/api/v1/devices/{nobody}/snapshot", {"w": "0"}, (422, "invalid")),
        ]
        if ids:
            asked.append((history, f"/api/v1/devices/{ids[0]}/history", {"since": "2", "until": "1"}, (422, "invalid")))
        for entry, path, params, expected in asked:
            self.refused(_what(path, params), path, self.wall.get(path, params), entry, expected)


def _address(said: str) -> str:
    """The wall's address as given: http:// or https://, a host, a port; nothing after it."""
    parts = urlsplit(said.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise NotChecked("the wall's address is written as http://host:port or https://host:port, and nothing after it")
    return f"{parts.scheme}://{parts.netloc}"


def _token(file: str) -> str:
    """The token from its file: one line, as the wall showed it once. Never written out, whatever is wrong with it."""
    try:
        text = Path(file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as ex:
        raise NotChecked(f"the token file cannot be read ({type(ex).__name__})") from None
    token = text.strip()
    if not token or len(token) > MOST_TOKEN or not all(33 <= ord(ch) < 127 for ch in token):
        raise NotChecked("the token file holds no token: it should hold the token alone, on one line, as the wall showed it")
    return token


def _plain_and_far(address: str) -> bool:
    """Whether the token would cross a network unencrypted: plain HTTP to anything but this computer."""
    parts = urlsplit(address)
    if parts.scheme != "http":
        return False
    try:
        return not ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        return parts.hostname != "localhost"


def run(argv: list[str], out: TextIO | None = None) -> int:
    """Check the wall `argv` names; the exit code (0 as promised, 1 not, 2 not checked)."""
    out = sys.stdout if out is None else out
    parser = argparse.ArgumentParser(prog="python -P -m qkvm.conformance", description="Check, reading only, that a qKVM wall answers its API as promised (v1).")
    parser.add_argument("address", help="the wall, as http://host:port or https://host:port")
    parser.add_argument("--token-file", required=True, help="a file holding a token for a script (viewer or operator), made under Settings > Tokens")
    parser.add_argument("--cafile", help="a certificate to trust for the wall: its own (tls/cert.pem in its data folder) or its CA's")
    parser.add_argument("--strict", action="store_true", help="the wall is this checker's own version: hold it to every word of the promise")
    parser.add_argument("--every-machine", action="store_true", help="read every machine, not one of each kind")
    parser.add_argument("--no-pictures", action="store_true", help="ask no machine for a picture")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for one answer (30)")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return NOT_CHECKED
    report = Report(out)
    wall: Wall | None = None
    try:
        address = _address(args.address)
        token = _token(args.token_file)
        report.tell(f"qKVM conformance check of {address}, reading only")
        if _plain_and_far(address):
            report.tell("      (over plain HTTP: the token crosses the network unencrypted; a wall reached over the network is better reached over HTTPS)")
        wall = Wall(address, token, args.cafile, args.timeout)
        check = Check(wall, report, strict=args.strict, every_machine=args.every_machine, pictures=not args.no_pictures)
        code = check.run()
    except NotChecked as ex:
        report.tell(f"not checked: {ex}")
        return NOT_CHECKED
    finally:
        if wall is not None:
            wall.close()
    counts = report.counts
    report.tell(f"{sum(counts.values())} looked at: {counts[OK]} as promised, {counts[FAIL]} not; {counts[NOTE]} notes; {counts[SKIP]} skipped")
    return code


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
