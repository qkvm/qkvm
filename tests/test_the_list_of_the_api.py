"""The list of what /api/v1 promises (qkvm/api_v1.json), held to the wall that serves it and to the guide that says it.

A client of a wall (the Desktop App, a phone, a script) is written against the promise, and a wall and its clients are
upgraded at different times. The guide's chapter "The API" says the promise in words; the list says it for a program, and
ships with qKVM. Neither may drift from what the wall does, nor from each other: a request added, taken away or changed
(who may, what it takes, what it answers, how it refuses) without the list and the guide changing with it fails here.
What every promised answer was seen to hold is held to the list by tests/test_the_api_as_promised.py, request by request.
"""

from __future__ import annotations

import re
import types
import typing
from pathlib import Path
from typing import Any

import pytest
from packaging.version import Version
from pydantic import BaseModel

from qkvm import promise, server
from qkvm._version import __version__
from qkvm.core import Core
from tests.test_the_api_as_promised import CHAPTER, PAGES_OWN, rows, served

GUIDE_ERRORS = CHAPTER.split("### Errors", 1)[1].split("\n### ", 1)[0]
NAMED = re.compile(r"{[^}]+}")


def section(title: str) -> str:
    return CHAPTER.split(f"### {title}", 1)[1].split("\n### ", 1)[0]


def said(name: str, text: str) -> bool:
    """Whether the guide names it: in backticks, as a JSON key in an example, or as a parameter of an address it writes."""
    return f"`{name}`" in text or f'"{name}"' in text or re.search(rf"[?&]{re.escape(name)}=", text) is not None


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return server.create_app(Core(tmp_path_factory.mktemp("wall")))


def test_the_list_is_shipped_inside_the_package() -> None:
    # (The wheel takes every file of the package folder: hatch's `packages = ["qkvm"]`. The sdist takes the folder whole.)
    assert promise.LIST.parent == Path(server.__file__).parent and promise.LIST.is_file()
    listed = promise.the_list()
    assert listed["api"] == "v1" and Version(listed["oldest"]) >= Version("0.2.0")
    assert len(promise.requests()) >= 40


def test_every_route_the_wall_serves_is_in_the_list_and_the_list_names_no_other(app: Any) -> None:
    there = set(served(app))
    sockets = {NAMED.sub("{}", route.path) for route in app.routes if getattr(route, "methods", None) is None}
    listed = promise.the_list()
    promised = set(promise.requests())
    own = {promise.key(*entry.split(" ", 1)) for entry in listed["own"]}
    outside = {promise.key(*entry.split(" ", 1)) for entry in listed["outside"]}
    assert not promised & own and not promised & outside and not own & outside, "a request listed under two headings"
    unlisted = sorted(there - promised - own - outside)
    assert not unlisted, f"served, and in no part of qkvm/api_v1.json (promised, the page's own, or outside the API): {unlisted}"
    gone = sorted((promised | own | outside) - there)
    assert not gone, f"in qkvm/api_v1.json, and not served: {gone}"
    assert sockets == {promise.key("GET", socket["path"])[1] for socket in listed["websockets"]}
    assert all(path.startswith("/api/v1/") for _, path in own), "the page's own requests are those under /api/v1/ that are not promised"


def test_who_may_ask_is_who_the_wall_lets_ask(app: Any) -> None:
    there = served(app)
    for request, entry in promise.requests().items():
        assert entry["who"] == there[request], f"{request}: the list says {entry['who']}, the wall asks for {there[request]}"
        public = NAMED.sub("ab12cd34", request[1]) in server.PUBLIC
        assert (entry["who"] == "nobody") == public, request


def model_of(route: Any) -> type[BaseModel] | None:
    """The model a route reads its JSON body into, where it reads one."""
    params = route.dependant.body_params
    assert len(params) <= 1, route.path
    if not params:
        return None
    model = params[0].field_info.annotation
    assert isinstance(model, type) and issubclass(model, BaseModel), route.path
    return model


SIMPLE = {str: "str", bool: "bool", int: "int", float: "num"}


def kind_of(annotation: Any) -> set[str] | None:
    """What a field of a request's model is, in the list's words, where it is simple enough to say; None where it is not."""
    if annotation in SIMPLE:
        return {SIMPLE[annotation]}
    origin = typing.get_origin(annotation)
    if origin is typing.Literal:
        return {SIMPLE[type(choice)] for choice in typing.get_args(annotation)}
    if origin is list:
        return {"list"}
    if origin in (typing.Union, types.UnionType):
        found: set[str] = set()
        for part in typing.get_args(annotation):
            kind = {"null"} if part is type(None) else kind_of(part)
            if kind is None:
                return None
            found |= kind
        return found
    return None


def test_what_each_promised_request_takes_is_what_the_wall_reads(app: Any) -> None:
    for route in app.routes:
        if getattr(route, "methods", None) is None:
            continue
        for method in route.methods:
            entry = promise.requests().get(promise.key(method, route.path))
            if entry is None:
                continue
            where = f"{method} {route.path}"
            own = set(entry.get("own", []))
            # The body: every field the wall reads is promised or named as the page's own; the required ones are the list's.
            model = model_of(route)
            sends = entry.get("sends", {"fields": {}, "optional": {}})
            required, optional = set(sends["fields"]), set(sends["optional"])
            if model is None:
                assert not required | optional, f"{where}: the list names a body the wall does not read"
            else:
                fields = model.model_fields
                assert required == {name for name, field in fields.items() if field.is_required()}, f"{where}: what must be sent"
                assert required | optional <= set(fields), f"{where}: the list promises fields the wall does not read: {sorted(required | optional - set(fields))}"
                assert set(fields) <= required | optional | own, f"{where}: the wall reads fields the list does not name: {sorted(set(fields) - required - optional - own)}"
                for name in required | optional:
                    kind = kind_of(fields[name].annotation)
                    listed = promise.primitives(sends["fields"].get(name) or sends["optional"][name])
                    assert kind is None or kind == listed, f"{where}: {name} is {kind} to the wall and {listed} in the list"
            # The address's parameters: the same, where the route declares them.
            declared = {param.name for param in route.dependant.query_params}
            query = entry.get("query", {"fields": {}, "optional": {}})
            named = set(query["fields"]) | set(query["optional"])
            assert named <= declared, f"{where}: the list promises parameters the wall does not read: {sorted(named - declared)}"
            assert declared <= named | own, f"{where}: the wall reads parameters the list does not name: {sorted(declared - named - own)}"


def test_the_list_and_the_guide_promise_the_same_requests() -> None:
    table = rows()
    listed = promise.requests()
    assert set(table) == set(listed), {"only in the guide": sorted(set(table) - set(listed)), "only in the list": sorted(set(listed) - set(table))}
    for request, (role, line) in table.items():
        entry = listed[request]
        who = line.strip().strip("|").split("|")[1]
        assert entry["who"] == role, f"{request}: the guide says {role}, the list {entry['who']}"
        assert entry.get("person", False) == ("a person" in who), f"{request}: whether a token may ask"
    for socket in promise.the_list()["websockets"]:
        assert f"| a WebSocket at `{socket['path']}`" in CHAPTER


def texts_for(request: tuple[str, str], entry: dict[str, Any]) -> str:
    """Where the guide describes a request: its row, and the sections its entry names (as "Doing something" for an action)."""
    return rows()[request][1] + "".join(section(title) for title in entry.get("also_in", []))


def described(record: dict[str, Any], fallback: str) -> str:
    """Where the guide describes a record: a section of its own, the row of the request that describes it, or `fallback`."""
    place = record.get("described")
    if place is None:
        return fallback
    if place.split(" ", 1)[0] in ("GET", "POST", "PUT", "DELETE"):
        method, path = place.split(" ", 1)
        return rows()[promise.key(method, path)][1]
    return section(place)


def test_every_name_in_the_list_is_said_by_the_guide_where_it_describes_it() -> None:
    listed = promise.the_list()
    records = listed["records"]
    unsaid: list[str] = []
    for request, entry in promise.requests().items():
        text = texts_for(request, entry)
        for part in ("sends", "query"):
            unsaid += [f"{request} {part} {name}" for name in promise.names(entry.get(part, {})) if not said(name, text)]
        unsaid += [f"{request} own {name}" for name in entry.get("own", []) if not said(name, text + PAGES_OWN)]
        unsaid += [f"{request} header {name}" for name in {**entry.get("headers", {}), **entry.get("optional_headers", {})} if name not in text]
        unsaid += [f"{request} carries {name}" for name in entry.get("carries", {}) if not said(name, text)]
        for record_name in promise.reached(entry):
            record = records[record_name]
            where = described(record, text)
            unsaid += [f"{request} answer {record_name}.{name}" for name in promise.names(record) if not said(name, where)]
    assert not unsaid, unsaid


def test_every_code_in_the_list_is_said_by_the_guide_and_by_the_words() -> None:
    listed = promise.the_list()
    refusals = promise.words()["refusals"]
    for group in ("every_request_may", "device_may"):
        for code, statuses in listed[group].items():
            assert f"`{code}`" in GUIDE_ERRORS, f"{group}: {code} is not in the guide's table of errors"
            assert set(statuses) <= set(refusals[code]), f"{code}: {statuses} in the list, {refusals.get(code)} in words.json"
    unsaid, unworded = [], []
    for request, entry in promise.requests().items():
        text = texts_for(request, entry)
        for code, statuses in entry.get("codes", {}).items():
            if f"`{code}`" not in text:
                unsaid.append(f"{request}: {code}")
            if not set(statuses) <= set(refusals.get(code, [])):
                unworded.append(f"{request}: {code} {statuses}")
    assert not unsaid, f"codes the list names for a request, and its row does not: {unsaid}"
    assert not unworded, f"codes with statuses words.json does not give them: {unworded}"


def test_the_list_is_well_formed() -> None:
    listed = promise.the_list()
    records = listed["records"]
    oldest = Version(listed["oldest"])
    for name, record in records.items():
        assert set(record) <= {"fields", "optional", "admin", "seen", "seen_when", "since", "described", "open"}, name
        assert ("seen" in record) == ("seen_when" in record), f"{name}: what is there once the machine was looked at, and when that is"
        for group in ("fields", "optional", "admin", "seen"):
            for field, kind in record.get(group, {}).items():
                promise.parse(kind)  # (raises where it does not read)
                assert promise.referenced(kind) <= set(records), f"{name}.{field}: {kind}"
        assert set(record.get("since", {})) <= set(promise.names(record)), name
        assert all(Version(version) > oldest for version in record.get("since", {}).values()), name
    shared = {*listed["every_request_may"], *listed["device_may"]}
    of_requests = {code for entry in promise.requests().values() for code in entry.get("codes", {})}
    assert set(listed["codes_since"]) <= shared | of_requests and all(oldest < Version(since) <= Version(__version__) for since in listed["codes_since"].values())
    for request, entry in promise.requests().items():
        assert set(entry) <= {"method", "path", "who", "person", "since", "sends", "query", "answer", "variants", "status", "codes", "own", "headers", "optional_headers", "content", "carries", "asks_device", "also_in", "reads"}, request
        assert entry["who"] in ("nobody", "viewer", "operator", "admin") and Version(entry["since"]) >= oldest, request
        assert entry["reads"] == (request[0] == "GET"), f"{request}: only a GET is a read"
        assert ("answer" in entry) != ("content" in entry), f"{request}: JSON of a kind, or content of a type (a picture, a file)"
        for kind in [entry.get("answer", "null"), *entry.get("variants", {}).values()]:
            promise.parse(kind)
            assert promise.referenced(kind) <= set(records), f"{request}: {kind}"
        for part in ("sends", "query"):
            for kind in {**entry.get(part, {}).get("fields", {}), **entry.get(part, {}).get("optional", {})}.values():
                assert promise.referenced(kind) <= set(records), f"{request}: {kind}"
    used = {name for entry in promise.requests().values() for name in promise.reached(entry)}
    assert used == set(records), f"records no request answers with: {sorted(set(records) - used)}"
    with pytest.raises(ValueError):
        promise.parse("str|nonsense|")
