"""What the client API /api/v1 promises, as a program reads it: the list `api_v1.json` beside this file.

The guide's chapter "The API" says the promise in words, for a person; the list says it for a program: every request a
client may rely on (who may ask it, what it takes, what it answers and of what kind each field is, how it refuses, and
since which version it is so), the records the answers are made of, and which other requests the wall serves (the page's
own, which change with it). The program's own tests hold the list to the wall and to the guide; `qkvm.conformance` holds
a running wall to it, for a client that wants to know.

The kinds of a field, in the list: `str`, `int`, `num` (an int or a float), `bool`, `list`, `dict`, `null`; the name of a
record (`account`); `[x]`, a list of x; `{x}`, an object whose values are x (by a machine's id); and several of those
joined by `|`, of which the value is one. A boolean is never an `int` or a `num`, as JSON has it.

A record's fields are in groups: `fields`, always there; `seen`, there once the machine was looked at (`seen_when` says by
what: a state of `online` or `no_signal`); `optional`, there where they apply; `admin`, there to an admin and never to
anybody else. `since` names the fields promised later than the request that answers with the record; `open`, that an
entry holds more as its kind writes it (the activity log's). A request's `sends` and `query` are records of what it takes,
`fields` the ones it must have; `own` what it takes beyond the promise (the page's own). `codes_since` names the codes
promised later than the oldest wall the list describes, with the version since: of `every_request_may` and `device_may`,
and those a request that is older answers with since (`machine_changed`).
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

LIST = Path(__file__).with_name("api_v1.json")
WORDS = Path(__file__).parent / "static" / "words.json"
PRIMITIVES = ("str", "int", "num", "bool", "list", "dict", "null")
_ATOM = re.compile(r"[a-z][a-z0-9_]*")
_NAMED = re.compile(r"{[^}/]+}")  # a name in a path: {id}, {device_id}, {stamp}


@cache
def the_list() -> dict[str, Any]:
    """The list as this copy of qKVM ships it."""
    loaded: dict[str, Any] = json.loads(LIST.read_text(encoding="utf-8"))
    return loaded


@cache
def words() -> dict[str, Any]:
    """words.json, as this copy ships it: the states, the codes and the statuses they come with, the kinds and the words of `can`."""
    loaded: dict[str, Any] = json.loads(WORDS.read_text(encoding="utf-8"))
    return loaded


def key(method: str, path: str) -> tuple[str, str]:
    """A request as the list and the router are compared by: its method, and its path with every name in it as {}."""
    return method.upper(), _NAMED.sub("{}", path)


@cache
def requests() -> dict[tuple[str, str], dict[str, Any]]:
    """Every promised request, by key()."""
    return {key(entry["method"], entry["path"]): entry for entry in the_list()["requests"]}


def parse(kind: str) -> list[tuple[str, str]]:
    """A kind as the list writes it, in its alternatives: each (form, name), form "" for a value of that primitive or record,
    "[" for a list of them and "{" for an object of them. ValueError where it does not read."""
    found = []
    for part in kind.split("|"):
        form, name = "", part
        if part[:1] == "[" and part[-1:] == "]":
            form, name = "[", part[1:-1]
        elif part[:1] == "{" and part[-1:] == "}":
            form, name = "{", part[1:-1]
        if not _ATOM.fullmatch(name):
            raise ValueError(f"not a kind the list writes: {kind!r}")
        found.append((form, name))
    return found


def referenced(kind: str) -> set[str]:
    """The records a kind names."""
    return {name for _, name in parse(kind) if name not in PRIMITIVES}


def primitives(kind: str) -> set[str]:
    """What JSON a value of this kind is: a record is a dict, a list of anything a list."""
    found = set()
    for form, name in parse(kind):
        found.add("list" if form == "[" else "dict" if form == "{" or name not in PRIMITIVES else name)
    return found


GROUPS = ("fields", "seen", "optional", "admin")


def names(record: dict[str, Any]) -> list[str]:
    """Every field a record (or what a request sends, or its parameters) names, whichever group it is in."""
    return [name for group in GROUPS for name in record.get(group, {})]


def kinds(record: dict[str, Any]) -> dict[str, str]:
    """Every field of a record with its kind."""
    return {name: kind for group in GROUPS for name, kind in record.get(group, {}).items()}


def may_refuse(entry: dict[str, Any], code: str) -> set[int]:
    """The statuses a request may answer `code` with: as its own row names it, as any request may, and as a device may
    answer where the request asks one. Empty: the request is not promised to answer that code at all."""
    listed = the_list()
    found = set(entry.get("codes", {}).get(code, [])) | set(listed["every_request_may"].get(code, []))
    if entry.get("asks_device"):
        found |= set(listed["device_may"].get(code, []))
    return found


def reached(entry: dict[str, Any]) -> set[str]:
    """The records a request's answer is made of (its variants', what it sends, what its refusals carry, too), all the way down."""
    records = the_list()["records"]
    pending = [entry.get("answer", "null"), *entry.get("variants", {}).values(), *entry.get("carries", {}).values()]
    for part in ("sends", "query"):
        pending += kinds(entry.get(part, {})).values()
    found: set[str] = set()
    while pending:
        for name in referenced(pending.pop()) - found:
            found.add(name)
            pending += kinds(records[name]).values()
    return found
