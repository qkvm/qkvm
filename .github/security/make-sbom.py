"""Make a release's SBOM: a CycloneDX 1.5 JSON of exactly what installing the version brings in, read from the metadata of
the environments it is installed in. Run by the release workflow's job `libraries`, with Python's own library only:

    python -I -S .github/security/make-sbom.py --version X --wheel release/qkvm-X-py3-none-any.whl \
        --lock libraries/qkvm-X-libraries.json --environments DIR --output libraries/qkvm-X-sbom.cdx.json

DIR holds one folder for each target of the lock (cp313-linux-x86_64 and so on), named so: the lock's libraries for that
target and the built wheel, as pip installs them there (make-libraries.py --environments; a folder of distributions, as
`pip install --target` leaves it). In each, what qkvm requires is followed from its metadata, name by name (a requirement
whose library is not installed there is one its markers leave out on that target; one with no marker must be installed),
and nothing may be installed that is not reached so. What each target holds must be what the lock names for it, library
for library and version for version: the SBOM is the signed lock's, with what the metadata says of each library.

Each library is a component with its name, version, licence (the metadata's License-Expression; else its License field
where that is a short name; else its licence classifiers), a purl (pkg:pypi/<name>@<version>), and every wheel of it the
lock names, as a distribution reference with the address on PyPI's file host and the SHA-256 (the component's own hash
where there is one wheel for every target); the targets it is installed on where that is not every one. qkvm itself is
the SBOM's subject (metadata.component), with the SHA-256 of the built wheel. The dependencies are what each component's
metadata requires that is installed beside it, on any target. The same input makes the same bytes.

Nothing of a wheel or of an environment is run here: its metadata is read as text.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import importlib.metadata
import json
import re
import sys
import uuid
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import quote

NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?")
EXTRA = re.compile(r"""\bextra\s*==\s*(?:"([^"]*)"|'([^']*)')""")
SHA256 = re.compile(r"[0-9a-f]{64}")
SHORT = 80  # characters of a License field that is a licence's name, not its text
# What a project's URLs are called in its metadata, and the kind of reference CycloneDX gives each.
LINKS = {"homepage": "website", "documentation": "documentation", "source": "vcs", "issues": "issue-tracker", "changelog": "release-notes"}


class Refused(Exception):
    """What was given is not what an SBOM of the release can be made from. The message says why."""


def canonical(name: str) -> str:
    """A project's name as PyPI compares it (PEP 503), and as its purl writes it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{canonical(name)}@{quote(version, safe='')}"


def requirement(text: str) -> tuple[str, frozenset[str], str]:
    """A Requires-Dist line: the library's name (canonical), the extras it asks of it, and its marker ("" where none)."""
    found = NAME.match(text)
    if found is None:
        raise Refused(f"a requirement that names no library: {text!r}")
    extras = frozenset(canonical(extra.strip()) for extra in (found.group(2) or "").split(",") if extra.strip())
    marker = text[found.end() :].partition(";")[2].strip()
    return canonical(found.group(1)), extras, marker


def needed_for(marker: str, extras: frozenset[str]) -> bool | None:
    """Whether a requirement with this marker is wanted where its library was asked for with `extras`: False where it is
    one of an extra that was not asked for; True where it is one of an extra that was; None where its marker speaks of
    no extra (then whether it is installed tells: a marker of the target's own)."""
    if not re.search(r"\bextra\b", marker):
        return None
    named = {canonical(first or second) for first, second in EXTRA.findall(marker)}
    return bool(named & extras)


def licences(metadata: Message) -> list[dict[str, Any]]:
    """What the metadata says of the licence, as CycloneDX writes it (one expression, or licences by name)."""
    expression = (metadata.get("License-Expression") or "").strip()
    if expression:
        return [{"expression": expression}]
    field = (metadata.get("License") or "").strip()
    if field and "\n" not in field and len(field) <= SHORT and field.upper() != "UNKNOWN":
        return [{"license": {"name": field}}]
    named = [classifier.split("::")[-1].strip() for classifier in metadata.get_all("Classifier") or [] if classifier.startswith("License ::")]
    return [{"license": {"name": name}} for name in dict.fromkeys(named) if name and name != "OSI Approved"]


def environment(path: Path, version: str) -> dict[str, tuple[Message, set[str]]]:
    """What qkvm brings in, installed in `path`: each library by its canonical name, with its metadata and the canonical
    names of what it requires that is installed there. qkvm itself is among them, at `version`."""
    found: dict[str, Message] = {}
    for distribution in importlib.metadata.distributions(path=[str(path)]):
        text = distribution.read_text("METADATA")
        metadata = email.message_from_string(text or "")
        name = canonical(metadata.get("Name") or "")
        if not name or name in found:
            raise Refused(f"{path.name}: a library installed twice, or with no metadata ({name or 'none'})")
        found[name] = metadata
    if "qkvm" not in found or found["qkvm"].get("Version") != version:
        raise Refused(f"{path.name}: qkvm {version} is not installed there")
    reached: dict[str, set[str]] = {}
    todo: list[tuple[str, frozenset[str]]] = [("qkvm", frozenset())]
    seen: set[tuple[str, frozenset[str]]] = set()
    while todo:
        name, extras = todo.pop()
        if (name, extras) in seen:
            continue
        seen.add((name, extras))
        edges = reached.setdefault(name, set())
        for text in found[name].get_all("Requires-Dist") or []:
            dependency, asked, marker = requirement(text)
            wanted = needed_for(marker, extras)
            if wanted is False:
                continue
            if dependency not in found:
                if not marker:
                    raise Refused(f"{path.name}: {name} requires {dependency}, which is not installed there")
                continue  # (its marker leaves it out on this target; the lock, where given, is held to what is installed)
            edges.add(dependency)
            todo.append((dependency, asked))
    stray = sorted(set(found) - set(reached))
    if stray:
        raise Refused(f"{path.name}: installed there, and not brought in by qkvm: {', '.join(stray)}")
    return {name: (found[name], reached[name]) for name in reached}


def read_lock(path: Path, version: str) -> dict[str, dict[tuple[str, str], list[dict[str, Any]]]]:
    """The lock's wheels: for each target, for each (canonical name, version), the wheels it names."""
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("version") != version or not isinstance(lock.get("targets"), dict):
        raise Refused(f"{path.name} is not the lock of {version}")
    wheels: dict[str, dict[tuple[str, str], list[dict[str, Any]]]] = {}
    for target, entry in lock["targets"].items():
        libraries = wheels.setdefault(target, {})
        for library in entry["libraries"]:
            listed = [{"file": str(wheel["file"]), "url": str(wheel["url"]), "sha256": str(wheel["sha256"])} for wheel in library["wheels"]]
            if not listed or not all(SHA256.fullmatch(wheel["sha256"]) and wheel["url"].endswith("/" + wheel["file"]) for wheel in listed):
                raise Refused(f"{path.name}: {library['name']} {library['version']} on {target} has a wheel with no checksum or address")
            libraries[(canonical(library["name"]), str(library["version"]))] = listed
    return wheels


def sbom(version: str, wheel: Path, environments: dict[str, Path], lock: dict[str, dict[tuple[str, str], list[dict[str, Any]]]] | None) -> dict[str, Any]:
    """The SBOM of `version` (as a JSON document) from the environments it is installed in, by target."""
    if not environments:
        raise Refused("no environment to read")
    if wheel.name != f"qkvm-{version}-py3-none-any.whl":
        raise Refused(f"{wheel.name} is not the wheel of qkvm {version}")
    if lock is not None and set(lock) != set(environments):
        raise Refused(f"the environments ({', '.join(sorted(environments))}) are not the lock's targets ({', '.join(sorted(lock))})")
    libraries: dict[tuple[str, str], Message] = {}
    on: dict[tuple[str, str], set[str]] = {}
    requires: dict[tuple[str, str], set[tuple[str, str]]] = {}
    subject: Message | None = None
    for target, path in sorted(environments.items()):
        installed = environment(path, version)
        versions = {name: str(metadata.get("Version")) for name, (metadata, _) in installed.items()}
        if lock is not None:
            held = {(name, versions[name]) for name in installed if name != "qkvm"}
            if held != set(lock[target]):
                differ = sorted(f"{name} {each}" for name, each in held ^ set(lock[target]))
                raise Refused(f"{target}: what is installed is not what the lock names ({', '.join(differ)})")
        for name, (metadata, edges) in installed.items():
            key = (name, versions[name])
            if name == "qkvm":
                subject = subject or metadata
            else:
                libraries.setdefault(key, metadata)
                on.setdefault(key, set()).add(target)
            requires.setdefault(key, set()).update((each, versions[each]) for each in edges)
    assert subject is not None  # (every environment holds qkvm: environment() said so)
    every = sorted(environments)
    components = []
    for key in sorted(libraries):
        name, at = key
        metadata = libraries[key]
        component: dict[str, Any] = {"type": "library", "bom-ref": purl(name, at), "name": str(metadata.get("Name")), "version": at}
        said = licences(metadata)
        if said:
            component["licenses"] = said
        component["purl"] = purl(name, at)
        if lock is not None:
            files: dict[str, dict[str, Any]] = {}
            for target in sorted(on[key]):
                for each in lock[target][key]:
                    kept = files.setdefault(each["file"], {**each, "targets": []})
                    if kept["sha256"] != each["sha256"] or kept["url"] != each["url"]:
                        raise Refused(f"the lock names {each['file']} twice, with another checksum or address")
                    kept["targets"].append(target)
            if len(files) == 1:
                component["hashes"] = [{"alg": "SHA-256", "content": next(iter(files.values()))["sha256"]}]
            component["externalReferences"] = [
                {
                    "type": "distribution", "url": each["url"], "hashes": [{"alg": "SHA-256", "content": each["sha256"]}],
                    "comment": "the wheel for " + ("every target" if each["targets"] == every else ", ".join(each["targets"])),
                }
                for each in sorted(files.values(), key=lambda each: each["file"])
            ]  # fmt: skip
        if sorted(on[key]) != every:
            component["properties"] = [{"name": "qkvm:targets", "value": " ".join(sorted(on[key]))}]
        components.append(component)
    application: dict[str, Any] = {"type": "application", "bom-ref": purl("qkvm", version), "name": "qkvm", "version": version}
    said = licences(subject)
    if said:
        application["licenses"] = said
    application["purl"] = purl("qkvm", version)
    application["hashes"] = [{"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}]
    links = []
    for line in subject.get_all("Project-URL") or []:
        label, _, url = line.partition(",")
        kind = LINKS.get(label.strip().lower())
        if kind and url.strip().startswith("https://"):
            links.append({"type": kind, "url": url.strip()})
    if links:
        application["externalReferences"] = links
    dependencies = [
        {"ref": purl(*key), "dependsOn": sorted(purl(*each) for each in requires.get(key, set()))}
        for key in [("qkvm", version), *sorted(libraries)]
    ]  # fmt: skip
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "make-sbom.py", "version": version, "description": "qKVM's release workflow (.github/security/make-sbom.py)"}]},
            "component": application,
            "properties": [{"name": "qkvm:targets", "value": " ".join(every)}],
        },
        "components": components,
        "dependencies": dependencies,
    }
    # (A serial number made of the content: the same input makes the same bytes.)
    body = json.dumps(document, sort_keys=True).encode("utf-8")
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'https://qkvm.com/sbom/' + hashlib.sha256(body).hexdigest())}", **document}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--environments", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(argv)
    environments = {path.name: path for path in sorted(options.environments.iterdir()) if path.is_dir()}
    try:
        lock = read_lock(options.lock, options.version) if options.lock else None
        made = sbom(options.version, options.wheel, environments, lock)
    except Refused as ex:
        raise SystemExit(f"No SBOM was made: {ex}") from None
    options.output.write_text(json.dumps(made, indent=1, ensure_ascii=True) + "\n", encoding="ascii", newline="\n")
    print(f"{options.output.name}: qkvm {options.version} and {len(made['components'])} libraries, on {len(environments)} targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
