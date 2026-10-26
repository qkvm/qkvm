#!/usr/bin/env python3
"""Gate the native code the vulnerability scanner cannot see against the minimums kept in the repository.

    check-native-versions.py native-versions.json --minimums native-minimums.json --arch amd64

native-versions.json is what native-versions.py printed inside the image: each component's own words. A version is
read out of them by a pattern of its own, exactly; a component that is below its minimum, or whose version cannot be
read, blocks the image. Every component recorded must have a minimum, and every minimum a component recorded, each
with the reason it is what it is. Exit status: 0 = passed, 1 = blocked, 2 = malformed or incomplete input.

A minimum keeps a release from going out with a library older than the reviewed one; it does not know of an advisory
published later. When one is, raise the minimum to the fixed version (with the reason), and the gate holds every image
to it from then on.
"""

import argparse
import json
from pathlib import Path
import re
import sys

ARCHITECTURES = {"amd64", "arm64"}
VERSION = re.compile(r"\d+(?:\.\d+)+")
# How each component says its version (see native-versions.py), and nothing looser.
PATTERNS = {
    "cpython": re.compile(r"(\d+\.\d+\.\d+)"),
    "ffmpeg": re.compile(r"n?(\d+\.\d+(?:\.\d+)?)"),
    "libvpx": re.compile(r"v(\d+\.\d+\.\d+)"),
    "libopus": re.compile(r"libopus (\d+\.\d+(?:\.\d+)?)"),
    "libdav1d": re.compile(r"(\d+\.\d+\.\d+)"),
    "cryptography-openssl": re.compile(r"OpenSSL (\d+\.\d+\.\d+)(?: .*)?"),
    "pylibsrtp-libsrtp": re.compile(r"libsrtp2 (\d+\.\d+\.\d+)"),
    "pylibsrtp-openssl": re.compile(r"OpenSSL (\d+\.\d+\.\d+)(?: .*)?"),
}


class InvalidInput(ValueError):
    """The record or the minimums cannot safely be interpreted."""


def parse_version(text):
    if not isinstance(text, str) or not VERSION.fullmatch(text):
        raise InvalidInput(f"not a version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def version_of(name, text):
    """The version a component's own words give, or None where they are not what that component says."""
    match = PATTERNS[name].fullmatch(text) if isinstance(text, str) else None
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def padded(version, length):
    return version + (0,) * (length - len(version))


def text_value(value, label):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise InvalidInput(f"{label} must be a nonempty string without outer whitespace")
    return value


def minimums_of(document):
    if not isinstance(document, dict) or set(document) != {"schema", "components"} or document["schema"] != 1:
        raise InvalidInput("minimums must be {schema: 1, components: {...}}")
    components = document["components"]
    if not isinstance(components, dict) or set(components) != set(PATTERNS):
        raise InvalidInput(f"minimums must name exactly: {', '.join(sorted(PATTERNS))}")
    minimums = {}
    for name, entry in components.items():
        if not isinstance(entry, dict) or set(entry) != {"minimum", "source", "reason"}:
            raise InvalidInput(f"{name} must have exactly a minimum, a source and a reason")
        text_value(entry["source"], f"{name}.source")
        text_value(entry["reason"], f"{name}.reason")
        minimums[name] = parse_version(entry["minimum"])
    return minimums


def evaluate(record, document, arch):
    """Each component's version, and what blocks the image."""
    if arch not in ARCHITECTURES:
        raise InvalidInput(f"unsupported architecture: {arch}")
    minimums = minimums_of(document)
    if not isinstance(record, dict) or record.get("schema") != 1 or not isinstance(record.get("raw"), dict):
        raise InvalidInput("the record is not what native-versions.py prints")
    if record.get("arch") != arch:
        raise InvalidInput(f"the record is of {record.get('arch')!r}, not {arch}")
    raw = record["raw"]
    if set(raw) != set(minimums):
        raise InvalidInput(f"the record must name exactly: {', '.join(sorted(minimums))}")
    versions, blocked = {}, []
    for name in sorted(raw):
        version = version_of(name, raw[name])
        if version is None:
            blocked.append(f"{name}: cannot read a version from {raw[name]!r}")
            continue
        versions[name] = version
        length = max(len(version), len(minimums[name]))
        if padded(version, length) < padded(minimums[name], length):
            blocked.append(f"{name} {'.'.join(map(str, version))} is below its minimum {'.'.join(map(str, minimums[name]))}")
    return versions, blocked


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidInput(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("record", help="what native-versions.py printed inside the image")
    parser.add_argument("--minimums", required=True)
    parser.add_argument("--arch", required=True, choices=sorted(ARCHITECTURES))
    arguments = parser.parse_args(argv)
    try:
        record = load_json(arguments.record)
        versions, blocked = evaluate(record, load_json(arguments.minimums), arguments.arch)
    except (OSError, UnicodeError, json.JSONDecodeError, InvalidInput) as error:
        print(f"INVALID INPUT: {error}", file=sys.stderr)
        return 2
    for name in sorted(versions):
        print(f"RECORDED: {name} {'.'.join(map(str, versions[name]))} ({record['raw'][name]})")
    for row in blocked:
        print(f"BLOCKED: {row}")
    print(f"{'FAIL' if blocked else 'PASS'}: {arguments.arch}; {len(versions)} bundled native components read; {len(blocked)} blocked.")
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
