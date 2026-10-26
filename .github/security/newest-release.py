#!/usr/bin/env python3
"""Which moving image tags a publication may move; stdlib only.

    newest-release.py RELEASES.json TAG [--github-latest TAG] >> "$GITHUB_OUTPUT"

RELEASES.json is GitHub's list of the repository's releases (one list, or pages of lists as `gh api --paginate
--slurp` writes them). The released versions are the published ones (no draft, no prerelease) tagged vX.Y.Z, and the
one being published counts whether the list shows it yet or not. Prints latest=true when TAG is the newest of all
(the image tag `latest`), minor=true when it is the newest of its line X.Y (the image tag `X.Y`); the full version's
tag is always the publication's. With --github-latest, the release GitHub labels "Latest" (what the in-app updater
asks GitHub for), a warning goes to stderr where that is not the newest version.
Exit status: 0 = said, 1 = refused (what was given cannot be read as releases and a version), 2 = usage.
"""

import argparse
import json
from pathlib import Path
import re
import sys

VERSION = re.compile(r"v(\d+)\.(\d+)\.(\d+)")


class Refused(ValueError):
    """The list or the tag cannot be read as releases and a version."""


def version_of(tag):
    match = VERSION.fullmatch(tag) if isinstance(tag, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


def released(releases):
    """The versions published (no draft, no prerelease, a tag vX.Y.Z), from a list or from pages of lists."""
    if not isinstance(releases, list):
        raise Refused("the releases are not a list")
    items = [item for page in releases for item in page] if releases and all(isinstance(page, list) for page in releases) else releases
    versions = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("tag_name"), str):
            raise Refused("a release without a tag")
        if type(item.get("draft")) is not bool or type(item.get("prerelease")) is not bool:
            raise Refused(f"{item['tag_name']}: draft and prerelease must be true or false")
        version = version_of(item["tag_name"])
        if version and not item["draft"] and not item["prerelease"]:
            versions.add(version)
    return versions


def moves(releases, tag):
    current = version_of(tag)
    if current is None:
        raise Refused(f"{tag!r} is not a release version vX.Y.Z")
    versions = released(releases) | {current}
    return {
        "latest": current == max(versions),
        "minor": current == max(version for version in versions if version[:2] == current[:2]),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("releases")
    parser.add_argument("tag")
    parser.add_argument("--github-latest", default="")
    arguments = parser.parse_args(argv)
    try:
        releases = json.loads(Path(arguments.releases).read_text(encoding="utf-8"))
        said = moves(releases, arguments.tag)
        newest = max(released(releases) | {version_of(arguments.tag)})
    except (OSError, UnicodeError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    for name in ("latest", "minor"):
        print(f"{name}={'true' if said[name] else 'false'}")
    if arguments.github_latest and version_of(arguments.github_latest) != newest:
        print(
            f"::warning::GitHub labels {arguments.github_latest} the latest release, and the in-app updater offers that one; "
            f"the newest released version is v{'.'.join(map(str, newest))}. Set that one as the latest release on GitHub.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
