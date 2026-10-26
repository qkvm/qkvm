#!/usr/bin/env python3
"""The source archive holds what the wheel was built and tested as; stdlib only.

    check-sdist.py WHEEL SDIST

Every file of the package (qkvm/...) is in both, byte for byte the same, and none is in only one of them; the name,
version, Python requirement and dependencies the wheel declares are those the source archive declares; and the wheel
holds nothing but qkvm/ and its own qkvm-<version>.dist-info/ (a top-level .pth would run at every start of the
Python it is installed into). The wheel is the one the release's suite ran against: with this, what PyPI gets as
source is that code too.
Exit status: 0 = the same, 1 = refused (with the reason), 2 = usage.
"""

import email.parser
from pathlib import Path
import posixpath
import struct
import sys
import tarfile
import zipfile

PACKAGE = "qkvm"
FIELDS = ("Name", "Version", "Requires-Python")


class Refused(ValueError):
    """The source archive is not what the tested wheel was made of."""


def declared(text, label):
    headers = email.parser.Parser().parsestr(text, headersonly=True)
    if headers.defects:
        raise Refused(f"{label} cannot be read")
    fields = {field: headers.get_all(field, []) for field in FIELDS}
    if any(len(values) != 1 for values in fields.values()):
        raise Refused(f"{label} does not name exactly one {', '.join(FIELDS)}")
    return {**fields, "Requires-Dist": sorted(headers.get_all("Requires-Dist", []))}


def plain(name, label):
    """A member's name as it is to be unpacked: no `..`, `.` or empty part, no backslash, no leading slash, nothing
    posixpath.normpath would change (pip makes qkvm/../evil.pth into site-packages/evil.pth)."""
    bare = name[:-1] if name.endswith("/") else name
    if (not bare or "\\" in bare or bare.startswith("/") or posixpath.normpath(bare) != bare
            or any(part in ("", ".", "..") for part in bare.split("/"))):
        raise Refused(f"{label} holds a member whose name is not plain: {name!r}")


UNICODE_PATH = 0x7075  # Info-ZIP's Unicode Path extra field


def unicode_paths(extra):
    """The names an entry's Unicode Path extra fields give (whatever this Python makes of them)."""
    names = []
    while len(extra) >= 4:
        kind, size = struct.unpack("<HH", extra[:4])
        data, extra = extra[4 : 4 + size], extra[4 + size :]
        if kind == UNICODE_PATH:
            if len(data) < 5 or data[0] != 1:
                raise Refused("a member has a Unicode Path field that cannot be read")
            try:
                names.append(data[5:].decode("utf-8"))
            except UnicodeDecodeError:
                raise Refused("a member has a Unicode Path field that is not UTF-8") from None
    return names


def wheel_contents(path):
    with zipfile.ZipFile(path) as archive:
        # The name as the archive holds it (orig_filename: on Windows zipfile turns a backslash into a slash), the name
        # as this Python reads it (filename: since 3.12 taken from a Unicode Path extra field whose checksum matches,
        # and pip installs by it), and any name such a field gives (seen here whatever Python reads the check): one
        # plain name, the same in all, or the wheel is refused.
        for info in archive.infolist():
            plain(info.orig_filename, str(path))
            if info.filename != info.orig_filename:
                raise Refused(f"{path} holds a member read as {info.filename!r} but stored as {info.orig_filename!r} (a Unicode Path field)")
            for said in unicode_paths(info.extra):
                if said != info.orig_filename:
                    raise Refused(f"{path} holds a member whose Unicode Path field names {said!r}, not {info.orig_filename!r}")
            plain(info.filename, str(path))
        names = [name for name in archive.namelist() if not name.endswith("/")]
        if len(names) != len(set(names)):
            raise Refused(f"{path} holds a file twice")
        code = {name: archive.read(name) for name in names if name.startswith(PACKAGE + "/")}
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise Refused(f"{path} has no single METADATA")
        return code, archive.read(metadata[0]).decode("utf-8"), names


def only_the_package(names, version):
    """A wheel holds its package and its own dist-info, and nothing else: a top-level .pth, say, would run at every
    start of the Python it is installed into."""
    dist_info = f"{PACKAGE}-{version}.dist-info/"
    stray = sorted(name for name in names if not (name.startswith(PACKAGE + "/") or name.startswith(dist_info)))
    if stray:
        raise Refused(f"the wheel holds files outside {PACKAGE}/ and {dist_info}: {stray}")
    if f"{dist_info}METADATA" not in names:
        raise Refused(f"the wheel's METADATA is not in {dist_info}")


def sdist_contents(path, version):
    with tarfile.open(path, "r:gz") as archive:
        for item in archive.getmembers():
            plain(item.name, str(path))
        members = [item for item in archive.getmembers() if not item.isdir()]
        roots = {item.name.split("/", 1)[0] for item in members}
        if roots != {f"{PACKAGE}-{version}"}:
            raise Refused(f"{path} is not one folder {PACKAGE}-{version}: {sorted(roots)}")
        code = {}
        metadata = None
        for item in members:
            name = item.name.split("/", 1)[1] if "/" in item.name else ""
            if not item.isfile():
                raise Refused(f"{path} holds {item.name}, which is not a plain file")
            data = archive.extractfile(item).read()
            if name.startswith(PACKAGE + "/"):
                if name in code:
                    raise Refused(f"{path} holds {name} twice")
                code[name] = data
            elif name == "PKG-INFO":
                metadata = data.decode("utf-8")
        if metadata is None:
            raise Refused(f"{path} has no PKG-INFO")
        return code, metadata


def check(wheel, sdist):
    wheel_code, wheel_metadata, wheel_names = wheel_contents(wheel)
    wheel_fields = declared(wheel_metadata, "the wheel's METADATA")
    only_the_package(wheel_names, wheel_fields["Version"][0])
    sdist_code, sdist_metadata = sdist_contents(sdist, wheel_fields["Version"][0])
    sdist_fields = declared(sdist_metadata, "the source archive's PKG-INFO")
    if wheel_fields != sdist_fields:
        differ = sorted(field for field in wheel_fields if wheel_fields[field] != sdist_fields[field])
        raise Refused(f"the source archive declares other {', '.join(differ)} than the wheel")
    if not wheel_code:
        raise Refused(f"the wheel holds no {PACKAGE}/")
    only_wheel = sorted(set(wheel_code) - set(sdist_code))
    only_sdist = sorted(set(sdist_code) - set(wheel_code))
    if only_wheel or only_sdist:
        raise Refused(f"not the same files: only in the wheel {only_wheel}, only in the source archive {only_sdist}")
    changed = sorted(name for name in wheel_code if wheel_code[name] != sdist_code[name])
    if changed:
        raise Refused(f"not the same contents: {changed}")
    return len(wheel_code)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        count = check(Path(argv[0]), Path(argv[1]))
    except (OSError, UnicodeError, zipfile.BadZipFile, tarfile.TarError, Refused) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(f"The source archive holds the {count} files of the tested wheel's {PACKAGE}/, and declares the same")
    return 0


if __name__ == "__main__":
    sys.exit(main())
