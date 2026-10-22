"""Assemble an immutable application runtime from installed, vendor-owned files.

Run only in the trusted build stage. Preserve original Debian package records,
file lists, copyright notices and Python distribution metadata for scanning.
Package installation scripts and their tool dependencies are build-time only.
"""

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


def main():
    destination = Path(sys.argv[1])
    if destination.exists() or not destination.is_absolute():
        raise SystemExit("Runtime destination must be a new absolute directory")
    destination.mkdir()
    for name in ("bin", "sbin", "lib", "lib64"):
        source = Path("/") / name
        if source.is_symlink():
            (destination / name).symlink_to(os.readlink(source))
    shutil.copytree("/usr/local", destination / "usr/local", symlinks=True)
    # Compilation headers/static objects are build tooling, not runtime imports.
    shutil.rmtree(destination / "usr/local/include", ignore_errors=True)
    for path in (destination / "usr/local/lib").glob("python*/config-*"):
        shutil.rmtree(path)
    for path in (destination / "usr/local/lib").glob("libpython*.a"):
        path.unlink()
    # These optional CPython extensions serve interactive terminal programs or
    # platform UUID1 generation, not qKVM. uuid.uuid4 still uses os.urandom.
    # Remove the extensions themselves, never leave an unloadable shared object.
    omitted = []
    for pattern in ("_curses*.so", "readline*.so", "_uuid*.so", "_tkinter*.so"):
        for path in (destination / "usr/local/lib").glob("python*/lib-dynload/" + pattern):
            omitted.append(str(path.relative_to(destination)))
            path.unlink()

    records = {}
    owners = {}
    lists = {}
    for block in Path("/var/lib/dpkg/status").read_text().strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Status") != "install ok installed":
            continue
        name = fields["Package"]
        records[name] = block
        prefix = Path("/var/lib/dpkg/info") / name
        if not Path(str(prefix) + ".list").exists():
            prefix = Path(str(prefix) + ":" + fields["Architecture"])
        listing = Path(str(prefix) + ".list")
        if not listing.exists():
            raise SystemExit("Missing package file list: " + name)
        lists[name] = (prefix, listing.read_text().splitlines())
        for item in lists[name][1]:
            path = Path(item)
            if path.is_file() and not path.is_symlink():
                owners.setdefault(str(path.resolve()), set()).add(name)

    selected = {"base-files", "ca-certificates", "tzdata", "netbase", "openssl", "openssl-provider-legacy", "gcc-14-base"}
    native = []
    for path in (destination / "usr/local").rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) == b"\x7fELF":
                native.append(path)
    # Resolve against the original trusted build installation, where bundled
    # wheel libraries and the loader's cache are still available.
    bundled = [str(p) for p in Path("/usr/local/lib").glob("python*/site-packages/*.libs")]
    link_environment = dict(os.environ, LD_LIBRARY_PATH=":".join(["/usr/local/lib", *bundled]))
    for path in native:
        source = Path("/") / path.relative_to(destination)
        result = subprocess.run(["ldd", str(source)], text=True, capture_output=True, check=False, env=link_environment)
        if "not found" in result.stdout or result.returncode:
            raise SystemExit("Unresolved native dependencies: " + str(source) + result.stdout + result.stderr)
        for library in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", result.stdout, re.MULTILINE):
            real = str(Path(library).resolve())
            if real.startswith("/usr/local/"):
                continue
            if real not in owners:
                raise SystemExit("Native library has no Debian provenance: " + real)
            selected.update(owners[real])

    def copy_file(source):
        target = destination / str(source).lstrip("/")
        if source.is_dir() and not source.is_symlink():
            target.mkdir(parents=True, exist_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            if not target.is_symlink():
                target.symlink_to(os.readlink(source))
        elif source.is_file():
            shutil.copy2(source, target)

    # Copy complete installed file lists of selected packages, not merely their
    # .so files. Original source/version fields stay intact for CVE attribution.
    for name in sorted(selected):
        prefix, paths = lists[name]
        for item in paths:
            copy_file(Path(item))
        for metadata in prefix.parent.glob(prefix.name + ".*"):
            copy_file(metadata)
    status = destination / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True, exist_ok=True)
    status.write_text("\n\n".join(records[name] for name in sorted(selected)) + "\n\n")
    # Generated trust links/bundle are not in the ca-certificates package list.
    shutil.copytree("/etc/ssl", destination / "etc/ssl", symlinks=True, dirs_exist_ok=True)
    for name in ("passwd", "group", "nsswitch.conf", "hosts", "host.conf", "resolv.conf", "localtime", "timezone", "fstab"):
        copy_file(Path("/etc") / name)
    for name in ("tmp", "data", "app", "proc", "dev", "sys", "run"):
        (destination / name).mkdir(exist_ok=True)
    (destination / "tmp").chmod(0o1777)
    os.chown(destination / "data", 10001, 10001)
    for path in destination.rglob("*"):
        if not path.is_symlink() and path.is_file():
            path.chmod(path.stat().st_mode & ~(stat.S_ISUID | stat.S_ISGID))
    manifest = {"packages": sorted(selected), "omitted_optional_extensions": sorted(omitted), "native_objects_checked": len(native)}
    (destination / "usr/local/runtime-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
