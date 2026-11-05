"""Wheels of libraries made by the tests, with no download and no compiler: a small pure-Python one of the tests' own, and
a native one repacked from what the test environment has installed (google-crc32c, its native module and, on Linux, the
shared library beside it), under a version of the test's choosing."""

from __future__ import annotations

import importlib.metadata
import io
import re
import zipfile
from pathlib import Path

from packaging.tags import sys_tags

PURE = "qkvm-proof-pure"  # a library of the tests' own
NATIVE = "google-crc32c"  # installed with aiortc; its native module is small


def escaped(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name)


def wheel(name: str, version: str, files: dict[str, bytes], tag: str = "py3-none-any", *, metadata: str | None = None) -> tuple[str, bytes]:
    """(its file name, its bytes): a wheel of `name` at `version` holding `files` and its own dist-info."""
    info = f"{escaped(name)}-{version}.dist-info"
    every = {
        **files,
        f"{info}/METADATA": (metadata if metadata is not None else f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nRequires-Python: >=3.11\n").encode(),
        f"{info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: qkvm-tests\nRoot-Is-Purelib: {'true' if tag.endswith('any') else 'false'}\nTag: {tag}\n".encode(),
    }
    every[f"{info}/RECORD"] = "".join(f"{path},,\n" for path in [*every, f"{info}/RECORD"]).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in every.items():
            info = zipfile.ZipInfo(path)
            info.filename = path  # (as given: ZipInfo turns a backslash into a slash on Windows)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return f"{escaped(name)}-{version}-{tag}.whl", buffer.getvalue()


def pure(version: str = "2.0", name: str = PURE) -> tuple[str, bytes]:
    module = escaped(name)
    return wheel(name, version, {f"{module}/__init__.py": f'VERSION = "{version}"\n'.encode()})


def native(version: str = "1.9.0.post1") -> tuple[str, bytes]:
    """The installed google-crc32c, file for file (its native module, and the .libs folder beside it where there is one),
    repacked as `version` with the tag this Python takes first among those its own wheel was built for."""
    distribution = importlib.metadata.distribution(NATIVE)
    files: dict[str, bytes] = {}
    tags = []
    for path in distribution.files or []:
        parts = Path(str(path)).parts
        if not parts or parts[0] == ".." or "__pycache__" in parts:
            continue
        if parts[0].endswith(".dist-info"):
            if parts[-1] == "WHEEL":
                tags = [line.split(":", 1)[1].strip() for line in Path(str(distribution.locate_file(path))).read_text(encoding="utf-8").splitlines() if line.startswith("Tag:")]
            continue
        files["/".join(parts)] = Path(str(distribution.locate_file(path))).read_bytes()
    ours = {str(tag) for tag in sys_tags()}
    tag = next(each for each in tags if each in ours)
    return wheel(NATIVE, version, files, tag)


def loader() -> dict[str, bytes]:
    """What a release's package that brings libraries has to put them in place (and judge them by): this tree's own files."""
    import qkvm

    package = Path(qkvm.__file__).parent
    return {f"qkvm/{name}": (package / name).read_bytes() for name in ("_libs.py", "__main__.py", "_folders.py")}
