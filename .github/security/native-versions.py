"""Run inside each built image: what the native code is that the vulnerability scanner cannot see.

The scanner reads Debian package records and Python package metadata. FFmpeg and its codecs come inside PyAV's wheel,
libsrtp and an OpenSSL inside pylibsrtp's, another OpenSSL inside cryptography's, and CPython is built from source by
the base image: none of them is a package the scanner matches against its advisories. Each is asked here by its own
version function, as it is loaded in the image, and what it says is printed as JSON, word for word: reading a version
out of it is check-native-versions.py's work, which fails closed on anything it cannot read.

    docker run ... --entrypoint python IMAGE -P -s - < native-versions.py > native-versions.json
"""

import ctypes
import importlib.metadata
import json
from pathlib import Path
import platform
import ssl
import sys

# Each component as check-native-versions.py and native-minimums.json name it.
COMPONENTS = (
    "cpython", "ffmpeg", "libvpx", "libopus", "libdav1d",
    "cryptography-openssl", "pylibsrtp-libsrtp", "pylibsrtp-openssl",
)
ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64"}


def one(folder, pattern):
    """The one library a wheel bundles under that name (auditwheel gives it a hash: libvpx-edb6de90.so.12.0.0)."""
    found = sorted(folder.glob(pattern))
    if len(found) != 1:
        raise SystemExit(f"Expected one {pattern} in {folder}, found {[path.name for path in found]}")
    return found[0]


def ask(library, function, *arguments):
    """What a library's own version function returns (a C string), from the copy the process has loaded."""
    call = getattr(ctypes.CDLL(str(library)), function)
    call.restype = ctypes.c_char_p
    call.argtypes = [type(argument) for argument in arguments]
    said = call(*arguments)
    if not said:
        raise SystemExit(f"{library.name} {function}() said nothing")
    return said.decode("ascii", "replace")


def collect():
    import av
    from cryptography.hazmat.backends.openssl import backend
    import pylibsrtp._binding

    bundled = Path(av.__file__).resolve().parent.parent / "av.libs"
    srtp = Path(pylibsrtp._binding.__file__).resolve()
    raw = {
        "cpython": platform.python_version(),
        "ffmpeg": str(av.ffmpeg_version_info),
        "libvpx": ask(one(bundled, "libvpx-*.so*"), "vpx_codec_version_str"),
        "libopus": ask(one(bundled, "libopus-*.so*"), "opus_get_version_string"),
        "libdav1d": ask(one(bundled, "libdav1d-*.so*"), "dav1d_version"),
        "cryptography-openssl": backend.openssl_version_text(),
        # libsrtp and its OpenSSL are linked into the extension itself; their functions are its own.
        "pylibsrtp-libsrtp": ask(srtp, "srtp_get_version_string"),
        "pylibsrtp-openssl": ask(srtp, "OpenSSL_version", ctypes.c_int(0)),
    }
    if tuple(raw) != COMPONENTS:
        raise SystemExit("The components asked for are not the ones named in COMPONENTS")
    site = bundled.parent
    context = {
        "python": sys.version,
        # Python's own ssl module uses Debian's libssl, a package the scanner does see.
        "python-ssl": ssl.OPENSSL_VERSION,
        "distributions": {name: importlib.metadata.version(name) for name in ("aiortc", "av", "cryptography", "pylibsrtp")},
        "libav": {name: ".".join(map(str, version)) for name, version in av.library_versions.items()},
        "bundled-files": {folder.name: sorted(path.name for path in folder.iterdir()) for folder in sorted(site.glob("*.libs"))},
    }
    return {"schema": 1, "arch": ARCHITECTURES.get(platform.machine(), platform.machine()), "raw": raw, "context": context}


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2, sort_keys=True))
