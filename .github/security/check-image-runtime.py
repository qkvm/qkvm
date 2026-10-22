"""Run inside each built image: check the conditions supporting its narrowly scoped exceptions."""

import importlib.util
import os
import pwd
import stat
import json
import ssl
import uuid
from zoneinfo import ZoneInfo
from pathlib import Path

from qkvm.video import RGBFrame, decode_jpeg, encode_jpeg, shutdown

if os.environ.get("QKVM_CONTAINER") != "1":
    raise SystemExit("Image must retain container update restrictions")
if os.getuid() != 10001:
    raise SystemExit("The image must run as qkvm UID 10001")
if any(line.strip() and not line.lstrip().startswith("#") for line in Path("/etc/fstab").read_text().splitlines()):
    raise SystemExit("Mount-related exceptions require an unconfigured fstab")
if pwd.getpwuid(os.getuid()).pw_name != "qkvm":
    raise SystemExit("The qkvm account must survive removal of account-management tools")
for module in ("pip", "setuptools"):
    if importlib.util.find_spec(module) is not None:
        raise SystemExit(f"Installer tooling must not remain in the runtime: {module}")
# Source-package CVEs do not apply when the affected executable/module is absent.
for pattern in ("**/systemd-homed", "**/systemd-homework", "**/Archive/Tar.pm", "**/setfacl", "**/mount", "**/umount", "**/nsenter", "**/infocmp", "**/perl", "**/libmount.so*", "**/apt", "**/apt-get", "**/apt-key", "**/useradd", "**/passwd", "**/libpam.so*", "**/libudev.so*", "**/nscd", "**/systemd-oomd", "**/bzip2recover", "**/getfattr", "**/setfattr"):
    for root in (Path("/usr"), Path("/bin"), Path("/sbin")):
        if next(root.glob(pattern), None) is not None:
            raise SystemExit(f"Exception precondition changed: found {pattern}")
# No qKVM feature needs an executable that changes identity using filesystem privilege bits.
for path in Path("/usr").rglob("*"):
    if path.is_file() and path.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise SystemExit(f"Privileged executable must not remain in the runtime: {path}")
# Package trimming must preserve Python's native extensions and the video/TLS stack.
for module in ("_ctypes", "_ssl", "_sqlite3", "_bz2", "_lzma", "aiortc", "av", "cryptography"):
    __import__(module)
print("Nonroot identity, absence of setuid/setgid files, and container exception preconditions verified")

# Nested seccomp must work under the ordinary nonroot container policy on each CPU.

picture = encode_jpeg(RGBFrame(17, 33, bytes([31, 64, 127]) * 17 * 33), None, 2)
if len(decode_jpeg(picture, 17, 33)) != 17 * 33 * 3:
    raise SystemExit("Isolated video processing failed in the runtime image")
shutdown()
print("Native video sandbox and bounded JPEG roundtrip verified")

# Application-only packaging must preserve the runtime features we actually use.
if not ssl.create_default_context().get_ca_certs():
    raise SystemExit("System TLS trust store is empty")
if uuid.uuid4().version != 4 or ZoneInfo("America/New_York") is None:
    raise SystemExit("UUID/timezone support failed")
manifest = json.loads(Path("/usr/local/runtime-manifest.json").read_text())
for name in ("libacl1", "libsystemd0", "libuuid1", "libncursesw6", "libtinfo6", "ncurses-base", "bash", "dash", "coreutils", "dpkg", "tar"):
    if name in manifest["packages"]:
        raise SystemExit("Unexpected runtime package: " + name)
for name in ("sh", "bash", "dash", "dpkg", "tar", "mount", "nsenter"):
    for directory in ("/bin", "/usr/bin", "/sbin", "/usr/sbin"):
        if (Path(directory) / name).exists():
            raise SystemExit("Unexpected maintenance executable: " + name)
print("Application UUIDs, system TLS trust, timezone data and minimal package inventory verified")

for name in ("_curses", "_curses_panel", "readline", "_uuid", "_tkinter"):
    if importlib.util.find_spec(name) is not None:
        raise SystemExit("Unexpected optional native extension: " + name)
status_packages = {line.removeprefix("Package: ") for line in Path("/var/lib/dpkg/status").read_text().splitlines() if line.startswith("Package: ")}
if status_packages != set(manifest["packages"]):
    raise SystemExit("Runtime manifest and vendor package inventory differ")
