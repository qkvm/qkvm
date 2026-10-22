"""Run inside each built image: check the conditions supporting its narrowly scoped exceptions."""

import importlib.util
import os
import pwd
import stat
from pathlib import Path

from qkvm.video import RGBFrame, decode_jpeg, encode_jpeg, shutdown

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
for module in ("_ctypes", "_ssl", "_uuid", "_curses", "_sqlite3", "_bz2", "_lzma", "aiortc", "av", "cryptography"):
    __import__(module)
print("Nonroot identity, absence of setuid/setgid files, and container exception preconditions verified")

# Nested seccomp must work under the ordinary nonroot container policy on each CPU.

picture = encode_jpeg(RGBFrame(17, 33, bytes([31, 64, 127]) * 17 * 33), None, 2)
if len(decode_jpeg(picture, 17, 33)) != 17 * 33 * 3:
    raise SystemExit("Isolated video processing failed in the runtime image")
shutdown()
print("Native video sandbox and bounded JPEG roundtrip verified")
