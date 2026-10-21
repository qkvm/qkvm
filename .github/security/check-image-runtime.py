"""Run inside each built image: check the conditions supporting its narrowly scoped exceptions."""

import importlib.util
import os
import stat
from pathlib import Path

if os.getuid() != 10001:
    raise SystemExit("The image must run as qkvm UID 10001")
if any(line.strip() and not line.lstrip().startswith("#") for line in Path("/etc/fstab").read_text().splitlines()):
    raise SystemExit("Mount-related exceptions require an unconfigured fstab")
for module in ("pip", "setuptools"):
    if importlib.util.find_spec(module) is not None:
        raise SystemExit(f"Installer tooling must not remain in the runtime: {module}")
# Source-package CVEs do not apply when the affected executable/module is absent.
for pattern in ("**/systemd-homed", "**/systemd-homework", "**/Archive/Tar.pm", "**/setfacl"):
    for root in (Path("/usr"), Path("/bin"), Path("/sbin")):
        if next(root.glob(pattern), None) is not None:
            raise SystemExit(f"Exception precondition changed: found {pattern}")
# No qKVM feature needs an executable that changes identity using filesystem privilege bits.
for path in Path("/usr").rglob("*"):
    if path.is_file() and path.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise SystemExit(f"Privileged executable must not remain in the runtime: {path}")
print("Nonroot identity, absence of setuid/setgid files, and container exception preconditions verified")
