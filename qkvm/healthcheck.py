"""Exit 0 if QKVM answers on this machine: python -m qkvm.healthcheck [port].

For a container's HEALTHCHECK or a watchdog. Works whether HTTPS is switched on or not.
"""

from __future__ import annotations

import ssl
import sys
import urllib.error
import urllib.request


def healthy(port: int) -> bool:
    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE  # our own self-signed certificate, asked over loopback
    for scheme in ("http", "https"):
        try:
            with urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/healthz", timeout=3, context=unverified) as reply:
                if reply.status == 200:
                    return True
        except (OSError, urllib.error.URLError, ValueError):
            continue
    return False


if __name__ == "__main__":
    sys.exit(0 if healthy(int(sys.argv[1]) if len(sys.argv) > 1 else 8787) else 1)
