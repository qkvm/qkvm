"""Where else a machine can be opened: "Open in" on its tile's menu, for MeshCentral, RustDesk and Remote Desktop.

An admin gives a machine any of the three; its operators (and admins) see them in the tile's menu. They are plain links:
no secret is stored or sent for them, and the wall fetches nothing from them, nor checks that anything answers there.

* MeshCentral: the address of the machine's page on a MeshCentral server, HTTPS only. No user name or password in it, and
  none of the parameters a login token or a password goes in (MeshCentral takes `login=` for a token that signs in).
* RustDesk: the machine's RustDesk ID, opened as rustdesk://connection/new/<ID>, the link the RustDesk app takes. Never its
  password.
* Remote Desktop: the machine's host name or address (and a port, where it is not 3389). The page hands out a small .rdp
  file that holds this and nothing else: Windows' Remote Desktop asks for the password itself.

Each is checked strictly where it is set (`checked`), and again wherever it is read (`kept`: the settings file, an import
written by hand), so that nothing else can reach a page as a link, or an .rdp file as a line of its own: what is not one is
left out where it is read, and refused where it is set. Each a line of printable ASCII, its characters by kind, of a length.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MESHCENTRAL, RUSTDESK, RDP = "meshcentral", "rustdesk", "rdp"
KINDS = (MESHCENTRAL, RUSTDESK, RDP)
CALLED = {MESHCENTRAL: "MeshCentral", RUSTDESK: "RustDesk", RDP: "Remote Desktop"}
MOST = {MESHCENTRAL: 512, RUSTDESK: 32, RDP: 260}  # characters, at the most
# Parameters of a MeshCentral address that sign in (its login token) or carry what signs in: never taken into a link that
# every operator of the machine is handed.
_SIGNING_IN = frozenset({"login", "token", "key", "auth", "pass", "password", "passwd", "pwd", "user", "username", "secret", "session"})
_PRINTABLE = re.compile(r"[!-~]+")  # printable ASCII, no blank
_RUSTDESK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{5,31}")
_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
_PORT = re.compile(r"[0-9]{1,5}")


def checked(kind: str, said: Any) -> str:
    """`said` as it is kept for a link of `kind`; "" for none. ValueError, in words for the person who typed it, for what is
    not one."""
    if kind not in KINDS:
        raise ValueError("that is no kind of link this version knows")
    if not isinstance(said, str):
        raise ValueError(f"the {CALLED[kind]} link is not a text")
    text = said.strip()
    if kind == RUSTDESK:
        text = "".join(text.split())  # (an ID as the RustDesk app shows it: 123 456 789)
    if not text:
        return ""
    if len(text) > MOST[kind]:
        raise ValueError(f"the {CALLED[kind]} link may have {MOST[kind]} characters at the most")
    if not _PRINTABLE.fullmatch(text):
        raise ValueError(f"the {CALLED[kind]} link may have letters, digits and punctuation only, on one line")
    if kind == MESHCENTRAL:
        return _meshcentral(text)
    if kind == RUSTDESK:
        if not _RUSTDESK_ID.fullmatch(text):
            raise ValueError("a RustDesk ID has 6 to 32 letters, digits, hyphens and underscores (the ID the RustDesk app shows), and no password")
        return text
    return _rdp(text)


def _meshcentral(text: str) -> str:
    parts = urlsplit(text)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError("the MeshCentral link must be the https:// address of the machine's page on your MeshCentral")
    if "@" in parts.netloc:
        raise ValueError("the MeshCentral link must not have a user name or password in it")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("the MeshCentral link's port is not one") from None
    if any(name.lower() in _SIGNING_IN for name, _ in parse_qsl(parts.query, keep_blank_values=True)):
        raise ValueError("the MeshCentral link must not carry a login token or a password: the wall keeps no secret for it")
    host = _host(parts.hostname)
    if host is None or port == 0:
        raise ValueError("the MeshCentral link's host is not a host name or an address")
    netloc = host if port is None or port == 443 else f"{host}:{port}"
    return urlunsplit(("https", netloc, parts.path, parts.query, parts.fragment))


def _rdp(text: str) -> str:
    host, port = text, None
    if text.startswith("["):  # [an IPv6 address], or [one]:port
        end = text.find("]")
        host, rest = text[: end + 1], text[end + 1 :]
        if end < 0 or (rest and not (rest.startswith(":") and _PORT.fullmatch(rest[1:]))):
            raise ValueError("the Remote Desktop host is not a host name or an address")
        port = rest[1:] or None
    elif text.count(":") == 1:
        host, port = text.split(":")
        if not _PORT.fullmatch(port):
            raise ValueError("the Remote Desktop port is not a number")
    found = _host(host.strip("[]") if host.startswith("[") else host)
    if found is None:
        raise ValueError("the Remote Desktop host is not a host name or an address, with a port if it is not 3389")
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("the Remote Desktop port is a number from 1 to 65535")
    return found if port is None or int(port) == 3389 else f"{found}:{int(port)}"


def _host(name: str) -> str | None:
    """A host name (labels of letters, digits, hyphens and the underscore a home network's names have), or an address, in
    small letters; an IPv6 address in brackets. None for anything else, an IPv6 address with a zone id among it: Python's
    address takes one of any punctuation after "%" ("fe80::1%x;y=z"), which the API and an export would hand on to every
    client as a host (review of wave 3, L2). A zone names an interface of the computer that reads it, and is no link."""
    if "%" in name:
        return None
    name = name.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        address = None
    if address is not None:
        return f"[{address}]" if address.version == 6 else str(address)
    if not name or len(name) > 253 or not all(_LABEL.fullmatch(label) for label in name.split(".")):
        return None
    if name.rsplit(".", 1)[-1].isdigit():
        return None  # (numbers that are no address as written: 127.1, 010.0.0.1)
    return name


def kept(said: Any) -> dict[str, str]:
    """A machine's links as they may be shown and carried: of what is read (a record, a file), each that is one, in the
    order of KINDS; what is not is left out."""
    if not isinstance(said, dict):
        return {}
    found = {}
    for kind in KINDS:
        try:
            link = checked(kind, said.get(kind, ""))
        except ValueError:
            continue
        if link:
            found[kind] = link
    return found
