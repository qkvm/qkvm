"""The other machines of this computer's tailnet, for "Find KVMs" (0.4.0).

Tailscale is asked by its command where it is installed (`tailscale status --json`). Where it is not (qKVM in a
container beside Tailscale's own), by Tailscale's local API, over its socket on this computer (`/localapi/v0/status`):
never over a network, never on another computer, and only a socket that is one, and Tailscale's (root's, or this
account's) is spoken to. Tailscale on Windows keeps its local API behind a named pipe, which is not asked: its command is.
NetBird is asked by its command where it is installed (`netbird status --json`). Where it is not (qKVM in a container
beside NetBird's own), by NetBird's management API (`/api/peers`), with a token an admin gave: over HTTPS, by the wall's
outbound rules (egress.py), the token sealed by the vault, sent to the address it was entered for and to no other, and
never handed back, logged or exported.

What comes back is somebody else's text: read by its kind, up to a size and within a time, and a machine of it is asked
whether it is a KVM only at an address of the shared space Tailscale and NetBird give out (100.64.0.0/10), and nowhere
else. A machine found is a suggestion: nothing is added to the wall but what a person ticks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import egress
from .kvm import plain
from .netbind import NO_WINDOW
from .netbind import netbird_command as netbird_command  # (asked through here, so that a test stands in for it in one place)
from .netbind import tailscale_command as tailscale_command

SHARED = ipaddress.ip_network("100.64.0.0/10")  # the shared address space (RFC 6598), where Tailscale's addresses are
MOST_PEERS = 256  # machines of a tailnet asked at the most: a search is of a wall's KVMs, not of a company's laptops
# Where tailscaled keeps its local API on Linux (and where the Compose file of qKVM with Tailscale mounts it). On macOS
# its command is there; on Windows it is a named pipe, and its command is there too.
SOCKETS = ("/var/run/tailscale/tailscaled.sock", "/run/tailscale/tailscaled.sock")
LOCAL_API_HOST = "local-tailscaled.sock"  # the Host its local API wants: anything else is refused there (a web page's rebinding)
ASK_WITHIN = 5.0  # seconds the local API has to answer in full (as its command is given)
STATUS_MOST = 8 * 1024 * 1024  # bytes of its status read at the most: some two thousand machines of a tailnet
HEAD_MOST = 16 * 1024  # bytes of an answer's status line and headers together
SEALED_FOR = "netbird:token"  # what NetBird's token is sealed for by the vault (no record's id has a colon: nothing else opens as it)
API_MOST = 4 * 1024 * 1024  # bytes of the management API's list of peers read at the most
TOKEN_MOST = 400  # characters of a token (a personal access token of NetBird's is some forty)
_PIECE = 64 * 1024
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?")


class Unasked(Exception):
    """What lists the tailnet's machines is there, and could not be read: the message says why, in a sentence for an admin."""


def in_shared_space(said: Any) -> bool:
    """Whether this is an address of a tailnet, written as one: what is asked is asked there and nowhere else.

    (Not this computer itself, not a cloud's own address for its machines, not somewhere on the internet: whatever
    stands in a list of a machine's addresses, only an address Tailscale gives out is one of its machines.)
    """
    try:
        return isinstance(said, str) and str(ipaddress.IPv4Address(said)) == said and ipaddress.IPv4Address(said) in SHARED
    except ValueError:
        return False


# --- Tailscale's local API ----------------------------------------------------------------------------------------------


def local_api_socket() -> str | None:
    """Where Tailscale's local API is on this computer, if anything is at one of its places; None where nothing is (and
    always on Windows: see the module's description). Whether what is there may be spoken to is asked by ask_local_api."""
    if sys.platform == "win32":
        return None
    return next((path for path in SOCKETS if os.path.lexists(path)), None)


def _not_its_socket(where: str) -> str | None:
    """Why what is at `where` is not spoken to as Tailscale's local API; None where it may be. A link, a file that is no
    socket, and a socket of another account than root (tailscaled's) or this one are not: what another account put there
    would be taken for Tailscale's word on what this computer's name is and which certificate is its own."""
    if sys.platform == "win32":
        return "is not asked on Windows"  # (see the module's description)
    try:
        found = os.lstat(where)
    except OSError as ex:
        return f"cannot be looked at ({ex.strerror or type(ex).__name__})"
    if stat.S_ISLNK(found.st_mode):
        return "is a link"
    if not stat.S_ISSOCK(found.st_mode):
        return "is not a socket"
    if found.st_uid not in (0, os.getuid()):
        return "belongs to another account than root"
    return None


SAID_READ = 4096  # bytes of a refusal's words that are looked through for what the request carried, before they are cut


def _said(body: bytes, carried: Collection[str] = ()) -> str:
    """What the other end said with a refusal, as one short line, with what the request carried as a secret (`carried`: the
    token) taken out of it, whole or in part, before it is cut and after (egress.hidden). An error page of NetBird's that
    repeated its request was handed back with the token in it, to the browser of an admin who had left the token's box
    empty (the outside review of 0.4.0, L1)."""
    line = plain(egress.hidden(body[:SAID_READ].decode("utf-8", "replace"), carried), 120)
    return egress.hidden(line, carried) if line else "nothing more"


async def ask_local_api(where: str, path: str, most: int, within: float | None = None) -> tuple[int, bytes]:
    """GET `path` of Tailscale's local API over its socket at `where`: (status, body), `most` bytes of the body at the most.

    Unasked, with why, where the socket is not to be spoken to, cannot be reached, does not answer in full within `within`
    seconds (ASK_WITHIN), answers with something that is not HTTP, or sends more than `most`. Asked as HTTP/1.0, so that
    the answer comes whole and is ended by the connection's end, never in pieces of a length the other end says.
    """
    within = ASK_WITHIN if within is None else within
    if (why := _not_its_socket(where)) is not None:
        raise Unasked(f"Tailscale's local API was not asked: {where} {why}")
    not_http = Unasked("Tailscale's local API answered with something that is not HTTP")
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(within):
            reader, writer = await asyncio.open_unix_connection(where, limit=HEAD_MOST)  # type: ignore[attr-defined,unused-ignore]
            writer.write(f"GET {path} HTTP/1.0\r\nHost: {LOCAL_API_HOST}\r\nAccept-Encoding: identity\r\n\r\n".encode("ascii"))
            await writer.drain()
            head = (await reader.readuntil(b"\r\n\r\n"))[:-4].split(b"\r\n")
            first = _STATUS_LINE.fullmatch(head[0])
            if first is None:
                raise not_http
            headers: dict[bytes, bytes] = {}
            for line in head[1:]:
                name, colon, value = line.partition(b":")
                if not colon:
                    raise not_http
                headers[name.strip().lower()] = value.strip()
            if headers.get(b"transfer-encoding", b"identity").lower() != b"identity":
                raise not_http  # (never to an HTTP/1.0 request: see above)
            length: int | None = None
            if b"content-length" in headers:
                said = headers[b"content-length"].lstrip(b"0") or b"0"
                if not said.isdigit():
                    raise not_http
                # (Counted by its digits first: Python reads no whole number of more than 4300 of them, and says so by a
                # ValueError of its own. More digits than `most` has is more than `most`.)
                length = int(said) if len(said) <= len(str(most)) else most + 1
                if length > most:
                    raise Unasked(f"Tailscale's local API sent more than this program reads of it ({most // 1024} KB)")
            body = bytearray()
            while len(body) <= most and (piece := await reader.read(min(_PIECE, most + 1 - len(body)))):
                body += piece
            if len(body) > most:
                raise Unasked(f"Tailscale's local API sent more than this program reads of it ({most // 1024} KB)")
            if length is not None:
                if len(body) < length:
                    raise Unasked("Tailscale's local API ended its answer before its end")
                del body[length:]
            return int(first.group(1)), bytes(body)
    except TimeoutError:
        raise Unasked(f"Tailscale's local API did not answer within {within:g} seconds") from None
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
        raise not_http from None
    except OSError as ex:
        raise Unasked(f"Tailscale's local API could not be reached at {where} ({ex.strerror or type(ex).__name__})") from None
    finally:
        if writer is not None:
            writer.transport.abort()  # (nothing more is read or sent: nothing is owed to the other end)


def read_json(body: bytes | str, whose: str) -> Any:
    """What `whose` answered, read as JSON. Unasked where it cannot be read as that (nested too deep among it)."""
    try:
        return json.loads(body)
    except RecursionError:
        raise Unasked(f"{whose} answered with JSON nested too deep to read") from None
    except ValueError:
        raise Unasked(f"{whose} answered with something that is not JSON") from None


# --- Tailscale --------------------------------------------------------------------------------------------------------


def _status_by_command(command: str) -> Any:
    """What `tailscale status --json` (or `netbird status --json`) prints, read as JSON; None where it could not be run or read."""
    try:
        # Read as what it is written in (UTF-8), whatever this system reads a program's text as. Read as
        # Windows does by default, one name in the tailnet that its code page has no letter for (a machine's,
        # or a person's: an accent is enough) left nothing read at all, and the search was an error.
        out = subprocess.run(
            [command, "status", "--json"], capture_output=True, encoding="utf-8", errors="replace", timeout=ASK_WITHIN, check=True, creationflags=NO_WINDOW
        )
        return json.loads(out.stdout)
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
        return None


async def tailscale_status() -> Any:
    """What Tailscale says of this computer and its tailnet: by its command where it is installed, else by its local API.

    None where neither is here (no Tailscale), or its command could not be run or read. Unasked, with why, where its
    local API is here and could not be read, or said no (in a container, that is what an admin needs to be told).
    """
    command = tailscale_command()
    if command is not None:
        return await asyncio.to_thread(_status_by_command, command)
    where = local_api_socket()
    if where is None:
        return None
    status, body = await ask_local_api(where, "/localapi/v0/status", STATUS_MOST)
    if status != 200:
        raise Unasked(f"Tailscale's local API did not say who is in the tailnet ({status}: {_said(body)})")
    return await asyncio.to_thread(read_json, body, "Tailscale's local API")


def tailscale_peers_of(status: Any) -> list[tuple[str, str]]:
    """(address, machine name) of the other machines of the tailnet that Tailscale's status says are online."""
    peers = status.get("Peer") if isinstance(status, dict) else None
    hosts = []
    for peer in peers.values() if isinstance(peers, dict) else []:
        listed = peer.get("TailscaleIPs") if isinstance(peer, dict) else None
        addresses = [said for said in listed if in_shared_space(said)] if isinstance(listed, list) else []
        if addresses and peer.get("Online") is True:
            # (Its name is what that machine calls itself: somebody else's text, like a device's.)
            hosts.append((addresses[0], plain(peer.get("HostName"), 60) or ""))
    return hosts[:MOST_PEERS]


async def tailscale_peers() -> list[tuple[str, str]]:
    """(address, machine name) of the other machines of this computer's tailnet that are online; Unasked as tailscale_status."""
    return tailscale_peers_of(await tailscale_status())


# --- NetBird ----------------------------------------------------------------------------------------------------------


def _first_part(fqdn: Any) -> str:
    """A machine's name, as the first part of the name NetBird gives it (rack-kvm of rack-kvm.netbird.cloud): one short line."""
    whole = (plain(fqdn, 255) if isinstance(fqdn, str) else None) or ""  # (a number there is no name)
    return plain(whole.split(".", 1)[0], 60) or ""


def netbird_peers_of(overview: Any) -> list[tuple[str, str]]:
    """(address, machine name) of the other machines of the NetBird network that its client's overview lists.

    Whatever their state: a peer NetBird shows as idle is one its client connects to with the first packet sent to it (its
    lazy connections), and one that is not there does not answer, which costs a search the few seconds every address has.
    """
    peers = overview.get("peers") if isinstance(overview, dict) else None
    details = peers.get("details") if isinstance(peers, dict) else None
    hosts = []
    for peer in details if isinstance(details, list) else []:
        said = peer.get("netbirdIp") if isinstance(peer, dict) else None
        address = said.split("/", 1)[0] if isinstance(said, str) else None  # (its own is written with its network: "/16")
        if isinstance(peer, dict) and in_shared_space(address):
            hosts.append((str(address), _first_part(peer.get("fqdn"))))
    return hosts[:MOST_PEERS]


async def netbird_peers(api: NetbirdApi | None = None) -> list[tuple[str, str]]:
    """(address, machine name) of the other machines of this computer's NetBird network: from its client where it is
    installed, else from its management API where an admin set that up (`api`). Unasked as netbird_by_api."""
    command = netbird_command()
    if command is not None:
        return netbird_peers_of(await asyncio.to_thread(_status_by_command, command))
    return [] if api is None else await netbird_by_api(api)


@dataclass(frozen=True)
class NetbirdApi:
    """NetBird's management API, as the wall asks it: its address (management_url), the token (opened from the vault for this
    one search or check), whether it may be at a private address, and the wall itself, which nothing is sent to."""

    url: str
    token: str = field(repr=False)  # (in no log line, error text or debugger's view of it)
    private: bool = False
    own: Collection[str] = ()
    own_ports: Collection[int] = ()


def management_url(text: str) -> str:
    """The address of a NetBird management API as it is kept: https://, its host, a port and a path before /api, nothing
    more. ValueError with a sentence fit for showing otherwise. (Where it leads is judged each time it is asked.)"""
    wanted = "Enter the address of NetBird's management API, starting with https:// (https://api.netbird.io for NetBird's own)"
    try:
        parts = urlsplit(egress.check_url(text, https_only=True))
    except ValueError as ex:
        raise ValueError(wanted if str(ex).startswith("Enter a web address") else str(ex)) from None
    if parts.username is not None or parts.password is not None or parts.query or not parts.hostname:
        raise ValueError(f"{wanted}, without a name, a password or a query in it: the token goes in its own box")
    return urlunsplit(("https", parts.netloc, parts.path.rstrip("/").removesuffix("/api").rstrip("/"), "", ""))


def management_token(text: str) -> str:
    """A token of NetBird's as it is kept: one word of plain signs. ValueError with a sentence fit for showing otherwise."""
    token = text.strip()
    if not token or len(token) > TOKEN_MOST or not all(33 <= ord(ch) < 127 for ch in token):
        raise ValueError("A NetBird token is one word of letters, digits and signs (a personal access token begins with nbp_)")
    return token


def netbird_peers_listed(listed: Any) -> list[tuple[str, str]]:
    """(address, machine name) of the machines the management API's list says are connected."""
    hosts = []
    for peer in listed if isinstance(listed, list) else []:
        if isinstance(peer, dict) and peer.get("connected") is True and in_shared_space(peer.get("ip")):
            name = peer.get("name")
            hosts.append((str(peer["ip"]), _first_part(peer.get("dns_label")) or (plain(name, 60) if isinstance(name, str) else None) or ""))
    return hosts[:MOST_PEERS]


async def netbird_by_api(api: NetbirdApi) -> list[tuple[str, str]]:
    """(address, machine name) of the connected machines of the NetBird network, from its management API. Unasked, with
    why, where the API is not to be asked there, cannot be reached, does not take the token, or answers no list."""
    try:
        reply = await egress.request(
            "GET", f"{api.url}/api/peers", None, {"Authorization": f"Token {api.token}", "Accept": "application/json"},
            private_ok=api.private, own=api.own, own_ports=api.own_ports, most=API_MOST + 1, https_only=True,
        )  # fmt: skip
    except egress.Refused as ex:
        raise Unasked(f"NetBird's management API is not asked there: {ex}") from None
    except egress.NotReached as ex:
        raise Unasked(f"NetBird's management API could not be asked: {ex}") from None
    if reply.status in (401, 403):
        raise Unasked(f"NetBird's management API did not take the token ({reply.status}): make a new one, and enter it under Settings > Network")
    if reply.status != 200:
        raise Unasked(f"NetBird's management API answered {reply.status} ({_said(reply.body, [api.token])})")
    if len(reply.body) > API_MOST:
        raise Unasked(f"NetBird's management API sent more than this program reads of it ({API_MOST // 1024} KB)")
    return netbird_peers_listed(await asyncio.to_thread(read_json, reply.body, "NetBird's management API"))
