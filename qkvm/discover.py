"""Find KVMs on the networks this computer is on, for the Add KVM dialog.

Only the computer's own private networks and its Tailscale peers are looked at, never an
address range somebody typed in: this must not turn into a tool for scanning other people.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import subprocess
from dataclasses import dataclass
from typing import Any

import httpx

from . import amt
from .kvm import MAX_PROBE, KvmError, bounded, certificate_mark, fetch_certificate, listens, other_way, plain, read_json
from .netbind import NO_WINDOW, lan_ip, tailscale_command
from .rfb import greeting
from .vncdevice import vnc_url

AT_ONCE = 64  # addresses asked at the same time
ANSWER_WITHIN = 4.0  # seconds an address has to answer in full; a search must not hang on one that dawdles
AMT_PORTS = amt.PORTS  # where a PC with Intel AMT would answer on an address: (scheme, port), the preferred way first
VNC_PORTS = (5900, 5901)  # where a VNC server listens as a rule: the first display, and the second
TAILNET = ipaddress.ip_network("100.64.0.0/10")  # Tailscale addresses: only peers are asked, not the whole range


@dataclass(frozen=True)
class Target:
    """One address to ask, and where each make of KVM would answer on it."""

    host: str
    kvmd: str  # GLKVM / PiKVM serve HTTPS
    jetkvm: str  # a JetKVM serves plain HTTP, and HTTPS beside it once its owner turns that on (asked for too)
    name: str = ""  # what the network calls this machine, where that is known


def _own_addresses() -> list[ipaddress.IPv4Address]:
    """This computer's address on its main network (the one its internet traffic leaves by).

    Other interfaces are left alone on purpose: they are often a VPN into somebody else's
    network, or a virtual switch with nothing but this computer's own virtual machines on it.
    """
    try:
        address = ipaddress.IPv4Address(str(lan_ip()))
    except ValueError:
        return []
    usable = address.is_private and not address.is_loopback and not address.is_link_local
    return [address] if usable else []


def _tailscale_peers() -> list[tuple[str, str]]:
    """(address, machine name) of the other machines on this computer's tailnet that are online."""
    command = tailscale_command()
    if command is None:
        return []
    try:
        # Read as what it is written in (UTF-8), whatever this system reads a program's text as. Read as
        # Windows does by default, one name in the tailnet that its code page has no letter for (a machine's,
        # or a person's: an accent is enough) left nothing read at all, and the search was an error.
        out = subprocess.run(
            [command, "status", "--json"], capture_output=True, encoding="utf-8", errors="replace", timeout=5, check=True, creationflags=NO_WINDOW
        )
        peers = json.loads(out.stdout).get("Peer") or {}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError, RecursionError):
        return []
    hosts = []
    for peer in peers.values() if isinstance(peers, dict) else []:
        listed = peer.get("TailscaleIPs") if isinstance(peer, dict) else None
        addresses = [said for said in listed if _an_address(said)] if isinstance(listed, list) else []
        if addresses and peer.get("Online"):
            # (Its name is what that machine calls itself: somebody else's text, like a device's.)
            hosts.append((addresses[0], plain(peer.get("HostName"), 60) or ""))
    return hosts[:256]


def _an_address(said: Any) -> bool:
    """Whether this is an address of a tailnet, written as one: what is asked is asked there and nowhere else.

    (Not this computer itself, not a cloud's own address for its machines, not somewhere on the internet:
    whatever stands in that list, only an address Tailscale gives out is one of its machines.)
    """
    try:
        return isinstance(said, str) and str(ipaddress.IPv4Address(said)) == said and ipaddress.IPv4Address(said) in TAILNET
    except ValueError:
        return False


def targets() -> tuple[list[Target], list[str]]:
    """Every address worth asking, and the names of the networks they come from."""
    hosts: list[str] = []
    names: dict[str, str] = {}
    networks: list[str] = []
    for address in _own_addresses():
        if address in TAILNET:
            continue
        network = ipaddress.ip_network(f"{address}/24", strict=False)  # at most 254 addresses
        networks.append(str(network))
        hosts += [str(host) for host in network.hosts() if host != address]
    peers = _tailscale_peers()
    if peers:
        networks.append("Tailscale")
        names = dict(peers)
        hosts += [peer for peer in names if peer not in hosts]
    return [Target(host, f"https://{host}", f"http://{host}", names.get(host, "")) for host in hosts], networks


async def _what_is(client: httpx.AsyncClient, target: Target) -> dict[str, Any] | None:
    """Ask one address whether it is a KVM this program can talk to. No login is attempted."""

    async def kvmd() -> dict[str, Any] | None:
        try:
            ask = client.build_request("GET", f"{target.kvmd}/api/auth/check")
            reply = await bounded(client, ask, MAX_PROBE, ANSWER_WITHIN)
            body = read_json(reply) if reply.status_code in (200, 401, 403) else None
        except (httpx.HTTPError, ValueError, KvmError):
            return None
        # kvmd answers in its own shape, logged in or not: {"ok": ..., "result": {...}}.
        if isinstance(body, dict) and "ok" in body and isinstance(body.get("result"), dict):
            try:
                mark = certificate_mark(await fetch_certificate(target.kvmd))  # its own, whichever address it was asked at
            except (KvmError, ValueError):
                mark = None
            return {"address": target.host, "kind": "kvmd", "url": target.kvmd, "name": target.name, "mark": mark}
        return None

    async def jetkvm() -> dict[str, Any] | None:
        async def says_so(address: str | None) -> bool:
            if address is None:
                return False
            try:
                ask = client.build_request("GET", f"{address}/device/status")
                reply = await bounded(client, ask, MAX_PROBE, ANSWER_WITHIN)
                body = read_json(reply) if reply.status_code == 200 else None
            except (httpx.HTTPError, ValueError, KvmError):
                return False
            return isinstance(body, dict) and "isSetup" in body

        # Asked both ways at once. With its HTTPS mode on it answers both, and HTTPS is then its address.
        secure = other_way(target.jetkvm) if target.jetkvm.startswith("http://") else None
        plain, over_https = await asyncio.gather(says_so(target.jetkvm), says_so(secure))
        if not (plain or over_https):
            return None
        return {"address": target.host, "kind": "jetkvm", "url": secure if over_https else target.jetkvm, "name": target.name}

    async def redfish() -> dict[str, Any] | None:
        try:
            ask = client.build_request("GET", f"{target.kvmd}/redfish/v1/")
            reply = await bounded(client, ask, MAX_PROBE, ANSWER_WITHIN)
            body = read_json(reply) if reply.status_code == 200 else None
        except (httpx.HTTPError, ValueError, KvmError):
            return None
        # A server's management controller shows the root of its Redfish service to anyone.
        if isinstance(body, dict) and "RedfishVersion" in body:
            return {"address": target.host, "kind": "redfish", "url": target.kvmd, "name": target.name}
        return None

    async def intel_amt() -> dict[str, Any] | None:
        # A PC with Intel AMT answers on ports of its own, and says what it is to anybody: asked both ways at
        # once, and taken over TLS where it answers that way. Listed at its plain address only where nothing
        # listens on its TLS port (as amt.detect decides it): where something there is slow (a scan waits less
        # than a second), or fails the TLS handshake, it is listed at its TLS address, and adding it says what
        # is wrong there; the plain way is the person's to type. Where something that is no engine answers
        # there, it is not listed at all: offered at either address, the password would go to one of two things.
        host = f"[{target.host}]" if ":" in target.host else target.host
        candidates = [f"{scheme}://{host}:{port}" for scheme, port in AMT_PORTS]
        answers = dict(zip(candidates, await asyncio.gather(*(amt.what_answers(client, candidate, ANSWER_WITHIN) for candidate in candidates)), strict=True))
        secure = next((candidate for candidate in candidates if candidate.startswith("https://")), None)
        found = next((candidate for candidate, answered in answers.items() if answered == "amt"), None)
        if found is None:
            return None
        if found.startswith("http://") and secure is not None:
            if answers[secure] == "other":
                return None
            # (Asked with a bare connection, and longer than the scan waits: on Windows a refusal takes two seconds.)
            if await listens(secure):
                found = secure
        return {"address": target.host, "kind": "amt", "url": found, "name": target.name}

    async def vnc() -> dict[str, Any] | None:
        """A VNC server greets whoever connects with its protocol version before a byte is sent to it: that is the whole question."""
        for port in VNC_PORTS:
            if await greeting(target.host, port, ANSWER_WITHIN) is not None:
                return {"address": target.host, "kind": "vnc", "url": vnc_url(f"{target.host}:{port}"), "name": target.name}
        return None

    first, second, third, fourth, fifth = await asyncio.gather(kvmd(), jetkvm(), redfish(), intel_amt(), vnc())
    return first or second or third or fourth or fifth


async def scan() -> dict[str, Any]:
    """Look for KVMs. Takes a few seconds per network."""
    wanted, networks = await asyncio.to_thread(targets)
    gate = asyncio.Semaphore(AT_ONCE)
    # Nothing secret is sent and the answer only says "there is a KVM here", so certificates are not checked.
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(2.0, connect=0.7), follow_redirects=False, trust_env=False) as client:

        async def ask(target: Target) -> dict[str, Any] | None:
            async with gate:
                return await _what_is(client, target)

        answers = await asyncio.gather(*(ask(target) for target in wanted))
    return {"found": once([answer for answer in answers if answer]), "scanned": len(wanted), "networks": networks}


def once(found: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What was found, with a KVM that answered at two addresses listed once.

    Under the first address it answered at: the network is asked before the VPN, so that is the nearer
    one. The others are kept as "also", for somebody who would rather use one of those.
    """
    listed: list[dict[str, Any]] = []
    by_mark: dict[str, dict[str, Any]] = {}
    for entry in found:
        entry.setdefault("mark", None)
        entry["also"] = []
        first = by_mark.get(entry["mark"]) if entry["mark"] else None
        if first is not None:
            first["also"].append({"address": entry["address"], "url": entry["url"], "name": entry["name"]})
            first["name"] = first["name"] or entry["name"]
            continue
        if entry["mark"]:
            by_mark[entry["mark"]] = entry
        listed.append(entry)
    return listed
