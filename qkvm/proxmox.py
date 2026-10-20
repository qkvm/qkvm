"""Kind "proxmox": a virtual machine on Proxmox VE, through Proxmox's own API, with an API token.

One tile per guest: the Proxmox it is on, its node and its number, and the token (its ID as the user name, its
secret as the password, kept in the vault like every password). The tile says whether the guest runs, and has the
power buttons: switch on, ask to shut down, stop at once, reset. Its screen comes through the console Proxmox hands
out: `POST .../vncproxy` makes a ticket, a port and a password for one connection, and `GET .../vncwebsocket` with
that ticket upgrades to a WebSocket that carries RFB, read by the shared reader (vncdevice.DoorScreen). There is no
other way to a guest's screen: Proxmox has no picture to ask for.

What was measured on Proxmox VE 9.2, and what follows from it here:

- The token alone opens the console: it goes in the `Authorization` header of the upgrade, as of every request, and
  never in an address. Every 401 is held back three seconds by Proxmox.
- The port waits ten seconds for one connection, on the host's own loopback; after that window, or for a ticket
  used a second time, the upgrade gets no answer at all. So the upgrade has a time of its own (UPGRADE_WAIT), and a
  ticket is used at once and once: neither it nor its password is kept beyond the handshake.
- Every vncproxy leaves a task in the node's task log, which the guest's owner reads. So a console is held while
  somebody looks at the tile and let go of five minutes after the last look (ProxmoxConsole.LET_GO_AFTER), opened again only
  where it ended; one that fails is asked for less and less often (CONSOLE_RETRY); and a guest that is stopped is
  asked for none at all (Proxmox would hand out a ticket all the same, and its task would say that it failed).
- Proxmox sends the console in binary frames of at most 128 KiB.
- The token's grants decide what a tile can do: VM.Audit to see the guest, VM.Console for its screen and keys,
  VM.PowerMgmt for the power buttons. What it lacks is said on the tile as Proxmox says it.
- A virtual machine made is given the lowest number that is free: one made after a guest was deleted had its number
  (2026-10-19). So a guest is known by the SMBIOS UUID it gives for itself, asked again before anything is sent (see
  ProxmoxGuest._same_guest), and not by its number alone.

Nothing a Proxmox answers is taken on trust: every answer is read within a size and a time, and taken apart by kind.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import httpx
from websockets.exceptions import InvalidStatus, WebSocketException

from . import kvm, rfb
from .kvm import (
    DOWN_CODES,
    MAX_REPLY,
    NO_SAID,
    REJECTED,
    RETIRED,
    STANDARD_HOLD,
    AlreadySo,
    Device,
    DeviceSpec,
    KvmError,
    Snapshot,
    _transport_error,
    can_do,
    number,
    plain,
    read_json,
    sign_in_waits,
    went_out,
    ws_connect,
    ws_error,
)
from .store import device_url
from .vncdevice import DoorScreen

log = logging.getLogger("qkvm")

PORT = 8006  # where Proxmox's API and its page answer, unless the address says otherwise
API = "/api2/json"
LOOK_EVERY = 5.0  # seconds between looks at a guest: a question that costs Proxmox next to nothing (no task)
RESTARTED_BY = 10.0  # seconds later than it was that a guest's process must have begun to have begun again (see _began_again)
LIVE_WAIT = 10.0  # seconds a live line, keys or a picture wait for the console to be open
UPGRADE_WAIT = 8.0  # seconds the console's upgrade may take: the port waits ten for its one connection, then nothing answers
MOST_FRAME = 128 * 1024 + 64  # bytes of one of the console's frames: Proxmox sends at most 128 KiB in one
MOST_LISTED = 4 * 1024 * 1024  # bytes of the list of a cluster's guests (a guest is about 350 of them: ten thousand fit)
MOST_GUESTS = 2000  # guests of one Proxmox listed to pick from
RELIST_EVERY = 60.0  # seconds between two readings of that list to find where a guest went that is not on its node
# By Proxmox and token: when that list was last read to find a guest, and where each guest was then (by its number); and
# by guest, when it last had the list read for it (once a minute at the most, whatever its Proxmox says at every look).
_NODES: dict[str, tuple[float, dict[int, str]]] = {}
_LISTED_FOR: dict[str, float] = {}
# A console that fails is asked for again after these many seconds, one after the other: every try is a task in the
# node's log, and a console that keeps failing must not write a task a minute into it all day.
CONSOLE_RETRY = (15.0, 60.0, 300.0, 900.0, 1800.0)
# Seconds within which a guest switched on or stopped is seen so, once Proxmox's task for it was seen to end (from the press,
# where how the task went cannot be read), or the command was not carried out.
CONFIRM_WITHIN = 25.0
# ...unless Proxmox's task for the command still runs (a guest with much memory, or devices of the host's, takes its time to
# start), or the command went to Proxmox's high availability, which carries it out a while after its own task ended: then
# up to this long, and after it the command is said to be still under way (it may yet be done), not to have failed.
TASK_WITHIN = 60.0
TASK_RUNS, TASK_OK = "running", "OK"  # how Proxmox says that a task runs, and that it ended well (its `exitstatus`)
TASK_WARNED = re.compile(r"WARNINGS: [0-9]{1,9}")  # ...and that it ended well with warnings, which its own page counts as done
CONFIRM_EVERY = 1.0
FOLLOW_UP = (2.0, 5.0, 10.0, 20.0, 40.0)  # moments after a power command at which the guest is looked at again
# Proxmox gives a new virtual machine the lowest number that is free: a guest deleted and another one made, on its node or on
# another, has its number, and a tile that went by the number alone showed that other one's screen, pressed its power
# buttons and typed into its console. So a guest is known by the number it gives for itself (its SMBIOS UUID, kept as
# DeviceSpec.machine), asked again before every power command, before each console (keys and text go through no other), and
# where the guest is followed to another node; and by a look once in this many seconds, so that the tile says so before
# anybody presses.
SAME_GUEST_EVERY = 60.0
ANOTHER_GUEST = (
    "Another virtual machine has this guest's number on its Proxmox now: it gives another SMBIOS UUID than the guest this tile "
    "was added for (Proxmox gives a new virtual machine the number of one that was deleted). Nothing is done to it: no power "
    "button, no key, no console. If it is this tile's guest now, edit the tile and type its token's secret."
)
NO_UUID = (
    "The virtual machine with this guest's number on its Proxmox gives no SMBIOS UUID, and the guest this tile was added for "
    "did. Nothing is done to it: no power button, no key, no console. If it is this tile's guest now, edit the tile and type "
    "its token's secret."
)

# What a token is: user@realm!name, and its secret, a UUID. Both go into a header, and nothing else may.
TOKEN_ID = re.compile(r"[A-Za-z0-9._+-]{1,64}@[A-Za-z][A-Za-z0-9._-]{0,31}![A-Za-z][A-Za-z0-9._-]{0,63}")
TOKEN_SECRET = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
NODE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")  # a node is named as a host is
LOWEST_VMID, HIGHEST_VMID = 100, 999_999_999  # the numbers Proxmox gives its guests
TICKET = re.compile(r"[!-~]{16,1024}")  # <password>:PVEVNC:<time>::<signature>, the password of any printable characters
ONE_TIME = re.compile(r"[!-~]{1,64}")  # the VNC password that comes with a ticket (eight printable characters, % < @ among them)
UPID = re.compile(r"UPID:[A-Za-z0-9:._@!+-]{1,500}")  # what Proxmox names a task by
WRONG_NODE = re.compile(r"does not exist|hostname lookup|no such (cluster )?node", re.IGNORECASE)
POWER_WORDS = {"running": "Running", "stopped": "Stopped", "paused": "Paused"}
POWER_VERBS = {"power_on": "start", "power_off": "shutdown", "atx_power_long": "stop", "atx_reset": "reset"}


# --- addresses ------------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Address:
    """A Proxmox, and a guest on it where one is named: `origin` is https://host[:port], as the wall writes it."""

    origin: str
    node: str | None = None
    vmid: int | None = None


def _vmid(text: str) -> int:
    if not text.isdigit() or len(text) > 9 or not LOWEST_VMID <= int(text) <= HIGHEST_VMID:
        raise ValueError(f"not a guest's ID: {text!r} (a number from {LOWEST_VMID} up)")
    return int(text)


def _node(text: str) -> str:
    if not NODE.fullmatch(text):
        raise ValueError(f"not a node's name: {text!r}")
    return text


def address_of(text: str) -> Address:
    """What somebody typed or pasted, as a Proxmox and the guest it names. ValueError where it is none.

    'pve.lan', 'pve.lan:8006', 'https://pve.lan:8006/' (no guest: the guests are listed to pick from);
    'pve.lan/100' (a guest by its number), 'pve.lan/pve1/100' (and its node); the address as the wall keeps it,
    'https://pve.lan:8006/nodes/pve1/qemu/100'; and the addresses Proxmox's own page shows: its console's
    ('...?console=kvm&vmid=100&node=pve1') and a guest's ('...#v1:0:=qemu%2F100:...'). Without a port: 8006.
    """
    text = text.strip()
    if not text:
        raise ValueError("no address")
    parts = urlsplit(text if "://" in text else f"https://{text}")
    if parts.scheme != "https":
        raise ValueError(f"not a Proxmox address: {text!r} (its API is spoken over HTTPS only)")
    try:
        port = parts.port or PORT
    except ValueError:
        raise ValueError(f"not a Proxmox address: {text!r}") from None
    if "@" in parts.netloc or not parts.hostname:
        raise ValueError(f"not a Proxmox address: {text!r}")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    origin = device_url(f"https://{host}:{port}")  # (written the one way, as every device's address is; ValueError for no host)
    node: str | None = None
    vmid: int | None = None
    steps = [step for step in parts.path.split("/") if step]
    if steps[:1] == ["nodes"] and len(steps) == 4:
        if steps[2] == "lxc":
            raise ValueError("a container's console is not shown on the wall yet: only virtual machines")
        if steps[2] != "qemu":
            raise ValueError(f"not a Proxmox guest's address: {text!r}")
        node, vmid = _node(steps[1]), _vmid(steps[3])
    elif len(steps) == 2:
        node, vmid = _node(steps[0]), _vmid(steps[1])
    elif len(steps) == 1:
        vmid = _vmid(steps[0])
    elif steps:
        raise ValueError(f"not a Proxmox guest's address: {text!r}")
    asked = parse_qs(parts.query)
    if vmid is None and asked.get("vmid"):
        # The address of a console Proxmox's own page opened.
        if asked.get("console") not in (["kvm"], None):
            raise ValueError("a container's or a node's console is not shown on the wall yet: only virtual machines")
        vmid = _vmid(asked["vmid"][0])
        node = _node(asked["node"][0]) if asked.get("node") else None
    if vmid is None and parts.fragment:
        # The address of Proxmox's own page with a guest picked in its tree: "#v1:0:=qemu%2F100:4:::::::".
        said = re.search(r"=(qemu|lxc)/(\d+)", unquote(parts.fragment))
        if said is not None:
            if said.group(1) == "lxc":
                raise ValueError("a container's console is not shown on the wall yet: only virtual machines")
            vmid = _vmid(said.group(2))
    return Address(origin, node, vmid)


def guest_url(origin: str, node: str, vmid: int) -> str:
    """A guest's address as the wall keeps it."""
    return f"{origin}/nodes/{node}/qemu/{vmid}"


def is_guest(url: str) -> bool:
    """Whether a kept address names one guest, with its node."""
    try:
        found = address_of(url)
    except ValueError:
        return False
    return found.node is not None and found.vmid is not None and guest_url(found.origin, found.node, found.vmid) == url


def console_page(url: str) -> str:
    """Where a browser opens the guest's own console, on Proxmox's page (after signing in there). Never fails: an
    address that is none (written into the settings by hand) is handed back as it is."""
    try:
        found = address_of(url)
    except ValueError:
        return url
    if found.node is None or found.vmid is None:
        return f"{found.origin}/"
    return f"{found.origin}/?" + urlencode({"console": "kvm", "novnc": "1", "vmid": found.vmid, "node": found.node, "resize": "scale"})


# --- reading what Proxmox answers -------------------------------------------------------------------------------------


class WrongNode(KvmError):
    """The guest is not on the node asked (it was moved, or the node is no more)."""


class Unwell(KvmError):
    """Proxmox answered with an error of its own (HTTP 5xx): one of its moments, as far as can be told, and no refusal."""


SAID_THE_TOKEN = "its words held the API token, and are not shown"


def _unsaid(text: str | None, reply: httpx.Response) -> str | None:
    """`text` without the token its request carried, where Proxmox (or a proxy before it) said it back: what Proxmox says
    goes into the log and onto the tile, which every account of the wall may read."""
    if not text:
        return text
    try:
        sent = reply.request.headers.get("authorization", "")
    except RuntimeError:  # (an answer made without a request: nothing was sent with it)
        return text
    token = sent.removeprefix("PVEAPIToken=")
    token_id, _, secret = token.partition("=")
    for piece in sorted({sent, token, token_id, secret}, key=len, reverse=True):
        if len(piece) >= 4:
            text = re.sub(re.escape(piece), "(the token)", text, flags=re.IGNORECASE)
    # Said back in another spelling (split by a line break, without its dashes, %-encoded): then none of these words, and
    # the owner is told so (whatever is in front of Proxmox says credentials back, and may write them down elsewhere).
    decoded = unquote(unquote(text)).lower()
    digits, secret_digits = re.sub(r"[^0-9a-f]", "", decoded), re.sub(r"[^0-9a-f]", "", secret.lower())
    if (len(token_id) >= 4 and token_id.lower() in decoded) or any(secret_digits[i : i + 8] in digits for i in range(len(secret_digits) - 7)):
        return SAID_THE_TOKEN
    return text


def _said(reply: httpx.Response) -> str:
    """What Proxmox said with an answer that is no yes: its message, or the words of its status line; never the token.
    (Made one line before the token is cut out, and cut to its length after: cut first, a token at the end would be
    left in part.)"""
    try:
        body = read_json(reply)
    except ValueError:
        body = None
    message = body.get("message") if isinstance(body, dict) else None
    return (
        plain(_unsaid(plain(message, 1000), reply), 160)
        or plain(_unsaid(plain(reply.reason_phrase, 1000), reply), 160)
        or f"HTTP {reply.status_code}"
    )


def data_of(reply: httpx.Response, what: str) -> Any:
    """The `data` of a yes, or the KvmError that says what Proxmox said instead. `what`: what was asked, for the words."""
    if reply.status_code == 200:
        try:
            body = read_json(reply)
        except ValueError:
            body = None
        if not isinstance(body, dict) or "data" not in body:
            raise KvmError("bad_response", f"Proxmox answered {what} with what is not its API's answer")
        return body["data"]
    said = _said(reply)
    if reply.status_code == 403:
        raise KvmError("bad_response", f"Proxmox does not let the token {what}: {said}")
    if reply.status_code == 500 and WRONG_NODE.search(said):
        raise WrongNode("bad_response", f"Proxmox has no such guest there: {said}")
    if reply.status_code in (595, 596):
        # (Proxmox's own numbers: the node it would hand the question on to does not answer.)
        raise KvmError("unreachable", f"Proxmox cannot reach the node the guest is on: {said}")
    if reply.status_code >= 500:
        raise Unwell("bad_response", f"Proxmox answered {what} with HTTP {reply.status_code}: {said}")
    raise KvmError("bad_response", f"Proxmox answered {what} with HTTP {reply.status_code}: {said}")


def guests_in(resources: Any) -> tuple[list[dict[str, Any]], int]:
    """The virtual machines of a cluster's list of resources (/cluster/resources?type=vm), by number; and how many
    containers it held, which the wall does not show yet. Taken by kind: what is not a guest is left out."""
    found: dict[int, dict[str, Any]] = {}
    containers = 0
    for entry in resources if isinstance(resources, list) else []:
        if not isinstance(entry, dict) or entry.get("template") in (1, True):
            continue
        vmid = number(entry.get("vmid"), LOWEST_VMID, HIGHEST_VMID)
        node = entry.get("node")
        if not isinstance(vmid, int) or not isinstance(node, str) or not NODE.fullmatch(node):
            continue
        if entry.get("type") == "lxc":
            containers += 1
            continue
        if entry.get("type") != "qemu" or vmid in found or len(found) >= MOST_GUESTS:
            continue
        status = entry.get("status")
        found[vmid] = {"vmid": vmid, "node": node, "name": plain(entry.get("name"), 80) or f"VM {vmid}", "status": status if isinstance(status, str) and status in POWER_WORDS else None}
    return [found[vmid] for vmid in sorted(found)], containers


def own_number(config: Any) -> str | None:
    """The number a virtual machine gives for itself (its SMBIOS UUID, which a clone is given anew), as a mark to know
    it by under another address of the same Proxmox; kept as a digest. None where there is none worth the name."""
    said = config.get("smbios1") if isinstance(config, dict) else None
    found = re.search(r"(?:^|,)uuid=([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})(?:,|$)", said) if isinstance(said, str) and len(said) < 1024 else None
    if found is None or len(set(found.group(1).replace("-", "").lower())) < 4:
        return None
    return "proxmox:" + hashlib.sha256(found.group(1).lower().encode()).hexdigest()[:32]


# --- the guest ---------------------------------------------------------------------------------------------------------


class ProxmoxConsole(DoorScreen):
    """The guest's screen: the console its Proxmox hands out, held while somebody looks (see DoorScreen)."""

    kind = "proxmox"
    THING = "the guest's console"
    # A console that gives a picture and ends, every time, is not well: each try is a task in Proxmox's log. Only a
    # console that lasted half a minute is.
    SETTLED_BY_A_FRAME = False
    # A guest that began again (see guest_began_again) explains a console that ended this many seconds or less before its
    # new process began; and forgives at most once in RESTART_FORGIVEN_EVERY. (What says so is Proxmox's word, its
    # `uptime`: a Proxmox that said it at every look had every console forgiven, also those that never let qKVM in.)
    RESTART_WITHIN = 60.0
    RESTART_FORGIVEN_EVERY = 60.0
    # Held this long after its last viewer (the owner's standard): every console opened is a task in the node's log, and a
    # wall looked at in visits a few minutes apart had one written at each visit.
    LET_GO_AFTER = STANDARD_HOLD
    # A guest seen stopped has the next console asked for at once once it runs again, at most once in this long: a Proxmox
    # that says "stopped" and "running" by turns had a console opened at every other look (about 360 an hour), each one a
    # task in its log. What failed before is still counted then, and the ladder goes on from where it was.
    STOPPED_FORGIVEN_EVERY = STANDARD_HOLD

    def __init__(self, spec: DeviceSpec, guest: ProxmoxGuest) -> None:
        super().__init__(spec)
        self._guest = guest
        self._restart_forgiven_at = float("-inf")
        self._stopped_forgiven_at = float("-inf")

    async def _open(self) -> rfb.Stream:
        """A ticket from Proxmox, and the WebSocket it opens, at once: what follows is RFB."""
        session = self._session
        assert session is not None  # (_run is only ever started for the session that is self._session)
        try:
            port, ticket, password = await self._guest.console_ticket()
            # (Used at once and once, and kept nowhere: a second use gets no answer from Proxmox at all.)
            ws = await self._guest.console_socket(port, ticket)
        except KvmError as ex:
            # Asked for again on this console's own ladder, not at the next look: every vncproxy that was answered
            # is a task in the node's log. (A no to the token, or a guest that is stopped, is the tile's to say: asking
            # again costs nothing then, the tile answers it without asking Proxmox.)
            if ex.code in DOWN_CODES:
                raise self._failed(ex) from None
            if isinstance(ex, Unwell):
                # One of Proxmox's moments ("busy", say): a console that failed, waited out by everyone, and no refusal.
                raise self._failed(KvmError("dropped", ex.message), moment=True) from None
            if ex.code in ("bad_response", "not_found"):
                raise self._left_alone(ex) from None
            raise
        session.one_time = password
        return rfb.WebSocketStream(ws)

    def _ended(self, session: Any, offered: str, ex: rfb.RfbError) -> KvmError:
        if ex.code in (rfb.AUTH, rfb.NO_PASSWORD, rfb.REFUSED, rfb.UNSUPPORTED):
            # The password Proxmox handed out with the ticket, refused a moment later; or a console that does not
            # let qKVM in. Nothing to do with the token, and nothing counted against it: said, and left alone.
            return self._left_alone(KvmError("bad_response", f"The guest's console does not let qKVM in: {ex.message}"))
        return super()._ended(session, offered, ex)

    def _retry(self) -> tuple[float, ...]:
        return CONSOLE_RETRY

    def guest_stopped(self) -> None:
        """The guest was seen stopped: its console ended with it and did not fail, so what failed before is forgiven, and the
        next one, once the guest runs again, is asked for at once (a guest stopped and started a few times would otherwise
        wait out a ladder that is not its).

        At most once in STOPPED_FORGIVEN_EVERY, and only where there is something to forgive: a Proxmox that reports a guest
        stopped and running by turns (the guest itself never stopping), about a console that keeps failing, cannot reset the
        ladder at every look (it was forgiven in full every time, and a console opened about 360 times an hour); a guest
        truly stopped and started more often than that climbs the ladder for the extra times, a small delay. A console that
        serves long enough forgives the rest, as ever (`_settled`)."""
        if not (self._failures or self._bad or self._cut_in_run):
            return  # (nothing failed: the once-in-five-minutes forgiveness is not spent on it)
        now = time.monotonic()
        if now - self._stopped_forgiven_at < self.STOPPED_FORGIVEN_EVERY:
            return
        self._stopped_forgiven_at = now
        self.forgive()

    def guest_began_again(self, began: float) -> None:
        """The guest's process began again since the last look, at `began` (qKVM's clock; Proxmox's own Reboot, HA starting
        it again): a console that let qKVM in and ended a little before ended with it, and what failed is forgiven, those
        tried while it began again with it; at most once in RESTART_FORGIVEN_EVERY. Without such a console nothing is
        forgiven: a restart does not explain consoles that never let qKVM in."""
        now, ended = time.monotonic(), self._let_in_ended_at
        if began - self.RESTART_WITHIN <= ended <= began + 2.0 and now - self._restart_forgiven_at >= self.RESTART_FORGIVEN_EVERY:
            # (`began` is when the process began at the latest, its answer having been on its way: a console that ended
            # with the old one ended before it, give or take the second Proxmox counts in.)
            self._restart_forgiven_at = now
            self.forgive()


class ProxmoxGuest(Device):
    """A virtual machine on Proxmox VE."""

    kind = "proxmox"
    picture = False  # (said as a server is: on or off, and its screen where it can be had: `screen`)
    # Its power buttons, and on/off by what is wanted. A look adds its screen, keys and text, and the live line with
    # keyboard and mouse, while it runs.
    can = ("power", "reset", "power_state")

    def __init__(self, spec: DeviceSpec, on_pin: Any = None) -> None:
        super().__init__(spec, on_pin)
        try:
            found = address_of(spec.base_url)
        except ValueError:
            found = Address("", None, None)
        self._origin, self._node, self._vmid = found.origin, found.node, found.vmid
        self._console = ProxmoxConsole(spec, self)
        self._login_lock = asyncio.Lock()
        self._signed_in = False  # the token was taken, and has not been refused since
        self._version: str | None = None  # Proxmox's own, as it said it at the sign-in
        self._power_on: bool | None = None  # what the last look found
        # When the guest's process began, as the last look that found it running could tell (qKVM's clock less the uptime
        # Proxmox said).
        self._began_at: float | None = None
        self._following: asyncio.Task[None] | None = None
        self._moved_said = False
        # Another virtual machine has this guest's number (see `_same_guest`): what is said, and nothing done, meanwhile.
        self._other: KvmError | None = None
        self._judged_at = float("-inf")  # when which virtual machine has the number was last asked and judged
        # How often it was: a look that asked on its way (following the guest to another node) does not ask twice. (Counted,
        # not told by the time: Windows' clock before Python 3.13 moves in steps of 15.6 ms, and a look that came within one
        # step of the last one's question took it for its own, and asked nothing.)
        self._judges = 0

    async def close(self) -> None:
        self._closed = True  # (no console is opened from here on)
        if self._following is not None:
            self._following.cancel()
        await self._console.close()
        await super().close()

    def tidy(self) -> None:
        self._console.tidy()

    # --- the token, and asking -----------------------------------------------------------------------------------

    def _offered(self) -> str:
        """The mark of this token at this Proxmox: one for every guest of it on the wall, which share one verdict."""
        return REJECTED.what("login", dataclasses.replace(self.spec, base_url=self._origin))

    def _authorization(self) -> dict[str, str]:
        if not TOKEN_ID.fullmatch(self.spec.username) or not TOKEN_SECRET.fullmatch(self.spec.password):
            # (Checked before anything is sent: both go into a header, and what is not a token is not sent anywhere.)
            raise KvmError("invalid", "The user name is to be an API token's ID (user@realm!token) and the password its secret", 422)
        return {"Authorization": f"PVEAPIToken={self.spec.username}={self.spec.password}"}

    async def _login(self) -> None:
        """Have the token taken once: the first request that carries it is the sign-in, counted as one.

        Every request after it carries the token again (Proxmox has no session for a token), and a 401 to any of them
        is answered by signing in once more, counted: a token that was taken back is a no like any other.
        """
        async with self._login_lock:
            if self._signed_in:
                return
            if self._login_error and time.monotonic() < self._login_retry_at:
                raise self._login_error.with_traceback(None)
            if not self.spec.password:
                raise KvmError("no_password", "No password saved for this device")
            if not self._origin:
                raise KvmError("invalid", "This is not the address of a Proxmox guest", 422)
            headers = self._authorization()
            offered = self._offered()
            self._not_yet(offered, NO_SAID)
            client = await self._http()
            request = client.build_request("GET", f"{self._origin}{API}/version", headers={**headers, "Accept": "application/json"}, timeout=sign_in_waits())
            before = REJECTED.sent(offered)
            try:
                reply = await self._send(client, request, MAX_REPLY)
            except httpx.HTTPError as ex:
                raise self._came_to_nothing(offered, _transport_error(ex, self.spec.tls), NO_SAID, before, went_out(ex)) from ex
            except KvmError as ex:
                raise self._came_to_nothing(offered, ex, NO_SAID, before) from None
            self._answered()
            if reply.status_code == 401:
                self._login_error = KvmError("auth_failed", "Proxmox does not take the saved API token - check the token's ID and secret")
                self._login_retry_at = time.monotonic() + REJECTED.said_no(offered)
                log.warning("%s: Proxmox rejected the API token", self.label)
                raise self._login_error
            try:
                said = data_of(reply, "say its version")
            except KvmError as ex:
                raise self._neither_yes_nor_no(offered, ex, NO_SAID) from None
            version = said.get("version") if isinstance(said, dict) else None
            if not isinstance(version, str):
                raise self._neither_yes_nor_no(offered, KvmError("bad_response", "What answers does not say it is Proxmox VE"), NO_SAID)
            self._login_error = None
            REJECTED.accepted(offered)
            self._version = plain(version, 20)
            self._signed_in = True

    async def _call(
        self,
        method: str,
        path: str,
        *,
        urgent: bool = False,
        vital: bool = True,
        again: bool = True,
        limit: int = MAX_REPLY,
        still: Callable[[], bool] | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        until: float | None = None,
    ) -> httpx.Response:
        """A request to Proxmox's API with the token. `urgent`, `vital` and `still` mean what they mean for a KVM (see
        KvmDevice._request); `again`: it may be sent a second time on a connection Proxmox closed while it sat idle
        (a power command is not: it is not pressed twice); `until`: the moment (time.monotonic()) by which the answer is
        to be in, as far as `bounded` lets a request be held to one (never less than getting a connection may take)."""
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = False
        while True:
            await self._login()
            client = await self._http()
            request = client.build_request(method, f"{self._origin}{API}{path}", headers={**self._authorization(), "Accept": "application/json"}, data=data, params=params)
            if still is not None and not still():
                raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
            within = None
            if until is not None:
                # What is left until then, and never more than the request's own time (as `bounded` adds it up where it is
                # given none): the moment shortens a request's wait, it does not lengthen it.
                waits = request.extensions.get("timeout") or {}
                within = min(until - time.monotonic(), (waits.get("connect") or 0.0) + (waits.get("read") or 0.0) + kvm.TRANSFER_TIME)
            try:
                reply = await self._send(client, request, limit, within)
            except KvmError as ex:
                raise failed(ex) from None
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as ex:
                if again and not retried:
                    retried = True
                    continue
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            except httpx.HTTPError as ex:
                raise failed(_transport_error(ex, self.spec.tls)) from ex
            self._answered()
            if reply.status_code != 401:
                return reply
            if relogged:
                # It takes the token for its version and refuses it for this: every look would end here. Not sent at
                # every look meanwhile: held back as a sign-in that came to nothing.
                async with self._login_lock:
                    self._signed_in = False
                    held = self._held_back(self._offered(), KvmError("bad_response", "Proxmox takes the token and refuses the request after it"), NO_SAID)
                raise held
            relogged = True
            self._signed_in = False  # the token was taken back, or Proxmox restarted: signed in once more, counted

    async def _guest(self, method: str, step: str, what: str, **options: Any) -> Any:
        """Ask about this guest (`step` below its place, as "status/current"); followed once to another node where
        Proxmox says the guest is not on the one asked (it was moved within its cluster), once the virtual machine with
        its number there is found to be this guest (`_judge`): it may be another one, made there after this one was
        deleted, and nothing is asked of it or sent to it then."""
        if self._node is None or self._vmid is None:
            raise KvmError("invalid", "This is not the address of a Proxmox guest", 422)
        for attempt in range(2):
            reply = await self._call(method, f"/nodes/{self._node}/qemu/{self._vmid}/{step}", **options)
            try:
                return data_of(reply, what)
            except WrongNode as ex:
                urgent, until = options.get("urgent", False), options.get("until")
                moved_to = await self._where_now(urgent, until) if attempt == 0 else None
                if moved_to is None or moved_to == self._node:
                    raise KvmError("bad_response", f"Proxmox has no guest {self._vmid} on {self._node}, nor on another node the token can see ({ex.message})") from None
                await self._judge(await self._number_at(moved_to, urgent=urgent, vital=options.get("vital", True), until=until))
                if not self._moved_said:
                    self._moved_said = True
                    log.info("%s: the guest is on node %s now (it was on %s)", self.label, moved_to, self._node)
                self._node = moved_to
        raise AssertionError("unreachable")  # (the loop returns or raises)

    # --- which virtual machine has the guest's number: the one this tile was added for, or another -----------------------
    # A guest is named by its node and its number, and Proxmox gives a new virtual machine the lowest number that is free.
    # A guest deleted and another made has its number, there or on another node; the tile, still named after the old one,
    # showed the new one's screen to whoever may see the old one, pressed its power buttons and typed into its console. The
    # number a guest gives for itself (its SMBIOS UUID, which a clone is given anew) tells the two apart: remembered when the
    # tile is added (DeviceSpec.machine), and asked again before anything is sent.

    async def _number_at(self, node: str, *, urgent: bool, vital: bool = True, until: float | None = None) -> str | None:
        """The number the virtual machine with this guest's number on `node` gives for itself (own_number; None: none)."""
        reply = await self._call("GET", f"/nodes/{node}/qemu/{self._vmid}/config", urgent=urgent, vital=vital, until=until)
        return own_number(data_of(reply, "read this guest's settings"))

    async def _same_guest(self, urgent: bool, vital: bool = True, until: float | None = None) -> None:
        """Ask afresh which virtual machine has this guest's number, and judge it (`_judge`): before every power command,
        before each console is opened (keys and text go through no other), and at a look once in SAME_GUEST_EVERY.
        KvmError "another_machine" where it is another one, or gives no number where one is remembered; the error of the
        asking where it could not be asked and one is remembered. Where none is remembered, an answer that is none is no
        number: there is nothing to tell the guest apart from, and it works as before."""
        try:
            config = await self._guest("GET", "config", "read this guest's settings", urgent=urgent, vital=vital, until=until)
        except KvmError as ex:
            if ex is RETIRED or self._closed or self.spec.machine or ex.code == "another_machine":
                raise
            config = None
        await self._judge(own_number(config))

    async def _judge(self, seen: str | None) -> None:
        """Whether the virtual machine that has this guest's number is the guest this tile was added for, by the number it
        gives for itself (`seen`; None: none). Nothing where it is; KvmError "another_machine" where it is not, or gives
        none where one is remembered.

        Where none is remembered (a tile taken from a file without one, or saved while its Proxmox could not be reached),
        the first one seen is remembered from then on, and said in the log: trust on first use, as for a certificate."""
        self._judged_at, self._judges = time.monotonic(), self._judges + 1
        remembered = self.spec.machine
        if seen is None:
            if remembered:
                raise self._another(NO_UUID)
            return
        if not remembered:
            self.spec.machine = seen
            log.info("%s: the guest is known by the number it gives for itself from now on", self.label)
            if self.on_known is not None and not self._closed:
                await self.on_known("", seen)  # (none was remembered: kept only where none is yet, as the server's hook checks)
            return
        if seen != remembered:
            raise self._another(ANOTHER_GUEST)
        if self._other is not None:
            log.info("%s: the guest this tile was added for has its number again", self.label)
            self._other = None
            self._status_at = 0.0  # (the tile says so at the next look)

    def _another(self, words: str) -> KvmError:
        """Note that another virtual machine has this guest's number: what is said from now on, until the guest has it again."""
        if self._other is None or self._other.message != words:
            log.warning("%s: %s", self.label, words)
            self._status_at = 0.0  # (the tile says it at the next look, not up to LOOK_EVERY later)
        self._other = KvmError("another_machine", words)
        # What was read of it is another's: its power is not taken for this guest's, nor its process's start for this one's.
        self._power_on, self._began_at = None, None
        return self._other

    async def _where_now(self, urgent: bool, until: float | None = None) -> str | None:
        """The node this guest is on, as the cluster says it; None where it is on none the token can see, or where the
        cluster was asked that less than RELIST_EVERY ago (a Proxmox that says "not on this node" at every look does not
        have its whole list read at every look)."""
        if self._vmid is None:
            return None
        # Kept beside the guests, which are made anew at every edit: the list as it was last read for this Proxmox and
        # token, where each guest was then; and, by guest, when it last had the list read for it.
        listing, guest = f"{self._origin}\0{self.spec.username}", f"{self._origin}\0{self.spec.username}\0{self._vmid}"
        read_at, nodes = _NODES.get(listing, (float("-inf"), {}))
        known = nodes.get(self._vmid)
        if known is not None and known != self._node and time.monotonic() - read_at < RELIST_EVERY:
            return known  # (a list read a moment ago, for this guest or another, says where it went)
        if time.monotonic() - _LISTED_FOR.get(guest, float("-inf")) < RELIST_EVERY:
            return None
        _LISTED_FOR.pop(guest, None)  # (the newest last)
        _LISTED_FOR[guest] = time.monotonic()
        while len(_LISTED_FOR) > 4096:
            del _LISTED_FOR[next(iter(_LISTED_FOR))]
        listed, _ = await self._listed(urgent, until)
        nodes = {int(one["vmid"]): str(one["node"]) for one in listed}
        _NODES.pop(listing, None)
        _NODES[listing] = (time.monotonic(), nodes)
        while len(_NODES) > 256:
            del _NODES[next(iter(_NODES))]
        return nodes.get(self._vmid)

    async def _listed(self, urgent: bool, until: float | None = None) -> tuple[list[dict[str, Any]], int]:
        reply = await self._call("GET", "/cluster/resources", urgent=urgent, limit=MOST_LISTED, params={"type": "vm"}, until=until)
        # Read in a thread: a cluster's list is megabytes where it is large, and reading it is the loop's time otherwise.
        return await asyncio.to_thread(lambda: guests_in(data_of(reply, "list its guests")))

    async def listing(self) -> tuple[list[dict[str, Any]], int]:
        """The virtual machines this token may see, for somebody adding them (see `guests_in`)."""
        return await self._listed(urgent=True)

    # --- the console's door (ProxmoxConsole) -----------------------------------------------------------------------

    async def console_ticket(self) -> tuple[int, str, str]:
        """(port, ticket, password) for one console: a task in the node's log each time, so asked only when one is opened."""
        if self._other is not None:
            raise self._other.with_traceback(None)  # (another virtual machine has the guest's number: see `_same_guest`)
        if self._power_on is False:
            raise KvmError("no_picture", "The guest is stopped", 404)
        # Asked first whether it runs, as it is now: a guest stopped since the last look is asked for no console (whose
        # task would say it failed); and this question, which may be asked again, is the one that finds a connection that
        # Proxmox closed while it sat idle, not the vncproxy after it, which is not sent twice.
        # (Not `vital`: a console that fails is the console's to retry, and the tile goes on saying how the guest is.)
        now = await self._guest("GET", "status/current", "look at this guest", urgent=True, vital=False)
        # And which virtual machine has the guest's number, right before its console is asked for: another one's screen is
        # not shown, nor are keys or text typed into it (they go through no other way than a console opened here). What the
        # question above found is acted on only once that is known.
        await self._same_guest(urgent=True, vital=False)
        if not isinstance(now, dict) or now.get("status") != "running":
            if isinstance(now, dict) and now.get("status") == "stopped":
                self._power_on = False
                self._began_at = None
                self._console.guest_stopped()  # (as the tile's own look does: the console that ended with it did not fail)
            raise KvmError("no_picture", "The guest is not running", 404)
        self._began_again(now)
        said = await self._guest("POST", "vncproxy", "open its console", urgent=True, vital=False, again=False, data={"websocket": "1"})
        said = said if isinstance(said, dict) else {}
        port, ticket, password = said.get("port"), said.get("ticket"), said.get("password")
        if isinstance(port, str) and port.isdigit() and len(port) <= 5:
            port = int(port)  # (Proxmox says it as a text)
        if not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
            raise KvmError("bad_response", "Proxmox handed out a console without a port")
        if not isinstance(ticket, str) or not TICKET.fullmatch(ticket) or not isinstance(password, str) or not ONE_TIME.fullmatch(password):
            raise KvmError("bad_response", "Proxmox handed out a console without a ticket and its password")
        return port, ticket, password

    def _anew(self, found: Any) -> bool:
        """Whether a look finds the guest otherwise than the last one did in a way a virtual machine made under its number
        mostly is: stopped where it ran, running where it was stopped, running a process begun since (see `_began_again`),
        or found after a look that knew neither (none yet since the tile was made, or one that found the guest neither
        running nor stopped). Not a guest stopped, deleted, and another made stopped: that one waits for the minute (it is
        asked for no console, and a button asks first). Nothing is changed by asking."""
        status = found.get("status") if isinstance(found, dict) else None
        on = True if status == "running" else False if status == "stopped" else None
        if on is None:
            return False
        if self._power_on is None or on != self._power_on:
            return True
        uptime = number(found.get("uptime"), 0, 2**40) if on else None
        if not uptime or self._began_at is None:
            return False  # (stopped and still stopped; or no uptime said, or one in its first second: the next look finds it)
        return time.monotonic() - uptime > self._began_at + RESTARTED_BY

    def _began_again(self, found: dict[str, Any]) -> None:
        """A running guest whose process began again since the last look (Proxmox's own Reboot, HA starting it again)
        ended its console with it (see ProxmoxConsole.guest_began_again). Told by when the process began, as qKVM's clock
        has it: later by more than RESTARTED_BY than the last look found. (Not by one uptime against the last: a restart
        found by a look long after was missed. Against the last look, and not the earliest: qKVM's clock and Proxmox's go
        apart a little each day, and that added up to a restart now and then where there was none.)"""
        uptime = number(found.get("uptime"), 0, 2**40)
        if not uptime:
            return  # (none said; or a process in its first second, which the next look finds)
        began = time.monotonic() - uptime
        if self._began_at is not None and began > self._began_at + RESTARTED_BY:
            self._console.guest_began_again(began)
        self._began_at = began

    async def console_socket(self, port: int, ticket: str) -> Any:
        """The WebSocket a ticket opens, to the Proxmox the token was given for and nowhere else, within UPGRADE_WAIT."""
        assert self._node is not None and self._vmid is not None
        await self._http()  # (the certificate is known by now: the ticket came over it)
        query = urlencode({"port": port, "vncticket": ticket}, quote_via=quote)
        uri = f"wss://{self._origin[len('https://'):]}{API}/nodes/{self._node}/qemu/{self._vmid}/vncwebsocket?{query}"
        try:
            return await ws_connect(
                uri, ssl=self._tls, additional_headers=self._authorization(), subprotocols=["binary"],
                open_timeout=UPGRADE_WAIT, close_timeout=1, max_size=MOST_FRAME, max_queue=8,
                ping_interval=None,  # (whether it is alive is seen by what arrives: see vncdevice's heartbeat)
            )  # fmt: skip
        except TimeoutError:
            raise KvmError("timeout", "Proxmox did not open the console in time", 504) from None
        except InvalidStatus as ex:
            said = f"Proxmox did not open the console it handed out (HTTP {ex.response.status_code})"
            raise (Unwell if ex.response.status_code >= 500 else KvmError)("bad_response", said) from None
        except (OSError, WebSocketException) as ex:
            raise ws_error(ex, self.spec.tls) from None

    # --- what the wall asks ----------------------------------------------------------------------------------------

    async def identify(self) -> dict[str, Any]:
        status = await self._guest("GET", "status/current", "look at this guest", urgent=True)
        # Added: the guest is remembered by the number it gives for itself from here on (the server keeps spec.machine with
        # the tile). Edited: it is the guest remembered, asked afresh, or the edit is refused (unless its token's secret was
        # typed, which takes the virtual machine that has the number now: see the server's update_device).
        status = status if isinstance(status, dict) else {}
        said = {"model": f"VM {self._vmid} on {self._node}", "version": f"Proxmox VE {self._version}" if self._version else None, "hostname": plain(status.get("name"), 60)}
        try:
            config = await self._guest("GET", "config", "read this guest's settings", urgent=True)
        except KvmError:
            if self.spec.machine:
                # Not read just now: that says nothing of the number, which is not "it gives none". An edit keeps what the
                # tile is known by (None, as every driver that could not read its number says), and every power command
                # and console asks again before anything is sent.
                return {**said, "ident": None}
            config = None  # (nothing to know it by: it is known by its address, and by the first number it gives)
        seen = own_number(config)
        await self._judge(seen)
        return {**said, "ident": seen}

    async def _screen_allowed(self) -> None:
        """Nothing, where the guest's screen may be had now; else the KvmError that says why not (the last look decides)."""
        if self._other is not None:
            raise self._other.with_traceback(None)  # (another virtual machine has the guest's number: see `_same_guest`)
        if self._status is None:
            self._refresh_soon()
            raise KvmError("no_stream", "Looking at the guest", 503)
        if self._status.get("state") not in ("online", "no_signal"):
            said = self._status.get("error") or {}
            raise KvmError(str(said.get("code") or "unreachable"), str(said.get("message") or "Device is unreachable"))
        if self._power_on is False:
            raise KvmError("no_picture", "The guest is stopped", 404)

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """The guest's screen: the first one asked for opens its console."""
        await self._screen_allowed()
        return await self._console.snapshot(width, fresh)

    @property
    def console_readable(self) -> bool:
        """Whether its screen can be had, as far as the last look knows: what the live line asks before it begins, and
        when a picture failed. A console that failed is waited for (asked again on its ladder); one turned away is not, nor
        is a guest whose Proxmox does not take the token, or shows another certificate (its tile asks no console then), nor
        one whose number another virtual machine has now."""
        if self._other is not None:
            return False
        status = self._status or {}
        said = status.get("error") or {}
        if status.get("state") == "auth" or said.get("code") in ("cert_mismatch", "cert_invalid"):
            return False
        return self._power_on is not False and self._console.turned_away() is None

    async def live_screen(self) -> tuple[int, int, int, bytearray]:
        """The guest's screen as it stands, for the live line: frames so far, width, height, three bytes a pixel."""
        await self._screen_allowed()
        self._console.live_seen()
        client = await self._console.ready(LIVE_WAIT)
        if client.frames == 0:
            await self._console.next_frame(0, LIVE_WAIT)
        shown = self._console.screen()
        if shown is None:
            raise KvmError("no_stream", "Waiting for the guest's screen", 503)
        return shown

    async def input_ready(self) -> None:
        await self._screen_allowed()
        self._console._looking()  # (somebody is at its keyboard: the console is not let go of for nobody)
        await self._console.ready(LIVE_WAIT)

    def screen_size(self) -> tuple[int, int] | None:
        return self._console.size()

    async def press(self, usage: int, down: bool) -> None:
        """A key by its HID usage (see VncDevice.press). A key let go of goes to the console that is open, whatever the
        last look found since, and opens none."""
        if not down:
            await self._console.let_go_key(usage)
            return
        await self.input_ready()
        await self._console.press(usage, down)

    async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False) -> None:
        """The pointer at (x, y) of the guest's screen (see VncDevice.pointer); `letting_go`: as a key let go of."""
        if letting_go:
            await self._console.let_go_pointer(x, y, buttons)
            return
        await self.input_ready()
        await self._console.pointer(x, y, buttons)

    def _stale(self) -> bool:
        return self._status is None or time.monotonic() - self._status_at > LOOK_EVERY

    async def _read_status(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._other is not None and now - self._judged_at < SAME_GUEST_EVERY:
            # (Another virtual machine has the guest's number: said, and asked again once a minute, not at every look.)
            return {"state": "error", "error": self._other.as_dict(), "kind": self.kind, "picture": False}
        try:
            judges = self._judges
            found = await self._guest("GET", "status/current", "look at this guest")
            # Which virtual machine has the guest's number, asked after its state was read and before anything is taken from
            # it (as before a button and a console: a VM made under the number between the two reads is found then): once a
            # minute, and at once where the look finds the guest otherwise than a VM made under its number mostly is (the
            # tile said the new one's power, processors and memory as this guest's until the minute was over). Not where the
            # state's own read just asked, following the guest to another node.
            if self._judges == judges and (now - self._judged_at >= SAME_GUEST_EVERY or self._anew(found)):
                await self._same_guest(urgent=False)
        except KvmError as ex:
            if ex.code == "another_machine":
                return {"state": "error", "error": ex.as_dict(), "kind": self.kind, "picture": False}
            if ex.code in ("auth_failed", "no_password", "no_sign_in", "bad_response"):
                ex = await self._gone_meanwhile(f"{self._origin}/") or ex
            if ex.code in ("auth_failed", "no_password"):
                state = "auth"
            elif ex.code in ("cert_mismatch", "cert_invalid", "bad_response", "no_sign_in", "invalid", "not_found"):
                state = "error"
            else:
                state = "offline"
            return {"state": state, "error": ex.as_dict(), "kind": self.kind, "picture": False}
        found = found if isinstance(found, dict) else {}
        status, running = found.get("status"), plain(found.get("qmpstatus"), 20)
        on = True if status == "running" else False if status == "stopped" else None
        self._power_on = on
        if on is False:
            self._began_at = None
            self._console.guest_stopped()
        elif on:
            self._began_again(found)
        refused = self._console.refused_now() if on else None
        has_screen = on is True and refused is None
        size = self._console.size() if on else None
        cpus = number(found.get("cpus"), 1, 4096)
        memory = number(found.get("maxmem"), 0, 2**50)
        used, cpu = number(found.get("mem"), 0, 2**50), number(found.get("cpu"), 0, 4096)
        power = "Paused" if on and running == "paused" else POWER_WORDS.get(status) if isinstance(status, str) else None
        return {
            "state": "no_signal" if on is False else "online",
            "error": None,
            "kind": self.kind,
            "picture": False,
            "screen": has_screen,  # a picture of the guest's screen can be asked for (see `snapshot`)
            "can": can_do(*self.can, *(("screen", "keys", "text", "live", "control") if has_screen else ())),
            "video": {"signal": on, "width": size[0] if size else None, "height": size[1] if size else None, "fps": None},
            "usb": {"keyboard": None, "mouse": None},
            "atx": {"enabled": True, "power": on, "hdd": None},
            "health": {
                "temp": None,
                "cpu": round(min(100.0, 100.0 * cpu), 1) if cpu is not None and on else None,
                "mem": round(min(100.0, 100.0 * used / memory), 1) if used is not None and memory and on else None,
            },
            "about": {"model": f"VM {self._vmid} on {self._node}", "version": f"Proxmox VE {self._version}" if self._version else None},
            "ports": None,
            "console": False,
            "server": {
                "power": power,
                "health": None,
                "processor": "vCPU" if cpus else None,
                "processors": cpus,
                "memory_gib": round(memory / 2**30, 2) if memory else None,
                "temperatures": [],
                "fans": [],
                "unwell": [],
                "locator": None,
                "no_screen": refused,  # why its screen is not shown while it runs, where it is not
                "rfb_console": None,  # (a server's OpenBMC console; the same record for every machine said as a server)
                "proxmox": {
                    "node": self._node,
                    "vmid": self._vmid,
                    "status": status if isinstance(status, str) and status in POWER_WORDS else None,
                    "qmpstatus": running,
                    "uptime": number(found.get("uptime"), 0, 2**40),
                },
            },
        }

    # --- the power buttons -----------------------------------------------------------------------------------------

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """What the wall's power buttons mean to a guest of Proxmox:

        'power_on'        start it; one that runs is left as it is (AlreadySo)
        'power_off'       ask the guest to shut down (Proxmox's shutdown, through ACPI or its agent); one that is stopped is left as it is
        'atx_power'       the power button: whichever of those two applies
        'atx_power_long'  stop it at once (Proxmox's stop: the plug pulled)
        'atx_reset'       reset it at once (Proxmox's reset)

        And through its console, where it runs: 'keys', 'text', 'ctrl_alt_del', as for a VNC server.
        """
        if action in ("keys", "text", "ctrl_alt_del"):
            await self.input_ready()
            await self._console.act(action, keys=keys, text=text, still=still)
            return
        if action == "reboot":
            raise KvmError("invalid", "A guest of Proxmox has no controller of its own to restart: reset the guest itself", 422)
        if action not in ("power_on", "power_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A guest of Proxmox cannot do that", 422)
        began = time.monotonic()  # (the press: what a start or a stop is waited for is bounded from here, see `_carried_out`)
        found = await self._guest("GET", "status/current", "look at this guest", urgent=True)
        # Which virtual machine has the guest's number, right before the command: another one is sent nothing, and what the
        # question above found of it decides nothing (not even "already on").
        await self._same_guest(urgent=True)
        status = found.get("status") if isinstance(found, dict) else None
        if status not in ("running", "stopped"):
            # (Not "stopped" for want of a word: a button decided on a guess could stop what runs, or say "already off" of it.)
            raise KvmError("bad_response", "Proxmox did not say whether the guest runs")
        running = status == "running"
        if action in ("power_on", "power_off") and running == (action == "power_on"):
            raise AlreadySo("already on" if running else "already off")
        if action == "atx_reset" and not running:
            raise KvmError("action_failed", "The guest is stopped: there is nothing to reset")
        verb = POWER_VERBS.get(action) or ("shutdown" if running else "start")
        said = await self._guest("POST", f"status/{verb}", f"{verb} this guest", urgent=True, again=False, still=still)
        if not isinstance(said, str) or not UPID.fullmatch(said):
            raise KvmError("bad_response", "Proxmox did not say that it took the power command")
        self._status_at = 0.0  # what the tile says is out of date now,
        self._refresh_soon()  # and is read again without waiting to be asked,
        if self._following is not None:
            self._following.cancel()
        self._following = asyncio.create_task(self._follow_up())  # and again while the guest gets round to it
        if verb in ("start", "stop"):
            await self._carried_out(verb, said, began)

    async def _carried_out(self, verb: str, upid: str, began: float) -> None:
        """Wait until the guest is seen running (or stopped, for `verb` "stop"): only then was the command carried out.

        Meanwhile Proxmox's task for it (`upid`, what the command was answered with) is asked how it stands. One that ended
        in an error is said at once, in Proxmox's words. One that still runs is waited for up to TASK_WITHIN, as is a command
        handed to Proxmox's high availability (its own task, "hastart" or "hastop", ends at once, and the guest is started or
        stopped by it a while later); after that it is said to be still under way (code "timeout": it may yet be done, and the
        history keeps that nobody knows), never that it failed. One that ended well, the guest still not seen so
        CONFIRM_WITHIN after it was seen to end, was not carried out (from then, not from the press: the guest is read
        before the task, and a task that ends between the two reads, its guest started with it, was taken for one whose
        guest did not start). Where how the task stands cannot be read, nothing is said of the task.

        All of it counts from the press (`began`, taken before the first question the command was decided by), and no read
        in it is waited for past TASK_WITHIN and CONFIRM_WITHIN from there (as far as `bounded` lets a request be held to a
        moment: never less than getting a connection may take): counted from here, a Proxmox slow to answer those first
        questions, or the reads in the wait, kept the button past the page's patience for it (ACTION_PATIENCE).
        """
        ended_at = began  # (the task's end, once it is seen; the press until then)
        until = began + TASK_WITHIN + CONFIRM_WITHIN
        seen_was = False  # a read since the task's end (or the press) found the guest as it was: what "not carried out" rests on
        wanted, was = ("running", "stopped") if verb == "start" else ("stopped", "running")
        handed = (upid.split(":")[5:6] or [""])[0].startswith("ha")
        task: str | None = None  # TASK_RUNS, TASK_OK, or Proxmox's words for how it ended; None while not known
        while True:
            try:
                found = await self._guest("GET", "status/current", "look at this guest", urgent=True, until=until)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    raise RETIRED.with_traceback(None) from None  # (whether it was carried out was not seen, and that is what is said)
                found = None
            status = found.get("status") if isinstance(found, dict) else None
            if status == wanted:
                return
            seen_was = seen_was or status == was
            if task in (None, TASK_RUNS):
                task = await self._task(upid, until) or task  # (a read that fails says nothing: what was known stands)
                if task not in (None, TASK_RUNS):
                    ended_at, seen_was = time.monotonic(), False
            if task not in (None, TASK_RUNS, TASK_OK):
                raise KvmError("action_failed", f"Proxmox could not {verb} the guest: {task}")
            now = time.monotonic()
            waited, since_end = now - began, now - ended_at
            if task == TASK_RUNS or handed:
                over = waited >= TASK_WITHIN
            else:
                # (From the task's end, or the press where that is not known; and never past one cap from the press, so that a
                # Proxmox slow to answer cannot keep the button past the page's patience for it.)
                over = since_end >= CONFIRM_WITHIN or waited >= TASK_WITHIN + CONFIRM_WITHIN
            if over:
                seconds = round(waited)
                if task == TASK_RUNS:
                    raise KvmError("timeout", f"Proxmox's task for the command is still running after {seconds} seconds, and the guest is not {wanted} yet. Look at it in a moment before trying again.", 504)
                if handed:
                    raise KvmError("timeout", f"Proxmox handed the command to its high availability, and the guest is not {wanted} after {seconds} seconds. Look at it in a moment before trying again.", 504)
                if task is None:
                    raise KvmError("timeout", f"The guest is still {was} after {seconds} seconds, and Proxmox did not say how its task went. Look at it before trying again.", 504)
                if not seen_was:
                    raise KvmError("timeout", "Proxmox's task for the command ended well, and how the guest is could not be read since. Look at it before trying again.", 504)
                if since_end < CONFIRM_WITHIN:
                    raise KvmError("timeout", f"Proxmox's task for the command ended well, and the guest is not {wanted} yet after {seconds} seconds. Look at it in a moment before trying again.", 504)
                raise KvmError("action_failed", f"Proxmox took the command, but the guest is still {was}. It was not carried out.")
            await asyncio.sleep(CONFIRM_EVERY)

    async def _task(self, upid: str, until: float | None = None) -> str | None:
        """How a task of Proxmox's stands: TASK_RUNS; TASK_OK, once it ended well; Proxmox's words, where it ended otherwise.
        None where that could not be read (the token may not, a moment of Proxmox's): no verdict either way. Asked of the
        node that runs it, which its name says (UPID:<node>:...); answered by `until` (see `_call`)."""
        node = (upid.split(":")[1:2] or [""])[0]
        if not NODE.fullmatch(node):
            return None
        try:
            reply = await self._call("GET", f"/nodes/{node}/tasks/{quote(upid, safe='')}/status", urgent=True, vital=False, until=until)
            said = data_of(reply, "say how its task went")
        except KvmError as ex:
            if ex is RETIRED or self._closed:
                raise RETIRED.with_traceback(None) from None
            return None
        if not isinstance(said, dict):
            return None
        if said.get("status") == TASK_RUNS:
            return TASK_RUNS
        ended = plain(said.get("exitstatus"), 200) if said.get("status") == "stopped" else None
        return TASK_OK if ended is not None and TASK_WARNED.fullmatch(ended) else ended

    async def _follow_up(self) -> None:
        waited = 0.0
        for moment in FOLLOW_UP:
            await asyncio.sleep(moment - waited)
            waited = moment
            if self._closed:
                return
            self._status_at = 0.0
            self._refresh_soon()


async def guests(base_url: str, username: str, password: str, *, typed: bool, tls: str = "pinned", cert_pem: str | None = None) -> tuple[list[dict[str, Any]], int, str | None]:
    """The virtual machines a token may see on a Proxmox, for somebody adding them: (guests, containers left out, the
    certificate it showed: remembered on this first contact, for this call alone). Each guest: vmid, node, name,
    status, and `url`, its address as the wall keeps it. `typed`: a person typed the token just now, and it is tried
    whatever was said to it before (as a password typed for a device is). KvmError where Proxmox does not list them."""
    found = address_of(base_url)
    spec = DeviceSpec(id="", name="", base_url=found.origin, username=username, password=password, tls=tls, cert_pem=cert_pem, kind="proxmox")
    if typed:
        REJECTED.forget(spec)
    asker = ProxmoxGuest(spec)
    try:
        listed, containers = await asker.listing()
    finally:
        await asker.close()
    for guest in listed:
        guest["url"] = guest_url(found.origin, guest["node"], guest["vmid"])
    return listed, containers, spec.cert_pem
