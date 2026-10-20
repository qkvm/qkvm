"""Client for a business PC with Intel AMT (vPro Enterprise), over WS-Management.

Intel's management engine sits beside the processor of a vPro PC and answers while the computer is
off, asleep or hung. It speaks WS-Management: SOAP over HTTP, on port 16992 plain and 16993 with TLS,
signed in to with HTTP Digest. What it gives the wall in this version is whether the PC is on, off,
asleep or hibernating, what the PC is (make, model, serial number, processor, memory, firmware), whether
its KVM could be used, in which control mode it was set up, and the power buttons.

No picture yet. Intel's KVM is RFB behind a handshake of its own, on the redirection ports (16994 and
16995), and a PC set up in client control mode shows a six-digit consent code on its own screen for
every session, which a wall that only looks can never type. The picture is the next phase, for PCs in
admin control mode, and needs a real machine to be tried on; this phase was built from Intel's published
class reference and has not met one.

Everything the machine says is taken by kind, with a size limit and a time limit on every read: what
answers at that address may be no management engine at all.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import ssl
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

import httpx

from . import rfb
from .kvm import (
    ABOUT_TTL,
    DOWN_CODES,
    KEEPALIVE_IDLE,
    MAX_PROBE,
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
    bounded,
    can_do,
    listens,
    pinned_context,
    plain,
    sign_in_waits,
    stopped,
    system_context,
    unverified_context,
    went_out,
)
from .redfish import named
from .vncdevice import BAD_HOLD, CONNECT_WAIT, VncDevice

log = logging.getLogger("qkvm")

WSMAN = "/wsman"  # where the management engine listens for WS-Management, on either port
PORTS = (("https", 16993), ("http", 16992))  # where Intel AMT answers, the way that is preferred first
CONTENT_TYPE = "application/soap+xml; charset=utf-8"
# Bytes a SOAP answer may be: the largest a real question here brings back is a few kilobytes (the memory
# modules, the software versions), and what is read is parsed on the one thread there is.
MAX_SOAP = 128 * 1024
MAX_ITEMS = 64  # instances asked for in one Pull, and the most of one class that are gone through
MOST_PULLS = 8  # an enumeration that never says it is at its end is not followed for ever
LOOK_EVERY = 10.0  # seconds between looks: the engine is a small computer, and a PC's state changes slowly
# Seconds a look at how the KVM is set up (control mode, consent, switched on) is taken to hold: the owner's standard
# (2026-10-18), where it was 60. Consent is read at most that often; the engine enforces it itself, so where consent was
# switched on since the last look, at most a few short sessions are begun (the engine refuses or shows its code for them)
# until the next look re-reads it.
KVM_TTL = STANDARD_HOLD
LIVE_WAIT = 10.0  # seconds a live line, or keys from one, wait for the session to the screen to be open
# A tile that is only shown on the wall (not enlarged, not live) gets a still every so often, each a short session (so
# Intel's border is on the PC's monitor only for the seconds that takes): the owner's standard (2026-10-18). A live session
# is held only while the machine is enlarged or its live view is open (see AmtScreen).
STILL_EVERY = STANDARD_HOLD
TIMEOUT_SLACK = 5.0  # seconds before the engine's SessionTimeout at which a session that ends is taken to have ended at its time
BRIDGE = 20.0  # seconds after such an end during which the last picture stands in, while the next session opens
INPUT_AFTER = 0.5  # seconds after the RFB handshake before the engine is sent keys or the pointer (see AmtScreen.taking_input)
FOLLOW_UP = (2.0, 4.0, 6.0, 8.0, 11.0, 15.0)  # moments after a power command at which the PC is looked at again
HICCUP = 45.0  # a look that fails does not change what the tile says until the last good one is this old
RETRY_LOOK = 4.0
# A power command is answered "done" before the PC has moved. Intel says the change takes up to ten seconds:
# where it can be seen whether it was carried out (on, off), it is looked for, this long and this often.
CONFIRM_WITHIN = 25.0
CONFIRM_EVERY = 2.0
# A real engine (AMT 16) neither offered nor carried out these while a KVM session, or a serial console, was open (it answered 2):
# the power cut off and the power cycled. With the wall's own session closed for them, it listed them again about a second later.
OFFER_WAIT = 5.0
OFFER_EVERY = 0.5
# Seconds after a PC was seen to start (switched on, reset, cycled) during which a redirection port that does not answer is the
# engine being busy, and said so: a real one (AMT 16) answered no new KVM session in time until 27 to 37 s after power on,
# and its WS-Management questions timed out now and then meanwhile. (A session open before the start went on through it.)
STARTING = 90.0
# Times a command, or a read it is decided by, asks which PC answers before it goes (see AmtDevice._request and
# _bound_read): once where the nonce changed since the last question, once more after a no, once for a nonce that ran out.
MOST_ASKED = 3
TIMEOUT = "PT30S"  # how long the engine may take over a question, as the question says it
# What a tile says, and a power button or its screen is answered with, where the engine at its address is not that of the
# PC it was added for (see AmtDevice._same_machine).
ANOTHER_PC = (
    "Another PC answers at this address: its management engine gives another number for its PC (PlatformGUID) than the PC "
    "this tile was added for. Nothing is done to it: no power command, no key, no session to its screen. If it is this tile's PC now, edit the tile and type its password."
)
NO_NUMBER = (
    "The management engine at this address does not say which PC it is (PlatformGUID), and the PC this tile was added for did. "
    "Nothing is done to it: no power command, no key, no session to its screen. If it is this tile's PC now, edit the tile and type its password."
)

# --- the names things have on the wire ---------------------------------------------------------------
SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSMAN_NS = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
ENUMERATION = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
TRANSFER = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
CIM = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
AMT = "http://intel.com/wbem/wscim/1/amt-schema/1/"
IPS = "http://intel.com/wbem/wscim/1/ips-schema/1/"

POWER_SERVICE = CIM + "CIM_PowerManagementService"
POWER_STATE = CIM + "CIM_AssociatedPowerManagementService"
COMPUTER = CIM + "CIM_ComputerSystem"
CHASSIS = CIM + "CIM_Chassis"
BOARD = CIM + "CIM_Card"
PROCESSOR = CIM + "CIM_Processor"
MEMORY = CIM + "CIM_PhysicalMemory"
BIOS = CIM + "CIM_BIOSElement"
SOFTWARE = CIM + "CIM_SoftwareIdentity"
PACKAGE = CIM + "CIM_ComputerSystemPackage"
KVM_SAP = CIM + "CIM_KVMRedirectionSAP"
GENERAL = AMT + "AMT_GeneralSettings"
REDIRECTION = AMT + "AMT_RedirectionService"
KVM_SETTINGS = IPS + "IPS_KVMRedirectionSettingData"
OPT_IN = IPS + "IPS_OptInService"
SETUP = IPS + "IPS_HostBasedSetupService"

# What the engine says the PC's power is (CIM_AssociatedPowerManagementService.PowerState), and the power
# that may be asked for (CIM_PowerManagementService.RequestPowerStateChange), from Intel's class reference.
ON, SLEEP_LIGHT, SLEEP_DEEP, CYCLE, OFF_HARD, HIBERNATE, OFF, CYCLE_HARD, RESET, NMI = 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
OFF_GRACEFUL, OFF_HARD_GRACEFUL, RESET_GRACEFUL, CYCLE_GRACEFUL, CYCLE_HARD_GRACEFUL = 12, 13, 14, 15, 16
POWER_WORDS = {
    1: "Other", ON: "On", SLEEP_LIGHT: "Sleeping", SLEEP_DEEP: "Sleeping", CYCLE: "Power cycling", OFF_HARD: "Off",
    HIBERNATE: "Hibernating", OFF: "Off", CYCLE_HARD: "Power cycling", RESET: "Resetting", NMI: "Interrupted",
    OFF_GRACEFUL: "Shutting down", OFF_HARD_GRACEFUL: "Shutting down", RESET_GRACEFUL: "Restarting",
    CYCLE_GRACEFUL: "Restarting", CYCLE_HARD_GRACEFUL: "Restarting", 17: "Interrupted",
}  # fmt: skip
RUNNING = {ON, SLEEP_LIGHT, SLEEP_DEEP}  # the power is there (a PC asleep wakes by itself; one hibernating is off)
NOT_RUNNING = {OFF_HARD, HIBERNATE, OFF}
KVM_BARS = (CYCLE, OFF)  # not offered, nor done, while a KVM session is open (see OFFER_WAIT)
# What a power command answers (ReturnValue), from the class reference.
RETURNS = {
    0: "done", 1: "not supported", 2: "unknown error", 3: "it could not be completed in time", 4: "failed",
    5: "invalid parameter", 6: "in use", 9: "not a change the PC can make from the state it is in", 10: "the timeout parameter is not supported",
    11: "busy", 4096: "started", 4097: "not a change the PC can make from the state it is in", 4099: "busy",
}  # fmt: skip
# How the PC was set up (IPS_HostBasedSetupService.CurrentControlMode).
CONTROL = {0: "none", 1: "client", 2: "admin"}
CONTROL_WORDS = {"none": "not provisioned", "client": "client control mode", "admin": "admin control mode"}
# What CIM_KVMRedirectionSAP.EnabledState says on Intel AMT: 2 enabled with a session, 3 disabled, 6 enabled and idle.
KVM_ON = {2, 6}
CONSENT_ALL = 4294967295  # IPS_OptInService.OptInRequired: "All"; 1 is "KVM", 0 is "None"
# The properties of AMT_RedirectionService a Put gives back, in the order of the class reference.
REDIRECTION_PROPERTIES = ("CreationClassName", "ElementName", "EnabledState", "ListenerEnabled", "Name", "SystemCreationClassName", "SystemName")
# Processor families, by the number SMBIOS gives them (DMTF DSP0134, the Processor Family field): the ones
# a PC with Intel AMT, or a stand-in, is likely to say, written plainly. Others are said by their number.
FAMILIES = {
    11: "Intel Pentium", 12: "Pentium Pro", 13: "Pentium II", 14: "Pentium with MMX", 15: "Intel Celeron", 16: "Pentium II Xeon",
    17: "Pentium III", 20: "Intel Celeron M", 21: "Intel Pentium 4 HT", 22: "Intel processor", 40: "Intel Core Duo",
    41: "Intel Core Duo mobile", 42: "Intel Core Solo mobile", 43: "Intel Atom", 44: "Intel Core M", 45: "Intel Core m3",
    46: "Intel Core m5", 47: "Intel Core m7", 107: "AMD Zen", 131: "AMD Athlon 64", 132: "AMD Opteron", 133: "AMD Sempron",
    176: "Pentium III Xeon", 178: "Pentium III with SpeedStep", 180: "Pentium 4", 181: "Intel Xeon", 183: "Intel Xeon MP",
    187: "Intel Pentium M", 188: "Intel Celeron D", 189: "Intel Pentium D", 190: "Intel Pentium Extreme Edition",
    191: "Intel Core Solo", 193: "Intel Core 2 Duo", 194: "Intel Core 2 Solo", 195: "Intel Core 2 Extreme",
    196: "Intel Core 2 Quad", 197: "Intel Core 2 Extreme mobile", 198: "Intel Core 2 Duo mobile", 199: "Intel Core 2 Solo mobile",
    200: "Intel Core i7", 201: "Dual-Core Intel Celeron", 205: "Intel Core i5", 206: "Intel Core i3", 207: "Intel Core i9",
    214: "Multi-Core Intel Xeon", 215: "Dual-Core Intel Xeon 3xxx", 216: "Quad-Core Intel Xeon 3xxx", 218: "Dual-Core Intel Xeon 5xxx",
    219: "Quad-Core Intel Xeon 5xxx", 221: "Dual-Core Intel Xeon 7xxx", 222: "Quad-Core Intel Xeon 7xxx", 223: "Multi-Core Intel Xeon 7xxx",
    224: "Multi-Core Intel Xeon 3400",
}  # fmt: skip

# What the engine hands out to be sent back to it in a header (its realm, a nonce, an opaque): what may stand
# in a quoted string of a header, which is nothing that could end the header line or the quotes.
HANDED = re.compile(r"[\x20\x21\x23-\x5b\x5d-\x7e]{1,1024}")
# What the engine hands out to be sent back to it inside a message (an enumeration context).
CONTEXT = re.compile(r"[A-Za-z0-9+/=:._-]{1,256}")
# A user name as it may stand in the sign-in header; what cannot is not a user name any engine knows.
USERNAME = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{1,64}")
PLATFORM = re.compile(r"[0-9A-Fa-f]{32}")  # the number a PC gives for itself (CIM_ComputerSystemPackage.PlatformGUID)
SIGN = "active management technology"  # what the engine calls itself in the Server header of every answer
REALM = re.compile(r"Digest:[0-9A-Fa-f]{8,64}")  # ...and the shape of its sign-in realm
DIGESTS: dict[str, Callable[[bytes], Any]] = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}


# --- HTTP Digest, by hand ----------------------------------------------------------------------------
# The HTTP library has a Digest of its own. It is not used: it reads the whole of the 401 that carries the
# challenge, however large, before anything here could bound it; it answers a malformed challenge with an
# error of the library's own kind, which nobody who asked a PC whether it is on would think to catch; and
# nothing in it bounds what the challenge hands out to be sent back. This is the standard's few lines,
# bounded, with every outcome one of the kinds a sign-in has here: yes, no, or neither.


@dataclass(frozen=True)
class Challenge:
    """How the engine wants to be signed in to: what its 401 said (RFC 7616)."""

    realm: str
    nonce: str
    opaque: str | None
    algorithm: str  # "MD5", "MD5-sess", "SHA-256", "SHA-256-sess"
    qop: bool  # it wants "auth" (every engine does); False: the older form without it
    stale: bool  # the nonce ran out, the password was not judged: answer the new nonce and nothing is counted


_PAIR = re.compile(r'\s*([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.){0,1024})"|([^\s,"]{0,1024}))\s*(?:,|$)')


def challenge_from(headers: list[str]) -> Challenge | None:
    """The Digest challenge among what a 401 said; None where it offered none this program can answer.

    Bounded as the whole answer is: one that hands out a realm or a nonce that could not stand in a header,
    or wants a hash this program has not got, is "neither yes nor no", and is said to be that.
    """
    for header in headers:
        scheme, _, rest = header.strip().partition(" ")
        if scheme.lower() != "digest":
            continue
        fields: dict[str, str] = {}
        at = 0
        while at < len(rest):
            pair = _PAIR.match(rest, at)
            if pair is None:
                break  # (another challenge follows, or something that is none: what was read so far is the challenge)
            name, quoted, bare = pair.groups()
            fields.setdefault(name.lower(), re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else bare)
            at = pair.end()
        realm, nonce, opaque = fields.get("realm"), fields.get("nonce"), fields.get("opaque")
        algorithm = fields.get("algorithm", "MD5").upper()
        offered = {part.strip().lower() for part in fields.get("qop", "").split(",")}
        if not (realm and nonce) or not HANDED.fullmatch(realm) or not HANDED.fullmatch(nonce):
            return None
        if opaque is not None and not HANDED.fullmatch(opaque):
            return None
        if algorithm.removesuffix("-SESS") not in DIGESTS or (offered - {""} and "auth" not in offered):
            return None
        return Challenge(realm, nonce, opaque, algorithm, "auth" in offered, fields.get("stale", "").lower() == "true")
    return None


def answer_to(challenge: Challenge, count: int, username: str, password: str, method: str, uri: str, cnonce: str | None = None) -> str:
    """The Authorization header that answers `challenge` (RFC 7616, qop "auth"), `count` being the nonce's use.

    `cnonce`: this program's own nonce, made here unless a test brings the standard's own.
    """
    make = DIGESTS[challenge.algorithm.removesuffix("-SESS")]

    def digest(*parts: str) -> str:
        return str(make(":".join(parts).encode("utf-8", "surrogatepass")).hexdigest())

    nc, cnonce = f"{count:08x}", cnonce or secrets.token_hex(8)
    first = digest(username, challenge.realm, password)
    if challenge.algorithm.endswith("-SESS"):
        first = digest(first, challenge.nonce, cnonce)
    second = digest(method, uri)
    if challenge.qop:
        response = digest(first, challenge.nonce, nc, cnonce, "auth", second)
    else:
        response = digest(first, challenge.nonce, second)
    fields = [f'username="{username}"', f'realm="{challenge.realm}"', f'nonce="{challenge.nonce}"', f'uri="{uri}"', f'response="{response}"', f"algorithm={challenge.algorithm}"]
    if challenge.qop:
        fields += ["qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
    if challenge.opaque is not None:
        fields.append(f'opaque="{challenge.opaque}"')
    return "Digest " + ", ".join(fields)


# --- the redirection port: Intel's handshake, then the screen as RFB ---------------------------------
# The KVM is reached on the redirection port, which is 16995 with TLS beside 16993 and 16994 plain beside 16992 (and
# only there: see REDIRECTION_BESIDE), with a handshake of Intel's own: a session is asked for, the engine says
# which sign-ins it takes, Digest is answered for the same account and password as on WS-Management, and once
# the engine says yes the KVM is told to begin. From there on the bytes are RFB, which the shared reader takes
# (rfb.py). The message codes are those MeshCommander's published source sends (read to learn them, not
# copied). Every answer is read by kind, with a size limit and a time limit: what answers on that port may be
# no engine at all.
REDIRECTION_URI = "/RedirectionService"  # what the Digest of the redirection port is made over
START_KVM = bytes((0x10, 0x01, 0x00, 0x00)) + b"KVMR"  # "a redirection session, for the KVM"
STARTED, AUTHENTICATE, AUTHENTICATED, KVM_GOING, RECORDED = 0x11, 0x13, 0x14, 0x41, 0xF0
KVM_GO = bytes((0x40, 0, 0, 0, 0, 0, 0, 0))  # "the KVM may begin", said once the sign-in is taken
QUERY, DIGEST = 0, 4  # kinds of sign-in message: "which do you take", and Digest with qop and a cnonce
ACCEPTED, ASKING = 0, 1  # what the engine says to one: yes; or "not so" (with the challenge to answer, or a no)
IN_USE = 2  # what a real engine answered the start of a KVM session with while another viewer had one open
REDIRECTION_STEP = 8.0  # seconds each answer of the handshake has to come in
REDIRECTION_WITHIN = 30.0  # ...and the whole handshake (the sign-in's answer included, which an engine may hold back)
MOST_SIGN_IN_DATA = 1024  # bytes an answer to a sign-in message may carry: three short texts at the most
MOST_RECORDED = 4  # "this session is being recorded" bytes taken before the KVM begins, at the most
NC = "00000002"  # the nonce count of the redirection port's Digest, as MeshCommander sends it


# The redirection port beside each of the engine's own WS-Management ports. Beside any other port it is not known: a
# gateway that forwards a port of its own to 16993 says nothing of where it forwards 16995, and what listens at that port
# and two may be anything (the Digest sign-in, and then the keys, would go to it). (A stand-in of the tests adds its own.)
REDIRECTION_BESIDE = {16993: 16995, 16992: 16994}


def redirection_address(base_url: str) -> tuple[str, int, bool]:
    """(host, port, over TLS) of the redirection port of the engine at `base_url`: 16995 beside 16993, 16994 beside 16992.
    ValueError where the engine is reached at another port (a forwarded one; 443 or 80 for an address without a port)."""
    parts = urlsplit(base_url)
    tls = parts.scheme == "https"
    at = parts.port or (443 if tls else 80)
    port = REDIRECTION_BESIDE.get(at)
    if port is None:
        raise ValueError(f"no redirection port is known beside port {at}")
    return parts.hostname or "", port, tls


def redirection_unknown(base_url: str) -> str | None:
    """What the tile says where the engine's redirection port is not known (see REDIRECTION_BESIDE); None where it is."""
    try:
        redirection_address(base_url)
    except ValueError:
        try:
            at = urlsplit(base_url).port or (443 if base_url.startswith("https") else 80)
        except ValueError:
            at = 0
        return (
            f"Its screen comes through the engine's redirection port, which qKVM knows only beside the engine's own ports (16995 beside 16993, "
            f"16994 beside 16992), and this tile reaches the engine at port {at}. Forward the engine's ports as they are to see its screen here."
        )
    return None


def at_its_port(url: str) -> str:
    """An engine's address typed without a port, at the engine's own port: 16993 over TLS, 16992 plain (not 443 or 80)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{host}:{dict(PORTS)['https' if parts.scheme == 'https' else 'http']}"


async def redirection_tls(spec: DeviceSpec) -> ssl.SSLContext:
    """The engine's certificate as the tile remembered it on WS-Management's port (the engine shows the one on both)."""
    if spec.tls == "system":
        return await system_context()
    if spec.tls == "insecure":
        return unverified_context()
    if not spec.cert_pem:
        # Never remembered here: the tile does that on its own port, where the password is first offered.
        raise KvmError("no_stream", "The engine's certificate is not known yet", 503)
    try:
        return pinned_context(spec.cert_pem)
    except (ssl.SSLError, TypeError, ValueError):
        raise KvmError("cert_invalid", "The certificate saved for this device cannot be read. Look at its certificate and trust it again.") from None


def sign_in_message(kind: int, texts: list[bytes]) -> bytes:
    """A sign-in message of the redirection port: its kind, then texts, each with its length in the byte before it."""
    data = b"".join(bytes((len(text),)) + text for text in texts)
    return bytes((AUTHENTICATE, 0, 0, 0, kind)) + len(data).to_bytes(4, "little") + data


def texts_of(data: bytes, count: int) -> list[bytes]:
    """`count` texts out of what an answer carries, each with its length in the byte before it. RfbError where they are not all there."""
    found: list[bytes] = []
    at = 0
    for _ in range(count):
        if at >= len(data) or at + 1 + data[at] > len(data):
            raise rfb.RfbError(rfb.PROTOCOL, "the engine's answer to the sign-in is cut short")
        found.append(data[at + 1 : at + 1 + data[at]])
        at += 1 + data[at]
    return found


def redirection_digest(username: str, realm: str, password: str, nonce: str, cnonce: str) -> str:
    """The Digest response the redirection port wants: MD5, qop "auth", over POST and /RedirectionService (RFC 7616's own sums)."""

    def md5(text: str) -> str:
        return hashlib.md5(text.encode("utf-8", "surrogatepass")).hexdigest()

    return md5(f"{md5(f'{username}:{realm}:{password}')}:{nonce}:{NC}:{cnonce}:auth:{md5(f'POST:{REDIRECTION_URI}')}")


async def _sign_in_answer(stream: rfb.Stream, within: float) -> tuple[int, int, bytes]:
    """The engine's answer to a sign-in message: (what it says, of which kind, what it carries)."""
    head = await stream.read(9, within)
    if head[0] != AUTHENTICATED:
        raise rfb.RfbError(rfb.PROTOCOL, f"the engine's handshake went wrong: it said {head[0]:#04x} where its answer to the sign-in belongs")
    length = int.from_bytes(head[5:9], "little")
    if length > MOST_SIGN_IN_DATA:
        raise rfb.RfbError(rfb.LIMIT, f"the engine's answer to the sign-in says it is {length} bytes long, which no such answer is")
    return head[1], head[4], (await stream.read(length, within) if length else b"")


async def redirect(
    stream: rfb.Stream,
    username: str,
    password: str,
    before_password: Callable[[], Any],
    within: float = REDIRECTION_STEP,
    taken: Callable[[], Any] | None = None,
) -> None:
    """Intel's handshake on the redirection port, for the KVM, up to where RFB begins.

    rfb.RfbError says why it did not get there: PROTOCOL (what answers is not an engine's redirection port, or
    the handshake went another way than the engine's does), REFUSED (the engine does not start a KVM session
    just now, or answered the sign-in with neither yes nor no), AUTH (it said no to the password: only that),
    UNSUPPORTED (no Digest sign-in), LIMIT, TIMEOUT, CLOSED. `before_password` is told the moment before the
    answer made with the password goes out, and nothing of the password goes out before the engine asked; `taken`,
    the moment the engine says yes to it (whatever follows: the password was taken).
    """
    await signed_in(stream, START_KVM, ("its KVM", "a KVM session"), username, password, before_password, within, taken)
    await stream.write(KVM_GO)
    for _ in range(MOST_RECORDED + 1):
        first = (await stream.read(1, within))[0]
        if first != RECORDED:
            break
    if first != KVM_GOING:
        raise rfb.RfbError(rfb.PROTOCOL, f"the engine's handshake went wrong: it said {first:#04x} where the KVM begins")
    await stream.read(7, within)


async def signed_in(
    stream: rfb.Stream,
    start: bytes,
    words: tuple[str, str],
    username: str,
    password: str,
    before_password: Callable[[], Any],
    within: float = REDIRECTION_STEP,
    taken: Callable[[], Any] | None = None,
) -> None:
    """Intel's handshake on the redirection port up to the sign-in taken, for a session of the kind `start` asks for (the
    KVM, the serial console); `words`: what that is ("its KVM", "a KVM session"), for what is said when it is refused. The
    errors, `before_password` and `taken` are those of `redirect`."""
    user, uri = username.encode("utf-8"), REDIRECTION_URI.encode()
    if not user or len(user) > 255:
        raise rfb.RfbError(rfb.UNSUPPORTED, "the user name is not one the redirection port's sign-in can carry")  # (sent nothing)
    await stream.write(start)
    head = await stream.read(4, within)
    if head[0] != STARTED:
        raise rfb.RfbError(rfb.PROTOCOL, "what answers on the redirection port is not Intel AMT's redirection service")
    if head[1] == IN_USE:
        raise rfb.RfbError(rfb.REFUSED, f"another viewer has {words[0]}: the engine gives one session at a time")
    if head[1] != 0:
        raise rfb.RfbError(rfb.REFUSED, f"the engine does not start {words[1]} (it answers {head[1]})")
    rest = await stream.read(9, within)
    if rest[8]:
        await stream.read(rest[8], within)  # (what the maker of the PC adds to the answer: nothing this program reads)
    await stream.write(sign_in_message(QUERY, []))
    _, kind, offered = await _sign_in_answer(stream, within)
    if kind != QUERY:
        raise rfb.RfbError(rfb.PROTOCOL, "the engine answered which sign-ins it takes with another kind of answer")
    if DIGEST not in offered:
        kinds = ", ".join(str(one) for one in sorted(set(offered))) or "none"
        raise rfb.RfbError(rfb.UNSUPPORTED, f"the engine does not take a Digest sign-in on its redirection port (it offers {kinds})")
    # The name and where, and nothing else: the engine answers with its realm and a nonce, as a 401 does.
    await stream.write(sign_in_message(DIGEST, [user, b"", b"", uri, b"", b"", b"", b""]))
    said, kind, carried = await _sign_in_answer(stream, within)
    if kind != DIGEST or said != ASKING:
        raise rfb.RfbError(rfb.PROTOCOL, f"the engine did not ask for the password the way Digest does (it answered {said} of kind {kind})")
    realm, nonce, qop = (text.decode("latin-1") for text in texts_of(carried, 3))
    if not (HANDED.fullmatch(realm) and HANDED.fullmatch(nonce)):
        raise rfb.RfbError(rfb.PROTOCOL, "the engine's challenge holds what no challenge does")
    if "auth" not in {part.strip().lower() for part in qop.split(",")}:
        raise rfb.RfbError(rfb.UNSUPPORTED, "the engine wants a kind of Digest this program does not answer")
    cnonce = secrets.token_hex(16)
    response = redirection_digest(username, realm, password, nonce, cnonce)
    before_password()
    answer = [user, realm.encode("latin-1"), nonce.encode("latin-1"), uri, cnonce.encode(), NC.encode(), response.encode(), b"auth"]
    await stream.write(sign_in_message(DIGEST, answer))
    said, kind, _ = await _sign_in_answer(stream, within)
    if said == ASKING and kind == DIGEST:
        raise rfb.RfbError(rfb.AUTH, "the engine rejected the password")
    if said != ACCEPTED:
        raise rfb.RfbError(rfb.REFUSED, f"the engine answered the sign-in with {said}, which is neither yes nor no")
    if taken is not None:
        taken()


# --- SOAP, the few shapes WS-Management needs ------------------------------------------------------


def _envelope(action: str, resource: str, body: str, selectors: dict[str, str] | None = None) -> bytes:
    chosen = "".join(f'<w:Selector Name="{escape(name)}">{escape(value)}</w:Selector>' for name, value in (selectors or {}).items())
    return (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{SOAP}" xmlns:a="{ADDRESSING}" xmlns:w="{WSMAN_NS}">'
        f"<s:Header><a:Action s:mustUnderstand=\"true\">{action}</a:Action><a:To>{WSMAN}</a:To>"
        f"<w:ResourceURI>{resource}</w:ResourceURI><a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>"
        f"<a:ReplyTo><a:Address>{ANONYMOUS}</a:Address></a:ReplyTo><w:OperationTimeout>{TIMEOUT}</w:OperationTimeout>"
        f"{f'<w:SelectorSet>{chosen}</w:SelectorSet>' if chosen else ''}</s:Header>"
        f"<s:Body>{body}</s:Body></s:Envelope>"
    ).encode()


def get_of(resource: str, selectors: dict[str, str] | None = None) -> bytes:
    """The question "what is the one instance of this class" (a class with a single instance needs no selector on Intel AMT)."""
    return _envelope(TRANSFER + "/Get", resource, "", selectors)


def enumerate_of(resource: str) -> bytes:
    return _envelope(ENUMERATION + "/Enumerate", resource, f'<n:Enumerate xmlns:n="{ENUMERATION}"/>')


def pull_of(resource: str, context: str) -> bytes:
    body = f'<n:Pull xmlns:n="{ENUMERATION}"><n:EnumerationContext>{escape(context)}</n:EnumerationContext><n:MaxElements>{MAX_ITEMS}</n:MaxElements></n:Pull>'
    return _envelope(ENUMERATION + "/Pull", resource, body)


def power_change(state: int) -> bytes:
    """Ask the power management service for `state`, of the PC itself (the "ManagedSystem" computer system)."""
    body = (
        f'<r:RequestPowerStateChange_INPUT xmlns:r="{POWER_SERVICE}"><r:PowerState>{int(state)}</r:PowerState>'
        f"<r:ManagedElement><a:Address>{ANONYMOUS}</a:Address><a:ReferenceParameters><w:ResourceURI>{COMPUTER}</w:ResourceURI>"
        f'<w:SelectorSet><w:Selector Name="CreationClassName">CIM_ComputerSystem</w:Selector><w:Selector Name="Name">ManagedSystem</w:Selector>'
        f"</w:SelectorSet></a:ReferenceParameters></r:ManagedElement></r:RequestPowerStateChange_INPUT>"
    )
    return _envelope(POWER_SERVICE + "/RequestPowerStateChange", POWER_SERVICE, body)


def state_change(resource: str, state: int) -> bytes:
    """Ask a service that is the only one of its class (the KVM's access point) to be in `state`: 2 enabled, 3 disabled."""
    body = f'<r:RequestStateChange_INPUT xmlns:r="{resource}"><r:RequestedState>{int(state)}</r:RequestedState></r:RequestStateChange_INPUT>'
    return _envelope(resource + "/RequestStateChange", resource, body)


def put_of(resource: str, properties: list[tuple[str, str]]) -> bytes:
    """Have the one instance of a class hold these properties (a Put: what it is not given, it may lose; give it what it said)."""
    name = resource.rsplit("/", 1)[-1]
    held = "".join(f"<r:{key}>{escape(value)}</r:{key}>" for key, value in properties)
    return _envelope(TRANSFER + "/Put", resource, f'<r:{name} xmlns:r="{resource}">{held}</r:{name}>')


# --- starting into the BIOS setup (AMT_BootSettingData, CIM_BootService) --------------------------------
# Intel AMT SDK, the WS-Management class reference: AMT_BootCapabilities.BIOSSetup says the engine can do it;
# AMT_BootSettingData.BIOSSetup "Enters the CMOS Setup screen on the next boot cycle" (a boolean, Put-required,
# "can be true only when no boot source is set"); CIM_BootService.SetBootConfigRole with Role 1 (IsNextSingleUse)
# makes the settings take effect on the next power change, once; then the power is changed. DMTF's Boot Control
# profile (DSP1012) is the model SetBootConfigRole follows.
BOOT_CAPABILITIES = AMT + "AMT_BootCapabilities"
BOOT_SETTINGS = AMT + "AMT_BootSettingData"
BOOT_SERVICE = CIM + "CIM_BootService"
BOOT_CONFIG = CIM + "CIM_BootConfigSetting"
BOOT_CONFIG_INSTANCE = "Intel(r) AMT: Boot Configuration 0"  # the one boot configuration, by its InstanceID (SDK)
# The properties a Put of AMT_BootSettingData carries. A real AMT 16 board refused a Put that left any of these out ("the
# supplied SOAP violates the corresponding XML schema definition"), so every one of these the engine reported goes along.
# Every one but BIOSSetup is sent at its OWN safe value, not echoed as the engine gave it: so that starting into the setup
# carries out nothing another tool left armed without a role (an erase, a BIOS reset, a boot source, a password bypass).
# `BOOT_PUT_KEEP` are the identifiers, echoed as they are; `BOOT_PUT_NUMBERS` are the numbers, set to 0; the rest are
# booleans, set to false. (Assigning SecureErase is said to be an error from Release 20; such a board has not been met.)
BOOT_PUT_PROPERTIES = (
    "BIOSPause", "BIOSSetup", "BootMediaIndex", "ConfigurationDataReset", "ElementName", "EnforceSecureBoot",
    "FirmwareVerbosity", "ForcedProgressEvents", "IDERBootDevice", "InstanceID", "LockKeyboard", "LockPowerButton",
    "LockResetButton", "LockSleepButton", "OwningEntity", "PlatformErase", "ReflashBIOS", "SecureErase",
    "UefiBootNumberOfParams", "UseIDER", "UseSOL", "UseSafeMode", "UserPasswordBypass",
)  # fmt: skip
BOOT_PUT_KEEP = ("InstanceID", "ElementName", "OwningEntity")  # identifiers, echoed as the engine gave them
BOOT_PUT_NUMBERS = ("BootMediaIndex", "FirmwareVerbosity", "IDERBootDevice", "UefiBootNumberOfParams")  # set to 0
# A boot option that destroys data or resets the machine, which qKVM never arms: a Put is refused where one of these is
# already set (another tool is in the middle of arming it), rather than silently clearing or carrying it out.
# What Start into BIOS setup says where it would have cleared a BIOS setup boot that was armed before it was pressed (an
# earlier press, not booted since, or another tool): a press that did not go through leaves the PC as it found it.
ARMED_BEFORE = "the BIOS setup boot was armed already before this press, and is left armed as it was, so the next boot will land in the BIOS setup"
ARMED_BEFORE_MADE_NEXT = "the BIOS setup boot was armed already before this press, which made it the next boot; it is left so, and the next boot will land in the BIOS setup"
ARMED_BEFORE_MAYBE_NEXT = "the BIOS setup boot was armed already before this press, which may have made it the next boot; it is left so, and the next boot may land in the BIOS setup"
BOOT_DESTRUCTIVE = ("PlatformErase", "SecureErase", "ConfigurationDataReset", "ReflashBIOS", "UseIDER", "UserPasswordBypass")
# A Start into BIOS setup that has not come to its power command within this many seconds goes no further: nothing more is
# armed or sent, and what was armed is cleared again (whoever pressed may have stopped waiting; the page waits four minutes
# for this press). As over Redfish (redfish.SETUP_WITHIN). Looked at before each request that changes something, so nothing
# under way is cut off for it; a real engine armed it in a quarter of a second.
SETUP_WITHIN = 120.0


def boot_setting_put(settings: Fields, bios_setup: bool) -> bytes:
    """A Put of AMT_BootSettingData that arms (true) or clears (false) "start into the BIOS setup" on the next boot, with
    every other boot option at its own safe value (no boot source, no erase, no reset): see BOOT_PUT_PROPERTIES."""
    held: list[tuple[str, str]] = []
    for key in BOOT_PUT_PROPERTIES:
        if key == "BIOSSetup":
            held.append((key, "true" if bios_setup else "false"))
        elif key not in settings:
            continue  # (one the engine did not report is not sent: older firmware whose schema lacks it would refuse the Put)
        elif key in BOOT_PUT_KEEP:
            if isinstance(value := settings.get(key), str) and value:
                held.append((key, value))
        elif key in BOOT_PUT_NUMBERS:
            held.append((key, "0"))
        else:
            held.append((key, "false"))
    return put_of(BOOT_SETTINGS, held)


def set_boot_config_role(role: int) -> bytes:
    """CIM_BootService.SetBootConfigRole on the one boot configuration; Role 1 is IsNextSingleUse (the armed settings are
    used the next time the PC is powered, once, and then cleared). From Intel's AMT SDK and DMTF DSP1012."""
    body = (
        f'<r:SetBootConfigRole_INPUT xmlns:r="{BOOT_SERVICE}"><r:BootConfigSetting><a:Address>{ANONYMOUS}</a:Address>'
        f'<a:ReferenceParameters><w:ResourceURI>{BOOT_CONFIG}</w:ResourceURI>'
        f'<w:SelectorSet><w:Selector Name="InstanceID">{escape(BOOT_CONFIG_INSTANCE)}</w:Selector></w:SelectorSet>'
        f"</a:ReferenceParameters></r:BootConfigSetting><r:Role>{int(role)}</r:Role></r:SetBootConfigRole_INPUT>"
    )
    return _envelope(BOOT_SERVICE + "/SetBootConfigRole", BOOT_SERVICE, body)


Fields = dict[str, str | list[str]]


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def fields_of(element: ET.Element) -> Fields:
    """An instance as the engine wrote it, by the names of its properties: a text each, a list where a name repeats.

    Only the first few hundred children, and only what stands in each as text, cut short: a property that is
    itself a record (a reference to another instance) is "not said", and nothing here is walked without end.
    """
    found: Fields = {}
    for child in list(element)[:256]:
        name, text = local(child.tag), " ".join((child.text or "").split())[:512]
        if len(child):  # a record inside the record: its text is not what it says
            continue
        had = found.get(name)
        if had is None:
            found[name] = text
        elif isinstance(had, list):
            had.append(text)
        else:
            found[name] = [had, text]
    return found


def text_of(fields: Fields, name: str, limit: int = 80) -> str | None:
    """A property that is one text, as one short line; None where it is not said, or said more than once."""
    value = fields.get(name)
    return plain(value, limit) if isinstance(value, str) and value else None


def int_of(fields: Fields, name: str, low: int = 0, high: int = 2**32) -> int | None:
    """A property that is one whole number within `low` and `high`; None for anything else."""
    value = fields.get(name)
    if not isinstance(value, str) or not re.fullmatch(r"-?[0-9]{1,20}", value):
        return None
    number = int(value)
    return number if low <= number <= high else None


def ints_of(fields: Fields, name: str, low: int = 0, high: int = 2**32) -> list[int]:
    """A property that is a list of whole numbers (one is a list of one); what is not a number in range is left out."""
    value = fields.get(name)
    values = value if isinstance(value, list) else [value] if isinstance(value, str) else []
    return [int(one) for one in values[:MAX_ITEMS] if re.fullmatch(r"-?[0-9]{1,20}", one) and low <= int(one) <= high]


def bool_of(fields: Fields, name: str) -> bool | None:
    value = fields.get(name)
    said = value.strip().lower() if isinstance(value, str) else ""
    return True if said in ("true", "1") else False if said in ("false", "0") else None


PERHAPS_DONE = "The machine's answer to the command did not come back: it may have been done. Look at the PC before trying again."
UNREADABLE_ANSWER = "The machine's answer to the command could not be read: it may have been done. Look at the PC before trying again."


class PerhapsDone(KvmError):
    """A command whose answer did not come back: it went out, and may have been done (code "timeout")."""


class Fault(KvmError):
    """The engine answered a question with a SOAP fault: its words are in `message`, its kind in `subcode`."""

    def __init__(self, subcode: str, reason: str, status: int) -> None:
        super().__init__("bad_response", f"The machine answered: {reason or subcode or f'HTTP {status}'}")
        self.subcode = subcode  # "DestinationUnreachable": no such class on this machine; "AccessDenied": not for this account

    @property
    def no_such_thing(self) -> bool:
        return self.subcode in ("DestinationUnreachable", "InvalidResourceURI")

    @property
    def not_allowed(self) -> bool:
        """The account was let in and may not ask this (WS-Management's own word for it)."""
        return self.subcode == "AccessDenied"


def body_of(reply: httpx.Response) -> ET.Element:
    """The Body of a SOAP answer, or the error that it is none: a fault, something that is not XML, or not SOAP."""
    kind = reply.headers.get("content-type", "").split(";")[0].strip().lower()
    if kind not in ("application/soap+xml", "application/xml", "text/xml"):
        raise KvmError("bad_response", f"The machine answered with {plain(kind, 40) or 'no kind of content'} where SOAP was expected (HTTP {reply.status_code})")
    data = reply.content
    # No answer of an engine has a document type: one that brings its own is after the parser, not the wall
    # (a handful of entity declarations unfold to gigabytes in a parser that lets them). Looked for as the
    # bytes they are, which means the answer has to be in an encoding where they are those bytes: the parser
    # reads UTF-16 as well, by its first bytes, and there the same declarations would pass unseen.
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\0" in data[:4]:
        raise KvmError("bad_response", "The machine's answer is not written the way SOAP is")
    shouted = data.upper()
    if b"<!DOCTYPE" in shouted or b"<!ENTITY" in shouted:
        raise KvmError("bad_response", "The machine's answer declares a document type, which SOAP has no use for")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise KvmError("bad_response", f"The machine's answer is not SOAP (HTTP {reply.status_code})") from None
    body = root.find(f"{{{SOAP}}}Body") if root.tag == f"{{{SOAP}}}Envelope" else None
    if body is None:
        raise KvmError("bad_response", f"The machine's answer is not a SOAP envelope (HTTP {reply.status_code})")
    fault = body.find(f"{{{SOAP}}}Fault")
    if fault is not None or reply.status_code != 200:
        subcode = reason = ""
        if fault is not None:
            value = fault.find(f"{{{SOAP}}}Code/{{{SOAP}}}Subcode/{{{SOAP}}}Value")
            subcode = plain(local((value.text or "").strip().split(":")[-1]), 64) or "" if value is not None else ""
            text = fault.find(f"{{{SOAP}}}Reason/{{{SOAP}}}Text")
            reason = plain(text.text, 200) or "" if text is not None else ""
        raise Fault(subcode, reason, reply.status_code)
    return body


def _first_instance(body: ET.Element) -> ET.Element | None:
    children = list(body)
    return children[0] if children else None


def family_of(fields: Fields) -> str | None:
    """What a CIM_Processor instance says the processor is, in a few plain words."""
    family = int_of(fields, "Family", 1, 65535)
    if family == 1:
        name = text_of(fields, "OtherFamilyDescription", 60)
    elif family is not None:
        name = FAMILIES.get(family) or f"processor family {family}"
    else:
        name = None
    speed = int_of(fields, "MaxClockSpeed", 1, 100_000)
    if name and speed:
        return f"{name}, {speed / 1000:.1f} GHz" if speed >= 1000 else f"{name}, {speed} MHz"
    return name


def own_number(guid: str | None) -> str | None:
    """The number a PC gives for itself, as a mark to know it by; None where it gives none worth the name (all zeros, "0")."""
    if not guid or not PLATFORM.fullmatch(guid) or len(set(guid.lower())) < 4:
        return None
    return "amt:" + hashlib.sha256(guid.lower().encode()).hexdigest()[:32]


def looks_like_amt(reply: httpx.Response) -> bool:
    """Whether what answered is an Intel management engine, by what every answer of one carries: its name in the
    Server header, or its sign-in realm, which no other device writes that way."""
    if SIGN in reply.headers.get("server", "").lower():
        return True
    challenge = challenge_from(reply.headers.get_list("www-authenticate"))
    return challenge is not None and REALM.fullmatch(challenge.realm) is not None


async def what_answers(client: httpx.AsyncClient, base_url: str, within: float) -> str:
    """Ask, without a password, what is at `base_url`: "amt" (an Intel management engine), "other" (something
    that answers and is none), "unconnected" (no connection was made: refused, or a TLS handshake that failed,
    which the library says alike) or "silent" (no answer in time)."""
    answered = "silent"  # a connection that takes too long to make, or an answer that never comes
    try:
        reply = await bounded(client, client.build_request("GET", f"{base_url}{WSMAN}"), MAX_PROBE, within)
        answered = "amt" if looks_like_amt(reply) else "other"
    except httpx.ConnectError:
        # (The library says "all connection attempts failed" for a refusal, whatever the system said, and raises the same
        # for a TLS handshake that failed: which of the two it was is for whoever needs to know to ask; see `detect`.)
        answered = "unconnected"
    except (httpx.HTTPError, KvmError):
        pass
    return answered


async def detect(url: str, scheme_given: bool, port: int | None, within: float = 5.0) -> tuple[str, str] | None:
    """Whether an Intel AMT machine answers for the address somebody typed: ("amt", the address to use) or None.

    Typed with a port, it is asked at that port and nowhere else. Typed without one, it is asked on the two
    ports every engine listens on, TLS first. What answers only the plain way is taken that way where nothing
    was said about how it is to be talked to and the TLS port plainly refuses (nothing listens there: asked
    with a bare connection, as `kvm.listens` asks); where `https://` was typed, or something on the TLS port
    is merely slow (a device slow to wake is not "no device") or takes the connection and fails the TLS
    handshake (an engine with an old TLS stack, or busy while its PC starts), that is said, and the plain
    address is the person's to type. Taken the plain way, the password goes as an MD5 Digest on the wire,
    and the screen, the keys and the typed texts over the plain redirection port.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    if port is not None or parts.port is not None:
        candidates = [url]
    else:
        candidates = [f"{scheme}://{host}:{number}" for scheme, number in PORTS]
    # (A refusal takes two seconds to be heard on Windows: the connection is given four, as `listens` gives it.)
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(3.0, connect=4.0), trust_env=False) as client:
        answers = dict(zip(candidates, await asyncio.gather(*(what_answers(client, candidate, within) for candidate in candidates)), strict=True))
    found = [candidate for candidate, answered in answers.items() if answered == "amt"]
    if not found:
        return None
    chosen = found[0]
    if chosen.startswith("http://"):
        secure = next((candidate for candidate in candidates if candidate.startswith("https://")), None)
        if scheme_given and url.startswith("https://"):
            raise KvmError("plain_only", f"Nothing answers over TLS at this address, but an Intel AMT machine answers over plain HTTP. To add it that way, type {chosen}")
        # "Unconnected" is a refusal or a failed TLS handshake: only a refusal of the bare connection is nothing there.
        if secure is not None and (answers[secure] != "unconnected" or await listens(secure)):
            raise KvmError(
                "plain_only",
                f"An Intel AMT machine answers over plain HTTP at this address, and something on its TLS port did not answer in time or did not finish a TLS handshake. To add it the plain way, type {chosen}; for TLS, try again.",
            )
    return "amt", chosen


class AmtScreen(VncDevice):
    """The PC's screen through Intel AMT's own KVM: the redirection port, Intel's handshake on it, then RFB, read by the
    shared reader as a VNC server's screen is read (vncdevice.py does the rest: the session, its pace, its pictures).

    It belongs to the PC's tile (AmtDevice), which decides whether a session may be opened at all (the KVM switched
    on, admin control mode, no consent asked), and it shares the tile's address, account and password, its
    remembered certificate and the count of what the engine said to that password (kvm.REJECTED): a no on either
    port is counted for the password, and while it stands no new sign-in offers it on either (the WS-Management
    port's signed looks go on while the sign-in it has holds, as they do for its own no). What goes wrong with the
    screen alone (a session refused, a stream that is not RFB, another certificate on its port) stays the screen's,
    said on the tile, and the tile goes on saying how the PC is.

    A tile that is only shown on the wall gets a still every STILL_EVERY (each a short session: Intel's border is on the
    PC's own monitor only for the seconds that takes), plus one at once when the tile first appears and one after a power
    change is seen; between stills the cached one is handed out, with its age. A session is held open, and drawn at a
    viewer's pace, only while the machine is enlarged or its live view is open (`_is_live`): the border is there then, and
    not for a tile nobody is watching close up.
    """

    kind = "amt"
    THING = "the PC's screen"
    # Raw only, with the screen's size changes. Offered ZRLE (16) as well, a real engine packed one rectangle in thirteen
    # and the whole screen came no sooner (4.7 s against 4.8 s at 2560 by 1440): its own pace is what a picture takes.
    ENCODINGS = (rfb.RAW, rfb.DESKTOP_SIZE)
    PIXELS = rfb.RGB565  # (the engine resets the connection at any format of 32 bits)
    # Signed in to with Digest before RFB begins: RFB's None alone. What asks for VNC authentication after Intel's
    # handshake is answered nothing (its DES answer, keyed on the password, would hand out far more than the Digest does).
    SIGNS_IN = (rfb.SECURITY_NONE,)
    # Every session begins with a Digest sign-in: an engine that gives a picture and hangs up, every time, is asked less and
    # less often (a picture is no proof that it is well again; a session that lasted half a minute is).
    SETTLED_BY_A_FRAME = False
    GREETED_AS_38 = (b"RFB 004.000\n",)  # what the engine's KVM greets with (seen on a real one), speaking 3.8 after it
    LOOK_PACE = 1.0
    LIVE_PACE = 0.1
    LET_GO_AFTER = 60.0  # (the session is held only while live or input goes: see `_let_go_if_unwanted`)
    LOG_CONNECT = False  # (a short session again and again: a still every five minutes, a session per live view)
    STILL_EVERY = STILL_EVERY
    # A still waits this long for its session and its first frame: longer than the handshake's own budget
    # (REDIRECTION_WITHIN) and the connect, so a session that fails resolves itself (and resolves its sign-in count) rather
    # than being cut off part way through, which would leave the password held back and the failure uncounted.
    STILL_WAIT = REDIRECTION_WITHIN + CONNECT_WAIT + 3.0
    STILL_RETRY = BAD_HOLD  # seconds before a still that came to nothing is tried again, doubling up to STILL_EVERY

    def __init__(self, spec: DeviceSpec, checked: Callable[[], Awaitable[None]] | None = None) -> None:
        """`checked`: asked before each session is opened whether the engine at the address is that of the tile's PC (the
        tile's AmtDevice._same_machine): KvmError where it is not, or could not be told."""
        super().__init__(spec, None)  # (the certificate is the engine's, remembered by the tile on its first look)
        self._checked = checked
        self._live_at = float("-inf")
        # The engine's SessionTimeout (minutes), as the tile's last look found it. A real engine ended a session at
        # that time to the second although it was asked for a picture every second: such an end is no failure.
        self.timeout_minutes: int | None = None
        self._ran_out_at = float("-inf")  # when a session last ended at its time (the live view's bridge)
        self._live_last: Snapshot | None = None  # the last live picture, for the moments the next session takes (BRIDGE)
        self._still: Snapshot | None = None  # the last still handed out between stills (a tile that is only shown)
        self._still_at = float("-inf")  # when that still's session drew it
        self._tried_still_at = float("-inf")  # when a still was last attempted (paces retries of one that drew no frame)
        self._still_fails = 0  # stills that opened a session but drew no frame, in a row (reset by one that draws)
        self._refresh_still = False  # a power change was seen: take one at once (see `want_still`)
        self._taking: asyncio.Task[None] | None = None  # a still session in flight
        self._asking = False  # a session being opened is asking the tile which PC answers (see `_open`)

    async def close(self) -> None:
        await super().close()  # (closed first: nothing new is opened; the session the still used is stopped with it)
        await stopped([self._taking])  # (and the still itself, waited for: nothing of it runs on unowned)

    def tidy(self) -> None:
        super().tidy()
        if time.monotonic() - self._wanted_at > KEEPALIVE_IDLE:
            self._live_last = None

    def want_still(self) -> None:
        """Take a still at the next look (the PC's power was seen to change): one picture of what the screen shows now."""
        self._refresh_still = True

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """The PC's screen. Live (the machine enlarged, or its live view open): the session that is held, drawn at a
        viewer's pace, and the last picture for the seconds the next session takes after the engine ends one at its time.
        Only shown on the wall: a still every STILL_EVERY, each a short session; the cached one between them, with its age."""
        if self._is_live():
            self._looking()
            try:
                snap = await self._picture(width, fresh)
            except KvmError as ex:
                if ex.code == "no_stream" and self._live_last is not None and time.monotonic() - self._ran_out_at < BRIDGE:
                    return self._live_last
                raise
            self._live_last = self._still = snap
            self._still_at = time.monotonic()
            return snap
        return await self._a_still(width)

    async def _a_still(self, width: int) -> Snapshot:
        """The cached still (with its age); a fresh one, in the background, where one is due and may be taken now. The first
        look returns "no_stream" (the tile shows it is waking) and the still comes on a later look: so a request never waits
        out a whole still, which the page would give up on."""
        now = time.monotonic()
        due = self._still is None or self._refresh_still or now - self._still_at >= self.STILL_EVERY
        busy = self._taking is not None and not self._taking.done()
        # Not while a refusal or a port that is down stands (`_standing`); and, after stills that came to nothing in any way,
        # no sooner than a pause that grows to STILL_EVERY (counted from the end of the last one), so a tile that is only shown
        # costs a PC whose port is blocked, refused or slow a question and a connection now and then, not every few seconds.
        # A still due by the clock, by a power change or on first appearance is not held back by it where the last did not fail.
        hold = min(self.STILL_EVERY, self.STILL_RETRY * 2 ** min(self._still_fails - 1, 5)) if self._still_fails else 0.0
        if due and not busy and self._standing(now) is None and now - self._tried_still_at >= hold:
            self._tried_still_at = now  # (`_refresh_still` stays until a still is stored: a power change's still that fails is tried again)
            self._taking = asyncio.create_task(self._one_still(width))
        if self._still is None:
            raise KvmError("no_stream", f"Waiting for {self.THING}", 503)
        return replace(self._still, still=True)

    async def _one_still(self, width: int) -> None:
        """One short session: open, wait for a frame (STILL_WAIT, past the handshake's own budget so a failing session ends
        itself), make the still, and close so Intel's border on the PC goes. Run in the background by `_a_still`. A session
        that was open already (held for keys, say) gives its picture and is left as it was."""
        task, stored, begun = None, False, None
        # (A session of someone else's, open or being opened (keys, the large view), gives its picture and is left as it was.)
        opened_here = self._session is None or self._session.done.is_set()
        try:
            with self.inputting():  # keeps the short session from being let go before a frame (see base `_let_go_if_unwanted`)
                try:
                    client = await self.ready(self.STILL_WAIT)
                finally:
                    begun = self._task if opened_here else None  # (the session this still began, also where it gave up waiting for it)
                task = self._task  # (the handshake is done, its sign-in counted: cutting this off leaves nothing pending)
                if client.frames == 0 and await self.next_frame(0, self.STILL_WAIT) is None:
                    return  # (no frame in time: counted below)
                if client is not self._connected_or_none():
                    return  # (the session ended meanwhile: no new one is opened only for the picture)
                snap = await self._picture(width, None)
            self._still, self._still_at, self._still_fails, self._refresh_still = snap, time.monotonic(), 0, False
            stored = True
            # A picture from a session that is still up, closed by qKVM and not by the engine: the port is well again (no
            # session of a still lasts SETTLED, so this is where a run of failures ends, and the next outage is logged).
            self._settled()
        except (KvmError, rfb.RfbError):
            pass  # (a refusal, a rejected password or a port that is down: recorded by the session itself, and counted below)
        finally:
            self._tried_still_at = time.monotonic()  # (the pause after a still that came to nothing counts from its end)
            if not stored:
                # A still that came to nothing, in any way: paced by `_a_still`'s ladder as well as by what the session
                # recorded, lest a shown tile ask a blocked, refusing or slow port every few seconds.
                self._still_fails += 1
            # Close the short session it opened; not one that was open before it, nor one a live view or keys took over
            # while it ran, nor a different one.
            if opened_here and task is not None and task is self._task and not self._is_live() and not self._inputs:
                await stopped([task])
            elif begun is not None and begun is self._task and not begun.done() and not self._is_live() and not self._inputs:
                # It gave up waiting for the session it began, which is still being opened: Intel's border would come up on the
                # PC for a picture nobody takes, and stay for LET_GO_AFTER. Stopped now where nothing is under way that must
                # not be cut off; else (the question which PC answers on the tile's own connection, or a sign-in on its way,
                # which cut off would leave the password held back and the try uncounted) let go of the moment it is open.
                session = self._session
                if self._asking or (session is not None and session.mark is not None):
                    self._wanted_at = time.monotonic() - self.LET_GO_AFTER
                else:
                    await stopped([begun])

    def live_seen(self) -> None:
        """A live line asks for the screen now: the pace is a viewer's, and the session is held, for the next moments."""
        self._live_at = time.monotonic()
        self._looking()

    def _is_live(self) -> bool:
        return super()._is_live() or time.monotonic() - self._live_at < 2.0

    async def _open(self) -> rfb.Stream:
        """The redirection port, over TLS where the tile's address is, with Intel's handshake done: what follows is RFB."""
        session = self._session
        assert session is not None  # (_run is only ever started for the session that is self._session)
        if not self.spec.password:
            raise KvmError("no_password", "No password saved for this device")
        try:
            host, port, tls = redirection_address(self.spec.base_url)
        except ValueError:
            raise self._left_alone(KvmError("bad_response", redirection_unknown(self.spec.base_url) or "Its redirection port is not known")) from None
        if self._checked is not None:
            # Which PC the engine at this address is, asked afresh before anything goes to its redirection port: over plain
            # HTTP, or with its certificate not checked, another PC that took the address (a new lease) would be shown here,
            # and sent the keys typed into this tile. See AmtDevice._same_machine.
            self._asking = True  # (on the tile's own connection: not to be cut off, see `_one_still`)
            try:
                await self._checked()
            except KvmError as ex:
                if ex is RETIRED or ex.code == "another_machine" or ex.code in DOWN_CODES:
                    # (The tile says it, and opens no session meanwhile; or WS-Management's port failed, which the tile's own
                    # looks find out about, and which is no failure of the redirection port.)
                    raise ex.with_traceback(None) from None
                raise self._left_alone(KvmError("bad_response", f"Which PC answers at this address could not be read: {ex.message}"), most=BAD_HOLD) from None
            finally:
                self._asking = False
        context = await self._redirection_tls() if tls else None
        try:
            stream = await rfb.open_tcp(host, port, context, CONNECT_WAIT)
        except OSError as ex:
            raise self._failed(self._connect_error(ex, self.spec.tls)) from None
        offered = REJECTED.what("login", self.spec)

        def sending() -> None:
            # Asked again the moment before the answer goes out: the handshake takes seconds, and a no heard on the
            # WS-Management port meanwhile (or a sign-in of its under way) stands for this password here too.
            self._not_yet(offered, NO_SAID)
            session.mark = REJECTED.sent(offered)

        def taken() -> None:
            # The password was taken: that is the sign-in, whatever the handshake or RFB says after it.
            REJECTED.accepted(offered)
            session.mark = None

        try:
            async with asyncio.timeout(REDIRECTION_WITHIN):
                await redirect(stream, self.spec.username, self.spec.password, sending, taken=taken)
        except TimeoutError:
            await stream.close()
            raise rfb.RfbError(rfb.TIMEOUT, "the engine did not finish its handshake in time") from None
        except BaseException:
            await stream.close()
            raise
        return stream

    async def _redirection_tls(self) -> ssl.SSLContext:
        return await redirection_tls(self.spec)

    def _ended(self, session: Any, offered: str, ex: rfb.RfbError) -> KvmError:
        lasted = time.monotonic() - session.since
        if ex.code == rfb.CLOSED and session.client is not None and self.timeout_minutes and lasted >= 60 * self.timeout_minutes - TIMEOUT_SLACK:
            # The engine's own time for a session (SessionTimeout): nothing went wrong, and the next look opens another at once.
            self._ran_out_at = time.monotonic()
            log.info("%s: the engine ended the session to the PC's screen at its time (%d minutes); the next look opens another", self.label, self.timeout_minutes)
            return KvmError("no_stream", "Opening the PC's screen again", 503)
        if ex.code in (rfb.REFUSED, rfb.UNSUPPORTED) and session.mark is None:
            # Before the password went out (the engine would not start a session), or after it was taken (RFB said
            # no): the screen's matter, not the password's. Left alone for a while, and said on the tile: 15 s each time,
            # not doubling, since asking costs the engine nothing (another viewer gives the KVM back, and the screen is
            # wanted again then, on the tile, a live line and the keys alike).
            return self._left_alone(KvmError("bad_response", f"{self._the()} is not shown: {ex.message}"), most=BAD_HOLD)
        return super()._ended(session, offered, ex)

    async def let_go_key(self, usage: int) -> None:
        """A key let go of, on the session that is open; with none open, nothing (and none is opened for it). Never held
        back by the tile's gate: what went down on the PC comes up again whatever the tile has found out since."""
        client, keysym = self._connected_or_none(), rfb.keysym_for(usage)
        if client is not None and keysym is not None:
            try:
                await client.key(keysym, False)
            except rfb.RfbError:
                pass  # (the session is ending, and the engine lets go of what it held with it)

    async def let_go_pointer(self, x: int, y: int, buttons: int) -> None:
        """Buttons let go of, on the session that is open; as `let_go_key`."""
        client = self._connected_or_none()
        if client is not None:
            try:
                await client.pointer(x, y, buttons)
            except rfb.RfbError:
                pass

    def refused_now(self, starting: bool = False) -> str | None:
        """What a session was refused with a moment ago, while it stands (see VncDevice._left_alone), or the password the
        redirection port said no to; None where nothing stands. `starting`: the PC is starting (see STARTING)."""
        now = time.monotonic()
        if self._login_error is not None and now < self._login_retry_at:
            return f"Its redirection port does not take the saved password: {self._login_error.message}"
        if self._refusal is not None and now < self._refusal_until:
            return self._refusal.message
        # Its redirection port alone failing while the engine answers on its own: said where it is no moment of its (another
        # certificate there; or no answer, time after time), until it is time to ask again. Unsaid, the tile went on
        # promising a screen that never came.
        down = self._down_error
        certificate = down is not None and down.code in ("cert_mismatch", "cert_invalid")
        if down is not None and now < self._down_until and (certificate or self._failures >= 3):
            if starting and not certificate:
                # (A real engine answered no new session in time for the first half-minute of every start: no fault of the port's.)
                return "The PC is starting, and its engine is too busy for a KVM session meanwhile"
            return f"Its redirection port: {down.message}"
        return None

    def size(self) -> tuple[int, int] | None:
        """The screen's width and height, where a session has said them."""
        client = self._connected_or_none()
        return (client.width, client.height) if client is not None and client.width else None

    async def ready(self, within: float) -> rfb.Client:
        """The session's client, connecting where there is none, waited for up to `within` seconds. KvmError where none came."""
        try:
            return self._connected(urgent=True)
        except KvmError as ex:
            if ex.code != "no_stream" or self._session is None:
                raise
        session = self._session
        try:
            async with asyncio.timeout(within):  # (no waiting task is left behind when the time runs out, or the caller is stopped)
                await session.ready.wait()
        except TimeoutError:
            pass
        if session.error is not None:
            raise session.error.with_traceback(None)
        return self._connected(urgent=True)

    async def taking_input(self, within: float) -> rfb.Client:
        """The session's client, once the engine takes keys on it. A real one dropped keys sent 0.05 and 0.15 s after
        the RFB handshake and took those sent 0.3 s after it and later, with or without a request between (measured
        with a letter at each moment, typed into the PC): keys and the pointer wait INPUT_AFTER from the handshake."""
        deadline = time.monotonic() + within
        while True:
            client = await self.ready(max(0.1, deadline - time.monotonic()))
            wait = (self._heard_at or 0.0) + INPUT_AFTER - time.monotonic()  # (_heard_at: the moment the handshake ended)
            if wait > 0:
                await asyncio.sleep(wait)
            if client is self._connected_or_none():
                return client
            if time.monotonic() >= deadline:  # (the session ended meanwhile: the next one is waited for, within the time)
                raise KvmError("no_stream", f"Waiting for {self.THING}", 503)


class AmtDevice(Device):
    """A business PC with Intel AMT, over WS-Management."""

    kind = "amt"
    picture = False  # (a tile that says how the PC is; its screen, where it can be had, is said by the status: `screen`)
    # The power buttons, and on/off by what is wanted. A look adds the screen, keys and text, and the live line with
    # keyboard and mouse, where a session may be opened (see `_no_screen`).
    can = ("power", "reset", "power_state")

    def __init__(self, spec: DeviceSpec, on_pin: Any = None) -> None:
        super().__init__(spec, on_pin)
        self._screen = AmtScreen(spec, self._before_a_session)
        # Where the engine at the address is not that of the PC this tile was added for: what is said, until a look finds
        # the right one there again (see `_same_machine`). Nothing is sent to the PC meanwhile.
        self._other: KvmError | None = None
        self._realm_seen: str | None = None  # the realm of the last challenge the engine gave (see `_challenged`)
        # A challenge came in another realm since which PC answers was last asked: the next look asks it, strictly.
        self._unsure = False
        # The nonce under which the engine last said which PC it is, where that was this tile's PC: a command is signed with
        # no other (see `_request`).
        self._checked_nonce: str | None = None
        self._login_lock = asyncio.Lock()
        self._login_error: KvmError | None = None
        self._login_retry_at = 0.0
        self._challenge: Challenge | None = None  # how the engine wants to be signed in to, as it last said
        # How often each nonce was answered with (the last few): a nonce count is never used twice for one nonce, whichever
        # request signed it first (a command waits for its turn with the nonce it was bound to while a look's no brings another).
        self._counts: dict[str, int] = {}
        self._answered_under: str | None = None  # the nonce under which the engine gave the last answer that was no no
        # Held by a look while it reads, and by a command from the question which PC answers to its sending: no look spends
        # the nonce, or brings another, in between (an engine whose nonces last few uses would otherwise refuse every command).
        self._quiet = asyncio.Lock()
        self._commanded = 0  # counts the commands that went out: a look that one went out during is looked at again
        self._good_commanded = 0  # ...as it stood when the look began that `_good` is of (see HICCUP in `_read_status`)
        # Signed requests go out one at a time: each answers the nonce with a count one higher than the last,
        # and an engine that checks the counts (the standard lets it) would take two that crossed for a replay.
        self._turn = asyncio.Lock()
        # The realm the password was taken for, while it is; None where it is not known to be taken (never
        # yet, or refused since). Digest signs every request: this is what stands in for a session.
        self._token: str | None = None
        self._about: dict[str, Any] = {}  # what rarely changes: what the PC is, its firmware, its number
        self._about_at = 0.0
        self._kvm: dict[str, Any] = {}  # whether its KVM could be used, and how it was set up
        self._kvm_at = 0.0
        self._following: asyncio.Task[None] | None = None
        self._good: dict[str, Any] | None = None
        self._good_at = 0.0
        self._hiccup = False
        self._power_on: bool | None = None  # what the last look found: on, off, or between the two
        self._starting_at = float("-inf")  # when the PC was last seen to start (switched on, reset, cycled: see STARTING)

    async def close(self) -> None:
        if self._following is not None:
            self._following.cancel()
        await super().close()
        await self._screen.close()

    def tidy(self) -> None:
        self._screen.tidy()

    # --- signing in and asking ----------------------------------------------------

    def _signed(self, client: httpx.AsyncClient, envelope: bytes, challenge: Challenge, timeout: httpx.Timeout | None = None) -> httpx.Request:
        """A request that answers `challenge` with the saved password. (Sent while `_turn` is held: see there.)"""
        count = self._counts.pop(challenge.nonce, 0) + 1
        self._counts[challenge.nonce] = count
        while len(self._counts) > 8:
            del self._counts[next(iter(self._counts))]
        headers = {"Content-Type": CONTENT_TYPE, "Authorization": answer_to(challenge, count, self.spec.username, self.spec.password, "POST", WSMAN)}
        if timeout is not None:
            return client.build_request("POST", WSMAN, content=envelope, headers=headers, timeout=timeout)
        return client.build_request("POST", WSMAN, content=envelope, headers=headers)

    def _challenged(self, reply: httpx.Response) -> Challenge | None:
        """Note how the engine wants to be signed in to, from its 401; None where it did not say in a way this program answers."""
        challenge = challenge_from(reply.headers.get_list("www-authenticate"))
        if challenge is not None and (self._challenge is None or challenge.nonce != self._challenge.nonce):
            self._challenge = challenge
        if challenge is not None:
            if self._realm_seen is not None and challenge.realm != self._realm_seen:
                # Another realm than the engine had: perhaps another engine has the address now (a new lease), whether its
                # no was a plain one or said that a nonce ran out (as an engine says of one it never handed out). What the PC
                # is is read again at this look, not ten minutes later, and which PC answers asked strictly (`_unsure`).
                # (Not "0": the clock that never goes back counts from the computer's start, and for its first ten minutes 0
                # was "a moment ago".) A command needs none of this: see `_request`.
                self._about_at = float("-inf")
                self._unsure = True
            self._realm_seen = challenge.realm
        return challenge

    async def _login(self) -> str:
        """Have the password taken once: the first request that carries it is the sign-in.

        What comes back is the realm it was taken for. Every request after it carries the password again (that
        is what Digest is), and a no to any of them is a no to the password, paced as every driver paces one.
        """
        async with self._login_lock:
            if self._token:
                return self._token
            if self._login_error and time.monotonic() < self._login_retry_at:
                raise self._login_error.with_traceback(None)
            if not self.spec.password:
                raise KvmError("no_password", "No password saved for this device")
            if not USERNAME.fullmatch(self.spec.username):
                raise KvmError("invalid", "The user name holds characters a sign-in header cannot carry", 422)
            offered = REJECTED.what("login", self.spec)
            self._not_yet(offered, NO_SAID)
            client = await self._http()
            question = get_of(GENERAL)  # the smallest question there is, and one every account may ask
            if self._challenge is None:
                # Asked without the password first: the engine says how it wants to be signed in to (its realm,
                # a nonce). Nothing of the password is made before that is known.
                try:
                    asked = await self._send(client, client.build_request("POST", WSMAN, content=question, headers={"Content-Type": CONTENT_TYPE}), MAX_SOAP)
                except httpx.HTTPError as ex:
                    raise self._failed(_transport_error(ex, self.spec.tls)) from ex
                except KvmError as ex:
                    raise self._failed(ex) from None
                self._answered()
                if asked.status_code >= 500 or asked.status_code == 429:
                    # One of its moments, or too many asking: it has said neither what it is nor how it is to be
                    # signed in to. Asked again after a while, not at every look, and said as what it is: there,
                    # and not signing this program in just now.
                    raise self._neither_yes_nor_no(offered, KvmError("bad_response", f"The machine did not say whether it asks for a sign-in (HTTP {asked.status_code})"), NO_SAID)
                if asked.status_code != 401 or self._challenged(asked) is None:
                    # It answers a question that needs a sign-in without asking for one, or asks for one of
                    # another kind (Kerberos only, say): not something this program signs in to, and the
                    # password is not sent anywhere on the strength of it.
                    raise KvmError("bad_response", f"The machine does not ask for a Digest sign-in as Intel AMT does (HTTP {asked.status_code})")
            before = REJECTED.sent(offered)
            answered_stale = False
            while True:
                challenge = self._challenge
                assert challenge is not None
                try:
                    async with self._turn:
                        reply = await self._send(client, self._signed(client, question, challenge, sign_in_waits()), MAX_SOAP)
                except httpx.HTTPError as ex:
                    raise self._came_to_nothing(offered, _transport_error(ex, self.spec.tls), NO_SAID, before, went_out(ex)) from ex
                except KvmError as ex:
                    raise self._came_to_nothing(offered, ex, NO_SAID, before) from None
                self._answered()
                if reply.status_code != 401:
                    # Not a no. A yes is an answer in SOAP: the answer to the question, or the fault an engine
                    # gives an account that was let in and may not ask this (the sign-in is checked before the
                    # question is). Anything else is an answer this program makes nothing of, and no verdict
                    # on the password, which is then not offered again at every look (see Rejected.unanswered):
                    # taken for a yes, what answers every signed request with a fault of its own had a digest
                    # of the password at every look, where HTML got the wait.
                    try:
                        body_of(reply)
                    except Fault as ex:
                        if not ex.not_allowed:
                            raise self._neither_yes_nor_no(offered, ex, NO_SAID) from None
                    except KvmError as ex:
                        raise self._neither_yes_nor_no(offered, ex, NO_SAID) from None
                    break
                fresh = self._challenged(reply)
                if fresh is None:
                    # A no is said with a new challenge. Said without one it is an answer this program makes
                    # nothing of, and not a verdict on the password.
                    raise self._neither_yes_nor_no(offered, KvmError("bad_response", "The machine refused the sign-in without saying how it is to be signed in to (HTTP 401)"), NO_SAID)
                if fresh.stale and not answered_stale:
                    # The nonce had run out, and the engine says so (the standard's word for it): the password
                    # was not judged. Answered once more with the new nonce, and counted once. (An engine that
                    # restarted while a look was under way says no to the nonce it has forgotten: that no is
                    # met in _request, which keeps the new nonce and signs in again with it, at no cost.)
                    answered_stale = True
                    continue
                self._login_error = KvmError("auth_failed", NO_SAID)
                self._login_retry_at = time.monotonic() + REJECTED.said_no(offered)
                log.warning("%s: login rejected", self.label)
                raise self._login_error
            self._login_error = None
            REJECTED.accepted(offered)
            self._token = challenge.realm
            return self._token

    async def _request(
        self, envelope: bytes, *, urgent: bool = False, vital: bool = True, again: bool = True, still: Callable[[], bool] | None = None, command: bool = False
    ) -> ET.Element:
        """Ask the engine `envelope`, signed in, and hand back the Body of its answer.

        `urgent`, `vital` and `still` mean what they mean for a KVM (see KvmDevice._request). `again`: the
        question may be asked a second time on a connection the engine closed while it sat idle (a power
        command may not: it is not pressed twice). `command`: it changes something on the PC, and a connection
        that broke after it went out leaves it perhaps done, which is what is said (code "timeout"), never "failed".
        """
        if not urgent:
            self._check_backoff()

        def failed(error: KvmError) -> KvmError:
            return self._failed(error, in_passing=urgent) if vital else error

        retried = relogged = answered_stale = sent = False
        asked = 0
        while True:
            await self._login()
            challenge, client = self._challenge, await self._http()
            if challenge is None:
                raise RETIRED.with_traceback(None)  # (let in by one connection, asked over another: the tile asks again)
            if command and self.spec.machine and challenge.nonce != self._checked_nonce:
                # A command is signed only with the nonce under which the engine last said that it is this tile's PC. An
                # engine takes only nonces it handed out, so what takes the command is what was asked, however the address
                # changed hands meanwhile and whatever another engine says (a no, or that a nonce it never handed out ran
                # out, in its realm or in the PC's: with one realm and one password across a fleet nothing else in its
                # answers tells). Another nonce than that one (a question or a no meanwhile): asked again first.
                asked += 1
                if asked > MOST_ASKED:
                    raise KvmError("action_failed", f"{'It was not done' if sent else 'Nothing was sent'}: the engine at this address handed out new nonces while it was asked which PC it is, or refused the command. Try again.")
                await self._which_pc_before_a_command("It was not done" if sent else "Nothing was sent")
                continue
            going = False
            try:
                async with self._turn:
                    request = self._signed(client, envelope, challenge)
                    if still is not None and not still():
                        raise KvmError("stopped", "It was not done: whoever asked for it may no longer do that", 403)
                    if self._closed:
                        raise RETIRED.with_traceback(None)  # (retired before it went: nothing went out)
                    sent = sent or command
                    going = True
                    reply = await self._send(client, request, MAX_SOAP)
            except KvmError as ex:
                if command and going and (ex is RETIRED or ex.code in ("timeout", "dropped")):
                    # (The wall's own time for the whole answer ran out, the answer broke off, or the connection was taken away,
                    # after the command went on its way.)
                    raise failed(PerhapsDone("timeout", PERHAPS_DONE, 504)) from None
                raise failed(ex) from None
            except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as ex:
                if again and not retried:  # a connection the engine closed while it sat idle
                    retried = True
                    continue
                raise failed(self._perhaps_done(ex) if command and went_out(ex) else _transport_error(ex, self.spec.tls)) from ex
            except httpx.HTTPError as ex:
                raise failed(self._perhaps_done(ex) if command and went_out(ex) else _transport_error(ex, self.spec.tls)) from ex
            self._answered()
            if reply.status_code != 401:
                try:
                    body = body_of(reply)
                except KvmError as ex:
                    if command and not isinstance(ex, Fault) and not 400 <= reply.status_code < 500:
                        # The command went out and what came back cannot be read: it may have been done. (A SOAP fault, or a
                        # 4xx, is a no. Not counted as the engine being down: it answered.)
                        raise PerhapsDone("timeout", UNREADABLE_ANSWER, 504) from None
                    raise failed(ex) from None
                self._answered_under = challenge.nonce  # (read by whoever awaited this, before anything else runs)
                return body
            fresh = self._challenged(reply)
            if command and self.spec.machine:
                # A no to a command bound to a nonce: it was not done. However it is worded (a stale nonce, another engine's
                # no, a sign-in that ran out), it is answered by asking which PC answers again (above, counted), and never by
                # a sign-in of the command's own.
                if fresh is None:
                    raise failed(KvmError("action_failed", "It was not done: the machine refused the command without saying how it is to be signed in to"))
                self._checked_nonce = None
                continue
            if fresh is not None and fresh.stale and not answered_stale:
                answered_stale = True  # a nonce that ran out: the same question, with the new one
                continue
            if relogged:
                # It takes the password and refuses the request after. Every look ends up here: the password is
                # not sent again with each of them. No verdict on the password (it was just taken): held back as
                # a sign-in that came to nothing, beside the connections, so that one made anew knows it too.
                async with self._login_lock:
                    self._token = None
                    held = self._held_back(REJECTED.what("login", self.spec), KvmError("bad_response", "The machine takes the sign-in and refuses the request after it"), NO_SAID)
                raise held
            relogged = True
            self._token = None  # the password was changed on the machine, or the engine restarted: sign in once more, counted

    def _perhaps_done(self, ex: BaseException) -> KvmError:
        """What a command whose answer did not come back is: perhaps done (the page and the history say so, and a run over many
        machines does not press it again as one that failed)."""
        error = _transport_error(ex, self.spec.tls)
        if error.code in ("cert_mismatch", "cert_invalid"):
            return error
        return PerhapsDone("timeout", PERHAPS_DONE, 504)

    async def _get(self, resource: str, urgent: bool = False, vital: bool = True) -> Fields:
        """The one instance of a class, by its properties."""
        instance = _first_instance(await self._request(get_of(resource), urgent=urgent, vital=vital))
        if instance is None:
            raise KvmError("bad_response", f"The machine answered {local(resource)} with nothing")
        return fields_of(instance)

    async def _all(self, resource: str, urgent: bool = False, vital: bool = True) -> list[Fields]:
        """Every instance of a class, by their properties: enumerated and pulled, within limits."""
        opened = await self._request(enumerate_of(resource), urgent=urgent, vital=vital)
        context = opened.find(f"{{{ENUMERATION}}}EnumerateResponse/{{{ENUMERATION}}}EnumerationContext")
        handle = (context.text or "").strip() if context is not None else ""
        if not CONTEXT.fullmatch(handle):
            raise KvmError("bad_response", f"The machine began listing {local(resource)} without a handle this program can send back")
        found: list[Fields] = []
        for _ in range(MOST_PULLS):
            pulled = await self._request(pull_of(resource, handle), urgent=urgent, vital=vital)
            answer = pulled.find(f"{{{ENUMERATION}}}PullResponse")
            if answer is None:
                raise KvmError("bad_response", f"The machine did not answer the listing of {local(resource)} as one")
            items = answer.find(f"{{{ENUMERATION}}}Items")
            for item in list(items)[: MAX_ITEMS - len(found)] if items is not None else []:
                found.append(fields_of(item))
            if answer.find(f"{{{ENUMERATION}}}EndOfSequence") is not None or len(found) >= MAX_ITEMS:
                return found
            handed = answer.find(f"{{{ENUMERATION}}}EnumerationContext")
            handle = (handed.text or "").strip() if handed is not None else handle
            if not CONTEXT.fullmatch(handle):
                raise KvmError("bad_response", f"The machine went on listing {local(resource)} with a handle this program cannot send back")
        return found  # (the engine never said it was at the end: what was read is what there is)

    # --- what the wall asks ---------------------------------------------------------

    async def _read_power(self, urgent: bool = False) -> tuple[int, list[int]]:
        """What the engine says the PC's power is, and which powers it may be asked for ([]: it does not say)."""
        states = await self._all(POWER_STATE, urgent=urgent)
        power = int_of(states[0], "PowerState", 1, 65535) if states else None
        if power is None:
            raise KvmError("bad_response", "The machine does not say how its power is")
        return power, ints_of(states[0], "AvailableRequestedPowerStates", 1, 65535)

    @staticmethod
    def _passing(ex: KvmError) -> bool:
        """Whether an error at a detail is one of the PC's moments (True), or one that ends the look (down, not let in)."""
        return not (ex.code in DOWN_CODES or ex.code in ("auth_failed", "no_password", "no_sign_in") or ex is RETIRED)

    async def _detail(self, resource: str, urgent: bool) -> Fields:
        """A class with one instance that is a detail (the PC is there, it has just answered): what it says, or nothing.
        (A detail is read by a look, or by `identify`, with `_quiet` held for it alone: see `_read_status`.)"""
        try:
            async with self._quiet:
                return await self._get(resource, urgent, False)
        except KvmError as ex:
            if not self._passing(ex):
                raise
            return {}

    async def _details(self, resource: str, urgent: bool) -> list[Fields]:
        """A class with several instances that is a detail: what it says, or nothing. (With `_quiet` held: see `_detail`.)"""
        try:
            async with self._quiet:
                return await self._all(resource, urgent, False)
        except KvmError as ex:
            if not self._passing(ex):
                raise
            return []

    async def _first_of(self, resource: str, urgent: bool) -> Fields:
        found = await self._details(resource, urgent)
        return found[0] if found else {}

    async def _read_about(self, urgent: bool = False) -> dict[str, Any]:
        """What rarely changes: what the PC is, its firmware, its name and its number. Asked once in a while, not at every look."""
        if self._about and time.monotonic() - self._about_at < ABOUT_TTL:
            return self._about
        chassis = await self._first_of(CHASSIS, urgent)
        make, model = named(text_of(chassis, "Manufacturer", 60)), named(text_of(chassis, "Model", 60))
        serial = named(text_of(chassis, "SerialNumber", 60))
        if not (make and model):
            board = await self._first_of(BOARD, urgent)
            make, model = make or named(text_of(board, "Manufacturer", 60)), model or named(text_of(board, "Model", 60))
        processors = await self._details(PROCESSOR, urgent)
        processor = next((family_of(one) for one in processors if family_of(one)), None)
        memory = await self._details(MEMORY, urgent)
        bytes_fitted = sum(int_of(one, "Capacity", 0, 2**50) or 0 for one in memory)
        gib = round(bytes_fitted / 2**30, 1)
        bios = await self._first_of(BIOS, urgent)
        versions = await self._details(SOFTWARE, urgent)
        firmware = next((text_of(one, "VersionString", 40) for one in versions if text_of(one, "InstanceID", 40) == "AMT"), None)
        general = await self._detail(GENERAL, urgent)
        package = await self._first_of(PACKAGE, urgent)
        self._about = {
            "make": make,
            "model": model,
            "serial": serial,
            "processor": processor,
            "processors": len(processors) or None,
            "memory_gib": (int(gib) if gib == int(gib) else gib) if bytes_fitted else None,
            "bios": named(text_of(bios, "Version", 40)),
            "version": firmware,
            "hostname": named(text_of(general, "HostName", 60)),
            "ident": own_number(text_of(package, "PlatformGUID", 40)),
            # Whether the engine can start the PC into its BIOS setup (AMT_BootCapabilities.BIOSSetup): rarely changes.
            "boot_setup": bool_of(await self._detail(BOOT_CAPABILITIES, urgent), "BIOSSetup") is True,
        }
        self._about_at = time.monotonic()
        return self._about

    # --- which PC answers: the number it gives for itself, against the one remembered -------------------------------
    # Over plain HTTP (the usual setup of a PC without TLS), or with its certificate not checked, nothing else tells one
    # engine from another: with one MEBx password across a fleet, a PC that took the address after a new lease would be
    # switched off, reset and typed into from this tile. Pinned TLS tells them apart by the certificate; this does it for
    # every way, by the PlatformGUID the PC gave when it was added (DeviceSpec.machine, kept in the settings).

    async def _same_machine(self, urgent: bool, vital: bool = True) -> None:
        """Ask the engine afresh which PC it is, and judge that (`_judge`, strictly): asked before every power command,
        before the KVM is switched, before each session to the screen, and at every look while another PC answers.
        KvmError "another_machine" where it is another PC, or says none where one is remembered; the error of the asking
        where it could not be asked and one is remembered.

        An account not let read the hardware asset information is answered with a fault, and says no number. Where none is
        remembered, an answer that is none (a fault of the engine's own, what this program makes nothing of, no answer) is
        "no number" too: there is nothing to tell the engine apart from, and a PC whose engine cannot say it keeps its
        buttons and its screen, as before the number was asked for at all.

        Asked strictly at a look too after a challenge in another realm (`_unsure`). Notes the nonce its answer came under
        (`_checked_nonce`): a command, and the reads it is decided by, go only under that one (see `_request`)."""
        self._checked_nonce = None
        try:
            found = await self._all(PACKAGE, urgent, vital)
            nonce = self._answered_under  # (the nonce the answer with the number came under: nothing else ran since)
        except KvmError as ex:
            restricted = isinstance(ex, Fault) and (ex.not_allowed or ex.no_such_thing)
            if ex is RETIRED or (self.spec.machine and not restricted):
                raise
            found, nonce = [], None
        # (And the realm: `_judge` may wait for the number to be kept, and a challenge that comes meanwhile is no part of this.)
        realm = self._realm_seen
        await self._judge(own_number(text_of(found[0], "PlatformGUID", 40)) if found else None, strict=True)
        self._checked_nonce = nonce
        if self._realm_seen == realm:
            self._unsure = False

    async def _before_a_session(self) -> None:
        """Which PC answers, asked before a session to the screen is opened (see AmtScreen._open). Not counted as the tile's
        failure, nor as the redirection port's: a moment of WS-Management's port while the PC starts would hold the tile's
        looks back, and blame the other port; one session is opened at a time, so one such question is under way at a time.
        Not beside a look or a command either (`_quiet`)."""
        async with self._quiet:
            await self._same_machine(urgent=False, vital=False)

    async def _judge(self, seen: str | None, strict: bool) -> None:
        """Whether the engine that answers is that of the PC this tile was added for, by the number it gives for itself
        (`seen`, as own_number makes it; None: none said). Nothing where it is; KvmError "another_machine" where it is not.

        Where none is remembered (a tile saved before this was: added while the PC could not be reached, or taken from a
        file with no number), the first one seen is remembered from then on, and said in the log: trust on first use, as for
        a certificate. Where the engine says none, nothing is known: `strict` (before something is sent) refuses where one
        is remembered; a look that read none in passing (what the PC is, read now and then) judges nothing."""
        remembered = self.spec.machine
        if seen is None:
            if remembered and strict:
                raise self._another(NO_NUMBER)
            return
        if not remembered:
            self.spec.machine = seen
            log.info("%s: the PC at this address is known by the number it gives for itself from now on", self.label)
            if self.on_known is not None and not self._closed:
                await self.on_known("", seen)
            return
        if seen != remembered:
            raise self._another(ANOTHER_PC)
        if self._other is not None:
            log.info("%s: the PC this tile was added for answers at its address again", self.label)
            self._other = None

    def _another(self, words: str) -> KvmError:
        """Note that the engine at the address is not that of this tile's PC: what is said from now on, until it is again."""
        if self._other is None or self._other.message != words:
            log.warning("%s: %s", self.label, words)
            self._status_at = 0.0  # (the tile says it at the next look, not up to LOOK_EVERY later)
        self._other = KvmError("another_machine", words)
        # What was read of it is another PC's: none of it is kept, nor its power taken for this one's; and what this one's
        # tile last said is not said again for a look that fails meanwhile (HICCUP).
        self._about, self._about_at, self._kvm, self._kvm_at, self._power_on, self._good = {}, 0.0, {}, 0.0, None, None
        self._checked_nonce = None
        return self._other

    async def _read_kvm(self, urgent: bool = False) -> dict[str, Any]:
        """Whether the PC's KVM could be used, and in which control mode the PC was set up. Read again every KVM_TTL:
        what decides whether a session may be opened is not taken from an old look."""
        if self._kvm and time.monotonic() - self._kvm_at < KVM_TTL:
            return self._kvm
        mode = int_of(await self._detail(SETUP, urgent), "CurrentControlMode", 0, 255)
        control = CONTROL.get(mode) if mode is not None else None
        kvm: str | None = None
        consent: bool | None = None
        timeout: int | None = None
        listener: bool | None = None
        try:
            async with self._quiet:  # (see `_detail`)
                sap = await self._get(KVM_SAP, urgent, False)
            settings = await self._detail(KVM_SETTINGS, urgent)
            state = int_of(sap, "EnabledState", 0, 65535)
            if bool_of(settings, "EnabledByMEBx") is False:
                kvm = "mebx"  # switched off in the BIOS menu: nothing from the network switches it on
            elif state in KVM_ON:
                kvm = "enabled"
            elif state == 3:
                kvm = "disabled"
            consent = bool_of(settings, "OptInPolicy")
            timeout = int_of(settings, "SessionTimeout", 0, 255)  # minutes (0: none), after which the engine ends a session
        except Fault as ex:
            if ex.no_such_thing:
                kvm = "absent"  # vPro Essentials: the engine has no KVM at all
        except KvmError as ex:
            if not self._passing(ex):
                raise
        if kvm != "absent":
            required = int_of(await self._detail(OPT_IN, urgent), "OptInRequired", 0, CONSENT_ALL)
            if required is not None:
                consent = required != 0
            # The redirection ports are open only while this is on (Intel: "The listener must be enabled before a KVM session can be established").
            listener = bool_of(await self._detail(REDIRECTION, urgent), "ListenerEnabled")
        if control == "client":
            consent = True  # mandatory there, whatever the setting says: Intel's rule, not a choice
        self._kvm = {"control": control, "kvm": kvm, "consent": consent, "listener": listener, "session_timeout": timeout}
        self._kvm_at = time.monotonic()
        return self._kvm

    @staticmethod
    def why_no_screen(kvm: dict[str, Any]) -> str | None:
        """Why no session to the PC's screen is opened, as the tile says it; None where one may be.

        Only where everything is known to allow it: the KVM switched on, its listener too, admin control mode (or a mode
        that is not client control), and no consent asked for. A session that would show a consent code on the PC's own
        screen is not opened: the wall cannot type it, and the person at the PC would see a code appear for nothing.
        """
        state, consent, control = kvm.get("kvm"), kvm.get("consent"), kvm.get("control")
        if state == "absent":
            return "This PC has no KVM: it is vPro Essentials, which has none."
        if state == "mebx":
            return "Its KVM is switched off in the PC's MEBx, which only somebody at the PC can change (Ctrl+P as it starts)."
        if state == "disabled" or (state == "enabled" and kvm.get("listener") is False):
            return "Its KVM is switched off on its management engine. An admin can switch it on from this tile."
        if state is None:
            return "Whether its KVM can be used is not known."
        if control == "client":
            return "Needs the code shown on the PC for every session: in client control mode Intel AMT always asks for it, and a wall cannot type it. A PC set up in admin control mode, with user consent off, shows its screen here."
        if consent is not False:
            if consent is None:
                return "Whether a session needs the code shown on the PC is not known, so none is opened."
            return "Needs the code shown on the PC for every session, which a wall cannot type. Switch user consent off in the PC's MEBx to see its screen here."
        return None

    def _screen_now(self) -> str | None:
        """What stands against the PC's screen at this moment, from the last look: the reason, or None."""
        if self._other is not None:
            return self._other.message  # (also where a look under way read how another PC's KVM is set up)
        if not self._kvm:
            return "Looking at how its KVM is set up."
        return self.why_no_screen(self._kvm) or redirection_unknown(self.spec.base_url)

    @staticmethod
    def kvm_words(found: dict[str, Any]) -> str:
        kvm, consent = found.get("kvm"), found.get("consent")
        if kvm == "absent":
            return "KVM: not on this machine (Essentials)"
        if kvm == "mebx":
            return "KVM: disabled in the MEBx"
        if kvm == "disabled":
            return "KVM: disabled"
        if kvm == "enabled":
            return "KVM: enabled, " + ("consent required" if consent else "no consent needed" if consent is False else "consent not known")
        return "KVM: not known"

    async def identify(self) -> dict[str, Any]:
        await self._read_power(urgent=True)  # the one question every account can ask, and the proof that this is an engine with a PC behind it
        about = await self._read_about(urgent=True)
        # Added: the PC is remembered by its number from here on (the server keeps spec.machine with the tile). Edited: it is
        # the PC remembered, asked afresh, or the edit is refused (unless its password was typed, which takes the PC that
        # answers now: see the server's update_device).
        if self.spec.machine:
            await self._same_machine(urgent=True)
        else:
            await self._judge(about["ident"], strict=True)
        return {"model": " ".join(part for part in (about["make"], about["model"]) if part) or None, "version": about["version"], "hostname": about["hostname"], "ident": about["ident"]}

    def watched(self) -> None:
        """The action comes from this PC's large view or live view: a session is held for it (and opened before a power-on),
        whatever the page's own feed of pictures has asked lately (it asks nothing of a PC that is off)."""
        self._screen.live_seen()

    async def snapshot(self, width: int, fresh: float | None = None, big: bool = False) -> Snapshot:
        """The PC's screen, through its KVM: the first one asked for opens a session (see AmtScreen).

        `big` (the enlarged view): the large view is open, so a session is held for it (the live branch, not stills), and is
        noted even where the picture is not had. (The page asks no pictures of a PC that is off; an action from its large view
        says so itself: `watched`.) A tile that is only shown (no `big`) opens a session only for its stills."""
        if big:
            self._screen.live_seen()
        await self._screen_allowed()
        return await self._screen.snapshot(width, fresh)

    async def _screen_allowed(self) -> None:
        """Nothing, where the PC's screen may be had now; else the KvmError that says why not (the last look decides)."""
        if self._other is not None:
            raise self._other.with_traceback(None)  # (another PC answers at the address: see `_same_machine`)
        if self._status is None or not self._kvm:
            self._refresh_soon()
            raise KvmError("no_stream", "Looking at how its KVM is set up", 503)
        if self._status.get("state") not in ("online", "no_signal"):
            # Its engine is not there, or not itself (its certificate changed), or does not let qKVM in: nor is its KVM asked.
            said = self._status.get("error") or {}
            raise KvmError(str(said.get("code") or "unreachable"), str(said.get("message") or "Device is unreachable"))
        if self._power_on is False:
            raise KvmError("no_picture", "The PC is off", 404)
        why = self._screen_now()
        if why is not None:
            raise KvmError("no_picture", why, 404)

    # --- the live line (live.py): the screen at a viewer's pace, keys and the pointer through RFB ---------

    @property
    def console_readable(self) -> bool:
        """Whether its screen can be had, as far as the last look knows: what the live line asks before it begins."""
        return bool(self._kvm) and self._screen_now() is None and self._power_on is not False

    async def live_screen(self) -> tuple[int, int, int, bytearray]:
        """The PC's screen as it stands, for the live line: frames so far, width, height, three bytes a pixel."""
        await self._screen_allowed()
        self._screen.live_seen()
        client = await self._screen.ready(LIVE_WAIT)
        if client.frames == 0:
            await self._screen.next_frame(0, LIVE_WAIT)
        shown = self._screen.screen()
        if shown is None:
            raise KvmError("no_stream", "Waiting for the PC's screen", 503)
        return shown

    async def input_ready(self) -> None:
        """The session that keys and the pointer go through, open: KvmError where there is none to be had."""
        await self._screen_allowed()
        with self._screen.inputting():  # (somebody is at the PC's keyboard: the session is not let go of for nobody)
            await self._screen.taking_input(LIVE_WAIT)

    def screen_size(self) -> tuple[int, int] | None:
        return self._screen.size()

    async def press(self, usage: int, down: bool) -> None:
        """A key by its HID usage, through the KVM (see VncDevice.press). Where the engine ended its session a moment ago (at
        its own time, every few minutes), it waits for the next one: refused, the live line took the keyboard away. A key
        let go of goes to the session that is open, whatever the tile found since, and opens none (`let_go_key`)."""
        if not down:
            await self._screen.let_go_key(usage)
            return
        await self._screen_allowed()
        with self._screen.inputting():
            await self._screen.taking_input(LIVE_WAIT)
            await self._screen.press(usage, down)

    async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False) -> None:
        """The pointer at (x, y) of the PC's screen, with these buttons held (see VncDevice.pointer; and `press` for the wait).
        `letting_go`: a button let go of, which goes as a key let go of does (see `press`)."""
        if letting_go:
            await self._screen.let_go_pointer(x, y, buttons)
            return
        await self._screen_allowed()
        with self._screen.inputting():
            await self._screen.taking_input(LIVE_WAIT)
            await self._screen.pointer(x, y, buttons)

    def _saw_power(self, power: int) -> bool | None:
        """Note what a look at the PC's power found: on, off, or between the two (restarting, being cycled), which is not
        "off" to the wall (a PC that is off is there, and dark, as a server that is off is)."""
        on = True if power in RUNNING else False if power in NOT_RUNNING else None
        if on and self._power_on is False:
            self._starting_at = time.monotonic()  # (switched on at the PC, or by another: seen off, and now on)
        if on is not None and self._power_on is not None and on != self._power_on:
            self._screen.want_still()  # a power change: a still at the next look, to catch the PC starting or going dark
        self._power_on = on
        return on

    def _stale(self) -> bool:
        return self._status is None or time.monotonic() - self._status_at > (RETRY_LOOK if self._hiccup else LOOK_EVERY)

    async def _refresh_status(self) -> None:
        """The look, as every device's; looked at again at once where a command went out while it read (a few times at the
        most): what it read before the command (the power before a power cut, the KVM as it was before it was switched on) is
        not what the tile goes on saying, nor kept as how its KVM is set up for a minute."""
        for _ in range(3):
            commanded = self._commanded
            await super()._refresh_status()
            if self._commanded == commanded or self._closed:
                return
            self._kvm, self._kvm_at = {}, float("-inf")  # (meanwhile its screen is "looking at how its KVM is set up")
        self._status_at = 0.0  # (given up on: what it says is asked again at the next look, not ten seconds later)

    async def _read_status(self) -> dict[str, Any]:
        # Each read of a look holds `_quiet` by itself (its power with which PC answers, each detail of what the PC is and of
        # its KVM): never between a command and the question which PC answers before it, and a command waits for one read, not
        # for all of a look (up to some twenty questions, every ten minutes). A look that a command went out during is looked
        # at again at once (`_refresh_status`); another PC found meanwhile is said at the end of this one.
        commanded = self._commanded
        try:
            async with self._quiet:
                power, _ = await self._read_power()
                if self._other is not None or self._unsure:
                    # (Another PC answered: whether this one is back is asked afresh at every look. Or a challenge came in
                    # another realm: whether this is the PC is asked strictly, also of an engine that names no number.)
                    await self._same_machine(urgent=False)
                # Noted at once, and in the same hold, not once the rest of the look is in: a look that went on to ask more
                # ended after a power cut had been seen, and said the PC was on again (the next picture opened a session to a
                # PC that was off).
                on = self._saw_power(power)
            about = await self._read_about()
            await self._judge(about["ident"], strict=False)  # (read anew every ABOUT_TTL, and at once after a challenge in another realm)
            kvm = await self._read_kvm()
            if self._other is not None:
                # (Found meanwhile, by a button or the screen: what this look read may be the other PC's, and is forgotten.)
                raise self._another(self._other.message)
        except KvmError as ex:
            if ex.code == "another_machine":
                self._hiccup = False
                return {"state": "error", "error": ex.as_dict(), "kind": self.kind, "picture": False}
            if ex.code in ("auth_failed", "no_password", "no_sign_in", "bad_response"):
                async with self._quiet:  # (its unsigned question brings a new nonce, as any no does)
                    ex = await self._gone_meanwhile(WSMAN) or ex
            if ex.code in ("auth_failed", "no_password"):
                state = "auth"
            elif ex.code in ("cert_mismatch", "cert_invalid", "bad_response", "no_sign_in", "invalid"):
                state = "error"
            else:
                state = "offline"
            passing = state != "auth" and ex.code not in ("cert_mismatch", "cert_invalid")
            # (Not where a command went out since the good look began: it said the PC as it was before it.)
            if passing and self._good is not None and time.monotonic() - self._good_at < HICCUP and self._good_commanded == self._commanded:
                self._hiccup = True
                return self._good
            self._hiccup = False
            return {"state": state, "error": ex.as_dict(), "kind": self.kind, "picture": False}
        plain_http = self.spec.base_url.startswith("http://")
        # Its screen: where the KVM may be used (why_no_screen), unless the screen itself was refused a moment ago (an
        # engine that would not start a session, a stream that was no RFB), which is said until it is asked again.
        self._screen.timeout_minutes = kvm["session_timeout"]
        why = self.why_no_screen(kvm) or redirection_unknown(self.spec.base_url)
        refused = self._screen.refused_now(starting=time.monotonic() - self._starting_at < STARTING)
        if why is not None:
            how = ", ".join(part for part in (self.kvm_words(kvm), CONTROL_WORDS.get(kvm["control"] or ""), "over plain HTTP" if plain_http else "") if part)
            no_screen: str | None = f"{why} ({how})"
        else:
            no_screen = refused
        has_screen = on is not False and no_screen is None
        size = self._screen.size()
        found = {
            "state": "no_signal" if on is False else "online",
            "error": None,
            "kind": self.kind,
            "picture": False,
            "screen": has_screen,  # a picture of the PC's screen can be asked for (see `snapshot`); asked for, it may still not come
            # (With the screen: keys and text through the KVM, and the live line with keyboard and mouse.)
            "can": can_do(
                *self.can,
                *(("screen", "keys", "text", "live", "control") if has_screen else ()),
                *(("bios_setup",) if about.get("boot_setup") else ()),
            ),
            "video": {"signal": on, "width": size[0] if size else None, "height": size[1] if size else None, "fps": None},
            "usb": {"keyboard": None, "mouse": None},
            "atx": {"enabled": True, "power": on, "hdd": None},
            "health": {"temp": None, "cpu": None, "mem": None},
            "about": {"model": " ".join(part for part in (about["make"], about["model"]) if part) or None, "version": about["version"]},
            "ports": None,
            "console": False,
            "server": {
                "power": POWER_WORDS.get(power, f"Unknown ({power})"),
                "health": None,
                "processor": about["processor"],
                "processors": about["processors"],
                "memory_gib": about["memory_gib"],
                "temperatures": [],
                "fans": [],
                "unwell": [],
                "locator": None,
                "no_screen": no_screen,  # why its screen is not shown, where it is not (and the PC is not simply off)
                "rfb_console": None,  # (a server's OpenBMC console; the same record for every machine said as a server)
                "amt": {
                    "power": power,
                    "control": kvm["control"],
                    "kvm": kvm["kvm"],
                    "consent": kvm["consent"],
                    "listener": kvm["listener"],
                    "session_timeout": kvm["session_timeout"],
                    "make": about["make"],
                    "model": about["model"],
                    "serial": about["serial"],
                    "bios": about["bios"],
                    "plain": plain_http,
                },
            },
        }
        self._good, self._good_at, self._hiccup, self._good_commanded = found, time.monotonic(), False, commanded
        return found

    # --- the power buttons -----------------------------------------------------------

    async def act(self, action: str, *, mac: str = "", keys: str = "", text: str = "", port: int = 0, still: Callable[[], bool] | None = None) -> None:
        """What the wall's power buttons mean to a PC with Intel AMT:

        'power_on'        switch on; a PC that is on is left as it is (AlreadySo)
        'power_off'       ask the operating system to shut down (graceful, where the machine offers it); one that is off is left as it is
        'atx_power'       the power button: whichever of those two applies
        'atx_power_long'  hold the power button: off, now
        'atx_reset'       the reset button (or a power cycle, where no reset is offered)
        'bios_setup'      arm "start into the BIOS setup" once, then switch on (if off) or reset (if on)

        And through its KVM, where its screen can be had: 'keys', 'text', 'ctrl_alt_del', as for a VNC server.
        """
        if action == "reboot":
            raise KvmError("invalid", "The management engine of a PC with Intel AMT is not restarted from here", 422)
        if action in ("keys", "text", "ctrl_alt_del"):
            await self._screen_allowed()
            # Somebody is at the PC: a session opened for this is held while the keys go, and let go of a minute after the last.
            with self._screen.inputting():
                await self._screen.taking_input(LIVE_WAIT)
                await self._screen.act(action, keys=keys, text=text, still=still)
            self._screen.want_still()  # the keys likely changed the screen: a fresh still for a tile that is only shown
            return
        if action == "bios_setup":
            await self._boot_into_setup(still)
            return
        if action not in ("power_on", "power_off", "atx_power", "atx_power_long", "atx_reset"):
            raise KvmError("invalid", "A PC with Intel AMT cannot do that", 422)
        if action == "power_on" or (action == "atx_power" and self._power_on is False):
            await self._open_before_a_boot()
        async with self._quiet:  # (no look between the question which PC answers and the command: see _quiet)
            state, wanted = await self._decide_and_command(action, still)
        if state is None:
            # A real engine (AMT 16) neither offers nor carries out cutting the power, or cycling it, while a KVM session is open
            # (it answered 2, and did nothing). The wall's own session is closed for it, and none is opened until it is answered
            # and, for a power cut, the PC is seen off (one opened at once showed a black screen for the seconds that took).
            async with self._screen.no_session("Its power is being switched"):
                # Waited for where a session of the wall's was open a moment ago (the engine lists them again about a second
                # after); asked once where none was (another viewer's session is not the wall's to close).
                async with self._quiet:
                    state = await self._offered_after_the_session(wanted, OFFER_WAIT if self._screen.session_ended_within(OFFER_WAIT) else 0.0)
                    await self._power_command(state, still)
                await self._after_the_command(state)
            return
        await self._after_the_command(state)

    async def _open_before_a_boot(self) -> None:
        """Open a session to the screen before switching the PC on (or restarting it into the BIOS setup), so the start
        shows from the first moment: only where the large view or the live view is open (`_screen._is_live`). On a real PC a
        session opened after the press mostly did not get through until Windows had loaded, while one open before it showed
        the whole start; one opened for a tile that is only shown would draw Intel's border on the PC for a start nobody is
        watching. So where the large or live view is open, the press waits (up to LIVE_WAIT) for the session to open first,
        and where it is not, the press does not wait at all. Opened only where a session may be opened but for the PC's own
        power (not where consent or the KVM's setup would stop it, nor where another PC answers; W11b's open question 1)."""
        if self._other is not None or not self._screen._is_live():
            return
        if self._kvm and self.why_no_screen(self._kvm) is None:  # (everything but the PC's own power allows a session)
            self._screen.live_seen()
            try:
                await self._screen.ready(LIVE_WAIT)  # (held through the power change by the live view that is open)
            except KvmError:
                pass  # (none could be opened just now: the press does not wait on it)

    async def _boot_into_setup(self, still: Callable[[], bool] | None) -> None:
        """Start the PC into its BIOS setup, once: arm AMT_BootSettingData.BIOSSetup, make it the next boot
        (SetBootConfigRole IsNextSingleUse), then switch the PC on where it is off, or reset it where it is on. All bound to
        the nonce under which the engine last said it is this tile's PC (see `_request`), with no look in between (`_quiet`);
        the large view, where it is open, shows the setup screen from the start. A press that has not come to its power
        command within SETUP_WITHIN sends nothing more, and what it armed is cleared again (nothing under way is cut off)."""
        until = time.monotonic() + SETUP_WITHIN

        def in_time() -> bool:
            # Asked before each request that changes something: not after the press's time, nor once whoever pressed may no
            # longer do it.
            return time.monotonic() < until and (still is None or still())

        await self._open_before_a_boot()
        async with self._quiet:
            power, offered = await self._power_before(checked=True)
            caps = await self._bound_read(lambda: self._get(BOOT_CAPABILITIES, urgent=True))
            if bool_of(caps, "BIOSSetup") is not True:
                raise KvmError("invalid", "This PC's Intel AMT does not offer starting into its BIOS setup", 422)
            if power not in RUNNING and power not in NOT_RUNNING:
                # Between states (restarting, being cycled, shutting down), or a state that says nothing: neither "switch on"
                # nor "reset" is sure to be right.
                said = f"changing its state just now ({POWER_WORDS[power]})" if power in POWER_WORDS and power != 1 else f"in a power state qKVM does not know ({POWER_WORDS.get(power, power)})"
                raise KvmError("action_failed", f"Nothing was done: the PC is {said}. Try again in a moment.")
            running = power in RUNNING
            wanted = [RESET, CYCLE] if running else [ON]
            state = next((one for one in wanted if not offered or one in offered), None)
            if state is None:
                # Nothing is armed where it could not be carried out: the PC is left as it is.
                raise KvmError("action_failed", f"This machine does not offer {'a reset' if running else 'switching on'} from the state it is in")
            settings = await self._bound_read(lambda: self._get(BOOT_SETTINGS, urgent=True))
            armed = [key for key in BOOT_DESTRUCTIVE if bool_of(settings, key)]
            if armed:
                # Another tool is in the middle of arming an erase, a BIOS reset or the like: qKVM does not clear it nor
                # carry it out. Nothing has been sent.
                raise KvmError("action_failed", f"Nothing was done: a boot option that qKVM does not arm is already set on this PC ({', '.join(armed)}). Clear it first.", 409)
            armed_before = bool_of(settings, "BIOSSetup") is True  # (pressed before, and not booted since)
            step = "arm"
            sent = False
            try:
                try:
                    self._commanded += 1
                    sent = True  # (from here on, the boot may be armed)
                    # A Put answers with the instance it wrote, not a method's ReturnValue: a fault is raised by `_request`.
                    await self._request(boot_setting_put(settings, True), urgent=True, again=False, command=True, still=in_time)
                    step = "role"
                    self._commanded += 1
                    self._returned(await self._request(set_boot_config_role(1), urgent=True, again=False, command=True, still=in_time), "make the BIOS setup boot the next one")
                    step = "power"
                    await self._power_command(state, in_time)
                except KvmError as ex:
                    if ex.code == "stopped" and time.monotonic() >= until:
                        # Not sent: the press's time ran out before it. Said as that, not as a right that was lost; and what
                        # was armed is cleared below, as for a power change that did not go through.
                        if step == "arm":
                            raise KvmError("action_failed", f"Nothing was done: the engine took more than {SETUP_WITHIN:.0f} seconds.") from None
                        ex = KvmError("action_failed", f"the engine took more than {SETUP_WITHIN:.0f} seconds")
                    if step == "power" and (isinstance(ex, PerhapsDone) or (ex.code == "bad_response" and not isinstance(ex, Fault))):
                        # The power command went out and its answer did not come back, or could not be read: it may have been
                        # done, and the boot is armed. Not cleared (it may be what the PC is starting into now). (A SOAP fault is
                        # a no.)
                        raise KvmError("timeout", f"The BIOS setup boot is armed and the power change may or may not have gone through ({ex.message}). Look at the PC: if it did not restart, the next boot of any kind will land in the BIOS setup.", 504) from None
                    if step == "arm" and not (isinstance(ex, PerhapsDone) or (ex.code == "bad_response" and not isinstance(ex, Fault))):
                        # The Put was refused (a SOAP fault), or never went out (stopped, not reached, another PC, a nonce the
                        # engine handed out meanwhile): nothing was armed, and nothing of the PC's is changed. (One whose answer
                        # was lost or could not be read may have been taken: cleared below.)
                        raise
                    # Armed, or perhaps armed, and no power change went out, or it was refused for certain: cleared again, so no
                    # ordinary boot (an update at night, a crash) lands in the setup; and said.
                    what = "the power change did not go through" if step == "power" else "the boot could not be armed in full"
                    left = await self._clear_bios_setup(armed_before)
                    if left is None:
                        raise KvmError("action_failed", f"Nothing was done: {what} ({ex.message}); the BIOS setup boot was cleared again.") from None
                    if left == ARMED_BEFORE and step == "power":
                        # (The role, which makes it the next boot, went through: the PC is not quite as the press found it.)
                        raise KvmError("action_failed", f"The power change did not go through ({ex.message}); {ARMED_BEFORE_MADE_NEXT}.") from None
                    if left == ARMED_BEFORE and step == "role" and (isinstance(ex, PerhapsDone) or (ex.code == "bad_response" and not isinstance(ex, Fault))):
                        # (The role's answer was lost or could not be read: it may have gone through.)
                        raise KvmError("timeout", f"The BIOS setup boot could not be armed in full ({ex.message}); {ARMED_BEFORE_MAYBE_NEXT}.", 504) from None
                    if left == ARMED_BEFORE:
                        raise KvmError("action_failed", f"Nothing was done: {what} ({ex.message}); {left}.") from None
                    # (It may be armed: a "maybe", as every other, and so in the history; never the code of what failed before
                    # the clearing, which said "nothing was sent" of a tile changed meanwhile, or "failed".)
                    raise KvmError("timeout", f"The BIOS setup boot may be armed and {what} ({ex.message}); {left}.", 504) from None
            except asyncio.CancelledError:
                if sent:
                    # qKVM is being stopped (also while the boot was being cleared again): nothing is awaited here (it must not
                    # hold the stop up), and whoever reads the log learns what may be left on the PC.
                    log.warning("%s: stopped while starting into the BIOS setup: the BIOS setup boot may be armed for the next boot", self.label)
                raise
        try:
            await self._after_the_command(state)  # (switching on is waited for until seen)
        except KvmError as ex:
            # Taken, and not seen done (or the wait cut short): the PC may still start into its setup later, so the boot is
            # left armed (clearing it could race a slow start) and that is said.
            if ex is RETIRED:
                raise KvmError("timeout", "The PC was switched on and it was not seen to start, the tile being changed meanwhile: it may have been done. The BIOS setup boot stays armed for the PC's next start.", 504) from None
            raise KvmError(ex.code, f"{ex.message} The BIOS setup boot stays armed for the PC's next start.", ex.status) from None

    async def _clear_bios_setup(self, armed_before: bool) -> str | None:
        """Best-effort: clear the BIOS setup boot just armed (after the power change was refused), under the same binding.
        None where it is known cleared (or shows not armed); else what is to be said of it. Not where it was armed already
        before this press (ARMED_BEFORE: it is left as it was), and not over a boot option that destroys data which another
        tool armed by the time of the read (the Put writes every option, and would clear that one too)."""
        if armed_before:
            return ARMED_BEFORE
        try:
            settings = await self._bound_read(lambda: self._get(BOOT_SETTINGS, urgent=True))
            if bool_of(settings, "BIOSSetup") is False:
                return None  # (not armed: the Put was not taken, or another tool cleared it)
            armed = [key for key in BOOT_DESTRUCTIVE if bool_of(settings, key)]
            if armed:
                return f"another tool armed a boot option meanwhile that qKVM does not write over ({', '.join(armed)}), so it was not cleared"
            self._commanded += 1
            # BIOSSetup back to false is enough: whatever role the configuration has, the next boot then starts as usual (every
            # other option is at its safe value). The role is not asked for again: it may be what was refused.
            await self._request(boot_setting_put(settings, False), urgent=True, again=False, command=True)
            return None
        except KvmError:
            return "it could not be cleared, so the next boot may land in the BIOS setup"

    async def _decide_and_command(self, action: str, still: Callable[[], bool] | None) -> tuple[int | None, list[int]]:
        """Which PC answers asked, its power read (under the same nonce), what to send decided, and sent: (the power state sent,
        what was wanted). (None, wanted) where the engine offers none of it while a KVM session is open: see `act`."""
        power, offered = await self._power_before(checked=True)
        running = power in RUNNING
        if action in ("power_on", "power_off") and running == (action == "power_on"):
            # Asked for by what is wanted, not by which button: after a power cut, the PCs ticked that came
            # back by themselves are not to be sorted out by hand first.
            raise AlreadySo("already on" if running else "already off")
        if action == "atx_reset" and power in NOT_RUNNING:
            # As for a guest of Proxmox: what is off is not reset. (Sent all the same where the engine lists nothing it offers;
            # and an engine that offered a power cycle there would switch the PC on for the reset button.)
            raise KvmError("action_failed", "The PC is off: there is nothing to reset")
        wanted = {
            "power_on": [ON],
            "power_off": [OFF_GRACEFUL],
            "atx_power": [OFF_GRACEFUL] if running else [ON],
            "atx_power_long": [OFF],
            "atx_reset": [RESET, CYCLE],
        }[action]
        state = next((one for one in wanted if not offered or one in offered), None)
        if state is None and running and any(one in KVM_BARS for one in wanted):
            return None, wanted  # (a KVM session stands in the way: see `act`)
        if state is None:
            # "Shut down nicely" is not on offer (no agent in the operating system to ask): pulling the plug is no substitute.
            raise KvmError("action_failed", f"This machine does not offer {POWER_WORDS[wanted[0]].lower()} ({wanted[0]}) from the state it is in")
        await self._power_command(state, still)
        return state, wanted

    async def _after_the_command(self, state: int) -> None:
        """The power command was taken: the tile looks again, and switching on or cutting the power is waited for until seen."""
        if state in (ON, RESET, CYCLE):
            self._starting_at = time.monotonic()
            self._screen.want_still()  # a start or restart: a fresh still, to catch the boot, even where on/off did not change
        self._status_at = 0.0  # what the tile says is out of date now,
        self._refresh_soon()  # and is read again without waiting to be asked,
        if self._following is not None:
            self._following.cancel()
        self._following = asyncio.create_task(self._follow_up())  # and again while the PC gets round to it
        if state in (ON, OFF):
            await self._carried_out(state == ON)

    async def _power_before(self, checked: bool = False) -> tuple[int, list[int]]:
        """The PC's power, and the powers offered, read before a power command goes out: KvmError, saying that nothing was sent,
        where they could not be read (a device being changed meanwhile would otherwise say "it may have been done").
        `checked`: and which PC the engine is, asked first (`_same_machine`): another one is sent nothing."""
        if checked:
            await self._which_pc_before_a_command()
        try:
            power, offered = await self._bound_read(lambda: self._read_power(urgent=True))
        except KvmError as ex:
            if ex.code == "another_machine":
                raise ex.with_traceback(None) from None
            raise self._nothing_sent(ex) from None
        self._saw_power(power)
        return power, offered

    async def _bound_read(self, read: Callable[[], Awaitable[Any]]) -> Any:
        """`read`, as one that decides what a command sends: taken where its answer came under the nonce under which the
        engine last said that it is this tile's PC, or where which PC answers, asked right after it, was answered under the
        read's own nonce (the engine that handed it out answered both); else read again (at most MOST_ASKED times). Else what
        it would tell might be another PC's (that it is on already, say), and decide for this one."""
        for _ in range(MOST_ASKED):
            found = await read()
            under = self._answered_under  # (the nonce of this answer: nothing else ran since)
            if not self.spec.machine or under == self._checked_nonce:
                return found
            await self._same_machine(urgent=True)
            if self._checked_nonce == under:
                # Asked under the nonce the read came under: the engine that handed it out answered both, and is this PC's.
                # (Read again instead, an engine whose nonces last a few uses was met each time with a nonce run out.)
                return found
        raise KvmError("bad_response", "The engine at this address handed out new nonces while it was asked which PC it is. Try again.")

    async def _which_pc_before_a_command(self, said: str = "Nothing was sent") -> None:
        """`_same_machine`, before a command goes out: KvmError "another_machine" as it is; any other beginning with `said`
        ("It was not done", where the command went out once and was answered with a no)."""
        try:
            await self._same_machine(urgent=True)
        except KvmError as ex:
            if ex.code == "another_machine":
                raise ex.with_traceback(None) from None
            raise self._nothing_sent(ex, said) from None

    def _nothing_sent(self, ex: KvmError, said: str = "Nothing was sent") -> KvmError:
        why = "it was being changed meanwhile" if ex is RETIRED or self._closed else ex.message[:1].lower() + ex.message[1:]
        return KvmError("action_failed", f"{said}: {why}")

    async def _offered_after_the_session(self, wanted: list[int], within: float) -> int:
        """The first of `wanted` the engine offers, asked again for up to `within` seconds once no KVM session of the wall's is
        open (a real one listed them again about a second after the session ended). KvmError where it does not (another
        viewer's session is not the wall's to close), and where the PC went off meanwhile (AlreadySo for a power cut)."""
        deadline = time.monotonic() + within
        while True:
            power, offered = await self._power_before()
            if power not in RUNNING:
                # Switched off meanwhile (at the PC, say): what was asked for is not what the PC needs now. (An engine that
                # offers a power cycle to a PC that is off would switch it on for the reset button.)
                if OFF in wanted:
                    raise AlreadySo("already off")
                raise KvmError("action_failed", "Nothing was sent: the PC went off meanwhile")
            state = next((one for one in wanted if not offered or one in offered), None)
            if state is not None:
                return state
            if time.monotonic() >= deadline:
                what = POWER_WORDS[wanted[0]].lower()
                raise KvmError("action_failed", f"This machine does not offer {what} ({wanted[0]}) just now. Intel AMT offers neither a power cut nor a power cycle while somebody has its KVM or its serial console open (Intel's own tools, say).")
            await asyncio.sleep(OFFER_EVERY)

    async def _power_command(self, state: int, still: Callable[[], bool] | None) -> None:
        """Ask the engine for power `state`, and take its answer: KvmError where it was not taken. (Signed only under the nonce
        of the last question which PC answers: see `_request`.)"""
        self._commanded += 1  # (a look under way meanwhile is looked at again: see `_refresh_status`)
        answer = await self._request(power_change(state), urgent=True, again=False, still=still, command=True)
        output = _first_instance(answer)
        returned = int_of(fields_of(output), "ReturnValue", 0, 2**32) if output is not None else None
        if returned is None:
            # Taken in, and answered with what says neither yes nor no: it may have been done (as an answer that did not come
            # back), never "failed", which a bulk run's "Retry failed" would press again.
            raise PerhapsDone("timeout", UNREADABLE_ANSWER, 504)
        if returned not in (0, 4096):
            raise KvmError("action_failed", f"The machine refused the power command: {RETURNS.get(returned, f'it answered {returned}')}")

    async def _carried_out(self, on: bool) -> None:
        """Wait until the PC is seen to be on (or off): only then was the command carried out (see CONFIRM_WITHIN)."""
        deadline = time.monotonic() + CONFIRM_WITHIN
        while True:
            try:
                power, _ = await self._read_power(urgent=True)
            except KvmError as ex:
                if ex is RETIRED or self._closed:
                    # The connection was taken away while this waited: whether it was carried out was not seen,
                    # and that is what is said, not "was not carried out".
                    raise RETIRED.with_traceback(None) from None
                power = None  # one of its moments: it is asked again
            if power is not None:
                self._saw_power(power)  # (a look at its power: no screen is asked of a PC seen off, until a look says otherwise)
            if (power in RUNNING) if on else (power in NOT_RUNNING):
                return
            if time.monotonic() >= deadline:
                still = "off" if on else "on"
                raise KvmError("action_failed", f"The machine took the command, but the PC is still {still}. It was not carried out.")
            await asyncio.sleep(CONFIRM_EVERY)

    # --- switching the KVM on from the network: only when an admin asks ---------------------------------

    async def switch_kvm(self, on: bool) -> None:
        """Switch the PC's KVM on (or off) on the engine, as Intel's reference does it: the KVM's access point to 2
        (or 3), then, switching on, the redirection listener on, which opens the redirection ports. A setting of the
        PC's, kept by its engine: changed here only because an admin asked for it (see the route), never by a look.

        KvmError where it cannot be: switched off in the MEBx (nothing from the network switches it on), not on this
        machine, or the engine refusing; or another PC at the address (`_same_machine`), which is changed nothing.
        """
        async with self._quiet:  # (no look between the question which PC answers and the writes: see _quiet)
            await self._switch_kvm(on)
        self._refresh_soon()

    async def _switch_kvm(self, on: bool) -> None:
        """`switch_kvm`, with no look in between (its writes are bound to the nonce of the question: see `_request`)."""
        try:
            await self._same_machine(urgent=True)
            settings = await self._bound_read(lambda: self._get(KVM_SETTINGS, urgent=True))
        except KvmError as ex:
            if ex.code == "another_machine":
                raise ex.with_traceback(None) from None
            raise self._nothing_sent(ex) from None
        if bool_of(settings, "EnabledByMEBx") is False:
            raise KvmError("invalid", "Its KVM is switched off in the PC's MEBx, which only somebody at the PC can change (Ctrl+P as it starts)", 422)
        self._commanded += 1  # (a look under way meanwhile is looked at again: see `_refresh_status`)
        self._returned(await self._request(state_change(KVM_SAP, 2 if on else 3), urgent=True, again=False, command=True), f"switch its KVM {'on' if on else 'off'}")
        self._kvm_at = float("-inf")  # (read again at the next look, whatever happens next; not "0": see `_login`)
        self._status_at = 0.0
        if on:
            try:
                service = await self._bound_read(lambda: self._get(REDIRECTION, urgent=True))
                if bool_of(service, "ListenerEnabled") is not True:
                    # Given back as it was read, with the listener on: a Put sets what it is given, and only these are the service's own.
                    kept = [(key, value) for key in REDIRECTION_PROPERTIES if isinstance(value := service.get(key), str)]
                    held = [(key, "true" if key == "ListenerEnabled" else value) for key, value in kept]
                    if not any(key == "ListenerEnabled" for key, _ in held):
                        held.append(("ListenerEnabled", "true"))
                    held.sort(key=lambda pair: REDIRECTION_PROPERTIES.index(pair[0]))
                    self._commanded += 1
                    answered = _first_instance(await self._request(put_of(REDIRECTION, held), urgent=True, again=False, command=True))
                    if answered is not None and bool_of(fields_of(answered), "ListenerEnabled") is False:
                        raise KvmError("action_failed", "the engine kept it switched off")
            except KvmError as ex:
                # Half done: whoever asked is told what was changed on the PC, and what was not (or is not known).
                retired = ex is RETIRED or self._closed
                said = "this tile was being changed meanwhile" if retired else ex.message[:1].lower() + ex.message[1:]
                if isinstance(ex, PerhapsDone):  # (the Put went on its way, and its answer did not come back)
                    raise KvmError("timeout", f"Its KVM was switched on on the engine, and whether its redirection listener was is not known: {said}", 504) from None
                if retired:
                    raise KvmError("action_failed", f"Its KVM was switched on on the engine, and its redirection listener was not: {said}") from None
                raise KvmError(ex.code, f"Its KVM was switched on on the engine, and its redirection listener was not: {said}", ex.status) from None

    @staticmethod
    def _returned(answer: ET.Element, what: str) -> None:
        """What a method of the engine answered, as a yes, or the error that says what it said instead."""
        output = _first_instance(answer)
        returned = int_of(fields_of(output), "ReturnValue", 0, 2**32) if output is not None else None
        if returned is None:
            raise KvmError("bad_response", f"The engine did not say whether it would {what}")
        if returned not in (0, 4096):
            raise KvmError("action_failed", f"The engine would not {what}: {RETURNS.get(returned, f'it answered {returned}')}")

    async def _follow_up(self) -> None:
        """Look at the PC again, several times, after something was done to it (see FOLLOW_UP)."""
        waited = 0.0
        for moment in FOLLOW_UP:
            await asyncio.sleep(moment - waited)
            waited = moment
            if self._closed:
                return
            self._status_at = 0.0
            self._refresh_soon()
