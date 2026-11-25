"""Where an alert may be sent, and how it gets there: the wall's outbound rules for alerts (0.4.0).

Sending somewhere on an admin's word is the classic way into a network from a server (SSRF): an address that leads to
this computer, to the network's own machines, or to a cloud's metadata service. So every alert goes out the same way:

- The name is looked up first, and every address it leads to is judged (`judge`). Always refused: the wall itself (the
  port it listens on, at any of its addresses and on loopback), link-local (169.254.0.0/16 with the metadata service,
  fe80::/10) and the clouds' metadata services in private ranges, the unspecified address, multicast, anything kept for
  another use; also where an IPv6 address carries one of those (IPv4-mapped, NAT64, 6to4, the old IPv4-compatible
  form). Refused unless the destination's "may be a private address" switch is on (an admin's, off by default): this
  computer (loopback, for a service of its own there), RFC 1918, unique local IPv6 (fc00::/7), and the shared space
  100.64.0.0/10, which Tailscale's addresses are in.
- The connection goes to the address that was judged, never to whatever the name leads to a moment later; the name
  travels where the service looks for it (the Host header, and TLS's SNI, whose certificate is checked for that name).
- No redirect is followed (the standard library's http.client follows none), no proxy is used, and no more of an
  answer is read than says how it went (MOST_READ).
- Every send has an end (SEND_TIMEOUT), and its connection is closed then: a service that never answers holds nothing
  of the wall. The answer's status line and headers are read by http.client's own rules.

The same rules hold for an identity provider the wall signs people in through (oidc.py, by `request`, HTTPS only, with
larger answers read: its keys and tokens), and for a mail server (`send_mail`), which smtplib speaks to in a thread of
its own. A test reaches its stand-ins on loopback by putting its own `vetted` in place (as webpush.py's tests do):
nothing a request can set lets an alert, or anything else, through to loopback.
"""

from __future__ import annotations

import asyncio
import base64
import bisect
import html.entities
import http.client
import io
import ipaddress
import logging
import os
import re
import smtplib
import socket
import ssl
import sys
import threading
import unicodedata
import weakref
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, NamedTuple
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .kvm import public_context

log = logging.getLogger("qkvm")

RESOLVE_TIMEOUT = 5.0  # seconds a name may take to be looked up
SEND_TIMEOUT = 15.0  # seconds one attempt may take, start to finish: the name looked up, the request sent, its answer read
STEP_TIMEOUT = 8.0  # ...and each step of it on the line (the connection, a read, a write)
MOST_READ = 8 * 1024  # bytes read of an answer: enough for a status and a service's reason, never "until it ends"
MOST_URL = 2048  # characters of an address (a Teams Workflows address carries a long signature)
USER_AGENT = "qKVM"

# Refused unless the destination may be a private address: networks of an organisation's own.
PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # shared address space (RFC 6598): carrier NAT, and Tailscale's addresses
    ipaddress.ip_network("fc00::/7"),  # unique local IPv6
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")  # the well-known prefix (RFC 6052): its IPv4 is its last 32 bits
# The local-use one (RFC 8215): where its IPv4 sits is its translator's to choose, so what it leads to cannot be told.
_LOCAL_NAT64 = ipaddress.ip_network("64:ff9b:1::/48")
_KEPT = ("retry-after", "content-type")  # the headers of an answer that are kept with it
# Clouds' metadata services that sit in ranges "May be a private address" lets through: never sent to all the same, as
# 169.254.169.254 (link-local) is not. AWS's over IPv6, and Alibaba's. (The review of 0.4.0's first wave, L1.)
METADATA = frozenset({ipaddress.ip_address("fd00:ec2::254"), ipaddress.ip_address("100.100.100.200")})

IP = ipaddress.IPv4Address | ipaddress.IPv6Address


class Refused(Exception):
    """An alert is not sent there by the wall's rules. The message is a sentence fit for showing; it is never tried again."""

    again = False


class NotReached(Exception):
    """An alert did not get there. The message is a sentence fit for showing."""

    def __init__(self, message: str, again: bool) -> None:
        super().__init__(message)
        self.again = again  # worth another try: the service was away, or slow


class Withheld(Exception):
    """Nothing was sent: what it was to go for no longer held when it was about to go (the sender's `still`, asked after the
    waits for a turn, for the name and for the connection). Never tried again."""

    again = False


# --- what may be sent to -------------------------------------------------------------------------------------------


def _carried(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 one leads to, where it carries one: mapped, through a NAT64 gateway, 6to4, or the old
    IPv4-compatible form (a connection to ::ffff:10.0.0.1 is one to 10.0.0.1)."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if 1 < int(ip) <= 0xFFFFFFFF:
        return ipaddress.IPv4Address(int(ip))
    return None


class Own(NamedTuple):
    """The wall itself, which no alert is sent to: its addresses, and the ports it listens on (there and on loopback)."""

    addresses: frozenset[str]
    ports: frozenset[int]


def _judge(ip: IP, private_ok: bool, own: set[IP], wall_port: bool) -> str | None:
    if ip in own and wall_port:
        return "it is this wall itself (its own address and port)"
    mine = ip in own
    if ip in METADATA:
        return "it is a cloud's metadata service"
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _carried(ip)
        if inner is not None:
            return _judge(inner, private_ok, own, wall_port)
        if ip in _LOCAL_NAT64:
            return "it is translated by a gateway of this network (local-use NAT64), and where it leads cannot be told"
    if ip.is_loopback:
        # This computer: a service of its own there (an ntfy, a relay) as a network's are, with the switch (the owner's
        # decision of 2026-11-17); the wall itself, never.
        if wall_port:
            return "it is this wall itself (this computer, at the port the wall listens on)"
        return None if private_ok else "it is this computer (loopback), and this destination is not allowed it (its switch \"May be a private address\")"
    if ip.is_link_local:
        return "it is link-local (a cloud's metadata service is one)"
    if ip.is_unspecified:
        return "it is the unspecified address"
    if ip.is_multicast:
        return "it is a multicast address"
    if mine:
        # An address of this computer's own, at another port than the wall's: as loopback is (the owner's rule: the switch
        # is what lets this computer through; the second review, L5).
        return None if private_ok else "it is this computer (an address of its own), and this destination is not allowed it (its switch \"May be a private address\")"
    if any(ip in network for network in PRIVATE):
        return None if private_ok else "it is a private address, and this destination is not allowed one (its switch \"May be a private address\")"
    if not ip.is_global or ip.is_reserved or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local):
        return "it is not an address of the internet"
    return None


def judge(address: str, *, private_ok: bool, own: Collection[str], port: int = 0, own_ports: Collection[int] = ()) -> str | None:
    """Why an alert may not go to this address (at this port), in words ("it is ..."); None where it may. `own`: the wall's
    addresses, `own_ports`: the ports it listens on, which are never sent to there or on this computer's loopback."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "it is not an address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
        # Python keeps a zone in what an address is: fd00:ec2::254%1 was not the metadata service fd00:ec2::254, nor the
        # wall's own address with %1 the wall (the second outside review of 0.4.0, M1). Nothing is sent to one.
        return ZONED
    mine: set[IP] = set()
    for one in own:
        try:
            mine.add(ipaddress.ip_address(one.split("%", 1)[0]))  # (an own address that came with a zone is the address)
        except ValueError:
            continue
    return _judge(ip, private_ok, mine, port in own_ports)


ZONED = "it names an interface of this computer (an IPv6 zone, %1 or %25eth0), which is never sent to"
ZONE_TYPED = "Write the IPv6 address without an interface of this computer after it (%1, %25eth0): an address that names one is not sent to"


def zoned(host: str) -> bool:
    """Whether a host as it is typed is an IPv6 address that names an interface of this computer: a zone, written raw (%1)
    or as a web address writes it (%25)."""
    return ":" in host and "%" in host


def this_computer() -> set[str]:
    """The addresses of this computer's interfaces, as far as the system says them: every interface's on Linux (its IPv4
    address by ioctl, every IPv6 one from /proc), what its name leads to (on Windows, every interface's), and the source
    address of its routes out. A wall that listens on every address is never sent to by its own alerts. Slow at times (a
    name looked up): not for the event loop."""
    found: set[str] = set()
    try:
        found.update(str(info[4][0]).split("%")[0] for info in socket.getaddrinfo(socket.gethostname(), None))
    except (OSError, UnicodeError):
        pass
    for family, somewhere in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.connect((somewhere, 9))  # a UDP connect sends nothing: it only picks the route, and its address here
                found.add(str(probe.getsockname()[0]).split("%")[0])
        except OSError:
            continue
    if sys.platform.startswith("linux"):
        found |= _linux_interfaces()
    return {address for address in found if address}


def _linux_interfaces() -> set[str]:
    found: set[str] = set()
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as listed:
            for line in listed:
                found.add(str(ipaddress.IPv6Address(int(line.split()[0], 16))))
    except (OSError, ValueError, IndexError):
        pass
    if sys.platform.startswith("linux"):  # (for the type checker, which looks at this as the platform it runs on)
        import fcntl
        import struct

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            for _, name in socket.if_nameindex():
                try:
                    said = fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))  # SIOCGIFADDR
                except OSError:
                    continue  # (an interface with no IPv4 address)
                found.add(socket.inet_ntoa(said[20:24]))
    return found


async def resolve(host: str, port: int) -> list[str]:
    """The addresses a name leads to, in the order they are to be tried. (A test puts its own in place of this.)"""
    found = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(str(entry[4][0]) for entry in found))


async def vetted(host: str, port: int, *, private_ok: bool, own: Collection[str], own_ports: Collection[int] = ()) -> tuple[list[str], int]:
    """Where to connect for this name: every address it leads to, in the order to try them, where every one of them may be
    sent to (judged all before any is connected to: no address comes in between), and the port.

    Refused where one may not (a name that leads into this network, written so or answered so by a DNS server somebody
    runs, is not followed there); NotReached where it leads nowhere just now. (A test puts its own in place of this to
    reach a stand-in on loopback: see the module's description.)"""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            async with asyncio.timeout(RESOLVE_TIMEOUT):
                addresses = await resolve(host, port)
        except (OSError, TimeoutError) as ex:
            raise NotReached(f"{host} could not be looked up ({type(ex).__name__})", again=True) from ex
    else:
        addresses = [host]
    if not addresses:
        raise NotReached(f"{host} leads nowhere", again=True)
    for address in addresses:
        why = judge(address, private_ok=private_ok, own=own, port=port, own_ports=own_ports)
        if why is not None:
            log.warning("an alert was not sent to %s: it leads to %s, and %s", host, address, why)
            raise Refused(f"Not sent: {host} leads to {address}, and {why}")
    return addresses, port


# Letters IDNA 2003 (Python's idna codec) and IDNA 2008 (browsers', registries') write apart: a sharp s, a final sigma,
# the zero-width joiner and non-joiner. "fa" and a sharp s and ".de" was written "fass.de" here, somebody else's name.
_READ_APART = frozenset(chr(code) for code in (0x00DF, 0x03C2, 0x200D, 0x200C))


def plain_host(host: str) -> str:
    """A host name in plain characters (its xn-- form). ValueError, with a sentence, for one with a letter the two IDNA
    standards read apart (the review of 0.4.0's first wave, L3), or one that has no such form."""
    if host.isascii():
        return host
    if any(ch in _READ_APART for ch in host):
        raise ValueError("Write that name in its xn-- form: a sharp s, a final sigma or a joiner in it is read two ways, and one of them is another name")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Write that name in its xn-- form") from None


def check_url(url: str, *, https_only: bool = False) -> str:
    """A web address an alert may be posted to, as it is sent: its name in plain characters (xn--), its path with what is
    not plain written as %XX, without a fragment. ValueError with a sentence fit for showing otherwise. (Where its name
    leads is judged at each send.)"""
    url = url.strip() if isinstance(url, str) else ""
    wanted = "https://" if https_only else "http:// or https://"
    if not url or len(url) > MOST_URL or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError(f"Enter a web address starting with {wanted}")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        raise ValueError(f"Enter a web address starting with {wanted}") from None
    if zoned(host):
        raise ValueError(ZONE_TYPED)  # (an IPv6 address with a zone, raw or %25: never sent to, see judge)
    host = plain_host(host)  # (ValueError with its own sentence)
    usable = parts.scheme in (("https",) if https_only else ("http", "https")) and bool(host) and port != 0
    if not usable:
        raise ValueError(f"Enter a web address starting with {wanted}")
    login = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    where = f"[{host}]" if ":" in host else host
    netloc = (f"{login}@" if login else "") + where + (f":{port}" if port is not None else "")

    def plain(text: str) -> str:
        return "".join(ch if ch.isascii() else quote(ch, safe="") for ch in text)

    return urlunsplit((parts.scheme, plain(netloc), plain(parts.path) or "/", plain(parts.query), ""))


# --- what a service says back ---------------------------------------------------------------------------------------

HIDDEN = "[hidden]"
LEAST_WHOLE = 4  # characters of a secret at the least for it to be looked for whole (a shorter one is no secret)
PART = 6  # characters of a machine's secret in a row that are a part of it, taken out wherever they stand; and of what is
# left of a secret with every sign but its letters and digits left out, at the least, for that to be looked for too


class Password(str):
    """A password a person chose (a mail login's), as `hidden` is given one: taken out whole only, never in part, and only
    where it stands whole. Every other secret `hidden` is given is a machine's (a token, a key, a signing secret, the secret
    part of an address, a password in an address), of which every run goes too; but for a word of an address (Word)."""

    __slots__ = ()


class Word(Password):
    """A word of an address's own (what stands between its slashes in small letters alone: "services", "webhooks",
    "manual"), as `hidden` is given one: taken out as a person's password is, whole only and only where it stands whole, as
    a service's own words may hold it (the final look at 0.4.0, L3). Any other secret of small letters (an ntfy topic with
    a dash in it, a key) is a machine's (the narrow look at 0.4.0, L7)."""

    __slots__ = ()


# What a text is looked through as, besides as it came (_signs): an escape as the sign it stands for (JSON's, a sign by
# its number after a backslash and a u, or a line's end as a backslash and an n; an address's %54; HTML's character
# references, &#84; &#x54; and by name, &amp;), and every letter or digit; nothing else.
_SIGN = re.compile(r'\\u([0-9a-fA-F]{4})|\\["\\/bfnrt]|%([0-9a-fA-F]{2})|&#[xX]([0-9a-fA-F]{1,6});?|&#([0-9]{1,7});?|&([A-Za-z][A-Za-z0-9]{1,31});|[^\W_]+')


def _small(sign: str) -> str:
    """A sign in small letters, where that is one sign (places must hold)."""
    return low if len(low := sign.lower()) == 1 else sign


def _signs(text: str) -> tuple[str, list[int], list[int]]:
    """The letters and digits of `text` in small letters, every other sign left out and an escape read as the sign it
    stands for, with where each of them begins and ends in `text` (an escape's: the whole escape). Signs side by side in
    `text` are a run, which a sign left out between them ends. (A run of letters and digits at a time: a mail server's
    answer may be most of a megabyte.)"""
    signs: list[str] = []
    begins: list[int] = []
    ends: list[int] = []
    for found in _SIGN.finditer(text):
        start, end = found.span()
        if text[start] not in "\\%&":
            signs.append(_lower(found.group()))
            begins.extend(range(start, end))
            ends.extend(range(start + 1, end + 1))
            continue
        json_code, address_code, html_code, html_number, html_name = found.groups()
        number = json_code or address_code or html_code
        code = int(number, 16) if number else int(html_number) if html_number else None
        if code is not None:
            said = chr(code) if 0 < code <= 0x10FFFF else ""
        elif html_name:
            said = html.entities.html5.get(f"{html_name};", "")
            if not said:  # (no reference of that name: its letters and digits are the text's own, as they stand)
                signs.append(_lower(html_name))
                begins.extend(range(start + 1, end - 1))
                ends.extend(range(start + 2, end))
                continue
        else:
            said = ""  # (JSON's \n and the like: no letter or digit)
        for sign in said:
            if sign.isalnum():
                signs.append(_small(sign))
                begins.append(start)
                ends.append(end)
    return "".join(signs), begins, ends


def _core(secret: str) -> str:
    """A secret's letters and digits in small letters, every other sign left out: what is looked for in _signs."""
    return "".join(_small(sign) for sign in secret if sign.isalnum())


def _composed(text: str) -> str:
    """`text` composed (Unicode's NFC), as a password typed one way is said back the other; a Password stays one."""
    if text.isascii() or unicodedata.is_normalized("NFC", text):
        return text
    made = unicodedata.normalize("NFC", text)
    return Password(made) if isinstance(text, Password) else made


def _whole_only(secret: str) -> bool:
    """Whether a secret is taken out only where it stands whole (not a part of a longer word of the text, nor across two of
    them): a person's password, and a word of an address (Word), which a service's own words may hold (the final look at
    0.4.0, L3). Every other secret goes wherever it stands, whatever its letters (Telegram's token says it fast after
    "bot"): one of small letters alone was taken for a word, and an ntfy topic or a key of small letters glued to a letter
    showed (the narrow look at 0.4.0, L7)."""
    return isinstance(secret, Password)


def _cuts(secret: str) -> frozenset[int]:
    """Where a secret's runs of letters and digits begin and end, counted in its letters and digits (_core): of "x9!Q#z",
    0, 2, 3 and 4; of "Mail!", 0 and 4."""
    cuts, place, inside = {0}, 0, False
    for sign in secret:
        if sign.isalnum():
            place, inside = place + 1, True
        elif inside:
            cuts.add(place)
            inside = False
    return frozenset({*cuts, place})


def _base64_forms(secret: str) -> list[str]:
    """What base64 makes of a secret wherever it stands in what was encoded (a Basic, Token or Bearer header said back as it
    went, encoded): for each of the three places its first byte can fall, the signs that are the same whatever comes before
    and after it (without the four at each end that the bytes around it change)."""
    data = secret.encode("utf-8", "replace")
    forms = []
    for before in range(3):
        encoded = base64.b64encode(bytes(before) + data).decode("ascii")[4 if before else 0 : -4]
        if len(encoded) >= PART:
            forms.append(encoded)
    return forms


def _lower(text: str) -> str:
    """`text` in small letters, sign for sign (a letter whose small form is two signs is left as it is: places must hold)."""
    low = text.lower()
    return low if len(low) == len(text) else "".join(_small(sign) for sign in text)  # (no sign's small form is none)


def hidden(text: str, secrets: Iterable[str], parts: Iterable[str] | None = None) -> str:
    """`text` (what a service said back) with what a request carried as a secret taken out, by one rule for each kind of
    secret. Of a secret that is an address, the caller gives what of it is the secret (a host name is shown anyway).

    - Every secret, whole, in any case; also where every sign but its letters and digits is left out of it and of the text
      (where PART of them are left at the least; a person's password with fewer where it holds two runs of them or more,
      and the text shows them in as many runs, each at the edges of one), and an escape in the text is read as
      the sign it stands for: a passphrase said back with "+" or "_" between its words, a token split over two lines, with
      a blank put in or its dashes left out, written with an address's, JSON's or HTML's escapes ("&amp;"). Both texts are
      compared composed (NFC): a password typed decomposed is said back composed. And so what base64 makes of each,
      wherever it stands in what was encoded (a Basic, Token or Bearer header said back as it went).
    - Where it stands: a token anywhere, also written fast to the service's words, whatever its letters (one of small
      letters alone too: the narrow look at 0.4.0, L7). A person's password, and a word of an address (Word: "services",
      "manual"), only where it stands whole: its first and last letter or digit at the edges of runs of the text's letters
      and digits, never a part of a longer word nor across two ("webhook settings" holds no "webhooks", "manually" no
      "manual": the final look at 0.4.0, L3, L4).
    - A machine's secret (anything but a Password or a Word: a token, a key, a signing secret, the secret part of an
      address, a password in an address; random signs, no words) goes in part too: every run of PART characters or more
      of one of `parts` (the machine's secrets themselves where none are given; none at all where `parts` is empty) or of
      what base64 makes of one, in any case, wherever it stands, which is how a service that cuts what it repeats, or a
      bound that cuts it, shows a part of one. A run of letters that reads as a word goes as well: a token holds no words
      of the service's.
    - A person's password (Password: a mail login's) goes whole only, never a part of it: a server's own words stay
      whatever words the password holds and in whatever case ("Username and Password not accepted" of "PASSWORD2024!",
      "Passwords" of "Password2024!", "alertsmailbox" of "alerts-mail"), and what is taken out never says which words a
      password holds (the fresh review of the fixes, N5, and the last look at them, L1).

    Looked for in the text as it came, before it is cut or its blanks closed up (the review of 0.4.0's first wave, L4),
    and the caller looks again after (the outside review of 0.4.0, L1: an error of NetBird's that repeated its token was
    handed to the browser as it came). What is found anywhere is taken out at once, as one [hidden] for what stands side
    by side (in the text composed; where nothing is found, the text is given back as it came)."""
    given = [secret for secret in secrets if len(secret) >= LEAST_WHOLE]
    wholes = {_composed(secret) for secret in given}
    machines = [whole for whole in wholes if not isinstance(whole, Password)]
    encoded = {form for secret in given for form in _base64_forms(secret)}  # (of the secret as it was sent)
    came, text = text, _composed(text)
    signs, begins, ends = _signs(text)

    def edge(at: int) -> bool:
        """Whether a run of the text's letters and digits begins, or ends, at sign `at`."""
        return at == 0 or at == len(signs) or begins[at] > ends[at - 1]

    def alone(start: int, end: int, whole: str) -> bool:
        """Whether `whole`, found at text[start:end], stands whole there: no letter or digit of the text (nor an escape of
        one) right before its first letter or digit, nor right after its last."""
        if whole[:1].isalnum() and (at := bisect.bisect_left(ends, start)) < len(ends) and ends[at] == start:
            return False
        return not (whole[-1:].isalnum() and (at := bisect.bisect_left(begins, end)) < len(begins) and begins[at] == end)

    found: list[tuple[int, int]] = []
    for whole in wholes:
        spans = [each.span() for each in re.finditer(re.escape(whole), text, flags=re.IGNORECASE)]
        found += [span for span in spans if alone(*span, whole)] if _whole_only(whole) else spans
        core = _core(whole)
        # (A person's password of fewer letters and digits than PART: by them alone only where it has two runs of them or
        # more, and the text shows them in as many, each at the edges of one; a single short run is looked for in its own
        # spelling alone, above. "Mail!" took the "mail" of a server's own link, "!!!7" a 7 of its code: the narrow look at
        # 0.4.0, L8.)
        cuts = _cuts(whole) if len(core) < PART else frozenset()
        if len(core) >= PART or (isinstance(whole, Password) and len(cuts) > 2):
            at = signs.find(core)
            while at >= 0:
                if cuts:
                    taken = all(edge(at + place) == (place in cuts) for place in range(len(core) + 1))
                else:
                    taken = not _whole_only(whole) or (edge(at) and edge(at + len(core)))
                if taken:
                    found.append((begins[at], ends[at + len(core) - 1]))
                at = signs.find(core, at + 1)
    for form in encoded:
        found += [each.span() for each in re.finditer(re.escape(form), text, flags=re.IGNORECASE)]
    for core in {_core(form) for form in encoded}:
        if len(core) >= PART:
            at = signs.find(core)
            while at >= 0:
                found.append((begins[at], ends[at + len(core) - 1]))
                at = signs.find(core, at + 1)
    pieces = machines if parts is None else [_composed(piece) for piece in parts if piece and not isinstance(piece, Password)]
    if parts is None or pieces:  # (none at all: whole only, what the caller looks through in full before it is bounded)
        runs = [form for secret in given if not isinstance(secret, Password) for form in _base64_forms(secret)]
        grams = {_lower(piece[at : at + PART]) for piece in (*pieces, *runs) for at in range(len(piece) - PART + 1)}
        lowered = _lower(text)
        found += [(at, at + PART) for at in range(len(text) - PART + 1) if lowered[at : at + PART] in grams]
    if not found:
        return came
    said: list[str] = []
    before = 0
    for start, end in sorted(found):
        if start > before or not said:
            said += [text[before:start], HIDDEN]
        before = max(before, end)
    said.append(text[before:])
    return "".join(said)


def basic(url: str) -> str | None:
    """The Authorization header a name and a password in an address are sent as (Basic), as `request` makes it; None
    where the address holds neither."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.username is None and parts.password is None:
        return None
    pair = f"{unquote(parts.username or '')}:{unquote(parts.password or '')}".encode()
    return "Basic " + base64.b64encode(pair).decode("ascii")


# --- sending ---------------------------------------------------------------------------------------------------------

HEAD_MOST = 64 * 1024  # bytes of an answer's status line and headers together
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # what a header's name is made of (RFC 9110)


@dataclass
class Reply:
    """What a service answered: its status, the few headers that say what to do next (lower-case names), and the start
    of what it said (MOST_READ at the most)."""

    status: int
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


class _Head:
    """What was read of an answer up to its body, handed to http.client as the socket it reads an answer from: the status
    line and the headers are read by the standard library's own rules (a line, and how many, at the most)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(io.BytesIO(self._data))


_open = [0]


def under_way() -> int:
    """How many sends have a connection open at this moment, mail included (for the tests: none is left open)."""
    return _open[0]


def _failed(host: str, ex: BaseException, speaking: str = "HTTP") -> NotReached:
    """What went wrong on the line to a service, in words."""
    if isinstance(ex, ssl.SSLCertVerificationError):
        return NotReached(f"{host} did not show a valid certificate for its name ({ex.verify_message or 'not trusted'})", again=False)
    if isinstance(ex, ConnectionRefusedError):
        return NotReached(f"{host} refused the connection", again=True)
    if isinstance(ex, (TimeoutError, socket.timeout)):
        return NotReached(f"{host} did not answer in time", again=True)
    if isinstance(ex, (http.client.HTTPException, asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError)):
        return NotReached(f"{host} answered with something that is not {speaking}", again=True)
    if isinstance(ex, ssl.SSLError):
        return NotReached(f"The encrypted connection to {host} failed ({ex.reason or type(ex).__name__})", again=True)
    return NotReached(f"{host} could not be reached ({type(ex).__name__})", again=True)


async def _body(reader: asyncio.StreamReader, answer: http.client.HTTPResponse, most: int = MOST_READ) -> bytes:
    """The start of an answer's body, `most` bytes at the most, by what its headers say of its length."""
    if answer.chunked:
        got = b""
        while len(got) < most:
            size = int((await reader.readuntil(b"\r\n")).split(b";")[0].strip(), 16)
            if size <= 0:
                break
            piece = await reader.readexactly(min(size, most - len(got)))
            got += piece
            if len(piece) < size:
                break
            await reader.readexactly(2)
        return got
    if answer.length is not None:
        try:
            return await reader.readexactly(min(answer.length, most))
        except asyncio.IncompleteReadError as ex:
            return ex.partial
    got = b""
    while len(got) < most and (piece := await reader.read(most - len(got))):
        got += piece
    return got


async def _connect(addresses: list[str], port: int, host: str, context: ssl.SSLContext | None) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A connection to the first of the judged addresses that takes one, each in turn (a name that leads to ::1 and to
    127.0.0.1, where its service listens on the second alone), within the send's one time. The name is what TLS asks the
    other end for, and what its certificate is checked for: a certificate refused is the answer, and ends the trying."""
    failed: OSError | None = None
    for address in addresses:
        try:
            async with asyncio.timeout(STEP_TIMEOUT):
                return await asyncio.open_connection(
                    address, port, ssl=context, server_hostname=host if context is not None else None, limit=HEAD_MOST,
                    ssl_handshake_timeout=STEP_TIMEOUT if context is not None else None,
                )  # fmt: skip
        except ssl.SSLError:
            raise
        except (OSError, TimeoutError) as ex:
            failed = ex if isinstance(ex, OSError) else TimeoutError(f"{address} did not answer in time")
    raise failed if failed is not None else OSError(f"{host} leads nowhere")


def _connected(addresses: list[str], port: int, timeout: float) -> socket.socket:
    """socket.create_connection's way, over the judged addresses alone: the first that takes a connection."""
    failed: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout)
        except OSError as ex:
            failed = ex
    raise failed if failed is not None else OSError("no address to connect to")


async def post(
    url: str, body: bytes, headers: Mapping[str, str], *, private_ok: bool, own: Collection[str], own_ports: Collection[int] = (),
    still: Callable[[], bool] | None = None,
) -> Reply:
    """POST `body` to `url` by the wall's rules (see the module's description). Refused, or NotReached, where it was not;
    Withheld where `still` said no right before it went."""
    return await request("POST", url, body, headers, private_ok=private_ok, own=own, own_ports=own_ports, still=still)


async def request(
    method: str, url: str, body: bytes | None, headers: Mapping[str, str], *, private_ok: bool, own: Collection[str], own_ports: Collection[int] = (),
    most: int = MOST_READ, https_only: bool = False, still: Callable[[], bool] | None = None,
) -> Reply:
    """`method` to `url` by the wall's rules (see the module's description), with `body` (None: none, as a GET has), and
    `most` bytes of the answer read at the most (an alert needs no more than MOST_READ; an identity provider's keys and
    tokens do, oidc.py). `https_only`: an address that is not https:// is refused before anything is looked up. Refused,
    or NotReached, where it was not."""
    try:
        checked = check_url(url, https_only=https_only)
    except ValueError as ex:
        raise Refused(str(ex)) from ex
    parts = urlsplit(checked)
    host = parts.hostname or ""
    tls = parts.scheme == "https"
    port = parts.port or (443 if tls else 80)
    said = {"User-Agent": USER_AGENT, **headers}
    if (login := basic(checked)) is not None:
        # A name and a password in the address are what the service takes them as: Basic authentication.
        said["Authorization"] = login
    named = (f"[{host}]" if ":" in host else host) + ("" if parts.port is None else f":{parts.port}")
    if not _TOKEN.fullmatch(method):
        raise Refused(f"{method[:20]!r} is no method of HTTP")
    lines = [f"{method} {parts.path or '/'}{'?' + parts.query if parts.query else ''} HTTP/1.1", f"Host: {named}"]
    for name, value in said.items():
        if not _TOKEN.fullmatch(name) or any(ch in value for ch in "\r\n\0"):
            raise Refused(f"A header of the alert cannot be written as one ({name[:40]})")
        lines.append(f"{name}: {value}")
    lines += [*([] if body is None else [f"Content-Length: {len(body)}"]), "Connection: close", "Accept-Encoding: identity"]
    try:
        sent = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b"")
    except UnicodeEncodeError as ex:
        raise Refused("A header of the alert cannot be written as one (a character outside Latin-1)") from ex
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(SEND_TIMEOUT):
            addresses, reach = await vetted(host, port, private_ok=private_ok, own=own, own_ports=own_ports)
            context = await public_context() if tls else None
            reader, writer = await _connect(addresses, reach, host, context)
            _open[0] += 1
            if still is not None and not still():
                # (Asked once more after the waits for the name and the connection, right before anything goes: alerts
                # stopped meanwhile are not sent. The second outside review of 0.4.0, M4.)
                raise Withheld("Not sent: what it was for was stopped while it waited")
            writer.write(sent)
            await writer.drain()
            answer = http.client.HTTPResponse(_Head(await reader.readuntil(b"\r\n\r\n")), method=method)  # type: ignore[arg-type]
            answer.begin()
            got = await _body(reader, answer, most)
            kept: dict[str, str] = {}
            for name in _KEPT:
                header = answer.getheader(name)
                if header is not None:
                    kept[name] = header[:200]
            return Reply(answer.status, str(answer.reason or "")[:80], kept, got)
    except (Refused, NotReached, Withheld):
        raise
    except Exception as ex:
        raise _failed(host, ex) from ex
    finally:
        if writer is not None:
            writer.transport.abort()  # (no more is read or sent: nothing is owed to the other end)
            _open[0] -= 1


# --- mail ------------------------------------------------------------------------------------------------------------

MAIL_PORTS = (465, 587)  # implicit TLS, and STARTTLS: a password is never sent where the line is not encrypted
MOST_REPLY_LINES = 100  # lines of one answer of a mail server (the standard library takes any number)
MOST_LINE = 8192  # bytes of one of them (the standard library's own bound)
MAIL_AT_ONCE = 4  # mail sends under way at once, from the whole wall: smtplib waits on its line, so each has a thread
HELLO = "localhost"  # what the wall calls itself to a mail server: its own name would tell the server where it is


class MailRefused(Exception):
    """A mail server said no. `code` its number (535: the login), the message its words."""

    def __init__(self, code: int, said: str) -> None:
        super().__init__(f"{code} {said}".strip())
        self.code = code
        self.again = 400 <= code < 500  # a 4xx is the server's "not now"


MOST_REFUSAL = 120  # characters of what a server said of each address it refused, where it took the message for others


class PartlyRefused(MailRefused):
    """A mail server took the message for some of its addresses and refused it for the others: said as such, with each
    address it refused and its words (what the login was carried as taken out). Never tried again, whatever it said (a 4xx
    too): those that took it have it, and would have it twice (the outside review of 0.4.0, round 6.2, M5)."""

    def __init__(self, took: int, refused: dict[str, tuple[int, str]]) -> None:
        listed = ", ".join(f"{address} ({' '.join((str(code), said)).strip()})" for address, (code, said) in refused.items())
        Exception.__init__(self, f"Delivered to {took} of {took + len(refused)} addresses, not tried again: refused for {listed}")
        self.code = next(iter(refused.values()))[0]
        self.again = False


class _Line:
    """The connection of one mail send, as the event loop sees it: ended where its time is up, which ends whatever its
    thread waits for on it. Shut, which ends a read under way on Linux and macOS; and on Windows, where it does not,
    closed as well (the thread reads with no file object of its own, so a close is a close)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._held: socket.socket | None = None
        self.let_go = False

    def hold(self, sock: socket.socket) -> None:
        with self._lock:
            if self.let_go:
                sock.close()
                raise TimeoutError("the send's time was up")
            self._held = sock

    def shut(self) -> None:
        with self._lock:
            self.let_go, held = True, self._held
        if held is None:
            return
        try:
            socket.socket.shutdown(held, socket.SHUT_RDWR)
        except OSError:
            pass
        if os.name == "nt":
            try:
                held.close()
            except OSError:
                pass


class _Mail(smtplib.SMTP):
    """smtplib's client, connected to the judged address for the server's name, its answers read with a bound on their
    lines and without a file object (a server, or anybody on the line before STARTTLS, that sends endless "250-" lines
    is not read for ever), and STARTTLS refused where more came with its answer than the answer."""

    def __init__(self, to: tuple[list[str], int], line: _Line, context: ssl.SSLContext, implicit: bool, accepted: list[tuple[str, dict[str, int]]]) -> None:
        self._to, self._line, self._tls, self._implicit = to, line, context, implicit
        self._got = b""
        self.taken: tuple[int, bytes] | None = None  # the server's answer to the message's end, where it was 250: its acceptance
        self._accepted = accepted  # (the same, the moment it is read, with the numbers of the addresses refused: _send_mail)
        self._refused: dict[str, int] = {}
        super().__init__(local_hostname=HELLO, timeout=STEP_TIMEOUT)

    def rcpt(self, recip: str, options: Sequence[str] = ()) -> tuple[int, bytes]:
        code, said = super().rcpt(recip, options)
        if code not in (250, 251):  # (as smtplib counts an address refused)
            self._refused[recip] = code
        return code, said

    def data(self, msg: Any) -> tuple[int, bytes]:
        code, said = super().data(msg)
        if code == 250:
            self.taken = (code, said)
            self._accepted.append((f"{code} {said.decode('utf-8', 'replace')}", dict(self._refused)))
        return code, said

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        self._host = host  # (what TLS is for; smtplib takes it from its constructor, which is given none so as not to connect there)
        sock = _connected(*self._to, timeout)
        self._line.hold(sock)
        return self._wrap(sock) if self._implicit else sock

    def _wrap(self, sock: socket.socket) -> socket.socket:
        # The name is what the certificate is checked for, and what TLS asks the other end for: never the address.
        tls = self._tls.wrap_socket(sock, server_hostname=self._host, do_handshake_on_connect=False)
        self._line.hold(tls)
        tls.do_handshake()
        return tls

    def _readline(self) -> bytes:
        while b"\n" not in self._got:
            if len(self._got) > MOST_LINE:
                self.close()
                raise smtplib.SMTPResponseException(500, b"An answer's line was too long")
            if self.sock is None:
                raise smtplib.SMTPServerDisconnected("Not connected")
            piece = self.sock.recv(4096)
            if not piece:
                self.close()
                raise smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
            self._got += piece
        line, _, self._got = self._got.partition(b"\n")
        return line + b"\n"

    def getreply(self) -> tuple[int, bytes]:
        lines: list[bytes] = []
        while True:
            line = self._readline()
            if len(lines) >= MOST_REPLY_LINES:
                self.close()
                raise smtplib.SMTPResponseException(500, b"The answer was too long")
            lines.append(line[4:].strip(b" \t\r\n"))
            try:
                code = int(line[:3])
            except ValueError:
                return -1, b"\n".join(lines)
            if line[3:4] != b"-":
                return code, b"\n".join(lines)

    def starttls(self, *args: Any, **kwargs: Any) -> tuple[int, bytes]:
        self.ehlo_or_helo_if_needed()
        if not self.has_extn("starttls"):
            raise Refused(f"{self._host} does not offer STARTTLS: nothing was sent, a password least of all, over a line that is not encrypted")
        code, said = self.docmd("STARTTLS")
        if code != 220:
            raise smtplib.SMTPResponseException(code, said)
        if self._got:
            # More came in the clear with the answer than the answer: what somebody on the line pushes in, to be read as if
            # the server had said it inside TLS (the STARTTLS command injection of CVE-2011-0411 and its kin).
            raise Refused(f"{self._host} sent more than its answer to STARTTLS, in the clear: nothing was sent")
        if self.sock is None:
            raise smtplib.SMTPServerDisconnected("Not connected")
        self.sock = self._wrap(self.sock)
        self.file = None
        self.helo_resp = self.ehlo_resp = None
        self.esmtp_features = {}
        self.does_esmtp = False
        return code, said

    def close(self) -> None:
        self._got = b""
        super().close()


def mail_secrets(login: tuple[str, str] | None) -> list[str]:
    """What a mail's login is carried as, which a mail server may say back as it got it: the password (a person's,
    Password: taken out whole only, so that the server's own words stay), as it was typed and without the blanks at its
    ends, which are its own and a server may leave out when it says it back (the outside review of 0.4.0, round
    6.2, M8), and SMTP's AUTH of it as smtplib sends it, in base64 (PLAIN: the name and the password in one; LOGIN: the
    password by itself), signs of a machine's making whose every run goes."""
    if login is None:
        return []
    user, password = login

    def sent(text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")

    persons = [Password(piece) for piece in dict.fromkeys((password, password.strip())) if piece]
    return [*persons, sent(f"\0{user}\0{password}"), sent(password)]


def _mail_said(ex: smtplib.SMTPException, carried: Collection[str] = ()) -> MailRefused | None:
    """A mail server's refusal, as its number and words, with what the login was carried as taken out of them (`carried`,
    mail_secrets, by `hidden`'s rules: as a server that repeats what it was sent says it); None where it said nothing (the
    line went)."""
    if isinstance(ex, smtplib.SMTPRecipientsRefused):
        # Refused for every address: nobody has it. A "not now" (4xx) of any of them says how it went, whatever the order of
        # the addresses, so that it is tried again (the outside review 6.2 second re-check, M5); otherwise the first refusal.
        said = list(ex.recipients.values())
        first = next((one for one in said if 400 <= int(one[0]) < 500), said[0] if said else (550, b"refused"))
        words = first[1].decode("utf-8", "replace") if isinstance(first[1], bytes) else str(first[1])
        return MailRefused(int(first[0]), hidden(words, carried))
    if isinstance(ex, smtplib.SMTPResponseException):
        words = ex.smtp_error.decode("utf-8", "replace") if isinstance(ex.smtp_error, bytes) else str(ex.smtp_error)
        return MailRefused(int(ex.smtp_code), hidden(words, carried))
    return None


def _refusal(said: bytes | str, carried: Collection[str]) -> str:
    """What a mail server said of an address it refused where it took the message for others (PartlyRefused): one line of
    MOST_REFUSAL characters at the most, with what the login was carried as taken out before it is cut or its blanks closed
    up, and once more after that (as destinations.scrub does)."""
    words = said.decode("utf-8", "replace") if isinstance(said, bytes) else str(said)
    line = " ".join("".join(ch if ch.isprintable() else " " for ch in hidden(words, carried)).split())
    return hidden(line, carried)[:MOST_REFUSAL]


_mail_threads = ThreadPoolExecutor(MAIL_AT_ONCE, thread_name_prefix="qkvm-mail")
_counting = threading.Lock()


async def send_mail(
    host: str, port: int, login: tuple[str, str] | None, message: EmailMessage, sender: str, to: list[str], *, private_ok: bool, own: Collection[str],
    own_ports: Collection[int] = (), still: Callable[[], bool] | None = None,
) -> str:
    """Send `message` through the mail server at `host` by the wall's rules: its address judged, TLS with the certificate
    checked for its name (implicit on 465; STARTTLS on 587, and a server that does not offer it is sent nothing). What
    the server said to the message's end, which is its acceptance whatever comes after; MailRefused (its own words),
    Refused or NotReached where it was not sent; PartlyRefused (a MailRefused, never tried again) where it was taken for
    some of `to` and refused for the others; Withheld where `still` said no after the waits for its turn and its name, or
    right before the message went.

    MAIL_AT_ONCE sends have a thread at a time; one waits for its turn first, and its time (SEND_TIMEOUT) begins with its
    turn: a burst to many mail destinations does not run out of time waiting (the review of 0.4.0's first wave, L2)."""
    if port not in MAIL_PORTS:
        raise Refused(f"A mail server is reached on port {' or '.join(map(str, MAIL_PORTS))}: the ports of TLS")
    loop = asyncio.get_running_loop()
    turns = _mail_turns.setdefault(loop, asyncio.Semaphore(MAIL_AT_ONCE))
    async with turns:
        return await _send_mail(loop, host, port, login, message, sender, to, private_ok=private_ok, own=own, own_ports=own_ports, still=still)


# The turns of the mail sends, of each event loop (a test runs many): MAIL_AT_ONCE at a time, as many as there are threads.
_mail_turns: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = weakref.WeakKeyDictionary()


async def _send_mail(
    loop: asyncio.AbstractEventLoop, host: str, port: int, login: tuple[str, str] | None, message: EmailMessage, sender: str, to: list[str], *,
    private_ok: bool, own: Collection[str], own_ports: Collection[int], still: Callable[[], bool] | None = None,
) -> str:  # fmt: skip
    deadline = loop.time() + SEND_TIMEOUT
    try:
        async with asyncio.timeout(SEND_TIMEOUT):
            reach = await vetted(host, port, private_ok=private_ok, own=own, own_ports=own_ports)
            context = await public_context()
    except TimeoutError:
        raise NotReached(f"{host} took too long", again=True) from None
    except (Refused, NotReached):
        raise
    except Exception as ex:  # (an authorities' file that cannot be read, say: said as any trouble on the way is)
        raise _failed(host, ex, "SMTP") from ex
    if still is not None and not still():
        raise Withheld("Not sent: what it was for was stopped while it waited")  # (after its turn and its name: M4)
    line = _Line()
    carried = mail_secrets(login)  # (taken out of whatever the server says back: _mail_said)
    # Once the server took the message, its answer to the message's end and the addresses it refused (each with its words),
    # kept where the event loop finds them whatever ends the send after that. And the same with the numbers alone, kept by
    # _Mail the moment its 250 is read: the time of a send that was up while the words were made fit to show had it said as
    # not answered in time, and sent again to the addresses that had it (the outside review 6.2 re-check, R7).
    taken: list[tuple[str, dict[str, tuple[int, str]]]] = []
    accepted: list[tuple[str, dict[str, int]]] = []

    def went() -> str:
        """How a send went that the server took: its answer to the message's end; PartlyRefused where it refused some of the
        addresses (M5), with the server's words for each where they were made in time."""
        said, refused = taken[0] if taken else (accepted[0][0], {address: (code, "") for address, code in accepted[0][1].items()})
        if refused:
            raise PartlyRefused(len(to) - len(refused), refused)
        return said

    def send() -> str:
        with _counting:
            _open[0] += 1
        server = _Mail(reach, line, context, implicit=port == 465, accepted=accepted)
        try:
            server.connect(host, port)
            server.ehlo()
            if port != 465:
                server.starttls()
                server.ehlo()
            if login is not None:
                server.login(*login)
            if still is not None and not still():  # (and once more right before the message goes)
                raise Withheld("Not sent: what it was for was stopped while it waited")
            # The server's 250 to the message's end is its acceptance, and the message is sent: what comes after it (QUIT,
            # the line closed, no answer until the time is up) undoes nothing. A NOOP after it was what the send was said
            # by, and a server that took the message and hung up was sent it again, four times (the outside review of 0.4.0,
            # round 6.2, M6). And what smtplib hands back is read: the addresses it refused (M5).
            refused = server.send_message(message, sender, to)
            code, said = server.taken or (250, b"")
            taken.append((f"{code} {said.decode('utf-8', 'replace')}", {str(address): (int(each[0]), _refusal(each[1], carried)) for address, each in refused.items()}))
        finally:
            try:
                server.quit()
            except (smtplib.SMTPException, OSError):
                server.close()
            with _counting:
                _open[0] -= 1
        return went()

    future = loop.run_in_executor(_mail_threads, send)
    # (Where its time was up, what the thread ends with is nobody's: taken, so that it is not said as never retrieved.)
    future.add_done_callback(lambda done: done.cancelled() or done.exception())
    try:
        # (Never wait_for, which loses a stop up to Python 3.11: see kvm.Listening.message. Where the time is up, the wait is
        # let go of and the thread's line is shut below, which ends it.)
        async with asyncio.timeout(max(0.0, deadline - loop.time())):
            return hidden(await future, carried)
    except TimeoutError:
        line.shut()
        if not taken and not accepted:
            raise NotReached(f"{host} did not answer in time", again=True) from None
    except asyncio.CancelledError:
        line.shut()
        raise
    except (NotReached, Refused, Withheld, MailRefused):
        raise
    except smtplib.SMTPException as ex:
        if not taken and not accepted:
            refused = _mail_said(ex, carried)
            if refused is not None:
                raise refused from None  # (the server's words as it said them stay out of what is raised: the outside review of 0.4.0, L1)
            raise NotReached(f"{host} ended the connection", again=True) from ex
    except Exception as ex:
        if not taken and not accepted:
            raise _failed(host, ex, "SMTP") from ex
    return hidden(went(), carried)  # (taken, and whatever ended the send after that undoes nothing: M6)
