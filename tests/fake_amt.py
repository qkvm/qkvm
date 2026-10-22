"""A stand-in for a PC with Intel AMT: as much of WS-Management as the wall asks for.

Built from Intel's published class reference (the shapes of CIM_AssociatedPowerManagementService,
CIM_PowerManagementService.RequestPowerStateChange, IPS_KVMRedirectionSettingData, CIM_KVMRedirectionSAP,
IPS_OptInService, IPS_HostBasedSetupService, AMT_RedirectionService and the hardware classes), not from a
real machine: none has been met yet. It challenges with HTTP Digest as the engine does, answers canned SOAP
in both control modes with a KVM that is enabled, disabled or absent, takes a power command and changes its
state, and can be told to answer wrongly: another kind of content, too much, too slowly, a fault.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import socket
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from qkvm import amt
from tests import local_socket
from tests.fake_kvm import make_device_certificate
from tests.fake_vnc import FakeVnc, PixelFormat, VncState

SERVER = "Intel(R) Active Management Technology 12.0.90"  # what every answer of an engine says of itself
GUID = "3C4A5B6C7D8E4F60A1B2C3D4E5F60718"  # the number this PC gives for itself (CIM_ComputerSystemPackage.PlatformGUID)


@dataclass
class AmtState:
    username: str = "admin"
    password: str = "secret"
    power: int = 2  # as CIM_AssociatedPowerManagementService.PowerState says it: 2 on, 3 and 4 asleep, 7 hibernating, 8 off
    offered: list[int] = field(default_factory=lambda: [2, 5, 8, 10, 12])  # AvailableRequestedPowerStates; []: not said
    control: int = 2  # IPS_HostBasedSetupService.CurrentControlMode: 0 not provisioned, 1 client control, 2 admin control
    kvm: str = "enabled"  # "enabled" | "disabled" (from the network) | "mebx" (disabled in the BIOS menu) | "absent" (Essentials: no such class)
    consent: bool = False  # whether a session needs the code on the PC's screen (IPS_OptInService.OptInRequired)
    make: object = "Example Computers"
    model: object = "Office Desk 7"
    serial: object = "PC0000000001"
    board_make: object = "Example Boards"
    board_model: object = "EB-Q370"
    bios: object = "E7ET42W (1.42)"
    family: int = 205  # the SMBIOS processor family: 205 is Intel Core i5
    other_family: object = None  # what the processor is where `family` is 1 ("Other")
    clock: int = 3400  # MHz
    processors: int = 1
    memory: list[int] = field(default_factory=lambda: [8 * 2**30, 8 * 2**30])  # bytes a module each
    version: object = "12.0.90"  # the AMT firmware (CIM_SoftwareIdentity "AMT")
    hostname: object = "desk-7"
    guid: object = GUID
    realm: str = ""  # its Digest realm ("": REALM, as every stand-in has unless told otherwise; a real engine has one of its own)
    checks_realm: bool = True  # False: the realm an answer names is not compared with its own (the digest made with it is checked)
    returns: int | None = None  # a power command is answered with this ReturnValue instead of 0
    drops: list[int] = field(default_factory=list)  # power states that are taken and not brought about
    power_takes: float = 0.0  # seconds between a power command being taken and the PC being seen in its new state
    power_later: tuple[float, int] | None = None
    stale_once: bool = False  # the first signed request is told that its nonce ran out, and asked again
    forgets_without_saying: bool = False  # a nonce it does not know is answered with a plain no, not with "stale"
    strict_nc: bool = False  # a nonce count not above the last one seen for that nonce is a replay, and a plain no
    nonce_uses: int = 0  # a nonce takes this many signed requests, and is said to have run out after (0: as many as come)
    nonce_used: dict[str, int] = field(default_factory=dict)
    refuses_after_sign_in: bool = False  # takes the sign-in question (AMT_GeneralSettings) and says a plain no to every other signed request
    unsigned_status: int | None = None  # what a request without a sign-in is answered with instead of the challenge (503: one of its moments)
    basic_only: bool = False  # it asks for a Basic sign-in and no Digest
    without_server_header: bool = False  # answers without saying what it is
    sign_in_takes: float = 0.0  # seconds a signed request waits before being answered
    # What is answered wrongly, by the class asked about (its short name), or "*" for every one:
    # "json" | "html" | "huge" | "slow" | "doctype" | "no_body" | "nonsense" | "fault" (not allowed) | "fault_other" (an error of its own)
    odd: dict[str, str] = field(default_factory=dict)
    pages: int = 1  # a listing is handed out in this many pulls
    # The redirection port (the WS-Management port and two), and the KVM behind it, as a real engine was seen to do it.
    listener: bool = True  # AMT_RedirectionService.ListenerEnabled: the redirection port takes connections only while it is on
    session_timeout: int = 0  # IPS_KVMRedirectionSettingData.SessionTimeout, minutes (0: none)
    session_lasts: float = 0.0  # seconds after which the stand-in ends a KVM session itself (its "minutes"); 0: never
    next_session_ends_when: threading.Event | None = None  # consumed by the next KVM session; explicit test-controlled expiry
    # The first session ends as the viewer's first request for the screen comes: its handshake is done, and a viewer that
    # is to send keys is waiting INPUT_AFTER (an end at the engine's own time that falls into that wait).
    first_session_ends_at_request: bool = False
    first_session_ends_after_keys: int = 0  # ...or once it has taken this many key events (0: neither)
    # Every session ends once the viewer has asked for the screen this many times (0: not so): with three, after the first
    # whole picture was sent (the first request is answered with the size alone), whatever the viewer's pace.
    sessions_end_after_requests: int = 0
    start_status: int | None = None  # what the start of a session is answered with; None: 0 where the KVM is on, 1 where not
    auth_types: list[int] = field(default_factory=lambda: [4])  # the sign-ins it offers on the redirection port
    redirection_password: str | None = None  # the password its redirection port takes, where it is not `password` (a test's own make)
    put_fails: bool = False  # a Put of AMT_RedirectionService is answered with a fault (the access point's change has gone through)
    redirect_odd: str = ""  # "not_redirection" | "wrong_end" | "not_rfb" | "hang_up" | "recorded" | "huge_answer" | "neither" | "stall" | "slow_challenge"
    challenge_takes: float = 0.0  # seconds the redirection port takes before its Digest challenge (an engine slow to open a session)
    answer_takes: float = 0.0  # seconds the redirection port takes to answer the Digest answer (the password is out meanwhile)
    screen: VncState = field(default_factory=lambda: amt_screen())  # the RFB part: what the KVM shows, and how it speaks
    redirections: int = 0  # connections to the redirection port
    redirected_at: list[float] = field(default_factory=list)  # ...and when each came (time.monotonic(), the tests' clock too)
    redirection_logins: int = 0  # Digest answers that came, right or wrong
    redirection_rejections: int = 0
    kvm_sessions: int = 0  # sessions that got as far as RFB
    redirection_open: int = 0  # connections to the redirection port open right now
    # KVM sessions open right now (in RFB). While one is, a real engine (AMT 16) did not list 8 (off) and 5 (cycle) among the
    # states it offers, and answered a request for either with 2; a test may count another viewer's in here too.
    kvm_open: int = 0
    session_ended_at: float = float("-inf")  # when the last KVM or serial session ended
    bars_linger: float = 0.0  # seconds after a session ended during which 8 and 5 stay barred (a real engine: about one)
    sol_recorded: bool = False  # "this session is being recorded" before the answer to the serial console's start
    power_answer_takes: float = 0.0  # seconds a power command takes before it is carried out and answered
    # Seconds after the PC was switched on (by a command) during which the redirection port answers no new session: a real
    # engine was too busy for one while its PC started (a session opened before went on through the start).
    starting_for: float = 0.0
    came_on_at: float = float("-inf")
    # The serial console (SOL) on the same port, as a real engine began it: its start answered with 23 bytes, a pong to
    # every ping. What the PC writes there is `sol_text`, a message each once the console has begun.
    sol_status: int = 0  # what the start of the console is answered with (0: begun)
    sol_text: list[bytes] = field(default_factory=list)
    sol_odd: str = ""  # "flood" | "huge" | "nonsense" | "silent" (no pong) | "ends" (the engine ends the console after its text)
    sol_sessions: int = 0  # consoles begun
    sol_open: int = 0  # ...open right now
    sol_pings: int = 0
    sol_ended: int = 0  # consoles ended by the console as the engine expects (its end, then the session's)
    sol_to_pc: list[bytes] = field(default_factory=list)  # anything sent to the PC over it (a reader that only reads sends none)
    # Starting into the BIOS setup (AMT_BootSettingData, CIM_BootService).
    boot_setup_supported: bool = True  # AMT_BootCapabilities.BIOSSetup: whether the engine can do it
    bios_setup_armed: bool = False  # AMT_BootSettingData.BIOSSetup as it stands (a Put sets it; a single-use boot clears it)
    secure_erase_armed: bool = False  # AMT_BootSettingData.SecureErase: a destructive boot another tool left armed
    role_returns: int = 0  # what SetBootConfigRole answers (ReturnValue): 0 done, else refused
    power_answer_empty: bool = False  # a power command is answered without a ReturnValue (an answer that cannot be read)
    boot_put_odd_once: str = ""  # the next Put of AMT_BootSettingData is made, and answered this way instead (see `odd`)
    boot_put_takes: float = 0.0  # seconds a Put of AMT_BootSettingData is answered after it was made
    erase_armed_meanwhile: bool = False  # another tool arms a secure erase while the wall makes its boot the next one
    boot_clear_fails: bool = False  # a Put of AMT_BootSettingData that clears BIOSSetup is answered with a fault (and not made)
    boot_role_set: int = 0  # how often SetBootConfigRole was called
    changes: list[tuple[str, str]] = field(default_factory=list)  # settings changed from the network: (class, what)
    requests: list[tuple[str, str]] = field(default_factory=list)  # every signed-in question: (what was asked, of which class)
    actions: list[int] = field(default_factory=list)  # the power states asked for
    logins: int = 0  # requests that carried a sign-in (right or wrong)
    rejections: int = 0  # ...of which were refused
    replays: int = 0  # ...of which were refused for their nonce count (strict_nc)
    unsigned: int = 0  # questions (POST) that carried no sign-in
    looks: int = 0  # GETs of /wsman without a sign-in: "are you there"
    stale_sent: int = 0
    nonces: dict[str, int] = field(default_factory=dict)  # the nonces handed out, and how often each was used
    contexts: dict[str, tuple[str, int]] = field(default_factory=dict)  # listings under way: handle -> (class, items handed out so far)


REALM = "Digest:" + "A3F7C2E1" * 4
# What a Put of AMT_BootSettingData must carry: the properties Intel's SDK marks put-required, and the four a real AMT 16
# engine refused a Put without as well ("the supplied SOAP violates the corresponding XML schema definition").
BOOT_PUT_REQUIRED = (
    "UseSOL", "UseSafeMode", "ReflashBIOS", "BIOSSetup", "BIOSPause", "LockPowerButton", "LockResetButton", "LockKeyboard",
    "LockSleepButton", "UserPasswordBypass", "ForcedProgressEvents", "FirmwareVerbosity", "ConfigurationDataReset",
    "IDERBootDevice", "UseIDER", "BootMediaIndex", "EnforceSecureBoot", "PlatformErase", "SecureErase", "UefiBootNumberOfParams",
)  # fmt: skip
KVM_BARS = (5, 8)  # the power states a real engine neither offers nor carries out while a KVM or serial session is open (cycle, off)
START_SOL = bytes((0x10, 0x00, 0x00, 0x00)) + b"SOL "  # the start of a serial console session, as on a real engine
_PAIR = re.compile(r'\s*([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,"]*))\s*(?:,|$)')
MESSAGE = re.compile(r"<a:MessageID>(uuid:[^<]{1,80})</a:MessageID>")

HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    f'<a:Envelope xmlns:a="{amt.SOAP}" xmlns:b="{amt.ADDRESSING}" xmlns:c="{amt.WSMAN_NS}" xmlns:d="{amt.TRANSFER}" xmlns:e="{amt.ENUMERATION}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
)


def realm_of(state: AmtState) -> str:
    return state.realm or REALM


def barring(state: AmtState) -> bool:
    """Whether a session stands in the way of cutting the power or cycling it: one is open, or ended a moment ago."""
    return bool(state.kvm_open or state.sol_open) or time.monotonic() - state.session_ended_at < state.bars_linger


def _fields(header: str, values: list[tuple[str, Any]]) -> str:
    """Properties of an instance as the engine writes them, in the order given (it writes them alphabetically)."""
    parts = []
    for name, value in values:
        if value is None:
            continue
        if isinstance(value, list):
            parts += [f"<g:{name}>{escape(str(one))}</g:{name}>" for one in value]
        elif isinstance(value, bool):
            parts.append(f"<g:{name}>{'true' if value else 'false'}</g:{name}>")
        else:
            parts.append(f"<g:{name}>{escape(str(value))}</g:{name}>")
    return f"<g:{header}>{''.join(parts)}</g:{header}>"


def _ref(name: str, resource: str, selectors: dict[str, str]) -> str:
    chosen = "".join(f'<c:Selector Name="{key}">{value}</c:Selector>' for key, value in selectors.items())
    return f"<g:{name}><b:Address>{amt.ANONYMOUS}</b:Address><b:ReferenceParameters><c:ResourceURI>{resource}</c:ResourceURI><c:SelectorSet>{chosen}</c:SelectorSet></b:ReferenceParameters></g:{name}>"


def make_fake_amt(state: AmtState) -> FastAPI:
    app = FastAPI()

    def power_now() -> int:
        if state.power_later and time.monotonic() >= state.power_later[0]:
            state.power, state.power_later = state.power_later[1], None
        return state.power

    def instances(short: str) -> list[str] | None:
        """Every instance of a class, as XML, with the prefix g: for its own namespace. None where the engine has no such class."""
        g = {"CIM": amt.CIM, "AMT": amt.AMT, "IPS": amt.IPS}.get(short.split("_")[0], "") + short
        kvm_classes = ("CIM_KVMRedirectionSAP", "IPS_KVMRedirectionSettingData", "IPS_OptInService")
        if state.kvm == "absent" and short in kvm_classes:
            return None
        consent = state.consent or state.control == 1
        if short == "CIM_AssociatedPowerManagementService":
            offered = [one for one in state.offered if not (barring(state) and one in KVM_BARS)]
            yield_ = _fields(short, [("AvailableRequestedPowerStates", offered or None), ("PowerState", power_now())])
            refs = _ref("ServiceProvided", amt.POWER_SERVICE, {"CreationClassName": "CIM_PowerManagementService", "Name": "Intel(r) AMT Power Management Service", "SystemCreationClassName": "CIM_ComputerSystem", "SystemName": "Intel(r) AMT"})
            refs += _ref("UserOfService", amt.COMPUTER, {"CreationClassName": "CIM_ComputerSystem", "Name": "ManagedSystem"})
            made = [yield_.replace(f"</g:{short}>", refs + f"</g:{short}>")]
        elif short == "CIM_Chassis":
            made = [_fields(short, [("ChassisPackageType", 35), ("CreationClassName", "CIM_Chassis"), ("ElementName", "Managed System Chassis"), ("Manufacturer", state.make), ("Model", state.model), ("OperationalStatus", 0), ("PackageType", 3), ("SerialNumber", state.serial), ("Tag", "CIM_Chassis"), ("Version", "1.0")])]
        elif short == "CIM_Card":
            made = [_fields(short, [("CreationClassName", "CIM_Card"), ("ElementName", "Managed System Base Board"), ("Manufacturer", state.board_make), ("Model", state.board_model), ("OperationalStatus", 0), ("PackageType", 9), ("SerialNumber", "BB0000000001"), ("Tag", "CIM_Card"), ("Version", "1.0")])]
        elif short == "CIM_Processor":
            made = [
                _fields(short, [
                    ("CPUStatus", 1), ("CreationClassName", "CIM_Processor"), ("CurrentClockSpeed", state.clock), ("DeviceID", f"CPU {number}"),
                    ("ElementName", "Managed System CPU"), ("EnabledState", 2), ("ExternalBusClockSpeed", 100), ("Family", state.family),
                    ("HealthState", 0), ("MaxClockSpeed", state.clock), ("OperationalStatus", 0), ("OtherFamilyDescription", state.other_family),
                    ("RequestedState", 12), ("Role", "Central"), ("Stepping", "10"), ("SystemCreationClassName", "CIM_ComputerSystem"),
                    ("SystemName", "ManagedSystem"), ("UpgradeMethod", 1),
                ])
                for number in range(state.processors)
            ]
        elif short == "CIM_PhysicalMemory":
            made = [
                _fields(short, [
                    ("BankLabel", f"BANK {number}"), ("Capacity", capacity), ("CreationClassName", "CIM_PhysicalMemory"), ("ElementName", "Managed System Memory Chip"),
                    ("FormFactor", 13), ("Manufacturer", "Example Memory"), ("MemoryType", 26), ("PartNumber", "EM-8G-2666"), ("SerialNumber", f"MM000000000{number}"),
                    ("Speed", 0), ("Tag", f"Physical Memory {number}"),
                ])
                for number, capacity in enumerate(state.memory)
            ]
        elif short == "CIM_BIOSElement":
            made = [_fields(short, [("ElementName", "Primary BIOS"), ("Manufacturer", "Example Computers"), ("Name", "Primary BIOS"), ("OperationalStatus", 0), ("PrimaryBIOS", True), ("ReleaseDate", "2024-06-01T00:00:00Z"), ("SoftwareElementID", state.bios), ("SoftwareElementState", 2), ("TargetOperatingSystem", 66), ("Version", state.bios)])]
        elif short == "CIM_SoftwareIdentity":
            named = [("Flash", state.version), ("Netstack", state.version), ("AMTApps", state.version), ("AMT", state.version), ("Sku", "16392"), ("VendorID", "8086"), ("Build Number", "1234"), ("Recovery Version", state.version), ("Recovery Build Num", "1234"), ("Legacy Mode", "False"), ("AMT FW Core Version", state.version)]
            made = [_fields(short, [("InstanceID", instance), ("IsEntity", True), ("VersionString", version)]) for instance, version in named]
        elif short == "CIM_ComputerSystemPackage":
            made = [_ref("Antecedent", amt.CHASSIS, {"CreationClassName": "CIM_Chassis", "Tag": "CIM_Chassis"}) + _ref("Dependent", amt.COMPUTER, {"CreationClassName": "CIM_ComputerSystem", "Name": "ManagedSystem"}) + (f"<g:PlatformGUID>{escape(str(state.guid))}</g:PlatformGUID>" if state.guid is not None else "")]
            made = [f"<g:{short}>{made[0]}</g:{short}>"]
        elif short == "AMT_GeneralSettings":
            made = [_fields(short, [("AMTNetworkEnabled", 1), ("DDNSUpdateByDHCPServerEnabled", True), ("DDNSUpdateEnabled", False), ("DigestRealm", realm_of(state)), ("DomainName", "example.test"), ("ElementName", "Intel(r) AMT: General Settings"), ("HostName", state.hostname), ("IdleWakeTimeout", 65535), ("InstanceID", "Intel(r) AMT: General Settings"), ("NetworkInterfaceEnabled", True), ("PingResponseEnabled", True), ("PowerSource", 0), ("PreferredAddressFamily", 0), ("PrivacyLevel", 0), ("RmcpPingResponseEnabled", True), ("SharedFQDN", True), ("WsmanOnlyMode", False)])]
        elif short == "IPS_HostBasedSetupService":
            made = [_fields(short, [("AllowedControlModes", [1, 2]), ("CertChainStatus", 0), ("ConfigurationNonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="), ("CreationClassName", "IPS_HostBasedSetupService"), ("CurrentControlMode", state.control), ("ElementName", "Intel(r) AMT Host Based Setup Service"), ("Name", "Intel(r) AMT Host Based Setup Service"), ("SystemCreationClassName", "CIM_ComputerSystem"), ("SystemName", "Intel(r) AMT")])]
        elif short == "IPS_KVMRedirectionSettingData":
            made = [_fields(short, [("BackToBackFbMode", False), ("DefaultScreen", 0), ("DoubleBufferMode", False), ("DoubleBufferState", False), ("ElementName", "Intel(r) KVM Redirection Settings"), ("EnabledByMEBx", state.kvm != "mebx"), ("InstanceID", "Intel(r) KVM Redirection Settings"), ("Is5900PortEnabled", False), ("OptInPolicy", consent), ("OptInPolicyTimeout", 300), ("RFBPassword", ""), ("SessionTimeout", state.session_timeout)])]
        elif short == "CIM_KVMRedirectionSAP":
            enabled = {"enabled": 6, "disabled": 3, "mebx": 3}.get(state.kvm, 3)
            made = [_fields(short, [("CreationClassName", "CIM_KVMRedirectionSAP"), ("ElementName", "KVM Redirection Service Access Point"), ("EnabledState", enabled), ("KVMProtocol", 4), ("Name", "KVM Redirection Service Access Point"), ("RequestedState", 2 if enabled != 3 else 3), ("SystemCreationClassName", "CIM_ComputerSystem"), ("SystemName", "ManagedSystem")])]
        elif short == "IPS_OptInService":
            made = [_fields(short, [("CanModifyOptInPolicy", 0 if state.control == 1 else 1), ("CreationClassName", "IPS_OptInService"), ("ElementName", "Intel(r) AMT OptIn Service"), ("Name", "Intel(r) AMT OptIn Service"), ("OptInCodeTimeout", 120), ("OptInDisplayTimeout", 300), ("OptInRequired", 1 if consent else 0), ("OptInState", 0), ("SystemCreationClassName", "CIM_ComputerSystem"), ("SystemName", "Intel(r) AMT")])]
        elif short == "AMT_RedirectionService":
            made = [_fields(short, [("CreationClassName", "AMT_RedirectionService"), ("ElementName", "Intel(r) AMT Redirection Service"), ("EnabledState", 32771), ("ListenerEnabled", state.listener), ("Name", "Intel(r) AMT Redirection Service"), ("SystemCreationClassName", "CIM_ComputerSystem"), ("SystemName", "Intel(r) AMT")])]
        elif short == "AMT_BootCapabilities":
            made = [_fields(short, [("BIOSSetup", state.boot_setup_supported), ("BIOSPause", False), ("ElementName", "Intel(r) AMT: Boot Capabilities"), ("ForceHardDriveBoot", True), ("ForcePXEBoot", True), ("IDER", True), ("InstanceID", "Intel(r) AMT:BootCapabilities 0"), ("SOL", True)])]
        elif short == "AMT_BootSettingData":
            made = [_fields(short, [
                ("BIOSLastStatus", [2, 0]), ("BIOSPause", False), ("BIOSSetup", state.bios_setup_armed), ("BootMediaIndex", 0),
                ("ConfigurationDataReset", False), ("ElementName", "Intel(r) AMT Boot Configuration Settings"), ("EnforceSecureBoot", False),
                ("FirmwareVerbosity", 0), ("ForcedProgressEvents", False), ("IDERBootDevice", 0), ("InstanceID", "Intel(r) AMT:BootSettingData 0"),
                ("LockKeyboard", False), ("LockPowerButton", False), ("LockResetButton", False), ("LockSleepButton", False),
                ("OptionsCleared", True), ("OwningEntity", "Intel(r) AMT"), ("PlatformErase", False), ("ReflashBIOS", False),
                ("SecureErase", state.secure_erase_armed), ("UefiBootNumberOfParams", 0), ("UseIDER", False), ("UseSOL", False), ("UseSafeMode", False),
                ("UserPasswordBypass", False),
            ])]  # fmt: skip
        elif short == "CIM_BootConfigSetting":
            made = [_fields(short, [("ElementName", "Intel(r) AMT: Boot Configuration"), ("InstanceID", amt.BOOT_CONFIG_INSTANCE)])]
        elif short == "CIM_BootService":
            made = [_fields(short, [("CreationClassName", "CIM_BootService"), ("ElementName", "Intel(r) AMT Boot Service"), ("EnabledState", 32769), ("Name", "Intel(r) AMT Boot Service"), ("SystemCreationClassName", "CIM_ComputerSystem"), ("SystemName", "Intel(r) AMT")])]
        else:
            return None
        return [one.replace(f"<g:{short}>", f'<g:{short} xmlns:g="{g}">', 1) for one in made]

    def envelope(action: str, relates: str, body: str, resource: str = "") -> Response:
        header = f"<a:Header><b:To>{amt.ANONYMOUS}</b:To><b:RelatesTo>{relates}</b:RelatesTo><b:Action a:mustUnderstand=\"true\">{action}</b:Action><b:MessageID>uuid:{secrets.token_hex(16)}</b:MessageID><c:ResourceURI>{resource}</c:ResourceURI></a:Header>"
        return Response(f"{HEAD}>{header}<a:Body>{body}</a:Body></a:Envelope>", media_type="application/soap+xml; charset=UTF-8")

    def fault(relates: str, subcode: str, reason: str, status: int = 400) -> Response:
        body = f"<a:Fault><a:Code><a:Value>a:Sender</a:Value><a:Subcode><a:Value>b:{subcode}</a:Value></a:Subcode></a:Code><a:Reason><a:Text xml:lang=\"en-US\">{escape(reason)}</a:Text></a:Reason><a:Detail></a:Detail></a:Fault>"
        answer = envelope(f"{amt.ADDRESSING}/fault", relates, body)
        answer.status_code = status
        return answer

    def challenge(stale: bool = False) -> Response:
        nonce = secrets.token_hex(16)
        state.nonces[nonce] = 0
        if state.basic_only:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="Intel(r) AMT"'})
        said = f'Digest realm="{realm_of(state)}", nonce="{nonce}", stale="{"true" if stale else "false"}", qop="auth"'
        return Response(status_code=401, headers={"WWW-Authenticate": said})

    def signed_in(request: Request) -> Response | None:
        """The 401 that stands against this request, or None where its sign-in is good."""
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("digest "):
            if request.method == "GET":
                state.looks += 1
            else:
                state.unsigned += 1
            if state.unsigned_status is not None:
                return Response("busy", status_code=state.unsigned_status, media_type="text/plain")
            return challenge()
        state.logins += 1
        fields: dict[str, str] = {}
        at, rest = 0, header[7:]
        while at < len(rest):
            pair = _PAIR.match(rest, at)
            if pair is None:
                break
            name, quoted, bare = pair.groups()
            fields[name.lower()] = quoted if quoted is not None else bare
            at = pair.end()
        nonce = fields.get("nonce", "")

        def md5(*parts: str) -> str:
            return hashlib.md5(":".join(parts).encode()).hexdigest()

        first = md5(fields.get("username", ""), fields.get("realm", ""), state.password)  # (made with the realm the answer names)
        second = md5(request.method, fields.get("uri", ""))
        expected = md5(first, nonce, fields.get("nc", ""), fields.get("cnonce", ""), fields.get("qop", ""), second)
        good = fields.get("username") == state.username and (fields.get("realm") == realm_of(state) or not state.checks_realm) and fields.get("uri") == amt.WSMAN and fields.get("response") == expected
        if not good:
            state.rejections += 1
            return challenge()
        if nonce not in state.nonces or state.stale_once or (state.nonce_uses and state.nonce_used.get(nonce, 0) >= state.nonce_uses):
            state.stale_once, state.stale_sent = False, state.stale_sent + 1
            return challenge(stale=not state.forgets_without_saying)  # the password was right, the nonce had run out: told so, and asked again
        count = int(fields.get("nc", "0") or "0", 16)
        if state.strict_nc and count <= state.nonces[nonce]:
            state.replays += 1
            return challenge()  # a count that did not grow is a replay, to an engine that checks: a plain no
        state.nonces[nonce] = max(state.nonces[nonce] + 1, count)
        state.nonce_used[nonce] = state.nonce_used.get(nonce, 0) + 1
        return None

    @app.middleware("http")
    async def says_what_it_is(request: Request, call_next: Any) -> Any:
        answer = await call_next(request)
        if not state.without_server_header:
            answer.headers["Server"] = SERVER
        return answer

    @app.get("/")
    @app.get("/index.htm")
    async def index() -> Response:
        return Response("<!doctype html><html><head><title>Intel&reg; Active Management Technology</title></head><body>Stand-in</body></html>", media_type="text/html")

    @app.get(amt.WSMAN)
    async def asked_the_wrong_way(request: Request) -> Response:
        return signed_in(request) or Response(status_code=405)

    @app.post(amt.WSMAN)
    async def wsman(request: Request) -> Response:
        refused = signed_in(request)
        if refused is not None:
            return refused
        if state.sign_in_takes:
            await asyncio.sleep(state.sign_in_takes)
        raw = await request.body()
        relates = MESSAGE.search(raw.decode("utf-8", "replace"))
        relates_to = relates.group(1) if relates else "uuid:unknown"
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return fault(relates_to, "InvalidMessageInformationHeader", "The message could not be read", 500)
        header = root.find(f"{{{amt.SOAP}}}Header")
        body = root.find(f"{{{amt.SOAP}}}Body")
        action = header.findtext(f"{{{amt.ADDRESSING}}}Action", "") if header is not None else ""
        resource = header.findtext(f"{{{amt.WSMAN_NS}}}ResourceURI", "") if header is not None else ""
        short = resource.rsplit("/", 1)[-1]
        what = action.rsplit("/", 1)[-1]
        state.requests.append((what, short))
        if state.refuses_after_sign_in and short != "AMT_GeneralSettings":
            return challenge()  # let in, and then said no to: what no engine does, and a wall must bear all the same
        odd = state.odd.get(short) or state.odd.get("*")
        if odd is not None:
            return oddly(odd, relates_to)
        nowhere = "No route can be determined to reach the destination role defined by the WS-Addressing To."
        if what == "Get":
            found = instances(short)
            if found is None:
                return fault(relates_to, "DestinationUnreachable", nowhere)
            if not found:
                return fault(relates_to, "DestinationUnreachable", "The requested instance does not exist.")
            return envelope(f"{amt.TRANSFER}/GetResponse", relates_to, found[0], resource)
        if what == "Enumerate":
            if instances(short) is None:
                return fault(relates_to, "DestinationUnreachable", nowhere)
            handle = f"{secrets.token_hex(4).upper()}-0000-0000-0000-000000000000"
            state.contexts[handle] = (short, 0)
            return envelope(f"{amt.ENUMERATION}/EnumerateResponse", relates_to, f"<e:EnumerateResponse><e:EnumerationContext>{handle}</e:EnumerationContext></e:EnumerateResponse>", resource)
        if what == "Pull":
            handed = body.findtext(f"{{{amt.ENUMERATION}}}Pull/{{{amt.ENUMERATION}}}EnumerationContext", "") if body is not None else ""
            if handed not in state.contexts:
                return fault(relates_to, "InvalidEnumerationContext", "The supplied enumeration context is invalid.")
            of, given = state.contexts[handed]
            found = instances(of) or []
            each = max(1, -(-len(found) // state.pages))  # (this many a page, the last page shorter)
            page = found[given : given + each]
            given += len(page)
            over = given >= len(found)
            if over:
                del state.contexts[handed]
                tail = "<e:EndOfSequence/>"
            else:
                state.contexts[handed] = (of, given)
                tail = f"<e:EnumerationContext>{handed}</e:EnumerationContext>"
            return envelope(f"{amt.ENUMERATION}/PullResponse", relates_to, f"<e:PullResponse><e:Items>{''.join(page)}</e:Items>{tail}</e:PullResponse>", resource)
        if what == "RequestPowerStateChange" and short == "CIM_PowerManagementService":
            asked = body.findtext(f"{{{amt.POWER_SERVICE}}}RequestPowerStateChange_INPUT/{{{amt.POWER_SERVICE}}}PowerState", "") if body is not None else ""
            wanted = int(asked) if asked.isdigit() else -1
            if state.power_answer_takes:
                await asyncio.sleep(state.power_answer_takes)
            state.actions.append(wanted)
            barred = barring(state) and wanted in KVM_BARS  # (a real engine answered 2 then, and did nothing)
            returned = state.returns if state.returns is not None else 0 if (not state.offered or wanted in state.offered) and not barred else 2
            if returned == 0 and wanted not in state.drops:
                becomes = {2: 2, 3: 3, 4: 4, 7: 7, 8: 8, 6: 6, 12: 8, 13: 6}.get(wanted, 2)  # a reset or a cycle ends on
                if becomes == 2:
                    state.came_on_at = time.monotonic()
                if wanted in (2, 5, 10) and state.bios_setup_armed:
                    state.bios_setup_armed = False  # a boot into the setup is single-use: it clears on the next power-on, reset or cycle
                if state.power_takes:
                    state.power_later = (time.monotonic() + state.power_takes, becomes)
                else:
                    state.power = becomes
            said_back = "" if state.power_answer_empty else f"<g:ReturnValue>{returned}</g:ReturnValue>"
            out = f'<g:RequestPowerStateChange_OUTPUT xmlns:g="{amt.POWER_SERVICE}">{said_back}</g:RequestPowerStateChange_OUTPUT>'
            return envelope(f"{amt.POWER_SERVICE}/RequestPowerStateChangeResponse", relates_to, out, resource)
        if what == "RequestStateChange" and short == "CIM_KVMRedirectionSAP":
            asked = body.findtext(f"{{{amt.KVM_SAP}}}RequestStateChange_INPUT/{{{amt.KVM_SAP}}}RequestedState", "") if body is not None else ""
            state.changes.append((short, asked))
            returned = 5 if asked not in ("2", "3") else 0
            if returned == 0 and state.kvm in ("enabled", "disabled"):
                state.kvm = "enabled" if asked == "2" else "disabled"
            out = f'<g:RequestStateChange_OUTPUT xmlns:g="{amt.KVM_SAP}"><g:ReturnValue>{returned}</g:ReturnValue></g:RequestStateChange_OUTPUT>'
            return envelope(f"{amt.KVM_SAP}/RequestStateChangeResponse", relates_to, out, resource)
        if what == "Put" and short == "AMT_RedirectionService":
            if state.put_fails:
                return fault(relates_to, "InternalError", "The service cannot comply with the request due to internal processing errors.", 500)
            given = body.find(f"{{{amt.REDIRECTION}}}AMT_RedirectionService") if body is not None else None
            if given is None:
                return fault(relates_to, "SchemaValidationError", "The supplied SOAP violates the corresponding XML schema definition.")
            said = {amt.local(child.tag): (child.text or "") for child in given}
            # As the class reference has it: the keys must come along, and as they are.
            keys = {"CreationClassName": "AMT_RedirectionService", "Name": "Intel(r) AMT Redirection Service", "SystemCreationClassName": "CIM_ComputerSystem", "SystemName": "Intel(r) AMT"}
            if any(said.get(key) != value for key, value in keys.items()) or "ListenerEnabled" not in said:
                return fault(relates_to, "SchemaValidationError", "The supplied SOAP violates the corresponding XML schema definition.")
            state.listener = said["ListenerEnabled"] == "true"
            state.changes.append((short, f"ListenerEnabled={said['ListenerEnabled']}"))
            return envelope(f"{amt.TRANSFER}/PutResponse", relates_to, instances(short)[0], resource)  # type: ignore[index]
        if what == "Put" and short == "AMT_BootSettingData":
            given = body.find(f"{{{amt.BOOT_SETTINGS}}}AMT_BootSettingData") if body is not None else None
            if given is None:
                return fault(relates_to, "SchemaValidationError", "The supplied SOAP violates the corresponding XML schema definition.")
            said = {amt.local(child.tag): (child.text or "") for child in given}
            # The keys must come along (InstanceID is the one key here); and, as a real engine (AMT 16) refused a Put that left
            # any of them out, every put-required property this instance has.
            if said.get("InstanceID") != "Intel(r) AMT:BootSettingData 0" or any(key not in said for key in BOOT_PUT_REQUIRED):
                return fault(relates_to, "SchemaValidationError", "The supplied SOAP violates the corresponding XML schema definition.")
            if state.boot_clear_fails and said.get("BIOSSetup") != "true":
                return fault(relates_to, "InternalError", "The service cannot comply with the request due to internal processing errors.", 500)
            state.bios_setup_armed = said.get("BIOSSetup") == "true"
            if "SecureErase" in said:
                state.secure_erase_armed = said.get("SecureErase") == "true"
            state.changes.append((short, f"BIOSSetup={said.get('BIOSSetup')}"))
            if state.boot_put_takes:
                await asyncio.sleep(state.boot_put_takes)  # (made, and answered late)
            if state.boot_put_odd_once:
                how, state.boot_put_odd_once = state.boot_put_odd_once, ""
                return oddly(how, relates_to)  # (made, and its answer one that cannot be read)
            return envelope(f"{amt.TRANSFER}/PutResponse", relates_to, instances(short)[0], resource)  # type: ignore[index]
        if what == "SetBootConfigRole" and short == "CIM_BootService":
            role = body.findtext(f"{{{amt.BOOT_SERVICE}}}SetBootConfigRole_INPUT/{{{amt.BOOT_SERVICE}}}Role", "") if body is not None else ""
            state.boot_role_set += 1
            state.changes.append((short, f"Role={role}"))
            if state.erase_armed_meanwhile:
                state.secure_erase_armed, state.erase_armed_meanwhile = True, False  # (another tool, at this moment)
            out = f'<g:SetBootConfigRole_OUTPUT xmlns:g="{amt.BOOT_SERVICE}"><g:ReturnValue>{state.role_returns}</g:ReturnValue></g:SetBootConfigRole_OUTPUT>'
            return envelope(f"{amt.BOOT_SERVICE}/SetBootConfigRoleResponse", relates_to, out, resource)
        return fault(relates_to, "ActionNotSupported", "The action is not supported by the service.")

    def oddly(how: str, relates_to: str) -> Response:
        """An answer of the wrong kind, as something at that address that is no engine (or a broken one) would give."""
        if how == "json":
            return JSONResponse({"ok": True, "result": {}})
        if how == "html":
            return Response("<!doctype html><title>Sign in</title><p>Somebody's web page.</p>", media_type="text/html")
        if how == "refused_page":
            return Response("<!doctype html><title>Bad Request</title><p>Bad Request</p>", status_code=400, media_type="text/html")
        if how == "nonsense":
            return Response("this is not XML <<<", media_type="application/soap+xml; charset=UTF-8")
        if how == "doctype":
            lol = '<!DOCTYPE a [<!ENTITY x "xxxxxxxxxx"><!ENTITY y "&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;">]>'
            return Response(f"{lol}{HEAD}><a:Body>&y;</a:Body></a:Envelope>", media_type="application/soap+xml; charset=UTF-8")
        if how == "no_body":
            return Response(f"{HEAD}><a:Header></a:Header></a:Envelope>", media_type="application/soap+xml; charset=UTF-8")
        if how == "fault":
            return fault(relates_to, "AccessDenied", "The sender was not authorized to access the resource.")
        if how == "fault_other":
            return fault(relates_to, "InternalError", "The service cannot comply with the request due to internal processing errors.", 500)
        if how == "huge":

            async def more_than_anybody_needs() -> Any:
                yield f"{HEAD}><a:Body><g:Padding>".encode()
                for _ in range(40):
                    yield b"x" * 65536
                    await asyncio.sleep(0)
                yield b"</g:Padding></a:Body></a:Envelope>"

            return StreamingResponse(more_than_anybody_needs(), media_type="application/soap+xml; charset=UTF-8")
        if how == "slow":

            async def a_byte_every_so_often() -> Any:
                yield f"{HEAD}><a:Body>".encode()
                for _ in range(600):
                    yield b" "
                    await asyncio.sleep(0.1)
                yield b"</a:Body></a:Envelope>"

            return StreamingResponse(a_byte_every_so_often(), media_type="application/soap+xml; charset=UTF-8")
        raise RuntimeError(f"no such oddity: {how}")

    return app


class FakeRedirection(FakeVnc):
    """The engine's redirection port: Intel's handshake (start, which sign-ins, Digest, "the KVM may begin"), then the
    KVM as RFB, which the VNC stand-in speaks with the manners of a real engine's (see `amt_screen`).

    Built from what a real engine (AMT 16) was seen to send, byte for byte, and from MeshCommander's published source
    for what it was not seen to send (the answer to a wrong password is not known: here it is "not so", 1, and the
    connection ends). It can be told to answer otherwise (`AmtState.redirect_odd`).
    """

    def __init__(self, amt_state: AmtState, sock: socket.socket, tls_dir: Path | None) -> None:
        super().__init__(amt_state.screen, tls_dir=tls_dir, sock=sock)
        self.amt = amt_state

    async def _handle(self, wire: Any) -> None:
        self.amt.redirections += 1
        self.amt.redirected_at.append(time.monotonic())
        self.amt.redirection_open += 1
        try:
            await super()._handle(wire)
        finally:
            self.amt.redirection_open -= 1

    async def _session(self, wire: Any) -> None:
        state = self.amt
        if not state.listener:
            return  # (a real engine does not listen at all then; hung up on at once is as near as a stand-in gets)
        if time.monotonic() - state.came_on_at < state.starting_for:
            await asyncio.sleep(state.starting_for)  # (no answer while the PC starts: the session is not begun)
            return
        odd = state.redirect_odd
        start = await wire.read(8)
        if odd == "not_redirection":
            await wire.write(b"HTTP/1.1 400 Bad Request" + bytes((13, 10, 13, 10)))
            return
        sol = start == START_SOL
        if start != amt.START_KVM and not sol:
            return
        status = state.start_status if state.start_status is not None else (0 if state.kvm == "enabled" or sol else 1)
        await wire.write(bytes((amt.STARTED, status, 0, 0, 1, 0, 12, 0, 0, 0, 0, 0, 0)))  # (a reply of a real engine's shape: versions, and no maker's part)
        if status:
            return
        query = await wire.read(9)
        if query[0] != amt.AUTHENTICATE or query[4] != amt.QUERY:
            return
        if odd == "huge_answer":
            await wire.write(bytes((amt.AUTHENTICATED, 0, 0, 0, amt.QUERY)) + (2**31).to_bytes(4, "little"))
            await asyncio.sleep(2)
            return
        await wire.write(bytes((amt.AUTHENTICATED, 0, 0, 0, amt.QUERY)) + len(state.auth_types).to_bytes(4, "little") + bytes(state.auth_types))
        named = await self._sign_in(wire)
        if named is None or named[1] or named[2]:
            return  # (the first Digest message names the account and where, and nothing else)
        if odd == "slow_challenge":
            await asyncio.sleep(1.0)  # (the challenge takes its time: a no may be heard on the other port meanwhile)
        if state.challenge_takes:
            await asyncio.sleep(state.challenge_takes)
        nonce = secrets.token_hex(16)
        offered = [realm_of(state).encode(), nonce.encode(), b"auth"]
        data = b"".join(bytes((len(text),)) + text for text in offered)
        await wire.write(bytes((amt.AUTHENTICATED, amt.ASKING, 0, 0, amt.DIGEST)) + len(data).to_bytes(4, "little") + data)
        answer = await self._sign_in(wire)
        if answer is None:
            return
        state.redirection_logins += 1
        if state.answer_takes:
            await asyncio.sleep(state.answer_takes)  # (the password is out, and its answer takes its time)
        if odd == "hang_up":
            return  # (the password went out, and nothing came back)
        if odd == "stall":
            await asyncio.sleep(3600)
        user, realm, said_nonce, uri, cnonce, nc, response, qop = (text.decode("latin-1") for text in answer)

        def md5(text: str) -> str:
            return hashlib.md5(text.encode()).hexdigest()

        password = state.password if state.redirection_password is None else state.redirection_password
        expected = md5(f"{md5(f'{user}:{realm}:{password}')}:{nonce}:{nc}:{cnonce}:{qop}:{md5(f'POST:{uri}')}")
        good = user == state.username and realm == realm_of(state) and said_nonce == nonce and uri == amt.REDIRECTION_URI and qop == "auth" and response == expected
        if odd == "neither":
            await wire.write(bytes((amt.AUTHENTICATED, 7, 0, 0, amt.DIGEST, 0, 0, 0, 0)))
            return
        if not good:
            state.redirection_rejections += 1
            await wire.write(bytes((amt.AUTHENTICATED, amt.ASKING, 0, 0, amt.DIGEST, 0, 0, 0, 0)))
            return
        await wire.write(bytes((amt.AUTHENTICATED, amt.ACCEPTED, 0, 0, amt.DIGEST, 0, 0, 0, 0)))
        if sol:
            await self._serial_console(wire)
            return
        if await wire.read(8) != amt.KVM_GO:
            return
        if odd == "wrong_end":
            await wire.write(bytes((0x42, 0, 0, 0, 0, 0, 0, 0)))
            return
        await wire.write((bytes((amt.RECORDED,)) if odd == "recorded" else b"") + bytes((amt.KVM_GOING, 0, 0, 0, 0, 0, 0, 0)))
        if odd == "not_rfb":
            await wire.write(b"<html><body>no screen here</body></html>")
            await asyncio.sleep(1)
            return
        state.kvm_sessions += 1
        state.kvm_open += 1
        try:
            ending = state.next_session_ends_when
            state.next_session_ends_when = None
            first = state.kvm_sessions == 1 and (state.first_session_ends_at_request or state.first_session_ends_after_keys)
            if ending is not None or first or state.sessions_end_after_requests:
                asked, keyed = len(state.screen.requests), len(state.screen.keys)

                def going_on() -> bool:
                    if ending is not None:
                        return not ending.is_set()
                    if not first:
                        return len(state.screen.requests) < asked + state.sessions_end_after_requests
                    if state.first_session_ends_at_request:
                        return len(state.screen.requests) == asked
                    return len(state.screen.keys) < keyed + state.first_session_ends_after_keys

                serving = asyncio.ensure_future(super()._session(wire))
                try:
                    while not serving.done() and going_on():
                        await asyncio.sleep(0.005)  # (waiting for the request or the keys, however long the viewer takes)
                finally:
                    serving.cancel()
                    await asyncio.gather(serving, return_exceptions=True)
                return  # (the connection simply ends, as at the engine's own time)
            lasts = state.session_lasts
            if lasts:
                try:
                    async with asyncio.timeout(lasts):
                        await super()._session(wire)
                except TimeoutError:
                    pass  # (the engine's SessionTimeout: the connection simply ends, as a real one's did)
                return
            await super()._session(wire)
        finally:
            state.kvm_open -= 1
            state.session_ended_at = time.monotonic()

    async def _serial_console(self, wire: Any) -> None:
        """The serial console once the sign-in is taken: its start (24 bytes) answered as a real engine answered it, then what
        the PC writes, a pong to every ping, and the console's end answered."""
        state = self.amt
        begun = await wire.read(24)
        if begun[0] != 0x20:
            return
        if state.sol_recorded:
            await wire.write(bytes((0xF0,)))
        await wire.write(bytes((0x21, state.sol_status, 0, 0, 1, 0, 0, 0, 1, 0, 0x10, 0x01, 0x00, 0x20, 0x01, 0, 0, 0, 0x57, 0x01, 0, 0, 0)))
        if state.sol_status:
            return
        state.sol_sessions += 1
        state.sol_open += 1

        def text(data: bytes) -> bytes:
            return bytes((0x2A, 0, 0, 0, 1, 0, 0, 0)) + len(data).to_bytes(2, "little") + data

        async def writes() -> None:
            if state.sol_odd == "nonsense":
                await wire.write(bytes((0x77,)) + bytes(7))
                return
            if state.sol_odd == "huge":
                await wire.write(bytes((0x2A, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0xFF)) + b"x" * 1000)
                return
            for piece in state.sol_text:
                await wire.write(text(piece))
            if state.sol_odd == "flood":
                while True:
                    await wire.write(text(b"y" * 200) * 50)
                    await asyncio.sleep(0)
            if state.sol_odd == "ends":
                await wire.write(bytes((0x23, 0, 0, 0, 1, 0, 0, 0)))

        writing = asyncio.create_task(writes())
        try:
            while True:
                head = await wire.read(8)
                if head[0] == 0x24:
                    state.sol_pings += 1
                    if state.sol_odd != "silent":
                        await wire.write(bytes((0x25,)) + head[1:])
                elif head[0] == 0x28:
                    length = int.from_bytes(await wire.read(2), "little")
                    state.sol_to_pc.append(await wire.read(length))
                elif head[0] == 0x22:
                    await wire.write(bytes((0x23,)) + head[1:])
                    if (await wire.read(4))[0] == 0x12:
                        state.sol_ended += 1
                    return
                else:
                    return
        except Exception:
            return  # (the console went away)
        finally:
            writing.cancel()
            state.sol_open -= 1
            state.session_ended_at = time.monotonic()

    @staticmethod
    async def _sign_in(wire: Any) -> list[bytes] | None:
        """The eight texts of a Digest sign-in message, or None where it is no such message."""
        head = await wire.read(9)
        if head[0] != amt.AUTHENTICATE or head[4] != amt.DIGEST:
            return None
        data = await wire.read(int.from_bytes(head[5:9], "little"))
        try:
            return amt.texts_of(data, 8)
        except Exception:
            return None


def amt_screen() -> VncState:
    """What the KVM of a real engine (AMT 16) was seen to be, in RFB: it greets as "RFB 004.000" and speaks 3.8, offers
    None and a type of its own (128), says its screen is RGB565, hangs up at any other number of bits a pixel, rings the
    bell before its first answer, answers the first request with the screen's size alone, sends Raw, and drops the keys
    that come within moments of the handshake (0.05 and 0.15 s after it were lost there, 0.3 s and later were not)."""
    return VncState(
        password=None,
        version=b"RFB 004.000" + bytes((10,)),
        offers=(1, 128),
        width=320,
        height=200,
        name="Intel(r) AMT KVM",
        encoding="raw",
        server_format=PixelFormat(16, 16, False, True, 31, 63, 31, 11, 5, 0),
        takes_bpp=(16,),
        bell_first=True,
        size_first=True,
        drops_keys_for=0.3,
    )


class FakeAmt:
    """Runs make_fake_amt() on a localhost port in a background thread, and its redirection port beside it.

    `tls_dir`: serve TLS with the certificate kept in that folder, as the engine does on its port 16993 (and on 16995,
    with the same certificate); without it, plain HTTP as on 16992. The redirection port is the WS-Management port and
    two, as 16995 is beside 16993 on every engine; the program knows it only beside those two ports (amt.REDIRECTION_BESIDE),
    and is told this one while the stand-in runs (`beside`: not told, as an engine behind a forwarded port is not known).
    """

    def __init__(self, state: AmtState | None = None, port: int = 0, tls_dir: Path | None = None, redirection_tls_dir: Path | None = None, beside: bool = True) -> None:
        """`redirection_tls_dir`: a certificate of its own on the redirection port (a real engine shows the one on both)."""
        self.beside = beside
        self.state = state or AmtState()
        self._sock, redirection = self._pair(port)
        self.port: int = self._sock.getsockname()[1]
        tls = {}
        if tls_dir is not None:
            cert, key = make_device_certificate(tls_dir)
            tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"
        self._server = uvicorn.Server(uvicorn.Config(make_fake_amt(self.state), log_level="error", access_log=False, **tls))
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True)
        self.redirection = FakeRedirection(self.state, redirection, redirection_tls_dir or tls_dir)

    @staticmethod
    def _pair(port: int) -> tuple[socket.socket, socket.socket]:
        """A socket for WS-Management and one for the redirection port two above it, both bound."""
        for _ in range(50):
            first = local_socket(port)
            try:
                if first.getsockname()[1] + 2 > 65535:
                    raise OSError("no port two above it")  # (the system handed out 65534 or 65535: bind() would raise OverflowError)
                return first, local_socket(first.getsockname()[1] + 2)
            except OSError:
                first.close()
                if port:
                    raise
        raise RuntimeError("no two free ports two apart")

    def start(self) -> FakeAmt:
        if self.beside:
            amt.REDIRECTION_BESIDE[self.port] = self.port + 2
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake Intel AMT machine did not start")
            time.sleep(0.02)
        self.redirection.start()
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
        self.redirection.stop()
        if self.beside and amt.REDIRECTION_BESIDE.get(self.port) == self.port + 2 and self.port not in (16992, 16993):
            del amt.REDIRECTION_BESIDE[self.port]
