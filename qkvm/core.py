"""State shared by the HTTP layer: what is saved, who is logged in, which devices are live."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any


from . import activity, unlock
from .alerts import Watcher
from .forward import Syslog
from .history import FILE as HISTORY_FILE
from .history import History
from .kvm import Device, DeviceSpec, KvmDevice, saved_mark
from .netbind import lan_ip, tailscale_ip
from .security import Limiter, Sessions, proxy_networks
from .store import FINGERBOT_STRENGTHS, AuditLog, DeviceRecord, Store, UserRecord, activity_file_bytes
from .tlscert import certificate_fingerprint, ensure_certificate
from .update import GITHUB_API, Updater
from .vault import NoMemory, Vault

log = logging.getLogger("qkvm")
RESTART = 75  # exit status that makes `python -m qkvm` start the wall again (see __main__.py)


class Core:
    """Everything that outlives a listener restart: saved state, the vault key, sessions."""

    def __init__(
        self,
        data_dir: Path,
        bind_override: list[str] | None = None,
        port_override: int | None = None,
        update_repo: str | None = None,
        allow_unsigned_updates: bool = False,
        trusted_proxies: Iterable[str] = (),
        allow_from: Iterable[str] = (),
        https: bool = False,
        tls_files: tuple[Path, Path] | None = None,
        unlock_secret: str | None = None,
        sso_header: str | None = None,
        audit_syslog: str | None = None,
        setup_code: bool = False,
        locked_start: bool = False,
        vault_key_file: Path | None = None,
    ) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        # Validate the external storage key before touching automatic-unlock keys or sessions.
        # A missing key or an unmigrated legacy vault must never become a fresh setup.
        self.store = Store(data_dir / "qkvm.json", vault_key_file=vault_key_file, protected=True)
        # The only addresses that are answered at all, if any were named (see security.client_allowed).
        self.allowed_clients = proxy_networks(allow_from)
        # HTTPS because it was said at start, whatever the settings say; and with whose certificate.
        self.https_forced = https or tls_files is not None
        self.tls_files = tls_files  # (certificate, key) of the owner's own, instead of one made here
        # Proxies in front of qKVM that are believed about who is calling (see security.client_ip).
        self.trusted_proxies = proxy_networks(trusted_proxies)
        # What opens the saved passwords without anybody signing in, so that qKVM carries on by itself after a
        # restart (see unlock.py): what the unlock file given at start holds; or, as it comes, a key of its own
        # in the data folder; or nothing, where it was started with --locked-start.
        self.locked_start = locked_start
        self.own_key = False
        self.key_unread: str | None = None  # why qKVM's own key could not be read or made at this start, where it could not
        self.key_left: str | None = None  # why it could not be taken out of the data folder, where it was to be
        if unlock_secret is None and not locked_start:
            try:
                unlock_secret, self.own_key = unlock.own_secret(data_dir), True
            except OSError as ex:
                self.key_unread = ex.strerror or type(ex).__name__
                log.error("no key could be kept in %s to carry on after a restart: %s", data_dir, self.key_unread)
        else:
            try:
                unlock.forget_own(data_dir)
            except OSError as ex:
                self.key_left = ex.strerror or type(ex).__name__
                log.error("the key in %s that opens the saved passwords could not be taken away (%s): a copy of the folder still opens them", data_dir, self.key_left)
        self.unlock_secret = unlock_secret
        # The header in which a named reverse proxy says who it has signed in (see security.sso_name). None: nobody is believed.
        self.sso_header = sso_header
        self.data_dir = data_dir
        self.started = time.time()
        # The activity log, and where a copy of each entry is sent as it is written (--audit-syslog); ValueError for no such place.
        self.audit = AuditLog(
            data_dir / "audit.log",
            max_bytes=activity_file_bytes(self.store.server.activity_mb),
            forward=Syslog(audit_syslog).send if audit_syslog is not None else None,
        )
        # ...and its index for the page's filters and search (see activity.py), made from those files and from nothing else,
        # told by the log's writer that there is more and never waited for; its thread is started with the wall.
        self.activity = activity.Index(data_dir / activity.FILE, self.audit)
        self.audit.on_written = self.activity.wake
        activity.leftover_downloads(data_dir)  # (what a power cut left of a download in the making)
        self.vault = Vault()
        # Browsers that asked to be kept signed in outlast a restart, where the saved passwords open by
        # themselves after one. Where they do not, a sign-in that outlasted it would be one to a wall that shows
        # nothing, and that nothing would ask for the sign-in that opens it. So they are taken up again only
        # once the saved passwords have in fact been opened: see unlock_at_start.
        self.sessions = Sessions(data_dir / "sessions.json")
        if self.unlock_secret is None:
            # Started with --locked-start, or the key could not be read this once: none is kept, and what was
            # is taken away. (Left lying for the next start, they were taken up by it whoever had signed out,
            # or switched a second step on, in a run that could write none of that down.)
            self.sessions.forget_kept()
        self.limiter = Limiter()
        # What each machine was last seen as, for alerts: kept over a restart, and over the listeners being reopened.
        self.watcher = Watcher(data_dir / "watch.json")
        # What the wall saw of each machine, kept for a while (see history.py): opened by its own thread once the wall serves.
        self.history = History(data_dir / HISTORY_FILE, limits=lambda: (self.store.server.history_days, self.store.server.history_mb))
        # Where qKVM was started with --setup-code: printed where it runs, and asked of whoever sets the first
        # password from another computer, as proof that they can see that. None: nothing is asked but the
        # password, and whoever opens a new wall first chooses it.
        self.setup_code: str | None = f"{secrets.randbelow(10**8):08d}" if setup_code else None
        self.bind_override = bind_override
        self.port_override = port_override
        self.listening: list[str] = []  # URLs being served right now
        self.addresses: list[str] = []  # the addresses the listeners were opened on
        self.missing: list[str] = []  # bind names that had no address at startup
        self.bind_error: str | None = None
        self.cert_fingerprint: str | None = None if tls_files is None else certificate_fingerprint(tls_files[0])
        self.restart_requested = False
        self.stop: Callable[[], None] | None = None  # set by the runner; ends the current listener
        self.exit_status: int | None = None  # set to leave the program altogether with this status
        self.supervised = False  # started by `python -m qkvm`, which can start us again
        self.container = os.environ.get("QKVM_CONTAINER") == "1"  # set in the Docker image
        self.updater = Updater(
            data_dir,
            update_repo or os.environ.get("QKVM_UPDATE_REPO") or None,
            # For a GitHub Enterprise server, or a stand-in when testing.
            api=os.environ.get("QKVM_UPDATE_API") or GITHUB_API,
            allow_unsigned=allow_unsigned_updates,
        )

    def _still_let_in(self, user_id: str, mark: str) -> bool:
        """Whether a browser that was kept signed in for this account is still to be let in after a restart."""
        user = self.store.user(user_id)
        return user is not None and not user.suspended and auth_mark(user) == mark

    @property
    def initialized(self) -> bool:
        return bool(self.store.users)

    @property
    def bind(self) -> list[str]:
        return self.bind_override or self.store.server.bind

    @property
    def port(self) -> int:
        return self.port_override or self.store.server.port

    @property
    def https(self) -> bool:
        """Whether browsers are served over HTTPS: switched on in the settings, or said at start."""
        return self.https_forced or self.store.server.https

    def prepare_tls(self, addresses: list[str]) -> tuple[Path, Path]:
        """Make sure the wall's own certificate covers `addresses`; returns (certificate, key) files.

        Given a certificate of the owner's own at start, that one is used as it is: what names it is for,
        and who vouches for it, is theirs to see to.
        """
        if self.tls_files is not None:
            self.cert_fingerprint = certificate_fingerprint(self.tls_files[0])
            return self.tls_files
        names = list(addresses)
        if "0.0.0.0" in names:
            names += [a for a in (lan_ip(), tailscale_ip()) if a]
        cert, key, self.cert_fingerprint = ensure_certificate(self.data_dir / "tls", names)
        return cert, key

    @staticmethod
    def urls(addresses: list[str], port: int, https: bool) -> list[str]:
        """The addresses a browser can use for these listeners."""
        hosts: list[str] = []
        for addr in addresses:
            if addr == "0.0.0.0":
                hosts += ["127.0.0.1", *(a for a in (lan_ip(), tailscale_ip()) if a)]
            else:
                hosts.append(f"[{addr}]" if ":" in addr else addr)
        scheme = "https" if https else "http"
        return [f"{scheme}://{host}:{port}/" for host in dict.fromkeys(hosts)]

    def unlock_at_start(self) -> str | None:
        """Open the saved passwords with the unlock file's secret, if qKVM was started with one.

        Once, before anything is served. Returns a line for whoever started qKVM where there is
        something they should know, and None otherwise.
        """
        if self.store.restored:
            # Read from the second copy, which is of what was saved last: nothing was undone by it. Said in the
            # activity log all the same: it is where somebody looks who wonders what happened to a file.
            self.audit.write("settings_restored", "", damaged=self.store.recovered_from.name if self.store.recovered_from else None, why=self.store.damage[:200])
        secret, fitted = self.unlock_secret, self.store.unlock
        if secret is None:
            if self.key_unread is not None:
                # Not asked to start locked: the key could not be read, this once. What it fits is left as it
                # is, and the next start tries again. (The browsers that were kept signed in sign in once more.)
                return (
                    f"the key qKVM keeps to carry on after a restart could not be read ({self.key_unread}): nothing is watched until somebody signs in, "
                    "and browsers that were kept signed in sign in once more"
                )
            left = f" The key that opened them could not be taken out of the data folder ({self.key_left}): remove {unlock.OWN} there by hand." if self.key_left else ""
            if fitted is None:
                return left.strip() or None
            # Started with no key (--locked-start), and what a key left in the data folder goes with it: this
            # is how carrying on by itself is switched off, and a copy of a key somebody kept opens nothing afterwards.
            old = self._unfit()
            self.audit.write("unlock_at_start_off", "")
            log.warning("started with nothing that opens the saved passwords: this data folder no longer opens by itself")
            return f"started with --locked-start: after a restart nothing is watched until somebody signs in.{left}{old}"
        if fitted is None:
            self.sessions.forget_kept(for_good=False)
            if not self.initialized:
                return None
            if self.own_key:
                return "qKVM carries on by itself after a restart from the next sign-in on: until then nothing is watched"
            return "the unlock file is in use from the next sign-in on: until then nothing is watched"
        try:
            key = Vault.open(fitted, secret)
        except (NoMemory, MemoryError) as ex:
            # The check itself could not be made (no memory for it at this moment, most likely). That is not
            # "the key does not fit": what it fits is left as it is, and the next start tries again.
            log.error("the saved passwords could not be opened at this start: %s", ex)
            self.sessions.forget_kept(for_good=False)
            return "the saved passwords could not be opened at this start (is there memory to spare?): nothing is watched until somebody signs in"
        if key is None:
            old = self._unfit()
            self.sessions.forget_kept(for_good=False)
            if self.own_key:
                log.warning("the key in the data folder does not open it: it is another one than the one that was in use")
                return f"the key qKVM keeps to carry on after a restart does not fit this data folder (the folder was put together from two, or was used with an unlock file before). It will fit again after the next sign-in; until then nothing is watched.{old}"
            log.warning("the unlock file does not open this data folder: it is another file than the one that was in use")
            return f"the unlock file does not fit this data folder (it was replaced, or this is another folder). It will fit again after the next sign-in; until then nothing is watched.{old}"
        self.vault.adopt(key)
        self.sessions.load(self._still_let_in)  # opened: the browsers that asked to be kept signed in are, from here on
        self.audit.write("unlocked_at_start", "")
        log.info("the saved passwords were opened with %s", "the key in the data folder" if self.own_key else "the unlock file")
        return None

    def _unfit(self) -> str:
        """Take out of the data folder what a key opened it with. Returns what is to be said if that was not done in full ("" if it was).

        The second copy of the settings is renewed with every save (store.write), so one save takes it out of
        both; older copies that lie in the folder (a damaged file set aside, a write that was cut off) are
        removed. Where one of them could be neither renewed nor taken away, it still holds what the old key
        opens, and somebody has to be told.
        """
        self.store.unlock = None
        self.store.save()
        left = self.store.clear_out()
        if not left:
            return ""
        names = ", ".join(left)
        log.error("%s still holds what the key before opened this folder with, and could not be renewed or removed", names)
        one = len(left) == 1
        return f" {names} in the data folder could not be removed, and still hold{'s' if one else ''} what the key before opened it with: remove {'that file' if one else 'those files'} by hand."

    def request_restart(self) -> None:
        """Re-open the listeners with the current settings."""
        self.restart_requested = True
        if self.stop:
            self.stop()

    def restart_program(self) -> None:
        """Leave so that the starter runs the program again, on whatever version is now installed."""
        self.exit_status = RESTART
        if self.stop:
            self.stop()

    def reset_password(self) -> list[str]:
        """Forget every account. The saved KVM passwords were encrypted for them, so they go too.

        Returns the names of the files in the data folder that still hold what was to be erased, because they
        could be neither renewed nor removed (none, as a rule): whoever asked for this has to be told to remove them.
        """
        self.store.users = []
        self.store.recovery, self.store.recovery_created = None, 0.0
        self.store.unlock = None  # what the unlock file opened is gone with the rest
        self.store.tokens = []  # nobody is left who made them
        for device in self.store.devices:
            device.secret = None
        # Saved "type text" actions were encrypted with it as well, and so was the address alerts go to: left
        # in, alerts would be shown as set up and go nowhere.
        self.store.actions = [action for action in self.store.actions if action.kind != "text"]
        self.store.alerts.webhook = None
        # Whoever had the token that reads the measurements was given it by an account that is gone.
        self.store.server.metrics_token = ""
        self.store.save()  # (the second copy of the settings is renewed with it)
        return self.store.clear_out()  # and nothing of this is left in the folder in a file of another name


def identity(record: DeviceRecord) -> str | None:
    """What makes a device the one it is, whichever address it is reached by. None where that cannot be told.

    One KVM is often reachable two ways, on the network it stands in and over a VPN, and somebody who
    adds what a search of both turns up has it on the wall twice. A KVM makes its certificate itself, on
    its first start, so the one remembered for it is its own: on thirteen real ones, ten certificates,
    and the three that came up twice were the three that had been added under two addresses.

    Not so for a server's management controller, whose maker may have put the same certificate on every
    board: a server is known by the number it gives for itself. Nor for a device behind somebody's front
    door, where the certificate is the door's. Nor for a guest of Proxmox: every guest of one Proxmox shows
    its certificate, and a guest is known by the number it gives for itself too.
    """
    if record.ident:
        return record.ident
    if record.kind not in ("redfish", "proxmox") and record.tls == "pinned" and record.cert_pem:
        return saved_mark(record.cert_pem)  # (None where what is remembered is no certificate: it is known by nothing then)
    return None


def auth_mark(user: UserRecord) -> str:
    """A mark of what an account signs in with, as it stands: its password (what lets it open the saved
    passwords, made anew with every change of it) and its second step, as often as that was switched.

    A browser kept signed in across a restart carries the mark from when it signed in, and is let in again
    only while the account's is the same: a password changed since, or a second step switched on, ends it,
    whatever else was or was not written down.
    """
    # (The count of how often the second step was switched on or off, and not its key: switched on and off
    # again, an account would otherwise stand as it did before, and a browser that the switching-on signed
    # out would be good again wherever a file still named it.)
    stands = [user.auth, user.totp_changes] if user.totp_changes else user.auth
    return hashlib.sha256(json.dumps(stands, sort_keys=True, default=str).encode()).hexdigest()[:24]


def driver_for(kind: str) -> type[Device]:
    """The client class for a make of KVM, or for a server's management controller."""
    if kind == "jetkvm":
        from .jetkvm import JetKvmDevice  # imported on first use: most walls have no JetKVM

        return JetKvmDevice
    if kind == "redfish":
        from .redfish import RedfishDevice

        return RedfishDevice
    if kind == "amt":
        from .amt import AmtDevice  # a business PC with Intel AMT

        return AmtDevice
    if kind == "vnc":
        from .vncdevice import VncDevice

        return VncDevice
    if kind == "proxmox":
        from .proxmox import ProxmoxGuest  # a virtual machine on Proxmox VE

        return ProxmoxGuest
    return KvmDevice


class DeviceManager:
    """Live clients for the saved devices. They exist only while the vault is unlocked."""

    def __init__(self, core: Core, save: Callable[[], Awaitable[None]]) -> None:
        self.core = core
        self.save = save  # writes the settings to disk: the server's way, off the event loop, when its turn among the changes has come
        self.devices: dict[str, Device] = {}
        self._saving: set[asyncio.Future[None]] = set()  # certificates (and machines' numbers) seen for the first time, on their way to disk
        self._closing: set[asyncio.Future[None]] = set()  # the rest of retirements whose callers were stopped (`_retire`)
        # Told when a device answers at its other address from now on (device id, the address it has, the one
        # it answers at). Whoever changes what is saved does so in one place, one change at a time: the server.
        self.moved: Callable[[str, str, str], Awaitable[None]] | None = None
        # Told when a driver takes a number its machine gives for itself (device id, the address it has, the number kept
        # until now, the one to keep): kept by whoever changes what is saved, one change at a time (see `_known`).
        self.known: Callable[[str, str, str, str], Awaitable[None]] | None = None
        # Told what the wall sees of a device at every look (device id, its status): the history keeps it. Must not wait.
        self.observed: Callable[[str, dict[str, Any]], None] | None = None
        # Told before a client is closed, with it still open: what a live line has down on the device is let go of
        # through it then (live.py); once the connection is gone there is no way to.
        self.retiring: Callable[[Device], Awaitable[None]] | None = None

    def spec(self, record: DeviceRecord, password: str | None = None) -> DeviceSpec:
        if password is None:
            password = ""
            if record.secret:
                # (None: sealed under an older key, or damaged. Treated as "no password saved": the tile
                # says that its login is to be given again, and the rest of the wall is there.)
                password = self.core.vault.read(record.secret, record.id) or ""
        return DeviceSpec(
            id=record.id,
            name=record.name,
            base_url=record.url,
            username=record.username,
            password=password,
            tls=record.tls,
            cert_pem=record.cert_pem,
            kind=record.kind,
            machine=record.machine,
            fingerbot_strength=record.fingerbot_strength if record.fingerbot_strength in FINGERBOT_STRENGTHS else FINGERBOT_STRENGTHS[0],
        )

    async def _known(self, device_id: str, url: str, was: str, mark: str) -> None:
        """A driver took a number its machine gives for itself (DeviceSpec.machine): the first one, where none was kept; or a
        server's controller's beside its computer's. Kept with the tile only where what is kept is still `was`, at the address
        it was seen at; by the server (`known`), as every change of what is saved is made: in its turn among the changes, with
        a new record in the old one's place, so that an edit under way notices. Not waited for: the driver is in the middle
        of a look or a command, which whoever holds that turn may be waiting for."""
        if self.known is not None:
            saving = asyncio.ensure_future(self.known(device_id, url, was, mark))
        else:
            # (No server: the record changed where it is, and saved in its turn, as a first certificate is.)
            record = self.core.store.device(device_id)
            if record is None or record.url != url or record.machine != was:
                return
            record.machine = mark
            saving = asyncio.ensure_future(self._save_certificate(record.name, "the number its machine gives for itself"))
        self._saving.add(saving)
        saving.add_done_callback(self._saving.discard)

    async def _pinned(self, device_id: str, url: str, cert_pem: str) -> None:
        record = self.core.store.device(device_id)
        # Only for the address it was seen at, and only where a certificate is still what is asked for:
        # a client that was replaced while it looked has nothing to say about the KVM's new settings.
        if record is None or record.url != url or record.tls != "pinned" or record.cert_pem:
            return
        record.cert_pem = cert_pem
        # Saved when its turn among the changes has come, and not waited for here. Saved at once, it wrote
        # down whatever else was in memory at that moment: the half of somebody's change that was then
        # refused and taken back, and was on disk all the same. And whoever waits for this device's
        # connection may be the one whose turn it is.
        saving = asyncio.ensure_future(self._save_certificate(record.name))
        self._saving.add(saving)
        saving.add_done_callback(self._saving.discard)

    async def _save_certificate(self, name: str, what: str = "its certificate") -> None:
        try:
            await self.save()
        except OSError as ex:
            # Trusted for as long as the program runs, and written with the next change that is saved.
            log.error("%s: %s could not be saved: %s", name, what, ex)

    async def _moved(self, device_id: str, url: str, to: str) -> None:
        if self.moved is not None:
            await self.moved(device_id, url, to)

    def client(self, record: DeviceRecord, password: str | None = None) -> Device:
        """A client for `record` that is not live yet; `password` overrides the saved one.

        Until it is adopted, a certificate it trusts on first contact stays in its own
        spec: checking an edit must not touch what is saved.
        """
        return driver_for(record.kind)(self.spec(record, password))

    def _install(self, device: Device) -> None:
        device_id, url = device.spec.id, device.spec.base_url
        device.on_pin = lambda pem: self._pinned(device_id, url, pem)
        device.on_move = lambda to: self._moved(device_id, url, to)
        device.on_status = lambda status: self._observed(device_id, status)
        device.on_known = lambda was, mark: self._known(device_id, url, was, mark)
        self.devices[device_id] = device

    def _observed(self, device_id: str, status: dict[str, Any]) -> None:
        if self.observed is not None and self.devices.get(device_id) is not None:
            self.observed(device_id, status)

    def load(self) -> None:
        """Create clients for saved devices that don't have one yet."""
        if not self.core.vault.unlocked:
            return
        for record in self.core.store.devices:
            if record.id not in self.devices:
                self._install(self.client(record))

    async def adopt(self, device: Device) -> None:
        """Make `device` the live client for its id, retiring the one it replaces."""
        retired = self.devices.get(device.spec.id)
        if retired is not None and type(retired) is type(device) and retired.spec.base_url == device.spec.base_url:
            device.takes_over(retired)
        self._install(device)  # first, so that the KVM is never missing from the wall in between
        if retired is not None:
            await self._retire(retired)

    async def _retire(self, device: Device) -> None:
        """Close a client that is no longer the live one. Whatever its device does to the goodbye, it is retired.

        Closing signs out of a device that has sessions, and so asks it something once more. An answer to that
        which nobody foresaw ended the removal of a tile halfway: gone from the wall, and still in the file.

        In the caller's own task (a client's close leaves the task that asks it alone: a JetKVM followed to HTTPS asks
        from a task of the old client's). A caller stopped while the live lines' letting go is waited for (a request cut
        off, the wall locking itself as the program stops) hands the rest to a task of its own, which waits for that
        letting go once more and then closes the client: cut off there, the client was never closed, and a KVM's session
        or a console seat was kept until the device timed it out. (`close` waits for what is left of these.)
        """
        if self.retiring is not None:
            try:
                await self.retiring(device)
            except asyncio.CancelledError:
                rest = asyncio.ensure_future(self._retire_after_all(device))
                self._closing.add(rest)
                rest.add_done_callback(self._closing.discard)
                raise
            except Exception:
                log.exception("%s: what was held on it could not be let go of before it was closed", device.label)
        await self._close(device)

    async def _retire_after_all(self, device: Device) -> None:
        """The rest of a retirement whose caller was stopped (`_retire`)."""
        if self.retiring is not None:
            try:
                await self.retiring(device)
            except Exception:
                log.exception("%s: what was held on it could not be let go of before it was closed", device.label)
        await self._close(device)

    @staticmethod
    async def _close(device: Device) -> None:
        try:
            await device.close()
        except Exception:
            log.exception("%s: its connection did not close cleanly", device.label)

    async def replace(self, record: DeviceRecord) -> None:
        await self.adopt(self.client(record))

    async def remove(self, device_id: str) -> None:
        device = self.devices.pop(device_id, None)
        if device is not None:
            await self._retire(device)

    def take(self, device_ids: Iterable[str]) -> list[Device]:
        """Take the live clients of these off the wall, all at once, to be closed together (retire_all)."""
        return [device for device in (self.devices.pop(device_id, None) for device_id in device_ids) if device is not None]

    async def retire_all(self, devices: Iterable[Device]) -> None:
        """Close clients that `take` took, side by side, as at the end. (One after the other, each sign-out and each live
        line's goodbye waited for the one before.)"""
        await asyncio.gather(*(self._retire(device) for device in devices))

    def tidy(self) -> None:
        for device in self.devices.values():
            device.tidy()

    async def close(self) -> None:
        devices, self.devices = list(self.devices.values()), {}
        await asyncio.gather(*(self._retire(d) for d in devices))
        # A certificate seen a moment ago is written down before the program ends, not learned anew after it; and a client
        # whose retirement was begun by a request that was cut off is closed to the end.
        if self._saving or self._closing:
            await asyncio.wait(self._saving | self._closing, timeout=5)
