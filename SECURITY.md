# Security

qKVM holds the passwords of your KVMs and can press the power button of the machines behind
them, so problems in it matter. Reports are welcome.

## Reporting a problem

Please do not open a public issue for something that could be used against other people's
installations. Report it privately instead: on https://github.com/qkvm/qkvm open the
*Security* tab and choose *Report a vulnerability*.

Say which version you run (`qkvm --version`, or *Settings > About*), what you did,
and what happened. A way to reproduce it helps most.

## What counts

- Getting past sign-in, a role, or the limit of an account to some KVMs.
- Reading a stored password, the recovery key, a two-factor key, the alert address, the wall's
  key for Web Push or a browser's push subscription from
  the page or the log; or from the protected data folder without the separate server
  storage key, including when an account password or legacy data key is known.
- Making qKVM send a KVM's password to something other than that KVM.
- Mounting an image on a machine, or starting a machine from one, without the media right (an
  admin, in person); or having a device handed an address somebody typed, or an image qKVM did
  not list for it; or an upload to a KVM's own storage that is kept on the wall (on its disk, or
  held whole in its memory), that goes past 16 GB, or that writes an image other than the one
  its confirmation named.
- Reading an image qKVM serves to a server's controller (`/media/...`) from any address but that
  controller's, after it was unmounted, without the mount's user and password where it has one,
  or reading any other file of the computer qKVM runs on through it; or learning that address
  (it is the controller's alone: in no log, and on no page).
- Running code on the computer qKVM runs on, including through the updater.
- A page on another website making a signed-in browser do something in qKVM.

## What qKVM assumes

- The server process and OS administrators are trusted. The protected settings file requires
  an independent random server storage key outside the data directory. A copied data folder,
  even with an account password, owner recovery key or its `unlock.key`, cannot open that
  envelope without the storage key. Keep the data and storage-key backups separately.
  Copying both defeats this storage boundary. `--locked-start` additionally requires an
  account password or owner recovery path to open the inner credential key after startup.
- Whoever can write to the data folder can stop qKVM; the account qKVM runs as and the
  computer's administrators can also put there what it runs after an update: that folder is
  the program's, as much as its settings'. qKVM runs no update from a folder anybody else may
  write, and a data folder it finds open to others is never changed: every start says so,
  with what to do.
- The network between qKVM and a KVM may be hostile; that is why certificates are remembered.
  The network between a browser and qKVM should be trusted, or HTTPS switched on.
- A VNC server at a plain `vnc://` address is spoken to without encryption: the answer to its
  password challenge, its pictures and every key typed into it, over the live line or by an
  action, go in the clear. Keep such servers on a network you trust or behind a tunnel, or use
  `vncs://` where the server speaks TLS.
- An admin is trusted with everything, including where alerts are sent, and with virtual
  media: an image mounted on a machine and started from is root on that machine, and is an
  admin's alone (operators press power buttons and type; they do not mount images).
- What a Proxmox token may do there is Proxmox's to say: a token given `VM.Config.CDROM`,
  `VM.Config.Disk` and `Datastore.Audit` lets qKVM put any ISO image of the storages it may
  see into the guests it may see, and start them from it.
- Images on a KVM's own storage (a Comet's, a PiKVM's, a JetKVM's) are the KVM's: anyone with
  its own password can read them there, and a machine given one writable can change it. qKVM
  removes what an upload cut off leaves, and deletes an image when asked; the rest is the
  admin's to delete after use.
- The folder of images for servers is the admin's to name and to fill (*Settings > Server
  images*): an admin is trusted with what is on the computer qKVM runs on, as with an update.
  A server's controller reads the image mounted on it from qKVM, and as a rule checks no
  certificate (Redfish's default): the network between the two should be trusted (a management
  network), or the image checked at the server. A server's controller is not trusted beyond its
  own image: it is answered for that one file, for as long as it is mounted, and nothing else.
- A new qKVM belongs to whoever opens it first, until a password is chosen. Where others can
  reach its port before you do, start it with `--setup-code`. The container image and
  supplied Compose deployment enable `--https --setup-code` by default. An explicit
  container command replaces these defaults; retain them unless using an isolated
  backend behind a trusted TLS proxy.
- qKVM has a host name (or an address) of its own. A browser keeps what signs it in by host
  name and not by port: a device whose own page is on another port of the name qKVM is
  looked at under (a router that forwards two ports, a tunnel to localhost) would be handed
  the sign-in to qKVM by the browser. The page offers no link to such a device's console and
  says why; it cannot keep you from opening that address yourself.
- A device is known again by the certificate it showed first. That is as good as the
  certificate is its own: a server controller whose maker put one certificate and one key on
  every board is known as "one of those", and qKVM asks for its password to be typed again
  whenever its tile is moved to another address.

How the protections work is described in the README under *How it is protected*.

## What is kept, and where

Application state lives in the data folder (`.qkvm` in the home folder of whoever runs it,
or the folder given with `--data-dir`; `/data` in the container). The independent server
storage key lives outside it: by default `<data-directory>.keys/vault.key`, or the path
selected by `--vault-key-file` / `QKVM_VAULT_KEY_FILE`. Docker uses `/keys/vault.key` in a
separate persistent volume. The key is created privately (0600 on POSIX; a Windows ACL
for the server account, Administrators and SYSTEM). Missing, invalid or overly accessible
keys are refused; an existing protected vault never gets a replacement key automatically.

The settings document is an AES-256-GCM authenticated envelope with a fresh nonce on every
write. Account records, roles, device metadata and the existing encrypted secrets are all
inside it. Other files listed below are not covered by that envelope.

| File | Holds | Readable without an account's password |
|---|---|---|
| `qkvm.json`, `qkvm.bak` | authenticated encrypted settings, account records, device metadata and inner credential records | no without the separate server storage key; that key alone reveals metadata, and with an inner unlock credential reveals secrets |
| external `vault.key` | independent random 256-bit server storage key | private OS permissions; must be backed up separately, never in the data folder |
| `vault-migration.recovery` | original settings bytes captured during migration | encrypted with the external storage key; not a plaintext rollback copy |
| `unlock.key` | automatic unlocking of the inner credential key | readable to the OS account; insufficient to open the protected settings without the external storage key |
| `qkvm.damaged-*.json` | a damaged protected settings file retained for inspection | a valid protected envelope requires the storage key; legacy plaintext remnants must be migrated or removed after verified archival |
| `sessions.json` | the browsers that asked to be kept signed in over a restart: a SHA-256 of each one's cookie, its account and date | yes; it cannot be replayed as a sign-in |
| `watch.json` | what each machine was last seen as (on, off, not answering), for alerts after a restart | yes |
| `screens.json` | which screen alerts stand ("no signal", "screen unchanged"), by device id, for their "back to normal" after a restart | yes |
| `alert-pictures/<device id>-<stamp>.jpg` (or `.png`) | the picture of a machine's screen that set off its last screen alert, as the wall had it: whatever that screen showed. One per machine, deleted after 30 days and when the machine leaves the wall; handed out to admins only, never sent with an alert | yes |
| `audit.log`, `audit.log.1` ... | the activity log: who did what, when, from which address. At a failed sign-in, the name that was typed only where it is an account's | yes |
| `audit.sqlite`, `audit.sqlite-wal`, `audit.sqlite-shm` | the activity log's searchable index, including copies of its entries; rebuilt from the text logs if missing or damaged. The companion files hold pending writes and SQLite's shared-memory index | yes |
| `history.sqlite`, `history.sqlite-wal`, `history.sqlite-shm` | machine states, sensor readings, power events and when a machine was first and last heard from, identified by device id; no stored passwords. The companion files hold pending writes and SQLite's shared-memory index | yes |
| `history.damaged-*.sqlite` and its `-wal` and `-shm` companions | history files set aside after damage was detected; retained for the configured history period | yes |
| `qkvm-download-*.tmp` | a temporary copy of an activity-log download that outgrew the memory buffer; removed when the download closes, or at the next start if a crash left it behind | yes |
| `qkvm.log` | starts, device outages, errors; until setup is done, the setup code (sign-ins, refused ones too, are in `audit.log`) | yes |
| `tls/key.pem`, `tls/cert.pem` | the key and certificate of qKVM's own HTTPS, when it made them | yes: whoever has the key can pass for this qKVM to a browser that has accepted its certificate |
| `updates/` | versions installed from inside the app | yes (program files) |

The inner credential key is still wrapped by account passwords and the owner recovery
key so that existing passwords, MFA and recovery flows survive migration. Those wrappers
are themselves inside the independent server-key envelope. Knowledge of an account password
or an old inner credential key does not unlock the migrated settings file. Online roles
and MFA are enforced by the server; this is not per-role encryption, offline MFA, hardware
key isolation or protection against a compromised running server.

Migration cannot revoke earlier plaintext-format backups or credentials already copied
from them. Anyone with such a backup and a matching password may still recover its old
secrets. Rotate affected device credentials and MFA/recovery material if an old copy may
have been exposed. Removing an account does not erase backups outside qKVM's control.
Audit/history/watch records and TLS private keys retain their separate OS-access requirements.

## Migrating an existing data folder

This is an offline operation; a running server's instance lock prevents it. Plan a maintenance
window, stop the old server, preserve your existing backup securely, and use the new version:

```sh
qkvm --data-dir /var/lib/qkvm --vault-key-file /var/lib/qkvm-keys/vault.key --migrate-vault
qkvm --data-dir /var/lib/qkvm --vault-key-file /var/lib/qkvm-keys/vault.key --verify-vault
```

The key path must be outside the data directory. A new key is generated privately if none
exists. The migration validates the legacy settings, saves and verifies an encrypted recovery
archive, replaces the backup first and then the primary atomically, and removes archived
legacy settings remnants. It preserves accounts, password wrappers, MFA state, recovery
codes, device credentials, settings and unknown future fields. No account passwords are
requested and no devices are contacted. Cleanup failures are reported as incomplete; rerun
with the same key after resolving the reported file access problem.

Back up the new storage key privately and separately before relying on the migrated data.
Test a restore of the data and matching key into an isolated directory with `--verify-vault`;
then test private sign-in and MFA in an isolated server. Do not run duplicate monitoring or
input against production devices during that drill. Start the production service with the
same `--vault-key-file` path, or set `QKVM_VAULT_KEY_FILE` in its service configuration.

Docker deployments keep the key in a named volume of its own at `/keys`, beside the data
volume at `/data`. The image declares no volume for `/keys`, and in a container qKVM makes a
new key only in a folder that is a mount of its own and outlasts the container: not the
container's own folder, a tmpfs, an anonymous volume or a pod's emptyDir, where it would be
lost with it. Stop the serving container, copy the data volume aside, then run the new image
once against both volumes, before starting it normally with both:

```sh
docker run --rm -v qkvm-data:/data -v qkvm-keys:/keys qkvm/qkvm:0.2.0 --migrate-vault
docker run --rm -v qkvm-data:/data -v qkvm-keys:/keys qkvm/qkvm:0.2.0 --verify-vault
```

Do not remove or recreate the key volume on an update. A key file bind-mounted read-only can
take its place, where it is a regular file (not a link) owned by uid 10001 with permissions
0400 or 0600; Kubernetes secret volumes (links) and Docker swarm secrets (owned by root) are
refused as they are. If a first start or a migration was cut off while the key was being
made, the key file can be empty and qKVM says it is not a storage key. An empty key file holds
no key, and nothing was sealed with it (a key is written to disk before anything is sealed):
remove it and run the command again.

**Losing the storage key makes the protected settings unrecoverable.** Account passwords,
authenticator codes and the existing owner recovery key cannot reconstruct it. A recovery
archive also needs that same storage key. Earlier qKVM versions reject the protected format;
do not downgrade the binary over migrated data or restore a legacy backup as an automatic
fallback. A failed/interrupted migration can be rerun with the same key; old external backups
remain sensitive even after migration succeeds.

An in-app update tried by an older supervisor can return to its previous binary only
while the vault is still untouched legacy data and that update has never been proven.
It tells the operator to perform this offline migration before upgrading. Once a
migration archive, protected settings copy or migration remnant exists, this path
is refused. Missing storage keys do not trigger an automatic downgrade. A direct
upgrade through pip or a container requires the offline procedure above.

**Tokens and display links** (*Settings > Tokens*) are credentials of their own: whoever has
one can do what it was made for (look, or look and act, on the machines it is for) until it
runs out or an admin takes it back. `qkvm.json` holds a SHA-256 of each, never the token.
They work only while qKVM is unlocked, and they cannot change settings, accounts, devices or
tokens (a PC with Intel AMT's view included, which an operator in person may change). An
operator token can type its own text on the machines it is for, press their keys
and power buttons and take pictures of their screens; it cannot run a saved text (which it
could then read off the screen), or ask for a way into a console.

**A PC with Intel AMT set to health only** is sent no KVM session by qKVM, whatever asks for one
(its tile, its large view, its live line, keys and text): the one place every session is opened
refuses it, so Intel's border never comes up on the PC's own monitor. It is a setting of the
tile, not of the PC: the engine's KVM stays as it was set up (switched on, say), and whoever has
the PC's password can still open a session with another tool.

**Sign-on through a proxy** (`--sso-header`, off unless asked for) makes the reverse proxy
named with `--trusted-proxy` the place where people prove who they are. qKVM then believes
that proxy, and only it, about the name; whoever can reach qKVM's port from that proxy's
address, or can make that proxy send the header, is whoever they say. Whoever signs in
elsewhere brings no password here, so it cannot be had together with `--locked-start`.

**A file exported with a passphrase** (*Settings > Export and import*) holds every device
password of the wall (but that of a tile of a kind the version does not know, which is not
opened for it), the saved texts and the alert address, encrypted with a key of its own
that the passphrase locks (scrypt, AES-256-GCM). It is as safe as its passphrase, and once
made it is out of qKVM's reach: who has the file can try passphrases for as long as they
like. Only an admin can make one, with their password typed again, and the activity log
says that it was made. A file exported without a passphrase holds no secret. What a file
that is taken in can do to a wall is add devices and saved actions, and set the alert and
wall settings an admin ticks; it cannot add an account or a token, or change where qKVM
listens or how people sign in. Neither the wall's key for Web Push nor the browsers turned on
for alerts go into a file: they are this wall's, and a browser subscribed to this wall's key.

**Alerts by Web Push** are sealed in the settings as the other secrets are: the wall's own
P-256 key (made the first time a browser is turned on, for "alerts:push-key"), and each
browser's push address and keys (for "push:" and its id). The page is given the public half of
the key and never a browser's address. Any account may turn on its own browsers, and is told
about the machines it may see; a token has none. The service worker (`static/push.js`, scope
`static/push/`, which holds no page) has no fetch handler: it shows what arrives and opens the
wall at a tap, and no request of the page passes through it. The Content-Security-Policy gains
`worker-src 'self'` and `manifest-src 'self'` for it and the Home Screen description.

**One-time codes** for two-factor sign-in are kept as a keyed hash under the data key, not as
a plain one: forty random bits would be tried through in minutes by whoever has the file.

**Carrying on after a restart** needs one more thing that unlocks a copy of the data key
without anybody signing in. There are three ways, chosen when qKVM is started:

- *As it comes:* `unlock.key` in the data folder automatically opens the inner key after
  the separate server storage key has authenticated and opened the settings envelope.
- *`--unlock-file FILE`:* the inner automatic-unlock secret is kept outside the data folder,
  for example as a service credential. It does not replace the server storage key.
- *`--locked-start`:* no inner automatic-unlock key is kept. The server storage key is
  still required to load the protected settings; after restart, a successful account
  sign-in is additionally required before devices are reached.

Switching the inner automatic-unlock key off (`--locked-start`) takes the key that was in use out
of `qkvm.json`, out of `qkvm.bak` and out of the folder at that start, after which a copy of that
key opens nothing: but not out of copies of the whole folder made before. Starting with another
key than the one in use (another unlock file, or a key of its own made anew) takes it out of
`qkvm.json` and `qkvm.bak`; what the folder keeps to recover from (`vault-migration.recovery`, the
damaged copies set aside) is kept, and named at that start, since a key that does not fit is as
often an accident (a wrong file given once, a key a power cut emptied). Remove those by hand where
the change was meant.

## What qKVM connects to

- The devices on the wall, directly, at the addresses saved for them.
- While somebody searches for devices: every address of the computer's own network (a /24),
  and the Tailscale peers, on the ports KVMs answer on.
- `api.github.com`, once a day, to ask whether a newer release exists (it sends nothing about
  the installation; *Settings > Updates* switches it off). When an admin installs one:
  `github.com`, and the file servers GitHub sends the download on to, over HTTPS only; and, for the
  libraries an update brings that this computer has not, `files.pythonhosted.org` (PyPI's file
  host), at the addresses the release's signed list names, over HTTPS only. A daily check
  downloads no library.
- The address alerts are sent to, if one was given.
- The push service of each browser turned on for alerts (*Settings > Alerts > This browser*):
  Apple's, Google's, Mozilla's or Microsoft's, at the address that browser was given there. Only
  over HTTPS on port 443 to a name, and only where every address the name leads to is a public
  one; the connection goes to the address that was checked, so a name that leads into the wall's
  own network (loopback, private, link-local, site-local, IPv4 inside IPv6) is never followed.
  Each alert is encrypted for that browser alone (RFC 8291) and signed with the wall's own key (RFC 8292); the
  service sees when, and a padded length (as whose the alerts are, the wall gives
  `https://qkvm.com`, never its address), and cannot
  read what it carries: a machine's name and what happened, never a password, a token, a machine's
  address or a picture.
- The syslog collector given with `--audit-syslog`, if one was: each entry of the activity
  log, in clear (UDP or TCP).

Nothing else: no telemetry, no licence check, nothing that reports use.

## Checking what you install

- An update installed from inside the app is checked against the publisher's signature, with
  a key that is part of the program. **The publisher's key is built in since 0.1.0**
  (`RELEASE_KEYS` in `qkvm/update.py`), and a copy with a key built in installs a release only
  if that key signed it, whatever it was started with: a release that carries no valid
  signature is refused. A signed release is installed when you click for it, except where
  *Updates* in the README says the app does not install one: a copy that runs from a container
  image is updated by pulling the new image, and a release this copy cannot take in place (a
  Python it does not run under, a computer its release has no build for, or, for a release without
  a list of its libraries, a Python package this copy has not) is installed with pip instead. A copy built without a key (a
  fork's, before it makes its own) cannot tell who published a release, and installs none by
  itself: it says when there is a newer version, and that one is installed the way the first
  was (`pip install --upgrade qkvm`, or the new image). Started with
  `--allow-unsigned-updates`, such a copy does install one, checked by its checksum alone,
  which catches a broken download and not a tampered release. The signature says who published a
  release, not that it is the newest: whoever could decide what the list of releases shows
  could hold a copy back on an older signed one, not give it anything unsigned.
- **The libraries an update brings** (0.3.0 on) are held to the same signature: the release's
  `SHA256SUMS` names the SHA-256 of its lock (`qkvm-<version>-libraries.json`), and the lock names
  the SHA-256 and size of every wheel, for each Python and system. A wheel is fetched only from
  `https://files.pythonhosted.org/packages/...` at the address the lock gives (PyPI is asked for
  the bytes, not trusted for them), streamed into a private file, cut off past its size, and refused
  unless it hashes to the lock's value. It is unpacked by the program, never by pip and never run:
  no name that would be another file, nothing of a `.data` folder but the code, no `.pth` file, no
  module named like one of Python's own (or `qkvm`, `sitecustomize`, `usercustomize`), metadata of
  that very library and version, and no file written by two libraries; every file private to the
  account. A throwaway process then loads the version before it is named. At every start the
  version's own loader (standard library only) judges `updates/<version>/lib` as the starter judges
  the update's code (no link, nothing another account may write, on Windows by owner and ACL),
  checks that it was brought for this Python and that none of its libraries was loaded before (a
  `.pth` file of your Python could), and only then puts it first on the path; otherwise it goes back
  to the version before it. The set is the one the release tested: the lock is made in the release
  workflow, installed by hash in its tests on Linux x86-64 and ARM64 and Windows, audited, and the
  container image is built from it too.
- The container image carries a record of what it was built from (provenance) and of what is
  in it (SBOM); `docker buildx imagetools inspect qkvm/qkvm` lists both.
- Each version on PyPI from 0.1.0 on is uploaded by the release workflow of the public
  repository (PyPI's "trusted publishing"), and PyPI shows that with its files. (0.0.1, which
  only held the name, was uploaded by hand.)

## Supported versions

The newest release is the one that gets fixes. There is no promise of a response time; a
report is answered as soon as it has been read and understood.

## Live access revocation

Live connections recheck current session, account, token and device access before
sending each screen frame, granting control, or dispatching input. Queued pointer
updates and individual steps of a relative mouse movement are checked again when
they dispatch. A device status request cannot delay the independent periodic check
that closes idle revoked connections and releases their held keys.

Data already sent to a client cannot be recalled. A device operation already in flight
may finish after revocation; qKVM releases keys and buttons it put down, including
late deliveries, and waits for cleanup during controller handover. Cleanup releases
are allowed after revocation so a machine is not left with keys held down.


## Native video isolation

JPEG decoding, H.264 decoding, resizing and JPEG encoding run in a fresh worker
process. The application sends bounded video data over pipes; it does not send
KVM addresses, passwords, session cookies, unlock keys or its environment. Native
frames remain in the worker. Replies use a fixed binary format with dimensions,
operation and size checks before payload allocation; Python object deserialization
is not used. A failed or timed-out worker stops video, and where decoding falls
behind, what waits for the worker is let go of up to the next key frame; neither
falls back to native decoding in the credential-holding application. The screen watch
(an alert where a screen looked the same for some minutes) decodes the pictures it
compares in a worker of its own, as the rest; it shrinks the decoded pixels itself, in
Python, and a picture that cannot be decoded is not compared.

On Linux x86-64 and ARM64, the worker loads trusted runtime code before applying a
seccomp syscall allowlist. It then cannot open files, create sockets, processes or
threads, inspect other processes or change its sandbox. It retains only the three
standard pipe/null descriptors, cannot dump core, and has a 1 GiB address-space
limit. Running one thread, it never uses more than one processor.

On Windows, each worker has a separate capability-free AppContainer identity. A
read-only copy of public Python and video runtime files is made available to it;
application data is not copied. A job limits the worker to one process and 1 GiB
of committed memory, restricts UI access, and holds all the worker's threads to
two of the processors qKVM itself runs on (one where it runs on fewer than four),
spread apart; the worker cannot widen them. Each new worker is placed on the pair
with the fewest live workers, and gives it back when it ends, so a pair that falls
empty is reused before any pair is shared. Windows cannot forbid a worker more
threads as the Linux filter does: the processors bound the CPU they get, and the
memory limit bounds their number (each costs the worker about 35 KiB of it). The
worker's own work is one thread. A CPU rate cap is not used for this: Windows gives
a rate-capped job's threads less time than other threads on busy processors, slow
cores most, and 4K video fell far behind under one. On machines with more than 64
processors, which Windows splits into processor groups, the job caps the CPU time
of all the worker's threads together instead, at two processors' worth (half the
machine where that is less).

A worker taken over through a decoder flaw can still raise its own threads to
priority 15 (HIGH class and TIME_CRITICAL), which no job setting undoes without a
cost: limiting the job to IDLE priority class does clamp those threads to priority
4, but it also drops a healthy worker below ordinary processes, and a legitimate
4K decoder then misses its deadline under normal contention, the same penalty the
rate cap carries. So a worker keeps its own two processors. It cannot reach a third
or starve a worker on another pair; it can only stall one that shares its pair, and
pairs are shared only when live workers outnumber pairs. A stalled video session's
worker misses its deadline, is stopped, and is started again the next time the
session is asked for a frame: not on the pair it died on while another pair is as
free, and a pair whose worker missed its deadline is passed over by every new worker
for a minute while any worker still runs on it, so the feed recovers away from what
stalled it. An empty pair is always used first. A worker being stopped still counts
on its pair until it ends, and one taken over can delay that: where no pair is empty
meanwhile, its feed's next worker, a fresh one, is placed beside another feed's. Its
own two processors a worker taken over holds until it ends.

A worker that does not end within two seconds of being stopped (a thread it raised
to a high priority can delay that) is waited for by a background reaper, which then
removes its job, handles and AppContainer profile. When qKVM itself stops, it tells
every worker to end at once and waits for them together, with those a reaper is
still waiting for (qKVM closes its devices first, and a reaper would be cut off as
it exits), five seconds in all however many there are, and then leaves any that has
not ended: that worker's job ends its process as qKVM exits, but its AppContainer
profile (an entry named qkvm.video.<id> among the account's AppContainer mappings
and a folder of that name under Packages) stays, and so may the runtime bundle in
the temporary folder if a worker still held its files. They hold no qKVM data and
are never reused, each worker having a profile of its own. qKVM does not sweep such
profiles when it starts: another qKVM on the same computer may own them.

Only the explicit input, output and null-error handles are inherited: they are
created non-inheritable and made inheritable only for the call that starts the
worker, which lists them, and qKVM starts no other process that inherits handles
without such a list. The worker verifies its AppContainer token and absence of
capabilities before reading video. It may access its own empty profile and system
resources permitted to AppContainers; it is not a no-filesystem sandbox. Windows
installations need permission to create an AppContainer profile and a writable
temporary directory for the public runtime bundle.

Other operating systems and Linux architectures currently fail closed for these
native-video paths. Connections that require a worker cannot start; this includes
JetKVM's shared video/control connection. Other device types' control and video
paths forwarded without native processing are separate. The aiortc version is pinned because its receiver hook
is an internal interface; upgrading it requires reviewing and testing the boundary.

Isolation limits the consequences of a native-library exploit; it does not fix
vulnerabilities in bundled libraries. A compromised worker can see video supplied
to it, corrupt or stop its output, and attack the operating-system sandbox. JPEG
decoders belong to one device connection; encoders belong to one device or live
stream. Workers are not shared across devices, and closed sessions cannot start
a replacement worker. Keep video libraries
and the host operating system updated. Browser-side decoding, network protocol
libraries, administrator access and a compromised host remain separate risks.


The encrypted migration recovery archive retains the exact pre-migration settings
for recovery. Keep it private with the matching external key, and retire it under
your backup-retention policy after acceptance. 0.2.0 has no command that restores
settings from it: going back is the copy of the data folder made before the
conversion (see the README). The explicit account reset and
inner-unlock-key invalidation paths also remove this local archive; failures are
reported. Neither operation can erase older backups stored elsewhere.

Advanced non-secret server settings can be changed with the offline
`--configure-server FILE` command described in the README. It validates a restricted
set of fields and requires the stopped server's storage key. It does not expose a
plaintext vault export or add any credential-access API for companion clients.
