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
- Reading a stored password, the recovery key, a two-factor key or the alert address from
  the page or the log; or from the data folder alone, where qKVM was started so that the
  folder alone opens nothing (`--locked-start`, `--unlock-file`: see below).
- Making qKVM send a KVM's password to something other than that KVM.
- Running code on the computer qKVM runs on, including through the updater.
- A page on another website making a signed-in browser do something in qKVM.

## What qKVM assumes

- Whoever can read the memory or the files of the computer it runs on is trusted. **As it
  comes, a copy of the data folder is a copy of everything saved in it**: so that qKVM
  carries on by itself after a restart, the key that opens the saved passwords lies in that
  folder (`unlock.key`). Keep the folder, and every backup of it, as you would keep those
  passwords. `--unlock-file` moves the automatic-unlock key out of the folder;
  `--locked-start` removes automatic unlocking. In either mode, an account password or
  recovery key can still decrypt a copied vault (see below).
- Whoever can write to the data folder can stop qKVM, and can put there what it runs after an
  update: that folder is the program's, as much as its settings'.
- The network between qKVM and a KVM may be hostile; that is why certificates are remembered.
  The network between a browser and qKVM should be trusted, or HTTPS switched on.
- An admin is trusted with everything, including where alerts are sent.
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

Everything is in the data folder (`.qkvm` in the home folder of whoever runs it, or the folder
given with `--data-dir`; `/data` in the container). On Linux and macOS qKVM makes the folder
and its files readable by their owner only.

| File | Holds | Readable without an account's password |
|---|---|---|
| `qkvm.json`, `qkvm.bak` | devices (names, addresses, sign-in names, groups, remembered certificates), accounts (names, roles, a locked copy of the data key for each), settings | yes, all of that. The device passwords, saved text, two-factor keys and alert address are encrypted with the data key: **with `unlock.key` beside them, they are readable too**; without it, not |
| `unlock.key` | the key that opens the data key after a restart. Not there with `--locked-start`; with `--unlock-file` it is the file you named, outside this folder | it is what makes the rest readable: see above |
| `qkvm.damaged-*.json` | a settings file that could not be read at some start, set aside for you to look at when qKVM went on from its second copy | as `qkvm.json`, of its day. `--reset-password`, and a start that takes the key out of the folder, remove these |
| `sessions.json` | the browsers that asked to be kept signed in over a restart: a SHA-256 of each one's cookie, its account and date | yes; it cannot be replayed as a sign-in |
| `watch.json` | what each machine was last seen as (on, off, not answering), for alerts after a restart | yes |
| `audit.log`, `audit.log.1` ... | the activity log: who did what, when, from which address. At a failed sign-in, the name that was typed only where it is an account's | yes |
| `audit.sqlite`, `audit.sqlite-wal`, `audit.sqlite-shm` | the activity log's searchable index, including copies of its entries; rebuilt from the text logs if missing or damaged. The companion files hold pending writes and SQLite's shared-memory index | yes |
| `history.sqlite`, `history.sqlite-wal`, `history.sqlite-shm` | machine states, sensor readings, power events and when a machine was first and last heard from, identified by device id; no stored passwords. The companion files hold pending writes and SQLite's shared-memory index | yes |
| `history.damaged-*.sqlite` and its `-wal` and `-shm` companions | history files set aside after damage was detected; retained for the configured history period | yes |
| `qkvm-download-*.tmp` | a temporary copy of an activity-log download that outgrew the memory buffer; removed when the download closes, or at the next start if a crash left it behind | yes |
| `qkvm.log` | starts, device outages, errors; until setup is done, the setup code (sign-ins, refused ones too, are in `audit.log`) | yes |
| `tls/key.pem`, `tls/cert.pem` | the key and certificate of qKVM's own HTTPS, when it made them | yes: whoever has the key can pass for this qKVM to a browser that has accepted its certificate |
| `updates/` | versions installed from inside the app | yes (program files) |

One data key encrypts every secret. Each account's password, the recovery key, and the key
qKVM keeps to carry on after a restart each unlock a copy of it; it is never written down
unlocked. It follows that **any account's password, with a copy of the folder, opens the
device passwords in that copy**, a viewer's included, and that removing an account does not
make an old copy of the folder safe. When somebody who had an account leaves, change the
passwords of the devices. Account roles and two-factor sign-in protect online access;
they do not create separate encryption keys for each role or add a second factor to
offline vault decryption. Device names, addresses, audit logs and history are also
readable in the data folder without decrypting the vault.

**Tokens and display links** (*Settings > Tokens*) are credentials of their own: whoever has
one can do what it was made for (look, or look and act, on the machines it is for) until it
runs out or an admin takes it back. `qkvm.json` holds a SHA-256 of each, never the token.
They work only while qKVM is unlocked, and they cannot change settings, accounts, devices or
tokens. An operator token can type its own text on the machines it is for, press their keys
and power buttons and take pictures of their screens; it cannot run a saved text (which it
could then read off the screen), or ask for a way into a console.

**Sign-on through a proxy** (`--sso-header`, off unless asked for) makes the reverse proxy
named with `--trusted-proxy` the place where people prove who they are. qKVM then believes
that proxy, and only it, about the name; whoever can reach qKVM's port from that proxy's
address, or can make that proxy send the header, is whoever they say. Whoever signs in
elsewhere brings no password here, so it cannot be had together with `--locked-start`.

**A file exported with a passphrase** (*Settings > Export and import*) holds every device
password of the wall, the saved texts and the alert address, encrypted with a key of its own
that the passphrase locks (scrypt, AES-256-GCM). It is as safe as its passphrase, and once
made it is out of qKVM's reach: who has the file can try passphrases for as long as they
like. Only an admin can make one, with their password typed again, and the activity log
says that it was made. A file exported without a passphrase holds no secret. What a file
that is taken in can do to a wall is add devices and saved actions, and set the alert and
wall settings an admin ticks; it cannot add an account or a token, or change where qKVM
listens or how people sign in.

**One-time codes** for two-factor sign-in are kept as a keyed hash under the data key, not as
a plain one: forty random bits would be tried through in minutes by whoever has the file.

**Carrying on after a restart** needs one more thing that unlocks a copy of the data key
without anybody signing in. There are three ways, chosen when qKVM is started:

- *As it comes:* a key of qKVM's own in the data folder (`unlock.key`). Nothing to set up,
  and a copy of the folder opens everything in it.
- *`--unlock-file FILE`:* the key is in a file you name, outside the data folder (qKVM
  refuses one inside it): a systemd credential, a Docker secret, another disk. `qkvm.json`
  holds a copy of the data key locked with it. Keep the file separate from the data folder
  and its backups. This removes automatic unlocking from a stolen data-folder copy;
  account passwords and the recovery key remain alternative ways to decrypt that copy.
- *`--locked-start`:* no automatic-unlock key. An account password or recovery key is
  still able to decrypt a copy of the vault. After every restart nothing is watched
  until somebody signs in.

Going from one way to another takes the key that was in use out of `qkvm.json`, out of
`qkvm.bak` and out of the folder at that start, after which a copy of that key opens nothing:
but not out of copies of the whole folder made before.

## What qKVM connects to

- The devices on the wall, directly, at the addresses saved for them.
- While somebody searches for devices: every address of the computer's own network (a /24),
  and the Tailscale peers, on the ports KVMs answer on.
- `api.github.com`, once a day, to ask whether a newer release exists (it sends nothing about
  the installation; *Settings > Updates* switches it off). When an admin installs one:
  `github.com`, and the file servers GitHub sends the download on to, over HTTPS only.
- The address alerts are sent to, if one was given.
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
  image is updated by pulling the new image, and a release that needs a Python package (or a
  Python) this copy has not is installed with pip instead. A copy built without a key (a
  fork's, before it makes its own) cannot tell who published a release, and installs none by
  itself: it says when there is a newer version, and that one is installed the way the first
  was (`pip install --upgrade qkvm`, or the new image). Started with
  `--allow-unsigned-updates`, such a copy does install one, checked by its checksum alone,
  which catches a broken download and not a tampered release. The signature says who published a
  release, not that it is the newest: whoever could decide what the list of releases shows
  could hold a copy back on an older signed one, not give it anything unsigned.
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
is not used. A failed, overloaded or timed-out worker stops video without falling
back to native decoding in the credential-holding application.

On Linux x86-64 and ARM64, the worker loads trusted runtime code before applying a
seccomp syscall allowlist. It then cannot open files, create sockets or processes,
inspect other processes or change its sandbox. It retains only the three standard
pipe/null descriptors, cannot dump core, and has a 1 GiB address-space limit.

On Windows, each worker has a separate capability-free AppContainer identity. A
read-only copy of public Python and video runtime files is made available to it;
application data is not copied. A job limits the worker to one process and 1 GiB
of committed memory and restricts UI access. Only the explicit input, output and
null-error handles are inherited. The worker verifies its AppContainer token and
absence of capabilities before reading video. It may access its own empty profile
and system resources permitted to AppContainers; it is not a no-filesystem sandbox.
Windows installations need permission to create an AppContainer profile and a
writable temporary directory for the public runtime bundle.

Other operating systems and Linux architectures currently fail closed for these
native-video paths. Device control and video paths forwarded without native
processing are separate. The aiortc version is pinned because its receiver hook
is an internal interface; upgrading it requires reviewing and testing the boundary.

Isolation limits the consequences of a native-library exploit; it does not fix
vulnerabilities in bundled libraries. A compromised worker can see video supplied
to it, corrupt or stop its output, and attack the operating-system sandbox. Shared
JPEG processing can include screens from multiple devices. Keep video libraries
and the host operating system updated. Browser-side decoding, network protocol
libraries, administrator access and a compromised host remain separate risks.
