# QKVM

A self-hosted screen wall and command center for IP KVMs. It works with GL.iNet Comet
devices (GL-RM10 / GL-RM1 and the four-port Comet X GL-RM4PE, GLKVM firmware), which share
the PiKVM `kvmd` API, and with JetKVM.
One page shows a live picture and the status of every KVM, and lets you act on one machine
or on many at once. Servers with a management controller of their own (a BMC) go on the same
wall, with their power state and health in place of a picture. Nothing goes through anyone's
cloud: QKVM talks to each device directly, over your LAN or Tailscale.

QKVM is an independent project. It is not affiliated with GL.iNet, PiKVM or JetKVM.

## Run it

**As a program** (Python 3.11 or newer):

```
pip install qkvm
qkvm
```

Then open http://127.0.0.1:8787/. Settings are kept in the
folder `.qkvm` in your home folder (on Windows `%USERPROFILE%\.qkvm`), whatever folder you
start it from; `--data-dir` puts them elsewhere. This is "the data folder" below, and QKVM
says where it is every time it starts.

Where the system's Python refuses `pip install` outside an environment of its own (Debian,
Ubuntu and others do), `pipx install qkvm` does the same and makes that environment for you.

**As a container:**

```
docker run -d --name qkvm --restart unless-stopped -p 8787:8787 -v qkvm-data:/data qkvm/qkvm
```

Then open `http://<this machine>:8787/` and choose a password. Do that right away: until a
password is chosen, a new QKVM belongs to whoever opens it first. Where others can reach
the port before you do (a server on the internet, a network that is not yours alone), add
`--setup-code` to the end of the command: QKVM then asks for a code that only its log shows
(`docker logs qkvm`).

The image is there for amd64 and arm64 (the same
one is at `ghcr.io/qkvm/qkvm`) and runs as an unprivileged user; settings live in the
`qkvm-data` volume. (If you mount a folder of your own at `/data` instead, it has to be
writable by that user, uid 10001.) The
[`docker-compose.yml`](https://github.com/qkvm/qkvm/blob/main/docker-compose.yml) in the
source runs it the same way and locked down further, on a read-only file system and without
capabilities: put that file in a folder and run `docker compose up -d` there. To update,
`docker compose pull && docker compose up -d`; without compose, `docker pull qkvm/qkvm`,
then remove the container and run it again.

The container carries on by itself after a restart, with a key it keeps in its volume (see
*Carrying on after a restart* under [Keeping it running](#keeping-it-running)): whoever has a
copy of the volume has the saved device passwords. To keep that key out of the volume and its
backups, give the container a key file of your own as a secret and say where it is: `-v
/etc/qkvm/unlock.key:/run/secrets/qkvm_unlock:ro -e QKVM_UNLOCK_FILE=/run/secrets/qkvm_unlock`
on the `docker run` line, or the lines that are commented out in the compose file. The file
needs 32 characters or more, and has to be readable by the container's user (uid 10001).

The line above serves plain HTTP on every address of that machine, which is fine for a first
look and not for a network other people are on: the first password would cross it in clear.
Put `--https` at the end of the `docker run` line (or `command: ["--https"]` in the compose
file) and QKVM serves HTTPS from the first request, with a certificate it makes itself; or
publish the port to that machine only (`-p 127.0.0.1:8787:8787`) and put a reverse proxy in
front. Both are described under [How it is protected](#how-it-is-protected).

**From the source:**

```
git clone https://github.com/qkvm/qkvm
cd qkvm
pip install .          # or, for the image:  docker build -t qkvm/qkvm .
```

The first visit walks you through four steps:

1. **Password** – choose the password of the first account, `admin`.
2. **Recovery key** – shown once. Keep it: it is the way back in if a password is forgotten.
3. **Network** – where it is reachable: this computer only, Tailscale, the local network.
   (In a container this is decided by the port mapping, `-p`, instead.)
4. **KVMs** – let QKVM find the KVMs on your network, or paste their addresses, and give
   their login; each one is checked and added.

## Using it

- **Tiles** refresh about once a second. Click one to enlarge it (`←` / `→` switch, `Esc` closes).
  Pictures are drawn pixel for pixel: each frame is fetched with detail to spare (for a
  normal tile, the KVM's full frame) and scaled once to exactly the screen pixels it covers,
  which keeps text sharp at any display scaling.
- **Find and filter:** the counts in the top bar (All / Online / No signal / Attention) are
  buttons, and the search box (`/`) narrows the wall by name, address or group.
- **Groups:** give a KVM a group when adding or editing it (a rack, a room, a customer). Once
  there are groups, the top bar gets a list to show one of them at a time.
- **Your own order:** an admin puts the tiles where they belong with *View → Arrange the
  tiles…*: every tile shows its place, 1, 2, 3 and so on, and is dragged to another, stepped
  one place with the arrows, or given a place by typing its number. *Save this order* keeps
  it on the server, so it is the same for every browser and every screen that shows this
  wall; `Esc` or *Cancel* leaves it as it was. A machine added later stands at the end until
  it is given a place.
- **View** (in the top bar) holds how the wall is shown: the order (as arranged, by name, by
  group, or with what needs attention first), the number of columns, how often a new picture
  is fetched, and display mode. These are each browser's own choice: a wall screen can show
  problems first while a desk keeps the arranged order.
- **Display mode** (*View → Display mode*, or `D`): the screens and nothing else, as large as
  fits, for a monitor on the wall. Move the mouse for a small bar that can rotate through
  the groups every 20 seconds; `Esc` leaves. The address gets `#display`, so a browser on a
  wall screen can be pointed straight at it. For a screen that is to stay on, make it a
  link of its own under *Settings → Tokens* (see [Scripts and wall screens](#scripts-and-wall-screens)):
  a viewer account signed in there with *Keep this browser signed in* is asked for its
  password again after 30 days, and a link is asked for nothing.
- **Find KVMs on my network** (in *Add KVM*): asks the 254 addresses around this computer's
  own (its `/24`, on the network its internet traffic leaves by), and every Tailscale peer
  that is online, whether it is a KVM or a server's controller. It only looks, it does not
  log in. Devices on another network or subnet (a management network, say) are not found:
  type their addresses. A GL.iNet or PiKVM-style KVM reachable both ways is listed once,
  with a choice of which address the wall uses for it; a JetKVM or a server found at two
  addresses is listed at each. A KVM that is on the wall and has **moved** (a new address
  from the router, after a power cut most often) is recognised by its certificate at the
  new address and offered with *Use this address*: the tile follows it, and the password
  saved for it is not asked for again. That holds for a new address typed by hand as well,
  and only for a device that shows the certificate remembered for it: anything else at that
  address is refused and is not sent the password. A device that shows no certificate (a
  JetKVM on plain HTTP) cannot be known again that way, so there the password is typed. In a
  container the search sees the container's network, not yours, unless it is started with
  `--network host` (Linux), and no Tailscale peers (the image has no `tailscale` command):
  type the addresses there.
- **One device, one tile.** A KVM is known by the certificate it made for itself, and a
  server or a JetKVM by its own number, so the wall notices when what you are adding is on
  it already under another address. It then asks: use the new address for the tile that is
  there, or keep both. Tiles that are the same device carry a small *twice* next to their
  name, which leads to the same choice. A device reached through somebody's front door
  (Cloudflare, a proxy) cannot be told apart by its certificate, because the one it shows is
  the door's.
- **Open console** (the arrow on a tile) opens that KVM's own page in a new tab for keyboard
  and mouse control.
- **Multi-port KVMs** (GL.iNet Comet X, four computers on one KVM) get one tile with numbered
  port buttons. The lit one is the computer on screen; click another to switch. Such a KVM
  captures one computer at a time, so there is one live picture per KVM, not one per port.
  Switching takes the KVM a few seconds and also changes a monitor plugged into it.
- **Actions** (the lightning button on a tile):
  - *Keyboard* – Wake screen, Ctrl+Alt+Del, Lock screen, Task Manager, Show desktop, Enter,
    Esc, Close window; *Send keys…* for any other combination; *Type text…* to type a command.
  - *Your actions* – key combinations and text you saved under Settings → Actions.
  - *Power* – Keep awake / Allow sleep (the KVM nudges the mouse); press power, hold power and
    press reset when the KVM has an ATX power board; Wake-on-LAN for the targets saved on it.
  - *Reboot KVM* – restarts the KVM itself.
- **Bulk actions:** press **Select** (or `S`) to enter select mode, tick the KVMs you want
  (*Select all* takes the ones currently shown, so filter or search first), then
  **Run action…**. You confirm against the list of machines; what can lose somebody's work
  (the power and reset buttons, a reboot, typed text, a saved action marked so) needs an
  extra tick; and each KVM reports back as it finishes, with a retry for the ones that
  failed. A run goes to a few machines at a time, or, if you say so when confirming, to one
  after the other in the order shown, with up to two minutes between them: machines switched
  on together draw their starting current together. Wake-on-LAN and switching ports are for
  one machine at a time.
- **One thing at a time per machine.** While an action is on its way to a machine, a second
  one for the same machine is refused, whoever sends it and from wherever: a power button
  pressed twice does not press harder, it undoes the first press.
- **Settings**
  - *KVMs* – add, edit, remove; review a KVM's certificate.
  - *Actions* – your own actions. Saved text is stored encrypted and never shown again. It
    can be typed by every operator, on any machine that operator may use, and what is typed
    can be read there: a saved text is known to all of them. A password that not every
    operator should have is not something to save here.
  - *Network* – where QKVM listens, the port, HTTPS. Changes apply without restarting the program.
  - *Accounts* – who may sign in, as what, and which KVMs they see (see [Accounts](#accounts)).
  - *Alerts* – be told when a KVM goes offline or loses its picture (see [Alerts](#alerts)).
  - *Security* – change your password, two-factor sign-in, the recovery key, sign out your
    other browsers.
  - *Updates* – the running version, checking for a newer one and installing it.
  - *Activity* – who signed in, who changed what, who sent which action (never what was typed);
    to search, to narrow down to one kind, and to download.
  - *About* – version, website, source and licence.
- **Fullscreen** (`F`) and the **colours** (light, dark, or as the system has them) are each
  a button of their own in the top bar, next to Settings.
- **Your account** (the person at the right end of the top bar) says who is signed in and
  as what, and holds your password and second step, and **Sign out**.

Text is typed with a US keyboard layout. On a computer set to another layout, letters and
digits arrive as written but some symbols do not.

## Accounts

The first account is an admin called `admin`. Admins add more under *Settings → Accounts*,
each with its own name, password and role:

| Role | Sees the wall | Runs actions (keys, text, power, ports, reboot) | Settings, KVMs, accounts, updates, activity log |
|---|---|---|---|
| Viewer | yes | no | no |
| Operator | yes | yes | no |
| Admin | yes | yes | yes |

- An operator or viewer can be limited to some of the KVMs: to whole groups, to single
  machines, or both. A group counts as whatever is in it on the day, so a machine added to
  the lab next month belongs to whoever has the lab without anybody ticking it. The other
  machines do not exist for that account: not on the wall, not in the status, not by
  guessing their address.
- An account can be **suspended**: it cannot sign in until an admin lifts that, and is
  signed out at once wherever it was. Its password, role, limits and second step are kept.
  For somebody who is away, or whose access is in question; removing the account would lose
  all of that, and changing its password would say something that did not happen.
- With one account, signing in asks for the password only. With several, it asks for the
  user name too.
- Everyone can change their own password (*Settings → Security*), which asks for the
  current one. An admin can set a new one for somebody else, which signs that account out
  everywhere; their own they change like everybody, where the current one is asked for.
- The only admin cannot be removed or demoted, and nobody can change their own role or
  suspend themselves. An admin who is suspended does not count as one to fall back on.
- *Sign out everywhere* (in an account's *Edit*) ends every session of that account at once
  and changes nothing else about it: for a laptop left on a train.
- The page hides what an account may not use, but the rule is enforced on the server:
  every request is checked against the role, and anything not explicitly opened to
  viewers or operators takes an admin.
- The activity log records the account behind every sign-in, change and action.

### Two-factor sign-in

Anyone can add a second step to their own account under *Settings → Security*: signing in
then asks for the password and for a 6-digit code from an authenticator app (Google
Authenticator, Microsoft Authenticator, 1Password, Aegis and so on). Setting it up shows a
QR code to scan (and the same key as text); a code works once.

- **It can be required.** *Settings → Accounts → Two-factor sign-in: required of* admins, of
  admins and operators, or of everybody. An account under the rule that has not set it up
  signs in with its password and lands on one page, which sets it up; until that is done it
  sees no screen and can do nothing else. Whoever makes the rule has to have it switched on
  for their own account first.
- **One-time codes for when the phone is not at hand.** Switching the second step on hands
  out ten codes, shown once: each signs you in a single time in place of a code from the
  app (*No phone at hand?* on the sign-in page). *Settings → Security* says how many are left
  and makes ten new ones, which ends the old. QKVM keeps only what it needs to recognise
  them, under the same key as the saved passwords, and a sign-in with one is marked as such
  in the activity log.
- **Wrong codes hold the account, not only the address.** After five of them, from wherever
  they came, the second step of that account is refused for 30 seconds, doubling up to 15
  minutes. Only somebody who has the password ever finds that out.
- If the phone is lost and the codes with it, an admin can take the second step off that
  account under *Accounts*; under a rule that requires it, the next sign-in sets it up anew.
  If it was the only admin's phone, run `qkvm --disable-2fa NAME` on the computer QKVM runs
  on.

### Signing in through your identity provider

Where people already sign in in one place (Authelia, authentik, Keycloak with oauth2-proxy,
a company's own gateway), QKVM can take that place's word for who somebody is. It is the
reverse proxy in front of QKVM that signs people in, and tells QKVM in a header:

```
qkvm --trusted-proxy 172.18.0.5 --sso-header Remote-User
```

```
server {
    listen 443 ssl;
    location / {
        auth_basic "QKVM";                          # or auth_request to your identity provider
        auth_basic_user_file /etc/nginx/users;
        proxy_pass http://qkvm:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Remote-User $remote_user;  # set by the proxy: whatever the visitor sent under that name is gone
    }
}
```

- Whoever the proxy names is signed in as **the QKVM account of that name**, with the role
  and the machines that account has. There has to be one: *Settings → Accounts → Add
  account*, with the name the proxy sends (`olga`, `olga@example.org`) and no password.
  Somebody the proxy knows and QKVM does not is told so, and sees nothing.
- **The header is believed of the proxy named with `--trusted-proxy`, and of nobody else:**
  not of the visitor, not of another machine on the network, not of a program on the same
  computer. And only where it arrives once: a proxy has to *set* it, as above, not add its
  line to one the visitor sent. Make sure nothing reaches QKVM's port except through the
  proxy (publish it to the proxy's network only, or use `--allow-from` with its address).
- **The second step is the identity provider's.** Somebody it signed in is not asked for
  QKVM's own code, whatever rule is set under Accounts; that rule is for those who sign in
  here with a password. An account without a password cannot be signed in to by typing
  anything, and a copy of the data folder holds nothing of it to guess at.
- Access is taken away in either place: at the identity provider, or here, by suspending or
  removing the account, which ends its session at once.
- It cannot be had with `--locked-start`: whoever signs in elsewhere brings no password
  here, and without a key of its own QKVM could not open the saved device passwords (see
  [Keeping it running](#keeping-it-running)).
- Accounts with a password still sign in with it, which is the way in when the identity
  provider is down. Keep at least the first admin that way.

## Alerts

*Settings → Alerts* makes QKVM watch the KVMs and tell you when one goes offline, when a
computer loses its picture, when a login is rejected or a certificate changes, and when that
is over. A change counts once it has lasted about half a minute.

- Alerts are posted to a webhook address: an [ntfy](https://ntfy.sh) topic, a Slack or
  Discord incoming webhook, or anything that accepts a JSON POST. The address is stored
  encrypted. *Send a test alert* tries it.
- Every change is also written to the activity log, with or without an address.
- **An alert says where to look.** *Link in alerts* is the address of the wall as you reach
  it; an alert then carries a link that opens the wall at the tile it is about (in ntfy, a
  tap on the notification does). Leave it empty for alerts without one.
- **One machine can be left out:** *Settings → KVMs → Edit → Send alerts about this one*. For
  a test bench that is switched on and off all day, or a machine that sleeps.
- **Pause for maintenance:** *Pause alerts*, for an hour or for four, sends nothing while machines
  are worked on, restarts included. When the pause is over, what is not as it was before it is
  told then, so nothing that went wrong meanwhile stays unseen; what went wrong and was put
  right within the pause is not mentioned. The changes are in the activity log all the same.
- While alerts are on, QKVM keeps watching after everyone has signed out, and after a restart
  (see below). What each machine was last seen as is written down, so a machine that does not
  come back when QKVM does (after a power cut, most of all) is told about: two minutes after
  the start, which is the time QKVM gives its own network to come up before it believes
  that anything is gone.
- A JetKVM that is not on screen is only checked for answering, because looking at its
  picture would take its one viewer slot.
- For a [server](#servers), "lost its picture" means it was switched off, and a critical
  fault reported by its controller counts as a problem.
- **After a restart QKVM goes on alerting by itself**, as it goes on watching. Not where it
  is started with `--locked-start`: the address alerts go to is itself saved encrypted, and
  so are the devices' passwords, and until somebody signs in QKVM can then neither look at a
  device nor tell anybody. `GET /healthz` says `"locked": true` for as long as that lasts
  (both under [Keeping it running](#keeping-it-running)).

## Export and import

*Settings → Export and import* writes the wall to a file, and takes a file in: to keep what
was set up, to fill a second QKVM without typing every device again, or to move to another
computer.

**Export** asks for your password again, and for what the file is to hold: the KVMs and
servers, the saved actions, the alert settings, the wall's settings.

- **With a passphrase** it is an encrypted file (`qkvm-<date>.qkvm`). It holds everything,
  the passwords of the devices, the texts of saved actions and the address alerts go to
  included, and opens with that passphrase only (scrypt and AES-256-GCM, as the saved
  passwords themselves are kept). The passphrase needs ten characters or more; keep it
  somewhere else than the file. Nothing of the wall can be read off the file without it,
  not a name and not an address either (its size says roughly how much is in it).
- **Without one** it is a plain file (`qkvm-<date>.json`): the same, with every password,
  every saved text and the alert address left out. It can be read, compared and kept
  anywhere.

**Import** reads either kind and says what is in it before anything is taken: every device
with its address, how its certificate is checked where that is not the usual way, and where
its console link leads; every saved action with what it does, and for one that types a text,
the text (which the wall shows nowhere once it is saved). A file may come from somebody
else: read that list. Then it takes in what you tick.

- KVMs and servers are **added** where the wall has none at that address, and none that is
  the same device under another address (known by what it says it is, or by its
  certificate). The page asks "keep both?" about such a one; a file cannot be asked, so it is
  left out and said, unless the wall it comes from was told "keep both" for that very tile.
- A saved action is added where the wall has none of that name, whatever it does.
- Nothing that is on the wall is changed or removed by a file, and taking the same file in
  twice adds nothing twice.
- A device from an encrypted file works at once, with the password and the remembered
  certificate it came with. One from a plain file says "Login failed" on its tile, with
  *Update login* beside it, until its password is typed.
- The alert settings and the wall's settings, of which there is one set, are **replaced**,
  and only where you tick them. A file without an alert address leaves the address the wall
  has. The link an alert carries back to the wall, and a pause, are the wall's own and are
  in no file.
- No device is talked to while a file is read. What does not pass (an address that is none,
  a kind of device this version does not know) is left out, and said.

A file written by hand in the same form is taken in as well: a list of devices as
`{"format": "qkvm-export", "version": 1, "devices": [{"url": "https://192.168.1.20",
"kind": "kvmd", "username": "admin", "password": "..."}]}` fills a new wall in one go. A
plain file with passwords in it is whoever wrote it's own to look after; the page says so
when it reads one.

**Not in any such file:** accounts, tokens and display links, two-factor keys and the
recovery key. Each is locked to the key of the QKVM it was made on, and could be carried
over only by carrying that key. To keep a whole QKVM, accounts and all, keep a copy of its
data folder (with QKVM stopped, or of `qkvm.json`, `unlock.key` and `audit.log` at least),
as carefully as the passwords in it: see [How it is protected](#how-it-is-protected).

An export is written to the activity log, with who made it and whether it was encrypted
(a wrong password at it as well), and every device a file adds is written there by name and
address, as one that is typed in is.
A token cannot ask for one, and neither can an account that only your identity provider
signs in: it has no password here to be asked for. Export as an admin that has one.

## Scripts and wall screens

*Settings → Tokens* makes two things that use QKVM without a person signing in. Both are
shown once, QKVM keeps only what it needs to know them again, and an admin can take either
back at any moment. Neither can change settings, accounts, devices or other tokens: that
takes a person.

**A link for a wall screen.** Open it once in the browser of that screen. The browser keeps
it, shows the wall as a display, and when QKVM has been restarted it comes back in by
itself: nobody has to stand at the screen with a keyboard after a power cut. It can look at
the machines it was made for, and no more than look. (The pictures are back by themselves
as well: QKVM carries on after a restart, see [Keeping it running](#keeping-it-running).
Only where it was started with `--locked-start` are they back once somebody has signed in
anywhere.)

**A token for a script** has a role (viewer: look; operator: look, and act on machines),
the machines it is for, and a date it works until. The script sends it with every request:

```
curl -H "Authorization: Bearer qkvm_..." https://qkvm.example:8787/api/v1/status
```

| Request | For | Answers |
|---|---|---|
| `GET /api/v1/wall` | viewer | the machines the token is for: `id`, `name`, `host`, `kind`, `group` |
| `GET /api/v1/status` | viewer | by `id`: `state` (`online`, `no_signal`, `offline`, `auth`, `error`, `busy`, `connecting`), seconds since it last answered, and what it reports about itself (video signal, power, temperatures) |
| `GET /api/v1/devices/{id}/snapshot?w=1280` | viewer | the screen as a JPEG, at least that many pixels wide where the source has them |
| `GET /api/v1/actions` | operator | the saved actions, to run by their `id` |
| `POST /api/v1/devices/{id}/actions` | operator | does something to that machine: see below |
| `GET /healthz` | nobody | `{"status": "ok", "version": "...", "api": ["v1"], "page": "...", "locked": false}`, without a token |

The `v1` in the paths is the version of this interface. What a script is written against
goes on working: within `v1`, requests and fields are added and none is taken away or given
another meaning, and a change that would break a script gets a path of its own (`/api/v2/`)
beside this one. `GET /healthz` says which versions a QKVM speaks (`"api"`). The table above
is all of `v1` that is promised: the other requests under `/api/v1/` are the page's own, and
change with it.

What to do is said as JSON, `{"action": "..."}`:

| `action` | Does | Also give |
|---|---|---|
| `power_on`, `power_off` | a server: switch on, or ask it to shut down; one that is there already answers `"note": "already on"` | |
| `atx_power`, `atx_power_long`, `atx_reset` | press the power button, hold it, press reset | |
| `reboot` | restart the KVM itself (for a server: its controller) | |
| `ctrl_alt_del` | Ctrl+Alt+Del | |
| `keys` | a key combination | `"keys": "MetaLeft,KeyL"` |
| `text` | type text | `"text": "...", "enter": true` |
| `custom` | one of the saved key combinations (saved text is typed by people only: a token that types it could read it back off the screen) | `"custom_id": "..."` |
| `jiggler_on`, `jiggler_off` | keep the computer awake, or let it sleep | |
| `wol` | Wake-on-LAN from the KVM | `"mac": "aa:bb:cc:dd:ee:ff"` |
| `port` | show another input of a multi-port KVM | `"port": 0` |
| `locate_on`, `locate_off` | a server's locator light | |

- Every answer is JSON. A refusal is `{"code": "...", "message": "..."}` with a status that
  fits: 401 without a valid token, 403 for what its role does not allow, 404 for a machine
  it is not for, 409 `busy` while something else is being done to that machine, 502 when
  the device refused or did not answer.
- After a restart QKVM carries on by itself, and a token works as before. Where it was
  started with `--locked-start`, a token is answered `503 locked` until somebody has signed
  in, because QKVM cannot reach its devices before that: that is not the way to start it
  where scripts run unattended. (The same answer comes for as long as the key it carries on
  with cannot be read, or does not fit yet: `GET /healthz` says `"locked": true` then.)
- A token cannot ask for a way into a server's console, and has nothing to sign out of.
- What a token did is in the activity log under its name.
- The page itself uses this interface, and more of it than the table above. What is in the
  table stays as it is within `v1`; the rest is the page's own and can change from one
  version to the next.

## Metrics

A monitoring system can collect the state of the wall: *Settings → Metrics* makes a token, and
from then on `GET /metrics` answers whoever sends it, in the text format that Prometheus and
everything that reads its format understand:

```
scrape_configs:
  - job_name: qkvm
    metrics_path: /metrics
    authorization:
      credentials: qkvm_...            # the token, as shown once when it was made
    static_configs:
      - targets: ["192.168.1.20:8787"]
```

QKVM answers when it is called by an IP address, by a name without a dot, or by one ending in
`.local`, `.lan`, `.internal`, `.home.arpa` or `.ts.net`. Any other name the collector is to
reach it by has to be listed under `allowed_hosts` in `qkvm.json`, as for a browser.

| Metric | Says |
|---|---|
| `qkvm_devices{state}` | how many tiles are in each state: `online`, `no_signal`, `offline`, `auth`, `error`, `busy`, `connecting` |
| `qkvm_device_up{id,device,kind,group}` | 1 while that device answers, 0 while it does not |
| `qkvm_device_picture{…}` | 1 while it shows a picture; for a server, while it is switched on |
| `qkvm_device_last_seen_seconds{…}` | seconds since it last answered |
| `qkvm_device_temperature_celsius{…,sensor}` | how warm it is: the KVM itself (`sensor="device"`), or each sensor of a server |
| `qkvm_server_healthy{…}` | 1 while a server's management controller calls it healthy |
| `qkvm_unlocked` | 1 while QKVM can talk to its devices (somebody has signed in since it started) |
| `qkvm_sessions`, `qkvm_devices_configured`, `qkvm_update_available`, `qkvm_info{version}`, `qkvm_start_time_seconds` | about QKVM itself |

- The token is shown once and QKVM keeps only its hash. It lets its holder read the above and
  nothing else; a new one replaces it, and *Switch off* makes `/metrics` answer nobody.
- While metrics are on, QKVM goes on watching the devices after the last person has signed
  out, as it does for alerts: the saved device passwords stay usable in memory for that.
- After a restart QKVM goes on by itself. Started with `--locked-start` (see
  [Keeping it running](#keeping-it-running)), nothing can be collected about the devices
  until somebody signs in; `qkvm_unlocked` is 0 until then, which is worth an alert of its own.
- A collector is nobody watching: a JetKVM that is not on screen is only asked whether it
  answers, as for alerts, and its one viewer is left to whoever wants it.
- `GET /healthz` is separate and needs no token. It says that QKVM is running, which version,
  and whether it is still waiting for a sign-in after a restart (`"locked"`).

## JetKVM

Add a JetKVM like any other KVM: type its address and QKVM recognises it. Leave the
password empty if the JetKVM has none; the user name is ignored. A JetKVM has no "send me a
picture" request: its screen exists only as WebRTC video, so QKVM connects the way the
JetKVM's own page does. What that takes (the `aiortc` package and the video decoder it
brings) is installed with QKVM. It is most of what an install takes on disk (75 to 120 MB of
it, depending on the system), and is loaded only once there is a JetKVM on the wall.
How a JetKVM is reached is its owner's choice, made at the device's own page (*Settings*,
*Access*), and QKVM goes along with it:

- **HTTPS or plain HTTP.** Out of its box a JetKVM serves plain HTTP. With its HTTPS mode on
  it serves HTTPS beside that, with a certificate of its own making or one you give it.
  QKVM asks both ways and uses HTTPS wherever the JetKVM offers it, also where `http://` was
  typed in front of the address; its certificate is remembered on first contact, as a
  Comet's is. An address typed with `https://` is never answered the plain way: where only
  plain HTTP answers, that is said, and the address is yours to type with `http://`. A
  JetKVM added over plain HTTP says so in the list of what was added.
- **When that is changed later, the tile follows.** A JetKVM on the wall over plain HTTP is
  asked every ten minutes whether it offers HTTPS by now, and moved there when it does. It
  is asked as well before QKVM signs in to it, and before a password you type for it is
  sent or a saved one is used in an edit, so that none goes out unencrypted where HTTPS is on
  offer. Each move is in the activity log. The other way round nothing moves by itself: a
  JetKVM that stops answering over HTTPS for two minutes and answers over plain HTTP keeps
  its address, with a password or without, and its tile says so. Over plain HTTP nothing is
  checked any more, and the certificate remembered for it is let go of by a person only: to
  allow it, change its address to `http://` (and type its password again, if it has one).
- **With a password or without.** Type the password when adding it, or leave it empty for
  one that has none. A password switched on at the device later shows on its tile as
  *Login failed*, with **Update login** to type it in. A JetKVM fresh from its box, where
  nobody has chosen yet how it is signed in to, lets nobody in and is said to be that.
- **Loopback-only mode** (*Settings*, *Advanced* on the device) shuts everything but the
  device itself out, QKVM included.

Three things are different from a Comet, and they come from the device:

- **One viewer at a time.** A JetKVM shows its picture to a single connection. While it is
  on the wall, QKVM is that viewer. When someone opens the JetKVM's own console, the tile
  says *In use elsewhere* and QKVM stays away, so it never throws that person out.
  **Show here** on the tile takes the picture back (and disconnects them).
- **Signing in signs others out.** A JetKVM with a password has one session for everybody:
  when QKVM logs in, a browser logged in to that JetKVM has to log in again, and the
  other way round. QKVM logs in once and keeps its session for as long as it can.
- **It must be reachable directly**, on the LAN or over a VPN such as Tailscale. JetKVM
  Cloud only works from a browser signed in with Google, so QKVM cannot go through it.

The picture is decoded on the computer running QKVM, and a JetKVM sends video at the rate
of the screen it watches. Measured with a 1920×1200 screen at 60 frames a second, one JetKVM
takes about 15 % of one core of a desktop processor for as long as somebody has the wall
open; half a minute after the last viewer has gone, QKVM disconnects and it takes nothing.
Keys, typed text (US layout, ASCII only), keep-awake, Wake-on-LAN, the ATX power extension
and reboot are in the action menu. On a real JetKVM the restart works and keys, keep-awake
and Wake-on-LAN are accepted; typed text and the ATX extension have so far only been tried
on a stand-in (see [Limits](#limits)).

## Servers

A server board has a management controller of its own (a BMC): AMI MegaRAC on ASRock Rack,
Gigabyte and many others, iDRAC on Dell, iLO on HPE, OpenBMC. They share one interface,
Redfish, and QKVM speaks it. Add a server like a KVM: type the address of its controller,
with the controller's user name and password, and QKVM recognises it. *Find KVMs on my
network* finds controllers as well.

**A server's tile shows the server's screen**, as a KVM's does, where the controller runs AMI's
MegaRAC firmware (ASRock Rack, Gigabyte and many others). Redfish itself has no picture; the
screen is in the console that the controller's own web page opens, and QKVM takes it from there:

- It signs in to that page with the login saved for the controller, opens the console, and
  only looks. No key, mouse movement or power command goes that way.
- It holds one of the controller's console seats (as a rule there are two) while somebody
  looks at the wall, and gives it back twenty seconds after nobody does.
- It keeps out of the way of whoever works at the console. Somebody who opens the controller's
  own console while the wall has it is let in at once, keys and all, and the wall goes on
  looking. When somebody has the console first, the controller asks them whether a newcomer
  may look; the wall does not leave that question on their screen. It leaves the moment it is
  told to wait, shows how the server is, says why, and looks again ten minutes later.
- A controller that is set to switch the server's own monitor off while a console is open is
  left alone, and the enlarged tile says why there is no picture. Ten minutes later it is asked
  again, in case the setting was changed.
- A controller ends a console session in which no key was pressed for a while (half an hour,
  on the boards this was tried with), and QKVM presses none. It opens the console again at
  once, and the tile keeps its picture for the moment that takes.
- The tile's footer says how large the screen is, how the server is and how warm. Enlarged,
  **Health** shows every temperature and every fan.
- The picture is read in Python, and what a controller sends is not believed. A text console
  costs next to nothing; a screen that changes all over (a video, a desktop being dragged
  about) takes seconds a frame on a desktop processor. The frames of two servers are read at
  a time and the others wait their turn, so busy screens slow each other's pictures and
  nothing else. No frame may be longer, or bring more, than a screen of its size could take
  twice over, and a screen larger than 2048 pixels either way is not shown.

On a controller of another make (iDRAC, iLO and the rest speak consoles of their own), and
whenever the screen cannot be had, the tile shows how the server is doing instead. That, and
what else a server's tile gives:

- Whether it is **on or off**, its **health** as the controller judges it, how warm its
  processors are and how many fans are running. Enlarged, every temperature and every fan,
  and which of them the controller is not happy with.
- **Power on** switches the server on and **Shut down** asks its operating system to shut
  down. A server that is already on, or already off, is left as it is and says so, which
  is what makes them safe to run on a whole selection: after a power cut, *Power on* brings
  back the servers that stayed off and does nothing to the ones that came back by
  themselves. (A KVM's power button cannot promise that: it presses a button, and what the
  press does depends on whether the computer is on.) **Hold power button** cuts the power,
  and **Press reset button** restarts it the hard way. **Restart controller** restarts the
  controller itself; the server keeps running.
- **Locator light on** lights the server up, front and back, for whoever is standing in
  front of the rack looking for it. The tile says so for as long as the light is on.
- **Open console** leads to the controller's own page, where its remote console is. Where
  the controller hands out a pass for that (AMI's does, on the boards whose maker left it
  in), the link leads straight into the console, signed in. See below for what that means.
- [Alerts](#alerts) tell you when a server is switched off or comes back, when its
  controller stops answering, and when the controller reports a critical fault, with the
  names of the sensors behind it. A fault that comes and goes (a fan at its limit makes a
  controller call itself critical and well again every few seconds) is one problem: the tile
  stays on it, and "recovered" is said once it has stayed away for five minutes.

A few things are worth knowing:

- **Done means seen.** A controller answers "accepted" before anything has happened, and now
  and then nothing does. When a server is switched on, or its power cut, QKVM waits until it
  sees the server on, or off, and says so if it does not get to. A request to shut down is
  different: the system takes the time it takes, and the tile shows when it is off.
- **A controller has its moments.** It is a small computer, and one in perfect health lets a
  request time out now and then, or answers errors for some seconds while its server starts
  or stops. The tile does not change for that. It does once the controller has given no
  proper answer for three quarters of a minute.
- **One sign-in, kept.** A controller allows only a few sessions at a time. QKVM signs in
  once, goes on using that session, and gives it back when the server is taken off the wall.
- **A rejected password is left alone.** Controllers lock an account after a few failed
  logins, for you as well. A password that the device said no to is tried again after a
  minute, five minutes after that, a quarter of an hour after that, and from then on once
  an hour, however often the wall is looked at or signed in to meanwhile. A KVM and a
  JetKVM are treated the same, and the controller's own console is offered the password
  no sooner than that. Only a no counts. A sign-in that is answered with an error of the
  device's own, or not at all, says nothing about the password: it is tried again after
  ten seconds, then after twice as long each time, five minutes at the most. A JetKVM
  that says when to come back (it shuts an address out after five wrong passwords) is
  asked then, and no sooner than a minute. The console's web page has waits of its own
  after such a failure: half a minute, then one, two and five, and ten where asking
  again would change nothing. (A device that answers everything but its sign-in is shown
  as having a problem, not as offline.) Typing the password again tries at once: with
  *Update login* on a tile that says *Login failed*, in the device's own dialog
  otherwise. What was rejected is kept in memory: after a restart of QKVM it is tried
  once more. While it waits QKVM still asks twice a minute whether the device is there,
  without the password, so a machine that goes off meanwhile is shown as offline.
- **The account decides what works.** An account with the controller's read-only role is
  enough to show the state. The power buttons and the locator light need the operator or
  administrator role.
- **A console opened from the wall is signed in as that account.** The pass works once and
  goes to the browser of whoever clicked, nowhere else; that they went in is written to the
  activity log. Operators and admins of the wall can do this, viewers cannot, and an account
  limited to some machines only for those. If the people on your wall should not have what
  the controller's account has, give the wall a controller account that has less.

## How it is protected

- **No account's password is stored.** Each account's password derives (scrypt) a key that
  unlocks the one key every saved KVM password is encrypted with (AES-256-GCM).
- **The saved KVM passwords are as safe as the data folder.** So that QKVM carries on by
  itself after a restart, a key that opens them without anybody's password lies in that
  folder too (`unlock.key`). Say it plainly: **someone who copies the data folder has the
  saved KVM passwords**, and with them the texts saved to be typed, every account's
  authenticator key and the address alerts go to. They have no account's password, and they
  are not signed in to anything. Keep the folder, and every backup of it, as you would keep
  those passwords.
  (Where QKVM makes the folder itself, on Linux and macOS it is readable by its owner only.)
  There are two ways to have it otherwise, both under
  [Keeping it running](#keeping-it-running): `--unlock-file` keeps that key where the
  folder's backups do not go, and `--locked-start` keeps none. With `--locked-start` a copy
  of the data folder is worth nothing without an account's password (any account's, a
  viewer's included, so give every account a good one), and after every restart QKVM
  reaches no KVM until someone signs in.
- **Forgotten password:** *Forgot your password?* on the sign-in page lists the ways back in.
  - *The recovery key* sets a new password for any account and keeps everything else as it
    was. It is shown once when QKVM is set up; an admin can make a new one under
    *Settings → Security*, which cancels the old one. Only a locked copy is stored. Whoever
    holds it can take over any account, so keep it like a password, and not on the computer
    QKVM runs on. It replaces the password only: an account with two-factor sign-in still
    needs its code.
  - *Another admin* can set a new password for you under *Settings → Accounts*.
  - *Starting over:* with neither, `qkvm --reset-password` forgets every account
    and the recovery key, so the first account can be created again. The saved KVM passwords
    were encrypted for those accounts, so they are erased and must be entered again; the
    list of KVMs and the other settings stay.
- **Sign-in** uses an HttpOnly, SameSite=Strict session cookie. Repeated wrong passwords lock
  the address they come from out for 30 seconds, doubling up to 15 minutes. Signing in to one
  account does not forgive guesses made at another, and the addresses of one IPv6 network
  count as one.
- **HTTPS from the first request:** started with `--https`, QKVM never serves plain HTTP,
  not even for the first-run setup, and the box in the settings cannot switch it off. With
  `--tls-cert` and `--tls-key` it uses a certificate of your own (from your company's
  authority, say) instead of the one it makes: the files are checked at start, and read
  again at every restart of the listeners, so a renewed certificate is picked up by a restart.
- **Only from where you say:** with `--allow-from` and a list of addresses or networks
  (`--allow-from 192.168.1.0/24,100.64.0.0/10`), QKVM answers those and the computer it runs
  on, and turns everybody else away before there is a sign-in page to guess at. Behind a
  named proxy it is the visitor's address that counts. Given without an address (an empty
  variable in a compose file), the option is an error at start and not "everybody".
- **Behind a reverse proxy,** start QKVM with `--trusted-proxy` and the proxy's address or
  network (`--trusted-proxy 172.18.0.0/16`). It then takes the visitor's address from
  `X-Forwarded-For` and "came over HTTPS" from `X-Forwarded-Proto`, both of which the proxy
  has to send. Without that every visitor looks like the proxy: five wrong passwords by one
  lock everybody out, and the activity log names the proxy. Where no proxy is named, one on
  the same computer is believed as it is (`tailscale serve`, for one), and has to send
  `X-Forwarded-For` as well: one that sends nothing makes every visitor look like somebody
  sitting at that computer, who is let through the first-run setup without the code. That
  also means that any program on that computer can say it is passing on whichever address
  it likes. Once a proxy is named, only what was named is believed: name `127.0.0.1` too if
  one of your proxies runs on the same computer.
- **First-run setup takes a password and nothing else**, so a new QKVM belongs to whoever
  opens it first: choose the password right after starting it. Started with `--setup-code`,
  QKVM asks whoever sets it up from another machine for a code printed in its terminal (or
  its log: `journalctl -u qkvm`, `docker logs qkvm`), so that nobody on the network can
  claim a copy you just started. Use it where others can reach the port before you do.
- **Each KVM's certificate is remembered** the first time QKVM talks to it (like an SSH host
  key). If something else answers at that address later, QKVM refuses to send it the password
  and the tile says so; *Settings → KVMs → Edit → Review certificate* shows both fingerprints.
  A tile moved to another address takes its saved password along only where the device
  there shows that same certificate; anywhere else, and always for a server's controller
  (whose maker may have put one certificate on every board), the password is typed again.
- **Give QKVM a host name or address of its own.** A browser keeps what signs it in by host
  name, not by port. Where a device's own page is reached on another port of the name QKVM
  is looked at under (a router that forwards two ports of one name, tunnels to `localhost`),
  the browser would hand that page your sign-in to QKVM, and a device is not trusted with
  that. The wall offers no *Open console* link to such a device and says why.
- **HTTPS** for QKVM itself is one checkbox (a certificate is made on this computer; its
  fingerprint is shown so you can check the browser's warning). Turn it on whenever QKVM
  listens on the local network. Tailscale already encrypts its traffic.
- Every change must come from QKVM's own page (cross-site requests are refused), the page
  runs under a strict Content-Security-Policy, and requests for unknown host names are rejected.
- **Nobody holds a connection for nothing.** One that has not sent a whole request within 20
  seconds is closed, a request's body gets the same, one that asks and then takes nothing of
  the answer for 20 seconds is dropped, and there is nothing in QKVM that is spoken to over a
  websocket. Wrong passwords are checked two at a time at most, so that
  guessing cannot use up the computer's memory.
- **A KVM is not trusted either.** What a device sends is read only up to a limit, only JPEG
  and PNG data of a sane size is passed on to a browser as a picture, and what a device says
  about itself (name, model, numbers) is reduced to plain short text or a number before it is
  shown or logged. A device cannot send QKVM on to another address, and QKVM talks to it
  directly whatever proxy the computer is set to use for the web (that one is used for
  alerts and for update checks). A broken or taken-over KVM can show a wrong picture; it
  cannot fill the memory of the computer QKVM runs on, or of the browser looking at it, or
  put a page of its own in your browser. One part of that is not QKVM's own to promise: a
  JetKVM's video and its control channel come through a WebRTC library (aiortc), and what a
  taken-over JetKVM could make that library hold or compute has not been measured.
- **The activity log** (*Settings → Activity*) keeps about 20 MB, which is years of an
  ordinary wall. It is a file of JSON lines, `audit.log` in the data folder: one entry a
  line, with the time, what happened, the address it came from, the account, and what it
  concerned. Where it cannot be written (a full disk), what is asked for is done all the
  same, a power button included, and the log says at its top how many entries are missing
  and since when. A log collector (Filebeat, Vector, Promtail) can follow it from there.
  Started with `--audit-syslog collector.example` (or `host:port`, or `tcp://host:port`),
  QKVM also sends each entry to a syslog collector as it is written (RFC 5424, the entry as
  JSON in the message), so that what was done is known somewhere whoever did it cannot
  reach. The file stays the record: an entry the collector was not there for is not sent
  again, and nothing in QKVM waits for the collector. In the
  page it can be searched (under the names the page shows, or the ones in the file), narrowed
  to sign-ins, actions, changes or alerts, and downloaded as a table (CSV) or as the lines
  themselves; in the table, a name that begins like a spreadsheet formula is written as text.
- What every account may look at on the wall is a tile's name, address and console link; how
  QKVM signs in to a device is shown to admins only.
- **Updates are installed only when signed** by the publisher's release key (see *Updates*).
- At start, QKVM says so if a library it runs on is older than the first version without a
  known vulnerability.

## Keeping it running

- **A KVM that is down doesn't slow the others.** It is retried less and less often (up to every
  15 seconds), its tile says when it was last seen, and the other tiles carry on. A KVM that
  reboots is picked up again by itself.
- **Log:** `qkvm.log` in the data folder (rotated at 2 MB, three old files kept) records starts, listener
  changes, KVMs going down and coming back, and errors inside the program. What the web server and the
  libraries have to say goes there too, one line of each kind a minute at the most: a line for every
  request that is none would be the log's history gone in minutes. Sign-ins, refused ones too, are in
  the activity log. `--log-level debug` writes more.
- **Health check:** `GET /healthz` answers `{"status": "ok", "version": "…", "api": ["v1"], "page": "…", "locked": false}`
  without a login, for a monitor or a watchdog. (`"page"` is a mark of the page's own files: a
  browser tab left open across a restart compares it with its own, and fetches the page again
  when they differ.) `"locked": true` means QKVM cannot open the saved device passwords just
  now: it was started with `--locked-start` and nobody has signed in since, or it has not
  been signed in to once since it was set up or its key was changed. It is running, and
  until somebody signs in it cannot reach a single device, so nothing is watched and no
  alert is sent. Have whatever monitors QKVM tell you about it.
- **Carrying on after a restart:** QKVM opens the saved device passwords itself at start, and
  goes on watching, alerting and answering a collector without anybody signing in. A browser
  that signed in with *Keep this browser signed in for 30 days* stays signed in across the
  restart; any other is asked for its password again, as is every visitor: the key opens
  the saved passwords for the program, not the wall for whoever comes by. What makes it
  possible is a key in the data folder (`unlock.key`), made at the first start. The first
  sign-in makes it fit this data folder, and from the next start on it opens it.

  What it costs: the key lies beside what it opens, so whoever has a copy of the data folder
  has every saved device password. The two other ways:

  - `--unlock-file FILE` keeps the key in a file of your choosing, where the folder and its
    backups do not go: a systemd credential, a Docker secret, another disk. Each is then
    useless without the other. QKVM makes the file if it is not there, refuses one that lies
    in the data folder, and says so when other users of the computer can read it (on Windows
    it cannot tell: keep the file in a folder that is yours alone).
  - `--locked-start` keeps no key. A copy of the data folder is then worth nothing without
    an account's password. After every restart nothing is watched, no alert is sent and
    every browser signs in again, until a person has been by; a power cut is when that matters.

  Going from one way to another takes one start and one sign-in. What the key before opened
  the folder with is taken out at that start, so a copy of it that somebody kept opens
  nothing afterwards. That is true of the key, not of an older copy of the whole folder:
  the saved passwords are encrypted with one key for as long as the accounts exist, and a
  backup from the time a key lay in the folder holds that key and what it fits, and reads
  what was saved since. To cut older copies off, `--reset-password` and enter the device
  passwords again; and keep backups as you would keep those passwords.
- **Backup:** everything QKVM knows is in the data folder. Copy the folder; it is safe to do
  while QKVM runs (the settings file is replaced in one step, never written halfway). To
  restore, or to move to another computer, put the folder there and start QKVM with it
  (`--data-dir`): accounts, devices and saved passwords are as they were, opened by the same
  account passwords. A copy holds the key that opens the saved device passwords, so keep it
  as you would keep those. (Not so with `--unlock-file` or `--locked-start`: then a copy is
  worth as much as the weakest account password it was made under.)
- **How large:** the largest wall run so far had 13 real KVMs for a night, and 44 stand-ins for
  an hour with a picture a second each: about 40 % of one processor core and 130 MB of memory,
  steady. Each tile that is being looked at costs the KVM one picture a second and QKVM
  little; a JetKVM costs more (see [JetKVM](#jetkvm)). Nothing is known yet about hundreds.
- **Settings file:** every change is written atomically, and a second copy of what was just
  saved is kept as `qkvm.bak` next to it. If `qkvm.json` is ever unreadable or gone (a hand edit
  gone wrong, a start that was cut off), QKVM starts from that copy, sets a damaged file aside
  and says so. The copy is of what was saved last, not of what was there before: nothing that
  was taken away (an account, a token, a password) comes back by it. A change that cannot be
  saved (a full disk) is refused and taken back, and the answer says so.
- **One copy per data folder:** a second `qkvm` pointed at the same folder refuses to start,
  so typing `qkvm` while it is running already does no harm.
- **After changing the program's files by hand, restart it.** The page is loaded into memory
  at start, so a browser always gets the page that matches the running server. (Updates
  installed from inside the app restart it for you.)
- **Start it with the system (Linux):** a systemd unit does it. With QKVM installed in an
  environment of its own (`python3 -m venv /opt/qkvm`, then `/opt/qkvm/bin/pip install qkvm`),
  this as `/etc/systemd/system/qkvm.service`:

  ```
  [Unit]
  Description=QKVM
  After=network-online.target
  Wants=network-online.target

  [Service]
  ExecStart=/opt/qkvm/bin/qkvm --data-dir /var/lib/qkvm
  DynamicUser=yes
  StateDirectory=qkvm
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target
  ```

  and `systemctl enable --now qkvm`. It runs as a user of its own that can write to
  `/var/lib/qkvm` and nowhere else. (With `--setup-code` on the `ExecStart` line, the code
  asked for at the first-run setup is in `journalctl -u qkvm`.)

  It carries on by itself after a restart. To keep the key that makes that possible out of
  the data folder and its backups, make one that only root can read and hand it to the
  service as a credential, which no other user of the computer can see:

  ```
  install -d -m 700 /etc/qkvm
  head -c 32 /dev/urandom | base64 > /etc/qkvm/unlock.key
  chmod 600 /etc/qkvm/unlock.key
  ```

  then add `LoadCredential=qkvm-unlock:/etc/qkvm/unlock.key` under `[Service]`, and
  ` --unlock-file %d/qkvm-unlock` to the end of the `ExecStart` line. Sign in once, and from
  the next restart on it is this key that opens the saved passwords.
- **Start it with Windows:** one way is a task that runs at log-on:

  ```
  schtasks /Create /TN "QKVM" /SC ONLOGON /RL LIMITED /TR "pythonw -P -m qkvm"
  ```

  QKVM comes up watching; a browser shows screens once someone has signed in there. Started this way there is
  no terminal: what it would say there is in `qkvm.log` in the data folder (the setup code
  too, where it was started with `--setup-code`), and it is stopped with `qkvm stop` from
  any terminal.

## Updates

*Settings → Updates* shows the running version, checks GitHub for a newer release, shows its
notes and installs it. By default QKVM asks GitHub once a day and shows an **Update**
button in the top bar when there is something new; installing is always your click, and asks
for your password again.

- **What a check sends:** one request to GitHub's public API for the newest release. Nothing
  about your KVMs. Turn the daily check off in the same place if you'd rather not.
- **How an install works:** the release is downloaded, its signature and checksum are
  checked, and it is unpacked into `updates/<version>/` in the data folder, next to the running version.
  QKVM then restarts itself on it.
- **Only signed releases are installed.** The public half of the publisher's release key is
  built into the program, and a release that does not carry a valid signature is refused. A
  copy built without a release key tells you about new versions and leaves installing them
  to you, unless it is started with `--allow-unsigned-updates`, which accepts a release
  checked by its checksum alone.
- **If the new version won't start,** QKVM goes back to the previous one by itself.
  `qkvm --roll-back` does the same by hand.
- **It only replaces the program's own files.** If a release needs a Python package you don't
  have, the app says so and you update with pip instead: `pip install --upgrade qkvm`. That
  works at any other time as well; QKVM runs whichever of the two is newer.
- **A container is updated by replacing its image**, not from inside: the app tells you when
  there is a new one.

### Publishing releases

Releases come from the GitHub repository named in `DEFAULT_REPO` at the top of
`qkvm/update.py`, which is `qkvm/qkvm`. Until that repository has a release, the
app says there is nothing newer.

1. A fork that publishes its own releases sets `DEFAULT_REPO = "owner/name"`. Use only a
   repository you control: whoever can publish a release there can run code on every copy
   that installs it.
2. Make a signing key with `python -m qkvm.release keygen release-signing.key`, put the
   printed public key in `RELEASE_KEYS`, and keep the key file out of the repository (the
   `.gitignore` leaves `*.key` out). Copies built with it install a release only if it is
   signed with that key; a copy built without one does not install updates by itself. Either
   sign on your own machine (`python -m qkvm.release sign release-signing.key SHA256SUMS`)
   or let the workflow sign: store the key's contents as the secret `RELEASE_SIGNING_KEY` of
   an environment called `release` (Settings, Environments), limited to tags. Not as a secret
   of the repository, which any workflow on any pushed branch can read. The workflow uses the
   key in a job of its own that installs nothing from PyPI, and refuses to publish a version
   that has a key built in unsigned, or signed with another key.
   To change the key later, take two releases for it: one that has both public keys in
   `RELEASE_KEYS` and is signed with the old key, and from the next one on the new key. A
   copy installs only what a key it already has signed, so a release that swaps the key in
   one step passes the workflow and is refused by every copy that is to install it.
3. To release: set `__version__` in `qkvm/_version.py`, commit, and create a GitHub release
   tagged `v<version>`. `.github/workflows/release.yml` builds the wheel and attaches it with
   `SHA256SUMS` (and `SHA256SUMS.sig`), uploads the same wheel to PyPI and pushes the
   container image. What those two need set up once is written at the top of that file.

## Command line

```
qkvm                             # run it here, in this window, until it is stopped (Ctrl+C); `qkvm start` is the same
qkvm status                      # is a copy running with this data folder, since when, and where does it listen
qkvm stop                        # end the copy that runs, from any window
qkvm restart                     # have it started again, where it runs
```

`status`, `stop` and `restart` are about the copy that already runs, whatever it was started
from: a window that has since been lost, or none at all (a task at log-on). They find it
also where it was started with `--data-dir`: QKVM notes such a folder in `.qkvm` in your home
folder (`elsewhere.json`) when it starts. With two walls running, or one that runs as another
user, say which: `qkvm stop --data-dir D:\qkvm-data`.

These three only look: they run nothing that lies in the folder they are asked about (not an
installed update either), make and change nothing in it, and take nothing a file in it says
at its word. `stop` and `restart` leave one small file there, which the running copy picks
up. That is also the whole of who may stop QKVM: **whoever can write to its data folder**,
and whoever can write there can put there what QKVM runs after an update as well. Keep the
folder writable by the account QKVM runs as and by nobody else; on Linux and macOS QKVM
says so at start when it is not, and on Windows it is for you to look (a folder under your
own profile is yours alone; one made elsewhere, on another drive say, often is not).

Stopping it this way is the same as Ctrl+C: connections are closed, the log says so.
`qkvm status` ends with status 0 when QKVM runs and 3 when it does not, for a script. Where
a service manager or Docker starts QKVM, stop and restart it there: they would only start it
again.

And what it can be started with:

```
qkvm --data-dir D:\qkvm-data     # where settings live (default: .qkvm in your home folder)
qkvm --bind local,tailscale      # override where it listens: local, tailscale, lan, all or an IP
qkvm --port 9000
qkvm --setup-code                # first-run setup from another machine asks for a code printed here
qkvm --https                         # HTTPS from the first request, with a certificate made here
qkvm --tls-cert qkvm.pem --tls-key qkvm.key   # ...or with a certificate of your own
qkvm --allow-from 192.168.1.0/24    # answer these addresses only (and this computer)
qkvm --trusted-proxy 172.18.0.0/16   # a reverse proxy in front of QKVM (see How it is protected)
qkvm --unlock-file /etc/qkvm/unlock.key   # keep the key that carries it on after a restart here, not in the data folder
qkvm --locked-start                  # keep no such key: after a restart nothing is watched until somebody signs in
qkvm --sso-header Remote-User        # sign in whoever the named proxy has signed in (see Accounts)
qkvm --audit-syslog collector.example   # send the activity log on to a syslog collector as it is written
qkvm --log-level debug           # debug, info (default), warning or error
qkvm --update-repo owner/name    # get updates from another GitHub repository
qkvm --allow-unsigned-updates    # only for a copy built without a release key (see Updates)
qkvm --roll-back                 # go back to the version before the last in-app update
qkvm --reset-password            # forget every account (and the saved KVM passwords)
qkvm --disable-2fa NAME          # switch two-factor sign-in off for one account
qkvm --version
```

`--bind` and `--port` take priority over what is saved in the app. `python -P -m qkvm` is the
same command, for where `qkvm` is not on the path. (`-P` keeps Python from looking for the
program in the folder the command is typed in before it looks where it was installed: without
it, a folder called `qkvm` lying there, or a file there with the name of one of Python's own,
would be run in its place.)

`qkvm` starts the program as a child process and watches it, which is what lets it restart
after an update. Closing or killing the starter stops it as well. Only one copy runs with a
data folder: a second one says which process holds it and since when, and how to stop it.

## Limits

What has been tried, and how:

| Device | State |
|---|---|
| GL.iNet Comet (GL-RM1, GL-RM10), GLKVM firmware | Used daily on real devices: picture, status, actions |
| GL.iNet Comet X (four ports) | Real device: picture, status, port switching |
| JetKVM | Real device: picture, status, restart; keys accepted; typed text and ATX only against a stand-in |
| Other KVMs with the PiKVM `kvmd` interface, stock PiKVM included | Expected to work; not tried on one |
| Servers through Redfish, AMI MegaRAC controllers | Real boards of two makers: see below |
| Servers through Redfish, other controllers (iDRAC, iLO, OpenBMC, Supermicro) | Expected to work where they follow the standard; not tried |
| Sipeed NanoKVM, IPMI without Redfish | Not supported |

- JetKVM support was built from the device's published source and tried on real hardware
  (firmware 0.5.9). The picture, the status, sharing the picture with the device's own page
  and restarting the JetKVM work there. Key presses, keep-awake and Wake-on-LAN are accepted
  by the device. Typed text and the ATX power extension have so far only been tried against
  a stand-in. The real device was one without a password, on plain HTTP: its HTTPS mode, a
  password, and following a change of either were tried against a stand-in only.
- Servers were built from what the controllers of an ASRock Rack and a Gigabyte board (both
  AMI MegaRAC) report about themselves, and tried on real boards of both makers. Signing in
  and out, the status with its temperatures and fans, and reading which power actions the
  controller offers work on both; a look at the server takes half a second to a second. On
  one of them the rest was tried as well: the locator light (a light told to blink went out
  by itself within twenty seconds, so a steady one is asked for, and stays), a restart of
  the controller (the server untouched), a request to shut down and switching on. A reset
  was accepted; whether the server restarted could not be seen from here. A power cut
  pressed seconds after that reset was accepted and not carried out, which is why QKVM now
  looks whether one was; why the controller dropped it is not yet known. The console opened
  signed in has so far only been tried on a stand-in. Other makes of controller (iDRAC,
  iLO, OpenBMC) have not been tried, and show how the server is without a picture of its
  screen: Redfish has none, and each maker's remote console speaks a protocol of its own.
- KVMs with two-factor login enabled are not supported.
- QKVM itself has been run on Windows 11 and on Linux (Debian 13 and Ubuntu 24.04, as a
  service and in a container; amd64, and arm64 in a container), with Python 3.11 to 3.14.
  It has not been tried on macOS: nothing in it is known to stand in the way, and nobody
  has seen it run there.
- The page is run by its tests in Chromium, which is what Chrome and Edge are. Most of those
  tests were run once in Firefox as well, and passed. Safari, and the browsers of phones and
  tablets, have not been tried.
- QKVM is view-only apart from the actions above. Typing and mouse control happen in the
  KVM's own console.
- The GL.iNet Fingerbot is not supported.
- Carrying on after a restart with an unlock file was tried with the program itself, in the
  container both ways described above, and as a systemd service that is given the file by
  its path. Handing the file over as a systemd credential (`LoadCredential`) is how systemd
  means it to be done and is what is recommended above, but it has not been tried yet.
- Where every browser reaches QKVM from one and the same address and no proxy says who is
  who (ports published by Docker Desktop arrive that way), the lock after wrong passwords
  applies to all of them at once.

## Development

From a clone of the source, after `pip install -e . pytest`. A copy started from
the clone keeps its settings where an installed one does; give it a folder of its own with
`--data-dir` if both are on the same computer.

```
python -m pytest                 # runs against a fake KVM, no hardware needed
ruff check . && mypy             # the other two checks every push gets (pip install ruff mypy)
python -m tests.demo             # wall with fake KVMs in every state: http://127.0.0.1:8788/
python -m tests.demo --fresh     # the same fakes, starting from the first-run setup
```

The demo's sign-in password is `DEMO_PASSWORD` in `tests/demo.py`.

Two files of tests run the page itself in a real browser, pressing what a person presses:
`tests/test_in_a_browser.py`, and `tests/test_in_a_browser_with_the_program_itself.py` for what
ends in a restart (an update, a move to HTTPS). They need Playwright and a browser for it, which
are for those tests only: nothing QKVM is installed with. Without them the files are skipped.

```
pip install playwright && python -m playwright install chromium
python -m pytest tests/test_in_a_browser.py tests/test_in_a_browser_with_the_program_itself.py
```

## About

Website: https://qkvm.com · Source: https://github.com/qkvm/qkvm

© 2026 QKVM. Free software under the
[GNU Affero General Public License, version 3](https://github.com/qkvm/qkvm/blob/main/LICENSE):
you may use, study, change and share it, and if you run a changed version for others, or pass
it on, you must offer them your source under the same licence. It comes with no warranty.
The name QKVM and its logo are not covered by that licence. QKVM is written and maintained
by its publisher alone: reports are welcome, pull requests are not taken
([CONTRIBUTING.md](https://github.com/qkvm/qkvm/blob/main/CONTRIBUTING.md) says why, and what helps).
