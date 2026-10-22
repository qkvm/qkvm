<!-- header: GitHub and PyPI show what is between this line and the closing one; the documentation site has a header of its own and leaves it out (tools/build_sites.py). -->
<div align="center">

<a href="https://qkvm.com"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/qkvm/main/.github/brand/qkvm-dark.svg"><img src="https://raw.githubusercontent.com/qkvm/qkvm/main/.github/brand/qkvm-light.svg" alt="qKVM" height="64"></picture></a>

**The live screen of every IP KVM and server you run, on one page.**<br>
Self-hosted, open source, no cloud and no device limit.

<a href="https://pypi.org/project/qkvm/"><img src="https://img.shields.io/pypi/v/qkvm?label=PyPI&color=0b6bff" alt="The version on PyPI"></a>
<a href="https://pypi.org/project/qkvm/"><img src="https://img.shields.io/pypi/pyversions/qkvm?label=Python&color=0b6bff" alt="Python versions"></a>
<a href="https://hub.docker.com/r/qkvm/qkvm"><img src="https://img.shields.io/docker/v/qkvm/qkvm?sort=semver&label=Docker&color=0b6bff" alt="The version on Docker Hub"></a>
<a href="https://github.com/qkvm/qkvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0-0b6bff" alt="Licence: AGPL-3.0"></a>

[Website](https://qkvm.com) · [Live demo](https://demo.qkvm.com) · [Documentation](https://docs.qkvm.com) · [Releases](https://github.com/qkvm/qkvm/releases)

<a href="https://demo.qkvm.com"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/hero-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/hero-light.png" width="100%" alt="The wall: fifteen machines with their live screens, their names and their state, and one of them in a window of its own."></picture></a>

<sub>Shown: the live demo. Its machines are made up.</sub>

<a href="https://demo.qkvm.com"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-demo-light.png" height="46" alt="Open the live demo"></a>
&nbsp;
<a href="#run-it"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-install-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-install-light.png" height="46" alt="Install qKVM"></picture></a>

</div>

<table>
  <tr>
    <td width="50%" valign="top">
      <picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-machine-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-machine-light.png" width="100%" alt="One machine as large as the window, with its actions and a way into its own console."></picture>
      <br><b>One Machine</b><br>
      As large as the window, with its actions and its own console a click away.
    </td>
    <td width="50%" valign="top">
      <picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-many-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-many-light.png" width="100%" alt="Five machines ticked on the wall, and a bar that runs one action on all of them."></picture>
      <br><b>Act on Many</b><br>
      Tick several, choose one action, confirm once.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-server-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-server-light.png" width="100%" alt="A server's own tile: switched on, a warning, its temperatures and its fans."></picture>
      <br><b>Servers</b><br>
      On the same wall, by their own controller: power, health, temperatures, fans.
    </td>
    <td width="50%" valign="top">
      <picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-accounts-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/shot-accounts-light.png" width="100%" alt="Settings: sessions, the recovery key, two-factor sign-in and the password."></picture>
      <br><b>Accounts</b><br>
      Three roles, two-factor sign-in and a recovery key.
    </td>
  </tr>
</table>

**Works with** GL.iNet Comet and Comet X · PiKVM-style KVMs · JetKVM · servers with a management controller (BMC) over Redfish, tested on real Gigabyte and ASRock Rack boards

<!-- /header -->

qKVM is a self-hosted screen wall and command center for IP KVMs. It works with GL.iNet Comet
devices (GL-RM10 / GL-RM1 and the four-port Comet X GL-RM4PE, GLKVM firmware), which share
the PiKVM `kvmd` API, and with JetKVM.
One page shows a live picture and the status of every KVM, and lets you act on one machine
or on many at once. Servers with a management controller of their own (a BMC) go on the same
wall, with their power state and health in place of a picture, and so do business PCs with
Intel AMT (experimental). Nothing goes through anyone's cloud: qKVM talks to each device
directly, over your LAN or Tailscale.

qKVM is an independent project. It is not affiliated with GL.iNet, PiKVM or JetKVM.

## Run it

Native video processing requires Linux x86-64/ARM64 or Windows with the video
sandbox available. macOS and other unverified platforms currently refuse these
video paths, including JetKVM's combined video/control connection; they do not
fall back to an unsandboxed decoder. See [Native video isolation](SECURITY.md#native-video-isolation)
for platform requirements and limitations.

**As a program** (Python 3.11 or newer):

```
pip install qkvm
qkvm
```

Then open http://127.0.0.1:8787/. Settings are kept in the
folder `.qkvm` in your home folder (on Windows `%USERPROFILE%\.qkvm`), whatever folder you
start it from; `--data-dir` puts them elsewhere. This is "the data folder" below, and qKVM
says where it is every time it starts.

Where the system's Python refuses `pip install` outside an environment of its own (Debian,
Ubuntu and others do), `pipx install qkvm` does the same and makes that environment for you.

**As a container:**

```
docker run -d --name qkvm --restart unless-stopped --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -p 8787:8787 -v qkvm-data:/data qkvm/qkvm --https --setup-code
```

Then open `https://<this machine>:8787/` and choose a password using the setup code
shown by `docker logs qkvm`. Verify the generated certificate on the host before trusting
it in the browser, or install a certificate trusted by your clients. These instructions
and the supplied Compose file enable HTTPS and protect remote first-account creation
with a setup code from the first request. Existing accounts are preserved.

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

For a reverse proxy that terminates HTTPS, publish the backend only on loopback
(`-p 127.0.0.1:8787:8787`) or an isolated private container network. Only then omit
`--https` from the backend command; retain `--setup-code`. Do not expose the HTTP
backend to untrusted clients. See [How it is protected](#how-it-is-protected) for proxy
trust and certificate configuration.

**From the source:**

```
git clone https://github.com/qkvm/qkvm
cd qkvm
pip install .          # or, for the image:  docker build -t qkvm/qkvm .
```

The first visit walks you through four steps:

1. **Password**: choose the password of the first account, `admin`.
2. **Recovery key**: shown once. Keep it: it is the way back in if a password is forgotten.
3. **Network**: where it is reachable: this computer only, Tailscale, the local network.
   (In a container this is decided by the port mapping, `-p`, instead.)
4. **KVMs**: let qKVM find the KVMs on your network, or paste their addresses, and give
   their login; each one is checked and added.

## Using it

- **Tiles** refresh about once a second. Click one to enlarge it (the left and right arrow keys switch, `Esc` closes).
  Pictures are drawn pixel for pixel: each frame is fetched with detail to spare (for a
  normal tile, the KVM's full frame) and scaled once to exactly the screen pixels it covers,
  which keeps text sharp at any display scaling.
- **Find and filter:** the counts in the top bar (All / Online / No signal / Attention) are
  buttons, and the search box (`/`) narrows the wall by name, address or group.
- **Groups:** give a KVM a group when adding or editing it (a rack, a room, a customer). Once
  there are groups, the top bar gets a list to show one of them at a time.
- **Your own order:** an admin puts the tiles where they belong with *View > Arrange the
  tiles...*: every tile shows its place, 1, 2, 3 and so on, and is dragged to another, stepped
  one place with the arrows, or given a place by typing its number. *Save this order* keeps
  it on the server, so it is the same for every browser and every screen that shows this
  wall; `Esc` or *Cancel* leaves it as it was. A machine added later stands at the end until
  it is given a place.
- **View** (in the top bar) holds how the wall is shown: the order (as arranged, by name, by
  group, or with what needs attention first), the number of columns, how often a new picture
  is fetched, and display mode. These are each browser's own choice: a wall screen can show
  problems first while a desk keeps the arranged order.
- **Display mode** (*View > Display mode*, or `D`): the screens and nothing else, as large as
  fits, for a monitor on the wall. Move the mouse for a small bar that can rotate through
  the groups every 20 seconds; `Esc` leaves. The address gets `#display`, so a browser on a
  wall screen can be pointed straight at it. For a screen that is to stay on, make it a
  link of its own under *Settings > Tokens* (see [Scripts and wall screens](#scripts-and-wall-screens)):
  a viewer account signed in there with *Keep this browser signed in* is asked for its
  password again after 30 days, and a link is asked for nothing.
- **Find KVMs on my network** (in *Add KVM*): asks the 254 addresses around this computer's
  own (its `/24`, on the network its internet traffic leaves by), and every Tailscale peer
  that is online, whether it is a KVM, a server's controller, a PC with Intel AMT, or a VNC
  server (on ports 5900 and 5901, by its greeting alone). It only looks, it does not log in.
  Devices on another network or subnet (a management network, say) are not found:
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
  - *Keyboard*: Wake screen, Ctrl+Alt+Del, Lock screen, Task Manager, Show desktop, Enter,
    Esc, Close window; *Send keys...* for any other combination; *Type text...* to type a command.
  - *Your actions*: key combinations and text you saved under Settings > Actions.
  - *Power*: Keep awake / Allow sleep (the KVM nudges the mouse); press power, hold power and
    press reset when the KVM has an ATX power board; Wake-on-LAN for the targets saved on it.
    On a KVM with the kvmd interface (a Comet, a PiKVM) a press is done when the board has let go
    of the button (half a second; six and a half for holding it). Where the board says whether the
    computer is on, a press that must change that (a short one on a computer that is off, holding
    it on one that is on) is done when the board shows the change, which takes it some seconds;
    where the change does not come within twenty, the answer says so ("pressed, but the computer
    is still off"; or that the board has said nothing since), and nothing offers to press again. A short press on a running computer asks its system to shut down, which takes the time
    it takes: the tile shows when it is off, as it does after a reset that the power stays on
    through. The tile says *Power on* or *Power off* by the board; with no picture and the board
    saying off, that the computer is off or asleep (a computer asleep may put its power light
    out, and the board then says off: a real one did). While somebody watches such a KVM's picture,
    the wall holds the KVM's line for events anyway (it keeps the picture coming), and hears the
    board there, as the KVM's own page does, instead of asking it: a Comet's board answers one
    question at a time and tells whoever asks meanwhile that there is none, which took the buttons
    from a second wall or a script beside it. Where nobody watches the picture (the alerts look
    every fifteen seconds), and where that line has said nothing, has gone quiet or says there is
    no board (a Comet's line says so too while the board answers somebody else's questions), the
    board is asked as before, and so it is once before every press. No line is opened for the
    board alone: the sleeping PC behind a real Comet woke three times soon after one was.
  - *Fingerbot*: a GL.iNet Fingerbot paired with a Comet presses the computer's power button with
    a small arm, for a machine that has no ATX board. Where the KVM says one is paired (it says so
    on its line for events, which the wall holds while somebody watches its picture; where it has
    not said either way since qKVM started, or not for two minutes, it is asked on a line of its own
    before a press; where it said there is none, or nothing when it was asked, less than two minutes
    ago, a press is refused without asking again), *Press with Fingerbot* (half a
    second: a computer that is off comes on, a running system is asked to shut down) and *Hold
    with Fingerbot* (eight seconds, which cuts the power) are under *Power*, beside a power board's
    buttons where the KVM has both, and in a run over several machines. Each is asked first, as
    every power button is. How hard it presses is the machine's own: *Fingerbot* in its Edit box,
    *Press firmly* (the Comet's own default) or *Press lightly*; it goes into a file with the rest.
    A press is done once the Comet has said the Fingerbot took it (some two seconds after it was
    sent) and the press's own time is over after that: a real Comet answered as early for an
    eight-second press as for a short one. A second press meanwhile is refused. The Comet's "Press
    Failed" (a refusal of its own) is said as a failure; anything else that is not its yes (its own
    error, a proxy's, an answer broken off, none within eight seconds beside the press's own time)
    as "may have been done", and then the Fingerbot is left alone for as long as that press can last
    from when its answer came, or was given up on (some ten seconds for a short one, seventeen for
    the long one): a press meanwhile is refused (409 `busy`), whoever sends it, a power board's
    button on the same machine too, and its battery is not asked. The tile's footer says *Fingerbot*, or that its battery is low (below
    a quarter; asked once an hour, never during a press), and the actions' head says when that battery is low. A
    Fingerbot says nothing of the computer's power: the tile shows what follows on the screen. On a
    KVM with several inputs it presses the machine it sits on, whichever is on screen.
  - *Reboot KVM*: restarts the KVM itself.
- **Bulk actions:** press **Select** (or `S`) to enter select mode, tick the KVMs you want
  (*Select all* takes the ones currently shown, so filter or search first), then
  **Run action...**. You confirm against the list of machines; what can lose somebody's work
  (the power and reset buttons, a reboot, typed text, a saved action marked so) needs an
  extra tick; and each KVM reports back as it finishes, with a retry for the ones that
  failed. A run goes to a few machines at a time, or, if you say so when confirming, to one
  after the other in the order shown, with up to two minutes between them: machines switched
  on together draw their starting current together. Wake-on-LAN and switching ports are for
  one machine at a time.
- **Removing several at once:** in select mode an admin has **Remove** beside *Run action...*.
  The question names every machine that is ticked, with its address, and says what goes with
  them: their saved passwords and their history, for good. To keep a copy, export the wall
  first (*Settings > Export and import*). More than one needs the extra tick. They go together
  or not at all: if one of them was removed by somebody else meanwhile, or the disk refuses the
  change, nothing is removed, and nothing being done to them is cut off. Something being done to
  one of them at that moment does not keep it there: an action on its way may have been done (its
  sender is told so), and a live line is closed, with the keys it held let go of first, as when
  one tile is removed. One tile removed by itself goes the same way: the settings are written
  without it first, so a disk that refuses the change leaves it on the wall with nothing cut off.
- **One thing at a time per machine.** While an action is on its way to a machine, a second
  one for the same machine is refused, whoever sends it and from wherever: a power button
  pressed twice does not press harder, it undoes the first press. A power button is on its way
  for as long as the board holds it, and a press is not sent while the KVM's board says it is
  pressing one already (from the KVM's own page, say). A Comet's board says so for the first half
  second of a press only, stock kvmd's for the whole of it: a press from the Comet's own page
  and one from the wall a second later both reach the board. The board is asked before every
  press, also where its line for events is heard: a real Comet read its board for that line about
  every second and a quarter, and in two presses its line never said busy. Only the board's no is
  "not pressed": an answer that says neither (the KVM's web server answers 502, 503 or 504 while
  kvmd restarts behind it, kvmd itself 500), none within eight seconds, or one that broke off, is
  "it may have been done", and the board is then left alone for eight seconds and the button's
  hold, whoever asks (a Fingerbot on the same machine too). A Fingerbot's press is
  on its way until the press's own time is over after the Comet's answer, and one press of the
  Fingerbot's and one of the board's on the same machine are two things, one after the other (also
  while a Fingerbot's press that got no clear answer may still be under way).
- **Settings**
  - *KVMs*: add, edit, remove; review a KVM's certificate.
  - *Actions*: your own actions. Saved text is stored encrypted and never shown again. It
    can be typed by every operator, on any machine that operator may use, and what is typed
    can be read there: a saved text is known to all of them. A password that not every
    operator should have is not something to save here.
  - *Network*: where qKVM listens, the port, HTTPS. Changes apply without restarting the program.
  - *Accounts*: who may sign in, as what, and which KVMs they see (see [Accounts](#accounts)).
  - *Alerts*: be told when a KVM goes offline or loses its picture (see [Alerts](#alerts)).
  - *Security*: change your password, two-factor sign-in, the recovery key, sign out your
    other browsers.
  - *Updates*: the running version, checking for a newer one and installing it.
  - *Activity*: who signed in, who changed what, who sent which action (never what was typed),
    who looked at which machine; to search, to narrow down to a kind, a machine, an account and
    a time, and to download (see [Activity log](#activity-log)).
  - *About*: version, website, source and licence.
- **Fullscreen** (`F`) and the **colours** (light, dark, or as the system has them) are each
  a button of their own in the top bar, next to Settings.
- **Your account** (the person at the right end of the top bar) says who is signed in and
  as what, and holds your password and second step, and **Sign out**.

Text is typed with a US keyboard layout. On a computer set to another layout, letters and
digits arrive as written but some symbols do not. (A VNC server is sent the characters
themselves, and its own layout decides: see [VNC servers](#vnc-servers). A JetKVM says which
layout its computer uses, and text is typed in that one: see [JetKVM](#jetkvm).) The keys of the
live view are places on the keyboard, whatever the layout.

## Live view and control

Beside the tiles, which ask for a picture about once a second, qKVM offers one machine live:
one connection per viewer that carries the machine's picture down as it comes and a keyboard
and a mouse up, key by key. A program that speaks it (the page's enlarged view; the qKVM
desktop program) opens it in two steps: it asks `POST /api/v1/devices/{id}/live`
for a pass, a call like every other, signed in and with the `X-QKVM: 1` header, and gets
`{"v": 2, "ticket": "..."}`, a pass good for half a minute and for one line; then it opens a
WebSocket at the same address, which carries no cookie, and shows the pass in its first message.
`GET /api/v1/wall` says `"live": 2` of a qKVM that has this; a program that speaks another form
of it asks for none. A line whose first message is not a pass this qKVM gave for that machine
is closed with a word (`no_pass`), and so is one whose pass was used before or has run out.

**In the page.** Enlarging a tile opens the machine's line, where it has one: the stills give
way once the first live picture is drawn, and come back when the line ends. **Control** (or
the key `C`) takes its keyboard and mouse; the right Ctrl by itself gives them back. Where
somebody else has them, the button says who (*Controlled by olga*); to an admin it offers
**Take over from olga**, which asks first, naming them. Whoever loses them is told why at the
edge of the page: *admin took over this machine's keyboard and mouse*, or *Given back after 15
minutes without input*.

**Who may.** Whoever may see the machine may watch it: a viewer, a wall screen opened with its
display link, a token for scripts. Taking its keyboard and mouse takes an operator or an admin,
in person or by a token with that role. One connection holds a machine's keyboard and mouse at
a time: a second one that asks is refused (`taken`, with `by`, the name of whoever has them), and
so is an action from the page while somebody holds them (`409 busy`, which says who as well), and
the other way round.

**Taking over.** An admin, in person, may take a machine's keyboard and mouse from whoever holds
them: another admin, an operator, a script's token. Never an operator, never a token (no token is
an admin), never a wall screen (which only looks). Whoever held them loses them as a line loses
them for any reason: everything they had down is let go of, nothing more of theirs goes out (a
word already on its way lands, and is let go of again, before the admin's first word), and they
are told who took them (`control`, `on: false`, `taken`, with `by`). Their line goes on showing
the machine. An admin's action from the wall (a power button, keys, text) does
not take over by itself: it is refused with the holder's name, and the answer says that an admin
can take them over in the live view, where it is done on purpose, after a question.

**Given back by themselves.** Keyboard and mouse are given back after **15 minutes without input**
from whoever holds them (no key, no button, no turn of the wheel, no move of the pointer): what
they had down is let go of, they are told why (`idle`), and the line goes on showing the machine.
Control takes them again.

**One hand at a time.** Whoever gets keyboard and mouse next (after a take-over, a giving back,
or a line that lost them) sends nothing to the machine until whatever the one before had down
has been let go of, and whatever of theirs was still on its way (a PC with Intel AMT waits up to
ten seconds for its next session) has landed and been let go of again, for 16 seconds at the
most: a key of the new holder's never lands beside a Ctrl the one before still had down. An
action from the page, and switching a PC's Intel AMT KVM, wait for the same; one whose tile is
changed or taken off the wall meanwhile sends nothing, and says so (409 `conflict`). A tile
changed or taken off the wall waits for that letting go before its connection is closed.

A line ends when the sign-in it was
opened from ends (signing out, being signed out everywhere, an account removed, suspended or
limited to other machines, a token taken back) and when the machine is edited, taken off the
wall or the wall locks itself; what the line had down on the machine is let go of then, as it
is when a line is cut or given back. A key or a mouse button still on its way at that moment
(a PC with Intel AMT waits up to ten seconds for its next session) is let go of again as soon
as it lands, and nothing more of that line's goes to the machine. qKVM asks a line every five
seconds whether it is there (a WebSocket ping, which a browser and every library answer by
themselves); one that has answered none of three is gone, and so is one that takes nothing off
the line for ten seconds, or is not reading what it is told, or sends pings by the dozen a second,
more than two thousand other frames a second, or a message in more than sixteen pieces: what it
had down is let go of either way. One account (a token, a wall screen) has 32 lines open at the
most, the passes it was given and has not used counted with them. A pass is
redeemed from the address it was given to. While a line holds a machine's keyboard and mouse,
an action from the page for that machine is refused (`409 busy`), for whoever holds them too:
text is typed over the line, or after the keyboard is given back.

**What is logged.** The activity log says who opened a machine's live view, and when it ended
and after how long (`live_opened`, `live_closed` with `seconds` and `why`: `closed` where its viewer
ended it, else the reason, such as `gone`); who took a machine's keyboard and mouse, and when
they were given back or taken away, and why: a take-over as two lines, the holder's (`why`
"taken", `by` the admin) and the admin's (`from` the holder); a giving back for want of input
with `why` "idle" and `minutes`. Never a key, never where the pointer was. An account's (a
token's, a wall screen's) live views write 120 entries an hour into the log at the most: the
next one after that says how many were left out (`unsaid`), so that a script opening lines in a
loop cannot push out of the log what was done before (see [Activity log](#activity-log)).

**What each kind of machine gives:**

| Machine | Picture | Keyboard and mouse |
|---|---|---|
| A KVM with the `kvmd` interface that has its H.264 line (`/api/media/ws`: stock PiKVM, and a GL.iNet Comet on a recent GLKVM firmware, tried on a real one) | its H.264 stream, passed on as it comes, one connection to the KVM shared by every viewer that can show it; every key frame carries the stream's parameter sets (a KVM that sent them once only has them put back before each key frame); a stream whose parameter sets say a picture larger than qKVM shows any (40 million pixels, 16384 a side) or cannot be read is not passed on, and its viewers get the pictures one by one instead | yes, on its line for events |
| A KVM with the `kvmd` interface without that line, and a viewer that shows JPEG alone | JPEG pictures asked one after the other, as fast as the fastest viewer asks and never more than the KVM gives (30 a second at most), only those that changed | yes; the pointer by steps where the KVM's mouse is set to relative (see below) |
| JetKVM | JPEG made of the frames qKVM decodes anyway; its H.264 is not passed on (see Limits) | yes |
| A server whose controller is AMI MegaRAC (see [Servers](#servers)) | JPEG of its screen, each time the screen changes | yes, as the console's own USB keyboard and mouse reports; the pointer goes as an absolute place where the server's mouse is absolute (what these boards are by default), the back and forward buttons have no bit there |
| A server whose controller runs OpenBMC (see [Servers](#servers)) | JPEG of its screen, each time the screen changes | not yet: qKVM only looks at an OpenBMC console |
| A PC with Intel AMT whose KVM qKVM may use (see [Intel AMT](#intel-amt)) | JPEG of its screen, each time the screen changes, at the pace the viewer asks for | yes, as the KVM's own key and pointer events; the back and forward buttons have none there |
| A virtual machine on Proxmox VE, while it runs (see [Proxmox and virtual machines](#proxmox-and-virtual-machines)) | JPEG of its screen, each time the screen changes, at the pace the viewer asks for; the tile's console and the line's are one | yes, as RFB's key and pointer events through its console; the back and forward buttons have none there |
| A VNC server | none in this version (`live` is not in its `can`): the tile's pictures | no |

**The pointer.** A KVM with the `kvmd` interface moves its computer's pointer the way its mouse
is set on the KVM (its own settings): to a place (absolute, stock kvmd's default) or by steps
(relative), and drops a move of the other kind; a real Comet set to relative never moved its
pointer to a place the page sent. The line says which (`pointer` in its `state` message), and
the page follows it: where the mouse moves by steps only, the bar says so and a click on the
picture hands the pointer to the machine (the browser's pointer lock; Esc gives it back), as
the KVM's own page does it, and that click is no click on the machine; where it takes places
only, *Relative mouse* is not offered. A JetKVM, a PC with Intel AMT and a virtual machine take
both. With the pointer handed over, the computer moves it by its own settings (Windows speeds a
fast move up), so it goes where the computer puts it, which the picture shows.

The messages of the line, for whoever writes a program that speaks it. Text messages are JSON
with a field `t`. From the program: `hello` (`v: 2`, `ticket`, `video`: the codecs it can show,
of `h264` and `jpeg`, `max_w`, `max_fps`), `shape` (`max_w`, `max_fps`), `key_frame` (a frame was
lost: send a key frame; of JPEG the last picture is sent again, once in half a second at the
most), `control` (`on`; and to take them over from whoever holds them, as an admin in person
may, `take`: true, with `from`: the `by` the refusal named, as a text, which a take-over has to
have, so that they are taken only from whom the person was asked about; without it, or with
another holder by then, it is refused `taken` with the `by` of now; where nobody holds them it
is an ordinary asking; sixty takings and givings back a minute of one account, on all its lines
together, and a line that asks more ends with `bye flooding`),
`k` (`u`: a key by its USB HID usage on page 7, 4 to 0xE7, but 0x66, the keyboard's Power key,
which is dropped unsent: a machine's power is under Power, asked first; `d`:
down), `m` (`x`, `y`: the pointer, 0 to 32767 over the picture), `mr` (`dx`, `dy`), `mb` (`b`: a
button 1 to 5, left, right, middle, back, forward; `d`), `mw` (`dx`, `dy`: turns of the wheel,
up and right positive, 16 at the most in one message), `up` (let go of everything). From the server: `video` (`codec`, `w`,
`h`: what follows; sent before the first picture and whenever it changes, and a key frame
follows it), `state` (as in `/api/v1/status`, when it changes; with `pointer`, how the machine's
pointer is moved, where that is known: `absolute`, to a place with `m`; `relative`, by steps with
`mr`; `both`), `control` (`on`; and when
refused `code` and `message`, with `by`, the name of who has them, where somebody has: one
answer to each asking, in order, within a minute (the way in to a machine can take that long: a
JetKVM connected anew some forty-seven seconds; not made by then, `timeout`), so wait a little
longer than that before giving up on it, and `on: false` with a code by itself when keyboard and mouse
were taken away: `taken` with `by` (an admin took them over), `idle` (15 minutes without
input), `not_allowed`, `dropped`, `in_use`), `bye` (`code`, `message`: why the line is about to close). Pictures are binary messages: 16 bytes of header (byte 0 the kind, 1 for one
H.264 access unit in Annex B form, 2 for one JPEG; byte 1 the flags, bit 0 a key frame; bytes
2 and 3 zero; bytes 4 to 7 a counter that goes up by one for each picture the machine gave,
little-endian; bytes 8 to 15 when qKVM got it, in microseconds of a clock that only goes
forward), then the picture. A viewer that falls behind is not waited for: it is brought
forward to the next key frame, and sees that as a jump in the counter. Keys and the mouse are
taken only from the connection that holds them, and only after the server has said so.

## Accounts

The first account is an admin called `admin`. Admins add more under *Settings > Accounts*,
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
- Everyone can change their own password (*Settings > Security*), which asks for the
  current one. An admin can set a new one for somebody else, which signs that account out
  everywhere; their own they change like everybody, where the current one is asked for.
- The only admin cannot be removed or demoted, and nobody can change their own role or
  suspend themselves. An admin who is suspended does not count as one to fall back on.
- *Sign out everywhere* (in an account's *Edit*) ends every session of that account at once
  and changes nothing else about it: for a laptop left on a train.
- An admin may take a machine's keyboard and mouse over from whoever holds them in its live
  view, after a question that names them; an operator never takes them from anybody (see
  [Live view and control](#live-view-and-control)).
- The page hides what an account may not use, but the rule is enforced on the server:
  every request is checked against the role, and anything not explicitly opened to
  viewers or operators takes an admin.
- The activity log records the account behind every sign-in, change and action.

### Two-factor sign-in

Anyone can add a second step to their own account under *Settings > Security*: signing in
then asks for the password and for a 6-digit code from an authenticator app (Google
Authenticator, Microsoft Authenticator, 1Password, Aegis and so on). Setting it up shows a
QR code to scan (and the same key as text); a code works once.

- **It can be required.** *Settings > Accounts > Two-factor sign-in: required of* admins, of
  admins and operators, or of everybody. An account under the rule that has not set it up
  signs in with its password and lands on one page, which sets it up; until that is done it
  sees no screen and can do nothing else. Whoever makes the rule has to have it switched on
  for their own account first.
- **One-time codes for when the phone is not at hand.** Switching the second step on hands
  out ten codes, shown once: each signs you in a single time in place of a code from the
  app (*No phone at hand?* on the sign-in page). *Settings > Security* says how many are left
  and makes ten new ones, which ends the old. qKVM keeps only what it needs to recognise
  them, under the same key as the saved passwords, and a sign-in with one is marked as such
  in the activity log.
- **Wrong codes hold the account, not only the address.** After five of them, from wherever
  they came, the second step of that account is refused for 30 seconds, doubling up to 15
  minutes. Only somebody who has the password ever finds that out.
- If the phone is lost and the codes with it, an admin can take the second step off that
  account under *Accounts*; under a rule that requires it, the next sign-in sets it up anew.
  If it was the only admin's phone, run `qkvm --disable-2fa NAME` on the computer qKVM runs
  on.

### Signing in through your identity provider

Where people already sign in in one place (Authelia, authentik, Keycloak with oauth2-proxy,
a company's own gateway), qKVM can take that place's word for who somebody is. It is the
reverse proxy in front of qKVM that signs people in, and tells qKVM in a header:

```
qkvm --trusted-proxy 172.18.0.5 --sso-header Remote-User
```

```
map $http_upgrade $connection_upgrade {             # the live view is a WebSocket: passed on as one
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    location / {
        auth_basic "qKVM";                          # or auth_request to your identity provider
        auth_basic_user_file /etc/nginx/users;
        proxy_pass http://qkvm:8787;
        proxy_http_version 1.1;                     # a WebSocket needs HTTP/1.1 and these two headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;                # on another port than 443: $http_host, which keeps the port
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Remote-User $remote_user;  # set by the proxy: whatever the visitor sent under that name is gone
    }
}
```

- Whoever the proxy names is signed in as **the qKVM account of that name**, with the role
  and the machines that account has. There has to be one: *Settings > Accounts > Add
  account*, with the name the proxy sends (`olga`, `olga@example.org`) and no password.
  Somebody the proxy knows and qKVM does not is told so, and sees nothing.
- **The header is believed of the proxy named with `--trusted-proxy`, and of nobody else:**
  not of the visitor, not of another machine on the network, not of a program on the same
  computer. And only where it arrives once: a proxy has to *set* it, as above, not add its
  line to one the visitor sent. Make sure nothing reaches qKVM's port except through the
  proxy (publish it to the proxy's network only, or use `--allow-from` with its address).
- **The second step is the identity provider's.** Somebody it signed in is not asked for
  qKVM's own code, whatever rule is set under Accounts; that rule is for those who sign in
  here with a password. An account without a password cannot be signed in to by typing
  anything, and a copy of the data folder holds nothing of it to guess at.
- Access is taken away in either place: at the identity provider, or here, by suspending or
  removing the account, which ends its session at once.
- It cannot be had with `--locked-start`: whoever signs in elsewhere brings no password
  here, and without a key of its own qKVM could not open the saved device passwords (see
  [Keeping it running](#keeping-it-running)).
- Accounts with a password still sign in with it, which is the way in when the identity
  provider is down. Keep at least the first admin that way.

## Alerts

*Settings > Alerts* makes qKVM watch the KVMs and tell you when one goes offline, when a
computer loses its picture, when a login is rejected or a certificate changes, and when that
is over. A change counts once it has lasted about half a minute.

- Alerts are posted to a webhook address: an [ntfy](https://ntfy.sh) topic, a Slack or
  Discord incoming webhook, or anything that accepts a JSON POST. The address is stored
  encrypted. *Send a test alert* tries it.
- Every change is also written to the activity log, with or without an address.
- **An alert says where to look.** *Link in alerts* is the address of the wall as you reach
  it; an alert then carries a link that opens the wall at the tile it is about (in ntfy, a
  tap on the notification does). Leave it empty for alerts without one.
- **One machine can be left out:** *Settings > KVMs > Edit > Send alerts about this one*. For
  a test bench that is switched on and off all day, or a machine that sleeps.
- **Pause for maintenance:** *Pause alerts*, for an hour or for four, sends nothing while machines
  are worked on, restarts included. When the pause is over, what is not as it was before it is
  told then, so nothing that went wrong meanwhile stays unseen; what went wrong and was put
  right within the pause is not mentioned. The changes are in the activity log all the same.
- While alerts are on, qKVM keeps watching after everyone has signed out, and after a restart
  (see below). What each machine was last seen as is written down, so a machine that does not
  come back when qKVM does (after a power cut, most of all) is told about: two minutes after
  the start, which is the time qKVM gives its own network to come up before it believes
  that anything is gone.
- A JetKVM that is not on screen is only checked for answering, because looking at its
  picture would take its one viewer slot.
- For a [server](#servers), "lost its picture" means it was switched off, and a critical
  fault reported by its controller counts as a problem. So it does for a KVM whose power board
  says the computer is off: the alert says it is off or asleep (its power light is out, which
  rules out a cable that came loose). Without a board, or with one that says the computer is on
  (its screen asleep), it says the picture is gone.
- **After a restart qKVM goes on alerting by itself**, as it goes on watching. Not where it
  is started with `--locked-start`: the address alerts go to is itself saved encrypted, and
  so are the devices' passwords, and until somebody signs in qKVM can then neither look at a
  device nor tell anybody. `GET /healthz` says `"locked": true` for as long as that lasts
  (both under [Keeping it running](#keeping-it-running)).

## Export and import

*Settings > Export and import* writes the wall to a file, and takes a file in: to keep what
was set up, to fill a second qKVM without typing every device again, or to move to another
computer.

**Export** asks for your password again, and for what the file is to hold: the KVMs and
servers, the saved actions, the alert settings, the wall's settings.

- **With a passphrase** it is an encrypted file (`qkvm-<date>.qkvm`). It holds everything,
  the passwords of the devices, the texts of saved actions and the address alerts go to
  included, and opens with that passphrase only (scrypt and AES-256-GCM, as the saved
  passwords themselves are kept). The passphrase needs ten characters or more; keep it
  somewhere else than the file. Nothing of the wall can be read off the file without it,
  not a name and not an address either (its size says roughly how much is in it).
- **Without one** it is a plain file (`qkvm-<date>.json`): the same, with every password
  and the alert address left out, and the saved actions that type a text left out with
  their text. It can be read, compared and kept anywhere.

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
recovery key. Each is locked to the key of the qKVM it was made on, and could be carried
over only by carrying that key. Nor the [history](#history) of what the wall saw: that is what
happened here, not a setting, and an import leaves the one that is here as it is. To keep a whole qKVM, accounts and all, keep a copy of its
data folder (with qKVM stopped, or of `qkvm.json`, `unlock.key` and the files of the activity log,
`audit.log` and `audit.log.1` to `.9`, at least; `audit.sqlite` is made again from those),
as carefully as the passwords in it: see [How it is protected](#how-it-is-protected).

An export is written to the activity log, with who made it and whether it was encrypted
(a wrong password at it as well), and every device a file adds is written there by name and
address, as one that is typed in is.
A token cannot ask for one, and neither can an account that only your identity provider
signs in: it has no password here to be asked for. Export as an admin that has one.

## Scripts and wall screens

*Settings > Tokens* makes two things that use qKVM without a person signing in. Both are
shown once, qKVM keeps only what it needs to know them again, and an admin can take either
back at any moment. Neither can change settings, accounts, devices or other tokens: that
takes a person.

**A link for a wall screen.** Open it once in the browser of that screen. The browser keeps
it, shows the wall as a display, and when qKVM has been restarted it comes back in by
itself: nobody has to stand at the screen with a keyboard after a power cut. It can look at
the machines it was made for, and no more than look. (The pictures are back by themselves
as well: qKVM carries on after a restart, see [Keeping it running](#keeping-it-running).
Only where it was started with `--locked-start` are they back once somebody has signed in
anywhere.)

**A token for a script** has a role (viewer: look; operator: look, and act on machines),
the machines it is for, and a date it works until. The script sends it with every request:

```
curl -H "Authorization: Bearer qkvm_..." https://qkvm.example:8787/api/v1/status
```

What a script may ask for, and what each request answers, is in [The API](#the-api): a
token with the role viewer may look (`GET /api/v1/wall`, `/status`, a picture), one with
the role operator may also act (`GET /api/v1/actions`, `POST /api/v1/devices/{id}/actions`).

- Every answer is JSON. A refusal is `{"code": "...", "message": "..."}` with a status that
  fits: 401 without a valid token, 403 for what its role does not allow, 404 for a machine
  it is not for, 409 `busy` while something else is being done to that machine, 502 when
  the device refused or did not answer.
- After a restart qKVM carries on by itself, and a token works as before. Where it was
  started with `--locked-start`, a token is answered `503 locked` until somebody has signed
  in, because qKVM cannot reach its devices before that: that is not the way to start it
  where scripts run unattended. (The same answer comes for as long as the key it carries on
  with cannot be read, or does not fit yet: `GET /healthz` says `"locked": true` then.)
- A token cannot ask for a way into a server's console, cannot type a saved text (it could
  read it back off the screen), and has nothing to sign out of.
- What a token did is in the activity log under its name.

## The API

Everything the page does, it does through this interface, and so can any other program:
a script, a monitoring system, a program of its own that shows a wall. The paths are under
`/api/v1/`, and the `v1` is the version of the interface. **Within `v1`, requests and fields
are added and none is taken away or given another meaning**; a change that would break a
program written against it gets a path of its own (`/api/v2/`) beside this one. `GET
/healthz` says which versions a qKVM speaks (`"api"`). What this chapter lists is promised
that way; the other requests under `/api/v1/` are the page's own and change with it (they
are named at the end). A client takes what it knows from an answer and leaves the rest: a
field or a word it has not met is one that was added since.

### Who may

Three roles, each including the ones below it: admin, operator, viewer. Three ways in:

- **A person**, with an account: `POST /api/v1/login`, which answers with the cookie
  `qkvm_session` (HttpOnly, SameSite=Strict, Secure over HTTPS), to be sent with every
  request. Every request that changes something (anything but GET) then has to carry the
  header `X-QKVM: 1`, and no `Origin` of another host; without it: 403 `forbidden`.
- **A script**, with a token an admin made (see above): `Authorization: Bearer qkvm_...`
  with every request, no cookie and no `X-QKVM` header. It is a viewer or an operator, never
  an admin, and has no account of its own to change or to sign out of.
- **A wall screen**, with its link: `POST /api/v1/display` with the key behind `#key=`,
  which answers with the cookie of a viewer that is not a person (`"token": true`).

Bodies are JSON with a `Content-Length` (sent chunked: 411 `length_required`), at most 64
KiB (413 `too_large`), except the two that carry a file. A field that is wrong is answered
422 `invalid`, and the message names the field and the rule, never the value. A field the
request does not need is left out.

### Errors

Every refusal is `{"code": "...", "message": "..."}` with a status that fits. `code` is one
word, for a program; `message` is a sentence fit to show to a person. Every code the wall
answers with is listed in `words.json` (see [Clients and versions](#clients-and-versions))
with the statuses it comes with; the ones the requests below answer:

| Status | Codes | Whose fault |
|---|---|---|
| 400, 408 | `disconnected` (the body was not sent in full), `timeout` (it took too long to arrive) | the request |
| 401 | `unauthorized` (sign in first; in the middle of things: the session ended, sign in again and do not loop), `bad_password`, `bad_code`, `code_required`, `bad_key`, `bad_recovery` | the session |
| 403 | `forbidden` (the header), `not_allowed` (the role, or a token), `totp_required` (set the second step up first), `suspended`, `stopped` (whoever asked lost the right while it was under way) | |
| 404 | `not_found` (also: a machine this account was not given), `no_picture`, `no_console`, `no_live` (no live picture of this machine) | |
| 409 | `busy` (something else is being done to that machine), `changed`, `no_text`, `in_use`, `console_held`, `enabled`, `not_enabled`, `not_started`, `not_initialized`, `no_second_step`, `no_password` (the account has no password here: it is signed in by the identity proxy) | the state of things |
| 411, 413 | `length_required` (a body sent without its length), `too_large` (a body over 64 KiB, or a file over what a file may be) | the request |
| 422 | `invalid`, `name_required`; for a file: `not_a_file`, `damaged`, `newer`, `passphrase_needed`, `wrong_passphrase`, `too_large` | the request |
| 429 | `rate_limited`, with `Retry-After` in seconds, which is meant; `busy` (too many passwords being checked at once: try again shortly) | |
| 500, 501 | `internal` (the details are in the wall's log); `missing_driver` (a JetKVM, where the Python that runs qKVM lacks the aiortc package qKVM is installed with) | the wall's |
| 502 | the device's: `unreachable`, `dropped`, `auth_failed`, `no_password`, `not_set_up`, `cert_mismatch`, `cert_invalid`, `plain_only`, `another_machine` (another machine answers at the address than the one the tile was added for, a PC with Intel AMT by its PlatformGUID, a server by its UUID and its controller's, or has its guest's number on its Proxmox, by the guest's SMBIOS UUID: nothing was sent; 422 from an edit), `bad_response`, `action_failed`, `console_time_up` | the device |
| 503 | `no_stream` (not yet: ask again), `no_sign_in` (the device answers, and does not sign qKVM in), `locked` (qKVM cannot open the saved passwords just now), `busy` (no memory to check a password with) | |
| 504 | `timeout`: no answer from the device | |
| 507 | `not_saved`: the change could not be written down (a full disk), and was taken back | the wall's disk |

After an action, `unreachable` and `no_stream` mean that nothing was sent; `timeout` and `dropped` mean
that the request went out and its answer did not come, or came broken: **it may have been done**, so do
not offer a blind retry of a power button for either. Every request may answer, beside what its row
names: `unauthorized`, `not_allowed`, `forbidden` and `totp_required` (who may); `invalid`, `too_large`
and `length_required` (the request); `rate_limited` and `busy` (429, 503) wherever a password is checked;
`no_password` (409) wherever one's own password is asked for of an account that has none here; `not_saved`
wherever something is written down; `locked`; and the device's own wherever a device is asked, `in_use`
(409) and `missing_driver` (501) among them.

### The requests

`*` marks what a request must have. "A person": not a token.

| Request | Who | Body | Answers |
|---|---|---|---|
| `GET /healthz` | nobody | | `status` ("ok"), `version`, `api` (the versions spoken: `["v1"]`), `page` (a mark of the page's own files, of no use to another program), `locked` (true: restarted with `--locked-start` and nobody has signed in since, so it reaches no device). Never refuses |
| `GET /api/v1/session` | nobody | | `initialized` (false: nobody has set this wall up, which is done on its page), `authenticated`, `user` (the account, below, or null), `ask_name` (true: more than one account, and signing in needs the name), `recovery` (a recovery key exists), `recovery_created` (to an admin: when, in seconds since 1970; otherwise null), `setup_code_required`, `min_password`, `unlocks_at_start`. Started with `--sso-header`: `sso` (`on`, `name`, `known`), and whoever the proxy signed in is signed in here by this answer, cookie included |
| `POST /api/v1/login` | nobody | `password`*, `name` (where `ask_name`), `code` (where asked for), `remember` (30 days) | `ok`, `user`, and the cookie. 401 `bad_password`; 401 `code_required`: the password was right and the account has a second step, send the same request again with `code`; 401 `bad_code`; 403 `suspended`; 409 `not_initialized`; 409 `no_second_step` (the key of the account's second step does not open any more: `qkvm --disable-2fa` where qKVM runs); 422 `name_required`; 429 `rate_limited` |
| `POST /api/v1/logout` | viewer, a person | `scope`: "this" (default), "others" (the account's other sessions), "all" | `ok`; the cookie is cleared, except for "others". 507 `not_saved`: signed out all the same, and a restart may undo it |
| `POST /api/v1/password` | viewer, a person | `current`*, `new`* (10 to 256 characters) | `ok`; the account's other sessions end. 401 `bad_password`; 409 `no_password` |
| `POST /api/v1/totp/begin` | viewer, a person | `password`* | `secret` (the key, in groups of four), `uri` (`otpauth://...`, for a QR code), `qr` (that code drawn, a text per row, "1" for a dark module). 409 `enabled`; 401 `bad_password` |
| `POST /api/v1/totp/enable` | viewer, a person | `code`* (from the app, for the key just shown) | `ok`, `user`, `recovery_codes` (ten one-time codes, shown this once); the account's other sessions end. 409 `not_started`; 401 `bad_code` |
| `POST /api/v1/totp/codes` | viewer, a person | `password`* | `ok`, `user`, `recovery_codes` (ten new ones; the old stop working). 409 `not_enabled`; 401 `bad_password` |
| `POST /api/v1/totp/disable` | viewer, a person | `password`* | `ok`, `user`. 401 `bad_password` |
| `POST /api/v1/recover` | nobody | `recovery_key`*, `new_password`*, `name` (where there are several accounts) | `ok`; every session of that account ends. 401 `bad_recovery`; 409 `not_initialized`; 422 `name_required`; 429 `rate_limited` |
| `POST /api/v1/display` | nobody | `key`* | `ok`, `user` (`token` true), and the cookie. 401 `bad_key`: the link was taken back or has run out |
| `GET /api/v1/about` | viewer | | `version`, `licence`; to an admin also what it runs on |
| `GET /api/v1/wall` | viewer | | `interval` (seconds between two pictures of a tile, as set for this wall), `live` (the form of the live line this qKVM speaks, as a number: 2; a program that speaks another form asks for no live picture, see [Live view and control](#live-view-and-control)), `devices` (the machines this account may see, each as below). Never waits for a device |
| `GET /api/v1/status` | viewer | | by device `id`, how each is (below), from what is known: it waits for no device, except up to a second and a half for one's very first look |
| `GET /api/v1/devices/{id}/history?what=summary&since=&until=&limit=&every=` | viewer | | what the wall saw of the machine, kept beside the settings (the chapter [History](#history)). `what`: "summary" (default), "states", "samples" or "events"; `since` and `until` in seconds since 1970 (left out: the last week, for samples the last day); `limit` 1 to 5000 (1000 left out); `every` 0 to 86400: samples averaged over spans of that many seconds. A summary: `since`, `until`, `first_seen`, `last_seen` (seconds since 1970, or null), `state` and `power` ("on", "off", or null) as last seen, `watched`, `online`, `answering` (seconds of the window), `share`, `answering_share` (online, and answering, over watched; null where nothing was seen), `changes`, `events` (how many in the window), `sensors` (the names of its readings of the last day). The rest: `since`, `until`, `rows` (oldest first; a state `t`, `state`, `code`; an event `t`, `kind` ("pressed": a power button pressed from the wall, "power": a change of power state seen), `what`, `ok` (null: nobody heard how it went), `note`; a sample `t`, `sensor`, `unit`, `value`), `more` (the page was cut: narrow the window), and for samples `every`; with `every` given, `series` in place of `rows`, one per sensor: `sensor`, `unit`, `points` of `[t, average, min, max]` (a sensor whose series does not fit whole is left out). 404 `not_found`; 503 `busy` (three reads at once are answered, from everybody together, and one at a time of each account or token, whose next waits its turn for eight seconds at the most and, after a read, as long again as that read took; `Retry-After` says when); 503 `history_unavailable` (the file is being opened or replaced, or the read took too long) |
| `GET /api/v1/devices/{id}/snapshot?w=640&age=1` | viewer | | the screen as `image/jpeg` or `image/png`, with `X-KVM-Signal` 1 or 0 (0: a placeholder, the computer shows nothing) and `Cache-Control: no-store`. A still kept between sessions (a PC with Intel AMT whose tile is only shown) carries `X-KVM-Still: 1` and `X-KVM-Age: <seconds>`, how old the still is. `w`: the width wanted, 1 to 16384 (the source's own is never exceeded); `age`: how old, in seconds, the frame may be (0 to 3600; viewers asking within that window share one frame). 404 `not_found`; 404 `no_picture` (a server whose controller gives none); 503 `no_stream` (not yet: ask again); 409 `in_use` (a JetKVM whose one viewer is somebody else); the device's |
| `POST /api/v1/devices/{id}/live` | viewer | `{}` | `v` (the form of the live line this qKVM speaks: 2), `ticket` (a pass for one live line to this machine, good for half a minute and for one use: 16 to 200 letters, digits, `-` or `_`; it is in no log, and is not to be kept). A viewer, a wall screen and a token may ask, and may watch; taking keyboard and mouse over the line takes an operator or an admin, by cookie or by token. 404 `not_found`; 404 `no_live` (a server whose console is not read: `live` is not in its `can`); 429 `busy` (this account, token or wall screen has 32 live lines open, the passes it has not used counted with them; or the wall 256 passes out: `Retry-After`); 503 `locked` |
| a WebSocket at `/api/v1/devices/{id}/live` (`GET`, upgraded) | by the pass | the first message, text: `{"t": "hello", "v": 2, "ticket": "...", "video": ["h264", "jpeg"], "max_w": 1920, "max_fps": 30}` | the live line: the machine's picture down, keyboard and mouse up, with the messages [Live view and control](#live-view-and-control) lists. It carries no cookie, and is asked for from the address the pass was given to. A line whose first message is not a pass this qKVM gave for this machine is told `{"t": "bye", "code": "no_pass", "message": ...}` and closed; one from a page of another host, or for a host this wall does not answer to, is refused 403 before anything is read |
| `GET /api/v1/actions` | operator | | `actions`: each `id`, `name`, `kind` ("keys" or "text"), `keys`, `enter`, `danger`, `changed` (how often it was edited). Never the text a saved action types |
| `GET /api/v1/devices/{id}/wol` | operator | | `targets`: each `mac`, `name` (what the device calls it, which a KVM fills with the address where it has no name; empty where it has nothing). A machine without `wol` in `can` answers an empty list. 404 `not_found`; the device's |
| `POST /api/v1/devices/{id}/actions` | operator | `action`*, and what that one needs (the table below); `batch` (any id of letters, digits and "-", up to forty: ties several requests together as one act in the activity log) | `ok`, `note` (null; or "already on", "already off" for a server that was so; or "pressed, but the computer is still off", "held, but the computer is still on", "pressed; its board has not said since", "pressed; not seen: its connection ended" (the tile was edited or removed, or the wall locked itself; and "held; ..." of the same) for a KVM's power button whose change its board did not show: it was pressed). 404 `not_found` (also: the saved action is gone); 409 `busy` (with `by`, the name of whoever has the machine's keyboard and mouse over a live line, where that is why: an account's, or a token's with "(token)"; to an admin in person the message adds that they can take them over in the live view: an action never takes over by itself); 409 `conflict` (it waited for the last holder of the keyboard to be let go of, and meanwhile the tile was changed or taken off the wall: nothing was sent); 409 `changed` (the saved action was edited since it was listed); 409 `no_text`; 403 `not_allowed` (a token and a saved text); 403 `stopped`; 422 `invalid` (also: an action this machine cannot do); 502 `action_failed` (the device refused); 504 `timeout` and 502 `dropped` (it may have been done); the device's. Every action is written to the activity log with the account |
| `POST /api/v1/devices/{id}/console` | operator, a person | `{}` | `url`: a way into a server's own console, signed in, good for one use, for the browser of whoever asked; it is in no log, and is not to be kept. 403 `not_allowed` (a token); 404 `not_found`; 404 `no_console` (no such way in from this device); the device's |
| `PUT /api/v1/wall/order` | admin | `ids`* (device ids, first to last; the rest keep their order after them) | `ok`, `ids` (the whole order, as it is now, for every browser). 507 `not_saved` |
| `POST /api/v1/devices/remove` | admin | `ids`* (1 to 5000 device ids, within the 64 KiB a body may have; one given twice is one machine) | takes every one of them off the wall, or none: `ok`, `removed` (their ids, in the wall's order). Each one's saved password and history go with it, and each gets a line of its own in the activity log (`device_removed`), as one removed on its own does. An action on its way to one of them is answered as one cut off by an edit of the tile (it may have been done), and a live line to one is told `gone`, the keys it held let go of first. 404 `not_found` with `unknown` (the ids that are not on the wall: nothing was removed); 507 `not_saved` (nothing was removed, and nothing on them was cut off) |
| `GET /api/v1/tokens` | admin | | `tokens`: each `id`, `name`, `kind` ("api" or "display"), `role`, `devices` (ids, or null for all), `groups`, `created`, `expires` (null: never), `used` (null: not yet). Never the token itself |
| `POST /api/v1/tokens` | admin | `name`*, `kind` ("api" default, "display"), `role` ("viewer" default, "operator"; never admin), `devices`, `groups`, `days` (1 to 3650; left out: until taken back) | 201 `token` (shown this once), `record` (as listed). 507 `not_saved` |
| `DELETE /api/v1/tokens/{id}` | admin | | `ok`; a screen showing with it goes dark. 404 `not_found` |
| `POST /api/v1/export` | admin, a person | `password`* (the account's own, again), `parts`* (of "devices", "actions", "alerts", "wall"), `passphrase` (10 characters or more: an encrypted file with the passwords in it; empty: a plain file without them) | the file as `application/json` with a `Content-Disposition` name (`qkvm-<date>.qkvm` or `.json`), and the header `X-QKVM-Not-Opened`: how many saved passwords or texts are not in it because they do not open any more. 401 `bad_password`; 422 `invalid`, `too_large` (more in the wall than a file holds); 503 `locked` |
| `POST /api/v1/import/read` | admin, a person | `file`* (its text), `passphrase` (of an encrypted one) | what the file holds, changing nothing: `encrypted`, `secrets` (a plain file with passwords in it), `made` (seconds since 1970, 0 where it does not say), `program` (the version that wrote it), `devices` (null where the file has no such part; else each `name`, `host`, `kind`, `group`, `password` (whether one is in the file), `tls`, `open_url`, `new` (this wall would take it), `same_as` (the name of the tile here that is the same device, or empty)), `actions` (null, or each `name`, `kind`, `keys`, `text` (of the new ones; what a button will type is read before it is taken), `enter`, `danger`, `new`), `alerts` (null, or `enabled`, `address` (the file names one), `host` (of that address), `format`, `kinds`), `wall` (null, or `interval`, `update_check`), `left_out` (a sentence for each entry that did not pass). 422 `not_a_file`, `damaged`, `newer`, `passphrase_needed`, `wrong_passphrase`, `too_large` |
| `POST /api/v1/import` | admin, a person | `file`*, `passphrase`, `take` (which parts, of the four; left out: the file is read and nothing is taken) | what was taken: `devices`, `actions` (how many were added), `alerts`, `wall` (whether they were replaced), `left_out`. 422 `not_a_file`, `damaged`, `newer`, `passphrase_needed`, `wrong_passphrase`, `too_large`; 503 `locked`; 507 `not_saved` |

### A machine, as the wall lists it

In `devices` of `GET /api/v1/wall`:

| Field | Is |
|---|---|
| `id` | eight hexadecimal digits: what every other request names the machine by |
| `name`, `host`, `group` | as shown on its tile; `host` is the name or address and port the wall talks to |
| `kind` | `kvmd` (GL.iNet Comet, PiKVM and alike), `jetkvm`, `redfish` (a server's controller), `amt` (a business PC's Intel AMT engine), `vnc` (a VNC server), `proxmox` (a virtual machine on Proxmox VE) |
| `picture` | false: a server, whose tile shows how it is doing where a KVM's shows a screen (it may still have a picture: `screen` in `can`) |
| `open_url` | where a browser reaches the machine's own page |
| `same_as` | other tiles that are the same machine under another address: each `id`, `name`, `host` |
| `can` | what this tile can be asked, as words (below) |
| to an admin only | `url`, `custom_open_url`, `username`, `tls` (`pinned`, `system`, `insecure`), `fingerprint`, `has_password`, `alerts`, `fingerbot_strength` (how hard a Fingerbot paired with the KVM presses: `firm` or `light`). The password is never sent to anybody |

**`can`** says what this machine can be asked: from its driver, and from what the wall last
found at the device (a power board, several inputs, a light). It is in the wall's answer
and in the status, and the status's is the fresher: a client that acts goes by that one,
and by the wall's until there is a status. No client has to guess it from the kind of
device, and none should: a server whose controller is not AMI's has a power button and no
keyboard, and a KVM without a power board has no power button either. Each word opens these requests:

| Word | Opens |
|---|---|
| `screen` | a picture: `GET .../snapshot` (a server: as long as its controller is not known to give none, which asking finds out; a PC with Intel AMT: where its KVM may be used; a virtual machine on Proxmox: while it runs; the status's `screen` says the same) |
| `keys` | `keys`, `ctrl_alt_del`, and a saved action that presses keys (a server: once its console is known to be AMI's, and while nobody at the controller's own console has it) |
| `text` | `text`, and a saved action that types |
| `jiggler` | `jiggler_on`, `jiggler_off` |
| `power` | the power button: `atx_power`, `atx_power_long` (a KVM with a power board; a server; a virtual machine on Proxmox, where holding it stops the machine at once) |
| `reset` | the reset button: `atx_reset` |
| `fingerbot` | the power button pressed by a Fingerbot paired with the KVM: `fingerbot_power`, `fingerbot_power_long` (beside `power`, where the KVM has a power board as well) |
| `power_state` | switching on, or asking to shut down, by what is wanted: `power_on`, `power_off` (a server, which knows whether it is on; a PC with Intel AMT; a virtual machine on Proxmox) |
| `bios_setup` | `bios_setup`: start into the BIOS setup once, then switch on or restart (a PC with Intel AMT whose engine offers it; a server over Redfish whose controller allows the "BiosSetup" boot override); one machine at a time, not a bulk run |
| `wol` | `wol`, and `GET .../wol` for what the KVM has saved to wake |
| `ports` | `port` (the status's `ports` says which inputs there are and which is on screen) |
| `reboot` | `reboot`: the KVM itself, or a server's controller |
| `resume` | `resume`: a JetKVM that stepped aside for whoever opened its own page is taken up again |
| `locator` | `locate_on`, `locate_off`: a server's light to find it by |
| `console` | `POST .../console`: a signed-in way into a server's own console |
| `live` | the live picture: `POST .../live` for a pass, then the WebSocket at the same path (a KVM; a server whose console the wall reads, once that is known; a PC with Intel AMT whose KVM may be used; a virtual machine on Proxmox while it runs) |
| `control` | keyboard and mouse over that line: `control` with `on` true, and with `take` true to take them over (an admin in person) (a KVM; a PC with Intel AMT; a virtual machine on Proxmox; a server whose console is AMI's, as `keys`; not an OpenBMC console, which answers `no_input`) |

A word not in this list was added since: a client leaves out what it does not know. And
`can` is what the wall would send, not a promise that the machine takes it: a controller
set up without a reset of that kind still answers 502 `action_failed`.

### How a machine is

In `GET /api/v1/status`, by `id`. Any value may be null: a device that does not say is not
guessed at.

| Field | Is |
|---|---|
| `can` | as above, as of this look |
| `state` | `online`, `no_signal` (there, and its computer shows nothing; a server: switched off), `offline`, `auth` (it refuses the saved password), `error` (its certificate changed, it does not sign qKVM in, a server reports a critical fault, and the like: `error.code` says which), `busy` (a JetKVM whose one viewer is somebody else), `connecting` (nothing known yet) |
| `error` | null, or `code` and `message` (the message fit to show) |
| `last_seen_ago` | seconds since the device last answered; null: never |
| `video` | `signal` (true or false), `width`, `height`, `fps` |
| `usb` | `keyboard`, `mouse`: whether the computer sees them |
| `atx` | `enabled` (a power board, or a server), `power` (the computer is on; asleep counts as on; null where the board does not say, at this look), `hdd` |
| `fingerbot` | a KVM's: null, or, where a Fingerbot is paired with it, `battery` (percent; null until it was asked, which is once an hour) and `low` (below 25). Nothing of the computer's power comes from a Fingerbot |
| `health` | `temp` (the KVM's own, or a server's hottest processor, in degrees Celsius), `cpu`, `mem` (percent) |
| `about` | `model`, `version`, as the device says them |
| `ports` | null, or `active` (counted from 0) and `list` (each `name`, `signal`) for a KVM with several inputs |
| `kind` | said by a JetKVM's and a server's status; a KVM's says neither this nor `picture` (the wall says both for every tile) |
| `picture` | said by a server's status: false |

Before the first look at a device there is only `can`, `state` (`connecting`), `error` and
`last_seen_ago`; while it cannot be reached, those with `error` filled in, and `kind` (and a server's
`picture`) where the status says them at all. A server adds
`screen` (a picture of its screen can be asked for), `console` (a signed-in way into its
console can be asked for) and `server`: `power` (the controller's own word: "On", "Off" and
others), `health` ("OK", "Warning", "Critical", or null), `processor`, `processors`,
`memory_gib`, `temperatures` (each `name`, `celsius`, `ok`), `fans` (each `name`, `reading`,
`unit`, `ok`), `unwell` (the names of the sensors it is not happy with), `locator` (the light:
true, false, or null where there is none), `no_screen` (null, or the sentence why its screen
is not shown where it could be), `rfb_console` (where the controller is OpenBMC with its KVM,
the path on it of the WebSocket that carries its console as VNC, `/kvm/0`, which is where the
wall takes that server's screen from; else null).

A business PC with Intel AMT (`kind` `amt`) is said as a server is, with no temperatures, fans
or light (empty, or null), `screen` true where its screen can be had through its KVM (and
`screen`, `keys`, `text`, `live` and `control` in its `can`), else false with `no_screen` saying
why, and one more record in `server`, `amt`: `power` (the engine's own number for the power
state, of which `server`'s `power` is the word), `control` (how the engine was set up: "none",
"client", "admin", or null where it did not say), `kvm` ("enabled", "disabled", "mebx" where it
was switched off in the PC's MEBx, "absent" on vPro Essentials, which has none, or null),
`consent` (true where a KVM session needs the code the PC shows on its own screen, false, or
null), `listener` (true where the engine's redirection listener is on, which its KVM is reached
through; false, or null), `session_timeout` (the minutes after which the engine ends a KVM
session, 0 for never, or null), `make`, `model`, `serial` and `bios` as the engine says them, and
`plain` (true where the wall reaches the engine over plain HTTP).

A virtual machine on Proxmox VE (`kind` `proxmox`) is said as a server is: `state` `online` while it
runs and `no_signal` while it is stopped, `atx.power` the same, no temperatures, fans or light,
`health.cpu` and `health.mem` (percent of what it was given, while it runs), `screen` true while
it runs and its console can be had (and `screen`, `keys`, `text`, `live` and `control` in its
`can`), else false, with `no_screen` saying why where it runs; in `server`, `power` ("Running",
"Paused", "Stopped"), `processor` ("vCPU"), `processors` and `memory_gib` as it was given them, and
one more record, `proxmox`: `node` (the node it is on, followed where it was moved), `vmid`,
`status` ("running" or "stopped", Proxmox's own word), `qmpstatus` (what QEMU says of it: "running",
"paused" and others) and `uptime` (seconds).

### An account

`user` in a sign-in and in the session: `id`, `name`, `role` (`admin`, `operator`, `viewer`),
`totp` (a second step is on), `must_enroll` (one is required and not set up: every request
but signing out and setting it up answers 403 `totp_required`), `sso` (signed in by the
identity proxy: there is nothing to sign out of here), `recovery_codes` (one-time codes
left), `token` (not a person: a wall screen opened with its link).

### Doing something

`POST /api/v1/devices/{id}/actions`, `{"action": "..."}` and what that one needs. The last
column says the word of `can` it takes. Any action may also say `"watching": true`: whoever
sends it has the machine's large view or live view open (a PC with Intel AMT then opens a
session to its screen before switching on, or starting into its BIOS setup, so the start shows
from the first moment). It is not heard with a `"batch"`: an entry of a bulk run comes from the
selection, not from a view.

| `action` | Does | Also give | Needs |
|---|---|---|---|
| `keys` | a key combination | `"keys": "MetaLeft,KeyL"` (names as browsers and kvmd spell them, up to eight) | `keys` |
| `ctrl_alt_del` | that one | | `keys` |
| `text` | type text | `"text": "...", "enter": true` (up to 2000 characters, US keyboard layout; on a JetKVM, the layout it says its computer uses, and 422 `invalid` before anything is typed for a character that layout cannot type) | `text` |
| `custom` | a saved action | `"custom_id": "..."`, and `"custom_changed"`: the action's `changed` as it was listed, refused with 409 `changed` if it was edited since, or edited or removed while it waited for what the last holder of the keyboard had down to be let go of (saved text is typed by people only: a token that types it could read it back off the screen) | `keys` or `text` |
| `atx_power`, `atx_power_long` | press the power button, hold it; answered once the button is let go, and where it must switch the computer on (or off) once that is seen; the KVM's refusal (a 4xx) is 502 `action_failed`, anything else that is not its yes 504 `timeout` or 502 `dropped` (it may have pressed), after which a press of the board's (or a Fingerbot's) is 409 `busy` for eight seconds and the button's hold | | `power` |
| `atx_reset` | press reset; an answer that is neither yes nor no as for the power button | | `reset` |
| `fingerbot_power`, `fingerbot_power_long` | a Fingerbot presses the power button for half a second, or holds it for eight, as hard as the machine's `fingerbot_strength` says; answered once the KVM has said the Fingerbot took the press and the press's own time is over (some three and eleven seconds); the KVM's refusal ("Failed to click") is 502 `action_failed`, anything else that is not its yes 504 `timeout` or 502 `dropped` (it may have pressed), after which a press is 409 `busy` for as long as that one can last; 422 `invalid` where the KVM said no Fingerbot is paired | | `fingerbot` |
| `power_on`, `power_off` | a server: switch on, or ask it to shut down; one that is so already is left alone and answers `"note": "already on"` or `"already off"` | | `power_state` |
| `bios_setup` | start into the BIOS setup once, then switch on (if off) or restart (if on); 422 `invalid` with a `"batch"` (one machine at a time); 409 `action_failed` where another boot override, or a boot option that destroys data, is already set | `"watching": true` (as for any action: see below) | `bios_setup` |
| `locate_on`, `locate_off` | a server's locator light | | `locator` |
| `reboot` | restart the KVM itself (for a server: its controller) | | `reboot` |
| `jiggler_on`, `jiggler_off` | keep the computer awake, or let it sleep | | `jiggler` |
| `wol` | Wake-on-LAN from the KVM | `"mac": "aa:bb:cc:dd:ee:ff"` | `wol` |
| `port` | show another input of a multi-port KVM | `"port": 0` | `ports` |
| `resume` | a JetKVM: take its picture back from whoever opened its own page | | `resume` |

The page asks before power, reset, a restart, and anything marked `danger`, and before
anything sent to several machines: a program should do no less. One thing at a time per
machine: while an action is on its way, a second one for the same machine is refused with
409 `busy`, whoever sends it.

### Manners

- One viewer's worth of asking: the status no more often than `interval`, a picture per
  tile no more often than that, with `age` set to the interval. Asking for pictures is what
  keeps the wall connected to its devices; a program that stops asking lets a JetKVM's one
  viewer go back to whoever wants it.
- Do not ask in the background for a window nobody sees.
- 401 `unauthorized` in the middle of things means the session ended (signed out elsewhere,
  ended by an admin): sign in again, do not loop. `Retry-After` is meant.

### The page's own

These are under `/api/v1/` as well, take an admin (but for the first-run setup, which takes
nobody), and change with the page: `setup`; `devices` (adding, changing and removing one),
`devices/{id}/certificate`, `devices/{id}/trust`, `devices/{id}/kvm` (switching a PC's Intel AMT
KVM on or off on its engine, `{"on": true}`; 409 `busy` with `by` as for an action), `discover`; `proxmox` (`proxmox/guests`, `{"url",
"username", "password"}`: the virtual machines an API token may see on a Proxmox, to pick from when
adding them, and `named`, the one an address names by its ID); `actions` (saving one);
`users`; `security`; `recovery`; `settings`; `alerts`; `audit` (the activity log, and `audit/export`
to download it: `q`, `kind`, `before`, `since`, `until`, `user`, `device`, `limit`, as the chapter
[Activity log](#activity-log) says); `metrics` (the token for
`/metrics`); `update`. A program written against them is written against this version. Their
codes are in `words.json` all the same.

## Clients and versions

Anything that talks to a wall other than its own page is a client of [The API](#the-api):
a script with a token, a monitoring system, a program of its own that shows the wall. This
is what such a program goes by, so that it keeps working from one version of qKVM to the
next, and says the same things the page says.

- **Ask `GET /healthz` first.** It needs no sign-in. `api` lists the versions of the
  interface this qKVM speaks: a program written against `v1` uses it where it is listed and,
  where it is not, says so plainly (one of the two has to be updated) and sends nothing
  else. `locked` says that the wall reaches no device until somebody has signed in.
- **Within `v1` nothing is taken away** and nothing is given another meaning; fields,
  requests, states, codes and words are added. A program takes what it knows from an answer
  and leaves the rest. A state, a code or a word it has not met is one that was added since:
  a code is shown as a problem, with the sentence the wall sent for it; a word in `can` is
  left out.
- **What a machine can do comes from the wall**, in `can`, never from its kind: see
  [The API](#the-api). A new kind of device brings new words, and a program that goes by
  `can` shows the right buttons for it without having heard of it.
- **The words are one file.** `words.json`, in the source at `qkvm/static/words.json` and
  served by every wall at `/static/words.json`, holds the states and what the page says for
  each (`states`; and `server_states`, for a server, whose "no signal" is "powered off"), a
  device's trouble by its code and the state a tile shows it under (`codes`), every code the
  wall refuses a request with and the statuses it comes with (`refusals`), the kinds of
  device and their names (`kinds`), and the words of `can` with a label for each. The page
  reads it as it starts; another program is built from it, or checked against it when it is
  built, so that no two programs call one thing by two names. A test of qKVM's own fails when
  the page or a driver uses a word the file does not have.
- **What the page does beyond this** (setting a wall up, its settings, accounts, alerts,
  updates) is the page's own, listed at the end of [The API](#the-api): a program leaves
  that to the page, in a browser.

## Metrics

A monitoring system can collect the state of the wall: *Settings > Metrics* makes a token, and
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

qKVM answers when it is called by an IP address, by a name without a dot, or by one ending in
`.local`, `.lan`, `.internal`, `.home.arpa` or `.ts.net`. Any other name the collector is to
reach it by has to be listed under `allowed_hosts` in `qkvm.json`, as for a browser.

| Metric | Says |
|---|---|
| `qkvm_devices{state}` | how many tiles are in each state: `online`, `no_signal`, `offline`, `auth`, `error`, `busy`, `connecting` |
| `qkvm_device_up{id,device,kind,group}` | 1 while that device answers, 0 while it does not |
| `qkvm_device_picture{...}` | 1 while it shows a picture; for a server, while it is switched on |
| `qkvm_device_last_seen_seconds{...}` | seconds since it last answered |
| `qkvm_device_temperature_celsius{...,sensor}` | how warm it is: the KVM itself (`sensor="device"`), or each sensor of a server |
| `qkvm_server_healthy{...}` | 1 while a server's management controller calls it healthy |
| `qkvm_unlocked` | 1 while qKVM can talk to its devices (somebody has signed in since it started) |
| `qkvm_sessions`, `qkvm_devices_configured`, `qkvm_update_available`, `qkvm_info{version}`, `qkvm_start_time_seconds` | about qKVM itself |

- The token is shown once and qKVM keeps only its hash. It lets its holder read the above and
  nothing else; a new one replaces it, and *Switch off* makes `/metrics` answer nobody.
- While metrics are on, qKVM goes on watching the devices after the last person has signed
  out, as it does for alerts: the saved device passwords stay usable in memory for that.
- After a restart qKVM goes on by itself. Started with `--locked-start` (see
  [Keeping it running](#keeping-it-running)), nothing can be collected about the devices
  until somebody signs in; `qkvm_unlocked` is 0 until then, which is worth an alert of its own.
- A collector is nobody watching: a JetKVM that is not on screen is only asked whether it
  answers, as for alerts, and its one viewer is left to whoever wants it.
- `GET /healthz` is separate and needs no token. It says that qKVM is running, which version,
  and whether it is still waiting for a sign-in after a restart (`"locked"`).

## History

qKVM keeps what it saw of each machine, beside the settings: `history.sqlite` in the data
folder. The activity log says who did what; this says what happened to the machines. For each
of them, by its id and nothing else: the states its tile went through (a row when the state
changes, not at every look), when it was last heard from, the readings it reports (a KVM's own
temperature; for a server every temperature and fan) at a slow pace (a sample a minute, sooner
when a reading moves by a few degrees), and the power events: every power button pressed from
the wall, at the moment it was pressed (a press that is waited for until it is seen done is not
moved to the end of the wait), and every change of power state the wall noticed, of a machine
that has a power to tell (a server, a PC with Intel AMT, a KVM with its power board; a KVM
without one has none).

- **Enlarged, a tile says so under its picture:** when the machine was last seen, how much of
  this week it was online, and where the machine reports readings, a small graph of the last
  day for each kind of them (temperatures, fans). "Online 99.2 % this week" is of the time the
  wall was watching: a wall that was stopped for two days, or locked after a restart, saw
  nothing in that time, and that time counts neither as online nor as down. Where more than a
  tenth of the week was not watched, the line says so: "of the 2 d 3 h it was watched this week".
- **How it looks.** Every look anybody takes at a machine reaches the history: a browser, the
  alert round, a collector. And once a minute qKVM looks by itself, the way the alerts look
  (a JetKVM that is not on screen is only asked whether it answers), so that a machine is
  watched while qKVM is unlocked whether or not anybody has the wall open.
- **How much is kept:** ninety days, and 200 MB, `history.sqlite` and `history.sqlite-wal`
  together; beyond either, the oldest rows go first, every ten minutes (as much of them as it
  takes at once, within about half a minute and some of it at the least, along one line of
  time for all the machines; what is left over goes at the next round). The `-wal` file holds
  what was written since the file was last brought up to date, and is held to a tenth of the
  size allowed (8 MB at the most): whenever it grows past that, what it holds goes into the
  file, once the reads under way have ended. The file is kept to the rest.
  (So between two rounds the two grow by what ten minutes bring, and while a round gives the
  room back, what it moves passes through the `-wal` file, a share at a time.)
  (A program outside qKVM that keeps a read of the file open, a database browser, keeps the
  `-wal` file growing until it lets go, and a round stops trimming as soon as it meets that,
  which would only grow it more; the log says so.) Both limits are in `qkvm.json`, under
  `server`: `history_days` (1 to 3650) and `history_mb` (10 to 100000); nothing, or 0, means
  the default. (A server with forty readings writes about 2 MB a day at the default pace; a
  KVM a few hundred kB. One machine puts 128 readings a minute in the history at the most: a
  controller that names its sensors anew at every look, or whose readings jump at every
  look, gets no more than that.)
- **What it holds, and what not.** A row is a device's id, a time, a state, a reading or the
  name of a button: no name, no address, no password, no text that was typed. The history is in
  no export, and an import leaves it alone (see [Export and import](#export-and-import)); a copy
  of the data folder carries it along (the file, and `history.sqlite-wal` beside it: brought
  into the file every ten minutes, whenever it has grown past its share, and when qKVM stops).
  A machine taken off the wall takes its history with it, however busy the history is. `qkvm
  status` says how large it is.
- **It is never in the way.** Rows are written by a thread of their own, from a queue of bounded
  size: nothing that keeps the history makes the wall wait, and where the disk refuses, rows are
  dropped and counted, and the log says so once a minute. A file that cannot be read, at a
  start or later, is moved aside (`history.damaged-<time>.sqlite`, the second it was moved
  aside, for somebody to look at; removed by itself once that is longer ago than the history
  is kept), a fresh one is started, and the log says so: the wall comes up either way. A file
  that is whole is never moved aside for a fault of qKVM's own: the log says that with its
  details, and the file is kept. Three reads of the history at a time are answered, from
  everybody together, and one at a time of each account or token: its next read waits its
  turn (eight seconds at the most), and after a read the same one waits as long again as that
  read took. Whoever asks beyond that is told to come back in a moment (503 `busy`).
- **A script reads it**, with a viewer's token or better, for a machine the account may see:
  `GET /api/v1/devices/{id}/history?what=summary&since=&until=&limit=&every=`, times in
  seconds since 1970. `what=summary` (the default) answers when the machine was first and last
  heard from (`first_seen`, `last_seen`), its last state and power state (`null` where it has
  none), how many seconds of the window it was `watched` and `online`, `share` (online over
  watched; `null` where nothing was seen), and the names of its `sensors`. `what=states`,
  `events` and `samples` answer
  `rows`, oldest first, up to `limit` (1000; 5000 at the most), and `more` says when the page
  was cut: narrow `since` and `until` then. A state row is `{t, state, code}`; an event row
  `{t, kind, what, ok, note}` with `kind` `pressed` (`what`: the action, `ok` whether the device
  took it, `null` where nobody knows, `note` the error code where it did not) or `power`
  (`what`: `on` or `off`); a sample row `{t, sensor, unit, value}`. With `every=900`, samples
  come as `series` instead, one per sensor (`{sensor, unit, points}`), each point
  `[t, average, min, max]` of a span of that many seconds; `limit` then counts the points, and
  a page that is cut loses whole sensors at its end, never the newest spans: a sensor whose
  series does not fit whole is left out (where the first does not fit, the page holds none:
  narrow `since` and `until`, or ask for longer spans). The window is the
  last week, for samples the last day, unless `since` and `until` say otherwise. This request is
  part of `v1`.

## Activity log

Who signed in, changed what, and did what to which machine: *Settings > Activity*, for admins.

- **The record is a set of text files** in the data folder: `audit.log`, and before it
  `audit.log.1` to `audit.log.9`, the oldest last. One entry a line, in JSON: `time` (seconds
  since 1970), `event`, `ip`, `user` (the account, or a token's name with " (token)"), and what
  it concerned: a machine by its name (`device`) and, since 0.2.0, its id (`device_id`). They
  are written first, by a thread of their own, as they were in 0.1.x; never rewritten; what
  `--audit-syslog` sends on; what grep and tail read when qKVM is down. When the newest is
  full it becomes `audit.log.1`, each of the others one older, and the oldest goes; a step of
  that which fails (a file held open by another program, on Windows) is taken up again at the
  next entry, from where it stopped, and no other file goes. A line cut off by a power cut is
  ended before the next entry, which is not lost with it.
- **How much is kept:** 100 MB, in ten files of 10 MB. A busy wall (64 machines with alerts
  on, three people working at them: live views, keyboards taken, actions, sign-ins, some 1,200
  entries a day) writes about 190 kB a day: 100 MB is a year and a half of it. An entry is 90 to
  180 bytes; a live view is two, keyboard and mouse taken and given back two more. At the worst,
  64 machines whose state changes at every look of the alerts (every half minute) write some
  27 MB a day, and 100 MB is four days of that. The size is `activity_mb` in `qkvm.json`, under
  `server` (10 to 100000; nothing, or 0, is 100), read at the start.
- **The page reads an index of it**, `audit.sqlite` beside the files: the same entries, with
  what they are found by, so that a search of a long log is answered at once (on a test PC, a
  100 MB log of 630,000 entries: a word that is nowhere in 0.2 s, one machine's alerts on a
  day a year ago in 0.2 s, the newest page in a few thousandths; reading the files for the same
  takes 2 to 5 s). It is made from the files and from nothing else, and holds what they hold
  and no more: an entry that goes from the files goes from it. It takes about two and a half
  times the files' size. At the first start of 0.2.0 it is made from the files an earlier version
  wrote (a few seconds for 20 MB), and again whenever it is damaged, missing, of another
  version, or finds that a file no longer holds what it read of it (a power cut can take the
  last lines of a text file, which is not written through to the disk at every entry, and leave
  them in the index) (some 15 s for 100 MB): nothing of the log is lost, and the log of qKVM
  says so.
  Nothing waits for it: the text files are written whatever it does, the wall answers as fast,
  and where it is behind (being made, its disk refusing) the page reads the files themselves,
  slower, with the same answers, for 5 s at the most (a page of a download, 15 s): a question
  that takes longer there is answered 503 `activity_unavailable`, to be asked again in a moment
  or narrowed down. It leaves the record its room: where the disk has less free than two text
  files and 32 MB more, it waits (the log of qKVM says so), and the page reads the files.
  Where two of the files begin with the same line (a copy made by hand), it steps aside until
  one of them goes, and is made again then. The newest file's last line counts once it has
  ended, for the index and the reading of the files alike (a line written into the file by
  hand without its end is run into by qKVM's next entry, as in 0.1.x, and is no entry for
  either; one cut off by a power cut is ended at the next start).
- **In the page** the log is searched (under the names the page shows, or the ones in the
  file), narrowed to sign-ins, actions on machines, changes or alerts, to a machine (what was
  done to it; what was written before 0.2.0 named it only, and is found by the name it has
  now), to an account or a token (typed: one that was removed is in the log all the same), and
  to a time from and to; older entries come a page at a time (those of the moment a page ended
  in come on the next one: a removal of many machines can write hundreds with one time; of a
  moment with more than 500, the newest 500 are shown). It is downloaded as a table (CSV)
  or as the lines themselves, all of it or what is shown: made a page at a time, however long
  it is (never the whole log in memory: beyond 8 MB in a temporary file in the data folder,
  gone once it is sent, or at the next start where a power cut left it), and sent once it is
  whole, with its length, so that one cut off on its way shows as cut off; one that cannot be
  made whole is refused (503 `activity_unavailable`). It takes none of the record's room: where
  the disk would keep less than the index waits for, it is refused (507 `not_saved`). Three are
  made or sent at once, one of each account (beyond that, 503 `busy`), and one whose asker went
  away is made no further. What goes from the log while a long one
  is made (the oldest file, when the newest is full) is not in it; made from the files
  themselves, it is of the files as they were when it began (on a share, the newest file is
  then moved on only once it is made: nothing is lost, the file grows past its size meanwhile).
  Enlarged, a tile shows an admin the last three things done to its machine beside its
  history (live views left out: "Nothing but live views" where its last 100 entries are only
  those), and *All of it* opens the log on that machine.
- **What is written:** sign-ins and sign-outs, wrong passwords and codes; every change of the
  settings, accounts, tokens, machines and saved actions; every action on a machine, and one
  that failed; a live view opened and ended, with how long it was open; keyboard and mouse
  taken, taken over and given back; a server's console opened, or asked for and not had;
  alerts; a file of the wall exported or taken in, and a download of this log with what it was
  of. Never a password, a key pressed, or a text that was typed. An account's live views write
  120 entries an hour at the most, and the next one says how many were left out: two entries a
  view, a script opening lines in a loop would otherwise push out of the log what was done
  before it. The same for a server's console opened, and for one asked for and not had: 120
  entries an hour of each account, each; and an opening of a server that no entry of that
  account named in the last hour is written whatever is left, so that every server whose
  console an account opened is named in the log within the hour (openings beyond that are
  counted).
- **Read in turns,** as the history is: one read at a time of each account (its next waits its
  turn, and after a read as long again as it took), three at once from everybody together;
  beyond that, 503 `busy` with `Retry-After`. A read of the index is given up after 5 s
  (503 `activity_unavailable`: narrow it down). A read that waited asks again whether its asker
  may still have it (signed out, removed, or no longer an admin meanwhile: refused), and so does
  a download before each page.
- **For a program** (an admin's session; a token is never an admin): `GET /api/v1/audit` with
  `q` (words, any of them, in any case; several `q`), `kind` (`signin`, `action`, `change`,
  `alert`), `device` (a machine's id), `user` (an account's name, or a token's as the log
  writes it, `night script (token)`; in any case),
  `since` and `until` (seconds since 1970), `before` (older than this: the next page),
  `limit` (1 to 500, 100 left out) answers `entries` (newest first, as written), `more`, and
  `missing` (entries that could not be written, or null). `GET /api/v1/audit/export` takes the
  same but `before` and `limit`, and `format` (`csv` or `jsonl`), and answers the file with its
  `Content-Length`, or 503 `activity_unavailable` or `busy`, 507 `not_saved`. These are the page's own
  requests (see [The API](#the-api)): they change with it. `qkvm status` says how large the
  files and the index are.

## JetKVM

Add a JetKVM like any other KVM: type its address and qKVM recognises it. Leave the
password empty if the JetKVM has none; the user name is ignored. A JetKVM has no "send me a
picture" request: its screen exists only as WebRTC video, so qKVM connects the way the
JetKVM's own page does. What that takes (the `aiortc` package and the video decoder it
brings) is installed with qKVM. It is most of what an install takes on disk (75 to 120 MB of
it, depending on the system), and is loaded only once there is a JetKVM on the wall.
How a JetKVM is reached is its owner's choice, made at the device's own page (*Settings*,
*Access*), and qKVM goes along with it:

- **HTTPS or plain HTTP.** Out of its box a JetKVM serves plain HTTP. With its HTTPS mode on
  it serves HTTPS beside that, with a certificate of its own making or one you give it.
  qKVM asks both ways and uses HTTPS wherever the JetKVM offers it, also where `http://` was
  typed in front of the address; its certificate is remembered on first contact, as a
  Comet's is. An address typed with `https://` is never answered the plain way: where only
  plain HTTP answers, that is said, and the address is yours to type with `http://`. A
  JetKVM added over plain HTTP says so in the list of what was added.
- **When that is changed later, the tile follows.** A JetKVM on the wall over plain HTTP is
  asked every ten minutes whether it offers HTTPS by now, and moved there when it does. It
  is asked as well before qKVM signs in to it, and before a password you type for it is
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
  device itself out, qKVM included.

Three things are different from a Comet, and they come from the device:

- **One viewer at a time.** A JetKVM shows its picture to a single connection. While it is
  on the wall, qKVM is that viewer. When someone opens the JetKVM's own console, the tile
  says *In use elsewhere* and qKVM stays away, so it never throws that person out.
  **Show here** on the tile takes the picture back (and disconnects them).
- **Signing in signs others out.** A JetKVM with a password has one session for everybody:
  when qKVM logs in, a browser logged in to that JetKVM has to log in again, and the
  other way round. qKVM logs in once and keeps its session for as long as it can.
- **It must be reachable directly**, on the LAN or over a VPN such as Tailscale. JetKVM
  Cloud only works from a browser signed in with Google, so qKVM cannot go through it.

The picture is decoded on the computer running qKVM, and a JetKVM sends video at the rate
of the screen it watches. Measured with a 1920×1200 screen at 60 frames a second, one JetKVM
takes about 15 % of one core of a desktop processor for as long as qKVM is connected to it:
while somebody has the wall open, and five minutes after the last viewer has gone. Then qKVM
disconnects and it takes nothing. A JetKVM nobody has watched for a minute or more sends its
first picture some five seconds after qKVM connects to it (a real one did every time; after a
long rest it once took longer than fifteen): its tile says *Waiting for the first picture*
meanwhile. Held for those five minutes, the picture is there at once when somebody looks again;
the JetKVM's own page takes the viewer as at any other time, and the JetKVM works harder
meanwhile (a real one: 8 % of its processor, where it used under 1 % with nobody connected).
When its computer's screen comes back on a connection qKVM holds (the computer woke, or its screen
did), the JetKVM says so at once and sends the first picture of it a moment later (a real one:
within a second or two). Until that picture comes, the one from before is not handed out as the
screen: the tile waits for it, and a live view that opens or asks for a picture meanwhile gets
none (one that is open keeps what it shows). That moment is no sign of a JetKVM that stopped
sending video, however old the picture from before: the first picture is waited for twenty
seconds, where a JetKVM that stops sending pictures of a screen it shows is given five. Where none
comes by then, it is taken for one that stopped, as after those five: called offline for the
moment it takes to connect again, and a live view that held its keyboard and mouse takes them
again (a real one once sent no picture on the connection it held while its computer was woken,
and a new connection had it at once).

Keys, typed text, keep-awake, Wake-on-LAN, the ATX power extension and reboot are in the action
menu. **Text is typed in the keyboard layout the JetKVM says its computer uses** (set on its own
page): for each of the nineteen layouts it offers, with the keys of the layout Windows has under
that name, from tables made of Unicode CLDR's keyboard data (`qkvm/layouts.py`); a character that
takes a dead key is typed as that key and the next (on a German keyboard, an e with a circumflex
is the circumflex key, then e). A character the layout has no key for (a Latin letter on a
Russian keyboard), or any character where the JetKVM names a layout qKVM has no table for, is
refused before anything is typed, with its place in the text and the layout named (not the
character itself: the words are kept in the activity log, where a typed text never goes). A
JetKVM whose layout was never chosen gets US keys, as its own page types them. Caps Lock is not
looked at: where it is on, letters come out the other way round. A layout of another system
(Linux, macOS) may have a few symbols elsewhere. **The live view's keys are not touched by
this:** they are places on the keyboard, and the computer makes of them what its layout has
there, as of a keyboard plugged into it. On a real JetKVM with a Windows PC behind it, keys,
Ctrl+Alt+Del, *Type text* (every character of a US keyboard, 48 a second), the saved actions and
keep-awake were seen to arrive on the PC, and so were the live view's keys, pointer, buttons and
wheel; the restart works. The ATX extension's short press woke a real one's PC from its sleep,
and its power and disk lights were read (see [Limits](#limits)); its long press, reset and
Wake-on-LAN have so far only been tried on a stand-in.

**How keys and the mouse go.** A JetKVM has a binary channel for them (`hidrpc`), which its own
page uses, and so does qKVM: each key, move and click goes at once, without waiting for the one
before, and the JetKVM does the keyboard's in the order they were sent and the mouse's in the
order they were sent. (A key and a mouse report that reach it at the same moment may be done in
either order, as from its own page; a person's Ctrl and click are far enough apart. The wheel,
which that channel has not got, goes over the other one, and may land a moment before or after a
press of a button made at the same time.) A key held in the live view is kept alive as its own
page keeps it: the JetKVM lets go of a key 100 ms after it was pressed or last kept alive. Its
page sends a keep-alive every 50 ms, qKVM every 30 (one that comes early counts in full, so a wall
that is busy for a moment has more time to spare). So when qKVM vanishes (stopped hard, or the network between them cut) a key it held
is let go of within a tenth of a second (a real one: 0.1 s after the last keep-alive, where it
took some six seconds before); Ctrl, Shift, Alt and Win the JetKVM never lets go of that way, and
those wait until it notices that the connection is gone, some seconds later. A keep-alive that
comes more than about a tenth of a second late lets go of the key for good: over a link that
stalls that long, the computer stops repeating a key that is still held. An action types one key
a round trip, each once the JetKVM has said that it has it, so one key is on its way at the most
(on a local network 48 keys a second, where the other way gave 33). A JetKVM that does not answer
qKVM's question on that channel within two seconds of its opening (a firmware older than the
channel) is spoken to as below; keys and actions then wait those two seconds once a connection.
One whose answer comes later (a wall busy for seconds, or a JetKVM still setting the channel up)
is asked again once a second for ten seconds, as its own page asks, and gets its keys and mouse
over that channel from the first moment nothing of qKVM's is down on it or on its way to it, and
no action types.

Over that other way, JSON-RPC, a JetKVM does each request in a task of its own, so two that arrive
together are done in either order. qKVM sends it keys and the mouse one at a time, each once the
JetKVM has answered the one before; sent without waiting, a real one typed the alphabet out of
order and kept a key and a mouse button down. On a local network an answer takes a few
milliseconds. Over a slow link (a VPN, Wi-Fi) keys wait their turn: at a tenth of a second there
and back, some five keys a second go through, and fast typing falls behind. Moves of the mouse and
turns of the wheel that wait add up, so the pointer keeps up (a turn of the wheel may then land a
little before or after where the pointer went meanwhile); a press or a release of a button stays
where it was made. A JetKVM that leaves one of them unanswered for five seconds, or falls far
behind, has its connection ended (it lets go of every key then, and what waited to go is lost)
and made anew; its tile stays online, and whoever held its keyboard and mouse is told at their next
key. On either way, an action that types waits for keys of the live view still on their way, and
is refused (*busy*) where they take longer than that; where the JetKVM does not say that it has a
key the action pressed, the key is let go of and the connection is ended as well.

**Letting go.** A JetKVM lets go of the keyboard when the connection that pressed it ends and when
its own page takes the viewer; never of a mouse button: a real one kept the left button down
across both, for whoever came next. So qKVM lets go of what it has down before it ends a
connection itself (the tile edited or removed, the wall locking itself or stopping, nobody
watching), and a connection after one that ended with something of qKVM's down, or maybe down,
begins with "nothing down" (the keyboard, and the mouse's buttons where the pointer was last put).
To the computer a JetKVM's mouse is two, one put at places and one moved by steps (the live
view's locked pointer), each with buttons of its own: a drag begun with one and ended with the
other is let go of on both. Where the JetKVM closes only the channel keys and the mouse go over, the
buttons and the keyboard are let go of over the other. An action that types stops where its
connection is ending: it lets go of its key at once, nothing of it goes after that, and it says
after how many keys it stopped; a key held in the live view is no longer kept alive then, so the
JetKVM lets go of it within a tenth of a second.
Whoever holds the keyboard and mouse in the live view loses them, and is told so, as soon as
somebody opens the JetKVM's own page, and nothing more goes to it, also not the rest of a text
being typed, but one thing: a letting go. A JetKVM goes on doing what the old connection sends for
about a second after the hand-over, and closes it then; a key pressed in that second stays down
for whoever has taken the viewer (a real one repeated it until the page's own connection ended),
and a letting go sent in that second lets go of it (seen on the real one too). Over `hidrpc`,
where qKVM cannot tell whether its last key was done before the hand-over or after, it sends one
letting go of the keyboard where the last it said had a key down, and of the mouse's buttons where
they were down, at once, behind everything of its own (the JetKVM does them in order), and nothing
else; its keep-alives stop. Over JSON-RPC, a key or a mouse button qKVM pressed that the JetKVM
did after it had handed its viewer over (its answer comes after the JetKVM said so) is let go of
by one more report as that answer comes, and one it never answered is let go of the same way once
no answer has come in time, while the connection is still open, and again, in turn, should its
answer come after all; a mouse button held as the page took over is let go of once no mouse
report of qKVM's is in the JetKVM's hands; qKVM waits up to two seconds for such answers before it
closes its connection, also when the tile is edited or removed or qKVM stops in those seconds.
A power button is not pressed where the page took over meanwhile (the action says so, also where
it was cut off while qKVM still asked whether the power board is on), and one that was on its way
is said to be "may have been done", as it is whichever way qKVM's connection to the JetKVM ended
while the press was on its way (the tile edited or removed, the wall locking itself, the
connection given up or closed). A press the JetKVM does only after qKVM's connection to it has
closed is the one thing nobody lets go of then (see [Limits](#limits)).

## Servers

A server board has a management controller of its own (a BMC): AMI MegaRAC on ASRock Rack,
Gigabyte and many others, iDRAC on Dell, iLO on HPE, OpenBMC. They share one interface,
Redfish, and qKVM speaks it. Add a server like a KVM: type the address of its controller,
with the controller's user name and password, and qKVM recognises it. *Find KVMs on my
network* finds controllers as well.

**A server's tile shows the server's screen**, as a KVM's does, where the controller runs AMI's
MegaRAC firmware (ASRock Rack, Gigabyte and many others). Redfish itself has no picture; the
screen is in the console that the controller's own web page opens, and qKVM takes it from there:

- It signs in to that page with the login saved for the controller and opens the console. The
  tile shows the screen; enlarged, **Control** takes the server's keyboard and mouse, and **Send
  keys**, **Type text** and **Ctrl+Alt+Del** work as they do for a KVM. These go to the server's
  own USB over the same console. A power command never goes that way: the power buttons are
  Redfish's, as below.
- It holds one of the controller's console seats (as a rule there are two) while somebody
  looks at the wall, and gives it back twenty seconds after nobody does.
- It keeps out of the way of whoever works at the console. Somebody who opens the controller's
  own console while the wall has it is let in at once, keys and all, and the wall goes on
  looking. Whatever a live line had down on the server is let go of first, and the line has the
  keyboard no more: its next key is refused with `in_use`. Keys go only once the
  controller has said that the console is the wall's; a console that another session still
  holds is shown, and nothing is typed into it. When somebody has the console first, the controller asks them whether a newcomer
  may look; the wall does not leave that question on their screen. It leaves the moment it is
  told to wait, shows how the server is, says why, and looks again ten minutes later.
- A controller that is set to switch the server's own monitor off while a console is open is
  left alone, and the enlarged tile says why there is no picture. Ten minutes later it is asked
  again, in case the setting was changed.
- A controller ends a console session in which no key was pressed for a while (half an hour,
  on the boards this was tried with), and a wall that only looks presses none. It opens the console again at
  once, and the tile keeps its picture for the moment that takes.
- The tile's footer says how large the screen is, how the server is and how warm. Enlarged,
  **Health** shows every temperature and every fan.
- The picture is read in Python, and what a controller sends is not believed. A text console
  costs next to nothing; a screen that changes all over (a video, a desktop being dragged
  about) takes seconds a frame on a desktop processor. The frames of two servers are read at
  a time and the others wait their turn, so busy screens slow each other's pictures and
  nothing else. No frame may be longer, or bring more, than a screen of its size could take
  twice over, and a screen larger than 2048 pixels either way is not shown.

**Where the controller runs OpenBMC** with its KVM (its manager says so: a graphical console of
the KVM-over-IP kind), the screen comes from that console instead: a WebSocket on the controller,
`/kvm/0`, that carries the protocol of VNC, read by the same reader as a [VNC server](#vnc-servers).
qKVM opens it with the Redfish session it holds already, so there is no second sign-in; it takes one
of the controller's four console seats while somebody looks, and gives it back a minute after nobody
does, and before the session it was opened with. The console asks for no password of its own; one
that does is sent nothing, since the only password here is the controller's. No key goes that way
yet. This was built from the source of OpenBMC's web server and tried against a stand-in; on
OpenBMC's own image in QEMU only the console's sign-in could be tried, since that image has no
console (see [Limits](#limits)).

On a controller of another make (iDRAC, iLO and the rest speak consoles of their own; an iDRAC's
own VNC server, where it is switched on, can be a tile of its own: see [VNC servers](#vnc-servers)), and
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
  controller itself; the server keeps running. **Start into BIOS setup** tells the controller
  to boot the server into its firmware setup once (Redfish's `BootSourceOverrideTarget`
  "BiosSetup", for one boot) and then switches it on, or restarts it if it is on, so it comes
  up in its BIOS setup; the question before it names the server and says which. It is offered
  only where the controller says it allows that boot override, is for one server at a time
  (its large view opens to show the setup screen), not a bulk run, and is written in the log.
  A boot override another tool set (a network boot, or one for every boot) is not replaced,
  nor is a server touched that is switching on or shutting down just then: the button says so
  and does nothing. Once the override may be set, the button says whether it is: where the
  controller refuses the restart for certain, or its answer to the override itself is lost, the
  override is set back to off, so no ordinary boot lands in the setup; where the restart may
  have gone through (its answer lost, an error of the controller's own, or an answer a command
  does not have), or a server switched on is not seen to come on, it is left set and the
  button says so. The clearing reads first and leaves an override another tool has set by
  then (one set in the moment between that read and the clearing is not seen); an override
  that was set already before the press is left as it was, and said. A controller that takes
  the override, or its clearing, for later (202) is read until it shows it; where it shows
  that it did not keep the override, nothing is restarted (where it cannot be read, the
  restart goes out). Where it is read back, the power that read shows decides what goes out: a
  server switched on meanwhile (at its button, by another tool) is restarted, and one that began
  to change its state is left alone and the override cleared again. After a 204, which is what
  the board this was tried on answers, nothing is read before the power command (that board
  answers no read for about a minute after the change): a server read off before the change and
  switched on by somebody during it is sent *On*, which a server that is on takes as nothing to
  do, so the button says done, nothing restarts, and the override waits for that server's next
  boot. A server switched on into its setup is waited for that minute and the usual 25 seconds
  after it before the button says it did not come on. A restart that the controller accepts is
  not seen done (the server is on
  before and after): the override stays set until the server boots, and the large view shows
  whether it did. A press that has not come to its restart within two minutes goes no further:
  nothing is restarted, and the override is cleared again. Nothing under way is cut off for
  that: a request is waited out within its own time, and a clearing goes to its end, so the
  answer can take several minutes on a controller that is slow at every step (some ten at the
  very worst). The page waits four, then says it had no answer and that the setup boot may be
  set; the activity log has how it ended.
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
  and then nothing does. When a server is switched on, or its power cut, qKVM waits until it
  sees the server on, or off, and says so if it does not get to. A request to shut down is
  different: the system takes the time it takes, and the tile shows when it is off. Where no
  look at the server comes back in that time, the button says that it may have been done
  (`timeout`), not that it was not; so does a command the controller answers with an error of
  its own (a 5xx): only a refusal (a 4xx) says that nothing was done. A bulk run's *Retry
  failed* does not press those again.
- **A controller has its moments.** It is a small computer, and one in perfect health lets a
  request time out now and then, or answers errors for some seconds while its server starts
  or stops. The tile does not change for that. It does once the controller has given no
  proper answer for three quarters of a minute.
- **One sign-in, kept.** A controller allows only a few sessions at a time. qKVM signs in
  once, goes on using that session, and gives it back when the server is taken off the wall.
- **The server it was added for, and no other.** A controller's maker may put one certificate,
  and its key, on every board, and a rack often has one password: after a new lease another
  server's controller may answer at a tile's address, and its certificate does not tell it apart.
  So qKVM remembers two numbers when a server is added, and keeps them in an export file: the one
  its computer gives for itself (its UUID), and the one its controller's Redfish service gives in
  its service root, which anybody may read. Before the password goes to the controller (when
  qKVM signs in, and again when that session has run out) the service root is read and its
  number compared. Before every power button, the locator light, *Start into BIOS setup*, the
  console's own sign-in (the screen and the keys come through that console; asked again once that
  sign-in is done, before the console is opened) and *Open console*, the computer is read and its
  number compared, and the command goes only under the session that read came under: another
  server does not know that session, so what takes a command is the server that was asked. Every
  look compares too, so the tile never shows another server's power, name and sensors as this
  one's. Where another server answers, or one whose computer names no number where this one's
  did, nothing is sent to it (not the password where its controller's number differs; no command,
  no key, no console), and the tile says so from the moment that is seen until this server
  answers there again. If it is the server this tile is for now (another board, or its controller
  set back to its factory settings, which may give its service another number), edit the tile and
  type its password; saved without being checked (*Save anyway*, password or not), the tile keeps
  the server it was added for. A tile from qKVM 0.1 knows its server by the number it kept then
  and takes its controller's at the first look that finds the server to be this one (the root's
  number is taken only where the controller's manager, read under that session, names the same,
  as the service it hosts or as itself; a controller whose manager names neither is known by its
  computer's number alone);
  a tile with neither (one kept beside its twin) takes the first it sees, as a certificate is
  remembered on first contact. A board whose computer gives no number (all zeros) is known by its
  controller's alone; one that gives neither is not told apart this way.
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
  otherwise. What was rejected is kept in memory: after a restart of qKVM it is tried
  once more. While it waits qKVM still asks twice a minute whether the device is there,
  without the password, so a machine that goes off meanwhile is shown as offline.
- **The account decides what works.** An account with the controller's read-only role is
  enough to show the state. The power buttons and the locator light need the operator or
  administrator role.
- **A console opened from the wall is signed in as that account.** The pass works once and
  goes to the browser of whoever clicked, nowhere else; that they went in is written to the
  activity log. Operators and admins of the wall can do this, viewers cannot, and an account
  limited to some machines only for those. If the people on your wall should not have what
  the controller's account has, give the wall a controller account that has less.

## Intel AMT

A business PC with Intel vPro Enterprise has a management engine beside its processor
(Intel AMT) that answers while the PC is off, asleep or hung. qKVM speaks WS-Management to
it, as Intel's own tools do, and reads its screen through the engine's own KVM. **This is
experimental**: it was built from Intel's published class reference and MeshCommander's
published source (read to learn the redirection handshake, not copied), tried against a
stand-in, and tried on one real machine, a business PC with Intel AMT 16 set up by hand in
admin control mode without user consent (see [Limits](#limits) for what exactly). Add a PC like
a KVM: type its address, with the engine's user name (`admin`, as it comes) and password, and
qKVM recognises it. *Find KVMs on my network* finds such PCs as well.

What a PC's tile gives:

- Whether it is **on, off, sleeping or hibernating**, as the engine reports it. A PC that is
  off is there, and dark, as a server that is off is; one asleep is shown as on.
- **What the PC is:** make, model and serial number, processor and memory, the BIOS version,
  the AMT firmware version, and the name the engine has for it (the tile's name, unless you
  give it one). The tile says *PC with Intel AMT* where a server's says *Server*.
- **Its screen**, through the engine's KVM, where the PC was set up in admin control mode with
  user consent off, and its KVM is switched on: on the tile, enlarged, and on the
  [live line](#live-view-and-control), where **Control** sends its keys and the pointer. *Send
  keys*, *Type text* and the saved actions that press keys work as for a KVM. Where its screen
  cannot be had, the tile says why, in plain words: the KVM is switched off (on the engine, or
  in the MEBx), the PC is vPro Essentials (no KVM), or a session needs the code the PC shows on
  its own screen (client control mode always asks for one; admin control mode does where
  consent is on), which a wall cannot type. No session is opened then, not even to find out:
  the code would appear on the PC's screen for nothing.
- **Whether its KVM could be used**, and the **control mode** the PC was set up in, client or
  admin, as the tile's enlarged view says.
- **The power buttons.** *Power on*, and *Shut down*, which asks the operating system (that
  needs Intel's management service in the operating system; where the engine does not offer
  an orderly shutdown, the button says so and does not pull the plug instead); *Hold power
  button* cuts the power; *Press reset button* resets a PC that is on (one that is off is
  sent nothing, and the button says so, as for a guest of Proxmox). *Start into BIOS setup*
  arms the PC's firmware setup for its next boot (once) and then switches it on, or resets it
  if it is on, so it comes up straight in its BIOS setup; its large view opens so the setup
  screen shows from the start, and a session is opened before the press when that view is open
  (see below). A PC that is already on,
  or already off, is left as it is and says so, as a server is. Done means seen: after switching on or
  cutting the power, qKVM waits to see the PC in its new state, and says so if it does not.
  On the real machine: switched on, it was seen on after 2 to 13 seconds (its engine answers
  slowly while the PC starts); its power cut, the screen went dark at once and the engine said
  "off" after 12 to 15 seconds. A shutdown is done once the engine has taken it: Windows then
  says "You're about to be signed out" for a minute and shuts down, and the tile says *Off*
  about 80 seconds after the click. A reset is done once the engine has taken it too: the PC's
  power does not change, so there is nothing to see it by.
- **No power cut while a KVM session is open.** The engine neither offers cutting the power
  (nor a power cycle) while somebody has its KVM or its serial console open, nor does it when
  asked, and lists it again about a second after the session ended. qKVM closes its own session
  for *Hold power button*, waits up to five seconds for the engine to offer the cut again, and
  opens no session until the PC is seen off; another viewer's session (Intel's own tools, say)
  it cannot close, and the button says why nothing was done. A PC that went off meanwhile is
  sent nothing. A command whose answer did not come back, or came back as something that cannot
  be read (no `ReturnValue`, or no SOAP at all), is said to have perhaps been done, as for every
  device: look at the PC before pressing again. Only a SOAP fault, a refusing `ReturnValue` or an
  answer of the 4xx kind says that it was not done.
- **The PC it was added for, and no other.** Over plain HTTP, or with its certificate not
  checked, nothing else tells one engine from another, and PCs set up alike often have one
  password and one Digest realm: after a new lease another PC may answer at a tile's address.
  qKVM remembers the number the PC gives for itself (its PlatformGUID) when it is added, and
  keeps it in an export file. Before every power command and before switching its KVM it asks
  for the number again, and sends the command, and reads what the command is decided by (its
  power, its KVM's settings), only under the nonce that answer came under: an engine takes
  only nonces it handed out, so what takes the command is the PC that was asked. Where the
  engine hands out another nonce meanwhile, or says no, it is asked again (three times at the
  most, then the button says that nothing was done). No look runs in between. Before each
  session to its screen it asks again as well. A look reads the number every ten minutes, and
  at once where the engine answers in another realm. Where another PC answers, or one that
  names no number, nothing is done to it (no power command, no key, no session to its screen),
  and the tile says so from the moment that is seen (a look, a button, the screen) until this
  PC answers there again. If it is the PC this tile is for now (its board was changed, say),
  edit the tile and type its password. A tile with no number yet (added while its PC could not
  be reached, or from a file without it) takes the first one it sees, as a certificate is
  remembered on first contact. An account that may not read the hardware asset information
  gets no number, nor does an engine that cannot say it; such a PC is not told apart this way,
  and works as before. That an engine takes only its own nonces is how Digest is meant to
  work, and was tried on a real engine (see [Limits](#limits)).
- **Start into BIOS setup.** *Start into BIOS setup* arms the firmware setup for the next boot,
  once (Intel's `AMT_BootSettingData` with `BIOSSetup`, made the next boot by
  `CIM_BootService.SetBootConfigRole` as a single use, with every other boot option set to its
  own safe value so nothing another tool left pending is carried out), then switches the PC on
  where it is off, or resets it where it is on, so it comes up in its BIOS setup. The question
  before it names the PC and says whether it will be switched on or reset. Where a boot option
  that destroys data (a secure erase) is already armed, qKVM does nothing (it neither clears it
  nor carries it out) and says so. The setup boot is single use: it clears at the next boot
  whether or not qKVM boots it; and where it could not be armed in full, or the power change
  is refused for certain (a refusal, or a SOAP fault), qKVM clears it again, so no ordinary boot
  lands in the setup (it reads first, and does not write over a boot option that destroys data
  which another tool armed by then: that is said instead; a setup boot armed already before the
  press is left as it was, and said). Where the power change's answer is lost or cannot be read,
  or a PC switched on is not seen to come on, the boot is left armed and the button says so;
  a reset the engine takes is not seen done, and the boot stays armed until the PC boots. A
  PC that is changing its power state just then is left alone. A press that has not come to its
  power change within two minutes (as over Redfish) sends nothing more and clears what it armed;
  nothing under way is cut off for that. An operator or an admin may press it;
  it is written in the activity log; it is for one machine at a time, not a bulk run (it opens
  the machine's large view to show the setup screen). A PC whose engine says it cannot do it
  (`AMT_BootCapabilities`) is not offered the button.
- **Consent is read at most every five minutes.** How the KVM is set up (its control mode,
  whether user consent is on, whether it is switched on) is read afresh at most every five
  minutes. The engine enforces consent itself, so where consent was switched on since the last
  look, at most a few short sessions are begun (which the engine refuses, or shows its code for)
  until the next look re-reads it and no more are.

**The screen, as the engine gives it.** The KVM is reached on the engine's redirection port
(16995 with TLS beside 16993, 16994 beside 16992), with the same account and password, a Digest
sign-in of Intel's own, and the certificate qKVM remembered on 16993 (the engine shows the same
one on both). Then the engine speaks RFB, as a VNC server does. qKVM knows the redirection port
only beside the engine's own ports: an engine reached at another port (forwarded by a gateway)
has its state and its power buttons on the tile, and the tile says that its screen needs the
engine's ports forwarded as they are. What a real engine was seen to do, and what qKVM does
about it:

- **A still now and then for a tile that is only shown; a held session only for the large or
  live view.** A tile that is only shown on the wall gets a still picture every five minutes,
  each one a short session: qKVM opens the KVM, takes one frame, and closes it, so Intel's
  border is on the PC's own monitor only for the few seconds that takes. Between stills the tile
  shows the cached picture and says how old it is. Only while the machine is enlarged, or its
  live view is open, does qKVM hold a session open and ask it for what changed at a viewer's
  pace. A still is also taken at once when the tile first appears and after a power change is
  seen. While another viewer (Intel's tools, say) has the KVM, the engine refuses a session,
  and the tile says so; qKVM asks again every fifteen seconds (asking costs the engine nothing).
  A still that gives up waiting for its session (a slow engine: some forty seconds) closes the
  session it began, or, where its sign-in is on its way just then, closes it the moment it is
  open: it is not left open, and held, for a picture nobody takes.
- **The PC's own monitor shows a red and yellow border** around the whole screen while a
  session is open: Intel AMT draws it there, and it is not in the picture the engine sends.
  So the border is on the PC only while somebody watches it close up (the large or live view),
  and for the few seconds each still takes, not for a tile that merely sits on the wall.
- **The first picture takes seconds.** The engine takes only 16-bit colour, sent as raw pixels
  at about 1.5 MB/s: a whole screen of 2560 by 1440 came in about five seconds; after it, only
  what changes is sent, which is quick. (Offered the packed encoding it has, the engine packed
  one rectangle in thirteen and the whole screen came no sooner, so qKVM does not ask for it.)
- **The engine ends a session at its own time** (its `SessionTimeout`, three minutes on that
  machine, whatever was asked meanwhile). qKVM opens the next one at once, and the tile keeps
  its last picture for the seconds that takes.
- **Keys sent in the first moments of a session are dropped by the engine**, so qKVM waits half
  a second after the handshake before it sends any.
- **While the PC starts, its engine is too busy for a new session**: on the real machine none
  was opened in time until 27 to 37 seconds after switching on, about when Windows began to
  load, and the tile says that the PC is starting. A session that is open when the PC is
  switched on, or reset, goes on through the start and shows it: the BIOS's "Waiting Up to 8
  Minutes For KVM FW" (it waits a few seconds for the KVM when a session is open), the maker's
  logo, Windows loading. The engine opens a session for a PC that is off as well (a black screen
  of 800 by 600); qKVM opens none for a tile that is only shown then.
- **Showing the start.** Because a session opened after *Power on* (or *Start into BIOS setup*)
  mostly does not get through until Windows loads, while one open before the press shows the
  whole start, qKVM opens a session before switching the PC on when the machine's large view or
  its live view is open (where its screen may otherwise be had; the page says so with the
  press, as it asks nothing of a PC that is off), and the press waits for that session: the
  setup or boot shows from the first moment. For a tile that is only shown, the press does not
  wait on a session, and Intel's border is not drawn on the PC for a start nobody is watching.
  A session held for the large or live view is let go of a minute after the view closes.

**The serial console (Serial over LAN)** is not on the wall yet. qKVM has a reader for it: the
same port and sign-in as the KVM, read only (nothing is ever sent to the PC), what the PC writes
kept in a bounded buffer, a ping every two seconds that the engine answers, and the console ended
as the engine expects. On the real machine it opened, stayed open and was ended as it should be,
and the PC wrote nothing there worth showing: nothing while Windows ran or started (Windows writes
to it only where its Emergency Management Services are switched on), and, started into its BIOS
setup with Serial over LAN asked for, a graphical BIOS sent the codes that clear a terminal and
nothing else. So nothing shows it until a PC that writes text there is at hand. While a serial
console is open, the engine does not cut the power either.

What the owner of such a PC sets up, and what qKVM does with it:

- **Intel AMT is switched on in the MEBx** (Ctrl+P at boot, or the BIOS setup): a password
  for it, network access, and the engine's host name. There are two ways of setting a PC up,
  and the engine remembers which: **client control mode** comes from a tool run inside the
  operating system (host-based setup) and makes user consent mandatory for every KVM session;
  **admin control mode** comes from the MEBx, a USB setup file or remote configuration with a
  certificate, and lets consent be switched off. Power and state need no consent either way.
  **For its screen on a wall, set the PC up in the MEBx** (that is admin control mode) and
  switch *User Consent* to *None* there. A wall cannot type the code a session asks for, and
  in client control mode every session after two minutes without one asks for a new code.
- **Its KVM switched on.** In the MEBx, *KVM* is on as it comes; on the engine itself a PC
  set up by hand comes with its KVM and its redirection listener off. An admin can switch both
  on from the tile (enlarged: *Switch on its KVM*), which says first what that changes (the
  listener serves the engine's serial console and remote storage as well), and the KVM off again
  under *Actions*, which leaves the listener as it is; both are written in the activity log. It is a setting of the PC's,
  kept by its engine, and qKVM never changes it by itself. Intel's own tools switch it as well.
  Where the MEBx has it off, only somebody at the PC can switch it on.
- **Two ports.** The engine listens on 16993 with TLS and on 16992 plain. qKVM asks both and
  takes TLS wherever the engine offers it; its certificate (the engine's own) is remembered on
  first contact, as a KVM's is. Intel has deprecated the plain port and refuses it from the
  network on newer platforms (from the CSME 16.1 firmware of 2022 on; CSME 19 is TLS only).
  Where nothing listens on 16993 and the plain port answers, the PC is added that way and the
  list of what was added says so, as does the tile. Where something on 16993 takes the
  connection and does not answer as an engine (no answer in time, or a TLS handshake that
  fails: an old engine, or one busy while its PC starts), nothing is added and qKVM says so;
  an address typed with `https://` is never answered the plain way. Type the port yourself to
  settle it (`http://192.168.1.60:16992`). *Find KVMs on my network* goes by the same rule: it
  lists a PC at its plain address only where nothing listens on 16993, at its TLS address where
  something there is slow or fails the handshake, and not at all where something else answers
  there. Added with the kind `amt` through the API and no port, the engine is at its own port
  (16993, or 16992 for `http://`), not at 443 or 80.
- **The sign-in is HTTP Digest**, as the engine wants it, on both ports: the password itself
  never travels, a hash made with a nonce from the engine does, and it is only ever sent to
  the address the password was saved for, after the engine has asked for it. Over the plain
  port a weak password can still be guessed from what travels by whoever listens on the
  network, which is one more reason for 16993. A password the engine refuses, on either port,
  is left alone as every device's is (see [Servers](#servers)): a minute, five, a quarter of an
  hour, then hourly. Intel AMT locks an account after a few wrong passwords.
- **The account decides what works.** The engine's `admin` account can do everything here. An
  account of your own needs the realms for remote control (the power buttons), the hardware
  asset information and the general settings (the name), and for the screen the redirection
  realm (an account other than `admin` was not tried); whatever it may not read is shown as
  not said.

## VNC servers

Any machine that runs a VNC server can be on the wall: a virtual machine whose hypervisor shows
its screen that way (QEMU, libvirt and Unraid, by the port they give each guest: see
[Proxmox and virtual machines](#proxmox-and-virtual-machines); a guest of Proxmox has a kind of its
own), a desktop with TigerVNC, TightVNC, RealVNC or x11vnc on it, a management controller whose own
VNC server is switched on. Choose *VNC servers* in *Add KVMs*, type the address with its port after a
colon where it is not 5900 (`192.168.1.20:5901`), and the VNC password; or type
`vnc://192.168.1.20:5901` with *KVMs and servers* chosen, which says the same. The tile is named
after the name the server gives itself. *Find KVMs on my network* lists what greets as a VNC
server on ports 5900 and 5901.

What works, and how:

- **The picture.** qKVM speaks RFB (RFC 6143), the protocol of VNC, in Python: versions 3.3, 3.7
  and 3.8; the Raw, CopyRect, Hextile, ZRLE and Tight encodings, JPEG within Tight included
  (OpenBMC's console sends that); a screen that changes its size. It asks for one pixel format of
  its own choosing and never leaves that to the server. It stays connected for as long as the
  machine is on the wall, as a viewer that shares the server with whoever else is connected, and
  asks for what changed every quarter of a second while somebody looks at the wall, every ten
  seconds while nobody does. A server that pushes frames at its own pace (obmc-ikvm does) is read
  all the same, and what it pushes while nobody looks is let go of without being decoded. The
  screen is kept as three bytes a pixel: a 1920 by 1080 screen takes 6 MB, and a screen wider or
  taller than 8192 pixels, or of more than 16 million pixels in all, is not shown.
- **Keys and text** from the action menu go as X11 keysyms, which is what the protocol has: the
  server's own keyboard layout turns them into keys. A key combination is pressed in order and let
  go of in the other. Typed text is sent character by character, each as the keysym of that
  character (Latin-1 characters as themselves, others as Unicode keysyms); what the machine makes
  of a character its layout has not got is the server's business. Ctrl+Alt+Del is a chord like any
  other.
- **The password** goes the way VNC authentication has it: the server's challenge encrypted with
  DES under a key made of the password's first eight characters (the rest is not looked at, by any
  server). That is weak, as RFC 6143 itself says: anybody who can read the line can take the
  challenge and the answer away and try passwords against them at leisure, and the pictures and
  keys that follow are in the clear. Keep VNC servers on a network you trust or behind a tunnel,
  and give the wall a VNC password that is used for nothing else. Over plain `vnc://` the answer
  to the challenge goes to whatever answers at that address, since the protocol gives the wall no
  way to tell the server from an impostor. Where a server speaks TLS from the first byte (some
  management controllers do), type `vncs://`: the certificate is remembered on first contact, as
  for every device, and nothing is sent to what shows another. VeNCrypt, which puts TLS inside the protocol, is not spoken
  yet; a server that offers only that, or another way of signing in that qKVM does not speak, is
  said to on its tile. A server that asks for no password (security type None) is added with the
  password left empty.
- **A rejected password is left alone**, on the same ladder as a KVM's (a minute, five, fifteen,
  then an hour), and while it waits the server is still asked whether it is there, by its greeting
  alone (inside TLS at a `vncs://` address). VNC servers shut an address out after a few wrong
  passwords, for you as well.
- **A VNC server has no number of its own**: it is known by its address and by the name it gives
  itself, and a machine added under two addresses is two tiles.
- **What a VNC server cannot do from here:** there is no power button, no reboot, no Wake-on-LAN
  list, no keep-awake; the action menu offers them until it knows better, and each answers that a
  VNC server cannot do that. There is no *Open console* either, since a VNC server has no page of
  its own; a console link typed into the tile (the hypervisor's page, say) is used as it is.
- **What a server sends is not believed.** Every length is checked against the screen the server
  announced before room is taken for it; a rectangle outside the screen, a stream that inflates
  past what its rectangle can hold, a message of a kind qKVM does not read, floods and stalls end
  the connection with a named reason on the tile, and the server is left alone for a while: one
  that sent what qKVM does not take for fifteen seconds, then twice as long each time it does so
  again, four minutes at the most, until a connection to it goes well. One that lets qKVM in and
  hangs up, at once or after a frame, is connected to as one that is down is: a second later, then
  twice as long each time, a quarter of a minute at the most. A connection that drew a frame and
  is found there five seconds after it began (on a still screen, at its next answer, within a
  minute) is the server there again, so one that ends every connection after a time of its own,
  of some seconds or more, is connected to again each time. What its pictures cost to
  draw is shared out, since a few kilobytes can cost seconds of drawing: every server's pictures
  are drawn in the same two threads, a few milliseconds at a time, one server's in half of a
  thread's time at the most and every server's together in three quarters (each may take a second's
  worth at once). A server whose pictures cost much to draw is shown more slowly, and the others,
  and the rest of qKVM, go on: their pictures wait a few milliseconds at a time behind its own, some
  tens where a JPEG or a stream of a large screen is decoded in one go.

VNC support was typed from RFC 6143 and from TightVNC's description of its encoding, and tried
against a stand-in server written for the purpose, which speaks every version, both ways of
signing in and every encoding above, and misbehaves in the ways tested. A test against real
servers (TigerVNC's `Xvnc` and QEMU's built-in server) is written for the automated tests on
GitHub, where the two are installed for that job alone; it had not run when this was written, and
no real VNC server has been tried yet: see [Limits](#limits).

An iDRAC's own VNC server (iDRAC Enterprise, port 5901 where it is switched on in the iDRAC, with the
VNC password set there) is a VNC server like any other: type `vncs://` where its SSL encryption is
on. That was built from Dell's documentation and has not been tried: whether that encryption is TLS
from the first byte, as `vncs://` speaks it, has not been seen.

## Proxmox and virtual machines

A virtual machine on Proxmox VE is a tile of its own: its screen, whether it runs, and its power
buttons, all through Proxmox's own API with an API token. Nothing is installed in the guest or on
the Proxmox host.

**The token.** In Proxmox (*Datacenter > Permissions*):

1. A user for the wall, `wall@pve` say (realm *Proxmox VE authentication server*; it needs no
   password of its own).
2. A role with `VM.Audit` (to see the guests and whether they run), `VM.Console` (their screens and
   keys) and `VM.PowerMgmt` (the power buttons; leave it out for a wall that only looks).
3. A pool with the guests the wall is to show, and the role given on the pool (*Permissions > Add*,
   path `/pool/<name>`).
4. An API token for the user (*API Tokens > Add*). With *Privilege Separation* on, as it comes, the
   token has only what is given to the token itself: give it the role on the pool as well. Its
   secret is shown once.

Then choose *Virtual machines on Proxmox VE* in *Add KVMs*, type the host's address (`192.168.1.5`,
its port after a colon where it is not 8006), the token's ID (`wall@pve!wall`) where the user name
goes and its secret as the password. The virtual machines the token may see are listed with their
number, name, node and whether they run; tick the ones to put on the wall. To add one at once, put
its number after the address (`192.168.1.5/100`), or paste the address Proxmox's own page shows for
it. The tile is named after the guest. Containers are not listed (see below).

What a guest's tile gives:

- **Whether it runs**, is paused or is stopped, asked of Proxmox every five seconds (a question
  Proxmox writes down nowhere). A stopped guest is there, and dark, as a server that is off is.
- **Its screen**, while it runs: on the tile, enlarged, and on the [live line](#live-view-and-control),
  where **Control** sends its keys and the pointer. *Send keys*, *Type text* and the saved actions
  that press keys work as for a KVM; typed text goes as each character's keysym, as to a
  [VNC server](#vnc-servers), and the guest's own keyboard layout decides.
- **The power buttons**: *Power on* (Proxmox's start), *Shut down* (its shutdown: the guest is asked,
  through ACPI or its agent), *Hold power button* (its stop: the plug pulled), *Press reset button*
  (its reset). What is so already is left as it is and says so, as for a server, and switching on
  and stopping are waited for until they are seen: while Proxmox's task for the command runs, or
  its high availability carries the command out, up to a minute, and then the button says that it
  is still under way (it may yet be done), not that it failed; a task that ends in an error is said
  at once, in Proxmox's words. A guest with nothing in it that hears a request to shut down goes on
  running; the tile shows it, and *Hold power button* stops it.
- **Open console** leads to the guest's console on Proxmox's own page (signed in there, as yourself).

**The screen, and what it costs Proxmox.** Proxmox has no picture of a guest to hand out. The screen
is in the console Proxmox's own page opens: qKVM asks for a ticket (`vncproxy`), opens the WebSocket
that ticket is for (`vncwebsocket`) and reads the protocol of VNC over it, with the password that
came with the ticket. What was measured on Proxmox VE 9.2, and what qKVM does about it:

- **Every console opened is a task in the node's task log**, which its owner reads. So qKVM holds
  one console per guest while somebody looks at its tile, and lets go of it five minutes after
  nobody does; it opens another only where one ended. A stopped guest is asked for none. A console
  that fails is asked for again after 15 seconds, then after a minute, 5, 15 and 30 minutes. **What
  a tile costs in tasks:** none while nobody looks at it; one each time somebody begins to look
  after five minutes or more without; a tile on a screen that shows the wall all day, one a day,
  and one more each time the guest is started or qKVM restarted. A console held for four hours was
  not ended by Proxmox.
- **Each console held costs the host** two processes and about 120 MB of its memory, and little
  processor time: twenty guests' consoles held at once, each looked at once a second, took 2.4 GB
  of the host's memory and under a third of one of its cores (Alpine Linux at its login prompt, a
  blinking cursor). Holding a console instead of opening one for every picture is what keeps the
  task log readable; letting go of it a minute after the last look is what keeps that memory free
  for the guests while nobody looks.
- The **first picture** comes about a second after a tile is first looked at. Nineteen asked for at
  once came within 7.2 seconds, half of them within 6.2: Proxmox starts each console's processes as
  it is asked.
- **On the wall's side** a guest whose tile is looked at costs what a server's screen does: about
  5 % of one core of the computer qKVM runs on, most of it making a JPEG of its screen once a second.
- The ticket is used at once, and once: Proxmox waits ten seconds for its one connection, and gives
  no answer at all to a second use, so qKVM gives up on an upgrade that is not answered within eight
  seconds. The password that comes with it expires half a minute after the connection. Neither is
  written down or logged, and neither is kept beyond the connection it opened.
- **A console that fails** (a guest that gives a picture and ends, a console that lets qKVM in and
  answers nothing, a moment of Proxmox's own such as an answer of HTTP 500) is not opened again at
  every picture, key or move of the pointer: a live viewer waits out the same pause as the tile, and
  after three failures in a row the live line ends and the tile says why there is no screen. A
  console Proxmox will not open (403), or that turns qKVM away, is left alone as a refusal, and a
  live line ends at once. A console that served for a while and ended (Proxmox ended it) is opened
  again at once; the next one that ends before it has served four minutes is one more failure, on
  the same ladder (a proxy in front that cuts every connection after a minute costs a console every
  half hour, not every minute). A console that serves a while and then hangs, or sends what qKVM
  does not take, climbs the same ladder, and so does one that lets qKVM in and sends that at once. A
  console that ended because Proxmox started the guest again (its uptime began again just after) is
  no failure, once a minute at most, and an hour after the last failure what failed before is
  forgotten. A guest a Proxmox reports stopped, and then running, by turns has a console opened for
  it at most once every five minutes beside its own ladder, where a guest truly stopped and started
  again has one opened at once: a Proxmox that lies about it that way costs its own task log a
  console every five minutes, no more. A still screen is
  asked for one dot every 25 seconds, so that a proxy in front of Proxmox does not take its quiet
  console for a dead one. How it was paced outlives the wall locking itself and being opened again;
  saving the tile again, or typing its token again, starts afresh.
- The token goes in the `Authorization` header of every request and of the console's upgrade, to
  the Proxmox it was saved for and nowhere else; never into an address, never into the log. Where
  Proxmox, or a proxy before it, says it back in an error, it is cut out of those words before they
  go to the log or the tile; said back in another spelling (split, without its dashes, encoded), none
  of those words are kept, and the tile says that Proxmox's words held the token.

A few things are worth knowing:

- **The token decides what works.** Without `VM.Console` there is no screen, and the tile says so in
  Proxmox's words; without `VM.PowerMgmt` the power buttons answer what Proxmox says. A token without
  `Pool.Audit` cannot list pools, and need not: the guests it may see are listed all the same.
- **A wrong token is left alone**, as every password is (a minute, five, a quarter of an hour, then
  hourly), and for every guest of that Proxmox together. Proxmox holds back each answer to a wrong one
  for three seconds.
- **A guest moved to another node** of its cluster is followed, without anything to do, once the
  virtual machine with its number there is found to be the guest itself (below).
- **Its certificate** is remembered on first contact, as for every device: the node's own. Every
  guest of one Proxmox shows the same, so a guest is known by the number it gives for itself (its
  SMBIOS UUID, which a clone is given anew): one guest added under two addresses of its Proxmox is
  noticed, two guests are two.
- **The guest it was added for, and no other.** Proxmox gives a new virtual machine the lowest
  number that is free, so a guest that is deleted, and another made after it (on its node or on
  another), leaves its number to the new one. qKVM remembers the SMBIOS UUID the guest gives when
  it is added, and keeps it in an export file. It asks for it again before every power button,
  before each console it opens (the screen, and the keys and text that go through it), and before
  it follows the guest to another node; a look asks once a minute, and at once where it finds the
  guest stopped where it ran, running where it was stopped, or started again. Where another
  virtual machine has the number, or one that gives no UUID, nothing is done to it (no power
  button, no key, no console), and the tile says so from the moment that is seen until the guest
  has its number again. If it is the guest the tile is for now, edit the tile and type its token's
  secret. A tile
  with no UUID yet (taken from a file without one, or saved while its Proxmox could not be reached)
  takes the first one it sees, as a certificate is remembered on first contact. A guest whose
  settings carry no SMBIOS UUID (Proxmox gives every new one a UUID; it can be taken out by hand)
  is not told apart this way, and works as before.
- **The tile and the live line share one console**, and so does somebody at Proxmox's own console
  page: the wall shares the guest's VNC server, and pushes nobody out of it.
- **Containers** (LXC) are not shown yet: their console is a terminal of Proxmox's own. The list says
  how many it left out.

**libvirt, QEMU and Unraid guests** are plain VNC servers: add them as [VNC servers](#vnc-servers).
Their port and password are in the guest's definition: for libvirt, `virsh vncdisplay <guest>` says
the display (`:0` is port 5900, `:1` is 5901), and the `<graphics type='vnc' ...>` line of
`virsh dumpxml <guest>` has its `port`, where it listens (`listen`, 127.0.0.1 as it comes: let it
listen where the wall can reach it, or tunnel) and its password (`passwd`, which `virsh dumpxml
--security-info` shows). Give the guest a fixed `port` (`autoport='no'`): one given out in turn may
be another guest's after a restart. Unraid's virtual machines are libvirt guests: the *XML view* of
a VM's settings has the same line, and its *VNC Password* is that `passwd`.

**XCP-ng** (and Citrix Hypervisor) is not on the wall yet: its consoles speak VNC's protocol behind an
HTTP request of their own, with a session; that door is not built.

## How it is protected

- **No account's password is stored.** Each account's password derives (scrypt) a key that
  unlocks the one key every saved KVM password is encrypted with (AES-256-GCM).
- **The saved KVM passwords are as safe as the data folder.** So that qKVM carries on by
  itself after a restart, a key that opens them without anybody's password lies in that
  folder too (`unlock.key`). Say it plainly: **someone who copies the data folder has the
  saved KVM passwords**, and with them the texts saved to be typed, every account's
  authenticator key and the address alerts go to. They have no account's password, and they
  are not signed in to anything. Keep the folder, and every backup of it, as you would keep
  those passwords.
  (Where qKVM makes the folder itself, on Linux and macOS it is readable by its owner only.)
  There are two ways to have it otherwise, both under
  [Keeping it running](#keeping-it-running): `--unlock-file` keeps that key where the
  folder's backups do not go, and `--locked-start` keeps none. With `--locked-start` a copy
  of the data folder is worth nothing without an account's password (any account's, a
  viewer's included, so give every account a good one), and after every restart qKVM
  reaches no KVM until someone signs in.
- **Forgotten password:** *Forgot your password?* on the sign-in page lists the ways back in.
  - *The recovery key* sets a new password for any account and keeps everything else as it
    was. It is shown once when qKVM is set up; an admin can make a new one under
    *Settings > Security*, which cancels the old one. Only a locked copy is stored. Whoever
    holds it can take over any account, so keep it like a password, and not on the computer
    qKVM runs on. It replaces the password only: an account with two-factor sign-in still
    needs its code.
  - *Another admin* can set a new password for you under *Settings > Accounts*.
  - *Starting over:* with neither, `qkvm --reset-password` forgets every account
    and the recovery key, so the first account can be created again. The saved KVM passwords
    were encrypted for those accounts, so they are erased and must be entered again; the
    list of KVMs and the other settings stay.
- **Sign-in** uses an HttpOnly, SameSite=Strict session cookie. Repeated wrong passwords lock
  the address they come from out for 30 seconds, doubling up to 15 minutes. Signing in to one
  account does not forgive guesses made at another, and the addresses of one IPv6 network
  count as one.
- **HTTPS from the first request:** started with `--https`, qKVM never serves plain HTTP,
  not even for the first-run setup, and the box in the settings cannot switch it off. With
  `--tls-cert` and `--tls-key` it uses a certificate of your own (from your company's
  authority, say) instead of the one it makes: the files are checked at start, and read
  again at every restart of the listeners, so a renewed certificate is picked up by a restart.
- **Only from where you say:** with `--allow-from` and a list of addresses or networks
  (`--allow-from 192.168.1.0/24,100.64.0.0/10`), qKVM answers those and the computer it runs
  on, and turns everybody else away before there is a sign-in page to guess at. Behind a
  named proxy it is the visitor's address that counts. Given without an address (an empty
  variable in a compose file), the option is an error at start and not "everybody".
- **Behind a reverse proxy,** start qKVM with `--trusted-proxy` and the proxy's address or
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
- **First-run setup takes a password and nothing else**, so a new qKVM belongs to whoever
  opens it first: choose the password right after starting it. Started with `--setup-code`,
  qKVM asks whoever sets it up from another machine for a code printed in its terminal (or
  its log: `journalctl -u qkvm`, `docker logs qkvm`), so that nobody on the network can
  claim a copy you just started. Use it where others can reach the port before you do.
- **Each KVM's certificate is remembered** the first time qKVM talks to it (like an SSH host
  key). If something else answers at that address later with another certificate, qKVM refuses
  to send it the password and the tile says so; *Settings > KVMs > Edit > Review certificate*
  shows both fingerprints. A server's controller may show the certificate its maker put on
  every board: a server is told apart by the numbers it gives for itself instead, before the
  password goes to it where its controller gives one (see [Servers](#servers)), and a PC with
  Intel AMT by its PlatformGUID (see [Intel AMT](#intel-amt)).
  A tile moved to another address takes its saved password along only where the device
  there shows that same certificate; anywhere else, and always for a server's controller
  (whose maker may have put one certificate on every board) and for a guest of Proxmox
  (whose certificate is its Proxmox's, or a proxy's, or a wildcard other hosts show too),
  the password or API token is typed again.
- **Give qKVM a host name or address of its own.** A browser keeps what signs it in by host
  name, not by port. Where a device's own page is reached on another port of the name qKVM
  is looked at under (a router that forwards two ports of one name, tunnels to `localhost`),
  the browser would hand that page your sign-in to qKVM, and a device is not trusted with
  that. The wall offers no *Open console* link to such a device and says why.
- **HTTPS** for qKVM itself is one checkbox (a certificate is made on this computer; its
  fingerprint is shown so you can check the browser's warning). Turn it on whenever qKVM
  listens on the local network. Tailscale already encrypts its traffic.
- Every change must come from qKVM's own page (cross-site requests are refused), the page
  runs under a strict Content-Security-Policy, and requests for unknown host names are rejected.
- **Nobody holds a connection for nothing.** One that has not sent a whole request within 20
  seconds is closed, a request's body gets the same, one that asks and then takes nothing of
  the answer for 20 seconds is dropped, and there is nothing in qKVM that is spoken to over a
  websocket. Wrong passwords are checked two at a time at most, so that
  guessing cannot use up the computer's memory.
- **A KVM is not trusted either.** What a device sends is read only up to a limit, only JPEG
  and PNG data of a sane size is passed on to a browser as a picture, and what a device says
  about itself (name, model, numbers) is reduced to plain short text or a number before it is
  shown or logged. A device cannot send qKVM on to another address, and qKVM talks to it
  directly whatever proxy the computer is set to use for the web (that one is used for
  alerts and for update checks). A broken or taken-over KVM can show a wrong picture; it
  cannot fill the memory of the computer qKVM runs on, or of the browser looking at it, or
  put a page of its own in your browser. One part of that is not qKVM's own to promise: a
  JetKVM's video and its control channel come through a WebRTC library (aiortc), and what a
  taken-over JetKVM could make that library hold or compute has not been measured.
- **The activity log** (*Settings > Activity*) keeps 100 MB, which is more than a year of a
  busy wall, in files of JSON lines in the data folder that are its record, never rewritten:
  one entry a line, with the time, what happened, the address it came from, the account, and
  what it concerned. Where it cannot be written (a full disk), what is asked for is done all the
  same, a power button included, and the log says at its top how many entries are missing
  and since when. A log collector (Filebeat, Vector, Promtail) can follow it from there.
  Started with `--audit-syslog collector.example` (or `host:port`, or `tcp://host:port`),
  qKVM also sends each entry to a syslog collector as it is written (RFC 5424, the entry as
  JSON in the message), so that what was done is known somewhere whoever did it cannot
  reach. This transport is unencrypted UDP or TCP; use a protected local relay for TLS
  forwarding, or a protected management network. The file stays the record: an entry the collector was not there for is not sent
  again, and nothing in qKVM waits for the collector. The page searches it, narrows it to a
  machine, an account, a kind and a time, and downloads it; in the table, a name that begins
  like a spreadsheet formula is written as text. The chapter [Activity log](#activity-log) has
  all of it.
- What every account may look at on the wall is a tile's name, address and console link; how
  qKVM signs in to a device is shown to admins only.
- **Updates are installed only when signed** by the publisher's release key (see *Updates*).
- At start, qKVM says so if a library it runs on is older than the first version without a
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
- **Health check:** `GET /healthz` answers `{"status": "ok", "version": "...", "api": ["v1"], "page": "...", "locked": false}`
  without a login, for a monitor or a watchdog. (`"page"` is a mark of the page's own files: a
  browser tab left open across a restart compares it with its own, and fetches the page again
  when they differ.) `"locked": true` means qKVM cannot open the saved device passwords just
  now: it was started with `--locked-start` and nobody has signed in since, or it has not
  been signed in to once since it was set up or its key was changed. It is running, and
  until somebody signs in it cannot reach a single device, so nothing is watched and no
  alert is sent. Have whatever monitors qKVM tell you about it.
- **Carrying on after a restart:** qKVM opens the saved device passwords itself at start, and
  goes on watching, alerting and answering a collector without anybody signing in. A browser
  that signed in with *Keep this browser signed in for 30 days* stays signed in across the
  restart; any other is asked for its password again, as is every visitor: the key opens
  the saved passwords for the program, not the wall for whoever comes by. What makes it
  possible is a key in the data folder (`unlock.key`), made at the first start. The first
  sign-in makes it fit this data folder, and from the next start on it opens it.

  What it costs: the key lies beside what it opens, so whoever has a copy of the data folder
  has every saved device password. The two other ways:

  - `--unlock-file FILE` keeps the key in a file of your choosing, where the folder and its
    backups do not go: a systemd credential, a Docker secret, another disk. A copy of the
    data folder then lacks the automatic-unlock key, but an account password or recovery
    key can still decrypt its vault. qKVM makes the file if it is not there, refuses one that lies
    in the data folder, and says so when other users of the computer can read it (on Windows
    it cannot tell: keep the file in a folder that is yours alone).
  - `--locked-start` keeps no automatic-unlock key. The vault still opens with an account
    password or recovery key; metadata and logs remain readable without either.
    After every restart nothing is watched, no alert is sent and
    every browser signs in again, until a person has been by; a power cut is when that matters.

  Going from one way to another takes one start and one sign-in. What the key before opened
  the folder with is taken out at that start, so a copy of it that somebody kept opens
  nothing afterwards. That is true of the key, not of an older copy of the whole folder:
  the saved passwords are encrypted with one key for as long as the accounts exist, and a
  backup from the time a key lay in the folder holds that key and what it fits, and reads
  what was saved since. To cut older copies off, `--reset-password` and enter the device
  passwords again; and keep backups as you would keep those passwords.
- **Backup:** everything qKVM knows is in the data folder. Copy the folder; it is safe to do
  while qKVM runs (the settings file is replaced in one step, never written halfway; the
  [history](#history) is two files, `history.sqlite` and `history.sqlite-wal`, and a copy of
  both taken while qKVM runs may lack its last minute, which is no harm to it; the
  [activity log](#activity-log) is its `audit.log` files, and `audit.sqlite` beside them is an
  index that is made again from them, which a backup may leave out). To
  restore, or to move to another computer, put the folder there and start qKVM with it
  (`--data-dir`): accounts, devices and saved passwords are as they were, opened by the same
  account passwords. A copy holds the key that opens the saved device passwords, so keep it
  as you would keep those. (Not so with `--unlock-file` or `--locked-start`: then a copy is
  worth as much as the weakest account password it was made under.)
- **How large:** the largest wall run so far had 13 real KVMs for a night, and 44 stand-ins for
  an hour with a picture a second each: about 40 % of one processor core and 130 MB of memory,
  steady. Each tile that is being looked at costs the KVM one picture a second and qKVM
  little; a JetKVM costs more (see [JetKVM](#jetkvm)). Nothing is known yet about hundreds.
- **Settings file:** every change is written atomically, and a second copy of what was just
  saved is kept as `qkvm.bak` next to it. If `qkvm.json` is ever unreadable or gone (a hand edit
  gone wrong, a start that was cut off), qKVM starts from that copy, sets a damaged file aside
  and says so. The copy is of what was saved last, not of what was there before: nothing that
  was taken away (an account, a token, a password) comes back by it. A change that cannot be
  saved (a full disk) is refused and taken back, and the answer says so.
- **One copy per data folder:** a second `qkvm` pointed at the same folder refuses to start,
  so typing `qkvm` while it is running already does no harm.
- **After changing the program's files by hand, restart it.** The page is loaded into memory
  at start, so a browser always gets the page that matches the running server. (Updates
  installed from inside the app restart it for you.)
- **Start it with the system (Linux):** a systemd unit does it. With qKVM installed in an
  environment of its own (`python3 -m venv /opt/qkvm`, then
  `/opt/qkvm/bin/python -m pip install --upgrade pip` and
  `/opt/qkvm/bin/python -m pip install qkvm`),
  this as `/etc/systemd/system/qkvm.service`:

  ```
  [Unit]
  Description=qKVM
  After=network-online.target
  Wants=network-online.target

  [Service]
  ExecStart=/opt/qkvm/bin/qkvm --data-dir /var/lib/qkvm --https --setup-code
  DynamicUser=yes
  User=qkvm-web
  Group=qkvm-web
  StateDirectory=qkvm
  StateDirectoryMode=0700
  UMask=0077
  CapabilityBoundingSet=
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target
  ```

  and `systemctl enable --now qkvm`. It runs as a user of its own that can write to
  its private state directory at `/var/lib/qkvm` and private temporary files. The code
  asked for at the first-run setup is in `journalctl -u qkvm`. Use a service identity
  that is not an existing login account: `DynamicUser=yes` reuses an account if its
  name already exists, including that account's supplementary groups. Do not use an
  administrator or an account in `sudo`, `docker` or `lxd` for the web service.
  The unit above uses `qkvm-web`; choose another unused name if that is already an account.
  These restrictions allow ordinary outbound device connections and application updates;
  they do not provide access to host administration tools. An explicit TLS proxy setup
  may replace `--https`, while retaining the protected first-run setup.

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
  schtasks /Create /TN "qKVM" /SC ONLOGON /RL LIMITED /TR "pythonw -P -m qkvm"
  ```

  qKVM comes up watching; a browser shows screens once someone has signed in there. Started this way there is
  no terminal: what it would say there is in `qkvm.log` in the data folder (the setup code
  too, where it was started with `--setup-code`), and it is stopped with `qkvm stop` from
  any terminal.

## Updates

*Settings > Updates* shows the running version, checks GitHub for a newer release, shows its
notes and installs it. By default qKVM asks GitHub once a day and shows an **Update**
button in the top bar when there is something new; installing is always your click, and asks
for your password again.

- **What a check sends:** one request to GitHub's public API for the newest release. Nothing
  about your KVMs. Turn the daily check off in the same place if you'd rather not.
- **How an install works:** the release is downloaded, its signature and checksum are
  checked, and it is unpacked into `updates/<version>/` in the data folder, next to the running version.
  qKVM then restarts itself on it.
- **Only signed releases are installed.** The public half of the publisher's release key is
  built into the program, and a release that does not carry a valid signature is refused. A
  copy built without a release key tells you about new versions and leaves installing them
  to you, unless it is started with `--allow-unsigned-updates`, which accepts a release
  checked by its checksum alone.
- **If the new version won't start,** qKVM goes back to the previous one by itself.
  `qkvm --roll-back` does the same by hand.
- **It only replaces the program's own files.** The installed Python and libraries must meet
  the new release's requirements. If a package is missing or its version is incompatible,
  the app refuses the update and asks you to use `pip install --upgrade qkvm`. That works at
  any other time as well; qKVM runs whichever of the two is newer. An installed update checks
  these requirements again before opening the data folder.
- **A container is updated by replacing its image**, not from inside: the app tells you when
  there is a new one.

### From 0.1.x to 0.2.0, and back

**Up:** use `pip install --upgrade qkvm`, or replace the container image on the same volume,
and start with the same data folder. The first move from 0.1.x should use pip because the old
in-app updater checks whether libraries are present but not whether their versions meet the
new requirements. If it stages 0.2.0 with incompatible libraries, 0.2.0 refuses to start and
the starter rolls back; upgrade with pip before trying again.
Accounts with their second step and recovery key, tokens and display links, browsers kept
signed in, the KVMs and servers with their saved passwords and groups, the saved actions, the
alert settings and the wall's settings are as they were. At the first start the history
(`history.sqlite`) begins. The activity log's index (`audit.sqlite`) is made from the text
files 0.1.x wrote, and the log of qKVM says so, with how many entries: whatever those files
still hold is searched from the first day. (What was written before 0.2.0 names a machine and
gives no id: it is found by the name the machine has now.) The settings file gains a few
fields and loses none. The activity log's files are only written on, now ten of 10 MB where
they were ten of 2 MB.

**Back** to 0.1.1 works on the same data folder, with these to know first:

- **Take every VNC server, PC with Intel AMT and Proxmox guest off the wall before.** Export
  the wall with a passphrase first to bring them back later, with their passwords. They come
  back as new tiles: their history goes when they are removed, and what the activity log says
  of them stays under their old id.
- **A VNC server:** 0.1.1 does not start with one on the wall. It says that `qkvm.json`
  "cannot be read" and to "fix one of them, or move both aside to start over". Moving them
  aside leaves every account and device behind. Start 0.2.0 again instead (`pip install
  qkvm==0.2.0`, or the 0.2.0 image), and remove the server there.
- **A PC with Intel AMT, a Proxmox guest:** 0.1.1 takes them for KVMs. It sends their saved
  password, or API token, to them as a KVM's sign-in, in clear where the address is `http://`
  (an Intel AMT's port 16992). It does so for as long as the wall looks at them, which is all
  the time where alerts are on. Where the answer is neither yes nor no, within seconds at
  first, then every five minutes. After a no, a minute later, then after five and fifteen,
  then every hour. Each Proxmox guest is counted on its own.
- **How.** `pip install qkvm==0.1.1`, and where 0.2.0 came by *Install*, also `qkvm
  --roll-back` (with the wall's `--data-dir`): pip alone leaves the newer copy in the data
  folder running. Then restart qKVM. In a container, the image `qkvm/qkvm:0.1.1` on the same
  volume.
- **The activity log is kept as 0.1.1 keeps it:** ten files, the newest moved on at 2 MB.
  Once `audit.log.8` and `audit.log.9` are both there, `audit.log.9` goes as soon as the
  newest is past 2 MB (at 0.1.1's first entry, where 0.2.0 left it larger), and another at
  every 2 MB it writes. Copy the
  `audit.log` files first where the older entries matter.
- **What only 0.2.0 knows waits for it:** 0.1.1 neither reads nor changes `history.sqlite` and
  `audit.sqlite`, and keeps the fields it does not know in the settings file. Started again,
  0.2.0 brings the index up to what 0.1.1 wrote, and the history goes on (the time between
  counts as not watched).

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
3. To cut a release: the test run of the commit to be released is green in every job of
   `.github/workflows/tests.yml` (both systems, every Python, the page in a browser). Set
   `__version__` in `qkvm/_version.py`, write the version's chapter in `CHANGELOG.md`, commit,
   and create a GitHub release tagged `v<version>`. `.github/workflows/release.yml` then
   requires a successful Tests workflow for that exact commit, refuses a tag that does not
   match the version in the code, runs the test suite once more (on Linux, with one Python),
   and builds the wheel and source archive. It audits the installed wheel and builds, runs
   and scans both container architectures before signing or publishing anything. The same
   checked packages go to GitHub and PyPI, and the checked container archives are transferred
   to the registries without rebuilding them. The container policy blocks every Python
   advisory, every fixable OS advisory, every critical advisory, and high OS advisories
   without a current, exact, reviewed exception. Unfixed lower-severity OS findings remain
   visible in the retained report. The policy and temporary exceptions are described in
   [.github/security/README.md](.github/security/README.md). What the publishing accounts
   need set up once is written at the top of the workflow.
4. The project's sites (the documentation is this README, page by page) are built after the
   release, not before: their build refuses to go out while the version in `qkvm/_version.py`
   is not on PyPI yet, so that no page says `pip install qkvm` for a version nobody can have.

## Command line

```
qkvm                             # run it here, in this window, until it is stopped (Ctrl+C); `qkvm start` is the same
qkvm status                      # is a copy running with this data folder, since when, where does it listen, and how large are the history and the activity log
qkvm stop                        # end the copy that runs, from any window
qkvm restart                     # have it started again, where it runs
```

`status`, `stop` and `restart` are about the copy that already runs, whatever it was started
from: a window that has since been lost, or none at all (a task at log-on). They find it
also where it was started with `--data-dir`: qKVM notes such a folder in `.qkvm` in your home
folder (`elsewhere.json`) when it starts. With two walls running, or one that runs as another
user, say which: `qkvm stop --data-dir D:\qkvm-data`.

These three only look: they run nothing that lies in the folder they are asked about (not an
installed update either), make and change nothing in it, and take nothing a file in it says
at its word. `stop` and `restart` leave one small file there, which the running copy picks
up. That is also the whole of who may stop qKVM: **whoever can write to its data folder**,
and whoever can write there can put there what qKVM runs after an update as well. Keep the
folder writable by the account qKVM runs as and by nobody else; on Linux and macOS qKVM
says so at start when it is not, and on Windows it is for you to look (a folder under your
own profile is yours alone; one made elsewhere, on another drive say, often is not).

Stopping it this way is the same as Ctrl+C: connections are closed, the log says so.
`qkvm status` ends with status 0 when qKVM runs and 3 when it does not, for a script. Where
a service manager or Docker starts qKVM, stop and restart it there: they would only start it
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
qkvm --trusted-proxy 172.18.0.0/16   # a reverse proxy in front of qKVM (see How it is protected)
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

What has been tried, and how. There are three tiers: *tried on a real device*; *tried against
the maker's own emulator or capture* (a program or a recording the maker publishes of what
its controller answers, run on a developer's PC and on every push); *built from the standard*
or from published source, and tried on a stand-in laid out like it.

| Device | State |
|---|---|
| GL.iNet Comet (GL-RM1, GL-RM10), GLKVM firmware | Used daily on real devices: picture, status, actions. ATX board, heard on the KVM's line for events, and keyboard and mouse in the live view: tried on a real device (see below). A Fingerbot paired with it: tried on a real Comet with a Fingerbot on a desk, pressing nothing (see below) |
| GL.iNet Comet X (four ports) | Real device: picture, status, port switching |
| JetKVM | Real device: picture, status, sharing with its own page, restart, keys, typed text, saved actions, keep-awake, the live view with keyboard and mouse, over its `hidrpc` channel and over JSON-RPC; a key and a mouse button held as its own page takes the viewer and as a connection ends; the ATX extension's short press and its lights (see below); its long press and reset, Wake-on-LAN, a password, HTTPS, a firmware without `hidrpc` and typed text in a layout other than US only against a stand-in |
| Stock PiKVM, and other KVMs with PiKVM's `kvmd` interface | kvmd's own test environment, kvmd 4.226 with ustreamer 6.67 (a video loopback and the GPIO mockup in place of a Pi's capture and pins): sign-in, the tile, its picture, the status, keys, typed text, keep-awake, the power and reset buttons and the power light, the network search, the live line with its pictures and with kvmd-media's H.264, keyboard and mouse over it, the history: see below. No real PiKVM yet |
| Servers through Redfish, AMI MegaRAC controllers | Real boards of two makers: see below |
| Servers through Redfish, Dell iDRAC9 | Dell's own capture of an iDRAC9 (firmware 7.20.10.05, from `dell/iDRAC-Redfish-Scripting`), served by DMTF's Redfish-Mockup-Server 1.3.0: sign-in and out, status, temperatures and fans, the locator light, the power actions it offers; no real iDRAC yet |
| Servers through Redfish, HPE iLO 5 | HPE's own `ilo-redfish-emulator` v1.1.0 (an iLO 5 on a DL360 Gen10 Plus): the same, and the power actions carried out; no real iLO yet |
| Servers through Redfish, OpenBMC | Built from bmcweb's source (its names, the newer shape of the sensors, where its console is and the console `/kvm/0` itself, its firmware inventory) and tried on a stand-in laid out like it, the console's pictures included, and against OpenBMC's own romulus image in QEMU (a build of its master branch of October 2026) on a Linux machine: signing in, the controller and its firmware's version, the server's power, where its console is, and the console's sign-in with the session (refused without one); that image has no console, so no picture came from a real OpenBMC; the run in QEMU is written for every push and has not been seen on GitHub yet |
| Virtual machines on Proxmox VE | A real Proxmox VE 9.2 (a throwaway one, with Alpine Linux guests): the guests a token may see listed and added, a running guest's screen on the tile, enlarged and live, letters typed at its login prompt and taken back, a stopped guest switched on, asked to shut down (not heard: nothing in it answers ACPI) and stopped, twenty guests' consoles held at once, a guest deleted and another made under its number refused; a stand-in for what was not met there (a guest moved to another node, a token that lacks a right, Proxmox misbehaving). Containers are not shown |
| Virtual machines on libvirt, QEMU, Unraid | As VNC servers (above): a libvirt guest's console (libvirt 11.3, QEMU 10.0, no password) was looked at so, its name and its screen; Unraid's VM form was read in its documentation, not tried |
| An iDRAC's own VNC server | As a VNC server, `vncs://` where its encryption is on: built from Dell's documentation, not tried |
| XCP-ng, Citrix Hypervisor, VMware ESXi, Hyper-V | Not supported |
| Servers through Redfish, the standard itself | DMTF's own example (DSP2043 `public-rackmount1`, in Redfish-Mockup-Server 1.3.0), and sushy-tools 2.2.0, whose stand-in server really goes on and off a few seconds after it is told: on, shut down, power cut and reset, each seen to happen |
| Servers through Redfish, other controllers (Supermicro, Lenovo XCC and the rest) | Expected to work where they follow the standard; not tried, and no emulator or capture of theirs is published |
| Business PCs with Intel AMT (vPro Enterprise) | Experimental. One real machine (AMT 16, admin control mode, no consent): its state, power state, what it is and how it was set up; its KVM switched on and off from the wall; its screen on the tile, enlarged and live; keys, typed text and the pointer; every power button. Against a stand-in only: client control mode and consent, the plain port, the network search: see below |
| VNC servers (QEMU and libvirt guests, TigerVNC, TightVNC, RealVNC, x11vnc, a controller's own VNC server) | Built from RFC 6143 and tried against a stand-in only; the test against TigerVNC and QEMU on GitHub had not run yet; no real VNC server tried |
| Sipeed NanoKVM, IPMI without Redfish | Not supported |

- A GL.iNet Comet's ATX power board was tried on a real device, wired to a PC's power and
  reset pins and its power light. Every button was pressed from the wall and its effect seen on
  the Comet's picture and in the board's word: a short press on the running PC (Windows shut
  down, and was off some fifteen seconds later), a short press on the PC that was off (it
  started, the maker's logo and then Windows; the board said so after about four seconds), reset
  (it restarted), and holding the button (the picture went at once and the power some seconds
  later), the last with a second press sent a second later, which was refused. The tile, the live
  line, the history, the activity log and an alert were looked at while the PC was off and while
  it started, and a run over a selection with its tick and its pacing was made from the page. The
  board said the PC's power in a word of its own while kvmd's power light stayed "off"; answered
  a press at once and held the button on (its `busy` said half a second whatever the hold;
  `wait=1` was answered with an error and pressed nothing); and told whoever asked while it
  answered somebody else that there was no board. What the wall does with each is said under
  *Using it* and in `FOR-THE-DESKTOP-APP.md`. One PC is one: another computer's power light may be
  wired otherwise, and a stock PiKVM's board was not tried.
- The same Comet's board was then heard on its line for events, as the wall now hears it: the
  Comet read its board for that line about every second and a quarter and said it there when it
  had changed (once, and nothing more for as long as nothing changed), "on" four and a half seconds
  after a press on the PC that was off (and the wall answered the press in the same moment),
  "off" some seventeen seconds after a press that shut Windows down (0.4 s after a question
  asked once a second had said it); it said "no board" for a second and a quarter every six
  while a script asked the board once a second beside it, and for as long as two scripts asked
  ten times a second. Its `busy` was never seen in two presses. Three times a line was opened to
  the Comet's events while the PC slept, and it woke within seconds (3.6 s the time it was
  timed); twice more it did not, some minutes after the Comet had begun to say its board was
  gone. Held open, a line did not keep the PC awake: it went to sleep seven minutes later with
  the line open. Whether opening the line wakes it is not settled; qKVM opens none for the board
  alone. From then on the Comet said it had no board, also after a restart of the Comet, and the
  PC answered neither a key nor the network: the board was not tried further.
- The live view's keyboard and mouse were tried on that Comet, over a wall of qKVM on the same
  network, with the PC at Windows' sign-in screen (letters only, each erased again; no password
  and no Enter). Keys arrived each once, also fifteen letters sent in one go, and within 20 to
  30 milliseconds (a CapsLock sent, and the PC's light seen in the Comet's answer); a key held
  when the keyboard was given back, or when the line was cut without a word, stopped repeating
  at once, and the Comet itself let go of a key when its own line was cut. Its mouse was set to
  relative on the KVM: every place sent was dropped, and steps moved the pointer (Windows sped
  a fast one up); a drag by steps lifted the lock screen. What the wall does about it is said
  under [Live view and control](#live-view-and-control). Its pictures at 2560 by 1440 came five
  to seven a second while the screen changed. Typing into a program on the desktop was not
  tried there (the PC asks for a password, which was not typed). Through another Comet, on a recent
  GLKVM firmware, in front of a PC at its desktop, it was: the page's live view opened Notepad (Win, its
  name, Enter), a click opened a tab where it was put, a line with a capital was typed, and the
  tab and Notepad were closed again; a key held when the keyboard was given back stopped at
  once. That Comet has kvmd's H.264 line as well, with its mouse set to absolute: the wall passed
  the stream on, sixty pictures a second at 2560 by 1440 with a key frame each second, and the
  page drew them.
- JetKVM support was built from the device's published source and tried on real hardware
  (firmware 0.5.9), with a Windows PC behind it. The picture, the status, sharing the picture
  with the device's own page (the tile said *In use elsewhere* one to four seconds after that
  page was opened, and *Show here* had the picture back on the tile a second and a half after
  the click; the page that lost it said so and did not take it back by itself) and restarting
  the JetKVM work there. Keys, Ctrl+Alt+Del, typed
  text (all 94 characters of a US keyboard, and Enter, in order), the saved actions and
  keep-awake were seen to arrive on the PC. The live view showed the JetKVM's screen at 1920
  by 1080 (28 pictures a second in the page), with its
  keys, the pointer where it was put, the mouse buttons and the wheel; that is where qKVM was
  found sending keys out of order, as the JetKVM chapter says, and fixed. Wake-on-LAN was not
  tried (no computer was saved on the device). The ATX power extension, switched on at the device
  later and wired to a test PC with Windows, was then tried through the wall and its page: a
  short press on the PC asleep (its power light off) woke it, the light said on two to nine seconds
  after the press and its screen came some seconds later, and the history has the press and the
  power coming on; a short press on the PC running, at its sign-in screen, changed nothing there,
  and one from the JetKVM's own page changed nothing either. The long
  press and reset were not pressed. The screen came back on the connection the wall held in five
  sleeps and wakes of it in a row, the picture 0.7 to 1.6 s after the key that woke it; once,
  before the rule the JetKVM chapter gives for it, the wall took such a moment for a JetKVM that
  had stopped, and a connection made while the PC was asleep sent no picture after it woke. The
  real device was one without a password, on plain HTTP: its
  HTTPS mode, a password, and following a change of either were tried against a stand-in
  only. Keys and the mouse over the JetKVM's `hidrpc` channel were tried there too: three
  alphabets sent over the live view in two milliseconds arrived in order; a key held two seconds
  repeated 47 times on the PC whether it was let go of, the live view's connection was cut, or
  qKVM closed its connection to the JetKVM with the key down; with qKVM's process killed instead,
  50 times (the JetKVM let go of it a tenth of a second after the last keep-alive, where over
  JSON-RPC it had taken some six seconds); typing 96 keys took 2.0 s (2.9 s over JSON-RPC, the same
  PC and network). With a key held, the key stopped repeating the moment the JetKVM's own page took
  the viewer. A key pressed by a connection in the second after its hand-over stayed down for the
  page's viewer (the PC repeated it until the page's own connection ended), and a letting go sent
  over that connection within that second let go of it; after about a second the JetKVM closes that
  connection. A mouse button held as the page took over, or as the connection that pressed it was
  closed, stayed down for whoever came next (seen as a drag on the PC), and qKVM's letting go at
  those moments let go of it. A JetKVM without the `hidrpc` channel (a firmware older than it) and
  typed text in a layout other than US were tried against a stand-in only; the tables of the
  layouts were made from CLDR's data and checked against it, not typed on computers set to them.
  What stays open: over `hidrpc`, a key pressed by qKVM's connection in the second after a
  hand-over is let go of only where qKVM's letting go reaches the JetKVM within that second (over
  a slower link, or from a wall too busy to answer within it, it stays down for whoever took the
  viewer, until something lets go of it); a JetKVM that answers qKVM's question on that channel
  only after two seconds, and gets its keys over JSON-RPC until then, was tried against a stand-in
  only; Ctrl,
  Shift, Alt and Win held when qKVM vanishes are let go of only once the JetKVM notices the
  connection gone, and a mouse button held then stays down until the next viewer's first move.
  Over JSON-RPC, a press the JetKVM still holds unanswered when qKVM's connection to it closes,
  and does after that, is let go of by nobody: the JetKVM does not let go of it when that
  connection closes, as it is no longer the viewer's. On either way, an action's keys go as whole
  keyboard reports, which the JetKVM never lets go of by itself: where qKVM vanishes in the few
  milliseconds a typed key is down (50 for a combination such as Ctrl+Alt+Del), that key stays
  down until the JetKVM notices the connection gone. That a connection ended with something down
  is remembered while qKVM runs, not across a restart of it, and the "nothing down" owed puts the
  pointer back where qKVM last put it. A drag in the live view begun with a click before the
  locked pointer moved, and ended by steps, puts the pointer back where the drag began once it
  is dropped (the drop itself lands where it should): the button was pressed on the mouse put at
  places, and that mouse can only let go of it at a place.
- Stock PiKVM was tried against kvmd's own test environment (`make run` in kvmd's source, kvmd
  4.226, ustreamer 6.67) on a Linux machine, with a video loopback showing a moving test
  pattern and the kernel's GPIO mockup in place of a Pi's pins. qKVM signed in, showed its
  tile, picture and status, and found it in the network search. Its keys, typed text,
  keep-awake and pointer arrived as the USB reports kvmd makes of them (read where a Pi's USB
  would take them), its power and reset buttons pulsed their pins, and its power light came
  through. On the live line its pictures came one after the other, and its H.264 as well: the
  test environment's ustreamer makes none (a Pi's comes from its hardware encoder), so
  kvmd-media was started by hand and given a stream made with ffmpeg where a Pi's ustreamer
  puts it; qKVM took it from kvmd-media's own WebSocket, about 29 pictures a second, which
  decoded. Where stock kvmd answers otherwise than GL.iNet's firmware, a stand-in in the
  tests answers the same way: it says what it is in `/api/info`, and offers no restart of
  itself and no Wake-on-LAN, which are not offered on its tile. Not supported: a kvmd with
  its sign-in switched off (it hands out no session), and moving the pointer by relative steps
  over the live line while the KVM's mouse is absolute, its default (kvmd drops such steps;
  the same on a Comet). Not tried: a real PiKVM, its HDMI capture and USB, and its WebRTC.
- Servers were built from what the controllers of an ASRock Rack and a Gigabyte board (both
  AMI MegaRAC) report about themselves, and tried on real boards of both makers. Signing in
  and out, the status with its temperatures and fans, and reading which power actions the
  controller offers work on both; a look at the server takes half a second to a second. On
  one of them the rest was tried as well: the locator light (a light told to blink went out
  by itself within twenty seconds, so a steady one is asked for, and stays), a restart of
  the controller (the server untouched), a request to shut down and switching on. A reset
  was accepted; whether the server restarted could not be seen from here. A power cut
  pressed seconds after that reset was accepted and not carried out, which is why qKVM now
  looks whether one was; why the controller dropped it is not yet known. The console opened
  signed in has so far only been tried on a stand-in.
- Other makes of controller show how the server is without a picture of its screen: Redfish
  has none, and each maker's remote console speaks a protocol of its own. What was tried
  against the makers' emulators and captures named above is what the wall asks of a
  controller: signing in and out, the computer, its chassis and its sensors found where that
  controller keeps them (an iDRAC lists its disk enclosures as chassis too; the computer says
  which chassis is its own, and that one is read), the temperatures and fans in either shape
  the standard has for them, the locator light in either of its two spellings, the power
  actions as the controller offers them. A capture is a still picture: a power command is
  accepted there and nothing changes, which the wall reports as it would of a real controller
  that dropped one. HPE's emulator switches at once and sushy-tools a few seconds later, and
  on both the wall was seen to wait for the change before calling a command done. Where a
  controller is OpenBMC, its screen is read from its console (`rfb_console`, `/kvm/0`): built
  from the source of OpenBMC's web server and of its VNC server, and tried against a stand-in
  that serves the protocol of VNC behind a `/kvm/0` of its own (pictures, four seats, a session
  it forgot, a console without its VNC server behind it). OpenBMC's own romulus image, run in
  QEMU, has no console in its latest build (its manager announces none, and `/kvm/0` is "not
  found" to a signed-in request), and QEMU's model of the board has no video engine to take a
  picture with anyway: there, what was tried is that the console's address is refused without a
  session (401) and passed with the one the tile holds. Supermicro, Lenovo XCC and the others
  have not been tried at all.
- Intel AMT support was written from Intel's published WS-Management class reference and
  from reading Intel's and MeshCommander's open tools (read to learn the calls and the
  redirection handshake, not copied), tried against a stand-in built from the same reference
  and from what a real engine was seen to send, and tried on one real machine: a business PC
  with Intel AMT 16, set up by hand in admin control mode with user consent off, with a GL.iNet
  Comet showing the same screen beside it to compare with. There, qKVM recognised it from its
  address and read its state, power state, what it is (as its BIOS says it), its control mode
  and consent setting; switched its KVM on (the access point, then the redirection listener),
  off again through the wall's own route, and on again with the page's button; showed its screen on the
  tile, enlarged and on the live line (the same 2560 by 1440 picture as the Comet's, but for
  Intel's border, which only the PC's own monitor shows); typed into it (the Windows key, a
  program's name, Enter, a line with capitals, Ctrl+A, Delete, Alt+F4) and clicked in it (the
  desktop's menu opened under the pointer), each seen on the Comet's picture; held its
  screen across the engine's three-minute sessions; and pressed every power button there,
  through the wall, with its tile looked at and without: switched it on, shut it down (Windows
  with Intel's management service), held the power button, pressed reset, each seen on the
  Comet's picture and in the engine's power state (a power cycle, which the wall has no button
  for, was sent to the engine directly); and opened its serial console with qKVM's reader, also
  with the PC started into its BIOS setup with Serial over LAN asked for (nothing that was text
  came). On that same engine the WS-Management calls behind *Start into BIOS setup* were tried:
  `AMT_BootSettingData` with `BIOSSetup` armed and then cleared, and `CIM_BootService.
  SetBootConfigRole` as a single use each time, read back both ways, with no power command sent,
  so the PC was left as it was; and a still through the new path (one short session, then closed).
  The engine was asked, too, whether it takes a Digest nonce it did not hand out: a made-up nonce
  of its own shape, and its own nonce with one character changed, were both refused (a fresh
  challenge, the account not locked), and one nonce it handed out was taken 400 times in a row
  with none refused, while a repeated or lower nonce count was refused as stale. So an engine
  takes only nonces it handed out, and a nonce lasts far more than the handful of requests a
  command needs under one (a power button two or three, Start into BIOS setup about nine; see
  "telling another PC apart" above). A PC in client control mode or with consent on, a
  KVM that is off in the MEBx or absent, the plain port and the network search were tried against
  the stand-in only, and so was telling another PC at the address apart (a session to the screen,
  which has a sign-in of its own on the redirection port, is opened a moment after its question
  which PC answers and is not bound to it). *Start into BIOS setup* sends every boot property
  the engine reported, each at its own safe value (the deprecated `SecureErase` as false
  included): a board from firmware Release 20 on, where assigning it is an error, has not been
  met. One
  machine is one: another engine's firmware may answer otherwise. `tests/test_real_amt.py`
  asks a real engine again (how it is, its screen, and a KVM's picture of the same screen to
  compare with, and its serial console for a few seconds) where one is named in the
  environment; it presses nothing.
- Proxmox support was built from Proxmox's API documentation and from what a real Proxmox VE 9.2
  answered (pve-manager 9.2.21, a throwaway one installed for the purpose, with Alpine Linux guests
  booted from their ISO and a token with exactly `VM.Audit`, `VM.Console` and `VM.PowerMgmt` on their
  pool, privilege separation on), and tried there through the wall's own driver: the list of guests,
  a guest added by its number, its state, its screen (the boot screen at 640 by 480, then its console
  at 1280 by 800), letters typed at its login prompt and taken back again, seen on its screen, its
  power buttons (start and stop seen done; a shutdown that the live system in it did not hear, which
  Proxmox's task says), a console held for hours, and twenty consoles held at once.
  `tests/test_real_proxmox.py` asks a real one again where one is named in the environment, and
  presses keys or power buttons only where that is said there too. A guest deleted and another
  made after it was tried there too (2026-10-19): Proxmox gave the new one the freed number, the
  tile said six seconds after the new one started that another virtual machine had it, before
  anybody pressed (where the deleted guest had run only seconds, so that the new one's start was
  not told from its own, at the look's minute), its power buttons, typed text and screen were
  refused with nothing sent (the new one's task log held its own creation and start only), and an
  edit with the token's secret typed took the new one. A cluster of several nodes, a guest moved between them (and another made under the
  number of one that was moved away), and a guest with the QEMU guest agent were tried against a
  stand-in only. Which virtual machine has the number is asked a moment before the command or the
  console it decides (one request before it): a guest deleted and another made with its number in
  that moment is not told apart.
- KVMs with two-factor login enabled are not supported.
- qKVM itself has been run on Windows 11 and on Linux (Debian 13 and Ubuntu 24.04, as a
  service and in a container; amd64, and arm64 in a container), with Python 3.11 to 3.14.
  macOS has no verified native-video sandbox in this candidate. Native-video paths
  fail closed there, including JetKVM's combined video/control connection; full
  macOS support is not claimed.
- The page is run by its tests in Chromium, which is what Chrome and Edge are. Most of those
  tests were run once in Firefox as well, and passed. Safari, and the browsers of phones and
  tablets, have not been tried.
- Typing and mouse control happen over the [live line](#live-view-and-control), which the
  page's enlarged view and the qKVM desktop program speak. The line was tried against the
  stand-in devices in the tests, against kvmd's own test environment, on a real JetKVM and on
  a real Comet (all above): what a real PiKVM makes of its keys and its mouse over it is
  unseen. A JetKVM's picture on the line
  is JPEG made of decoded frames (the WebRTC library qKVM uses hands out decoded frames and
  nothing else through what it documents). A server's console takes keyboard and mouse
  where it is AMI's: typed keys were tried on a real board (an older Gigabyte); the pointer
  went out and was taken there, but its effect was not seen (the screen was a text console),
  and a board set to a relative mouse was not tried. An OpenBMC console takes none from qKVM.
- A GL.iNet Fingerbot paired with a Comet was tried on a real Comet with a Fingerbot on a desk:
  it lay loose, so its presses pressed nothing, and what a press does to a computer was not
  seen. Presses were sent from the wall, from the page and through the driver (half a second,
  three and eight seconds, both strengths, a second press while one ran), and straight at the
  Comet beside them. The Comet said whether one is paired only in a `fingerbot` event on its line
  for events (`{"exist": true}`), 0.2 to 2.0 seconds after a line opened (twice 4.3, beside another
  line, and it then said it again on every line open to it); answered every press with "success"
  1.9 to 2.5 seconds after it was sent, for half a second and eight alike, so its answer says the
  Fingerbot took the press, not that it is over; answered "Failed to click" to a press sent 0.3 s
  into another and took one sent a second in; and said its battery (a question of its own, 0.6 to
  0.7 s) was 101. Through the wall a short press was answered in 3.2 to 3.8 s, the long one in
  10.8 and 11.4 s, and one where the KVM was asked first in 7.6 s (twice). A Comet without a
  Fingerbot was not looked at for this: that its event says `{"exist": false}` is read from the
  size of that event in a record of an earlier look at one. How hard a real power button needs
  pressing, and what the Comet says when its Fingerbot is out of reach or its battery is empty,
  are not known; nor whether its "Failed to click" can come of a press the Fingerbot made after
  all (it was seen only for a press sent 0.3 s into another), or whether it says by itself that
  a Fingerbot was paired since (the stand-in in the tests does).
- *Start into BIOS setup* was tried on that same real Gigabyte board (AMI MegaRAC): from its
  Proxmox login prompt it was restarted and came up in its AMI BIOS setup, which was then left
  without saving, through the console's keys, and the server booted back to its login prompt. A
  board whose controller does not allow the "BiosSetup" boot override is not offered the button;
  that case was tried against the stand-in only. That board answered the change of its boot
  override with 204 after about 20 seconds, and left reads right after it unanswered for about
  a minute; so a 204 is taken as the standard means it (the change was made), only a
  controller that answers otherwise is read back before the restart, and the change, the
  restart and the clearing wait up to a minute for their answer (a look waits 20 seconds).
  Switching an off server on into its setup was not tried on the real board (its timings were
  given to the stand-in instead). Nor was a server switched on by somebody during the change: on
  the 204 path, which that board takes, such a server is sent *On*, which it takes as nothing
  to do, and the override waits for its next boot (the stand-in takes *On* to a server that is
  on as nothing to do, as a real controller is expected to).
- *The server it was added for* (see [Servers](#servers)) was tried on that same real board for
  the case that matters there, that the right server is never refused: a tile kept by qKVM 0.1
  took its server's number from what it kept, took its controller's at the first look, and was
  looked at, signed in to again, asked as before a button and as an edit without the password
  asks, also after a restart of the wall, and refused nothing. That board's service root says
  its controller's own number (the same as its manager's), not the computer's; OpenBMC's web
  server says one it made on its first start, which a reflash without its settings would
  change (then edit the tile and type its password). Another server at the address was tried
  against a stand-in only. Reading the service root before a sign-in adds its time (some
  seconds to a quarter of a minute on that board) to each sign-in, which is once and then when
  the controller's session has run out. The first sign-in after an upgrade from 0.1, where
  only the computer's number is known, is not checked before the password goes (the computer
  is, before anything is sent to it). The console's own sign-in goes a moment after the
  computer was asked, and is not bound to that question as a command is to its session (it is
  asked again after that sign-in, before the console is opened). Not known: whether a real
  controller still gives its computer's number while the server is off after the controller
  itself lost power (a board learns it from the server's firmware as it starts); where it does
  not, its tile goes by its controller's number meanwhile, where that is known and was compared
  before the session (so another board whose controller gave the very same number and whose
  computer gives none, or gives something that is no number, would be taken for it, as would
  another computer behind that same controller); where the controller's is not known either, every
  button is refused until the computer gives its number again, or the password is typed. A
  person's edit, or *Trust*, made in the very moment a tile takes its server's number for the
  first time is answered "changed by someone else just now", and goes through when made again.
- Carrying on after a restart with an unlock file was tried with the program itself, in the
  container both ways described above, and as a systemd service that is given the file by
  its path. Handing the file over as a systemd credential (`LoadCredential`) is how systemd
  means it to be done and is what is recommended above, but it has not been tried yet.
- Where every browser reaches qKVM from one and the same address and no proxy says who is
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
are for those tests only: nothing qKVM is installed with. Without them the files are skipped.

```
pip install playwright && python -m playwright install chromium
python -m pytest tests/test_in_a_browser.py tests/test_in_a_browser_with_the_program_itself.py
```

A test that passes alone and fails on a busy computer (GitHub's runners are slow ones) takes
something for granted about time. `tools/under_load.py` runs tests the way a busy computer does,
so that such a failure happens on purpose before it is fixed, and is seen gone after:

```
python tools/under_load.py --copies 6 --burners 12 --cores 0-7 -- tests/test_live.py   # six at once beside twelve busy processes, on eight cores
python tools/under_load.py --late 10:0 --repeat 20 -- tests/test_jetkvm.py            # every event loop held up 10 ms at every turn
```

Such a test waits for what it means instead of a moment of the clock; where the time is a limit of
the program's, it stays, and the test measures it with the program's own clock.

## About

Website: https://qkvm.com · Source: https://github.com/qkvm/qkvm

© 2026 qKVM, part of [PyPV Python Platform Ventures](https://pypv.com). Free software under the
[GNU Affero General Public License, version 3](https://github.com/qkvm/qkvm/blob/main/LICENSE):
you may use, study, change and share it, and if you run a changed version for others, or pass
it on, you must offer them your source under the same licence. It comes with no warranty.
The name qKVM and its logo are not covered by that licence. qKVM is written and maintained
by its publisher alone: reports are welcome, pull requests are not taken
([CONTRIBUTING.md](https://github.com/qkvm/qkvm/blob/main/CONTRIBUTING.md) says why, and what helps).
