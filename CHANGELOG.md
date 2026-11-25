# Changes

## 0.4.0

Be told where you work: alerts by mail, Slack, Microsoft Teams, Telegram, Discord, PagerDuty, ntfy and a signed
webhook, each told what it asked for. Sign in through your team's identity provider. Hold the wall to what it says: an
activity log that shows an edit, the API written down as a promise, and encrypted backups every night. Reach it over
Tailscale or NetBird. Intel AMT is no longer experimental, a wall can no longer freeze where 0.3.x could, and a wall
run as a Windows service shows its pictures. Upgrade with `pip install --upgrade qkvm` or
`docker pull qkvm/qkvm:0.4.0`; from 0.3.0, 0.3.1 and 0.3.2 the app's own update installs it in place. 0.4.0 needs the
same libraries as 0.3.2. Read "Upgrading from 0.3.x" first: alerts no longer go through a proxy.

### New

- **Alerts to several destinations.** *Settings > Alerts > Add destination*, fifty at the most, of nine kinds: mail by
  your own mail server or Gmail (always encrypted: STARTTLS on 587 or TLS on 465, its certificate checked), mail
  through Resend, Slack, Microsoft Teams (a Workflows webhook, sent an Adaptive Card), Telegram, Discord, PagerDuty
  (Events API v2: trouble opens an incident, back to normal resolves it), ntfy, and a JSON webhook signed as Standard
  Webhooks sign (the fields 0.3.2 sent, with `id`, `what` and `severity` added). Every address, key, token and password
  of a destination is stored encrypted with the saved passwords and never shown again; a password, token or key goes
  only where it was saved for, and is typed again for another host, port or region.
  - **Routing:** each destination is told the events it ticks, from the severity it chooses (critical, error, warning),
    of all machines or of chosen machines and groups. "Back to normal" is told exactly where the trouble was told, so
    an incident opened is closed, after a restart too. **Quiet hours** that recur by the day, beside the pause;
    **reminders** of what is still wrong (off by default); **one message** for many machines that change at once (a
    switch that dies); *Minimal content* leaves the address and the tile's text out. *Backup failed* is an event too.
  - **Delivery:** each destination by itself, in the order things happened, so that one that is slow holds up no other;
    tried again after 5, 30 and 120 seconds where its service was busy or broken, never where it said no. **Send test**
    says what the service answered, in its own words, with the destination's secrets taken out; **Log** shows the last
    fifty deliveries since qKVM started. A destination that begins to fail, and one that works again, is a line in the
    activity log. What waits to be sent when its destination or the alerts are switched off is dropped (*Not sent* in
    the log), even where they are on again before its next try. A pause or quiet hours stop new alerts, and what
    changes meanwhile is told when they end, where it is
    still so; an alert already on its way when they begin still goes, within its own tries (the last ending some three
    and a half minutes after its first began where a service does not answer, some four and a half for PagerDuty's two
    events of one change, and up to ten minutes more for each wait a service asks for; alerts for one destination go in
    turn; once a message of a change went, the rest of it goes, and a change tried again sends only what did not go).
    A screen watch that ends within a destination's quiet hours is told there when they end. A destination edited to
    send elsewhere (another address, chat, routing key or recipients) starts with nothing known of the machines, and
    what waited for it is dropped. A mail password has four signs at least and is kept as typed; a mail that some of
    its addresses refused says which. Browsers told by Web Push follow the same rules.
  - **Outbound rules:** before every send the name is looked up and every address it leads to is judged, and the
    connection goes to an address that was judged; no redirect is followed and no proxy used. Never sent to: the wall
    itself (qKVM's own port, at any of its addresses), link-local addresses and the metadata services of clouds,
    multicast, the ranges kept for other uses, and an IPv6 address that names an interface (`%`). This computer
    (`localhost`, `127.0.0.1`, `::1`, its own addresses) and your own network's addresses (10.x, 172.16 to 31.x,
    192.168.x, fc00::/7, and 100.64.0.0/10, where Tailscale's are) only where the destination's *May be a private
    address* is ticked, which is off for a new one. An alert never carries a password, a token or a picture, and its
    words are fixed: there are no templates.
- **Sign in through an identity provider** (OpenID Connect: Microsoft Entra ID, Google Workspace, Authentik, Keycloak
  and the others), free as the rest of qKVM. *Settings > Accounts > Identity provider*: the provider's groups give the
  roles (the highest of them), and anybody else it signs in may be given one role, with an email domain where the
  provider lets people sign up, and always for Google. The authorization code flow with PKCE, and the ID token held to
  every rule: its signature against the provider's keys (RS256 or ES256 only) and its claims. An account is known by the
  provider's own number for the person, never by a name that is taken. A sign-in lasts 8 hours at the most, and every
  sign-in the provider made ends at once when anything in the wall's settings that decides roles is changed. The
  wall's own passwords keep working beside it, and qKVM keeps one admin who signs in with one. Every sign-in, refusal
  and change of role is in the activity log.
- **An activity log that shows an edit.** Each line is chained to the one before and signed with a key the data folder
  does not hold in the clear (it is kept in the settings, which the vault key seals). The wall seals the chain at each
  start and stop, every hour and before its oldest file goes, and can keep heads outside itself: every line goes to
  syslog with its place in the chain (`--audit-syslog`), and an alert destination can be sent the head once a day
  (*Daily seal of the activity log*, sent within a pause and quiet hours too). *Settings > Activity > Check the log*
  reads it through on the wall;
  `python -m qkvm.checklog` checks a download or the files away from it (exit 0 intact, 1 broken, 2 could not check,
  3 intact with lines not proved; with `--part`, a download that is only a part of the log, 4 where it is intact as far
  as it goes and not proved complete). The order the lines come in decides nothing. Somebody who edits the files
  without the vault key is caught; somebody who holds the data folder and the vault key together is shown only by the
  heads kept elsewhere.
- **The API v1 is written down as a promise**, in the guide's chapter *The API*: within `/api/v1/` requests, fields,
  states, codes and words are added, and none is taken away or given another meaning. A `/api/v2/`, if one ever comes,
  is served beside it, and v1 goes on for at least twelve months and two minor releases after that, with `Deprecation`
  and `Sunset` headers meanwhile. `qkvm/api_v1.json`, in every installed copy, lists it for a program, and qKVM's own
  tests fail where the code and the list differ. `python -P -m qkvm.conformance <address> --token-file FILE` holds a
  running wall to it, reading only (nothing but GET: nothing is changed or pressed, no live line is opened), and exits
  0 where all is as promised, 1 where it is not and 2 where it could not check: a test for a client's release. An
  older wall is held to its own version's promise.
- **Scheduled backups, always encrypted.** *Settings > Backups*: every day at the hour you choose, one file in a folder
  you name (a mounted share, or a folder another tool copies elsewhere), the newest 7 kept unless you choose otherwise,
  with the history where ticked. Sealed with a backup key of its own (AES-256-GCM, with a key for each file derived
  from it), which is shown once as a printable recovery kit and kept sealed in the vault, so that a backup at night
  needs nobody. A backup takes its name only once it has been read back whole; *Verify the latest* reads it again and
  says what it holds; a run that fails is told to the destinations that ask for *Backup failed* and is a line in the
  activity log. `qkvm --restore FILE --backup-key KIT --data-dir NEW` brings the wall back into an empty folder on
  another computer, and refuses a file that was changed, cut off, made with another key or by a later version.
  Whoever has a backup and its kit has every device password in it: keep the kit as carefully as the wall's own key.
  No backup holds a backup key: a wall restored from one has backups off until its admin makes a new kit. A folder
  takes one run at a time by whatever name it is reached; a run that does not end within the hour is said failed and
  told, and one stuck on a share holds only that share. A restore holds the folder it restores into: a second restore
  there is refused until the first ends, and one that was stopped before it finished is taken over by the next, which
  takes away what it wrote, and nothing else, and begins again.
- **Over Tailscale or NetBird.** *Find KVMs* lists a tailnet's machines from Tailscale's command or, in a container
  beside Tailscale's, from its local API over its socket (only one that is root's or qKVM's own account's), and a
  NetBird network's from its client or from its management API (with a token kept in the vault, under *Settings >
  Network*). `--tls-tailscale` serves Tailscale's own certificate for the wall's name under ts.net, which browsers
  trust, renewed without a restart. `docker-compose.tailscale.yml` and `docker-compose.netbird.yml` run qKVM in the
  network of the tailnet's own container (its image pinned by digest), and the guide's chapter *Over Tailscale or
  NetBird* says how to let only the wall reach the KVMs, and why never Funnel.
- **Open in.** An admin gives a machine its page on MeshCentral, its RustDesk ID or its Remote Desktop host (*Open
  in...*, in the tile's menu), and operators and admins open it from there; for Remote Desktop the menu hands out an
  `.rdp` file that holds the host alone. They are plain links: no password or token is kept for them or put in them,
  and the wall fetches nothing from them.
- **The guide says how to run a VNC server safely** on a machine that has no KVM in front of it, and what such a
  server cannot do (*No KVM in front of it? A VNC server*).

### Changed

- **Intel AMT is no longer experimental.** Five more business PCs were on the wall, two walls at once, and what their
  engines did is built in, and was tried on them again:
  - A plain no to a password the engine took before is answered once more, with its fresh challenge. Refused again,
    the tile says that the engine refuses sign-ins from qKVM for now, and nothing is sent to it for 16 minutes: an
    engine refuses one address for a while after failed sign-ins, and every try meanwhile keeps it refusing. One that
    still refuses after the wait is tried once more some 90 seconds later; *Login rejected* is said only of a refusal
    then.
  - *Shutting down* is shown from a shutdown until the PC is seen off (the engine itself says nothing of it). *Shut
    down* pressed again says it is under way; *Hold power button* meanwhile, where the engine offers no power cut,
    says why nothing was sent; a PC not off three minutes after says what may be the matter.
  - While another viewer has the engine's KVM (another wall, Intel's or MeshCentral's tools), the tile says *In use by
    another viewer* (409 `in_use`), and its port is asked again after 15 seconds, 30, then once a minute.
  - A PC that asks for the consent code, or has no KVM (vPro Essentials), says so and what to do; one reached over
    plain HTTP says so on its tile.
  - A tile set to *Live KVM* keeps its session while a picture is being made. It was let go of under the picture, and
    the next look opened another, with Intel's border on the PC again.
  - The guide says, in short, how to set a PC up for qKVM.
- **GL.iNet's newer firmware**, from Comets that run it:
  - A KVM whose mouse is set to move by steps says that it can be set to absolute on the KVM's own page.
  - A virtual drive that says offline is said to be not ready, to be tried again once the machine behind it has
    started.
  - **A reset is judged by the screen** on a KVM with the kvmd interface: done once the screen is seen to change from
    what it was just before the press, else said pressed and not seen to change, never not carried out. (A Comet's
    computer kept its video signal up through its restart.) Where the screen cannot be read just before the press, the
    reset is done when the button is let go, as before.
- **The manual is GUIDE.md**, and README.md a short page that leads to it; the page and its messages call it the
  guide.
- **An address nothing is served at, or one served by another method, is refused as every refusal is promised to be**:
  `{"code": "...", "message": "..."}`, 404 `not_found` or 405 `method_not_allowed` (a new code) with `Allow`. An admin
  was answered the web framework's `{"detail": "..."}` there.

### Fixed

- **A wall could freeze for good.** Where Python's garbage collector ran the clean-up of an earlier answer (a
  download's, a served image's) while the same thread held the lock that clean-up takes, the thread waited for itself,
  every request of the wall with it, and the process could not even end. Seen once in many runs of the tests, in a
  download of the activity log; 0.3.x has the same code. The clean-up is handed to a thread of its own now, which
  holds no lock.
- **Pictures under a Windows service or an SSH session.** qKVM run as a Windows service, by a task that runs whether
  anybody is signed in or not, or over SSH, showed no picture of a JetKVM, a server, a PC with Intel AMT, a VNC server
  or a Proxmox guest: its video workers could not load their libraries on the desktop qKVM was started from. Each
  worker now starts on a desktop of its own (see Security). Where no worker can start at all, those tiles say why
  (`no_video`), `GET /healthz` says `"video": "unavailable"` (not why: it answers anybody), and the log says it once;
  each tile said an error of its own before. A start that only took longer than 15 seconds counts as none only three
  times in a row. KVMs with the kvmd interface need no worker for their pictures.
- **A JetKVM's last picture from before its screen went dark is not shown as its screen.** Its video library lets a
  picture go only once the next one begins, and a busy wall took the last picture from before for the screen that had
  come back, until the next one. Each picture is stamped now with when its first packet came.
- **A JetKVM whose video worker is slow to start is not said to be offline.** On a busy computer that took up to 18
  seconds, and meanwhile its tile, its history and the alerts said offline.
- **A stock PiKVM whose computer has no video signal no longer sends alerts in pairs.** Stock kvmd stops its video
  while nobody watches and then says nothing of the signal, which was taken for a picture: "has no video signal" and
  "has a picture again" went out each time somebody looked. A signal the KVM does not say keeps the last word of it
  now. (Found by a soak of 500 stand-in machines; 0.3.x has the same code.)
- **The guide's way to start qKVM with Windows kept it running for three days.** The task its `schtasks` line makes is
  ended by Windows after three days, and on a laptop as soon as it runs on its battery. A second line now lifts both
  (*Keeping it running, Start it with Windows*). Found by a soak of the release on Windows; the guide had the same
  line since 0.1.
- **A sign-in made at once after a session ended elsewhere stays.** When a session ended elsewhere (signed out
  everywhere, a password changed, a restart), a sign-in made at once could be thrown back to the sign-in page by a
  late answer to the session before, and a dialog or the large view's last picture stayed on show until the sign-in
  page came. The wall leaves the screen at once now, a late answer of an ended session ends no newer one, and on the
  way back the sign-in page waits at most 5 seconds for the identity provider's button (as long as before at its
  first opening, the button added if it comes later).
- **A KVM that closes the connections kept to it all at once no longer shows offline for some seconds.** A look is
  tried again on a connection of its own; nothing that acts is tried again.
- **Keys to a KVM whose switch hangs are refused after two seconds**, not eight.
- **Two clicks on Actions while the page waits for its first word of a machine open one menu**, and keys from the
  large view the wall refused give keyboard and mouse back, as its question says.
- **The activity log names the input a key action was for**, or that it went as for a KVM of one input, and logs keys
  refused for their input before anything went. Keys whose tile was taken off the wall while their own request
  signed in again said they may have gone; they say nothing went.
- **A PC's view chosen for a tile now pointed at a KVM is refused as `machine_changed`**, not `invalid`, so that the
  page fetches the wall again.
- **A wall of many tiles loads each tile once** (10,000 tiles in 0.25 s, where it took 1.7 s).
- **A JetKVM picture stamped as its screen came back is taken as from before.** On Windows with Python 3.11 and 3.12,
  whose clock moves in steps of some 16 ms, a picture of the same step could pass for the returned screen.
- **A JetKVM tile whose video connection came to nothing tries again by itself**; it stayed red until opened large.
  Where the JetKVM refused the offer, the tile tries again after 5 seconds and up to every 2 minutes. After any other
  failed offer, which may have taken the JetKVM's one viewer from somebody at its own page, it makes one more, then
  says why and waits to be opened. Only a tile on screen tries; a look at the status does not.
- **No "Task exception was never retrieved" from the WebRTC library** when a JetKVM connection ends on a busy
  computer.
- **A VNC server's idle video workers are stopped**: its picture encoder and its Tight JPEG decoder (some 35 MB each)
  stop a minute and a half after the last look and start again at the next. They were kept for every VNC server
  anybody had looked at, for as long as it was on the wall. Many of them starting again at once start a few at a time,
  in threads of their own, so that the rest of the wall does not wait for them.
- **Video runtimes earlier runs left in the temporary folder are removed** once nothing in them is open (a wall that
  Windows ended as it restarted left some 90 MB there each time).
- **A wall's memory on Linux.** On Linux with glibc the wall's process grew 1 to 3 MB an hour over the days while
  Python's own memory stayed level: memory freed and kept by malloc in its arenas. Every 0.4.0 wall now keeps malloc to
  two arenas and a fixed trim threshold of 131072 bytes, however it came to 0.4.0 (pip, the service, the image, or an
  update from inside the app: the wall asks glibc itself where its starter set nothing); whoever set
  `MALLOC_ARENA_MAX`, `MALLOC_TRIM_THRESHOLD_` or the same in `GLIBC_TUNABLES` keeps their own. Freed memory piles up
  more slowly, for about 1% of a processor core on a wall serving 40 pictures a second.
- **An update kept on trial on Windows.** Marking an update that had started and stayed up was tried once, and a
  moment when the program read its note made it fail without a word: the update was on trial again at the next start.
  It is tried again for a few seconds now (going back alike), never over a note another program wrote meanwhile, and
  said in qkvm.log where it still cannot be written. `qkvm --roll-back` that meets such a note says so and changes
  nothing. (That is the starter's: a wall updated from inside the app has it once the package itself is upgraded.)
- **A restore stopped near its end.** A restore stopped right after it wrote the settings, before its line in the
  activity log, left a wall without that line, and the same command refused to finish it. The line (and the log's
  check) now comes before the settings: stopped before them, the same command takes the restore over and finishes it.
  A start on a folder whose restore has not finished (under way, or stopped) is refused, with what to do: run the same
  `--restore` again.
- **Windows: no ERROR for a connection reset as it closed.** qkvm.log got an asyncio ERROR and a traceback each time a
  browser or a device reset a connection as Windows' event loop closed it (WinError 10054). That one case is no line
  now, unless it hid an error of qKVM's own; every other error of the loop is logged as before.

### Security

- **Alerts are held to the outbound rules above, the address carried over from 0.3.2 too.** 0.3.2 posted to whatever
  address was saved, through the environment's proxy where one was named: a link-local address (where clouds keep their
  metadata service) or the wall's own port was sent to as any other. Those are refused now, and this computer and
  private addresses are reached only where *May be a private address* is ticked (it is, for the address carried over:
  see below).
- **Each video worker on Windows starts on a desktop of its own**, which lets in SYSTEM, qKVM's account and that worker
  alone; until 0.4.0 a worker in a signed-in session started on the user's own desktop. Where qKVM's window station
  lets no AppContainer in (a service's, an SSH session's), the worker's own identity is given one entry there, taken out
  again when the worker ends. SECURITY.md now also says what a worker taken over could still reach in a signed-in
  session (as before 0.4.0), and that the station entries of a qKVM ended from outside stay until the station ends.
- **Several qKVMs on one Windows computer no longer crowd their video workers onto the same two processors.** Each
  began at the first pair, where Windows takes most interrupts too; each begins at a pair drawn at random now. (Found
  in this release's work, and confirmed by a review.)
- Each part of this release's new code was read by a fresh reviewer of our own, and its fixes again; then the whole of
  it by an outside review in two rounds, and its fixes by two more fresh reviews. Every finding of high or medium was
  fixed before the release, with tests; one, that alerts no longer use the environment's proxy, is said instead
  (below). Among them: a destination's saved password could follow an edit of its address to another host; the
  activity log could be edited without the vault key and still check as intact, and a log cut short with its lines
  turned round was taken as intact by the offline check; a sign-in by the provider could keep its role for up to 30
  days after its groups changed; two walls backing up to one folder pruned each other's backups; a new recovery kit
  made while a backup was being made could be opened by the kit before it (no backup holds a backup key now); an IPv6
  address that names an interface passed the outbound rules; an alert waiting to be sent again went out after the
  alerts were switched off; a service that said a token back in an error had it shown to the admin. A second outside
  round, on the release candidate, found three of high: a power button, keys or typed text confirmed for one machine
  went to the one an admin put at its tile meanwhile; a person in a provider's group was given the role for anybody
  else where that was higher; a mail password of fewer than four signs came back whole in what the server said. All
  are fixed, with its medium findings: among them, a failed restore took away the files and the key of one that had
  ended well, a mail some of its addresses refused was logged as delivered, one the server took before hanging up
  was sent four times, and a push service's reason could repeat the query of a browser's address. A re-check of those
  fixes found that a menu left open while its tile was pointed at another machine still sent its one-click keys
  there, and that keys and text on a KVM with several inputs went to whichever computer was on screen: both go only
  where the page showed now (409 `machine_changed`, and `input_changed`). Also fixed then: a failed restore took away
  a `--vault-key-file` another restore used; a full disk while the first storage key was written left a key no retry
  could use; a mail its server took was sent again when the time ran out while its refusals were written up; a
  restore that ended well could be taken for a stopped one; what was left of a PagerDuty change went to a routing
  key edited meanwhile. A second re-check found that a question could name the tile as it was at the click while its
  request carried the machine the menu showed, that the key and text editors lost the KVM's port, that a KVM whose
  switch did not answer was offered keys naming no input, that the Ctrl+Alt+Del action was not held to the input,
  that the AMT view buttons named no PC, that a failed restore could take away a storage key another restore had
  taken up, that a first key cut short by a stop left none a retry could use, and that a mail refused by every
  address was given up where the first refusal was for good. All are fixed: keys and text now go only where the KVM
  itself, asked right before they go, shows the input the page showed. A third re-check found that a page just
  opened, or a tile pointed at another machine, offered keys naming no input on a KVM with several (no word of it yet,
  or the word of the one before); that a KVM whose switch listed its inputs without the one on screen, or whose wall
  was locked and opened again, was taken for one of a single input; that Ctrl+Alt+Del and Alt+F4 confirmed in the
  large view named no input; and that making a first storage key took away files beside it named like its own
  (another wall's key, another restore's key in the making), failed for a long key name or a volume without hard
  links, and could refuse a key another restore had just put in place. A narrow look at those fixes found that keys
  could still go naming no input to a KVM with several (a page holding an older status or a failed first contact; an
  action that waited for control to be let go), that the large view's Ctrl+Alt+Del and Alt+F4 went over the live line
  where the page took the KVM for one of a single input, and that making a first storage key could take away a file
  named as its lock or its staging file, and put a key in its place before it was whole or private on a volume without
  hard links. The page's keys now say the input they are for, or that they take the KVM for one of a single input,
  and the wall refuses those where it finds several; a key is made only on a volume that takes hard links. These are
  fixed, but for the limits under Known.
- **0.4.0 was held at its release to fix every issue still known**, and each fix was read by a fresh reviewer of our
  own, and the fixes of those again. They found, and this release fixes: a status, a picture, the Media box (since
  0.3.2), a PC's KVM switch, a server's console, *Open in*, the certificate box and *Trust*, and the list of computers
  to wake could be of, or act on, the machine an edit had put under the tile, where the page still held the wall as
  it was. Each now names the machine it was asked for (`target`, refused with 409 `machine_changed`), the page fetches
  the wall again, and a Media box and its questions close once their tile is at another machine. Keys sent as for a
  KVM of one input went where its switch had not answered (a 502 while kvmd restarted, no answer, a proxy's page),
  where its answer said a switch was there but listed no input yet, and after a restart that forgot that the KVM had
  shown several inputs; a KVM with several inputs could be taken for one past 4,096 remembered; a switch not in step
  had its input taken as said; and keys confirmed for an input could wait seconds for a free connection after the KVM
  said its input, so that a switch at its buttons meanwhile sent them to the other computer. Keys as for one input go
  only on kvmd's own word that it has no switch now, what a wall learned of a KVM's inputs is kept with its tile
  (across restarts, locks and a certificate trusted anew; let go of after ten minutes of kvmd's word that its switch
  is gone), and keys leave within half a second of the KVM's answer or are refused. On Windows a vault key named as
  the staging file with a trailing dot, a space or `::$DATA` was taken and could be removed: names are judged as
  Windows opens them.

### Releasing

- **Each release lists what it brings in**, from 0.4.0 on: `qkvm-<version>-sbom.cdx.json`, an SBOM in CycloneDX 1.5 of
  every library that installing it brings in, for each Python and system it is built for, with each one's version,
  licence, package URL and the SHA-256 of its wheels. It is listed in `SHA256SUMS` and signed with the release;
  `python -m qkvm.release verify --signed SHA256SUMS qkvm-<version>-sbom.cdx.json` checks a copy.
- **Which versions get fixes** is written down, in the guide (*Updates, Which versions get fixes*) and in SECURITY.md:
  before 1.0, only the newest release gets fixes, security fixes too, as the next release, and nothing is carried
  back to an older line; long-term support starts with 1.0. A security fix is announced by a GitHub security
  advisory, a *Security* part in its version's chapter here, and the release itself.
- **An update is tried on a data folder made by the released 0.3.2** (accounts with two-factor sign-in, a token, five
  devices of four kinds, saved actions, the alert address, history and an export): in 0.4.0 everything in it is there
  and works, and the released 0.3.2, started on it again afterwards, finds its alert address.
- Tests that failed only on a slow or busy Windows computer wait for what they mean now, not for a moment of the
  clock: those that failed on GitHub's Windows runners, and seven that failed where sixteen test files ran at once.
  Two of them had found defects of the wall: the JetKVM's picture and its slow video worker above.
- A newer push of a `release-X.Y.Z` rehearsal branch cancels that branch's older Release and Tests runs; a tag's run
  and its publication share a group no rehearsal joins (where GitHub still cancels a run that waits once a third
  joins).

### Upgrading from 0.3.x

- **By pip:** `pip install --upgrade qkvm`, then start qKVM again. **By Docker:** pull `qkvm/qkvm:0.4.0` and start the
  container again with the same volumes. **From the app** (*Settings, Updates*): 0.3.0, 0.3.1 and 0.3.2 install it in
  place. From 0.2.x, update to 0.3.2 first.
- **The alert address of 0.3.2 is the first destination**, of the kind its *Service* said, with *May be a private
  address* ticked, so that one on `127.0.0.1` or `localhost` keeps working. New for it: link-local addresses and the
  wall's own port are refused, and a JSON webhook carried over is sent unsigned until *Make a new one*, in its *Edit*
  box, gives it a secret. A name that leads to several addresses is tried at each in turn, as 0.3.2 did (`localhost`
  leads to `::1` first on some computers). `GET` and `PUT /api/v1/alerts` and `POST /api/v1/alerts/test` keep their
  fields and their meaning, of the first destination.
- **Alerts go through no proxy any more.** A wall that reaches the internet only through a proxy (`HTTPS_PROXY`,
  `HTTP_PROXY`) stops alerting after the update, and the activity log and the list of destinations say why. Let the
  firewall pass the wall's connections to the services it alerts (HTTPS on 443 to their hosts, the mail server on 587
  or 465), or alert a service on your own network (an ntfy or a mail relay, with *May be a private address* ticked)
  that passes them on.
- **The activity log is taken in once**, before its first line (some 3 s for 50 MB), and the lines of 0.3.2 check as
  "from before the chain". Each line is some 136 bytes longer with its place in the chain, so the same `activity_mb`
  (50 MB, unless it was changed) keeps some 45% fewer lines: about five months of a busy wall, where it was nine.
  Raise `activity_mb` to keep as long as before.
- **Going back to 0.3.2** (an update that does not start, `qkvm --roll-back`, or `pip install qkvm==0.3.2`) finds what
  0.3.2 saved, its alert address too while the first destination is unchanged; what only 0.4.0 has (more
  destinations, the identity provider, backups) it does not see. The lines 0.3.2 writes meanwhile, after a 0.4.0 that
  stopped as it should, are taken in at the next start of 0.4.0 and said as not proved by the chain.

### Known

- The Docker image keeps the three exceptions for SQLite's findings (its FTS5 search and secure delete, its session
  extension; none reachable from qKVM), which Debian calls minor and has not fixed for trixie, and takes two for
  OpenSSL's (memory its QUIC code keeps, both rated low by OpenSSL; qKVM has no QUIC), which Debian has not fixed
  yet, until 2026-12-24 (the second of OpenSSL's until 2026-12-25) or Debian's fixes, whichever comes first.
- What this release changed for Intel AMT was built from what five real engines did and tried on them again, except
  the consent code (none of them asks for one). Not built yet: a state that says a PC's monitor is on a
  graphics card other than Intel's (the engine's KVM shows Intel's graphics alone), and a way to type a consent code
  that somebody at the PC reads out.
- On a real tailnet, on Linux, Tailscale's machines were listed alike by its command and by its local API, and
  `--tls-tailscale` served Tailscale's certificate, which a browser's check takes, once Tailscale had made it (the
  first can take a minute or two; the wall's own certificate is served meanwhile). NetBird's management API,
  `--tls-tailscale` on Windows and the Compose files were tried against stand-ins only.
- Sign-in through an identity provider was tried against a stand-in provider; the setups the guide gives for Entra ID,
  Google, Authentik and Keycloak were written from their documentation. SAML and SCIM are not offered, and the Desktop
  App does not sign in to a wall through its provider. A key the provider has taken out of its set is still taken for
  up to an hour.
- A reset judged by the screen was built from what a real Comet did, and tried against a stand-in. The RustDesk link
  (`rustdesk://connection/new/<ID>`) was not tried with the RustDesk app.
- The delivery log, and what quiet hours hold back, are kept in memory: a restart forgets them. A screen watch that
  goes off within quiet hours is not told there, nor then its end. Where a screen watch's start went is kept in
  memory: after a restart its end goes wherever *Back to normal* is heard. Mail goes out on ports 587 and 465 alone.
- Backups to a network share were not tried. Browsers told the alerts by Web Push are not told of a failed backup. A
  run that failed is made again at the next day's hour, or with *Back up now*. The guide gives the restore of a plain
  install; for a wall in Docker it is not written out yet.
- On Windows, where qKVM is ended from outside (killed, or a crash), each of its running video workers leaves its
  entry in a service's window station until the station ends; some 1,300 fill it, and then no worker starts there
  until the computer restarts (SECURITY.md).
- On the PiKVM V4, its power and reset buttons were not pressed, its power light could not be read on the test
  machine's board, and a computer was not started from an image there.
- An action, a picture, a console's way in, the Media box and a machine's *Open in* links are tied to the machine
  their question or view named (`target`). Where what qKVM knows of a machine grows (its certificate or its number
  first remembered, a JetKVM followed onto HTTPS), an action asked for just before is refused once, and asked again
  goes, and an open Media box closes (an upload under way with it). A script that sends no `target` acts as before.
- Secrets are taken out of what alert services, the identity provider and NetBird say back: a token or key whatever
  its letters, and a password in an address, whole in any spelling and wherever six of its signs stand together; the
  words of an address of small letters alone, and a mail login's password, only whole (in any case and spelling) and
  where they stand whole, so that the server's own words stay; a short mail password of one run of letters and digits
  only as it is spelt. What a KVM, a server's controller or Proxmox says in an error is shown as it came.
- An alert waiting to be tried again when qKVM stops is not sent after the start. A machine's trouble that was not
  delivered counts as told, and its end is still sent: given up on after its tries, refused at one try, given way
  when a hundred waited, or not to be sent at all (the saved passwords locked). A browser told by Web Push may be told
  that a machine is back to normal without its trouble, where a switch dropped the trouble, and a newly added
  destination may be told so of a trouble from before it. Where a mail server takes an alert for some of its
  addresses and refuses others for now, those miss that alert. The log of a mail some addresses refused gives up to
  300 signs of their addresses and reasons, so it may name none of them whole; of one refused by all, it gives the
  first refusal for now, else the first.
- In these rare combinations a destination can be told that a machine or the backups are back to normal without
  having been told the trouble, or not be told a recovery it was owed: switched off and on while an older backup's
  recovery waits and another backup fails; alerts switched off and on while a screen watch's start waits, the watch
  then ending, going off again and ending again within quiet hours; a restart between an edit reaching the disk and
  the alerts' next write of what they told. An edit of a destination that cannot be saved (a full or read-only disk)
  while a trouble alert waits for it loses that alert: it is not tried again. On a wall of more than 10,000 machines,
  a restart keeps, in each of the alerts' saved records, what they knew of the first 10,000 by their ids, as of the
  last time those records could be saved whole (one grown too large is not saved).
- On a KVM with several inputs, keys and text go only where the KVM itself, asked right before they go, shows the
  input the page showed, and only within half a second of its answer; a switch in that half second, or while the KVM
  types a long text, can still send them to the other computer. Keys the page sends as for a KVM of one input go only
  on kvmd's own word that it has no switch: a KVM a wall has never seen list its inputs (just added while its switch
  is not up, or after an edit of its address, check, machine or identity) is taken at that word, and so is one whose
  switch kvmd says for ten minutes is not there while it still routes (its link to kvmd lost, or switched off in
  kvmd's settings); a switch plugged in again then takes keys as for one input while it starts. A restart of the wall
  starts the ten minutes again. Keys typed in the large view or on its on-screen keyboard (its Ctrl+Alt+Del and Alt+F4 there too), its
  Win, Alt+Tab and PrtSc, and chords typed on the person's own keyboard (Right Ctrl+Delete and the like) go over the
  live line, which names no input: they reach whichever computer the KVM shows as they arrive. The large view's
  Ctrl+Alt+Del and Alt+F4 buttons, typed text and the Actions menu name the input, or say they take the KVM for one of
  a single input, and are held to it; on a KVM of one input each of them asks its switch first (one more short
  request, of two seconds once it has a connection) and briefly lets go of control in the large view. A script that sends neither
  `input` nor `one_input` acts as before. The status's `ports.active` is the last look and may lag; it decides nothing.
- A stock PiKVM's signal that comes back while nobody watches is seen at the next look that starts its picture: until
  then the machine stays without signal, and a watch of minutes without signal can go off.
- On Linux and macOS a vault key folder on a volume without hard links, or one
  that shows its files to others (FAT, exFAT), is refused, and an empty `.qkvm-key.lock` stays beside a key once one
  was made there. On Windows a first key is not made in a folder that holds such a file (carried from Linux or macOS,
  or left by a power cut): remove it by hand while no qKVM is making a key there.
- A folder on a share that gives no file numbers is held with every share of its volume number. Where that number
  is 0 it is told apart by its server and share, so the same share reached by another name is taken for another
  folder; on Linux a share mounted twice is another folder whatever its number. Each run still keeps its own file in
  the making.
- The Docker image's health check asks port 8787: a container started with another `--port` is said to be unhealthy.
  Keep 8787 inside and map it (`-p 9000:8787`), or in Compose give the check its port, as
  `test: ["CMD", "python", "-P", "-s", "-m", "qkvm.healthcheck", "9000"]` (the image has no shell for `--health-cmd`).
- Some of this release's browser tests were run on Windows alone as their pages were made, and on Linux in the whole
  suite since. A few tests still fail now and then where a Windows computer runs many test files at once.

## 0.3.2

Fixes found in 0.3.1's reviews, by the Desktop App, and on real devices. Upgrade with `pip install --upgrade qkvm` or
`docker pull qkvm/qkvm:0.3.2`; from 0.2.1, 0.2.2, 0.3.0 and 0.3.1 the app's own update installs it in place. 0.3.2
needs the same libraries as 0.3.1.

### Fixed

- **A media change goes only to the machine the tile was at when its list was made.** The Media box stays open across an
  edit of its tile: a box opened for one KVM whose tile was then pointed at another sent its mount, unmount, deletion or
  upload there. A list now carries a mark of its machine (`listed`), a change sends it back, and where the tile's
  machine has moved since, the change is refused (409 `moved`) with nothing asked of either. Before an upload the page
  asks for the list again, so that a box whose tile has moved sends nothing and closes. A client that sends no mark is
  served as before.
- **A server's console is opened only where its controller says the monitor stays on.** Where the controller's console
  pass does not say both of its monitor-off words, or says either some other way than a plain no, the console is left
  alone and the tile says why (where one of the two is a plain no and the other is not, that only one of them is off). A
  word said as nothing (an empty text) is a word not said. (One that said neither, or said one as nothing, had its
  console opened, and the server's own monitor could go dark.)
- **Sign-in pacing keeps every wait that stands.** Past 2048 remembered sign-ins the oldest was let go of whatever it
  held, and a password a device had just refused could be offered to it again at once. Only waits that have run out
  make room now.
- **The history and the activity log are not held up by their own reads.** Reads that kept coming, one beginning before
  the other ended, kept the database's checkpoint from getting through, and the file SQLite writes ahead to grew to
  several times its share. qKVM's own reads now wait while a checkpoint runs (3 s for the history, 2 s for the activity
  log, then "try again in a moment"). A download of the activity log waits longer, 15 s for each page after the first,
  so that a checkpoint never sends it to the text files. Where it goes there all the same (the index made again
  meanwhile), it goes on from where it was in them, each entry once: it went on from the time of the last entry it had,
  and entries of that same moment were left out, and one out of the order of time left out or sent twice. A program
  outside qKVM that keeps a read of the files open (a database browser, a backup tool) still holds the checkpoint off,
  and the file grows until it lets go; the wall's own reads wait out each such try, which takes about a second and a
  half.
- **A connection is kept 130 s between requests.** The web server let an idle connection go after 5 s: a request sent on
  it at that moment was lost, and a proxy in front answered it 502, a power button's too. A proxy in front of qKVM
  should let an idle connection to it go sooner than 130 s; the README names the defaults that do. At most 1000 are kept
  at once (a quarter of the open files allowed, where that is fewer), the one kept longest let go first, so that
  requests nobody has to sign in for cannot hold open connections without end; a busy wall uses a few hundred. A request
  whose head came with the one before it has 20 s to be finished, as every request has; it had the whole 130 s. Where a
  later web server library lacks what the 20 s limit of such a request reads, a connection is kept 5 s between requests,
  as before; where it lacks only what the count of kept connections reads, they are kept 130 s without that count. The
  log says which, once.
- **Two requests the Desktop App reads are promised in v1:** a machine's activity (`GET /api/v1/audit` with `device`
  and `limit`) and the picture of a screen alert (`GET /api/v1/devices/{id}/alert-picture/{stamp}`), with their
  answers and refusals in the README's table. A test holds every request the Desktop App makes to that table.
- **The Add KVM line has no dash:** `<name> added (<model>, over plain HTTP)`, as the Desktop App says it. A test
  keeps dashes out of everything the page and the server say.
- **A server's command that found no free connection says "Nothing was sent".** With its certificate pinned, where
  none of the connections came free in time, a reset said "it may have been done" and a controller's restart "done".
- From real devices:
  - **A KVM whose plain address sends everybody on to HTTPS is said so.** Added as http://, it said only "Login failed
    (HTTP 301)". It is refused with `https_only` and its HTTPS address, which the page offers; it is never followed by
    itself. A plain address taken for a PiKVM-style KVM is asked the same before the password goes out, and a tile whose
    KVM has begun to do so can still be renamed or regrouped with Save without checking.
  - **Why a KVM's power is unknown is said.** Where its board says the power light is off while the screen shows a
    picture, the tile says "Power unknown" and its Details say the power-LED wires are probably not connected
    (`power_led_unwired`, in the status's `atx.note`, which is there only then). On a KVM with several inputs the board
    may be another computer's than the one on screen: the tile says "Power unknown" alone, also after an edit of the
    tile.
  - **A jiggler switched off in the KVM's own settings is refused in those words**, and nothing is sent; it was 502
    `action_failed`. (A new GL.iNet firmware gives the jiggler settings of its own.)
- **The README says what a real PiKVM V4 did.** It said that no real PiKVM had been tried. One was: its
  picture, the live line with its H.264, keys, typed text and the pointer, keep-awake, and virtual media, each as it
  should be; its power light is the second of the three above. GL.iNet Comets on a new firmware were tried too, and
  gave the other two.
- **No model of the test hardware in anything published.** The stand-ins in the tests, and the demo the website
  shows, had processor models, firmware versions, sensor names and more of the machines qKVM was tried on. They are
  made up now, the website's pictures were taken again, and a test refuses a real processor's model.

### Releasing

- **The Docker image is on a newer base**, `python:3.13-slim` of 2026-11-05 (the same Python 3.13.18), with Debian's
  fixes for zlib: its two exceptions are gone.
- Three tests that were tighter than the code hold to what it promises: typing for an account suspended meanwhile, a
  JetKVM's picture from before its screen came back, and the history's test of reads that overlap (0.3.1's known
  one), which passes now that the checkpoint gets through.

### Known

- The Docker image keeps the three exceptions for SQLite's findings (its FTS5 search and secure delete, its session
  extension; none reachable from qKVM), which Debian calls minor and has not fixed for trixie, until 2026-12-17 or
  Debian's fixes, whichever comes first.
- On the PiKVM V4, its power and reset buttons were not pressed, and its power light could not be read on the test
  machine's board; a computer was not started from an image there.
- A power button, keys and typed text go to the machine the tile is at when they arrive; they are not yet tied to the
  one their confirmation named, as media changes are now.

## 0.3.1

Fixes found while 0.3.0 was released and in its reviews. Nothing new is added. Upgrade with `pip install --upgrade qkvm`
or `docker pull qkvm/qkvm:0.3.1`; from 0.2.1, 0.2.2 and 0.3.0 the app's own update installs it in place. 0.3.1 needs
the same libraries as 0.3.0.

### Fixed

- **A server's image is let go of under faults too.** Where the threads that read a served image were stopped with
  work still waiting, or opening its file failed in an unexpected way, a file could stay open and a read's place stay
  taken until qKVM restarted. (Found by the outside review, with faults made on purpose.)
- **The Media box says only what is plain.** Where qKVM serves HTTPS already and the address named in *Settings, Server
  images* is plain HTTP, it says to name the HTTPS address there, and nothing of switching HTTPS on.
- **A failed edit says what it did not take back.** An edit to another controller that could not be saved ends the
  image mounted on the tile all the same; it now says so, and to mount it again.
- **AMI's boards and a wall in Docker:** the README says how a wall in Docker on Linux serves them on port 80
  (`-p 80:8787`), and why Docker Desktop cannot.

### Releasing

- **A release is rehearsed before its tag.** Pushing a release's branch runs the release workflow up to the signing:
  the build, the libraries' lock and its audit, the tries on every target, both images and their scans. Signing and
  publishing stay on the tag. (0.3.0's release found faults only its tag ran, on a tag that could not be moved.)
- Tests that failed on GitHub's runners for reasons of the runners hold now: a stand-in is started again where Windows
  had no buffer space for a socket, a slower ARM runner's drawing work is allowed its time, a JetKVM stand-in's first
  picture comes later than a slow runner's look, two tests that read the settings file while the wall saves it look
  again where Windows refuses that moment, and a test of the no signal alert waits until the wall holds the tile's
  picture.

### Known

- The Docker image keeps the five exceptions for Debian's findings accepted for 0.3.0 (SQLite's FTS5 and session
  extension, zlib's gzip file writing; none reachable from qKVM), until 2026-12-03 or Debian's fixes, whichever comes
  first.
- A test of the history file's checkpoint fails now and then on GitHub's slower runners, under reads that never
  pause: a checkpoint refused is tried again once the file SQLite writes ahead to has doubled, and was refused again
  there, so that file grew to some four times its share before one got through. The checkpoint is unchanged in 0.3.1.

## 0.3.0

Recover a machine from the wall: mount an image on it and start it from there, on Proxmox guests, KVMs with the kvmd
interface, JetKVM and servers over Redfish. Be told when a screen goes dark or stops changing, also on a phone. See and
steer more of them: VNC servers live, keys to OpenBMC consoles, three views for a PC with Intel AMT, zoom. And updates
that bring their own libraries. Upgrade with `pip install --upgrade qkvm` or `docker pull qkvm/qkvm:0.3.0`; from 0.2.1
and 0.2.2 the app's own update installs it in place (0.3.0 needs the same libraries as 0.2.2).

### New

- **Virtual media.** A tile's *Actions, Media...* lists the images the machine can be given, mounts one, says what is
  mounted and unmounts it:
  - **Proxmox guests:** an ISO image from the guest's own Proxmox storage in its CD-ROM drive (one is added where it has
    none), read-only; started from it once, or until it is unmounted, its boot order put back afterwards.
  - **KVMs with the kvmd interface (GL.iNet Comet, PiKVM) and JetKVM:** the images on the KVM's own storage, as a CD-ROM
    drive or a USB flash drive (read-only unless chosen writable). An image uploaded from the browser is carried
    through qKVM to the KVM as it comes, up to 16 GB, hashed on its way and kept nowhere; one cut off is taken off the
    KVM again. Images are deleted there too. Before a byte goes, the KVM is asked again whether it is the one the tile
    was added for; what the KVM would refuse at once (a name there already, more than is free) the box says itself.
  - **Servers over Redfish** (AMI MegaRAC first): an image from a folder the admin names in *Settings, Server images*,
    which qKVM serves to that server's controller alone, over HTTPS with a user and password made for that mount (or
    over plain HTTP, where the controller takes no other), at an address made for it, for as long as it is mounted and
    bound to that controller; started from it once or until it is unmounted.
  - Mounting, uploading and deleting are for admins (a token never may), asked first with the machine and the image
    named, one at a time per machine, and each written in the activity log, with the image's SHA-256 where qKVM carried
    it.
- **Screen watching.** Two watches on a machine's *Edit*, in minutes: **no signal** (the KVM's own signal flag) and,
  where chosen, **screen unchanged** (from the pictures the wall gets anyway: no session is opened for it). Each is
  told through the alerts and again when it is over, with the picture that set it off kept on the wall for an admin
  for 30 days, never sent.
- **Alerts in a browser and on a phone (Web Push).** *Settings, Alerts, This browser*: the alerts of the machines the
  account may see, as notifications, with the wall closed too; a tap opens the wall at the tile. Encrypted for that
  browser alone and signed with the wall's own key, through its maker's push service (Apple's, Google's, Mozilla's or
  Microsoft's), which cannot read them. It needs the wall over HTTPS with a certificate the phone trusts; on an iPhone
  or iPad, the wall added to the Home Screen.
- **VNC servers live, with keyboard and mouse**, in the enlarged view as the other kinds, over one connection.
- **Keys to an OpenBMC console**: keys, combinations and typed text (in the US layout) in its live view.
- **Three views for a PC with Intel AMT**, chosen per tile by an admin or an operator: *health only* (no KVM session
  is ever opened), *stills* (the default: a picture now and then, so Intel's border is on the PC's monitor only for
  moments; enlarged, it goes live) and *live KVM* (a session held while the tile is shown: the border stays).
- **Zoom in the enlarged view**: Fit, 50 % to 200 %, where 100 % is the machine's own pixels, remembered per viewer
  and machine; scrolled or dragged when larger than the window, and the pointer lands where it points at every size.
- **Updates that bring their own libraries.** From 0.3.0 on, a release lists the exact libraries it was tested with,
  in a file signed with it. The app's own update puts them in a folder of the new version's own (copied where the same
  version is installed already, else downloaded from PyPI and checked by its hash), tries the new version in a
  process of its own before it switches to it, and stays on the old one at any refusal. On Linux (x86-64 and ARM64,
  glibc) and Windows (x64), with Python 3.11 to 3.14; elsewhere it says the pip command. The first update it serves is
  the one after 0.3.0. A backup may leave the data folder's `updates` out.

### Fixed

- Proxmox guests on one token no longer sign in one after the other at a start.
- The hold after a power press follows the machine's address (and its pinned certificate), not the tile.
- A JetKVM that does not answer requests for a key frame is asked less and less often (5 to 40 seconds), not every 5.
- A server's power action answered with no content waits no longer than its own bound for the next state.
- A tile with a 0.2.0 console link in an unusual number form can be edited again.
- An export leaves out the passwords of tiles of a kind it does not know.
- The printed lines to take over files: in a container they name the container's paths; on Windows the owner and the
  access are given in two lines (an account without administrator rights was left without access to the file).
- A JetKVM whose video connection fails is said to be online where it answers, not offline.
- A check for updates gives up after a minute; an install that fails for any reason says so and ends.

### Security

- Who may mount, upload and delete images: admins alone, never a token. An image served to a server goes to its
  controller's own address only, with that mount's user and password, at an address that ends with the mount; the
  controller's own words are shown without that address and its token, and no log has either.
- Web Push: the wall's key and the browsers' subscriptions are sealed with the saved passwords and are not exported;
  a push service is sent to only at a name on the internet whose every address is one of the internet's, looked up at
  each send, and connected to at the address looked at. A browser is kept for one account, and only that account or
  an admin replaces it.
- Alert pictures are the data folder owner's files alone, shown to admins only, for 30 days, and refused at start
  where something else stands in their place, as `screens.json` is.
- Updates: only what is in the signed list of libraries is loaded, by hash; the list is tried on every system and
  Python it names before it is signed, and the container image is built from it. Whether a release has such a list is
  its signed checksums' to say: one left out of the release's assets is not done without.
- Before the release, an outside security review and a second review of our own read the new code; nothing they found
  was high, and what they found of medium and low is changed: the reads of a served image are counted before they
  wait, and end when its tile is removed or moved; what a cut-off upload left is taken off only on the device it was
  going to; an image a KVM wrote whole is never deleted for a listing that lags; the local-use NAT64 prefix is no
  address of the internet's for a push service; an alert waiting for a browser asks again, before each attempt,
  whether its account may still be told it.

### Upgrading

- **By pip:** `pip install --upgrade qkvm`, then start qKVM again.
- **By Docker:** pull `qkvm/qkvm:0.3.0` and start the container again with the same volumes.
- **From the app (Settings, Updates):** 0.2.1 and 0.2.2 install it in place. On 0.2.0, use pip or Docker, as for
  0.2.1.
- **Going back to 0.2.2** (`pip install qkvm==0.2.2`, or the app's roll-back) keeps what only 0.3.0 has in the
  settings, unused, and 0.3.0 finds it again: tried on one data folder, 0.3.0 to 0.2.2 and back.

### Known

- Virtual media was tried on a real JetKVM and against kvmd's own test environment (upload, each kind of drive,
  delete). A server's was tried on three real AMI boards: a newer Gigabyte board mounts an image over plain HTTP from
  port 80 alone (name the address on port 80 and forward it to qKVM: see the README); an ASRock Rack board keeps its
  remote media off without an image share of its own, and an older Gigabyte board ends the mount with its own error.
  Starting a server from an image was not tried on a real board.
- A mount on a controller qKVM knew nothing of (no certificate checked, no numbers) ends the first time the
  controller is known, and is mounted again.
- Two walls on one computer share a browser's sign-in: use a private window for the second.
- A KVM's CD-ROM drive (Linux's USB gadget) gives the machine only the first 2.36 GB of an image, as a Windows image
  is larger: the mount's question says so; as a USB flash drive or a disk it is read whole.
- Intel AMT has no virtual media yet (planned for 0.4, experimental).
- Web Push was tried with Chrome on Windows; an iPhone needs the wall's certificate trusted, and was not tried. The
  push services are told `https://qkvm.com` as whose the alerts are (the software's site, never the wall's address);
  it cannot be changed yet.
- Where the free space on a KVM changes between the Media box's look and an upload, the browser may say there was no
  answer instead of the reason; the box then shows the KVM as it is.
- The desktop app's joint test of the live connection waits for the desktop.
- The container image's SQLite exception ends on 2026-12-03, or when Debian fixes it, whichever comes first.
- Two walls on one computer, at two ports, share a browser's session cookie (a browser keeps cookies by name and host,
  whatever the port): signing in to one may sign out of the other, and a page over plain HTTP cannot replace the
  cookie one over HTTPS set. A private window, or another name for the computer, keeps them apart.
- The signed list of libraries names every build of a library's version that fits a system (for older and newer
  Linux, say); the release's tests run each system's Python on the build its own runner picks.

## 0.2.2

Fixes found on a real wall after 0.2.1. Nothing new is added. Upgrade with `pip install --upgrade qkvm` or
`docker pull qkvm/qkvm:0.2.2`; from 0.2.1 the app's own update installs it in place.

### Fixed

- **An update that cannot be installed in place is said when it is found.** The wall checks a new release's
  requirements as soon as it finds it. Where the libraries installed beside qKVM are too old for it, Settings, Updates
  says so plainly, with the exact command for this install (pip run by the Python qKVM runs under, or the container's
  lines) and a Copy button, and offers no Install button and asks no password; where it needs a newer Python, it
  says which. (0.2.0 offered Install, asked the password, and only then refused.) Checking a release never holds up
  the wall's own rounds, and gives up after two minutes; an install refused anyway refreshes the page.
- **The row of keys under Control takes its own place.** It no longer covers the top of the machine's screen: the
  whole picture is shown below it, and clicks land where they point.
- **Every button in a row has its icon**: Fullscreen in the enlarged view, the keys under Control (Ctrl+Alt+Del, Win,
  Alt+Tab, Alt+F4, PrtSc, Type text, Relative mouse), and every Copy button.
- **A PC with Intel AMT: its KVM is switched on and off from Actions**, whichever applies (switching it on was only on
  the Health view before). The Health view's button stays.
- A server console's web page is signed out of on its own connection where the server is known by its computer alone.

### Known

- A manual *Check for updates* waits for GitHub's answer for as long as GitHub takes to give it.
- A Windows path with unusual quote characters may need its printed command adjusted by hand.

- A server whose console is AMI's and whose controller does not give its own number may keep the console's web session
  until it runs out on the controller, where the Redfish session is given back first.

## 0.2.1

A release of fixes only: a security review of the whole web app, of every device driver and of how the
settings are kept, an update of every library with a known hole, and the bugs left open in 0.2.0. Nothing new
is added. Upgrade with `pip install --upgrade qkvm` or `docker pull qkvm/qkvm:0.2.1`; a wall on 0.2.0 needs no
offline step.

### Upgrading from 0.2.0

- **By pip:** `pip install --upgrade qkvm`, then start qKVM again. The libraries qKVM needs are raised with it
  (see *Libraries* below).
- **By Docker:** pull `qkvm/qkvm:0.2.1` and start the container again with the same volumes.
- **From the app (Settings, Updates):** 0.2.0 refuses the update where the libraries installed beside it are
  older than 0.2.1 needs, which is most installs; it then says so, and `pip install --upgrade qkvm` is the way.
  Where it is taken, it starts as any update does.
- **Going back to 0.2.0** works as before (`pip install qkvm==0.2.0`, or the app's roll-back).

### Security

- **Open console keeps to the wall's own host name.** The enlarged view's *Open console* now follows the same
  rule as the tile's link: a device page on the host name qKVM is reached under (at another port) is never
  opened with the wall's sign-in, and the wall refuses to hand out such a link (`same_host`).
- **The right machine, every time.** A tile now acts only on the machine it was added for, on every road:
  - a JetKVM's number is compared before every connection, and over plain HTTP before any password goes where
    the JetKVM shows it to anybody; following a JetKVM onto HTTPS (by itself, or in an edit, also when saved
    without checking) goes only to that same JetKVM;
  - a Proxmox guest, an Intel AMT PC and a JetKVM whose number cannot be read when it is added or edited are
    refused, not saved without it;
  - a server controller's password, console pass, session and keys go only on a connection on which the
    controller was just told apart; an AMT PC's screen and serial console go only to the engine that said
    which PC it is.
- **Passwords:** AMT's Digest sign-in without `qop` is refused (a listener could recover the password from
  it). A Redfish sign-out goes only to the session it ended.
- **A hostile device cannot stall the wall.** Answers from servers are read by a bounded HTTP reader (h11);
  a JetKVM message larger than any JetKVM sends ends its connection; JetKVM video addresses are tried only
  at the JetKVM's own address; one slow or hostile VNC-family server can no longer hold up every screen, and
  what all of them cost together is bounded for the whole wall.
- **Settings and keys on Windows, as on Linux.** Every folder and file qKVM makes (the data folder, the
  storage key's folder, the key, the unlock file, the settings, the logs, the history and activity
  databases, the certificate) is its account's alone from the moment it is made. A folder qKVM finds is never
  changed: where others may read or change it, the start says so, with the lines that fix it.
- **No update from a folder others may write.** The starter checks the data folder, every link on the way,
  and every file of an update before it runs it, on Windows as on Linux.
- **Files planted while a folder was open are refused.** A file or link with one of qKVM's own names that is a
  link or belongs to another account stops the start, with the lines that take it over; a `tls` folder that is
  a link or another account's is never written into.
- **The unlock file** is judged by who may read or change it (also by its ACL and through a link); a systemd
  credential is recognised. An unlock key is on the disk before it is used, and a key that does not fit
  deletes nothing that could recover the settings.
- **The setup code** is never written into a log others may read.
- **Sign-in checks do not hold up the wall.** A recovery key or a password is checked beside every change
  rather than inside the one lock every change takes.
- **A wall screen's display link** is kept no longer than it is valid, by the wall's clock.
- **FastAPI's own telemetry** is switched off.

### Fixed

- A JetKVM no longer ends its session when the wall falls behind decoding its video: it goes on from the next
  key frame, keys and held buttons kept.
- Nothing stays held: what the wall lets go of at an end it decides is let go of at once, after presses still
  on their way.
- A press that never went out says it was not done, on every kind of device, and holds nothing.
- A Proxmox power command whose answer was lost is said to be perhaps done, so pressing again is asked, not
  assumed; one rejected token counts once for all its guests; guests on one token are all online at the
  first look.
- A server's sensors no longer vanish for ten minutes after one failed read; a fan that keeps failing shows
  no old reading; Start into BIOS setup reads the power again where a controller answered without a body,
  and its messages say only what is known.
- The live view starts when control becomes possible after the view was opened; with Control on, the *No
  signal* veil lets the pointer through; *Done to it* is kept up to date.
- A saved action a kind of device cannot run is refused when it is saved.
- A tile of a kind this version does not know (left by a later version) is kept and never connected to.
- A lock after wrong guesses is never shortened.
- `docker stop` and `systemctl stop` write that qKVM stopped.
- An AMT entry imported without a port takes the AMT ports, as adding does.
- A wall screen behind a proxy that answers for a restarting wall waits for it and keeps its link.
- `--data-dir` given twice is refused.
- Holds and paces that kept a device from being asked too often no longer start again when a tile is edited,
  re-added or the wall is locked.

### Libraries

qKVM now asks for websockets 17.4 or later, cryptography 50.0.2 or later, dnspython 2.9.0 or later (named for
the first time), h11 0.16.0 or later, and FastAPI 0.148 or later. The Docker image is built on Python 3.13.18.
The release pipeline's actions and scanners are updated past their known holes, and the sites are built with
a pinned wrangler.

### Changed

- A data folder on Windows that others may read is said at every start and left as it is (0.2.0 said nothing);
  run the lines the start prints to make it yours alone. A folder on a drive without permissions (FAT, exFAT)
  is said once and used.
- A server controller that answers HTTP/1.0, or closes the connection after every answer, is signed in to
  only where its certificate is pinned and its own.
- A JetKVM reached only through a port forward, a tunnel or a reverse proxy to another host shows no picture.
- A second `--data-dir` added to the Docker image's own is refused: the image sets the data folder (`/data`).

### Known

- Proxmox guests on one token sign in one after the other at a start (a few seconds for many guests).
- A press's hold starts again when qKVM itself restarts.
- On Windows, a file made by 0.2.0 that others may read stays readable until the printed lines are run.
- A Redfish session token goes on the HTTP library's connections where the controller's certificate is
  pinned and its own (the certificate binds them there).
- A slow VNC whole-screen update on a host many times slower than a desktop PC can count as a long step.
- Where qKVM runs as a Windows service and an administrator runs an offline command (such as
  `--reset-password`) elevated, the files it writes may belong to that administrator's own account; the
  service's next start then refuses them and says so on its console only. Run the lines the start prints (they
  take the files over for the service's account) before starting the service again.
- A tile edited to another KVM keeps the first KVM's Fingerbot answer and holds for up to an hour (they err on
  the side of asking less).
- A console link saved by 0.2.0 whose host is written in an unusual number form makes an edit of that tile
  refused until the link is written plainly.
- The first start of 0.2.1 rebuilds the activity log's index from its text files; until it is done, searches
  read the text files.

## 0.2.0

Keyboard and mouse in the browser, and more kinds of machine on the wall: PCs with Intel AMT
(experimental), VNC servers, virtual machines on Proxmox VE and servers whose controller runs
OpenBMC. Each machine has a history, the activity log is searched at once however long it is, and
several machines are removed in one go. The settings are sealed with a storage key kept outside the
data folder, and pictures are decoded in a sandboxed worker. The move from 0.1.x takes one offline
step: read *Upgrading from 0.1.x* before you upgrade.

### New

- **A machine live, with its keyboard and mouse.** Enlarge a tile and press **Control** (or the
  key C). One connection per viewer carries a KVM's own H.264 stream where it has one (stock PiKVM,
  and a GL.iNet Comet on a recent GLKVM firmware), its pictures one by one where it has not, a
  JetKVM's as JPEG and a server's screen as it changes. A program of your own can speak the same
  line, and the README's nginx recipe passes it on (*Live view and control*).
- **The enlarged view, made for control.** Control is a toggle and the picture stays put; the
  header matches the home page's height; keyboard, shortcuts and relative mouse sit in a row
  beneath Control; live status sits under the machine's name; a thin strip at the bottom shows the
  stream's statistics, and its *Details* opens status, statistics and the activity you may see,
  together. An on-screen keyboard can be moved and resized, with one-shot modifiers, for touch or
  the mouse. *Type text* works while you hold Control: it waits until qKVM has confirmed that
  control was given back.
- **One holder at a time.** One connection holds a machine's keyboard and mouse, and an action
  refused because somebody has them says who. The activity log says who took them and gave them
  back, never a key.
- **An admin can take over**, after a question that names the holder (**Take over from**), who is
  told who took them; the activity log says who took them from whom. An operator, a token or a wall
  screen never takes over, nor does an admin's action from the wall (its refusal says where it can
  be done). The way in can take a minute (a JetKVM connected anew took some forty-seven seconds):
  the page says it is asking, the wall answers within that time, and an admin who closes the view
  meanwhile takes nothing.
- **Given back after 15 minutes without input:** what the holder had down is let go of, they are
  told why, and the picture goes on.
- **Nothing is left held down.** Whoever loses keyboard and mouse has what they had down let go of,
  and nothing new of theirs goes out. The next holder, and an action from the wall, send nothing
  until that is done and nothing of the last holder's is still on its way (a PC with Intel AMT
  waits up to ten seconds for its next session): what lands late is let go of again, and a new key
  never lands beside the last holder's Ctrl. A saved action edited or removed while it waited is
  refused, and nothing is sent.
- **Taken away is not given back.** Where a line loses keyboard and mouse against its will (signed
  out, its right withdrawn, taken over), keys and clicks still waiting on their way (queued for a
  JetKVM, or for a PC's next AMT session or a Proxmox console opened again) are not sent. Given
  back, or the page closed, they still go while whoever said them may still act: signed out a
  moment after closing the page, what still waits goes nowhere.
- **The pointer moves the way the machine takes it** (`pointer` in the line's `state` message).
  Where the mouse moves by steps only, a click on the picture hands the pointer over (Esc gives it
  back) and never reaches the machine; where it takes places only, *Relative mouse* is not offered.
  Relative moves make up no button changes while the browser puts the locked pointer back, and a
  pointer lock granted only after control was given back (Firefox and Safari do not say when) is
  let go of as it comes.
- **Tried on a real GL.iNet Comet:** each key arrived once at any pace (fifteen letters sent in one
  go among them), within some 25 milliseconds, and nothing stayed down when the keyboard was given
  back or the line was cut. Its mouse, set to relative on the KVM, dropped every place the page
  sent: that is why the line says `pointer`.
- **The live line is guarded:**
  - Access is asked again before every picture, key and click, also for input waiting for the
    machine to hand over, and before control goes to a request that waited for the device to open
    its keyboard and mouse; a holder no longer allowed is let go. A stalled look at a device does
    not hold that up.
  - A live view keeps no sign-in alive: only the person's own requests do. One opened by somebody
    signed in through the identity proxy (`--sso-header`) ends once the proxy has not named them on
    a request for ten minutes.
  - A line that is not read, or floods the wall with frames or pieces of a message, is hung up on,
    before its pass as after. A line that lost the keyboard cannot take it from whoever has it now.
  - One account has 32 live lines at the most, takes nobody else's pass, and takes and gives back
    keyboard and mouse sixty times a minute at the most on all its lines together (at DEBUG in the
    program's log; the activity log keeps them).
  - The keyboard's Power key is never sent to a machine, as the page never sent it; one message
    turns the wheel sixteen notches at the most; a stream that announces a picture larger than qKVM
    shows any is not passed on; what the line says is never in the log, at any level.
- **Business PCs with Intel AMT** (vPro Enterprise), experimental, through their management engine:
  whether the PC is on, off, asleep or hibernating, what it is, whether its KVM could be used and in
  which control mode it was set up, and the power buttons. An admin can switch a KVM that is off on
  the engine on from its tile. **Its screen** comes through Intel's own KVM where the PC was set up
  in admin control mode without user consent: on the tile, enlarged and live, with keys, typed text
  and the pointer. See *Intel AMT* in the README.
- **An AMT PC's own monitor is spared Intel's border.** A tile that is only shown gets a still every
  five minutes, each a short session, so the red and yellow border is on the PC only for the seconds
  a still takes; between them the tile shows the last still and its age. A session is held only
  while the machine is enlarged or live, and closed a minute after; one is opened before *Power on*
  (or *Start into BIOS setup*) when that view is open, so the start shows from the first moment. A
  still that gives up waiting closes the session it began (or, where its sign-in is on its way, the
  moment it is open). Consent is read at most every five minutes, and the screen is asked for only
  beside the engine's own ports, never at a forwarded port and two.
- **An AMT PC's power:** every button was pressed on a real PC, *Hold power button* also while its
  screen was watched (the engine cuts no power while a KVM session is open, so qKVM closes its own
  first). A PC that is starting is said to be, and reset is not sent to a PC that is off. A command
  whose answer did not come back, or cannot be read (no `ReturnValue`, or no SOAP at all), may have
  been done (504) and is not offered for *Retry failed*. Nothing is written to the engine for an
  admin signed out, suspended or demoted while it was waited for: access is checked before each
  write, and the refusal (403 `stopped`) says what, if anything, was written before.
- **An AMT tile acts only on its own PC.** It remembers the PC by the number the PC gives for
  itself; another PC that answers at its address (after a new lease, over plain HTTP) is sent no
  power command, no keys and no session to its screen, and the tile says so. A PC whose TLS port
  takes the connection and fails the handshake is not added the plain way unasked.
- **Start into BIOS setup**, for a PC with Intel AMT and a server over Redfish: one boot into the
  firmware setup, switching the machine on if it is off or restarting it if it is on, with its large
  view opened so the setup shows from the start. The question before it names the machine and says
  which it will be. Offered only where the machine says it can (Intel's `AMT_BootCapabilities`, or a
  Redfish board that allows the "BiosSetup" boot override), to operators and admins, one machine at
  a time (not in a bulk run), and written in the activity log.
- **Start into BIOS setup is single use:** it clears at the next boot. A boot override another tool
  set, or a boot option that destroys data, is not replaced, and a machine changing its power state
  just then is left alone, and that is said. Where the power change is refused for certain, the
  setup boot is cleared again; where it may have gone through, it is left and the button says so. A
  press that has not come to its power change within two minutes sends nothing more and clears what
  it armed. Over Redfish it waits through the minute a controller answers nothing after its boot
  override changes, and where the controller's answer is read back, the power that read shows
  decides: a server switched on meanwhile is restarted, not sent *On*.
- **VNC servers** on the wall: any machine with a VNC server (a QEMU or libvirt guest, a desktop
  with TigerVNC or x11vnc, a controller's own VNC server), by address, port and password, with its
  screen, key combinations and typed text; found by the network search on ports 5900 and 5901; in
  and out of an export file. Built from RFC 6143 and tried against a stand-in (*VNC servers* in the
  README says what that means).
- **VNC over TLS (`vncs://`)** is shown as encrypted in the list of KVMs, with how its certificate
  is checked, and the summary of a file to import says where its certificate is not checked. A
  certificate that changed shows in the edit dialog and can be trusted again from the page, as for
  an address with `https://`.
- **A VNC server that hangs up is not hammered.** One that lets qKVM in and hangs up, at once or
  after one frame, is connected to less and less often, as one that is down; a frame counts for the
  server being well again only once its connection has lasted five seconds. One that ends every
  connection after a time of its own (TigerVNC's MaxConnectionTime, a proxy's limit) is connected to
  again at once after the first end, then after 15 seconds, a minute and five minutes, until a
  connection has served four minutes.
- **Meanwhile its tile says that it ends every connection**, not that it is offline (which an alert
  would report as gone), also while nobody looks, and once for the whole run, so an alert is told
  once. Watching it enlarged, or sending it keys, connects at once, and an action waits for the
  connection instead of answering "Connecting" at the first click. A look at its status does not cut
  a wait short (its greeting is asked every two minutes at the most), an edit of its tile does not
  begin the count anew, and a server that stops answering counts as down, not as one that ends what
  it lets in. A PC with Intel AMT, whose engine ends sessions at its own time, is not paced so.
- **VNC pictures are held to what they draw:** ZRLE and Tight refuse trailing bytes and the reuse of
  an ended compression stream, idle or empty ZRLE updates included; valid continuing streams and
  Tight's stream resets still work.
- **Typed text on a VNC server, a PC with Intel AMT or a Proxmox guest** names a character it cannot
  send by its place in the text, never by itself (the answer goes into the activity log, and the
  text may be a saved password), and asks again before every piece of keys whether whoever asked
  may still have it done.
- **Virtual machines on Proxmox VE**, one tile each, through Proxmox's API with an API token:
  whether it runs, its power buttons (start, shutdown, stop, reset), and its screen through the
  console Proxmox hands out, on the tile, enlarged and live, with keys and the pointer. *Add KVMs*
  lists the virtual machines the token may see, to tick. Tried on a real Proxmox VE 9.2 (*Proxmox
  and virtual machines* in the README).
- **A Proxmox console costs little.** Each is a task in Proxmox's log and two processes on its host,
  so one is held while somebody looks and let go of five minutes after the last viewer, and a guest
  reported stopped and running by turns has one opened at most every five minutes. Switching on and
  stopping are waited for while Proxmox's task runs (or its high availability carries them out);
  one still under way after a minute is said to be so, not to have failed. A press is answered
  within its time counted from the press, the questions it was decided by and the looks while it
  is waited for included.
- **A Proxmox tile acts only on its own guest,** though Proxmox gives a new virtual machine the
  number of a deleted one. A guest is known by its SMBIOS UUID, remembered when it is added and
  asked again before every power button, before each console and before it is followed to another
  node, and by a look once a minute and wherever it is found stopped, started or started again:
  another virtual machine is sent nothing, and the tile says so. Typing the token's secret in an
  edit takes the one that has the number now. A guest moved to another address asks for its token
  again, as a server's controller does: a certificate remembered for it would vouch for any host
  that shows the same one (a proxy, a wildcard).
- **Servers whose controller runs OpenBMC show their screen** from its console (`/kvm/0`, the
  protocol of VNC), opened with the session the tile holds: on the tile, enlarged and live (*Servers*
  in the README). A controller that does not state its firmware's version in its own resource
  (OpenBMC in QEMU did not) has it read from its firmware inventory: the image it says it runs, or
  the one active image that names it. OpenBMC's own image in QEMU passes every check of its test.
- **Servers whose controller is not AMI's** are tried on every push against Dell's capture of an
  iDRAC, HPE's iLO emulator, DMTF's example of the standard and sushy-tools. Their tiles show the
  sensors and the locator light in either shape and spelling the standard has, an error answered
  with HTTP 200 is an error, and a power command is done once the change is seen. The README's
  *Limits* says per maker what was tried: a real device, the maker's emulator or capture, or the
  standard.
- **Stock PiKVM**, tried against kvmd's own test environment (*Limits* in the README says how far):
  its tile says what it is (its platform's model, kvmd's version), a new one is named as it calls
  itself, and it is not offered a restart of itself or Wake-on-LAN, which stock kvmd has not got,
  nor keep-awake where its own settings switch that off.
- **A GL.iNet Fingerbot paired with a Comet presses the power button** of a machine without an ATX
  board: *Press with Fingerbot* (half a second) and *Hold with Fingerbot* (eight seconds, which cuts
  the power), under *Power* and in a run over several machines, where the KVM says one is paired
  (`fingerbot` in `can`; beside a power board's buttons where it has both). Asked first, for
  operators and admins, in the activity log and the history. How hard it presses is set per machine
  (*Fingerbot* in its Edit box, firmly unless set; `fingerbot_strength`). The tile says the
  Fingerbot is there, and when its battery is low (`fingerbot` in the status).
- **A Fingerbot press is done** once the Comet has said the Fingerbot took it and the press's own
  time is over after that (a real Comet answered about two seconds after the press was sent, for
  half a second and eight alike), one at a time per machine. The KVM's "Failed to click" is a
  failure; anything else short of its yes may have been done, and nothing more goes to the
  Fingerbot for as long as that press can last.
- **Keys and the mouse reach a JetKVM in the order they were sent**, though it does each request in
  a task of its own; over a slow link moves of the mouse add up while they wait. A JetKVM that stops
  answering has its connection ended, which lets go of every key, and its tile, history and live
  view do not take that for it going offline, also where a look at it was under way. Keys, typed
  text, the saved actions and keep-awake were seen to arrive on a Windows PC behind a real one.
- **A JetKVM's own channel for keys** (`hidrpc`) is used where its firmware has it (one without it
  is spoken to as before): the live view's keys, moves and clicks go at once and arrive in order,
  and *Type text* is a third faster (96 keys in 2.0 s on a real one). A key held is kept alive as
  the JetKVM's own page keeps it, so when qKVM vanishes it is let go of within a tenth of a second
  (a real one: 50 characters for a key held two seconds and the program killed, where it went on for
  some six seconds before). A JetKVM that answers on that channel after the two seconds it is given
  (a wall busy for seconds) gets its keys over JSON-RPC until then, and over its channel from the
  first moment nothing of qKVM's is down on it or on its way.
- **A JetKVM types in its computer's keyboard layout**, as the JetKVM names it, for the nineteen it
  offers, from tables made of Unicode CLDR's keyboard data; a character the layout cannot type is
  refused before anything is typed, with words that say where in the text and why. The live view's
  keys are places on the keyboard and are not touched by that.
- **Nothing stays down on a JetKVM.** It keeps a mouse button down across a hand-over to its own
  page and across the end of the connection that pressed it (a real one did), so qKVM lets go at the
  hand-over and before it ends a connection, and a connection after one that ended with something
  down begins with nothing down. Whoever holds it live is told at once when its own page is opened;
  then nothing goes to it but the letting go of what it pressed after the hand-over or never
  answered, not even the keep-alive, and an action whose last key was pressed as the page took over
  is done, not refused. A drag begun on one of its two mice (places, and steps) and ended on the
  other is let go of on both; an action that types stops at once where its connection ends under it,
  and says after how many keys.
- **History:** what the wall saw of each machine, kept beside the settings for ninety days
  (`history.sqlite`): the states its tile went through, when it was last heard from, a server's
  temperatures and fans at a slow pace, and the power buttons pressed from the wall. Enlarged, a
  tile says when the machine was last seen and how much of the week it was online, with a small graph
  of the last day's readings. A script reads `GET /api/v1/devices/{id}/history`, and `qkvm status`
  says how large it is (*History* in the README).
- **The history keeps to its size,** 200 MB (or `history_mb`) for the file and its `-wal` file
  together: the `-wal` file goes into the file whenever it passes a tenth of that (8 MB at the most),
  once the reads under way have ended, and one trim brings the file under the size at once, keeping
  as much as fits and the state each machine was in when the kept time begins. A machine puts 128
  readings a minute in it at the most, and only the sensors it reports now are kept in memory.
- **Nobody can keep the others from reading the history:** one read at a time of each account or
  token (the next waits its turn, and after a read as long again as it took), three at once from
  everybody. An enlarged view whose history could not be read asks again after 5 s, then 10, 20 and
  so on up to a minute. A page of `series` leaves out a sensor that does not fit whole.
- **The history goes with its machine,** also when it is too busy to keep up, and so does that of a
  machine whose adding could not be saved. Only damage moves a file aside (a slip of qKVM's own is
  said in the log with its details, and the file is kept); a file moved aside stays as long as the
  history from then, and two in one second are both kept. It works in a data folder on a share
  (`\\server\share\...`) too.
- **The activity log is searched at once, however long it is,** and narrowed to a machine, an
  account and a time, beside its search and its kinds. The page reads an index (`audit.sqlite`) made
  from the text files and nothing else. They stay the record: written first and never rewritten,
  what syslog is sent and what grep reads when qKVM is down. The index holds what they hold and no
  more, and is made again where it is damaged or missing; where it is behind, the page reads the
  files themselves.
- **A download of the activity log** is of what is shown, made a page at a time (never the whole log
  in memory, as it was) and sent once whole, with its length; access is asked again before every
  page is made and as every piece of it is handed to the connection, so nothing more is handed over
  once it is lost (what the connection holds already still arrives). It leaves the disk the room
  the record needs (507 where it would not), and three are made at once, one of each account.
- **Enlarged, a machine shows an admin what was done to it** beside its history: its last three
  entries in the activity log, and the whole of it a click away.
- **Written down now:** a live view opened and ended, with how long it was open (120 entries an hour
  of each account's at the most, and the next says how many were left out); a server's console
  asked for and not had (opened or not had, 120 an hour of each account each, and every server
  opened named at least once an hour); a download of the activity log, with what it was of;
  switching an account's second step off, and erasing every account from the command line (in
  qkvm.log as well). Entries that name a machine give its id (`device_id`), so it is found through
  a rename.
- **Several machines removed at once:** in select mode an admin removes the ticked machines (Remove,
  beside Run action) after a question that names each with its address, says that their saved
  passwords and history go with them for good, and asks for the extra tick where there are several.
  One request, `POST /api/v1/devices/remove`, in the README's table: all of them or none, the
  settings written once, and each removal in the activity log.
- **The API is promised to programs other than the page.** Every request a program needs to show a
  wall, sign in, act and keep a copy of the wall is in one table in the README (*The API*), with its
  fields and refusals, and held to the program by a test. Within `v1` nothing is taken away.
- **A tile says what it can be asked** (`can` in the wall and the status): keys, text, the power
  button, Wake-on-LAN, its inputs, a server's locator light and console, as the device has them. The
  page goes by that, no longer by the kind of device.
- **One file of words** (`words.json`): the states, every code the wall answers with, the kinds of
  device and the words of `can`, with what the page shows for each, for other programs to be built
  from. *Clients and versions* in the README says how a program keeps up with a wall.

### Changed

- **More of the activity log is kept:** 50 MB in ten files, where it was 20 MB, which is some nine
  months of a busy wall (64 machines with alerts on, three people at them). `activity_mb` sets it,
  changed with `--configure-server`; a wall whose settings already say a size keeps it. Reads of
  the log take turns: one at a time of each account, three at once, as the history's do.
- **A KVM's power board is heard on the KVM's line for events** while somebody watches its picture,
  as the KVM's own page does, instead of being asked at every look: a Comet's board answers one
  question at a time, and told whoever asked meanwhile (a second wall, a script) that there was no
  board. A press that must switch the computer on or cut its power is answered as soon as the board
  says the change (on a real Comet, four and a half seconds after the click). The board is asked as
  before where nobody watches, where the line has said nothing, has gone quiet or says there is no
  board, and once before every press (a Comet's line was never seen to say busy). No line is opened
  for the board alone: the PC behind a real Comet woke three times soon after one was.
- **A JetKVM nobody watches is given back after five minutes**, where it was half a minute: looked
  at again within them, its picture is there at once instead of some five seconds later.
- **An update checks the packages it needs:** it is refused where one is missing or its version does
  not meet the new package's requirements, and the start checks an installed update's own
  requirements too, so that a trial installed by the older updater can roll back before it opens
  the data folder.

### Security

- **The settings file is sealed whole** with an independent server storage key kept outside the
  data folder, and a missing key is refused. No key is made anew in a data folder that holds files
  sealed with one (the migration's recovery archive, a damaged copy set aside), where a key not
  found was not mounted or restored yet: the start and `--migrate-vault` ask for it and write
  nothing.
- **A power cut during a settings write locks nothing out.** A second copy (`qkvm.bak`), a temporary
  file or a second copy in the making that it left empty or zero-filled holds nothing, and the start
  and `--migrate-vault` write the second copy anew (`--verify-vault`, which writes nothing, says to
  start qKVM once). The second copy is on the disk, and its folder written out, before and after it
  takes the place of the last one.
- **Pictures are decoded in a sandboxed worker,** away from the KVMs' passwords: native JPEG and
  H.264 work runs in a process of its own under a Linux seccomp filter or a Windows AppContainer,
  with bounded messages, resource limits and deadlines, and no unsandboxed fallback. A decoder or
  encoder belongs to one device connection or live stream, so a worker taken over sees no other
  device's screen, and it ends with its session. JPEG is decoded only within the expected rectangle
  (plus buffer alignment), and a decoded size that disagrees is refused. A JetKVM is asked for H.264
  and retransmission only, so no other decoder is used and no other codec is fallen back to. The
  reviewed WebRTC receiver interface is pinned, and the boundary and container compatibility are
  tested.
- **A worker is held to two processors** on Windows, whatever threads it starts (one where qKVM
  runs on fewer than four; on a machine of more than 64 processors, two processors' worth of time),
  on the pair with the fewest live workers, given back when it ends; on Linux it runs one thread.
  A worker started again after its predecessor died does not go back to that pair while another is
  as free, and a pair whose worker missed its deadline is passed over for a minute while any
  worker still runs on it (an empty pair is always used first). Its pipes are inheritable only for
  the call that starts it.
- **A worker that fails is cleaned up and replaced.** One that does not stop within two seconds of
  being closed (a thread it raised to a high priority can delay that) is reaped once it ends, its
  handles, job and, on Windows, AppContainer profile and processor pair freed. A video session (a
  VNC, Intel AMT or server-console screen, or a Redfish or JetKVM JPEG feed) whose worker stops (a
  deadline kill, out of memory, a stall cleared by a kill) starts a fresh one for the next frame;
  one that keeps stopping, or cannot be started, is started again after a pause that doubles up to
  30 seconds and comes down a step for each minute without a stop, noted in the log once a run and
  at most every ten minutes; a frame refused before it reaches the worker is no stop. When qKVM
  stops, it tells every video worker to end at once and waits for them together, five seconds in
  all, with any still being reaped since its device was closed; one worker's close never stops the
  others' or the runtime's cleanup (the security policy says what a worker that has not ended by
  then leaves behind).
- **Installing requires current video and trust libraries:** the audited minimum versions of aiortc
  and PyAV, and a current certificate trust bundle, so that an existing installation cannot keep the
  compromised emSign trust chain; where an environment is kept by hand, the start warns about older
  ones.
- **A server's tile acts only on the server it was added for.** A controller's maker may put one
  certificate on every board, and a rack often has one password, so after a new lease another
  server's controller could answer at a tile's address, be signed in to with the saved password and
  be sent Power, Reset, Start into BIOS setup, the console's keys and the way into its console. The
  number the server's computer gives for itself (its UUID) and the one its controller's service root
  gives are now remembered when it is added (and carried in an export file); the service root is
  read before the password goes, and the computer before anything is sent, which goes under the
  session that read came under. Where another server answers, nothing is sent to it and the tile
  says so (`another_machine`) until this one answers again; typing the password in an edit takes the
  server that answers now.
- **A stock PiKVM's session no longer goes into the address of its event line,** which its log
  writes down.
- **The in-app updater takes exactly the wheel of the release's own version**
  (`qkvm-<version>-py3-none-any.whl`), where it took the first `qkvm-*.whl` in the order GitHub
  lists the files, and makes its files and folders private even where the process would let others
  write. An update is no longer installed, nor restarted into, for an admin signed out, suspended or
  demoted while the download was waited for: access is checked again before anything is installed
  and before qKVM restarts into it (403 `stopped`), and before an install that failed, or a check
  for updates, says anything of how it went.
- **Releases are made so that what you install is what was tested and scanned:**
  - Only of a commit on the protected branch `main`, which GitHub is asked first (the branch named
    in full, so a tag called `main` is not taken for it), before the tests are waited for and
    anything is built, signed or published; before that still, a tag that is not three numbers
    (`vX.Y.Z`) is refused. A `v*` tag on any commit with a green test run would do before, and an
    odd tag was refused only after its release had been published.
  - Draft first, so that GitHub's immutable releases can be turned on (before, the files were
    attached after publication, which such a release refuses). A `v*` tag runs the checks, build,
    tests, scans and signature, makes a draft with every file attached (the wheel, the source
    archive, `qkvm-<version>-image.json` with what each architecture's scan saw, `SHA256SUMS` and
    its signature), and reads every file back and checks it; its text says by when to publish it
    (two days before its image archives expire). A person reviews and publishes it, as a final
    release: one ticked pre-release goes nowhere.
  - Only then do the registries and PyPI get anything: every file of the published release is
    checked against the signature, and the image archives its signed record names against the scan;
    the registries get the image, and PyPI comes last, as an upload there cannot be undone. The jobs
    that hold the registries' credentials and PyPI's token install nothing and hold their files to
    the list whose signature was checked.
  - The job that holds the signing key only signs, with the runner's own openssl
    (`python -m qkvm.release publish --openssl`, the very signature the cryptography library
    makes), and the library checks it in a job with no secret before the draft is made. Each
    secret is in a GitHub environment of its own, named by the one job that uses it: the signing
    key in `release`, Docker Hub's credentials in `registries`, none in `pypi`.
  - PyPI gets the wheel and the source archive the signed `SHA256SUMS` names, and nothing else, the signature checked
    with the key built into the version. The source archive is in that list and on the GitHub
    release beside the wheel, checked to hold the tested wheel's code file for file and to install
    by itself, and the release's test run runs against the built wheel installed by itself, not the
    source tree. `python -m qkvm.release verify` is the check; with `--signed` it also refuses where
    the checking copy has no key built in. A release whose signed list is not exactly the files of
    its version is not published.
  - What is signed is what was built, tested and scanned: the packages' build tools are pinned by
    hash, and the packages are checksummed right after they are built, then tested, checked and
    audited on a copy held to that checksum. The signing job holds the packages to it, and each
    image's scan record (with its archive's checksum) and native versions to hashes its image job
    took right after the scan; the draft is made of exactly the files the signed list names, with
    the list and its signature, both held to the signing job's hashes. The image's Debian updates,
    Python dependencies and build backend are not pinned: the Dockerfile's `apt-get upgrade` and
    `pip install .` take them when the image is built (the Debian libraries the application needs
    are copied into the final image, and the image's qKVM is built there from the tagged source by
    that backend, not taken from the checked wheel), and what is signed is the image that was then
    scanned and tested. A wheel that holds anything but `qkvm/` and its own dist-info, or a member
    whose name is not plain (`..` and the like, in a zip's Unicode name field too), is refused
    before anything is installed beside it. Every commit's test run builds, checks and installs the
    packages as the release does, on the same runner.
  - The image the registries get is the one the scan saw, never rebuilt: the digest scanned and
    every manifest under it are written down, checked against the scanner's report, and held to
    before the checksum is written and before anything is pushed; each tag is read back, and the
    index the version tags name is checked before they move and after. BuildKit and the SBOM
    generator are named by digest, not by tags that can be moved, and no BuildKit and no action of
    anybody else's runs beside the image job's logins (its tags are named before them).
  - The native code in the image that the scan cannot see (CPython, FFmpeg, libvpx, libopus and
    dav1d in PyAV, the OpenSSL in cryptography, libsrtp and its OpenSSL in pylibsrtp) is asked its
    version inside each image, kept with the scan's evidence and in the signed image record, and
    fails the image where it is below the minimum kept, with its reason, in
    `.github/security/native-minimums.json`, or cannot be read.
  - The built wheel and both container architectures are audited before publication, and the scan
    evidence is kept; exceptions for reviewed, unfixed OS advisories are limited to exact package
    versions and expire.
  - `latest` and `X.Y` move only to the newest released version (of all, and of its line), decided
    right before they move, one image job at a time; a fix to an older line published after a newer
    version moved both back to it. The README says what GitHub's own "Latest" label decides (what
    installed copies are offered), and the workflow warns where it is not on the newest version.
- **The supplied Docker deployment turns on HTTPS and a setup code** for the first account, from the
  first request. **The documented Linux service** does too, and runs as an account of its own, with
  private file modes, no Linux capabilities and protected kernel settings.
- **The container image carries less:** it takes the base system's available security fixes, is
  built on a Python base pinned by digest, and has no pip, no `ensurepip` (a way to put pip back),
  no setuid or setgid programs, and none of the package, account, PAM, mounting, namespace,
  terminal-inspection or Perl tools qKVM does not use. The scan holds them out and checks the Python,
  video and TLS libraries kept; the package inventory and native runtime libraries stay.
- **The container's Python loads no packages from the data volume,** its home (`/data`), where a
  `.pth` file would have run code before qKVM at every start and every health check: the image sets
  `PYTHONNOUSERSITE=1`, starts with `-s`, and checks both.

### Fixed

- **A JetKVM whose computer's screen comes back** (the computer woke, or its screen did) is given
  twenty seconds for its first picture of it, and the picture from before is not handed out as the
  screen meanwhile, to a tile or to a live view that opens; a frame that spans the return is thrown
  away. The wall took that moment for a JetKVM that had stopped sending video, called it offline for
  some seconds (in its history too) and connected again; now only where no picture comes in those
  twenty seconds. Seen on a real JetKVM with a test PC behind it, as were the press of its ATX
  extension that woke the PC and the power light it read.
- **A JetKVM's tile no longer says "in use"** until somebody clicks *Show here* where a connection of
  the wall's own, slow to close, hears that the wall's new one took the viewer.
- **A JetKVM's video connection still closing** when its tile is edited or removed, or qKVM stops,
  is held until it has closed, and its close is begun before the video worker is closed: the
  garbage collector could throw the close away halfway.
- **A KVM's power board, as a real GL.iNet Comet with its ATX board showed it.** The tile says
  whether the computer is on by the board's own word: a Comet's power light in kvmd's answer stays
  "off" whatever the computer does, and the wall said "off" of a running PC, in its history too. A
  board that tells another asker "no board" for a moment no longer takes the power buttons away. A
  computer whose board says it is off is "off or asleep" on its tile and in the alert, where the
  tile said the KVM was slow to answer for as long as it was off.
- **A power board's press is answered once the board has let go of the button,** which it holds on
  after answering (six and a half seconds for the long press), so a second press meanwhile is
  refused as one thing at a time; a press that must switch the computer on, or cut its power, once
  the board shows that or says it did not. Only the board's no is "not pressed": an answer that says
  neither (the KVM's web server's 502, 503 or 504 while kvmd restarts, kvmd's own 500), none in
  time, or one that broke off may have been done, and the board (and a Fingerbot on the machine) is
  left alone for some seconds after it, whoever asks. A press cut off by qKVM stopping while the
  board held it is written down as pressed, and the page no longer offers to send again an action
  whose answer broke off or was no answer of the wall's own: it may have been done.
- **A server's press says "may have been done" where that is what is known:** a switching on of
  which no look came back is a maybe (504), not a failure, and so is a command the controller
  answers with an error of its own (5xx); only a 4xx is a refusal. It was "failed", and *Retry
  failed* pressed a reset again.
- **A controller whose Redfish root takes some seconds to answer**, as an older firmware's did, is
  known for a server's controller when it is added; it was taken for a KVM, and whoever added it was
  told that it did not respond in time.
- **The picture of every kvmd KVM is held from the first one on,** and no longer breaks off to the
  KVM's own "no live video" ten seconds after somebody else stopped watching it.
- **Removing one machine writes the settings first,** as removing several does: a disk that refuses
  the change leaves it on the wall with its live lines, its keys and what is being done to it
  untouched, where it was told that the machine was gone and then that nothing had changed.
- **The activity log's files move on without loss:** a step that fails (a file held open on Windows)
  no longer loses an old file, and a line cut off by a power cut no longer swallows the next entry.
- **Saving the settings on Windows waits out a brief lock** (a reader holding the file for a moment)
  for a bounded time, so a newly learned server identity is not lost; a lasting failure still says
  that the save failed, and stale backups are handled as before.
- **A closed enlarged view stays closed:** an enlargement still waiting for its animation is
  cancelled by Escape, signing out or a newer view.
- **A busy button's spinner keeps turning** where the system asks for less motion (it stopped half
  way round), and adding an address again replaces what the earlier try said of it.

### Upgrading from 0.1.x

- **One offline step.** 0.2.0 does not start on a 0.1.x data folder until it is converted with
  `--migrate-vault`, with qKVM stopped. The conversion keeps everything a 0.1.x wall holds
  (accounts, passwords, two-factor and device credentials among it) and an encrypted recovery
  archive; `--verify-vault` checks the converted folder together with its key. The README's *From
  0.1.x to 0.2.0, and back* gives the steps, and the security policy the exact container commands.
- **In short:** stop qKVM; copy the data folder (or volume) aside; upgrade with pip (not *Install*
  in *Settings > Updates*) or take the 0.2.0 image; run `--migrate-vault`, then `--verify-vault`,
  with the key outside the data folder; back the key up separately; start.
- **In a container the key needs a volume of its own,** such as `-v qkvm-keys:/keys` beside `/data`.
  The image gives `/keys` no volume, and a new key is made only in a folder that is a mount of its
  own and outlasts the container (not a tmpfs, an anonymous volume or a pod's emptyDir); elsewhere
  the start and `--migrate-vault` refuse before anything is written, and say what to mount. The
  migration and the verification say where the key is, never what it is.
- **The migration can be run again:** it leaves alone a damaged file that a start set aside sealed,
  instead of refusing it or calling it plaintext.
- **Where 0.1.x's own *Install* tries 0.2.0 anyway,** that trial can go back to its previous version
  only while the data is still untouched 0.1.x data (with what 0.1.x itself leaves and passes over:
  an empty file a power cut left, a damaged copy it set aside, the second copy alone): migrated data
  and a missing storage key never send it back.
- **Going back** means starting 0.1.1 on the copy made before the conversion: older versions cannot
  read the converted folder, and 0.1.1's advice to move the files aside would leave a new wall that
  anyone could claim.
- **Earlier backups stay sensitive** after the conversion: read `SECURITY.md` before upgrading.
- **The activity log is there from the first day:** at the first start its index is made from the
  files 0.1.x wrote, so whatever they still hold is searched at once.
- **A server's tile from 0.1.x** takes its server's number from what it kept then, so after the
  upgrade another server that answers at its address first is sent nothing but its first sign-in:
  the controller's number, asked before the password goes from then on, is not known yet.

### Known limits

The README's *Limits* says what was tried on a real device, what against a maker's own emulator or
capture, and what was built from the standard and tried on a stand-in. Those that matter most:

- **Intel AMT is experimental:** tried on one real PC, set up in admin control mode without user
  consent. Client control mode, consent, the plain port, the network search and telling another PC
  at the address apart were tried against a stand-in only. A reader for the PC's serial console
  (Serial over LAN) is built and was tried on the real PC, which wrote nothing there: this version
  shows nothing of it.
- **No real PiKVM, iDRAC or iLO has been tried** (stock kvmd in its own test environment, Dell's
  capture and HPE's emulator have), and no controller of Supermicro, Lenovo or another maker.
- **An OpenBMC console** was built from OpenBMC's source and tried against a stand-in only
  (OpenBMC's own image in QEMU has none), and takes no keys from qKVM.
- **The VNC reader** was tried against TigerVNC and QEMU, and a libvirt guest's console was shown;
  TightVNC, RealVNC, x11vnc and a controller's own VNC server have not been tried.
- **A JetKVM's** long press, reset, Wake-on-LAN, password and HTTPS, a firmware without `hidrpc` and
  typed text in a layout other than US were tried against a stand-in only. Its H.264 is not passed
  on to the live view. A few moments can leave a key or a button down on it, such as Ctrl, Shift,
  Alt or Win held when qKVM vanishes (until the JetKVM notices), or a key sent in the second after a
  hand-over over a slow link: the README's *Limits* names them.
- **A server's AMI console** took typed keys on a real board; the pointer's effect was not seen, and
  a board set to a relative mouse was not tried. Switching an off server on into its BIOS setup was
  not tried on a real board, and another server at a tile's address only on a stand-in.
- **A Proxmox cluster** of several nodes, a guest moved between them and a guest with the QEMU guest
  agent were tried against a stand-in only. A guest deleted and another made with its number in the
  moment between the question and the command is not told apart. Containers on Proxmox are not
  shown.
- **A Fingerbot's presses** were sent on a real Comet with the Fingerbot lying loose on a desk, so
  they pressed no real power button.
- **macOS has no verified sandbox for native video:** the video paths that need one, JetKVM's
  connection included, refuse to start there, and full macOS support is not claimed.
- **Not supported:** KVMs with two-factor login, Sipeed NanoKVM, IPMI without Redfish, XCP-ng,
  Citrix Hypervisor, VMware ESXi and Hyper-V. **Not tried:** Safari, and the browsers of phones and
  tablets (the page's tests run in Chromium, and most of them once in Firefox).
- **Also in the README's *Limits*:** an unlock file handed over as a systemd credential
  (`LoadCredential`) has not been tried, and where every browser reaches qKVM from one address and
  no proxy says who is who (as through ports Docker Desktop publishes), the lock after wrong
  passwords applies to all of them at once.

## 0.1.1

0.1.0 under its name written qKVM, with three things in the program put right, four tests
and the test bed made right, the security policy's paragraph on updates corrected and the
README's release steps rewritten. A release's own test run is green on all thirteen jobs
GitHub runs (the run of 0.1.0's tag was red in one); on Python 3.11 what is told to stop
stops, also while a device keeps sending; and a device that does not answer the wall's
goodbye is hung up on.

- The name is written **qKVM**, with a small q, wherever the program, its README and its pages
  say it. Nothing a script or a setup depends on changes with it: the package, the command, the
  container image, the settings folder and the web addresses are `qkvm` as before, and so are
  the `X-QKVM` header the page sends and the `"app": "QKVM"` field of an alert's webhook.
- A new mark: the wall's four screens, the lower right one carried on down and the left two
  rounded on the outside, so that they read as a small q. It is the program's icon and stands
  in its top bar, where the q of the name is in the accent blue. The README opens with it, a
  line on what qKVM is, the links and a picture of the wall.
- On Python 3.11, a device's connection that was told to stop while the device kept sending did
  not stop. A KVM taken off the wall or changed, a server whose console was sending its screen,
  every device when the wall itself was stopped: the reader of what the device sends was told to
  stop in the moment a message arrived, and went on reading as if it had not been told. Against a
  device that sends without pause that can be every time (in the trials here it was, on Windows,
  and on Linux with a message every thousandth of a second). A KVM's connection lived on for up
  to half a minute after it had left the wall; a server's console kept its seat on the
  controller for up to twenty seconds more; a JetKVM changed or taken off the wall in the second
  it was connecting could hold up that change for up to half a minute; a text being typed on a
  JetKVM when qKVM was stopped could go on with the next keys until its connection was closed
  under it. Python 3.11's `asyncio.wait_for` hands back what it waited for where a stop comes in
  the same moment, and the stop is lost (3.12 rewrote it). The program no longer uses it: it
  waits within a time with `asyncio.timeout`, and a test fails when `asyncio.wait_for` is
  written in it again. (The new tests failed on the program as it was, with Python 3.11 on
  Windows and on Linux.)
- A KVM speaking kvmd (Comet, PiKVM) or a server taken off the wall or changed, or every one when
  the wall is stopped, is told goodbye, and its connection is closed once the device answers
  that. A device that had not answered within half a second could keep its connection open for
  as long as it liked: whoever retires such a device tells it to stop once more after half a
  second, and that cut the goodbye short and left the connection as it was, with nobody reading
  it. A server's controller kept
  the console's seat that way. A goodbye cut short now ends the connection at once, on every
  Python. (The new tests failed on the program as it was: a KVM that does not answer the goodbye
  was never hung up on, and a server whose console was slow to take the goodbye kept it open.)
- After a lock on sign-ins (thirty seconds after five wrong guesses, doubling, fifteen minutes
  at most), the wait that was said could be a floating-point hair more than the lock: "try
  again in 31 s", or "901 s", and `Retry-After` the same, where 30 or 900 was meant. Only on
  Windows with Python 3.11 or 3.12, where the clock stands still for sixteen thousandths of a
  second at a time, and only for a try that comes within the same instant as the lock, so for
  a script rather than a person. The wait said is never more than the lock was set for now.
  (The test that asks for exactly that, for the longest lock, failed by what the clock
  happened to read, about one run in five on such a machine; one pins the clock to such a
  value now, for the first lock and the longest, and failed on the program as it was.)
- The security policy (`SECURITY.md`) said that the versions so far have no release key built
  in and install nothing by themselves. That has been wrong since 0.1.0: the publisher's key is
  built in since 0.1.0, as the README's *Updates* chapter says, and a release signed with it is
  installed from inside the app when you click for it (not in a container, which is updated by
  pulling the new image, and not a release that needs a package this copy has not, which is
  installed with pip). The policy says so now, and also what a copy built without a key does,
  `--allow-unsigned-updates` included.
- The README's *Publishing releases* says the order of a release: a green test run of the
  commit, the version and its chapter here, the tag; what the release workflow then checks,
  runs and publishes; and that the project's sites are built after the release, because their
  build waits for the version on PyPI.
- The stand-in devices of the test bed (the KVM, the JetKVM, the controller, GitHub, and the
  scripted device) wait for their server to be up instead of ten seconds, for a loaded machine;
  one whose server fails to start says so at once, and why.
- The test for a device that says something and resets the connection in the same breath let
  the words come while the wall was between two reads. On Windows what arrived then is thrown
  away by the system itself once the reset lands behind it (Linux hands it over), and a wall
  that is late to look, as on a loaded machine, has lost those words before the program sees
  anything: 18 of 40 heard on GitHub's machine, 39 of 40 on an idle one. The test now has the
  wall reading when the words come, and then not looking until the device has hung up, so that
  the reset is known of before the words are handed over, which is the moment they used to be
  thrown away by the program. Forty in forty, loaded or not; on the program as it was before
  that fix, none or one in forty.
- The test for a flood of pings counts the frames the wall worked through before it hung up
  by itself, not by the wall's count of the second it is in; and its stand-in's reader no
  longer ends with a warning when the wall hangs up on it.
- Two tests stood in another certificate's fingerprint by writing AA over its first byte. One
  real fingerprint in 256 begins with AA, and then the stand-in was the real one: one of them
  failed so on GitHub's Windows with Python 3.13, the other would have proved nothing. They
  take another first byte than the real one's now.
- The page and the README write their punctuation plainly: menu paths as Settings > Security,
  three dots where a word trails off, straight quotes.

## 0.1.0

The first public version.

- **The wall:** a live picture and the status of every KVM on one page, drawn pixel for pixel;
  enlarge one, filter by state, search, light and dark themes.
- **Devices:** GL.iNet Comet and Comet Pro, the four-port Comet X (with port switching), other
  KVMs speaking the PiKVM `kvmd` API, and JetKVM.
- **Servers** through their management controller (Redfish): the server's own screen on its
  tile where the controller's console can be read (AMI MegaRAC), power state, health,
  temperatures and fans, the power and reset buttons, the locator light, and the controller's
  own console one click away, signed in where it allows that. The wall only looks, and keeps
  out of the way of whoever works at that console: they are let in at once, and a console
  somebody is already using is left to them.
- **A JetKVM as its owner set it up**: over HTTPS wherever it offers that (its own certificate
  remembered on first contact), over plain HTTP where it does not, with a password or
  without, and followed when its HTTPS mode is switched later. Known by its own number, so
  it is one tile under whichever address.
- **Actions**, on one machine or on a selection: key combinations, typed text, your own saved
  actions, keep-awake, ATX power and reset, Wake-on-LAN, reboot of the KVM.
- **Accounts:** admin, operator and viewer roles, accounts limited to groups or single KVMs,
  accounts that can be suspended, two-factor
  sign-in with an authenticator app that can be required of a role and above, one-time codes
  for a phone that is not at hand, a recovery key for a forgotten password, an activity log
  that says who did what, to search and to download.
- **Export and import:** the devices, saved actions and settings of a wall as a file, to
  keep or to take to another qKVM. Encrypted with a passphrase it carries the devices'
  passwords; plain, it carries none. Taking a file in adds what is not there and changes
  nothing that is.
- **Alerts** to ntfy, Slack, Discord or any webhook when a KVM goes offline, loses its
  picture, has a problem, or recovers.
- **Metrics** for Prometheus and what reads its format, behind a token of their own.
- **Groups and display mode** for a monitor on the wall.
- **`qkvm status`, `qkvm stop`, `qkvm restart`** for the copy that runs already, from any
  window; a second copy started with the same data folder says which process holds it.
- **Your own order:** an admin arranges the tiles by dragging them or by numbering them, and
  the order is the wall's, the same on every screen; each browser may still sort by name, by
  group, or with what needs attention first.
- **Find KVMs on my network** when adding devices. A device reachable by two addresses is
  recognised as one, in the search and when it is added.
- **Protection:** no saved password readable in the data folder without an account's password,
  each KVM's certificate remembered, strict page policy, HTTPS from the first request if asked
  for, a list of the addresses it answers (`--allow-from`), one action at a time per machine.
- **Sign-on through your identity provider:** a reverse proxy that signs people in says who
  they are (`--sso-header`), for accounts that then need no password here.
- **The activity log sent on** to a syslog collector as it is written (`--audit-syslog`).
- **Tokens** for scripts (a role, the machines it is for, an end date) and **links for wall
  screens** that come back by themselves after a restart.
- **Carrying on after a restart** by itself: watching, alerts and metrics go on without
  anybody signing in, and a browser that asked to be kept signed in stays so. The key for
  that lies in the data folder; `--unlock-file` keeps it elsewhere, `--locked-start` keeps
  none.
- **Running it:** `pip install qkvm`, or the container image (amd64 and arm64); settings in
  one folder, `.qkvm` in your home folder, wherever it is started; updates from inside the
  app, with roll-back.
