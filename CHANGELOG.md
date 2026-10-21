# Changes

## 0.2.0

- Remove unused mounting, namespace, terminal-inspection and Perl packages from the container; enforce their absence in image scans and verify retained Python/video/TLS dependencies.

- Discard a JetKVM frame receive that overlaps a returning video signal instead of marking its potentially old picture as current.

- Audit-log downloads stop before sending another chunk when their session or administrator access is revoked.

- Relative mouse movement no longer fabricates button changes during pointer-lock cursor warps; the capture click cannot become a remote click. CI now runs all eight browser suites.

- Recheck live-view access before every screen delivery and input dispatch, including input waiting for controller handover. A stalled device-status request no longer delays revocation.
- Enable HTTPS and protected first-run setup in the supplied Docker deployment, and remove unnecessary setuid/setgid permissions from the runtime image.

- **Settings saves tolerate brief Windows file locks.** Atomic replacement of the settings
  and their backup retries temporary access and sharing errors for a bounded time. A reader
  briefly holding the file no longer loses a newly learned server identity; persistent
  failures still report that the save failed, and stale backups are handled as before.
- **Live control ends when access is revoked.** A request that waited for a device to open its
  keyboard and mouse checks the account's or token's access again before granting control;
  an existing holder who is no longer allowed to control the machine is released.
- **Compressed VNC pictures cannot retain an ever-growing tail of input.** ZRLE and Tight
  reject trailing bytes and reuse of an ended compression stream, including idle or empty
  ZRLE updates. Valid continuing streams and Tight's stream resets still work.
- **Updates check the dependencies their package requires.** An update is refused when an
  applicable dependency is missing or its installed version does not meet the new package's
  requirements. Startup checks an installed update's own metadata too, so a trial installed
  by the older updater can roll back before opening the data folder. Use pip for the first
  upgrade from 0.1.x.
- **The container applies available OS security fixes and removes pip after installation.**
  Its Python base is pinned by digest. Release jobs audit the built wheel and both container
  architectures before publication, retain scan evidence, and publish the checked images
  without rebuilding them. Temporary exceptions for reviewed, unfixed OS advisories are
  limited to exact package versions and expire.

- **A JetKVM whose computer's screen comes back** (the computer woke, or its screen did) is given
  twenty seconds for its first picture of it, and the picture from before is not handed out as the
  screen meanwhile, to a tile or to a live view that opens. The wall took that moment for a JetKVM
  that had stopped sending video: it called it offline for some seconds, in its history too, and
  connected again; it does so now only where no picture comes in those twenty seconds. Seen on a
  real JetKVM with a test PC behind it, as were the press of its ATX extension that woke the PC
  and the power light it read.
- **A server's tile acts only on the server it was added for.** A controller's maker may put one
  certificate on every board, and a rack often has one password, so after a new lease another
  server's controller could answer at a tile's address, be signed in to with the saved password
  and be sent Power, Reset, Start into BIOS setup, the console's keys and the way into its
  console. Now the number the server's computer gives for itself (its UUID) and the one its
  controller's service root gives are remembered when it is added (and carried in an export
  file); the service root is read before the password goes, and the computer before anything is
  sent, which goes under the session that read came under. Where another server answers, nothing
  is sent to it and the tile says so (`another_machine`) until this one answers again; typing the
  password in an edit takes the server that answers now. A tile from 0.1 takes its server's number
  from what it kept then, so after an upgrade nothing is sent to a server that answers first but
  its first sign-in (the controller's number, asked before the password goes from then on, is
  not known yet).
- **A server's press says "may have been done" where that is what is known.** A server switched
  on into its BIOS setup is waited for through the minute its controller answers nothing after a
  change of the boot override (it was said "still off, not carried out"); a switching on of which
  no look came back at all is a maybe (504), not a failure; a command the controller answers
  with an error of its own (5xx) is a maybe, where only a 4xx is a refusal (it was "failed", and
  *Retry failed* pressed a reset again). Start into BIOS setup goes by the power the read-back of
  the boot override shows, where the controller's answer is read back: a server switched on
  meanwhile is restarted, not sent *On*.
- **A PC with Intel AMT:** a power command whose answer cannot be read (no `ReturnValue`, or no
  SOAP at all) may have been done (504), as one whose answer did not come back, and is no longer
  kept as failed and offered for *Retry failed*; a still that gives up waiting for its session
  closes the session it began (or, where its sign-in is on its way, the moment it is open), where
  it left it open, and Intel's border on the PC, for a minute; and Start into BIOS setup has the
  two minutes Redfish's has, past which it sends nothing more and clears what it armed.
- **The activity log can be narrowed to a machine, an account and a time,** beside its search
  and its kinds, and is searched at once however long it is: the page reads an index of it
  (`audit.sqlite`), made from its text files and from nothing else. The text files stay the
  record, written first and never rewritten, what syslog is sent and what grep reads when qKVM
  is down; the index holds what they hold and no more, is made again from them where it is
  damaged or missing, and at the first start of this version from the files an earlier one
  wrote, so what those files hold is there from the first day. Where it is behind, the page
  reads the files themselves. A download is of what is shown, made a page at a time (never the
  whole log in memory, as it was) and sent once it is whole, with its length; it leaves the disk
  the room the record needs (507 where it would not), and three are made at once, one of each
  account.
- **More of it is kept:** 100 MB in ten files, where it was 20 MB: a year and a half of a busy
  wall (64 machines with alerts on, three people at them), and `activity_mb` in `qkvm.json`
  sets it. Moving the files on no longer loses an old one where a step fails (a file held open
  on Windows), and a line cut off by a power cut no longer swallows the first entry after it.
- **Enlarged, a machine shows an admin what was done to it** beside its history: the last three
  entries of the activity log that are of it, and the whole of it a click away.
- **Written down now:** a live view opened and ended (with how long it was open; 120 entries an
  hour of each account's live views at the most, and the next one says how many were left out),
  a server's console asked for and not had (a console's entries, opened or not had, 120 an hour
  of each account at the most, as a live view's, and each server opened named at least once an
  hour), and a download of the activity log with what it was of. Entries that name a machine
  give its id as well (`device_id`), so that what was done to a machine is found through a
  rename. Reads of the activity log are one at a time of each account
  and three at once, as the history's are. Switching an account's second step off and erasing
  every account from the command line are in the activity log as well as in qkvm.log.
- **A data folder on a share** (`\\server\share\...`) has its history read: SQLite refused the
  address Python gave it, and every read of the history failed there.
- **Start into BIOS setup.** A new power action for a PC with Intel AMT, and for a server over
  Redfish, boots the machine into its firmware setup once and then switches it on (if off) or
  restarts it (if on), so it comes up in its BIOS setup; its large view opens so the setup screen
  shows from the start. The question before it names the machine and says whether it will be
  switched on or restarted. It is offered only where the machine says it can do it (Intel's
  `AMT_BootCapabilities`, or a Redfish board that allows the "BiosSetup" boot override), to an
  operator or an admin, one machine at a time (not in a bulk run), and is written in the activity
  log. The setup boot is single use: it clears at the next boot. A boot override another tool
  set, or a boot option that destroys data, is not replaced, and a machine changing its power
  state just then is left alone (nothing is done, and it is said); where the power change is
  refused for certain, the setup boot is cleared again, and where it may have gone through, it
  is left and the button says so.
- **A PC with Intel AMT whose tile is only shown costs its monitor almost nothing.** Where before
  qKVM held a KVM session open the whole time such a tile was watched (so Intel's red and yellow
  border was on the PC's own monitor all that while), it now takes a still picture every five
  minutes, each a short session, so the border is on the PC only for the few seconds each still
  takes. The tile shows the cached still between them, and says how old it is. A session is held
  open only while the machine is enlarged or its live view is open, and one is opened before
  *Power on* (or *Start into BIOS setup*) when that view is open, so the start shows from the
  first moment. How the KVM is set up (consent) is read at most every five minutes.
- **A guest of Proxmox's console is held five minutes after the last viewer** (it was a minute),
  and a Proxmox that reports a guest stopped and running by turns has a console opened for it at
  most once every five minutes, where before one was opened at every other look.
- **An admin can take over a machine's keyboard and mouse** from whoever holds them in the live
  view: where Control is refused because somebody else has them, an admin sees **Take over from**
  and their name, and is asked first. Whoever held them is told who took them, everything they had
  down is let go of, and nothing more of theirs goes out; the activity log says who took them from
  whom. An operator never takes them from anybody, nor does a token or a wall screen, and
  an admin's action from the wall does not take over by itself (its refusal says where it can be
  done). The page waits for the answer as long as a machine can take to hand them over (up to a
  minute: a JetKVM connected anew took some forty-seven seconds) and says it is asking, and the
  wall answers within that time: given up on after five seconds, a slow take-over went on at the
  wall and left nobody holding the machine. An admin who closes the view meanwhile takes nothing.
- **Keyboard and mouse are given back after 15 minutes without input** from whoever holds them:
  what they had down is let go of, they are told why, and the picture goes on.
- **One hand at a time on a machine:** whoever gets its keyboard and mouse next sends nothing until
  what the one before had down has been let go of, and what was still on its way has landed and
  been let go of again, and so does an action from the wall. A key of the new holder's no longer
  lands beside a Ctrl of the one before. A saved action edited or removed while it waited so is
  not sent as it was when it was clicked: it is refused, and nothing is sent.
- **Removing one machine writes the settings first,** as removing several does: a disk that
  refuses the change leaves it on the wall with its live lines, its keys and what is being done to
  it untouched, where it was told that the machine was gone and then that nothing had changed.
- **The history holds to the size it is allowed, and nobody can keep the others from reading it.**
  The 200 MB (or whatever `history_mb` says) is the file and its `-wal` file together: the
  `-wal` file is brought into the file whenever it grows past a tenth of that (8 MB at the
  most), once the reads under way have ended, where reads that overlapped kept it growing for as
  long as they came, past the size allowed; and one trim brings the file under the size at once,
  keeping as much as fits, where it took several rounds ten minutes apart, and keeping the state each machine was in
  when the time kept begins (a machine online for a hundred days that changed an hour ago was counted as watched for
  one hour of the week). Of each account or token one read of the
  history at a time is answered (the next waits its turn, and after a read as long again as it
  took), so that one viewer's script can no longer take the three reads that are answered at
  once from everybody else; an enlarged view whose history could not be read asks again after
  5 s, then 10, 20 and so on up to the minute, instead of every 5 s. One machine puts 128
  readings a minute in the history at the most, and only the sensors it reports now are kept in
  memory (a controller that named its sensors anew at every look grew it without end). A page of
  `series` leaves out a sensor that does not fit whole, as the README said it did. A machine
  taken off the wall takes its history with it also when the history is too busy to keep up,
  and so does one whose adding could not be saved. A file moved aside as damaged stays as long
  as the history from when it was moved aside (it was deleted at once where it had last been
  written long before), two in one second are both kept, and only damage moves a file aside:
  a slip of qKVM's own is said in the log with its details, and the file is kept.
- **A console over `vncs://`** is said to be encrypted in the list of KVMs, with how its
  certificate is checked, and the summary of a file to import says when its certificate is not
  checked; both said so only of addresses with `https://`.
- **A guest of Proxmox moved to another address** asks for its API token to be typed again,
  as a server's controller does: a certificate remembered for it vouched for any host that
  showed the same one (a proxy, a wildcard), and the saved token went there.
- **A guest of Proxmox is the one its tile was added for, and no other.** Proxmox gives a new
  virtual machine the number of one that was deleted, and the old guest's tile went green again
  with the new one behind it: its screen shown to whoever may see the old guest, its power buttons
  pressed, keys, typed text and saved texts sent into its console, on its node or, followed there
  without a word, on another. A guest is known by its SMBIOS UUID now, remembered when it is added
  and asked again before every power button, before each console and before it is followed to
  another node, and by a look once a minute and wherever it finds the guest stopped, started or
  started again: another virtual machine is sent nothing, and the tile says so. Typing the token's
  secret in an edit takes the one that has the number now.
- **A VNC server over `vncs://` whose certificate changed can be trusted again from the page:**
  its certificate dialog showed nothing, and *Trust this certificate* asked for the certificate
  at port 443 of its host, somebody else's. Its edit dialog shows the certificate remembered, as
  for an address with `https://`.
- **A VNC server that draws one frame and hangs up** is connected to less and less often, as one
  that hangs up after its handshake is: the frame was taken for the server being well again, and
  it was connected to, its password answered, every second for good. A frame counts once its
  connection has lasted five seconds as well.
- **Switching a guest of Proxmox on or stopping it answers within its time, counted from the
  press:** the questions the press was decided by were not counted, and each look at the guest
  while it was waited for was given a request's whole time, so a Proxmox slow to answer kept the
  button past the page's two and a half minutes.

- **Several machines removed at once.** In select mode an admin removes the ticked machines in
  one go (Remove, beside Run action), after a question that names each of them with its
  address, says that their saved passwords and their history go with them for good, and asks
  for the extra tick where there are several. One request, `POST /api/v1/devices/remove`, in
  the README's table: every one of them or none, the settings written once, and each removal
  in the activity log as before.
- **A JetKVM, as a real one with a Windows PC behind it showed it.** Keys and the mouse in the
  live view reach it in the order they were sent: a JetKVM does each request in a task of its own,
  and sent without waiting a real one typed the alphabet out of order and kept a key and a mouse
  button down; over a slow link moves of the mouse add up while they wait, and a JetKVM that stops
  answering has its connection ended, which lets go of every key (its tile, its history and the
  live view do not take that for the JetKVM going offline, also where a look at it was under way
  as the wall ended the connection). Whoever holds its keyboard and
  mouse in the live view is told at once when somebody opens the JetKVM's own page, where they heard
  of it only at their next key, and nothing more is sent to it but the letting go of a key or a
  mouse button that the JetKVM pressed after it had handed its viewer over, or never answered; an
  action whose last key was pressed when the page took over is done, not refused. A connection of
  the wall's own that is slow to close, and hears that the wall's new one took the viewer, no longer
  has the tile say "in use" until somebody clicks *Show here*. Keys, typed text,
  the saved actions and keep-awake were seen to arrive on the PC (the README, "Limits").

- **A KVM's power board heard on the KVM's line for events.** While somebody watches a KVM's
  picture, the wall hears its power board on the KVM's own WebSocket for events, which it holds
  for the picture anyway, as the KVM's page does, instead of asking it at every look: a Comet's
  board answers one question at a time and told whoever asked meanwhile (a second wall, a script)
  that there was no board, because this wall had asked. A press that must switch the computer on
  or cut its power is answered as soon as the board says the change (on a real Comet, four and a
  half seconds after the click, the moment its line said "on"). The board is asked as before where
  nobody watches the picture, where the line has said nothing, has gone quiet or says there is no
  board, and once before every press (a Comet's line was never seen to say busy). No line is
  opened for the board alone: the PC behind a real Comet woke three times soon after one was.
- **Keys and the mouse in the live view, on a real Comet.** Keys arrived each once at any pace
  (fifteen letters sent in one go among them), within some 25 milliseconds of being sent, and nothing
  stayed down when the keyboard was given back or the line was cut. Its mouse was set to relative
  on the KVM, and every place the page sent was dropped there: the line now says how a machine's
  pointer is moved (`pointer` in its `state` message), and the page follows it. Where the mouse
  moves by steps only, a click on the picture hands the pointer over (Esc gives it back) and no
  place is sent; where it takes places only, *Relative mouse* is not offered. A pointer lock the
  browser grants only after keyboard and mouse were given back (Firefox and Safari say nothing of
  when) is let go of as it comes, where it kept this PC's pointer until Esc.
- **Keys and the mouse to a JetKVM over its own channel for them** (`hidrpc`), as its own page
  sends them, where it has one (a firmware without it is spoken to as before): the live view's keys,
  moves and clicks go at once, without waiting for the one before, and arrive in order; a key held
  in the live view is kept alive the way the page keeps it, so that when qKVM vanishes the JetKVM
  lets go of it within a tenth of a second (a real one: 50 characters for a key held two seconds and
  the program killed, where it went on for some six seconds before); *Type text* is a third faster
  (96 keys in 2.0 s on a real one). A JetKVM keeps a mouse button down across a hand-over to its
  own page and across the end of the connection that pressed it (a real one did): qKVM lets go of
  it at the hand-over and before it ends a connection itself, and a connection after one that ended
  with something down begins with nothing down. At a hand-over nothing goes to the JetKVM but that
  one letting go, also not the keep-alive. **Typed text goes in the keyboard layout the JetKVM says
  its computer uses**, for the nineteen it offers, from tables made of Unicode CLDR's keyboard data;
  a character the layout cannot type is refused before anything is typed, with words that say where
  in the text and why. A drag begun on one of the JetKVM's two mice (places, and steps) and ended on
  the other is let go of on both. An action that types stops at once where its connection ends under
  it, and says after how many keys. The live view's keys are places on the keyboard and are not touched by that. A JetKVM
  nobody watches any more is given back five minutes later (it was half a minute): looked at again
  within them, its picture is there at once instead of some five seconds later. A JetKVM whose
  answer to qKVM's question on that channel comes after the two seconds it is given (a wall busy for
  seconds) gets its keys over JSON-RPC until it comes, and over its own channel from the first
  moment nothing of qKVM's is down on it or on its way. See the README, *JetKVM* and *Limits*.

- **A GL.iNet Fingerbot paired with a Comet presses the power button,** for a machine without an
  ATX board: *Press with Fingerbot* (half a second) and *Hold with Fingerbot* (eight seconds, which
  cuts the power) under *Power* and in a run over several machines, where the KVM says one is
  paired (`fingerbot` in `can`; beside a power board's buttons where it has both), asked first,
  for operators and admins, in the activity log and the history. How hard it presses is each
  machine's own (*Fingerbot* in its Edit box: firmly unless set; `fingerbot_strength`). A press is
  done once the Comet has said the Fingerbot took it and the press's own time is over after that
  (a real Comet answered about two seconds after the press was sent, for half a second and eight
  alike), one at a time per machine; the KVM's own refusal ("Failed to click") is a failure, and
  anything else that is not its yes "may have been done", after which nothing more goes to the
  Fingerbot for as long as that press can last. The tile says the Fingerbot is there, and when its battery is low (`fingerbot` in the
  status). Tried on a real Comet with a Fingerbot lying loose on a desk (the README, "Limits").

- **A KVM's power board, as a real GL.iNet Comet with its ATX board showed it.** The tile says
  whether the computer is on by the board's own word (a Comet's power light in kvmd's answer stays
  "off" whatever the computer does, and the wall said "off" of a running PC, and kept that in the
  history); a board that tells another asker "no board" for a moment no longer takes the tile's
  power buttons away. A press is answered once the board has let go of the button, which it holds
  on after answering (six and a half seconds for the long press), so that a second press meanwhile
  is refused as one thing at a time; and a press that must switch the computer on, or cut its
  power, is answered once the board shows that, or says that it did not. A computer whose board
  says it is off is "off or asleep" on its tile and in the alert, where the tile said "Connecting...
  The KVM is slow to answer" for as long as it was off. A press cut off by qKVM stopping while the board held it is
  written down as pressed, and the page no longer offers to send again an action whose answer broke
  off on its way or was no answer of the wall's own: it may have been done. Only the board's no is
  "not pressed": an answer that says neither (the KVM's web server's 502, 503 or 504 while kvmd
  restarts, kvmd's own 500), none in time, or one that broke off may have been done, and the board
  (and a Fingerbot on the same machine) is left alone for some seconds after it, whoever asks.

- **A machine live, with its keyboard and mouse,** over one connection per viewer (the README,
  "Live view and control"): a KVM's own H.264 stream passed on where it has one (stock PiKVM,
  and a GL.iNet Comet on a recent GLKVM firmware), its pictures one after the other where it has not, a JetKVM's as JPEG, a
  server's screen as it changes. One connection holds a machine's keyboard and mouse at a
  time; the activity log says who took them and gave them back, never a key. The page's
  enlarged view speaks it (Control, or the key C), and so does the qKVM desktop program.
  Read again for this release: a key or a mouse button still on its way when a line loses the
  keyboard (a PC with Intel AMT waits up to ten seconds for its next session) is let go of again
  as soon as it lands; a line that lost the keyboard can no longer take it from whoever holds it
  now; an action refused because somebody has the keyboard says who; a line that is not read, or
  floods the wall with frames or pieces of a message, is hung up on, before a pass as after; one
  account has 32 live lines at the most and takes nobody else's pass, and takes and gives back
  keyboard and mouse sixty times a minute at the most on all its lines together (counted per line,
  a script that opened lines anew wrote some twenty thousand log lines a minute; the program's log
  has them at DEBUG now, the activity log as before); the keyboard's Power key is never sent to a
  machine, as the page never sent it; one word turns the wheel
  sixteen notches at the most; a KVM's stream that says a picture larger than qKVM shows any is
  not passed on to the browser; what the line says is never in the log, at any log level; and
  the README's nginx recipe passes the live view's WebSocket on.
- **The API is promised to programs other than the page.** Every request a program needs to show
  a wall, sign in, act and keep a copy of the wall is in one table in the README, "The API", with
  its fields and refusals, and is held to the program by a test. Within `v1` nothing is taken away.
- **A tile says what it can be asked** (`can` in the wall and in the status): keys, text, the power
  button, Wake-on-LAN, its inputs, a server's locator light and console, as the device has them.
  The page goes by that and no longer by the kind of device.
- **One file of words** (`words.json`): the states, every code the wall answers with, the kinds of
  device and the words of `can`, with what the page shows for each, for other programs to be built
  from. "Clients and versions" in the README says how a program keeps up with a wall.
- **Business PCs with Intel AMT** (vPro Enterprise), experimental: on the wall through their
  management engine, with whether the PC is on, off, asleep or hibernating, what it is, whether
  its KVM could be used and in which control mode it was set up, and the power buttons; and
  **its screen through Intel's own KVM** where the PC was set up in admin control mode without
  user consent: on the tile, enlarged, and on the live line, with keys, typed text and the
  pointer. A session is held while somebody looks and closed a minute after; the PC's own monitor
  shows Intel's red and yellow border meanwhile. An admin can switch a KVM that is off on the
  engine on from its tile. Every power button was pressed on a real PC, *Hold power button*
  also while its screen is watched (the engine cuts no power while a KVM session is open: qKVM
  closes its own first), and a PC that is starting is said to be. A reader for the PC's serial
  console (Serial over LAN) is built and was tried on the real PC, which wrote nothing there:
  nothing shows it yet. See *Intel AMT* in the README for what was tried on a real machine.
  A tile remembers its PC by the number the PC gives for itself, and sends another PC that
  answers at its address (after a new lease, over plain HTTP) no power command, no keys and no
  session to its screen, and says so; a PC whose TLS port takes the connection and fails the
  handshake is not added the plain way unasked; the reset button is not sent to a PC that is
  off; and the screen is asked for only beside the engine's own ports, never at a forwarded
  port and two.
- **History:** what the wall saw of each machine is kept beside the settings for ninety days
  (`history.sqlite`): the states its tile went through, when it was last heard from, a server's
  temperatures and fans at a slow pace, and the power buttons pressed from the wall. Enlarged, a
  tile says under its picture when the machine was last seen and how much of the week it was
  online, with a small graph of the last day's readings; a script reads it at
  `GET /api/v1/devices/{id}/history`; `qkvm status` says how large it is. See *History* in the
  README.
- **Stock PiKVM**, tried against kvmd's own test environment (kvmd 4.226; the README's *Limits*
  says how far): its tile says what it is (the model of its platform and kvmd's version), and a
  new one is named as it calls itself; it is not offered a restart of itself or Wake-on-LAN,
  which stock kvmd has not got, nor keep-awake where its own settings switch that off; and its
  session no longer goes into the address of its event line, which its log writes down. The
  picture of every kvmd KVM is held from the first one on, and no longer breaks off to the KVM's
  own "no live video" ten seconds after somebody else stopped watching it.
- A server's controller that does not say its firmware's version in its own resource (OpenBMC
  in QEMU did not) has it read from its firmware inventory: the image it says it runs, or the
  one active image that names it as what it is for. OpenBMC's own image in QEMU now passes
  every check of the test written for it.
- **Servers whose controller is not AMI's**, tried on every push against the makers' own
  emulators and captures: Dell's capture of an iDRAC9, HPE's iLO 5 emulator, DMTF's example of
  the standard, and sushy-tools. Their tiles show the sensors and the locator light in either
  shape and spelling the standard has for them, an error a controller answers with HTTP 200 is
  an error, and a power command is called done once the change is seen. No real iDRAC or iLO
  has been tried yet. The README's *Limits* says per maker what was tried against what, in
  three tiers: a real device, the maker's emulator or capture, or built from the standard.
- A server's controller whose Redfish root takes some seconds to answer, as an older firmware's
  did, is known for a controller when it is added. It was taken for a KVM, and the one adding
  it was told that it did not respond in time.
- A busy button's spinner goes on turning where the system asks for less motion, where it
  stopped half way round. Adding an address again replaces what the earlier try said of it.
- **VNC servers** on the wall: any machine with a VNC server (a QEMU or libvirt guest, a desktop
  with TigerVNC or x11vnc, a controller's own VNC server), by address, port and password; its
  screen, key combinations and typed text; found by the network search on ports 5900 and 5901;
  in and out of an export file. Built from RFC 6143 and tried against a stand-in: see the
  README's chapter *VNC servers* for what that means.
- **Virtual machines on Proxmox VE**, one tile each, through Proxmox's own API with an API token:
  whether it runs, its power buttons (start, shutdown, stop, reset), and its screen through the
  console Proxmox hands out, on the tile, enlarged and live, with keys and the pointer. *Add KVMs*
  lists the virtual machines the token may see, to tick. A console is held while somebody looks
  and let go of a minute after, since each one is a task in Proxmox's log and two processes on its
  host. Switching on and stopping are waited for while Proxmox's task for them runs (or its high
  availability carries them out), and one still under way after a minute is said to be so, not to
  have failed. Tried on a real Proxmox VE 9.2: see the README's chapter *Proxmox and virtual machines*.
- **A server whose controller runs OpenBMC shows its screen**, from its console (`/kvm/0`, the
  protocol of VNC), opened with the session the tile holds already: on the tile, enlarged and live.
  Built from OpenBMC's source and tried against a stand-in only (see *Servers* in the README).
- **From 0.1.x, and back.** An update keeps everything a 0.1.x wall holds, and what its activity
  log's files still hold is searched from the first day. Going back to 0.1.1 on the same data
  folder works once the VNC servers, PCs with Intel AMT and Proxmox guests are off the wall: 0.1.1
  does not start with a VNC server on it, and takes the other two for KVMs, sending their saved
  password, or API token, to them as a KVM's sign-in. The README, *From 0.1.x to 0.2.0, and
  back*, says what else to know.

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
