# Changes

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
