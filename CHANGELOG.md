# Changes

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
