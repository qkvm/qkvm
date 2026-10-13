# Changes

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
  keep or to take to another QKVM. Encrypted with a passphrase it carries the devices'
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
