<div align="center">

<a href="https://qkvm.com"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/qkvm/main/.github/brand/qkvm-dark.svg"><img src="https://raw.githubusercontent.com/qkvm/qkvm/main/.github/brand/qkvm-light.svg" alt="qKVM" height="64"></picture></a>

**The live screen of every IP KVM and server you run, on one page.**<br>
Self-hosted, open source, no cloud and no device limit.

<a href="https://pypi.org/project/qkvm/"><img src="https://img.shields.io/pypi/v/qkvm?label=PyPI&color=0b6bff" alt="The version on PyPI"></a>
<a href="https://pypi.org/project/qkvm/"><img src="https://img.shields.io/pypi/pyversions/qkvm?label=Python&color=0b6bff" alt="Python versions"></a>
<a href="https://hub.docker.com/r/qkvm/qkvm"><img src="https://img.shields.io/docker/v/qkvm/qkvm?sort=semver&label=Docker&color=0b6bff" alt="The version on Docker Hub"></a>
<a href="https://github.com/qkvm/qkvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0-0b6bff" alt="Licence: AGPL-3.0"></a>

[Website](https://qkvm.com) · [Live demo](https://demo.qkvm.com) · [Documentation](https://docs.qkvm.com) · [Desktop App](https://qkvm.com/#desktop) · [Releases](https://github.com/qkvm/qkvm/releases)

<a href="https://demo.qkvm.com"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/hero-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/hero-light.png" width="100%" alt="The wall: fifteen machines with their live screens, their names and their state, and one of them in a window of its own."></picture></a>

<sub>Shown: the live demo. Its machines are made up.</sub>

<a href="https://demo.qkvm.com"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-demo-light.png" height="46" alt="Open the live demo"></a>
<a href="#get-started"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-install-dark.png"><img src="https://raw.githubusercontent.com/qkvm/.github/main/profile/button-install-light.png" height="46" alt="Install qKVM"></picture></a>

</div>

## What is qKVM?

If you look after machines through IP KVMs and server controllers, you know the routine: a browser tab for every device, a different login and a different page for every maker, and no single place that tells you which machine just lost its screen.

qKVM puts them all on one wall. Every KVM, server, PC and virtual machine shows its live screen and its state side by side, whatever make it is, and each one is a click away from your own keyboard and mouse. It runs on your own hardware, talks to every device directly over your LAN or Tailscale, and needs no account anywhere and no cloud in between.

## Why people use it

- **See everything at a glance.** Green is online, amber has no signal, red needs you. Search, filter, group, and put the problems first.
- **One way of working, whatever the make.** A Comet, a JetKVM, a server's own controller, a PC with Intel AMT, a Proxmox VE guest: the same tile, the same buttons, the same keyboard and mouse.
- **Hands on in one click.** Take a machine's keyboard and mouse in the browser, type a long command into it, mount an installer image, press its power button, start it into BIOS setup.
- **Many machines, one action.** Tick several, choose an action, confirm once.
- **Know before anyone calls.** Alerts to ntfy, Slack, Discord, any webhook or your syslog collector, and ninety days of what each machine went through.
- **Made for a team.** Three roles, two-factor sign-in, sign-on through your identity proxy, and an activity log of who did what.
- **Free, without limits.** Open source under the AGPL-3.0, with no device limit and no licence key.

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

## Try it in your browser first

**[Open the live demo](https://demo.qkvm.com)**: the real qKVM Web App, with a wall of made-up machines. Open a machine, change the view, tick a few and try an action. Nothing to install and nothing to sign up for.

## Web App or Desktop App?

qKVM comes in two ways. Both are free and open source under the same licence; pick by where you work, or run both.

| | **qKVM Web App** | **qKVM Desktop App** (beta) |
| --- | --- | --- |
| **What it is** | A self-hosted server you open in any browser | A native app for Windows 10 and 11 |
| **Made for** | A team that shares one wall, from anywhere that can reach it | One person at a desk, a NOC screen, a laptop on the road |
| **Needs a server** | Yes: one small program on a server, a mini PC or your own computer | No. Install it and add your KVMs |
| **Install** | pip or Docker, on Linux or Windows | A setup or a ZIP, no administrator rights |
| **People** | Accounts with three roles, two-factor sign-in and a recovery key | One per PC, with an app password and a lock |
| **Machines** | KVMs, JetKVM, servers, PCs with Intel AMT, Proxmox VE and VNC servers | Comet and other kvmd KVMs, JetKVM, servers over Redfish, and everything a qKVM server 0.3 or later has |
| **Keyboard and video** | In the browser | The Windows key and Alt+Tab taken in its window, video decoded on your graphics card |

**Rather not run a server?** Download the Desktop App, add your KVMs, and they are on your screen. When your team sets up a Web App later, the Desktop App shows that wall too, in the same window.

## Get started

### qKVM Web App

As a program, with Python 3.11 or newer:

```
pip install qkvm
qkvm
```

Then open http://127.0.0.1:8787/. Where the system's Python refuses `pip install` (Debian, Ubuntu), `pipx install qkvm` does the same.

Or as a container, for amd64 and arm64:

```
docker run -d --name qkvm --restart unless-stopped --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -p 8787:8787 -v qkvm-data:/data -v qkvm-keys:/keys qkvm/qkvm --https --setup-code
```

Then open `https://<this machine>:8787/` with the setup code that `docker logs qkvm` shows. Back up the `qkvm-keys` volume apart from `qkvm-data`: the saved device passwords cannot be opened without it.

The first visit takes four short steps: choose a password, keep the recovery key it shows, say where the wall may be reached from, and let qKVM find the KVMs on your network. Compose, a reverse proxy and the rest: **[Run it](https://docs.qkvm.com/run-it)**.

### qKVM Desktop App

**[Download it for Windows](https://qkvm.com/#desktop)**, as a setup or a ZIP, and check it against SHA256SUMS on its [release page](https://github.com/qkvm/qkvm-desktop/releases/latest). The setup installs it for you alone, with no administrator rights; then start qKVM Desktop and choose its app password.

Windows may say it protected your PC: the app is not yet signed with a certificate. Choose *More info*, then *Run anyway*. Step by step: **[Installing the Desktop App](https://docs.qkvm.com/desktop-install)**.

## What it works with

| | |
| --- | --- |
| **GL.iNet Comet and Comet X** | The screen, keyboard and mouse, virtual media, and power through an ATX board or a GL.iNet Fingerbot |
| **PiKVM-style KVMs** | Whatever speaks the kvmd interface, its H.264 passed on as it comes |
| **JetKVM** | Over its own channel, typing in the keyboard layout its computer uses |
| **Servers** | Any controller that speaks Redfish: state, power, health, temperatures and fans. AMI MegaRAC: the screen, keyboard and mouse. OpenBMC: the screen |
| **PCs with Intel AMT** | Power, start into BIOS setup, and the screen through Intel's own KVM |
| **Proxmox VE** | Its guests through Proxmox's own API: the screen, keyboard and mouse, and power |
| **VNC servers** | QEMU and libvirt guests, TigerVNC and others: the screen, keys and typed text |

Tested on real hardware from GL.iNet, JetKVM, Gigabyte and ASRock Rack.

## Built for what it holds

qKVM keeps the passwords of your KVMs and can press the power button of what is behind them, so it is built around what somebody could walk away with:

- **A copied data folder opens nothing.** Accounts and saved passwords are sealed with a storage key kept outside that folder.
- **Something else at a device's address is refused.** A device's certificate is remembered the first time, like an SSH host key, and anything else at that address is refused.
- **A KVM that is taken over stays that KVM.** Its video is decoded in a locked-down process of its own, which is given no password.
- **An update is installed only when it is signed** by the publisher, and never without you asking for it.

How each of these works: **[How it is protected](https://docs.qkvm.com/how-it-is-protected)**.

## Documentation

Everything is at **[docs.qkvm.com](https://docs.qkvm.com)**, and the same text ships with the program as [GUIDE.md](https://github.com/qkvm/qkvm/blob/main/GUIDE.md).

| Start | Devices | Running it | Reference |
| --- | --- | --- | --- |
| [Run it](https://docs.qkvm.com/run-it) | [JetKVM](https://docs.qkvm.com/jetkvm) | [Accounts](https://docs.qkvm.com/accounts) | [The API](https://docs.qkvm.com/the-api) |
| [Using it](https://docs.qkvm.com/using-it) | [Servers](https://docs.qkvm.com/servers) | [Alerts](https://docs.qkvm.com/alerts) | [Command line](https://docs.qkvm.com/command-line) |
| [Live view and control](https://docs.qkvm.com/live-view-and-control) | [Intel AMT](https://docs.qkvm.com/intel-amt) | [Keeping it running](https://docs.qkvm.com/keeping-it-running) | [Metrics](https://docs.qkvm.com/metrics) |
| [Virtual media](https://docs.qkvm.com/virtual-media) | [VNC servers](https://docs.qkvm.com/vnc-servers) | [Updates](https://docs.qkvm.com/updates) | [Limits](https://docs.qkvm.com/limits) |
| [Export and import](https://docs.qkvm.com/export-and-import) | [Proxmox and VMs](https://docs.qkvm.com/proxmox-and-virtual-machines) | [How it is protected](https://docs.qkvm.com/how-it-is-protected) | [Changes](https://docs.qkvm.com/changes) |

## Help and contributing

- **A question, a bug or an idea?** [Open an issue](https://github.com/qkvm/qkvm/issues).
- **A security problem?** Please report it privately, as the [security policy](https://docs.qkvm.com/security-policy) says, and not in a public issue.
- **Want to help?** Read [CONTRIBUTING.md](https://github.com/qkvm/qkvm/blob/main/CONTRIBUTING.md) first.

## Licence

qKVM is free software under the [AGPL-3.0](https://github.com/qkvm/qkvm/blob/main/LICENSE).

qKVM is an independent project. It is not affiliated with GL.iNet, PiKVM or JetKVM.
