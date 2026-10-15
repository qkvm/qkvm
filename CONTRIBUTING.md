# Contributing to qKVM

qKVM is written and maintained by its publisher alone. **Reports are welcome; pull requests are
not taken.** qKVM holds the passwords of KVMs and can press the power button of the machines
behind them, so every line of it is written, reviewed and answered for in one place. That is a
decision about trust, and no judgement of what you would have sent.

## What helps

- **A bug, or a device that does not work as it should:** open an issue at
  https://github.com/qkvm/qkvm/issues. Say which version you run (`qkvm --version`, or
  *Settings > About*), how it is installed (pip, a container), what kind of device it is
  about, what you did and what happened. The lines of `qkvm.log` from that moment help; it
  holds no passwords, but take out any address or name you would rather not show.
- **A security problem:** not in a public issue. [SECURITY.md](SECURITY.md) says how to
  report it privately.
- **An idea:** an issue as well. What gets built is decided here, and said there.
- **A fix you have already worked out:** describe it in the issue, with the lines that matter
  if you like. The change itself is written here; who found it is named in `CHANGELOG.md`.

A pull request that is opened all the same is closed with a pointer to this page.

## Your own version

The licence lets you change qKVM and run what you changed: the GNU Affero General Public
License, version 3 (see `LICENSE`). If you run a changed version for others, or pass it on,
you owe them its source under the same licence. A fork that publishes releases of its own
needs its own repository and its own signing key: *Publishing releases* in the README says
how. The name qKVM and its logo are not covered by the licence.

To run the tests of a copy you changed: `python -m pytest`. They use stand-in KVMs, so no
hardware is needed.

## Why so few dependencies

qKVM depends on few packages, and that is on purpose: each one has to be kept up to date,
trusted, and answered for when it has a hole. The list, with what each package is for, is in
`tests/test_packaging.py`, and a test fails when the list and `pyproject.toml` disagree. The
page uses no JavaScript libraries and loads nothing from other servers.
