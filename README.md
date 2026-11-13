![OnionShare](/docs/source/_static/logo.png)

[![Run Tests](https://github.com/onionshare/onionshare/actions/workflows/tests.yml/badge.svg)](https://github.com/onionshare/onionshare/actions/workflows/tests.yml)

# OnionShare

OnionShare is an open source tool that lets you securely and anonymously share files, host websites, and chat with friends using the Tor network.

## About this fork

This fork adds encrypted backups of onion service identities, plus a local list called Saved Services. It is not part of upstream OnionShare, and the OnionShare project hasn't reviewed or accepted it. The official downloads and Flatpak/Snap packages below are upstream OnionShare and don't include these changes. No packaged builds of this fork have been published; to try it, run it from source ([desktop/README.md](desktop/README.md)).

**Why.** If you publish an OnionShare address in advance, or use one now and then, you may want the same address back after losing your local settings, replacing a device or rebuilding an environment. This fork lets you keep that ability under your own control.

**What already existed.** OnionShare could already reuse an onion key internally through persistent tabs, and the CLI could reuse one with `--persistent FILE`. This fork adds a deliberate recovery workflow that is encrypted, contains only the identity and is strictly checked on import. It also adds an archive you manage from the GUI. It isn't just a GUI wrapper around an existing encrypted-backup command, because there was no such command.

**How it works**

- **Backups:** on a Share, Receive, Website or Chat tab, you can export the onion identity as an encrypted backup file. A six-word recovery phrase, drawn from the EFF wordlist, protects it.
- **QR code:** the QR code contains exactly the same encrypted text as the backup file. It never contains the recovery phrase.
- **Opening:** importing a backup, or opening an entry in Saved Services, gives you a stopped tab. That tab isn't persistent and won't autostart. You add files or other content and start it yourself.
- **Saved Services:** this list is separate from persistent tabs. It stores keys **unencrypted** on this computer, like persistent tabs do, and the app says so. Exporting an encrypted backup is a separate step.
- **What a backup contains:** only six identity fields: mode, service ID, private key, the client-auth key pair, and whether the service is public. It doesn't contain local paths, filenames, receive folders, webhooks, titles, timers, content settings or autostart settings.
- **Unchanged:** persistent and non-persistent tabs work exactly as before.
- **Privacy:** nothing is uploaded and no camera is used. There are no new user-facing CLI export or import commands.
- **Keep them apart:** anyone who has both an encrypted backup and its recovery phrase can control that onion identity. Store them separately.

**Details**

- How to use it, and compatibility with older versions: [Identity backups and Saved Services](docs/source/advanced.rst) in `docs/source/advanced.rst`.
- The exact v1 backup format and validation rules: the comments at the top of [`cli/onionshare_cli/identity_backup.py`](cli/onionshare_cli/identity_backup.py).

**Known limitations**

- No formal cryptographic audit has been done.
- Any Windows or macOS builds of this fork would be unsigned and not notarized. No packaged build of this fork has been published or tested by a person on real Windows or macOS.
- Saved Services doesn't lock its writes across processes, so two OnionShare instances writing at the same time can conflict.
- Older OnionShare versions, including 2.7.2, can't import these backups.

## Installing OnionShare

You can download OnionShare for Windows and macOS from the [OnionShare website](https://onionshare.org).

For macOS you can also use [Homebrew](https://brew.sh/):

```
brew install --cask onionshare
```

See [these instructions](https://docs.onionshare.org/2.6.5/en/install.html#linux) to install OnionShare in Linux as a Flatpak or Snap package.

## Documentation

To learn how OnionShare works, what its security properties are, how to use it, and how to contribute to the project, check out https://docs.onionshare.org.
