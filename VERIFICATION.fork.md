# Verification evidence (fork only)

This page covers the identity-backup prototype on this fork. The OnionShare project hasn't reviewed or accepted it. Everything below was run by automated test harnesses and CI. None of it is a human test, a cryptographic audit, or maintainer approval.

## What was tested

| Ref | Commit | What it is |
| --- | --- | --- |
| Base | `53d496b7` | Upstream OnionShare v2.7.2 |
| Prototype | `0d3c1cb4` on `submission/identity-backups-v2` | 13 commits on the base. Tree `277c0f48` |
| Earlier prototype head | `9c7649d7` on `submission/identity-backups` | Same tree as `0d3c1cb4` (`277c0f48`). Only the commit metadata differs |
| Fork build line | `ad219018` on `release/fork-v2.7.2-identity-backups-1` (tag `v2.7.2-fork.3`) | `0d3c1cb4` plus a fork README section and an unsigned build workflow. `cli/onionshare_cli`, `desktop/onionshare`, `cli/tests` and `desktop/tests` are identical to `0d3c1cb4` |

## 1. Test suites (source, Linux)

| Where | Commit | CLI | Desktop (offscreen Qt) |
| --- | --- | --- | --- |
| Linux VM | `0d3c1cb4` | 446 passed, 5 skipped | 166 passed |
| GitHub Actions, ubuntu-26.04 ([run 43613090349](https://github.com/maxtannahill/onionshare/actions/runs/43613090349)) | `ad219018` | 446 passed, 5 skipped | 166 passed |

The cli and desktop wheels and sdists also built at `0d3c1cb4`.

## 2. Real-Tor round trip (source, Linux, automated harness)

Run at `9c7649d7` (same tree as `0d3c1cb4`) on a Linux VM. Tor 0.4.9.11 was used, with a separate client Tor. The GUI ran offscreen under xvfb and was driven by a script, not by a person. All identities were disposable. Addresses were redacted and compared by SHA-256.

For each case, the script created a service, exported a backup while it was stopped, closed the tab and removed its persistent settings, then imported the backup. It then checked that the restored tab was stopped, non-persistent and not set to autostart, started it again and compared the address.

| Case | Result |
| --- | --- |
| Private share (client auth) | PASS. Same address after restore. A separate Tor client using the restored client-auth key fetched the share (HTTP 200 on the 2nd attempt) |
| Public share | PASS. Same address. Public fetch HTTP 200 |
| Chat | PASS for address equality. No chat fetch was attempted. One `AttributeError: 'WSGIServer' object has no attribute 'socket'` was printed on the first Chat start, and the process exited 0. A targeted test reproduced the same error on unmodified v2.7.2 in that environment when Chat is stopped immediately after it reports started |

The real-Tor run was not repeated at `0d3c1cb4`, because the tree is identical.

NOT PERFORMED in the real-Tor run: Receive mode, Website mode, wrong-passphrase import, duplicate import while the tab is open, Saved Services open/rename/delete, a chat fetch, bridges.

## 3. Packaged builds (unsigned, CI only)

These come from tag `v2.7.2-fork.3`, [run 43613090349](https://github.com/maxtannahill/onionshare/actions/runs/43613090349). Every job succeeded. The files are in an unpublished draft release that only the repository owner can see.

| File | SHA-256 |
| --- | --- |
| `OnionShare-fork-2.7.2-fork.3-win64-UNSIGNED.msi` | `2d788e1d00e5a4e0303857e6719d813b1cd5955881ee84fe59b8f22b2de1e781` |
| `OnionShare-fork-2.7.2-fork.3-macos-universal2-UNSIGNED.dmg` | `b3fdf106d72af7db463268aec40bb3b45871b5489c6152ce537cdf37f0c386f0` |
| `OnionShare-fork-2.7.2-fork.3.tar.gz` (source, matches `git archive` of `ad219018`) | `a436d15986593b39d68c64a62c2992c458cbb76e316e2e78048df9f8e08a3b22` |

The Windows MSI is not Authenticode-signed. The macOS app is only ad-hoc signed (`codesign --sign -`) and is not notarized.

Performed on the CI runners, before packaging:
- Windows x64: `onionshare-cli --help` exited 0.
- Windows x64: a frozen self-test printed `SELFTEST PASSED`. It imported PyNaCl, validated a disposable identity, ran an encrypt/decrypt round trip, and rejected a wrong passphrase and a tampered backup.
- Windows x64: an 8-second offscreen GUI launch ran.
- macOS arm64 and Intel, single-arch and both halves of the universal2 bundle: the same three checks.
- The ad-hoc-signed universal app got one more 8-second launch before the DMG was created.

An 8-second launch is not full application verification. A frozen self-test is not full application verification.

NOT PERFORMED for packaged builds:
- real Tor
- GUI export/import
- QR equality
- Saved Services operations
- normal shutdown
- SmartScreen/Gatekeeper
- real-machine installation
- installing the MSI, mounting the DMG, or launching either installed app

Earlier tags `v2.7.2-fork.1` ([run 43596608824](https://github.com/maxtannahill/onionshare/actions/runs/43596608824)) and `v2.7.2-fork.2` ([run 43602861108](https://github.com/maxtannahill/onionshare/actions/runs/43602861108)) are failed attempts of the same workflow:
- fork.1: the macOS arm64 build failed.
- fork.2: the universal macOS merge failed.

Both tags were left in place, and each fix was a new commit with a new tag. Actions artifacts from all three runs can be downloaded by signed-in GitHub users until 2027-02-12. They are unsigned CI outputs, not releases.

### Flatpak and Snap (excluded, experimental)

Flatpak and Snap are excluded experimental builds and are not attached to the draft.

Earlier fork.1 local investigation: Flatpak Tor connectivity and packaged-library backup restore passed, but single-instance handling failed because the fork app ID was not recognised by is_flatpak(), leading to a stale-PID lock problem. Snap Tor connectivity was not verified.

In the fork.3 workflow, both packages built and passed an 8-second offscreen launch; Snap also installed on the runner. In that run, Tor connectivity, single-instance handling, drag-and-drop and backup restore were NOT PERFORMED for either package. These packages remain excluded.

## Not done at all

- No formal cryptographic audit.
- No human testing on real Windows, macOS or Linux desktops.
- No review or approval by OnionShare maintainers.
- No accessibility or translation review.
