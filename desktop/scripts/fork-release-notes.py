#!/usr/bin/env python3
"""Assemble unsigned draft release notes from smoke summaries."""

import argparse
import pathlib
import sys

HEADER = """\
Unsigned draft. Windows files are not Authenticode-signed. The macOS app is ad-hoc signed with codesign --sign - and is not notarized. No upstream OnionShare signature is attached.

Source commit: {sha}
Tag: {tag}

WiX ProductVersion stays numeric 2.7.2. The Windows product name is OnionShare Fork (identity backups), with its own UpgradeCode, install folder, and shortcut component. The macOS bundle filename is OnionShareFork.app. The Flatpak app id is io.github.maxtannahill.OnionShareFork. The snap name is onionshare-fork. The snap is built and is not uploaded to the Snap Store.

cli/onionshare_cli/common.py was not modified. is_flatpak() is true only for FLATPAK_ID org.onionshare.OnionShare, and is_snapcraft() is true only for SNAP_INSTANCE_NAME onionshare. Those two checks will not recognize this Flatpak id or snap name. The desktop GUI still detects a Flatpak sandbox when /.flatpak-info exists.

A package command that exits successfully is not a packaged-app test. Checks that did not run are marked NOT PERFORMED below.

## Smoke summaries
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--smoke-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not args.sha or not args.tag.startswith("v2.7.2-fork."):
        print("unexpected tag or empty sha", file=sys.stderr)
        return 1

    smoke_dir = pathlib.Path(args.smoke_dir)
    files = sorted(path for path in smoke_dir.rglob("*") if path.is_file())
    if not files:
        print("no smoke summaries", file=sys.stderr)
        return 1

    parts = [HEADER.format(sha=args.sha, tag=args.tag)]
    for path in files:
        text = path.read_text(encoding="utf-8")
        if "NOT PERFORMED" not in text:
            print("summary missing NOT PERFORMED: " + path.name, file=sys.stderr)
            return 1
        if "frozen=" in text and "SELFTEST PASSED" not in text:
            print("frozen summary missing SELFTEST PASSED: " + path.name, file=sys.stderr)
            return 1
        if "SELFTEST FAILED" in text or "GUI SMOKE FAILED" in text:
            print("failed summary: " + path.name, file=sys.stderr)
            return 1
        parts.append("### " + path.name + "\n\n```\n" + text.rstrip() + "\n```\n")
    notes = "\n".join(parts)
    lowered = notes.lower()
    if "http://" in lowered or "https://" in lowered or "begin private key" in lowered:
        print("refusing notes that contain a link or a key block", file=sys.stderr)
        return 1
    pathlib.Path(args.output).write_text(notes, encoding="utf-8")
    print(f"wrote {args.output} from {len(files)} summaries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
