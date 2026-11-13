#!/usr/bin/env python3
"""Launch a packaged OnionShare build and record what was not tested.

The summary is safe to publish. Onion-shaped strings and long base64 blobs
are redacted. A missing display is NOT PERFORMED. An import or frozen-module
error fails the process.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

NOT_PERFORMED = (
    "NOT PERFORMED: GUI export of a six-word phrase, an encrypted file, and a QR image.",
    "NOT PERFORMED: QR text equals backup file text in the GUI. "
    "onionshare_cli has no identity-backup QR helper, and the desktop dialog is product code.",
    "NOT PERFORMED: Import into a stopped, nonpersistent tab with autostart off.",
    "NOT PERFORMED: Start the restored service through Tor and compare the onion address.",
    "NOT PERFORMED: Saved Services open, export, rename, and delete.",
    "NOT PERFORMED: Normal application shutdown. "
    "The runner does not close the window through the GUI quit path.",
)

_ONION = re.compile(r"[a-z2-7]{56}")
_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")


def redact(text):
    text = _ONION.sub("[redacted]", text)
    text = _BLOB.sub("[redacted]", text)
    return text


def _import_error(line):
    lowered = line.lower()
    if any(
        marker in lowered
        for marker in (
            "modulenotfounderror",
            "importerror",
            "dll load failed",
            "undefined symbol",
            "no module named",
        )
    ):
        return True
    if any(marker in lowered for marker in ("libsodium", "pynacl", "nacl")):
        return any(
            marker in lowered
            for marker in ("error", "fail", "not found", "no module", "unable")
        )
    return False


def _qthread(line):
    lowered = line.lower()
    return "qthread" in lowered and ("destroyed" in lowered or "still running" in lowered)


def _environment(line):
    lowered = line.lower()
    return any(
        marker in lowered
        for marker in (
            "could not load the qt platform plugin",
            "could not find the qt platform plugin",
            "cannot open display",
            "no protocol specified",
        )
    )


def _matching(text, predicate):
    lines = []
    for line in redact(text).splitlines():
        if predicate(line):
            lines.append(line[:300])
        if len(lines) == 8:
            break
    return lines


def _write(summary, lines, append):
    mode = "a" if append else "w"
    with open(summary, mode, encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")
    for line in lines:
        print(line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--seconds", type=int, default=8)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]

    lines = [f"artifact-label: {args.label}"]
    failed = False
    if not command:
        lines.append("GUI launch: NOT PERFORMED (no command given)")
        lines.append(
            "QThread scan: NOT PERFORMED (the packaged app was not started)"
        )
    else:
        env = os.environ.copy()
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        stdout_file = tempfile.NamedTemporaryFile("w+b", delete=False)
        stderr_file = tempfile.NamedTemporaryFile("w+b", delete=False)
        try:
            proc = subprocess.Popen(
                command,
                stdout=stdout_file,
                stderr=stderr_file,
                env=env,
                start_new_session=True,
            )
        except OSError as err:
            stdout_file.close()
            stderr_file.close()
            os.remove(stdout_file.name)
            os.remove(stderr_file.name)
            lines.append(
                "GUI launch: NOT PERFORMED (could not start the process: "
                + type(err).__name__
                + ")"
            )
            lines.append(
                "QThread scan: NOT PERFORMED (the packaged app was not started)"
            )
        else:
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.2)
            early = proc.poll()
            if early is None and os.name != "nt":
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except OSError:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except OSError:
                        proc.kill()
                    proc.wait(timeout=5)
            elif early is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            stdout_file.close()
            stderr_file.close()
            with open(stdout_file.name, "rb") as handle:
                stdout = handle.read()
            with open(stderr_file.name, "rb") as handle:
                stderr = handle.read()
            os.remove(stdout_file.name)
            os.remove(stderr_file.name)
            captured = (
                stdout.decode("utf-8", errors="replace")
                + "\n"
                + stderr.decode("utf-8", errors="replace")
            )
            import_lines = _matching(captured, _import_error)
            qthread_lines = _matching(captured, _qthread)
            env_lines = _matching(captured, _environment)
            stayed_up = early is None
            if import_lines:
                failed = True
                lines.append("GUI launch: FAIL (import or frozen-module error)")
                lines.extend("GUI error: " + line for line in import_lines)
            elif stayed_up:
                lines.append(
                    f"GUI launch: process stayed up for {args.seconds}s "
                    "without an import, PyNaCl, or frozen-module error"
                )
            elif env_lines:
                lines.append(
                    "GUI launch: NOT PERFORMED (display or Qt platform plugin was unavailable)"
                )
            else:
                lines.append(
                    "GUI launch: NOT PERFORMED (process exited early with code "
                    + str(early)
                    + " and no import error was captured)"
                )
            if qthread_lines:
                failed = True
                lines.append(
                    "QThread scan: FAIL (warning observed during the forced stop; "
                    "this is not a normal GUI shutdown)"
                )
                lines.extend("QThread: " + line for line in qthread_lines)
            elif stayed_up or early is not None:
                lines.append(
                    "QThread scan: no QThread destruction warning in the forced-stop output. "
                    "Normal application shutdown was NOT PERFORMED."
                )
            else:
                lines.append("QThread scan: NOT PERFORMED")

    lines.extend(NOT_PERFORMED)
    if failed:
        lines.append("GUI SMOKE FAILED")
    else:
        lines.append("GUI SMOKE COMPLETED")
    _write(args.summary, lines, args.append)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
