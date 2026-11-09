#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Gated driver for the rsa-ledger key-operations fixture.

Spawns the fixture, walks its G/F stdin barriers behind shell-owned gate
files, reaps it and requires exit 0. The observer owns the gates: it
touches GOFILE once the workload may run (after the linked lane seals
and attaches) and STOPFILE once the observer has stopped (the fixture
holds its provider mapping through the observer's terminal drain).

Usage: key_operations_fixture.py FIXTURE MODULE LEDGER GOFILE DONEFILE
       STOPFILE TIMEOUT_S
Env: P11SCOPE_KEY_FIXTURE_PIN, SOFTHSM2_CONF,
     P11SCOPE_KEY_FIXTURE_TIMEOUT_MS (the fixture's own alarm; the
     supervisor TIMEOUT_S below is separate and never renewed).
Prints "pid=N" first and "exit=N kinds=K" last; the ledger (partial on
failure) is always written. Exit 0 on success, 1 on fixture/protocol
failure, 2 on usage errors.
"""
import json
import os
import select
import subprocess
import sys
import time


class FixtureError(Exception):
    """A fixture or protocol failure (exit 1)."""


def wait_path(path, deadline, poll=0.05):
    """Wait for a gate file up to the absolute deadline. Never renews it."""
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            return False
        time.sleep(poll)
    return True


def run_gated_fixture(fixture, module, ledger_path, gofile, donefile,
                      stopfile, timeout_s, env, on_spawn=None):
    """Run one gated fixture session; return its result dict.

    Calls on_spawn(pid) immediately after spawning (the --pid cell needs
    the fixture pid before the observer starts). Raises FixtureError on
    any protocol failure. The ledger always lands (partial on failure).
    The child is always reaped, never orphaned.
    """
    deadline = time.monotonic() + float(timeout_s)
    proc = subprocess.Popen(
        [fixture, module],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )
    if on_spawn is not None:
        on_spawn(proc.pid)
    kinds = []
    ledger_lines = []
    stderr_text = ""
    stdout_fd = proc.stdout.fileno()
    stderr_fd = proc.stderr.fileno()
    line_buf = b""

    def drain_stderr_available():
        """Read only stderr bytes already available; never blocks."""
        out = b""
        while len(out) < 65536:
            ready, _, _ = select.select([stderr_fd], [], [], 0)
            if not ready:
                break
            try:
                chunk = os.read(stderr_fd, 65536 - len(out))
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        return out.decode("utf-8", errors="replace")

    def read_row(want):
        """Read one stdout row, honoring the deadline while blocked.

        select() waits on the pipe with the remaining budget; a silent
        fixture trips the deadline instead of wedging readline().
        Raw os.read (not the text wrapper's readline) keeps no hidden
        buffer, so select-readiness and the bytes consumed agree.
        """
        nonlocal line_buf
        while True:
            newline = line_buf.find(b"\n")
            if newline >= 0:
                raw = line_buf[:newline + 1]
                line_buf = line_buf[newline + 1:]
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise FixtureError(
                        f"non-UTF8 ledger line: {raw[:100]!r}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FixtureError(f"timeout waiting for {want}")
            ready, _, _ = select.select([stdout_fd], [], [], remaining)
            if not ready:
                raise FixtureError(f"timeout waiting for {want}")
            try:
                chunk = os.read(stdout_fd, 65536)
            except OSError as error:
                raise FixtureError(
                    f"fixture stdout unreadable before {want}: {error}")
            if not chunk:
                status = proc.poll()
                if status is None:
                    raise FixtureError(
                        "fixture went silent (stdout EOF, still running) "
                        f"before {want}: {drain_stderr_available()[:300]}")
                raise FixtureError(
                    f"fixture exited {status} before {want}: "
                    f"{drain_stderr_available()[:300]}")
            line_buf += chunk

    def wait_row(want):
        while True:
            line = read_row(want)
            ledger_lines.append(line)
            try:
                kinds.append(json.loads(line).get("kind"))
            except ValueError:
                raise FixtureError(f"non-JSON ledger line: {line[:100]}")
            if kinds[-1] == want:
                return

    try:
        wait_row("ready")
        if not wait_path(gofile, deadline):
            raise FixtureError("timeout waiting for go gate")
        proc.stdin.write("G")
        proc.stdin.flush()
        wait_row("done")
        with open(donefile, "w", encoding="utf-8"):
            pass
        if not wait_path(stopfile, deadline):
            raise FixtureError("timeout waiting for stop gate")
        proc.stdin.write("F")
        proc.stdin.flush()
        try:
            _, stderr_text = proc.communicate(
                timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            _, stderr_text = proc.communicate()
            raise FixtureError("fixture did not exit after F")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        with open(ledger_path, "w", encoding="utf-8") as handle:
            handle.writelines(ledger_lines)
    if proc.returncode != 0:
        raise FixtureError(f"fixture exit {proc.returncode}")
    return {
        "pid": proc.pid,
        "exit": proc.returncode,
        "kinds": len(kinds),
        "stderr": (stderr_text or "").strip()[:500],
    }


def main(argv):
    if len(argv) != 8:
        print("usage: key_operations_fixture.py FIXTURE MODULE LEDGER "
              "GOFILE DONEFILE STOPFILE TIMEOUT_S", file=sys.stderr)
        return 2
    fixture, module, ledger, gofile, donefile, stopfile, timeout_s = argv[1:8]
    try:
        result = run_gated_fixture(
            fixture, module, ledger, gofile, donefile, stopfile,
            timeout_s, dict(os.environ),
            on_spawn=lambda pid: print(f"pid={pid}", flush=True))
    except FixtureError as error:
        print(f"key_operations_fixture: {error}", file=sys.stderr)
        return 1
    print(f"exit={result['exit']} kinds={result['kinds']}", flush=True)
    if result["stderr"]:
        print(f"fixture stderr: {result['stderr']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
