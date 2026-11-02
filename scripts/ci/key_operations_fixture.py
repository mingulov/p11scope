#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
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

    def wait_row(want):
        while True:
            if time.monotonic() > deadline:
                raise FixtureError(f"timeout waiting for {want}")
            line = proc.stdout.readline()
            if line == "":
                raise FixtureError(
                    f"fixture exited {proc.poll()} before {want}: "
                    f"{proc.stderr.read()[:300]}")
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
