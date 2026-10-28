#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned EXT-01 filtered-worker qualification; live use needs its host lane.

First require the observer's functional doctor Clean verdict. Only then launch
our own tiny pthread caller/SO. No target PID, version shortcut or risk override
can be supplied. Both scenarios retain the original worker and provider through
observer exit and proven final drain. This qualifies exact C_GetInfo returns,
not arbitrary target safety or a reproduced kernel crash.

The Python suite uses the real unprivileged C protocol with a fake observer;
those controls do not attach BPF or qualify a kernel. Live example:
  qualify-return-probe-admission.py --observer /path/p11scope --output-dir NEW_DIR
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MODES = ("worker-pre-filter", "worker-late-filter")
MAX_BYTES = 8 * 1024 * 1024
CLEAN_DETAIL = "the trampoline's syscall is exempt from seccomp; confined targets are safe"
READY = re.compile(r"p11scope: capturing: ([1-9][0-9]*) probe\(s\) attached; stop with Ctrl-C")
DOCTOR_SECONDS = 60
READINESS_SECONDS = 60
DRAIN_SECONDS = 30
CALL_SECONDS = 10
CALLER_SECONDS = 120
# Reuse the public profile's finite loss vocabulary, including semantic and
# process-tracking loss. COMPLETE alone cannot excuse a contradictory counter.
LOSS_COUNTERS = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))["COUNTERS"]


class Refused(Exception):
    """Finite qualification failure; target-controlled bytes are not echoed."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def uint(value):
    return type(value) is int and 0 <= value < 1 << 64


def require_clean_doctor(text):
    rows = [row for row in text.splitlines() if row.startswith("uretprobe vs seccomp ")]
    require(len(rows) == 1, "functional return-probe assessment missing or duplicated")
    match = re.fullmatch(r"uretprobe vs seccomp \.+ ok +(.+)", rows[0])
    require(match is not None and match[1] == CLEAN_DETAIL,
            "functional return-probe assessment is not Clean; no filtered target launched")


class OwnedProcess:
    """One launched child, bounded pipes and one absolute monotonic deadline."""
    def __init__(self, argv, prefix, timeout):
        self.started = time.monotonic()
        self.deadline = self.started + timeout  # Before Popen; never renewed.
        self.logs = {channel: Path(str(prefix) + "." + channel).open("xb")
                     for channel in ("stdout", "stderr")}
        self.selector = selectors.DefaultSelector()
        self.pending = {"stdout": [], "stderr": []}
        self.buffers = {"stdout": b"", "stderr": b""}
        self.sizes = {"stdout": 0, "stderr": 0}
        self.eof = {"stdout": False, "stderr": False}
        self.closed = False
        try:
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, start_new_session=True)
        except BaseException:
            self.selector.close()
            for file in self.logs.values():
                file.close()
            raise
        self.pid = self.child.pid
        for channel in self.logs:
            pipe = getattr(self.child, channel)
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, channel)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def remaining(self, deadline=None):
        remaining = min(self.deadline, deadline if deadline is not None else self.deadline) - time.monotonic()
        require(remaining > 0, "owned process absolute deadline expired")
        return remaining

    def poll(self):
        return self.child.poll()

    def _pump(self, deadline=None):
        for key, _ in self.selector.select(min(self.remaining(deadline), .1)):
            data = os.read(key.fd, 65536)
            channel = key.data
            if not data:
                self.eof[channel] = True
                self.selector.unregister(key.fileobj)
                continue
            self.sizes[channel] += len(data)
            require(self.sizes[channel] <= MAX_BYTES, "owned process output limit exceeded")
            self.logs[channel].write(data)
            self.logs[channel].flush()
            lines = (self.buffers[channel] + data).split(b"\n")
            self.buffers[channel] = lines.pop()
            try:
                self.pending[channel].extend(line.decode("utf-8", "strict") for line in lines)
            except UnicodeError as error:
                raise Refused("owned process output is not UTF-8") from error

    def read_line(self, channel="stdout", *, deadline=None):
        self.remaining(deadline)
        while not self.pending[channel]:
            self.remaining(deadline)
            self._pump(deadline)
            if self.eof[channel] and not self.pending[channel]:
                raise Refused("owned process exited before the required protocol line")
        self.remaining(deadline)
        return self.pending[channel].pop(0)

    def read_json(self, phase, *, deadline=None):
        try:
            row = json.loads(self.read_line(deadline=deadline))
        except (ValueError, UnicodeError) as error:
            raise Refused("owned fixture protocol is malformed") from error
        require(isinstance(row, dict) and row.get("phase") == phase,
                "owned fixture protocol phase disagrees")
        return row

    def send(self, command):
        self.remaining()
        require(self.poll() is None, "owned fixture exited before command")
        try:
            self.child.stdin.write((command + "\n").encode("ascii"))
            self.child.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise Refused("owned fixture command failed") from error

    def wait(self, *, deadline=None):
        while self.poll() is None or self.selector.get_map():
            self._pump(deadline)
        self.remaining(deadline)  # An overdue success is still a failed qualification.
        return self.child.returncode

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=1)
        for channel in ("stdin", "stdout", "stderr"):
            getattr(self.child, channel).close()
        self.selector.close()
        for file in self.logs.values():
            file.close()


def run_doctor(observer, work):
    with OwnedProcess([str(observer), "doctor"], work / "doctor", DOCTOR_SECONDS) as child:
        rc = child.wait()
    # Other doctor rows can affect its aggregate exit; only this functional row
    # grants fixture launch. Signals/usage exits cannot grant a Clean assessment.
    require(rc in (0, 1), "doctor did not complete normally")
    require_clean_doctor((work / "doctor.stdout").read_text())
    return time.monotonic() - child.started


def compile_fixture(work):
    app, provider = work / "caller", work / "provider.so"
    source = ROOT / "tests/fixtures/return-probe-admission.c"
    flags = ["cc", "-std=gnu11", "-O0", "-Wall", "-Wextra", "-Werror"]
    for argv in ([*flags, "-shared", "-fPIC", "-DRETURN_PROBE_PROVIDER", str(source), "-o", str(provider)],
                 [*flags, str(source), "-pthread", "-ldl", "-o", str(app)]):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        require(result.returncode == 0, "owned native fixture compilation failed")
    return app, provider


def parse_status(text):
    result = {}
    for row in text.splitlines():
        if ":" not in row:
            continue
        name, value = row.split(":", 1)
        if name in ("Pid", "Tgid", "Seccomp"):
            require(name not in result and value.strip().isdigit(), "task status fact malformed")
            result[name] = int(value.strip())
    require(set(result) == {"Pid", "Tgid", "Seccomp"}, "task status facts unavailable")
    return result


def stat_birth(path):
    text = path.read_text()
    # comm may contain whitespace/parentheses. Fields after the final ')' begin
    # at state(field3); starttime(field22) is relative index19.
    tail = text.rsplit(")", 1)[1].split()
    require(len(tail) > 19 and tail[19].isdigit() and tail[0] not in ("Z", "X", "x"),
            "original live task generation unavailable")
    return int(tail[19])


def capture_identity(pid, tid, provider):
    require(type(pid) is int and type(tid) is int and 0 < pid != tid > 0,
            "worker identity is not a distinct owned thread")
    base = Path(f"/proc/{pid}")
    before = (stat_birth(base / "stat"), stat_birth(base / "task" / str(tid) / "stat"))
    leader = parse_status((base / "task" / str(pid) / "status").read_text())
    worker = parse_status((base / "task" / str(tid) / "status").read_text())
    require(leader["Pid"] == leader["Tgid"] == worker["Tgid"] == pid and worker["Pid"] == tid,
            "owned thread group identity disagrees")
    st = provider.stat()
    mapped = []
    for line in (base / "maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) >= 5:
            device = fields[3].split(":")
            if int(fields[4]) == st.st_ino and "x" in fields[1]:
                link = base / "map_files" / fields[0]
                # Btrfs mapping device and filesystem stat device are distinct
                # domains. Pin this NEW owned object's exact kernel map-files
                # pathname/inode, and retain its mapping domain separately.
                if link.readlink() == provider:
                    mapped.append((int(device[0], 16), int(device[1], 16)))
    after = (stat_birth(base / "stat"), stat_birth(base / "task" / str(tid) / "stat"))
    require(len(set(mapped)) == 1 and before == after,
            "owned provider mapping or task generation changed")
    return {"pid": pid, "tid": tid, "birth": before, "dev": st.st_dev, "ino": st.st_ino,
            "sha256": hashlib.sha256(provider.read_bytes()).hexdigest(), "mapping_dev": mapped[0],
            "leader_seccomp": leader["Seccomp"], "worker_seccomp": worker["Seccomp"]}


def verify_facts(child, row, provider, original, *, armed):
    require(child.poll() is None, "owned caller did not survive")
    current = capture_identity(child.pid, original["tid"], provider)
    for key in ("pid", "tid", "birth", "dev", "ino", "sha256", "mapping_dev"):
        require(current[key] == original[key], "original owned identity changed")
    expected_worker = 2 if armed else original["worker_seccomp"]
    require(current["leader_seccomp"] == 0 and current["worker_seccomp"] == expected_worker,
            "required leader/worker seccomp facts are not proven")
    for key in ("pid", "tid", "leader_seccomp", "worker_seccomp"):
        require(type(row.get(key)) is int and row[key] == current[key],
                "fixture-reported task facts disagree with procfs")


def validate_ledger(rows, pid, tid, count):
    require(isinstance(rows, list) and len(rows) == count, "owned call ledger length disagrees")
    for index, row in enumerate(rows, 1):
        require(isinstance(row, dict) and set(row) == {"index", "pid", "tid", "rv"},
                "owned call ledger row is malformed")
        require(all(uint(value) for value in row.values()) and
                row == {"index": index, "pid": pid, "tid": tid, "rv": 0},
                "owned call ledger identity, sequence or return disagrees")


def validate_report(document, provider, pid, count, *, mapping_dev):
    """Narrow exact-return/drain oracle over the current public profile fields."""
    try:
        require(document["schema"] == "p11scope/observed-profile/v3" and
                document["lane"] == "profile", "observer profile schema disagrees")
        capture, ev = document["capture"], document["evidence"]
        require(capture["mode"] == "profile" and capture["scope"] == f"pid:{pid}" and
                capture["privacy_mode"] == "allowlisted", "observer scope or privacy disagrees")
        st = provider.stat()
        require(len(mapping_dev) == 2 and all(uint(value) for value in mapping_dev),
                "original mapping identity unavailable")
        identity = {"dev": list(mapping_dev), "ino": st.st_ino,
                    "sha256": hashlib.sha256(provider.read_bytes()).hexdigest()}
        require(len(capture["modules"]) == 1 and
                all(capture["modules"][0][key] == value for key, value in identity.items()),
                "observer provider identity disagrees")
        require(ev["completeness"] == "COMPLETE" and ev["verdict_detail"] == "clean_proven" and
                ev["drain_proven"] is True and ev["uretprobe_override"] is None,
                "observer is partial, undrained or used a risk override")
        require(ev["stop_quiescence"] == {"state": "proven", "post_q_events": False,
                                         "post_q_discovery": False} and
                all(ev["stop_quiescence"][key] is False for key in ("post_q_events", "post_q_discovery")),
                "observer final drain is unproven")
        require(ev["attach_backend"] == {"selection": "multi", "fallback": None,
                                        "scope_filter": "kernel-pid+bpf"} and
                ev["attach_mechanisms"] == ["uprobe-multi"] and ev["attach_failures"] == [],
                "actual PID Multi attachment is not proven")
        for key in (*LOSS_COUNTERS, "in_flight_at_end"):
            require(type(ev[key]) is int and ev[key] == 0, "observer loss or incomplete returns")
        control = ev["kernel_control"]
        require(control == {"capture_halted": False, "owner_poison": [],
                                        "owner_admission_failures": 0, "identity_unavailable": 0,
                                        "identity_budget_exhausted": False,
                                        "root_affiliation_failures": []} and
                control["capture_halted"] is False and control["identity_budget_exhausted"] is False and
                all(type(control[key]) is int for key in ("owner_admission_failures", "identity_unavailable")),
                "native authority is unhealthy")
        rows = document["functions"]
        require(isinstance(rows, list) and rows, "observer has no function rows")
        positive = []
        for row in rows:
            for key in ("calls", "errors", "in_flight", "pending_returns"):
                require(uint(row[key]), "observer function counter is malformed")
            require(row["errors"] == row["in_flight"] == row["pending_returns"] == 0,
                    "observer function return is incomplete")
            require(isinstance(row["rv_counts"], dict) and
                    all(uint(value) for value in row["rv_counts"].values()) and
                    sum(row["rv_counts"].values()) == row["calls"],
                    "observer function return counters disagree with calls")
            if row["calls"]:
                positive.append(row)
        require(len(positive) == 1, "observer extra or missing positive function rows")
        row = positive[0]
        require(row["names"] == ["C_GetInfo"] and row["calls"] == count and
                row["module"] == identity and row["module_ambiguous"] is False and
                row["module_unresolved"] is False and
                row["rv_counts"] == {"0x0000000000000000": count} and
                type(row["rv_counts"]["0x0000000000000000"]) is int,
                "observer exact C_GetInfo returns or provider identity disagree")
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise Refused("observer required profile facts are missing or malformed") from error


def read_json(path):
    require(path.stat().st_size <= MAX_BYTES, "saved output exceeds bound")
    try:
        return json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as error:
        raise Refused("saved output is malformed") from error


def qualify_cell(observer, app, provider, work, mode, calls, duration):
    work.mkdir(mode=0o700)
    ledger = work / "calls.jsonl"
    with OwnedProcess([str(app), str(provider), mode, str(calls), str(ledger)],
                      work / "caller", CALLER_SECONDS) as child:
        ready = child.read_json("ready", deadline=child.started + CALL_SECONDS)
        original = capture_identity(child.pid, ready.get("tid"), provider)
        require(original["worker_seccomp"] == (2 if mode == MODES[0] else 0),
                "required pre-attachment worker seccomp state is unavailable")
        verify_facts(child, ready, provider, original, armed=False)
        require(ready.get("calls") == 0 and ledger.read_bytes() == b"", "calls preceded attachment")
        output = work / "profile.json"
        argv = [str(observer), "profile", "--pid", str(child.pid), "--module", str(provider),
                "--attach-backend", "multi", "--duration", f"{duration}s", "-o", str(output)]
        with OwnedProcess(argv, work / "observer", child.remaining()) as capture:
            readiness_deadline = capture.started + READINESS_SECONDS
            while True:
                line = capture.read_line("stderr", deadline=readiness_deadline)
                if READY.fullmatch(line):
                    break
            attached = time.monotonic()
            call_deadline = attached + CALL_SECONDS
            child.send("A")
            armed = child.read_json("armed", deadline=call_deadline)
            verify_facts(child, armed, provider, original, armed=True)
            require(armed.get("calls") == 0 and ledger.read_bytes() == b"", "calls preceded GO")
            child.send("G")
            done = child.read_json("done", deadline=call_deadline)
            require(type(done.get("calls")) is int and done["calls"] == calls, "fixture did not finish calls")
            require(ledger.stat().st_size <= MAX_BYTES, "call ledger exceeds bound")
            data = ledger.read_bytes()
            require(data.endswith(b"\n"), "call ledger is truncated")
            try:
                rows = [json.loads(line) for line in data.splitlines()]
            except ValueError as error:
                raise Refused("call ledger is malformed") from error
            validate_ledger(rows, child.pid, original["tid"], calls)
            verify_facts(child, done, provider, original, armed=True)
            # Stop only after all exact returns. The workload stays held until
            # the observer's normal exit and validated terminal drain.
            require(capture.poll() is None, "observer ended before all owned calls")
            draining = time.monotonic()
            capture.child.send_signal(signal.SIGINT)
            require(capture.wait(deadline=draining + DRAIN_SECONDS) == 0, "observer did not stop successfully")
            drained = time.monotonic()
            verify_facts(child, done, provider, original, armed=True)
            validate_report(read_json(output), provider, child.pid, calls, mapping_dev=original["mapping_dev"])
            require(ledger.read_bytes() == data, "call ledger changed during final drain")
        child.send("R")
        require(child.wait(deadline=time.monotonic() + CALL_SECONDS) == 0,
                "owned caller did not exit successfully after release")
        return {"mode": mode, "pid": child.pid, "tid": original["tid"], "calls": calls,
                "leader_seccomp": 0, "worker_seccomp": 2, "owned_cleanup": True,
                "attach_seconds": attached - capture.started, "calls_seconds": draining - attached,
                "drain_seconds": drained - draining, "total_seconds": time.monotonic() - child.started}


def qualify(observer, work, *, calls=16, duration=4, modes=MODES):
    require(type(calls) is int and 1 <= calls <= 64, "call count is outside fixture bound")
    require(type(duration) is int and 1 <= duration <= 10, "capture duration is outside fixture bound")
    require(all(mode in MODES for mode in modes) and modes, "unknown fixture mode")
    observer = observer.resolve(strict=True)
    work.mkdir(mode=0o700)
    doctor_seconds = run_doctor(observer, work)  # Refusal precedes compilation/filtered-target launch.
    app, provider = compile_fixture(work)
    cells = [qualify_cell(observer, app, provider, work / mode, mode, calls, duration) for mode in modes]
    return {"qualification": "owned-return-probe-admission", "doctor_seconds": doctor_seconds,
            "cells": cells}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=(*MODES, "both"), default="both")
    parser.add_argument("--calls", type=int, default=16)
    parser.add_argument("--duration", type=int, default=4)
    args = parser.parse_args()
    try:
        result = qualify(args.observer, args.output_dir.resolve(), calls=args.calls,
                         duration=args.duration, modes=MODES if args.mode == "both" else (args.mode,))
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        # Deliberately finite diagnostics: never echo the observer's argv,
        # arbitrary target output, provider bytes or source-controlled errors.
        print(str(error) if isinstance(error, Refused) else "owned qualification setup failed",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
