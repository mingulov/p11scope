#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed H6 cgroup stop checks at real collection stages.

The final stage is final membership sampling, pre-read boundary. This does
not test interruption of a kernel filesystem operation or a returning read.
Live execution requires the controller's separately authorized root lane.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
FD_ENV = "P11SCOPE_CGROUP_STOP_FD"
STAGES = ("traversed", "final_pre_read")
EVENTS = {"armed", "launch", "traversed", "worker_returned", "worker_joined",
          "final_pre_read", "end_sampled", "published", "retiring", "retired"}
MAX_FRAME = 1024
MAX_EVENTS = 256


class StageController:
    """One inherited socket, one deadline, and only a healthy-release command."""
    def __init__(self, stage, candidate=None, seconds=180):
        if stage not in STAGES or not 0 < seconds <= 180:
            raise ValueError("unsupported stage or finite controller deadline")
        self.deadline = time.monotonic() + seconds
        self.frames, self.buffer, self.eof = [], bytearray(), False
        self.socket, self.child = socket.socketpair()
        self.socket.setblocking(False)
        try:
            self.stage = stage
            self.candidate = candidate or {"pid": 0, "start_time": 0}
            self.send({"version": 1, "stage": stage, "timeout_ms": int(seconds * 1000),
                       **self.candidate})
        except BaseException:
            self.close()
            raise

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("cgroup stage controller deadline exhausted")
        return H6["remaining_seconds"](left)

    def send(self, value):
        pending = memoryview(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        while pending:
            _, writable, _ = select.select([], [self.socket], [], self.remaining())
            if not writable:
                raise TimeoutError("cgroup stage send deadline exhausted")
            count = self.socket.send(pending)
            if count == 0:
                raise EOFError("cgroup stage socket closed during send")
            pending = pending[count:]

    def inherited(self):
        return {FD_ENV: str(self.child.fileno())}, (self.child.fileno(),)

    def spawned(self):
        self.child.close()

    def receive(self):
        while b"\n" not in self.buffer:
            readable, _, _ = select.select([self.socket], [], [], self.remaining())
            if not readable:
                raise TimeoutError("cgroup stage receive deadline exhausted")
            part = self.socket.recv(MAX_FRAME + 1)
            if not part:
                self.eof = True
                if self.buffer:
                    raise ValueError("truncated cgroup stage frame")
                raise EOFError("cgroup stage observer closed")
            self.buffer.extend(part)
            if b"\n" not in self.buffer and len(self.buffer) > MAX_FRAME:
                raise ValueError("oversized cgroup stage frame")
        raw, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        if len(raw) > MAX_FRAME or len(self.frames) >= MAX_EVENTS:
            raise ValueError("cgroup stage exchange exceeded its bounds")
        frame = json.loads(raw)
        if (not isinstance(frame, dict) or type(frame.get("version")) is not int or frame["version"] != 1
                or frame.get("event") not in EVENTS
                or type(frame.get("sequence")) is not int
                or frame["sequence"] != len(self.frames)
                or type(frame.get("transaction")) is not int
                or frame["transaction"] < 0):
            raise ValueError("wrong cgroup stage phase or sequence")
        self.frames.append(frame)
        return frame

    def wait(self, event):
        while True:
            frame = self.receive()
            if frame["event"] == event:
                return frame

    def release(self, frame):
        if frame.get("event") != self.stage:
            raise ValueError("release requires the selected actual stage")
        self.send({"version": 1, "release": frame["transaction"]})

    def finish(self):
        while not self.eof:
            try:
                self.receive()
            except EOFError:
                break
        return self.frames

    def close(self):
        self.socket.close()
        self.child.close()


def caller_subject(event):
    context = event.get("identity_context") or {}
    return context.get("caller") or {}


def provider_modules(records, provider):
    mapping = provider.get("mapping") or {}
    selected = set()
    for record in records:
        event = record.get("event") or {}
        context = event.get("identity_context") or {}
        module = context.get("module") or {}
        if (record.get("kind") == "edge_observed" and type(context.get("version")) is int
                and context["version"] == 1 and isinstance(event.get("module"), str)
                and re.fullmatch(r"m[0-9]+", event["module"])
                and module.get("status") == "observed" and module.get("id") == event.get("module")
                and all(type(module.get(key)) is int for key in ("device_major", "device_minor", "inode"))
                and [module["device_major"], module["device_minor"]] == mapping.get("dev")
                and module["inode"] == mapping.get("ino")):
            selected.add(event["module"])
    return selected


def evaluate_stop_stage(receipt, frames, document, records):
    """Require actual stage/lifecycle metadata plus independent admission facts."""
    errors = H6["stop_errors"](receipt)
    if receipt.get("observer_rc") != 0 or receipt.get("workload_rc") != 0:
        errors.append("observer or workload failed its normal stop")
    before, after = receipt.get("provider_before") or {}, receipt.get("provider_after") or {}
    mapping = before.get("mapping") or {}
    if (not before or before != after or before.get("dev") != mapping.get("dev")
            or before.get("ino") != mapping.get("ino")
            or not re.fullmatch(r"[0-9a-f]{64}", before.get("sha256", ""))):
        errors.append("held provider changed or lacks its independent mapping-domain anchor")
    if not frames or len(frames) > MAX_EVENTS or any(
            type(frame.get("version")) is not int or frame["version"] != 1
            or type(frame.get("sequence")) is not int or frame["sequence"] != index
            or type(frame.get("transaction")) is not int or frame["transaction"] < 0
            or frame.get("event") not in EVENTS for index, frame in enumerate(frames)):
        errors.append("missing or malformed bounded stage exchange")
    if not frames or frames[0].get("event") != "armed":
        errors.append("observer did not arm before any real work")
    stage = receipt.get("stage")
    selected = [frame for frame in frames if frame.get("event") == stage]
    if stage not in STAGES or len(selected) != 1:
        errors.append("missing unique actual selected stage")
        return {"pass": False, "errors": errors}
    gate = selected[0]
    tx = gate.get("transaction")
    healthy = receipt.get("healthy") is True
    expected = "complete" if healthy else "operator_stop"
    same = [frame for frame in frames if frame.get("transaction") == tx]
    def unique(event):
        values = [frame for frame in same if frame.get("event") == event]
        if len(values) != 1:
            errors.append(f"missing unique {event} for the selected transaction")
            return {}
        return values[0]
    returned, joined, published = (unique(name) for name in
                                  ("worker_returned", "worker_joined", "published"))
    retiring = [frame for frame in frames if frame.get("event") == "retiring"]
    retired = [frame for frame in frames if frame.get("event") == "retired"]
    if (len(retiring) != 1 or len(retired) != 1
            or not returned.get("sequence", MAX_EVENTS) < joined.get("sequence", -1)
            or not joined.get("sequence", MAX_EVENTS) < published.get("sequence", -1)
            or not published.get("sequence", MAX_EVENTS) < retiring[0].get("sequence", -1)
            or not retiring[0].get("sequence", MAX_EVENTS) < retired[0].get("sequence", -1)):
        errors.append("worker return/join/publication did not precede normal native retirement")
    if published.get("outcome") != expected:
        errors.append("selected transaction has the wrong real collection outcome")
    if any(frame.get("event") == "launch" and frame.get("transaction", 0) > tx
           for frame in frames):
        errors.append("a later collection launched after the selected stage")
    if not records or records[-1].get("kind") != "ended":
        errors.append("missing same-observer terminal inventory record")
    admission_records = [row for row in records
                  if row.get("kind") == "caller_event"
                  and (row.get("event") or {}).get("event") == "admitted"]
    admissions = [caller_subject(row.get("event") or {}) for row in admission_records]
    callers = document.get("callers", [])
    edges = document.get("edges", [])
    modules = provider_modules(records, before)
    if stage == "traversed":
        if tx != 1 or not gate.get("sequence", MAX_EVENTS) < returned.get("sequence", -1):
            errors.append("gate was not inside the first actual worker traversal")
        if returned.get("outcome") != expected:
            errors.append("worker did not return the actual expected collection outcome")
        if not healthy and (admissions or callers or edges or document.get("modules")
                or published.get("admitted") != 0 or published.get("callers") != 0
                or published.get("endpoints") != 0
                or any(frame.get("event") == "published" and frame.get("outcome") == "complete"
                       for frame in frames)):
            errors.append("first cancelled transaction published caller/endpoint authority")
        if healthy and (published.get("admitted", 0) < 1 or not admissions
                        or not any(edge.get("module") in modules for edge in edges)):
            errors.append("healthy traversal twin did not actually admit its held member")
    else:
        candidate = receipt.get("candidate") or {}
        if (type(candidate.get("pid")) is not int or candidate["pid"] <= 0
                or type(candidate.get("start_time")) is not int or candidate["start_time"] <= 0
                or gate.get("pid") != candidate.get("pid")
                or gate.get("start_time") != candidate.get("start_time")
                or gate.get("requested") is not True
                or not joined.get("sequence", MAX_EVENTS) < gate.get("sequence", -1)):
            errors.append("final stage lacks the real ready/requested candidate and joined worker")
        if returned.get("outcome") != "complete":
            errors.append("final stage worker did not return a complete real candidate collection")
        sampled = unique("end_sampled")
        if (not gate.get("sequence", MAX_EVENTS) < sampled.get("sequence", -1)
                < published.get("sequence", -1) or sampled.get("outcome") != expected):
            errors.append("actual final membership sample has the wrong outcome/order")
        bound = lambda row: row.get("pid") == candidate.get("pid") and row.get("start_time") == candidate.get("start_time")
        candidate_admissions = [row for row in admissions if bound(row)]
        candidate_rows = [row for row in callers if bound(row)]
        if healthy:
            if (sampled.get("present") is not True or published.get("candidate_admitted") is not True
                    or len(candidate_admissions) != 1 or len(candidate_rows) != 1
                    or not any(row.get("caller") == candidate_rows[0].get("id")
                               and row.get("module") in modules for row in edges)):
                errors.append("healthy final twin did not sample and actually admit the same candidate")
        elif (candidate_admissions or candidate_rows or published.get("candidate_admitted") is not False
              or sampled.get("present") is not False):
            errors.append("cancelled final sample admitted the fresh candidate")
        baseline = receipt.get("baseline") or {}
        boundary = baseline.get("seq")
        if type(boundary) is not int or boundary < 0:
            errors.append("baseline lacks its independent complete stream boundary")
        else:
            fresh_admissions = [caller_subject(row["event"]) for row in admission_records
                                if row.get("seq", -1) > boundary]
            if ((not healthy and fresh_admissions)
                    or (healthy and (len(fresh_admissions) != 1 or not bound(fresh_admissions[0])))):
                errors.append("extra admission after the held baseline boundary")
        histories = [row for row in edges if row.get("caller") == baseline.get("caller")
                     and row.get("module") == baseline.get("module")]
        if (baseline.get("count", 0) < 1 or len(histories) != 1
                or baseline.get("module") not in modules
                or (histories[0].get("entries") or {}).get("count", -1) < baseline["count"]
                or ((histories[0].get("entries") or {}).get("coverage") or {}).get("state") != "counted"
                or ((histories[0].get("entries") or {}).get("coverage") or {}).get("lossy") is not False):
            errors.append("useful baseline capture/history was not preserved")
    return {"pass": not errors, "stage": stage, "healthy": healthy,
            "transaction": tx, "errors": errors}


def read_records(path, final=False):
    with Path(path).open("rb") as stream:
        data = stream.read(H6["R5_STREAM_BYTES"] + 1)
    if len(data) > H6["R5_STREAM_BYTES"] or (final and not data.endswith(b"\n")):
        raise ValueError("incomplete or oversized inventory event stream")
    if not data.endswith(b"\n"):
        data = data[:data.rfind(b"\n") + 1]
    rows = [json.loads(line) for line in data.splitlines()]
    if len(rows) > H6["R5_STREAM_RECORDS"] or any(
            row.get("seq") != index for index, row in enumerate(rows)):
        raise ValueError("inventory event sequence is incomplete")
    return rows


def wait_baseline(path, owner, executable, provider, reader, phases):
    H6["wait_usage_armed"](path, [(owner.pid, str(executable.path), 1)])
    H6["n3_command"](owner, reader, "C_GenerateRandom", 3, 0, "baseline", "selected",
                      0, None, phases)
    deadline = H6["wait_deadline"](60)
    while True:
        records = read_records(path)
        modules = provider_modules(records, provider)
        ids = {row["event"].get("caller") for row in records
               if row.get("kind") == "caller_event"
               and caller_subject(row.get("event") or {}).get("pid") == owner.pid}
        for record in reversed(records):
            event = record.get("event") or {}
            count = (event.get("entries") or {}).get("count", 0)
            coverage = (event.get("entries") or {}).get("coverage") or {}
            if (record.get("kind") == "edge_observed" and event.get("caller") in ids
                    and event.get("module") in modules and count >= 3
                    and coverage.get("state") == "counted" and coverage.get("lossy") is False):
                return {"caller": event["caller"], "module": event["module"], "count": count,
                        "seq": records[-1]["seq"]}
        H6["pause_until"](deadline, 0.05)


@H6["owned_leg"](stop_b=True)
def run_leg(ctx, directory, backend, stage, healthy):
    directory = Path(directory) / backend / f"{stage}-{'release' if healthy else 'sigint'}"
    (directory / "workload").mkdir(mode=0o755, parents=True)
    env = H6["init_token"](directory / "workload", ctx.args.uid, ctx.args.gid, "h6-stage")
    provider_before = H6["provider_receipt"](ctx.provider_pin)
    root, _ = H6["create_tracked"](ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-stop-{os.getpid()}-{time.monotonic_ns()}")
    selected, _ = H6["create_tracked"](ctx, root.path / "selected")
    outside, _ = H6["create_tracked"](ctx, root.path / "outside")
    workloads, moves, phases = [], [], []
    for tag in (("baseline", "candidate") if stage == "final_pre_read" else ("candidate",)):
        owner, reader, stderr = H6["spawn_caller"](ctx.owners, ctx.readers, directory,
            ctx.pins["caller-a"], ctx.provider_pin, ctx.args.uid, ctx.args.gid, env, tag=tag)
        reader.record("ready", 0, seconds=30)
        ctx.pins["caller-a"].image_receipt(reader.record("image", 0), owner)
        H6["move_and_verify"](outside if tag == "candidate" and stage == "final_pre_read" else selected,
                              owner, moves, tag)
        workloads.append((owner, reader, stderr))
    candidate = workloads[-1][0]
    identity = {"pid": candidate.pid, "start_time": candidate.identity["start_time"]}
    channel = StageController(stage, identity if stage == "final_pre_read" else None)
    try:
        extra, fds = channel.inherited()
        doc_path, log_path = directory / "inventory.json", directory / "inventory.jsonl"
        argv = [str(ctx.binary.path), "inventory", "--cgroup", str(selected.path),
                "--module", str(ctx.provider_pin.path), "--duration", "300", "--capture", "native",
                "--attach-backend", backend, "-o", str(doc_path), "--event-log", str(log_path)]
        ctx.observer_start = len(ctx.owners)
        owned = H6["spawn_owned"](ctx.owners, argv, 0, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, **extra}, pass_fds=fds, start_new_session=True)
        ctx.observer_owned = owned
        channel.spawned()
        H6["owned_reader"](ctx.readers, H6["Reader"], owned.popen.stdout, directory / "observer.stdout")
        errors = H6["owned_reader"](ctx.readers, H6["Reader"], owned.popen.stderr, directory / "observer.stderr")
        channel.wait("armed")
        baseline = None
        if stage == "final_pre_read":
            H6["wait_inventory_ready"](owned, errors, log_path, backend)
            baseline = wait_baseline(log_path, workloads[0][0], ctx.pins["caller-a"],
                                     provider_before, workloads[0][1], phases)
            H6["move_and_verify"](selected, candidate, moves, "fresh-mapped-candidate")
        gate = channel.wait(stage)
        if healthy:
            channel.release(gate)
            channel.wait("published")
        rc, _stopped, latency = H6["stop_b_observer"](ctx, owned)
        frames = channel.finish()
        workload_rc = 0
        for owner, reader, _stderr in workloads:
            workload_rc |= H6["stop_caller"](owner, reader, 0)
        H6["finish_readers"](ctx.readers)
        document, records = json.loads(doc_path.read_text()), read_records(log_path, final=True)
        ctx.binary.verify()
        ctx.provider_pin.verify()
        receipt = {"stage": stage, "healthy": healthy, "candidate": identity, "baseline": baseline,
                   "provider_before": provider_before,
                   "provider_after": H6["provider_receipt"](ctx.provider_pin),
                   "observer_rc": rc, "workload_rc": workload_rc,
                   **H6["stop_receipt"](owned, latency)}
        result = evaluate_stop_stage(receipt, frames, document, records)
        result["backend"] = backend
        print(json.dumps(result), flush=True)
        return result
    finally:
        channel.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--provider", type=Path,
                        default=Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"))
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--backends", default="singles,multi")
    parser.add_argument("--out", type=Path, required=True,
                        help="new owned disk directory under /var/tmp/p11scope-ws-tmp")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error("live acceptance requires authorized root and an ordinary workload uid/gid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        parser.error("source revision must be the exact 40-hex commit")
    backends = args.backends.split(",")
    if not backends or len(set(backends)) != len(backends) or any(name not in H6["BACKENDS"] for name in backends):
        parser.error("backends must be unique singles,multi selections")
    if not args.out.is_absolute() or not args.out.is_relative_to(Path("/var/tmp/p11scope-ws-tmp")):
        parser.error("out must be an absolute owned disk path under /var/tmp/p11scope-ws-tmp")
    if any(not path.is_absolute() for path in (args.binary, args.provider)):
        parser.error("binary and provider paths must be absolute")
    os.umask(0o022)
    args.out.mkdir(mode=0o755)
    directory_fd = os.open(args.out, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if H6["N3HARNESS"]["fs_magic"](directory_fd) == 0x01021994:
            parser.error("tmpfs is not an acceptance fixture filesystem")
    finally:
        os.close(directory_fd)
    (args.out / "bin").mkdir(mode=0o755)
    ctx = H6["Case"](args)
    try:
        ctx.binary = H6["leg_pin"](ctx, args.binary)
        ctx.provider_pin = H6["leg_pin"](ctx, args.provider)
        ctx.pins = H6["compile_case_fixtures"](args.out / "bin", ctx.leg_pins)
        for backend in backends:
            for stage in STAGES:
                for healthy in (False, True):
                    result = run_leg(ctx, args.out, backend, stage, healthy)
                    if not result["pass"] or ctx.cleanup_failed:
                        return 1
        return 0
    finally:
        H6["cleanup_leg_resources"](ctx)


if __name__ == "__main__":
    with H6["signal_cleanup"]():
        raise SystemExit(main())
