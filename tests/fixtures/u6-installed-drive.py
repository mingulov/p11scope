#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""U6 installed journey cells: all-modes-vs-ledger and named-trace/false-name twins.

Two full journeys, three modes each:

- ``--self-test`` runs synthetic twin red-green only. No binary, no root and
  no capture, except the diff twin's OFFLINE ``inventory diff`` which needs an
  explicit ``--binary`` for the computation alone (capture provenance is never
  claimed from it). Every green twin must pass and every red twin must fail;
  any inversion exits nonzero.
- ``--dry-run`` validates installed wiring without capturing: it resolves the
  explicit ``--binary`` (an installed candidate or a documented shape
  stand-in, recorded as such), probes the ``--help`` flags the live path
  needs, validates pins/manifests/coordinator/pair inputs, runs the twin
  matrix and prints the live cell plan. It never captures.
- live (default) runs the installed cells and fails closed on any mismatch,
  missing input or unrunnable twin. It refuses ``P11SCOPE_U6_RED_PROOF``.

Ledger journey cells (``--journey ledger``): pipe-JSON, PTY dashboard (80x24
and the U6 compact 48x12), event-log rotation and exec generations, every
population matched against the owned workload ledger.

The live-only ``--journey ledger-component`` runs just the shared rotation and
compact PTY cells. Its component-only receipt does not qualify C8 or full U6.

Named-trace journey cells (``--journey named-trace``): named-trace positives
plus false-name twins (mapped-only, unreadable, unknown, exec,
duplicate-basename, slow-reader) under explicit-trusted-manifest discipline
(default discovery is refused), and the two-real-saved-inventory diff path.

Environment seams: ``P11SCOPE_U6_INSTALLED_BINARY`` (absolute installed
candidate), ``P11SCOPE_U6_SOURCE_REVISION`` (40-hex, live), and the
proof-only ``P11SCOPE_U6_RED_PROOF=<red-twin>`` which runs one red twin
through the pass assertion so the check path must exit nonzero. The
installed gate never sets the proof seam; live mode refuses it.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
TRACE_ORACLE = ROOT / "scripts/cgroup-trace-oracle.py"
INVENTORY_ORACLE = ROOT / "scripts/inventory-native-oracle.py"
CROSS_DRIVE = ROOT / "tests/fixtures/cross-command-drive.py"
QUALIFY_TRACE = ROOT / "scripts/qualify-cgroup-trace.py"
QUALIFY_INVENTORY = ROOT / "scripts/qualify-inventory-native.sh"
CAPTURE_PAIR = ROOT / "tests/fixtures/operator-output/capture_inventory_pair.py"
INVENTORY_SCHEMA = "p11scope/inventory/v1"
EVENTS_SCHEMA = "p11scope/inventory-events/v1"
MANIFEST_SCHEMA = "p11scope-manifest/5"
INPUT_LIMIT = 16 * 1024 * 1024
OUTPUT_LIMIT = 4 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
BASE_TMP = Path(os.environ.get("TMPDIR", "/var/tmp/p11scope-ws-tmp"))

# Native qualify cells backing the complete U6 named-trace journey.
U6_TRACE_NATIVE_CELLS = ("stable", "onecall", "exec", "run")
U6_TRACE_EXTENDED_TWINS = ("mapped-only", "unreadable", "duplicate-basename", "slow-reader")
U6_TRACE_PLAN = (
    ("named-positive", "stable", "named>0 with zero false names"),
    ("unknown-honest", "onecall", "Unknown reported, never forced; zero false names"),
    ("exec-generations", "exec", "both images named; zero wrong names"),
    ("run-parity", "run", "public route parity with zero false names"),
    ("mapped-only", "mapped-only", "mapped-but-never-called image contributes zero call events"),
    ("unreadable", "unreadable", "unreadable-exe rows stay Unknown, never an invented label"),
    ("duplicate-basename", "duplicate-basename", "same-basename paths stay distinct full paths"),
    ("slow-reader", "slow-reader", "delivered rows stay exact; loss is accounted, never silent"),
)
RED_PROOF_ENV = "P11SCOPE_U6_RED_PROOF"
INSTALLED_ENV = "P11SCOPE_U6_INSTALLED_BINARY"
REVISION_ENV = "P11SCOPE_U6_SOURCE_REVISION"


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def read_bounded(path, limit=INPUT_LIMIT):
    with Path(path).open("rb") as stream:
        payload = stream.read(limit + 1)
    require(len(payload) <= limit, f"input exceeds {limit} bytes: {path}")
    return payload


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv, *, timeout=20, output_limit=OUTPUT_LIMIT):
    """Bounded child reaping mirrored from cross-command-drive.py."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, f"command timed out: {argv!r}")
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.data].extend(data)
                    require(sum(map(len, streams.values())) <= output_limit,
                            f"command output exceeded {output_limit} bytes: {argv!r}")
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"command timed out: {argv!r}")
            code = child.wait(timeout=remaining)
        return code, bytes(streams["stdout"]), bytes(streams["stderr"])
    finally:
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        child.stdout.close()
        child.stderr.close()


def scratch_root():
    BASE_TMP.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="u6-", dir=BASE_TMP))


_MODULES = {}


def load_module(path):
    key = str(path)
    if key not in _MODULES:
        require(Path(path).is_file(), f"missing oracle/driver module: {path}")
        _MODULES[key] = runpy.run_path(key)
    return _MODULES[key]


def trace_oracle():
    return load_module(TRACE_ORACLE)["evaluate"]


def inventory_oracle_module():
    return load_module(INVENTORY_ORACLE)


def cross_drive_module():
    return load_module(CROSS_DRIVE)


def resolve_binary(path):
    require(Path(path).is_absolute(), f"binary path is not absolute: {path}")
    resolved = Path(path).resolve(strict=True)
    require(resolved.is_absolute(), f"binary path is not absolute: {path}")
    require(os.access(resolved, os.X_OK), f"binary is not executable: {resolved}")
    return resolved


def binary_role(resolved):
    pinned = os.environ.get(INSTALLED_ENV)
    if pinned and Path(pinned).resolve() == resolved:
        return "installed_candidate"
    return "shape_stand_in"


def help_text(binary, *arguments):
    code, stdout, stderr = run([str(binary), *arguments], timeout=20)
    require(code == 0, f"help probe failed: {arguments} rc={code} {stderr[:512]!r}")
    return stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Named-trace twins: synthetic (trace, ledger, receipt) triples through the
# real cgroup-trace oracle. Shapes mirror tests/python/test_cgroup_trace_oracle.py.
# ---------------------------------------------------------------------------

def trace_base():
    image = {"kind": "image", "image": 0, "pid": 123, "start_time": 77,
             "path": "/owned/trace-a", "dev": 2, "ino": 3,
             "mtime_ns": 4, "pid_namespace": 5, "time_namespace": 6, "t": 70}
    target = {"kind": "target", "image": 0, "fn": "C_GenerateRandom",
              "dev": [8, 1], "ino": 9, "file_offset": 100}
    ledger = [image, target, {"kind": "ready", "image": 0, "t": 80}]
    ledger += [{"kind": "call", "image": 0, "pid": 123, "tid": 123,
                "fn": "C_GenerateRandom", "rv": 0, "phase": "main",
                "scope": "selected", "t0": 110 + i * 10, "t1": 111 + i * 10}
               for i in range(3)]
    pin = {"dev": [8, 1], "ino": 9, "sha256": "a" * 64,
           "mapping": {"dev": [8, 1], "ino": 9, "file_offset": 0}}
    receipt = {"cell": "stable", "require_named": True, "pid_namespace": 5,
               "selected_initial_pids": [123],
               "time_namespace": 6, "images": [copy.deepcopy(image)],
               "provider_before": pin, "provider_after": copy.deepcopy(pin),
               "observer_started_ns": 90, "observer_ready_ns": 100,
               "observer_stopped_ns": 200, "scope_created_ns": 50,
               "stop_latency_seconds": 0.1, "observer_rc": 0, "caller_rc": 0,
               "privacy_canaries": ["PRIVATE_N3_SENTINEL"], "observer_stderr": ""}
    evidence = ('EVIDENCE {"privacy_mode":"allowlisted","final_drain":true,'
                '"trace_truncated":false,"event_loss":0}\n')
    counts = 'COUNT_EVIDENCE {"stats_entered":3,"stats_returned":3,"raw_calls":3}\n'
    rows = ['12:00:00.00000%d %s (PID 123, TID 123)%s C_GenerateRandom \u2192 CKR_OK 1.0\u00b5s\n'
            % (i, "Unknown executable" if i == 0 else '"trace-a"',
               "" if i == 0 else ' exe="/owned/trace-a"') for i in range(3)]
    return "".join(rows) + counts + evidence, ledger, receipt


def trace_row(pid, tid, fn, label, path, stamp):
    rendered = "Unknown executable" if label is None else json.dumps(label)
    suffix = "" if path is None else " exe=%s" % json.dumps(path)
    return ("12:00:00.00000%d %s (PID %d, TID %d)%s %s \u2192 CKR_OK 1.0\u00b5s\n"
            % (stamp, rendered, pid, tid, suffix, fn))


def trace_counts_events(total, loss=0):
    counts = ('COUNT_EVIDENCE {"stats_entered":%d,"stats_returned":%d,"raw_calls":%d}\n'
              % (total, total, total))
    evidence = ('EVIDENCE {"privacy_mode":"allowlisted","final_drain":true,'
                '"trace_truncated":false,"event_loss":%d}\n' % loss)
    return counts + evidence


def trace_duplicate_basename(confuse=False):
    """Two images share basename ``tool`` under different directories."""
    _, ledger, receipt = trace_base()
    image_a = dict(ledger[0], path="/owned/dir-a/tool")
    image_b = dict(ledger[0], image=1, pid=124, path="/owned/dir-b/tool",
                   dev=7, ino=8, t=71)
    target_a = dict(ledger[1])
    target_b = dict(ledger[1], image=1)
    calls_a = ledger[3:]
    calls_b = [dict(call, image=1, pid=124, tid=124, t0=call["t0"] + 40,
                    t1=call["t1"] + 40) for call in calls_a]
    ledger = [image_a, target_a, {"kind": "ready", "image": 0, "t": 80}] + calls_a
    ledger += [image_b, target_b, {"kind": "ready", "image": 1, "t": 81}] + calls_b
    receipt["images"] = [copy.deepcopy(image_a), copy.deepcopy(image_b)]
    receipt["selected_initial_pids"] = [123, 124]
    receipt["observer_stopped_ns"] = 260
    b_path = "/owned/dir-a/tool" if confuse else "/owned/dir-b/tool"
    rows = [trace_row(123, 123, "C_GenerateRandom", "tool", "/owned/dir-a/tool", i)
            for i in range(3)]
    rows += [trace_row(124, 124, "C_GenerateRandom", "tool",
                       b_path if i == 0 else "/owned/dir-b/tool", i + 4)
             for i in range(3)]
    return "".join(rows) + trace_counts_events(6), ledger, receipt


def trace_exec_pair(mixup=False):
    """Exec transition A -> B across different paths; B's first CALL is Unknown."""
    trace, ledger, receipt = trace_base()
    image_b = dict(ledger[0], image=1, path="/owned/trace-b", dev=9, ino=10, t=135)
    request = dict(kind="exec", image=0, pid=123, tid=123, start_time=77,
                   mode="leader", path="/owned/trace-b", scope="outside", t=134)
    ledger = ledger + [request, image_b,
                       dict(ledger[1], image=1, fn="C_GetSessionInfo")]
    ledger += [dict(ledger[3], image=1, fn="C_GetSessionInfo", phase="reenter",
                    t0=140 + i * 10, t1=141 + i * 10) for i in range(3)]
    receipt.update(cell="exec", require_named_images=[0, 1], first_unknown_images=[1],
                   exec_transitions=[dict(from_image=0, to_image=1, mode="leader",
                                          same_path=False, t0=133, t1=136,
                                          request=copy.deepcopy(request))])
    receipt["images"].append(copy.deepcopy(image_b))
    receipt["observer_stopped_ns"] = 260
    b_path = "/owned/trace-a" if mixup else "/owned/trace-b"
    b_label = "trace-a" if mixup else "trace-b"
    lines = trace.splitlines()
    lines[3:3] = [trace_row(123, 123, "C_GetSessionInfo",
                            None if i == 0 else b_label,
                            None if i == 0 else b_path, i + 3).rstrip("\n")
                  for i in range(3)]
    return ("\n".join(lines) + "\n").replace(":3", ":6"), ledger, receipt


def trace_unreadable(invented=False):
    """The unreadable-exe image must stay Unknown; other images stay named."""
    text, ledger, receipt = trace_base()
    lines = text.splitlines()
    if invented:
        lines[0] = trace_row(123, 123, "C_GenerateRandom",
                             "guessed", "/owned/guessed", 0).rstrip("\n")
    return "\n".join(lines) + "\n", ledger, receipt


def trace_mapped_only_phantom():
    """A trace row for an image with zero ledgered calls is a phantom."""
    text, ledger, receipt = trace_base()
    phantom = dict(ledger[0], image=1, pid=129, path="/owned/mapped-only",
                   dev=11, ino=12, t=72)
    target = dict(ledger[1], image=1)
    ledger = ledger + [phantom, target]
    receipt["images"].append(copy.deepcopy(phantom))
    receipt["selected_initial_pids"] = [123, 129]
    lines = text.splitlines()
    lines[1:1] = [trace_row(129, 129, "C_GenerateRandom",
                            "mapped-only", "/owned/mapped-only", 1).rstrip("\n")]
    return ("\n".join(lines) + "\n").replace(":3", ":4"), ledger, receipt


def trace_slow_reader_drop():
    """A delivered-but-dropped row disagrees with the terminal counts."""
    text, ledger, receipt = trace_base()
    lines = text.splitlines()
    del lines[1]
    return "\n".join(lines) + "\n", ledger, receipt


def trace_unknown_honest():
    _, ledger, receipt = trace_base()
    receipt = dict(receipt, require_named=False)
    rows = [trace_row(123, 123, "C_GenerateRandom", None, None, i) for i in range(3)]
    return "".join(rows) + trace_counts_events(3), ledger, receipt


def run_trace_twins():
    """(twin, want_pass, triple) list: green twins must pass, red must fail."""
    green = trace_base()
    return [
        ("trace-green-named-positive", True, green),
        ("trace-red-false-name", False,
         (green[0].replace('exe="/owned/trace-a"', 'exe="/owned/other"', 1)
          .replace('"trace-a"', '"other"', 1), green[1], green[2])),
        ("trace-green-duplicate-basename", True, trace_duplicate_basename()),
        ("trace-red-basename-confusion", False, trace_duplicate_basename(confuse=True)),
        ("trace-green-exec-generations", True, trace_exec_pair()),
        ("trace-red-exec-mixup", False, trace_exec_pair(mixup=True)),
        ("trace-green-unreadable-unknown", True, trace_unreadable()),
        ("trace-red-unreadable-invented", False, trace_unreadable(invented=True)),
        ("trace-green-unknown-honest", True, trace_unknown_honest()),
        ("trace-red-mapped-only-phantom", False, trace_mapped_only_phantom()),
        ("trace-red-slow-reader-drop", False, trace_slow_reader_drop()),
    ]


def check_trace_twin(evaluate, name, want_pass, triple):
    trace, ledger, receipt = triple
    result = evaluate(trace, ledger, copy.deepcopy(receipt), None)
    detail = {"named": result.get("named"), "unknown": result.get("unknown"),
              "false_names": result.get("false_names"),
              "errors": result.get("errors", [])[:3]}
    if want_pass:
        require(result["pass"], f"{name}: expected pass, errors={result.get('errors')}")
        if name == "trace-green-named-positive":
            require(result["named"] == 2 and result["unknown"] == 1
                    and result["false_names"] == 0, f"{name}: wrong population {detail}")
    else:
        require(not result["pass"], f"{name}: mutation was accepted: {detail}")
    return detail


# ---------------------------------------------------------------------------
# Ledger twins: synthetic C8 runs through the real inventory-native oracle.
# ---------------------------------------------------------------------------

def ledger_case(module, root, mutate=None, **write_kw):
    synth = module["Synth"]("native")
    doc = copy.deepcopy(synth.doc)
    dash = copy.deepcopy(synth.dash_doc)
    extra = mutate(synth, doc, dash) if mutate else None
    write_kw.update(extra or {})
    path = synth.write(str(root), doc=doc, dash_doc=dash, **write_kw)
    result = module["oracle"](path)
    failed = sorted({row["check"] for row in result.failed()})
    return result, failed


def ledger_cell_id(synth, cell, gen=0, idx=0):
    keys = sorted(key for key in synth.ids if key[0] == cell and key[2] == gen)
    return synth.ids[keys[idx]]


def ledger_drop_use(synth, doc, _dash):
    edge = next(edge for edge in doc["edges"]
                if edge["caller"] == ledger_cell_id(synth, "P1")
                and edge["module"] == synth.mid["A"])
    doc["edges"].remove(edge)
    return None


def ledger_phantom_edge(synth, doc, _dash):
    real = next(edge for edge in doc["edges"]
                if edge["caller"] == ledger_cell_id(synth, "P1"))
    phantom = copy.deepcopy(real)
    phantom["module"] = synth.mid["C"]
    doc["edges"].append(phantom)
    return None


def ledger_exec_merged(synth, doc, _dash):
    gone = {ledger_cell_id(synth, "P5", gen) for gen in (1, 2)}
    doc["callers"] = [caller for caller in doc["callers"] if caller["id"] not in gone]
    doc["edges"] = [edge for edge in doc["edges"] if edge["caller"] not in gone]
    doc["gaps"].append({"caller": None, "module": synth.mid["A"], "pid": None,
                       "subject": "used by an unidentified caller image",
                       "reason": "x", "budget": None, "repeats": 1})
    return None


def ledger_corrupt_frames(synth, doc, dash):
    frames = bytearray(synth.frames(dash))
    start = frames.rfind(b"p11scope inventory")
    require(start > 0, "synthetic frames lack the dashboard header")
    end = frames.find(b"\n", start)
    line = bytearray(frames[start:end])
    pos = line.rfind(b" edges")
    require(pos > 0, "dashboard header lacks edge totals")
    digit = bytes(line[pos - 1:pos])
    require(b"0" <= digit <= b"9", "edge total is not numeric")
    line[pos - 1:pos] = b"8" if digit == b"9" else bytes([digit[0] + 1])
    frames[start:end] = line
    return {"frames": bytes(frames)}


def ledger_drop_stream_record(synth, doc, _dash):
    events = synth.events(doc, True)
    index = next(i for i, event in enumerate(events)
                 if event.get("kind") == "edge_observed")
    del events[index]
    return {"events": events}


def check_ledger_twin(module, root, name, want_pass, mutate=None, **write_kw):
    result, failed = ledger_case(module, root, mutate, **write_kw)
    summary = result.summary()
    detail = {"exit": result.exit_code(), "failed": failed,
              "passed": summary.get("pass", 0)}
    if want_pass:
        require(not failed and detail["passed"] > 0,
                f"{name}: expected pass, failed={failed}")
        rows = result.rows
        require(any(row["check"] == "AGREE-EDGE-EVENTS" and row["status"] == "pass"
                    for row in rows), f"{name}: pipe JSON/JSONL agreement not proven")
        require(any(row["check"] == "DASH-TOTALS" and row["status"] == "pass"
                    for row in rows), f"{name}: PTY frame/document agreement not proven")
        require(any(row["check"] == "IDLE-NOT-POSITIVE" and row["run"] == "dashboard"
                    for row in rows), f"{name}: idle dashboard cell missing")
    else:
        require(result.exit_code() != 0,
                f"{name}: mutation exited {result.exit_code()}, expected nonzero")
    return detail


def run_ledger_twins(module, root):
    cases = [("ledger-green-native-pass", True, None, {}),
             ("ledger-red-drop-use", False, ledger_drop_use, {}),
             ("ledger-red-phantom-edge", False, ledger_phantom_edge, {}),
             ("ledger-red-exec-merged", False, ledger_exec_merged, {}),
             ("ledger-red-pty-disagree", False, ledger_corrupt_frames, {}),
             ("ledger-red-pipe-disagree", False, ledger_drop_stream_record, {})]
    results = []
    for index, (name, want_pass, mutate, write_kw) in enumerate(cases):
        cell_root = root / ("c8-%02d" % index)
        detail = check_ledger_twin(module, cell_root, name, want_pass, mutate, **write_kw)
        results.append((name, detail))
    return results


# ---------------------------------------------------------------------------
# Rotation twins: conservation plus ledger match over retained rotation files.
# ---------------------------------------------------------------------------

def parse_ledger_uses(text):
    """(pid, module path) uses from inventory-ledger LEDGER lines."""
    return {(pid, module) for pid, module, _t0, _t1 in parse_ledger_use_windows(text)}


def parse_ledger_use_windows(text):
    """(pid, module, t0, t1) uses; times are CLOCK_MONOTONIC ns like capture."""
    uses = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != "LEDGER":
            continue
        record = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
        require("pid" in record and "module" in record, f"ledger line lacks pid/module: {line[:120]}")
        uses.append((int(record["pid"]), record["module"],
                     int(record.get("t0", 0)), int(record.get("t1", 0))))
    require(uses, "rotation ledger has no LEDGER uses")
    return uses


def ledger_uses_in_window(text, window):
    """Uses overlapping the capture window; idle-outside uses are excluded."""
    start, end = window
    require(isinstance(start, int) and isinstance(end, int) and start < end,
            f"invalid capture window: {window!r}")
    return {(pid, module) for pid, module, t0, t1 in parse_ledger_use_windows(text)
            if t0 < end and t1 > start}


def rotation_verdict(doc, files, ledger_text, window=None):
    """Conservation plus exact retained-population match against the ledger.

    Returns (ok, detail); raises only on malformed inputs. Every retained
    edge_observed record must match a ledgered use, every ledgered in-window
    use must retain a record, and retained + accounted must equal emitted.
    Without a window every ledgered use is in-window (twin shorthand).
    """
    errors = []
    records = []
    for path in files:
        payload = read_bounded(path)
        for lineno, line in enumerate(payload.splitlines(), 1):
            try:
                record = json.loads(line)
            except ValueError:
                errors.append(f"{path}:{lineno}: invalid JSON")
                continue
            if record.get("schema") != EVENTS_SCHEMA:
                errors.append(f"{path}:{lineno}: wrong schema")
                continue
            records.append(record)
    seqs = [record["seq"] for record in records
            if isinstance(record.get("seq"), int)]
    if len(seqs) != len(records):
        errors.append("some records lack integer seq")
    emitted = max(seqs) + 1 if seqs else 0

    def event_of(record):
        event = record.get("event")
        return event if isinstance(event, dict) else {}

    evicted = [record for record in records if record.get("kind") == "retention_evicted"]
    accounted = sum(event_of(record).get("evicted_events", 0)
                    + event_of(record).get("covered_events", 0) for record in evicted)
    rotated = [record for record in records if record.get("kind") == "rotated"]
    ended = [record for record in records if record.get("kind") == "ended"]
    if len(files) < 2 or not rotated:
        errors.append("rotation was not exercised (need 2+ files and a rotated marker)")
    if not evicted or accounted <= 0:
        errors.append("retention eviction was not exercised")
    if len(ended) != 1:
        errors.append(f"expected exactly one ended marker, saw {len(ended)}")
    elif event_of(ended[0]).get("edges_unretained"):
        errors.append("edges_unretained is nonzero: retention cannot prove the population")
    if len(records) + accounted != emitted:
        errors.append(f"retained {len(records)} + accounted {accounted} != emitted {emitted}")
    if len(set(seqs)) != len(seqs):
        errors.append("duplicate seq in retained records")
    callers = {caller["id"]: caller for caller in doc.get("callers", [])}
    modules = {module["id"]: module for module in doc.get("modules", [])}
    retained = set()
    for record in records:
        if record.get("kind") != "edge_observed":
            continue
        context = record.get("identity_context", {})
        caller, module = context.get("caller", {}), context.get("module", {})
        pid, path = caller.get("pid"), module.get("path")
        if not isinstance(pid, int) or not path:
            errors.append("edge_observed lacks caller pid/module path context")
            continue
        if caller.get("id") not in callers or module.get("id") not in modules:
            errors.append("edge_observed references unknown caller/module ids")
            continue
        retained.add((pid, path))
    uses = (parse_ledger_uses(ledger_text) if window is None
            else ledger_uses_in_window(ledger_text, window))
    for use in sorted(uses - retained):
        errors.append(f"ledgered use has no retained record: pid={use[0]} module={use[1]}")
    for use in sorted(retained - uses):
        errors.append(f"retained record is not ledgered: pid={use[0]} module={use[1]}")
    detail = {"files": len(files), "retained": len(records), "accounted": accounted,
              "emitted": emitted, "uses": len(uses), "errors": errors[:5]}
    return not errors, detail


def rotation_fixture(root, *, drop_seq=None, duplicate_seq=None, phantom=False,
                     missing_use=False, single_file=False, extra_idle_use=False):
    """Synthetic two-generation rotation: three files, one eviction, full ledger."""
    doc = {"callers": [{"id": "c0", "pid": 501},
                       {"id": "c1", "pid": 502}],
           "modules": [{"id": "m0", "paths": ["/prov/a/libsofthsm2.so"]},
                       {"id": "m1", "paths": ["/prov/b/libsofthsm2.so"]}],
           "edges": []}
    ledger_lines = ["IDENT cell=P1 pid=501 start=5777 gen=0 exe=/wl/ledger",
                    "MAPPED cell=P1 pid=501 start=5777 gen=0 exe=/wl/ledger module=/prov/a/libsofthsm2.so ino=101",
                    "LEDGER cell=P1 pid=501 start=5777 gen=0 exe=/wl/ledger module=/prov/a/libsofthsm2.so fn=C_GetSlotList mech=- n=3 bad=0 phase=main t0=11 t1=12",
                    "IDENT cell=P2 pid=502 start=5778 gen=0 exe=/wl/ledger",
                    "MAPPED cell=P2 pid=502 start=5778 gen=0 exe=/wl/ledger module=/prov/b/libsofthsm2.so ino=102",
                    "LEDGER cell=P2 pid=502 start=5778 gen=0 exe=/wl/ledger module=/prov/b/libsofthsm2.so fn=C_GetSlotList mech=- n=2 bad=0 phase=main t0=13 t1=14",
                    "DONE cell=P1 pid=501", "DONE cell=P2 pid=502"]
    if extra_idle_use:
        ledger_lines += ["IDENT cell=P9 pid=509 start=5799 gen=0 exe=/wl/ledger",
                         "LEDGER cell=P9 pid=509 start=5799 gen=0 exe=/wl/ledger module=/prov/z/idle.so fn=C_GetSlotList mech=- n=1 bad=0 phase=main t0=100000 t1=100010"]
    ledger_text = "\n".join(ledger_lines) + "\n"

    def edge(pid, cid, module, mid, seq):
        return {"schema": EVENTS_SCHEMA, "seq": seq, "kind": "edge_observed",
                "event": {"caller": cid, "module": mid},
                "identity_context": {"version": 1,
                                     "caller": {"id": cid, "pid": pid},
                                     "module": {"id": mid, "path": module}}}

    seq = [0]

    def numbered(kind, event):
        record = {"schema": EVENTS_SCHEMA, "seq": seq[0], "kind": kind, "event": event}
        seq[0] += 1
        return record

    evicted = [numbered("started", {}),
               numbered("edge_observed", {"caller": "c0", "module": "m0"})]
    evicted[1]["identity_context"] = {"version": 1, "caller": {"id": "c0", "pid": 501},
                                      "module": {"id": "m0", "path": "/prov/a/libsofthsm2.so"}}
    first = [numbered("rotated", {"prior_file": "events.jsonl.1", "prior_events": 2,
                                  "prior_bytes": 10, "rotation_seq": 1}),
             numbered("retention_evicted", {"evicted_file": "events.jsonl.1",
                                            "evicted_events": 2, "evicted_bytes": 10,
                                            "covered_events": 0, "covered_bytes": 0,
                                            "reason": "retention"}),
             edge(501, "c0", "/prov/a/libsofthsm2.so", "m0", seq[0])]
    seq[0] += 1
    live = [numbered("rotated", {"prior_file": "events.jsonl.2", "prior_events": 3,
                                 "prior_bytes": 12, "rotation_seq": 2})]
    if not missing_use:
        live.append(edge(502, "c1", "/prov/b/libsofthsm2.so", "m1", seq[0]))
        seq[0] += 1
    if phantom:
        live.append(edge(599, "c0", "/prov/ghost.so", "m0", seq[0]))
        seq[0] += 1
    live.append(numbered("pass_committed", {"pass": 1}))
    live.append(numbered("ended", {"edges_unretained": 0}))
    if single_file:
        # One live file, no rotation at all: strip rotation markers and
        # renumber so the only verdict error is "not exercised".
        rows = [row for row in evicted + first + live
                if row.get("kind") not in ("rotated", "retention_evicted")]
        for seq_no, row in enumerate(rows):
            row["seq"] = seq_no
        files = {"events.jsonl": rows}
    else:
        # events.jsonl.1 was evicted (absent); .2 and live are retained.
        files = {"events.jsonl.2": first, "events.jsonl": live}
    paths = []
    for name, rows in files.items():
        if drop_seq is not None:
            rows = [row for row in rows if row.get("seq") != drop_seq]
        if duplicate_seq is not None:
            extra = [row for row in rows if row.get("seq") == duplicate_seq]
            rows = rows + extra
        path = root / name
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        paths.append(path)
    return doc, sorted(paths), ledger_text


def run_rotation_twins(root):
    cases = [("rotation-green-conserved", True, {}, None),
             ("rotation-green-window-excludes-idle", True, {"extra_idle_use": True}, (10, 20)),
             ("rotation-red-gap", False, {"drop_seq": 4}, None),
             ("rotation-red-duplicate", False, {"duplicate_seq": 6}, None),
             ("rotation-red-phantom", False, {"phantom": True}, None),
             ("rotation-red-missing-use", False, {"missing_use": True}, None),
             ("rotation-red-no-rotation", False, {"single_file": True}, None)]
    results = []
    for index, (name, want_pass, options, window) in enumerate(cases):
        cell_root = root / ("rotation-%02d" % index)
        cell_root.mkdir(mode=0o700, parents=True)
        doc, files, ledger_text = rotation_fixture(cell_root, **options)
        ok, detail = rotation_verdict(doc, files, ledger_text, window)
        if want_pass:
            require(ok, f"{name}: expected pass: {detail}")
        else:
            require(not ok, f"{name}: mutation was accepted: {detail}")
        results.append((name, detail))
    return results


ROTATION_RED_OPTIONS = {"rotation-red-gap": {"drop_seq": 4},
                        "rotation-red-duplicate": {"duplicate_seq": 6},
                        "rotation-red-phantom": {"phantom": True},
                        "rotation-red-missing-use": {"missing_use": True},
                        "rotation-red-no-rotation": {"single_file": True}}
LEDGER_RED_MUTATIONS = {"ledger-red-drop-use": ledger_drop_use,
                        "ledger-red-phantom-edge": ledger_phantom_edge,
                        "ledger-red-exec-merged": ledger_exec_merged,
                        "ledger-red-pty-disagree": ledger_corrupt_frames,
                        "ledger-red-pipe-disagree": ledger_drop_stream_record}


# ---------------------------------------------------------------------------
# Diff-path twins: synthetic saved-inventory pairs through the real offline
# diff journey. The binary computes the offline comparison only; no capture
# provenance is claimed from this twin.
# ---------------------------------------------------------------------------

DIFF_CASES = ("diff-green-known-change", "diff-red-empty-population", "diff-red-wrong-schema")


def check_diff_twin(cross, binary, root, name, want_pass):
    value = json.loads(cross["FIXTURE"].read_bytes())
    before, after = root / (name + "-before.json"), root / (name + "-after.json")
    if name == "diff-green-known-change":
        cross["write_input"](before, value)
        changed = copy.deepcopy(value)
        changed["modules"][0]["identity"]["sha256"] = "b" * 64
        cross["write_input"](after, changed)
    elif name == "diff-red-empty-population":
        empty = {"schema": INVENTORY_SCHEMA, "callers": [], "modules": [], "edges": []}
        cross["write_input"](before, empty)
        cross["write_input"](after, empty)
    elif name == "diff-red-wrong-schema":
        cross["write_input"](before, value)
        cross["write_input"](after, {"schema": "wrong"})
    else:
        raise AssertionError(f"unknown diff twin: {name}")
    journey = cross["Journey"](binary, root)
    if want_pass:
        journey.saved(before, after, label=name)
        return {"pair": name}
    try:
        journey.saved(before, after, label=name)
    except AssertionError:
        return {"rejected": name}
    raise AssertionError(f"{name}: mutation was accepted")


def run_diff_twins(cross, binary, root):
    return [(name, check_diff_twin(cross, binary, root, name, name.startswith("diff-green")))
            for name in DIFF_CASES]


# ---------------------------------------------------------------------------
# Self-test and the proof-only red seam.
# ---------------------------------------------------------------------------

def red_twins_for(journeys):
    names = []
    if "ledger" in journeys:
        names += sorted(LEDGER_RED_MUTATIONS) + sorted(ROTATION_RED_OPTIONS)
    if "named-trace" in journeys:
        names += [name for name, want, _ in run_trace_twins() if not want]
        names += [name for name in DIFF_CASES if "-red-" in name]
    return names


def run_twin_matrix(journeys, binary, root):
    cells = []
    if "ledger" in journeys:
        module = inventory_oracle_module()
        cells += [(name, "ledger", detail)
                  for name, detail in run_ledger_twins(module, root / "c8")]
        cells += [(name, "ledger", detail)
                  for name, detail in run_rotation_twins(root / "rotation")]
    if "named-trace" in journeys:
        require(binary, "named-trace twins need --binary for the offline diff twin only")
        evaluate = trace_oracle()
        for name, want_pass, triple in run_trace_twins():
            cells.append((name, "named-trace", check_trace_twin(evaluate, name, want_pass, triple)))
        cross = cross_drive_module()
        diff_root = root / "diff"
        diff_root.mkdir(mode=0o700, parents=True)
        cells += [(name, "named-trace", detail)
                  for name, detail in run_diff_twins(cross, binary, diff_root)]
    return cells


def run_red_proof(name, journeys, binary, root):
    """Run one red twin through the pass assertion: it must exit nonzero."""
    require(name in red_twins_for(journeys),
            f"unknown red twin {name!r} for {','.join(journeys)}: {red_twins_for(journeys)}")
    if name in LEDGER_RED_MUTATIONS:
        check_ledger_twin(inventory_oracle_module(), root / "red", name, True,
                          LEDGER_RED_MUTATIONS[name])
    elif name in ROTATION_RED_OPTIONS:
        cell_root = root / "red"
        cell_root.mkdir(mode=0o700, parents=True)
        doc, files, ledger_text = rotation_fixture(cell_root, **ROTATION_RED_OPTIONS[name])
        ok, detail = rotation_verdict(doc, files, ledger_text)
        require(ok, f"{name}: red proof behaves: {detail}")
    elif name.startswith("trace-"):
        triple = next(triple for twin, _want, triple in run_trace_twins() if twin == name)
        check_trace_twin(trace_oracle(), name, True, triple)
    else:
        diff_root = root / "red"
        diff_root.mkdir(mode=0o700, parents=True)
        require(binary, "diff red proof needs --binary for the offline diff twin only")
        check_diff_twin(cross_drive_module(), binary, diff_root, name, True)
    raise AssertionError(f"{name}: red proof twin unexpectedly passed")


def self_test(journeys, binary):
    if binary:
        binary = resolve_binary(binary)
    root = scratch_root()
    try:
        red_proof = os.environ.get(RED_PROOF_ENV)
        if red_proof:
            run_red_proof(red_proof, journeys, binary, root)
        cells = run_twin_matrix(journeys, binary, root)
        summary = {"mode": "self-test", "journeys": journeys,
                   "twins": [{"twin": name, "journey": journey, "detail": detail}
                             for name, journey, detail in cells]}
        print(json.dumps(summary))
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Dry-run: wiring validation without capture.
# ---------------------------------------------------------------------------

LEDGER_HELP_FLAGS = ("--capture", "--event-log", "--event-rotate-bytes", "--event-max-files",
                     "--dashboard", "--pid", "--system", "--module", "--duration", "--json")
TRACE_HELP_FLAGS = ("--cgroup", "--duration", "--max-events", "--manifest")


def dry_run_plan(args, journeys, binary):
    root = scratch_root()
    try:
        resolved = resolve_binary(binary)
        role = binary_role(resolved)
        info = {"path": str(resolved), "sha256": sha256_file(resolved), "role": role}
        top = help_text(resolved, "--help")
        plan = {"mode": "dry-run", "journeys": journeys, "binary": info, "cells": []}
        if "ledger" in journeys:
            require("inventory" in top, "candidate help omits inventory")
            inventory = help_text(resolved, "inventory", "--help")
            for flag in LEDGER_HELP_FLAGS:
                require(flag in inventory, f"candidate inventory help omits {flag}")
            require(QUALIFY_INVENTORY.is_file(), "missing scripts/qualify-inventory-native.sh")
            inventory_oracle_module()
            if args.workload_coordinator:
                plan["cells"].append(validate_coordinator(args.workload_coordinator))
            if args.c8_base:
                require(Path(args.c8_base).is_absolute(), "--c8-base must be absolute")
                plan["cells"].append({"cell": "c8-base", "path": str(args.c8_base)})
            for name in ("pipe-json-matches-ledger", "pty-dashboard-matches-ledger",
                         "u6-compact-pty-matches-ledger", "rotation-conserves-ledger",
                         "exec-generations-match-ledger"):
                plan["cells"].append({"cell": name, "wiring": "validated"})
        if "named-trace" in journeys:
            require("trace" in top, "candidate help omits trace")
            trace = help_text(resolved, "trace", "--help")
            for flag in TRACE_HELP_FLAGS:
                require(flag in trace, f"candidate trace help omits {flag}")
            runner = help_text(resolved, "run", "--trace", "--help")
            require("--trace" in runner, "candidate run help omits --trace")
            require(QUALIFY_TRACE.is_file(), "missing scripts/qualify-cgroup-trace.py")
            plan["trace_inputs"] = trace_inputs(args, live=False)
            if not plan["trace_inputs"]["manifests"]:
                plan.setdefault("live_blockers", []).append(
                    "trusted-manifest inputs absent: supply --provider/--caller/--manifest/--manifest-helper/--helper-source-revision/--uid/--gid")
            native = load_module(QUALIFY_TRACE)["CELLS"]
            for name, cell, rule in U6_TRACE_PLAN:
                if cell not in native:
                    plan["cells"].append({"cell": name, "rule": rule,
                                         "wiring": "twin-verdict-ready",
                                         "live": "needs-qualify-support"})
                else:
                    require(cell in native, f"qualify matrix lacks native cell {cell}")
                    plan["cells"].append({"cell": name, "rule": rule, "wiring": "validated",
                                         "qualify_cell": cell})
            pair = dry_run_pair(args, resolved)
            if pair:
                plan["cells"].append(pair)
        twins = run_twin_matrix(journeys, binary, root)
        plan["twins"] = [{"twin": name, "journey": journey} for name, journey, _ in twins]
        red_proof = os.environ.get(RED_PROOF_ENV)
        if red_proof:
            run_red_proof(red_proof, journeys, binary, root)
        if args.out:
            out = Path(args.out)
            out.mkdir(mode=0o700, parents=True, exist_ok=True)
            (out / "dry-run-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        print(json.dumps(plan))
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


def validate_coordinator(path):
    """Inventory-output native coordinator shape: {pid, modules, ledger, gate?}."""
    raw = read_bounded(path)
    try:
        config = json.loads(raw)
    except ValueError as error:
        raise AssertionError(f"coordinator is not JSON: {error}") from error
    require(type(config.get("pid")) is int and config["pid"] > 1, "coordinator pid must be > 1")
    modules = config.get("modules")
    require(isinstance(modules, list) and modules, "coordinator modules must be nonempty")
    for module in modules:
        require(Path(module).is_file(), f"coordinator module missing: {module}")
    require(Path(config.get("ledger", "")).is_file(), "coordinator ledger missing")
    return {"cell": "workload-coordinator", "pid": config["pid"], "modules": len(modules)}


def trace_inputs(args, live):
    """Resolve and validate named-trace inputs; trusted-manifest discipline."""
    provider = Path(args.provider).resolve(strict=True) if args.provider else None
    caller = Path(args.caller).resolve(strict=True) if args.caller else None
    helper = Path(args.manifest_helper).resolve(strict=True) if args.manifest_helper else None
    if live or args.manifest or provider or caller or helper:
        require(provider and provider.is_absolute(), "an absolute --provider is required")
        require(caller and os.access(caller, os.X_OK), "an executable --caller is required")
        require(args.manifest, "explicit --manifest is required: default discovery is refused")
        require(helper and os.access(helper, os.X_OK),
                "explicit manifests require the held trusted --manifest-helper")
        require(args.helper_source_revision and HEX40.fullmatch(args.helper_source_revision),
                "explicit manifests require the exact 40-hex --helper-source-revision")
        for manifest in args.manifest:
            validate_manifest(Path(manifest).resolve(strict=True), provider)
        require(type(args.uid) is int and args.uid > 0, "an ordinary workload --uid is required")
        require(type(args.gid) is int and args.gid > 0, "an ordinary workload --gid is required")
    return {"provider": str(provider) if provider else None,
            "caller": str(caller) if caller else None,
            "manifests": [str(Path(path).resolve(strict=True)) for path in args.manifest],
            "helper": str(helper) if helper else None}


def validate_manifest(path, provider):
    """Mirror qualify-cgroup-trace manifest/provider binding (bounded read)."""
    require(path.is_absolute(), f"manifest path is not absolute: {path}")
    try:
        document = json.loads(read_bounded(path))
    except ValueError as error:
        raise AssertionError(f"invalid manifest JSON {path}: {error}") from error
    require(isinstance(document, dict), f"manifest must be an object: {path}")
    objects = document.get("objects")
    require(document.get("schema") == MANIFEST_SCHEMA
            and document.get("module_path") == str(provider)
            and isinstance(objects, list) and len(objects) == 1
            and isinstance(objects[0], dict) and objects[0].get("path") == str(provider)
            and isinstance(objects[0].get("identity"), dict)
            and objects[0]["identity"].get("sha256") == sha256_file(provider),
            f"manifest does not bind the held provider: {path}")
    return {"manifest": str(path)}


def dry_run_pair(args, binary):
    if args.before or args.after:
        require(args.before and args.after, "--before and --after must be paired")
        for path in (args.before, args.after):
            require(Path(path).is_file(), f"saved inventory missing: {path}")
        before = json.loads(read_bounded(args.before))
        after = json.loads(read_bounded(args.after))
        for document, path in ((before, args.before), (after, args.after)):
            require(document.get("schema") == INVENTORY_SCHEMA, f"wrong input: {path}")
            require(document.get("callers") and document.get("modules") and document.get("edges"),
                    f"saved input lacks caller/module/edge population: {path}")
        # The offline diff runs unprivileged: prove the diff wiring now.
        code, stdout, stderr = run([sys.executable, "-I", str(CROSS_DRIVE),
                                   "--binary", str(binary),
                                   "--before", str(args.before), "--after", str(args.after)])
        require(code == 0, f"dry-run saved-input diff failed: {stderr[:1024]!r} {stdout[:512]!r}")
        return {"cell": "two-real-saved-inventory-diff", "wiring": "offline-diff-proven"}
    if args.pair_prebuilt:
        require(Path(args.pair_prebuilt).is_dir(), "--pair-prebuilt must exist")
        return {"cell": "two-real-saved-inventory-diff", "wiring": "capture-live"}
    return None


# ---------------------------------------------------------------------------
# Live execution (installed gate only; never runs unprivileged here).
# ---------------------------------------------------------------------------

def capture_ledger_cells(args, resolved, out, record):
    """Shared installed rotation/compact cells; no C8 prerequisite here."""
    coordinator = validate_coordinator(args.workload_coordinator)
    config = json.loads(read_bounded(args.workload_coordinator))
    if config.get("gate"):
        # The coordinator holds its workload on this gate; touching it
        # releases the main phase immediately before each capture below.
        Path(config["gate"]).touch()
    rotation_dir = out / "rotation"
    rotation_dir.mkdir(mode=0o700)
    document = rotation_dir / "report.json"
    stream = rotation_dir / "events.jsonl"
    argv = [str(resolved), "inventory", "--pid", str(config["pid"])]
    for module in config["modules"]:
        argv += ["--module", module]
    # Retain the real edge and terminal accounting record; 1K leaves no
    # guaranteed refresh capacity after the writer's control allowance.
    argv += ["--capture", "native", "--duration", "20s", "--json", "-o", str(document),
            "--event-log", str(stream), "--event-rotate-bytes", "8K", "--event-max-files", "3"]
    code, _stdout, stderr = run(argv, timeout=120)
    record("rotation-capture", code == 0,
           {"exit": code, "stderr": stderr[:512].decode("utf-8", "replace")})
    require(code == 0, f"installed rotation capture failed: {stderr[:512]!r}")
    report = json.loads(read_bounded(document))
    observation = report.get("observation", {})
    require(observation.get("lane") == "native",
            "scan fallback fails the installed rotation cell")
    window = (observation.get("started_ns"), observation.get("ended_ns"))
    require(isinstance(window[0], int) and isinstance(window[1], int),
            "rotation report lacks the capture window")
    files = sorted(rotation_dir.glob("events.jsonl*"))
    ok, detail = rotation_verdict(report, files, read_bounded(config["ledger"]).decode(),
                                  window)
    record("rotation-conserves-ledger", ok, detail)
    require(ok, f"installed rotation cell failed: {detail}")
    pty_dir = out / "compact-pty"
    pty_dir.mkdir(mode=0o700)
    pty_doc, pty_stream, pty_out = (pty_dir / name for name in
                                    ("report.json", "events.jsonl", "compact.pty"))
    dashboard = [str(resolved), "inventory", "--pid", str(config["pid"])]
    for module in config["modules"]:
        dashboard += ["--module", module]
    dashboard += ["--capture", "native", "--duration", "25s", "--dashboard",
                  "-o", str(pty_doc), "--event-log", str(pty_stream)]
    if config.get("gate"):
        Path(config["gate"]).touch()
    code, stdout, _ = run([sys.executable, "-I", str(INVENTORY_ORACLE), "record-pty",
                           str(pty_out), "12", "48", "60", "20", "--"] + dashboard, timeout=120)
    match = re.search(r"rc=(\d+)", stdout.decode())
    observer_rc = int(match.group(1)) if match else None
    record("u6-compact-pty-capture", code == 0 and observer_rc == 0,
           {"exit": code, "observer_rc": observer_rc})
    require(code == 0 and observer_rc == 0, "installed U6 compact PTY capture failed")
    compact = compact_pty_verdict(json.loads(read_bounded(pty_doc)),
                                  read_bounded(pty_out), config)
    record("u6-compact-pty-matches-ledger", compact[0], compact[1])
    require(compact[0], f"installed U6 compact PTY cell failed: {compact[1]}")
    return coordinator


def live_ledger(args, binary, out):
    resolved = resolve_binary(binary)
    revision = args.source_revision or os.environ.get(REVISION_ENV, "")
    require(HEX40.fullmatch(revision or ""), "live mode requires the exact 40-hex source revision")
    require(args.c8_base and Path(args.c8_base).is_absolute(), "live mode requires --c8-base")
    cells = []
    info = {"path": str(resolved), "sha256": sha256_file(resolved),
            "role": binary_role(resolved), "source_revision": revision}

    def record(name, ok, detail):
        cells.append({"cell": name, "pass": bool(ok), "detail": detail})
        return ok

    code, stdout, stderr = run([str(QUALIFY_INVENTORY), str(resolved), "--lane", "native",
                                "--base", str(args.c8_base)],
                               timeout=1500, output_limit=16 * 1024 * 1024)
    record("c8-system-dashboard-stop", code == 0,
           {"exit": code, "tail": (stdout + stderr)[-1024:].decode("utf-8", "replace")})
    require(code == 0, f"installed inventory qualification failed with exit {code}")
    coordinator = capture_ledger_cells(args, resolved, out, record)
    receipt = {"mode": "live", "journey": "ledger", "binary": info,
               "coordinator": coordinator, "cells": cells,
               "pass": all(cell["pass"] for cell in cells)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return 0 if receipt["pass"] else 1


def live_ledger_component(args, binary, out):
    resolved = resolve_binary(binary)
    revision = args.source_revision or os.environ.get(REVISION_ENV, "")
    require(HEX40.fullmatch(revision or ""), "live mode requires the exact 40-hex source revision")
    cells = []
    info = {"path": str(resolved), "sha256": sha256_file(resolved),
            "role": binary_role(resolved), "source_revision": revision}

    def record(name, ok, detail):
        cells.append({"cell": name, "pass": bool(ok), "detail": detail})
        return ok

    coordinator = capture_ledger_cells(args, resolved, out, record)
    receipt = {"mode": "live", "journey": "ledger-component", "qualification": "component_only",
               "covers": ["rotation", "compact-pty"], "not_evaluated": ["c8-system-dashboard-stop"],
               "binary": info, "coordinator": coordinator, "cells": cells,
               "pass": all(cell["pass"] for cell in cells)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return 0 if receipt["pass"] else 1


def compact_pty_verdict(doc, transcript, config):
    """Join full/48x12 dashboard references to saved identities and the ledger."""
    module = inventory_oracle_module()
    table = module["FRAME"]
    frames = module["parse_frames"](transcript)
    errors = []
    minimal = []
    # The shared parser recognizes full-layout headers. The 48x12 renderer
    # uses render_minimal's separate totals and application/module rows.
    body = transcript.split(table["alt_off"], 1)[0]
    for chunk in body.split(table["repaint"])[1:]:
        lines = table["ansi"].sub(b"", chunk).replace(b"\r", b"").decode("utf-8", "replace").split("\n")
        if lines and re.fullmatch(r"p11scope inventory .+ \(minimal\)", lines[0]):
            minimal.append(lines)
        elif lines and lines[0].startswith("p11scope inventory") and not table["header"].match(lines[0]):
            errors.append("unrecognized dashboard frame header")
    if minimal:
        if frames:
            errors.append("mixed full and compact dashboard layouts")
        frames = minimal
    if not frames or table["alt_on"] not in transcript or table["alt_off"] not in transcript:
        errors.append("no complete alternate-screen dashboard session")

    def identities(name, pattern):
        result = {}
        rows = doc.get(name)
        if not isinstance(rows, list) or not rows:
            errors.append("missing saved identity population")
            return result
        for row in rows:
            identity = row.get("id") if isinstance(row, dict) else None
            if not isinstance(identity, str) or not re.fullmatch(pattern, identity) or identity in result:
                errors.append("invalid or duplicate saved identity reference")
                continue
            result[identity] = row
        return result

    callers, modules = identities("callers", r"c[0-9]+"), identities("modules", r"m[0-9]+")
    for caller in callers.values():
        if type(caller.get("pid")) is not int or caller["pid"] <= 0:
            errors.append("saved caller lacks a valid PID")
    pairs = set()
    edges = doc.get("edges")
    if not isinstance(edges, list) or not edges:
        errors.append("missing saved edge population")
    else:
        for edge in edges:
            pair = (edge.get("caller"), edge.get("module")) if isinstance(edge, dict) else (None, None)
            if (not all(isinstance(ref, str) for ref in pair) or pair[0] not in callers
                    or pair[1] not in modules or pair in pairs):
                errors.append("invalid or duplicate saved edge reference")
            else:
                pairs.add(pair)
    totals = (re.fullmatch(r"totals: (\d+) callers (\d+) modules (\d+) edges", frames[-1][1])
              if minimal and len(frames[-1]) > 1 else
              table["header"].match(frames[-1][0]) if frames else None)
    if not totals:
        errors.append("final frame lacks the coverage header totals")
    else:
        counts = totals.groups() if minimal else totals.groups()[2:]
        if tuple(map(int, counts)) != (len(callers), len(modules), len(edges) if isinstance(edges, list) else 0):
            errors.append("frame totals disagree with the saved document")

    ledger_pids, frame_pids = set(), set()
    for line in read_bounded(config["ledger"]).decode().splitlines():
        if line.startswith("IDENT "):
            pid = re.search(r"(?:^| )pid=([0-9]+)(?: |$)", line)
            if pid is None or int(pid.group(1)) <= 0:
                errors.append("ledger identity lacks a valid PID")
            else:
                ledger_pids.add(int(pid.group(1)))

    def bind(pair, shown):
        if pair not in pairs or pair in shown:
            errors.append("frame pair is missing, duplicated or not a saved edge")
            return
        shown.add(pair)
        pid = callers[pair[0]].get("pid")
        if type(pid) is int and pid > 0:
            frame_pids.add(pid)

    for lines in frames:
        shown, pending = set(), None
        for line in lines:
            if minimal:
                if line.startswith(("application ", "> application ")):
                    if pending is not None:
                        errors.append("compact application lacks its module row")
                    match = re.fullmatch(r"(?:> )?application .* \[(c\d+)\]", line)
                    pending = match.group(1) if match else None
                    if match is None:
                        errors.append("malformed compact caller reference")
                elif line.startswith("module "):
                    match = re.fullmatch(r"module .* \[(m\d+)\]", line)
                    if pending is None or match is None:
                        errors.append("malformed or unpaired compact module reference")
                    else:
                        bind((pending, match.group(1)), shown)
                    pending = None
                elif pending is not None:
                    errors.append("compact application lacks its module row")
                    pending = None
            else:
                match = table["identity"].match(line)
                if match:
                    bind((match.group(2), match.group(4)), shown)
                elif " -> " in line:
                    errors.append("malformed full dashboard identity reference")
        if pending is not None:
            errors.append("compact application lacks its module row")
    if not frame_pids:
        errors.append("frames name no caller pids")
    for pid in sorted(frame_pids - ledger_pids):
        errors.append(f"frame pid is not ledgered: {pid}")
    for pid in sorted(ledger_pids - frame_pids):
        errors.append(f"ledgered pid never framed: {pid}")
    detail = {"frames": len(frames), "frame_pids": sorted(frame_pids),
              "ledger_pids": sorted(ledger_pids), "errors": errors[:5]}
    return not errors, detail


def live_named_trace(args, binary, out):
    resolved = resolve_binary(binary)
    revision = args.source_revision or os.environ.get(REVISION_ENV, "")
    require(HEX40.fullmatch(revision or ""), "live mode requires the exact 40-hex source revision")
    inputs = trace_inputs(args, live=True)
    requested = (args.cells if args.cells is not None else
                 ",".join(U6_TRACE_NATIVE_CELLS + U6_TRACE_EXTENDED_TWINS)).split(",")
    require(all(requested) and len(set(requested)) == len(requested),
            "trace cells must be nonempty and unique")
    native = load_module(QUALIFY_TRACE)["CELLS"]
    unsupported = [name for name in requested if name not in native]
    require(not unsupported, f"qualify matrix lacks requested trace cells: {unsupported}")
    info = {"path": str(resolved), "sha256": sha256_file(resolved),
            "role": binary_role(resolved), "source_revision": revision}
    cells = []

    def record(name, ok, detail):
        cells.append({"cell": name, "pass": bool(ok), "detail": detail})
        return ok

    qualify_out = out / "qualify"
    # The qualifier owns new-only directory creation and refuses reuse.
    argv = [sys.executable, "-I", str(QUALIFY_TRACE), "--binary", str(resolved),
           "--provider", inputs["provider"], "--caller", inputs["caller"],
           "--source-revision", revision]
    for manifest in inputs["manifests"]:
        argv += ["--manifest", manifest]
    argv += ["--manifest-helper", inputs["helper"],
            "--helper-source-revision", args.helper_source_revision,
            "--uid", str(args.uid), "--gid", str(args.gid),
            "--cells", ",".join(requested),
            "--out", str(qualify_out)]
    code, stdout, stderr = run(argv, timeout=900, output_limit=16 * 1024 * 1024)
    record("qualify-native-cells", code == 0,
           {"exit": code, "tail": (stdout + stderr)[-1024:].decode("utf-8", "replace")})
    require(code == 0, f"installed trace qualification failed with exit {code}")
    for twin, cell, rule in U6_TRACE_PLAN:
        if cell not in requested:
            record(twin, False, {"not_requested": cell, "rule": rule})
            continue
        result = json.loads(read_bounded(qualify_out / cell / "result.json"))
        require(isinstance(result, dict), f"native trace result must be an object: {cell}")
        errors = result.get("errors")
        detail = {"pass": result.get("pass"), "calls": result.get("calls"),
                  "named": result.get("named"), "unknown": result.get("unknown"),
                  "false_names": result.get("false_names"),
                  "errors": errors[:3] if isinstance(errors, list) else ["invalid result errors"]}
        counts = [result.get(key) for key in ("calls", "named", "unknown", "false_names")]
        valid_counts = all(type(value) is int and value >= 0 for value in counts)
        ok = (result.get("cell") == cell and result.get("pass") is True
              and valid_counts and counts[0] > 0 and counts[1] + counts[2] == counts[0]
              and counts[3] == 0 and errors == [])
        if twin == "named-positive" or twin in U6_TRACE_EXTENDED_TWINS:
            ok = ok and counts[1] > 0
        elif twin == "exec-generations":
            generations = result.get("image_generation_populations", {})
            ok = (ok and isinstance(generations, dict) and len(generations) >= 2
                  and all(isinstance(pop, dict) and type(pop.get("named")) is int
                          and pop["named"] > 0 for pop in generations.values()))
        record(twin, ok, dict(detail, rule=rule))
    pair = live_pair(args, resolved, out)
    record("two-real-saved-inventory-diff", pair[0], pair[1])
    receipt = {"mode": "live", "journey": "named-trace", "binary": info,
               "inputs": inputs, "cells": cells,
               "pass": all(cell["pass"] for cell in cells)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return 0 if receipt["pass"] else 1


def live_pair(args, binary, out):
    if args.before and args.after:
        before, after = Path(args.before), Path(args.after)
    elif args.pair_prebuilt:
        pair_out = out / "pair"
        # The capture driver owns new-only directory creation and refuses reuse.
        revision = args.source_revision or os.environ.get(REVISION_ENV, "")
        code, stdout, stderr = run([sys.executable, "-I", str(CAPTURE_PAIR),
                                   "--binary", str(binary),
                                   "--prebuilt", str(args.pair_prebuilt),
                                   "--out", str(pair_out),
                                   "--source-revision", revision], timeout=600)
        if code != 0:
            return False, {"capture_exit": code, "stderr": stderr[:512].decode("utf-8", "replace"),
                           "stdout": stdout[:512].decode("utf-8", "replace")}
        before, after = pair_out / "before" / "snapshot.json", pair_out / "after" / "snapshot.json"
    else:
        return False, {"blocked": "the diff path needs --before/--after or --pair-prebuilt"}
    code, stdout, stderr = run([sys.executable, "-I", str(CROSS_DRIVE),
                                "--binary", str(binary),
                                "--before", str(before), "--after", str(after)], timeout=120)
    return code == 0, {"exit": code, "before": str(before), "after": str(after),
                       "tail": (stdout + stderr)[-1024:].decode("utf-8", "replace")}


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journey", choices=["ledger", "ledger-component", "named-trace"],
                        help="U6 journey (ledger-component is live-only; self-test defaults to both full journeys)")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--binary", help="explicit candidate path")
    parser.add_argument("--source-revision", help="exact 40-hex source commit (or env)")
    parser.add_argument("--out", type=Path, help="receipt/output directory")
    parser.add_argument("--c8-base", type=Path, help="root-owned qualify-inventory base")
    parser.add_argument("--workload-coordinator", type=Path,
                        help="native workload coordinator JSON {pid, modules, ledger, gate?}")
    parser.add_argument("--provider", type=Path)
    parser.add_argument("--caller", type=Path)
    parser.add_argument("--manifest", type=Path, action="append", default=[])
    parser.add_argument("--manifest-helper", type=Path)
    parser.add_argument("--helper-source-revision")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    parser.add_argument("--cells", help="trace cells (default: the full U6 twin matrix)")
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--pair-prebuilt", type=Path)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test and args.dry_run:
        parser.error("--self-test and --dry-run are exclusive")
    if args.journey == "ledger-component" and (args.self_test or args.dry_run):
        parser.error("ledger-component is live-only and does not qualify C8 or full U6")
    if os.environ.get(RED_PROOF_ENV) and not (args.self_test or args.dry_run):
        parser.error(f"{RED_PROOF_ENV} is proof-only; live mode refuses it")
    journeys = [args.journey] if args.journey else (["ledger", "named-trace"]
                                                    if args.self_test else None)
    if journeys is None:
        parser.error("--journey is required for --dry-run and live modes")
    binary = args.binary or os.environ.get(INSTALLED_ENV)
    if args.self_test:
        if "named-trace" in journeys and not binary:
            parser.error("named-trace --self-test needs --binary for the offline diff twin")
        return self_test(journeys, binary)
    if args.dry_run:
        if not binary:
            parser.error("--dry-run needs --binary (installed candidate or shape stand-in)")
        return dry_run_plan(args, journeys, binary)
    if not binary:
        parser.error("live mode needs --binary (or " + INSTALLED_ENV + ")")
    if not args.out:
        parser.error("live mode needs --out")
    require(not args.out.exists(), f"live --out must be new: {args.out}")
    out = args.out
    out.mkdir(mode=0o755, parents=True)
    if journeys == ["ledger"]:
        return live_ledger(args, binary, out)
    if journeys == ["ledger-component"]:
        return live_ledger_component(args, binary, out)
    return live_named_trace(args, binary, out)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, ValueError, KeyError) as error:
        print(f"u6 installed journey failed: {error}", file=sys.stderr)
        sys.exit(1)
