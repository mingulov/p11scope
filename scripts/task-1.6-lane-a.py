#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 1.6 Lane A: broad vs publication-selected attach-cost isolation.

Drives the owned multi-wrapper fixture through a pre-capture-publish /
mid-capture-activation protocol under two admission modes — broad
(P11SCOPE_BROAD_ADMIT=1: every validated fixed-family target attached
up front) vs selected (default publication-driven admission) — and
records exact expected-vs-observed invocation counts, first-call
coverage, phase timings, observer/target CPU, map memory, map-read
cost, and every loss counter.

Method mirrors scripts/system-scope-measure.sh (attach gate = discovery
marker AND attach-complete line, both on stderr; /proc
sampling via system-scope-sample.py; stderr dating via
system-scope-ts.py) but the workload is fixture stage children with a
gated call plan, and the analysis (oracle diff, bpftool memory,
map-dump timing) is lane-specific. Read-only against the harness: phase
splitting, observer stats, the COUNTERS universe, and per-function
aggregation are imported from system-scope-measure.py, never copied.

Single topology: one stage child keeps wrappers {0(fwd ords 5,43),
4, 5(fail ord 43), 7, 13, 17} — dormant-mid-capture activation, sparse
indices, 5+ wrappers, direct forwarding, wrapper-only failure, nested
wrapper->backend — all published BEFORE capture, then each kept wrapper
x each exercised ordinal is called N times after attach.

Pair topology: two stage children in one cgroup keep {0,1} and {5,6}
(two processes, one inode, sparse indices across processes).

Usage:
  scripts/task-1.6-lane-a.py --lane broad|selected --mode metrics|profile
      --topology single|pair --work DIR --binary PATH [--duration S]
      [--n-per-ordinal N] [--self-test]

Stdlib only. Live runs need sudo (observer + sampler + bpftool);
--self-test needs nothing and pins the pure analysis.
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_measure():
    spec = importlib.util.spec_from_file_location(
        "system_scope_measure", SCRIPT_DIR / "system-scope-measure.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MEASURE = _load_measure()

RECORD_SCHEMA = "p11scope/task-1.6-lane-a/v1"

EX_ORDS = [0, 5, 13, 18, 43, 44]
# Fixture ordinal -> PKCS#11 catalog label the observer prints for a
# linked (name-authorized) slot. Ordinals 5/13 are the known fixture
# misnomers (1.4 baseline): the fixture calls them C_GetSlotList /
# C_OpenSession, the catalog calls them C_GetSlotInfo / C_CloseSession.
CATALOG = {
    0: "C_Initialize",
    5: "C_GetSlotInfo",
    13: "C_CloseSession",
    18: "C_Login",
    43: "C_Sign",
    44: "C_SignUpdate",
}
FIXTURE_FUNC_TO_ORD = {
    "C_Initialize": 0,
    "C_GetSlotList": 5,
    "C_OpenSession": 13,
    "C_Login": 18,
    "C_Sign": 43,
    "C_SignUpdate": 44,
}


# --------------------------------------------------------------------------
# Pure analysis (pinned by --self-test).
# --------------------------------------------------------------------------

def parse_mw_log(path):
    """Parse mw_log lines into (layer, func, idx, via, rv) records."""
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            pid, tid, layer, func, idx, via, rv = line.split(" ")
            records.append((layer, func, int(idx), via, int(rv)))
    return records


def expected_observed(wrapper_records, named_idx, fwd, fail):
    """Map wrapper-layer truth to the observer's scan-onlyObserved shape.

    `named_idx`: the one wrapper index whose closures carry linked
    (name-authorized) labels — template[0]'s. Every other admitted
    wrapper aggregates under "unknown". `fwd`: {idx: {ords}} forwarded
    straight to backend.so (never observed — backend.so is unprobed);
    `fail`: {idx: ord} failing wrapper-only (observed with rv=48).

    Returns (expected_named, expected_unknown_total, expected_rv48).
    Forwarded ordinals emit no wrapper record at all, so they never
    appear here — the explicit pre-capture-forwarding gap, quantified
    separately from the backend-direct records.
    """
    expected_named = {}
    expected_unknown_total = 0
    expected_rv48 = 0
    for layer, func, idx, via, rv in wrapper_records:
        assert layer == "wrapper", f"wrapper layer only, got {layer}"
        assert via == "direct", f"wrapper records are direct, got {via}"
        ordinal = FIXTURE_FUNC_TO_ORD[func]
        assert ordinal not in fwd.get(idx, set()), \
            f"forwarded ordinal {ordinal} at idx={idx} must emit no wrapper record"
        if idx == named_idx:
            label = CATALOG[ordinal]
            expected_named[label] = expected_named.get(label, 0) + 1
        else:
            expected_unknown_total += 1
        if rv == 0x30:
            assert fail.get(idx) == ordinal, \
                f"unexpected rv=48 at idx={idx} func={func}"
            expected_rv48 += 1
        else:
            assert rv == 0, f"unexpected rv={rv}"
    return expected_named, expected_unknown_total, expected_rv48


def admitted_indices(lane, kept_all):
    """Wrapper indices the lane admits, from the admission contract.

    Broad attaches every validated fixed-family target, so every kept
    wrapper's closures are probed. Selected admits the K=4 window
    (templates 0-3), so only kept wrappers aliasing those templates
    observe anything — the measured coverage gap.
    """
    if lane == "broad":
        return set(kept_all)
    return set(kept_all) & {0, 1, 2, 3}


def compare_counts(observed, expected_named, expected_unknown_total, lane):
    """Compare aggregate_functions() output against the oracle mapping.

    Returns (match, note, detail). `observed` maps name -> calls.
    """
    observed = dict(observed)
    problems = []
    for label, want in sorted(expected_named.items()):
        got = observed.pop(label, 0)
        if got != want:
            problems.append(f"{label}: observed {got}, want {want}")
    unknown_got = observed.pop("unknown", 0)
    if unknown_got != expected_unknown_total:
        problems.append(
            f"unknown: observed {unknown_got}, want {expected_unknown_total}")
    for label, got in sorted(observed.items()):
        if got:
            problems.append(f"unexpected observed calls: {label}={got}")
    if problems:
        return False, f"{lane}: mismatch ({'; '.join(problems)})", problems
    return True, (f"{lane}: exact (named {len(expected_named)} ordinals + "
                   f"unknown total {expected_unknown_total})"), []


# --------------------------------------------------------------------------
# Fixture build + stage driver.
# --------------------------------------------------------------------------

GCC_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


def build_fixture(fixture_dir, out_dir):
    """Build backend.so + provider.so + workload (README's exact commands)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    backend = out_dir / "backend.so"
    provider = out_dir / "provider.so"
    workload = out_dir / "workload"
    run(["gcc", *GCC_FLAGS, "-fPIC", "-shared", "-Wl,-z,defs",
         "-o", str(backend), str(fixture_dir / "backend.c")])
    run(["gcc", *GCC_FLAGS, "-fPIC", "-shared", "-Wl,-z,defs",
         "-o", str(provider), str(fixture_dir / "provider.c"), str(backend)])
    run(["gcc", *GCC_FLAGS, "-o", str(workload),
         str(fixture_dir / "workload.c"), "-ldl"])
    return backend, provider, workload


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True,
                          capture_output=True, **kwargs)


class Stage:
    """One `workload stage` child driven over pipes."""

    def __init__(self, workload, provider, log_path, tag):
        self.tag = tag
        self.log_path = log_path
        self.proc = subprocess.Popen(
            [str(workload), str(provider), "stage", "0",
             str(log_path), str(log_path) + ".unused-oracle.json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        hello = self.proc.stdout.readline()
        assert hello.startswith("STAGE pid="), f"{tag}: {hello!r}"
        self.pid = self.proc.pid
        assert hello.strip() == f"STAGE pid={self.pid}", f"{tag}: {hello!r}"

    def command(self, line, terminator=None):
        """Send one REPL line; return reply lines up to terminator."""
        if self.proc.poll() is not None:
            raise SystemExit(f"{self.tag}: stage exited mid-protocol")
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        if terminator is None:
            reply = self.proc.stdout.readline()
            assert reply, f"{self.tag}: stage exited mid-protocol"
            assert not reply.startswith("ERROR"), \
                f"{self.tag}: stage reported {reply!r} for {line!r}"
            return reply.strip()
        lines = []
        while True:
            reply = self.proc.stdout.readline()
            assert reply, f"{self.tag}: stage exited mid-protocol"
            assert not reply.startswith("ERROR"), \
                f"{self.tag}: stage reported {reply!r} for {line!r}"
            lines.append(reply.strip())
            if reply.startswith(terminator):
                return lines

    def alloc(self, fwd, fail):
        reply = self.command(f"A {fwd} {fail}")
        assert reply.startswith("ALLOC "), reply
        return int(reply.split("idx=")[1].split()[0])

    def free(self, idx):
        self.command(f"F {idx}")

    def call(self, idx, ordinal, n):
        reply = self.command(f"C {idx} {ordinal} {n}")
        assert reply.startswith("CALLED "), reply
        fields = dict(part.split("=", 1) for part in reply.split()[1:])
        assert int(fields["idx"]) == idx and int(fields["ord"]) == ordinal \
            and int(fields["n"]) == n, reply
        return int(fields["rv"])

    def publish(self):
        return self.command("P", "PUBLISH end")

    def close(self):
        try:
            if self.proc.poll() is None:
                self.command("X")
                self.proc.wait(timeout=10)
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()


# --------------------------------------------------------------------------
# Target sampler (inline; sample.py only follows a sudo parent's child).
# --------------------------------------------------------------------------

class TargetSampler(threading.Thread):
    """Sample target CPU/RSS at 5 Hz into a JSONL file."""

    def __init__(self, pids, out_path, interval=0.2):
        super().__init__(daemon=True)
        self.pids = list(pids)
        self.out_path = out_path
        self.interval = interval
        self.clk_tck = os.sysconf("SC_CLK_TCK")
        self.page_bytes = os.sysconf("SC_PAGE_SIZE")
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _sample_one(self, pid):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
                stat = handle.read()
            with open(f"/proc/{pid}/statm", encoding="utf-8") as handle:
                statm = handle.read().split()
        except OSError:
            return None
        tail = stat.rsplit(")", 1)[1].split()
        try:
            return {
                "pid": pid,
                "utime_ticks": int(tail[11]),
                "stime_ticks": int(tail[12]),
                "rss_bytes": int(statm[1]) * self.page_bytes,
            }
        except (IndexError, ValueError):
            return None

    def run(self):
        with open(self.out_path, "w", encoding="utf-8", buffering=1) as out:
            while not self._stop.is_set():
                rows = []
                for pid in self.pids:
                    row = self._sample_one(pid)
                    if row is not None:
                        row["t_mono_ns"] = time.monotonic_ns()
                        row["clk_tck"] = self.clk_tck
                        rows.append(row)
                for row in rows:
                    out.write(json.dumps(row) + "\n")
                time.sleep(self.interval)


def summarize_targets(path):
    """Per-PID CPU deltas + RSS max from a target sample file."""
    per_pid = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            per_pid.setdefault(row["pid"], []).append(row)
    summary = {}
    for pid, rows in per_pid.items():
        first, last = rows[0], rows[-1]
        clk = int(first.get("clk_tck", 100)) or 100
        summary[str(pid)] = {
            "samples": len(rows),
            "cpu_user_s": round(
                (last["utime_ticks"] - first["utime_ticks"]) / clk, 3),
            "cpu_sys_s": round(
                (last["stime_ticks"] - first["stime_ticks"]) / clk, 3),
            "rss_max_bytes": max(row["rss_bytes"] for row in rows),
        }
    return summary


# --------------------------------------------------------------------------
# bpftool map memory + map-read cost.
# --------------------------------------------------------------------------

def bpftool_maps():
    """Snapshot id -> map facts via `sudo -n bpftool map show -j`."""
    proc = subprocess.run(
        ["sudo", "-n", "bpftool", "map", "show", "-j"],
        check=True, text=True, capture_output=True)
    found = {}
    for entry in json.loads(proc.stdout or "[]"):
        found[int(entry["id"])] = {
            "name": entry.get("name"),
            "type": entry.get("type"),
            "key_size": entry.get("bytes_key", entry.get("key_size")),
            "value_size": entry.get(
                "bytes_value", entry.get("value_size")),
            "max_entries": entry.get("max_entries"),
            "memlock": entry.get(
                "bytes_memlock", entry.get("memlock")),
        }
    return found


def diff_maps(before, after):
    """Maps present after but not before (the observer's), by id."""
    return {map_id: facts for map_id, facts in after.items()
            if map_id not in before}


def bpftool_dump_timed(map_id, reps=3):
    """Wall time of full `bpftool map dump` reps (map-read cost proxy)."""
    times = []
    for _ in range(reps):
        start = time.monotonic_ns()
        subprocess.run(
            ["sudo", "-n", "bpftool", "map", "dump", "id", str(map_id)],
            check=True, capture_output=True)
        times.append((time.monotonic_ns() - start) / 1e9)
    return [round(value, 3) for value in times]


# --------------------------------------------------------------------------
# Observer run + attach gate.
# --------------------------------------------------------------------------

# Attach-complete signal: the observer prints one stderr line once the
# attach session completes (src/run.rs format_attach_complete, 0801e79c),
# strictly before the capture loop — 'p11scope: attached N probe' for one
# probe, 'p11scope: attached N probes' otherwise. Both spellings match.
_ATTACH_COMPLETE_RE = re.compile(r"p11scope: attached [0-9]+ probes?")


def has_attach_complete_line(stderr_text):
    """True when the stderr transcript holds the attach-complete line."""
    return _ATTACH_COMPLETE_RE.search(stderr_text) is not None


def wait_attach(cell_dir, observer_proc, timeout_s=600):
    """Gate: discovery marker AND attach-complete line, both on stderr.

    Same contract as system-scope-measure.sh's wait_attach: the
    attach-complete line is the in-observer attach-end signal. The old
    stdout first-live-frame signal died with M-10 (7eb86f0d made live
    frames terminal-only) while the harness captures observer stdout to
    a file, so a frame gate could never fire. An fd plateau is
    deliberately NOT the gate (fires early under load). Returns the gate
    monotonic timestamp. Raises on observer death or timeout.
    """
    stderr_path = cell_dir / "stderr.txt"
    deadline = time.monotonic() + timeout_s
    while True:
        if observer_proc.poll() is not None:
            raise SystemExit(
                f"observer died during attach "
                f"(rc={observer_proc.returncode}); see {stderr_path}")
        if time.monotonic() >= deadline:
            raise SystemExit(f"attach never settled; see {stderr_path}")
        try:
            stderr_text = stderr_path.read_text(encoding="utf-8",
                                                errors="replace")
        except OSError:
            stderr_text = ""
        if "p11scope: discovery:" in stderr_text \
                and has_attach_complete_line(stderr_text):
            return time.monotonic_ns()
        time.sleep(0.2)


def wait_gone(proc, timeout_s):
    try:
        proc.wait(timeout=timeout_s)
        return True
    except subprocess.TimeoutExpired:
        return False


def signal_proc_tree(proc, sig):
    """Signal the sudo parent and its oldest live child (the observer)."""
    try:
        proc.send_signal(sig)
    except (OSError, ProcessLookupError):
        pass
    try:
        kids = subprocess.run(
            ["pgrep", "-P", str(proc.pid)], check=False, text=True,
            capture_output=True).stdout.split()
        for kid in kids:
            try:
                os.kill(int(kid), sig)
            except (OSError, ValueError):
                pass
    except OSError:
        pass


class Cgroup:
    """A dedicated cgroup v2 leaf for the pair topology (sudo)."""

    def __init__(self, name):
        self.path = Path("/sys/fs/cgroup") / name

    def create(self):
        run(["sudo", "-n", "mkdir", "-p", str(self.path)])

    def add(self, pid):
        run(["sudo", "-n", "sh", "-c",
             f"echo {pid} > {self.path}/cgroup.procs"])

    def remove(self):
        run(["sudo", "-n", "rmdir", str(self.path)])


# --------------------------------------------------------------------------
# Call plans.
# --------------------------------------------------------------------------

def plan_single(stage, n_per_ordinal):
    """Pre-capture alloc/free/publish; returns (kept, fwd, fail).

    Keeps {0(fwd ords 5,43), 4, 5(fail ord 43), 7, 13, 17}: dormant
    activation, sparse indices, 5+ wrappers, direct forwarding,
    wrapper-only failure; every kept wrapper nests to backend.so.
    """
    fwd_mask = (1 << 1) | (1 << 4)  # EX positions of ordinals 5 and 43
    assert stage.alloc(fwd_mask, -1) == 0
    for want in (1, 2, 3, 4):
        assert stage.alloc(0, -1) == want
    assert stage.alloc(0, 43) == 5
    for want in range(6, 18):
        assert stage.alloc(0, -1) == want
    for idx in (1, 2, 3, 6, 8, 9, 10, 11, 12, 14, 15, 16):
        stage.free(idx)
    kept = [0, 4, 5, 7, 13, 17]
    stage.publish()
    return kept, {0: {5, 43}}, {5: 43}


def plan_pair(stage_a, stage_b):
    """Two processes, one inode: A keeps {0,1}, B keeps {5,6}."""
    for want in (0, 1):
        assert stage_a.alloc(0, -1) == want
    for want in range(7):
        assert stage_b.alloc(0, -1) == want
    for idx in range(5):
        stage_b.free(idx)
    stage_a.publish()
    stage_b.publish()
    return [(stage_a, [0, 1]), (stage_b, [5, 6])]


def drive_calls(stages_kept, n_per_ordinal, fwd, fail):
    """Issue the mid-capture call plan; assert every CALLED reply."""
    calls = 0
    for stage, kept in stages_kept:
        for idx in kept:
            for ordinal in EX_ORDS:
                rv = stage.call(idx, ordinal, n_per_ordinal)
                want = 0x30 if fail.get(idx) == ordinal else 0
                assert rv == want, \
                    f"{stage.tag}: idx={idx} ord={ordinal}: rv={rv:#x}"
                calls += n_per_ordinal
    return calls


# --------------------------------------------------------------------------
# Record + summary.
# --------------------------------------------------------------------------

def build_record(meta, report, samples, stderr_rows, truth, observed,
                 counts_match, match_note, detail, targets, maps_before,
                 maps_new, dump_times):
    counter_names, counters_source = MEASURE.load_counters()
    evidence = report.get("evidence", {})
    capture = report.get("capture", {})
    counters = {}
    missing_counters = []
    for name in counter_names:
        if name in evidence:
            counters[name] = int(evidence[name])
        else:
            counters[name] = None
            missing_counters.append(name)
    refused = []
    for row in stderr_rows:
        line = row.get("line", "")
        if "module refused:" in line:
            rest = line.split("module refused:", 1)[1].strip()
            path, _, reason = rest.partition(" — ")
            refused.append({"path": path, "reason": reason or "unknown"})
    broad_lines = [row.get("line", "") for row in stderr_rows
                   if "broad fixed-family:" in row.get("line", "")]
    surfaces = evidence.get("surfaces", [])
    phases, discovery_line = MEASURE.derive_phases(
        samples, stderr_rows,
        float(meta["condition"]["duration_s"]),
        int(meta["timing"]["t_spawn_mono_ns"]),
        int(meta["timing"]["t_exit_mono_ns"]),
        int(meta["timing"]["t_go_mono_ns"]),
    )
    if missing_counters:
        phases["method_warnings"].append(
            f"report lacks counters (schema drift?): {missing_counters}")
    memlock_total = sum(facts.get("memlock") or 0 for facts in maps_new.values())
    return {
        "schema": RECORD_SCHEMA,
        "harness": meta["harness"],
        "condition": meta["condition"],
        "host": meta["host"],
        "verdict": evidence.get("completeness", "unknown"),
        "report_schema": report.get("schema", "unknown"),
        "capture_block": {
            "start": capture.get("start"),
            "end": capture.get("end"),
            "mode": capture.get("mode"),
            "scope": capture.get("scope"),
        },
        "phases": phases,
        "discovery_line": discovery_line,
        "evidence": {
            "scan_ms": evidence.get("scan_ms"),
            "counters_source": counters_source,
            "counters": counters,
            "attach_failures": evidence.get("attach_failures", []),
            "attached_probes": int(evidence.get("attached_probes", 0)),
            "slots_allocated": int(evidence.get("slots", 0)),
            "table_entries": evidence.get("table_entries"),
            "admitted_modules": [
                {"path": module.get("path"),
                 "sources": module.get("sources", []),
                 "corroboration": module.get("corroboration", []),
                 "tables": len(module.get("tables", []))}
                for module in evidence.get("discovery", [])
            ],
            "refused_modules": refused,
            "modules_skipped": evidence.get("modules_skipped", []),
            "tables_admitted": sum(
                1 for s in surfaces if s.get("walk") == "full"),
            "spill_uncorroborated_candidates": evidence.get(
                "discovery_uncorroborated_candidates"),
            "in_flight_at_end": evidence.get("in_flight_at_end"),
            "attach_mechanisms": evidence.get("attach_mechanisms"),
            "broad_lines": broad_lines,
        },
        "truth_vs_observed": {
            "truth_wrapper_records": truth["wrapper_total"],
            "truth_wrapper_admitted": truth["wrapper_admitted"],
            "truth_wrapper_gap": truth["wrapper_gap"],
            "truth_gap_indices": truth["gap_indices"],
            "truth_backend_nested": truth["backend_nested"],
            "truth_backend_direct": truth["backend_direct"],
            "truth_rv48": truth["rv48"],
            "expected_named": truth["expected_named"],
            "expected_unknown_total": truth["expected_unknown_total"],
            "observed": observed,
            "counts_match": counts_match,
            "match_note": match_note,
            "mismatch_detail": detail,
        },
        "observer": MEASURE.observer_stats(
            sorted(samples, key=lambda row: int(row["t_mono_ns"]))),
        "targets": targets,
        "maps": {
            "before_ids": sorted(maps_before),
            "new_ids": sorted(maps_new),
            "new": {str(map_id): facts
                    for map_id, facts in maps_new.items()},
            "memlock_new_total": memlock_total,
            "stats_dump_s": dump_times,
            "stats_dump_note": "full `bpftool map dump` of the STATS-class "
                               "map during capture (map-read cost proxy)",
        },
        "artifacts": meta["artifacts"],
    }


def build_summary(record):
    cond = record["condition"]
    phases = record["phases"]
    ev = record["evidence"]
    obs = record["observer"]
    tvo = record["truth_vs_observed"]
    lines = [
        f"task-1.6 lane A: {cond['lane']} / {cond['topology']} / "
        f"{cond['mode']} / {cond['duration_s']}s",
        f"verdict: {record['verdict']}  counts_match={tvo['counts_match']}",
        f"  {tvo['match_note']}",
        "",
        "ledger:",
        f"  command: {' '.join(cond['observer_argv'])}",
        f"  git_rev: {record['harness']['git_rev']} "
        f"(clean={record['harness']['git_clean']} "
        f"tracked_clean={record['harness'].get('git_tracked_clean', '?')})",
        f"  binary: {cond['binary']}",
        f"  config: lane={cond['lane']} topology={cond['topology']} "
        f"mode={cond['mode']} duration={cond['duration_s']}s "
        f"n_per_ordinal={cond['n_per_ordinal']}",
        f"  host: {record['host']['kernel']} x{record['host']['ncpu']}",
        "",
        "phases (s):",
        f"  discovery={fmt_s(phases['discovery_s'])} "
        f"attach={fmt_s(phases['attach_s'])} "
        f"capture={fmt_s(phases['capture_measured_s'])} "
        f"(requested {phases['capture_requested_s']}s)",
        f"  drain={fmt_s(phases['drain_s'])} "
        f"detach={fmt_s(phases['detach_s'])} "
        f"publish={fmt_s(phases['publish_s'])} "
        f"wall={fmt_s(phases['wall_s'])}",
        f"  evidence.scan_ms={ev['scan_ms']}",
    ]
    for warning in phases["method_warnings"]:
        lines.append(f"  method warning: {warning}")
    lines += ["", "loss counters (nonzero only; full map in record.json):"]
    nonzero = {k: v for k, v in ev["counters"].items() if v}
    if nonzero:
        for key in sorted(nonzero):
            lines.append(f"  {key}={nonzero[key]}")
    else:
        lines.append("  all zero")
    lines += [
        f"  attach_failures={len(ev['attach_failures'])} "
        f"in_flight_at_end={ev['in_flight_at_end']}",
        "",
        "admission:",
        f"  modules admitted={len(ev['admitted_modules'])} "
        f"refused={len(ev['refused_modules'])}",
        f"  tables admitted={ev['tables_admitted']} "
        f"(entries seen={ev['table_entries']})",
        f"  spill (uncorroborated candidates)"
        f"={ev['spill_uncorroborated_candidates']}",
        f"  slots allocated={ev['slots_allocated']} "
        f"(attached_probes={ev['attached_probes']})",
        f"  attach_mechanisms={ev['attach_mechanisms']}",
    ]
    for module in ev["admitted_modules"]:
        lines.append(f"    admitted: {module['path']} "
                     f"sources={','.join(module['sources'])} "
                     f"corroboration={','.join(module['corroboration'])}")
    for module in ev["refused_modules"]:
        lines.append(f"    refused: {module['path']} — {module['reason']}")
    for text in ev["broad_lines"]:
        lines.append(f"    {text}")
    observed_nz = {k: v for k, v in tvo["observed"].items() if v}
    lines += [
        "",
        "truth vs observed (wrapper layer; backend.so is unprobed):",
        f"  wrapper records={tvo['truth_wrapper_records']} "
        f"(admitted={tvo['truth_wrapper_admitted']} "
        f"gap={tvo['truth_wrapper_gap']} gap_indices={tvo['truth_gap_indices']} "
        f"rv48={tvo['truth_rv48']})",
        f"  backend_nested(missed by design)"
        f"={tvo['truth_backend_nested']} backend_direct(missed by design)"
        f"={tvo['truth_backend_direct']}",
        f"  expected named: {json.dumps(tvo['expected_named'], sort_keys=True)}",
        f"  expected unknown total: {tvo['expected_unknown_total']}",
        f"  observed (nonzero): {json.dumps(observed_nz, sort_keys=True)}",
        "",
        "observer:",
        f"  cpu_user={obs.get('cpu_user_s', 'n/a')}s "
        f"cpu_sys={obs.get('cpu_sys_s', 'n/a')}s "
        f"cpu_pct_of_wall={obs.get('cpu_pct_of_wall', 'n/a')} "
        f"rss_max={obs.get('rss_max_bytes', 'n/a')}B "
        f"fds_max={obs.get('fds_max', 'n/a')} "
        f"threads_max={obs.get('threads_max', 'n/a')}",
        f"  samples={obs.get('samples', 0)}",
        "",
        "targets:",
    ]
    for pid, stats in sorted(record["targets"].items()):
        lines.append(
            f"  pid {pid}: cpu_user={stats['cpu_user_s']}s "
            f"cpu_sys={stats['cpu_sys_s']}s "
            f"rss_max={stats['rss_max_bytes']}B samples={stats['samples']}")
    lines += [
        "",
        "maps:",
        f"  new map ids during capture: {record['maps']['new_ids']}",
        f"  memlock new total: {record['maps']['memlock_new_total']}B",
        f"  stats dump times (s): {record['maps']['stats_dump_s']}",
        "",
        f"artifacts: {record['artifacts']['dir']}",
    ]
    return "\n".join(lines) + "\n"


def fmt_s(value):
    return "n/a" if value is None else f"{value:.2f}s"


# --------------------------------------------------------------------------
# Main.
# --------------------------------------------------------------------------

def git_facts(repo):
    rev = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    status = run(["git", "-C", str(repo), "status", "--porcelain"]).stdout
    tracked = run(["git", "-C", str(repo), "status", "--porcelain",
                   "--untracked-files=no"]).stdout
    return rev, not status.strip(), not tracked.strip()


def load1():
    with open("/proc/loadavg", encoding="utf-8") as handle:
        return float(handle.read().split()[0])


def preflight(args):
    repo = SCRIPT_DIR.parent
    binary = Path(args.binary)
    assert binary.is_file(), f"no binary at {binary}"
    assert shutil.which("gcc"), "gcc is required (fixture build)"
    assert shutil.which("bpftool"), "bpftool is required (map memory)"
    run(["sudo", "-n", "true"])
    if args.lane == "broad":
        probe = subprocess.run(
            ["sudo", "-n", "P11SCOPE_BROAD_ADMIT=1", "printenv",
             "P11SCOPE_BROAD_ADMIT"],
            check=False, text=True, capture_output=True)
        assert probe.returncode == 0 and probe.stdout.strip() == "1", \
            "sudo must pass P11SCOPE_BROAD_ADMIT through (SETENV)"
    ncpu = os.cpu_count() or 1
    current = load1()
    print(f"preflight: load1={current:.2f} ncpu={ncpu} "
          f"binary={binary} lane={args.lane}", flush=True)
    if current > 0.75 * ncpu:
        print(f"preflight: WARNING: box is loaded (load1 {current:.2f} > "
              f"0.75*ncpu); timings are indicative, counts must stay exact",
              flush=True)
    return repo


def run_cell(args):
    repo = preflight(args)
    work = Path(args.work)
    cell_name = f"{args.lane}-{args.topology}-{args.mode}"
    cell_dir = work / cell_name
    if cell_dir.exists():
        shutil.rmtree(cell_dir)
    cell_dir.mkdir(parents=True)
    os.chmod(cell_dir, 0o700)
    print(f"=== condition: {cell_name} ===", flush=True)

    git_rev, git_clean, git_tracked_clean = git_facts(repo)
    kernel = os.uname().release
    ncpu = os.cpu_count() or 1

    # Fixture + pre-capture publication (unobserved by design).
    fixture_dir = repo / "tests" / "fixtures" / "multi-wrapper"
    _, provider, workload = build_fixture(fixture_dir, cell_dir / "bin")
    stages = []
    cgroup = None
    try:
        if args.topology == "single":
            stage = Stage(workload, provider,
                          cell_dir / "stage.log", "stage")
            stages = [stage]
            kept, fwd, fail = plan_single(stage, args.n_per_ordinal)
            stages_kept = [(stage, kept)]
            scope_argv = ["--pid", str(stage.pid)]
        else:
            stage_a = Stage(workload, provider,
                            cell_dir / "stage-a.log", "stage-a")
            stage_b = Stage(workload, provider,
                            cell_dir / "stage-b.log", "stage-b")
            stages = [stage_a, stage_b]
            cgroup = Cgroup(f"p11scope-lane-a-{os.getpid()}")
            cgroup.create()
            cgroup.add(stage_a.pid)
            cgroup.add(stage_b.pid)
            stages_kept = plan_pair(stage_a, stage_b)
            fwd, fail = {}, {}
            scope_argv = ["--cgroup", str(cgroup.path)]
        target_pids = [stage.pid for stage in stages]

        maps_before = bpftool_maps()

        # Observer with timestamped stderr + /proc sampling.
        fifo = cell_dir / "stderr.fifo"
        try:
            os.unlink(fifo)
        except FileNotFoundError:
            pass
        os.mkfifo(fifo)
        # RDWR never blocks on open (a read-only open would deadlock the
        # main thread until the observer's stderr appears as a writer).
        fifo_fd = os.open(fifo, os.O_RDWR)
        ts_proc = subprocess.Popen(
            [sys.executable, "-I", str(SCRIPT_DIR / "system-scope-ts.py"),
             "--out", str(cell_dir / "stderr-ts.jsonl"),
             "--passthrough", str(cell_dir / "stderr.txt")],
            stdin=fifo_fd)
        env_prefix = []
        if args.lane == "broad":
            env_prefix = ["P11SCOPE_BROAD_ADMIT=1"]
        observer_argv = (["sudo", "-n", *env_prefix, str(args.binary),
                           "profile", *scope_argv, "--mode", args.mode,
                           "--duration", str(args.duration),
                           "-o", str(cell_dir / "report.json")])
        stdout_file = open(cell_dir / "observer.stdout", "w", encoding="utf-8")
        stderr_fifo = open(fifo, "w", encoding="utf-8")
        t_spawn = time.monotonic_ns()
        observer_proc = subprocess.Popen(
            observer_argv, stdout=stdout_file, stderr=stderr_fifo)
        sample_proc = subprocess.Popen(
            ["sudo", "-n", sys.executable, "-I",
             str(SCRIPT_DIR / "system-scope-sample.py"),
             "--ppid", str(observer_proc.pid),
             "--out", str(cell_dir / "samples.jsonl"),
             "--interval", "0.05"])
        sampler = TargetSampler(target_pids, cell_dir / "targets.jsonl")
        sampler.start()

        t_go = wait_attach(cell_dir, observer_proc)
        print(f"attached: gate reached; driving {args.topology} calls",
              flush=True)

        # Map memory + map-read cost, measured mid-capture.
        maps_after = bpftool_maps()
        maps_new = diff_maps(maps_before, maps_after)
        stats_ids = [map_id for map_id, facts in maps_new.items()
                     if facts.get("name") == "STATS"]
        if not stats_ids:
            stats_ids = [
                map_id for map_id, facts in maps_new.items()
                if facts.get("value_size") == 296
                and facts.get("max_entries") == 512]
        dump_times = bpftool_dump_timed(stats_ids[0]) if stats_ids else []
        if not stats_ids:
            print("WARNING: no STATS-class map found for dump timing",
                  flush=True)

        # Mid-capture activation of the dormant pre-published wrappers.
        # Stages stay alive until the observer exits: closing them early
        # ends a per-PID capture before --duration (observed once), which
        # would confound the detach comparison. The idle tail also proves
        # dormant attached targets emit no records.
        calls = drive_calls(stages_kept, args.n_per_ordinal, fwd, fail)
        print(f"calls driven: {calls}", flush=True)

        if not wait_gone(observer_proc, args.duration + 600):
            print("observer hung; interrupting", flush=True)
            signal_proc_tree(observer_proc, signal.SIGINT)
            if not wait_gone(observer_proc, 300):
                signal_proc_tree(observer_proc, signal.SIGKILL)
        obs_rc = observer_proc.wait()
        t_exit = time.monotonic_ns()
        for stage in stages:
            stage.close()
        stages = []
        sampler.stop()
        sampler.join(timeout=10)
        stdout_file.close()
        stderr_fifo.close()
        # Closing our RDWR handle lets ts.py see EOF now that the
        # observer's stderr is gone; it exits on its own.
        os.close(fifo_fd)
        try:
            ts_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            ts_proc.kill()
        try:
            sample_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            sample_proc.kill()
        try:
            os.unlink(fifo)
        except FileNotFoundError:
            pass
        report_path = cell_dir / "report.json"
        if not report_path.is_file():
            raise SystemExit(f"observer exit={obs_rc} wrote no report; see "
                             f"{cell_dir / 'stderr.txt'}")
        run(["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}",
             str(cell_dir)])

        # Analysis: oracle diff + record.
        records = []
        for stage_log in sorted(cell_dir.glob("stage*.log")):
            records.extend(parse_mw_log(stage_log))
        wrapper = [row for row in records if row[0] == "wrapper"]
        backend_nested = sum(1 for row in records
                             if row[0] == "backend" and row[3] == "nested")
        backend_direct = sum(1 for row in records
                             if row[0] == "backend" and row[3] == "direct")
        kept_all = [idx for _, kept in stages_kept for idx in kept]
        admitted = admitted_indices(args.lane, kept_all)
        observable = [row for row in wrapper if row[2] in admitted]
        gap = [row for row in wrapper if row[2] not in admitted]
        named_idx = 0
        expected_named, expected_unknown, expected_rv48 = expected_observed(
            observable, named_idx, fwd, fail)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        observed = MEASURE.aggregate_functions(report)
        counts_match, match_note, detail = compare_counts(
            observed, expected_named, expected_unknown, args.lane)
        targets = summarize_targets(cell_dir / "targets.jsonl")
        samples = MEASURE.load_jsonl(cell_dir / "samples.jsonl")
        stderr_rows = MEASURE.load_jsonl(cell_dir / "stderr-ts.jsonl")
        meta = {
            "harness": {
                "name": "task-1.6-lane-a.py",
                "git_rev": git_rev,
                "git_clean": git_clean,
                "git_tracked_clean": git_tracked_clean,
                "observer_exit": obs_rc,
            },
            "condition": {
                "lane": args.lane,
                "topology": args.topology,
                "mode": args.mode,
                "duration_s": args.duration,
                "n_per_ordinal": args.n_per_ordinal,
                "binary": str(args.binary),
                "observer_argv": observer_argv,
                "workload": "multi-wrapper stage (pre-capture publish, "
                            "mid-capture C calls)",
            },
            "host": {"kernel": kernel, "ncpu": ncpu},
            "timing": {"t_spawn_mono_ns": t_spawn,
                       "t_go_mono_ns": t_go,
                       "t_exit_mono_ns": t_exit},
            "artifacts": {
                "dir": str(cell_dir),
                "report": str(report_path),
                "samples": str(cell_dir / "samples.jsonl"),
                "stderr_ts": str(cell_dir / "stderr-ts.jsonl"),
                "stderr": str(cell_dir / "stderr.txt"),
            },
        }
        truth = {
            "wrapper_total": len(wrapper),
            "wrapper_admitted": len(observable),
            "wrapper_gap": len(gap),
            "gap_indices": sorted({row[2] for row in gap}),
            "backend_nested": backend_nested,
            "backend_direct": backend_direct,
            "rv48": sum(1 for row in observable if row[4] == 0x30),
            "expected_named": expected_named,
            "expected_unknown_total": expected_unknown,
        }
        assert truth["rv48"] == expected_rv48
        record = build_record(meta, report, samples, stderr_rows, truth,
                              observed, counts_match, match_note, detail,
                              targets, maps_before, maps_new, dump_times)
        (cell_dir / "record.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8")
        (cell_dir / "summary.txt").write_text(
            build_summary(record), encoding="utf-8")
        print(f"record: {cell_dir / 'record.json'}", flush=True)
        print(f"verdict={record['verdict']} "
              f"counts_match={counts_match} "
              f"wall={record['phases']['wall_s']:.1f}s", flush=True)
        if not counts_match:
            raise SystemExit(f"counts mismatch in {cell_name}:\n"
                             + "\n".join(detail))
    finally:
        for stage in stages:
            try:
                stage.close()
            except (OSError, SystemExit, AssertionError):
                pass
        if cgroup is not None:
            try:
                cgroup.remove()
            except subprocess.CalledProcessError:
                pass


# --------------------------------------------------------------------------
# Self-test.
# --------------------------------------------------------------------------

def self_test():
    # parse_mw_log: wrapper/nested/direct/rv48 shapes.
    sample = ("1 1 wrapper C_Sign 4 direct 0\n"
              "1 1 backend C_Sign 4 nested 0\n"
              "1 1 backend C_Sign 0 direct 0\n"
              "1 1 wrapper C_Sign 5 direct 48\n")
    tmp = Path("/tmp/task-1.6-lane-a-selftest.log")
    tmp.write_text(sample, encoding="utf-8")
    try:
        rows = parse_mw_log(tmp)
    finally:
        tmp.unlink()
    assert rows == [("wrapper", "C_Sign", 4, "direct", 0),
                    ("backend", "C_Sign", 4, "nested", 0),
                    ("backend", "C_Sign", 0, "direct", 0),
                    ("wrapper", "C_Sign", 5, "direct", 48)], rows

    # expected_observed: misnomer mapping, unknown aggregation, rv48,
    # forwarded-ordinal exclusion.
    wrapper = [("wrapper", "C_GetSlotList", 0, "direct", 0),
               ("wrapper", "C_GetSlotList", 0, "direct", 0),
               ("wrapper", "C_Sign", 4, "direct", 0),
               ("wrapper", "C_Sign", 5, "direct", 48)]
    named, unknown, rv48 = expected_observed(
        wrapper, 0, {}, {5: 43})
    assert named == {"C_GetSlotInfo": 2}, named
    assert unknown == 2, unknown
    assert rv48 == 1, rv48
    # A wrapper record on a forwarded (idx, ord) is a fixture violation.
    try:
        expected_observed(
            [("wrapper", "C_Sign", 0, "direct", 0)], 0, {0: {43}}, {})
    except AssertionError:
        pass
    else:
        raise SystemExit("forwarded wrapper record was not rejected")

    # admitted_indices: broad keeps everything, selected the K=4 window.
    assert admitted_indices("broad", [0, 4, 5, 7, 13, 17]) == \
        {0, 4, 5, 7, 13, 17}
    assert admitted_indices("selected", [0, 4, 5, 7, 13, 17]) == {0}
    assert admitted_indices("selected", [0, 1, 5, 6]) == {0, 1}

    # compare_counts: exact, short unknown, extras.
    match, _, _ = compare_counts(
        {"C_GetSlotInfo": 2, "unknown": 2}, {"C_GetSlotInfo": 2}, 2, "lane")
    assert match
    match, note, _ = compare_counts(
        {"C_GetSlotInfo": 2, "unknown": 1}, {"C_GetSlotInfo": 2}, 2, "lane")
    assert not match and "unknown" in note, note
    match, note, _ = compare_counts(
        {"C_GetSlotInfo": 3, "unknown": 2}, {"C_GetSlotInfo": 2}, 2, "lane")
    assert not match and "C_GetSlotInfo" in note, note
    match, note, _ = compare_counts(
        {"C_GetSlotInfo": 2, "unknown": 2, "C_Login": 1},
        {"C_GetSlotInfo": 2}, 2, "lane")
    assert not match and "unexpected" in note, note

    # diff_maps + map_signature (bpftool -j field names).
    before = {7: {"type": "x"}}
    after = {7: {"type": "x"},
             9: {"type": "percpu_array", "bytes_key": 4,
                 "bytes_value": 296, "max_entries": 512,
                 "bytes_memlock": 100, "name": "STATS"}}
    new = diff_maps(before, after)
    assert list(new) == [9], new
    assert new[9]["name"] == "STATS" and new[9]["bytes_memlock"] == 100

    # summarize_targets over synthetic rows.
    rows_path = Path("/tmp/task-1.6-lane-a-selftest-targets.jsonl")
    rows_path.write_text(
        '{"pid": 11, "utime_ticks": 100, "stime_ticks": 50, '
        '"rss_bytes": 1000, "t_mono_ns": 1, "clk_tck": 100}\n'
        '{"pid": 11, "utime_ticks": 150, "stime_ticks": 60, '
        '"rss_bytes": 2000, "t_mono_ns": 2, "clk_tck": 100}\n',
        encoding="utf-8")
    try:
        summary = summarize_targets(rows_path)
    finally:
        rows_path.unlink()
    assert summary == {"11": {"samples": 2, "cpu_user_s": 0.5,
                              "cpu_sys_s": 0.1, "rss_max_bytes": 2000}}, summary

    print("task-1.6-lane-a self-test: 6 groups green")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=("broad", "selected"))
    parser.add_argument("--mode", choices=("metrics", "profile"))
    parser.add_argument("--topology", choices=("single", "pair"))
    parser.add_argument("--work", required=False)
    parser.add_argument("--binary", required=False)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--n-per-ordinal", type=int, default=10)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    for required in ("lane", "mode", "topology", "work", "binary"):
        if getattr(args, required) is None:
            parser.error(f"--{required.replace('_', '-')} is required")
    run_cell(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
