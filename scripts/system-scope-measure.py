#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build one system-scope measurement record from a controlled capture.

Inputs: the observer's JSON report, the /proc sampler trace, the
timestamped stderr trace, the workload log (TRUTH line), and a JSON blob
of condition metadata from system-scope-measure.sh.

Outputs: a versioned JSON record plus a human-readable summary, both
containing the ledger-paste-ready command/revision/config/seed, phase
timings, every loss counter, verdict, admission truth, and observer
resource peaks. Read-only against the repo: the loss-counter universe is
imported from scripts/check-capture-evidence.py (COUNTERS) so it cannot
drift; an embedded fallback is used only if that import fails, and the
record says which source was used.

Stdlib only.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

RECORD_SCHEMA = "p11scope/system-scope-measurement/v1"

# Fallback only: used when check-capture-evidence.py cannot be imported,
# and flagged in the record as counters_source=embedded-fallback.
EMBEDDED_COUNTERS = (
    "event_loss",
    "start_insert_failures",
    "unmatched_returns",
    "rv_update_failures",
    "cgroup_scope_failures",
    "abi_refusals",
    "semantic_capture_failures",
    "unregistered_mechanisms",
    "template_tail_failures",
    "process_tracking_fallbacks",
    "process_tracking_failures",
    "process_tracking_evictions",
    "state_reconciliations",
    "session_cancel_ambiguities",
    "session_cancel_unknown_flags",
    "operation_state_imports",
    "auth_state_ambiguities",
    "async_target_failures",
    "async_orphans",
    "async_duplicates",
    "async_evictions",
    "fork_state_ambiguities",
    "semantic_state_drops",
    "semantic_history_drops",
    "pending_at_end",
    "malformed_records",
    "orphan_ops",
    "unmatched_closes",
    "shape_decode_failures",
    "shape_decode_total_failures",
    "discovery_conflicts",
    "discovery_uncorroborated",
    "module_ambiguous",
    "discovery_ring_loss",
    "discovery_state_failures",
    "discovery_read_failures",
    "discovery_truncated",
    "task_uprobe_link_losses",
)


def load_counters():
    """Import COUNTERS from the canonical evidence oracle (read-only)."""
    oracle = Path(__file__).resolve().parent / "check-capture-evidence.py"
    try:
        spec = importlib.util.spec_from_file_location(
            "check_capture_evidence", oracle
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = tuple(module.COUNTERS)
        if names and all(isinstance(name, str) for name in names):
            return names, "check-capture-evidence.py:COUNTERS"
    except Exception as error:  # noqa: BLE001 - fallback is the point
        print(f"measure: oracle import failed ({error}); embedded fallback",
              file=sys.stderr)
    return EMBEDDED_COUNTERS, "embedded-fallback"


def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def parse_truth(workload_log):
    truth = truth_prego = None
    with open(workload_log, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("TRUTH_PREGO "):
                truth_prego = json.loads(line[len("TRUTH_PREGO "):])
            elif line.startswith("TRUTH "):
                truth = json.loads(line[len("TRUTH "):])
    if truth is None:
        raise SystemExit(f"no TRUTH line in {workload_log}")
    if truth_prego is None:
        raise SystemExit(f"no TRUTH_PREGO line in {workload_log}")
    return truth, truth_prego


def aggregate_functions(report):
    observed = {}
    for entry in report.get("functions", []):
        names = entry.get("names") or []
        if not names:
            continue
        observed[names[0]] = observed.get(names[0], 0) + int(entry.get("calls", 0))
    return observed


def derive_phases(samples, stderr_rows, duration_s, t_spawn_ns, t_exit_ns,
                  t_go_ns=None):
    """Split wall time into phases from external traces.

    t_discovery: timestamped `p11scope: discovery:` stderr marker (the
      observer prints it when discovery completes, before attach).
    t_attached: first fd sample reaching 95% of the run max — the end of
      the per-slot link ramp, after which the capture loop starts.
    t_expiry: t_attached + requested duration (the observer honors
      --duration from loop start; capture.start/end are 1 s precision and
      serve only as a cross-check).
    t_detach_start: first post-expiry sample below 95% of max (sustained).
    t_detach_end: first sample after that back at baseline.
    drain = expiry -> detach start (final drain + detach setup);
    publish = detach end -> exit (report write + teardown).
    BPF program/map load has no external marker: it is folded into attach
    and reported as load_s=null with this reason.
    """
    method_warnings = []
    t_discovery = None
    discovery_line = None
    for row in stderr_rows:
        if "p11scope: discovery:" in row.get("line", ""):
            t_discovery = int(row["t_mono_ns"])
            discovery_line = row["line"]
            break
    if t_discovery is None:
        method_warnings.append("no discovery marker on stderr; discovery/attach split unknown")
    if t_go_ns is not None and (t_go_ns - t_spawn_ns) / 1e9 > duration_s:
        # The observer's --duration runs from capture-loop start and expires
        # at the first tick after the budget is spent. The attach gate
        # (first live frame) marks loop-live: if setup alone exceeds the
        # requested duration, expiry fires on an early post-go tick and the
        # workload window collapses from D seconds to tick granularity —
        # whether the burst fits is timing luck, not margin. counts_match
        # tells whether it fit; this flag tells not to trust the margin.
        method_warnings.append(
            f"COLLAPSED WINDOW: setup (spawn to capture-live) took "
            f"{(t_go_ns - t_spawn_ns) / 1e9:.1f}s, exceeding the requested "
            f"{duration_s}s capture; the loop expired during setup, so the "
            f"workload burst raced teardown at tick granularity")

    phases = {
        "discovery_s": None,
        "load_s": None,
        "load_note": "folded into attach_s: BPF load precedes the link ramp "
                     "without an external marker",
        "attach_s": None,
        "capture_requested_s": duration_s,
        "capture_measured_s": None,
        "drain_s": None,
        "detach_s": None,
        "publish_s": None,
        "wall_s": (t_exit_ns - t_spawn_ns) / 1e9,
        "method_warnings": method_warnings,
        "t_spawn_mono_ns": t_spawn_ns,
        "t_exit_mono_ns": t_exit_ns,
        "t_discovery_mono_ns": t_discovery,
        "t_attached_mono_ns": None,
        "t_detach_start_mono_ns": None,
        "t_detach_end_mono_ns": None,
    }
    if not samples:
        method_warnings.append("no sampler rows; only wall time is known")
        return phases, discovery_line
    samples = sorted(samples, key=lambda row: int(row["t_mono_ns"]))
    fds = [int(row["fds"]) for row in samples]
    times = [int(row["t_mono_ns"]) for row in samples]
    baseline = min(fds[:5]) if len(fds) >= 5 else min(fds)
    run_max = max(fds)
    phases["fd_baseline"] = baseline
    phases["fd_max"] = run_max
    if run_max <= baseline + 10:
        method_warnings.append(
            "no attach ramp visible in fd trace (<=10 fds above baseline); "
            "attach/detach phases unknown")
        return phases, discovery_line
    hi = 0.95 * run_max
    attach_idx = next(i for i, value in enumerate(fds) if value >= hi)
    t_attached = times[attach_idx]
    phases["t_attached_mono_ns"] = t_attached
    if t_discovery is not None:
        phases["discovery_s"] = max(0.0, (t_discovery - t_spawn_ns) / 1e9)
        phases["attach_s"] = max(0.0, (t_attached - t_discovery) / 1e9)
    t_expiry = t_attached + int(duration_s * 1e9)
    phases["capture_measured_s"] = duration_s
    # First post-expiry dip below the plateau, sustained over 3 samples.
    detach_start = None
    for i in range(len(samples)):
        if times[i] < t_expiry or fds[i] >= hi:
            continue
        if all(fds[j] < hi for j in range(i, min(i + 3, len(samples)))):
            detach_start = times[i]
            break
    if detach_start is None:
        # No dip found (short capture, coarse sampling): fall back to the
        # first below-plateau post-expiry sample, else the last sample.
        later = [t for t, value in zip(times, fds)
                 if t >= t_expiry and value < hi]
        detach_start = later[0] if later else times[-1]
        method_warnings.append("detach start fell back to first post-expiry dip")
    phases["t_detach_start_mono_ns"] = detach_start
    floor = baseline + max(10, int(0.05 * run_max))
    detach_end = next((t for t, value in zip(times, fds)
                       if t >= detach_start and value <= floor), times[-1])
    phases["t_detach_end_mono_ns"] = detach_end
    drain = (detach_start - t_expiry) / 1e9
    if drain < 0:
        method_warnings.append(
            f"detach began {abs(drain):.2f}s before estimated expiry; "
            "capture window estimate is off (attach-end marker or duration)")
        drain = 0.0
    phases["drain_s"] = drain
    phases["detach_s"] = max(0.0, (detach_end - detach_start) / 1e9)
    phases["publish_s"] = max(0.0, (t_exit_ns - detach_end) / 1e9)
    return phases, discovery_line


def observer_stats(samples):
    if not samples:
        return {"samples": 0}
    first, last = samples[0], samples[-1]
    clk = int(first.get("clk_tck", 100)) or 100
    user_s = (int(last["utime_ticks"]) - int(first["utime_ticks"])) / clk
    sys_s = (int(last["stime_ticks"]) - int(first["stime_ticks"])) / clk
    wall_s = (int(last["t_mono_ns"]) - int(first["t_mono_ns"])) / 1e9
    return {
        "samples": len(samples),
        "sample_wall_s": round(wall_s, 3),
        "cpu_user_s": round(user_s, 3),
        "cpu_sys_s": round(sys_s, 3),
        "cpu_total_s": round(user_s + sys_s, 3),
        "cpu_pct_of_wall": round(100.0 * (user_s + sys_s) / wall_s, 2) if wall_s > 0 else None,
        "rss_max_bytes": max(int(row["rss_bytes"]) for row in samples),
        "rss_first_bytes": int(first["rss_bytes"]),
        "rss_last_bytes": int(last["rss_bytes"]),
        "fds_max": max(int(row["fds"]) for row in samples),
        "threads_max": max(int(row.get("threads", 0)) for row in samples),
    }


def fmt_seconds(value):
    return "n/a" if value is None else f"{value:.2f}s"


def build_summary(record):
    cond = record["condition"]
    phases = record["phases"]
    ev = record["evidence"]
    obs = record["observer"]
    tvo = record["truth_vs_observed"]
    lines = [
        f"system-scope measurement: {cond['scope']} / {cond['mode']} / {cond['duration_s']}s",
        f"verdict: {record['verdict']}",
        "",
        "ledger:",
        f"  command: {' '.join(cond['observer_argv'])}",
        f"  git_rev: {record['harness']['git_rev']} "
        f"(clean={record['harness']['git_clean']} "
        f"tracked_clean={record['harness'].get('git_tracked_clean', '?')})",
        f"  binary: {cond['binary']} ({cond['build_profile']})",
        f"  config: mode={cond['mode']} duration={cond['duration_s']}s "
        f"ring_bytes={cond['ring_bytes']} drain_interval_ms={cond['drain_interval_ms']} "
        f"manifest={cond['manifest'] or 'none'}",
        f"  workload: {cond['workload_argv']} seed={cond['seed']} n_calls={cond['n_calls']} "
        f"pace_us={cond['pace_us']} map_early={cond.get('map_early', '?')}",
        f"  host: {record['host']['kernel']} {record['host']['cpu']} "
        f"x{record['host']['ncpu']}",
        "",
        "phases (s):",
        f"  discovery={fmt_seconds(phases['discovery_s'])} "
        f"load={fmt_seconds(phases['load_s'])} "
        f"attach={fmt_seconds(phases['attach_s'])} "
        f"capture={fmt_seconds(phases['capture_measured_s'])} "
        f"(requested {phases['capture_requested_s']}s)",
        f"  drain={fmt_seconds(phases['drain_s'])} "
        f"detach={fmt_seconds(phases['detach_s'])} "
        f"publish={fmt_seconds(phases['publish_s'])} "
        f"wall={fmt_seconds(phases['wall_s'])}",
        f"  evidence.scan_ms={ev['scan_ms']}",
    ]
    for warning in phases["method_warnings"]:
        lines.append(f"  method warning: {warning}")
    lines += [
        "",
        "loss counters (nonzero only; full map in record.json):",
    ]
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
        f"refused={len(ev['refused_modules'])} "
        f"skipped_views={len(ev['modules_skipped'])}",
        f"  tables admitted={ev['tables_admitted']} "
        f"refused={ev['tables_refused']} "
        f"(entries seen={ev['table_entries']})",
        f"  K=4 spill (uncorroborated candidates)"
        f"={ev['spill_uncorroborated_candidates']}",
        f"  slots allocated={ev['slots_allocated']} "
        f"active_derived={ev['slots_active_derived']} "
        f"(attached_probes={ev['attached_probes']})",
        f"  attach_mechanisms={ev['attach_mechanisms']}",
    ]
    for module in ev["admitted_modules"]:
        lines.append(f"    admitted: {module['path']} "
                     f"sources={','.join(module['sources'])} "
                     f"corroboration={','.join(module['corroboration'])}")
    for module in ev["refused_modules"]:
        lines.append(f"    refused: {module['path']} — {module['reason']}")
    observed_nz = {k: v for k, v in tvo["observed"].items() if v}
    n_zero = len(tvo["observed"]) - len(observed_nz)
    lines += [
        "",
        "truth vs observed:",
        f"  truth: {json.dumps(tvo['truth'], sort_keys=True)}",
        f"  truth_prego (outside window): "
        f"{json.dumps(tvo['truth_prego'], sort_keys=True)}",
        f"  observed (nonzero; +{n_zero} zero-call functions in record.json): "
        f"{json.dumps(observed_nz, sort_keys=True)}",
        f"  counts_match={tvo['counts_match']} ({tvo['match_note']})",
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
        f"artifacts: {record['artifacts']}",
    ]
    return "\n".join(lines) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--samples", required=True)
    parser.add_argument("--stderr-ts", required=True)
    parser.add_argument("--workload-log", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args(argv)

    counter_names, counters_source = load_counters()
    meta = json.loads(Path(args.meta).read_text(encoding="utf-8"))
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    samples = load_jsonl(args.samples)
    stderr_rows = load_jsonl(args.stderr_ts)
    truth, truth_prego = parse_truth(args.workload_log)
    observed = aggregate_functions(report)

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
            # p11scope: module refused: <path> — <reason>
            rest = line.split("module refused:", 1)[1].strip()
            path, _, reason = rest.partition(" — ")
            refused.append({"path": path, "reason": reason or "unknown"})
    surfaces = evidence.get("surfaces", [])
    tables_admitted = sum(1 for s in surfaces if s.get("walk") == "full")
    tables_refused = sum(1 for s in surfaces if s.get("walk") == "refused")
    attached_probes = int(evidence.get("attached_probes", 0))
    slots_allocated = int(evidence.get("slots", 0))

    scope = meta["condition"]["scope"]
    if scope == "pid":
        counts_match = all(observed.get(k, 0) == v for k, v in truth.items())
        extras = {k: v for k, v in observed.items()
                  if k not in truth and v}
        match_note = ("exact per-PID equality of workload truth vs observed "
                      "calls" + ("" if not extras else
                                 f"; unexpected observed calls: {extras}"))
        if extras:
            counts_match = False
    else:
        if set(observed) <= {"unknown"}:
            # System runs are scan-only: since the 1.3 mislabel guard,
            # unlinked heuristic tables carry no ordinal labels, so
            # per-function matching is impossible and coverage is compared
            # on totals (foreign processes may still add calls).
            truth_total = sum(truth.values())
            observed_total = sum(observed.values())
            counts_match = observed_total >= truth_total
            match_note = (
                "system scan-only: names unavailable (unknown); "
                f"total coverage {observed_total} >= {truth_total}"
            )
        else:
            counts_match = all(observed.get(k, 0) >= v for k, v in truth.items())
            match_note = ("system scope: observed must cover workload truth "
                          "(other processes may add calls)")

    phases, discovery_line = derive_phases(
        samples, stderr_rows,
        float(meta["condition"]["duration_s"]),
        int(meta["timing"]["t_spawn_mono_ns"]),
        int(meta["timing"]["t_exit_mono_ns"]),
        int(meta["timing"]["t_go_mono_ns"]),
    )
    if missing_counters:
        phases["method_warnings"].append(
            f"report lacks counters (schema drift?): {missing_counters}")

    record = {
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
            "ring_bytes": capture.get("ring_bytes"),
            "drain_interval_ms": capture.get("drain_interval_ms"),
        },
        "phases": phases,
        "discovery_line": discovery_line,
        "evidence": {
            "scan_ms": evidence.get("scan_ms"),
            "counters_source": counters_source,
            "counters": counters,
            "attach_failures": evidence.get("attach_failures", []),
            "attached_probes": attached_probes,
            "slots_allocated": slots_allocated,
            "slots_active_derived": attached_probes // 2,
            "slots_active_note": "derived: 2 probes (entry+return) per "
                                 "fully-attached slot",
            "table_entries": evidence.get("table_entries"),
            "admitted_modules": [
                {
                    "path": module.get("path"),
                    "sources": module.get("sources", []),
                    "corroboration": module.get("corroboration", []),
                    "tables": len(module.get("tables", [])),
                    "interfaces": module.get("interfaces"),
                }
                for module in evidence.get("discovery", [])
            ],
            "refused_modules": refused,
            "modules_skipped": evidence.get("modules_skipped", []),
            "tables_admitted": tables_admitted,
            "tables_refused": tables_refused,
            "spill_uncorroborated_candidates": evidence.get(
                "discovery_uncorroborated_candidates"
            ),
            "spill_note": "K=4 per-object heuristic spill: decoded but "
            "unadmitted tables. Informational in check-capture-evidence.py "
            "(not a COUNTER), recorded here because capacity analysis "
            "needs it.",
            "surfaces_total": len(surfaces),
            "in_flight_at_end": evidence.get("in_flight_at_end"),
            "attach_mechanisms": evidence.get("attach_mechanisms"),
        },
        "truth_vs_observed": {
            "truth": truth,
            "truth_prego": truth_prego,
            "truth_note": "TRUTH covers post-go calls (the capture window); "
                          "TRUTH_PREGO covers calls made before READY, outside "
                          "the window by construction",
            "observed": observed,
            "counts_match": counts_match,
            "match_note": match_note,
        },
        "observer": observer_stats(
            sorted(samples, key=lambda row: int(row["t_mono_ns"]))),
        "artifacts": meta["artifacts"],
        "limitations": [
            "Phase boundaries are externally derived (fd trace + one stderr "
            "marker), not in-observer timestamps; drain/detach/publish splits "
            "are approximate.",
            "BPF load is folded into attach_s (no external marker).",
            "Observer CPU/RSS are wall-window samples; noisy under concurrent "
            "build load (sibling workers) — see the design note.",
            "counts_match for pid scope requires exact per-name equality; "
            "for system scope (scan-only, unknown names) it requires "
            "observed total >= truth total.",
        ],
    }
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n",
                              encoding="utf-8")
    Path(args.summary).write_text(build_summary(record), encoding="utf-8")
    # Files first, terminal last: a closed stdout (e.g. a downstream `head`)
    # must not fail a completed measurement.
    try:
        print(f"record: {args.out}", flush=True)
        print(f"verdict={record['verdict']} "
              f"counts_match={counts_match} "
              f"wall={phases['wall_s']:.1f}s", flush=True)
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
