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
import re
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


def parse_burst(lines):
    """Extract (go_ns, end_ns) monotonic bounds of the measured call burst.

    The workload prints one `BURST go_ns=<...> end_ns=<...>` line between
    READY and TRUTH; the burst rate (calls/s into the ring) derives from
    it. Missing or reversed bounds fail closed like a missing TRUTH.
    """
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("BURST "):
            continue
        fields = dict(token.split("=", 1) for token in stripped.split()[1:]
                      if "=" in token)
        try:
            go_ns = int(fields["go_ns"])
            end_ns = int(fields["end_ns"])
        except (KeyError, ValueError):
            raise SystemExit(f"malformed BURST line: {stripped!r}")
        if end_ns < go_ns:
            raise SystemExit(f"reversed BURST line: {stripped!r}")
        return go_ns, end_ns
    raise SystemExit("no BURST line in workload log")


def burst_rate_per_s(n_calls, go_ns, end_ns):
    """Calls per second over the burst window, or None when unknowable."""
    if n_calls <= 0 or end_ns <= go_ns:
        return None
    return n_calls / ((end_ns - go_ns) / 1e9)


# One EVENTS ring-buffer record: 328-byte Event (pinned by
# ebpf-common's size test) + the 8-byte ringbuf header, 8-aligned.
RING_RECORD_BYTES = 336


def ring_capacity_records(ring_bytes):
    """Whole CALL records a ring holds, or None when the size is unknown."""
    if ring_bytes is None:
        return None
    return int(ring_bytes) // RING_RECORD_BYTES


def predicted_burst_loss(generated, capacity_records):
    """Loss when a burst completes inside one inter-drain gap.

    The ring must absorb the whole burst: everything past capacity is a
    kernel reserve failure (event_loss), drained or not.
    """
    if capacity_records is None:
        return None
    return max(0, int(generated) - capacity_records)


def resolve_ring_bytes(value):
    """Ring bytes from a condition value: default/None, int, or n[K|M]."""
    if value is None or value == "default":
        return 256 * 1024
    if isinstance(value, int):
        return value
    text = str(value).strip()
    multiplier = 1
    if text[-1:] in ("K", "M"):
        multiplier = 1024 if text[-1:] == "K" else 1024 * 1024
        text = text[:-1]
    try:
        return int(text) * multiplier
    except ValueError:
        raise ValueError(f"unparseable ring_bytes: {value!r}")


CALL_LINE_RE = re.compile(
    r"^\d{2}:\d{2}:\d{2}\.\d{6} pid \d+ tid \d+ (?:sess#\d+ )?(\S+)(.*) \u2192 (\S+) (.+)$")
LOST_LINE_RE = re.compile(r"^LOST (\d+) events$")
TRUNCATED_LINE_RE = re.compile(r"^TRUNCATED at \d+ events")


def parse_trace_stream(lines):
    """Parse a `p11scope trace` line stream into exact tallies.

    Line taxonomy (src/trace.rs + src/run.rs): one CAPTURE header first,
    timestamped completed-call lines, cumulative `LOST n events` reports
    (the kernel counter value, not a delta), at most one TRUNCATED line,
    then COUNT_EVIDENCE and EVIDENCE JSON records last. Anything else
    fails closed: an oracle that silently skips lines invents shares.
    """
    capture_seen = 0
    truncated = False
    lost_values = []
    per_function = {}
    call_lines_total = 0
    qualified_lines = 0
    mechanism_lines = 0
    count_evidence = None
    evidence = None
    content = [line.rstrip("\n") for line in lines]
    content = [line for line in content if line != ""]
    if not content or not content[0].startswith("CAPTURE "):
        raise ValueError("trace stream must open with the CAPTURE header")
    if not content[-1].startswith("EVIDENCE "):
        raise ValueError("trace stream must close with the EVIDENCE record")
    for line in content:
        if line.startswith("CAPTURE "):
            capture_seen += 1
            continue
        if line.startswith("COUNT_EVIDENCE "):
            if count_evidence is not None:
                raise ValueError("duplicate COUNT_EVIDENCE record")
            try:
                count_evidence = json.loads(line[len("COUNT_EVIDENCE "):])
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed COUNT_EVIDENCE: {error}")
            continue
        if line.startswith("EVIDENCE "):
            if evidence is not None:
                raise ValueError("duplicate EVIDENCE record")
            try:
                evidence = json.loads(line[len("EVIDENCE "):])
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed EVIDENCE: {error}")
            continue
        lost = LOST_LINE_RE.match(line)
        if lost is not None:
            lost_values.append(int(lost.group(1)))
            continue
        if TRUNCATED_LINE_RE.match(line) is not None:
            truncated = True
            continue
        call = CALL_LINE_RE.match(line)
        if call is not None:
            function, middle = call.group(1), call.group(2)
            per_function[function] = per_function.get(function, 0) + 1
            call_lines_total += 1
            if "[semantics unverified]" in middle:
                qualified_lines += 1
            if "(" in middle and ")" in middle:
                mechanism_lines += 1
            continue
        raise ValueError(f"unrecognized trace line: {line!r}")
    if capture_seen != 1:
        raise ValueError(f"expected one CAPTURE header, saw {capture_seen}")
    if count_evidence is None:
        raise ValueError("trace stream lacks the COUNT_EVIDENCE record")
    if evidence is None:
        raise ValueError("trace stream lacks the EVIDENCE record")
    for key in ("stats_entered", "stats_returned", "raw_calls"):
        if not isinstance(count_evidence.get(key), int):
            raise ValueError(f"COUNT_EVIDENCE lacks integer {key!r}")
    if any(b < a for a, b in zip(lost_values, lost_values[1:])):
        raise ValueError(f"LOST series decreased (concatenated streams?): {lost_values}")
    return {
        "call_lines_total": call_lines_total,
        "per_function": per_function,
        "qualified_lines": qualified_lines,
        "mechanism_lines": mechanism_lines,
        "lost_values": lost_values,
        "lost_total": lost_values[-1] if lost_values else 0,
        "truncated": truncated,
        "count_evidence": count_evidence,
        "evidence": evidence,
    }


def trace_counts_match(scope, truth, stats_returned):
    """Window-validity rule for trace: kernel aggregate totals.

    Trace lines are delivered (lossy), so per-name line matching cannot
    validate the window; the ring-independent aggregate total can: exact
    equality per-PID (no foreign calls), coverage on --system.
    """
    truth_total = sum(truth.values())
    if scope == "pid":
        match = stats_returned == truth_total
        note = ("trace pid: kernel aggregate total must equal workload "
                f"truth exactly ({stats_returned} vs {truth_total}); "
                "per-name lines are delivered (lossy)")
    else:
        match = stats_returned >= truth_total
        note = ("trace system: kernel aggregate total must cover workload "
                f"truth ({stats_returned} >= {truth_total}); other "
                "processes may add calls")
    return match, note


def trace_crosscheck(*, lost_total, event_loss, stats_returned, raw_calls,
                     semantic_failures, truncated):
    """Pin the trace loss identity: produced - reduced == kernel loss.

    stats_returned counts completed calls in BPF before the ring reserve;
    raw_calls counts CALL records the drain reduced; event_loss counts
    failed reserves; the last LOST line repeats that counter. With no
    pre-reserve skips (semantic_capture_failures==0) and no truncation,
    stats_returned - raw_calls == event_loss == last LOST, exactly.
    """
    if truncated:
        return False, "truncated: post-limit reductions emit no lines, so no loss identity is claimed"
    problems = []
    if lost_total != event_loss:
        problems.append(
            f"last LOST line ({lost_total}) != EVIDENCE event_loss ({event_loss})")
    gap = stats_returned - raw_calls - event_loss
    if semantic_failures == 0:
        if gap != 0:
            problems.append(
                f"stats_returned - raw_calls - event_loss = {gap}, want 0")
    elif not 0 <= gap <= semantic_failures:
        problems.append(
            f"unexplained gap {gap} outside semantic_failures={semantic_failures} bound")
    if problems:
        return False, "; ".join(problems)
    return True, ("loss identity holds: stats_returned - raw_calls == "
                  "event_loss == last LOST")


def build_event_path(*, mode, generated, kernel_observed, event_loss,
                     semantic_capture_failures, call_lines, raw_calls,
                     ring_bytes, burst_wall_s):
    """Per-run event-path attribution: generated vs kernel vs delivered."""
    capacity = ring_capacity_records(ring_bytes)
    path = {
        "generated_total": generated,
        "kernel_observed_total": kernel_observed,
        "kernel_loss_event": event_loss,
        "ring_capacity_records": capacity,
        "predicted_burst_loss": predicted_burst_loss(generated, capacity),
        "burst_wall_s": burst_wall_s,
        "burst_rate_per_s": (generated / burst_wall_s
                             if burst_wall_s and burst_wall_s > 0 else None),
        "delivered_derived": None,
        "lines_vs_raw_calls_match": None,
        "delivery_gap": None,
    }
    if mode == "metrics":
        path["delivery_gap"] = ("metrics mode submits no ring traffic "
                                "(FLAG_POLICY_AGGREGATE): no delivered total")
    elif mode == "trace":
        path["delivered_derived"] = call_lines
        path["lines_vs_raw_calls_match"] = (call_lines == raw_calls)
        if call_lines != raw_calls:
            path["delivery_gap"] = (
                f"trace lines={call_lines} != raw_calls={raw_calls} "
                "(write suppression or post-limit reduction; see truncated flag)")
    elif semantic_capture_failures == 0:
        path["delivered_derived"] = kernel_observed - event_loss
    else:
        path["delivery_gap"] = (
            f"semantic_capture_failures={semantic_capture_failures}: some "
            "completed calls skipped the ring reserve, so delivered "
            "is bounded, not exact")
    return path


def assess_window(*, gate, scope, counts_match, collapsed,
                  attached_probes, trace_crosscheck):
    """Post-hoc window validity, decisive for weak (non-frame) gates.

    The frame gate is an in-observer attach-end signal; marker+settle
    gates are not, so they stand or fall on post-hoc evidence. The
    aggregate counts are ring-independent, which makes counts_match a
    window proof rather than a loss statement.
    """
    problems = []
    if not counts_match:
        problems.append("counts_match=False (window missed workload calls)")
    if collapsed:
        problems.append("COLLAPSED WINDOW (setup exceeded the duration)")
    if attached_probes <= 0:
        problems.append("attached_probes=0 (attach never completed)")
    if not trace_crosscheck:
        problems.append("trace loss crosscheck failed")
    strong = gate == "frame"
    scope_note = ("pid exact totals" if scope == "pid"
                  else "system covering totals")
    if problems:
        note = ("window INVALID (" + ("strong" if strong else "weak") +
                f" gate {gate}; {scope_note}): " + "; ".join(problems))
        return {"gate_strength": "strong" if strong else "weak",
                "window_valid": False, "window_note": note}
    return {"gate_strength": "strong" if strong else "weak",
            "window_valid": True,
            "window_note": ("window valid (" +
                            ("strong" if strong else "weak") +
                            f" gate {gate}; {scope_note})")}


def parse_loadavg(text):
    """First three /proc/loadavg fields, or None when absent/malformed."""
    if not text:
        return None
    try:
        one, five, fifteen = text.split()[:3]
        return float(one), float(five), float(fifteen)
    except (ValueError, IndexError):
        return None


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
    host = record["host"]
    load = "/".join(str(host.get(k, "?")) for k in
                    ("loadavg_1m", "loadavg_5m", "loadavg_15m"))
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
        f"sink={cond.get('sink', 'file')} gate={cond.get('gate', 'frame')} "
        f"manifest={cond['manifest'] or 'none'}",
        f"  workload: {cond['workload_argv']} seed={cond['seed']} n_calls={cond['n_calls']} "
        f"pace_us={cond['pace_us']} map_early={cond.get('map_early', '?')}",
        f"  host: {host['kernel']} {host['cpu']} "
        f"x{host['ncpu']} loadavg={load} (at go)",
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
        f"  observed ({tvo.get('observed_source', 'per-function calls')}; "
        f"+{n_zero} zero-call functions in record.json): "
        f"{json.dumps(observed_nz, sort_keys=True)}",
        f"  kernel_observed_total={tvo.get('kernel_observed_total', '?')}",
        f"  counts_match={tvo['counts_match']} ({tvo['match_note']})",
        f"  window: {record['window']['window_note']}",
        "",
        "event path:",
    ]
    path = record["event_path"]
    if "error" in path:
        lines.append(f"  error: {path['error']}")
    else:
        rate = path["burst_rate_per_s"]
        lines += [
            f"  generated={path['generated_total']} "
            f"kernel_observed={path['kernel_observed_total']} "
            f"kernel_loss={path['kernel_loss_event']}",
            f"  burst_wall={path['burst_wall_s']:.3f}s "
            f"burst_rate={'?' if rate is None else f'{rate:.0f}/s'} "
            f"ring_capacity={path['ring_capacity_records']} "
            f"predicted_burst_loss={path['predicted_burst_loss']}",
            f"  delivered_derived={path['delivered_derived']} "
            f"delivery_gap={path['delivery_gap'] or 'none'}",
        ]
    stream = record.get("trace_stream")
    if stream is not None:
        lines += [
            f"  trace lines={stream['call_lines_total']} "
            f"raw_calls={stream['count_evidence']['raw_calls']} "
            f"lost_stream={stream['lost_total']} "
            f"truncated={stream['truncated']}",
            f"  crosscheck: {stream['crosscheck_detail']}",
        ]
    lines += [
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
    scope = meta["condition"]["scope"]
    mode = meta["condition"]["mode"]
    is_trace = mode == "trace"
    samples = load_jsonl(args.samples)
    stderr_rows = load_jsonl(args.stderr_ts)
    truth, truth_prego = parse_truth(args.workload_log)
    workload_lines = Path(args.workload_log).read_text(encoding="utf-8").splitlines()
    burst_go_ns, burst_end_ns = parse_burst(workload_lines)
    burst_wall_s = (burst_end_ns - burst_go_ns) / 1e9

    stream = None
    if is_trace:
        # Trace publishes a line stream, not a JSON report: --report points
        # at the -o stream file and the EVIDENCE record inside it carries
        # the same counter universe as a profile report.
        stream = parse_trace_stream(
            Path(args.report).read_text(encoding="utf-8").splitlines(keepends=True))
        report = {"schema": stream["evidence"].get("schema", "trace-stream"),
                  "evidence": stream["evidence"], "capture": {}}
        observed = dict(stream["per_function"])
        observed_source = "trace lines (delivered: lossy, ring-dependent)"
    else:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        observed = aggregate_functions(report)
        observed_source = "aggregate maps (ring-independent kernel counts)"

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

    kernel_observed = None
    crosscheck_holds, crosscheck_detail = True, "n/a (not a trace run)"
    if is_trace:
        kernel_observed = int(stream["count_evidence"]["stats_returned"])
        counts_match, match_note = trace_counts_match(
            scope, truth, kernel_observed)
        crosscheck_holds, crosscheck_detail = trace_crosscheck(
            lost_total=stream["lost_total"],
            event_loss=int(evidence.get("event_loss", 0)),
            stats_returned=kernel_observed,
            raw_calls=int(stream["count_evidence"]["raw_calls"]),
            semantic_failures=int(evidence.get("semantic_capture_failures", 0)),
            truncated=stream["truncated"])
    elif scope == "pid":
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
    if kernel_observed is None:
        kernel_observed = sum(observed.values())

    # Effective ring bytes: the report's capture block is authoritative for
    # profile/metrics; trace streams carry no capture block, so the
    # requested condition value (resolved) stands in.
    ring_effective = capture.get("ring_bytes")
    if ring_effective is None:
        ring_effective = resolve_ring_bytes(meta["condition"].get("ring_bytes"))
    else:
        requested = resolve_ring_bytes(meta["condition"].get("ring_bytes"))
        if int(ring_effective) != requested:
            phases["method_warnings"].append(
                f"ring_bytes mismatch: requested {requested}, "
                f"report says {ring_effective}")
    drain_effective = capture.get("drain_interval_ms")
    if drain_effective is None:
        drain_raw = meta["condition"].get("drain_interval_ms")
        drain_effective = None if drain_raw in (None, "default") else drain_raw

    generated = sum(truth.values())
    event_loss = counters.get("event_loss")
    semantic_failures = counters.get("semantic_capture_failures")
    if event_loss is None or semantic_failures is None:
        event_path = {"error": "event_loss/semantic_capture_failures "
                               "counters missing; no attribution possible"}
    else:
        event_path = build_event_path(
            mode=mode, generated=generated,
            kernel_observed=kernel_observed, event_loss=event_loss,
            semantic_capture_failures=semantic_failures,
            call_lines=(stream["call_lines_total"] if stream else None),
            raw_calls=(int(stream["count_evidence"]["raw_calls"])
                       if stream else None),
            ring_bytes=ring_effective, burst_wall_s=burst_wall_s)
    collapsed = any("COLLAPSED WINDOW" in warning
                    for warning in phases["method_warnings"])
    window = assess_window(
        gate=meta["condition"].get("gate", "frame"), scope=scope,
        counts_match=counts_match, collapsed=collapsed,
        attached_probes=attached_probes,
        trace_crosscheck=crosscheck_holds)

    host = dict(meta["host"])
    loadavg = parse_loadavg(host.get("loadavg"))
    host["loadavg_1m"] = loadavg[0] if loadavg else None
    host["loadavg_5m"] = loadavg[1] if loadavg else None
    host["loadavg_15m"] = loadavg[2] if loadavg else None

    record = {
        "schema": RECORD_SCHEMA,
        "harness": meta["harness"],
        "condition": meta["condition"],
        "host": host,
        "verdict": evidence.get("completeness", "unknown"),
        "report_schema": report.get("schema", "unknown"),
        "capture_block": {
            "start": capture.get("start"),
            "end": capture.get("end"),
            "mode": capture.get("mode"),
            "scope": capture.get("scope"),
            "ring_bytes": ring_effective,
            "drain_interval_ms": drain_effective,
        },
        "phases": phases,
        "discovery_line": discovery_line,
        "window": window,
        "event_path": event_path,
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
            "observed_source": observed_source,
            "kernel_observed_total": kernel_observed,
            "counts_match": counts_match,
            "match_note": match_note,
        },
        "trace_stream": None if stream is None else {
            "call_lines_total": stream["call_lines_total"],
            "qualified_lines": stream["qualified_lines"],
            "mechanism_lines": stream["mechanism_lines"],
            "lost_values": stream["lost_values"],
            "lost_total": stream["lost_total"],
            "truncated": stream["truncated"],
            "count_evidence": stream["count_evidence"],
            "crosscheck_holds": crosscheck_holds,
            "crosscheck_detail": crosscheck_detail,
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
