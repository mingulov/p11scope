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

System-scope owned matching needs the workload's own mapping/pin
receipt: meta["condition"]["workload_module_identity"], a list of
{"dev", "ino", "sha256"?, "path"?} dicts attesting the module the
workload mapped. Pathnames (workload argv, discovery labels, refusal
lines) are display-only: without a receipt, or without identity on
the report side, owned matching is unknown, never pathname-guessed.

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


def parse_mapped_generation(lines):
    """Return the workload's unique mapped (PID, birth, endpoint) tuple.

    Mapping evidence is used only for the PID target-exit ordering proof.
    Missing, duplicate, or malformed evidence leaves that proof unavailable;
    it does not weaken the independent call-count oracle.
    """
    pattern = re.compile(
        r"workload: MAPPED pid=([1-9][0-9]*) "
        r"starttime=([1-9][0-9]*) endpoint=(0x[0-9a-f]+)")
    found = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("workload: MAPPED"):
            continue
        match = pattern.fullmatch(stripped)
        if match is None:
            return None
        found.append((int(match[1]), int(match[2]), int(match[3], 16)))
    return found[0] if len(found) == 1 else None


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
    """Ring bytes from a condition value: default/None, int, or n[K|M].

    The default tracks the binary's RING_BYTES (4 MiB since the F1
    repair); profile/metrics records carry the authoritative capture
    block, this only stands in for trace streams and mismatch notes.
    """
    if value is None or value == "default":
        return 4 * 1024 * 1024
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


def trace_counts_match(scope, truth, stats_returned, *, owned_admitted=True,
                       owned_note=""):
    """Window-validity rule for trace: kernel aggregate totals.

    Trace lines are delivered (lossy), so per-name line matching cannot
    validate the window; the ring-independent aggregate total can: exact
    equality per-PID (no foreign calls), coverage on --system. On system
    scope the aggregate cannot attribute calls to the owned workload, so
    System trace rows and aggregate counters have no module identity, so
    admission cannot turn their global totals into owned attribution.
    """
    truth_total = sum(truth.values())
    if scope == "pid":
        match = stats_returned == truth_total
        note = ("trace pid: kernel aggregate total must equal workload "
                f"truth exactly ({stats_returned} vs {truth_total}); "
                "per-name lines are delivered (lossy)")
        return match, note
    # A system trace exposes one global kernel total and delivered text rows,
    # neither of which carries a provider identity. Admission establishes that
    # the owned object was attached, but cannot attribute any returned call to
    # it. Never let foreign traffic satisfy the owned workload oracle.
    admission = ("matching unresolved" if owned_admitted is None else
                 "not admitted" if not owned_admitted else "admitted")
    note = (f"trace system: owned workload is {admission}, but the stream "
            "lacks per-module attribution; global kernel aggregate "
            f"({stats_returned}) cannot prove owned coverage of truth "
            f"({truth_total})" +
            ("" if not owned_note else f" ({owned_note})"))
    return False, note


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
        "delivered_note": None,
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
        path["delivered_note"] = (
            "arithmetic identity (kernel_observed - event_loss), not an "
            "independently observed consumer count: profile mode has no "
            "consumer oracle (audit F-74)")
    else:
        path["delivery_gap"] = (
            f"semantic_capture_failures={semantic_capture_failures}: some "
            "completed calls skipped the ring reserve, so delivered "
            "is bounded, not exact")
    return path


CANCEL_MARKER_RE = re.compile(
    r"p11scope: cancel: loop exited on signal (-?\d+) after (\d+) ticks")
# The discovery completion marker (engine.rs `report`), and only it: the
# generic "p11scope: discovery:" prefix also matches per-class noise
# summaries, broad fixed-family tallies and overlay-collapse notes, any
# of which may precede the completion line (audit F-74).
DISCOVERY_COMPLETION_RE = re.compile(
    r"p11scope: discovery: \d+ module\(s\), \d+ attach slot\(s\), "
    r"scan \d+ms, conflicts \d+, uncorroborated \d+")
# The loop-end marker run.rs prints when the capture loop stops because
# its target exited (audit F-74: the actual early-exit boundary).
TARGET_EXIT_RE = re.compile(r"p11scope: capture ended: target exited")
CANCEL_LATENCY_BUDGET_NS = 100_000_000


def check_scheduling_evidence(evidence):
    """Consistency of the repair's scheduling sub-object.

    Returns (ok, detail). Fail-closed: a missing sub-object, a split that
    does not sum to its published counter, or a sink policy other than the
    declared bounded-wait-drop all fail — the harness must assert the
    policy's evidence, never assume it.
    """
    scheduling = evidence.get("scheduling")
    if not isinstance(scheduling, dict):
        return (False, "scheduling evidence missing (pre-repair schema?); "
                       "repair credit unverifiable")
    for key in ("capture_event_loss", "detach_event_loss",
                "capture_discovery_loss", "detach_discovery_loss",
                "sink_policy"):
        if scheduling.get(key) is None:
            return (False, f"scheduling evidence incomplete: missing {key}")
    event_loss = evidence.get("event_loss")
    if event_loss is None:
        return (False, "event_loss counter missing; split unverifiable")
    capture = scheduling["capture_event_loss"]
    detach = scheduling["detach_event_loss"]
    if capture + detach != event_loss:
        return (False, f"event-loss split mismatch: capture {capture} + "
                       f"detach {detach} != event_loss {event_loss}")
    cap_disc = scheduling["capture_discovery_loss"]
    det_disc = scheduling["detach_discovery_loss"]
    disc_loss = evidence.get("discovery_ring_loss")
    if disc_loss is not None and cap_disc + det_disc != disc_loss:
        return (False, f"discovery-loss split mismatch: capture {cap_disc} "
                       f"+ detach {det_disc} != discovery_ring_loss "
                       f"{disc_loss}")
    if scheduling["sink_policy"] != "bounded-wait-drop":
        return (False, f"sink_policy {scheduling['sink_policy']!r}: want "
                       "'bounded-wait-drop' (undeclared slow-sink behavior)")
    return (True, "scheduling evidence consistent: splits sum to their "
                  "counters, sink policy bounded-wait-drop")


def attribute_loss(*, truth_calls, ring_capacity, event_loss,
                   semantic_failures, scheduling):
    """Name which bound broke: the envelope's outside-loss evidence.

    Returns {"status", "bounds", "detail"}. Statuses: lossless (zero loss
    with evidence), attributed (every share names a bound), guarded
    (semantic skips make delivered bounded, not exact), lossless-unverified
    (zero loss but no scheduling evidence), UNATTRIBUTED (loss past burst
    physics with no bound fired — never silently absorbed).
    """
    if scheduling is None:
        if event_loss == 0:
            return {"status": "lossless-unverified", "bounds": [],
                    "detail": "zero loss but no scheduling evidence: "
                              "repair credit unverifiable"}
        return {"status": "UNATTRIBUTED", "bounds": [],
                "detail": f"event_loss={event_loss} with no scheduling "
                          "evidence"}
    if semantic_failures:
        return {"status": "guarded", "bounds": [],
                "detail": f"semantic_capture_failures={semantic_failures}: "
                          "delivered is bounded, not exact"}
    if event_loss == 0:
        return {"status": "lossless", "bounds": [],
                "detail": "event_loss=0 with consistent scheduling evidence"}
    bounds = []
    detach = scheduling.get("detach_event_loss") or 0
    truncated = scheduling.get("terminal_drain_truncated", False)
    exhausted = scheduling.get("drain_budget_exhaustions") or 0
    if exhausted:
        bounds.append("drain-tick-budget")
    if detach:
        bounds.append("detach-window")
    if truncated:
        bounds.append("terminal-drain-bound")
    if scheduling.get("sink_timeouts") or scheduling.get("sink_dropped_bytes"):
        bounds.append("slow-sink")
    if not bounds:
        if event_loss <= predicted_burst_loss(truth_calls, ring_capacity):
            bounds.append("ring-capacity-vs-production")
        else:
            return {"status": "UNATTRIBUTED", "bounds": [],
                    "detail": f"event_loss={event_loss} past burst physics "
                              f"({truth_calls} calls vs {ring_capacity} "
                              "records) with no bound fired"}
    elif not (exhausted or truncated):
        # A fired scheduling bound explains the path it meters; any capture
        # residue past burst physics is still unattributed.
        residue = event_loss - detach
        if residue > 0:
            if residue <= predicted_burst_loss(truth_calls, ring_capacity):
                bounds.append("ring-capacity-vs-production")
            else:
                return {"status": "UNATTRIBUTED", "bounds": list(bounds),
                        "detail": f"capture residue {residue} past burst "
                                  f"physics; {bounds} explain only part"}
    return {"status": "attributed", "bounds": bounds,
            "detail": f"event_loss={event_loss} attributed to "
                      f"{', '.join(bounds)}"}


def find_cancel_marker(stderr_rows):
    """(ts_ns, signal, ticks) of the loop-exit cancel marker, else None.

    Accepts harness stderr-ts rows (t_mono_ns, stderr-only) and the
    stream-tagged shape: rows tagged a non-stderr stream never match.
    """
    for row in stderr_rows:
        if row.get("stream", "stderr") != "stderr":
            continue
        match = CANCEL_MARKER_RE.search(row.get("line", ""))
        if match is None:
            continue
        ts = row.get("ts_ns", row.get("t_mono_ns"))
        if ts is None:
            continue
        return (int(ts), int(match.group(1)), int(match.group(2)))
    return None


def cancel_probe_verdict(t0_ns, t_marker_ns):
    """Control-latency verdict: ack within the 100ms budget. Fail-closed."""
    if t_marker_ns is None:
        return {"pass": False,
                "detail": "cancel marker missing: the loop never "
                          "acknowledged the signal"}
    latency = t_marker_ns - t0_ns
    if latency <= CANCEL_LATENCY_BUDGET_NS:
        return {"pass": True,
                "detail": f"cancel acknowledged in {latency} ns "
                          "(budget 100ms)"}
    return {"pass": False,
            "detail": f"cancel latency {latency} ns exceeded the 100ms "
                      "budget"}


def assess_window(*, gate, scope, counts_match, burst_outside_window,
                  attached_probes, trace_crosscheck, coverage_detail=None,
                  observer_outcome=None, burst_window_relation=None):
    """Post-hoc window validity, decisive for weak (non-frame) gates.

    The frame gate is an in-observer attach-end signal; marker+settle
    gates are not, so they stand or fall on post-hoc evidence. The
    aggregate counts are ring-independent, which makes counts_match a
    window proof rather than a loss statement. `coverage_detail`, when
    given, names the exact coverage failure (e.g. unattributable owned
    traffic) instead of the generic missed-window text.
    `burst_window_relation` is the boundary-based overlap verdict from
    derive_phases. An explicit unknown fails closed; unchecked preserves
    the legacy case where no temporal claim was requested. When omitted,
    `burst_outside_window` supplies the backward-compatible verdict.
    """
    problems = []
    if observer_outcome:
        problems.append(observer_outcome)
    if not counts_match:
        if coverage_detail is None:
            problems.append("counts_match=False (window missed workload calls)")
        else:
            problems.append(f"counts_match=False ({coverage_detail})")
    if burst_window_relation is None:
        if burst_outside_window is True:
            burst_window_relation = "outside"
        elif burst_outside_window is False:
            burst_window_relation = "inside"
        else:
            burst_window_relation = "unchecked"
    if burst_window_relation == "outside":
        problems.append("BURST OUTSIDE WINDOW (workload burst escaped the "
                        "estimated capture window; see method warnings)")
    elif burst_window_relation == "unknown":
        problems.append("BURST WINDOW UNKNOWN (available external timestamps "
                        "do not prove that the workload burst stayed inside "
                        "the capture loop)")
    elif burst_window_relation not in ("inside", "unchecked"):
        problems.append("BURST WINDOW UNKNOWN (invalid boundary relation)")
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


def owned_module_candidates(meta):
    """Argv entries that may name the owned workload provider module.

    The harness runs the workload as [workload, MODULE, N, PACE, MAP_EARLY],
    so argv[1] is the owned module; a single-entry argv (synthetic inputs)
    names it directly. Display labels only: matching uses the workload
    mapping/pin receipt, and these labels merely veto on refusal.
    """
    argv = (meta.get("condition", {}).get("workload_argv") or [])
    if len(argv) > 1:
        return [str(argv[1])]
    return [str(entry) for entry in argv]


def _module_identity(ref):
    """(dev, ino, sha256) identity of a module ref, or None when absent.

    Real reports carry dev/ino/sha256 on both functions[].module and
    evidence.discovery[]; synthetic inputs may carry a bare path instead.
    """
    if not isinstance(ref, dict):
        return None
    if "ino" not in ref or "dev" not in ref:
        return None
    dev = ref["dev"]
    if isinstance(dev, (list, tuple)):
        dev = tuple(dev)
    return (dev, ref.get("ino"), ref.get("sha256"))


def _validated_report_identity_bridge(receipt):
    """Return the receipt identity only for an exact map-files bridge."""
    if not isinstance(receipt, dict):
        return None
    identity = _module_identity(receipt)
    bridge = receipt.get("report_identity_bridge")
    if (receipt.get("report_identity_associated") is not True
            or not isinstance(bridge, dict)
            or bridge.get("schema") != "p11scope/map-files-mountinfo-bridge/v1"
            or bridge.get("kind") != "map_files_fdinfo_target_mountinfo"):
        return None
    mapping = _module_identity(bridge.get("mapping_identity"))
    opened_mapping = bridge.get("opened_mapping_identity")
    opened_file = bridge.get("opened_file_identity")
    if (identity is None or mapping is None
            or not isinstance(opened_mapping, dict)
            or not isinstance(opened_file, dict)):
        return None
    opened_mapping_identity = _module_identity(opened_mapping)
    if (opened_mapping_identity is None
            or type(opened_mapping.get("mount_id")) is not int
            or opened_mapping["mount_id"] <= 0):
        return None
    identity_dev, identity_ino, identity_sha = identity
    mapping_dev, mapping_ino, _ = mapping
    opened_dev, opened_ino, _ = opened_mapping_identity
    file_dev = opened_file.get("dev")
    if isinstance(file_dev, (list, tuple)):
        file_dev = tuple(file_dev)
    if not (identity_dev == mapping_dev == opened_dev
            and identity_ino == mapping_ino == opened_ino
            and opened_file.get("ino") == identity_ino
            and isinstance(identity_sha, str)
            and opened_file.get("sha256") == identity_sha
            and isinstance(file_dev, tuple) and len(file_dev) == 2
            and all(type(part) is int and part >= 0 for part in file_dev)):
        return None
    return identity


def assess_owned_coverage(functions, discovery, refused, owned_paths,
                          owned_receipts=None):
    """Owned-workload attribution for system-scope coverage (audit F2).

    Scan-only system captures name every slot `unknown`, so unknown-name
    totals cannot tell owned workload calls from foreign traffic: coverage
    must come from calls attributed to the owned workload module, never
    from global sums. Matching is by physical identity from the
    workload's own mapping/pin receipt (`owned_receipts`: joined mapping-domain
    {"dev", "ino"} plus opened-file "sha256" dicts); pathname labels are
    display-only (audit F-74):
    the same pathname on another inode is not the owned module, and an
    alternate path to the receipt's inode is. A sha256 present on both
    sides must agree; a file that changed under the receipt no longer
    matches it. A refusal naming an owned label vetoes admission even
    without a receipt — negative evidence fails closed.
    Returns {"owned_admitted" (True/False/None when unresolvable),
    "owned_calls" (int/None), "owned_observed" (per-name dict/None),
    "total_calls", "note"}.
    """
    discovery = discovery or []
    if isinstance(owned_receipts, dict):
        owned_receipts = [owned_receipts]
    receipt_identities = set()
    association_unavailable = False
    for receipt in owned_receipts or []:
        if not isinstance(receipt, dict):
            continue
        identity = _validated_report_identity_bridge(receipt)
        if identity is None:
            association_unavailable = True
            continue
        receipt_identities.add(identity)

    def receipt_match(ref):
        if not isinstance(ref, dict):
            return False
        identity = _module_identity(ref)
        if identity is None:
            return False
        dev, ino, sha = identity
        for receipt_dev, receipt_ino, receipt_sha in receipt_identities:
            if (dev, ino) != (receipt_dev, receipt_ino):
                continue
            # Exact pinned identity includes bytes. An identity missing either
            # hash is insufficient to attribute host traffic to the receipt.
            if not isinstance(sha, str) or not isinstance(receipt_sha, str):
                continue
            if sha != receipt_sha:
                continue
            return True
        return False

    refused_paths = {str(row.get("path")) for row in (refused or [])
                     if isinstance(row, dict) and row.get("path")}
    owned_refused = [path for path in owned_paths if path in refused_paths]
    owned_entries = [entry for entry in discovery if receipt_match(entry)]
    identified = [entry for entry in discovery
                  if isinstance(entry, dict)
                  and _module_identity(entry) is not None]
    owned_calls = 0
    owned_observed = {}
    total_calls = 0
    for entry in functions or []:
        calls = int(entry.get("calls", 0))
        total_calls += calls
        if receipt_match(entry.get("module")):
            owned_calls += calls
            names = entry.get("names") or []
            if names:
                name = str(names[0])
                owned_observed[name] = owned_observed.get(name, 0) + calls
    admitted = sorted(str(entry.get("path")) for entry in discovery
                      if isinstance(entry, dict)) or ["none"]
    if owned_refused:
        note = (f"owned workload module {owned_refused} refused (not "
                f"admitted); unknown-name totals cannot prove owned coverage")
        return {"owned_admitted": False, "owned_calls": owned_calls,
                "owned_observed": owned_observed,
                "total_calls": total_calls, "note": note}
    if not receipt_identities:
        if association_unavailable:
            note = ("owned workload matching unresolved: mapping/opened-file "
                    "device domains differ and no report-visible opened-object "
                    "association exists")
        else:
            note = ("owned workload matching unresolved: no authoritative "
                    f"mapping/pin receipt (pathnames {owned_paths} are "
                    "display-only)")
        return {"owned_admitted": None, "owned_calls": None,
                "owned_observed": None,
                "total_calls": total_calls, "note": note}
    if not identified:
        note = ("owned workload matching unresolved: no discovery entry "
                f"carries mapping/pin identity (pathnames {admitted} are "
                "display-only)")
        return {"owned_admitted": None, "owned_calls": None,
                "owned_observed": None,
                "total_calls": total_calls, "note": note}
    if not owned_entries:
        note = (f"owned workload module {owned_paths} not admitted "
                f"(admitted: {admitted}"
                + ("" if not refused_paths else
                   f"; refused: {sorted(refused_paths)}") + ")")
        return {"owned_admitted": False, "owned_calls": owned_calls,
                "owned_observed": owned_observed,
                "total_calls": total_calls, "note": note}
    note = (f"owned-attributed {owned_calls} of {total_calls} observed "
            f"calls (module {owned_paths})")
    return {"owned_admitted": True, "owned_calls": owned_calls,
            "owned_observed": owned_observed,
            "total_calls": total_calls, "note": note}


def _observer_phase_s(phase_ms, key):
    """In-observer phase timer as seconds, or None when absent/unusable."""
    if not isinstance(phase_ms, dict):
        return None
    value = phase_ms.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0:
        return None
    return float(value) / 1000.0


def _canonical_identity(ref, *, require_sha=False, require_size=False):
    """Strict receipt identity tuple, or None for an incomplete record."""
    if not isinstance(ref, dict):
        return None
    dev = ref.get("dev")
    ino = ref.get("ino")
    if (not isinstance(dev, (list, tuple)) or len(dev) != 2
            or any(isinstance(part, bool) or not isinstance(part, int)
                   or part < 0 for part in dev)
            or isinstance(ino, bool) or not isinstance(ino, int) or ino <= 0):
        return None
    sha = ref.get("sha256")
    if require_sha and (not isinstance(sha, str)
                        or re.fullmatch(r"[0-9a-f]{64}", sha) is None):
        return None
    size = ref.get("size")
    if require_size and (isinstance(size, bool) or not isinstance(size, int)
                         or size < 0):
        return None
    return (tuple(dev), ino, sha, size)


def _validated_workload_generation(condition, mapped_generation):
    """Authenticate the selected PID generation against the full receipt."""
    if not isinstance(condition, dict) or condition.get("scope") != "pid":
        return None
    if mapped_generation is None:
        return None
    receipt = condition.get("workload_mapping_receipt")
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "p11scope/workload-mapping-receipt/v1"):
        return None
    pid = receipt.get("pid")
    birth = receipt.get("starttime")
    endpoint_text = receipt.get("endpoint_address")
    if (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
            or isinstance(birth, bool) or not isinstance(birth, int)
            or birth <= 0 or not isinstance(endpoint_text, str)
            or re.fullmatch(r"0x[0-9a-f]+", endpoint_text) is None):
        return None
    endpoint = int(endpoint_text, 16)
    if mapped_generation != (pid, birth, endpoint):
        return None

    mapping = receipt.get("mapping")
    mapping_id = _canonical_identity(receipt.get("mapping_identity"))
    opened_mapping = _canonical_identity(receipt.get("opened_mapping_identity"))
    opened = _canonical_identity(receipt.get("opened_file_identity"),
                                 require_sha=True, require_size=True)
    pinned = _canonical_identity(receipt.get("pinned"),
                                 require_sha=True, require_size=True)
    expected = _canonical_identity(receipt.get("expected"),
                                   require_sha=True, require_size=True)
    source = _canonical_identity(receipt.get("source"),
                                 require_sha=True, require_size=True)
    if (not isinstance(mapping, dict) or mapping_id is None
            or opened_mapping is None or opened is None or pinned is None
            or expected is None or source is None):
        return None
    mapping_row_id = _canonical_identity(mapping)
    mount_id = receipt.get("opened_mapping_identity", {}).get("mount_id")
    if (mapping_row_id is None or mapping_id[:2] != mapping_row_id[:2]
            or mapping_id[:2] != opened_mapping[:2]
            or mapping_id[1] != opened[1]
            or opened != pinned or opened != expected
            or source[2:] != expected[2:] or source[:2] == expected[:2]
            or isinstance(mount_id, bool) or not isinstance(mount_id, int)
            or mount_id <= 0):
        return None
    try:
        start = int(mapping["start"], 16)
        end = int(mapping["end"], 16)
    except (KeyError, TypeError, ValueError):
        return None
    if (not all(isinstance(mapping.get(key), str)
                and re.fullmatch(r"0x[0-9a-f]+", mapping[key])
                for key in ("start", "end", "offset"))
            or start >= end or not start <= endpoint < end
            or re.fullmatch(r"[r-][w-]x[ps]", str(mapping.get("perms"))) is None):
        return None

    namespace_before = receipt.get("mount_namespace_identity_before")
    namespace_after = receipt.get("mount_namespace_identity_after")
    bridge = receipt.get("mapping_bridge")
    if (_canonical_identity(namespace_before) is None
            or namespace_before != namespace_after or not isinstance(bridge, dict)
            or bridge.get("schema") != "p11scope/map-files-mountinfo-bridge/v1"
            or bridge.get("kind") != "map_files_fdinfo_target_mountinfo"
            or bridge.get("range") != f"{start:x}-{end:x}"
            or bridge.get("mount_namespace_identity") != namespace_before
            or re.fullmatch(r"[0-9a-f]{64}",
                            str(bridge.get("mountinfo_sha256"))) is None
            or any(re.fullmatch(r"[0-9a-f]{64}", str(receipt.get(name))) is None
                   for name in ("maps_before_sha256", "maps_after_sha256"))):
        return None
    report_bridge = {
        "schema": "p11scope/map-files-mountinfo-bridge/v1",
        "kind": "map_files_fdinfo_target_mountinfo",
        "mapping_identity": receipt["mapping_identity"],
        "opened_mapping_identity": receipt["opened_mapping_identity"],
        "opened_file_identity": {
            "dev": receipt["opened_file_identity"]["dev"],
            "ino": receipt["opened_file_identity"]["ino"],
            "sha256": receipt["opened_file_identity"]["sha256"],
        },
    }
    if bridge.get("report_identity_bridge") != report_bridge:
        return None
    module_receipts = condition.get("workload_module_identity")
    if isinstance(module_receipts, dict):
        module_receipts = [module_receipts]
    if not isinstance(module_receipts, list):
        return None
    expected_report_id = (mapping_id[0], mapping_id[1], opened[2])
    if not any(isinstance(candidate, dict)
               and candidate.get("report_identity_bridge") == report_bridge
               and _validated_report_identity_bridge(candidate)
               == expected_report_id
               for candidate in module_receipts):
        return None
    return pid, birth


def owned_pid_target_causal(condition, mapped_generation):
    """Whether target-exit causally follows this owned workload generation."""
    generation = _validated_workload_generation(condition, mapped_generation)
    if generation is None:
        return False
    receipt_pid, _ = generation
    argv = condition.get("observer_argv")
    if not isinstance(argv, list) or argv.count("--pid") != 1:
        return False
    index = argv.index("--pid")
    if index + 1 >= len(argv):
        return False
    try:
        selected_pid = int(argv[index + 1])
    except (TypeError, ValueError):
        return False
    return selected_pid == receipt_pid


def derive_phases(samples, stderr_rows, duration_s, t_spawn_ns, t_exit_ns,
                  t_go_ns=None, phase_ms=None, burst_go_ns=None,
                  burst_end_ns=None, gate=None,
                  owned_target_exit_causal=False):
    """Split wall time into phases from external traces.

    t_discovery: the discovery *completion* marker's timestamp (the
      observer prints it when discovery completes, before attach).
      Per-class noise summaries share the `p11scope: discovery:` prefix
      and may precede it, so only the completion shape counts.
    t_attached_fd_estimate: first fd sample reaching 95% of the run max.
      It is retrospective phase diagnostics, not an authoritative capture
      boundary. For a frame gate, t_go is recorded only as a latest-start
      bound: the loop was live before the harness observed the frame and
      released the workload, but frame delivery may be delayed.
    t_expiry_fd_estimate: fd attach estimate + requested duration. Frame
      gates never publish this as an exact expiry and never derive expiry
      from the delayed gate receipt.
    t_loop_end: for legacy gates, a loop-end marker (target-exit, cancel)
      when present, else t_expiry. For frame gates, external marker receipt
      is only an observation bound; it remains diagnostic unless exact
      owned-PID ordering supplies the causal target-exit premise.
    t_detach_start: first post-loop-end sample below 95% of max (sustained).
    t_detach_end: first sample after that back at baseline.
    drain = loop end -> detach start (final drain + detach setup);
    publish = detach end -> exit (report write + teardown).
    BPF program/map load has no external marker: it is folded into attach
    and reported as load_s=null with this reason.
    For frame gates the workload/window overlap uses conservative bounds:
    a BURST after gate release started after attach; an owned PID target-exit
    is causally after that exact workload generation's BURST; generic exit
    and cancel marker timestamps are only observation upper bounds. Unknown
    ordering is reported as unknown and cannot validate the window.
    `phase_ms`: the observer's own phase timers
      (evidence.scheduling.phase_ms), when the report carries them. The
      fd-trace estimator assumes the target lives until the computed
      expiry; a target that exits early leaves no taper, so the estimate
      reports detach_s=0.0 while the observer measured a real tail
      (audit F9). The in-observer detach timer is authoritative in that
      case; an estimated 0.0 without one is unconfirmed, never proof of
      instant teardown.
    """
    method_warnings = []
    t_discovery = None
    discovery_line = None
    summary_shaped = 0
    for row in stderr_rows:
        line = row.get("line", "")
        if DISCOVERY_COMPLETION_RE.search(line):
            t_discovery = int(row["t_mono_ns"])
            discovery_line = line
            break
        if "p11scope: discovery:" in line:
            summary_shaped += 1
    if t_discovery is None:
        ignored = (f" ({summary_shaped} summary-shaped lines ignored)"
                   if summary_shaped else "")
        method_warnings.append("no discovery completion marker on stderr"
                               + ignored + "; discovery/attach split unknown")
    t_loop_markers = []
    for row in stderr_rows:
        line = row.get("line", "")
        if TARGET_EXIT_RE.search(line):
            reason = "target-exit"
        elif CANCEL_MARKER_RE.search(line):
            reason = "cancel"
        else:
            continue
        ts = row.get("ts_ns", row.get("t_mono_ns"))
        if ts is None:
            continue
        t_loop_markers.append((int(ts), reason))

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
        "t_go_mono_ns": t_go_ns,
        "t_gate_release_mono_ns": t_go_ns if gate == "frame" else None,
        "t_discovery_mono_ns": t_discovery,
        "t_attached_mono_ns": None,
        "t_expiry_mono_ns": None,
        "t_attached_fd_estimate_mono_ns": None,
        "t_expiry_fd_estimate_mono_ns": None,
        "attach_fd_estimate_s": None,
        "capture_proven_lower_bound_s": None,
        "t_loop_end_observed_mono_ns": None,
        "t_loop_end_mono_ns": None,
        "loop_end_reason": "expiry",
        "t_detach_start_mono_ns": None,
        "t_detach_end_mono_ns": None,
        "burst_go_mono_ns": burst_go_ns,
        "burst_end_mono_ns": burst_end_ns,
        "burst_outside_window": None,
        "burst_window_relation": "unchecked",
    }

    is_frame_gate = gate == "frame"
    if is_frame_gate:
        phases["attach_boundary_source"] = "frame_gate_release_latest_bound"
        phases["capture_boundary_source"] = "external_bounds"
        if t_loop_markers:
            observed_end, observed_reason = min(t_loop_markers)
            phases["t_loop_end_observed_mono_ns"] = observed_end
            phases["loop_end_reason"] = observed_reason
    else:
        phases["attach_boundary_source"] = "fd_95pct_estimate"
        phases["capture_boundary_source"] = "fd_estimate_plus_duration"

    def classify_frame_burst():
        if burst_go_ns is None or burst_end_ns is None:
            return
        outside = False
        start_safe = False
        end_safe = False
        if burst_end_ns <= t_spawn_ns:
            outside = True
            method_warnings.append(
                "BURST PREDATED ATTACH: workload burst ended before "
                "the observer was spawned")
        elif t_go_ns is not None and burst_go_ns >= t_go_ns:
            start_safe = True
        else:
            method_warnings.append(
                "BURST START UNKNOWN: frame receipt is a latest attach "
                "bound and the workload began before that receipt")

        marker = min(t_loop_markers) if t_loop_markers else None
        if marker is not None:
            marker_ns, marker_reason = marker
            if marker_reason == "target-exit" and owned_target_exit_causal:
                if burst_end_ns > marker_ns:
                    method_warnings.append(
                        "BURST END UNKNOWN: owned target-exit observation "
                        "contradicts workload ordering")
                else:
                    # The truth/BURST log and mapping receipt name the exact
                    # selected PID generation. That process emits BURST end
                    # before it can exit, independent of stderr pipe delay.
                    end_safe = True
            elif burst_end_ns > marker_ns:
                outside = True
                method_warnings.append(
                    f"BURST OUTLIVED {marker_reason.upper()}: workload burst "
                    "ended after the externally observed loop-end marker")
            else:
                method_warnings.append(
                    f"BURST END UNKNOWN: delayed {marker_reason} observation "
                    "does not prove when the loop stopped")
        elif t_go_ns is not None:
            latest_expiry = t_go_ns + int(duration_s * 1e9)
            if burst_end_ns > latest_expiry:
                outside = True
                method_warnings.append(
                    "BURST OUTLIVED WINDOW: workload burst ended after the "
                    "latest possible duration expiry")
            else:
                method_warnings.append(
                    "capture expiry unknown: delayed frame receipt is not "
                    "the loop-start timestamp")
        else:
            method_warnings.append(
                "BURST END UNKNOWN: frame gate has no release timestamp")

        if outside:
            phases["burst_outside_window"] = True
            phases["burst_window_relation"] = "outside"
        elif start_safe and end_safe:
            phases["burst_outside_window"] = False
            phases["burst_window_relation"] = "inside"
            phases["capture_proven_lower_bound_s"] = max(
                0.0, (burst_end_ns - t_go_ns) / 1e9)
        else:
            phases["burst_window_relation"] = "unknown"

    if is_frame_gate:
        classify_frame_burst()
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
    phases["t_attached_fd_estimate_mono_ns"] = t_attached
    if t_discovery is not None:
        phases["discovery_s"] = max(0.0, (t_discovery - t_spawn_ns) / 1e9)
        phases["attach_fd_estimate_s"] = max(
            0.0, (t_attached - t_discovery) / 1e9)
    t_expiry = t_attached + int(duration_s * 1e9)
    phases["t_expiry_fd_estimate_mono_ns"] = t_expiry
    if not is_frame_gate:
        phases["t_attached_mono_ns"] = t_attached
        phases["t_expiry_mono_ns"] = t_expiry
        phases["attach_s"] = phases["attach_fd_estimate_s"]
    if t_loop_markers:
        t_loop_end, loop_end_reason = min(t_loop_markers)
    else:
        t_loop_end, loop_end_reason = t_expiry, "expiry"
    if is_frame_gate:
        if t_loop_markers:
            phases["t_loop_end_observed_mono_ns"] = t_loop_end
        else:
            loop_end_reason = "fd-estimated-expiry"
    else:
        phases["t_loop_end_mono_ns"] = t_loop_end
    phases["loop_end_reason"] = loop_end_reason
    if t_loop_markers and t_loop_end < t_attached:
        method_warnings.append(
            "loop-end marker precedes estimated attach (coarse fd sampling "
            "dated attach late); measured window unknown")
    elif not t_loop_markers and t_exit_ns < t_expiry:
        method_warnings.append(
            f"capture_measured unknown: observer exited "
            f"{(t_expiry - t_exit_ns) / 1e9:.2f}s before estimated expiry "
            "with no target-exit or cancel marker")
        phases["loop_end_reason"] = "unknown-early-exit"
    elif not is_frame_gate:
        phases["capture_measured_s"] = max(
            0.0, (t_loop_end - t_attached) / 1e9)
    if (not is_frame_gate and burst_go_ns is not None
            and burst_end_ns is not None):
        outside = False
        if burst_go_ns < t_attached:
            method_warnings.append(
                f"BURST PREDATED ATTACH: workload burst began "
                f"{(t_attached - burst_go_ns) / 1e9:.2f}s before attach "
                "completed; pre-attach calls are outside the window")
            outside = True
        if burst_end_ns > t_expiry:
            method_warnings.append(
                f"BURST OUTLIVED WINDOW: workload burst ended "
                f"{(burst_end_ns - t_expiry) / 1e9:.2f}s after the estimated "
                "capture expiry; calls past expiry are outside the window")
            outside = True
        phases["burst_outside_window"] = outside
        phases["burst_window_relation"] = "outside" if outside else "inside"
    # First post-loop-end dip below the plateau, sustained over 3 samples.
    detach_start = None
    for i in range(len(samples)):
        if times[i] < t_loop_end or fds[i] >= hi:
            continue
        if all(fds[j] < hi for j in range(i, min(i + 3, len(samples)))):
            detach_start = times[i]
            break
    if detach_start is None:
        # No dip found (short capture, coarse sampling): fall back to the
        # first below-plateau post-loop-end sample, else the last sample.
        later = [t for t, value in zip(times, fds)
                 if t >= t_loop_end and value < hi]
        detach_start = later[0] if later else times[-1]
        method_warnings.append("detach start fell back to first post-loop-end dip")
    phases["t_detach_start_mono_ns"] = detach_start
    floor = baseline + max(10, int(0.05 * run_max))
    detach_end = next((t for t, value in zip(times, fds)
                       if t >= detach_start and value <= floor), times[-1])
    phases["t_detach_end_mono_ns"] = detach_end
    drain = (detach_start - t_loop_end) / 1e9
    if drain < 0:
        method_warnings.append(
            f"detach began {abs(drain):.2f}s before estimated loop end; "
            "capture window estimate is off (attach-end marker or duration)")
        drain = 0.0
    phases["drain_s"] = drain
    phases["detach_s"] = max(0.0, (detach_end - detach_start) / 1e9)
    phases["publish_s"] = max(0.0, (t_exit_ns - detach_end) / 1e9)
    observer_detach_s = _observer_phase_s(phase_ms, "detach")
    if observer_detach_s is not None:
        if phases["detach_s"] == 0.0 and observer_detach_s > 0:
            method_warnings.append(
                "fd-trace detach estimate 0.0s contradicts the in-observer "
                f"detach timer ({observer_detach_s:.3f}s); using the "
                "in-observer value")
            phases["detach_s"] = observer_detach_s
    elif phases["detach_s"] == 0.0:
        method_warnings.append(
            "detach_s=0.0 is an fd-trace estimate with no in-observer "
            "timer to confirm it; an early target exit hides the detach "
            "tail (audit F9)")
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
        f"  boundaries: attach_source={phases.get('attach_boundary_source')} "
        f"attach_fd_estimate={fmt_seconds(phases.get('attach_fd_estimate_s'))} "
        f"capture_source={phases.get('capture_boundary_source')} "
        f"capture_proven_lower_bound="
        f"{fmt_seconds(phases.get('capture_proven_lower_bound_s'))}",
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
        if path.get("delivered_note") is not None:
            lines.append(f"  delivered note: {path['delivered_note']}")
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
    mapped_generation = parse_mapped_generation(workload_lines)
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
    window_coverage_detail = None
    # System-scope coverage requires owned attribution (audit F2): the
    # owned workload module resolves via workload_argv against admitted
    # discovery. Trace streams carry no functions[]; the admission half
    # of this assessment still applies to them.
    owned = assess_owned_coverage(
        report.get("functions", []), evidence.get("discovery", []),
        refused, owned_module_candidates(meta),
        meta["condition"].get("workload_module_identity"))
    if is_trace:
        kernel_observed = int(stream["count_evidence"]["stats_returned"])
        counts_match, match_note = trace_counts_match(
            scope, truth, kernel_observed,
            owned_admitted=owned["owned_admitted"], owned_note=owned["note"])
        if scope != "pid" and not counts_match:
            window_coverage_detail = match_note
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
            # per-name matching is impossible. Unknown-name totals cannot
            # tell owned workload calls from foreign traffic, so coverage
            # requires owned-module attribution (audit F2): foreign-only
            # sums never satisfy the assertion, even when they are large.
            truth_total = sum(truth.values())
            if not owned["owned_admitted"]:
                counts_match = False
                match_note = ("system scan-only: names unavailable "
                              f"(unknown); {owned['note']}; total coverage "
                              "unprovable")
            else:
                counts_match = owned["owned_calls"] >= truth_total
                match_note = (
                    "system scan-only: names unavailable (unknown); "
                    "owned-attributed coverage "
                    f"{owned['owned_calls']} vs truth {truth_total} "
                    f"({owned['note']})"
                )
            window_coverage_detail = match_note
        elif not owned["owned_admitted"]:
            counts_match = False
            match_note = ("system scope: named coverage requires the owned "
                          f"workload module; {owned['note']}")
            window_coverage_detail = match_note
        else:
            owned_observed = owned["owned_observed"] or {}
            counts_match = all(owned_observed.get(k, 0) >= v
                               for k, v in truth.items())
            match_note = ("system scope: receipt-attributed per-name rows must "
                          f"cover workload truth ({owned_observed} vs {truth}); "
                          f"{owned['note']}")
            if not counts_match:
                window_coverage_detail = match_note

    scheduling_timers = evidence.get("scheduling")
    observer_phase_ms = (scheduling_timers.get("phase_ms")
                         if isinstance(scheduling_timers, dict) else None)
    phases, discovery_line = derive_phases(
        samples, stderr_rows,
        float(meta["condition"]["duration_s"]),
        int(meta["timing"]["t_spawn_mono_ns"]),
        int(meta["timing"]["t_exit_mono_ns"]),
        int(meta["timing"]["t_go_mono_ns"]),
        phase_ms=observer_phase_ms,
        burst_go_ns=burst_go_ns, burst_end_ns=burst_end_ns,
        gate=meta["condition"].get("gate"),
        owned_target_exit_causal=owned_pid_target_causal(
            meta["condition"], mapped_generation),
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
    harness = meta.get("harness", {})
    observer_exit = harness.get("observer_exit")
    observer_timed_out = harness.get("observer_timed_out", False)
    observer_signal = harness.get("observer_signal")
    observer_problems = []
    if observer_timed_out:
        observer_problems.append("observer timed out")
    if observer_signal not in (None, "", 0):
        observer_problems.append(f"observer terminated by {observer_signal}")
    if observer_exit != 0:
        observer_problems.append(f"observer exit={observer_exit}")
    observer_outcome = ("; ".join(observer_problems)
                        if observer_problems else None)
    window = assess_window(
        gate=meta["condition"].get("gate", "frame"), scope=scope,
        counts_match=counts_match,
        burst_outside_window=phases["burst_outside_window"],
        attached_probes=attached_probes,
        trace_crosscheck=crosscheck_holds,
        coverage_detail=window_coverage_detail,
        observer_outcome=observer_outcome,
        burst_window_relation=phases["burst_window_relation"])

    # Task 3.1 repair: scheduling consistency + which-bound-broke
    # attribution + the cancel control-latency probe. A missing scheduling
    # sub-object is recorded in-section (pre-repair schema); only a present
    # but inconsistent one warns globally, so old fixtures stay clean.
    sched_evidence = evidence.get("scheduling")
    sched_ok, sched_detail = check_scheduling_evidence({
        "event_loss": event_loss,
        "discovery_ring_loss": counters.get("discovery_ring_loss"),
        "scheduling": sched_evidence,
    })
    if sched_evidence is not None and not sched_ok:
        phases["method_warnings"].append(
            f"scheduling evidence inconsistent: {sched_detail}")
    if (event_loss is None or semantic_failures is None
            or not isinstance(event_path, dict)
            or "ring_capacity_records" not in event_path):
        attribution = {"status": "guarded", "bounds": [],
                       "detail": "loss counters missing; no attribution "
                                 "possible"}
    else:
        attribution = attribute_loss(
            truth_calls=generated,
            ring_capacity=event_path["ring_capacity_records"],
            event_loss=event_loss, semantic_failures=semantic_failures,
            scheduling=sched_evidence)
    if (sched_evidence is not None
            and attribution["status"] == "UNATTRIBUTED"):
        phases["method_warnings"].append(
            f"loss unattributed: {attribution['detail']}")
    cancel_request = meta["condition"].get("cancel_probe") or {}
    marker = find_cancel_marker(stderr_rows)
    if marker is None and not cancel_request:
        cancel_probe = None
    else:
        t_ref = cancel_request.get(
            "sent_mono_ns", int(meta["timing"]["t_go_mono_ns"]))
        cancel_probe = {"marker": None, "verdict": None}
        if marker is not None:
            ts, sig, ticks = marker
            cancel_probe["marker"] = {"ts_ns": ts, "signal": sig,
                                      "ticks": ticks}
            cancel_probe["verdict"] = cancel_probe_verdict(t_ref, ts)
        else:
            cancel_probe["verdict"] = cancel_probe_verdict(t_ref, None)
        if not cancel_request:
            cancel_probe["note"] = (
                "unsolicited marker (no cancel_probe condition); latency "
                "vs t_go is informational")
        elif not cancel_probe["verdict"]["pass"]:
            phases["method_warnings"].append(
                "cancel probe failed: "
                f"{cancel_probe['verdict']['detail']}")

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
        "scheduling": {
            "check": {"ok": sched_ok, "detail": sched_detail},
            "attribution": attribution,
            "evidence": sched_evidence,
        },
        "cancel_probe": cancel_probe,
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
            "owned_observed": owned["owned_observed"],
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
            "Phase boundaries are externally derived (fd trace + stderr "
            "markers), not in-observer timestamps; drain/detach/publish "
            "splits are approximate. Without a loop-end marker, an early "
            "exit leaves the measured window unknown rather than assumed.",
            "BPF load is folded into attach_s (no external marker).",
            "Observer CPU/RSS are wall-window samples; noisy under concurrent "
            "build load (sibling workers) — see the design note.",
            "counts_match for pid scope requires exact per-name equality; "
            "for system profile/metrics scope it requires receipt-attributed "
            "per-name rows to cover truth (scan-only unknown names use the "
            "owned-attributed total); system trace remains unknown because "
            "its rows and aggregate counters carry no module identity "
            "(foreign/unknown totals alone never satisfy coverage). "
            "Without a workload mapping/pin receipt, owned matching is "
            "unknown.",
            "delivered_derived in profile mode is arithmetic "
            "(kernel_observed - event_loss), not an independently "
            "observed consumer count.",
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
