#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare an S1 throughput run's driver ledger with observer output.

Inputs: one driver ledger per worker thread (the T0 per-call shape:
ready, call{seq,fn,rv,pid,tid,t0,t1}, ack on CLOCK_MONOTONIC ns, each
file validated by scripts/joint-ledger-oracle.py verbatim), the
observer's --event-log JSONL (one --events per retained rotation file,
concatenated) and the inventory JSON snapshot of a --pid-scoped run.

Gates, in order; the first failure refuses with its own reason:

1. Sustained rate: every full 1 s window aligned to the earliest
   ready.t holds at least --min-rate ledgered call END stamps (t1).
   A burst followed by idle fails; the partial tail is reported, never
   gated; a run with no full window fails (a sub-second burst is not a
   sustained rate). --min-rate 0 records windows without gating, for
   diagnostic runs only.
2. Conservation: issued == observed exactly, at the finest granularity
   the v0.5.0 S1 contract publishes (docs/schema/inventory-v1.md):
   exact call and error totals per mechanism - the driver edge
   entries.count, operations.calls and the summed api_returns counts
   each equal issued, and every mechanism row's calls / errors equal
   the ledgered totals of its evidence functions - with the observed
   function-name and return-code sets equal to the ledger's hot-loop
   sets. The driver's ledgered teardown calls (C_CloseSession,
   C_Finalize) are conserved in the exact totals but claim no
   mechanism row, so they are exempt from the evidence-set checks.
   Within one mechanism row, function swaps are invisible in v1 output
   and are a documented blind spot, not a proof.
3. Zero event loss: observation.lifecycle.ring_loss == 0, the S1
   event-loss account observation.semantic_capture.unrouted_returns ==
   0 (reported as events_lost), a proven full drain (final_drain true,
   stop_quiescence quiesced), no known-loss gap, loss-free counted
   coverage on the driver edge and its semantic rows, and a complete
   event stream (ended present, edges_unretained == 0,
   gaps_suppressed == 0, no retention eviction). The v0.5.0
   joint_journal_unavailable lane disclosure is tolerated, never gated.
4. S1-active proof: object_observations reads unavailable with reason
   journal_unavailable (the v0.5.0 marker: no key-operation feed was
   installed, so the S1 path carried every call), and the semantic
   lane left disabled behind.

Recorded, never gated: S1 publish latency. Each ledgered END t1 maps
to the first edge_observed record whose cumulative entries.count
reaches it (the coarse tail-bound mapping); the report carries the
sample count with p50/p99/max. Twins live in
tests/python/test_s1_throughput_compare.py.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

try:
    _T0_SPEC = importlib.util.spec_from_file_location(
        "joint_ledger_oracle",
        Path(__file__).resolve().parent / "joint-ledger-oracle.py")
    T0 = importlib.util.module_from_spec(_T0_SPEC)
    _T0_SPEC.loader.exec_module(T0)
except OSError:
    T0 = None

DEFAULT_MIN_RATE = 10000
NS_PER_S = 1_000_000_000
MAX_WORD = (1 << 64) - 1
MAX_EVENT_ROWS = 500000
MAX_EVENT_LINE_BYTES = 4 * 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024 * 1024
MAX_INVENTORY_BYTES = 256 * 1024 * 1024
EVENT_SCHEMA = "p11scope/inventory-events/v1"

# Gap subjects that name event or capture loss. The first three are fixed
# producer strings; "joint machine unavailable" is the plan-named text
# (it reads as the subject argument of the two-arg gap helper) and is
# denied in both positions.
LOSS_GAP_SUBJECTS = frozenset({
    "semantic capture loss",
    "native capture lifecycle evidence lost",
    "native capture retirement unsettled",
    "joint machine unavailable",
})
# Gap reasons that name a lost feed (the plan-named text above).
LOSS_GAP_REASONS = frozenset({
    "joint machine unavailable",
})
# Driver teardown calls, ledgered in their own file: S1 counts them in
# entries/operations/api_returns, but lifecycle-only calls claim no
# mechanism row, so they are exempt from the evidence-set checks.
TEARDOWN_FUNCTIONS = frozenset({"C_CloseSession", "C_Finalize"})
# The v0.5.0 per-lane S1 disclosure: expected on every --manifest run,
# tolerated by the loss gate, never required and never a failure.
TOLERATED_GAP_REASONS = frozenset({
    "joint_journal_unavailable",
})
# Semantic-lane states past "no lane": the S1 path carried the run.
S1_ACTIVE_STATUSES = frozenset({"active", "partial", "stopped"})
# Derived presentation keys on edge_observed records, stripped before
# the record is compared with its snapshot edge.
DERIVED_EDGE_KEYS = frozenset(
    {"presence", "capture", "activity", "identity_context"})


class S1Error(ValueError):
    """A gate refused: the run did not prove S1 throughput."""


def _require(condition, reason):
    if not condition:
        raise S1Error(reason)


def _u64(value):
    return type(value) is int and 0 <= value <= MAX_WORD


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise S1Error("nonfinite JSON number")


def read_events(stream):
    """Read bounded event-log JSONL with strict envelopes."""
    rows = []
    total = 0
    while line := stream.readline(MAX_EVENT_LINE_BYTES + 1):
        _require(type(line) is str, "events must be text")
        try:
            size = len(line.encode("utf-8"))
        except UnicodeError as error:
            raise S1Error("invalid events encoding") from error
        total += size
        _require(size <= MAX_EVENT_LINE_BYTES and total <= MAX_EVENT_BYTES,
                 "events byte limit")
        _require(len(rows) < MAX_EVENT_ROWS, "events row limit")
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)
        except json.JSONDecodeError as error:
            raise S1Error("invalid events row") from error
        _require(type(row) is dict, "event row must be an object")
        _require(row.get("schema") == EVENT_SCHEMA, "event schema mismatch")
        _require(_u64(row.get("seq")), "event seq out of range")
        _require(_u64(row.get("at_ns")), "event at_ns out of range")
        _require(type(row.get("kind")) is str, "event kind must be a string")
        _require(type(row.get("event")) is dict, "event payload must be an object")
        rows.append(row)
    rows.sort(key=lambda row: row["seq"])
    return rows


def read_inventory_file(path):
    """Read the inventory JSON snapshot with a size cap."""
    with open(path, "rb") as stream:
        raw = stream.read(MAX_INVENTORY_BYTES + 1)
    _require(len(raw) <= MAX_INVENTORY_BYTES, "inventory byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise S1Error("invalid inventory encoding") from error
    try:
        doc = json.loads(text, object_pairs_hook=_unique_object,
                         parse_constant=_invalid_constant)
    except json.JSONDecodeError as error:
        raise S1Error("invalid inventory document") from error
    _require(type(doc) is dict, "inventory must be an object")
    return doc


def load_ledgers(paths):
    """Validate every ledger with the T0 core and merge the calls.

    One file per worker thread; all share the driver's pid. Returns the
    merged view: pid, issued, per-call (t0, t1, fn, rv), the ready..ack
    span and the per-function table.
    """
    _require(T0 is not None, "joint-ledger oracle missing")
    _require(paths, "no ledgers given")
    _require(len(set(paths)) == len(paths), "duplicate ledger path given")
    merged = []
    pid = None
    ready_min = None
    ack_max = None
    for path in paths:
        try:
            with open(path, encoding="utf-8") as stream:
                rows = T0.read_ledger(stream)
        except (OSError, UnicodeError) as error:
            raise S1Error(f"unreadable ledger {path}") from error
        except T0.LedgerError as error:
            raise S1Error(f"ledger {path}: {error}") from error
        try:
            T0.validate_ledger(rows)
        except T0.LedgerError as error:
            raise S1Error(f"ledger {path}: {error}") from error
        ready = rows[0]
        ack = rows[-1]
        _require(pid is None or ready["pid"] == pid,
                 f"ledger pid {ready['pid']} disagrees with {pid}")
        pid = ready["pid"]
        ready_min = ready["t"] if ready_min is None else min(ready_min, ready["t"])
        ack_max = ack["t"] if ack_max is None else max(ack_max, ack["t"])
        for row in rows:
            if row.get("kind") == "call":
                merged.append(row)
    _require(merged, f"issued 0: empty run with {len(paths)} ledgers, no calls")
    fn_table = {}
    for row in merged:
        cell = fn_table.setdefault(row["fn"], {"total": 0, "errors": 0})
        cell["total"] += 1
        cell["errors"] += row["rv"] != 0
    return {"pid": pid, "issued": len(merged), "ledgers": len(paths),
            "calls": merged, "ready_min": ready_min, "ack_max": ack_max,
            "fn_table": fn_table, "fn_set": set(fn_table),
            "rv_set": {row["rv"] for row in merged}}


def check_windows(view, min_rate):
    """Bin call END stamps into full 1 s windows aligned to ready.t.

    Every full window must hold at least min_rate calls; the partial
    tail is counted and returned, never gated. min_rate 0 records the
    bins without gating (diagnostic runs only).
    """
    _require(type(min_rate) is int and min_rate >= 0,
             "min_rate must be a non-negative integer")
    ends = sorted(row["t1"] for row in view["calls"])
    ready = view["ready_min"]
    ack = view["ack_max"]
    full = (ack - ready) // NS_PER_S
    if min_rate > 0:
        _require(full > 0,
                 f"no full 1 s window in {ack - ready} ns "
                 f"(ready {ready}, ack {ack}); a sustained rate needs "
                 "a run longer than 1 s")
    windows = []
    start = 0
    for index in range(full):
        window_start = ready + index * NS_PER_S
        window_end = window_start + NS_PER_S
        while start < len(ends) and ends[start] < window_start:
            start += 1
        stop = start
        while stop < len(ends) and ends[stop] < window_end:
            stop += 1
        count = stop - start
        if min_rate > 0:
            _require(count >= min_rate,
                     f"window {index}: {count} calls/s below minimum "
                     f"{min_rate} [{window_start}, {window_end})")
        windows.append({"index": index, "start_ns": window_start,
                        "end_ns": window_end, "count": count})
        start = stop
    tail_start = ready + full * NS_PER_S
    tail = {"start_ns": tail_start, "end_ns": ack,
            "count": len(ends) - start}
    return {"windows": windows, "tail": tail, "full_windows": full}


def _started_event(events):
    for row in events:
        if row["kind"] == "started":
            return row["event"]
    raise S1Error("event stream incomplete: no started marker")


def check_scope_and_clock(events, pid):
    """The run was --pid-scoped on the driver, on the capture clock."""
    started = _started_event(events)
    scope = started.get("scope")
    _require(scope == f"pid:{pid}",
             f"event scope {scope!r} is not --pid for driver pid {pid}")
    clock = started.get("clock")
    _require(type(clock) is dict, "started clock must be an object")
    _require(clock.get("basis") == "CLOCK_MONOTONIC"
             and clock.get("unit") == "ns",
             f"event clock basis {clock.get('basis')!r}/"
             f"{clock.get('unit')!r} disagrees with CLOCK_MONOTONIC/ns")


def select_driver(doc, pid):
    """Find the driver's single edge and its semantic rows."""
    callers = doc.get("callers")
    _require(type(callers) is list, "inventory callers must be a list")
    caller_ids = {caller["id"] for caller in callers
                  if type(caller) is dict and caller.get("pid") == pid
                  and type(caller.get("id")) is str}
    _require(caller_ids, f"no caller with driver pid {pid} in inventory")
    edges = doc.get("edges")
    _require(type(edges) is list, "inventory edges must be a list")
    driver_edges = [edge for edge in edges
                    if type(edge) is dict and edge.get("caller") in caller_ids]
    _require(len(driver_edges) == 1,
             f"driver edge: {len(driver_edges)} edges for pid {pid}, "
             "need exactly 1 for an exact comparison")
    edge = driver_edges[0]
    sem_rows = [row for row in doc.get("semantic_edges", [])
                if type(row) is dict and row.get("caller") == edge.get("caller")
                and row.get("module") == edge.get("module")]
    _require(sem_rows,
             f"no semantic_edges rows for driver edge "
             f"({edge.get('caller')}, {edge.get('module')})")
    observation = doc.get("observation")
    _require(type(observation) is dict, "inventory observation must be an object")
    _require(observation.get("lane") == "native",
             f"capture lane is {observation.get('lane')!r}, not native; "
             "throughput needs the native lane")
    _require(type(observation.get("lifecycle")) is dict,
             "native observation without a lifecycle account")
    _require(type(observation.get("semantic_capture")) is dict,
             "native observation without a semantic_capture summary")
    return {"caller_ids": sorted(caller_ids), "edge": edge,
            "sem_rows": sem_rows, "observation": observation}


def driver_series(events, edge):
    """(at_ns, entries.count) records for the driver edge, in time order."""
    caller = edge.get("caller")
    module = edge.get("module")
    series = []
    for row in events:
        if row["kind"] != "edge_observed":
            continue
        payload = row["event"]
        if payload.get("caller") != caller or payload.get("module") != module:
            continue
        entries = payload.get("entries")
        _require(type(entries) is dict, "edge_observed without entries")
        count = entries.get("count")
        _require(_u64(count), "edge_observed count out of range")
        series.append({"at_ns": row["at_ns"], "count": count,
                       "seq": row["seq"], "payload": payload})
    series.sort(key=lambda point: (point["at_ns"], point["seq"]))
    _require(series,
             "event stream incomplete: no edge_observed records "
             "for the driver edge")
    return series


def check_stream_matches_snapshot(series, edge):
    """The last retained record must equal the snapshot edge verbatim."""
    last = series[-1]["payload"]
    stripped = {key: value for key, value in last.items()
                if key not in DERIVED_EDGE_KEYS}
    _require(stripped == edge,
             "stream/snapshot divergence: the last retained edge_observed "
             "record for the driver edge differs from its snapshot entry")


def record_latency(view, series):
    """Coarse per-call publication latency: k-th END to first covering record.

    Recorded only. counts are cumulative, so the k-th END t1 maps to the
    first record whose count reaches k; calls past every record stay
    unmapped and are counted, never gated.
    """
    ends = sorted(row["t1"] for row in view["calls"])
    samples = []
    unmapped = 0
    for position, end in enumerate(ends, start=1):
        cover = next((point for point in series if point["count"] >= position),
                     None)
        if cover is None:
            unmapped += 1
        else:
            samples.append(cover["at_ns"] - end)
    samples.sort()
    if not samples:
        return {"samples": 0, "p50_ns": None, "p99_ns": None,
                "max_ns": None, "unmapped": unmapped}
    count = len(samples)
    p50 = samples[(50 * count + 99) // 100 - 1]
    p99 = samples[(99 * count + 99) // 100 - 1]
    return {"samples": count, "p50_ns": p50, "p99_ns": p99,
            "max_ns": samples[-1], "unmapped": unmapped}


def check_conservation(view, selected):
    """Issued == observed: totals, mechanism rows, function and rv sets."""
    issued = view["issued"]
    edge = selected["edge"]
    entries = edge.get("entries")
    _require(type(entries) is dict, "driver edge without entries")
    _require(entries.get("count") == issued,
             f"entries.count {entries.get('count')} != issued {issued}")
    operations = edge.get("operations")
    _require(type(operations) is dict,
             f"no S1 operations on the driver edge "
             f"(semantics {edge.get('semantics')!r})")
    _require(operations.get("calls") == issued,
             f"operations.calls {operations.get('calls')} != issued {issued}")
    api_total = 0
    for row in selected["sem_rows"]:
        returns = row.get("api_returns")
        _require(type(returns) is dict, "semantic row without api_returns")
        count = returns.get("count")
        _require(_u64(count),
                 f"api_returns {count!r} unusable with issued {issued}")
        api_total += count
    _require(api_total == issued,
             f"api_returns {api_total} != issued {issued}")
    mechanisms = edge.get("mechanisms")
    _require(type(mechanisms) is list and mechanisms,
             f"no S1 mechanism rows on the driver edge "
             f"with {issued} issued calls")
    observed_fns = set()
    observed_rvs = set()
    for row in mechanisms:
        _require(type(row) is dict, "mechanism row must be an object")
        evidence = row.get("evidence")
        _require(type(evidence) is dict, "mechanism without evidence")
        functions = evidence.get("functions")
        _require(type(functions) is list
                 and all(type(fn) is str for fn in functions),
                 "mechanism evidence functions must be a string list")
        returns = evidence.get("returns")
        _require(type(returns) is list, "mechanism evidence returns must be a list")
        for entry in returns:
            _require(type(entry) is dict and _u64(entry.get("rv")),
                     "observed return code out of range")
            observed_rvs.add(entry["rv"])
        observed_fns.update(functions)
    hot_calls = [row for row in view["calls"]
               if row["fn"] not in TEARDOWN_FUNCTIONS]
    hot_fns = {row["fn"] for row in hot_calls}
    hot_rvs = {row["rv"] for row in hot_calls}
    missing = sorted(hot_fns - observed_fns)
    if missing:
        raise S1Error(
            f"ledger function {missing[0]} missing from observed evidence")
    extra = sorted(observed_fns - view["fn_set"])
    if extra:
        raise S1Error(f"observed function {extra[0]} absent from ledger")
    missing_rv = sorted(hot_rvs - observed_rvs)
    if missing_rv:
        raise S1Error(
            f"ledger rv {missing_rv[0]} missing from observed returns")
    extra_rv = sorted(observed_rvs - view["rv_set"])
    if extra_rv:
        raise S1Error(f"observed rv {extra_rv[0]} absent from ledger")
    checked = []
    for row in mechanisms:
        functions = row["evidence"]["functions"]
        want_calls = sum(view["fn_table"][fn]["total"] for fn in functions)
        want_errors = sum(view["fn_table"][fn]["errors"] for fn in functions)
        label = row.get("mechanism")
        _require(row.get("calls") == want_calls,
                 f"mechanism {label} calls {row.get('calls')} != "
                 f"ledger {want_calls} for functions {sorted(functions)}")
        _require(row.get("errors") == want_errors,
                 f"mechanism {label} errors {row.get('errors')} != "
                 f"ledger {want_errors} for functions {sorted(functions)}")
        checked.append({"mechanism": label, "calls": row["calls"],
                        "errors": row["errors"]})
    teardown_fns = sorted(view["fn_set"] & TEARDOWN_FUNCTIONS)
    teardown = {
        "functions": teardown_fns,
        "calls": sum(view["fn_table"][fn]["total"] for fn in teardown_fns),
        "errors": sum(view["fn_table"][fn]["errors"] for fn in teardown_fns),
    }
    return {"entries": entries["count"], "operations": operations["calls"],
            "api_returns": api_total, "mechanisms": checked,
            "teardown": teardown}


def _gap_loss_reason(subject, reason):
    if reason in TOLERATED_GAP_REASONS:
        return None
    if subject in LOSS_GAP_SUBJECTS or reason in LOSS_GAP_REASONS:
        return f"loss gap: subject {subject!r} reason {reason!r}"
    return None


def check_loss(selected, doc, events):
    """Zero event loss across counters, drain proof, gaps and coverage."""
    observation = selected["observation"]
    ring_loss = observation["lifecycle"].get("ring_loss")
    _require(_u64(ring_loss), "lifecycle ring_loss out of range")
    _require(ring_loss == 0,
             f"ring_loss {ring_loss} (observation.lifecycle.ring_loss)")
    capture = observation["semantic_capture"]
    unrouted = capture.get("unrouted_returns")
    _require(_u64(unrouted), "semantic_capture unrouted_returns out of range")
    _require(unrouted == 0,
             f"events_lost {unrouted} "
             "(observation.semantic_capture.unrouted_returns)")
    drain = capture.get("final_drain")
    quiescence = capture.get("stop_quiescence")
    _require(drain is True and quiescence == "quiesced",
             f"stop did not prove a full drain (final_drain={drain}, "
             f"stop_quiescence={quiescence})")
    gaps = doc.get("gaps")
    _require(type(gaps) is list, "inventory gaps must be a list")
    for gap in gaps:
        _require(type(gap) is dict, "gap entry must be an object")
        subject = gap.get("subject")
        reason = gap.get("reason")
        _require(type(subject) is str and type(reason) is str,
                 "gap entry without subject/reason")
        hit = _gap_loss_reason(subject, reason)
        _require(hit is None, hit)
    for row in events:
        if row["kind"] != "gap_recorded":
            continue
        payload = row["event"]
        subject = payload.get("subject")
        reason = payload.get("reason")
        _require(type(subject) is str and type(reason) is str,
                 "gap_recorded without subject/reason")
        hit = _gap_loss_reason(subject, reason)
        _require(hit is None, hit)
    edge = selected["edge"]
    coverage = edge.get("entries", {}).get("coverage")
    _require(type(coverage) is dict, "driver edge without entries coverage")
    _require(coverage.get("state") == "counted"
             and coverage.get("lossy") is False,
             f"edge coverage not loss-free: state={coverage.get('state')!r} "
             f"lossy={coverage.get('lossy')!r}")
    for row in selected["sem_rows"]:
        row_coverage = row.get("coverage")
        _require(type(row_coverage) is dict, "semantic row without coverage")
        _require(row_coverage.get("lossy") is False,
                 "semantic coverage not loss-free for instance "
                 f"{row.get('instance')!r}")
    ended = next((row["event"] for row in events if row["kind"] == "ended"),
                 None)
    _require(ended is not None, "event stream incomplete: no ended marker")
    unretained = ended.get("edges_unretained")
    _require(unretained == 0,
             f"event stream incomplete: edges_unretained {unretained}")
    suppressed = ended.get("gaps_suppressed")
    _require(suppressed == 0,
             f"event stream incomplete: gaps_suppressed {suppressed}")
    evicted = [row for row in events if row["kind"] == "retention_evicted"]
    _require(not evicted,
             f"event stream incomplete: retention evicted {len(evicted)} files")
    budgets = doc.get("budgets")
    _require(budgets is None or type(budgets) is dict,
             "inventory budgets must be an object")
    retained = (budgets or {}).get("retained_history")
    _require(retained is None or type(retained) is dict,
             "retained_history must be an object")
    retained = retained or {}
    _require(retained.get("suppressed", 0) == 0,
             "event stream incomplete: snapshot suppressed "
             f"{retained.get('suppressed')} gaps")
    return {"ring_loss": ring_loss, "events_lost": unrouted,
            "gaps": len(gaps)}


def check_s1_active(doc, selected):
    """The S1 path carried the run: no key-operation feed was installed."""
    observed = doc.get("object_observations")
    _require(type(observed) is dict, "no object_observations section")
    status = observed.get("status")
    reason = observed.get("reason")
    _require(status == "unavailable" and reason == "journal_unavailable",
             f"object_observations status {status} reason {reason}, not "
             "the S1 marker unavailable/journal_unavailable")
    lane = selected["observation"]["semantic_capture"].get("status")
    _require(lane in S1_ACTIVE_STATUSES,
             f"semantic lane never active: status {lane}")
    return {"status": status, "reason": reason, "lane": lane}


def compare(ledger_paths, event_paths, inventory_path,
            min_rate=DEFAULT_MIN_RATE):
    """Run every gate; return the pass verdict or raise S1Error."""
    view = load_ledgers([str(path) for path in ledger_paths])
    events = []
    for path in event_paths:
        try:
            with open(path, encoding="utf-8") as stream:
                events.extend(read_events(stream))
        except (OSError, UnicodeError) as error:
            raise S1Error(f"unreadable events {path}") from error
    events.sort(key=lambda row: row["seq"])
    try:
        doc = read_inventory_file(inventory_path)
    except OSError as error:
        raise S1Error(f"unreadable inventory {inventory_path}") from error
    check_scope_and_clock(events, view["pid"])
    windows = check_windows(view, min_rate)
    selected = select_driver(doc, view["pid"])
    series = driver_series(events, selected["edge"])
    check_stream_matches_snapshot(series, selected["edge"])
    latency = record_latency(view, series)
    conservation = check_conservation(view, selected)
    loss = check_loss(selected, doc, events)
    active = check_s1_active(doc, selected)
    return {"verdict": "pass", "pid": view["pid"],
            "ledgers": view["ledgers"], "issued": view["issued"],
            "min_rate": min_rate, "windows": windows["windows"],
            "tail": windows["tail"],
            "full_windows": windows["full_windows"],
            "conservation": conservation, "loss": loss, "s1": active,
            "latency": latency}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", action="append", required=True,
                        help="driver ledger JSONL file; repeat per thread")
    parser.add_argument("--events", action="append", required=True,
                        help="observer --event-log file; repeat per rotation")
    parser.add_argument("--inventory", required=True,
                        help="observer inventory JSON snapshot (-o output)")
    parser.add_argument("--min-rate", type=int, default=DEFAULT_MIN_RATE,
                        help="minimum calls/s in every full 1 s window "
                             "(default %(default)s; 0 records without gating)")
    args = parser.parse_args(argv)
    if args.min_rate < 0:
        parser.error("--min-rate must be >= 0")
    try:
        result = compare(args.ledger, args.events, args.inventory,
                         args.min_rate)
    except S1Error as error:
        print(json.dumps({"verdict": "fail", "reason": str(error)},
                         sort_keys=True))
        print(f"s1-throughput refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print(json.dumps({"verdict": "fail",
                          "reason": "unreadable input"}, sort_keys=True))
        print("s1-throughput refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
