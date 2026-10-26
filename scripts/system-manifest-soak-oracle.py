#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verdict gates for the system--manifest soak vehicle (M13, cell 5.5).

Evaluates one evidence directory produced by
scripts/system-manifest-soak.sh: a long `inventory --system --manifest`
capture over owned SoftHSM workloads on a private provider copy, with a
1 Hz RSS/FD trace in the bench-inventory-native.sh sampler format.
Six fail-closed gates:

- finite_stop: the observer exited 0 on its own, the receipt window
  covers require_duration_s, and the report's observation window
  closed over at least one pass.
- workload_ledger: every workload finished (DONE status=ok) and its
  post-gate LEDGER call totals (main + teardown phases; setup runs
  before the attach gate by design) equal the report's per-caller
  edge entries on the owned provider copy exactly, with counted
  non-lossy coverage and no foreign caller on that copy.
- loss_accounting: no silent loss. The semantic stop line conserves
  (collected == joined + shed); every nonzero shed/refused/unrouted
  count and every budget refusal has a named gap; every gap carries a
  subject and a reason; gaps_suppressed == 0.
- resource_accounting: the trace spans the window without stalls, RSS
  stays within 256 MiB, and neither RSS nor FDs grow steadily
  (last-quartile median within margin of the first quartile, with the
  third quartile confirming a sustained rise rather than a spike).
- journal_disclosure: key operations stay honestly unavailable with
  the journal_unavailable reason (they arrive in 0.5.1).
- clean_exit: the sampler and every workload exited 0 (the observer
  outcome belongs to finite_stop so each gate fails alone).

A PASS verdict in live mode qualifies; a dry-run PASS proves wiring
only and never qualifies. Stdlib only. Unprivileged: this module never
launches the observer.
"""

import argparse
import json
import re
import sys
from pathlib import Path

RUN_SCHEMA = "p11scope/manifest-soak-run/v1"
VERDICT_SCHEMA = "p11scope/manifest-soak-verdict/v1"
GATES = ("finite_stop", "workload_ledger", "loss_accounting",
         "resource_accounting", "journal_disclosure", "clean_exit")
RSS_LIMIT_KB = 256 * 1024
RSS_GROWTH_MARGIN_KB = 32 * 1024
FD_GROWTH_MARGIN = 64
STOP_LINE_RE = re.compile(
    r"p11scope: semantic calls: collected (\d+), joined (\d+), "
    r"shed (\d+), bindings (\d+), refused (\d+)")


class OracleError(ValueError):
    """A gate input is missing or malformed; the gate fails, never passes."""


def require(condition, message):
    if not condition:
        raise OracleError(message)
    return condition


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise OracleError(f"cannot read {path}: {error}") from error
    except ValueError as error:
        raise OracleError(f"malformed JSON in {path}: {error}") from error


def strict_int(value, name):
    require(type(value) is int, f"{name} must be an integer")
    return value


def strict_str(value, name):
    require(isinstance(value, str) and value, f"{name} must be a nonempty string")
    return value


def median(sorted_values):
    count = len(sorted_values)
    require(count > 0, "median of no values")
    middle = count // 2
    if count % 2:
        return sorted_values[middle]
    return (sorted_values[middle - 1] + sorted_values[middle]) / 2


class Evidence:
    """Typed view of one soak evidence directory; missing files fail loads."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.run = load_json(self.directory / "run.json")
        require(isinstance(self.run, dict), "run.json must be a JSON object")
        require(self.run.get("schema") == RUN_SCHEMA, "run.json schema mismatch")
        self.artifacts = self.run.get("artifacts")
        require(isinstance(self.artifacts, dict), "run.json artifacts must be an object")
        self.report = load_json(self.directory / self.artifact("report"))
        require(isinstance(self.report, dict), "report.json must be a JSON object")

    def artifact(self, name):
        relative = strict_str(self.artifacts.get(name), f"artifact {name}")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                f"artifact {name} escapes the evidence directory")
        return relative

    def path(self, name):
        return self.directory / self.artifact(name)


def gate_finite_stop(evidence):
    run = evidence.run
    observer = run.get("observer")
    require(isinstance(observer, dict), "run.json observer must be an object")
    code = observer.get("exit")
    require(type(code) is int, "observer exit must be an integer")
    if observer.get("timed_out") is True:
        return False, "observer timed out (killed by the harness)"
    if code != 0 or observer.get("signal") is not None:
        return False, f"observer exit={code} signal={observer.get('signal')}"
    timing = run.get("timing")
    require(isinstance(timing, dict), "run.json timing must be an object")
    start = strict_int(timing.get("start_mono_ns"), "start_mono_ns")
    end = strict_int(timing.get("end_mono_ns"), "end_mono_ns")
    required = strict_int(run.get("require_duration_s"), "require_duration_s")
    actual_ns = end - start
    detail_window = f"window {actual_ns / 1e9:.3f}s against required {required}s"
    if actual_ns < required * 1_000_000_000:
        return False, detail_window
    observation = evidence.report.get("observation")
    require(isinstance(observation, dict), "report observation must be an object")
    started = strict_int(observation.get("started_ns"), "observation started_ns")
    ended = strict_int(observation.get("ended_ns"), "observation ended_ns")
    passes = strict_int(observation.get("passes"), "observation passes")
    if ended <= started or passes < 1:
        return False, "observation window never closed over a pass"
    return True, f"observer exit=0, {detail_window}, {passes} passes"


def split_log_fields(line):
    """Split a DONE/LEDGER row into fields; a token without '=' fails the gate."""
    fields = {}
    for part in line.split()[1:]:
        key_value = part.split("=", 1)
        if len(key_value) != 2:
            raise OracleError(f"malformed log token without '=': {part!r}")
        fields[key_value[0]] = key_value[1]
    return fields


def parse_workload_log(text, pid):
    """Split one ledger log into post-gate truth and setup counts.

    LEDGER rows aggregate per (module, fn, mech, phase); the eager
    workloads map and run setup before the attach gate opens, so only
    main + teardown phases are post-attach truth. A missing DONE or a
    row for another pid invalidates the log.
    """
    truth = 0
    setup = 0
    bad = 0
    done = None
    for line in text.splitlines():
        if line.startswith("DONE "):
            fields = split_log_fields(line)
            if fields.get("pid") == str(pid):
                done = fields.get("status")
            continue
        if not line.startswith("LEDGER "):
            continue
        fields = split_log_fields(line)
        require(fields.get("pid") == str(pid), "LEDGER row names another pid")
        count = strict_int(int(fields.get("n", "x")) if fields.get("n", "").isdigit()
                           else fields.get("n"), "LEDGER n")
        bad += int(fields.get("bad", "0")) if fields.get("bad", "0").isdigit() else 0
        require("phase" in fields and "module" in fields, "LEDGER row lacks phase/module")
        if fields["phase"] in ("main", "teardown"):
            truth += count
        elif fields["phase"] == "setup":
            setup += count
        else:
            raise OracleError(f"LEDGER row has an unexpected phase: {fields['phase']!r}")
    return truth, setup, bad, done


def gate_workload_ledger(evidence):
    run = evidence.run
    module_path = strict_str(run.get("provider_copy"), "provider_copy")
    workloads = run.get("workloads")
    require(isinstance(workloads, list) and workloads, "run.json workloads must be nonempty")
    report = evidence.report
    callers = report.get("callers")
    require(isinstance(callers, list), "report callers must be an array")
    pid_to_caller = {}
    for caller in callers:
        require(isinstance(caller, dict), "caller row must be an object")
        pid_to_caller[caller.get("pid")] = caller.get("id")
    modules = report.get("modules")
    require(isinstance(modules, list), "report modules must be an array")
    owned_ids = {module.get("id") for module in modules
                 if isinstance(module, dict) and module_path in (module.get("paths") or [])}
    if not owned_ids:
        return False, "the owned provider copy has no module row"
    edges = report.get("edges")
    require(isinstance(edges, list), "report edges must be an array")
    per_caller = []
    total_observed = 0
    for workload in workloads:
        require(isinstance(workload, dict), "workload row must be an object")
        pid = strict_int(workload.get("pid"), "workload pid")
        log_name = strict_str(workload.get("log"), "workload log")
        require(".." not in Path(log_name).parts and not Path(log_name).is_absolute(),
                "workload log escapes the evidence directory")
        try:
            text = (evidence.directory / log_name).read_text(encoding="utf-8")
        except OSError as error:
            raise OracleError(f"cannot read workload log {log_name}: {error}") from error
        truth, setup, bad, done = parse_workload_log(text, pid)
        if done != "ok":
            return False, f"workload pid={pid} never finished (DONE status={done})"
        caller_id = pid_to_caller.get(pid)
        if caller_id is None:
            return False, f"workload pid={pid} has no caller row"
        observed = 0
        for edge in edges:
            require(isinstance(edge, dict), "edge row must be an object")
            if edge.get("caller") != caller_id or edge.get("module") not in owned_ids:
                continue
            entries = edge.get("entries") or {}
            observed += strict_int(entries.get("count"), "edge entries count")
            coverage = edge.get("coverage") or {}
            if coverage.get("state") != "counted" or coverage.get("lossy") not in (False, None):
                return False, (f"workload pid={pid} edge coverage is not counted "
                               f"clean: {coverage!r}")
        total_observed += observed
        per_caller.append(f"pid={pid}: {observed} observed vs {truth} ledgered "
                          f"(setup {setup} pre-gate excluded, bad {bad})")
        if observed != truth:
            return False, "; ".join(per_caller)
    foreign = 0
    for edge in edges:
        if edge.get("module") in owned_ids and edge.get("caller") not in {
                pid_to_caller.get(workload.get("pid")) for workload in workloads}:
            foreign += strict_int((edge.get("entries") or {}).get("count"), "edge entries count")
    if foreign:
        return False, f"{foreign} owned-copy calls belong to no workload ({'; '.join(per_caller)})"
    return True, "; ".join(per_caller)


def gap_subjects(report):
    gaps = report.get("gaps")
    require(isinstance(gaps, list), "report gaps must be an array")
    subjects = []
    for gap in gaps:
        require(isinstance(gap, dict), "gap row must be an object")
        subject = gap.get("subject")
        reason = gap.get("reason")
        require(isinstance(subject, str) and subject, "every gap needs a subject")
        require(isinstance(reason, str) and reason, "every gap needs a reason")
        subjects.append(subject.lower())
    return subjects


def gate_loss_accounting(evidence):
    report = evidence.report
    subjects = gap_subjects(report)
    suppressed = report.get("gaps_suppressed")
    require(suppressed == 0, f"gaps_suppressed must be 0, got {suppressed!r}")
    budgets = report.get("budgets")
    require(isinstance(budgets, dict), "report budgets must be an object")
    refused_total = 0
    for resource in ("callers", "modules", "edges", "endpoints"):
        block = budgets.get(resource)
        require(isinstance(block, dict), f"budgets {resource} must be an object")
        refused_total += strict_int(block.get("refused"), f"budgets {resource} refused")
    counters = budgets.get("counters")
    require(isinstance(counters, dict), "budgets counters must be an object")
    observed_edges = strict_int(counters.get("observed_edges"), "counters observed_edges")
    saturated_edges = strict_int(counters.get("saturated_edges"), "counters saturated_edges")
    capture = (report.get("observation") or {}).get("semantic_capture")
    require(isinstance(capture, dict), "observation semantic_capture must be an object")
    unrouted = strict_int(capture.get("unrouted_returns"), "unrouted_returns")
    refused_endpoints = strict_int(capture.get("refused_endpoints"), "refused_endpoints")
    cuts = strict_int(capture.get("continuity_cuts"), "continuity_cuts")
    require(capture.get("final_drain") is True, "semantic capture never proved its final drain")
    try:
        stderr = evidence.path("stderr").read_text(encoding="utf-8")
    except OSError as error:
        raise OracleError(f"cannot read observer stderr: {error}") from error
    matches = STOP_LINE_RE.findall(stderr)
    if not matches:
        return False, "observer stderr has no semantic stop line"
    collected, joined, shed, bindings, refused = (int(group) for group in matches[-1])
    if collected != joined + shed:
        return False, (f"semantic counts do not conserve: collected={collected} "
                       f"joined={joined} shed={shed}")
    named = []

    def needs(count, words, label):
        if count and not any(word in subject for subject in subjects for word in words):
            return f"{label}={count} has no named gap"
        if count:
            named.append(f"{label}={count}")
        return None

    for missing in (
            needs(shed, ("semantic", "shed"), "shed"),
            needs(refused, ("admission", "refus"), "refused"),
            needs(unrouted, ("unrout",), "unrouted_returns"),
            needs(refused_total + refused_endpoints,
                  ("admission", "refus", "budget", "exhaust"),
                  "budget_refused")):
        if missing:
            return False, missing
    detail = (f"conserved collected={collected} joined={joined} shed={shed} "
              f"bindings={bindings} refused={refused}; unrouted={unrouted} "
              f"cuts={cuts} saturated_edges={saturated_edges} "
              f"observed_edges={observed_edges} budget_refused={refused_total}; "
              f"{len(subjects)} named gaps"
              + (f" ({', '.join(named)} disclosed)" if named else ", zero loss"))
    return True, detail


def gate_resource_accounting(evidence):
    run = evidence.run
    required = strict_int(run.get("require_duration_s"), "require_duration_s")
    try:
        lines = evidence.path("resources").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise OracleError(f"cannot read resources trace: {error}") from error
    rows = []
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 4 and all(part.isdigit() for part in parts),
                f"malformed resources row: {line!r}")
        rows.append(tuple(int(part) for part in parts))
    if len(rows) < 2:
        return False, "fewer than two resource samples"
    stamps = [row[0] for row in rows]
    if stamps != sorted(stamps):
        return False, "sample timestamps are not ordered"
    if stamps[0] > 10_000:
        return False, "sampler started more than 10 s after the observer"
    span_ms = stamps[-1] - stamps[0]
    floor_ms = max(0, required - 10) * 1000
    if span_ms < floor_ms:
        return False, f"trace spans {span_ms / 1000:.1f}s against a {floor_ms / 1000:.1f}s floor"
    worst_gap = max(b - a for a, b in zip(stamps, stamps[1:]))
    if worst_gap > 30_000:
        return False, f"sampler stalled for {worst_gap / 1000:.1f}s mid-window"
    rss = [row[1] for row in rows]
    hwm = [row[2] for row in rows]
    fds = [row[3] for row in rows]
    rss_max = max(rss)
    if rss_max > RSS_LIMIT_KB:
        return False, f"rss_max {rss_max} KiB exceeds the 256 MiB bound"
    growth = growth_check(rss, RSS_GROWTH_MARGIN_KB, "RSS")
    if growth:
        return False, growth
    growth = growth_check(fds, FD_GROWTH_MARGIN, "FDs")
    if growth:
        return False, growth
    return True, (f"{len(rows)} samples spanning {span_ms / 1000:.1f}s, worst gap "
                  f"{worst_gap / 1000:.1f}s; rss_max={rss_max} hwm_max={max(hwm)} "
                  f"KiB fds_max={max(fds)}")


def growth_check(series, margin, label):
    """Steady-growth veto: the last quartile must stay within margin of the
    first, with the third quartile confirming a sustained rise (a lone
    spike is bounded, not growth). Margins are absolute-or-quarter."""
    if len(series) < 8:
        return None
    quarter = len(series) // 4
    first = median(sorted(series[:quarter]))
    third = median(sorted(series[2 * quarter:3 * quarter]))
    last = median(sorted(series[3 * quarter:]))
    allowed = max(margin, first / 4)
    if last > first + allowed and third > first + allowed / 2:
        return (f"{label} grows steadily: quartile medians first={first:.0f} "
                f"third={third:.0f} last={last:.0f} (margin {allowed:.0f})")
    return None


def gate_journal_disclosure(evidence):
    observations = evidence.report.get("object_observations")
    require(isinstance(observations, dict), "report object_observations must be an object")
    status = observations.get("status")
    reason = observations.get("reason")
    if status != "unavailable" or reason != "journal_unavailable":
        return False, f"object_observations is {status}/{reason}, not unavailable/journal_unavailable"
    return True, "key operations unavailable/journal_unavailable (0.5.1 scope)"


def gate_clean_exit(evidence):
    run = evidence.run
    sampler = run.get("sampler")
    require(isinstance(sampler, dict), "run.json sampler must be an object")
    if sampler.get("exit") != 0 or sampler.get("signal") is not None:
        return False, (f"sampler exit={sampler.get('exit')} "
                       f"signal={sampler.get('signal')}")
    workloads = run.get("workloads")
    require(isinstance(workloads, list) and workloads, "run.json workloads must be nonempty")
    for workload in workloads:
        code = workload.get("exit")
        require(type(code) is int, "workload exit must be an integer")
        if code != 0:
            return False, f"workload pid={workload.get('pid')} exit={code}"
    return True, "sampler and every workload exited 0"


GATE_FUNCTIONS = {
    "finite_stop": gate_finite_stop,
    "workload_ledger": gate_workload_ledger,
    "loss_accounting": gate_loss_accounting,
    "resource_accounting": gate_resource_accounting,
    "journal_disclosure": gate_journal_disclosure,
    "clean_exit": gate_clean_exit,
}


def evaluate(directory):
    """Run every gate; malformed evidence fails the gate that reads it."""
    try:
        evidence = Evidence(directory)
    except (OracleError, OSError, AttributeError) as error:
        gates = {name: {"pass": False, "detail": f"evidence load failed: {error}"}
                 for name in GATES}
        # A hang still names its cell: run.json loads even when the
        # report it points at was never written.
        identity: dict = {"cell_id": None, "mode": None,
                          "require_duration_s": None, "window_s": None}
        try:
            run = json.loads((Path(directory) / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            run = None
        if isinstance(run, dict):
            identity["cell_id"] = run.get("cell_id")
            identity["mode"] = run.get("mode")
            identity["require_duration_s"] = run.get("require_duration_s")
            timing = run.get("timing")
            if isinstance(timing, dict):
                start, end = timing.get("start_mono_ns"), timing.get("end_mono_ns")
                if type(start) is int and type(end) is int:
                    identity["window_s"] = (end - start) / 1e9
        return {"schema": VERDICT_SCHEMA, "verdict": "FAIL", "qualifying": False,
                "gates": gates, "evidence_dir": str(Path(directory)), **identity}
    gates = {}
    for name in GATES:
        try:
            passed, detail = GATE_FUNCTIONS[name](evidence)
            gates[name] = {"pass": bool(passed), "detail": str(detail)}
        except (OracleError, AttributeError) as error:
            gates[name] = {"pass": False, "detail": f"invalid evidence: {error}"}
    timing = evidence.run.get("timing")
    if not isinstance(timing, dict):
        timing = {}
    start, end = timing.get("start_mono_ns"), timing.get("end_mono_ns")
    window_s = (end - start) / 1e9 if type(start) is int and type(end) is int else None
    verdict = "PASS" if all(gate["pass"] for gate in gates.values()) else "FAIL"
    return {"schema": VERDICT_SCHEMA, "cell_id": evidence.run.get("cell_id"),
            "mode": evidence.run.get("mode"), "verdict": verdict,
            "qualifying": verdict == "PASS" and evidence.run.get("mode") == "live",
            "require_duration_s": evidence.run.get("require_duration_s"),
            "window_s": window_s, "gates": gates,
            "evidence_dir": str(evidence.directory)}


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--out-verdict", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verdict = evaluate(args.evidence_dir)
        args.out_verdict.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
        if verdict["verdict"] != "PASS":
            print(f"manifest soak {verdict['cell_id']}: FAIL", flush=True)
            for name in GATES:
                gate = verdict["gates"][name]
                if not gate["pass"]:
                    print(f"  RED {name}: {gate['detail']}", flush=True)
            return 1
        print(f"manifest soak {verdict['cell_id']}: PASS "
              f"(qualifying={verdict['qualifying']})", flush=True)
        return 0
    except (OracleError, OSError) as error:
        print(f"manifest soak oracle refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
