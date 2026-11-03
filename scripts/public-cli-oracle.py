#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge public-command evidence against independent fixture targets/counts.

TARGET records bind actual mapped device/inode and function file offsets.
The receipt supplies independently hashed and mapped provider identity before/after, launch
identity, readiness, and process exits. Counts remain provider totals; this
checker never claims system-wide per-caller attribution.
"""

import argparse
import json
from pathlib import Path
import re
import runpy
import stat
import sys

NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
COUNT_CELLS = {"profile-pid", "metrics-pid", "mt-exact", "system",
               "names-pid", "verdict-pid",
               "run-short", "run-cover", "run-ia32", "sigint",
               "profile-cgroup", "metrics-cgroup",
               "counter-counts-pid", "counter-timestamps-pid", "counter-latency-pid",
               "counter-counts-system", "counter-timestamps-system", "counter-latency-system",
               "select-endpoint-pid", "select-endpoint-system",
               "profile-pid-ia32"}
SMOKE_CELLS = {"trace-pid", "trace-cgroup"}
RUN_CELLS = {"run-short", "run-cover", "run-ia32"}
COUNTER_MODES = {
    "counter-counts-pid": "counts", "counter-timestamps-pid": "timestamps",
    "counter-latency-pid": "latency",
    "counter-counts-system": "counts", "counter-timestamps-system": "timestamps",
    "counter-latency-system": "latency",
    "select-endpoint-pid": "counts", "select-endpoint-system": "counts",
}
CELL_SCOPES = {
    "system": "system",
    "counter-counts-system": "system", "counter-timestamps-system": "system",
    "counter-latency-system": "system", "select-endpoint-system": "system",
    "profile-cgroup": "cgroup", "metrics-cgroup": "cgroup", "trace-cgroup": "cgroup",
}
METRICS_CELLS = {"metrics-pid", "metrics-cgroup",
                 "counter-counts-pid", "counter-timestamps-pid", "counter-latency-pid",
                 "counter-counts-system", "counter-timestamps-system", "counter-latency-system",
                 "select-endpoint-pid", "select-endpoint-system"}
LOSS_COUNTERS = ("event_loss", "in_flight_at_end", "start_insert_failures", "unmatched_returns",
                 "rv_update_failures", "cgroup_scope_failures", "abi_refusals", "malformed_records",
                 "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures",
                 "discovery_truncated", "task_uprobe_link_losses")
# Keep verdict policy in the existing canonical reader; it recomputes classes
# from published counters rather than trusting a report's claimed statuses.
VERDICT = runpy.run_path(str(Path(__file__).with_name("check-capture-evidence.py")))
# Trace loss identity lives in the system-scope measurer; reuse it so the two
# oracles cannot drift (gap §3 item 11).
TRACE = runpy.run_path(str(Path(__file__).with_name("system-scope-measure.py")))


class EvidenceError(Exception):
    pass


class Nonqualifying(Exception):
    pass


def require(condition, detail):
    if not condition:
        raise EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    require(stat.S_ISREG(path.stat().st_mode), "evidence must be a regular file")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence exceeds size limit")
    return path.read_text(encoding="utf-8")


def identity(value):
    require(isinstance(value, dict), "missing physical identity")
    dev = value.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
            "invalid device identity")
    require(integer(value.get("ino")) and value["ino"] > 0, "invalid inode identity")
    require(isinstance(value.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "missing provider hash")
    return (*dev, value["ino"], value["sha256"])


def provider_pin(value):
    physical = identity(value)
    anchor = value.get("mapping")
    require(isinstance(anchor, dict) and isinstance(anchor.get("dev"), list) and
            all(integer(x) for x in anchor["dev"]) and anchor["dev"] == list(physical[:2]) and
            type(anchor.get("ino")) is int and anchor["ino"] == physical[2] and
            type(anchor.get("file_offset")) is int and anchor["file_offset"] == 0 and
            integer(anchor.get("length")) and anchor["length"] > 0 and
            anchor.get("permissions") == "r--p", "missing or invalid independent mapping anchor")
    file = value.get("file_identity")
    require(isinstance(file, dict), "missing private FD identity")
    dev = file.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            type(file.get("ino")) is int and file["ino"] == physical[2] and
            integer(file.get("size")) and file["size"] >= anchor["length"] and
            all(type(file.get(key)) is int for key in ("mtime_ns", "ctime_ns")),
            "invalid private FD identity")
    return physical, (*dev, file["ino"], file["size"], file["mtime_ns"], file["ctime_ns"])


def ownership(row):
    """Validate the v3 exclusive ownership relation; absence has no authority."""
    require({"module", "module_ambiguous", "module_unresolved"} <= set(row),
            "missing required row ownership evidence")
    ambiguous, unresolved = row["module_ambiguous"], row["module_unresolved"]
    require(type(ambiguous) is bool and type(unresolved) is bool, "invalid row ownership flag")
    module = row["module"]
    if module is None:
        require(ambiguous != unresolved, "null module requires exactly one ownership reason")
        return None
    require(not ambiguous and not unresolved, "nonnull module contradicts ownership reason")
    require(isinstance(module, dict) and {"dev", "ino", "sha256"} <= set(module),
            "missing module ownership identity")
    dev = module["dev"]
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            integer(module["ino"]) and module["ino"] > 0, "invalid module ownership identity")
    if module["sha256"] is None:
        return None
    return identity(module)


def terminal(evidence, *, profile):
    # The schema/cell selects policy. Field omission cannot turn a profile
    # into the canonical reader's intentionally selection-blind metrics lane.
    profile_fields = VERDICT["PROFILE_V3_FIELDS"]
    if profile:
        require(profile_fields <= set(evidence), "missing required profile verdict authority")
        selection = evidence["interface_selection"]
        VERDICT["exact_keys"](selection, VERDICT["SELECTION_KEYS"], "interface_selection")
        require(type(selection["selection_truncated"]) is bool, "invalid selection truncation authority")
        for key in ("providers", "standard_exports", "inventory_surfaces", "tuples"):
            require(isinstance(selection[key], list), "invalid selection authority list: " + key)
        for row in selection["providers"]:
            require(isinstance(row, dict) and row.get("coverage") in VERDICT["SELECTION_COVERAGE"],
                    "invalid selection provider coverage")
        for row in selection["standard_exports"]:
            require(isinstance(row, dict) and row.get("status") in VERDICT["STANDARD_EXPORT_STATUS"],
                    "invalid selection export authority")
        for row in selection["tuples"]:
            require(isinstance(row, dict) and {"rv", "authority", "inventory_matches", "result"} <= set(row) and
                    integer(row.get("rv")) and
                    row.get("authority") in VERDICT["SELECTION_AUTHORITIES"] and
                    isinstance(row.get("inventory_matches"), list) and
                    (row.get("result") is None or isinstance(row["result"], dict)),
                    "invalid selection tuple verdict authority")
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            VERDICT["uint"](evidence[key], VERDICT["U64_MAX"], key)
    else:
        require(profile_fields.isdisjoint(evidence), "metrics contains profile-only verdict authority")
    for key in (*VERDICT["COUNTERS"], "slots", "semantic_unverified_slots",
                "unprotected_live_windows", "module_unresolved_slots", "pause_partial", "vendor_interfaces"):
        require(integer(evidence.get(key)), "invalid or missing verdict counter: " + key)
    for key in ("drain_proven", "provider_changed", "templates_truncated"):
        require(type(evidence.get(key)) is bool, "invalid or missing verdict authority: " + key)
    scheduling = evidence.get("scheduling", {})
    require(type(scheduling.get("terminal_drain_truncated")) is bool and
            integer(scheduling.get("sink_dropped_bytes")), "invalid verdict scheduling authority")
    loader = evidence.get("loader_discovery", {})
    for group, keys in VERDICT["LOADER_DISCOVERY_GROUPS"].items():
        require(isinstance(loader.get(group), dict) and all(integer(loader[group].get(key)) for key in keys),
                "invalid verdict loader authority: " + group)
    for key in VERDICT["LOADER_DISCOVERY_COUNTERS"]:
        require(integer(loader.get(key)), "invalid verdict loader counter: " + key)
    VERDICT["exact_stop_quiescence"](evidence)
    VERDICT["exact_verdict_classes"](evidence)
    require(evidence.get("completeness") == VERDICT["expected_terminal_completeness"](evidence),
            "completeness conflicts with terminal gap and settlement evidence")


def fixture(text, receipt, cell):
    targets, ledgers, ready = [], [], []
    for line in text.splitlines():
        if line.startswith("TARGET "):
            require(not ready and not ledgers, "fixture target emitted after readiness or ledger")
            targets.append(parse(line[7:]))
        elif line.startswith("LEDGER "):
            require(len(ready) == 1, "fixture ledger emitted before workload READY")
            ledgers.append(parse(line[7:]))
        elif line.startswith("READY "):
            match = re.fullmatch(r"READY pid=([0-9]+)", line)
            require(match is not None, "invalid workload READY")
            ready.append(int(match[1]))
    pid = receipt.get("launched_pid")
    require(integer(pid) and pid > 0 and ready == [pid] and receipt.get("ready_pid") == pid,
            "workload READY does not match launched PID")
    require(len(ledgers) == 1, "missing or duplicate complete LEDGER")
    ledger = ledgers[0]
    require(ledger.get("schema") == "p11scope/public-cli-ledger/v1" and
            ledger.get("pid") == pid and ledger.get("complete") is True,
            "invalid or incomplete fixture ledger")
    names = {NAMES[0]} if cell == "mt-exact" else set(NAMES)
    functions = ledger.get("functions")
    require(isinstance(functions, list), "missing ledger functions")
    expected = {}
    for row in functions:
        name = row.get("name")
        require(name in names and name not in expected, "duplicate or unexpected ledger function")
        attempts, successes = row.get("attempts"), row.get("successful")
        require(integer(attempts) and integer(successes) and attempts > 0 and attempts == successes,
                "workload had failed calls or no successful calls")
        if CELL_SCOPES.get(cell, "pid") == "system":
            require(attempts == 500, "strict SYSTEM requires 500 successful calls per target: " + name)
        expected[name] = attempts
    require(set(expected) == names, "missing fixture ledger function")
    physical, seen = {}, set()
    provider = identity(receipt.get("provider_before"))
    for row in targets:
        name, offset = row.get("name"), row.get("file_offset")
        require(name in names and name not in physical and integer(offset),
                "duplicate, missing or invalid fixture target")
        require(row.get("dev") == list(provider[:2]) and row.get("ino") == provider[2],
                "mapped fixture target differs from independently hashed provider")
        key = (*provider, offset)
        require(key not in seen, "fixture functions share an ambiguous target")
        physical[name] = key
        seen.add(key)
    require(set(physical) == names, "missing fixture target")
    return expected, physical


def common(receipt, cell):
    require(receipt.get("schema") == "p11scope/public-cli-receipt/v1" and
            receipt.get("cell") == cell, "receipt schema or cell mismatch")
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, "missing " + key)
    if cell not in RUN_CELLS:
        require(receipt.get("gate_released") is True, "gate was not safely released")
    for key in ("observer_exit", "workload_exit"):
        require(type(receipt.get(key)) is int and receipt[key] == 0, "nonzero or missing " + key)
    generation = receipt.get("generation")
    if generation is not None:
        require(integer(generation) and generation > 0 and
                type(receipt.get("ready_generation")) is int and
                receipt["ready_generation"] == generation, "workload generation changed")
    require(provider_pin(receipt.get("provider_before")) == provider_pin(receipt.get("provider_after")),
            "provider physical identity or hash changed")


def trace_judge(report_text, expected):
    try:
        parsed = TRACE["parse_trace_stream"](report_text.splitlines(keepends=True))
    except ValueError as error:
        raise EvidenceError("trace stream malformed: " + str(error))
    total = sum(expected.values())
    for name, want in expected.items():
        got = parsed["per_function"].get(name, 0)
        require(got == want, "trace per-function lines differ from ledger: %s has %d, want %d" % (name, got, want))
    require(parsed["call_lines_total"] >= total,
            "trace delivery/count short of independent ledger: %d lines vs %d ledger" % (
                parsed["call_lines_total"], total))
    require(parsed["truncated"] is False, "trace truncated; line stream is short")
    count = parsed["count_evidence"]
    evidence = parsed["evidence"]
    require(isinstance(evidence, dict), "trace EVIDENCE is not an object")
    for key in LOSS_COUNTERS:
        require(type(evidence.get(key)) is int and evidence[key] == 0, "trace loss or unknown " + key)
    observation = evidence.get("gap_classes", {}).get("observation", {})
    require(observation.get("status") == "exact" and observation.get("causes") == [],
            "trace lossy or unknown observation gap class")
    require(evidence.get("drain_proven") is True, "trace drain unproven")
    require(evidence.get("final_drain") is True, "trace final drain unproven")
    terminal = (evidence.get("completeness"), evidence.get("verdict_detail"))
    require(terminal in {("COMPLETE", "clean_proven"), ("PARTIAL", "attribution_only")},
            "trace terminal is not exact (COMPLETE/clean or PARTIAL/attribution-only): %r" % (terminal,))
    require(evidence.get("trace_truncated") is False, "trace truncated flag set")
    semantic_failures = evidence.get("semantic_capture_failures", 0)
    require(type(semantic_failures) is int, "trace semantic failures unknown")
    ok, note = TRACE["trace_crosscheck"](
        lost_total=parsed["lost_total"], event_loss=evidence.get("event_loss", 0),
        stats_returned=count.get("stats_returned", 0), raw_calls=count.get("raw_calls", 0),
        semantic_failures=semantic_failures, truncated=parsed["truncated"])
    require(ok, "trace loss identity broken: " + note)
    require(count.get("stats_returned") == parsed["call_lines_total"],
            "trace kernel aggregate differs from delivered lines: %r vs %d" % (
                count.get("stats_returned"), parsed["call_lines_total"]))
    require(count.get("raw_calls") == parsed["call_lines_total"],
            "trace reduced records differ from delivered lines: %r vs %d" % (
                count.get("raw_calls"), parsed["call_lines_total"]))
    require(count.get("stats_returned") >= total,
            "trace kernel aggregate short of ledger: %r vs %d" % (count.get("stats_returned"), total))
    require(parsed["lost_total"] == 0, "trace LOST reports loss")


def counter_judge(evidence, rows, cell):
    want_mode = COUNTER_MODES[cell]
    collection = evidence.get("counter_collection")
    require(isinstance(collection, dict), "missing counter_collection metadata")
    require(collection.get("mode") == want_mode,
            "counter mode differs from declared cell: %r vs %s" % (collection.get("mode"), want_mode))
    require(integer(collection.get("generation")) and collection["generation"] > 0,
            "invalid counter collection generation")
    window = collection.get("read_window")
    if window is not None:
        require(isinstance(window, dict) and integer(window.get("started_ns")) and
                integer(window.get("finished_ns")) and window["started_ns"] <= window["finished_ns"],
                "invalid counter read window")
    require(collection.get("status") == "fresh", "counter collection is not fresh")
    health = collection.get("health")
    require(isinstance(health, dict) and health.get("saturated") is False and
            health.get("contended") is False, "counter collection health is not OK")
    require(collection.get("discontinuity") is False, "counter collection discontinuity")
    require(collection.get("failure") is None, "counter collection failure")
    duration_ns = 25 * 10**9 if CELL_SCOPES.get(cell, "pid") == "system" else 12 * 10**9
    for row in rows:
        timing = row.get("latency_ns")
        calls = row.get("calls", 0)
        if want_mode == "counts":
            require(timing is None, "counts mode publishes timing")
        elif want_mode == "timestamps":
            require(isinstance(timing, dict), "timestamps mode lacks timing")
            require(timing.get("approximate") is False, "timestamps approximation flag wrong")
            require(timing.get("p50") is None and timing.get("p95") is None and timing.get("p99") is None,
                    "timestamps publishes percentiles")
            total, maximum = timing.get("total"), timing.get("max")
            if calls == 0:
                require(total == 0 and maximum == 0, "idle endpoint timing is not zero")
                continue
            require(integer(total) and total > 0 and integer(maximum) and maximum > 0,
                    "timestamps timing is not positive")
            require(maximum <= total, "timestamps max exceeds total")
            require(maximum < duration_ns and total < duration_ns * max(calls, 1),
                    "timestamps timing outside the capture window")
        else:
            require(isinstance(timing, dict), "latency mode lacks timing")
            require(timing.get("approximate") is True, "latency approximation flag wrong")
            total, maximum = timing.get("total"), timing.get("max")
            if calls == 0:
                require(total == 0 and maximum == 0, "idle endpoint timing is not zero")
                require(timing.get("p50") is None and timing.get("p95") is None and timing.get("p99") is None,
                        "idle endpoint publishes percentiles")
                continue
            require(integer(total) and total > 0 and integer(maximum) and maximum > 0,
                    "latency timing is not positive")
            require(maximum <= total, "latency max exceeds total")
            require(maximum < duration_ns and total < duration_ns * max(calls, 1),
                    "latency timing outside the capture window")
            for key in ("p50", "p95", "p99"):
                value = timing.get(key)
                require(integer(value) and value <= maximum,
                        "latency percentile missing or above max: " + key)


def select_judge(evidence, cell):
    envelope = evidence.get("selected_detail")
    require(isinstance(envelope, dict), "missing selected_detail envelope")
    selection = envelope.get("selection")
    require(isinstance(selection, dict), "missing selection record")
    require(selection.get("endpoint") == "C_Digest", "selection endpoint differs from declared cell")
    require(envelope.get("events") == [], "selection events are not empty")
    require(envelope.get("lineage") is None and envelope.get("aggregate") is None and
            envelope.get("detail") is None, "selection close products present without a closed window")
    if cell == "select-endpoint-pid":
        require(selection.get("refusal") == "bundle_unavailable",
                "selection refusal differs from today's named unavailability: %r" % selection.get("refusal"))
        require(integer(selection.get("slot")) and integer(selection.get("file_offset")),
                "resolved selection lacks slot or file offset")
        require(selection.get("names") == ["C_Digest"], "resolved selection names differ")
        require(set(selection) == {"endpoint", "slot", "file_offset", "names", "refusal"},
                "resolved selection carries unexpected keys")
    else:
        require(selection.get("refusal") == "promotion_scope_unsupported",
                "system selection refusal differs from named refusal: %r" % selection.get("refusal"))
        require("slot" not in selection and "file_offset" not in selection and "names" not in selection,
                "unresolved system selection carries resolution")
        require(set(selection) == {"endpoint", "refusal"},
                "unresolved selection carries unexpected keys")


def run_judge(evidence):
    require(evidence.get("pause") == "sigstop", "run pause is not confirmed sigstop")
    attempts, confirmed, partial = (evidence.get("pause_attempts"), evidence.get("pause_confirmed"),
                                    evidence.get("pause_partial"))
    require(integer(attempts) and attempts > 0, "run pause attempted nothing")
    require(confirmed == attempts and partial == 0,
            "run pause is not fully confirmed")
    require(evidence.get("child_still_running") is False, "run child still running")


def judge(report_text, ledger_text, receipt, cell, *, allow_pid_descendant_gaps=False):
    require(cell in COUNT_CELLS | SMOKE_CELLS, "undeclared cell")
    # Ruling CI-GAP-1: only the hosted-runner host system cell may disclose
    # short-lived descendant exits as runner noise, via an explicit flag.
    relaxed = cell == "system" and allow_pid_descendant_gaps is True
    common(receipt, cell)
    expected, physical = fixture(ledger_text, receipt, cell)
    if cell in SMOKE_CELLS:
        trace_judge(report_text, expected)
        raise Nonqualifying("trace delivery/count checked with loss identity; text lacks attributable physical targets")
    report = parse(report_text)
    schema = "p11scope/observed-profile/v3-metrics" if cell in METRICS_CELLS else "p11scope/observed-profile/v3"
    require(report.get("schema") == schema, "unsupported or wrong cell profile schema")
    mode = "metrics" if cell in METRICS_CELLS else "profile"
    require(report.get("lane") == mode and report.get("capture", {}).get("mode") == mode,
            "report lane or capture mode differs from declared cell/schema")
    scope = CELL_SCOPES.get(cell, "pid")
    require(receipt.get("scope") == scope and report.get("capture", {}).get("scope") == scope,
            "receipt or report capture scope differs from declared cell")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")
    for key in LOSS_COUNTERS:
        require(type(evidence.get(key)) is int and evidence[key] == 0, "loss or unknown " + key)
    observation = evidence.get("gap_classes", {}).get("observation", {})
    if relaxed:
        ok_exact = observation.get("status") == "exact" and observation.get("causes") == []
        ok_noise = (observation.get("status") == "lossy" and
                    observation.get("causes") == ["pid_descendant_gaps"])
        require(ok_exact or ok_noise, "lossy or unknown observation gap class")
    else:
        require(observation.get("status") == "exact" and observation.get("causes") == [],
                "lossy or unknown observation gap class")
    kernel = evidence.get("kernel_control", {})
    require(kernel.get("capture_halted") is False and kernel.get("owner_poison") == [] and
            kernel.get("root_affiliation_failures") == [], "kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        require(type(kernel.get(key)) is int and kernel[key] == 0, "kernel loss or unknown " + key)
    VERDICT["exact_attach_backend"](
        evidence.get("attach_backend"),
        evidence.get("attach_mechanisms") if mode == "profile" else None,
        report)
    terminal(evidence, profile=mode == "profile")
    if relaxed and evidence.get("pid_descendant_gaps", 0) > 0:
        # The pre-terminal observation pin plus terminal consistency already
        # prove the single observation class: any nonzero multi_rebuild_gaps
        # or other loss would have failed above, and PARTIAL/concrete_gap
        # follow necessarily. Attribution and semantics gaps are not gated
        # by the system counts cell -- strict mode discloses them via
        # PARTIAL without failing -- so relaxed mode must accept them too;
        # otherwise it would be stricter than strict. The only added ruling
        # requirement is the provider-subject check below. Hints are never
        # required; when present they must not place a gap subject in the
        # watched provider set.
        hints = evidence.get("gap_exe_hints")
        if hints is not None:
            require(hints.get("links_provider", 0) == 0,
                    "runner noise subject links the watched provider")
    if cell in RUN_CELLS:
        run_judge(evidence)
    if cell.startswith("select-endpoint-"):
        select_judge(evidence, cell)
    provider = identity(receipt["provider_before"])
    admitted = evidence.get("discovery")
    require(isinstance(admitted, list) and any(identity(row) == provider for row in admitted
            if isinstance(row, dict) and row.get("sha256") is not None), "owned provider not admitted")
    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    observed = {}
    unknown = []
    uncertainty = []
    for row in rows:
        ownership(row)
        require(integer(row.get("calls")), "invalid function count")
        require(isinstance(row.get("names"), list) and all(isinstance(name, str) for name in row["names"]),
                "invalid function names")
        for counter in ("errors", "in_flight", "pending_returns"):
            require(integer(row.get(counter)), "invalid function return counter: " + counter)
        target = row.get("target")
        require(isinstance(target, dict) and integer(target.get("file_offset")), "invalid physical target")
        obj = target.get("object")
        if obj is None:
            unknown.append(row)
            uncertainty.append("missing physical target identity; counts are unattributable")
            continue
        key = (*identity(obj), target["file_offset"])
        require(key not in observed, "duplicate observed physical target")
        observed[key] = row
    if receipt.get("count_domain") != "owned-provider":
        uncertainty.append("shared or unknown count domain; provider totals cannot prove per-caller coverage")
    # Definite contradictions and coverage failures have priority over uncertainty.
    # A null-object row at the expected offset can only keep identity unknown; it
    # never supplies a qualifying match and never excuses a known row's deficit.
    for name, key in physical.items():
        if key not in observed:
            possible = [row for row in unknown if row["target"]["file_offset"] == key[-1]]
            require(any(row["calls"] == expected[name] and name in row["names"] and
                        all(row[counter] == 0 for counter in ("errors", "in_flight", "pending_returns"))
                        for row in possible), "missing owned physical target: " + name)
            continue
        row = observed[key]
        require(type(row.get("calls")) is int and row["calls"] == expected[name],
                "owned target count differs from independent ledger: " + name)
        for counter in ("errors", "in_flight", "pending_returns"):
            require(type(row.get(counter)) is int and row[counter] == 0,
                    "owned target has failed or unsettled returns: " + name)
        require(isinstance(row.get("names"), list) and name in row["names"],
                "physical target semantic name differs: " + name)
        owner = ownership(row)
        if owner is None:
            uncertainty.append("shared, unresolved or unpinned module count domain: " + name)
        else:
            require(owner == provider, "owned target has a different publishing module: " + name)
    if cell in COUNTER_MODES:
        counter_judge(evidence, rows, cell)
    if uncertainty:
        raise Nonqualifying("; ".join(dict.fromkeys(uncertainty)))
    if cell == "sigint":
        require(evidence.get("drain_proven") is True, "SIGINT terminal drain unproven")
    if cell == "verdict-pid":
        require(evidence.get("completeness") in {"COMPLETE", "PARTIAL"} and
                evidence.get("verdict_detail") in {"clean_proven", "attribution_only", "clean_but_unproven"},
                "missing or inconsistent clean capture verdict")
        require((evidence["completeness"] == "COMPLETE") == (evidence["verdict_detail"] == "clean_proven"),
                "completeness conflicts with terminal verdict")
        return "verdict-consistency", "clean owned target verdict is consistent"
    if cell == "names-pid":
        return "semantic-names", "six independent physical targets carry expected semantic names"
    if relaxed:
        gaps = evidence.get("pid_descendant_gaps", 0)
        if gaps > 0:
            return "owned-provider-counts-with-runner-noise", (
                "owned physical-provider counts match independent successful ledger; "
                f"disclosed runner noise: pid_descendant_gaps={gaps}; "
                "per-caller attribution is not established")
        return "owned-provider-counts", (
            "owned physical-provider counts match independent successful ledger; "
            "disclosed runner noise: pid_descendant_gaps=0; "
            "per-caller attribution is not established")
    return "owned-provider-counts", ("owned physical-provider counts match independent successful ledger; "
                                     "per-caller attribution is not established")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("report", "ledger", "receipt", "cell"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--allow-pid-descendant-gaps", action="store_true",
                        help="CI-GAP-1: on the system cell only, disclose nonzero "
                             "pid_descendant_gaps as runner noise instead of failing")
    args = parser.parse_args(argv)
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        qualification, detail = judge(read(Path(args.report)), read(Path(args.ledger)),
                                      parse(read(Path(args.receipt))), args.cell,
                                      allow_pid_descendant_gaps=args.allow_pid_descendant_gaps)
        result.update({"pass": True, "qualification": qualification, "detail": detail})
        code = 0
    except Nonqualifying as error:
        result.update(qualification="nonqualifying", detail=str(error))
        code = 2
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError, AssertionError) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
