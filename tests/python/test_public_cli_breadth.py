# SPDX-License-Identifier: GPL-3.0-or-later
"""Public CLI breadth oracles: exact run, cgroup, counter, select, ia32, trace loss.

Covers WP-4 new cells and strengthened oracles. All expectations are
independent: ledgers are synthetic, provider identity is pinned, and trace
streams are constructed to satisfy the loss identity from
system-scope-measure.py.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/public-cli-oracle.py"

NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
OWNED = {"dev": [8, 1], "ino": 71, "sha256": "a" * 64}
FOREIGN = {"dev": [8, 1], "ino": 72, "sha256": "b" * 64}
LOSS_COUNTERS = ("start_insert_failures", "unmatched_returns", "rv_update_failures",
                 "cgroup_scope_failures", "abi_refusals", "malformed_records",
                 "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures",
                 "discovery_truncated", "task_uprobe_link_losses")
VERDICT_COUNTERS = (
    "semantic_capture_failures", "unregistered_mechanisms", "template_tail_failures",
    "process_tracking_fallbacks", "process_tracking_failures", "process_tracking_evictions",
    "state_reconciliations", "session_cancel_ambiguities", "session_cancel_unknown_flags",
    "operation_state_imports", "auth_state_ambiguities", "async_target_failures", "async_orphans",
    "async_duplicates", "async_evictions", "fork_state_ambiguities", "semantic_state_drops",
    "semantic_history_drops", "pending_at_end", "orphan_ops", "unmatched_closes",
    "shape_decode_failures", "shape_decode_total_failures", "discovery_conflicts",
    "discovery_uncorroborated", "module_ambiguous", "semantic_unverified_slots",
    "module_unresolved_slots", "unprotected_live_windows", "pause_partial", "pause_unavailable",
    "unpublished_mechanisms", "vendor_interfaces")
PROFILE_FIELDS = ("interface_selection", "attach_mechanisms",
                  "pid_descendant_gaps", "multi_rebuild_gaps")


def provider_pin():
    return dict(OWNED,
                file_identity={"dev": [0, 38], "ino": 71, "size": 8192,
                               "mtime_ns": 123, "ctime_ns": 456},
                mapping={"dev": [8, 1], "ino": 71, "file_offset": 0,
                         "length": 4096, "permissions": "r--p"})


def inputs(*, metrics=False, scope="pid", calls=None, cell="profile-pid"):
    if calls is None:
        calls = 500 if scope == "system" else 7
    targets = [{"name": name, "dev": [8, 1], "ino": 71,
                "file_offset": 4096 + i * 16} for i, name in enumerate(NAMES)]
    report = {"schema": "p11scope/observed-profile/v3",
              "lane": "profile", "capture": {"scope": scope, "mode": "profile"},
              "functions": [{"names": [name], "calls": calls, "errors": 0, "in_flight": 0, "pending_returns": 0,
                             "module": dict(OWNED), "module_ambiguous": False, "module_unresolved": False,
                             "target": {"object": dict(OWNED),
                                        "file_offset": 4096 + i * 16}}
                            for i, name in enumerate(NAMES)],
              "evidence": {"completeness": "COMPLETE", "verdict_detail": "clean_proven",
                           "in_flight_at_end": 0, "event_loss": 0,
                           "discovery": [dict(OWNED, path="/owned.so", tables=[{}])],
                           "modules_skipped": []}}
    report["evidence"].update({key: 0 for key in LOSS_COUNTERS + VERDICT_COUNTERS})
    report["evidence"].update(
        slots=6, scan_unavailable=None, attach_failures=[], skipped=[], surfaces=[], aliased=[],
        interface_list="absent", provider_changed=False, templates_truncated=False,
        pause="none", pause_attempts=0, pause_confirmed=0,
        scheduling={"terminal_drain_truncated": False, "sink_dropped_bytes": 0},
        loader_discovery={"strategies": {"debug_state_every_hit": 0, "dlopen_return": 0, "unavailable": 0},
                          "dlopen_timing": {"qualified_pre_constructor": 0, "known_pre_relocation": 0,
                                            "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_timing": {"qualified_pre_constructor": 0, "known_pre_relocation": 0,
                                                 "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_capture": {"eligible": 0, "none": 0, "pause_protected": 0},
                          "state_read_failures": 0, "hits": 0},
        pid_namespace={"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
        drain_proven=True, stop_quiescence={"state": "proven", "post_q_events": False, "post_q_discovery": False})
    report["evidence"]["gap_classes"] = {
        "observation": {"status": "exact", "causes": []},
        "attribution": {"status": "attested", "causes": []},
        "semantics": {"status": "complete", "causes": []},
        "open_calls": 0, "settlement": "proven", "stdout_data_sink": False}
    report["evidence"]["kernel_control"] = {
        "capture_halted": False, "owner_poison": [], "owner_admission_failures": 0,
        "identity_unavailable": 0, "identity_budget_exhausted": False,
        "root_affiliation_failures": []}
    report["evidence"].update(
        interface_selection={"selection_truncated": False, "providers": [],
                             "standard_exports": [], "inventory_surfaces": [], "tuples": []},
        attach_mechanisms=["per-offset"],
        attach_backend={"selection": "singles", "fallback": None,
                        "scope_filter": None if scope in ("system", "cgroup") else "perf-task+bpf"},
        pid_descendant_gaps=0, multi_rebuild_gaps=0)
    if metrics:
        report["schema"] = "p11scope/observed-profile/v3-metrics"
        report["lane"] = report["capture"]["mode"] = "metrics"
        for key in PROFILE_FIELDS:
            del report["evidence"][key]
    ledger = ["TARGET " + json.dumps(row) for row in targets]
    ledger += ["READY pid=123", "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": 123, "complete": True,
        "functions": [{"name": name, "attempts": calls, "successful": calls}
                      for name in NAMES]})]
    receipt = {"schema": "p11scope/public-cli-receipt/v1", "cell": cell,
               "scope": scope, "count_domain": "owned-provider",
               "launched_pid": 123, "generation": 456,
               "ready_pid": 123, "ready_generation": 456,
               "workload_ready": True, "capture_ready": True, "gate_released": True,
               "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
               "provider_before": provider_pin(), "provider_after": provider_pin()}
    return report, ledger, receipt


def trace_stream(*, calls_per_function=7, lost=0, event_loss=0, semantic_failures=0,
                 truncated=False, stats_returned=None, raw_calls=None):
    total = calls_per_function * len(NAMES)
    if stats_returned is None:
        stats_returned = total
    if raw_calls is None:
        raw_calls = total - event_loss if semantic_failures == 0 else total - event_loss
    lines = ["CAPTURE privacy=allowlisted"]
    seq = 0
    for name in NAMES:
        for _ in range(calls_per_function):
            seq += 1
            lines.append(f"00:00:{seq // 60:02d}.{seq % 60:06d} pid 123 tid 456 {name} -> CKR_OK 1.0us".replace("->", "\u2192"))
    if lost:
        lines.append(f"LOST {lost} events")
    if truncated:
        lines.append("TRUNCATED at 100 events")
    lines.append("COUNT_EVIDENCE " + json.dumps({
        "stats_entered": stats_returned, "stats_returned": stats_returned, "raw_calls": raw_calls}))
    _, _, receipt_evidence = inputs_for_evidence()
    ev = receipt_evidence
    ev["event_loss"] = event_loss
    ev["semantic_capture_failures"] = semantic_failures
    ev["trace_truncated"] = truncated
    ev["final_drain"] = True
    if event_loss == 0 and not truncated:
        ev["completeness"] = "COMPLETE"
        ev["verdict_detail"] = "clean_proven"
    else:
        ev["completeness"] = "PARTIAL"
        ev["verdict_detail"] = "attribution_only"
        ev["gap_classes"]["attribution"] = {"status": "withheld", "causes": ["trace_text"]}
    lines.append("EVIDENCE " + json.dumps(ev))
    return "\n".join(lines) + "\n"


def inputs_for_evidence():
    report, ledger, receipt = inputs()
    return report, ledger, report["evidence"]


MT_NAMES = ("C_GenerateRandom", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo")
MT_BOGUS_RV = 0xB3  # CKR_SESSION_HANDLE_INVALID from a bogus session handle


def mt_rv_key(rv):
    return "0x%016x" % rv


def mt_row_ledger(name, calls, errors):
    row = {"name": name, "attempts": calls, "successful": calls - errors,
           "rv_counts": {mt_rv_key(0): calls - errors}}
    if errors:
        row["rv_counts"][mt_rv_key(MT_BOGUS_RV)] = errors
    return row


def inputs_mt(*, metrics=False, scope="pid", calls=24, errors=0, cell):
    targets = [{"name": name, "dev": [8, 1], "ino": 71,
                "file_offset": 4096 + i * 16} for i, name in enumerate(MT_NAMES)]
    report = {"schema": "p11scope/observed-profile/v3",
              "lane": "profile", "capture": {"scope": scope, "mode": "profile"},
              "functions": [{"names": [name], "calls": calls,
                             "errors": errors if i == 0 else 0,
                             "in_flight": 0, "pending_returns": 0,
                             "module": dict(OWNED), "module_ambiguous": False, "module_unresolved": False,
                             "rv_counts": dict(mt_row_ledger(name, calls, errors if i == 0 else 0)["rv_counts"]),
                             "target": {"object": dict(OWNED),
                                        "file_offset": 4096 + i * 16}}
                            for i, name in enumerate(MT_NAMES)],
              "evidence": {"completeness": "COMPLETE", "verdict_detail": "clean_proven",
                           "in_flight_at_end": 0, "event_loss": 0,
                           "discovery": [dict(OWNED, path="/owned.so", tables=[{}])],
                           "modules_skipped": []}}
    report["evidence"].update({key: 0 for key in LOSS_COUNTERS + VERDICT_COUNTERS})
    report["evidence"].update(
        slots=8, scan_unavailable=None, attach_failures=[], skipped=[], surfaces=[], aliased=[],
        interface_list="absent", provider_changed=False, templates_truncated=False,
        pause="none", pause_attempts=0, pause_confirmed=0,
        scheduling={"terminal_drain_truncated": False, "sink_dropped_bytes": 0},
        loader_discovery={"strategies": {"debug_state_every_hit": 0, "dlopen_return": 0, "unavailable": 0},
                          "dlopen_timing": {"qualified_pre_constructor": 0, "known_pre_relocation": 0,
                                            "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_timing": {"qualified_pre_constructor": 0, "known_pre_relocation": 0,
                                                 "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_capture": {"eligible": 0, "none": 0, "pause_protected": 0},
                          "state_read_failures": 0, "hits": 0},
        pid_namespace={"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
        drain_proven=True, stop_quiescence={"state": "proven", "post_q_events": False, "post_q_discovery": False})
    report["evidence"]["gap_classes"] = {
        "observation": {"status": "exact", "causes": []},
        "attribution": {"status": "attested", "causes": []},
        "semantics": {"status": "complete", "causes": []},
        "open_calls": 0, "settlement": "proven", "stdout_data_sink": False}
    report["evidence"]["kernel_control"] = {
        "capture_halted": False, "owner_poison": [], "owner_admission_failures": 0,
        "identity_unavailable": 0, "identity_budget_exhausted": False,
        "root_affiliation_failures": []}
    report["evidence"].update(
        interface_selection={"selection_truncated": False, "providers": [],
                             "standard_exports": [], "inventory_surfaces": [], "tuples": []},
        attach_mechanisms=["per-offset"],
        attach_backend={"selection": "singles", "fallback": None,
                        "scope_filter": None if scope == "system" else "perf-task+bpf"},
        pid_descendant_gaps=0, multi_rebuild_gaps=0)
    if metrics:
        report["schema"] = "p11scope/observed-profile/v3-metrics"
        report["lane"] = report["capture"]["mode"] = "metrics"
        for key in PROFILE_FIELDS:
            del report["evidence"][key]
    ledger = ["TARGET " + json.dumps(row) for row in targets]
    ledger += ["READY pid=123", "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v2", "pid": 123, "complete": True,
        "functions": [mt_row_ledger(name, calls, errors if i == 0 else 0)
                      for i, name in enumerate(MT_NAMES)]})]
    receipt = {"schema": "p11scope/public-cli-receipt/v1", "cell": cell,
               "scope": scope, "count_domain": "owned-provider",
               "launched_pid": 123, "generation": 456,
               "ready_pid": 123, "ready_generation": 456,
               "workload_ready": True, "capture_ready": True, "gate_released": True,
               "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
               "provider_before": provider_pin(), "provider_after": provider_pin()}
    return report, ledger, receipt


def mutate_mt_ledger(ledger, index, *, attempts=None, successful=None, rv_counts=None):
    payload = json.loads(ledger[-1][len("LEDGER "):])
    row = payload["functions"][index]
    if attempts is not None:
        row["attempts"] = attempts
    if successful is not None:
        row["successful"] = successful
    if rv_counts is not None:
        row["rv_counts"] = rv_counts
    ledger[-1] = "LEDGER " + json.dumps(payload)


def trace_stream_mt(*, calls_per_function=8, lost=0, event_loss=0, semantic_failures=0,
                    truncated=False, stats_returned=None, raw_calls=None):
    total = calls_per_function * len(MT_NAMES)
    if stats_returned is None:
        stats_returned = total
    if raw_calls is None:
        raw_calls = total - event_loss
    lines = ["CAPTURE privacy=allowlisted"]
    seq = 0
    for name in MT_NAMES:
        for _ in range(calls_per_function):
            seq += 1
            lines.append(f"00:00:{seq // 60:02d}.{seq % 60:06d} pid 123 tid 456 {name} \u2192 CKR_OK 1.0us")
    if lost:
        lines.append(f"LOST {lost} events")
    if truncated:
        lines.append("TRUNCATED at 100 events")
    lines.append("COUNT_EVIDENCE " + json.dumps({
        "stats_entered": stats_returned, "stats_returned": stats_returned, "raw_calls": raw_calls}))
    _, _, ev = inputs_for_evidence()
    ev["event_loss"] = event_loss
    ev["semantic_capture_failures"] = semantic_failures
    ev["trace_truncated"] = truncated
    ev["final_drain"] = True
    if event_loss == 0 and not truncated:
        ev["completeness"] = "COMPLETE"
        ev["verdict_detail"] = "clean_proven"
    else:
        ev["completeness"] = "PARTIAL"
        ev["verdict_detail"] = "attribution_only"
        ev["gap_classes"]["attribution"] = {"status": "withheld", "causes": ["trace_text"]}
    lines.append("EVIDENCE " + json.dumps(ev))
    return "\n".join(lines) + "\n"


class BreadthTests(unittest.TestCase):
    def run_case(self, mutate=None, *, cell, want=0, report_text=None):
        metrics = cell in {"metrics-pid", "metrics-cgroup"} or cell.startswith("counter-") or cell.startswith("select-endpoint-")
        scope = "system" if cell.endswith("-system") or cell == "system" else ("cgroup" if "cgroup" in cell else "pid")
        # Run-tree (v0.7.0): owned runs capture at cgroup scope; sigint
        # still attaches to one PID (profile --pid, not run).
        if cell in {"run-short", "run-cover", "run-ia32"}:
            scope = "cgroup"
        if cell in {"run-short", "run-cover", "run-ia32", "sigint"}:
            metrics = False
        report, ledger, receipt = inputs(metrics=metrics, scope=scope, cell=cell)
        if cell in {"run-short", "run-cover", "run-ia32"}:
            report["evidence"].update(pause="sigstop", pause_attempts=1, pause_confirmed=1, pause_partial=0)
            report["evidence"]["child_still_running"] = False
        if cell.startswith("counter-") or cell.startswith("select-endpoint-"):
            mode = "counts"
            if "timestamps" in cell:
                mode = "timestamps"
            elif "latency" in cell:
                mode = "latency"
            report["evidence"]["counter_collection"] = {
                "mode": mode, "generation": 1,
                "read_window": {"started_ns": 100, "finished_ns": 200},
                "status": "fresh", "health": {"saturated": False, "contended": False},
                "discontinuity": False, "failure": None}
            for row in report["functions"]:
                if mode == "counts":
                    row["latency_ns"] = None
                elif mode == "timestamps":
                    row["latency_ns"] = {"approximate": False, "p50": None, "p95": None, "p99": None,
                                         "total": 1000, "max": 100}
                else:
                    row["latency_ns"] = {"approximate": True, "p50": 50, "p95": 90, "p99": 95,
                                         "total": 1000, "max": 100}
        if cell == "select-endpoint-pid":
            report["evidence"]["counter_collection"]["mode"] = "counts"
            for row in report["functions"]:
                row["latency_ns"] = None
            selected = {"slot": 2, "object": 0, "file_offset": 4096 + 2 * 16,
                        "entered": 7, "returned": 7, "errors": 0, "rv_counts": {"0": 7}}
            idle = {"slot": 5, "object": 0, "file_offset": 4096 + 5 * 16,
                    "entered": 0, "returned": 0, "errors": 0, "rv_counts": {}}
            report["evidence"]["selected_detail"] = {
                "selection": {"endpoint": "C_Digest", "slot": 2, "file_offset": 4096 + 2 * 16,
                              "names": ["C_Digest"]},
                "events": [],
                "detail": {"scope": "detail", "unit": "calls", "mode": "counts",
                           "detail_generation": 1, "mode_mixed": False,
                           "rows": [dict(selected)]},
                "aggregate": {"scope": "broad", "unit": "calls", "mode": "counts",
                              "seq_before": 1, "seq_after": 2, "mode_mixed": False,
                              "rows": [dict(selected), idle]}}
        if cell == "select-endpoint-system":
            report["evidence"]["counter_collection"]["mode"] = "counts"
            for row in report["functions"]:
                row["latency_ns"] = None
            report["evidence"]["selected_detail"] = {
                "selection": {"endpoint": "C_Digest", "refusal": "promotion_scope_unsupported"},
                "events": []}
        if mutate:
            mutate(report, ledger, receipt)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt)):
                paths[key] = tmp / key
                text = json.dumps(value)
                if report_text is not None and key == "report":
                    text = report_text
                paths[key].write_text(text)
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(ORACLE),
                                   "--cell", cell, *sum((["--" + key, str(path)]
                                                        for key, path in paths.items()), [])],
                                  capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], cell)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_run_short_exact_passes_with_confirmed_pause(self):
        self.run_case(cell="run-short")

    def test_run_short_pause_none_fails(self):
        self.run_case(lambda d, l, r: d["evidence"].update(pause="none", pause_attempts=0, pause_confirmed=0),
                      cell="run-short", want=1)

    def test_run_short_pause_partial_fails(self):
        def mutate(d, l, r):
            d["evidence"].update(pause="partial", pause_attempts=1, pause_confirmed=0, pause_partial=1,
                                 completeness="PARTIAL", verdict_detail="concrete_gap")
            d["evidence"]["gap_classes"]["observation"] = {"status": "lossy", "causes": ["pause_partial"]}
        self.run_case(mutate, cell="run-short", want=1)

    def test_run_short_count_drift_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=6),
                      cell="run-short", want=1)

    def test_run_cover_exact_passes(self):
        self.run_case(cell="run-cover")

    def test_run_ia32_exact_passes(self):
        self.run_case(cell="run-ia32")

    def test_sigint_exact_passes(self):
        self.run_case(cell="sigint")

    def test_sigint_partial_attribution_only_with_proven_drain_passes(self):
        def mutate(d, l, r):
            d["evidence"].update(completeness="PARTIAL", verdict_detail="attribution_only",
                                 semantic_unverified_slots=68)
            d["evidence"]["gap_classes"]["attribution"] = {"status": "withheld",
                                                           "causes": ["semantic_unverified_slots"]}
            d["evidence"]["gap_classes"]["semantics"] = {"status": "not_applicable", "causes": []}
        self.run_case(mutate, cell="sigint")

    def test_sigint_count_drift_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=6),
                      cell="sigint", want=1)

    def test_sigint_unproven_drain_fails(self):
        def mutate(d, l, r):
            d["evidence"].update(drain_proven=False, completeness="PARTIAL",
                                 verdict_detail="clean_but_unproven")
            d["evidence"]["stop_quiescence"]["state"] = "unproven"
            d["evidence"]["gap_classes"]["settlement"] = "unproven"
        self.run_case(mutate, cell="sigint", want=1)

    def test_sigint_lossy_observation_fails(self):
        self.run_case(lambda d, l, r: d["evidence"]["gap_classes"]["observation"].update(status="lossy", causes=["event_loss"]),
                      cell="sigint", want=1)

    def test_profile_cgroup_exact_passes(self):
        self.run_case(cell="profile-cgroup")

    def test_profile_cgroup_wrong_scope_fails(self):
        self.run_case(lambda d, l, r: d["capture"].update(scope="pid"),
                      cell="profile-cgroup", want=1)

    def test_profile_cgroup_count_drift_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=6),
                      cell="profile-cgroup", want=1)

    def test_metrics_cgroup_exact_passes(self):
        self.run_case(cell="metrics-cgroup")

    def test_counter_counts_pid_exact_passes(self):
        self.run_case(cell="counter-counts-pid")

    def test_counter_counts_pid_stale_collection_fails(self):
        def mutate(d, l, r):
            d["evidence"]["counter_collection"].update(status="stale", health=None, failure="topology")
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
            d["evidence"]["gap_classes"]["observation"] = {"status": "lossy", "causes": ["counter_collection"]}
        self.run_case(mutate, cell="counter-counts-pid", want=1)

    def test_counter_timestamps_pid_exact_passes(self):
        self.run_case(cell="counter-timestamps-pid")

    def test_counter_timestamps_pid_zero_timing_fails(self):
        def mutate(d, l, r):
            for row in d["functions"]:
                row["latency_ns"].update(total=0, max=0)
        self.run_case(mutate, cell="counter-timestamps-pid", want=1)

    def test_counter_latency_pid_exact_passes(self):
        self.run_case(cell="counter-latency-pid")

    def test_counter_latency_pid_missing_percentiles_fails(self):
        def mutate(d, l, r):
            for row in d["functions"]:
                row["latency_ns"].update(p50=None, p95=None, p99=None)
        self.run_case(mutate, cell="counter-latency-pid", want=1)

    def test_counter_counts_system_exact_passes(self):
        self.run_case(cell="counter-counts-system")

    def test_counter_timestamps_system_exact_passes(self):
        self.run_case(cell="counter-timestamps-system")

    def test_counter_latency_system_exact_passes(self):
        self.run_case(cell="counter-latency-system")

    def test_select_endpoint_pid_closed_window_exact_passes(self):
        result = self.run_case(cell="select-endpoint-pid")
        self.assertIn("owned-provider", result["qualification"])

    def test_select_endpoint_pid_refusal_fails(self):
        self.run_case(lambda d, l, r: d["evidence"]["selected_detail"]["selection"].update(refusal="bundle_unavailable"),
                      cell="select-endpoint-pid", want=1)

    def test_select_endpoint_pid_detail_drift_fails(self):
        def mutate(d, l, r):
            d["evidence"]["selected_detail"]["detail"]["rows"][0]["returned"] = 6
        self.run_case(mutate, cell="select-endpoint-pid", want=1)

    def test_select_endpoint_pid_missing_detail_fails(self):
        def mutate(d, l, r):
            del d["evidence"]["selected_detail"]["detail"]
        self.run_case(mutate, cell="select-endpoint-pid", want=1)

    def test_select_endpoint_pid_lineage_fails(self):
        def mutate(d, l, r):
            d["evidence"]["selected_detail"]["lineage"] = {"drift": None}
        self.run_case(mutate, cell="select-endpoint-pid", want=1)

    def test_select_endpoint_pid_aggregate_missing_slot_fails(self):
        def mutate(d, l, r):
            rows = d["evidence"]["selected_detail"]["aggregate"]["rows"]
            del rows[0]
        self.run_case(mutate, cell="select-endpoint-pid", want=1)

    def test_select_endpoint_pid_count_drift_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=6),
                      cell="select-endpoint-pid", want=1)

    def test_select_endpoint_system_refuses_scope(self):
        self.run_case(cell="select-endpoint-system")

    def test_select_endpoint_system_with_slot_fails(self):
        def mutate(d, l, r):
            d["evidence"]["selected_detail"]["selection"].update(slot=2, file_offset=4128, names=["C_Digest"])
        self.run_case(mutate, cell="select-endpoint-system", want=1)

    def test_profile_pid_ia32_exact_passes(self):
        self.run_case(cell="profile-pid-ia32")

    def test_trace_pid_loss_identity_passes_as_smoke(self):
        text = trace_stream(calls_per_function=7)
        self.run_case(cell="trace-pid", want=2, report_text=text)

    def test_trace_pid_partial_attribution_only_passes_as_smoke(self):
        text = trace_stream(calls_per_function=7)
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if line.startswith("EVIDENCE "):
                ev = json.loads(line[9:])
                ev["completeness"] = "PARTIAL"
                ev["verdict_detail"] = "attribution_only"
                ev["gap_classes"]["attribution"] = {"status": "withheld", "causes": ["trace_text"]}
                lines[i] = "EVIDENCE " + json.dumps(ev) + "\n"
        self.run_case(cell="trace-pid", want=2, report_text="".join(lines))

    def test_trace_pid_broken_loss_identity_fails(self):
        text = trace_stream(calls_per_function=7, event_loss=1, lost=0)
        self.run_case(cell="trace-pid", want=1, report_text=text)

    def test_trace_pid_wrong_line_count_fails(self):
        text = trace_stream(calls_per_function=6)
        self.run_case(cell="trace-pid", want=1, report_text=text)

    def test_trace_cgroup_loss_identity_passes_as_smoke(self):
        text = trace_stream(calls_per_function=7)
        self.run_case(cell="trace-cgroup", want=2, report_text=text)

    def test_trace_cgroup_broken_loss_identity_fails(self):
        text = trace_stream(calls_per_function=7, event_loss=1, lost=0)
        self.run_case(cell="trace-cgroup", want=1, report_text=text)


PROVIDER = r'''
#include <stdlib.h>
typedef unsigned long U;
U C_Initialize(void *a){(void)a;return 0;}
U C_Finalize(void *a){(void)a;return 0;}
U C_GetSlotList(unsigned char t,U *s,U *n){(void)t;s[0]=1;*n=1;return 0;}
U C_OpenSession(U a,U b,void *c,void*d,U*s){(void)a;(void)b;(void)c;(void)d;*s=1;return 0;}
U C_CloseSession(U s){(void)s;return 0;}
U C_Login(U s,U u,unsigned char*p,U n){(void)s;(void)u;(void)p;(void)n;return 0;}
U C_Logout(U s){(void)s;return 0;}
U C_GenerateRandom(U s,unsigned char*b,U n){(void)s;(void)b;(void)n;return 0;}
U C_DigestInit(U s,void*m){(void)s;(void)m;return 0;}
U C_Digest(U s,unsigned char*b,U n,unsigned char*o,U*l){(void)s;(void)b;(void)n;(void)o;*l=32;return 0;}
U C_FindObjectsInit(U s,void*t,U n){(void)s;(void)t;(void)n;return 0;}
U C_FindObjects(U s,U*o,U n,U*c){(void)s;(void)o;(void)n;*c=0;return 0;}
U C_FindObjectsFinal(U s){(void)s;return 0;}
struct { unsigned char version[8]; void *p[68]; } list={.version={2,40},.p={
 [0]=C_Initialize,[1]=C_Finalize,[4]=C_GetSlotList,[12]=C_OpenSession,
 [13]=C_CloseSession,[18]=C_Login,[19]=C_Logout,[26]=C_FindObjectsInit,
 [27]=C_FindObjects,[28]=C_FindObjectsFinal,[37]=C_DigestInit,[38]=C_Digest,[64]=C_GenerateRandom}};
U C_GetFunctionList(void**out){*out=&list;return 0;}
'''


PROVIDER_CONFLOG = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned long U;
U C_Initialize(void *a){(void)a;
 const char *f=getenv("P11SCOPE_CONFLOG");
 if(f){FILE *h=fopen(f,"a");if(h){const char *c=getenv("SOFTHSM2_CONF");
  fprintf(h,"%d %s\n",(int)getpid(),c?c:"(unset)");fclose(h);}}
 return 0;}
U C_Finalize(void *a){(void)a;return 0;}
U C_GetSlotList(unsigned char t,U *s,U *n){(void)t;s[0]=1;*n=1;return 0;}
U C_OpenSession(U a,U b,void *c,void*d,U*s){(void)a;(void)b;(void)c;(void)d;*s=1;return 0;}
U C_CloseSession(U s){(void)s;return 0;}
U C_Login(U s,U u,unsigned char*p,U n){(void)s;(void)u;(void)p;(void)n;return 0;}
U C_Logout(U s){(void)s;return 0;}
U C_GenerateRandom(U s,unsigned char*b,U n){(void)s;(void)b;(void)n;return 0;}
U C_DigestInit(U s,void*m){(void)s;(void)m;return 0;}
U C_Digest(U s,unsigned char*b,U n,unsigned char*o,U*l){(void)s;(void)b;(void)n;(void)o;*l=32;return 0;}
U C_FindObjectsInit(U s,void*t,U n){(void)s;(void)t;(void)n;return 0;}
U C_FindObjects(U s,U*o,U n,U*c){(void)s;(void)o;(void)n;*c=0;return 0;}
U C_FindObjectsFinal(U s){(void)s;return 0;}
struct { unsigned char version[8]; void *p[68]; } list={.version={2,40},.p={
 [0]=C_Initialize,[1]=C_Finalize,[4]=C_GetSlotList,[12]=C_OpenSession,
 [13]=C_CloseSession,[18]=C_Login,[19]=C_Logout,[26]=C_FindObjectsInit,
 [27]=C_FindObjects,[28]=C_FindObjectsFinal,[37]=C_DigestInit,[38]=C_Digest,[64]=C_GenerateRandom}};
U C_GetFunctionList(void**out){*out=&list;return 0;}
'''


class ForkFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.storage.name)
        source = cls.tmp / "provider.c"; source.write_text(PROVIDER)
        cls.module = cls.tmp / "provider.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(cls.module), str(source)], check=True)
        subprocess.run(["gcc", "-O1", "-o", str(cls.tmp / "cgroup-fork"),
                        str(ROOT / "tests/fixtures/public-cli/cgroup-fork.c"), "-ldl"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def test_fork_combined_ledger_and_child_line(self):
        gate = self.tmp / "gate"
        gate.touch()
        proc = subprocess.Popen([str(self.tmp / "cgroup-fork"), str(self.module), "3", "0", str(gate)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            stdout, _ = proc.communicate(timeout=5)
        lines = stdout.splitlines()
        targets = [json.loads(line[7:]) for line in lines if line.startswith("TARGET ")]
        self.assertEqual({row["name"] for row in targets}, set(NAMES))
        ready = [line for line in lines if line.startswith("READY pid=")]
        self.assertEqual(len(ready), 1)
        child = [line for line in lines if line.startswith("CHILD pid=")]
        self.assertEqual(len(child), 1)
        self.assertNotEqual(ready[0], child[0].replace("CHILD", "READY"))
        ledgers = [json.loads(line[7:]) for line in lines if line.startswith("LEDGER ")]
        self.assertEqual(len(ledgers), 1)
        self.assertTrue(ledgers[0]["complete"])
        for row in ledgers[0]["functions"]:
            self.assertEqual(row["attempts"], 6)
            self.assertEqual(row["successful"], 6)

    def test_fork_child_uses_own_token_conf(self):
        # Concurrent C_OpenSession/C_Login on one shared SoftHSM token
        # fails intermittently under the cgroup thundering herd, which
        # exits the workload nonzero and preempts the cell oracle. The
        # fork child therefore switches to its own pre-inited token conf
        # (the harness passes one per workload); the parent keeps the
        # inherited conf. Unset child conf keeps the old shared behavior.
        source = self.tmp / "provider-conflog.c"
        source.write_text(PROVIDER_CONFLOG)
        module = self.tmp / "provider-conflog.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(module), str(source)],
                       check=True)
        gate = self.tmp / "gate-child-conf"
        gate.touch()
        conflog = self.tmp / "conflog"
        env = dict(os.environ, SOFTHSM2_CONF="conf-parent",
                   P11SCOPE_CGROUP_FORK_CHILD_CONF="conf-child",
                   P11SCOPE_CONFLOG=str(conflog))
        proc = subprocess.Popen([str(self.tmp / "cgroup-fork"), str(module), "3", "0", str(gate)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            stdout, _ = proc.communicate(timeout=5)
        parent = [line for line in stdout.splitlines() if line.startswith("READY pid=")][0]
        child = [line for line in stdout.splitlines() if line.startswith("CHILD pid=")][0]
        seen = {}
        for line in conflog.read_text().splitlines():
            pid, _, conf = line.partition(" ")
            seen[pid] = conf
        self.assertEqual(seen[parent.split("=")[1]], "conf-parent")
        self.assertEqual(seen[child.split("=")[1]], "conf-child")

    def test_fork_child_inherits_conf_when_unset(self):
        source = self.tmp / "provider-conflog.c"
        if not source.exists():
            source.write_text(PROVIDER_CONFLOG)
            subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o",
                            str(self.tmp / "provider-conflog.so"), str(source)], check=True)
        module = self.tmp / "provider-conflog.so"
        gate = self.tmp / "gate-inherit-conf"
        gate.touch()
        conflog = self.tmp / "conflog-inherit"
        env = dict(os.environ, SOFTHSM2_CONF="conf-shared",
                   P11SCOPE_CONFLOG=str(conflog))
        env.pop("P11SCOPE_CGROUP_FORK_CHILD_CONF", None)
        proc = subprocess.Popen([str(self.tmp / "cgroup-fork"), str(module), "3", "0", str(gate)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            stdout, _ = proc.communicate(timeout=5)
        child = [line for line in stdout.splitlines() if line.startswith("CHILD pid=")][0]
        seen = {}
        for line in conflog.read_text().splitlines():
            pid, _, conf = line.partition(" ")
            seen[pid] = conf
        self.assertEqual(seen[child.split("=")[1]], "conf-shared")


PROVIDER32 = r'''
#include <stdlib.h>
typedef unsigned long U;
U C_Initialize(void *a){(void)a;return 0;}
U C_Finalize(void *a){(void)a;return 0;}
U C_GetSlotList(unsigned char t,U *s,U *n){(void)t;s[0]=1;*n=1;return 0;}
U C_OpenSession(U a,U b,void *c,void*d,U*s){(void)a;(void)b;(void)c;(void)d;*s=1;return 0;}
U C_CloseSession(U s){(void)s;return 0;}
U C_Login(U s,U u,unsigned char*p,U n){(void)s;(void)u;(void)p;(void)n;return 0;}
U C_Logout(U s){(void)s;return 0;}
U C_GenerateRandom(U s,unsigned char*b,U n){(void)s;(void)b;(void)n;return 0;}
U C_DigestInit(U s,void*m){(void)s;(void)m;return 0;}
U C_Digest(U s,unsigned char*b,U n,unsigned char*o,U*l){(void)s;(void)b;(void)n;(void)o;*l=32;return 0;}
U C_FindObjectsInit(U s,void*t,U n){(void)s;(void)t;(void)n;return 0;}
U C_FindObjects(U s,U*o,U n,U*c){(void)s;(void)o;(void)n;*c=0;return 0;}
U C_FindObjectsFinal(U s){(void)s;return 0;}
/* True cryptoki layout: the 2-byte version, then the table at pointer
 * alignment (offset 4 under -m32). A fixture that hard-codes the LP64
 * offset reads every entry shifted and never reaches READY. */
struct { unsigned char major, minor; void *p[70]; } list={.major=2,.minor=40,.p={
 [0]=C_Initialize,[1]=C_Finalize,[4]=C_GetSlotList,[12]=C_OpenSession,
 [13]=C_CloseSession,[18]=C_Login,[19]=C_Logout,[26]=C_FindObjectsInit,
 [27]=C_FindObjects,[28]=C_FindObjectsFinal,[37]=C_DigestInit,[38]=C_Digest,[64]=C_GenerateRandom}};
U C_GetFunctionList(void**out){*out=&list;return 0;}
'''


class Gated32FixtureTests(unittest.TestCase):
    """The ia32 leg builds gated.c -m32; its function-table offset must be
    width-correct or the workload segfaults before READY (no ledger)."""

    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.storage.name)
        probe = cls.tmp / "probe32.c"
        probe.write_text("int main(void){return 0;}\n")
        tiny = cls.tmp / "tiny32"
        build = subprocess.run(["gcc", "-m32", "-O1", "-o", str(tiny), str(probe)],
                               capture_output=True, text=True)
        runnable = (build.returncode == 0 and tiny.exists() and
                    subprocess.run([str(tiny)]).returncode == 0)
        if not runnable:
            raise unittest.SkipTest("no working gcc -m32 on this host")
        source = cls.tmp / "provider32.c"
        source.write_text(PROVIDER32)
        cls.module = cls.tmp / "provider32.so"
        subprocess.run(["gcc", "-m32", "-shared", "-fPIC", "-O1",
                        "-o", str(cls.module), str(source)], check=True)
        cls.gated = cls.tmp / "gated32"
        subprocess.run(["gcc", "-m32", "-O1", "-o", str(cls.gated),
                        str(ROOT / "tests/fixtures/public-cli/gated.c"),
                        "-ldl"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def test_gated32_reaches_ready_and_ledgers(self):
        proc = subprocess.run([str(self.gated), str(self.module),
                               "3", "0", "-"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        targets = [json.loads(line[7:]) for line in lines
                   if line.startswith("TARGET ")]
        self.assertEqual({row["name"] for row in targets}, set(NAMES))
        ready = [line for line in lines if line.startswith("READY pid=")]
        self.assertEqual(len(ready), 1)
        ledgers = [json.loads(line[7:]) for line in lines
                   if line.startswith("LEDGER ")]
        self.assertEqual(len(ledgers), 1)
        self.assertTrue(ledgers[0]["complete"])
        for row in ledgers[0]["functions"]:
            self.assertEqual(row["attempts"], 3)
            self.assertEqual(row["successful"], 3)


PROVIDER_MT = r'''
#include <stdlib.h>
typedef unsigned long U;
typedef struct { U slotID; U state; U flags; U ulDeviceError; } INFO;
U C_Initialize(void *a){(void)a;return 0;}
U C_Finalize(void *a){(void)a;return 0;}
U C_GetSlotList(unsigned char t,U *s,U *n){(void)t;s[0]=1;*n=1;return 0;}
U C_OpenSession(U a,U b,void *c,void*d,U*s){(void)a;(void)b;(void)c;(void)d;*s=7;return 0;}
U C_CloseSession(U s){(void)s;return 0;}
U C_GetSessionInfo(U s,INFO*i){i->slotID=1;i->state=0;i->flags=6;i->ulDeviceError=(U)(s!=7);return 0;}
U C_GenerateRandom(U s,unsigned char*b,U n){(void)b;(void)n;return s==0xDEADBEEFUL?0xB3:0;}
U C_DigestInit(U s,void*m){(void)s;(void)m;return 0;}
U C_DigestUpdate(U s,unsigned char*b,U n){(void)s;(void)b;(void)n;return 0;}
U C_DigestFinal(U s,unsigned char*b,U*l){(void)s;(void)b;*l=32;return 0;}
U C_FindObjectsInit(U s,void*t,U n){(void)s;(void)t;(void)n;return 0;}
U C_FindObjects(U s,U*o,U n,U*c){(void)s;(void)o;(void)n;*c=0;return 0;}
U C_FindObjectsFinal(U s){(void)s;return 0;}
struct { unsigned char version[8]; void *p[68]; } list={.version={2,40},.p={
 [0]=C_Initialize,[1]=C_Finalize,[4]=C_GetSlotList,[12]=C_OpenSession,
 [13]=C_CloseSession,[15]=C_GetSessionInfo,[26]=C_FindObjectsInit,
 [27]=C_FindObjects,[28]=C_FindObjectsFinal,[37]=C_DigestInit,
 [39]=C_DigestUpdate,[41]=C_DigestFinal,[64]=C_GenerateRandom}};
U C_GetFunctionList(void**out){*out=&list;return 0;}
'''

PROVIDER_MT_ALWAYS_OK = PROVIDER_MT.replace(
    "return s==0xDEADBEEFUL?0xB3:0;", "return 0;")


def parse_mt_output(text):
    lines = text.splitlines()
    targets = [json.loads(line[7:]) for line in lines if line.startswith("TARGET ")]
    ready = [line for line in lines if line.startswith("READY pid=")]
    ledgers = [json.loads(line[7:]) for line in lines if line.startswith("LEDGER ")]
    return targets, ready, ledgers


def check_mt_ledger(testcase, ledger, pid, calls, errors):
    testcase.assertEqual(ledger["schema"], "p11scope/public-cli-ledger/v2")
    testcase.assertEqual(ledger["pid"], pid)
    testcase.assertTrue(ledger["complete"])
    testcase.assertEqual([row["name"] for row in ledger["functions"]], list(MT_NAMES))
    for i, row in enumerate(ledger["functions"]):
        want_errors = errors if i == 0 else 0
        testcase.assertEqual(row["attempts"], calls + want_errors, row["name"])
        testcase.assertEqual(row["successful"], calls, row["name"])
        testcase.assertEqual(row["rv_counts"].get("0x0000000000000000"), calls, row["name"])
        if want_errors:
            testcase.assertEqual(row["rv_counts"].get("0x00000000000000b3"), want_errors,
                                 row["name"])
        else:
            testcase.assertNotIn("0x00000000000000b3", row["rv_counts"], row["name"])


class MtFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.storage.name)
        for name, source in (("provider-mt.c", PROVIDER_MT),
                             ("provider-mt-ok.c", PROVIDER_MT_ALWAYS_OK)):
            (cls.tmp / name).write_text(source)
        cls.module = cls.tmp / "provider-mt.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(cls.module),
                        str(cls.tmp / "provider-mt.c")], check=True)
        cls.ok_module = cls.tmp / "provider-mt-ok.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(cls.ok_module),
                        str(cls.tmp / "provider-mt-ok.c")], check=True)
        flags = ["-O2", "-Wall", "-Wextra", "-Werror"]
        subprocess.run(["gcc", *flags, "-o", str(cls.tmp / "mt_mixed"),
                        str(ROOT / "tests/fixtures/public-cli/mt_mixed.c"),
                        "-ldl", "-lpthread"], check=True)
        subprocess.run(["gcc", *flags, "-o", str(cls.tmp / "mt_fork"),
                        str(ROOT / "tests/fixtures/public-cli/mt_fork.c"),
                        "-ldl", "-lpthread"], check=True)
        cls.gate = cls.tmp / "gate"
        cls.gate.touch()

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def run_mixed(self, module, *args):
        return subprocess.run([str(self.tmp / "mt_mixed"), str(module), *args],
                              capture_output=True, text=True, timeout=60)

    def test_sessions_mode_ledgers_exact_totals(self):
        proc = self.run_mixed(self.module, "8", "50", str(self.gate), "sessions", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        targets, ready, ledgers = parse_mt_output(proc.stdout)
        self.assertEqual({row["name"] for row in targets}, set(MT_NAMES))
        self.assertEqual(len(ready), 1)
        self.assertEqual(len(ledgers), 1)
        check_mt_ledger(self, ledgers[0], int(ready[0].split("=")[1]), 8 * 50, 8 * 3)

    def test_shared_mode_ledgers_exact_totals(self):
        proc = self.run_mixed(self.module, "8", "50", str(self.gate), "shared", "0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        _, ready, ledgers = parse_mt_output(proc.stdout)
        self.assertEqual(len(ledgers), 1)
        check_mt_ledger(self, ledgers[0], int(ready[0].split("=")[1]), 8 * 50, 0)

    def test_churn_mode_ledgers_exact_totals(self):
        proc = self.run_mixed(self.module, "8", "50", str(self.gate), "churn", "2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        _, ready, ledgers = parse_mt_output(proc.stdout)
        self.assertEqual(len(ledgers), 1)
        check_mt_ledger(self, ledgers[0], int(ready[0].split("=")[1]), 8 * 50, 8 * 2)

    def test_churn_rejects_odd_iterations(self):
        proc = self.run_mixed(self.module, "8", "51", str(self.gate), "churn", "0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("LEDGER ", proc.stdout)

    def test_churn_rejects_odd_errors(self):
        proc = self.run_mixed(self.module, "8", "50", str(self.gate), "churn", "1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("LEDGER ", proc.stdout)

    def test_error_probe_that_succeeds_fails_loud(self):
        # The always-OK provider breaks the error script: no LEDGER may print.
        proc = self.run_mixed(self.ok_module, "4", "10", str(self.gate), "sessions", "2")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("LEDGER ", proc.stdout)

    def test_fork_merges_multiprocess_totals(self):
        proc = subprocess.run([str(self.tmp / "mt_fork"), str(self.module),
                               "2", "4", "25", str(self.gate), "2"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        targets, ready, ledgers = parse_mt_output(proc.stdout)
        self.assertEqual({row["name"] for row in targets}, set(MT_NAMES))
        self.assertEqual(len(ready), 1)
        self.assertEqual(len(ledgers), 1)
        children = [line for line in proc.stdout.splitlines() if line.startswith("CHILD pid=")]
        self.assertEqual(len(children), 2)
        check_mt_ledger(self, ledgers[0], int(ready[0].split("=")[1]), 2 * 4 * 25, 2 * 4 * 2)


class MtOracleTests(unittest.TestCase):
    """Multi-threaded same-provider exact cells: every count, error and
    return-value assertion has a healthy twin and a failing twin."""

    def run_case_mt(self, mutate=None, *, cell, want=0, calls=24, errors=0,
                    report_text=None, allow_pid_descendant_gaps=False):
        metrics = cell in {"mt-metrics", "counter-latency-mt"}
        scope = "system" if cell == "mt-system" else "pid"
        report, ledger, receipt = inputs_mt(metrics=metrics, scope=scope, calls=calls,
                                            errors=errors if cell == "mt-errors" else 0,
                                            cell=cell)
        if cell == "counter-latency-mt":
            report["evidence"]["counter_collection"] = {
                "mode": "latency", "generation": 1,
                "read_window": {"started_ns": 100, "finished_ns": 200},
                "status": "fresh", "health": {"saturated": False, "contended": False},
                "discontinuity": False, "failure": None}
            for row in report["functions"]:
                row["latency_ns"] = {"approximate": True, "p50": 50, "p95": 90, "p99": 95,
                                     "total": 1000, "max": 100}
        if mutate:
            mutate(report, ledger, receipt)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt)):
                paths[key] = tmp / key
                text = json.dumps(value)
                if report_text is not None and key == "report":
                    text = report_text
                paths[key].write_text(text)
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            args = [sys.executable, "-I", str(ORACLE),
                    "--cell", cell, *sum((["--" + key, str(path)]
                                         for key, path in paths.items()), [])]
            if allow_pid_descendant_gaps:
                args.append("--allow-pid-descendant-gaps")
            proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], cell)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_mt_metrics_exact_passes(self):
        self.run_case_mt(cell="mt-metrics")

    def test_mt_errors_exact_passes(self):
        self.run_case_mt(cell="mt-errors", errors=3)

    def test_mt_shared_exact_passes(self):
        self.run_case_mt(cell="mt-shared")

    def test_mt_churn_exact_passes(self):
        self.run_case_mt(cell="mt-churn")

    def test_mt_system_exact_passes(self):
        # The merged multi-process ledger is exact on its own terms; the
        # single-workload 500-per-target system rule does not apply.
        self.run_case_mt(cell="mt-system", calls=40)

    def test_counter_latency_mt_exact_passes(self):
        self.run_case_mt(cell="counter-latency-mt")

    def test_mt_ledger_plus_one_fails(self):
        # A coherent fixture ledger claiming one call more than the observer
        # saw must fail on the observer-vs-ledger comparison, not on ledger
        # self-consistency.
        def mutate(d, l, r):
            mutate_mt_ledger(l, 2, attempts=25, successful=25,
                             rv_counts={mt_rv_key(0): 25})
        result = self.run_case_mt(mutate, cell="mt-shared", want=1)
        self.assertIn("owned target count differs from independent ledger",
                      result["detail"])

    def test_mt_report_overcount_fails(self):
        self.run_case_mt(lambda d, l, r: d["functions"][5].update(calls=25),
                         cell="mt-shared", want=1)

    def test_mt_report_undercount_fails(self):
        self.run_case_mt(lambda d, l, r: d["functions"][5].update(calls=23),
                         cell="mt-metrics", want=1)

    def test_mt_hidden_error_fails(self):
        # The ledger proves 3 failed calls; an observer row claiming zero
        # errors with a clean return map contradicts it.
        def mutate(d, l, r):
            d["functions"][0].update(errors=0, rv_counts={mt_rv_key(0): 24})
        result = self.run_case_mt(mutate, cell="mt-errors", errors=3, want=1)
        self.assertIn("owned target error count differs from independent ledger",
                      result["detail"])

    def test_mt_rv_drift_fails(self):
        # Same totals, but one return moved between codes: the map must match exactly.
        def mutate(d, l, r):
            d["functions"][0]["rv_counts"] = {mt_rv_key(0): 22, mt_rv_key(MT_BOGUS_RV): 2}
        result = self.run_case_mt(mutate, cell="mt-errors", errors=3, want=1)
        self.assertIn("owned target return map differs from independent ledger",
                      result["detail"])

    def test_mt_missing_rv_counts_fails_closed(self):
        self.run_case_mt(lambda d, l, r: d["functions"][1].pop("rv_counts"),
                         cell="mt-shared", want=1)

    def test_mt_unexpected_error_fails(self):
        self.run_case_mt(lambda d, l, r: d["functions"][4].update(errors=1),
                         cell="mt-churn", want=1)

    def test_mt_v1_ledger_without_rv_proof_fails(self):
        # MT cells require ledger v2: per-function return maps, not bare totals.
        def mutate(d, l, r):
            payload = json.loads(l[-1][len("LEDGER "):])
            payload["schema"] = "p11scope/public-cli-ledger/v1"
            for row in payload["functions"]:
                row.pop("rv_counts", None)
            l[-1] = "LEDGER " + json.dumps(payload)
        self.run_case_mt(mutate, cell="mt-shared", want=1)

    def test_mt_ledger_rv_sum_mismatch_fails(self):
        def mutate(d, l, r):
            mutate_mt_ledger(l, 0, rv_counts={mt_rv_key(0): 20})
        self.run_case_mt(mutate, cell="mt-shared", want=1)

    def test_mt_trace_loss_identity_passes_as_smoke(self):
        text = trace_stream_mt(calls_per_function=3)
        report, ledger, _ = inputs_mt(scope="pid", calls=3, cell="mt-trace")
        payload = json.loads(ledger[-1][len("LEDGER "):])
        self.assertEqual(payload["functions"][0]["attempts"], 3)
        self.run_case_mt(cell="mt-trace", want=2, calls=3, report_text=text)

    def test_mt_trace_wrong_line_count_fails(self):
        text = trace_stream_mt(calls_per_function=2)
        self.run_case_mt(cell="mt-trace", want=1, calls=3, report_text=text)

    def test_mt_trace_malformed_stream_fails(self):
        self.run_case_mt(cell="mt-trace", want=1, report_text="CALL \u2192 done\n" * 42)

    def test_mt_system_runner_noise_disclosed(self):
        def mutate(d, l, r):
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap",
                                 pid_descendant_gaps=2)
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
        result = self.run_case_mt(mutate, cell="mt-system", calls=40, want=0,
                                  allow_pid_descendant_gaps=True)
        self.assertIn("disclosed runner noise", result["detail"])

    def test_mt_system_runner_noise_strict_fails(self):
        def mutate(d, l, r):
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap",
                                 pid_descendant_gaps=2)
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
        self.run_case_mt(mutate, cell="mt-system", calls=40, want=1)


if __name__ == "__main__":
    unittest.main()
