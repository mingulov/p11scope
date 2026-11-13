# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Public CLI oracle entrypoint controls; all expectations are independent."""

import copy
import ctypes
import hashlib
import io
import json
import mmap
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/public-cli-oracle.py"
SHELL = ROOT / "scripts/qualify-public-cli.sh"
PIN = ROOT / "scripts/mapped-provider-pin.py"
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
    "mechanism_id_overflow",
    "semantic_history_drops", "pending_at_end", "orphan_ops", "unmatched_closes",
    "shape_decode_failures", "shape_decode_total_failures", "discovery_conflicts",
    "discovery_uncorroborated", "module_ambiguous", "semantic_unverified_slots",
    "module_unresolved_slots", "unprotected_live_windows", "pause_partial", "pause_unavailable",
    "unpublished_mechanisms", "vendor_interfaces")
PROFILE_FIELDS = ("interface_selection", "attach_mechanisms",
                  "pid_descendant_gaps", "multi_rebuild_gaps",
                  "learned_staged_files", "learned_event_loss",
                  "learned_cap_skipped")


def provider_pin():
    return dict(OWNED,
                file_identity={"dev": [0, 38], "ino": 71, "size": 8192,
                               "mtime_ns": 123, "ctime_ns": 456},
                mapping={"dev": [8, 1], "ino": 71, "file_offset": 0,
                         "length": 4096, "permissions": "r--p"})


def independent_mapping_identity(path):
    # A separate Python mmap API and parser derive expectations, never the
    # production pin helper or the fixture/capture outputs under test.
    with open(path, "rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as view:
            address = ctypes.addressof(ctypes.c_char.from_buffer(view))
            matches = []
            for line in Path("/proc/self/maps").read_text().splitlines():
                fields = line.split()
                low, high = [int(bound, 16) for bound in fields[0].split("-")]
                if low <= address < high:
                    matches.append(([int(part, 16) for part in fields[3].split(":")],
                                    int(fields[4])))
            assert len(matches) == 1, "independent mapping has no unique maps anchor"
            return matches[0]


def inputs(*, metrics=False, system=False):
    calls = 500 if system else 7
    scope = "system" if system else "pid"
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
                        "scope_filter": None if system else "perf-task+bpf"},
        pid_descendant_gaps=0, multi_rebuild_gaps=0,
        learned_staged_files=0, learned_event_loss=0,
        learned_cap_skipped=0)
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
    receipt = {"schema": "p11scope/public-cli-receipt/v1", "cell": "profile-pid",
               "scope": scope, "count_domain": "owned-provider",
               "launched_pid": 123, "generation": 456,
               "ready_pid": 123, "ready_generation": 456,
               "workload_ready": True, "capture_ready": True, "gate_released": True,
               "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
               "provider_before": provider_pin(), "provider_after": provider_pin()}
    return report, ledger, receipt


MT_NAMES = ("C_GenerateRandom", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo")
MT_SYSTEM_CHILDREN = (124, 125, 126, 127)


def mt_rv_key(rv):
    return "0x%016x" % rv


def mt_row_ledger(name, calls):
    return {"name": name, "attempts": calls, "successful": calls,
            "rv_counts": {mt_rv_key(0): calls}}


def inputs_mt_system(*, calls=40):
    # Minimal mt-system fixture for the lone-gap twins: ledger v2 with
    # return maps, 4 distinct children and the 32-open scaffold the
    # oracle requires, plus the profile verdict fields (including the
    # learned_* trio) so the gap gate, not field authority, judges.
    targets = [{"name": name, "dev": [8, 1], "ino": 71,
                "file_offset": 4096 + i * 16} for i, name in enumerate(MT_NAMES)]
    report = {"schema": "p11scope/observed-profile/v3",
              "lane": "profile", "capture": {"scope": "system", "mode": "profile"},
              "functions": [{"names": [name], "calls": calls, "errors": 0,
                             "in_flight": 0, "pending_returns": 0,
                             "module": dict(OWNED), "module_ambiguous": False,
                             "module_unresolved": False,
                             "rv_counts": dict(mt_row_ledger(name, calls)["rv_counts"]),
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
        attach_backend={"selection": "singles", "fallback": None, "scope_filter": None},
        pid_descendant_gaps=0, multi_rebuild_gaps=0,
        learned_staged_files=0, learned_event_loss=0,
        learned_cap_skipped=0)
    ledger = ["TARGET " + json.dumps(row) for row in targets]
    ledger += ["CHILD pid=%d" % pid for pid in MT_SYSTEM_CHILDREN]
    ledger += ["READY pid=123", "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v2", "pid": 123, "complete": True,
        "functions": [mt_row_ledger(name, calls) for name in MT_NAMES]})]
    ledger += ["SCAFFOLD " + json.dumps({"opens_attempted": 32, "opens_ok": 32,
                                        "closes": 32, "finalizes": 1})]
    receipt = {"schema": "p11scope/public-cli-receipt/v1", "cell": "mt-system",
               "scope": "system", "count_domain": "owned-provider",
               "launched_pid": 123, "generation": 456,
               "ready_pid": 123, "ready_generation": 456,
               "workload_ready": True, "capture_ready": True, "gate_released": True,
               "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
               "provider_before": provider_pin(), "provider_after": provider_pin()}
    return report, ledger, receipt


def replace_successful_totals(report, ledger, totals):
    """Keep the independent ledger and observed report coherent for denominator controls."""
    payload = json.loads(ledger[-1][len("LEDGER "):])
    for row, total in zip(payload["functions"], totals):
        row.update(attempts=total, successful=total)
    ledger[-1] = "LEDGER " + json.dumps(payload)
    for row, total in zip(report["functions"], totals):
        row["calls"] = total


class OracleTests(unittest.TestCase):
    def run_case(self, mutate=None, *, cell="profile-pid", want=0,
                 allow_pid_descendant_gaps=False, census=None):
        report, ledger, receipt = inputs(metrics=cell == "metrics-pid", system=cell == "system")
        receipt["cell"] = cell
        if mutate:
            mutate(report, ledger, receipt)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt)):
                paths[key] = tmp / key
                text = json.dumps(value)
                if key == "report" and cell == "trace-pid":
                    text = "CALL -> done\n" * 42
                paths[key].write_text(text)
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            args = [sys.executable, "-I", str(ORACLE),
                    "--cell", cell, *sum((["--" + key, str(path)]
                                         for key, path in paths.items()), [])]
            if allow_pid_descendant_gaps:
                args.append("--allow-pid-descendant-gaps")
            if census is not None:
                census_path = tmp / "census"
                census_path.write_text(census)
                args += ["--census", str(census_path)]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], cell)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_valid_profile(self):
        self.run_case()

    def test_valid_metrics(self):
        self.run_case(cell="metrics-pid")

    def test_benign_loader_hit_stays_exact(self):
        def benign(report, ledger, receipt):
            report["evidence"]["loader_discovery"] = {
                "strategies": {"debug_state_every_hit": 1, "dlopen_return": 0,
                               "unavailable": 0},
                "dlopen_timing": {"qualified_pre_constructor": 0,
                                  "known_pre_relocation": 0, "unproven": 1,
                                  "none": 0, "pause_protected": 0},
                "initial_set_timing": {"qualified_pre_constructor": 0,
                                       "known_pre_relocation": 0, "unproven": 0,
                                       "none": 0, "pause_protected": 0},
                "initial_set_capture": {"eligible": 0, "none": 0,
                                        "pause_protected": 0},
                "hits": 1, "benign_hits": 1, "state_read_failures": 0,
            }
        self.run_case(benign)

    def test_benign_key_present_on_clean_capture(self):
        self.run_case(lambda d, l, r: d["evidence"]["loader_discovery"].update(benign_hits=0))

    def test_benign_above_hits_is_refused(self):
        oracle = runpy.run_path(str(ORACLE))
        report, ledger, receipt = inputs()
        report["evidence"]["loader_discovery"].update(
            strategies={"debug_state_every_hit": 1, "dlopen_return": 0,
                        "unavailable": 0},
            dlopen_timing={"qualified_pre_constructor": 0,
                           "known_pre_relocation": 0, "unproven": 1,
                           "none": 0, "pause_protected": 0},
            hits=1, benign_hits=2)
        with self.assertRaisesRegex(oracle["EvidenceError"], "above"):
            oracle["judge"](json.dumps(report), "\n".join(ledger) + "\n",
                            receipt, "profile-pid")

    def test_system_six_500_call_totals_pass(self):
        self.run_case(cell="system")

    def test_system_seven_call_smoke_cannot_qualify(self):
        self.run_case(lambda d, l, r: replace_successful_totals(d, l, (7,) * 6),
                      cell="system", want=1)

    def test_system_six_499_call_totals_cannot_qualify(self):
        self.run_case(lambda d, l, r: replace_successful_totals(d, l, (499,) * 6),
                      cell="system", want=1)

    def test_system_compensated_499_501_totals_cannot_qualify(self):
        for index in range(6):
            totals = [500] * 6
            totals[index], totals[(index + 1) % 6] = 499, 501
            self.assertEqual(sum(totals), 3000)
            with self.subTest(deficient=NAMES[index]):
                self.run_case(lambda d, l, r: replace_successful_totals(d, l, totals),
                              cell="system", want=1)

    def test_system_report_must_match_each_independent_total(self):
        for index in range(6):
            with self.subTest(target=NAMES[index]):
                self.run_case(lambda d, l, r: d["functions"][index].update(calls=499),
                              cell="system", want=1)

    def test_system_target_identity_failures_cannot_qualify(self):
        mutations = {
            "missing": lambda d, l, r: l.pop(0),
            "duplicate": lambda d, l, r: l.insert(0, l[0]),
            "foreign": lambda d, l, r: d["functions"][0]["target"].update(object=FOREIGN),
        }
        for fault, mutate in mutations.items():
            with self.subTest(fault=fault):
                self.run_case(mutate, cell="system", want=1)

    def test_system_loss_and_pending_returns_fail(self):
        mutations = {
            "loss": lambda d, l, r: d["evidence"].update(event_loss=1),
            "pending": lambda d, l, r: d["functions"][0].update(pending_returns=1),
            "in-flight": lambda d, l, r: d["functions"][0].update(in_flight=1),
        }
        for fault, mutate in mutations.items():
            with self.subTest(fault=fault):
                self.run_case(mutate, cell="system", want=1)

    def test_system_unproven_drain_cannot_be_complete(self):
        self.run_case(lambda d, l, r: d["evidence"].update(drain_proven=False),
                      cell="system", want=1)

    def test_foreign_provider_equal_counts_fails(self):
        self.run_case(lambda d, l, r: [f["target"].update(object=FOREIGN)
                                      for f in d["functions"]], want=1)

    def test_swapped_physical_offsets_fails_even_with_equal_counts(self):
        def mutate(d, l, r):
            d["functions"][0]["target"]["file_offset"], d["functions"][1]["target"]["file_offset"] = (
                d["functions"][1]["target"]["file_offset"], d["functions"][0]["target"]["file_offset"])
        self.run_case(mutate, want=1)

    def test_path_reused_changed_identity_fails(self):
        self.run_case(lambda d, l, r: r.update(provider_after=FOREIGN), want=1)

    def test_split_stat_maps_device_with_independent_anchor_passes(self):
        self.run_case()

    def test_same_inode_hash_wrong_mapped_device_fails(self):
        def mutate(d, l, r):
            for pin in (r["provider_before"], r["provider_after"]):
                pin["dev"] = [0, 38]
        self.run_case(mutate, want=1)

    def test_changed_private_fd_identity_fails(self):
        self.run_case(lambda d, l, r: r["provider_after"]["file_identity"].update(dev=[0, 39]), want=1)

    def test_changed_provider_hash_fails(self):
        self.run_case(lambda d, l, r: r["provider_after"].update(sha256="c" * 64), want=1)

    def test_missing_mapping_anchor_fails(self):
        self.run_case(lambda d, l, r: r["provider_before"].pop("mapping"), want=1)

    def test_invalid_mapping_anchor_fails(self):
        for key, value in (("dev", [0, 38]), ("ino", 72), ("file_offset", 4096),
                           ("length", 0), ("permissions", "r-xp")):
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: r["provider_before"]["mapping"].update({key: value}), want=1)

    def test_missing_or_invalid_private_fd_identity_fails(self):
        for value in (None, {}, {"dev": [0, 38], "ino": 72, "size": 8192,
                                "mtime_ns": 123, "ctime_ns": 456}):
            with self.subTest(value=value):
                self.run_case(lambda d, l, r: r["provider_before"].update(file_identity=value), want=1)

    def test_mapping_anchor_bool_device_fails(self):
        self.run_case(lambda d, l, r: r["provider_before"]["mapping"].update(dev=[8, True]), want=1)

    def test_missing_first_call_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=6), want=1)

    def test_duplicate_ledger_fails(self):
        self.run_case(lambda d, l, r: l.append(l[-1]), want=1)

    def test_missing_ledger_fails(self):
        self.run_case(lambda d, l, r: l.pop(), want=1)

    def test_observer_nonzero_fails(self):
        self.run_case(lambda d, l, r: r.update(observer_exit=17), want=1)

    def test_workload_nonzero_fails(self):
        self.run_case(lambda d, l, r: r.update(workload_exit=1), want=1)

    def test_owned_refusal_fails(self):
        self.run_case(lambda d, l, r: d["evidence"].update(discovery=[], modules_skipped=[
            {"name": "/owned.so", "reason": "capacity"}]), want=1)

    def test_unrelated_system_traffic_passes_owned_provider_only(self):
        def mutate(d, l, r):
            d["functions"].append({"names": ["unknown"], "calls": 91, "errors": 0, "in_flight": 0, "pending_returns": 0,
                "module": dict(FOREIGN), "module_ambiguous": False, "module_unresolved": False,
                "target": {"object": dict(FOREIGN), "file_offset": 4096}})
        result = self.run_case(mutate, cell="system")
        self.assertEqual(result["qualification"], "owned-provider-counts")
        self.assertIn("per-caller", result["detail"])

    def test_shared_domain_nonqualifying(self):
        self.run_case(lambda d, l, r: r.update(count_domain="shared"), cell="system", want=2)

    def test_absent_identity_nonqualifying(self):
        self.run_case(lambda d, l, r: d["functions"][0]["target"].update(object=None), want=2)

    def test_duplicate_target_fails(self):
        self.run_case(lambda d, l, r: l.insert(0, l[0]), want=1)

    def test_duplicate_observed_target_fails(self):
        self.run_case(lambda d, l, r: d["functions"].append(copy.deepcopy(d["functions"][0])), want=1)

    def test_generation_mismatch_fails(self):
        self.run_case(lambda d, l, r: r.update(ready_generation=457), want=1)

    def test_loss_fails(self):
        self.run_case(lambda d, l, r: d["evidence"].update(event_loss=1), want=1)

    def test_bool_count_fails(self):
        self.run_case(lambda d, l, r: d["functions"][0].update(calls=True), want=1)

    def test_run_exact_requires_confirmed_pause(self):
        # WP-4: run-short/run-cover are exact, not smoke. Default inputs carry
        # pause none and must fail; a confirmed pause with an exited child passes.
        # Run-tree (v0.7.0): owned runs capture at cgroup scope, so both
        # arms build cgroup inputs; the first still fails on the pause.
        def tree_scope(d, l, r):
            d["capture"]["scope"] = "cgroup"
            r["scope"] = "cgroup"
            d["evidence"]["attach_backend"]["scope_filter"] = None
        self.run_case(tree_scope, cell="run-short", want=1)
        def confirmed(d, l, r):
            tree_scope(d, l, r)
            d["evidence"].update(pause="sigstop", pause_attempts=1, pause_confirmed=1, pause_partial=0)
            d["evidence"]["child_still_running"] = False
        self.run_case(confirmed, cell="run-short", want=0)

    def test_trace_malformed_stream_fails(self):
        # WP-4: trace-pid applies the loss identity; the old arrow-only smoke
        # text without CAPTURE/COUNT_EVIDENCE/EVIDENCE must fail. Valid streams
        # that satisfy the identity remain nonqualifying (see breadth suite).
        self.run_case(cell="trace-pid", want=1)

    def test_real_clean_verdict_passes(self):
        self.run_case(cell="verdict-pid")

    def test_kernel_capture_halted_fails(self):
        self.run_case(lambda d,l,r: d["evidence"]["kernel_control"].update(capture_halted=True), want=1)

    def test_lossy_gap_class_fails(self):
        self.run_case(lambda d,l,r: d["evidence"]["gap_classes"]["observation"].update(status="lossy",causes=["provider_changed"]), want=1)

    def test_missing_loss_counter_fails(self):
        self.run_case(lambda d,l,r: d["evidence"].pop("discovery_ring_loss"), want=1)

    def test_shared_domain_with_loss_fails(self):
        def mutate(d,l,r):
            r["count_domain"] = "shared"
            d["evidence"]["event_loss"] = 1
        self.run_case(mutate, cell="system", want=1)

    def test_wrong_capture_scope_fails(self):
        self.run_case(lambda d,l,r: d["capture"].update(scope="system"), want=1)

    def test_ambiguous_owned_row_nonqualifying(self):
        self.run_case(shared_owned_row, want=2)

    def test_ready_after_ledger_fails(self):
        self.run_case(lambda d,l,r: l.reverse(), want=1)

    def test_duplicate_ready_fails(self):
        self.run_case(lambda d,l,r: l.insert(6, "READY pid=123"), want=1)

    def test_owned_observed_error_conflicts_with_successful_ledger(self):
        self.run_case(lambda d,l,r: d["functions"][0].update(errors=1), want=1)

    def test_owned_pending_return_fails(self):
        self.run_case(lambda d,l,r: d["functions"][0].update(pending_returns=1), want=1)

    def test_partial_clean_proven_verdict_is_inconsistent(self):
        self.run_case(lambda d,l,r: d["evidence"].update(completeness="PARTIAL"), cell="verdict-pid", want=1)


def shared_owned_row(d, l, r):
    d["functions"][0].update(module=None, module_ambiguous=True)
    d["evidence"].update(module_ambiguous=1, completeness="PARTIAL", verdict_detail="attribution_only")
    d["evidence"]["gap_classes"]["attribution"] = {"status": "withheld", "causes": ["module_ambiguous"]}


def unresolved_extra_row(d, l, r):
    d["functions"].append({"names": ["unknown"], "calls": 0, "errors": 0, "in_flight": 0,
        "pending_returns": 0, "module": None, "module_ambiguous": False, "module_unresolved": True,
        "target": {"object": None, "file_offset": 9999}})
    d["evidence"].update(module_unresolved_slots=1, completeness="PARTIAL", verdict_detail="attribution_only")
    d["evidence"]["gap_classes"]["attribution"] = {"status": "withheld", "causes": ["module_unresolved_slots"]}


class ReviewFixTests(unittest.TestCase):
    run_case = OracleTests.run_case

    def test_r1_missing_ownership_fields_fail(self):
        for key in ("module", "module_ambiguous", "module_unresolved"):
            with self.subTest(key=key):
                self.run_case(lambda d,l,r: d["functions"][0].pop(key), want=1)

    def test_r1_malformed_ownership_flags_fail(self):
        for value in (None, "true", "false", 0, 1):
            with self.subTest(value=value):
                self.run_case(lambda d,l,r: d["functions"][0].update(module_ambiguous=value), want=1)

    def test_r1_null_module_without_reason_fails(self):
        self.run_case(lambda d,l,r: d["functions"][0].update(module=None), want=1)

    def test_r1_nonnull_module_with_ambiguity_fails(self):
        self.run_case(lambda d,l,r: d["functions"][0].update(module_ambiguous=True), want=1)

    def test_r1_two_ownership_reasons_fail(self):
        def mutate(d,l,r):
            shared_owned_row(d,l,r)
            d["functions"][0]["module_unresolved"] = True
        self.run_case(mutate, want=1)

    def test_r1_malformed_module_identity_fails(self):
        self.run_case(lambda d,l,r: d["functions"][0].update(module={"path": "/owned.so"}), want=1)

    def test_r2_unproven_terminal_cannot_be_complete(self):
        def mutate(d,l,r):
            d["evidence"]["drain_proven"] = False
            d["evidence"]["stop_quiescence"]["state"] = "unproven"
            d["evidence"]["gap_classes"]["settlement"] = "unproven"
        self.run_case(mutate, cell="verdict-pid", want=1)

    def test_r2_degraded_semantics_cannot_be_clean(self):
        def mutate(d,l,r):
            d["evidence"]["semantic_capture_failures"] = 1
            d["evidence"]["gap_classes"]["semantics"] = {"status": "degraded", "causes": ["semantic_capture_failures"]}
        self.run_case(mutate, cell="verdict-pid", want=1)

    def test_r2_missing_terminal_authority_fails(self):
        for key in ("drain_proven", "stop_quiescence"):
            with self.subTest(key=key):
                self.run_case(lambda d,l,r: d["evidence"].pop(key), cell="verdict-pid", want=1)

    def test_r2_post_q_record_cannot_prove_drain(self):
        self.run_case(lambda d,l,r: d["evidence"]["stop_quiescence"].update(post_q_events=True), cell="verdict-pid", want=1)

    def test_r2_owned_refusal_cannot_hide_in_retained_discovery(self):
        self.run_case(lambda d,l,r: d["evidence"].update(modules_skipped=[
            {"name": "/owned.so", "reason": "capacity"}]), want=1)

    def test_r2_valid_unproven_terminal_stays_partial(self):
        def mutate(d,l,r):
            d["evidence"].update(completeness="PARTIAL", verdict_detail="clean_but_unproven", drain_proven=False)
            d["evidence"]["stop_quiescence"]["state"] = "unproven"
            d["evidence"]["gap_classes"]["settlement"] = "unproven"
        self.run_case(mutate, cell="verdict-pid")

    def test_r4_deficit_with_unrelated_unknown_row_fails(self):
        def mutate(d,l,r):
            unresolved_extra_row(d,l,r)
            d["functions"][0]["calls"] = 6
        self.run_case(mutate, want=1)

    def test_r4_deficit_with_shared_owned_row_fails(self):
        def mutate(d,l,r):
            shared_owned_row(d,l,r)
            d["functions"][0]["calls"] = 6
        self.run_case(mutate, want=1)

    def test_r4_missing_owned_row_with_shared_domain_fails(self):
        def mutate(d,l,r):
            d["functions"].pop(0)
            r["count_domain"] = "shared"
        self.run_case(mutate, want=1)

    def test_r4_unknown_row_without_definite_failure_nonqualifying(self):
        self.run_case(unresolved_extra_row, want=2)


class ProfileVerdictModeTests(unittest.TestCase):
    run_case = OracleTests.run_case

    def test_profile_selection_aware_positive(self):
        def check(d, l, r):
            self.assertEqual(d["lane"], "profile")
            self.assertEqual(d["capture"]["mode"], "profile")
            self.assertEqual(set(d["evidence"]["interface_selection"]),
                             {"providers", "standard_exports", "inventory_surfaces", "tuples", "selection_truncated"})
            self.assertEqual(d["evidence"]["pid_descendant_gaps"], 0)
            self.assertEqual(d["evidence"]["multi_rebuild_gaps"], 0)
        self.run_case(check, cell="verdict-pid")

    def test_profile_missing_selection_fails(self):
        self.run_case(lambda d, l, r: d["evidence"].pop("interface_selection"),
                      cell="verdict-pid", want=1)

    def test_profile_omitted_selection_cannot_hide_gap(self):
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            with self.subTest(key=key):
                def mutate(d, l, r):
                    d["evidence"][key] = 1
                    del d["evidence"]["interface_selection"]
                self.run_case(mutate, cell="verdict-pid", want=1)

    def test_profile_nonzero_gap_cannot_be_clean(self):
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"].update({key: 1}),
                              cell="verdict-pid", want=1)

    def test_profile_missing_gap_counter_fails(self):
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"].pop(key),
                              cell="verdict-pid", want=1)

    def test_profile_gap_counter_requires_u64(self):
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            for value in (None, False, True, 0.0, "0", -1, 2**64):
                with self.subTest(key=key, value=value):
                    self.run_case(lambda d, l, r: d["evidence"].update({key: value}),
                                  cell="verdict-pid", want=1)

    def test_profile_selection_flag_requires_boolean(self):
        for value in (None, 0, 0.0, "false"):
            with self.subTest(value=value):
                self.run_case(lambda d, l, r: d["evidence"]["interface_selection"].update(
                    selection_truncated=value), cell="verdict-pid", want=1)

    def test_profile_selection_lists_required(self):
        for key in ("providers", "standard_exports", "inventory_surfaces", "tuples"):
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"]["interface_selection"].update({key: {}}),
                              cell="verdict-pid", want=1)

    def test_profile_selection_required_keys(self):
        for key in ("providers", "standard_exports", "inventory_surfaces", "tuples", "selection_truncated"):
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"]["interface_selection"].pop(key),
                              cell="verdict-pid", want=1)

    def test_declared_lane_and_mode_must_match_cell_schema(self):
        for cell in ("verdict-pid", "metrics-pid"):
            for key in ("lane", "mode"):
                for value in (None, "metrics" if cell == "verdict-pid" else "profile"):
                    with self.subTest(cell=cell, key=key, value=value):
                        def mutate(d, l, r):
                            destination = d if key == "lane" else d["capture"]
                            if value is None:
                                del destination[key]
                            else:
                                destination[key] = value
                        self.run_case(mutate, cell=cell, want=1)

    def test_metrics_selection_blind_positive(self):
        def check(d, l, r):
            self.assertEqual(d["lane"], "metrics")
            self.assertEqual(d["capture"]["mode"], "metrics")
            self.assertTrue(set(PROFILE_FIELDS).isdisjoint(d["evidence"]))
        self.run_case(check, cell="metrics-pid")

    def test_metrics_accepts_actual_backend_metadata(self):
        for backend in (
                {"selection": "singles", "fallback": None, "scope_filter": "perf-task+bpf"},
                {"selection": "multi", "fallback": None, "scope_filter": "kernel-pid+bpf"},
                {"selection": "auto", "fallback": "uprobe-multi functional probe failed",
                 "scope_filter": "perf-task+bpf"}):
            with self.subTest(backend=backend):
                self.run_case(lambda d, l, r: d["evidence"].update(attach_backend=backend),
                              cell="metrics-pid")

    def test_metrics_requires_closed_valid_backend_metadata(self):
        changes = {
            "missing": lambda ev: ev.pop("attach_backend"),
            "missing-filter": lambda ev: ev["attach_backend"].pop("scope_filter"),
            "extra": lambda ev: ev["attach_backend"].update(pid=123),
            "wrong-selection": lambda ev: ev["attach_backend"].update(selection="always"),
            "wrong-filter": lambda ev: ev["attach_backend"].update(scope_filter="kernel-pid"),
            "global-filter": lambda ev: ev["attach_backend"].update(scope_filter=None),
            "wrong-fallback": lambda ev: ev["attach_backend"].update(fallback="probe failed"),
            "private-fallback": lambda ev: ev["attach_backend"].update(
                selection="auto", fallback="attach /owned.so failed"),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.run_case(lambda d, l, r: change(d["evidence"]), cell="metrics-pid", want=1)

    def test_metrics_profile_only_inputs_fail(self):
        profile, _, _ = inputs()
        for key in PROFILE_FIELDS:
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"].update({key: profile["evidence"][key]}),
                              cell="metrics-pid", want=1)


class RunnerNoiseTests(unittest.TestCase):
    """Ruling CI-GAP-1: hosted host system cell discloses runner noise."""
    run_case = OracleTests.run_case

    def run_case_mt_system(self, mutate=None, *, want=0, census=None):
        report, ledger, receipt = inputs_mt_system()
        if mutate:
            mutate(report, ledger, receipt)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt)):
                paths[key] = tmp / key
                paths[key].write_text(json.dumps(value))
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            args = [sys.executable, "-I", str(ORACLE),
                    "--cell", "mt-system", *sum((["--" + key, str(path)]
                                         for key, path in paths.items()), [])]
            if census is not None:
                census_path = tmp / "census"
                census_path.write_text(census)
                args += ["--census", str(census_path)]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], "mt-system")
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_exact_with_noise_passes_when_allowed(self):
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", allow_pid_descendant_gaps=True)
        self.assertEqual(result["qualification"], "owned-provider-counts-with-runner-noise")
        self.assertIn("disclosed runner noise", result["detail"])
        self.assertIn("pid_descendant_gaps=1", result["detail"])

    def test_exact_with_other_class_fails_when_allowed(self):
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["multi_rebuild_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps", "multi_rebuild_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        self.run_case(mutate, cell="system", allow_pid_descendant_gaps=True, want=1)

    def test_count_mismatch_with_noise_fails_when_allowed(self):
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 2
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
            d["functions"][0]["calls"] = 499
        self.run_case(mutate, cell="system", allow_pid_descendant_gaps=True, want=1)

    def test_lone_gap_passes_on_system_in_strict_mode(self):
        # Wave-1 ruling 2026-11-12 (supersedes the former strict
        # lone-gap pin test_noise_fails_in_strict_mode for the system
        # cell): quiet VNG guests disclose exactly
        # the ambient descendant exit with no skip (60906ccca stopped
        # filing the bogus B4 window gap, and the exit itself predates
        # wave 1 on every leg). Strict system scope accepts the
        # disclosed ambient gap with exact owned counts; any other
        # class still fails. Shape mirrors wave1-early run 43212507781
        # (lossy [pid_descendant_gaps], gaps=1, skipped=[]).
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system")
        self.assertEqual(result["qualification"], "owned-provider-counts-with-ambient-gap")
        self.assertIn("pid_descendant_gaps=1", result["detail"])
        self.assertIn("discovery_skips=0", result["detail"])

    def test_lone_gap_with_other_class_fails_in_strict_mode(self):
        # The wave-1 lone-gap arm stays narrow: a descendant gap
        # bundled with any other observation class still fails strict.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["multi_rebuild_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps", "multi_rebuild_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        self.run_case(mutate, cell="system", want=1)

    def test_lone_gap_with_skip_is_not_lone_in_strict_mode(self):
        # A descendant gap bundled with a skip is the ambient shape,
        # not the lone shape: the ambient arm (not the lone arm)
        # judges it, so a non-disclosable skip still fails strict.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["skipped"] = [{"name": "discovery subject",
                                         "reason": "something else"}]
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["skipped", "pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        self.run_case(mutate, cell="system", want=1)

    def test_lone_gap_with_two_gaps_fails_in_strict_mode(self):
        # The wave-1 lone-gap ceiling is exactly one disclosed
        # descendant gap: two ambient exits are not a lone gap and
        # still fail strict, with exact owned counts otherwise.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 2
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_unknown_status_fails_in_strict_mode(self):
        # Only the disclosed lossy lone class qualifies: an unknown
        # observation status with the same gap count still fails.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "unknown", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_count_mismatch_fails_in_strict_mode(self):
        # The lone arm never waives exact owned counts: one
        # disclosed gap with a 499/500 deficit still fails strict.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
            d["functions"][0]["calls"] = 499
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("owned target count differs", result["detail"])

    def test_lone_gap_with_solo_other_gap_fails_in_strict_mode(self):
        # Any other gap kind alone is not the lone descendant gap:
        # a solo multi_rebuild_gaps disclosure still fails strict.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 0
            d["evidence"]["multi_rebuild_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["multi_rebuild_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_modules_skipped_fails_in_strict_mode(self):
        # The lone arm requires no skipped modules: one disclosed
        # descendant gap bundled with a skipped module still fails
        # strict at the gap gate, with exact owned counts otherwise.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["modules_skipped"] = [
                {"name": "discovery subject", "reason": "discovery unavailable"}]
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_bool_count_fails_at_gap_gate_in_strict_mode(self):
        # The lone count gate states the full invariant: a boolean
        # True gap count (True == 1 in Python) fails at the gap gate
        # instead of leaking through to the terminal uint check.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = True
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_passes_on_mt_system_in_strict_mode(self):
        # Fix2 twin of the system lone-gap pass: mt-system carries
        # the same exactly-one-gap ceiling with exact owned counts.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate)
        self.assertEqual(result["qualification"], "owned-provider-counts-with-ambient-gap")
        self.assertIn("pid_descendant_gaps=1", result["detail"])
        self.assertIn("discovery_skips=0", result["detail"])

    def test_lone_gap_with_two_gaps_fails_on_mt_system_in_strict_mode(self):
        # The mt-system ceiling is exactly one, never nonzero: two
        # descendant gaps still fail strict, with exact counts.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 2
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_unknown_status_fails_on_mt_system_in_strict_mode(self):
        # Only the disclosed lossy lone class qualifies on
        # mt-system: an unknown status with one gap still fails.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "unknown", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_count_mismatch_fails_on_mt_system_in_strict_mode(self):
        # The mt-system lone arm never waives exact owned counts:
        # one disclosed gap with a 39/40 deficit still fails.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
            d["functions"][0]["calls"] = 39
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("owned target count differs", result["detail"])

    def test_lone_gap_with_solo_other_gap_fails_on_mt_system_in_strict_mode(self):
        # Zero descendant gaps with a solo other gap kind is not
        # the lone descendant gap on mt-system either.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 0
            d["evidence"]["multi_rebuild_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["multi_rebuild_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_modules_skipped_fails_on_mt_system_in_strict_mode(self):
        # Mt-system twin of the system modules-skipped pin: one
        # disclosed descendant gap bundled with a skipped module
        # still fails strict at the gap gate, with exact counts.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["modules_skipped"] = [
                {"name": "discovery subject", "reason": "discovery unavailable"}]
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_lone_gap_with_other_class_fails_on_mt_system_in_strict_mode(self):
        # Mt-system twin of the system bundled-class pin: the lone
        # arm stays narrow, so a descendant gap bundled with any
        # other observation class still fails strict.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 1
            d["evidence"]["multi_rebuild_gaps"] = 1
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["pid_descendant_gaps", "multi_rebuild_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case_mt_system(mutate, want=1)
        self.assertIn("lossy or unknown observation gap class",
                      result["detail"])

    def test_attribution_gap_without_noise_passes_in_both_modes(self):
        # The system counts cell never gated attribution/semantics gaps
        # (strict discloses them via PARTIAL); relaxed mode must accept
        # them too, otherwise it would be stricter than strict. Shape
        # mirrors hosted run 41743410302 (attribution_only, zero noise).
        def mutate(d, l, r):
            d["evidence"].update(semantic_unverified_slots=6,
                                  completeness="PARTIAL",
                                  verdict_detail="attribution_only")
            d["evidence"]["gap_classes"]["attribution"] = {
                "status": "withheld", "causes": ["semantic_unverified_slots"]}
            d["evidence"]["gap_classes"]["semantics"] = {
                "status": "not_applicable", "causes": []}
        strict = self.run_case(mutate, cell="system")
        self.assertEqual(strict["qualification"], "owned-provider-counts")
        relaxed = self.run_case(mutate, cell="system",
                                allow_pid_descendant_gaps=True)
        self.assertTrue(relaxed["pass"])
        self.assertIn("disclosed runner noise", relaxed["detail"])

    def test_skip_family_passes_on_system_when_allowed(self):
        # Controller ruling 2026-11-09 07:50 (supersedes the U1
        # mt-system-only pin): every system-scope cell discloses
        # exactly the named family; the flag keeps its runner-noise
        # qualification and now prints both counts.
        def mutate(d, l, r):
            d["evidence"]["pid_descendant_gaps"] = 41
            d["evidence"]["skipped"] = [{"name": "discovery subject",
                                         "reason": "discovery unavailable"}]
            d["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["skipped", "pid_descendant_gaps"]}
            d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
        result = self.run_case(mutate, cell="system", allow_pid_descendant_gaps=True)
        self.assertEqual(result["qualification"], "owned-provider-counts-with-runner-noise")
        self.assertIn("pid_descendant_gaps=41", result["detail"])
        self.assertIn("discovery_skips=1", result["detail"])


def burst_census(*, ambient=0, workload_tree=(), observer_tree=(), baseline_exits=(),
                 kthreads=(), extra_baselines=(), workload=123, observer=456, broken=None,
                 harness=None, harness_tree=(), logins=0, broken_chain=()):
    """Synthetic system-cell census: `ambient` foreign ssh-avalanche exits
    (login-bash children in their own session), plus in-window exits in
    the workload, observer and harness trees, pre-existing foreign exits,
    kernel-thread exits and `logins` mid-capture login sessions (a session
    leader and its shell, both born in-window), all joined against the
    same capture window. `broken_chain` exits carry an unrecorded ppid,
    so their ancestry is unknown, never foreign. `broken` corrupts the
    evidence one way (garbage, workload-mismatch, no-markers or
    no-observer) for the fail-loud twins."""
    rows = [{"type": "header", "schema": "p11scope/system-cell-census/v1",
             "workload_pid": workload, "poll_ms": 5, "census_start_mono_ns": 0}]
    rows.append({"type": "baseline", "pid": 1, "ppid": 0, "pgrp": 1,
                 "session": 1, "flags": 0, "starttime": 1})
    rows.append({"type": "baseline", "pid": 100, "ppid": 99, "pgrp": 100,
                 "session": 100, "flags": 0, "starttime": 10})
    rows.append({"type": "baseline", "pid": 123, "ppid": 100, "pgrp": 100,
                 "session": 100, "flags": 0, "starttime": 11})
    rows.append({"type": "baseline", "pid": 50, "ppid": 1, "pgrp": 50,
                 "session": 50, "flags": 0, "starttime": 5})
    if harness is not None:
        rows.append({"type": "baseline", "pid": harness, "ppid": 1, "pgrp": harness,
                     "session": harness, "flags": 0, "starttime": 6})
    for pid, ppid in extra_baselines:
        rows.append({"type": "baseline", "pid": pid, "ppid": ppid, "pgrp": 100,
                     "session": 100, "flags": 0, "starttime": 11})
    rows.append({"type": "birth", "pid": 456, "ppid": 100, "pgrp": 100,
                 "session": 100, "flags": 0, "starttime": 12, "seen_mono_ns": 100})
    rows.append({"type": "birth", "pid": 501, "ppid": 50, "pgrp": 501,
                 "session": 501, "flags": 0, "starttime": 13, "seen_mono_ns": 200})
    rows.append({"type": "birth", "pid": 502, "ppid": 501, "pgrp": 501,
                 "session": 501, "flags": 0, "starttime": 14, "seen_mono_ns": 300})
    rows.append({"type": "marker", "name": "capturing", "seen_mono_ns": 1000})
    tick = 1100
    for i in range(ambient):
        pid = 1000 + i
        rows.append({"type": "birth", "pid": pid, "ppid": 502, "pgrp": 501,
                     "session": 501, "flags": 0, "starttime": 100 + i, "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 100 + i,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for pid in workload_tree:
        rows.append({"type": "birth", "pid": pid, "ppid": 123, "pgrp": 100,
                     "session": 100, "flags": 0, "starttime": 500 + pid, "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 500 + pid,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for pid in observer_tree:
        rows.append({"type": "birth", "pid": pid, "ppid": 456, "pgrp": 100,
                     "session": 100, "flags": 0, "starttime": 600 + pid, "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 600 + pid,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for pid in harness_tree:
        assert harness is not None, "harness_tree needs the harness root pid"
        rows.append({"type": "birth", "pid": pid, "ppid": harness, "pgrp": harness,
                     "session": harness, "flags": 0, "starttime": 900 + pid, "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 900 + pid,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for login in range(logins):
        leader, shell = 2000 + 2 * login, 2001 + 2 * login
        rows.append({"type": "birth", "pid": leader, "ppid": 1, "pgrp": leader,
                     "session": leader, "flags": 0, "starttime": 950 + leader,
                     "seen_mono_ns": tick})
        rows.append({"type": "birth", "pid": shell, "ppid": leader, "pgrp": leader,
                     "session": leader, "flags": 0, "starttime": 950 + shell,
                     "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": leader, "starttime": 950 + leader,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        rows.append({"type": "exit", "pid": shell, "starttime": 950 + shell,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for pid in baseline_exits:
        rows.append({"type": "baseline", "pid": pid, "ppid": 50, "pgrp": 50,
                     "session": 50, "flags": 0, "starttime": 700 + pid})
        rows.append({"type": "exit", "pid": pid, "starttime": 700 + pid,
                     "birth_seen_mono_ns": None, "exit_seen_mono_ns": tick})
        tick += 1
    for pid in broken_chain:
        rows.append({"type": "birth", "pid": pid, "ppid": 9999, "pgrp": pid,
                     "session": pid, "flags": 0, "starttime": 960 + pid, "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 960 + pid,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    for pid in kthreads:
        rows.append({"type": "birth", "pid": pid, "ppid": 2, "pgrp": 0,
                     "session": 0, "flags": 0x00200000, "starttime": 800 + pid,
                     "seen_mono_ns": tick})
        rows.append({"type": "exit", "pid": pid, "starttime": 800 + pid,
                     "birth_seen_mono_ns": tick, "exit_seen_mono_ns": tick + 50})
        tick += 1
    rows.append({"type": "marker", "name": "settled", "seen_mono_ns": 2000})
    rows.append({"type": "observer", "pid": observer})
    if harness is not None:
        rows.append({"type": "harness", "pid": harness})
    rows.append({"type": "trailer", "census_stop_mono_ns": 2100})
    if broken == "workload-mismatch":
        rows[0]["workload_pid"] = 999
    if broken == "no-markers":
        rows = [row for row in rows if row.get("type") != "marker"]
    if broken == "no-observer":
        rows = [row for row in rows if row.get("type") != "observer"]
    text = "\n".join(json.dumps(row) for row in rows) + "\n"
    if broken == "garbage":
        text += "not json\n"
    return text


def burst_mutate(gaps):
    def mutate(d, l, r):
        d["evidence"]["pid_descendant_gaps"] = gaps
        d["evidence"]["gap_classes"]["observation"] = {
            "status": "lossy", "causes": ["pid_descendant_gaps"]}
        d["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
    return mutate


def phase_mutate(gaps, *, loop_start, loop_end):
    """The lone burst shape plus the product's own capture-loop window:
    the census join clamps to it, so exits outside never count."""
    def mutate(d, l, r):
        burst_mutate(gaps)(d, l, r)
        d["evidence"]["scheduling"]["phase_mono_ns"] = {
            "attach_mono_ns": 900, "loop_start_mono_ns": loop_start,
            "loop_end_mono_ns": loop_end, "loop_end_reason": "expiry"}
    return mutate


class BurstClassificationTests(unittest.TestCase):
    """Ambient-burst arm, evidence-only: the census join is appended to
    the failure detail and never accepts a burst; only the lone-gap arm
    passes, with exact owned counts."""
    run_case = OracleTests.run_case
    run_case_mt_system = RunnerNoiseTests.run_case_mt_system

    def test_burst_fully_joined_stays_a_failure_with_census_evidence(self):
        # The sm1 shape (pdg=37, census-joined ssh avalanche): count
        # cover is not proof, so the cell still fails, with the exact
        # join accounting in the detail.
        result = self.run_case(burst_mutate(37), cell="system", want=1,
                               census=burst_census(ambient=37))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=37", result["detail"])
        self.assertIn("workload_unproven=0", result["detail"])
        self.assertIn("observer_tree_exits_observed=0", result["detail"])

    def test_burst_with_one_unproven_gap_stays_a_failure_with_census_evidence(self):
        # 37 joined ambient plus one unattributed gap: evidence, not a
        # pass; the lone-gap ceiling no longer reaches past one gap.
        result = self.run_case(burst_mutate(38), cell="system", want=1,
                               census=burst_census(ambient=37))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=37", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_burst_with_two_unproven_gaps_fails_in_strict_mode(self):
        # Two unattributed gaps are not a lone gap, however large the
        # joined ambient burst beside them.
        result = self.run_case(burst_mutate(39), cell="system", want=1,
                               census=burst_census(ambient=37))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=37", result["detail"])
        self.assertIn("workload_unproven=2", result["detail"])

    def test_burst_over_join_is_noted_never_raised(self):
        # The census can join more exits than the product gaps (a login
        # bash the scope walk listed is no gap): the note records the
        # over-join and the cell fails on its gap count, never on the
        # join arithmetic.
        result = self.run_case(burst_mutate(37), cell="system", want=1,
                               census=burst_census(ambient=38))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("over-join", result["detail"])
        self.assertIn("ambient_proven=38", result["detail"])

    def test_over_join_with_lone_gap_reports_the_gap(self):
        # One gap with two joined exits: the over-join never raises, so
        # the lone-gap arm passes exactly the cell that passes today.
        result = self.run_case(burst_mutate(1), cell="system",
                               census=burst_census(ambient=2))
        self.assertEqual(result["qualification"], "owned-provider-counts-with-ambient-gap")
        self.assertIn("pid_descendant_gaps=1", result["detail"])

    def test_workload_tree_exits_are_never_joined(self):
        # A census exit descending from the workload is not ambient: it
        # never joins, and the two-gap cell fails with the workload
        # observation in the census note.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=1, workload_tree=(124,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=1", result["detail"])
        self.assertIn("workload_tree_exits_observed=1", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])
        result = self.run_case(burst_mutate(3), cell="system", want=1,
                               census=burst_census(ambient=1, workload_tree=(124,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])

    def test_observer_tree_exits_are_never_joined(self):
        # Observer children (a regressed self-probe fork) are not ambient
        # either: two of them with no foreign burst still fail strict.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(observer_tree=(457, 458)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("observer_tree_exits_observed=2", result["detail"])

    def test_malformed_census_fails_loud_instead_of_lone_pass(self):
        # Corrupt census evidence fails closed: one gap with a garbage
        # census must not silently fall back to the lone-gap pass.
        result = self.run_case(burst_mutate(1), cell="system", want=1,
                               census=burst_census(ambient=1, broken="garbage"))
        self.assertIn("census", result["detail"])
        self.assertNotIn("lossy or unknown observation gap class", result["detail"])

    def test_census_bound_to_launched_pid(self):
        # A census for another workload proves nothing about this cell.
        result = self.run_case(burst_mutate(37), cell="system", want=1,
                               census=burst_census(ambient=37, broken="workload-mismatch"))
        self.assertIn("census workload", result["detail"])

    def test_pre_existing_foreign_exits_are_not_joined(self):
        # A foreign exit without an in-window birth was alive at the
        # initial scope walk, so it was listed, not a gap: it never
        # joins, and the two-gap cell fails with one proven ambient.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=1, baseline_exits=(777,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=1", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_burst_keeps_counts_exact(self):
        # The census arm never waives exact owned counts: a 499/500
        # deficit with a fully joined lone gap still fails strict on
        # the counts, past the gap gate.
        def mutate(d, l, r):
            burst_mutate(1)(d, l, r)
            d["functions"][0]["calls"] = 499
        result = self.run_case(mutate, cell="system", want=1,
                               census=burst_census(ambient=1))
        self.assertIn("owned target count differs", result["detail"])

    def test_burst_with_provider_linked_hint_fails(self):
        # The provider-subject check still guards the lone gap the
        # census arm annotates: a hint linking a gap subject to the
        # watched provider is not ambient.
        def mutate(d, l, r):
            burst_mutate(1)(d, l, r)
            d["evidence"]["gap_exe_hints"] = {
                "label": "STATIC HINT", "scope": "test",
                "links_provider": 1, "links_pkcs11_loader": 0,
                "no_static_link_within_scope": 0, "unknown": 0}
        result = self.run_case(mutate, cell="system", want=1,
                               census=burst_census(ambient=1))
        self.assertIn("ambient gap subject links the watched provider", result["detail"])

    def test_burst_without_window_markers_fails(self):
        # No capture window, no join: a census that never observed the
        # capturing/settled markers cannot place any exit in-window.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=2, broken="no-markers"))
        self.assertIn("census capture window", result["detail"])

    def test_burst_without_observer_pid_fails(self):
        # No single observer pid, no observer tree to exclude: the join
        # cannot tell a regressed self-probe fork from ambient, so the
        # census fails closed.
        result = self.run_case(burst_mutate(37), cell="system", want=1,
                               census=burst_census(ambient=37, broken="no-observer"))
        self.assertIn("census names no single observer pid", result["detail"])

    def test_lone_gap_with_full_census_join_reports_the_gap(self):
        # One gap fully joined by the census stays the lone ambient
        # gap: the evidence-only arm annotates failures, never labels
        # passes.
        result = self.run_case(burst_mutate(1), cell="system",
                               census=burst_census(ambient=1))
        self.assertEqual(result["qualification"], "owned-provider-counts-with-ambient-gap")
        self.assertIn("pid_descendant_gaps=1", result["detail"])

    def test_lone_gap_with_zero_ambient_joins_reports_the_gap(self):
        # The quiet-host everyday case: one gap, nothing joined, is the
        # lone ambient gap, not a burst (nothing burst and nothing was
        # proven ambient).
        result = self.run_case(burst_mutate(1), cell="system",
                               census=burst_census(ambient=0))
        self.assertEqual(result["qualification"], "owned-provider-counts-with-ambient-gap")
        self.assertIn("pid_descendant_gaps=1", result["detail"])

    def test_burst_stays_a_failure_on_mt_system_with_census_evidence(self):
        # Mt-system twin: the ledger children are workload roots, the
        # foreign avalanche joins the same way, and the cell still
        # fails with the accounting in the detail.
        mt_census = burst_census(ambient=5, extra_baselines=[(124, 123), (125, 123),
                                                             (126, 123), (127, 123)])
        result = self.run_case_mt_system(burst_mutate(5), want=1, census=mt_census)
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=5", result["detail"])
        self.assertIn("workload_unproven=0", result["detail"])

    def test_burst_with_two_unproven_gaps_fails_on_mt_system_in_strict_mode(self):
        # The mt-system failure carries the same census accounting.
        mt_census = burst_census(ambient=5, extra_baselines=[(124, 123), (125, 123),
                                                             (126, 123), (127, 123)])
        result = self.run_case_mt_system(burst_mutate(7), want=1, census=mt_census)
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=5", result["detail"])
        self.assertIn("workload_unproven=2", result["detail"])

    def test_kernel_thread_exits_are_never_joined(self):
        # A PF_KTHREAD exit inside the window is not a user gap the
        # product would count, so it never joins: one joined ambient
        # plus one kthread exit fails with a remainder of one.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=1, kthreads=(31,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=1", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_harness_tree_exits_are_never_joined(self):
        # The harness tail (terminate sleeps) forks inside the capture
        # window: harness-tree exits are a never-joined root, so one
        # in-window harness child plus one foreign exit fails a
        # two-gap cell with exactly one proven ambient.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=1, harness=789,
                                                   harness_tree=(790,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=1", result["detail"])
        self.assertIn("harness_tree_exits_observed=1", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_mid_capture_login_avalanche_joins_as_ambient(self):
        # A login session born mid-capture (leader plus shell, own
        # session, complete chain to init) joins as ambient evidence:
        # two joined exits against three gaps fail with the count.
        result = self.run_case(burst_mutate(3), cell="system", want=1,
                               census=burst_census(logins=1))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=2", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_broken_ancestry_chain_is_unknown_never_foreign(self):
        # An exit whose ppid was never recorded proves nothing about
        # its tree: it stays unknown, never joins as ambient, and the
        # two-gap cell fails with one proven ambient beside it.
        result = self.run_case(burst_mutate(2), cell="system", want=1,
                               census=burst_census(ambient=1, broken_chain=(5000,)))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=1", result["detail"])
        self.assertIn("unknown_ancestry_exits_observed=1", result["detail"])
        self.assertIn("workload_unproven=1", result["detail"])

    def test_census_window_clamps_to_the_product_loop(self):
        # The product's own loop window clamps the census markers: both
        # foreign exits land outside the loop, so nothing joins and the
        # two-gap cell fails with zero proven ambient.
        result = self.run_case(phase_mutate(2, loop_start=1900, loop_end=1950),
                               cell="system", want=1,
                               census=burst_census(ambient=2))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=0", result["detail"])
        self.assertIn("workload_unproven=2", result["detail"])

    def test_census_window_covering_loop_joins_inside_it(self):
        # A loop window covering the census markers changes nothing:
        # both foreign exits sit inside both windows and join.
        result = self.run_case(phase_mutate(2, loop_start=1000, loop_end=2000),
                               cell="system", want=1,
                               census=burst_census(ambient=2))
        self.assertIn("lossy or unknown observation gap class", result["detail"])
        self.assertIn("ambient_proven=2", result["detail"])
        self.assertIn("workload_unproven=0", result["detail"])

    def test_duplicate_census_exits_fail_loud(self):
        # One process exits once: a doubled exit line is corrupt
        # evidence, and double-joining it would mask a workload gap.
        census = burst_census(ambient=1)
        doubled = census + [line for line in census.splitlines()
                            if '"exit"' in line][0] + "\n"
        result = self.run_case(burst_mutate(2), cell="system", want=1, census=doubled)
        self.assertIn("census exit is recorded twice", result["detail"])


# Test-only independent mapping code runs in both separate lifecycle children.
FAKE_MAPPING = '''
def mapped_identity(path):
 import ctypes,mmap
 with open(path,'rb') as stream:
  with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_COPY) as view:
   address=ctypes.addressof(ctypes.c_char.from_buffer(view))
   found=[]
   for line in pathlib.Path('/proc/self/maps').read_text().splitlines():
    fields=line.split(); lo,hi=(int(v,16) for v in fields[0].split('-'))
    if lo<=address<hi: found.append(([int(v,16) for v in fields[3].split(':')],int(fields[4])))
   assert len(found)==1
   return found[0]
'''

FAKE_FIXTURE = '''#!/usr/bin/python3
import json, os, pathlib, signal, sys, time
''' + FAKE_MAPPING + '''
cell = os.environ.get('CONTROL_CELL', 'profile-pid')
if cell == 'mt-exact':
 module, threads, secs, pre, gate = sys.argv[1:]; iters = '7'
else: module, iters, pace, gate = sys.argv[1:]
root = pathlib.Path(gate).parent
(root / 'fixture.pid').write_text(str(os.getpid()))
mode = os.environ['CONTROL_MODE']
names = ['C_GenerateRandom','C_DigestInit','C_Digest','C_FindObjectsInit','C_FindObjects','C_FindObjectsFinal']
if cell == 'mt-exact': names=names[:1]
dev,ino = mapped_identity(module)
for i, name in enumerate(names):
 print('TARGET '+json.dumps({'name':name,'dev':dev,'ino':ino,'file_offset':4096+i*16}), flush=True)
print('READY pid=%d' % (123 if mode=='wrong-ready-pid' else os.getpid()), flush=True)
while not pathlib.Path(gate).exists(): time.sleep(.02)
(root / 'readiness-before-release.json').write_text(json.dumps(
 'p11scope: capturing:' in (root / (cell + '.stderr')).read_text()))
(root / 'released').write_text('yes')
if mode != 'missing-ledger':
 print('LEDGER '+json.dumps({'schema':'p11scope/public-cli-ledger/v1','pid':os.getpid(),'complete':True,
 'functions':[{'name':n,'attempts':int(iters),'successful':int(iters)} for n in names]}), flush=True)
if cell == 'mt-exact' and mode != 'missing-ledger': sys.exit(0)
signal.signal(signal.SIGTERM, lambda a,b: sys.exit(0))
while True: time.sleep(.02)
'''
FAKE_OBSERVER = '''#!/usr/bin/python3
import hashlib,json,os,pathlib,signal,sys,time
''' + FAKE_MAPPING + '''
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]); root=pathlib.Path(os.environ.get('CONTROL_OUT',str(out.parent)))
(root / 'selected-output.json').write_text(json.dumps(str(out)))
(root / 'observer-argv.json').write_text(json.dumps(sys.argv[1:]))
(root / 'observer.pid').write_text(str(os.getpid()))
shim_log=os.environ.get('SHIM_LOG')
if shim_log:
 with open(shim_log,'a') as f: f.write('OBSERVER_START' + chr(10))
mode=os.environ['CONTROL_MODE']
if mode=='exits-before-ready': sys.exit(17)
if mode=='ignore-term': signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode in ('never-ready','stale-output','ignore-term'):
 while True: time.sleep(.02)
print('p11scope: capturing: controlled',file=sys.stderr,flush=True)
while not (root/(out.stem+'.gate')).exists(): time.sleep(.02)
time.sleep(.1)
module=pathlib.Path(os.environ['MODULE']); dev,ino=mapped_identity(module)
obj={'dev':dev,'ino':ino,'sha256':hashlib.sha256(module.read_bytes()).hexdigest()}
names=['C_GenerateRandom','C_DigestInit','C_Digest','C_FindObjectsInit','C_FindObjects','C_FindObjectsFinal']
if out.stem == 'mt-exact': names=names[:1]
report=json.loads(pathlib.Path(os.environ['CONTROL_REPORT']).read_text())
report['functions']=report['functions'][:len(names)]
report['evidence']['slots']=len(names)
for i,row in enumerate(report['functions']):
 row['target']={'object':obj,'file_offset':4096+i*16}
 row['module']=obj
report['evidence']['discovery']=[dict(obj,path=str(module),tables=[{}])]
out.write_text(json.dumps(report))
if shim_log:
 with open(shim_log,'a') as f: f.write('OBSERVER_EXIT' + chr(10))
'''

FAKE_SIGNAL_PARENT = '''#!/usr/bin/python3
import json,os,pathlib,signal,subprocess,sys,time
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);root=pathlib.Path(os.environ.get('CONTROL_OUT',str(out.parent)))
(root/'selected-output.json').write_text(json.dumps(str(out)))
self_stat=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()
(root/'signal-parent.json').write_text(json.dumps({'pid':os.getpid(),'generation':int(self_stat[19])}))
received=0
def interrupt(a,b):
 global received
 received+=1
signal.signal(signal.SIGINT,interrupt)
mode=os.environ['CONTROL_SIGNAL_MODE']
print('p11scope: capturing: controlled signal parent',file=sys.stderr,flush=True)
if mode=='delayed': time.sleep(.4)
command=sys.argv[sys.argv.index('--')+1:]
if mode=='missing-pid': command[2]=command[2].replace('echo $$ > "$1";', '')
if mode=='wrong-parent':
 pathlib.Path(command[-1]).write_text(os.environ['CONTROL_UNRELATED_PID'])
else:
 child=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 stat=pathlib.Path('/proc/%d/stat'%child.pid).read_text().rsplit(') ',1)[1].split()
 (root/'actual-child.json').write_text(json.dumps({'pid':child.pid,'generation':int(stat[19])}))
while received<2: time.sleep(.02)
out.write_text(json.dumps({'schema':'p11scope/observed-profile/v3','evidence':{'completeness':'PARTIAL','drain_proven':True,'stop_quiescence':{'state':'proven','post_q_events':False,'post_q_discovery':False},'scheduling':{'inter_drain_gap':{'samples':5}},'child_still_running':False}}))
print('p11scope: cleanup incomplete',file=sys.stderr,flush=True)
sys.exit(130)
'''


class SignalCustodyTests(unittest.TestCase):
    def control(self, mode, want, *, local_output=False):
        with tempfile.TemporaryDirectory() as raw:
            tmp=Path(raw);observer=tmp/'observer';out=tmp/'out';out.mkdir()
            observer.write_text(FAKE_SIGNAL_PARENT);observer.chmod(0o700)
            sentinel=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(20)'])
            env=dict(os.environ,CONTROL_SIGNAL_MODE=mode,CONTROL_UNRELATED_PID=str(sentinel.pid),
                     RUNUID=str(os.getuid()),RUNGID=str(os.getgid()),CONTROL_OUT=str(out))
            local=tmp/'local disk';local.mkdir(mode=0o700)
            if local_output: env['P11SCOPE_LOCAL_OUTPUT_ROOT']=str(local)
            try:
                args=['bash',str(SHELL),'--control-second-sigint',str(observer),str(out)]
                proc=subprocess.run(args,env=env,text=True,capture_output=True,timeout=9)
                self.assertEqual(proc.returncode,want,proc.stdout+proc.stderr)
                rows=[json.loads(line) for line in (out/'results.jsonl').read_text().splitlines()]
                self.assertEqual(len(rows),1,rows)
                self.assertEqual(rows[0]['cell'],'second-sigint')
                self.assertEqual(rows[0]['pass'],want==0)
                if local_output:
                    selected=Path(json.loads((out/'selected-output.json').read_text()))
                    self.assertTrue(selected.is_relative_to(local))
                    self.assertEqual((out/'sigint2.json').read_bytes(), selected.read_bytes())
                self.assertIsNone(sentinel.poll(),'cleanup killed the unrelated sentinel')
                path=out/'actual-child.json'
                if path.exists():
                    child=json.loads(path.read_text())
                    self.assertFalse(self.running(child),'authenticated child survived runner cleanup')
            finally:
                path=out/'actual-child.json'
                if path.exists():
                    child=json.loads(path.read_text())
                    if self.running(child): os.kill(child['pid'],9)
                path=out/'signal-parent.json'
                if path.exists():
                    parent=json.loads(path.read_text())
                    if self.running(parent): os.kill(parent['pid'],9)
                sentinel.terminate();sentinel.wait(timeout=2)

    @staticmethod
    def running(child):
        try:
            stat=Path('/proc/%d/stat'%child['pid']).read_text().rsplit(') ',1)[1].split()
            return int(stat[19])==child['generation'] and stat[0]!='Z'
        except FileNotFoundError:
            return False

    def test_r3_delayed_child_pid_has_bounded_owned_cleanup(self):
        self.control('delayed',0)

    def test_guest_signal_output_copies_bytes_after_owned_cleanup(self):
        self.control('delayed',0,local_output=True)

    def test_r3_missing_child_pid_fails_without_leaking_owned_child(self):
        self.control('missing-pid',1)

    def test_r3_wrong_parent_pid_fails_and_preserves_unrelated_process(self):
        self.control('wrong-parent',1)


class ShellControls(unittest.TestCase):
    def control(self, mode, want, cell="profile-pid", *, unrelated=False, local_output=False):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fixture, observer, module = [tmp / p for p in ("fixture", "observer", "module")]
            fixture.write_text(FAKE_FIXTURE); observer.write_text(FAKE_OBSERVER)
            fixture.chmod(0o700); observer.chmod(0o700); module.write_text("independent provider")
            out = tmp / "out"; out.mkdir()
            if mode == "stale-output":
                (out / "profile-pid.stderr").write_text("p11scope: capturing: stale\n")
                (out / "profile-pid.json").write_text(json.dumps(inputs()[0]))
                (out / "profile-pid.wl").write_text("READY pid=123\n" + inputs()[1][-1])
            report = inputs(system=cell == "system")[0]
            if mode == "unproven-drain":
                report["evidence"]["drain_proven"] = False
            template=tmp / "report-template.json";template.write_text(json.dumps(report))
            local = tmp / "local disk"; local.mkdir(mode=0o700)
            env = dict(os.environ, CONTROL_MODE=mode, CONTROL_CELL=cell, MODULE=str(module),
                       ITERS="500" if cell == "system" else "7", CONTROL_REPORT=str(template),
                       CONTROL_OUT=str(out))
            env.pop("P11SCOPE_LOCAL_OUTPUT_ROOT", None)
            if local_output: env["P11SCOPE_LOCAL_OUTPUT_ROOT"] = str(local)
            sentinel = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(20)"]) if unrelated else None
            try:
                proc = subprocess.run(["bash", str(SHELL), "--control-gated", str(observer),
                                       str(out), str(fixture), cell], env=env, text=True,
                                      capture_output=True, timeout=8)
                self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
                rows = [json.loads(s) for s in (out / "results.jsonl").read_text().splitlines()]
                self.assertEqual(len(rows), 1, rows)
                self.assertEqual(rows[0]["cell"], cell)
                self.assertEqual(rows[0]["pass"], want == 0)
                if sentinel is not None:
                    self.assertIsNone(sentinel.poll(), "runner cleanup killed an unrelated process")
                if mode in ("never-ready", "exits-before-ready", "stale-output", "wrong-ready-pid"):
                    self.assertFalse((out / "released").exists())
                if cell == "system" and (out / "observer-argv.json").exists():
                    argv = json.loads((out / "observer-argv.json").read_text())
                    self.assertNotIn("--pid", argv)
                    self.assertEqual(argv, ["profile", "--system", "--module", str(module),
                                            "--duration", "25", "-o", str(out / "system.json")])
                if want == 0 or mode in ("missing-ledger", "unproven-drain"):
                    self.assertTrue((out / "released").exists())
                    self.assertIs(json.loads((out / "readiness-before-release.json").read_text()), True)
                if want == 0:
                    if cell == "system":
                        ledger = [json.loads(line[7:]) for line in (out / "system.wl").read_text().splitlines()
                                  if line.startswith("LEDGER ")]
                        self.assertEqual(len(ledger), 1)
                        self.assertIs(ledger[0]["complete"], True)
                        self.assertEqual([(row["name"], row["attempts"], row["successful"])
                                          for row in ledger[0]["functions"]], [(name, 500, 500) for name in NAMES])
                        receipt = json.loads((out / "system.receipt.json").read_text())
                        self.assertEqual((receipt["observer_exit"], receipt["workload_exit"]), (0, 0))
                        self.assertTrue(receipt["workload_ready"] and receipt["capture_ready"] and receipt["gate_released"])
                        self.assertIs(json.loads((out / "system.json").read_text())["evidence"]["drain_proven"], True)
                    if not local_output:
                        selected = Path(json.loads((out / "selected-output.json").read_text()))
                        self.assertEqual(selected, out / (cell + ".json"))
                        self.assertEqual(list(local.iterdir()), [])
                if local_output:
                    selected = Path(json.loads((out / "selected-output.json").read_text()))
                    self.assertTrue(selected.is_relative_to(local), "product output did not use the local disk root")
                    self.assertFalse(selected.is_relative_to(out))
                    self.assertEqual(json.loads((out / (cell + ".json")).read_text())["schema"], "p11scope/observed-profile/v3")
                for name in ("fixture.pid", "observer.pid"):
                    path = out / name
                    if path.exists():
                        with self.assertRaises(ProcessLookupError):
                            os.kill(int(path.read_text()), 0)
            finally:
                if sentinel is not None:
                    sentinel.terminate(); sentinel.wait(timeout=2)
                # Only direct fake fixture/observer children created by this case.
                for name in ("fixture.pid", "observer.pid"):
                    path = out / name
                    if path.exists():
                        try: os.kill(int(path.read_text()), 9)
                        except ProcessLookupError: pass

    def test_ready_completed_ledger_control(self):
        self.control("healthy", 0)

    def test_system_control_uses_strict_argv_and_500_call_ledgers(self):
        self.control("healthy", 0, "system", unrelated=True)

    def test_system_capture_spawns_no_runner_subprocesses(self):
        # A system-scope capture counts every ambient process exit as a
        # descendant gap, so the runner must poll the capture window with
        # shell builtins only: no sleep/grep/touch while the observer runs.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fixture, observer, module = [tmp / p for p in ("fixture", "observer", "module")]
            fixture.write_text(FAKE_FIXTURE); observer.write_text(FAKE_OBSERVER)
            fixture.chmod(0o700); observer.chmod(0o700); module.write_text("independent provider")
            out = tmp / "out"; out.mkdir()
            template = tmp / "report-template.json"
            template.write_text(json.dumps(inputs(system=True)[0]))
            shims = tmp / "shims"; shims.mkdir()
            log = tmp / "shim.log"
            for name in ("sleep", "grep", "touch"):
                real = shutil.which(name)
                self.assertIsNotNone(real, "test host lacks " + name)
                (shims / name).write_text(
                    "#!/bin/bash\necho \"CALL %s $*\" >> \"$SHIM_LOG\"\nexec \"%s\" \"$@\"\n" % (name, real))
                (shims / name).chmod(0o755)
            env = dict(os.environ, CONTROL_MODE="healthy", CONTROL_CELL="system", MODULE=str(module),
                       ITERS="500", CONTROL_REPORT=str(template), CONTROL_OUT=str(out),
                       SHIM_LOG=str(log), PATH=str(shims) + ":" + os.environ["PATH"])
            env.pop("P11SCOPE_LOCAL_OUTPUT_ROOT", None)
            proc = subprocess.run(["bash", str(SHELL), "--control-gated", str(observer),
                                   str(out), str(fixture), "system"],
                                  env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            try:
                lines = log.read_text().splitlines()
            finally:
                for name in ("fixture.pid", "observer.pid"):
                    path = out / name
                    if path.exists():
                        try: os.kill(int(path.read_text()), 9)
                        except ProcessLookupError: pass
            self.assertIn("OBSERVER_START", lines)
            self.assertIn("OBSERVER_EXIT", lines)
            window = lines[lines.index("OBSERVER_START") + 1:lines.index("OBSERVER_EXIT")]
            calls = [line for line in window if line.startswith("CALL ")]
            self.assertEqual(calls, [], "runner spawned subprocesses during the system capture")

    def test_system_census_lifecycle_binds_window_and_trees(self):
        # Ambient-burst lane: a healthy CONTROL system cell leaves a
        # complete census (header bound to the launched workload, both
        # window markers, the observer and harness lines, trailer) for
        # the oracle.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fixture, observer, module = [tmp / p for p in ("fixture", "observer", "module")]
            fixture.write_text(FAKE_FIXTURE); observer.write_text(FAKE_OBSERVER)
            fixture.chmod(0o700); observer.chmod(0o700); module.write_text("independent provider")
            out = tmp / "out"; out.mkdir()
            template = tmp / "report-template.json"
            template.write_text(json.dumps(inputs(system=True)[0]))
            env = dict(os.environ, CONTROL_MODE="healthy", CONTROL_CELL="system", MODULE=str(module),
                       ITERS="500", CONTROL_REPORT=str(template), CONTROL_OUT=str(out))
            env.pop("P11SCOPE_LOCAL_OUTPUT_ROOT", None)
            proc = subprocess.Popen(["bash", str(SHELL), "--control-gated", str(observer),
                                     str(out), str(fixture), "system"],
                                    env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate(timeout=30)
            try:
                self.assertEqual(proc.returncode, 0, stdout + stderr)
                census = [json.loads(line) for line in (out / "system.census.jsonl").read_text().splitlines()
                          if line.strip()]
                kinds = [row["type"] for row in census]
                self.assertEqual(kinds[0], "header")
                self.assertIn("trailer", kinds)
                self.assertEqual(kinds[-2:], ["observer", "harness"])
                receipt = json.loads((out / "system.receipt.json").read_text())
                self.assertEqual(census[0]["schema"], "p11scope/system-cell-census/v1")
                self.assertEqual(census[0]["workload_pid"], receipt["launched_pid"])
                markers = [row["name"] for row in census if row["type"] == "marker"]
                self.assertEqual(markers, ["capturing", "settled"])
                observers = [row["pid"] for row in census if row["type"] == "observer"]
                self.assertEqual(observers, [int((out / "observer.pid").read_text())])
                harness = [row["pid"] for row in census if row["type"] == "harness"]
                self.assertEqual(harness, [proc.pid])
            finally:
                for name in ("fixture.pid", "observer.pid"):
                    path = out / name
                    if path.exists():
                        try: os.kill(int(path.read_text()), 9)
                        except ProcessLookupError: pass

    def test_system_never_ready_fails_without_release(self):
        self.control("never-ready", 1, "system")

    def test_system_observer_exit_before_ready_fails_without_release(self):
        self.control("exits-before-ready", 1, "system")

    def test_system_missing_ledger_fails_with_owned_cleanup(self):
        self.control("missing-ledger", 1, "system", unrelated=True)

    def test_system_wrong_ready_pid_fails_without_release(self):
        self.control("wrong-ready-pid", 1, "system")

    def test_system_unproven_drain_fails_with_owned_cleanup(self):
        self.control("unproven-drain", 1, "system")

    def test_guest_output_redirects_then_restores_verified_bytes(self):
        self.control("healthy", 0, local_output=True)

    def test_guest_output_redirect_preserves_fifo_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);out=root/'out';out.mkdir();local=root/'local';local.mkdir(mode=0o700)
            fixture=root/'fixture'
            fixture.write_text('#!/usr/bin/python3\nimport os,signal,time\nprint("READY pid=%d"%os.getpid(),flush=True)\nsignal.signal(signal.SIGTERM,lambda a,b:exit(0))\nwhile True: time.sleep(.02)\n')
            fixture.chmod(0o755)
            observer=root/'observer'
            observer.write_text('#!/usr/bin/python3\nimport json,os,pathlib,stat,sys\np=pathlib.Path(sys.argv[sys.argv.index("-o")+1])\npathlib.Path(os.environ["CONTROL_OUT"],"selected-output.json").write_text(json.dumps(str(p)))\nif stat.S_ISFIFO(p.stat().st_mode):\n print(f"output {p} exists and is a FIFO; refusing to replace it",file=sys.stderr);sys.exit(1)\np.write_text("{}");sys.exit(0)\n')
            observer.chmod(0o755)
            env=dict(os.environ,CONTROL_OUT=str(out),P11SCOPE_LOCAL_OUTPUT_ROOT=str(local))
            result=subprocess.run(['bash',str(SHELL),'--control-fifo',str(observer),str(out),str(fixture)],
                                  env=env,text=True,capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            rows=[json.loads(line) for line in (out/'results.jsonl').read_text().splitlines()]
            self.assertEqual([(row['cell'],row['pass']) for row in rows],[('fifo-refused',True)])
            self.assertTrue(stat.S_ISFIFO((out/'fifo').stat().st_mode))
            self.assertEqual(json.loads((out/'selected-output.json').read_text()),str(out/'fifo'))
            self.assertEqual(list(local.iterdir()),[])

    def test_never_ready_fails_without_release(self):
        self.control("never-ready", 1)

    def test_observer_exit_before_ready_fails_without_release(self):
        self.control("exits-before-ready", 1)

    def test_missing_ledger_fails(self):
        self.control("missing-ledger", 1)

    def test_stale_output_cannot_release_gate(self):
        self.control("stale-output", 1)

    def test_wrong_workload_ready_pid_fails_without_release(self):
        self.control("wrong-ready-pid", 1)

    def test_mt_ready_and_completed_ledger_with_workload_already_exited(self):
        self.control("healthy", 0, "mt-exact")

    def test_mt_never_ready_fails_without_release(self):
        self.control("never-ready", 1, "mt-exact")

    def test_cleanup_is_bounded_when_observer_ignores_term(self):
        self.control("ignore-term", 1)

    def test_cleanup_preserves_an_unrelated_process(self):
        self.control("never-ready", 1, unrelated=True)


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
U C_GenerateRandom(U s,unsigned char*b,U n){(void)s;(void)b;(void)n;return getenv("FAIL_RANDOM")?1:0;}
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


class MappedPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = runpy.run_path(str(PIN))

    def test_real_pin_matches_independent_mapping_and_hash(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            content = b"short nonempty held provider"
            path.write_bytes(content)
            want_dev, want_ino = independent_mapping_identity(path)
            result = self.helper["pin"](path)
            self.assertEqual(result["dev"], want_dev)
            self.assertEqual(result["ino"], want_ino)
            self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(result["mapping"]["permissions"], "r--p")
            self.assertEqual(result["mapping"]["file_offset"], 0)
            info = path.stat()
            self.assertEqual(result["file_identity"], {
                "dev": [os.major(info.st_dev), os.minor(info.st_dev)], "ino": info.st_ino,
                "size": len(content), "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns})

    def test_held_fd_rename_and_path_replacement_keeps_original(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            old = Path(raw) / "renamed"
            original = b"original provider bytes"
            path.write_bytes(original)
            with path.open("rb") as stream:
                path.rename(old)
                path.write_bytes(b"replacement provider bytes")
                want_dev, want_ino = independent_mapping_identity(old)
                result = self.helper["pin_fd"](stream.fileno())
                self.assertEqual((result["dev"], result["ino"]), (want_dev, want_ino))
                self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
                self.assertNotEqual(result["ino"], path.stat().st_ino)

    def test_empty_and_nonregular_fd_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            empty = Path(raw) / "empty"
            empty.touch()
            for path in (empty, Path(raw)):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.helper["pin"](path)

    def test_short_hash_read_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            path.write_bytes(b"provider bytes")
            with patch("os.pread", side_effect=[b"short", b""]):
                with self.assertRaisesRegex(ValueError, "short read"):
                    self.helper["pin"](path)

    def test_fd_metadata_change_during_pin_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            path.write_bytes(b"original")
            probe = self.helper["mapping_from_fd"]

            def replace_bytes(fd, size):
                anchor = probe(fd, size)
                path.write_bytes(b"modified")
                os.utime(path, ns=(1, 2))
                return anchor

            with patch.dict(self.helper["pin_fd"].__globals__, mapping_from_fd=replace_bytes):
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.helper["pin"](path)

    def test_unmappable_opath_fd_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            path.write_bytes(b"provider bytes")
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                with self.assertRaises(OSError):
                    self.helper["pin_fd"](fd)
            finally:
                os.close(fd)

    def test_self_maps_read_or_parse_failure_unmaps_probe(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "provider"
            path.write_bytes(b"provider bytes")
            with path.open("rb") as stream:
                inode = str(os.fstat(stream.fileno()).st_ino)
                for error in (OSError("maps unreadable"), None):
                    with self.subTest(error=error):
                        kwargs = {"side_effect": error} if error else {"return_value": io.StringIO("malformed\n")}
                        with patch("builtins.open", **kwargs), self.assertRaises((OSError, ValueError)):
                            self.helper["mapping_from_fd"](stream.fileno(), path.stat().st_size)
                        rows = [line.split() for line in Path("/proc/self/maps").read_text().splitlines()]
                        self.assertFalse([row for row in rows if row[4] == inode and str(path) in row])

    def test_missing_duplicate_malformed_or_wrong_offset_maps_anchor_refused(self):
        valid = "1000-2000 r--p 00000000 00:23 71 /provider\n"
        bad = ("", valid + valid, "malformed\n", valid.replace("00000000", "00001000"),
               valid.replace(" 71 ", " 72 "), valid.replace("r--p", "r-xp"),
               valid.replace("2000", "1000"), valid.replace("2000", "1001"))
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.helper["maps_anchor"](text, 0x1000, 4096, 71)

    def test_valid_maps_anchor_accepts_its_device_without_stat_guess(self):
        anchor = self.helper["maps_anchor"]("1000-2000 r--p 00000000 00:23 71 /provider\n", 0x1000, 4096, 71)
        self.assertEqual(anchor, {"dev": [0, 35], "ino": 71, "file_offset": 0,
                                  "length": 4096, "permissions": "r--p"})


class NativeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.storage.name)
        source = cls.tmp / "provider.c"; source.write_text(PROVIDER)
        cls.module = cls.tmp / "provider.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(cls.module), str(source)], check=True)
        for name in ("gated", "mt"):
            subprocess.run(["gcc", "-O1", "-o", str(cls.tmp / name),
                            str(ROOT / "tests/fixtures/public-cli" / (name + ".c")),
                            "-ldl", "-lpthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def check_ledger(self, proc, names, count=None, *, identity_gate=True):
        targets = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("TARGET ")]
        self.assertEqual({row["name"] for row in targets}, set(names), proc.stdout)
        ledgers = [json.loads(line[7:]) for line in proc.stdout.splitlines() if line.startswith("LEDGER ")]
        self.assertEqual(len(ledgers), 1, proc.stdout)
        self.assertTrue(ledgers[0]["complete"])
        self.assertEqual({row["name"] for row in ledgers[0]["functions"]}, set(names))
        mapped_dev, mapped_ino = independent_mapping_identity(self.module)
        symbols = subprocess.run(["nm", "-D", "--defined-only", str(self.module)],
                                 check=True, capture_output=True, text=True).stdout
        addresses = {line.split()[2]: int(line.split()[0], 16) for line in symbols.splitlines()}
        data = self.module.read_bytes()
        # Independent ELF PT_LOAD translation of exported symbol addresses.
        phoff = struct.unpack_from("<Q", data, 32)[0]
        entsize, entries = struct.unpack_from("<HH", data, 54)
        segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize) for i in range(entries)]
        for row in targets:
            if identity_gate:
                self.assertEqual(row["dev"], mapped_dev)
                self.assertEqual(row["ino"], mapped_ino)
            address = addresses[row["name"]]
            offsets = [p[2] + address - p[3] for p in segments if p[0] == 1 and p[3] <= address < p[3] + p[5]]
            self.assertEqual(offsets, [row["file_offset"]])
        if count is not None:
            for row in ledgers[0]["functions"]:
                self.assertEqual(row["attempts"], count)
        return ledgers[0]

    def test_gated_independent_targets_and_successful_counts(self):
        proc = subprocess.run([str(self.tmp / "gated"), str(self.module), "3", "0", "-"],
                              capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ledger = self.check_ledger(proc, NAMES, 3)
        self.assertEqual([r["successful"] for r in ledger["functions"]], [3] * 6)

    def test_gated_nonzero_calls_are_not_successful_counts(self):
        proc = subprocess.run([str(self.tmp / "gated"), str(self.module), "3", "0", "-"],
                              env=dict(os.environ, FAIL_RANDOM="1"), capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        ledger = self.check_ledger(proc, NAMES, 3)
        self.assertEqual(ledger["functions"][0]["successful"], 0)

    def test_mt_independent_target_and_counts(self):
        proc = subprocess.run([str(self.tmp / "mt"), str(self.module), "2", "1", "0"],
                              capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ledger = self.check_ledger(proc, [NAMES[0]])
        self.assertGreater(ledger["functions"][0]["successful"], 0)
        self.assertEqual(ledger["functions"][0]["attempts"], ledger["functions"][0]["successful"])

    def test_gated_offsets_counts_without_namespace_identity_claim(self):
        proc = subprocess.run([str(self.tmp / "gated"), str(self.module), "3", "0", "-"],
                              capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ledger = self.check_ledger(proc, NAMES, 3, identity_gate=False)
        self.assertEqual([r["successful"] for r in ledger["functions"]], [3] * 6)

    def test_gated_failed_counts_without_namespace_identity_claim(self):
        proc = subprocess.run([str(self.tmp / "gated"), str(self.module), "3", "0", "-"],
                              env=dict(os.environ, FAIL_RANDOM="1"), capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        ledger = self.check_ledger(proc, NAMES, 3, identity_gate=False)
        self.assertEqual(ledger["functions"][0]["successful"], 0)

    def test_mt_offsets_counts_without_namespace_identity_claim(self):
        proc = subprocess.run([str(self.tmp / "mt"), str(self.module), "2", "1", "0"],
                              capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ledger = self.check_ledger(proc, [NAMES[0]], identity_gate=False)
        self.assertGreater(ledger["functions"][0]["successful"], 0)
        self.assertEqual(ledger["functions"][0]["attempts"], ledger["functions"][0]["successful"])


CENSUS = ROOT / "scripts/system-cell-census.py"


class CensusTests(unittest.TestCase):
    """The system-cell census records fork-free /proc ancestry for the burst arm."""

    def test_census_is_fork_free_by_construction(self):
        text = CENSUS.read_text(encoding="utf-8")
        for banned in ("subprocess", "os.system", "os.spawn", "os.fork",
                       "os.exec", "os.posix_spawn", "popen(", "check_output"):
            self.assertNotIn(banned, text,
                             "the census poll loop must never fork inside a system capture")

    def test_system_census_settled_is_written_before_the_workload_stops(self):
        # The capture window closes when the observer settles, before
        # the harness tail (terminate sleeps) forks: past the observer
        # settle, every workload stop in gated() must land after the
        # settled write, and the census must bind the harness root the
        # oracle never joins. (Pre-capture failure exits stop the
        # workload with no window at all and stay out of scope.)
        text = SHELL.read_text(encoding="utf-8")
        start = text.index("gated() {")
        following = text.index("counter_build_supported() {", start)
        gated = text[start:following]
        settled_region = gated[gated.index('then terminate "$pp"; observer_rc=$LAST_EXIT; fi'):]
        settled = '>> "$cell.census.settled"'
        self.assertEqual(settled_region.count(settled), 1,
                         "gated() must write the settled marker exactly once past the settle")
        mark = settled_region.index(settled)
        stops = []
        for needle in ('finish "$wl"', 'terminate "$wl"'):
            at = settled_region.find(needle)
            while at != -1:
                stops.append(at)
                at = settled_region.find(needle, at + 1)
        self.assertTrue(stops, "gated() must stop its workload")
        for stop in stops:
            self.assertLess(mark, stop,
                            "the settled marker must precede every workload stop")
        self.assertIn('"type": "harness"',
                      gated, "gated() must bind the harness root pid for the census")

    def test_census_records_births_exits_and_window_markers(self):
        children = 3
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            out, stop = tmp / "census.jsonl", tmp / "stop"
            capturing, settled, ready = tmp / "capturing", tmp / "settled", tmp / "ready"
            proc = subprocess.Popen(
                [sys.executable, "-I", str(CENSUS), "--out", str(out),
                 "--stop", str(stop), "--workload", str(os.getpid()),
                 "--capturing", str(capturing), "--settled", str(settled),
                 "--ready", str(ready),
                 "--poll-ms", "5"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.time() + 10
                while time.time() < deadline and not ready.exists():
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "the census never finished its baseline: " +
                                (proc.stderr.read() if proc.poll() is not None else "still running"))
                capturing.touch()
                kids = [subprocess.Popen(
                    [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    for _ in range(children)]
                try:
                    deadline = time.time() + 10
                    mine = []
                    while time.time() < deadline and len(mine) < children:
                        time.sleep(0.02)
                        try:
                            text = out.read_text(encoding="utf-8")
                        except OSError:
                            continue
                        mine = [json.loads(line) for line in text.splitlines()
                                if line.strip() and json.loads(line).get("type") == "birth"
                                and json.loads(line).get("ppid") == os.getpid()]
                    self.assertEqual(
                        len(mine), children,
                        "every spawned child is birth-recorded with its ppid "
                        "(census alive=%s, kids alive=%s)" % (
                            proc.poll() is None,
                            [kid.poll() is None for kid in kids]))
                    for kid in kids:
                        kid.terminate()
                    for kid in kids:
                        kid.wait(timeout=10)
                finally:
                    for kid in kids:
                        if kid.poll() is None:
                            kid.kill()
                            kid.wait(timeout=5)
                settled.touch()
                stop.touch()
                _, stderr = proc.communicate(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0, stderr)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        kinds = [row["type"] for row in rows]
        self.assertEqual(kinds[0], "header")
        self.assertEqual(kinds[-1], "trailer")
        header = rows[0]
        self.assertEqual(header["schema"], "p11scope/system-cell-census/v1")
        self.assertEqual(header["workload_pid"], os.getpid())
        self.assertEqual(header["poll_ms"], 5)
        self.assertIs(type(header["census_start_mono_ns"]), int)
        baselines = [row for row in rows if row["type"] == "baseline"]
        self.assertTrue(any(row["pid"] == os.getpid() for row in baselines),
                        "the census baselines its live workload")
        births = [row for row in rows if row["type"] == "birth"]
        exits = [row for row in rows if row["type"] == "exit"]
        mine = [row for row in births if row["ppid"] == os.getpid()]
        self.assertGreaterEqual(len(mine), children,
                                "every spawned child is birth-recorded with its ppid")
        for row in mine:
            for key in ("pid", "ppid", "pgrp", "session", "flags", "starttime", "seen_mono_ns"):
                self.assertIs(type(row[key]), int, key)
            self.assertEqual(row["session"], os.getsid(os.getpid()))
            match = [exit for exit in exits
                     if exit["pid"] == row["pid"] and exit["starttime"] == row["starttime"]]
            self.assertEqual(len(match), 1, "each birth has exactly one matched exit")
            self.assertGreaterEqual(match[0]["exit_seen_mono_ns"], row["seen_mono_ns"])
        markers = [row for row in rows if row["type"] == "marker"]
        self.assertEqual([row["name"] for row in markers], ["capturing", "settled"])
        self.assertLessEqual(markers[0]["seen_mono_ns"], markers[1]["seen_mono_ns"])
        self.assertLessEqual(header["census_start_mono_ns"], markers[0]["seen_mono_ns"])
        self.assertLessEqual(markers[1]["seen_mono_ns"], rows[-1]["census_stop_mono_ns"])
        self.assertNotIn("comm", json.dumps(rows), "the census records ancestry, never names")
        self.assertNotIn("cmd", json.dumps(rows), "the census records ancestry, never command lines")

    def test_census_refuses_a_non_pid_workload(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            proc = subprocess.run(
                [sys.executable, "-I", str(CENSUS), "--out", str(tmp / "o"),
                 "--stop", str(tmp / "s"), "--workload", "0",
                 "--capturing", str(tmp / "c"), "--settled", str(tmp / "e"),
                 "--ready", str(tmp / "r")],
                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
