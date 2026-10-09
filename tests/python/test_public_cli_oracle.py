# SPDX-License-Identifier: GPL-3.0-or-later
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
import subprocess
import struct
import sys
import tempfile
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
    "semantic_history_drops", "pending_at_end", "orphan_ops", "unmatched_closes",
    "shape_decode_failures", "shape_decode_total_failures", "discovery_conflicts",
    "discovery_uncorroborated", "module_ambiguous", "semantic_unverified_slots",
    "module_unresolved_slots", "unprotected_live_windows", "pause_partial", "vendor_interfaces")
PROFILE_FIELDS = ("interface_selection", "attach_mechanisms", "attach_backend",
                  "pid_descendant_gaps", "multi_rebuild_gaps")


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


def inputs(*, metrics=False):
    targets = [{"name": name, "dev": [8, 1], "ino": 71,
                "file_offset": 4096 + i * 16} for i, name in enumerate(NAMES)]
    report = {"schema": "p11scope/observed-profile/v3",
              "lane": "profile", "capture": {"scope": "pid", "mode": "profile"},
              "functions": [{"names": [name], "calls": 7, "errors": 0, "in_flight": 0, "pending_returns": 0,
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
        attach_backend={"selection": "singles", "fallback": None, "scope_filter": "perf-task+bpf"},
        pid_descendant_gaps=0, multi_rebuild_gaps=0)
    if metrics:
        report["schema"] = "p11scope/observed-profile/v3-metrics"
        report["lane"] = report["capture"]["mode"] = "metrics"
        for key in PROFILE_FIELDS:
            del report["evidence"][key]
    ledger = ["TARGET " + json.dumps(row) for row in targets]
    ledger += ["READY pid=123", "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": 123, "complete": True,
        "functions": [{"name": name, "attempts": 7, "successful": 7}
                      for name in NAMES]})]
    receipt = {"schema": "p11scope/public-cli-receipt/v1", "cell": "profile-pid",
               "scope": "pid", "count_domain": "owned-provider",
               "launched_pid": 123, "generation": 456,
               "ready_pid": 123, "ready_generation": 456,
               "workload_ready": True, "capture_ready": True, "gate_released": True,
               "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
               "provider_before": provider_pin(), "provider_after": provider_pin()}
    return report, ledger, receipt


class OracleTests(unittest.TestCase):
    def run_case(self, mutate=None, *, cell="profile-pid", want=0):
        report, ledger, receipt = inputs(metrics=cell == "metrics-pid")
        receipt["cell"] = cell
        if cell == "system":
            receipt["scope"] = "system"
            report["capture"]["scope"] = "system"
            report["evidence"]["attach_backend"]["scope_filter"] = None
        if mutate:
            mutate(report, ledger, receipt)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt)):
                paths[key] = tmp / key
                text = json.dumps(value)
                if key == "report" and cell == "trace-pid":
                    text = "CALL → done\n" * 42
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

    def test_valid_profile(self):
        self.run_case()

    def test_valid_metrics(self):
        self.run_case(cell="metrics-pid")

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

    def test_run_smoke_nonqualifying(self):
        self.run_case(cell="run-short", want=2)

    def test_trace_smoke_nonqualifying(self):
        self.run_case(cell="trace-pid", want=2)

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

    def test_metrics_profile_only_inputs_fail(self):
        profile, _, _ = inputs()
        for key in PROFILE_FIELDS:
            with self.subTest(key=key):
                self.run_case(lambda d, l, r: d["evidence"].update({key: profile["evidence"][key]}),
                              cell="metrics-pid", want=1)


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
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]); root=out.parent
(root / 'observer.pid').write_text(str(os.getpid()))
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
'''

FAKE_SIGNAL_PARENT = '''#!/usr/bin/python3
import json,os,pathlib,signal,subprocess,sys,time
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);root=out.parent
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
out.write_text('{}')
print('p11scope: cleanup incomplete',file=sys.stderr,flush=True)
sys.exit(130)
'''


class SignalCustodyTests(unittest.TestCase):
    def control(self, mode, want):
        with tempfile.TemporaryDirectory() as raw:
            tmp=Path(raw);observer=tmp/'observer';out=tmp/'out';out.mkdir()
            observer.write_text(FAKE_SIGNAL_PARENT);observer.chmod(0o700)
            sentinel=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(20)'])
            env=dict(os.environ,CONTROL_SIGNAL_MODE=mode,CONTROL_UNRELATED_PID=str(sentinel.pid),
                     RUNUID=str(os.getuid()),RUNGID=str(os.getgid()))
            try:
                args=['bash',str(SHELL),'--control-second-sigint',str(observer),str(out)]
                proc=subprocess.run(args,env=env,text=True,capture_output=True,timeout=9)
                self.assertEqual(proc.returncode,want,proc.stdout+proc.stderr)
                rows=[json.loads(line) for line in (out/'results.jsonl').read_text().splitlines()]
                self.assertEqual(len(rows),1,rows)
                self.assertEqual(rows[0]['cell'],'second-sigint')
                self.assertEqual(rows[0]['pass'],want==0)
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

    def test_r3_missing_child_pid_fails_without_leaking_owned_child(self):
        self.control('missing-pid',1)

    def test_r3_wrong_parent_pid_fails_and_preserves_unrelated_process(self):
        self.control('wrong-parent',1)


class ShellControls(unittest.TestCase):
    def control(self, mode, want, cell="profile-pid", *, unrelated=False):
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
            template=tmp / "report-template.json";template.write_text(json.dumps(inputs()[0]))
            env = dict(os.environ, CONTROL_MODE=mode, CONTROL_CELL=cell, MODULE=str(module), ITERS="7", CONTROL_REPORT=str(template))
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
                if want == 0:
                    self.assertTrue((out / "released").exists())
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


if __name__ == "__main__":
    unittest.main()
