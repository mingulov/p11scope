#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed 104-slot ABI execution driver twins (fake outputs, owned inputs).

Twins for scripts/qualify-abi-execution.py: the profile-to-counts
conversion, the S1 report gates, the ledger binding, the oracle judging
seam and the verdict aggregation, all against canned ledgers and canned
profile documents. No root, no BPF, no observer: every live behavior is
covered by the guest qualification run instead.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = ROOT / "scripts" / "qualify-abi-execution.py"
ORACLE_PATH = ROOT / "scripts" / "joint-abi-compare.py"
EVIDENCE_PATH = ROOT / "scripts" / "check-capture-evidence.py"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    DRIVER = load_module("qualify_abi_execution", DRIVER_PATH)
except OSError:
    DRIVER = None

try:
    ORACLE = load_module("joint_abi_compare", ORACLE_PATH)
except OSError:
    ORACLE = None

try:
    EVIDENCE = load_module("check_capture_evidence", EVIDENCE_PATH)
except OSError:
    EVIDENCE = None


def require_driver(test):
    if DRIVER is None:
        test.fail(f"driver missing: {DRIVER_PATH} (implementation not present)")
    return DRIVER


def require_oracle(test):
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


def require_evidence(test):
    if EVIDENCE is None:
        test.fail(f"evidence reader missing: {EVIDENCE_PATH}")
    return EVIDENCE


PIN = {"dev": [8, 1], "ino": 424242, "sha256": "0" * 64}


def build_ledger(entries, cond="threads", cell="threads", pid=4242, tid=4242):
    """Canned ABI ledger over (entry, fn, rv) triples plus unreturned entries."""
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": 1000,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    tick = 1000
    seq = 0
    calls = 0
    blocked = 0

    def stamp(step=10):
        nonlocal tick
        tick += step
        return tick

    for item in entries:
        seq += 1
        if len(item) == 4:
            entry, fn, rv, returned = item
        else:
            entry, fn, rv = item
            returned = True
        if returned:
            t0 = stamp()
            t1 = stamp(5)
            rows.append({"kind": "call", "seq": seq, "entry": entry,
                         "fn": fn, "rv": rv, "pid": pid, "tid": tid,
                         "t0": t0, "t1": t1, "cond": cond, "cell": cell})
            calls += 1
        else:
            rows.append({"kind": "entry", "seq": seq, "entry": entry,
                         "fn": fn, "pid": pid, "tid": tid, "t0": stamp(),
                         "cond": cond, "cell": cell})
            blocked += 1
    rows.append({"kind": "ack", "issued": calls, "blocked": blocked,
                 "t": tick + 10})
    return rows


def function_row(entry, name, calls, rv_counts, ordinal=Path("x"), **over):
    _ = ordinal
    row = {"names": [name], "aliased": False,
           "target": {"object": dict(PIN), "file_offset": 0x1000 + entry},
           "ordinals": [{"table_file_offset": 0x2000, "ordinal": entry}],
           "module": dict(PIN), "module_ambiguous": False,
           "module_unresolved": False, "calls": calls,
           "errors": 0, "pending_returns": 0, "in_flight": 0,
           "latency_ns": None, "rv_counts": dict(rv_counts)}
    row.update(over)
    return row


def export_row(name="C_GetFunctionList", **over):
    row = {"names": [name], "aliased": False,
           "target": {"object": dict(PIN), "file_offset": 0x500},
           "ordinals": [], "module": dict(PIN),
           "module_ambiguous": False, "module_unresolved": False,
           "calls": 0, "errors": 0, "pending_returns": 0, "in_flight": 0,
           "latency_ns": None, "rv_counts": {}}
    row.update(over)
    return row


SEMANTICS_COUNTERS = (
    "semantic_capture_failures", "template_tail_failures",
    "process_tracking_failures", "process_tracking_evictions",
    "state_reconciliations", "session_cancel_ambiguities",
    "session_cancel_unknown_flags", "operation_state_imports",
    "auth_state_ambiguities", "async_target_failures", "async_orphans",
    "async_duplicates", "async_evictions", "fork_state_ambiguities",
    "semantic_state_drops", "semantic_history_drops", "pending_at_end",
)


def build_evidence(driver, functions, *, slots=104, unverified=104,
                   extra=None):
    """Self-consistent gated-attach-late evidence (PARTIAL/concrete_gap).

    Carries exactly the pinned observation disclosure: one unprotected
    live window, an unproven exit-time loader hit, and an absent uncovered
    selection binding, over a fully walked 104-function surface.
    """
    evidence = {
        "slots": slots, "semantic_unverified_slots": unverified,
        "unprotected_live_windows": 1, "module_unresolved_slots": 0,
        "pause_partial": 0, "vendor_interfaces": 0,
        "drain_proven": True, "provider_changed": False,
        "templates_truncated": False,
        "scheduling": {"terminal_drain_truncated": False,
                       "sink_dropped_bytes": 0},
        "loader_discovery": {},
        "stop_quiescence": {"state": "proven", "post_q_events": False,
                            "post_q_discovery": False},
        "interface_selection": {"providers": [], "standard_exports": [],
                                "inventory_surfaces": [], "tuples": [],
                                "selection_truncated": False},
        "attach_mechanisms": ["per-offset"],
        "pid_descendant_gaps": 0, "multi_rebuild_gaps": 0,
        "attach_backend": {"selection": "singles", "fallback": None,
                           "scope_filter": "perf-task+bpf"},
        "gap_classes": {"stdout_data_sink": False},
        "completeness": "PARTIAL", "verdict_detail": "x",
        "kernel_control": {"capture_halted": False, "owner_poison": [],
                           "root_affiliation_failures": [],
                           "owner_admission_failures": 0,
                           "identity_unavailable": 0},
        "aliased": False, "module_ambiguous": 0,
        "unregistered_mechanisms": 0, "discovery_conflicts": 0,
        "discovery_uncorroborated": 0, "shape_decode_total_failures": 0,
        "scan_unavailable": None, "modules_skipped": [],
        "attach_failures": [], "skipped": [],
        "surfaces": [{"acquisition": "ok", "functions": 104,
                      "source": "stub table 3.2", "walk": "full"}],
        "interface_list": "",
        "pid_namespace": {"observer": "initial", "proc_pids": "observer"},
        "discovery": [{"dev": list(PIN["dev"]), "ino": PIN["ino"],
                       "sha256": PIN["sha256"]}],
    }
    for key in driver.LOSS_COUNTERS:
        evidence[key] = 0
    for key in SEMANTICS_COUNTERS:
        evidence[key] = 0
    for key in ("in_flight_at_end",):
        evidence.setdefault(key, 0)
    # check-capture-evidence COUNTERS beyond the loss tuple.
    for key in ("slots", "semantic_unverified_slots", "unprotected_live_windows",
                "module_unresolved_slots", "pause_partial", "vendor_interfaces"):
        evidence.setdefault(key, 0)
    try:
        counters = EVIDENCE.COUNTERS
    except AttributeError:
        counters = ()
    for key in counters:
        evidence.setdefault(key, 0)
    try:
        groups = EVIDENCE.LOADER_DISCOVERY_GROUPS
    except AttributeError:
        groups = {}
    for group, keys in groups.items():
        evidence["loader_discovery"][group] = dict.fromkeys(keys, 0)
    try:
        for key in EVIDENCE.LOADER_DISCOVERY_COUNTERS:
            evidence["loader_discovery"][key] = 0
    except AttributeError:
        pass
    if extra:
        evidence.update(extra)
    # The pinned attach-late disclosure inputs: one exit-time loader hit
    # with unproven timing, and one absent uncovered selection binding.
    evidence["loader_discovery"]["hits"] = 2
    evidence["loader_discovery"]["dlopen_timing"]["unproven"] = 1
    evidence["interface_selection"]["providers"] = [
        {"module": 0, "coverage": "absent_uncovered"}]
    functions = list(functions)
    document = {"schema": "p11scope/observed-profile/v3", "lane": "profile",
                "capture": {"mode": "profile", "scope": "pid"},
                "evidence": evidence, "functions": functions}
    EVIDENCE.settle_fixture_verdict(document)
    evidence["completeness"] = EVIDENCE.expected_terminal_completeness(evidence)
    return document


class CellTableTests(unittest.TestCase):
    def test_cells_cover_every_oracle_cond(self):
        driver = require_driver(self)
        oracle = require_oracle(self)
        self.assertEqual(set(driver.CELLS), set(oracle.CONDS))
        self.assertEqual(len(driver.COND_ORDER), 13)
        self.assertEqual(set(driver.COND_ORDER), set(oracle.CONDS))

    def test_cell_modes_are_fixture_shaped(self):
        driver = require_driver(self)
        allowed = {"full", "threads", "hot", "rv64", "entry", "blocked"}
        for cond, spec in driver.CELLS.items():
            with self.subTest(cond=cond):
                self.assertIn(spec["provider"], ("stub", "hibit"))
                mode = spec["mode"]
                valid = (mode in allowed or mode.startswith("cond:")
                         or mode.startswith("cell:"))
                self.assertTrue(valid, mode)
                if mode.startswith("cell:"):
                    self.assertTrue(re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}",
                                                mode[5:]), mode)
                if spec["provider"] == "hibit":
                    self.assertEqual(spec["workload_exit"], 1)
                else:
                    self.assertEqual(spec["workload_exit"], 0)

    def test_rv64_and_entry_and_cellrun_pin_twin_values(self):
        driver = require_driver(self)
        self.assertEqual(driver.CELLS["rv64"]["provider"], "hibit")
        self.assertEqual(driver.CELLS["entry"]["arg"], "103")
        self.assertEqual(driver.CELLS["cellrun"]["mode"], "cell:g31-575")
        self.assertEqual(driver.CELLS["threads"]["arg"], "4,25,5")
        self.assertEqual(driver.CELLS["hot"]["arg"], "8,50,5")

    def test_build_commands_mirror_oracle_twins(self):
        driver = require_driver(self)
        fixture = driver.gcc_fixture_cmd("gcc", "abi-104.c", "abi-104", False)
        self.assertEqual(fixture[:9],
                         ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra",
                          "-Werror", "-pthread", "abi-104.c", "-ldl"])
        self.assertTrue(fixture[-2:] == ["-o", "abi-104"])
        fixture32 = driver.gcc_fixture_cmd("gcc", "abi-104.c", "abi-104-32", True)
        self.assertIn("-m32", fixture32)
        provider = driver.gcc_provider_cmd("gcc", "provider.c", "provider.so", False)
        self.assertIn("-DP11SCOPE_EXPORT_TABLES=1", provider)
        self.assertIn("-shared", provider)
        self.assertIn("-Wl,-z,defs", provider)
        self.assertIn("-fPIC", provider)
        self.assertNotIn("-m32", provider)
        provider32 = driver.gcc_provider_cmd("gcc", "provider.c", "p32.so", True)
        self.assertIn("-m32", provider32)
        hibit = driver.gcc_provider_cmd("gcc", "hibit.c", "hibit.so", False,
                                        exports_macro=False)
        self.assertNotIn("-DP11SCOPE_EXPORT_TABLES=1", hibit)


class LedgerBindingTests(unittest.TestCase):
    def test_binding_accepts_matching_rows(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        keys = driver.check_ledger_binding(rows, "threads", "threads")
        self.assertEqual(keys, {("threads", 5)})

    def test_binding_collects_calls_and_entries(self):
        driver = require_driver(self)
        rows = build_ledger([(9, "C_InitToken", 0),
                             (10, "C_InitPIN", 0, False)],
                            cond="blocked", cell="blocked-unreturned")
        keys = driver.check_ledger_binding(rows, "blocked", "blocked-unreturned")
        self.assertEqual(keys, {("blocked-unreturned", 9),
                                ("blocked-unreturned", 10)})

    def test_binding_refuses_wrong_cond(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)], cond="hot", cell="hot-keys")
        with self.assertRaisesRegex(driver.DriverRefusal, "cond"):
            driver.check_ledger_binding(rows, "threads", "threads")

    def test_binding_refuses_wrong_cell(self):
        driver = require_driver(self)
        rows = build_ledger([(0, "C_Initialize", 0)], cond="cellrun",
                            cell="g31-575")
        with self.assertRaisesRegex(driver.DriverRefusal, "cell"):
            driver.check_ledger_binding(rows, "cellrun", "other-tag")

    def test_binding_refuses_empty_population(self):
        driver = require_driver(self)
        rows = build_ledger([])
        with self.assertRaisesRegex(driver.DriverRefusal, "without populations"):
            driver.check_ledger_binding(rows, "threads", "threads")


class CountsConversionTests(unittest.TestCase):
    def test_exact_threads_cell_converts(self):
        driver = require_driver(self)
        require_oracle(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)] * 100)
        ORACLE.validate_ledger(rows)
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 100,
                                  {"0x0000000000000000": 100}),
                     export_row()])
        converted = driver.counts_from_profile(report, rows, PIN,
                                               "threads", "threads")
        self.assertEqual(converted["counts"],
                         [{"kind": "counts", "cell": "threads", "entry": 5,
                           "fn": "C_GetSlotInfo", "calls": 100,
                           "returns": 100, "rv": [0] * 100}])
        result = ORACLE.compare_abi(rows, converted["counts"])
        self.assertEqual((result["keys"], result["calls"], result["returns"]),
                         (1, 100, 100))

    def test_in_flight_maps_to_unreturned_calls(self):
        driver = require_driver(self)
        rows = build_ledger([(9, "C_InitToken", 0),
                             (10, "C_InitPIN", 0, False)],
                            cond="blocked", cell="blocked-unreturned")
        report = build_evidence(
            driver, [function_row(9, "C_InitToken", 1,
                                  {"0000000000000000": 1}),
                     function_row(10, "C_InitPIN", 0, {}, in_flight=1),
                     export_row()])
        converted = driver.counts_from_profile(report, rows, PIN,
                                               "blocked", "blocked-unreturned")
        by_entry = {row["entry"]: row for row in converted["counts"]}
        self.assertEqual((by_entry[9]["calls"], by_entry[9]["returns"]), (1, 1))
        self.assertEqual((by_entry[10]["calls"], by_entry[10]["returns"]), (1, 0))
        self.assertEqual(by_entry[10]["rv"], [])

    def test_high_bit_rv_round_trip(self):
        driver = require_driver(self)
        self.assertEqual(driver.parse_rv_counts({"8000000000000001": 1}),
                         [0x8000000000000001])
        self.assertEqual(driver.parse_rv_counts({"0x8000000000000001": 1}),
                         [0x8000000000000001])
        self.assertEqual(driver.parse_rv_counts({"00000000ffffffff": 2}),
                         [0xFFFFFFFF, 0xFFFFFFFF])
        self.assertEqual(driver.parse_rv_counts({"0X00000000FFFFFFFF": 1}),
                         [0xFFFFFFFF])
        self.assertEqual(driver.parse_rv_counts({}), [])

    def test_unknown_name_passes_through_for_oracle(self):
        driver = require_driver(self)
        rows = build_ledger([(68, "P11ScopeSlot68", 0)], cond="full", cell="full")
        report = build_evidence(
            driver, [function_row(68, "unknown", 1,
                                  {"0000000000000000": 1})])
        converted = driver.counts_from_profile(report, rows, PIN, "full", "full")
        self.assertEqual(converted["counts"][0]["fn"], "unknown")

    def test_ambiguous_ordinal_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1}),
                     function_row(5, "C_GetSlotInfo", 0, {})])
        with self.assertRaisesRegex(driver.DriverRefusal, "ordinal 5"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")

    def test_shared_target_across_ledger_entries_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(0, "C_Initialize", 0), (1, "C_Finalize", 0)],
                            cond="cellrun", cell="g31-575")
        shared = function_row(0, "C_Initialize", 2, {"0000000000000000": 2})
        shared["ordinals"].append({"table_file_offset": 0x2000, "ordinal": 1})
        report = build_evidence(driver, [shared])
        with self.assertRaisesRegex(driver.DriverRefusal, "shares its target"):
            driver.counts_from_profile(report, rows, PIN, "cellrun", "g31-575")

    def test_noisy_ordinal_less_row_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1}),
                     export_row(calls=1, rv_counts={"0000000000000000": 1})])
        with self.assertRaisesRegex(driver.DriverRefusal, "ordinal"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")

    def test_off_ledger_activity_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1}),
                     function_row(6, "C_GetTokenInfo", 1,
                                  {"0000000000000000": 1})])
        with self.assertRaisesRegex(driver.DriverRefusal, "entry 6"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")

    def test_target_identity_mismatch_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        foreign = dict(PIN, ino=999)
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1},
                                  target={"object": foreign,
                                          "file_offset": 0x1005})])
        with self.assertRaisesRegex(driver.DriverRefusal, "target"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")

    def test_null_target_sha_tolerated_with_note(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        nosha = {"dev": list(PIN["dev"]), "ino": PIN["ino"], "sha256": None}
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1},
                                  target={"object": nosha,
                                          "file_offset": 0x1005})])
        converted = driver.counts_from_profile(report, rows, PIN,
                                               "threads", "threads")
        self.assertEqual(converted["counts"][0]["calls"], 1)
        self.assertIn("sha256_unavailable",
                      converted["diagnostics"].get("notes", []))

    def test_null_module_on_active_row_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0000000000000000": 1},
                                  module=None, module_unresolved=True)])
        with self.assertRaisesRegex(driver.DriverRefusal, "module"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")

    def test_malformed_rv_counts_refused(self):
        driver = require_driver(self)
        with self.assertRaisesRegex(driver.DriverRefusal, "rv_counts"):
            driver.parse_rv_counts({"zz": 1})
        with self.assertRaisesRegex(driver.DriverRefusal, "rv_counts"):
            driver.parse_rv_counts({"0000000000000000": -1})

    def test_missing_ordinal_row_refused(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        report = build_evidence(driver, [export_row()])
        with self.assertRaisesRegex(driver.DriverRefusal, "entry 5"):
            driver.counts_from_profile(report, rows, PIN, "threads", "threads")


class S1ReportGateTests(unittest.TestCase):
    def test_pinned_disclosure_accepted(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(
            driver, [function_row(5, "C_GetSlotInfo", 1,
                                  {"0x0000000000000000": 1})])
        self.assertEqual(report["evidence"]["verdict_detail"], "concrete_gap")
        self.assertEqual(report["evidence"]["completeness"], "PARTIAL")
        self.assertEqual(
            set(report["evidence"]["gap_classes"]["observation"]["causes"]),
            set(driver.PINNED_OBSERVATION_CAUSES))
        diagnostics = driver.check_s1_report(report, PIN)
        self.assertEqual(diagnostics["verdict_detail"], "concrete_gap")
        self.assertEqual(diagnostics["completeness"], "PARTIAL")
        self.assertEqual(set(diagnostics["observation_causes"]),
                         set(driver.PINNED_OBSERVATION_CAUSES))
        self.assertFalse(diagnostics["observation_exact"])

    def test_exact_observation_refused_as_unpinned(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [], slots=1, unverified=0)
        report["evidence"]["unprotected_live_windows"] = 0
        report["evidence"]["loader_discovery"]["hits"] = 0
        report["evidence"]["loader_discovery"]["dlopen_timing"]["unproven"] = 0
        report["evidence"]["interface_selection"]["providers"] = []
        EVIDENCE.settle_fixture_verdict(report)
        report["evidence"]["completeness"] = \
            EVIDENCE.expected_terminal_completeness(report["evidence"])
        self.assertEqual(report["evidence"]["completeness"], "COMPLETE")
        with self.assertRaisesRegex(driver.DriverRefusal, "pinned"):
            driver.check_s1_report(report, PIN)

    def test_extra_observation_cause_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["modules_skipped"] = [{"reason": "x"}]
        EVIDENCE.settle_fixture_verdict(report)
        with self.assertRaisesRegex(driver.DriverRefusal, "pinned"):
            driver.check_s1_report(report, PIN)

    def test_surface_without_full_walk_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["surfaces"] = []
        with self.assertRaisesRegex(driver.DriverRefusal, "surface"):
            driver.check_s1_report(report, PIN)

    def test_loss_counter_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["event_loss"] = 1
        with self.assertRaisesRegex(driver.DriverRefusal, "event_loss"):
            driver.check_s1_report(report, PIN)

    def test_lossy_observation_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["slots"] = 0
        EVIDENCE.settle_fixture_verdict(report)
        with self.assertRaisesRegex(driver.DriverRefusal, "observation"):
            driver.check_s1_report(report, PIN)

    def test_stale_classes_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["gap_classes"]["observation"]["status"] = "exact"
        with self.assertRaisesRegex(driver.DriverRefusal, "verdict|classes"):
            driver.check_s1_report(report, PIN)

    def test_degraded_semantics_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["semantic_capture_failures"] = 2
        EVIDENCE.settle_fixture_verdict(report)
        with self.assertRaisesRegex(driver.DriverRefusal, "semantics"):
            driver.check_s1_report(report, PIN)

    def test_unexpected_attribution_cause_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["module_ambiguous"] = 1
        EVIDENCE.settle_fixture_verdict(report)
        with self.assertRaisesRegex(driver.DriverRefusal, "attribution"):
            driver.check_s1_report(report, PIN)

    def test_wrong_schema_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["schema"] = "p11scope/observed-profile/v2"
        with self.assertRaisesRegex(driver.DriverRefusal, "schema"):
            driver.check_s1_report(report, PIN)

    def test_wrong_scope_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["capture"]["scope"] = "system"
        with self.assertRaisesRegex(driver.DriverRefusal, "scope"):
            driver.check_s1_report(report, PIN)

    def test_provider_not_admitted_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["discovery"] = [{"dev": [9, 9], "ino": 1,
                                            "sha256": "1" * 64}]
        with self.assertRaisesRegex(driver.DriverRefusal, "admitted"):
            driver.check_s1_report(report, PIN)

    def test_kernel_halt_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = build_evidence(driver, [export_row()])
        report["evidence"]["kernel_control"]["capture_halted"] = True
        with self.assertRaisesRegex(driver.DriverRefusal, "kernel|halted"):
            driver.check_s1_report(report, PIN)


class BlockedS1PinTests(unittest.TestCase):
    def blocked_report(self, driver, in_flight_at_end):
        return build_evidence(
            driver, [function_row(9, "C_InitToken", 1,
                                  {"0000000000000000": 1}),
                     function_row(10, "C_InitPIN", 0, {}, in_flight=1)],
            extra={"in_flight_at_end": in_flight_at_end})

    def test_blocked_in_flight_pin_accepted(self):
        driver = require_driver(self)
        require_evidence(self)
        report = self.blocked_report(driver, 1)
        self.assertIn("in_flight_at_end",
                      report["evidence"]["gap_classes"]["observation"]["causes"])
        diagnostics = driver.check_s1_report(
            report, PIN, expected_in_flight_at_end=1,
            extra_observation_causes={"in_flight_at_end"})
        self.assertEqual(set(diagnostics["observation_causes"]),
                         set(driver.PINNED_OBSERVATION_CAUSES)
                         | {"in_flight_at_end"})

    def test_blocked_in_flight_refused_by_default(self):
        driver = require_driver(self)
        require_evidence(self)
        report = self.blocked_report(driver, 1)
        with self.assertRaisesRegex(driver.DriverRefusal, "in_flight_at_end"):
            driver.check_s1_report(report, PIN)

    def test_blocked_in_flight_count_mismatch_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = self.blocked_report(driver, 2)
        with self.assertRaisesRegex(driver.DriverRefusal, "in_flight_at_end"):
            driver.check_s1_report(
                report, PIN, expected_in_flight_at_end=1,
                extra_observation_causes={"in_flight_at_end"})
        report = self.blocked_report(driver, 0)
        with self.assertRaisesRegex(driver.DriverRefusal, "in_flight_at_end"):
            driver.check_s1_report(
                report, PIN, expected_in_flight_at_end=1,
                extra_observation_causes={"in_flight_at_end"})

    def test_blocked_unpinned_cause_refused(self):
        driver = require_driver(self)
        require_evidence(self)
        report = self.blocked_report(driver, 1)
        with self.assertRaisesRegex(driver.DriverRefusal, "pinned"):
            driver.check_s1_report(report, PIN, expected_in_flight_at_end=1)


class BlockedEntryProofTests(unittest.TestCase):
    def test_capture_saw_entry_found(self):
        driver = require_driver(self)
        report = {"functions": [
            function_row(9, "C_InitToken", 1, {"0000000000000000": 1}),
            function_row(10, "C_InitPIN", 0, {}, in_flight=1)]}
        proof = driver.blocked_entry_in_flight(report)
        self.assertEqual((proof["calls"], proof["in_flight"]), (0, 1))

    def test_capture_missed_entry_refused(self):
        driver = require_driver(self)
        report = {"functions": [
            function_row(10, "C_InitPIN", 0, {})]}
        with self.assertRaisesRegex(driver.DriverRefusal, "in flight"):
            driver.blocked_entry_in_flight(report)

    def test_entry_row_missing_refused(self):
        driver = require_driver(self)
        report = {"functions": [
            function_row(9, "C_InitToken", 1, {"0000000000000000": 1})]}
        with self.assertRaisesRegex(driver.DriverRefusal, "entry 10"):
            driver.blocked_entry_in_flight(report)


class OracleSeamTests(unittest.TestCase):
    def test_healthy_ledger_judged_through_cli(self):
        driver = require_driver(self)
        require_oracle(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)] * 4)
        counts = [{"kind": "counts", "cell": "threads", "entry": 5,
                   "fn": "C_GetSlotInfo", "calls": 4, "returns": 4,
                   "rv": [0, 0, 0, 0]}]
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            counts_path = Path(tmp) / "counts.jsonl"
            with open(ledger, "w", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")
            with open(counts_path, "w", encoding="utf-8") as stream:
                for row in counts:
                    stream.write(json.dumps(row) + "\n")
            code, out, err = driver.judge_with_oracle(
                str(ORACLE_PATH), str(ledger), str(counts_path))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["calls"], 4)

    def test_mutated_counts_refused_through_cli(self):
        driver = require_driver(self)
        require_oracle(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)] * 4)
        counts = [{"kind": "counts", "cell": "threads", "entry": 5,
                   "fn": "C_GetSlotInfo", "calls": 3, "returns": 3,
                   "rv": [0, 0, 0]}]
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            counts_path = Path(tmp) / "counts.jsonl"
            with open(ledger, "w", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")
            with open(counts_path, "w", encoding="utf-8") as stream:
                for row in counts:
                    stream.write(json.dumps(row) + "\n")
            code, out, err = driver.judge_with_oracle(
                str(ORACLE_PATH), str(ledger), str(counts_path))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("calls disagree", err)


class DetailTests(unittest.TestCase):
    def test_healthy_detail_marks_all_ok(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)] * 3)
        counts = [{"kind": "counts", "cell": "threads", "entry": 5,
                   "fn": "C_GetSlotInfo", "calls": 3, "returns": 3,
                   "rv": [0, 0, 0]}]
        detail = driver.entry_detail(rows, counts)
        self.assertEqual(detail["mismatched_entries"], [])
        (entry,) = detail["entries"]
        self.assertTrue(entry["calls_ok"] and entry["returns_ok"]
                        and entry["fn_ok"] and entry["rv_ok"])

    def test_detail_localizes_dimensions(self):
        driver = require_driver(self)
        rows = build_ledger([(3, "P11ScopeSlot3", 0)])
        counts = [{"kind": "counts", "cell": "full", "entry": 3,
                   "fn": "C_GetFunctionList", "calls": 1, "returns": 1,
                   "rv": [0]}]
        rows[1]["cond"] = "full"
        rows[1]["cell"] = "full"
        detail = driver.entry_detail(rows, counts)
        self.assertEqual(detail["mismatched_entries"], [3])
        (entry,) = detail["entries"]
        self.assertTrue(entry["calls_ok"] and entry["returns_ok"]
                        and entry["rv_ok"])
        self.assertFalse(entry["fn_ok"])

    def test_detail_marks_missing_counts(self):
        driver = require_driver(self)
        rows = build_ledger([(5, "C_GetSlotInfo", 0)])
        detail = driver.entry_detail(rows, [])
        self.assertEqual(detail["mismatched_entries"], [5])
        self.assertTrue(detail["entries"][0]["missing_counts"])


class BuildRuleTests(unittest.TestCase):
    def test_build_all_produces_runnable_fixtures(self):
        driver = require_driver(self)
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        with tempfile.TemporaryDirectory() as tmp:
            built = driver.build_all("gcc", str(ROOT / "tests" / "fixtures"),
                                     str(Path(tmp) / "fix"), ["lp64", "ia32"])
            for arch in ("lp64", "ia32"):
                for name in ("fixture", "stub", "hibit"):
                    self.assertTrue(Path(built[arch][name]).is_file(), (arch, name))
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [built["lp64"]["fixture"], built["lp64"]["stub"],
                 str(ledger), "", "entry", "103"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_prebuilt_layout_missing_file_refused(self):
        driver = require_driver(self)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(driver.DriverRefusal, "prebuilt"):
                driver._prebuilt(tmp, ["lp64"])


class AggregationTests(unittest.TestCase):
    def test_all_pass_aggregates(self):
        driver = require_driver(self)
        results = [{"cell": "threads", "arch": "lp64", "passed": True},
                   {"cell": "hot", "arch": "lp64", "passed": True}]
        overall = driver.aggregate(results)
        self.assertTrue(overall["passed"])
        self.assertEqual(overall["cells"], 2)
        self.assertEqual(overall["failed"], [])

    def test_one_failure_fails_overall(self):
        driver = require_driver(self)
        results = [{"cell": "threads", "arch": "lp64", "passed": True},
                   {"cell": "blocked", "arch": "lp64", "passed": False,
                    "reason": "calls disagree"}]
        overall = driver.aggregate(results)
        self.assertFalse(overall["passed"])
        self.assertEqual(overall["failed"], ["blocked/lp64"])

    def test_empty_results_fail(self):
        driver = require_driver(self)
        overall = driver.aggregate([])
        self.assertFalse(overall["passed"])


class WaitHelperTests(unittest.TestCase):
    def test_match_returns_line(self):
        driver = require_driver(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.log"
            path.write_text("booting\nREADY pid=99\n", encoding="utf-8")
            line = driver.wait_for_match(str(path), r"^READY pid=99$", 5)
        self.assertEqual(line, "READY pid=99")

    def test_missing_pattern_times_out(self):
        driver = require_driver(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.log"
            path.write_text("nothing here\n", encoding="utf-8")
            line = driver.wait_for_match(str(path), r"^READY pid=", 1)
        self.assertIsNone(line)


if __name__ == "__main__":
    unittest.main()
