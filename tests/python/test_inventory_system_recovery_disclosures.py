#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline System recovery disclosures retain partial truth and exact workloads."""

import copy
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASE = runpy.run_path(str(ROOT / "tests/python/test_inventory_system_sibling.py"))
H6 = BASE["H6"]
MAPS = "process maps sweep"
CUSTODY = "semantic input refused"
TERMINAL = "native capture retirement unsettled"
RETIREMENT = ("the probes did not detach within 10000 ms; the document was written while the Inventory "
              "probes may still be attached, and they are reclaimed (blocking) after it")


def records(data):
    return data[2]["inventory_control"]["final_records"]


def insert(data, position, rows):
    """Insert publications while retaining every existing receipt's stream reference."""
    seen = set()
    def shift(value):
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                return
            seen.add(id(value))
        if isinstance(value, dict):
            if "command" not in value and type(value.get("seq")) is int and value["seq"] >= position:
                value["seq"] += len(rows)
            for child in value.values():
                shift(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                shift(child)
    shift(data)
    at_ns = records(data)[position]["at_ns"]
    for offset, row in enumerate(rows):
        row.update(schema="p11scope/inventory-events/v1", seq=position + offset, at_ns=at_ns)
    records(data)[position:position] = rows


def add_gap(data, subject, reason, position, repeats=1, caller=None, module=None):
    index = len(data[0]["gaps"])
    gap = {"subject": subject, "reason": reason, "caller": caller, "module": module,
           "pid": None, "budget": None, "repeats": repeats}
    data[0]["gaps"].append(gap)
    rows = [{"kind": "gap_recorded", "event": {"index": index,
        **{key: value for key, value in gap.items() if key != "repeats"}}}]
    if repeats > 1:
        rows.append({"kind": "gap_repeated", "event": {"index": index, "repeats": repeats}})
    insert(data, position, rows)
    return index


def refresh_successor_proof(data):
    control = data[2]["inventory_control"]
    measurement = control["measurements"][1]
    proof = measurement["proof"]
    image, admission = proof["image"], proof["admission"]
    owner = SimpleNamespace(pid=image["pid"], identity={"start_time": image["start_time"]})
    warm = proof["markers"][-1]
    population = [row for parsed in data[1].values() for row in parsed["batches"]
        if (row["pid"], row["gen"], row["module"]) == (owner.pid, 1, proof["provider"]["path"])]
    baseline = H6["inventory_boundary"](
        [row for row in records(data) if row["seq"] <= proof["baseline"]["pass"]["seq"]],
        owner, image, proof["provider"], admission, max(proof["cursor"]["seq"], admission["seq"]),
        warm, [row for row in population if row["t1"] <= warm["ack"]["t1"]],
        physical_hooks=proof["physical_hooks"], started_ns=proof["observer_started_ns"],
        recovery_from=control["measurements"][0])
    assert baseline is not None
    proof["baseline"] = baseline
    measurement["end"] = H6["inventory_boundary"](
        [row for row in records(data) if row["seq"] <= measurement["end"]["pass"]["seq"]],
        owner, image, proof["provider"], admission, baseline["pass"]["seq"],
        measurement["marker"], population, prior=baseline,
        physical_hooks=proof["physical_hooks"], started_ns=proof["observer_started_ns"])
    assert measurement["end"] is not None
    control["proofs"][1] = copy.deepcopy(proof)


def inputs(subject, *, placement=None, cap=None):
    data = BASE["controlled_inputs"]()
    doc, _ledgers, receipt = data
    stream = records(data)
    control = receipt["inventory_control"]
    if subject == MAPS:
        position = next(i for i, row in enumerate(stream) if row["kind"] == "pass_committed")
        if placement == "terminal":
            position = max(i for i, row in enumerate(stream)
                           if row["kind"] == "pass_committed" and not row["event"].get("final")) + 1
        index = add_gap(data, MAPS,
            "maps snapshots unavailable for 2 of 32 attempted processes; provider presence remains unknown", position)
        if cap is not None:
            total, missing = cap
            change_gap(data, index, "reason", f"maps snapshots unavailable for 2 of {total} attempted processes; "
                       "provider presence remains unknown")
            reason = (f"{total} processes in scope; 256 deep-scanned by provider rarity (limit 256); "
                "1 attributed to pinned provider objects by exact maps identity; "
                "5 processes map 3 shared objects no deep scan examined and may use undiscovered providers")
            if missing:
                reason += f"; {missing} processes past the cap had no maps snapshot"
            add_gap(data, "discovery capped", reason, position)
            completing = next(row for row in stream if row["kind"] == "pass_committed")
            completing["event"].update(scanned=257, maps_matched=1)
    elif subject == CUSTODY:
        successor = control["measurements"][1]["proof"]
        first = next(row for row in stream if row["kind"] == "instance_observed"
                     and row["event"]["id"] == successor["instance"])
        add_gap(data, "physical provider use preceded first observed semantic registration",
            "before_semantic_boundary", first["seq"], caller=successor["caller"], module=successor["module"])
        refresh_successor_proof(data)
        position = successor["admission"]["completed_pass"]["seq"]
        if placement == "before-exec":
            position = control["measurements"][0]["end"]["pass"]["seq"]
        elif placement == "after-registration":
            position = successor["baseline"]["pass"]["seq"]
        index = add_gap(data, CUSTODY, "custody", position, repeats=18)
    else:
        position = max(i for i, row in enumerate(stream)
                       if row["kind"] == "pass_committed" and not row["event"].get("final")) + 1
        if placement == "ordinary":
            position -= 1
        elif placement == "after-final":
            position = len(stream) - 1
        index = add_gap(data, TERMINAL, RETIREMENT, position)
        doc["observation"].update(retirement="unsettled", settlement="unsettled",
            ended_ns=stream[-1]["at_ns"], semantic_capture={"status": "stopped", "final_drain": False,
                "stop_quiescence": "quiesced", "unrouted_returns": 0})
        stream[-1]["event"].update(ended_ns=stream[-1]["at_ns"], passes=doc["observation"]["passes"],
                                  gaps_suppressed=0)
        receipt.update(forced_cleanup=False, stop_latency_seconds=18.9, stop_limit_seconds=30)
    return data, index


def change_gap(data, index, key, value):
    data[0]["gaps"][index][key] = value
    for row in records(data):
        if row["kind"] == "gap_recorded" and row["event"].get("index") == index:
            row["event"][key] = value


class SystemRecoveryDisclosureTest(unittest.TestCase):
    def assert_positive(self, data, index):
        result = H6["evaluate_inventory_h6"](*data)
        self.assertTrue(result["pass"], result["errors"])
        self.assertIn(data[0]["gaps"][index], result["expected_disclosures"])
        self.assertEqual(result["completed_operations"], 20)
        self.assertEqual(result["physical_counted"], result["physical_entered"])
        return result

    def assert_refused(self, data, index):
        result = H6["evaluate_inventory_h6"](*data)
        self.assertFalse(result["pass"])
        self.assertNotIn(data[0]["gaps"][index], result.get("expected_disclosures", []))

    def test_uncapped_partial_maps_sweep_remains_unresolved_with_exact_owned_outcomes(self):
        data, index = inputs(MAPS)
        self.assertFalse(any(row["subject"] == "discovery capped" for row in data[0]["gaps"]))
        self.assert_positive(data, index)

    def test_capped_maps_sweep_includes_selected_and_unselected_snapshot_failures(self):
        for missing in (0, 1, 2):
            with self.subTest(unselected_missing=missing):
                self.assert_positive(*inputs(MAPS, cap=(437, missing)))

    def test_maps_sweep_refuses_noncanonical_counts_and_contradictory_same_pass_cap(self):
        for reason in ("maps snapshots unavailable for 0 of 32 attempted processes; provider presence remains unknown",
                       "maps snapshots unavailable for 33 of 32 attempted processes; provider presence remains unknown",
                       "maps snapshots unavailable for 02 of 32 attempted processes; provider presence remains unknown",
                       "maps snapshots unavailable for 2 of 18446744073709551616 attempted processes; provider presence remains unknown"):
            with self.subTest(reason=reason):
                data, index = inputs(MAPS)
                change_gap(data, index, "reason", reason)
                self.assert_refused(data, index)
        data, index = inputs(MAPS, cap=(437, 3))
        self.assert_refused(data, index)
        data, index = inputs(MAPS, cap=(437, 1))
        change_gap(data, index, "reason",
            "maps snapshots unavailable for 2 of 438 attempted processes; provider presence remains unknown")
        self.assert_refused(data, index)

    def test_maps_repeat_needs_its_own_ordinary_completing_pass(self):
        data, index = inputs(MAPS)
        data[0]["gaps"][index]["repeats"] = 2
        position = [row for row in records(data) if row["kind"] == "pass_committed"][1]["seq"]
        insert(data, position, [{"kind": "gap_repeated", "event": {"index": index, "repeats": 2}}])
        self.assert_positive(data, index)
        data[0]["gaps"][index]["repeats"] = 3
        position = max(i for i, row in enumerate(records(data))
                       if row["kind"] == "pass_committed" and not row["event"].get("final")) + 1
        insert(data, position, [{"kind": "gap_repeated", "event": {"index": index, "repeats": 3}}])
        self.assert_refused(data, index)
        self.assert_refused(*inputs(MAPS, placement="terminal"))

    def test_clean_successor_recovery_keeps_coalesced_custody_refusals_unattributed(self):
        data, index = inputs(CUSTODY)
        self.assertIsNone(data[2]["inventory_control"]["measurements"][1]["proof"]["baseline"]["recovery"])
        self.assertGreater(data[0]["gaps"][index]["repeats"], data[0]["observation"]["passes"])
        result = self.assert_positive(data, index)
        self.assertIn("publication", result["s1"]["limitation"])
        self.assertIn("unattributed", result["s1"]["limitation"])

    def test_custody_refuses_pre_exec_and_post_registration_publications(self):
        for placement in ("before-exec", "after-registration"):
            with self.subTest(placement=placement):
                self.assert_refused(*inputs(CUSTODY, placement=placement))

    def test_custody_refuses_missing_early_boundary_or_changed_recovery_identity(self):
        for fault in ("early-gap", "retirement", "admission", "birth", "image"):
            with self.subTest(fault=fault):
                data, index = inputs(CUSTODY)
                proof = data[2]["inventory_control"]["measurements"][1]["proof"]
                admission = records(data)[proof["admission"]["seq"]]
                if fault == "early-gap":
                    early = proof["baseline"]["early"]["gaps"][0]
                    records(data)[early["seq"]]["event"]["reason"] = "unknown"
                elif fault == "retirement":
                    admission["event"]["old"] = "foreign"
                elif fault == "admission":
                    admission["event"]["new"] = "foreign"
                elif fault == "birth":
                    admission["event"]["identity_context"]["new"]["start_time"] += 1
                else:
                    admission["event"]["identity_context"]["new"]["executable"]["ino"] += 1
                self.assert_refused(data, index)

    def test_later_custody_repeat_cannot_borrow_an_earlier_recovery_publication(self):
        data, index = inputs(CUSTODY)
        data[0]["gaps"][index]["repeats"] = 19
        position = data[2]["inventory_control"]["measurements"][1]["end"]["pass"]["seq"]
        insert(data, position, [{"kind": "gap_repeated", "event": {"index": index, "repeats": 19}}])
        self.assert_refused(data, index)

    def test_custody_needs_an_ordinary_commit_before_first_successor_registration(self):
        data, index = inputs(CUSTODY)
        proof = data[2]["inventory_control"]["measurements"][1]["proof"]
        records(data)[proof["admission"]["completed_pass"]["seq"]]["kind"] = "incomplete_pass"
        self.assert_refused(data, index)

    def test_terminal_unsettled_retirement_retains_false_final_drain_and_normal_stop(self):
        data, index = inputs(TERMINAL)
        result = self.assert_positive(data, index)
        self.assertEqual(result["unresolved_observation"], {key: data[0]["observation"][key]
            for key in ("retirement", "settlement", "semantic_capture")})
        self.assertIs(result["unresolved_observation"]["semantic_capture"]["final_drain"], False)
        self.assertIn("terminal drain remains unqualified", result["s1"]["limitation"])

    def test_unsettled_physical_retirement_preserves_successful_independent_semantic_drain(self):
        data, index = inputs(TERMINAL)
        data[0]["observation"]["semantic_capture"]["final_drain"] = True
        result = self.assert_positive(data, index)
        self.assertEqual(result["unresolved_observation"]["retirement"], "unsettled")
        self.assertIs(result["unresolved_observation"]["semantic_capture"]["final_drain"], True)

    def test_terminal_retirement_refuses_nonterminal_or_after_final_placement(self):
        for placement in ("ordinary", "after-final"):
            with self.subTest(placement=placement):
                self.assert_refused(*inputs(TERMINAL, placement=placement))

    def test_terminal_retirement_refuses_contradictory_state_force_failure_or_late_stop(self):
        for fault in ("closed", "settled", "drain-unavailable", "forced", "exit", "late", "limit", "ended"):
            with self.subTest(fault=fault):
                data, index = inputs(TERMINAL)
                doc, _ledgers, receipt = data
                if fault in ("closed", "settled"):
                    doc["observation"]["retirement" if fault == "closed" else "settlement"] = fault
                elif fault == "drain-unavailable":
                    doc["observation"]["semantic_capture"]["final_drain"] = None
                elif fault == "ended":
                    doc["observation"]["ended_ns"] += 1
                else:
                    key, value = {"forced": ("forced_cleanup", True), "exit": ("observer_rc", 7),
                        "late": ("stop_latency_seconds", 30.1), "limit": ("stop_limit_seconds", 60)}[fault]
                    receipt[key] = value
                self.assert_refused(data, index)

    def test_terminal_retirement_requires_the_exact_single_ten_second_final_report(self):
        for fault in ("repeated", "different-timeout", "missing-final"):
            with self.subTest(fault=fault):
                data, index = inputs(TERMINAL)
                if fault == "repeated":
                    data[0]["gaps"][index]["repeats"] = 2
                    position = next(i for i, row in enumerate(records(data))
                                    if row["kind"] == "pass_committed" and row["event"].get("final"))
                    insert(data, position, [{"kind": "gap_repeated", "event": {"index": index, "repeats": 2}}])
                elif fault == "different-timeout":
                    change_gap(data, index, "reason", RETIREMENT.replace("10000", "5000"))
                else:
                    next(row for row in records(data) if row["kind"] == "pass_committed"
                         and row["event"].get("final"))["kind"] = "incomplete_final_pass"
                self.assert_refused(data, index)

    def test_residual_disclosures_refuse_scoped_changed_reason_or_missing_repeat_parity(self):
        for subject in (MAPS, CUSTODY, TERMINAL):
            for fault in ("scope", "caller", "module", "pid", "budget", "reason", "suppressed", "repeat", "publication"):
                with self.subTest(subject=subject, fault=fault):
                    data, index = inputs(subject)
                    if fault == "scope":
                        data[2]["scope_kind"] = "cgroup"
                    elif fault == "suppressed":
                        data[0]["gaps_suppressed"] = 1
                    elif fault == "repeat":
                        data[0]["gaps"][index]["repeats"] += 1
                    elif fault == "publication":
                        row = next(row for row in records(data) if row["kind"] == "gap_recorded"
                                   and row["event"]["index"] == index)
                        row["event"]["reason"] = "different"
                    else:
                        change_gap(data, index, fault, "different")
                    self.assert_refused(data, index)

    def test_custody_disclosure_never_rescues_owned_count_or_semantic_corruption(self):
        for field in ("physical", "api", "completed", "failed", "mechanism", "history"):
            with self.subTest(field=field):
                data, index = inputs(CUSTODY)
                doc = data[0]
                if field == "physical":
                    doc["edges"][0]["entries"]["count"] += 1
                else:
                    semantic = doc["semantic_edges"][-1]
                    if field == "api":
                        semantic["api_returns"]["count"] += 1
                    elif field == "history":
                        semantic["api_returns"]["historical_only_returns"] += 1
                    elif field == "mechanism":
                        semantic["mechanisms"][0]["calls"] += 1
                    else:
                        semantic["operations"][field] += 1
                result = H6["evaluate_inventory_h6"](*data)
                self.assertFalse(result["pass"])
                self.assertTrue(any("parity" in error or "totals" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
