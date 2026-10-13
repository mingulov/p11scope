#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""System disclosures cannot weaken the independently ledgered H6 population.

The existing unprivileged controller seam supplies real owned-child ledgers.
Ambient rows mirror the observed public shapes; none qualify a native capture.
"""

import copy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = runpy.run_path(str(ROOT / "tests/python/test_automatic_exec_oracle.py"))
H6 = BASE["H6"]

CAP_REASON = (
    "462 processes in scope; 256 deep-scanned by provider rarity (limit 256); "
    "1 attributed to pinned provider objects by exact maps identity; "
    "5 processes map 3 shared objects no deep scan examined and may use undiscovered providers")
SCAN_REASON = (
    "memory scan refused: initial mapping validation unavailable: "
    "empty or truncated /proc maps snapshot")


class SystemDisclosureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BASE["InventoryFixtureTest"].setUpClass.__func__(cls)

    def inputs(self, population=None):
        doc, ledgers, receipt = BASE["InventoryFixtureTest"].run_inventory_route(self)
        records = receipt["inventory_control"]["final_records"]
        # Preserve the final drain's own changed rows and emitter accounting.
        # This additional scan pass completes before that terminal tail starts.
        position = max(i for i, row in enumerate(records)
                       if row["kind"] == "pass_committed" and not row["event"].get("final")) + 1
        at_ns = records[position]["at_ns"]
        pass_number = max(row["event"]["pass"] for row in records
                          if row["kind"] == "pass_committed") + 1
        doc["observation"].update(lane="native", passes=pass_number + 1)
        doc["observation"]["attach"]["scope_filter"] = None
        doc["gaps_suppressed"] = 0
        receipt["system_scan_limit"] = 256
        kernel = {"id": "c800", "pid": 2, "start_time": 3, "incarnation": 0,
                  "authority": "scan_pinned", "lifecycle": "mapped", "status": "unavailable",
                  "executable": None}
        ambient = {"id": "c801", "pid": 5097, "start_time": 1820, "incarnation": 0,
                   "authority": "scan_pinned", "lifecycle": "mapped", "status": "observed",
                   "executable": {"dev": 37, "ino": 42858, "mtime_secs": 1774003435,
                                  "mtime_nanos": 0, "path": "/usr/libexec/gsd-smartcard"}}
        inserted = []
        for context in (kernel, ambient):
            doc["callers"].append({key: context[key] for key in
                                  ("id", "pid", "start_time", "incarnation", "lifecycle")})
            doc["callers"][-1].update(retired=False, image={
                "authority": context["authority"], "exe": context["executable"]})
            inserted.append({"kind": "caller_event", "event": {"caller": context["id"],
                "event": "admitted", "identity_context": {"version": 1, "caller": context}}})
        module = next(row for row in doc["modules"]
                      if receipt["providers"]["A"]["path"] in row["paths"])
        provider = receipt["providers"]["A"]
        module["identity"]["device"] = {"major": provider["dev"][0], "minor": provider["dev"][1]}
        # The ambient process shares A with MX/MS. Its quiet watch is not an
        # independent no-call ledger and never contributes an owned positive.
        edge = {"caller": ambient["id"], "module": module["id"], "presence": "mapped",
                "capture": "armed", "activity": "quiet",
                "mapping": {"state": "mapped", "evidence": "deep_scan", "reason": None,
                            "first_seen_ns": at_ns, "last_seen_ns": at_ns, "interruptions": 0},
                "entries": {"count": 0, "saturated": False, "cap": 18446744073709551615,
                            "first_seen_ns": None, "last_seen_ns": None, "in_flight": False,
                            "observation": "observed", "coverage": {"state": "watched_no_use",
                            "reason": None, "detail": None, "since_ns": at_ns, "until_ns": None,
                            "first_ns": None, "lossy": None}},
                "semantics": "unknown (semantic capture withheld)", "mechanisms": None,
                "operations": None}
        doc["edges"].append(edge)
        inserted.append({"kind": "edge_observed", "event": {**edge, "identity_context": {
            "version": 1, "caller": ambient, "module": {"id": module["id"],
                "device_major": provider["dev"][0], "device_minor": provider["dev"][1],
                "inode": provider["ino"], "path": provider["path"], "status": "observed"}}}})
        populations = {
            "cap": {"subject": "discovery capped", "reason": CAP_REASON, "caller": None, "pid": None},
            "scan": {"subject": "capture discovery", "reason": SCAN_REASON, "caller": "c800", "pid": 2},
            "semantic": {"subject": "semantic admission refused", "reason": "semantic_unavailable",
                         "caller": "c801", "pid": None},
        }
        for name, gap in populations.items():
            if population is None or population == name:
                doc["gaps"].append({**gap, "module": None, "budget": None, "repeats": 1})
                inserted.append({"kind": "gap_recorded", "event": {
                    **gap, "module": None, "budget": None, "index": len(doc["gaps"]) - 1}})
        inserted.append({"kind": "pass_committed", "event": {"pass": pass_number,
            "scanned": 257, "maps_matched": 1, "native_callers": 0, "scan_callers": 257,
            "totals": {"callers": len(doc["callers"]), "modules": len(doc["modules"]),
                       "edges": len(doc["edges"])}, "new_gaps": len(doc["gaps"]),
            "suppressed_delta": 0, "gaps_suppressed": 0, "edge_events": 1,
            "instance_events": 0, "semantic_edge_events": 0, "edge_events_deferred": 0,
            "instance_events_deferred": 0, "semantic_edge_events_deferred": 0,
            "unbound_rows": [], "unbound_rows_truncated": 0}})
        for record in inserted:
            record.update(schema="p11scope/inventory-events/v1", at_ns=at_ns)
        records[position:position] = inserted
        next(row for row in records if row["kind"] == "pass_committed"
             and row["event"].get("final"))["event"]["pass"] = pass_number
        for seq, record in enumerate(records):
            record["seq"] = seq
        return doc, ledgers, receipt

    def change_gap(self, data, key, value):
        data[0]["gaps"][0][key] = value
        for row in data[2]["inventory_control"]["final_records"]:
            if row["kind"] == "gap_recorded" and row["event"]["index"] == 0:
                row["event"][key] = value

    def test_system_disclosures_preserve_partial_rows_and_exact_owned_outcomes(self):
        original = self.inputs()
        result = H6["evaluate_inventory_h6"](*original)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_operations"], 20)
        self.assertEqual(result["physical_counted"], result["physical_entered"])
        self.assertEqual(result["expected_disclosures"], original[0]["gaps"])
        limitation = result["s1"]["limitation"]
        self.assertIn("only independently ledgered owned callers", limitation)
        self.assertIn("Global discovery remains partial", limitation)
        self.assertIn("ambient usage remains unqualified", limitation)
        self.assertIn("does not prove a complete host census", limitation)
        self.assertEqual(original[0]["edges"][-1]["semantics"], "unknown (semantic capture withheld)")

    def test_system_disclosures_require_exact_scope_publication_and_terminal_repeats(self):
        original = self.inputs()
        def publication(data):
            row = next(row for row in data[2]["inventory_control"]["final_records"]
                       if row["kind"] == "gap_recorded")
            row["event"]["reason"] = "different"
        cases = {
            "receipt-scope": lambda d: d[2].update(scope_kind="cgroup"),
            "snapshot-scope": lambda d: d[0].update(scope="cgroup"),
            "stream-scope": lambda d: d[2]["inventory_control"]["final_records"][0]["event"].update(scope="cgroup"),
            "lane": lambda d: d[0]["observation"].update(lane="scan"),
            "filter": lambda d: d[0]["observation"]["attach"].update(scope_filter="bpf-cgroup"),
            "missing-filter": lambda d: d[0]["observation"]["attach"].pop("scope_filter"),
            "suppressed": lambda d: d[0].update(gaps_suppressed=1),
            "publication": publication,
            "unknown-repeat": lambda d: d[0]["gaps"][0].update(repeats=2),
            "repeat-bool": lambda d: d[0]["gaps"][0].update(repeats=True),
            "repeat-zero": lambda d: d[0]["gaps"][0].update(repeats=0),
            "missing-MF-ledger": lambda d: d[1].pop("MF"),
            "missing-MF-birth": lambda d: d[1]["MF"]["idents"].clear(),
            "missing-owned-MF": lambda d: d[2]["owned_pids"].remove(d[1]["MF"]["idents"][0]["pid"]),
            "duplicate-owned": lambda d: d[2]["owned_pids"].append(d[2]["owned_pids"][0]),
            "foreign-owned": lambda d: d[2]["owned_pids"].append(42),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                data = copy.deepcopy(original)
                mutate(data)
                result = H6["evaluate_inventory_h6"](*data)
                self.assertFalse(result["pass"], result)
        data = copy.deepcopy(original)
        # Public repeated counts are exact only after the terminal flush.
        data[0]["gaps"][1]["repeats"] = 2
        records = data[2]["inventory_control"]["final_records"]
        records.insert(-1, {"schema": "p11scope/inventory-events/v1", "kind": "gap_repeated",
            "event": {"index": 1, "repeats": 2}, "at_ns": records[-1]["at_ns"]})
        for seq, row in enumerate(records):
            row["seq"] = seq
        result = H6["evaluate_inventory_h6"](*data)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["expected_disclosures"][1]["repeats"], 2)

    def test_system_scan_disclosures_cannot_hide_owned_births_or_unknown_reasons(self):
        original = self.inputs("scan")
        for name in ("MX", "MS", "MF"):
            with self.subTest(owned=name):
                data = copy.deepcopy(original)
                ident = data[1][name]["idents"][0]
                context = next(row["event"]["identity_context"]["caller"] for row in
                    data[2]["inventory_control"]["final_records"] if row["kind"] == "caller_event"
                    and row["event"].get("caller") == "c800")
                caller = next(row for row in data[0]["callers"] if row["id"] == "c800")
                # Even a different birth cannot exempt an owned numeric PID.
                context.update(pid=ident["pid"], start_time=ident["start"] + 1)
                caller.update(pid=ident["pid"], start_time=ident["start"] + 1)
                self.change_gap(data, "pid", ident["pid"])
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        cases = {
            "missing-caller": ("caller", "c999"), "missing-pid": ("pid", None),
            "wrong-pid": ("pid", 3), "module": ("module", "m0"),
            "budget": ("budget", {"resource": "callers", "limit": 4096, "requested": 4097}),
            "reason": ("reason", "memory scan refused: final mapping validation unavailable: denied"),
        }
        for name, (key, value) in cases.items():
            with self.subTest(name=name):
                data = copy.deepcopy(original)
                self.change_gap(data, key, value)
                data[2]["allowed_gap_subjects"].append("capture discovery")
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        for location in ("snapshot", "admission"):
            with self.subTest(birth=location):
                data = copy.deepcopy(original)
                if location == "snapshot":
                    caller = next(row for row in data[0]["callers"] if row["id"] == "c800")
                else:
                    caller = next(row["event"]["identity_context"]["caller"] for row in
                        data[2]["inventory_control"]["final_records"] if row["kind"] == "caller_event"
                        and row["event"].get("caller") == "c800")
                caller["start_time"] = None
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        data = copy.deepcopy(original)
        context = next(row["event"]["identity_context"]["caller"] for row in
            data[2]["inventory_control"]["final_records"] if row["kind"] == "caller_event"
            and row["event"].get("caller") == "c800")
        context["incarnation"] = False
        self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])

    def test_system_cap_disclosures_require_real_bounded_scan_metadata(self):
        original = self.inputs("cap")
        replacements = {
            "no-leftovers": CAP_REASON.replace("5 processes map 3", "0 processes map 0"),
            "too-many-leftovers": CAP_REASON.replace("5 processes", "500 processes"),
            "wrong-limit": CAP_REASON.replace("limit 256", "limit 512"),
            "too-many-scans": CAP_REASON.replace("256 deep-scanned", "257 deep-scanned"),
            "wrong-matches": CAP_REASON.replace("1 attributed", "2 attributed"),
            "no-objects": CAP_REASON.replace("map 3 shared", "map 0 shared"),
            "unknown-tail": CAP_REASON + "; unexpected loss",
        }
        for name, reason in replacements.items():
            with self.subTest(name=name):
                data = copy.deepcopy(original)
                self.change_gap(data, "reason", reason)
                data[2]["allowed_gap_subjects"].append("discovery capped")
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        for key, value in (("caller", "c800"), ("pid", 2), ("module", "m0"),
                           ("budget", {"resource": "modules", "limit": 4096, "requested": 4097})):
            with self.subTest(field=key):
                data = copy.deepcopy(original)
                self.change_gap(data, key, value)
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        data = copy.deepcopy(original)
        self.change_gap(data, "reason", CAP_REASON.replace("5 processes map 3", "0 processes map 0")
                        + "; 2 processes past the cap had no maps snapshot")
        self.assertTrue(H6["evaluate_inventory_h6"](*data)["pass"])
        data = copy.deepcopy(original)
        # One past-cap PID can both match A and map an unexamined object.
        self.change_gap(data, "reason",
            "257 processes in scope; 256 deep-scanned by provider rarity (limit 256); "
            "1 attributed to pinned provider objects by exact maps identity; "
            "1 processes map 1 shared objects no deep scan examined and may use undiscovered providers")
        result = H6["evaluate_inventory_h6"](*data)
        self.assertTrue(result["pass"], result["errors"])
        for field, value in (("scanned", 258), ("maps_matched", 2), ("maps_matched", True)):
            with self.subTest(pass_metadata=field, value=value):
                data = copy.deepcopy(original)
                records = data[2]["inventory_control"]["final_records"]
                publication = next(row for row in records if row["kind"] == "gap_recorded")
                completing = next(row for row in records if row["kind"] == "pass_committed"
                                  and row["seq"] > publication["seq"])
                completing["event"][field] = value
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])

    def test_system_semantic_disclosures_require_unowned_birth_and_physical_context(self):
        original = self.inputs("semantic")
        for name in ("MX", "MS", "MF"):
            with self.subTest(owned=name):
                data = copy.deepcopy(original)
                ident = data[1][name]["idents"][0]
                context = next(row["event"]["identity_context"]["caller"] for row in
                    data[2]["inventory_control"]["final_records"] if row["kind"] == "caller_event"
                    and row["event"].get("caller") == "c801")
                context.update(pid=ident["pid"], start_time=ident["start"] + 1)
                caller = next(row for row in data[0]["callers"] if row["id"] == "c801")
                caller.update(pid=ident["pid"], start_time=ident["start"] + 1)
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        for reason in ("provider_instance_unproven", "semantic_descriptor_refused", "future_refusal"):
            with self.subTest(reason=reason):
                data = copy.deepcopy(original)
                self.change_gap(data, "reason", reason)
                data[2]["allowed_gap_subjects"].append("semantic admission refused")
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        for field in ("inode", "device_minor", "id"):
            with self.subTest(context=field):
                data = copy.deepcopy(original)
                module = next(row["event"]["identity_context"]["module"] for row in
                    data[2]["inventory_control"]["final_records"] if row["kind"] == "edge_observed"
                    and row["event"].get("caller") == "c801")
                module[field] = "m999" if field == "id" else module[field] + 1
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])
        data = copy.deepcopy(original)
        self.change_gap(data, "reason", "provider_mapping_unproven")
        self.assertTrue(H6["evaluate_inventory_h6"](*data)["pass"])

    def test_system_owned_births_reject_boolean_generation_and_duplicate_pid_populations(self):
        _, ledgers, receipt = self.inputs()
        for fault in ("boolean-generation", "duplicate-pid"):
            with self.subTest(fault=fault):
                data, claimed = copy.deepcopy(ledgers), copy.deepcopy(receipt)
                if fault == "boolean-generation":
                    data["MX"]["idents"][1]["gen"] = True
                else:
                    data["MS"]["idents"][0].update(pid=data["MX"]["idents"][0]["pid"],
                                                  start=data["MX"]["idents"][0]["start"] + 1)
                    claimed["owned_pids"] = [data[name]["idents"][0]["pid"] for name in ("MX", "MS", "MF")]
                self.assertIsNone(H6["inventory_system_owned_births"](data, claimed))

    def test_system_disclosures_leave_owned_count_identity_and_s1_history_failures_red(self):
        original = self.inputs()
        for fault in ("count", "identity", "S1", "history", "manual-rebind"):
            with self.subTest(fault=fault):
                data = copy.deepcopy(original)
                if fault == "count":
                    data[0]["edges"][0]["entries"]["count"] += 1
                elif fault == "identity":
                    data[0]["modules"][0]["identity"]["inode"] += 1
                elif fault == "S1":
                    data[0]["semantic_edges"][0]["operations"]["completed"] += 1
                elif fault == "history":
                    data[2]["inventory_control"]["final_records"][-1]["event"]["edges_unretained"] = 1
                else:
                    data[2]["manual_rebind"] = True
                self.assertFalse(H6["evaluate_inventory_h6"](*data)["pass"])


if __name__ == "__main__":
    unittest.main()
