#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline controls for selecting an owned provider on a busy System host."""

import copy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
SYSTEM = runpy.run_path(str(ROOT / "tests/python/test_inventory_system_sibling.py"))
BASE, H6 = SYSTEM["BASE"], SYSTEM["H6"]


def foreign_module(module, *, device=(0, 275), inode=3161916):
    """Same pathname and complete content, independently different mapped file."""
    foreign = copy.deepcopy(module)
    foreign["id"] = "m-foreign"
    foreign["identity"].update(device={"major": device[0], "minor": device[1]}, inode=inode)
    return foreign


def cgroup_mapping_zero_inputs():
    """Reuse the public sibling shapes for an independently idle owned mapping."""
    doc, original, receipt, sibling_records = SYSTEM["sibling_inputs"]()
    ident = original["idents"][0]
    ledger = H6["parse_inv_ledger"]("")
    ledger.update(idents=[ident], mapped=original["mapped"], readys=[ident],
                  dones=[{**ident, "status": "ok"}])
    edge = copy.deepcopy(doc["edges"][0])
    edge["entries"].update(count=0, saturated=False, in_flight=False,
        coverage={"state": "unknown", "reason": "scope_membership_unproven", "lossy": None})
    first = copy.deepcopy(edge)
    first["entries"]["coverage"]["reason"] = "not_attached"
    gap = {"subject": "semantic admission refused", "caller": "c2", "module": None,
           "pid": None, "budget": None, "reason": "semantic_unavailable", "repeats": 1}
    events = [("started", {"scope": "cgroup"}),
        ("caller_event", sibling_records[1]["event"]), ("edge_observed", first),
        ("gap_recorded", {**{key: value for key, value in gap.items() if key != "repeats"}, "index": 0}),
        ("edge_observed", copy.deepcopy(edge))]
    records = [{"schema": "p11scope/inventory-events/v1", "seq": seq, "at_ns": BASE["START"] + seq,
                "kind": kind, "event": event} for seq, (kind, event) in enumerate(events)]
    doc.update(scope="cgroup", edges=[edge], instances=[], semantic_edges=[], gaps=[gap], gaps_suppressed=0)
    doc["observation"].update(lane="native", passes=2)
    doc["observation"]["attach"]["scope_filter"] = "bpf-cgroup"
    receipt.update(scope_kind="cgroup", scope_label="cgroup", count_only_providers=[],
        expected_edges={"2000:0:A": {"zero_ok": True}},
        expected_incarnations={"2000": {"gens": {"0": {"exe": ident["exe"], "retired": False}}}},
        scope_intervals=[{"pid": 2000, "membership": "selected", "t0": BASE["START"], "t1": BASE["STOP"]}],
        inventory_control={"measurements": [], "final_records": records})
    return doc, {"MS": ledger}, receipt


class InventoryProviderIdentityTest(unittest.TestCase):
    def test_full_system_oracle_ignores_same_path_and_digest_foreign_identity(self):
        for position in (0, 2):
            with self.subTest(position=position):
                doc, ledgers, receipt = SYSTEM["controlled_inputs"]()
                doc["modules"].insert(position, foreign_module(doc["modules"][0]))
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertTrue(result["pass"], result["errors"])
                self.assertEqual((result["physical_entered"], result["physical_counted"]), (260, 260))
                self.assertEqual(result["completed_operations"], 20)
                self.assertEqual(result["s1"]["sibling_instances"][0]["early"]["unobserved"]["api"], 17)
                self.assertEqual(result["s1"]["sibling_instances"][0]["delta"]["observed"]["api"], 30)
                self.assertEqual(len(doc["modules"]), 3)

    def test_physical_oracle_ignores_same_path_and_digest_foreign_identity(self):
        for position in (0, 1):
            with self.subTest(position=position):
                doc, ledgers, receipt = BASE["inventory_inputs"](s1_expected=False)
                doc["modules"].insert(position, foreign_module(doc["modules"][0]))
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertTrue(result["pass"], result["errors"])
                self.assertEqual((result["physical_entered"], result["physical_counted"]), (30, 30))

    def test_sibling_oracle_selects_only_the_held_mapping_identity(self):
        doc, ledger, receipt, records = SYSTEM["sibling_inputs"]()
        doc["modules"].insert(0, foreign_module(doc["modules"][0]))
        errors, summaries = H6["inventory_sibling_s1_errors"](doc, ledger, receipt, records)
        self.assertEqual(errors, [])
        self.assertEqual(summaries[0]["tuple"], [8888, "c2", 0, "m0", "i2"])

    def test_mapping_device_cannot_be_replaced_by_the_btrfs_fstat_device(self):
        doc, ledgers, receipt = BASE["inventory_inputs"](s1_expected=False)
        receipt["providers"]["A"]["file_identity"] = {"dev": [8, 2], "ino": 201}
        doc["modules"].insert(0, foreign_module(doc["modules"][0], device=(8, 2), inode=201))
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_counted"], 30)

    def test_owned_device_inode_digest_and_path_must_all_match(self):
        for fault in ("major", "minor", "inode", "digest", "path", "missing-device"):
            with self.subTest(fault=fault):
                doc, ledgers, receipt = SYSTEM["controlled_inputs"]()
                module = doc["modules"][0]
                if fault in ("major", "minor"):
                    module["identity"]["device"][fault] += 1
                elif fault == "inode":
                    module["identity"]["inode"] += 1
                elif fault == "digest":
                    module["identity"]["sha256"] = "f" * 64
                elif fault == "path":
                    module["paths"] = ["/w/other.so"]
                else:
                    module["identity"].pop("device")
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertFalse(result["pass"], result["errors"])

    def test_duplicate_exact_module_identity_cannot_satisfy_physical_or_sibling_claims(self):
        for factory in (lambda: BASE["inventory_inputs"](s1_expected=False), SYSTEM["controlled_inputs"]):
            for duplicate_id, divergent in (("m0", None), ("m-duplicate", None),
                                           ("m-duplicate", "digest"), ("m-duplicate", "path")):
                with self.subTest(factory=factory.__name__, duplicate_id=duplicate_id, divergent=divergent):
                    doc, ledgers, receipt = factory()
                    duplicate = copy.deepcopy(doc["modules"][0])
                    duplicate["id"] = duplicate_id
                    if divergent == "digest":
                        duplicate["identity"]["sha256"] = "f" * 64
                    elif divergent == "path":
                        duplicate["paths"] = ["/w/other.so"]
                    doc["modules"].append(duplicate)
                    result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                    self.assertFalse(result["pass"], result["errors"])

    def test_sibling_wrong_or_duplicate_exact_identity_is_rejected(self):
        for fault in ("device", "inode", "digest", "duplicate"):
            with self.subTest(fault=fault):
                doc, ledger, receipt, records = SYSTEM["sibling_inputs"]()
                module = doc["modules"][0]
                if fault == "device":
                    module["identity"]["device"]["minor"] += 1
                elif fault == "inode":
                    module["identity"]["inode"] += 1
                elif fault == "digest":
                    module["identity"]["sha256"] = "f" * 64
                else:
                    doc["modules"].append({**copy.deepcopy(module), "id": "m-duplicate"})
                errors, _ = H6["inventory_sibling_s1_errors"](doc, ledger, receipt, records)
                self.assertTrue(errors)

    def test_malformed_identity_objects_return_a_failed_verdict(self):
        for subject in ("receipt-mapping", "ambient-identity", "ambient-device"):
            for value in ([8, 1], "8:1", True):
                with self.subTest(subject=subject, value=value):
                    doc, ledgers, receipt = BASE["inventory_inputs"](s1_expected=False)
                    ambient = foreign_module(doc["modules"][0])
                    doc["modules"].append(ambient)
                    if subject == "receipt-mapping":
                        receipt["providers"]["A"]["mapping"] = value
                    elif subject == "ambient-identity":
                        ambient["identity"] = value
                    else:
                        ambient["identity"]["device"] = value
                    result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                    self.assertFalse(result["pass"], result["errors"])

    def test_path_evidence_requires_exact_elements_in_a_string_list(self):
        for paths in ("/w/libA.so.foreign", "/w/libA.so", ["/w/libA.so", True]):
            with self.subTest(paths=paths):
                doc, ledgers, receipt = BASE["inventory_inputs"](s1_expected=False)
                doc["modules"][0]["paths"] = paths
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertFalse(result["pass"], result["errors"])

    def test_cgroup_mapping_zero_disclosure_ignores_same_path_foreign_module(self):
        doc, ledgers, receipt = cgroup_mapping_zero_inputs()
        self.assertTrue(H6["inventory_cgroup_disclosure"](doc, ledgers, receipt, 0))
        doc["modules"].insert(0, foreign_module(doc["modules"][0]))
        self.assertTrue(H6["inventory_cgroup_disclosure"](doc, ledgers, receipt, 0))
        self.assertEqual(doc["edges"][0]["entries"]["count"], 0)
        self.assertEqual(doc["edges"][0]["entries"]["coverage"]["reason"], "scope_membership_unproven")

    def test_cgroup_mapping_zero_identity_and_owned_idle_proof_remain_required(self):
        for fault in ("device", "inode", "digest", "path", "duplicate", "count", "in-flight", "birth", "outside", "work"):
            with self.subTest(fault=fault):
                doc, ledgers, receipt = cgroup_mapping_zero_inputs()
                module = doc["modules"][0]
                if fault == "device":
                    module["identity"]["device"]["minor"] += 1
                elif fault == "inode":
                    module["identity"]["inode"] += 1
                elif fault == "digest":
                    module["identity"]["sha256"] = "f" * 64
                elif fault == "path":
                    module["paths"] = ["/w/other.so"]
                elif fault == "duplicate":
                    doc["modules"].append({**copy.deepcopy(module), "id": "m-duplicate"})
                elif fault in ("count", "in-flight"):
                    field, value = ("count", 1) if fault == "count" else ("in_flight", True)
                    doc["edges"][0]["entries"][field] = value
                elif fault == "birth":
                    ledgers["MS"]["idents"][0]["start"] += 1
                elif fault == "outside":
                    receipt["scope_intervals"][0]["membership"] = "outside"
                else:
                    ledgers["MS"]["batches"] = [{"pid": 2000}]
                self.assertFalse(H6["inventory_cgroup_disclosure"](doc, ledgers, receipt, 0))

    def test_count_only_claim_does_not_borrow_same_path_foreign_semantics(self):
        doc, ledgers, receipt = BASE["inventory_inputs"](s1_expected=False)
        receipt["count_only_providers"] = ["A"]
        foreign = foreign_module(doc["modules"][0])
        doc["modules"].insert(0, foreign)
        doc["callers"].append({"id": "c-foreign", "pid": 9000, "incarnation": 0})
        doc["edges"].append({"caller": "c-foreign", "module": foreign["id"],
            "entries": {"count": 10, "coverage": {"state": "counted", "lossy": False}},
            "semantics": "observed", "mechanisms": [{"calls": 10}], "operations": {"completed": 5}})
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_counted"], 30)

    def test_full_system_count_only_claim_leaves_foreign_semantics_ambient(self):
        doc, ledgers, receipt = SYSTEM["controlled_inputs"]()
        foreign = foreign_module(doc["modules"][1])
        doc["modules"].append(foreign)
        doc["callers"].append({"id": "c-foreign", "pid": 9000, "incarnation": 0})
        edge = {"caller": "c-foreign", "module": foreign["id"],
            "entries": {"count": 10, "coverage": {"state": "counted", "lossy": False}},
            "semantics": "observed", "mechanisms": [{"calls": 10}], "operations": {"completed": 5}}
        doc["edges"].append(copy.deepcopy(edge))
        records = receipt["inventory_control"]["final_records"]
        final_pass = records[-2]
        self.assertEqual(final_pass["kind"], "pass_committed")
        self.assertTrue(final_pass["event"]["final"])
        records.insert(-2, {"schema": "p11scope/inventory-events/v1", "seq": final_pass["seq"],
            "at_ns": final_pass["at_ns"], "kind": "edge_observed", "event": edge})
        final_pass["event"]["edge_events"] += 1
        for index in range(len(records) - 3, len(records)):
            records[index]["seq"] = index
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual((result["physical_counted"], result["completed_operations"]), (260, 20))


if __name__ == "__main__":
    unittest.main()
