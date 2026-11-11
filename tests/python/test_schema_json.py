# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Machine-readable v3 schema agrees with the release oracle (F-50, F-12).

docs/schema/observed-profile-v3.schema.json is a consumer aid, not the
enforcement: scripts/check-capture-evidence.py stays the gate. These tests
keep the two in agreement — the closed evidence key sets per lane, the
required enums, and the lane discriminator — so the schema cannot drift
from what the oracle accepts.

Run: python3 -I tests/python/test_schema_json.py -v
"""

import copy
import json
import re
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
SCHEMA = json.loads(
    (ROOT / "docs" / "schema" / "observed-profile-v3.schema.json").read_text(
        encoding="utf-8"
    )
)


def evidence_schema():
    return SCHEMA["properties"]["evidence"]


class SchemaOracleAgreement(unittest.TestCase):
    def metrics_document(self):
        return CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")

    def counter_document(self, *, mode="counts", failure=None, discontinuity=False):
        document = self.metrics_document()
        evidence = document["evidence"]
        evidence["counter_collection"] = {
            "mode": mode,
            "generation": 2,
            "read_window": {"started_ns": 10, "finished_ns": 20},
            "status": "fresh" if failure is None else "stale",
            "health": {"saturated": False, "contended": False} if failure is None else None,
            "discontinuity": discontinuity,
            "failure": failure,
        }
        if failure is not None or discontinuity:
            evidence["completeness"] = "PARTIAL"
            evidence["verdict_detail"] = "concrete_gap"
            observation = evidence["gap_classes"]["observation"]
            observation["status"] = "lossy"
            observation["causes"].append("counter_collection")
        return document

    def counter_gaps_document(self, *, gaps, health_unknown=False,
                              failure=None, discontinuity=False):
        """A counter document carrying the additive `bank_gaps` object.
        Any gap forces PARTIAL with the `counter_collection` cause, even
        on a fresh read; only a health gap reports unknown (null) health."""
        document = self.counter_document(
            failure=failure, discontinuity=discontinuity)
        evidence = document["evidence"]
        evidence["counter_collection"]["bank_gaps"] = dict(gaps)
        if health_unknown:
            evidence["counter_collection"]["health"] = None
        evidence["completeness"] = "PARTIAL"
        evidence["verdict_detail"] = "concrete_gap"
        observation = evidence["gap_classes"]["observation"]
        observation["status"] = "lossy"
        if "counter_collection" not in observation["causes"]:
            observation["causes"].append("counter_collection")
        return document

    def legacy_gaps_document(self, *, unread_stats=1, rv_failed=False,
                             unknown_evidence=()):
        """A legacy (non-counter) document carrying the additive
        `legacy_collection` object. Any gap forces PARTIAL with the
        `legacy_collection` cause."""
        document = self.metrics_document()
        evidence = document["evidence"]
        evidence["legacy_collection"] = {
            "unread_stats": unread_stats,
            "rv_failed": rv_failed,
            "unknown_evidence": list(unknown_evidence),
        }
        evidence["completeness"] = "PARTIAL"
        evidence["verdict_detail"] = "concrete_gap"
        observation = evidence["gap_classes"]["observation"]
        observation["status"] = "lossy"
        observation["causes"].append("legacy_collection")
        return document

    def pause_refused_document(self, *, refused="interrupted"):
        """A metrics document whose required pause did not hold: the
        lattice reads one partial attempt and `pause_refused` names why.
        The annotation adds no gap cause of its own; the partial does."""
        document = self.metrics_document()
        evidence = document["evidence"]
        evidence["pause"] = "partial"
        evidence["pause_attempts"] = 1
        evidence["pause_confirmed"] = 0
        evidence["pause_partial"] = 1
        evidence["pause_unavailable"] = 0
        evidence["pause_refused"] = refused
        evidence["completeness"] = "PARTIAL"
        evidence["verdict_detail"] = "concrete_gap"
        observation = evidence["gap_classes"]["observation"]
        observation["status"] = "lossy"
        observation["causes"].append("pause_partial")
        return document

    def snapshot_failure_document(self, *, failure="read_rvs", legacy=False):
        """A zero-snapshot terminal report: no aggregate rows, the failed
        read's finite name, PARTIAL with the `snapshot_failure` cause.
        The legacy path also carries its all-unknown gap object."""
        document = self.metrics_document()
        evidence = document["evidence"]
        evidence["snapshot_failure"] = failure
        document["functions"] = []
        evidence["completeness"] = "PARTIAL"
        evidence["verdict_detail"] = "concrete_gap"
        observation = evidence["gap_classes"]["observation"]
        observation["status"] = "lossy"
        if legacy:
            evidence["legacy_collection"] = {
                "unread_stats": 0,
                "rv_failed": True,
                "unknown_evidence": list(CHECKER["LEGACY_UNKNOWN_CELLS"]),
            }
            observation["causes"].append("legacy_collection")
        observation["causes"].append("snapshot_failure")
        return document

    def selected_document(self, *, selection="resolved", events=(), mode="counts",
                          with_close_products=False):
        """A metrics document carrying the 6.15 selection envelope. The
        default mirrors the R1 root positive shape: the resolved slot
        plus the honest host-seam refusal and no window yet. Selection
        "unresolved" mirrors the named-refusal record; "omitted" drops
        the record (a close-only ledger)."""
        document = self.metrics_document()
        section = {"events": list(events)}
        if selection == "resolved":
            section["selection"] = {
                "endpoint": "counter_bank_growth_e0007",
                "slot": 7,
                "file_offset": 0x120,
                "names": ["counter_bank_growth_e0007"],
                "refusal": "bundle_unavailable",
            }
        elif selection == "unresolved":
            section["selection"] = {
                "endpoint": "C_Missing",
                "refusal": "endpoint_unknown",
            }
        elif selection != "omitted":
            raise AssertionError(f"unknown selection shape: {selection!r}")
        if with_close_products:
            section["lineage"] = self.selected_lineage()
            section["aggregate"] = self.selected_bracket(detail=False, mode=mode)
            section["detail"] = self.selected_bracket(detail=True, mode=mode)
        document["evidence"]["selected_detail"] = section
        return document

    @staticmethod
    def selected_mark(seq):
        return {
            "seq": seq,
            "generation": 7,
            "indices": [0, 1, 2, 3],
            "bank_ids": [[0, 0], [1, 0]],
            "transaction": None,
        }

    def selected_lineage(self):
        return {
            "request": 3,
            "caller": 3,
            "provider": 5,
            "view": 11,
            "endpoint_offset": 144,
            "broad_original_index": 1,
            "broad_generation": 7,
            "detail_generation": 9,
            "broad_read_seq_before": 1,
            "broad_read_seq_after": 2,
            "broad_mark_before": self.selected_mark(1),
            "broad_mark_after": self.selected_mark(2),
            "drift": None,
            "after_read": "matched",
        }

    @staticmethod
    def selected_row(mode, slot=0):
        row = {
            "slot": slot,
            "object": 1,
            "file_offset": 128 + slot * 16,
            "entered": 3,
            "returned": 3,
            "errors": 0,
            "rv_counts": {"0": 3},
        }
        if mode in ("timestamps", "latency"):
            row["total_ns"] = 30
            row["max_ns"] = 10
        if mode == "latency":
            row["buckets"] = [0] * 32
        return row

    def selected_bracket(self, *, detail, mode="counts"):
        fragment = {
            "scope": "detail" if detail else "broad",
            "unit": "calls",
            "mode": mode,
            "mode_mixed": False,
            "rows": [self.selected_row(mode, slot) for slot in (0, 1)],
        }
        if detail:
            fragment["detail_generation"] = 9
        else:
            fragment["seq_before"] = 1
            fragment["seq_after"] = 2
        return fragment

    @staticmethod
    def selected_events_covering_every_row():
        return [
            {"event": "reserved", "request": 3, "caller": 3, "provider": 5,
             "seq": 1, "note": "selected 0x80"},
            {"event": "bound", "request": 3, "caller": 3, "provider": 5, "seq": 1},
            {"event": "cas_won", "request": 3, "caller": 3, "provider": 5, "seq": 1},
            {"event": "cas_refused", "request": 3, "caller": 3, "provider": 5, "seq": 1},
            {"event": "closed", "request": 3, "caller": 3, "provider": 5, "seq": 2},
            {"event": "cancelled_unactivated", "request": 4, "caller": 3,
             "provider": 5, "seq": 2, "note": "cancelled before delivery"},
            {"event": "close_refused", "request": 4, "caller": 3, "provider": 5,
             "view": 11, "endpoint_offset": 128, "refusal": "quarantined"},
            {"event": "reserve_refused", "request": 5, "caller": 3, "provider": 5,
             "refusal": "window_active", "seq": None},
            {"event": "reserve_refused", "request": 6, "caller": 3, "provider": 5,
             "refusal": "child_shape", "seq": 2},
            {"event": "start_refused", "request": 7, "caller": 3, "provider": 5,
             "reason": "ambiguous endpoints"},
            {"event": "promotion_outcome", "request": 3, "outcome": "refused",
             "reason": "preparation failed"},
            {"event": "promotion_outcome", "request": 4, "outcome": "ended",
             "reason": "run stopped"},
            {"event": "promotion_outcome", "request": 5, "outcome": "active",
             "caller": 3, "provider": 5},
        ]

    def test_counter_collection_optional_fresh_modes_and_unknown_window(self):
        legacy = self.metrics_document()
        CHECKER["exact_metrics_schema"](legacy)
        self.assertNotIn("counter_collection", legacy["evidence"])
        for mode in ("counts", "timestamps", "latency"):
            with self.subTest(mode=mode):
                document = self.counter_document(mode=mode)
                CHECKER["exact_metrics_schema"](document)
                document["evidence"]["counter_collection"]["read_window"] = None
                CHECKER["exact_metrics_schema"](document)

    def test_counter_collection_stale_and_discontinuity_require_concrete_gap(self):
        for failure in ("read_rvs", "saturated", "contended"):
            with self.subTest(failure=failure):
                document = self.counter_document(failure=failure)
                CHECKER["exact_metrics_schema"](document)
                for field, value in (("completeness", "COMPLETE"),
                                     ("verdict_detail", "clean_proven")):
                    invalid = copy.deepcopy(document)
                    invalid["evidence"][field] = value
                    with self.assertRaises(AssertionError):
                        CHECKER["exact_metrics_schema"](invalid)
                invalid = copy.deepcopy(document)
                invalid["evidence"]["gap_classes"]["observation"]["causes"].remove("counter_collection")
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        document = self.counter_document(discontinuity=True)
        CHECKER["exact_metrics_schema"](document)
        document["evidence"]["counter_collection"]["discontinuity"] = False
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](document)

    def test_counter_collection_closed_shape_and_consistency_twins(self):
        healthy = self.counter_document()
        stale = self.counter_document(failure="read_rvs")
        invalid_values = (
            (healthy, {"extra": 1}),
            (healthy, {"mode": "requested"}),
            (healthy, {"generation": 0}),
            (healthy, {"generation": True}),
            (healthy, {"generation": 2**64}),
            (healthy, {"read_window": {"started_ns": 20, "finished_ns": 10}}),
            (healthy, {"read_window": {"started_ns": True, "finished_ns": 20}}),
            (healthy, {"read_window": {"started_ns": 10, "finished_ns": 20, "extra": 0}}),
            (healthy, {"status": "cached"}),
            (healthy, {"discontinuity": 1}),
            (healthy, {"failure": "read_rvs"}),
            (healthy, {"health": None}),
            (healthy, {"health": {"saturated": True, "contended": False}}),
            (healthy, {"health": {"saturated": False, "contended": 0}}),
            (healthy, {"health": {"saturated": False, "contended": False, "extra": False}}),
            (stale, {"failure": None}),
            (stale, {"failure": "arbitrary"}),
            (stale, {"health": {"saturated": False, "contended": False}}),
        )
        for document, patch in invalid_values:
            with self.subTest(patch=patch):
                invalid = copy.deepcopy(document)
                invalid["evidence"]["counter_collection"].update(patch)
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        for field in healthy["evidence"]["counter_collection"]:
            with self.subTest(missing=field):
                invalid = copy.deepcopy(healthy)
                del invalid["evidence"]["counter_collection"][field]
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        historical = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["HISTORICAL_METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")
        historical["evidence"]["counter_collection"] = healthy["evidence"]["counter_collection"]
        with self.assertRaises(AssertionError):
            CHECKER["exact_historical_metrics_schema"](historical)

    def test_counter_collection_schema_matches_finite_oracle_shape(self):
        collection = evidence_schema()["properties"]["counter_collection"]
        keys = {"mode", "generation", "read_window", "status", "health", "discontinuity", "failure"}
        self.assertEqual(set(collection["required"]), keys)
        self.assertEqual(set(collection["properties"]), keys | {"bank_gaps"})
        self.assertFalse(collection["additionalProperties"])
        self.assertNotIn("counter_collection", evidence_schema()["required"])
        failure = collection["properties"]["failure"]["enum"]
        self.assertEqual(set(failure) - {None}, set(CHECKER["COUNTER_COLLECTION_FAILURES"]))
        self.assertIn(None, failure)
        gaps = collection["properties"]["bank_gaps"]
        self.assertEqual(
            set(gaps["required"]), set(CHECKER["BANK_GAPS_KEYS"]))
        self.assertEqual(
            set(gaps["properties"]), set(CHECKER["BANK_GAPS_KEYS"]))
        self.assertFalse(gaps["additionalProperties"])
        self.assertNotIn("bank_gaps", collection["required"])

    def test_counter_bank_gaps_fresh_and_stale_shapes_accepted(self):
        """Gap captures pass the gate: fresh reads with slot, health or
        kernel gaps, and stale reads with gaps, all PARTIAL with the
        `counter_collection` cause. Only a health gap reports null health."""
        slot_gaps = {"failed_slots": 1, "health_failed": False,
                     "kernel_failed": False}
        health_gaps = {"failed_slots": 0, "health_failed": True,
                       "kernel_failed": False}
        kernel_gaps = {"failed_slots": 0, "health_failed": False,
                       "kernel_failed": True}
        positives = [
            self.counter_gaps_document(gaps=slot_gaps),
            self.counter_gaps_document(gaps=health_gaps, health_unknown=True),
            self.counter_gaps_document(gaps=kernel_gaps),
            self.counter_gaps_document(gaps=slot_gaps, failure="read_rvs"),
        ]
        for document in positives:
            with self.subTest(document=document["evidence"]["counter_collection"]):
                CHECKER["exact_metrics_schema"](document)
        stale = self.counter_gaps_document(gaps=slot_gaps, failure="read_rvs")
        for field, value in (("completeness", "COMPLETE"),
                             ("verdict_detail", "clean_proven")):
            invalid = copy.deepcopy(stale)
            invalid["evidence"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        fresh = self.counter_gaps_document(gaps=slot_gaps)
        for field, value in (("completeness", "COMPLETE"),
                             ("verdict_detail", "clean_proven")):
            invalid = copy.deepcopy(fresh)
            invalid["evidence"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        unflagged = copy.deepcopy(fresh)
        unflagged["evidence"]["gap_classes"]["observation"]["causes"].remove(
            "counter_collection")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](unflagged)

    def test_counter_bank_gaps_malformed_rejected(self):
        """Malformed `bank_gaps` objects are refused for their own shape,
        not for the closed collection keys: each case differs from an
        accepted positive by one field."""
        base = {"failed_slots": 1, "health_failed": False,
                "kernel_failed": False}
        shape_cases = [
            {**base, "extra": 0},
            {**base, "failed_slots": True},
            {**base, "failed_slots": -1},
            {**base, "failed_slots": 2**64},
            {**base, "failed_slots": "1"},
            {**base, "health_failed": 0},
            {**base, "kernel_failed": None},
            {"failed_slots": 1, "health_failed": False},
            {"failed_slots": 0, "health_failed": False,
             "kernel_failed": False},
        ]
        for gaps in shape_cases:
            with self.subTest(gaps=gaps):
                document = self.counter_gaps_document(gaps=gaps)
                with self.assertRaisesRegex(AssertionError, "counter bank_gaps"):
                    CHECKER["exact_metrics_schema"](document)
        healthy = {"failed_slots": 0, "health_failed": True,
                   "kernel_failed": False}
        contradiction = self.counter_gaps_document(gaps=healthy)
        with self.assertRaisesRegex(AssertionError, "counter collection"):
            CHECKER["exact_metrics_schema"](contradiction)
        unknown = self.counter_gaps_document(gaps=base, health_unknown=True)
        with self.assertRaisesRegex(AssertionError, "counter collection"):
            CHECKER["exact_metrics_schema"](unknown)

    def test_legacy_collection_accepted_and_requires_gap(self):
        """Legacy gap captures pass the gate with PARTIAL and the
        `legacy_collection` cause, for slot, RV and evidence-cell gaps."""
        positives = [
            self.legacy_gaps_document(unread_stats=2),
            self.legacy_gaps_document(unread_stats=0, rv_failed=True),
            self.legacy_gaps_document(
                unread_stats=0, unknown_evidence=["ring_loss", "owner"]),
            self.legacy_gaps_document(
                unread_stats=1, rv_failed=True,
                unknown_evidence=["cookie", "root"]),
        ]
        for document in positives:
            with self.subTest(document=document["evidence"]["legacy_collection"]):
                CHECKER["exact_metrics_schema"](document)
        gap = self.legacy_gaps_document(
            unread_stats=1, unknown_evidence=["ring_loss"])
        for field, value in (("completeness", "COMPLETE"),
                             ("verdict_detail", "clean_proven")):
            invalid = copy.deepcopy(gap)
            invalid["evidence"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        unflagged = copy.deepcopy(gap)
        unflagged["evidence"]["gap_classes"]["observation"]["causes"].remove(
            "legacy_collection")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](unflagged)

    def test_legacy_collection_malformed_rejected(self):
        """Malformed `legacy_collection` objects are refused for their own
        shape: each case differs from an accepted positive by one field."""
        cases = [
            {"unread_stats": 1, "rv_failed": False, "unknown_evidence": [],
             "extra": 0},
            {"unread_stats": -1, "rv_failed": False, "unknown_evidence": []},
            {"unread_stats": True, "rv_failed": False, "unknown_evidence": []},
            {"unread_stats": 1, "rv_failed": 1, "unknown_evidence": []},
            {"unread_stats": 1, "rv_failed": False,
             "unknown_evidence": ["no_such_cell"]},
            {"unread_stats": 0, "rv_failed": False,
             "unknown_evidence": ["ring_loss", "ring_loss"]},
            {"unread_stats": 0, "rv_failed": False,
             "unknown_evidence": ["owner", "ring_loss"]},
            {"unread_stats": 0, "rv_failed": False, "unknown_evidence": []},
            {"unread_stats": 1, "rv_failed": False,
             "unknown_evidence": "ring_loss"},
            {"unread_stats": 1, "rv_failed": False},
        ]
        for legacy in cases:
            with self.subTest(legacy=legacy):
                document = self.legacy_gaps_document()
                document["evidence"]["legacy_collection"] = legacy
                with self.assertRaisesRegex(AssertionError, "legacy_collection[ .:]"):
                    CHECKER["exact_metrics_schema"](document)

    def test_legacy_collection_schema_matches_oracle_shape(self):
        legacy = evidence_schema()["properties"]["legacy_collection"]
        self.assertEqual(
            set(legacy["required"]), set(CHECKER["LEGACY_COLLECTION_KEYS"]))
        self.assertEqual(
            set(legacy["properties"]), set(CHECKER["LEGACY_COLLECTION_KEYS"]))
        self.assertFalse(legacy["additionalProperties"])
        self.assertNotIn("legacy_collection", evidence_schema()["required"])
        names = legacy["properties"]["unknown_evidence"]["items"]["enum"]
        self.assertEqual(names, list(CHECKER["LEGACY_UNKNOWN_CELLS"]))
        self.assertTrue(legacy["properties"]["unknown_evidence"]["uniqueItems"])

    def test_pause_refused_accepted_and_vocabulary_closed(self):
        """A refused pause passes the gate with its finite reason beside
        the partial lattice; anything outside the vocabulary is refused."""
        clean = self.metrics_document()
        self.assertNotIn("pause_refused", clean["evidence"])
        CHECKER["exact_metrics_schema"](clean)
        for refused in ("interrupted", "refused"):
            with self.subTest(refused=refused):
                CHECKER["exact_metrics_schema"](
                    self.pause_refused_document(refused=refused))
        for refused in ("cancelled", "FAILED", "", None, 0):
            with self.subTest(refused=refused):
                document = self.pause_refused_document()
                document["evidence"]["pause_refused"] = refused
                with self.assertRaisesRegex(AssertionError, "pause_refused[ :]"):
                    CHECKER["exact_metrics_schema"](document)

    def test_pause_refused_schema_matches_oracle_vocabulary(self):
        refused = evidence_schema()["properties"]["pause_refused"]
        self.assertEqual(set(refused["enum"]), set(CHECKER["PAUSE_REFUSALS"]))
        self.assertNotIn("pause_refused", evidence_schema()["required"])

    def test_snapshot_failure_accepted_and_requires_gap(self):
        """Zero-snapshot terminal reports pass the gate: the named
        failure, PARTIAL with the `snapshot_failure` cause, and no rows.
        The legacy path adds its all-unknown gap object and cause."""
        for failure in ("read_rvs", "bank_routing", "topology",
                        "legacy_slots", "legacy_kernel", "unavailable"):
            with self.subTest(failure=failure):
                CHECKER["exact_metrics_schema"](
                    self.snapshot_failure_document(failure=failure))
        CHECKER["exact_metrics_schema"](
            self.snapshot_failure_document(failure="legacy_slots", legacy=True))
        gap = self.snapshot_failure_document()
        for field, value in (("completeness", "COMPLETE"),
                             ("verdict_detail", "clean_proven")):
            invalid = copy.deepcopy(gap)
            invalid["evidence"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        unflagged = copy.deepcopy(gap)
        unflagged["evidence"]["gap_classes"]["observation"]["causes"].remove(
            "snapshot_failure")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](unflagged)

    def test_snapshot_failure_malformed_rejected(self):
        """A snapshot failure is refused when its reason leaves the
        vocabulary, when rows are claimed beside it, or when an accepted
        read is described beside it."""
        document = self.snapshot_failure_document()
        document["evidence"]["snapshot_failure"] = "arbitrary"
        with self.assertRaisesRegex(AssertionError, "snapshot_failure[ :]"):
            CHECKER["exact_metrics_schema"](document)
        rows = self.snapshot_failure_document()
        rows["functions"] = [{"names": ["C_Initialize"]}]
        with self.assertRaisesRegex(AssertionError, "aggregate rows"):
            CHECKER["exact_metrics_schema"](rows)
        described = self.snapshot_failure_document()
        described["evidence"]["counter_collection"] = self.counter_document()[
            "evidence"]["counter_collection"]
        described["evidence"]["gap_classes"]["observation"]["causes"].append(
            "counter_collection")
        with self.assertRaisesRegex(AssertionError, "accepted read"):
            CHECKER["exact_metrics_schema"](described)

    def test_snapshot_failure_schema_matches_oracle_vocabulary(self):
        failure = evidence_schema()["properties"]["snapshot_failure"]
        self.assertEqual(
            set(failure["enum"]), set(CHECKER["SNAPSHOT_FAILURES"]))
        self.assertNotIn("snapshot_failure", evidence_schema()["required"])

    def test_counter_mode_agrees_with_function_timing_in_both_document_lanes(self):
        timestamp = {"approximate": False, "p50": None, "p95": None, "p99": None,
                     "total": 0, "max": 0}
        histogram_zero = {**timestamp, "approximate": True, "p50": 0, "p95": 0, "p99": 0}
        histogram_empty = {**timestamp, "approximate": True}
        for profile in (False, True):
            for mode, timing in (("counts", None), ("timestamps", timestamp),
                                 ("latency", histogram_zero), ("latency", histogram_empty)):
                with self.subTest(profile=profile, mode=mode, timing=timing):
                    document = self.counter_document(mode=mode)
                    check = CHECKER["exact_metrics_schema"]
                    if profile:
                        document = CHECKER["document_fixture"](document["evidence"])
                        check = CHECKER["exact_profile_v3_selection"]
                    row = {
                        "names": ["C_Sign"], "aliased": False, "module": None,
                        "module_ambiguous": False, "module_unresolved": True,
                        "target": {"object": None, "file_offset": 16}, "ordinals": [],
                        "calls": 0, "errors": 0, "pending_returns": 0, "in_flight": 0,
                        "rv_counts": {}, "latency_ns": timing,
                    }
                    document["functions"] = [row]
                    check(document)
                    contradictions = (timestamp, histogram_zero) if mode == "counts" else (
                        (None, histogram_zero) if mode == "timestamps" else (None, timestamp))
                    for contradiction in contradictions:
                        invalid = copy.deepcopy(document)
                        invalid["functions"][0]["latency_ns"] = contradiction
                        with self.assertRaises(AssertionError):
                            check(invalid)
                    missing = copy.deepcopy(document)
                    del missing["functions"][0]["latency_ns"]
                    with self.assertRaises(AssertionError):
                        check(missing)
                    if mode != "counts":
                        for patch in ({"extra": 1}, {"total": True}, {"max": -1},
                                      {"total": 2**64}, {"p95": False}):
                            invalid = copy.deepcopy(document)
                            invalid["functions"][0]["latency_ns"].update(patch)
                            with self.assertRaises(AssertionError):
                                check(invalid)

    def test_counter_mode_schema_selects_the_existing_timing_shapes(self):
        by_mode = {}
        for branch in SCHEMA["allOf"]:
            evidence = branch["if"].get("properties", {}).get("evidence", {})
            collection = evidence.get("properties", {}).get("counter_collection")
            if collection is None:
                continue
            mode = collection["properties"]["mode"]["const"]
            self.assertEqual(evidence["required"], ["counter_collection"])
            row = branch["then"]["properties"]["functions"]["items"]
            self.assertEqual(row["required"], ["latency_ns"])
            pointer = row["properties"]["latency_ns"]["$ref"]
            shape = SCHEMA
            for key in pointer.removeprefix("#/").split("/"):
                shape = shape[int(key)] if isinstance(shape, list) else shape[key]
            by_mode[mode] = shape
        self.assertEqual(set(by_mode), {"counts", "timestamps", "latency"})
        self.assertEqual(by_mode["counts"], {"type": "null"})
        for mode, approximate in (("timestamps", False), ("latency", True)):
            shape = by_mode[mode]
            self.assertEqual(shape["type"], "object")
            self.assertIs(shape["properties"]["approximate"]["const"], approximate)
            for field in ("total", "max"):
                self.assertEqual(shape["properties"][field]["type"], "integer")
            for field in ("p50", "p95", "p99"):
                self.assertEqual(shape["properties"][field]["type"],
                                 "null" if mode == "timestamps" else ["integer", "null"])

    def test_selected_detail_optional_legacy_omission_and_resolved_positive(self):
        """Legacy captures omit the envelope; the R1 root-positive shape
        (resolved slot plus the honest host-seam refusal) passes the
        real metrics consumer, in the metrics lane and the shared
        profile-lane evidence path (the producer's CLI policy gates the
        lane; the consumer enforces the closed shape in both)."""
        legacy = self.metrics_document()
        self.assertNotIn("selected_detail", legacy["evidence"])
        CHECKER["exact_metrics_schema"](legacy)
        resolved = self.selected_document()
        CHECKER["exact_metrics_schema"](resolved)
        profile = CHECKER["document_fixture"](resolved["evidence"])
        CHECKER["exact_profile_v3_selection"](profile)

    def test_selected_detail_unresolved_and_driver_refusal_shapes(self):
        unresolved = self.selected_document(selection="unresolved")
        CHECKER["exact_metrics_schema"](unresolved)
        for refusal in ("promotion_activation_failed", "promotion_scope_unsupported",
                        "broad_plan_topology", "window_active", "endpoint_unknown",
                        "bundle_unavailable"):
            with self.subTest(refusal=refusal):
                document = self.selected_document(selection="unresolved")
                document["evidence"]["selected_detail"]["selection"]["refusal"] = refusal
                CHECKER["exact_metrics_schema"](document)
        omitted = self.selected_document(
            selection="omitted", events=[{"event": "closed", "request": 3, "caller": 3,
                                                  "provider": 5, "seq": 2}],
            with_close_products=True)
        CHECKER["exact_metrics_schema"](omitted)

    def test_selected_detail_close_products_shape(self):
        """Every ledger row kind plus lineage and both brackets pass in
        each counter mode; drift variants and mismatch words pass."""
        for mode in ("counts", "timestamps", "latency"):
            with self.subTest(mode=mode):
                document = self.selected_document(
                    events=self.selected_events_covering_every_row(),
                    mode=mode, with_close_products=True)
                CHECKER["exact_metrics_schema"](document)
        drifts = (None,
                  {"kind": "generation", "before": 7, "after": 9},
                  {"kind": "indices", "before": [0, 1], "after": [0, 1, 2]},
                  {"kind": "bank_ids", "bank": 1, "before": 0, "after": None},
                  {"kind": "transaction", "before": None, "after": 12})
        for drift in drifts:
            with self.subTest(drift=drift):
                document = self.selected_document(with_close_products=True)
                document["evidence"]["selected_detail"]["lineage"]["drift"] = drift
                CHECKER["exact_metrics_schema"](document)
        for after_read in ("matched", "unavailable", "mismatched:generation",
                           "mismatched:rows", "mismatched:rejected"):
            with self.subTest(after_read=after_read):
                document = self.selected_document(with_close_products=True)
                document["evidence"]["selected_detail"]["lineage"]["after_read"] = after_read
                CHECKER["exact_metrics_schema"](document)

    def test_selected_detail_rejects_forbidden_identities(self):
        """No raw PID/TID anywhere in the envelope: the removed
        `original_pid` publication and any pid-shaped extra key fail the
        closed-key checks, in the selection record and every nested row."""
        resolved = self.selected_document()
        resolved["evidence"]["selected_detail"]["selection"]["original_pid"] = 4242
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](resolved)
        full = self.selected_document(
            events=self.selected_events_covering_every_row(),
            with_close_products=True)
        section = full["evidence"]["selected_detail"]
        section["original_pid"] = 4242
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](full)
        del section["original_pid"]
        section["events"][0]["original_pid"] = 4242
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](full)
        del section["events"][0]["original_pid"]
        section["lineage"]["original_pid"] = 4242
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](full)
        del section["lineage"]["original_pid"]
        section["aggregate"]["rows"][0]["original_pid"] = 4242
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](full)

    def test_selected_detail_rejects_unknown_nested_fields(self):
        """Every nested object is closed: one unknown field at each level
        fails, and the historical lane rejects the whole envelope."""
        full = self.selected_document(
            events=self.selected_events_covering_every_row(),
            with_close_products=True)
        mutations = [
            ("envelope", []),
            ("selection", ["selection"]),
            ("window row", ["events", 0]),
            ("close_refused row", ["events", 6]),
            ("reserve_refused row", ["events", 7]),
            ("start_refused row", ["events", 9]),
            ("outcome row", ["events", 10]),
            ("lineage", ["lineage"]),
            ("mark", ["lineage", "broad_mark_before"]),
            ("aggregate", ["aggregate"]),
            ("detail", ["detail"]),
            ("cell row", ["aggregate", "rows", 0]),
        ]
        for label, path in mutations:
            with self.subTest(level=label):
                invalid = copy.deepcopy(full)
                node = invalid["evidence"]["selected_detail"]
                for key in path:
                    node = node[key]
                node["unexpected_field"] = 1
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        historical = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["HISTORICAL_METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")
        historical["evidence"]["selected_detail"] = full["evidence"]["selected_detail"]
        with self.assertRaises(AssertionError):
            CHECKER["exact_historical_metrics_schema"](historical)

    def test_selected_detail_rejects_bad_vocabularies(self):
        """Finite words only: bad refusals, labels, outcomes, modes and
        mode-conditional row keys fail, as do uncorrelated slot/offset
        and empty endpoint/names."""
        full = self.selected_document(
            events=self.selected_events_covering_every_row(),
            with_close_products=True)
        cases = [
            ("selection", {"refusal": "no_such_refusal"}),
            ("selection", {"refusal": "preparation failed"}),
            ("selection", {"endpoint": ""}),
            ("selection", {"names": []}),
            ("selection", {"names": [""]}),
            ("selection", {"slot": True}),
            ("events.6", {"refusal": "window_active"}),
            ("events.7", {"refusal": "no_such_word"}),
            ("events.7", {"seq": True}),
            ("events.9", {"reason": "no such reason"}),
            ("events.10", {"reason": "run stopped"}),
            ("events.11", {"reason": "preparation failed"}),
            ("events.12", {"reason": "run stopped"}),
            ("events.10", {"outcome": "active"}),
            ("events.12", {"outcome": "refused"}),
            ("lineage", {"after_read": "mismatched:nope"}),
            ("lineage", {"after_read": "matched "}),
            ("lineage", {"broad_generation": 0}),
            ("lineage", {"drift": {"kind": "nope", "before": 1, "after": 2}}),
            ("lineage", {"drift": {"kind": "generation", "before": 0, "after": 2}}),
            ("aggregate", {"scope": "detail"}),
            ("aggregate", {"mode": "requested"}),
            ("aggregate", {"mode_mixed": 0}),
            ("detail", {"scope": "broad"}),
        ]
        for path, patch in cases:
            with self.subTest(path=path, patch=patch):
                invalid = copy.deepcopy(full)
                node = invalid["evidence"]["selected_detail"]
                for key in path.split("."):
                    node = node[int(key) if key.isdigit() else key]
                node.update(patch)
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        for lonely in ({"slot": 7}, {"file_offset": 144}):
            with self.subTest(lonely=lonely):
                document = self.selected_document(selection="unresolved")
                document["evidence"]["selected_detail"]["selection"].update(lonely)
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](document)
        row_cases = [
            ("counts", {"total_ns": 30}),
            ("counts", {"buckets": [0] * 32}),
            ("timestamps", {"buckets": [0] * 32}),
            ("timestamps", {"total_ns": None}),
            ("latency", {"total_ns": None}),
            ("latency", {"buckets": [0] * 31}),
            ("latency", {"buckets": [0] * 32 + [True]}),
            ("counts", {"rv_counts": {"0x0": 3}}),
            ("counts", {"rv_counts": {"007": 3}}),
            ("counts", {"rv_counts": {"0": True}}),
            ("counts", {"object": 2**32}),
        ]
        for mode, patch in row_cases:
            with self.subTest(mode=mode, patch=patch):
                document = self.selected_document(with_close_products=True, mode=mode)
                document["evidence"]["selected_detail"]["aggregate"]["rows"][0].update(patch)
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](document)

    def test_selected_detail_schema_matches_finite_oracle_shape(self):
        """The machine schema carries the same closed envelope the oracle
        enforces: key sets, required keys, finite vocabularies and the
        mode-linked row shapes resolve to the shared $defs."""
        section = evidence_schema()["properties"]["selected_detail"]
        self.assertEqual(set(section["properties"]), set(CHECKER["SELECTED_DETAIL_KEYS"]))
        self.assertEqual(set(section["required"]), set(CHECKER["SELECTED_DETAIL_REQUIRED"]))
        self.assertFalse(section["additionalProperties"])
        self.assertNotIn("selected_detail", evidence_schema()["required"])
        selection = section["properties"]["selection"]
        self.assertEqual(set(selection["properties"]),
                         set(CHECKER["SELECTED_DETAIL_SELECTION_KEYS"]))
        self.assertEqual(set(selection["required"]),
                         set(CHECKER["SELECTED_DETAIL_SELECTION_REQUIRED"]))
        self.assertEqual(set(selection["properties"]["refusal"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_SELECTION_REFUSALS"]))
        branches = section["properties"]["events"]["items"]["anyOf"]
        self.assertEqual(len(branches), 7)
        window = next(branch for branch in branches
                      if "enum" in branch["properties"]["event"])
        self.assertEqual(set(window["properties"]["event"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_WINDOW_EVENTS"]))
        by_event = {branch["properties"]["event"]["const"]: branch
                    for branch in branches
                    if "const" in branch["properties"]["event"]}
        self.assertEqual(set(window["required"]),
                         set(CHECKER["SELECTED_DETAIL_WINDOW_ROW_KEYS"]))
        self.assertEqual(
            set(window["properties"]),
            set(CHECKER["SELECTED_DETAIL_WINDOW_ROW_KEYS"]) | {"note"})
        self.assertEqual(set(by_event["close_refused"]["required"]),
                         set(CHECKER["SELECTED_DETAIL_CLOSE_REFUSED_KEYS"]))
        self.assertEqual(set(by_event["close_refused"]["properties"]["refusal"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_GATE_WORDS"]))
        self.assertEqual(set(by_event["reserve_refused"]["required"]),
                         set(CHECKER["SELECTED_DETAIL_RESERVE_REFUSED_KEYS"]))
        self.assertEqual(set(by_event["reserve_refused"]["properties"]["refusal"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_ADAPTER_WORDS"]))
        self.assertEqual(set(by_event["start_refused"]["required"]),
                         set(CHECKER["SELECTED_DETAIL_START_REFUSED_KEYS"]))
        self.assertEqual(set(by_event["start_refused"]["properties"]["reason"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_REFUSAL_LABELS"]))
        outcomes = [branch for branch in branches
                    if branch["properties"]["event"].get("const") == "promotion_outcome"]
        self.assertEqual(len(outcomes), 3)
        by_outcome = {branch["properties"]["outcome"]["const"]: branch
                      for branch in outcomes}
        self.assertEqual(set(by_outcome), set(CHECKER["SELECTED_DETAIL_OUTCOMES"]))
        self.assertEqual(set(by_outcome["refused"]["properties"]["reason"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_REFUSAL_LABELS"]))
        self.assertEqual(set(by_outcome["ended"]["properties"]["reason"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_END_LABELS"]))
        self.assertEqual(set(by_outcome["active"]["required"]),
                         {"event", "request", "outcome", "caller", "provider"})
        lineage = section["properties"]["lineage"]
        self.assertEqual(set(lineage["required"]),
                         set(CHECKER["SELECTED_DETAIL_LINEAGE_KEYS"]))
        self.assertEqual(set(lineage["properties"]["after_read"]["enum"]),
                         set(CHECKER["SELECTED_DETAIL_AFTER_READS"]))
        drifts = lineage["properties"]["drift"]["anyOf"]
        self.assertIn({"type": "null"}, drifts)
        self.assertEqual({branch["properties"]["kind"]["const"] for branch in drifts
                          if branch.get("type") == "object"},
                         set(CHECKER["SELECTED_DETAIL_DRIFT_KINDS"]))
        for fragment, keys in (("aggregate", CHECKER["SELECTED_DETAIL_AGGREGATE_KEYS"]),
                               ("detail", CHECKER["SELECTED_DETAIL_DETAIL_KEYS"])):
            with self.subTest(fragment=fragment):
                shape = section["properties"][fragment]
                self.assertEqual(set(shape["required"]), set(keys))
                self.assertEqual(set(shape["properties"]), set(keys))
                self.assertEqual(set(shape["properties"]["mode"]["enum"]),
                                 set(CHECKER["SELECTED_DETAIL_MODES"]))
                linked = {}
                for clause in shape["allOf"]:
                    mode = clause["if"]["properties"]["mode"]["const"]
                    pointer = clause["then"]["properties"]["rows"]["items"]["$ref"]
                    row = SCHEMA
                    for key in pointer.removeprefix("#/").split("/"):
                        row = row[key]
                    linked[mode] = row
                self.assertEqual(set(linked), set(CHECKER["SELECTED_DETAIL_MODES"]))
                self.assertEqual(
                    set(linked["counts"]["required"]),
                    set(CHECKER["SELECTED_DETAIL_ROW_BASE_KEYS"]))
                self.assertEqual(
                    set(linked["timestamps"]["required"]) -
                    set(CHECKER["SELECTED_DETAIL_ROW_BASE_KEYS"]),
                    {"total_ns", "max_ns"})
                self.assertEqual(
                    set(linked["latency"]["required"]) -
                    set(CHECKER["SELECTED_DETAIL_ROW_BASE_KEYS"]),
                    {"total_ns", "max_ns", "buckets"})
                buckets = linked["latency"]["properties"]["buckets"]
                self.assertEqual(buckets["minItems"], CHECKER["SELECTED_DETAIL_LATENCY_BUCKETS"])
                self.assertEqual(buckets["maxItems"], CHECKER["SELECTED_DETAIL_LATENCY_BUCKETS"])
        mark = SCHEMA["$defs"]["selected_detail_bracket_mark"]
        self.assertEqual(set(mark["required"]), set(CHECKER["SELECTED_DETAIL_MARK_KEYS"]))
        self.assertEqual(set(mark["properties"]), set(CHECKER["SELECTED_DETAIL_MARK_KEYS"]))

    def test_current_metrics_requires_backend_but_historical_shape_excludes_it(self):
        current = self.metrics_document()
        self.assertEqual(current["evidence"].get("attach_backend"),
                         {"selection": "auto", "fallback": None, "scope_filter": "perf-task+bpf"})
        CHECKER["exact_metrics_schema"](current)
        missing = copy.deepcopy(current)
        missing["evidence"].pop("attach_backend")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](missing)
        historical = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["HISTORICAL_METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")
        self.assertNotIn("attach_backend", historical["evidence"])
        CHECKER["exact_historical_metrics_schema"](historical)
        historical["evidence"]["attach_backend"] = current["evidence"]["attach_backend"]
        with self.assertRaises(AssertionError):
            CHECKER["exact_historical_metrics_schema"](historical)

    def test_current_metrics_requires_ring_accounting_but_historical_shape_excludes_it(self):
        current = self.metrics_document()
        self.assertEqual(current["evidence"].get("ring_accounting"), {})
        CHECKER["exact_metrics_schema"](current)
        missing = copy.deepcopy(current)
        missing["evidence"].pop("ring_accounting")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](missing)
        historical = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["HISTORICAL_METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")
        self.assertNotIn("ring_accounting", historical["evidence"])
        CHECKER["exact_historical_metrics_schema"](historical)
        historical["evidence"]["ring_accounting"] = {}
        with self.assertRaises(AssertionError):
            CHECKER["exact_historical_metrics_schema"](historical)

    def test_metrics_backend_shape_and_scope_twins(self):
        document = self.metrics_document()
        document["evidence"]["attach_backend"] = {
            "selection": "multi", "fallback": None, "scope_filter": "kernel-pid+bpf"}
        for scope in ("pid", "system", "cgroup"):
            with self.subTest(scope=scope):
                valid = copy.deepcopy(document)
                valid["capture"]["scope"] = scope
                valid["evidence"]["attach_backend"]["scope_filter"] = (
                    "kernel-pid+bpf" if scope == "pid" else None)
                CHECKER["exact_metrics_schema"](valid)
                invalid = copy.deepcopy(valid)
                invalid["evidence"]["attach_backend"]["scope_filter"] = (
                    None if scope == "pid" else "kernel-pid+bpf")
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        for field in ("selection", "fallback", "scope_filter"):
            with self.subTest(missing=field):
                invalid = copy.deepcopy(document)
                del invalid["evidence"]["attach_backend"][field]
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)
        for values in ({"extra": 1}, {"selection": "always"}, {"fallback": "failed"},
                       {"scope_filter": "kernel-pid"}):
            with self.subTest(values=values):
                invalid = copy.deepcopy(document)
                invalid["evidence"]["attach_backend"].update(values)
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)

    def test_current_metrics_requires_object_capture_but_historical_shape_excludes_it(self):
        current = self.metrics_document()
        self.assertEqual(current["evidence"].get("object_capture"),
                         {"available": True, "reason": None})
        CHECKER["exact_metrics_schema"](current)
        missing = copy.deepcopy(current)
        missing["evidence"].pop("object_capture")
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](missing)
        historical = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}), schema=CHECKER["HISTORICAL_METRICS_SCHEMA"],
            mode="metrics", privacy="aggregate-only")
        self.assertNotIn("object_capture", historical["evidence"])
        CHECKER["exact_historical_metrics_schema"](historical)
        historical["evidence"]["object_capture"] = current["evidence"]["object_capture"]
        with self.assertRaises(AssertionError):
            CHECKER["exact_historical_metrics_schema"](historical)

    def test_object_capture_shape_twins(self):
        document = self.metrics_document()
        for value in ({"available": True, "reason": None},
                      {"available": False, "reason": "not_enabled"}):
            with self.subTest(value=value):
                valid = copy.deepcopy(document)
                valid["evidence"]["object_capture"] = value
                CHECKER["exact_metrics_schema"](valid)
        for value in ({"available": True, "reason": "not_enabled"},
                      {"available": False, "reason": None},
                      {"available": "yes", "reason": None},
                      {"available": True}):
            with self.subTest(value=value):
                invalid = copy.deepcopy(document)
                invalid["evidence"]["object_capture"] = value
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)

    def test_evidence_keys_match_oracle_closed_sets(self):
        """Schema evidence properties are exactly the oracle's closed key
        universe: base keys + profile-only keys + run-only child flag +
        the optional additive envelopes (counter, selection, excludes,
        forwarding, legacy, short-lived splits) and the two additive
        annotations (refused pause, snapshot failure)."""
        wanted = (
            set(CHECKER["BASE_EVIDENCE_KEYS"])
            | set(CHECKER["PROFILE_V3_FIELDS"])
            | {"child_still_running", "run_tree_handed_back",
               "counter_collection", "selected_detail",
               "excluded_modules", "unmatched_excludes", "legacy_collection",
               "gap_exe_hints", "target_exec_hints", "gap_exit_mappings",
               "unmatched_forwarding", "pause_refused", "snapshot_failure"}
        )
        self.assertEqual(set(evidence_schema()["properties"]), wanted)

    def test_excluded_modules_shape_twins(self):
        document = self.metrics_document()
        valid = copy.deepcopy(document)
        valid["evidence"]["excluded_modules"] = [
            {"path": "/lib/x.so", "dev": 8, "ino": 42, "processes": 3}
        ]
        valid["evidence"]["unmatched_excludes"] = ["nope.so"]
        CHECKER["exact_metrics_schema"](valid)
        for excluded, unmatched in (
            ([{"path": "", "dev": 8, "ino": 42, "processes": 3}], ["nope.so"]),
            ([{"path": "/lib/x.so", "dev": 8, "ino": 42, "processes": 0}],
             ["nope.so"]),
            ([{"path": "/lib/x.so", "dev": 8, "ino": 42}], ["nope.so"]),
            ([{"path": "/lib/x.so", "dev": 8, "ino": 42, "processes": 3,
               "extra": 1}], ["nope.so"]),
            ([{"path": "/lib/x.so", "dev": 8, "ino": 42, "processes": 3}],
             [42]),
        ):
            with self.subTest(excluded=excluded, unmatched=unmatched):
                invalid = copy.deepcopy(document)
                invalid["evidence"]["excluded_modules"] = excluded
                invalid["evidence"]["unmatched_excludes"] = unmatched
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)

    def test_unmatched_forwarding_shape_twins(self):
        document = self.metrics_document()
        valid = copy.deepcopy(document)
        valid["evidence"]["unmatched_forwarding"] = ["nope.so"]
        CHECKER["exact_metrics_schema"](valid)
        for unmatched in (["nope.so", 42], "nope.so", [None]):
            with self.subTest(unmatched=unmatched):
                invalid = copy.deepcopy(document)
                invalid["evidence"]["unmatched_forwarding"] = unmatched
                with self.assertRaises(AssertionError):
                    CHECKER["exact_metrics_schema"](invalid)

    def test_metrics_required_is_oracle_base(self):
        """Metrics requires exactly the oracle base key set."""
        self.assertEqual(
            set(evidence_schema()["required"]), set(CHECKER["BASE_EVIDENCE_KEYS"])
        )

    def test_profile_branch_requires_versioned_only_fields(self):
        """The lane==profile branch requires exactly the 4 versioned-only
        fields; the metrics branch forbids them plus the profile-only
        exit-mapping split (no instance hooks under metrics)."""
        branches = SCHEMA["allOf"]
        profile = next(
            b
            for b in branches
            if b["if"] == {"properties": {"lane": {"const": "profile"}}}
        )
        self.assertEqual(
            set(profile["then"]["properties"]["evidence"]["required"]),
            set(CHECKER["PROFILE_V3_FIELDS"]),
        )
        metrics = next(
            b
            for b in branches
            if b["if"] == {"properties": {"lane": {"const": "metrics"}}}
        )
        forbidden = {
            req
            for clause in metrics["then"]["properties"]["evidence"]["not"]["anyOf"]
            for req in clause["required"]
        }
        self.assertEqual(
            forbidden, set(CHECKER["PROFILE_V3_FIELDS"]) | {"gap_exit_mappings"}
        )

    def test_function_row_identity_matches_oracle(self):
        """`functions[].target` and `.ordinals` keys and bounds match the
        oracle's closed row-identity shape (review answer (c))."""
        row = SCHEMA["properties"]["functions"]["items"]["properties"]
        self.assertEqual(
            set(row["target"]["properties"]), set(CHECKER["FUNCTION_TARGET_KEYS"])
        )
        self.assertEqual(
            set(row["ordinals"]["items"]["properties"]),
            set(CHECKER["FUNCTION_ORDINAL_KEYS"]),
        )
        self.assertEqual(
            row["ordinals"]["items"]["properties"]["ordinal"]["maximum"] + 1,
            CHECKER["MAX_FUNCTION_ORDINALS"],
        )

    def test_function_timing_availability_has_three_closed_shapes(self):
        row = SCHEMA["properties"]["functions"]["items"]["properties"]
        self.assertIn("latency_ns", row, "function timing needs an explicit consumer contract")
        shapes = row["latency_ns"]["oneOf"]
        self.assertEqual(len(shapes), 3)
        self.assertIn({"type": "null"}, shapes)
        objects = [shape for shape in shapes if shape.get("type") == "object"]
        self.assertEqual(len(objects), 2)
        for shape in objects:
            self.assertIs(type(shape["properties"]["approximate"]["const"]), bool)
        by_approximation = {shape["properties"]["approximate"]["const"]: shape
                            for shape in objects}
        self.assertEqual(set(by_approximation), {True, False})
        fields = {"approximate", "p50", "p95", "p99", "total", "max"}
        for approximate, shape in by_approximation.items():
            with self.subTest(approximate=approximate):
                self.assertFalse(shape["additionalProperties"])
                self.assertEqual(set(shape["required"]), fields)
                self.assertEqual(set(shape["properties"]), fields)
                for field in ("total", "max"):
                    self.assertEqual(shape["properties"][field],
                                     {"type": "integer", "minimum": 0, "maximum": 2**64 - 1})
                for field in ("p50", "p95", "p99"):
                    self.assertEqual(
                        shape["properties"][field],
                        {"type": ["integer", "null"], "minimum": 0, "maximum": 2**64 - 1}
                        if approximate else {"type": "null"},
                    )

    def test_pid_namespace_shape_matches_oracle(self):
        """`evidence.pid_namespace` is the oracle's closed object (DR-K8S-2)."""
        pidns = evidence_schema()["properties"]["pid_namespace"]
        self.assertEqual(set(pidns["properties"]), set(CHECKER["PID_NAMESPACE_KEYS"]))
        self.assertEqual(set(pidns["required"]), set(CHECKER["PID_NAMESPACE_KEYS"]))
        self.assertEqual(
            set(pidns["properties"]["observer"]["enum"]),
            set(CHECKER["PID_NAMESPACE_OBSERVERS"]),
        )
        self.assertEqual(
            set(pidns["properties"]["proc_pids"]["enum"]),
            set(CHECKER["PID_NAMESPACE_PROC_PIDS"]),
        )

    def test_gap_classes_shape_matches_oracle(self):
        """`evidence.gap_classes` keys match the oracle's closed set."""
        classes = evidence_schema()["properties"]["gap_classes"]
        self.assertEqual(set(classes["properties"]), set(CHECKER["GAP_CLASS_KEYS"]))
        self.assertEqual(set(classes["required"]), set(CHECKER["GAP_CLASS_KEYS"]))

    def test_enums_match_oracle(self):
        """Closed enums in the schema equal the oracle's vocabularies."""
        props = evidence_schema()["properties"]
        self.assertEqual(
            set(props["verdict_detail"]["enum"]), set(CHECKER["VERDICT_DETAILS"])
        )
        self.assertEqual(
            set(props["pause"]["enum"]), set(CHECKER["PAUSE_VALUES"])
        )
        self.assertEqual(
            set(props["completeness"]["enum"]), {"COMPLETE", "PARTIAL"}
        )
        self.assertEqual(
            set(props["p11scope_env"]["items"]["properties"]["name"]["enum"]),
            set(CHECKER["P11SCOPE_ENV_VARS"]),
        )
        skip_reasons = set(
            props["skipped"]["items"]["properties"]["reason"]["enum"]
        )
        self.assertEqual(
            skip_reasons,
            set(CHECKER["ENTRY_REASONS"])
            | set(CHECKER["DISCOVERY_REASONS"])
            | set(CHECKER["RUN_TREE_REASONS"])
            | set(CHECKER["HANDOFF_REASONS"]),
        )

    def test_handoff_partial_profile_validates(self):
        """A handoff `-o` JSON — the failed step plus every drain/read gap
        the seals file — validates against the oracle behind the schema."""
        document = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}))
        evidence = document["evidence"]
        evidence["skipped"] = [
            {"name": name, "reason": reason}
            for name, reasons in CHECKER["HANDOFF_REASONS_BY_SUBJECT"].items()
            for reason in sorted(reasons)
        ]
        CHECKER["settle_fixture_verdict"](document)
        CHECKER["discovery_skips"](evidence)
        CHECKER["exact_profile_v3_selection"](document)

    def test_handoff_vocabulary_matches_producer(self):
        """The oracle's handoff vocabulary is exactly what `src/run.rs`
        emits: transcription drift between the producer consts and this
        checker fails closed here."""
        run_rs = (ROOT / "src" / "run.rs").read_text(encoding="utf-8")
        kinds = {"REASON": set(), "GAP": set(), "STEP": set()}
        for const, value in re.findall(
            r'const (HANDOFF_(?:REASON|GAP|STEP)_\w+): &str =\s*"([^"]*)";',
            run_rs,
        ):
            kinds[const.split("_")[1]].add(value)
        self.assertEqual(set(kinds["REASON"]), set(CHECKER["HANDOFF_REASONS"]))
        self.assertEqual(
            set(kinds["GAP"]) | set(kinds["STEP"]),
            set(CHECKER["HANDOFF_SUBJECTS"]),
        )
        self.assertEqual(
            set(SCHEMA["properties"]["lane"]["enum"]),
            {CHECKER["PROFILE_LANE"], CHECKER["METRICS_LANE"]},
        )

    def test_selection_shape_matches_oracle(self):
        """Selection sub-object keys and bounds match the oracle."""
        selection = evidence_schema()["properties"]["interface_selection"]
        self.assertEqual(
            set(selection["properties"]), set(CHECKER["SELECTION_KEYS"])
        )
        self.assertEqual(
            set(
                selection["properties"]["providers"]["items"]["properties"][
                    "coverage"
                ]["enum"]
            ),
            set(CHECKER["SELECTION_COVERAGE"]),
        )
        self.assertEqual(
            set(
                selection["properties"]["tuples"]["items"]["properties"][
                    "authority"
                ]["enum"]
            ),
            set(CHECKER["SELECTION_AUTHORITIES"]),
        )

    def test_scheduling_shape_matches_oracle(self):
        """Scheduling closed keys match the oracle."""
        scheduling = evidence_schema()["properties"]["scheduling"]
        self.assertEqual(
            set(scheduling["properties"]), set(CHECKER["SCHEDULING_KEYS"])
        )
        self.assertEqual(
            set(scheduling["properties"]["phase_ms"]["properties"]),
            set(CHECKER["SCHEDULING_PHASE_KEYS"]),
        )

    def hint_split(self, **overrides):
        split = {
            "label": "STATIC HINT",
            "scope": ("D-transitive depth=2 objects<=32 edges<=128 "
                      "exe-bytes<=1MiB capture-bytes<=64MiB "
                      "names<=255B verdicts<=1024"),
            "links_provider": 1, "links_pkcs11_loader": 0,
            "no_static_link_within_scope": 0, "unknown": 2,
        }
        split.update(overrides)
        return split

    def exit_split(self, **overrides):
        split = {"mapped": 1, "unknown": 2}
        split.update(overrides)
        return split

    def gap_armed_profile_document(self):
        document = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}))
        evidence = document["evidence"]
        evidence["gap_exe_hints"] = self.hint_split()
        evidence["gap_exit_mappings"] = self.exit_split()
        return document

    def target_armed_profile_document(self):
        document = CHECKER["document_fixture"](
            CHECKER["evidence_fixture"]({}))
        document["evidence"]["target_exec_hints"] = self.hint_split(
            links_provider=0)
        return document

    def test_short_lived_splits_accepted_in_profile_metrics_and_terminal(self):
        """Armed evidence carries the short-lived splits in every lane
        that publishes them: profile and metrics documents plus the
        terminal trace EVIDENCE object. The engine arms exactly one
        consumer per capture, so each document carries either the gap
        splits or the target split, never both; metrics never carries
        the exit-mapping split (no instance hooks there)."""
        CHECKER["exact_profile_v3_selection"](
            self.gap_armed_profile_document())
        CHECKER["exact_profile_v3_selection"](
            self.target_armed_profile_document())
        gap_metrics = self.metrics_document()
        gap_metrics["evidence"]["gap_exe_hints"] = self.hint_split()
        CHECKER["exact_metrics_schema"](gap_metrics)
        target_metrics = self.metrics_document()
        target_metrics["evidence"]["target_exec_hints"] = self.hint_split()
        CHECKER["exact_metrics_schema"](target_metrics)
        terminal = copy.deepcopy(
            self.gap_armed_profile_document()["evidence"])
        terminal.update(
            privacy_mode="allowlisted", capture_aborted=None,
            final_drain=False, counters_available=True,
            trace_truncated=False,
        )
        CHECKER["exact_profile_v3_selection"](terminal, terminal=True)

    def test_short_lived_splits_wrong_lane_or_combined_rejected(self):
        """The exit-mapping split is profile-only (metrics never arms
        it), and the gap splits never publish together with the
        target split (one consumer per capture)."""
        metrics = self.metrics_document()
        metrics["evidence"]["gap_exit_mappings"] = self.exit_split()
        with self.assertRaises(AssertionError):
            CHECKER["exact_metrics_schema"](metrics)
        combined = self.gap_armed_profile_document()
        combined["evidence"]["target_exec_hints"] = self.hint_split()
        with self.assertRaises(AssertionError):
            CHECKER["exact_profile_v3_selection"](combined)

    def test_short_lived_splits_malformed_rejected(self):
        """Each split validates its closed shape: exact keys, the
        STATIC HINT label and scope, and saturating-u64 counts."""
        cases = [
            ("gap_exe_hints", self.hint_split(label="STATIC GUESS")),
            ("gap_exe_hints", self.hint_split(scope="D-direct")),
            ("gap_exe_hints", self.hint_split(extra=1)),
            ("gap_exe_hints", {k: v for k, v in self.hint_split().items()
                               if k != "unknown"}),
            ("gap_exe_hints", self.hint_split(links_provider=-1)),
            ("gap_exe_hints", self.hint_split(unknown="2")),
            ("target_exec_hints", self.hint_split(label="STATIC GUESS")),
            ("target_exec_hints", self.hint_split(extra=1)),
            ("gap_exit_mappings", self.exit_split(extra=1)),
            ("gap_exit_mappings", {"mapped": 1}),
            ("gap_exit_mappings", self.exit_split(mapped=-1)),
            ("gap_exit_mappings", self.exit_split(unknown="2")),
        ]
        for key, bad in cases:
            with self.subTest(key=key, bad=bad):
                if key == "target_exec_hints":
                    document = self.target_armed_profile_document()
                else:
                    document = self.gap_armed_profile_document()
                document["evidence"][key] = bad
                with self.assertRaises(AssertionError):
                    CHECKER["exact_profile_v3_selection"](document)

    def test_short_lived_split_schemas_match_oracle(self):
        """Schema properties for the three splits are the oracle's
        closed shapes: exact keys, pinned label/scope, u64 counts."""
        props = evidence_schema()["properties"]
        for key in ("gap_exe_hints", "target_exec_hints"):
            with self.subTest(key=key):
                split = props[key]
                self.assertFalse(split["additionalProperties"])
                self.assertEqual(
                    set(split["properties"]),
                    set(CHECKER["STATIC_HINT_SPLIT_KEYS"]),
                )
                self.assertEqual(
                    split["properties"]["label"]["const"],
                    CHECKER["STATIC_HINT_LABEL"],
                )
                self.assertEqual(
                    split["properties"]["scope"]["const"],
                    CHECKER["STATIC_HINT_SCOPE"],
                )
                for count in ("links_provider", "links_pkcs11_loader",
                              "no_static_link_within_scope", "unknown"):
                    self.assertEqual(
                        split["properties"][count],
                        {"type": "integer", "minimum": 0},
                    )
        mappings = props["gap_exit_mappings"]
        self.assertFalse(mappings["additionalProperties"])
        self.assertEqual(
            set(mappings["properties"]),
            set(CHECKER["EXIT_MAPPINGS_SPLIT_KEYS"]),
        )
        for count in ("mapped", "unknown"):
            self.assertEqual(
                mappings["properties"][count],
                {"type": "integer", "minimum": 0},
            )


class PrearmOracleAgreement(unittest.TestCase):
    """Packet 6.13: the oracle admits the prearm source shapes and checks
    the additive watch keys."""

    def evidence(self, sources):
        return CHECKER["evidence_fixture"]({}, sources)

    def test_prearm_source_shapes_admitted(self):
        for sources in (
            ("prearm",),
            ("scan", "prearm"),
            ("manifest", "prearm"),
            ("scan", "manifest", "prearm"),
        ):
            evidence = self.evidence(sources)
            CHECKER["exact_discovery_semantics"](evidence)

    def test_prearm_only_reads_uncorroborated(self):
        evidence = self.evidence(("prearm",))
        module = evidence["discovery"][0]
        self.assertEqual(module["corroboration"], ["uncorroborated"])
        self.assertFalse(module["corroborated"])
        self.assertEqual(evidence["discovery_uncorroborated"], 1)

    def test_prearm_fixture_carries_no_tables(self):
        evidence = self.evidence(("prearm",))
        self.assertEqual(evidence["discovery"][0]["tables"], [])

    def test_watch_keys_accepted_and_rejected(self):
        evidence = self.evidence(("prearm",))
        module = evidence["discovery"][0]
        module["watch"] = {"since_ns": None, "state": "pinned_unarmed"}
        module["attached_at_ns"] = None
        CHECKER["exact_discovery_semantics"](evidence)
        module["watch"] = {
            "since_ns": 100,
            "state": "ended",
            "until_ns": 300,
            "ended_by": "object_changed",
            "changed": {
                "last_ok_ns": 200,
                "detected_ns": 300,
                "previous_ino": 42,
            },
        }
        module["attached_at_ns"] = 900
        module["unobserved_windows"] = [
            {"start_ns": 50, "end_ns": 900, "reason": "pre_attach"}
        ]
        CHECKER["exact_discovery_semantics"](evidence)
        for bad in (
            {"since_ns": None, "state": "watched"},
            {"since_ns": None, "state": "armed", "ended_by": "cancel"},
            {
                "since_ns": 100,
                "state": "ended",
                "changed": {
                    "last_ok_ns": 300,
                    "detected_ns": 200,
                    "previous_ino": 42,
                },
            },
        ):
            broken = copy.deepcopy(evidence)
            broken["discovery"][0]["watch"] = bad
            with self.assertRaises(AssertionError):
                CHECKER["exact_discovery_semantics"](broken)
        broken = copy.deepcopy(evidence)
        broken["discovery"][0]["unobserved_windows"] = [
            {"start_ns": 50, "end_ns": 900, "reason": "missed_calls"}
        ]
        with self.assertRaises(AssertionError):
            CHECKER["exact_discovery_semantics"](broken)

    def test_watch_shapes_enforce_keys_ordering_and_coherence(self):
        """Residual 6.13 review: the oracle closes watch/window shapes."""
        changed = {
            "last_ok_ns": 200,
            "detected_ns": 300,
            "previous_ino": 42,
        }
        valid = (
            {"since_ns": None, "state": "pinned_unarmed"},
            {"since_ns": None, "state": "unavailable"},
            {"since_ns": 100, "state": "armed"},
            {"since_ns": 100, "state": "armed_idle"},
            # Legitimate clock-unknown end: latched cause, no invented stamps.
            {"since_ns": None, "state": "ended", "ended_by": "attached"},
            # Never-mapped cancel and natural closes.
            {
                "since_ns": None,
                "state": "ended",
                "until_ns": 300,
                "ended_by": "scope_end",
            },
            {
                "since_ns": 100,
                "state": "armed_idle",
                "until_ns": 300,
                "ended_by": "scope_end",
            },
            {
                "since_ns": 100,
                "state": "ended",
                "until_ns": 300,
                "ended_by": "object_changed",
                "changed": dict(changed),
            },
        )
        for watch in valid:
            evidence = self.evidence(("prearm",))
            evidence["discovery"][0]["watch"] = copy.deepcopy(watch)
            CHECKER["exact_discovery_semantics"](evidence)
        invalid = (
            # Reversed interval, idle without arm, ended without cause,
            # synthetic extra key.
            {
                "since_ns": 300,
                "state": "armed_idle",
                "until_ns": 100,
                "ended_by": "scope_end",
            },
            {"since_ns": None, "state": "armed_idle"},
            {"since_ns": 100, "state": "ended", "until_ns": 200},
            {
                "since_ns": 100,
                "state": "armed_idle",
                "until_ns": 200,
                "ended_by": "scope_end",
                "raw_pin": "SYNTHETIC",
            },
            # Coherence: end causes only on ended/preserved-idle, a natural
            # close alone preserves idle, until implies an end, changed
            # implies object_changed, unarmed waits carry no arm instant.
            {"since_ns": 100, "state": "armed", "ended_by": "scope_end"},
            {"since_ns": 100, "state": "armed_idle", "ended_by": "health_loss"},
            {"since_ns": 100, "state": "armed", "until_ns": 200},
            {
                "since_ns": 100,
                "state": "ended",
                "until_ns": 200,
                "ended_by": "scope_end",
                "changed": dict(changed),
            },
            {"since_ns": 100, "state": "pinned_unarmed"},
            {"since_ns": 100, "state": "unavailable"},
        )
        for watch in invalid:
            broken = self.evidence(("prearm",))
            broken["discovery"][0]["watch"] = copy.deepcopy(watch)
            with self.assertRaises(
                AssertionError, msg=f"oracle accepted {watch!r}"
            ):
                CHECKER["exact_discovery_semantics"](broken)
        # Windows close their keys and order their bounds too.
        evidence = self.evidence(("prearm",))
        evidence["discovery"][0]["unobserved_windows"] = [
            {"start_ns": 50, "end_ns": 900, "reason": "pre_attach", "extra": 1}
        ]
        with self.assertRaises(AssertionError):
            CHECKER["exact_discovery_semantics"](evidence)
        evidence["discovery"][0]["unobserved_windows"] = [
            {"start_ns": 900, "end_ns": 50, "reason": "pre_attach"}
        ]
        with self.assertRaises(AssertionError):
            CHECKER["exact_discovery_semantics"](evidence)


class InitializationRowAgreement(unittest.TestCase):
    """functions[].initialization: the optional v3-additive Initialize claim.

    The release oracle does not close functions[] row keys (subset checks
    only), so there is no oracle vocabulary to agree with here: these pins
    lock the machine schema's additive shape instead — optional, closed
    sub-object, finite outcome words, likelihood true-only.
    """

    def row_schema(self):
        return SCHEMA["properties"]["functions"]["items"]

    def test_initialization_is_optional_with_finite_outcome(self):
        row = self.row_schema()
        self.assertIn("initialization", row["properties"])
        self.assertNotIn("initialization", row["required"])
        init = row["properties"]["initialization"]
        self.assertFalse(init["additionalProperties"])
        self.assertEqual(set(init["required"]), {"outcome"})
        self.assertEqual(
            set(init["properties"]["outcome"]["enum"]),
            {"ok", "already_initialized", "error", "mixed"},
        )

    def test_initialization_potential_provider_is_true_only(self):
        row = self.row_schema()
        self.assertIn("initialization", row["properties"])
        init = row["properties"]["initialization"]
        self.assertEqual(
            set(init["properties"]), {"outcome", "potential_provider"}
        )
        self.assertEqual(
            init["properties"]["potential_provider"], {"const": True}
        )


class RvNamesRowAgreement(unittest.TestCase):
    """functions[].rv_names: the v3-additive CKR name map.

    Like initialization above, the oracle closes only the object-canary
    row keys, so this pins the machine schema's additive shape instead:
    a hex-keyed object of nonempty name strings, never required (older
    v3 documents predate it and must stay valid).
    """

    def row_schema(self):
        return SCHEMA["properties"]["functions"]["items"]

    def test_rv_names_is_an_optional_hex_to_name_map(self):
        row = self.row_schema()
        self.assertIn("rv_names", row["properties"])
        self.assertNotIn("rv_names", row["required"])
        names = row["properties"]["rv_names"]
        self.assertEqual(names["type"], "object")
        self.assertEqual(
            names["additionalProperties"], {"type": "string", "minLength": 1}
        )


if __name__ == "__main__":
    unittest.main()
