# SPDX-License-Identifier: GPL-3.0-or-later
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
        self.assertEqual(set(collection["properties"]), keys)
        self.assertFalse(collection["additionalProperties"])
        self.assertNotIn("counter_collection", evidence_schema()["required"])
        failure = collection["properties"]["failure"]["enum"]
        self.assertEqual(set(failure) - {None}, set(CHECKER["COUNTER_COLLECTION_FAILURES"]))
        self.assertIn(None, failure)

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
        universe: base keys + profile-only keys + run-only child flag."""
        wanted = (
            set(CHECKER["BASE_EVIDENCE_KEYS"])
            | set(CHECKER["PROFILE_V3_FIELDS"])
            | {"child_still_running", "counter_collection"}
        )
        self.assertEqual(set(evidence_schema()["properties"]), wanted)

    def test_metrics_required_is_oracle_base(self):
        """Metrics requires exactly the oracle base key set."""
        self.assertEqual(
            set(evidence_schema()["required"]), set(CHECKER["BASE_EVIDENCE_KEYS"])
        )

    def test_profile_branch_requires_versioned_only_fields(self):
        """The lane==profile branch requires exactly the 4 versioned-only
        fields; the metrics branch forbids them."""
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
        self.assertEqual(forbidden, set(CHECKER["PROFILE_V3_FIELDS"]))

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
            set(CHECKER["ENTRY_REASONS"]) | set(CHECKER["DISCOVERY_REASONS"]),
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


if __name__ == "__main__":
    unittest.main()
