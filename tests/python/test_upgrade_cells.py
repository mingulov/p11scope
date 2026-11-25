#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Upgrade cells: package upgrade (gate 5) and report compat (gate 6).

Gate 5 is a root-only cell (installs DEB/RPM); this suite pins its script
contract without installing: argument parsing, the non-root refusal, typed
emitter behaviour through the script's self-test mode, and the schema/key
pins gate 6 consumes. The live upgrade runs in the upgrade-cells workflow
and on the fedora host via scripts/upgrade-gate5.sh.

Gate 6's end-to-end leg lives in .github/workflows/upgrade-cells.yml and in
the release-candidate host runs. This suite pins its pure typed checks and
the exact B1/B2/B3 schema deltas from the tree alone.
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE5 = ROOT / "scripts/upgrade-gate5.sh"
GATE6_PATH = ROOT / "scripts/upgrade-gate6.py"


def load_gate6():
    spec = importlib.util.spec_from_file_location("upgrade_gate6_under_test", GATE6_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_package_release():
    spec = importlib.util.spec_from_file_location(
        "package_release_under_test", ROOT / "scripts/package-release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UpgradeGate5ContractTests(unittest.TestCase):
    def run_gate5(self, *args):
        return subprocess.run(
            ["bash", str(GATE5), *args],
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_gate5_rejects_bad_format(self):
        r = self.run_gate5("--format", "bogus")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--format", r.stderr)

    @unittest.skipUnless(os.geteuid() != 0, "root can install; refusal is unreachable")
    def test_gate5_refuses_valid_args_without_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            old = base / "old.pkg"
            new = base / "new.pkg"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            workdir = base / "work"
            r = self.run_gate5(
                "--format", "deb",
                "--old", str(old),
                "--new", str(new),
                "--workdir", str(workdir),
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("must run as root", r.stderr)
            self.assertFalse(workdir.exists(), "refusal must happen before any install state")

    def test_gate5_self_test_emits_exact_typed_results(self):
        expected_keys = {
            "gate",
            "format",
            "status",
            "old_package",
            "new_package",
            "binary",
            "old_version",
            "new_version",
            "old_package_version",
            "new_package_version",
            "doctor_old_rc",
            "doctor_new_rc",
            "doctor_rcs_equal",
            "capture_old_rc",
            "capture_new_rc",
            "canary_recovery_sha_before",
            "canary_recovery_sha_after",
            "canary_report_sha_before",
            "canary_report_sha_after",
            "canary_survived",
            "fail_reason",
        }
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_gate5("--self-test", tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            passed = json.loads((Path(tmp) / "gate5-result.json").read_text())
            mismatch = json.loads((Path(tmp) / "gate5-result-mismatch.json").read_text())
            doctor_mismatch = json.loads(
                (Path(tmp) / "gate5-result-doctor-mismatch.json").read_text()
            )
            empty_hash = json.loads((Path(tmp) / "gate5-result-empty-hash.json").read_text())
        self.assertEqual(set(passed), expected_keys)
        self.assertEqual(set(mismatch), expected_keys)
        self.assertEqual(set(doctor_mismatch), expected_keys)
        self.assertEqual(set(empty_hash), expected_keys)
        self.assertEqual(passed["gate"], 5)
        self.assertEqual(passed["binary"], "/usr/bin/p11scope")
        self.assertEqual(passed["status"], "pass")
        self.assertIs(passed["doctor_rcs_equal"], True)
        self.assertIs(passed["canary_survived"], True)
        self.assertEqual(len(passed["canary_recovery_sha_before"]), 64)
        self.assertIs(mismatch["canary_survived"], False)
        self.assertNotEqual(
            mismatch["canary_report_sha_before"], mismatch["canary_report_sha_after"]
        )
        self.assertIs(doctor_mismatch["doctor_rcs_equal"], False)
        self.assertNotEqual(doctor_mismatch["doctor_old_rc"], doctor_mismatch["doctor_new_rc"])
        self.assertEqual(empty_hash["canary_recovery_sha_before"], "")
        self.assertEqual(empty_hash["canary_recovery_sha_after"], "")
        self.assertIs(empty_hash["canary_survived"], False)


class UpgradeGate6PureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()

    def test_initial_result_has_exact_breaking_list_and_shape(self):
        result = self.gate6.initial_result()
        self.assertEqual(set(result), {"gate", "status", "checks", "breaking", "notes", "fail_reason"})
        self.assertEqual(result["gate"], 6)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["checks"], {})
        self.assertEqual(result["fail_reason"], "")
        self.assertEqual(
            result["breaking"],
            ["departed_use", "live_joint_feed_absent", "profile_evidence_fields"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.gate6.emit(Path(tmp), result, 0)
            self.assertEqual(code, 0)
            emitted = json.loads((Path(tmp) / "gate6-result.json").read_text())
        self.assertEqual(emitted, result)

    def test_b1_and_additive_pins_are_exact(self):
        self.assertEqual(
            set(self.gate6.B1_KEYS),
            {
                "budgets.callers.late_refused",
                "budgets.callers.retired",
                "budgets.callers.retired_with_calls",
                "budgets.departed_use",
                "budgets.departed_use.identities_dropped",
                "budgets.departed_use.mech_overflow",
                "budgets.edges.folded",
                "budgets.edges.folded_entries",
                "budgets.instances.folded",
                "budgets.native_departed",
                "budgets.native_departed.exec_prune_overflow",
                "budgets.native_departed.pair_dropped_base",
                "budgets.native_departed.pair_dropped_rows",
                "budgets.native_departed.pair_prune_overflow",
                "modules[0].departed_use",
            },
        )
        self.assertEqual(
            set(self.gate6.ADDITIVE_KEYS),
            {
                "observation.semantic_capture.length_insert_failures",
                "observation.semantic_capture.length_stash_mismatches",
            },
        )

    def test_flatten_keys_unions_every_list_element(self):
        value = {
            "modules": [
                {"path": "one", "departed_use": None},
                {"path": "two", "extra": {"nested": 1}},
            ]
        }
        self.assertEqual(
            set(self.gate6.flatten_keys(value)),
            {
                "modules",
                "modules[0].path",
                "modules[0].departed_use",
                "modules[0].extra",
                "modules[0].extra.nested",
            },
        )

    def test_b1_delta_is_exact_in_both_directions(self):
        old_keys = {"schema", "modules[0].path"}
        good_new = old_keys | set(self.gate6.B1_KEYS) | set(self.gate6.ADDITIVE_KEYS)
        delta = self.gate6.evaluate_b1_delta(old_keys, good_new)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["unexpected"], set())
        self.assertEqual(delta["missing_b1"], set())

        missing = self.gate6.evaluate_b1_delta(old_keys, good_new - {"budgets.edges.folded"})
        self.assertEqual(missing["missing_b1"], {"budgets.edges.folded"})
        unexpected = self.gate6.evaluate_b1_delta(old_keys, good_new | {"modules[0].surprise"})
        self.assertEqual(unexpected["unexpected"], {"modules[0].surprise"})
        removed = self.gate6.evaluate_b1_delta(old_keys, good_new - {"modules[0].path"})
        self.assertEqual(removed["removed"], {"modules[0].path"})

    def test_reason_membership_uses_enum_not_description(self):
        schema = {
            "properties": {
                "reason": {
                    "enum": ["none"],
                    "description": "mentions live_joint_feed_absent only in prose",
                }
            }
        }
        self.assertFalse(self.gate6.schema_reason_has(schema, "live_joint_feed_absent"))
        schema["properties"]["reason"]["enum"].append("live_joint_feed_absent")
        self.assertTrue(self.gate6.schema_reason_has(schema, "live_joint_feed_absent"))

    def test_cbom_properties_are_typed_exactly(self):
        doc = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:object_observations", "value": "partial (live_joint_feed_absent)"},
                    {"name": "unrelated", "value": "x"},
                ]
            }
        }
        props = self.gate6.cbom_properties(doc)
        self.assertEqual(
            props["p11scope:object_observations"], "partial (live_joint_feed_absent)"
        )
        self.assertEqual(props["unrelated"], "x")

    def test_run_timeout_is_a_typed_failure_result(self):
        completed = self.gate6.run(
            [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.2
        )
        self.assertEqual(completed.returncode, 124)
        self.assertIn("timeout", completed.stderr)

    def test_key_exists_recurses_typed_json(self):
        self.assertTrue(self.gate6.key_exists({"a": [{"departed_use": None}]}, "departed_use"))
        self.assertFalse(self.gate6.key_exists({"a": [{"other": "departed_use"}]}, "departed_use"))

    def test_diff_zero_requires_typed_empty_changes(self):
        good = {
            "schema": "p11scope/inventory-diff/v1",
            "application_changes": [],
            "module_path_changes": [],
        }
        self.assertTrue(self.gate6.diff_zero_same(good))
        self.assertFalse(self.gate6.diff_zero_same({**good, "application_changes": [{"x": 1}]}))
        self.assertFalse(self.gate6.diff_zero_same({**good, "module_path_changes": [{"x": 1}]}))
        self.assertFalse(self.gate6.diff_zero_same({**good, "schema": "other"}))

    def test_live_joint_render_requires_exact_reason(self):
        doc = {
            "metadata": {
                "properties": [
                    {
                        "name": "p11scope:object_observations",
                        "value": "partial (live_joint_feed_absent)",
                    }
                ]
            }
        }
        self.assertTrue(self.gate6.cbom_live_joint_rendered(doc))
        bogus = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:object_observations", "value": "partial (bogus_reason)"}
                ]
            }
        }
        self.assertFalse(self.gate6.cbom_live_joint_rendered(bogus))

    def test_profile_markers_require_exact_window_and_note(self):
        note = (
            "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
        )
        doc = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:source_schema", "value": "p11scope/observed-profile/v3"},
                    {
                        "name": "p11scope:window",
                        "value": "2026-01-01T00:00:00Z..2026-01-01T00:00:01Z (capture wall clock)",
                    },
                    {"name": "p11scope:profile_note", "value": note},
                ]
            }
        }
        self.assertTrue(self.gate6.cbom_profile_markers_present(doc))
        changed = json.loads(json.dumps(doc))
        changed["metadata"]["properties"][1]["value"] = "other"
        self.assertFalse(self.gate6.cbom_profile_markers_present(changed))


class UpgradeTestPackageTests(unittest.TestCase):
    def test_test_build_variant_never_claims_official(self):
        package = load_package_release()
        variant = package.system_package_variant("full", test_build=True)
        self.assertIn("TEST build", variant)
        self.assertIn("not an official release", variant)
        self.assertNotIn("FULL official build", variant)
        description = package.system_package_description("full", "0.7.2", test_build=True)
        self.assertIn(variant, description)


class UpgradeSchemaDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()

    def git_show(self, rev, path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        out = subprocess.run(
            ["git", "show", f"{rev}:{path}"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            check=True,
        )
        return out.stdout

    def test_b2_live_joint_only_in_new_reason_enums(self):
        names = [
            "docs/schema/inventory-v1-object-observations.schema.json",
            *(f"docs/schema/inventory-v1-object-observations-{ver}.schema.json" for ver in ("v2", "v3", "v4", "v5")),
        ]
        self.assertEqual(len(names), 5)
        for name in names:
            with self.subTest(name=name):
                old = json.loads(self.git_show("v0.7.1", name))
                new = json.loads((ROOT / name).read_text())
                old_enum = old["properties"]["reason"]["enum"]
                new_enum = new["properties"]["reason"]["enum"]
                self.assertNotIn("live_joint_feed_absent", old_enum)
                self.assertIn("live_joint_feed_absent", new_enum)

    def test_b3_then_required_adds_exactly_three(self):
        old = json.loads(
            self.git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json")
        )
        new = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )
        added = self.gate6.then_required(new) - self.gate6.then_required(old)
        self.assertEqual(
            added,
            {
                "pid_descendant_gaps_admitted",
                "member_stop_attached",
                "member_stop_unattached",
            },
        )

    def test_b3_full_required_adds_exactly_four(self):
        old = json.loads(
            self.git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json")
        )
        new = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )
        added = self.gate6.required_evidence(new) - self.gate6.required_evidence(old)
        removed = self.gate6.required_evidence(old) - self.gate6.required_evidence(new)
        self.assertEqual(
            added,
            {
                "pid_descendant_gaps_admitted",
                "member_stop_attached",
                "member_stop_unattached",
                "coverage_retired_slots",
            },
        )
        self.assertEqual(removed, set())


if __name__ == "__main__":
    unittest.main()
