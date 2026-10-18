# SPDX-License-Identifier: GPL-3.0-or-later
"""Causal mutations of the acceptance manifest and its execution receipts."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERIFY = runpy.run_path(str(ROOT / "scripts/verify-system-test-manifest.py"))


# Independently pinned bounded-scope population: literal identities, never
# derived from production metadata. Any membership change requires editing
# these lists AND the checked-in scope catalog together.
EXPECTED_BOUNDED_IN = frozenset({
    "T7.default.detailed_hot_slot_third_rv_lp64",
    "T7.default.inventory_n1024_lp64",
    "T7.default.inventory_n4097_lp64",
    "T7.default.inventory_n576_lp64",
    "T7.default.inventory_n6530_lp64",
    "T7.default.inventory_n6531_lp64",
    "T7.default.inventory_n8192_boundary_lp64",
    "T7.wide.detailed_hot_slot_third_rv_lp64",
    "finding:A-F8",
    "finding:F-01",
    "finding:F-02",
    "finding:F-03",
    "finding:F-04",
    "finding:F-08",
    "finding:F-09",
    "finding:F-10",
    "finding:F-11",
    "finding:F-12",
    "finding:F-13",
    "finding:F-14",
    "finding:F-15",
    "finding:F-16a",
    "finding:F-17",
    "finding:F-20",
    "finding:F-25",
    "finding:F-26",
    "finding:F-27",
    "finding:F-28",
    "finding:F-29",
    "finding:F-30",
    "finding:F-32",
    "finding:F-38",
    "finding:F-39",
    "finding:F-40",
    "finding:F-43",
    "finding:F-44",
    "finding:F-48",
    "finding:F-50",
    "finding:F-51",
    "finding:F-52",
    "finding:F-53",
    "finding:F-57",
    "finding:F-59",
    "finding:F-60",
    "finding:F-61b",
    "finding:F-62",
    "finding:F-63",
    "finding:F-65",
    "finding:F-67",
    "finding:F-68",
    "finding:F-69",
    "finding:F-70",
    "finding:F-71",
    "finding:F-72",
    "finding:F-73",
    "finding:F-74",
    "finding:F-75",
    "finding:O-15",
    "finding:R-01",
    "finding:R-02",
    "finding:R-03",
    "finding:R-04",
    "finding:R-05",
    "finding:R-06",
    "followup:G-13",
    "followup:G-16",
    "followup:U-01",
    "followup:U-05",
    "followup:U-06",
    "followup:U-09",
    "followup:U-12",
    "followup:U-19",
    "followup:U-20",
    "followup:U-21",
    "followup:U-22",
    "followup:U-24",
    "installed.current.default",
    "installed.current.wide",
    "installed.linux-5.15.default",
    "installed.linux-5.15.wide",
    "soak.1800s",
})
EXPECTED_BOUNDED_OUT = frozenset({
    "R01.public",
    "R02.public",
    "R03.public",
    "R04.public",
    "R05.public",
    "R06.public",
    "R07.public",
    "R08.public",
    "R09.public",
    "R10.public",
    "finding:A-F1",
    "finding:A-F2",
    "finding:A-F3",
    "finding:A-F4",
    "finding:A-F5",
    "finding:A-F6",
    "finding:A-F7",
    "finding:A-F9",
    "finding:E01",
    "finding:E02",
    "finding:E03",
    "finding:E04",
    "finding:E05",
    "finding:E06",
    "finding:E07",
    "finding:E08",
    "finding:E09",
    "finding:E10",
    "finding:E11",
    "finding:E12",
    "finding:E13",
    "finding:E14",
    "finding:E15",
    "finding:E16",
    "finding:E17",
    "finding:E18",
    "finding:E19",
    "finding:E20",
    "finding:E21",
    "finding:E22",
    "finding:E23",
    "finding:E24",
    "finding:E25",
    "finding:F-05",
    "finding:F-06",
    "finding:F-07",
    "finding:F-16b",
    "finding:F-18",
    "finding:F-19",
    "finding:F-21",
    "finding:F-22",
    "finding:F-23",
    "finding:F-24",
    "finding:F-31",
    "finding:F-33",
    "finding:F-34",
    "finding:F-35",
    "finding:F-36",
    "finding:F-37",
    "finding:F-41",
    "finding:F-42",
    "finding:F-45",
    "finding:F-46",
    "finding:F-47",
    "finding:F-49",
    "finding:F-54",
    "finding:F-55",
    "finding:F-56",
    "finding:F-58-D7",
    "finding:F-58-D8",
    "finding:F-58-E4",
    "finding:F-58-I3",
    "finding:F-58-R2",
    "finding:F-58-R3",
    "finding:F-58-R5",
    "finding:F-58-T7",
    "finding:F-61a",
    "finding:F-64",
    "finding:FB-F1",
    "finding:FB-F3",
    "finding:FB-F4",
    "finding:FB-F6",
    "finding:FB-F7",
    "finding:O-1",
    "finding:O-10",
    "finding:O-11",
    "finding:O-13",
    "finding:O-14",
    "finding:O-16",
    "finding:O-17",
    "finding:O-6",
    "followup:G-01",
    "followup:G-02",
    "followup:G-03",
    "followup:G-04",
    "followup:G-05",
    "followup:G-06",
    "followup:G-07",
    "followup:G-08",
    "followup:G-10",
    "followup:G-11",
    "followup:G-12",
    "followup:G-14",
    "followup:G-15",
    "followup:G-17",
    "followup:G-18",
    "followup:G-19",
    "followup:U-02",
    "followup:U-03",
    "followup:U-04",
    "followup:U-07",
    "followup:U-08",
    "followup:U-10",
    "followup:U-11",
    "followup:U-13",
    "followup:U-14",
    "followup:U-15",
    "followup:U-16",
    "followup:U-17",
    "followup:U-18",
    "soak.14400s",
    "soak.86400s",
})


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = VERIFY["new_manifest"]()
        self.manifest["subject"] = {"revision": "a" * 40, "tree": "b" * 40}
        self.payload = self.root / "observer"
        self.payload.write_bytes(b"owned test artifact")
        artifact = {"observer": {"path": "observer", "sha256": hashlib.sha256(self.payload.read_bytes()).hexdigest()}}
        for row in self.manifest["cells"]:
            if "t7-static" not in row["required_for_claims"]:
                continue
            tids = row["test_ids"] or [row["id"] + "::test"]
            row.update({"outcome": "PASS", "test_ids": list(tids),
                        "command": ["observer", "--exact", tids[0]],
                        "artifact_hashes": copy.deepcopy(artifact), "evidence_paths": ["observer"],
                        "receipt": row["id"] + ".json"})
            receipt = {"schema": "p11scope/test-execution/v1", "cell_id": row["id"],
                       "subject": self.manifest["subject"], "evidence_level": "live-mechanism",
                       "entrypoint": "private-live-test", "kernel_profile": row["kernel_profile"],
                       "test_ids": row["test_ids"], "executed_test_ids": row["test_ids"],
                       "command": row["command"], "exit_code": 0, "outcome": "PASS",
                       "artifact_hashes": artifact, "evidence_paths": row["evidence_paths"],
                       "observed_behavior": row["expected_behavior"]}
            receipt_path = self.root / row["receipt"]
            receipt_path.write_text(json.dumps(receipt))
            row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        self.row = next(row for row in self.manifest["cells"] if row["outcome"] == "PASS")

    def verify(self, **kwargs):
        return VERIFY["verify_manifest"](self.manifest, self.root, claim="t7-static", **kwargs)

    def change_receipt(self, **fields):
        path = self.root / self.row["receipt"]
        receipt = json.loads(path.read_text())
        receipt.update(fields)
        path.write_text(json.dumps(receipt))
        self.row["receipt_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_complete_selected_claim_passes_and_other_claim_stays_open(self):
        self.assertEqual(self.verify()["passed"], 8)
        with self.assertRaisesRegex(ValueError, "required cell"):
            VERIFY["verify_manifest"](self.manifest, self.root, claim="system-product")

    def test_missing_mandatory_row_is_rejected_even_if_manifest_drops_claim(self):
        self.manifest["cells"].remove(self.row)
        with self.assertRaisesRegex(ValueError, "missing mandatory"):
            self.verify()

    def test_deferred_measurement_gate_cannot_be_silently_omitted(self):
        row = next(row for row in self.manifest["cells"] if row["id"] == "followup:G-14")
        self.manifest["cells"].remove(row)
        with self.assertRaisesRegex(ValueError, "missing mandatory"):
            self.verify()

    def test_duplicate_ids_are_rejected(self):
        self.manifest["cells"].append(copy.deepcopy(self.row))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.verify()

    def test_required_claim_membership_cannot_be_removed(self):
        self.row["required_for_claims"] = []
        with self.assertRaisesRegex(ValueError, "claim membership"):
            self.verify()

    def test_missing_or_changed_artifacts_are_rejected(self):
        self.payload.write_bytes(b"different binary")
        with self.assertRaisesRegex(ValueError, "artifact"):
            self.verify()
        self.payload.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.verify()

    def test_empty_execution_is_rejected(self):
        self.change_receipt(executed_test_ids=[])
        with self.assertRaisesRegex(ValueError, "executed test"):
            self.verify()

    def test_empty_test_declaration_is_rejected(self):
        self.row["test_ids"] = []
        with self.assertRaisesRegex(ValueError, "empty test"):
            self.verify()

    def test_private_fixture_cannot_be_promoted_to_public(self):
        self.row["evidence_level"] = "public-command"
        self.change_receipt(evidence_level="public-command")
        with self.assertRaisesRegex(ValueError, "level|entrypoint"):
            self.verify()

    def test_receipt_cannot_label_an_ordinary_test_as_live(self):
        self.change_receipt(entrypoint="unit-test")
        with self.assertRaisesRegex(ValueError, "entrypoint"):
            self.verify()

    def test_changed_receipt_bytes_are_rejected(self):
        with (self.root / self.row["receipt"]).open("a") as stream:
            stream.write(" ")
        with self.assertRaisesRegex(ValueError, "receipt hash"):
            self.verify()

    def test_placeholder_matrix_cannot_close_a_product_requirement(self):
        row = next(row for row in self.manifest["cells"] if row["id"] == "R01.public")
        row["outcome"] = "PASS"
        with self.assertRaisesRegex(ValueError, "placeholder matrix"):
            self.verify()

    def test_soak_requires_installed_artifact_and_actual_duration(self):
        row = next(row for row in self.manifest["cells"] if row["id"] == "soak.1800s")
        for field in ["test_ids", "command", "artifact_hashes", "evidence_paths", "outcome"]:
            row[field] = copy.deepcopy(self.row[field])
        row["receipt"] = "soak.json"
        row["artifact_hashes"]["installed"] = copy.deepcopy(row["artifact_hashes"]["observer"])
        receipt = json.loads((self.root / self.row["receipt"]).read_text())
        receipt.update({"cell_id": row["id"], "evidence_level": "soak", "entrypoint": "installed-cli",
                        "kernel_profile": row["kernel_profile"], "artifact_hashes": row["artifact_hashes"],
                        "observed_behavior": row["expected_behavior"], "start_mono_ns": 1_000_000_000,
                        "end_mono_ns": 1800_000_000_000,
                        "installed_artifact_sha256": row["artifact_hashes"]["installed"]["sha256"]})
        def save():
            path = self.root / row["receipt"]
            path.write_text(json.dumps(receipt))
            row["receipt_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        save()
        with self.assertRaisesRegex(ValueError, "duration"):
            self.verify()
        receipt["end_mono_ns"] += 1_000_000_000
        save()
        self.verify()
        receipt.pop("installed_artifact_sha256")
        save()
        with self.assertRaisesRegex(ValueError, "installed artifact"):
            self.verify()

    def test_old_build_cannot_qualify_final_subject(self):
        self.change_receipt(subject={"revision": "c" * 40, "tree": "b" * 40})
        with self.assertRaisesRegex(ValueError, "subject"):
            self.verify()

    def test_failed_skipped_unsupported_and_absent_cells_fail_claim(self):
        for outcome in ["FAIL", "INVALID", "NOT_RUN", "UNSUPPORTED", "BLOCKED"]:
            with self.subTest(outcome=outcome):
                self.row["outcome"] = outcome
                with self.assertRaisesRegex(ValueError, "required cell"):
                    self.verify()

    def test_wrong_kernel_and_failed_exit_are_rejected(self):
        self.change_receipt(kernel_profile="different")
        with self.assertRaisesRegex(ValueError, "kernel_profile"):
            self.verify()
        self.change_receipt(kernel_profile=self.row["kernel_profile"], exit_code=101)
        with self.assertRaisesRegex(ValueError, "exit"):
            self.verify()

    def test_refusal_is_distinct_from_capture(self):
        boundary = next(row for row in self.manifest["cells"] if "n8192" in row["id"])
        path = self.root / boundary["receipt"]
        receipt = json.loads(path.read_text())
        receipt["observed_behavior"] = "capture"
        path.write_text(json.dumps(receipt))
        boundary["receipt_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "behavior"):
            self.verify()

    def test_paths_cannot_escape_evidence_root(self):
        self.row["receipt"] = "../outside.json"
        with self.assertRaisesRegex(ValueError, "escape"):
            self.verify()

    def test_bounded_release_claim_has_exact_membership(self):
        policies = VERIFY["catalog"]()
        system = {identifier for identifier, policy in policies.items()
                  if "system-product" in policy["required_for_claims"]}
        bounded = {identifier for identifier, policy in policies.items()
                   if "bounded-release" in policy["required_for_claims"]}
        # Independently pinned population: production membership must
        # equal the literal lists, never a metadata derivation. Nothing
        # here reads kernel_profile or any other production metadata.
        self.assertEqual(len(EXPECTED_BOUNDED_IN), 81)
        self.assertEqual(len(EXPECTED_BOUNDED_OUT), 122)
        self.assertEqual(bounded, EXPECTED_BOUNDED_IN)
        self.assertEqual(system - bounded, EXPECTED_BOUNDED_OUT)
        self.assertEqual(system, EXPECTED_BOUNDED_IN | EXPECTED_BOUNDED_OUT)
        scope = json.loads(Path(VERIFY["BOUNDED_SCOPE"]).read_text())
        self.assertEqual(scope["claim"], "bounded-release")
        self.assertEqual(scope["status"], "proposed-for-owner-approval")
        self.assertEqual(set(scope["in"]), EXPECTED_BOUNDED_IN)
        self.assertEqual({entry["id"] for entry in scope["out"]}, EXPECTED_BOUNDED_OUT)
        # Every exclusion carries an auditable reason naming its owning
        # campaign and the concrete condition that would move it IN.
        groups = {}
        for entry in scope["out"]:
            for key in ("reason", "owner_task", "move_in"):
                self.assertTrue(entry[key], f"{entry['id']}: empty {key}")
            self.assertEqual(entry["owner_task"], policies[entry["id"]]["owner_task"])
            groups[entry["reason_group"]] = groups.get(entry["reason_group"], 0) + 1
        self.assertEqual(groups, {"kernel-concretization-pending": 99,
                                 "public-oracle-unregistered": 11,
                                 "public-contract-unregistered": 10,
                                 "full-endurance": 2})
        # Spot identities: the 30-minute soak stays required, the 4h/24h
        # endurance soaks and the public-contract cells stay out.
        self.assertIn("soak.1800s", bounded)
        self.assertIn("soak.14400s", EXPECTED_BOUNDED_OUT)
        self.assertIn("soak.86400s", EXPECTED_BOUNDED_OUT)
        self.assertIn("R01.public", EXPECTED_BOUNDED_OUT)
        self.assertTrue(any(identifier.startswith("T7.") for identifier in bounded))
        static = {identifier for identifier, policy in policies.items()
                  if "t7-static" in policy["required_for_claims"]}
        self.assertEqual(len(static), 8)

    def test_placeholder_flip_cannot_change_bounded_membership(self):
        # Bounded membership comes only from the checked-in scope catalog:
        # flipping a cell's kernel metadata must not move it IN or OUT.
        # Only a catalog edit (pinned literally above) may do that.
        module = VERIFY["catalog"].__globals__
        old_ledger, old_deferred = module["LEDGER"], module["DEFERRED"]
        self.addCleanup(module.update, {"LEDGER": old_ledger, "DEFERRED": old_deferred})

        def recatalog():
            return {identifier for identifier, policy in VERIFY["catalog"]().items()
                    if "bounded-release" in policy["required_for_claims"]}

        # IN -> placeholder kernel: the cell must stay IN.
        ledger = json.loads(Path(old_ledger).read_text())
        for finding in ledger["findings"]:
            if finding["id"] == "A-F8":
                finding["disposition"] = "required-open"
        flipped = self.root / "ledger-flipped.json"
        flipped.write_text(json.dumps(ledger))
        module["LEDGER"] = flipped
        self.assertEqual(recatalog(), EXPECTED_BOUNDED_IN)
        module["LEDGER"] = old_ledger

        # A second IN cell via the deferred gates: still IN.
        gates = json.loads(Path(old_deferred).read_text())
        for group in gates["gates"]:
            if group["id"] == "U-01":
                group["evidence_level"] = "live-mechanism"
        flipped_gates = self.root / "deferred-flipped.json"
        flipped_gates.write_text(json.dumps(gates))
        module["DEFERRED"] = flipped_gates
        self.assertEqual(recatalog(), EXPECTED_BOUNDED_IN)
        module["DEFERRED"] = old_deferred

        # OUT -> concrete kernel: the cell must stay OUT; only a scope
        # catalog edit moves it IN.
        ledger = json.loads(Path(old_ledger).read_text())
        for finding in ledger["findings"]:
            if finding["id"] == "F-05":
                finding["disposition"] = "source-fixed"
        flipped2 = self.root / "ledger-concrete.json"
        flipped2.write_text(json.dumps(ledger))
        module["LEDGER"] = flipped2
        self.assertEqual(recatalog(), EXPECTED_BOUNDED_IN)
        module["LEDGER"] = old_ledger

    def pass_claim_row(self, row, artifact):
        """Give a closable row passing evidence with a consistent receipt."""
        tids = row["test_ids"] or [row["id"] + "::test"]
        row.update({"outcome": "PASS", "test_ids": list(tids),
                    "command": ["observer", "--exact", tids[0]],
                    "artifact_hashes": copy.deepcopy(artifact),
                    "evidence_paths": ["observer"],
                    "receipt": row["id"].replace(":", "_") + ".json"})
        if row["evidence_level"] in ("installed", "soak"):
            row["artifact_hashes"]["installed"] = copy.deepcopy(artifact["observer"])
        receipt = {"schema": "p11scope/test-execution/v1", "cell_id": row["id"],
                   "subject": self.manifest["subject"], "evidence_level": row["evidence_level"],
                   "entrypoint": VERIFY["ENTRYPOINTS"][row["evidence_level"]],
                   "kernel_profile": row["kernel_profile"],
                   "test_ids": row["test_ids"], "executed_test_ids": row["test_ids"],
                   "command": row["command"], "exit_code": 0, "outcome": "PASS",
                   "artifact_hashes": row["artifact_hashes"], "evidence_paths": row["evidence_paths"],
                   "observed_behavior": row["expected_behavior"]}
        if row["evidence_level"] in ("installed", "soak"):
            receipt["installed_artifact_sha256"] = row["artifact_hashes"]["installed"]["sha256"]
        if row["evidence_level"] == "soak":
            receipt["start_mono_ns"] = 0
            receipt["end_mono_ns"] = row["minimum_duration_s"] * 1_000_000_000
        receipt_path = self.root / row["receipt"]
        receipt_path.write_text(json.dumps(receipt))
        row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    def test_bounded_claim_cannot_pass_full_system_product(self):
        # A complete valid bounded fixture: every bounded-required cell
        # carries passing evidence with a consistent receipt, so the
        # bounded claim genuinely passes.
        artifact = {"observer": {"path": "observer",
                                 "sha256": hashlib.sha256(self.payload.read_bytes()).hexdigest()}}
        for row in self.manifest["cells"]:
            if "bounded-release" in row["required_for_claims"] and row["outcome"] != "PASS":
                self.pass_claim_row(row, artifact)
        report = VERIFY["verify_manifest"](self.manifest, self.root, claim="bounded-release")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["passed"], report["required"])
        # The same evidence bundle cannot pass the full claim.
        with self.assertRaisesRegex(ValueError, "required cell"):
            VERIFY["verify_manifest"](self.manifest, self.root, claim="system-product")
        with self.assertRaisesRegex(ValueError, "unknown acceptance claim"):
            VERIFY["verify_manifest"](self.manifest, self.root, claim="bounded-plus")
        policies = VERIFY["catalog"]()
        self.assertNotIn("bounded-release",
                         policies["soak.14400s"]["required_for_claims"])
        self.assertNotIn("bounded-release",
                         policies["soak.86400s"]["required_for_claims"])
        self.assertIn("system-product", policies["soak.14400s"]["required_for_claims"])
        self.assertIn("system-product", policies["soak.86400s"]["required_for_claims"])
        # The full-claim gap is exactly the catalog's OUT population:
        # all 122 bounded-excluded cells stay visible with their reasons
        # (nothing filtered out silently), order-independent.
        gap = {row["id"] for row in self.manifest["cells"]
               if "system-product" in row["required_for_claims"]
               and row["outcome"] != "PASS"}
        self.assertEqual(len(gap), 122)
        self.assertEqual(gap, EXPECTED_BOUNDED_OUT)
        scope = json.loads(Path(VERIFY["BOUNDED_SCOPE"]).read_text())
        reasons = {entry["id"]: entry["reason"] for entry in scope["out"]}
        self.assertTrue(all(reasons[identifier] for identifier in gap))
        # The verifier reports the first gap in row order; with the
        # endurance rows first the full-claim rejection names them.
        ordered = copy.deepcopy(self.manifest)
        soak = [row for row in ordered["cells"] if row["id"] in ("soak.14400s", "soak.86400s")]
        rest = [row for row in ordered["cells"] if row["id"] not in ("soak.14400s", "soak.86400s")]
        ordered["cells"] = soak + rest
        with self.assertRaisesRegex(ValueError, r"required cell soak\.14400s: NOT_RUN"):
            VERIFY["verify_manifest"](ordered, self.root, claim="system-product")
        # Row order is not authority: bounded still passes reordered.
        self.assertEqual(VERIFY["verify_manifest"](ordered, self.root,
                                                   claim="bounded-release")["verdict"], "PASS")

    def test_t7_selectors_survive_regeneration(self):
        expected = {
            "T7.default.inventory_n576_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64",
            "T7.default.inventory_n1024_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64",
            "T7.default.inventory_n4097_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64",
            "T7.default.inventory_n6530_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64",
            "T7.default.inventory_n6531_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6531_lp64",
            "T7.default.inventory_n8192_boundary_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64",
            "T7.default.detailed_hot_slot_third_rv_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64",
            "T7.wide.detailed_hot_slot_third_rv_lp64": "attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64",
        }
        fresh = VERIFY["new_manifest"]()
        seeded = {row["id"]: row["test_ids"] for row in fresh["cells"] if row["id"].startswith("T7.")}
        self.assertEqual(seeded, {identifier: [selector] for identifier, selector in expected.items()})
        # The checked-in open register is exactly the generator output:
        # any silent regen drift (selectors, memberships, limitations)
        # fails here instead of landing unnoticed.
        checked_in = json.loads((ROOT / "tests/fixtures/system-qualification/system-test-manifest.json").read_text())
        self.assertEqual(checked_in, fresh)

    def test_deferred_archive_gates_require_product_custody_not_agent_archives(self):
        deferred = json.loads(VERIFY["DEFERRED"].read_text())
        gates = {group["id"]: group for group in deferred["gates"]}
        for identifier in ("U-01", "U-21"):
            with self.subTest(gate=identifier):
                gate = gates[identifier]
                self.assertTrue(gate["required"])
                text = gate["gate"] + " " + gate["review_disposition"]
                self.assertNotIn("archiv", text.lower())
                self.assertTrue("hash" in text.lower() or "checksum" in text.lower())

    def test_structure_validation_does_not_qualify_an_open_manifest(self):
        report = VERIFY["verify_manifest"](VERIFY["new_manifest"](), self.root, structure_only=True)
        self.assertEqual(report["verdict"], "STRUCTURE_VALID")
        self.assertEqual(report["passed"], 0)

    def test_checked_in_register_remains_complete(self):
        manifest = json.loads((ROOT / "tests/fixtures/system-qualification/system-test-manifest.json").read_text())
        report = VERIFY["verify_manifest"](manifest, self.root, structure_only=True)
        self.assertFalse(report["qualification"])


if __name__ == "__main__":
    unittest.main()
