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
            row.update({"outcome": "PASS", "test_ids": [row["id"] + "::test"],
                        "command": ["observer", "--exact", row["id"] + "::test"],
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
        self.assertEqual(self.verify()["passed"], 7)
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
