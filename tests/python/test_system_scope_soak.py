# SPDX-License-Identifier: GPL-3.0-or-later
"""Acceptance seams of the soak vehicle (scripts/system-scope-soak.sh).

The oracle's own --self-test battery proves every gate red-green on
synthetic evidence; this suite pins the seams around it: the battery
stays green, the manifest seeds the soak selectors, the dry-run shape
receipt is structurally complete yet rejected for the cell, the epoch
parser fails closed, and the runner carries its lock/lane/mode
discipline in its text.
Run: python3 -I tests/python/test_system_scope_soak.py -v
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts" / "system-scope-soak-oracle.py"
RUNNER = ROOT / "scripts" / "system-scope-soak.sh"
FIXTURE = ROOT / "tests/fixtures/system-qualification/system-test-manifest.json"

EXPECTED_SOAK_SELECTORS = {
    "soak.1800s": ["soak.1800s::continuous-owned-workload"],
    "soak.14400s": ["soak.14400s::continuous-owned-workload"],
    "soak.86400s": ["soak.86400s::continuous-owned-workload"],
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOAK = load_module("system_scope_soak_oracle", ORACLE)
VERIFY = load_module("soak_verify_manifest", ROOT / "scripts/verify-system-test-manifest.py")


class SoakVehicleTests(unittest.TestCase):
    def test_oracle_self_test_battery_is_green(self):
        result = subprocess.run(
            [sys.executable, "-I", str(ORACLE), "--self-test"],
            capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0,
                         f"battery failed:\n{result.stdout}\n{result.stderr}")
        self.assertIn("self-test: all legs green", result.stdout)

    def test_manifest_seeds_soak_selectors(self):
        self.assertEqual(VERIFY.SOAK_SELECTORS, EXPECTED_SOAK_SELECTORS)
        fresh = VERIFY.new_manifest()
        seeded = {row["id"]: row["test_ids"] for row in fresh["cells"]
                  if row["id"] in EXPECTED_SOAK_SELECTORS}
        self.assertEqual(seeded, EXPECTED_SOAK_SELECTORS)
        checked_in = json.loads(FIXTURE.read_text())
        pinned = {row["id"]: (row["test_ids"], row["command"], row["outcome"])
                  for row in checked_in["cells"]
                  if row["id"] in EXPECTED_SOAK_SELECTORS}
        for identifier, selector in EXPECTED_SOAK_SELECTORS.items():
            self.assertEqual(pinned[identifier], (selector, [], "NOT_RUN"),
                             f"{identifier}: selectors seeded, command filled at execution")

    def test_epoch_parser_fails_closed(self):
        self.assertEqual(SOAK.parse_epochs("no epochs here\n"), [])
        good = 'EPOCH {"epoch": 2, "calls": 5, "t_mono_ns": 9}\n'
        self.assertEqual(SOAK.parse_epochs(good),
                         [{"epoch": 2, "calls": 5, "t_mono_ns": 9}])
        for bad in ('EPOCH {"epoch": 0}\n',
                    "EPOCH not-json\n",
                    'EPOCH [1, 2]\n',
                    'EPOCH {"epoch": "0", "calls": 5, "t_mono_ns": 9}\n'):
            with self.subTest(line=bad):
                with self.assertRaises(SOAK.OracleError):
                    SOAK.parse_epochs(bad)

    def test_dry_run_shape_is_complete_but_rejected_for_the_cell(self):
        with tempfile.TemporaryDirectory(prefix="soak-suite-") as tmp:
            root = SOAK.make_synthetic_evidence(
                Path(tmp) / "dry", mode="dry-run", require_duration_s=10,
                epochs=4, epoch_s=2, epoch_calls=5)
            verdict = SOAK.evaluate(root)
            self.assertEqual(verdict["verdict"], "FAIL")
            self.assertFalse(verdict["gates"]["installed_identity"]["pass"])
            passing = dict(verdict, verdict="PASS",
                           gates={name: {"pass": True, "detail": "suite shape proof"}
                                  for name in SOAK.GATES})
            SOAK.write_json(root / "verdict.json", passing)
            shape = SOAK.build_receipt(root, passing, dry_run=True)
            for key in ("schema", "cell_id", "subject", "evidence_level",
                        "entrypoint", "kernel_profile", "test_ids",
                        "executed_test_ids", "command", "exit_code", "outcome",
                        "artifact_hashes", "evidence_paths",
                        "observed_behavior", "start_mono_ns", "end_mono_ns"):
                self.assertIn(key, shape, f"shape receipt lacks {key}")
            self.assertEqual(shape["observed_behavior"], "dry-run-loopback")
            with self.assertRaisesRegex(ValueError, "behavior"):
                SOAK.verify_soak_receipt(VERIFY, root, shape)

    def test_live_receipt_round_trip_through_the_verifier(self):
        with tempfile.TemporaryDirectory(prefix="soak-suite-") as tmp:
            root = SOAK.make_synthetic_evidence(Path(tmp) / "control")
            verdict = SOAK.evaluate(root)
            self.assertEqual(verdict["verdict"], "PASS", verdict["gates"])
            SOAK.write_json(root / "verdict.json", verdict)
            receipt = SOAK.build_receipt(root, verdict, dry_run=False)
            report = SOAK.verify_soak_receipt(VERIFY, root, receipt)
            self.assertEqual(report["verdict"], "STRUCTURE_VALID")

    def test_runner_carries_its_lock_lane_and_mode_discipline(self):
        source = RUNNER.read_text(encoding="utf-8")
        code = [line for line in source.splitlines()
                if not line.lstrip().startswith("#")]
        text = "\n".join(code)
        # Live mode requires an ancestor holding the privileged lock.
        self.assertIn("/proc/locks", text)
        self.assertIn("no ancestor holds the privileged lock", text)
        # The pre-free rule: refuse when the cargo lane is busy at start,
        # and never invoke cargo in-script.
        self.assertIn("v040-cargo-lane.lock", text)
        self.assertIn("free it before the window", text)
        scrubbed = text.replace("v040-cargo-lane.lock", "").replace(
            "cargo lane", "").replace("CARGO_LANE", "")
        self.assertNotIn("cargo", scrubbed)
        self.assertIn("Pre-free rule", source)
        # The release-matrix lane is never nested; it is named only to
        # forbid nesting.
        for line in code:
            self.assertNotIn("qualify-release-matrix", line)
        self.assertIn("qualify-release-matrix", source)
        # Mode separation is enforced, not conventional.
        self.assertIn("--dry-run refuses --installed", text)
        self.assertIn("live mode refuses --observer-stub", text)
        self.assertIn("live mode refuses --stub-arg", text)
        # The oracle hookup: the runner evaluates and writes the verdict.
        self.assertIn("system-scope-soak-oracle.py", text)
        self.assertIn("--out-verdict", text)
        self.assertIn("--out-receipt", text)
        self.assertIn("--dry-run-receipt", text)

    def test_runner_refuses_dirty_subject_and_bad_tuning(self):
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("tracked tree is dirty", source)
        self.assertIn("85%", source)
        self.assertIn("97%", source)
        self.assertIn("epochs do not divide the horizon", source)

    def test_oracle_stays_unprivileged_for_the_hosted_derivation(self):
        # The hosted UNRUN derivation flags a .py helper only for a quoted
        # elevated-invocation token or an elevated call site; the oracle
        # must stay an unprivileged --self-test step.
        source = ORACLE.read_text(encoding="utf-8")
        self.assertNotIn('"sudo"', source)
        self.assertNotIn("'sudo'", source)
        runner = RUNNER.read_text(encoding="utf-8")
        for line in runner.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "system-scope-soak-oracle.py" not in line:
                continue
            self.assertNotIn("sudo", line)
            self.assertNotIn("owned_launch root", line)


if __name__ == "__main__":
    unittest.main()
