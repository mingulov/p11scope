# SPDX-License-Identifier: GPL-3.0-or-later
"""SYSPLAN residual CI/doc gates (F-04, F-28, F-27, F-63, F-40, F-30, F-29).

Each test pins one residual finding's recurring gate: a privileged E2E job,
a release-preview job, an advisory/deny gate, a scripts lint gate, a
coverage gate with a ratchet, a help/usage drift check, and the flake
quarantine mapping. All fail until the gates land (RED); the suite stays
green by implementation, never by weakening.

Run: python3 -I tests/python/test_residual_gates.py -v
"""

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
DENY_TOML = ROOT / "deny.toml"
QUARANTINE = ROOT / "docs" / "notes" / "test-quarantine.md"


def ci_text():
    return CI_YML.read_text(encoding="utf-8")


class ResidualGates(unittest.TestCase):
    def test_privileged_e2e_job_exists(self):
        """F-04: one privileged CI E2E job running the gated capture cells."""
        text = ci_text()
        self.assertIn("privileged-e2e", text)
        self.assertIn("system-scope-measure", text)

    def test_release_preview_job_exists(self):
        """F-28: release-preview CI job (musl/docker/SBOM/build-release)."""
        text = ci_text()
        self.assertIn("release-preview", text)
        self.assertIn("build-release.sh", text)

    def test_dispatch_only_jobs_can_be_dispatched(self):
        """F-28: jobs gated on workflow_dispatch need that trigger in `on:`;
        without it they can never run."""
        text = ci_text()
        on_line = next(line for line in text.splitlines() if line.startswith("on:"))
        on_block = on_line
        if on_line == "on:":
            on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("workflow_dispatch", on_block)
        for job in ("privileged-e2e", "release-preview"):
            block = text.split(f"\n  {job}:\n", 1)[1]
            gate = block.splitlines()[0].strip()
            self.assertTrue(
                gate.startswith("if: ${{ github.event_name == 'workflow_dispatch'"),
                f"{job}: {gate}",
            )

    def test_release_preview_passes_an_evidence_root(self):
        """F-28: build-release.sh exits 2 without its one evidence-root
        argument, whose parent also supplies the private temporary directory."""
        block = ci_text().split("\n  release-preview:\n", 1)[1]
        block = block.split("\n  coverage:\n", 1)[0]
        self.assertIn('mkdir -m 700 "$RUNNER_TEMP/release-evidence"', block)
        self.assertIn(
            '- run: TMPDIR="$RUNNER_TEMP/release-evidence" '
            'scripts/build-release.sh "$RUNNER_TEMP/release-evidence/receipt"',
            block,
        )
        self.assertNotIn("- run: scripts/build-release.sh\n", block)

    def test_advisory_gate_exists(self):
        """F-27: cargo audit/deny CI gate + deny.toml."""
        text = ci_text()
        self.assertTrue(
            "cargo-audit" in text or "cargo audit" in text, "no cargo audit gate"
        )
        self.assertTrue(
            "cargo-deny" in text or "cargo deny" in text, "no cargo deny gate"
        )
        self.assertTrue(DENY_TOML.is_file(), "deny.toml missing")

    def test_release_summary_exposes_fixed_diagnostics_without_private_log_text(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_CANARY_/secret-path/::error::untrusted"
        cases = (
            (
                "=== release privacy gate ===\n"
                "=== live safe START policy: hostile exact-name and mechanism controls ===\n",
                "capture-stopped-canary: observer-readiness: CustodyError\n",
                "privacy-gate", "canary-safe-start", "matched-signature",
                ["observer-readiness-custody-error"], [], [],
            ),
            (
                "=== p11scope: isolated safe-only official static build ===\n",
                "error[E0463]: private compiler input\nPermission denied (os error 13)\n",
                "static-build", "unknown", "matched-signature", [], ["E0463"], ["EACCES"],
            ),
            (
                "=== release privacy gate === " + private + "\n",
                private + "\n",
                "unknown", "unknown", "unknown", [], [], [],
            ),
        )
        for stdout, stderr, stage, substage, classification, signatures, codes, errnos in cases:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                receipt = root / "receipt"
                receipt.mkdir()
                (receipt / "stdout.log").write_text(stdout + private + "\n")
                (receipt / "stderr.log").write_text(stderr + private + "\n")
                (receipt / "facts.log").write_text("head\t" + private + "\n")
                (receipt / "status").write_text("1\n")
                summary = root / "summary.md"
                result = subprocess.run(
                    [sys.executable, "-I", "-", str(receipt), str(summary)],
                    input=program, text=True, capture_output=True, check=True,
                )
                self.assertIn("release-diagnostic: ", result.stdout)
                report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
                self.assertEqual(report["last_recorded_stage"], stage)
                self.assertEqual(report["last_recorded_substage"], substage)
                self.assertEqual(report["stderr_classification"], classification)
                self.assertEqual(report["observed_signature_ids"], signatures)
                self.assertEqual(report["rustc_error_codes"], codes)
                self.assertEqual(report["observed_errno_names"], errnos)
                rendered = result.stdout + result.stderr + summary.read_text()
                self.assertNotIn(private, rendered)
                self.assertNotIn("private compiler input", rendered)

    def test_release_summary_locates_canary_assertions_without_their_values(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_::error::canary-bytes"
        stderr = (
            "Traceback (most recent call last):\n"
            f'  File "/{private}/scripts/check-canary-evidence.py", line 705, in private_function\n'
            "    assert evidence_total == 2, evidence_total\n"
            f"AssertionError: {private}\n"
            f'  File "/{private}/unknown.py", line 123, in unknown_function\n'
            f'  File "/{private}/capture-stopped-canary.py", line 0, in unknown_function\n'
            f'  File "/{private}/check-canary-evidence.py", line 1234567, in unknown_function\n'
            'canary-failure-location: capture-stopped-canary.py:773\n'
            f'canary-failure-location: {private}:123\n'
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir()
            (receipt / "stderr.log").write_text(stderr)
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(receipt), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report.get("python_failure_locations"), [
                {"script": "capture-stopped-canary.py", "line": 773},
                {"script": "check-canary-evidence.py", "line": 705},
            ])
            self.assertIn("python-assertion-failed", report["observed_signature_ids"])
            rendered = result.stdout + result.stderr + summary.read_text()
            for forbidden in (private, "private_function", "unknown.py", "unknown_function",
                              "assert evidence_total", "1234567"):
                self.assertNotIn(forbidden, rendered)

    def test_scripts_lint_gate_exists(self):
        """F-63: shellcheck/ruff CI over scripts/."""
        text = ci_text()
        self.assertIn("shellcheck", text)
        self.assertIn("ruff", text)

    def test_caught_capture_rejection_is_located_without_publishing_its_data(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_CAPTURE_SCHEMA_AND_PATH"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / private
            capture.write_text(json.dumps({"schema": private, "evidence": {}}))
            rejected = subprocess.run(
                [sys.executable, "-I", str(ROOT / "scripts/check-capture-evidence.py"),
                 "canary", "owned-default-metrics", str(capture)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(rejected.returncode, 1)
            receipt = root / "receipt"
            receipt.mkdir()
            (receipt / "stderr.log").write_text(rejected.stderr)
            (receipt / "stdout.log").write_text(
                "=== release privacy gate ===\n"
                "=== live diagnostic START policy: distinct template faults ===\n"
                "=== owned-default-metrics (default owned metrics) ===\n"
            )
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(receipt), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report["last_recorded_substage"], "canary-owned-default-metrics")
            self.assertIn("capture-evidence-rejected", report["observed_signature_ids"])
            locations = report["python_failure_locations"]
            self.assertTrue(locations)
            self.assertTrue(all(row["script"] == "check-capture-evidence.py" for row in locations))
            source = (ROOT / "scripts/check-capture-evidence.py").read_text().splitlines()
            self.assertTrue(any('"schema"' in source[row["line"] - 1] for row in locations))
            for forbidden in (private, str(root), "capture evidence rejected:"):
                self.assertNotIn(forbidden, result.stdout + result.stderr + summary.read_text())

    def test_release_summary_reports_only_known_bounded_counter_mismatches(self):
        import runpy

        checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0])
        errors = []
        for name in checker["COUNTERS"]:
            values = dict.fromkeys(checker["COUNTERS"], 0)
            values[name] = 3
            with self.assertRaises(AssertionError) as caught:
                checker["exact_counters"](values)
            errors.append(f"capture evidence rejected: {caught.exception}\n")
        errors.extend([
            "capture evidence rejected: PRIVATE_COUNTER_NAME: want 0, got 3\n",
            "capture evidence rejected: event_loss: want 0, got 18446744073709551616\n",
            "capture evidence rejected: event_loss: want -1, got 3\n",
            "capture evidence rejected: event_loss: want 0, got True\n",
            "capture evidence rejected: event_loss: want 0, got 4 PRIVATE_VALUE\n",
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "stderr.log").write_text("".join(errors))
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(root), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report["counter_mismatches"], [
                {"counter": name, "expected": 0, "observed": 3}
                for name in sorted(checker["COUNTERS"])
            ])
            public = result.stdout + result.stderr + summary.read_text()
            for private in ("PRIVATE_COUNTER_NAME", "PRIVATE_VALUE", "18446744073709551616"):
                self.assertNotIn(private, public)

    def test_coverage_gate_exists(self):
        """F-40: llvm-cov/tarpaulin CI gate with a ratchet."""
        text = ci_text()
        self.assertTrue(
            "llvm-cov" in text or "tarpaulin" in text, "no coverage gate"
        )

    def test_help_drift_check_exists(self):
        """F-30: CI drift check for flags/help/usage agreement."""
        text = ci_text()
        self.assertTrue(
            "help-drift" in text or "test_help_usage_drift" in text,
            "no help/usage drift check in CI",
        )

    def test_flake_quarantine_mapping_exists(self):
        """F-29: the 7 documented flakes have a quarantine mapping."""
        self.assertTrue(QUARANTINE.is_file(), f"{QUARANTINE} missing")
        text = QUARANTINE.read_text(encoding="utf-8")
        for name in (
            "lane13_evidence_finalizes_only_after_owned_cleanup",
            "metadata_canary_matrix",
            "stopped_canary_capture_lifecycle",
            "native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup",
            "actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines",
            "release_seal_denies_the_caller_path_to_every_reached_command",
            "signal_settlement_observes_second_sigint_during_fallback_term_grace",
        ):
            self.assertIn(name, text)


class ResidualOracleKeys(unittest.TestCase):
    def test_oracle_pins_new_evidence_keys(self):
        """F-02/F-01/F-15: oracle pins drain_proven, verdict_detail,
        uretprobe_override, handoff_child_pid."""
        import runpy

        checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        keys = checker["BASE_EVIDENCE_KEYS"]
        for key in (
            "drain_proven",
            "verdict_detail",
            "uretprobe_override",
            "handoff_child_pid",
        ):
            self.assertIn(key, keys)


class VerdictRecompute(unittest.TestCase):
    """Review answer (a) / F-1: the oracle recomputes `verdict_detail` from
    the published counters and refuses a document that disagrees."""

    def setUp(self):
        import runpy

        self.checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))

    def evidence(self, **counters):
        checker = self.checker
        evidence = checker["evidence_fixture"](checker["LEGACY_SURFACES"])
        evidence.update(table_entries=68, slots=68, active_slots=68, attached_probes=136)
        evidence.update(counters)
        settle = checker.get("settle_fixture_verdict")
        if settle is not None:
            settle(evidence)
        return evidence

    def test_a_lossy_document_cannot_claim_a_clean_detail(self):
        evidence = self.evidence(unmatched_returns=1)
        self.checker["exact_terminal_verdict"](evidence)
        evidence["verdict_detail"] = "clean_but_unproven"
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](evidence)

    def proven(self, **stop):
        """A clean document whose drain the stop gate proved (ruling B)."""
        evidence = self.evidence()
        evidence["stop_quiescence"] = dict(
            {"state": "proven", "post_q_events": False, "post_q_discovery": False}, **stop
        )
        evidence["drain_proven"] = True
        self.checker["settle_fixture_verdict"](evidence)
        evidence["completeness"] = self.checker["expected_terminal_completeness"](evidence)
        return evidence

    def test_a_proven_clean_drain_is_complete(self):
        evidence = self.proven()
        self.assertEqual(evidence["verdict_detail"], "clean_proven")
        self.assertEqual(evidence["completeness"], "COMPLETE")
        self.checker["exact_terminal_verdict"](evidence)
        partial = dict(evidence, completeness="PARTIAL")
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](partial)

    def test_the_latch_needs_a_proven_quiescence_without_post_q_records(self):
        for stop in (
            {"post_q_events": True},
            {"post_q_discovery": True},
            {"state": "unproven"},
            {"state": "not_reached"},
        ):
            with self.subTest(stop=stop), self.assertRaises(AssertionError):
                self.checker["exact_terminal_verdict"](self.proven(**stop))

    def test_a_post_q_flag_needs_a_proven_quiescence(self):
        evidence = self.evidence()
        evidence["stop_quiescence"] = {
            "state": "unproven", "post_q_events": True, "post_q_discovery": False,
        }
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](evidence)
        evidence["stop_quiescence"]["state"] = "proven"
        self.checker["exact_terminal_verdict"](evidence)

    def test_withheld_names_alone_are_attribution_only(self):
        evidence = self.evidence(semantic_unverified_slots=68)
        self.assertEqual(evidence["verdict_detail"], "attribution_only")
        self.checker["exact_terminal_verdict"](evidence)
        for wrong in ("concrete_gap", "clean_but_unproven"):
            bad = dict(evidence, verdict_detail=wrong)
            with self.assertRaises(AssertionError):
                self.checker["exact_terminal_verdict"](bad)


if __name__ == "__main__":
    unittest.main()
