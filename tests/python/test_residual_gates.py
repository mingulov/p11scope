# SPDX-License-Identifier: GPL-3.0-or-later
"""SYSPLAN residual CI/doc gates (F-04, F-28, F-27, F-63, F-40, F-30, F-29).

Each test pins one residual finding's recurring gate: a privileged E2E job,
a release-preview job, an advisory/deny gate, a scripts lint gate, a
coverage gate with a ratchet, a help/usage drift check, and the flake
quarantine mapping. All fail until the gates land (RED); the suite stays
green by implementation, never by weakening.

Run: python3 -I tests/python/test_residual_gates.py -v
"""

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

    def test_scripts_lint_gate_exists(self):
        """F-63: shellcheck/ruff CI over scripts/."""
        text = ci_text()
        self.assertIn("shellcheck", text)
        self.assertIn("ruff", text)

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
