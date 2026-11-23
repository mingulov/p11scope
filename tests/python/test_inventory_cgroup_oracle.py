# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Inventory-cgroup degraded-shape twins: accept the decided PARTIAL, refuse the rest.

When the kernel (K1) witness is unavailable under scoped cgroup
collection, the observer publishes PARTIAL: the owned module stays
admitted with its data, plus exactly three named gap families — the
per-caller original_file_unproven note, the per-caller scan-pinned
fallback, and the module-level unidentified-caller positive on the
owned module. The qualifier oracle must accept that shape (overlay or
no-witness) and still fail when the module is missing or any gap is
unnamed. The oracle block is extracted from
scripts/qualify-public-cli.sh (not copied) so the twins track the
real code.
"""

import ast
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUAL = ROOT / "scripts/qualify-public-cli.sh"

MODPATH = "/usr/lib64/pkcs11/libsofthsm2.so"
PIN = {"dev": [0, 46], "ino": 153887,
       "sha256": "611254bf118e3c4ef0f3ef3dd25667d984202ef10055b7d6d5da20d60898c5a5"}
UNPROVEN = ("original_file_unproven: kernel witness unavailable: "
            "scoped collection deactivates the kernel proof")
NATIVE = ("no settled expected native image for this caller in the "
          "acquisition domain; scan-pinned fallback retained")
REFRESH_RETAINED = ("the final-sample permit was not granted; "
                    "prior owner facts retained")
REFRESH_MEMBER_LOST = "the final-sample permit was not granted"
DEADLINE = "cgroup collection deadline reached"
PREP_INPUT_INTERRUPTED = "cgroup provider input comparison interrupted"
PREP_SUBJECT = "cgroup provider preparation incomplete"
DEADLINE_SUBJECT = "cgroup scope transaction incomplete"
UNBOUND_SUBJECT = "used by an unidentified caller image"
UNBOUND_FIRST = "no live caller incarnation held the tgid when the row was read"
UNBOUND_FIRST_EXITED = "the pinned caller exited before its cookie could be queried"


def unbound_reason(first=UNBOUND_FIRST):
    """The producer framing around one diagnosed binder first-cause."""
    return ("%s: native witness rows of this module were not bound to a caller "
            "incarnation (first: %s); module-level positive use only, never "
            "attributed by pid" % (MODPATH, first))


def extract_inventory_oracle():
    """Extract the inventory-cgroup python oracle block from the qualifier."""
    lines = QUAL.read_text().splitlines(keepends=True)
    start = next(
        i for i, line in enumerate(lines)
        if '"$cell-inside.wl"' in line
        and line.strip().startswith("python3 - "))
    end = next(i for i in range(start, len(lines))
               if lines[i].rstrip("\n") == "PY")
    return "".join(lines[start + 1:end])


def run_oracle(report, *, modfs, pin=None, modpath=MODPATH):
    """Run the extracted oracle against a fixture report."""
    block = extract_inventory_oracle()
    if pin is None:
        pin = PIN
    inside_wl = "READY pid=100\nCHILD pid=101\nLEDGER x\n"
    outside_wl = "READY pid=102\nLEDGER y\n"
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        (tmp / "r.json").write_text(json.dumps(report))
        (tmp / "in.wl").write_text(inside_wl)
        (tmp / "out.wl").write_text(outside_wl)
        proc = subprocess.run(
            ["python3", "-I", "-", "r.json", "in.wl", "out.wl",
             json.dumps(pin), modpath, modfs],
            input=block, capture_output=True, text=True, timeout=30,
            cwd=str(tmp))
    return proc.returncode, proc.stdout + proc.stderr


def run_oracle_optimized(report, *, modfs, pin=None, modpath=MODPATH):
    """Run the extracted oracle with assertions stripped (python3 -O)."""
    block = extract_inventory_oracle()
    if pin is None:
        pin = PIN
    inside_wl = "READY pid=100\nCHILD pid=101\nLEDGER x\n"
    outside_wl = "READY pid=102\nLEDGER y\n"
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        (tmp / "r.json").write_text(json.dumps(report))
        (tmp / "in.wl").write_text(inside_wl)
        (tmp / "out.wl").write_text(outside_wl)
        proc = subprocess.run(
            ["python3", "-I", "-O", "-", "r.json", "in.wl", "out.wl",
             json.dumps(pin), modpath, modfs],
            input=block, capture_output=True, text=True, timeout=30,
            cwd=str(tmp))
    return proc.returncode, proc.stdout + proc.stderr


def decided_report():
    """The decided degraded shape (rc-13 vng 7.3.1 evidence, local pids).

    One module, m0 libsofthsm2, admitted with its data (mapped, 68
    endpoints), inside edges from both callers, and exactly the three
    named gap families: per-caller unproven, per-caller scan-pinned
    fallback, and the module-level unidentified-caller positive.
    """
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "cgroup",
        "modules": [{"id": "m0",
                     "identity": {"device": {"major": 0, "minor": 46},
                                  "inode": 153887, "sha256": PIN["sha256"]},
                     "admission": {"state": "admitted", "endpoints": 68},
                     "lifecycle": "mapped",
                     "paths": [MODPATH]}],
        "callers": [{"id": "c0", "pid": 100}, {"id": "c1", "pid": 101}],
        "edges": [{"caller": "c0", "module": "m0"},
                  {"caller": "c1", "module": "m0"}],
        "gaps": [
            {"caller": "c0", "module": None, "pid": 100,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 10},
            {"caller": "c0", "module": None, "pid": 100,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 1},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 9},
            {"caller": None, "module": "m0", "pid": None,
             "reason": unbound_reason(), "subject": UNBOUND_SUBJECT,
             "repeats": 1},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 8},
        ],
    }


def witness_available_report():
    """Host-leg shape (hosted public-cli host, 7.0.0-azure evidence).

    The kernel witness ran on a non-overlay filesystem, so no
    per-caller original_file_unproven gap exists; the producer kept
    the named module-level unidentified-caller positive on the owned
    module plus the per-caller scan-pinned fallback gaps.
    """
    report = decided_report()
    report["gaps"] = [
        g for g in report["gaps"]
        if not (g.get("reason") or "").startswith("original_file_unproven")]
    return report


class AcceptTests(unittest.TestCase):
    def test_decided_overlay_shape_passes(self):
        rc, out = run_oracle(decided_report(), modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("inventory cgroup: inside=100 child=101 "
                      "outside=102 excluded module=m0 admission=admitted "
                      "unproven=2 gaps=5", out)

    def test_decided_shape_passes_with_another_binder_cause(self):
        # The unbound reason frames a diagnosed binder first-cause;
        # any diagnosed cause keeps the gap named (same precedent as
        # the unproven prefix).
        report = decided_report()
        report["gaps"][3]["reason"] = unbound_reason(UNBOUND_FIRST_EXITED)
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=5", out)

    def test_decided_no_witness_shape_passes_off_overlay(self):
        # No kernel witness on a non-overlay filesystem degrades the
        # same way: the named shape qualifies, the module stays admitted.
        rc, out = run_oracle(decided_report(), modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=5", out)

    def test_deadline_straddle_with_retained_refresh_passes(self):
        # CI run 43309778622, v6.6.157 leg: twelve passes, two of
        # them deadline-cancelled; one cancelled pass had staged a
        # refresh of the already-active c0 owner, so the producer
        # refused it by name and retained the owner's facts (c0
        # kept native_exact with its 1507 counted entries). The
        # deadline is the designed run bound and the facts-retained
        # refusal its designed disclosure, so the shape qualifies.
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": "cgroup scope transaction incomplete",
             "repeats": 2})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=7", out)

    def test_deadline_straddle_with_retained_refresh_passes_witness_available(self):
        # F1 control: the N3 retained-refresh invariant applies
        # irrespective of substrate — a witness-available report with
        # the deadline gap and one retained row per caller qualifies.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": "cgroup scope transaction incomplete",
             "repeats": 2})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=5", out)

    def test_witness_available_unbound_positive_passes_off_overlay(self):
        # Host leg (7.0.0-azure): the witness ran, so no unproven gaps
        # exist; the named counted positive on the owned module is
        # PARTIAL coverage, not a failure. Gap order mirrors the CI
        # row exactly (per-caller fallback, owned positive, fallback).
        report = witness_available_report()
        self.assertEqual(
            [(g.get("caller"), g.get("module")) for g in report["gaps"]],
            [("c0", None), (None, "m0"), ("c1", None)])
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=3", out)

    def test_deadline_straddle_with_preparation_interrupted_passes(self):
        # CI run 44960926490, v7.3.1 leg: twelve passes, two of them
        # deadline-cancelled; one cancelled pass was interrupted
        # mid-preparation (input comparison), so the producer refused
        # it by name alongside the deadline and the retained refresh.
        # The deadline is the designed run bound and the interrupted
        # preparation its designed disclosure, so the shape qualifies.
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=8", out)

    def test_deadline_straddle_with_preparation_interrupted_passes_witness_available(self):
        # The preparation-interrupted guard is substrate-independent
        # like the retained-refresh guard: a witness-available report
        # with the deadline gap and the interrupted preparation
        # qualifies.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=5", out)


def healthy_report_with_unbound():
    """The healthy-leg shape (host ext4/btrfs evidence, local pids).

    The kernel witness is available (no per-caller unproven gaps, no
    scan-pinned fallback), the owned module is admitted with inside
    edges from both callers, and the fork-after-attach child's first
    witness row arrived before any member scan admitted it — so the
    report carries exactly the named module-level unidentified-caller
    positive (fail-safe R-C51-1: the late edge reads
    use_before_admission). The race is independent of the witness
    substrate, so the healthy leg accepts the same named shape the
    degraded leg does.
    """
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "cgroup",
        "modules": [{"id": "m0",
                     "identity": {"device": {"major": 0, "minor": 46},
                                  "inode": 153887, "sha256": PIN["sha256"]},
                     "admission": {"state": "admitted", "endpoints": 68},
                     "lifecycle": "mapped",
                     "paths": [MODPATH]}],
        "callers": [{"id": "c0", "pid": 100}, {"id": "c1", "pid": 101}],
        "edges": [{"caller": "c0", "module": "m0"},
                  {"caller": "c1", "module": "m0"}],
        "gaps": [
            {"caller": None, "module": "m0", "pid": None,
             "reason": unbound_reason(), "subject": UNBOUND_SUBJECT,
             "repeats": 1},
        ],
    }


class HealthyLegTests(unittest.TestCase):
    def test_healthy_leg_accepts_named_unbound_gap(self):
        rc, out = run_oracle(healthy_report_with_unbound(), modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("inside=100 child=101 "
                      "outside=102 excluded module=m0 admission=admitted "
                      "unproven=0 gaps=1", out)

    def test_healthy_leg_refuses_unnamed_owned_gap(self):
        report = healthy_report_with_unbound()
        report["gaps"].append(
            {"caller": None, "module": "m0", "pid": None,
             "reason": "something new about the owned module",
             "subject": "novel owned trouble", "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)

    def test_healthy_leg_refuses_misframed_unbound_gap(self):
        # The subject alone does not name the gap on the healthy leg
        # either: the reason must carry the producer framing.
        report = healthy_report_with_unbound()
        report["gaps"][0]["reason"] = "native witness rows, truncated"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)


class RefuseTests(unittest.TestCase):
    def test_missing_module_still_fails(self):
        report = decided_report()
        report["modules"] = []
        report["edges"] = []
        report["gaps"] = [g for g in report["gaps"]
                          if g.get("module") != "m0"]
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("empty view never qualifies", out)

    def test_unnamed_owned_gap_still_fails(self):
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": "m0", "pid": None,
             "reason": "something new about the owned module",
             "subject": "novel owned trouble", "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)

    def test_unnamed_owned_gap_still_fails_off_overlay(self):
        # The witness-available branch accepts only named owned-module
        # gaps; an unnamed one still fails loudly.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": "m0", "pid": None,
             "reason": "something new about the owned module",
             "subject": "novel owned trouble", "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)

    def test_misframed_unbound_gap_still_fails(self):
        # The subject alone does not name the gap: the reason must
        # carry the producer framing, or the owned-module check fails.
        report = decided_report()
        report["gaps"][3]["reason"] = "native witness rows, truncated"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)

    def test_unbound_shaped_gap_without_owned_module_still_fails(self):
        # The named positive belongs to the owned module; the same
        # shape detached from it is an unexpected extra gap.
        report = decided_report()
        report["gaps"][3]["module"] = None
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay published extra gap", out)

    def test_unnamed_extra_gap_still_fails(self):
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None,
             "reason": "something new", "subject": "novel gap",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay published extra gap", out)

    def test_member_lost_refresh_refusal_still_fails(self):
        # Only the facts-retained variant is a known deadline
        # consequence. The bare variant means the member was lost
        # after the final sample of a still-complete transaction
        # (its admission standing was withdrawn, its owner
        # suspended): a different, stronger disclosure that must
        # keep failing loudly here.
        report = decided_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_MEMBER_LOST,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay published extra gap", out)

    def test_retained_refresh_without_deadline_still_fails(self):
        # N3: the facts-retained refresh refusal only comes with a
        # run-deadline straddle, so the deadline gap must be present
        # in the same run; the retained row alone stays loud.
        report = decided_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("retained refresh without a run deadline", out)

    def test_duplicate_retained_refresh_per_caller_still_fails(self):
        # N3: one row per owning caller — a second retained row for
        # the same caller stays loud even with the deadline present.
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": "cgroup scope transaction incomplete",
             "repeats": 2})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("duplicate retained refresh for one caller", out)

    def test_retained_refresh_without_deadline_fails_witness_available(self):
        # F1: the N3 deadline rule is not degraded-only — a lone
        # facts-retained row stays loud on a witness-available report.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("retained refresh without a run deadline", out)

    def test_duplicate_retained_refresh_per_caller_fails_witness_available(self):
        # F1: one row per owning caller on every substrate — a second
        # retained row for the same caller stays loud even with the
        # deadline present on a witness-available report.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": "cgroup scope transaction incomplete",
             "repeats": 2})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("duplicate retained refresh for one caller", out)

    def test_preparation_interrupted_without_deadline_still_fails(self):
        # The interrupted preparation only comes with a run-deadline
        # straddle, so the deadline gap must be present in the same
        # run; the interrupted row alone stays loud (a budget or fence
        # interruption without a deadline is a different phenomenon).
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("interrupted preparation without a run deadline", out)

    def test_preparation_interrupted_without_deadline_fails_witness_available(self):
        # The deadline rule is not degraded-only — a lone interrupted
        # preparation stays loud on a witness-available report.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("interrupted preparation without a run deadline", out)

    def test_preparation_interrupted_with_missing_count_fails(self):
        # The producer counts every recording (repeats>=1): a prep row
        # without its count is malformed and stays loud even with the
        # deadline present.
        report = decided_report()
        prep = {"caller": None, "module": None, "pid": None, "budget": None,
                "reason": PREP_INPUT_INTERRUPTED,
                "subject": PREP_SUBJECT}
        report["gaps"].append(prep)
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed interrupted preparation count", out)

    def test_preparation_interrupted_with_missing_count_fails_witness_available(self):
        report = witness_available_report()
        prep = {"caller": None, "module": None, "pid": None, "budget": None,
                "reason": PREP_INPUT_INTERRUPTED,
                "subject": PREP_SUBJECT}
        report["gaps"].append(prep)
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed interrupted preparation count", out)

    def test_preparation_interrupted_with_zero_deadline_count_fails(self):
        # A deadline row with zero recordings is malformed: repeats
        # counts recordings, so zero authorizes nothing.
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 0})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed run deadline count", out)

    def test_preparation_interrupted_with_zero_deadline_count_fails_witness_available(self):
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 0})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed run deadline count", out)

    def test_preparation_interrupted_with_wrong_subject_and_caller_fails(self):
        # A caller-bound row with the wrong producer subject is not the
        # unscoped preparation disclosure the exception names.
        report = decided_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": "wrong subject",
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed interrupted preparation", out)

    def test_preparation_interrupted_with_wrong_subject_and_caller_fails_witness_available(self):
        report = witness_available_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": "wrong subject",
             "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed interrupted preparation", out)

    def test_preparation_interrupted_with_wrong_deadline_subject_and_caller_fails(self):
        # A caller-bound deadline row with the wrong subject does not
        # satisfy the straddle guard.
        report = decided_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": DEADLINE,
             "subject": "wrong subject",
             "repeats": 2})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed run deadline", out)

    def test_preparation_interrupted_with_wrong_deadline_subject_and_caller_fails_witness_available(self):
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": PREP_INPUT_INTERRUPTED,
             "subject": PREP_SUBJECT,
             "repeats": 1})
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": DEADLINE,
             "subject": "wrong subject",
             "repeats": 2})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("malformed run deadline", out)

    def test_duplicate_preparation_interrupted_rows_fail(self):
        # The producer publishes one row per distinct shape with repeats
        # counting recordings: duplicate identical prep rows are malformed.
        report = decided_report()
        for _ in range(2):
            report["gaps"].append(
                {"caller": None, "module": None, "pid": None, "budget": None,
                 "reason": PREP_INPUT_INTERRUPTED,
                 "subject": PREP_SUBJECT,
                 "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("duplicate interrupted preparation rows", out)

    def test_duplicate_preparation_interrupted_rows_fail_witness_available(self):
        report = witness_available_report()
        for _ in range(2):
            report["gaps"].append(
                {"caller": None, "module": None, "pid": None, "budget": None,
                 "reason": PREP_INPUT_INTERRUPTED,
                 "subject": PREP_SUBJECT,
                 "repeats": 1})
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None, "budget": None,
             "reason": DEADLINE,
             "subject": DEADLINE_SUBJECT,
             "repeats": 2})
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("duplicate interrupted preparation rows", out)


def straddle_prep_row(*, drop=(), over=None):
    """One producer-exact interrupted-preparation row.

    The JSON renderer always emits `caller`, `module`, `pid` and
    `budget` (`src/inventory/mod.rs`); both producer sites file null
    scope with no budget (`src/discovery/inventory_coordinator.rs`).
    `drop` removes keys (absent is not null), `over` overrides values.
    """
    row = {"caller": None, "module": None, "pid": None, "budget": None,
           "reason": PREP_INPUT_INTERRUPTED,
           "subject": PREP_SUBJECT,
           "repeats": 1}
    for key in drop:
        del row[key]
    row.update(over or {})
    return row


def straddle_deadline_row(*, drop=(), over=None):
    """One producer-exact run-deadline row (same shape, its subject)."""
    row = {"caller": None, "module": None, "pid": None, "budget": None,
           "reason": DEADLINE,
           "subject": DEADLINE_SUBJECT,
           "repeats": 2}
    for key in drop:
        del row[key]
    row.update(over or {})
    return row


# A real producer refusal under the same transaction subject: the
# member scan did not complete, so the transaction publishes this
# row instead of the deadline row. The qualifier must refuse it.
SCAN_INCOMPLETE = "cgroup member scan was incomplete"


# A producer-shaped budget refusal: neither straddle row may carry one.
SPURIOUS_BUDGET = {"resource": "inventory_endpoints", "limit": 1,
                   "requested": 2}


class StraddleShapeTests(unittest.TestCase):
    # Fix2 (Codex B1 + NB3): each straddle row carries its null-valued
    # keys explicitly, and every guard assert owns an independent
    # single-field twin with its targeted message — removing any one
    # assert (subject, scope, budget, duplicate) must fail its twins on
    # both substrates. (name, prep_drop, prep_over, deadline_drop,
    # deadline_over, extra_deadline, message).
    CASES = [
        ("prep drops caller", ("caller",), {}, (), {}, False,
         "malformed interrupted preparation scope"),
        ("prep drops module", ("module",), {}, (), {}, False,
         "malformed interrupted preparation scope"),
        ("prep drops pid", ("pid",), {}, (), {}, False,
         "malformed interrupted preparation scope"),
        ("prep drops budget", ("budget",), {}, (), {}, False,
         "malformed interrupted preparation budget"),
        ("prep carries a budget refusal", (), {"budget": SPURIOUS_BUDGET},
         (), {}, False, "malformed interrupted preparation budget"),
        ("prep wrong subject only", (), {"subject": "wrong subject"},
         (), {}, False, "malformed interrupted preparation row"),
        ("prep caller value only", (), {"caller": "c0"},
         (), {}, False, "malformed interrupted preparation scope"),
        # No module-value twin: a module-bound straddle row is refused
        # earlier by the owned-module check (fail-closed), so it can
        # never reach the scope assert; the drop-module twin above pins
        # the scope assert's module clause instead.
        ("deadline drops caller", (), {}, ("caller",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops module", (), {}, ("module",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops pid", (), {}, ("pid",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops budget", (), {}, ("budget",), {}, False,
         "malformed run deadline budget"),
        ("deadline carries a budget refusal", (), {},
         (), {"budget": SPURIOUS_BUDGET}, False,
         "malformed run deadline budget"),
        ("deadline wrong subject only", (), {},
         (), {"subject": "wrong subject"}, False,
         "malformed run deadline row"),
        ("deadline caller value only", (), {},
         (), {"caller": "c0"}, False, "malformed run deadline scope"),
        ("duplicate deadline rows", (), {}, (), {}, True,
         "duplicate run deadline rows"),
    ]

    def test_preparation_rejects_boolean_count_on_both_substrates(self):
        # Fix5 (sweep M-P8): the prep count floor is exactly
        # repeats>=1 over real integers — a boolean count stays
        # malformed on both substrates.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_prep_row(over={"repeats": True}))
                report["gaps"].append(straddle_deadline_row())
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("malformed interrupted preparation count",
                              out)

    def test_single_field_mutations_fail_on_both_substrates(self):
        self.assertEqual(len(self.CASES), 15)
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for (name, prep_drop, prep_over, deadline_drop,
                    deadline_over, extra_deadline, message) in self.CASES:
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_prep_row(drop=prep_drop, over=prep_over))
                    report["gaps"].append(
                        straddle_deadline_row(drop=deadline_drop,
                                             over=deadline_over))
                    if extra_deadline:
                        report["gaps"].append(straddle_deadline_row())
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(message, out)


class DeadlineOnlyShapeTests(unittest.TestCase):
    # Fix3 (Codex B1): the deadline row carries the same producer
    # shape with or without a preparation-interruption row — a clean
    # preparation pass can still hit the run deadline (the retained
    # refresh shape proves it). Every deadline assert owns an
    # independent deadline-only twin (no prep row) with its targeted
    # message on both substrates. (name, drop, over,
    # extra_deadline, message).
    CASES = [
        ("deadline drops caller", ("caller",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops module", ("module",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops pid", ("pid",), {}, False,
         "malformed run deadline scope"),
        ("deadline drops budget", ("budget",), {}, False,
         "malformed run deadline budget"),
        ("deadline carries a budget refusal", (),
         {"budget": SPURIOUS_BUDGET}, False,
         "malformed run deadline budget"),
        ("deadline wrong subject only", (),
         {"subject": "wrong subject"}, False,
         "malformed run deadline row"),
        ("deadline caller value only", (), {"caller": "c0"}, False,
         "malformed run deadline scope"),
        ("deadline zero count", (), {"repeats": 0}, False,
         "malformed run deadline count"),
        ("duplicate deadline rows", (), {}, True,
         "duplicate run deadline rows"),
    ]

    def test_deadline_only_valid_shape_passes_on_both_substrates(self):
        # Control: one producer-exact deadline row with no prep and
        # no retained row qualifies on both substrates (open-ended
        # positive; the retained-refresh positives cover the paired
        # shape).
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(straddle_deadline_row())
                rc, out = run_oracle(report, modfs=modfs)
                self.assertEqual(rc, 0, out)

    def test_single_field_mutations_fail_without_prep_row(self):
        self.assertEqual(len(self.CASES), 9)
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for name, drop, over, extra_deadline, message in self.CASES:
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_deadline_row(drop=drop, over=over))
                    if extra_deadline:
                        report["gaps"].append(straddle_deadline_row())
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(message, out)

    def test_deadline_count_boundaries_on_both_substrates(self):
        # Fix5 (sweep M-D7/M-D8): the count floor is exactly
        # repeats>=1 over real integers — a single recording
        # qualifies, a boolean count stays malformed.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs, case="single recording"):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(over={"repeats": 1}))
                rc, out = run_oracle(report, modfs=modfs)
                self.assertEqual(rc, 0, out)
            with self.subTest(substrate=modfs, case="boolean count"):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(over={"repeats": True}))
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("malformed run deadline count", out)

    def test_near_deadline_reason_is_not_deadline_validated(self):
        # Fix5 (sweep M-D6): the deadline selector matches the exact
        # reason only — a near-miss reason skips deadline shape
        # validation and falls through to the transaction gate on
        # both substrates, with the branch-appropriate message.
        for modfs, base, message in (
                ("overlayfs", decided_report,
                 "overlay published extra gap"),
                ("ext4", witness_available_report,
                 "unrecognized cgroup transaction row")):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(
                        drop=("caller",),
                        over={"reason":
                              "cgroup collection frobnicate exploded"}))
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(message, out)

    def test_retained_refresh_with_malformed_deadline_fails_without_prep(self):
        # The retained-refresh presence check reuses the validated
        # deadline collection: a retained row plus a malformed
        # deadline (no prep) stays loud with the deadline message,
        # not the retained message.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(drop=("caller",)))
                report["gaps"].append(
                    {"caller": "c0", "module": None, "pid": 100,
                     "reason": REFRESH_RETAINED,
                     "subject": "native owner refresh refused",
                     "repeats": 1})
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("malformed run deadline scope", out)


class TransactionReasonTests(unittest.TestCase):
    # The producer files every incomplete cgroup transaction under
    # one fixed subject with many possible reasons
    # (src/inspect_system/inventory_cgroup.rs), and only the named
    # deadline disclosure qualifies (CI-GAP-2). A transaction row
    # counts as a deadline only after its exact reason and shape are
    # validated: a missing, unknown or scan-incomplete reason fails
    # on both substrates. The degraded branch already refuses these
    # rows through its reason list (pinned by the qualifier's
    # truncated-transaction twin); the transaction gate closes the
    # same hole on witness-available ext4, which has no degraded
    # reason gate of its own. (name, drop, over, overlayfs message,
    # witness-available message).
    CASES = [
        ("transaction drops reason", ("reason",), {},
         "overlay published extra gap",
         "unrecognized cgroup transaction row"),
        ("transaction unknown reason", (),
         {"reason": "cgroup collection frobnicate exploded"},
         "overlay published extra gap",
         "unrecognized cgroup transaction row"),
        ("transaction scan-incomplete reason", (),
         {"reason": SCAN_INCOMPLETE},
         "overlay published extra gap",
         "unrecognized cgroup transaction row"),
    ]

    def test_unrecognized_transaction_reasons_fail_on_both_substrates(self):
        self.assertEqual(len(self.CASES), 3)
        for modfs, base, pick in (("overlayfs", decided_report, 3),
                                 ("ext4", witness_available_report, 4)):
            for case in self.CASES:
                name, drop, over = case[0], case[1], case[2]
                message = case[pick]
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_deadline_row(drop=drop, over=over))
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(message, out)

    def test_transaction_with_fallback_reason_fails_on_both_substrates(self):
        # Fix5: the fallback reason is known on the degraded branch
        # for its own native-refusal subject only — a transaction
        # row carrying it is an impossible shape and must fail on
        # both substrates, with the branch-appropriate message.
        for modfs, base, message in (
                ("overlayfs", decided_report,
                 "overlay published extra gap"),
                ("ext4", witness_available_report,
                 "unrecognized cgroup transaction row")):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(over={"reason": NATIVE}))
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(message, out)


class ExplicitRefusalTests(unittest.TestCase):
    # Fix5 (no assert-based checks): every refusal in the extracted
    # inventory-cgroup block raises explicitly, so the verdicts are
    # identical under optimization (python3 -O strips bare asserts).
    # The AST test pins the property structurally; the behavioral
    # test pins it on the accepts plus one refusal per guard family
    # (transaction gate, validated deadline collection, retained
    # presence, prep shape, degraded reason list, empty view).
    def test_block_has_no_bare_asserts(self):
        tree = ast.parse(extract_inventory_oracle())
        found = sorted(node.lineno for node in ast.walk(tree)
                       if isinstance(node, ast.Assert))
        self.assertEqual(found, [])

    def test_verdicts_match_under_optimization(self):
        accepts = [
            ("decided overlay", decided_report(), "overlayfs"),
            ("witness available", witness_available_report(), "ext4"),
        ]
        for name, report, modfs in accepts:
            with self.subTest(case=name):
                rc, out = run_oracle_optimized(report, modfs=modfs)
                self.assertEqual(rc, 0, out)
        refusals = [
            ("transaction unknown reason",
             {"reason": "cgroup collection frobnicate exploded"},
             "overlayfs", "overlay published extra gap"),
            ("transaction unknown reason",
             {"reason": "cgroup collection frobnicate exploded"},
             "ext4", "unrecognized cgroup transaction row"),
            ("transaction fallback reason",
             {"reason": NATIVE},
             "overlayfs", "overlay published extra gap"),
            ("transaction fallback reason",
             {"reason": NATIVE},
             "ext4", "unrecognized cgroup transaction row"),
            ("malformed deadline scope",
             {"caller": "c0"},
             "overlayfs", "malformed run deadline scope"),
        ]
        for name, over, modfs, message in refusals:
            with self.subTest(case=name, substrate=modfs):
                base = (decided_report() if modfs == "overlayfs"
                        else witness_available_report())
                base["gaps"].append(straddle_deadline_row(over=over))
                rc, out = run_oracle_optimized(base, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(message, out)
        prep = decided_report()
        prep["gaps"].append(
            straddle_prep_row(over={"subject": "wrong subject"}))
        prep["gaps"].append(straddle_deadline_row())
        with self.subTest(case="malformed prep subject"):
            rc, out = run_oracle_optimized(prep, modfs="overlayfs")
            self.assertNotEqual(rc, 0, out)
            self.assertIn("malformed interrupted preparation row", out)
        retained = decided_report()
        retained["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        with self.subTest(case="retained without deadline"):
            rc, out = run_oracle_optimized(retained, modfs="overlayfs")
            self.assertNotEqual(rc, 0, out)
            self.assertIn("retained refresh without a run deadline", out)
        extra = decided_report()
        extra["gaps"].append(
            {"caller": None, "module": None, "pid": None,
             "reason": "something new", "subject": "novel gap",
             "repeats": 1})
        with self.subTest(case="unnamed extra gap"):
            rc, out = run_oracle_optimized(extra, modfs="overlayfs")
            self.assertNotEqual(rc, 0, out)
            self.assertIn("overlay published extra gap", out)
        empty = decided_report()
        empty["modules"] = []
        empty["edges"] = []
        empty["gaps"] = [g for g in empty["gaps"]
                         if g.get("module") != "m0"]
        with self.subTest(case="empty view"):
            rc, out = run_oracle_optimized(empty, modfs="overlayfs")
            self.assertNotEqual(rc, 0, out)
            self.assertIn("empty view never qualifies", out)


if __name__ == "__main__":
    unittest.main()
