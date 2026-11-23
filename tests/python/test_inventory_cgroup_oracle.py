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
DEFERRED = ("only one native owner activation per transaction; the staged "
            "owner is deferred to a later pass; scan-pinned fallback retained")
DEADLINE = "cgroup collection deadline reached"
UNBOUND_SUBJECT = "used by an unidentified caller image"
UNBOUND_FIRST = "no live caller incarnation held the tgid when the row was read"
UNBOUND_FIRST_EXITED = "the pinned caller exited before its cookie could be queried"
ACTIVATION = "native owner activation refused"
FUNCTIONS = ["C_GenerateRandom", "C_DigestInit", "C_Digest",
             "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]
ITERS = 250
# cgroup-fork: each member drives ITERS x six calls plus four setup and
# three teardown entries (1507 at the qualifier's 250 iterations).
DRIVEN = 6 * ITERS + 7


def inside_ledger(*, iters=ITERS, complete=True):
    """The cgroup-fork LEDGER line: parent plus child totals per function."""
    return "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": 100,
        "complete": complete,
        "functions": [{"name": name, "attempts": 2 * iters,
                       "successful": 2 * iters} for name in FUNCTIONS]})


def counted(count=DRIVEN):
    """An edge's entries as published for an exactly counted caller."""
    return {"cap": 18446744073709551615, "count": count,
            "coverage": {"detail": None, "first_ns": None, "lossy": False,
                         "reason": None, "since_ns": 1000, "state": "counted",
                         "until_ns": None},
            "first_seen_ns": 1000, "in_flight": False, "last_seen_ns": 2000,
            "observation": "observed", "saturated": False}


def witnessed_zero():
    """The regressed child shape: the witness saw it, the count is gone."""
    return {"cap": 18446744073709551615, "count": 0,
            "coverage": {"detail": None, "first_ns": 1000, "lossy": None,
                         "reason": None, "since_ns": None,
                         "state": "witnessed", "until_ns": None},
            "first_seen_ns": None, "in_flight": False, "last_seen_ns": None,
            "observation": "unknown (count unavailable; use witnessed)",
            "saturated": False}


def owned_edges():
    return [{"caller": "c0", "module": "m0", "entries": counted()},
            {"caller": "c1", "module": "m0", "entries": counted()}]


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


def run_oracle(report, *, modfs, pin=None, modpath=MODPATH, ledger=None):
    """Run the extracted oracle against a fixture report."""
    block = extract_inventory_oracle()
    if pin is None:
        pin = PIN
    if ledger is None:
        ledger = inside_ledger()
    inside_wl = "READY pid=100\nCHILD pid=101\n%s\n" % ledger
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
        # Recover and continue: each refused caller activates from
        # fresh proof on a later pass and ends native_exact.
        "callers": [
            {"id": "c0", "pid": 100, "image": {"authority": "native_exact"}},
            {"id": "c1", "pid": 101, "image": {"authority": "native_exact"}}],
        "edges": owned_edges(),
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
            {"caller": None, "module": None, "pid": None,
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
            {"caller": None, "module": None, "pid": None,
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
        "edges": owned_edges(),
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
            {"caller": None, "module": None, "pid": None,
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
            {"caller": None, "module": None, "pid": None,
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


def deferred_recovered_report(*, modfs_witness=False):
    """Both members settle in one pass (CI run 45046518330, v6.12.111).

    Late binding settles the fork child's expected image in the same
    pass as the parent's, so both stage; the one-commit-per-transaction
    gate activates c0 and defers c1 by name; the next pass activates
    c1 from fresh proof. Both callers end native_exact, and the child's
    witness row binds to c1, so no module-level unbound positive exists.
    """
    report = witness_available_report() if modfs_witness else decided_report()
    report["callers"] = [
        {"id": "c0", "pid": 100, "image": {"authority": "native_exact"}},
        {"id": "c1", "pid": 101, "image": {"authority": "native_exact"}}]
    report["gaps"] = [
        g for g in report["gaps"]
        if g.get("subject") != UNBOUND_SUBJECT
        and not (g.get("caller") == "c1" and g.get("reason") == NATIVE)]
    report["gaps"].append(
        {"caller": "c1", "module": None, "pid": 101,
         "reason": DEFERRED, "subject": "native owner activation refused",
         "repeats": 1})
    return report


class DeferredActivationTests(unittest.TestCase):
    def test_deferred_then_activated_member_passes_degraded(self):
        rc, out = run_oracle(deferred_recovered_report(), modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=4", out)

    def test_deferred_then_activated_member_passes_witness_available(self):
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=2", out)

    def test_deferred_member_that_stays_scan_pinned_fails(self):
        # Recover and continue: a deferral is a disclosure of one
        # delayed activation, never a resting state.
        report = deferred_recovered_report()
        report["callers"][1]["image"]["authority"] = "scan_pinned"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation never recovered", out)

    def test_deferred_member_that_stays_scan_pinned_fails_witness_available(self):
        report = deferred_recovered_report(modfs_witness=True)
        report["callers"][1]["image"]["authority"] = "scan_pinned"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation never recovered", out)

    def test_deferred_member_without_image_fails(self):
        report = deferred_recovered_report()
        del report["callers"][1]["image"]
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation never recovered", out)

    def test_callerless_deferral_fails(self):
        report = deferred_recovered_report()
        report["gaps"][-1]["caller"] = None
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation never recovered", out)

    def test_deferral_under_another_subject_fails(self):
        report = deferred_recovered_report()
        report["gaps"][-1]["subject"] = "native owner refresh refused"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("activation refusal under another subject", out)


class CountReconciliationTests(unittest.TestCase):
    """Driven equals counted, per caller, on its own owned-module edge."""

    SHAPES = (("overlayfs", False), ("ext4", True))

    def report(self, witness):
        return deferred_recovered_report(modfs_witness=witness)

    def test_exactly_counted_callers_pass(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                rc, out = run_oracle(self.report(witness), modfs=modfs)
                self.assertEqual(rc, 0, out)

    def test_child_count_dropped_to_witnessed_zero_fails(self):
        # The regression this lane fixed: the fork child's 1507 calls
        # bound to c1 as "witnessed, count unavailable".
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = self.report(witness)
                report["edges"][1]["entries"] = witnessed_zero()
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("fork child calls not counted", out)

    def test_missing_child_edge_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = self.report(witness)
                del report["edges"][1]
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("fork child has no edge to the owned module", out)

    def test_missing_parent_edge_fails(self):
        report = self.report(True)
        del report["edges"][0]
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside parent has no edge to the owned module", out)

    def test_child_edge_to_another_module_fails(self):
        report = self.report(True)
        report["edges"][1]["module"] = "m9"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("fork child has no edge to the owned module", out)

    def test_short_child_count_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = self.report(witness)
                report["edges"][1]["entries"] = counted(DRIVEN - 1)
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("fork child counted 1506 entries, drove 1507", out)

    def test_excess_parent_count_fails(self):
        report = self.report(True)
        report["edges"][0]["entries"] = counted(DRIVEN + 1)
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside parent counted 1508 entries, drove 1507", out)

    def test_count_follows_the_ledger(self):
        # The driven amount comes from the ledger, not a constant.
        report = self.report(True)
        report["edges"][0]["entries"] = counted(6 * 100 + 7)
        report["edges"][1]["entries"] = counted(6 * 100 + 7)
        rc, out = run_oracle(report, modfs="ext4",
                             ledger=inside_ledger(iters=100))
        self.assertEqual(rc, 0, out)
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside parent counted 607 entries, drove 1507", out)

    def test_incomplete_ledger_fails(self):
        rc, out = run_oracle(self.report(True), modfs="ext4",
                             ledger=inside_ledger(complete=False))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside ledger incomplete", out)

    def test_unparsable_ledger_fails(self):
        rc, out = run_oracle(self.report(True), modfs="ext4",
                             ledger="LEDGER x")
        self.assertNotEqual(rc, 0, out)


class RefusalIdentityTests(unittest.TestCase):
    """An activation refusal is recognized by its reason on every
    substrate, and binds to the refused caller incarnation."""

    SHAPES = (("overlayfs", False), ("ext4", True))

    def test_settle_refusal_under_another_subject_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = (witness_available_report() if witness
                          else decided_report())
                report["callers"][1]["image"]["authority"] = "scan_pinned"
                for g in report["gaps"]:
                    if g.get("caller") == "c1" and g.get("reason") == NATIVE:
                        g["subject"] = "native owner refresh refused"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("activation refusal under another subject", out)

    def test_recovered_settle_refusal_under_another_subject_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = (witness_available_report() if witness
                          else decided_report())
                for g in report["gaps"]:
                    if g.get("caller") == "c1" and g.get("reason") == NATIVE:
                        g["subject"] = "native owner refresh refused"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("activation refusal under another subject", out)

    def test_deferral_under_another_subject_fails_on_every_substrate(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                report["callers"][1]["image"]["authority"] = "scan_pinned"
                report["gaps"][-1]["subject"] = "native owner refresh refused"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("activation refusal under another subject", out)

    def test_refusal_of_another_incarnation_at_the_same_pid_fails(self):
        # The child pid's activated incarnation does not recover a
        # refusal of a different incarnation (new start time) there.
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                report["callers"][1]["start_time"] = 500
                report["callers"].append(
                    {"id": "c2", "pid": 101, "start_time": 900,
                     "image": {"authority": "scan_pinned"}})
                report["gaps"][-1]["caller"] = "c2"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("deferred activation never recovered", out)

    def test_refusal_of_an_unknown_caller_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                report["gaps"][-1]["caller"] = "c7"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("deferred activation never recovered", out)


class NeverSettledTests(unittest.TestCase):
    """A per-caller settle refusal is a delay, never a resting state."""

    def test_settle_refusal_that_never_recovers_fails_degraded(self):
        # The pre-late-binding shape (main, CI run 44046420097): the
        # fork child is refused on every pass and stays scan_pinned.
        report = decided_report()
        report["callers"][1]["image"]["authority"] = "scan_pinned"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("native activation never recovered", out)

    def test_settle_refusal_that_never_recovers_fails_witness_available(self):
        report = witness_available_report()
        report["callers"][1]["image"]["authority"] = "scan_pinned"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("native activation never recovered", out)

    def test_settle_refusal_on_a_caller_without_image_fails(self):
        report = decided_report()
        del report["callers"][0]["image"]
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("native activation never recovered", out)

    def test_settle_refusal_at_another_pid_fails(self):
        report = decided_report()
        report["gaps"][1]["pid"] = 999
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("native activation never recovered", out)

    def test_both_callers_never_recovering_fails(self):
        # The loaded-host shape: no witness row was ever read, so
        # neither caller settles; that is lost data, never a pass.
        report = decided_report()
        for caller in report["callers"]:
            caller["image"]["authority"] = "scan_pinned"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("native activation never recovered", out)


if __name__ == "__main__":
    unittest.main()
