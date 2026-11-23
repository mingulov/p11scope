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


# Process generations the harness registered for the workload (field 22
# of /proc/PID/stat, clock ticks since boot); the report's start_time of
# the one incarnation per workload process must match.
GENERATIONS = {100: 5000, 101: 5001}


def workload_caller(cid, pid, authority="native_exact"):
    return {"id": cid, "pid": pid, "start_time": GENERATIONS[pid],
            "start_time_unit": "clock_ticks_since_boot", "retired": False,
            "image": {"authority": authority}}


def workload_callers():
    return [workload_caller("c0", 100), workload_caller("c1", 101)]


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


def run_oracle(report, *, modfs, pin=None, modpath=MODPATH, ledger=None,
               generations=None):
    """Run the extracted oracle against a fixture report."""
    if generations is None:
        generations = (GENERATIONS[100], GENERATIONS[101])
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
             json.dumps(pin), modpath, modfs,
             str(generations[0]), str(generations[1])],
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
        "callers": workload_callers(),
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
    scan-pinned fallback), the owned module is admitted, and both
    workload callers end native_exact with exactly counted edges. Beside
    them the report carries one named module-level unidentified-caller
    positive: a witness row the binder could not attribute to any
    caller incarnation. That positive is an extra disclosure; it never
    stands in for a workload caller's own count. The healthy leg accepts
    it as a named gap, as the degraded leg does.
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
        "callers": workload_callers(),
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
    report["callers"] = workload_callers()
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
        self.assertIn("caller image has type NoneType", out)

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
        # The fork child never execs, so its pid holds exactly one
        # caller incarnation. A second one there fails the expected
        # table before any refusal could be recovered through it.
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                second = workload_caller("c2", 101, authority="scan_pinned")
                second["start_time"] = 9000
                report["callers"].append(second)
                report["gaps"][-1]["caller"] = "c2"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("fork child has 2 caller incarnations", out)

    def test_refusal_of_an_unknown_caller_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                report["gaps"][-1]["caller"] = "c7"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("deferred activation never recovered", out)


def _split_child_count(report):
    # Codex r3 F1: 1507 conserved across two incarnations at one pid.
    second = workload_caller("c2", 101)
    second["start_time"] = 9000
    report["callers"].append(second)
    report["edges"][1]["entries"] = counted(1007)
    report["edges"].append({"caller": "c2", "module": "m0",
                            "entries": counted(500)})
    if any((g.get("reason") or "").startswith("original_file_unproven")
           for g in report["gaps"]):
        report["gaps"].append({"caller": "c2", "module": None, "pid": 101,
                               "reason": UNPROVEN, "subject": MODPATH,
                               "repeats": 1})


def _provision_failed_child(report):
    # Codex r3 F2: another activation reason under the canonical
    # subject, the child still scan-pinned, both edges exactly counted.
    report["callers"][1]["image"]["authority"] = "scan_pinned"
    report["gaps"] = [g for g in report["gaps"]
                      if g.get("reason") != DEFERRED]
    report["gaps"].append({"caller": "c1", "module": None, "pid": 101,
                           "reason": "staged owner provision failed: scripted error",
                           "subject": ACTIVATION, "repeats": 1})


def _scan_pinned_child_without_gap(report):
    report["callers"][1]["image"]["authority"] = "scan_pinned"
    report["gaps"] = [g for g in report["gaps"]
                      if g.get("reason") != DEFERRED]


def _retired_child(report):
    report["callers"][1]["retired"] = True


def _wrong_generation(report):
    report["callers"][1]["start_time"] = 7777


def _other_unit(report):
    report["callers"][1]["start_time_unit"] = "jiffies"


def _child_flag(key, value):
    def mutate(report):
        report["edges"][1]["entries"][key] = value
    return mutate


def _child_lossy(report):
    # Codex r3 F3: a lossy lower bound at the exact total.
    report["edges"][1]["entries"]["coverage"]["lossy"] = True


def _child_second_edge(report):
    report["edges"].append({"caller": "c1", "module": "m9",
                            "entries": counted(1)})


def _edge_from_unknown_caller(report):
    report["edges"].append({"caller": "c9", "module": "m0",
                            "entries": counted(1)})


def _third_pid_caller(report):
    # Hy4 N2: a refusal naming a known caller outside the workload.
    third = workload_caller("c3", 100)
    third["pid"] = 103
    report["callers"].append(third)
    report["gaps"].append({"caller": "c3", "module": None, "pid": 103,
                           "reason": NATIVE, "subject": ACTIVATION,
                           "repeats": 1})


def _unknown_gap(report):
    # Hy4 N4: every substrate sweeps unclassified gaps.
    report["gaps"].append({"caller": None, "module": None, "pid": None,
                           "reason": "something new", "subject": "novel gap",
                           "repeats": 1})


def _deadline():
    return {"caller": None, "module": None, "pid": None, "reason": DEADLINE,
            "subject": "cgroup scope transaction incomplete", "repeats": 1}


def _retained(**override):
    gap = {"caller": "c1", "module": None, "pid": 101,
           "reason": REFRESH_RETAINED,
           "subject": "native owner refresh refused", "repeats": 1}
    gap.update(override)
    return gap


def _admission_note(**override):
    gap = {"caller": "c1", "module": "m0", "pid": 101,
           "reason": MODPATH + ": admission changed from unresolved to admitted",
           "subject": "module admission changed", "repeats": 1}
    gap.update(override)
    return gap


def _add_gaps(*gaps):
    def mutate(report):
        report["gaps"].extend(gaps)
    return mutate


def _deferral_on(**override):
    def mutate(report):
        report["gaps"][-1].update(override)
    return mutate


def _duplicate_caller_id(report):
    # Codex r4 F2: a copy of c1 at the outside pid, ahead of the real row.
    hidden = workload_caller("c1", 101)
    hidden["pid"] = 102
    hidden["start_time"] = 5002
    report["callers"].insert(0, hidden)


def _null_child_identity(report):
    # Codex r5 F1: a null id with matching null references.
    report["callers"][1]["id"] = None
    report["edges"][1]["caller"] = None
    report["gaps"][-1]["caller"] = None


def _set(path, value):
    """Mutation setting report[path...] = value (missing keys deleted)."""
    def mutate(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        if value is _DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return mutate


_DELETE = object()


def _duplicate_module_id(report):
    # Codex r5 N3: a module row with the owned id but another identity,
    # ahead of the real row.
    shadow = json.loads(json.dumps(report["modules"][0]))
    shadow["identity"]["inode"] = 1
    report["modules"].insert(0, shadow)


class ExpectedTableTests(unittest.TestCase):
    """One typed record per workload caller against the ledger table.

    Each row is one refused class: (name, mutation, failure marker).
    Every row runs on the degraded (overlayfs) and witness-available
    (ext4) shapes of the recovered report; the unmutated report passes.
    """

    ROWS = [
        ("split-incarnations", _split_child_count,
         "fork child has 2 caller incarnations"),
        ("provision-failure", _provision_failed_child,
         "unexpected activation refusal"),
        ("scan-pinned-without-gap", _scan_pinned_child_without_gap,
         "fork child never activated a native owner"),
        ("retired-at-report", _retired_child,
         "fork child caller retired at report time"),
        ("wrong-generation", _wrong_generation,
         "fork child start time 7777 is not the workload generation 5001"),
        ("other-start-unit", _other_unit,
         "fork child start time unit 'jiffies'"),
        ("lossy-lower-bound", _child_lossy,
         "fork child calls not counted exactly"),
        ("lossy-unknown", lambda r: r["edges"][1]["entries"]["coverage"].update(lossy=None),
         "fork child calls not counted exactly"),
        ("saturated", _child_flag("saturated", True),
         "fork child calls not counted exactly"),
        ("in-flight", _child_flag("in_flight", True),
         "fork child calls not counted exactly"),
        ("not-observed", _child_flag("observation", "lower bound"),
         "fork child calls not counted exactly"),
        ("second-edge", _child_second_edge,
         "fork child has 2 edges, expected its one owned edge"),
        ("edge-from-unknown-caller", _edge_from_unknown_caller,
         "edge from a caller outside the workload"),
        ("third-pid-caller", _third_pid_caller,
         "unexpected caller outside the workload"),
        ("unknown-gap", _unknown_gap, "published extra gap"),
        # Codex r4 F1: each named allowance carries exactly the
        # producer's attribution (caller, pid, module).
        ("retained-at-excluded-pid", _add_gaps(_deadline(), _retained(pid=102)),
         "retained refresh attribution"),
        ("retained-on-owned-module", _add_gaps(_deadline(), _retained(module="m0")),
         "retained refresh attribution"),
        ("retained-unknown-caller", _add_gaps(_deadline(), _retained(caller="c9")),
         "retained refresh attribution"),
        ("deadline-with-caller", _add_gaps(dict(_deadline(), caller="c0", pid=100)),
         "collection deadline attribution"),
        ("deadline-on-owned-module", _add_gaps(dict(_deadline(), module="m0")),
         "collection deadline attribution"),
        ("activation-on-owned-module", _deferral_on(module="m0"),
         "deferred activation never recovered"),
        ("activation-at-excluded-pid", _deferral_on(pid=102),
         "deferred activation never recovered"),
        ("admission-note-at-excluded-pid", _add_gaps(_admission_note(pid=102)),
         "admission note attribution"),
        ("admission-note-unknown-caller", _add_gaps(_admission_note(caller="c9")),
         "admission note attribution"),
        ("admission-note-misframed", _add_gaps(_admission_note(reason="admission changed")),
         "admission note attribution"),
        ("duplicate-caller-id", _duplicate_caller_id, "duplicate caller id"),
        ("duplicate-module-id", _duplicate_module_id, "duplicate module id"),
        ("deadline-with-pid", _add_gaps(dict(_deadline(), pid=100)),
         "collection deadline attribution"),
        # Codex r5 F1: strict types while parsing.
        ("null-id-and-references", _null_child_identity,
         "caller id has type NoneType"),
        ("caller-pid-string", _set(["callers", 1, "pid"], "101"),
         "caller pid has type str"),
        ("caller-pid-bool", _set(["callers", 1, "pid"], True),
         "caller pid has type bool"),
        ("caller-start-missing", _set(["callers", 1, "start_time"], _DELETE),
         "caller start_time has type NoneType"),
        ("caller-retired-int", _set(["callers", 1, "retired"], 0),
         "caller retired has type int"),
        ("caller-authority-missing", _set(["callers", 1, "image", "authority"], _DELETE),
         "caller authority has type NoneType"),
        ("module-id-null", _set(["modules", 0, "id"], None),
         "module id has type NoneType"),
        ("edge-caller-null", _set(["edges", 1, "caller"], None),
         "edge caller has type NoneType"),
        ("edge-module-int", _set(["edges", 1, "module"], 0),
         "edge module has type int"),
        ("edge-count-string", _set(["edges", 1, "entries", "count"], "1507"),
         "edge count has type str"),
        ("edge-coverage-missing", _set(["edges", 1, "entries", "coverage"], _DELETE),
         "edge coverage has type NoneType"),
        ("gap-pid-string", _set(["gaps", -1, "pid"], "101"),
         "gap pid has type str"),
        ("gap-caller-int", _set(["gaps", -1, "caller"], 1),
         "gap caller has type int"),
        ("gap-subject-null", _set(["gaps", -1, "subject"], None),
         "gap subject has type NoneType"),
        # Codex r5 N2: only the producer's upward transitions.
        ("admission-note-empty-transition",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from ")),
         "admission note attribution"),
        ("admission-note-unknown-state",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from candidate to admitted")),
         "admission note attribution"),
        ("admission-note-downward",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from admitted to refused")),
         "admission note attribution"),
        ("admission-note-other-path",
         _add_gaps(_admission_note(reason="/other.so: admission changed from refused to admitted")),
         "admission note attribution"),
    ]

    ACCEPTED = [
        ("retained-with-deadline", _add_gaps(_deadline(), _retained())),
        ("admission-note", _add_gaps(_admission_note())),
        ("admission-note-refused-up",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from refused to admitted (export agreement; 68 endpoints)"))),
        ("admission-note-unresolved-to-refused",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from unresolved to refused"))),
    ]

    def test_each_named_allowance_passes_with_its_attribution(self):
        for name, mutate in self.ACCEPTED:
            for modfs, witness in (("overlayfs", False), ("ext4", True)):
                with self.subTest(row=name, modfs=modfs):
                    report = deferred_recovered_report(modfs_witness=witness)
                    mutate(report)
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertEqual(rc, 0, out)

    def test_swapped_generations_fail(self):
        # Codex r4 N3: parent and child generations are not interchangeable.
        for modfs, witness in (("overlayfs", False), ("ext4", True)):
            with self.subTest(modfs=modfs):
                rc, out = run_oracle(
                    deferred_recovered_report(modfs_witness=witness),
                    modfs=modfs,
                    generations=(GENERATIONS[101], GENERATIONS[100]))
                self.assertNotEqual(rc, 0, out)
                self.assertIn("inside parent start time 5000 is not the "
                              "workload generation 5001", out)

    def test_unproven_row_on_the_owned_module_fails(self):
        report = deferred_recovered_report()
        for g in report["gaps"]:
            if (g.get("reason") or "").startswith("original_file_unproven"):
                g["module"] = "m0"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay unproven module", out)

    def test_recovered_report_passes(self):
        for modfs, witness in (("overlayfs", False), ("ext4", True)):
            with self.subTest(modfs=modfs):
                rc, out = run_oracle(
                    deferred_recovered_report(modfs_witness=witness),
                    modfs=modfs)
                self.assertEqual(rc, 0, out)

    def test_each_refused_class_fails_on_every_substrate(self):
        for name, mutate, marker in self.ROWS:
            for modfs, witness in (("overlayfs", False), ("ext4", True)):
                with self.subTest(row=name, modfs=modfs):
                    report = deferred_recovered_report(modfs_witness=witness)
                    mutate(report)
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(marker, out)

    def test_missing_generation_fails(self):
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4", generations=(5000, ""))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("fork child generation not recorded", out)


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
        self.assertIn("caller image has type NoneType", out)

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
