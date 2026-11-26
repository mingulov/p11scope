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


def verdict(text):
    """Keep only the lines a check emits: a failure is matched on its
    final exception line, never on traceback frames (a frame's source
    line would show a check's message text even when another error
    raised there)."""
    return "\n".join(line for line in text.splitlines()
                     if line and not line[0].isspace()
                     and not line.startswith("Traceback (most recent call last)"))


def assert_refusal_rule(case, verdict_out, rule, out):
    """Assert the typed verdict for one refused oracle input."""
    case.assertEqual("fail", verdict_out.get("verdict"), out)
    case.assertEqual(rule, verdict_out.get("rule"), out)


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
PREP_INPUT_INTERRUPTED = "cgroup provider input comparison interrupted"
# The other seven preparation reasons the producer files under the
# same subject and shape (src/discovery/inventory_attach_set.rs
# prepare_absorption): the qualifier refuses all seven until one is
# observed with evidence. Only PREP_INPUT_INTERRUPTED qualifies, with
# a run-deadline straddle.
PREP_INPUT_CEILING = "cgroup provider preparation input ceiling reached"
PREP_INTERRUPTED_OR_ALLOWANCE = (
    "cgroup provider preparation interrupted or allowance exhausted")
PREP_INTERRUPTED_AFTER_RETENTION = (
    "cgroup provider preparation interrupted after retention")
PREP_RESOLUTION_INTERRUPTED = "cgroup provider resolution interrupted"
PREP_COMPARISON_CEILING = (
    "cgroup provider preparation comparison ceiling reached")
PREP_IDENTITY_INTERRUPTED = (
    "cgroup provider identity comparison interrupted")
PREP_INTERRUPTED_BEFORE_COMPLETION = (
    "cgroup provider preparation interrupted before completion")
OTHER_PREP_REASONS = (
    PREP_INPUT_CEILING,
    PREP_INTERRUPTED_OR_ALLOWANCE,
    PREP_INTERRUPTED_AFTER_RETENTION,
    PREP_RESOLUTION_INTERRUPTED,
    PREP_COMPARISON_CEILING,
    PREP_IDENTITY_INTERRUPTED,
    PREP_INTERRUPTED_BEFORE_COMPLETION,
)
PREP_SUBJECT = "cgroup provider preparation incomplete"
DEADLINE_SUBJECT = "cgroup scope transaction incomplete"
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


OUTSIDE_ITERS = 500


def outside_ledger(*, pid=102, iters=OUTSIDE_ITERS, complete=True,
                   functions=None):
    """The gated workload's LEDGER line (the exclusion control)."""
    if functions is None:
        functions = [{"name": name, "attempts": iters, "successful": iters}
                     for name in FUNCTIONS]
    return "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": pid,
        "complete": complete, "functions": functions})


def outside_wl(ledger=None):
    return "READY pid=102\n%s\n" % (outside_ledger() if ledger is None else ledger)


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


def activation_note(caller, pid, *, kind="activation_unsettled", reason=None,
                    repeats=1):
    """A recovered activation delay as the producer publishes it: a
    typed note (`notes[]`), never a loss gap (v0.7.2 I1)."""
    if reason is None:
        reason = NATIVE if kind == "activation_unsettled" else DEFERRED
    return {"kind": kind, "caller": caller, "module": None, "pid": pid,
            "reason": reason, "subject": "native owner activation refused",
            "repeats": repeats}


# The producer's coverage inputs (src/inventory/mod.rs budgets_json
# and the report document): every report carries the four refusing
# resources' `refused` counters and `gaps_suppressed`; these are their
# healthy zero values in the producer's shape.
COVERAGE_RESOURCES = ("callers", "modules", "edges", "endpoints")


def producer_counters():
    return {"budgets": {resource: {"limit": 4096, "occupied": 0, "refused": 0}
                        for resource in COVERAGE_RESOURCES},
            "gaps_suppressed": 0}


RECORDS = ROOT / "scripts/qualify_records.py"
RUN_ID = "test-run"


def stamp(tmp, cell):
    """The shell's run stamp for one leg (written before its inputs)."""
    subprocess.run(["python3", "-I", str(RECORDS), "stamp", str(tmp / (cell + ".stamp")), RUN_ID, cell],
                   check=True)


# Interpreters the loader must hold under: the plain test interpreter,
# an optimized one (-O strips assert statements), and PYTHONOPTIMIZE
# inherited from the environment.
PLAIN = (["python3", "-I"], None)
OPTIMIZED = (["python3", "-O", "-I"], None)
INHERITED = (["python3"], {"PYTHONOPTIMIZE": "1"})


def run_oracle(report, *, modfs, pin=None, modpath=MODPATH, ledger=None,
               generations=None, inside_wl=None, outside_wl=None,
               interpreter=PLAIN, report_text=None, pin_text=None, inside_iters=ITERS,
               outside_iters=OUTSIDE_ITERS, pids=(100, 101, 102), verdict_out=None):
    """Run the cgroup-inventory judge of the typed loader on a fixture.

    `pids` are the launched inside parent, the registered owned child
    and the launched outside workload, as the shell passes them."""
    if generations is None:
        generations = (GENERATIONS[100], GENERATIONS[101])
    if pin is None:
        pin = PIN
    if ledger is None:
        ledger = inside_ledger()
    if inside_wl is None:
        inside_wl = "READY pid=100\nCHILD pid=101\n%s\n" % ledger
    if outside_wl is None:
        outside_wl = globals()["outside_wl"]()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        stamp(tmp, "inventory-cgroup")
        # The product report: only from the run's private output directory.
        (tmp / ("run-" + RUN_ID)).mkdir()
        (tmp / ("run-" + RUN_ID) / "r.json").write_text(
            json.dumps(report) if report_text is None else report_text)
        (tmp / "in.wl").write_text(inside_wl)
        (tmp / "out.wl").write_text(outside_wl)
        argv, extra_env = interpreter
        env = None
        if extra_env is not None:
            import os
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith("PYTHON")}
            env.update(extra_env)
        proc = subprocess.run(
            argv + [str(RECORDS), "cgroup-inventory", "--stamp", "inventory-cgroup.stamp",
                    "--run-id", RUN_ID, "--verdict", "verdict.json", "--cell", "inventory-cgroup",
                    "--report", "run-%s/r.json" % RUN_ID, "--inside-wl", "in.wl", "--outside-wl", "out.wl",
                    "--pin", json.dumps(pin) if pin_text is None else pin_text,
                    "--inside-iters", str(inside_iters), "--outside-iters", str(outside_iters),
                    "--module", modpath, "--module-fs", modfs,
                    "--inside-pid", str(pids[0]), "--inside-gen", str(generations[0]),
                    "--child-pid", str(pids[1]), "--child-gen", str(generations[1]),
                    "--outside-pid", str(pids[2])],
            capture_output=True, text=True, timeout=30, cwd=str(tmp), env=env)
        if verdict_out is not None:
            verdict_out.update(json.loads((tmp / "verdict.json").read_text()))
    return proc.returncode, verdict(proc.stdout + proc.stderr)


def run_oracle_optimized(report, *, modfs, pin=None, modpath=MODPATH,
                         verdict_out=None):
    """Run the module judge with assertions stripped (python3 -O)."""
    return run_oracle(report, modfs=modfs, pin=pin, modpath=modpath,
                      interpreter=OPTIMIZED, verdict_out=verdict_out)


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
            {"caller": "c1", "module": None, "pid": 101,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 9},
            {"caller": None, "module": "m0", "pid": None,
             "reason": unbound_reason(), "subject": UNBOUND_SUBJECT,
             "repeats": 1},
        ],
        # Each recovered settle refusal is a typed note, not a gap.
        "notes": [activation_note("c0", 100),
                  activation_note("c1", 101, repeats=8)],
        "notes_suppressed": 0,
        **producer_counters(),
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
                      "unproven=2 gaps=3 notes=2", out)

    def test_decided_shape_passes_with_another_binder_cause(self):
        # The unbound reason frames a diagnosed binder first-cause;
        # any diagnosed cause keeps the gap named (same precedent as
        # the unproven prefix).
        report = decided_report()
        report["gaps"][2]["reason"] = unbound_reason(UNBOUND_FIRST_EXITED)
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=3 notes=2", out)

    def test_decided_no_witness_shape_passes_off_overlay(self):
        # No kernel witness on a non-overlay filesystem degrades the
        # same way: the named shape qualifies, the module stays admitted.
        rc, out = run_oracle(decided_report(), modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=3 notes=2", out)

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
        self.assertIn("unproven=2 gaps=5 notes=2", out)

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
        self.assertIn("unproven=0 gaps=3 notes=2", out)

    def test_witness_available_unbound_positive_passes_off_overlay(self):
        # Host leg (7.0.0-azure): the witness ran, so no unproven gaps
        # exist; the named counted positive on the owned module is
        # PARTIAL coverage, not a failure. The recovered per-caller
        # fallbacks are typed notes beside the one owned positive.
        report = witness_available_report()
        self.assertEqual(
            [(g.get("caller"), g.get("module")) for g in report["gaps"]],
            [(None, "m0")])
        self.assertEqual([n.get("caller") for n in report["notes"]], ["c0", "c1"])
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=1 notes=2", out)

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
        self.assertIn("unproven=2 gaps=6 notes=2", out)

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
        self.assertIn("unproven=0 gaps=3 notes=2", out)


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
        **producer_counters(),
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
        report["gaps"][2]["reason"] = "native witness rows, truncated"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory gaps about owned module", out)

    def test_unbound_shaped_gap_without_owned_module_still_fails(self):
        # The named positive belongs to the owned module; the same
        # shape detached from it is an unexpected extra gap.
        report = decided_report()
        report["gaps"][2]["module"] = None
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
        verdict_out = {}
        rc, out = run_oracle(report, modfs="overlayfs",
                             verdict_out=verdict_out)
        self.assertNotEqual(rc, 0, out)
        assert_refusal_rule(self, verdict_out, "gap.unclassified", out)

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
        verdict_out = {}
        rc, out = run_oracle(report, modfs="ext4", verdict_out=verdict_out)
        self.assertNotEqual(rc, 0, out)
        assert_refusal_rule(self, verdict_out, "gap.unclassified", out)

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
        verdict_out = {}
        rc, out = run_oracle(report, modfs="overlayfs",
                             verdict_out=verdict_out)
        self.assertNotEqual(rc, 0, out)
        assert_refusal_rule(self, verdict_out, "gap.deadline", out)

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
        verdict_out = {}
        rc, out = run_oracle(report, modfs="ext4", verdict_out=verdict_out)
        self.assertNotEqual(rc, 0, out)
        assert_refusal_rule(self, verdict_out, "gap.deadline", out)

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
    # keys explicitly, and every guard owns an independent single-field
    # twin with its typed verdict rule — removing any one assert
    # (subject, scope, budget, duplicate) must fail its twins on both
    # substrates. Missing producer keys are type-stage `record.gap`
    # refusals before relation validation. (name, prep_drop, prep_over,
    # deadline_drop, deadline_over, extra_deadline, rule).
    CASES = [
        ("prep drops caller", ("caller",), {}, (), {}, False,
         "record.gap"),
        ("prep drops module", ("module",), {}, (), {}, False,
         "record.gap"),
        ("prep drops pid", ("pid",), {}, (), {}, False,
         "record.gap"),
        ("prep drops budget", ("budget",), {}, (), {}, False,
         "gap.prep"),
        ("prep carries a budget refusal", (), {"budget": SPURIOUS_BUDGET},
         (), {}, False, "gap.prep"),
        ("prep wrong subject only", (), {"subject": "wrong subject"},
         (), {}, False, "gap.unclassified"),
        ("prep caller value only", (), {"caller": "c0"},
         (), {}, False, "gap.prep"),
        # No module-value twin: a module-bound straddle row is refused
        # earlier by the owned-module check (fail-closed), so it can
        # never reach the scope assert; the drop-module twin above pins
        # the scope assert's module clause instead.
        ("deadline drops caller", (), {}, ("caller",), {}, False,
         "record.gap"),
        ("deadline drops module", (), {}, ("module",), {}, False,
         "record.gap"),
        ("deadline drops pid", (), {}, ("pid",), {}, False,
         "record.gap"),
        ("deadline drops budget", (), {}, ("budget",), {}, False,
         "gap.deadline"),
        ("deadline carries a budget refusal", (), {},
         (), {"budget": SPURIOUS_BUDGET}, False,
         "gap.deadline"),
        ("deadline wrong subject only", (), {},
         (), {"subject": "wrong subject"}, False,
         "gap.deadline"),
        ("deadline caller value only", (), {},
         (), {"caller": "c0"}, False, "gap.deadline"),
        ("duplicate deadline rows", (), {}, (), {}, True,
         "gap.deadline"),
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
                    deadline_over, extra_deadline, rule) in self.CASES:
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_prep_row(drop=prep_drop, over=prep_over))
                    report["gaps"].append(
                        straddle_deadline_row(drop=deadline_drop,
                                             over=deadline_over))
                    if extra_deadline:
                        report["gaps"].append(straddle_deadline_row())
                    verdict_out = {}
                    rc, out = run_oracle(report, modfs=modfs,
                                         verdict_out=verdict_out)
                    self.assertNotEqual(rc, 0, out)
                    assert_refusal_rule(self, verdict_out, rule, out)


class DeadlineOnlyShapeTests(unittest.TestCase):
    # Fix3 (Codex B1): the deadline row carries the same producer
    # shape with or without a preparation-interruption row — a clean
    # preparation pass can still hit the run deadline (the retained
    # refresh shape proves it). Every deadline guard owns an
    # independent deadline-only twin (no prep row) with its typed
    # verdict rule on both substrates. Missing producer keys are
    # type-stage `record.gap` refusals before relation validation.
    # (name, drop, over, extra_deadline, rule).
    CASES = [
        ("deadline drops caller", ("caller",), {}, False,
         "record.gap"),
        ("deadline drops module", ("module",), {}, False,
         "record.gap"),
        ("deadline drops pid", ("pid",), {}, False,
         "record.gap"),
        ("deadline drops budget", ("budget",), {}, False,
         "gap.deadline"),
        ("deadline carries a budget refusal", (),
         {"budget": SPURIOUS_BUDGET}, False,
         "gap.deadline"),
        ("deadline wrong subject only", (),
         {"subject": "wrong subject"}, False,
         "gap.deadline"),
        ("deadline caller value only", (), {"caller": "c0"}, False,
         "gap.deadline"),
        ("deadline zero count", (), {"repeats": 0}, False,
         "gap.deadline"),
        ("duplicate deadline rows", (), {}, True,
         "gap.deadline"),
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
            for name, drop, over, extra_deadline, rule in self.CASES:
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_deadline_row(drop=drop, over=over))
                    if extra_deadline:
                        report["gaps"].append(straddle_deadline_row())
                    verdict_out = {}
                    rc, out = run_oracle(report, modfs=modfs,
                                         verdict_out=verdict_out)
                    self.assertNotEqual(rc, 0, out)
                    assert_refusal_rule(self, verdict_out, rule, out)

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
        # reason only — a producer-shaped near-miss reason skips
        # deadline shape validation and stays unclassified on both
        # substrates.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(
                        over={"reason":
                              "cgroup collection frobnicate exploded"}))
                verdict_out = {}
                rc, out = run_oracle(report, modfs=modfs,
                                     verdict_out=verdict_out)
                self.assertNotEqual(rc, 0, out)
                assert_refusal_rule(self, verdict_out,
                                    "gap.unclassified", out)

    def test_retained_refresh_with_malformed_deadline_fails_without_prep(self):
        # The retained-refresh presence check reuses the validated
        # deadline collection: a retained row plus a deadline row
        # missing a producer key is a type-stage gap-record refusal,
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
                verdict_out = {}
                rc, out = run_oracle(report, modfs=modfs,
                                     verdict_out=verdict_out)
                self.assertNotEqual(rc, 0, out)
                assert_refusal_rule(self, verdict_out, "record.gap", out)


class TransactionReasonTests(unittest.TestCase):
    # The producer files every incomplete cgroup transaction under
    # one fixed subject with many possible reasons
    # (src/inspect_system/inventory_cgroup.rs), and only the named
    # deadline disclosure qualifies (CI-GAP-2). A transaction row
    # counts as a deadline only after its exact reason and shape are
    # validated: a missing, unknown or scan-incomplete reason fails
    # on both substrates. A missing reason is a type-stage record
    # refusal; an unknown or scan-incomplete reason reaches the
    # unclassified-gap relation rule. (name, drop, over, rule).
    CASES = [
        ("transaction drops reason", ("reason",), {}, "record.gap"),
        ("transaction unknown reason", (),
         {"reason": "cgroup collection frobnicate exploded"},
         "gap.unclassified"),
        ("transaction scan-incomplete reason", (),
         {"reason": SCAN_INCOMPLETE}, "gap.unclassified"),
    ]

    def test_unrecognized_transaction_reasons_fail_on_both_substrates(self):
        self.assertEqual(len(self.CASES), 3)
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for name, drop, over, rule in self.CASES:
                with self.subTest(substrate=modfs, case=name):
                    report = base()
                    report["gaps"].append(
                        straddle_deadline_row(drop=drop, over=over))
                    verdict_out = {}
                    rc, out = run_oracle(report, modfs=modfs,
                                         verdict_out=verdict_out)
                    self.assertNotEqual(rc, 0, out)
                    assert_refusal_rule(self, verdict_out, rule, out)

    def test_transaction_with_fallback_reason_fails_on_both_substrates(self):
        # Fix5: the fallback reason is known for its own native-refusal
        # subject only — a transaction row carrying it is an activation
        # refusal under another subject on both substrates.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            with self.subTest(substrate=modfs):
                report = base()
                report["gaps"].append(
                    straddle_deadline_row(over={"reason": NATIVE}))
                verdict_out = {}
                rc, out = run_oracle(report, modfs=modfs,
                                     verdict_out=verdict_out)
                self.assertNotEqual(rc, 0, out)
                assert_refusal_rule(self, verdict_out,
                                    "gap.activation", out)


class CrossPairTests(unittest.TestCase):
    # Fix6: the qualifier enforces a typed (subject, reason)
    # allowlist on both branches and refuses every other pair. The
    # degraded branch used to check reasons only (X1/X2), and the
    # witness-available branch had no gate at all (X3). Each
    # impossible pair below fails identically under optimization, at
    # its typed verdict rule.

    def assert_cross_pair_refusal(self, report, modfs, optimized, rule):
        verdict_out = {}
        run = run_oracle_optimized if optimized else run_oracle
        rc, out = run(report, modfs=modfs, verdict_out=verdict_out)
        self.assertNotEqual(rc, 0, out)
        assert_refusal_rule(self, verdict_out, rule, out)

    def test_prep_subject_with_fallback_reason_fails(self):
        # X1: the fallback reason is filed only under the native
        # activation-refused subject — a preparation row carrying
        # it is an activation refusal under another subject.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for optimized in (False, True):
                with self.subTest(substrate=modfs,
                                  optimized=optimized):
                    report = base()
                    report["gaps"].append(
                        straddle_prep_row(over={"reason": NATIVE}))
                    report["gaps"].append(straddle_deadline_row())
                    self.assert_cross_pair_refusal(
                        report, modfs, optimized, "gap.activation")

    def test_novel_subject_with_retained_reason_fails(self):
        # X2: the retained reason is filed only under the native
        # refresh-refused subject — a novel subject carrying it fails
        # the retained-row attribution rule, even with a deadline.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for optimized in (False, True):
                with self.subTest(substrate=modfs,
                                  optimized=optimized):
                    report = base()
                    report["gaps"].append(
                        {"caller": "c0", "module": None, "pid": 100,
                         "reason": REFRESH_RETAINED,
                         "subject": "novel gap", "repeats": 1})
                    report["gaps"].append(straddle_deadline_row())
                    self.assert_cross_pair_refusal(
                        report, modfs, optimized, "gap.retained")

    def test_novel_prep_reason_with_valid_shape_fails(self):
        # X3: a preparation-subject row with a ninth reason (here a
        # near-miss of the filed one) and otherwise valid shape is
        # unclassified on both substrates, even with a deadline.
        for modfs, base in (("overlayfs", decided_report),
                            ("ext4", witness_available_report)):
            for optimized in (False, True):
                with self.subTest(substrate=modfs,
                                  optimized=optimized):
                    report = base()
                    report["gaps"].append(
                        straddle_prep_row(over={"reason":
                            "cgroup provider input comparison "
                            "interruptedly"}))
                    report["gaps"].append(straddle_deadline_row())
                    self.assert_cross_pair_refusal(
                        report, modfs, optimized, "gap.unclassified")

    def test_other_prep_reasons_fail_without_evidence(self):
        # The seven other filed preparation reasons carry the same
        # producer shape and straddle the same run deadline, but none
        # was ever observed, so each fails loudly on both substrates,
        # identically under -O. The refusal is decided from the typed
        # verdict, never from log text. Re-allowing one needs evidence
        # plus an allowlist edit here and in the qualifier.
        self.assertEqual(len(OTHER_PREP_REASONS), 7)
        for reason in OTHER_PREP_REASONS:
            for modfs, base in (("overlayfs", decided_report),
                                ("ext4", witness_available_report)):
                for optimized in (False, True):
                    with self.subTest(reason=reason,
                                      substrate=modfs,
                                      optimized=optimized):
                        report = base()
                        report["gaps"].append(
                            straddle_prep_row(over={"reason": reason}))
                        report["gaps"].append(straddle_deadline_row())
                        run = (run_oracle_optimized if optimized
                               else run_oracle)
                        verdict = {}
                        rc, out = run(report, modfs=modfs,
                                        verdict_out=verdict)
                        # Rule id first: restoring a reason must fail
                        # here (rule None), not just on rc.
                        self.assertEqual(verdict.get("rule"),
                                         "gap.unclassified", out)
                        self.assertEqual(verdict.get("verdict"), "fail", out)
                        self.assertNotEqual(rc, 0, out)

    def test_unnamed_extra_gap_fails_witness_available(self):
        # The witness-available branch refuses unnamed gaps too: a
        # novel pair fails loudly instead of passing silently.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None,
             "reason": "something new", "subject": "novel gap",
             "repeats": 1})
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                self.assert_cross_pair_refusal(
                    report, "ext4", optimized, "gap.unclassified")

    def test_member_lost_refresh_refusal_fails_witness_available(self):
        # Only the facts-retained variant is a known deadline
        # consequence on the witness-available branch too: the bare
        # member-lost variant is unclassified there.
        report = witness_available_report()
        report["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_MEMBER_LOST,
             "subject": "native owner refresh refused",
             "repeats": 1})
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                self.assert_cross_pair_refusal(
                    report, "ext4", optimized, "gap.unclassified")

    def test_detached_unbound_gap_fails_witness_available(self):
        # The named positive belongs to the owned module on the
        # witness-available branch too; the same shape detached
        # from it is unclassified there.
        report = witness_available_report()
        report["gaps"][0]["module"] = None
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                self.assert_cross_pair_refusal(
                    report, "ext4", optimized, "gap.unclassified")


class ExplicitRefusalTests(unittest.TestCase):
    # Fix5 (no assert-based checks): every refusal in the extracted
    # inventory-cgroup block raises explicitly, so the verdicts are
    # identical under optimization (python3 -O strips bare asserts).
    # The AST test pins the property structurally; the behavioral
    # test pins it on the accepts plus one refusal per guard family
    # (transaction gate, validated deadline collection, retained
    # presence, prep shape, degraded reason list, empty view).
    def test_block_has_no_bare_asserts(self):
        tree = ast.parse(RECORDS.read_text())
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

        def refuse_optimized(report, modfs, rule):
            verdict_out = {}
            rc, out = run_oracle_optimized(report, modfs=modfs,
                                           verdict_out=verdict_out)
            self.assertNotEqual(rc, 0, out)
            assert_refusal_rule(self, verdict_out, rule, out)

        refusals = [
            ("transaction unknown reason",
             {"reason": "cgroup collection frobnicate exploded"},
             "overlayfs", "gap.unclassified"),
            ("transaction unknown reason",
             {"reason": "cgroup collection frobnicate exploded"},
             "ext4", "gap.unclassified"),
            ("transaction fallback reason",
             {"reason": NATIVE},
             "overlayfs", "gap.activation"),
            ("transaction fallback reason",
             {"reason": NATIVE},
             "ext4", "gap.activation"),
            ("malformed deadline scope",
             {"caller": "c0"},
             "overlayfs", "gap.deadline"),
        ]
        for name, over, modfs, rule in refusals:
            with self.subTest(case=name, substrate=modfs):
                base = (decided_report() if modfs == "overlayfs"
                        else witness_available_report())
                base["gaps"].append(straddle_deadline_row(over=over))
                refuse_optimized(base, modfs, rule)
        prep = decided_report()
        prep["gaps"].append(
            straddle_prep_row(over={"subject": "wrong subject"}))
        prep["gaps"].append(straddle_deadline_row())
        with self.subTest(case="malformed prep subject"):
            refuse_optimized(prep, "overlayfs", "gap.unclassified")
        retained = decided_report()
        retained["gaps"].append(
            {"caller": "c0", "module": None, "pid": 100,
             "reason": REFRESH_RETAINED,
             "subject": "native owner refresh refused",
             "repeats": 1})
        with self.subTest(case="retained without deadline"):
            refuse_optimized(retained, "overlayfs", "gap.retained")
        extra = decided_report()
        extra["gaps"].append(
            {"caller": None, "module": None, "pid": None,
             "reason": "something new", "subject": "novel gap",
             "repeats": 1})
        with self.subTest(case="unnamed extra gap"):
            refuse_optimized(extra, "overlayfs", "gap.unclassified")
        empty = decided_report()
        empty["modules"] = []
        empty["edges"] = []
        empty["gaps"] = [g for g in empty["gaps"]
                         if g.get("module") != "m0"]
        with self.subTest(case="empty view"):
            refuse_optimized(empty, "overlayfs", "cgroup.owned-module")


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
        if g.get("subject") != UNBOUND_SUBJECT]
    report["notes"] = [
        n for n in report["notes"]
        if not (n.get("caller") == "c1" and n.get("reason") == NATIVE)]
    # The recovered deferral: a typed note (v0.7.2 I1), never a gap.
    report["notes"].append(activation_note("c1", 101, kind="activation_deferred"))
    return report


class DeferredActivationTests(unittest.TestCase):
    def test_deferred_then_activated_member_passes_degraded(self):
        rc, out = run_oracle(deferred_recovered_report(), modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=2 notes=2", out)

    def test_deferred_then_activated_member_passes_witness_available(self):
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=0 notes=2", out)

    def test_healthy_fork_leg_pins_coverage_complete(self):
        # N5: the healthy fork leg (both members settle, the deferral
        # recovered as a note) is coverage complete: no loss gap, no
        # refusal, nothing suppressed. Notes never count.
        report = deferred_recovered_report(modfs_witness=True)
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=0 notes=2 coverage=complete", out)

    def test_degraded_fork_leg_pins_coverage_partial(self):
        # The same recovered shape on overlayfs keeps its named
        # unproven gaps: the cell passes, but coverage is partial.
        report = deferred_recovered_report()
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=2 notes=2 coverage=partial", out)

    def test_coverage_counts_refusals_and_suppressed_gaps(self):
        # Each coverage input beyond the gap list flips the pin on its
        # own: one refusal of any one refusing resource, or one
        # suppressed gap, reads partial with zero gaps shown (one
        # killing case per input).
        cases = [("refused", resource) for resource in COVERAGE_RESOURCES]
        cases.append(("suppressed", None))
        for kind, resource in cases:
            with self.subTest(kind=kind, resource=resource):
                report = deferred_recovered_report(modfs_witness=True)
                if resource is None:
                    report["gaps_suppressed"] = 1
                else:
                    report["budgets"][resource]["refused"] = 1
                verdict = {}
                rc, out = run_oracle(report, modfs="ext4", verdict_out=verdict)
                self.assertEqual(rc, 0, out)
                self.assertEqual(verdict["verdict"], "pass", verdict)
                self.assertTrue(verdict["detail"].endswith(" gaps=0 notes=2 coverage=partial"), verdict)

    def test_missing_coverage_inputs_fail_typing(self):
        # The producer always emits these keys: a report without one
        # (or with a mistyped one) is refused by the report record,
        # never read as a zero that pins complete.
        def drop(*path):
            def go(report):
                node = report
                for key in path[:-1]:
                    node = node[key]
                del node[path[-1]]
            return go

        def put(value, *path):
            def go(report):
                node = report
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return go

        rows = [("budgets", drop("budgets"), "record.cgroup-report"),
                ("gaps_suppressed", drop("gaps_suppressed"), "record.cgroup-report"),
                ("gaps_suppressed mistyped", put(0.0, "gaps_suppressed"), "record.cgroup-report"),
                ("notes_suppressed beside notes", drop("notes_suppressed"), "record.cgroup-report"),
                ("notes beside notes_suppressed", drop("notes"), "record.cgroup-report")]
        for resource in COVERAGE_RESOURCES:
            rows.append(("budgets." + resource, drop("budgets", resource), "record.cgroup-budgets"))
            rows.append(("budgets.%s.refused" % resource, drop("budgets", resource, "refused"),
                         "record.cgroup-budget"))
            rows.append(("budgets.%s.refused mistyped" % resource, put(True, "budgets", resource, "refused"),
                         "record.cgroup-budget"))
        for name, mutate, rule in rows:
            with self.subTest(case=name):
                report = deferred_recovered_report(modfs_witness=True)
                mutate(report)
                verdict = {}
                rc, out = run_oracle(report, modfs="ext4", verdict_out=verdict)
                self.assertNotEqual(rc, 0, out)
                self.assertEqual((verdict["verdict"], verdict["rule"], verdict["stage"]),
                                 ("fail", rule, "type"), verdict)

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

    def test_deferral_with_zero_observed_rows_fails(self):
        report = deferred_recovered_report()
        report["edges"][1]["entries"]["count"] = 0
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation recovered without observed witness rows", out)

    def test_callerless_deferral_fails(self):
        report = deferred_recovered_report()
        report["notes"][-1]["caller"] = None
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("deferred activation never recovered", out)

    def test_deferral_under_another_subject_fails(self):
        report = deferred_recovered_report()
        report["notes"][-1]["subject"] = "native owner refresh refused"
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("activation refusal under another subject", out)


class RestoredActivationArmTests(unittest.TestCase):
    """v0.7.2 I1: the relaxed arms of 6d6cdefc3/b126200cd/18d95edb7 are
    restored. The producer resolves a recovered activation delay to a
    typed note, so an activation delay in `gaps` is the producer's own
    verdict that it never recovered and fails the cell on every
    substrate, even when the caller ended native_exact. Notes are typed
    strictly: kind, reason and attribution must agree."""

    SHAPES = (("overlayfs", False), ("ext4", True))

    def test_recovered_deferral_published_as_a_gap_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                note = report["notes"].pop()
                del note["kind"]
                report["gaps"].append(note)
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("deferred activation never recovered", out)

    def test_recovered_settle_refusal_published_as_a_gap_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = (witness_available_report() if witness
                          else decided_report())
                note = report["notes"].pop(0)
                del note["kind"]
                report["gaps"].append(note)
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("native activation never recovered", out)

    def test_note_kind_must_match_its_reason(self):
        report = deferred_recovered_report(modfs_witness=True)
        report["notes"][-1]["kind"] = "activation_unsettled"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("activation note reason is not its kind's", out)

    def test_other_note_kinds_fail_the_cell(self):
        for kind in ("member_demoted", "fold_deferred_oversized"):
            with self.subTest(kind=kind):
                report = deferred_recovered_report(modfs_witness=True)
                report["notes"][-1]["kind"] = kind
                rc, out = run_oracle(report, modfs="ext4")
                self.assertNotEqual(rc, 0, out)
                self.assertIn("unrecognized cgroup note", out)

    def test_unknown_note_kind_fails_typing(self):
        report = deferred_recovered_report(modfs_witness=True)
        report["notes"][-1]["kind"] = "activation_maybe"
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("note kind 'activation_maybe' is not one of", out)

    def test_suppressed_notes_fail(self):
        report = deferred_recovered_report(modfs_witness=True)
        report["notes_suppressed"] = 1
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("notes suppressed", out)

    def test_note_records_are_strict(self):
        for key in ("kind", "caller", "pid", "module", "subject", "reason", "repeats"):
            with self.subTest(missing=key):
                report = deferred_recovered_report(modfs_witness=True)
                del report["notes"][-1][key]
                rc, out = run_oracle(report, modfs="ext4")
                self.assertNotEqual(rc, 0, out)
                self.assertIn("missing", out)
        report = deferred_recovered_report(modfs_witness=True)
        report["notes"][-1]["extra"] = 1
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("unknown keys ['extra']", out)
        report = deferred_recovered_report(modfs_witness=True)
        report["notes"][-1]["repeats"] = 0
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("note repeats out of range", out)

    def test_fork_shape_without_notes_passes_complete(self):
        # The healthy fork cell with no delay at all: no gap, no note.
        report = deferred_recovered_report(modfs_witness=True)
        report["notes"] = []
        rc, out = run_oracle(report, modfs="ext4")
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=0 gaps=0 notes=0", out)


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
                self.assertIn("deferred activation recovered without observed witness rows", out)

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
        # The driven amount comes from the ledger, and the ledger must
        # report exactly the launched iterations (ruled 2026-11-23: a
        # reconciling ledger with another total is refused).
        report = self.report(True)
        report["edges"][0]["entries"] = counted(6 * 100 + 7)
        report["edges"][1]["entries"] = counted(6 * 100 + 7)
        rc, out = run_oracle(report, modfs="ext4",
                             ledger=inside_ledger(iters=100), inside_iters=100)
        self.assertEqual(rc, 0, out)
        rc, out = run_oracle(report, modfs="ext4",
                             ledger=inside_ledger(iters=100))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside ledger attempts 200 are not two members of 250 "
                      "launched iterations", out)
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
                for g in report["notes"]:
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
                for g in report["notes"]:
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
                report["notes"][-1]["subject"] = "native owner refresh refused"
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
                report["notes"][-1]["caller"] = "c2"
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("fork child has 2 caller incarnations", out)

    def test_refusal_of_an_unknown_caller_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                report["notes"][-1]["caller"] = "c7"
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
    report["notes"] = [n for n in report["notes"]
                       if n.get("reason") != DEFERRED]
    report["gaps"].append({"caller": "c1", "module": None, "pid": 101,
                           "reason": "staged owner provision failed: scripted error",
                           "subject": ACTIVATION, "repeats": 1})


def _scan_pinned_child_without_gap(report):
    report["callers"][1]["image"]["authority"] = "scan_pinned"
    report["notes"] = [n for n in report["notes"]
                       if n.get("reason") != DEFERRED]


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
    report["notes"].append(activation_note("c3", 103))


def _unknown_gap(report):
    # Hy4 N4: every substrate sweeps unclassified gaps.
    report["gaps"].append({"caller": None, "module": None, "pid": None,
                           "reason": "something new", "subject": "novel gap",
                           "repeats": 1})


def _deadline():
    return {"caller": None, "module": None, "pid": None, "budget": None,
            "reason": DEADLINE,
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
        report["notes"][-1].update(override)
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
    report["notes"][-1]["caller"] = None


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


def _typed_gap(field, value):
    """Mutation adding one gap row with `field` mistyped. The recovered
    activation delays are notes now (v0.7.2 I1), so the witness-available
    fork report may publish no gap; the typing rows carry their own."""
    def mutate(report):
        gap = _deadline()
        gap[field] = value
        report["gaps"].append(gap)
    return mutate


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
        ("gap-pid-string", _typed_gap("pid", "101"),
         "gap pid has type str"),
        ("gap-caller-int", _typed_gap("caller", 1),
         "gap caller has type int"),
        ("gap-subject-null", _typed_gap("subject", None),
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


def _ledger_with(functions):
    return "LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": 100,
        "complete": True, "functions": functions})


def _functions(attempts):
    return [{"name": name, "attempts": attempt, "successful": attempt}
            for name, attempt in zip(FUNCTIONS, attempts)]


def _unbound_gap(**override):
    gap = {"caller": None, "module": "m0", "pid": None,
           "reason": unbound_reason(), "subject": UNBOUND_SUBJECT,
           "repeats": 1}
    gap.update(override)
    return gap


def _unproven_rows(report):
    return [g for g in report["gaps"]
            if (g.get("reason") or "").startswith("original_file_unproven")]


class CheckCoverageTests(unittest.TestCase):
    """Rows that each kill one oracle check (mutation sweep, round 6).

    Every check in the oracle block has at least one row here or in the
    expected table whose report fails only through that check."""

    SHAPES = (("overlayfs", False), ("ext4", True))

    REPORT_ROWS = [
        ("wrong-schema", _set(["schema"], "p11scope/inventory/v0"),
         "inventory schema"),
        ("wrong-scope", _set(["scope"], "system"), "inventory scope"),
        ("module-other-device", _set(["modules", 0, "identity", "device", "minor"], 47),
         "owned provider not inventoried"),
        ("module-other-inode", _set(["modules", 0, "identity", "inode"], 1),
         "owned provider not inventoried"),
        ("module-other-sha", _set(["modules", 0, "identity", "sha256"], "00" * 32),
         "owned provider not inventoried"),
        ("unbound-other-subject", _add_gaps(_unbound_gap(subject="used by someone")),
         "inventory gaps about owned module"),
        ("unbound-with-caller", _add_gaps(_unbound_gap(caller="c0")),
         "inventory gaps about owned module"),
        ("unbound-with-pid", _add_gaps(_unbound_gap(pid=100)),
         "inventory gaps about owned module"),
        ("unbound-other-prefix", _add_gaps(_unbound_gap(reason="X" + unbound_reason())),
         "inventory gaps about owned module"),
        ("unbound-other-suffix", _add_gaps(_unbound_gap(reason=unbound_reason() + "X")),
         "inventory gaps about owned module"),
        ("admission-note-same-length-path",
         _add_gaps(_admission_note(reason="X" + MODPATH[1:] + ": admission changed from refused to admitted")),
         "admission note attribution"),
        ("admission-note-empty-reasons",
         _add_gaps(_admission_note(reason=MODPATH + ": admission changed from refused to admitted ()")),
         "admission note attribution"),
        ("retained-other-subject",
         _add_gaps(_deadline(), _retained(subject="native owner activation retained")),
         "retained refresh attribution"),
        ("deadline-other-subject",
         _add_gaps(dict(_deadline(), subject="cgroup scope ended")),
         "collection deadline attribution"),
        ("deadline-caller-only", _add_gaps(dict(_deadline(), caller="c0")),
         "collection deadline attribution"),
        ("edge-witnessed-otherwise-exact",
         _set(["edges", 1, "entries", "coverage", "state"], "witnessed"),
         "fork child calls not counted exactly"),
        ("callers-not-a-list", _set(["callers"], {}), "callers has type dict"),
        ("caller-not-an-object", lambda r: r["callers"].append("c9"),
         "caller has type str"),
        ("caller-start-unit-int", _set(["callers", 1, "start_time_unit"], 1),
         "caller start_time_unit has type int"),
        ("modules-missing", _set(["modules"], _DELETE), "modules has type NoneType"),
        ("module-not-an-object", lambda r: r["modules"].append(["m9"]),
         "module has type list"),
        ("edges-not-a-list", _set(["edges"], "e"), "edges has type str"),
        ("edge-not-an-object", lambda r: r["edges"].append(None),
         "edge has type NoneType"),
        ("edge-entries-missing", _set(["edges", 1, "entries"], _DELETE),
         "edge entries has type NoneType"),
        ("edge-state-int", _set(["edges", 1, "entries", "coverage", "state"], 1),
         "edge coverage state has type int"),
        ("edge-lossy-string", _set(["edges", 1, "entries", "coverage", "lossy"], "false"),
         "edge coverage lossy has type str"),
        ("edge-observation-null", _set(["edges", 1, "entries", "observation"], None),
         "edge observation has type NoneType"),
        ("edge-saturated-null", _set(["edges", 1, "entries", "saturated"], None),
         "edge saturated has type NoneType"),
        ("edge-in-flight-missing", _set(["edges", 1, "entries", "in_flight"], _DELETE),
         "edge in_flight has type NoneType"),
        ("gaps-not-a-list", _set(["gaps"], None), "gaps has type NoneType"),
        ("gap-not-an-object", lambda r: r["gaps"].append("gap"),
         "gap has type str"),
        ("gap-module-int", _typed_gap("module", 0), "gap module has type int"),
        ("gap-reason-int", _typed_gap("reason", 7), "gap reason has type int"),
    ]

    LEDGER_ROWS = [
        ("five-functions", _ledger_with(_functions([500] * 5)),
         "inside ledger attempts differ per function"),
        ("mixed-attempts", _ledger_with(_functions([500] * 5 + [498])),
         "inside ledger attempts differ per function"),
        ("odd-attempts", _ledger_with(_functions([501] * 6)),
         "inside ledger attempts not split per member"),
        ("zero-attempts", _ledger_with(_functions([0] * 6)),
         "inside ledger attempts not split per member"),
        ("string-attempts", _ledger_with(_functions(["500"] * 6)),
         "inside ledger attempts not split per member"),
    ]

    def test_each_report_row_fails_on_every_substrate(self):
        for name, mutate, marker in self.REPORT_ROWS:
            for modfs, witness in self.SHAPES:
                with self.subTest(row=name, modfs=modfs):
                    report = deferred_recovered_report(modfs_witness=witness)
                    mutate(report)
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(marker, out)

    def test_each_ledger_row_fails(self):
        for name, ledger, marker in self.LEDGER_ROWS:
            with self.subTest(row=name):
                rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                                     modfs="ext4", ledger=ledger)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(marker, out)

    def test_one_character_admission_reason_passes(self):
        # The reasons suffix needs at least one character in its parens.
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                _add_gaps(_admission_note(
                    reason=MODPATH + ": admission changed from refused to admitted (x)"))(report)
                rc, out = run_oracle(report, modfs=modfs)
                self.assertEqual(rc, 0, out)

    def test_real_workload_line_order_passes(self):
        # cgroup-fork and the gated workload print their TARGET lines
        # before READY; the pids come from the READY line, not line one.
        target = ('TARGET {"name":"C_GenerateRandom","dev":[0,46],'
                  '"ino":153887,"file_offset":4096}')
        inside = "%s\nREADY pid=100\nCHILD pid=101\n%s\n" % (target, inside_ledger())
        outside = "%s\n%s" % (target, outside_wl())
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4", inside_wl=inside, outside_wl=outside)
        self.assertEqual(rc, 0, out)
        self.assertIn("inside=100 child=101 outside=102", out)

    def test_duplicate_inside_ledger_fails(self):
        wl = "READY pid=100\nCHILD pid=101\n%s\n%s\n" % (inside_ledger(), inside_ledger())
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4", inside_wl=wl)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inside ledger missing", out)

    def test_missing_outside_ledger_fails(self):
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                             modfs="ext4", outside_wl="READY pid=102\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("outside ledger missing", out)

    def test_overlay_without_unproven_rows_fails(self):
        # On overlayfs the witness never runs, so the unproven cover is
        # required even when no unproven row was published.
        report = deferred_recovered_report(modfs_witness=True)
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay unproven caller cover", out)

    def test_partial_unproven_cover_off_overlay_fails(self):
        # Any unproven row makes the report degraded on every
        # filesystem, so its cover must be complete there too.
        report = deferred_recovered_report()
        report["gaps"] = [g for g in report["gaps"]
                          if not (g in _unproven_rows(report) and g["caller"] == "c1")]
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay unproven caller cover", out)

    def test_unproven_row_at_another_pid_fails(self):
        report = deferred_recovered_report()
        _unproven_rows(report)[0]["pid"] = 102
        rc, out = run_oracle(report, modfs="overlayfs")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("overlay unproven pid", out)


def _identity_token(report, token):
    """Serialize the report with the owned inode replaced by a raw JSON
    token (floats and huge decimals do not survive a Python round trip)."""
    text = json.dumps(report)
    needle = '"inode": %d' % PIN["ino"]
    assert text.count(needle) == 1
    return text.replace(needle, '"inode": %s' % token)


class IdentityTypeTests(unittest.TestCase):
    """The provider pin matches by exact JSON integers and strings."""

    SHAPES = (("overlayfs", False), ("ext4", True))
    BIG = 9007199254740992

    def test_integer_identity_control_passes(self):
        pin = dict(PIN, ino=self.BIG)
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                rc, out = run_oracle(report, modfs=modfs, pin=pin,
                                     report_text=_identity_token(report, str(self.BIG)))
                self.assertEqual(rc, 0, out)

    def test_decimal_inode_token_fails(self):
        # Codex r6 F2: 9007199254740993.0 rounds to the pinned integer.
        pin = dict(PIN, ino=self.BIG)
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                rc, out = run_oracle(report, modfs=modfs, pin=pin,
                                     report_text=_identity_token(report, "9007199254740993.0"))
                self.assertNotEqual(rc, 0, out)
                self.assertIn("module inode has type float", out)

    def test_float_inode_fails(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                report = deferred_recovered_report(modfs_witness=witness)
                rc, out = run_oracle(report, modfs=modfs,
                                     report_text=_identity_token(report, "%d.0" % PIN["ino"]))
                self.assertNotEqual(rc, 0, out)
                self.assertIn("module inode has type float", out)

    ROWS = [
        ("major-bool", ["identity", "device", "major"], False,
         "module device major has type bool"),
        ("minor-string", ["identity", "device", "minor"], "46",
         "module device minor has type str"),
        ("device-missing", ["identity", "device"], _DELETE,
         "module device missing"),
        ("identity-missing", ["identity"], _DELETE,
         "module identity missing"),
        ("sha-int", ["identity", "sha256"], 7, "module sha256 has type int"),
        ("admission-state-int", ["admission", "state"], 1,
         "module admission state has type int"),
        ("admission-missing", ["admission"], _DELETE,
         "module admission missing"),
    ]

    def test_each_identity_type_row_fails(self):
        for name, path, value, marker in self.ROWS:
            for modfs, witness in self.SHAPES:
                with self.subTest(row=name, modfs=modfs):
                    report = deferred_recovered_report(modfs_witness=witness)
                    _set(["modules", 0] + path, value)(report)
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(marker, out)

    def test_pin_types_are_exact(self):
        report = deferred_recovered_report(modfs_witness=True)
        for name, pin, marker in (
                ("pin-ino-bool", dict(PIN, ino=True), "pin ino has type bool"),
                ("pin-dev-float", dict(PIN, dev=[0.0, 46]), "pin dev has type float"),
                ("pin-sha-null", dict(PIN, sha256=None), "pin sha256 has type NoneType"),
                ("pin-dev-missing", {k: v for k, v in PIN.items() if k != "dev"},
                 "pin dev missing"),
                ("pin-dev-triple", dict(PIN, dev=PIN["dev"] + [0]),
                 "pin dev is not [major, minor]"),
                ("pin-not-object", [PIN], "pin has type list")):
            with self.subTest(row=name):
                rc, out = run_oracle(report, modfs="ext4", pin=pin)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(marker, out)


class FieldPresenceTests(unittest.TestCase):
    """Nullable attribution fields must be present (codex r6 N3)."""

    def test_missing_gap_fields_fail(self):
        for key in ("caller", "pid", "module", "reason", "subject"):
            for modfs, witness in (("overlayfs", False), ("ext4", True)):
                with self.subTest(field=key, modfs=modfs):
                    report = deferred_recovered_report(modfs_witness=witness)
                    report["gaps"].append(_deadline())
                    del report["gaps"][-1][key]
                    rc, out = run_oracle(report, modfs=modfs)
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn("gap %s missing" % key, out)

    def test_missing_lossy_fails(self):
        report = deferred_recovered_report(modfs_witness=True)
        del report["edges"][1]["entries"]["coverage"]["lossy"]
        rc, out = run_oracle(report, modfs="ext4")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("edge coverage lossy missing", out)


def _never_recovered_zero(report):
    # Codex r6 F1: the child stays scan-pinned and loses all its calls.
    report["callers"][1]["image"]["authority"] = "scan_pinned"
    report["edges"][1]["entries"]["count"] = 0


class OptimizedInterpreterTests(unittest.TestCase):
    """Optimization never strips a check: every refused row still fails
    under -O and under an inherited PYTHONOPTIMIZE."""

    def all_rows(self):
        rows = [("never-recovered-zero", _never_recovered_zero,
                 "deferred activation never recovered")]
        rows += ExpectedTableTests.ROWS + CheckCoverageTests.REPORT_ROWS
        return rows

    def test_refused_rows_fail_optimized(self):
        for label, interpreter in (("-O", OPTIMIZED),
                                   ("PYTHONOPTIMIZE", INHERITED)):
            for name, mutate, marker in self.all_rows():
                for modfs, witness in (("overlayfs", False), ("ext4", True)):
                    with self.subTest(mode=label, row=name, modfs=modfs):
                        report = deferred_recovered_report(modfs_witness=witness)
                        mutate(report)
                        rc, out = run_oracle(report, modfs=modfs,
                                             interpreter=interpreter)
                        self.assertNotEqual(rc, 0, out)
                        self.assertIn(marker, out)

    def test_healthy_report_passes_optimized(self):
        for label, interpreter in (("-O", OPTIMIZED),
                                   ("PYTHONOPTIMIZE", INHERITED)):
            with self.subTest(mode=label):
                rc, out = run_oracle(deferred_recovered_report(modfs_witness=True),
                                     modfs="ext4", interpreter=interpreter)
                self.assertEqual(rc, 0, out)


def _inside_with(**changes):
    record = json.loads(inside_ledger()[len("LEDGER "):])
    record.update(changes)
    return "LEDGER " + json.dumps(record)


class WorkloadLedgerTests(unittest.TestCase):
    """Both workload ledgers are typed producer records (codex r7 F2/N3)."""

    SHAPES = (("overlayfs", False), ("ext4", True))

    def fails(self, marker, **kwargs):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                rc, out = run_oracle(deferred_recovered_report(modfs_witness=witness),
                                     modfs=modfs, **kwargs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(marker, out)

    def test_producer_shaped_ledgers_pass(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs):
                rc, out = run_oracle(deferred_recovered_report(modfs_witness=witness),
                                     modfs=modfs)
                self.assertEqual(rc, 0, out)
                self.assertIn("outside=102 excluded", out)

    OUTSIDE_ROWS = [
        # Codex r7 F2: incomplete and empty still earned the exclusion.
        ("incomplete-empty", outside_ledger(complete=False, functions=[]),
         "outside ledger incomplete"),
        ("incomplete", outside_ledger(complete=False), "outside ledger incomplete"),
        ("complete-empty", outside_ledger(functions=[]),
         "outside ledger functions are not the six driven calls"),
        ("five-functions", outside_ledger(functions=[
            {"name": n, "attempts": 500, "successful": 500} for n in FUNCTIONS[:5]]),
         "outside ledger functions are not the six driven calls"),
        ("wrong-pid", outside_ledger(pid=103), "outside ledger pid 103 is not the workload 102"),
        ("pid-string", outside_ledger(pid="102"), "outside ledger pid has type str"),
        ("not-json", "LEDGER y", "outside ledger is not JSON"),
        ("not-object", "LEDGER []", "outside ledger has type list"),
        ("schema", outside_ledger().replace("public-cli-ledger/v1", "public-cli-ledger/v2"),
         "outside ledger schema"),
        ("short-run", outside_ledger(iters=499), "outside ledger C_GenerateRandom attempts 499, drove 500"),
        ("float-attempts", outside_ledger(functions=[
            {"name": n, "attempts": 500.0, "successful": 500} for n in FUNCTIONS]),
         "outside ledger function attempts has type float"),
        ("bool-successful", outside_ledger(functions=[
            {"name": n, "attempts": 500, "successful": True} for n in FUNCTIONS]),
         "outside ledger function successful has type bool"),
        ("schema-missing", outside_ledger().replace('"schema": "p11scope/public-cli-ledger/v1", ', ''),
         "outside ledger schema missing"),
        ("name-missing", outside_ledger(functions=[
            {"attempts": 500, "successful": 500}] + [
            {"name": n, "attempts": 500, "successful": 500} for n in FUNCTIONS[1:]]),
         "outside ledger function name missing"),
        ("function-not-object", outside_ledger(functions=["C_GenerateRandom"] + [
            {"name": n, "attempts": 500, "successful": 500} for n in FUNCTIONS[1:]]),
         "outside ledger function has type str"),
        ("renamed", outside_ledger(functions=[
            {"name": n, "attempts": 500, "successful": 500}
            for n in FUNCTIONS[:5] + ["C_Sign"]]),
         "outside ledger functions are not the six driven calls"),
    ]

    def test_each_outside_row_fails(self):
        for name, ledger, marker in self.OUTSIDE_ROWS:
            with self.subTest(row=name):
                self.fails(marker, outside_wl=outside_wl(ledger))

    def test_launch_lines_drive_the_checked_iterations(self):
        # The oracle's expected attempts and the workload launches share
        # the same shell variables.
        text = QUAL.read_text()
        self.assertIn('asuser "$CFORK" "$MODULE" "$inside_iters" 200', text)
        self.assertIn('"$GATED" "$MODULE" "$outside_iters" 200 "$outside_gate"', text)
        self.assertIn('--pin "$before" --inside-iters "$inside_iters" --outside-iters "$outside_iters" '
                      '--module "$MODULE"', text)

    def test_inside_iterations_come_from_the_shell(self):
        self.fails("inside ledger attempts 500 are not two members of 249 "
                   "launched iterations", inside_iters=249)

    def test_outside_iterations_come_from_the_shell(self):
        self.fails("outside ledger C_GenerateRandom attempts 500, drove 400",
                   outside_iters=400)

    INSIDE_ROWS = [
        # Codex r7 N3: a duplicated name and a float row passed.
        ("duplicate-name", _ledger_with(
            [{"name": n, "attempts": 500, "successful": 500}
             for n in FUNCTIONS[:5] + FUNCTIONS[:1]]),
         "inside ledger functions are not the six driven calls"),
        ("float-row", _ledger_with(_functions([500] * 5 + [500.0])),
         "inside ledger attempts differ per function"),
        ("bool-row", _ledger_with(_functions([1] * 5 + [True])),
         "inside ledger attempts differ per function"),
        ("all-float", _ledger_with(_functions([500.0] * 6)),
         "inside ledger attempts not split per member"),
        ("reordered", _ledger_with(
            [{"name": n, "attempts": 500, "successful": 500}
             for n in reversed(FUNCTIONS)]),
         "inside ledger functions are not the six driven calls"),
        ("wrong-pid", _inside_with(pid=101), "inside ledger pid 101 is not the workload 100"),
        ("schema", _inside_with(schema="other"), "inside ledger schema"),
        ("not-json", "LEDGER {", "inside ledger is not JSON"),
        ("functions-null", _inside_with(functions=None), "inside ledger functions has type NoneType"),
    ]

    def test_shared_ledger_rules_hold_on_both_paths(self):
        # Each shared invariant is killed at both of its use sites.
        def rows(pid, total):
            return [{"name": n, "attempts": total, "successful": total} for n in FUNCTIONS]
        sides = (("inside", 100, 2 * ITERS, "ledger"), ("outside", 102, OUTSIDE_ITERS, "outside"))
        for what, pid, total, kind in sides:
            def build(functions=None, text=None):
                if text is not None:
                    return text
                record = {"schema": "p11scope/public-cli-ledger/v1", "pid": pid,
                          "complete": True,
                          "functions": rows(pid, total) if functions is None else functions}
                return "LEDGER " + json.dumps(record)
            def bad_success(value):
                functions = rows(pid, total)
                functions[0]["successful"] = value
                return build(functions)
            healthy = build()
            cases = [
                ("successful-bool", bad_success(True), "%s ledger function successful has type bool" % what),
                ("successful-negative", bad_success(-1), "%s ledger 'C_GenerateRandom' successful -1 of %d attempts" % (what, total)),
                ("successful-above", bad_success(total + 1), "%s ledger 'C_GenerateRandom' successful %d of %d attempts" % (what, total + 1, total)),
                ("successful-short", bad_success(total - 1), "%s ledger 'C_GenerateRandom' successful %d of %d attempts" % (what, total - 1, total)),
                ("duplicate-complete", healthy.replace('"complete": true', '"complete": false, "complete": true'),
                 "%s ledger: duplicate JSON key 'complete'" % what),
                ("duplicate-row-key", healthy.replace('"attempts": %d' % total, '"attempts": %d, "attempts": %d' % (total, total), 1),
                 "%s ledger: duplicate JSON key 'attempts'" % what),
            ]
            for name, ledger, marker in cases:
                with self.subTest(side=what, row=name):
                    if kind == "ledger":
                        self.fails(marker, ledger=ledger)
                    else:
                        self.fails(marker, outside_wl=outside_wl(ledger))

    PROTOCOL_ROWS = [
        ("two-inside-ready", "READY pid=100\nREADY pid=100\nCHILD pid=101\n", None,
         "inside workload printed 2 READY lines"),
        ("two-child", "READY pid=100\nCHILD pid=101\nCHILD pid=101\n", None,
         "inside workload printed 2 CHILD lines"),
        ("no-child", "READY pid=100\n", None, "inside workload printed 0 CHILD lines"),
        ("ready-zero", "READY pid=0\nCHILD pid=101\n", None,
         "inside workload READY line malformed: 'READY pid=0'"),
        ("ready-suffix", "READY pid=100x\nCHILD pid=101\n", None,
         "inside workload READY line malformed: 'READY pid=100x'"),
        ("two-outside-ready", None, "READY pid=102\nREADY pid=102\n",
         "outside workload printed 2 READY lines"),
    ]

    def test_each_protocol_line_row_fails(self):
        for name, inside_head, outside_head, marker in self.PROTOCOL_ROWS:
            with self.subTest(row=name):
                kwargs = {}
                if inside_head is not None:
                    kwargs["inside_wl"] = inside_head + inside_ledger() + "\n"
                if outside_head is not None:
                    kwargs["outside_wl"] = outside_head + outside_ledger() + "\n"
                self.fails(marker, **kwargs)

    def test_duplicate_keys_in_report_and_pin_fail(self):
        for modfs, witness in self.SHAPES:
            with self.subTest(modfs=modfs, input="report"):
                text = json.dumps(deferred_recovered_report(modfs_witness=witness))
                text = text.replace('"scope": "cgroup"', '"scope": "pid", "scope": "cgroup"')
                rc, out = run_oracle(None, modfs=modfs, report_text=text)
                self.assertNotEqual(rc, 0, out)
                self.assertIn("inventory report: duplicate JSON key 'scope'", out)
        rc, out = run_oracle(deferred_recovered_report(modfs_witness=True), modfs="ext4",
                             pin_text=json.dumps(PIN).replace('"ino": ', '"ino": 1, "ino": '))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("provider pin: duplicate JSON key 'ino'", out)

    def test_each_inside_row_fails(self):
        for name, ledger, marker in self.INSIDE_ROWS:
            with self.subTest(row=name):
                self.fails(marker, ledger=ledger)


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
        report["notes"][0]["pid"] = 999
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
